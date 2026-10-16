from __future__ import annotations

import time
from collections import OrderedDict, defaultdict
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Generic, TypeVar

from src.static.search.backend import MAX_SEMANTIC_DISPATCH_TARGETS, GraphBackend
from src.static.search.dex_ir import (
    destination_register,
    invocation_formals,
    invocation_receiver,
    method_ir,
    method_ref,
    parse_method_reference,
)
from src.static.model.container import (
    ContainerEntry,
    ContainerSlot,
    ContainerTransfer,
    ContainerWrite,
)
from src.static.model.values import CallSite, Component, MethodIR, MethodRef

K = TypeVar("K")
V = TypeVar("V")


@dataclass
class LazyAndroguardSession:
    """Parse APK/DEX without constructing XREFs or a whole call graph."""

    apk_path: Path
    apk: Any
    dex_files: list[Any]
    analysis: Any

    @classmethod
    def from_parsed_context(cls, context: Any) -> LazyAndroguardSession:
        """Reuse parsed APK/DEX objects without wrapping the whole app in an
        androguard Analysis. Analysis().add() eagerly builds a MethodAnalysis
        (with basic blocks, xref sets, etc.) for every method in every dex at
        once, which is what drives multi-GB memory use on large multidex
        apps. LazyBytecodeBackend now walks the raw DEX classes directly for
        IR extraction and builds androguard MethodAnalysis objects lazily,
        one method at a time, only for methods a trace actually visits (see
        _LazyMethodAnalyses below) - so no whole-app Analysis is needed here.
        """
        from src.parsing.androguard_logging import disable_androguard_logs

        disable_androguard_logs()
        return cls(
            Path(context.apk_path).resolve(),
            context.apk,
            list(context.dex_objects),
            None,
        )

    @classmethod
    def load(cls, apk_path: str | Path) -> LazyAndroguardSession:
        path = Path(apk_path).expanduser().resolve()
        if not path.is_file() or path.suffix.lower() != ".apk":
            raise FileNotFoundError(f"APK file not found: {path}")

        from androguard.core.apk import APK
        from androguard.core.dex import DEX

        from src.parsing.androguard_logging import disable_androguard_logs

        disable_androguard_logs()
        apk = APK(str(path))
        dex_files = [DEX(data) for data in apk.get_all_dex()]
        return cls(path, apk, dex_files, None)


@dataclass(frozen=True, slots=True)
class _InvokeOccurrence:
    caller: MethodRef
    index: int
    offset: int
    invoke_name: str
    declared_owner: str


class _LazyMethods:
    """dict-like facade over MethodIR, built on first access and bounded by
    an LRU cache instead of being fully materialized for the whole app.

    Every consumer of `backend.methods` (the lexical catalog builder in this
    file, _index_containers/_index_reactive_callbacks/_index_fragment_arguments
    in _base_backend.py, scan_sinks() in the sink catalog) needs to inspect
    every method's instructions at least once - that full-app scan cannot be
    skipped, it is how the tool finds sink callsites, container writes, etc.
    in the first place. What does NOT need to happen is keeping every one of
    those methods' full MethodIR (one Python object per instruction) resident
    forever afterward: building MethodIR is cheap and repeatable from the raw
    EncodedMethod reference captured during the one-time DEX walk, so this
    class rebuilds it on demand and evicts the least-recently-used entry once
    the cache is full. Each of the whole-app scans still runs to completion,
    just with a bounded amount of MethodIR resident in memory at any moment
    instead of everything at once. This is the direct fix for the multidex
    OOM: holding every method's IR simultaneously (whether wrapped in an
    androguard MethodAnalysis or in this project's own MethodIR) is what
    exhausted memory on large multidex apps; nothing about *what* gets
    computed changes, only *how much of it is kept around at once*.
    """

    def __init__(
        self,
        raw_method_index: dict[MethodRef, tuple[int, Any]],
        max_cache: int = 8000,
    ) -> None:
        self._raw_method_index = raw_method_index
        self._max_cache = max_cache
        self._cache: OrderedDict[MethodRef, MethodIR] = OrderedDict()

    def _build(self, ref: MethodRef) -> MethodIR | None:
        cached = self._cache.get(ref)
        if cached is not None:
            self._cache.move_to_end(ref)
            return cached
        location = self._raw_method_index.get(ref)
        if location is None:
            return None
        _dex_index, raw_method = location
        parsed = method_ir(raw_method)
        if parsed is not None:
            self._cache[ref] = parsed
            self._cache.move_to_end(ref)
            if len(self._cache) > self._max_cache:
                self._cache.popitem(last=False)
        return parsed

    def __getitem__(self, ref: MethodRef) -> MethodIR:
        value = self._build(ref)
        if value is None:
            raise KeyError(ref)
        return value

    def get(self, ref: MethodRef, default: Any = None) -> Any:
        value = self._build(ref)
        return default if value is None else value

    def __contains__(self, ref: MethodRef) -> bool:
        return ref in self._raw_method_index

    def __iter__(self):
        return iter(self._raw_method_index)

    def __len__(self) -> int:
        return len(self._raw_method_index)

    def keys(self):
        return self._raw_method_index.keys()

    def values(self):
        for ref in self._raw_method_index:
            value = self._build(ref)
            if value is not None:
                yield value

    def items(self):
        for ref in self._raw_method_index:
            value = self._build(ref)
            if value is not None:
                yield ref, value


class _LazyMethodAnalyses:
    """dict-like facade over androguard MethodAnalysis objects, built one
    method at a time on first access instead of wrapping every method in the
    app up front.

    MethodAnalysis(vm, method).__init__ only reads that single method's own
    bytecode to build its basic blocks (androguard's analysis.py,
    _create_basic_block) - it never touches other classes or other dex
    files. So constructing it lazily, from a (dex_index, raw EncodedMethod)
    reference captured while walking the DEX once, is exactly equivalent to
    what Analysis.add() would have produced for that method, at a fraction
    of the memory: only methods a trace actually visits (e.g. for CFG
    reaching-definitions or branch-condition checks) ever get built, and
    each one is cheap because there is no whole-app Analysis behind it.

    Looking a method up by name against a freshly rebuilt androguard
    Analysis (get_method_analysis_by_name) was tried before this and broke,
    because that lookup requires the descriptor string to match the exact
    (whitespace-and-all) formatting androguard stored it under - our
    MethodRef descriptors are whitespace-normalized. This class sidesteps
    that entirely: it never re-looks-up by name, it just holds onto the
    exact raw object reference obtained during the one-time DEX walk.
    """

    def __init__(
        self,
        dex_files: list[Any],
        raw_method_index: dict[MethodRef, tuple[int, Any]],
        max_cache: int = 256,
    ) -> None:
        self._dex_files = dex_files
        self._raw_method_index = raw_method_index
        self._max_cache = max_cache
        self._built: OrderedDict[MethodRef, Any] = OrderedDict()

    def _build(self, method: MethodRef) -> Any:
        cached = self._built.get(method)
        if cached is not None:
            self._built.move_to_end(method)
            return cached
        location = self._raw_method_index.get(method)
        if location is None:
            return None
        from androguard.core.analysis.analysis import MethodAnalysis

        dex_index, raw_method = location
        analysis_method = MethodAnalysis(self._dex_files[dex_index], raw_method)
        self._built[method] = analysis_method
        self._built.move_to_end(method)
        if len(self._built) > self._max_cache:
            self._built.popitem(last=False)
        return analysis_method

    def __getitem__(self, method: MethodRef) -> Any:
        value = self._build(method)
        if value is None:
            raise KeyError(method)
        return value

    def get(self, method: MethodRef, default: Any = None) -> Any:
        value = self._build(method)
        return default if value is None else value

    def __contains__(self, method: MethodRef) -> bool:
        return method in self._raw_method_index

    def items(self):
        for method in self._raw_method_index:
            yield method, self._build(method)


class _DemandMapping(Generic[K, V]):
    """Dictionary-like facade whose values are materialized per queried key."""

    def __init__(self, resolver: Callable[[K], list[V]]) -> None:
        self._resolver = resolver
    def get(self, key: K, default: Any = None) -> Any:
        # Visibility is phase-dependent.  The backend memoizes direct and
        # approximate subqueries separately; this facade must not freeze the
        # value observed during the first phase.
        value = list(self._resolver(key))
        return value if value else default


class LazyBytecodeBackend(GraphBackend):
    """GraphBackend-compatible facade backed by demand bytecode searches.

    The backend has no whole-app call graph or XREF index. Exact calls, virtual
    dispatch candidates and field writers are searched only when the backward
    tracer asks about a concrete method/callsite/field, then memoized.
    """

    def __init__(self, session: Any, components: list[Component]) -> None:
        # Do not call GraphBackend.__init__: it eagerly indexes every edge.
        self.session = session
        self.analysis = session.analysis
        self.call_graph = None
        self.package_name = str(session.apk.get_package())
        self.components = components
        self.direct_supertypes: dict[str, tuple[str, ...]] = {}
        self.class_access: dict[str, frozenset[str]] = {}
        self._lineage_cache: dict[str, tuple[str, ...]] = {}
        self.semantic_dispatch_edges = 0
        self._index_hierarchy()

        self.methods_by_class: dict[str, list[MethodRef]] = defaultdict(list)
        # (dex_index, raw EncodedMethod) per method. This first walk only
        # reads method *signatures* (method_ref()) and checks for a code body
        # - it does not parse instructions (method_ir()) for every method up
        # front. Walking dex classes directly enumerates exactly the same
        # methods Analysis.add() would (direct + virtual methods per class),
        # without ever building an androguard MethodAnalysis/basic-block/xref
        # for all of them, and without building this project's own per-
        # instruction MethodIR for all of them either - both of those, kept
        # resident for the whole app at once, are what caused the multi-GB
        # memory spike on large multidex apps. Full MethodIR is built lazily,
        # per method, by self.methods below.
        raw_method_index: dict[MethodRef, tuple[int, Any]] = {}
        for dex_index, dex in enumerate(session.dex_files):
            for dex_class in dex.get_classes():
                for raw_method in dex_class.get_methods():
                    if raw_method.get_code() is None:
                        continue
                    ref = method_ref(raw_method)
                    self.methods_by_class[ref.class_name].append(ref)
                    raw_method_index[ref] = (dex_index, raw_method)
        # self.methods and self.method_analyses both rebuild their respective
        # androguard/project representations on demand from raw_method_index
        # and evict least-recently-used entries once bounded. Every consumer
        # (lexical catalog below, _index_containers/_index_reactive_callbacks/
        # _index_fragment_arguments in _base_backend.py, scan_sinks() in the
        # sink catalog) still scans every method exactly as before - only the
        # amount of parsed IR resident in memory at any one moment changes.
        self.methods = _LazyMethods(raw_method_index)
        self.method_analyses = _LazyMethodAnalyses(session.dex_files, raw_method_index)

        self.components_by_descriptor: dict[str, list[Component]] = defaultdict(list)
        for component in components:
            self.components_by_descriptor[component.descriptor].append(component)

        self._cfg_cache: OrderedDict[MethodRef, Any] = OrderedDict()
        self._direct_root_cache: dict[MethodRef, tuple[Component, ...]] = {}
        self._approximate_root_cache: dict[MethodRef, tuple[Component, ...]] = {}
        self._root_cache = self._approximate_root_cache
        self._object_key_cache = OrderedDict()
        self._type_cache = OrderedDict()

        self.approximation_enabled = True
        self.direct_fanout = 32
        self.approximate_fanout = 8

        self._callers_direct: dict[MethodRef, list[CallSite]] = {}
        self._callers_approximate: dict[MethodRef, list[CallSite]] = {}
        self._targets_approximate: OrderedDict[
            tuple[MethodRef, int], list[MethodRef]
        ] = OrderedDict()
        self._field_cache: dict[str, list[tuple[MethodRef, int, int]]] = {}
        self._callback_cache: dict[MethodRef, list[CallSite]] = {}
        self._dispatch_domain_cache: dict[tuple[str, str, str], tuple[MethodRef, ...]] = {}

        # A compact lexical occurrence catalog is not a call graph: it records
        # raw invoke/field/allocation locations but resolves no caller/callee
        # edges.  It lets each demand query behave like BackDroid's targeted
        # bytecode search without re-reading the full DEX for every request.
        catalog_started = time.perf_counter()
        self._invokes_exact: dict[MethodRef, list[_InvokeOccurrence]] = defaultdict(list)
        self._invokes_by_name: dict[tuple[str, str], list[_InvokeOccurrence]] = defaultdict(list)
        self._methods_by_name: dict[tuple[str, str], list[MethodRef]] = defaultdict(list)
        self._allocations: dict[str, list[tuple[MethodRef, int, int]]] = defaultdict(list)
        self._class_constants: dict[str, list[tuple[MethodRef, int, int]]] = defaultdict(list)
        self._string_constants: dict[str, list[tuple[MethodRef, int, int]]] = defaultdict(list)
        self._field_writer_occurrences: dict[str, list[tuple[MethodRef, int, int]]] = defaultdict(
            list
        )
        lexical_instructions = 0
        for owner_method, method in self.methods.items():
            self._methods_by_name[(owner_method.name, owner_method.descriptor)].append(owner_method)
            for index, instruction in enumerate(method.instructions):
                lexical_instructions += 1
                parsed = parse_method_reference(instruction.reference)
                if parsed is not None:
                    reference = MethodRef(*parsed)
                    occurrence = _InvokeOccurrence(
                        owner_method,
                        index,
                        instruction.offset,
                        instruction.name,
                        reference.class_name,
                    )
                    self._invokes_exact[reference].append(occurrence)
                    self._invokes_by_name[(reference.name, reference.descriptor)].append(occurrence)
                if (
                    instruction.name.startswith("new-instance")
                    and instruction.type_value
                    and instruction.registers
                ):
                    self._allocations[instruction.type_value].append(
                        (owner_method, index, instruction.registers[0])
                    )
                if (
                    instruction.name.startswith("const-class")
                    and instruction.string_value
                    and instruction.registers
                ):
                    self._class_constants[instruction.string_value].append(
                        (owner_method, index, instruction.registers[0])
                    )
                if (
                    instruction.name.startswith("const-string")
                    and instruction.string_value is not None
                    and instruction.registers
                ):
                    self._string_constants[instruction.string_value].append(
                        (owner_method, index, instruction.registers[0])
                    )
                if (
                    instruction.name.startswith(("iput", "sput"))
                    and instruction.reference
                    and instruction.registers
                ):
                    self._field_writer_occurrences[instruction.reference].append(
                        (owner_method, index, instruction.registers[0])
                    )

        self.callers = _DemandMapping(self._resolve_callers)
        self.call_targets = _DemandMapping(self._resolve_targets)
        self.field_writes = _DemandMapping(self._resolve_field_writes)

        # Approximate state relations are also delayed until first use.
        self.container_writes: dict[ContainerSlot, list[ContainerWrite]] = defaultdict(list)
        self.container_slots_by_object: dict[str, dict[ContainerSlot, None]] = defaultdict(dict)
        self.container_transfers: dict[str, list[ContainerTransfer]] = defaultdict(list)
        self.fragment_argument_writes: dict[
            str, list[tuple[MethodRef, int, int, str]]
        ] = defaultdict(list)
        self.reactive_parameter_sources: dict[
            tuple[MethodRef, int], list[tuple[MethodRef, int, int, str]]
        ] = defaultdict(list)
        self._containers_materialized = False
        self._fragment_arguments_materialized = False
        self._fragment_owner_cache: dict[str, tuple[Component, ...]] = {}
        self._method_owner_component_cache: dict[str, tuple[Component, ...]] = {}
        self._fragment_argument_source_cache: dict[
            tuple[MethodRef, int], tuple[tuple[MethodRef, int, int, str], ...]
        ] = {}
        self._fragment_writer_component_cache: dict[
            MethodRef, frozenset[str]
        ] = {}
        self._reactive_materialized = False

        self.metrics: dict[str, Any] = defaultdict(int)
        self.metrics["lexical_catalog_instructions"] = lexical_instructions
        self.metrics["lexical_invoke_signatures"] = len(self._invokes_exact)
        self.metrics["lexical_catalog_seconds"] = round(time.perf_counter() - catalog_started, 6)

    def set_trace_phase(
        self,
        approximation_enabled: bool,
        approximate_fanout: int,
        direct_fanout: int = 32,
    ) -> None:
        self.approximation_enabled = approximation_enabled
        self.approximate_fanout = max(0, approximate_fanout)
        self.direct_fanout = max(0, direct_fanout)

    def _resolve_callers(self, callee: MethodRef) -> list[CallSite]:
        direct = self._direct_callers(callee)[: self.direct_fanout]
        if not self.approximation_enabled:
            return direct
        approximate = self._approximate_callers(callee)
        return [*direct, *approximate[: self.approximate_fanout]]

    def _direct_callers(self, callee: MethodRef) -> list[CallSite]:
        cached = self._callers_direct.get(callee)
        if cached is not None:
            self.metrics["caller_cache_hits"] += 1
            return cached
        self.metrics["caller_searches"] += 1
        result: list[CallSite] = []
        occurrences = self._invokes_exact.get(callee, ())
        self.metrics["caller_occurrences_examined"] += len(occurrences)
        for occurrence in occurrences:
            result.append(
                CallSite(
                    occurrence.caller,
                    callee,
                    occurrence.index,
                    occurrence.offset,
                )
            )
        self._callers_direct[callee] = result
        self.metrics["direct_call_edges_materialized"] += len(result)
        return result

    def _approximate_callers(self, callee: MethodRef) -> list[CallSite]:
        cached = self._callers_approximate.get(callee)
        if cached is not None:
            self.metrics["approximate_caller_cache_hits"] += 1
            return cached
        self.metrics["approximate_caller_searches"] += 1
        direct_keys = {
            (item.caller, item.instruction_index) for item in self._direct_callers(callee)
        }
        result: list[CallSite] = []
        occurrences = self._invokes_by_name.get((callee.name, callee.descriptor), ())
        self.metrics["approximate_caller_occurrences_examined"] += len(occurrences)
        for occurrence in occurrences:
            caller = occurrence.caller
            index = occurrence.index
            if not occurrence.invoke_name.startswith(("invoke-interface", "invoke-virtual")):
                continue
            domain = self._dispatch_domain(
                occurrence.declared_owner, callee.name, callee.descriptor
            )
            if not domain or callee not in domain:
                continue
            if occurrence.invoke_name.startswith("invoke-virtual"):
                instruction = self.methods[caller].instructions[index]
                receiver = invocation_receiver(instruction)
                receiver_types = (
                    self.inferred_types(self.methods[caller], receiver, index)
                    if receiver is not None
                    else ()
                )
                if not receiver_types or not any(
                    self.is_subtype(callee.class_name, item)
                    or self.is_subtype(item, callee.class_name)
                    for item in receiver_types
                ):
                    continue
            key = (caller, index)
            if key in direct_keys:
                continue
            result.append(CallSite(caller, callee, index, occurrence.offset))
            if len(result) >= MAX_SEMANTIC_DISPATCH_TARGETS:
                break

        # Framework callbacks are commonly registered as objects and never
        # invoked in app bytecode.  Add a bounded same-method allocation ->
        # registration relation only in the approximate phase.
        if len(result) < MAX_SEMANTIC_DISPATCH_TARGETS:
            for site in self._callback_registrations(callee):
                key = (site.caller, site.instruction_index)
                if key not in direct_keys and all(
                    (item.caller, item.instruction_index) != key for item in result
                ):
                    result.append(site)
                    if len(result) >= MAX_SEMANTIC_DISPATCH_TARGETS:
                        break

        self._callers_approximate[callee] = result
        self.semantic_dispatch_edges += len(result)
        self.metrics["approximate_call_edges_materialized"] += len(result)
        return result

    def _dispatch_domain(self, owner: str, name: str, descriptor: str) -> tuple[MethodRef, ...]:
        key = (owner, name, descriptor)
        cached = self._dispatch_domain_cache.get(key)
        if cached is not None:
            return cached
        candidates = tuple(
            method
            for method in self._methods_by_name.get((name, descriptor), ())
            if method.class_name != owner and self.is_subtype(method.class_name, owner)
        )
        value = candidates if len(candidates) <= MAX_SEMANTIC_DISPATCH_TARGETS else ()
        self._dispatch_domain_cache[key] = value
        return value

    def _callback_registrations(self, callback: MethodRef) -> list[CallSite]:
        cached = self._callback_cache.get(callback)
        if cached is not None:
            return cached
        if not callback.name.startswith(("on", "invoke", "run", "accept", "call")):
            self._callback_cache[callback] = []
            return []
        callback_lineage = self.owner_lineage(callback.class_name)
        callback_markers = (
            "Listener;",
            "Callback;",
            "Observer;",
            "Runnable;",
            "Callable;",
            "Consumer;",
            "Function0;",
            "Function1;",
            "Function2;",
        )
        if not any(parent.endswith(callback_markers) for parent in callback_lineage[1:]):
            self._callback_cache[callback] = []
            return []
        self.metrics["callback_registration_searches"] += 1
        result: list[CallSite] = []
        candidate_methods = {
            caller for caller, _index, _register in self._allocations.get(callback.class_name, ())
        }
        for caller in sorted(candidate_methods, key=MethodRef.display):
            method = self.methods[caller]
            aliases: set[int] = set()
            for index, instruction in enumerate(method.instructions):
                self.metrics["callback_instructions_scanned"] += 1
                if (
                    instruction.name.startswith("new-instance")
                    and instruction.type_value == callback.class_name
                    and instruction.registers
                ):
                    aliases.add(instruction.registers[0])
                    continue
                destination = destination_register(instruction)
                if (
                    instruction.name.startswith("move")
                    and not instruction.name.startswith("move-result")
                    and len(instruction.registers) >= 2
                ):
                    if instruction.registers[1] in aliases:
                        aliases.add(instruction.registers[0])
                    elif destination in aliases:
                        aliases.discard(destination)
                    continue
                parsed = parse_method_reference(instruction.reference)
                if parsed is not None and parsed[1] != "<init>":
                    actuals = {actual for _formal, _type, actual in invocation_formals(instruction)}
                    if aliases.intersection(actuals):
                        result.append(CallSite(caller, callback, index, instruction.offset))
                        if len(result) >= MAX_SEMANTIC_DISPATCH_TARGETS:
                            break
                if destination is not None and destination in aliases:
                    aliases.discard(destination)
            if len(result) >= MAX_SEMANTIC_DISPATCH_TARGETS:
                break
        self._callback_cache[callback] = result
        return result

    def _resolve_targets(self, key: tuple[MethodRef, int]) -> list[MethodRef]:
        direct = self._direct_targets(key)[: self.direct_fanout]
        if not self.approximation_enabled:
            return direct
        approximate = self._approximate_targets(key)
        return [*direct, *approximate[: self.approximate_fanout]]

    def _direct_targets(self, key: tuple[MethodRef, int]) -> list[MethodRef]:
        self.metrics["target_searches"] += 1
        caller, index = key
        method = self.methods.get(caller)
        if method is None or index < 0 or index >= len(method.instructions):
            result: list[MethodRef] = []
        else:
            parsed = parse_method_reference(method.instructions[index].reference)
            target = MethodRef(*parsed) if parsed is not None else None
            result = [target] if target in self.methods else []
        self.metrics["direct_call_edges_materialized"] += len(result)
        return result

    def _approximate_targets(self, key: tuple[MethodRef, int]) -> list[MethodRef]:
        cached = self._targets_approximate.get(key)
        if cached is not None:
            self._targets_approximate.move_to_end(key)
            self.metrics["approximate_target_cache_hits"] += 1
            return cached
        self.metrics["approximate_target_searches"] += 1
        caller, index = key
        method = self.methods.get(caller)
        if method is None or index < 0 or index >= len(method.instructions):
            result: list[MethodRef] = []
        else:
            instruction = method.instructions[index]
            parsed = parse_method_reference(instruction.reference)
            result = []
            if parsed is not None and instruction.name.startswith(
                ("invoke-interface", "invoke-virtual")
            ):
                owner, name, descriptor = parsed
                exact = MethodRef(owner, name, descriptor)
                candidates = list(self._dispatch_domain(owner, name, descriptor))
                if instruction.name.startswith("invoke-virtual"):
                    receiver = invocation_receiver(instruction)
                    receiver_types = (
                        self.inferred_types(method, receiver, index) if receiver is not None else ()
                    )
                    candidates = [
                        candidate
                        for candidate in candidates
                        if any(
                            self.is_subtype(candidate.class_name, item)
                            or self.is_subtype(item, candidate.class_name)
                            for item in receiver_types
                        )
                    ]
                result.extend(candidate for candidate in candidates if candidate != exact)
        self._targets_approximate[key] = result
        self._targets_approximate.move_to_end(key)
        if len(self._targets_approximate) > 100000:
            self._targets_approximate.popitem(last=False)
            self.metrics["approximate_target_cache_evictions"] += 1
        self.semantic_dispatch_edges += len(result)
        self.metrics["approximate_call_edges_materialized"] += len(result)
        return result

    def _resolve_field_writes(self, field_reference: str) -> list[tuple[MethodRef, int, int]]:
        cached = self._field_cache.get(field_reference)
        if cached is not None:
            self.metrics["field_cache_hits"] += 1
            result = cached
        else:
            self.metrics["field_searches"] += 1
            result = list(self._field_writer_occurrences.get(field_reference, ()))
            self.metrics["field_occurrences_examined"] += len(result)
            self._field_cache[field_reference] = result
            self.metrics["field_edges_materialized"] += len(result)
        if self.approximation_enabled:
            return result[: self.approximate_fanout]
        # Constructor field writes are exact object captures used by Kotlin
        # lambdas/coroutines and ordinary value objects. Opening only these in
        # the direct phase preserves that common data hand-off without turning
        # every mutable application field into an eager whole-program search.
        captures = [item for item in result if item[0].name == "<init>"]
        return captures[: self.direct_fanout]

    def container_sources(
        self,
        method: MethodIR,
        call_index: int,
        *,
        object_keys_override: tuple[str, ...] = (),
        key_override: str | None = None,
    ) -> tuple[tuple[MethodRef, int, int, str], ...]:
        if not self.approximation_enabled:
            return ()
        if not self._containers_materialized:
            self.metrics["container_index_materializations"] += 1
            self._index_containers()
            self._containers_materialized = True
        return super().container_sources(
            method,
            call_index,
            object_keys_override=object_keys_override,
            key_override=key_override,
        )[: self.approximate_fanout]

    def container_entries(
        self, method: MethodIR, register: int, before: int
    ) -> tuple[ContainerEntry, ...]:
        """Materialize Bundle state before exposing entries to Intent transfers."""
        if not self.approximation_enabled:
            return ()
        if not self._containers_materialized:
            self.metrics["container_index_materializations"] += 1
            self._index_containers()
            self._containers_materialized = True
        return super().container_entries(method, register, before)[
            : self.approximate_fanout
        ]

    def _index_fragment_arguments(self) -> None:
        occurrences = self._invokes_by_name.get(
            ("setArguments", "(Landroid/os/Bundle;)V"), ()
        )
        for occurrence in occurrences:
            method = self.methods[occurrence.caller]
            instruction = method.instructions[occurrence.index]
            parsed = parse_method_reference(instruction.reference)
            if parsed is None or not self._is_fragment(parsed[0]):
                continue
            receiver = invocation_receiver(instruction)
            bundle = next(
                (
                    actual
                    for formal, _type, actual in invocation_formals(instruction)
                    if formal == 0
                ),
                None,
            )
            if receiver is None or bundle is None:
                continue
            for channel in self._fragment_channels(
                method, receiver, occurrence.index, parsed[0]
            ):
                self.fragment_argument_writes[channel].append(
                    (
                        occurrence.caller,
                        occurrence.index,
                        bundle,
                        "Fragment.setArguments Bundle [object]"
                        if channel.startswith("fragment-object:")
                        else "Fragment.setArguments Bundle [type fallback]",
                    )
                )

    def reactive_sources(
        self, method: MethodRef, formal_index: int
    ) -> tuple[tuple[MethodRef, int, int, str], ...]:
        if not self.approximation_enabled:
            return ()
        if not self._reactive_materialized:
            self.metrics["reactive_index_materializations"] += 1
            self._index_reactive_callbacks()
            self._reactive_materialized = True
        return tuple(
            self.reactive_parameter_sources.get((method, formal_index), ())[
                : self.approximate_fanout
            ]
        )

    def fragment_argument_sources(
        self, method: MethodIR, call_index: int
    ) -> tuple[tuple[MethodRef, int, int, str], ...]:
        if not self.approximation_enabled:
            return ()
        if not self._fragment_arguments_materialized:
            self.metrics["fragment_argument_index_materializations"] += 1
            self._index_fragment_arguments()
            self._fragment_arguments_materialized = True
        cache_key = (method.method, call_index)
        cached = self._fragment_argument_source_cache.get(cache_key)
        if cached is not None:
            self.metrics["fragment_argument_source_cache_hits"] += 1
            return cached
        direct = list(super().fragment_argument_sources(method, call_index))
        if direct:
            value = tuple(direct[: self.approximate_fanout])
            self._fragment_argument_source_cache[cache_key] = value
            return value

        # A generic Activity base class often calls setArguments() on the
        # Fragment returned by an overridden factory method.  Object keys do
        # not survive that virtual return boundary.  Correlate the read and
        # write by exact Fragment allocation plus their common component
        # owner; this is bounded and never falls back to a method-name search.
        parsed = parse_method_reference(method.instructions[call_index].reference)
        receiver = invocation_receiver(method.instructions[call_index])
        if parsed is None or receiver is None:
            self._fragment_argument_source_cache[cache_key] = ()
            return ()
        reader_types = {
            item for item in self.inferred_types(method, receiver, call_index)
            if self._is_fragment(item)
        }
        if self._is_fragment(method.method.class_name):
            reader_types.add(method.method.class_name)
        reader_owners = {
            component.name
            for fragment_type in reader_types
            for component in self.fragment_owner_components(fragment_type)
        }
        if not reader_owners:
            self._fragment_argument_source_cache[cache_key] = ()
            return ()
        result: list[tuple[MethodRef, int, int, str]] = []
        for writes in self.fragment_argument_writes.values():
            for writer, writer_index, value_register, _relation in writes:
                writer_owners = self._fragment_writer_component_cache.get(writer)
                if writer_owners is None:
                    owner_components = self._components_for_method_owner(writer)
                    if not owner_components:
                        owner_components = self.component_roots(writer)
                    writer_owners = frozenset(
                        component.name for component in owner_components
                    )
                    self._fragment_writer_component_cache[writer] = writer_owners
                if reader_owners & writer_owners:
                    result.append(
                        (
                            writer,
                            writer_index,
                            value_register,
                            "Fragment.setArguments Bundle [component owner]",
                        )
                    )
                    if len(result) >= self.approximate_fanout:
                        value = tuple(result)
                        self._fragment_argument_source_cache[cache_key] = value
                        return value
        value = tuple(dict.fromkeys(result))
        self._fragment_argument_source_cache[cache_key] = value
        return value

    def fragment_owner_components(self, fragment_descriptor: str) -> tuple[Component, ...]:
        cached = self._fragment_owner_cache.get(fragment_descriptor)
        if cached is not None:
            return cached
        result: list[Component] = []
        for allocator, _index, _register in self._allocations.get(fragment_descriptor, ()):
            # The common factory form allocates the Fragment inside the target
            # Activity itself.  component_roots also handles a factory helper.
            for component in self._components_for_method_owner(allocator):
                if component not in result:
                    result.append(component)
            for component in super().component_roots(allocator):
                if component not in result:
                    result.append(component)
        value = tuple(result[:24])
        self._fragment_owner_cache[fragment_descriptor] = value
        return value

    def _components_for_method_owner(self, method: MethodRef) -> tuple[Component, ...]:
        exact = self.direct_component(method)
        if exact is not None:
            return (exact,)
        # An Activity may inherit its lifecycle from an app-defined base class.
        # Type hierarchy evidence is stronger than a name-only caller edge.
        if method.class_name not in self.methods_by_class:
            return ()
        cached = self._method_owner_component_cache.get(method.class_name)
        if cached is not None:
            self.metrics["method_owner_component_cache_hits"] += 1
            return cached
        value = tuple(
            component
            for component in self.components
            if component.analysis_enabled
            and self.is_subtype(component.descriptor, method.class_name)
        )[:24]
        self._method_owner_component_cache[method.class_name] = value
        return value

    def component_roots(
        self, method: MethodRef, max_depth: int = 12, max_results: int = 24
    ) -> tuple[Component, ...]:
        previous = self._root_cache
        self._root_cache = (
            self._approximate_root_cache if self.approximation_enabled else self._direct_root_cache
        )
        try:
            roots = list(super().component_roots(method, max_depth, max_results))
            if not roots:
                roots.extend(self._components_for_method_owner(method))
            if not roots and self._is_fragment(method.class_name):
                roots.extend(self.fragment_owner_components(method.class_name))
            value = tuple(dict.fromkeys(roots))[:max_results]
            self._root_cache[method] = value
            return value
        finally:
            self._root_cache = previous

    def metric_snapshot(self) -> dict[str, int]:
        values = dict(self.metrics)
        values.update(
            {
                "lazy_caller_keys": len(self._callers_direct),
                "lazy_target_keys": len(self._targets_approximate),
                "lazy_field_keys": len(self._field_cache),
                "lazy_callback_keys": len(self._callback_cache),
                "container_write_sites": sum(
                    len(items) for items in self.container_writes.values()
                ),
                "reactive_parameter_edges": sum(
                    len(items) for items in self.reactive_parameter_sources.values()
                ),
                "fragment_argument_source_cache_entries": len(
                    self._fragment_argument_source_cache
                ),
                "fragment_writer_component_cache_entries": len(
                    self._fragment_writer_component_cache
                ),
                "method_owner_component_cache_entries": len(
                    self._method_owner_component_cache
                ),
            }
        )
        return values
