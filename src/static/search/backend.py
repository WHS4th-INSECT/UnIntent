from __future__ import annotations

from collections import OrderedDict, defaultdict, deque
from typing import Any

from src.static.model.values import (
    CallSite, Component, MethodIR, MethodRef, Origin, TraceStep,
)
from src.static.search.dex_ir import (
    destination_register,
    invocation_formals,
    invocation_receiver,
    method_ir,
    method_ref,
    parse_method_reference,
)
from src.static.search.method_cfg import MethodCFG
from src.static.search.api_rules import (
    WEBVIEW,
    WEBVIEW_CLIENT,
    WEBVIEW_DOWNLOAD,
    WEB_NAVIGATION_CALLBACK_PARAMETERS,
    COLLECTION_READERS,
    COLLECTION_TYPES,
    COLLECTION_WRITER_ARGUMENTS,
    CONCRETE_COLLECTION_TYPES,
)
from src.static.model.container import (
    ContainerEntry,
    ContainerSlot,
    ContainerTransfer,
    ContainerWrite,
)

ENTRY_INTENT_PARAMETERS: dict[str, dict[str, set[int]]] = {
    "activity": {"onNewIntent": {0}, "onActivityResult": {2}},
    "service": {
        "onStartCommand": {0},
        "onBind": {0},
        "onUnbind": {0},
        "onRebind": {0},
        "onHandleIntent": {0},
    },
    "receiver": {"onReceive": {1}},
}

PROVIDER_ENTRY_METHODS = {
    "query",
    "insert",
    "update",
    "delete",
    "openFile",
    "openAssetFile",
    "call",
    "getType",
}

LIVE_DATA_TYPES = {
    "Landroidx/lifecycle/LiveData;",
    "Landroidx/lifecycle/MutableLiveData;",
}
LIVE_DATA_PUBLISHERS = {"postValue": 0, "setValue": 0}
LIVE_DATA_OBSERVERS = {"observe": 1, "observeForever": 0}

# Android and lifecycle state carriers expose the same key/value semantics as
# a Map, although they do not implement java.util.Map.  Values written through
# put*/set and later read through get* must retain their provenance across
# Activity, Fragment, navigation and saved-state boundaries.
KEY_VALUE_CONTAINER_TYPES = {
    "Landroid/os/BaseBundle;",
    "Landroid/os/Bundle;",
    "Landroid/os/PersistableBundle;",
    "Landroidx/lifecycle/SavedStateHandle;",
}

FRAGMENT_BASE_TYPES = {
    "Landroid/app/Fragment;",
    "Landroidx/fragment/app/Fragment;",
    "Landroid/support/v4/app/Fragment;",
}

# Class-hierarchy dispatch is deliberately bounded.  A framework callback such
# as kotlin.jvm.functions.Function1 can have hundreds of implementations in one
# APK; connecting every implementation would make every caller reachable from
# unrelated components.  Small application interfaces and receiver types that
# can be narrowed locally still get the additional dispatch edges.
MAX_SEMANTIC_DISPATCH_TARGETS = 32
MAX_OBJECT_KEYS_PER_STATE = 64
MAX_OBJECT_KEY_CACHE_ENTRIES = 20000


def replace_backend_components(backend: Any, components: list[Component]) -> None:
    """Install enriched components and invalidate component-root caches."""

    backend.components = components
    backend.components_by_descriptor = defaultdict(list)
    for component in components:
        backend.components_by_descriptor[component.descriptor].append(component)
    for name in (
        "_root_cache",
        "_direct_root_cache",
        "_approximate_root_cache",
        "_method_owner_component_cache",
    ):
        cache = getattr(backend, name, None)
        if hasattr(cache, "clear"):
            cache.clear()


class GraphBackend:
    """Androguard graph facade preserving XREF call-site offsets."""

    def __init__(self, session: Any, components: list[Component]) -> None:
        self.session = session
        self.analysis = session.analysis
        self.call_graph = session.call_graph
        self.package_name = str(session.apk.get_package())
        self.components = components
        self.direct_supertypes: dict[str, tuple[str, ...]] = {}
        self.class_access: dict[str, frozenset[str]] = {}
        self._lineage_cache: dict[str, tuple[str, ...]] = {}
        self.semantic_dispatch_edges = 0
        self._index_hierarchy()
        self.methods: dict[MethodRef, MethodIR] = {}
        self.method_analyses: dict[MethodRef, Any] = {}
        self.methods_by_class: dict[str, list[MethodRef]] = defaultdict(list)
        for analysis_method in self.analysis.get_methods():
            if analysis_method.is_external():
                continue
            parsed = method_ir(analysis_method)
            if parsed is None:
                continue
            self.methods[parsed.method] = parsed
            self.method_analyses[parsed.method] = analysis_method
            self.methods_by_class[parsed.method.class_name].append(parsed.method)

        self.callers: dict[MethodRef, list[CallSite]] = defaultdict(list)
        self.call_targets: dict[tuple[MethodRef, int], list[MethodRef]] = defaultdict(list)
        self.field_writes: dict[str, list[tuple[MethodRef, int, int]]] = defaultdict(list)
        self.container_writes: dict[ContainerSlot, list[ContainerWrite]] = defaultdict(list)
        self.container_slots_by_object: dict[str, dict[ContainerSlot, None]] = defaultdict(dict)
        self.container_transfers: dict[str, list[ContainerTransfer]] = defaultdict(list)
        self.fragment_argument_writes: dict[
            str, list[tuple[MethodRef, int, int, str]]
        ] = defaultdict(list)
        self.reactive_parameter_sources: dict[
            tuple[MethodRef, int], list[tuple[MethodRef, int, int, str]]
        ] = defaultdict(list)
        self.components_by_descriptor: dict[str, list[Component]] = defaultdict(list)
        self._cfg_cache: OrderedDict[MethodRef, MethodCFG] = OrderedDict()
        self._root_cache: dict[MethodRef, tuple[Component, ...]] = {}
        self._object_key_cache: OrderedDict[
            tuple[MethodRef, int, int], tuple[str, ...]
        ] = OrderedDict()
        self._type_cache: OrderedDict[
            tuple[MethodRef, int, int], tuple[str, ...]
        ] = OrderedDict()
        for component in components:
            self.components_by_descriptor[component.descriptor].append(component)
        self._index_xrefs()
        self._index_virtual_dispatch()
        self._index_fields()
        self._index_containers()
        self._index_fragment_arguments()
        self._index_reactive_callbacks()

    def _index_hierarchy(self) -> None:
        for dex in self.session.dex_files:
            for dex_class in dex.get_classes():
                class_name = str(dex_class.get_name())
                access = str(dex_class.get_access_flags_string() or "")
                self.class_access[class_name] = frozenset(access.split())
                parents: list[str] = []
                super_name = str(dex_class.get_superclassname() or "")
                if super_name:
                    parents.append(super_name)
                parents.extend(str(item) for item in dex_class.get_interfaces())
                self.direct_supertypes[class_name] = tuple(dict.fromkeys(parents))

    def owner_lineage(self, owner: str) -> tuple[str, ...]:
        cached = self._lineage_cache.get(owner)
        if cached is not None:
            return cached
        queue = deque([owner])
        seen: set[str] = set()
        result: list[str] = []
        while queue:
            current = queue.popleft()
            if current in seen:
                continue
            seen.add(current)
            result.append(current)
            queue.extend(self.direct_supertypes.get(current, ()))
        value = tuple(result)
        self._lineage_cache[owner] = value
        return value

    def is_subtype(self, candidate: str, expected: str) -> bool:
        return expected in self.owner_lineage(candidate)

    def _index_xrefs(self) -> None:
        for caller, analysis_method in self.method_analyses.items():
            caller_ir = self.methods[caller]
            for _target_class, target_analysis, offset in analysis_method.get_xref_to():
                callee = method_ref(target_analysis.get_method())
                if callee not in self.methods:
                    continue
                instruction_index = caller_ir.offset_to_index.get(int(offset))
                if instruction_index is None:
                    continue
                self._add_call_target(caller, instruction_index, int(offset), callee)

    def _add_call_target(
        self, caller: MethodRef, instruction_index: int, offset: int, callee: MethodRef
    ) -> None:
        key = (caller, instruction_index)
        if callee in self.call_targets[key]:
            return
        self.call_targets[key].append(callee)
        callsite = CallSite(caller, callee, instruction_index, offset)
        if callsite not in self.callers[callee]:
            self.callers[callee].append(callsite)

    def _index_virtual_dispatch(self) -> None:
        implementations: dict[tuple[str, str], list[MethodRef]] = defaultdict(list)
        for candidate in self.methods:
            implementations[(candidate.name, candidate.descriptor)].append(candidate)

        for caller, method in self.methods.items():
            for index, instruction in enumerate(method.instructions):
                if not instruction.name.startswith(("invoke-interface", "invoke-virtual")):
                    continue
                parsed = parse_method_reference(instruction.reference)
                if parsed is None:
                    continue
                owner, name, descriptor = parsed
                if owner not in self.direct_supertypes:
                    continue
                candidates = [
                    candidate
                    for candidate in implementations.get((name, descriptor), ())
                    if candidate.class_name != owner
                    and self.is_subtype(candidate.class_name, owner)
                ]

                # For ordinary virtual calls, only add targets when the receiver
                # has a locally recoverable type narrower than the declared call
                # owner.  Interface calls retain bounded CHA as a high-recall
                # fallback because their concrete receiver is often held behind
                # an interface-typed field or return value.
                if instruction.name.startswith("invoke-virtual"):
                    receiver = invocation_receiver(instruction)
                    if receiver is None:
                        continue
                    receiver_types = tuple(
                        item
                        for item in self.inferred_types(method, receiver, index)
                        if item != owner and self.is_subtype(item, owner)
                    )
                    if not receiver_types:
                        continue
                    candidates = [
                        candidate
                        for candidate in candidates
                        if any(
                            self.is_subtype(candidate.class_name, receiver_type)
                            or candidate.class_name in self.owner_lineage(receiver_type)
                            for receiver_type in receiver_types
                        )
                    ]

                if not candidates or len(candidates) > MAX_SEMANTIC_DISPATCH_TARGETS:
                    continue
                for candidate in candidates:
                    before = len(self.call_targets[(caller, index)])
                    self._add_call_target(caller, index, instruction.offset, candidate)
                    if len(self.call_targets[(caller, index)]) > before:
                        self.semantic_dispatch_edges += 1

    def _index_fields(self) -> None:
        for method_ref_key, method in self.methods.items():
            for index, instruction in enumerate(method.instructions):
                if (
                    instruction.name.startswith(("iput", "sput"))
                    and instruction.reference
                    and instruction.registers
                ):
                    self.field_writes[instruction.reference].append(
                        (method_ref_key, index, instruction.registers[0])
                    )

    def object_keys(self, method: MethodIR, register: int, before: int) -> tuple[str, ...]:
        return self._object_keys(method, register, before, frozenset(), 0)

    def _object_keys(
        self,
        method: MethodIR,
        register: int,
        before: int,
        visited: frozenset[tuple[MethodRef, int, int]],
        depth: int,
    ) -> tuple[str, ...]:
        state = (method.method, register, before)
        if depth > 10 or state in visited:
            return ()
        cached = self._object_key_cache.get(state)
        if cached is not None:
            self._object_key_cache.move_to_end(state)
            return cached
        next_visited = visited | {state}
        reaching = self.cfg_for(method).reaching_definitions(register, before)
        keys: list[str] = []
        for index in reaching.instruction_indices:
            instruction = method.instructions[index]
            definition_keys: list[str] = []
            if instruction.name.startswith("move") and not instruction.name.startswith(
                "move-result"
            ):
                if len(instruction.registers) >= 2:
                    definition_keys.extend(
                        self._object_keys(
                            method,
                            instruction.registers[1],
                            index,
                            next_visited,
                            depth + 1,
                        )
                    )
            elif instruction.name.startswith(("iget", "sget")) and instruction.reference:
                definition_keys.append(f"field:{instruction.reference}")
                # Preserve the identity of the object stored in this field.
                # This is needed when a Bundle, Parcelable or coroutine capture
                # is written in one method and read in another: the field symbol
                # alone does not match the allocation token used at container
                # writes. The DEX field reference is exact, so following its
                # value writers does not require a name-based approximation.
                for writer, writer_index, value_register in self.field_writes.get(
                    instruction.reference, ()
                )[:32]:
                    writer_method = self.methods[writer]
                    definition_keys.extend(
                        self._object_keys(
                            writer_method,
                            value_register,
                            writer_index,
                            next_visited,
                            depth + 1,
                        )
                    )
            elif instruction.name.startswith("new-instance"):
                allocation_type = instruction.type_value or "object"
                definition_keys.append(
                    f"allocation:{method.display()}@0x{instruction.offset:04x}:{allocation_type}"
                )
            elif instruction.name.startswith("move-result") and index > 0:
                call_index = index - 1
                call = method.instructions[call_index]
                parsed = parse_method_reference(call.reference)
                receiver = invocation_receiver(call)
                if (
                    parsed
                    and (
                        parsed[1] in {"iterator", "listIterator", "asSequence"}
                        or (
                            parsed[0] == "Landroid/content/Intent;"
                            and parsed[2].endswith(")Landroid/content/Intent;")
                        )
                    )
                    and receiver is not None
                ):
                    definition_keys.extend(
                        self._object_keys(method, receiver, call_index, next_visited, depth + 1)
                    )
                for target_ref in self.call_targets.get((method.method, call_index), ())[:32]:
                    target = self.methods[target_ref]
                    for return_index, returned in enumerate(target.instructions):
                        if returned.name.startswith("return-object") and returned.registers:
                            definition_keys.extend(
                                self._object_keys(
                                    target,
                                    returned.registers[0],
                                    return_index,
                                    next_visited,
                                    depth + 1,
                                )
                            )
                if not definition_keys and parsed and not invocation_formals(call):
                    signature = f"{parsed[0]}->{parsed[1]}{parsed[2]}"
                    receiver_keys = (
                        self._object_keys(
                            method,
                            receiver,
                            call_index,
                            next_visited,
                            depth + 1,
                        )
                        if receiver is not None
                        else ()
                    )
                    definition_keys.extend(
                        f"getter:{receiver_key}:{signature}"
                        for receiver_key in receiver_keys
                    )
                    if not definition_keys:
                        definition_keys.append(f"getter:{signature}")
            remaining = MAX_OBJECT_KEYS_PER_STATE - len(keys)
            if remaining <= 0:
                break
            keys.extend(definition_keys[:remaining])

        if reaching.reaches_entry:
            parameter = method.parameters.get(register)
            if parameter is not None:
                formal_index, _dex_type = parameter
                for callsite in self.callers.get(method.method, ())[:32]:
                    caller = self.methods[callsite.caller]
                    call = caller.instructions[callsite.instruction_index]
                    actual = next(
                        (
                            actual_register
                            for formal, _actual_type, actual_register in invocation_formals(call)
                            if formal == formal_index
                        ),
                        None,
                    )
                    if actual is not None:
                        keys.extend(
                            self._object_keys(
                                caller,
                                actual,
                                callsite.instruction_index,
                                next_visited,
                                depth + 1,
                            )[: MAX_OBJECT_KEYS_PER_STATE - len(keys)]
                        )
                        if len(keys) >= MAX_OBJECT_KEYS_PER_STATE:
                            break
            elif method.receiver_register == register:
                for callsite in self.callers.get(method.method, ())[:32]:
                    caller = self.methods[callsite.caller]
                    call = caller.instructions[callsite.instruction_index]
                    receiver = invocation_receiver(call)
                    if receiver is not None:
                        keys.extend(
                            self._object_keys(
                                caller,
                                receiver,
                                callsite.instruction_index,
                                next_visited,
                                depth + 1,
                            )[: MAX_OBJECT_KEYS_PER_STATE - len(keys)]
                        )
                        if len(keys) >= MAX_OBJECT_KEYS_PER_STATE:
                            break
        value = tuple(dict.fromkeys(keys))[:MAX_OBJECT_KEYS_PER_STATE]
        self._object_key_cache[state] = value
        self._object_key_cache.move_to_end(state)
        if len(self._object_key_cache) > MAX_OBJECT_KEY_CACHE_ENTRIES:
            self._object_key_cache.popitem(last=False)
        return value

    def inferred_types(self, method: MethodIR, register: int, before: int) -> tuple[str, ...]:
        state = (method.method, register, before)
        cached = self._type_cache.get(state)
        if cached is not None:
            self._type_cache.move_to_end(state)
            return cached
        result: list[str] = []
        for index in range(min(before, len(method.instructions)) - 1, -1, -1):
            instruction = method.instructions[index]
            if register not in instruction.registers:
                continue
            if (
                instruction.name.startswith(("new-instance", "check-cast"))
                and instruction.type_value
            ):
                result.append(instruction.type_value)
                break
            elif instruction.name.startswith("move-result") and index > 0:
                parsed = parse_method_reference(method.instructions[index - 1].reference)
                if parsed:
                    return_type = parsed[2].split(")", 1)[1]
                    if return_type.startswith(("L", "[")):
                        result.append(return_type)
                break
            elif instruction.name.startswith(("iget", "sget")) and instruction.reference:
                field_type = instruction.reference.rsplit(" ", 1)[-1].strip()
                if field_type.startswith(("L", "[")):
                    result.append(field_type)
                break
            elif instruction.name.startswith("move") and len(instruction.registers) >= 2:
                result.extend(self.inferred_types(method, instruction.registers[1], index))
                break
        if not result:
            parameter = method.parameters.get(register)
            if parameter and parameter[1].startswith(("L", "[")):
                result.append(parameter[1])
        value = tuple(dict.fromkeys(result))
        self._type_cache[state] = value
        self._type_cache.move_to_end(state)
        if len(self._type_cache) > 100000:
            self._type_cache.popitem(last=False)
        return value

    def confirmed_dispatch(
        self, caller: MethodRef, instruction_index: int, target: MethodRef
    ) -> dict[str, Any] | None:
        """Return proof only for a complete, singleton type-compatible dispatch."""

        method = self.methods.get(caller)
        if method is None or not 0 <= instruction_index < len(method.instructions):
            return None
        instruction = method.instructions[instruction_index]
        if not instruction.name.startswith(("invoke-interface", "invoke-virtual")):
            return None
        parsed = parse_method_reference(instruction.reference)
        if parsed is None:
            return None
        owner, name, descriptor = parsed
        domain_lookup = getattr(self, "_dispatch_domain", None)
        domain = (
            tuple(domain_lookup(owner, name, descriptor))
            if callable(domain_lookup)
            else tuple(
                candidate
                for candidate in self.methods
                if candidate.name == name
                and candidate.descriptor == descriptor
                and candidate.class_name != owner
                and self.is_subtype(candidate.class_name, owner)
            )
        )
        if not domain or len(domain) > MAX_SEMANTIC_DISPATCH_TARGETS:
            return None
        if len(domain) == 1 and domain[0] == target:
            return {
                "dispatch_resolution": "confirmed_type_dispatch",
                "invoke_kind": instruction.name,
                "declared_receiver_type": owner,
                "receiver_types": [],
                "candidate_count": 1,
                "search_complete": True,
                "target": target.display(),
            }
        receiver = invocation_receiver(instruction)
        receiver_types = self.inferred_types(method, receiver, instruction_index) if receiver is not None else ()
        concrete_types = tuple(
            item for item in receiver_types if item != owner and self.is_subtype(item, owner)
        )
        narrowed = tuple(
            candidate
            for candidate in domain
            if any(
                self.is_subtype(candidate.class_name, receiver_type)
                or self.is_subtype(receiver_type, candidate.class_name)
                for receiver_type in concrete_types
            )
        )
        candidates = narrowed if concrete_types else domain
        if len(candidates) != 1 or candidates[0] != target:
            return None
        return {
            "dispatch_resolution": "confirmed_type_dispatch",
            "invoke_kind": instruction.name,
            "declared_receiver_type": owner,
            "receiver_types": list(receiver_types),
            "candidate_count": 1,
            "search_complete": True,
            "target": target.display(),
        }

    def _is_livedata(self, owner: str) -> bool:
        return bool(LIVE_DATA_TYPES.intersection(self.owner_lineage(owner)))

    def _is_collection(self, owner: str) -> bool:
        return (
            owner in CONCRETE_COLLECTION_TYPES
            or bool(COLLECTION_TYPES.intersection(self.owner_lineage(owner)))
            or owner.startswith("Lkotlin/collections/")
        )

    def _is_key_value_container(self, owner: str) -> bool:
        return bool(KEY_VALUE_CONTAINER_TYPES.intersection(self.owner_lineage(owner)))

    def _channel_keys(self, method: MethodIR, call_index: int) -> tuple[str, ...]:
        call = method.instructions[call_index]
        receiver = invocation_receiver(call)
        if receiver is None:
            return ()
        return self.object_keys(method, receiver, call_index)

    def _index_reactive_callbacks(self) -> None:
        publications: dict[str, list[tuple[MethodRef, int, int, str]]] = defaultdict(list)
        observers: list[tuple[tuple[str, ...], tuple[str, ...]]] = []
        for method_ref_key, method in self.methods.items():
            for index, instruction in enumerate(method.instructions):
                parsed = parse_method_reference(instruction.reference)
                if parsed is None or not self._is_livedata(parsed[0]):
                    continue
                _owner, name, _descriptor = parsed
                formals = invocation_formals(instruction)
                channels = self._channel_keys(method, index)
                if name in LIVE_DATA_PUBLISHERS:
                    value_index = LIVE_DATA_PUBLISHERS[name]
                    value_register = next(
                        (actual for formal, _type, actual in formals if formal == value_index),
                        None,
                    )
                    if value_register is not None:
                        for channel in channels:
                            publications[channel].append(
                                (
                                    method_ref_key,
                                    index,
                                    value_register,
                                    f"LiveData.{name} -> observer callback",
                                )
                            )
                elif name in LIVE_DATA_OBSERVERS:
                    callback_index = LIVE_DATA_OBSERVERS[name]
                    callback_register = next(
                        (actual for formal, _type, actual in formals if formal == callback_index),
                        None,
                    )
                    if callback_register is not None:
                        observers.append(
                            (channels, self.inferred_types(method, callback_register, index))
                        )

        callback_methods: dict[str, list[MethodRef]] = defaultdict(list)
        for method_ref_key in self.methods:
            if (
                method_ref_key.name == "onChanged"
                and method_ref_key.descriptor.startswith("(")
                and method_ref_key.descriptor != "()V"
            ):
                callback_methods[method_ref_key.class_name].append(method_ref_key)

        for channels, callback_types in observers:
            sources = [source for channel in channels for source in publications.get(channel, ())]
            if not sources:
                continue
            for callback_type in callback_types:
                for method_ref_key in callback_methods.get(callback_type, ()):
                    key = (method_ref_key, 0)
                    for source in sources:
                        if source not in self.reactive_parameter_sources[key]:
                            self.reactive_parameter_sources[key].append(source)

    def _index_containers(self) -> None:
        """Index keyed writes and whole-container transfers by abstract object ID."""
        for method_ref_key, method in self.methods.items():
            for index, instruction in enumerate(method.instructions):
                parsed = parse_method_reference(instruction.reference)
                if parsed is None or not (
                    self._is_collection(parsed[0])
                    or self._is_key_value_container(parsed[0])
                ):
                    continue
                owner, name, _descriptor = parsed
                receiver = invocation_receiver(instruction)
                if receiver is None:
                    continue
                if self._is_key_value_container(owner) and name == "putAll":
                    source_register = next(
                        (
                            actual
                            for formal, dex_type, actual in invocation_formals(instruction)
                            if formal == 0 and self._is_key_value_container(dex_type)
                        ),
                        None,
                    )
                    if source_register is None:
                        continue
                    source_ids = self.object_keys(method, source_register, index)
                    for destination_id in self.object_keys(method, receiver, index):
                        self.container_transfers[destination_id].append(
                            ContainerTransfer(
                                method=method_ref_key,
                                instruction_index=index,
                                source_object_ids=source_ids,
                                relation="Bundle.putAll container merge",
                            )
                        )
                    continue
                value_indices = (
                    (1,)
                    if self._is_key_value_container(owner)
                    and name.startswith(("put", "set"))
                    else COLLECTION_WRITER_ARGUMENTS.get(name)
                )
                if value_indices is None:
                    continue
                object_ids = self.object_keys(method, receiver, index)
                slot_key = (
                    self._container_key(method, index)
                    if self._is_key_value_container(owner)
                    else None
                )
                for formal, _dex_type, actual in invocation_formals(instruction):
                    if formal not in value_indices:
                        continue
                    for object_id in object_ids:
                        slot = ContainerSlot(object_id, slot_key)
                        self.container_writes[slot].append(
                            ContainerWrite(
                                method=method_ref_key,
                                instruction_index=index,
                                value_register=actual,
                                relation=f"container {name} value",
                            )
                        )
                        self.container_slots_by_object[object_id][slot] = None

    def _is_fragment(self, owner: str) -> bool:
        return owner in FRAGMENT_BASE_TYPES or any(
            base in self.owner_lineage(owner) for base in FRAGMENT_BASE_TYPES
        )

    def _fragment_channels(
        self, method: MethodIR, register: int, before: int, declared_owner: str
    ) -> tuple[str, ...]:
        keys = [f"fragment-object:{key}" for key in self.object_keys(method, register, before)]
        types = self.inferred_types(method, register, before)
        keys.extend(
            f"fragment-type:{item}"
            for item in types
            if self._is_fragment(item)
        )
        if not keys and self._is_fragment(declared_owner):
            keys.append(f"fragment-type:{declared_owner}")
        return tuple(dict.fromkeys(keys))

    def _index_fragment_arguments(self) -> None:
        for method_ref_key, method in self.methods.items():
            for index, instruction in enumerate(method.instructions):
                parsed = parse_method_reference(instruction.reference)
                if (
                    parsed is None
                    or parsed[1] != "setArguments"
                    or not parsed[2].startswith("(Landroid/os/Bundle;)V")
                    or not self._is_fragment(parsed[0])
                ):
                    continue
                receiver = invocation_receiver(instruction)
                formals = invocation_formals(instruction)
                bundle = next((actual for formal, _type, actual in formals if formal == 0), None)
                if receiver is None or bundle is None:
                    continue
                for channel in self._fragment_channels(
                    method, receiver, index, parsed[0]
                ):
                    self.fragment_argument_writes[channel].append(
                        (
                            method_ref_key,
                            index,
                            bundle,
                            "Fragment.setArguments Bundle [object]"
                            if channel.startswith("fragment-object:")
                            else "Fragment.setArguments Bundle [type fallback]",
                        )
                    )

    def fragment_argument_sources(
        self, method: MethodIR, call_index: int
    ) -> tuple[tuple[MethodRef, int, int, str], ...]:
        call = method.instructions[call_index]
        parsed = parse_method_reference(call.reference)
        receiver = invocation_receiver(call)
        if (
            parsed is None
            or receiver is None
            or parsed[1] not in {"getArguments", "requireArguments"}
            or not parsed[2].endswith(")Landroid/os/Bundle;")
            or not self._is_fragment(parsed[0])
        ):
            return ()
        result: list[tuple[MethodRef, int, int, str]] = []
        for channel in self._fragment_channels(method, receiver, call_index, parsed[0]):
            result.extend(self.fragment_argument_writes.get(channel, ()))
        return tuple(dict.fromkeys(result))

    def container_sources(
        self,
        method: MethodIR,
        call_index: int,
        *,
        object_keys_override: tuple[str, ...] = (),
        key_override: str | None = None,
    ) -> tuple[tuple[MethodRef, int, int, str], ...]:
        call = method.instructions[call_index]
        parsed = parse_method_reference(call.reference)
        if parsed is None:
            return ()
        owner, name, _descriptor = parsed
        if not (
            self._is_collection(owner) and name in COLLECTION_READERS
            or self._is_key_value_container(owner) and name.startswith("get")
        ):
            return ()
        receiver = invocation_receiver(call)
        container_register: int | None = receiver
        if receiver is None and owner.startswith("Lkotlin/collections/"):
            formals = invocation_formals(call)
            container_register = formals[0][2] if formals else None
        if container_register is None:
            return ()
        result: list[tuple[MethodRef, int, int, str]] = []
        object_keys = object_keys_override or self.object_keys(
            method, container_register, call_index
        )
        requested_key = (
            key_override
            if key_override is not None
            else self._container_key(method, call_index)
            if self._is_key_value_container(owner)
            else None
        )
        for object_id in object_keys:
            for entry in self._container_entries_for_object(
                object_id,
                requested_key,
                frozenset(),
                use_method=method.method,
                use_before=call_index,
            ):
                write = entry.write
                relation = write.relation
                if entry.via_transfer:
                    relation = f"{relation} via Bundle.putAll"
                result.append(
                    (
                        write.method,
                        write.instruction_index,
                        write.value_register,
                        relation,
                    )
                )
        return tuple(dict.fromkeys(result))

    def container_entries(
        self, method: MethodIR, register: int, before: int
    ) -> tuple[ContainerEntry, ...]:
        """Return all known keyed values for a container object at a use site."""
        result: list[ContainerEntry] = []
        for object_id in self.object_keys(method, register, before):
            result.extend(
                self._container_entries_for_object(
                    object_id,
                    None,
                    frozenset(),
                    use_method=method.method,
                    use_before=before,
                )
            )
        return tuple(dict.fromkeys(result))

    def _container_entries_for_object(
        self,
        object_id: str,
        requested_key: str | None,
        visited: frozenset[str],
        *,
        use_method: MethodRef | None = None,
        use_before: int | None = None,
    ) -> list[ContainerEntry]:
        """Resolve direct writes and transitive Bundle merges for one object."""
        result: dict[ContainerEntry, None] = {}
        expanded: set[tuple[str, MethodRef | None, int | None]] = set()
        pending = [(object_id, use_method, use_before, False)]
        while pending:
            current, merge_method, merge_before, via_transfer = pending.pop()
            state = (current, merge_method, merge_before)
            if (
                state in expanded
                or current in visited
                or (via_transfer and current == object_id)
            ):
                continue
            expanded.add(state)
            for slot in self.container_slots_by_object.get(current, ()):
                if requested_key is not None and slot.key not in {requested_key, None}:
                    continue
                for write in self.container_writes[slot]:
                    if not (
                        merge_method is not None
                        and merge_before is not None
                        and write.method == merge_method
                        and write.instruction_index >= merge_before
                    ):
                        result.setdefault(
                            ContainerEntry(slot.key, write, via_transfer), None
                        )
            sources: list[tuple[str, MethodRef | None, int | None, bool]] = []
            for transfer in self.container_transfers.get(current, ()):
                if (
                    merge_method is not None
                    and merge_before is not None
                    and transfer.method == merge_method
                    and transfer.instruction_index >= merge_before
                ):
                    continue
                sources.extend(
                    (source_id, transfer.method, transfer.instruction_index, True)
                    for source_id in transfer.source_object_ids
                )
            pending.extend(reversed(sources))
        return list(result)

    def _container_key(self, method: MethodIR, call_index: int) -> str | None:
        """Resolve a constant key for a keyed container access."""
        formals = invocation_formals(method.instructions[call_index])
        key_register = next(
            (
                actual
                for formal, dex_type, actual in formals
                if formal == 0 and dex_type == "Ljava/lang/String;"
            ),
            None,
        )
        return (
            self._local_string_constant(method, key_register, call_index)
            if key_register is not None
            else None
        )

    def _keyed_container_channels(
        self, method: MethodIR, call_index: int, object_keys: tuple[str, ...]
    ) -> tuple[str, ...]:
        key = self._container_key(method, call_index)
        slot = repr(key) if key is not None else "*"
        return tuple(f"{object_key}|slot:{slot}" for object_key in object_keys)

    @staticmethod
    def _local_string_constant(
        method: MethodIR, register: int, before: int
    ) -> str | None:
        current = register
        for index in range(min(before, len(method.instructions)) - 1, -1, -1):
            instruction = method.instructions[index]
            if destination_register(instruction) != current:
                continue
            if instruction.name.startswith("const-string"):
                return instruction.string_value
            if (
                instruction.name.startswith("move")
                and not instruction.name.startswith("move-result")
                and len(instruction.registers) >= 2
            ):
                current = instruction.registers[1]
                continue
            return None
        return None

    def reactive_sources(
        self, method: MethodRef, formal_index: int
    ) -> tuple[tuple[MethodRef, int, int, str], ...]:
        return tuple(self.reactive_parameter_sources.get((method, formal_index), ()))

    _CFG_CACHE_MAX = 1024

    def cfg_for(self, method: MethodIR) -> MethodCFG:
        cfg = self._cfg_cache.get(method.method)
        if cfg is not None:
            self._cfg_cache.move_to_end(method.method)
            return cfg
        cfg = MethodCFG(method, self.method_analyses[method.method])
        self._cfg_cache[method.method] = cfg
        self._cfg_cache.move_to_end(method.method)
        if len(self._cfg_cache) > self._CFG_CACHE_MAX:
            self._cfg_cache.popitem(last=False)
        return cfg

    def direct_component(self, method: MethodRef) -> Component | None:
        candidates = self.components_by_descriptor.get(method.class_name, [])
        if not candidates:
            return None
        return next((item for item in candidates if item.is_entry_point), candidates[0])

    def entry_parameter_origin(
        self, method: MethodIR, formal_index: int, dex_type: str
    ) -> Origin | None:
        download_field = WEBVIEW_DOWNLOAD.parameter_fields.get((dex_type, formal_index))
        registration = (
            self._webview_download_registration(method.method)
            if method.method.name == "onDownloadStart"
            and WEBVIEW_DOWNLOAD.callback_owner in self.owner_lineage(method.method.class_name)
            else None
        )
        if download_field is not None and registration is not None:
            caller, call_index = registration
            call = self.methods[caller].instructions[call_index]
            return Origin(
                kind="framework_parameter",
                api=f"DownloadListener.onDownloadStart parameter[{formal_index}]",
                field=download_field,
                method=method.display(),
                path=(
                    TraceStep(
                        method=caller.display(),
                        offset=call.offset,
                        instruction=call.text(),
                        relation="WebView.setDownloadListener framework callback registration",
                        edge_type="FRAMEWORK_CALLBACK",
                        direct=False,
                        evidence={
                            "framework": WEBVIEW_DOWNLOAD.framework,
                            "registration_api": WEBVIEW_DOWNLOAD.registration_name,
                            "callback_api": WEBVIEW_DOWNLOAD.callback_name,
                            "object_match": "allocated_listener_registration",
                            "trigger": "download_response",
                        },
                    ),
                ),
            )
        if (
            (method.method.name, dex_type, formal_index)
            in WEB_NAVIGATION_CALLBACK_PARAMETERS
            and WEBVIEW_CLIENT in self.owner_lineage(method.method.class_name)
        ):
            return Origin(
                kind="framework_parameter",
                api=f"WebViewClient.{method.method.name} parameter[{formal_index}]",
                field="navigation_url" if dex_type == "Ljava/lang/String;" else "navigation_request",
                method=method.display(),
            )
        component = self.direct_component(method.method)
        if component is None:
            return None
        is_intent = (
            dex_type == "Landroid/content/Intent;"
            and formal_index
            in ENTRY_INTENT_PARAMETERS.get(component.component_type, {}).get(
                method.method.name, set()
            )
        )
        is_provider_input = (
            component.component_type == "provider" and method.method.name in PROVIDER_ENTRY_METHODS
        )
        if not is_intent and not is_provider_input:
            return None
        if is_intent:
            kind = "external_intent" if component.is_entry_point else "component_intent"
            field = None
        else:
            kind = "external_parameter" if component.is_entry_point else "component_parameter"
            field = f"parameter[{formal_index}]"
        return Origin(
            kind=kind,
            api=f"{method.method.name} parameter[{formal_index}]",
            field=field,
            component=component.name,
            method=method.display(),
        )

    def framework_callback_inputs(
        self, method: MethodIR, formal_index: int, dex_type: str
    ) -> list[tuple[MethodIR, int, int, TraceStep]]:
        """Return trigger arguments for a registered framework callback.

        A callback parameter is not treated as an external Entry by itself.
        For WebView downloads, the trigger is restricted to loadUrl calls on
        the same receiver object as the listener registration.
        """

        if (
            method.method.name != WEBVIEW_DOWNLOAD.callback_name
            or formal_index != 0
            or dex_type != "Ljava/lang/String;"
            or WEBVIEW_DOWNLOAD.callback_owner
            not in self.owner_lineage(method.method.class_name)
        ):
            return []
        registration = self._webview_download_registration(method.method)
        if registration is None:
            return []
        registration_ref, registration_index = registration
        registration_method = self.methods[registration_ref]
        registration_call = registration_method.instructions[registration_index]
        registration_receiver = invocation_receiver(registration_call)
        if registration_receiver is None:
            return []
        registration_keys = set(
            self.object_keys(
                registration_method, registration_receiver, registration_index
            )
        )
        result: list[tuple[MethodIR, int, int, TraceStep]] = []
        for (name, descriptor), occurrences in self._invokes_by_name.items():
            if name != "loadUrl" or not descriptor.startswith("(Ljava/lang/String;"):
                continue
            for occurrence in occurrences:
                trigger_method = self.methods[occurrence.caller]
                trigger = trigger_method.instructions[occurrence.index]
                parsed = parse_method_reference(trigger.reference)
                trigger_receiver = invocation_receiver(trigger)
                if (
                    parsed is None
                    or WEBVIEW not in self.owner_lineage(parsed[0])
                    or trigger_receiver is None
                ):
                    continue
                trigger_keys = set(
                    self.object_keys(trigger_method, trigger_receiver, occurrence.index)
                )
                same_object = bool(registration_keys & trigger_keys)
                if not same_object and not (
                    occurrence.caller == registration_ref
                    and trigger_receiver == registration_receiver
                ):
                    continue
                url_register = next(
                    (
                        actual
                        for formal, actual_type, actual in invocation_formals(trigger)
                        if formal == 0 and actual_type == "Ljava/lang/String;"
                    ),
                    None,
                )
                if url_register is None:
                    continue
                result.append(
                    (
                        trigger_method,
                        url_register,
                        occurrence.index,
                        TraceStep(
                            method=trigger_method.display(),
                            offset=trigger.offset,
                            instruction=trigger.text(),
                            relation=(
                                "same WebView load URL may trigger "
                                "DownloadListener.onDownloadStart"
                            ),
                            edge_type="FRAMEWORK_CALLBACK",
                            direct=False,
                            evidence={
                                "framework": WEBVIEW_DOWNLOAD.framework,
                                "registration_api": WEBVIEW_DOWNLOAD.registration_name,
                                "callback_api": WEBVIEW_DOWNLOAD.callback_name,
                                "object_match": "same_webview_receiver",
                                "causality": "framework_download_event",
                            },
                        ),
                    )
                )
        return result[:16]

    def _webview_download_registration(
        self, callback: MethodRef
    ) -> tuple[MethodRef, int] | None:
        """Find a concrete DownloadListener object passed to a WebView registration API."""

        descriptor = "(Landroid/webkit/DownloadListener;)V"
        for occurrence in self._invokes_by_name.get(("setDownloadListener", descriptor), ()):
            caller = self.methods[occurrence.caller]
            instruction = caller.instructions[occurrence.index]
            parsed = parse_method_reference(instruction.reference)
            if parsed is None or WEBVIEW not in self.owner_lineage(parsed[0]):
                continue
            listener_register = next(
                (
                    actual
                    for formal, actual_type, actual in invocation_formals(instruction)
                    if formal == 0 and actual_type == WEBVIEW_DOWNLOAD.callback_owner
                ),
                None,
            )
            if listener_register is None:
                continue
            concrete_types = set(
                self.inferred_types(caller, listener_register, occurrence.index)
            )
            reaching = self.cfg_for(caller).reaching_definitions(
                listener_register, occurrence.index
            )
            for definition_index in reaching.instruction_indices:
                definition = caller.instructions[definition_index]
                if not definition.name.startswith(("iget", "sget")) or not definition.reference:
                    continue
                for writer, writer_index, value_register in self.field_writes.get(
                    definition.reference, ()
                ):
                    concrete_types.update(
                        self.inferred_types(
                            self.methods[writer], value_register, writer_index
                        )
                    )
            if callback.class_name in concrete_types:
                return occurrence.caller, occurrence.index
        return None

    def component_roots(
        self, method: MethodRef, max_depth: int = 12, max_results: int = 24
    ) -> tuple[Component, ...]:
        cached = self._root_cache.get(method)
        if cached is not None:
            return cached
        queue = deque([(method, 0)])
        visited: set[MethodRef] = set()
        result: list[Component] = []
        while queue and len(result) < max_results:
            current, depth = queue.popleft()
            if current in visited or depth > max_depth:
                continue
            visited.add(current)
            component = self.direct_component(current)
            if component is not None:
                if component not in result:
                    result.append(component)
                continue
            queue.extend((site.caller, depth + 1) for site in self.callers.get(current, []))
        value = tuple(result)
        self._root_cache[method] = value
        return value
