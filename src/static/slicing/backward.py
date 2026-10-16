from __future__ import annotations

from collections import Counter, OrderedDict, defaultdict
from collections.abc import Callable, Iterable, Iterator
from contextlib import contextmanager, nullcontext
from dataclasses import dataclass
from typing import Any

from src.static.model.evidence import report_reference
from src.static.model.values import (
    IntentFact,
    IntentState,
    MethodIR,
    MethodRef,
    Origin,
    SinkSite,
    TraceFrontier,
    TraceStep,
)
from src.static.search.api_rules import (
    EXTERNAL_FIELD_APIS,
    NESTED_INTENT_APIS,
    external_field_api,
)
from src.static.search.backend import GraphBackend
from src.static.search.dex_ir import (
    destination_register,
    invocation_formals,
    invocation_receiver,
    parse_method_reference,
)

IDENTITY_METHODS = {
    "requireNonNull",
    "checkNotNull",
    "checkNotNullExpressionValue",
    "checkNotNullParameter",
    "valueOf",
    "toString",
    "trim",
    "concat",
    "parse",
    "decode",
    "encode",
}

INTENT_URI_FACTORIES = {
    ("parseUri", "(Ljava/lang/String;I)Landroid/content/Intent;"),
    ("getIntent", "(Ljava/lang/String;)Landroid/content/Intent;"),
    ("getIntentOld", "(Ljava/lang/String;)Landroid/content/Intent;"),
}

NOTIFICATION_BUILDER_TYPES = {
    "Landroid/app/Notification$Builder;",
    "Landroidx/core/app/NotificationCompat$Builder;",
    "Landroid/support/v4/app/NotificationCompat$Builder;",
}

INTENT = "Landroid/content/Intent;"
# Value types that can neither be an Intent nor hold one as an element.
NON_INTENT_TYPES = frozenset(
    {
        "Ljava/lang/String;",
        "Ljava/lang/CharSequence;",
        "Landroid/net/Uri;",
        "Z", "B", "C", "S", "I", "J", "F", "D",
    }
)
# Extras getters whose collection elements are fixed to non-Intent types by the API.
NON_INTENT_COLLECTION_GETTERS = frozenset(
    {"getStringArrayListExtra", "getIntegerArrayListExtra", "getCharSequenceArrayListExtra"}
)
# Framework types an Intent value can be declared as: itself, its supertypes and LabeledIntent.
INTENT_COMPATIBLE_TYPES = frozenset(
    {
        INTENT,
        "Landroid/content/pm/LabeledIntent;",
        "Landroid/os/Parcelable;",
        "Ljava/lang/Object;",
        "Ljava/lang/Cloneable;",
    }
)
FRAMEWORK_PREFIXES = ("Landroid/", "Ljava/", "Ljavax/", "Ldalvik/")


def return_may_hold_intent(descriptor: str) -> bool:
    """Return whether a method's declared result can be or contain an Intent."""
    return_type = descriptor[descriptor.rfind(")") + 1:]
    return return_type.lstrip("[") not in NON_INTENT_TYPES

def build_call_transition(
    caller: MethodIR,
    callsite_index: int,
    selected_callee: MethodRef,
    *,
    role: str,
    selection: str,
) -> dict[str, Any]:
    """Describe an already selected call transfer without resolving targets."""
    call = caller.instructions[callsite_index]
    declared = parse_method_reference(call.reference)
    return {
        "schema_version": 1,
        "role": role,
        "caller_method": caller.display(),
        "callsite_index": callsite_index,
        "callsite_offset": call.offset,
        "opcode": call.name,
        "declared_callee": MethodRef(*declared).display() if declared is not None else None,
        "selected_callee": selected_callee.display(),
        "actual_arguments": [
            {"formal_index": formal, "register": register, "type": dex_type}
            for formal, dex_type, register in invocation_formals(call)
        ],
        "receiver_register": invocation_receiver(call),
        "selection": selection,
    }


def origin_key(origin: Origin) -> tuple[Any, ...]:
    return (
        origin.kind,
        origin.api,
        origin.field,
        origin.key,
        repr(origin.value),
        origin.component,
        origin.method,
        origin.offset,
        origin.outer_field,
        origin.outer_key,
    )


def deduplicate_origins(origins: list[Origin]) -> list[Origin]:
    result: list[Origin] = []
    seen: set[tuple[Any, ...]] = set()
    for origin in origins:
        key = origin_key(origin)
        if key not in seen:
            seen.add(key)
            result.append(origin)
    return result


def outer_read_of(parent: Origin) -> tuple[str | None, str | None]:
    """Return where the attacker writes when a value is read through a parsed Intent."""

    if parent.kind.startswith("uri_parsed_"):
        return parent.field, parent.key
    return parent.outer_field, parent.outer_key


class _DemandTracerBase:
    """Bounded backward tracer over Androguard-backed CG/XREF/CFG data."""

    def __init__(
        self,
        backend: GraphBackend,
        max_depth: int = 24,
        max_paths: int = 16,
        max_fanout: int = 32,
    ) -> None:
        self.backend = backend
        self.max_depth = max_depth
        self.max_paths = max_paths
        self.max_fanout = max_fanout
        self._memo: dict[tuple[MethodRef, int, int, str], tuple[Origin, ...]] = {}
        self._active: set[tuple[MethodRef, int, int, str]] = set()
        self._cycle_cutoffs = 0

    def trace(
        self, method: MethodIR, register: int, before: int, purpose: str = "value"
    ) -> list[Origin]:
        state = (method.method, register, before, purpose)
        if state in self._memo:
            return list(self._memo[state])
        if state in self._active:
            self._cycle_cutoffs += 1
            return []
        cycle_epoch = self._cycle_cutoffs
        self._active.add(state)
        try:
            result = self._limit(self._trace(method, register, before, purpose, frozenset(), 0))
        finally:
            self._active.discard(state)
        if cycle_epoch == self._cycle_cutoffs:
            self._memo[state] = tuple(result)
        return result

    def trace_many(
        self,
        method: MethodIR,
        requests: Iterable[tuple[int, int, str]],
    ) -> dict[tuple[int, int, str], list[Origin]]:
        """Trace several facts while preserving fact-local result semantics.

        The base implementation is intentionally conservative.  V6's targeted
        tracer overrides this method to batch the CFG propagation that precedes
        the individual semantic transfers.
        """

        ordered = tuple(dict.fromkeys(requests))
        return {
            request: self.trace(method, request[0], request[1], request[2]) for request in ordered
        }

    def constant(self, method: MethodIR, register: int, before: int) -> Any:
        for origin in self.trace(method, register, before, "constant"):
            if origin.kind == "constant":
                return origin.value
        return None

    def _trace(
        self,
        method: MethodIR,
        register: int,
        before: int,
        purpose: str,
        visited: frozenset[tuple[MethodRef, int, int, str]],
        depth: int,
    ) -> list[Origin]:
        state = (method.method, register, before, purpose)
        if depth > self.max_depth or state in visited:
            return []
        return self._limit(self._trace_uncached(method, register, before, purpose, visited, depth))

    def _trace_uncached(
        self,
        method: MethodIR,
        register: int,
        before: int,
        purpose: str,
        visited: frozenset[tuple[MethodRef, int, int, str]],
        depth: int,
    ) -> list[Origin]:
        state = (method.method, register, before, purpose)
        next_visited = visited | {state}
        reaching = self.backend.cfg_for(method).reaching_definitions(register, before)
        results: list[Origin] = []

        for index in reaching.instruction_indices:
            instruction = method.instructions[index]
            if instruction.name.startswith("move") and not instruction.name.startswith(
                "move-result"
            ):
                if len(instruction.registers) >= 2:
                    origins = self._trace(
                        method,
                        instruction.registers[1],
                        index,
                        purpose,
                        next_visited,
                        depth + 1,
                    )
                    results.extend(self._steps(origins, method, index, "register move"))
                    if purpose == "control":
                        results.extend(
                            self._definition_control_origins(
                                method, index, next_visited, depth + 1
                            )
                        )
                continue
            if instruction.name.startswith("const-string"):
                results.append(
                    Origin(
                        "constant",
                        value=instruction.string_value,
                        method=method.display(),
                        offset=instruction.offset,
                    )
                )
                if purpose == "control":
                    results.extend(
                        self._definition_control_origins(
                            method, index, next_visited, depth + 1
                        )
                    )
                continue
            if instruction.name.startswith("const-class"):
                results.append(
                    Origin(
                        "constant",
                        field="class",
                        value=instruction.string_value,
                        method=method.display(),
                        offset=instruction.offset,
                    )
                )
                if purpose == "control":
                    results.extend(
                        self._definition_control_origins(
                            method, index, next_visited, depth + 1
                        )
                    )
                continue
            if instruction.name.startswith("const"):
                results.append(
                    Origin(
                        "constant",
                        value=instruction.literal_value,
                        method=method.display(),
                        offset=instruction.offset,
                    )
                )
                if purpose == "control":
                    results.extend(
                        self._definition_control_origins(
                            method, index, next_visited, depth + 1
                        )
                    )
                continue
            if instruction.name.startswith("move-result") and index > 0:
                call = method.instructions[index - 1]
                if call.name.startswith("invoke-"):
                    origins = self._trace_call_result(
                        method, index - 1, purpose, next_visited, depth + 1
                    )
                    results.extend(self._steps(origins, method, index, "store call result"))
                continue
            if instruction.name.startswith("new-instance"):
                results.extend(
                    self._trace_constructor_arguments(
                        method,
                        register,
                        index,
                        before,
                        purpose,
                        next_visited,
                        depth + 1,
                    )
                )
                continue
            if instruction.name.startswith(("iget", "sget")) and instruction.reference:
                field_origins: list[Origin] = []
                for writer, writer_index, value_register in self.backend.field_writes.get(
                    instruction.reference, []
                )[: self.max_fanout]:
                    writer_method = self.backend.methods[writer]
                    field_origins.extend(
                        self._trace(
                            writer_method,
                            value_register,
                            writer_index,
                            purpose,
                            next_visited,
                            depth + 1,
                        )
                    )
                results.extend(
                    self._steps(
                        field_origins,
                        method,
                        index,
                        "field read",
                        evidence={
                            "execution_boundary": {
                                "kind": "STATE_TRANSFER",
                                "reason": "value_provenance_without_execution_order",
                            },
                        },
                    )
                )
                continue
            if instruction.name.startswith(
                (
                    "add-",
                    "sub-",
                    "mul-",
                    "div-",
                    "rem-",
                    "and-",
                    "or-",
                    "xor-",
                    "shl-",
                    "shr-",
                    "ushr-",
                    "rsub-",
                    "aget",
                    "instance-of",
                )
            ):
                origins: list[Origin] = []
                for source_register in instruction.registers[1:]:
                    origins.extend(
                        self._trace(
                            method,
                            source_register,
                            index,
                            purpose,
                            next_visited,
                            depth + 1,
                        )
                    )
                results.extend(self._steps(origins, method, index, "value operation"))

        if reaching.reaches_entry:
            parameter = method.parameters.get(register)
            if parameter is not None:
                formal_index, dex_type = parameter
                entry_origin = self.backend.entry_parameter_origin(method, formal_index, dex_type)
                if entry_origin is not None:
                    if entry_origin.kind != "framework_parameter":
                        results.append(entry_origin)
                callback_inputs = getattr(self.backend, "framework_callback_inputs", None)
                callback_seeds = []
                if callable(callback_inputs):
                    callback_seeds = list(callback_inputs(method, formal_index, dex_type))
                    for trigger_method, trigger_register, trigger_before, trigger_step in callback_seeds:
                        origins = self._trace(
                            trigger_method,
                            trigger_register,
                            trigger_before,
                            purpose,
                            next_visited,
                            depth + 1,
                        )
                        results.extend(origin.with_step(trigger_step) for origin in origins)
                if (
                    entry_origin is not None
                    and entry_origin.kind == "framework_parameter"
                    and not callback_seeds
                ):
                    recorder = getattr(self, "_record_frontier", None)
                    if callable(recorder):
                        recorder(
                            method,
                            register,
                            before,
                            purpose,
                            "framework_callback_trigger_unresolved",
                            depth,
                        )
                for callsite in self.backend.callers.get(method.method, [])[: self.max_fanout]:
                    caller = self.backend.methods[callsite.caller]
                    call = caller.instructions[callsite.instruction_index]
                    actual = next(
                        (
                            actual_register
                            for formal, _actual_type, actual_register in invocation_formals(call)
                            if formal == formal_index
                        ),
                        None,
                    )
                    if actual is None:
                        continue
                    origins = self._trace(
                        caller,
                        actual,
                        callsite.instruction_index,
                        purpose,
                        next_visited,
                        depth + 1,
                    )
                    results.extend(
                        self._steps(
                            origins,
                            caller,
                            callsite.instruction_index,
                            f"actual argument -> {method.display()} parameter[{formal_index}]",
                            evidence={
                                "call_transition": build_call_transition(
                                    caller,
                                    callsite.instruction_index,
                                    method.method,
                                    role="argument_transfer",
                                    selection="observed_caller",
                                ),
                            },
                        )
                    )
                for (
                    publisher,
                    publish_index,
                    value_register,
                    relation,
                ) in self.backend.reactive_sources(method.method, formal_index)[: self.max_fanout]:
                    publisher_method = self.backend.methods[publisher]
                    origins = self._trace(
                        publisher_method,
                        value_register,
                        publish_index,
                        purpose,
                        next_visited,
                        depth + 1,
                    )
                    results.extend(self._steps(origins, publisher_method, publish_index, relation))
        return self._limit(results)

    def _definition_control_origins(
        self,
        method: MethodIR,
        definition_index: int,
        visited: frozenset[tuple[MethodRef, int, int, str]],
        depth: int,
    ) -> list[Origin]:
        """Recover predicates selecting a reaching definition or return site.

        Compilers commonly materialize true/false constants on separate
        branches, move them through a join, or return directly from a branch.
        This focused control slice follows the selecting predicate without
        admitting every helper argument or every Intent read in the callee.
        """

        cfg = self.backend.cfg_for(method)
        reachability = getattr(cfg, "controlling_branch_reachability", None)
        if not callable(reachability):
            return []
        result: list[Origin] = []
        for record in reachability(definition_index):
            branch_index = record.branch_instruction_index
            for register in method.instructions[branch_index].registers:
                origins = self._trace(
                    method,
                    register,
                    branch_index,
                    "control",
                    visited,
                    depth + 1,
                )
                result.extend(
                    self._steps(
                        origins,
                        method,
                        branch_index,
                        "branch predicate selects definition or return",
                        edge_type="CONTROL",
                        direct=True,
                        evidence={
                            "predicate_correlation": "definition_control_slice",
                            "controlled_definition_index": definition_index,
                            "may_control_definition_or_return": True,
                        },
                    )
                )
        return self._limit(result)

    def _trace_call_result(
        self,
        method: MethodIR,
        call_index: int,
        purpose: str,
        visited: frozenset[tuple[MethodRef, int, int, str]],
        depth: int,
    ) -> list[Origin]:
        call = method.instructions[call_index]
        parsed = parse_method_reference(call.reference)
        if parsed is None:
            return []
        owner, name, descriptor = parsed
        if "Landroid/app/PendingIntent;" in owner + descriptor:
            return []
        if purpose == "intent" and not return_may_hold_intent(descriptor):
            return []
        receiver = invocation_receiver(call)
        receiver_origins = (
            self._trace(method, receiver, call_index, "object", visited, depth + 1)
            if receiver is not None
            else []
        )

        if name == "getIntent" and descriptor.startswith("()Landroid/content/Intent;"):
            roots = self.backend.component_roots(method.method)
            return [
                Origin(
                    "external_intent" if component.is_entry_point else "component_intent",
                    api=call.reference,
                    component=component.name,
                    method=method.display(),
                    offset=call.offset,
                )
                for component in roots
            ]

        if name == "getPackageName" and descriptor.startswith("()Ljava/lang/String;"):
            return [
                Origin(
                    "constant",
                    api=call.reference,
                    value=self.backend.package_name,
                    method=method.display(),
                    offset=call.offset,
                )
            ]

        fragment_sources = getattr(self.backend, "fragment_argument_sources", None)
        if callable(fragment_sources):
            sources = fragment_sources(method, call_index)
            if sources:
                results: list[Origin] = []
                for writer, writer_index, value_register, relation in sources[
                    : self.max_fanout
                ]:
                    writer_method = self.backend.methods[writer]
                    exact_fragment = relation.endswith("[object]")
                    origins = self._trace(
                        writer_method,
                        value_register,
                        writer_index,
                        purpose,
                        visited,
                        depth + 1,
                    )
                    results.extend(
                        self._steps(
                            origins,
                            writer_method,
                            writer_index,
                            relation,
                            edge_type="FRAGMENT_ARGUMENT",
                            direct=exact_fragment,
                            evidence={
                                "state_semantics": "fragment_arguments",
                                "fragment_resolution": (
                                    "object" if exact_fragment else "type_fallback"
                                ),
                            },
                        )
                    )
                if results:
                    return self._steps(
                        results,
                        method,
                        call_index,
                        "Fragment arguments read",
                        edge_type="FRAGMENT_ARGUMENT",
                        direct=all(
                            relation.endswith("[object]")
                            for _writer, _index, _register, relation in sources
                        ),
                        evidence={"state_semantics": "fragment_arguments"},
                    )

        if (
            owner == "Landroid/content/Intent;"
            and (name, descriptor) in INTENT_URI_FACTORIES
        ):
            string_arguments = [
                actual
                for _formal, dex_type, actual in invocation_formals(call)
                if dex_type == "Ljava/lang/String;"
            ]
            inputs: list[Origin] = []
            for actual in string_arguments:
                inputs.extend(
                    self._trace(method, actual, call_index, "value", visited, depth + 1)
                )
            parsed_intents = [
                Origin(
                    "uri_parsed_external_intent" if origin.external else "uri_parsed_intent",
                    api=origin.api or call.reference,
                    field=origin.field,
                    key=origin.key,
                    value=origin.value,
                    component=origin.component,
                    method=origin.method or method.display(),
                    offset=origin.offset if origin.offset is not None else call.offset,
                    path=origin.path,
                )
                for origin in inputs
            ]
            return self._steps(
                parsed_intents,
                method,
                call_index,
                "external String/URI -> parsed Intent with destination control",
                evidence={"intent_uri_factory": call.reference},
            )

        source_api = external_field_api(name, owner)
        if source_api is not None:
            canonical_name, source_field = source_api
            carrier_origins = list(receiver_origins)
            if not carrier_origins:
                # Static Kotlin extension/Java compat wrappers carry the
                # Intent as an ordinary formal rather than as an invoke
                # receiver, e.g. getParcelableExtraCompat(intent, key).
                intent_actuals = [
                    actual
                    for _formal, dex_type, actual in invocation_formals(call)
                    if dex_type == "Landroid/content/Intent;"
                ]
                for actual in intent_actuals:
                    carrier_origins.extend(
                        self._trace(
                            method,
                            actual,
                            call_index,
                            "intent",
                            visited,
                            depth + 1,
                        )
                    )
            parent = next(
                (
                    item
                    for item in carrier_origins
                    if item.kind
                    in {
                        "external_intent",
                        "component_intent",
                        "nested_external_intent",
                        "uri_parsed_external_intent",
                        "external_field",
                        "component_field",
                    }
                ),
                None,
            )
            if parent is not None:
                formals = invocation_formals(call)
                key_actual = next(
                    (
                        actual
                        for _formal, dex_type, actual in formals
                        if dex_type == "Ljava/lang/String;"
                    ),
                    None,
                )
                key = (
                    self.constant(method, key_actual, call_index)
                    if key_actual is not None
                    else None
                )
                if purpose == "intent" and not self._extra_may_hold_intent(
                    method, call_index, canonical_name, visited, depth
                ):
                    return []
                external = parent.external
                nested = purpose == "intent" and canonical_name in NESTED_INTENT_APIS
                kind = (
                    "nested_external_intent"
                    if external and nested
                    else "component_intent"
                    if nested
                    else "external_field"
                    if external
                    else "component_field"
                )
                outer_field, outer_key = outer_read_of(parent)
                return [
                    Origin(
                        kind,
                        api=call.reference,
                        field=source_field,
                        key=str(key) if key is not None else None,
                        component=parent.component,
                        method=method.display(),
                        offset=call.offset,
                        path=parent.path,
                        outer_field=outer_field,
                        outer_key=outer_key,
                    )
                ]

        if owner == "Landroid/content/Intent;" and name == "getExtras":
            parent = next(
                (
                    item
                    for item in receiver_origins
                    if item.kind
                    in {
                        "external_intent",
                        "uri_parsed_external_intent",
                        "component_intent",
                    }
                ),
                None,
            )
            if parent is not None:
                outer_field, outer_key = outer_read_of(parent)
                return [
                    Origin(
                        "external_field" if parent.external else "component_field",
                        api=call.reference,
                        field="extras",
                        component=parent.component,
                        method=method.display(),
                        offset=call.offset,
                        path=parent.path,
                        outer_field=outer_field,
                        outer_key=outer_key,
                    )
                ]

        # Preserve the Intent field identity when a whole extras Bundle is
        # handed through another object boundary (most commonly
        # Activity.getIntent().getExtras() -> Fragment.setArguments()).  The
        # Bundle API name is irrelevant; the receiver origin and constant key
        # are the structural evidence.
        is_key_value_container = getattr(
            self.backend, "_is_key_value_container", lambda _owner: False
        )
        if (
            is_key_value_container(owner)
            and (name.startswith("get") or name == "containsKey")
            and receiver_origins
        ):
            key_actual = next(
                (
                    actual
                    for formal, dex_type, actual in invocation_formals(call)
                    if formal == 0 and dex_type == "Ljava/lang/String;"
                ),
                None,
            )
            key = (
                self.constant(method, key_actual, call_index)
                if key_actual is not None
                else None
            )
            projected: list[Origin] = []
            for parent in receiver_origins:
                if parent.kind not in {"external_field", "component_field"}:
                    continue
                projected.append(
                    Origin(
                        parent.kind,
                        api=call.reference,
                        field="extra" if parent.field in {"extras", "extra"} else parent.field,
                        key=str(key) if key is not None else parent.key,
                        component=parent.component,
                        method=method.display(),
                        offset=call.offset,
                        path=parent.path,
                        outer_field=parent.outer_field,
                        outer_key=parent.outer_key,
                    )
                )
            if projected:
                return self._steps(
                    projected,
                    method,
                    call_index,
                    "keyed container field read",
                    edge_type="CONTAINER_FIELD_READ",
                    direct=key is not None,
                    evidence={
                        "state_semantics": "carrier_field_projection",
                        "container_key": str(key) if key is not None else None,
                        "execution_boundary": {
                            "kind": "STATE_TRANSFER",
                            "reason": "value_provenance_without_execution_order",
                        },
                    },
                )

        if (owner == "Ljava/lang/Class;" and name == "forName") or (
            owner.endswith("ClassLoader;") and name == "loadClass"
        ):
            results: list[Origin] = []
            for _formal, dex_type, actual in invocation_formals(call):
                if dex_type == "Ljava/lang/String;":
                    results.extend(
                        self._trace(method, actual, call_index, purpose, visited, depth + 1)
                    )
            return self._steps(results, method, call_index, "class-name String -> Class")

        if (
            name == "build"
            and receiver is not None
            and NOTIFICATION_BUILDER_TYPES.intersection(self.backend.owner_lineage(owner))
        ):
            return self._trace_notification_builder(
                method, receiver, call_index, purpose, visited, depth + 1
            )

        contextual_container_sources = getattr(self, "_contextual_container_sources", None)
        container_sources = (
            contextual_container_sources(method, call_index)
            if callable(contextual_container_sources)
            else self.backend.container_sources(method, call_index)
        )
        if container_sources:
            results: list[Origin] = []
            for writer, writer_index, value_register, relation in container_sources[
                : self.max_fanout
            ]:
                writer_method = self.backend.methods[writer]
                origins = self._trace(
                    writer_method,
                    value_register,
                    writer_index,
                    purpose,
                    visited,
                    depth + 1,
                )
                results.extend(self._steps(origins, writer_method, writer_index, relation))
            if results:
                return self._steps(
                    results,
                    method,
                    call_index,
                    "collection element read",
                    evidence={
                        "execution_boundary": {
                            "kind": "STATE_TRANSFER",
                            "reason": "value_provenance_without_execution_order",
                        },
                    },
                )

        targets = self.backend.call_targets.get((method.method, call_index), [])
        if targets:
            results: list[Origin] = []
            control_fallbacks: list[Origin] = []
            for target_ref in targets[: self.max_fanout]:
                target = self.backend.methods[target_ref]
                target_results: list[Origin] = []
                context = getattr(self, "_callee_context", None)
                scope = (
                    context(method, call_index, target_ref)
                    if callable(context)
                    else nullcontext()
                )
                with scope:
                    for return_index, return_instruction in enumerate(target.instructions):
                        if (
                            return_instruction.name.startswith("return")
                            and return_instruction.registers
                        ):
                            target_results.extend(
                                self._trace(
                                    target,
                                    return_instruction.registers[0],
                                    return_index,
                                    purpose,
                                    visited,
                                    depth + 1,
                                )
                            )
                            if purpose == "control" and getattr(
                                self, "_phase", "direct"
                            ) == "direct":
                                target_results.extend(
                                    self._definition_control_origins(
                                        target,
                                        return_index,
                                        visited,
                                        depth + 1,
                                    )
                                )
                results.extend(
                    self._steps(
                        target_results,
                        method,
                        call_index,
                        "internal method return",
                        evidence={
                            "call_transition": build_call_transition(
                                method,
                                call_index,
                                target_ref,
                                role="return_value",
                                selection="selected_return",
                            ),
                        },
                    )
                )
                if purpose == "control" and getattr(
                    self, "_phase", "approximate"
                ) == "approximate":
                    for _formal, _dex_type, actual in invocation_formals(call):
                        control_fallbacks.extend(
                            self._trace(method, actual, call_index, "value", visited, depth + 1)
                        )
                    for target_index, target_call in enumerate(target.instructions[:-1]):
                        target_parsed = parse_method_reference(target_call.reference)
                        if target_parsed is None or external_field_api(
                            target_parsed[1], target_parsed[0]
                        ) is None:
                            continue
                        move_result = target.instructions[target_index + 1]
                        if move_result.name.startswith("move-result") and move_result.registers:
                            control_fallbacks.extend(
                                self._trace(
                                    target,
                                    move_result.registers[0],
                                    target_index + 2,
                                    "value",
                                    visited,
                                    depth + 1,
                                )
                            )
            combined = [
                *results,
                *self._steps(
                    control_fallbacks,
                    method,
                    call_index,
                    "internal method control fallback",
                    edge_type="CONTROL",
                    direct=False,
                    evidence={
                        "approximation": "callee actual/getExtra control fallback",
                        "predicate_correlation": "unresolved",
                    },
                ),
            ]
            return (
                self._prefer_precise_control_origins(combined)
                if purpose == "control"
                else combined
            )

        if owner == "Ljava/lang/StringBuilder;" and name == "toString" and receiver is not None:
            return self._trace_mutations(method, receiver, call_index, purpose, visited, depth + 1)

        if name in IDENTITY_METHODS or owner in {
            "Landroid/net/Uri;",
            "Ljava/lang/String;",
            "Ljava/util/Objects;",
            "Lkotlin/jvm/internal/Intrinsics;",
        }:
            results: list[Origin] = []
            for _formal, _dex_type, actual in invocation_formals(call):
                results.extend(self._trace(method, actual, call_index, purpose, visited, depth + 1))
            if name != "toString":
                results.extend(receiver_origins)
            return self._steps(results, method, call_index, f"{name} value transform")

        if owner == "Landroid/content/Intent;" and name.startswith("set"):
            return receiver_origins
        return []

    def _extra_may_hold_intent(
        self,
        method: MethodIR,
        call_index: int,
        canonical_name: str,
        visited: frozenset[tuple[MethodRef, int, int, str]],
        depth: int,
    ) -> bool:
        """Return whether an extras read can yield an Intent, judged by its element type."""
        if canonical_name in NON_INTENT_COLLECTION_GETTERS:
            return False
        call = method.instructions[call_index]
        class_arguments = [
            actual
            for _formal, dex_type, actual in invocation_formals(call)
            if dex_type == "Ljava/lang/Class;"
        ]
        for actual in class_arguments:
            origins = self._trace(method, actual, call_index, "value", visited, depth + 1)
            # An unresolved or non-constant class may be Intent.class.
            if not origins or any(
                origin.kind != "constant" or not isinstance(origin.value, str)
                for origin in origins
            ):
                return True
            if any(self._class_may_be_intent(origin.value) for origin in origins):
                return True
        return not class_arguments

    def _class_may_be_intent(self, descriptor: str) -> bool:
        """Return whether a class literal admits Intent instances."""
        element = descriptor.lstrip("[")
        if element in INTENT_COMPATIBLE_TYPES:
            return True
        if INTENT in self.backend.owner_lineage(element):
            return True
        if element in getattr(self.backend, "direct_supertypes", {}):
            return False  # Bytecode in the APK whose hierarchy excludes Intent.
        # Other framework classes are unrelated to Intent; unknown classes may not be.
        return not element.startswith(FRAMEWORK_PREFIXES)

    def _trace_constructor_arguments(
        self,
        method: MethodIR,
        register: int,
        allocation_index: int,
        before: int,
        purpose: str,
        visited: frozenset[tuple[MethodRef, int, int, str]],
        depth: int,
    ) -> list[Origin]:
        results: list[Origin] = []
        for index in range(allocation_index + 1, min(before, len(method.instructions))):
            instruction = method.instructions[index]
            if destination_register(instruction) == register:
                break
            parsed = parse_method_reference(instruction.reference)
            if (
                parsed is None
                or parsed[1] != "<init>"
                or invocation_receiver(instruction) != register
            ):
                continue
            for _formal, _dex_type, actual in invocation_formals(instruction):
                origins = self._trace(
                    method,
                    actual,
                    index,
                    purpose,
                    visited,
                    depth + 1,
                )
                results.extend(self._steps(origins, method, index, "object constructor argument"))
            break
        return self._limit(results)

    def _trace_mutations(
        self,
        method: MethodIR,
        register: int,
        before: int,
        purpose: str,
        visited: frozenset[tuple[MethodRef, int, int, str]],
        depth: int,
    ) -> list[Origin]:
        results: list[Origin] = []
        for index in range(before - 1, -1, -1):
            instruction = method.instructions[index]
            if invocation_receiver(instruction) == register:
                parsed = parse_method_reference(instruction.reference)
                if parsed and parsed[1] in {"append", "insert", "replace"}:
                    for _formal, _dex_type, actual in invocation_formals(instruction):
                        results.extend(
                            self._trace(method, actual, index, purpose, visited, depth + 1)
                        )
            if destination_register(instruction) == register:
                break
        return self._limit(results)

    def _trace_notification_builder(
        self,
        method: MethodIR,
        register: int,
        before: int,
        purpose: str,
        visited: frozenset[tuple[MethodRef, int, int, str]],
        depth: int,
    ) -> list[Origin]:
        """Trace values assigned to the exact Notification builder object."""

        target_keys = set(self.backend.object_keys(method, register, before))
        if not target_keys:
            return []
        results: list[Origin] = []
        for index in range(before - 1, -1, -1):
            instruction = method.instructions[index]
            parsed = parse_method_reference(instruction.reference)
            mutation_receiver = invocation_receiver(instruction)
            if (
                parsed is None
                or mutation_receiver is None
                or not parsed[1].startswith(("set", "add"))
            ):
                continue
            mutation_keys = set(
                self.backend.object_keys(method, mutation_receiver, index)
            )
            if not target_keys.intersection(mutation_keys):
                continue
            for _formal, dex_type, actual in invocation_formals(instruction):
                if dex_type == "Landroid/app/PendingIntent;":
                    continue
                origins = self._trace(
                    method, actual, index, purpose, visited, depth + 1
                )
                results.extend(
                    self._steps(
                        origins,
                        method,
                        index,
                        f"Notification builder {parsed[1]} value",
                        edge_type="OBJECT_STATE_WRITE",
                        direct=True,
                        evidence={
                            "state_semantics": "notification_builder",
                            "builder_setter": parsed[1],
                        },
                    )
                )
        return self._limit(results)

    def _steps(
        self,
        origins: list[Origin],
        method: MethodIR,
        index: int,
        relation: str,
        *,
        edge_type: str | None = None,
        direct: bool | None = None,
        evidence: dict[str, Any] | None = None,
    ) -> list[Origin]:
        instruction = method.instructions[index]
        step_evidence = dict(evidence or {})
        if (
            direct is None
            and relation.startswith("actual argument -> ")
            and instruction.name.startswith(("invoke-interface", "invoke-virtual"))
        ):
            target_text = relation.removeprefix("actual argument -> ").split(" parameter[", 1)[0]
            parsed_target = parse_method_reference(target_text)
            resolver = getattr(self.backend, "confirmed_dispatch", None)
            if parsed_target is not None and callable(resolver):
                proof = resolver(method.method, index, MethodRef(*parsed_target))
                if proof is not None:
                    edge_type = "DISPATCH"
                    direct = True
                    step_evidence.update(proof)
        step = TraceStep(
            method=method.display(),
            offset=instruction.offset,
            instruction=instruction.text(),
            relation=relation,
            edge_type=edge_type,
            direct=direct,
            evidence=step_evidence,
        )
        return [origin.with_step(step) for origin in origins]

    @staticmethod
    def _prefer_precise_control_origins(origins: list[Origin]) -> list[Origin]:
        """Collapse helper controls by source, preferring a predicate slice."""

        selected: dict[tuple[Any, ...], tuple[Origin, tuple[int, int, int]]] = {}
        for origin in origins:
            identity = (
                origin.kind,
                origin.api,
                origin.field,
                origin.key,
                repr(origin.value),
                origin.component,
                origin.method,
                origin.offset,
            )
            fallback = any(
                step.evidence.get("predicate_correlation") == "unresolved"
                for step in origin.path.iter_reverse()
            )
            score = (
                int(fallback),
                sum(step.direct is False for step in origin.path.iter_reverse()),
                len(origin.path),
            )
            current = selected.get(identity)
            if current is None or score < current[1]:
                selected[identity] = (origin, score)
        return [origin for origin, _score in selected.values()]

    def _limit(self, origins: list[Origin]) -> list[Origin]:
        unique = deduplicate_origins(origins)
        external = [origin for origin in unique if origin.external]
        others = [origin for origin in unique if not origin.external]
        return [*external, *others[: max(0, self.max_paths - len(external))]]


@dataclass(frozen=True)
class CallFrame:
    caller: MethodRef
    call_index: int
    callee: MethodRef
    actuals: tuple[tuple[int, int], ...]
    receiver: int | None


CallContext = tuple[tuple[MethodRef, int, MethodRef], ...]
TraceState = tuple[
    MethodRef, int, int, str, tuple[str, tuple[str, ...]], str, CallContext
]


@dataclass
class _TraceWork:
    """One resumable iterative-DFS frame for a deep trace."""

    method: MethodRef
    register: int
    before: int
    purpose: str
    depth: int
    phase: str
    interest_profile: tuple[str, tuple[str, ...]]
    call_frames: tuple[CallFrame, ...]
    ancestors: frozenset[TraceState]
    charged: bool = False
    dependencies: tuple[TraceState, ...] = ()


@dataclass
class _TraceContinuation:
    """Compact state retained between fixed deep-analysis slices."""

    root: TraceState
    stack: list[_TraceWork]
    results: dict[TraceState, tuple[Origin, ...]]
    references: dict[TraceState, int]
    cycle_tainted: set[TraceState]


class DemandTracer(_DemandTracerBase):
    """Sink-targeted backward may-tracer with memoized two-phase exploration.

    A request first follows only CFG/XREF-backed relations. Field, reactive,
    container and semantic-dispatch relations are exposed only if that direct
    phase did not already reach an external source. Recursive states use a
    Scout and Promote retain the small recursive walk. Deep uses an explicit
    LIFO work stack, so a bounded slice resumes unfinished dependencies without
    replaying completed child states in the next scheduler round.
    """

    def __init__(
        self,
        *args: Any,
        max_states_per_request: int = 25000,
        max_approx_states_per_request: int | None = None,
        max_approx_fanout: int = 8,
        max_external_origins: int | None = None,
        resume_roots: set[str] | None = None,
        resume_budget_multiplier: int = 4,
        max_frontiers_per_request: int = 32,
        analysis_frontier_sink: Callable[[dict[str, Any]], None] | None = None,
        max_trace_cache_entries: int = 10000,
        sink_tiers: dict[str, str] | None = None,
        scout_states_per_request: int = 500,
        promote_states_per_request: int = 5000,
        promote_approx_states_per_request: int = 800,
        max_total_direct_states: int | None = None,
        max_total_approx_states: int | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(*args, **kwargs)
        self.max_states_per_request = max_states_per_request
        self.max_approx_states_per_request = (
            max_states_per_request
            if max_approx_states_per_request is None
            else max_approx_states_per_request
        )
        self.max_approx_fanout = max_approx_fanout
        self.max_external_origins = (
            self.max_paths if max_external_origins is None else max_external_origins
        )
        self.resume_roots = resume_roots or set()
        self.resume_budget_multiplier = max(1, resume_budget_multiplier)
        self.max_frontiers_per_request = max(1, max_frontiers_per_request)
        self.analysis_frontier_sink = analysis_frontier_sink
        self.max_trace_cache_entries = max(1, max_trace_cache_entries)
        self.sink_tiers = dict(sink_tiers or {})
        self.scout_states_per_request = max(1, scout_states_per_request)
        self.promote_states_per_request = max(1, promote_states_per_request)
        self.promote_approx_states_per_request = max(
            1, promote_approx_states_per_request
        )
        self.max_total_direct_states = max_total_direct_states
        self.max_total_approx_states = max_total_approx_states
        self._remaining_total_direct_states = max_total_direct_states
        self._remaining_total_approx_states = max_total_approx_states

        # Path-local visited sets are deliberately absent from the v9 state.
        self._memo: OrderedDict[TraceState, tuple[Origin, ...]] = OrderedDict()
        self._active: set[TraceState] = set()
        self._deep_continuations: dict[
            tuple[str | None, TraceState], _TraceContinuation
        ] = {}
        self._iterative_continuation: _TraceContinuation | None = None
        self._iterative_work: _TraceWork | None = None
        self._iterative_dependencies: list[_TraceWork] = []
        self._last_trace_complete = True

        self.truncation_count = 0
        self._request_level = 0
        self._current_request = ""
        self._reported_current = False
        self._current_sink_site: str | None = None
        self._current_sink_tier = "deep"
        self._current_allow_approx = True
        # A sink analysis can issue thousands of individual trace() requests.
        # Request-local limits alone therefore do not provide fairness between
        # sinks.  These optional counters cap the whole pipeline pass for one
        # sink and are shared by every nested request it creates.
        self._active_sink_slice: str | None = None
        self._active_slice_tier: str | None = None
        self._remaining_slice_direct_states: int | None = None
        self._remaining_slice_approx_states: int | None = None
        self.sink_slice_direct_exhaustions = 0
        self.sink_slice_approx_exhaustions = 0
        self._current_round_name: str | None = None
        self._frontiers_in_current = 0
        self._frontier_sample_keys: set[tuple[Any, ...]] = set()
        self._phase = "direct"
        self._interest_profile: tuple[str, tuple[str, ...]] = ("generic", ())
        self._remaining_direct_states = max_states_per_request
        self._remaining_approx_states = self.max_approx_states_per_request
        self._current_max_depth = self.max_depth
        self._budget_exhaustions = 0
        self._depth_exhaustions = 0
        self._cycle_cutoffs = 0

        self.cache_hits = 0
        self.cache_misses = 0
        self.cache_evictions = 0
        self.peak_cache_entries = 0
        self.cycle_tainted_states_not_cached = 0
        self.direct_states_explored = 0
        self.approx_states_explored = 0
        self.approximation_passes = 0
        self.approximation_skips = 0
        self.approximation_gates = 0
        self.global_direct_budget_exhaustions = 0
        self.global_approx_budget_exhaustions = 0
        self.direct_budget_exhaustions = 0
        self.approx_budget_exhaustions = 0
        self.batched_trace_calls = 0
        self.batched_trace_requests = 0
        self.max_trace_batch_width = 0
        self.seed_batch_methods = 0
        self.seed_batch_requests = 0
        self.unresolved_frontiers: list[TraceFrontier] = []
        self.frontier_occurrences: Counter[tuple[str | None, str, str]] = Counter()
        self.sink_evidence_signals: dict[str, set[str]] = defaultdict(set)
        self._resumed_roots_seen: set[str] = set()
        self._call_frames: tuple[CallFrame, ...] = ()
        self._method_source_hint_cache: dict[MethodRef, bool] = {}
        self.max_call_context_depth = 6
        # DEX has no first-party/library marker. Treat the manifest package
        # namespace (and its immediate parent for common *.app package IDs) as app code.
        package_path = self.backend.package_name.replace(".", "/")
        self._app_class_prefixes = [f"L{package_path}/"]
        if "/" in package_path:
            self._app_class_prefixes.append(
                f"L{package_path.rsplit('/', 1)[0]}/"
            )
        self.last_sink_slice_profile: dict[str, Any] = {}
        self._profile_methods: set[MethodRef] = set()
        self._profile_states = 0
        self._profile_library_states = 0
        self._profile_max_trace_depth = 0
        self._profile_max_call_depth = 0

    @contextmanager
    def _callee_context(
        self, caller: MethodIR, call_index: int, callee: MethodRef
    ) -> Iterator[None]:
        call = caller.instructions[call_index]
        frame = CallFrame(
            caller=caller.method,
            call_index=call_index,
            callee=callee,
            actuals=tuple(
                (formal, actual)
                for formal, _dex_type, actual in invocation_formals(call)
            ),
            receiver=invocation_receiver(call),
        )
        previous = self._call_frames
        self._call_frames = (*previous, frame)[-self.max_call_context_depth :]
        try:
            yield
        finally:
            self._call_frames = previous

    @contextmanager
    def _caller_context(self) -> Iterator[None]:
        previous = self._call_frames
        self._call_frames = previous[:-1]
        try:
            yield
        finally:
            self._call_frames = previous

    @property
    def resumed_root_requests(self) -> int:
        return len(self._resumed_roots_seen)

    @property
    def cached_state_count(self) -> int:
        return len(self._memo)

    @property
    def max_fanout(self) -> int:
        direct = getattr(self, "_max_direct_fanout", 32)
        if getattr(self, "_phase", "direct") == "approximate":
            return direct + getattr(self, "max_approx_fanout", 0)
        return direct

    @max_fanout.setter
    def max_fanout(self, value: int) -> None:
        self._max_direct_fanout = value

    @contextmanager
    def sink_scope(self, sink: SinkSite) -> Iterator[None]:
        """Select a lightweight relevance profile from the sink's DEX arguments."""
        previous = self._interest_profile
        previous_sink = self._current_sink_site
        previous_tier = self._current_sink_tier
        previous_allow_approx = self._current_allow_approx
        method = self.backend.methods[sink.method]
        call = method.instructions[sink.instruction_index]
        argument_registers = set(sink.argument_registers)
        types = tuple(
            sorted(
                {
                    dex_type
                    for _formal, dex_type, actual in invocation_formals(call)
                    if actual in argument_registers
                }
            )
        )
        self._interest_profile = (sink.category, types)
        self._current_sink_site = sink.site_id
        self._current_sink_tier = (
            self._active_slice_tier
            if self._active_slice_tier is not None
            else self.sink_tiers.get(sink.site_id, "deep")
        )
        self._current_allow_approx = self._current_sink_tier == "deep"
        try:
            yield
        finally:
            self._interest_profile = previous
            self._current_sink_site = previous_sink
            self._current_sink_tier = previous_tier
            self._current_allow_approx = previous_allow_approx

    @contextmanager
    def sink_analysis_slice(
        self,
        sink: SinkSite,
        *,
        tier: str,
        direct_states: int,
        approximate_states: int,
        round_name: str | None = None,
    ) -> Iterator[None]:
        """Give one sink a hard, aggregate state quota for a scheduler round.

        The quota covers all trace requests made while building that sink's
        candidate flow, including nested ICC resolution.  Re-entering this
        context in a later round reuses completed memo entries while partial
        states, which are deliberately not cached, can be explored further.
        """
        previous = (
            self._active_sink_slice,
            self._active_slice_tier,
            self._remaining_slice_direct_states,
            self._remaining_slice_approx_states,
            self._current_sink_site,
            self._current_sink_tier,
            self._current_allow_approx,
            self._current_round_name,
            self._frontiers_in_current,
            self._frontier_sample_keys,
            self._profile_methods,
            self._profile_states,
            self._profile_library_states,
            self._profile_max_trace_depth,
            self._profile_max_call_depth,
        )
        self._active_sink_slice = sink.site_id
        self._active_slice_tier = tier
        self._remaining_slice_direct_states = max(0, direct_states)
        self._remaining_slice_approx_states = max(0, approximate_states)
        self._current_sink_site = sink.site_id
        self._current_sink_tier = tier
        self._current_allow_approx = tier != "scout"
        self._current_round_name = round_name or tier
        self._frontiers_in_current = 0
        self._frontier_sample_keys = set()
        self._profile_methods = set()
        self._profile_states = 0
        self._profile_library_states = 0
        self._profile_max_trace_depth = 0
        self._profile_max_call_depth = 0
        try:
            yield
        finally:
            self.last_sink_slice_profile = {
                "site_id": sink.site_id,
                "round": round_name or tier,
                "visited_methods": len(self._profile_methods),
                "visited_states": self._profile_states,
                "max_trace_depth": self._profile_max_trace_depth,
                "max_call_depth": self._profile_max_call_depth,
                "library_states": self._profile_library_states,
                "library_entry_ratio": round(
                    self._profile_library_states / self._profile_states, 6
                )
                if self._profile_states
                else 0.0,
            }
            (
                self._active_sink_slice,
                self._active_slice_tier,
                self._remaining_slice_direct_states,
                self._remaining_slice_approx_states,
                self._current_sink_site,
                self._current_sink_tier,
                self._current_allow_approx,
                self._current_round_name,
                self._frontiers_in_current,
                self._frontier_sample_keys,
                self._profile_methods,
                self._profile_states,
                self._profile_library_states,
                self._profile_max_trace_depth,
                self._profile_max_call_depth,
            ) = previous

    def _record_profile_state(
        self, method: MethodRef, depth: int, call_depth: int
    ) -> None:
        """Record one explored state for the active sink slice."""
        if self._active_sink_slice is None:
            return
        self._profile_methods.add(method)
        self._profile_states += 1
        self._profile_max_trace_depth = max(self._profile_max_trace_depth, depth)
        self._profile_max_call_depth = max(self._profile_max_call_depth, call_depth)
        if not method.class_name.startswith(tuple(self._app_class_prefixes)):
            self._profile_library_states += 1

    def trace(
        self, method: MethodIR, register: int, before: int, purpose: str = "value"
    ) -> list[Origin]:
        purpose = self._canonical_purpose(purpose)
        outermost = self._request_level == 0
        if outermost:
            self._current_request = (
                f"{method.display()}@instruction[{before}]:v{register}:{purpose}"
            )
            multiplier = (
                self.resume_budget_multiplier
                if (
                    self._current_request in self.resume_roots
                    or report_reference(self._current_request) in self.resume_roots
                ) else 1
            )
            if multiplier > 1:
                self._resumed_roots_seen.add(self._current_request)
            direct_limit, approximate_limit = self._tier_request_limits()
            self._remaining_direct_states = direct_limit * multiplier
            self._remaining_approx_states = approximate_limit * multiplier
            self._current_max_depth = self.max_depth * multiplier
            self._reported_current = False
            if self._active_sink_slice is None:
                self._frontiers_in_current = 0
                self._frontier_sample_keys = set()

        self._request_level += 1
        try:
            if not outermost:
                return self._trace(method, register, before, purpose, frozenset(), 0)

            self._phase = "direct"
            direct = self._trace(method, register, before, purpose, frozenset(), 0)
            self._record_sink_evidence(direct, purpose)
            if not self._last_trace_complete:
                return direct
            if self._has_external_source(direct):
                self.approximation_skips += 1
                return direct

            # Scout only proves exact sink-argument provenance. Unknown or
            # indirect values are preserved for Promote instead of expanded here.
            if self._current_sink_tier == "scout":
                return direct

            approximate_budget_available = (
                self._remaining_total_approx_states is None
                or self._remaining_total_approx_states > 0
            )
            if not self._current_allow_approx or not approximate_budget_available:
                self.approximation_gates += 1
                self._record_frontier(
                    method,
                    register,
                    before,
                    purpose,
                    (
                        "approximation_not_promoted"
                        if not self._current_allow_approx
                        else "global_approximate_state_budget"
                    ),
                    0,
                )
                return direct

            self.approximation_passes += 1
            self._phase = "approximate"
            approximate = self._trace(method, register, before, purpose, frozenset(), 0)
            self._record_sink_evidence(approximate, purpose)
            if not self._last_trace_complete:
                return direct
            return self._limit([*direct, *approximate])
        finally:
            self._request_level -= 1
            if outermost:
                self._phase = "direct"
                self._current_max_depth = self.max_depth
                self._current_request = ""
                # Outside a trace, consumers such as IntentStateResolver and
                # component-root discovery retain the backend's full graph.
                self._set_backend_phase(True)

    def _tier_request_limits(self) -> tuple[int, int]:
        """Return request-local state caps for the active sink scheduling tier."""
        if self._current_sink_tier == "scout":
            return min(self.max_states_per_request, self.scout_states_per_request), 0
        if self._current_sink_tier == "promote":
            return (
                min(self.max_states_per_request, self.promote_states_per_request),
                min(
                    self.max_approx_states_per_request,
                    self.promote_approx_states_per_request,
                ),
            )
        return self.max_states_per_request, self.max_approx_states_per_request

    def trace_many(
        self,
        method: MethodIR,
        requests: Iterable[tuple[int, int, str]],
    ) -> dict[tuple[int, int, str], list[Origin]]:
        """Batch compatible CFG lanes, then solve each semantic fact safely.

        The reaching-definition phase carries all ``(register, before)`` lanes
        through the method CFG in one delta worklist.  Trace budgets, direct /
        approximate gating and memo entries remain request-local; one noisy
        lane therefore cannot consume or suppress another lane's result.
        """

        ordered = tuple(
            dict.fromkeys(
                (register, before, self._canonical_purpose(purpose))
                for register, before, purpose in requests
            )
        )
        if not ordered:
            return {}
        if len(ordered) > 1:
            self.batched_trace_calls += 1
            self.batched_trace_requests += len(ordered)
            self.max_trace_batch_width = max(self.max_trace_batch_width, len(ordered))
            self.backend.cfg_for(method).reaching_definitions_many(
                (register, before) for register, before, _purpose in ordered
            )
        return {
            request: self.trace(method, request[0], request[1], request[2]) for request in ordered
        }

    def prime_reaching_definitions(self, requests: Iterable[tuple[MethodIR, int, int]]) -> None:
        """Coalesce all known sink seeds per method before semantic tracing."""

        grouped: dict[MethodRef, tuple[MethodIR, list[tuple[int, int]]]] = {}
        for method, register, before in requests:
            item = grouped.get(method.method)
            if item is None:
                item = (method, [])
                grouped[method.method] = item
            item[1].append((register, before))
        for method, lanes in grouped.values():
            unique = tuple(dict.fromkeys(lanes))
            if len(unique) < 2:
                continue
            self.seed_batch_methods += 1
            self.seed_batch_requests += len(unique)
            self.backend.cfg_for(method).reaching_definitions_many(unique)

    def _trace(
        self,
        method: MethodIR,
        register: int,
        before: int,
        purpose: str,
        visited: frozenset[tuple[MethodRef, int, int, str]],
        depth: int,
    ) -> list[Origin]:
        """Dispatch deep work to a resumable iterative DFS."""
        if self._iterative_work is not None:
            return self._iterative_dependency(
                method, register, before, purpose, depth
            )
        if (
            self._current_sink_tier in {"promote", "deep"}
            and self._active_sink_slice is not None
        ):
            return self._trace_iterative(method, register, before, purpose, depth)
        return self._trace_recursive(
            method, register, before, purpose, visited, depth
        )

    def _trace_recursive(
        self,
        method: MethodIR,
        register: int,
        before: int,
        purpose: str,
        visited: frozenset[tuple[MethodRef, int, int, str]],
        depth: int,
    ) -> list[Origin]:
        del visited  # Global _active replaces path-local history.
        purpose = self._canonical_purpose(purpose)

        if depth > self._current_max_depth:
            self._depth_exhaustions += 1
            self._report_current_truncation("depth limit")
            self._record_frontier(method, register, before, purpose, "depth_limit", depth)
            return []

        state = self._state(method, register, before, purpose, self._phase)
        cached = self._memo_get(state)
        if cached is not None:
            self.cache_hits += 1
            return list(cached)

        # Do not open speculative edges for a subproblem whose direct solution
        # already reaches a modeled external source.
        if self._phase == "approximate":
            direct_state = self._state(method, register, before, purpose, "direct")
            direct = self._memo_get(direct_state)
            if direct is not None and self._has_external_source(direct):
                self.approximation_skips += 1
                self._memo_store(state, direct)
                return list(direct)

        if state in self._active:
            self._cycle_cutoffs += 1
            return []
        exhausted = self._consume_state()
        if exhausted is not None:
            self._record_sink_signal("frontier_progress")
            self._record_frontier(
                method, register, before, purpose, exhausted.replace(" ", "_"), depth
            )
            return []

        self._record_profile_state(method.method, depth, len(self._call_frames))
        self.cache_misses += 1
        if depth > 0:
            self._record_sink_signal("frontier_progress")
        budget_epoch = self._budget_exhaustions
        depth_epoch = self._depth_exhaustions
        cycle_epoch = self._cycle_cutoffs
        self._active.add(state)
        previous_backend_phase = self._backend_phase()
        self._set_backend_phase(self._phase == "approximate")
        try:
            # A completed state is deduplicated/capped exactly once here.
            result = self._limit(
                self._trace_uncached(method, register, before, purpose, frozenset(), depth)
            )
        finally:
            self._active.discard(state)
            self._set_backend_phase(previous_backend_phase)

        # Never memoize an answer made partial by a descendant cutoff.
        if (
            budget_epoch == self._budget_exhaustions
            and depth_epoch == self._depth_exhaustions
            and cycle_epoch == self._cycle_cutoffs
        ):
            self._memo_store(state, tuple(result))
        elif cycle_epoch != self._cycle_cutoffs:
            self.cycle_tainted_states_not_cached += 1
        return result

    def _trace_iterative(
        self,
        method: MethodIR,
        register: int,
        before: int,
        purpose: str,
        depth: int,
    ) -> list[Origin]:
        """Run or resume one deep root without revisiting completed states."""
        purpose = self._canonical_purpose(purpose)
        root = self._state(method, register, before, purpose, self._phase)
        cached = self._memo_get(root)
        if cached is not None:
            self.cache_hits += 1
            self._last_trace_complete = True
            return list(cached)

        continuation_key = (self._current_sink_site, root)
        continuation = self._deep_continuations.get(continuation_key)
        if continuation is None:
            continuation = _TraceContinuation(
                root=root,
                stack=[
                    _TraceWork(
                        method=method.method,
                        register=register,
                        before=before,
                        purpose=purpose,
                        depth=depth,
                        phase=self._phase,
                        interest_profile=self._interest_profile,
                        call_frames=self._call_frames,
                        ancestors=frozenset(),
                    )
                ],
                results={},
                references={},
                cycle_tainted=set(),
            )
            self._deep_continuations[continuation_key] = continuation

        previous_continuation = self._iterative_continuation
        self._iterative_continuation = continuation
        try:
            while continuation.stack:
                work = continuation.stack.pop()
                state = self._work_state(work)
                cached = continuation.results.get(state)
                if cached is None:
                    cached = self._memo_get(state)
                if cached is not None:
                    continuation.results[state] = cached
                    continue

                if work.depth > self._current_max_depth:
                    self._depth_exhaustions += 1
                    self._report_current_truncation("depth limit")
                    self._record_frontier(
                        self.backend.methods[work.method],
                        work.register,
                        work.before,
                        work.purpose,
                        "depth_limit",
                        work.depth,
                    )
                    continuation.cycle_tainted.update(work.ancestors | {state})
                    continuation.results[state] = ()
                    continue

                if not work.charged:
                    previous_phase = self._phase
                    self._phase = work.phase
                    try:
                        exhausted = self._consume_state()
                    finally:
                        self._phase = previous_phase
                    if exhausted is not None:
                        continuation.stack.append(work)
                        self._record_sink_signal("frontier_progress")
                        self._record_frontier(
                            self.backend.methods[work.method],
                            work.register,
                            work.before,
                            work.purpose,
                            exhausted.replace(" ", "_"),
                            work.depth,
                        )
                        self._last_trace_complete = False
                        return []
                    work.charged = True
                    self._record_profile_state(
                        work.method, work.depth, len(work.call_frames)
                    )
                    self.cache_misses += 1

                previous_context = (
                    self._phase,
                    self._interest_profile,
                    self._call_frames,
                    self._iterative_work,
                    self._iterative_dependencies,
                )
                self._phase = work.phase
                self._interest_profile = work.interest_profile
                self._call_frames = work.call_frames
                self._iterative_work = work
                self._iterative_dependencies = []
                previous_backend_phase = self._backend_phase()
                self._set_backend_phase(work.phase == "approximate")
                try:
                    result = self._limit(
                        self._trace_uncached(
                            self.backend.methods[work.method],
                            work.register,
                            work.before,
                            work.purpose,
                            frozenset(),
                            work.depth,
                        )
                    )
                    dependencies = self._unique_iterative_dependencies(
                        self._iterative_dependencies
                    )
                finally:
                    self._set_backend_phase(previous_backend_phase)
                    (
                        self._phase,
                        self._interest_profile,
                        self._call_frames,
                        self._iterative_work,
                        self._iterative_dependencies,
                    ) = previous_context

                if dependencies:
                    # ponytail: replay only this cheap transfer after its children
                    # finish; add per-opcode cursors only if profiling shows a need.
                    work.dependencies = tuple(
                        self._work_state(dependency) for dependency in dependencies
                    )
                    for dependency_state in work.dependencies:
                        continuation.references[dependency_state] = (
                            continuation.references.get(dependency_state, 0) + 1
                        )
                    continuation.stack.append(work)
                    continuation.stack.extend(reversed(dependencies))
                    continue

                frozen = tuple(result)
                continuation.results[state] = frozen
                if state not in continuation.cycle_tainted:
                    self._memo_store(state, frozen)
                self._release_iterative_dependencies(continuation, work)

            result = list(continuation.results.get(root, ()))
            self._deep_continuations.pop(continuation_key, None)
            self._last_trace_complete = True
            return result
        finally:
            self._iterative_continuation = previous_continuation

    def _iterative_dependency(
        self,
        method: MethodIR,
        register: int,
        before: int,
        purpose: str,
        depth: int,
    ) -> list[Origin]:
        """Return a completed child or schedule it on the active DFS stack."""
        purpose = self._canonical_purpose(purpose)
        state = self._state(method, register, before, purpose, self._phase)
        continuation = self._iterative_continuation
        work = self._iterative_work
        if continuation is None or work is None:
            return []
        cached = continuation.results.get(state)
        if cached is None:
            cached = self._memo_get(state)
        if cached is not None:
            self.cache_hits += 1
            return list(cached)
        current_state = self._work_state(work)
        if state == current_state or state in work.ancestors:
            self._cycle_cutoffs += 1
            continuation.cycle_tainted.update(work.ancestors | {current_state})
            return []
        self._iterative_dependencies.append(
            _TraceWork(
                method=method.method,
                register=register,
                before=before,
                purpose=purpose,
                depth=depth,
                phase=self._phase,
                interest_profile=self._interest_profile,
                call_frames=self._call_frames,
                ancestors=work.ancestors | {current_state},
            )
        )
        return []

    def _work_state(self, work: _TraceWork) -> TraceState:
        """Build a trace key without mutating the active analysis context."""
        return (
            work.method,
            work.register,
            work.before,
            work.purpose,
            work.interest_profile,
            work.phase,
            tuple(
                (frame.caller, frame.call_index, frame.callee)
                for frame in work.call_frames
            ),
        )

    def _unique_iterative_dependencies(
        self, dependencies: list[_TraceWork]
    ) -> list[_TraceWork]:
        """Preserve DFS order while removing duplicate child states."""
        unique: list[_TraceWork] = []
        seen: set[TraceState] = set()
        for dependency in dependencies:
            state = self._work_state(dependency)
            if state not in seen:
                seen.add(state)
                unique.append(dependency)
        return unique

    def _release_iterative_dependencies(
        self, continuation: _TraceContinuation, work: _TraceWork
    ) -> None:
        """Drop child results as soon as their parent has absorbed them."""
        for state in work.dependencies:
            remaining = continuation.references.get(state, 0) - 1
            if remaining > 0:
                continuation.references[state] = remaining
                continue
            continuation.references.pop(state, None)
            if state != continuation.root:
                continuation.results.pop(state, None)

    def discard_sink_continuations(self, sink_site: str) -> None:
        """Release unfinished iterative work after a sink is finalized."""
        for key in [key for key in self._deep_continuations if key[0] == sink_site]:
            self._deep_continuations.pop(key, None)

    def _memo_get(self, state: TraceState) -> tuple[Origin, ...] | None:
        if self._iterative_continuation is not None:
            local = self._iterative_continuation.results.get(state)
            if local is not None:
                return local
        value = self._memo.get(state)
        if value is not None:
            self._memo.move_to_end(state)
        return value

    def _memo_store(self, state: TraceState, value: tuple[Origin, ...]) -> None:
        self._memo[state] = value
        self._memo.move_to_end(state)
        if len(self._memo) > self.max_trace_cache_entries:
            self._memo.popitem(last=False)
            self.cache_evictions += 1
        self.peak_cache_entries = max(self.peak_cache_entries, len(self._memo))

    def _trace_uncached(
        self,
        method: MethodIR,
        register: int,
        before: int,
        purpose: str,
        visited: frozenset[tuple[MethodRef, int, int, str]],
        depth: int,
    ) -> list[Origin]:
        """Base transfer functions with relevance pruning and no path history."""
        reaching = self.backend.cfg_for(method).reaching_definitions(register, before)
        results: list[Origin] = []

        for index in reaching.instruction_indices:
            instruction = method.instructions[index]
            if instruction.name.startswith("move") and not instruction.name.startswith(
                "move-result"
            ):
                if len(instruction.registers) >= 2:
                    origins = self._trace(
                        method,
                        instruction.registers[1],
                        index,
                        purpose,
                        visited,
                        depth + 1,
                    )
                    results.extend(self._steps(origins, method, index, "register move"))
                    if purpose == "control" and self._phase == "direct":
                        results.extend(
                            self._definition_control_origins(
                                method, index, visited, depth + 1
                            )
                        )
                continue
            if instruction.name.startswith("const-string"):
                results.append(
                    Origin(
                        "constant",
                        value=instruction.string_value,
                        method=method.display(),
                        offset=instruction.offset,
                    )
                )
                if purpose == "control" and self._phase == "direct":
                    results.extend(
                        self._definition_control_origins(
                            method, index, visited, depth + 1
                        )
                    )
                continue
            if instruction.name.startswith("const-class"):
                results.append(
                    Origin(
                        "constant",
                        field="class",
                        value=instruction.string_value,
                        method=method.display(),
                        offset=instruction.offset,
                    )
                )
                if purpose == "control" and self._phase == "direct":
                    results.extend(
                        self._definition_control_origins(
                            method, index, visited, depth + 1
                        )
                    )
                continue
            if instruction.name.startswith("const"):
                results.append(
                    Origin(
                        "constant",
                        value=instruction.literal_value,
                        method=method.display(),
                        offset=instruction.offset,
                    )
                )
                if purpose == "control" and self._phase == "direct":
                    results.extend(
                        self._definition_control_origins(
                            method, index, visited, depth + 1
                        )
                    )
                continue
            if instruction.name.startswith("move-result") and index > 0:
                call = method.instructions[index - 1]
                if call.name.startswith("invoke-"):
                    origins = self._trace_call_result(
                        method, index - 1, purpose, visited, depth + 1
                    )
                    results.extend(self._steps(origins, method, index, "store call result"))
                continue
            if instruction.name.startswith("new-instance"):
                results.extend(
                    self._trace_constructor_arguments(
                        method,
                        register,
                        index,
                        before,
                        purpose,
                        visited,
                        depth + 1,
                    )
                )
                continue
            if instruction.name.startswith(("iget", "sget")) and instruction.reference:
                field_origins: list[Origin] = []
                writers = list(self.backend.field_writes.get(instruction.reference, []))
                # For instance fields, prefer writes whose receiver resolves to
                # the same allocation/field/getter token as the read receiver.
                # If Androguard cannot prove an object identity, retain every
                # writer so this precision step cannot introduce a false negative.
                if instruction.name.startswith("iget") and len(instruction.registers) >= 2:
                    read_keys = set(
                        self.backend.object_keys(
                            method, instruction.registers[1], index
                        )
                    )
                    matching = []
                    if read_keys:
                        for writer, writer_index, value_register in writers:
                            writer_method = self.backend.methods[writer]
                            writer_instruction = writer_method.instructions[writer_index]
                            if len(writer_instruction.registers) < 2:
                                continue
                            write_keys = set(
                                self.backend.object_keys(
                                    writer_method,
                                    writer_instruction.registers[1],
                                    writer_index,
                                )
                            )
                            if read_keys & write_keys:
                                matching.append((writer, writer_index, value_register))
                    if matching:
                        writers = matching
                writers = sorted(
                    writers,
                    key=lambda item: (
                        not self._method_has_external_source_hint(item[0]),
                        item[0].display(),
                        item[1],
                    ),
                )[: self.max_fanout]
                for writer, writer_index, value_register in writers:
                    writer_method = self.backend.methods[writer]
                    field_origins.extend(
                        self._trace(
                            writer_method,
                            value_register,
                            writer_index,
                            purpose,
                            visited,
                            depth + 1,
                        )
                    )
                results.extend(
                    self._steps(
                        field_origins,
                        method,
                        index,
                        "field read",
                        evidence={
                            "execution_boundary": {
                                "kind": "STATE_TRANSFER",
                                "reason": "value_provenance_without_execution_order",
                            },
                        },
                    )
                )
                continue
            if instruction.name.startswith(
                (
                    "add-",
                    "sub-",
                    "mul-",
                    "div-",
                    "rem-",
                    "and-",
                    "or-",
                    "xor-",
                    "shl-",
                    "shr-",
                    "ushr-",
                    "rsub-",
                    "aget",
                    "instance-of",
                )
            ):
                if not self._operation_is_relevant(instruction.name, purpose):
                    continue
                origins: list[Origin] = []
                source_registers = instruction.registers[1:]
                if instruction.name.startswith("aget-object"):
                    source_registers = source_registers[:1]
                for source_register in source_registers:
                    origins.extend(
                        self._trace(
                            method,
                            source_register,
                            index,
                            purpose,
                            visited,
                            depth + 1,
                        )
                    )
                results.extend(self._steps(origins, method, index, "value operation"))

        if reaching.reaches_entry:
            frame = self._call_frames[-1] if self._call_frames else None
            parameter = method.parameters.get(register)
            if parameter is not None:
                formal_index, dex_type = parameter
                self._record_sink_signal("entry_boundary_progress")
                if any(
                    marker in dex_type
                    for marker in (
                        "Landroid/content/Intent;",
                        "Landroid/os/Bundle;",
                        "Landroid/net/Uri;",
                        "Landroid/content/ClipData;",
                    )
                ):
                    self._record_sink_signal("intent_typed_dependency")
                entry_origin = self.backend.entry_parameter_origin(method, formal_index, dex_type)
                if entry_origin is not None:
                    results.append(entry_origin)
                exact_actual = (
                    dict(frame.actuals).get(formal_index)
                    if frame is not None and frame.callee == method.method
                    else None
                )
                if exact_actual is not None and frame is not None:
                    caller = self.backend.methods[frame.caller]
                    with self._caller_context():
                        origins = self._trace(
                            caller,
                            exact_actual,
                            frame.call_index,
                            purpose,
                            visited,
                            depth + 1,
                        )
                    results.extend(
                        self._steps(
                            origins,
                            caller,
                            frame.call_index,
                            f"exact actual argument -> {method.display()} parameter[{formal_index}]",
                            evidence={
                                "call_context": "exact",
                                "call_transition": build_call_transition(
                                    caller,
                                    frame.call_index,
                                    method.method,
                                    role="argument_transfer",
                                    selection="exact_call_context",
                                ),
                            },
                        )
                    )
                callsites = ()
                if frame is None or frame.callee != method.method:
                    callsites = sorted(
                        self.backend.callers.get(method.method, []),
                        key=lambda item: (
                            not self._method_has_external_source_hint(item.caller),
                            item.caller.display(),
                            item.instruction_index,
                        ),
                    )[: self.max_fanout]
                for callsite in callsites:
                    caller = self.backend.methods[callsite.caller]
                    call = caller.instructions[callsite.instruction_index]
                    actual = next(
                        (
                            actual_register
                            for formal, _actual_type, actual_register in invocation_formals(call)
                            if formal == formal_index
                        ),
                        None,
                    )
                    if actual is None:
                        continue
                    origins = self._trace(
                        caller,
                        actual,
                        callsite.instruction_index,
                        purpose,
                        visited,
                        depth + 1,
                    )
                    results.extend(
                        self._steps(
                            origins,
                            caller,
                            callsite.instruction_index,
                            f"actual argument -> {method.display()} parameter[{formal_index}]",
                            evidence={
                                "call_transition": build_call_transition(
                                    caller,
                                    callsite.instruction_index,
                                    method.method,
                                    role="argument_transfer",
                                    selection="observed_caller",
                                ),
                            },
                        )
                    )
                reactive_sources = sorted(
                    self.backend.reactive_sources(method.method, formal_index),
                    key=lambda item: (
                        not self._method_has_external_source_hint(item[0]),
                        item[0].display(),
                        item[1],
                    ),
                )[: self.max_fanout]
                for (
                    publisher,
                    publish_index,
                    value_register,
                    relation,
                ) in reactive_sources:
                    publisher_method = self.backend.methods[publisher]
                    origins = self._trace(
                        publisher_method,
                        value_register,
                        publish_index,
                        purpose,
                        visited,
                        depth + 1,
                    )
                    results.extend(self._steps(origins, publisher_method, publish_index, relation))
            elif (
                frame is not None
                and frame.callee == method.method
                and method.receiver_register == register
                and frame.receiver is not None
            ):
                caller = self.backend.methods[frame.caller]
                with self._caller_context():
                    origins = self._trace(
                        caller,
                        frame.receiver,
                        frame.call_index,
                        purpose,
                        visited,
                        depth + 1,
                    )
                results.extend(
                    self._steps(
                        origins,
                        caller,
                        frame.call_index,
                        f"exact receiver -> {method.display()} this",
                        evidence={
                            "call_context": "exact",
                            "receiver": True,
                            "call_transition": build_call_transition(
                                caller,
                                frame.call_index,
                                method.method,
                                role="receiver_transfer",
                                selection="exact_call_context",
                            ),
                        },
                    )
                )
        return results

    def _trace_call_result(
        self,
        method: MethodIR,
        call_index: int,
        purpose: str,
        visited: frozenset[tuple[MethodRef, int, int, str]],
        depth: int,
    ) -> list[Origin]:
        call = method.instructions[call_index]
        parsed = parse_method_reference(call.reference)
        receiver = invocation_receiver(call)
        if purpose == "intent" and parsed is not None and not return_may_hold_intent(parsed[2]):
            return []
        if parsed is not None:
            owner, name, descriptor = parsed
            if external_field_api(name, owner) is not None:
                self._record_sink_signal("source_api_encountered")
                self._record_sink_signal("intent_typed_dependency")
            elif name == "getIntent" and owner.endswith(("Activity;", "ActivityCompat;")):
                self._record_sink_signal("source_api_encountered")
                self._record_sink_signal("intent_typed_dependency")
                self._record_sink_signal("whole_intent_influence")
            if any(
                marker in owner or marker in descriptor
                for marker in (
                    "Landroid/content/Intent;",
                    "Landroid/os/Bundle;",
                    "Landroid/net/Uri;",
                    "Landroid/content/ClipData;",
                )
            ):
                self._record_sink_signal("intent_typed_dependency")

        # A property getter on a value obtained from another object is best
        # solved from that concrete receiver first. Expanding every write to a
        # commonly named model field (url, data, value, ...) before following
        # the receiver creates thousands of unrelated constructor paths and can
        # exhaust the depth budget before reaching Bundle/Intent transport.
        if (
            self._phase == "approximate"
            and parsed is not None
            and receiver is not None
            and not invocation_formals(call)
            and parsed[1].startswith(("get", "is"))
            and not parsed[2].endswith(")V")
        ):
            receiver_origins = self._trace(
                method,
                receiver,
                call_index,
                "object",
                visited,
                depth + 1,
            )
            if self._has_external_source(receiver_origins):
                return self._steps(
                    receiver_origins,
                    method,
                    call_index,
                    "concrete receiver state -> internal getter result",
                    edge_type="OBJECT_STATE_READ",
                    direct=True,
                    evidence={"state_semantics": "receiver_first_getter"},
                )

        results = super()._trace_call_result(method, call_index, purpose, visited, depth)

        # Container reconstruction can return the transported whole extras
        # Bundle after the base call has already selected a writer.  Restore
        # the constant read key here as well so that this late path has the
        # same field identity as a receiver-first Bundle read.
        if parsed is not None and receiver is not None:
            owner, name, _descriptor = parsed
            is_key_value_container = getattr(
                self.backend, "_is_key_value_container", lambda _owner: False
            )
            if is_key_value_container(owner) and (
                name.startswith("get") or name == "containsKey"
            ):
                key_register = next(
                    (
                        actual
                        for formal, dex_type, actual in invocation_formals(call)
                        if formal == 0 and dex_type == "Ljava/lang/String;"
                    ),
                    None,
                )
                local_constant = getattr(self.backend, "_local_string_constant", None)
                key = (
                    local_constant(method, key_register, call_index)
                    if callable(local_constant) and key_register is not None
                    else None
                )
                if key is None and key_register is not None:
                    key = self.constant(method, key_register, call_index)
                projected = [
                    Origin(
                        origin.kind,
                        api=call.reference,
                        field="extra",
                        key=str(key) if key is not None else origin.key,
                        value=origin.value,
                        component=origin.component,
                        method=origin.method,
                        offset=origin.offset,
                        path=origin.path,
                    )
                    if origin.kind in {"external_field", "component_field"}
                    and origin.field in {"extras", "extra"}
                    and origin.key is None
                    else origin
                    for origin in results
                ]
                if projected != results:
                    results = self._steps(
                        projected,
                        method,
                        call_index,
                        "keyed container field read",
                        edge_type="CONTAINER_FIELD_READ",
                        direct=key is not None,
                    evidence={
                        "state_semantics": "carrier_field_projection",
                        "container_key": str(key) if key is not None else None,
                        "execution_boundary": {
                            "kind": "STATE_TRANSFER",
                            "reason": "value_provenance_without_execution_order",
                        },
                    },
                    )

        # Model value-carrying builder/factory objects from bytecode evidence,
        # rather than from API-specific setter names.  If a callee stores one
        # of its formal parameters into an instance field, that actual value
        # becomes part of the receiver state returned by a fluent call.
        if self._call_returns_mutated_receiver(method, call_index):
            results.extend(
                self._trace_state_write_arguments(
                    method, call_index, purpose, visited, depth + 1
                )
            )

        # Receiver-to-getter is an object-state approximation and is delayed.
        if self._phase != "approximate":
            return results

        if parsed is None or receiver is None:
            return results
        _owner, name, descriptor = parsed
        targets = self.backend.call_targets.get((method.method, call_index), [])
        if (
            not targets
            or invocation_formals(call)
            or not name.startswith(("get", "is"))
            or descriptor.endswith(")V")
        ):
            return results

        receiver_origins = self._trace(
            method,
            receiver,
            call_index,
            "object",
            visited,
            depth + 1,
        )
        receiver_origins = self._steps(
            receiver_origins,
            method,
            call_index,
            "object receiver state -> internal getter result",
        )
        return [*results, *receiver_origins]

    def _contextual_container_sources(
        self, method: MethodIR, call_index: int
    ) -> tuple[tuple[MethodRef, int, int, str], ...]:
        """Resolve a wrapper's container and slot from its exact caller."""

        frame = self._call_frames[-1] if self._call_frames else None
        if frame is None or frame.callee != method.method:
            return self.backend.container_sources(method, call_index)
        call = method.instructions[call_index]
        receiver = invocation_receiver(call)
        if receiver is None:
            return self.backend.container_sources(method, call_index)
        parameter = method.parameters.get(receiver)
        if parameter is None:
            return self.backend.container_sources(method, call_index)
        actual = dict(frame.actuals).get(parameter[0])
        if actual is None:
            return self.backend.container_sources(method, call_index)
        caller = self.backend.methods[frame.caller]
        object_keys = self.backend.object_keys(caller, actual, frame.call_index)

        key_override = None
        formals = invocation_formals(call)
        key_register = next(
            (
                value
                for formal, dex_type, value in formals
                if formal == 0 and dex_type == "Ljava/lang/String;"
            ),
            None,
        )
        if key_register is not None:
            key_parameter = method.parameters.get(key_register)
            key_actual = (
                dict(frame.actuals).get(key_parameter[0])
                if key_parameter is not None
                else None
            )
            if key_actual is not None:
                key_override = self.backend._local_string_constant(
                    caller, key_actual, frame.call_index
                )
        return self.backend.container_sources(
            method,
            call_index,
            object_keys_override=object_keys,
            key_override=key_override,
        )

    def _trace_state_write_arguments(
        self,
        method: MethodIR,
        call_index: int,
        purpose: str,
        visited: frozenset[tuple[MethodRef, int, int, str]],
        depth: int,
    ) -> list[Origin]:
        """Trace actuals proven to be stored in the called object's state."""

        call = method.instructions[call_index]
        result: list[Origin] = []
        for target in self.backend.call_targets.get((method.method, call_index), ())[
            : self.max_fanout
        ]:
            target_method = self.backend.methods.get(target)
            if target_method is None:
                continue
            stored_formals = self._receiver_field_stored_formals(target_method)
            for formal, _dex_type, actual in invocation_formals(call):
                if formal not in stored_formals:
                    continue
                origins = self._trace(
                    method, actual, call_index, purpose, visited, depth + 1
                )
                result.extend(
                    self._steps(
                        origins,
                        method,
                        call_index,
                        f"actual argument stored in {target.display()} receiver state",
                        edge_type="OBJECT_STATE_WRITE",
                        direct=self._state_writer_call_is_direct(
                            method, call_index, target
                        ),
                        evidence={
                            "state_semantics": "formal_to_receiver_field",
                            "callee": target.display(),
                            "formal_index": formal,
                        },
                    )
                )
        return self._limit(result)

    @staticmethod
    def _receiver_field_stored_formals(method: MethodIR) -> set[int]:
        """Return formals directly written to fields owned by the callee class."""

        parameter_by_register = {
            register: formal for register, (formal, _type) in method.parameters.items()
        }
        result: set[int] = set()
        for instruction in method.instructions:
            if (
                not instruction.name.startswith("iput")
                or not instruction.reference
                or len(instruction.registers) < 2
            ):
                continue
            field_owner = instruction.reference.split("->", 1)[0]
            if field_owner != method.method.class_name:
                continue
            formal = parameter_by_register.get(instruction.registers[0])
            if formal is not None:
                result.add(formal)
        return result

    def _call_returns_mutated_receiver(
        self, method: MethodIR, call_index: int
    ) -> bool:
        """Prove that a fluent call returns the same object it mutated."""

        for target in self.backend.call_targets.get((method.method, call_index), ())[
            : self.max_fanout
        ]:
            target_method = self.backend.methods.get(target)
            if target_method is None:
                continue
            receiver_registers = {
                instruction.registers[1]
                for instruction in target_method.instructions
                if instruction.name.startswith("iput")
                and instruction.reference
                and instruction.reference.split("->", 1)[0] == target.class_name
                and len(instruction.registers) >= 2
            }
            if any(
                instruction.name.startswith("return-object")
                and instruction.registers
                and instruction.registers[0] in receiver_registers
                for instruction in target_method.instructions
            ):
                return True
        return False

    def _state_writer_call_is_direct(
        self, method: MethodIR, call_index: int, target: MethodRef
    ) -> bool:
        call = method.instructions[call_index]
        if call.name.startswith(("invoke-direct", "invoke-static")):
            return True
        parsed = parse_method_reference(call.reference)
        if parsed is not None and parsed[0] == target.class_name:
            proof = getattr(self.backend, "confirmed_dispatch", None)
            if callable(proof):
                return proof(method.method, call_index, target) is not None
        return False

    def _trace_constructor_arguments(
        self,
        method: MethodIR,
        register: int,
        allocation_index: int,
        before: int,
        purpose: str,
        visited: frozenset[tuple[MethodRef, int, int, str]],
        depth: int,
    ) -> list[Origin]:
        results: list[Origin] = []
        allocation_type = method.instructions[allocation_index].type_value
        for index in range(allocation_index + 1, min(before, len(method.instructions))):
            instruction = method.instructions[index]
            if destination_register(instruction) == register:
                break
            parsed = parse_method_reference(instruction.reference)
            if (
                parsed is None
                or parsed[1] != "<init>"
                or invocation_receiver(instruction) != register
            ):
                continue
            for _formal, _dex_type, actual in invocation_formals(instruction):
                origins = self._trace(
                    method,
                    actual,
                    index,
                    purpose,
                    visited,
                    depth + 1,
                )
                results.extend(self._steps(origins, method, index, "object constructor argument"))
            break
        # DownloadManager.enqueue() derives the remote resource from the URI
        # supplied to Request(Uri). Later setters configure metadata and the
        # destination, but mixing all of them into the download-URL slice
        # creates unrelated origins and can exhaust the trace budget.
        if allocation_type == "Landroid/app/DownloadManager$Request;":
            return results
        for index in range(allocation_index + 1, min(before, len(method.instructions))):
            instruction = method.instructions[index]
            if destination_register(instruction) == register:
                break
            if invocation_receiver(instruction) != register:
                continue
            results.extend(
                self._trace_state_write_arguments(
                    method, index, purpose, visited, depth + 1
                )
            )
        return results

    def _trace_mutations(
        self,
        method: MethodIR,
        register: int,
        before: int,
        purpose: str,
        visited: frozenset[tuple[MethodRef, int, int, str]],
        depth: int,
    ) -> list[Origin]:
        results: list[Origin] = []
        for index in range(before - 1, -1, -1):
            instruction = method.instructions[index]
            if invocation_receiver(instruction) == register:
                parsed = parse_method_reference(instruction.reference)
                if parsed and parsed[1] in {"append", "insert", "replace"}:
                    for _formal, _dex_type, actual in invocation_formals(instruction):
                        results.extend(
                            self._trace(
                                method,
                                actual,
                                index,
                                purpose,
                                visited,
                                depth + 1,
                            )
                        )
            if destination_register(instruction) == register:
                break
        return results

    @staticmethod
    def _canonical_purpose(purpose: str) -> str:
        # A constant query is a value query followed by a constant-only filter.
        return "value" if purpose == "constant" else purpose

    def _state(
        self,
        method: MethodIR,
        register: int,
        before: int,
        purpose: str,
        phase: str,
    ) -> TraceState:
        return (
            method.method,
            register,
            before,
            self._canonical_purpose(purpose),
            self._interest_profile,
            phase,
            tuple(
                (frame.caller, frame.call_index, frame.callee)
                for frame in self._call_frames
            ),
        )

    def _consume_state(self) -> str | None:
        if self._phase == "approximate":
            if (
                self._remaining_slice_approx_states is not None
                and self._remaining_slice_approx_states <= 0
            ):
                self.sink_slice_approx_exhaustions += 1
                self._record_truncation("sink-slice approximate-state budget")
                return "sink_slice_approximate_state_budget"
            if self._remaining_approx_states <= 0:
                self.approx_budget_exhaustions += 1
                self._record_truncation("approximate-state budget")
                return "approximate_state_budget"
            if self._remaining_total_approx_states is not None:
                if self._remaining_total_approx_states <= 0:
                    self.global_approx_budget_exhaustions += 1
                    self._record_truncation("global approximate-state budget")
                    return "global_approximate_state_budget"
                self._remaining_total_approx_states -= 1
            if self._remaining_slice_approx_states is not None:
                self._remaining_slice_approx_states -= 1
            self._remaining_approx_states -= 1
            self.approx_states_explored += 1
            return None

        if (
            self._remaining_slice_direct_states is not None
            and self._remaining_slice_direct_states <= 0
        ):
            self.sink_slice_direct_exhaustions += 1
            self._record_truncation("sink-slice direct-state budget")
            return "sink_slice_direct_state_budget"
        if self._remaining_direct_states <= 0:
            self.direct_budget_exhaustions += 1
            self._record_truncation("direct-state budget")
            return "direct_state_budget"
        if self._remaining_total_direct_states is not None:
            if self._remaining_total_direct_states <= 0:
                self.global_direct_budget_exhaustions += 1
                self._record_truncation("global direct-state budget")
                return "global_direct_state_budget"
            self._remaining_total_direct_states -= 1
        if self._remaining_slice_direct_states is not None:
            self._remaining_slice_direct_states -= 1
        self._remaining_direct_states -= 1
        self.direct_states_explored += 1
        return None

    @property
    def global_direct_budget_exhausted(self) -> bool:
        """Return whether no new direct state may be explored for this APK."""
        return (
            self._remaining_total_direct_states is not None
            and self._remaining_total_direct_states <= 0
        )

    @property
    def global_approx_budget_exhausted(self) -> bool:
        """Return whether no new approximate state may be explored for this APK."""
        return (
            self._remaining_total_approx_states is not None
            and self._remaining_total_approx_states <= 0
        )

    @property
    def remaining_total_direct_states(self) -> int | None:
        """Expose the app-wide direct budget for reporting and scheduling."""
        return self._remaining_total_direct_states

    @property
    def remaining_total_approx_states(self) -> int | None:
        """Expose the app-wide approximate budget for reporting and scheduling."""
        return self._remaining_total_approx_states

    def _method_has_external_source_hint(self, method_ref: MethodRef) -> bool:
        """Return a cached lexical hint used to rank relations before fanout capping."""
        cached = self._method_source_hint_cache.get(method_ref)
        if cached is not None:
            return cached
        method = self.backend.methods.get(method_ref)
        found = False
        if method is not None:
            for instruction in method.instructions:
                parsed = parse_method_reference(instruction.reference)
                if parsed is None:
                    continue
                owner, name, _descriptor = parsed
                if external_field_api(name, owner) is not None or (
                    name == "getIntent"
                    and owner.endswith(("Activity;", "ActivityCompat;"))
                ):
                    found = True
                    break
        self._method_source_hint_cache[method_ref] = found
        return found

    def _record_truncation(self, reason: str) -> None:
        self._budget_exhaustions += 1
        self._report_current_truncation(reason)

    def _report_current_truncation(self, reason: str) -> None:
        if not self._reported_current:
            self.truncation_count += 1
            self._reported_current = True

    def _record_frontier(
        self,
        method: MethodIR,
        register: int,
        before: int,
        purpose: str,
        reason: str,
        depth: int,
    ) -> None:
        round_name = self._current_round_name or self._current_sink_tier
        self.frontier_occurrences[(self._current_sink_site, round_name, reason)] += 1
        if self.analysis_frontier_sink is not None:
            self.analysis_frontier_sink(
                {
                    "kind": "trace_frontier",
                    "root_request": self._current_request,
                    "sink_site": self._current_sink_site,
                    "round": round_name,
                    "method": method.display(),
                    "register": register,
                    "before": before,
                    "purpose": purpose,
                    "phase": self._phase,
                    "reason": reason,
                    "depth": depth,
                }
            )
        key = (
            self._current_sink_site,
            round_name,
            method.method,
            register,
            before,
            purpose,
            self._phase,
            reason,
            depth,
        )
        if (
            self._frontiers_in_current >= self.max_frontiers_per_request
            or key in self._frontier_sample_keys
        ):
            return
        self._frontier_sample_keys.add(key)
        self._frontiers_in_current += 1
        self.unresolved_frontiers.append(
            TraceFrontier(
                root_request=self._current_request,
                sink_site=self._current_sink_site,
                method=method.display(),
                register=register,
                before=before,
                purpose=purpose,
                phase=self._phase,
                reason=reason,
                depth=depth,
            )
        )

    @staticmethod
    def _has_external_source(origins: list[Origin] | tuple[Origin, ...]) -> bool:
        return any(origin.external for origin in origins)

    def _record_sink_evidence(
        self,
        origins: list[Origin] | tuple[Origin, ...],
        purpose: str,
    ) -> None:
        """Retain structured runtime signals even before a full flow is assembled."""
        if self._current_sink_site is None:
            return
        signals = self.sink_evidence_signals[self._current_sink_site]
        for origin in origins:
            field_name = str(origin.field or "").lower()
            outer_field = str(origin.outer_field or "").lower()
            if origin.external:
                signals.add("external_input_dependency")
                if len(origin.path) <= 2:
                    signals.add("source_adjacent_frontier")
                if origin.component:
                    signals.add("exported_entry_direction")
            if origin.kind in {
                "external_intent",
                "external_field",
                "nested_external_intent",
            } or origin.key is not None:
                signals.add("intent_or_extra_origin")
            if origin.kind == "external_intent" or field_name == "whole_intent":
                signals.add("whole_intent_influence")
            if any(
                token in field_name or token in outer_field
                for token in ("uri", "data", "clip")
            ):
                signals.add("uri_or_clip_data")
            if purpose == "destination" or field_name in {
                "action",
                "component",
                "destination",
                "package",
                "data_uri",
            }:
                signals.add("destination_influence")
            if any(
                step.edge_type == "icc"
                or bool(step.evidence.get("icc_boundary"))
                for step in origin.path.iter_reverse()
            ):
                signals.add("icc_boundary")

    def _record_sink_signal(self, signal: str) -> None:
        """Attach a partial backward-progress signal to the active sink."""
        if self._current_sink_site is not None:
            self.sink_evidence_signals[self._current_sink_site].add(signal)

    def _operation_is_relevant(self, name: str, purpose: str) -> bool:
        category, interested_types = self._interest_profile
        if not interested_types and category == "generic":
            return True
        if purpose == "control":
            return True
        if name.startswith("aget-object"):
            return any(dex_type.startswith(("L", "[L")) for dex_type in interested_types)
        if name.startswith(("aget", "instance-of")):
            return False
        if category == "icc" and name.startswith(("and-", "or-", "xor-")):
            # Intent flags are primitive but remain relevant to injection flows.
            return True
        return any(
            dex_type[:1] in {"Z", "B", "S", "C", "I", "J", "F", "D"}
            for dex_type in interested_types
        )

    def _backend_phase(self) -> bool:
        return bool(getattr(self.backend, "approximation_enabled", True))

    def _set_backend_phase(self, approximation_enabled: bool) -> None:
        setter = getattr(self.backend, "set_trace_phase", None)
        if setter is not None:
            setter(
                approximation_enabled,
                self.max_approx_fanout,
                self._max_direct_fanout,
            )

    def _limit(self, origins: list[Origin]) -> list[Origin]:
        """Bound both external and non-external origins after route deduplication."""
        result: list[Origin] = []
        seen: set[tuple[Any, ...]] = set()
        for origin in origins:
            route_kinds: set[str] = set()
            predicate_precision: set[str] = set()
            for step in origin.path.iter_reverse():
                relation = step.relation.lower()
                instruction = step.instruction.lower()
                if "callback" in relation:
                    route_kinds.add("CALLBACK")
                if "collection" in relation:
                    route_kinds.add("COLLECTION_STATE")
                if "field" in relation:
                    route_kinds.add("FIELD_STATE")
                if "constructor" in relation or "object state" in relation:
                    route_kinds.add("OBJECT_STATE")
                if step.edge_type == "DISPATCH" or "invoke-interface" in instruction:
                    route_kinds.add("DISPATCH")
                predicate_correlation = step.evidence.get("predicate_correlation")
                if predicate_correlation:
                    predicate_precision.add(str(predicate_correlation))
            key = (
                origin.kind,
                origin.api,
                origin.field,
                origin.key,
                repr(origin.value),
                origin.component,
                origin.method,
                origin.offset,
                tuple(sorted(route_kinds)),
                tuple(sorted(predicate_precision)),
            )
            if key in seen:
                continue
            seen.add(key)
            result.append(origin)

        external_cap = min(self.max_paths, max(0, self.max_external_origins))
        external = [origin for origin in result if origin.external][:external_cap]
        others = [origin for origin in result if not origin.external]
        return [*external, *others[: max(0, self.max_paths - len(external))]]
