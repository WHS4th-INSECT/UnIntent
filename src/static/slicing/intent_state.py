from __future__ import annotations

import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any

from src.static.model.values import (
    IntentFact,
    IntentState,
    MethodIR,
    MethodRef,
    Origin,
    TraceStep,
)
from src.static.search.dex_ir import (
    destination_register,
    invocation_formals,
    invocation_receiver,
    parse_method_reference,
)
from src.static.slicing.backward import DemandTracer


CallContext = tuple[tuple[MethodRef, int], ...]
IntentWalkState = tuple[MethodRef, int, int, CallContext]

INTENT_URI_FACTORIES = {
    ("parseUri", "(Ljava/lang/String;I)Landroid/content/Intent;"),
    ("getIntent", "(Ljava/lang/String;)Landroid/content/Intent;"),
    ("getIntentOld", "(Ljava/lang/String;)Landroid/content/Intent;"),
}

DESTINATION_FIELDS = frozenset({"component", "class", "package"})
COMPONENT_SETTERS = frozenset({"setComponent", "setClass", "setClassName"})
COMPONENT_NAME = "Landroid/content/ComponentName;"
CONTEXT = "Landroid/content/Context;"

# Calls whose result is the same object as an argument: (owner, name) -> formal indices.
INTENT_IDENTITY_CALLS = {
    ("Ljava/util/Objects;", "requireNonNull"): (0,),
    ("Ljava/util/Objects;", "requireNonNullElse"): (0, 1),
    ("Ljava/util/Objects;", "requireNonNullElseGet"): (0,),
    ("Ljava/lang/Class;", "cast"): (0,),
}
# Calls whose result is a new Intent carrying another Intent's state; -1 is the receiver.
INTENT_DERIVING_CALLS = {
    ("Landroid/content/Intent;", "clone"): (-1,),
    ("Landroid/content/Intent;", "cloneFilter"): (-1,),
    # The chooser delivers the wrapped target Intent to the app the user picks.
    ("Landroid/content/Intent;", "createChooser"): (0,),
}
# Fields copied by Intent.cloneFilter (COPY_MODE_FILTER); flags, extras, selector and clip data are not.
CLONE_FILTER_FIELDS = frozenset(
    {"action", "data", "type", "category", "component", "class", "package"}
)

@dataclass
class _IntentWalkWork:
    """One resumable iterative-DFS frame for Intent object recovery."""

    method: MethodRef
    register: int
    before: int
    depth: int
    ancestors: frozenset[IntentWalkState]
    charged: bool = False
    dependencies: tuple[IntentWalkState, ...] = ()
    context: CallContext = ()


@dataclass
class _IntentWalkContinuation:
    """Intent walk state retained between fixed deep-analysis slices."""

    root: IntentWalkState
    stack: list[_IntentWalkWork]
    results: dict[IntentWalkState, IntentState]
    references: dict[IntentWalkState, int]


class IntentStateResolver:
    def __init__(
        self,
        tracer: DemandTracer,
        forward_refiner: Any | None = None,
        max_walk_states: int = 10000,
    ) -> None:
        self.tracer = tracer
        self.backend = tracer.backend
        self.forward_refiner = forward_refiner
        self.max_walk_states = max(1, max_walk_states)
        self.walk_states = 0
        self.walk_budget_exhaustions = 0
        self.peak_walk_states = 0
        self.instruction_visits = 0
        self.peak_instruction_visits = 0
        self.instruction_budget_exhaustions = 0
        self._request_walk_states = 0
        self._request_instruction_visits = 0
        self._request_budget_exhausted = False
        self._request_instruction_budget_exhausted = False
        self._remaining_slice_walk_states: int | None = None
        self._remaining_slice_instruction_visits: int | None = None
        self._deadline: float | None = None
        self._active_sink_site: str | None = None
        self._active_tier = "scout"
        self._deep_continuations: dict[
            tuple[str | None, IntentWalkState], _IntentWalkContinuation
        ] = {}
        self._resolved_states: dict[
            tuple[str | None, IntentWalkState], IntentState
        ] = {}
        self._iterative_continuation: _IntentWalkContinuation | None = None
        self._iterative_work: _IntentWalkWork | None = None
        self._iterative_dependencies: list[_IntentWalkWork] = []
        self._last_resolve_complete = True

    @contextmanager
    def sink_analysis_slice(
        self,
        *,
        walk_states: int,
        instruction_visits: int,
        deadline: float | None,
        sink_site: str | None = None,
        tier: str = "scout",
    ) -> Iterator[None]:
        """Bound all Intent-state work performed for one scheduled sink pass."""
        previous = (
            self._remaining_slice_walk_states,
            self._remaining_slice_instruction_visits,
            self._deadline,
            self._active_sink_site,
            self._active_tier,
        )
        self._remaining_slice_walk_states = max(0, walk_states)
        self._remaining_slice_instruction_visits = max(0, instruction_visits)
        self._deadline = deadline
        self._active_sink_site = sink_site
        self._active_tier = tier
        try:
            yield
        finally:
            (
                self._remaining_slice_walk_states,
                self._remaining_slice_instruction_visits,
                self._deadline,
                self._active_sink_site,
                self._active_tier,
            ) = previous

    def resolve(self, method: MethodIR, register: int, before: int) -> IntentState:
        if self._deadline is not None and time.monotonic() >= self._deadline:
            raise TimeoutError("Intent dispatch analysis timed out")
        self._request_walk_states = 0
        self._request_instruction_visits = 0
        self._request_budget_exhausted = False
        self._request_instruction_budget_exhausted = False
        self._last_resolve_complete = True
        result = self._resolve(method, register, before, frozenset(), 0)
        self.walk_states += self._request_walk_states
        self.peak_walk_states = max(self.peak_walk_states, self._request_walk_states)
        self.instruction_visits += self._request_instruction_visits
        self.peak_instruction_visits = max(
            self.peak_instruction_visits,
            self._request_instruction_visits,
        )
        if self._remaining_slice_walk_states is not None:
            self._remaining_slice_walk_states = max(
                0,
                self._remaining_slice_walk_states - self._request_walk_states,
            )
        if self._remaining_slice_instruction_visits is not None:
            self._remaining_slice_instruction_visits = max(
                0,
                self._remaining_slice_instruction_visits
                - self._request_instruction_visits,
            )
        if self._request_budget_exhausted:
            self.walk_budget_exhaustions += 1
        if self._request_instruction_budget_exhausted:
            self.instruction_budget_exhaustions += 1
        # The object-state walk is intentionally mutation ordered, but a DEX
        # register can be reused in a mutually exclusive branch that appears
        # later in bytecode order.  Recover only parsed-Intent factories from
        # the CFG-aware reaching-definition tracer here; admitting arbitrary
        # fallback origins would incorrectly turn payload-only values into a
        # whole attacker-controlled Intent.
        if (
            self._last_resolve_complete
            and not self._request_budget_exhausted
            and not any(
                origin.kind.startswith("uri_parsed_")
                for origin in (*result.object_origins, *result.pinned_object_origins)
            )
        ):
            parsed_origins = [
                origin
                for origin in self.tracer.trace(method, register, before, "intent")
                if origin.kind.startswith("uri_parsed_")
            ]
            if parsed_origins:
                result.add_origins(parsed_origins)
        if self._last_resolve_complete and self.forward_refiner is not None:
            return self.forward_refiner.refine(method, before, result)
        return result

    def _resolve(
        self,
        method: MethodIR,
        register: int,
        before: int,
        visited: frozenset[IntentWalkState],
        depth: int,
        context: CallContext = (),
    ) -> IntentState:
        """Dispatch deep Intent recovery to a resumable iterative DFS."""
        if self._iterative_work is not None:
            return self._iterative_dependency(method, register, before, depth, context)
        if (
            self._active_tier in {"promote", "deep"}
            and self._active_sink_site is not None
        ):
            return self._resolve_iterative(method, register, before, depth, context)
        return self._resolve_recursive(method, register, before, visited, depth, context)

    def _resolve_recursive(
        self,
        method: MethodIR,
        register: int,
        before: int,
        visited: frozenset[IntentWalkState],
        depth: int,
        context: CallContext = (),
    ) -> IntentState:
        if self._iterative_work is None:
            walk_limit = self.max_walk_states
            if self._remaining_slice_walk_states is not None:
                walk_limit = min(walk_limit, self._remaining_slice_walk_states)
            if self._request_walk_states >= walk_limit:
                self._request_budget_exhausted = True
                return IntentState()
            self._request_walk_states += 1
        if depth > self.tracer.max_depth:
            return IntentState()
        state_key = (method.method, register, before, context)
        if state_key in visited:
            return IntentState()
        next_visited = visited | {state_key}
        result = IntentState()
        state = result
        earlier_state: IntentState | None = None
        extras_replaced = False
        object_keys = getattr(self.backend, "object_keys", lambda *_args: ())
        tracked_keys = frozenset(object_keys(method, register, before))
        cfg_for = getattr(self.backend, "cfg_for", None)
        tracked_reaching = None
        if callable(cfg_for):
            reaching = cfg_for(method).reaching_definitions(register, before)
            tracked_reaching = reaching
            reaching_definitions = set(reaching.instruction_indices)
            reaches_entry = reaching.reaches_entry
        else:
            reaching_definitions = {
                index
                for index, instruction in enumerate(method.instructions[:before])
                if destination_register(instruction) == register
            }
            reaches_entry = not reaching_definitions

        scan_end = min(before, len(method.instructions))
        for index in range(scan_end - 1, -1, -1):
            if not self._consume_instruction():
                break
            instruction = method.instructions[index]
            # A reused register may hold another object at this instruction.
            same_value = (
                instruction.name.startswith("invoke-")
                and register in instruction.registers
                and self._holds_tracked_value(method, register, index, tracked_reaching)
            )
            if invocation_receiver(instruction) == register and same_value:
                receiver_keys = frozenset(object_keys(method, register, index))
                if not (
                    tracked_keys
                    and receiver_keys
                    and tracked_keys.isdisjoint(receiver_keys)
                ):
                    replaced, pins_destination = self._collect_intent_call(
                        state,
                        method,
                        index,
                        next_visited,
                        depth,
                        include_extras=not extras_replaced,
                        context=context,
                    )
                    extras_replaced = extras_replaced or replaced
                    if (
                        pins_destination
                        and earlier_state is None
                        and self._setter_pins_walk(
                            method, index, before, reaching_definitions
                        )
                    ):
                        earlier_state = IntentState()
                        state = earlier_state
            if instruction.name.startswith("invoke-") and same_value:
                actual_keys = frozenset(object_keys(method, register, index))
                if not (
                    tracked_keys
                    and actual_keys
                    and tracked_keys.isdisjoint(actual_keys)
                ):
                    self._collect_called_intent_mutations(
                        state,
                        method,
                        index,
                        register,
                        next_visited,
                        depth,
                    )
            if destination_register(instruction) != register:
                continue
            if reaching_definitions and index not in reaching_definitions:
                continue
            if instruction.name.startswith("check-cast"):
                continue
            if instruction.name.startswith("move") and not instruction.name.startswith(
                "move-result"
            ):
                if len(instruction.registers) >= 2:
                    state.extend(
                        self._resolve(
                            method, instruction.registers[1], index, next_visited, depth + 1, context,
                        )
                    )
                continue
            if instruction.name.startswith("move-result") and index > 0:
                call_index = index - 1
                call = method.instructions[call_index]
                parsed = parse_method_reference(call.reference)
                receiver = invocation_receiver(call)
                if (
                    parsed
                    and parsed[0] == "Landroid/content/Intent;"
                    and (parsed[1], parsed[2]) in INTENT_URI_FACTORIES
                ):
                    for _formal, dex_type, actual in invocation_formals(call):
                        if dex_type != "Ljava/lang/String;":
                            continue
                        for origin in self.tracer.trace(
                            method, actual, call_index, "value"
                        ):
                            state.add_origin(
                                Origin(
                                    "uri_parsed_external_intent"
                                    if origin.external
                                    else "uri_parsed_intent",
                                    api=origin.api or call.reference,
                                    field=origin.field,
                                    key=origin.key,
                                    value=origin.value,
                                    component=origin.component,
                                    method=origin.method or method.display(),
                                    offset=(
                                        origin.offset
                                        if origin.offset is not None
                                        else call.offset
                                    ),
                                    path=origin.path.append(
                                        TraceStep(
                                            method.display(),
                                            call.offset,
                                            call.text(),
                                            "external String/URI -> parsed Intent with destination control",
                                            "INTENT_URI_FACTORY",
                                            True,
                                            {"intent_uri_factory": call.reference},
                                        )
                                    ),
                                )
                            )
                    continue
                sources = self._pass_through_sources(call)
                if sources:
                    for source in sources:
                        earlier = self._resolve(
                            method, source, call_index, next_visited, depth + 1, context
                        )
                        if parsed[1] == "cloneFilter":
                            earlier.facts = [
                                fact for fact in earlier.facts if fact.field in CLONE_FILTER_FIELDS
                            ]
                        state.extend(earlier)
                    continue
                if (
                    parsed
                    and parsed[0] == "Landroid/content/Intent;"
                    and parsed[1].startswith(("set", "add", "put", "remove", "replace"))
                    and receiver is not None
                ):
                    replaced, pins_destination = self._collect_intent_call(
                        state, method, call_index, next_visited, depth, context=context
                    )
                    earlier = self._resolve(
                        method, receiver, call_index, next_visited, depth + 1, context
                    )
                    if replaced:
                        earlier.facts = [fact for fact in earlier.facts if fact.field != "extra"]
                    if pins_destination:
                        earlier = self._pin_destination(earlier)
                    state.extend(earlier)
                    continue
                targets = self.backend.call_targets.get((method.method, call_index), [])
                for target_ref in targets[: self.tracer.max_fanout]:
                    target = self.backend.methods[target_ref]
                    for return_index, returned in enumerate(target.instructions):
                        if returned.name.startswith("return-object") and returned.registers:
                            state.extend(
                                self._resolve(
                                    target,
                                    returned.registers[0],
                                    return_index,
                                    next_visited,
                                    depth + 1,
                                    ((method.method, call_index), *context),
                                )
                            )
                if targets:
                    continue
                state.add_origins(
                    self.tracer.trace(method, register, index + 1, "intent")
                )
                continue
            if instruction.name.startswith("new-instance"):
                continue
            state.add_origins(self.tracer.trace(method, register, index + 1, "intent"))
            continue

        if self._request_budget_exhausted:
            return self._merge_earlier(result, earlier_state)
        parameter = method.parameters.get(register) if reaches_entry else None
        if parameter is not None:
            formal_index, dex_type = parameter
            if not context:
                origin = self.backend.entry_parameter_origin(method, formal_index, dex_type)
                if origin is not None:
                    state.add_origin(origin)
            # Scout only decides whether a sink deserves direct provenance
            # recovery. Utility callers belong to Promote, which resumes this
            # same sink/root with the iterative resolver.
            if self._active_tier == "scout":
                return self._merge_earlier(result, earlier_state)
            if context:
                # The walk entered this method from one known call site to resolve
                # its return value; only that caller's argument reaches here.
                callsites = [context[0]]
                caller_context = context[1:]
            else:
                callsites = [
                    (callsite.caller, callsite.instruction_index)
                    for callsite in self.backend.callers.get(method.method, [])[
                        : self.tracer.max_fanout
                    ]
                ]
                caller_context = ()
            for caller_ref, call_index in callsites:
                caller = self.backend.methods[caller_ref]
                call = caller.instructions[call_index]
                actual = next(
                    (
                        actual_register
                        for formal, _dex_type, actual_register in invocation_formals(call)
                        if formal == formal_index
                    ),
                    None,
                )
                if actual is not None:
                    state.extend(
                        self._resolve(
                            caller,
                            actual,
                            call_index,
                            next_visited,
                            depth + 1,
                            caller_context,
                        )
                    )
        elif (
            tracked_reaching is None
            or reaches_entry
            or any(index >= scan_end for index in reaching_definitions)
        ):
            # The scan above already handled every reaching definition before
            # ``before`` with Intent semantics (pins, pass-through, callee mutations).
            # The generic tracer lacks those, so use it only for
            # definitions the scan cannot see: loop back-edges or no CFG.
            state.add_origins(self.tracer.trace(method, register, before, "intent"))
        return self._merge_earlier(result, earlier_state)

    def _merge_earlier(
        self, result: IntentState, earlier: IntentState | None
    ) -> IntentState:
        """Merge the walk part preceding a dominating component setter, destination pinned."""
        if earlier is not None:
            result.extend(self._pin_destination(earlier))
        return result

    @staticmethod
    def _pin_destination(state: IntentState) -> IntentState:
        """Drop overwritten destination facts and demote whole-Intent origins to pinned."""
        pinned = IntentState(
            facts=[fact for fact in state.facts if fact.field not in DESTINATION_FIELDS]
        )
        pinned.add_pinned_origins(state.pinned_object_origins)
        pinned.add_pinned_origins(state.object_origins)
        return pinned

    def _setter_pins_walk(
        self,
        method: MethodIR,
        setter_index: int,
        before: int,
        reaching_definitions: set[int],
    ) -> bool:
        """Check that a setter mutates the dispatched object on every path to ``before``."""
        cfg_for = getattr(self.backend, "cfg_for", None)
        if not callable(cfg_for):
            return False
        if any(index > setter_index for index in reaching_definitions):
            return False
        return cfg_for(method).instruction_dominates(setter_index, before)

    def _resolve_iterative(
        self,
        method: MethodIR,
        register: int,
        before: int,
        depth: int,
        context: CallContext = (),
    ) -> IntentState:
        """Run or resume one deep Intent walk from its exact pending state."""
        root = (method.method, register, before, context)
        continuation_key = (self._active_sink_site, root)
        resolved = self._resolved_states.get(continuation_key)
        if resolved is not None:
            self._last_resolve_complete = True
            return self._copy_state(resolved)
        continuation = self._deep_continuations.get(continuation_key)
        if continuation is None:
            continuation = _IntentWalkContinuation(
                root=root,
                stack=[
                    _IntentWalkWork(
                        method=method.method,
                        register=register,
                        before=before,
                        depth=depth,
                        ancestors=frozenset(),
                        context=context,
                    )
                ],
                results={},
                references={},
            )
            self._deep_continuations[continuation_key] = continuation

        previous_continuation = self._iterative_continuation
        self._iterative_continuation = continuation
        try:
            while continuation.stack:
                work = continuation.stack.pop()
                state = self._intent_work_state(work)
                if state in continuation.results:
                    continue
                if work.depth > self.tracer.max_depth:
                    continuation.results[state] = IntentState()
                    continue
                if not work.charged:
                    walk_limit = self.max_walk_states
                    if self._remaining_slice_walk_states is not None:
                        walk_limit = min(
                            walk_limit, self._remaining_slice_walk_states
                        )
                    if self._request_walk_states >= walk_limit:
                        continuation.stack.append(work)
                        self._request_budget_exhausted = True
                        self._last_resolve_complete = False
                        return IntentState()
                    self._request_walk_states += 1
                    work.charged = True

                previous_work = self._iterative_work
                previous_dependencies = self._iterative_dependencies
                self._iterative_work = work
                self._iterative_dependencies = []
                try:
                    result = self._resolve_recursive(
                        self.backend.methods[work.method],
                        work.register,
                        work.before,
                        work.ancestors,
                        work.depth,
                        work.context,
                    )
                    dependencies = self._unique_intent_dependencies(
                        self._iterative_dependencies
                    )
                finally:
                    self._iterative_work = previous_work
                    self._iterative_dependencies = previous_dependencies

                if dependencies:
                    # ponytail: replay only this local mutation scan after its
                    # children finish; completed child walks are never repeated.
                    work.dependencies = tuple(
                        self._intent_work_state(dependency)
                        for dependency in dependencies
                    )
                    for dependency_state in work.dependencies:
                        continuation.references[dependency_state] = (
                            continuation.references.get(dependency_state, 0) + 1
                        )
                    continuation.stack.append(work)
                    continuation.stack.extend(reversed(dependencies))
                    continue

                continuation.results[state] = self._copy_state(result)
                self._release_intent_dependencies(continuation, work)

            result = self._copy_state(
                continuation.results.get(root, IntentState())
            )
            self._resolved_states[continuation_key] = self._copy_state(result)
            self._deep_continuations.pop(continuation_key, None)
            self._last_resolve_complete = True
            return result
        finally:
            self._iterative_continuation = previous_continuation

    def _iterative_dependency(
        self,
        method: MethodIR,
        register: int,
        before: int,
        depth: int,
        context: CallContext = (),
    ) -> IntentState:
        """Return a finished child state or schedule it on the DFS stack."""
        continuation = self._iterative_continuation
        work = self._iterative_work
        if continuation is None or work is None:
            return IntentState()
        state = (method.method, register, before, context)
        cached = continuation.results.get(state)
        if cached is not None:
            return self._copy_state(cached)
        current_state = self._intent_work_state(work)
        if state == current_state or state in work.ancestors:
            return IntentState()
        self._iterative_dependencies.append(
            _IntentWalkWork(
                method=method.method,
                register=register,
                before=before,
                depth=depth,
                ancestors=work.ancestors | {current_state},
                context=context,
            )
        )
        return IntentState()

    @staticmethod
    def _intent_work_state(work: _IntentWalkWork) -> IntentWalkState:
        """Return the stable key of one Intent walk frame."""
        return (work.method, work.register, work.before, work.context)

    def _unique_intent_dependencies(
        self, dependencies: list[_IntentWalkWork]
    ) -> list[_IntentWalkWork]:
        """Preserve DFS order while removing duplicate child states."""
        unique: list[_IntentWalkWork] = []
        seen: set[IntentWalkState] = set()
        for dependency in dependencies:
            state = self._intent_work_state(dependency)
            if state not in seen:
                seen.add(state)
                unique.append(dependency)
        return unique

    @staticmethod
    def _copy_state(state: IntentState) -> IntentState:
        """Copy only the mutable containers, not their immutable evidence."""
        return IntentState(
            object_origins=list(state.object_origins),
            pinned_object_origins=list(state.pinned_object_origins),
            facts=list(state.facts),
        )

    def _release_intent_dependencies(
        self,
        continuation: _IntentWalkContinuation,
        work: _IntentWalkWork,
    ) -> None:
        """Drop child states after their parent has absorbed them."""
        for state in work.dependencies:
            remaining = continuation.references.get(state, 0) - 1
            if remaining > 0:
                continuation.references[state] = remaining
                continue
            continuation.references.pop(state, None)
            if state != continuation.root:
                continuation.results.pop(state, None)

    def discard_sink_continuations(self, sink_site: str) -> None:
        """Release unfinished and completed per-sink Intent walk state."""
        for cache in (self._deep_continuations, self._resolved_states):
            for key in [key for key in cache if key[0] == sink_site]:
                cache.pop(key, None)

    def _consume_instruction(self) -> bool:
        limit = self._remaining_slice_instruction_visits
        if (
            self._iterative_work is None
            and limit is not None
            and self._request_instruction_visits >= limit
        ):
            self._request_budget_exhausted = True
            self._request_instruction_budget_exhausted = True
            return False
        self._request_instruction_visits += 1
        if (
            self._deadline is not None
            and self._request_instruction_visits % 256 == 0
            and time.monotonic() >= self._deadline
        ):
            raise TimeoutError("Intent dispatch analysis timed out")
        return True

    def _collect_called_intent_mutations(
        self,
        state: IntentState,
        method: MethodIR,
        call_index: int,
        tracked_register: int,
        visited: frozenset[IntentWalkState],
        depth: int,
    ) -> None:
        call = method.instructions[call_index]
        matching_formals = {
            formal_index
            for formal_index, dex_type, actual_register in invocation_formals(call)
            if actual_register == tracked_register and dex_type == "Landroid/content/Intent;"
        }
        if not matching_formals:
            return
        targets = self.backend.call_targets.get((method.method, call_index), [])
        for target_ref in targets[: self.tracer.max_fanout]:
            target = self.backend.methods.get(target_ref)
            if target is None:
                continue
            for parameter_register, (formal_index, dex_type) in target.parameters.items():
                if formal_index not in matching_formals or dex_type != "Landroid/content/Intent;":
                    continue
                state.add_facts(
                    self._parameter_mutations(target, parameter_register, visited, depth + 1)
                )

    def _parameter_mutations(
        self,
        method: MethodIR,
        parameter_register: int,
        visited: frozenset[IntentWalkState],
        depth: int,
    ) -> list[IntentFact]:
        """Collect Intent mutations a callee applies to one Intent parameter."""
        walk_key = (method.method, parameter_register, -1, ())
        cfg_for = getattr(self.backend, "cfg_for", None)
        if depth > self.tracer.max_depth or walk_key in visited or not callable(cfg_for):
            return []
        next_visited = visited | {walk_key}
        cfg = cfg_for(method)
        memo: dict[tuple[int, int], bool] = {}
        local = IntentState()
        for index in range(len(method.instructions) - 1, -1, -1):
            if not self._consume_instruction():
                break
            instruction = method.instructions[index]
            if not instruction.name.startswith("invoke-"):
                continue
            receiver = invocation_receiver(instruction)
            parsed = parse_method_reference(instruction.reference)
            if (
                receiver is not None
                and parsed is not None
                and parsed[0] == "Landroid/content/Intent;"
                and self._holds_parameter(method, cfg, parameter_register, receiver, index, memo)
            ):
                self._collect_intent_call(local, method, index, next_visited, depth)
            for _formal, dex_type, actual in invocation_formals(instruction):
                if dex_type == "Landroid/content/Intent;" and self._holds_parameter(
                    method, cfg, parameter_register, actual, index, memo
                ):
                    self._collect_called_intent_mutations(
                        local, method, index, actual, next_visited, depth
                    )
        return local.facts

    def _holds_parameter(
        self,
        method: MethodIR,
        cfg: Any,
        parameter_register: int,
        register: int,
        before: int,
        memo: dict[tuple[int, int], bool],
    ) -> bool:
        """Return whether ``register`` may still hold the incoming Intent parameter."""
        key = (register, before)
        if key in memo:
            return memo[key]
        memo[key] = False  # Break move cycles conservatively.
        reaching = cfg.reaching_definitions(register, before)
        result = register == parameter_register and reaching.reaches_entry
        for index in reaching.instruction_indices:
            if result:
                break
            instruction = method.instructions[index]
            if instruction.name.startswith("move-result") and index > 0:
                # Intent builder methods return their receiver object.
                call = method.instructions[index - 1]
                parsed = parse_method_reference(call.reference)
                receiver = invocation_receiver(call)
                result = bool(
                    parsed
                    and parsed[0] == "Landroid/content/Intent;"
                    and parsed[2].endswith(")Landroid/content/Intent;")
                    and receiver is not None
                    and self._holds_parameter(
                        method, cfg, parameter_register, receiver, index - 1, memo
                    )
                ) or any(
                    self._holds_parameter(method, cfg, parameter_register, source, index - 1, memo)
                    for source in self._pass_through_sources(call, same_object_only=True)
                )
            elif (
                instruction.name.startswith("move")
                and not instruction.name.startswith("move-exception")
                and len(instruction.registers) >= 2
            ):
                result = self._holds_parameter(
                    method, cfg, parameter_register, instruction.registers[1], index, memo
                )
        memo[key] = result
        return result

    @staticmethod
    def _pass_through_sources(
        call: Any, *, same_object_only: bool = False
    ) -> tuple[int, ...]:
        """Return argument registers whose Intent state a call result carries."""
        parsed = parse_method_reference(call.reference)
        if parsed is None:
            return ()
        key = (parsed[0], parsed[1])
        positions = INTENT_IDENTITY_CALLS.get(key)
        if positions is None and not same_object_only:
            positions = INTENT_DERIVING_CALLS.get(key)
        if positions is None:
            return ()
        formals = {formal: register for formal, _dex_type, register in invocation_formals(call)}
        registers = (
            invocation_receiver(call) if position == -1 else formals.get(position)
            for position in positions
        )
        return tuple(register for register in registers if register is not None)

    def _holds_tracked_value(
        self,
        method: MethodIR,
        register: int,
        index: int,
        tracked: Any,
    ) -> bool:
        """Return whether ``register`` at ``index`` may hold the value dispatched at the walk point."""
        if tracked is None:
            return True
        here = self.backend.cfg_for(method).reaching_definitions(register, index)
        if here.reaches_entry and tracked.reaches_entry:
            return True
        return not set(here.instruction_indices).isdisjoint(tracked.instruction_indices)

    def _collect_intent_call(
        self,
        state: IntentState,
        method: MethodIR,
        call_index: int,
        visited: frozenset[IntentWalkState],
        depth: int,
        *,
        include_extras: bool = True,
        context: CallContext = (),
    ) -> tuple[bool, bool]:
        """Collect one Intent mutation; report whether it replaces extras or pins the destination."""
        call = method.instructions[call_index]
        parsed = parse_method_reference(call.reference)
        if parsed is None or parsed[0] != "Landroid/content/Intent;":
            return False, False
        _owner, name, _descriptor = parsed
        formals = invocation_formals(call)
        assignments: list[tuple[str, int, str | None]] = []
        replaces_extras = False
        if name == "setComponent":
            assignments.extend(("component", register, None) for _, _, register in formals)
        elif name == "setClass":
            assignments.extend(
                ("class", register, None)
                for _, dex_type, register in formals
                if dex_type == "Ljava/lang/Class;"
            )
        elif name == "setClassName":
            strings = [
                register for _, dex_type, register in formals if dex_type == "Ljava/lang/String;"
            ]
            if strings:
                assignments.append(("class", strings[-1], None))
            if len(strings) > 1:
                assignments.append(("package", strings[0], None))
        elif name == "setPackage":
            assignments.extend(("package", register, None) for _, _, register in formals)
        elif name == "setAction":
            assignments.extend(("action", register, None) for _, _, register in formals)
        elif name in {"setData", "setDataAndType"}:
            assignments.extend(
                ("data", register, None)
                for _, dex_type, register in formals
                if dex_type == "Landroid/net/Uri;"
            )
            assignments.extend(
                ("type", register, None)
                for _, dex_type, register in formals
                if dex_type == "Ljava/lang/String;"
            )
        elif name == "addCategory":
            assignments.extend(("category", register, None) for _, _, register in formals)
        elif name in {"addFlags", "setFlags"}:
            assignments.extend(("flags", register, None) for _, _, register in formals)
        elif name == "setSelector":
            assignments.extend(("selector", register, None) for _, _, register in formals)
        elif name in {"putExtras", "replaceExtras"} and include_extras:
            bundle_register = next(
                (
                    register
                    for formal, dex_type, register in formals
                    if formal == 0 and dex_type == "Landroid/os/Bundle;"
                ),
                None,
            )
            if bundle_register is not None:
                replaces_extras = name == "replaceExtras"
                self._collect_bundle_extras(
                    state,
                    method,
                    call_index,
                    bundle_register,
                    name,
                    visited,
                    depth,
                )
        elif name.startswith("putExtra") and len(formals) >= 2 and include_extras:
            key = self.tracer.constant(method, formals[0][2], call_index)
            assignments.append(("extra", formals[1][2], str(key) if key is not None else None))
        elif name == "<init>":
            for _, dex_type, source in formals:
                if dex_type == "Landroid/content/Intent;":
                    state.extend(
                        self._resolve(method, source, call_index, visited, depth + 1, context)
                    )
                elif dex_type == "Ljava/lang/Class;":
                    assignments.append(("class", source, None))
                elif dex_type == "Ljava/lang/String;":
                    assignments.append(("action", source, None))
                elif dex_type == "Landroid/net/Uri;":
                    assignments.append(("data", source, None))

        trace_requests = [
            (value_register, call_index, "value")
            for _field_name, value_register, _key in assignments
        ]
        traced = self.tracer.trace_many(method, trace_requests)
        pins_destination = name in COMPONENT_SETTERS and bool(assignments)
        for field_name, value_register, key in assignments:
            origins = traced.get((value_register, call_index, "value"), []) or [
                Origin("unknown", method=method.display(), offset=call.offset)
            ]
            state.add_facts(
                IntentFact(
                    field=field_name,
                    origin=origin,
                    key=key,
                    setter=name,
                    method=method.display(),
                    offset=call.offset,
                )
                for origin in origins
            )
            if name == "setComponent":
                pins_destination = pins_destination and self._constant_component_name(
                    method, value_register, call_index
                )
            else:
                pins_destination = pins_destination and self._all_fixed(origins)
        return replaces_extras, pins_destination

    @staticmethod
    def _all_fixed(origins: list[Origin]) -> bool:
        """Return whether every traced value is a non-null constant."""
        return bool(origins) and all(
            origin.kind == "constant" and origin.value not in (None, 0)
            for origin in origins
        )

    def _constant_component_name(
        self, method: MethodIR, register: int, before: int
    ) -> bool:
        """Check that a ComponentName is built locally from constant package/class values."""
        cfg_for = getattr(self.backend, "cfg_for", None)
        if not callable(cfg_for):
            return False
        reaching = cfg_for(method).reaching_definitions(register, before)
        definitions = tuple(reaching.instruction_indices)
        if reaching.reaches_entry or len(definitions) != 1:
            return False
        allocation = method.instructions[definitions[0]]
        if not allocation.name.startswith("new-instance") or COMPONENT_NAME not in (
            allocation.type_value,
            allocation.reference,
        ):
            return False
        for index in range(definitions[0] + 1, before):
            instruction = method.instructions[index]
            parsed = parse_method_reference(instruction.reference)
            if (
                parsed is None
                or parsed[0] != COMPONENT_NAME
                or parsed[1] != "<init>"
                or invocation_receiver(instruction) != register
            ):
                continue
            # The Context argument only supplies this app's own package name.
            values = [
                actual
                for _formal, dex_type, actual in invocation_formals(instruction)
                if dex_type != CONTEXT
            ]
            return bool(values) and all(
                self._all_fixed(self.tracer.trace(method, actual, index, "value"))
                for actual in values
            )
        return False

    def _collect_bundle_extras(
        self,
        state: IntentState,
        method: MethodIR,
        call_index: int,
        bundle_register: int,
        setter: str,
        visited: frozenset[IntentWalkState],
        depth: int,
    ) -> None:
        """Project keyed Bundle state into outgoing Intent extras."""
        call = method.instructions[call_index]
        container_entries = getattr(self.backend, "container_entries", None)
        entries = (
            container_entries(method, bundle_register, call_index)
            if callable(container_entries)
            else ()
        )
        for entry in entries[: self.tracer.max_fanout]:
            write = entry.write
            writer_method = self.backend.methods[write.method]
            origins = self.tracer.trace(
                writer_method,
                write.value_register,
                write.instruction_index,
                "value",
            ) or [
                Origin(
                    "unknown",
                    method=writer_method.display(),
                    offset=writer_method.instructions[write.instruction_index].offset,
                )
            ]
            relation = f"Bundle slot copied by Intent.{setter}"
            if entry.via_transfer:
                relation += " after Bundle.putAll"
            projected = self.tracer._steps(
                origins,
                method,
                call_index,
                relation,
                edge_type="CONTAINER_TRANSFER",
                direct=entry.key is not None,
                evidence={
                    "state_semantics": "bundle_to_intent_extras",
                    "transfer_mode": "replace" if setter == "replaceExtras" else "merge",
                    "container_key": entry.key,
                },
            )
            state.add_facts(
                IntentFact(
                    field="extra",
                    origin=origin,
                    key=entry.key,
                    setter=setter,
                    method=method.display(),
                    offset=call.offset,
                )
                for origin in projected
            )

        if entries:
            return
        # A whole external extras Bundle may not have local keyed writes. Keep
        # its provenance as a wildcard extra instead of dropping the transfer.
        origins = self.tracer._trace(
            method,
            bundle_register,
            call_index,
            "value",
            visited,
            depth + 1,
        )
        state.add_facts(
            IntentFact(
                field="extra",
                origin=origin,
                key=origin.key,
                setter=setter,
                method=method.display(),
                offset=call.offset,
            )
            for origin in origins
            if origin.kind in {"external_field", "component_field"}
        )
