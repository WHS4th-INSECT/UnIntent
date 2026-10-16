from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from src.static.search.dex_ir import (
    destination_register,
    invocation_formals,
    invocation_receiver,
    parse_method_reference,
)
from src.static.search.icc_index import normalize_component
from src.static.model.values import MethodIR, MethodRef


INTENT = "Landroid/content/Intent;"
COMPONENT_NAME = "Landroid/content/ComponentName;"


@dataclass(frozen=True)
class ICCArgumentProvenance:
    """Bounded provenance used only to avoid destructive ICC pre-triage."""

    intent_parameter_dependency: bool = False
    unresolved_dependency: bool = False
    target_hints: tuple[str, ...] = ()
    reasons: tuple[str, ...] = ()
    parameter_indices: tuple[int, ...] = ()


def analyze_icc_argument(
    backend: Any,
    method_ref: MethodRef,
    registers: tuple[int, ...],
    before: int,
    component_names: set[str],
    *,
    max_depth: int = 6,
    max_states: int = 96,
    use_cfg: bool = True,
) -> ICCArgumentProvenance:
    """Trace only sink-connected Intent values through moves and helper returns."""

    worklist = [(method_ref, register, before, 0) for register in registers]
    visited: set[tuple[MethodRef, int, int]] = set()
    hints: set[str] = set()
    reasons: set[str] = set()
    parameter_dependency = False
    parameter_indices: set[int] = set()
    unresolved = False

    while worklist and len(visited) < max_states:
        current_ref, register, limit, depth = worklist.pop()
        state = (current_ref, register, limit)
        if state in visited or depth > max_depth:
            continue
        visited.add(state)
        method = backend.methods.get(current_ref)
        if method is None:
            unresolved = True
            reasons.add("missing_method_body")
            continue

        parameter = method.parameters.get(register)
        if parameter is not None and parameter[1] == INTENT:
            parameter_dependency = True
            parameter_indices.add(parameter[0])
            reasons.add("intent_parameter_dependency")

        aliases = _register_aliases(method, register, limit)
        hints.update(
            _connected_target_hints(
                method,
                aliases,
                limit,
                component_names,
                getattr(backend, "package_name", ""),
            )
        )

        definitions, reaches_entry = _reaching_definitions(
            backend,
            method,
            register,
            limit,
            use_cfg=use_cfg,
        )
        if reaches_entry and parameter is None:
            unresolved = True
            reasons.add("value_reaches_method_entry")
        if not definitions and parameter is None:
            unresolved = True
            reasons.add("missing_local_definition")

        for definition_index in definitions:
            instruction = method.instructions[definition_index]
            if (
                instruction.name.startswith("move")
                and not instruction.name.startswith("move-result")
                and len(instruction.registers) >= 2
            ):
                worklist.append(
                    (current_ref, instruction.registers[1], definition_index, depth + 1)
                )
                continue
            if instruction.name.startswith("move-result") and definition_index > 0:
                invoke_index = definition_index - 1
                invoke = method.instructions[invoke_index]
                parsed = parse_method_reference(invoke.reference)
                if parsed is None or not parsed[2].endswith(f"){INTENT}"):
                    unresolved = True
                    reasons.add("unresolved_result_producer")
                    continue
                intent_inputs = [
                    actual
                    for _formal, dex_type, actual in invocation_formals(invoke)
                    if dex_type == INTENT
                ]
                for actual in intent_inputs:
                    worklist.append((current_ref, actual, invoke_index, depth + 1))
                targets = list(
                    getattr(backend, "call_targets", {}).get(
                        (current_ref, invoke_index), []
                    )
                    or []
                )
                for target in targets[:12]:
                    target_method = backend.methods.get(target)
                    if target_method is None:
                        continue
                    for return_index, returned in _return_registers(target_method):
                        worklist.append((target, returned, return_index, depth + 1))
                if not intent_inputs and not targets:
                    unresolved = True
                    reasons.add("unresolved_intent_factory")
                elif intent_inputs:
                    reasons.add("intent_transformer_input")
                continue
            if instruction.name.startswith(("iget", "sget", "aget")):
                unresolved = True
                reasons.add("intent_loaded_from_storage")
            elif instruction.name.startswith("check-cast"):
                worklist.append((current_ref, register, definition_index, depth + 1))

    if worklist:
        unresolved = True
        reasons.add("provenance_budget_exhausted")
    return ICCArgumentProvenance(
        intent_parameter_dependency=parameter_dependency,
        unresolved_dependency=unresolved,
        target_hints=tuple(sorted(hints)),
        reasons=tuple(sorted(reasons)),
        parameter_indices=tuple(sorted(parameter_indices)),
    )


def propagate_caller_target_hints(
    backend: Any,
    method_ref: MethodRef,
    parameter_indices: tuple[int, ...],
    component_names: set[str],
    *,
    preferred_targets: set[str] | None = None,
    max_depth: int = 5,
    max_states: int = 256,
) -> tuple[set[str], tuple[str, ...]]:
    """Propagate an ICC wrapper parameter to bounded caller actual arguments."""

    queue = [(method_ref, parameter_indices, 0)]
    visited: set[tuple[MethodRef, tuple[int, ...]]] = set()
    hints: set[str] = set()
    reasons: set[str] = set()
    preferred = set(preferred_targets or ())
    preferred_owners = _preferred_owner_classes(backend, preferred)
    while queue and len(visited) < max_states:
        callee, formals, depth = queue.pop(0)
        marker = (callee, formals)
        if marker in visited or depth >= max_depth:
            continue
        visited.add(marker)
        for caller, call_index in _bounded_callers(
            backend,
            callee,
            preferred_owner_classes=preferred_owners,
        ):
            method = backend.methods.get(caller)
            if method is None or call_index >= len(method.instructions):
                continue
            invocation = method.instructions[call_index]
            actual_by_formal = {
                formal: actual
                for formal, _type, actual in invocation_formals(invocation)
            }
            actuals = tuple(
                actual_by_formal[formal]
                for formal in formals
                if formal in actual_by_formal
            )
            if not actuals:
                continue
            provenance = analyze_icc_argument(
                backend,
                caller,
                actuals,
                call_index,
                component_names,
                max_depth=2,
                max_states=24,
                use_cfg=False,
            )
            hints.update(provenance.target_hints)
            if provenance.target_hints:
                reasons.add("caller_connected_target")
                if preferred and hints & preferred:
                    reasons.add("preferred_target_recovered")
                    return hints, tuple(sorted(reasons))
            if provenance.parameter_indices:
                queue.append((caller, provenance.parameter_indices, depth + 1))
                reasons.add("wrapper_parameter_forwarding")
    if queue:
        reasons.add("caller_summary_budget_exhausted")
    return hints, tuple(sorted(reasons))


def _bounded_callers(
    backend: Any,
    callee: MethodRef,
    *,
    max_results: int = 64,
    preferred_owner_classes: set[str] | None = None,
) -> tuple[tuple[MethodRef, int], ...]:
    """Return exact/dispatch callers plus a bounded signature-only fallback."""

    result: list[tuple[MethodRef, int]] = []
    callers = getattr(backend, "callers", {})
    for site in callers.get(callee, ()) or ():
        pair = (site.caller, site.instruction_index)
        if pair not in result:
            result.append(pair)
    # Large DI interface domains are intentionally rejected by the ordinary
    # call resolver. For pre-triage only, inspect same-signature callsites and
    # require the actual Intent itself to provide a connected target before a
    # hint is emitted. This cannot confirm dispatch; it only preserves work.
    occurrences = list(getattr(backend, "_invokes_by_name", {}).get(
        (callee.name, callee.descriptor), ()
    ))
    preferred_owners = set(preferred_owner_classes or ())
    occurrences.sort(
        key=lambda occurrence: (
            occurrence.caller.class_name not in preferred_owners,
            occurrence.caller.display(),
            occurrence.index,
        )
    )
    for occurrence in occurrences:
        pair = (occurrence.caller, occurrence.index)
        if pair not in result:
            result.append(pair)
        if len(result) >= max_results:
            break
    return tuple(result[:max_results])


def _preferred_owner_classes(backend: Any, targets: set[str]) -> set[str]:
    """Use class constants only to prioritize, never to create target evidence."""

    result: set[str] = set()
    constants = getattr(backend, "_class_constants", {})
    for target in targets:
        descriptor = "L" + target.replace(".", "/") + ";"
        for method_ref, _index, _register in constants.get(descriptor, ()):
            result.add(method_ref.class_name)
    return result


def _reaching_definitions(
    backend: Any,
    method: MethodIR,
    register: int,
    before: int,
    *,
    use_cfg: bool,
) -> tuple[tuple[int, ...], bool]:
    """Use the real CFG when available and a bounded linear fallback in tests."""

    cfg_for = getattr(backend, "cfg_for", None)
    if use_cfg and callable(cfg_for):
        result = cfg_for(method).reaching_definitions(register, before)
        return result.instruction_indices, result.reaches_entry
    for index in range(min(before, len(method.instructions)) - 1, -1, -1):
        if destination_register(method.instructions[index]) == register:
            return (index,), False
    return (), True


def _return_registers(method: MethodIR) -> tuple[tuple[int, int], ...]:
    """Return object registers from a callee body."""

    return tuple(
        (index, instruction.registers[0])
        for index, instruction in enumerate(method.instructions)
        if instruction.name.startswith("return-object") and instruction.registers
    )


def _register_aliases(method: MethodIR, register: int, before: int) -> set[int]:
    """Collect aliases connected by local move instructions."""

    aliases = {register}
    for instruction in reversed(method.instructions[:before]):
        if not instruction.name.startswith("move") or instruction.name.startswith("move-result"):
            continue
        if len(instruction.registers) < 2:
            continue
        target, source = instruction.registers[:2]
        if target in aliases:
            aliases.add(source)
    return aliases


def _connected_target_hints(
    method: MethodIR,
    aliases: set[int],
    before: int,
    component_names: set[str],
    package_name: str,
) -> set[str]:
    """Read targets only from constructors/setters on the sink Intent aliases."""

    result: set[str] = set()
    for index, instruction in enumerate(method.instructions[:before]):
        parsed = parse_method_reference(instruction.reference)
        if parsed is None or parsed[0] != INTENT:
            continue
        receiver = invocation_receiver(instruction)
        if receiver not in aliases:
            continue
        formals = invocation_formals(instruction)
        target_actuals: list[int] = []
        if parsed[1] in {"setClass", "setClassName"} and len(formals) >= 2:
            target_actuals.append(formals[1][2])
        elif parsed[1] == "<init>" and len(formals) >= 2:
            target_actuals.append(formals[1][2])
        elif parsed[1] == "setComponent" and formals:
            result.update(
                _component_name_values(
                    method,
                    formals[0][2],
                    index,
                    component_names,
                    package_name,
                )
            )
        for actual in target_actuals:
            for raw in _text_values(method, actual, index):
                normalized = normalize_component(raw, package_name)
                if normalized in component_names:
                    result.add(normalized)
    return result


def _component_name_values(
    method: MethodIR,
    register: int,
    before: int,
    component_names: set[str],
    package_name: str,
) -> set[str]:
    """Resolve a ComponentName constructor tied to an Intent setter."""

    aliases = _register_aliases(method, register, before)
    result: set[str] = set()
    for index, instruction in enumerate(method.instructions[:before]):
        parsed = parse_method_reference(instruction.reference)
        if parsed is None or parsed[:2] != (COMPONENT_NAME, "<init>"):
            continue
        if invocation_receiver(instruction) not in aliases:
            continue
        formals = invocation_formals(instruction)
        if len(formals) < 2:
            continue
        for raw in _text_values(method, formals[1][2], index):
            normalized = normalize_component(raw, package_name)
            if normalized in component_names:
                result.add(normalized)
    return result


def _text_values(
    method: MethodIR,
    register: int,
    before: int,
    depth: int = 0,
) -> set[str]:
    """Resolve local string and class constants through moves."""

    if depth >= 8:
        return set()
    result: set[str] = set()
    index = _last_definition(method, register, before)
    if index is None:
        return result
    instruction = method.instructions[index]
    if instruction.string_value is not None:
        result.add(instruction.string_value)
    elif instruction.name.startswith("check-cast"):
        result.update(_text_values(method, register, index, depth + 1))
    elif (
        instruction.name.startswith("move")
        and not instruction.name.startswith("move-result")
        and len(instruction.registers) >= 2
    ):
        result.update(_text_values(method, instruction.registers[1], index, depth + 1))
    elif instruction.name.startswith("move-result") and index > 0:
        invocation = method.instructions[index - 1]
        for _formal, dex_type, actual in invocation_formals(invocation):
            if dex_type in {"Ljava/lang/Class;", "Ljava/lang/String;"}:
                result.update(_text_values(method, actual, index - 1, depth + 1))
    elif instruction.name.startswith("iget") and len(instruction.registers) >= 2:
        # Pair/holder objects commonly carry a Class through a factory
        # result. Follow only typed Class/String arguments of that exact
        # receiver producer; unrelated method constants are never read.
        receiver = instruction.registers[1]
        producer = _last_definition(method, receiver, index)
        if producer is not None:
            producer_instruction = method.instructions[producer]
            if producer_instruction.name.startswith("move-result") and producer > 0:
                invocation = method.instructions[producer - 1]
                for _formal, dex_type, actual in invocation_formals(invocation):
                    if dex_type in {"Ljava/lang/Class;", "Ljava/lang/String;"}:
                        result.update(
                            _text_values(method, actual, producer - 1, depth + 1)
                        )
    return result


def _last_definition(method: MethodIR, register: int, before: int) -> int | None:
    """Return the nearest local register definition before an instruction."""

    for index in range(min(before, len(method.instructions)) - 1, -1, -1):
        if destination_register(method.instructions[index]) == register:
            return index
    return None
