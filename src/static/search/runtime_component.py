"""런타임 시 활성화되는 컴포넌트 식별"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import replace
from typing import Any

from src.static.search.backend import replace_backend_components
from src.static.search.dex_ir import (
    destination_register,
    invocation_formals,
    invocation_receiver,
    move_aliases,
    parse_method_reference,
)
from src.static.search.icc_index import normalize_component
from src.static.model.values import (
    Component,
    MethodIR,
    RuntimeActivationEvidence,
)


PACKAGE_MANAGER = "Landroid/content/pm/PackageManager;"
COMPONENT_NAME = "Landroid/content/ComponentName;"
SET_COMPONENT_ENABLED = "setComponentEnabledSetting"
COMPONENT_ENABLED_STATE_ENABLED = 1

PACKAGE_INFO_COMPONENT_FIELDS = {
    "activities": "activity",
    "receivers": "receiver",
    "services": "service",
    "providers": "provider",
}


def collect_runtime_activation_evidence(
    backend: Any,
    components: list[Component],
) -> tuple[list[Component], list[RuntimeActivationEvidence]]:
    """Collect generic PackageManager activation evidence without deciding app policy."""

    by_name = {component.name: component for component in components}
    attached: dict[str, list[RuntimeActivationEvidence]] = defaultdict(list)
    all_evidence: list[RuntimeActivationEvidence] = []

    for method_ref, method in backend.methods.items():
        enumerated_types = _manifest_component_types(method)
        for index, instruction in enumerate(method.instructions):
            parsed = parse_method_reference(instruction.reference)
            if parsed is None or parsed[:2] != (PACKAGE_MANAGER, SET_COMPONENT_ENABLED):
                continue
            arguments = {
                formal: register
                for formal, _type, register in invocation_formals(instruction)
            }
            component_register = arguments.get(0)
            state_register = arguments.get(1)
            states = (
                _integer_values(method, state_register, index)
                if state_register is not None
                else set()
            )
            # An exact non-enabling state is not activation evidence. Unknown
            # and branch-dependent states remain evidence for later review.
            if states and COMPONENT_ENABLED_STATE_ENABLED not in states:
                continue

            exact_targets = (
                _component_name_values(method, component_register, index, backend.package_name)
                if component_register is not None
                else set()
            )
            candidates: list[Component]
            resolution: str
            if exact_targets:
                candidates = [by_name[name] for name in exact_targets if name in by_name]
                resolution = "exact_component_name"
            elif enumerated_types:
                candidates = [
                    component
                    for component in components
                    if component.component_type in enumerated_types
                ]
                resolution = "manifest_component_enumeration"
            else:
                candidates = []
                resolution = "unresolved_component_name"

            roots = tuple(
                dict.fromkeys(
                    root.name for root in backend.component_roots(method_ref)
                )
            )
            dependencies: list[str] = []
            if not states:
                dependencies.append("component_state")
            elif states != {COMPONENT_ENABLED_STATE_ENABLED}:
                dependencies.append("component_state_branch")
            if not candidates:
                dependencies.append("component_target")

            if candidates:
                for component in candidates:
                    evidence = RuntimeActivationEvidence(
                        component=component.name,
                        callsite=f"{method.display()}@0x{instruction.offset:04x}",
                        api=instruction.reference or SET_COMPONENT_ENABLED,
                        requested_states=tuple(sorted(states)),
                        target_resolution=resolution,
                        reachable_from=roots,
                        unresolved_dependencies=tuple(dependencies),
                    )
                    attached[component.name].append(evidence)
                    all_evidence.append(evidence)
            else:
                all_evidence.append(
                    RuntimeActivationEvidence(
                        component="*",
                        callsite=f"{method.display()}@0x{instruction.offset:04x}",
                        api=instruction.reference or SET_COMPONENT_ENABLED,
                        requested_states=tuple(sorted(states)),
                        target_resolution=resolution,
                        reachable_from=roots,
                        unresolved_dependencies=tuple(dependencies),
                    )
                )

    updated = [
        replace(
            component,
            runtime_activation_evidence=tuple(attached.get(component.name, ())),
        )
        for component in components
    ]
    replace_backend_components(backend, updated)
    return updated, all_evidence


def _manifest_component_types(method: MethodIR) -> set[str]:
    """Recognize generic PackageInfo component-array enumeration evidence."""

    result: set[str] = set()
    for instruction in method.instructions:
        reference = instruction.reference or ""
        if "Landroid/content/pm/PackageInfo;->" not in reference:
            continue
        for field, component_type in PACKAGE_INFO_COMPONENT_FIELDS.items():
            if f"->{field}" in reference:
                result.add(component_type)
    return result


def _integer_values(method: MethodIR, register: int, before: int) -> set[int]:
    """Collect bounded local integer definitions that may reach a framework call."""

    return {
        value
        for value in _local_values(method, register, before, expected="integer")
        if isinstance(value, int)
    }


def _component_name_values(
    method: MethodIR,
    register: int,
    before: int,
    package_name: str,
) -> set[str]:
    """Resolve locally constructed ComponentName values tied to one call argument."""

    aliases = move_aliases(method, register, before)
    result: set[str] = set()
    for index, instruction in enumerate(method.instructions[:before]):
        parsed = parse_method_reference(instruction.reference)
        if parsed is None or parsed[0] != COMPONENT_NAME:
            continue
        receiver = invocation_receiver(instruction)
        if parsed[1] == "<init>" and receiver in aliases:
            formals = invocation_formals(instruction)
            values = [
                _local_values(method, actual, index, expected="text")
                for _formal, _type, actual in formals
            ]
            if len(values) >= 2:
                for raw in values[1]:
                    if isinstance(raw, str):
                        result.add(normalize_component(raw, package_name))
        if parsed[1] in {"createRelative", "unflattenFromString"}:
            move_result = _move_result_register(method, index)
            if move_result not in aliases:
                continue
            for _formal, _type, actual in invocation_formals(instruction):
                for raw in _local_values(method, actual, index, expected="text"):
                    if isinstance(raw, str):
                        result.add(normalize_component(raw, package_name))
    return result


def _local_values(
    method: MethodIR,
    register: int,
    before: int,
    *,
    expected: str,
    depth: int = 0,
) -> set[str | int]:
    """Collect constants through local moves while retaining branch alternatives."""

    if depth >= 8:
        return set()
    result: set[str | int] = set()
    for index in range(min(before, len(method.instructions)) - 1, -1, -1):
        instruction = method.instructions[index]
        if destination_register(instruction) != register:
            continue
        if expected == "integer" and instruction.literal_value is not None:
            result.add(instruction.literal_value)
        elif expected == "text" and instruction.string_value is not None:
            result.add(instruction.string_value)
        elif (
            instruction.name.startswith("move")
            and not instruction.name.startswith("move-result")
            and len(instruction.registers) >= 2
        ):
            result.update(
                _local_values(
                    method,
                    instruction.registers[1],
                    index,
                    expected=expected,
                    depth=depth + 1,
                )
            )
    return result


def _move_result_register(method: MethodIR, invoke_index: int) -> int | None:
    """Return the register receiving an invocation result."""

    next_index = invoke_index + 1
    if next_index >= len(method.instructions):
        return None
    instruction = method.instructions[next_index]
    if instruction.name.startswith("move-result") and instruction.registers:
        return instruction.registers[0]
    return None
