"""동적으로 등록되는 BroadcastReceiver"""
from __future__ import annotations

import hashlib
from collections import defaultdict
from dataclasses import replace
from typing import Any

from src.static.search.backend import replace_backend_components
from src.static.search.dex_ir import (
    destination_register,
    invocation_formals,
    move_aliases,
    parse_method_reference,
)
from src.static.model.values import (
    Component,
    IntentFilter,
    MethodIR,
    MethodRef,
    RuntimeReceiverRegistrationEvidence,
)


BROADCAST_RECEIVER = "Landroid/content/BroadcastReceiver;"
INTENT_FILTER = "Landroid/content/IntentFilter;"
STRING = "Ljava/lang/String;"
RECEIVER_EXPORTED = 2
RECEIVER_NOT_EXPORTED = 4
EXTERNAL_EXPOSURES = {"EXPORTED", "PERMISSION_GATED"}


def collect_runtime_receiver_entries(
    backend: Any,
    components: list[Component],
    *,
    target_sdk: int | str | None,
) -> tuple[list[Component], list[RuntimeReceiverRegistrationEvidence]]:
    """Resolve context-registered receivers and install exact external entries."""

    try:
        sdk = int(target_sdk or 0)
    except (TypeError, ValueError):
        sdk = 0
    evidence_items: list[RuntimeReceiverRegistrationEvidence] = []
    attached: dict[str, list[RuntimeReceiverRegistrationEvidence]] = defaultdict(list)

    for method_ref, method in backend.methods.items():
        for index, instruction in enumerate(method.instructions):
            parsed = parse_method_reference(instruction.reference)
            if parsed is None or parsed[1] != "registerReceiver":
                continue
            formals = invocation_formals(instruction)
            receiver_register = _argument_register(formals, BROADCAST_RECEIVER)
            filter_register = _argument_register(formals, INTENT_FILTER)
            if receiver_register is None or filter_register is None:
                # registerReceiver(null, filter) is a sticky-broadcast query,
                # not callback registration and therefore not an Entry.
                continue
            if _local_values(method, receiver_register, index) == {0}:
                continue

            receiver_types = _receiver_types(
                backend, method, receiver_register, index
            )
            callbacks = [
                callback
                for receiver_type in receiver_types
                if (callback := _callback_for_type(backend, receiver_type)) is not None
            ]
            filters = _intent_filters(method, filter_register, index)
            flags = _argument_values(method, formals, "I", index)
            permissions = _argument_values(method, formals, STRING, index)
            permission = next(
                (value for value in permissions if isinstance(value, str)), None
            )
            exposure = _exposure(flags, permission, sdk)
            roots = _registration_roots(backend, method_ref)
            application_reachable = _is_application_method(backend, method_ref)

            dependencies: list[str] = []
            if not callbacks:
                dependencies.append("receiver_target")
            elif len(callbacks) != 1:
                dependencies.append("receiver_target_set")
            if exposure == "UNKNOWN":
                dependencies.append("export_status")
            if not any(item.actions for item in filters):
                dependencies.append("intent_filter_action")
            if not roots and not application_reachable:
                dependencies.append("registration_reachability")

            callback = callbacks[0] if len(callbacks) == 1 else None
            receiver_class = callback.class_name if callback is not None else None
            marker = (
                f"{method.display()}:{instruction.offset}:"
                f"{receiver_class or '*'}"
            )
            registration_id = "runtime-receiver-" + hashlib.sha256(
                marker.encode("utf-8")
            ).hexdigest()[:16]
            evidence = RuntimeReceiverRegistrationEvidence(
                registration_id=registration_id,
                callsite=f"{method.display()}@0x{instruction.offset:04x}",
                api=instruction.reference or "registerReceiver",
                receiver_class=receiver_class,
                callback_method=callback.display() if callback is not None else None,
                target_resolution=(
                    "exact_receiver_callback"
                    if callback is not None
                    else "ambiguous_receiver_type"
                    if callbacks
                    else "unresolved_receiver_type"
                ),
                exposure=exposure,
                requested_flags=tuple(
                    sorted(value for value in flags if isinstance(value, int))
                ),
                permission=permission,
                filters=filters,
                reachable_from=(
                    roots
                    or (("application_lifecycle",) if application_reachable else ())
                ),
                unresolved_dependencies=tuple(dependencies),
            )
            evidence_items.append(evidence)
            if (
                receiver_class is not None
                and exposure in EXTERNAL_EXPOSURES
                and not set(dependencies).intersection(
                    {
                        "receiver_target",
                        "receiver_target_set",
                        "export_status",
                        "registration_reachability",
                    }
                )
            ):
                attached[receiver_class].append(evidence)

    updated = _attach_entries(components, attached)
    replace_backend_components(backend, updated)
    return updated, evidence_items


def _argument_register(
    formals: list[tuple[int, str, int]], dex_type: str
) -> int | None:
    return next(
        (actual for _formal, value_type, actual in formals if value_type == dex_type),
        None,
    )


def _argument_values(
    method: MethodIR,
    formals: list[tuple[int, str, int]],
    dex_type: str,
    before: int,
) -> set[str | int]:
    result: set[str | int] = set()
    for _formal, value_type, register in formals:
        if value_type == dex_type:
            result.update(_local_values(method, register, before))
    return result


def _receiver_types(
    backend: Any, method: MethodIR, register: int, before: int
) -> tuple[str, ...]:
    result: set[str] = set()
    infer = getattr(backend, "inferred_types", None)
    if callable(infer):
        result.update(infer(method, register, before))
    aliases = move_aliases(method, register, before)
    for instruction in method.instructions[:before]:
        if (
            instruction.name.startswith("new-instance")
            and instruction.registers
            and instruction.registers[0] in aliases
            and instruction.type_value
        ):
            result.add(instruction.type_value)
    is_subtype = getattr(backend, "is_subtype", None)
    if callable(is_subtype):
        result = {
            item for item in result
            if item != BROADCAST_RECEIVER and is_subtype(item, BROADCAST_RECEIVER)
        }
    return tuple(sorted(item for item in result if item.startswith("L")))


def _callback_for_type(backend: Any, receiver_type: str) -> MethodRef | None:
    descriptor = "(Landroid/content/Context;Landroid/content/Intent;)V"
    direct = MethodRef(receiver_type, "onReceive", descriptor)
    if direct in backend.methods:
        return direct
    lineage = getattr(backend, "owner_lineage", lambda value: (value,))(receiver_type)
    return next(
        (
            MethodRef(owner, "onReceive", descriptor)
            for owner in lineage
            if MethodRef(owner, "onReceive", descriptor) in backend.methods
        ),
        None,
    )


def _intent_filters(
    method: MethodIR, register: int, before: int
) -> tuple[IntentFilter, ...]:
    aliases = move_aliases(method, register, before)
    actions: list[str] = []
    categories: list[str] = []
    schemes: list[str] = []
    mime_types: list[str] = []
    hosts: list[str] = []
    paths: list[str] = []
    for index, instruction in enumerate(method.instructions[:before]):
        parsed = parse_method_reference(instruction.reference)
        if parsed is None or parsed[0] != INTENT_FILTER or not instruction.registers:
            continue
        if instruction.registers[0] not in aliases:
            continue
        strings = [
            value
            for _formal, dex_type, actual in invocation_formals(instruction)
            if dex_type == STRING
            for value in _local_values(method, actual, index)
            if isinstance(value, str)
        ]
        name = parsed[1]
        if name == "<init>" or name == "addAction":
            actions.extend(strings[:1])
        elif name == "addCategory":
            categories.extend(strings[:1])
        elif name == "addDataScheme":
            schemes.extend(strings[:1])
        elif name == "addDataType":
            mime_types.extend(strings[:1])
        elif name == "addDataAuthority":
            hosts.extend(strings[:1])
        elif name in {"addDataPath", "addDataSchemeSpecificPart"}:
            paths.extend(strings[:1])
    return (
        IntentFilter(
            actions=tuple(dict.fromkeys(actions)),
            categories=tuple(dict.fromkeys(categories)),
            schemes=tuple(dict.fromkeys(schemes)),
            hosts=tuple(dict.fromkeys(hosts)),
            paths=tuple(dict.fromkeys(paths)),
            mime_types=tuple(dict.fromkeys(mime_types)),
        ),
    )


def _exposure(flags: set[str | int], permission: str | None, target_sdk: int) -> str:
    integer_flags = {value for value in flags if isinstance(value, int)}
    exported = any(value & RECEIVER_EXPORTED for value in integer_flags)
    not_exported = any(value & RECEIVER_NOT_EXPORTED for value in integer_flags)
    if exported and not_exported:
        return "UNKNOWN"
    if not_exported:
        return "NOT_EXPORTED"
    if exported:
        return "PERMISSION_GATED" if permission else "EXPORTED"
    if integer_flags:
        return "UNKNOWN"
    if target_sdk and target_sdk < 34:
        return "PERMISSION_GATED" if permission else "EXPORTED"
    return "UNKNOWN"


def _is_application_method(backend: Any, method: MethodRef) -> bool:
    lineage = getattr(backend, "owner_lineage", lambda value: (value,))(method.class_name)
    return "Landroid/app/Application;" in lineage


def _registration_roots(backend: Any, method: MethodRef) -> tuple[str, ...]:
    """Resolve registration reachability using exact caller edges only."""

    if not hasattr(backend, "approximation_enabled"):
        return tuple(
            dict.fromkeys(root.name for root in backend.component_roots(method))
        )
    previous = backend.approximation_enabled
    backend.approximation_enabled = False
    try:
        return tuple(
            dict.fromkeys(root.name for root in backend.component_roots(method))
        )
    finally:
        backend.approximation_enabled = previous


def _local_values(
    method: MethodIR, register: int, before: int, depth: int = 0
) -> set[str | int]:
    if depth >= 8:
        return set()
    result: set[str | int] = set()
    for index in range(min(before, len(method.instructions)) - 1, -1, -1):
        instruction = method.instructions[index]
        if destination_register(instruction) != register:
            continue
        if instruction.string_value is not None:
            result.add(instruction.string_value)
        elif instruction.literal_value is not None:
            result.add(instruction.literal_value)
        elif (
            instruction.name.startswith("move")
            and not instruction.name.startswith("move-result")
            and len(instruction.registers) >= 2
        ):
            result.update(
                _local_values(method, instruction.registers[1], index, depth + 1)
            )
    return result


def _attach_entries(
    components: list[Component],
    attached: dict[str, list[RuntimeReceiverRegistrationEvidence]],
) -> list[Component]:
    by_descriptor = {component.descriptor: component for component in components}
    for receiver_class, evidence in attached.items():
        current = by_descriptor.get(receiver_class)
        filters = tuple(
            dict.fromkeys(
                item
                for registration in evidence
                for item in registration.filters
            )
        )
        permission = next(
            (item.permission for item in evidence if item.permission is not None), None
        )
        if any(item.permission is None for item in evidence):
            permission = None
        if current is None:
            name = _descriptor_name(receiver_class)
            current = Component(
                name=name,
                code_class=name,
                descriptor=receiver_class,
                component_type="receiver",
                exported=False,
                enabled=False,
                permission=permission,
                permission_protection_level=None,
                filters=filters,
                runtime_receiver_evidence=tuple(evidence),
            )
            components = [*components, current]
        else:
            current = replace(
                current,
                filters=tuple(dict.fromkeys((*current.filters, *filters))),
                runtime_receiver_evidence=tuple(
                    (*current.runtime_receiver_evidence, *evidence)
                ),
            )
            components = [
                current if item.descriptor == receiver_class else item
                for item in components
            ]
        by_descriptor[receiver_class] = current
    return components


def _descriptor_name(value: str) -> str:
    return value[1:-1].replace("/", ".") if value.startswith("L") else value


__all__ = ["collect_runtime_receiver_entries"]
