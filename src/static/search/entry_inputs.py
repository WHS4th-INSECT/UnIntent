"""Bounded entry-first catalog of externally supplied Intent fields."""

from __future__ import annotations

from collections import deque
from typing import Any

from src.static.search.manifest import generic_attacker_can_invoke
from src.static.search.api_rules import external_field_api
from src.static.search.dex_ir import invocation_formals, parse_method_reference
from src.static.model.values import Component, MethodRef


def collect_entry_input_catalog(
    backend: Any,
    components: list[Component],
    *,
    max_depth: int = 10,
    max_methods_per_entry: int = 512,
    max_inputs_per_entry: int = 256,
) -> list[dict[str, Any]]:
    """Collect input reads from exported Entry classes and bounded direct helpers."""

    result: list[dict[str, Any]] = []
    seen_inputs: set[tuple[Any, ...]] = set()
    for component in components:
        if not component.is_entry_point:
            continue
        owner_lineage = set(backend.owner_lineage(component.descriptor))
        seeds = sorted(
            (
                reference
                for reference in backend.methods
                if reference.class_name in owner_lineage
            ),
            key=MethodRef.display,
        )
        queue = deque((reference, 0) for reference in seeds)
        visited: set[MethodRef] = set()
        input_count = 0
        while (
            queue
            and len(visited) < max_methods_per_entry
            and input_count < max_inputs_per_entry
        ):
            reference, depth = queue.popleft()
            if reference in visited or depth > max_depth:
                continue
            visited.add(reference)
            method = backend.methods.get(reference)
            if method is None:
                continue
            for index, instruction in enumerate(method.instructions):
                parsed = parse_method_reference(instruction.reference)
                if parsed is None:
                    continue
                owner, name, descriptor = parsed
                source_api = external_field_api(name, owner)
                if source_api is not None:
                    key_register = next(
                        (
                            actual
                            for formal, dex_type, actual in invocation_formals(instruction)
                            if formal == 0 and dex_type == "Ljava/lang/String;"
                        ),
                        None,
                    )
                    key = (
                        backend._local_string_constant(method, key_register, index)
                        if key_register is not None
                        else None
                    )
                    marker = (
                        component.name,
                        source_api[1],
                        key,
                        method.display(),
                        instruction.offset,
                    )
                    if marker not in seen_inputs:
                        seen_inputs.add(marker)
                        result.append(
                            _record(
                                component,
                                field=source_api[1],
                                key=key,
                                api=instruction.reference or name,
                                method=method.display(),
                                offset=instruction.offset,
                                call_depth=depth,
                            )
                        )
                        input_count += 1
                elif name == "getIntent" and owner.endswith(
                    ("Activity;", "ActivityCompat;")
                ):
                    marker = (
                        component.name,
                        "whole_intent",
                        None,
                        method.display(),
                        instruction.offset,
                    )
                    if marker not in seen_inputs:
                        seen_inputs.add(marker)
                        result.append(
                            _record(
                                component,
                                field="whole_intent",
                                key=None,
                                api=instruction.reference or name,
                                method=method.display(),
                                offset=instruction.offset,
                                call_depth=depth,
                            )
                        )
                        input_count += 1
                if depth >= max_depth:
                    continue
                target = MethodRef(owner, name, descriptor)
                if target in backend.methods and target not in visited:
                    queue.append((target, depth + 1))
    return result


def _record(
    component: Component,
    *,
    field: str,
    key: str | None,
    api: str,
    method: str,
    offset: int,
    call_depth: int,
) -> dict[str, Any]:
    return {
        "component": component.name,
        "component_type": component.component_type,
        "permission": component.permission,
        "generic_attacker_can_invoke": generic_attacker_can_invoke(component),
        "field": field,
        "key": key,
        "api": api,
        "method": method,
        "offset": offset,
        "call_depth": call_depth,
    }


__all__ = ["collect_entry_input_catalog"]
