from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from src.static.search.dex_ir import (
    destination_register,
    invocation_formals,
    invocation_receiver,
    parse_method_reference,
)
from src.static.model.values import (
    ICCEdge,
    ICCValueObservation,
    MethodIR,
    MethodRef,
    SinkSite,
)


@dataclass(frozen=True)
class _RouteWrite:
    key: str
    register: int
    index: int
    setter: str


@dataclass(frozen=True)
class _RouteDispatch:
    method: MethodRef
    index: int
    route: str
    writes: tuple[_RouteWrite, ...]


class RouteICCProvider:
    """Resolve typed route builders as demand-driven ICC transports.

    The model uses only three structural facts: a constant route and component
    class occur in the same registration call, the route factory returns a
    builder object, and key/value setters plus the terminal navigation call use
    that same object.  It contains no router package or method-name allowlist.
    """

    def __init__(self, backend: Any, tracer: Any, callback_resolver: Any) -> None:
        self.backend = backend
        self.tracer = tracer
        self.callback_resolver = callback_resolver
        self.sites_by_id: dict[str, SinkSite] = {}
        self._cache: dict[str, tuple[ICCEdge, ...]] = {}
        self.requests = 0
        self.registrations_examined = 0
        self.dispatches_resolved = 0

    def incoming_edges(self, target_component: str) -> list[ICCEdge]:
        self.requests += 1
        cached = self._cache.get(target_component)
        if cached is not None:
            return list(cached)
        component = next(
            (item for item in self.backend.components if item.name == target_component),
            None,
        )
        if component is None:
            self._cache[target_component] = ()
            return []
        routes = self._registered_routes(component.descriptor)
        edges: list[ICCEdge] = []
        for route in routes:
            for dispatch in self._route_dispatches(route):
                edges.extend(self._materialize(component, dispatch))
        value = tuple(self._deduplicate(edges))
        self._cache[target_component] = value
        return list(value)

    def _registered_routes(self, target_descriptor: str) -> tuple[str, ...]:
        result: list[str] = []
        for method_ref, class_index, class_register in self.backend._class_constants.get(
            target_descriptor, ()
        ):
            method = self.backend.methods[method_ref]
            aliases = {class_register}
            for index in range(class_index + 1, min(len(method.instructions), class_index + 48)):
                instruction = method.instructions[index]
                self._update_move_aliases(instruction, aliases)
                parsed = parse_method_reference(instruction.reference)
                if parsed is None:
                    continue
                self.registrations_examined += 1
                formals = invocation_formals(instruction)
                if not any(
                    dex_type == "Ljava/lang/Class;" and actual in aliases
                    for _formal, dex_type, actual in formals
                ):
                    continue
                for _formal, dex_type, actual in formals:
                    if dex_type != "Ljava/lang/String;":
                        continue
                    value = self._local_constant(method, actual, index, "const-string")
                    if self._looks_like_route(value) and value not in result:
                        result.append(value)
                # Generated registries commonly build a metadata object with
                # the normalized path, then store it as Map.put(publicPath,
                # metadata).  Follow that exact result object so both spellings
                # refer to the same component registration.
                metadata_register = self._move_result_register(method, index)
                if metadata_register is not None:
                    metadata_aliases = {metadata_register}
                    for store_index in range(
                        index + 2, min(len(method.instructions), index + 18)
                    ):
                        store = method.instructions[store_index]
                        self._update_move_aliases(store, metadata_aliases)
                        store_parsed = parse_method_reference(store.reference)
                        if store_parsed is None:
                            continue
                        store_formals = invocation_formals(store)
                        if not any(actual in metadata_aliases for _f, _t, actual in store_formals):
                            continue
                        for _formal, _dex_type, actual in store_formals:
                            if actual in metadata_aliases:
                                continue
                            value = self._local_constant(
                                method, actual, store_index, "const-string"
                            )
                            if self._looks_like_route(value) and value not in result:
                                result.append(value)
        return tuple(result)

    def _route_dispatches(self, route: str) -> tuple[_RouteDispatch, ...]:
        result: list[_RouteDispatch] = []
        for method_ref, constant_index, route_register in self.backend._string_constants.get(
            route, ()
        ):
            method = self.backend.methods[method_ref]
            route_aliases = {route_register}
            for factory_index in range(
                constant_index + 1, min(len(method.instructions), constant_index + 32)
            ):
                instruction = method.instructions[factory_index]
                self._update_move_aliases(instruction, route_aliases)
                parsed = parse_method_reference(instruction.reference)
                if parsed is None or not any(
                    dex_type == "Ljava/lang/String;" and actual in route_aliases
                    for _formal, dex_type, actual in invocation_formals(instruction)
                ):
                    continue
                builder = self._move_result_register(method, factory_index)
                if builder is None or not self._object_return(parsed[2]):
                    continue
                dispatch = self._follow_builder(method, factory_index + 1, builder, route)
                if dispatch is not None and dispatch not in result:
                    result.append(dispatch)
                break
        return tuple(result)

    def _follow_builder(
        self, method: MethodIR, start: int, builder: int, route: str
    ) -> _RouteDispatch | None:
        aliases = {builder}
        writes: list[_RouteWrite] = []
        for index in range(start + 1, min(len(method.instructions), start + 96)):
            instruction = method.instructions[index]
            if instruction.name.startswith("move-result"):
                continue
            self._update_move_aliases(instruction, aliases)
            parsed = parse_method_reference(instruction.reference)
            if parsed is None or invocation_receiver(instruction) not in aliases:
                continue
            formals = invocation_formals(instruction)
            keyed = next(
                (
                    (position, item, self._local_constant(method, item[2], index, "const-string"))
                    for position, item in enumerate(formals)
                    if item[1] == "Ljava/lang/String;"
                    and self._local_constant(method, item[2], index, "const-string") is not None
                ),
                None,
            )
            if keyed is not None:
                position, _key_formal, key = keyed
                value_formal = next(
                    (item for item in formals[position + 1 :] if item[2] != _key_formal[2]),
                    None,
                )
                if value_formal is not None and key is not None:
                    writes.append(
                        _RouteWrite(key, value_formal[2], index, instruction.reference or parsed[1])
                    )
            context_argument = any(
                dex_type == "Landroid/content/Context;"
                or self.backend.is_subtype(dex_type, "Landroid/content/Context;")
                for _formal, dex_type, _actual in formals
                if dex_type.startswith("L")
            )
            next_builder = self._move_result_register(method, index)
            if context_argument and writes:
                return _RouteDispatch(method.method, index, route, tuple(writes))
            if next_builder is not None and self._object_return(parsed[2]):
                aliases.add(next_builder)
        return None

    def _materialize(self, component: Any, dispatch: _RouteDispatch) -> list[ICCEdge]:
        method = self.backend.methods[dispatch.method]
        instruction = method.instructions[dispatch.index]
        parsed = parse_method_reference(instruction.reference)
        if parsed is None:
            return []
        site = SinkSite(
            rule_id="ROUTE_NAVIGATION",
            category="icc",
            method=dispatch.method,
            instruction_index=dispatch.index,
            offset=instruction.offset,
            api=instruction.reference or parsed[1],
            api_name=parsed[1],
            argument_registers=(invocation_receiver(instruction) or 0,),
        )
        self.sites_by_id[site.site_id] = site
        observations: list[ICCValueObservation] = []
        for write in dispatch.writes:
            for origin in self.tracer.trace(method, write.register, write.index, "value"):
                observations.append(
                    ICCValueObservation(
                        f"extra:{write.key}",
                        origin,
                        write.setter,
                        method.display(),
                        method.instructions[write.index].offset,
                    )
                )
        if not observations:
            return []
        roots = self.backend.component_roots(dispatch.method)
        callbacks = self.callback_resolver.callbacks_for(component, "startActivity")
        self.dispatches_resolved += 1
        return [
            ICCEdge(
                source_site=site.site_id,
                source_component=root.name,
                dispatch_api=site.api_name,
                target_component=component.name,
                target_callback_nodes=callbacks,
                resolution="route_registry",
                reason=f"constant route {dispatch.route!r} maps to component class",
                carried_fields=tuple(dict.fromkeys(item.target_field for item in observations)),
                value_observations=tuple(observations),
            )
            for root in roots
        ]

    @staticmethod
    def _local_constant(
        method: MethodIR, register: int, before: int, prefix: str
    ) -> str | None:
        current = register
        for index in range(min(before, len(method.instructions)) - 1, -1, -1):
            instruction = method.instructions[index]
            if destination_register(instruction) != current:
                continue
            if instruction.name.startswith(prefix):
                return instruction.string_value
            if instruction.name.startswith("move") and not instruction.name.startswith(
                "move-result"
            ) and len(instruction.registers) >= 2:
                current = instruction.registers[1]
                continue
            return None
        return None

    @staticmethod
    def _move_result_register(method: MethodIR, call_index: int) -> int | None:
        index = call_index + 1
        if index >= len(method.instructions):
            return None
        instruction = method.instructions[index]
        if not instruction.name.startswith("move-result"):
            return None
        return destination_register(instruction)

    @staticmethod
    def _update_move_aliases(instruction: Any, aliases: set[int]) -> None:
        if instruction.name.startswith("move") and not instruction.name.startswith(
            "move-result"
        ) and len(instruction.registers) >= 2:
            destination, source = instruction.registers[:2]
            if source in aliases:
                aliases.add(destination)
            elif destination in aliases:
                aliases.discard(destination)
            return
        destination = destination_register(instruction)
        if destination in aliases:
            aliases.discard(destination)

    @staticmethod
    def _looks_like_route(value: str | None) -> bool:
        return bool(value and (value.startswith("/") or "://" in value))

    @staticmethod
    def _object_return(descriptor: str) -> bool:
        return descriptor.rsplit(")", 1)[-1].startswith(("L", "["))

    @staticmethod
    def _deduplicate(edges: list[ICCEdge]) -> list[ICCEdge]:
        result: list[ICCEdge] = []
        seen: set[tuple[Any, ...]] = set()
        for edge in edges:
            key = (
                edge.source_site,
                edge.source_component,
                edge.target_component,
                tuple(
                    (
                        item.target_field,
                        item.origin.kind,
                        item.origin.component,
                        item.origin.method,
                        item.origin.offset,
                        item.origin.field,
                        item.origin.key,
                    )
                    for item in edge.value_observations
                ),
            )
            if key not in seen:
                seen.add(key)
                result.append(edge)
        return result

    def metrics(self) -> dict[str, int]:
        return {
            "route_provider_requests": self.requests,
            "route_registrations_examined": self.registrations_examined,
            "route_dispatches_resolved": self.dispatches_resolved,
            "route_synthetic_sites": len(self.sites_by_id),
        }
