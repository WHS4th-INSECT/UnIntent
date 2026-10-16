from __future__ import annotations

from urllib.parse import urlparse

from collections import defaultdict
from dataclasses import replace

from src.static.model.values import (
    Component, ICCEdge, ICCValueObservation, IntentFact, IntentState, SinkSite,
)
from src.static.search.backend import GraphBackend
from src.static.search.dex_ir import parse_method_reference

COMPONENT_CALLBACKS: dict[str, tuple[str, ...]] = {
    "activity": ("onCreate", "onNewIntent"),
    "service": ("onStartCommand", "onBind", "onHandleIntent"),
    "receiver": ("onReceive",),
    "provider": ("query", "insert", "update", "delete", "call", "openFile"),
}

# Only destinations resolved from a constant explicit component or from a
# concrete manifest filter are allowed to expand global entry reachability.
# High-recall candidate destinations remain attached to their sink as evidence
# but cannot make unrelated components appear externally reachable.
TRUSTED_REACHABILITY_RESOLUTIONS = {
    "explicit_component",
    "implicit_filter",
    "route_registry",
}


def constant_values(facts: list[IntentFact]) -> list[str]:
    return list(
        dict.fromkeys(
            str(fact.origin.value)
            for fact in facts
            if fact.origin.kind == "constant" and fact.origin.value is not None
        )
    )


def normalize_component(value: str, package_name: str) -> str:
    if value.startswith("L") and value.endswith(";"):
        return value[1:-1].replace("/", ".")
    if "/" in value:
        package, class_name = value.split("/", 1)
        if class_name.startswith("."):
            return package + class_name
        return class_name if "." in class_name else f"{package}.{class_name}"
    if value.startswith("."):
        return package_name + value
    if "." not in value:
        return f"{package_name}.{value}"
    return value


class ICCResolver:
    """Convert abstract Intent state to high-recall synthetic component edges."""

    def __init__(self, backend: GraphBackend) -> None:
        self.backend = backend
        self._callback_cache: dict[tuple[str, str], tuple[str, ...]] = {}
        self._methods_by_class = getattr(backend, "methods_by_class", None)
        if self._methods_by_class is None:
            self._methods_by_class = defaultdict(list)
            for method in backend.methods:
                self._methods_by_class[method.class_name].append(method)

    def resolve(
        self, site: SinkSite, state: IntentState, source_component: str | None
    ) -> list[ICCEdge]:
        observations = tuple([
            *(
                ICCValueObservation(
                    f"extra:{fact.key}"
                    if fact.field == "extra" and fact.key is not None
                    else fact.field,
                    fact.origin, fact.setter, fact.method, fact.offset,
                )
                for fact in state.facts
            ),
            *(
                ICCValueObservation("whole_intent", origin)
                for origin in (*state.object_origins, *state.pinned_only_origins())
            ),
        ])
        return [
            replace(
                edge,
                value_observations=observations,
            )
            for edge in self._resolve_targets(site, state, source_component)
        ]

    def _resolve_targets(
        self, site: SinkSite, state: IntentState, source_component: str | None
    ) -> list[ICCEdge]:
        parsed = parse_method_reference(site.api)
        api_name = parsed[1] if parsed else site.api_name
        target_types = self._target_types(api_name)
        compatible = [
            component
            for component in self.backend.components
            if component.analysis_enabled and component.component_type in target_types
        ]
        carried_values = [
            f"extra:{fact.key}"
            if fact.field == "extra" and fact.key is not None
            else fact.field
            for fact in state.facts
        ]
        if state.object_origins or state.pinned_object_origins:
            carried_values.append("whole_intent")
        carried = tuple(dict.fromkeys(carried_values))

        external_whole_destination = any(
            origin.external for origin in state.object_origins
        )
        dynamic_destination = bool(
            external_whole_destination
            or state.external_values("component", "class", "package")
        )
        if dynamic_destination:
            return self._edges(
                site,
                source_component,
                api_name,
                compatible,
                "attacker-controlled whole Intent or destination field",
                "attacker_controlled_candidate",
                carried,
            ) or [
                self._unresolved(
                    site,
                    source_component,
                    api_name,
                    "attacker-controlled destination; no app-local target enumerated",
                    "dynamic_external_target",
                    carried,
                )
            ]

        explicit_values = constant_values([*state.values("component"), *state.values("class")])
        explicit_targets: list[Component] = []
        for raw in explicit_values:
            normalized = normalize_component(raw, self.backend.package_name)
            explicit_targets.extend(
                component
                for component in compatible
                if normalized in {component.name, component.code_class}
            )
        if explicit_targets:
            return self._edges(
                site,
                source_component,
                api_name,
                explicit_targets,
                "constant explicit component/class",
                "explicit_component",
                carried,
            )

        packages = constant_values(state.values("package"))
        actions = constant_values(state.values("action"))
        data = constant_values(state.values("data"))
        schemes = {urlparse(value).scheme for value in data if urlparse(value).scheme}
        candidates = [
            component
            for component in compatible
            if (not packages or self._in_packages(component, packages))
            and self._matches_filters(component, actions, schemes)
        ]
        if candidates:
            resolution = "implicit_filter" if actions or schemes else "type_candidate"
            reason = (
                "constant action/data matched manifest intent-filter"
                if actions or schemes
                else "destination unresolved; enabled type-compatible targets retained"
            )
            return self._edges(
                site,
                source_component,
                api_name,
                candidates,
                reason,
                resolution,
                carried,
            )

        if state.external_values("action", "data", "type", "category"):
            return self._edges(
                site,
                source_component,
                api_name,
                compatible,
                "attacker-controlled implicit Intent fields",
                "dynamic_implicit_candidate",
                carried,
            ) or [
                self._unresolved(
                    site,
                    source_component,
                    api_name,
                    "dynamic implicit destination",
                    "dynamic_implicit_external_target",
                    carried,
                )
            ]

        return [
            self._unresolved(
                site,
                source_component,
                api_name,
                "static destination could not be resolved",
                "unresolved",
                carried,
            )
        ]

    @staticmethod
    def trusted_reachability_edges(edges: list[ICCEdge]) -> list[ICCEdge]:
        return [
            edge
            for edge in edges
            if edge.target_component is not None
            and edge.resolution in TRUSTED_REACHABILITY_RESOLUTIONS
        ]

    def _edges(
        self,
        site: SinkSite,
        source_component: str | None,
        api_name: str,
        targets: list[Component],
        reason: str,
        resolution: str,
        carried: tuple[str, ...],
    ) -> list[ICCEdge]:
        result: list[ICCEdge] = []
        seen: set[str] = set()
        for component in targets:
            if component.name in seen:
                continue
            seen.add(component.name)
            result.append(
                ICCEdge(
                    source_site=site.site_id,
                    source_component=source_component,
                    dispatch_api=api_name,
                    target_component=component.name,
                    target_callback_nodes=self._callbacks(component, api_name),
                    resolution=resolution,
                    reason=reason,
                    carried_fields=carried,
                )
            )
        return result

    def _callbacks(self, component: Component, api_name: str) -> tuple[str, ...]:
        cache_key = (component.name, api_name)
        cached = self._callback_cache.get(cache_key)
        if cached is not None:
            return cached
        names = (
            ("onDestroy",)
            if component.component_type == "service" and api_name == "stopService"
            else COMPONENT_CALLBACKS.get(component.component_type, ())
        )
        concrete = tuple(
            method.display()
            for method in self._methods_by_class.get(component.descriptor, ())
            if method.name in names
        )
        result = concrete or tuple(
            f"{component.descriptor}->{name}(framework callback)" for name in names[:1]
        )
        self._callback_cache[cache_key] = result
        return result

    def callbacks_for(self, component: Component, api_name: str) -> tuple[str, ...]:
        """Expose callback resolution to other exact component transports."""
        return self._callbacks(component, api_name)

    @staticmethod
    def _unresolved(
        site: SinkSite,
        source_component: str | None,
        api_name: str,
        reason: str,
        resolution: str,
        carried: tuple[str, ...],
    ) -> ICCEdge:
        return ICCEdge(
            source_site=site.site_id,
            source_component=source_component,
            dispatch_api=api_name,
            target_component=None,
            target_callback_nodes=(),
            resolution=resolution,
            reason=reason,
            carried_fields=carried,
        )

    @staticmethod
    def _target_types(api_name: str) -> set[str]:
        if api_name.startswith("startActiv"):
            return {"activity"}
        if api_name in {
            "startService", "startForegroundService", "stopService", "bindService"
        }:
            return {"service"}
        if "Broadcast" in api_name:
            return {"receiver"}
        return {"activity", "service", "receiver"}

    @staticmethod
    def _in_packages(component: Component, packages: list[str]) -> bool:
        return any(
            component.name == package or component.name.startswith(package + ".")
            for package in packages
        )

    @staticmethod
    def _matches_filters(component: Component, actions: list[str], schemes: set[str]) -> bool:
        if not actions and not schemes:
            return True
        for intent_filter in component.filters:
            action_matches = not actions or any(
                action in intent_filter.actions for action in actions
            )
            scheme_matches = (
                not schemes
                or not intent_filter.schemes
                or bool(schemes.intersection(intent_filter.schemes))
            )
            if action_matches and scheme_matches:
                return True
        return False
