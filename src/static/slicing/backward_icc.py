from __future__ import annotations

from collections import defaultdict, deque
from collections.abc import Callable
from dataclasses import dataclass, replace
from typing import Any, Protocol

from src.static.model.constants import TRUSTED_ENTRY_REACHABILITIES
from src.static.search.dex_ir import parse_method_reference
from src.static.model.values import (
    Component,
    ICCEdge,
    ICCValueObservation,
    MethodRef,
    Origin,
    SinkSite,
    TracePath,
    TraceStep,
)


COMPONENT_ORIGINS = {"component_intent", "component_field", "component_parameter"}
ACTIVITY_LIFECYCLE = {
    "onCreate",
    "onStart",
    "onResume",
    "onRestart",
    "onPostCreate",
    "onPostResume",
    "onNewIntent",
}
DESTINATION_FIELDS = {"component", "class", "package"}
MAX_BACKWARD_ICC_CACHE_ENTRIES = 2000


class IncomingICCProvider(Protocol):
    def incoming_edges(self, target_component: str) -> list[ICCEdge]: ...


@dataclass(frozen=True)
class BackwardICCPath:
    """One data-supported route from an external Entry to an internal Source."""

    origin: Origin
    components: tuple[str, ...]
    icc_edges: tuple[ICCEdge, ...]
    entry_reachability: str
    transfer_evidence: tuple[dict[str, Any], ...] = ()
    transported_field: str | None = None


@dataclass(frozen=True)
class _MatchedObservation:
    observation: ICCValueObservation
    requested_field: str | None
    match_kind: str
    field_direct: bool


class BackwardICCTracer:
    """Trace component-local Intent Sources through incoming ICC data.

    Component reachability is used only as a bounded candidate index.  A path
    is returned only when every hop has a matching receiver callback and a
    matching live Intent observation at the sending dispatch. A hop is marked
    direct only when its target, callback and field/key transfer are exact.
    """

    def __init__(
        self,
        icc_edges_by_site: dict[str, list[ICCEdge]],
        sites_by_id: dict[str, SinkSite],
        components: list[Component],
        *,
        max_depth: int,
        max_paths: int,
        max_states: int | None = None,
        max_live_entry_num: int = 3,
        max_dead_entry_num: int = 5,
        backend: Any | None = None,
        incoming_provider: IncomingICCProvider | None = None,
        analysis_frontier_sink: Callable[[dict[str, Any]], None] | None = None,
    ) -> None:
        self.sites_by_id = sites_by_id
        self.components = {component.name: component for component in components}
        self.max_depth = max(1, max_depth)
        self.max_paths = max(1, max_paths)
        self.max_live_entry_num = max(1, max_live_entry_num)
        self.max_dead_entry_num = max(1, max_dead_entry_num)
        self.max_states = max(
            1,
            max_states
            if max_states is not None
            else max(256, self.max_depth * self.max_paths * 16),
        )
        self.backend = backend
        self.incoming_provider = incoming_provider
        self.analysis_frontier_sink = analysis_frontier_sink
        self.methods_by_display = {
            method.display(): method for method in getattr(backend, "methods", {})
        }
        self.incoming: dict[str, list[ICCEdge]] = defaultdict(list)
        for edges in icc_edges_by_site.values():
            for edge in edges:
                if edge.target_component:
                    self.incoming[edge.target_component].append(edge)
        for edges in self.incoming.values():
            edges.sort(key=self._edge_rank)

        self.requests = 0
        self.resolved_paths = 0
        self.unresolved_origins = 0
        self.depth_truncations = 0
        self.path_truncations = 0
        self.entry_truncations = 0
        self.cycles = 0
        self.owner_mismatches = 0
        self.state_truncations = 0
        self.provider_incomplete_requests = 0
        self.states_explored = 0
        self.cache_hits = 0
        self.cache_misses = 0
        self.unresolved_boundary_count = 0
        self._cache: dict[tuple[Any, ...], tuple[BackwardICCPath, ...]] = {}
        self._request_states = 0
        self._request_state_truncated = False
        self._request_provider_incomplete = False
        self._loaded_incoming_components: set[str] = set()

    def _incoming_edges(self, component: str) -> list[ICCEdge]:
        if (
            self.incoming_provider is not None
            and component not in self._loaded_incoming_components
        ):
            provided_edges = self.incoming_provider.incoming_edges(component)
            provider_complete = getattr(
                self.incoming_provider, "last_request_complete", True
            )
            if not provider_complete:
                self._request_provider_incomplete = True
            else:
                self._loaded_incoming_components.add(component)
            for edge in provided_edges:
                if edge.target_component == component and edge not in self.incoming[component]:
                    self.incoming[component].append(edge)
            self.incoming[component].sort(key=self._edge_rank)
        return self.incoming.get(component, [])

    def resolve(self, origin: Origin) -> list[BackwardICCPath]:
        self.requests += 1
        cache_key = self._origin_key(origin)
        cached = self._cache.get(cache_key)
        if cached is not None:
            self.cache_hits += 1
            result = list(cached)
            self.resolved_paths += len(result)
            if not result:
                self.unresolved_origins += 1
            return result
        self.cache_misses += 1
        self._request_states = 0
        self._request_state_truncated = False
        self._request_provider_incomplete = False
        result, truncated = self._resolve(origin, frozenset(), 0)
        self.states_explored += self._request_states
        result, entry_truncated = self._limit_entry_paths(result)
        if len(result) > self.max_paths:
            result = result[: self.max_paths]
            entry_truncated = True
        result = [self._mark_internal_source(path, origin) for path in result]
        if truncated:
            self.path_truncations += 1
        if self._request_state_truncated:
            self.state_truncations += 1
        if self._request_provider_incomplete:
            self.provider_incomplete_requests += 1
        if entry_truncated:
            self.entry_truncations += 1
        if not result:
            self.unresolved_origins += 1
        self.resolved_paths += len(result)
        if not self._request_state_truncated and not self._request_provider_incomplete:
            self._cache[cache_key] = tuple(result)
            if len(self._cache) > MAX_BACKWARD_ICC_CACHE_ENTRIES:
                self._cache.pop(next(iter(self._cache)))
        return result

    def _limit_entry_paths(
        self, paths: list[BackwardICCPath]
    ) -> tuple[list[BackwardICCPath], bool]:
        exact: list[BackwardICCPath] = []
        approximate: list[BackwardICCPath] = []
        for path in paths:
            if self._is_exact_entry_path(path):
                exact.append(path)
            else:
                approximate.append(path)
        exact = exact[: self.max_live_entry_num]
        approximate = approximate[: self.max_dead_entry_num]
        return [*exact, *approximate], (
            len(paths) > len(exact) + len(approximate)
        )

    def _is_exact_entry_path(self, path: BackwardICCPath) -> bool:
        return path.entry_reachability in {
            *TRUSTED_ENTRY_REACHABILITIES,
            "backward_icc_exact_candidate",
        }

    def _resolve(
        self,
        receiver: Origin,
        visited: frozenset[tuple[Any, ...]],
        depth: int,
    ) -> tuple[list[BackwardICCPath], bool]:
        if self._request_state_truncated:
            return [], False
        if receiver.external:
            component = self.components.get(receiver.component or "")
            if component is None or not component.is_entry_point:
                return [], False
            return (
                [
                    BackwardICCPath(
                        origin=receiver,
                        components=(component.name,),
                        icc_edges=(),
                        entry_reachability={
                            "manifest_runtime_activation": (
                                "direct_manifest_runtime_activation"
                            ),
                            "dynamic_receiver_registration": (
                                "direct_dynamic_receiver"
                            ),
                        }.get(
                            component.entry_provenance,
                            "direct_manifest",
                        ),
                    )
                ],
                False,
            )
        if receiver.kind not in COMPONENT_ORIGINS or not receiver.component:
            return [], False
        self._request_states += 1
        if self._request_states > self.max_states:
            self._request_state_truncated = True
            return [], False
        if depth >= self.max_depth:
            self.depth_truncations += 1
            return [], False

        marker = (
            receiver.component,
            receiver.method,
            receiver.offset,
            receiver.field,
            receiver.key,
        )
        if marker in visited:
            self.cycles += 1
            return [], False
        next_visited = visited | {marker}
        result: list[BackwardICCPath] = []
        seen: set[tuple[Any, ...]] = set()
        truncated = False

        for edge in self._incoming_edges(receiver.component):
            callback, callback_kind = self._matching_callback(receiver, edge)
            if callback is None:
                self._record_unresolved_boundary(
                    receiver,
                    edge,
                    "receiver_callback_not_connected_to_target_callback",
                )
                continue
            matches = self._matching_observations(receiver, edge)
            if not matches:
                self._record_unresolved_boundary(
                    receiver,
                    edge,
                    "receiver_field_or_key_not_observed_at_dispatch",
                )
            for match in matches:
                upstream = match.observation.origin
                if (
                    edge.source_component is not None
                    and upstream.component is not None
                    and edge.source_component != upstream.component
                ):
                    self.owner_mismatches += 1
                    self._record_unresolved_boundary(
                        receiver,
                        edge,
                        "dispatch_owner_mismatch",
                        match,
                    )
                    continue
                upstream_paths, upstream_truncated = self._resolve(
                    upstream, next_visited, depth + 1
                )
                truncated = truncated or upstream_truncated
                for upstream_path in upstream_paths:
                    path = self._bridge(
                        upstream_path,
                        receiver,
                        edge,
                        callback,
                        callback_kind,
                        match,
                    )
                    path_key = self._path_key(path)
                    if path_key in seen:
                        continue
                    seen.add(path_key)
                    result.append(path)
                    # Keep one unique overflow item so exactly max_paths
                    # routes do not get reported as truncated.
                    if len(result) > self.max_paths:
                        return result, True
        return result, truncated

    def _matching_observations(
        self, receiver: Origin, edge: ICCEdge
    ) -> list[_MatchedObservation]:
        observations = list(edge.value_observations)
        if not observations:
            return []

        if receiver.field is None:
            result = [
                _MatchedObservation(
                    observation=item,
                    requested_field=None,
                    match_kind=(
                        "whole_intent"
                        if item.target_field == "whole_intent"
                        else "field_in_whole_intent"
                    ),
                    field_direct=self._observation_field_is_exact(item.target_field),
                )
                for item in observations
            ]
            return sorted(result, key=self._match_rank)

        requested = self._transport_marker(receiver.field, receiver.key)
        selected: list[tuple[ICCValueObservation, str, bool]] = []
        if receiver.field == "query_parameter":
            selected.extend(
                (item, "data_to_query_parameter", False)
                for item in observations
                if item.target_field == "data"
            )
        elif receiver.field == "extras":
            selected.extend(
                (item, "extra_in_bundle", False)
                for item in observations
                if item.target_field == "extra" or item.target_field.startswith("extra:")
            )
        elif receiver.field == "extra" and receiver.key is None:
            selected.extend(
                (item, "unknown_extra_key", False)
                for item in observations
                if item.target_field == "extra" or item.target_field.startswith("extra:")
            )
        else:
            selected.extend(
                (item, "exact_field_key", True)
                for item in observations
                if item.target_field == requested
            )

        if not selected and receiver.field == "extra" and receiver.key is not None:
            selected.extend(
                (item, "unknown_sender_extra_key", False)
                for item in observations
                if item.target_field == "extra"
            )

        # A matching setter and an incoming whole Intent can belong to
        # different branches, so retain both candidates.
        for item in observations:
            if item.target_field != "whole_intent":
                continue
            selected.append((item, "whole_intent_field_fallback", False))

        result = [
            _MatchedObservation(item, requested, match_kind, direct)
            for item, match_kind, direct in selected
        ]
        return sorted(result, key=self._match_rank)

    def _matching_callback(
        self, receiver: Origin, edge: ICCEdge
    ) -> tuple[str | None, str]:
        callbacks = list(edge.target_callback_nodes)
        concrete = [
            callback for callback in callbacks if "(framework callback)" not in callback
        ]

        # Check all concrete callbacks before any lifecycle approximation. This
        # prevents an early onCreate fallback from hiding an exact onNewIntent.
        if receiver.method:
            for callback in concrete:
                if receiver.method == callback:
                    return callback, "exact_callback"
            for callback in concrete:
                if self._direct_caller_chain_reaches(receiver.method, callback):
                    return callback, "direct_caller_chain"

        methods = {receiver.method, *(step.method for step in receiver.path)}
        methods.discard(None)
        if callbacks and self._activity_lifecycle_reaches(methods, edge.target_component):
            return self._preferred_lifecycle_callback(callbacks), "activity_lifecycle"

        fragment_owners = getattr(self.backend, "fragment_owner_components", None)
        if callable(fragment_owners):
            receiver_methods = {
                self.methods_by_display.get(name or "")
                for name in {receiver.method, *(step.method for step in receiver.path)}
            }
            receiver_methods.discard(None)
            for receiver_method in receiver_methods:
                owners = fragment_owners(receiver_method.class_name)
                if any(item.name == edge.target_component for item in owners):
                    return (
                        self._preferred_lifecycle_callback(callbacks),
                        "fragment_owner_callback",
                    )

        # component_roots() was already used to label the receiver Origin. It
        # is not independent callback evidence and must not complete a path.
        return None, "callback_unmatched"

    def _direct_caller_chain_reaches(self, method_name: str, callback: str) -> bool:
        if self.backend is None:
            return False
        start = self.methods_by_display.get(method_name)
        if start is None:
            return False
        queue = deque([start])
        visited: set[MethodRef] = set()
        while queue and len(visited) < 256:
            method = queue.popleft()
            if method in visited:
                continue
            visited.add(method)
            if self._method_matches_callback(method, callback):
                return True
            for site in self.backend.callers.get(method, ()):
                caller_method = self.backend.methods.get(site.caller)
                if caller_method is None:
                    continue
                instruction = caller_method.instructions[site.instruction_index]
                parsed = parse_method_reference(instruction.reference)
                if parsed is not None and MethodRef(*parsed) == method:
                    queue.append(site.caller)
        return False

    def _activity_lifecycle_reaches(
        self, methods: set[str | None], target_component: str | None
    ) -> bool:
        component = self.components.get(target_component or "")
        if component is None or component.component_type != "activity":
            return False
        for name in methods:
            method = self.methods_by_display.get(name or "")
            if (
                method is not None
                and method.class_name == component.descriptor
                and method.name in ACTIVITY_LIFECYCLE
            ):
                return True
        return False

    def _bridge(
        self,
        upstream: BackwardICCPath,
        receiver: Origin,
        edge: ICCEdge,
        callback: str,
        callback_kind: str,
        match: _MatchedObservation,
    ) -> BackwardICCPath:
        observation = match.observation
        route_direct = edge.resolution in {"explicit_component", "route_registry"}
        callback_direct = callback_kind in {
            "exact_callback",
            "direct_caller_chain",
            "fragment_owner_callback",
        }
        owner_status = (
            "unknown"
            if not edge.source_component or not observation.origin.component
            else "same"
            if edge.source_component == observation.origin.component
            else "different"
        )
        owner_direct = owner_status == "same"
        exact_candidate = (
            route_direct
            and callback_direct
            and match.field_direct
            and owner_direct
        )
        # The current SSG is a may-analysis: live target and payload writers can
        # come from different branch alternatives.  The hop is therefore a
        # data-supported candidate, but cannot yet be called a direct transfer.
        hop_direct = False

        reasons: list[str] = []
        if not route_direct:
            reasons.append("icc_target_not_explicit")
        if not callback_direct:
            reasons.append("callback_continuity_approximate")
        if not match.field_direct:
            reasons.append("field_or_key_match_approximate")
        if not owner_direct:
            reasons.append("dispatch_owner_continuity_unknown")
        reasons.append("dispatch_path_correlation_unproven")
        evidence = {
            "source_component": edge.source_component,
            "target_component": edge.target_component,
            "source_site": edge.source_site,
            "dispatch_api": edge.dispatch_api,
            "resolution": edge.resolution,
            "target_callback": callback,
            "callback_match": callback_kind,
            "receiver_api": receiver.api,
            "receiver_method": receiver.method,
            "receiver_offset": receiver.offset,
            "receiver_field": receiver.field,
            "receiver_key": receiver.key,
            "required_field": match.requested_field,
            "observed_field": observation.target_field,
            "observed_origin_kind": observation.origin.kind,
            "observed_origin_api": observation.origin.api,
            "observed_origin_field": observation.origin.field,
            "observed_origin_key": observation.origin.key,
            "observed_origin_component": observation.origin.component,
            "observed_origin_method": observation.origin.method,
            "observed_origin_offset": observation.origin.offset,
            "observed_setter": observation.setter,
            "observed_write_method": observation.method,
            "observed_write_offset": observation.offset,
            "dispatch_owner_continuity": owner_status,
            "match_kind": match.match_kind,
            "static_match_strength": (
                "exact_candidate" if exact_candidate else "approximate_candidate"
            ),
            "value_transfer_status": "unproven",
            "reasons": reasons,
        }

        path = upstream.origin.path
        if observation.setter or observation.method or observation.offset is not None:
            path = path.append(
                TraceStep(
                    method=observation.method or edge.source_site,
                    offset=observation.offset,
                    instruction=observation.setter or f"Intent.{observation.target_field}",
                    relation=f"value assigned to outgoing Intent {observation.target_field}",
                    edge_type="INTENT_FIELD_ASSIGNMENT",
                    direct=True,
                    evidence=evidence,
                )
            )
        site = self.sites_by_id.get(edge.source_site)
        path = path.append(
            TraceStep(
                method=site.method.display() if site else edge.source_site,
                offset=site.offset if site else None,
                instruction=site.api if site else edge.dispatch_api,
                relation="Intent reaches ICC dispatch",
                edge_type="ICC_ARGUMENT",
                direct=site is not None,
                evidence=evidence,
            )
        )
        path = path.append(
            TraceStep(
                method=callback,
                offset=None,
                instruction="framework ICC callback",
                relation="incoming ICC callback",
                edge_type="ICC",
                direct=route_direct and callback_direct,
                evidence=evidence,
            )
        )
        path = path.append(
            TraceStep(
                method=receiver.method or callback,
                offset=receiver.offset,
                instruction=receiver.api or receiver.kind,
                relation="incoming Intent value read",
                edge_type="ICC_DATA_TRANSFER",
                direct=hop_direct,
                evidence=evidence,
            )
        )
        for step in receiver.path:
            path = path.append(step)

        transported_field = upstream.transported_field
        if receiver.field is None and observation.target_field != "whole_intent":
            transported_field = observation.target_field.split(":", 1)[0]

        components = upstream.components
        if edge.source_component and (not components or components[-1] != edge.source_component):
            components = (*components, edge.source_component)
        if receiver.component and (not components or components[-1] != receiver.component):
            components = (*components, receiver.component)
        upstream_exact = upstream.entry_reachability in {
            *TRUSTED_ENTRY_REACHABILITIES,
            "backward_icc_exact_candidate",
        }
        reachability = (
            "backward_icc_exact_candidate"
            if exact_candidate and upstream_exact
            else "backward_icc_approximate"
        )
        return BackwardICCPath(
            origin=Origin(
                kind=upstream.origin.kind,
                api=upstream.origin.api,
                field=upstream.origin.field,
                key=upstream.origin.key,
                value=upstream.origin.value,
                component=upstream.origin.component,
                method=upstream.origin.method,
                offset=upstream.origin.offset,
                path=path,
            ),
            components=components,
            icc_edges=(*upstream.icc_edges, edge),
            entry_reachability=reachability,
            transfer_evidence=(*upstream.transfer_evidence, evidence),
            transported_field=transported_field,
        )

    def metrics(self) -> dict[str, int]:
        return {
            "backward_icc_requests": self.requests,
            "backward_icc_resolved_paths": self.resolved_paths,
            "backward_icc_unresolved_origins": self.unresolved_origins,
            "backward_icc_depth_truncations": self.depth_truncations,
            "backward_icc_path_truncations": self.path_truncations,
            "backward_icc_entry_truncations": self.entry_truncations,
            "backward_icc_live_entry_cap": self.max_live_entry_num,
            "backward_icc_dead_entry_cap": self.max_dead_entry_num,
            "backward_icc_state_truncations": self.state_truncations,
            "backward_icc_provider_incomplete_requests": self.provider_incomplete_requests,
            "backward_icc_states_explored": self.states_explored,
            "backward_icc_cycles": self.cycles,
            "backward_icc_owner_mismatches": self.owner_mismatches,
            "backward_icc_cache_hits": self.cache_hits,
            "backward_icc_cache_misses": self.cache_misses,
            "backward_icc_unresolved_boundaries": self.unresolved_boundary_count,
        }

    @staticmethod
    def _mark_internal_source(
        path: BackwardICCPath, local_origin: Origin
    ) -> BackwardICCPath:
        if not path.icc_edges:
            return path
        steps = list(path.origin.path)
        for index in range(len(steps) - 1, -1, -1):
            step = steps[index]
            if step.edge_type != "ICC_DATA_TRANSFER":
                continue
            evidence = dict(step.evidence)
            evidence["internal_source"] = True
            evidence["internal_source_origin"] = {
                "kind": local_origin.kind,
                "api": local_origin.api,
                "field": local_origin.field,
                "key": local_origin.key,
                "component": local_origin.component,
                "method": local_origin.method,
                "offset": local_origin.offset,
            }
            steps[index] = replace(step, evidence=evidence)
            break
        return replace(
            path,
            origin=replace(path.origin, path=TracePath.from_steps(steps)),
        )

    def _record_unresolved_boundary(
        self,
        receiver: Origin,
        edge: ICCEdge,
        reason: str,
        match: _MatchedObservation | None = None,
    ) -> None:
        self.unresolved_boundary_count += 1
        if self.analysis_frontier_sink is None:
            return
        record: dict[str, Any] = {
            "kind": "backward_icc_boundary",
            "reason": reason,
            "receiver": {
                "kind": receiver.kind,
                "component": receiver.component,
                "method": receiver.method,
                "offset": receiver.offset,
                "field": receiver.field,
                "key": receiver.key,
            },
            "incoming_icc": {
                "source_site": edge.source_site,
                "source_component": edge.source_component,
                "target_component": edge.target_component,
                "resolution": edge.resolution,
            },
        }
        if match is not None:
            origin = match.observation.origin
            record["observed_origin"] = {
                "kind": origin.kind,
                "component": origin.component,
                "method": origin.method,
                "offset": origin.offset,
                "target_field": match.observation.target_field,
            }
        self.analysis_frontier_sink(record)

    @staticmethod
    def _path_key(path: BackwardICCPath) -> tuple[Any, ...]:
        return (
            BackwardICCTracer._origin_key(path.origin),
            path.components,
            tuple(BackwardICCTracer._edge_key(edge) for edge in path.icc_edges),
            path.entry_reachability,
            path.transported_field,
            tuple(
                BackwardICCTracer._evidence_key(item)
                for item in path.transfer_evidence
            ),
        )

    @staticmethod
    def _origin_key(origin: Origin) -> tuple[Any, ...]:
        """Identify an origin without rendering nested ICC evidence."""
        return (
            origin.kind,
            origin.api,
            origin.field,
            origin.key,
            (
                origin.value
                if isinstance(origin.value, (str, int, float, bool, type(None)))
                else type(origin.value).__name__
            ),
            origin.component,
            origin.method,
            origin.offset,
            origin.outer_field,
            origin.outer_key,
            tuple(
                (
                    step.method,
                    step.offset,
                    step.instruction,
                    step.relation,
                    step.edge_type,
                    step.direct,
                    BackwardICCTracer._evidence_key(step.evidence),
                )
                for step in origin.path
            ),
        )

    @staticmethod
    def _edge_key(edge: ICCEdge) -> tuple[Any, ...]:
        """Identify an ICC route without copying all value observations."""
        return (
            edge.source_site,
            edge.source_component,
            edge.dispatch_api,
            edge.target_component,
            edge.target_callback_nodes,
            edge.resolution,
            edge.reason,
            edge.carried_fields,
        )

    @staticmethod
    def _evidence_key(evidence: dict[str, Any]) -> tuple[Any, ...]:
        """Retain only fields that distinguish ICC transfers."""
        names = (
            "source_site",
            "source_component",
            "target_component",
            "target_callback",
            "receiver_method",
            "receiver_offset",
            "receiver_field",
            "receiver_key",
            "observed_field",
            "observed_origin_kind",
            "observed_origin_component",
            "observed_origin_method",
            "observed_origin_offset",
            "observed_setter",
            "observed_write_method",
            "observed_write_offset",
            "match_kind",
        )
        return tuple(evidence.get(name) for name in names)

    @staticmethod
    def _transport_marker(field: str, key: str | None) -> str:
        if field == "query_parameter":
            return "data"
        if field in {"extra", "extras"}:
            return f"extra:{key}" if key is not None else "extra"
        return field

    @staticmethod
    def _observation_field_is_exact(field: str) -> bool:
        return field != "extra" and not field.endswith(":None")

    @staticmethod
    def _match_rank(match: _MatchedObservation) -> tuple[int, str, str, int]:
        order = {
            "exact_field_key": 0,
            "whole_intent": 0,
            "field_in_whole_intent": 1,
            "data_to_query_parameter": 2,
            "extra_in_bundle": 2,
            "unknown_extra_key": 3,
            "unknown_sender_extra_key": 3,
            "whole_intent_field_fallback": 4,
        }
        origin = match.observation.origin
        return (
            order.get(match.match_kind, 9),
            origin.component or "",
            origin.method or "",
            origin.offset if origin.offset is not None else -1,
        )

    @staticmethod
    def _method_matches_callback(method: MethodRef, callback: str) -> bool:
        return "(framework callback)" not in callback and method.display() == callback

    @staticmethod
    def _preferred_lifecycle_callback(callbacks: list[str]) -> str:
        return next(
            (callback for callback in callbacks if "->onCreate" in callback),
            callbacks[0],
        )

    @staticmethod
    def _edge_rank(edge: ICCEdge) -> tuple[int, str, str]:
        resolution_order = {
            "explicit_component": 0,
            "implicit_filter": 1,
            "attacker_controlled_candidate": 2,
            "dynamic_implicit_candidate": 3,
            "type_candidate": 4,
        }
        return (
            resolution_order.get(edge.resolution, 9),
            edge.source_component or "",
            edge.source_site,
        )


__all__ = ["BackwardICCPath", "BackwardICCTracer"]
