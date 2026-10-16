'''Source → 경로 → Sink를 node/edge 그래프로 변환, 취약점 분류 담당'''
from __future__ import annotations

import hashlib
from itertools import pairwise
from typing import Any

from src.static.model.constants import (
    CONFIRMED,
    ENTRY_REACHABILITY_DYNAMIC_RECEIVER,
    ENTRY_REACHABILITY_DIRECT_MANIFEST,
    ENTRY_REACHABILITY_MANIFEST_RUNTIME,
    ENTRY_REACHABILITY_UNCONFIRMED,
    NON_PROOVED,
    PATH_CLASS_ATTACKER_SOURCE,
    SOURCE_ROLE_CONTROL,
    UNCONFIRMED,
)
from src.static.classification.confirmation import StrictConfirmationPolicy
from src.static.search.manifest import generic_attacker_can_invoke
from src.static.classification.spoofing import match_spoofing_rules
from src.static.model.evidence import FlowGraph, GraphEdge, GraphNode, GraphPath
from src.static.model.values import (
    Component,
    EvidenceSource,
    FlowEvidence,
    ICCEdge,
    ICCValueObservation,
    TraceStep,
    serializable,
)

SOURCE_KINDS = {
    "external_intent",
    "external_field",
    "nested_external_intent",
    "uri_parsed_external_intent",
    "external_parameter",
    "component_intent",
    "component_field",
    "component_parameter",
    "external_invocation",
}


def stable_id(prefix: str, value: str, size: int = 12) -> str:
    digest = hashlib.sha1(value.encode("utf-8")).hexdigest()[:size]
    return f"{prefix}-{digest}"


def short_method(value: str | None) -> str:
    if not value:
        return "unknown"
    tail = value.split("->", 1)[-1]
    return tail.split("(", 1)[0]


def short_api(value: str | None) -> str:
    if not value:
        return "unknown source"
    return short_method(value)


class GraphRegistry:
    def __init__(self) -> None:
        self.nodes: list[GraphNode] = []
        self.edges: list[GraphEdge] = []
        self._node_ids: dict[tuple[Any, ...], str] = {}
        self._edge_ids: dict[tuple[Any, ...], str] = {}
        self._edge_direct: dict[str, bool] = {}
        self._next_node_id = 1
        self._next_edge_id = 1
        self._touched_node_ids: set[str] = set()
        self._touched_edge_ids: set[str] = set()

    def node(self, identity: tuple[Any, ...], **values: Any) -> str:
        existing = self._node_ids.get(identity)
        if existing is not None:
            self._touched_node_ids.add(existing)
            return existing
        node_id = f"n{self._next_node_id:04d}"
        self._next_node_id += 1
        self._node_ids[identity] = node_id
        self.nodes.append(GraphNode(id=node_id, **values))
        self._touched_node_ids.add(node_id)
        return node_id

    def edge(
        self,
        source: str,
        target: str,
        edge_type: str,
        direct: bool,
        relation: str,
        evidence: dict[str, Any] | None = None,
    ) -> str | None:
        if source == target:
            return None
        evidence = evidence or {}
        mode = "direct" if direct else "approximate"
        evidence_key = self._edge_evidence_key(evidence)
        if "mode" not in evidence:
            evidence_key = tuple(sorted((*evidence_key, ("mode", mode))))
        key = (
            source,
            target,
            edge_type,
            direct,
            relation,
            evidence_key,
        )
        existing = self._edge_ids.get(key)
        if existing is not None:
            self._touched_edge_ids.add(existing)
            return existing
        payload = dict(evidence)
        payload.setdefault("mode", mode)
        edge_id = f"e{self._next_edge_id:06d}"
        self._next_edge_id += 1
        self._edge_ids[key] = edge_id
        self._edge_direct[edge_id] = direct
        self.edges.append(
            GraphEdge(
                id=edge_id,
                source=source,
                target=target,
                type=edge_type,
                direct=direct,
                relation=relation,
                evidence=payload,
            )
        )
        self._touched_edge_ids.add(edge_id)
        return edge_id

    @staticmethod
    def _edge_evidence_key(payload: dict[str, Any]) -> tuple[tuple[str, Any], ...]:
        """Use only cheap scalar evidence to distinguish structural edges."""
        return tuple(
            sorted(
                (name, value)
                for name, value in payload.items()
                if value is None or isinstance(value, (str, int, float, bool))
            )
        )

    def take_touched(self) -> tuple[set[str], set[str]]:
        """Return IDs used by the graph just built and start a fresh capture."""
        node_ids = self._touched_node_ids
        edge_ids = self._touched_edge_ids
        self._touched_node_ids = set()
        self._touched_edge_ids = set()
        return node_ids, edge_ids

    def prune(self, active_node_ids: set[str], active_edge_ids: set[str]) -> None:
        """Discard registry payloads unreachable from the latest sink graphs."""
        kept_edge_ids = set(active_edge_ids)
        kept_edges = [edge for edge in self.edges if edge.id in kept_edge_ids]
        kept_node_ids = set(active_node_ids)
        for edge in kept_edges:
            kept_node_ids.add(edge.source)
            kept_node_ids.add(edge.target)

        self.nodes = [node for node in self.nodes if node.id in kept_node_ids]
        self.edges = kept_edges
        self._node_ids = {
            identity: node_id
            for identity, node_id in self._node_ids.items()
            if node_id in kept_node_ids
        }
        self._edge_ids = {
            identity: edge_id
            for identity, edge_id in self._edge_ids.items()
            if edge_id in kept_edge_ids
        }
        self._edge_direct = {
            edge_id: direct
            for edge_id, direct in self._edge_direct.items()
            if edge_id in kept_edge_ids
        }


class FlowGraphAssembler:
    """Intern all flow evidence into one analysis-wide graph registry."""

    def __init__(self, components: list[Component]) -> None:
        self.components = {component.name: component for component in components}
        self.registry = GraphRegistry()
        self.confirmation_policy = StrictConfirmationPolicy()
        self.value_observation_pool: dict[
            str, tuple[ICCValueObservation, ...]
        ] = {}
        self._value_observation_ids: dict[int, str] = {}
        self._next_value_observation_id = 1

    @property
    def nodes(self) -> list[GraphNode]:
        return self.registry.nodes

    @property
    def edges(self) -> list[GraphEdge]:
        return self.registry.edges

    def take_touched(self) -> tuple[set[str], set[str]]:
        return self.registry.take_touched()

    def prune(
        self,
        node_ids: set[str],
        edge_ids: set[str],
        observation_ids: set[str] | None = None,
    ) -> None:
        self.registry.prune(node_ids, edge_ids)
        if observation_ids is None:
            return
        self.value_observation_pool = {
            key: value
            for key, value in self.value_observation_pool.items()
            if key in observation_ids
        }
        self._value_observation_ids = {
            identity: key
            for identity, key in self._value_observation_ids.items()
            if key in observation_ids
        }

    def build(self, flow: FlowEvidence) -> FlowGraph:
        registry = self.registry
        component_ids = self._component_nodes(registry, flow)
        sink_id = self._sink_node(registry, flow)
        graph_id = stable_id("graph", flow.flow_id)
        paths: list[GraphPath] = []
        source_ids: list[str] = []
        source_roles: dict[str, list[str]] = {}
        unresolved: list[str] = []

        if flow.sources:
            for source_index, source in enumerate(flow.sources, 1):
                entry_component = self.components.get(flow.entry_point.component)
                attacker_controlled = bool(
                    source.attacker_controlled
                    and entry_component is not None
                    and generic_attacker_can_invoke(entry_component)
                )
                entry_source_id = self._origin_node(
                    registry, source, attacker_controlled
                )
                modeled_source = source.origin.kind in SOURCE_KINDS
                node_ids, edge_ids, source_to_sink_edge_ids = self._path_prefix(
                    registry, flow, component_ids, source, entry_source_id
                )
                previous = node_ids[-1]
                source_id = entry_source_id
                source_origin_kind = source.origin.kind
                internal_source_seen = False
                has_internal_source = any(
                    bool(step.evidence.get("internal_source"))
                    for step in source.origin.path
                )
                for step in source.origin.path:
                    step_id = self._step_node(registry, step)
                    edge_type, direct = self._relation(step)
                    edge_id = registry.edge(
                        previous,
                        step_id,
                        edge_type,
                        direct,
                        step.relation,
                        {
                            "method": step.method,
                            "offset": step.offset,
                            "instruction": step.instruction,
                            **step.evidence,
                        },
                    )
                    if edge_id is not None:
                        edge_ids.append(edge_id)
                        if internal_source_seen or not has_internal_source:
                            source_to_sink_edge_ids.append(edge_id)
                    if not node_ids or node_ids[-1] != step_id:
                        node_ids.append(step_id)
                    if step.evidence.get("internal_source"):
                        source_id = step_id
                        source_origin_kind = (
                            step.evidence.get("internal_source_origin", {}).get("kind")
                            or source_origin_kind
                        )
                        internal_source_seen = True
                    previous = step_id
                control_dependency = source.role.value == SOURCE_ROLE_CONTROL
                invocation = source.role.value == "invocation"
                edge_id = registry.edge(
                    previous,
                    sink_id,
                    "INVOCATION_EFFECT" if invocation else "CONTROL_DEPENDENCY" if control_dependency else "SINK_ARGUMENT",
                    True,
                    (
                        f"external invocation may execute {flow.sink.api_name}"
                        if invocation else f"value controls reachability of {flow.sink.api_name}"
                        if control_dependency
                        else f"value reaches {flow.sink.api_name} argument"
                    ),
                    {"sink_api": flow.sink.api, "sink_offset": flow.sink.offset},
                )
                if edge_id is not None:
                    edge_ids.append(edge_id)
                    source_to_sink_edge_ids.append(edge_id)
                if not node_ids or node_ids[-1] != sink_id:
                    node_ids.append(sink_id)
                if modeled_source and source_id not in source_ids:
                    source_ids.append(source_id)
                if modeled_source:
                    roles = source_roles.setdefault(source_id, [])
                    if source.role.value not in roles:
                        roles.append(source.role.value)
                source_evidence = self._path_evidence(registry, source_to_sink_edge_ids)
                branch_candidate = self._is_branch_candidate_source(
                    source, modeled_source, attacker_controlled
                )
                spoofing_evidence = match_spoofing_rules(
                    flow, source, self.components
                )
                paths.append(
                    GraphPath(
                        id=f"{graph_id}-path-{source_index:03d}",
                        node_ids=self._deduplicate_adjacent(node_ids),
                        edge_ids=edge_ids,
                        source_id=(source_id if modeled_source else None),
                        entry_point_id=component_ids[0] if component_ids else None,
                        **self._path_evidence(registry, edge_ids),
                        path_class=self._path_class(
                            modeled_source, attacker_controlled
                        ),
                        candidate_types=self._candidate_types_for_source(
                            flow,
                            source,
                            attacker_controlled,
                            bool(spoofing_evidence),
                        ),
                        source_role=source.role.value if modeled_source else None,
                        spoofing_evidence=spoofing_evidence,
                        spoofing_conditions=source.spoofing_conditions,
                        source_origin_kind=(source_origin_kind if modeled_source else None),
                        entry_origin_kind=(source.origin.kind if modeled_source else None),
                        attacker_controlled=(attacker_controlled if modeled_source else False),
                        source_to_sink_evidence_mode=source_evidence["evidence_mode"],
                        source_to_sink_direct_edge_count=source_evidence[
                            "direct_edge_count"
                        ],
                        source_to_sink_approximate_edge_count=source_evidence[
                            "approximate_edge_count"
                        ],
                        entry_reachability=self._entry_reachability(
                            flow, source
                        ),
                        entry_transfer_evidence=list(source.entry_transfer_evidence),
                        control_branch_evidence=list(source.control_branch_evidence),
                        branch_candidate=branch_candidate,
                        branch_candidate_status=(
                            "unresolved" if branch_candidate else "none"
                        ),
                        guards=list(source.route_guards),
                        guard_assessments=list(source.route_guard_assessments),
                        guard_coverage=list(source.route_guard_coverage),
                    )
                )
                if source.origin.kind == "unknown":
                    unresolved.append(
                        "unresolved value origin at "
                        f"{source.origin.method or flow.sink.method.display()}"
                    )
        else:
            node_ids = list(component_ids)
            edge_ids: list[str] = []
            component_names = [item.component for item in flow.nodes]
            for index, (left, right) in enumerate(pairwise(component_ids)):
                edge_id = self._component_edge(
                    registry,
                    flow,
                    left,
                    right,
                    component_names[index],
                    component_names[index + 1],
                )
                if edge_id is not None:
                    edge_ids.append(edge_id)
            previous = node_ids[-1] if node_ids else None
            if previous is not None:
                edge_id = registry.edge(
                    previous,
                    sink_id,
                    "REACHABILITY",
                    False,
                    "entry component can reach sink owner; no modeled source",
                )
                if edge_id is not None:
                    edge_ids.append(edge_id)
            node_ids.append(sink_id)
            paths.append(
                GraphPath(
                    id=f"{graph_id}-path-001",
                    node_ids=self._deduplicate_adjacent(node_ids),
                    edge_ids=edge_ids,
                    source_id=None,
                    entry_point_id=component_ids[0] if component_ids else None,
                    **self._path_evidence(registry, edge_ids),
                    path_class="unresolved_diagnostic",
                )
            )
            unresolved.append("no modeled source found on the sink-targeted slice")

        # Keep control candidates independent until a branch can be correlated
        # with one concrete effect path.

        candidate_types: list[str] = []
        for path in paths:
            for candidate_type in path.candidate_types:
                if candidate_type not in candidate_types:
                    candidate_types.append(candidate_type)
        guard_nodes, guard_edges = self._guard_nodes(registry, flow, sink_id)
        outgoing_targets = self._outgoing_targets(flow)
        graph = FlowGraph(
            graph_id=graph_id,
            candidate_types=candidate_types,
            entry_points=component_ids[:1],
            sources=source_ids,
            source_roles=source_roles,
            sink=sink_id,
            paths=paths,
            guards=list(flow.guards),
            guard_assessments=list(flow.guard_assessments),
            guard_nodes=guard_nodes,
            guard_edges=guard_edges,
            outgoing_targets=outgoing_targets,
            unresolved=list(dict.fromkeys(unresolved)),
        )
        return self.reclassify(graph)

    @staticmethod
    def _link_control_dependencies(paths: list[GraphPath]) -> None:
        """Attach control-only evidence to the sink's concrete effect paths.

        Backward tracing produces one path per origin. A control origin is not
        an alternative value reaching the sink argument, so associate it with
        effect paths in the same sink flow as supporting evidence. This coarse
        association does not recover AND/OR structure or prove that every
        control belongs to every effect; its status therefore remains
        unresolved until predicate correlation is available.
        """

        effects = [
            path
            for path in paths
            if path.source_role != SOURCE_ROLE_CONTROL
            and path.path_class == PATH_CLASS_ATTACKER_SOURCE
            and bool(path.candidate_types)
        ]
        # branch_candidate also encodes weak/unprotected external Entry
        # provenance. Internal, constant, and signature-protected controls do
        # not become dependencies of attacker-driven effects.
        controls = [
            path
            for path in paths
            if path.source_role == SOURCE_ROLE_CONTROL and path.branch_candidate
        ]
        if not effects or not controls:
            return

        effect_ids = [path.id for path in effects]
        control_ids = [path.id for path in controls]
        for control in controls:
            control.supporting = True
            control.support_kind = "control_dependency"
            control.supports_path_ids = list(effect_ids)
        for effect in effects:
            effect.control_dependency_path_ids = list(control_ids)
            effect.control_dependency_status = "unresolved"

    def _is_branch_candidate_source(
        self,
        source: EvidenceSource,
        modeled_source: bool,
        attacker_controlled: bool,
    ) -> bool:
        """Admit external attacker data that may taint a sink-controlling branch."""

        return bool(
            source.role.value == SOURCE_ROLE_CONTROL
            and modeled_source
            and attacker_controlled
            and source.origin.external
            and any(
                item.get("may_control_sink_reachability") is True
                and item.get("predicate_taint_status") == "may_tainted"
                for item in source.control_branch_evidence
            )
        )

    def reclassify(self, graph: FlowGraph) -> FlowGraph:
        """Apply the strict policy after every source of unresolved data is known."""

        confirmed_types: list[str] = []
        counts = {CONFIRMED: 0, NON_PROOVED: 0, UNCONFIRMED: 0}
        branch_candidates = 0
        for path in graph.paths:
            path_guards = path.guards if path.guard_coverage else graph.guards
            path_assessments = (
                path.guard_assessments if path.guard_coverage else graph.guard_assessments
            )
            path_unresolved = list(graph.unresolved)
            if path.guard_coverage and any(
                item.get("status") != "complete" for item in path.guard_coverage
            ):
                path_unresolved.append("guard_scope_incomplete")
            decision = self.confirmation_policy.evaluate(
                path,
                guards=path_guards,
                unresolved=path_unresolved,
                guard_assessments=path_assessments,
            )
            path.confirmation_status = decision.status
            if decision.status == CONFIRMED:
                path.static_status = "static_high_confidence"
            elif (
                path.candidate_types
                and path.attacker_controlled
                and path.entry_point_id is not None
                and path.entry_reachability != ENTRY_REACHABILITY_UNCONFIRMED
            ):
                path.static_status = "static_reachable"
            else:
                path.static_status = "candidate"
            path.confirmed_types = list(decision.confirmed_types)
            path.confirmation_reasons = list(decision.reasons)
            path.rejection_reasons = list(decision.rejection_reasons)
            path.confirmation_warnings = list(decision.warnings)
            if path.branch_candidate:
                branch_candidates += 1
            if not path.supporting and (
                not path.branch_candidate or decision.status == CONFIRMED
            ):
                counts[decision.status] += 1
            for candidate_type in decision.confirmed_types:
                if candidate_type not in confirmed_types:
                    confirmed_types.append(candidate_type)

        if counts[CONFIRMED]:
            graph.classification = CONFIRMED
        elif counts[NON_PROOVED] or branch_candidates:
            graph.classification = NON_PROOVED
        else:
            graph.classification = UNCONFIRMED
        graph.confirmed_types = confirmed_types
        return graph

    @staticmethod
    def _path_evidence(registry: GraphRegistry, edge_ids: list[str]) -> dict[str, Any]:
        direct = sum(bool(registry._edge_direct.get(edge_id)) for edge_id in edge_ids)
        approximate = len(edge_ids) - direct
        mode = "direct" if approximate == 0 else "approximate" if direct == 0 else "mixed"
        return {
            "evidence_mode": mode,
            "direct_edge_count": direct,
            "approximate_edge_count": approximate,
        }

    @staticmethod
    def _guard_nodes(
        registry: GraphRegistry, flow: FlowEvidence, sink_id: str
    ) -> tuple[list[str], list[str]]:
        node_ids: list[str] = []
        edge_ids: list[str] = []
        for raw in flow.guards:
            assessments = [item for item in flow.guard_assessments if item.get("guard") == raw]
            effectiveness = (
                "result_discarded" if assessments and all(
                    item.get("effectiveness") == "result_discarded" for item in assessments
                ) else "not_evaluated"
            )
            description, separator, location = raw.partition(": ")
            reference, marker, raw_offset = location.rpartition("@0x")
            if not separator:
                description, reference = "caller validation candidate", raw
            offset = None
            if marker:
                try:
                    offset = int(raw_offset, 16)
                except ValueError:
                    offset = None
            api = reference or location or raw
            node_id = registry.node(
                ("guard", flow.sink.method.display(), offset, api, description, effectiveness),
                type="guard",
                label=short_api(api),
                component=flow.sink_component,
                method=flow.sink.method.display(),
                offset=offset,
                instruction=api,
                api=api,
                metadata={
                    "description": description,
                    "effectiveness": effectiveness,
                },
            )
            edge_id = registry.edge(
                node_id,
                sink_id,
                "GUARD",
                False,
                "guard observation; no effective authorization proof",
                {"description": description, "guard": raw, "effectiveness": effectiveness},
            )
            if node_id not in node_ids:
                node_ids.append(node_id)
            if edge_id is not None and edge_id not in edge_ids:
                edge_ids.append(edge_id)
        return node_ids, edge_ids

    def _component_nodes(self, registry: GraphRegistry, flow: FlowEvidence) -> list[str]:
        result: list[str] = []
        for item in flow.nodes:
            component = self.components.get(item.component)
            node_type = (
                "entry_point" if component is not None and component.is_entry_point else "component"
            )
            node_id = registry.node(
                ("component", item.component),
                type=node_type,
                label=item.component,
                component=item.component,
                metadata={
                    "component_type": component.component_type if component else None,
                    "exported": component.is_entry_point if component else None,
                    "manifest_exported": component.exported if component else None,
                    "enabled": component.enabled if component else None,
                    "permission": component.permission if component else None,
                    "entry_provenance": (
                        item.provenance
                        or (component.entry_provenance if component else None)
                    ),
                    "runtime_activation_evidence": (
                        [serializable(evidence) for evidence in component.runtime_activation_evidence]
                        if component
                        else []
                    ),
                    "runtime_receiver_evidence": (
                        [serializable(evidence) for evidence in component.runtime_receiver_evidence]
                        if component
                        else []
                    ),
                },
            )
            if component is not None:
                self._runtime_activation_nodes(registry, component, node_id)
            result.append(node_id)
        return result

    @staticmethod
    def _runtime_activation_nodes(
        registry: GraphRegistry,
        component: Component,
        entry_node_id: str,
    ) -> None:
        """Keep runtime registration/activation as explicit graph evidence."""

        for evidence in component.runtime_receiver_evidence:
            method, offset = FlowGraphAssembler._callsite(evidence.callsite)
            registration_id = registry.node(
                ("runtime_receiver_registration", evidence.registration_id),
                type="runtime_registration",
                label="registerReceiver",
                component=component.name,
                method=method,
                offset=offset,
                api=evidence.api,
                metadata={
                    "registration_id": evidence.registration_id,
                    "entry_provenance": "dynamic_receiver_registration",
                    "exposure": evidence.exposure,
                    "permission": evidence.permission,
                    "filters": [serializable(item) for item in evidence.filters],
                    "reachable_from": list(evidence.reachable_from),
                    "unresolved_dependencies": list(
                        evidence.unresolved_dependencies
                    ),
                },
            )
            registry.edge(
                registration_id,
                entry_node_id,
                "RUNTIME_REGISTERS",
                True,
                "registerReceiver installs the BroadcastReceiver entry",
                {"registration_id": evidence.registration_id},
            )
        for evidence in component.runtime_activation_evidence:
            method, offset = FlowGraphAssembler._callsite(evidence.callsite)
            activation_id = registry.node(
                ("manifest_runtime_activation", evidence.callsite, component.name),
                type="runtime_activation",
                label="setComponentEnabledSetting",
                component=component.name,
                method=method,
                offset=offset,
                api=evidence.api,
                metadata={
                    "entry_provenance": "manifest_runtime_activation",
                    "requested_states": list(evidence.requested_states),
                    "target_resolution": evidence.target_resolution,
                    "reachable_from": list(evidence.reachable_from),
                    "unresolved_dependencies": list(
                        evidence.unresolved_dependencies
                    ),
                },
            )
            registry.edge(
                activation_id,
                entry_node_id,
                "RUNTIME_ACTIVATES",
                True,
                "setComponentEnabledSetting activates the manifest entry",
                {"target_resolution": evidence.target_resolution},
            )

    @staticmethod
    def _callsite(value: str) -> tuple[str | None, int | None]:
        if "@0x" not in value:
            return value or None, None
        method, raw_offset = value.rsplit("@0x", 1)
        try:
            return method, int(raw_offset, 16)
        except ValueError:
            return method, None

    def _path_prefix(
        self,
        registry: GraphRegistry,
        flow: FlowEvidence,
        component_ids: list[str],
        source: EvidenceSource,
        source_id: str,
    ) -> tuple[list[str], list[str], list[str]]:
        if not component_ids:
            return [source_id], [], []
        # FlowBuilder has already resolved the external provenance by following
        # incoming ICC data.  Keep the Entry and actual Source in the main path;
        # the ICC bridge steps on Origin.path carry every inter-component hop.
        # Intermediate component nodes remain registered for graph inspection,
        # but no reachability-only data edge is synthesized here.
        prefix = [component_ids[0]]
        edge_ids: list[str] = []
        source_to_sink_edge_ids: list[str] = []
        edge_id = registry.edge(
            prefix[-1],
            source_id,
            "SOURCE_PROVENANCE",
            (
                source.origin.external
                and source.origin.component == flow.entry_point.component
            ),
            "external source belongs to the resolved Entry",
            {
                "component": source.origin.component,
                "entry_reachability": self._entry_reachability(flow, source),
            },
        )
        if edge_id is not None:
            edge_ids.append(edge_id)
        prefix.append(source_id)
        return prefix, edge_ids, source_to_sink_edge_ids

    def _entry_reachability(
        self, flow: FlowEvidence, source: EvidenceSource
    ) -> str:
        if source.entry_reachability != ENTRY_REACHABILITY_UNCONFIRMED:
            return source.entry_reachability
        if (
            source.origin.external
            and source.origin.component == flow.entry_point.component
            and flow.sink_component == flow.entry_point.component
        ):
            return {
                "manifest_runtime_activation": ENTRY_REACHABILITY_MANIFEST_RUNTIME,
                "dynamic_receiver_registration": ENTRY_REACHABILITY_DYNAMIC_RECEIVER,
            }.get(
                flow.entry_point.provenance,
                ENTRY_REACHABILITY_DIRECT_MANIFEST,
            )
        return ENTRY_REACHABILITY_UNCONFIRMED

    @staticmethod
    def _source_carried_markers(source: EvidenceSource) -> set[str]:
        origin = source.origin
        # A nested Intent read from an extra requires that extra; the mere
        # presence of an outer Intent says nothing about its nested payload.
        if origin.key is not None:
            return {f"extra:{origin.key}"}
        if source.role.value == "whole_intent":
            return {"whole_intent"}
        if origin.field:
            return {origin.field}
        return set()

    def _component_edge(
        self,
        registry: GraphRegistry,
        flow: FlowEvidence,
        left_id: str,
        right_id: str,
        left_component: str,
        right_component: str,
    ) -> str | None:
        edge = self._icc_edge(flow, left_component, right_component)
        return registry.edge(
            left_id,
            right_id,
            "ICC",
            False,
            edge.reason if edge else "candidate component transition",
            self._icc_evidence(edge),
        )

    @staticmethod
    def _icc_edge(flow: FlowEvidence, source: str, target: str) -> ICCEdge | None:
        return next(
            (
                edge
                for edge in flow.icc_edges
                if edge.source_component == source and edge.target_component == target
            ),
            None,
        )

    @staticmethod
    def _icc_evidence(edge: ICCEdge | None) -> dict[str, Any]:
        if edge is None:
            return {}
        return {
            "source_site": edge.source_site,
            "dispatch_api": edge.dispatch_api,
            "resolution": edge.resolution,
            "carried_fields": list(edge.carried_fields),
            # Full observations live once in the source dispatch graph's pool.
            "value_observation_count": len(edge.value_observations),
            "value_transfer_status": "unproven",
            "target_callbacks": list(edge.target_callback_nodes),
        }

    @staticmethod
    def _origin_node(
        registry: GraphRegistry,
        source: EvidenceSource,
        attacker_controlled: bool,
    ) -> str:
        origin = source.origin
        is_source = origin.kind in SOURCE_KINDS
        if is_source:
            label = short_api(origin.api or origin.kind)
            node_type = "source"
        elif origin.kind == "constant":
            label = f"constant: {origin.value!r}"
            node_type = "value"
        else:
            label = origin.api or origin.field or origin.kind
            node_type = "value"
        return registry.node(
            (
                "origin",
                origin.kind,
                origin.api,
                origin.field,
                origin.key,
                repr(origin.value),
                origin.component,
                origin.method,
                origin.offset,
                attacker_controlled,
            ),
            type=node_type,
            label=label,
            component=origin.component,
            method=origin.method,
            offset=origin.offset,
            api=origin.api,
            field=origin.field,
            key=origin.key,
            external=origin.external,
            metadata={
                "origin_kind": origin.kind,
                "attacker_controlled": attacker_controlled,
                "value": origin.value,
                "via_uri_parse": any(
                    step.evidence.get("intent_uri_factory") for step in origin.path
                ),
                "outer_field": origin.outer_field,
                "outer_key": origin.outer_key,
            },
        )

    @staticmethod
    def _step_node(registry: GraphRegistry, step: TraceStep) -> str:
        relation = step.relation.lower()
        instruction = step.instruction.lower()
        internal_source = step.evidence.get("internal_source_origin")
        if internal_source:
            node_type = "source"
        elif "callback" in relation:
            node_type = "callback"
        elif any(
            marker in relation for marker in ("field", "collection", "constructor", "object state")
        ):
            node_type = "state"
        elif step.edge_type == "DISPATCH" or "invoke-interface" in instruction:
            node_type = "dispatch"
        else:
            node_type = "method"
        identity = (
            (
                "internal_source",
                internal_source.get("kind"),
                internal_source.get("component"),
                internal_source.get("method"),
                internal_source.get("offset"),
                internal_source.get("api"),
                internal_source.get("field"),
                internal_source.get("key"),
            )
            if internal_source
            else (
                "step",
                step.method,
                step.offset,
                step.instruction,
                step.relation,
                step.edge_type,
                step.direct,
            )
        )
        metadata = (
            {
                "relation": step.relation,
                "internal_source": True,
                "origin_kind": internal_source.get("kind"),
                "attacker_controlled": True,
            }
            if internal_source
            else {"relation": step.relation, **step.evidence}
        )
        return registry.node(
            identity,
            type=node_type,
            label=(
                short_api(internal_source.get("api") or internal_source.get("kind"))
                if internal_source
                else short_method(step.method)
            ),
            component=(internal_source.get("component") if internal_source else None),
            method=(internal_source.get("method") if internal_source else step.method),
            offset=(internal_source.get("offset") if internal_source else step.offset),
            instruction=step.instruction,
            api=(internal_source.get("api") if internal_source else None),
            field=(internal_source.get("field") if internal_source else None),
            key=(internal_source.get("key") if internal_source else None),
            external=False if internal_source else None,
            metadata=metadata,
        )

    @staticmethod
    def _sink_node(registry: GraphRegistry, flow: FlowEvidence) -> str:
        sink = flow.sink
        return registry.node(
            ("sink", sink.site_id),
            type="sink",
            label=sink.api_name,
            component=flow.sink_component,
            method=sink.method.display(),
            offset=sink.offset,
            instruction=sink.api,
            api=sink.api,
            metadata={
                "site_id": sink.site_id,
                "rule": sink.rule_id,
                "category": sink.category,
                "argument_registers": list(sink.argument_registers),
            },
        )

    @staticmethod
    def _relation(step: TraceStep) -> tuple[str, bool]:
        if step.edge_type is not None and step.direct is not None:
            return step.edge_type, step.direct
        relation = step.relation.lower()
        instruction = step.instruction.lower()
        if "callback" in relation:
            return "CALLBACK", False
        if "collection" in relation:
            return "COLLECTION_STATE", False
        if "field" in relation:
            return "FIELD_STATE", False
        if "constructor" in relation or "object state" in relation:
            return "OBJECT_STATE", False
        if step.edge_type == "DISPATCH" or "invoke-interface" in instruction:
            return "DISPATCH", False
        if "actual argument" in relation:
            return "ARGUMENT", True
        if "return" in relation:
            return "RETURN", True
        if "control" in relation:
            return "CONTROL", True
        return "DATA_FLOW", True

    def _candidate_types_for_source(
        self,
        flow: FlowEvidence,
        source: EvidenceSource,
        attacker_controlled: bool,
        spoofing_detected: bool,
    ) -> list[str]:
        if source.origin.kind not in SOURCE_KINDS or not attacker_controlled:
            return []
        role = source.role.value
        if source.origin.kind == "external_invocation":
            return (
                ["Intent Spoofing"]
                if role == "invocation" and spoofing_detected
                else []
            )
        result: list[str] = []
        if self._controls_icc_destination(flow, source):
            result.append("Intent Redirection")
        if role in {"control", "payload", "sensitive_argument"}:
            result.append("Intent Injection")
        if spoofing_detected:
            result.append("Intent Spoofing")
        return result

    @staticmethod
    def _controls_icc_destination(
        flow: FlowEvidence,
        source: EvidenceSource,
    ) -> bool:
        """Return whether this source participates in ICC target selection."""
        if flow.sink.category != "icc":
            return False
        if source.role.value in {"destination", "whole_intent"}:
            return True
        return (
            source.role.value == "payload"
            and source.origin.field in {"action", "data", "type", "category"}
            and any(
                edge.source_site == flow.sink.site_id
                and edge.resolution
                in {"dynamic_implicit_candidate", "dynamic_implicit_external_target"}
                for edge in getattr(flow, "icc_edges", ())
            )
        )

    @staticmethod
    def _path_class(modeled_source: bool, attacker_controlled: bool) -> str:
        if not modeled_source:
            return "diagnostic_origin"
        if attacker_controlled:
            return "attacker_source"
        return "modeled_source"

    def _outgoing_targets(
        self,
        flow: FlowEvidence,
    ) -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = []
        targets: dict[tuple[Any, ...], dict[str, Any]] = {}
        for edge in flow.icc_edges:
            if edge.source_site != flow.sink.site_id:
                continue
            observation_id = self._observation_id(edge.value_observations)
            key = (
                edge.target_component,
                edge.resolution,
                edge.carried_fields,
                edge.target_callback_nodes,
            )
            target = targets.get(key)
            if target is None:
                target = {
                    "target_component": edge.target_component,
                    "resolution": edge.resolution,
                    "target_tier": FlowGraphAssembler._target_tier(edge.resolution),
                    "reason": edge.reason,
                    "carried_fields": list(edge.carried_fields),
                    "value_observation_ids": [],
                    "value_transfer_status": "unproven",
                    "target_callbacks": list(edge.target_callback_nodes),
                }
                targets[key] = target
                result.append(target)
            if (
                observation_id is not None
                and observation_id not in target["value_observation_ids"]
            ):
                target["value_observation_ids"].append(observation_id)
        return result

    def _observation_id(
        self, observations: tuple[ICCValueObservation, ...]
    ) -> str | None:
        if not observations:
            return None
        identity = id(observations)
        existing = self._value_observation_ids.get(identity)
        if existing is not None:
            return existing
        existing = next(
            (
                identifier
                for identifier, pooled in self.value_observation_pool.items()
                if pooled == observations
            ),
            None,
        )
        if existing is not None:
            self._value_observation_ids[identity] = existing
            return existing
        identifier = f"vo{self._next_value_observation_id:06d}"
        self._next_value_observation_id += 1
        self._value_observation_ids[identity] = identifier
        self.value_observation_pool[identifier] = observations
        return identifier

    @staticmethod
    def _target_tier(resolution: str) -> str:
        if resolution in {"explicit_component", "route_registry"}:
            return "exact"
        if resolution == "implicit_filter":
            return "manifest_match"
        if resolution in {
            "attacker_controlled_candidate",
            "dynamic_implicit_candidate",
            "type_candidate",
        }:
            return "compatible_candidate"
        return "unresolved"

    @staticmethod
    def _deduplicate_adjacent(items: list[str]) -> list[str]:
        result: list[str] = []
        for item in items:
            if not result or result[-1] != item:
                result.append(item)
        return result
