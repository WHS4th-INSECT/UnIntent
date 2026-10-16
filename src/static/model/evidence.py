from __future__ import annotations

import hashlib
from collections.abc import Iterable
from dataclasses import dataclass
from dataclasses import field as dc_field
from typing import Any

from src.static.model.values import ICCValueObservation, serializable


def report_reference(value: str) -> str:
    """Hide descriptor-based reference keys without losing their identity."""
    if "->" not in value:
        return value
    return "ref_" + hashlib.sha256(value.encode("utf-8")).hexdigest()[:24]


@dataclass
class GraphNode:
    id: str
    type: str
    label: str
    component: str | None = None
    method: str | None = None
    offset: int | None = None
    instruction: str | None = None
    api: str | None = None
    field: str | None = None
    key: str | None = None
    external: bool | None = None
    metadata: dict[str, Any] = dc_field(default_factory=dict)


@dataclass
class GraphEdge:
    id: str
    source: str
    target: str
    type: str
    direct: bool
    relation: str
    evidence: dict[str, Any] = dc_field(default_factory=dict)


@dataclass
class GraphPath:
    id: str
    node_ids: list[str]
    edge_ids: list[str]
    source_id: str | None
    entry_point_id: str | None
    evidence_mode: str = "direct"
    direct_edge_count: int = 0
    approximate_edge_count: int = 0
    path_class: str = "diagnostic_origin"
    candidate_types: list[str] = dc_field(default_factory=list)
    confirmed_types: list[str] = dc_field(default_factory=list)
    source_role: str | None = None
    # source_origin_kind describes the sink-side Source node.  For an ICC
    # bridge, entry_origin_kind retains the exported Entry's attacker origin.
    source_origin_kind: str | None = None
    entry_origin_kind: str | None = None
    attacker_controlled: bool = False
    source_to_sink_evidence_mode: str = "unconfirmed"
    source_to_sink_direct_edge_count: int = 0
    source_to_sink_approximate_edge_count: int = 0
    entry_reachability: str = "unconfirmed"
    confirmation_status: str = "unconfirmed"
    static_status: str = "candidate"
    confirmation_reasons: list[str] = dc_field(default_factory=list)
    rejection_reasons: list[str] = dc_field(default_factory=list)
    confirmation_warnings: list[str] = dc_field(default_factory=list)
    entry_transfer_evidence: list[dict[str, Any]] = dc_field(default_factory=list)
    # Control inputs do not flow into a sink argument. They may support an
    # effect path by influencing whether execution can reach the sink. Keep
    # that conservative relationship explicit so reports can retain relevant
    # conditions without promoting arbitrary control-only paths to findings.
    supporting: bool = False
    support_kind: str | None = None
    supports_path_ids: list[str] = dc_field(default_factory=list)
    control_dependency_path_ids: list[str] = dc_field(default_factory=list)
    control_dependency_status: str = "none"
    # Branch candidates are independently reportable when CFG evidence shows
    # that some branch outcomes can reach the sink while others bypass it and
    # the predicate comes from an attacker-controlled, weakly protected Entry.
    # They remain unresolved until logical grouping and satisfiability exist.
    control_branch_evidence: list[dict[str, Any]] = dc_field(default_factory=list)
    branch_candidate: bool = False
    branch_candidate_status: str = "none"
    # Guard evidence used for this path's final decision.
    guards: list[str] = dc_field(default_factory=list)
    guard_assessments: list[dict[str, Any]] = dc_field(default_factory=list)
    guard_coverage: list[dict[str, Any]] = dc_field(default_factory=list)
    # Effect-family matches are candidate evidence, separate from caller authorization.
    spoofing_evidence: list[dict[str, Any]] = dc_field(default_factory=list)
    spoofing_conditions: dict[str, Any] | None = None


@dataclass
class FlowGraph:
    graph_id: str
    candidate_types: list[str]
    entry_points: list[str]
    sources: list[str]
    source_roles: dict[str, list[str]]
    sink: str
    paths: list[GraphPath]
    guards: list[str] = dc_field(default_factory=list)
    guard_nodes: list[str] = dc_field(default_factory=list)
    guard_edges: list[str] = dc_field(default_factory=list)
    outgoing_targets: list[dict[str, Any]] = dc_field(default_factory=list)
    unresolved: list[str] = dc_field(default_factory=list)
    classification: str = "unconfirmed"
    confirmed_types: list[str] = dc_field(default_factory=list)
    guard_assessments: list[dict[str, Any]] = dc_field(default_factory=list)


@dataclass
class FindingGroup:
    """Human-scale summary over raw graphs without deleting their evidence."""

    finding_id: str
    classification: str
    entry_point: dict[str, Any]
    source: dict[str, Any]
    sink: dict[str, Any]
    roles: list[str]
    candidate_types: list[str]
    candidate_type_support: dict[str, list[str]]
    chain_status: str
    graph_ids: list[str]
    path_ids: list[str]
    representative_paths: dict[str, dict[str, Any]]
    candidate_type_representatives: dict[str, dict[str, Any]]
    alternate_path_count: int
    target_tiers: dict[str, list[dict[str, Any]]] = dc_field(default_factory=dict)
    guards: list[str] = dc_field(default_factory=list)


@dataclass
class AnalysisResult:
    analyzer: str
    apk: str
    metadata: dict[str, Any]
    limits: dict[str, int]
    statistics: dict[str, Any]
    entry_points: list[dict[str, Any]]
    sinks: list[dict[str, Any]]
    nodes: list[GraphNode]
    edges: list[GraphEdge]
    unresolved_frontiers: list[dict[str, Any]]
    graph_sections: dict[str, list[str]]
    finding_groups: list[FindingGroup]
    flow_graphs: Iterable[FlowGraph]
    unresolved_data_origins: list[dict[str, Any]] = dc_field(default_factory=list)
    value_observation_pool: dict[str, tuple[ICCValueObservation, ...]] = dc_field(
        default_factory=dict
    )
