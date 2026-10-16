"""Flow-graph normalization and result aggregation."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

import psutil

from src.static.model.constants import (
    CONFIRMED,
    NON_PROOVED,
    PATH_CLASS_ATTACKER_SOURCE,
    PATH_CLASS_DIAGNOSTIC_SOURCE,
    PATH_CLASS_MODELED_SOURCE,
    PATH_CLASS_UNRESOLVED_DIAGNOSTIC,
    UNCONFIRMED,
)
from src.static.model.evidence import FlowGraph
from src.static.classification.grouping import FindingGrouper
from src.static.model.values import (
    ICCEdge,
    IntentFact,
    IntentState,
    Origin,
    SinkSite,
    serializable,
)



def compact_intent_state(state: IntentState) -> None:
    """Collapse equivalent observations while retaining the best trace."""

    origin_cache: dict[int, tuple[Origin, tuple[Any, ...]]] = {}

    def score(origin: Origin) -> tuple[int, int]:
        return (sum(step.direct is False for step in origin.path), len(origin.path))

    def select(origins: list[Origin]) -> list[Origin]:
        """Keep the best-scored trace for each equivalent origin."""
        selected: dict[tuple[Any, ...], Origin] = {}
        for origin in origins:
            key = _origin_key(origin, origin_cache)
            current = selected.get(key)
            if current is None or score(origin) < score(current):
                selected[key] = origin
        return list(selected.values())

    state.object_origins = select(state.object_origins)
    state.pinned_object_origins = select(state.pinned_object_origins)

    selected_facts: dict[tuple[Any, ...], IntentFact] = {}
    for fact in state.facts:
        key = (
            fact.field,
            fact.key,
            fact.setter,
            fact.method,
            fact.offset,
            _origin_key(fact.origin, origin_cache),
        )
        current = selected_facts.get(key)
        if current is None or score(fact.origin) < score(current.origin):
            selected_facts[key] = fact
    state.facts = list(selected_facts.values())

def peak_rss_mb() -> float:
    """Return peak RSS where available, otherwise current RSS, in MiB.

    Keep the legacy metric name for report compatibility. psutil does not
    expose a peak in memory_info() on every supported platform/version.
    """
    memory = psutil.Process().memory_info()
    value = getattr(memory, "peak_rss", getattr(memory, "peak_wset", memory.rss))
    return float(value) / (1024 * 1024)

def summarize_flow_graphs(
    graphs: Iterable[FlowGraph],
    nodes: list[Any],
) -> tuple[dict[str, list[str]], list[Any], dict[str, int]]:
    """Aggregate report indexes and counters in one sequential pass."""

    sections: dict[str, list[str]] = {
        "confirmed": [],
        "non_prooved": [],
        "unconfirmed": [],
    }
    metrics = {
        "raw_flow_graphs": 0,
        "graphs_with_modeled_sources": 0,
        "graph_paths": 0,
        "attacker_source_paths": 0,
        "modeled_source_paths": 0,
        "diagnostic_origin_paths": 0,
        "confirmed_paths": 0,
        "non_prooved_paths": 0,
        "unconfirmed_paths": 0,
        "graph_node_references": 0,
        "graph_edge_references": 0,
        "guard_nodes": 0,
    }
    grouper = FindingGrouper(nodes)
    for graph in graphs:
        classification = (
            graph.classification
            if graph.classification in sections
            else "unconfirmed"
        )
        sections[classification].append(graph.graph_id)
        grouper.consume(graph)
        metrics["raw_flow_graphs"] += 1
        metrics["graphs_with_modeled_sources"] += int(bool(graph.sources))
        metrics["graph_paths"] += len(graph.paths)
        metrics["guard_nodes"] += len(graph.guard_nodes)
        for path in graph.paths:
            metrics["graph_node_references"] += len(path.node_ids)
            metrics["graph_edge_references"] += len(path.edge_ids)
            if path.path_class == PATH_CLASS_ATTACKER_SOURCE:
                metrics["attacker_source_paths"] += 1
            elif path.path_class == PATH_CLASS_MODELED_SOURCE:
                metrics["modeled_source_paths"] += 1
            elif path.path_class in {
                PATH_CLASS_DIAGNOSTIC_SOURCE,
                PATH_CLASS_UNRESOLVED_DIAGNOSTIC,
            }:
                metrics["diagnostic_origin_paths"] += 1
            if path.confirmation_status == CONFIRMED:
                metrics["confirmed_paths"] += 1
            elif path.confirmation_status == NON_PROOVED:
                metrics["non_prooved_paths"] += 1
            elif path.confirmation_status == UNCONFIRMED:
                metrics["unconfirmed_paths"] += 1
    return sections, grouper.finish(), metrics

def sink_record(sink: SinkSite) -> dict[str, Any]:
    return {"site_id": sink.site_id, **serializable(sink)}

def deduplicate_icc_edges(
    edges: list[ICCEdge],
) -> list[ICCEdge]:
    """Bucket on small fields and compare full evidence only within a bucket."""

    result: list[ICCEdge] = []
    buckets: dict[tuple[Any, ...], list[ICCEdge]] = {}
    for edge in edges:
        bucket = buckets.setdefault(
            (
                edge.source_site,
                edge.source_component,
                edge.dispatch_api,
                edge.target_component,
                edge.target_callback_nodes,
                edge.resolution,
                edge.reason,
                edge.carried_fields,
                len(edge.value_observations),
            ),
            [],
        )
        if any(existing == edge for existing in bucket):
            continue
        bucket.append(edge)
        result.append(edge)
    return result

def _origin_key(
    origin: Origin,
    cache: dict[int, tuple[Origin, tuple[Any, ...]]],
) -> tuple[Any, ...]:
    identity = id(origin)
    cached = cache.get(identity)
    if cached is not None and cached[0] is origin:
        return cached[1]
    result = (
        origin.kind,
        origin.api,
        origin.field,
        origin.key,
        _freeze_key_value(origin.value),
        origin.component,
        origin.method,
        origin.offset,
        tuple(
            (
                step.method,
                step.offset,
                step.instruction,
                step.relation,
                step.edge_type,
                step.direct,
                _freeze_key_value(step.evidence),
            )
            for step in origin.path
        ),
    )
    cache[identity] = (origin, result)
    return result

def _freeze_key_value(value: Any) -> Any:
    """Convert small arbitrary evidence values to deterministic hashable data."""

    if isinstance(value, dict):
        return tuple(
            sorted(
                (
                    _freeze_key_value(key),
                    _freeze_key_value(item),
                )
                for key, item in value.items()
            )
        )
    if isinstance(value, (list, tuple)):
        return tuple(_freeze_key_value(item) for item in value)
    if isinstance(value, set):
        return frozenset(_freeze_key_value(item) for item in value)
    try:
        hash(value)
    except TypeError:
        return repr(value)
    return value

def deduplicate_flow_graphs(
    graphs: list[FlowGraph],
) -> tuple[list[FlowGraph], int]:
    """Drop only exact duplicates while preserving every distinct candidate path."""

    result: list[FlowGraph] = []
    seen: dict[int, list[FlowGraph]] = {}
    duplicates = 0
    for graph in graphs:
        signature = _graph_fingerprint(graph)
        bucket = seen.setdefault(signature, [])
        existing = next(
            (
                item
                for item in bucket
                if _same_logical_graph(item, graph)
            ),
            None,
        )
        if existing is None:
            bucket.append(graph)
            result.append(graph)
            continue
        duplicates += 1
        existing.unresolved = list(dict.fromkeys([*existing.unresolved, *graph.unresolved]))
        existing.outgoing_targets = [
            *existing.outgoing_targets,
            *(
                target
                for target in graph.outgoing_targets
                if target not in existing.outgoing_targets
            ),
        ]
    return result, duplicates

def _graph_fingerprint(graph: FlowGraph) -> int:
    """Build a cheap bucket key; exact comparison still decides equality.

    v5 retained a giant tuple containing every path until deduplication
    finished. Hashing every ID separately with SHA-256 avoided that peak
    but was needlessly expensive for large graphs. Tuple hashes run in C,
    and only one path's temporary tuples exist at a time. A hash collision
    cannot drop a route because ``_same_logical_graph`` verifies the full
    structure inside the bucket.
    """

    fingerprint = hash(
        (
            tuple(graph.candidate_types),
            tuple(graph.entry_points),
            tuple(graph.sources),
            tuple(sorted((key, tuple(value)) for key, value in graph.source_roles.items())),
            graph.sink,
            tuple(graph.guards),
            len(graph.paths),
        )
    )
    for path in graph.paths:
        fingerprint = hash(
            (
                fingerprint,
                path.source_id,
                path.entry_point_id,
                path.path_class,
                tuple(path.candidate_types),
                path.source_role,
                path.source_origin_kind,
                path.entry_origin_kind,
                path.attacker_controlled,
                path.supporting,
                path.support_kind,
                tuple(path.supports_path_ids),
                tuple(path.control_dependency_path_ids),
                path.control_dependency_status,
                tuple(
                    repr(sorted(item.items()))
                    for item in path.control_branch_evidence
                ),
                path.branch_candidate,
                path.branch_candidate_status,
                tuple(path.node_ids),
                tuple(path.edge_ids),
            )
        )
    return fingerprint

def _same_logical_graph(left: FlowGraph, right: FlowGraph) -> bool:
    return (
        left.candidate_types == right.candidate_types
        and left.classification == right.classification
        and left.entry_points == right.entry_points
        and left.sources == right.sources
        and left.source_roles == right.source_roles
        and left.sink == right.sink
        and left.guards == right.guards
        and left.guard_assessments == right.guard_assessments
        and len(left.paths) == len(right.paths)
        and all(
            first.source_id == second.source_id
            and first.entry_point_id == second.entry_point_id
            and first.path_class == second.path_class
            and first.candidate_types == second.candidate_types
            and first.source_role == second.source_role
            and first.source_origin_kind == second.source_origin_kind
            and first.entry_origin_kind == second.entry_origin_kind
            and first.attacker_controlled == second.attacker_controlled
            and first.supporting == second.supporting
            and first.support_kind == second.support_kind
            and first.supports_path_ids == second.supports_path_ids
            and first.control_dependency_path_ids
            == second.control_dependency_path_ids
            and first.control_dependency_status
            == second.control_dependency_status
            and first.control_branch_evidence
            == second.control_branch_evidence
            and first.branch_candidate == second.branch_candidate
            and first.branch_candidate_status
            == second.branch_candidate_status
            and first.node_ids == second.node_ids
            and first.edge_ids == second.edge_ids
            and first.entry_transfer_evidence == second.entry_transfer_evidence
            for first, second in zip(left.paths, right.paths, strict=True)
        )
    )
