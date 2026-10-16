from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from collections.abc import Iterable
from typing import Any

from src.static.model.evidence import FindingGroup, FlowGraph, GraphNode, GraphPath
from src.static.model.constants import CONFIRMED

TYPE_ORDER = (
    "Intent Redirection",
    "Intent Injection",
    "Intent Spoofing",
)
MODE_ORDER = ("direct", "mixed", "approximate")
TARGET_TIER_ORDER = (
    "exact",
    "manifest_match",
    "compatible_candidate",
    "unresolved",
)


class FindingGrouper:
    """Collapse semantically equivalent candidate paths into review findings.

    The raw ``flow_graphs`` remain untouched.  Groups only add a compact review
    index with representatives per evidence mode and vulnerability type.
    """

    def __init__(self, nodes: list[GraphNode]) -> None:
        self.nodes = {node.id: node for node in nodes}
        self._buckets: dict[tuple[Any, ...], dict[str, Any]] = {}

    def build(self, graphs: Iterable[FlowGraph]) -> list[FindingGroup]:
        self._buckets = {}
        for graph in graphs:
            self.consume(graph)
        return self.finish()

    def consume(self, graph: FlowGraph) -> None:
        """Update compact finding buckets from one graph."""

        if graph.classification != CONFIRMED:
            return
        entry = self._node(graph.entry_points[0] if graph.entry_points else None)
        sink = self._node(graph.sink)
        if entry is None or sink is None:
            return
        for path in graph.paths:
            if (
                path.confirmation_status != CONFIRMED
                or not path.confirmed_types
                or path.source_id is None
            ):
                continue
            source = self._node(path.source_id)
            if source is None:
                continue
            key = self._group_key(entry, source, sink)
            bucket = self._buckets.setdefault(
                key,
                {
                    "entry": entry,
                    "source": source,
                    "sink": sink,
                    "targets": [],
                    "target_keys": set(),
                    "roles": [],
                    "types": [],
                    "type_support": defaultdict(list),
                    "graph_ids": [],
                    "path_ids": [],
                    "path_type_sets": set(),
                    "representatives": {},
                    "type_representatives": {},
                    "guards": [],
                },
            )
            self._append_unique(bucket["graph_ids"], graph.graph_id)
            bucket["path_ids"].append(path.id)
            self._append_unique(bucket["roles"], path.source_role)
            for candidate_type in path.confirmed_types:
                self._append_unique(bucket["types"], candidate_type)
                self._append_unique(bucket["type_support"][candidate_type], path.id)
            for guard in graph.guards:
                self._append_unique(bucket["guards"], guard)
            for target in graph.outgoing_targets:
                summary = {
                    key: value
                    for key, value in target.items()
                    if key not in {"value_observation_id", "value_observation_ids"}
                }
                marker = json.dumps(summary, ensure_ascii=False, sort_keys=True)
                if marker not in bucket["target_keys"]:
                    bucket["target_keys"].add(marker)
                    bucket["targets"].append(summary)

            record = self._path_record(graph, path)
            bucket["path_type_sets"].add(frozenset(path.confirmed_types))
            self._keep_best_mode_representative(bucket["representatives"], record)
            self._keep_best_type_representatives(bucket["type_representatives"], record)

    def finish(self) -> list[FindingGroup]:
        groups = [self._finish(key, bucket) for key, bucket in self._buckets.items()]
        return sorted(
            groups,
            key=lambda item: (
                TYPE_ORDER.index(item.candidate_types[0])
                if item.candidate_types and item.candidate_types[0] in TYPE_ORDER
                else len(TYPE_ORDER),
                item.entry_point.get("component") or "",
                item.sink.get("method") or "",
                item.source.get("offset") or -1,
            ),
        )

    def _finish(self, key: tuple[Any, ...], bucket: dict[str, Any]) -> FindingGroup:
        candidate_types = self._ordered(bucket["types"], TYPE_ORDER)
        roles = sorted(role for role in bucket["roles"] if role)
        representatives = bucket["representatives"]
        type_representatives = {
            candidate_type: bucket["type_representatives"][candidate_type]
            for candidate_type in candidate_types
        }
        represented = {
            item["path_id"] for item in (*representatives.values(), *type_representatives.values())
        }
        all_types = set(candidate_types)
        if len(all_types) <= 1:
            chain_status = "single_type"
        elif frozenset(all_types) in bucket["path_type_sets"]:
            chain_status = "single_path"
        else:
            chain_status = "correlated_same_source_sink"

        entry: GraphNode = bucket["entry"]
        source: GraphNode = bucket["source"]
        sink: GraphNode = bucket["sink"]
        payload = json.dumps(key, ensure_ascii=False, sort_keys=True, default=repr)
        finding_id = "finding-" + hashlib.sha1(payload.encode("utf-8")).hexdigest()[:12]
        return FindingGroup(
            finding_id=finding_id,
            classification=CONFIRMED,
            entry_point=self._entry_record(entry),
            source=self._source_record(source),
            sink=self._sink_record(sink),
            roles=roles,
            candidate_types=candidate_types,
            candidate_type_support={
                candidate_type: list(bucket["type_support"].get(candidate_type, []))
                for candidate_type in candidate_types
            },
            chain_status=chain_status,
            graph_ids=list(bucket["graph_ids"]),
            path_ids=list(bucket["path_ids"]),
            representative_paths=representatives,
            candidate_type_representatives=type_representatives,
            alternate_path_count=max(0, len(bucket["path_ids"]) - len(represented)),
            target_tiers=self._targets_by_tier(bucket["targets"]),
            guards=list(bucket["guards"]),
        )

    @staticmethod
    def _keep_best_mode_representative(
        representatives: dict[str, dict[str, Any]],
        candidate: dict[str, Any],
    ) -> None:
        mode = candidate["evidence_mode"]
        current = representatives.get(mode)
        candidate_rank = FindingGrouper._mode_rank(candidate)
        if current is None or candidate_rank < FindingGrouper._mode_rank(current):
            representatives[mode] = candidate

    @staticmethod
    def _keep_best_type_representatives(
        representatives: dict[str, dict[str, Any]],
        candidate: dict[str, Any],
    ) -> None:
        for candidate_type in candidate["confirmed_types"]:
            current = representatives.get(candidate_type)
            candidate_rank = FindingGrouper._type_rank(candidate)
            if current is None or candidate_rank < FindingGrouper._type_rank(current):
                representatives[candidate_type] = candidate

    @staticmethod
    def _mode_rank(item: dict[str, Any]) -> tuple[Any, ...]:
        return (
            item["approximate_edge_count"],
            len(item["edge_ids"]),
            item["path_id"],
        )

    @staticmethod
    def _type_rank(item: dict[str, Any]) -> tuple[Any, ...]:
        return (
            MODE_ORDER.index(item["evidence_mode"]),
            item["approximate_edge_count"],
            len(item["edge_ids"]),
            item["path_id"],
        )

    @staticmethod
    def _group_key(
        entry: GraphNode,
        source: GraphNode,
        sink: GraphNode,
    ) -> tuple[Any, ...]:
        # Deliberately exclude origin_kind and role.  The same bytecode source
        # may be traced once as an Intent object and again as a controlling
        # value; v9 correlates those roles only when location and sink match.
        return (
            entry.component or entry.label,
            source.component,
            source.method,
            source.offset,
            source.api,
            source.field,
            source.key,
            sink.component,
            sink.method,
            sink.offset,
            sink.api,
        )

    @staticmethod
    def _target_signature(
        targets: list[dict[str, Any]],
    ) -> tuple[tuple[str, str, str], ...]:
        return tuple(
            sorted(
                (
                    str(target.get("target_tier") or "unresolved"),
                    str(target.get("target_component") or ""),
                    str(target.get("resolution") or ""),
                )
                for target in targets
            )
        )

    @staticmethod
    def _path_record(graph: FlowGraph, path: GraphPath) -> dict[str, Any]:
        return {
            "graph_id": graph.graph_id,
            "path_id": path.id,
            "candidate_types": list(path.candidate_types),
            "confirmed_types": list(path.confirmed_types),
            "source_role": path.source_role,
            "source_origin_kind": path.source_origin_kind,
            "entry_origin_kind": path.entry_origin_kind,
            "evidence_mode": path.evidence_mode,
            "source_to_sink_evidence_mode": path.source_to_sink_evidence_mode,
            "direct_edge_count": path.direct_edge_count,
            "approximate_edge_count": path.approximate_edge_count,
            "source_to_sink_direct_edge_count": path.source_to_sink_direct_edge_count,
            "source_to_sink_approximate_edge_count": (
                path.source_to_sink_approximate_edge_count
            ),
            "entry_reachability": path.entry_reachability,
            "confirmation_status": path.confirmation_status,
            "confirmation_reasons": list(path.confirmation_reasons),
            "confirmation_warnings": list(path.confirmation_warnings),
            "node_ids": list(path.node_ids),
            "edge_ids": list(path.edge_ids),
        }

    @staticmethod
    def _entry_record(node: GraphNode) -> dict[str, Any]:
        return {
            "node_id": node.id,
            "component": node.component or node.label,
            "component_type": node.metadata.get("component_type"),
            "exported": node.metadata.get("exported"),
            "permission": node.metadata.get("permission"),
        }

    @staticmethod
    def _source_record(node: GraphNode) -> dict[str, Any]:
        return {
            "node_id": node.id,
            "label": node.label,
            "component": node.component,
            "method": node.method,
            "offset": node.offset,
            "api": node.api,
            "field": node.field,
            "key": node.key,
            "origin_kind": node.metadata.get("origin_kind"),
            "via_uri_parse": node.metadata.get("via_uri_parse"),
            "outer_field": node.metadata.get("outer_field"),
            "outer_key": node.metadata.get("outer_key"),
            "attacker_controlled": node.metadata.get("attacker_controlled"),
        }

    @staticmethod
    def _sink_record(node: GraphNode) -> dict[str, Any]:
        return {
            "node_id": node.id,
            "label": node.label,
            "component": node.component,
            "method": node.method,
            "offset": node.offset,
            "api": node.api,
            "rule": node.metadata.get("rule"),
            "category": node.metadata.get("category"),
        }

    @staticmethod
    def _targets_by_tier(
        targets: list[dict[str, Any]],
    ) -> dict[str, list[dict[str, Any]]]:
        grouped: dict[str, list[dict[str, Any]]] = {tier: [] for tier in TARGET_TIER_ORDER}
        for target in targets:
            tier = str(target.get("target_tier") or "unresolved")
            grouped.setdefault(tier, []).append(target)
        return {tier: grouped[tier] for tier in TARGET_TIER_ORDER if grouped[tier]}

    def _node(self, identifier: str | None) -> GraphNode | None:
        return self.nodes.get(identifier) if identifier else None

    @staticmethod
    def _append_unique(items: list[Any], value: Any) -> None:
        if value is not None and value not in items:
            items.append(value)

    @staticmethod
    def _ordered(items: list[str], order: tuple[str, ...]) -> list[str]:
        present = set(items)
        return [item for item in order if item in present] + sorted(present.difference(order))
