from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def _reject_legacy_report(document: dict[str, Any]) -> dict[str, Any]:
    """Reject schema 9.6 evidence-pool reports that the current analyzer no longer reads."""
    if document.get("schema_version") == "9.6" or "evidence_pool" in document:
        raise ValueError("Legacy static.json format; re-run the analysis for this package")
    return document

class AnalysisStore:
    def __init__(self, data_file: Path):
        self.data_file = data_file
        with data_file.open("r", encoding="utf-8") as stream:
            self.data: dict[str, Any] = _reject_legacy_report(json.load(stream))
        raw_nodes = self.data.get("nodes", {})
        raw_edges = self.data.get("edges", {})
        self.nodes: dict[str, dict[str, Any]] = (
            {item["id"]: item for item in raw_nodes}
            if isinstance(raw_nodes, list)
            else raw_nodes
        )
        self.edges: dict[str, dict[str, Any]] = (
            {item["id"]: item for item in raw_edges}
            if isinstance(raw_edges, list)
            else raw_edges
        )
        self.graphs: dict[str, dict[str, Any]] = {
            graph["graph_id"]: graph for graph in self.data.get("flow_graphs", [])
        }
        self.findings: dict[str, dict[str, Any]] = {
            finding["finding_id"]: finding
            for finding in self.data.get("finding_groups", [])
        }

    @property
    def package(self) -> str:
        metadata = self.data.get("metadata", {})
        return (
            metadata.get("package")
            or self.data.get("package")
            or self.data.get("apk")
            or self.data_file.parent.name
        )

    @property
    def apk_name(self) -> str:
        raw_apk = str(self.data.get("apk") or "").strip()
        return Path(raw_apk).name if raw_apk else f"{self.data_file.stem}.apk"

    def _label(self, node_id: str | None) -> str | None:
        if not node_id:
            return None
        node = self.nodes.get(node_id, {})
        return node.get("label") or node_id

    def overview(self) -> dict[str, Any]:
        metadata = self.data.get("metadata", {})
        stats = self.data.get("statistics", {})
        indexed_paths = sum(
            len(graph.get("paths", [])) for graph in self.graphs.values()
        )
        indexed_branch_candidates = sum(
            1
            for graph in self.graphs.values()
            for path in graph.get("paths", [])
            if self._is_branch_candidate(path)
        )
        indexed_standalone_branch_candidates = sum(
            1
            for graph in self.graphs.values()
            for path in graph.get("paths", [])
            if self._is_standalone_branch_candidate(path)
        )
        indexed_supporting_controls = sum(
            1
            for graph in self.graphs.values()
            for path in graph.get("paths", [])
            if self._is_supporting_control(path)
        )
        return {
            "package": self.package,
            "workflow": metadata.get("workflow"),
            "schema_version": self.data.get(
                "source_schema_version", self.data.get("schema_version")
            ),
            "pending_intent_excluded": metadata.get("pending_intent_excluded"),
            "statistics": {
                "manifest_entry_points": stats.get("manifest_entry_points", 0),
                "sink_sites": stats.get("sink_sites", 0),
                "candidate_flow_graphs": stats.get("candidate_flow_graphs", 0),
                "raw_flow_graphs": stats.get(
                    "raw_flow_graphs", stats.get("candidate_flow_graphs", 0)
                ),
                "primary_finding_graphs": stats.get(
                    "confirmed_graphs",
                    stats.get("primary_finding_graphs", stats.get("candidate_flow_graphs", 0)),
                ),
                "confirmed_graphs": stats.get(
                    "confirmed_graphs",
                    stats.get("primary_finding_graphs", stats.get("candidate_flow_graphs", 0)),
                ),
                "non_prooved_graphs": stats.get("non_prooved_graphs", 0),
                "unconfirmed_graphs": stats.get("unconfirmed_graphs", 0),
                "semantic_finding_groups": stats.get(
                    "semantic_finding_groups", len(self.findings)
                ),
                "unresolved_diagnostic_graphs": stats.get(
                    "unresolved_diagnostic_graphs", 0
                ),
                "graphs_with_modeled_sources": stats.get(
                    "graphs_with_modeled_sources", 0
                ),
                "graph_paths": stats.get("graph_paths", 0),
                "attacker_source_paths": stats.get("attacker_source_paths", 0),
                "reported_flow_graphs": stats.get(
                    "reported_flow_graphs", len(self.graphs)
                ),
                "reported_paths": stats.get("reported_paths", indexed_paths),
                "reported_confirmed_paths": stats.get(
                    "reported_confirmed_paths", 0
                ),
                "reported_review_paths": stats.get("reported_review_paths", 0),
                "reported_effect_paths": stats.get(
                    "reported_effect_paths",
                    max(
                        0,
                        stats.get("reported_paths", indexed_paths)
                        - stats.get(
                            "reported_supporting_control_paths",
                            indexed_supporting_controls,
                        )
                        - stats.get(
                            "reported_standalone_branch_candidate_paths",
                            indexed_standalone_branch_candidates,
                        ),
                    ),
                ),
                "reported_branch_candidate_paths": stats.get(
                    "reported_branch_candidate_paths", indexed_branch_candidates
                ),
                "reported_standalone_branch_candidate_paths": stats.get(
                    "reported_standalone_branch_candidate_paths",
                    indexed_standalone_branch_candidates,
                ),
                "reported_supporting_control_paths": stats.get(
                    "reported_supporting_control_paths", indexed_supporting_controls
                ),
                "omitted_unactionable_graphs": stats.get(
                    "omitted_unactionable_graphs", 0
                ),
                "omitted_unactionable_paths": stats.get(
                    "omitted_unactionable_paths", 0
                ),
                "reported_resume_roots": stats.get(
                    "reported_resume_roots",
                    len(self.data.get("unresolved_frontiers", [])),
                ),
                "elapsed_seconds": stats.get("elapsed_seconds", 0),
            },
            "indexed_graphs": len(self.graphs),
            "indexed_findings": len(self.findings),
            "source_file": self.data.get("source_file", str(self.data_file)),
        }

    def graph_summaries(self) -> list[dict[str, Any]]:
        summaries: list[dict[str, Any]] = []
        for graph in self.graphs.values():
            entry_ids = graph.get("entry_points", [])
            paths = graph.get("paths", [])
            path_classes: dict[str, int] = {}
            confirmation_counts: dict[str, int] = {}
            supporting_control_count = 0
            branch_candidate_count = 0
            standalone_branch_candidate_count = 0
            source_keys: list[str] = []
            for path in paths:
                path_class = path.get("path_class", "legacy")
                path_classes[path_class] = path_classes.get(path_class, 0) + 1
                is_supporting_control = self._is_supporting_control(path)
                is_branch_candidate = self._is_branch_candidate(path)
                if is_supporting_control:
                    supporting_control_count += 1
                if is_branch_candidate:
                    branch_candidate_count += 1
                    if not is_supporting_control:
                        standalone_branch_candidate_count += 1
                if not is_supporting_control:
                    status = path.get("confirmation_status", "unconfirmed")
                    confirmation_counts[status] = confirmation_counts.get(status, 0) + 1
                source = self.nodes.get(path.get("source_id"))
                source_key = source.get("key") if source else None
                if source_key and source_key not in source_keys:
                    source_keys.append(source_key)
            classification = graph.get("classification") or (
                "primary_finding"
                if graph.get("candidate_types")
                else "unresolved_diagnostic"
            )
            summaries.append(
                {
                    "graph_id": graph["graph_id"],
                    "candidate_types": graph.get("candidate_types", []),
                    "status": graph.get("status", "candidate"),
                    "classification": classification,
                    "entry_points": [self._label(node_id) for node_id in entry_ids],
                    "source_count": len(graph.get("sources", [])),
                    "sink": self._label(graph.get("sink")),
                    "path_count": len(paths),
                    "effect_path_count": (
                        len(paths)
                        - supporting_control_count
                        - standalone_branch_candidate_count
                    ),
                    "branch_candidate_count": branch_candidate_count,
                    "standalone_branch_candidate_count": (
                        standalone_branch_candidate_count
                    ),
                    "supporting_control_count": supporting_control_count,
                    "confirmed_path_count": confirmation_counts.get("confirmed", 0),
                    "review_path_count": confirmation_counts.get("non_prooved", 0),
                    "path_classes": path_classes,
                    "attacker_path_count": path_classes.get("attacker_source", 0),
                    "source_keys": source_keys,
                    "target_components": [
                        target.get("target_component")
                        for target in graph.get("outgoing_targets", [])
                        if target.get("target_component")
                    ],
                    "unresolved": graph.get("unresolved", []),
                }
            )
        priority = {
            "confirmed": 0,
            "primary_finding": 0,
            "non_prooved": 1,
            "supporting_flow": 1,
            "unconfirmed": 2,
            "unresolved_diagnostic": 2,
        }
        return sorted(
            summaries,
            key=lambda item: (
                priority.get(item["classification"], 3),
                -item["attacker_path_count"],
                item["graph_id"],
            ),
        )

    @staticmethod
    def _is_supporting_control(path: dict[str, Any]) -> bool:
        """Separate v9.3 branch effects from controls that only support an effect.

        The explicit boolean wins for new reports. The fallbacks keep v9.2 and
        older dashboard fixtures readable without treating a standalone
        branch-controlled sink as supporting evidence.
        """

        if "supporting" in path:
            return path.get("supporting") is True
        if path.get("reporting_role") is not None:
            return path.get("reporting_role") == "supporting_control"
        return (
            path.get("source_role") == "control"
            and path.get("branch_candidate") is not True
        )

    @classmethod
    def _is_standalone_branch_candidate(cls, path: dict[str, Any]) -> bool:
        return cls._is_branch_candidate(path) and not cls._is_supporting_control(path)

    @staticmethod
    def _is_branch_candidate(path: dict[str, Any]) -> bool:
        return path.get("branch_candidate") is True

    def graph_detail(self, graph_id: str) -> dict[str, Any] | None:
        graph = self.graphs.get(graph_id)
        if graph is None:
            return None

        node_ids: set[str] = set(graph.get("entry_points", []))
        node_ids.update(graph.get("sources", []))
        if graph.get("sink"):
            node_ids.add(graph["sink"])
        edge_ids: set[str] = set()
        for path in graph.get("paths", []):
            node_ids.update(path.get("node_ids", []))
            edge_ids.update(path.get("edge_ids", []))

        return {
            **graph,
            "resolved_nodes": [self.nodes[node_id] for node_id in node_ids],
            "resolved_edges": [self.edges[edge_id] for edge_id in edge_ids],
        }
