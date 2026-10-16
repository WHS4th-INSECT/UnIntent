from __future__ import annotations

import json
import os
import re
import tempfile
from collections.abc import Iterable, Iterator
from dataclasses import fields
from pathlib import Path
from typing import Any
from src.static.model.evidence import AnalysisResult, report_reference, serializable
from src.static.model.constants import (
    CONFIRMED,
    NON_PROOVED,
    PATH_CLASS_ATTACKER_SOURCE,
    SOURCE_ROLE_CONTROL,
    ENTRY_REACHABILITY_BACKWARD_ICC_UNPROVEN,
    ENTRY_REACHABILITY_BACKWARD_ICC_EXACT,
    ENTRY_REACHABILITY_BACKWARD_ICC_APPROXIMATE,
    HARD_REJECTION_REASONS,
    REVIEW_SOURCE_ROLES,
    TRUSTED_ENTRY_REACHABILITIES,
)


_OMITTED_REPORT_FIELDS = frozenset({
    "analyzer", "metadata", "limits", "statistics", "unresolved_frontiers",
    "unresolved_data_origins",
})

_OBJECT = r"L[\w/$]+;"
_TYPE = rf"\[*(?:{_OBJECT}|[VZBSCIJFD])"
_PROTOTYPE = re.compile(rf"\(((?:\s*{_TYPE})*\s*)\)({_TYPE})")
_CLASS = re.compile(_OBJECT)
_PRIMITIVES = dict(zip("VZBSCIJFD", (
    "void", "boolean", "byte", "short", "char", "int", "long", "float", "double"
)))
_JSON_ENCODER = json.JSONEncoder(ensure_ascii=True, separators=(",", ":"))


def _graph_payloads(values: Iterable[Any]) -> Iterable[Any]:
    payloads = getattr(values, "iter_payloads", None)
    return payloads() if payloads is not None else values


def _unique(values: Iterable[Any]) -> list[Any]:
    return list(dict.fromkeys(values))


def _type_name(value: str) -> str:
    dimensions = len(value) - len(value.lstrip("["))
    base = value[dimensions:]
    name = base[1:-1].rsplit("/", 1)[-1] if base.startswith("L") else _PRIMITIVES[base]
    return name + "[]" * dimensions


def _readable_text(value: str) -> str:
    def prototype(match: re.Match[str]) -> str:
        return "(" + ", ".join(_type_name(arg) for arg in re.findall(_TYPE, match[1])) + ")"

    if "->" in value or _PROTOTYPE.fullmatch(value):
        value = _PROTOTYPE.sub(prototype, value)
    value = re.sub(
        rf"({_OBJECT})\s*->\s*", lambda match: _type_name(match[1]) + ".", value
    )
    value = _CLASS.sub(lambda match: _type_name(match[0]), value)
    return value.rsplit("/", 1)[-1] if re.fullmatch(r"L[\w$]+(?:/[\w$]+)+", value) else value


def write_json_report(result: AnalysisResult, destination: str | Path) -> dict[str, Any]:
    """Atomically stream only actionable finding and review paths to JSON."""

    path = Path(destination)
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".partial",
        dir=path.parent,
    )
    temporary = Path(temporary_name)
    try:
        projection = _ActionableProjection(result)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write("{\n")
            result_fields = [
                item for item in fields(result) if item.name not in _OMITTED_REPORT_FIELDS
            ]
            for index, item in enumerate(result_fields):
                stream.write(f"  {json.dumps(item.name)}: ")
                value = projection.value(item.name)
                if item.name in {
                    "entry_points",
                    "sinks",
                    "nodes",
                    "edges",
                    "unresolved_frontiers",
                    "finding_groups",
                    "flow_graphs",
                    "unresolved_data_origins",
                    "value_observation_pool",
                }:
                    _write_array(stream, value)
                else:
                    _write_item(stream, value)
                stream.write(",\n" if index + 1 < len(result_fields) else "\n")
            stream.write("}\n")
        os.replace(temporary, path)
        return projection._statistics()
    except BaseException:
        try:
            os.close(descriptor)
        except OSError:
            pass
        temporary.unlink(missing_ok=True)
        raise


class _ActionableProjection:
    """Select connected, attacker-controlled paths after full classification.

    The flow graph spool explicitly provides a replayable payload stream. Other
    Iterable implementations are cached because Python's Iterable/Collection
    contracts do not guarantee that a second traversal yields the same data.
    """

    def __init__(self, result: AnalysisResult) -> None:
        self.result = result
        self._cached_graphs: list[dict[str, Any]] | None = None
        self.raw_graph_count = 0
        self.raw_path_count = 0
        self.graph_ids: set[str] = set()
        self.path_ids: set[str] = set()
        self.node_ids: set[str] = set()
        self.edge_ids: set[str] = set()
        self.entry_node_ids: set[str] = set()
        self.sink_node_ids: set[str] = set()
        self.transfer_sink_site_ids: set[str] = set()
        self.value_observation_ids: set[str] = set()
        self.sections: dict[str, list[str]] = {
            CONFIRMED: [],
            NON_PROOVED: [],
        }
        self.path_counts = {CONFIRMED: 0, NON_PROOVED: 0}
        self.supporting_control_count = 0
        self.branch_candidate_count = 0
        self.standalone_branch_candidate_count = 0

        one_shot = not callable(getattr(result.flow_graphs, "iter_payloads", None))
        if one_shot:
            self._cached_graphs = []
        for raw_graph in _graph_payloads(result.flow_graphs):
            payload = serializable(raw_graph)
            self.raw_graph_count += 1
            self.raw_path_count += len(payload.get("paths", ()))
            graph = _project_graph(payload)
            if graph is None:
                continue
            if self._cached_graphs is not None:
                self._cached_graphs.append(graph)
            self._register_graph(graph)

        self._edge_count = 0
        for edge in self._iter_payloads(result.edges, self.edge_ids):
            self._edge_count += 1
            self.node_ids.add(str(edge["source"]))
            self.node_ids.add(str(edge["target"]))

        # Keep only indexes; materialize at most one node/edge payload at a time.
        self._node_count = 0
        self._entry_components: set[str] = set()
        for node in self._iter_payloads(result.nodes, self.node_ids):
            self._node_count += 1
            if node.get("id") in self.entry_node_ids and node.get("component"):
                self._entry_components.add(str(node["component"]))
        self._sink_site_ids = self._resolve_sink_site_ids()
        self._sink_site_ids.update(self.transfer_sink_site_ids)
        self._resume_roots = self._collect_resume_roots()

    @staticmethod
    def _iter_payloads(values: Iterable[Any], retained_ids: set[str]) -> Iterator[dict[str, Any]]:
        """Serialize selected records individually without retaining a payload list."""
        for value in values:
            identifier = value.get("id") if isinstance(value, dict) else getattr(value, "id", None)
            if identifier in retained_ids:
                yield serializable(value)

    def _register_graph(self, graph: dict[str, Any]) -> None:
        graph_id = str(graph["graph_id"])
        classification = str(graph["classification"])
        self.graph_ids.add(graph_id)
        self.sections[classification].append(graph_id)
        self.entry_node_ids.update(graph.get("entry_points", ()))
        self.sink_node_ids.add(str(graph["sink"]))
        self.node_ids.update(graph.get("entry_points", ()))
        self.node_ids.update(graph.get("sources", ()))
        self.node_ids.add(str(graph["sink"]))
        self.node_ids.update(graph.get("guard_nodes", ()))
        self.edge_ids.update(graph.get("guard_edges", ()))
        for path in graph["paths"]:
            self.path_ids.add(str(path["id"]))
            if path.get("branch_candidate"):
                self.branch_candidate_count += 1
            if path.get("supporting"):
                self.supporting_control_count += 1
            elif path.get("confirmation_status") == CONFIRMED:
                self.path_counts[CONFIRMED] += 1
            elif path.get("branch_candidate"):
                self.standalone_branch_candidate_count += 1
            else:
                self.path_counts[str(path["confirmation_status"])] += 1
            self.node_ids.update(path.get("node_ids", ()))
            self.edge_ids.update(path.get("edge_ids", ()))
            self.transfer_sink_site_ids.update(
                str(evidence["source_site"])
                for evidence in path.get("entry_transfer_evidence", ())
                if evidence.get("source_site")
            )
        self.value_observation_ids.update(
            str(identifier)
            for target in graph.get("outgoing_targets", ())
            for identifier in (
                target.get("value_observation_ids")
                or ([target["value_observation_id"]]
                    if target.get("value_observation_id") else [])
            )
        )

    def value(self, name: str) -> Any:
        if name == "metadata":
            return self.result.metadata
        if name == "statistics":
            return self._statistics()
        if name == "entry_points":
            return (
                entry
                for entry in self.result.entry_points
                if entry.get("component") in self._entry_components
            )
        if name == "sinks":
            return (
                sink
                for sink in self.result.sinks
                if sink.get("site_id") in self._sink_site_ids
            )
        if name == "nodes":
            return self._iter_payloads(self.result.nodes, self.node_ids)
        if name == "edges":
            return self._iter_payloads(self.result.edges, self.edge_ids)
        if name == "unresolved_frontiers":
            return self._resume_roots
        if name == "graph_sections":
            return self.sections
        if name == "finding_groups":
            return (
                group
                for group in self.result.finding_groups
                if any(
                    graph_id in self.graph_ids
                    for graph_id in (
                        group.get("graph_ids", ())
                        if isinstance(group, dict)
                        else group.graph_ids
                    )
                )
            )
        if name == "flow_graphs":
            return self.iter_graphs()
        if name == "value_observation_pool":
            return (
                {"id": identifier, "observations": observations}
                for identifier, observations in self.result.value_observation_pool.items()
                if identifier in self.value_observation_ids
            )
        if name == "unresolved_data_origins":
            return (
                item
                for item in self.result.unresolved_data_origins
                if item.get("sink_site") in self._sink_site_ids
            )
        return getattr(self.result, name)

    def iter_graphs(self) -> Iterator[dict[str, Any]]:
        if self._cached_graphs is not None:
            yield from self._cached_graphs
            return
        yield from self._project_graphs(_graph_payloads(self.result.flow_graphs))

    @staticmethod
    def _project_graphs(values: Iterable[Any]) -> Iterator[dict[str, Any]]:
        for graph in values:
            projected = _project_graph(graph)
            if projected is not None:
                yield projected

    def _statistics(self) -> dict[str, Any]:
        statistics = dict(self.result.statistics)
        # The final report exposes actionable findings only. Keep rejection
        # accounting inside the analyzer instead of leaking rejected result
        # classes into the report schema.
        statistics.pop("unconfirmed_graphs", None)
        statistics.pop("unconfirmed_paths", None)
        statistics.pop("unresolved_diagnostic_graphs", None)
        statistics.setdefault("raw_flow_graphs", self.raw_graph_count)
        statistics.setdefault("graph_paths", self.raw_path_count)
        analyzed_graphs = max(
            self.raw_graph_count, int(statistics.get("raw_flow_graphs", 0))
        )
        analyzed_paths = max(self.raw_path_count, int(statistics.get("graph_paths", 0)))
        reported_graphs = len(self.graph_ids)
        reported_effect_paths = sum(self.path_counts.values())
        reported_paths = (
            reported_effect_paths
            + self.supporting_control_count
            + self.standalone_branch_candidate_count
        )
        statistics.update(
            {
                "reported_flow_graphs": reported_graphs,
                "reported_confirmed_graphs": len(self.sections[CONFIRMED]),
                "reported_review_graphs": len(self.sections[NON_PROOVED]),
                "reported_paths": reported_paths,
                "reported_effect_paths": reported_effect_paths,
                "reported_confirmed_paths": self.path_counts[CONFIRMED],
                "reported_review_paths": self.path_counts[NON_PROOVED],
                "reported_supporting_control_paths": self.supporting_control_count,
                "reported_branch_candidate_paths": self.branch_candidate_count,
                "reported_standalone_branch_candidate_paths": (
                    self.standalone_branch_candidate_count
                ),
                "omitted_unactionable_graphs": max(
                    0, analyzed_graphs - reported_graphs
                ),
                "omitted_unactionable_paths": max(
                    0, analyzed_paths - reported_paths
                ),
                "reported_graph_nodes": self._node_count,
                "reported_graph_edges": self._edge_count,
                "reported_resume_roots": len(self._resume_roots),
            }
        )
        return statistics

    def _resolve_sink_site_ids(self) -> set[str]:
        sink_nodes = {
            str(node["id"]): node
            for node in self._iter_payloads(self.result.nodes, self.sink_node_ids)
            if node.get("id") in self.sink_node_ids
        }
        result: set[str] = set()
        for node in sink_nodes.values():
            site_id = node.get("metadata", {}).get("site_id")
            if site_id:
                result.add(str(site_id))
        for sink in self.result.sinks:
            method = sink.get("method", {})
            display = (
                f"{method.get('class_name', '')}->{method.get('name', '')}"
                f"{method.get('descriptor', '')}"
            )
            for node in sink_nodes.values():
                if (
                    node.get("method") == display
                    and node.get("offset") == sink.get("offset")
                    and node.get("metadata", {}).get("rule") == sink.get("rule_id")
                ):
                    result.add(str(sink["site_id"]))
                    break
        return result

    def _collect_resume_roots(self) -> list[dict[str, str]]:
        result: list[dict[str, str]] = []
        seen: set[str] = set()
        for frontier in self.result.unresolved_frontiers:
            root = str(frontier.get("root_request") or "")
            if root and root not in seen:
                seen.add(root)
                result.append({"root_request": root})
        return result


def _project_graph(value: Any) -> dict[str, Any] | None:
    graph = value if isinstance(value, dict) else serializable(value)
    raw_paths = list(graph.get("paths", ()))
    effect_paths = [
        path
        for path in raw_paths
        if not path.get("supporting")
        and (
            not path.get("branch_candidate")
            or path.get("confirmation_status") == CONFIRMED
        )
        and _is_actionable_path(path)
    ]
    effect_ids = {str(path["id"]) for path in effect_paths}
    supporting_paths = [
        path
        for path in raw_paths
        if _is_supporting_control_path(path, effect_ids)
    ]
    supporting_ids = {str(path["id"]) for path in supporting_paths}
    branch_candidate_paths = [
        path
        for path in raw_paths
        if str(path.get("id")) not in supporting_ids
        and _is_actionable_branch_candidate(path)
    ]
    branch_candidate_ids = {
        str(path["id"]) for path in branch_candidate_paths
    }
    retained_ids = {
        str(path["id"])
        for path in [*effect_paths, *supporting_paths, *branch_candidate_paths]
    }
    paths = [path for path in raw_paths if str(path.get("id")) in retained_ids]
    if not paths:
        return None

    for path in paths:
        path_id = str(path["id"])
        if path_id in supporting_ids:
            path["supports_path_ids"] = [
                identifier
                for identifier in path.get("supports_path_ids", ())
                if str(identifier) in effect_ids
            ]
        elif path_id in branch_candidate_ids:
            # A raw control may have supported an effect that projection
            # rejected. Its independent branch marker still makes it a review
            # candidate, so present it as standalone rather than dangling
            # support.
            path["supporting"] = False
            path["support_kind"] = None
            path["supports_path_ids"] = []
        elif path_id in effect_ids:
            path["control_dependency_path_ids"] = [
                identifier
                for identifier in path.get("control_dependency_path_ids", ())
                if str(identifier) in supporting_ids
            ]

    graph["paths"] = paths
    graph["entry_points"] = _unique(
        path.get("entry_point_id") for path in paths if path.get("entry_point_id")
    )
    graph["sources"] = _unique(
        path.get("source_id") for path in paths if path.get("source_id")
    )
    graph["source_roles"] = {
        source_id: _unique(
            path.get("source_role")
            for path in paths
            if path.get("source_id") == source_id and path.get("source_role")
        )
        for source_id in graph["sources"]
    }
    graph["candidate_types"], graph["candidate_type_support"] = _type_support(
        paths, "candidate_types"
    )
    graph["confirmed_types"], graph["confirmed_type_support"] = _type_support(
        paths, "confirmed_types"
    )
    projected_effect_paths = [
        path for path in paths if str(path["id"]) in effect_ids
    ]
    counts = {
        CONFIRMED: sum(
            path.get("confirmation_status") == CONFIRMED
            for path in projected_effect_paths
        ),
        NON_PROOVED: sum(
            path.get("confirmation_status") == NON_PROOVED
            for path in projected_effect_paths
        ),
    }
    graph["classification"] = CONFIRMED if counts[CONFIRMED] else NON_PROOVED
    static_counts = {
        "static_high_confidence": sum(
            path.get("static_status") == "static_high_confidence"
            for path in projected_effect_paths
        ),
        "static_reachable": sum(
            path.get("static_status") == "static_reachable"
            for path in projected_effect_paths
        ),
        "candidate": sum(
            path.get("static_status") == "candidate"
            for path in projected_effect_paths
        ),
    }
    graph["static_classification"] = (
        "static_high_confidence" if static_counts["static_high_confidence"]
        else "static_reachable" if static_counts["static_reachable"]
        else "candidate"
    )
    graph["status"] = "finding" if counts[CONFIRMED] else "review_candidate"
    graph["confirmation_summary"] = {
        **counts,
        **static_counts,
        "supporting_control_dependencies": len(supporting_paths),
        "branch_candidates": sum(
            path.get("branch_candidate") is True for path in paths
        ),
        "standalone_branch_candidates": len(branch_candidate_paths),
        "coverage_incomplete": bool(graph.get("unresolved")),
    }
    return graph


def _is_actionable_path(path: dict[str, Any]) -> bool:
    status = path.get("confirmation_status")
    if status == CONFIRMED:
        return bool(
            path.get("attacker_controlled")
            and path.get("source_id")
            and path.get("entry_point_id")
            and path.get("confirmed_types")
        )
    if status != NON_PROOVED:
        return False
    if not (
        path.get("path_class") == PATH_CLASS_ATTACKER_SOURCE
        and path.get("attacker_controlled")
        and path.get("source_id")
        and path.get("entry_point_id")
        and path.get("candidate_types")
        and path.get("source_role") in REVIEW_SOURCE_ROLES
    ):
        return False
    rejected = set(path.get("rejection_reasons", ()))
    if rejected.intersection(HARD_REJECTION_REASONS):
        return False
    if path.get("entry_reachability") not in TRUSTED_ENTRY_REACHABILITIES:
        return bool(
            path.get("entry_reachability") in {
                ENTRY_REACHABILITY_BACKWARD_ICC_UNPROVEN,
                ENTRY_REACHABILITY_BACKWARD_ICC_EXACT,
                ENTRY_REACHABILITY_BACKWARD_ICC_APPROXIMATE,
            }
            and path.get("entry_transfer_evidence")
        )
    return True


def _is_supporting_control_path(
    path: dict[str, Any], effect_ids: set[str]
) -> bool:
    """Keep attacker controls only when linked to a retained effect they may influence."""

    if not effect_ids:
        return False
    if not (
        path.get("supporting") is True
        and path.get("support_kind") == "control_dependency"
        and path.get("branch_candidate") is True
        and path.get("source_role") == SOURCE_ROLE_CONTROL
        and path.get("confirmation_status") == NON_PROOVED
        and path.get("path_class") == PATH_CLASS_ATTACKER_SOURCE
        and path.get("attacker_controlled")
        and path.get("source_id")
        and path.get("entry_point_id")
        and path.get("candidate_types")
        and _has_may_control_branch_evidence(path)
    ):
        return False
    return bool(
        effect_ids.intersection(str(item) for item in path.get("supports_path_ids", ()))
    )


def _is_actionable_branch_candidate(path: dict[str, Any]) -> bool:
    """Keep only explicit unresolved branch candidates; control role alone is insufficient."""

    if not (
        path.get("branch_candidate") is True
        and path.get("branch_candidate_status") == "unresolved"
        and path.get("source_role") == SOURCE_ROLE_CONTROL
        and path.get("confirmation_status") == NON_PROOVED
        and path.get("path_class") == PATH_CLASS_ATTACKER_SOURCE
        and path.get("attacker_controlled")
        and path.get("source_id")
        and path.get("entry_point_id")
        and path.get("candidate_types")
        and _has_may_control_branch_evidence(path)
    ):
        return False
    if path.get("entry_reachability") in TRUSTED_ENTRY_REACHABILITIES:
        return True
    return bool(
        path.get("entry_reachability") in {
            ENTRY_REACHABILITY_BACKWARD_ICC_UNPROVEN,
            ENTRY_REACHABILITY_BACKWARD_ICC_EXACT,
            ENTRY_REACHABILITY_BACKWARD_ICC_APPROXIMATE,
        }
        and path.get("entry_transfer_evidence")
    )


def _has_may_control_branch_evidence(path: dict[str, Any]) -> bool:
    """Require branch-local predicate taint; broad helper fallback is insufficient."""

    return any(
        item.get("may_control_sink_reachability") is True
        and item.get("predicate_taint_status") == "may_tainted"
        for item in path.get("control_branch_evidence", ())
    )


def _type_support(
    paths: list[dict[str, Any]], field: str
) -> tuple[list[str], dict[str, list[str]]]:
    types: list[str] = []
    support: dict[str, list[str]] = {}
    for path in paths:
        for candidate_type in path.get(field, ()):
            if candidate_type not in types:
                types.append(candidate_type)
            support.setdefault(candidate_type, []).append(str(path["id"]))
    return types, support


def _write_array(stream: Any, values: Iterable[Any]) -> None:
    """Write records one at a time without retaining the whole report in memory."""
    stream.write("[\n")
    first = True
    for value in values:
        if not first:
            stream.write(",\n")
        stream.write("    ")
        _write_item(stream, value)
        first = False
    if not first:
        stream.write("\n")
    stream.write("  ]")


def _write_item(stream: Any, value: Any) -> None:
    """Write one value recursively without materializing another object tree."""
    if not isinstance(value, (dict, list, tuple, str, int, float, bool, type(None))):
        value = serializable(value)
    _write_json_value(stream, value)


def _write_json_value(stream: Any, value: Any, field: str = "") -> None:
    """Apply report text normalization while streaming containers in place."""
    if isinstance(value, dict):
        stream.write("{")
        for index, (key, item) in enumerate(value.items()):
            if index:
                stream.write(",")
            key = str(key)
            output_key = report_reference(key) if "->" in key else key
            stream.write(_JSON_ENCODER.encode(output_key))
            stream.write(":")
            _write_json_value(stream, item, key)
        stream.write("}")
        return
    if isinstance(value, (list, tuple, set)):
        stream.write("[")
        for index, item in enumerate(value):
            if index:
                stream.write(",")
            _write_json_value(stream, item, field)
        stream.write("]")
        return
    if isinstance(value, str):
        if "->" in value and (
            "@" in value
            or field in {"root_request", "site_id", "source_site", "sink_site"}
        ):
            value = report_reference(value)
        else:
            value = _readable_text(value)
    elif not isinstance(value, (int, float, bool, type(None))):
        converted = serializable(value)
        if converted is value:
            raise TypeError(f"Object of type {type(value).__name__} is not JSON serializable")
        _write_json_value(stream, converted, field)
        return
    for chunk in _JSON_ENCODER.iterencode(value):
        stream.write(chunk)
