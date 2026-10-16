from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, replace

from src.dynamic.contracts.candidate_set import (
    ANOMALY_MULTIPLE_CONSTRAINTS,
    ANOMALY_NO_SINK_POLICY,
    ANOMALY_OFFSET_MISMATCH,
    ANOMALY_SECTION_INCONSISTENCY,
    ANOMALY_UNKNOWN_COMPONENT_TYPE,
    ANOMALY_UNKNOWN_CONFIRMATION_STATUS,
    ANOMALY_UNKNOWN_OPERATOR,
    ANOMALY_UNKNOWN_ORIGIN_KIND,
    ANOMALY_UNRESOLVED_URI_CARRIER,
    ALL_OPERATORS,
    Anomaly,
    Candidate,
    CandidateSet,
    CONFIRMATION_STATUS_TO_TIER,
    GATE_CONFIG,
    Injection,
    GATE_EXPRESSIBILITY,
    GATE_OBSERVABILITY,
    GATE_SATISFIABILITY,
    OPERATOR_ABSENT,
    OPERATOR_CONTAINS,
    OPERATOR_ENDS_WITH,
    OPERATOR_EQUALS,
    OPERATOR_GREATER_OR_EQUAL,
    OPERATOR_GREATER_THAN,
    OPERATOR_IS_EMPTY,
    OPERATOR_IS_NULL,
    OPERATOR_LESS_OR_EQUAL,
    OPERATOR_LESS_THAN,
    OPERATOR_NON_NULL,
    OPERATOR_NOT_CONTAINS,
    OPERATOR_NOT_EMPTY,
    OPERATOR_NOT_ENDS_WITH,
    OPERATOR_NOT_EQUALS,
    OPERATOR_NOT_STARTS_WITH,
    OPERATOR_STARTS_WITH,
    Reason,
    RequiredInput,
    STATUS_CONTRADICTORY,
    STATUS_SKIPPED_BY_CONFIG,
    STATUS_TESTABLE,
    STATUS_UNOBSERVABLE,
    STATUS_UNSUPPORTED_SYNTAX,
    TIER_UNKNOWN,
    ValueSpec,
    VALUE_KIND_EXACT,
    VALUE_KIND_FALLBACK,
    VALUE_KIND_FREE,
    is_marker_friendly_operator,
    is_marker_sufficient_operator,
)
from src.dynamic.rules.intent_syntax import (
    UNSUPPORTED_COMPONENT_TYPE,
    resolve_adb_flag,
    unsupported_component_reason,
)
from src.dynamic.rules.source_syntax import (
    UNSUPPORTED_UNKNOWN_CARRIER,
    WHOLE_INTENT_WRAPPER,
    build_uri_wrapper,
    is_known_origin_kind,
    resolve_origin,
)
from src.dynamic.rules.predicate_syntax import parse_predicate
from src.dynamic.rules.sink_policy import OBSERVABILITY_NO_POLICY, OBSERVABILITY_OK, check_observability


TYPE_UNKNOWN = "unknown"

SECTION_CONFIRMED = "confirmed"
CONFIRMATION_CONFIRMED = "confirmed"


OPERATOR_STRENGTH = {
    OPERATOR_EQUALS: 6,
    OPERATOR_IS_NULL: 6,
    OPERATOR_ABSENT: 6,
    OPERATOR_STARTS_WITH: 4,
    OPERATOR_ENDS_WITH: 4,
    OPERATOR_IS_EMPTY: 4,
    OPERATOR_CONTAINS: 3,
    OPERATOR_GREATER_THAN: 2,
    OPERATOR_GREATER_OR_EQUAL: 2,
    OPERATOR_LESS_THAN: 2,
    OPERATOR_LESS_OR_EQUAL: 2,
    OPERATOR_NOT_STARTS_WITH: 1,
    OPERATOR_NOT_ENDS_WITH: 1,
    OPERATOR_NOT_CONTAINS: 1,
    OPERATOR_NOT_EQUALS: 1,
    OPERATOR_NOT_EMPTY: 1,
    OPERATOR_NON_NULL: 1,
}


STATUS_BY_GATE_PRIORITY = (
    (GATE_EXPRESSIBILITY, STATUS_UNSUPPORTED_SYNTAX),
    (GATE_SATISFIABILITY, STATUS_CONTRADICTORY),
    (GATE_OBSERVABILITY, STATUS_UNOBSERVABLE),
    (GATE_CONFIG, STATUS_SKIPPED_BY_CONFIG),
)


@dataclass(frozen=True)
class ScreeningConfig:
    """1단계 동작을 조절하는 설정"""

    deny_rules: tuple = ()
    allow_unknown_type: bool = True


@dataclass(frozen=True)
class ParsedGuard:
    """이 경로를 통과하려면 어떤 필드가 어떤 값이어야 하는가 - 가드 하나"""

    field: str
    key: str | None
    api: str
    operator: str | None
    expected_type: str | None
    expected_value: object
    value_known: bool
    offset: int | None = None

    def is_resolved(self):
        """확정값을 갖고 있어 그대로 넣을 수 있는 가드인지 판별한다"""
        return self.value_known and self.operator is not None

    def identity(self):
        """어느 인텐트 필드를 가리키는 가드인지 나타내는 키를 돌려준다"""
        return (self.field, self.key)


def type_of_value(value):
    """비교 상수의 파이썬 타입에서 우리 타입 어휘를 얻는다"""
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "int"
    if isinstance(value, float):
        return "float"
    if isinstance(value, str):
        return "string"
    return None


def resolve_declared_type(field, api, expected_value, value_known, type_hint=None):
    """getter 시그니처나 비교 상수에서 이 입력의 타입을 되살린다"""
    if type_hint:
        return type_hint
    if api:
        found = resolve_adb_flag(field, api, None).value_type
        if found:
            return found
    if value_known:
        return type_of_value(expected_value)
    return None


def build_guards(path, finding_source, anomaly_sink):
    """path.control_branch_evidence 를 필드별 가드 목록으로 옮긴다"""
    source = finding_source or {}
    source_identity = (source.get("field"), source.get("key"))

    source_api = source.get("api") or source.get("label") or ""
    source_type = resolve_declared_type(
        source.get("field"), source_api, None, False) if source_api else None

    guards = []
    for evidence in path.get("control_branch_evidence", []):
        operand = evidence.get("predicate_operand") or {}
        on_source = (operand.get("source_field"),
                     operand.get("source_key")) == source_identity
        parsed = parse_predicate(evidence, anomaly_sink,
                                 field_type=source_type if on_source else None)
        if not parsed.is_guard or not parsed.field:
            continue

        identity = parsed.identity()
        api = source_api if identity == source_identity else ""
        guards.append(ParsedGuard(
            field=parsed.field,
            key=parsed.key,
            api=api,
            operator=parsed.operator,
            expected_type=resolve_declared_type(
                parsed.field, api, parsed.expected_value, parsed.value_known,
                parsed.type_hint),
            expected_value=parsed.expected_value,
            value_known=parsed.value_known,
            offset=evidence.get("branch_offset"),
        ))

        if parsed.operator is not None and parsed.operator not in ALL_OPERATORS:
            anomaly_sink(ANOMALY_UNKNOWN_OPERATOR, f"처음 보는 연산자: {parsed.operator!r}")

    return guards


def build_candidate_id(finding_id, path_id):
    """두 식별자를 합쳐 같은 입력이면 항상 같은 후보 식별자를 만든다"""
    payload = f"{finding_id}\x00{path_id}"
    return "c-" + hashlib.sha256(payload.encode("utf-8")).hexdigest()[:10]


def resolve_tier(confirmation_status, anomaly_sink):
    """path 의 확인 상태(confirmation_status)를 우선순위 티어로 옮긴다"""
    tier = CONFIRMATION_STATUS_TO_TIER.get(confirmation_status)
    if tier is None:
        anomaly_sink(ANOMALY_UNKNOWN_CONFIRMATION_STATUS,
                     f"처음 보는 확인 상태: {confirmation_status!r}")
        return TIER_UNKNOWN
    return tier


def choose_strongest(guards):
    """같은 필드를 가리키는 가드들 중 가장 구체적인 하나를 고른다"""
    return max(
        guards,
        key=lambda item: (
            1 if item.is_resolved() else 0,
            OPERATOR_STRENGTH.get(item.operator, 0),
        ),
    )


SELF_DETERMINED_OPERATORS = (OPERATOR_IS_NULL, OPERATOR_ABSENT, OPERATOR_IS_EMPTY)


def decide_value_kind(guard):
    """가드(guard)의 연산자와 상수 확보 여부로 값 생성 방식을 정한다"""
    if guard.operator is None:
        return VALUE_KIND_FALLBACK
    if guard.operator in SELF_DETERMINED_OPERATORS:
        return VALUE_KIND_EXACT
    if guard.value_known and guard.expected_type != TYPE_UNKNOWN:
        return VALUE_KIND_EXACT
    if is_marker_sufficient_operator(guard.operator):
        return VALUE_KIND_FREE
    return VALUE_KIND_FALLBACK


def resolve_injection(finding_source, source_field, source_key):
    """소스가 parseUri 를 거쳐 읽히면 감싸기와 실제 주입 자리를 정한다"""
    source = finding_source or {}
    if not source.get("via_uri_parse"):
        return None

    if (source.get("origin_kind") or "").startswith("uri_parsed_"):
        return Injection(
            wrapper=WHOLE_INTENT_WRAPPER.template, encode=WHOLE_INTENT_WRAPPER.encode)

    outer_field = source.get("outer_field")
    inner_api = source.get("api") or source.get("label") or ""
    wrapper = build_uri_wrapper(
        source_field, source_key,
        resolve_declared_type(source_field, inner_api, None, False))
    if not outer_field or wrapper is None:
        return Injection(blocked=True)

    return Injection(
        field=outer_field,
        key=source.get("outer_key"),
        wrapper=wrapper.template,
        encode=wrapper.encode,
    )


def build_required_inputs(finding_source, guards, anomaly_sink):
    """소스와 가드를 합쳐 이 경로를 타는 데 필요한 인자 목록을 만든다"""
    grouped = {}
    for guard in guards:
        grouped.setdefault(guard.identity(), []).append(guard)

    source_field = (finding_source or {}).get("field")
    source_key = (finding_source or {}).get("key")
    source_identity = (source_field, source_key)
    source_offset = (finding_source or {}).get("offset")

    source_origin_kind = (finding_source or {}).get("origin_kind")
    if source_origin_kind and not is_known_origin_kind(source_origin_kind):
        anomaly_sink(ANOMALY_UNKNOWN_ORIGIN_KIND,
                     f"처음 보는 소스 origin_kind: {source_origin_kind!r}")

    injection = resolve_injection(finding_source, source_field, source_key)
    if injection is not None and injection.blocked:
        anomaly_sink(ANOMALY_UNRESOLVED_URI_CARRIER,
                     f"{(source_field, source_key)} 는 parseUri 를 거쳐 읽히는데 "
                     f"그 문자열을 싣는 자리를 정적이 집어내지 못했다")

    inputs = []
    for identity, items in grouped.items():
        chosen = choose_strongest(items)
        if len(items) > 1:
            anomaly_sink(
                ANOMALY_MULTIPLE_CONSTRAINTS,
                f"{identity} 에 가드가 {len(items)}개다. "
                f"가장 구체적인 {chosen.operator!r} 만 남기고 나머지는 반영되지 않는다",
            )

        is_taint_source = identity == source_identity
        if is_taint_source and source_offset is not None and chosen.offset is not None:
            if source_offset != chosen.offset:
                anomaly_sink(
                    ANOMALY_OFFSET_MISMATCH,
                    f"{identity} 의 offset 이 소스({source_offset})와 "
                    f"가드({chosen.offset})에서 다르다. 가드를 따른다",
                )

        value_kind = decide_value_kind(chosen)
        inputs.append(RequiredInput(
            field=chosen.field,
            key=chosen.key,
            api=chosen.api,
            markable=is_taint_source and is_marker_friendly_operator(chosen.operator),
            value_spec=ValueSpec(
                value_kind=value_kind,
                declared_type=chosen.expected_type,
                operator=chosen.operator,
                expected_value=chosen.expected_value if value_kind == VALUE_KIND_EXACT else None,
                guard_seen=True,
            ),
            origin_kind=source_origin_kind if is_taint_source else None,
            injection=injection if is_taint_source else None,
        ))

    if source_field and source_identity not in grouped:
        api = (finding_source or {}).get("api") or (finding_source or {}).get("label") or ""
        inputs.append(RequiredInput(
            field=source_field,
            key=source_key,
            api=api,
            markable=True,
            value_spec=ValueSpec(
                value_kind=VALUE_KIND_FALLBACK,
                declared_type=resolve_declared_type(source_field, api, None, False),
                operator=None,
                expected_value=None,
                guard_seen=False,
            ),
            origin_kind=source_origin_kind,
            injection=injection,
        ))

    inputs.sort(key=lambda item: (item.field, item.key or ""))
    return tuple(inputs)


def check_expressibility(inputs, config):
    """모든 입력을 adb am 문법으로 표현할 수 있는지 검사한다"""
    reasons = []
    for required_input in inputs:
        field, _ = required_input.injection_site()
        if required_input.wrapper():
            resolution = resolve_adb_flag(field, "", "string")
        else:
            resolution = resolve_adb_flag(
                field, required_input.api, required_input.value_spec.declared_type)
        if resolution.is_supported():
            continue
        if not resolution.is_hard and config.allow_unknown_type:
            continue
        reasons.append(Reason(
            GATE_EXPRESSIBILITY, resolution.reason,
            "adb am 문법으로 표현할 수 없는 입력이다",
            {"field": required_input.field, "key": required_input.key,
             "api": required_input.api,
             "declared_type": required_input.value_spec.declared_type},
        ))
    return reasons


def check_trigger_verb(component_type):
    """이 컴포넌트 종류(component_type)를 adb am 으로 띄울 수 있는지 검사한다"""
    code = unsupported_component_reason(component_type)
    if code is None:
        return []
    return [Reason(
        GATE_EXPRESSIBILITY, code,
        "adb am 으로 띄울 수 없는 컴포넌트 종류다",
        {"component_type": component_type},
    )]


def check_injectable_origin(inputs):
    """오염 소스를 진입점 인텐트에 실어 보낼 수 있는지 검사한다"""
    reasons = []
    for required_input in inputs:
        if not required_input.origin_kind:
            continue
        resolution = resolve_origin(required_input.origin_kind)
        code = resolution.reason if not resolution.injectable else None
        if code is None and required_input.injection and required_input.injection.blocked:
            code = UNSUPPORTED_UNKNOWN_CARRIER
        if code is None:
            continue
        reasons.append(Reason(
            GATE_EXPRESSIBILITY, code,
            "이 소스는 진입점 인텐트에 실어 보낼 수 없다",
            {"field": required_input.field, "key": required_input.key,
             "origin_kind": required_input.origin_kind},
        ))
    return reasons


def to_number(value):
    """비교에 쓰려고 값(value)을 수치로 바꾸고 안 되면 None 을 돌려준다"""
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def detect_contradictions(guards):
    """같은 필드의 가드들이 동시에 만족될 수 없는지 검사한다"""
    grouped = {}
    for guard in guards:
        grouped.setdefault(guard.identity(), []).append(guard)

    reasons = []
    for identity, items in grouped.items():
        operators = {item.operator for item in items}
        if OPERATOR_IS_NULL in operators and OPERATOR_NON_NULL in operators:
            reasons.append(Reason(
                GATE_SATISFIABILITY, "null_and_non_null",
                "같은 필드가 널이어야 하면서 동시에 널이 아니어야 한다",
                {"field": identity[0], "key": identity[1]},
            ))
        if OPERATOR_ABSENT in operators and len(operators) > 1:
            reasons.append(Reason(
                GATE_SATISFIABILITY, "absent_and_present",
                "같은 필드를 싣지 않아야 하면서 동시에 값을 검사한다",
                {"field": identity[0], "key": identity[1]},
            ))

        resolved = [item for item in items if item.is_resolved()]

        equals_values = {
            repr(item.expected_value)
            for item in resolved if item.operator == OPERATOR_EQUALS
        }
        if len(equals_values) > 1:
            reasons.append(Reason(
                GATE_SATISFIABILITY, "conflicting_equals",
                "같은 필드가 서로 다른 값과 동시에 같아야 한다",
                {"field": identity[0], "key": identity[1],
                 "values": sorted(equals_values)},
            ))

        not_equals_values = {
            repr(item.expected_value)
            for item in resolved if item.operator == OPERATOR_NOT_EQUALS
        }
        overlap = equals_values & not_equals_values
        if overlap:
            reasons.append(Reason(
                GATE_SATISFIABILITY, "equals_and_not_equals",
                "같은 값이어야 하면서 동시에 그 값이 아니어야 한다",
                {"field": identity[0], "key": identity[1], "values": sorted(overlap)},
            ))

        starts = {
            repr(item.expected_value)
            for item in resolved if item.operator == OPERATOR_STARTS_WITH
        }
        not_starts = {
            repr(item.expected_value)
            for item in resolved if item.operator == OPERATOR_NOT_STARTS_WITH
        }
        prefix_overlap = starts & not_starts
        if prefix_overlap:
            reasons.append(Reason(
                GATE_SATISFIABILITY, "conflicting_prefix",
                "같은 접두사로 시작해야 하면서 동시에 시작하면 안 된다",
                {"field": identity[0], "key": identity[1], "values": sorted(prefix_overlap)},
            ))

        lower_bounds = [
            to_number(item.expected_value)
            for item in resolved
            if item.operator in (OPERATOR_GREATER_THAN, OPERATOR_GREATER_OR_EQUAL)
        ]
        upper_bounds = [
            to_number(item.expected_value)
            for item in resolved
            if item.operator in (OPERATOR_LESS_THAN, OPERATOR_LESS_OR_EQUAL)
        ]
        lower_bounds = [value for value in lower_bounds if value is not None]
        upper_bounds = [value for value in upper_bounds if value is not None]
        if lower_bounds and upper_bounds and min(upper_bounds) <= max(lower_bounds):
            reasons.append(Reason(
                GATE_SATISFIABILITY, "empty_range",
                "수치 범위가 비어 있어 만족시킬 값이 없다",
                {"field": identity[0], "key": identity[1],
                 "greater_than": max(lower_bounds), "less_or_equal": min(upper_bounds)},
            ))

    return reasons


def check_observability_gate(sink_rule, candidate, anomaly_sink):
    """싱크 도달을 관측할 방법이 있는지 검사한다"""
    result = check_observability(sink_rule, candidate)
    if result.status == OBSERVABILITY_OK:
        return []
    if result.status == OBSERVABILITY_NO_POLICY:
        anomaly_sink(ANOMALY_NO_SINK_POLICY,
                     f"싱크 규칙 {sink_rule!r} 에 등록된 정책이 없다")
    return [Reason(GATE_OBSERVABILITY, result.status,
                   result.detail, {"sink_rule": sink_rule})]


def check_config_gate(sink_rule, config):
    """실행 설정이 이 싱크를 테스트 대상에서 뺐는지 검사한다"""
    if sink_rule in config.deny_rules:
        return [Reason(GATE_CONFIG, "denied_sink_rule",
                       "실행 설정에서 제외한 싱크 규칙이다", {"sink_rule": sink_rule})]
    return []


def deduplicate_reasons(reasons):
    """같은 게이트의 같은 사유가 두 번 나오면 하나로 접는다"""
    seen = set()
    kept = []
    for reason in reasons:
        signature = (reason.gate, reason.code)
        if signature in seen:
            continue
        seen.add(signature)
        kept.append(reason)
    return kept


def pick_status(reasons):
    """누적된 사유들 중 대표 상태 하나를 고른다"""
    gates = {reason.gate for reason in reasons}
    for gate, status in STATUS_BY_GATE_PRIORITY:
        if gate in gates:
            return status
    return STATUS_TESTABLE


def check_graph_sections(graph_sections, flow_graphs, anomaly_sink):
    """graph_sections 의 confirmed 색인이 path 등급과 맞는지 대조한다"""
    indexed = set((graph_sections or {}).get(SECTION_CONFIRMED, []))
    for graph in flow_graphs:
        graph_id = graph.get("graph_id")
        has_confirmed = any(
            path.get("confirmation_status") == CONFIRMATION_CONFIRMED
            for path in graph.get("paths", [])
        )
        if has_confirmed and graph_id not in indexed:
            anomaly_sink(ANOMALY_SECTION_INCONSISTENCY,
                         f"{graph_id} 에 confirmed path 가 있는데 색인에 없다",
                         graph_id=graph_id)
        elif not has_confirmed and graph_id in indexed:
            anomaly_sink(ANOMALY_SECTION_INCONSISTENCY,
                         f"{graph_id} 가 색인에는 있는데 confirmed path 가 없다",
                         graph_id=graph_id)


def build_source_from_node(node):
    """Build a source description from a flow graph node."""
    if not node:
        return None
    metadata = node.get("metadata") or {}
    return {
        "node_id": node.get("id"),
        "label": node.get("label"),
        "component": node.get("component"),
        "method": node.get("method"),
        "offset": node.get("offset"),
        "api": node.get("api"),
        "field": node.get("field"),
        "key": node.get("key"),
        "origin_kind": metadata.get("origin_kind"),
        "via_uri_parse": metadata.get("via_uri_parse", False),
        "outer_field": metadata.get("outer_field"),
        "outer_key": metadata.get("outer_key"),
        "attacker_controlled": metadata.get("attacker_controlled"),
    }


def build_entry_point_from_node(node):
    """Build an entry point description from a flow graph node."""
    if not node:
        return {}
    metadata = node.get("metadata") or {}
    return {
        "node_id": node.get("id"),
        "component": node.get("component"),
        "component_type": metadata.get("component_type"),
        "exported": metadata.get("exported"),
        "enabled": metadata.get("enabled"),
        "permission": metadata.get("permission"),
    }


def build_sink_from_node(node):
    """Build a sink description from a flow graph node."""
    if not node:
        return {}
    metadata = node.get("metadata") or {}
    return {
        "node_id": node.get("id"),
        "label": node.get("label"),
        "component": node.get("component"),
        "method": node.get("method"),
        "offset": node.get("offset"),
        "api": node.get("api"),
        "rule": metadata.get("rule"),
        "category": metadata.get("category"),
    }


def build_synthetic_finding(graph, nodes_by_id):
    """Build minimal finding metadata for a graph without a finding group."""
    graph_id = graph.get("graph_id")
    paths = graph.get("paths") or []
    entry_node = None
    entry_points = graph.get("entry_points") or []
    if entry_points:
        entry_node = nodes_by_id.get(entry_points[0])
    if entry_node is None and paths:
        entry_node = nodes_by_id.get(paths[0].get("entry_point_id"))

    return {
        "finding_id": f"finding-{graph_id}",
        "entry_point": build_entry_point_from_node(entry_node),
        "source": None,
        "sink": build_sink_from_node(nodes_by_id.get(graph.get("sink"))),
    }


def merge_source(finding_source, path, nodes_by_id):
    """Merge finding source metadata with the path source node."""
    node_source = build_source_from_node(nodes_by_id.get(path.get("source_id")))
    if not finding_source:
        return node_source
    if not node_source:
        return finding_source
    merged = dict(node_source)
    merged.update({key: value for key, value in finding_source.items() if value is not None})
    return merged


def screen(data, config=None):
    """Build CandidateSet from all flow graph paths with finding metadata as an overlay."""
    config = config or ScreeningConfig()
    anomalies = []

    def record_anomaly(code, detail, finding_id=None, graph_id=None, path_id=None):
        """Record an anomaly with its related identifiers."""
        anomalies.append(Anomaly(code, detail, finding_id, graph_id, path_id))

    flow_graphs = data.get("flow_graphs", [])
    graphs_by_id = {graph.get("graph_id"): graph for graph in flow_graphs}
    nodes_by_id = {node.get("id"): node for node in data.get("nodes", [])}
    check_graph_sections(data.get("graph_sections"), flow_graphs, record_anomaly)

    findings_by_graph = {}
    for finding in data.get("finding_groups", []):
        for graph_id in finding.get("graph_ids", []):
            findings_by_graph.setdefault(graph_id, []).append(finding)

    for finding in data.get("finding_groups", []):
        for graph_id in finding.get("graph_ids", []):
            if graph_id not in graphs_by_id:
                record_anomaly(
                    "missing_graph",
                    f"{graph_id} 가 flow_graphs 에 없다",
                    finding_id=finding.get("finding_id"),
                    graph_id=graph_id,
                )

    candidates = []
    for graph in flow_graphs:
        graph_id = graph.get("graph_id")
        findings = findings_by_graph.get(graph_id) or [
            build_synthetic_finding(graph, nodes_by_id)
        ]

        for finding in findings:
            finding_id = finding.get("finding_id")
            entry_point = finding.get("entry_point") or {}
            sink = finding.get("sink") or {}
            component_type = entry_point.get("component_type")
            if unsupported_component_reason(component_type) == UNSUPPORTED_COMPONENT_TYPE:
                record_anomaly(
                    ANOMALY_UNKNOWN_COMPONENT_TYPE,
                    f"처음 보는 컴포넌트 종류: {component_type!r}",
                    finding_id=finding_id,
                    graph_id=graph_id,
                )

            for path_index, path in enumerate(graph.get("paths", [])):
                path_id = path.get("id") or f"{graph_id}-path-{path_index:03d}"

                def path_anomaly(code, detail, _path_id=path_id, **_ignored):
                    """Record a path-level anomaly with its identifiers."""
                    record_anomaly(code, detail, finding_id, graph_id, _path_id)

                source = merge_source(
                    finding.get("source"), path, nodes_by_id
                )
                if not entry_point:
                    entry_point = build_entry_point_from_node(
                        nodes_by_id.get(path.get("entry_point_id"))
                    )
                    component_type = entry_point.get("component_type")
                if not sink:
                    sink = build_sink_from_node(nodes_by_id.get(graph.get("sink")))

                guards = build_guards(path, source, path_anomaly)
                inputs = build_required_inputs(source, guards, path_anomaly)
                tier = resolve_tier(path.get("confirmation_status"), path_anomaly)
                sink_rule = sink.get("rule")

                candidate = Candidate(
                    candidate_id=build_candidate_id(finding_id, path_id),
                    finding_id=finding_id,
                    graph_id=graph_id,
                    path_id=path_id,
                    status=STATUS_TESTABLE,
                    tier=tier,
                    reasons=(),
                    component=entry_point.get("component"),
                    component_type=component_type,
                    permission=entry_point.get("permission"),
                    sink_rule=sink_rule,
                    sink_label=sink.get("label"),
                    inputs=inputs,
                )

                reasons = []
                reasons.extend(check_trigger_verb(component_type))
                reasons.extend(check_injectable_origin(inputs))
                reasons.extend(check_expressibility(inputs, config))
                reasons.extend(detect_contradictions(guards))
                reasons.extend(check_observability_gate(sink_rule, candidate, path_anomaly))
                reasons.extend(check_config_gate(sink_rule, config))

                reasons = deduplicate_reasons(reasons)
                candidates.append(replace(
                    candidate, status=pick_status(reasons), reasons=tuple(reasons)
                ))

    return CandidateSet(
        apk=data.get("apk"),
        candidates=tuple(candidates),
        anomalies=tuple(anomalies),
    )


def screen_file(path, config=None):
    """정적 분석기 JSON 파일(path)을 읽어 CandidateSet 을 만든다"""
    with open(path, encoding="utf-8") as handle:
        return screen(json.load(handle), config)


def render_screening_report(candidate_set):
    """선별 결과(candidate_set)를 사람이 훑어볼 수 있는 요약 문자열로 만든다"""
    lines = [f"apk: {candidate_set.apk}",
             f"후보 {len(candidate_set.candidates)}개"]

    by_status = {}
    by_tier = {}
    by_reason = {}
    for candidate in candidate_set.candidates:
        by_status[candidate.status] = by_status.get(candidate.status, 0) + 1
        if candidate.status == STATUS_TESTABLE:
            by_tier[candidate.tier] = by_tier.get(candidate.tier, 0) + 1
        for reason in candidate.reasons:
            label = f"{reason.gate}/{reason.code}"
            by_reason[label] = by_reason.get(label, 0) + 1

    lines.append("")
    lines.append("상태별")
    for status, count in sorted(by_status.items(), key=lambda item: -item[1]):
        lines.append(f"  {status:22} {count}")

    if by_tier:
        lines.append("")
        lines.append("testable 의 티어별")
        for tier, count in sorted(by_tier.items(), key=lambda item: -item[1]):
            lines.append(f"  {tier:22} {count}")

    if by_reason:
        lines.append("")
        lines.append("사유별 (한 후보가 여러 사유를 가질 수 있다)")
        for label, count in sorted(by_reason.items(), key=lambda item: -item[1]):
            lines.append(f"  {label:34} {count}")

    if candidate_set.anomalies:
        counted = {}
        for anomaly in candidate_set.anomalies:
            counted[anomaly.code] = counted.get(anomaly.code, 0) + 1
        lines.append("")
        lines.append("이상 징후")
        for code, count in sorted(counted.items(), key=lambda item: -item[1]):
            lines.append(f"  {code:34} {count}")

    return "\n".join(lines)
