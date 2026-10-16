"""1단계(후보 선별)가 만들어 2단계(인자 조립)에 넘기는 계약 자료구조.

이 파일에는 1단계가 '판단한 것'만 담는다.
다른 필드에서 순수 함수로 유도할 수 있는 값(adb 플래그, am 서브커맨드,
pm grant 명령 등)은 담지 않고 intent_syntax.py 의 함수로 그때그때 구한다.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


# ---------------------------------------------------------------------------
# 후보 상태 - 하나의 후보는 반드시 아래 중 하나를 가진다
# ---------------------------------------------------------------------------
STATUS_TESTABLE = "testable"                      # 2단계로 넘어가는 유일한 상태
STATUS_UNSUPPORTED_SYNTAX = "unsupported_syntax"  # adb am 문법으로 표현 불가
STATUS_CONTRADICTORY = "contradictory"            # 제약끼리 모순이라 도달 불가
STATUS_UNOBSERVABLE = "unobservable"              # 도달을 관측할 방법이 없음
STATUS_SKIPPED_BY_CONFIG = "skipped_by_config"    # 실행 설정으로 제외
STATUS_UNRESOLVED_VALUE = "unresolved_value"      # 값 후보를 만들 재료가 없음 (2단계 판정)

ALL_STATUSES = (
    STATUS_TESTABLE,
    STATUS_UNSUPPORTED_SYNTAX,
    STATUS_CONTRADICTORY,
    STATUS_UNOBSERVABLE,
    STATUS_SKIPPED_BY_CONFIG,
    STATUS_UNRESOLVED_VALUE,
)


# ---------------------------------------------------------------------------
# 우선순위 티어 - 상태와 독립이다 (testable 이면서 candidate 티어가 정상)
# ---------------------------------------------------------------------------
TIER_CONFIRMED = "confirmed"  # 확정 경로, 우선 실행
TIER_CANDIDATE = "candidate"  # 후보 경로, 후순위 실행
TIER_UNKNOWN = "unknown"      # 근거가 가장 약함, 최후순위 (실측상 0건 예상)

# 정적 분석기의 path.confirmation_status 를 티어로 옮기는 표
CONFIRMATION_STATUS_TO_TIER = {
    "confirmed": TIER_CONFIRMED,
    "non_prooved": TIER_CANDIDATE,
    "unconfirmed": TIER_UNKNOWN,
}


# ---------------------------------------------------------------------------
# 값 생성 방식 - 2단계가 케이스를 몇 개로 확장할지를 결정한다
# ---------------------------------------------------------------------------
VALUE_KIND_EXACT = "exact"        # 확정값이 있음 (expected_value 가 null 이면 '널이어야 함')
VALUE_KIND_FALLBACK = "fallback"  # 타입만 앎, 2단계가 타입별 후보로 확장
VALUE_KIND_FREE = "free"          # 가드 없음, 마커만 심으면 됨 (케이스 1개)

ALL_VALUE_KINDS = (VALUE_KIND_EXACT, VALUE_KIND_FALLBACK, VALUE_KIND_FREE)


# ---------------------------------------------------------------------------
# 인텐트 필드
# ---------------------------------------------------------------------------
FIELD_ACTION = "action"
FIELD_DATA = "data"
FIELD_EXTRA = "extra"
FIELD_CATEGORY = "category"
FIELD_TYPE = "type"
FIELD_COMPONENT = "component"


# ---------------------------------------------------------------------------
# 연산자 - "이 필드가 어떤 값이어야 싱크에 도달하는가".
#
# 정적 분석기는 이제 정규화된 연산자를 주지 않고 조각 두 개를 준다.
#   branch_opcode x sink_may_reaching_outcomes -> 극성 (통과해야 하나 튕겨야 하나)
#   predicate_operand.compare_api              -> 어떤 비교인가
# 둘을 곱해 아래 어휘로 옮기는 일은 predicate_syntax.py 가 한다.
# 값 생성은 그대로 2단계 몫이다.
# ---------------------------------------------------------------------------
OPERATOR_EQUALS = "equals"
OPERATOR_NOT_EQUALS = "not_equals"
OPERATOR_STARTS_WITH = "starts_with"
OPERATOR_NOT_STARTS_WITH = "not_starts_with"
OPERATOR_ENDS_WITH = "ends_with"
OPERATOR_NOT_ENDS_WITH = "not_ends_with"
OPERATOR_CONTAINS = "contains"
OPERATOR_NOT_CONTAINS = "not_contains"
OPERATOR_GREATER_THAN = "greater_than"
OPERATOR_GREATER_OR_EQUAL = "greater_or_equal"
OPERATOR_LESS_THAN = "less_than"
OPERATOR_LESS_OR_EQUAL = "less_or_equal"
OPERATOR_IS_NULL = "is_null"          # 널이어야 통과 (--esn)
OPERATOR_NON_NULL = "non_null"        # 값이 있기만 하면 통과
OPERATOR_IS_EMPTY = "is_empty"
OPERATOR_NOT_EMPTY = "not_empty"
OPERATOR_ABSENT = "absent"            # 이 extra 를 아예 싣지 않아야 통과

ALL_OPERATORS = (
    OPERATOR_EQUALS,
    OPERATOR_NOT_EQUALS,
    OPERATOR_STARTS_WITH,
    OPERATOR_NOT_STARTS_WITH,
    OPERATOR_ENDS_WITH,
    OPERATOR_NOT_ENDS_WITH,
    OPERATOR_CONTAINS,
    OPERATOR_NOT_CONTAINS,
    OPERATOR_GREATER_THAN,
    OPERATOR_GREATER_OR_EQUAL,
    OPERATOR_LESS_THAN,
    OPERATOR_LESS_OR_EQUAL,
    OPERATOR_IS_NULL,
    OPERATOR_NON_NULL,
    OPERATOR_IS_EMPTY,
    OPERATOR_NOT_EMPTY,
    OPERATOR_ABSENT,
)

# 분기가 반대로 걸렸을 때 뒤집는 표. 극성 계산의 유일한 근거다.
NEGATED_OPERATOR = {
    OPERATOR_EQUALS: OPERATOR_NOT_EQUALS,
    OPERATOR_NOT_EQUALS: OPERATOR_EQUALS,
    OPERATOR_STARTS_WITH: OPERATOR_NOT_STARTS_WITH,
    OPERATOR_NOT_STARTS_WITH: OPERATOR_STARTS_WITH,
    OPERATOR_ENDS_WITH: OPERATOR_NOT_ENDS_WITH,
    OPERATOR_NOT_ENDS_WITH: OPERATOR_ENDS_WITH,
    OPERATOR_CONTAINS: OPERATOR_NOT_CONTAINS,
    OPERATOR_NOT_CONTAINS: OPERATOR_CONTAINS,
    OPERATOR_GREATER_THAN: OPERATOR_LESS_OR_EQUAL,
    OPERATOR_LESS_OR_EQUAL: OPERATOR_GREATER_THAN,
    OPERATOR_LESS_THAN: OPERATOR_GREATER_OR_EQUAL,
    OPERATOR_GREATER_OR_EQUAL: OPERATOR_LESS_THAN,
    OPERATOR_IS_NULL: OPERATOR_NON_NULL,
    OPERATOR_NON_NULL: OPERATOR_IS_NULL,
    OPERATOR_IS_EMPTY: OPERATOR_NOT_EMPTY,
    OPERATOR_NOT_EMPTY: OPERATOR_IS_EMPTY,
}

# 값 일부를 자유롭게 쓸 수 있어 마커를 심을 여지가 남는 연산자.
# None 은 가드 자체가 없는 경우다.
MARKER_FRIENDLY_OPERATORS = (
    None,
    OPERATOR_NOT_EQUALS,
    OPERATOR_NOT_STARTS_WITH,
    OPERATOR_NOT_ENDS_WITH,
    OPERATOR_NOT_CONTAINS,
    OPERATOR_STARTS_WITH,
    OPERATOR_ENDS_WITH,
    OPERATOR_CONTAINS,
    OPERATOR_NON_NULL,
    OPERATOR_NOT_EMPTY,
)

# 값을 못 알아내도 마커만으로 통과시킬 수 있는 연산자.
# "이 값이면 안 된다" 류는 마커가 어떤 앱 상수와도 같지 않으므로 자동으로 만족된다.
MARKER_SUFFICIENT_OPERATORS = (
    OPERATOR_NOT_EQUALS,
    OPERATOR_NOT_STARTS_WITH,
    OPERATOR_NOT_ENDS_WITH,
    OPERATOR_NOT_CONTAINS,
    OPERATOR_NON_NULL,
    OPERATOR_NOT_EMPTY,
)


# ---------------------------------------------------------------------------
# 게이트 - Reason.gate 에 쓰는 값
# ---------------------------------------------------------------------------
GATE_EXPRESSIBILITY = "expressibility"  # adb am 문법으로 표현 가능한가
GATE_SATISFIABILITY = "satisfiability"  # 제약을 동시에 만족시킬 수 있는가
GATE_OBSERVABILITY = "observability"    # 도달을 관측할 수 있는가
GATE_CONFIG = "config"                  # 실행 설정으로 제외
GATE_VALUE_BUILD = "value_build"        # 값 후보를 만들 수 있는가 (2단계)


# ---------------------------------------------------------------------------
# 이상 코드 - 필터 결과가 아니라 입력 데이터나 파이프라인 자체의 문제
# ---------------------------------------------------------------------------
ANOMALY_OFFSET_MISMATCH = "offset_mismatch"                    # source 와 constraint 의 offset 불일치
ANOMALY_NO_SINK_POLICY = "no_sink_policy"                      # 등록되지 않은 sink 규칙
ANOMALY_UNKNOWN_COMPONENT_TYPE = "unknown_component_type"      # 예상 밖 컴포넌트 종류
ANOMALY_UNKNOWN_CONFIRMATION_STATUS = "unknown_confirmation_status"
ANOMALY_UNKNOWN_OPERATOR = "unknown_operator"                  # 표에 없는 연산자
ANOMALY_SECTION_INCONSISTENCY = "section_inconsistency"        # graph_sections 와 path 등급 불일치
ANOMALY_MULTIPLE_CONSTRAINTS = "multiple_constraints"          # 한 필드에 제약이 둘 이상
ANOMALY_UNKNOWN_OPCODE = "unknown_opcode"                      # 표에 없는 분기 명령어
ANOMALY_UNKNOWN_COMPARE_API = "unknown_compare_api"            # 표에 없는 비교 API
ANOMALY_UNKNOWN_VALUE_KIND = "unknown_value_kind"              # 표에 없는 compare_value_kind
ANOMALY_BRANCH_NOT_A_GUARD = "branch_not_a_guard"              # 양쪽 다 싱크에 도달하는 분기
ANOMALY_UNKNOWN_ORIGIN_KIND = "unknown_origin_kind"            # 표에 없는 소스 origin_kind
ANOMALY_UNRESOLVED_URI_CARRIER = "unresolved_uri_carrier"      # parseUri 소스인데 실을 자리 미상


def is_marker_friendly_operator(operator):
    """연산자가 값 일부를 자유롭게 남겨 마커를 심을 여지가 있는지 판별한다"""
    return operator in MARKER_FRIENDLY_OPERATORS


def is_marker_sufficient_operator(operator):
    """값을 몰라도 마커만으로 통과시킬 수 있는 연산자인지 판별한다"""
    return operator in MARKER_SUFFICIENT_OPERATORS


# ---------------------------------------------------------------------------
# 자료구조
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class ValueSpec:
    """어떤 값을 넣어야 이 필드가 경로를 통과시키는지에 대한 제약"""

    value_kind: str                 # VALUE_KIND_* 중 하나
    declared_type: str | None       # "string" | "int" | "boolean" | "unknown" | None
    operator: str | None            # OPERATOR_* 중 하나. 가드가 없으면 None
    expected_value: Any = None      # value_kind 가 exact 일 때만 의미가 있다
    guard_seen: bool = True         # 정적이 이 필드를 검사하는 분기를 찾았는가

    def to_dict(self):
        """직렬화를 위해 dict 로 변환한다"""
        return {
            "value_kind": self.value_kind,
            "declared_type": self.declared_type,
            "operator": self.operator,
            "expected_value": self.expected_value,
            "guard_seen": self.guard_seen,
        }

    @staticmethod
    def from_dict(raw):
        """dict(raw) 에서 ValueSpec 을 복원한다"""
        return ValueSpec(
            value_kind=raw["value_kind"],
            declared_type=raw.get("declared_type"),
            operator=raw.get("operator"),
            expected_value=raw.get("expected_value"),
            guard_seen=raw.get("guard_seen", True),
        )


@dataclass(frozen=True)
class Injection:
    """값을 실제로 어디에 어떤 모양으로 실어 보내는가.

    앱이 Intent.parseUri 로 만든 인텐트에서 값을 읽으면, RequiredInput 의 field/key 는
    그 '안쪽' 읽기를 가리킨다. 가드도 거기 걸려 있으므로 값 후보는 계속 안쪽 기준으로
    만들고, 다 만든 값을 wrapper 로 감싸 이쪽 자리에 싣는다.
    """

    field: str | None = None      # None 이면 RequiredInput.field 자리에 그대로 쓴다
    key: str | None = None
    wrapper: str | None = None    # "{value}" 자리를 가진 intent: URI 템플릿
    encode: bool = False          # {value} 를 percent-encoding 해서 넣어야 하는가
    # parseUri 를 거치는 것은 아는데 그 문자열을 싣는 자리를 정적이 못 집어냈다.
    # 진입점에 그대로 쓰면 앱이 안 읽는 자리에 써 놓고 미도달이라 말하게 된다.
    blocked: bool = False

    def to_dict(self):
        """직렬화를 위해 dict 로 변환한다"""
        return {"field": self.field, "key": self.key, "wrapper": self.wrapper,
                "encode": self.encode, "blocked": self.blocked}

    @staticmethod
    def from_dict(raw):
        """dict(raw) 에서 Injection 을 복원한다"""
        return Injection(
            field=raw.get("field"), key=raw.get("key"), wrapper=raw.get("wrapper"),
            encode=raw.get("encode", False), blocked=raw.get("blocked", False),
        )


@dataclass(frozen=True)
class RequiredInput:
    """이 경로를 타려면 인텐트에 실어야 하는 필드 하나"""

    field: str                # FIELD_* 중 하나
    key: str | None           # FIELD_EXTRA 일 때만 쓰는 extra 키
    api: str                  # 예: "Intent.getStringExtra(String)"
    markable: bool            # 싱크까지 흘러가고 값에 여유가 있어 마커를 심을 수 있는가
    value_spec: ValueSpec
    # 정적이 준 소스의 origin_kind. 오염 소스인 입력에만 붙고 가드에서 온 입력은 None 이다.
    # 같은 필드라도 앱이 값을 어디서 꺼내느냐에 따라 주입이 통하는지가 갈린다.
    origin_kind: str | None = None
    # 값을 어디에 실어 보내는가. field/key 와 다를 수 있다 - 아래 Injection 참고.
    injection: Injection | None = None

    def injection_site(self):
        """이 입력의 값을 실제로 실어 보낼 (필드, 키) 를 돌려준다"""
        if self.injection is None or self.injection.field is None:
            return (self.field, self.key)
        return (self.injection.field, self.injection.key)

    def wrapper(self):
        """값을 감쌀 템플릿을 돌려준다. 감싸지 않으면 None 이다"""
        return self.injection.wrapper if self.injection else None

    def to_dict(self):
        """직렬화를 위해 dict 로 변환한다"""
        return {
            "field": self.field,
            "key": self.key,
            "api": self.api,
            "markable": self.markable,
            "value_spec": self.value_spec.to_dict(),
            "origin_kind": self.origin_kind,
            "injection": self.injection.to_dict() if self.injection else None,
        }

    @staticmethod
    def from_dict(raw):
        """dict(raw) 에서 RequiredInput 을 복원한다"""
        return RequiredInput(
            field=raw["field"],
            key=raw.get("key"),
            api=raw["api"],
            markable=raw["markable"],
            value_spec=ValueSpec.from_dict(raw["value_spec"]),
            origin_kind=raw.get("origin_kind"),
            injection=Injection.from_dict(raw["injection"]) if raw.get("injection") else None,
        )


@dataclass(frozen=True)
class Reason:
    """후보가 testable 이 아닌 이유 하나"""

    gate: str          # GATE_* 중 하나
    code: str          # 게이트별 세부 코드 (예: "adb_nested_intent", "unreliable")
    detail: str        # 사람이 읽을 설명
    evidence: dict     # 어떤 입력이나 제약 때문인지

    def to_dict(self):
        """직렬화를 위해 dict 로 변환한다"""
        return {
            "gate": self.gate,
            "code": self.code,
            "detail": self.detail,
            "evidence": self.evidence,
        }

    @staticmethod
    def from_dict(raw):
        """dict(raw) 에서 Reason 을 복원한다"""
        return Reason(
            gate=raw["gate"],
            code=raw["code"],
            detail=raw.get("detail", ""),
            evidence=raw.get("evidence", {}),
        )


@dataclass(frozen=True)
class Anomaly:
    """입력 JSON 이나 정책 등록의 이상 - 후보 필터 결과와는 층이 다르다"""

    code: str                     # ANOMALY_* 중 하나
    detail: str
    finding_id: str | None = None
    graph_id: str | None = None
    path_id: str | None = None

    def to_dict(self):
        """직렬화를 위해 dict 로 변환한다"""
        return {
            "code": self.code,
            "detail": self.detail,
            "finding_id": self.finding_id,
            "graph_id": self.graph_id,
            "path_id": self.path_id,
        }

    @staticmethod
    def from_dict(raw):
        """dict(raw) 에서 Anomaly 를 복원한다"""
        return Anomaly(
            code=raw["code"],
            detail=raw.get("detail", ""),
            finding_id=raw.get("finding_id"),
            graph_id=raw.get("graph_id"),
            path_id=raw.get("path_id"),
        )


@dataclass(frozen=True)
class Candidate:
    """검증 단위 하나 - finding 안의 특정 경로.

    같은 경로가 여러 finding 에 속할 수 있어 (finding.path_ids 가 리스트다) 키는
    (finding_id, path_id) 두 개다. graph_id 는 path_id 에서 유도되지만 리포트에
    자주 쓰여 함께 들고 다닌다.
    """

    candidate_id: str
    finding_id: str
    graph_id: str
    path_id: str            # 정적이 매긴 경로 식별자. 순번이 아니라 이름이라 정렬이 바뀌어도 안 깨진다

    status: str                      # STATUS_* 중 하나
    tier: str                        # TIER_* 중 하나
    reasons: tuple[Reason, ...]      # status 가 testable 이면 빈 튜플

    component: str                   # 진입점 컴포넌트명
    component_type: str              # activity | service | receiver
    permission: str | None           # 진입점이 요구하는 권한

    sink_rule: str                   # "FILE_STREAM_OPEN" 등, sink_policy 조회 키
    sink_label: str                  # "FileOutputStream.<init>" 등 원본 라벨

    inputs: tuple[RequiredInput, ...]

    def is_testable(self):
        """이 후보가 2단계로 넘어갈 수 있는 상태인지 판별한다"""
        return self.status == STATUS_TESTABLE

    def get_markable_inputs(self):
        """마커를 심을 수 있는 입력만 추려서 돌려준다"""
        return tuple(item for item in self.inputs if item.markable)

    def to_dict(self):
        """직렬화를 위해 dict 로 변환한다"""
        return {
            "candidate_id": self.candidate_id,
            "finding_id": self.finding_id,
            "graph_id": self.graph_id,
            "path_id": self.path_id,
            "status": self.status,
            "tier": self.tier,
            "reasons": [item.to_dict() for item in self.reasons],
            "component": self.component,
            "component_type": self.component_type,
            "permission": self.permission,
            "sink_rule": self.sink_rule,
            "sink_label": self.sink_label,
            "inputs": [item.to_dict() for item in self.inputs],
        }

    @staticmethod
    def from_dict(raw):
        """dict(raw) 에서 Candidate 를 복원한다"""
        return Candidate(
            candidate_id=raw["candidate_id"],
            finding_id=raw["finding_id"],
            graph_id=raw["graph_id"],
            path_id=raw["path_id"],
            status=raw["status"],
            tier=raw["tier"],
            reasons=tuple(Reason.from_dict(item) for item in raw.get("reasons", [])),
            component=raw["component"],
            component_type=raw["component_type"],
            permission=raw.get("permission"),
            sink_rule=raw["sink_rule"],
            sink_label=raw["sink_label"],
            inputs=tuple(RequiredInput.from_dict(item) for item in raw.get("inputs", [])),
        )


@dataclass(frozen=True)
class CandidateSet:
    """1단계의 산출물이자 2단계의 유일한 입력"""

    apk: str
    candidates: tuple[Candidate, ...]
    anomalies: tuple[Anomaly, ...] = ()

    def get_testable(self):
        """2단계가 소비할 testable 후보만 추려서 돌려준다"""
        return tuple(item for item in self.candidates if item.is_testable())

    def get_by_status(self, status):
        """주어진 상태(status)를 가진 후보만 추려서 돌려준다"""
        return tuple(item for item in self.candidates if item.status == status)

    def find(self, candidate_id):
        """candidate_id 로 후보 하나를 찾고 없으면 None 을 돌려준다"""
        for item in self.candidates:
            if item.candidate_id == candidate_id:
                return item
        return None

    def to_dict(self):
        """CLI 검수용 JSON 으로 떨구기 위해 dict 로 변환한다"""
        return {
            "apk": self.apk,
            "candidates": [item.to_dict() for item in self.candidates],
            "anomalies": [item.to_dict() for item in self.anomalies],
        }

    @staticmethod
    def from_dict(raw):
        """dict(raw) 에서 CandidateSet 을 복원한다"""
        return CandidateSet(
            apk=raw["apk"],
            candidates=tuple(Candidate.from_dict(item) for item in raw.get("candidates", [])),
            anomalies=tuple(Anomaly.from_dict(item) for item in raw.get("anomalies", [])),
        )
