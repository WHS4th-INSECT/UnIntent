"""control_branch_evidence 한 건을 "이 필드가 어떤 값이어야 하는가"로 옮긴다.

정적 분석기는 정규화된 연산자를 주지 않는다. 대신 조각 세 개를 준다.

    branch_opcode              분기가 '걸리는' 조건 (if-eqz 면 레지스터가 0일 때)
    sink_may_reaching_outcomes 싱크에 가려면 분기가 걸려야 하나 말아야 하나
    predicate_operand          그 레지스터를 만든 비교와 비교 상수

앞의 둘을 곱하면 극성이 나오고, 거기에 compare_api 를 곱하면 우리 연산자가 된다.
예를 들어 `if-eqz` + `fallthrough`(안 걸려야 도달) + `String.startsWith(String)` 는
"startsWith 가 참이어야 싱크에 도달" 이므로 starts_with 다.

adb 도 기기도 모르는 순수 모듈이다. 달빅 분기 의미론만 안다.
"""

from __future__ import annotations

from dataclasses import dataclass

from src.dynamic.contracts.candidate_set import (
    ANOMALY_BRANCH_NOT_A_GUARD,
    ANOMALY_UNKNOWN_COMPARE_API,
    ANOMALY_UNKNOWN_OPCODE,
    ANOMALY_UNKNOWN_VALUE_KIND,
    FIELD_EXTRA,
    NEGATED_OPERATOR,
    OPERATOR_CONTAINS,
    OPERATOR_EQUALS,
    OPERATOR_GREATER_OR_EQUAL,
    OPERATOR_GREATER_THAN,
    OPERATOR_IS_EMPTY,
    OPERATOR_IS_NULL,
    OPERATOR_LESS_OR_EQUAL,
    OPERATOR_LESS_THAN,
    OPERATOR_NON_NULL,
    OPERATOR_STARTS_WITH,
    OPERATOR_ENDS_WITH,
)
from src.dynamic.rules.intent_syntax import (
    PRIMITIVE_VALUE_TYPES,
    extract_method_name,
    is_source_getter,
    value_type_of_getter,
)


# ---------------------------------------------------------------------------
# 입력 어휘
# ---------------------------------------------------------------------------
OUTCOME_FALLTHROUGH = "fallthrough"      # 분기가 안 걸리고 다음 명령으로 진행
OUTCOME_BRANCH_TARGET = "branch_target"  # 분기가 걸려 점프

VALUE_KIND_CONSTANT = "constant"
VALUE_KIND_NULL_CHECK = "null_check"
VALUE_KIND_UNKNOWN = "unknown"
KNOWN_COMPARE_VALUE_KINDS = (VALUE_KIND_CONSTANT, VALUE_KIND_NULL_CHECK, VALUE_KIND_UNKNOWN)


# ---------------------------------------------------------------------------
# 분기 명령어 -> "분기가 걸리는 조건"
#
# 값은 (레지스터가 만족해야 하는 관계, 0 과 비교하는가) 다. 0 비교형(...z)은
# 피연산자가 하나뿐이라 비교 대상이 언제나 0 이고, 두 레지스터형은 비교 상수를
# predicate_operand.compare_value 에서 받는다.
# ---------------------------------------------------------------------------
OPCODE_TAKEN_RELATION = {
    "if-eqz": (OPERATOR_EQUALS, True),
    "if-nez": (NEGATED_OPERATOR[OPERATOR_EQUALS], True),
    "if-ltz": (OPERATOR_LESS_THAN, True),
    "if-gez": (OPERATOR_GREATER_OR_EQUAL, True),
    "if-gtz": (OPERATOR_GREATER_THAN, True),
    "if-lez": (OPERATOR_LESS_OR_EQUAL, True),
    "if-eq": (OPERATOR_EQUALS, False),
    "if-ne": (NEGATED_OPERATOR[OPERATOR_EQUALS], False),
    "if-lt": (OPERATOR_LESS_THAN, False),
    "if-ge": (OPERATOR_GREATER_OR_EQUAL, False),
    "if-gt": (OPERATOR_GREATER_THAN, False),
    "if-le": (OPERATOR_LESS_OR_EQUAL, False),
}

# 0 과의 동등 비교만이 '술어 결과 레지스터'로 해석될 수 있다.
# if-ltz 같은 대소 비교가 boolean 레지스터에 걸리는 것은 말이 안 된다.
EQUALITY_OPERATORS = (OPERATOR_EQUALS, NEGATED_OPERATOR[OPERATOR_EQUALS])


# ---------------------------------------------------------------------------
# 비교 API -> 술어가 참일 때의 연산자
#
# 키는 파라미터를 뗀 메서드 이름이다. compare_api 는 "String.equals(Object)" 처럼
# 풀 시그니처로 오므로 extract_method_name() 으로 먼저 줄인다.
# ---------------------------------------------------------------------------
COMPARE_API_OPERATORS = {
    "equals": OPERATOR_EQUALS,
    "equalsIgnoreCase": OPERATOR_EQUALS,     # 대소문자 무시라 정답 값은 그대로 통한다
    "contentEquals": OPERATOR_EQUALS,
    "startsWith": OPERATOR_STARTS_WITH,
    "endsWith": OPERATOR_ENDS_WITH,
    "contains": OPERATOR_CONTAINS,
    "hasExtra": OPERATOR_NON_NULL,           # 키가 있기만 하면 통과
    "hasCategory": OPERATOR_EQUALS,
    "isEmpty": OPERATOR_IS_EMPTY,
}


@dataclass(frozen=True)
class ParsedPredicate:
    """control_branch_evidence 한 건을 해석한 결과"""

    field: str | None           # 이 가드가 검사하는 인텐트 필드
    key: str | None             # extra 면 키
    operator: str | None        # OPERATOR_* 중 하나. 해석 실패면 None
    expected_value: object      # 비교 상수. 모르면 None
    value_known: bool           # expected_value 를 믿어도 되는가
    is_guard: bool              # 싱크 도달을 실제로 좌우하는 분기인가
    type_hint: str | None = None  # getter 시그니처에서 알아낸 값 타입

    def identity(self):
        """어느 인텐트 필드를 가리키는 가드인지 나타내는 키를 돌려준다"""
        return (self.field, self.key)


# ---------------------------------------------------------------------------
# 극성
# ---------------------------------------------------------------------------
def collect_outcomes(raw_outcomes):
    """도달 결과 목록에서 방향 이름만 모아 집합으로 돌려준다"""
    names = set()
    for item in raw_outcomes or ():
        name = item.get("outcome") if isinstance(item, dict) else item
        if name:
            names.add(name)
    return names


def resolve_reaching_relation(branch_opcode, raw_outcomes, anomaly_sink=None):
    """분기 명령어와 도달 방향으로 '레지스터가 만족해야 하는 관계'를 정한다"""
    entry = OPCODE_TAKEN_RELATION.get(branch_opcode)
    if entry is None:
        if anomaly_sink:
            anomaly_sink(ANOMALY_UNKNOWN_OPCODE, f"처음 보는 분기 명령어: {branch_opcode!r}")
        return None, None

    taken_relation, is_zero_compare = entry
    outcomes = collect_outcomes(raw_outcomes)

    # 양쪽 다 싱크에 도달하면 이 분기는 조건이 아니다. 걸러내지 않으면 극성이
    # 두 방향으로 동시에 계산돼 멀쩡한 후보가 모순으로 버려진다.
    if OUTCOME_FALLTHROUGH in outcomes and OUTCOME_BRANCH_TARGET in outcomes:
        if anomaly_sink:
            anomaly_sink(ANOMALY_BRANCH_NOT_A_GUARD,
                         f"{branch_opcode} 는 어느 방향으로 가도 싱크에 도달한다")
        return None, is_zero_compare

    if OUTCOME_BRANCH_TARGET in outcomes:
        return taken_relation, is_zero_compare
    if OUTCOME_FALLTHROUGH in outcomes:
        return NEGATED_OPERATOR[taken_relation], is_zero_compare
    return None, is_zero_compare


# ---------------------------------------------------------------------------
# 본체
# ---------------------------------------------------------------------------
def parse_predicate(evidence, anomaly_sink=None, field_type=None):
    """control_branch_evidence 한 건(evidence)을 ParsedPredicate 로 옮긴다.

    field_type 은 이 필드에 담기는 값의 타입이다. 0 비교형 분기에서 `if-eqz` 가
    '널이냐' 인지 '숫자 0 이냐' 인지는 레지스터에 담긴 것이 무엇이냐로만 갈리는데,
    그건 분기 증거만 봐서는 알 수 없다. 호출자가 소스 getter 시그니처에서 알아내
    넘겨준다. extra 가 아닌 필드는 언제나 객체 참조라 넘기지 않아도 된다.
    """
    operand = evidence.get("predicate_operand") or {}
    field = operand.get("source_field")
    key = operand.get("source_key")
    compare_api = operand.get("compare_api")
    compare_value = operand.get("compare_value")
    value_kind = operand.get("compare_value_kind")

    if value_kind is not None and value_kind not in KNOWN_COMPARE_VALUE_KINDS:
        if anomaly_sink:
            anomaly_sink(ANOMALY_UNKNOWN_VALUE_KIND,
                         f"처음 보는 compare_value_kind: {value_kind!r}")
        value_kind = VALUE_KIND_UNKNOWN

    relation, is_zero_compare = resolve_reaching_relation(
        evidence.get("branch_opcode"), evidence.get("sink_may_reaching_outcomes"), anomaly_sink
    )
    blank = ParsedPredicate(field, key, None, None, False, is_guard=False)
    if relation is None:
        return blank

    # 가지 0 - 비교 API 자리에 소스 getter 가 왔다.
    #
    # `String mode = intent.getStringExtra("mode"); if (mode == null) return;` 은
    # `invoke getStringExtra; move-result v1; if-eqz v1` 이 된다. v1 을 만든 명령을
    # 되짚으면 getStringExtra 가 나오는데 이건 비교가 아니다. 딸려온 "mode" 도 비교
    # 상수가 아니라 extra 키다. 그대로 믿으면 extra["mode"] == "mode" 라는 헛소리
    # 제약이 생기므로, compare_value 를 버리고 레지스터에 담긴 것이 무엇인지로 읽는다.
    if compare_api and is_source_getter(compare_api):
        returned = value_type_of_getter(compare_api)
        if returned == "boolean":
            # 레지스터가 boolean 자체다. 0 이 아니어야 한다는 말은 true 여야 한다는 뜻.
            wanted = "false" if relation == OPERATOR_EQUALS else "true"
            if relation not in EQUALITY_OPERATORS:
                if anomaly_sink:
                    anomaly_sink(ANOMALY_UNKNOWN_OPCODE,
                                 f"boolean getter 결과에 {relation} 비교가 걸렸다")
                return blank
            return ParsedPredicate(field, key, OPERATOR_EQUALS, wanted, True,
                                   is_guard=True, type_hint=returned)
        if returned in PRIMITIVE_VALUE_TYPES:
            # 수치다. 0 과의 비교가 곧 조건이다.
            return ParsedPredicate(field, key, relation, 0, True,
                                   is_guard=True, type_hint=returned)
        # 객체 참조를 돌려주는 getter. 0 과의 비교는 널 검사다.
        if relation not in EQUALITY_OPERATORS:
            if anomaly_sink:
                anomaly_sink(ANOMALY_UNKNOWN_OPCODE,
                             f"객체 참조에 {relation} 비교가 걸렸다")
            return blank
        operator = OPERATOR_IS_NULL if relation == OPERATOR_EQUALS else OPERATOR_NON_NULL
        return ParsedPredicate(field, key, operator, None, True,
                               is_guard=True, type_hint=returned)

    # 가지 1 - 조건 레지스터가 비교 API 의 반환값이다.
    if compare_api:
        method = extract_method_name(compare_api)
        positive = COMPARE_API_OPERATORS.get(method)
        if positive is None:
            if anomaly_sink:
                anomaly_sink(ANOMALY_UNKNOWN_COMPARE_API,
                             f"처음 보는 비교 API: {compare_api!r}")
            return blank
        if relation not in EQUALITY_OPERATORS:
            # boolean 레지스터에 대소 비교가 걸렸다. 우리가 잘못 읽었거나 정적이 틀렸다.
            if anomaly_sink:
                anomaly_sink(ANOMALY_UNKNOWN_OPCODE,
                             f"{compare_api} 의 결과에 {relation} 비교가 걸렸다")
            return blank

        # relation 이 '0 이 아니어야 한다' 면 술어가 참이어야 한다는 뜻이다.
        predicate_must_hold = relation != OPERATOR_EQUALS
        operator = positive if predicate_must_hold else NEGATED_OPERATOR[positive]
        known = value_kind == VALUE_KIND_CONSTANT
        return ParsedPredicate(field, key, operator,
                               compare_value if known else None, known, is_guard=True)

    # 가지 2 - 비교 API 없이 레지스터를 직접 비교한다.
    #
    # 여기서 타입이 결정적이다. `if-eqz v1` 은 v1 에 담긴 것이 무엇이냐에 따라
    # '널이냐' 도 되고 '0 이냐' 도 된다. 객체 참조인데 숫자로 읽으면
    # `-a 0` / `-a 0_x` 같은 무의미한 액션이 확정값으로 들어가고, exact 라서
    # 케이스가 하나뿐이라 제대로 된 값을 시도조차 못 하게 된다.
    resolved_type = field_type or (None if field == FIELD_EXTRA else "string")
    is_primitive = resolved_type in PRIMITIVE_VALUE_TYPES if resolved_type else None

    def as_null_check():
        """0 과의 비교를 널 검사로 읽는다"""
        if relation not in EQUALITY_OPERATORS:
            if anomaly_sink:
                anomaly_sink(ANOMALY_UNKNOWN_OPCODE,
                             f"객체 참조에 {relation} 비교가 걸렸다")
            return blank
        operator = OPERATOR_IS_NULL if relation == OPERATOR_EQUALS else OPERATOR_NON_NULL
        # '널이어야 통과' 는 --esn 으로 넣을 수 있는 확정값이다.
        return ParsedPredicate(field, key, operator, None, True,
                               is_guard=True, type_hint=resolved_type)

    if value_kind == VALUE_KIND_NULL_CHECK:
        return as_null_check()

    if is_zero_compare:
        if is_primitive is False:
            # 객체 참조와 0 을 비교한다 = 널 검사다. 숫자 0 이 아니다.
            return as_null_check()
        if is_primitive:
            return ParsedPredicate(field, key, relation, 0, True,
                                   is_guard=True, type_hint=resolved_type)
        # 담긴 것이 무엇인지 모른다. 관계만 남기고 값은 풀로 탐색하게 한다.
        # 여기서 0 이라고 단정하면 틀렸을 때 케이스가 하나로 줄어 못 찾는다.
        return ParsedPredicate(field, key, relation, None, False, is_guard=True)

    if value_kind == VALUE_KIND_CONSTANT:
        return ParsedPredicate(field, key, relation, compare_value, True,
                               is_guard=True, type_hint=resolved_type)

    # 관계는 알지만 비교 대상을 모른다. 값 풀로 탐색해야 한다.
    return ParsedPredicate(field, key, relation, None, False, is_guard=True)
