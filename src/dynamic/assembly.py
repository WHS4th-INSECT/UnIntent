"""2단계 - 후보마다 실제로 넣을 인자 값을 정하고 adb 커맨드를 조립한다.

CandidateSet 과 ValuePool 을 받아 TestCaseSet 을 만드는 순수 변환이다.
에뮬레이터를 건드리지 않으므로 같은 입력이면 항상 같은 출력이 나온다.

한 후보는 폴백 후보의 조합만큼 여러 케이스로 불어난다. 조합은 점수가 높은 것부터
꺼내므로 variant_index=0 은 언제나 그 후보의 최선 조합이다.
"""

from __future__ import annotations

import hashlib
import heapq
import shlex
from urllib.parse import quote
from dataclasses import dataclass
import logging

from src.dynamic.contracts.candidate_set import (
    FIELD_ACTION,
    FIELD_CATEGORY,
    FIELD_DATA,
    FIELD_EXTRA,
    FIELD_TYPE,
    GATE_VALUE_BUILD,
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
    STATUS_UNRESOLVED_VALUE,
    TIER_CANDIDATE,
    TIER_CONFIRMED,
    TIER_UNKNOWN,
    VALUE_KIND_EXACT,
    VALUE_KIND_FALLBACK,
    VALUE_KIND_FREE,
)
from src.dynamic.contracts.test_case_set import (
    ATTRIBUTION_MARKER,
    ATTRIBUTION_TIMING,
    Binding,
    ORIGIN_DERIVED,
    ORIGIN_EXACT,
    ORIGIN_MARKER,
    ORIGIN_POOL_CLASS,
    ORIGIN_POOL_COMPONENT,
    ORIGIN_POOL_GENERIC,
    ORIGIN_SINK_SHAPE,
    ORIGIN_TYPE_DEFAULT,
    ORIGIN_UNGUARDED_MARKER,
    TestCase,
    TestCaseSet,
    SkippedCandidate,
    WEIGHT_BY_ORIGIN,
    WEIGHT_PENALTY_UNCONFIDENT,
)
from src.dynamic.environment import AssemblyConfig
from src.dynamic.rules.intent_syntax import resolve_adb_flag, resolve_trigger_verb
from src.dynamic.rules.source_syntax import VALUE_SLOT
from src.dynamic.rules.sink_policy import get_policy
from src.dynamic.adapters.value_pool import (
    SHAPE_ACTION,
    SHAPE_CATEGORY,
    SHAPE_MIME,
    SHAPE_PATH,
    SHAPE_URI,
    classify_shape,
)

LOGGER = logging.getLogger(__name__)

MARKER_PLACEHOLDER = "{marker}"
DIGITS_PLACEHOLDER = "{digits}"

# 이 자리는 커맨드에 아예 싣지 않아야 통과한다 (operator == absent).
# 널을 명시하는 --esn 과는 다르므로 None 으로 표현할 수 없다.
OMIT_PLACEHOLDER = "{omit}"

TIER_ORDER = {TIER_CONFIRMED: 0, TIER_CANDIDATE: 1, TIER_UNKNOWN: 2}

# 필드마다 받아들일 수 있는 값의 생김새. None 이면 생김새로 거르지 않는다.
FIELD_ALLOWED_SHAPES = {
    FIELD_ACTION: (SHAPE_ACTION,),
    FIELD_CATEGORY: (SHAPE_CATEGORY,),
    FIELD_DATA: (SHAPE_URI, SHAPE_PATH),
    FIELD_TYPE: (SHAPE_MIME,),
    FIELD_EXTRA: None,
}

# 타입만 아는 경우의 기본 후보.
# int 가 네 개뿐인 이유: 값을 아는 경우는 이미 exact 로 오므로 여기 내려온 int 는
# 대개 열거값이거나 -1 센티넬이다. 리소스 ID 나 비트 플래그는 추측으로 맞을 수 없어
# 후보를 늘려도 히트율은 그대로이고 조합만 불어난다.
TYPE_DEFAULTS = {
    "boolean": ("true", "false"),
    "int": ("0", "1", "2", "-1"),
    "long": ("0", "1", "2", "-1"),
    "float": ("0.0", "1.0", "-1.0"),
    "double": ("0.0", "1.0", "-1.0"),
    "string": ("", "true", "1", MARKER_PLACEHOLDER),
}


@dataclass(frozen=True)
class ValueCandidate:
    """입력 하나에 넣어볼 값 후보"""

    template: str | None    # None 이면 '널이어야 함'. 마커 자리표시자를 품을 수 있다
    origin: str
    weight: float


# ---------------------------------------------------------------------------
# 마커
# ---------------------------------------------------------------------------
def build_marker(case_number):
    """케이스 번호(case_number)로 사람이 읽을 수 있는 마커를 만든다"""
    # 소문자 영숫자만 쓴다. 파일명, URL 경로, 호스트명 라벨에 모두 들어가야 하기 때문이다.
    return f"mk{case_number:04d}"


def build_sub_marker(marker, input_index):
    """입력 순번(input_index)까지 구분되는 서브마커를 만든다"""
    # 입력마다 다른 마커를 심으면 어느 입력이 실제로 싱크에 도달했는지까지 알 수 있다.
    return f"{marker}{chr(ord('a') + input_index)}"


def build_digits_marker(case_number, input_index):
    """숫자만 허용되는 자리에 쓸 숫자 마커를 만든다"""
    return f"{case_number:04d}{input_index:02d}"


def render_config_slots(template, config):
    """템플릿(template)의 설정 자리표시자를 실제 값으로 채운다"""
    if template is None:
        return None
    return (
        template
        .replace("{host_suffix}", config.host_suffix)
        .replace("{canary_dir}", config.canary_dir)
        .replace("{canary_authority}", config.canary_authority)
        .replace("{telecom_prefix}", config.telecom_prefix)
    )


def render_marker_slots(template, marker, case_number, input_index):
    """템플릿(template)의 마커 자리표시자를 채우고 실제로 심었는지 함께 돌려준다"""
    if template is None:
        return None, None
    text = template
    used = None
    if MARKER_PLACEHOLDER in text:
        sub_marker = build_sub_marker(marker, input_index)
        text = text.replace(MARKER_PLACEHOLDER, sub_marker)
        used = sub_marker
    if DIGITS_PLACEHOLDER in text:
        digits = build_digits_marker(case_number, input_index)
        text = text.replace(DIGITS_PLACEHOLDER, digits)
        used = used or digits
    return text, used


# ---------------------------------------------------------------------------
# 확정값에서 값 유도
# ---------------------------------------------------------------------------
def make_different_value(expected, declared_type):
    """확정값(expected)과 확실히 다른 값을 타입(declared_type)에 맞게 만든다"""
    if expected is None:
        return "x"
    if declared_type == "boolean":
        return "false" if str(expected).lower() == "true" else "true"
    if declared_type in ("int", "long"):
        try:
            return str(int(expected) + 1)
        except (TypeError, ValueError):
            return "0"
    return f"{expected}_x"


def shift_number(expected, delta, fallback=None):
    """수치 확정값(expected)을 delta 만큼 옮긴 문자열을 만든다"""
    try:
        return str(int(expected) + delta)
    except (TypeError, ValueError):
        return fallback


def derive_exact_value(value_spec, markable):
    """확정값과 연산자로 실제로 넣을 값 후보 하나를 유도한다"""
    operator = value_spec.operator
    expected = value_spec.expected_value
    declared_type = value_spec.declared_type

    # 연산자만으로 넣을 값이 정해지는 것들부터 본다. 비교 상수가 없어도 확정이다.
    if operator == OPERATOR_IS_NULL:
        # None 템플릿은 커맨드 조립에서 --esn (명시적 널) 이 된다.
        return ValueCandidate(None, ORIGIN_EXACT, WEIGHT_BY_ORIGIN[ORIGIN_EXACT])
    if operator == OPERATOR_IS_EMPTY:
        return ValueCandidate("", ORIGIN_EXACT, WEIGHT_BY_ORIGIN[ORIGIN_EXACT])
    if operator == OPERATOR_ABSENT:
        # 이 자리는 아예 싣지 않아야 통과한다. 조립이 바인딩을 건너뛴다.
        return ValueCandidate(OMIT_PLACEHOLDER, ORIGIN_EXACT, WEIGHT_BY_ORIGIN[ORIGIN_EXACT])

    if operator is None or operator == OPERATOR_EQUALS:
        template = None if expected is None else str(expected)
        return ValueCandidate(template, ORIGIN_EXACT, WEIGHT_BY_ORIGIN[ORIGIN_EXACT])

    if operator == OPERATOR_NOT_EQUALS:
        value = make_different_value(expected, declared_type)
    elif operator == OPERATOR_NON_NULL:
        value = MARKER_PLACEHOLDER if markable else "x"
    elif operator == OPERATOR_NOT_EMPTY:
        value = MARKER_PLACEHOLDER if markable else "x"
    elif operator == OPERATOR_STARTS_WITH:
        tail = MARKER_PLACEHOLDER if markable else "x"
        value = f"{expected}{tail}"
    elif operator == OPERATOR_NOT_STARTS_WITH:
        value = f"x{expected}"
    elif operator == OPERATOR_ENDS_WITH:
        head = MARKER_PLACEHOLDER if markable else "x"
        value = f"{head}{expected}"
    elif operator == OPERATOR_NOT_ENDS_WITH:
        value = f"{expected}x"
    elif operator == OPERATOR_CONTAINS:
        head = MARKER_PLACEHOLDER if markable else "x"
        value = f"{head}{expected}"
    elif operator == OPERATOR_NOT_CONTAINS:
        value = MARKER_PLACEHOLDER if markable else "x"
    elif operator == OPERATOR_GREATER_THAN:
        value = shift_number(expected, 1)
    elif operator == OPERATOR_GREATER_OR_EQUAL:
        value = shift_number(expected, 0)
    elif operator == OPERATOR_LESS_THAN:
        value = shift_number(expected, -1)
    elif operator == OPERATOR_LESS_OR_EQUAL:
        value = shift_number(expected, 0)
    else:
        return None

    if value is None:
        return None
    return ValueCandidate(value, ORIGIN_DERIVED, WEIGHT_BY_ORIGIN[ORIGIN_DERIVED])


# ---------------------------------------------------------------------------
# 풀 값의 순위 - 대상 컴포넌트를 기준으로 매긴다
# ---------------------------------------------------------------------------
def get_allowed_shapes(required_input):
    """이 입력(required_input)이 받아들일 값의 생김새 목록을 정한다"""
    if required_input.field != FIELD_EXTRA:
        return FIELD_ALLOWED_SHAPES.get(required_input.field)
    declared_type = (required_input.value_spec.declared_type or "").lower()
    if declared_type == "uri":
        return (SHAPE_URI, SHAPE_PATH)
    return None


def matches_shape(value, allowed_shapes):
    """값(value)의 생김새가 허용 목록(allowed_shapes)에 드는지 판별한다"""
    if allowed_shapes is None:
        return True
    return bool(set(classify_shape(value)) & set(allowed_shapes))


def is_type_compatible(value, declared_type):
    """값(value)이 선언 타입(declared_type)으로 넘길 수 있는 형태인지 판별한다"""
    # int extra 에 문자열 상수를 넣으면 --ei 가 깨진다. 생김새 필터가 없는 extra 필드는
    # 타입으로 걸러야 한다.
    name = (declared_type or "").lower()
    if name == "boolean":
        return value.lower() in ("true", "false")
    if name in ("int", "long"):
        try:
            int(value)
            return True
        except (TypeError, ValueError):
            return False
    if name in ("float", "double"):
        try:
            float(value)
            return True
        except (TypeError, ValueError):
            return False
    return True


def collect_component_values(pool, component, field):
    """대상 컴포넌트(component)가 선언하거나 사용하는 값을 필드(field)별로 모은다"""
    filters = pool.get_component_filters(component)
    if field == FIELD_ACTION:
        return list(filters.get("action", [])) + list(pool.get_dynamic_actions(component))
    if field == FIELD_CATEGORY:
        return list(filters.get("category", []))
    if field == FIELD_TYPE:
        return list(filters.get("mime", []))
    if field == FIELD_DATA:
        return build_uris_from_filter(filters)
    return []


def build_uris_from_filter(filters):
    """매니페스트의 scheme/host/path 조각을 합쳐 온전한 URI 후보를 만든다"""
    # 매니페스트는 scheme 과 host 와 path 를 따로 선언하므로 그대로는 URI 가 아니다.
    schemes = filters.get("scheme", [])
    hosts = filters.get("host", []) or ["localhost"]
    paths = filters.get("path", []) or ["/"]
    uris = []
    for scheme in schemes:
        for host in hosts:
            for path in paths:
                tail = path if path.startswith("/") else f"/{path}"
                uri = f"{scheme}://{host}{tail}"
                if uri not in uris:
                    uris.append(uri)
    return uris


def rank_pool_values(pool, component, required_input):
    """대상 컴포넌트 기준으로 풀 값에 순위를 매겨 값 후보 목록을 돌려준다"""
    allowed_shapes = get_allowed_shapes(required_input)
    ranked = {}

    def add(value, origin, confident=True):
        """값(value)을 출처(origin)의 가중치와 함께 후보 사전에 넣는다"""
        if not isinstance(value, str) or not value:
            return
        if not matches_shape(value, allowed_shapes):
            return
        if not is_type_compatible(value, required_input.value_spec.declared_type):
            return
        weight = WEIGHT_BY_ORIGIN[origin]
        if not confident:
            weight *= WEIGHT_PENALTY_UNCONFIDENT
        current = ranked.get(value)
        if current is None or weight > current.weight:
            ranked[value] = ValueCandidate(value, origin, weight)

    for value in collect_component_values(pool, component, required_input.field):
        add(value, ORIGIN_POOL_COMPONENT)

    for value in pool.get_class_strings(component):
        add(value, ORIGIN_POOL_CLASS)

    for item in pool.all_values:
        add(item.value, ORIGIN_POOL_GENERIC, item.confident)

    # 같은 등급 안에서는 앱 자신의 이름 공간에 있는 값을 앞에 둔다. 매니페스트에
    # android.intent.action.VIEW 와 앱 고유 액션이 함께 선언돼 있으면, 그 앱의
    # 가드가 검사하는 쪽은 대개 고유 액션이기 때문이다.
    prefix = (pool.package or "") + "."
    return sorted(
        ranked.values(),
        key=lambda item: (
            -item.weight,
            not (prefix and item.template.startswith(prefix)),
            item.template,
        ),
    )


def build_type_defaults(required_input):
    """선언 타입만 아는 입력(required_input)에 쓸 기본 후보를 만든다"""
    declared_type = (required_input.value_spec.declared_type or "").lower()
    if declared_type == "uri":
        values = (
            "{canary_dir}/canary_{marker}",
            "content://{marker}.{canary_authority}/{marker}",
            "https://{marker}.{host_suffix}/{marker}",
        )
    else:
        values = TYPE_DEFAULTS.get(declared_type)
        if values is None:
            # 타입을 못 알아냈으면 문자열로 가정한다. API 시그니처로 되살릴 여지가
            # 남아 있어 1단계에서 자르지 않고 여기까지 보낸 경우다.
            values = TYPE_DEFAULTS["string"]
    weight = WEIGHT_BY_ORIGIN[ORIGIN_TYPE_DEFAULT]
    return [ValueCandidate(value, ORIGIN_TYPE_DEFAULT, weight) for value in values]


# ---------------------------------------------------------------------------
# 입력별 값 후보
# ---------------------------------------------------------------------------
def build_value_candidates(candidate, required_input, pool, policy, config):
    """입력 하나에 넣어볼 값 후보를 확신도 높은 순으로 만든다"""
    spec = required_input.value_spec
    hint = policy.marker_hint(required_input) if policy else None
    shape_template = render_config_slots(hint.template, config) if hint else None

    if spec.value_kind == VALUE_KIND_EXACT:
        derived = derive_exact_value(spec, required_input.markable)
        return [derived] if derived else []

    if spec.value_kind == VALUE_KIND_FREE:
        # 가드가 없으므로 무슨 값이든 통과한다. 싱크가 알려준 형태가 있으면 쓰고,
        # 없으면 마커만 넣는다.
        if shape_template:
            return [ValueCandidate(shape_template, ORIGIN_SINK_SHAPE,
                                   WEIGHT_BY_ORIGIN[ORIGIN_SINK_SHAPE])]
        return [ValueCandidate(MARKER_PLACEHOLDER, ORIGIN_MARKER,
                               WEIGHT_BY_ORIGIN[ORIGIN_MARKER])]

    # value_kind == fallback : 타입만 알고 값은 모른다
    collected = []

    # 정적이 이 필드를 검사하는 분기를 하나도 못 찾았다면 마커를 제일 앞에 둔다.
    # 정적이 맞으면 첫 발에 통과해 조기 종료가 나머지를 건너뛰고, 틀렸으면 뒤의
    # 값 후보로 자연히 내려간다. 그 말을 믿고 케이스를 하나로 줄이지는 않는다.
    if not spec.guard_seen:
        collected.append(ValueCandidate(
            shape_template or MARKER_PLACEHOLDER,
            ORIGIN_UNGUARDED_MARKER,
            WEIGHT_BY_ORIGIN[ORIGIN_UNGUARDED_MARKER],
        ))
    elif shape_template:
        collected.append(ValueCandidate(shape_template, ORIGIN_SINK_SHAPE,
                                        WEIGHT_BY_ORIGIN[ORIGIN_SINK_SHAPE]))
    collected.extend(rank_pool_values(pool, candidate.component, required_input))

    # 타입 기본 후보도 생김새를 통과해야 한다. action 필드에 ""/"1"/"true" 를 넣는 건
    # 무의미하고, 그런 값이 후보로 남으면 '재료가 없다'는 판정도 못 하게 된다.
    allowed_shapes = get_allowed_shapes(required_input)
    for item in render_defaults(build_type_defaults(required_input), config):
        if item.template and matches_shape(item.template, allowed_shapes):
            collected.append(item)
        elif item.template == "" and allowed_shapes is None:
            collected.append(item)

    seen = set()
    unique = []
    for item in collected:
        if item.template in seen:
            continue
        seen.add(item.template)
        unique.append(item)

    # 가중치로만 정렬한다. 파이썬 정렬은 안정적이라 같은 가중치끼리는 넣은 순서가
    # 유지되고, rank_pool_values 가 매긴 동점 순서(앱 고유 이름 공간 우선)가 살아남는다.
    unique.sort(key=lambda item: -item.weight)
    return unique[:config.max_values_per_input]


def render_defaults(candidates, config):
    """기본 후보들의 설정 자리표시자를 채운다"""
    return [
        ValueCandidate(render_config_slots(item.template, config), item.origin, item.weight)
        for item in candidates
    ]


def is_hopeless(required_input, candidates):
    """값 후보가 없어 이 입력의 가드를 통과할 수 없는 상태인지 판별한다"""
    # 문자열 equals 가드는 정답 문자열을 블라인드로 맞힐 수 없다. 재료가 없으면
    # 몇 번을 시도해도 실패하며, 억지로 돌리면 '미도달' 통계만 오염된다.
    if candidates:
        return False
    return True


# ---------------------------------------------------------------------------
# 조합 전개 - 점수 높은 것부터
# ---------------------------------------------------------------------------
def score_combination(value_lists, indices):
    """조합(indices)의 점수를 각 값 가중치의 곱으로 계산한다"""
    score = 1.0
    for position, index in enumerate(indices):
        score *= value_lists[position][index].weight
    return score


def expand_combinations(value_lists, max_cases):
    """입력별 후보 목록을 점수 높은 조합부터 최대 개수까지 꺼낸다"""
    # 가중치가 모두 1 이하라 곱은 단조 감소한다. 그래서 힙으로 최적 우선 탐색을 하면
    # 첫 조합이 언제나 최선이고, 상한에서 잘라도 좋은 것부터 남는다.
    if not value_lists:
        return [((), 1.0)], False

    start = tuple(0 for _ in value_lists)
    heap = [(-score_combination(value_lists, start), start)]
    seen = {start}
    picked = []

    while heap and len(picked) < max_cases:
        negative, indices = heapq.heappop(heap)
        picked.append((indices, -negative))
        for position in range(len(value_lists)):
            moved = list(indices)
            moved[position] += 1
            if moved[position] >= len(value_lists[position]):
                continue
            nxt = tuple(moved)
            if nxt in seen:
                continue
            seen.add(nxt)
            heapq.heappush(heap, (-score_combination(value_lists, nxt), nxt))

    return picked, bool(heap)


# ---------------------------------------------------------------------------
# 커맨드 조립
# ---------------------------------------------------------------------------
def resolve_flag_for_input(required_input):
    """입력(required_input)에 쓸 adb 플래그를 정하고 못 정하면 None 을 돌려준다"""
    field, _ = required_input.injection_site()
    if required_input.wrapper():
        # 감싼 결과는 언제나 intent: URI 문자열이다. 안쪽 읽기의 타입이 무엇이었든
        # 바깥에 실리는 것은 문자열 하나다.
        return resolve_adb_flag(field, "", "string").flag
    resolution = resolve_adb_flag(
        field, required_input.api, required_input.value_spec.declared_type
    )
    if resolution.is_supported():
        return resolution.flag
    if not resolution.is_hard:
        # 타입 미상은 문자열로 가정한다. 1단계가 이 경우를 자르지 않고 넘긴 이유다.
        return "--es"
    return None


def build_argv(package, candidate, bindings):
    """컴포넌트와 바인딩으로 adb am 인자 배열을 만든다"""
    verb = resolve_trigger_verb(candidate.component_type)
    argv = ["am", verb, "-n", f"{package}/{candidate.component}"]

    for binding in bindings:
        if binding.field == FIELD_EXTRA:
            if binding.value is None:
                argv.extend(["--esn", binding.key])
            else:
                argv.extend([binding.adb_flag, binding.key, str(binding.value)])
            continue
        if binding.value is None:
            # action 같은 비-extra 필드의 '널이어야 함'은 플래그를 빼는 것으로 표현한다.
            continue
        argv.extend([binding.adb_flag, str(binding.value)])

    return tuple(argv)


def format_shell_command(argv):
    """인자 배열(argv)을 셸에 넘길 수 있게 따옴표를 붙여 한 줄로 만든다"""
    # 값에 공백, 따옴표, $, 세미콜론이 들어가는 일이 흔하다. 문자열을 이어 붙여
    # 만들면 조용히 깨지므로 배열로 들고 다니다가 여기서 한 번만 감싼다.
    return "adb shell " + " ".join(shlex.quote(part) for part in argv)


def compute_dedup_key(candidate, argv, marker):
    """마커를 뺀 커맨드와 싱크 규칙으로 중복 판정 키를 만든다"""
    # 같은 커맨드라도 싱크가 다르면 3단계의 준비물과 관측 채널이 다르므로 합치지 않는다.
    normalized = [part.replace(marker, "*") for part in argv]
    payload = "\x00".join([candidate.sink_rule] + normalized)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]


# ---------------------------------------------------------------------------
# 본체
# ---------------------------------------------------------------------------
def sort_candidates(candidates):
    """실행 순서가 재현되도록 티어와 식별자로 후보를 정렬한다"""
    return sorted(
        candidates,
        key=lambda item: (TIER_ORDER.get(item.tier, 99), item.candidate_id),
    )


def apply_wrapper(required_input, value):
    """완성된 값을 소스가 요구하는 모양으로 감싼다. 감쌀 게 없으면 그대로 돌려준다"""
    # 마커를 채운 뒤에 감싼다. 먼저 감싸면 인코딩이 마커 자리표시자를 갉아먹는다.
    wrapper = required_input.wrapper()
    if wrapper is None or value is None:
        return value
    text = str(value)
    if required_input.injection.encode:
        # intent: URI 의 파라미터 값은 세미콜론과 '#' 에서 끊긴다. 마커는 영숫자라
        # 인코딩해도 그대로 남아 로그에서 계속 찾을 수 있다.
        text = quote(text, safe="")
    return wrapper.replace(VALUE_SLOT, text)


def build_bindings(candidate, value_lists, indices, flags, marker, case_number, config):
    """고른 조합(indices)으로 실제 값을 채운 바인딩 목록을 만든다"""
    bindings = []
    for position, index in enumerate(indices):
        required_input = candidate.inputs[position]
        chosen = value_lists[position][index]
        if chosen.template == OMIT_PLACEHOLDER:
            # 이 필드를 싣지 않는 것이 곧 조건 충족이다. 바인딩을 만들지 않으면
            # build_argv 가 플래그를 붙이지 않는다.
            continue
        value, marker_part = render_marker_slots(
            chosen.template, marker, case_number, position
        )
        # 값은 안쪽 읽기 기준으로 만들고, 다 만든 것을 감싸 바깥 자리에 싣는다.
        payload = value
        value = apply_wrapper(required_input, value)
        field, key = required_input.injection_site()
        flag = "--esn" if (value is None and field == FIELD_EXTRA) else flags[position]
        bindings.append(Binding(
            field=field,
            key=key,
            adb_flag=flag,
            value=value,
            origin=chosen.origin,
            weight=chosen.weight,
            marker_part=marker_part,
            payload=payload,
        ))
    return tuple(bindings)

def skip_candidate(candidate, code, detail, evidence):
    """후보(candidate)를 실행 대상에서 빼는 기록을 만든다"""
    return SkippedCandidate(
        candidate.candidate_id,
        STATUS_UNRESOLVED_VALUE,
        (Reason(GATE_VALUE_BUILD, code, detail, evidence),),
    )


def build_candidate_cases(candidate, pool, config, package, first_case_number, dedup_seen):
    """후보 하나의 테스트 케이스를 만든다. (케이스, 건너뜀 기록, 잘림 여부, 새 중복 키) 를 돌려준다"""
    policy = get_policy(candidate.sink_rule)

    flags = []
    for required_input in candidate.inputs:
        field, key = required_input.injection_site()
        if field == FIELD_EXTRA and key is None:
            return [], skip_candidate(
                candidate, "no_extra_key", "extra 의 키를 알 수 없는 입력이 있다",
                {"field": required_input.field, "api": required_input.api},
            ), False, {}
        flag = resolve_flag_for_input(required_input)
        if flag is None:
            return [], skip_candidate(
                candidate, "no_adb_flag", "adb 플래그를 정할 수 없는 입력이 있다",
                {"field": required_input.field, "key": required_input.key,
                 "api": required_input.api},
            ), False, {}
        flags.append(flag)

    value_lists = []
    for required_input in candidate.inputs:
        candidates_for_input = build_value_candidates(
            candidate, required_input, pool, policy, config
        )
        if is_hopeless(required_input, candidates_for_input):
            return [], skip_candidate(
                candidate, "no_value_candidate", "가드를 통과시킬 값 후보를 만들 재료가 없다",
                {"field": required_input.field, "key": required_input.key,
                 "operator": required_input.value_spec.operator,
                 "declared_type": required_input.value_spec.declared_type},
            ), False, {}
        value_lists.append(candidates_for_input)

    combinations, was_truncated = expand_combinations(
        value_lists, config.max_cases_per_candidate
    )

    cases = []
    local_seen = {}
    case_number = first_case_number
    for variant_index, (indices, score) in enumerate(combinations):
        case_number += 1
        marker = build_marker(case_number)
        bindings = build_bindings(
            candidate, value_lists, indices, flags, marker, case_number, config
        )
        argv = build_argv(package, candidate, bindings)

        attribution = (ATTRIBUTION_MARKER
                       if any(item.marker_part for item in bindings)
                       else ATTRIBUTION_TIMING)

        dedup_key = compute_dedup_key(candidate, argv, marker)
        test_case_id = f"tc-{case_number:04d}"
        cases.append(TestCase(
            test_case_id=test_case_id,
            candidate_id=candidate.candidate_id,
            variant_index=variant_index,
            marker=marker,
            attribution=attribution,
            argv=argv,
            bindings=bindings,
            confidence=score,
            duplicate_of=dedup_seen.get(dedup_key, local_seen.get(dedup_key)),
        ))
        if dedup_key not in dedup_seen:
            local_seen.setdefault(dedup_key, test_case_id)

    return cases, None, was_truncated, local_seen

def assemble(candidate_set, pool, config=None):
    """CandidateSet 과 ValuePool 로 실행할 TestCaseSet 을 만든다"""
    config = config or AssemblyConfig()
    package = candidate_set.apk
    cases = []
    skipped = []
    truncated = []
    dedup_seen = {}

    for candidate in sort_candidates(candidate_set.get_testable()):
        try:
            candidate_cases, skip, was_truncated, new_seen = build_candidate_cases(
                candidate, pool, config, package, len(cases), dedup_seen
            )
        except Exception as error:
            LOGGER.warning("테스트 케이스 조립 실패: %s", candidate.candidate_id,
                           exc_info=True)
            skipped.append(skip_candidate(
                candidate, "assembly_failed", "테스트 케이스를 조립하다 예외가 났다",
                {"error": f"{type(error).__name__}: {error}"},
            ))
            continue

        if skip is not None:
            skipped.append(skip)
            continue
  
        if was_truncated:
            truncated.append(candidate.candidate_id)
            
        cases.extend(candidate_cases)
        dedup_seen.update(new_seen)

    return TestCaseSet(
        apk=package,
        cases=tuple(cases),
        skipped=tuple(skipped),
        truncated_candidates=tuple(truncated),
    )