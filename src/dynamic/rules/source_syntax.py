"""소스가 요구하는 값의 모양을 판별한다. intent_syntax.py 의 대칭물이다.

싱크 정책이 "관측되려면 어떤 모양이어야 하나"를 말하듯, 여기서는 정적 분석기가
알려준 origin_kind 로 "앱의 파싱을 살아남으려면 어떤 모양이어야 하나"를 말한다.

같은 `--es path <값>` 이라도 앱이 그 값을 진입점 인텐트에서 바로 꺼내는지, 한 번
파싱해서 꺼내는지, 아예 다른 컴포넌트에서 꺼내는지에 따라 주입이 통하기도 하고
안 통하기도 한다. 분기 증거만 보는 predicate_syntax 로는 알 수 없고, 정적이
origin_kind 로 알려주는 것이 유일한 근거다.

adb 도 기기도 모르는 순수 모듈이다.
"""

from __future__ import annotations

from dataclasses import dataclass

from src.dynamic.contracts.candidate_set import (
    FIELD_ACTION,
    FIELD_DATA,
    FIELD_EXTRA,
    FIELD_TYPE,
)
from src.dynamic.rules.intent_syntax import UNSUPPORTED_NESTED_INTENT


# ---------------------------------------------------------------------------
# 정적 분석기의 origin_kind 어휘
# src/static/findings/classifier.py 의 SOURCE_KINDS 와 1:1 로 대응한다.
# 거기에 종류가 늘면 여기도 늘려야 하고, 안 늘리면 unknown_origin_kind 로 걸린다.
# ---------------------------------------------------------------------------
ORIGIN_EXTERNAL_INTENT = "external_intent"                        # 진입점 인텐트 통째
ORIGIN_EXTERNAL_FIELD = "external_field"                          # 진입점 인텐트의 한 필드
ORIGIN_URI_PARSED_EXTERNAL_INTENT = "uri_parsed_external_intent"  # 문자열을 파싱한 인텐트
ORIGIN_NESTED_EXTERNAL_INTENT = "nested_external_intent"          # extra 로 실려 온 인텐트
ORIGIN_EXTERNAL_PARAMETER = "external_parameter"                  # exported provider 의 인자
ORIGIN_COMPONENT_INTENT = "component_intent"                      # 진입점이 아닌 컴포넌트
ORIGIN_COMPONENT_FIELD = "component_field"
ORIGIN_COMPONENT_PARAMETER = "component_parameter"

ALL_ORIGIN_KINDS = (
    ORIGIN_EXTERNAL_INTENT,
    ORIGIN_EXTERNAL_FIELD,
    ORIGIN_URI_PARSED_EXTERNAL_INTENT,
    ORIGIN_NESTED_EXTERNAL_INTENT,
    ORIGIN_EXTERNAL_PARAMETER,
    ORIGIN_COMPONENT_INTENT,
    ORIGIN_COMPONENT_FIELD,
    ORIGIN_COMPONENT_PARAMETER,
)

# ---------------------------------------------------------------------------
# 주입 불가 사유 코드
# ---------------------------------------------------------------------------
# provider 는 am 으로 부를 수단이 없다. `content query --uri` 로 부르는 길이 있지만
# 인자 조립과 관측이 통째로 달라져 지금 범위 밖이다.
UNSUPPORTED_PROVIDER_ENTRY = "adb_provider_entry"

# parseUri 를 거쳐 읽는 것은 알겠는데 그 문자열을 어디에 싣는지를 정적이 못 집어냈다.
# 진입점에 그대로 쓰면 앱이 안 읽는 자리에 쓰는 것이라 미도달이 거짓이 된다.
UNSUPPORTED_UNKNOWN_CARRIER = "adb_unknown_uri_carrier"

# 중첩 인텐트는 intent_syntax 가 getParcelableExtra 로도 잡아내던 것과 같은 사실이다.
# 사유 코드를 나누면 같은 원인이 두 통계로 쪼개지므로 그 코드를 그대로 쓴다.


@dataclass(frozen=True)
class OriginResolution:
    """소스 하나를 진입점 인텐트에 실어 보낼 수 있는지에 대한 판정.

    '어떤 모양으로' 감싸느냐는 안쪽 읽기의 필드에 달렸고 build_uri_wrapper 가 정한다.
    여기서는 origin_kind 만으로 정해지는 '보낼 수 있느냐' 만 본다.
    """

    injectable: bool        # 진입점 인텐트에 실어 보낼 수 있는가
    reason: str | None      # 주입 불가일 때의 사유 코드
    via_icc: bool = False   # 진입점이 아닌 컴포넌트에서 읽는가


# 그대로 실으면 되는 종류. 값이 진입점 인텐트의 그 필드에서 바로 읽힌다.
_DIRECT = OriginResolution(injectable=True, reason=None)

_BY_ORIGIN_KIND = {
    ORIGIN_EXTERNAL_INTENT: _DIRECT,
    ORIGIN_EXTERNAL_FIELD: _DIRECT,

    # 앱이 Intent.parseUri 를 거쳐 읽는다. 안쪽 읽기면 그 값을 intent: URI 로 감싸
    # 바깥 자리에 싣고(B-2), 파싱된 인텐트 자체가 흘러가면 통째로 꾸민다(Case A).
    # 어느 쪽이든 보낼 수는 있으므로 여기서는 통과시킨다.
    ORIGIN_URI_PARSED_EXTERNAL_INTENT: _DIRECT,

    # 인텐트를 extra 로 요구한다. am 문법에 Intent 를 실을 플래그가 없다.
    ORIGIN_NESTED_EXTERNAL_INTENT: OriginResolution(
        injectable=False, reason=UNSUPPORTED_NESTED_INTENT),

    # exported provider 의 진입 인자다. am 으로는 부를 수 없다.
    ORIGIN_EXTERNAL_PARAMETER: OriginResolution(
        injectable=False, reason=UNSUPPORTED_PROVIDER_ENTRY),

    # 진입점이 아닌 곳에서 읽는다. 진입점을 때리면 ICC 를 타고 닿을 수는 있으므로
    # 시도는 하되, 기록된 필드명이 실제로 읽히는 필드와 다를 수 있다.
    ORIGIN_COMPONENT_INTENT: OriginResolution(injectable=True, reason=None, via_icc=True),
    ORIGIN_COMPONENT_FIELD: OriginResolution(injectable=True, reason=None, via_icc=True),
    ORIGIN_COMPONENT_PARAMETER: OriginResolution(injectable=True, reason=None, via_icc=True),
}


# ---------------------------------------------------------------------------
# intent: URI 감싸기
#
# 앱이 Intent.parseUri(문자열) 로 인텐트를 만들어 거기서 값을 꺼내는 경우, 우리가
# 실어야 하는 것은 값 자체가 아니라 "그 값을 담은 인텐트 URI" 다. 평문을 실으면
# 프레임워크가 Intent(ACTION_VIEW, Uri.parse(값)) 을 만들어 주므로 data 를 읽는 앱에는
# 우연히 통하지만, extra 를 읽는 앱에는 통하지 않는다.
#
# intent: 스킴은 parseUri 구현과 flags 인자에 상관없이 받아들여지는 유일한 형태다.
# 그래서 여기 감싸기는 프레임워크 판본을 가정하지 않는다. 다만 2단계는 감싼 값만
# 넣지 않고 평문 후보도 함께 남긴다 - 어느 쪽이 맞는지 고르는 대신 둘 다 던진다.
# ---------------------------------------------------------------------------
VALUE_SLOT = "{value}"


@dataclass(frozen=True)
class UriWrapper:
    """값 하나를 intent: URI 로 감싸는 방법"""

    template: str    # VALUE_SLOT 자리를 가진 템플릿
    encode: bool     # 자리에 넣기 전에 percent-encoding 해야 하는가


# 템플릿이 VALUE_SLOT 하나뿐이면 감싸지 않고 값을 그대로 싣는다는 뜻이다.
# 실을 자리만 바깥으로 옮기면 되는 경우가 있어서 그것과 '감쌀 방법이 없다'(None)를
# 구분해야 한다.
PASSTHROUGH = UriWrapper(VALUE_SLOT, encode=False)

# 안쪽 읽기가 어느 필드였느냐에 따라 필요한 것이 다르다.
#
# data 는 감쌀 필요가 없다. parseUri 는 인텐트 URI 가 아닌 문자열을 받으면 그것을
# 그대로 data 로 하는 인텐트를 만들어 주므로, 값을 바깥 자리에 그냥 실으면 안쪽의
# getData() 가 우리 값을 읽는다. 굳이 감싸면 얻는 것 없이 형식 위험만 는다.
#
# action 과 type 은 다르다. 평문을 실으면 data 로만 들어가고 action/type 은 우리가
# 넣은 것이 아니게 되므로, 인텐트 URI 파라미터로 명시해야 한다.
_WRAPPER_BY_INNER_FIELD = {
    FIELD_DATA: PASSTHROUGH,
    FIELD_ACTION: UriWrapper("intent:#Intent;action=" + VALUE_SLOT + ";end", encode=True),
    FIELD_TYPE: UriWrapper("intent:#Intent;type=" + VALUE_SLOT + ";end", encode=True),
}


# intent: URI 는 extra 의 타입을 접두사로 구분한다. 문자열 extra 자리에 S. 대신 i. 를
# 쓰면 getIntExtra 가 기본값을 돌려주고 흐름이 조용히 죽는다.
_EXTRA_PREFIX_BY_TYPE = {
    "string": "S",
    "boolean": "B",
    "int": "i",
    "long": "l",
    "float": "f",
    "double": "d",
}


def build_uri_wrapper(inner_field, inner_key, inner_type=None):
    """parseUri 가 만든 인텐트의 어느 자리에서 읽히는지로 감싸기 방법을 정한다"""
    # extra 는 키가 있어야 자리를 특정할 수 있다.
    if inner_field == FIELD_EXTRA:
        if not inner_key:
            return None
        # 타입을 모르면 문자열로 본다. am 의 기본 동작과 같고, 우리 값 후보도
        # 타입 미상이면 문자열로 만든다.
        prefix = _EXTRA_PREFIX_BY_TYPE.get(inner_type or "string", "S")
        return UriWrapper(
            f"intent:#Intent;{prefix}.{inner_key}=" + VALUE_SLOT + ";end", encode=True)
    return _WRAPPER_BY_INNER_FIELD.get(inner_field)


# 파싱된 인텐트 '자체' 가 싱크로 흘러가는 경우(Case A). 앱이 값을 꺼내는 게 아니라
# startActivity(parseUri(우리문자열)) 처럼 인텐트를 통째로 던진다. 우리가 통제하는
# 것은 그 인텐트의 action 이고, 던질 때 나오는 기동 로그(START ... act=...)에 그대로
# 찍혀 IccPolicy 가 관측한다. 마커를 action 에 실으면 그 로그에서 마커가 잡힌다.
#
# 마커를 action 에 두는 이유: 기동 로그는 컴포넌트 해석 전, 던지는 시점에 찍히므로
# 인텐트가 아무 데도 안 붙어도 act= 는 남는다. 값 후보(평문 마커)를 그대로 넣던
# 지금 동작은 parseUri 가 그것을 data 로 하는 ACTION_VIEW 인텐트로 만들어, 무엇을
# 던졌는지 우리가 통제하지 못한 채 우연히 관측되기만 했다.
WHOLE_INTENT_WRAPPER = UriWrapper(
    "intent:#Intent;action=" + VALUE_SLOT + ";end", encode=True)


def is_known_origin_kind(origin_kind):
    """정적이 준 origin_kind 가 우리 표에 있는 종류인지 판별한다"""
    return origin_kind in _BY_ORIGIN_KIND


def resolve_origin(origin_kind):
    """소스의 origin_kind 로 주입 가능성과 감싸기 형태를 정한다"""
    # 표에 없는 종류는 막지 않는다. 우리 표가 낡았을 뿐 값이 통할 수도 있어서다.
    # 호출한 쪽이 is_known_origin_kind() 로 따로 알람을 남긴다.
    return _BY_ORIGIN_KIND.get(origin_kind, _DIRECT)
