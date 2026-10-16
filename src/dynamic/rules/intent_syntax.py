"""인텐트 필드/타입을 adb am 문법으로 옮길 수 있는지 판별하고 플래그를 결정한다.

싱크 종류와 무관한 규칙만 담는다. getParcelableExtra 가 am 으로 표현 불가능한 것은
그 흐름이 WEBVIEW_LOAD 로 가든 FILE_STREAM_OPEN 으로 가든 똑같기 때문이다.
1단계의 표현 가능성 필터와 2단계의 커맨드 조립이 이 파일을 함께 쓴다.
"""

from __future__ import annotations

from dataclasses import dataclass

from src.dynamic.contracts.candidate_set import (
    FIELD_ACTION,
    FIELD_CATEGORY,
    FIELD_COMPONENT,
    FIELD_DATA,
    FIELD_EXTRA,
    FIELD_TYPE,
)


# ---------------------------------------------------------------------------
# 표현 불가 사유 코드
# ---------------------------------------------------------------------------
UNSUPPORTED_NESTED_INTENT = "adb_nested_intent"        # Intent 를 extra 로 요구
UNSUPPORTED_PARCELABLE = "adb_parcelable_extra"        # 임의 Parcelable
UNSUPPORTED_SERIALIZABLE = "adb_serializable_extra"
UNSUPPORTED_BUNDLE = "adb_bundle_extra"
UNSUPPORTED_BINARY_ARRAY = "adb_binary_array_extra"    # byte[] / char[] / short[]
UNSUPPORTED_CLIP_DATA = "adb_clip_data"
UNSUPPORTED_UNKNOWN_FIELD = "adb_unknown_field"
UNSUPPORTED_TYPE_UNKNOWN = "adb_type_unknown"          # 타입을 못 알아냄 (연성 사유)
UNSUPPORTED_COMPONENT_TYPE = "adb_unknown_component_type"  # 표에 없는 컴포넌트 종류
UNSUPPORTED_PROVIDER_COMPONENT = "adb_provider_entry"      # provider - am 으로 부를 수단이 없다

# 연성 사유는 2단계에서 api 시그니처로 타입을 되살릴 여지가 있으므로
# 1단계에서 바로 잘라내지 않고 통과시키는 선택이 가능하다.
SOFT_UNSUPPORTED_REASONS = (UNSUPPORTED_TYPE_UNKNOWN,)


# ---------------------------------------------------------------------------
# extra 가 아닌 필드의 플래그
# ---------------------------------------------------------------------------
NON_EXTRA_FLAGS = {
    FIELD_ACTION: "-a",
    FIELD_DATA: "-d",
    FIELD_TYPE: "-t",
    FIELD_CATEGORY: "-c",
    FIELD_COMPONENT: "-n",
}


# ---------------------------------------------------------------------------
# extra 타입별 플래그
# ---------------------------------------------------------------------------
EXTRA_FLAGS_BY_TYPE = {
    "string": "--es",
    "null_string": "--esn",
    "boolean": "--ez",
    "int": "--ei",
    "long": "--el",
    "float": "--ef",
    "double": "--ed",
    "uri": "--eu",
    "component": "--ecn",
    "int_array": "--eia",
    "int_list": "--eial",
    "long_array": "--ela",
    "long_list": "--elal",
    "float_array": "--efa",
    "float_list": "--efal",
    "double_array": "--eda",
    "double_list": "--edal",
    "string_array": "--esa",
    "string_list": "--esal",
}


# ---------------------------------------------------------------------------
# Intent getter API -> 값 타입
# 표현 가능한 API 는 타입을, 불가능한 API 는 사유 코드를 값으로 갖는다.
# ---------------------------------------------------------------------------
SUPPORTED_EXTRA_APIS = {
    "getStringExtra": "string",
    "getCharSequenceExtra": "string",   # putExtra(String, String) 로 들어간 값을 읽는다
    "getBooleanExtra": "boolean",
    "getIntExtra": "int",
    "getLongExtra": "long",
    "getFloatExtra": "float",
    "getDoubleExtra": "double",
    "getIntArrayExtra": "int_array",
    "getIntegerArrayListExtra": "int_list",
    "getLongArrayExtra": "long_array",
    "getFloatArrayExtra": "float_array",
    "getDoubleArrayExtra": "double_array",
    "getStringArrayExtra": "string_array",
    "getStringArrayListExtra": "string_list",
    "getCharSequenceArrayListExtra": "string_list",
}

UNSUPPORTED_EXTRA_APIS = {
    "getParcelableExtra": UNSUPPORTED_PARCELABLE,
    "getParcelableArrayExtra": UNSUPPORTED_PARCELABLE,
    "getParcelableArrayListExtra": UNSUPPORTED_PARCELABLE,
    "getSerializableExtra": UNSUPPORTED_SERIALIZABLE,
    "getBundleExtra": UNSUPPORTED_BUNDLE,
    "getExtras": UNSUPPORTED_BUNDLE,
    "getByteExtra": UNSUPPORTED_BINARY_ARRAY,
    "getByteArrayExtra": UNSUPPORTED_BINARY_ARRAY,
    "getShortExtra": UNSUPPORTED_BINARY_ARRAY,
    "getShortArrayExtra": UNSUPPORTED_BINARY_ARRAY,
    "getCharExtra": UNSUPPORTED_BINARY_ARRAY,
    "getCharArrayExtra": UNSUPPORTED_BINARY_ARRAY,
    "getClipData": UNSUPPORTED_CLIP_DATA,
    "getExtra": UNSUPPORTED_TYPE_UNKNOWN,  # 반환 타입이 Object 라 정적으로 알 수 없다
}

# Intent 를 extra 로 꺼내는 경우만 따로 잡아낸다. Nested Intent 는 연구상 별도 집계 대상이다.
NESTED_INTENT_TYPE_HINTS = ("intent", "android.content.intent", "landroid/content/intent;")


# ---------------------------------------------------------------------------
# extra 가 아닌 인텐트 필드를 꺼내는 getter -> 값 타입
# ---------------------------------------------------------------------------
NON_EXTRA_GETTERS = {
    "getAction": "string",
    "getType": "string",
    "getScheme": "string",
    "getPackage": "string",
    "getDataString": "string",
    "getData": "uri",
    "getComponent": "component",
    "getCategories": "string_list",
    "getFlags": "int",
}

# 원시값을 돌려주는 타입. 조건 레지스터에 담겼을 때 널 검사가 아니라 값 비교다.
PRIMITIVE_VALUE_TYPES = ("boolean", "int", "long", "float", "double")


def is_source_getter(api):
    """이 API 가 인텐트에서 값을 꺼내는 getter 인지 판별한다"""
    # 비교 API 자리에 이런 것이 오면 그건 비교가 아니다. 조건 레지스터를 만든 명령을
    # 되짚다가 소스 getter 까지 간 것이고, 딸려온 상수는 비교 대상이 아니라 extra 키다.
    method = extract_method_name(api)
    return (method in SUPPORTED_EXTRA_APIS
            or method in UNSUPPORTED_EXTRA_APIS
            or method in NON_EXTRA_GETTERS)


def value_type_of_getter(api):
    """소스 getter 가 돌려주는 값의 타입을 얻고 모르면 None 을 돌려준다"""
    method = extract_method_name(api)
    if method in SUPPORTED_EXTRA_APIS:
        return SUPPORTED_EXTRA_APIS[method]
    return NON_EXTRA_GETTERS.get(method)


# ---------------------------------------------------------------------------
# 컴포넌트 종류 -> am 서브커맨드
# start-service 는 API 26 미만에서 startservice 다. 대상 API 레벨이 낮으면 이 표만 바꾸면 된다.
# ---------------------------------------------------------------------------
TRIGGER_VERBS = {
    "activity": "start",
    "service": "start-service",
    "receiver": "broadcast",
}

FOREGROUND_SERVICE_VERB = "start-foreground-service"

# 컴포넌트 종류 표기는 매니페스트 태그, 정적 분석기, 사람이 쓴 JSON 마다 다르다.
# 서브커맨드가 같은 표기는 여기서 흡수한다. activity-alias 는 매니페스트상 별도 태그지만
# 별칭 이름 그대로 `am start -n` 으로 띄워지므로 activity 와 같게 본다.
# 매니페스트에는 있지만 am 으로 부를 수단이 없는 종류. '처음 보는 것' 과 구분해야
# "표를 늘리면 되는 문제" 와 "adb 로는 원래 안 되는 문제" 가 한 사유로 뭉치지 않는다.
UNINVOKABLE_COMPONENT_TYPES = {
    "provider": UNSUPPORTED_PROVIDER_COMPONENT,
    "contentprovider": UNSUPPORTED_PROVIDER_COMPONENT,
}

COMPONENT_TYPE_ALIASES = {
    "broadcast_receiver": "receiver",
    "broadcastreceiver": "receiver",
    "broadcast-receiver": "receiver",
    "activity_alias": "activity",
    "activity-alias": "activity",
    "activityalias": "activity",
}


@dataclass(frozen=True)
class FlagResolution:
    """하나의 입력을 adb am 플래그로 옮긴 결과"""

    flag: str | None      # 표현 가능하면 플래그 문자열, 아니면 None
    value_type: str | None  # EXTRA_FLAGS_BY_TYPE 의 키
    reason: str | None    # 표현 불가일 때의 사유 코드
    is_hard: bool = True  # 연성 사유(타입 미상)면 False

    def is_supported(self):
        """이 입력이 adb am 문법으로 표현 가능한지 판별한다"""
        return self.flag is not None


def extract_method_name(api):
    """API 시그니처 문자열(api)에서 메서드 이름만 뽑아낸다"""
    if not api:
        return ""
    head = api.split("(")[0]
    return head.split(".")[-1].strip()


def is_nested_intent(api, declared_type):
    """API(api)와 선언 타입(declared_type)이 Intent 를 extra 로 요구하는지 판별한다"""
    method = extract_method_name(api)
    if not method.startswith("getParcelable"):
        return False
    if not declared_type:
        return False
    return declared_type.strip().lower() in NESTED_INTENT_TYPE_HINTS


def normalize_value_type(declared_type):
    """정적 분석기의 타입 문자열(declared_type)을 내부 타입 어휘로 정규화한다"""
    if not declared_type:
        return None
    name = declared_type.strip().lower()
    aliases = {
        "java.lang.string": "string",
        "str": "string",
        "charsequence": "string",
        "bool": "boolean",
        "integer": "int",
        "android.net.uri": "uri",
        "android.content.componentname": "component",
    }
    name = aliases.get(name, name)
    return name if name in EXTRA_FLAGS_BY_TYPE else name


def resolve_adb_flag(field, api, declared_type):
    """인텐트 필드(field), API(api), 선언 타입(declared_type)으로 am 플래그를 결정한다"""
    if field in NON_EXTRA_FLAGS:
        return FlagResolution(flag=NON_EXTRA_FLAGS[field], value_type="string", reason=None)

    if field != FIELD_EXTRA:
        return FlagResolution(
            flag=None, value_type=None, reason=UNSUPPORTED_UNKNOWN_FIELD, is_hard=True
        )

    method = extract_method_name(api)

    if is_nested_intent(api, declared_type):
        return FlagResolution(
            flag=None, value_type=None, reason=UNSUPPORTED_NESTED_INTENT, is_hard=True
        )

    if method in UNSUPPORTED_EXTRA_APIS:
        reason = UNSUPPORTED_EXTRA_APIS[method]
        return FlagResolution(
            flag=None,
            value_type=None,
            reason=reason,
            is_hard=reason not in SOFT_UNSUPPORTED_REASONS,
        )

    if method in SUPPORTED_EXTRA_APIS:
        value_type = SUPPORTED_EXTRA_APIS[method]
        return FlagResolution(flag=EXTRA_FLAGS_BY_TYPE[value_type], value_type=value_type, reason=None)

    # API 를 못 알아본 경우 선언 타입으로 한 번 더 시도한다.
    value_type = normalize_value_type(declared_type)
    if value_type in EXTRA_FLAGS_BY_TYPE:
        return FlagResolution(flag=EXTRA_FLAGS_BY_TYPE[value_type], value_type=value_type, reason=None)

    return FlagResolution(
        flag=None, value_type=None, reason=UNSUPPORTED_TYPE_UNKNOWN, is_hard=False
    )


def normalize_component_type(component_type):
    """컴포넌트 종류 표기(component_type)를 TRIGGER_VERBS 의 어휘로 정규화한다"""
    # 표기만 다른 것은 여기서 흡수하고, 정말 모르는 것은 정규화한 이름 그대로 흘려보내
    # 호출한 쪽이 '표에 없다'로 판단하게 둔다.
    if not isinstance(component_type, str):
        return ""
    name = component_type.strip().lower()
    return COMPONENT_TYPE_ALIASES.get(name, name)


def unsupported_component_reason(component_type):
    """이 컴포넌트 종류를 am 으로 못 띄우는 사유 코드를 돌려준다"""
    # 띄울 수 있으면 None 이다. 못 띄우면 '원래 안 되는 것' 과 '표에 없는 것' 을 가른다.
    if resolve_trigger_verb(component_type) is not None:
        return None
    name = normalize_component_type(component_type)
    return UNINVOKABLE_COMPONENT_TYPES.get(name, UNSUPPORTED_COMPONENT_TYPE)


def resolve_trigger_verb(component_type, use_foreground_service=False):
    """컴포넌트 종류(component_type)로 am 서브커맨드를 결정하고 모르면 None 을 돌려준다"""
    name = normalize_component_type(component_type)
    if name == "service" and use_foreground_service:
        return FOREGROUND_SERVICE_VERB
    return TRIGGER_VERBS.get(name)


def build_permission_setup(package, permission):
    """진입점 권한(permission)을 셸에서 쥐기 위한 pm grant 명령 목록을 만든다"""
    # normal 수준 권한은 grant 가 필요 없고 signature 수준은 grant 로 얻을 수 없다.
    # 정적 분석기가 '셸이 획득 가능'한 것만 넘겨준다는 전제 아래 단순 변환만 한다.
    if not permission:
        return ()
    return (f"pm grant {package} {permission}",)
