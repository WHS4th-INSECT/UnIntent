from __future__ import annotations

import contextlib
import hashlib
import json
import logging
import os
import re
import tempfile
from dataclasses import dataclass

SHAPE_ACTION = "action"
SHAPE_CATEGORY = "category"
SHAPE_URI = "uri"
SHAPE_PATH = "path"
SHAPE_MIME = "mime"
SHAPE_EXTRA_KEY = "extra_key"
SHAPE_PLAIN = "plain"


ORIGIN_MANIFEST_FILTER = "manifest_filter"
ORIGIN_DYNAMIC_FILTER = "dynamic_filter"
ORIGIN_EXTRA_KEY = "extra_key"
ORIGIN_INTENT_SETTER = "intent_setter"
ORIGIN_DEX_STRING = "dex_string"


MAX_STRING_LENGTH = 512
MIN_STRING_LENGTH = 1
MAX_STRINGS_PER_CLASS = 200


ANDROID_NS = "{http://schemas.android.com/apk/res/android}"


INTENT_FILTER_CLASS = "Landroid/content/IntentFilter;"
INTENT_CLASS = "Landroid/content/Intent;"

DYNAMIC_FILTER_METHODS = ("<init>", "addAction", "addCategory", "addDataScheme", "addDataType")
INTENT_SETTER_METHODS = ("setAction", "addCategory", "setType", "setPackage")


RE_TYPE_DESCRIPTOR = re.compile(r"^\[*L[\w/$\-]+;$")
RE_PRIMITIVE_ARRAY = re.compile(r"^\[+[BCDFIJSZ]$")
RE_METHOD_SIGNATURE = re.compile(r"^\(.*\)\[*[LBCDFIJSZV]")
RE_FORMAT_SPECIFIER = re.compile(r"%[-+ #0]*[\d.$]*[sdfxXoeEgGcbn]")
RE_CONTROL_CHAR = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")

RE_URI = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://")
RE_PATH = re.compile(r"^/[^\s:]*$")
RE_MIME = re.compile(r"^[\w.\-+*]+/[\w.\-+*]+$")
RE_ACTION_TAIL = re.compile(r"^[A-Z][A-Z0-9_]*$")
RE_IDENTIFIER = re.compile(r"^[a-zA-Z_][\w.$\-]{0,63}$")

_LOGGER = logging.getLogger(__name__)


def is_junk_string(value):
    """문자열(value)이 후보가 될 수 없는 명백한 쓰레기인지 판별한다"""
    if not isinstance(value, str):
        return True
    if any(0xD800 <= ord(character) <= 0xDFFF for character in value):
        return True
    if len(value) < MIN_STRING_LENGTH or len(value) > MAX_STRING_LENGTH:
        return True
    if not value.strip():
        return True
    if len(value) == 1 and not value.isalnum():
        return True
    if RE_CONTROL_CHAR.search(value):
        return True
    if RE_TYPE_DESCRIPTOR.match(value) or RE_PRIMITIVE_ARRAY.match(value):
        return True
    if RE_METHOD_SIGNATURE.match(value):
        return True
    return bool(RE_FORMAT_SPECIFIER.search(value))


def normalize_unicode_surrogates(value):
    """유효한 surrogate 쌍은 Unicode 문자로 합치고 단독 surrogate는 None으로 돌려준다"""
    if not isinstance(value, str):
        return None

    normalized = []
    index = 0
    while index < len(value):
        codepoint = ord(value[index])
        if 0xD800 <= codepoint <= 0xDBFF:
            if index + 1 >= len(value):
                return None
            low_surrogate = ord(value[index + 1])
            if not 0xDC00 <= low_surrogate <= 0xDFFF:
                return None
            normalized.append(
                chr(0x10000 + ((codepoint - 0xD800) << 10) + (low_surrogate - 0xDC00))
            )
            index += 2
            continue
        if 0xDC00 <= codepoint <= 0xDFFF:
            return None
        normalized.append(value[index])
        index += 1
    return "".join(normalized)


def classify_shape(value):
    """문자열(value)이 어떤 인텐트 필드에 쓰일 수 있는 생김새인지 태그들을 돌려준다"""

    shapes = []

    if RE_URI.match(value):
        shapes.append(SHAPE_URI)
    elif RE_PATH.match(value):
        shapes.append(SHAPE_PATH)
    elif RE_MIME.match(value):
        shapes.append(SHAPE_MIME)

    if "." in value:
        tail = value.rsplit(".", 1)[-1]
        if ".category." in value or value.startswith("android.intent.category."):
            shapes.append(SHAPE_CATEGORY)
        elif RE_ACTION_TAIL.match(tail) or value.startswith("android.intent.action."):
            shapes.append(SHAPE_ACTION)

    if RE_IDENTIFIER.match(value):
        shapes.append(SHAPE_EXTRA_KEY)

    if not shapes:
        shapes.append(SHAPE_PLAIN)
    return tuple(shapes)


def normalize_class_name(name):
    """DEX 타입 이름(name)을 매니페스트와 같은 점 표기 클래스명으로 바꾼다"""
    if not name:
        return ""
    text = name.strip()
    if text.startswith("L") and text.endswith(";"):
        text = text[1:-1]
    return text.replace("/", ".")


def expand_component_name(name, package):
    """매니페스트의 상대 컴포넌트명(name)을 패키지(package)로 채워 완전한 이름으로 만든다"""
    if not name:
        return ""
    if name.startswith("."):
        return package + name
    if "." not in name:
        return f"{package}.{name}"
    return name


def parse_authority(uri):
    """content:// 같은 URI 문자열(uri)에서 authority 부분만 뽑는다"""
    match = RE_URI.match(uri)
    if not match:
        return None
    rest = uri[match.end() :]
    return rest.split("/", 1)[0] or None


def extract_string_operand(instruction):
    """const-string 명령어(instruction)에서 대상 레지스터와 문자열 값을 뽑는다"""
    from androguard.core.dex import Operand

    register = None
    value = None
    for operand in instruction.get_operands():
        if operand[0] == Operand.REGISTER:
            if register is None:
                register = operand[1]
            continue
        for part in operand[1:]:
            if isinstance(part, str):
                value = part
    return register, value


def extract_invoke_target(instruction):
    """invoke 명령어(instruction)에서 인자 레지스터와 호출 대상 클래스/메서드를 뽑는다"""
    from androguard.core.dex import Operand

    registers = []
    parts = []
    for operand in instruction.get_operands():
        if operand[0] == Operand.REGISTER:
            registers.append(operand[1])
            continue
        parts = [part for part in operand[1:] if isinstance(part, str)]
    class_name = parts[0] if len(parts) >= 1 else None
    method_name = parts[1] if len(parts) >= 2 else None
    return registers, class_name, method_name


def match_target_method(class_name, method_name):
    """호출 대상(class_name, method_name)이 표적 추출 대상인지 보고 출처 이름을 돌려준다"""
    if not class_name or not method_name:
        return None
    if class_name == INTENT_FILTER_CLASS and method_name in DYNAMIC_FILTER_METHODS:
        return ORIGIN_DYNAMIC_FILTER
    if class_name == INTENT_CLASS:
        if method_name.startswith("get") and method_name.endswith("Extra"):
            return ORIGIN_EXTRA_KEY
        if method_name in INTENT_SETTER_METHODS:
            return ORIGIN_INTENT_SETTER
    return None


def scan_method(instructions):
    """메서드 명령어(instructions)를 한 번 훑어 문자열 상수와 표적 호출의 인자를 모은다"""
    register_values = {}
    last_value = None
    strings = []
    hits = []

    for instruction in instructions:
        name = instruction.get_name()

        if name.startswith("const-string"):
            register, value = extract_string_operand(instruction)
            if value is not None:
                strings.append(value)
                last_value = value
                if register is not None:
                    register_values[register] = value
            continue

        if not name.startswith("invoke"):
            continue

        registers, class_name, method_name = extract_invoke_target(instruction)
        origin = match_target_method(class_name, method_name)
        if origin is None:
            continue

        matched = None
        for register in registers:
            if register in register_values:
                matched = register_values[register]
                break
        if matched is not None:
            hits.append((origin, matched, True))
        elif last_value is not None:
            hits.append((origin, last_value, False))

    return strings, hits


def extract_from_dex(apk):
    """APK(apk)의 모든 DEX 를 한 번 훑어 클래스별 문자열과 표적 추출 결과를 모은다"""
    from androguard.core.dex import DEX

    class_strings = {}
    dynamic_filters = {}
    extra_keys = {}
    setter_values = {}
    confidence = {}

    for raw_dex in apk.get_all_dex():
        dex = DEX(raw_dex)
        for class_item in dex.get_classes():
            class_name = normalize_class_name(class_item.get_name())
            collected = class_strings.setdefault(class_name, [])

            for method in class_item.get_methods():
                if method.get_code() is None:
                    continue
                strings, hits = scan_method(method.get_instructions())

                for value in strings:
                    value = normalize_unicode_surrogates(value)
                    if value is None:
                        continue
                    if is_junk_string(value):
                        continue
                    if len(collected) >= MAX_STRINGS_PER_CLASS:
                        break
                    if value not in collected:
                        collected.append(value)

                for origin, value, confident in hits:
                    value = normalize_unicode_surrogates(value)
                    if value is None:
                        continue
                    if is_junk_string(value):
                        continue
                    bucket = {
                        ORIGIN_DYNAMIC_FILTER: dynamic_filters,
                        ORIGIN_EXTRA_KEY: extra_keys,
                        ORIGIN_INTENT_SETTER: setter_values,
                    }[origin]
                    values = bucket.setdefault(class_name, [])
                    if value not in values:
                        values.append(value)
                    key = (origin, value)
                    confidence[key] = confidence.get(key, False) or confident

    class_strings = {name: values for name, values in class_strings.items() if values}
    return class_strings, dynamic_filters, extra_keys, setter_values, confidence


def extract_manifest_filters(apk):
    """APK(apk)의 매니페스트에서 컴포넌트별 intent-filter 선언을 모은다"""
    package = apk.get_package()
    filters = {}

    for item_type, names in (
        ("activity", apk.get_activities()),
        ("service", apk.get_services()),
        ("receiver", apk.get_receivers()),
    ):
        for name in names:
            component = expand_component_name(name, package)
            found = apk.get_intent_filters(item_type, name) or {}
            filters[component] = {
                "action": list(found.get("action", [])),
                "category": list(found.get("category", [])),
                "scheme": [],
                "host": [],
                "path": [],
                "mime": [],
            }

    _merge_manifest_data_elements(apk, package, filters)
    return filters


def _merge_manifest_data_elements(apk, package, filters):
    """매니페스트 XML 을 훑어 intent-filter 의 data 요소를 filters 에 채워 넣는다"""
    root = apk.get_android_manifest_xml()
    if root is None:
        return

    data_attributes = (
        ("scheme", "scheme"),
        ("host", "host"),
        ("path", "path"),
        ("path", "pathPrefix"),
        ("path", "pathPattern"),
        ("mime", "mimeType"),
    )

    for item_type in ("activity", "service", "receiver"):
        for element in root.iter(item_type):
            name = element.get(ANDROID_NS + "name")
            if not name:
                continue
            component = expand_component_name(name, package)
            entry = filters.setdefault(
                component,
                {"action": [], "category": [], "scheme": [], "host": [], "path": [], "mime": []},
            )
            for data in element.iter("data"):
                for bucket, attribute in data_attributes:
                    value = data.get(ANDROID_NS + attribute)
                    if value and value not in entry[bucket]:
                        entry[bucket].append(value)


def extract_provider_authorities(apk):
    """APK(apk)의 매니페스트에서 ContentProvider 주소 목록을 모은다"""
    root = apk.get_android_manifest_xml()
    if root is None:
        return ()
    authorities = []
    for element in root.iter("provider"):
        declared = element.get(ANDROID_NS + "authorities")
        if not declared:
            continue
        for authority in declared.split(";"):
            authority = authority.strip()
            if authority and authority not in authorities:
                authorities.append(authority)
    return tuple(authorities)


@dataclass(frozen=True)
class PooledValue:
    """APK 에서 뽑은 상수 하나와 그 출처 정보"""

    value: str
    shapes: tuple[str, ...]
    origin: str
    owners: tuple[str, ...]
    confident: bool = True

    def to_dict(self):
        """직렬화를 위해 dict 로 변환한다"""
        return {
            "value": self.value,
            "shapes": list(self.shapes),
            "origin": self.origin,
            "owners": list(self.owners),
            "confident": self.confident,
        }

    @staticmethod
    def from_dict(raw):
        """dict(raw) 에서 PooledValue 를 복원한다"""
        return PooledValue(
            value=raw["value"],
            shapes=tuple(raw.get("shapes", ())),
            origin=raw["origin"],
            owners=tuple(raw.get("owners", ())),
            confident=raw.get("confident", True),
        )


@dataclass(frozen=True)
class ValuePool:
    """APK 한 개에서 뽑은 인텐트 인자 후보 재료"""
    package: str
    apk_id: str
    manifest_filters: dict
    provider_authorities: tuple
    dynamic_filters: dict
    extra_keys: dict
    class_strings: dict
    all_values: tuple

    def get_component_filters(self, component):
        """컴포넌트명(component)의 매니페스트 intent-filter 선언을 돌려준다"""
        return self.manifest_filters.get(component, {})

    def get_class_strings(self, class_name):
        """클래스명(class_name)이 참조하는 문자열 목록을 돌려준다"""
        return tuple(self.class_strings.get(class_name, ()))

    def get_extra_keys(self, class_name):
        """클래스명(class_name)이 읽는 extra 키 목록을 돌려준다"""
        return tuple(self.extra_keys.get(class_name, ()))

    def get_dynamic_actions(self, class_name):
        """클래스명(class_name)이 코드에서 등록한 action 목록을 돌려준다"""
        return tuple(self.dynamic_filters.get(class_name, ()))

    def to_dict(self):
        """직렬화를 위해 dict 로 변환한다"""
        return {
            "package": self.package,
            "apk_id": self.apk_id,
            "manifest_filters": self.manifest_filters,
            "provider_authorities": list(self.provider_authorities),
            "dynamic_filters": self.dynamic_filters,
            "extra_keys": self.extra_keys,
            "class_strings": self.class_strings,
            "all_values": [item.to_dict() for item in self.all_values],
        }

    @staticmethod
    def from_dict(raw):
        """dict(raw) 에서 ValuePool 을 복원한다"""
        return ValuePool(
            package=raw["package"],
            apk_id=raw["apk_id"],
            manifest_filters=raw.get("manifest_filters", {}),
            provider_authorities=tuple(raw.get("provider_authorities", ())),
            dynamic_filters=raw.get("dynamic_filters", {}),
            extra_keys=raw.get("extra_keys", {}),
            class_strings=raw.get("class_strings", {}),
            all_values=tuple(PooledValue.from_dict(item) for item in raw.get("all_values", [])),
        )


def build_all_values(
    manifest_filters,
    dynamic_filters,
    extra_keys,
    setter_values,
    class_strings,
    provider_authorities,
    confidence,
):
    """출처별 수집 결과를 합쳐 중복 없는 전역 후보 목록을 만든다"""
    priority = {
        ORIGIN_MANIFEST_FILTER: 4,
        ORIGIN_DYNAMIC_FILTER: 3,
        ORIGIN_EXTRA_KEY: 3,
        ORIGIN_INTENT_SETTER: 2,
        ORIGIN_DEX_STRING: 1,
    }
    merged = {}

    def add(value, origin, owner, confident=True):
        """값(value)을 출처(origin)와 소유자(owner)와 함께 병합 사전에 넣는다"""
        if is_junk_string(value):
            return
        current = merged.get(value)
        if current is None:
            merged[value] = {"origin": origin, "owners": [], "confident": confident}
            current = merged[value]
        elif priority[origin] > priority[current["origin"]]:
            current["origin"] = origin
            current["confident"] = confident
        if owner and owner not in current["owners"]:
            current["owners"].append(owner)

    for component, entry in manifest_filters.items():
        for values in entry.values():
            for value in values:
                add(value, ORIGIN_MANIFEST_FILTER, component)

    for authority in provider_authorities:
        add(authority, ORIGIN_MANIFEST_FILTER, None)

    for bucket, origin in (
        (dynamic_filters, ORIGIN_DYNAMIC_FILTER),
        (extra_keys, ORIGIN_EXTRA_KEY),
        (setter_values, ORIGIN_INTENT_SETTER),
    ):
        for class_name, values in bucket.items():
            for value in values:
                add(value, origin, class_name, confidence.get((origin, value), True))

    for class_name, values in class_strings.items():
        for value in values:
            add(value, ORIGIN_DEX_STRING, class_name)

    return tuple(
        PooledValue(
            value=value,
            shapes=classify_shape(value),
            origin=entry["origin"],
            owners=tuple(entry["owners"]),
            confident=entry["confident"],
        )
        for value, entry in merged.items()
    )


def read_package_name(apk_path):
    """APK 의 매니페스트만 읽어 패키지명을 얻는다"""
    from androguard.core.apk import APK

    return APK(apk_path).get_package()


def empty_value_pool(package=""):
    """재료 없이 빈 값 풀을 만든다"""
    return ValuePool(
        package=package,
        apk_id="",
        manifest_filters={},
        provider_authorities=(),
        dynamic_filters={},
        extra_keys={},
        class_strings={},
        all_values=(),
    )


def compute_apk_id(apk_path):
    """APK 파일(apk_path)의 sha256 을 계산해 캐시 키로 쓸 문자열을 돌려준다"""
    digest = hashlib.sha256()
    with open(apk_path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_value_pool(apk_path):
    """APK 파일(apk_path)을 읽어 ValuePool 을 만든다"""
    from androguard.core.apk import APK

    apk = APK(apk_path)
    manifest_filters = extract_manifest_filters(apk)
    provider_authorities = extract_provider_authorities(apk)
    class_strings, dynamic_filters, extra_keys, setter_values, confidence = extract_from_dex(apk)

    all_values = build_all_values(
        manifest_filters,
        dynamic_filters,
        extra_keys,
        setter_values,
        class_strings,
        provider_authorities,
        confidence,
    )
    return ValuePool(
        package=apk.get_package(),
        apk_id=compute_apk_id(apk_path),
        manifest_filters=manifest_filters,
        provider_authorities=provider_authorities,
        dynamic_filters=dynamic_filters,
        extra_keys=extra_keys,
        class_strings=class_strings,
        all_values=all_values,
    )


def save_value_pool(pool, path):
    """ValuePool(pool)을 JSON 파일(path)로 저장한다"""
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, exist_ok=True)
    file_descriptor, temporary_path = tempfile.mkstemp(
        prefix=f".{os.path.basename(path)}.",
        suffix=".tmp",
        dir=directory,
    )
    try:
        with os.fdopen(file_descriptor, "w", encoding="utf-8") as handle:
            json.dump(pool.to_dict(), handle, ensure_ascii=True, indent=2)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, path)
        temporary_path = None
    finally:
        if temporary_path is not None:
            with contextlib.suppress(FileNotFoundError):
                os.unlink(temporary_path)


def load_value_pool(path):
    """JSON 파일(path)에서 ValuePool 을 읽어 온다"""
    with open(path, encoding="utf-8") as handle:
        return ValuePool.from_dict(json.load(handle))


def load_or_build(apk_path, cache_dir, external_pool_path=None):
    """외부 풀 파일, 캐시, 직접 생성 순으로 ValuePool 을 확보한다"""
    if external_pool_path and os.path.exists(external_pool_path):
        return load_value_pool(external_pool_path)

    apk_id = compute_apk_id(apk_path)
    cache_path = os.path.join(cache_dir, f"{apk_id}.json")
    if os.path.exists(cache_path):
        try:
            cached_pool = load_value_pool(cache_path)
        except (
            json.JSONDecodeError,
            UnicodeDecodeError,
            KeyError,
            TypeError,
            AttributeError,
        ) as exc:
            _LOGGER.warning("Ignoring invalid value-pool cache %s: %s", cache_path, exc)
        else:
            if cached_pool.apk_id == apk_id:
                return cached_pool
            _LOGGER.warning(
                "Ignoring value-pool cache %s because its APK id does not match",
                cache_path,
            )

    pool = build_value_pool(apk_path)
    save_value_pool(pool, cache_path)
    return pool