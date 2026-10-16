"""2단계(인자 조립)가 만들어 3단계(실행 검증)에 넘기는 계약 자료구조.

1단계의 Candidate 는 여기서 수정되지 않는다. TestCase 는 candidate_id 로 역참조만
하고, 값 생성 근거는 bindings 에 남겨 결과에서 "왜 이 값을 넣었나"가 역추적되게 한다.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


# ---------------------------------------------------------------------------
# 값의 출처 - 결과 보고의 근거이자 신뢰도 가중치의 키
# ---------------------------------------------------------------------------
ORIGIN_EXACT = "exact"                  # 정적 분석기가 준 확정값 그대로
ORIGIN_DERIVED = "derived"              # 확정값에서 연산자에 맞게 유도 (not_equals 등)
ORIGIN_SINK_SHAPE = "sink_shape"        # 싱크가 알려준 값의 형태
ORIGIN_POOL_COMPONENT = "pool_component"  # 대상 컴포넌트가 선언/사용하는 값
ORIGIN_POOL_CLASS = "pool_class"        # 대상 클래스가 참조하는 문자열
ORIGIN_POOL_GENERIC = "pool_generic"    # APK 어딘가에서 관측된 값
ORIGIN_TYPE_DEFAULT = "type_default"    # 타입별 기본 후보
ORIGIN_MARKER = "marker"                # 제약이 없어 마커만 넣은 값
ORIGIN_UNGUARDED_MARKER = "unguarded_marker"  # 정적이 가드를 못 찾은 자리의 첫 시도


# 가드를 통과할 가능성. 후보 점수는 이 값들의 곱이다.
# 곱을 쓰는 이유: 모든 가드가 동시에 만족되어야 싱크에 도달하므로, 합을 쓰면
# 인자가 많을수록 점수가 올라가는 반대 방향의 편향이 생긴다.
WEIGHT_BY_ORIGIN = {
    ORIGIN_EXACT: 1.0,
    ORIGIN_MARKER: 1.0,
    ORIGIN_DERIVED: 1.0,
    # 정적이 "이 필드엔 가드가 없다" 고 했지만 안 믿고 값 풀까지 도는 경우.
    # 그 말이 맞으면 마커 한 발로 끝나므로 제일 앞에 두고, 틀렸으면 뒤의 값 후보로
    # 자연히 내려간다. 싱크 형태(0.9)보다 앞이어야 첫 발이 마커가 된다.
    ORIGIN_UNGUARDED_MARKER: 0.95,
    ORIGIN_SINK_SHAPE: 0.9,
    ORIGIN_POOL_COMPONENT: 0.7,
    ORIGIN_POOL_CLASS: 0.5,
    ORIGIN_POOL_GENERIC: 0.25,
    ORIGIN_TYPE_DEFAULT: 0.15,
}

# 레지스터 되짚기에 실패해 근사로 얻은 풀 값에 곱하는 감점
WEIGHT_PENALTY_UNCONFIDENT = 0.8


# ---------------------------------------------------------------------------
# 귀속 방식 - 3단계가 실행 결과를 어느 케이스에 붙일지 정하는 방법
# ---------------------------------------------------------------------------
ATTRIBUTION_MARKER = "marker"   # 값에 심은 마커로 귀속. 케이스를 병렬 실행해도 된다
ATTRIBUTION_TIMING = "timing"   # 실행 시각 전후로 귀속. 순차 실행해야 한다


@dataclass(frozen=True)
class Binding:
    """이 실행에서 어떤 필드에 어떤 값을 왜 넣었는지"""

    field: str
    key: str | None
    adb_flag: str
    value: Any                  # None 이면 '널이어야 함' (extra 는 --esn 으로 표현)
    origin: str                 # ORIGIN_* 중 하나
    weight: float               # 이 값이 가드를 통과할 가능성
    marker_part: str | None     # 이 값에 심은 서브마커. 안 심었으면 None
    # 소스 wrapper 로 감싸기 전의 값. 감싸지 않았으면 value 와 같다.
    # 싱크 정책이 "이게 파일 경로인가 content:// 인가" 를 값의 생김새로 판단하는데,
    # 감싼 값을 보면 전부 intent: 로 보여 카나리 감시와 신뢰도 판정이 통째로 망가진다.
    payload: Any = None

    def to_dict(self):
        """직렬화를 위해 dict 로 변환한다"""
        return {
            "field": self.field,
            "key": self.key,
            "adb_flag": self.adb_flag,
            "value": self.value,
            "origin": self.origin,
            "weight": self.weight,
            "marker_part": self.marker_part,
            "payload": self.payload,
        }

    @staticmethod
    def from_dict(raw):
        """dict(raw) 에서 Binding 을 복원한다"""
        return Binding(
            field=raw["field"],
            key=raw.get("key"),
            adb_flag=raw["adb_flag"],
            value=raw.get("value"),
            origin=raw["origin"],
            weight=raw["weight"],
            marker_part=raw.get("marker_part"),
            payload=raw.get("payload", raw.get("value")),
        )


@dataclass(frozen=True)
class TestCase:
    """에뮬레이터에서 한 번 실행할 단위"""

    test_case_id: str
    candidate_id: str            # 역참조만. Candidate 는 수정하지 않는다
    variant_index: int           # 0 이 점수가 가장 높은 조합
    marker: str
    attribution: str             # ATTRIBUTION_* 중 하나
    argv: tuple[str, ...]        # 이스케이핑 전 인자 배열
    bindings: tuple[Binding, ...]
    confidence: float            # bindings 가중치의 곱
    duplicate_of: str | None = None   # 같은 커맨드가 앞서 있으면 그 test_case_id

    def is_runnable(self):
        """중복이 아니어서 실제로 실행해야 하는 케이스인지 판별한다"""
        return self.duplicate_of is None

    def to_dict(self):
        """직렬화를 위해 dict 로 변환한다"""
        return {
            "test_case_id": self.test_case_id,
            "candidate_id": self.candidate_id,
            "variant_index": self.variant_index,
            "marker": self.marker,
            "attribution": self.attribution,
            "argv": list(self.argv),
            "bindings": [item.to_dict() for item in self.bindings],
            "confidence": self.confidence,
            "duplicate_of": self.duplicate_of,
        }

    @staticmethod
    def from_dict(raw):
        """dict(raw) 에서 TestCase 를 복원한다"""
        return TestCase(
            test_case_id=raw["test_case_id"],
            candidate_id=raw["candidate_id"],
            variant_index=raw["variant_index"],
            marker=raw["marker"],
            attribution=raw["attribution"],
            argv=tuple(raw.get("argv", ())),
            bindings=tuple(Binding.from_dict(item) for item in raw.get("bindings", [])),
            confidence=raw["confidence"],
            duplicate_of=raw.get("duplicate_of"),
        )


@dataclass(frozen=True)
class SkippedCandidate:
    """2단계에서 값을 만들지 못해 실행 대상에서 빠진 후보"""

    candidate_id: str
    status: str                  # candidate_set 의 STATUS_* 어휘를 공유한다
    reasons: tuple               # candidate_set.Reason 목록

    def to_dict(self):
        """직렬화를 위해 dict 로 변환한다"""
        return {
            "candidate_id": self.candidate_id,
            "status": self.status,
            "reasons": [item.to_dict() for item in self.reasons],
        }

    @staticmethod
    def from_dict(raw):
        """dict(raw) 에서 SkippedCandidate 를 복원한다"""
        from src.dynamic.contracts.candidate_set import Reason

        return SkippedCandidate(
            candidate_id=raw["candidate_id"],
            status=raw["status"],
            reasons=tuple(Reason.from_dict(item) for item in raw.get("reasons", [])),
        )


@dataclass(frozen=True)
class TestCaseSet:
    """2단계의 산출물이자 3단계의 유일한 입력"""

    apk: str
    cases: tuple[TestCase, ...]
    skipped: tuple[SkippedCandidate, ...] = ()
    truncated_candidates: tuple[str, ...] = ()   # 상한에 걸려 조합이 잘린 후보

    def get_runnable(self):
        """중복을 뺀, 실제로 실행할 케이스만 추려서 돌려준다"""
        return tuple(item for item in self.cases if item.is_runnable())

    def get_by_candidate(self, candidate_id):
        """한 후보에서 나온 케이스를 variant 순서대로 돌려준다"""
        return tuple(item for item in self.cases if item.candidate_id == candidate_id)

    def get_sequential_only(self):
        """마커를 못 심어 순차 실행해야 하는 케이스만 돌려준다"""
        return tuple(
            item for item in self.cases
            if item.is_runnable() and item.attribution == ATTRIBUTION_TIMING
        )

    def to_dict(self):
        """CLI 검수용 JSON 으로 떨구기 위해 dict 로 변환한다"""
        return {
            "apk": self.apk,
            "cases": [item.to_dict() for item in self.cases],
            "skipped": [item.to_dict() for item in self.skipped],
            "truncated_candidates": list(self.truncated_candidates),
        }

    @staticmethod
    def from_dict(raw):
        """dict(raw) 에서 TestCaseSet 을 복원한다"""
        return TestCaseSet(
            apk=raw["apk"],
            cases=tuple(TestCase.from_dict(item) for item in raw.get("cases", [])),
            skipped=tuple(SkippedCandidate.from_dict(item) for item in raw.get("skipped", [])),
            truncated_candidates=tuple(raw.get("truncated_candidates", ())),
        )
