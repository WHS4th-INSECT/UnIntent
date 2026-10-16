"""수집된 문자열만 받아 케이스 하나의 판정을 내리는 순수 함수들.

adb 실행은 여기서 하지 않는다. device 모듈이 긁어온 logcat, am 출력, 오라클 채널
증거를 문자열로 받아 판정만 한다. 그래야 에뮬레이터 없이 가짜 문자열로 규칙을
검증할 수 있다.

여기서 다루지 않는 것: 환경 봉쇄 검증(경로 화이트리스트, 네트워크 불변식)은 실행
직전에 실제 상태를 확인하는 일이라 execution/setup 모듈 몫이다. 판정은 이미 벌어진
일을 해석할 뿐이다.
"""

from __future__ import annotations

import re

from dataclasses import dataclass

from src.dynamic.contracts.run_result import (
    VERDICT_BLOCKED,
    VERDICT_CRASHED,
    VERDICT_INCONCLUSIVE,
    VERDICT_NOT_REACHED,
    VERDICT_REACHED,
)
from src.dynamic.contracts.test_case_set import ATTRIBUTION_MARKER, ATTRIBUTION_TIMING


# ---------------------------------------------------------------------------
# 판별 신호
#
# 주의: 아래 문자열들은 안드로이드 API 레벨마다 문구가 다를 수 있다. 실제 대상
# 에뮬레이터에서 한 번 확인하고 맞춰야 한다. 여기 값은 널리 쓰이는 형태를 모은 것이다.
# ---------------------------------------------------------------------------

# 앱이 치명적으로 종료된 신호. 반드시 대상 패키지와 함께 나타날 때만 crash 로 본다.
# 에뮬레이터에는 상시 다른 프로세스가 죽고 살므로, 패키지 한정 없이 매칭하면
# 무관한 크래시를 우리 탓으로 돌려 crashed 가 남발된다.
CRASH_SIGNALS = (
    "FATAL EXCEPTION",
    "ANR in",
    ">>> ",                 # tombstone 헤더의 프로세스 표시 (>>> <pkg> <<<)
    "signal 11 (SIGSEGV)",
    "signal 6 (SIGABRT)",
)

JAVA_CRASH_SIGNAL = "FATAL EXCEPTION"
JAVA_CRASH_PROCESS_PREFIX = "Process: "
JAVA_CRASH_WINDOW = 6

# am 자체가 인텐트 전달을 거부한 신호. "우리가 못 보냈다"는 확정된 사실이다.
BLOCKED_SIGNALS = (
    "java.lang.SecurityException",
    "Permission Denial",
    "requires permission",
    "Error type 3",              # 컴포넌트를 찾을 수 없음
    "Activity not started",
    "Error: Activity class",
    "does not exist",
    "Unable to find",
    "not exported",
)

# am 이 정상 처리했다는 신호. 이게 보이면 최소한 프레임워크까지는 도달했다.
AM_SUCCESS_SIGNALS = (
    "Broadcast completed",
    "Starting: Intent",
    "Starting service",
)


# ---------------------------------------------------------------------------
# 증거 등급 - 마커가 거기 있다는 것이 무엇을 뜻하는가
# ---------------------------------------------------------------------------
GRADE_ARTIFACT = "artifact"   # 그 API 가 실제로 불려야만 생기는 흔적
GRADE_ECHO = "echo"           # 값이 문자열로 찍히기만 한 것. 앱이 그냥 로그했을 수도 있다

# 파일이 생겼다거나 provider 조회가 실패했다는 것은 싱크가 불렸다는 뜻이고, 우리 값이
# 그 인자로 쓰였다는 뜻이기도 하다. 반면 logcat 에 값이 그냥 찍힌 것은 누가 찍었는지
# 알 수 없다. 둘을 같은 증거로 다루면 reached 가 과대 집계된다.


@dataclass(frozen=True)
class ChannelEvidence:
    """오라클 채널 하나가 수집한 텍스트. readable=False 면 채널을 못 읽은 것이다"""

    channel: str            # sink_policy 의 CHANNEL_* 값
    text: str = ""          # 채널이 관측한 내용 (로그 줄, 파일 목록 등)
    readable: bool = True    # 채널 자체를 읽지 못했으면 False (관측 불능과 부재를 구분)
    grade: str = GRADE_ARTIFACT


@dataclass(frozen=True)
class Judgement:
    """판정 결과와 그 근거"""

    verdict: str
    detail: str = ""            # 왜 그렇게 판정했는지 한 줄
    matched_markers: tuple = ()  # reached 일 때 증거에서 찾은 서브마커들
    evidence_grade: str = ""     # 그 증거가 artifact 였나 echo 였나


# ---------------------------------------------------------------------------
# 개별 판별 - 전부 순수
# ---------------------------------------------------------------------------
def contains_any(text, signals):
    """텍스트(text)에 신호 문자열(signals) 중 하나라도 들어 있는지 판별한다"""
    if not text:
        return None
    for signal in signals:
        if signal in text:
            return signal
    return None

def mentions_package(line, package):
    """줄(line)에 패키지 이름이 온전한 이름으로 들어 있는지 판별한다"""
    return re.search(re.escape(package) + r"(?![\w.])", line) is not None

def detect_crash(logcat_text, package):
    """시간창 logcat(logcat_text)에서 대상 패키지의 치명적 종료를 찾는다"""
    if not logcat_text or not package:
        return None
    lines = [line for line in logcat_text.splitlines() if not is_command_echo(line)]
    for index, line in enumerate(lines):
        signal = contains_any(line, CRASH_SIGNALS)
        if signal is None:
            continue
        if signal == JAVA_CRASH_SIGNAL:
            window = lines[index + 1:index + JAVA_CRASH_WINDOW]
            if any(JAVA_CRASH_PROCESS_PREFIX in item
                   and mentions_package(item.split(JAVA_CRASH_PROCESS_PREFIX, 1)[1], package)
                   for item in window):
                return signal
        elif mentions_package(line, package):
            return signal
    return None


def detect_blocked(am_output):
    """am 출력(am_output)에서 프레임워크가 전달을 거부한 신호를 찾는다"""
    return contains_any(am_output, BLOCKED_SIGNALS)


def find_marker_evidence(channel_evidence, sub_markers):
    """채널 증거들에서 서브마커(sub_markers)를 찾아 (채널, 마커, 등급) 을 모은다"""
    hits = []
    for evidence in channel_evidence:
        if not evidence.readable or not evidence.text:
            continue
        for marker in sub_markers:
            if marker and marker in evidence.text:
                hits.append((evidence.channel, marker, evidence.grade))
    return hits


def best_grade(hits):
    """찾은 증거들 중 가장 강한 등급을 고른다"""
    return GRADE_ARTIFACT if any(grade == GRADE_ARTIFACT for _, _, grade in hits) else GRADE_ECHO


# ---------------------------------------------------------------------------
# 우리 자신이 만든 로그 걸러내기
# ---------------------------------------------------------------------------
# 실행 순서가 `logcat -c` → `am` → `logcat -d` 라서, 우리가 던진 am 이 만든 기동
# 로그가 시간창 안에 들어온다. 그 줄에는 우리가 넣은 action 과 data 가 그대로 찍히므로
# 앱이 아무것도 하지 않아도 마커가 발견된다. 빼지 않으면 구조적 거짓 양성이 된다.
#
# 아래 문자열들은 API 레벨마다 다를 수 있어 상수로 분리했다. 실물 확인 항목이다.
LAUNCH_LOG_TAGS = ("ActivityManager:", "ActivityTaskManager:")
LAUNCH_LOG_SIGNALS = ("START u", "Starting service", "Sending broadcast")
SHELL_UID_MARKS = ("from uid 2000", "from uid=2000", "callingUid=2000")

RE_COMPONENT = re.compile(r"cmp=(?P<name>[^\s}]+)")
RE_ADBD_TAG = re.compile(r"\badbd\s*:")
RE_CALLER_UID = re.compile(r"(?:from uid|callingUid)[=\s]*(?P<uid>\d+)")

def component_forms(package, component):
    """로그에 찍힐 수 있는 컴포넌트 표기를 모두 만든다"""
    # ComponentName 은 클래스가 패키지로 시작하면 pkg/.Cls 로 줄여 찍는다.
    if not component:
        return ()
    forms = {component}
    if package:
        forms.add(f"{package}/{component}")
        if component.startswith(package + "."):
            forms.add(f"{package}/{component[len(package):]}")
    return tuple(forms)

def is_command_echo(line):
    """이 로그 줄이 adbd 가 우리 adb 명령을 받아 찍은 줄인지 판별한다"""
    return RE_ADBD_TAG.search(line) is not None


def is_own_launch_echo(line, own_forms):
    """이 로그 줄이 우리가 던진 am 이 만든 기동 로그인지 판별한다"""
    if not any(tag in line for tag in LAUNCH_LOG_TAGS):
        return False
    if not any(signal in line for signal in LAUNCH_LOG_SIGNALS):
        return False
    # 1순위 - 셸 UID 에서 온 기동이면 우리 것이다. 앱이 다시 던지면 앱 UID 로 찍힌다.
    if any(mark in line for mark in SHELL_UID_MARKS):
        return True
    # 2순위 - 대상 컴포넌트가 우리가 지정한 진입점이면 우리 것이다.
    found = RE_COMPONENT.search(line)
    return bool(found and found.group("name") in own_forms)


def strip_launch_echo(text, package="", component=""):
    """우리가 던진 adb 명령과 am 이 만든 기동 로그 줄을 빼고 돌려준다"""
    own_forms = component_forms(package, component)
    return "\n".join(line for line in (text or "").splitlines()
                      if not is_command_echo(line)
                      and not is_own_launch_echo(line, own_forms))

def split_app_launches(text, package, app_uid=None):
    """기동 로그(text)를 대상 앱이 던진 줄과 그 밖의 줄로 가른다"""
    own, other = [], []
    for line in (text or "").splitlines():
        if app_uid:
            found = RE_CALLER_UID.search(line)
            is_own = bool(found and found.group("uid") == str(app_uid))
        else:
            is_own = bool(package) and package in line
        (own if is_own else other).append(line)
    return "\n".join(own), "\n".join(other)

def split_by_patterns(text, patterns):
    """패턴에 걸린 줄과 나머지 줄로 텍스트를 가른다"""
    # 패턴이 없으면 전부 '나머지' 다. 이 싱크는 로그 모양으로 구분할 근거가 없다는 뜻이다.
    if not patterns:
        return "", text or ""
    matched, rest = [], []
    for line in (text or "").splitlines():
        (matched if any(pattern in line for pattern in patterns) else rest).append(line)
    return "\n".join(matched), "\n".join(rest)


def any_channel_readable(channel_evidence):
    """오라클 채널 중 하나라도 읽을 수 있었는지 판별한다"""
    return any(evidence.readable for evidence in channel_evidence)


def am_succeeded(am_output):
    """am 출력(am_output)이 정상 처리를 나타내는지 판별한다"""
    return contains_any(am_output, AM_SUCCESS_SIGNALS) is not None


# ---------------------------------------------------------------------------
# 종합 판정
# ---------------------------------------------------------------------------
def find_any_evidence(channel_evidence):
    """마커 없이, 채널이 싱크 고유의 흔적(artifact)을 관측했는지만 본다"""
    return [evidence.channel for evidence in channel_evidence
            if evidence.readable and evidence.grade == GRADE_ARTIFACT
            and evidence.text.strip()]


def judge(am_output, logcat_text, channel_evidence, sub_markers, package,
          attribution=ATTRIBUTION_MARKER):
    """수집된 문자열들로 케이스 하나의 판정을 내린다"""
    # 순서가 중요하다. 먼저 걸리는 것이 이긴다.
    #   1) 앱이 죽었으면 그 뒤의 "증거 없음"은 "안 흘렀다"가 아니라 "못 봤다"이다.
    #   2) am 이 거부했으면 그 뒤 증거는 이전 케이스의 잔재일 수 있다.
    #   3) 증거를 찾았으면 도달이다.
    #   4) 채널을 못 읽었으면 판정 불가.
    #   5) am 은 정상인데 증거가 없으면 미도달 (가드 미통과가 대부분).

    crash_signal = detect_crash(logcat_text, package)
    if crash_signal:
        return Judgement(VERDICT_CRASHED, f"crash 신호: {crash_signal!r}")

    blocked_signal = detect_blocked(am_output)
    if blocked_signal:
        return Judgement(VERDICT_BLOCKED, f"am 거부: {blocked_signal!r}")

    if attribution == ATTRIBUTION_TIMING:
        # 마커를 심을 자리가 없던 케이스다. 시간창 diff 에 뭐라도 잡히면 도달로 본다.
        channels = find_any_evidence(channel_evidence)
        if channels:
            return Judgement(VERDICT_REACHED,
                             f"시간창 증거 @ {', '.join(sorted(set(channels)))}",
                             evidence_grade=GRADE_ARTIFACT)
    elif sub_markers:
        hits = find_marker_evidence(channel_evidence, sub_markers)
        if hits:
            channels = sorted({channel for channel, _, _ in hits})
            markers = tuple(sorted({marker for _, marker, _ in hits}))
            grade = best_grade(hits)
            note = "" if grade == GRADE_ARTIFACT else " (에코 가능)"
            return Judgement(VERDICT_REACHED,
                             f"마커 발견 @ {', '.join(channels)}{note}",
                             matched_markers=markers, evidence_grade=grade)
    else:
        # 마커 귀속인데 심은 마커가 없다. 2단계가 attribution 을 잘못 붙인 경우라
        # 미도달로 단정하면 안 된다.
        return Judgement(VERDICT_INCONCLUSIVE, "마커 귀속인데 심은 마커가 없음")

    if not any_channel_readable(channel_evidence):
        return Judgement(VERDICT_INCONCLUSIVE, "오라클 채널을 읽지 못함")

    if am_succeeded(am_output):
        return Judgement(VERDICT_NOT_REACHED, "am 정상, 싱크 증거 없음")

    # am 출력에 성공 신호도 거부 신호도 없다. 무슨 일이 있었는지 단정할 수 없다.
    return Judgement(VERDICT_INCONCLUSIVE, "am 결과가 불분명하고 증거도 없음")


def collect_sub_markers(bindings):
    """바인딩 목록(bindings)에서 실제로 심은 서브마커만 뽑는다"""
    return tuple(b.marker_part for b in bindings if b.marker_part)