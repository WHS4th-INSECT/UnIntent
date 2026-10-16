"""싱크 규칙 1종에 대한 실행 계약을 담는다.

1단계는 is_observable() 만, 2단계는 marker_hint() 만 부른다. setup/observe/teardown 은
3단계 실행 루프가 부른다.

observe() 는 판정하지 않는다. 증거만 모아 돌려주고 판정은 verdict.judge() 가 한다.
그래야 판정 규칙이 한곳에 모이고 에뮬레이터 없이 검증할 수 있다.

안전은 이 파일의 책임이 아니다. 스냅샷 복원, DNS 싱크홀, SIM 없는 에뮬레이터라는
환경 층이 단독으로 책임진다. 여기는 '어떻게 관측하고 무엇을 준비하는가'만 다룬다.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from src.dynamic.contracts.candidate_set import is_marker_friendly_operator
from src.dynamic.rules.verdict import (
    ChannelEvidence,
    LAUNCH_LOG_SIGNALS,
    GRADE_ARTIFACT,
    GRADE_ECHO,
    split_app_launches,
    split_by_patterns,
    strip_launch_echo,
)


# ---------------------------------------------------------------------------
# 관측 채널
# ---------------------------------------------------------------------------
CHANNEL_LOGCAT = "logcat"
CHANNEL_LOCAL_HTTP = "local_http"    # 로컬 싱크홀 서버 액세스 로그
CHANNEL_DNS = "dns"                  # 싱크홀 DNS 질의 로그
CHANNEL_FILESYSTEM = "filesystem"    # 카나리 파일 생성/변경/소멸
CHANNEL_DUMPSYS = "dumpsys"
CHANNEL_PROCESS = "process"          # 자식 프로세스 생성


# ---------------------------------------------------------------------------
# 관측 가능성 판정
# ---------------------------------------------------------------------------
OBSERVABILITY_OK = "ok"
OBSERVABILITY_NO_CHANNEL = "no_channel"      # 관측 채널 자체가 없음
OBSERVABILITY_UNRELIABLE = "unreliable"      # 채널은 있으나 신뢰할 수 없음
OBSERVABILITY_NO_POLICY = "no_policy"        # 등록되지 않은 규칙 (파이프라인 결함)


# ---------------------------------------------------------------------------
# 관측 신뢰도 - is_observable 과 다르다
#
# is_observable 은 '관측할 수단이 있는가'라 1단계 필터에 쓰인다. 이쪽은 '그 수단이
# 놓칠 수 있는가'이고 필터링하지 않는다. weak 인데 not_reached 가 나오면 결과에
# 표시만 해서, 진짜 안 흐른 것과 못 봤을 수도 있는 것을 구분한다.
# ---------------------------------------------------------------------------
CONFIDENCE_STRONG = "strong"
CONFIDENCE_WEAK = "weak"


# ---------------------------------------------------------------------------
# 되돌리기 수준 - 3단계가 케이스 사이에 무엇을 복원해야 하는가
# ---------------------------------------------------------------------------
REVERSIBILITY_SNAPSHOT = "snapshot"              # 에뮬레이터 스냅샷 복원 필요
REVERSIBILITY_APP_DATA_CLEAR = "app_data_clear"  # pm clear 로 충분
REVERSIBILITY_PROCESS_KILL = "process_kill"      # force-stop 으로 충분


# ---------------------------------------------------------------------------
# 마커 삽입 위치
# ---------------------------------------------------------------------------
MARKER_POSITION_SUFFIX = "suffix"
MARKER_POSITION_PREFIX = "prefix"
MARKER_POSITION_PATH_SEGMENT = "path_segment"
MARKER_POSITION_DIGITS = "digits"      # 숫자만 허용되는 자리 (전화번호 등)


@dataclass(frozen=True)
class MarkerHint:
    """관측 귀속을 위해 값의 어느 자리에 마커를 심을지에 대한 힌트"""

    position: str       # MARKER_POSITION_* 중 하나
    template: str       # 자리표시자를 포함한 값의 형태. 2단계가 채운다

    # 템플릿에 쓰는 자리표시자
    #   {marker}             2단계가 케이스마다 발급하는 마커
    #   {digits}             숫자만 허용되는 자리에 쓰는 숫자 마커
    #   {host_suffix}        싱크홀 서버의 도메인 꼬리
    #   {canary_dir}         카나리 파일을 두는 디렉터리
    #   {canary_authority}   존재하지 않는 ContentProvider 주소의 꼬리
    #   {telecom_prefix}     전화번호 앞자리


@dataclass(frozen=True)
class Observability:
    """관측 가능성 판정 결과"""

    status: str         # OBSERVABILITY_* 중 하나
    detail: str = ""

    def is_ok(self):
        """관측이 가능한 판정인지 판별한다"""
        return self.status == OBSERVABILITY_OK


@dataclass
class ExecutionContext:
    """3단계 메서드들이 공유하는 실행 환경"""

    device: object                  # device.Device
    env: object                     # environment.EnvironmentConfig
    package: str
    component: str = ""             # 우리가 때린 진입점. 우리 기동 로그를 골라내는 데 쓴다
    sinkhole: object = None         # sinkhole.Sinkhole. 없을 수도 있다
    started_at: float = 0.0         # 시간창 시작 시각


@dataclass
class SetupHandle:
    """setup() 이 남긴 기준선과 배치물. observe/teardown 이 받아 쓴다"""

    file_states: dict = field(default_factory=dict)   # 경로 -> (존재, 체크섬)
    placed_files: tuple = ()                          # 우리가 깔아 둔 카나리
    dumpsys_baselines: dict = field(default_factory=dict)
    process_baseline: frozenset = frozenset()
    app_uid: str | None = None   
    started_at: float = 0.0


# ---------------------------------------------------------------------------
# 바인딩에서 값 뽑아내기 - 순수
# ---------------------------------------------------------------------------
def extract_observed_paths(test_case):
    """바인딩 값들 중 파일 경로로 보이는 것을 뽑는다"""
    # 읽기 전용 확인에만 쓰므로 경로 제한을 두지 않는다. 앱이 건드릴 만한 경로를
    # 그대로 지켜보기 위해서다.
    paths = []
    for binding in test_case.bindings:
        # 감싼 값이 아니라 감싸기 전 값을 본다. 소스가 intent: URI 를 요구하면
        # binding.value 는 전부 intent: 로 시작해 카나리 경로가 하나도 안 잡힌다.
        value = binding.payload if binding.payload is not None else binding.value
        if isinstance(value, str) and value.startswith("/") and value not in paths:
            paths.append(value)
    return tuple(paths)


def extract_placeable_paths(test_case, canary_dir):
    """우리가 직접 깔거나 지워도 되는 카나리 경로만 뽑는다"""
    # 쓰기·삭제는 카나리 디렉터리 안으로 한정한다. device 계층에도 같은 검사가 있지만,
    # 애초에 여기서 걸러 두면 앱 데이터 경로를 건드릴 일 자체가 생기지 않는다.
    prefix = canary_dir.rstrip("/") + "/"
    return tuple(path for path in extract_observed_paths(test_case)
                 if path.startswith(prefix))


def diff_lines(before, after):
    """사후 텍스트에서 기준선에 없던 줄만 뽑는다"""
    # 시간창 밖의 내용을 증거로 넘기지 않기 위해서다. 전체 덤프를 그대로 넘기면
    # 이전 케이스의 잔재가 도달로 잡힌다.
    baseline = set((before or "").splitlines())
    return "\n".join(line for line in (after or "").splitlines()
                     if line not in baseline)


def describe_file_changes(before_states, after_states):
    """파일 상태의 전후 차이를 사람이 읽고 마커도 찾을 수 있는 문장으로 만든다"""
    lines = []
    for path, after in after_states.items():
        before = before_states.get(path, (False, None))
        if before == after:
            continue
        if not before[0] and after[0]:
            lines.append(f"created {path}")
        elif before[0] and not after[0]:
            lines.append(f"deleted {path}")
        else:
            lines.append(f"modified {path}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# 기반 클래스
# ---------------------------------------------------------------------------
class SinkPolicy:
    """싱크 규칙 1종의 관측 방법과 실행 준비물을 정의한다"""

    rule = ""
    channels: tuple = ()
    # 정착 대기 상한. 우리 네트워크는 전부 루프백이고 am broadcast 는 리시버가 끝날
    # 때까지 기다렸다 돌아오므로, 대부분의 싱크는 am 반환 시점에 이미 일이 끝나 있다.
    # 이 값은 '증거가 안 잡혔을 때 언제 포기하나'이지 '얼마나 기다려야 하나'가 아니다.
    settle_ms = 500
    reversibility = REVERSIBILITY_PROCESS_KILL
    observation_confidence = CONFIDENCE_STRONG

    # 이 싱크가 불렸을 때만 나오는 로그 줄의 표식. 비어 있으면 로그 모양으로
    # 구분할 근거가 없다는 뜻이고, 그 logcat 증거는 전부 echo 등급이 된다.
    evidence_patterns: tuple = ()

    # 이 싱크로 흘러갈 값의 형태. None 이면 형태 힌트가 없다는 뜻이고,
    # 2단계는 마커만 넣은 밋밋한 값으로 대체한다.
    marker_position = MARKER_POSITION_SUFFIX
    marker_template: str | None = None

    # --- 1단계에서 호출 ---
    def is_observable(self, candidate):
        """후보(candidate)의 싱크 도달을 관측할 수 있는지 판정한다"""
        if not self.channels:
            return Observability(
                OBSERVABILITY_NO_CHANNEL,
                f"{self.rule} 에 등록된 관측 채널이 없다",
            )
        return Observability(OBSERVABILITY_OK)

    def confidence_for(self, test_case):
        """이 케이스의 관측 신뢰도를 판정한다"""
        # 주입한 값에 따라 신뢰도가 달라지는 싱크만 재정의한다.
        return self.observation_confidence

    # --- 2단계에서 호출 ---
    def marker_hint(self, required_input):
        """입력(required_input)의 어느 자리에 마커를 심을지 힌트를 돌려준다"""
        if not required_input.markable:
            return None
        if not is_marker_friendly_operator(required_input.value_spec.operator):
            return None
        if not self.marker_template:
            return None
        return MarkerHint(self.marker_position, self.marker_template)

    # --- 3단계에서 호출 ---
    def setup(self, context, test_case):
        """실행 전 기준선을 잡고 필요한 준비물을 배치한다"""
        return SetupHandle(started_at=time.time())

    def poll(self, context, test_case, handle):
        """정착 대기 중 값싸게 확인할 주 채널만 본다"""
        # observe 를 폴링마다 부르면 logcat 을 수십 번 덤프하게 된다. 폴링은 싱크마다
        # 하나뿐인 주 채널만 보고, 전체 수집은 마지막에 observe 가 한 번만 한다.
        return []

    def observe(self, context, test_case, handle):
        """실행 후 증거를 모아 돌려준다. 판정은 하지 않는다"""
        return self._logcat_evidence(context)

    def teardown(self, context, handle):
        """setup 이 남긴 것을 정리한다"""
        for path in handle.placed_files:
            context.device.remove_file(path)

    # --- 파생 클래스가 함께 쓰는 조각 ---
    def _logcat_evidence(self, context):
        """logcat 덤프를 등급을 나눠 증거로 만든다"""
        # 실행 직전에 logcat -c 로 비웠으므로 이 덤프가 곧 시간창이다. 다만 그 안에는
        # 우리가 던진 am 이 만든 기동 로그도 들어 있어, 먼저 그것부터 빼야 한다.
        text = strip_launch_echo(context.device.dump_logcat(),
                                 context.package, context.component)
        matched, rest = split_by_patterns(text, self.evidence_patterns)
        evidence = []
        if matched:
            evidence.append(ChannelEvidence(CHANNEL_LOGCAT, matched, grade=GRADE_ARTIFACT))
        evidence.append(ChannelEvidence(CHANNEL_LOGCAT, rest, grade=GRADE_ECHO))
        return evidence


# ---------------------------------------------------------------------------
# 파생 클래스
# ---------------------------------------------------------------------------
class IccPolicy(SinkPolicy):
    """인텐트를 다른 컴포넌트로 다시 던지는 싱크. 타겟 기동 로그로 관측한다"""

    # 기동 로그 줄만 증거로 인정한다. 우리가 던진 am 의 기동 로그는 _logcat_evidence
    # 가 이미 빼므로, 여기 남는 기동 로그는 앱이 다시 던진 것뿐이다.
    evidence_patterns = LAUNCH_LOG_SIGNALS
    channels = (CHANNEL_LOGCAT,)
    settle_ms = 1500          # 액티비티/서비스 기동에 약간 걸린다
    reversibility = REVERSIBILITY_PROCESS_KILL

    def setup(self, context, test_case):
        """대상 앱의 UID 를 읽어 둔다"""
        return SetupHandle(app_uid=context.device.package_uid(context.package),
                           started_at=time.time())

    def observe(self, context, test_case, handle):
        """대상 앱이 다시 던진 기동 로그만 artifact 로 남기고 나머지는 echo 로 내린다"""
        evidence = []
        for item in self._logcat_evidence(context):
            if item.grade != GRADE_ARTIFACT:
                evidence.append(item)
                continue
            own, other = split_app_launches(item.text, context.package, handle.app_uid)
            if own:
                evidence.append(ChannelEvidence(item.channel, own, grade=GRADE_ARTIFACT))
            if other:
                evidence.append(ChannelEvidence(item.channel, other, grade=GRADE_ECHO))
        return evidence


class FailureLogPolicy(SinkPolicy):
    """호출이 실패하면 프레임워크가 값을 로그에 찍는 싱크"""

    # 존재하지 않는 대상을 가리키게 만들어 두면 반드시 실패하고, 그 실패 메시지에
    # 우리 마커가 실려 나온다. 성공은 조용하지만 실패는 시끄럽다는 성질을 쓰는 것이라
    # 관측용 앱을 따로 설치할 필요가 없다.
    channels = (CHANNEL_LOGCAT,)
    settle_ms = 500
    reversibility = REVERSIBILITY_APP_DATA_CLEAR
    marker_position = MARKER_POSITION_PATH_SEGMENT

    # 이 문구가 있는 줄에 마커가 있어야 '조회를 시도하다 실패했다' 는 뜻이 된다.
    # 그냥 로그에 값이 찍힌 것과 구분하는 근거다. API 레벨마다 다를 수 있다.
    evidence_patterns = (
        "Failed to find provider info",
        "Unknown URL",
        "Unknown URI",
        "no such table",
        "SQLiteException",
        "IllegalArgumentException: Unknown",
    )

    def poll(self, context, test_case, handle):
        """logcat 만 값싸게 확인한다"""
        return self._logcat_evidence(context)


class LocalHttpPolicy(SinkPolicy):
    """URL 을 싣고 나가는 싱크. 네트워크가 꺼져 있으므로 실패 로그로 관측한다"""

    # content:// 마커를 쓸 때 나오는 실패 문구. 가드가 http 를 강제해 이 문구가 안
    # 나오면 남은 증거는 전부 echo 등급이 되고, confidence_for() 도 weak 를 준다.
    evidence_patterns = (
        "Failed to find provider info",
        "Unknown URL",
    )
    channels = (CHANNEL_LOGCAT,)
    settle_ms = 2000          # WebView 최초 초기화에 약간 걸린다
    reversibility = REVERSIBILITY_APP_DATA_CLEAR

    # content:// 를 쓰는 이유: WebView 는 content:// URL 도 로드하고, 존재하지 않는
    # authority 면 프레임워크가 'Failed to find provider info' 를 반드시 찍는다.
    # http(s) 로드 실패는 WebViewClient.onReceivedError 로 앱 코드에 전달될 뿐이라
    # 앱이 안 찍으면 아무 흔적도 안 남는다.
    marker_position = MARKER_POSITION_PATH_SEGMENT
    marker_template = "content://{marker}.{canary_authority}/{marker}"

    def confidence_for(self, test_case):
        """주입한 값이 확실히 로그를 남기는 형태인지 보고 신뢰도를 정한다"""
        # 가드가 http 를 강제하면 content:// 를 못 쓰고, 그때는 앱이 실패를 찍어야만
        # 관측된다. 그 사실을 결과에 남겨 not_reached 를 그대로 믿지 않게 한다.
        for binding in test_case.bindings:
            # 감싸기 전 값으로 본다. 감싼 값은 전부 intent: 로 시작한다.
            value = binding.payload if binding.payload is not None else binding.value
            if isinstance(value, str) and value.startswith("content://"):
                return CONFIDENCE_STRONG
        return CONFIDENCE_WEAK

    def setup(self, context, test_case):
        """싱크홀 모드일 때만 이전 기록을 비운다"""
        if context.sinkhole is not None:
            context.sinkhole.clear()
        return SetupHandle(started_at=time.time())

    def poll(self, context, test_case, handle):
        """logcat 을 확인한다. 싱크홀 모드면 그 기록도 함께 본다"""
        evidence = list(self._logcat_evidence(context))
        evidence.extend(self._sinkhole_evidence(context, handle))
        return evidence

    def observe(self, context, test_case, handle):
        """실패 로그를 증거로 모은다"""
        return list(self._logcat_evidence(context)) + self._sinkhole_evidence(context, handle)

    def _sinkhole_evidence(self, context, handle):
        """싱크홀 모드일 때만 그 기록을 증거로 만든다"""
        # 기본 경로에서는 싱크홀이 없다. 없는 채널을 'readable=False' 로 넣으면
        # '못 읽었다'는 뜻이 되어 오해를 부르므로 아예 빼는 편이 정확하다.
        if context.sinkhole is None:
            return []
        return [ChannelEvidence(
            channel, context.sinkhole.evidence_text(channel, since=handle.started_at))
            for channel in (CHANNEL_LOCAL_HTTP, CHANNEL_DNS)]


class DownloadEnqueuePolicy(LocalHttpPolicy):
    """다운로드를 큐에 넣는 싱크. 실제 내려받기를 기다리지 않고 큐 기록을 본다"""

    # enqueue() 는 동기 호출이라 큐에 행이 들어가는 즉시 끝난다. 실제 내려받기는
    # JobScheduler 를 거쳐 나중에 일어나고 조건에 따라 미뤄질 수도 있으므로, 그것을
    # 기다리면 오래 걸리면서도 놓칠 수 있다. 우리가 알고 싶은 것은 '시도했는가'다.
    settle_ms = 1500
    channels = (CHANNEL_DUMPSYS, CHANNEL_LOGCAT)

    # 셸 UID 가 이 주소를 읽을 수 있는지는 빌드마다 다르다. 실물에서 확인이 필요하고,
    # 못 읽으면 싱크홀과 logcat 채널이 남는다.
    download_uri = "content://downloads/all_downloads"

    def _queue_evidence(self, context):
        """다운로드 큐에서 이번 케이스의 URI 를 찾을 증거를 만든다"""
        result = context.device.content_query(self.download_uri)
        if not result.succeeded():
            return ChannelEvidence(CHANNEL_DUMPSYS, "", readable=False)
        return ChannelEvidence(CHANNEL_DUMPSYS, result.stdout)

    def confidence_for(self, test_case):
        """큐 기록이 네트워크와 무관하게 남으므로 신뢰도가 높다"""
        # enqueue 는 동기 호출이고 큐 행은 네트워크 상태와 관계없이 들어간다.
        return CONFIDENCE_STRONG

    def poll(self, context, test_case, handle):
        """큐 기록과 logcat 을 값싸게 확인한다"""
        return [self._queue_evidence(context)] + super().poll(context, test_case, handle)

    def observe(self, context, test_case, handle):
        """큐 기록을 더해 증거를 모은다"""
        return [self._queue_evidence(context)] + super().observe(context, test_case, handle)


class FileSystemPolicy(SinkPolicy):
    """파일을 열거나 바꾸는 싱크. 카나리 파일의 생성·변경·소멸로 관측한다"""

    channels = (CHANNEL_FILESYSTEM, CHANNEL_LOGCAT)
    settle_ms = 500
    reversibility = REVERSIBILITY_APP_DATA_CLEAR

    marker_position = MARKER_POSITION_SUFFIX
    marker_template = "{canary_dir}/canary_{marker}"

    # 삭제·이동 계열은 사라질 대상이 미리 있어야 신호가 생긴다.
    place_before_run = False

    def setup(self, context, test_case):
        """카나리 경로의 기준선을 잡는다. 필요하면 파일을 미리 깐다"""
        placeable = extract_placeable_paths(test_case, context.env.canary_dir)
        placed = []
        for path in placeable:
            if self.place_before_run:
                context.device.write_file(path)
                placed.append(path)
            else:
                # 생성 계열은 '없다가 생겼다'가 신호이므로 남은 찌꺼기를 치운다.
                context.device.remove_file(path)

        states = {path: context.device.file_state(path)
                  for path in extract_observed_paths(test_case)}
        return SetupHandle(file_states=states, placed_files=tuple(placed),
                           started_at=time.time())

    def poll(self, context, test_case, handle):
        """파일 상태만 값싸게 확인한다"""
        return [self._file_evidence(context, test_case, handle)]

    def _file_evidence(self, context, test_case, handle):
        """기준선 대비 파일 변화를 증거로 만든다"""
        after = {path: context.device.file_state(path)
                 for path in extract_observed_paths(test_case)}
        return ChannelEvidence(CHANNEL_FILESYSTEM,
                               describe_file_changes(handle.file_states, after))

    def observe(self, context, test_case, handle):
        """기준선 대비 파일이 생겼는지 사라졌는지 바뀌었는지 본다"""
        # 방향을 미리 정하지 않고 '변화'로 본다. FILE_MUTATION 하나에도 delete 와
        # mkdir 이 함께 있어 생성인지 삭제인지 단정할 수 없기 때문이다.
        return ([self._file_evidence(context, test_case, handle)]
                + self._logcat_evidence(context))


class DestructiveFileSystemPolicy(FileSystemPolicy):
    """삭제나 이동이 섞인 파일 싱크. 사라질 대상을 미리 깔아 둔다"""

    # 앱이 지우는 것은 우리가 넘긴 카나리 경로이고, teardown 이 치우며 앱 데이터
    # 손상은 pm clear 로 복구된다. 스냅샷 복원은 케이스당 수십 초가 들어 실익이 없다.
    # 앱이 시스템 상태까지 망가뜨리는 것이 관측되면 그때 올린다.
    reversibility = REVERSIBILITY_APP_DATA_CLEAR
    place_before_run = True


class DumpsysPolicy(SinkPolicy):
    """시스템 서비스 상태로 드러나는 싱크. dumpsys 전후 비교로 관측한다"""

    channels = (CHANNEL_DUMPSYS, CHANNEL_LOGCAT)
    settle_ms = 1000
    reversibility = REVERSIBILITY_PROCESS_KILL
    dumpsys_sections: tuple = ()

    def setup(self, context, test_case):
        """비교할 dumpsys 섹션의 기준선을 뜬다"""
        baselines = {section: context.device.dumpsys(section)
                     for section in self.dumpsys_sections}
        return SetupHandle(dumpsys_baselines=baselines, started_at=time.time())

    def poll(self, context, test_case, handle):
        """dumpsys 섹션만 값싸게 확인한다"""
        return [self._dumpsys_evidence(context, handle)]

    def _dumpsys_evidence(self, context, handle):
        """기준선에 없던 dumpsys 줄만 증거로 만든다"""
        added = []
        for section in self.dumpsys_sections:
            after = context.device.dumpsys(section)
            added.append(diff_lines(handle.dumpsys_baselines.get(section, ""), after))
        return ChannelEvidence(CHANNEL_DUMPSYS,
                               "\n".join(part for part in added if part))

    def observe(self, context, test_case, handle):
        """기준선에 없던 줄만 증거로 넘긴다"""
        return [self._dumpsys_evidence(context, handle)] + self._logcat_evidence(context)


class TelecomCallControlPolicy(DumpsysPolicy):
    """통화 상태를 바꾸는 싱크. 인자가 없고 통화도 없어 호출 흔적이 남지 않는다"""

    dumpsys_sections = ("telecom",)
    marker_template = None   # 마커를 심을 인자 자체가 없다

    def is_observable(self, candidate):
        """통화가 없는 에뮬레이터에서는 호출이 무동작이라 관측이 불가함을 판정한다"""
        return Observability(
            OBSERVABILITY_UNRELIABLE,
            "SIM 과 활성 통화가 없는 에뮬레이터에서는 answer/reject/endCall 이 흔적을 남기지 않는다",
        )


class ProcessPolicy(SinkPolicy):
    """외부 명령을 실행하는 싱크. 자식 프로세스는 짧게 살아 놓치기 쉽다"""

    channels = (CHANNEL_PROCESS, CHANNEL_LOGCAT)
    settle_ms = 2000
    reversibility = REVERSIBILITY_SNAPSHOT

    def is_observable(self, candidate):
        """프로세스 폴링으로는 단명 프로세스를 놓칠 수 있어 신뢰 불가로 판정한다"""
        return Observability(
            OBSERVABILITY_UNRELIABLE,
            "자식 프로세스가 폴링 주기보다 짧게 살면 관측되지 않는다",
        )

    def setup(self, context, test_case):
        """지금 돌고 있는 프로세스 목록을 기준선으로 잡는다"""
        return SetupHandle(process_baseline=frozenset(context.device.process_names()),
                           started_at=time.time())

    def poll(self, context, test_case, handle):
        """프로세스 목록만 값싸게 확인한다"""
        return [self._process_evidence(context, handle)]

    def _process_evidence(self, context, handle):
        """새로 생긴 프로세스를 증거로 만든다"""
        new_names = sorted(frozenset(context.device.process_names()) - handle.process_baseline)
        return ChannelEvidence(CHANNEL_PROCESS, "\n".join(new_names))

    def observe(self, context, test_case, handle):
        """새로 생긴 프로세스를 증거로 넘긴다"""
        return ([self._process_evidence(context, handle)]
                + self._logcat_evidence(context))


# ---------------------------------------------------------------------------
# 규칙별 인스턴스 - DEFAULT_RULES 18종과 1:1 로 대응한다
# ---------------------------------------------------------------------------
def build_policy(policy_class, rule, **overrides):
    """정책 클래스(policy_class)에 규칙명(rule)과 재정의값을 붙인 인스턴스를 만든다"""
    instance = policy_class()
    instance.rule = rule
    for name, value in overrides.items():
        setattr(instance, name, value)
    return instance


SINK_POLICIES = {
    "ICC_DISPATCH": build_policy(IccPolicy, "ICC_DISPATCH"),

    "WEBVIEW_LOAD": build_policy(LocalHttpPolicy, "WEBVIEW_LOAD"),
    "GECKOVIEW_LOAD": build_policy(LocalHttpPolicy, "GECKOVIEW_LOAD"),
    "DOWNLOAD_MANAGER_ENQUEUE": build_policy(
        DownloadEnqueuePolicy, "DOWNLOAD_MANAGER_ENQUEUE"
    ),

    "NOTIFICATION_DISPLAY": build_policy(
        DumpsysPolicy, "NOTIFICATION_DISPLAY", dumpsys_sections=("notification",)
    ),
    # 전화번호는 NANP 가상번호 대역을 쓴다. 에뮬레이터 콘솔 포트와 겹치는 짧은 숫자를
    # 피하고, 어디에도 할당되지 않은 번호라야 하기 때문이다.
    "TELECOM_PLACE_CALL": build_policy(
        DumpsysPolicy, "TELECOM_PLACE_CALL",
        dumpsys_sections=("telecom",),
        marker_position=MARKER_POSITION_DIGITS,
        marker_template="tel:{telecom_prefix}{digits}",
    ),
    "TELECOM_CALL_CONTROL": build_policy(TelecomCallControlPolicy, "TELECOM_CALL_CONTROL"),

    # 둘 다 '실패가 곧 증거'다. 존재하지 않는 provider 주소와 존재하지 않는 테이블
    # 이름을 넣으면 프레임워크와 SQLite 가 그 이름을 담은 예외를 로그에 남긴다.
    # 앱의 비공개 DB 에 시드 레코드를 넣는 방식은 스키마를 알아야 하고 run-as 가
    # 디버그 빌드에서만 되어 현실적이지 않다.
    "CONTENT_RESOLVER_URI": build_policy(
        FailureLogPolicy, "CONTENT_RESOLVER_URI",
        marker_template="content://{marker}.{canary_authority}/{marker}",
    ),
    "SQL_EXECUTION": build_policy(
        FailureLogPolicy, "SQL_EXECUTION",
        marker_position=MARKER_POSITION_SUFFIX,
        marker_template="seed_{marker}",
    ),

    "FILE_STREAM_OPEN": build_policy(FileSystemPolicy, "FILE_STREAM_OPEN"),
    "RANDOM_ACCESS_FILE_OPEN": build_policy(FileSystemPolicy, "RANDOM_ACCESS_FILE_OPEN"),
    "FILE_TEMP_CREATE": build_policy(FileSystemPolicy, "FILE_TEMP_CREATE"),
    "PARCEL_FILE_OPEN": build_policy(FileSystemPolicy, "PARCEL_FILE_OPEN"),
    "ANDROID_OS_FILE_OPEN": build_policy(FileSystemPolicy, "ANDROID_OS_FILE_OPEN"),
    "CONTEXT_FILE_ACCESS": build_policy(FileSystemPolicy, "CONTEXT_FILE_ACCESS"),
    "FILE_MUTATION": build_policy(DestructiveFileSystemPolicy, "FILE_MUTATION"),
    "NIO_FILE_ACCESS": build_policy(DestructiveFileSystemPolicy, "NIO_FILE_ACCESS"),

    "COMMAND_EXECUTION": build_policy(ProcessPolicy, "COMMAND_EXECUTION"),
}


def get_policy(rule):
    """싱크 규칙명(rule)에 해당하는 정책을 찾고 미등록이면 None 을 돌려준다"""
    # 관대한 기본 정책을 돌려주지 않는다. 규칙이 추가됐는데 파이프라인이 모르면
    # 오라클 없는 테스트가 조용히 '미도달'로 집계되어 결과가 오염되기 때문이다.
    return SINK_POLICIES.get(rule)


def check_observability(rule, candidate):
    """규칙(rule)과 후보(candidate)로 관측 가능성을 판정하고 미등록 규칙도 처리한다"""
    policy = get_policy(rule)
    if policy is None:
        return Observability(OBSERVABILITY_NO_POLICY, f"등록되지 않은 싱크 규칙: {rule}")
    return policy.is_observable(candidate)