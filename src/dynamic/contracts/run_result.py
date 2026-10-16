"""3단계 결과 구조.

경로(= finding × graph × path) 하나당 레코드 하나. 무엇을 시도했고 도달했는지만
담는다. 실행되지 않은 경로도 사유와 함께 전부 들어간다 — 1·2단계에서 걸러진 것들이
결과에서 사라지면 커버리지를 셀 수 없기 때문이다.
"""

from __future__ import annotations

import json
import shlex
from dataclasses import dataclass


# ---------------------------------------------------------------------------
# 판정
# ---------------------------------------------------------------------------
VERDICT_REACHED = "reached"            # 싱크 도달 증거 있음
VERDICT_NOT_REACHED = "not_reached"    # 정상 실행됐으나 증거 없음
VERDICT_BLOCKED = "blocked"            # am 이 거부됨 (권한/exported/컴포넌트 부재)
VERDICT_CRASHED = "crashed"            # 앱이 죽음. 테스트 무효
VERDICT_INCONCLUSIVE = "inconclusive"  # 환경 제약 또는 증거 모호
VERDICT_NOT_TESTED = "not_tested"      # 실행 자체를 안 함
DYNAMIC_SCHEMA_VERSION = "1.0"

ALL_VERDICTS = (
    VERDICT_REACHED,
    VERDICT_NOT_REACHED,
    VERDICT_BLOCKED,
    VERDICT_CRASHED,
    VERDICT_INCONCLUSIVE,
    VERDICT_NOT_TESTED,
)

# 여러 시도를 하나로 접을 때의 우선순위. 정보량이 많은 쪽이 앞이다.
# blocked 가 crashed 보다 앞인 이유: 전자는 "우리가 못 보냈다"는 확정된 사실이고
# 후자는 관측 실패에 가깝다.
VERDICT_ROLLUP_PRIORITY = (
    VERDICT_REACHED,
    VERDICT_NOT_REACHED,
    VERDICT_BLOCKED,
    VERDICT_CRASHED,
    VERDICT_INCONCLUSIVE,
)

# 이 개수 이상 돌렸는데 도달이 하나도 없으면 리포트에 경고를 단다.
WARN_ALL_MISSED_THRESHOLD = 10


@dataclass(frozen=True)
class Attempt:
    """한 경로에 대해 실제로 던진 커맨드 하나와 그 결과"""

    test_case_id: str
    command: str          # 사람이 읽을 수 있는 한 줄
    verdict: str
    inputs: tuple = ()
    detail: str = ""
    # 어느 입력이 실제로 싱크까지 흘렀는가. "extra:path" 꼴.
    # 우리가 내놓는 가장 강한 주장이다. 경로가 아니라 소스 귀속이며, 정적 분석의
    # taint 판정을 동적으로 검증한 결과다.
    matched_inputs: tuple = ()
    # 그 증거가 artifact 였나 echo 였나. verdict.GRADE_* 값.
    evidence_grade: str = ""
    # 원 증거(am 출력·logcat·채널 텍스트)를 파일로 남겼으면 그 상대 경로. 안 남겼으면 None.
    evidence_ref: str | None = None
    # 그 증거 파일 내용의 sha256. 나중에 파일이 바뀌었는지 대조하는 용도.
    evidence_hash: str | None = None

    def to_dict(self):
        """직렬화를 위해 dict 로 변환한다"""
        return {
            "test_case_id": self.test_case_id,
            "command": self.command,
            "verdict": self.verdict,
            "inputs": list(self.inputs),
            "detail": self.detail,
            "matched_inputs": list(self.matched_inputs),
            "evidence_grade": self.evidence_grade,
            "evidence_ref": self.evidence_ref,
            "evidence_hash": self.evidence_hash,
        }

    @staticmethod
    def from_dict(raw):
        """dict(raw) 에서 Attempt 를 복원한다"""
        return Attempt(
            test_case_id=raw["test_case_id"],
            command=raw["command"],
            verdict=raw["verdict"],
            inputs=tuple(raw.get("inputs", ())),
            detail=raw.get("detail", ""),
            matched_inputs=tuple(raw.get("matched_inputs", ())),
            evidence_grade=raw.get("evidence_grade", ""),
            evidence_ref=raw.get("evidence_ref"),
            evidence_hash=raw.get("evidence_hash"),
        )


@dataclass(frozen=True)
class PathResult:
    """검증 단위 하나(finding × graph × path)의 결과"""

    finding_id: str
    graph_id: str
    path_id: str
    candidate_id: str
    tested: bool
    verdict: str
    reason: str | None = None       # 실행 안 됐으면 "status/code" 한 줄
    attempts: tuple = ()

    def to_dict(self):
        """직렬화를 위해 dict 로 변환한다"""
        return {
            "finding_id": self.finding_id,
            "graph_id": self.graph_id,
            "path_id": self.path_id,
            "candidate_id": self.candidate_id,
            "tested": self.tested,
            "verdict": self.verdict,
            "reason": self.reason,
            "attempts": [item.to_dict() for item in self.attempts],
        }

    @staticmethod
    def from_dict(raw):
        """dict(raw) 에서 PathResult 를 복원한다"""
        return PathResult(
            finding_id=raw["finding_id"],
            graph_id=raw["graph_id"],
            path_id=raw["path_id"],
            candidate_id=raw["candidate_id"],
            tested=raw["tested"],
            verdict=raw["verdict"],
            reason=raw.get("reason"),
            attempts=tuple(Attempt.from_dict(item) for item in raw.get("attempts", [])),
        )


def _command_entry_point(command, package):
    """ADB 명령의 명시적 컴포넌트에서 진입점 클래스명을 추출한다"""
    try:
        arguments = shlex.split(command)
        component_index = arguments.index("-n") + 1
        component = arguments[component_index]
    except (ValueError, IndexError):
        return ""

    component_package, separator, class_name = component.partition("/")
    if not separator:
        return component
    if class_name.startswith("."):
        return f"{component_package or package}{class_name}"
    return class_name


def _attempt_payload_key(attempt):
    """한 Flow 안에서 의미가 같은 Payload를 식별할 키를 만든다"""
    inputs = json.dumps(
        list(attempt.inputs),
        ensure_ascii=False,
        sort_keys=True,
        default=str,
    )
    return attempt.command, inputs


@dataclass(frozen=True)
class RunResult:
    """3단계의 산출물"""

    apk: str
    results: tuple = ()

    def get_reached(self):
        """싱크 도달이 확인된 경로만 추려서 돌려준다"""
        return tuple(item for item in self.results if item.verdict == VERDICT_REACHED)

    def get_by_verdict(self, verdict):
        """주어진 판정을 받은 경로만 추려서 돌려준다"""
        return tuple(item for item in self.results if item.verdict == verdict)

    def to_dict(self):
        """동적 분석 결과를 execution 요약과 flows를 포함한 dynamic.json 형식의 dict로 변환한다"""
        flows_by_graph = {}
        payload_indexes_by_graph = {}
        for path_result in self.results:
            if not path_result.graph_id or not path_result.attempts:
                continue
            flow = flows_by_graph.get(path_result.graph_id)
            if flow is None:
                flow = {
                    "flow_id": f"flow-{len(flows_by_graph) + 1:03d}",
                    "graph_id": path_result.graph_id,
                    "entry_point": "",
                    "payloads": [],
                }
                flows_by_graph[path_result.graph_id] = flow
                payload_indexes_by_graph[path_result.graph_id] = {}
            for attempt in path_result.attempts:
                if not flow["entry_point"]:
                    flow["entry_point"] = _command_entry_point(
                        attempt.command, self.apk
                    )
                payload = {
                    "status": (
                        "success" if attempt.verdict == VERDICT_REACHED else "failure"
                    ),
                    "command": attempt.command,
                    "inputs": list(attempt.inputs),
                    "result": {
                        "verdict": attempt.verdict,
                        "detail": attempt.detail,
                    },
                }
                payload_key = _attempt_payload_key(attempt)
                payload_indexes = payload_indexes_by_graph[path_result.graph_id]
                existing_index = payload_indexes.get(payload_key)
                if existing_index is None:
                    payload_indexes[payload_key] = len(flow["payloads"])
                    flow["payloads"].append(payload)
                elif (
                    payload["status"] == "success"
                    and flow["payloads"][existing_index]["status"] != "success"
                ):
                    flow["payloads"][existing_index] = payload

        payload_number = 0
        for flow in flows_by_graph.values():
            for payload in flow["payloads"]:
                payload_number += 1
                payload["payload_id"] = f"payload-{payload_number:02d}"

        tested_paths = sum(
            1 for item in self.results if item.tested
        )
        reached_paths = sum(
            1
            for item in self.results
            if item.verdict == VERDICT_REACHED
        )

        failure_reason_counts = {}
        for item in self.results:
            if item.reason:
                failure_reason_counts[item.reason] = (
                    failure_reason_counts.get(item.reason, 0) + 1
                )

        return {
            "schema_version": DYNAMIC_SCHEMA_VERSION,
            "package": self.apk,
            "execution": {
                "status": (
                    "completed"
                    if tested_paths > 0
                    else "not_executed"
                ),
                "total_paths": len(self.results),
                "tested_paths": tested_paths,
                "reached_paths": reached_paths,
                "failure_reasons": [
                    {
                        "reason": reason,
                        "count": count,
                    }
                    for reason, count in failure_reason_counts.items()
                ],
            },
            "flows": list(flows_by_graph.values()),
        }

    @staticmethod
    def from_dict(raw):
        """dict(raw) 에서 RunResult 를 복원한다"""
        return RunResult(
            apk=raw["apk"],
            results=tuple(PathResult.from_dict(item) for item in raw.get("results", [])),
        )


# ---------------------------------------------------------------------------
# 판정 접기
# ---------------------------------------------------------------------------
def rollup_verdicts(verdicts):
    """여러 시도의 판정(verdicts)을 경로 하나의 판정으로 접는다"""
    if not verdicts:
        return VERDICT_NOT_TESTED
    seen = set(verdicts)
    for verdict in VERDICT_ROLLUP_PRIORITY:
        if verdict in seen:
            return verdict
    return VERDICT_INCONCLUSIVE


def format_reason(status, reasons):
    """상태(status)와 사유 목록(reasons)을 결과에 실을 한 줄로 만든다"""
    if not reasons:
        return status
    return f"{status}/{reasons[0].code}"


# ---------------------------------------------------------------------------
# 뼈대 만들기 - 모든 경로가 결과에 나타나게 한다
# ---------------------------------------------------------------------------
def build_skeleton(candidate_set, test_case_set=None):
    """모든 경로에 대해 미실행 상태의 결과 뼈대를 만든다"""
    # 1·2단계에서 걸러진 경로도 결과에 남아야 커버리지를 셀 수 있다. 실행 루프는
    # 이 뼈대를 받아 실제로 돌린 경로만 갈아 끼운다.
    from src.dynamic.contracts.candidate_set import STATUS_TESTABLE

    skipped_by_id = {}
    if test_case_set is not None:
        skipped_by_id = {item.candidate_id: item for item in test_case_set.skipped}

    results = []
    for candidate in candidate_set.candidates:
        if candidate.status != STATUS_TESTABLE:
            reason = format_reason(candidate.status, candidate.reasons)
        elif candidate.candidate_id in skipped_by_id:
            skipped = skipped_by_id[candidate.candidate_id]
            reason = format_reason(skipped.status, skipped.reasons)
        else:
            reason = None   # 실행 대기. 실행 루프가 갈아 끼운다

        results.append(PathResult(
            finding_id=candidate.finding_id,
            graph_id=candidate.graph_id,
            path_id=candidate.path_id,
            candidate_id=candidate.candidate_id,
            tested=False,
            verdict=VERDICT_NOT_TESTED,
            reason=reason,
        ))

    return RunResult(apk=candidate_set.apk, results=tuple(results))


def apply_attempts(path_result, attempts):
    """경로 결과(path_result)에 시도 목록을 채우고 판정을 접어 넣는다"""
    attempts = tuple(attempts)
    if not attempts:
        return path_result
    return PathResult(
        finding_id=path_result.finding_id,
        graph_id=path_result.graph_id,
        path_id=path_result.path_id,
        candidate_id=path_result.candidate_id,
        tested=True,
        verdict=rollup_verdicts([item.verdict for item in attempts]),
        reason=None,
        attempts=attempts,
    )


def render_run_report(run_result):
    """실행 결과(run_result)를 사람이 훑어볼 수 있는 요약 문자열로 만든다"""
    lines = [f"apk: {run_result.apk}", f"경로 {len(run_result.results)}개", ""]

    counted = {}
    attempt_total = 0
    for item in run_result.results:
        counted[item.verdict] = counted.get(item.verdict, 0) + 1
        attempt_total += len(item.attempts)

    lines.append("판정별")
    for verdict in ALL_VERDICTS:
        if verdict in counted:
            lines.append(f"  {verdict:16} {counted[verdict]}")

    lines.append("")
    lines.append(f"실행한 커맨드 {attempt_total}개")

    # 연결성을 확인하고 빠지는 앱이면 싱크 종류를 가리지 않고 전부 미도달이 된다.
    # 로그에 아무것도 안 남아 가드 미통과와 구분이 안 되므로, 눈에 띄게만 해 둔다.
    tested_count = sum(1 for item in run_result.results if item.tested)
    if tested_count >= WARN_ALL_MISSED_THRESHOLD and not run_result.get_reached():
        lines.append("")
        lines.append(f"경고: 실행한 {tested_count}개 경로에서 reached 0건.")
        lines.append("      앱이 연결성을 확인하고 빠지는 경로일 수 있습니다.")

    # reached 인데 증거가 echo 등급뿐이면 앱이 값을 그냥 로그로 찍은 것일 수도 있다.
    # 미도달의 '못 봤을 수도 있음' 과 짝이 되는, 도달 쪽의 정직성 표시다.
    echo_only = [item for item in run_result.results
                 if item.verdict == VERDICT_REACHED
                 and any(attempt.evidence_grade == "echo" and attempt.verdict == VERDICT_REACHED
                         for attempt in item.attempts)]
    if echo_only:
        lines.append("")
        lines.append(f"증거가 에코뿐인 도달 {len(echo_only)}건 — 앱이 값을 로그로 찍은 것일 수도 있음")

    weak = [item for item in run_result.results
            if item.reason and item.reason.startswith("weak_observation/")]
    if weak:
        lines.append("")
        lines.append(f"관측이 약한 미도달 {len(weak)}건 — 못 봤을 수도 있음")
        by_rule = {}
        for item in weak:
            by_rule[item.reason] = by_rule.get(item.reason, 0) + 1
        for reason, count in sorted(by_rule.items(), key=lambda pair: -pair[1]):
            lines.append(f"  {reason:40} {count}")

    not_tested = [item for item in run_result.results
                  if item.verdict == VERDICT_NOT_TESTED and item.reason]
    if not_tested:
        by_reason = {}
        for item in not_tested:
            by_reason[item.reason] = by_reason.get(item.reason, 0) + 1
        lines.append("")
        lines.append("미실행 사유별")
        for reason, count in sorted(by_reason.items(), key=lambda pair: -pair[1]):
            lines.append(f"  {reason:40} {count}")

    return "\n".join(lines)
