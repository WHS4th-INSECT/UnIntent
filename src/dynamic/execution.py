"""3단계 - 조립된 케이스를 에뮬레이터에서 실제로 돌리고 판정한다.

부수효과를 다루는 유일한 모듈이지만, 실제 일은 device / sink_policy / verdict 에
맡기고 여기서는 순서와 복원만 관리한다. 덕분에 가짜 기기를 넣으면 루프 전체를
에뮬레이터 없이 돌려볼 수 있다.

전부 순차 실행이다. 마커를 못 심은 케이스(attribution=timing)는 시각으로 귀속하므로
동시에 던지면 어느 커맨드의 결과인지 가릴 수 없고, 한 브로드캐스트가 앱 상태를 바꾸면
다음 케이스 결과가 오염되기 때문이다.
"""

from __future__ import annotations

import hashlib
import os
import shlex
import time

from src.dynamic.contracts.run_result import (
    Attempt,
    PathResult,
    RunResult,
    VERDICT_INCONCLUSIVE,
    VERDICT_NOT_REACHED,
    VERDICT_NOT_TESTED,
    VERDICT_REACHED,
    apply_attempts,
    build_skeleton,
    rollup_verdicts,
)
from src.dynamic.contracts.test_case_set import ATTRIBUTION_TIMING
from src.dynamic.rules.sink_policy import (
    CONFIDENCE_WEAK,
    ExecutionContext,
    REVERSIBILITY_APP_DATA_CLEAR,
    REVERSIBILITY_PROCESS_KILL,
    REVERSIBILITY_SNAPSHOT,
    get_policy,
)
from src.dynamic.rules.verdict import (
    Judgement,
    collect_sub_markers,
    find_any_evidence,
    find_marker_evidence,
    judge,
)
from src.dynamic.environment import NETWORK_OFF


# 복원 수준의 비용 순서. 직전 케이스가 요구한 만큼만 수행한다.
RESTORE_RANK = {
    REVERSIBILITY_PROCESS_KILL: 1,
    REVERSIBILITY_APP_DATA_CLEAR: 2,
    REVERSIBILITY_SNAPSHOT: 3,
}

# 티어 실행 순서
TIER_RANK = {"confirmed": 0, "candidate": 1, "unknown": 2}

# 실행을 멈춘 경로에 남기는 사유
REASON_RUN_STOPPED = "run_stopped/environment"
REASON_BUDGET = "run_stopped/budget"
REASON_NO_POLICY = "unobservable/no_policy"


def format_command(argv):
    """인자 배열(argv)을 결과에 실을 사람이 읽는 한 줄로 만든다"""
    return "adb shell " + " ".join(shlex.quote(str(part)) for part in argv)


def dashboard_inputs(test_case):
    """대시보드에 표시할 인텐트 입력만 추려낸다"""
    return tuple(
        {
            "field": binding.field,
            "key": binding.key,
            "value": binding.value,
        }
        for binding in test_case.bindings
    )


def restore_device(device, package, level, env):
    """직전 케이스가 남긴 오염을 요구된 수준(level)만큼 되돌린다"""
    # 매번 스냅샷을 복원하면 케이스당 수십 초가 날아간다. 파괴적 싱크 뒤에만 스냅샷을
    # 쓰고 나머지는 force-stop 이나 pm clear 로 끝낸다.
    if level == REVERSIBILITY_SNAPSHOT:
        device.load_snapshot(env.snapshot_name)
        device.force_stop(package)
        return
    if level == REVERSIBILITY_APP_DATA_CLEAR:
        device.force_stop(package)
        device.clear_data(package)
        return
    device.force_stop(package)


def group_cases_by_candidate(test_case_set):
    """케이스를 후보별로 묶고 각 묶음을 variant 순서로 정렬한다"""
    grouped = {}
    for case in test_case_set.cases:
        grouped.setdefault(case.candidate_id, []).append(case)
    for cases in grouped.values():
        cases.sort(key=lambda item: item.variant_index)
    return grouped


def order_candidates(candidates, grouped):
    """실행 순서를 티어와 복원 비용으로 정한다"""
    # 티어가 우선이고, 같은 티어 안에서는 복원이 싼 것부터 돌려 비싼 스냅샷 복원
    # 횟수를 줄인다. 동점은 식별자로 고정해 재실행 비교가 되게 한다.
    def sort_key(candidate):
        """후보 하나의 정렬 키를 만든다"""
        policy = get_policy(candidate.sink_rule)
        cost = RESTORE_RANK.get(
            getattr(policy, "reversibility", REVERSIBILITY_PROCESS_KILL), 1)
        return (TIER_RANK.get(candidate.tier, 99), cost, candidate.candidate_id)

    return sorted(
        (item for item in candidates if item.candidate_id in grouped),
        key=sort_key,
    )


def has_evidence(evidence, sub_markers, attribution):
    """수집된 증거에 이번 케이스의 흔적이 잡혔는지 본다"""
    # 정착 대기를 일찍 끊기 위한 값싼 확인이다. 최종 판정은 judge 가 한다.
    if attribution == ATTRIBUTION_TIMING:
        return bool(find_any_evidence(evidence))
    return bool(find_marker_evidence(evidence, sub_markers))


def wait_for_evidence(context, test_case, policy, handle, config):
    """증거가 잡히거나 정착 시간이 다할 때까지 관측을 되풀이한다"""
    # 고정 sleep 을 쓰면 비동기 싱크에서 거짓 음성이 나거나 매번 상한을 꽉 채워
    # 케이스당 수 초를 버린다. 잡히면 즉시 끊는다.
    sub_markers = collect_sub_markers(test_case.bindings)
    deadline = time.time() + policy.settle_ms / 1000.0

    # 폴링은 주 채널만 값싸게 본다. 전체 수집은 마지막에 observe 가 한 번만 한다.
    while time.time() < deadline:
        if has_evidence(policy.poll(context, test_case, handle),
                        sub_markers, test_case.attribution):
            break
        time.sleep(config.poll_interval_ms / 1000.0)

    return policy.observe(context, test_case, handle), sub_markers


def windows_long_path(path):
    """윈도우 MAX_PATH(260자) 제한을 피하려고 \\\\?\\ 접두어를 붙인다

    package/candidate_id/test_case_id 를 이어 붙인 경로는 쉽게 260자를 넘는다.
    접두어를 붙이면 그 제한 없이 그대로 쓰고 읽을 수 있다. 윈도우가 아니면 그대로 돌려준다.
    """
    if os.name != "nt":
        return path
    resolved = os.path.abspath(path)
    if resolved.startswith("\\\\?\\"):
        return resolved
    if resolved.startswith("\\\\"):
        return "\\\\?\\UNC\\" + resolved.lstrip("\\")
    return "\\\\?\\" + resolved


def save_case_evidence(evidence_dir, candidate_id, test_case_id, am_output,
                       logcat_text, channel_evidence):
    """이번 케이스가 남긴 원 증거를 파일로 남기고 (evidence_dir 기준 상대 경로, sha256) 을 돌려준다"""
    directory = os.path.join(evidence_dir, candidate_id)
    os.makedirs(windows_long_path(directory), exist_ok=True)
    path = os.path.join(directory, f"{test_case_id}.txt")
    parts = [f"=== am ===\n{am_output}", f"=== logcat ===\n{logcat_text}"]
    for item in channel_evidence:
        status = "readable" if item.readable else "unreadable"
        parts.append(f"=== {item.channel} ({status}) ===\n{item.text}")
    payload = "\n\n".join(parts).encode("utf-8")
    with open(windows_long_path(path), "wb") as handle:
        handle.write(payload)
    return os.path.relpath(path, evidence_dir), hashlib.sha256(payload).hexdigest()


def run_case(device, sinkhole, env, config, package, candidate, test_case, policy,
            evidence_dir=None):
    """케이스 하나를 준비·실행·관측하고 판정까지 마친다. (판정, 증거 참조, 증거 sha256) 을 돌려준다"""
    context = ExecutionContext(device=device, env=env, package=package,
                               component=candidate.component or "",
                               sinkhole=sinkhole, started_at=time.time())
    handle = policy.setup(context, test_case)

    # 시간창을 좁히려고 setup 직후, am 직전에 비운다.
    clear_result = device.clear_logcat()
    if config.grant_permissions and candidate.permission:
        device.grant(context.package, candidate.permission)

    if not clear_result.succeeded():
        # 못 비웠으면 이전 케이스의 잔재가 이번 도달 증거로 오인될 수 있다. am 을
        # 던지지 않고 정직하게 '못 봤다'로 남긴다 (거짓 reached 보다 낫다).
        policy.teardown(context, handle)
        return Judgement(VERDICT_INCONCLUSIVE,
                         "logcat 비우기 실패 - 이전 케이스 잔재와 구분 불가"), None, None

    am_result = device.run_am(test_case.argv, timeout_ms=config.am_timeout_ms)
    evidence, sub_markers = wait_for_evidence(context, test_case, policy, handle, config)
    logcat_text = device.dump_logcat()

    judgement = judge(am_result.output, logcat_text, evidence, sub_markers,
                      context.package, test_case.attribution)

    policy.teardown(context, handle)

    evidence_ref = None
    evidence_hash = None
    if evidence_dir is not None:
        evidence_ref, evidence_hash = save_case_evidence(
            evidence_dir, candidate.candidate_id, test_case.test_case_id,
            am_result.output, logcat_text, evidence)

    return judgement, evidence_ref, evidence_hash


def inputs_for_markers(test_case, markers):
    """도달이 확인된 서브마커를 그 마커를 심은 입력 이름으로 옮긴다"""
    # 마커는 입력마다 다르므로 "어느 입력이 흘렀나" 까지 되짚을 수 있다.
    found = []
    for binding in test_case.bindings:
        if binding.marker_part and binding.marker_part in markers:
            name = f"{binding.field}:{binding.key}" if binding.key else binding.field
            if name not in found:
                found.append(name)
    return tuple(found)


def run(candidate_set, test_case_set, device, env, config, sinkhole=None, package=None,
        on_progress=None, evidence_dir=None, expected_boot_time=None, expected_boot_id=None):
    """조립된 케이스를 전부 돌려 경로별 결과를 만든다

    on_progress 가 주어지면 후보 하나를 마칠 때마다 그 시점까지의 RunResult 를 넘겨
    부른다. 배치 중간에 죽어도 마지막 체크포인트가 남게 하는 용도다.
    """
    # 앱 패키지는 컴포넌트 클래스명에서 뽑을 수 없다. 둘은 다른 이름이라
    # com.foo.bar.BazService 에서 잘라낸 com.foo.bar 는 설치된 앱이 아니다.
    package = package or candidate_set.apk

    skeleton = build_skeleton(candidate_set, test_case_set)
    results = {item.candidate_id: item for item in skeleton.results}

    grouped = group_cases_by_candidate(test_case_set)
    ordered = order_candidates(candidate_set.get_testable(), grouped)

    verdict_by_case = {}
    pending_restore = REVERSIBILITY_APP_DATA_CLEAR   # 첫 케이스도 깨끗한 상태에서 시작
    executed = 0
    stop_reason = None

    for candidate in ordered:
        if stop_reason:
            break
        policy = get_policy(candidate.sink_rule)
        if policy is None:
            # 1단계가 걸렀어야 하는 경우다. 여기까지 왔다면 사유를 남기고 넘어간다.
            results[candidate.candidate_id] = replace_reason(
                results[candidate.candidate_id], REASON_NO_POLICY)
            continue

        attempts = []
        saw_weak_observation = False
        for test_case in grouped[candidate.candidate_id]:
            if config.max_total_cases and executed >= config.max_total_cases:
                stop_reason = REASON_BUDGET
                break

            # 같은 커맨드가 앞서 돌았으면 그 판정을 그대로 쓴다. dedup 키에 sink_rule
            # 이 들어 있어 관측 조건까지 같으므로 복사가 안전하다.
            if test_case.duplicate_of in verdict_by_case:
                copied = verdict_by_case[test_case.duplicate_of]
                attempts.append(Attempt(test_case.test_case_id,
                                        format_command(test_case.argv), copied.verdict,
                                        inputs=dashboard_inputs(test_case),
                                        detail=copied.detail,
                                        matched_inputs=copied.matched_inputs,
                                        evidence_grade=copied.evidence_grade,
                                        evidence_ref=copied.evidence_ref,
                                        evidence_hash=copied.evidence_hash))
                if config.stop_on_success and copied.verdict == VERDICT_REACHED:
                    break
                continue

            problems = device.check_invariants(
                package=package,
                require_network_off=(env.network_mode == NETWORK_OFF),
                expected_boot_time=expected_boot_time,
                expected_boot_id=expected_boot_id)
            if problems:
                # 봉쇄가 깨진 상태에서 계속 돌리면 안 된다. 케이스가 아니라 실행
                # 전체를 멈춘다.
                stop_reason = f"{REASON_RUN_STOPPED}: {'; '.join(problems)}"
                break

            restore_device(device, package, pending_restore, env)

            if policy.confidence_for(test_case) == CONFIDENCE_WEAK:
                saw_weak_observation = True

            judgement, evidence_ref, evidence_hash = run_case(
                device, sinkhole, env, config, package,
                candidate, test_case, policy, evidence_dir=evidence_dir)
            executed += 1

            # 다음 케이스가 얼마나 되돌려야 하는지는 이번 케이스가 실제로 무엇을
            # 했는지에 달렸다. 아무 데도 닿지 못했으면 지울 것도 없으니 force-stop 이면
            # 된다. pm clear 는 케이스당 1~3초씩 드는데 대부분은 미도달이라 낭비가 크다.
            pending_restore = (policy.reversibility
                               if judgement.verdict == VERDICT_REACHED
                               else REVERSIBILITY_PROCESS_KILL)
            verdict_by_case[test_case.test_case_id] = Attempt(
                test_case.test_case_id, format_command(test_case.argv),
                judgement.verdict,
                inputs=dashboard_inputs(test_case),
                detail=judgement.detail,
                matched_inputs=inputs_for_markers(test_case, judgement.matched_markers),
                evidence_grade=judgement.evidence_grade,
                evidence_ref=evidence_ref,
                evidence_hash=evidence_hash)
            attempts.append(verdict_by_case[test_case.test_case_id])

            # 이 경로가 도달 가능하다는 답이 나왔다. 남은 값 후보는 정보를 더하지 않는다.
            if config.stop_on_success and judgement.verdict == VERDICT_REACHED:
                break

        if attempts:
            filled = apply_attempts(results[candidate.candidate_id], attempts)
            # 관측이 약한 싱크에서 나온 not_reached 는 '안 흘렀다'가 아니라 '못 봤을
            # 수도 있다'이다. 결과에 남겨 그대로 믿지 않게 한다.
            if filled.verdict == VERDICT_NOT_REACHED and saw_weak_observation:
                filled = replace_reason(
                    filled, f"weak_observation/{candidate.sink_rule}")
            results[candidate.candidate_id] = filled

            if on_progress is not None:
                on_progress(RunResult(apk=candidate_set.apk, results=tuple(results.values())))

    if stop_reason:
        results = mark_unrun(results, stop_reason)

    return RunResult(apk=candidate_set.apk, results=tuple(results.values()))


def replace_reason(path_result, reason):
    """경로 결과의 사유만 바꾼 새 객체를 만든다"""
    return PathResult(
        finding_id=path_result.finding_id,
        graph_id=path_result.graph_id,
        path_id=path_result.path_id,
        candidate_id=path_result.candidate_id,
        tested=path_result.tested,
        verdict=path_result.verdict,
        reason=reason,
        attempts=path_result.attempts,
    )


def mark_unrun(results, reason):
    """실행이 멈춰 돌지 못한 경로에 사유를 남긴다"""
    updated = {}
    for candidate_id, item in results.items():
        if not item.tested and item.reason is None:
            updated[candidate_id] = replace_reason(item, reason)
        else:
            updated[candidate_id] = item
    return updated
