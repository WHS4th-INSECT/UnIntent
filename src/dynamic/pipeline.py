from __future__ import annotations

import json
import os
import logging
from dataclasses import dataclass

from src.dynamic import setup as setup_stage
from src.dynamic.assembly import assemble
from src.dynamic.environment import (
    EnvironmentConfig,
    ExecutionConfig,
    build_assembly_config,
)
from src.dynamic.execution import run as run_cases
from src.dynamic.contracts.run_result import (
    PathResult,
    RunResult,
    VERDICT_NOT_TESTED,
    build_skeleton,
    render_run_report,
)
from src.dynamic.screening import ScreeningConfig, screen
from src.dynamic.adapters.value_pool import empty_value_pool, read_package_name
from src.parsing.androguard_logging import disable_androguard_logs

LOGGER = logging.getLogger(__name__)

REASON_NO_STATIC = "pipeline/static_analysis_missing"
REASON_UNREADABLE_APK = "pipeline/apk_unreadable"
REASON_SETUP_FAILED = "setup_failed"
REASON_PIPELINE_CRASHED = "pipeline/crashed"


@dataclass(frozen=True)
class ProjectLayout:
    """프로젝트 경로 규약. 폴더 구조가 바뀌면 여기만 고친다"""

    root: str = "."
    results_dir: str = "data/results"
    static_filename: str = "static.json"
    dynamic_filename: str = "dynamic.json"

    def package_dir(self, package):
        """패키지 하나의 결과 폴더 경로를 만든다"""
        return os.path.join(self.root, self.results_dir, package)

    def static_path(self, package):
        """정적 분석 결과 파일 경로를 만든다"""
        return os.path.join(self.package_dir(package), self.static_filename)

    def dynamic_path(self, package):
        """동적 검증 결과 파일 경로를 만든다"""
        return os.path.join(self.package_dir(package), self.dynamic_filename)

    def evidence_dir(self, package):
        """케이스별 원 증거 파일을 두는 폴더 경로를 만든다"""
        return os.path.join(self.package_dir(package), "evidence")


def build_failed_result(package, reason, candidate_set=None):
    """실행하지 못한 이유를 담은 결과를 만든다"""
    if candidate_set is not None:
        skeleton = build_skeleton(candidate_set)
        results = tuple(
            item if item.reason else _with_reason(item, reason)
            for item in skeleton.results
        )
        return RunResult(apk=package, results=results)

    return RunResult(apk=package, results=(
        PathResult(finding_id="", graph_id="", path_id="", candidate_id="",
                   tested=False, verdict=VERDICT_NOT_TESTED, reason=reason),
    ))


def _with_reason(path_result, reason):
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


def write_result(result, path):
    """결과를 JSON 파일로 원자적으로 쓴다

    임시 파일에 다 쓰고 나서 os.replace 로 바꿔치기한다. 실행 도중 체크포인트로도
    이 함수를 쓰므로, 쓰는 중간에 죽어도 직전 체크포인트가 깨지지 않고 남는다.
    """
    absolute = os.path.abspath(path)
    os.makedirs(os.path.dirname(absolute), exist_ok=True)
    tmp_path = f"{absolute}.tmp"
    with open(tmp_path, "w", encoding="utf-8") as handle:
        json.dump(result.to_dict(), handle, ensure_ascii=False, indent=2)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(tmp_path, absolute)
    return path


def load_static_analysis(path):
    """정적 분석 결과 JSON 을 읽는다. 없으면 None 을 돌려준다"""
    if not os.path.exists(path):
        return None
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def run_one(apk_path, layout=None, env=None, setup_config=None,
            screening_config=None, execution_config=None, assembly_policy=None,
            sinkhole=None, runner=None):
    """APK 하나의 동적 검증을 끝까지 돌리고 결과 JSON 을 쓴다"""
    disable_androguard_logs()

    layout = layout or ProjectLayout()
    env = env or EnvironmentConfig()
    setup_config = setup_config or setup_stage.SetupConfig()
    screening_config = screening_config or ScreeningConfig()
    execution_config = execution_config or ExecutionConfig()

    try:
        package = read_package_name(apk_path)
    except Exception as error:
        return build_failed_result(
            os.path.basename(apk_path), f"{REASON_UNREADABLE_APK}/{error}")

    dynamic_path = layout.dynamic_path(package)

    data = load_static_analysis(layout.static_path(package))
    if data is None:
        result = build_failed_result(package, REASON_NO_STATIC)
        write_result(result, dynamic_path)
        return result

    candidates = None
    prepared = None
    try:
        candidates = screen(data, screening_config)

        prepared = setup_stage.prepare(apk_path, env, setup_config,
                                       package=package, runner=runner)
        if not prepared.ok():
            result = build_failed_result(
                package, f"{REASON_SETUP_FAILED}/{'; '.join(prepared.problems)}",
                candidates)
        else:
            pool = prepared.value_pool or empty_value_pool(package)
            plan = assemble(candidates, pool,
                            build_assembly_config(env, **(assembly_policy or {})))

            evidence_dir = (layout.evidence_dir(package)
                            if execution_config.capture_evidence else None)

            def checkpoint(partial_result):
                """실행 도중 지금까지의 결과를 원자적으로 써 둔다"""
                write_result(partial_result, dynamic_path)

            try:
                result = run_cases(candidates, plan, prepared.device, env,
                                   execution_config, sinkhole=sinkhole, package=package,
                                   on_progress=checkpoint, evidence_dir=evidence_dir,
                                   expected_boot_time=prepared.boot_time,
                                   expected_boot_id=prepared.boot_id)
            finally:
                prepared.device.force_stop(package)
    except Exception as error:
        result = build_failed_result(
            package,
            f"{REASON_PIPELINE_CRASHED}/{type(error).__name__}: {error}",
            candidates)
    finally:
        if prepared is not None and prepared.original_state is not None:
            restore_problems = setup_stage.restore_device_state(
                prepared.device, prepared.original_state)
            if restore_problems:
                LOGGER.warning("기기 설정을 분석 전 상태로 되돌리지 못했다: %s: %s",
                               package, "; ".join(restore_problems))

    write_result(result, dynamic_path)
    return result


def dynamic_core_run(apk_path, **kwargs):
    """Analyzer 진입점. 실행하지 못했으면 보존된 실패 사유를 예외로 올린다."""
    result = run_one(apk_path, **kwargs)
    if any(item.tested for item in result.results):
        return True
    reasons = sorted({item.reason for item in result.results if item.reason})
    raise RuntimeError("; ".join(reasons) or "실행된 동적 테스트 케이스가 없다")



def main(argv=None):
    """명령줄에서 APK 하나를 돌린다"""
    import argparse

    parser = argparse.ArgumentParser(description="인텐트 흐름 동적 검증")
    parser.add_argument("apk", help="대상 APK 경로")
    parser.add_argument("--root", default=".", help="프로젝트 루트")
    parser.add_argument("--avd", default=None, help="띄울 AVD 이름")
    parser.add_argument("--serial", default=None, help="쓸 기기 식별자")
    parser.add_argument("--no-stop-on-success", action="store_true",
                        help="경로가 도달해도 남은 값 후보를 전부 시도한다")
    parsed = parser.parse_args(argv)

    result = run_one(
        parsed.apk,
        layout=ProjectLayout(root=parsed.root),
        env=EnvironmentConfig(adb_serial=parsed.serial),
        setup_config=setup_stage.SetupConfig(avd_name=parsed.avd),
        execution_config=ExecutionConfig(
            stop_on_success=not parsed.no_stop_on_success),
    )

    print(render_run_report(result))
    return 0 if any(item.tested for item in result.results) else 1


if __name__ == "__main__":
    raise SystemExit(main())