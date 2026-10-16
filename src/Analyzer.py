from __future__ import annotations

import logging
import math
import uuid
from contextlib import ExitStack
from pathlib import Path
from src.dynamic.environment import EnvironmentConfig
from src.dynamic.pipeline import ProjectLayout, dynamic_core_run as run_dynamic_analysis
from src.dynamic.setup import SetupConfig
from src.logging_utils import configure_logging
from src.notifications.discord import notify_analysis_result
from src.parsing.androguard_parser import parse_apk
from src.static.model.flow_spool import FlowGraphSpool
from src.static.model.evidence import AnalysisResult
from src.static.pipeline import run_static_analysis
from src.static.report.json_report import write_json_report
from tools.apk.download_apks import (
    TARGET_FILE,
    discover_local_apks,
    download_package,
    fetch_top100_packages,
    is_package_installed,
    load_target_packages,
    resolve_device_serial,
    uninstall_package,
)

LOGGER = logging.getLogger(__name__)
DEFAULT_STATIC_TIMEOUT_SECONDS: float | None = None
DEFAULT_STATIC_MAX_CALL_DEPTH = 10
PROJECT_ROOT = Path(__file__).resolve().parents[1]
STATIC_RESULT_DIRECTORY = PROJECT_ROOT / "data" / "results"
DYNAMIC_VALUE_POOL_CACHE_DIRECTORY = PROJECT_ROOT / ".cache" / "value_pool"


class Analyzer:
    def __init__(
        self,
        download: bool,
        top100: bool,
        timeout_seconds: float | None = DEFAULT_STATIC_TIMEOUT_SECONDS,
        max_call_depth: int = DEFAULT_STATIC_MAX_CALL_DEPTH,
    ):
        """Initialize the analyzer with APK acquisition and static analysis options."""
        if download and top100:
            raise ValueError("download and top100 cannot both be enabled")
        if timeout_seconds is not None and (
            not math.isfinite(timeout_seconds) or timeout_seconds <= 0
        ):
            raise ValueError("timeout_seconds must be a positive finite number")
        if max_call_depth < 0:
            raise ValueError("max_call_depth must not be negative")
        self.download = download
        self.top100 = top100
        self.timeout_seconds = timeout_seconds
        self.max_call_depth = max_call_depth
        self.dynamic_layout = ProjectLayout(root=str(PROJECT_ROOT))
        self.dynamic_setup_config = SetupConfig(
            cache_dir=str(DYNAMIC_VALUE_POOL_CACHE_DIRECTORY),
        )
        self.analysis_run_id = uuid.uuid4().hex
        self.dynamic_environment = EnvironmentConfig()
        self.last_dynamic_error: str | None = None
        self.failed = False

    def run(self) -> int:
        """Run the complete APK analysis workflow and return its exit status."""
        configure_logging()
        if self.top100:
            print("[TOP100] Fetching Google Play Top 100")
            packages = fetch_top100_packages()
            print(f"[TOP100] Loaded {len(packages)} packages")
            self.run_downloaded_packages(packages)
        elif self.download:
            self.run_downloaded_packages(load_target_packages(TARGET_FILE))
        else:
            apk_paths = discover_local_apks()
            if not apk_paths:
                print("[ERROR] No APKs are available for analysis")
                return 1
            for apk_path in apk_paths:
                if not self.analyze_apk(apk_path):
                    self.failed = True
        return 1 if self.failed else 0

    def run_downloaded_packages(self, packages: list[str]) -> None:
        """Download, analyze, and remove one successfully analyzed package at a time."""
        if not packages:
            print("[ERROR] No packages are available for download")
            self.failed = True
            return

        serial = resolve_device_serial()
        self.dynamic_environment = EnvironmentConfig(adb_serial=serial)
        for index, package in enumerate(packages, start=1):
            print(f"[PACKAGE {index}/{len(packages)}] {package}")
            installed_before = True
            analysis_succeeded = False
            try:
                installed_before = is_package_installed(package, serial)
                apk_path = download_package(package, serial=serial)
                analysis_succeeded = self.analyze_apk(apk_path)
                if not analysis_succeeded:
                    self.failed = True
            except Exception as exception:  # Continue with the remaining packages.
                print(f"[PACKAGE ERROR] {package}: {exception}")
                self.failed = True
            finally:
                if not installed_before and analysis_succeeded:
                    try:
                        print(f"[CLEANUP] Removing analyzed package: {package}")
                        uninstall_package(package, serial)
                    except RuntimeError as exception:
                        print(f"[CLEANUP ERROR] {package}: {exception}")
                        self.failed = True
                elif not installed_before:
                    print(f"[CLEANUP] Keeping package after analysis failure: {package}")

    def analyze_apk(self, apk_path: Path) -> bool:
        """Run static analysis first and dynamic analysis only when it succeeds."""
        static_result_path = self.static_core_run(apk_path)
        if static_result_path is None:
            return False

        dynamic_succeeded = self.dynamic_core_run(apk_path, static_result_path)
        dynamic_result_path = static_result_path.with_name("dynamic.json")
        print(f"[NOTIFY] Sending analysis result: {apk_path.name}")
        notified = notify_analysis_result(
            apk_path=apk_path,
            static_result_path=static_result_path,
            dynamic_result_path=(
                dynamic_result_path if dynamic_result_path.is_file() else None
            ),
            analysis_run_id=self.analysis_run_id,
            dynamic_error=(
                None if dynamic_succeeded else self.last_dynamic_error
            ),
        )
        if not notified:
            print(f"[NOTIFY] Skipped or failed: {apk_path.name}")
        return dynamic_succeeded

    def static_core_run(self, apk_path: Path) -> Path | None:
        """Parse one APK, run the static core, and save its graph report."""
        print(f"[ANALYZE] {apk_path}")
        try:
            context = parse_apk(apk_path)
        except Exception as exception:
            error_message = f"APK parsing failed: {type(exception).__name__}: {exception}"
            print(f"[PARSE ERROR] {error_message}")
            notify_analysis_result(
                apk_path=apk_path,
                static_result_path=None,
                dynamic_result_path=None,
                analysis_run_id=self.analysis_run_id,
                static_error=error_message,
            )
            return None
        with ExitStack() as resources:
            try:
                flow_graph_store = resources.enter_context(
                    FlowGraphSpool(
                        STATIC_RESULT_DIRECTORY / context.metadata.package_name,
                        flush_every=1,
                    )
                )
                result = run_static_analysis(
                    context=context,
                    timeout_seconds=self.timeout_seconds,
                    max_call_depth=self.max_call_depth,
                    flow_graph_store=flow_graph_store,
                )
            except Exception as exception:
                error_message = f"{type(exception).__name__}: {exception}"
                print(f"[STATIC ERROR] {error_message}")
                notify_analysis_result(
                    apk_path=apk_path,
                    static_result_path=None,
                    dynamic_result_path=None,
                    analysis_run_id=self.analysis_run_id,
                    static_error=error_message,
                )
                return None

            if result is None:
                error_message = "Static analysis failed before static.json was created"
                print(f"[STATIC ERROR] {error_message}")
                notify_analysis_result(
                    apk_path=apk_path,
                    static_result_path=None,
                    dynamic_result_path=None,
                    analysis_run_id=self.analysis_run_id,
                    static_error=error_message,
                )
                return None

            try:
                output_path = self.static_result_save(result, context.metadata.package_name)
            except (OSError, TypeError, ValueError) as exception:
                error_message = f"Failed to save static.json: {exception}"
                print(f"[STATIC RESULT ERROR] {exception}")
                notify_analysis_result(
                    apk_path=apk_path,
                    static_result_path=None,
                    dynamic_result_path=None,
                    analysis_run_id=self.analysis_run_id,
                    static_error=error_message,
                )
                return None

            LOGGER.info("Static analysis succeeded: package=%s", context.metadata.package_name)
            return output_path

    def static_result_save(
        self,
        result: AnalysisResult,
        package_name: str,
    ) -> Path:
        """Save one complete static graph under data/results/{package_name}."""
        result_directory = STATIC_RESULT_DIRECTORY / package_name
        output_path = result_directory / "static.json"
        write_json_report(result, output_path)
        return output_path

    def dynamic_core_run(
        self,
        apk_path: Path,
        static_result_path: Path,
    ) -> bool:
        """Run dynamic validation and report whether at least one case was tested."""
        print(f"[DYNAMIC] {apk_path}")
        self.last_dynamic_error = None

        dynamic_result_path = static_result_path.with_name(
            self.dynamic_layout.dynamic_filename
        )

        try:
            dynamic_result_path.unlink(missing_ok=True)
        except OSError as exception:
            self.last_dynamic_error = f"Failed to clear previous dynamic.json: {exception}"
            print(f"[DYNAMIC ERROR] {self.last_dynamic_error}")

            return False

        try:
            succeeded = run_dynamic_analysis(
                apk_path,
                layout=self.dynamic_layout,
                env=self.dynamic_environment,
                setup_config=self.dynamic_setup_config,
            )
        except Exception as exception:
            self.last_dynamic_error = f"{type(exception).__name__}: {exception}"
            print(f"[DYNAMIC ERROR] 동적분석에 실패했습니다: {apk_path}: {exception}")
            LOGGER.exception("Dynamic analysis failed: apk=%s", apk_path)
            return False

        if not dynamic_result_path.is_file():
            self.last_dynamic_error = "dynamic.json was not created"
            print(f"[DYNAMIC ERROR] {self.last_dynamic_error}: {apk_path}")
            return False

        if not succeeded:
            self.last_dynamic_error = "No dynamic test case was executed"
            print(f"[DYNAMIC ERROR] 동적분석에 실패했습니다: {apk_path}")
            return False

        LOGGER.info(
            "Dynamic analysis executed at least one test case: apk=%s",
            apk_path,
        )

        return True
