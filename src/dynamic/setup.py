from __future__ import annotations

import os
import subprocess
import time
from dataclasses import dataclass

from src.dynamic.adapters.device import Device, build_adb_argv, subprocess_runner
from src.dynamic.environment import NETWORK_OFF


DEFAULT_EMULATOR_ARGS = (
    "-no-audio",
    "-no-boot-anim",
    "-no-snapshot-save",
)

EMULATOR_SERIAL_PREFIX = "emulator-"


@dataclass(frozen=True)
class SetupConfig:
    """0단계 동작을 조절하는 설정"""

    avd_name: str | None = None          
    emulator_binary: str = "emulator"
    headless: bool = True
    boot_timeout_ms: int = 180000
    cache_dir: str = ".cache/value_pool"
    external_pool_path: str | None = None   
    build_value_pool: bool = True
    disable_animations: bool = True
    install_if_missing: bool = True     
    install_timeout_ms: int = 180000
    network_off_timeout_ms: int = 15000


@dataclass
class SetupResult:
    """0단계가 갖춘 것과 남은 문제"""

    device: Device | None = None
    value_pool: object = None           
    package: str | None = None
    problems: tuple = ()
    started_emulator: bool = False
    emulator_process: object = None     
    boot_time: float | None = None      
    boot_id: str | None = None    
    original_state: object = None       

    def ok(self):
        """준비가 끝나 실행해도 되는 상태인지 판별한다"""
        return not self.problems and self.device is not None


def parse_device_list(output):
    """adb devices 출력에서 (식별자, 상태) 목록을 뽑는다"""
    entries = []
    for line in (output or "").splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 2:
            entries.append((parts[0], parts[1]))
    return entries


def pick_emulator_serial(entries, preferred=None):
    """기기 목록에서 쓸 에뮬레이터를 고른다"""
    ready = [serial for serial, state in entries if state == "device"]
    if preferred:
        return preferred if preferred in ready else None
    return ready[0] if ready else None


def pick_device_serial(entries, preferred=None):
    """기기 목록에서 쓸 기기 식별자를 고른다. 실기기가 붙어 있으면 실기기를 먼저 쓴다"""
    ready = [serial for serial, state in entries if state == "device"]
    if preferred:
        return preferred if preferred in ready else None
    for serial in ready:
        if not serial.startswith(EMULATOR_SERIAL_PREFIX):
            return serial
    return pick_emulator_serial(entries)


def list_devices(runner=None, timeout_ms=15000):
    """지금 붙어 있는 기기 목록을 읽는다"""
    runner = runner or subprocess_runner
    return parse_device_list(runner(build_adb_argv(["devices"]), timeout_ms).stdout)



def build_emulator_argv(config):
    """에뮬레이터를 띄울 명령 인자 배열을 만든다"""
    argv = [config.emulator_binary, "-avd", config.avd_name]
    argv.extend(DEFAULT_EMULATOR_ARGS)
    if config.headless:
        argv.append("-no-window")
    return tuple(argv)


def launch_emulator(config):
    """에뮬레이터를 백그라운드로 띄우고 프로세스 핸들을 돌려준다"""
    return subprocess.Popen(
        list(build_emulator_argv(config)),
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )


def wait_for_emulator_serial(config, process=None, runner=None, poll_interval_ms=2000):
    """새로 뜬 에뮬레이터가 목록에 나타날 때까지 기다린다"""
    deadline = time.time() + config.boot_timeout_ms / 1000.0
    while time.time() < deadline:
        serial = pick_emulator_serial(list_devices(runner))
        if serial:
            return serial
        if process is not None and process.poll() is not None:
            return None
        time.sleep(poll_interval_ms / 1000.0)
    return None


def ensure_device(config, env, runner=None):
    """기기를 확보한다. 붙어 있으면 그대로 쓰고 없으면 에뮬레이터를 띄운다"""
    serial = pick_device_serial(list_devices(runner), env.adb_serial)
    if serial:
        return serial, False, None

    if not config.avd_name:
        # 띄울 수단이 없다. 어떤 상태인지 알려주고 호출자가 판단하게 한다.
        return None, False, None

    process = launch_emulator(config)
    serial = wait_for_emulator_serial(config, process, runner)
    return serial, serial is not None, process


def configure_device(device, env, config):
    """봉쇄와 속도 설정을 걸고 문제 목록을 돌려준다"""
    problems = []

    if env.network_mode == NETWORK_OFF:
        device.set_airplane_mode(True)
        device.disable_network()
        is_off, status = device.wait_for_network_off(config.network_off_timeout_ms)
        if not is_off:
            problems.append("네트워크를 껐는데도 꺼진 것으로 확인되지 않는다 "
                            f"({format_network_status(status)})")

    if config.disable_animations:
        device.disable_animations()

    return problems


def format_network_status(status):
    """network_status() 결과(status)를 사유 문자열에 붙일 모양으로 만든다"""
    active = status.get("active_default_network")
    network = "알 수 없음" if active is None else ("있음" if active else "없음")
    return (f"wifi_on={status.get('wifi_on') or '-'}, "
            f"mobile_data={status.get('mobile_data') or '-'}, 기본 네트워크={network}")



def restore_device_state(device, state, timeout_ms=10000):
    """0단계에서 바꾼 기기 설정을 분석 전 상태(state)로 되돌리고 남은 문제 목록을 돌려준다"""
    if device is None or state is None:
        return ["되돌릴 기기나 원래 상태가 없다"]
    try:
        device.restore_state(state)
        mismatches = device.wait_for_state(state, timeout_ms)
    except Exception as error:
        return [f"복원 중 예외가 났다: {type(error).__name__}: {error}"]
    return [f"원래 값으로 돌아오지 않았다: {name}" for name in mismatches]


def ensure_installed(device, apk_path, package, config):
    """대상 앱이 기기에 없으면 APK 를 설치하고 문제 목록을 돌려준다"""
    if not package or not config.install_if_missing:
        return []
    if device.is_installed(package):
        return []
    if not apk_path or not os.path.exists(apk_path):
        return [f"설치할 APK 파일이 없다: {apk_path}"]

    result = device.install_apk(apk_path, config.install_timeout_ms)

    if device.is_installed(package):
        return []
    return [f"APK 설치에 실패했다: {result.output}"]


def prepare_value_pool(apk_path, config):
    """APK 에서 값 풀을 만들거나 캐시·외부 파일에서 읽어 온다"""
    from src.dynamic.adapters.value_pool import load_or_build

    os.makedirs(config.cache_dir, exist_ok=True)
    return load_or_build(apk_path, config.cache_dir, config.external_pool_path)



def prepare(apk_path, env, config=None, package=None, runner=None):
    """에뮬레이터를 확보하고 봉쇄를 건 뒤 값 풀까지 준비한다"""
    config = config or SetupConfig()

    serial, started, process = ensure_device(config, env, runner)
    if serial is None:
        hint = ("avd_name 을 지정하면 직접 띄운다"
                if not config.avd_name else "에뮬레이터가 부팅되지 않았다")
        return SetupResult(problems=(f"쓸 수 있는 기기가 없다 ({hint})",))

    device = Device(serial=serial, runner=runner)

    if not device.wait_for_boot(config.boot_timeout_ms):
        return SetupResult(device=device, problems=("부팅이 끝나지 않았다",),
                           started_emulator=started, emulator_process=process)

    original_state = device.read_state()
    if original_state is None:
        return SetupResult(device=device,
                           problems=("기기 설정을 읽지 못해 분석 뒤 되돌릴 수 없으므로 "
                                     "아무것도 바꾸지 않고 멈춘다",),
                           started_emulator=started, emulator_process=process)
    try:
        problems = list(configure_device(device, env, config))

        pool = None
        if config.build_value_pool and apk_path:
            pool = prepare_value_pool(apk_path, config)
            package = package or getattr(pool, "package", None)

        problems.extend(ensure_installed(device, apk_path, package, config))

        problems.extend(device.check_invariants(
            package=package,
            require_network_off=(env.network_mode == NETWORK_OFF),
        ))

        return SetupResult(
            device=device, value_pool=pool, package=package,
            problems=tuple(problems), started_emulator=started,
            emulator_process=process, boot_time=device.boot_time(),
            boot_id=device.boot_id(), original_state=original_state,
        )
    except BaseException:
        restore_device_state(device, original_state)
        raise


def render_setup_report(result):
    """준비 결과를 사람이 훑어볼 수 있는 요약 문자열로 만든다"""
    lines = []
    if result.device is not None:
        lines.append(f"기기: {result.device.serial or '(기본)'}"
                     f"{' — 우리가 띄움' if result.started_emulator else ''}")
    if result.package:
        lines.append(f"대상 앱: {result.package}")
    if result.value_pool is not None:
        pool = result.value_pool
        lines.append(f"값 풀: 전역 후보 {len(pool.all_values)}개, "
                     f"클래스 색인 {len(pool.class_strings)}개")
    if result.problems:
        lines.append("")
        lines.append("문제")
        for problem in result.problems:
            lines.append(f"  - {problem}")
    else:
        lines.append("준비 완료")
    return "\n".join(lines)