from __future__ import annotations

import os
import re
import shlex
import subprocess
import tempfile
import time
from dataclasses import dataclass


ALLOWED_WRITE_ROOTS = (
    "/sdcard/",
    "/storage/emulated/0/",
    "/data/local/tmp/",
)

DEFAULT_INSTALL_TIMEOUT_MS = 180000

ANIMATION_SCALE_SETTINGS = (
    "window_animation_scale",
    "transition_animation_scale",
    "animator_duration_scale",
)


WIFI_ON_VALUES = ("1", "2")
WIFI_OFF_VALUES = ("", "0", "3", "null", "none")

MOBILE_DATA_SETTING = re.compile(r"^mobile_data\d*$")
ACTIVE_DEFAULT_NETWORK_PREFIX = "Active default network:"
COMMAND_ERROR_WORDS = ("unknown", "error", "exception", "usage", "can't find",
                       "not found", "no shell command")

class UnsafePathError(Exception):
    """허용되지 않은 경로에 파괴적 연산을 시도했을 때 난다"""


@dataclass(frozen=True)
class CommandResult:
    """명령 하나의 실행 결과"""

    argv: tuple
    returncode: int
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False

    @property
    def output(self):
        """표준 출력과 표준 에러를 합쳐 돌려준다"""
        return f"{self.stdout}\n{self.stderr}".strip()

    def succeeded(self):
        """명령이 정상 종료했는지 판별한다"""
        return self.returncode == 0 and not self.timed_out



def is_safe_write_path(path):
    """파일을 쓰거나 지워도 되는 경로인지 판별한다"""
    if not path or not path.startswith("/"):
        return False
    if ".." in path.split("/"):
        return False
    return any(path.startswith(root) for root in ALLOWED_WRITE_ROOTS)


def assert_safe_write_path(path):
    """허용되지 않은 경로면 예외를 던져 파괴적 연산을 막는다"""
    if not is_safe_write_path(path):
        raise UnsafePathError(
            f"쓰기/삭제가 허용되지 않은 경로: {path!r} "
            f"(허용: {', '.join(ALLOWED_WRITE_ROOTS)})"
        )


def build_adb_argv(args, serial=None):
    """adb 명령의 전체 인자 배열을 만든다"""
    prefix = ["adb"]
    if serial:
        prefix += ["-s", serial]
    return tuple(prefix + list(args))


def build_shell_argv(command_parts, serial=None):
    """기기 셸에서 실행할 명령을 따옴표까지 붙여 adb 인자 배열로 만든다"""
    joined = " ".join(shlex.quote(str(part)) for part in command_parts)
    return build_adb_argv(["shell", joined], serial)


def parse_getprop(output):
    """getprop 한 줄 출력에서 값을 다듬어 돌려준다"""
    return (output or "").strip()


def parse_file_exists(output, path):
    """ls 출력에서 해당 경로(path)가 실제로 있는지 읽는다"""
    text = output or ""
    if "No such file" in text or "not found" in text:
        return False
    return path in text


def parse_process_names(output):
    """ps 출력에서 프로세스 이름 집합을 뽑는다"""
    names = set()
    for line in (output or "").splitlines()[1:]:
        parts = line.split()
        if parts:
            names.add(parts[-1])
    return names


def parse_network_off(wifi_on, mobile_data):
    """settings 출력으로 네트워크가 꺼져 있는지 읽는다"""
    def is_off(value):
        """설정 값(value)이 꺼짐을 뜻하는지 판별한다"""
        text = (value or "").strip().lower()
        return text in ("", "0", "null", "none")

    return parse_wifi_off(wifi_on) and is_off(mobile_data)

def parse_wifi_off(wifi_on):
    """settings 의 wifi_on 값(wifi_on)이 와이파이 꺼짐을 뜻하는지 판별한다"""
    return (wifi_on or "").strip().lower() in WIFI_OFF_VALUES

def parse_active_default_network(output):
    """dumpsys connectivity 출력에서 기본 네트워크가 살아 있는지 읽는다. 판단할 수 없으면 None"""
    for line in (output or "").splitlines():
        text = line.strip()
        if text.startswith(ACTIVE_DEFAULT_NETWORK_PREFIX):
            value = text[len(ACTIVE_DEFAULT_NETWORK_PREFIX):].strip().lower()
            return value not in ("", "none", "null")
    return None

def parse_global_settings(output):
    """settings list global 출력을 이름→값 dict 로 만든다"""
    settings = {}
    for line in (output or "").splitlines():
        name, separator, value = line.partition("=")
        if separator:
            settings[name.strip()] = value.strip()
    return settings


def parse_device_state(settings):
    """전역 설정 dict(settings)에서 분석 뒤 되돌릴 기기 상태를 뽑는다. 비어 있으면 None"""
    if not settings:
        return None
    airplane = settings.get("airplane_mode_on")
    wifi = settings.get("wifi_on")
    data_values = [value for name, value in settings.items()
                   if MOBILE_DATA_SETTING.match(name)]
    return DeviceState(
        airplane_mode_on=None if airplane is None else airplane == "1",
        wifi_on=None if wifi is None else wifi in WIFI_ON_VALUES,
        mobile_data_on=not data_values or "1" in data_values,
        animation_scales=tuple(
            (name, settings.get(name, "")) for name in ANIMATION_SCALE_SETTINGS),
    )

def normalize_setting(value):
    """설정 값(value)의 '값 없음' 표현(빈 문자열, null)을 하나로 맞춘다"""
    text = (value or "").strip()
    return "" if text.lower() == "null" else text


def find_state_mismatches(expected, actual):
    """되돌리려던 상태(expected)와 지금 상태(actual)가 다른 항목 이름을 돌려준다"""
    if actual is None:
        return ["기기 설정을 다시 읽지 못했다"]
    mismatches = []
    if (expected.airplane_mode_on is not None
            and expected.airplane_mode_on != actual.airplane_mode_on):
        mismatches.append("airplane_mode_on")
    if expected.wifi_on is not None and expected.wifi_on != actual.wifi_on:
        mismatches.append("wifi_on")
    current_scales = dict(actual.animation_scales)
    for name, value in expected.animation_scales:
        if normalize_setting(value) != normalize_setting(current_scales.get(name)):
            mismatches.append(name)
    return mismatches

def parse_package_uid(output, package):
    """pm list packages -U 출력에서 패키지(package)의 UID 를 읽는다. 없으면 None"""
    for line in (output or "").splitlines():
        parts = line.split()
        if parts and parts[0] == f"package:{package}":
            for part in parts[1:]:
                if part.startswith("uid:"):
                    return part[len("uid:"):].split(",")[0] or None
    return None

def command_failed(result):
    """셸 명령이 실패했거나 지원되지 않는 명령이었는지 판별한다"""
    text = result.output.lower()
    return not result.succeeded() or any(word in text for word in COMMAND_ERROR_WORDS)

def subprocess_runner(argv, timeout_ms):
    """실제 subprocess 로 명령을 돌려 결과를 돌려준다"""
    try:
        completed = subprocess.run(
            list(argv), capture_output=True, text=True,
            encoding="utf-8", errors="replace",
            timeout=max(timeout_ms, 1) / 1000.0,
        )
        return CommandResult(tuple(argv), completed.returncode,
                             completed.stdout or "", completed.stderr or "")
    except subprocess.TimeoutExpired:
        return CommandResult(tuple(argv), -1, "", "timeout", timed_out=True)
    except FileNotFoundError as error:
        return CommandResult(tuple(argv), -1, "", str(error))

@dataclass(frozen=True)
class DeviceState:
    """동적 분석 전에 읽어 둔 기기 설정. 분석이 끝나면 이 상태로 되돌린다"""

    airplane_mode_on: bool | None = False   
    wifi_on: bool | None = True
    mobile_data_on: bool = True
    animation_scales: tuple = ()


class Device:
    """adb 로 기기 하나를 다룬다"""

    def __init__(self, serial=None, runner=None, default_timeout_ms=15000):
        """기기 식별자와 명령 러너를 받아 준비한다"""
        self.serial = serial
        self.runner = runner or subprocess_runner
        self.default_timeout_ms = default_timeout_ms

    def adb(self, args, timeout_ms=None):
        """adb 명령을 그대로 실행한다"""
        return self.runner(build_adb_argv(args, self.serial),
                           timeout_ms or self.default_timeout_ms)

    def shell(self, command_parts, timeout_ms=None):
        """기기 셸에서 명령을 실행한다"""
        return self.runner(build_shell_argv(command_parts, self.serial),
                           timeout_ms or self.default_timeout_ms)

    def getprop(self, name):
        """기기 속성(name) 값을 읽는다"""
        return parse_getprop(self.shell(["getprop", name]).stdout)

    def is_connected(self):
        """기기가 붙어 있고 명령을 받을 수 있는지 판별한다"""
        return self.adb(["get-state"]).stdout.strip() == "device"

    def read_state(self):
        """분석 뒤 되돌릴 항공기 모드·네트워크·애니메이션 설정을 읽는다. 읽지 못하면 None"""
        result = self.shell(["settings", "list", "global"])
        if not result.succeeded():
            return None
        return parse_device_state(parse_global_settings(result.stdout))

    def restore_state(self, state):
        """read_state() 로 읽어 둔 상태(state)로 기기 설정을 되돌린다"""
        if state.airplane_mode_on is not None:
            self.set_airplane_mode(state.airplane_mode_on)
        if state.wifi_on is not None:
            self.shell(["svc", "wifi", "enable" if state.wifi_on else "disable"])
        self.shell(["svc", "data", "enable" if state.mobile_data_on else "disable"])
        for name, value in state.animation_scales:
            if value and value.lower() != "null":
                self.shell(["settings", "put", "global", name, value])
            else:
                self.shell(["settings", "delete", "global", name])


    def wait_for_state(self, state, timeout_ms=10000, poll_interval_ms=1000):
        """기기 설정이 상태(state)와 같아질 때까지 기다리고 끝내 다른 항목을 돌려준다"""
        # 와이파이는 svc 명령 뒤 설정 값이 바뀌기까지 몇 초 걸린다.
        deadline = time.time() + timeout_ms / 1000.0
        while True:
            mismatches = find_state_mismatches(state, self.read_state())
            if not mismatches or time.time() >= deadline:
                return mismatches
            time.sleep(poll_interval_ms / 1000.0)
            
    def disable_network(self):
        """와이파이와 모바일 데이터를 꺼서 나갈 경로를 없앤다"""
        results = [self.shell(["svc", "wifi", "disable"]),
                   self.shell(["svc", "data", "disable"])]
        return results

    def enable_network(self):
        """동적 분석이 끝난 뒤 와이파이와 모바일 데이터를 다시 켠다"""
        results = [self.shell(["svc", "wifi", "enable"]),
                   self.shell(["svc", "data", "enable"])]
        return results

    def network_status(self):
        """와이파이 설정과 실제 기본 네트워크 유무를 읽어 dict 로 돌려준다"""
        return {
            "wifi_on": self.shell(["settings", "get", "global", "wifi_on"]).stdout.strip(),
            "mobile_data": self.shell(
                ["settings", "get", "global", "mobile_data"]).stdout.strip(),
            "active_default_network": parse_active_default_network(
                self.dumpsys("connectivity")),
        }

    def network_is_off(self, status=None):
        """네트워크가 실제로 꺼져 있는지 확인한다."""
        status = status or self.network_status()
        active = status["active_default_network"]
        if active is None:
            return parse_network_off(status["wifi_on"], status["mobile_data"])
        return parse_wifi_off(status["wifi_on"]) and not active


    def wait_for_network_off(self, timeout_ms=15000, poll_interval_ms=1000):
        """네트워크가 실제로 내려갈 때까지 기다리고 마지막 상태를 돌려준다"""
        deadline = time.time() + timeout_ms / 1000.0
        while True:
            status = self.network_status()
            if self.network_is_off(status) or time.time() >= deadline:
                return self.network_is_off(status), status
            time.sleep(poll_interval_ms / 1000.0)

    def boot_time(self):
        """기기가 마지막으로 부팅된 시각을 추정한다. 재부팅 여부를 판별하는 데 쓴다"""
        output = self.shell(["cat", "/proc/uptime"]).stdout.strip()
        try:
            uptime_seconds = float(output.split()[0])
        except (ValueError, IndexError):
            return None
        return time.time() - uptime_seconds

    def boot_id(self):
        """부팅마다 커널이 새로 발급하는 고유 식별자를 읽는다. boot_time 근사치의 정확한 보조 확인용"""
        output = self.shell(["cat", "/proc/sys/kernel/random/boot_id"]).stdout.strip()
        return output or None

    def check_invariants(self, package=None, require_network_off=False, 
                         expected_boot_time=None, expected_boot_id=None):
        """케이스 실행 전에 지켜져야 할 환경 조건을 확인해 문제 목록을 돌려준다"""
        problems = []
        if not self.is_connected():
            problems.append("기기가 연결되어 있지 않다")
            return problems          
        
        if package and not self.is_installed(package):
            problems.append(f"대상 앱이 설치되어 있지 않다: {package}")

        if require_network_off and not self.network_is_off():
            problems.append("네트워크가 켜져 있다")

        if expected_boot_time is not None:
            current = self.boot_time()
            if current is None or abs(current - expected_boot_time) > 5:
                problems.append("기기가 중간에 재부팅된 것으로 보인다 (가동시간 불일치)")

        if expected_boot_id is not None:
            current_id = self.boot_id()
            if current_id is not None and current_id != expected_boot_id:
                problems.append("기기가 중간에 재부팅된 것으로 보인다 (boot_id 불일치)")
                
        return problems

    def set_airplane_mode(self, enabled):
        """항공기 모드를 켜거나(enabled) 끈다"""
        state = "enable" if enabled else "disable"
        result = self.shell(["cmd", "connectivity", "airplane-mode", state])
        if not command_failed(result):
            return result
        self.shell(["settings", "put", "global", "airplane_mode_on", "1" if enabled else "0"])
        return self.shell(["am", "broadcast", "-a", "android.intent.action.AIRPLANE_MODE",
                           "--ez", "state", "true" if enabled else "false"])

    def disable_animations(self):
        """화면 전환 애니메이션을 꺼서 액티비티 기동을 빠르게 한다"""
        results = []
        for name in ANIMATION_SCALE_SETTINGS:
            results.append(self.shell(["settings", "put", "global", name, "0"]))
        return results

    def wait_for_boot(self, timeout_ms=180000, poll_interval_ms=1000):
        """부팅이 끝날 때까지 기다린다"""
        deadline = time.time() + timeout_ms / 1000.0
        while time.time() < deadline:
            if (self.getprop("sys.boot_completed") == "1"
                    and self.getprop("init.svc.bootanim") in ("stopped", "")):
                return True
            time.sleep(poll_interval_ms / 1000.0)
        return False

    def force_stop(self, package):
        """앱 프로세스를 종료한다"""
        return self.shell(["am", "force-stop", package])

    def clear_data(self, package):
        """앱 데이터를 지운다"""
        return self.shell(["pm", "clear", package])

    def load_snapshot(self, name):
        """에뮬레이터 스냅샷을 복원한다"""
        return self.adb(["emu", "avd", "snapshot", "load", name], timeout_ms=120000)

    def clear_logcat(self):
        """logcat 버퍼를 비운다. 케이스 실행 직전에 부른다"""
        return self.shell(["logcat", "-c"])

    def dump_logcat(self, timeout_ms=None):
        """지금까지 쌓인 logcat 을 통째로 읽는다"""
        return self.shell(["logcat", "-d", "-v", "threadtime"],
                          timeout_ms or self.default_timeout_ms).stdout

    def run_am(self, am_argv, timeout_ms=None):
        """2단계가 만든 am 인자 배열을 그대로 실행한다"""
        return self.shell(list(am_argv), timeout_ms)

    def grant(self, package, permission):
        """앱에 권한을 부여한다"""
        return self.shell(["pm", "grant", package, permission])

    def file_exists(self, path):
        """파일이 있는지 확인한다"""
        return parse_file_exists(self.shell(["ls", "-d", path]).output, path)

    def write_file(self, path, content="canary\n"):
        """카나리 파일을 만든다. 허용된 경로에만 쓴다"""
        assert_safe_write_path(path)
        with tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8") as handle:
            handle.write(content)
            local_path = handle.name
        try:
            return self.adb(["push", local_path, path])
        finally:
            os.unlink(local_path)

    def remove_file(self, path):
        """카나리 파일을 지운다. 허용된 경로에만 지운다"""
        assert_safe_write_path(path)
        return self.shell(["rm", "-f", path])

    def file_checksum(self, path):
        """파일 내용의 체크섬을 읽는다. 없으면 None 을 돌려준다"""
        result = self.shell(["md5sum", path])
        text = result.stdout.strip()
        if not text or "No such file" in result.output:
            return None
        return text.split()[0]

    def file_state(self, path):
        """파일의 존재 여부와 체크섬을 한 쌍으로 읽는다"""
        checksum = self.file_checksum(path)
        return (checksum is not None, checksum)

    def content_query(self, uri, timeout_ms=None):
        """ContentProvider 를 셸에서 조회한다. 권한이 없으면 빈 결과가 온다"""
        return self.shell(["content", "query", "--uri", uri], timeout_ms)

    def dumpsys(self, section, timeout_ms=None):
        """dumpsys 섹션을 읽는다"""
        return self.shell(["dumpsys", section], timeout_ms).stdout

    def process_names(self):
        """지금 돌고 있는 프로세스 이름 집합을 읽는다"""
        return parse_process_names(self.shell(["ps", "-A"]).stdout)

    def is_installed(self, package):
        """앱이 설치되어 있는지 판별한다"""
        result = self.shell(["pm", "list", "packages", package])
        return any(line.strip() == f"package:{package}"
                   for line in result.stdout.splitlines())

    def package_uid(self, package):
        """앱의 UID 를 읽는다. 읽지 못하면 None"""
        return parse_package_uid(
            self.shell(["pm", "list", "packages", "-U", package]).stdout, package)

    def install_apk(self, apk_path, timeout_ms=None):
        """APK 를 기기에 설치한다. 이미 있으면 덮어쓴다"""
        return self.adb(["install", "-r", str(apk_path)],
                        timeout_ms or DEFAULT_INSTALL_TIMEOUT_MS)