import json
import re
import subprocess
import time
from pathlib import Path
import httpx
from xml.etree import ElementTree


PACKAGE_RE = re.compile(
    r"^[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+$"
)
BOUNDS_RE = re.compile(r"^\[(\d+),(\d+)]\[(\d+),(\d+)]$")
PLAY_STORE = "com.android.vending"
UI_DUMP_PATH = "/sdcard/unintent-window.xml"

UI_TIMEOUT = 30.0
INSTALL_TIMEOUT = 300.0
PULL_TIMEOUT = 120.0
POLL_INTERVAL = 2.0
PROJECT_ROOT = Path(__file__).resolve().parents[2]
TARGET_FILE = PROJECT_ROOT / "data" / "apks" / "target.txt"
OUTPUT_DIR = PROJECT_ROOT / "data" / "apks" / "targets"

INSTALL_LABELS = {"install", "설치"}
UPDATE_LABELS = {"update", "업데이트"}
OPEN_LABELS = {"open", "열기"}
SIGN_IN_LABELS = {"sign in", "로그인"}
TERMS_LABELS = {"accept", "동의", "i agree", "동의함"}
INCOMPATIBLE_LABEL_KEYWORDS = (
    "not available on this device",
    "not compatible",
    "device is not supported",
    "device not supported",
    "doesn't support your device",
    "incompatible",
    "이 앱은 이 기기에서 사용할 수 없습니다",
    "이 기기에서 사용할 수 없습니다",
    "이 기기에서 지원되지 않습니다",
    "호환되지 않는",
    "호환되지 않",
)

TOP100_URL = "https://play.google.com/_/PlayStoreUi/data/batchexecute"
TOP100_RPC = "vyAe2"
TOP100_COUNT = 100


def _adb(
    *args: str,
    serial: str | None = None,
    timeout: float = 30.0,
) -> str:
    command = ["adb"]
    if serial:
        command += ["-s", serial]
    command += args

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError(f"ADB execution failed: {exc}") from exc

    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip() or "unknown ADB error"
        raise RuntimeError(
            f"ADB command failed (exit={result.returncode}, command={command!r}): "
            f"{detail}"
        )

    return result.stdout


def _shell(
    *args: str,
    serial: str,
    timeout: float = 30.0,
) -> str:
    return _adb("shell", *args, serial=serial, timeout=timeout)


def _resolve_serial(serial: str | None) -> str:
    if serial:
        return serial

    devices = []
    for line in _adb("devices").splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 2 and parts[1] == "device":
            devices.append(parts[0])

    if not devices:
        raise RuntimeError("No Android device or emulator is connected")
    if len(devices) > 1:
        raise RuntimeError(
            "Multiple Android devices are connected. Pass serial=... explicitly."
        )

    return devices[0]


def load_target_packages(target_file: str | Path) -> list[str]:
    path = Path(target_file)
    if not path.is_file():
        raise FileNotFoundError(f"Target file not found: {path}")

    packages = []

    for line_no, raw_line in enumerate(
        path.read_text(encoding="utf-8").splitlines(),
        start=1,
    ):
        package = raw_line.partition("#")[0].strip()

        if not package:
            continue

        if not PACKAGE_RE.fullmatch(package):
            raise ValueError(
                f"Invalid package name at {path}:{line_no}: {package}"
            )

        packages.append(package)

    return list(dict.fromkeys(packages))


def _build_top100_request(count: int) -> str:
    """
    Build the minimal vyAe2 request body used as the f.req form field.
    """
    args = [
        [
            None,
            [[None, [None, count]], None, None, [113]],
            [2, "topselling_free", "APPLICATION"],
        ]
    ]
    request = [[[TOP100_RPC, json.dumps(args, separators=(",", ":"))]]]

    return json.dumps(request, separators=(",", ":"))


def _parse_top100_response(text: str, expected_count: int) -> list[str]:
    rpc_data = None

    for raw_line in text.splitlines():
        line = raw_line.strip()

        if not line.startswith("["):
            continue

        try:
            frame = json.loads(line)
        except json.JSONDecodeError:
            continue

        if not isinstance(frame, list):
            continue

        for entry in frame:
            if (
                isinstance(entry, list)
                and len(entry) >= 3
                and entry[0] == "wrb.fr"
                and entry[1] == TOP100_RPC
            ):
                rpc_data = entry[2]
                if isinstance(rpc_data, str):
                    try:
                        rpc_data = json.loads(rpc_data)
                    except json.JSONDecodeError as exc:
                        raise RuntimeError(
                            "Google Play returned invalid Top 100 JSON"
                        ) from exc
                break

        if rpc_data is not None:
            break

    if rpc_data is None:
        raise RuntimeError("Google Play Top 100 RPC result not found")

    try:
        entries = rpc_data[0][1][0][28][0]
    except (IndexError, KeyError, TypeError) as exc:
        raise RuntimeError(
            "Google Play Top 100 response structure has changed"
        ) from exc

    packages = []

    for entry in entries:
        try:
            package = entry[0][0][0]
        except (IndexError, KeyError, TypeError) as exc:
            raise RuntimeError("Invalid Google Play Top 100 entry") from exc

        if not isinstance(package, str) or not PACKAGE_RE.fullmatch(package):
            raise RuntimeError(
                f"Invalid package name returned by Google Play: {package}"
            )

        packages.append(package)

    packages = list(dict.fromkeys(packages))

    if len(packages) != expected_count:
        raise RuntimeError(
            f"Google Play returned {len(packages)} unique packages; "
            f"expected {expected_count}"
        )

    return packages


def fetch_top100_packages(
    *,
    country: str = "kr",
    language: str = "ko",
    count: int = TOP100_COUNT,
) -> list[str]:
    """
    Fetch Google Play Top 100 package names using the original httpx stack.
    """
    if count <= 0:
        raise ValueError("count must be greater than 0")

    try:
        response = httpx.post(
            TOP100_URL,
            params={
                "rpcids": TOP100_RPC,
                "source-path": "/store/apps",
                "authuser": "0",
                "soc-app": "121",
                "soc-platform": "1",
                "soc-device": "1",
                "rt": "c",
                "hl": language,
                "gl": country,
            },
            data={"f.req": _build_top100_request(count)},
            headers={
                "Content-Type":
                "application/x-www-form-urlencoded;charset=UTF-8"
            },
            timeout=30.0,
            follow_redirects=True,
        )
        response.raise_for_status()

    except httpx.HTTPError as exc:
        raise RuntimeError(
            f"Google Play Top 100 request failed: {exc}"
        ) from exc

    return _parse_top100_response(response.text, count)


def _dump_ui(serial: str) -> ElementTree.Element:
    _shell(
        "uiautomator",
        "dump",
        UI_DUMP_PATH,
        serial=serial,
    )
    xml = _adb(
        "exec-out",
        "cat",
        UI_DUMP_PATH,
        serial=serial,
    )

    try:
        return ElementTree.fromstring(xml)
    except ElementTree.ParseError as exc:
        raise RuntimeError("UIAutomator returned invalid XML") from exc


def _find_play_store_action(
    root: ElementTree.Element,
) -> tuple[str, ElementTree.Element | None] | None:
    ready = None
    update = None
    install = None
    compatible_error = None

    for node in root.iter("node"):
        labels = {
            value.strip().casefold()
            for value in (
                node.get("text", ""),
                node.get("content-desc", ""),
            )
            if value.strip()
        }

        if compatible_error is None and any(
            any(keyword in label for keyword in INCOMPATIBLE_LABEL_KEYWORDS)
            for label in labels
        ):
            compatible_error = node

        if labels & SIGN_IN_LABELS:
            raise RuntimeError("Google Play Store requires account sign-in")
        if labels & TERMS_LABELS:
            raise RuntimeError(
                "Google Play Store requires manual terms acceptance"
            )

        if ready is None and labels & OPEN_LABELS:
            ready = node
        if update is None and labels & UPDATE_LABELS:
            update = node
        if install is None and labels & INSTALL_LABELS:
            install = node

    # If Open exists, the app is already installed. Skip install/update waiting.
    if ready is not None:
        return "ready", ready
    if compatible_error is not None:
        return "incompatible", compatible_error
    if update is not None:
        return "update", update
    if install is not None:
        return "install", install

    return None


def _wait_for_action(
    serial: str,
    timeout: float = UI_TIMEOUT,
) -> tuple[str, ElementTree.Element]:
    deadline = time.monotonic() + timeout

    while time.monotonic() < deadline:
        action = _find_play_store_action(_dump_ui(serial))

        if action is not None:
            return action

        time.sleep(POLL_INTERVAL)

    raise RuntimeError("Google Play Store action timed out")


def _tap(node: ElementTree.Element, serial: str) -> None:
    match = BOUNDS_RE.fullmatch(node.get("bounds", ""))

    if not match:
        raise RuntimeError(f"Invalid UI bounds: {node.get('bounds')}")

    left, top, right, bottom = map(int, match.groups())

    if right <= left or bottom <= top:
        raise RuntimeError(f"Invalid UI bounds: {node.get('bounds')}")

    _shell(
        "input",
        "tap",
        str((left + right) // 2),
        str((top + bottom) // 2),
        serial=serial,
    )


def _request_install(package: str, serial: str) -> bool | None:
    """
    Returns True when Install/Update was tapped.
    Returns False when the app was already installed.
    Returns None when the app is not compatible with this device.
    """
    _shell(
        "am",
        "start",
        "-a",
        "android.intent.action.VIEW",
        "-d",
        f"market://details?id={package}",
        "-p",
        PLAY_STORE,
        serial=serial,
    )

    action, node = _wait_for_action(serial)

    if action == "ready":
        return False

    if action == "incompatible":
        print(f"[SKIP] {package} -> Not compatible with this device")
        return None

    if action not in {"install", "update"}:
        raise RuntimeError(
            f"Unexpected Play Store action for {package}: {action}"
        )

    _tap(node, serial)
    return True


def _package_is_installed(package: str, serial: str) -> bool:
    """Return whether PackageManager lists the package for the primary user."""
    output = _shell(
        "pm", "list", "packages", "--user", "0", package,
        serial=serial, timeout=20.0,
    )
    return f"package:{package}" in output.splitlines()


def _wait_for_install(package: str, serial: str, timeout: float) -> None:
    """Wait until PackageManager sees the installed package."""
    deadline = time.monotonic() + timeout

    while time.monotonic() < deadline:
        if _package_is_installed(package, serial):
            return
        time.sleep(POLL_INTERVAL)

    raise RuntimeError(f"Timed out waiting for Google Play installation: {package}")


def _pull_apk(package: str, output_dir: Path, serial: str) -> Path:
    output = _shell(
        "pm",
        "path",
        package,
        serial=serial,
    )

    paths = [
        line.removeprefix("package:").strip()
        for line in output.splitlines()
        if line.startswith("package:")
    ]

    if not paths:
        raise RuntimeError(f"APK path not found: {package}")

    remote_path = next(
        (path for path in paths if path.endswith("/base.apk")),
        paths[0],
    )

    output_dir.mkdir(parents=True, exist_ok=True)
    local_path = output_dir / f"{package}.apk"
    temporary_path = local_path.with_suffix(".apk.part")
    temporary_path.unlink(missing_ok=True)
    remote_size = int(
        _shell("stat", "-c", "%s", remote_path, serial=serial).strip()
    )

    try:
        _adb(
            "pull",
            remote_path,
            str(temporary_path),
            serial=serial,
            timeout=PULL_TIMEOUT,
        )

        local_size = temporary_path.stat().st_size
        if local_size != remote_size:
            raise RuntimeError(
                f"ADB pull size mismatch: {package} "
                f"(remote={remote_size}, local={local_size})"
            )

        temporary_path.replace(local_path)
    finally:
        temporary_path.unlink(missing_ok=True)

    return local_path


def download_package(
    package_name: str,
    *,
    serial: str | None = None,
    install_timeout: float = INSTALL_TIMEOUT,
) -> Path:
    """Install one Play Store package and pull its base APK locally."""
    if not PACKAGE_RE.fullmatch(package_name):
        raise ValueError(f"Invalid package name: {package_name}")

    device = _resolve_serial(serial)
    local_path = OUTPUT_DIR / f"{package_name}.apk"
    installed = _package_is_installed(package_name, device)
    if installed and local_path.is_file() and local_path.stat().st_size > 0:
        print(f"[LOCAL] {package_name} -> {local_path}")
        return local_path

    requested = False if installed else _request_install(package_name, device)
    if requested is None:
        raise RuntimeError(f"Package is not compatible with this device: {package_name}")
    if requested:
        print(f"[WAIT] {package_name}")
        _wait_for_install(package_name, device, install_timeout)

    local_path = _pull_apk(package_name, OUTPUT_DIR, device)
    print(f"[PULL] {package_name} -> {local_path}")
    return local_path


def resolve_device_serial(serial: str | None = None) -> str:
    """Resolve the device shared by download, analysis, and cleanup."""
    return _resolve_serial(serial)


def is_package_installed(package: str, serial: str) -> bool:
    """Return whether the package was already present on the selected device."""
    return _package_is_installed(package, serial)


def uninstall_package(package: str, serial: str) -> None:
    """Remove one analyzed package from the selected device."""
    if not _package_is_installed(package, serial):
        return
    try:
        _shell(
            "pm", "uninstall", "--user", "0", package,
            serial=serial, timeout=60.0,
        )
    except RuntimeError:
        pass
    if _package_is_installed(package, serial):
        _adb("uninstall", package, serial=serial, timeout=60.0)
    if _package_is_installed(package, serial):
        raise RuntimeError(f"Package is still installed after cleanup: {package}")


def discover_local_apks() -> list[Path]:
    """Return APKs already present in the downloader output directory."""
    if not OUTPUT_DIR.is_dir():
        raise FileNotFoundError(f"APK target directory does not exist: {OUTPUT_DIR}")

    apk_paths = sorted(OUTPUT_DIR.glob("*.apk"))
    if not apk_paths:
        raise FileNotFoundError(f"No APK files found in {OUTPUT_DIR}")
    return apk_paths


__all__ = [
    "TARGET_FILE",
    "discover_local_apks",
    "download_package",
    "fetch_top100_packages",
    "is_package_installed",
    "load_target_packages",
    "resolve_device_serial",
    "uninstall_package",
]
