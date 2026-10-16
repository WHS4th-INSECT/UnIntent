from __future__ import annotations

import os
import platform
import queue
import select
import shutil
import signal
import struct
import subprocess
import threading
import uuid
from pathlib import Path
from typing import Any

if os.name != "nt":
    import pty
else:
    pty = None


class AndroidRuntime:
    def __init__(self) -> None:
        """Resolve the local Android SDK tools used by emulator API calls."""
        self.sdk_root = self._find_sdk_root()
        self.adb_path = self._find_tool("platform-tools", "adb")
        self.emulator_path = self._find_tool("emulator", "emulator")
        self.started_processes: dict[str, subprocess.Popen[Any]] = {}

    def _find_sdk_root(self) -> Path | None:
        """Find the Android SDK root from environment variables and platform defaults."""
        configured = os.environ.get("ANDROID_SDK_ROOT") or os.environ.get("ANDROID_HOME")
        candidates = [Path(configured).expanduser()] if configured else []
        system = platform.system()
        if system == "Darwin":
            candidates.append(Path.home() / "Library" / "Android" / "sdk")
        elif system == "Windows":
            local_app_data = os.environ.get("LOCALAPPDATA")
            if local_app_data:
                candidates.append(Path(local_app_data) / "Android" / "Sdk")
        else:
            candidates.append(Path.home() / "Android" / "Sdk")
        return next((item.resolve() for item in candidates if item.exists()), None)

    def _find_tool(self, folder: str, name: str) -> Path | None:
        """Resolve one Android SDK executable by folder and command name."""
        executable = f"{name}.exe" if platform.system() == "Windows" else name
        if self.sdk_root:
            candidate = self.sdk_root / folder / executable
            if candidate.exists():
                return candidate
        discovered = shutil.which(executable)
        return Path(discovered).resolve() if discovered else None

    def status(self) -> dict[str, Any]:
        """Return local SDK availability and the current operating system."""
        return {
            "platform": platform.system().lower(),
            "sdk_root": str(self.sdk_root) if self.sdk_root else None,
            "adb_path": str(self.adb_path) if self.adb_path else None,
            "emulator_path": str(self.emulator_path) if self.emulator_path else None,
            "available": bool(self.adb_path and self.emulator_path),
        }

    def list_avds(self) -> list[str]:
        """List Android Virtual Devices registered in the local SDK."""
        if not self.emulator_path:
            return []
        result = subprocess.run(
            [str(self.emulator_path), "-list-avds"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        return [line.strip() for line in result.stdout.splitlines() if line.strip()]

    def _avd_name_for_serial(self, serial: str) -> str | None:
        """Resolve the AVD name behind one emulator serial."""
        if not self.adb_path or not serial.startswith("emulator-"):
            return None
        try:
            result = subprocess.run(
                [str(self.adb_path), "-s", serial, "emu", "avd", "name"],
                capture_output=True,
                text=True,
                timeout=3,
                check=False,
            )
        except subprocess.SubprocessError:
            return None
        if result.returncode:
            return None
        return next(
            (
                line.strip()
                for line in result.stdout.splitlines()
                if line.strip() and line.strip() not in {"OK", "KO"}
            ),
            None,
        )

    def _list_device_rows(self) -> list[dict[str, str | None]]:
        """Read connected ADB devices without querying emulator console metadata."""
        if not self.adb_path:
            return []
        result = subprocess.run(
            [str(self.adb_path), "devices", "-l"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        devices = []
        for line in result.stdout.splitlines()[1:]:
            if not line.strip():
                continue
            parts = line.split()
            if len(parts) < 2:
                continue
            metadata = {
                key: value for item in parts[2:] if ":" in item
                for key, value in [item.split(":", 1)]
            }
            devices.append({
                "serial": parts[0],
                "state": parts[1],
                "model": metadata.get("model", "Android device"),
                "device": metadata.get("device", ""),
                "avd_name": None,
            })
        return devices

    def list_devices(self) -> list[dict[str, str | None]]:
        """List ADB devices and attach the AVD name for each emulator."""
        devices = self._list_device_rows()
        for device in devices:
            device["avd_name"] = self._avd_name_for_serial(str(device["serial"]))
        return devices

    def _validate_device(self, serial: str) -> None:
        """Reject input commands for devices that are not currently connected."""
        valid_serials = {
            str(item["serial"])
            for item in self._list_device_rows()
            if item["state"] == "device"
        }
        if serial not in valid_serials:
            raise ValueError("Unknown or offline device serial")

    def _send_input(self, serial: str, *arguments: str) -> None:
        """Run one Android input command and report ADB failures to the caller."""
        if not self.adb_path:
            raise RuntimeError("ADB executable was not found")
        self._validate_device(serial)
        result = subprocess.run(
            [str(self.adb_path), "-s", serial, "shell", "input", *arguments],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        if result.returncode:
            detail = result.stderr.strip() or result.stdout.strip()
            raise RuntimeError(detail or "ADB input command failed")

    def start_avd(self, avd_name: str) -> dict[str, Any]:
        """Start one validated AVD in its native emulator window."""
        if not self.emulator_path:
            raise RuntimeError("Android Emulator executable was not found")
        if avd_name not in self.list_avds():
            raise ValueError("Unknown AVD")
        process = subprocess.Popen(
            [str(self.emulator_path), "-avd", avd_name],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=platform.system() != "Windows",
            creationflags=(
                subprocess.CREATE_NEW_PROCESS_GROUP
                if platform.system() == "Windows"
                else 0
            ),
        )
        self.started_processes[avd_name] = process
        return {"avd_name": avd_name, "pid": process.pid, "state": "starting"}

    def stop_device(self, serial: str) -> None:
        """Stop one currently connected emulator by its validated ADB serial."""
        if not self.adb_path:
            raise RuntimeError("ADB executable was not found")
        valid_serials = {item["serial"] for item in self._list_device_rows()}
        if serial not in valid_serials or not serial.startswith("emulator-"):
            raise ValueError("Unknown emulator serial")
        subprocess.run(
            [str(self.adb_path), "-s", serial, "emu", "kill"],
            capture_output=True,
            timeout=10,
            check=False,
        )

    def screenshot(self, serial: str) -> bytes:
        """Capture a PNG screenshot from one validated ADB device."""
        if not self.adb_path:
            raise RuntimeError("ADB executable was not found")
        self._validate_device(serial)
        result = subprocess.run(
            [str(self.adb_path), "-s", serial, "exec-out", "screencap", "-p"],
            capture_output=True,
            timeout=12,
            check=False,
        )
        if result.returncode or not result.stdout.startswith(b"\x89PNG"):
            raise RuntimeError("Could not capture the device screen")
        return result.stdout

    def tap(self, serial: str, x: int, y: int) -> None:
        """Send one touch event to a validated ADB device at the supplied coordinates."""
        if x < 0 or y < 0:
            raise ValueError("Touch coordinates must be positive")
        self._send_input(serial, "tap", str(x), str(y))

    def swipe(
        self,
        serial: str,
        start_x: int,
        start_y: int,
        end_x: int,
        end_y: int,
        duration_ms: int,
    ) -> None:
        """Send a bounded swipe gesture to a validated ADB device."""
        coordinates = (start_x, start_y, end_x, end_y)
        if any(value < 0 for value in coordinates):
            raise ValueError("Swipe coordinates must be positive")
        duration_ms = max(50, min(duration_ms, 5000))
        self._send_input(
            serial,
            "swipe",
            *(str(value) for value in coordinates),
            str(duration_ms),
        )

    def keyevent(self, serial: str, keycode: int) -> None:
        """Send an Android key event to the selected device."""
        if keycode < 0 or keycode > 999:
            raise ValueError("Invalid Android keycode")
        self._send_input(serial, "keyevent", str(keycode))


class PosixTerminal:
    def __init__(self, shell: str, cwd: Path, rows: int, cols: int) -> None:
        """Start a POSIX shell attached to a pseudoterminal."""
        if pty is None:
            raise RuntimeError("POSIX PTY is unavailable on this platform")
        self.master_fd, slave_fd = pty.openpty()
        environment = os.environ.copy()
        environment["TERM"] = "xterm-256color"
        environment["NO_COLOR"] = "1"
        environment["CLICOLOR"] = "0"
        shell_name = Path(shell).name
        if shell_name == "zsh":
            command = [shell, "-f", "-i"]
        elif shell_name == "bash":
            command = [shell, "--noprofile", "--norc", "-i"]
        else:
            command = [shell, "-i"]

        def configure_child() -> None:
            """Create a session and assign the slave descriptor as its controlling terminal."""
            import fcntl
            import termios

            os.setsid()
            fcntl.ioctl(slave_fd, termios.TIOCSCTTY, 0)

        # Establish the terminal dimensions before zsh draws its initial prompt.
        self.resize(rows, cols)
        self.process = subprocess.Popen(
            command,
            stdin=slave_fd,
            stdout=slave_fd,
            stderr=slave_fd,
            cwd=str(cwd),
            env=environment,
            preexec_fn=configure_child,
            close_fds=True,
        )
        os.close(slave_fd)
        os.set_blocking(self.master_fd, False)
        self.resize(rows, cols)

    def read(self, limit: int = 131072) -> str:
        """Read currently available terminal output up to the supplied byte limit."""
        chunks = []
        size = 0
        while size < limit:
            ready, _, _ = select.select([self.master_fd], [], [], 0)
            if not ready:
                break
            try:
                chunk = os.read(self.master_fd, min(16384, limit - size))
            except (BlockingIOError, OSError):
                break
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
        return b"".join(chunks).decode("utf-8", errors="replace")

    def write(self, data: str) -> None:
        """Write user input to the pseudoterminal."""
        os.write(self.master_fd, data.encode("utf-8"))

    def resize(self, rows: int, cols: int) -> None:
        """Resize the pseudoterminal to the supplied row and column count."""
        import fcntl
        import termios

        fcntl.ioctl(
            self.master_fd,
            termios.TIOCSWINSZ,
            struct.pack("HHHH", rows, cols, 0, 0),
        )

    def alive(self) -> bool:
        """Return whether the shell process is still running."""
        return self.process.poll() is None

    def close(self) -> None:
        """Terminate the shell process group and close its PTY descriptor."""
        if self.alive():
            try:
                os.killpg(os.getpgid(self.process.pid), signal.SIGTERM)
            except ProcessLookupError:
                pass
        try:
            os.close(self.master_fd)
        except OSError:
            pass


class WindowsTerminal:
    def __init__(self, shell: str, cwd: Path, rows: int, cols: int) -> None:
        """Start a Windows shell through the native ConPTY wrapper."""
        try:
            from winpty import PtyProcess
        except ImportError as error:
            raise RuntimeError("pywinpty is required on Windows") from error
        self.process = PtyProcess.spawn(
            shell,
            cwd=str(cwd),
            dimensions=(rows, cols),
        )
        self.closed = threading.Event()
        self.output: queue.Queue[str] = queue.Queue()
        self.output_remainder = ""
        self.output_lock = threading.Lock()
        self.reader = threading.Thread(target=self._collect_output, daemon=True)
        self.reader.start()

    def _collect_output(self) -> None:
        """Read blocking ConPTY output in the background for non-blocking HTTP polling."""
        while not self.closed.is_set():
            try:
                data = self.process.read(16384)
            except (EOFError, OSError, RuntimeError):
                return
            if data:
                self.output.put(data)
            elif not self.alive():
                return
            else:
                self.closed.wait(0.01)

    def read(self, limit: int = 131072) -> str:
        """Read currently available ConPTY output up to the supplied character limit."""
        with self.output_lock:
            chunks = [self.output_remainder]
            self.output_remainder = ""
            size = len(chunks[0])
            while size < limit:
                try:
                    chunk = self.output.get_nowait()
                except queue.Empty:
                    break
                remaining = limit - size
                chunks.append(chunk[:remaining])
                size += len(chunks[-1])
                if len(chunk) > remaining:
                    self.output_remainder = chunk[remaining:]
                    break
            return "".join(chunks)

    def write(self, data: str) -> None:
        """Write user input to the Windows pseudoconsole."""
        self.process.write(data)

    def resize(self, rows: int, cols: int) -> None:
        """Resize the Windows pseudoconsole to the supplied dimensions."""
        self.process.setwinsize(rows, cols)

    def alive(self) -> bool:
        """Return whether the Windows shell process is still running."""
        return self.process.isalive()

    def close(self) -> None:
        """Terminate the Windows pseudoconsole and its shell process."""
        self.closed.set()
        if self.alive():
            self.process.terminate(force=True)
        self.reader.join(timeout=1)


class TerminalManager:
    def __init__(self, default_cwd: Path) -> None:
        """Manage local terminal sessions created by the dashboard."""
        self.default_cwd = default_cwd.resolve()
        self.sessions: dict[str, PosixTerminal | WindowsTerminal] = {}
        self.lock = threading.Lock()

    def create(self, cwd: str | None = None, rows: int = 28, cols: int = 100) -> dict[str, Any]:
        """Create a platform-native terminal session with an optional working directory."""
        selected_cwd = Path(cwd).expanduser().resolve() if cwd else self.default_cwd
        if not selected_cwd.is_dir():
            raise ValueError("Terminal working directory does not exist")
        system = platform.system()
        if system == "Windows":
            shell = shutil.which("powershell.exe") or "powershell.exe"
            terminal: PosixTerminal | WindowsTerminal = WindowsTerminal(
                shell, selected_cwd, rows, cols
            )
        elif system == "Darwin":
            shell = shutil.which("zsh") or "/bin/zsh"
            terminal = PosixTerminal(shell, selected_cwd, rows, cols)
        else:
            shell = os.environ.get("SHELL") or shutil.which("bash") or "/bin/bash"
            terminal = PosixTerminal(shell, selected_cwd, rows, cols)
        session_id = uuid.uuid4().hex
        with self.lock:
            self.sessions[session_id] = terminal
        return {
            "session_id": session_id,
            "shell": shell,
            "cwd": str(selected_cwd),
            "platform": system.lower(),
        }

    def get(self, session_id: str) -> PosixTerminal | WindowsTerminal:
        """Return one terminal session by its opaque identifier."""
        with self.lock:
            terminal = self.sessions.get(session_id)
        if terminal is None:
            raise KeyError("Unknown terminal session")
        return terminal

    def close(self, session_id: str) -> None:
        """Close and remove one terminal session by identifier."""
        with self.lock:
            terminal = self.sessions.pop(session_id, None)
        if terminal:
            terminal.close()

    def close_all(self) -> None:
        """Close every terminal session owned by this manager."""
        with self.lock:
            session_ids = list(self.sessions)
        for session_id in session_ids:
            self.close(session_id)
