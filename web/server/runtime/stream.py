"""Pinned scrcpy 3.3.4 transport: H.264 packets and validated input over WebSocket."""
from __future__ import annotations

import atexit
import json
import secrets
import socket
import struct
import subprocess
import threading
import time
from pathlib import Path
from urllib.parse import urlsplit

from flask import request
from flask_sock import Sock

VERSION = "3.3.4"
SERVER = Path(__file__).resolve().parents[2] / "vendor" / "scrcpy" / f"scrcpy-server-v{VERSION}"
MAX_PACKET = 8 * 1024 * 1024


def read_exact(sock, size):
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise EOFError("Device stream disconnected")
        data.extend(chunk)
    return bytes(data)


def control_packet(message):
    """Only expose touch, scroll, keys and text; never arbitrary scrcpy commands."""
    kind = message.get("type")
    if kind in {"touch", "scroll"}:
        width, height = int(message["width"]), int(message["height"])
        if not (1 <= width <= 8192 and 1 <= height <= 8192):
            raise ValueError("Invalid screen dimensions")
        x = max(0, min(width - 1, int(message["x"])))
        y = max(0, min(height - 1, int(message["y"])))
        if kind == "touch":
            action = int(message["action"])
            if action not in {0, 1, 2, 3}:
                raise ValueError("Invalid touch action")
            return struct.pack(">BBQiiHHHII", 2, action, 0, x, y, width, height,
                               0 if action in {1, 3} else 65535, 0, 0)
        horizontal = max(-32768, min(32767, int(float(message.get("horizontal", 0)) * 2048)))
        vertical = max(-32768, min(32767, int(float(message.get("vertical", 0)) * 2048)))
        return struct.pack(">BiiHHhhI", 3, x, y, width, height, horizontal, vertical, 0)
    if kind == "key":
        key = int(message["keycode"])
        if not 0 <= key <= 999:
            raise ValueError("Invalid keycode")
        return b"".join(struct.pack(">BBIII", 0, action, key, 0, 0) for action in (0, 1))
    if kind == "text":
        data = str(message["text"]).encode("utf-8")
        if not 0 < len(data) <= 300:
            raise ValueError("Text must be 1–300 UTF-8 bytes")
        return struct.pack(">BI", 1, len(data)) + data
    raise ValueError("Unsupported input")


class DeviceStream:
    def __init__(self, runtime, serial):
        self.runtime = runtime
        self.serial = serial
        self.port = None
        self.process = None
        self.video = None
        self.control = None
        self.closed = threading.Event()
        self.scid = f"{secrets.randbelow(0x7fffffff):08x}"
        self.remote = f"/data/local/tmp/unintent-scrcpy-{self.scid}.jar"

    def adb(self, *args):
        result = subprocess.run([str(self.runtime.adb_path), "-s", self.serial, *args],
                                capture_output=True, timeout=15, check=True)
        return result.stdout.decode().strip()

    def start(self):
        self.runtime._validate_device(self.serial)
        if not SERVER.is_file():
            raise RuntimeError(f"Missing bundled scrcpy server: {SERVER.name}")
        self.adb("push", str(SERVER), self.remote)
        self.port = int(self.adb("forward", "tcp:0", f"localabstract:scrcpy_{self.scid}"))
        self.process = subprocess.Popen([
            str(self.runtime.adb_path), "-s", self.serial, "shell",
            f"CLASSPATH={self.remote}", "app_process", "/", "com.genymobile.scrcpy.Server", VERSION,
            f"scid={self.scid}", "tunnel_forward=true", "audio=false", "control=true",
            "video_codec=h264", "max_size=1280", "max_fps=30", "video_bit_rate=3000000",
            "send_device_meta=false", "clipboard_autosync=false", "power_on=false",
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline and not self.closed.is_set():
            candidate = None
            try:
                candidate = socket.create_connection(("127.0.0.1", self.port), timeout=1)
                if read_exact(candidate, 1) != b"\0":
                    raise RuntimeError("Invalid scrcpy handshake")
                self.video = candidate
                break
            except (OSError, EOFError):
                if candidate:
                    candidate.close()
                if self.process.poll() is not None:
                    raise RuntimeError("scrcpy server exited during startup")
                self.closed.wait(0.1)
        if self.video is None:
            raise RuntimeError("scrcpy connection timed out")
        self.control = socket.create_connection(("127.0.0.1", self.port), timeout=3)
        self.control.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.video.settimeout(15)
        codec, width, height = struct.unpack(">III", read_exact(self.video, 12))
        if codec != 0x68323634:
            raise RuntimeError("Expected H.264 video")
        return {"type": "ready", "width": width, "height": height, "maxFps": 30}

    def packets(self):
        while not self.closed.is_set():
            header = read_exact(self.video, 12)
            size = struct.unpack(">I", header[8:])[0]
            if not 0 < size <= MAX_PACKET:
                raise ValueError("Invalid video packet size")
            yield header + read_exact(self.video, size)

    def close(self):
        self.closed.set()
        for connection in (self.video, self.control):
            if connection:
                try:
                    connection.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                connection.close()
        if self.process:
            self.process.terminate()
            try:
                self.process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=2)
        if self.port:
            try:
                self.adb("forward", "--remove", f"tcp:{self.port}")
            except (OSError, subprocess.SubprocessError):
                pass
        try:
            self.adb("shell", "rm", "-f", self.remote)
        except (OSError, subprocess.SubprocessError):
            pass


def close_websocket(ws):
    try:
        ws.close()
    except Exception:
        pass


def register_stream(app, runtime, require_local):
    app.config["SOCK_SERVER_OPTIONS"] = {"ping_interval": 10, "max_message_size": 4096}
    sock = Sock(app)
    sessions = set()
    sessions_lock = threading.Lock()

    def close_sessions():
        with sessions_lock:
            active = list(sessions)
        for session in active:
            session.close()

    atexit.register(close_sessions)

    @sock.route("/api/local/devices/<serial>/stream")
    def stream(ws, serial):
        session = None
        sender = None
        try:
            require_local()
            origin = urlsplit(request.headers.get("Origin", ""))
            if origin.scheme not in {"http", "https"} or origin.netloc != request.host:
                raise ValueError("Stream requires a same-origin dashboard connection")
            session = DeviceStream(runtime, serial)
            with sessions_lock:
                sessions.add(session)
            ws.send(json.dumps(session.start()))
            counters = {"sent": 0, "ack": 0, "last_ack": time.monotonic()}

            def send_video():
                try:
                    for packet in session.packets():
                        # Bound queued video: restart instead of displaying stale seconds of video.
                        if counters["sent"] - counters["ack"] >= 12:
                            raise RuntimeError("Video client is too slow; reconnecting")
                        counters["sent"] += 1
                        ws.send(packet)
                except Exception:
                    session.closed.set()
                    close_websocket(ws)

            sender = threading.Thread(target=send_video, daemon=True)
            sender.start()
            while not session.closed.is_set():
                raw = ws.receive(timeout=1)
                if raw is None:
                    if counters["sent"] > counters["ack"] and time.monotonic() - counters["last_ack"] > 5:
                        break
                    continue
                if not isinstance(raw, str):
                    raise ValueError("Expected JSON control message")
                message = json.loads(raw)
                if message.get("type") == "ack":
                    ack = int(message["count"])
                    if not counters["ack"] <= ack <= counters["sent"]:
                        raise ValueError("Invalid video acknowledgement")
                    counters["ack"] = ack
                    counters["last_ack"] = time.monotonic()
                else:
                    session.control.sendall(control_packet(message))
        except Exception as error:
            try:
                ws.send(json.dumps({"type": "error", "message": str(error)}))
            except Exception:
                pass
        finally:
            if session:
                session.close()
                with sessions_lock:
                    sessions.discard(session)
            if sender:
                sender.join(timeout=2)
            close_websocket(ws)
