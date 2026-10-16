from __future__ import annotations

import atexit
import os
import subprocess
import sys
from pathlib import Path

from flask import Flask, Response, abort, jsonify, render_template, request, send_from_directory

from server.results.dynamic_store import DynamicAnalysisStore
from server.results.static_store import AnalysisStore
from server.runtime.android import AndroidRuntime, TerminalManager
from server.runtime.stream import register_stream


BASE_DIR = Path(__file__).resolve().parent
RESULTS_DIR = BASE_DIR.parent / "data" / "results"


def _result_files(results_dir: Path) -> dict[str, Path]:
    """Return package static-result files from the canonical result directory."""
    if not results_dir.is_dir():
        return {}
    return {
        package_dir.name: static_file
        for package_dir in sorted(results_dir.iterdir())
        if package_dir.is_dir()
        and (static_file := package_dir / "static.json").is_file()
    }


def _start_default_emulator() -> None:
    """Start the first registered AVD before the dashboard is opened."""
    runtime = AndroidRuntime()
    avd_names = runtime.list_avds()
    if not avd_names:
        print("[EMULATOR] No AVD is registered; create one in Android Studio to enable it.")
        return
    result = runtime.start_avd(avd_names[0])
    print(f"[EMULATOR] Starting {result['avd_name']} (pid {result['pid']})")


def run_default_workflow() -> None:
    """Start AVD and serve the local dashboard."""
    try:
        _start_default_emulator()
    except (OSError, RuntimeError, ValueError) as error:
        print(f"[EMULATOR] {error}", file=sys.stderr)

    print("[STATIC] Existing data/results/{package}/static.json files are loaded by the dashboard.")
    print("[DYNAMIC] Existing data/results/{package}/dynamic.json files are loaded by the dashboard.")
    create_app().run(
        host=os.environ.get("FLOW_HOST", "127.0.0.1"),
        port=int(os.environ.get("FLOW_PORT", "5056")),
        debug=False,
    )


def create_app(results_dir: Path | None = None) -> Flask:
    app = Flask(__name__)
    app.config["TEMPLATES_AUTO_RELOAD"] = True
    results_dir = (results_dir or RESULTS_DIR).resolve()
    stores: dict[str, tuple[int, AnalysisStore]] = {}
    failed_loads: dict[str, int] = {}
    android_runtime = AndroidRuntime()
    terminal_manager = TerminalManager(BASE_DIR.parent)
    atexit.register(terminal_manager.close_all)

    def require_local_request() -> None:
        """Restrict process-control endpoints to requests originating on this computer."""
        if request.remote_addr not in {None, "127.0.0.1", "::1"}:
            abort(403, description="Local runtime APIs only accept loopback requests")

    register_stream(app, android_runtime, require_local_request)

    def current_project_files() -> dict[str, Path]:
        """Rescan the result directory so analyses finished after startup are listed."""
        project_files = _result_files(results_dir)
        for project_id in stores.keys() - project_files.keys():
            stores.pop(project_id, None)
        for project_id in failed_loads.keys() - project_files.keys():
            failed_loads.pop(project_id, None)
        return project_files

    def load_store(project_id: str, project_file: Path) -> AnalysisStore:
        """Return the cached store for a static result, reloading it when the file changes."""
        modified_ns = project_file.stat().st_mtime_ns
        cached = stores.get(project_id)
        if cached is not None and cached[0] == modified_ns:
            return cached[1]
        if failed_loads.get(project_id) == modified_ns:
            raise ValueError("Project JSON could not be loaded")
        try:
            project_store = AnalysisStore(project_file)
        except (OSError, ValueError, KeyError):
            failed_loads[project_id] = modified_ns
            raise
        failed_loads.pop(project_id, None)
        stores[project_id] = (modified_ns, project_store)
        return project_store

    def default_project_id(project_files: dict[str, Path]) -> str | None:
        """Return the first project whose static result loads, for requests naming none."""
        for project_id, project_file in project_files.items():
            try:
                load_store(project_id, project_file)
            except (OSError, ValueError, KeyError):
                continue
            return project_id
        return None
    
    def selected_project() -> tuple[str, AnalysisStore]:
        project_files = current_project_files()
        project_id = request.args.get("project") or default_project_id(project_files)
        if project_id is None:
            abort(404, description="No static results found")
        if project_id not in project_files:
            abort(404, description="Unknown project")
        try:
            return project_id, load_store(project_id, project_files[project_id])
        except (OSError, ValueError, KeyError):
            abort(422, description="Project JSON could not be loaded")

    def dynamic_store(
        package_name: str, static_store: AnalysisStore
    ) -> DynamicAnalysisStore:
        selected_dynamic = results_dir / package_name / "dynamic.json"
        return DynamicAnalysisStore(
            selected_dynamic,
            expected_package=static_store.package,
        )

    @app.get("/")
    def index():
        return render_template("index.html")

    @app.get("/vendor/xterm-fit/<path:filename>")
    def xterm_fit_asset(filename: str):
        return send_from_directory(
            BASE_DIR / "node_modules" / "@xterm" / "addon-fit", filename
        )

    @app.get("/vendor/xterm/<path:filename>")
    def xterm_asset(filename: str):
        """Serve the installed xterm.js browser bundle and stylesheet."""
        return send_from_directory(BASE_DIR / "node_modules" / "@xterm" / "xterm", filename)

    @app.get("/api/projects")
    def projects():
        values = []
        project_files = current_project_files()
        requested_project = request.args.get("project") or default_project_id(project_files)
        for project_id, project_file in project_files.items():
            try:
                project_store = load_store(project_id, project_file)
                overview = project_store.overview()
                project_dynamic_store = dynamic_store(project_id, project_store)
                file_size = project_file.stat().st_size
            except (OSError, ValueError, KeyError):
                continue
            values.append(
                {
                    "id": project_id,
                    "name": project_store.package,
                    "apk_name": project_store.apk_name,
                    "schema_version": overview["schema_version"],
                    "static_graphs": overview["indexed_graphs"],
                    "dynamic_executions": project_dynamic_store.overview()[
                        "payload_count"
                    ],
                    "source_file": str(project_file),
                    "file_size": file_size,
                    "selected": project_id == requested_project,
                }
            )
        return jsonify(values)

    @app.get("/api/local/runtime")
    def local_runtime_status():
        require_local_request()
        return jsonify(
            {
                **android_runtime.status(),
                "avds": android_runtime.list_avds(),
                "devices": android_runtime.list_devices(),
            }
        )

    @app.post("/api/local/emulator/start")
    def local_emulator_start():
        require_local_request()
        payload = request.get_json(silent=True) or {}
        try:
            return jsonify(android_runtime.start_avd(str(payload.get("avd_name", ""))))
        except (RuntimeError, ValueError, subprocess.SubprocessError) as error:
            return jsonify({"error": str(error)}), 400

    @app.post("/api/local/emulator/stop")
    def local_emulator_stop():
        require_local_request()
        payload = request.get_json(silent=True) or {}
        try:
            android_runtime.stop_device(str(payload.get("serial", "")))
            return jsonify({"ok": True})
        except (RuntimeError, ValueError, subprocess.SubprocessError) as error:
            return jsonify({"error": str(error)}), 400

    @app.get("/api/local/devices/<serial>/screen")
    def local_device_screen(serial: str):
        require_local_request()
        try:
            return Response(android_runtime.screenshot(serial), mimetype="image/png")
        except (RuntimeError, ValueError, subprocess.SubprocessError) as error:
            return jsonify({"error": str(error)}), 400

    @app.post("/api/local/devices/<serial>/tap")
    def local_device_tap(serial: str):
        require_local_request()
        payload = request.get_json(silent=True) or {}
        try:
            android_runtime.tap(serial, int(payload.get("x", 0)), int(payload.get("y", 0)))
            return jsonify({"ok": True})
        except (RuntimeError, ValueError, TypeError, subprocess.SubprocessError) as error:
            return jsonify({"error": str(error)}), 400

    @app.post("/api/local/devices/<serial>/swipe")
    def local_device_swipe(serial: str):
        require_local_request()
        payload = request.get_json(silent=True) or {}
        try:
            android_runtime.swipe(
                serial,
                int(payload.get("start_x", 0)),
                int(payload.get("start_y", 0)),
                int(payload.get("end_x", 0)),
                int(payload.get("end_y", 0)),
                int(payload.get("duration_ms", 250)),
            )
            return jsonify({"ok": True})
        except (RuntimeError, ValueError, TypeError, subprocess.SubprocessError) as error:
            return jsonify({"error": str(error)}), 400

    @app.post("/api/local/devices/<serial>/keyevent")
    def local_device_keyevent(serial: str):
        require_local_request()
        payload = request.get_json(silent=True) or {}
        try:
            android_runtime.keyevent(serial, int(payload.get("keycode", -1)))
            return jsonify({"ok": True})
        except (RuntimeError, ValueError, TypeError, subprocess.SubprocessError) as error:
            return jsonify({"error": str(error)}), 400

    @app.post("/api/local/terminal/sessions")
    def local_terminal_create():
        require_local_request()
        payload = request.get_json(silent=True) or {}
        try:
            return jsonify(
                terminal_manager.create(
                    cwd=payload.get("cwd"),
                    rows=int(payload.get("rows", 28)),
                    cols=int(payload.get("cols", 100)),
                )
            )
        except (RuntimeError, ValueError, OSError) as error:
            return jsonify({"error": str(error)}), 400

    @app.get("/api/local/terminal/sessions/<session_id>/output")
    def local_terminal_output(session_id: str):
        require_local_request()
        try:
            terminal = terminal_manager.get(session_id)
            return jsonify({"data": terminal.read(), "alive": terminal.alive()})
        except KeyError as error:
            return jsonify({"error": str(error)}), 404

    @app.post("/api/local/terminal/sessions/<session_id>/input")
    def local_terminal_input(session_id: str):
        require_local_request()
        payload = request.get_json(silent=True) or {}
        try:
            terminal_manager.get(session_id).write(str(payload.get("data", "")))
            return jsonify({"ok": True})
        except KeyError as error:
            return jsonify({"error": str(error)}), 404
        except OSError as error:
            return jsonify({"error": str(error)}), 400

    @app.post("/api/local/terminal/sessions/<session_id>/resize")
    def local_terminal_resize(session_id: str):
        require_local_request()
        payload = request.get_json(silent=True) or {}
        try:
            terminal_manager.get(session_id).resize(
                int(payload.get("rows", 28)), int(payload.get("cols", 100))
            )
            return jsonify({"ok": True})
        except KeyError as error:
            return jsonify({"error": str(error)}), 404
        except (ValueError, OSError) as error:
            return jsonify({"error": str(error)}), 400

    @app.delete("/api/local/terminal/sessions/<session_id>")
    def local_terminal_close(session_id: str):
        require_local_request()
        terminal_manager.close(session_id)
        return jsonify({"ok": True})

    @app.get("/api/health")
    def health():
        project_id, store = selected_project()
        project_dynamic_store = dynamic_store(project_id, store)
        return jsonify(
            {
                "ok": True,
                "results_dir": str(results_dir),
                "static_data_file": str(store.data_file),
                "dynamic_data_file": (
                    str(project_dynamic_store.data_file)
                    if project_dynamic_store.data_file
                    else None
                ),
            }
        )

    @app.get("/api/overview")
    def overview():
        _, store = selected_project()
        return jsonify(store.overview())

    @app.get("/api/graphs")
    def graphs():
        _, store = selected_project()
        query = request.args.get("q", "").strip().lower()
        candidate_type = request.args.get("type", "").strip().lower()
        classification = request.args.get("classification", "").strip().lower()
        values = store.graph_summaries()
        if query:
            values = [
                graph
                for graph in values
                if query
                in " ".join(
                    [
                        graph["graph_id"],
                        *graph["entry_points"],
                        graph["sink"] or "",
                        *graph["candidate_types"],
                    ]
                ).lower()
            ]
        if candidate_type:
            values = [
                graph
                for graph in values
                if any(candidate_type in item.lower() for item in graph["candidate_types"])
            ]
        if classification:
            values = [
                graph
                for graph in values
                if graph["classification"].lower() == classification
            ]
        return jsonify(values)

    @app.get("/api/graphs/<graph_id>")
    def graph(graph_id: str):
        _, store = selected_project()
        value = store.graph_detail(graph_id)
        if value is None:
            abort(404)
        return jsonify(value)

    @app.get("/api/dynamic/overview")
    def dynamic_overview():
        project_id, store = selected_project()
        return jsonify(dynamic_store(project_id, store).overview())

    @app.get("/api/dynamic/flows")
    def dynamic_flows():
        project_id, store = selected_project()
        return jsonify(dynamic_store(project_id, store).flow_summaries())

    @app.get("/api/dynamic/flows/<flow_id>/payloads")
    def dynamic_payloads(flow_id: str):
        project_id, store = selected_project()
        values = dynamic_store(project_id, store).payload_summaries(flow_id)
        if values is None:
            abort(404)
        return jsonify(values)

    @app.get("/api/dynamic/payloads/<payload_id>")
    def dynamic_payload(payload_id: str):
        project_id, store = selected_project()
        value = dynamic_store(project_id, store).detail(payload_id)
        if value is None:
            abort(404)
        return jsonify(value)

    return app


if __name__ == "__main__":
    run_default_workflow()
else:
    app = create_app()
