from __future__ import annotations

import gc
import json
import os
import sys
import tempfile
from collections import Counter
from contextlib import redirect_stdout
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable
from zipfile import ZipFile

from src.dynamic.environment import EnvironmentConfig
from src.dynamic.pipeline import ProjectLayout, dynamic_core_run
from src.dynamic.setup import SetupConfig
from src.parsing.androguard_parser import parse_apk
from src.static.model.flow_spool import FlowGraphSpool
from src.static.model.values import MethodRef, serializable
from src.static.pipeline import run_static_analysis
from src.static.report.json_report import write_json_report
from tools.apk.download_apks import PACKAGE_RE, download_package

REPO_ROOT = Path(__file__).resolve().parents[1]
RESULTS_ROOT = REPO_ROOT / "data" / "results"
MAX_VECTORS = 2000
MAX_SEEDS = 1000
MAX_BOUNDARIES = 512
MAX_PATH_ITEMS = 128
DEFAULT_LIMIT = 30
MAX_LIMIT = 100

VECTOR_TYPES = (
    "EXTERNAL_INPUT",
    "KNOWN_FLOW",
    "ANALYSIS_FRONTIER",
    "UNKNOWN_EFFECT",
    "DYNAMIC_DISPATCH",
    "NATIVE_BOUNDARY",
)


class ToolError(Exception):
    def __init__(self, code: str, message: str, **details: Any) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = details

    def result(self) -> dict[str, Any]:
        return {
            "status": "error",
            "error": {"code": self.code, "message": self.message},
            **self.details,
        }


def _atomic_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(value, stream, ensure_ascii=False, separators=(",", ":"))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except BaseException:
        try:
            os.close(descriptor)
        except OSError:
            pass
        temporary.unlink(missing_ok=True)
        raise


def _load_json(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as stream:
        value = json.load(stream)
    if not isinstance(value, dict):
        raise ValueError(f"JSON root must be an object: {path}")
    return value


def _page(items: list[Any], offset: int, limit: int) -> dict[str, Any]:
    if offset < 0 or not 1 <= limit <= MAX_LIMIT:
        raise ToolError("INVALID_ARGUMENT", f"offset must be >= 0 and limit 1..{MAX_LIMIT}")
    return {
        "items": items[offset : offset + limit],
        "total_count": len(items),
        "offset": offset,
        "limit": limit,
        "has_more": offset + limit < len(items),
    }


def _apk_identity(apk_path: Path, workspace: Path) -> dict[str, Any]:
    stat = apk_path.stat()
    try:
        name = str(apk_path.relative_to(workspace))
    except ValueError:
        name = str(apk_path)
    return {"apk_file": name, "size": stat.st_size, "mtime_ns": stat.st_mtime_ns}


@dataclass
class ActiveProject:
    workspace: Path
    package_name: str
    apk_path: Path
    result_dir: Path
    vectors: list[dict[str, Any]]
    seeds: list[dict[str, Any]]
    summary: dict[str, Any]
    explorer: ProgramExplorer | None = None


class ProgramExplorer:
    """One lazy, bounded DEX backend for the active project only."""

    def __init__(self, apk_path: Path) -> None:
        from src.static.search.call_resolver import LazyAndroguardSession, LazyBytecodeBackend
        from src.static.search.manifest import parse_components

        self.apk_path = apk_path
        self.session = LazyAndroguardSession.load(apk_path)
        components, _ = parse_components(self.session.apk)
        self.backend = LazyBytecodeBackend(self.session, components)

    def _ref(self, display: str) -> MethodRef:
        for ref in self.backend.methods:
            if ref.display() == display:
                return ref
        raise ToolError("METHOD_NOT_FOUND", f"Method was not found: {display}")

    def method(self, display: str, offset: int, limit: int) -> dict[str, Any]:
        value = self.backend.methods[self._ref(display)]
        instructions = [
            {
                "offset": item.offset,
                "name": item.name,
                "output": item.output,
                "registers": list(item.registers),
                "reference": item.reference,
                "string_value": item.string_value,
                "literal_value": item.literal_value,
                "type_value": item.type_value,
            }
            for item in value.instructions
        ]
        return {
            "method": value.display(),
            "access": value.access,
            "receiver_register": value.receiver_register,
            "parameters": {
                str(register): {"formal": formal, "type": dex_type}
                for register, (formal, dex_type) in value.parameters.items()
            },
            "instructions": _page(instructions, offset, limit),
        }

    def callers(self, display: str) -> list[dict[str, Any]]:
        ref = self._ref(display)
        result = []
        for callsite in self.backend.callers.get(ref, []):
            caller = self.backend.methods[callsite.caller]
            instruction = caller.instructions[callsite.instruction_index]
            result.append(
                {
                    "caller": callsite.caller.display(),
                    "callee": display,
                    "instruction_index": callsite.instruction_index,
                    "offset": instruction.offset,
                    "instruction": instruction.text(),
                }
            )
        return result

    def callees(self, display: str) -> list[dict[str, Any]]:
        ref = self._ref(display)
        method = self.backend.methods[ref]
        result = []
        for index, instruction in enumerate(method.instructions):
            if not instruction.name.startswith("invoke-"):
                continue
            targets = self.backend.call_targets.get((ref, index), [])
            result.append(
                {
                    "offset": instruction.offset,
                    "declared_target": instruction.reference,
                    "resolved_targets": [target.display() for target in targets],
                    "resolution": "resolved" if targets else "unresolved",
                }
            )
        return result

    def usages(self, symbol: str) -> list[dict[str, Any]]:
        result = []
        for ref, method in self.backend.methods.items():
            for instruction in method.instructions:
                if symbol in (instruction.reference or "") or symbol in (
                    instruction.type_value or ""
                ):
                    result.append(
                        {
                            "method": ref.display(),
                            "offset": instruction.offset,
                            "instruction": instruction.text(),
                            "reference": instruction.reference or instruction.type_value,
                        }
                    )
                    if len(result) >= MAX_LIMIT:
                        return result
        return result

    def search(self, query: str) -> list[dict[str, Any]]:
        needle = query.casefold()
        result = []
        for ref, method in self.backend.methods.items():
            if needle in ref.display().casefold():
                result.append({"kind": "method", "method": ref.display()})
            for instruction in method.instructions:
                haystack = " ".join(
                    str(value)
                    for value in (
                        instruction.output,
                        instruction.reference,
                        instruction.string_value,
                        instruction.type_value,
                    )
                    if value is not None
                )
                if needle in haystack.casefold():
                    result.append(
                        {
                            "kind": "instruction",
                            "method": ref.display(),
                            "offset": instruction.offset,
                            "instruction": instruction.text(),
                            "reference": instruction.reference,
                            "string_value": instruction.string_value,
                        }
                    )
            if len(result) >= MAX_LIMIT:
                return result[:MAX_LIMIT]
        return result[:MAX_LIMIT]


REFLECTION_OWNERS = ("Ljava/lang/Class;", "Ljava/lang/reflect/")
DYNAMIC_CODE_OWNERS = (
    "Ldalvik/system/BaseDexClassLoader;",
    "Ldalvik/system/DexClassLoader;",
    "Ldalvik/system/PathClassLoader;",
    "Ldalvik/system/InMemoryDexClassLoader;",
)


def collect_agent_boundaries(
    explorer: ProgramExplorer, focus_methods: Iterable[str]
) -> list[dict[str, Any]]:
    from src.static.search.dex_ir import parse_method_reference

    focus = set(focus_methods)
    result = []
    seen = set()
    for reference in explorer.backend.methods:
        if reference.display() not in focus:
            continue
        method = explorer.backend.methods[reference]
        for instruction in method.instructions:
            parsed = parse_method_reference(instruction.reference)
            if parsed is None:
                continue
            owner, name, descriptor = parsed
            target = explorer.backend.methods.get(MethodRef(owner, name, descriptor))
            kind = None
            if owner.startswith(REFLECTION_OWNERS) and name in {
                "forName", "invoke", "newInstance", "getMethod", "getDeclaredMethod"
            }:
                kind = "reflection"
            elif owner in DYNAMIC_CODE_OWNERS:
                kind = "dynamic_code"
            elif owner in {"Ljava/lang/System;", "Ljava/lang/Runtime;"} and name in {
                "load", "loadLibrary"
            }:
                kind = "jni_load"
            elif target is not None and "native" in target.access.split():
                kind = "jni_call"
            elif target is None and not owner.startswith(
                ("Landroid/", "Landroidx/", "Ljava/", "Ljavax/", "Lkotlin/", "Ldalvik/")
            ):
                kind = "unresolved_custom_library_call"
            if kind is None:
                continue
            marker = (method.display(), instruction.offset, kind)
            if marker in seen:
                continue
            seen.add(marker)
            result.append(
                {
                    "kind": kind,
                    "method": method.display(),
                    "offset": instruction.offset,
                    "api": instruction.reference,
                }
            )
            if len(result) >= MAX_BOUNDARIES:
                return result
    return result


class VectorBuilder:
    def build(self, result: Any, explorer: ProgramExplorer) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        vectors: list[dict[str, Any]] = []
        observed = 0

        def add(kind: str, payload: dict[str, Any]) -> None:
            nonlocal observed
            observed += 1
            if len(vectors) < MAX_VECTORS:
                vectors.append({"vector_id": f"AV-{len(vectors) + 1:04d}", "type": kind, **payload})

        for item in result.metadata.get("entry_input_catalog", []):
            add(
                "EXTERNAL_INPUT",
                {
                    "component": item.get("component"),
                    "method": item.get("method"),
                    "offset": item.get("offset"),
                    "api": item.get("api"),
                    "field": item.get("field"),
                    "key": item.get("key"),
                    "attacker_controlled": item.get("generic_attacker_can_invoke"),
                },
            )

        # Index the existing objects; serializing the full node/edge tables here
        # would temporarily duplicate the largest in-memory static structures.
        nodes = {str(item.id): item for item in result.nodes}
        edges = {str(item.id): item for item in result.edges}
        focus = {
            str(item.get("method"))
            for item in result.metadata.get("entry_input_catalog", [])
            if item.get("method")
        }
        for raw_graph in result.flow_graphs:
            graph = serializable(raw_graph)
            for path in graph.get("paths", []):
                path_nodes = [
                    {
                        key: getattr(node, key)
                        for key in (
                            "id", "type", "label", "component", "method", "offset",
                            "api", "field", "key", "external",
                        )
                        if getattr(node, key) is not None
                    }
                    for item in path.get("node_ids", [])[:MAX_PATH_ITEMS]
                    if (node := nodes.get(str(item))) is not None
                ]
                path_edges = [
                    {
                        key: getattr(edge, key)
                        for key in ("id", "source", "target", "type", "direct", "relation")
                        if getattr(edge, key) is not None
                    }
                    for item in path.get("edge_ids", [])[:MAX_PATH_ITEMS]
                    if (edge := edges.get(str(item))) is not None
                ]
                focus.update(str(item["method"]) for item in path_nodes if item.get("method"))
                add(
                    "KNOWN_FLOW",
                    {
                        "graph_id": graph.get("graph_id"),
                        "path_id": path.get("id"),
                        "classification": path.get("confirmation_status") or graph.get("classification"),
                        "entry": path.get("entry_point_id"),
                        "source": path.get("source_id"),
                        "sink": graph.get("sink"),
                        "nodes": path_nodes,
                        "edges": path_edges,
                        "guards": path.get("guards", graph.get("guards", [])),
                        "attacker_controlled": path.get("attacker_controlled", False),
                    },
                )

        for item in [*result.unresolved_frontiers, *result.unresolved_data_origins]:
            value = serializable(item)
            method = value.get("method")
            if method:
                focus.add(str(method))
            add(
                "ANALYSIS_FRONTIER",
                {
                    key: value.get(key)
                    for key in (
                        "root_request", "sink_site", "method", "register", "before",
                        "purpose", "phase", "reason", "depth", "kind", "api", "field",
                        "key", "component", "offset",
                    )
                    if value.get(key) is not None
                },
            )
        focus.update(str(item.get("method")) for item in result.sinks if item.get("method"))

        for boundary in collect_agent_boundaries(explorer, focus):
            kind = boundary.pop("kind")
            vector_type = {
                "unresolved_custom_library_call": "UNKNOWN_EFFECT",
                "reflection": "DYNAMIC_DISPATCH",
                "dynamic_code": "DYNAMIC_DISPATCH",
                "jni_load": "NATIVE_BOUNDARY",
                "jni_call": "NATIVE_BOUNDARY",
            }[kind]
            add(vector_type, {"boundary_type": kind, **boundary})

        return vectors, {
            "truncated": observed > len(vectors),
            "total_observed": observed,
            "retained": len(vectors),
        }


def _dynamic_evidence(path: Path) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    if not path.is_file():
        return {"available": False, "execution_status": "not_executed"}, {}
    payload = _load_json(path)
    execution = payload.get("execution", {})
    by_graph = {}
    for flow in payload.get("flows", []):
        graph_id = flow.get("graph_id")
        if not graph_id:
            continue
        payloads = flow.get("payloads", [])
        reached = [item for item in payloads if item.get("result", {}).get("verdict") == "reached"]
        by_graph[str(graph_id)] = {
            "tested": bool(payloads),
            "sink_reached": bool(reached),
            "successful_payloads": len(reached),
            "best_payload_id": reached[0].get("payload_id") if reached else None,
        }
    return {
        "available": True,
        "execution_status": execution.get("status", "unknown"),
        "tested_paths": execution.get("tested_paths", 0),
        "reached_paths": execution.get("reached_paths", 0),
        "failure_reasons": execution.get("failure_reasons", []),
    }, by_graph


def build_seeds(
    vectors: list[dict[str, Any]], dynamic_by_graph: dict[str, dict[str, Any]]
) -> list[dict[str, Any]]:
    seeds = []
    for vector in vectors:
        if len(seeds) >= MAX_SEEDS:
            break
        kind = vector["type"]
        if kind == "EXTERNAL_INPUT":
            priority = 40 if vector.get("attacker_controlled") else 20
        elif kind == "KNOWN_FLOW":
            priority = 40 + (20 if vector.get("attacker_controlled") else 0)
        elif kind in {"UNKNOWN_EFFECT", "DYNAMIC_DISPATCH", "NATIVE_BOUNDARY"}:
            priority = 35
        else:
            priority = 25
        graph_id = vector.get("graph_id")
        dynamic = dynamic_by_graph.get(str(graph_id), {}) if graph_id else {}
        if dynamic.get("sink_reached"):
            priority += 25
        location = vector.get("method") or vector.get("component") or graph_id or "analysis boundary"
        seeds.append(
            {
                "seed_id": f"SEED-{len(seeds) + 1:04d}",
                "priority": priority,
                "component": vector.get("component"),
                "summary": f"{kind} at {location}",
                "vector_ids": [vector["vector_id"]],
                "vector_types": [kind],
                "static_evidence": {
                    "graph_id": graph_id,
                    "path_id": vector.get("path_id"),
                    "classification": vector.get("classification"),
                    "status": "candidate",
                },
                "dynamic_evidence": dynamic or {"tested": False, "sink_reached": False},
            }
        )
    return sorted(seeds, key=lambda item: (-item["priority"], item["seed_id"]))


class AnalysisService:
    def __init__(self, workspace: Path | None = None) -> None:
        configured = os.environ.get("UNINTENT_WORKSPACE")
        self.workspace = (workspace or Path(configured) if configured else workspace or Path.cwd()).resolve()
        self.active: ActiveProject | None = None

    @property
    def session_path(self) -> Path:
        return self.workspace / ".UnIntent" / "session.json"

    def analyze_workspace(self) -> dict[str, Any]:
        apks = sorted(self.workspace.glob("*.apk"))
        if not apks:
            raise ToolError("APK_NOT_FOUND", "No APK file was found in the current workspace.")
        if len(apks) > 1:
            raise ToolError(
                "MULTIPLE_APKS",
                "Multiple APK files were found in the current workspace.",
                candidates=[path.name for path in apks],
            )
        return self.analyze_path(apks[0])

    def analyze_package(self, package_name: str) -> dict[str, Any]:
        if not PACKAGE_RE.fullmatch(package_name):
            raise ToolError("APK_DOWNLOAD_FAILED", f"Invalid package name: {package_name}")
        if self.active and self.active.package_name == package_name:
            return self._ready(self.active, restored=True)
        restored = self._restore_package(package_name)
        if restored is not None:
            self.active = restored
            return self._ready(restored, restored=True)
        try:
            with redirect_stdout(sys.stderr):
                apk_path = download_package(package_name)
        except (OSError, RuntimeError, ValueError) as exception:
            raise ToolError("APK_DOWNLOAD_FAILED", str(exception)) from exception
        return self.analyze_path(apk_path)

    def analyze_path(self, apk_path: Path) -> dict[str, Any]:
        apk_path = apk_path.expanduser().resolve()
        restored = self._restore(apk_path)
        if restored is not None:
            self.active = restored
            return self._ready(restored, restored=True)

        self.active = None
        try:
            with redirect_stdout(sys.stderr):
                context = parse_apk(apk_path)
        except Exception as exception:
            raise ToolError("APK_PARSE_FAILED", f"{type(exception).__name__}: {exception}") from exception

        package = context.metadata.package_name
        result_dir = RESULTS_ROOT / package
        static_path = result_dir / "static.json"
        dynamic_path = result_dir / "dynamic.json"
        result_dir.mkdir(parents=True, exist_ok=True)

        explorer = None
        try:
            with FlowGraphSpool(result_dir, flush_every=1) as flow_store:
                with redirect_stdout(sys.stderr):
                    result = run_static_analysis(
                        context=context,
                        timeout_seconds=None,
                        max_call_depth=10,
                        flow_graph_store=flow_store,
                    )
                if result is None:
                    raise ToolError("STATIC_ANALYSIS_FAILED", "Static analysis returned no result.")
                del context
                gc.collect()
                explorer = ProgramExplorer(apk_path)
                vectors, vector_stats = VectorBuilder().build(result, explorer)
                write_json_report(result, static_path)
                del result
            gc.collect()
        except ToolError:
            raise
        except Exception as exception:
            raise ToolError("STATIC_ANALYSIS_FAILED", f"{type(exception).__name__}: {exception}") from exception

        # The explorer was needed for boundary vectors. Do not keep its DEX
        # session alive while the device-backed dynamic pipeline runs.
        explorer = None
        gc.collect()
        dynamic_error = None
        try:
            dynamic_path.unlink(missing_ok=True)
            with redirect_stdout(sys.stderr):
                dynamic_core_run(
                    apk_path,
                    layout=ProjectLayout(root=str(REPO_ROOT)),
                    env=EnvironmentConfig(),
                    setup_config=SetupConfig(cache_dir=str(REPO_ROOT / ".cache" / "value_pool")),
                )
        except Exception as exception:
            dynamic_error = f"{type(exception).__name__}: {exception}"

        dynamic_summary, dynamic_by_graph = _dynamic_evidence(dynamic_path)
        if dynamic_error:
            dynamic_summary["error"] = dynamic_error
        seeds = build_seeds(vectors, dynamic_by_graph)
        counts = Counter(item["type"] for item in vectors)
        summary = {
            "seeds": len(seeds),
            **{kind.lower(): counts[kind] for kind in VECTOR_TYPES},
            "dynamic_status": dynamic_summary.get("execution_status"),
            "vectors": vector_stats,
        }
        project = ActiveProject(
            self.workspace, package, apk_path, result_dir, vectors, seeds, summary
        )
        self.active = project
        self._save(project, dynamic_summary)
        return self._ready(project, restored=False)

    def _save(self, project: ActiveProject, dynamic: dict[str, Any]) -> None:
        _atomic_json(
            self.session_path,
            {
                "package_name": project.package_name,
                **_apk_identity(project.apk_path, self.workspace),
                "static_result": str(project.result_dir / "static.json"),
                "dynamic_result": str(project.result_dir / "dynamic.json"),
                "summary": project.summary,
                "dynamic_evidence": dynamic,
                "vectors": project.vectors,
                "seeds": project.seeds,
            },
        )

    def _restore_package(self, package_name: str) -> ActiveProject | None:
        """Restore a matching saved package before trying a device download."""
        if not self.session_path.is_file():
            return None
        try:
            payload = _load_json(self.session_path)
            if payload.get("package_name") != package_name:
                return None
            apk_path = Path(payload["apk_file"])
            if not apk_path.is_absolute():
                apk_path = self.workspace / apk_path
            return self._restore(apk_path)
        except (KeyError, OSError, TypeError, ValueError, json.JSONDecodeError):
            return None

    def _restore(self, apk_path: Path) -> ActiveProject | None:
        if not self.session_path.is_file():
            return None
        try:
            payload = _load_json(self.session_path)
            identity = _apk_identity(apk_path, self.workspace)
            if any(payload.get(key) != identity[key] for key in ("apk_file", "size", "mtime_ns")):
                return None
            result_dir = RESULTS_ROOT / str(payload["package_name"])
            if not (result_dir / "static.json").is_file():
                return None
            return ActiveProject(
                self.workspace,
                str(payload["package_name"]),
                apk_path,
                result_dir,
                list(payload.get("vectors", [])),
                list(payload.get("seeds", [])),
                dict(payload.get("summary", {})),
            )
        except (KeyError, OSError, TypeError, ValueError, json.JSONDecodeError):
            return None

    def _project(self) -> ActiveProject:
        if self.active is None:
            raise ToolError("PROJECT_NOT_READY", "Call analyze_apk or analyze_app first.")
        return self.active

    def _explorer(self) -> ProgramExplorer:
        project = self._project()
        if project.explorer is None:
            project.explorer = ProgramExplorer(project.apk_path)
        return project.explorer

    @staticmethod
    def _ready(project: ActiveProject, *, restored: bool) -> dict[str, Any]:
        return {
            "status": "ready",
            "session": "restored" if restored else "created",
            "package_name": project.package_name,
            "apk": project.apk_path.name,
            "summary": project.summary,
        }

    def seeds(self, offset: int = 0, limit: int = 20, vector_type: str | None = None) -> dict[str, Any]:
        values = self._project().seeds
        if vector_type:
            if vector_type not in VECTOR_TYPES:
                raise ToolError("INVALID_ARGUMENT", f"Unknown vector type: {vector_type}")
            values = [item for item in values if vector_type in item.get("vector_types", [])]
        return _page(values, offset, limit)

    def flow(self, seed_id: str) -> dict[str, Any]:
        project = self._project()
        seed = next((item for item in project.seeds if item.get("seed_id") == seed_id), None)
        if seed is None:
            raise ToolError("SEED_NOT_FOUND", f"Seed was not found: {seed_id}")
        wanted = set(seed.get("vector_ids", []))
        return {**seed, "vectors": [item for item in project.vectors if item.get("vector_id") in wanted]}

    def native(self, target: str | None = None) -> dict[str, Any]:
        project = self._project()
        boundaries = [
            item for item in project.vectors
            if item.get("type") == "NATIVE_BOUNDARY"
            and (target is None or target in str(item))
        ]
        libraries = []
        with ZipFile(project.apk_path) as archive:
            for name in archive.namelist():
                if name.startswith("lib/") and name.endswith(".so"):
                    parts = name.split("/")
                    libraries.append({"path": name, "abi": parts[1], "name": parts[-1]})
        if target and not boundaries and not libraries:
            raise ToolError("NATIVE_TARGET_NOT_FOUND", f"Native target was not found: {target}")
        return {"libraries": libraries, "related_vectors": boundaries}