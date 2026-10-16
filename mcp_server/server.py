#!/usr/bin/env python3
from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from mcp.server import MCPServer

from mcp_server.core import AnalysisService, ToolError, _page

mcp = MCPServer("UnIntent")
service = AnalysisService()


def _call(action: Any) -> dict[str, Any]:
    try:
        return action()
    except ToolError as exception:
        return exception.result()


@mcp.tool()
def analyze_apk() -> dict[str, Any]:
    """Analyze the single APK in the current workspace, or restore its session."""
    return _call(service.analyze_workspace)


@mcp.tool()
def analyze_app(package_name: str) -> dict[str, Any]:
    """Download and analyze an Android app by exact package name."""
    return _call(lambda: service.analyze_package(package_name))


@mcp.tool()
def get_analysis_seeds(
    offset: int = 0, limit: int = 20, vector_type: str | None = None
) -> dict[str, Any]:
    """List compact vulnerability-analysis starting points for the active APK."""
    return _call(lambda: service.seeds(offset, limit, vector_type))


@mcp.tool()
def get_analysis_frontiers(offset: int = 0, limit: int = 30) -> dict[str, Any]:
    """Page through compact DEX locations needing additional analysis."""
    return _call(lambda: service.frontiers(offset, limit))


@mcp.tool()
def get_flow(seed_id: str) -> dict[str, Any]:
    """Return the vectors and evidence for one analysis seed."""
    return _call(lambda: service.flow(seed_id))


@mcp.tool()
def get_method(method_id: str, offset: int = 0, limit: int = 100) -> dict[str, Any]:
    """Read one exact DEX method with paged instructions."""
    return _call(lambda: service._explorer().method(method_id, offset, limit))


@mcp.tool()
def get_callers(method_id: str, offset: int = 0, limit: int = 30) -> dict[str, Any]:
    """Find callers of one exact DEX method."""
    return _call(lambda: _page(service._explorer().callers(method_id), offset, limit))


@mcp.tool()
def get_callees(method_id: str, offset: int = 0, limit: int = 30) -> dict[str, Any]:
    """Find declared and resolved callees of one exact DEX method."""
    return _call(lambda: _page(service._explorer().callees(method_id), offset, limit))


@mcp.tool()
def find_usages(symbol: str, offset: int = 0, limit: int = 30) -> dict[str, Any]:
    """Find DEX method, class, or field references containing a symbol."""
    return _call(lambda: _page(service._explorer().usages(symbol), offset, limit))


@mcp.tool()
def search_code(query: str, offset: int = 0, limit: int = 30) -> dict[str, Any]:
    """Substring-search DEX methods, references, constants, keys, actions, and URIs."""
    return _call(lambda: _page(service._explorer().search(query), offset, limit))


@mcp.tool()
def inspect_native(target: str | None = None) -> dict[str, Any]:
    """List APK native libraries and native-boundary vectors without guessing semantics."""
    return _call(lambda: service.native(target))


if __name__ == "__main__":
    mcp.run()
