"""Send a compact analysis summary to a Discord webhook."""

from __future__ import annotations

import json
import logging
import os
import re
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener

try:
    from dotenv import load_dotenv
except ImportError:
    load_dotenv = None

PROJECT_ROOT = Path(__file__).resolve().parents[2]
LOGGER = logging.getLogger(__name__)
WEBHOOK_PATTERN = re.compile(
    r"https://discord\.com/api(?:/v\d+)?/webhooks/\d+/[A-Za-z0-9_-]+"
)
VULNERABILITY_TYPES = (
    "Intent Redirection",
    "Intent Spoofing",
    "Intent Injection",
)


class NoRedirect(HTTPRedirectHandler):
    """Prevent webhook requests from following redirects."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        """Reject a redirect response for the given webhook request."""
        return None


def _webhook_url() -> str:
    """Load and normalize the configured Discord webhook URL."""
    if load_dotenv is not None:
        load_dotenv(PROJECT_ROOT / ".env", override=False)
    webhook_url = os.getenv("DISCORD_WEBHOOK_URL", "").strip()
    if webhook_url.startswith("https://discordapp.com/"):
        return "https://discord.com/" + webhook_url.removeprefix("https://discordapp.com/")
    return webhook_url

def _analyst_name() -> str:
    """Load the configured analyst name from the environment."""
    if load_dotenv is not None:
        load_dotenv(PROJECT_ROOT / ".env", override=False)
    return os.getenv("ANALYST_NAME", "").strip() or "Unknown"

def _safe_text(value: object, limit: int = 120) -> str:
    """Sanitize a value for Discord text and truncate it to the given limit."""
    text = " ".join(str(value).split())
    return "".join(
        character
        for character in text
        if character.isprintable() and character not in "`*~|\\"
    )[:limit]


def _load_json(path: Path) -> dict:
    """Load an analysis result JSON file from the given path."""
    with path.open("r", encoding="utf-8") as file:
        data = json.load(file)

    if not isinstance(data, dict):
        raise ValueError(f"JSON root must be an object: {path}")

    return data


def _finding_counts(static_result: dict) -> dict[str, int]:
    """Count confirmed Intent vulnerability types from a static result."""
    counts = {
        vulnerability_type: 0
        for vulnerability_type in VULNERABILITY_TYPES
    }

    for graph in static_result.get("flow_graphs", []):
        for path in graph.get("paths", []):
            for vulnerability_type in set(
                path.get("confirmed_types", [])
            ):
                if vulnerability_type in counts:
                    counts[vulnerability_type] += 1

    return counts


def build_analysis_message(
    apk_path: Path,
    static_result_path: Path | None,
    dynamic_result_path: Path | None,
    analysis_run_id: str,
    *,
    static_error: str | None = None,
    dynamic_error: str | None = None,
) -> str:
    """Build a Discord summary from static.json and dynamic.json results."""
    analyst_name = _analyst_name()
    if static_result_path is None:
        return "\n".join(
            (
                "## UnIntent Analysis Summary",
                f"**Analyst**: `{_safe_text(analyst_name)}`",
                f"**Target**: `{_safe_text(apk_path.name)}`",
                "**Status**: Static analysis failed",
                f"**Error**: `{_safe_text(static_error or 'static.json was not created', 300)}`",
            )
        )

    try:
        static_result = _load_json(static_result_path)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        return "\n".join(
            (
                "## UnIntent Analysis Summary",
                f"**Analyst**: `{_safe_text(analyst_name)}`",
                f"**Target**: `{_safe_text(apk_path.name)}`",
                "**Status**: Static result read failed",
                f"**Error**: `{_safe_text(error, 300)}`",
            )
        )

    target = static_result.get("apk") or apk_path.name
    counts = _finding_counts(static_result)

    lines = [
        "## UnIntent Analysis Summary",
        "",
        f"**Analyst**: `{_safe_text(analyst_name)}`",
        f"**Target**: `{_safe_text(target)}`",
        "",
        "**Static analysis**: Completed",
    ]

    lines.extend(
        f"- **{vulnerability_type}**: "
        f"{counts[vulnerability_type]} confirmed"
        for vulnerability_type in VULNERABILITY_TYPES
    )

    lines.append("")

    if dynamic_result_path is None:
        lines.extend(
            (
                "**Status**: Static completed / Dynamic failed",
                "**Dynamic verification**: Failed",
                f"**Dynamic error**: "
                f"`{_safe_text(dynamic_error or 'dynamic.json was not created', 300)}`",
            )
        )
        return "\n".join(lines)

    try:
        dynamic_result = _load_json(dynamic_result_path)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        lines.extend(
            (
                "**Status**: Static completed / Dynamic result read failed",
                "**Dynamic verification**: Failed",
                f"**Dynamic error**: `{_safe_text(error, 300)}`",
            )
        )
        return "\n".join(lines)

    execution = dynamic_result.get("execution", {})

    if execution.get("status") == "completed":
        lines.extend(
            (
                "**Status**: Completed",
                "",
                "**Dynamic verification**: Completed",
                f"- Tested paths: {execution.get('tested_paths', 0)}",
                f"- Reached paths: {execution.get('reached_paths', 0)}",
            )
        )

    else:
        lines.extend(
            (
                "**Status**: Static completed / Dynamic not executed",
                "",
                "**Dynamic verification**: Failed",
                f"- Tested paths: {execution.get('tested_paths', 0)}",
                f"- Reached paths: {execution.get('reached_paths', 0)}",
            )
        )
        reasons = execution.get("failure_reasons", [])

        if reasons:
            lines.append("**Dynamic failure reasons**:")

            for item in reasons[:5]:
                lines.append(
                    f"- `{_safe_text(item.get('reason', 'unknown'), 220)}` "
                    f"({item.get('count', 0)})"
                )
        else:
            lines.append(
                f"**Dynamic error**: "
                f"`{_safe_text(dynamic_error or 'No test case was executed', 300)}`"
            )

    return "\n".join(lines)

def send_discord_message(message: str) -> bool:
    """Send the given message through the configured Discord webhook."""
    webhook_url = _webhook_url()
    if not webhook_url or not WEBHOOK_PATTERN.fullmatch(webhook_url):
        return False
    if not message.strip() or len(message.encode("utf-16-le")) // 2 > 2000:
        return False

    request = Request(
        url=f"{webhook_url}?wait=true",
        data=json.dumps(
            {"content": message, "allowed_mentions": {"parse": []}},
            ensure_ascii=False,
        ).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "User-Agent": "UnIntent-Notifier/1.0",
        },
        method="POST",
    )
    try:
        with build_opener(NoRedirect()).open(request, timeout=5) as response:
            response_data = json.loads(response.read(65536))
            return response.status == 200 and bool(response_data.get("id"))
    except HTTPError as error:
        try:
            LOGGER.warning("Discord delivery failed: HTTP %s", error.code)
        finally:
            error.close()
    except (URLError, OSError, ValueError, json.JSONDecodeError):
        LOGGER.warning("Discord delivery failed: connection error or invalid response")
    return False

def notify_analysis_result(
    apk_path: Path,
    static_result_path: Path | None,
    dynamic_result_path: Path | None,
    analysis_run_id: str,
    *,
    static_error: str | None = None,
    dynamic_error: str | None = None,
) -> bool:
    """Send a notification without allowing webhook errors to stop analysis."""
    try:
        if not _webhook_url():
            return False

        return send_discord_message(
            build_analysis_message(
                apk_path,
                static_result_path,
                dynamic_result_path,
                analysis_run_id,
                static_error=static_error,
                dynamic_error=dynamic_error,
            )
        )

    except Exception:
        LOGGER.warning(
            "Discord notification failed; analysis will continue"
        )
        return False