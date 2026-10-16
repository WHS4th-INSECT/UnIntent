# Androguard-backed parser for downloaded base APKs.

from __future__ import annotations

import logging
import builtins
from pathlib import Path

from androguard.core.apk import APK
from androguard.core.dex import DEX

from src.models.apk import ApkMetadata, ParsedApkContext
from src.parsing.androguard_logging import disable_androguard_logs

LOGGER = logging.getLogger(__name__)


# Convert an optional manifest value into a non-empty string or None.
def _optional_string(value: object | None) -> str | None:
    if value is None:
        return None
    normalized_value = str(value).strip()
    return normalized_value or None


# Convert an optional manifest value into an integer or None.
def _optional_integer(value: object | None) -> int | None:
    normalized_value = _optional_string(value)
    return int(normalized_value) if normalized_value is not None else None


def _configure_resource_encoding() -> None:
    """Make Androguard's bundled JSON resources consistently use UTF-8."""
    from androguard.core import api_specific_resources

    if getattr(api_specific_resources, "_unintent_utf8_resources", False):
        return
    default_open = builtins.open

    def open_resource(file, mode="r", *args, **kwargs):
        if "b" not in mode:
            kwargs.setdefault("encoding", "utf-8")
        return default_open(file, mode, *args, **kwargs)

    api_specific_resources.open = open_resource
    api_specific_resources._unintent_utf8_resources = True


def parse_apk(apk_path: Path) -> ParsedApkContext:
    """Parse one APK into a shared Androguard analysis context."""
    resolved_path = apk_path.expanduser().resolve()
    if not resolved_path.is_file() or resolved_path.suffix.lower() != ".apk":
        raise FileNotFoundError(f"APK file not found: {resolved_path}")
    LOGGER.info("APK parsing started: apk=%s", resolved_path)
    disable_androguard_logs()
    _configure_resource_encoding()
    apk = APK(str(resolved_path))
    dex_objects = tuple(
        DEX(raw_dex, using_api=apk.get_target_sdk_version())
        for raw_dex in apk.get_all_dex()
    )
    metadata = ApkMetadata(
        package_name=apk.get_package(),
        app_name=_optional_string(apk.get_app_name()),
        version_name=_optional_string(apk.get_androidversion_name()),
        version_code=_optional_integer(apk.get_androidversion_code()),
        min_sdk=_optional_integer(apk.get_min_sdk_version()),
        target_sdk=_optional_integer(apk.get_target_sdk_version()),
    )
    context = ParsedApkContext(
        apk_path=resolved_path,
        metadata=metadata,
        apk=apk,
        dex_objects=dex_objects,
    )
    LOGGER.info(
        "APK parsing completed: package=%s dex_files=%d",
        metadata.package_name,
        len(dex_objects),
    )
    return context
