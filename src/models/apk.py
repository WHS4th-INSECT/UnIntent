"""Immutable models for parsed APKs."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from androguard.core.apk import APK
    from androguard.core.dex import DEX


@dataclass(frozen=True, slots=True)
class ApkMetadata:
    """Application metadata extracted from AndroidManifest.xml."""

    package_name: str
    app_name: str | None
    version_name: str | None
    version_code: int | None
    min_sdk: int | None
    target_sdk: int | None

    def __post_init__(self) -> None:
        self.validate()

    def validate(self) -> None:
        if not self.package_name.strip():
            raise ValueError("package_name must not be empty")
        for field_name, value in (
            ("version_code", self.version_code),
            ("min_sdk", self.min_sdk),
            ("target_sdk", self.target_sdk),
        ):
            if value is not None and value < 0:
                raise ValueError(f"{field_name} must not be negative")

@dataclass(frozen=True, slots=True)
class ParsedApkContext:
    """Androguard objects and metadata shared by static-analysis cores."""

    apk_path: Path
    metadata: ApkMetadata
    apk: APK
    dex_objects: tuple[DEX, ...]
