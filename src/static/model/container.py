from __future__ import annotations

from dataclasses import dataclass

from src.static.model.values import MethodRef


@dataclass(frozen=True)
class ContainerSlot:
    """Identify one keyed slot on one abstract container object."""

    object_id: str
    key: str | None


@dataclass(frozen=True)
class ContainerWrite:
    """Retain the program point that supplies a container slot's value."""

    method: MethodRef
    instruction_index: int
    value_register: int
    relation: str


@dataclass(frozen=True)
class ContainerTransfer:
    """Describe a whole-container state transfer such as Bundle.putAll."""

    method: MethodRef
    instruction_index: int
    source_object_ids: tuple[str, ...]
    relation: str
    mode: str = "merge"


@dataclass(frozen=True)
class ContainerEntry:
    """Expose a resolved keyed writer while leaving provenance demand-driven."""

    key: str | None
    write: ContainerWrite
    via_transfer: bool = False
