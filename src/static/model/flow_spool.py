"""Disk-backed storage for raw flow graphs awaiting consumption."""

from __future__ import annotations

import os
import pickle
import tempfile
from collections.abc import Iterator
from pathlib import Path
from typing import BinaryIO

from src.static.model.evidence import FlowGraph


class FlowGraphSpool:
    """Disk-backed collection for raw flow graphs.

    Graphs are written immediately; only each sink's latest records stay active.
    """

    def __init__(self, directory: str | Path, flush_every: int = 128) -> None:
        target = Path(directory)
        target.mkdir(parents=True, exist_ok=True)
        descriptor, name = tempfile.mkstemp(
            prefix=".static-flow-",
            suffix=".pickle.tmp",
            dir=target,
        )
        self.path = Path(name)
        self._stream: BinaryIO = os.fdopen(descriptor, "w+b")
        self.flush_every = max(1, flush_every)
        self._records: list[tuple[int, int]] = []
        self._records_by_group: dict[str, list[tuple[int, int]]] = {}
        self._writes_since_flush = 0
        self.flushes = 0
        self.closed = False

    def __len__(self) -> int:
        return len(self._records)

    def __iter__(self) -> Iterator[FlowGraph]:
        yield from self.iter_payloads()

    @property
    def bytes_written(self) -> int:
        if self.closed:
            return self.path.stat().st_size if self.path.exists() else 0
        self._stream.flush()
        return self.path.stat().st_size

    def replace_group(self, group: str) -> None:
        """Deactivate a sink's prior round without reading its graphs."""
        stale = set(self._records_by_group.pop(group, ()))
        if stale:
            self._records = [record for record in self._records if record not in stale]

    def append(self, graph: FlowGraph, *, group: str | None = None) -> bool:
        """Write one graph without copying or revisiting prior records."""
        self._ensure_open()
        record = self._write_graph(graph)
        self._records.append(record)
        if group is not None:
            self._records_by_group.setdefault(group, []).append(record)
        return True

    def iter_payloads(self) -> Iterator[FlowGraph]:
        self._ensure_open()
        self.flush()
        with self.path.open("rb") as stream:
            for offset, _length in self._records:
                stream.seek(offset)
                yield pickle.load(stream)

    def flush(self) -> None:
        self._ensure_open()
        self._stream.flush()
        if self._writes_since_flush == 0:
            return
        self._writes_since_flush = 0
        self.flushes += 1

    def close(self, *, remove: bool = True) -> None:
        if not self.closed:
            self._stream.close()
            self.closed = True
        if remove:
            self.path.unlink(missing_ok=True)

    def __enter__(self) -> FlowGraphSpool:
        return self

    def __exit__(self, _exc_type: object, _exc: object, _traceback: object) -> None:
        self.close(remove=True)

    def _write_graph(self, graph: FlowGraph) -> tuple[int, int]:
        self._stream.seek(0, os.SEEK_END)
        offset = self._stream.tell()
        pickle.dump(graph, self._stream, protocol=pickle.HIGHEST_PROTOCOL)
        length = self._stream.tell() - offset
        self._writes_since_flush += 1
        if self._writes_since_flush >= self.flush_every:
            self.flush()
        return offset, length

    def _ensure_open(self) -> None:
        if self.closed:
            raise RuntimeError("flow graph spool is closed")
