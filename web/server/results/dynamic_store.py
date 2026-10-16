from __future__ import annotations

import json
from pathlib import Path
from typing import Any


class DynamicAnalysisStore:
    def __init__(self, data_file: Path | None, expected_package: str):
        self.data_file = data_file if data_file and data_file.is_file() else None
        self.error: str | None = None
        self.data: dict[str, Any] = {}
        if self.data_file:
            with self.data_file.open("r", encoding="utf-8") as stream:
                self.data = json.load(stream)
            package = self.data.get("package")
            if package and package != expected_package:
                self.error = (
                    f"dynamic package mismatch: expected {expected_package}, got {package}"
                )
                self.data = {}
                self.data_file = None

        self.flows = {
            flow["flow_id"]: flow
            for flow in self.data.get("flows", [])
            if flow.get("flow_id")
        }
        self.payloads: dict[str, tuple[str, dict[str, Any]]] = {}
        for flow_id, flow in self.flows.items():
            for payload in flow.get("payloads", []):
                payload_id = payload.get("payload_id")
                if payload_id:
                    self.payloads[payload_id] = (flow_id, payload)

    @property
    def available(self) -> bool:
        """Return whether a dynamic result document was loaded."""
        return bool(self.data)

    def overview(self) -> dict[str, Any]:
        """Return compact counts used outside the dynamic result page."""
        payloads = [payload for _, payload in self.payloads.values()]
        return {
            "available": self.available,
            "error": self.error,
            "package": self.data.get("package"),
            "schema_version": self.data.get("schema_version"),
            "source_file": str(self.data_file) if self.data_file else None,
            "flow_count": len(self.flows),
            "payload_count": len(payloads),
            "success_count": sum(1 for item in payloads if item.get("status") == "success"),
            "failure_count": sum(1 for item in payloads if item.get("status") == "failure"),
        }

    def flow_summaries(self) -> list[dict[str, Any]]:
        """Return flow rows with status counts derived from their payloads."""
        values = []
        for flow in self.flows.values():
            payloads = flow.get("payloads", [])
            values.append({
                "flow_id": flow["flow_id"],
                "entry_point": flow.get("entry_point", ""),
                "payload_count": len(payloads),
                "success_count": sum(
                    1 for item in payloads if item.get("status") == "success"
                ),
                "failure_count": sum(
                    1 for item in payloads if item.get("status") == "failure"
                ),
            })
        return values

    def payload_summaries(self, flow_id: str) -> list[dict[str, Any]] | None:
        """Return the payload list for one flow."""
        flow = self.flows.get(flow_id)
        if flow is None:
            return None
        return [
            {
                "payload_id": payload.get("payload_id"),
                "status": payload.get("status"),
                "inputs": payload.get("inputs", []),
                "result": payload.get("result", {}),
            }
            for payload in flow.get("payloads", [])
        ]

    def detail(self, payload_id: str) -> dict[str, Any] | None:
        """Return the complete dashboard payload with its parent flow id."""
        found = self.payloads.get(payload_id)
        if found is None:
            return None
        flow_id, payload = found
        return {"flow_id": flow_id, **payload}
