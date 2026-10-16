"""sink 탐색"""
from __future__ import annotations

from collections.abc import Callable

from src.static.search.api_rules import PENDING_INTENT, SinkRule
from src.static.search.dex_ir import parse_method_reference
from src.static.model.values import MethodIR, SinkSite


def scan_sinks(
    methods: dict[object, MethodIR],
    rules: tuple[SinkRule, ...],
    owner_lineage: Callable[[str], tuple[str, ...]] | None = None,
) -> list[SinkSite]:
    """Find only sink callsites; sources are discovered later by backward demand."""
    rules_by_name: dict[str, list[SinkRule]] = {}
    for rule in rules:
        for name in rule.method_names:
            rules_by_name.setdefault(name, []).append(rule)

    sinks: list[SinkSite] = []
    seen: set[tuple[str, int, str]] = set()
    for method in methods.values():
        for index, instruction in enumerate(method.instructions):
            parsed = parse_method_reference(instruction.reference)
            if parsed is None or parsed[0] == PENDING_INTENT:
                continue
            owner, api_name, _descriptor = parsed
            lineage = owner_lineage(owner) if owner_lineage is not None else (owner,)
            for rule in rules_by_name.get(api_name, ()):
                if not rule.matches(instruction, lineage):
                    continue
                registers = rule.argument_registers(instruction)
                if not registers and not rule.allow_control_only:
                    continue
                key = (method.display(), instruction.offset, rule.rule_id)
                if key in seen:
                    continue
                seen.add(key)
                sinks.append(
                    SinkSite(
                        rule_id=rule.rule_id,
                        category=rule.category,
                        method=method.method,
                        instruction_index=index,
                        offset=instruction.offset,
                        api=instruction.reference or api_name,
                        api_name=api_name,
                        argument_registers=registers,
                    )
                )
    sinks.sort(key=lambda site: (site.method.display(), site.offset, site.rule_id))
    return sinks


__all__ = [
    "scan_sinks",
]
