from __future__ import annotations

from typing import Any

from src.static.model.values import MethodIR
from src.static.search.api_rules import GUARD_DESCRIPTIONS, GUARD_KINDS
from src.static.search.dex_ir import destination_register, parse_method_reference


def assess_guards(
    method: MethodIR, before: int, backend: Any | None = None
) -> list[dict[str, Any]]:
    """Classify exact framework guard calls and their relation to the sink."""

    cfg = backend.cfg_for(method) if backend is not None else None
    controlling = cfg.controlling_branches(before) if cfg is not None else ()
    result: list[dict[str, Any]] = []
    for index, instruction in enumerate(method.instructions[:before]):
        if not instruction.name.startswith("invoke-"):
            continue
        parsed = parse_method_reference(instruction.reference)
        if parsed is None:
            continue
        owner, name, _descriptor = parsed
        kind = GUARD_KINDS.get(name)
        if kind is None or not owner.startswith("Landroid/"):
            continue
        dominates = cfg.instruction_dominates(index, before) if cfg is not None else None
        following = method.instructions[index + 1] if index + 1 < len(method.instructions) else None
        result_register = (
            destination_register(following)
            if following is not None and following.name.startswith("move-result")
            else None
        )
        controls_sink = False
        if cfg is not None and result_register is not None:
            controls_sink = any(
                index + 1 in cfg.reaching_definitions(result_register, branch).instruction_indices
                for branch in controlling
                if result_register in method.instructions[branch].registers
            )
        if kind == "enforcing":
            effectiveness = (
                "not_evaluated" if cfg is None
                else "enforcing_dominates_sink" if dominates
                else "not_effective_for_sink"
            )
        elif following is None:
            effectiveness = "not_evaluated"
        elif result_register is None:
            effectiveness = "result_discarded"
        elif dominates and controls_sink:
            effectiveness = "controls_sink_reachability"
        elif cfg is None:
            effectiveness = "not_evaluated"
        else:
            effectiveness = "not_effective_for_sink"
        reference = instruction.reference or ""
        raw = f"{GUARD_DESCRIPTIONS[kind]}: {reference}@0x{instruction.offset:04x}"
        result.append({
            "guard": raw,
            "method": method.display(),
            "offset": instruction.offset,
            "api": reference,
            "kind": kind,
            "effectiveness": effectiveness,
            "dominates_sink": dominates,
            "controls_sink_reachability": controls_sink,
            "result_usage": "discarded" if result_register is None else "retained",
            "exception_handler_present": "unknown" if kind == "enforcing" else None,
            "reason": effectiveness,
        })
    return result
