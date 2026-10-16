from __future__ import annotations

import re
from dataclasses import replace
from typing import Any

from src.static.model.values import InstructionIR, MethodIR, MethodRef


def move_aliases(method: MethodIR, register: int, before: int) -> set[int]:
    """Collect registers connected by local move instructions."""
    aliases = {register}
    changed = True
    while changed:
        changed = False
        for instruction in method.instructions[:before]:
            if (
                not instruction.name.startswith("move")
                or instruction.name.startswith("move-result")
                or len(instruction.registers) < 2
            ):
                continue
            target, source = instruction.registers[:2]
            if target in aliases or source in aliases:
                size = len(aliases)
                aliases.update((target, source))
                changed = changed or len(aliases) != size
    return aliases

REFERENCE_RE = re.compile(r"^(L[^;]+;)->([^\(\s]+)(\(.*)$")


def normalize_descriptor(value: str) -> str:
    return "".join(value.split())


def parse_method_reference(value: str | None) -> tuple[str, str, str] | None:
    if not value:
        return None
    match = REFERENCE_RE.match(value)
    if match is None:
        return None
    owner, name, descriptor = match.groups()
    return owner, name, normalize_descriptor(descriptor)


def method_ref(method: Any) -> MethodRef:
    return MethodRef(
        class_name=str(method.get_class_name()),
        name=str(method.get_name()),
        descriptor=normalize_descriptor(str(method.get_descriptor())),
    )


def parse_parameter_types(descriptor: str) -> list[str]:
    descriptor = normalize_descriptor(descriptor)
    result: list[str] = []
    cursor = 1
    while cursor < len(descriptor) and descriptor[cursor] != ")":
        start = cursor
        while descriptor[cursor] == "[":
            cursor += 1
        if descriptor[cursor] == "L":
            cursor = descriptor.index(";", cursor) + 1
        else:
            cursor += 1
        result.append(descriptor[start:cursor])
    return result


def type_width(dex_type: str) -> int:
    return 2 if dex_type in {"J", "D"} else 1


def parameter_registers(method: Any) -> dict[int, tuple[int, str]]:
    code = method.get_code()
    if code is None:
        return {}
    cursor = code.get_registers_size() - code.get_ins_size()
    if "static" not in str(method.get_access_flags_string()).split():
        cursor += 1
    result: dict[int, tuple[int, str]] = {}
    for formal_index, dex_type in enumerate(parse_parameter_types(str(method.get_descriptor()))):
        result[cursor] = (formal_index, dex_type)
        cursor += type_width(dex_type)
    return result


def receiver_register(method: Any) -> int | None:
    code = method.get_code()
    if code is None or "static" in str(method.get_access_flags_string()).split():
        return None
    return code.get_registers_size() - code.get_ins_size()


def instruction_ir(offset: int, instruction: Any) -> InstructionIR:
    registers: list[int] = []
    reference: str | None = None
    string_value: str | None = None
    literal_value: int | None = None
    type_value: str | None = None
    name = str(instruction.get_name())
    branch_target = None
    for operand in instruction.get_operands():
        kind = getattr(operand[0], "name", str(operand[0]))
        if kind == "REGISTER":
            registers.append(int(operand[1]))
        elif kind == "LITERAL":
            literal_value = int(operand[1])
        elif kind == "OFFSET":
            branch_target = offset + 2 * int(operand[1])
        if len(operand) >= 3 and isinstance(operand[2], str):
            rendered = operand[2]
            if "->" in rendered:
                reference = rendered
            elif name.startswith("const-string") or (
                name.startswith("const-class") and rendered.startswith("L")
            ):
                string_value = rendered
            elif rendered.startswith(("L", "[")) and name.startswith(
                ("new-instance", "new-array", "check-cast", "instance-of")
            ):
                type_value = normalize_descriptor(rendered)
    return InstructionIR(
        offset=offset,
        name=name,
        output=str(instruction.get_output()),
        registers=tuple(registers),
        reference=reference,
        string_value=string_value,
        literal_value=literal_value,
        type_value=type_value,
        branch_target=branch_target,
    )


def method_ir(method: Any) -> MethodIR | None:
    # Accepts either a raw dex.EncodedMethod (from walking DEX classes
    # directly) or an androguard MethodAnalysis wrapper (which exposes
    # get_method() to reach the same raw object). Extraction below only
    # ever touches the raw method's own bytecode, so both inputs behave
    # identically.
    if hasattr(method, "get_method"):
        method = method.get_method()
    code = method.get_code()
    if code is None:
        return None
    raw = dict(method.get_instructions_idx())
    instructions = [instruction_ir(offset, item) for offset, item in raw.items()]
    for index, item in enumerate(instructions):
        if item.name not in {"packed-switch", "sparse-switch"}:
            continue
        payload = raw.get(item.branch_target)
        if payload is not None and hasattr(payload, "get_keys") and hasattr(payload, "get_targets"):
            instructions[index] = replace(item, switch_cases=tuple(
                (int(key), item.offset + 2 * int(target))
                for key, target in zip(payload.get_keys(), payload.get_targets(), strict=True)
            ))
    return MethodIR(
        method=method_ref(method),
        access=str(method.get_access_flags_string()),
        instructions=instructions,
        parameters=parameter_registers(method),
        receiver_register=receiver_register(method),
    )


def invocation_formals(instruction: InstructionIR) -> list[tuple[int, str, int]]:
    parsed = parse_method_reference(instruction.reference)
    if parsed is None:
        return []
    descriptor = parsed[2]
    register_cursor = 0 if instruction.name.startswith("invoke-static") else 1
    result: list[tuple[int, str, int]] = []
    for formal_index, dex_type in enumerate(parse_parameter_types(descriptor)):
        if register_cursor >= len(instruction.registers):
            break
        result.append((formal_index, dex_type, instruction.registers[register_cursor]))
        register_cursor += type_width(dex_type)
    return result


def invocation_receiver(instruction: InstructionIR) -> int | None:
    if not instruction.name.startswith("invoke-") or instruction.name.startswith("invoke-static"):
        return None
    return instruction.registers[0] if instruction.registers else None


def destination_register(instruction: InstructionIR) -> int | None:
    if not instruction.registers:
        return None
    no_write = (
        "invoke-",
        "return",
        "if-",
        "goto",
        "monitor-",
        "throw",
        "packed-switch",
        "sparse-switch",
        "fill-array-data",
        "filled-new-array",
        "iput",
        "sput",
        "aput",
        "nop",
    )
    if instruction.name.startswith(no_write):
        return None
    writes = (
        "move",
        "const",
        "new-instance",
        "new-array",
        "check-cast",
        "instance-of",
        "array-length",
        "iget",
        "sget",
        "aget",
        "cmp",
        "neg-",
        "not-",
        "int-to-",
        "long-to-",
        "float-to-",
        "double-to-",
        "add-",
        "sub-",
        "mul-",
        "div-",
        "rem-",
        "and-",
        "or-",
        "xor-",
        "shl-",
        "shr-",
        "ushr-",
        "rsub-",
    )
    return instruction.registers[0] if instruction.name.startswith(writes) else None
