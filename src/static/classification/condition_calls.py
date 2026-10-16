from __future__ import annotations

"""조건식에 등장하는 메서드 호출을 해석함"""

from dataclasses import dataclass
import hashlib
import json
from src.static.classification.branch_predicates import (
    combine,
    compare,
    constant,
    integer_operation,
    negate,
)
from src.static.model.values import MethodRef
from src.static.search.dex_ir import invocation_formals, invocation_receiver, parse_method_reference


@dataclass(frozen=True)
class RecordedExecution:
    """Keep a verified call suffix and the uncertainty of its selected provenance."""

    chain: tuple
    evidence: dict
    reasons: tuple[str, ...]
    fingerprint: str


def _method(value):
    """Parse a recorded method without resolving new callers or dispatch targets."""
    parsed = parse_method_reference(value) if isinstance(value, str) else None
    return MethodRef(*parsed) if parsed else None


def _legacy_target(step):
    """Read old argument/receiver records only when structured evidence is absent."""
    relation = step.relation if isinstance(step.relation, str) else ""
    for prefix in ("exact actual argument -> ", "actual argument -> "):
        if relation.startswith(prefix):
            return _method(relation[len(prefix):].split(" parameter[", 1)[0]), "argument_transfer"
    if relation.startswith("exact receiver -> "):
        return _method(relation[len("exact receiver -> "):].removesuffix(" this")), "receiver_transfer"
    return None, None


def _validate(backend, step, item):
    """Check recorded sites, selected signatures and actual registers against DEX."""
    if (not isinstance(item, dict) or type(item.get("schema_version")) is not int
            or item.get("schema_version") != 1):
        return None, "execution_schema_invalid"
    role = item.get("role")
    if not isinstance(role, str) or role not in {"argument_transfer", "receiver_transfer", "return_value"}:
        return None, "execution_role_invalid"
    selections = {"argument_transfer": {"exact_call_context", "observed_caller"},
                  "receiver_transfer": {"exact_call_context"},
                  "return_value": {"selected_return"}}
    selection = item.get("selection")
    if not isinstance(selection, str) or selection not in selections[role]:
        return None, "execution_selection_invalid"
    caller_ref, selected = _method(item.get("caller_method")), _method(item.get("selected_callee"))
    caller = backend.methods.get(caller_ref)
    if caller is None or selected not in backend.methods or caller_ref != _method(step.method):
        return None, "execution_method_mismatch"
    index = item.get("callsite_index")
    if type(index) is not int or not 0 <= index < len(caller.instructions):
        return None, "execution_callsite_invalid"
    instruction = caller.instructions[index]
    if (type(item.get("callsite_offset")) is not int or type(step.offset) is not int
            or instruction.offset != item.get("callsite_offset") or instruction.offset != step.offset
            or instruction.name != item.get("opcode") or not instruction.name.startswith("invoke-")):
        return None, "execution_callsite_mismatch"
    declared = _method(instruction.reference)
    if declared is None or declared != _method(item.get("declared_callee")):
        return None, "execution_declared_target_mismatch"
    if (declared.name, declared.descriptor) != (selected.name, selected.descriptor):
        return None, "execution_selected_target_mismatch"
    if instruction.name.startswith(("invoke-static", "invoke-direct")) and selected != declared:
        return None, "execution_selected_target_mismatch"
    arguments = [{"formal_index": formal, "register": register, "type": kind}
                 for formal, kind, register in invocation_formals(instruction)]
    recorded_arguments = item.get("actual_arguments")
    recorded_receiver = item.get("receiver_register")
    if (not isinstance(recorded_arguments, list)
            or any(not isinstance(arg, dict) or type(arg.get("formal_index")) is not int
                   or type(arg.get("register")) is not int or not isinstance(arg.get("type"), str)
                   for arg in recorded_arguments)
            or recorded_arguments != arguments
            or (recorded_receiver is not None and type(recorded_receiver) is not int)
            or recorded_receiver != invocation_receiver(instruction)):
        return None, "execution_argument_mapping_mismatch"
    return (caller, index, selected), None


def check_recovered_calls(backend, chain):
    """Keep prefix recovery from silently proving an unresolved selected dispatch."""
    reasons, records = set(), []
    for (caller_ref, index), (selected, _) in zip(chain, chain[1:]):
        caller = backend.methods.get(caller_ref)
        call = caller.instructions[index] if caller and 0 <= index < len(caller.instructions) else None
        declared = _method(call.reference) if call else None
        failure = None
        if call is None or not call.name.startswith("invoke-") or declared is None:
            failure = "execution_prefix_callsite_invalid"
        elif (declared.name, declared.descriptor) != (selected.name, selected.descriptor):
            failure = "execution_selected_target_mismatch"
        elif call.name.startswith(("invoke-static", "invoke-direct")):
            if declared != selected:
                failure = "execution_selected_target_mismatch"
        else:
            failure = "execution_dispatch_not_proven"
        if failure:
            reasons.add(failure)
        records.append({"caller": caller_ref.display(), "callsite_offset": call.offset if call else None,
                        "selected_callee": selected.display(), "reason": failure,
                        "status": "unverified" if failure else "dex_direct_call"})
    return tuple(sorted(reasons)), records


def read_recorded_execution(backend, site, source, *, max_depth=8, max_records=256):
    """Recover selected synchronous frames, preserving return and event boundaries separately."""
    chain = [(site.method, site.instruction_index)]
    steps = tuple(getattr(getattr(source, "origin", None), "path", ()))
    records, boundaries, reasons = [], [], set()
    boundary_cut = False
    if len(steps) > max_records:
        reasons.add("execution_evidence_limit")
    # Read in the same reverse provenance order as the legacy suffix recovery.
    for position in range(len(steps) - 1, max(-1, len(steps) - max_records - 1), -1):
        step = steps[position]
        raw = getattr(step, "evidence", {}) or {}
        if not isinstance(raw, dict):
            reasons.add("execution_schema_invalid")
            continue
        edge_type = str(step.edge_type or "")
        state_boundary = raw.get("execution_boundary")
        state_transfer = state_boundary is not None or step.relation in (
            "field read", "keyed container field read", "collection element read")
        if (state_transfer or edge_type.startswith("ICC")
                or edge_type in {"ASYNC", "CALLBACK", "FRAMEWORK_CALLBACK"}):
            boundaries.append({"trace_index": position, "kind": "STATE_TRANSFER" if state_transfer else edge_type,
                               "method": step.method, "offset": step.offset,
                               "direct": step.direct, "synchronous_replay": False,
                               "producer_boundary": state_boundary})
            reasons.add("execution_boundary_not_replayed")
            boundary_cut = True
        structured = "call_transition" in raw
        target, role = (None, None) if structured else _legacy_target(step)
        if not structured and target is None:
            continue
        record = {"trace_index": position, "source": "producer" if structured else "legacy",
                  "role": role, "consumed": False}
        if structured:
            item = raw["call_transition"]
            record["transition"] = item
            record["role"] = item.get("role") if isinstance(item, dict) else None
            validated, failure = _validate(backend, step, item)
            if failure:
                # Corrupt/inconsistent structured evidence must not bypass validation
                # by falling back to an older human-readable relation string.
                record.update(status="rejected", reason=failure)
                reasons.add(failure)
                records.append(record)
                continue
            caller, index, target = validated
            role = item["role"]
        else:
            caller = backend.methods.get(_method(step.method))
            index = caller.offset_to_index.get(step.offset) if caller else None
            if index is None:
                continue
            call = caller.instructions[index]
            # Compatibility records cannot invent an override or a new call edge.
            if not call.name.startswith("invoke-") or _method(call.reference) != target:
                continue
        record.update(caller=caller.display(), callsite_offset=caller.instructions[index].offset,
                      selected_callee=target.display(), role=role, status="site_validated")
        if boundary_cut:
            record["status"] = "boundary_segment_not_replayed"
            records.append(record)
            continue
        if role == "return_value":
            record["status"] = "value_provenance_only"
            records.append(record)
            continue
        if target != chain[0][0]:
            record["status"] = "outside_current_suffix"
            records.append(record)
            continue
        if step.direct is False:
            reasons.add("execution_selected_call_approximate")
            record["status"] = "approximate_not_replayed"
        elif len(chain) > max_depth:
            reasons.add("recorded_call_depth_limit")
            record["status"] = "depth_limited"
        elif caller.method in {ref for ref, _ in chain}:
            reasons.add("recorded_recursive_route")
            record["status"] = "recursive_not_replayed"
        else:
            if not caller.instructions[index].name.startswith(("invoke-static", "invoke-direct")):
                # A selected virtual target and matching DEX signature do not
                # prove that this receiver dispatches to it on this execution.
                reasons.add("execution_dispatch_not_proven")
            chain.insert(0, (caller.method, index))
            record.update(status="replayed_frame", consumed=True)
        records.append(record)
    transfer = getattr(source, "entry_transfer_evidence", ()) or ()
    if transfer:
        reasons.add("execution_boundary_not_replayed")
        boundaries.append({"kind": "ENTRY_TRANSFER", "count": len(transfer),
                           "synchronous_replay": False})
    evidence = {"schema_version": 1, "scope": "selected_trace_call_suffix",
                "producer_records": sum(r["source"] == "producer" for r in records),
                "legacy_records": sum(r["source"] == "legacy" for r in records),
                "consumed_calls": sum(r["consumed"] for r in records),
                "transitions": list(reversed(records)), "boundaries": list(reversed(boundaries)),
                "uncertainty_reasons": sorted(reasons), "runtime_validated": False,
                "recorded_chain": [{"method": ref.display(), "target_offset": backend.methods[ref].instructions[i].offset}
                                   for ref, i in chain]}
    identity = {"evidence": evidence, "entry_transfer_evidence": transfer,
                "origin": {k: getattr(getattr(source, "origin", None), k, None)
                           for k in ("kind", "component", "method", "offset", "api", "field", "key")}}
    fingerprint = hashlib.sha256(json.dumps(identity, sort_keys=True, separators=(",", ":"),
                                          default=str).encode()).hexdigest()
    return RecordedExecution(tuple(chain), evidence, tuple(sorted(reasons)), fingerprint)





@dataclass(frozen=True)
class AccessorSummary:
    operations: tuple
    returned: dict


def build_accessor_summary(method, resolve_call=None):
    """Infer an exact normal-return transfer for small getters, setters and captures."""
    if not method.instructions or len(method.instructions) > 32:
        return None
    registers = {r: {"slot": r} for r in method.parameters}
    if method.receiver_register is not None:
        registers[method.receiver_register] = {"slot": method.receiver_register}
    operations = []
    pending_result = None
    for index, instruction in enumerate(method.instructions):
        name, regs = instruction.name, instruction.registers
        if name.startswith("move-result"):
            if pending_result is None or len(regs) != 1:
                return None
            registers[regs[0]], pending_result = pending_result, None
            continue
        pending_result = None
        if name.startswith("return"):
            if index != len(method.instructions) - 1:
                return None
            value = registers.get(regs[0]) if regs else {"value": constant(None, "V")}
            return AccessorSummary(tuple(operations), value) if value is not None else None
        if name == "nop":
            continue
        if name.startswith("move") and not name.startswith(("move-result", "move-exception")) and len(regs) == 2:
            if regs[1] not in registers:
                return None
            registers[regs[0]] = registers[regs[1]]
        elif name.startswith("const-string"):
            registers[regs[0]] = {"value": constant(instruction.string_value, "Ljava/lang/String;")}
        elif name.startswith("const") and instruction.literal_value is not None:
            registers[regs[0]] = {"value": constant(instruction.literal_value, "J" if "wide" in name else "I")}
        elif name.startswith(("iget", "sget", "iput", "sput")):
            static = name.startswith(("sget", "sput"))
            base = None if static else registers.get(regs[1])
            if not static and base is None:
                return None
            write = name.startswith(("iput", "sput"))
            value = registers.get(regs[0]) if write else None
            if write and value is None:
                return None
            operations.append({"index": index, "base": base, "value": value, "write": write})
            if not write:
                registers[regs[0]] = {"read": len(operations) - 1}
        elif (name.startswith("invoke-direct")
              and parse_method_reference(instruction.reference) == ("Ljava/lang/Object;", "<init>", "()V")):
            continue
        elif resolve_call is not None and name.startswith(("invoke-static", "invoke-direct")):
            resolved = resolve_call(instruction)
            if resolved is None or any(reg not in registers for reg in regs):
                return None
            target, summary = resolved
            operations.append({"index": index, "target": target, "summary": summary,
                               "arguments": {reg: registers[reg] for reg in regs}})
            if not target.method.descriptor.endswith(")V"):
                pending_result = {"read": len(operations) - 1}
        else:
            return None
    return None


def build_composed_summary(method, backend):
    """Compose exact straight-line calls under fixed structural and exception limits."""
    from src.static.model.values import MethodRef

    remaining = [128]

    def visit(target, stack):
        """Reject unknown effects instead of interpreting an absent transfer as no writes."""
        if target.method in stack or len(stack) >= 4 or "synchronized" in target.access.split():
            return None
        analysis = getattr(backend, "method_analyses", {}).get(target.method)
        code = analysis.get_method().get_code() if analysis else None
        if code is None or code.get_tries_size() != 0:
            return None
        remaining[0] -= len(target.instructions)
        if remaining[0] < 0:
            return None

        def resolve(call):
            """Follow only recorded static/direct callees, with no virtual target guesses."""
            parsed = parse_method_reference(call.reference)
            callee = backend.methods.get(MethodRef(*parsed)) if parsed else None
            if callee is None:
                return None
            summary = visit(callee, (*stack, target.method))
            return (callee, summary) if summary is not None else None

        return build_accessor_summary(target, resolve)

    return visit(method, ())


def summary_value(value, registers, reads):
    """Substitute call-site inputs or an earlier read without re-reading mutated state."""
    if "slot" in value:
        return registers[value["slot"]]
    if "read" in value:
        return reads[value["read"]]
    return value["value"]


def pure_summary_eligible(method):
    """Admit small acyclic primitive helpers whose only effects are return values."""
    if not method.instructions or len(method.instructions) > 64:
        return False
    for instruction in method.instructions:
        name = instruction.name
        if name.startswith(("if-", "goto")) and instruction.branch_target is not None and instruction.branch_target <= instruction.offset:
            return False
        if name.startswith(("return", "if-", "goto", "const", "move")) and not name.startswith(("move-result", "move-exception")):
            continue
        if name == "nop" or "-int" in name and name.split("-")[0] in {"add", "sub", "rsub", "mul", "and", "or", "xor", "shl", "shr", "ushr"}:
            continue
        return False
    return True


def state_summary_eligible(method):
    """Admit small field setters whose calls are supported Intent/Bundle readers."""
    if not method.instructions or len(method.instructions) > 64:
        return False
    if not any(i.name.startswith(("iput", "sput")) for i in method.instructions):
        return False
    readers = {"getAction", "getType", "getStringExtra", "getIntExtra", "getBooleanExtra",
               "getString", "getInt", "getBoolean", "hasExtra", "containsKey"}
    for instruction in method.instructions:
        name = instruction.name
        if name.startswith(("return", "const", "move", "if-", "goto", "iget", "sget", "iput", "sput")):
            if name == "move-exception":
                return False
            continue
        if name == "nop":
            continue
        parsed = parse_method_reference(instruction.reference)
        if name.startswith("invoke-") and parsed and parsed[0] in {"Landroid/content/Intent;", "Landroid/os/Bundle;"} and parsed[1] in readers:
            continue
        return False
    return True


def instantiate(expression, registers):
    """Substitute actual arguments and simplify each cached return-case predicate."""
    op = expression["op"]
    if op == "summary_parameter":
        return registers[expression["register"]]
    if "args" not in expression:
        return expression
    args = [instantiate(a, registers) for a in expression["args"]]
    if op in {"and", "or"}:
        return combine(op, args)
    if op == "not":
        return negate(args[0])
    if op in {"eq", "ne", "lt", "le", "gt", "ge"}:
        return compare(op, *args)
    if op.endswith("32"):
        return integer_operation(op[:-2] + "-int", args)
    return {**expression, "args": args}


class NonReturningCalls:
    """Prove absence of normal returns in bounded, handler-free exact callees."""

    def __init__(self, backend):
        """Cache unconditional bytecode facts independently of argument values."""
        self.backend = backend
        self.cache = {}

    def check(self, instruction):
        """Accept only exact static/direct calls whose bodies cannot return normally."""
        return self._call(instruction, (), [256])

    def handler_free(self, method):
        """Require DEX exception-table evidence, including handlers without move-exception."""
        analysis = getattr(self.backend, "method_analyses", {}).get(method.method)
        if analysis is None:
            return False
        code = analysis.get_method().get_code()
        return code is not None and code.get_tries_size() == 0

    def nullcheck(self, method):
        """Verify the wrapper's exception table before proving its normal-return guard."""
        if not self.handler_free(method):
            return None
        return nullcheck_parameter(method, self.backend.cfg_for(method), self.check)

    def _call(self, instruction, stack, budget):
        """Resolve a bounded exact call without guessing virtual/native dispatch."""
        if not instruction.name.startswith(("invoke-static", "invoke-direct")):
            return False
        parsed = parse_method_reference(instruction.reference)
        if parsed is None:
            return False
        reference = MethodRef(*parsed)
        if reference in stack or len(stack) >= 4:
            return False
        if reference in self.cache:
            return self.cache[reference]
        method = self.backend.methods.get(reference)
        if (method is None or not method.instructions or len(method.instructions) > 64
                or not self.handler_free(method)
                or any(i.name == "move-exception" for i in method.instructions)):
            return False
        cfg = self.backend.cfg_for(method)
        pending, seen, terminal = [0], set(), False
        while pending:
            index = pending.pop()
            if index in seen:
                continue
            budget[0] -= 1
            if budget[0] < 0:
                return False
            seen.add(index)
            current = method.instructions[index]
            if current.name.startswith("return"):
                return False
            if current.name == "throw" or (
                current.name.startswith("invoke-") and self._call(current, (*stack, reference), budget)
            ):
                terminal = True
                continue
            successors = cfg.successors[index]
            if not successors:
                return False
            pending.extend(successors)
        # This only claims no normal return, not that a throwing call terminates.
        # Retain a real terminal witness instead of treating a pure loop as a throw.
        if terminal:
            if len(self.cache) >= 512:
                self.cache.clear()
            self.cache[reference] = True
        return terminal


def nullcheck_parameter(method, cfg, nonreturning_call=None):
    """Recognize a static null check with a pure success arm and a nonreturning failure arm."""
    code = method.instructions
    if ("static" not in method.access.split() or not method.method.descriptor.endswith(")V")
            or not 3 <= len(code) <= 64 or any(i.name == "move-exception" for i in code)):
        return None
    branch = code[0]
    if branch.name not in {"if-eqz", "if-nez"} or len(branch.registers) != 1:
        return None
    register = branch.registers[0]
    parameter = method.parameters.get(register)
    if parameter is None or not parameter[1].startswith(("L", "[")):
        return None
    jump = method.offset_to_index.get(branch.branch_target)
    if jump is None or set(cfg.successors[0]) != {1, jump}:
        return None
    success, failure = (jump, 1) if branch.name == "if-nez" else (1, jump)
    seen, current = set(), success
    while current not in seen:
        seen.add(current)
        instruction = code[current]
        if instruction.name == "return-void":
            break
        if instruction.name != "nop" and not instruction.name.startswith("goto"):
            return None
        if len(cfg.successors[current]) != 1:
            return None
        current = cfg.successors[current][0]
    else:
        return None
    # No exceptional handler or normal return is allowed in the failure region.
    pending, checked = [failure], set()
    while pending:
        index = pending.pop()
        if index in checked:
            continue
        checked.add(index)
        if index in seen or code[index].name.startswith("return"):
            return None
        if (nonreturning_call is not None and code[index].name.startswith("invoke-")
                and nonreturning_call(code[index])):
            continue
        successors = cfg.successors[index]
        if not successors and code[index].name != "throw":
            return None
        pending.extend(successors)
    return register
