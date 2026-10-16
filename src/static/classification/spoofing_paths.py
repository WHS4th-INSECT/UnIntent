"""Bounded normal-CFG execution conditions for narrowly catalogued spoofing effects.

Routes start at exact manifest callbacks and contain observed invoke sites. This
collector does not invent Intent data flow, prove caller authorization, or model
framework scheduling. Unsupported values and incomplete searches remain UNKNOWN.
"""

from __future__ import annotations

import hashlib
import re
import time
from dataclasses import dataclass, field, replace
from itertools import pairwise
from typing import Any

from src.static.model.constants import (
    ENTRY_REACHABILITY_DIRECT_MANIFEST,
    ENTRY_REACHABILITY_DYNAMIC_RECEIVER,
    ENTRY_REACHABILITY_MANIFEST_RUNTIME,
)

from src.static.classification.branch_predicates import (
    Expr,
    combine,
    compact_conditions,
    compare,
    constant,
    impossible,
    inputs,
    integer_operation,
    negate,
    render,
    unknown,
)
from src.static.classification.condition_events import EventReplay
from src.static.classification.condition_events import SupportingEvents
from src.static.classification.condition_calls import (
    NonReturningCalls,
    build_accessor_summary,
    build_composed_summary,
    check_recovered_calls,
    instantiate,
    pure_summary_eligible,
    read_recorded_execution,
    state_summary_eligible,
    summary_value,
)
from src.static.classification.condition_runtime import (
    ARRAY_LENGTH,
    BUFFER_TYPE,
    ConditionAliases,
    ConditionMemory,
    framework_transfer,
    instance_of,
    library_summary,
    load_property,
    model_container,
    nonnull_reference,
    object_id,
    required_presence,
    resolve_receiver_method,
    store_property,
)
from src.static.classification.condition_solver import ConditionSolver, cacheable_solver_result
from src.static.search.manifest import generic_attacker_can_invoke
from src.static.classification.spoofing import SPOOFING_RULES, match_spoofing_rules
from src.static.search.dex_ir import (
    destination_register,
    invocation_formals,
    parse_method_reference,
)
from src.static.model.values import (
    EntryPoint,
    EvidenceSource,
    FlowEvidence,
    FlowNode,
    MethodRef,
    Origin,
    TraceStep,
    UseRole,
)

CALLBACKS = {
    "receiver": {("onReceive", "(Landroid/content/Context;Landroid/content/Intent;)V")},
    "service": {
        ("onStartCommand", "(Landroid/content/Intent;II)I"),
        ("onHandleIntent", "(Landroid/content/Intent;)V"),
    },
    "activity": {
        ("onCreate", "(Landroid/os/Bundle;)V"),
        ("onNewIntent", "(Landroid/content/Intent;)V"),
    },
}


@dataclass
class PathState:
    registers: dict[int, Expr] = field(default_factory=dict)
    predicates: list[dict[str, Any]] = field(default_factory=list)
    calls: list[TraceStep] = field(default_factory=list)
    last_result: Expr = field(default_factory=lambda: unknown("no invoke result"))
    solver_result: dict[str, Any] | None = None
    memory: ConditionMemory = field(default_factory=ConditionMemory)
    summaries: list[dict[str, Any]] = field(default_factory=list)
    opaque_effect: bool = False

    def fork(self) -> PathState:
        """Copy path-local registers and predicates before taking a CFG alternative."""
        return PathState(
            dict(self.registers), list(self.predicates), list(self.calls), self.last_result,
            memory=self.memory.fork(), summaries=list(self.summaries), opaque_effect=self.opaque_effect,
        )


class SpoofingPathAnalyzer:
    def __init__(self, backend, *, max_depth=8, max_paths=32, max_steps=4000, deadline=None):
        """Reuse the bytecode backend with independent, bounded condition-search budgets."""
        self.backend = backend
        self.max_depth = max(0, min(max_depth, 8))
        self.max_paths = max(1, min(max_paths, 32))
        self.max_steps = max_steps
        self.deadline = deadline
        self._reachable_cache = {}
        self._source_condition_cache = {}
        self._accessor_summaries = {}
        self._dependency_writes = {}
        self._pure_summaries = {}
        self._nullcheck_summaries = {}
        self._nonreturning_calls = NonReturningCalls(backend)
        self._prefix_cache = {}
        self.aliases = ConditionAliases(backend)
        self.supporting_events = SupportingEvents()
        self.event_replay = EventReplay(backend)
        self._entry_methods = {}
        for component in backend.components:
            if not generic_attacker_can_invoke(component):
                continue
            for name, descriptor in CALLBACKS.get(component.component_type, ()):
                reference = MethodRef(component.descriptor, name, descriptor)
                if reference in backend.methods:
                    self._entry_methods.setdefault(reference, []).append(component)
        self.statistics = {
            "sinks": 0,
            "new_entry_sink_candidates": 0,
            "steps": 0,
            "truncated_sinks": 0,
            "infeasible_paths": 0,
            "existing_sources_assessed": 0,
            "existing_sources_infeasible": 0,
            "existing_sources_unknown": 0,
            "accessor_summaries_built": 0,
            "accessor_summary_hits": 0,
            "accessor_summary_applications": 0,
            "composed_summaries_built": 0,
            "composed_summary_applications": 0,
            "composed_nested_calls": 0,
            "field_reads_resolved": 0,
            "field_reads_unresolved": 0,
            "nested_bundle_reads": 0,
        }
        self.remaining_steps = 50000
        self.remaining_seconds = 5.0
        self.solver = ConditionSolver()
        self.statistics["smt"] = self.solver.statistics
        self.statistics["smt_infeasible_paths"] = 0
        self.statistics["library_summary_applications"] = 0
        self.statistics["aliases"] = self.aliases.statistics
        self.statistics["conditional_summaries_built"] = 0
        self.statistics["conditional_summary_hits"] = 0
        self.statistics["conditional_summary_incomplete_uncached"] = 0
        self.statistics["prefix_incomplete_uncached"] = 0
        self.statistics["source_condition_cache_hits"] = 0
        self.statistics["source_condition_incomplete_uncached"] = 0
        self.statistics["entry_prefixes_recovered"] = 0
        self.statistics["nullcheck_summary_applications"] = 0
        self.statistics["supporting_events"] = self.supporting_events.statistics
        self.statistics["event_replay"] = self.event_replay.statistics
        self.statistics["framework_transfer_applications"] = 0
        self.statistics["execution_contexts_checked"] = 0
        self.statistics["execution_producer_records"] = 0
        self.statistics["execution_calls_consumed"] = 0
        self.statistics["execution_contexts_incomplete"] = 0



    def _check_conditions(self, states, *, complete_prefix=True):
        """Check completed path conjunctions without extending CFG exploration budgets."""
        for state in states:
            formula = combine("and", [item["predicate"] for item in state.predicates])
            if not complete_prefix:
                formula = combine("and", [formula, unknown("entry prefix not replayed", "Z")])
            state.solver_result = self.solver.check(formula, deadline=self.sink_deadline)
            if state.solver_result["status"] == "UNSAT":
                self.statistics["smt_infeasible_paths"] += 1

    def _spend(self) -> bool:
        """Stop condition exploration on instruction, application, or time limits."""
        if (
            self.steps >= self.max_steps
            or self.remaining_steps <= 0
            or time.monotonic() >= self.sink_deadline
        ):
            self.reasons.add("condition_search_budget")
            return False
        self.steps += 1
        self.remaining_steps -= 1
        return True

    def _ancestors(self, method, target):
        """Cache instructions that can structurally reach one target via normal CFG edges."""
        key = (method.method, target)
        if key not in self._reachable_cache:
            cfg = self.backend.cfg_for(method)
            todo, seen = [target], set()
            complete = True
            while todo:
                if not self._spend():
                    self.reasons.add("cfg_reachability_limit")
                    complete = False
                    break
                index = todo.pop()
                if index not in seen:
                    seen.add(index)
                    todo.extend(cfg.predecessors[index])
            if len(self._reachable_cache) >= 1024:
                self._reachable_cache.clear()
            # A partial reverse walk must not become a later proof of unreachability.
            if complete:
                self._reachable_cache[key] = seen
            return seen
        return self._reachable_cache[key]

    @staticmethod
    def _field_type(instruction):
        """Read a field's declared DEX descriptor instead of inferring int from its opcode."""
        match = re.search(r"\s+(\[*[ZBSCIJFD]|\[*L[^;]+;)\s*$", instruction.reference or "")
        return match.group(1) if match else "?"

    def _routes(self, reference, target, suffix=(), visited=(), *, entry_methods=None):
        """Walk observed caller sites backwards to exact externally invocable callbacks."""
        if reference in visited:
            self.reasons.add("recursive_call_route")
            return []
        method = self.backend.methods[reference]
        if 0 not in self._ancestors(method, target):
            return []
        chain = ((reference, target), *suffix)
        roots = self._entry_methods if entry_methods is None else entry_methods
        result = [(entry, chain) for entry in roots.get(reference, ())]
        if len(visited) >= self.max_depth:
            self.reasons.add("call_depth_limit")
            return result
        get_callers = getattr(self.backend, "_direct_callers", None)
        callers = get_callers(reference) if get_callers else self.backend.callers.get(reference, ())
        if len(callers) > self.max_paths:
            self.reasons.add("caller_fanout_limit")
        for call in callers[: self.max_paths]:
            if not self._spend():
                break
            caller = self.backend.methods.get(call.caller)
            if caller is None:
                continue
            instruction = caller.instructions[call.instruction_index]
            parsed = parse_method_reference(instruction.reference)
            if parsed is None or MethodRef(*parsed) != reference:
                continue
            result.extend(
                self._routes(call.caller, call.instruction_index, chain, (*visited, reference), entry_methods=roots)
            )
            if len(result) >= self.max_paths:
                self.reasons.add("route_count_limit")
                break
        return result[: self.max_paths]


    def _bind(self, target, call, parent):
        """Bind actual registers to callee parameters without mixing call contexts."""
        bound = parent.fork()
        bound.registers = {}
        actuals = {
            formal: parent.registers.get(register, unknown(f"argument v{register}"))
            for formal, _, register in invocation_formals(call)
        }
        for register, (formal, kind) in target.parameters.items():
            value = actuals.get(formal, unknown(f"parameter {formal}", kind))
            if value.get("op") == "const":
                if kind == "Z" and value.get("value") in (0, 1):
                    value = constant(bool(value["value"]), "Z")
                elif kind.startswith(("L", "[")) and value.get("value") == 0:
                    value = constant(None, kind)
            bound.registers[register] = value
        if target.receiver_register is not None and call.registers:
            bound.registers[target.receiver_register] = parent.registers.get(
                call.registers[0], unknown("receiver")
            )
        return bound

    def _field_read(self, method, instruction, state, base=None):
        """Resolve an executed write or retain bounded supporting-write dependencies."""
        reference = instruction.reference
        if instruction.name == "sget-object" and reference == f"{BUFFER_TYPE}->NORMAL {BUFFER_TYPE}":
            return {"op": "framework_enum", "type": BUFFER_TYPE, "value": "NORMAL"}
        if instruction.name == "sget" and reference == "Landroid/os/Build$VERSION;->SDK_INT I":
            apk = getattr(getattr(self.backend, "session", None), "apk", None)
            try:
                minimum = max(1, int(apk.get_min_sdk_version() or 1)) if apk else 1
            except (TypeError, ValueError):
                minimum = 1
            return {"op": "environment", "field": "sdk_int", "type": "I", "control": "platform",
                    "min_value": minimum, "runtime_value_observed": False}
        if instruction.name.startswith("sget"):
            state.memory.touch_class((reference or "").split("->")[0])
        identity = "static" if instruction.name.startswith("sget") else object_id(base)
        record = state.memory.fields.get((identity, reference)) if identity else None
        site = {"method": method.display(), "offset": instruction.offset}
        dependency_id = hashlib.sha1(repr((reference, identity, site)).encode()).hexdigest()[:16]
        evidence = {"id": dependency_id, "field": reference, "read": site, "object_identity": identity}
        if record is not None:
            self.statistics["field_reads_resolved"] += 1
            evidence.update(status="resolved_same_path", write=record["write"],
                            value_text=render(record["value"]), same_object_proven=True,
                            execution_order_proven=True)
            state.memory.record(evidence)
            return record["value"]
        self.statistics["field_reads_unresolved"] += 1
        if reference not in self._dependency_writes:
            # Read the existing occurrence index; do not expand discovery or dispatch.
            occurrences = getattr(self.backend, "_field_writer_occurrences", {}).get(reference, ())
            writers = []
            for ref, index, _register in occurrences[:8]:
                writer = self.backend.methods.get(ref)
                if writer is not None:
                    writers.append({"method": ref.display(), "offset": writer.instructions[index].offset,
                                    "entry_components": [e.name for e in self._entry_methods.get(ref, ())]})
            if len(self._dependency_writes) < 1024:
                self._dependency_writes[reference] = (writers, len(occurrences) > 8)
        writers, truncated = self._dependency_writes.get(reference, ([], True))
        evidence.update(status="unresolved", candidate_writes=writers,
                        writers_truncated=truncated, same_object_proven=False,
                        execution_order_proven=False,
                        reason="no_replayed_write_for_this_object")
        state.memory.record(evidence)
        context = hashlib.sha1(repr([(s.method, s.offset) for s in state.calls]).encode()).hexdigest()[:12]
        return {**unknown(f"{reference} at {method.display()}@{instruction.offset} via {context} epoch {state.memory.epoch}",
                          self._field_type(instruction), "app_state"), "state_dependency": dependency_id}

    def _field_write(self, method, instruction, state, base, value):
        """Apply an ordered DEX field assignment to only this path's known object."""
        if instruction.name.startswith("sput"):
            state.memory.touch_class((instruction.reference or "").split("->")[0])
        state.memory.write(instruction.reference, base, value, self._field_type(instruction),
                           {"method": method.display(), "offset": instruction.offset},
                           static=instruction.name.startswith("sput"), backend=self.backend)

    def _summary_for(self, target):
        """Cache only the method transfer structure, never a mutable field's value."""
        reference = target.method
        if reference in self._accessor_summaries:
            summary = self._accessor_summaries[reference]
            if summary is not None:
                self.statistics["accessor_summary_hits"] += 1
        else:
            summary = build_accessor_summary(target)
            if summary is None:
                summary = build_composed_summary(target, self.backend)
                self.statistics["composed_summaries_built"] += summary is not None
            if len(self._accessor_summaries) < 1024:
                self._accessor_summaries[reference] = summary
            self.statistics["accessor_summaries_built"] += summary is not None
        return summary

    def _apply_transfer(self, target, registers, state, summary):
        """Apply ordered nested transfers using fresh call bindings and current heap reads."""
        reads, nested = {}, []
        for number, operation in enumerate(summary.operations):
            instruction = target.instructions[operation["index"]]
            if "target" in operation:
                callee = operation["target"]
                caller = state.fork()
                caller.registers = {reg: summary_value(value, registers, reads)
                                    for reg, value in operation["arguments"].items()}
                if instruction.name.startswith("invoke-direct") and not nonnull_reference(
                    caller.registers.get(instruction.registers[0], {})
                ):
                    return None
                if instruction.name.startswith("invoke-static"):
                    state.memory.touch_class(callee.method.class_name)
                bound = self._bind(callee, instruction, caller)
                transferred = self._apply_transfer(callee, bound.registers, state, operation["summary"])
                if transferred is None:
                    return None
                reads[number], children = transferred
                nested.append({"caller_method": target.display(), "call_offset": instruction.offset,
                               "method": callee.display()})
                nested.extend(children)
            else:
                base = summary_value(operation["base"], registers, reads) if operation["base"] else None
                if operation["write"]:
                    self._field_write(target, instruction, state, base, summary_value(operation["value"], registers, reads))
                else:
                    reads[number] = self._field_read(target, instruction, state, base)
        return summary_value(summary.returned, registers, reads), nested

    def _accessor(self, caller, target, call, state, summary):
        """Instantiate reusable parameter/field/return transfers at the actual call."""
        if summary is None:
            return None
        bound = self._bind(target, call, state)
        if any("target" in operation for operation in summary.operations):
            # Discard partial effects if a nested receiver cannot be bound exactly.
            updated = state.fork()
            transferred = self._apply_transfer(target, bound.registers, updated, summary)
            if transferred is None:
                return None
            value, nested = transferred
            self.statistics["accessor_summary_applications"] += 1
            self.statistics["composed_summary_applications"] += 1
            self.statistics["composed_nested_calls"] += len(nested)
            if len(updated.summaries) < 32:
                updated.summaries.append({"method": target.display(), "kind": "composed_field_return",
                    "caller_method": caller.display(), "call_offset": call.offset,
                    "nested_calls": nested, "complete_normal_transfer": True})
            return [(value, updated)]
        reads = {}
        for number, operation in enumerate(summary.operations):
            instruction = target.instructions[operation["index"]]
            base = summary_value(operation["base"], bound.registers, reads) if operation["base"] else None
            if operation["write"]:
                value = summary_value(operation["value"], bound.registers, reads)
                self._field_write(target, instruction, state, base, value)
            else:
                reads[number] = self._field_read(target, instruction, state, base)
        self.statistics["accessor_summary_applications"] += 1
        if len(state.summaries) < 32:
            state.summaries.append({"method": target.display(), "kind": "parameter_field_return",
                                    "caller_method": caller.display(), "call_offset": call.offset,
                                    "complete_normal_transfer": True})
        return [(summary_value(summary.returned, bound.registers, reads), state)]

    def _pure_helper(self, caller, target, call, state, depth):
        """Reuse complete return alternatives of a bounded, effect-free branch helper."""
        if target.method not in self._pure_summaries:
            cases = None
            complete = True
            if pure_summary_eligible(target):
                symbolic = PathState(registers={r: {"op": "summary_parameter", "register": r, "type": kind}
                                                for r, (_formal, kind) in target.parameters.items()})
                if target.receiver_register is not None:
                    symbolic.registers[target.receiver_register] = unknown("summary receiver", target.method.class_name)
                reasons, contradictions = self.reasons, getattr(self, "_contradictions", [])
                self.reasons, self._contradictions = set(), []
                try:
                    returned = self._walk(target, None, symbolic, depth + 1, (target.method,))
                    complete = not self.reasons
                    if complete and 0 < len(returned) <= 8:
                        cases = [(s.last_result, s.predicates) for s in returned]
                        self.statistics["conditional_summaries_built"] += 1
                finally:
                    self.reasons, self._contradictions = reasons, contradictions
            if complete and len(self._pure_summaries) < 512:
                self._pure_summaries[target.method] = cases
            elif not complete:
                self.statistics["conditional_summary_incomplete_uncached"] += 1
        else:
            cases = self._pure_summaries[target.method]
            self.statistics["conditional_summary_hits"] += cases is not None
        if cases is None:
            return None
        bound = self._bind(target, call, state)
        results = []
        for returned, branches in cases:
            updated = state.fork()
            updated.predicates.extend({**b, "predicate": instantiate(b["predicate"], bound.registers)} for b in branches)
            if impossible([b["predicate"] for b in updated.predicates]):
                if hasattr(self, "_contradictions"):
                    self._contradictions.append(updated.predicates)
                continue
            updated.calls.append(TraceStep(caller.display(), call.offset, call.text(), "predicate helper call", "CALL", True))
            if len(updated.summaries) < 32:
                updated.summaries.append({"method": target.display(), "caller_method": caller.display(),
                                          "call_offset": call.offset, "kind": "conditional_return",
                                          "return_cases": len(cases), "complete_normal_transfer": True})
            results.append((instantiate(returned, bound.registers), updated))
        return results

    def _invoke(self, method, index, state, depth, stack):
        """Model Intent/string accessors and retain return-case predicates for local helpers."""
        call = method.instructions[index]
        parsed = parse_method_reference(call.reference)
        label = f"{method.display()}@{call.offset}"
        if parsed is None:
            state.opaque_effect = True
            state.memory.havoc(state.registers.values(), all_fields=True)
            return [(unknown(label), state)]
        owner, name, descriptor = parsed
        if call.name.startswith("invoke-static"):
            state.memory.touch_class(owner)
        result_type = descriptor.split(")")[-1]
        args = [state.registers.get(r, unknown(f"{label}:v{r}")) for r in call.registers]
        receiver = args[0] if args and not call.name.startswith("invoke-static") else None
        if receiver and receiver.get("op") == "const" and receiver.get("value") in (None, 0) and owner in {
            "Landroid/content/Intent;", "Landroid/os/Bundle;", "Ljava/lang/String;"
        }:
            return []
        if parsed == ("Ljava/lang/Object;", "<init>", "()V") and call.name.startswith("invoke-direct"):
            return [(constant(None, "V"), state)]
        if (call.name.startswith("invoke-super") and owner == "Landroid/telecom/InCallService;"
                and name in {"onCallAdded", "onCallRemoved"} and descriptor == "(Landroid/telecom/Call;)V"):
            return [(constant(None, "V"), state)]
        if (
            name == "getIntent"
            and descriptor == "()Landroid/content/Intent;"
            and receiver
            and receiver.get("op") == "entry_this"
            and owner in {"Landroid/app/Activity;", receiver.get("owner")}
        ):
            return [({"op": "intent", "id": self.entry_name, "type": result_type}, state)]
        transferred = framework_transfer(self.backend, method, call, state, args)
        if transferred is not None:
            value, kind = transferred
            self.statistics["framework_transfer_applications"] += 1
            if len(state.summaries) < 32:
                state.summaries.append({"kind": kind, "method": method.display(), "call_offset": call.offset,
                                        "same_object_proven": True, "complete_normal_transfer": True})
            return [(value, state)]
        if (name == "toString" and descriptor == "()Ljava/lang/String;" and receiver
                and receiver.get("type") == "Ljava/lang/String;"
                and owner in {"Ljava/lang/CharSequence;", "Ljava/lang/Object;", "Ljava/lang/String;"}):
            if receiver.get("op") == "const" and receiver.get("value") is None:
                return []
            if not nonnull_reference(receiver):
                state.predicates.append({"method": method.display(), "offset": call.offset,
                    "predicate": compare("ne", receiver, constant(None, "Ljava/lang/String;")),
                    "outcome": "normal_invoke_return"})
            return [(receiver, state)]
        modeled = model_container(owner, name, descriptor, args, state, label, self.backend)
        if modeled is not None:
            self.statistics["library_summary_applications"] += 1
            self.statistics["nested_bundle_reads"] += name in {"getBundle", "getBundleExtra"}
            for predicate in required_presence(receiver or {}):
                state.predicates.append({"method": method.display(), "offset": call.offset,
                                         "predicate": predicate, "outcome": "normal_invoke_return"})
            return [(modeled, state)]
        library = library_summary(owner, name, descriptor, args)
        if library is not None:
            value, predicates = library
            self.statistics["library_summary_applications"] += 1
            for predicate in predicates:
                state.predicates.append({"method": method.display(), "offset": call.offset,
                                         "predicate": predicate, "outcome": "normal_invoke_return"})
            return [(value, state)]
        if (
            owner in {"Landroid/content/Intent;", "Landroid/os/Bundle;"}
            and receiver
            and receiver.get("op") in {"intent", "bundle"}
        ):
            if receiver["id"] in state.memory.invalidated_intents:
                return [(unknown(f"Intent or Bundle may have changed at {label}", result_type), state)]
            if name == "getExtras" and receiver["op"] == "intent":
                return [({**receiver, "op": "bundle", "type": result_type}, state)]
            if ((owner == "Landroid/content/Intent;" and name == "getBundleExtra")
                    or (owner == "Landroid/os/Bundle;" and name == "getBundle")) and descriptor == "(Ljava/lang/String;)Landroid/os/Bundle;":
                key = args[1].get("value") if len(args) > 1 and args[1].get("op") == "const" else None
                if isinstance(key, str):
                    self.statistics["nested_bundle_reads"] += 1
                    return [({**receiver, "op": "bundle", "type": result_type,
                              "key_path": [*receiver.get("key_path", []), key]}, state)]
            if receiver.get("key_path"):
                # A nested Bundle must exist and have the right runtime type. Keep
                # that reference constraint; a primitive extra alone cannot prove it.
                state.predicates.append({"method": method.display(), "offset": call.offset,
                    "predicate": unknown("nested Bundle exists: " + repr(receiver["key_path"]), "Z", "external_intent"),
                    "outcome": "normal_invoke_return"})
            fields = {
                "getAction": "action",
                "getData": "data",
                "getDataString": "data",
                "getType": "type",
            }
            extra = name in {
                "getIntExtra",
                "getBooleanExtra",
                "getStringExtra",
                "getLongExtra",
                "getInt",
                "getBoolean",
                "getString",
                "getLong",
            }
            if name in fields or extra:
                key = (
                    args[1].get("value")
                    if extra and len(args) > 1 and args[1]["op"] == "const"
                    else None
                )
                if extra and not isinstance(key, str):
                    return [(unknown(f"dynamic Intent key at {label}", result_type), state)]
                value = {
                    "op": "input",
                    "field": "extra" if extra else fields[name],
                    "key": key,
                    "type": result_type,
                    "control": "external_intent",
                    "intent_id": receiver["id"],
                }
                if extra and len(args) > 2:
                    value["default"] = args[2]
                if receiver.get("key_path"):
                    value["key_path"] = receiver["key_path"]
                return [(value, state)]
        if (
            (owner == "Ljava/lang/String;" or owner == "Ljava/lang/Object;" and receiver and receiver.get("type") == "Ljava/lang/String;")
            and name == "equals"
            and descriptor == "(Ljava/lang/Object;)Z"
            and len(args) == 2
        ):
            if args[0]["op"] == "const" and args[0].get("value") is None:
                return []
            if args[0]["op"] != "const":
                state.predicates.append(
                    {
                        "method": method.display(),
                        "offset": call.offset,
                        "predicate": compare("ne", args[0], constant(None, "Ljava/lang/String;")),
                        "outcome": "normal_invoke_return",
                    }
                )
            return [(compare("eq", args[0], args[1]), state)]
        target = self.backend.methods.get(MethodRef(*parsed))
        concrete_target = (resolve_receiver_method(self.backend, receiver, name, descriptor)
                           if receiver and call.name.startswith(("invoke-interface", "invoke-virtual")) else None)
        if concrete_target is not None:
            target = concrete_target
        if target is not None:
            if call.name.startswith("invoke-static") and result_type == "V" and len(target.instructions) <= 64:
                if target.method not in self._nullcheck_summaries:
                    if len(self._nullcheck_summaries) >= 512:
                        self._nullcheck_summaries.clear()
                    self._nullcheck_summaries[target.method] = self._nonreturning_calls.nullcheck(target)
                checked_register = self._nullcheck_summaries[target.method]
                if checked_register is not None:
                    value = self._bind(target, call, state).registers[checked_register]
                    predicate = (constant(True, "Z") if nonnull_reference(value)
                                 else compare("ne", value, constant(None, value.get("type", "Ljava/lang/Object;"))))
                    if value == constant(0):
                        predicate = constant(False, "Z")
                    self.statistics["nullcheck_summary_applications"] += 1
                    if predicate == constant(False, "Z"):
                        if hasattr(self, "_contradictions"):
                            self._contradictions.append([{"predicate": predicate, "method": target.display(), "offset": 0}])
                        return []
                    state.predicates.append({"method": method.display(), "offset": call.offset,
                                             "predicate": predicate, "outcome": "nonnull_helper_normal_return"})
                    if len(state.summaries) < 32:
                        state.summaries.append({"kind": "nonnull_normal_return", "method": target.display(),
                                                "caller_method": method.display(), "call_offset": call.offset,
                                                "complete_normal_transfer": True})
                    return [(constant(None, "V"), state)]
            summary = self._summary_for(target)
            prior_helper = result_type in {"Z", "I", "J", "Ljava/lang/String;"}
            value_factory = (
                not owner.startswith(("Landroid/", "Landroidx/", "Ljava/", "Lkotlin/", "Lkotlinx/"))
                and (name == "<init>" or result_type.startswith("L"))
                and len(target.instructions) <= 192
                and any(i.name == "new-instance" or i.name.startswith("iput") for i in target.instructions)
            )
            state_helper = (
                not owner.startswith(("Landroid/", "Landroidx/", "Ljava/", "Lkotlin/", "Lkotlinx/"))
                and result_type == "V" and state_summary_eligible(target)
            )
            if not prior_helper and summary is None and not value_factory and not state_helper:
                state.opaque_effect = True
                state.memory.havoc(args)
                return [(unknown(label, result_type), state)]
            if depth >= self.max_depth or target.method in stack:
                self.reasons.add("helper_depth_or_recursion")
                state.opaque_effect = True
                state.memory.havoc(args)
                return [(unknown(label, result_type), state)]
            if concrete_target is None and not call.name.startswith(("invoke-static", "invoke-direct")) and not {
                "final",
                "private",
            }.intersection(target.access.split()) and not (
                receiver and receiver.get("op") == "object" and receiver.get("type") == owner
                and call.name.startswith("invoke-virtual")
            ):
                self.reasons.add("virtual_helper_dispatch_unresolved")
                state.opaque_effect = True
                state.memory.havoc(args)
                return [(unknown(label, result_type), state)]
            summarized = self._accessor(method, target, call, state, summary)
            if summarized is not None:
                return summarized
            pure = self._pure_helper(method, target, call, state, depth)
            if pure is not None:
                return pure
            # Only small app value factories/constructors add body exploration.
            # Framework builder internals do not consume the condition budget.
            bound = self._bind(target, call, state)
            bound.calls.append(
                TraceStep(
                    method.display(),
                    call.offset,
                    call.text(),
                    "predicate helper call",
                    "CALL",
                    True,
                )
            )
            returned = self._walk(target, None, bound, depth + 1, (*stack, target.method))
            result = []
            for value in returned:
                caller_state = value.fork()
                caller_state.registers = dict(state.registers)
                result.append((value.last_result, caller_state))
            return result
        state.memory.havoc(args)
        state.opaque_effect = True
        if len(state.summaries) < 32:
            state.summaries.append({"kind": "opaque_call", "method": label})
        return [(unknown(label, result_type), state)]

    def _branch(self, method, index, successor, state):
        """Translate a chosen if/switch edge into a typed predicate and exact DEX site."""
        if len(state.predicates) >= 64:
            self.reasons.add("predicate_count_limit")
            state.predicates = [*state.predicates[:63], {"method": method.display(), "offset": None,
                                "predicate": unknown("additional path predicates", "Z")}]
            return True
        instruction = method.instructions[index]
        values = [
            state.registers.get(r, unknown(f"{method.display()}@{instruction.offset}:v{r}"))
            for r in instruction.registers
        ]
        offset = method.instructions[successor].offset
        if instruction.name.startswith("if-"):
            op = instruction.name[3:].removesuffix("z")
            if op not in {"eq", "ne", "lt", "le", "gt", "ge"} or not values:
                predicate = unknown("unsupported if", "Z")
            else:
                if op in {"eq", "ne"} and object_id(values[0]) and (
                    len(values) == 1 or (values[1].get("op") == "const" and values[1].get("value") in (0, None))
                ):
                    predicate = constant(op == "ne", "Z")
                elif len(values) == 2 and op in {"eq", "ne"} and all(object_id(value) for value in values):
                    predicate = constant((object_id(values[0]) == object_id(values[1])) == (op == "eq"), "Z")
                elif len(values) == 2 and op in {"eq", "ne"} and all(value.get("type", "?").startswith(("L", "[")) for value in values):
                    # DEX if-eq on objects compares references, unlike String.equals.
                    predicate = {"op": "ref_" + op, "args": values, "type": "Z"}
                else:
                    predicate = compare(op, values[0], values[1] if len(values) > 1 else constant(0))
                if offset != instruction.branch_target:
                    if successor == index + 1:
                        predicate = negate(predicate)
                    else:
                        predicate = unknown("unresolved branch target", "Z")
            direction = "jump" if offset == instruction.branch_target else "fallthrough"
        else:
            cases = instruction.switch_cases
            matching = [constant(key) for key, target in cases if target == offset]
            options = [compare("eq", values[0], key) for key in matching] if values else []
            if successor == index + 1 and values:
                options.append(
                    combine("and", [compare("ne", values[0], constant(key)) for key, _ in cases])
                )
            predicate = (
                combine("or", options)
                if cases and options
                else unknown("unresolved switch payload", "Z")
            )
            direction = "default_or_case" if successor == index + 1 else "case"
        state.predicates.append(
            {
                "method": method.display(),
                "offset": instruction.offset,
                "opcode": instruction.name,
                "successor_offset": offset,
                "outcome": direction,
                "predicate": predicate,
            }
        )
        rejected = impossible([item["predicate"] for item in state.predicates])
        if rejected and hasattr(self, "_contradictions"):
            self._contradictions.append(list(state.predicates))
        return not rejected

    def _walk(self, method, target, initial, depth=0, stack=()):
        """Explore bounded normal-CFG paths to a call/sink or the helper's return sites."""
        cfg = self.backend.cfg_for(method)
        entry_bindings = dict(initial.registers)
        relevant = self._ancestors(method, target) if target is not None else None
        if any(i.name == "move-exception" and (relevant is None or n in relevant)
               for n, i in enumerate(method.instructions)):
            self.reasons.add("exception_path_unmodeled")
        todo, result = [(0, initial, frozenset())], []
        incomplete = False
        while todo and len(result) < self.max_paths:
            index, state, visited = todo.pop()
            if not self._spend():
                incomplete = True
                break
            if index in visited:
                self.reasons.add("loop_not_unrolled")
                incomplete = True
                continue
            if relevant is not None and index not in relevant:
                continue
            if index == target:
                result.append(state)
                continue
            instruction = method.instructions[index]
            name, registers = instruction.name, instruction.registers
            label = f"{method.display()}@{instruction.offset}"
            if name.startswith("return"):
                if target is None:
                    state.last_result = (
                        state.registers.get(registers[0], unknown(label))
                        if registers
                        else unknown("void return", "V")
                    )
                    result.append(state)
                continue
            if name == "throw":
                continue
            if name.startswith(("aget", "aput")) and len(registers) >= 2:
                array = state.registers.get(registers[1])
                if load_property(state, array, ARRAY_LENGTH) == constant(0):
                    # Every access to a proven empty array throws; never continue
                    # along the normal CFG as though the access had succeeded.
                    self.reasons.add("array_access_exception_path_unmodeled")
                    continue
            states = [state]
            if name.startswith("invoke-"):
                states = []
                for value, updated in self._invoke(method, index, state, depth, stack):
                    updated.last_result = value
                    states.append(updated)
            elif name.startswith("move-result") and registers:
                state.registers[registers[0]] = state.last_result
            elif name.startswith("move") and len(registers) > 1:
                state.registers[registers[0]] = state.registers.get(registers[1], unknown(label))
            elif name.startswith("const-string") and registers:
                state.registers[registers[0]] = constant(
                    instruction.string_value, "Ljava/lang/String;"
                )
            elif name.startswith("const") and registers:
                state.registers[registers[0]] = (
                    constant(instruction.literal_value, "J" if "wide" in name else "I")
                    if instruction.literal_value is not None
                    else unknown(label)
                )
            elif name == "new-instance" and registers:
                state.memory.touch_class(instruction.type_value)
                state.registers[registers[0]] = state.memory.allocate(label, instruction.type_value or "?")
            elif name == "new-array" and len(registers) == 2:
                size = state.registers.get(registers[1])
                if size == constant(0) and (instruction.type_value or "").startswith("["):
                    value = state.memory.allocate(label, instruction.type_value)
                    state.registers[registers[0]] = value
                    store_property(state, value, ARRAY_LENGTH, size, label)
                else:
                    state.registers[registers[0]] = unknown(label, instruction.type_value)
            elif name.startswith(("iget", "sget")) and registers:
                base = state.registers.get(registers[1]) if name.startswith("iget") else None
                if name.startswith("iget") and not object_id(base) and not (base and base.get("op") == "const"):
                    resolved, query = self.aliases.resolve(method, registers[1], index, state, entry_bindings, self._spend)
                    if resolved is not None:
                        base = resolved
                        state.registers[registers[1]] = resolved
                    if len(state.summaries) < 32:
                        state.summaries.append({**query, "method": method.display(), "read_offset": instruction.offset})
                state.registers[registers[0]] = self._field_read(method, instruction, state, base)
            elif name.startswith(("iput", "sput")) and registers:
                base = state.registers.get(registers[1]) if name.startswith("iput") else None
                self._field_write(method, instruction, state, base, state.registers.get(registers[0], unknown(label)))
            elif name.startswith("aput") and len(registers) >= 2:
                state.memory.havoc([state.registers.get(registers[1])])
                if name.startswith("aput-object"):
                    state.memory.escape(state.registers.get(registers[0]))
            elif (
                "-int" in name
                and name.split("-")[0]
                in {"add", "sub", "rsub", "mul", "and", "or", "xor", "shl", "shr", "ushr"}
                and registers
            ):
                source_registers = registers if "/2addr" in name else registers[1:]
                operands = [state.registers.get(r, unknown(label, "I")) for r in source_registers]
                operands = [{"op": "bool_to_int", "args": [v], "type": "I"} if v.get("type") == "Z" else v for v in operands]
                if instruction.literal_value is not None:
                    operands.append(constant(instruction.literal_value))
                state.registers[registers[0]] = integer_operation(name, operands)
            elif name == "instance-of" and len(registers) == 2:
                state.registers[registers[0]] = instance_of(
                    state.registers.get(registers[1], unknown(label)), instruction.type_value, self.backend, label
                )
            elif name.startswith("check-cast"):
                value = state.registers.get(registers[0], unknown(label))
                target_type = instruction.type_value or instruction.reference
                actual_type = value.get("type") or value.get("owner")
                known = (value.get("op") == "const" and value.get("value") in (None, 0)
                         or actual_type == target_type
                         or target_type == "Ljava/lang/Object;" and actual_type and actual_type.startswith(("L", "["))
                         or actual_type and getattr(self.backend, "is_subtype", lambda *_: False)(actual_type, target_type))
                if not known and value.get("op") == "object":
                    state.predicates.append({"method": method.display(), "offset": instruction.offset,
                                             "predicate": unknown(f"unresolved cast to {target_type} at {label}", "Z"),
                                             "outcome": "normal_cast_return"})
                if not known:
                    state.opaque_effect = True
                if value.get("op") == "unknown" and target_type and target_type.startswith(("L", "[")):
                    # A normal cast narrows a type, not the unknown object's value/identity.
                    state.registers[registers[0]] = {**value, "type": target_type,
                                                    "cast_from_type": value.get("type", "?")}
            elif destination_register(instruction) is not None:
                state.registers[registers[0]] = unknown(f"{name} at {label}")
            for updated in states:
                for successor in cfg.successors[index]:
                    if relevant is not None and successor not in relevant:
                        continue
                    next_state = updated.fork()
                    if name.startswith(
                        ("if-", "packed-switch", "sparse-switch")
                    ) and not self._branch(method, index, successor, next_state):
                        self.statistics["infeasible_paths"] += 1
                        continue
                    todo.append((successor, next_state, visited | {index}))
        if todo:
            self.reasons.add("path_count_or_step_limit")
            incomplete = True
        if incomplete:
            fallback = initial.fork()
            fallback.memory.havoc(fallback.registers.values(), all_fields=True)
            fallback.registers = {}
            fallback.last_result = unknown("incomplete helper return")
            fallback.predicates.append(
                {
                    "method": method.display(),
                    "offset": None,
                    "predicate": unknown("unexplored path alternatives", "Z"),
                }
            )
            result.append(fallback)
        return result[: self.max_paths + 1]

    def _conditions(self, entry, chain, intent_context=None, *, initial=None, event_methods=None):
        """Replay one exact call chain, carrying inputs and helper return alternatives."""
        self.entry_name = intent_context or entry.name
        first = self.backend.methods[chain[0][0]]
        roots = self._entry_methods if event_methods is None else event_methods
        is_entry = entry in roots.get(first.method, ())
        state = initial.fork() if initial is not None else PathState()
        state.registers = {}
        state.memory.initialized_classes.add(first.method.class_name)
        for register, (_formal, kind) in first.parameters.items():
            state.registers[register] = (
                {"op": "intent", "id": self.entry_name, "type": kind,
                 "known_nonnull": first.method.name == "onReceive" and entry.component_type == "receiver"}
                if is_entry and kind == "Landroid/content/Intent;"
                else {"op": "framework_object", "type": kind, "control": "framework", "known_nonnull": True}
                if is_entry and first.method.name == "onReceive" and kind == "Landroid/content/Context;"
                else {"op": "framework_object", "type": kind, "control": "framework", "known_nonnull": True}
                if event_methods is not None and first.method.name in {"onCallAdded", "onCallRemoved"}
                and kind == "Landroid/telecom/Call;" and self.event_replay.is_telecom_entry(first.method)
                else unknown(f"parameter v{register}", kind, "framework" if is_entry else "unknown")
            )
        if first.receiver_register is not None:
            state.registers[first.receiver_register] = {
                "op": "entry_this",
                "owner": first.method.class_name,
                "type": first.method.class_name,
            } if is_entry else unknown("suffix receiver", first.method.class_name)
        states = [state]
        for position, (reference, target) in enumerate(chain):
            method = self.backend.methods[reference]
            advanced = []
            for current in states:
                advanced.extend(self._walk(method, target, current, stack=(reference,)))
            if len(advanced) > self.max_paths:
                self.reasons.add("route_path_limit")
            states = advanced[: self.max_paths]
            if position + 1 < len(chain):
                call = method.instructions[target]
                callee = self.backend.methods[chain[position + 1][0]]
                if not call.name.startswith(("invoke-static", "invoke-direct")):
                    self.reasons.add("virtual_route_dispatch_unresolved")
                for current in states:
                    if call.name.startswith("invoke-static"):
                        current.memory.touch_class(callee.method.class_name)
                    current.calls.append(
                        TraceStep(
                            method.display(),
                            call.offset,
                            call.text(),
                            "invocation reaches effect helper",
                            "CALL",
                            True,
                        )
                    )
                states = [self._bind(callee, call, current) for current in states]
        return states

    def _recorded_chain(self, site, source):
        """Consume validated producer context and retain legacy trace compatibility."""
        self._recorded_execution = read_recorded_execution(
            self.backend, site, source, max_depth=self.max_depth,
        )
        self.reasons.update(self._recorded_execution.reasons)
        return self._recorded_execution.chain

    def _local_constant(self, method, register, before, parameters=None, seen=()):
        """Resolve only agreeing local constants/copies and explicitly bound parameters."""
        key = (register, before)
        if key in seen or len(seen) >= 8 or not self._spend():
            return None
        definitions = self.backend.cfg_for(method).reaching_definitions(register, before)
        values = []
        if definitions.reaches_entry:
            values.append((parameters or {}).get(register))
        for index in definitions.instruction_indices:
            instruction = method.instructions[index]
            if instruction.name.startswith("const-string"):
                values.append(constant(instruction.string_value, "Ljava/lang/String;"))
            elif instruction.name.startswith("const") and instruction.literal_value is not None:
                values.append(constant(instruction.literal_value, "J" if "wide" in instruction.name else "I"))
            elif instruction.name.startswith("move") and len(instruction.registers) == 2:
                values.append(self._local_constant(method, instruction.registers[1], index,
                                                   parameters, (*seen, key)))
            else:
                return None
        return values[0] if values and values[0] is not None and all(v == values[0] for v in values) else None

    def _constant_call_blocker(self, chain):
        """Prove a recorded call segment blocked by a dominating constant branch only."""
        for (caller_ref, call_index), (callee_ref, target) in pairwise(chain):
            caller, callee = self.backend.methods[caller_ref], self.backend.methods[callee_ref]
            call = caller.instructions[call_index]
            if (not call.name.startswith(("invoke-static", "invoke-direct"))
                    or len(caller.instructions) > 512 or len(callee.instructions) > 512
                    or any(i.name == 'move-exception' for i in caller.instructions)):
                continue
            actuals = {r: value for _, _, r in invocation_formals(call)
                       if (value := self._local_constant(caller, r, call_index)) is not None}
            if not actuals:
                continue
            bound = self._bind(callee, call, PathState(registers=actuals)).registers
            cfg = self.backend.cfg_for(callee)
            relevant = self._ancestors(callee, target)
            if self.reasons.intersection({'cfg_reachability_limit', 'condition_search_budget'}):
                return None
            if any(i.name == 'move-exception' and n in relevant for n, i in enumerate(callee.instructions)):
                continue
            for index in sorted(relevant):
                if not self._spend():
                    return None
                branch = callee.instructions[index]
                if not branch.name.startswith('if-') or not cfg.instruction_dominates(index, target):
                    continue
                values = {r: self._local_constant(callee, r, index, bound) for r in branch.registers}
                if not values or any(v is None or v.get('op') != 'const' for v in values.values()):
                    continue
                outcomes = [s for s in cfg.successors[index] if s in relevant]
                if not outcomes:
                    continue
                rejected = []
                for successor in outcomes:
                    state = PathState(registers=values)
                    if self._branch(callee, index, successor, state):
                        break
                    rejected.extend(state.predicates)
                else:
                    return {'branches': rejected,
                            'caller': caller.display(), 'call_offset': call.offset,
                            'callee': callee.display(), 'target_offset': callee.instructions[target].offset,
                            'constant_arguments': {str(r): v for r, v in bound.items() if v.get('op') == 'const'}}
        return None

    @staticmethod
    def _cacheable_conditions(summary):
        """Reject incomplete groups and transient solver failures at every evidence level."""
        if summary.get("unresolved"):
            return False
        pending = [summary]
        while pending:
            value = pending.pop()
            if isinstance(value, dict):
                for name, child in value.items():
                    if name in {"solver", "solver_under_assumptions"} and (
                        not isinstance(child, dict) or not cacheable_solver_result(child)
                    ):
                        return False
                    if isinstance(child, (dict, list, tuple)):
                        pending.append(child)
            elif isinstance(value, (list, tuple)):
                pending.extend(value)
        return True

    def _source_conditions(self, site, entry, source):
        """Check an existing candidate's own call suffix; incomplete evidence never rejects it."""
        self.reasons = set()
        self._contradictions = []
        self._recorded_execution = None
        chain = self._recorded_chain(site, source)
        execution = self._recorded_execution
        context_reasons = execution.reasons if execution else ()
        key = (entry.name, chain, execution.fingerprint) if execution else (entry.name, chain)
        if execution:
            self.statistics["execution_contexts_checked"] += 1
            self.statistics["execution_producer_records"] += execution.evidence["producer_records"]
            self.statistics["execution_calls_consumed"] += execution.evidence["consumed_calls"]
            self.statistics["execution_contexts_incomplete"] += bool(context_reasons)
        if key in self._source_condition_cache:
            self.statistics["source_condition_cache_hits"] += 1
            return self._source_condition_cache[key]
        reached_entry = entry in self._entry_methods.get(chain[0][0], ())
        prefix_status = "recorded_entry" if reached_entry else "missing"
        prefix_limits = []
        recovered_calls = []
        block_prefix = any(reason != "execution_dispatch_not_proven" for reason in context_reasons)
        if not reached_entry and not block_prefix:
            prefix_key = (entry.name, chain)
            if prefix_key not in self._prefix_cache:
                saved_reasons, saved_limit = set(self.reasons), self.max_steps
                self.max_steps = min(saved_limit, self.steps + 256)
                self.reasons = set()
                try:
                    routes = self._routes(*chain[0])
                    matching = {(*prefix, *chain[1:]) for candidate, prefix in routes
                                 if candidate.name == entry.name and len(prefix) + len(chain) - 1 <= self.max_depth + 1}
                    complete = not self.reasons
                    prefix_limits = sorted(self.reasons)
                    prefix_status = ("search_incomplete" if not complete else
                                     "no_matching_entry" if not matching else
                                     "multiple_matching_prefixes" if len(matching) > 1 else "unique_prefix")
                finally:
                    self.max_steps, self.reasons = saved_limit, saved_reasons
                if complete:
                    if len(self._prefix_cache) >= 1024:
                        self._prefix_cache.clear()
                    self._prefix_cache[prefix_key] = next(iter(matching)) if len(matching) == 1 else None
                else:
                    self.statistics["prefix_incomplete_uncached"] += 1
            if self._prefix_cache.get(prefix_key) is not None:
                chain = self._prefix_cache[prefix_key]
                reached_entry = True
                prefix_status = "recovered_prefix"
                self.statistics["entry_prefixes_recovered"] += 1
                prefix_reasons, recovered_calls = check_recovered_calls(self.backend, chain)
                context_reasons = tuple(sorted(set(context_reasons) | set(prefix_reasons)))
                self.reasons.update(prefix_reasons)
                if execution and prefix_reasons and not execution.reasons:
                    self.statistics["execution_contexts_incomplete"] += 1
        elif not reached_entry and block_prefix:
            prefix_status = "unverified_context_not_replayed"
        blocker = self._constant_call_blocker(chain) if not context_reasons else None
        self._contradictions = []
        states = self._conditions(entry, chain) if not blocker and self._spend() else []
        if context_reasons:
            for state in states:
                state.predicates.append({"method": chain[0][0].display(), "offset": None,
                                         "predicate": unknown("unverified recorded execution context", "Z"),
                                         "execution_reasons": list(context_reasons)})
        # Only a supported contradiction, with complete replay and no opaque operands,
        # can rule out this recorded suffix. Missing routes/handlers/budgets stay UNKNOWN.
        decisive = [items for items in self._contradictions
                    if not any(value['op'] == 'unknown' for item in items for value in inputs(item['predicate']))]
        if context_reasons:
            decisive = []
        self._check_conditions(states, complete_prefix=reached_entry)
        if reached_entry and not context_reasons:
            states += self.event_replay.refine(self, entry, chain, states, PathState)
        state_supports = self.supporting_events.attach(self, states, PathState)
        smt_infeasible = (bool(states) and not self.reasons
                          and len(decisive) == len(self._contradictions)
                          and all(state.solver_result["status"] == "UNSAT" for state in states))
        infeasible = bool(blocker) or (not states and not self.reasons and bool(decisive)
                                      and len(decisive) == len(self._contradictions)) or smt_infeasible
        reason = sorted(self.reasons)
        if not reached_entry:
            reason.append("entry_prefix_not_replayed")
        if not states and not infeasible and not reason:
            reason.append("recorded_route_not_resolved")
        chain_json = [{"method": ref.display(), "target_offset": self.backend.methods[ref].instructions[i].offset}
                      for ref, i in chain]
        paths = []
        for state in states:
            predicates = [item['predicate'] for item in state.predicates]
            if not reached_entry:
                predicates.append(unknown("entry prefix not replayed", "Z"))
            formula = combine("and", predicates)
            rejected = state.solver_result["status"] == "UNSAT"
            paths.append({"call_chain": chain_json, "condition": formula,
                          "state_dependencies": state.memory.dependencies,
                          "method_summaries": state.summaries,
                          "solver": state.solver_result,
                          "path_status": "infeasible" if rejected else "candidate",
                          "proof": "sound_partial_condition_unsat" if rejected and state.solver_result.get("abstracted_atoms") else None,
                          "branches": state.predicates, "guards": [],
                          "guard_assessments": [], "guard_coverage": []})
        if infeasible and not smt_infeasible:
            paths = [{"call_chain": chain_json, "condition": constant(False, "Z"),
                      "branches": blocker['branches'] if blocker else decisive[0], "path_status": "infeasible",
                      "guards": [], "guard_assessments": [], "guard_coverage": []}]
        elif not paths or self.reasons:
            paths.append({"call_chain": chain_json, "condition": unknown("incomplete recorded route", "Z"),
                          "branches": [], "path_status": "unexplored", "guards": [],
                          "guard_assessments": [], "guard_coverage": []})
        formula = combine("or", [path['condition'] for path in paths
                                 if path.get("path_status") != "infeasible"])
        summary = compact_conditions({
            "scope": "recorded_call_chain" if reached_entry else "recorded_call_suffix",
            "entry_component": entry.name, "sink_site": site.site_id,
            "logic": "OR_of_path_ANDs", "condition": formula, "condition_text": render(formula),
            "paths": paths, "inputs": inputs(formula),
            "state_supports": state_supports,
            "unknown_inputs": [v for v in inputs(formula) if v['op'] == 'unknown'],
            "coverage": "partial" if reason else "bounded_normal_cfg", "unresolved": reason,
            "feasibility": "INFEASIBLE" if infeasible else "UNKNOWN",
            "proof": ("complete_recorded_suffix_smt_unsat" if smt_infeasible else
                      "constant_call_segment" if blocker else
                      "complete_recorded_suffix_contradiction") if infeasible else None,
            "blocking_call_segment": {k: v for k, v in blocker.items() if k != 'branches'} if blocker else None,
            "authorization": "assessed_separately", "runtime_validated": False,
            "assessment_status": "infeasible" if infeasible else "candidate",
            **({"execution_evidence": {**execution.evidence, "context_sha256": execution.fingerprint,
                                       "prefix_status": prefix_status, "prefix_search_limits": prefix_limits,
                                       "recovered_calls": recovered_calls,
                                       "uncertainty_reasons": list(context_reasons),
                                       "reached_entry": reached_entry}}
               if execution else {}),
        })
        cacheable = self._cacheable_conditions(summary)
        if len(self._source_condition_cache) < 1024 and cacheable:
            self._source_condition_cache[key] = summary
        elif not cacheable:
            self.statistics["source_condition_incomplete_uncached"] += 1
        return summary

    def _annotate_existing(self, site, flows):
        """Attach per-source conditions without deleting shared injection/redirection flows."""
        components = {c.name: c for c in self.backend.components}
        reasons = set()
        for flow in flows:
            sources = []
            for source in flow.sources:
                if match_spoofing_rules(flow, source, components):
                    summary = self._source_conditions(site, components[flow.entry_point.component], source)
                    source = replace(source, spoofing_conditions=summary)
                    reasons.update(summary['unresolved'])
                    self.statistics['existing_sources_assessed'] += 1
                    self.statistics['existing_sources_infeasible' if summary['feasibility'] == 'INFEASIBLE'
                                    else 'existing_sources_unknown'] += 1
                sources.append(source)
            flow.sources = sources
        self.reasons.update(reasons)

    def augment(self, site, flows, flow_builder):
        """Add missing invocation-effect candidates and attach entry/sink condition alternatives."""
        discover = any(rule.matches_sink(site) for rule in SPOOFING_RULES)
        components = {c.name: c for c in self.backend.components}
        if not discover and not any(match_spoofing_rules(flow, source, components)
                                    for flow in flows for source in flow.sources):
            return flows
        self.statistics["sinks"] += 1
        self.steps, self.reasons = 0, set()
        started = time.monotonic()
        self.sink_deadline = min(started + min(0.5, max(0, self.remaining_seconds)), self.deadline or float("inf"))
        self._annotate_existing(site, flows)
        source_reasons = set(self.reasons)
        self.reasons = set()
        if not discover or self.remaining_steps <= 0 or self.remaining_seconds <= 0:
            self.statistics["steps"] += self.steps
            self.statistics["truncated_sinks"] += bool(source_reasons)
            elapsed = time.monotonic() - started
            self.remaining_seconds -= elapsed
            self.statistics["elapsed_seconds"] = self.statistics.get("elapsed_seconds", 0.0) + elapsed
            return flows
        by_entry = {}
        for entry, chain in self._routes(site.method, site.instruction_index):
            states = self._conditions(entry, chain)
            self._check_conditions(states)
            states += self.event_replay.refine(self, entry, chain, states, PathState)
            for state in states:
                if state.solver_result["status"] == "UNSAT" and not self.reasons:
                    continue
                by_entry.setdefault(entry.name, (entry, []))[1].append((chain, state))
        for entry, alternatives in by_entry.values():
            paths = []
            for chain, state in alternatives:
                formula = combine("and", [item["predicate"] for item in state.predicates])
                route_steps = [
                    *state.calls,
                    *(
                        TraceStep(
                            ref.display(),
                            self.backend.methods[ref].instructions[index].offset,
                            self.backend.methods[ref].instructions[index].text(),
                            "execution route boundary",
                            "CALL",
                            True,
                        )
                        for ref, index in chain
                    ),
                ]
                guards, assessments, coverage = flow_builder._route_guards(
                    self.backend.methods[site.method], site, (), tuple(route_steps)
                )
                paths.append(
                    {
                        "call_chain": [
                            {
                                "method": ref.display(),
                                "target_offset": self.backend.methods[ref]
                                .instructions[index]
                                .offset,
                            }
                            for ref, index in chain
                        ],
                        "condition": formula,
                        "state_dependencies": state.memory.dependencies,
                        "method_summaries": state.summaries,
                        "condition_text": render(formula),
                        "solver": state.solver_result,
                        "path_status": "infeasible" if state.solver_result["status"] == "UNSAT" else "candidate",
                        "proof": "sound_partial_condition_unsat" if state.solver_result["status"] == "UNSAT" and state.solver_result.get("abstracted_atoms") else None,
                        "branches": state.predicates,
                        "guards": guards,
                        "guard_assessments": assessments,
                        "guard_coverage": coverage,
                    }
                )
            incomplete_search = any(
                word in reason
                for reason in self.reasons
                for word in ("limit", "budget", "recursive", "recursion", "loop")
            )
            if incomplete_search or (self.reasons and all(p.get("path_status") == "infeasible" for p in paths)):
                paths.append({
                    "call_chain": [], "condition": unknown("unexplored route alternatives", "Z"),
                    "condition_text": "UNKNOWN(unexplored route alternatives)", "branches": [],
                    "guards": [], "guard_assessments": [], "guard_coverage": [],
                    "path_status": "unexplored",
                })
            formula = combine("or", [path["condition"] for path in paths if path.get("path_status") != "infeasible"])
            summary = {
                "scope": "entry_to_sink",
                "entry_component": entry.name,
                "sink_site": site.site_id,
                "logic": "OR_of_path_ANDs",
                "condition": formula,
                "condition_text": render(formula),
                "paths": paths,
                "state_supports": self.supporting_events.attach(self, [state for _chain, state in alternatives], PathState),
                "inputs": inputs(formula),
                "coverage": "partial" if self.reasons else "bounded_normal_cfg",
                "unresolved": sorted(self.reasons),
                "feasibility": "UNKNOWN",
                "unknown_inputs": [value for value in inputs(formula) if value["op"] == "unknown"],
                "authorization": "assessed_separately",
                "runtime_validated": False,
                "assessment_status": "candidate",
            }
            summary = compact_conditions(summary)
            existing = [
                flow
                for flow in flows
                if flow.entry_point.component == entry.name
                and any(
                    match_spoofing_rules(flow, source, {c.name: c for c in self.backend.components})
                    for source in flow.sources
                )
            ]
            if existing:
                for flow in existing:
                    flow.sources = [
                        source if source.spoofing_conditions else replace(source, spoofing_conditions=summary)
                        for source in flow.sources
                    ]
                continue
            trace = tuple(alternatives[0][1].calls)
            # Graph trace and caller checks refer to the same representative route.
            # Alternative route checks stay attached to their own path, never unioned.
            summary["representative_path_index"] = 0
            guards = paths[0]["guards"]
            assessments = paths[0]["guard_assessments"]
            coverage = paths[0]["guard_coverage"]
            source = EvidenceSource(
                Origin(
                    "external_invocation",
                    api=alternatives[0][0][0][0].display(),
                    component=entry.name,
                    method=alternatives[0][0][0][0].display(),
                    offset=0,
                    path=trace,
                ),
                UseRole.INVOCATION,
                True,
                {
                    "manifest_runtime_activation": ENTRY_REACHABILITY_MANIFEST_RUNTIME,
                    "dynamic_receiver_registration": ENTRY_REACHABILITY_DYNAMIC_RECEIVER,
                }.get(entry.entry_provenance, ENTRY_REACHABILITY_DIRECT_MANIFEST),
                route_guards=tuple(guards),
                route_guard_assessments=tuple(assessments),
                route_guard_coverage=tuple(coverage),
                spoofing_conditions=summary,
            )
            flows.append(
                FlowEvidence(
                    f"{site.site_id}|{entry.name}|invocation",
                    EntryPoint(
                        entry.name,
                        entry.component_type,
                        entry.permission,
                        entry.filters,
                        entry.entry_provenance or "manifest_enabled",
                        entry.runtime_activation_evidence,
                        entry.runtime_receiver_evidence,
                    ),
                    [source],
                    site,
                    entry.name,
                    [
                        FlowNode(
                            entry.name,
                            source.origin.method,
                            "entry_point",
                            entry.entry_provenance,
                        )
                    ],
                    [],
                    guards,
                    assessments,
                )
            )
            self.statistics["new_entry_sink_candidates"] += 1
        self.statistics["steps"] += self.steps
        self.statistics["truncated_sinks"] += bool(self.reasons or source_reasons)
        elapsed = time.monotonic() - started
        self.remaining_seconds -= elapsed
        self.statistics["elapsed_seconds"] = self.statistics.get("elapsed_seconds", 0.0) + elapsed
        return flows
