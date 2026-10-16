from __future__ import annotations

"""조건에 영향을 주는 이전 이벤트·콜백 상태 해석"""

from src.static.classification.branch_predicates import (
    combine,
    compare,
    constant,
    inputs,
    negate,
    unknown,
)
from src.static.model.values import MethodRef
from src.static.search.dex_ir import parse_method_reference
from src.static.search.manifest import generic_attacker_can_invoke


def replace_dependency(expression, identity, value):
    """Replace one state read inside a path formula without mixing writer alternatives."""
    if expression.get("state_dependency") == identity:
        return value
    if "args" not in expression:
        return expression
    args = [replace_dependency(a, identity, value) for a in expression["args"]]
    op = expression["op"]
    if op in {"and", "or"}:
        return combine(op, args)
    if op == "not":
        return negate(args[0])
    if op in {"eq", "ne", "lt", "le", "gt", "ge"}:
        return compare(op, *args)
    return {**expression, "args": args}


class SupportingEvents:
    def __init__(self):
        """Bound event refinement separately from ordinary candidate discovery."""
        self.cache = {}
        self.remaining_queries = 8
        self.remaining_solver_checks = 8
        self.statistics = {"field_queries": 0, "writer_cases": 0, "solver_requests": 0}

    def writer_cases(self, analyzer, reference, state_factory):
        """Recover normal-path writer conditions from callbacks or initialization code."""
        if reference in self.cache:
            return self.cache[reference]
        if self.remaining_queries <= 0 or analyzer.remaining_steps <= 0:
            return []
        self.remaining_queries -= 1
        self.statistics["field_queries"] += 1
        saved = (analyzer.reasons, analyzer.max_steps, analyzer.max_paths,
                 getattr(analyzer, "_contradictions", []), analyzer.entry_name)
        analyzer.reasons, analyzer._contradictions = set(), []
        analyzer.max_steps = min(analyzer.max_steps, analyzer.steps + 256)
        analyzer.max_paths = min(analyzer.max_paths, 4)
        cases = []
        try:
            writes = getattr(analyzer.backend, "_field_writer_occurrences", {}).get(reference, ())
            for ref, index, register in writes[:4]:
                if not analyzer._spend() or len(cases) >= 4:
                    break
                method = analyzer.backend.methods[ref]
                routes = analyzer._routes(ref, index, entry_methods=analyzer.event_replay.roots)[:2]
                if ref.name in {"<clinit>", "<init>"}:
                    initial = state_factory(registers={r: unknown("initializer parameter", t)
                                                      for r, (_n, t) in method.parameters.items()})
                    states = analyzer._walk(method, index, initial)
                    alternatives = [(None, [(ref, index)], s, "initializer") for s in states[:2]]
                else:
                    alternatives = []
                    for entry, chain in routes:
                        states = analyzer._conditions(entry, chain, intent_context=f"{entry.name}#prior:{ref.display()}@{index}",
                                                      event_methods=analyzer.event_replay.roots)
                        alternatives.extend((entry, chain, s, "callback") for s in states[:2])
                for entry, chain, state, kind in alternatives:
                    value = state.registers.get(register, unknown("unresolved writer value", analyzer._field_type(method.instructions[index])))
                    if analyzer._field_type(method.instructions[index]) == "Z" and value.get("op") == "const" and value.get("value") in (0, 1):
                        value = constant(bool(value["value"]), "Z")
                    cases.append({"event_kind": kind, "entry_component": entry.name if entry else None,
                                  "event_control": "framework" if chain[0][0] in analyzer.event_replay.telecom else "component_callback",
                                  "preconditions": ["system_incall_service_binding", "platform_call_event"]
                                  if chain[0][0] in analyzer.event_replay.telecom else [],
                                  "writer": {"method": ref.display(), "offset": method.instructions[index].offset},
                                  "call_chain": [{"method": r.display(), "target_offset": analyzer.backend.methods[r].instructions[i].offset} for r, i in chain],
                                  "condition": combine("and", [b["predicate"] for b in state.predicates]),
                                  "value": value, "coverage": "partial" if analyzer.reasons else "bounded_normal_cfg"})
                    if len(cases) >= 4:
                        break
            self.cache[reference] = cases
            self.statistics["writer_cases"] += len(cases)
            return cases
        finally:
            analyzer.reasons, analyzer.max_steps, analyzer.max_paths, analyzer._contradictions, analyzer.entry_name = saved

    def attach(self, analyzer, states, state_factory):
        """Attach conditional write-before-read formulas while leaving primary verdicts intact."""
        supports = {}
        for state in states:
            formula = combine("and", [p["predicate"] for p in state.predicates])
            dependencies = {d.get("id"): d for d in state.memory.dependencies if d.get("id")}
            for value in inputs(formula):
                identity = value.get("state_dependency")
                if not identity or identity not in dependencies or identity in supports or len(supports) >= 4:
                    continue
                dependency = dependencies[identity]
                alternatives = []
                for case in self.writer_cases(analyzer, dependency["field"], state_factory):
                    linked = combine("and", [case["condition"], replace_dependency(formula, identity, case["value"])])
                    if self.remaining_solver_checks > 0:
                        self.remaining_solver_checks -= 1
                        self.statistics["solver_requests"] += 1
                        checked = analyzer.solver.check(linked, deadline=analyzer.sink_deadline)
                    else:
                        checked = {"status": "UNKNOWN", "reason": "support_solver_limit", "model": []}
                    alternatives.append({**case, "linked_condition": linked, "solver_under_assumptions": checked,
                                         "assumptions": ["writer_executes_before_read", "value_not_overwritten", "same_runtime_object_if_instance_field"],
                                         "order_proven": False, "runtime_validated": False})
                if alternatives:
                    supports[identity] = {"field": dependency["field"], "read": dependency["read"],
                                          "alternatives": alternatives, "logic": "OR_of_conditional_event_chains",
                                          "used_for_primary_verdict": False}
        return supports



ANDROID = "{http://schemas.android.com/apk/res/android}"
RECEIVE = ("onReceive", "(Landroid/content/Context;Landroid/content/Intent;)V")
CALL = "(Landroid/telecom/Call;)V"
PREPARATION_CALLBACKS = {
    "receiver": [RECEIVE],
    "activity": [("onCreate", "(Landroid/os/Bundle;)V"), ("onNewIntent", "(Landroid/content/Intent;)V"),
                 ("onStart", "()V"), ("onResume", "()V"), ("onPause", "()V"), ("onStop", "()V")],
    "service": [("onCreate", "()V"), ("onStartCommand", "(Landroid/content/Intent;II)I"),
                ("onHandleIntent", "(Landroid/content/Intent;)V"), ("onDestroy", "()V")],
}


class EventReplay:
    def __init__(self, backend):
        """Index preparation callbacks independently of attacker entry discovery."""
        self.backend = backend
        self.roots = {}
        self.telecom = set()
        self.cache = {}
        self.remaining = 8
        self.processes = self._processes()
        self.statistics = {"queries": 0, "normal_returns": 0, "attempts": 0,
                           "sat_paths": 0, "blocked": 0, "framework_roots": 0}
        for component in backend.components:
            if not component.analysis_enabled:
                continue
            signatures = list(PREPARATION_CALLBACKS.get(component.component_type, []))
            telecom = (component.component_type == "service"
                       and component.permission == "android.permission.BIND_INCALL_SERVICE"
                       and any("android.telecom.InCallService" in f.actions for f in component.filters)
                       and getattr(backend, "is_subtype", lambda *_: False)(component.descriptor, "Landroid/telecom/InCallService;"))
            if telecom:
                signatures += [("onCallAdded", CALL), ("onCallRemoved", CALL)]
            for name, descriptor in signatures:
                ref = MethodRef(component.descriptor, name, descriptor)
                if ref in backend.methods:
                    self.roots.setdefault(ref, []).append(component)
                    if telecom:
                        self.telecom.add(ref)
        self.statistics["framework_roots"] = len(self.telecom)

    def _processes(self):
        """Read real manifest process boundaries; missing metadata never proves sharing."""
        result = {}
        apk = getattr(getattr(self.backend, "session", None), "apk", None)
        if apk is None:
            return result
        app = apk.get_android_manifest_xml().find("application")
        if app is None:
            return result
        package = apk.get_package()
        default = app.get(ANDROID + "process", package)
        for element in app:
            name = element.get(ANDROID + "name", "")
            name = package + name if name.startswith(".") else package + "." + name if "." not in name else name
            if element.get(ANDROID + "isolatedProcess") != "true":
                result[name] = element.get(ANDROID + "process", default)
        return result

    def is_telecom_entry(self, reference):
        """Recognize only a declared, protected InCallService override."""
        return reference in self.telecom

    def _simple_receiver(self, component):
        """Reject implicit component initialization that could invalidate carried state."""
        if component.component_type != "receiver" or not generic_attacker_can_invoke(component):
            return False
        owner = component.descriptor
        seen = set()
        while owner != "Landroid/content/BroadcastReceiver;":
            if owner in seen:
                return False
            seen.add(owner)
            if MethodRef(owner, "<clinit>", "()V") in self.backend.methods:
                return False
            ctor = self.backend.methods.get(MethodRef(owner, "<init>", "()V"))
            if ctor is None or len(ctor.instructions) != 2:
                return False
            call, ret = ctor.instructions
            target = parse_method_reference(call.reference)
            if (not call.name.startswith("invoke-direct") or ret.name != "return-void"
                    or not target or target[1:] != ("<init>", "()V")
                    or call.registers != (ctor.receiver_register,)):
                return False
            owner = target[0]
        return True

    def _returns(self, analyzer, component, reference):
        """Execute a preparation callback through return, preserving its final heap."""
        if reference in self.cache:
            return self.cache[reference]
        if self.remaining <= 0 or not self._simple_receiver(component):
            return []
        self.remaining -= 1
        self.statistics["queries"] += 1
        saved = analyzer.reasons, analyzer.max_steps, analyzer.max_paths, analyzer.entry_name, getattr(analyzer, "_contradictions", [])
        analyzer.reasons, analyzer._contradictions = set(), []
        analyzer.max_steps = min(analyzer.max_steps, analyzer.steps + 256)
        analyzer.max_paths = min(analyzer.max_paths, 4)
        try:
            states = analyzer._conditions(component, [(reference, None)],
                                          intent_context=component.name + "#preparation",
                                          event_methods=self.roots)
            states = [s for s in states if not analyzer.reasons and not s.opaque_effect]
            self.statistics["normal_returns"] += len(states)
            # An incomplete analysis must be retryable, not a negative cache entry.
            if not analyzer.reasons:
                self.cache[reference] = states
            return states
        finally:
            analyzer.reasons, analyzer.max_steps, analyzer.max_paths, analyzer.entry_name, analyzer._contradictions = saved

    def refine(self, analyzer, entry, chain, states, state_factory):
        """Add at most two SAT sequence witnesses without drawing UNSAT conclusions."""
        if not self._simple_receiver(entry) or not self.processes.get(entry.name):
            return []
        wanted = set()
        for state in states:
            if (state.solver_result or {}).get("status") != "UNKNOWN":
                continue
            needed = {v.get("state_dependency") for v in inputs(combine("and", [p["predicate"] for p in state.predicates]))}
            wanted.update(d["field"] for d in state.memory.dependencies
                          if d.get("id") in needed and d.get("object_identity") == "static")
        if not wanted:
            return []
        roots = set()
        saved_reasons = analyzer.reasons
        saved_entry = analyzer.entry_name
        saved_contradictions = getattr(analyzer, "_contradictions", [])
        analyzer._contradictions = []
        analyzer.reasons = set()
        try:
            for field in sorted(wanted)[:2]:
                for ref, index, _ in getattr(self.backend, "_field_writer_occurrences", {}).get(field, ())[:4]:
                    for component, route in analyzer._routes(ref, index, entry_methods=self.roots)[:2]:
                        if self.processes.get(component.name) == self.processes[entry.name]:
                            roots.add((component, route[0][0]))
            output = []
            for component, ref in sorted(roots, key=lambda item: item[1].display())[:2]:
                for prior in self._returns(analyzer, component, ref):
                    if not any(("static", f) in prior.memory.fields for f in wanted):
                        continue
                    self.statistics["attempts"] += 1
                    initial = prior.fork()
                    # Receiver instances are distinct across deliveries. Static heap
                    # objects keep their allocation identities; instance-this facts do not.
                    initial.memory.fields = {k: v for k, v in initial.memory.fields.items()
                                             if not k[0].startswith("entry:")
                                             and v["value"].get("op") != "entry_this"}
                    initial.summaries.append({"kind": "ordered_event_replay", "preparation": ref.display(),
                        "target": chain[0][0].display(), "field_refs": sorted(wanted),
                        "normal_return_replayed": True, "same_process_proven": True,
                        "order": "preparation_return_then_target_entry", "scope": "sequential_callback_model",
                        "runtime_validated": False})
                    replayed = analyzer._conditions(entry, chain, initial=initial)
                    analyzer._check_conditions(replayed)
                    for state in replayed:
                        if state.solver_result["status"] == "SAT":
                            output.append(state)
                            self.statistics["sat_paths"] += 1
                            if len(output) >= 2:
                                return output
            if not output:
                self.statistics["blocked"] += 1
            return output
        finally:
            analyzer.reasons = saved_reasons
            analyzer.entry_name = saved_entry
            analyzer._contradictions = saved_contradictions
