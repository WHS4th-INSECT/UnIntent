from __future__ import annotations

import hashlib
from collections.abc import Callable
from typing import Any

from src.static.slicing.backward_icc import BackwardICCPath, BackwardICCTracer
from src.static.slicing.backward import DemandTracer
from src.static.classification.processing import deduplicate_icc_edges
from src.static.search.guards import assess_guards
from src.static.search.manifest import entry_points
from src.static.search.backend import GraphBackend
from src.static.model.values import (
    EntryPoint,
    EvidenceSource,
    FlowEvidence,
    FlowNode,
    ICCEdge,
    IntentState,
    MethodIR,
    MethodRef,
    Origin,
    SinkSite,
    UseRole,
)
from src.static.search.api_rules import external_field_api
from src.static.search.dex_ir import invocation_formals, parse_method_reference

DESTINATION_FIELDS = {"component", "class", "package"}
PAYLOAD_FIELDS = {"action", "data", "type", "category", "extra", "flags", "selector"}


class FlowBuilder:
    def __init__(
        self,
        backend: GraphBackend,
        tracer: DemandTracer,
        icc_edges_by_site: dict[str, list[ICCEdge]],
        backward_icc: BackwardICCTracer,
        *,
        analysis_frontier_sink: Callable[[dict[str, Any]], None] | None = None,
    ) -> None:
        self.backend = backend
        self.tracer = tracer
        self.icc_edges_by_site = icc_edges_by_site
        self.backward_icc = backward_icc
        self.entries: dict[str, EntryPoint] = {
            item.component: item for item in entry_points(backend.components)
        }
        self.analysis_frontier_sink = analysis_frontier_sink
        self.unresolved_data_origin_count = 0
        # Index lightweight references only; retaining IR here defeats LRU eviction.
        self._method_refs_by_display: dict[str, MethodRef] = {
            reference.display(): reference for reference in backend.methods
        }
        self._guard_assessment_cache: dict[
            tuple[object, int], tuple[dict[str, object], ...]
        ] = {}
        self.route_guard_requests = 0
        self.route_guard_methods_checked = 0
        self.route_guard_cache_hits = 0

    def _method_for_display(self, display: str) -> MethodIR | None:
        """Resolve a displayed method name through the backend's bounded IR cache."""
        reference = self._method_refs_by_display.get(display)
        return None if reference is None else self.backend.methods.get(reference)

    def build(
        self,
        site: SinkSite,
        intent_states: dict[tuple[str, int], IntentState],
        *,
        include_controls: bool = True,
    ) -> list[FlowEvidence]:
        scope = getattr(self.tracer, "sink_scope", None)
        if scope is None:
            return self._build(site, intent_states, include_controls=include_controls)
        with scope(site):
            return self._build(site, intent_states, include_controls=include_controls)

    def argument_origin_groups(
        self,
        site: SinkSite,
        intent_states: dict[tuple[str, int], IntentState],
    ) -> list[list[Origin]]:
        """Return exact origins carried by each sink argument."""
        if site.category == "icc":
            groups: list[list[Origin]] = []
            for register in site.argument_registers:
                state = intent_states.get((site.site_id, register), IntentState())
                groups.append(
                    [
                        *state.object_origins,
                        *state.pinned_only_origins(),
                        *(fact.origin for fact in state.facts),
                    ]
                )
            return groups
        method = self.backend.methods[site.method]
        requests = [
            (register, site.instruction_index, "value")
            for register in site.argument_registers
        ]
        traced = self.tracer.trace_many(method, requests)
        return [list(traced.get(request, ())) for request in requests]

    def control_origin_groups(self, site: SinkSite) -> list[list[Origin]]:
        """Return exact origins for predicates that may control sink reachability."""
        method = self.backend.methods[site.method]
        cfg = self.backend.cfg_for(method)
        reachability = getattr(cfg, "controlling_branch_reachability", None)
        records = (
            reachability(site.instruction_index) if callable(reachability) else ()
        )
        requests = [
            (register, record.branch_instruction_index, "control")
            for record in records
            for register in method.instructions[
                record.branch_instruction_index
            ].registers
        ]
        traced = self.tracer.trace_many(method, requests)
        return [list(traced.get(request, ())) for request in requests]

    def _build(
        self,
        site: SinkSite,
        intent_states: dict[tuple[str, int], IntentState],
        *,
        include_controls: bool = True,
    ) -> list[FlowEvidence]:
        method = self.backend.methods[site.method]
        roots = list(self.backend.component_roots(site.method))
        candidates: list[
            tuple[Origin, UseRole, tuple[dict[str, object], ...]]
        ] = []

        if site.category == "icc":
            for register in site.argument_registers:
                state = intent_states.get((site.site_id, register), IntentState())
                candidates.extend(
                    (origin, UseRole.WHOLE_INTENT, ()) for origin in state.object_origins
                )
                candidates.extend(
                    (origin, UseRole.PAYLOAD, ()) for origin in state.pinned_only_origins()
                )
                for fact in state.facts:
                    role = (
                        UseRole.DESTINATION if fact.field in DESTINATION_FIELDS else UseRole.PAYLOAD
                    )
                    candidates.append((fact.origin, role, ()))
        else:
            for origins in self.argument_origin_groups(site, intent_states):
                candidates.extend(
                    (origin, UseRole.SENSITIVE_ARGUMENT, ())
                    for origin in origins
                )

        if include_controls:
            candidates.extend(
                (origin, UseRole.CONTROL, branch_evidence)
                for origin, branch_evidence in self._control_origins(
                    method, site.instruction_index
                )
            )
        root_names = {root.name for root in roots}
        buckets: dict[
            tuple[object, ...],
            tuple[
                BackwardICCPath,
                str,
                list[EvidenceSource],
                dict[tuple[int, UseRole], list[EvidenceSource]],
            ],
        ] = {}
        for origin, role, control_branch_evidence in candidates:
            if self._pending_intent_path(origin):
                continue
            traceable = origin.external or origin.kind in {
                "component_intent",
                "component_field",
                "component_parameter",
            }
            resolved_paths = self.backward_icc.resolve(origin) if traceable else []
            if not resolved_paths and traceable:
                self._record_unresolved_origin(site, origin, role)
            for resolved in resolved_paths:
                entry_component = resolved.origin.component
                entry = self.entries.get(entry_component or "")
                if entry is None:
                    continue
                component_local_source = origin.kind in {
                    "component_intent",
                    "component_field",
                    "component_parameter",
                }
                if component_local_source:
                    sink_component = origin.component
                elif origin.component in root_names:
                    sink_component = origin.component
                elif len(root_names) == 1:
                    sink_component = next(iter(root_names))
                else:
                    sink_component = None
                if sink_component is None:
                    self._record_unresolved_origin(
                        site,
                        origin,
                        role,
                        "sink_component_ambiguous_for_resolved_external_origin",
                    )
                    continue
                # The local Source must belong to the sink owner's component.
                # Do not bridge unrelated component roots through reachability.
                if component_local_source and root_names and sink_component not in root_names:
                    self._record_unresolved_origin(
                        site,
                        origin,
                        role,
                        "source_component_not_a_sink_owner",
                    )
                    continue
                if not resolved.components or resolved.components[-1] != sink_component:
                    self._record_unresolved_origin(
                        site,
                        origin,
                        role,
                        "source_to_sink_component_continuity_unproven",
                    )
                    continue

                resolved_role = role
                if role == UseRole.WHOLE_INTENT and resolved.transported_field is not None:
                    resolved_role = (
                        UseRole.DESTINATION
                        if resolved.transported_field in DESTINATION_FIELDS
                        else UseRole.PAYLOAD
                    )
                route_guards, route_guard_assessments, route_guard_coverage = (
                    self._route_guards(
                        method,
                        site,
                        resolved.icc_edges,
                        resolved.origin.path,
                    )
                )
                evidence = EvidenceSource(
                    resolved.origin,
                    resolved_role,
                    True,
                    resolved.entry_reachability,
                    resolved.transfer_evidence,
                    control_branch_evidence,
                    tuple(route_guards),
                    tuple(route_guard_assessments),
                    tuple(route_guard_coverage),
                )
                route_key = (
                    entry.component,
                    sink_component,
                    resolved.components,
                    tuple(
                        (edge.source_site, edge.target_component, edge.resolution)
                        for edge in resolved.icc_edges
                    ),
                    resolved.entry_reachability,
                    resolved.transported_field,
                    tuple(
                        BackwardICCTracer._evidence_key(item)
                        for item in resolved.transfer_evidence
                    ),
                    self._whole_intent_branch_key(origin, resolved_role),
                )
                evidence_key = self._evidence_bucket_key(evidence)
                bucket = buckets.get(route_key)
                if bucket is None:
                    buckets[route_key] = (
                        resolved,
                        sink_component,
                        [evidence],
                        {evidence_key: [evidence]},
                    )
                    continue
                matching = bucket[3].setdefault(evidence_key, [])
                if not any(self._same_evidence(item, evidence) for item in matching):
                    matching.append(evidence)
                    bucket[2].append(evidence)

        current_edges = (
            self.icc_edges_by_site.get(site.site_id, [])
            if site.category == "icc"
            else []
        )
        result: list[FlowEvidence] = []
        for route_key, (resolved, sink_component, evidence, _) in buckets.items():
            entry = self.entries[resolved.components[0]]
            flow_nodes = [
                FlowNode(
                    component=component,
                    method=site.method.display() if component == sink_component else None,
                    role=(
                        "entry_point"
                        if index == 0
                        else "sink_owner"
                        if component == sink_component
                        else "node"
                    ),
                    provenance=entry.provenance if index == 0 else None,
                )
                for index, component in enumerate(resolved.components)
            ]
            if len(flow_nodes) == 1:
                flow_nodes[0] = FlowNode(
                    entry.component,
                    site.method.display(),
                    "entry_point",
                    entry.provenance,
                )
            guards = list(dict.fromkeys(
                guard for item in evidence for guard in item.route_guards
            ))
            guard_assessments = self._deduplicate_dicts([
                assessment
                for item in evidence
                for assessment in item.route_guard_assessments
            ])
            route_signature = hashlib.sha1(
                repr(route_key).encode("utf-8")
            ).hexdigest()[:12]
            result.append(
                FlowEvidence(
                    flow_id=(
                        f"{site.site_id}|{entry.component}|backward-icc:"
                        f"{route_signature}:{'->'.join(resolved.components)}"
                    ),
                    entry_point=entry,
                    sources=evidence,
                    sink=site,
                    sink_component=sink_component,
                    nodes=flow_nodes,
                    icc_edges=self._deduplicate_edges([*resolved.icc_edges, *current_edges]),
                    guards=guards,
                    guard_assessments=guard_assessments,
                )
            )
        return result

    def _route_guards(
        self,
        sink_method,
        sink: SinkSite,
        route_edges: tuple[ICCEdge, ...],
        trace_steps: tuple,
    ) -> tuple[list[str], list[dict[str, object]], list[dict[str, object]]]:
        """Collect authorization checks on the already resolved route.

        This does not walk the APK again. It inspects only methods and ICC
        boundaries already present in the sink-targeted backward trace.
        Results for an identical method boundary are cached across paths.
        """

        self.route_guard_requests += 1

        # One furthest route boundary per method is sufficient: every guard
        # that can protect an earlier data operation and the method's onward
        # route call is visible before that boundary. This keeps both CFG work
        # and JSON size proportional to route methods, not trace-step count.
        targets: dict[object, tuple[int, set[str]]] = {}
        unresolved_methods: dict[str, set[str]] = {}

        def add_target(method_ir, before: int, kind: str) -> None:
            if before < 0 or before > len(method_ir.instructions):
                unresolved_methods.setdefault(method_ir.display(), set()).add(
                    f"{kind}:invalid_boundary"
                )
                return
            existing = targets.get(method_ir.method)
            if existing is None or before > existing[0]:
                kinds = set(existing[1]) if existing is not None else set()
                kinds.add(kind)
                targets[method_ir.method] = (before, kinds)
            else:
                existing[1].add(kind)

        add_target(sink_method, sink.instruction_index, "sink")

        for step in trace_steps:
            method_ir = self._method_for_display(step.method)
            if method_ir is None:
                # Framework/library references are evidence edges, not app
                # methods whose caller checks can be inspected in this APK.
                continue
            if step.offset is None:
                unresolved_methods.setdefault(step.method, set()).add(
                    "trace_step:missing_offset"
                )
                continue
            index = method_ir.offset_to_index.get(step.offset)
            if index is None:
                unresolved_methods.setdefault(step.method, set()).add(
                    "trace_step:offset_not_found"
                )
                continue
            add_target(method_ir, index, "trace_step")

        sites_by_id = getattr(self.backward_icc, "sites_by_id", {})
        for edge in route_edges:
            dispatch = sites_by_id.get(edge.source_site)
            if dispatch is not None:
                dispatch_method = self.backend.methods.get(dispatch.method)
                if dispatch_method is not None:
                    add_target(dispatch_method, dispatch.instruction_index, "icc_dispatch")
            for callback in edge.target_callback_nodes:
                callback_ir = self._method_for_display(callback)
                if callback_ir is None:
                    continue
                if callback_ir.method not in targets:
                    unresolved_methods.setdefault(callback, set()).add(
                        "icc_callback:boundary_not_observed"
                    )

        assessments: list[dict[str, object]] = []
        coverage: list[dict[str, object]] = []
        for method_ref, (before, kinds) in sorted(
            targets.items(), key=lambda item: item[0].display()
        ):
            method_ir = self.backend.methods[method_ref]
            cache_key = (method_ref, before)
            cached = self._guard_assessment_cache.get(cache_key)
            if cached is None:
                cached = tuple(assess_guards(method_ir, before, self.backend))
                self._guard_assessment_cache[cache_key] = cached
                self.route_guard_methods_checked += 1
            else:
                self.route_guard_cache_hits += 1
            boundary_offset = (
                method_ir.instructions[before].offset
                if before < len(method_ir.instructions)
                else None
            )
            route_position = "+".join(sorted(kinds))
            for raw in cached:
                assessments.append({
                    **raw,
                    "route_method": method_ref.display(),
                    "route_boundary_index": before,
                    "route_boundary_offset": boundary_offset,
                    "route_position": route_position,
                })
            coverage.append({
                "method": method_ref.display(),
                "boundary_index": before,
                "boundary_offset": boundary_offset,
                "route_position": route_position,
                "status": "complete",
                "guard_count": len(cached),
            })

        for method_name, reasons in sorted(unresolved_methods.items()):
            # If another exact boundary for this method was inspected, the
            # offset-free callback marker adds no missing coverage.
            if any(item["method"] == method_name for item in coverage):
                continue
            coverage.append({
                "method": method_name,
                "boundary_index": None,
                "boundary_offset": None,
                "route_position": "+".join(sorted(reasons)),
                "status": "incomplete",
                "guard_count": 0,
            })

        unique = self._deduplicate_dicts(assessments)
        return (
            list(dict.fromkeys(str(item["guard"]) for item in unique)),
            unique,
            self._deduplicate_dicts(coverage),
        )

    def metrics(self) -> dict[str, int]:
        return {
            "route_guard_requests": self.route_guard_requests,
            "route_guard_methods_checked": self.route_guard_methods_checked,
            "route_guard_cache_hits": self.route_guard_cache_hits,
            "route_guard_cache_entries": len(self._guard_assessment_cache),
        }

    @staticmethod
    def _deduplicate_dicts(items: list[dict[str, object]]) -> list[dict[str, object]]:
        result: list[dict[str, object]] = []
        seen: set[str] = set()
        for item in items:
            marker = repr(sorted(item.items()))
            if marker not in seen:
                seen.add(marker)
                result.append(item)
        return result

    def _record_unresolved_origin(
        self,
        site: SinkSite,
        origin: Origin,
        role: UseRole,
        reason: str = "no_external_entry_reached_by_backward_icc_data_trace",
    ) -> None:
        self.unresolved_data_origin_count += 1
        if self.analysis_frontier_sink is None:
            return
        direct_edges = sum(step.direct is True for step in origin.path)
        approximate_edges = sum(step.direct is False for step in origin.path)
        record: dict[str, object] = {
            "kind": "unresolved_data_origin",
            "sink_site": site.site_id,
            "source_role": role.value,
            "origin_kind": origin.kind,
            "api": origin.api,
            "field": origin.field,
            "key": origin.key,
            "component": origin.component,
            "method": origin.method,
            "offset": origin.offset,
            "external": origin.external,
            "path_length": len(origin.path),
            "direct_edges": direct_edges,
            "approximate_edges": approximate_edges,
            "reason": reason,
        }
        self.analysis_frontier_sink(record)

    @staticmethod
    def _same_evidence(left: EvidenceSource, right: EvidenceSource) -> bool:
        return (
            left.origin == right.origin
            and left.role == right.role
            and left.attacker_controlled == right.attacker_controlled
            and left.entry_reachability == right.entry_reachability
            and left.entry_transfer_evidence == right.entry_transfer_evidence
            and left.control_branch_evidence == right.control_branch_evidence
            and left.route_guards == right.route_guards
            and left.route_guard_assessments == right.route_guard_assessments
            and left.route_guard_coverage == right.route_guard_coverage
        )

    @staticmethod
    def _evidence_bucket_key(evidence: EvidenceSource) -> tuple[int, UseRole]:
        return id(evidence.origin.path), evidence.role

    @staticmethod
    def _whole_intent_branch_key(
        origin: Origin,
        role: UseRole,
    ) -> tuple[object, ...] | None:
        """Keep distinct Intent factories as distinct dispatch candidates."""
        if role != UseRole.WHOLE_INTENT:
            return None
        factories = tuple(
            (step.method, step.offset, step.evidence.get("intent_uri_factory"))
            for step in origin.path
            if step.evidence.get("intent_uri_factory")
        )
        return origin.kind, factories

    @staticmethod
    def _deduplicate_edges(edges: list[ICCEdge]) -> list[ICCEdge]:
        return deduplicate_icc_edges(edges)

    @staticmethod
    def _pending_intent_path(origin: Origin) -> bool:
        marker = "Landroid/app/PendingIntent;"
        return marker in (origin.api or "") or any(
            marker in step.method or marker in step.instruction for step in origin.path
        )

    def _control_origins(
        self, method, target: int
    ) -> list[tuple[Origin, tuple[dict[str, object], ...]]]:
        """Trace predicate values from CFG branches that may control the sink.

        The CFG establishes only that branch outcomes have different structural
        may-reach/may-bypass profiles. Predicate truth, compound logic, and
        feasibility remain unresolved and are carried into the finding path for
        dynamic validation.
        """

        cfg = self.backend.cfg_for(method)
        requests: list[tuple[int, int, str]] = []
        evidence_by_request: dict[
            tuple[int, int, str], list[dict[str, object]]
        ] = {}
        reachability = getattr(cfg, "controlling_branch_reachability", None)
        branch_records = reachability(target) if callable(reachability) else ()
        for record in branch_records:
            branch_index = record.branch_instruction_index
            branch = method.instructions[branch_index]
            sink = method.instructions[target]

            def outcome(successor_index: int) -> dict[str, object]:
                successor = method.instructions[successor_index]
                return {
                    "instruction_index": successor_index,
                    "offset": successor.offset,
                    "outcome": (
                        "fallthrough"
                        if successor_index == branch_index + 1
                        else "branch_target"
                    ),
                }

            reaching_indices = set(record.sink_reaching_successor_indices)
            bypass_indices = set(record.sink_bypass_successor_indices)
            outcome_indices = sorted(reaching_indices | bypass_indices)
            base_evidence: dict[str, object] = {
                "branch_method": method.display(),
                "branch_instruction_index": branch_index,
                "branch_offset": branch.offset,
                "branch_opcode": branch.name,
                "branch_instruction": branch.text(),
                "sink_instruction_index": target,
                "sink_offset": sink.offset,
                "sink_may_reaching_outcomes": [
                    outcome(index)
                    for index in record.sink_reaching_successor_indices
                ],
                "sink_may_bypass_outcomes": [
                    outcome(index)
                    for index in record.sink_bypass_successor_indices
                ],
                "branch_outcome_profiles": [
                    {
                        **outcome(index),
                        "may_reach_sink": index in reaching_indices,
                        "may_bypass_sink": index in bypass_indices,
                    }
                    for index in outcome_indices
                ],
                "outcome_profiles_differ": True,
                "may_control_sink_reachability": True,
                "dependence_kind": "may_control_sink_reachability",
                "predicate_satisfiability": "unresolved",
                "logical_grouping": "unresolved",
                "dynamic_validation_required": True,
            }
            for register in branch.registers:
                request = (register, branch_index, "control")
                requests.append(request)
                evidence_by_request.setdefault(request, []).append(
                    {
                        **base_evidence,
                        "condition_register": register,
                        "predicate_operand": self._predicate_operand(
                            method, branch_index, register
                        ),
                    }
                )
        traced = self.tracer.trace_many(method, requests)
        correlated: dict[
            tuple[object, ...],
            tuple[Origin, list[dict[str, object]], tuple[int, int, int]],
        ] = {}
        for request in requests:
            for origin in traced.get(request, ()):
                approximate_fallback = any(
                    step.evidence.get("predicate_correlation") == "unresolved"
                    for step in origin.path
                )
                branch_evidence = [
                    {
                        **item,
                        "predicate_operand": {
                            **item["predicate_operand"],
                            "source_field": origin.field,
                            "source_key": origin.key,
                        },
                        "condition_origin_precision": (
                            "fallback_approximate"
                            if approximate_fallback
                            else "predicate_slice"
                        ),
                        "predicate_taint_status": (
                            "not_established"
                            if approximate_fallback
                            else "may_tainted"
                        ),
                        "static_confidence": (
                            "unresolved"
                            if approximate_fallback
                            else "structural_may"
                        ),
                    }
                    for item in evidence_by_request.get(request, ())
                ]
                identity = (
                    origin.kind,
                    origin.api,
                    origin.field,
                    origin.key,
                    repr(origin.value),
                    origin.component,
                    origin.method,
                    origin.offset,
                )
                score = (
                    int(approximate_fallback),
                    sum(step.direct is False for step in origin.path),
                    len(origin.path),
                )
                existing = correlated.get(identity)
                if existing is None:
                    correlated[identity] = (origin, branch_evidence, score)
                    continue
                if score < existing[2]:
                    # Select the display trace independently of branch evidence.
                    # Different sites using the same extra are not duplicates.
                    correlated[identity] = (origin, existing[1], score)
                for item in branch_evidence:
                    if item not in existing[1]:
                        existing[1].append(item)
        return [
            (origin, tuple(branch_evidence))
            for origin, branch_evidence, _score in correlated.values()
        ]

    def _predicate_operand(
        self, method, branch_index: int, register: int
    ) -> dict[str, object]:
        """Describe the call and constant that produced one branch condition register."""

        cfg = self.backend.cfg_for(method)
        branch = method.instructions[branch_index]
        compare_api: str | None = None
        compare_value: object = None
        kind = "unknown"
        for index in cfg.reaching_definitions(register, branch_index).instruction_indices:
            definition = method.instructions[index]
            if definition.name.startswith("const"):
                compare_value = (
                    definition.string_value
                    if definition.string_value is not None
                    else definition.literal_value
                )
                kind = "constant"
                break
            if not definition.name.startswith("move-result") or index == 0:
                continue
            call = method.instructions[index - 1]
            parsed = parse_method_reference(call.reference)
            if parsed is None or not call.name.startswith("invoke-"):
                continue
            # A source getter call is the read being guarded, not a comparison.
            if external_field_api(parsed[1], parsed[0]) is not None:
                break
            compare_api = call.reference
            for _formal, _dex_type, actual in invocation_formals(call):
                value = self.tracer.constant(method, actual, index - 1)
                if value is not None:
                    compare_value = value
                    kind = "constant"
                    break
            break
        if compare_value is None and len(branch.registers) == 2:
            other = next(item for item in branch.registers if item != register)
            value = self.tracer.constant(method, other, branch_index)
            if value is not None:
                compare_value = value
                kind = "constant"
        if compare_api is None and compare_value is None and branch.name in {
            "if-eqz",
            "if-nez",
        }:
            kind = "null_check"
        return {
            "compare_api": compare_api,
            "compare_value": compare_value,
            "compare_value_kind": kind,
            "source_field": None,
            "source_key": None,
        }

    @staticmethod
    def _guards(method, before: int) -> list[str]:
        return list(dict.fromkeys(item["guard"] for item in assess_guards(method, before)))
