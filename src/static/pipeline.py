from __future__ import annotations

import logging
import threading
import time
from collections.abc import Callable
from typing import Any

from src.models.apk import ParsedApkContext
from src.static.slicing.backward import DemandTracer
from src.static.slicing.backward_icc import BackwardICCTracer
from src.static.search.entry_inputs import collect_entry_input_catalog
from src.static.search.icc_provider import DemandICCProvider
from src.static.slicing.flow_builder import FlowBuilder
from src.static.search.route_provider import RouteICCProvider
from src.static.search.runtime_component import collect_runtime_activation_evidence
from src.static.search.runtime_receivers import collect_runtime_receiver_entries
from src.static.slicing.scheduling import (
    AdaptiveSinkScheduler,
    SinkScheduler,
    classify_scout_origins,
    collect_backward_evidence,
)
from src.static.classification.spoofing_paths import SpoofingPathAnalyzer
from src.static.classification.spoofing import SPOOFING_RULES
from src.static.model.flow_spool import FlowGraphSpool
from src.static.search.manifest import entry_points, parse_components
from src.static.search.api_rules import SinkRule, load_rules
from src.static.search.sinks import scan_sinks
from src.static.classification.classifier import FlowGraphAssembler
from src.static.model.evidence import AnalysisResult, FlowGraph
from src.static.classification.processing import (
    compact_intent_state,
    deduplicate_flow_graphs,
    deduplicate_icc_edges,
    peak_rss_mb,
    sink_record,
    summarize_flow_graphs,
)
from src.static.search.call_resolver import LazyAndroguardSession, LazyBytecodeBackend
from src.static.search.icc_index import ICCResolver
from src.static.search.triage import select_sinks, triage_icc_sinks
from src.static.slicing.intent_state import IntentStateResolver
from src.static.model.values import (
    ICCEdge,
    IntentState,
    SinkSite,
    serializable,
)

LOGGER = logging.getLogger(__name__)
PROGRESS_LOG_INTERVAL_SECONDS = 60.0


def run_static_analysis(
    context: ParsedApkContext,
    timeout_seconds: float | None,
    max_call_depth: int,
    *,
    flow_graph_store: FlowGraphSpool | None = None,
    analysis_frontier_sink: Callable[[dict[str, Any]], None] | None = None,
) -> AnalysisResult | None:
    """Analyze one parsed APK and return its complete graph result."""
    started = time.monotonic()
    try:
        LOGGER.info("Static core started: package=%s", context.metadata.package_name)
        session = LazyAndroguardSession.from_parsed_context(context)
        analyzer = OnDemandIntentAnalyzer(max_depth=max_call_depth)
        deadline = None if timeout_seconds is None else started + timeout_seconds
        result = analyzer.analyze_session(
            session,
            deadline=deadline,
            flow_graph_store=flow_graph_store,
            analysis_frontier_sink=analysis_frontier_sink,
        )
        LOGGER.info(
            "Static core completed: package=%s elapsed_seconds=%.2f",
            context.metadata.package_name,
            time.monotonic() - started,
        )
        return result
    except Exception as exception:  # noqa: BLE001 - analyze the next APK after failure.
        LOGGER.warning(
            "Static core failed: package=%s error=%s",
            context.metadata.package_name,
            exception,
        )
        return None


class _StageProgressLogger:
    """Emit periodic liveness logs while one analysis stage is running."""

    def __init__(self, stage: str, deadline: float | None) -> None:
        """Initialize a stage logger with its optional analysis deadline."""
        self._stage = stage
        self._deadline = deadline
        self._started = time.monotonic()
        self._stop_event = threading.Event()
        self._detail_lock = threading.Lock()
        self._detail = ""
        self._thread = threading.Thread(
            target=self._log_heartbeats,
            name="static-analysis-progress",
            daemon=True,
        )

    def __enter__(self) -> _StageProgressLogger:
        """Log stage start and begin periodic liveness reporting."""
        self._log("Static analysis stage started")
        self._thread.start()
        return self

    def update(self, detail: str) -> None:
        """Update and immediately log the current unit of work in this stage."""
        with self._detail_lock:
            self._detail = detail
        self._log("Static analysis stage progress")

    def __exit__(self, exc_type: Any, exc_value: Any, traceback: Any) -> None:
        """Stop liveness reporting and log the final stage state."""
        self._stop_event.set()
        self._thread.join(timeout=1)
        message = (
            "Static analysis stage completed"
            if exc_type is None
            else "Static analysis stage stopped"
        )
        self._log(message)

    def _log_heartbeats(self) -> None:
        """Log that the current stage remains active at a fixed interval."""
        while not self._stop_event.wait(PROGRESS_LOG_INTERVAL_SECONDS):
            self._log("Static analysis stage in progress")

    def _log(self, message: str) -> None:
        """Write stage name, elapsed time, and remaining deadline to the logger."""
        elapsed_seconds = time.monotonic() - self._started
        remaining_seconds = (
            "unlimited"
            if self._deadline is None
            else f"{max(0.0, self._deadline - time.monotonic()):.1f}"
        )
        with self._detail_lock:
            detail = self._detail
        LOGGER.info(
            "%s: stage=%s detail=%s elapsed_seconds=%.1f remaining_seconds=%s",
            message,
            self._stage,
            detail or "-",
            elapsed_seconds,
            remaining_seconds,
        )


class OnDemandIntentAnalyzer:
    """Sink-first analyzer with no whole-program XREF or call graph."""

    def __init__(
        self,
        sink_rules: tuple[SinkRule, ...] | None = None,
        max_depth: int = 24,
        max_paths: int = 32,
        max_fanout: int = 32,
        max_states_per_request: int = 25000,
        max_approx_states_per_request: int | None = None,
        max_approx_fanout: int = 8,
        max_external_origins: int | None = None,
        only_rules: set[str] | None = None,
        resume_roots: set[str] | None = None,
        resume_budget_multiplier: int = 4,
        max_frontiers_per_request: int = 32,
        max_trace_cache_entries: int = 10000,
        max_live_entry_num: int = 3,
        max_dead_entry_num: int = 5,
        scout_states_per_request: int = 500,
        max_scout_rounds: int = 3,
        scout_continuation_states_per_request: int = 1500,
        promote_states_per_request: int = 5000,
        promote_approx_states_per_request: int = 800,
        max_promote_rounds: int = 3,
        max_deep_rounds: int = 10,
        max_total_direct_states: int | None = None,
        max_total_approx_states: int | None = None,
    ) -> None:
        self.sink_rules = sink_rules or load_rules()
        self.max_depth = max_depth
        self.max_paths = max_paths
        self.max_fanout = max_fanout
        self.max_states_per_request = max_states_per_request
        self.max_approx_states_per_request = max_approx_states_per_request
        self.max_approx_fanout = max_approx_fanout
        self.max_external_origins = max_external_origins
        self.only_rules = only_rules
        self.resume_roots = resume_roots or set()
        self.resume_budget_multiplier = max(1, resume_budget_multiplier)
        self.max_frontiers_per_request = max(1, max_frontiers_per_request)
        self.max_trace_cache_entries = max(1, max_trace_cache_entries)
        self.max_live_entry_num = max_live_entry_num
        self.max_dead_entry_num = max_dead_entry_num
        self.scout_states_per_request = scout_states_per_request
        self.max_scout_rounds = max(1, max_scout_rounds)
        self.scout_continuation_states_per_request = max(
            self.scout_states_per_request,
            scout_continuation_states_per_request,
        )
        self.promote_states_per_request = promote_states_per_request
        self.promote_approx_states_per_request = promote_approx_states_per_request
        self.max_promote_rounds = max(1, max_promote_rounds)
        self.max_deep_rounds = max(1, max_deep_rounds)
        self.max_total_direct_states = max_total_direct_states
        self.max_total_approx_states = max_total_approx_states

    def analyze_session(
        self,
        session: LazyAndroguardSession,
        *,
        flow_graph_store: FlowGraphSpool | None = None,
        deadline: float | None = None,
        started: float | None = None,
        analysis_frontier_sink: Callable[[dict[str, Any]], None] | None = None,
    ) -> AnalysisResult:
        """Analyze an existing session, checking a cooperative monotonic deadline."""
        started = time.perf_counter() if started is None else started
        self._ensure_before_deadline(deadline)
        parsed_at = time.perf_counter()
        with _StageProgressLogger("manifest parsing", deadline):
            components, metadata = parse_components(session.apk)
        manifest_component_count = len(components)
        backend = LazyBytecodeBackend(session, components)
        with _StageProgressLogger("runtime component activation evidence", deadline):
            components, runtime_activation_evidence = collect_runtime_activation_evidence(
                backend,
                components,
            )
        with _StageProgressLogger("runtime receiver registration evidence", deadline):
            components, runtime_receiver_evidence = collect_runtime_receiver_entries(
                backend,
                components,
                target_sdk=metadata.get("target_sdk"),
            )
        with _StageProgressLogger("entry input catalog", deadline):
            entry_input_catalog = collect_entry_input_catalog(
                backend,
                components,
                max_depth=self.max_depth,
            )
        indexed_at = time.perf_counter()
        self._ensure_before_deadline(deadline)

        with _StageProgressLogger("sink discovery", deadline):
            discovered_sinks = scan_sinks(
                backend.methods,
                self.sink_rules,
                backend.owner_lineage,
            )
        LOGGER.info(
            "Static analysis sink discovery completed: discovered_sinks=%d",
            len(discovered_sinks),
        )
        sinks, icc_sinks = select_sinks(
            discovered_sinks,
            self.only_rules,
        )
        selected_sink_count = len(sinks)
        sink_roots = {
            sink.site_id: backend.component_roots(sink.method)
            for sink in sinks
        }
        # Keep rootless report sinks for conservative Scout classification.
        # Component roots remain diagnostics and later Entry evidence only.
        rootless_sinks = [
            sink
            for sink in sinks
            if sink.category != "icc" and not sink_roots[sink.site_id]
        ]
        excluded_sink_count = 0
        required_components = {
            root.name
            for sink in sinks
            if sink.category != "icc"
            for root in sink_roots[sink.site_id]
        }
        with _StageProgressLogger("ICC sink triage", deadline):
            (
                redirection_icc_sites,
                transport_icc_sites,
                icc_argument_summaries,
                icc_triage_metrics,
            ) = triage_icc_sinks(backend, icc_sinks, required_components)
        report_icc_site_ids = {
            sink.site_id for sink in sinks if sink.category == "icc"
        }
        selected_icc_site_ids = (
            redirection_icc_sites | transport_icc_sites | report_icc_site_ids
        )
        icc_sinks = [sink for sink in icc_sinks if sink.site_id in selected_icc_site_ids]
        # This count is diagnostic only. Component roots were used for triage,
        # never to synthesize a data edge in a reported flow.
        root_reachable_sink_count = sum(
            bool(sink_roots.get(sink.site_id, ())) for sink in sinks
        )
        LOGGER.info(
            "Static analysis sink triage completed: report_sinks=%d icc_sinks=%d excluded_sinks=%d",
            len(sinks),
            len(icc_sinks),
            excluded_sink_count,
        )
        scanned_at = time.perf_counter()

        report_site_ids = {sink.site_id for sink in sinks}
        transport_only_sinks = [
            sink for sink in icc_sinks if sink.site_id not in report_site_ids
        ]
        report_schedule = SinkScheduler().build(backend, sinks)
        transport_schedule = SinkScheduler().build(backend, transport_only_sinks)
        sink_schedule = [*report_schedule, *transport_schedule]
        schedule_by_site = {profile.sink.site_id: profile for profile in sink_schedule}
        ordered_report_site_ids = {sink.site_id for sink in sinks}
        sinks = [
            profile.sink
            for profile in sink_schedule
            if profile.sink.site_id in ordered_report_site_ids
        ]
        adaptive_scheduler = AdaptiveSinkScheduler(
            [
                profile
                for profile in sink_schedule
                if profile.sink.site_id in ordered_report_site_ids
            ]
        )
        sink_tiers = {
            profile.sink.site_id: profile.tier for profile in sink_schedule
        }

        tracer = DemandTracer(
            backend,
            max_depth=self.max_depth,
            max_paths=self.max_paths,
            max_fanout=self.max_fanout,
            max_states_per_request=self.max_states_per_request,
            max_approx_states_per_request=self.max_approx_states_per_request,
            max_approx_fanout=self.max_approx_fanout,
            max_external_origins=self.max_external_origins,
            resume_roots=self.resume_roots,
            resume_budget_multiplier=self.resume_budget_multiplier,
            max_frontiers_per_request=self.max_frontiers_per_request,
            analysis_frontier_sink=analysis_frontier_sink,
            max_trace_cache_entries=self.max_trace_cache_entries,
            sink_tiers=sink_tiers,
            scout_states_per_request=self.scout_states_per_request,
            promote_states_per_request=self.promote_states_per_request,
            promote_approx_states_per_request=self.promote_approx_states_per_request,
            max_total_direct_states=self.max_total_direct_states,
            max_total_approx_states=self.max_total_approx_states,
        )
        intent_resolver = IntentStateResolver(tracer)
        icc_resolver = ICCResolver(backend)

        intent_states: dict[tuple[str, int], IntentState] = {}
        icc_edges_by_site: dict[str, list[ICCEdge]] = {}
        def resolve_icc_site(sink: SinkSite) -> tuple[list[ICCEdge], bool]:
            """Resolve one ICC site and expose whether its bounded state is complete."""
            self._ensure_before_deadline(deadline)
            truncations_before = tracer.truncation_count
            direct_slices_before = tracer.sink_slice_direct_exhaustions
            approximate_slices_before = tracer.sink_slice_approx_exhaustions
            intent_walk_exhaustions_before = intent_resolver.walk_budget_exhaustions
            method = backend.methods[sink.method]
            roots = backend.component_roots(sink.method)
            root_names = [root.name for root in roots] or [None]
            site_edges: list[ICCEdge] = []
            for register in sink.argument_registers:
                with tracer.sink_scope(sink):
                    state = intent_resolver.resolve(method, register, sink.instruction_index)
                compact_intent_state(state)
                intent_states[(sink.site_id, register)] = state
                for source_component in root_names:
                    site_edges.extend(icc_resolver.resolve(sink, state, source_component))
            site_edges = deduplicate_icc_edges(site_edges)
            icc_edges_by_site[sink.site_id] = site_edges
            complete = not bool(
                tracer.truncation_count > truncations_before
                or tracer.sink_slice_direct_exhaustions > direct_slices_before
                or tracer.sink_slice_approx_exhaustions > approximate_slices_before
                or intent_resolver.walk_budget_exhaustions
                > intent_walk_exhaustions_before
                or tracer.global_direct_budget_exhausted
                or tracer.global_approx_budget_exhausted
            )
            return site_edges, complete

        target_hints = {
            str(item["site_id"]): set(item.get("target_hints", ()))
            for item in icc_argument_summaries
        }
        route_provider = RouteICCProvider(backend, tracer, icc_resolver)
        icc_provider = DemandICCProvider(
            icc_sinks,
            target_hints,
            resolve_icc_site,
            supplemental_providers=(route_provider,),
        )
        backward_icc = BackwardICCTracer(
            {},
            icc_provider.sites_by_id,
            components,
            max_depth=self.max_depth,
            max_paths=self.max_paths,
            max_states=self.max_states_per_request,
            max_live_entry_num=self.max_live_entry_num,
            max_dead_entry_num=self.max_dead_entry_num,
            backend=backend,
            incoming_provider=icc_provider,
            analysis_frontier_sink=analysis_frontier_sink,
        )
        flow_builder = FlowBuilder(
            backend,
            tracer,
            icc_edges_by_site,
            backward_icc,
            analysis_frontier_sink=analysis_frontier_sink,
        )
        assembler = FlowGraphAssembler(components)
        spoofing_paths = SpoofingPathAnalyzer(
            backend, max_depth=self.max_depth, max_paths=self.max_paths, deadline=deadline
        )
        in_memory_graphs: list[FlowGraph] = []
        sink_analysis_metrics: list[dict[str, Any]] = []
        analyzed_sink_sites: set[str] = set()
        evidence_sink_sites: set[str] = set()
        deferred_round_passes: list[str] = []
        spooled_duplicate_flow_graphs = 0
        active_graph_refs: dict[str, tuple[set[str], set[str], set[str]]] = {}

        def emit_candidates(
            site_id: str, candidates: list[Any], notes: list[str]
        ) -> None:
            """Build and store candidates as soon as one sink round finishes."""
            nonlocal spooled_duplicate_flow_graphs
            seen_graph_ids: set[str] = set()
            group_node_ids: set[str] = set()
            group_edge_ids: set[str] = set()
            group_observation_ids: set[str] = set()
            if flow_graph_store is not None:
                flow_graph_store.replace_group(site_id)
            for candidate in candidates:
                graph = assembler.build(candidate)
                node_ids, edge_ids = assembler.take_touched()
                graph.unresolved.extend(notes)
                if notes or flow_graph_store is not None:
                    assembler.reclassify(graph)
                if graph.graph_id in seen_graph_ids:
                    spooled_duplicate_flow_graphs += 1
                    continue
                seen_graph_ids.add(graph.graph_id)
                if flow_graph_store is None:
                    in_memory_graphs.append(graph)
                else:
                    group_node_ids.update(node_ids)
                    group_edge_ids.update(edge_ids)
                    group_observation_ids.update(
                        str(observation_id)
                        for target in graph.outgoing_targets
                        for observation_id in (
                            target.get("value_observation_ids")
                            or ([target["value_observation_id"]]
                                if target.get("value_observation_id") else [])
                        )
                    )
                    flow_graph_store.append(graph, group=site_id)
            if flow_graph_store is not None:
                active_graph_refs[site_id] = (
                    group_node_ids,
                    group_edge_ids,
                    group_observation_ids,
                )
                active_node_ids = set().union(
                    *(
                        node_ids
                        for node_ids, _edge_ids, _observation_ids
                        in active_graph_refs.values()
                    )
                )
                active_edge_ids = set().union(
                    *(
                        edge_ids
                        for _node_ids, edge_ids, _observation_ids
                        in active_graph_refs.values()
                    )
                )
                active_observation_ids = set().union(
                    *(
                        observation_ids
                        for _node_ids, _edge_ids, observation_ids
                        in active_graph_refs.values()
                    )
                )
                assembler.prune(
                    active_node_ids,
                    active_edge_ids,
                    active_observation_ids,
                )

        def discard_sink_state(sink: SinkSite) -> None:
            """Release state after the scheduler has finished with one sink."""
            for register in sink.argument_registers:
                intent_states.pop((sink.site_id, register), None)
            icc_edges_by_site.pop(sink.site_id, None)
            tracer.discard_sink_continuations(sink.site_id)
            intent_resolver.discard_sink_continuations(sink.site_id)

        def round_slice(
            remaining: int | None,
            sink_count: int,
            cap: int,
            fraction: float,
        ) -> int:
            """Return a fair per-sink slice while reserving budget for later rounds."""
            if cap <= 0 or sink_count <= 0:
                return 0
            if remaining is None:
                return cap
            pool = max(0, int(remaining * fraction))
            return min(cap, max(1, pool // sink_count)) if pool else 0

        def run_round(
            round_name: str,
            round_sinks: list[SinkSite],
            *,
            tier: str,
            direct_cap: int,
            approximate_cap: int,
            direct_fraction: float,
            approximate_fraction: float,
            progress: _StageProgressLogger,
        ) -> None:
            """Visit every selected sink once under one aggregate sink quota."""
            direct_slice = round_slice(
                tracer.remaining_total_direct_states,
                len(round_sinks),
                direct_cap,
                direct_fraction,
            )
            approximate_slice = round_slice(
                tracer.remaining_total_approx_states,
                len(round_sinks),
                approximate_cap,
                approximate_fraction,
            )
            intent_walk_slice = (
                min(intent_resolver.max_walk_states, max(64, direct_slice))
                if direct_slice
                else 0
            )
            intent_instruction_slice = (
                max(4096, direct_slice * 16) if direct_slice else 0
            )
            for sink_index, sink in enumerate(round_sinks, start=1):
                progress.update(
                    f"round={round_name} sink={sink_index}/{len(round_sinks)} "
                    f"rule={sink.rule_id} site_id={sink.site_id}"
                )
                self._ensure_before_deadline(deadline)
                sink_started = time.perf_counter()
                direct_states_before = tracer.direct_states_explored
                approx_states_before = tracer.approx_states_explored
                cache_hits_before = tracer.cache_hits
                cache_misses_before = tracer.cache_misses
                direct_exhaustions_before = tracer.direct_budget_exhaustions
                approx_exhaustions_before = tracer.approx_budget_exhaustions
                slice_direct_exhaustions_before = tracer.sink_slice_direct_exhaustions
                slice_approx_exhaustions_before = tracer.sink_slice_approx_exhaustions
                truncation_count = tracer.truncation_count
                frontier_count = len(tracer.unresolved_frontiers)
                backward_truncation_count = (
                    backward_icc.depth_truncations
                    + backward_icc.path_truncations
                    + backward_icc.state_truncations
                )
                provider_incomplete_before = (
                    backward_icc.provider_incomplete_requests
                )
                intent_budget_exhaustions_before = (
                    intent_resolver.walk_budget_exhaustions
                )
                intent_instruction_visits_before = intent_resolver.instruction_visits
                scout_origin_groups: list[list[Any]] = []
                scout_control_origin_groups: list[list[Any]] = []
                with (
                    tracer.sink_analysis_slice(
                        sink,
                        tier=tier,
                        direct_states=direct_slice,
                        approximate_states=approximate_slice,
                        round_name=round_name,
                    ),
                    intent_resolver.sink_analysis_slice(
                        walk_states=intent_walk_slice,
                        instruction_visits=intent_instruction_slice,
                        deadline=deadline,
                        sink_site=sink.site_id,
                        tier=tier,
                    ),
                ):
                    if tier == "scout":
                        if sink.category == "icc":
                            method = backend.methods[sink.method]
                            for register in sink.argument_registers:
                                with tracer.sink_scope(sink):
                                    state = intent_resolver.resolve(
                                        method, register, sink.instruction_index
                                    )
                                compact_intent_state(state)
                                intent_states[(sink.site_id, register)] = state
                        scout_origin_groups = flow_builder.argument_origin_groups(
                            sink, intent_states
                        )
                        scout_control_origin_groups = []
                        candidates = []
                        if (
                            sink.rule_id
                            in {"NOTIFICATION_DISPLAY", "SHELL_COMMAND_SUBMISSION", "FILE_STREAM_OPEN"}
                            and sink_roots[sink.site_id]
                            and any(rule.matches_sink(sink) for rule in SPOOFING_RULES)
                        ):
                            candidates = spoofing_paths.augment(sink, candidates, flow_builder)
                    else:
                        if sink.category == "icc":
                            if tier == "promote":
                                method = backend.methods[sink.method]
                                for register in sink.argument_registers:
                                    with tracer.sink_scope(sink):
                                        state = intent_resolver.resolve(
                                            method,
                                            register,
                                            sink.instruction_index,
                                        )
                                    compact_intent_state(state)
                                    intent_states[(sink.site_id, register)] = state
                            else:
                                icc_provider.resolve_site(sink.site_id)
                        candidates = flow_builder.build(
                            sink,
                            intent_states,
                            include_controls=tier == "deep",
                        )
                        if tier == "deep":
                            candidates = spoofing_paths.augment(
                                sink, candidates, flow_builder
                            )
                profile = schedule_by_site[sink.site_id]
                analyzed_sink_sites.add(sink.site_id)
                direct_states = tracer.direct_states_explored - direct_states_before
                approximate_states = tracer.approx_states_explored - approx_states_before
                new_frontiers = [
                    frontier
                    for frontier in tracer.unresolved_frontiers[frontier_count:]
                    if frontier.sink_site == sink.site_id
                ]
                evidence = collect_backward_evidence(
                    candidates,
                    [
                        state
                        for (site_id, _register), state in intent_states.items()
                        if site_id == sink.site_id
                    ],
                    new_frontiers,
                    tracer.sink_evidence_signals.get(sink.site_id, set()),
                )
                budget_exhausted = bool(
                    tracer.truncation_count > truncation_count
                    or tracer.sink_slice_direct_exhaustions
                    > slice_direct_exhaustions_before
                    or tracer.sink_slice_approx_exhaustions
                    > slice_approx_exhaustions_before
                    or tracer.global_direct_budget_exhausted
                    or tracer.global_approx_budget_exhausted
                    or backward_icc.provider_incomplete_requests
                    > provider_incomplete_before
                    or intent_resolver.walk_budget_exhaustions
                    > intent_budget_exhaustions_before
                )
                continuation_required = bool(
                    tracer.sink_slice_direct_exhaustions
                    > slice_direct_exhaustions_before
                    or tracer.sink_slice_approx_exhaustions
                    > slice_approx_exhaustions_before
                    or backward_icc.provider_incomplete_requests
                    > provider_incomplete_before
                    or intent_resolver.walk_budget_exhaustions
                    > intent_budget_exhaustions_before
                )
                scout_verdict = None
                scout_reasons: tuple[str, ...] = ()
                if tier == "scout":
                    scout_verdict, scout_reasons = classify_scout_origins(
                        scout_origin_groups,
                        control_origin_groups=scout_control_origin_groups,
                        incomplete=budget_exhausted or continuation_required,
                    )
                runtime_state = adaptive_scheduler.record_pass(
                    sink.site_id,
                    tier,
                    evidence,
                    direct_states=direct_states,
                    approximate_states=approximate_states,
                    budget_exhausted=budget_exhausted,
                    continuation_required=continuation_required,
                    candidate_found=bool(candidates),
                    scout_verdict=scout_verdict,
                    scout_reasons=scout_reasons,
                )
                if budget_exhausted:
                    deferred_round_passes.append(f"{round_name}:{sink.site_id}")
                if evidence.reasons:
                    evidence_sink_sites.add(sink.site_id)
                sink_analysis_metrics.append(
                    {
                        "site_id": sink.site_id,
                        "rule_id": sink.rule_id,
                        "schedule_order": profile.order,
                        "round": round_name,
                        "tier": tier,
                        "initial_tier": profile.tier,
                        "direct_slice": direct_slice,
                        "approximate_slice": approximate_slice,
                        "elapsed_seconds": round(time.perf_counter() - sink_started, 6),
                        "direct_states": direct_states,
                        "approximate_states": approximate_states,
                        **tracer.last_sink_slice_profile,
                        "cache_hits": tracer.cache_hits - cache_hits_before,
                        "cache_misses": tracer.cache_misses - cache_misses_before,
                        "cache_hit_rate": round(
                            (tracer.cache_hits - cache_hits_before)
                            / max(
                                1,
                                tracer.cache_hits
                                - cache_hits_before
                                + tracer.cache_misses
                                - cache_misses_before,
                            ),
                            6,
                        ),
                        "intent_instruction_visits": (
                            intent_resolver.instruction_visits
                            - intent_instruction_visits_before
                        ),
                        "intent_budget_exhaustions": (
                            intent_resolver.walk_budget_exhaustions
                            - intent_budget_exhaustions_before
                        ),
                        "direct_budget_exhaustions": (
                            tracer.direct_budget_exhaustions - direct_exhaustions_before
                        ),
                        "approximate_budget_exhaustions": (
                            tracer.approx_budget_exhaustions - approx_exhaustions_before
                        ),
                        "sink_slice_direct_exhaustions": (
                            tracer.sink_slice_direct_exhaustions
                            - slice_direct_exhaustions_before
                        ),
                        "sink_slice_approximate_exhaustions": (
                            tracer.sink_slice_approx_exhaustions
                            - slice_approx_exhaustions_before
                        ),
                        "candidate_graphs": len(candidates),
                        "evidence": evidence.as_dict(),
                        "scheduler_status": runtime_state.status,
                        "deferred_reason": runtime_state.deferred_reason,
                        "scout_verdict": runtime_state.scout_verdict,
                        "scout_reasons": list(runtime_state.scout_reasons),
                    }
                )
                notes: list[str] = []
                if tracer.truncation_count > truncation_count:
                    notes.append(
                        "backward trace reached its round slice or state budget; "
                        "additional candidate origins may exist"
                    )
                if (
                    backward_icc.depth_truncations
                    + backward_icc.path_truncations
                    + backward_icc.state_truncations
                    > backward_truncation_count
                ):
                    notes.append(
                        "backward ICC data trace reached its depth/path budget; "
                        "additional external Entry candidates may exist"
                    )
                if (
                    intent_resolver.walk_budget_exhaustions
                    > intent_budget_exhaustions_before
                ):
                    notes.append(
                        "Intent dispatch walk reached its round budget; "
                        "additional Intent mutations may exist"
                    )
                # An unfinished iterative root intentionally returns no partial
                # graph. Keep the last complete group until new evidence exists
                # or the continuation finishes with a genuinely empty result.
                if candidates or (tier != "scout" and not continuation_required):
                    emit_candidates(sink.site_id, candidates, notes)
                if not runtime_state.status.startswith("queued_"):
                    discard_sink_state(sink)
                sink_analysis_metrics[-1]["elapsed_seconds"] = round(
                    time.perf_counter() - sink_started, 6
                )

        with _StageProgressLogger("candidate flow construction", deadline) as progress:
            # Scout treats every sink equally and examines exact argument and
            # sink-controlling predicate provenance. A sink is removed only
            # when both are proven fixed; external or unresolved origins
            # continue to Promote.
            run_round(
                "scout",
                sinks,
                tier="scout",
                direct_cap=self.scout_states_per_request,
                approximate_cap=0,
                direct_fraction=0.5,
                approximate_fraction=0.0,
                progress=progress,
            )

            # Promote every preserved sink. This is where callers, callbacks,
            # ICC, field state and approximate relations are first expanded.
            for promote_round in range(1, self.max_promote_rounds + 1):
                promoted = adaptive_scheduler.promotion_queue()
                if not promoted:
                    break
                growth = 1 << (promote_round - 1)
                run_round(
                    (
                        "promote"
                        if promote_round == 1
                        else f"promote_continuation_{promote_round}"
                    ),
                    promoted,
                    tier="promote",
                    direct_cap=self.promote_states_per_request * growth,
                    approximate_cap=0,
                    direct_fraction=1.0,
                    approximate_fraction=0.0,
                    progress=progress,
                )
            for sink in adaptive_scheduler.promotion_queue():
                adaptive_scheduler.mark_deferred(
                    sink.site_id, "entry_resolution_promote_round_limit"
                )
                discard_sink_state(sink)

            # Deep uses fixed aggregate slices. Each sink retains a compact
            # iterative-DFS continuation and resumes at its next unvisited
            # state instead of replaying an increasingly large prefix.
            for deep_round in range(1, self.max_deep_rounds + 1):
                deep_candidates = adaptive_scheduler.deep_queue()
                if not deep_candidates:
                    break
                if tracer.remaining_total_direct_states == 0:
                    for sink in deep_candidates:
                        adaptive_scheduler.mark_deferred(
                            sink.site_id, "global_direct_state_budget"
                        )
                        discard_sink_state(sink)
                    break
                run_round(
                    f"deep_{deep_round}",
                    deep_candidates,
                    tier="deep",
                    direct_cap=self.max_states_per_request,
                    approximate_cap=tracer.max_approx_states_per_request,
                    direct_fraction=1.0,
                    approximate_fraction=1.0,
                    progress=progress,
                )
            for sink in adaptive_scheduler.deep_queue():
                adaptive_scheduler.mark_deferred(
                    sink.site_id, "deep_round_limit"
                )
                discard_sink_state(sink)

        budget_deferred_sink_sites = [
            site_id
            for site_id, state in adaptive_scheduler.states.items()
            if state.status in {"budget_exhausted", "deferred"}
        ]

        if flow_graph_store is None:
            flow_graphs, duplicate_flow_graphs = deduplicate_flow_graphs(in_memory_graphs)
            for graph in flow_graphs:
                assembler.reclassify(graph)
        else:
            flow_graph_store.flush()
            flow_graphs = flow_graph_store
            duplicate_flow_graphs = spooled_duplicate_flow_graphs

        sections, finding_groups, graph_metrics = summarize_flow_graphs(
            flow_graphs,
            assembler.nodes,
        )
        self._ensure_before_deadline(deadline)
        finished = time.perf_counter()
        all_icc_edges = deduplicate_icc_edges(icc_provider.materialized_edges)
        trusted_icc_edges = ICCResolver.trusted_reachability_edges(all_icc_edges)
        lazy_metrics = backend.metric_snapshot()
        node_references = graph_metrics["graph_node_references"]
        edge_references = graph_metrics["graph_edge_references"]
        spooled = flow_graph_store is not None
        unresolved_data_origin_count = (
            flow_builder.unresolved_data_origin_count
            + backward_icc.unresolved_boundary_count
        )
        runtime_states = [
            state.as_dict()
            for state in adaptive_scheduler.states.values()
            if state.status in {
                "budget_exhausted",
                "deferred",
                "queued_scout_continuation",
                "queued_promote",
                "queued_promote_continuation",
                "queued_deep",
                "queued_deep_continuation",
            }
        ]
        result_metadata = {
            **metadata,
            "analysis_direction": "sink_to_entry",
            "frontier_occurrences": [
                {
                    "sink_site": sink_site,
                    "round": round_name,
                    "reason": reason,
                    "count": count,
                }
                for (sink_site, round_name, reason), count in sorted(
                    tracer.frontier_occurrences.items(),
                    key=lambda item: tuple(str(value) for value in item[0]),
                )
            ],
            **({"adaptive_sink_schedule": runtime_states} if runtime_states else {}),
            **(
                {
                    "runtime_receiver_registrations": [
                        serializable(item)
                        for item in runtime_receiver_evidence
                        if item.unresolved_dependencies
                        and item.exposure != "NOT_EXPORTED"
                    ]
                }
                if any(
                    item.unresolved_dependencies and item.exposure != "NOT_EXPORTED"
                    for item in runtime_receiver_evidence
                )
                else {}
            ),
            **({"entry_input_catalog": entry_input_catalog} if entry_input_catalog else {}),
            **(
                {
                    "unresolved_component_root_sinks": [
                        sink_record(item) for item in rootless_sinks
                    ]
                }
                if rootless_sinks
                else {}
            ),
        }
        statistics: dict[str, Any] = {
            "classes": len(backend.class_access),
            "manifest_components": manifest_component_count,
            "manifest_entry_points": sum(
                component.exported and component.enabled for component in components
            ),
            "conditional_runtime_entry_points": sum(
                component.exported
                and not component.enabled
                and bool(component.runtime_activation_evidence)
                for component in components
            ),
            "runtime_activation_evidence_sites": len(
                {item.callsite for item in runtime_activation_evidence}
            ),
            "dynamic_receiver_registration_sites": len(runtime_receiver_evidence),
            "dynamic_receiver_entry_points": sum(
                component.entry_provenance == "dynamic_receiver_registration"
                for component in components
            ),
            "unresolved_dynamic_receiver_registrations": sum(
                bool(item.unresolved_dependencies)
                for item in runtime_receiver_evidence
            ),
            "methods": len(backend.methods),
            "sink_sites": len(sinks),
            "discovered_report_sink_sites": selected_sink_count,
            "sink_deep_sites": len(analyzed_sink_sites),
            "sink_round_passes": len(sink_analysis_metrics),
            "sink_round_scout_passes": sum(
                item["tier"] == "scout" for item in sink_analysis_metrics
            ),
            "sink_scout_continuation_passes": sum(
                item["round"].startswith("scout_continuation_")
                for item in sink_analysis_metrics
            ),
            "sink_round_promote_passes": sum(
                item["round"].startswith("promote") for item in sink_analysis_metrics
            ),
            "sink_round_deep_passes": sum(
                item["round"].startswith("deep_") for item in sink_analysis_metrics
            ),
            "sink_round_evidence_sites": len(evidence_sink_sites),
            "sink_dynamic_promotions": adaptive_scheduler.dynamic_promotions,
            "sink_scout_external": sum(
                state.scout_verdict == "external"
                for state in adaptive_scheduler.states.values()
            ),
            "sink_scout_fixed": sum(
                state.scout_verdict == "fixed"
                for state in adaptive_scheduler.states.values()
            ),
            "sink_scout_unknown": sum(
                state.scout_verdict == "unknown"
                for state in adaptive_scheduler.states.values()
            ),
            "sink_scout_preserved": sum(
                state.scout_verdict in {"external", "unknown"}
                for state in adaptive_scheduler.states.values()
            ),
            "sink_scout_removed": sum(
                state.scout_verdict == "fixed"
                for state in adaptive_scheduler.states.values()
            ),
            "sink_dynamic_promote_sites": sum(
                state.pass_counts["promote"] > 0
                for state in adaptive_scheduler.states.values()
            ),
            "sink_dynamic_deep_sites": sum(
                state.pass_counts["deep"] > 0
                for state in adaptive_scheduler.states.values()
            ),
            "sink_budget_exhausted_sites": sum(
                state.status == "budget_exhausted"
                for state in adaptive_scheduler.states.values()
            ),
            "sink_deferred_round_passes": len(deferred_round_passes),
            "sink_schedule_deep": sum(
                profile.tier == "deep" and profile.sink.site_id in report_site_ids
                for profile in sink_schedule
            ),
            "sink_schedule_promote": sum(
                profile.tier == "promote" and profile.sink.site_id in report_site_ids
                for profile in sink_schedule
            ),
            "sink_schedule_scout": sum(
                profile.tier == "scout" and profile.sink.site_id in report_site_ids
                for profile in sink_schedule
            ),
            "icc_transport_schedule_deep": sum(
                profile.tier == "deep" and profile.sink.site_id not in report_site_ids
                for profile in sink_schedule
            ),
            "icc_transport_schedule_promote": sum(
                profile.tier == "promote" and profile.sink.site_id not in report_site_ids
                for profile in sink_schedule
            ),
            "icc_transport_schedule_scout": sum(
                profile.tier == "scout" and profile.sink.site_id not in report_site_ids
                for profile in sink_schedule
            ),
            "sink_budget_deferred": len(budget_deferred_sink_sites),
            "sink_analysis_metrics": sink_analysis_metrics,
            "sink_excluded_without_entry_relation": excluded_sink_count,
            **icc_triage_metrics,
            "icc_prepass_sites": len(icc_sinks),
            "call_root_reachable_sink_sites": root_reachable_sink_count,
            "generated_cfgs": len(backend._cfg_cache),
            "intent_state_walk_states": intent_resolver.walk_states,
            "intent_state_peak_walk_states": intent_resolver.peak_walk_states,
            "intent_state_walk_budget_exhaustions": intent_resolver.walk_budget_exhaustions,
            "intent_state_instruction_visits": intent_resolver.instruction_visits,
            "intent_state_peak_instruction_visits": (
                intent_resolver.peak_instruction_visits
            ),
            "intent_state_instruction_budget_exhaustions": (
                intent_resolver.instruction_budget_exhaustions
            ),
            "semantic_dispatch_edges": backend.semantic_dispatch_edges,
            "synthetic_icc_edges": len(all_icc_edges),
            "trusted_reachability_icc_edges": len(trusted_icc_edges),
            "candidate_only_icc_edges": len(all_icc_edges) - len(trusted_icc_edges),
            **icc_provider.metrics(),
            **backward_icc.metrics(),
            **flow_builder.metrics(),
            "spoofing_condition_analysis": dict(spoofing_paths.statistics),
            "raw_flow_graphs": graph_metrics["raw_flow_graphs"],
            "confirmed_graphs": len(sections["confirmed"]),
            "non_prooved_graphs": len(sections["non_prooved"]),
            "unconfirmed_graphs": len(sections["unconfirmed"]),
            # Compatibility aliases for v7 dashboard readers.
            "candidate_flow_graphs": len(sections["confirmed"]),
            "primary_finding_graphs": len(sections["confirmed"]),
            "supporting_flow_graphs": len(sections["non_prooved"]),
            "unresolved_diagnostic_graphs": len(sections["unconfirmed"]),
            "semantic_finding_groups": len(finding_groups),
            "duplicate_flow_graphs_removed": duplicate_flow_graphs,
            "graphs_with_modeled_sources": graph_metrics["graphs_with_modeled_sources"],
            "graph_nodes": len(assembler.nodes),
            "graph_edges": len(assembler.edges),
            "graph_paths": graph_metrics["graph_paths"],
            "unresolved_data_origins": unresolved_data_origin_count,
            "attacker_source_paths": graph_metrics["attacker_source_paths"],
            "modeled_source_paths": graph_metrics["modeled_source_paths"],
            "diagnostic_origin_paths": graph_metrics["diagnostic_origin_paths"],
            "confirmed_paths": graph_metrics["confirmed_paths"],
            "non_prooved_paths": graph_metrics["non_prooved_paths"],
            "unconfirmed_paths": graph_metrics["unconfirmed_paths"],
            "representative_finding_paths": sum(
                len(
                    {
                        path["path_id"]
                        for path in (
                            *group.representative_paths.values(),
                            *group.candidate_type_representatives.values(),
                        )
                    }
                )
                for group in finding_groups
            ),
            "alternate_finding_paths": sum(group.alternate_path_count for group in finding_groups),
            "graph_node_references": node_references,
            "graph_edge_references": edge_references,
            "graph_node_payloads_avoided": max(0, node_references - len(assembler.nodes)),
            "graph_edge_payloads_avoided": max(0, edge_references - len(assembler.edges)),
            "truncated_trace_requests": tracer.truncation_count,
            "unresolved_frontiers": len(tracer.unresolved_frontiers),
            "unresolved_frontier_occurrences": sum(
                tracer.frontier_occurrences.values()
            ),
            "resumed_root_requests": tracer.resumed_root_requests,
            "guard_nodes": graph_metrics["guard_nodes"],
            "flow_graphs_spooled": spooled,
            "flow_graph_spool_bytes": (
                flow_graph_store.bytes_written if flow_graph_store is not None else 0
            ),
            "flow_graph_spool_flushes": (
                flow_graph_store.flushes if flow_graph_store is not None else 0
            ),
            "direct_graph_edges": sum(edge.direct for edge in assembler.edges),
            "approximate_graph_edges": sum(not edge.direct for edge in assembler.edges),
            "trace_cache_hits": tracer.cache_hits,
            "trace_cache_misses": tracer.cache_misses,
            "trace_cache_entries": tracer.cached_state_count,
            "trace_cache_peak_entries": tracer.peak_cache_entries,
            "trace_cache_evictions": tracer.cache_evictions,
            "trace_cycle_cutoffs": tracer._cycle_cutoffs,
            "cycle_tainted_states_not_cached": tracer.cycle_tainted_states_not_cached,
            "direct_trace_states": tracer.direct_states_explored,
            "approximate_trace_states": tracer.approx_states_explored,
            "approximation_passes": tracer.approximation_passes,
            "approximation_skips": tracer.approximation_skips,
            "approximation_gates": tracer.approximation_gates,
            "direct_budget_exhaustions": tracer.direct_budget_exhaustions,
            "approximate_budget_exhaustions": tracer.approx_budget_exhaustions,
            "global_direct_budget_exhaustions": tracer.global_direct_budget_exhaustions,
            "global_approximate_budget_exhaustions": (
                tracer.global_approx_budget_exhaustions
            ),
            "sink_slice_direct_exhaustions": tracer.sink_slice_direct_exhaustions,
            "sink_slice_approximate_exhaustions": (
                tracer.sink_slice_approx_exhaustions
            ),
            "remaining_total_direct_states": tracer.remaining_total_direct_states,
            "remaining_total_approx_states": tracer.remaining_total_approx_states,
            "batched_trace_calls": tracer.batched_trace_calls,
            "batched_trace_requests": tracer.batched_trace_requests,
            "max_trace_batch_width": tracer.max_trace_batch_width,
            "seed_batch_methods": tracer.seed_batch_methods,
            "seed_batch_requests": tracer.seed_batch_requests,
            "apk_parse_seconds": round(parsed_at - started, 6),
            "ir_index_seconds": round(indexed_at - parsed_at, 6),
            "sink_scan_seconds": round(scanned_at - indexed_at, 6),
            "flow_analysis_seconds": round(finished - scanned_at, 6),
            "elapsed_seconds": round(finished - started, 6),
            "peak_rss_mb": round(peak_rss_mb(), 3),
            **lazy_metrics,
        }
        return AnalysisResult(
            analyzer="static",
            apk=metadata["package"],
            metadata=result_metadata,
            limits={
                "max_depth": self.max_depth,
                "max_paths": self.max_paths,
                "max_fanout": self.max_fanout,
                "max_states_per_request": self.max_states_per_request,
                "max_approx_states_per_request": tracer.max_approx_states_per_request,
                "max_approx_fanout": self.max_approx_fanout,
                "max_external_origins": tracer.max_external_origins,
                "max_frontier_samples_per_sink_round": tracer.max_frontiers_per_request,
                "max_trace_cache_entries": tracer.max_trace_cache_entries,
                "max_total_direct_states": self.max_total_direct_states,
                "max_total_approx_states": self.max_total_approx_states,
                "scout_states_per_request": self.scout_states_per_request,
                "max_scout_rounds": self.max_scout_rounds,
                "scout_continuation_states_per_request": (
                    self.scout_continuation_states_per_request
                ),
                "promote_states_per_request": self.promote_states_per_request,
                "promote_approx_states_per_request": (
                    self.promote_approx_states_per_request
                ),
                "max_promote_rounds": self.max_promote_rounds,
                "max_deep_rounds": self.max_deep_rounds,
                "resume_budget_multiplier": tracer.resume_budget_multiplier,
                "max_backward_icc_states": backward_icc.max_states,
                "max_live_backward_icc_entries": self.max_live_entry_num,
                "max_dead_backward_icc_entries": self.max_dead_entry_num,
            },
            statistics=statistics,
            entry_points=[serializable(item) for item in entry_points(components)],
            sinks=[
                sink_record(item)
                for item in {
                    item.site_id: item for item in [*sinks, *icc_sinks, *rootless_sinks]
                }.values()
            ],
            nodes=assembler.nodes,
            edges=assembler.edges,
            unresolved_frontiers=[serializable(item) for item in tracer.unresolved_frontiers],
            graph_sections=sections,
            finding_groups=finding_groups,
            flow_graphs=flow_graphs,
            unresolved_data_origins=[],
            value_observation_pool=assembler.value_observation_pool,
        )

    @staticmethod
    def _ensure_before_deadline(deadline: float | None) -> None:
        """Stop between analysis stages when the configured deadline expires."""
        if deadline is not None and time.monotonic() >= deadline:
            raise TimeoutError("Intent static analysis timed out")
