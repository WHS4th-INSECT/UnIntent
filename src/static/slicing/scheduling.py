from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from src.static.model.values import SinkSite


def classify_scout_origins(
    origin_groups: list[list[Any]],
    *,
    control_origin_groups: list[list[Any]] | None = None,
    incomplete: bool,
) -> tuple[str, tuple[str, ...]]:
    """Drop only sinks whose arguments and controlling predicates are proven fixed."""
    control_origin_groups = control_origin_groups or []
    origins = [origin for group in origin_groups for origin in group]
    if any(origin.external for origin in origins):
        return "external", ("sink_argument_has_external_origin",)
    control_origins = [
        origin for group in control_origin_groups for origin in group
    ]
    if any(origin.external for origin in control_origins):
        return "external", ("sink_control_has_external_origin",)
    if incomplete:
        return "unknown", ("scout_origin_analysis_incomplete",)
    if not origin_groups or any(not group for group in origin_groups):
        return "unknown", ("sink_argument_origin_unresolved",)
    if any(not group for group in control_origin_groups):
        return "unknown", ("sink_control_origin_unresolved",)
    if all(origin.kind in {"constant", "uri_parsed_intent"} for origin in origins):
        if all(origin.kind == "constant" for origin in control_origins):
            return "fixed", (
                "sink_arguments_and_controls_resolved_without_external_origin",
            )
        return "unknown", ("sink_control_origin_not_proven_fixed",)
    return "unknown", ("sink_argument_origin_not_proven_fixed",)


@dataclass(frozen=True)
class SinkProfile:
    """Stable discovery order for equal-priority round-robin scheduling."""

    sink: SinkSite
    order: int
    tier: str

    def as_dict(self) -> dict[str, Any]:
        """Serialize scheduling state without a security or cost score."""
        return {
            "site_id": self.sink.site_id,
            "rule_id": self.sink.rule_id,
            "category": self.sink.category,
            "method": self.sink.method.display(),
            "offset": self.sink.offset,
            "order": self.order,
            "tier": self.tier,
        }


class SinkScheduler:
    """Keep discovery order and give every sink the same initial Scout tier."""

    def build(self, backend: Any, sinks: list[SinkSite]) -> list[SinkProfile]:
        """Return every sink exactly once without ranking or clustering."""
        del backend
        return [
            SinkProfile(sink=sink, order=order, tier="scout")
            for order, sink in enumerate(sinks)
        ]


@dataclass(frozen=True)
class BackwardEvidence:
    """Structured evidence observed by the real backward analysis."""

    external_input_dependency: bool = False
    source_adjacent_frontier: bool = False
    intent_or_extra_origin: bool = False
    uri_or_clip_data: bool = False
    whole_intent_influence: bool = False
    destination_influence: bool = False
    exported_entry_direction: bool = False
    icc_boundary: bool = False
    strong_source_to_entry_corridor: bool = False
    source_api_encountered: bool = False
    intent_typed_dependency: bool = False
    entry_boundary_progress: bool = False
    frontier_progress: bool = False
    frontier_count: int = 0
    reasons: tuple[str, ...] = ()

    def merged(self, other: BackwardEvidence) -> BackwardEvidence:
        """Merge observations from repeated slices without losing prior evidence."""
        return BackwardEvidence(
            external_input_dependency=(
                self.external_input_dependency or other.external_input_dependency
            ),
            source_adjacent_frontier=(
                self.source_adjacent_frontier or other.source_adjacent_frontier
            ),
            intent_or_extra_origin=self.intent_or_extra_origin or other.intent_or_extra_origin,
            uri_or_clip_data=self.uri_or_clip_data or other.uri_or_clip_data,
            whole_intent_influence=(
                self.whole_intent_influence or other.whole_intent_influence
            ),
            destination_influence=self.destination_influence or other.destination_influence,
            exported_entry_direction=(
                self.exported_entry_direction or other.exported_entry_direction
            ),
            icc_boundary=self.icc_boundary or other.icc_boundary,
            strong_source_to_entry_corridor=(
                self.strong_source_to_entry_corridor
                or other.strong_source_to_entry_corridor
            ),
            source_api_encountered=(
                self.source_api_encountered or other.source_api_encountered
            ),
            intent_typed_dependency=(
                self.intent_typed_dependency or other.intent_typed_dependency
            ),
            entry_boundary_progress=(
                self.entry_boundary_progress or other.entry_boundary_progress
            ),
            frontier_progress=self.frontier_progress or other.frontier_progress,
            frontier_count=max(self.frontier_count, other.frontier_count),
            reasons=tuple(dict.fromkeys((*self.reasons, *other.reasons))),
        )

    def as_dict(self) -> dict[str, Any]:
        """Serialize evidence without assigning a priority score."""
        return {
            "external_input_dependency": self.external_input_dependency,
            "source_adjacent_frontier": self.source_adjacent_frontier,
            "intent_or_extra_origin": self.intent_or_extra_origin,
            "uri_or_clip_data": self.uri_or_clip_data,
            "whole_intent_influence": self.whole_intent_influence,
            "destination_influence": self.destination_influence,
            "exported_entry_direction": self.exported_entry_direction,
            "icc_boundary": self.icc_boundary,
            "strong_source_to_entry_corridor": self.strong_source_to_entry_corridor,
            "source_api_encountered": self.source_api_encountered,
            "intent_typed_dependency": self.intent_typed_dependency,
            "entry_boundary_progress": self.entry_boundary_progress,
            "frontier_progress": self.frontier_progress,
            "frontier_count": self.frontier_count,
            "reasons": list(self.reasons),
        }


@dataclass
class SinkRuntimeState:
    """Mutable per-sink scheduling state retained across round-robin slices."""

    profile: SinkProfile
    tier: str = "scout"
    evidence: BackwardEvidence = field(default_factory=BackwardEvidence)
    pass_counts: dict[str, int] = field(
        default_factory=lambda: {"scout": 0, "promote": 0, "deep": 0}
    )
    direct_states: int = 0
    approximate_states: int = 0
    promotion_reasons: list[str] = field(default_factory=list)
    scout_verdict: str | None = None
    scout_reasons: list[str] = field(default_factory=list)
    status: str = "pending_scout"
    deferred_reason: str | None = None

    def as_dict(self) -> dict[str, Any]:
        """Serialize fair scheduling and conservative Scout decisions."""
        return {
            "site_id": self.profile.sink.site_id,
            "order": self.profile.order,
            "tier": self.tier,
            "pass_counts": dict(self.pass_counts),
            "direct_states": self.direct_states,
            "approximate_states": self.approximate_states,
            "promotion_reasons": list(self.promotion_reasons),
            "scout_verdict": self.scout_verdict,
            "scout_reasons": list(self.scout_reasons),
            "status": self.status,
            "deferred_reason": self.deferred_reason,
            "evidence": self.evidence.as_dict(),
        }


class AdaptiveSinkScheduler:
    """Order fair sink slices while evidence accelerates, but never gates, coverage."""

    def __init__(
        self,
        profiles: list[SinkProfile],
    ) -> None:
        self.states = {
            profile.sink.site_id: SinkRuntimeState(profile=profile)
            for profile in profiles
        }
        self.dynamic_promotions = 0

    def record_pass(
        self,
        site_id: str,
        tier: str,
        evidence: BackwardEvidence,
        *,
        direct_states: int,
        approximate_states: int,
        budget_exhausted: bool,
        continuation_required: bool = False,
        candidate_found: bool = False,
        scout_verdict: str | None = None,
        scout_reasons: tuple[str, ...] = (),
    ) -> SinkRuntimeState:
        """Accumulate one slice and retain incomplete work for a later fair turn."""
        state = self.states[site_id]
        state.pass_counts[tier] += 1
        state.direct_states += max(0, direct_states)
        state.approximate_states += max(0, approximate_states)
        state.evidence = state.evidence.merged(evidence)
        if scout_verdict is not None:
            state.scout_verdict = scout_verdict
            state.scout_reasons = list(
                dict.fromkeys((*state.scout_reasons, *scout_reasons))
            )
        state.status = "budget_exhausted" if budget_exhausted else "analyzed"
        state.deferred_reason = "budget_exhausted" if budget_exhausted else None

        if tier == "scout" and state.scout_verdict == "fixed":
            state.status = "complete"
            state.deferred_reason = None
        elif tier == "scout":
            verdict = state.scout_verdict or "unknown"
            self._promote(state, "promote", [f"scout_{verdict}"])
        elif tier == "promote" and continuation_required:
            state.status = "queued_promote_continuation"
            state.deferred_reason = "direct_provenance_slice_exhausted"
        elif tier == "promote" and (
            candidate_found or self._should_deepen(state.evidence)
        ):
            reasons = self._deep_reasons(state.evidence)
            if candidate_found:
                reasons.append("direct_candidate_detected")
            self._promote(state, "deep", reasons)
        elif tier == "promote" and budget_exhausted:
            state.status = "deferred"
            state.deferred_reason = "promote_budget_exhausted_without_strong_corridor"
        elif tier == "promote":
            state.status = "complete"
        elif tier == "deep" and continuation_required:
            state.status = "queued_deep_continuation"
            state.deferred_reason = "sink_slice_exhausted"
        elif tier == "deep" and budget_exhausted:
            state.status = "deferred"
            state.deferred_reason = "request_or_global_budget_exhausted"
        elif tier == "deep":
            state.status = "complete"

        return state

    def promotion_queue(self) -> list[SinkSite]:
        """Return all queued Promote work; limits affect order, never eligibility."""
        states = [
            state
            for state in self.states.values()
            if state.tier == "promote"
            and state.status in {"queued_promote", "queued_promote_continuation"}
        ]
        states.sort(key=self._queue_key)
        return [state.profile.sink for state in states]

    def deep_queue(self) -> list[SinkSite]:
        """Return all incomplete Deep work in fair pass and discovery order."""
        states = [
            state
            for state in self.states.values()
            if state.tier == "deep"
            and state.status in {"queued_deep", "queued_deep_continuation"}
        ]
        states.sort(key=self._queue_key)
        return [state.profile.sink for state in states]

    def scout_continuation_queue(self) -> list[SinkSite]:
        """Return only Scout work stopped by its exact direct slice."""
        states = [
            state
            for state in self.states.values()
            if state.tier == "scout"
            and state.status == "queued_scout_continuation"
        ]
        states.sort(key=self._queue_key)
        return [state.profile.sink for state in states]

    def mark_deferred(self, site_id: str, reason: str) -> None:
        """Record incomplete work without classifying the sink as safe."""
        state = self.states[site_id]
        state.status = "deferred"
        state.deferred_reason = reason

    @staticmethod
    def _should_deepen(evidence: BackwardEvidence) -> bool:
        return bool(
            evidence.strong_source_to_entry_corridor
            or (
                evidence.external_input_dependency
                and evidence.exported_entry_direction
                and (evidence.destination_influence or evidence.icc_boundary)
            )
        )

    def _promote(self, state: SinkRuntimeState, tier: str, reasons: list[str]) -> None:
        if state.tier == tier:
            return
        state.tier = tier
        state.promotion_reasons.extend(
            reason for reason in reasons if reason not in state.promotion_reasons
        )
        state.status = f"queued_{tier}"
        state.deferred_reason = None
        self.dynamic_promotions += 1

    @staticmethod
    def _promotion_reasons(evidence: BackwardEvidence) -> list[str]:
        names = (
            "external_input_dependency",
            "source_adjacent_frontier",
            "intent_or_extra_origin",
            "uri_or_clip_data",
            "whole_intent_influence",
            "destination_influence",
            "exported_entry_direction",
            "icc_boundary",
            "source_api_encountered",
            "intent_typed_dependency",
            "entry_boundary_progress",
            "frontier_progress",
        )
        return [name for name in names if getattr(evidence, name)]

    @staticmethod
    def _deep_reasons(evidence: BackwardEvidence) -> list[str]:
        reasons = AdaptiveSinkScheduler._promotion_reasons(evidence)
        if evidence.strong_source_to_entry_corridor:
            reasons.append("strong_source_to_entry_corridor")
        return reasons

    @staticmethod
    def _queue_key(state: SinkRuntimeState) -> tuple[int, int, str]:
        return (
            state.pass_counts.get(state.tier, 0),
            state.profile.order,
            state.profile.sink.site_id,
        )


def collect_backward_evidence(
    candidates: list[Any],
    intent_states: list[Any],
    frontiers: list[Any],
    runtime_signals: set[str] | tuple[str, ...] = (),
) -> BackwardEvidence:
    """Derive scheduling facts from provenance, flow, and frontier objects."""
    external = False
    adjacent = False
    intent_or_extra = False
    uri_or_clip = False
    whole_intent = False
    destination = False
    entry_direction = False
    icc_boundary = False
    strong_corridor = False
    reasons: list[str] = []
    runtime_signals = set(runtime_signals)
    external = "external_input_dependency" in runtime_signals
    adjacent = "source_adjacent_frontier" in runtime_signals
    intent_or_extra = "intent_or_extra_origin" in runtime_signals
    uri_or_clip = "uri_or_clip_data" in runtime_signals
    whole_intent = "whole_intent_influence" in runtime_signals
    destination = "destination_influence" in runtime_signals
    entry_direction = "exported_entry_direction" in runtime_signals
    icc_boundary = "icc_boundary" in runtime_signals
    source_api_encountered = "source_api_encountered" in runtime_signals
    intent_typed_dependency = "intent_typed_dependency" in runtime_signals
    entry_boundary_progress = "entry_boundary_progress" in runtime_signals
    frontier_progress = "frontier_progress" in runtime_signals or bool(frontiers)

    def observe_origin(origin: Any, role: str | None = None) -> None:
        nonlocal external, adjacent, intent_or_extra, uri_or_clip, whole_intent, destination
        kind = str(getattr(origin, "kind", ""))
        field_name = str(getattr(origin, "field", "") or "").lower()
        outer_field = str(getattr(origin, "outer_field", "") or "").lower()
        key = getattr(origin, "key", None) or getattr(origin, "outer_key", None)
        path = tuple(getattr(origin, "path", ()))
        is_external = bool(getattr(origin, "external", False))
        external = external or is_external
        adjacent = adjacent or (is_external and len(path) <= 2)
        intent_or_extra = intent_or_extra or bool(
            kind in {"external_intent", "external_field", "nested_external_intent"}
            or key is not None
        )
        uri_or_clip = uri_or_clip or any(
            token in field_name or token in outer_field for token in ("uri", "data", "clip")
        )
        whole_intent = whole_intent or kind == "external_intent" or field_name == "whole_intent"
        destination = destination or role == "destination" or field_name in {
            "action",
            "component",
            "destination",
            "package",
            "data_uri",
        }

    for state in intent_states:
        for fact in getattr(state, "facts", ()):
            origin = getattr(fact, "origin", None)
            if origin is None:
                continue
            observe_origin(origin)
            field_name = str(getattr(fact, "field", "")).lower()
            if field_name in {"action", "component", "destination", "package", "data_uri"}:
                destination = destination or bool(getattr(origin, "external", False))
            if "clip" in field_name or "uri" in field_name:
                uri_or_clip = True

    for flow in candidates:
        flow_has_external = False
        flow_has_entry = False
        if getattr(flow, "icc_edges", ()):
            icc_boundary = True
        entry = getattr(flow, "entry_point", None)
        if entry is not None:
            flow_has_entry = True
            entry_direction = True
        for source in getattr(flow, "sources", ()):
            origin = getattr(source, "origin", None)
            if origin is None:
                continue
            role_value = getattr(getattr(source, "role", None), "value", None)
            observe_origin(origin, role_value)
            source_external = bool(
                getattr(source, "attacker_controlled", False)
                or getattr(origin, "external", False)
            )
            flow_has_external = flow_has_external or source_external
            reachability = str(getattr(source, "entry_reachability", "unconfirmed"))
            if reachability != "unconfirmed":
                entry_direction = True
                flow_has_entry = True
        strong_corridor = strong_corridor or (flow_has_external and flow_has_entry)

    if external:
        reasons.append("external_input_dependency")
    if adjacent:
        reasons.append("source_adjacent_frontier")
    if intent_or_extra:
        reasons.append("intent_or_extra_origin")
    if uri_or_clip:
        reasons.append("uri_or_clip_data")
    if whole_intent:
        reasons.append("whole_intent_influence")
    if destination:
        reasons.append("destination_influence")
    if entry_direction:
        reasons.append("exported_entry_direction")
    if icc_boundary:
        reasons.append("icc_boundary")
    if strong_corridor:
        reasons.append("strong_source_to_entry_corridor")
    if source_api_encountered:
        reasons.append("source_api_encountered")
    if intent_typed_dependency:
        reasons.append("intent_typed_dependency")
    if entry_boundary_progress:
        reasons.append("entry_boundary_progress")
    if frontier_progress:
        reasons.append("frontier_progress")
    if frontiers:
        reasons.append("saved_frontier")

    return BackwardEvidence(
        external_input_dependency=external,
        source_adjacent_frontier=adjacent,
        intent_or_extra_origin=intent_or_extra,
        uri_or_clip_data=uri_or_clip,
        whole_intent_influence=whole_intent,
        destination_influence=destination,
        exported_entry_direction=entry_direction,
        icc_boundary=icc_boundary,
        strong_source_to_entry_corridor=strong_corridor,
        source_api_encountered=source_api_encountered,
        intent_typed_dependency=intent_typed_dependency,
        entry_boundary_progress=entry_boundary_progress,
        frontier_progress=frontier_progress,
        frontier_count=len(frontiers),
        reasons=tuple(reasons),
    )


__all__ = [
    "AdaptiveSinkScheduler",
    "BackwardEvidence",
    "SinkProfile",
    "SinkRuntimeState",
    "SinkScheduler",
    "classify_scout_origins",
    "collect_backward_evidence",
]
