from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from src.static.model.evidence import GraphPath
from src.static.model.constants import (
    CONFIRMED,
    ENTRY_REACHABILITY_BACKWARD_ICC_APPROXIMATE,
    ENTRY_REACHABILITY_BACKWARD_ICC_EXACT,
    ENTRY_REACHABILITY_BACKWARD_ICC_UNPROVEN,
    NON_PROOVED,
    PATH_CLASS_ATTACKER_SOURCE,
    SOURCE_ROLE_CONTROL,
    TRUSTED_ENTRY_REACHABILITIES,
    UNCONFIRMED,
)


# The former proven_icc_transfer label was based on field-name presence.
# It must not regain trust when an older graph is reclassified.
TRUSTED_ENTRY_REACHABILITY = TRUSTED_ENTRY_REACHABILITIES


@dataclass(frozen=True)
class PathDecision:
    status: str
    confirmed_types: tuple[str, ...] = ()
    reasons: tuple[str, ...] = ()
    rejection_reasons: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()


class StrictConfirmationPolicy:

    def evaluate(
        self,
        path: GraphPath,
        *,
        guards: list[str],
        unresolved: list[str],
        guard_assessments: list[dict[str, Any]] | None = None,
    ) -> PathDecision:
        if not path.candidate_types:
            return PathDecision(
                status=UNCONFIRMED,
                rejection_reasons=("no_candidate_vulnerability_type",),
            )

        if path.source_role == "invocation":
            # A structural execution route does not prove runtime feasibility,
            # framework permissions, app state, or caller authorization.
            rejection = self._guard_rejection(guards, guard_assessments or [])
            return PathDecision(
                status=NON_PROOVED,
                reasons=("manifest_callback_to_effect_route",),
                rejection_reasons=(rejection or "invocation_effect_requires_validation",),
                warnings=("dynamic_validation_required", "normal_cfg_and_bounded_calls_only"),
            )

        branch_entry_reachable = bool(
            path.entry_reachability in TRUSTED_ENTRY_REACHABILITY
            or (
                path.entry_reachability == ENTRY_REACHABILITY_BACKWARD_ICC_EXACT
                and path.entry_transfer_evidence
            )
        )
        precise_branch = any(
            item.get("may_control_sink_reachability") is True
            and item.get("predicate_taint_status") == "may_tainted"
            and item.get("condition_origin_precision") != "fallback_approximate"
            and item.get("outcome_profiles_differ") is True
            and bool(item.get("sink_may_reaching_outcomes"))
            for item in path.control_branch_evidence
        )
        if (
            path.source_role == SOURCE_ROLE_CONTROL
            and path.branch_candidate
            and path.branch_candidate_status == "unresolved"
            and path.path_class == PATH_CLASS_ATTACKER_SOURCE
            and path.attacker_controlled
            and path.source_id is not None
            and path.entry_point_id is not None
            and branch_entry_reachable
        ):
            rejected: list[str] = []
            if not precise_branch:
                rejected.append("branch_control_evidence_missing")
            if path.source_to_sink_direct_edge_count == 0:
                rejected.append("source_to_sink_direct_flow_missing")
            if path.source_to_sink_approximate_edge_count:
                rejected.append("source_to_sink_contains_approximation")
            if self._coverage_blocks_confirmation(unresolved):
                rejected.append("analysis_budget_or_broad_resolution")
            guard_rejection = self._guard_rejection(
                guards, guard_assessments or []
            )
            if guard_rejection:
                rejected.append(guard_rejection)
            if rejected:
                return PathDecision(
                    status=NON_PROOVED,
                    reasons=("attacker_controlled_predicate_may_control_sink",),
                    rejection_reasons=tuple(dict.fromkeys(rejected)),
                    warnings=("dynamic_validation_required",),
                )
            return PathDecision(
                status=CONFIRMED,
                confirmed_types=tuple(path.candidate_types),
                reasons=(
                    "attacker_controlled_predicate",
                    "branch_outcome_reaches_sink",
                    "direct_source_predicate_sink_flow",
                    "trusted_external_entry",
                    "no_effective_caller_guard",
                    "analysis_not_truncated_or_broad",
                ),
                warnings=("dynamic_validation_required",),
            )

        rejected: list[str] = []
        if path.path_class != PATH_CLASS_ATTACKER_SOURCE or not path.attacker_controlled:
            rejected.append("source_not_attacker_controlled")
        if path.source_id is None:
            rejected.append("modeled_source_missing")
        if path.entry_reachability not in TRUSTED_ENTRY_REACHABILITY:
            rejected.append("entry_reachability_not_exact")
        if path.source_to_sink_direct_edge_count == 0:
            rejected.append("source_to_sink_direct_flow_missing")
        if path.source_to_sink_approximate_edge_count:
            rejected.append("source_to_sink_contains_approximation")
        if path.source_role == SOURCE_ROLE_CONTROL:
            rejected.append("branch_control_evidence_missing")
        if "guard_scope_incomplete" in unresolved:
            rejected.append("guard_scope_incomplete")
        if (
            not path.supporting
            and path.control_dependency_status == "unresolved"
            and path.control_dependency_path_ids
        ):
            rejected.append("control_dependency_unresolved")
        if (
            path.source_role == "whole_intent"
            and "Intent Redirection" in path.candidate_types
            and (path.entry_origin_kind or path.source_origin_kind)
            not in {"nested_external_intent", "uri_parsed_external_intent"}
        ):
            rejected.append("outer_intent_destination_bound_to_entry")
        assessments = guard_assessments or []
        guard_rejection = self._guard_rejection(guards, assessments)
        if guard_rejection:
            rejected.append(guard_rejection)

        warning_list = ["analysis_coverage_incomplete"] if unresolved else []
        if guards:
            warning_list.append("guard_observed_not_proven_effective")
        if path.control_dependency_status == "unresolved":
            warning_list.append("control_dependency_feasibility_unproven")
        if path.branch_candidate_status == "unresolved":
            warning_list.append("branch_logic_and_feasibility_unproven")
        if path.entry_reachability in {
            "icc_transfer_unproven",
            "backward_icc_unproven",
            "backward_icc_exact_candidate",
            "backward_icc_approximate",
        }:
            warning_list.append("icc_value_identity_not_proven")
        warnings = tuple(warning_list)
        if rejected:
            return PathDecision(
                status=NON_PROOVED,
                rejection_reasons=tuple(dict.fromkeys(rejected)),
                warnings=warnings,
            )

        return PathDecision(
            status=CONFIRMED,
            confirmed_types=tuple(path.candidate_types),
            reasons=(
                "attacker_controlled_modeled_source",
                "trusted_external_entry",
                "direct_source_to_sink_argument_flow",
                "no_unresolved_observed_guard",
            ),
            warnings=warnings,
        )

    @staticmethod
    def _coverage_blocks_confirmation(unresolved: list[str]) -> bool:
        markers = ("budget", "truncat", "name-based", "name based", "broad")
        return any(marker in item.lower() for item in unresolved for marker in markers)

    @staticmethod
    def _guard_rejection(
        guards: list[str], assessments: list[dict[str, Any]]
    ) -> str | None:
        if not guards:
            return None
        effective = {"enforcing_dominates_sink", "controls_sink_reachability"}
        ineffective = {"result_discarded", "not_effective_for_sink"}
        observed: list[str] = []
        for guard in guards:
            matches = [item for item in assessments if item.get("guard") == guard]
            if any(item.get("effectiveness") in effective for item in matches):
                return "effective_caller_guard_present"
            if not matches:
                return "guard_effectiveness_unproven"
            observed.extend(str(item.get("effectiveness")) for item in matches)
        if observed and all(item in ineffective for item in observed):
            return None
        return "guard_effectiveness_unproven"
