"""Sink discovery and cheap ICC triage before data-flow slicing."""

from __future__ import annotations

from typing import Any

from src.static.search.icc_provenance import (
    analyze_icc_argument,
    propagate_caller_target_hints,
)
from src.static.search.api_rules import external_field_api
from src.static.search.dex_ir import parse_method_reference
from src.static.search.call_resolver import LazyBytecodeBackend
from src.static.model.values import SinkSite


def select_sinks(
    discovered: list[SinkSite],
    only_rules: set[str] | None,
) -> tuple[list[SinkSite], list[SinkSite]]:
    """Select report sinks while retaining ICC sites needed as transport edges."""
    report_sinks = (
        [sink for sink in discovered if sink.rule_id in only_rules]
        if only_rules
        else list(discovered)
    )
    return report_sinks, [sink for sink in discovered if sink.category == "icc"]


def triage_icc_sinks(
    backend: LazyBytecodeBackend,
    icc_sinks: list[SinkSite],
    required_components: set[str] | None = None,
) -> tuple[set[str], set[str], list[dict[str, Any]], dict[str, int]]:
    """Keep ICC sites related to external inputs or required component routes."""
    source_methods: set[Any] = set()
    source_locations: dict[Any, list[dict[str, Any]]] = {}
    for method_ref, method in backend.methods.items():
        locations: list[dict[str, Any]] = []
        for instruction in method.instructions:
            parsed = parse_method_reference(instruction.reference)
            if parsed is None:
                continue
            owner, name, _descriptor = parsed
            source_api = external_field_api(name, owner)
            field = source_api[1] if source_api is not None else None
            if field is None and not (
                name == "getIntent" and owner.endswith(("Activity;", "ActivityCompat;"))
            ):
                continue
            locations.append(
                {
                    "api": instruction.reference,
                    "offset": instruction.offset,
                    "field": field or "whole_intent",
                }
            )
        if locations:
            source_methods.add(method_ref)
            source_locations[method_ref] = locations

    external_sites: set[str] = set()
    transport_sites: set[str] = set()
    summaries: list[dict[str, Any]] = []
    component_names = {component.name for component in backend.components}
    target_hints: dict[str, set[str]] = {}
    source_components: dict[str, set[str]] = {}
    for sink in icc_sinks:
        nearby = source_locations.get(sink.method, [])
        if nearby:
            external_sites.add(sink.site_id)
        provenance = analyze_icc_argument(
            backend,
            sink.method,
            sink.argument_registers,
            sink.instruction_index,
            component_names,
        )
        intent_parameter = provenance.intent_parameter_dependency
        unresolved_dependency = provenance.unresolved_dependency
        if intent_parameter or unresolved_dependency:
            external_sites.add(sink.site_id)
        hints = set(provenance.target_hints)
        caller_hint_reasons: tuple[str, ...] = ()
        if not hints and provenance.parameter_indices:
            propagated, caller_hint_reasons = propagate_caller_target_hints(
                backend,
                sink.method,
                provenance.parameter_indices,
                component_names,
                preferred_targets=set(required_components or ()),
            )
            hints.update(propagated)
        target_hints[sink.site_id] = hints
        source_components[sink.site_id] = {
            root.name for root in backend.component_roots(sink.method)
        }
        summaries.append(
            {
                "site_id": sink.site_id,
                "method": sink.method.display(),
                "offset": sink.offset,
                "api": sink.api,
                "role": (
                    "source_nearby"
                    if nearby
                    else "intent_parameter"
                    if intent_parameter
                    else "unresolved_intent_dependency"
                    if unresolved_dependency
                    else "pending_relation_check"
                ),
                "arguments": [
                    {"register": register} for register in sink.argument_registers
                ],
                "nearby_sources": nearby,
                "target_hints": sorted(hints),
                "intent_parameter": intent_parameter,
                "unresolved_intent_dependency": unresolved_dependency,
                "provenance_reasons": list(
                    dict.fromkeys((*provenance.reasons, *caller_hint_reasons))
                ),
            }
        )

    needed = set(required_components or ())
    changed = True
    while changed:
        changed = False
        for sink in icc_sinks:
            if sink.site_id in transport_sites:
                continue
            if not (target_hints[sink.site_id] & needed):
                continue
            transport_sites.add(sink.site_id)
            previous = len(needed)
            needed.update(source_components[sink.site_id])
            changed = changed or len(needed) != previous

    retained = external_sites | transport_sites
    for summary in summaries:
        site_id = summary["site_id"]
        if site_id in transport_sites:
            summary["role"] = "icc_transport"
        elif site_id not in external_sites:
            summary["role"] = "excluded_unrelated"

    return external_sites, transport_sites, summaries, {
        "icc_triage_sites": len(icc_sinks),
        "lexical_source_methods": len(source_methods),
        "icc_source_nearby_sites": len(external_sites),
        "icc_intent_parameter_dependency_sites": sum(
            bool(item["intent_parameter"]) for item in summaries
        ),
        "icc_unresolved_dependency_sites": sum(
            bool(item["unresolved_intent_dependency"]) for item in summaries
        ),
        "icc_transport_candidate_sites": len(transport_sites),
        "icc_excluded_unrelated_sites": len(icc_sinks) - len(retained),
        "icc_triage_walk_states": 0,
        "icc_triage_walk_budget_exhaustions": 0,
        "icc_deep_sites": len(retained),
    }
