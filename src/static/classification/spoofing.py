"""Recognize specific app-authority effects reached from untrusted Intent inputs.

These are candidate rules, not authorization proofs. The common confirmation
policy still evaluates route precision and effective caller guards. Platform
permissions, user consent and app-specific intended exposure remain separate.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from src.static.model.values import Component, EvidenceSource, FlowEvidence, SinkSite
from src.static.search.dex_ir import parse_method_reference
from src.static.search.manifest import generic_attacker_can_invoke

INTENT_SOURCE_KINDS = frozenset(
    {
        "external_intent",
        "external_field",
        "nested_external_intent",
        "uri_parsed_external_intent",
        "external_parameter",
        "component_intent",
        "component_field",
        "component_parameter",
        "external_invocation",
    }
)
EFFECT_ROLES = frozenset({"control", "payload", "sensitive_argument", "invocation"})


@dataclass(frozen=True)
class SpoofingRule:
    rule_id: str
    sink_rules: tuple[str, ...]
    effect: str
    required_app_capability: str
    method_names: tuple[str, ...] = ()
    api_owners: tuple[str, ...] = ()

    # Match an already scanned sink against a narrow effect family and optional API subset.
    def matches_sink(self, sink: SinkSite) -> bool:
        if sink.rule_id not in self.sink_rules:
            return False
        if self.method_names and sink.api_name not in self.method_names:
            return False
        if self.api_owners:
            parsed = parse_method_reference(sink.api)
            return parsed is not None and parsed[0] in self.api_owners
        return True

    # Apply the same sink constraint when classifying an existing flow.
    def matches(self, flow: FlowEvidence) -> bool:
        return self.matches_sink(flow.sink)


SPOOFING_RULES = (
    SpoofingRule(
        "IS_SHELL_COMMAND_SUBMISSION",
        ("SHELL_COMMAND_SUBMISSION",),
        "queue_shell_command_as_app",
        "shell access and command-specific privileges required by the library",
    ),
    SpoofingRule(
        "IS_NOTIFICATION_POST",
        ("NOTIFICATION_DISPLAY",),
        "post_app_notification",
        "notification posting allowed for the victim app",
    ),
    SpoofingRule(
        "IS_NOTIFICATION_CANCEL",
        ("NOTIFICATION_CANCEL",),
        "cancel_app_notification",
        "a matching notification owned by the victim app",
    ),
    SpoofingRule(
        "IS_SMS_SEND",
        ("SMS_SEND",),
        "send_sms_as_app",
        "SMS sending permission and platform/subscription requirements",
    ),
    SpoofingRule(
        "IS_TELECOM_CALL",
        ("TELECOM_PLACE_CALL", "TELECOM_CALL_CONTROL"),
        "place_or_control_call_as_app",
        "telecom permission/role and call state",
    ),
    SpoofingRule(
        "IS_DEVICE_POLICY",
        ("DEVICE_POLICY_CONTROL",),
        "change_device_policy_as_app",
        "active device admin, owner or delegated capability required by the API",
    ),
    SpoofingRule(
        "IS_SETTINGS_WRITE",
        ("SETTINGS_WRITE",),
        "write_system_setting_as_app",
        "write access to the selected settings namespace/key",
    ),
    SpoofingRule(
        "IS_PACKAGE_STATE",
        ("PACKAGE_STATE_CHANGE",),
        "change_package_state_as_app",
        "own-package scope or the API-specific package management capability",
    ),
    SpoofingRule(
        "IS_CONTENT_MUTATION",
        ("CONTENT_RESOLVER_URI",),
        "mutate_provider_data_as_app",
        "victim has write access to the selected provider URI",
        ("insert", "update", "delete"),
    ),
    SpoofingRule(
        "IS_FILE_WRITE_OPEN",
        ("FILE_STREAM_OPEN",),
        "open_file_for_write_as_app",
        "victim has create or write access to the selected file",
        ("<init>",),
        ("Ljava/io/FileOutputStream;", "Ljava/io/FileWriter;", "Ljava/io/PrintWriter;"),
    ),
    SpoofingRule(
        "IS_FILE_DELETE",
        ("FILE_MUTATION", "CONTEXT_FILE_ACCESS", "NIO_FILE_ACCESS"),
        "delete_file_as_app",
        "victim has delete access to the selected file",
        ("delete", "deleteOnExit", "deleteIfExists", "deleteFile"),
    ),
)


# Require a sink-related branch, rather than treating any nearby predicate as an effect trigger.
def _has_control_evidence(source: EvidenceSource) -> bool:
    return any(
        item.get("may_control_sink_reachability") is True
        and item.get("predicate_taint_status") == "may_tainted"
        and item.get("outcome_profiles_differ") is True
        and bool(item.get("sink_may_reaching_outcomes"))
        for item in source.control_branch_evidence
    )


# Preserve the existing receiver-action rule only for a resolved in-app service effect.
def _service_effect(
    flow: FlowEvidence, source: EvidenceSource, entry: Component, components: dict[str, Component]
) -> bool:
    if (
        flow.sink.rule_id != "ICC_DISPATCH"
        or entry.component_type != "receiver"
        or source.role.value != "control"
        or source.origin.field != "action"
        or flow.sink.api_name not in {"startService", "startForegroundService", "stopService"}
    ):
        return False
    return any(
        edge.source_site == flow.sink.site_id
        and edge.resolution in {"explicit_component", "implicit_filter"}
        and edge.target_component in components
        and components[edge.target_component].component_type == "service"
        for edge in flow.icc_edges
    )


# Return path-local rule evidence without changing flow provenance or guard confirmation.
def match_spoofing_rules(
    flow: FlowEvidence, source: EvidenceSource, components: dict[str, Component]
) -> list[dict[str, Any]]:
    conditions = source.spoofing_conditions or {}
    if (conditions.get("feasibility") == "INFEASIBLE"
            and conditions.get("proof") in {"complete_recorded_suffix_contradiction", "constant_call_segment",
                                           "complete_recorded_suffix_smt_unsat"}):
        return []
    entry = components.get(flow.entry_point.component)
    if (
        entry is None
        or entry.component_type not in {"activity", "service", "receiver"}
        or not generic_attacker_can_invoke(entry)
        or not source.attacker_controlled
        or source.origin.kind not in INTENT_SOURCE_KINDS
        or source.role.value not in EFFECT_ROLES
        or (source.role.value == "control" and not _has_control_evidence(source))
        or (source.role.value == "invocation" and not source.spoofing_conditions)
        or (source.origin.kind == "external_invocation" and source.role.value != "invocation")
    ):
        return []
    matched = [rule for rule in SPOOFING_RULES if rule.matches(flow)]
    if _service_effect(flow, source, entry, components):
        matched.append(
            SpoofingRule(
                "IS_SERVICE_CONTROL",
                ("ICC_DISPATCH",),
                "trigger_in_app_service",
                "resolved in-app service and applicable service start restrictions",
            )
        )
    return [
        {
            "rule_id": rule.rule_id,
            "effect": rule.effect,
            "entry_component": entry.name,
            "entry_type": entry.component_type,
            "source_role": source.role.value,
            "input_field": source.origin.field,
            "input_key": source.origin.key,
            "sink_rule_id": flow.sink.rule_id,
            "sink_api": flow.sink.api,
            "connection": ("external_invocation" if source.role.value == "invocation"
                           else "control_dependency" if source.role.value == "control" else "data_flow"),
            "required_app_capability": rule.required_app_capability,
            "capability_status": "not_assessed",
            "authorization_evaluated_separately": True,
        }
        for rule in matched
    ]
