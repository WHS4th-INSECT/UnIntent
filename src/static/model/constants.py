from __future__ import annotations

from typing import Final

CONFIRMED: Final = "confirmed"
NON_PROOVED: Final = "non_prooved"
UNCONFIRMED: Final = "unconfirmed"

# Path class names
PATH_CLASS_ATTACKER_SOURCE: Final = "attacker_source"
PATH_CLASS_DIAGNOSTIC_SOURCE: Final = "diagnostic_origin"
PATH_CLASS_MODELED_SOURCE: Final = "modeled_source"
PATH_CLASS_UNRESOLVED_DIAGNOSTIC: Final = "unresolved_diagnostic"

# Source roles
SOURCE_ROLE_CONTROL: Final = "control"

# Entry-reachability modes
ENTRY_REACHABILITY_DIRECT_MANIFEST: Final = "direct_manifest"
ENTRY_REACHABILITY_MANIFEST_RUNTIME: Final = "direct_manifest_runtime_activation"
ENTRY_REACHABILITY_DYNAMIC_RECEIVER: Final = "direct_dynamic_receiver"
ENTRY_REACHABILITY_BACKWARD_ICC_UNPROVEN: Final = "backward_icc_unproven"
ENTRY_REACHABILITY_BACKWARD_ICC_EXACT: Final = "backward_icc_exact_candidate"
ENTRY_REACHABILITY_BACKWARD_ICC_APPROXIMATE: Final = "backward_icc_approximate"
ENTRY_REACHABILITY_UNCONFIRMED: Final = "unconfirmed"

TRUSTED_ENTRY_REACHABILITIES = frozenset(
    {
        ENTRY_REACHABILITY_DIRECT_MANIFEST,
        ENTRY_REACHABILITY_MANIFEST_RUNTIME,
        ENTRY_REACHABILITY_DYNAMIC_RECEIVER,
    }
)

HARD_REJECTION_REASONS = frozenset(
    {
        "no_candidate_vulnerability_type",
        "source_not_attacker_controlled",
        "modeled_source_missing",
    }
)

REVIEW_SOURCE_ROLES = {
    "invocation",
    "destination",
    "whole_intent",
    "payload",
    "sensitive_argument",
}
