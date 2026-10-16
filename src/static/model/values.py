from __future__ import annotations

from dataclasses import dataclass, field, fields, is_dataclass
from dataclasses import field as dc_field
from enum import Enum
from typing import Any


@dataclass(frozen=True)
class MethodRef:
    class_name: str
    name: str
    descriptor: str

    def display(self) -> str:
        return f"{self.class_name}->{self.name}{self.descriptor}"


@dataclass(frozen=True)
class InstructionIR:
    offset: int
    name: str
    output: str
    registers: tuple[int, ...] = ()
    reference: str | None = None
    string_value: str | None = None
    literal_value: int | None = None
    type_value: str | None = None
    # Absolute byte offsets, decoded from DEX code-unit-relative operands.
    branch_target: int | None = None
    switch_cases: tuple[tuple[int, int], ...] = ()

    def text(self) -> str:
        suffix = f" {self.output}" if self.output else ""
        return f"0x{self.offset:04x}: {self.name}{suffix}"


@dataclass
class MethodIR:
    method: MethodRef
    access: str
    instructions: list[InstructionIR]
    parameters: dict[int, tuple[int, str]] = field(default_factory=dict)
    receiver_register: int | None = None
    offset_to_index: dict[int, int] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.offset_to_index:
            self.offset_to_index = {
                instruction.offset: index for index, instruction in enumerate(self.instructions)
            }

    def display(self) -> str:
        return self.method.display()


@dataclass(frozen=True)
class IntentFilter:
    actions: tuple[str, ...] = ()
    categories: tuple[str, ...] = ()
    schemes: tuple[str, ...] = ()
    hosts: tuple[str, ...] = ()
    paths: tuple[str, ...] = ()
    mime_types: tuple[str, ...] = ()


@dataclass(frozen=True)
class RuntimeActivationEvidence:
    """Framework-call evidence that a disabled component may be enabled later."""

    component: str
    callsite: str
    api: str
    requested_states: tuple[int, ...]
    target_resolution: str
    guards: tuple[str, ...] = ()
    reachable_from: tuple[str, ...] = ()
    unresolved_dependencies: tuple[str, ...] = ()


@dataclass(frozen=True)
class RuntimeReceiverRegistrationEvidence:
    """Evidence for one context-registered BroadcastReceiver entry surface."""

    registration_id: str
    callsite: str
    api: str
    receiver_class: str | None
    callback_method: str | None
    target_resolution: str
    exposure: str
    requested_flags: tuple[int, ...] = ()
    permission: str | None = None
    filters: tuple[IntentFilter, ...] = ()
    reachable_from: tuple[str, ...] = ()
    unresolved_dependencies: tuple[str, ...] = ()


@dataclass(frozen=True)
class Component:
    name: str
    code_class: str
    descriptor: str
    component_type: str
    exported: bool
    enabled: bool
    permission: str | None
    permission_protection_level: str | None
    filters: tuple[IntentFilter, ...] = ()
    runtime_activation_evidence: tuple[RuntimeActivationEvidence, ...] = ()
    runtime_receiver_evidence: tuple[RuntimeReceiverRegistrationEvidence, ...] = ()

    @property
    def analysis_enabled(self) -> bool:
        """Include manifest-enabled and evidence-backed conditional components."""

        return (
            self.enabled
            or bool(self.runtime_activation_evidence)
            or bool(self.runtime_receiver_evidence)
        )

    @property
    def runtime_receiver_exported(self) -> bool:
        """Whether at least one resolved registration accepts external broadcasts."""

        return any(
            item.exposure in {"EXPORTED", "PERMISSION_GATED"}
            and item.receiver_class is not None
            and not set(item.unresolved_dependencies).intersection(
                {
                    "receiver_target",
                    "receiver_target_set",
                    "export_status",
                    "registration_reachability",
                }
            )
            for item in self.runtime_receiver_evidence
        )

    @property
    def is_entry_point(self) -> bool:
        return self.analysis_enabled and (
            self.exported or self.runtime_receiver_exported
        )

    @property
    def entry_provenance(self) -> str | None:
        """Describe why this manifest component is an external Entry candidate."""

        if not self.is_entry_point:
            return None
        if self.runtime_receiver_exported and not (self.exported and self.enabled):
            return "dynamic_receiver_registration"
        if not self.enabled and self.runtime_activation_evidence:
            return "manifest_runtime_activation"
        return "manifest_enabled"


@dataclass(frozen=True)
class EntryPoint:
    component: str
    component_type: str
    permission: str | None
    filters: tuple[IntentFilter, ...] = ()
    provenance: str = "manifest_enabled"
    runtime_activation_evidence: tuple[RuntimeActivationEvidence, ...] = ()
    runtime_receiver_evidence: tuple[RuntimeReceiverRegistrationEvidence, ...] = ()


@dataclass(frozen=True)
class TraceStep:
    method: str
    offset: int | None
    instruction: str
    relation: str
    # Most legacy trace steps derive these attributes from their relation.
    # ICC boundary tracing supplies them explicitly so a route candidate is
    # never promoted merely because two component names are connected.
    edge_type: str | None = None
    direct: bool | None = None
    evidence: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True, eq=False)
class TracePath:
    """Persistent trace path whose prefixes are shared by cached origins."""

    parent: TracePath | None = None
    step: TraceStep | None = None
    length: int = 0

    def append(self, step: TraceStep) -> TracePath:
        return TracePath(self, step, self.length + 1)

    @classmethod
    def from_steps(cls, steps: Any) -> TracePath:
        if isinstance(steps, cls):
            return steps
        result = cls()
        for step in steps:
            result = result.append(step)
        return result

    def __len__(self) -> int:
        return self.length

    def __iter__(self):
        steps: list[TraceStep] = []
        steps.extend(self.iter_reverse())
        yield from reversed(steps)

    def iter_reverse(self):
        """Walk newest-to-oldest without allocating a flattened path."""
        current: TracePath | None = self
        while current is not None and current.step is not None:
            yield current.step
            current = current.parent

    def __eq__(self, other: object) -> bool:
        if self is other:
            return True
        if isinstance(other, TracePath):
            return len(self) == len(other) and all(
                left == right for left, right in zip(self, other)
            )
        if isinstance(other, (list, tuple)):
            return len(self) == len(other) and all(
                left == right for left, right in zip(self, other)
            )
        return NotImplemented

    def __repr__(self) -> str:
        return repr(tuple(self))

    def __reduce__(self):
        return (TracePath.from_steps, (tuple(self),))


@dataclass(frozen=True)
class TraceFrontier:
    """A bounded backward-slice state that can be retried with a larger budget."""

    root_request: str
    sink_site: str | None
    method: str
    register: int
    before: int
    purpose: str
    phase: str
    reason: str
    depth: int


@dataclass(frozen=True)
class Origin:
    kind: str
    api: str | None = None
    field: str | None = None
    key: str | None = None
    value: Any = None
    component: str | None = None
    method: str | None = None
    offset: int | None = None
    path: TracePath = dc_field(default_factory=TracePath)
    outer_field: str | None = None
    outer_key: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.path, TracePath):
            object.__setattr__(self, "path", TracePath.from_steps(self.path))

    @property
    def external(self) -> bool:
        return self.kind in {
            "external_intent",
            "external_field",
            "nested_external_intent",
            "uri_parsed_external_intent",
            "external_parameter",
        }

    def with_step(self, step: TraceStep) -> Origin:
        return Origin(
            kind=self.kind,
            api=self.api,
            field=self.field,
            key=self.key,
            value=self.value,
            component=self.component,
            method=self.method,
            offset=self.offset,
            path=self.path.append(step),
            outer_field=self.outer_field,
            outer_key=self.outer_key,
        )


@dataclass(frozen=True)
class IntentFact:
    field: str
    origin: Origin
    key: str | None = None
    setter: str | None = None
    method: str | None = None
    offset: int | None = None


@dataclass
class IntentState:
    object_origins: list[Origin] = field(default_factory=list)
    pinned_object_origins: list[Origin] = field(default_factory=list)
    facts: list[IntentFact] = field(default_factory=list)

    @staticmethod
    def _freeze(value: Any) -> Any:
        if isinstance(value, dict):
            items = [
                (IntentState._freeze(key), IntentState._freeze(item))
                for key, item in value.items()
            ]
            return tuple(sorted(items, key=repr))
        if isinstance(value, (list, tuple)):
            return tuple(IntentState._freeze(item) for item in value)
        if isinstance(value, set):
            return frozenset(IntentState._freeze(item) for item in value)
        try:
            hash(value)
        except TypeError:
            return repr(value)
        return value

    @classmethod
    def _origin_key(cls, origin: Origin) -> tuple[Any, ...]:
        return (
            origin.kind,
            origin.api,
            origin.field,
            origin.key,
            cls._freeze(origin.value),
            origin.component,
            origin.method,
            origin.offset,
            origin.outer_field,
            origin.outer_key,
        )

    @staticmethod
    def _origin_score(origin: Origin) -> tuple[int, int]:
        return (sum(step.direct is False for step in origin.path), len(origin.path))

    def _origin_index(self) -> dict[tuple[Any, ...], int]:
        stamp = (id(self.object_origins), len(self.object_origins))
        if getattr(self, "_object_origin_stamp", None) != stamp:
            self._object_origin_index = {
                self._origin_key(origin): index
                for index, origin in enumerate(self.object_origins)
            }
            self._object_origin_stamp = stamp
        return self._object_origin_index

    def _fact_index(self) -> dict[tuple[Any, ...], int]:
        stamp = (id(self.facts), len(self.facts))
        if getattr(self, "_intent_fact_stamp", None) != stamp:
            self._intent_fact_index = {
                (
                    fact.field,
                    fact.key,
                    fact.setter,
                    fact.method,
                    fact.offset,
                    self._origin_key(fact.origin),
                ): index
                for index, fact in enumerate(self.facts)
            }
            self._intent_fact_stamp = stamp
        return self._intent_fact_index

    def add_origin(self, origin: Origin) -> None:
        key = self._origin_key(origin)
        index = self._origin_index().get(key)
        if index is None:
            self.object_origins.append(origin)
            self._object_origin_index[key] = len(self.object_origins) - 1
            self._object_origin_stamp = (id(self.object_origins), len(self.object_origins))
        elif self._origin_score(origin) < self._origin_score(self.object_origins[index]):
            self.object_origins[index] = origin

    def add_origins(self, origins: Any) -> None:
        for origin in origins:
            self.add_origin(origin)

    def add_pinned_origin(self, origin: Origin) -> None:
        """Record a whole-Intent origin whose destination fields cannot reach the dispatch."""
        key = self._origin_key(origin)
        for index, existing in enumerate(self.pinned_object_origins):
            if self._origin_key(existing) != key:
                continue
            if self._origin_score(origin) < self._origin_score(existing):
                self.pinned_object_origins[index] = origin
            return
        self.pinned_object_origins.append(origin)

    def add_pinned_origins(self, origins: Any) -> None:
        """Record several destination-pinned whole-Intent origins."""
        for origin in origins:
            self.add_pinned_origin(origin)

    def pinned_only_origins(self) -> list[Origin]:
        """Return pinned origins not also reaching the dispatch through an unpinned path."""
        unpinned = self._origin_index()
        return [
            origin
            for origin in self.pinned_object_origins
            if self._origin_key(origin) not in unpinned
        ]

    def add_fact(self, fact: IntentFact) -> None:
        key = (
            fact.field,
            fact.key,
            fact.setter,
            fact.method,
            fact.offset,
            self._origin_key(fact.origin),
        )
        index = self._fact_index().get(key)
        if index is None:
            self.facts.append(fact)
            self._intent_fact_index[key] = len(self.facts) - 1
            self._intent_fact_stamp = (id(self.facts), len(self.facts))
        elif self._origin_score(fact.origin) < self._origin_score(self.facts[index].origin):
            self.facts[index] = fact

    def add_facts(self, facts: Any) -> None:
        for fact in facts:
            self.add_fact(fact)

    def extend(self, other: IntentState) -> None:
        self.add_origins(other.object_origins)
        self.add_facts(other.facts)
        self.add_pinned_origins(other.pinned_object_origins)

    def values(self, name: str) -> list[IntentFact]:
        return [fact for fact in self.facts if fact.field == name]

    def external_values(self, *names: str) -> list[IntentFact]:
        selected = set(names)
        return [fact for fact in self.facts if fact.field in selected and fact.origin.external]


@dataclass(frozen=True)
class SinkSite:
    rule_id: str
    category: str
    method: MethodRef
    instruction_index: int
    offset: int
    api: str
    api_name: str
    argument_registers: tuple[int, ...]

    @property
    def site_id(self) -> str:
        return f"{self.method.display()}@0x{self.offset:04x}:{self.rule_id}"


@dataclass(frozen=True)
class CallSite:
    caller: MethodRef
    callee: MethodRef
    instruction_index: int
    offset: int


@dataclass(frozen=True)
class ICCValueObservation:
    """An observed write/origin, not proof of the value delivered at dispatch."""

    target_field: str
    origin: Origin
    setter: str | None = None
    method: str | None = None
    offset: int | None = None


@dataclass(frozen=True)
class ICCEdge:
    source_site: str
    source_component: str | None
    dispatch_api: str
    target_component: str | None
    target_callback_nodes: tuple[str, ...]
    resolution: str
    reason: str
    carried_fields: tuple[str, ...] = ()
    value_observations: tuple[ICCValueObservation, ...] = ()


class UseRole(str, Enum):
    INVOCATION = "invocation"
    DESTINATION = "destination"
    CONTROL = "control"
    PAYLOAD = "payload"
    SENSITIVE_ARGUMENT = "sensitive_argument"
    WHOLE_INTENT = "whole_intent"


@dataclass(frozen=True)
class EvidenceSource:
    origin: Origin
    role: UseRole
    attacker_controlled: bool
    entry_reachability: str = "unconfirmed"
    entry_transfer_evidence: tuple[dict[str, Any], ...] = ()
    control_branch_evidence: tuple[dict[str, Any], ...] = ()
    route_guards: tuple[str, ...] = ()
    route_guard_assessments: tuple[dict[str, Any], ...] = ()
    route_guard_coverage: tuple[dict[str, Any], ...] = ()
    spoofing_conditions: dict[str, Any] | None = None


@dataclass(frozen=True)
class FlowNode:
    component: str
    method: str | None
    role: str
    provenance: str | None = None


@dataclass
class FlowEvidence:
    flow_id: str
    entry_point: EntryPoint
    sources: list[EvidenceSource]
    sink: SinkSite
    sink_component: str | None
    nodes: list[FlowNode]
    icc_edges: list[ICCEdge]
    guards: list[str] = field(default_factory=list)
    guard_assessments: list[dict[str, Any]] = field(default_factory=list)


def serializable(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, TracePath):
        return [serializable(item) for item in value]
    if is_dataclass(value) and not isinstance(value, type):
        result = {
            item.name: serializable(getattr(value, item.name))
            for item in fields(value)
        }
        if isinstance(value, Origin):
            result["external"] = value.external
        return result
    if isinstance(value, dict):
        return {str(key): serializable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [serializable(item) for item in value]
    return value
