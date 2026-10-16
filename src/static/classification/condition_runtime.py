from __future__ import annotations

"""Symbolic execution state and transfer models."""

from dataclasses import dataclass, field

from src.static.classification.branch_predicates import combine, compare, constant, unknown
from src.static.model.values import MethodRef
from src.static.search.dex_ir import parse_method_reference


OBJECT = "Ljava/lang/Object;"


def reference_type(value):
    """Read a known reference descriptor while retaining exact allocation types."""
    kind = value.get("type") or value.get("owner") or "?"
    return kind if kind.startswith(("L", "[")) else None


def nonnull_reference(value):
    """Use only allocation, current receiver or explicitly certified non-null facts."""
    return bool(value.get("op") == "object" and value.get("id")
                or value.get("op") == "entry_this" and value.get("owner")
                or value.get("op") in {"intent", "bundle", "framework_object"} and value.get("known_nonnull")
                or value.get("op") == "const" and value.get("type") == "Ljava/lang/String;"
                and isinstance(value.get("value"), str))


def reference_assignable(actual, expected, backend=None):
    """Prove widening from descriptors or recorded ancestry; missing edges prove nothing."""
    if not actual or not expected or not actual.startswith(("L", "[")) or not expected.startswith(("L", "[")):
        return False
    return (actual == expected or expected == OBJECT
            or bool(backend and getattr(backend, "is_subtype", lambda *_: False)(actual, expected)))


def complete_ancestors(kind, backend):
    """Return closed local ancestry only when every superclass/interface is available."""
    hierarchy = getattr(backend, "direct_supertypes", {})
    pending, seen = [kind], set()
    while pending:
        current = pending.pop()
        if current in seen:
            continue
        if len(seen) >= 64 or current != OBJECT and current not in hierarchy:
            return None
        seen.add(current)
        if current != OBJECT:
            pending.extend(hierarchy[current])
    return seen


def instance_of(value, expected, backend, label):
    """Evaluate DEX instance-of only from null, assignability or closed exact ancestry."""
    if value.get("op") == "const" and value.get("value") in (None, 0):
        return constant(False, "Z")
    actual = reference_type(value)
    if reference_assignable(actual, expected, backend):
        return constant(True, "Z") if nonnull_reference(value) else compare("ne", value, constant(None, actual))
    if value.get("op") == "object" and actual and expected:
        ancestors = complete_ancestors(actual, backend)
        if ancestors is not None and expected not in ancestors:
            return constant(False, "Z")
    return unknown("instance-of at " + label, "Z", value.get("control", "unknown"))





def object_id(value):
    """Identify singleton allocations or the current component, never opaque aliases."""
    if value and value.get("op") == "object":
        return value["id"]
    if value and value.get("op") == "entry_this":
        return "entry:" + value["owner"]
    return None


def escaped_identity(value):
    """Name an escaped heap or container handle without asserting pointer inequality."""
    if value and value.get("op") in {"intent", "bundle"}:
        return value.get("container_id") or value["id"] + ":" + repr(value.get("key_path", []))
    return object_id(value)


@dataclass
class ConditionMemory:
    fields: dict = field(default_factory=dict)
    escaped: set = field(default_factory=set)
    dependencies: list = field(default_factory=list)
    epoch: int = 0
    allocations: int = 0
    invalidated_intents: set = field(default_factory=set)
    initialized_classes: set = field(default_factory=set)
    containers: dict = field(default_factory=dict)
    allocations_by_site: dict = field(default_factory=dict)

    def fork(self):
        """Keep heap facts and dependency evidence separate for each CFG alternative."""
        return ConditionMemory(dict(self.fields), set(self.escaped), list(self.dependencies), self.epoch, self.allocations,
                               set(self.invalidated_intents), set(self.initialized_classes),
                               {k: {**v, "values": dict(v["values"])} for k, v in self.containers.items()},
                               dict(self.allocations_by_site))

    def touch_class(self, owner):
        """Forget shared facts on first class use because its initializer was not replayed."""
        if owner and owner not in self.initialized_classes:
            self.havoc()
            self.initialized_classes.add(owner)

    def allocate(self, label, kind):
        """Create a distinct identity for every allocation executed on this path."""
        self.allocations += 1
        value = {"op": "object", "id": f"{label}#{self.allocations}", "type": kind}
        # Multiple executions of an allocation site cannot be collapsed to a singleton.
        self.allocations_by_site[label] = value if label not in self.allocations_by_site else None
        return value

    def record(self, evidence):
        """Bound diagnostic evidence without interpreting omitted entries as resolved."""
        if len(self.dependencies) < 32 and evidence not in self.dependencies:
            self.dependencies.append(evidence)

    def write(self, reference, base, value, kind, site, *, static=False, backend=None):
        """Strong-update a known object and invalidate may-alias writes conservatively."""
        identity = "static" if static else object_id(base)
        self.epoch += 1
        if identity is None:
            self.fields = {k: v for k, v in self.fields.items() if k[1] != reference}
            # The value can escape through an object whose identity is unavailable.
            self.escape(value)
            return
        if kind == "Z" and value.get("op") == "const" and type(value.get("value")) in {int, bool} and value["value"] in (0, 1):
            value = constant(bool(value["value"]), "Z")
        elif kind.startswith(("L", "[")) and value.get("op") == "const" and value.get("value") in (None, 0):
            value = constant(None, kind)
        elif reference_assignable(reference_type(value), kind, backend):
            # Widening does not change the object, its runtime type or its provenance.
            pass
        elif value.get("type") != kind:
            # Narrowing, wide overlap and invalid typed values are not guessed.
            value = unknown(f"unmodeled field conversion at {site['method']}@{site['offset']}", kind)
        if identity == "static" or identity.startswith("entry:") or identity in self.escaped:
            self.escape(value)
        if len(self.fields) < 128 or (identity, reference) in self.fields:
            self.fields[(identity, reference)] = {"value": value, "write": site}

    def escape(self, value):
        """Mark the reachable known object graph shared with code outside this path."""
        if value and value.get("op") in {"intent", "bundle"}:
            self.invalidated_intents.add(value["id"])
        pending = [escaped_identity(value)]
        while pending:
            identity = pending.pop()
            if identity is None or identity in self.escaped:
                continue
            self.escaped.add(identity)
            for (owner, _), stored in self.fields.items():
                if owner == identity:
                    child = stored["value"]
                    if child.get("op") in {"intent", "bundle"}:
                        self.invalidated_intents.add(child["id"])
                    pending.append(escaped_identity(child))
            for child in self.containers.get(identity, {}).get("values", {}).values():
                if child.get("op") in {"intent", "bundle"}:
                    self.invalidated_intents.add(child["id"])
                pending.append(escaped_identity(child))

    def havoc(self, values=(), *, all_fields=False):
        """Forget side effects of opaque calls, including escaped objects and static state."""
        for value in values:
            self.escape(value)
        self.epoch += 1
        self.fields = {} if all_fields else {
            k: v for k, v in self.fields.items()
            if k[0] != "static" and not k[0].startswith("entry:") and k[0] not in self.escaped
        }
        for identity, container in self.containers.items():
            if all_fields or identity in self.escaped or container.get("source_id") in self.invalidated_intents:
                container.update(values={}, unknown=True)




class ConditionAliases:
    def __init__(self, backend):
        """Reuse CFG reaching definitions and keep bounded query diagnostics."""
        self.backend = backend
        self.statistics = {"queries": 0, "resolved": 0, "unknown": 0}

    def resolve(self, method, register, before, state, entry_bindings, spend):
        """Recover only a singleton identity shared by every reaching definition."""
        self.statistics["queries"] += 1
        remaining = [24]
        steps = []

        def visit(reg, index, seen):
            """Follow copies and casts backwards to a bound argument or live allocation."""
            if (reg, index) in seen or remaining[0] <= 0 or not spend():
                return None
            remaining[0] -= 1
            definitions = self.backend.cfg_for(method).reaching_definitions(reg, index)
            values = [entry_bindings.get(reg)] if definitions.reaches_entry else []
            for position in definitions.instruction_indices:
                instruction = method.instructions[position]
                steps.append({"method": method.display(), "offset": instruction.offset, "register": reg})
                if instruction.name == "new-instance":
                    values.append(state.memory.allocations_by_site.get(f"{method.display()}@{instruction.offset}"))
                elif instruction.name.startswith("move") and not instruction.name.startswith(("move-result", "move-exception")) and len(instruction.registers) == 2:
                    values.append(visit(instruction.registers[1], position, seen | {(reg, index)}))
                elif instruction.name == "check-cast":
                    values.append(visit(reg, position, seen | {(reg, index)}))
                else:
                    return None
            if not values or any(not object_id(value) for value in values):
                return None
            return values[0] if all(object_id(value) == object_id(values[0]) for value in values) else None

        value = visit(register, before, set())
        self.statistics["resolved" if value is not None else "unknown"] += 1
        return value, {"kind": "demand_allocation_query", "resolved": value is not None,
                       "allocation_id": object_id(value), "definition_sites": steps[:24]}


INTENT = "Landroid/content/Intent;"
BUNDLE = "Landroid/os/Bundle;"
STRING = "Ljava/lang/String;"


def container_key(value):
    """Identify a container handle without claiming distinct incoming Bundles cannot alias."""
    if not value:
        return None
    if value.get("op") in {"intent", "bundle"}:
        return value.get("container_id") or (value["id"] + ":" + repr(value.get("key_path", [])))
    return object_id(value) if value.get("type") in {INTENT, BUNDLE} else None


def container(state, value):
    """Create a symbolic incoming container or reuse a constructed object's properties."""
    key = container_key(value)
    if key is None:
        return None
    if key not in state.memory.containers:
        if len(state.memory.containers) >= 64:
            return None
        external = value.get("op") in {"intent", "bundle"}
        state.memory.containers[key] = {
            "values": {}, "external": external, "unknown": not external,
            "source_id": value.get("id") if external else None,
            "key_path": list(value.get("key_path", [])), "kind": value.get("type"),
            "extras_allocated": False,
            "isolated_properties": not external,
        }
    return state.memory.containers[key]


def required_presence(value):
    """Require each enclosing incoming Bundle to exist with the expected type."""
    path = value.get("key_path", [])
    result = [{"op": "input", "field": "bundle_present", "key": key, "key_path": path[:i],
               "intent_id": value["id"], "type": "Z", "control": "external_intent"}
              for i, key in enumerate(path)] if value.get("op") == "bundle" else []
    if value.get("requires_extras"):
        result.append({"op": "input", "field": "extras_present", "key": None,
                       "intent_id": value["id"], "type": "Z", "control": "external_intent"})
    return result


def read_property(record, field, key, kind, default=None):
    """Read a stored property or a typed incoming getter with its actual default."""
    slot = (field, key)
    if slot in record["values"]:
        value = record["values"][slot]
        if value.get("op") == "absent":
            return default if default is not None else constant(None, kind)
        if value.get("type") == kind:
            return value
        return default if default is not None else constant(None, kind)
    if record["unknown"]:
        return unknown("container property may have changed", kind)
    if not record["external"]:
        return default if default is not None else constant(None, kind)
    value = {"op": "input", "field": field, "key": key, "type": kind,
             "intent_id": record["source_id"], "control": "external_intent"}
    if record["key_path"]:
        value["key_path"] = record["key_path"]
    if default is not None:
        value["default"] = default
    return value


def model_container(owner, name, descriptor, args, state, label, backend=None):
    """Apply exact supported SDK transfers; return None for unmodeled APIs."""
    if owner not in {INTENT, BUNDLE} or not args:
        return None
    receiver, kind = args[0], descriptor.split(")")[-1]
    record = container(state, receiver)
    if record is None:
        return None
    if record.get("source_id") in state.memory.invalidated_intents:
        record.update(values={}, unknown=True)
    if owner == BUNDLE and name in {"putParcelable", "getParcelable"}:
        parcelable = "Landroid/os/Parcelable;"
        signatures = {"putParcelable": "(Ljava/lang/String;Landroid/os/Parcelable;)V",
                      "getParcelable": "(Ljava/lang/String;)Landroid/os/Parcelable;"}
        if descriptor != signatures[name] or len(args) < 2:
            return None
        key = args[1].get("value") if args[1].get("op") == "const" else None
        if not isinstance(key, str):
            return None
        if name == "putParcelable" and len(args) == 3 and not record["external"]:
            value = constant(None, parcelable) if args[2] == constant(0) else args[2]
            actual = value.get("type", "?")
            assignable = (actual == parcelable or value.get("op") == "const" and value.get("value") is None
                          or backend is not None and getattr(backend, "is_subtype", lambda *_: False)(actual, parcelable))
            if not assignable:
                return None
            record["values"][("extra", key)] = value
            return constant(None, "V")
        if name == "getParcelable" and not record["unknown"] and not record["external"]:
            value = record["values"].get(("extra", key))
            if value is not None:
                actual = value.get("type", "?")
                if (actual == parcelable or value.get("op") == "const" and value.get("value") is None
                        or backend is not None and getattr(backend, "is_subtype", lambda *_: False)(actual, parcelable)):
                    return value
            return constant(None, parcelable)
        return None
    if name == "<init>":
        if descriptor == "()V":
            record.update(external=False, unknown=False, values={})
        elif descriptor == "(Ljava/lang/String;)V" and owner == INTENT:
            record.update(external=False, unknown=False, values={("action", None): args[1]})
        elif descriptor == f"({owner})V" and len(args) == 2:
            source = container(state, args[1])
            if source is None:
                return None
            record.update({**source, "values": dict(source["values"]), "isolated_properties": True})
        else:
            return None
        return constant(None, "V")
    fields = {"getAction": "action", "getDataString": "data", "getType": "mime_type"}
    if owner == INTENT and name in fields and descriptor == "()Ljava/lang/String;":
        return read_property(record, fields[name], None, STRING)
    if owner == INTENT and name == "setAction" and descriptor == "(Ljava/lang/String;)Landroid/content/Intent;":
        value = constant(None, STRING) if args[1] == constant(0) else args[1]
        record["values"][("action", None)] = value
        return receiver
    getters = {"getIntExtra": "I", "getBooleanExtra": "Z", "getStringExtra": STRING,
               "getLongExtra": "J", "getInt": "I", "getBoolean": "Z", "getString": STRING, "getLong": "J"}
    if name in getters and kind == getters[name] and descriptor.startswith("(Ljava/lang/String;"):
        key = args[1].get("value") if len(args) > 1 and args[1].get("op") == "const" else None
        if not isinstance(key, str):
            return unknown("dynamic container key at " + label, kind)
        default = args[2] if len(args) > 2 else constant(False, "Z") if kind == "Z" else constant(0, kind) if kind in {"I", "J"} else None
        if kind == "Z" and default and default.get("op") == "const" and default.get("value") in (0, 1):
            default = constant(bool(default["value"]), "Z")
        return read_property(record, "extra", key, kind, default)
    if name in {"hasExtra", "containsKey"} and descriptor == "(Ljava/lang/String;)Z":
        key = args[1].get("value") if len(args) > 1 and args[1].get("op") == "const" else None
        if not isinstance(key, str):
            return unknown("dynamic presence key", "Z")
        stored = record["values"].get(("extra", key))
        if stored is not None:
            return constant(stored.get("op") != "absent", "Z")
        if record["unknown"]:
            return unknown("container presence may have changed", "Z")
        if not record["external"]:
            return constant(False, "Z")
        return {"op": "input", "field": "has_extra", "key": key, "key_path": record["key_path"],
                "intent_id": record["source_id"], "type": "Z", "control": "external_intent"}
    writes = {"putExtra", "putInt", "putBoolean", "putString", "putLong", "putBundle", "removeExtra", "remove"}
    if name in writes and descriptor.startswith("(Ljava/lang/String;"):
        key = args[1].get("value") if len(args) > 1 and args[1].get("op") == "const" else None
        if not isinstance(key, str):
            record.update(unknown=True, values={})
            return receiver if kind == INTENT else constant(None, "V")
        if name in {"removeExtra", "remove"}:
            value = {"op": "absent", "type": "?"}
        elif len(args) >= 3:
            declared = descriptor.split("Ljava/lang/String;", 1)[1].split(")")[0]
            if declared not in {"I", "Z", "J", STRING, BUNDLE}:
                return None
            value = args[2]
            if declared == "Z" and value.get("op") == "const" and value.get("value") in (0, 1):
                value = constant(bool(value["value"]), "Z")
            elif declared == "Z" and value.get("type") == "I":
                value = compare("ne", value, constant(0))
            elif declared.startswith("L") and value == constant(0):
                value = constant(None, declared)
            elif value.get("type") != declared:
                value = unknown("unresolved typed container assignment", declared)
        else:
            return None
        if record["external"] and owner == BUNDLE and not record.get("isolated_properties"):
            # Different incoming Bundle paths may alias. Invalidate their old views.
            state.memory.invalidated_intents.add(record["source_id"])
            for other in state.memory.containers.values():
                if other.get("source_id") == record["source_id"]:
                    other.update(unknown=True, values={})
            record.update(external=False, source_id=None)
        record["values"][("extra", key)] = value
        if name not in {"removeExtra", "remove"}:
            record["extras_allocated"] = True
        return receiver if kind == INTENT else constant(None, "V")
    if name in {"getBundleExtra", "getBundle"} and descriptor == "(Ljava/lang/String;)Landroid/os/Bundle;":
        key = args[1].get("value") if len(args) > 1 and args[1].get("op") == "const" else None
        if not isinstance(key, str):
            return unknown("dynamic Bundle key", BUNDLE)
        slot = ("extra", key)
        if slot in record["values"]:
            return read_property(record, "extra", key, BUNDLE)
        if record["unknown"] or not record["external"]:
            return unknown("unresolved Bundle", BUNDLE) if record["unknown"] else constant(None, BUNDLE)
        return {"op": "bundle", "id": record["source_id"], "key_path": [*record["key_path"], key], "type": BUNDLE}
    if owner == INTENT and name == "getExtras" and descriptor == "()Landroid/os/Bundle;":
        if not record["unknown"] and not record["external"] and not record["extras_allocated"]:
            return constant(None, BUNDLE)
        if len(state.memory.containers) >= 64:
            return unknown("container object limit", BUNDLE)
        # Intent.getExtras returns a shallow Bundle copy, not a mutable view of Intent.
        state.memory.allocations += 1
        identity = f"extras-copy:{label}#{state.memory.allocations}"
        value = {"op": "bundle", "id": record.get("source_id") or identity, "key_path": [],
                 "container_id": identity, "type": BUNDLE, "requires_extras": record["external"] and not record["extras_allocated"],
                 "known_nonnull": record["extras_allocated"] and not record["unknown"]}
        state.memory.containers[identity] = {**record, "kind": BUNDLE,
                                           "values": {k: v for k, v in record["values"].items() if k[0] == "extra"},
                                           "isolated_properties": True}
        return value
    return None


TEXT = "Landroid/widget/TextView;"
BUTTON = "Landroid/widget/Button;"
STRING = "Ljava/lang/String;"
BUNDLE = "Landroid/os/Bundle;"
FRAGMENTS = {"Landroid/app/Fragment;", "Landroidx/fragment/app/Fragment;", "Landroid/support/v4/app/Fragment;"}
TEXT_VALUE = "framework:text"
TEXT_SAFE = "framework:text_untransformed"
TEXT_FRESH = "framework:text_default_factories"
TEXT_NO_KEY = "framework:text_no_key_listener"
ARRAY_LENGTH = "framework:array_length"
BUFFER_TYPE = "Landroid/widget/TextView$BufferType;"
FRAGMENT_ARGS = "framework:fragment_arguments"
FRAGMENT_HOST = "framework:fragment_host"


def load_property(state, receiver, slot):
    """Read an executed write for this exact object, including intervening invalidation."""
    identity = object_id(receiver)
    record = state.memory.fields.get((identity, slot)) if identity else None
    return record["value"] if record else None


def store_property(state, receiver, slot, value, label):
    """Store a synthetic framework field in the existing alias-aware path memory."""
    identity = object_id(receiver)
    if identity is None:
        state.memory.havoc([receiver, value])
        return False
    key = (identity, slot)
    state.memory.epoch += 1
    if len(state.memory.fields) >= 128 and key not in state.memory.fields:
        return False
    state.memory.fields[key] = {"value": value, "write": {"method": label, "offset": None}}
    if identity in state.memory.escaped:
        state.memory.escape(value)
    return True


def resolve_receiver_method(backend, value, name, descriptor):
    """Resolve a concrete allocation/current component through its class superclass chain."""
    if not value or value.get("op") not in {"object", "entry_this"}:
        return None
    owner = value.get("type") or value.get("owner")
    seen = set()
    while owner and owner not in seen and len(seen) < 32:
        seen.add(owner)
        method = backend.methods.get(MethodRef(owner, name, descriptor))
        if method is not None and "abstract" not in method.access.split():
            return method
        parents = getattr(backend, "direct_supertypes", {}).get(owner, ())
        # Interfaces may have unrelated defaults. Do not choose one arbitrarily.
        classes = [p for p in parents if "interface" not in getattr(backend, "class_access", {}).get(p, ())]
        if len(classes) != 1:
            return None
        owner = classes[0]
    return None


def framework_transfer(backend, method, call, state, args):
    """Apply only exact supported SDK signatures and same-path object properties."""
    parsed = parse_method_reference(call.reference)
    if parsed is None or not args or call.name.startswith("invoke-static"):
        return None
    owner, name, descriptor = parsed
    receiver = args[0]
    runtime = receiver.get("type")
    label = f"{method.display()}@{call.offset}"
    result_type = descriptor.split(")")[-1]
    if not object_id(receiver):
        return None
    # Restrict widget summaries to concrete framework widgets: application overrides,
    # editable buffers, filters and text watchers need their own effect model.
    widget = runtime in {TEXT, BUTTON}
    if widget and owner in {TEXT, BUTTON}:
        if name == "<init>" and descriptor in {"(Landroid/content/Context;)V", "(Landroid/content/Context;Landroid/util/AttributeSet;)V"}:
            if runtime in {TEXT, BUTTON}:
                # Context-only constructors also read textViewStyle: filters, key
                # listeners and buffer type cannot be inferred from that constructor.
                store_property(state, receiver, TEXT_FRESH, constant(True, "Z"), label)
                store_property(state, receiver, TEXT_SAFE, constant(False, "Z"), label)
            return constant(None, "V"), "framework_widget_constructor"
        if runtime in {TEXT, BUTTON} and name == "setFilters" and descriptor == "([Landroid/text/InputFilter;)V" and len(args) == 2:
            if (args[1].get("type") == "[Landroid/text/InputFilter;"
                    and load_property(state, args[1], ARRAY_LENGTH) == constant(0)
                    and load_property(state, receiver, TEXT_FRESH) == constant(True, "Z")):
                store_property(state, receiver, TEXT_SAFE, constant(True, "Z"), label)
                return constant(None, "V"), "framework_empty_text_filters"
        if runtime in {TEXT, BUTTON} and name == "setKeyListener" and descriptor == "(Landroid/text/method/KeyListener;)V" and len(args) == 2:
            if (args[1] == constant(0) or args[1].get("op") == "const" and args[1].get("value") is None
                    ) and load_property(state, receiver, TEXT_FRESH) == constant(True, "Z"):
                store_property(state, receiver, TEXT_NO_KEY, constant(True, "Z"), label)
                return constant(None, "V"), "framework_clear_key_listener"
        if name in {"setFilters", "addTextChangedListener", "setTransformationMethod", "setInputType", "setKeyListener", "setTextFactory", "setEditableFactory", "setSpannableFactory"}:
            store_property(state, receiver, TEXT_SAFE, constant(False, "Z"), label)
            store_property(state, receiver, TEXT_FRESH, constant(False, "Z"), label)
            state.memory.fields.pop((object_id(receiver), TEXT_VALUE), None)
            return None
        if runtime in {TEXT, BUTTON} and name == "setText" and descriptor == f"(Ljava/lang/CharSequence;{BUFFER_TYPE})V" and len(args) == 3:
            value = args[1]
            if (load_property(state, receiver, TEXT_SAFE) != constant(True, "Z")
                    or load_property(state, receiver, TEXT_NO_KEY) != constant(True, "Z")
                    or args[2] != {"op": "framework_enum", "type": BUFFER_TYPE, "value": "NORMAL"}):
                return None
            if value == constant(0) or value.get("op") == "const" and value.get("value") is None:
                value = constant("", STRING)
            if value.get("type") != STRING:
                return None
            if value.get("op") != "const":
                value = {"op": "str_null_to_empty", "args": [value], "type": STRING}
            store_property(state, receiver, TEXT_VALUE, value, label)
            return constant(None, "V"), "framework_text_write"
        if runtime in {TEXT, BUTTON} and name == "getText" and descriptor == "()Ljava/lang/CharSequence;":
            value = load_property(state, receiver, TEXT_VALUE)
            safe = load_property(state, receiver, TEXT_SAFE) == constant(True, "Z")
            return (value if safe and value is not None else unknown("widget text not replayed at " + label, result_type, "app_state")), "framework_text_read"
    if owner in FRAGMENTS:
        # A declared Fragment API still needs a compatible concrete receiver.
        if runtime not in FRAGMENTS and not getattr(backend, "is_subtype", lambda *_: False)(runtime, owner):
            return None
        implementation = resolve_receiver_method(backend, receiver, name, descriptor)
        if runtime not in FRAGMENTS and (implementation is None or implementation.method.class_name not in FRAGMENTS):
            # Missing superclass bodies or an application override are not SDK summaries.
            return None
        if name == "setArguments" and descriptor == "(Landroid/os/Bundle;)V" and len(args) == 2:
            value = constant(None, BUNDLE) if args[1] == constant(0) else args[1]
            store_property(state, receiver, FRAGMENT_ARGS, value, label)
            return constant(None, "V"), "framework_fragment_arguments_write"
        if name == "getArguments" and descriptor == "()Landroid/os/Bundle;":
            value = load_property(state, receiver, FRAGMENT_ARGS)
            return (value if value is not None else unknown("Fragment arguments not replayed at " + label, BUNDLE)), "framework_fragment_arguments_read"
        host_signatures = {("getContext", "()Landroid/content/Context;"),
                           ("getActivity", "()Landroid/app/Activity;"),
                           ("getActivity", "()Landroidx/fragment/app/FragmentActivity;"),
                           ("getActivity", "()Landroid/support/v4/app/FragmentActivity;")}
        if (name, descriptor) in host_signatures:
            value = load_property(state, receiver, FRAGMENT_HOST)
            return (value if value is not None else unknown("Fragment host not replayed at " + label, result_type)), "framework_fragment_host_read"
    return None



STRING = "Ljava/lang/String;"
INTEGER = "Ljava/lang/Integer;"
NUMBER = "Ljava/lang/Number;"



def library_summary(owner, name, descriptor, args):
    """Preserve Integer payloads without assuming arbitrary Number subclasses are exact."""
    if (owner, name, descriptor) == (INTEGER, "valueOf", "(I)Ljava/lang/Integer;"):
        if len(args) != 1 or args[0].get("type") != "I":
            return None
        # Integer.valueOf may return a cached object. This term carries a value
        # and a normal-return non-null fact, deliberately not object identity.
        return {"op": "boxed_integer", "type": INTEGER, "args": [args[0]]}, []
    if owner in {INTEGER, NUMBER} and (name, descriptor) == ("intValue", "()I"):
        if len(args) != 1:
            return None
        receiver = args[0]
        is_null = receiver.get("value") is None and receiver.get("type", "").startswith(("L", "["))
        is_dex_zero = (receiver.get("type") == "I" and type(receiver.get("value")) is int
                       and receiver["value"] == 0)
        if receiver.get("op") == "const" and (is_null or is_dex_zero):
            return unknown("null receiver cannot return from Number.intValue", "I"), [constant(False, "Z")]
        payload = receiver.get("args", [])
        if (receiver.get("op") == "boxed_integer" and receiver.get("type") == INTEGER
                and len(payload) == 1 and payload[0].get("type") == "I"):
            return payload[0], []
        # Even a receiver declared Number or Integer needs a proven payload;
        # user-defined Number.intValue methods may compute unrelated values.
        return None
    return string_summary(owner, name, descriptor, args)


def string_summary(owner, name, descriptor, args):
    """Return a value and necessary normal-return predicates for supported string APIs."""
    if owner == "Landroid/text/TextUtils;" and name == "isEmpty" and descriptor == "(Ljava/lang/CharSequence;)Z" and args:
        value = args[0]
        if value == constant(0):
            value = constant(None, STRING)
        if value.get("type") != STRING:
            return None
        length = {"op": "str_length", "args": [value], "type": "I"}
        return combine("or", [compare("eq", value, constant(None, STRING)), compare("eq", length, constant(0))]), []
    if owner != STRING or not args:
        return None
    receiver = args[0]
    nonnull = compare("ne", receiver, constant(None, STRING))
    if name == "hashCode" and descriptor == "()I":
        return {"op": "str_hash32", "args": [receiver], "type": "I"}, [nonnull]
    if name == "length" and descriptor == "()I":
        return {"op": "str_length", "args": [receiver], "type": "I"}, [nonnull]
    if name == "isEmpty" and descriptor == "()Z":
        return compare("eq", {"op": "str_length", "args": [receiver], "type": "I"}, constant(0)), [nonnull]
    methods = {("startsWith", "(Ljava/lang/String;)Z"): "str_prefix",
               ("endsWith", "(Ljava/lang/String;)Z"): "str_suffix",
               ("contains", "(Ljava/lang/CharSequence;)Z"): "str_contains"}
    op = methods.get((name, descriptor))
    if op and len(args) == 2 and args[1].get("type") == STRING:
        return {"op": op, "args": args, "type": "Z"}, [nonnull, compare("ne", args[1], constant(None, STRING))]
    return None

