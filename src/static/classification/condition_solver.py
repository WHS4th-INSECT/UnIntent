from __future__ import annotations

"""Translation and bounded SMT solving for path conditions."""

import json
import operator
import time
from src.static.classification.branch_predicates import Expr, constant, marker
from src.static.classification.condition_runtime import nonnull_reference, required_presence


class UnsupportedTerm(ValueError):
    """A term cannot be translated with the currently modeled Java semantics."""


class ConditionTerms:
    def __init__(self, z3, context):
        """Keep one query's canonical inputs, nullability, type tags and abstraction log."""
        self.z3, self.context = z3, context
        self.symbols, self.inputs, self.constraints, self.abstracted = {}, {}, [], []
        self.seq_sort = z3.SeqSort(z3.BitVecSort(16, ctx=context))

    def symbol(self, key, kind):
        """Share a symbol by input property rather than by getter default or call site."""
        if key not in self.symbols:
            if len(self.symbols) >= 256:
                raise UnsupportedTerm("variable_limit")
            name = "property_" + str(len(self.symbols))
            constructors = {"Z": lambda: self.z3.Bool(name, ctx=self.context),
                            "I": lambda: self.z3.BitVec(name, 32, ctx=self.context),
                            "tag": lambda: self.z3.Int(name, ctx=self.context),
                            "string": lambda: self.z3.Const(name, self.seq_sort)}
            self.symbols[key] = constructors[kind]()
        return self.symbols[key]

    def literal(self, text):
        """Encode Java strings as UTF-16 units so non-BMP length and equality are exact."""
        raw = text.encode("utf-16-le", errors="surrogatepass")
        units = [self.z3.Unit(self.z3.BitVecVal(int.from_bytes(raw[i:i+2], "little"), 16, ctx=self.context))
                 for i in range(0, len(raw), 2)]
        if len(units) > 512:
            raise UnsupportedTerm("string_literal_limit")
        return self.z3.Empty(self.seq_sort) if not units else units[0] if len(units) == 1 else self.z3.Concat(*units)

    def tag(self, root, path):
        """Use one type tag for absent, null, primitive, Bundle and other extra values."""
        key = json.dumps([root, path, "type"], sort_keys=True)
        new = key not in self.symbols
        result = self.symbol(key, "tag")
        if new:
            self.constraints.extend([result >= 0, result <= 7])
        return result

    def input(self, node):
        """Tie action, presence, nested keys, types and getter defaults to one Intent."""
        z = self.z3
        root, field, kind = node.get("intent_id"), node.get("field"), node.get("type")
        if not root or node.get("control") != "external_intent":
            raise UnsupportedTerm("unsupported_input")
        path = [*node.get("key_path", []), node.get("key")]
        if field in {"extra", "has_extra", "bundle_present"} and not isinstance(node.get("key"), str):
            raise UnsupportedTerm("unsupported_key")
        key = json.dumps([root, field if field in {"action", "data", "mime_type"} else "extra", path])
        if field == "has_extra":
            value = self.tag(root, path) != 0
        elif field == "bundle_present":
            value = self.tag(root, path) == 5
        elif field == "extras_present":
            value = self.symbol(json.dumps([root, "extras_present"]), "Z")
        elif field == "extra" and kind in {"I", "Z"}:
            tag = self.tag(root, path)
            raw = self.symbol(key + kind, kind)
            default = node.get("default", {"op": "const", "type": kind, "value": False if kind == "Z" else 0})
            value = z.If(tag == (3 if kind == "I" else 4), raw, self.term(default))
        elif kind == "Ljava/lang/String;" and field in {"extra", "action", "data", "mime_type"}:
            content = self.symbol(key + "text", "string")
            is_null = self.tag(root, path) != 2 if field == "extra" else self.symbol(key + "null", "Z")
            # A Java String's length is a nonnegative signed int.
            self.constraints.append(z.Length(content) <= 2147483647)
            value = (is_null, content)
        else:
            raise UnsupportedTerm("unsupported_input")
        if len(self.inputs) >= 64 and marker(node) not in self.inputs:
            raise UnsupportedTerm("input_limit")
        self.inputs[marker(node)] = (node, value)
        return value

    def term(self, node):
        """Translate supported terms and fail at the containing atom for everything else."""
        z, op, kind = self.z3, node.get("op"), node.get("type")
        if op == "environment" and node.get("field") == "sdk_int" and node.get("control") == "platform" and kind == "I":
            value = self.symbol("environment:Build.VERSION.SDK_INT", "tag")
            self.constraints.extend([value >= max(1, node.get("min_value", 1)), value <= 2147483647])
            self.inputs[marker(node)] = (node, value)
            return value
        if (op == "boxed_integer" and kind == "Ljava/lang/Integer;"
                and len(node.get("args", [])) == 1 and node["args"][0].get("type") == "I"):
            # Normal return from Integer.valueOf is non-null even when its int
            # payload is unknown. Cache identity and reference equality are not
            # represented by this immutable value transfer.
            return (z.BoolVal(False, ctx=self.context), None)
        if op != "const" and nonnull_reference(node):
            return (z.BoolVal(False, ctx=self.context), None)
        if op == "input":
            return self.input(node)
        if op == "bundle":
            presence = required_presence(node)
            if node.get("known_nonnull"):
                return (z.BoolVal(False, ctx=self.context), None)
            if presence:
                return (z.Not(z.And(*[self.term(p) for p in presence])), None)
            raise UnsupportedTerm("bundle_presence_unknown")
        if op == "const":
            value = node.get("value")
            if value is None and kind.startswith(("L", "[")):
                return (z.BoolVal(True, ctx=self.context), None)
            if kind == "Ljava/lang/String;" and isinstance(value, str):
                return (z.BoolVal(False, ctx=self.context), self.literal(value))
            if kind == "Z" and type(value) in {bool, int} and value in (0, 1):
                return z.BoolVal(bool(value), ctx=self.context)
            if kind == "I" and type(value) is int and -(2**31) <= value < 2**31:
                return z.BitVecVal(value, 32, ctx=self.context)
            raise UnsupportedTerm("unsupported_constant")
        if op in {"and", "or", "not"}:
            args = [self.term(a) for a in node["args"]]
            if not args or not all(z.is_bool(a) for a in args):
                raise UnsupportedTerm("boolean_sort_mismatch")
            return z.Not(args[0]) if op == "not" and len(args) == 1 else z.And(*args) if op == "and" else z.Or(*args) if op == "or" else self.fail("operator_arity")
        children = node.get("args", [])
        # Length is already a nonnegative Java int: compare in the sequence theory
        # when the other operand is a signed int constant, avoiding Int2BV search.
        if op in {"eq", "ne", "lt", "le", "gt", "ge"} and len(children) == 2:
            for index in (0, 1):
                length, literal = children[index], children[1-index]
                if (length.get("op") == "str_length" and len(length.get("args", [])) == 1
                        and literal.get("op") == "const" and literal.get("type") == "I"
                        and type(literal.get("value")) is int and -(2**31) <= literal["value"] < 2**31):
                    value = self.term(length["args"][0])
                    if not isinstance(value, tuple) or value[1] is None:
                        raise UnsupportedTerm("string_length_sort")
                    pair = [z.Length(value[1]), z.IntVal(literal["value"], ctx=self.context)]
                    left, right = pair if index == 0 else pair[::-1]
                    return getattr(operator, op)(left, right)
        args = [self.term(a) for a in children]
        if op == "str_null_to_empty" and kind == "Ljava/lang/String;" and len(args) == 1 and isinstance(args[0], tuple):
            is_null, content = args[0]
            if content is None:
                if z.is_true(is_null):
                    return (z.BoolVal(False, ctx=self.context), self.literal(""))
                raise UnsupportedTerm("string_normalization_sort")
            return (z.BoolVal(False, ctx=self.context), z.If(is_null, self.literal(""), content))
        if op == "bool_to_int" and len(args) == 1 and z.is_bool(args[0]):
            return z.If(args[0], z.BitVecVal(1, 32, ctx=self.context), z.BitVecVal(0, 32, ctx=self.context))
        if op == "str_length" and len(args) == 1 and isinstance(args[0], tuple) and args[0][1] is not None:
            return z.Int2BV(z.Length(args[0][1]), 32)
        if op in {"str_prefix", "str_suffix", "str_contains"} and len(args) == 2 and all(isinstance(a, tuple) and a[1] is not None for a in args):
            receiver, other = args
            predicate = {"str_prefix": z.PrefixOf, "str_suffix": z.SuffixOf}.get(op)
            return z.And(z.Not(receiver[0]), z.Not(other[0]), predicate(other[1], receiver[1]) if predicate else z.Contains(receiver[1], other[1]))
        if len(args) != 2:
            raise UnsupportedTerm("unsupported_type_or_value")
        left, right = args
        if op in {"eq", "ne", "lt", "le", "gt", "ge"} and any(z.is_int(a) for a in args):
            converted = [z.IntVal(a.as_signed_long(), ctx=self.context) if z.is_bv_value(a) else a for a in args]
            if all(z.is_int(a) for a in converted):
                return getattr(operator, op)(*converted)
        if op in {"eq", "ne", "ref_eq", "ref_ne"} and all(isinstance(a, tuple) for a in args):
            if left[1] is None and z.is_true(left[0]):
                equal = right[0]
            elif right[1] is None and z.is_true(right[0]):
                equal = left[0]
            elif left[1] is None or right[1] is None:
                raise UnsupportedTerm("object_reference_identity")
            elif op.startswith("ref_"):
                raise UnsupportedTerm("string_reference_identity")
            else:
                equal = z.Or(z.And(left[0], right[0]), z.And(z.Not(left[0]), z.Not(right[0]), left[1] == right[1]))
            return equal if op.endswith("eq") else z.Not(equal)
        ints = all(z.is_bv(a) and a.size() == 32 for a in args)
        bools = all(z.is_bool(a) for a in args)
        if op in {"eq", "ne"} and (ints or bools):
            return left == right if op == "eq" else left != right
        if kind == "Z" and ints and op in {"lt", "le", "gt", "ge"}:
            return {"lt": lambda: left < right, "le": lambda: left <= right,
                    "gt": lambda: left > right, "ge": lambda: left >= right}[op]()
        operations = {"add32": lambda: left + right, "sub32": lambda: left - right,
                      "rsub32": lambda: right - left, "mul32": lambda: left * right,
                      "and32": lambda: left & right, "or32": lambda: left | right,
                      "xor32": lambda: left ^ right, "shl32": lambda: left << (right & 31),
                      "shr32": lambda: left >> (right & 31), "ushr32": lambda: z.LShR(left, right & 31)}
        if kind == "I" and ints and op in operations:
            return operations[op]()
        raise UnsupportedTerm("unsupported_operator_or_sort")

    @staticmethod
    def fail(reason):
        """Raise a typed unsupported-term failure inside an expression dispatch."""
        raise UnsupportedTerm(reason)

    def boolean(self, node):
        """Overapproximate unsupported atoms independently while retaining AND/OR/NOT."""
        z, op = self.z3, node.get("op")
        if node.get("type") == "Z" and op in {"and", "or", "not"}:
            children = node.get("args", [])
            if children and (op != "not" or len(children) == 1):
                args = [self.boolean(a) for a in children]
                return z.Not(args[0]) if op == "not" else z.And(*args) if op == "and" else z.Or(*args)
        symbols, inputs, count = dict(self.symbols), dict(self.inputs), len(self.constraints)
        try:
            value = self.term(node)
            if not z.is_bool(value):
                raise UnsupportedTerm("non_boolean_condition")
            return value
        except UnsupportedTerm as error:
            self.symbols, self.inputs = symbols, inputs
            del self.constraints[count:]
            self.abstracted.append(str(error))
            return z.Bool("opaque_" + str(len(self.abstracted)), ctx=self.context)

    def decode(self, model, value):
        """Return bounded Java values, retaining raw UTF-16 units for unpaired surrogates."""
        z = self.z3
        if isinstance(value, tuple):
            if z.is_true(model.eval(value[0], model_completion=True)):
                return None
            sequence = value[1]
            length = model.eval(z.Length(sequence), model_completion=True).as_long()
            if length > 256:
                return {"utf16_length": length, "truncated": True}
            units = [model.eval(sequence[i], model_completion=True).as_long() for i in range(length)]
            raw = b"".join(x.to_bytes(2, "little") for x in units)
            try:
                return raw.decode("utf-16-le")
            except UnicodeDecodeError:
                return {"utf16_code_units": units}
        decoded = model.eval(value, model_completion=True)
        return z.is_true(decoded) if z.is_bool(decoded) else decoded.as_long() if z.is_int_value(decoded) else decoded.as_signed_long()





try:
    import z3
except (ImportError, OSError):  # fmt: skip
    z3 = None

SOLVER_ERROR = z3.Z3Exception if z3 is not None else RuntimeError


class UnsupportedCondition(ValueError):
    """A formula cannot be represented faithfully by the supported SMT fragment."""


def cacheable_solver_result(result):
    """Reuse formula facts, but never preserve a transient resource or solver failure."""
    return result.get("status") in {"SAT", "UNSAT"} or (
        result.get("status") == "UNKNOWN"
        and result.get("reason") == "satisfiable_abstraction_not_a_witness"
    )


class ConditionSolver:
    def __init__(self, *, timeout_ms=25, budget_seconds=0.5, max_checks=128):
        """Limit per-query time, cumulative work, query count and cached results per app."""
        self.timeout_ms = timeout_ms
        self.remaining_seconds = budget_seconds
        self.max_checks = max_checks
        self.cache = {}
        self.context = None
        self.statistics = {
            "requests": 0,
            "solver_calls": 0,
            "cache_hits": 0,
            "SAT": 0,
            "UNSAT": 0,
            "UNKNOWN": 0,
            "elapsed_seconds": 0.0,
        }

    def _result(self, status, reason=None, *, engine="z3", model=None):
        """Describe formula satisfiability separately from runtime vulnerability status."""
        return {
            "status": status,
            "reason": reason,
            "engine": engine,
            "version": z3.get_version_string() if z3 is not None else None,
            "semantics": "bool_bv32_nullable_utf16_intent_properties",
            "scope": "recovered_path_condition",
            "runtime_validated": False,
            "model": model or [],
        }

    def _translate(self, expression):
        """Translate supported terms and conservatively abstract unsupported Boolean atoms."""
        if self.context is None:
            self.context = z3.Context()
        terms = ConditionTerms(z3, self.context)
        formula = terms.boolean(refine_string_hashes(expression))
        return formula, terms

    def _solve(self, expression, deadline):
        """Solve one supported formula within the remaining cooperative time budget."""
        if z3 is None:
            return self._result("UNKNOWN", "solver_unavailable")
        if self.statistics["solver_calls"] >= self.max_checks:
            return self._result("UNKNOWN", "solver_query_limit")
        formula, terms = self._translate(expression)
        milliseconds = min(self.timeout_ms, int((deadline - time.monotonic()) * 1000))
        if milliseconds < 1:
            return self._result("UNKNOWN", "solver_budget")
        solver = z3.Solver(ctx=self.context)
        solver.set(timeout=milliseconds, rlimit=100000, random_seed=0)
        solver.add(formula, *terms.constraints)
        self.statistics["solver_calls"] += 1
        answer = solver.check()
        if answer == z3.unsat:
            return {**self._result("UNSAT"), "abstraction": "sound_boolean_overapproximation" if terms.abstracted else "none",
                    "abstracted_atoms": len(terms.abstracted)}
        if answer != z3.sat:
            return self._result("UNKNOWN", "solver_unknown: " + solver.reason_unknown())
        if terms.abstracted:
            return {**self._result("UNKNOWN", "satisfiable_abstraction_not_a_witness"),
                    "abstraction": "sound_boolean_overapproximation", "abstracted_atoms": len(terms.abstracted),
                    "unsupported_reasons": sorted(set(terms.abstracted))}
        model = solver.model()
        values = [{"input": node, "value": terms.decode(model, symbol)}
                  for node, symbol in terms.inputs.values()]
        return self._result("SAT", model=values)

    def check(self, expression: Expr, *, deadline=None):
        """Return SAT/UNSAT only for supported formulas; retain all unresolved cases."""
        started = time.monotonic()
        self.statistics["requests"] += 1
        key = None
        try:
            if (
                self.timeout_ms <= 0
                or (deadline is not None and started >= deadline)
            ):
                result = self._result("UNKNOWN", "solver_budget")
            else:
                # Bound traversal before serializing potentially large expressions.
                pending, size = [(expression, 0)], 0
                while pending:
                    node, depth = pending.pop()
                    size += 1
                    if size > 2048 or depth > 64:
                        raise UnsupportedCondition("expression_limit")
                    pending.extend((child, depth + 1) for child in node.get("args", []))
                key = marker(expression)
                if deadline is not None and time.monotonic() >= deadline:
                    result = self._result("UNKNOWN", "solver_budget")
                elif key in self.cache:
                    self.statistics["cache_hits"] += 1
                    result = self.cache[key]
                elif self.remaining_seconds <= 0:
                    result = self._result("UNKNOWN", "solver_budget")
                elif (
                    expression.get("op") == "const"
                    and expression.get("type") == "Z"
                    and type(expression.get("value")) is bool
                ):
                    result = self._result(
                        "SAT" if expression["value"] else "UNSAT", engine="constant"
                    )
                else:
                    limit = min(deadline or float("inf"), started + self.remaining_seconds)
                    result = self._solve(expression, limit)
        except UnsupportedCondition as error:
            result = self._result("UNKNOWN", str(error))
        except (SOLVER_ERROR, OSError, ValueError, TypeError, KeyError, RecursionError) as error:
            # Optional native solver failures must not erase candidates or stop analysis.
            result = self._result("UNKNOWN", "solver_error: " + type(error).__name__)
        elapsed = time.monotonic() - started
        self.remaining_seconds -= elapsed
        self.statistics["elapsed_seconds"] += elapsed
        self.statistics[result["status"]] += 1
        # A SAT overapproximation with unsupported atoms cannot become an exact
        # witness by spending more time. Reuse that stable answer, but never cache
        # timeouts, resource limits, missing solvers or other transient failures.
        if key is not None and len(self.cache) < 1024 and cacheable_solver_result(result):
            self.cache[key] = result
        return result


def java_string_hash(text):
    """Compute String.hashCode over UTF-16 code units with signed Java int overflow."""
    raw = text.encode("utf-16-le", errors="surrogatepass")
    value = 0
    for index in range(0, len(raw), 2):
        value = (31 * value + int.from_bytes(raw[index:index+2], "little")) & 0xffffffff
    return value if value < 2**31 else value - 2**32


def refine_string_hashes(expression, equalities=None):
    """Evaluate hashes only from literal equalities in the same AND scope, never other OR arms."""
    equalities = dict(equalities or {})
    op, children = expression.get("op"), expression.get("args", [])
    if op == "and":
        for child in children:
            if child.get("op") != "eq" or len(child.get("args", [])) != 2:
                continue
            left, right = child["args"]
            if left.get("op") == "const":
                left, right = right, left
            if (left.get("op") == "input" and left.get("control") == "external_intent"
                    and left.get("type") == "Ljava/lang/String;" and right.get("op") == "const"
                    and right.get("type") == "Ljava/lang/String;" and isinstance(right.get("value"), str)):
                equalities[marker(left)] = right["value"]
    if op == "str_hash32" and len(children) == 1:
        value = children[0]
        text = value.get("value") if value.get("op") == "const" else equalities.get(marker(value))
        if isinstance(text, str) and len(text) <= 512:
            return constant(java_string_hash(text))
    if not children:
        return expression
    return {**expression, "args": [refine_string_hashes(c, equalities) for c in children]}
