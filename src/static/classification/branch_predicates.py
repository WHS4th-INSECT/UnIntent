"""DEX 분기 조건을 분석하기 쉬운 단순한 표현식으로 변환"""

from __future__ import annotations

import json
from typing import Any

Expr = dict[str, Any]
INVERSE = {"eq": "ne", "ne": "eq", "lt": "ge", "ge": "lt", "gt": "le", "le": "gt", "ref_eq": "ref_ne", "ref_ne": "ref_eq"}


def constant(value: Any, value_type: str = "I") -> Expr:
    """Represent a DEX constant without guessing whether zero denotes null."""
    return {"op": "const", "value": value, "type": value_type}


def unknown(label: str, value_type: str = "?", control: str = "unknown") -> Expr:
    """Keep an unsupported value and its provenance explicit."""
    return {"op": "unknown", "label": label, "type": value_type, "control": control}


def marker(value: Expr) -> str:
    """Provide a deterministic identity for a symbolic expression."""
    return json.dumps(value, sort_keys=True, ensure_ascii=False)


def negate(expr: Expr) -> Expr:
    """Negate a predicate, including the selected direction of a DEX branch."""
    op = expr["op"]
    if op == "const" and expr.get("type") == "Z":
        return constant(not expr["value"], "Z")
    if op in INVERSE:
        return {**expr, "op": INVERSE[op]}
    if op == "not":
        return expr["args"][0]
    return {"op": "not", "args": [expr], "type": "Z"}


def compare(op: str, left: Expr, right: Expr) -> Expr:
    """Normalize primitive comparisons while retaining unresolved operand types."""
    if left.get("type", "?").startswith(("L", "[")) and right == constant(0):
        right = constant(None, left["type"])
    if (
        left.get("type") == "Z"
        and right.get("op") == "const"
        and right.get("value") in (0, 1)
        and op in {"eq", "ne"}
    ):
        positive = (op == "ne") == (right["value"] == 0)
        return left if positive else negate(left)
    if left["op"] == right["op"] == "const":
        lv, rv = left["value"], right["value"]
        try:
            result = {
                "eq": lambda: lv == rv,
                "ne": lambda: lv != rv,
                "lt": lambda: lv < rv,
                "le": lambda: lv <= rv,
                "gt": lambda: lv > rv,
                "ge": lambda: lv >= rv,
            }[op]()
            return constant(result, "Z")
        except (TypeError, KeyError):
            pass
    return {"op": op, "args": [left, right], "type": "Z"}


def combine(op: str, items: list[Expr]) -> Expr:
    """Flatten AND/OR, remove identities and simplify opposite predicate pairs."""
    identity = op == "and"
    values: dict[str, Expr] = {}
    for item in items:
        children = item["args"] if item["op"] == op else [item]
        for child in children:
            if child == constant(not identity, "Z"):
                return child
            if child != constant(identity, "Z"):
                values[marker(child)] = child
    if any(marker(negate(item)) in values for item in values.values()):
        return constant(not identity, "Z")
    result = list(values.values())
    # Absorption also removes paths made redundant by an unconditional route.
    if op == "or":
        terms = [{marker(x) for x in (v["args"] if v["op"] == "and" else [v])} for v in result]
        result = [
            v
            for i, v in enumerate(result)
            if not any(t < terms[i] for j, t in enumerate(terms) if j != i)
        ]
    if not result:
        return constant(identity, "Z")
    return result[0] if len(result) == 1 else {"op": op, "args": result, "type": "Z"}


def impossible(predicates: list[Expr]) -> bool:
    """Reject only explicit contradictions in supported primitive constraints."""
    combined = combine("and", predicates)
    if combined == constant(False, "Z"):
        return True
    bounds: dict[str, list[Any]] = {}
    for item in combined.get("args", []) if combined["op"] == "and" else [combined]:
        if item["op"] not in INVERSE:
            continue
        left, right = item["args"]
        op = item["op"]
        if left["op"] == "const":
            left, right = right, left
            op = {"lt": "gt", "le": "ge", "gt": "lt", "ge": "le"}.get(op, op)
        # App state and unknown calls may change; never constrain them globally.
        if left["op"] != "input" or right["op"] != "const":
            continue
        if left.get("type") != "I" or type(right.get("value")) is not int:
            continue
        lower, upper, excluded = bounds.setdefault(marker(left), [-(2**31), 2**31 - 1, set()])
        value = right["value"]
        if op == "eq":
            lower, upper = max(lower, value), min(upper, value)
        elif op == "ne":
            excluded.add(value)
        elif op in {"gt", "ge"}:
            lower = max(lower, value + (op == "gt"))
        elif op in {"lt", "le"}:
            upper = min(upper, value - (op == "lt"))
        bounds[marker(left)] = [lower, upper, excluded]
        if lower > upper or (lower == upper and lower in excluded):
            return True
    return False


def integer_operation(name: str, operands: list[Expr]) -> Expr:
    """Preserve signed 32-bit wraparound for supported DEX integer operations."""
    pending, size = list(operands), 0
    while pending:
        node = pending.pop()
        size += 1
        if size > 256:
            return unknown("integer expression size limit", "I")
        pending.extend(node.get("args", []))
    op = name.split("-")[0]
    supported = {"add", "sub", "mul", "and", "or", "xor", "shl", "shr", "ushr", "rsub"}
    if op not in supported or len(operands) != 2:
        return unknown(f"unsupported integer operation {name}", "I")
    if all(x["op"] == "const" and type(x.get("value")) is int for x in operands):
        a, b = (x["value"] for x in operands)
        value = {
            "add": lambda: a + b,
            "sub": lambda: a - b,
            "rsub": lambda: b - a,
            "mul": lambda: a * b,
            "and": lambda: a & b,
            "or": lambda: a | b,
            "xor": lambda: a ^ b,
            "shl": lambda: a << (b & 31),
            "shr": lambda: a >> (b & 31),
            "ushr": lambda: (a & 0xFFFFFFFF) >> (b & 31),
        }[op]()
        return constant(((value + 2**31) % 2**32) - 2**31)
    return {"op": op + "32", "args": operands, "type": "I", "semantics": "signed_32_bit_wraparound"}


def inputs(expr: Expr) -> list[Expr]:
    """Collect exact Intent fields and unknown state dependencies from a formula."""
    found = {marker(expr): expr} if expr["op"] in {"input", "unknown", "environment"} else {}
    for child in expr.get("args", []):
        found.update({marker(value): value for value in inputs(child)})
    return list(found.values())


def render(expr: Expr) -> str:
    """Render structured predicates for reports without pretending to recover source code."""
    op = expr["op"]
    if op == "const":
        return json.dumps(expr["value"], ensure_ascii=False)
    if op == "input":
        return (
            "extra" + "".join(f"[{json.dumps(k)}]" for k in [*expr.get("key_path", []), expr['key']])
            if expr["field"] == "extra"
            else f"intent.{expr['field']}" + (f"[{json.dumps(expr.get('key'))}]" if expr.get("key") is not None else "")
        )
    if op == "unknown":
        return f"UNKNOWN({expr['label']})"
    if op == "environment":
        return f"platform.{expr['field']}"
    if op == "boxed_integer":
        return f"Integer.valueOf({render(expr['args'][0])})"
    if op == "not":
        return f"!({render(expr['args'][0])})"
    if op == "object":
        return f"object<{expr.get('type')}>@{expr.get('id')}"
    if op in {"intent", "bundle"}:
        return f"{op}<{expr.get('id')}>" + repr(expr.get("key_path", []))
    symbols = {
        "eq": "==",
        "ne": "!=",
        "lt": "<",
        "le": "<=",
        "gt": ">",
        "ge": ">=",
        "and": "AND",
        "or": "OR",
    }
    return "(" + f" {symbols.get(op, op)} ".join(render(a) for a in expr.get("args", [])) + ")"


def compact_conditions(summary: dict[str, Any]) -> dict[str, Any]:
    """Intern repeated expressions and branch sites; references retain AND/OR structure."""
    expressions, expression_ids, sites, site_ids = {}, {}, {}, {}
    witnesses = [index for index, path in enumerate(summary.get("paths", []))
                 if path.get("solver", {}).get("status") == "SAT" and path.get("path_status") not in {"infeasible", "unexplored"}]
    # Existence of one solved condition is distinct from exhaustive CFG coverage
    # and from runtime feasibility. Preserve both of those independent fields.
    summary = {**summary, "condition_status": "SAT" if witnesses else "UNSAT" if summary.get("feasibility") == "INFEASIBLE" else "UNKNOWN",
               "condition_status_scope": "exists_recovered_path_condition",
               "condition_witness_path_indices": witnesses}

    def intern(expr):
        """Assign one local ID to an expression and recursively intern its operands."""
        key = marker(expr)
        if key in expression_ids:
            return expression_ids[key]
        reference = f"p{len(expression_ids) + 1}"
        expression_ids[key] = reference
        expressions[reference] = {
            **expr,
            **({"args": [intern(a) for a in expr["args"]]} if "args" in expr else {}),
        }
        return reference

    result = {k: v for k, v in summary.items() if k not in {"condition", "paths"}}
    result["condition_ref"] = intern(summary["condition"])
    result["condition_text"] = summary["condition_text"][:1000]
    result["condition_text_truncated"] = len(summary["condition_text"]) > 1000
    result["paths"] = []
    for path in summary["paths"]:
        branch_refs = []
        for branch in path["branches"]:
            key = marker(branch)
            if key not in site_ids:
                reference = f"b{len(site_ids) + 1}"
                site_ids[key] = reference
                sites[reference] = {
                    **{k: v for k, v in branch.items() if k != "predicate"},
                    "predicate_ref": intern(branch["predicate"]),
                }
            branch_refs.append(site_ids[key])
        result["paths"].append(
            {
                **{
                    k: v
                    for k, v in path.items()
                    if k not in {"condition", "condition_text", "branches"}
                },
                "condition_ref": intern(path["condition"]),
                "branch_refs": branch_refs,
            }
        )
    result["expressions"], result["branch_sites"] = expressions, sites
    if summary.get("state_supports"):
        result["state_supports"] = {}
        for identity, support in summary["state_supports"].items():
            result["state_supports"][identity] = {**support, "alternatives": [
                {**{k: v for k, v in case.items() if k not in {"condition", "value", "linked_condition"}},
                 "condition_ref": intern(case["condition"]), "value_ref": intern(case["value"]),
                 "linked_condition_ref": intern(case["linked_condition"])} for case in support["alternatives"]]}
    return result
