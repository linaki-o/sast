"""Code metrics used for quality reporting and by the complexity rules."""

from __future__ import annotations

from sast.ast.nodes import (
    BinaryOp,
    CaseStmt,
    CatchClause,
    CompoundStmt,
    ConditionalOp,
    DoWhileStmt,
    ForStmt,
    FunctionDecl,
    IfStmt,
    Node,
    RangeForStmt,
    SwitchStmt,
    TranslationUnit,
    VariableDecl,
    WhileStmt,
)
from sast.core.models import FileMetrics


def cyclomatic_complexity(node: Node) -> int:
    """McCabe cyclomatic complexity of a function body."""
    complexity = 1
    for child in node.walk():
        if child is node:
            continue
        kind = child.kind
        if kind in {"if_stmt", "while_stmt", "do_while_stmt", "for_stmt", "range_for_stmt"}:
            complexity += 1
        elif kind == "case_stmt":
            complexity += 1
        elif kind == "catch_clause":
            complexity += 1
        elif kind == "conditional":
            complexity += 1
        elif kind == "binary_op" and getattr(child, "operator", "") in {"&&", "||"}:
            complexity += 1
    return complexity


def max_nesting_depth(node: Node) -> int:
    """Maximum nesting depth of the control flow structures in *node*."""
    nesting_kinds = {
        "if_stmt",
        "while_stmt",
        "do_while_stmt",
        "for_stmt",
        "range_for_stmt",
        "switch_stmt",
        "try_stmt",
        "compound_stmt",
    }
    best = 0

    def walk(current: Node, depth: int) -> None:
        nonlocal best
        for child in current.children:
            child_depth = depth + 1 if child.kind in nesting_kinds else depth
            best = max(best, child_depth)
            walk(child, child_depth)

    walk(node, 0)
    return best


def function_line_span(function: FunctionDecl) -> int:
    """Number of source lines a function spans."""
    if function.body is None:
        return 0
    start = function.location.line
    end = function.body.end_location.line or start
    return max(end - start + 1, 1)


def parameter_count(function: FunctionDecl) -> int:
    return len(function.parameters)


def count_loc_statements(node: Node) -> int:
    """Number of logical lines (statements) in a function."""
    count = 0
    for child in node.walk():
        if child.kind in {
            "expr_stmt",
            "decl_stmt",
            "if_stmt",
            "while_stmt",
            "do_while_stmt",
            "for_stmt",
            "range_for_stmt",
            "switch_stmt",
            "return_stmt",
            "goto_stmt",
            "throw_stmt",
            "try_stmt",
            "compound_stmt",
        }:
            count += 1
    return count


def collect_metrics(context) -> list[FileMetrics]:
    """Compute the per-file metrics of a parsed translation unit."""
    unit: TranslationUnit = context.unit
    lines = context.lines
    total = len(lines) if lines else 1

    code = 0
    comment = 0
    blank = 0
    occupied: set[int] = set()
    for token in unit.walk():
        if token.location.line:
            occupied.add(token.location.line)
    for number in range(1, total + 1):
        if number in occupied:
            code += 1
        else:
            text = lines[number - 1].strip() if number <= len(lines) else ""
            if text.startswith("//") or text.startswith("/*") or text.startswith("*"):
                comment += 1
            elif not text:
                blank += 1
            else:
                comment += 1

    functions = [d for d in unit.declarations if isinstance(d, FunctionDecl)]
    classes = [d for d in unit.declarations if getattr(d, "kind", "") == "class_decl"]
    globals_ = [
        d
        for d in unit.declarations
        if isinstance(d, VariableDecl) and not d.is_parameter
    ]

    complexity = sum(
        cyclomatic_complexity(function.body) for function in functions if function.body
    )
    nesting = max(
        (max_nesting_depth(f.body) for f in functions if f.body), default=0
    )

    metrics = FileMetrics(
        path=context.path,
        language=context.language,
        lines_total=total,
        lines_code=code,
        lines_comment=comment,
        lines_blank=blank,
        functions=len(functions),
        classes=len(classes),
        cyclomatic_complexity=complexity,
        max_nesting=nesting,
        parameters=sum(parameter_count(f) for f in functions),
        globals=len(globals_),
        comment_ratio=round(comment / total, 3) if total else 0.0,
    )
    return [metrics]


def function_metrics(function: FunctionDecl) -> dict[str, int]:
    """Detailed metrics of a single function."""
    body = function.body
    return {
        "lines": function_line_span(function),
        "complexity": cyclomatic_complexity(body) if body else 1,
        "max_nesting": max_nesting_depth(body) if body else 0,
        "parameters": parameter_count(function),
        "statements": count_loc_statements(body) if body else 0,
    }
