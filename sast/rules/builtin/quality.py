"""Quality rule pack for CodeShield.

The rules in this module keep the code base maintainable: unused entities,
hidden complexity, dangerous comparisons and constructs that make the code
hard to review.
"""

from __future__ import annotations

from typing import Iterator

from sast.analysis.metrics import (
    cyclomatic_complexity,
    function_line_span,
    max_nesting_depth,
)
from sast.analysis.scope import is_pointer_type, resolve_typedef
from sast.ast.nodes import (
    ArrayType,
    CaseStmt,
    DefaultStmt,
    Assignment,
    BinaryOp,
    Call,
    Cast,
    CompoundStmt,
    DeclStmt,
    DoWhileStmt,
    Expr,
    ForStmt,
    FunctionDecl,
    GotoStmt,
    Identifier,
    IfStmt,
    IndexAccess,
    Literal,
    MemberAccess,
    Node,
    PointerType,
    ReferenceType,
    ReturnStmt,
    SizeOfExpr,
    Stmt,
    StructType,
    SwitchStmt,
    ThrowStmt,
    TryStmt,
    TypeNode,
    UnaryOp,
    VariableDecl,
    WhileStmt,
)
from sast.core.models import Severity
from sast.rules.base import Rule, register
from sast.rules.builtin import (
    iter_functions,
    prepare,
    resolve_symbol,
    resolve_type,
    signedness,
)

DEPRECATED_FUNCTIONS = {
    "strcpy": "strncpy or memcpy with an explicit size",
    "strcat": "strncat with an explicit size",
    "sprintf": "snprintf",
    "gets": "fgets",
    "atoi": "strtol",
    "atof": "strtod",
    "sscanf": "strtol or sscanf_s",
}

MAGIC_ALLOWED_VALUES = frozenset({0, 1, -1})


def _function_return_type(function: FunctionDecl) -> Node | None:
    """The declared return type of a function, ``None`` for ``void``."""
    type_node = getattr(function, "type", None)
    return getattr(type_node, "return_type", None)


def _is_void(type_node: Node | None) -> bool:
    if type_node is None:
        return True
    name = getattr(type_node, "name", "")
    return str(name).replace("const ", "").strip() == "void"


def _switch_cases(statement: SwitchStmt) -> list:
    """The case labels of *statement* in source order."""
    body = statement.body
    if body is None:
        return []
    cases: list = []
    for node in body.walk():
        if not isinstance(node, (CaseStmt, DefaultStmt)):
            continue
        nearest = None
        current = node.parent
        while current is not None:
            if isinstance(current, SwitchStmt):
                nearest = current
                break
            current = current.parent
        if nearest is statement:
            cases.append(node)
    return cases


def _switch_returns(statement: SwitchStmt) -> bool | None:
    """Does every branch of *statement* return?

    A switch without a ``default`` label can fall through, so the answer is
    only ``True`` when a default exists and every case returns.  A case
    without a body falls through into the next one.
    """
    cases = _switch_cases(statement)
    if not cases:
        return None
    if not any(isinstance(case, DefaultStmt) for case in cases):
        return None

    results = [_statement_returns(case.body) for case in cases]
    for index in range(len(results) - 2, -1, -1):
        if cases[index].body is None:
            results[index] = results[index + 1]
    return all(result is True for result in results)


def _statement_returns(statement: Stmt | None) -> bool | None:
    """Does *statement* end the function with a return value?

    ``True`` means the function always returns, ``False`` means it can fall
    through the end of the function and ``None`` means that this cannot be
    decided.
    """
    if statement is None:
        return False
    if isinstance(statement, ReturnStmt):
        return True
    if isinstance(statement, ThrowStmt):
        return True
    if isinstance(statement, IfStmt):
        if statement.else_branch is None:
            return False
        then_result = _statement_returns(statement.then_branch)
        else_result = _statement_returns(statement.else_branch)
        if then_result is None or else_result is None:
            return None
        return bool(then_result and else_result)
    if isinstance(statement, CompoundStmt):
        if not statement.statements:
            return False
        return _statement_returns(statement.statements[-1])
    if isinstance(statement, SwitchStmt):
        return _switch_returns(statement)
    if isinstance(statement, CaseStmt):
        return _statement_returns(statement.body) if statement.body is not None else False
    if isinstance(statement, DefaultStmt):
        return _statement_returns(statement.body) if statement.body is not None else False
    if isinstance(statement, TryStmt):
        results = [_statement_returns(statement.body)]
        for handler in statement.handlers:
            results.append(_statement_returns(getattr(handler, "body", None)))
        if any(result is None for result in results):
            return None
        return all(results)
    if isinstance(statement, GotoStmt):
        return None
    return False


def _is_modified(body: Node, name: str) -> bool:
    """Is *name* assigned, incremented or has its address taken?"""
    for node in body.walk():
        if isinstance(node, Assignment):
            target = node.target
            if isinstance(target, Identifier) and target.name == name:
                return True
        elif isinstance(node, UnaryOp):
            if node.operator in {"++", "--", "post++", "post--"}:
                operand = node.operand
                if isinstance(operand, Identifier) and operand.name == name:
                    return True
            if node.operator == "&":
                operand = node.operand
                if isinstance(operand, Identifier) and operand.name == name:
                    return True
    return False


def _is_magic_literal(ctx, node: Literal) -> bool:
    """Is *node* a numeric literal that should be a named constant?"""
    if node.literal_type not in {"int", "float"}:
        return False
    value = ctx.const_int(node)
    if value is None:
        return True
    if value in MAGIC_ALLOWED_VALUES:
        return False
    return True


def _is_excluded_magic(ctx, node: Literal) -> bool:
    """Numeric literals in cases, enums and array sizes are not magic."""
    parent = node.parent
    if parent is not None and parent.kind == "case_stmt":
        return True
    if parent is not None and parent.kind == "enumerator":
        return True
    return False


def _is_meaningful_magic(node: Literal) -> bool:
    """Only report literals whose value actually carries meaning.

    Numbers used as an array index, as a call argument or as a loop bound
    are idiomatic; a number inside a comparison or an arithmetic expression
    is the one that usually deserves a name.
    """
    parent = node.parent
    if parent is None:
        return False
    kind = parent.kind
    if kind in {"index_access", "call", "arg"}:
        return False
    if kind == "assignment":
        return False
    if kind == "variable_decl":
        return False
    if kind in {"binary_op", "unary_op", "conditional"}:
        operator = getattr(parent, "operator", "")
        if kind == "binary_op" and operator in {"==", "!=", "<", ">", "<=", ">=", "+", "-", "*", "/", "%"}:
            return True
        if kind == "unary_op" and operator in {"-", "+"}:
            return True
        return False
    return False


def _local_declarations(body: Node) -> Iterator[VariableDecl]:
    for node in body.walk():
        if not isinstance(node, DeclStmt):
            continue
        for declaration in getattr(node, "declarations", []) or []:
            if isinstance(declaration, VariableDecl) and declaration.name:
                yield declaration


def _shadowed_declarations(ctx, function: FunctionDecl) -> Iterator[VariableDecl]:
    """Local declarations that hide a name of an enclosing scope."""
    body = function.body
    if body is None:
        return
    global_names: set[str] = set()
    for declaration in ctx.unit.declarations:
        if isinstance(declaration, VariableDecl) and declaration.name:
            global_names.add(declaration.name)
    parameter_names = {
        parameter.name for parameter in function.parameters if parameter.name
    }
    enclosing: set[str] = global_names | parameter_names
    reported: set[int] = set()

    def visit(block: CompoundStmt, outer: set[str]) -> Iterator[VariableDecl]:
        own: set[str] = set()
        for statement in block.statements:
            if not isinstance(statement, DeclStmt):
                continue
            for declaration in getattr(statement, "declarations", []) or []:
                if not isinstance(declaration, VariableDecl) or not declaration.name:
                    continue
                if declaration.name in outer and id(declaration) not in reported:
                    reported.add(id(declaration))
                    yield declaration
                own.add(declaration.name)
        nested = outer | own
        for statement in block.statements:
            if isinstance(statement, CompoundStmt):
                yield from visit(statement, nested)
                continue
            for child in statement.children:
                if isinstance(child, CompoundStmt):
                    yield from visit(child, nested)

    yield from visit(body, enclosing)


def _is_deprecated_call(call: Call) -> bool:
    return call.callee_name in DEPRECATED_FUNCTIONS


def _resolved_type(ctx, type_node: TypeNode | None) -> TypeNode | None:
    """Resolve a typedef to the type it stands for."""
    if type_node is None:
        return None
    types = getattr(ctx.symbols, "types", None) or {}
    try:
        resolved = resolve_typedef(type_node, types)
    except Exception:
        return type_node
    return resolved if resolved is not None else type_node


def _member_type(ctx, access: MemberAccess) -> TypeNode | None:
    """The type of the member a member access refers to."""
    base = _resolved_type(ctx, _expression_type(ctx, access.object))
    if isinstance(base, (PointerType, ReferenceType)):
        base = _resolved_type(ctx, base.pointee)
    if isinstance(base, StructType):
        for field in base.fields:
            if field.name == access.member:
                return field.type
    return None


def _expression_type(ctx, expression: Expr | None) -> TypeNode | None:
    """The type of an expression, when it can be determined."""
    if expression is None:
        return None
    try:
        if isinstance(expression, Identifier):
            symbol = resolve_symbol(ctx, expression.name, expression)
            return getattr(symbol, "type", None)
        if isinstance(expression, MemberAccess):
            return _member_type(ctx, expression)
        if isinstance(expression, Cast):
            return expression.target_type
        if isinstance(expression, IndexAccess):
            base = _resolved_type(ctx, _expression_type(ctx, expression.object))
            if isinstance(base, ArrayType):
                return base.element
            if isinstance(base, (PointerType, ReferenceType)):
                return base.pointee
            return None
        if isinstance(expression, UnaryOp):
            if expression.operator == "*":
                base = _resolved_type(ctx, _expression_type(ctx, expression.operand))
                if isinstance(base, (PointerType, ReferenceType)):
                    return base.pointee
                return None
            if expression.operator == "&":
                pointer = PointerType(expression.location)
                pointer.pointee = _expression_type(ctx, expression.operand)
                return pointer
    except Exception:
        return None
    return None


def _is_pointer_expression(ctx, expression: Expr | None) -> bool:
    """Does the expression really have a pointer type?

    The base identifier of an lvalue chain is not enough: for ``p->field``
    the base is the pointer ``p`` while the expression itself is the type
    of the field.  The type of the expression is therefore resolved and an
    expression whose type stays unknown is never a pointer.
    """
    type_node = _expression_type(ctx, expression)
    if type_node is None:
        return False
    return is_pointer_type(_resolved_type(ctx, type_node))


@register
class UnusedLocalVariable(Rule):
    id = "QLT-UNUSED-001"
    name = "Unused local variable"
    category = "quality"
    severity = Severity.LOW
    description = "A local variable is declared but never referenced."
    rationale = "Dead variables hide real bugs and confuse the reader."
    recommendation = "Remove the variable or use it where it is needed."
    standards = ("MISRA C:2012 Rule 8.7",)
    tags = ("dead-code", "local")

    def check(self, ctx):
        prepare(ctx)
        for function in iter_functions(ctx):
            body = function.body
            if body is None:
                continue
            for declaration in _local_declarations(body):
                name = declaration.name
                used = False
                for node in body.walk():
                    if isinstance(node, Identifier) and node.name == name:
                        used = True
                        break
                if used:
                    continue
                yield ctx.report(
                    self, declaration, f"the local variable '{name}' is never used"
                )


@register
class UnusedParameter(Rule):
    id = "QLT-UNUSED-002"
    name = "Unused function parameter"
    category = "quality"
    severity = Severity.LOW
    description = "A parameter of a function is never referenced in its body."
    rationale = "Unused parameters suggest a wrong interface or dead code."
    recommendation = "Remove the parameter or mark it as unused in the implementation."
    standards = ("MISRA C:2012 Rule 8.7",)
    tags = ("dead-code", "parameter", "interface")

    def check(self, ctx):
        prepare(ctx)
        for function in iter_functions(ctx):
            body = function.body
            if body is None:
                continue
            for parameter in function.parameters:
                name = parameter.name
                if not name:
                    continue
                used = False
                for node in body.walk():
                    if isinstance(node, Identifier) and node.name == name:
                        used = True
                        break
                if not used:
                    for initialiser in getattr(function, "member_inits", []) or []:
                        value = getattr(initialiser, "value", None)
                        if value is None:
                            continue
                        for node in value.walk():
                            if isinstance(node, Identifier) and node.name == name:
                                used = True
                                break
                        if used:
                            break
                if used:
                    continue
                yield ctx.report(
                    self, parameter, f"the parameter '{name}' is never used"
                )


@register
class UnusedStaticFunction(Rule):
    id = "QLT-UNUSED-003"
    name = "Unused static function"
    category = "quality"
    severity = Severity.LOW
    description = "A file scope static function is never called in the file."
    rationale = "Static helpers that are never called are dead code."
    recommendation = "Remove the function or make it non static when it is used elsewhere."
    standards = ("MISRA C:2012 Rule 8.7",)
    tags = ("dead-code", "function", "static")

    def check(self, ctx):
        prepare(ctx)
        if ctx.path.lower().endswith((".h", ".hpp", ".hh", ".hxx")):
            return
        calls = {
            node.callee_name
            for node in ctx.unit.walk()
            if isinstance(node, Call)
        }
        for declaration in ctx.unit.declarations:
            if not isinstance(declaration, FunctionDecl):
                continue
            if not declaration.is_static:
                continue
            if declaration.name in calls:
                continue
            yield ctx.report(
                self,
                declaration,
                f"the static function '{declaration.name}' is never called in "
                "this file",
            )


@register
class VariableShadowing(Rule):
    id = "QLT-SHADOW-001"
    name = "Variable shadowing"
    category = "quality"
    severity = Severity.LOW
    description = "A local declaration hides a name of an enclosing scope."
    rationale = "Shadowing makes it ambiguous which variable is used."
    recommendation = "Rename the local variable or remove the shadowing declaration."
    standards = ("MISRA C:2012 Rule 8.14",)
    tags = ("scope", "naming", "readability")

    def check(self, ctx):
        prepare(ctx)
        for function in iter_functions(ctx):
            for declaration in _shadowed_declarations(ctx, function):
                yield ctx.report(
                    self,
                    declaration,
                    f"the local variable '{declaration.name}' shadows a "
                    "declaration of an enclosing scope",
                )


@register
class HighCyclomaticComplexity(Rule):
    id = "QLT-COMPLEX-001"
    name = "Cyclomatic complexity is too high"
    category = "quality"
    severity = Severity.MEDIUM
    description = "The cyclomatic complexity of a function exceeds the limit."
    rationale = "Complex functions are hard to test and hard to review."
    recommendation = "Split the function into smaller functions with a single purpose."
    standards = ("MISRA C:2012 Rule 15.5",)
    tags = ("complexity", "maintainability")

    def check(self, ctx):
        prepare(ctx)
        limit = ctx.config.max_cyclomatic_complexity
        for function in iter_functions(ctx):
            body = function.body
            if body is None:
                continue
            complexity = cyclomatic_complexity(body)
            if complexity <= limit:
                continue
            yield ctx.report(
                self,
                function,
                f"the cyclomatic complexity of '{function.name}' is "
                f"{complexity} and exceeds the limit of {limit}",
                complexity=complexity,
            )


@register
class LongFunction(Rule):
    id = "QLT-LENGTH-001"
    name = "Function is too long"
    category = "quality"
    severity = Severity.LOW
    description = "A function spans more lines than the configured limit."
    rationale = "Long functions hide responsibilities and are hard to review."
    recommendation = "Split the function into smaller functions."
    cwe = (398,)
    standards = ()
    tags = ("size", "maintainability")

    def check(self, ctx):
        prepare(ctx)
        limit = ctx.config.max_function_lines
        for function in iter_functions(ctx):
            if function.body is None:
                continue
            span = function_line_span(function)
            if span <= limit:
                continue
            yield ctx.report(
                self,
                function,
                f"'{function.name}' spans {span} lines and exceeds the limit "
                f"of {limit} lines",
                lines=span,
            )


@register
class LongFile(Rule):
    id = "QLT-FILE-001"
    name = "File is too long"
    category = "quality"
    severity = Severity.LOW
    description = "A file contains more lines than the configured limit."
    rationale = "Very large files are hard to navigate and to review."
    recommendation = "Split the file along the natural module boundaries."
    cwe = (398,)
    standards = ()
    tags = ("size", "maintainability")

    def check(self, ctx):
        prepare(ctx)
        limit = ctx.config.max_file_lines
        total = len(ctx.lines)
        if total <= limit:
            return
        yield ctx.report(
            self,
            ctx.unit,
            f"the file contains {total} lines and exceeds the limit of "
            f"{limit} lines",
            lines=total,
        )


@register
class DeepNesting(Rule):
    id = "QLT-NESTING-001"
    name = "Nesting is too deep"
    category = "quality"
    severity = Severity.MEDIUM
    description = "The control flow of a function nests deeper than allowed."
    rationale = "Deep nesting indicates a function with several responsibilities."
    recommendation = "Use early returns to flatten the control flow."
    cwe = (398,)
    standards = ()
    tags = ("complexity", "nesting", "readability")

    def check(self, ctx):
        prepare(ctx)
        limit = ctx.config.max_nesting_depth
        for function in iter_functions(ctx):
            body = function.body
            if body is None:
                continue
            depth = max_nesting_depth(body)
            if depth <= limit:
                continue
            yield ctx.report(
                self,
                function,
                f"the nesting depth of '{function.name}' is {depth} and "
                f"exceeds the limit of {limit}",
                depth=depth,
            )


@register
class TooManyParameters(Rule):
    id = "QLT-PARAM-001"
    name = "Function has too many parameters"
    category = "quality"
    severity = Severity.LOW
    description = "A function declares more parameters than allowed."
    rationale = "Long parameter lists are error prone at the call site."
    recommendation = "Group the parameters into a structure."
    standards = ("MISRA C:2012 Rule 15.5",)
    tags = ("interface", "maintainability")

    def check(self, ctx):
        prepare(ctx)
        limit = ctx.config.max_parameters
        for function in iter_functions(ctx):
            count = len(function.parameters)
            if count <= limit:
                continue
            yield ctx.report(
                self,
                function,
                f"'{function.name}' has {count} parameters and exceeds the "
                f"limit of {limit}",
                parameters=count,
            )


@register
class MagicNumber(Rule):
    id = "QLT-MAGIC-001"
    name = "Magic number"
    category = "quality"
    severity = Severity.LOW
    description = "A numeric literal is used without a name that explains it."
    rationale = "Named constants document the intent of a number."
    recommendation = "Introduce a named constant for the literal."
    cwe = (398,)
    standards = ()
    tags = ("readability", "maintainability")

    def check(self, ctx):
        prepare(ctx)
        for node in ctx.unit.walk():
            if not isinstance(node, Literal):
                continue
            if not _is_magic_literal(ctx, node):
                continue
            if _is_excluded_magic(ctx, node):
                continue
            if not _is_meaningful_magic(node):
                continue
            yield ctx.report(
                self,
                node,
                f"the magic number {node.value} should be replaced by a named "
                "constant",
            )


@register
class GotoStatement(Rule):
    id = "QLT-GOTO-001"
    name = "Use of goto"
    category = "quality"
    severity = Severity.LOW
    description = "A goto statement jumps inside the function."
    rationale = "Unstructured jumps make the control flow hard to follow."
    recommendation = "Restructure the function or use break and continue."
    standards = ("MISRA C:2012 Rule 15.4",)
    tags = ("control-flow", "readability")

    def check(self, ctx):
        prepare(ctx)
        for node in ctx.unit.walk():
            if not isinstance(node, GotoStmt):
                continue
            yield ctx.report(
                self,
                node,
                f"the goto statement jumps to the label '{node.label}'",
            )


@register
class MissingBraces(Rule):
    id = "QLT-BRACE-001"
    name = "Missing braces around a control structure body"
    category = "quality"
    severity = Severity.LOW
    description = (
        "The body of an if, else, for or while statement is not enclosed in "
        "braces."
    )
    rationale = "Unbraced bodies are a frequent source of dangling statement bugs."
    recommendation = "Always enclose the body of a control structure in braces."
    standards = ("MISRA C:2012 Rule 15.5",)
    tags = ("style", "readability")

    def check(self, ctx):
        prepare(ctx)
        for node in ctx.unit.walk():
            if isinstance(node, IfStmt):
                if not isinstance(node.then_branch, CompoundStmt):
                    yield ctx.report(
                        self,
                        node,
                        "the body of the if statement is not enclosed in braces",
                    )
                else_branch = node.else_branch
                if else_branch is not None and not isinstance(
                    else_branch, (CompoundStmt, IfStmt)
                ):
                    yield ctx.report(
                        self,
                        node,
                        "the body of the else statement is not enclosed in braces",
                    )
            elif isinstance(node, (ForStmt, WhileStmt, DoWhileStmt)):
                body = node.body
                if not isinstance(body, CompoundStmt):
                    yield ctx.report(
                        self,
                        node,
                        "the body of the loop is not enclosed in braces",
                    )
            elif isinstance(node, SwitchStmt):
                if not isinstance(node.body, CompoundStmt):
                    yield ctx.report(
                        self,
                        node.body,
                        "the body of the switch statement is not enclosed in braces",
                    )


@register
class PointerComparedWithZero(Rule):
    id = "QLT-NULL-002"
    name = "Pointer compared with zero instead of NULL"
    category = "quality"
    severity = Severity.LOW
    description = "A pointer is compared with the integer literal zero."
    rationale = "NULL documents the intent and avoids pointer/integer warnings."
    recommendation = "Compare the pointer with NULL."
    standards = ("MISRA C:2012 Rule 10.4",)
    tags = ("null", "style", "pointer")

    def check(self, ctx):
        prepare(ctx)
        for node in ctx.unit.walk():
            if not isinstance(node, BinaryOp) or node.operator not in {"==", "!="}:
                continue
            for side, other in ((node.left, node.right), (node.right, node.left)):
                if not isinstance(side, Literal) or side.literal_type != "int":
                    continue
                if side.value.strip() != "0":
                    continue
                try:
                    pointer = _is_pointer_expression(ctx, other)
                except Exception:
                    pointer = False
                if pointer:
                    yield ctx.report(
                        self,
                        node,
                        "the pointer is compared with 0; use NULL instead",
                    )
                break


@register
class RedundantCondition(Rule):
    id = "QLT-REDUNDANT-001"
    name = "Redundant condition"
    category = "quality"
    severity = Severity.MEDIUM
    description = "Both operands of a comparison are the same variable."
    rationale = "The condition is always true or always false."
    recommendation = "Remove the comparison or compare against the intended value."
    cwe = (570, 571)
    standards = ()
    tags = ("logic", "dead-code")

    def check(self, ctx):
        prepare(ctx)
        for node in ctx.unit.walk():
            if not isinstance(node, BinaryOp) or node.operator not in {"==", "!="}:
                continue
            left = node.left
            right = node.right
            if not isinstance(left, Identifier) or not isinstance(right, Identifier):
                continue
            if left.name != right.name:
                continue
            yield ctx.report(
                self,
                node,
                f"the condition compares '{left.name}' with itself and is "
                "always constant",
            )


@register
class AssignmentInCondition(Rule):
    id = "QLT-ASSIGN-001"
    name = "Assignment used as a condition"
    category = "quality"
    severity = Severity.MEDIUM
    description = "An assignment is used directly as the condition of a statement."
    rationale = "The assignment is easy to overlook and mixes two statements."
    recommendation = "Split the assignment and the condition into two statements."
    standards = ("MISRA C:2012 Rule 13.2",)
    tags = ("logic", "readability")

    def check(self, ctx):
        prepare(ctx)
        for node in ctx.unit.walk():
            if isinstance(node, (IfStmt, WhileStmt, DoWhileStmt)):
                condition = getattr(node, "condition", None)
                if isinstance(condition, Assignment):
                    yield ctx.report(
                        self,
                        condition,
                        "the condition of the statement is an assignment",
                    )
            elif isinstance(node, ForStmt):
                if isinstance(node.condition, Assignment):
                    yield ctx.report(
                        self,
                        node.condition,
                        "the condition of the loop is an assignment",
                    )


@register
class EmptyBlock(Rule):
    id = "QLT-EMPTY-001"
    name = "Empty block"
    category = "quality"
    severity = Severity.LOW
    description = "A compound statement or a branch of a conditional is empty."
    rationale = "Empty blocks are usually left over from removed code."
    recommendation = "Remove the empty block or add a comment that explains it."
    cwe = (398,)
    standards = ()
    tags = ("dead-code", "readability")

    def check(self, ctx):
        prepare(ctx)
        for node in ctx.unit.walk():
            if isinstance(node, CompoundStmt):
                if node.statements:
                    continue
                yield ctx.report(self, node, "the block is empty")
            elif isinstance(node, IfStmt):
                then_branch = node.then_branch
                if isinstance(then_branch, CompoundStmt) and not then_branch.statements:
                    yield ctx.report(
                        self, then_branch, "the if branch is empty"
                    )
                else_branch = node.else_branch
                if isinstance(else_branch, CompoundStmt) and not else_branch.statements:
                    yield ctx.report(
                        self, else_branch, "the else branch is empty"
                    )


@register
class MixedDeclarationsAndCode(Rule):
    id = "QLT-MIXED-001"
    name = "Mixed declarations and code"
    category = "quality"
    severity = Severity.LOW
    description = (
        "A declaration appears after an executable statement in the same "
        "block."
    )
    rationale = "Mixed blocks are harder to read and were forbidden by C89."
    recommendation = "Move all declarations to the top of the block."
    standards = ("MISRA C:2012 Rule 8.2",)
    tags = ("style", "readability")

    def check(self, ctx):
        prepare(ctx)
        for node in ctx.unit.walk():
            if not isinstance(node, CompoundStmt):
                continue
            seen_statement = False
            for statement in node.statements:
                if isinstance(statement, DeclStmt):
                    if seen_statement:
                        yield ctx.report(
                            self,
                            statement,
                            "the declaration appears after an executable "
                            "statement in the same block",
                        )
                    continue
                seen_statement = True


@register
class SizeofOnPointer(Rule):
    id = "QLT-SIZEOF-001"
    name = "sizeof applied to a pointer"
    category = "quality"
    severity = Severity.MEDIUM
    description = "sizeof() is applied to a pointer instead of the pointee."
    rationale = "The result is the size of the pointer and not the size of the data."
    recommendation = "Apply sizeof() to the pointed to type or to the array."
    standards = ("MISRA C:2012 Rule 6.7",)
    tags = ("sizeof", "pointer", "bug")

    def check(self, ctx):
        prepare(ctx)
        for node in ctx.unit.walk():
            if not isinstance(node, SizeOfExpr):
                continue
            operand = node.operand
            if operand is None or isinstance(operand, TypeNode):
                continue
            try:
                pointer = _is_pointer_expression(ctx, operand)
            except Exception:
                pointer = False
            if not pointer:
                continue
            yield ctx.report(
                self,
                node,
                "sizeof() is applied to a pointer and yields the size of the "
                "pointer instead of the size of the pointee",
            )


@register
class MultipleDeclarations(Rule):
    id = "QLT-MULTI-001"
    name = "Multiple variables declared in one statement"
    category = "quality"
    severity = Severity.LOW
    description = "A declaration statement declares more than one variable."
    rationale = "One declaration per statement simplifies reviews and diffs."
    recommendation = "Split the declaration into one statement per variable."
    standards = ("MISRA C:2012 Rule 8.2",)
    tags = ("style", "declaration")

    def check(self, ctx):
        prepare(ctx)
        for node in ctx.unit.walk():
            if not isinstance(node, DeclStmt):
                continue
            count = len(getattr(node, "declarations", []) or [])
            if count <= 1:
                continue
            yield ctx.report(
                self,
                node,
                f"{count} variables are declared in a single statement",
            )


@register
class MissingConstQualifier(Rule):
    id = "QLT-CONST-001"
    name = "Local variable could be const"
    category = "quality"
    severity = Severity.INFO
    description = "A local variable is initialised but never modified."
    rationale = "The const qualifier documents that the value does not change."
    recommendation = "Declare the variable as const."
    standards = ("MISRA C:2012 Rule 8.13",)
    tags = ("const", "maintainability")

    def check(self, ctx):
        prepare(ctx)
        for function in iter_functions(ctx):
            body = function.body
            if body is None:
                continue
            for declaration in _local_declarations(body):
                if declaration.is_const or declaration.is_static or declaration.is_extern:
                    continue
                if getattr(declaration, "init", None) is None:
                    continue
                type_node = getattr(declaration, "type", None)
                if isinstance(type_node, PointerType):
                    continue
                name = declaration.name
                if _is_modified(body, name):
                    continue
                yield ctx.report(
                    self,
                    declaration,
                    f"'{name}' is never modified and could be declared const",
                )


@register
class ImplicitSignedToUnsignedConversion(Rule):
    id = "QLT-TYPE-001"
    name = "Implicit conversion from a signed to an unsigned type"
    category = "quality"
    severity = Severity.MEDIUM
    description = "A signed value is assigned to an unsigned variable."
    rationale = "A negative value becomes a large positive one without a warning."
    recommendation = "Use matching types or convert the value explicitly."
    standards = ("MISRA C:2012 Rule 10.3",)
    tags = ("type", "conversion", "signedness")

    def check(self, ctx):
        prepare(ctx)
        for node in ctx.unit.walk():
            if not isinstance(node, Assignment):
                continue
            try:
                target = signedness(resolve_type(ctx, node.target))
                source = signedness(resolve_type(ctx, node.value))
            except Exception:
                continue
            if target != -1 or source != 1:
                continue
            yield ctx.report(
                self,
                node,
                "a signed value is assigned to an unsigned variable and is "
                "converted implicitly",
            )


@register
class MissingReturnStatement(Rule):
    id = "QLT-RETURN-001"
    name = "Missing return statement"
    category = "quality"
    severity = Severity.MEDIUM
    description = (
        "A function with a return value can reach its end without returning "
        "one."
    )
    rationale = "The caller receives an undefined return value."
    recommendation = "Return a value on every path or make the function void."
    standards = ("MISRA C:2012 Rule 15.5",)
    tags = ("control-flow", "return", "bug")

    def check(self, ctx):
        prepare(ctx)
        for function in iter_functions(ctx):
            body = function.body
            if body is None:
                continue
            if function.is_constructor or function.is_destructor:
                continue
            return_type = _function_return_type(function)
            if return_type is None or _is_void(return_type):
                continue
            result = _statement_returns(body)
            if result is None or result:
                continue
            yield ctx.report(
                self,
                function,
                f"'{function.name}' may reach its end without returning a value",
            )


@register
class DeprecatedFunction(Rule):
    id = "QLT-DEPRECATED-001"
    name = "Use of a deprecated function"
    category = "quality"
    severity = Severity.MEDIUM
    description = "A function that is unsafe or deprecated is used."
    rationale = "Deprecated functions have no bounds checking or error reporting."
    recommendation = "Use the modern replacement of the function."
    cwe = (676,)
    standards = ("MISRA C:2012 Rule 21.6",)
    tags = ("deprecated", "api", "modernisation")

    def check(self, ctx):
        prepare(ctx)
        for node in ctx.unit.walk():
            if not isinstance(node, Call) or not _is_deprecated_call(node):
                continue
            name = node.callee_name
            replacement = DEPRECATED_FUNCTIONS[name]
            yield ctx.report(
                self,
                node,
                f"'{name}' is deprecated; use {replacement} instead",
            )
