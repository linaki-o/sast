"""MISRA C:2012 rule pack for CodeShield.

The rules in this module implement a set of MISRA C:2012 guidelines.  Every
rule maps onto exactly one MISRA rule and reports through the regular
``ctx.report`` mechanism, so the findings appear in the ordinary reports
next to the security and quality findings.

The implementations work on the abstract syntax tree and on the symbol table
of the analysed translation unit.  They are deliberately conservative: when
the shape of the tree is not what the rule expects, or when the type of an
expression cannot be determined, the rule stays silent instead of guessing.
"""

from __future__ import annotations

import re
from typing import Any, Iterator

from sast.analysis.scope import resolve_typedef
from sast.ast.nodes import (
    ArrayType,
    Assignment,
    BinaryOp,
    Call,
    CaseStmt,
    Cast,
    CatchClause,
    CommaOp,
    CompoundStmt,
    ConditionalOp,
    DefaultStmt,
    DoWhileStmt,
    EnumType,
    Expr,
    ExprStmt,
    ForStmt,
    FunctionDecl,
    FunctionType,
    Identifier,
    IfStmt,
    IndexAccess,
    Literal,
    MemberAccess,
    Node,
    PointerType,
    PrimitiveType,
    RangeForStmt,
    ReferenceType,
    ReturnStmt,
    SizeOfExpr,
    StructType,
    SwitchStmt,
    TryStmt,
    ThrowStmt,
    TypeNode,
    UnaryOp,
    VariableDecl,
    WhileStmt,
)
from sast.core.models import Severity
from sast.rules.base import Rule, register
from sast.rules.builtin import (
    find_calls,
    iter_functions,
    prepare,
    resolve_symbol,
    signedness,
)

#: Types that behave like a boolean.
BOOL_TYPES = frozenset({"bool", "_Bool"})

#: Operators that produce an essentially boolean result.
COMPARISON_OPERATORS = frozenset({"==", "!=", "<", ">", "<=", ">="})

#: Operators that perform an arithmetic or bitwise computation.
ARITHMETIC_OPERATORS = frozenset({"+", "-", "*", "/", "%", "<<", ">>", "&", "|", "^"})

#: Operators that add or subtract a value from a pointer.
POINTER_ARITHMETIC_OPERATORS = frozenset({"+", "-"})

#: The compound assignment operators of C.
COMPOUND_ASSIGNMENTS = frozenset(
    {"+=", "-=", "*=", "/=", "%=", "<<=", ">>=", "&=", "^=", "|="}
)

#: The compound assignment operators that are defined for a pointer operand.
POINTER_ARITHMETIC_OPERATIONS = frozenset({"+=", "-="})

#: The memory management functions of the standard library.
MEMORY_FUNCTIONS = frozenset(
    {
        "malloc",
        "calloc",
        "realloc",
        "reallocarray",
        "free",
        "aligned_alloc",
        "valloc",
        "pvalloc",
    }
)

#: The time handling functions of the standard library.
TIME_FUNCTIONS = frozenset(
    {
        "time",
        "clock",
        "difftime",
        "mktime",
        "asctime",
        "ctime",
        "ctime_s",
        "ctime_r",
        "gmtime",
        "gmtime_r",
        "localtime",
        "localtime_r",
        "strftime",
        "timespec_get",
        "timespec_getres",
    }
)

#: Frequently used library functions whose essential type is not visible in
#: the analysed translation unit.
COMMON_LIBC_FUNCTIONS = frozenset(
    {
        "abort",
        "abs",
        "assert",
        "atoi",
        "atol",
        "atof",
        "bsearch",
        "calloc",
        "exit",
        "fclose",
        "fflush",
        "fgets",
        "fgetc",
        "fopen",
        "fprintf",
        "fputc",
        "fputs",
        "free",
        "fread",
        "fscanf",
        "fwrite",
        "getchar",
        "isalnum",
        "isalpha",
        "isdigit",
        "isspace",
        "isupper",
        "islower",
        "labs",
        "malloc",
        "memcmp",
        "memcpy",
        "memmove",
        "memset",
        "printf",
        "putchar",
        "puts",
        "qsort",
        "rand",
        "realloc",
        "scanf",
        "snprintf",
        "sprintf",
        "srand",
        "strcat",
        "strchr",
        "strcmp",
        "strcpy",
        "strcspn",
        "strlen",
        "strncat",
        "strncmp",
        "strncpy",
        "strrchr",
        "strspn",
        "strstr",
        "strtok",
        "tolower",
        "toupper",
        "vprintf",
        "vsnprintf",
        "vsprintf",
    }
)


def _resolved_type(ctx: Any, type_node: TypeNode | None) -> TypeNode | None:
    """Resolve a typedef to the type it stands for."""
    if type_node is None:
        return None
    types = getattr(ctx.symbols, "types", None) or {}
    try:
        resolved = resolve_typedef(type_node, types)
    except Exception:
        return type_node
    return resolved if resolved is not None else type_node


def _type_name(type_node: TypeNode | None) -> str:
    """A comparable name of a type, without the qualifiers."""
    if type_node is None:
        return ""
    try:
        text = type_node.describe()
    except Exception:
        text = getattr(type_node, "name", "")
    text = str(text).replace("const ", "").replace("volatile ", "")
    return " ".join(text.split())


def _same_type(ctx: Any, left: TypeNode | None, right: TypeNode | None) -> bool:
    """Are the two types compatible enough for a pointer conversion?"""
    left = _resolved_type(ctx, left)
    right = _resolved_type(ctx, right)
    if left is None or right is None:
        return False
    return _type_name(left) == _type_name(right)


def _is_void_type(ctx: Any, type_node: TypeNode | None) -> bool:
    """Is the type the incomplete type ``void``?"""
    resolved = _resolved_type(ctx, type_node)
    if isinstance(resolved, PrimitiveType):
        return resolved.name.replace("const ", "").strip() == "void"
    return False


def _category(ctx: Any, type_node: TypeNode | None) -> str:
    """The essential type category of a type.

    The result is one of ``bool``, ``int``, ``uint``, ``float``, ``pointer``,
    ``array``, ``struct``, ``void`` or ``unknown``.
    """
    resolved = _resolved_type(ctx, type_node)
    if resolved is None:
        return "unknown"
    if isinstance(resolved, PrimitiveType):
        name = resolved.name.replace("const ", "").strip()
        if name in BOOL_TYPES:
            return "bool"
        if name in {"float", "double", "long double"}:
            return "float"
        if name == "void":
            return "void"
        try:
            sign = signedness(resolved)
        except Exception:
            sign = 0
        if sign == 1:
            return "int"
        if sign == -1:
            return "uint"
        return "unknown"
    if isinstance(resolved, (PointerType, ReferenceType)):
        return "pointer"
    if isinstance(resolved, ArrayType):
        return "array"
    if isinstance(resolved, (StructType, EnumType)):
        return "struct"
    return "unknown"


def _function_return_type(function: FunctionDecl | None) -> TypeNode | None:
    """The declared return type of a function."""
    if function is None:
        return None
    type_node = getattr(function, "type", None)
    if isinstance(type_node, FunctionType):
        return type_node.return_type
    return getattr(type_node, "return_type", None)


def _call_return_type(ctx: Any, call: Call) -> TypeNode | None:
    """The return type of the function a call refers to."""
    functions = getattr(ctx.symbols, "functions", None) or {}
    try:
        function = functions.get(call.callee_name)
    except Exception:
        return None
    return _function_return_type(function)


def _call_parameter(ctx: Any, call: Call, index: int) -> Node | None:
    """The declaration of the parameter a call argument is passed to."""
    functions = getattr(ctx.symbols, "functions", None) or {}
    try:
        function = functions.get(call.callee_name)
    except Exception:
        return None
    if function is None:
        return None
    parameters = getattr(function, "parameters", None) or []
    if index >= len(parameters):
        return None
    return parameters[index]


def _literal_type(literal: Literal) -> TypeNode:
    """The type of a literal."""
    kind = literal.literal_type
    if kind == "int":
        return PrimitiveType("int", literal.location)
    if kind == "float":
        return PrimitiveType("double", literal.location)
    if kind == "char":
        return PrimitiveType("char", literal.location)
    if kind == "bool":
        return PrimitiveType("bool", literal.location)
    pointer = PointerType(literal.location)
    if kind == "string":
        pointer.pointee = PrimitiveType("char", literal.location)
    else:
        pointer.pointee = PrimitiveType("void", literal.location)
    return pointer


def _element_type(ctx: Any, expression: Expr | None) -> TypeNode | None:
    """The type of the elements an array or pointer expression refers to."""
    resolved = _resolved_type(ctx, _expression_type(ctx, expression))
    if isinstance(resolved, ArrayType):
        return resolved.element
    if isinstance(resolved, (PointerType, ReferenceType)):
        return resolved.pointee
    return None


def _member_type(ctx: Any, access: MemberAccess) -> TypeNode | None:
    """The type of the member a member access refers to."""
    base = _resolved_type(ctx, _expression_type(ctx, access.object))
    if isinstance(base, (PointerType, ReferenceType)):
        base = _resolved_type(ctx, base.pointee)
    if isinstance(base, StructType):
        for field in base.fields:
            if field.name == access.member:
                return field.type
    return None


def _is_essentially_boolean(ctx: Any, expression: Expr | None) -> bool:
    """Does *expression* have an essentially boolean type?

    A comparison always yields a boolean value, a logical operator only does
    so when both of its operands are boolean themselves, and a plain integer
    or pointer expression is not boolean at all.
    """
    if expression is None:
        return True
    if isinstance(expression, BinaryOp):
        if expression.operator in COMPARISON_OPERATORS:
            return True
        if expression.operator in {"&&", "||"}:
            return _is_essentially_boolean(
                ctx, expression.left
            ) and _is_essentially_boolean(ctx, expression.right)
        return False
    if isinstance(expression, UnaryOp):
        return expression.operator == "!"
    if isinstance(expression, Cast):
        return _category(ctx, expression.target_type) == "bool"
    return _category(ctx, _expression_type(ctx, expression)) == "bool"


def _binary_type(ctx: Any, node: BinaryOp) -> TypeNode | None:
    """The type of the result of a binary operation."""
    operator = node.operator
    if operator in {"&&", "||"} or operator in COMPARISON_OPERATORS:
        return PrimitiveType("bool", node.location)
    left = _category(ctx, _expression_type(ctx, node.left))
    right = _category(ctx, _expression_type(ctx, node.right))
    if operator in POINTER_ARITHMETIC_OPERATORS and "pointer" in (left, right):
        return PointerType(node.location)
    if "float" in (left, right):
        return PrimitiveType("double", node.location)
    if "uint" in (left, right):
        return PrimitiveType("unsigned int", node.location)
    if "int" in (left, right):
        return PrimitiveType("int", node.location)
    return None


def _unary_type(ctx: Any, node: UnaryOp) -> TypeNode | None:
    """The type of the result of a unary operation."""
    if node.operator == "!":
        return PrimitiveType("bool", node.location)
    operand_type = _expression_type(ctx, node.operand)
    if node.operator == "*":
        resolved = _resolved_type(ctx, operand_type)
        if isinstance(resolved, (PointerType, ReferenceType)):
            return resolved.pointee
        return None
    if node.operator == "&":
        pointer = PointerType(node.location)
        pointer.pointee = operand_type
        return pointer
    return operand_type


def _expression_type(ctx: Any, expression: Expr | None) -> TypeNode | None:
    """The type of an expression, when it can be determined."""
    if expression is None:
        return None
    try:
        if isinstance(expression, Literal):
            return _literal_type(expression)
        if isinstance(expression, Identifier):
            symbol = resolve_symbol(ctx, expression.name, expression)
            return getattr(symbol, "type", None)
        if isinstance(expression, Cast):
            return expression.target_type
        if isinstance(expression, SizeOfExpr):
            return PrimitiveType("size_t", expression.location)
        if isinstance(expression, BinaryOp):
            return _binary_type(ctx, expression)
        if isinstance(expression, UnaryOp):
            return _unary_type(ctx, expression)
        if isinstance(expression, Call):
            return _call_return_type(ctx, expression)
        if isinstance(expression, ConditionalOp):
            return _expression_type(ctx, expression.then_branch)
        if isinstance(expression, IndexAccess):
            return _element_type(ctx, expression.object)
        if isinstance(expression, MemberAccess):
            return _member_type(ctx, expression)
        if isinstance(expression, CommaOp):
            return _expression_type(ctx, expression.right)
    except Exception:
        return None
    return None


def _implicit_conversions(ctx: Any) -> Iterator[tuple[Any, Expr, Node]]:
    """Yield every implicit conversion of the translation unit.

    Each item is the target type, the converted expression and the node the
    finding should be attached to.
    """
    for node in ctx.unit.walk():
        if isinstance(node, Assignment):
            target = _expression_type(ctx, node.target)
            if target is not None:
                yield target, node.value, node
        elif isinstance(node, VariableDecl):
            initialiser = getattr(node, "init", None)
            if initialiser is None or node.type is None:
                continue
            yield node.type, initialiser, node
        elif isinstance(node, Call):
            for index, argument in enumerate(node.arguments):
                parameter = _call_parameter(ctx, node, index)
                if parameter is None:
                    continue
                parameter_type = getattr(parameter, "type", None)
                if parameter_type is None:
                    continue
                yield parameter_type, argument, argument


def _source_before_name(ctx: Any, declaration: Node, name: str) -> str:
    """The source text that precedes a declared name on its line."""
    if not name:
        return ""
    line = ctx.line_text(declaration.location.line)
    if not line:
        return ""
    match = re.search(r"\b" + re.escape(name) + r"\b", line)
    if match is None:
        return line
    return line[: match.start()]


def _pointee_is_const(ctx: Any, declaration: Node) -> bool:
    """Is the object a pointer points to declared const?

    The parser keeps the qualifier of the pointer itself but not the one of
    the pointee, so the declaration is inspected in the source text.
    """
    type_node = getattr(declaration, "type", None)
    if not isinstance(type_node, PointerType):
        return False
    if type_node.const:
        return False
    name = getattr(declaration, "name", "")
    return "const" in _source_before_name(ctx, declaration, name)


def _references_name(expression: Expr | None, name: str) -> bool:
    """Does the expression read the variable called *name*?"""
    if expression is None or not name:
        return False
    for node in expression.walk():
        if isinstance(node, Identifier) and node.name == name:
            return True
    return False


def _is_name(expression: Expr | None, name: str) -> bool:
    """Is the expression the variable called *name*?"""
    if isinstance(expression, Cast):
        return _is_name(expression.operand, name)
    return isinstance(expression, Identifier) and expression.name == name


def _dereferences(expression: Expr | None, name: str) -> bool:
    """Does the expression write through the pointer called *name*?"""
    if isinstance(expression, UnaryOp) and expression.operator == "*":
        return _is_name(expression.operand, name)
    if isinstance(expression, IndexAccess):
        return _is_name(expression.object, name)
    if isinstance(expression, MemberAccess) and expression.operator == "->":
        return _is_name(expression.object, name)
    return False


def _argument_modifies(ctx: Any, call: Call, name: str) -> bool:
    """Is the pointer passed to a function that may modify it?"""
    for index, argument in enumerate(call.arguments):
        if not _references_name(argument, name):
            continue
        parameter = _call_parameter(ctx, call, index)
        if parameter is None:
            return True
        if _pointee_is_const(ctx, parameter):
            continue
        return True
    return False


def _pointer_is_modified(ctx: Any, function: FunctionDecl, name: str) -> bool:
    """Is the object the pointer points to modified in the function?"""
    body = function.body
    if body is None:
        return True
    for node in body.walk():
        if isinstance(node, Assignment):
            if _dereferences(node.target, name):
                return True
        elif isinstance(node, UnaryOp):
            if node.operator in {"++", "--", "post++", "post--"}:
                if _dereferences(node.operand, name):
                    return True
            elif node.operator == "&" and _is_name(node.operand, name):
                return True
        elif isinstance(node, Call):
            if _argument_modifies(ctx, node, name):
                return True
    return False


def _pointer_declarations(function: FunctionDecl) -> Iterator[Node]:
    """The pointer parameters and pointer locals of a function."""
    for parameter in function.parameters:
        if isinstance(getattr(parameter, "type", None), PointerType):
            yield parameter
    body = function.body
    if body is None:
        return
    for node in body.walk():
        if isinstance(node, VariableDecl) and isinstance(node.type, PointerType):
            yield node


def _array_size(ctx: Any, expression: Expr | None) -> int | None:
    """The number of elements of the array an expression refers to."""
    identifier = ctx.base_identifier(expression)
    if identifier is None:
        return None
    symbol = resolve_symbol(ctx, identifier.name, expression)
    if symbol is None or not getattr(symbol, "is_array", False):
        return None
    size = getattr(symbol, "array_size", None)
    if size is not None:
        return size
    type_node = getattr(symbol, "type", None)
    if isinstance(type_node, ArrayType):
        try:
            return ctx.const_int(type_node.size_expr)
        except Exception:
            return None
    return None


def _switch_labels(statement: SwitchStmt) -> list[Node]:
    """The labels of a switch statement in source order."""
    labels: list[Node] = []
    body = statement.body
    if body is None:
        return labels
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
            labels.append(node)
    return labels


@register
class DuplicateExternalDefinition(Rule):
    id = "MISRA-8-007"
    name = "Object with external linkage has more than one external definition"
    category = "standards"
    severity = Severity.HIGH
    description = (
        "An object with external linkage is defined more than once in the "
        "translation unit."
    )
    rationale = (
        "A duplicated external definition lets the linker pick one of the "
        "definitions, which makes the behaviour of the program unpredictable."
    )
    recommendation = (
        "Keep exactly one definition of the object and declare it with "
        "extern in every other translation unit."
    )
    standards = ("MISRA C:2012 Rule 8.7",)
    tags = ("misra", "linkage", "definition")

    def check(self, ctx):
        prepare(ctx)
        definitions: dict[str, Node] = {}
        tentative: dict[str, Node] = {}
        for declaration in ctx.unit.declarations:
            if not isinstance(declaration, VariableDecl):
                continue
            name = declaration.name
            if not name or declaration.is_static or declaration.is_parameter:
                continue
            initialiser = getattr(declaration, "init", None)
            if initialiser is not None:
                if name in definitions:
                    yield ctx.report(
                        self,
                        declaration,
                        f"'{name}' has a second external definition; an object "
                        "with external linkage shall have exactly one",
                    )
                else:
                    definitions[name] = declaration
                continue
            if declaration.is_extern:
                continue
            if name in tentative:
                yield ctx.report(
                    self,
                    declaration,
                    f"'{name}' is defined a second time; an object with "
                    "external linkage shall have exactly one definition",
                )
            else:
                tentative[name] = declaration


@register
class InternalLinkageUsedBeforeDefinition(Rule):
    id = "MISRA-8-009"
    name = "Object with internal linkage is used before it is defined"
    category = "standards"
    severity = Severity.MEDIUM
    description = (
        "A file scope object with internal linkage is referenced before the "
        "declaration that defines it."
    )
    rationale = (
        "The reader cannot tell which definition the use refers to and the "
        "program depends on the order of the declarations."
    )
    recommendation = (
        "Move the definition above its first use or declare the object "
        "before it is used."
    )
    standards = ("MISRA C:2012 Rule 8.9",)
    tags = ("misra", "linkage", "declaration")

    def check(self, ctx):
        prepare(ctx)
        definitions: dict[str, Node] = {}
        for declaration in ctx.unit.declarations:
            if not isinstance(declaration, VariableDecl):
                continue
            if not declaration.is_static or not declaration.name:
                continue
            definitions.setdefault(declaration.name, declaration)
        if not definitions:
            return
        for node in ctx.unit.walk():
            if not isinstance(node, Identifier):
                continue
            declaration = definitions.get(node.name)
            if declaration is None:
                continue
            if node.location.line < declaration.location.line:
                yield ctx.report(
                    self,
                    node,
                    f"the internal linkage object '{node.name}' is used "
                    "before it is defined",
                )


@register
class PointerShouldBeConst(Rule):
    id = "MISRA-8-013"
    name = "Pointer could be declared as a pointer to const"
    category = "standards"
    severity = Severity.LOW
    description = (
        "A pointer that is never used to modify the object it points to is "
        "not declared as a pointer to const."
    )
    rationale = (
        "The const qualifier documents the intent of the interface and lets "
        "the compiler protect the object against unwanted modification."
    )
    recommendation = "Declare the pointer as a pointer to a const type."
    standards = ("MISRA C:2012 Rule 8.13",)
    tags = ("misra", "const", "pointer")

    def check(self, ctx):
        prepare(ctx)
        for function in iter_functions(ctx):
            for declaration in _pointer_declarations(function):
                name = getattr(declaration, "name", "")
                if not name:
                    continue
                if _pointee_is_const(ctx, declaration):
                    continue
                if _pointer_is_modified(ctx, function, name):
                    continue
                yield ctx.report(
                    self,
                    declaration,
                    f"'{name}' is never used to modify the object it points to "
                    "and could be declared as a pointer to const",
                )


@register
class InappropriateEssentialTypeConversion(Rule):
    id = "MISRA-10-001"
    name = "Conversion to an inappropriate essential type"
    category = "standards"
    severity = Severity.MEDIUM
    description = (
        "A floating point value is converted to an integer type or an "
        "arithmetic operation mixes a floating point operand with an "
        "integer operand."
    )
    rationale = (
        "The conversion happens silently, so the fractional part is lost or "
        "the result is rounded in a way the author did not expect."
    )
    recommendation = (
        "Use matching types or convert the value explicitly at the point "
        "where the truncation is intended."
    )
    standards = ("MISRA C:2012 Rule 10.1",)
    tags = ("misra", "conversion", "type")

    def check(self, ctx):
        prepare(ctx)
        for target_type, value, node in _implicit_conversions(ctx):
            source = _category(ctx, _expression_type(ctx, value))
            target = _category(ctx, target_type)
            if source == "float" and target in {"int", "uint"}:
                yield ctx.report(
                    self,
                    node,
                    "a floating point value is converted to an integer type",
                )
        for node in ctx.unit.walk():
            if not isinstance(node, BinaryOp):
                continue
            if node.operator not in ARITHMETIC_OPERATORS:
                continue
            left = _category(ctx, _expression_type(ctx, node.left))
            right = _category(ctx, _expression_type(ctx, node.right))
            if "float" not in (left, right):
                continue
            if "int" not in (left, right) and "uint" not in (left, right):
                continue
            yield ctx.report(
                self,
                node,
                "the operation mixes a floating point operand with an integer "
                "operand, which converts one of them implicitly",
            )


@register
class SignedValueConvertedToUnsigned(Rule):
    id = "MISRA-10-003"
    name = "Signed value assigned to an unsigned object"
    category = "standards"
    severity = Severity.MEDIUM
    description = (
        "An expression with a signed essential type is converted to an "
        "unsigned essential type."
    )
    rationale = (
        "A negative value becomes a large positive one, so the program "
        "behaves differently from what the source suggests."
    )
    recommendation = (
        "Use matching types or convert the value explicitly after checking "
        "that it fits into the unsigned range."
    )
    standards = ("MISRA C:2012 Rule 10.3",)
    tags = ("misra", "conversion", "signedness")

    def check(self, ctx):
        prepare(ctx)
        for target_type, value, node in _implicit_conversions(ctx):
            if _category(ctx, target_type) != "uint":
                continue
            if _category(ctx, _expression_type(ctx, value)) != "int":
                continue
            try:
                constant = ctx.const_int(value)
            except Exception:
                constant = None
            if constant is not None and constant >= 0:
                continue
            yield ctx.report(
                self,
                node,
                "a signed value is converted to an unsigned type",
            )


@register
class AdditionResultConvertedToUnsigned(Rule):
    id = "MISRA-10-004"
    name = "Result of an addition or subtraction converted to an unsigned type"
    category = "standards"
    severity = Severity.MEDIUM
    description = (
        "The result of an addition or a subtraction on an integer type is "
        "converted to an unsigned type."
    )
    rationale = (
        "An intermediate overflow of the signed addition wraps around and "
        "the unsigned conversion hides it."
    )
    recommendation = (
        "Keep the result in a signed type and convert it only after the "
        "range has been checked."
    )
    standards = ("MISRA C:2012 Rule 10.4",)
    tags = ("misra", "conversion", "overflow")

    def check(self, ctx):
        prepare(ctx)
        for target_type, value, node in _implicit_conversions(ctx):
            if _category(ctx, target_type) != "uint":
                continue
            if not isinstance(value, BinaryOp):
                continue
            if value.operator not in POINTER_ARITHMETIC_OPERATORS:
                continue
            left = _category(ctx, _expression_type(ctx, value.left))
            right = _category(ctx, _expression_type(ctx, value.right))
            if "int" not in (left, right) and "uint" not in (left, right):
                continue
            yield ctx.report(
                self,
                node,
                "the result of an addition or subtraction on an integer type "
                "is converted to an unsigned type",
            )


@register
class CompoundAssignmentOnPointer(Rule):
    id = "MISRA-10-006"
    name = "Compound assignment on a pointer operand"
    category = "standards"
    severity = Severity.HIGH
    description = (
        "A compound assignment operator is applied to a pointer that does "
        "not point to a compatible object type."
    )
    rationale = (
        "Pointer arithmetic on an incomplete or on a non arithmetic type is "
        "undefined behaviour and is usually a mistake."
    )
    recommendation = (
        "Apply the compound assignment to an integer and convert the result "
        "back to a pointer of the correct type."
    )
    standards = ("MISRA C:2012 Rule 10.6",)
    tags = ("misra", "pointer", "assignment")

    def check(self, ctx):
        prepare(ctx)
        for node in ctx.unit.walk():
            if not isinstance(node, Assignment):
                continue
            if node.operator not in COMPOUND_ASSIGNMENTS:
                continue
            target_type = _resolved_type(ctx, _expression_type(ctx, node.target))
            if not isinstance(target_type, PointerType):
                continue
            if node.operator not in POINTER_ARITHMETIC_OPERATIONS:
                yield ctx.report(
                    self,
                    node,
                    f"the compound assignment operator '{node.operator}' is "
                    "not defined for a pointer operand",
                )
                continue
            pointee = _resolved_type(ctx, target_type.pointee)
            if _is_void_type(ctx, pointee):
                yield ctx.report(
                    self,
                    node,
                    "pointer arithmetic is applied to a pointer to void, "
                    "which has no compatible object type",
                )
                continue
            if isinstance(pointee, (StructType, EnumType)):
                yield ctx.report(
                    self,
                    node,
                    "pointer arithmetic is applied to a pointer to a type "
                    "that is not an arithmetic type",
                )
                continue
            if _category(ctx, _expression_type(ctx, node.value)) == "float":
                yield ctx.report(
                    self,
                    node,
                    "a floating point value is added to a pointer",
                )


@register
class PointerCastToInteger(Rule):
    id = "MISRA-11-003"
    name = "Pointer converted to an integer type"
    category = "standards"
    severity = Severity.HIGH
    description = "A pointer is explicitly cast to an integer type."
    rationale = (
        "The integer value of a pointer is implementation defined, so the "
        "code cannot be ported and the pointer may be truncated."
    )
    recommendation = (
        "Keep the pointer in a pointer type and use uintptr_t only when the "
        "conversion is unavoidable."
    )
    standards = ("MISRA C:2012 Rule 11.3",)
    tags = ("misra", "pointer", "cast")

    def check(self, ctx):
        prepare(ctx)
        for node in ctx.unit.walk():
            if not isinstance(node, Cast):
                continue
            source = _category(ctx, _expression_type(ctx, node.operand))
            target = _category(ctx, node.target_type)
            if source != "pointer":
                continue
            if target not in {"int", "uint"}:
                continue
            yield ctx.report(
                self,
                node,
                "a pointer is converted to an integer type",
            )


@register
class PointerAndIntegerConversion(Rule):
    id = "MISRA-11-004"
    name = "Conversion between a pointer to object and an integer type"
    category = "standards"
    severity = Severity.HIGH
    description = (
        "A pointer to an object and an integer are converted into one "
        "another without an explicit cast."
    )
    rationale = (
        "The conversion loses the type information of the pointer and the "
        "compiler is free to reject or to miscompile it."
    )
    recommendation = (
        "Use a pointer type on both sides of the conversion or an explicit "
        "cast that documents the intention."
    )
    standards = ("MISRA C:2012 Rule 11.4",)
    tags = ("misra", "pointer", "conversion")

    def check(self, ctx):
        prepare(ctx)
        for target_type, value, node in _implicit_conversions(ctx):
            target = _category(ctx, target_type)
            source = _category(ctx, _expression_type(ctx, value))
            if target == "pointer" and source in {"int", "uint"}:
                yield ctx.report(
                    self,
                    node,
                    "an integer is converted to a pointer to an object",
                )
            elif target in {"int", "uint"} and source == "pointer":
                yield ctx.report(
                    self,
                    node,
                    "a pointer to an object is converted to an integer type",
                )


@register
class IncompatiblePointerCast(Rule):
    id = "MISRA-11-005"
    name = "Pointer cast to an incompatible object pointer type"
    category = "standards"
    severity = Severity.MEDIUM
    description = (
        "A pointer to an object is cast to a pointer to a different object "
        "type."
    )
    rationale = (
        "The two types may have a different alignment or a different "
        "representation, so the access through the new pointer is undefined."
    )
    recommendation = (
        "Cast through void * only, or use a union with a common member when "
        "the conversion is really required."
    )
    standards = ("MISRA C:2012 Rule 11.5",)
    tags = ("misra", "pointer", "cast")

    def check(self, ctx):
        prepare(ctx)
        for node in ctx.unit.walk():
            if not isinstance(node, Cast):
                continue
            report = self._incompatible(ctx, node.target_type, node.operand)
            if report is not None:
                yield ctx.report(self, node, report)
        for target_type, value, node in _implicit_conversions(ctx):
            report = self._incompatible(ctx, target_type, value)
            if report is not None:
                yield ctx.report(self, node, report)

    def _incompatible(self, ctx: Any, target: Any, value: Expr | None) -> str | None:
        """Describe the conversion when it breaks the rule, otherwise None."""
        target_type = _resolved_type(ctx, target)
        source_type = _resolved_type(ctx, _expression_type(ctx, value))
        if not isinstance(target_type, PointerType):
            return None
        if not isinstance(source_type, PointerType):
            return None
        target_pointee = _resolved_type(ctx, target_type.pointee)
        source_pointee = _resolved_type(ctx, source_type.pointee)
        if _is_void_type(ctx, target_pointee) or _is_void_type(ctx, source_pointee):
            return None
        if _same_type(ctx, target_pointee, source_pointee):
            return None
        return (
            "a pointer is converted from "
            f"'{_type_name(source_pointee)}' to "
            f"'{_type_name(target_pointee)}', which are different object types"
        )


@register
class LogicalOperatorOnBooleanOperands(Rule):
    id = "MISRA-12-001"
    name = "Logical operator applied to boolean operands"
    category = "standards"
    severity = Severity.LOW
    description = (
        "The operators && and || are applied to operands that already have "
        "an essentially boolean type."
    )
    rationale = (
        "The rule is required in the stricter profiles of the standard; it "
        "keeps the boolean intent of the expression explicit."
    )
    recommendation = (
        "Use the bitwise operators & and | on boolean operands or rewrite "
        "the expression so that the boolean type is not implied."
    )
    standards = ("MISRA C:2012 Rule 12.1",)
    tags = ("misra", "boolean", "operator")
    enabled_by_default = False

    def check(self, ctx):
        prepare(ctx)
        for node in ctx.unit.walk():
            if not isinstance(node, BinaryOp):
                continue
            if node.operator not in {"&&", "||"}:
                continue
            left = _category(ctx, _expression_type(ctx, node.left))
            right = _category(ctx, _expression_type(ctx, node.right))
            if left != "bool" or right != "bool":
                continue
            yield ctx.report(
                self,
                node,
                f"the operator '{node.operator}' is applied to two operands "
                "that already have an essentially boolean type",
            )


@register
class CommaOperatorUsed(Rule):
    id = "MISRA-12-003"
    name = "Comma operator used"
    category = "standards"
    severity = Severity.LOW
    description = "The comma operator is used in an expression."
    rationale = (
        "The comma operator hides the evaluation of several expressions in "
        "one statement and is easy to misread."
    )
    recommendation = "Split the expression into separate statements."
    standards = ("MISRA C:2012 Rule 12.3",)
    tags = ("misra", "operator", "readability")

    def check(self, ctx):
        prepare(ctx)
        for node in ctx.unit.walk():
            if isinstance(node, CommaOp):
                yield ctx.report(
                    self,
                    node,
                    "the comma operator must not be used",
                )


@register
class LogicalOperandWithoutEssentialType(Rule):
    id = "MISRA-13-005"
    name = "Right hand operand of a logical operator has no essential type"
    category = "standards"
    severity = Severity.LOW
    description = (
        "The right hand operand of && or || is an expression whose essential "
        "type cannot be determined."
    )
    rationale = (
        "The right hand operand is only evaluated when the left hand operand "
        "is true, so an operand without a type hides an effect that may "
        "never happen."
    )
    recommendation = (
        "Give the operand a well defined type and evaluate the side effect "
        "in a separate statement."
    )
    standards = ("MISRA C:2012 Rule 13.5",)
    tags = ("misra", "boolean", "operator")

    def check(self, ctx):
        prepare(ctx)
        for node in ctx.unit.walk():
            if not isinstance(node, BinaryOp):
                continue
            if node.operator not in {"&&", "||"}:
                continue
            right = node.right
            if isinstance(right, Cast) and _category(ctx, right.target_type) == "void":
                yield ctx.report(
                    self,
                    right,
                    "the right hand operand of the logical operator has no "
                    "essential type",
                )
                continue
            if not isinstance(right, Call):
                continue
            return_type = _call_return_type(ctx, right)
            if return_type is not None:
                if _category(ctx, return_type) == "void":
                    yield ctx.report(
                        self,
                        right,
                        "the right hand operand of the logical operator has "
                        "no essential type",
                    )
                continue
            if right.callee_name in COMMON_LIBC_FUNCTIONS:
                continue
            yield ctx.report(
                self,
                right,
                f"the essential type of '{right.callee_name}()' is unknown, "
                "so the right hand operand of the logical operator has no "
                "essential type",
            )


@register
class NonBooleanIfCondition(Rule):
    id = "MISRA-14-004"
    name = "Controlling expression of an if statement is not essentially boolean"
    category = "standards"
    severity = Severity.MEDIUM
    description = (
        "The controlling expression of an if statement does not have an "
        "essentially boolean type."
    )
    rationale = (
        "A non boolean condition hides the intent of the test and lets the "
        "reader guess how the value is interpreted."
    )
    recommendation = (
        "Compare the value explicitly, for example with '!= 0', so that the "
        "condition has an essentially boolean type."
    )
    standards = ("MISRA C:2012 Rule 14.4",)
    tags = ("misra", "boolean", "control-flow")

    def check(self, ctx):
        prepare(ctx)
        for node in ctx.unit.walk():
            if not isinstance(node, IfStmt):
                continue
            if _is_essentially_boolean(ctx, node.condition):
                continue
            yield ctx.report(
                self,
                node,
                "the controlling expression of the if statement does not have "
                "an essentially boolean type",
            )


@register
class MultipleExitPoints(Rule):
    id = "MISRA-15-005"
    name = "Function has more than one point of exit"
    category = "standards"
    severity = Severity.INFO
    description = (
        "A function has three or more points of exit."
    )
    rationale = (
        "A single exit point keeps the cleanup of a function in one place "
        "and makes the control flow easier to review."
    )
    recommendation = (
        "Collect the result of the function in a single variable and return "
        "it once at the end of the function."
    )
    standards = ("MISRA C:2012 Rule 15.5",)
    tags = ("misra", "control-flow", "advisory")

    def check(self, ctx):
        prepare(ctx)
        for function in iter_functions(ctx):
            body = function.body
            if body is None:
                continue
            returns = [node for node in body.walk() if isinstance(node, ReturnStmt)]
            if len(returns) < 3:
                continue
            yield ctx.report(
                self,
                function,
                f"the function has {len(returns)} exit points but should "
                "have a single point of exit at the end",
            )


@register
class LoopBodyNotCompound(Rule):
    id = "MISRA-15-006"
    name = "Body of an iteration statement is not a compound statement"
    category = "standards"
    severity = Severity.LOW
    description = (
        "The body of a for, while or do while statement is not enclosed in "
        "braces."
    )
    rationale = (
        "An unbraced body is easy to extend by accident and hides the "
        "extent of the loop."
    )
    recommendation = "Enclose the body of the iteration statement in braces."
    standards = ("MISRA C:2012 Rule 15.6",)
    tags = ("misra", "braces", "control-flow")

    def check(self, ctx):
        prepare(ctx)
        for node in ctx.unit.walk():
            if not isinstance(node, (ForStmt, WhileStmt, DoWhileStmt, RangeForStmt)):
                continue
            body = node.body
            if body is None or isinstance(body, CompoundStmt):
                continue
            yield ctx.report(
                self,
                body,
                "the body of the iteration statement is not a compound "
                "statement",
            )


@register
class BranchBodyNotCompound(Rule):
    id = "MISRA-15-007"
    name = "Body of an if or else statement is not a compound statement"
    category = "standards"
    severity = Severity.LOW
    description = (
        "The body of an if or else statement is not enclosed in braces."
    )
    rationale = (
        "An unbraced branch is easy to extend by accident and is a frequent "
        "source of dangling statement bugs."
    )
    recommendation = "Enclose the body of the branch in braces."
    standards = ("MISRA C:2012 Rule 15.7",)
    tags = ("misra", "braces", "control-flow")

    def check(self, ctx):
        prepare(ctx)
        for node in ctx.unit.walk():
            if not isinstance(node, IfStmt):
                continue
            then_branch = node.then_branch
            if then_branch is not None and not isinstance(then_branch, CompoundStmt):
                yield ctx.report(
                    self,
                    then_branch,
                    "the body of the if statement is not a compound statement",
                )
            else_branch = node.else_branch
            if else_branch is None:
                continue
            if isinstance(else_branch, (CompoundStmt, IfStmt)):
                continue
            yield ctx.report(
                self,
                else_branch,
                "the body of the else statement is not a compound statement",
            )


@register
class SwitchWithoutDefault(Rule):
    id = "MISRA-16-004"
    name = "Switch statement without a default label"
    category = "standards"
    severity = Severity.MEDIUM
    description = "A switch statement does not have a default label."
    rationale = (
        "Without a default label the behaviour of the statement depends on "
        "the value of the controlling expression and is easy to overlook."
    )
    recommendation = (
        "Add a default label that handles the unexpected values of the "
        "controlling expression."
    )
    standards = ("MISRA C:2012 Rule 16.4",)
    tags = ("misra", "switch", "control-flow")

    def check(self, ctx):
        prepare(ctx)
        for node in ctx.unit.walk():
            if not isinstance(node, SwitchStmt):
                continue
            labels = _switch_labels(node)
            if any(isinstance(label, DefaultStmt) for label in labels):
                continue
            yield ctx.report(
                self,
                node,
                "the switch statement does not have a default label",
            )


@register
class DefaultLabelNotFirstOrLast(Rule):
    id = "MISRA-16-005"
    name = "Default label is neither the first nor the last label"
    category = "standards"
    severity = Severity.LOW
    description = (
        "The default label of a switch statement stands between two other "
        "labels."
    )
    rationale = (
        "A default label in the middle of a switch statement hides the "
        "fall through into the labels that follow it."
    )
    recommendation = (
        "Move the default label to the first or to the last position of the "
        "switch statement."
    )
    standards = ("MISRA C:2012 Rule 16.5",)
    tags = ("misra", "switch", "control-flow")

    def check(self, ctx):
        prepare(ctx)
        for node in ctx.unit.walk():
            if not isinstance(node, SwitchStmt):
                continue
            labels = _switch_labels(node)
            if len(labels) < 2:
                continue
            for index, label in enumerate(labels):
                if not isinstance(label, DefaultStmt):
                    continue
                if index == 0 or index == len(labels) - 1:
                    continue
                yield ctx.report(
                    self,
                    label,
                    "the default label is neither the first nor the last "
                    "label of the switch statement",
                )


@register
class ReturnValueNotUsed(Rule):
    id = "MISRA-17-007"
    name = "Return value of a function is not used"
    category = "standards"
    severity = Severity.MEDIUM
    description = (
        "A function with a non void return type is called as a statement, "
        "so its return value is discarded."
    )
    rationale = (
        "The result of the call often carries the error indication, and "
        "ignoring it hides the failure."
    )
    recommendation = (
        "Store the return value and check it, or call a function that "
        "returns void."
    )
    standards = ("MISRA C:2012 Rule 17.7",)
    tags = ("misra", "return", "error-handling")

    def check(self, ctx):
        prepare(ctx)
        for node in ctx.unit.walk():
            if not isinstance(node, ExprStmt):
                continue
            expression = node.expression
            if isinstance(expression, Cast):
                expression = expression.operand
            if not isinstance(expression, Call):
                continue
            return_type = _call_return_type(ctx, expression)
            if return_type is None:
                continue
            category = _category(ctx, return_type)
            if category in {"void", "unknown"}:
                continue
            yield ctx.report(
                self,
                node,
                f"the value returned by {expression.callee_name}() is not used",
            )


@register
class PointerArithmeticOutsideArray(Rule):
    id = "MISRA-18-001"
    name = "Pointer arithmetic points outside the array"
    category = "standards"
    severity = Severity.HIGH
    description = (
        "A pointer arithmetic expression or an array index refers to an "
        "element outside of the array."
    )
    rationale = (
        "The access is outside of the object and therefore undefined "
        "behaviour."
    )
    recommendation = (
        "Check the index against the size of the array before the access."
    )
    standards = ("MISRA C:2012 Rule 18.1",)
    tags = ("misra", "array", "pointer")

    def check(self, ctx):
        prepare(ctx)
        for node in ctx.unit.walk():
            if isinstance(node, IndexAccess):
                try:
                    index = ctx.const_int(node.index)
                except Exception:
                    index = None
                if index is None:
                    continue
                size = _array_size(ctx, node.object)
                if size is None:
                    continue
                if index < 0 or index >= size:
                    yield ctx.report(
                        self,
                        node,
                        f"the index {index} is outside of the array with "
                        f"{size} element(s)",
                    )
                continue
            if not isinstance(node, BinaryOp):
                continue
            if node.operator not in POINTER_ARITHMETIC_OPERATORS:
                continue
            left = _category(ctx, _expression_type(ctx, node.left))
            right = _category(ctx, _expression_type(ctx, node.right))
            if left == "pointer" and right in {"int", "uint"}:
                pointer = node.left
                offset = node.right
            elif node.operator == "+" and right == "pointer" and left in {"int", "uint"}:
                pointer = node.right
                offset = node.left
            else:
                continue
            try:
                distance = ctx.const_int(offset)
            except Exception:
                distance = None
            if distance is None:
                continue
            size = _array_size(ctx, pointer)
            if size is None:
                continue
            if distance >= size:
                yield ctx.report(
                    self,
                    node,
                    f"the pointer arithmetic moves {distance} element(s) "
                    f"beyond the array with {size} element(s)",
                )


@register
class DynamicMemoryFunctions(Rule):
    id = "MISRA-21-006"
    name = "Standard library memory management function used"
    category = "standards"
    severity = Severity.MEDIUM
    description = (
        "A memory allocation or deallocation function of the standard "
        "library is used."
    )
    rationale = (
        "The dynamic memory of the standard library cannot be sized at "
        "compile time, so the memory footprint of the program is not "
        "predictable."
    )
    recommendation = (
        "Use static or stack memory with a size that is known at compile "
        "time."
    )
    standards = ("MISRA C:2012 Rule 21.6",)
    tags = ("misra", "memory", "stdlib")

    def check(self, ctx):
        prepare(ctx)
        for call in find_calls(ctx, *sorted(MEMORY_FUNCTIONS)):
            yield ctx.report(
                self,
                call,
                f"the standard library function {call.callee_name}() must not "
                "be used",
            )


@register
class TimeFunctions(Rule):
    id = "MISRA-21-010"
    name = "Standard library time function used"
    category = "standards"
    severity = Severity.MEDIUM
    description = "A time function of the standard library is used."
    rationale = (
        "The time functions are not portable and make the behaviour of the "
        "program depend on the environment it runs in."
    )
    recommendation = (
        "Take the time from a platform specific interface that is covered "
        "by the requirements of the project."
    )
    standards = ("MISRA C:2012 Rule 21.10",)
    tags = ("misra", "time", "stdlib")

    def check(self, ctx):
        prepare(ctx)
        for call in find_calls(ctx, *sorted(TIME_FUNCTIONS)):
            yield ctx.report(
                self,
                call,
                f"the standard library function {call.callee_name}() must not "
                "be used",
            )


@register
class ExceptionHandlingUsed(Rule):
    id = "MISRA-21-012"
    name = "Exception handling features used"
    category = "standards"
    severity = Severity.MEDIUM
    description = (
        "The exception handling features of the language are used."
    )
    rationale = (
        "The unwinding of the stack during an exception makes the control "
        "flow of the program hard to predict and hard to test."
    )
    recommendation = (
        "Report the error with a return value and handle it in the caller."
    )
    standards = ("MISRA C:2012 Rule 21.12",)
    tags = ("misra", "exception", "control-flow")

    def check(self, ctx):
        prepare(ctx)
        for node in ctx.unit.walk():
            if isinstance(node, (TryStmt, ThrowStmt, CatchClause)):
                yield ctx.report(
                    self,
                    node,
                    "the exception handling features must not be used",
                )
