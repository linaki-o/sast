"""Security rule pack for CodeShield.

The rules in this module look for the classic C/C++ security weaknesses:
buffer overflows, format string abuse, command and SQL injection, use after
free, unchecked return values, weak cryptography and hard coded secrets.
"""

from __future__ import annotations

from sast.ast.nodes import (
    Assignment,
    BinaryOp,
    Call,
    Cast,
    ClassDecl,
    ConditionalOp,
    DeclStmt,
    DeleteExpr,
    Expr,
    ExprStmt,
    FieldDecl,
    Identifier,
    IfStmt,
    IndexAccess,
    Literal,
    MemberAccess,
    NewExpr,
    Node,
    ReturnStmt,
    UnaryOp,
    VariableDecl,
)
from sast.core.models import Severity
from sast.rules.base import Rule, register
from sast.rules.builtin import (
    base_name,
    buffer_capacity,
    find_calls,
    find_calls_ci,
    format_specifier_count,
    is_null_expression,
    iter_functions,
    matches_sensitive,
    prepare,
    resolve_type,
    signedness,
    sizeof_capacity,
    string_value,
)

CREDENTIAL_WORDS = frozenset(
    {
        "password",
        "passwd",
        "pwd",
        "passphrase",
        "secret",
        "token",
        "key",
        "apikey",
        "credential",
        "credentials",
    }
)

SENSITIVE_WORDS = frozenset(
    {
        "password",
        "passwd",
        "pwd",
        "passphrase",
        "secret",
        "token",
        "key",
        "apikey",
        "credential",
        "credentials",
        "nonce",
        "salt",
        "seed",
        "session",
    }
)

SECURITY_CONTEXT_WORDS = frozenset(
    {
        "password",
        "passwd",
        "pwd",
        "passphrase",
        "secret",
        "token",
        "key",
        "auth",
        "login",
        "hash",
        "digest",
        "checksum",
        "fingerprint",
        "sign",
        "signature",
        "crypt",
        "credential",
        "session",
        "cookie",
        "jwt",
        "cert",
        "verify",
        "validate",
        "integrity",
    }
)

TAINTED_WORDS = frozenset(
    {
        "user",
        "username",
        "login",
        "input",
        "inp",
        "name",
        "param",
        "arg",
        "argv",
        "request",
        "path",
        "file",
        "filename",
        "dir",
        "directory",
        "url",
        "uri",
        "query",
        "value",
        "data",
        "src",
        "source",
        "dest",
        "target",
        "cmd",
        "command",
    }
)

SQL_BUFFER_WORDS = frozenset(
    {"sql", "query", "stmt", "statement", "sqlbuf", "sqlquery", "command", "cmd"}
)

FORMAT_ARGUMENT_INDEX = {
    "printf": 0,
    "printf_s": 0,
    "fprintf": 1,
    "fprintf_s": 1,
    "sprintf": 1,
    "sprintf_s": 1,
    "snprintf": 2,
    "snprintf_s": 2,
    "syslog": 1,
    "vprintf": 0,
    "vfprintf": 1,
    "vsprintf": 1,
    "vsnprintf": 2,
    "dprintf": 1,
    "asprintf": 1,
    "err": 1,
    "warn": 1,
    "errx": 1,
    "warnx": 1,
}

COMMAND_FUNCTIONS = {
    "system",
    "popen",
    "popen_s",
    "execl",
    "execv",
    "execvp",
    "execle",
    "execlp",
    "execvpe",
    "execve",
    "WinExec",
    "CreateProcess",
    "ShellExecute",
    "ShellExecuteA",
    "ShellExecuteW",
}

WEAK_HASH_FUNCTIONS = {
    "md5",
    "md5_init",
    "md5_update",
    "md5_final",
    "md5_transform",
    "sha1",
    "sha1_init",
    "sha1_update",
    "sha1_final",
    "sha1_transform",
    "evp_md5",
    "evp_sha1",
}

ECB_FUNCTIONS = {
    "des_ecb_encrypt",
    "des_ecb_decrypt",
    "aes_ecb_encrypt",
    "aes_ecb_decrypt",
    "ecb_encrypt",
    "ecb_decrypt",
}
NULL_RETURNING_FUNCTIONS = {
    "malloc",
    "calloc",
    "realloc",
    "fopen",
    "getenv",
    "strchr",
    "strstr",
    "open",
}

NON_NULL_ARGUMENTS = {
    "memcpy": (0, 1),
    "memmove": (0, 1),
    "memset": (0,),
    "strcpy": (0,),
    "strncpy": (0,),
    "strcat": (0,),
    "strncat": (0,),
    "strcmp": (0, 1),
    "strncmp": (0, 1),
    "strlen": (0,),
    "fgets": (0,),
    "fread": (0,),
    "fwrite": (0,),
    "puts": (0,),
    "strtok": (0,),
}

ALLOCATORS = {"malloc", "calloc"}


def _source_length(ctx, source: Expr | None) -> int | None:
    """The number of bytes a string source may contribute."""
    literal = string_value(source)
    if literal is not None:
        return len(literal) + 1
    capacity = buffer_capacity(ctx, source)
    if capacity is not None:
        return capacity + 1
    return None


def _null_checked_name(ctx, condition: Expr | None) -> tuple[str | None, bool]:
    """The variable a null check applies to.

    The second element of the result tells whether the branch that follows
    the condition proves that the pointer is *not* null, which is the case
    for a comparison with ``!=``.
    """
    if condition is None:
        return None, False
    try:
        if not ctx.is_null_check(condition):
            return None, False
    except Exception:
        return None, False
    if isinstance(condition, BinaryOp) and condition.operator in {"==", "!="}:
        for side in (condition.left, condition.right):
            if isinstance(side, Identifier) and not is_null_expression(side):
                return side.name, condition.operator == "!="
        return None, False
    if isinstance(condition, UnaryOp) and condition.operator == "!":
        operand = condition.operand
        if isinstance(operand, Identifier) and not is_null_expression(operand):
            return operand.name, False
        return None, False
    return None, False


def _is_dereference(node: Node) -> bool:
    """Is the identifier used in a way that dereferences the pointer?"""
    parent = node.parent
    if parent is None:
        return False
    if isinstance(parent, UnaryOp) and parent.operator == "*":
        return True
    if isinstance(parent, MemberAccess) and parent.operator == "->":
        return True
    if isinstance(parent, IndexAccess):
        return True
    if isinstance(parent, Call):
        return True
    return False


def _subtree_ids(node: Node) -> set[int]:
    return {id(child) for child in node.walk()}


def _assigned_names(branch: Node | None) -> set[str]:
    """Names that are assigned inside *branch*."""
    names: set[str] = set()
    if branch is None:
        return names
    for node in branch.walk():
        if isinstance(node, Assignment) and isinstance(node.target, Identifier):
            names.add(node.target.name)
        elif isinstance(node, DeclStmt):
            for declaration in getattr(node, "declarations", []) or []:
                if getattr(declaration, "init", None) is not None:
                    names.add(declaration.name)
    return names


def _assigned_before(body: Node, scope: Node, name: str) -> bool:
    """Is *name* assigned before *scope* in the same function?"""
    line = scope.location.line
    inside = _subtree_ids(scope)
    for node in body.walk():
        if id(node) in inside:
            continue
        if node.location.line >= line:
            continue
        if isinstance(node, Assignment) and isinstance(node.target, Identifier):
            if node.target.name == name:
                return True
        elif isinstance(node, VariableDecl):
            if node.name == name and getattr(node, "init", None) is not None:
                return True
        elif isinstance(node, UnaryOp) and node.operator in {
            "++",
            "--",
            "post++",
            "post--",
        }:
            operand = node.operand
            if isinstance(operand, Identifier) and operand.name == name:
                return True
    return False


def _used_after(body: Node, scope: Node, name: str) -> bool:
    """Is *name* read after *scope* in the same function?"""
    line = scope.location.line
    inside = _subtree_ids(scope)
    for node in body.walk():
        if not isinstance(node, Identifier) or node.name != name:
            continue
        if id(node) in inside:
            continue
        if node.location.line <= line:
            continue
        return True
    return False


def _free_target(node: Node) -> tuple[str | None, Node | None]:
    """The identifier a ``free``/``delete`` statement releases."""
    if isinstance(node, DeleteExpr):
        return base_name(node.operand), node
    if isinstance(node, Call) and node.callee_name == "free" and node.arguments:
        return base_name(node.arguments[0]), node
    return None, None


def _access_path(expression: Expr | None) -> str | None:
    """The path of an lvalue chain.

    ``buffer->items[2]`` becomes ``buffer.items[]`` so that two accesses to
    the same object always share the same path, no matter how the object is
    reached.
    """
    if expression is None:
        return None
    if isinstance(expression, Identifier):
        return expression.name
    if isinstance(expression, MemberAccess):
        base = _access_path(expression.object)
        if base is None:
            return None
        return f"{base}.{expression.member}"
    if isinstance(expression, IndexAccess):
        base = _access_path(expression.object)
        if base is None:
            return None
        return f"{base}[]"
    if isinstance(expression, Cast):
        return _access_path(expression.operand)
    if isinstance(expression, UnaryOp) and expression.operator == "*":
        base = _access_path(expression.operand)
        if base is None:
            return None
        return f"*{base}"
    return None


def _release_site(node: Node) -> tuple[str | None, Node | None, Expr | None]:
    """The object a ``free``/``delete`` statement releases."""
    if isinstance(node, DeleteExpr):
        return _access_path(node.operand), node, node.operand
    if isinstance(node, Call) and node.callee_name == "free" and node.arguments:
        operand = node.arguments[0]
        return _access_path(operand), node, operand
    return None, None, None


def _assignment_target(node: Expr) -> Assignment | None:
    """The assignment *node* is the target of, if any."""
    parent = node.parent
    if isinstance(parent, Assignment) and parent.target is node:
        return parent
    return None


def _references_path(expression: Expr | None, path: str) -> bool:
    """Does *expression* access the object with the given *path*?"""
    if expression is None:
        return False
    for node in expression.walk():
        if _access_path(node) == path:
            return True
    return False


def _call_is_checked(ctx, call: Call) -> bool:
    """Is the result of *call* compared against NULL?"""
    parent = call.parent
    while isinstance(parent, Cast) and parent.parent is not None:
        parent = parent.parent
    if parent is None:
        return False
    if isinstance(parent, BinaryOp) and parent.operator in {"==", "!="}:
        try:
            return bool(ctx.is_null_check(parent))
        except Exception:
            return False
    if isinstance(parent, UnaryOp) and parent.operator == "!":
        return True
    if isinstance(parent, ConditionalOp):
        return True
    name = None
    if isinstance(parent, Assignment) and isinstance(parent.target, Identifier):
        name = parent.target.name
    elif isinstance(parent, VariableDecl):
        name = parent.name
    elif isinstance(parent, DeclStmt):
        for declaration in getattr(parent, "declarations", []) or []:
            if getattr(declaration, "init", None) is call:
                name = declaration.name
    if name is None:
        return False
    function = ctx.enclosing_function(call)
    if function is None or function.body is None:
        return False
    for node in function.body.walk():
        if not isinstance(node, BinaryOp) or node.operator not in {"==", "!="}:
            continue
        for side in (node.left, node.right):
            if isinstance(side, Identifier) and side.name == name:
                try:
                    if ctx.is_null_check(node):
                        return True
                except Exception:
                    return False
    return False


def _assigned_call_name(ctx, call: Call) -> str | None:
    """The variable the result of *call* is stored in."""
    parent = call.parent
    if isinstance(parent, Assignment) and isinstance(parent.target, Identifier):
        return parent.target.name
    if isinstance(parent, VariableDecl):
        return parent.name
    if isinstance(parent, DeclStmt):
        for declaration in getattr(parent, "declarations", []) or []:
            if getattr(declaration, "init", None) is call:
                return declaration.name
    return None


def _is_released(body: Node, name: str) -> bool:
    """Is the memory of *name* released or handed back?"""
    for node in body.walk():
        freed, _ = _free_target(node)
        if freed == name:
            return True
        if isinstance(node, ReturnStmt):
            if base_name(node.value) == name:
                return True
    return False


def _class_names(function: FunctionDecl) -> list[str]:
    """The names of the classes the function is a member of."""
    names: list[str] = []
    current: Node | None = function.parent
    while current is not None:
        if isinstance(current, ClassDecl) and current.name not in names:
            names.append(current.name)
        current = current.parent
    qualified = getattr(function, "qualified_name", "") or getattr(function, "name", "")
    parts = str(qualified).split("::")
    for index in range(1, len(parts)):
        candidate = "::".join(parts[:index])
        if candidate not in names:
            names.append(candidate)
    return names


def _class_field(ctx, class_name: str, name: str) -> bool:
    """Does the class own a field called *name*?"""
    for node in ctx.unit.walk():
        if not isinstance(node, ClassDecl) or node.name != class_name:
            continue
        for member in node.members:
            if isinstance(member, FieldDecl) and member.name == name:
                return True
    return False


def _is_class_member(ctx, function: FunctionDecl, name: str) -> bool:
    """Is *name* a member of the class that *function* belongs to?

    A member is usually released by the destructor of its class, so an
    assignment to it is not a leak of the function.
    """
    if not name:
        return False
    for class_name in _class_names(function):
        if _class_field(ctx, class_name, name):
            return True
    return False


def _declared_locally(function: FunctionDecl, name: str) -> bool:
    """Is *name* a local variable or a parameter of *function*?"""
    for parameter in function.parameters:
        if parameter.name == name:
            return True
    body = function.body
    if body is None:
        return False
    for node in body.walk():
        if isinstance(node, VariableDecl) and node.name == name:
            return True
    return False


def _security_context(ctx, call: Call) -> str | None:
    """The security related word that makes a weak hash a real finding."""
    function = ctx.enclosing_function(call)
    if function is not None:
        for word in SECURITY_CONTEXT_WORDS:
            if word in function.name.lower():
                return word
        document = ctx.doc_comment_for(function)
        for word in SECURITY_CONTEXT_WORDS:
            if word in document.lower():
                return word
    name = _assigned_call_name(ctx, call)
    if name:
        for word in SECURITY_CONTEXT_WORDS:
            if matches_sensitive(name, {word}):
                return word
    for argument in call.arguments:
        for word in SECURITY_CONTEXT_WORDS:
            if matches_sensitive(base_name(argument) or "", {word}):
                return word
    return None


@register
class UnboundedStringCopy(Rule):
    id = "SEC-BUF-001"
    name = "Unbounded string copy into a fixed buffer"
    category = "security"
    severity = Severity.HIGH
    description = (
        "strcpy and strcat copy an amount of data that is not limited by the "
        "size of the destination buffer."
    )
    rationale = (
        "The copy can write past the end of the buffer and corrupt the stack "
        "or the heap."
    )
    recommendation = (
        "Use strncpy or snprintf with the explicit size of the destination "
        "buffer and terminate the result when needed."
    )
    cwe = (120, 787)
    standards = ("MISRA C:2012 Rule 21.6", "CERT STR31-C")
    tags = ("buffer", "overflow", "string")

    def check(self, ctx):
        prepare(ctx)
        for call in find_calls(ctx, "strcpy", "strcat"):
            if len(call.arguments) < 2:
                continue
            capacity = buffer_capacity(ctx, call.arguments[0])
            if capacity is None:
                continue
            length = _source_length(ctx, call.arguments[1])
            if length is not None and length <= capacity:
                continue
            if length is None:
                message = (
                    f"{call.callee_name}() copies an unbounded amount of data "
                    f"into a buffer of {capacity} byte(s)"
                )
            else:
                message = (
                    f"{call.callee_name}() may copy {length} byte(s) into a "
                    f"buffer of {capacity} byte(s)"
                )
            yield ctx.report(self, call, message)


@register
class UnsafeGetsAndFgets(Rule):
    id = "SEC-BUF-002"
    name = "Unsafe use of gets or fgets"
    category = "security"
    severity = Severity.CRITICAL
    description = (
        "gets() cannot bound the amount of data it writes and fgets() may be "
        "called with a size that exceeds the destination buffer."
    )
    rationale = "Both functions are a classic entry point for stack overflows."
    recommendation = (
        "Replace gets() with fgets() and always pass the real size of the "
        "destination buffer."
    )
    cwe = (120, 242)
    standards = ("MISRA C:2012 Rule 21.6", "CERT STR31-C")
    tags = ("buffer", "overflow", "stdio")

    def check(self, ctx):
        prepare(ctx)
        for call in find_calls(ctx, "gets"):
            yield ctx.report(
                self,
                call,
                "gets() writes an unbounded amount of data into the buffer; "
                "use fgets() with the buffer size instead",
                severity=Severity.CRITICAL,
            )
        for call in find_calls(ctx, "fgets"):
            if len(call.arguments) < 2:
                continue
            capacity = buffer_capacity(ctx, call.arguments[0])
            if capacity is None:
                continue
            size = ctx.const_int(call.arguments[1])
            if size is None:
                continue
            if size <= 0:
                yield ctx.report(
                    self,
                    call,
                    f"fgets() is called with a size of {size}; nothing can be read",
                    severity=Severity.LOW,
                )
            elif size > capacity:
                yield ctx.report(
                    self,
                    call,
                    f"fgets() may write {size} byte(s) into a buffer of "
                    f"{capacity} byte(s)",
                )


@register
class UnboundedSprintf(Rule):
    id = "SEC-BUF-003"
    name = "sprintf writes into a fixed buffer"
    category = "security"
    severity = Severity.HIGH
    description = "sprintf() formats into a buffer without any size limit."
    rationale = "A long input overflows the destination buffer."
    recommendation = "Use snprintf() and check the returned length."
    cwe = (120, 121)
    standards = ("MISRA C:2012 Rule 21.6", "CERT STR31-C")
    tags = ("buffer", "overflow", "format")

    def check(self, ctx):
        prepare(ctx)
        for call in find_calls(ctx, "sprintf", "vsprintf"):
            if not call.arguments:
                continue
            capacity = buffer_capacity(ctx, call.arguments[0])
            if capacity is None:
                continue
            yield ctx.report(
                self,
                call,
                f"{call.callee_name}() formats an unbounded string into a "
                f"buffer of {capacity} byte(s); use snprintf()",
            )


@register
class OversizedMemcpy(Rule):
    id = "SEC-BUF-004"
    name = "memcpy or memmove copies more than the destination can hold"
    category = "security"
    severity = Severity.HIGH
    description = (
        "The length passed to memcpy()/memmove() is statically larger than "
        "the destination buffer."
    )
    rationale = "The copy writes past the end of the destination buffer."
    recommendation = "Check the length against the capacity of the buffer."
    cwe = (120, 787)
    standards = ("MISRA C:2012 Rule 21.6", "CERT STR31-C")
    tags = ("buffer", "overflow", "memory")

    def check(self, ctx):
        prepare(ctx)
        for call in find_calls(ctx, "memcpy", "memmove"):
            if len(call.arguments) < 3:
                continue
            capacity = buffer_capacity(ctx, call.arguments[0])
            if capacity is None:
                continue
            length = ctx.const_int(call.arguments[2])
            if length is None:
                continue
            if length > capacity:
                yield ctx.report(
                    self,
                    call,
                    f"{call.callee_name}() copies {length} byte(s) into a "
                    f"buffer of {capacity} byte(s)",
                )


@register
class StrncpyWithoutTermination(Rule):
    id = "SEC-BUF-005"
    name = "strncpy result may not be null terminated"
    category = "security"
    severity = Severity.MEDIUM
    description = (
        "strncpy() does not terminate the destination when the source is "
        "longer than the requested count."
    )
    rationale = "The result can be used as a string although it is not one."
    recommendation = "Terminate the buffer manually or use snprintf()."
    cwe = (170, 120)
    standards = ("MISRA C:2012 Rule 21.6",)
    tags = ("buffer", "string", "termination")

    def check(self, ctx):
        prepare(ctx)
        for call in find_calls(ctx, "strncpy"):
            if len(call.arguments) < 3:
                continue
            capacity = buffer_capacity(ctx, call.arguments[0])
            if capacity is None:
                continue
            count = ctx.const_int(call.arguments[2])
            if count is None:
                count = sizeof_capacity(ctx, call.arguments[2])
            if count is None:
                continue
            if count >= capacity:
                yield ctx.report(
                    self,
                    call,
                    f"strncpy() copies up to {count} byte(s) into a buffer of "
                    f"{capacity} byte(s) and leaves it unterminated",
                )


@register
class NonConstantFormatString(Rule):
    id = "SEC-FMT-001"
    name = "Non constant format string"
    category = "security"
    severity = Severity.HIGH
    description = (
        "A printf() family function is called with a format string that is "
        "not a string literal."
    )
    rationale = (
        "An attacker controlled format string can read and write arbitrary "
        "memory."
    )
    recommendation = "Always pass a literal format string to the function."
    cwe = (134,)
    standards = ("MISRA C:2012 Rule 21.6", "CERT FIO30-C")
    tags = ("format", "injection", "printf")

    def check(self, ctx):
        prepare(ctx)
        for name, index in FORMAT_ARGUMENT_INDEX.items():
            for call in find_calls(ctx, name):
                if len(call.arguments) <= index:
                    continue
                if string_value(call.arguments[index]) is not None:
                    continue
                yield ctx.report(
                    self,
                    call,
                    f"{name}() is called with a format string that is not a "
                    "string literal",
                )


@register
class FormatArgumentMismatch(Rule):
    id = "SEC-FMT-002"
    name = "Format string argument count mismatch"
    category = "security"
    severity = Severity.MEDIUM
    description = (
        "The number of arguments passed to a printf() family function does "
        "not match the number of conversions in the format string."
    )
    rationale = (
        "Missing or extra arguments make the function read or write values "
        "that do not exist."
    )
    recommendation = "Align the arguments with the format specifiers."
    cwe = (134, 685)
    standards = ("MISRA C:2012 Rule 21.6", "CERT FIO31-C")
    tags = ("format", "printf")

    def check(self, ctx):
        prepare(ctx)
        for name, index in FORMAT_ARGUMENT_INDEX.items():
            for call in find_calls(ctx, name):
                if len(call.arguments) <= index:
                    continue
                text = string_value(call.arguments[index])
                if text is None:
                    continue
                conversions, stars = format_specifier_count(text)
                expected = conversions + stars
                provided = len(call.arguments) - index - 1
                if provided == expected:
                    continue
                yield ctx.report(
                    self,
                    call,
                    f"{name}() format string expects {expected} argument(s) "
                    f"but {provided} were supplied",
                )


@register
class CommandInjection(Rule):
    id = "SEC-CMD-001"
    name = "Command injection through a non constant command"
    category = "security"
    severity = Severity.CRITICAL
    description = (
        "system(), popen() or an exec() variant is called with a command "
        "that is not a string literal."
    )
    rationale = "Shell metacharacters in the command lead to arbitrary code execution."
    recommendation = (
        "Use exec() with an argument vector or validate the command against a "
        "whitelist."
    )
    cwe = (78,)
    owasp = ("A03:2021 - Injection",)
    standards = ("CERT ENV33-C",)
    tags = ("injection", "command", "shell")

    def check(self, ctx):
        prepare(ctx)
        for call in find_calls(ctx, *sorted(COMMAND_FUNCTIONS)):
            if not call.arguments:
                continue
            if string_value(call.arguments[0]) is not None:
                continue
            yield ctx.report(
                self,
                call,
                f"{call.callee_name}() is called with a command that is not a "
                "string literal and can be influenced by an attacker",
            )


@register
class SqlInjection(Rule):
    id = "SEC-SQLE-001"
    name = "SQL statement built by string concatenation"
    category = "security"
    severity = Severity.HIGH
    description = (
        "A SQL statement is assembled by copying or concatenating text into "
        "a buffer instead of using bound parameters."
    )
    rationale = "Concatenated input allows an attacker to change the query."
    recommendation = "Use prepared statements with bound parameters."
    cwe = (89,)
    owasp = ("A03:2021 - Injection",)
    standards = ()
    tags = ("injection", "sql", "database")

    def check(self, ctx):
        prepare(ctx)
        for call in find_calls(ctx, "strcpy", "strcat", "strncpy", "strncat", "sprintf", "snprintf"):
            if not call.arguments:
                continue
            destination = base_name(call.arguments[0])
            if destination is None or not matches_sensitive(destination, SQL_BUFFER_WORDS):
                continue
            yield ctx.report(
                self,
                call,
                f"the SQL statement in '{destination}' is built with "
                f"{call.callee_name}(); use bound parameters instead",
            )
        for node in ctx.unit.walk():
            if not isinstance(node, Assignment):
                continue
            if not isinstance(node.target, Identifier):
                continue
            if not matches_sensitive(node.target.name, SQL_BUFFER_WORDS):
                continue
            value = node.value
            if isinstance(value, BinaryOp) and value.operator == "+":
                yield ctx.report(
                    self,
                    node,
                    f"the SQL statement in '{node.target.name}' is built by "
                    "concatenation; use bound parameters instead",
                )


@register
class PathTraversal(Rule):
    id = "SEC-PATH-001"
    name = "File path built from an untrusted value"
    category = "security"
    severity = Severity.HIGH
    description = (
        "A file is opened with a path that is built by concatenation or that "
        "is taken from an externally controlled variable."
    )
    rationale = "Traversal sequences in the path grant access to other files."
    recommendation = (
        "Normalise the path and verify that it stays inside the intended "
        "directory."
    )
    cwe = (22,)
    owasp = ("A01:2021 - Broken Access Control",)
    standards = ("CERT FIO15-C",)
    tags = ("path", "traversal", "file")

    def check(self, ctx):
        prepare(ctx)
        for call in find_calls(ctx, "fopen", "fopen_s", "freopen", "open", "openat"):
            if not call.arguments:
                continue
            path = call.arguments[0]
            if isinstance(path, BinaryOp) and path.operator == "+":
                yield ctx.report(
                    self,
                    call,
                    f"{call.callee_name}() uses a path that is built by "
                    "concatenation and may contain traversal sequences",
                )
                continue
            name = base_name(path)
            if name is None or not matches_sensitive(name, TAINTED_WORDS):
                continue
            yield ctx.report(
                self,
                call,
                f"{call.callee_name}() uses the externally controlled path "
                f"'{name}' which may contain traversal sequences",
            )


@register
class MissingUrlEncoding(Rule):
    id = "SEC-URL-001"
    name = "URL assembled without encoding"
    category = "security"
    severity = Severity.MEDIUM
    description = "A URL is built by concatenating unencoded values."
    rationale = (
        "Unencoded characters such as & or # allow an attacker to change the "
        "meaning of the URL."
    )
    recommendation = "URL encode every dynamic part of the URL."
    cwe = (116,)
    owasp = ("A03:2021 - Injection",)
    standards = ()
    tags = ("url", "encoding", "web")

    def check(self, ctx):
        prepare(ctx)
        for node in ctx.unit.walk():
            if not isinstance(node, BinaryOp) or node.operator != "+":
                continue
            for side in (node.left, node.right):
                text = string_value(side)
                if text is None:
                    continue
                if "http://" in text or "https://" in text:
                    yield ctx.report(
                        self,
                        node,
                        "the URL is assembled by concatenation; URL encode the "
                        "dynamic parts",
                    )
                    break


@register
class NullPointerDereference(Rule):
    id = "SEC-NULL-001"
    name = "Pointer dereferenced after a null check"
    category = "security"
    severity = Severity.HIGH
    description = (
        "A pointer that was compared against NULL is used in the branch that "
        "handles the null case."
    )
    rationale = "Dereferencing a null pointer usually terminates the process."
    recommendation = "Return early or handle the null case before the dereference."
    cwe = (476,)
    standards = ("MISRA C:2012 Rule 17.8",)
    tags = ("null", "pointer", "crash")

    def check(self, ctx):
        prepare(ctx)
        for node in ctx.unit.walk():
            if not isinstance(node, IfStmt):
                continue
            name, negated = _null_checked_name(ctx, node.condition)
            if name is None:
                continue
            branch = node.else_branch if negated else node.then_branch
            if branch is None:
                continue
            for use in branch.walk():
                if not isinstance(use, Identifier) or use.name != name:
                    continue
                if not _is_dereference(use):
                    continue
                yield ctx.report(
                    self,
                    use,
                    f"'{name}' is dereferenced although it was just compared "
                    "against NULL",
                )
                break


@register
class NullArgumentToNonNullParameter(Rule):
    id = "SEC-NULL-002"
    name = "NULL passed where a non null pointer is required"
    category = "security"
    severity = Severity.HIGH
    description = (
        "A library function that requires a valid pointer is called with "
        "NULL."
    )
    rationale = "The function dereferences the pointer and the program crashes."
    recommendation = "Check the pointer before the call and handle the error."
    cwe = (476,)
    standards = ("MISRA C:2012 Rule 17.8",)
    tags = ("null", "pointer", "api")

    def check(self, ctx):
        prepare(ctx)
        for name, indexes in NON_NULL_ARGUMENTS.items():
            for call in find_calls(ctx, name):
                for index in indexes:
                    if index >= len(call.arguments):
                        continue
                    if not is_null_expression(call.arguments[index]):
                        continue
                    yield ctx.report(
                        self,
                        call,
                        f"{name}() is called with NULL in argument "
                        f"{index + 1} but requires a valid pointer",
                    )


@register
class UncheckedNullReturn(Rule):
    id = "SEC-NULL-003"
    name = "Return value of a NULL returning function is not checked"
    category = "security"
    severity = Severity.MEDIUM
    description = (
        "A function that may return NULL is called without comparing the "
        "result against NULL."
    )
    rationale = "The result is dereferenced although the allocation or lookup failed."
    recommendation = "Check the result against NULL before using it."
    cwe = (252, 476)
    standards = ("MISRA C:2012 Rule 17.8", "CERT ERR34-C")
    tags = ("null", "error handling", "api")

    def check(self, ctx):
        prepare(ctx)
        for name in sorted(NULL_RETURNING_FUNCTIONS):
            for call in find_calls(ctx, name):
                if _call_is_checked(ctx, call):
                    continue
                yield ctx.report(
                    self,
                    call,
                    f"the result of {name}() is not compared against NULL "
                    "before it is used",
                )


@register
class UseAfterFree(Rule):
    id = "SEC-USE-001"
    name = "Use of a pointer after it was freed"
    category = "security"
    severity = Severity.HIGH
    description = "A variable is used after free() or delete released it."
    rationale = "The memory is gone; the access corrupts the heap."
    recommendation = "Set the pointer to NULL after freeing it and check it before use."
    cwe = (416,)
    standards = ("MISRA C:2012 Rule 17.8", "CERT MEM34-C")
    tags = ("memory", "free", "uaf")

    def check(self, ctx):
        prepare(ctx)
        for function in iter_functions(ctx):
            body = function.body
            if body is None:
                continue
            releases: list[tuple[str, Node, Expr | None]] = []
            for node in body.walk():
                path, release, operand = _release_site(node)
                if release is None or path is None:
                    continue
                releases.append((path, release, operand))
            released: set[int] = set()
            for path, release, operand in releases:
                if operand is not None:
                    released |= _subtree_ids(operand)
            for path, release, operand in releases:
                line = release.location.line
                inside = _subtree_ids(release)
                for other in body.walk():
                    if id(other) in inside or id(other) in released:
                        continue
                    if other.location.line <= line:
                        continue
                    if not isinstance(other, (Identifier, MemberAccess, IndexAccess)):
                        continue
                    if _access_path(other) != path:
                        continue
                    target = _assignment_target(other)
                    if target is not None:
                        if _references_path(target.value, path):
                            yield ctx.report(
                                self,
                                other,
                                f"'{path}' is read after it was released at "
                                f"line {line}",
                            )
                        break
                    yield ctx.report(
                        self,
                        other,
                        f"'{path}' is used after it was released at line {line}",
                    )
                    break


@register
class DoubleFree(Rule):
    id = "SEC-USE-002"
    name = "Double free"
    category = "security"
    severity = Severity.HIGH
    description = "The same pointer is released twice in one function."
    rationale = "A double free corrupts the heap allocator state."
    recommendation = "Set the pointer to NULL after the first release."
    cwe = (415,)
    standards = ("MISRA C:2012 Rule 17.8", "CERT MEM31-C")
    tags = ("memory", "free", "double-free")

    def check(self, ctx):
        prepare(ctx)
        for function in iter_functions(ctx):
            body = function.body
            if body is None:
                continue
            released: dict[str, Node] = {}
            for node in body.walk():
                name, release = _free_target(node)
                if release is None or name is None:
                    continue
                if name in released:
                    yield ctx.report(
                        self,
                        release,
                        f"'{name}' is released twice; the first release is at "
                        f"line {released[name].location.line}",
                    )
                    continue
                released[name] = release


@register
class MemoryLeak(Rule):
    id = "SEC-MEM-001"
    name = "Allocated memory is never released"
    category = "security"
    severity = Severity.MEDIUM
    description = (
        "The result of malloc(), calloc() or new is stored in a local "
        "variable that is neither freed nor returned."
    )
    rationale = "Every iteration of the enclosing loop leaks memory."
    recommendation = "Release the memory on every path or hand it to the caller."
    cwe = (401,)
    standards = ("MISRA C:2012 Rule 17.8", "CERT MEM31-C")
    tags = ("memory", "leak", "resource")

    def check(self, ctx):
        prepare(ctx)
        for function in iter_functions(ctx):
            body = function.body
            if body is None:
                continue
            for node in body.walk():
                if isinstance(node, Assignment) and isinstance(node.target, MemberAccess):
                    continue
                name = None
                if isinstance(node, Assignment) and isinstance(node.target, Identifier):
                    value = node.value
                    if isinstance(value, Call) and value.callee_name in ALLOCATORS:
                        name = node.target.name
                    elif isinstance(value, NewExpr):
                        name = node.target.name
                elif isinstance(node, DeclStmt):
                    for declaration in getattr(node, "declarations", []) or []:
                        init = getattr(declaration, "init", None)
                        if isinstance(init, Call) and init.callee_name in ALLOCATORS:
                            name = declaration.name
                        elif isinstance(init, NewExpr):
                            name = declaration.name
                if name is None:
                    continue
                if (
                    isinstance(node, Assignment)
                    and not _declared_locally(function, name)
                    and _is_class_member(ctx, function, name)
                ):
                    continue
                if _is_released(body, name):
                    continue
                yield ctx.report(
                    self,
                    node,
                    f"the memory allocated for '{name}' is never released and "
                    "not returned to the caller",
                )


@register
class IntegerOverflowInSizeExpression(Rule):
    id = "SEC-INT-001"
    name = "Integer overflow in a size expression"
    category = "security"
    severity = Severity.HIGH
    description = (
        "The size passed to memcpy() or malloc() is the result of a "
        "multiplication that can overflow."
    )
    rationale = "An overflowed size turns into a small allocation or a huge copy."
    recommendation = "Check the multiplication against the maximum size before use."
    cwe = (190, 191)
    standards = ("MISRA C:2012 Rule 17.8", "CERT INT32-C")
    tags = ("integer", "overflow", "memory")

    def check(self, ctx):
        prepare(ctx)
        for call in find_calls(ctx, "memcpy", "memmove"):
            if len(call.arguments) < 3:
                continue
            length = call.arguments[2]
            if not isinstance(length, BinaryOp) or length.operator != "*":
                continue
            yield ctx.report(
                self,
                call,
                f"the copy length is computed with a multiplication that can "
                "overflow",
            )
        for name in ("malloc", "calloc"):
            for call in find_calls(ctx, name):
                index = 1 if name == "calloc" else 0
                if len(call.arguments) <= index:
                    continue
                argument = call.arguments[index]
                if not isinstance(argument, BinaryOp) or argument.operator != "*":
                    continue
                yield ctx.report(
                    self,
                    call,
                    f"the size passed to {name}() is computed with a "
                    "multiplication that can overflow",
                )


@register
class SignedUnsignedComparison(Rule):
    id = "SEC-INT-002"
    name = "Signed and unsigned values are compared"
    category = "security"
    severity = Severity.MEDIUM
    description = "A relational comparison mixes a signed and an unsigned operand."
    rationale = (
        "The signed value is converted to unsigned, so a negative value "
        "becomes a large positive one and the comparison behaves unexpectedly."
    )
    recommendation = "Use matching types or cast both operands explicitly."
    cwe = (681,)
    standards = ("MISRA C:2012 Rule 10.4", "CERT INT15-C")
    tags = ("integer", "signedness", "comparison")

    def check(self, ctx):
        prepare(ctx)
        for node in ctx.unit.walk():
            if not isinstance(node, BinaryOp):
                continue
            if node.operator not in {"<", ">", "<=", ">="}:
                continue
            left = signedness(resolve_type(ctx, node.left))
            right = signedness(resolve_type(ctx, node.right))
            if left == 0 or right == 0 or left == right:
                continue
            yield ctx.report(
                self,
                node,
                "a signed value is compared with an unsigned value; the signed "
                "value is converted and the result may be unexpected",
            )


@register
class WeakRandomNumberGenerator(Rule):
    id = "SEC-RAND-001"
    name = "rand() used for a security sensitive value"
    category = "security"
    severity = Severity.HIGH
    description = (
        "rand() or srand() is used to produce a password, token, key or "
        "similar secret."
    )
    rationale = "The linear congruential generator of rand() is predictable."
    recommendation = "Use a cryptographic random generator such as arc4random_buf()."
    cwe = (338,)
    standards = ("MISRA C:2012 Rule 21.6", "CERT MSC30-C")
    tags = ("random", "crypto", "secret")

    def check(self, ctx):
        prepare(ctx)
        for call in find_calls(ctx, "rand", "random", "srand"):
            if call.callee_name == "srand":
                name = base_name(call.arguments[0]) if call.arguments else None
            else:
                name = _assigned_call_name(ctx, call)
            if name is None or not matches_sensitive(name, SENSITIVE_WORDS):
                function = ctx.enclosing_function(call)
                if function is None or not matches_sensitive(
                    function.name, SENSITIVE_WORDS
                ):
                    continue
                name = function.name
            yield ctx.report(
                self,
                call,
                f"'{name}' is derived from {call.callee_name}() which is not "
                "cryptographically secure",
            )


@register
class WeakHashAlgorithm(Rule):
    id = "SEC-CRYPTO-001"
    name = "Weak hash algorithm"
    category = "security"
    severity = Severity.MEDIUM
    description = "MD5 or SHA1 is used for a security relevant purpose."
    rationale = "Both algorithms have practical collision attacks."
    recommendation = "Use SHA-256 or better for integrity and signatures."
    cwe = (327, 328)
    standards = ("MISRA C:2012 Rule 21.6",)
    tags = ("crypto", "hash", "weak")

    def check(self, ctx):
        prepare(ctx)
        for call in find_calls_ci(ctx, *sorted(WEAK_HASH_FUNCTIONS)):
            context = _security_context(ctx, call)
            if context is None:
                continue
            yield ctx.report(
                self,
                call,
                f"{call.callee_name}() is a weak hash algorithm and must not "
                f"be used for {context} related data",
            )


@register
class EcbModeCipher(Rule):
    id = "SEC-CRYPTO-002"
    name = "ECB block cipher mode"
    category = "security"
    severity = Severity.HIGH
    description = "A cipher is configured with the ECB block cipher mode."
    rationale = "ECB leaks the structure of the plaintext and is not secure."
    recommendation = "Use an authenticated mode such as GCM or CBC with a random IV."
    cwe = (327,)
    standards = ()
    tags = ("crypto", "cipher", "ecb")

    def check(self, ctx):
        prepare(ctx)
        for node in ctx.unit.walk():
            if isinstance(node, Literal) and node.literal_type == "string":
                if "ECB" not in node.value.upper():
                    continue
                yield ctx.report(
                    self,
                    node,
                    "the cipher is configured with the ECB mode which does not "
                    "hide the structure of the plaintext",
                )
            elif isinstance(node, Call) and node.callee_name in ECB_FUNCTIONS:
                yield ctx.report(
                    self,
                    node,
                    f"{node.callee_name}() uses the ECB mode which does not "
                    "hide the structure of the plaintext",
                )


@register
class HardcodedCredential(Rule):
    id = "SEC-CRED-001"
    name = "Hard coded credential"
    category = "security"
    severity = Severity.HIGH
    description = "A credential is assigned from a string literal."
    rationale = "Credentials in the source code leak with the repository."
    recommendation = "Read the secret from a protected configuration or a vault."
    cwe = (798, 259)
    owasp = ("A07:2021 - Identification and Authentication Failures",)
    standards = ("MISRA C:2012 Rule 21.6",)
    tags = ("secret", "credential", "configuration")

    def check(self, ctx):
        prepare(ctx)
        for node in ctx.unit.walk():
            if isinstance(node, VariableDecl):
                name = node.name
                literal = string_value(getattr(node, "init", None))
            elif isinstance(node, Assignment) and isinstance(node.target, Identifier):
                name = node.target.name
                literal = string_value(node.value)
            else:
                continue
            if literal is None:
                continue
            if len(literal.strip()) < 3:
                continue
            if not matches_sensitive(name, CREDENTIAL_WORDS):
                continue
            yield ctx.report(
                self,
                node,
                f"the credential '{name}' is hard coded in the source code",
            )


@register
class SensitiveEnvironmentVariable(Rule):
    id = "SEC-ENV-001"
    name = "Sensitive data read from the environment"
    category = "security"
    severity = Severity.MEDIUM
    description = (
        "A password, key or token is read from an environment variable."
    )
    rationale = "Environment variables leak into child processes and crash dumps."
    recommendation = "Read secrets from a protected secret store."
    cwe = (522, 214)
    standards = ("CERT ENV34-C",)
    tags = ("environment", "secret", "configuration")

    def check(self, ctx):
        prepare(ctx)
        for call in find_calls(ctx, "getenv", "secure_getenv"):
            if not call.arguments:
                continue
            text = string_value(call.arguments[0])
            if text is not None and matches_sensitive(text, SENSITIVE_WORDS):
                yield ctx.report(
                    self,
                    call,
                    f"the environment variable '{text}' holds sensitive data",
                )
                continue
            name = _assigned_call_name(ctx, call)
            if name is not None and matches_sensitive(name, SENSITIVE_WORDS):
                yield ctx.report(
                    self,
                    call,
                    f"the environment variable stored in '{name}' holds "
                    "sensitive data",
                )


@register
class UninitialisedVariableUse(Rule):
    id = "SEC-CS-001"
    name = "Possibly uninitialised variable"
    category = "security"
    severity = Severity.MEDIUM
    description = (
        "A variable is only assigned in one branch of an if/else statement "
        "but is read afterwards."
    )
    rationale = "The value may be used before it is written."
    recommendation = "Initialise the variable before the conditional statement."
    cwe = (457, 908)
    standards = ("MISRA C:2012 Rule 9.1",)
    tags = ("uninitialised", "control-flow", "data-flow")

    def check(self, ctx):
        prepare(ctx)
        for function in iter_functions(ctx):
            body = function.body
            if body is None:
                continue
            parameter_names = {
                parameter.name for parameter in function.parameters if parameter.name
            }
            for node in body.walk():
                if not isinstance(node, IfStmt):
                    continue
                then_names = _assigned_names(node.then_branch)
                if node.else_branch is None:
                    else_names: set[str] = set()
                else:
                    else_names = _assigned_names(node.else_branch)
                partial = then_names ^ else_names
                for name in sorted(partial):
                    if name in parameter_names:
                        continue
                    if _assigned_before(body, node, name):
                        continue
                    if not _used_after(body, node, name):
                        continue
                    yield ctx.report(
                        self,
                        node,
                        f"'{name}' is only assigned in one branch of the "
                        "conditional and may be used uninitialised",
                    )


@register
class NegativeArrayIndex(Rule):
    id = "SEC-ARR-001"
    name = "Array index may be negative"
    category = "security"
    severity = Severity.MEDIUM
    description = (
        "An index that was compared against zero is used to address an "
        "array."
    )
    rationale = "A negative index accesses memory in front of the array."
    recommendation = "Validate the index against the array bounds."
    cwe = (129, 125)
    standards = ("MISRA C:2012 Rule 21.6",)
    tags = ("array", "bounds", "index")

    def check(self, ctx):
        prepare(ctx)
        for function in iter_functions(ctx):
            body = function.body
            if body is None:
                continue
            guarded: set[str] = set()
            for node in body.walk():
                if not isinstance(node, BinaryOp) or node.operator not in {"<", "<="}:
                    continue
                for side, other in ((node.left, node.right), (node.right, node.left)):
                    if not isinstance(side, Identifier):
                        continue
                    if not isinstance(other, Literal) or other.literal_type != "int":
                        continue
                    if other.value.strip() != "0":
                        continue
                    guarded.add(side.name)
            if not guarded:
                continue
            for node in body.walk():
                if not isinstance(node, IndexAccess):
                    continue
                index = node.index
                if not isinstance(index, Identifier) or index.name not in guarded:
                    continue
                yield ctx.report(
                    self,
                    node,
                    f"'{index.name}' is only checked against zero and may be "
                    "negative when it is used as an array index",
                )


@register
class IgnoredSnprintfResult(Rule):
    id = "SEC-LEAK-001"
    name = "Return value of snprintf() is ignored"
    category = "security"
    severity = Severity.INFO
    description = (
        "snprintf() truncates its output silently when the buffer is too "
        "small and the return value is not inspected."
    )
    rationale = "Truncated data is used as if it were complete."
    recommendation = "Compare the return value with the size of the buffer."
    cwe = (120,)
    standards = ("MISRA C:2012 Rule 21.6",)
    tags = ("format", "truncation", "informational")

    def check(self, ctx):
        prepare(ctx)
        for call in find_calls(ctx, "snprintf", "vsnprintf"):
            parent = call.parent
            if not isinstance(parent, ExprStmt):
                continue
            yield ctx.report(
                self,
                call,
                f"the return value of {call.callee_name}() is ignored; the "
                "output may have been truncated",
                severity=Severity.INFO,
            )
