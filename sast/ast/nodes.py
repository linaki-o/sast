"""Lightweight AST used by the analysis engine.

The tree is intentionally compact: rules work against node *kinds* and the
handful of attributes that matter (callee name, argument list, operator, ...).
A full blown typed AST would multiply the amount of code without improving
the quality of the findings.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterator

from sast.core.models import SourceLocation


class Node:
    """Base class of every AST node."""

    kind: str = "node"

    def __init__(self, location: SourceLocation | None = None) -> None:
        self.location = location or SourceLocation("<unknown>", 0, 0)
        self.parent: Node | None = None
        self.children: list["Node"] = []

    # -- traversal -------------------------------------------------------
    def add(self, child: "Node | None") -> "Node | None":
        if child is None:
            return None
        child.parent = self
        self.children.append(child)
        return child

    def add_all(self, children: list["Node | None"]) -> None:
        for child in children:
            self.add(child)

    def walk(self) -> Iterator["Node"]:
        """Depth first pre-order traversal including this node."""
        yield self
        for child in self.children:
            yield from child.walk()

    def ancestors(self) -> Iterator["Node"]:
        node = self.parent
        while node is not None:
            yield node
            node = node.parent

    def child_of(self, *kinds: str) -> Iterator["Node"]:
        for child in self.children:
            if child.kind in kinds:
                yield child

    # -- helpers ---------------------------------------------------------
    @property
    def end_location(self) -> SourceLocation:
        """The location of the last token that belongs to this node."""
        last = self.children[-1] if self.children else None
        if last is not None and last.location:
            return last.end_location
        return self.location

    def find(self, kind: str) -> Iterator["Node"]:
        for node in self.walk():
            if node.kind == kind:
                yield node

    def find_all(self) -> Iterator["Node"]:
        return self.walk()

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "kind": self.kind,
            "line": self.location.line,
            "column": self.location.column,
        }
        for key, value in vars(self).items():
            if key in {"location", "parent", "children"}:
                continue
            if isinstance(value, Node):
                data[key] = value.to_dict()
            elif isinstance(value, list):
                data[key] = [
                    v.to_dict() if isinstance(v, Node) else v for v in value
                ]
            else:
                data[key] = value
        data["children"] = [c.to_dict() for c in self.children]
        return data

    def __repr__(self) -> str:  # pragma: no cover - debugging helper
        return f"<{self.kind} @{self.location}>"


# --------------------------------------------------------------------------
# Root
# --------------------------------------------------------------------------


class TranslationUnit(Node):
    kind = "translation_unit"

    def __init__(self, location: SourceLocation | None = None) -> None:
        super().__init__(location)
        self.declarations: list[Node] = []
        self.path: str = ""
        self.language: str = "c"
        self.includes: list[str] = []

    @property
    def functions(self) -> list["FunctionDecl"]:
        return [d for d in self.declarations if isinstance(d, FunctionDecl)]

    @property
    def variables(self) -> list["VariableDecl"]:
        return [
            d
            for d in self.declarations
            if isinstance(d, VariableDecl) and not d.is_parameter
        ]


# --------------------------------------------------------------------------
# Types
# --------------------------------------------------------------------------


class TypeNode(Node):
    kind = "type"

    def __init__(self, location: SourceLocation | None = None) -> None:
        super().__init__(location)
        self.name: str = ""

    def describe(self) -> str:
        return self.name or self.kind


class PrimitiveType(TypeNode):
    kind = "primitive_type"

    def __init__(self, name: str, location: SourceLocation | None = None) -> None:
        super().__init__(location)
        self.name = name


class PointerType(TypeNode):
    kind = "pointer_type"

    def __init__(self, location: SourceLocation | None = None) -> None:
        super().__init__(location)
        self.pointee: TypeNode | None = None
        self.const: bool = False
        self.name = "pointer"

    def describe(self) -> str:
        inner = self.pointee.describe() if self.pointee else "void"
        return f"{inner}*"


class ReferenceType(TypeNode):
    kind = "reference_type"

    def __init__(self, location: SourceLocation | None = None) -> None:
        super().__init__(location)
        self.pointee: TypeNode | None = None
        self.name = "reference"


class ArrayType(TypeNode):
    kind = "array_type"

    def __init__(self, location: SourceLocation | None = None) -> None:
        super().__init__(location)
        self.element: TypeNode | None = None
        self.size: int | None = None
        self.size_expr: "Expr | None" = None
        self.name = "array"


class FunctionType(TypeNode):
    kind = "function_type"

    def __init__(self, location: SourceLocation | None = None) -> None:
        super().__init__(location)
        self.return_type: TypeNode | None = None
        self.parameters: list["ParamDecl"] = []
        self.variadic: bool = False
        self.name = "function"


class StructType(TypeNode):
    kind = "struct_type"

    def __init__(self, location: SourceLocation | None = None) -> None:
        super().__init__(location)
        self.tag: str = ""
        self.fields: list["FieldDecl"] = []
        self.methods: list["FunctionDecl"] = []
        self.is_union: bool = False
        self.is_class: bool = False
        self.bases: list[str] = []
        self.name = self.tag


class EnumType(TypeNode):
    kind = "enum_type"

    def __init__(self, location: SourceLocation | None = None) -> None:
        super().__init__(location)
        self.tag: str = ""
        self.enumerators: list["EnumConstant"] = []
        self.name = self.tag


class EnumConstant(Node):
    kind = "enumerator"

    def __init__(self, name: str, location: SourceLocation | None = None) -> None:
        super().__init__(location)
        self.name = name
        self.value: "Expr | None" = None


class TypedefType(TypeNode):
    kind = "typedef_type"

    def __init__(self, location: SourceLocation | None = None) -> None:
        super().__init__(location)
        self.alias: str = ""
        self.target: TypeNode | None = None
        self.name = self.alias


class TypeofType(TypeNode):
    kind = "typeof_type"

    def __init__(self, location: SourceLocation | None = None) -> None:
        super().__init__(location)
        self.target: TypeNode | None = None


# --------------------------------------------------------------------------
# Declarations
# --------------------------------------------------------------------------


class Decl(Node):
    kind = "declaration"

    def __init__(self, location: SourceLocation | None = None) -> None:
        super().__init__(location)
        self.name: str = ""
        self.type: TypeNode | None = None
        self.init: "Expr | InitList | None" = None
        self.storage: set[str] = set()
        self.doc: str = ""


class VariableDecl(Decl):
    kind = "variable_decl"

    def __init__(self, location: SourceLocation | None = None) -> None:
        super().__init__(location)
        self.is_parameter: bool = False
        self.is_static: bool = False
        self.is_extern: bool = False
        self.is_const: bool = False
        self.is_volatile: bool = False
        self.bitfield_width: int | None = None


class FieldDecl(Decl):
    kind = "field_decl"

    def __init__(self, location: SourceLocation | None = None) -> None:
        super().__init__(location)
        self.access: str = "public"
        self.bitfield_width: int | None = None


class ParamDecl(Decl):
    kind = "param_decl"

    def __init__(self, location: SourceLocation | None = None) -> None:
        super().__init__(location)
        self.default: "Expr | None" = None
        self.variadic: bool = False


class FunctionDecl(Decl):
    kind = "function_decl"

    def __init__(self, location: SourceLocation | None = None) -> None:
        super().__init__(location)
        self.body: "CompoundStmt | None" = None
        self.is_static: bool = False
        self.is_extern: bool = False
        self.is_inline: bool = False
        self.is_virtual: bool = False
        self.is_const: bool = False
        self.is_constructor: bool = False
        self.is_destructor: bool = False
        self.is_pure_virtual: bool = False
        self.is_abstract: bool = False
        self.is_template: bool = False
        self.template_params: list[str] = []
        self.parameters: list[ParamDecl] = []
        self.qualified_name: str = ""
        self.variadic: bool = False
        self.thrown_types: list[str] = []
        self.access: str = "public"
        self.is_const_method: bool = False
        self.member_inits: list["MemberInit"] = []

    @property
    def is_definition(self) -> bool:
        return self.body is not None

    @property
    def parameter_count(self) -> int:
        return len(self.parameters)


class MemberInit(Node):
    """A member of the C++ initialiser list of a constructor."""

    kind = "member_init"

    def __init__(self, name: str, value: Expr | None = None, location: SourceLocation | None = None) -> None:
        super().__init__(location)
        self.name = name
        self.value = value


class ClassDecl(Node):
    kind = "class_decl"

    def __init__(self, location: SourceLocation | None = None) -> None:
        super().__init__(location)
        self.name: str = ""
        self.bases: list[str] = []
        self.is_struct: bool = False
        self.is_union: bool = False
        self.is_enum: bool = False
        self.is_template: bool = False
        self.template_params: list[str] = []
        self.access: str = "private" if not self.is_struct else "public"
        self.doc: str = ""
        self.members: list[Node] = []
        self.methods: list[FunctionDecl] = []


class EnumDecl(Node):
    kind = "enum_decl"

    def __init__(self, location: SourceLocation | None = None) -> None:
        super().__init__(location)
        self.name: str = ""
        self.constants: list[EnumConstant] = []
        self.doc: str = ""


class TypedefDecl(Node):
    kind = "typedef_decl"

    def __init__(self, location: SourceLocation | None = None) -> None:
        super().__init__(location)
        self.name: str = ""
        self.target: TypeNode | None = None
        self.alias: str = ""


class UsingDecl(Node):
    kind = "using_decl"

    def __init__(self, location: SourceLocation | None = None) -> None:
        super().__init__(location)
        self.name: str = ""
        self.target: str = ""


class NamespaceDecl(Node):
    kind = "namespace_decl"

    def __init__(self, location: SourceLocation | None = None) -> None:
        super().__init__(location)
        self.name: str = ""
        self.body: "CompoundStmt | None" = None


class MacroDecl(Node):
    kind = "macro_decl"

    def __init__(self, location: SourceLocation | None = None) -> None:
        super().__init__(location)
        self.name: str = ""
        self.body: str = ""
        self.params: list[str] = []
        self.function_like: bool = False


# --------------------------------------------------------------------------
# Expressions
# --------------------------------------------------------------------------


class Expr(Node):
    kind = "expr"

    def __init__(self, location: SourceLocation | None = None) -> None:
        super().__init__(location)
        self.type_hint: TypeNode | None = None
        self.is_lvalue: bool = False


class Identifier(Expr):
    kind = "identifier"

    def __init__(self, name: str, location: SourceLocation | None = None) -> None:
        super().__init__(location)
        self.name = name
        self.is_lvalue = True


class Literal(Expr):
    kind = "literal"

    def __init__(self, value: str, literal_type: str, location: SourceLocation | None = None) -> None:
        super().__init__(location)
        self.value = value
        self.literal_type = literal_type  # int | float | char | string | bool | null


class BinaryOp(Expr):
    kind = "binary_op"

    def __init__(self, operator: str, left: Expr, right: Expr, location: SourceLocation | None = None) -> None:
        super().__init__(location)
        self.operator = operator
        self.left = left
        self.right = right
        self.add(left)
        self.add(right)


class UnaryOp(Expr):
    kind = "unary_op"

    def __init__(self, operator: str, operand: Expr, location: SourceLocation | None = None) -> None:
        super().__init__(location)
        self.operator = operator
        self.operand = operand
        self.add(operand)


class Assignment(Expr):
    kind = "assignment"

    def __init__(self, operator: str, target: Expr, value: Expr, location: SourceLocation | None = None) -> None:
        super().__init__(location)
        self.operator = operator
        self.target = target
        self.value = value
        self.add(target)
        self.add(value)


class ConditionalOp(Expr):
    kind = "conditional"

    def __init__(self, condition: Expr, then_branch: Expr, else_branch: Expr, location: SourceLocation | None = None) -> None:
        super().__init__(location)
        self.condition = condition
        self.then_branch = then_branch
        self.else_branch = else_branch
        self.add(condition)
        self.add(then_branch)
        self.add(else_branch)


class Call(Expr):
    kind = "call"

    def __init__(self, callee: Expr, arguments: list[Expr], location: SourceLocation | None = None) -> None:
        super().__init__(location)
        self.callee = callee
        self.arguments = arguments
        self.add(callee)
        self.add_all(arguments)

    @property
    def callee_name(self) -> str:
        """The unqualified name of the called function.

        A qualified name such as ``std::strcpy`` is reported as ``strcpy``
        so that the rules do not have to know about namespaces.
        """
        if isinstance(self.callee, Identifier):
            name = self.callee.name
            return name.rsplit("::", 1)[-1]
        if isinstance(self.callee, MemberAccess):
            return self.callee.member
        return ""


class MemberAccess(Expr):
    kind = "member_access"

    def __init__(self, obj: Expr, member: str, operator: str = ".", location: SourceLocation | None = None) -> None:
        super().__init__(location)
        self.object = obj
        self.member = member
        self.operator = operator
        self.add(obj)

    @property
    def is_arrow(self) -> bool:
        return self.operator == "->"


class IndexAccess(Expr):
    kind = "index_access"

    def __init__(self, obj: Expr, index: Expr, location: SourceLocation | None = None) -> None:
        super().__init__(location)
        self.object = obj
        self.index = index
        self.add(obj)
        self.add(index)


class Cast(Expr):
    kind = "cast"

    def __init__(self, target_type: TypeNode, operand: Expr, location: SourceLocation | None = None) -> None:
        super().__init__(location)
        self.target_type = target_type
        self.operand = operand
        self.add(operand)


class SizeOfExpr(Expr):
    kind = "sizeof"

    def __init__(self, operand: Expr | TypeNode | None, location: SourceLocation | None = None) -> None:
        super().__init__(location)
        self.operand = operand
        if isinstance(operand, Node):
            self.add(operand)


class InitList(Expr):
    kind = "init_list"

    def __init__(self, elements: list[Expr], location: SourceLocation | None = None) -> None:
        super().__init__(location)
        self.elements = elements
        self.add_all(elements)


class NewExpr(Expr):
    kind = "new"

    def __init__(self, type_node: TypeNode, count: Expr | None = None, location: SourceLocation | None = None) -> None:
        super().__init__(location)
        self.type_node = type_node
        self.count = count
        self.add(type_node)
        if count is not None:
            self.add(count)


class DeleteExpr(Expr):
    kind = "delete"

    def __init__(self, operand: Expr, array: bool = False, location: SourceLocation | None = None) -> None:
        super().__init__(location)
        self.operand = operand
        self.array = array
        self.add(operand)


class ThisExpr(Expr):
    kind = "this"


class LambdaExpr(Expr):
    kind = "lambda"

    def __init__(self, body: "CompoundStmt | None" = None, location: SourceLocation | None = None) -> None:
        super().__init__(location)
        self.body = body
        self.parameters: list[ParamDecl] = []


class CommaOp(Expr):
    kind = "comma_op"

    def __init__(self, left: Expr, right: Expr, location: SourceLocation | None = None) -> None:
        super().__init__(location)
        self.left = left
        self.right = right
        self.add(left)
        self.add(right)


# --------------------------------------------------------------------------
# Statements
# --------------------------------------------------------------------------


class Stmt(Node):
    kind = "stmt"


class CompoundStmt(Stmt):
    kind = "compound_stmt"

    def __init__(self, location: SourceLocation | None = None) -> None:
        super().__init__(location)
        self.statements: list[Stmt] = []
        self.labels: list[str] = []


class ExprStmt(Stmt):
    kind = "expr_stmt"

    def __init__(self, expression: Expr | None = None, location: SourceLocation | None = None) -> None:
        super().__init__(location)
        self.expression = expression
        if expression is not None:
            self.add(expression)


class DeclStmt(Stmt):
    kind = "decl_stmt"

    def __init__(self, location: SourceLocation | None = None) -> None:
        super().__init__(location)
        self.declarations: list[Decl] = []


class IfStmt(Stmt):
    kind = "if_stmt"

    def __init__(self, condition: Expr, then_branch: Stmt, else_branch: Stmt | None = None, location: SourceLocation | None = None) -> None:
        super().__init__(location)
        self.condition = condition
        self.then_branch = then_branch
        self.else_branch = else_branch
        self.add(condition)
        self.add(then_branch)
        if else_branch is not None:
            self.add(else_branch)


class WhileStmt(Stmt):
    kind = "while_stmt"

    def __init__(self, condition: Expr, body: Stmt, location: SourceLocation | None = None) -> None:
        super().__init__(location)
        self.condition = condition
        self.body = body
        self.add(condition)
        self.add(body)


class DoWhileStmt(Stmt):
    kind = "do_while_stmt"

    def __init__(self, body: Stmt, condition: Expr, location: SourceLocation | None = None) -> None:
        super().__init__(location)
        self.body = body
        self.condition = condition
        self.add(body)
        self.add(condition)


class ForStmt(Stmt):
    kind = "for_stmt"

    def __init__(self, init: Stmt | None, condition: Expr | None, update: Expr | None, body: Stmt, location: SourceLocation | None = None) -> None:
        super().__init__(location)
        self.init = init
        self.condition = condition
        self.update = update
        self.body = body
        self.add(init)
        self.add(condition)
        self.add(update)
        self.add(body)


class RangeForStmt(Stmt):
    kind = "range_for_stmt"

    def __init__(self, variable: VariableDecl, sequence: Expr, body: Stmt, location: SourceLocation | None = None) -> None:
        super().__init__(location)
        self.variable = variable
        self.sequence = sequence
        self.body = body
        self.add(variable)
        self.add(sequence)
        self.add(body)


class SwitchStmt(Stmt):
    kind = "switch_stmt"

    def __init__(self, condition: Expr, body: Stmt, location: SourceLocation | None = None) -> None:
        super().__init__(location)
        self.condition = condition
        self.body = body
        self.add(condition)
        self.add(body)


class CaseStmt(Stmt):
    kind = "case_stmt"

    def __init__(self, value: Expr | None, body: Stmt | None = None, location: SourceLocation | None = None) -> None:
        super().__init__(location)
        self.value = value
        self.body = body
        if value is not None:
            self.add(value)
        if body is not None:
            self.add(body)


class DefaultStmt(Stmt):
    kind = "default_stmt"

    def __init__(self, body: Stmt | None = None, location: SourceLocation | None = None) -> None:
        super().__init__(location)
        self.body = body
        if body is not None:
            self.add(body)


class BreakStmt(Stmt):
    kind = "break_stmt"


class ContinueStmt(Stmt):
    kind = "continue_stmt"


class ReturnStmt(Stmt):
    kind = "return_stmt"

    def __init__(self, value: Expr | None = None, location: SourceLocation | None = None) -> None:
        super().__init__(location)
        self.value = value
        if value is not None:
            self.add(value)


class GotoStmt(Stmt):
    kind = "goto_stmt"

    def __init__(self, label: str, location: SourceLocation | None = None) -> None:
        super().__init__(location)
        self.label = label


class LabelStmt(Stmt):
    kind = "label_stmt"

    def __init__(self, label: str, body: Stmt | None = None, location: SourceLocation | None = None) -> None:
        super().__init__(location)
        self.label = label
        self.body = body
        if body is not None:
            self.add(body)


class TryStmt(Stmt):
    kind = "try_stmt"

    def __init__(self, body: Stmt, handlers: list["CatchClause"] = [], location: SourceLocation | None = None) -> None:
        super().__init__(location)
        self.body = body
        self.handlers = handlers
        self.add(body)
        self.add_all(handlers)


class CatchClause(Node):
    kind = "catch_clause"

    def __init__(self, exception_type: str, body: Stmt | None = None, location: SourceLocation | None = None) -> None:
        super().__init__(location)
        self.exception_type = exception_type
        self.body = body
        if body is not None:
            self.add(body)


class ThrowStmt(Stmt):
    kind = "throw_stmt"

    def __init__(self, value: Expr | None = None, location: SourceLocation | None = None) -> None:
        super().__init__(location)
        self.value = value
        if value is not None:
            self.add(value)


class AssertStmt(Stmt):
    kind = "assert_stmt"

    def __init__(self, condition: Expr, message: Expr | None = None, location: SourceLocation | None = None) -> None:
        super().__init__(location)
        self.condition = condition
        self.message = message
        self.add(condition)
        if message is not None:
            self.add(message)


class AsmStmt(Stmt):
    kind = "asm_stmt"


class EmptyStmt(Stmt):
    kind = "empty_stmt"


def is_expression_node(node: Node) -> bool:
    return isinstance(node, Expr)


def is_statement_node(node: Node) -> bool:
    return isinstance(node, Stmt)


def is_declaration_node(node: Node) -> bool:
    return isinstance(node, Decl)
