"""Symbol tables and scope resolution.

The engine builds a scope tree for every translation unit.  Rules use it to
answer questions such as *"is this identifier a pointer?"*, *"what is the
declared size of this buffer?"* or *"is this variable ever initialised?"*
without having to re-implement type reasoning in every rule.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, Iterator

from sast.ast.nodes import (
    ArrayType,
    EnumType,
    FieldDecl,
    FunctionDecl,
    FunctionType,
    Identifier,
    Node,
    PointerType,
    PrimitiveType,
    ReferenceType,
    StructType,
    TranslationUnit,
    TypedefType,
    TypeNode,
    VariableDecl,
)
from sast.core.models import SourceLocation

#: Approximate size in bytes of the primitive types, per platform.
SIZEOF_PRIMITIVES = {
    "void": 1,
    "char": 1,
    "signed char": 1,
    "unsigned char": 1,
    "short": 2,
    "short int": 2,
    "signed short": 2,
    "unsigned short": 2,
    "int": 4,
    "signed": 4,
    "signed int": 4,
    "unsigned": 4,
    "unsigned int": 4,
    "long": 4,
    "long int": 4,
    "unsigned long": 4,
    "long long": 8,
    "long long int": 8,
    "unsigned long long": 8,
    "float": 4,
    "double": 8,
    "long double": 16,
    "bool": 1,
    "_Bool": 1,
    "wchar_t": 4,
    "char16_t": 2,
    "char32_t": 4,
    "size_t": 8,
    "int8_t": 1,
    "int16_t": 2,
    "int32_t": 4,
    "int64_t": 8,
    "uint8_t": 1,
    "uint16_t": 2,
    "uint32_t": 4,
    "uint64_t": 8,
    "intptr_t": 8,
    "uintptr_t": 8,
    "ptrdiff_t": 8,
    "FILE": 8,
}

#: Types whose values come from outside the program and therefore must be
#: validated before use.
SINK_TYPE_NAMES = frozenset({"char", "signed char", "unsigned char"})


@dataclass
class Symbol:
    """A named entity visible in some scope."""

    name: str
    kind: str = "variable"  # variable | function | parameter | typedef | enum | macro | field
    type: TypeNode | None = None
    location: SourceLocation | None = None
    scope: "Scope | None" = None
    is_global: bool = False
    is_static: bool = False
    is_const: bool = False
    is_volatile: bool = False
    is_parameter: bool = False
    is_pointer: bool = False
    is_array: bool = False
    array_size: int | None = None
    is_function: bool = False
    function: FunctionDecl | None = None
    is_typedef: bool = False
    typedef_target: TypeNode | None = None
    is_enum_constant: bool = False
    enum_value: int | None = None
    is_incomplete: bool = False
    read_count: int = 0
    write_count: int = 0
    is_initialized: bool = False
    init_expr: Node | None = None
    doc: str = ""

    @property
    def qualified_name(self) -> str:
        if self.scope and self.scope.kind not in {"global", "file"} and self.scope.name:
            return f"{self.scope.name}::{self.name}"
        return self.name

    def element_type(self) -> TypeNode | None:
        """The type of the elements for arrays, the pointee for pointers."""
        if isinstance(self.type, ArrayType):
            return self.type.element
        if isinstance(self.type, PointerType):
            return self.type.pointee
        return None

    def buffer_size(self) -> int | None:
        """Number of elements of an array or buffer, when statically known."""
        if isinstance(self.type, ArrayType):
            return self.type.size
        return None

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "kind": self.kind,
            "type": self.type.describe() if self.type else "",
            "global": self.is_global,
            "static": self.is_static,
            "const": self.is_const,
            "pointer": self.is_pointer,
            "array_size": self.array_size,
        }


class Scope:
    """A lexical scope."""

    def __init__(
        self,
        kind: str,
        parent: "Scope | None" = None,
        name: str = "",
        owner: Node | None = None,
    ) -> None:
        self.kind = kind
        self.parent = parent
        self.name = name
        self.owner = owner
        self.symbols: dict[str, Symbol] = {}
        self.children: list["Scope"] = []
        if parent is not None:
            parent.children.append(self)

    def declare(self, symbol: Symbol) -> Symbol:
        symbol.scope = self
        self.symbols[symbol.name] = symbol
        return symbol

    def lookup(self, name: str) -> Symbol | None:
        scope: Scope | None = self
        while scope is not None:
            symbol = scope.symbols.get(name)
            if symbol is not None:
                return symbol
            scope = scope.parent
        return None

    def lookup_local(self, name: str) -> Symbol | None:
        return self.symbols.get(name)

    def lookup_deep(self, name: str) -> Symbol | None:
        """Look the name up in this scope and in its nested scopes."""
        symbol = self.symbols.get(name)
        if symbol is not None:
            return symbol
        for child in self.children:
            found = child.lookup_deep(name)
            if found is not None:
                return found
        return None

    def walk(self) -> Iterator["Scope"]:
        yield self
        for child in self.children:
            yield from child.walk()

    def __repr__(self) -> str:  # pragma: no cover - debugging helper
        return f"<Scope {self.kind}:{self.name} symbols={list(self.symbols)}>"


class SymbolTable:
    """The symbol table of a whole translation unit."""

    def __init__(self, unit: TranslationUnit) -> None:
        self.unit = unit
        self.global_scope = Scope("global", name="<file>")
        self.scopes: list[Scope] = [self.global_scope]
        self.functions: dict[str, FunctionDecl] = {}
        self.globals: dict[str, Symbol] = {}
        self.types: dict[str, TypeNode] = {}
        self.enum_constants: dict[str, Symbol] = {}
        self.macros: dict[str, object] = {}
        self.class_symbols: dict[str, Symbol] = {}
        self._build()

    # ------------------------------------------------------------------
    def _build(self) -> None:
        for declaration in self.unit.declarations:
            self._collect(declaration, self.global_scope)

    def _collect(self, node: Node, scope: Scope) -> None:
        kind = node.kind

        if kind == "function_decl":
            function = node  # type: ignore[assignment]
            self.functions[function.name] = function
            symbol = Symbol(
                name=function.name,
                kind="function",
                type=function.type,
                location=function.location,
                scope=scope,
                is_global=True,
                is_static=function.is_static,
                is_function=True,
                function=function,
            )
            scope.declare(symbol)
            function_scope = Scope("function", scope, function.name, owner=function)
            self.scopes.append(function_scope)
            for parameter in function.parameters:
                parameter_scope = self._declare_variable(parameter, function_scope, is_parameter=True)
            if function.body is not None:
                self._collect_body(function.body, function_scope)
            return

        if kind == "variable_decl":
            symbol = self._declare_variable(node, scope)  # type: ignore[arg-type]
            if scope is self.global_scope and symbol is not None:
                self.globals[symbol.name] = symbol
            return

        if kind == "typedef_decl":
            typedef = node  # type: ignore[assignment]
            symbol = Symbol(
                name=typedef.name,
                kind="typedef",
                type=typedef.target,
                location=typedef.location,
                scope=scope,
                is_typedef=True,
                typedef_target=typedef.target,
            )
            scope.declare(symbol)
            self.types[typedef.name] = typedef.target
            return

        if kind == "class_decl":
            class_decl = node  # type: ignore[assignment]
            symbol = Symbol(
                name=class_decl.name,
                kind="class",
                location=class_decl.location,
                scope=scope,
            )
            scope.declare(symbol)
            self.types[class_decl.name] = StructType(class_decl.location)
            class_scope = Scope("class", scope, class_decl.name)
            self.scopes.append(class_scope)
            for member in class_decl.members:
                if isinstance(member, FunctionDecl):
                    member.qualified_name = f"{class_decl.name}::{member.name}"
                    self.functions[member.qualified_name] = member
                    class_scope.declare(
                        Symbol(
                            name=member.name,
                            kind="function",
                            type=member.type,
                            location=member.location,
                            scope=class_scope,
                            is_function=True,
                            function=member,
                        )
                    )
                elif isinstance(member, FieldDecl):
                    class_scope.declare(
                        Symbol(
                            name=member.name,
                            kind="field",
                            type=member.type,
                            location=member.location,
                            scope=class_scope,
                        )
                    )
            return

        if kind == "enum_decl":
            enum_decl = node  # type: ignore[assignment]
            for constant in enum_decl.constants:
                symbol = Symbol(
                    name=constant.name,
                    kind="enum",
                    location=constant.location,
                    scope=scope,
                    is_enum_constant=True,
                    is_const=True,
                )
                scope.declare(symbol)
                self.enum_constants[constant.name] = symbol
            return

        if kind == "namespace_decl":
            namespace = node  # type: ignore[assignment]
            namespace_scope = Scope("namespace", scope, namespace.name)
            self.scopes.append(namespace_scope)
            if namespace.body is not None:
                for child in namespace.body.children:
                    self._collect(child, namespace_scope)
            return

    def _declare_variable(
        self, declaration: Node, scope: Scope, *, is_parameter: bool = False
    ) -> Symbol | None:
        variable = declaration  # type: ignore[assignment]
        if not getattr(variable, "name", ""):
            return None
        symbol = Symbol(
            name=variable.name,
            kind="parameter" if is_parameter else "variable",
            type=variable.type,
            location=variable.location,
            scope=scope,
            is_global=scope is self.global_scope,
            is_static=getattr(variable, "is_static", False),
            is_const=getattr(variable, "is_const", False),
            is_volatile=getattr(variable, "is_volatile", False),
            is_parameter=is_parameter,
            is_pointer=isinstance(variable.type, PointerType),
            is_array=isinstance(variable.type, ArrayType),
            array_size=getattr(variable.type, "size", None) if isinstance(variable.type, ArrayType) else None,
            is_initialized=getattr(variable, "init", None) is not None,
            init_expr=getattr(variable, "init", None),
        )
        scope.declare(symbol)
        return symbol

    def _collect_body(self, node: Node, scope: Scope) -> None:
        """Recursively declare the variables of a function body.

        Block scopes are nested inside the scope that contains them so that
        a name declared in one function can never shadow a name used in
        another one.
        """
        for child in node.children:
            kind = child.kind
            if kind == "compound_stmt":
                block = Scope("block", scope)
                self.scopes.append(block)
                self._collect_body(child, block)
            elif kind == "decl_stmt":
                for declaration in getattr(child, "declarations", []) or []:
                    if isinstance(declaration, VariableDecl):
                        self._declare_variable(declaration, scope)
            elif kind == "function_decl":
                nested_scope = Scope("function", scope, getattr(child, "name", ""), owner=child)
                self.scopes.append(nested_scope)
                for parameter in getattr(child, "parameters", []):
                    self._declare_variable(parameter, nested_scope, is_parameter=True)
                if getattr(child, "body", None) is not None:
                    self._collect_body(child.body, nested_scope)
            elif kind == "class_decl":
                self._collect(child, scope)
            else:
                self._collect_body(child, scope)

    # ------------------------------------------------------------------
    def lookup(self, name: str) -> Symbol | None:
        """Look a name up from the file scope outwards."""
        symbol = self.global_scope.lookup_local(name)
        if symbol is not None:
            return symbol
        for scope in self.scopes:
            if scope.kind == "function":
                found = scope.lookup_deep(name)
                if found is not None:
                    return found
        return None

    def scope_for(self, node: Node | None) -> Scope | None:
        """The scope that encloses *node*."""
        if node is None:
            return None
        current: Node | None = node
        while current is not None:
            for scope in self.scopes:
                if scope.owner is current:
                    return scope
            current = current.parent
        return None

    def lookup_at(self, name: str, node: Node | None = None) -> Symbol | None:
        """Resolve *name* as seen from *node*.

        The enclosing function scope wins over the file scope, so a local
        variable is never confused with a global of the same name.
        """
        scope = self.scope_for(node)
        if scope is not None:
            found = scope.lookup_deep(name)
            if found is not None:
                return found
        return self.lookup(name)

    def lookup_in_function(self, name: str, function: FunctionDecl) -> Symbol | None:
        for scope in self.scopes:
            if scope.kind == "function" and scope.owner is function:
                found = scope.lookup_deep(name)
                if found is not None:
                    return found
        return None

    def all_symbols(self) -> Iterator[Symbol]:
        for scope in self.scopes:
            yield from scope.symbols.values()

    def local_symbols(self, function: FunctionDecl) -> list[Symbol]:
        result: list[Symbol] = []
        for scope in self.scopes:
            if scope.kind == "function" and scope.owner is function:
                result.extend(scope.symbols.values())
                for child in scope.walk():
                    if child is not scope:
                        result.extend(child.symbols.values())
                break
        return result


# --------------------------------------------------------------------------
# Type helpers
# --------------------------------------------------------------------------


def type_size(type_node: TypeNode | None) -> int | None:
    """Best effort size of a type in bytes."""
    if type_node is None:
        return None
    if isinstance(type_node, PrimitiveType):
        return SIZEOF_PRIMITIVES.get(type_node.name.replace("const ", "").strip())
    if isinstance(type_node, PointerType):
        return 8
    if isinstance(type_node, ReferenceType):
        return 8
    if isinstance(type_node, ArrayType):
        element = type_size(type_node.element)
        count = type_node.size
        if element is None or count is None:
            return None
        return element * count
    if isinstance(type_node, EnumType):
        return 4
    if isinstance(type_node, StructType):
        total = 0
        for field in type_node.fields:
            size = type_size(field.type)
            if size is None:
                return None
            total += size
        return total or None
    if isinstance(type_node, TypedefType):
        return None
    if isinstance(type_node, FunctionType):
        return 8
    return None


def is_pointer_type(type_node: TypeNode | None) -> bool:
    return isinstance(type_node, (PointerType, ReferenceType))


def is_char_type(type_node: TypeNode | None) -> bool:
    if isinstance(type_node, PrimitiveType):
        return type_node.name.replace("const ", "").strip() in SINK_TYPE_NAMES
    return False


def is_integer_type(type_node: TypeNode | None) -> bool:
    if isinstance(type_node, PrimitiveType):
        name = type_node.name.replace("const ", "").strip()
        return name in SIZEOF_PRIMITIVES and name not in {
            "void", "float", "double", "long double", "bool", "_Bool"
        }
    return False


def is_float_type(type_node: TypeNode | None) -> bool:
    if isinstance(type_node, PrimitiveType):
        return type_node.name.replace("const ", "").strip() in {"float", "double", "long double"}
    return False


def deref(type_node: TypeNode | None) -> TypeNode | None:
    """Follow one level of indirection."""
    if isinstance(type_node, PointerType):
        return type_node.pointee
    if isinstance(type_node, ArrayType):
        return type_node.element
    if isinstance(type_node, ReferenceType):
        return type_node.pointee
    return None


def resolve_typedef(type_node: TypeNode | None, types: dict[str, TypeNode]) -> TypeNode | None:
    """Resolve a typedef name to the underlying type (one level deep)."""
    seen = 0
    current = type_node
    while isinstance(current, TypedefType) and seen < 8:
        target = types.get(current.alias)
        if target is None:
            return current
        current = target
        seen += 1
    return current
