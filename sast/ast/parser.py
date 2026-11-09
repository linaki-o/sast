"""A recursive descent parser for a practical subset of C and C++.

The parser is not a conforming compiler front-end, and it does not need to
be: the goal is to produce a tree precise enough for static analysis.  The
following are supported:

* full declaration syntax including pointers, references, arrays,
  function pointers, structs/unions/classes, enums, typedefs and templates;
* the complete statement grammar of C99/C11 plus the common C++ statements
  (``try``/``catch``/``throw``, range based ``for``, ``new``/``delete``);
* the complete expression grammar with the standard precedence and
  associativity rules;
* C++ scope resolution, operator overloads, constructors and destructors.

Constructs that cannot be parsed are skipped gracefully: the parser records
an error and resynchronises on the next ``;`` or ``}`` so that a single
syntax error never aborts the analysis of a whole file.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from sast.ast.nodes import (
    AssertStmt,
    AsmStmt,
    Assignment,
    BinaryOp,
    Call,
    BreakStmt,
    CaseStmt,
    Cast,
    CatchClause,
    ClassDecl,
    CommaOp,
    CompoundStmt,
    ConditionalOp,
    ContinueStmt,
    DeclStmt,
    DefaultStmt,
    DeleteExpr,
    DoWhileStmt,
    EnumConstant,
    EnumDecl,
    EnumType,
    Expr,
    ExprStmt,
    FieldDecl,
    ForStmt,
    FunctionDecl,
    FunctionType,
    GotoStmt,
    Identifier,
    IfStmt,
    IndexAccess,
    InitList,
    LabelStmt,
    LambdaExpr,
    MemberInit,
    Literal,
    MemberAccess,
    Node,
    NamespaceDecl,
    NewExpr,
    ParamDecl,
    PointerType,
    PrimitiveType,
    RangeForStmt,
    ReferenceType,
    ReturnStmt,
    SizeOfExpr,
    StructType,
    SwitchStmt,
    ThisExpr,
    ThrowStmt,
    TranslationUnit,
    TryStmt,
    TypeNode,
    TypedefDecl,
    TypedefType,
    TypeofType,
    UnaryOp,
    UsingDecl,
    VariableDecl,
    ArrayType,
    WhileStmt,
)
from sast.core.models import SourceLocation
from sast.lexer.clexer import Token, TokenType, tokenize

#: Built-in type keywords that may appear in a declaration.
TYPE_KEYWORDS = frozenset(
    """
    void char short int long float double signed unsigned bool wchar_t char8_t
    char16_t char32_t auto _Bool _Complex _Imaginary
    """.split()
)

STORAGE_KEYWORDS = frozenset(
    """
    static extern inline register auto typedef thread_local mutable virtual explicit
    constexpr consteval constinit friend _Noreturn _Thread_local _Atomic
    """.split()
)

QUALIFIER_KEYWORDS = frozenset("const volatile restrict __restrict _Atomic".split())

ASSIGNMENT_OPERATORS = frozenset(
    "= += -= *= /= %= <<= >>= &= ^= |=".split()
)

#: Names that are so likely to be types that accepting them in a type
#: position cannot reasonably misparse an expression.
KNOWN_TYPE_NAMES = frozenset(
    """
    size_t ssize_t ptrdiff_t intptr_t uintptr_t max_align_t nullptr_t
    wchar_t char16_t char32_t time_t clock_t va_list fpos_t off_t
    pid_t ino_t dev_t mode_t uid_t gid_t nlink_t blksize_t blkcnt_t
    pthread_t pthread_mutex_t pthread_cond_t sem_t
    int8_t int16_t int32_t int64_t
    uint8_t uint16_t uint32_t uint64_t
    int_least8_t int_least16_t int_least32_t int_least64_t
    uint_least8_t uint_least16_t uint_least32_t uint_least64_t
    int_fast8_t int_fast16_t int_fast32_t int_fast64_t
    uint_fast8_t uint_fast16_t uint_fast32_t uint_fast64_t
    intmax_t uintmax_t imaxdiv_t
    """.split()
)


def _looks_like_type_name(name: str) -> bool:
    """Is *name* likely to be the name of a type?"""
    if not name:
        return False
    if name in KNOWN_TYPE_NAMES:
        return True
    return name.endswith("_t")

BINARY_PRECEDENCE = {
    "||": 1,
    "&&": 2,
    "|": 3,
    "^": 4,
    "&": 5,
    "==": 6,
    "!=": 6,
    "<": 7,
    ">": 7,
    "<=": 7,
    ">=": 7,
    "<<": 8,
    ">>": 8,
    "+": 9,
    "-": 9,
    "*": 10,
    "/": 10,
    "%": 10,
}


class ParseError(Exception):
    """Raised internally when the parser cannot make progress."""

    def __init__(self, message: str, location: SourceLocation | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.location = location


@dataclass
class Declarator:
    """The result of parsing a declarator."""

    name: str = ""
    #: Modifier operations applied to the base type.
    ops: list[tuple] = None  # type: ignore[assignment]
    #: Nested declarator operations (``int (*fp)(void)``).
    inner_ops: list[tuple] | None = None
    location: SourceLocation | None = None

    def __post_init__(self) -> None:
        if self.ops is None:
            self.ops = []


class Parser:
    """Recursive descent parser over a token stream."""

    def __init__(self, tokens: list[Token], *, path: str = "<memory>", language: str = "c") -> None:
        self.tokens = tokens
        self.pos = 0
        self.path = path
        self.language = language
        self.errors: list[tuple[SourceLocation, str]] = []
        self.typedef_names: set[str] = set()
        self.typedef_targets: dict[str, TypeNode] = {}
        self.implicit_types: bool = False
        self.implicit_types_permissive: bool = False
        self.implicit_type_names: set[str] = set()
        self.current_function: str = ""
        self._class_stack: list[str] = []
        self._current_struct_methods: list[FunctionDecl] = []

    # ------------------------------------------------------------------
    # token helpers
    # ------------------------------------------------------------------
    @property
    def current(self) -> Token:
        if self.pos < len(self.tokens):
            return self.tokens[self.pos]
        return self.tokens[-1]

    def _peek(self, offset: int = 0) -> Token:
        index = min(self.pos + offset, len(self.tokens) - 1)
        return self.tokens[index]

    def _check(self, *values: str) -> bool:
        token = self.current
        if token.type in (TokenType.KEYWORD, TokenType.PUNCTUATOR):
            return token.value in values
        return False

    def _check_any(self, *values: str) -> bool:
        return self._check(*values)

    def _advance(self) -> Token:
        token = self.current
        if self.pos < len(self.tokens) - 1:
            self.pos += 1
        return token

    def _match(self, *values: str) -> Token | None:
        if self._check(*values):
            return self._advance()
        return None

    def _expect(self, value: str) -> Token:
        if self._check(value):
            return self._advance()
        token = self.current
        self._error(f"expected {value!r} but found {token.value!r}", token.location)
        raise ParseError(f"expected {value!r}", token.location)

    def _error(self, message: str, location: SourceLocation | None = None) -> None:
        self.errors.append((location or self.current.location, message))

    def _at_end(self) -> bool:
        return self.current.type is TokenType.EOF

    def _at_identifier(self) -> bool:
        token = self.current
        return token.type is TokenType.IDENTIFIER

    def _identifier_ahead(self, offset: int = 1) -> bool:
        return self._peek(offset).type is TokenType.IDENTIFIER

    # ------------------------------------------------------------------
    # entry point
    # ------------------------------------------------------------------
    def parse(self) -> TranslationUnit:
        unit = TranslationUnit(SourceLocation(self.path, 1, 1))
        unit.path = self.path
        unit.language = self.language
        while not self._at_end():
            try:
                declaration = self._parse_declaration(top_level=True)
            except ParseError:
                self._synchronise()
                continue
            if declaration is None:
                continue
            if isinstance(declaration, list):
                for item in declaration:
                    unit.declarations.append(item)
                    unit.add(item)
            else:
                unit.declarations.append(declaration)
                unit.add(declaration)
        return unit

    def _synchronise(self) -> None:
        depth = 0
        while not self._at_end():
            token = self._advance()
            if token.value == "{":
                depth += 1
            elif token.value == "}":
                if depth == 0:
                    return
                depth -= 1
            elif token.value == ";" and depth == 0:
                return

    # ------------------------------------------------------------------
    # declarations
    # ------------------------------------------------------------------
    def _parse_declaration(self, *, top_level: bool = False) -> Any:
        if self._match(";"):
            return None

        if self._check("namespace"):
            return self._parse_namespace()

        if self._check("using"):
            return self._parse_using()

        if self._check("template"):
            return self._parse_template()

        if self._check("extern") and self._peek(1).type is TokenType.STRING:
            self._advance()
            self._advance()
            return None

        if self._check("static_assert") or self._check("_Static_assert"):
            self._advance()
            if self._match("("):
                self._skip_balanced("(", ")")
            self._match(";")
            return None

        # function definition or variable declaration
        if self._is_qualified_constructor():
            return self._parse_qualified_constructor()

        specifiers, base_type = self._parse_specifiers(permissive=True)
        if base_type is None:
            raise ParseError("expected a declaration", self.current.location)

        enum_decl: EnumDecl | None = None
        if isinstance(base_type, EnumType):
            enum_decl = EnumDecl(base_type.location)
            enum_decl.name = base_type.tag
            enum_decl.constants = base_type.enumerators
            for constant in enum_decl.constants:
                enum_decl.add(constant)
            if self._match(";"):
                return enum_decl

        if isinstance(base_type, StructType) and base_type.fields or (
            isinstance(base_type, StructType) and base_type.methods
        ):
            if self._check(";"):
                self._advance()
                class_decl = ClassDecl(base_type.location)
                class_decl.name = base_type.tag
                class_decl.is_struct = base_type.is_union
                class_decl.is_union = base_type.is_union
                class_decl.members = list(base_type.methods) + list(base_type.fields)
                class_decl.methods = list(base_type.methods)
                for member in class_decl.members:
                    class_decl.add(member)
                return class_decl

        if self._match(";"):
            return None

        declarator = self._parse_declarator()
        declarations: list[Node] = []

        if "typedef" in specifiers:
            typedef = TypedefDecl(declarator.location)
            typedef.name = declarator.name
            typedef.alias = declarator.name
            typedef.target = self._apply_ops(base_type, declarator.ops)
            typedef.add(base_type)
            if enum_decl is not None:
                typedef.add(enum_decl)
            self.typedef_names.add(declarator.name)
            self.typedef_targets[declarator.name] = typedef.target
            if self._match(";"):
                return typedef
            while self._match(","):
                declarator = self._parse_declarator()
                extra = TypedefDecl(declarator.location)
                extra.name = declarator.name
                extra.alias = declarator.name
                extra.target = self._apply_ops(base_type, declarator.ops)
                extra.add(base_type)
                self.typedef_names.add(declarator.name)
                self.typedef_targets[declarator.name] = extra.target
            self._expect(";")
            return typedef

        # ``class Foo { ... };`` declares a type, not a variable
        if isinstance(base_type, StructType) and base_type.tag and declarator.name == base_type.tag:
            class_decl = ClassDecl(declarator.location)
            class_decl.name = base_type.tag
            class_decl.is_struct = base_type.is_union
            class_decl.is_union = base_type.is_union
            class_decl.members = list(base_type.methods) + list(base_type.fields)
            class_decl.methods = list(base_type.methods)
            for member in class_decl.members:
                class_decl.add(member)
            if self._match(";"):
                return class_decl
            while self._match(","):
                declarator = self._parse_declarator()
                declarations.append(self._build_declaration(specifiers, base_type, declarator))
            self._expect(";")
            return class_decl

        while True:
            node = self._build_declaration(specifiers, base_type, declarator)
            declarations.append(node)
            if self._match(","):
                declarator = self._parse_declarator()
                continue
            break

        # function body?
        if isinstance(declarations[0], FunctionDecl) and (self._check("{") or self._check(":")):
            function = declarations[0]
            function.body = self._parse_function_body(function)
            function.add(function.body)
            function.doc = self._doc_for(function.location)
            return function

        self._expect(";")
        return declarations

    def _doc_for(self, location: SourceLocation) -> str:
        """Placeholder hook for documentation lookup (filled by the engine)."""
        return ""

    def _parse_namespace(self) -> Node:
        location = self._advance().location
        name = ""
        if self._at_identifier():
            name = self._advance().value
        namespace = NamespaceDecl(location)
        namespace.name = name
        if self._check("{"):
            namespace.body = self._parse_declaration_block()
            namespace.add(namespace.body)
        else:
            self._expect(";")
        return namespace

    def _parse_declaration_block(self) -> CompoundStmt:
        """Parse a ``{ ... }`` block that contains declarations (namespace scope)."""
        location = self._expect("{").location
        block = CompoundStmt(location)
        while not self._check("}") and not self._at_end():
            try:
                declaration = self._parse_declaration()
            except ParseError:
                self._synchronise()
                continue
            if declaration is None:
                continue
            if isinstance(declaration, list):
                for item in declaration:
                    block.statements.append(item)
                    block.add(item)
            else:
                block.statements.append(declaration)
                block.add(declaration)
        self._expect("}")
        return block

    def _parse_using(self) -> Node:
        location = self._advance().location
        using = UsingDecl(location)
        if self._at_identifier():
            using.name = self._advance().value
            if self._check("="):
                self._advance()
                using.target = self._parse_type_name()
        while not self._check(";") and not self._at_end():
            self._advance()
        self._match(";")
        return using

    def _parse_template(self) -> Node:
        location = self._advance().location
        params: list[str] = []
        if self._match("<"):
            depth = 1
            while depth > 0 and not self._at_end():
                token = self._advance()
                if token.value == "<":
                    depth += 1
                elif token.value == ">":
                    depth -= 1
                elif token.type is TokenType.IDENTIFIER and depth == 1:
                    params.append(token.value)
        declaration = self._parse_declaration()
        if isinstance(declaration, list):
            for item in declaration:
                if isinstance(item, (FunctionDecl, ClassDecl)):
                    item.is_template = True
                    item.template_params = params
            return declaration
        if isinstance(declaration, (FunctionDecl, ClassDecl)):
            declaration.is_template = True
            declaration.template_params = params
        return declaration

    def _parse_specifiers(self, permissive: bool = False) -> tuple[set[str], TypeNode | None]:
        """Parse the specifiers of a declaration.

        When the strict parse fails because a type name is unknown, the
        declaration is parsed again with implicit types enabled so that code
        using types from unseen headers is still analysed.  The permissive
        mode accepts any unknown name, the cautious mode only accepts the
        names that look like a type.
        """
        saved = self.pos
        try:
            specifiers, base_type = self._parse_declaration_specifiers()
            if base_type is None:
                raise ParseError("expected a type", self.current.location)
            return specifiers, base_type
        except ParseError:
            self.pos = saved
            if self.implicit_types:
                raise
        self.implicit_types = True
        self.implicit_types_permissive = permissive
        try:
            specifiers, base_type = self._parse_declaration_specifiers()
        finally:
            self.implicit_types = False
            self.implicit_types_permissive = False
        if base_type is None:
            return set(), None
        return specifiers, base_type

    def _parse_declaration_specifiers(self) -> tuple[set[str], TypeNode | None]:
        storage: set[str] = set()
        qualifiers: set[str] = set()
        base: TypeNode | None = None

        while True:
            if self._check(*STORAGE_KEYWORDS):
                storage.add(self._advance().value)
                continue
            if self._check(*QUALIFIER_KEYWORDS):
                qualifiers.add(self._advance().value)
                continue
            break

        base = self._parse_type_specifier()

        # trailing qualifiers after the type (``int const``)
        while self._check(*QUALIFIER_KEYWORDS) or self._check(*STORAGE_KEYWORDS):
            token = self._advance().value
            if token in QUALIFIER_KEYWORDS:
                qualifiers.add(token)
            else:
                storage.add(token)

        if qualifiers:
            if base is not None:
                base.name = base.name
        return storage, base

    def _parse_type_specifier(self) -> TypeNode | None:
        token = self.current

        if token.type is TokenType.KEYWORD and token.value in {"struct", "union", "class"}:
            return self._parse_struct_specifier()

        if token.is_keyword("enum"):
            return self._parse_enum_specifier()

        if token.is_keyword("typeof") or token.is_keyword("__typeof__"):
            location = self._advance().location
            typeof = TypeofType(location)
            if self._match("("):
                typeof.target = self._parse_type_name()
                self._match(")")
            return typeof

        if token.type is TokenType.KEYWORD and token.value in TYPE_KEYWORDS:
            return self._parse_builtin_type()

        if token.is_keyword("typename"):
            self._advance()
            return self._parse_type_specifier()

        # a user defined type name
        if token.type is TokenType.IDENTIFIER:
            if token.value in self.typedef_names:
                location = self._advance().location
                typedef = TypedefType(location)
                typedef.alias = token.value
                return typedef
            # a qualified or templated type name (std::vector<int>)
            if token.value in {"std", "class", "typename"} or self._peek(1).value == "::" or self._peek(1).value == "<":
                if self._peek(1).value == "::" and self._qualified_name_is_declarator():
                    return None
                return self._parse_named_type()
            if self.implicit_types:
                return self._parse_implicit_type()

        return None

    def _parse_implicit_type(self) -> TypeNode | None:
        """Treat an unknown name in a type position as an opaque type.

        Real world code uses types that come from headers the analyser
        never sees (``uint32_t``, ``size_t``, project specific aliases).
        Dropping every declaration that mentions such a type would hide
        most of the code base, so the name is accepted as an opaque type
        instead.
        """
        token = self.current
        if token.type is not TokenType.IDENTIFIER:
            return None
        following = self._peek(1)
        if following.type is not TokenType.IDENTIFIER:
            return None
        name = token.value
        if not self.implicit_types_permissive and not _looks_like_type_name(name):
            return None
        self._advance()
        self.typedef_names.add(name)
        self.implicit_type_names.add(name)
        typedef = TypedefType(token.location)
        typedef.alias = name
        return typedef

    def _qualified_name_is_declarator(self) -> bool:
        """``A::B(`` introduces a function declarator, not a type."""
        scanned = self._scan_qualified_name()
        if scanned is None:
            return False
        _, index = scanned
        return index < len(self.tokens) and self.tokens[index].value == "("

    def _parse_named_type(self) -> TypeNode | None:
        """Parse ``std::vector<int>`` style type names."""
        token = self.current
        if token.type is not TokenType.IDENTIFIER:
            return None
        location = token.location
        name = self._advance().value
        self._parse_template_arguments()
        while self._check("::"):
            self._advance()
            if self._at_identifier() or self.current.type is TokenType.KEYWORD:
                name += "::" + self._advance().value
            self._parse_template_arguments()
        typedef = TypedefType(location)
        typedef.alias = name
        return typedef

    def _parse_template_arguments(self) -> list[TypeNode]:
        """Consume ``< ... >`` template arguments when they look like types."""
        if not self._check("<"):
            return []
        if not self._looks_like_template_arguments():
            return []
        self._advance()
        arguments: list[TypeNode] = []
        while not self._at_end():
            if self._check(">") or self._check(">>"):
                break
            if self._check("const", "volatile"):
                self._advance()
                continue
            if self._check("..."):
                self._advance()
                continue
            argument = self._parse_type_specifier()
            if argument is None:
                break
            arguments.append(argument)
            if self._match(","):
                continue
            break
        self._consume_template_close()
        return arguments

    def _consume_template_close(self) -> None:
        """Consume ``>`` or split a ``>>`` into two closing brackets."""
        if self._check(">"):
            self._advance()
            return
        if self._check(">>"):
            token = self.tokens[self.pos]
            self.tokens[self.pos] = Token(TokenType.PUNCTUATOR, ">", token.location)
            return
        self._expect(">")

    def _looks_like_template_arguments(self) -> bool:
        """Distinguish ``vector<int>`` from a comparison ``a < b``."""
        index = self.pos + 1
        depth = 1
        steps = 0
        while index < len(self.tokens) and steps < 64:
            token = self.tokens[index]
            steps += 1
            if token.value == "<":
                depth += 1
            elif token.value == ">":
                depth -= 1
                if depth == 0:
                    return True
            elif token.value == ">>":
                depth -= 2
                if depth <= 0:
                    return True
            elif token.value in {";", "{", "}", "(", ")", "&&", "||", "==", "!="}:
                return False
            elif token.type is TokenType.EOF:
                return False
            index += 1
        return False

    def _parse_builtin_type(self) -> TypeNode:
        parts: list[str] = []
        location = self.current.location
        while self.current.type is TokenType.KEYWORD and self.current.value in TYPE_KEYWORDS:
            parts.append(self._advance().value)
        name = " ".join(parts)
        return PrimitiveType(name, location)

    def _parse_struct_specifier(self) -> TypeNode:
        keyword = self._advance()
        location = keyword.location
        struct = StructType(location)
        struct.is_union = keyword.value == "union"
        struct.is_class = keyword.value == "class"

        if self._at_identifier() and not self._check("final"):
            struct.tag = self._advance().value

        if self._check(":"):
            self._advance()
            while not self._check("{") and not self._at_end():
                self._advance()

        if self._check("{"):
            self._advance()
            self._current_struct_methods = []
            if struct.tag:
                self._class_stack.append(struct.tag)
            struct.fields = self._parse_struct_body(struct.is_class)
            if struct.tag:
                self._class_stack.pop()
            struct.methods = self._current_struct_methods
            for field in struct.fields:
                struct.add(field)
            for method in struct.methods:
                struct.add(method)
        return struct

    def _parse_struct_body(self, is_class: bool) -> list[FieldDecl]:
        fields: list[FieldDecl] = []
        access = "private" if is_class else "public"
        while not self._check("}") and not self._at_end():
            if self._check("public") or self._check("private") or self._check("protected"):
                access = self._advance().value
                self._match(":")
                continue
            if self._match(";"):
                continue
            if self._check("static_assert") or self._check("_Static_assert"):
                self._advance()
                if self._match("("):
                    self._skip_balanced("(", ")")
                self._match(";")
                continue
            if self._check("using"):
                self._parse_using()
                continue
            try:
                specifiers, base = self._parse_specifiers(permissive=True)
            except ParseError:
                self._synchronise()
                continue
            if base is None:
                self._synchronise()
                continue
            if self._match(";"):
                continue
            first = True
            while True:
                declarator = self._parse_declarator()
                is_method = any(op[0] == "func" for op in declarator.ops)
                if is_method:
                    function = self._make_function(specifiers, base, declarator)
                    function.access = access  # type: ignore[attr-defined]
                    if self._check("{") or self._check(":"):
                        function.body = self._parse_function_body(function)
                    self._current_struct_methods.append(function)
                else:
                    field = FieldDecl(declarator.location)
                    field.name = declarator.name
                    field.type = self._apply_ops(base, declarator.ops)
                    field.access = access
                    if "const" in specifiers:
                        field.type = self._mark_const(field.type)
                    fields.append(field)
                if self._match(","):
                    first = False
                    continue
                break
            self._match(";")
        self._expect("}")
        return fields

    def _make_function(self, specifiers: set[str], base: TypeNode | None, declarator: Declarator) -> FunctionDecl:
        resolved = self._apply_ops(base, declarator.ops)
        function = FunctionDecl(declarator.location)
        function.name = declarator.name
        function.type = resolved
        for op in declarator.ops:
            if op[0] == "func":
                function.parameters = op[1]
        function.is_static = "static" in specifiers
        function.is_extern = "extern" in specifiers
        function.is_inline = "inline" in specifiers
        function.is_virtual = "virtual" in specifiers
        function.is_const = "const" in specifiers
        function.is_pure_virtual = False
        for parameter in function.parameters:
            function.add(parameter)

        simple = declarator.name.rsplit("::", 1)[-1]
        owner = declarator.name.rsplit("::", 1)[0] if "::" in declarator.name else ""
        if simple.startswith("~"):
            function.is_destructor = True
        elif owner and owner == simple:
            function.is_constructor = True
        elif self._class_stack and simple == self._class_stack[-1]:
            function.is_constructor = True
        if function.is_constructor or function.is_destructor:
            function.return_type = None
        return function

    def _parse_function_body(self, function: Any = None) -> CompoundStmt:
        """Parse a function body, including the C++ member initialiser list."""
        if self._check(":"):
            self._advance()
            while not self._check("{") and not self._at_end():
                initialiser = self._parse_member_init()
                if initialiser is None:
                    self._advance()
                    continue
                if function is not None:
                    function.member_inits.append(initialiser)
                    function.add(initialiser)
        return self._parse_compound_statement()

    def _parse_member_init(self) -> Any:
        """Parse one entry of a C++ member initialiser list."""
        if not self._at_identifier():
            return None
        name = self._advance().value
        initialiser = MemberInit(name, None, self.current.location)
        if self._match("("):
            value = self._parse_assignment_expression()
            self._expect(")")
            initialiser.value = value
            initialiser.add(value)
        elif self._match("{"):
            elements: list[Expr] = []
            while not self._check("}") and not self._at_end():
                elements.append(self._parse_initializer())
                if not self._match(","):
                    break
            self._expect("}")
            initialiser.value = InitList(elements, initialiser.location)
            initialiser.add(initialiser.value)
        return initialiser

    def _parse_enum_specifier(self) -> TypeNode:
        location = self._advance().location
        enum = EnumType(location)
        if self._at_identifier():
            enum.tag = self._advance().value
        if self._check(":"):
            self._advance()
            self._parse_type_specifier()
        if self._check("{"):
            self._advance()
            enum.enumerators = self._parse_enumerators()
        return enum

    def _parse_enumerators(self) -> list[EnumConstant]:
        constants: list[EnumConstant] = []
        while not self._check("}") and not self._at_end():
            if not self._at_identifier():
                self._advance()
                continue
            name = self._advance().value
            constant = EnumConstant(name, self.current.location)
            if self._match("="):
                constant.value = self._parse_assignment_expression()
            constants.append(constant)
            if not self._match(","):
                break
        self._expect("}")
        return constants

    # ------------------------------------------------------------------
    # declarators
    # ------------------------------------------------------------------
    def _parse_declarator(self) -> Declarator:
        ops: list[tuple] = []
        location = self.current.location

        while self._check("*", "&"):
            operator = self._advance().value
            const = False
            while self._check("const", "volatile", "restrict"):
                token = self._advance().value
                if token == "const":
                    const = True
            ops.append(("ptr" if operator == "*" else "ref", const))

        name = ""
        inner_ops: list[tuple] | None = None

        if self._check("~"):
            self._advance()
            name = "~"

        if self._check("(") and self._is_declarator_group():
            self._advance()
            nested = self._parse_declarator()
            name = nested.name
            inner_ops = nested.ops
            self._expect(")")

        elif self._at_identifier() and not self._is_keyword_like_identifier():
            name = self._advance().value
            name = self._consume_qualified_suffix(name)

        while True:
            if self._check("["):
                self._advance()
                size: Expr | None = None
                if not self._check("]"):
                    size = self._parse_expression()
                self._expect("]")
                ops.append(("array", size))
            elif self._check("("):
                params, variadic = self._parse_parameters()
                ops.append(("func", params, variadic))
            else:
                break

        declarator = Declarator(name=name, ops=ops, inner_ops=inner_ops, location=location)
        if inner_ops is not None:
            declarator.ops = ops
        return declarator

    def _is_declarator_group(self) -> bool:
        """Distinguish ``(*fp)`` from a parameter list ``(int a)``."""
        first = self._peek(1)
        if first.value in {"*", "&"}:
            return True
        if first.type is TokenType.IDENTIFIER and self._peek(2).value == ")":
            return True
        return False

    def _is_keyword_like_identifier(self) -> bool:
        return False

    def _consume_qualified_suffix(self, name: str) -> str:
        """Consume ``:: identifier`` chains (``demo::sum``)."""
        while self._check("::") and self._peek(1).type is TokenType.IDENTIFIER:
            self._advance()
            name += "::" + self._advance().value
        return name

    def _scan_qualified_name(self) -> tuple[str, int] | None:
        """Look ahead for ``A::B`` and return the name plus the next index."""
        if not self._at_identifier():
            return None
        index = self.pos
        name = self.tokens[index].value
        index += 1
        while (
            index + 1 < len(self.tokens)
            and self.tokens[index].value == "::"
            and self.tokens[index + 1].type is TokenType.IDENTIFIER
        ):
            name += "::" + self.tokens[index + 1].value
            index += 2
        return name, index

    def _is_qualified_constructor(self) -> bool:
        """Detect a C++ constructor or destructor definition."""
        if not self._at_identifier():
            return False
        if self._peek(1).value != "::":
            return False
        third = self._peek(2)
        if third.value == "~":
            owner = self._peek(0).value
            member = self._peek(3)
            if member.type is not TokenType.IDENTIFIER or member.value != owner:
                return False
            return self._peek(4).value == "("
        if third.type is not TokenType.IDENTIFIER:
            return False
        owner = self._peek(0).value
        if third.value != owner:
            return False
        return self._peek(3).value == "("

    def _parse_qualified_constructor(self) -> Node:
        """Parse ``Class::Class(...)`` / ``Class::~Class(...)`` definitions."""
        location = self.current.location
        owner = self._advance().value
        self._advance()
        destructor = False
        if self._check("~"):
            self._advance()
            destructor = True
        member = self._advance().value
        name = f"{owner}::{'~' if destructor else ''}{member}"

        function = FunctionDecl(location)
        function.name = name
        function.qualified_name = name
        function.is_constructor = not destructor
        function.is_destructor = destructor
        function.return_type = None
        params, variadic = self._parse_parameters()
        function.parameters = params
        function.variadic = variadic
        for parameter in params:
            function.add(parameter)
        function.type = None
        if self._check("{") or self._check(":"):
            function.body = self._parse_function_body(function)
            function.add(function.body)
        else:
            self._expect(";")
        return function

    def _parse_parameters(self) -> tuple[list[ParamDecl], bool]:
        self._expect("(")
        params: list[ParamDecl] = []
        variadic = False

        if self._match(")"):
            return params, variadic

        if self._check("void") and self._peek(1).value == ")":
            self._advance()
            self._advance()
            return params, variadic

        while not self._check(")") and not self._at_end():
            if self._match("..."):
                variadic = True
                break
            try:
                specifiers, base = self._parse_specifiers(permissive=True)
            except ParseError:
                break
            if base is None:
                # '...' or unknown: consume and continue
                self._advance()
                continue
            if self._match("..."):
                variadic = True
                break
            declarator = self._parse_declarator()
            param = ParamDecl(declarator.location)
            param.name = declarator.name
            param.type = self._apply_ops(base, declarator.ops)
            param.variadic = False
            if self._match("="):
                param.default = self._parse_assignment_expression()
            if "const" in specifiers:
                param.type = self._mark_const(param.type)
            params.append(param)
            if not self._match(","):
                break

        self._match(")")
        return params, variadic

    def _apply_ops(self, base: TypeNode | None, ops: list[tuple]) -> TypeNode | None:
        """Build the final type by applying declarator operations."""
        if base is None:
            return None
        current = base
        for op in reversed(ops):
            if op[0] == "array":
                array = ArrayType(current.location)
                array.element = current
                array.size_expr = op[1]
                array.size = _const_int(op[1])
                current = array
            elif op[0] == "func":
                function = FunctionType(current.location)
                function.return_type = current
                function.parameters = op[1]
                current = function
            elif op[0] == "ptr":
                pointer = PointerType(current.location)
                pointer.pointee = current
                pointer.const = op[1]
                current = pointer
            elif op[0] == "ref":
                reference = ReferenceType(current.location)
                reference.pointee = current
                current = reference
        return current

    def _mark_const(self, type_node: TypeNode | None) -> TypeNode | None:
        if type_node is None:
            return None
        if isinstance(type_node, (PointerType, ReferenceType)):
            type_node.const = True
        return type_node

    def _build_declaration(
        self, specifiers: set[str], base: TypeNode | None, declarator: Declarator
    ) -> Any:
        resolved = self._apply_ops(base, declarator.ops)
        if declarator.inner_ops is not None:
            resolved = self._apply_ops(resolved, declarator.inner_ops)

        is_function = (
            any(op[0] == "func" for op in declarator.ops)
            and declarator.inner_ops is None
        )

        if is_function:
            function = self._make_function(specifiers, base, declarator)
            self.current_function = declarator.name
            return function

        variable = VariableDecl(declarator.location)
        variable.name = declarator.name
        variable.type = resolved
        variable.is_static = "static" in specifiers
        variable.is_extern = "extern" in specifiers
        variable.is_const = "const" in specifiers
        variable.is_volatile = "volatile" in specifiers

        if self._match("="):
            variable.init = self._parse_initializer()
            variable.add(variable.init)

        if self._check(":"):
            self._advance()
            width = self._parse_constant_expression()
            variable.bitfield_width = _const_int(width)

        return variable

    def _parse_initializer(self, class_target: bool = False) -> Expr:
        if self._check("{"):
            location = self._advance().location
            elements: list[Expr] = []
            while not self._check("}") and not self._at_end():
                if self._check("."):
                    self._advance()
                    self._advance()
                    self._match("=")
                if self._check("}"):
                    break
                elements.append(self._parse_initializer())
                if not self._match(","):
                    break
            self._expect("}")
            return InitList(elements, location)

        if class_target and self._check("(") and self._is_function_style_initialiser():
            location = self._advance().location
            elements = []
            while not self._check(")") and not self._at_end():
                elements.append(self._parse_initializer())
                if not self._match(","):
                    break
            self._expect(")")
            return InitList(elements, location)

        return self._parse_assignment_expression()

    def _is_class_type(self, type_node: TypeNode | None) -> bool:
        """Is *type_node* a class or struct type?"""
        if type_node is None:
            return False
        if isinstance(type_node, StructType):
            return True
        if isinstance(type_node, TypedefType):
            target = self.typedef_targets.get(type_node.alias)
            return isinstance(target, StructType)
        return False

    def _is_function_style_initialiser(self) -> bool:
        """Is ``(`` the start of a C++ function style initialiser?

        A cast such as ``(Node *)malloc(...)`` also starts with a
        parenthesis, so the decision needs more than the first token.
        """
        if self._is_cast():
            return False
        depth = 0
        index = self.pos
        commas = 0
        content = 0
        while index < len(self.tokens):
            token = self.tokens[index]
            if token.value == "(":
                depth += 1
                if depth == 1:
                    index += 1
                    continue
            elif token.value == ")":
                depth -= 1
                if depth == 0:
                    return content == 0 or commas > 0
            elif token.value == "," and depth == 1:
                commas += 1
            elif token.type is TokenType.EOF:
                return False
            if depth >= 1:
                content += 1
            index += 1
        return False

    # ------------------------------------------------------------------
    # statements
    # ------------------------------------------------------------------
    def _parse_compound_statement(self) -> CompoundStmt:
        location = self._expect("{").location
        compound = CompoundStmt(location)
        while not self._check("}") and not self._at_end():
            try:
                statement = self._parse_statement()
            except ParseError:
                self._synchronise()
                continue
            if statement is not None:
                compound.statements.append(statement)
                compound.add(statement)
        self._expect("}")
        return compound

    def _parse_statement(self) -> Any:
        token = self.current

        if token.value == "{":
            return self._parse_compound_statement()

        if token.value == ";":
            self._advance()
            return ExprStmt(None, token.location)

        if token.is_keyword("if"):
            return self._parse_if()

        if token.is_keyword("while"):
            return self._parse_while()

        if token.is_keyword("do"):
            return self._parse_do_while()

        if token.is_keyword("for"):
            return self._parse_for()

        if token.is_keyword("switch"):
            return self._parse_switch()

        if token.is_keyword("case"):
            location = self._advance().location
            value = self._parse_constant_expression()
            self._expect(":")
            body = None
            if not self._check("}") and not self._check("case") and not self._check("default"):
                body = self._parse_statement()
            return CaseStmt(value, body, location)

        if token.is_keyword("default") and self._peek(1).value == ":":
            location = self._advance().location
            self._expect(":")
            body = None
            if not self._check("}") and not self._check("case"):
                body = self._parse_statement()
            return DefaultStmt(body, location)

        if token.is_keyword("break"):
            location = self._advance().location
            self._match(";")
            return BreakStmt(location)

        if token.is_keyword("continue"):
            location = self._advance().location
            self._match(";")
            return ContinueStmt(location)

        if token.is_keyword("return"):
            location = self._advance().location
            value = None
            if not self._check(";"):
                value = self._parse_expression()
            self._match(";")
            return ReturnStmt(value, location)

        if token.is_keyword("goto"):
            location = self._advance().location
            label = self._advance().value if self._at_identifier() else ""
            self._match(";")
            return GotoStmt(label, location)

        if token.is_keyword("try"):
            return self._parse_try()

        if token.is_keyword("throw"):
            location = self._advance().location
            value = None
            if not self._check(";"):
                value = self._parse_expression()
            self._match(";")
            return ThrowStmt(value, location)

        if token.is_keyword("asm") or token.is_keyword("__asm__"):
            location = self._advance().location
            if self._match("("):
                self._skip_balanced("(", ")")
            self._match(";")
            return AsmStmt(location)

        if token.is_keyword("static_assert") or token.is_keyword("_Static_assert"):
            location = self._advance().location
            condition = None
            message = None
            if self._match("("):
                condition = self._parse_assignment_expression()
                if self._match(","):
                    message = self._parse_assignment_expression()
                self._match(")")
            self._match(";")
            return AssertStmt(condition, message, location) if condition else ExprStmt(None, location)

        # label
        if token.type is TokenType.IDENTIFIER and self._peek(1).value == ":" and self._peek(2).value != ":":
            label = self._advance().value
            self._advance()
            body = None
            if not self._check("}") and not self._at_end():
                body = self._parse_statement()
            node = LabelStmt(label, body, token.location)
            return node

        # declaration statement?
        if self._looks_like_declaration():
            saved = self.pos
            try:
                statement = self._parse_declaration_statement()
                return statement
            except ParseError:
                self.pos = saved
                if self.errors:
                    self.errors.pop()

        expression = self._parse_expression()
        self._match(";")
        return ExprStmt(expression, expression.location if expression else token.location)

    def _parse_declaration_statement(self) -> DeclStmt:
        specifiers, base = self._parse_specifiers()
        if base is None:
            raise ParseError("not a declaration", self.current.location)
        statement = DeclStmt(self.current.location)
        if self._match(";"):
            return statement
        while True:
            declarator = self._parse_declarator()
            if "typedef" in specifiers:
                typedef = TypedefDecl(declarator.location)
                typedef.name = declarator.name
                typedef.target = self._apply_ops(base, declarator.ops)
                typedef.alias = declarator.name
                self.typedef_names.add(declarator.name)
                self.typedef_targets[declarator.name] = typedef.target
                statement.declarations.append(typedef)
                statement.add(typedef)
            else:
                variable = VariableDecl(declarator.location)
                variable.name = declarator.name
                variable.type = self._apply_ops(base, declarator.ops)
                variable.is_static = "static" in specifiers
                variable.is_extern = "extern" in specifiers
                variable.is_const = "const" in specifiers
                variable.is_volatile = "volatile" in specifiers
                if self._match("="):
                    variable.init = self._parse_initializer(
                        self._is_class_type(variable.type)
                    )
                    variable.add(variable.init)
                statement.declarations.append(variable)
                statement.add(variable)
            if self._match(","):
                continue
            break
        self._expect(";")
        return statement

    def _looks_like_declaration(self) -> bool:
        token = self.current
        if token.type is TokenType.KEYWORD:
            if token.value in TYPE_KEYWORDS or token.value in STORAGE_KEYWORDS:
                return True
            if token.value in QUALIFIER_KEYWORDS:
                # ``const int x`` / ``volatile int x``
                following = self._peek(1)
                return following.value in TYPE_KEYWORDS or following.value in QUALIFIER_KEYWORDS
            if token.value in {"struct", "union", "class", "enum", "typename"}:
                return True
            return False
        if token.type is TokenType.IDENTIFIER:
            if token.value in self.typedef_names:
                return True
            # 'identifier identifier' or 'identifier *' looks like a declaration
            following = self._peek(1)
            if following.type is TokenType.IDENTIFIER:
                return True
            if following.value in {"*", "&"}:
                return True
        return False

    def _parse_if(self) -> IfStmt:
        location = self._advance().location
        self._expect("(")
        condition = self._parse_expression()
        self._expect(")")
        then_branch = self._parse_statement()
        else_branch = None
        if self._check("else"):
            self._advance()
            else_branch = self._parse_statement()
        return IfStmt(condition, then_branch, else_branch, location)

    def _parse_while(self) -> WhileStmt:
        location = self._advance().location
        self._expect("(")
        condition = self._parse_expression()
        self._expect(")")
        body = self._parse_statement()
        return WhileStmt(condition, body, location)

    def _parse_do_while(self) -> DoWhileStmt:
        location = self._advance().location
        body = self._parse_statement()
        self._expect("while")
        self._expect("(")
        condition = self._parse_expression()
        self._expect(")")
        self._match(";")
        return DoWhileStmt(body, condition, location)

    def _parse_for(self) -> Any:
        location = self._advance().location
        self._expect("(")

        # range based for:  for (auto x : container)
        if self._looks_like_range_for():
            specifiers, base = self._parse_specifiers(permissive=True)
            declarator = self._parse_declarator()
            variable = VariableDecl(declarator.location)
            variable.name = declarator.name
            variable.type = self._apply_ops(base, declarator.ops)
            self._expect(":")
            sequence = self._parse_expression()
            self._expect(")")
            body = self._parse_statement()
            return RangeForStmt(variable, sequence, body, location)

        init: Any = None
        if not self._check(";"):
            if self._looks_like_declaration():
                init = self._parse_declaration_statement()
            else:
                expression = self._parse_expression()
                init = ExprStmt(expression, expression.location)
                self._expect(";")
        else:
            self._advance()

        condition: Expr | None = None
        if not self._check(";"):
            condition = self._parse_expression()
        self._expect(";")

        update: Expr | None = None
        if not self._check(")"):
            update = self._parse_expression()
        self._expect(")")

        body = self._parse_statement()
        return ForStmt(init, condition, update, body, location)

    def _looks_like_range_for(self) -> bool:
        """Detect ``for (auto x : container)``.

        The opening parenthesis has already been consumed, so the depth
        counter starts at one.
        """
        depth = 1
        index = self.pos
        while index < len(self.tokens):
            token = self.tokens[index]
            if token.value == "(":
                depth += 1
            elif token.value == ")":
                depth -= 1
                if depth == 0:
                    return False
            elif token.value == ":" and depth == 1:
                return True
            elif token.value == ";" and depth == 1:
                return False
            elif token.type is TokenType.EOF:
                return False
            index += 1
        return False

    def _parse_switch(self) -> SwitchStmt:
        location = self._advance().location
        self._expect("(")
        condition = self._parse_expression()
        self._expect(")")
        body = self._parse_statement()
        return SwitchStmt(condition, body, location)

    def _parse_try(self) -> TryStmt:
        location = self._advance().location
        body = self._parse_statement()
        handlers: list[CatchClause] = []
        while self._check("catch"):
            catch_location = self._advance().location
            exception_type = ""
            if self._match("("):
                exception_type = self._parse_type_name()
                if self._check("..."):
                    self._advance()
                self._match(")")
            handler_body = self._parse_statement()
            handlers.append(CatchClause(exception_type, handler_body, catch_location))
        return TryStmt(body, handlers, location)

    def _parse_type_name(self) -> str:
        specifiers, base = self._parse_specifiers(permissive=True)
        if base is None:
            return ""
        declarator = self._parse_declarator()
        resolved = self._apply_ops(base, declarator.ops)
        return resolved.describe() if resolved else ""

    # ------------------------------------------------------------------
    # expressions
    # ------------------------------------------------------------------
    def _parse_expression(self) -> Expr:
        expression = self._parse_assignment_expression()
        while self._check(","):
            location = self._advance().location
            right = self._parse_assignment_expression()
            expression = CommaOp(expression, right, location)
        return expression

    def _parse_assignment_expression(self) -> Expr:
        left = self._parse_conditional_expression()
        token = self.current
        if token.type is TokenType.PUNCTUATOR and token.value in ASSIGNMENT_OPERATORS:
            operator = self._advance().value
            right = self._parse_assignment_expression()
            return Assignment(operator, left, right, left.location)
        return left

    def _parse_conditional_expression(self) -> Expr:
        condition = self._parse_binary_expression(1)
        if self._check("?"):
            location = self._advance().location
            then_branch = self._parse_expression()
            self._expect(":")
            else_branch = self._parse_conditional_expression()
            return ConditionalOp(condition, then_branch, else_branch, location)
        return condition

    def _parse_binary_expression(self, min_precedence: int) -> Expr:
        left = self._parse_unary_expression()
        while True:
            token = self.current
            if token.type is not TokenType.PUNCTUATOR:
                break
            precedence = BINARY_PRECEDENCE.get(token.value)
            if precedence is None or precedence < min_precedence:
                break
            # '>' inside a template argument list is not a comparison
            operator = self._advance().value
            right = self._parse_binary_expression(precedence + 1)
            left = BinaryOp(operator, left, right, left.location)
        return left

    def _parse_unary_expression(self) -> Expr:
        token = self.current
        location = token.location

        if token.type is TokenType.PUNCTUATOR and token.value in {"++", "--"}:
            operator = self._advance().value
            operand = self._parse_unary_expression()
            return UnaryOp(operator, operand, location)

        if token.type is TokenType.PUNCTUATOR and token.value in {"+", "-", "!", "~", "*", "&"}:
            operator = self._advance().value
            operand = self._parse_unary_expression()
            return UnaryOp(operator, operand, location)

        if token.is_keyword("sizeof") or token.is_keyword("_Alignof") or token.is_keyword("alignof"):
            self._advance()
            if self._check("("):
                saved = self.pos
                self._advance()
                type_node = self._parse_type_specifier()
                if type_node is not None and self._check(")"):
                    self._advance()
                    return SizeOfExpr(type_node, location)
                self.pos = saved
            operand = self._parse_unary_expression()
            return SizeOfExpr(operand, location)

        if token.is_keyword("new"):
            return self._parse_new()

        if token.is_keyword("delete"):
            self._advance()
            is_array = False
            if self._check("[") and self._peek(1).value == "]":
                self._advance()
                self._advance()
                is_array = True
            operand = self._parse_unary_expression()
            return DeleteExpr(operand, is_array, location)

        if token.is_keyword("throw"):
            self._advance()
            value = None
            if not self._check(";") and not self._check(")") and not self._check(","):
                value = self._parse_assignment_expression()
            return UnaryOp("throw", value, location) if value else UnaryOp("throw", Literal("", "null", location), location)

        # cast expression
        if token.value == "(" and self._is_cast():
            self._advance()
            type_node = self._parse_type_name()
            self._expect(")")
            operand = self._parse_unary_expression()
            return Cast(type_node, operand, location)

        return self._parse_postfix_expression()

    def _is_cast(self) -> bool:
        """Heuristically decide whether ``(`` starts a cast expression."""
        if not self._check("("):
            return False
        following = self._peek(1)
        if following.type is TokenType.KEYWORD:
            if following.value in TYPE_KEYWORDS or following.value in QUALIFIER_KEYWORDS:
                # scan forward to the matching ')' and check the token after it
                return self._cast_closes_before_operand()
        if following.type is TokenType.IDENTIFIER and following.value in self.typedef_names:
            return self._cast_closes_before_operand()
        return False

    def _cast_closes_before_operand(self) -> bool:
        index = self.pos + 1
        depth = 1
        while index < len(self.tokens):
            token = self.tokens[index]
            if token.value == "(":
                depth += 1
            elif token.value == ")":
                depth -= 1
                if depth == 0:
                    after = self.tokens[index + 1] if index + 1 < len(self.tokens) else None
                    if after is None:
                        return False
                    if after.type in (TokenType.IDENTIFIER, TokenType.NUMBER, TokenType.STRING, TokenType.CHAR):
                        return True
                    if after.type is TokenType.KEYWORD and after.value not in {"sizeof"}:
                        return True
                    if after.value in {"(", "!", "~", "*", "&", "-", "+", "++", "--"}:
                        return True
                    return False
            elif token.type is TokenType.EOF:
                return False
            index += 1
        return False

    def _parse_new(self) -> NewExpr:
        location = self._advance().location
        type_node = self._parse_type_specifier() or PrimitiveType("void", location)
        while self._check("["):
            self._advance()
            self._parse_expression()
            self._expect("]")
        count = None
        if self._check("("):
            self._advance()
            count = self._parse_expression()
            self._match(")")
        return NewExpr(type_node, count, location)

    def _parse_postfix_expression(self) -> Expr:
        expression = self._parse_primary_expression()

        while True:
            token = self.current

            if token.value == "(":
                location = self._advance().location
                arguments: list[Expr] = []
                while not self._check(")") and not self._at_end():
                    arguments.append(self._parse_assignment_expression())
                    if not self._match(","):
                        break
                self._expect(")")
                expression = Call(expression, arguments, location)
                continue

            if token.value == "[":
                location = self._advance().location
                index = self._parse_expression()
                self._expect("]")
                expression = IndexAccess(expression, index, location)
                continue

            if token.value in {".", "->"}:
                operator = self._advance().value
                member = ""
                if self._at_identifier() or self.current.type is TokenType.KEYWORD:
                    member = self._advance().value
                expression = MemberAccess(expression, member, operator, token.location)
                continue

            if token.value == "::":
                self._advance()
                if self._at_identifier():
                    name = self._advance().value
                    if isinstance(expression, Identifier):
                        expression.name = f"{expression.name}::{name}"
                    else:
                        expression = Identifier(name, token.location)
                continue

            if token.type is TokenType.PUNCTUATOR and token.value in {"++", "--"}:
                operator = self._advance().value
                expression = UnaryOp(f"post{operator}", expression, token.location)
                continue

            break

        return expression

    def _parse_primary_expression(self) -> Expr:
        token = self.current
        location = token.location

        if token.type is TokenType.NUMBER:
            self._advance()
            literal_type = "float" if ("." in token.value or "e" in token.value.lower()) else "int"
            return Literal(token.value, literal_type, location)

        if token.type is TokenType.STRING:
            self._advance()
            return Literal(token.literal or token.value, "string", location)

        if token.type is TokenType.CHAR:
            self._advance()
            return Literal(token.literal or token.value, "char", location)

        if token.type is TokenType.IDENTIFIER:
            self._advance()
            if token.value in {"true", "false"}:
                return Literal(token.value, "bool", location)
            if token.value == "nullptr":
                return Literal(token.value, "null", location)
            return Identifier(token.value, location)

        if token.type is TokenType.KEYWORD and token.value in {"true", "false"}:
            self._advance()
            return Literal(token.value, "bool", location)

        if token.type is TokenType.KEYWORD and token.value == "nullptr":
            self._advance()
            return Literal(token.value, "null", location)

        if token.value == "(":
            self._advance()
            expression = self._parse_expression()
            self._expect(")")
            return expression

        if token.value == "[" and self.language == "c++":
            if self._peek(1).value != "]":
                return self._parse_lambda()

        if token.is_keyword("this"):
            self._advance()
            from sast.ast.nodes import ThisExpr

            return ThisExpr(location)

        if token.is_keyword("new"):
            return self._parse_new()

        if token.is_keyword("__func__") or token.is_keyword("__FUNCTION__"):
            self._advance()
            return Literal("__func__", "string", location)

        raise ParseError(f"unexpected token {token.value!r}", location)

    def _parse_lambda(self) -> LambdaExpr:
        location = self._advance().location
        parameters: list[ParamDecl] = []
        if self._check("("):
            self._advance()
            while not self._check(")") and not self._at_end():
                specifiers, base = self._parse_specifiers(permissive=True)
                declarator = self._parse_declarator()
                param = ParamDecl(declarator.location)
                param.name = declarator.name
                param.type = self._apply_ops(base, declarator.ops)
                parameters.append(param)
                if not self._match(","):
                    break
            self._match(")")

        body = None
        if self._check("{"):
            body = self._parse_compound_statement()
        elif self._check("->"):
            self._advance()
            self._parse_type_specifier()
        return LambdaExpr(body, location)

    def _parse_constant_expression(self) -> Expr:
        return self._parse_conditional_expression()

    # ------------------------------------------------------------------
    def _skip_balanced(self, open_token: str, close_token: str) -> None:
        if not self._check(open_token):
            return
        depth = 0
        while not self._at_end():
            token = self._advance()
            if token.value == open_token:
                depth += 1
            elif token.value == close_token:
                depth -= 1
                if depth == 0:
                    return


def _const_int(expression: Expr | None) -> int | None:
    """Best effort evaluation of a constant integer expression."""
    if expression is None:
        return None
    if isinstance(expression, Literal):
        text = expression.value.replace("'", "")
        try:
            if text.lower().startswith("0x"):
                return int(text, 16)
            if text.lower().startswith("0b"):
                return int(text, 2)
            if text.lower().startswith("0o"):
                return int(text, 8)
            if text.startswith("0") and len(text) > 1 and text[1:].isdigit():
                return int(text, 8)
            return int(text)
        except ValueError:
            return None
    if isinstance(expression, UnaryOp) and expression.operator in {"-", "+"}:
        value = _const_int(expression.operand)
        if value is None:
            return None
        return -value if expression.operator == "-" else value
    if isinstance(expression, BinaryOp):
        left = _const_int(expression.left)
        right = _const_int(expression.right)
        if left is None or right is None:
            return None
        try:
            if expression.operator == "+":
                return left + right
            if expression.operator == "-":
                return left - right
            if expression.operator == "*":
                return left * right
            if expression.operator == "/":
                return left // right if right else None
            if expression.operator == "%":
                return left % right if right else None
            if expression.operator == "<<":
                return left << right
            if expression.operator == ">>":
                return left >> right
            if expression.operator == "&":
                return left & right
            if expression.operator == "|":
                return left | right
            if expression.operator == "^":
                return left ^ right
        except (ValueError, TypeError):
            return None
    return None


def parse_source(source: str, path: str = "<memory>", *, language: str = "c") -> tuple[TranslationUnit, list[tuple[SourceLocation, str]]]:
    """Parse *source* and return the translation unit plus parse errors."""
    result = tokenize(source, path, language=language)
    parser = Parser(result.tokens, path=path, language=language)
    unit = parser.parse()
    unit.includes = list(result.includes)
    return unit, parser.errors


def parse_file(path: str, *, encoding: str = "utf-8") -> tuple[TranslationUnit, list[tuple[SourceLocation, str]]]:
    from pathlib import Path

    file_path = Path(path)
    data = file_path.read_bytes()
    try:
        source = data.decode(encoding)
    except UnicodeDecodeError:
        source = data.decode("utf-8", errors="replace")
    language = "c++" if file_path.suffix.lower() in {".cpp", ".cc", ".cxx", ".c++", ".hpp", ".hh"} else "c"
    return parse_source(source, str(file_path), language=language)
