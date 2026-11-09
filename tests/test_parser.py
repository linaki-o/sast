"""Tests for the C/C++ parser and the shape of the produced AST."""

from __future__ import annotations

from sast.ast.nodes import (
    Assignment,
    BinaryOp,
    BreakStmt,
    Call,
    CaseStmt,
    ContinueStmt,
    EnumDecl,
    ForStmt,
    FunctionDecl,
    IfStmt,
    ReturnStmt,
    StructType,
    SwitchStmt,
    TypedefDecl,
    VariableDecl,
    WhileStmt,
)
from sast.ast.parser import parse_file, parse_source


def parse(code: str, language: str = "c"):
    unit, errors = parse_source(code, "test.c", language=language)
    return unit, errors


def test_simple_function_has_no_errors():
    unit, errors = parse("int add(int a, int b) { return a + b; }")
    assert errors == []
    assert len(unit.declarations) == 1
    function = unit.declarations[0]
    assert isinstance(function, FunctionDecl)
    assert function.name == "add"
    assert function.is_definition
    assert [p.name for p in function.parameters] == ["a", "b"]


def test_declarations_are_linked_as_children():
    unit, _ = parse("int add(int a, int b) { return a + b; }")
    kinds = {node.kind for node in unit.walk()}
    assert "function_decl" in kinds
    assert "return_stmt" in kinds
    assert "identifier" in kinds


def test_pointer_and_array_declarators():
    unit, errors = parse("int *p; char buf[16]; int **pp;")
    assert errors == []
    names = {d.name for d in unit.declarations if isinstance(d, VariableDecl)}
    assert names == {"p", "buf", "pp"}


def test_function_pointer_declarator():
    unit, errors = parse("int (*compare)(int, int);")
    assert errors == []
    declaration = unit.declarations[0]
    assert isinstance(declaration, VariableDecl)
    assert declaration.name == "compare"


def test_struct_definition_is_parsed():
    unit, errors = parse(
        "typedef struct Point { int x; int y; } Point;"
    )
    assert errors == []
    typedef = unit.declarations[0]
    assert isinstance(typedef, TypedefDecl)
    assert typedef.name == "Point"
    target = typedef.target
    assert isinstance(target, StructType)
    assert [f.name for f in target.fields] == ["x", "y"]


def test_enum_declaration_is_kept():
    unit, errors = parse("enum Color { RED, GREEN = 5, BLUE };")
    assert errors == []
    enum = unit.declarations[0]
    assert isinstance(enum, EnumDecl)
    assert [c.name for c in enum.constants] == ["RED", "GREEN", "BLUE"]


def test_control_flow_statements():
    unit, errors = parse(
        """
        void f(int n) {
            int i;
            for (i = 0; i < n; i++) {
                if (i == 2) { continue; }
                if (i == 3) { break; }
            }
            while (n > 0) { n--; }
        }
        """
    )
    assert errors == []
    kinds = {node.kind for node in unit.walk()}
    assert "for_stmt" in kinds
    assert "if_stmt" in kinds
    assert "while_stmt" in kinds
    assert "continue_stmt" in kinds
    assert "break_stmt" in kinds


def test_switch_statement():
    unit, errors = parse(
        """
        int f(int x) {
            switch (x) {
            case 1: return 10;
            case 2: return 20;
            default: return 0;
            }
        }
        """
    )
    assert errors == []
    kinds = {node.kind for node in unit.walk()}
    assert "switch_stmt" in kinds
    assert "case_stmt" in kinds
    assert "default_stmt" in kinds


def test_cast_expression_is_parsed():
    unit, errors = parse("int f(void) { return (int)3.5; }")
    assert errors == []
    kinds = {node.kind for node in unit.walk()}
    assert "cast" in kinds


def test_cpp_class_with_member_functions():
    unit, errors = parse(
        """
        class Widget {
        public:
            Widget(int size);
            int size() const { return size_; }
        private:
            int size_;
        };
        """,
        language="c++",
    )
    assert errors == []
    names = [d.name for d in unit.declarations]
    assert "Widget" in names


def test_cpp_namespace_body_is_parsed():
    unit, errors = parse(
        """
        namespace demo {
            int helper(int x) { return x + 1; }
        }
        """,
        language="c++",
    )
    assert errors == []
    functions = [
        node for node in unit.walk() if isinstance(node, FunctionDecl)
    ]
    assert any(f.name == "helper" for f in functions)


def test_cpp_range_based_for():
    unit, errors = parse(
        """
        int total(const std::vector<int> &values) {
            int sum = 0;
            for (const auto &v : values) { sum += v; }
            return sum;
        }
        """,
        language="c++",
    )
    assert errors == []
    kinds = {node.kind for node in unit.walk()}
    assert "range_for_stmt" in kinds


def test_cpp_try_catch():
    unit, errors = parse(
        """
        int f() {
            try { return 1; }
            catch (const std::exception &e) { return 0; }
        }
        """,
        language="c++",
    )
    assert errors == []
    kinds = {node.kind for node in unit.walk()}
    assert "try_stmt" in kinds
    assert "catch_clause" in kinds


def test_qualified_constructor_definition():
    unit, errors = parse(
        """
        class Buffer {
        public:
            Buffer(int size);
        };
        Buffer::Buffer(int size) : size_(size) { }
        """,
        language="c++",
    )
    assert errors == []
    constructors = [
        node
        for node in unit.walk()
        if isinstance(node, FunctionDecl) and node.is_constructor
    ]
    assert constructors


def test_malformed_source_does_not_raise():
    unit, errors = parse("int f( { return ; ; ) }")
    assert unit is not None


def test_example_project_parses_cleanly():
    for name in ("utils.c", "features.c", "buffer.cpp"):
        unit, errors = parse_file(f"examples/sample_project/src/{name}")
        assert errors == [], f"{name}: {errors}"
        assert unit.declarations


def test_assignment_and_call_nodes():
    unit, _ = parse("void f(int *p) { *p = 1; g(*p); }")
    kinds = [node.kind for node in unit.walk()]
    assert "assignment" in kinds
    assert "call" in kinds
