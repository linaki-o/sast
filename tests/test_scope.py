"""Tests for the symbol table and the scope resolution."""

from __future__ import annotations

from sast.analysis.scope import SymbolTable, type_size
from sast.ast.nodes import ArrayType, FunctionDecl, PointerType, PrimitiveType
from sast.ast.parser import parse_source


def build(code: str):
    unit, errors = parse_source(code, "test.c")
    assert errors == [], errors
    return unit, SymbolTable(unit)


def test_global_variables_are_declared():
    unit, symbols = build("int counter; static int limit = 10;")
    assert "counter" in symbols.globals
    assert symbols.globals["counter"].is_global
    assert symbols.globals["limit"].is_static


def test_functions_are_registered():
    unit, symbols = build("int add(int a, int b) { return a + b; }")
    assert "add" in symbols.functions
    assert symbols.functions["add"].parameters


def test_parameters_are_declared_in_the_function_scope():
    unit, symbols = build("int add(int a, int b) { return a + b; }")
    function = symbols.functions["add"]
    locals_ = symbols.local_symbols(function)
    names = {symbol.name for symbol in locals_}
    assert {"a", "b"} <= names


def test_local_variables_are_declared():
    unit, symbols = build(
        "void f(void) { int x = 1; char buffer[32]; { int y = 2; } }"
    )
    function = next(iter(symbols.functions.values()))
    locals_ = symbols.local_symbols(function)
    names = {symbol.name for symbol in locals_}
    assert {"x", "buffer", "y"} <= names


def test_local_variable_shadows_the_global_only_inside_its_scope():
    unit, symbols = build(
        """
        int value = 1;
        void f(void) { int value = 2; }
        """
    )
    function = symbols.functions["f"]
    local = symbols.lookup_in_function("value", function)
    assert local is not None
    assert local.scope.kind in {"block", "function"}
    global_ = symbols.globals["value"]
    assert local is not global_
    assert global_.scope.kind == "global"


def test_array_size_is_recorded():
    unit, symbols = build("void f(void) { char buffer[64]; }")
    function = next(iter(symbols.functions.values()))
    buffer_ = next(
        s for s in symbols.local_symbols(function) if s.name == "buffer"
    )
    assert buffer_.is_array
    assert buffer_.array_size == 64


def test_pointer_variables_are_flagged():
    unit, symbols = build("void f(char *p) { }")
    function = next(iter(symbols.functions.values()))
    pointer = next(s for s in symbols.local_symbols(function) if s.name == "p")
    assert pointer.is_pointer


def test_typedef_names_are_registered():
    unit, symbols = build("typedef int my_int; my_int value;")
    assert "my_int" in symbols.types


def test_enum_constants_are_registered():
    unit, symbols = build("enum Color { RED, GREEN };")
    assert "RED" in symbols.enum_constants
    assert "GREEN" in symbols.enum_constants


def test_lookup_at_prefers_the_enclosing_function():
    unit, symbols = build(
        """
        int shared = 1;
        int first(void) { int shared = 2; return shared; }
        int second(void) { return shared; }
        """
    )
    first = symbols.functions["first"]
    body = first.body
    found = symbols.lookup_at("shared", body)
    assert found is not None
    assert found.scope.kind in {"block", "function"}


def test_type_size_known_types():
    assert type_size(PrimitiveType("int")) == 4
    assert type_size(PrimitiveType("char")) == 1
    assert type_size(PrimitiveType("double")) == 8
    assert type_size(PointerType()) == 8


def test_type_size_of_array():
    unit, _ = build("int values[10];")
    declaration = unit.declarations[0]
    assert isinstance(declaration.type, ArrayType)
    assert type_size(declaration.type) == 40
