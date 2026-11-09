"""Tests for the C/C++ tokenizer."""

from __future__ import annotations

from sast.lexer.clexer import TokenType, tokenize


def test_tokenizes_keywords_identifiers_and_numbers():
    result = tokenize("int x = 42;", "a.c")
    kinds = [token.type for token in result.tokens]
    assert TokenType.KEYWORD in kinds
    assert TokenType.IDENTIFIER in kinds
    assert TokenType.NUMBER in kinds
    assert result.tokens[-1].type is TokenType.EOF


def test_captures_comments():
    result = tokenize("/* block */ int x; // line\n", "a.c")
    assert len(result.comments) == 2
    assert result.comments[0].block is True
    assert result.comments[1].block is False
    assert result.comments[1].doc is False


def test_recognises_doc_comments():
    result = tokenize("/// doc\n/** api */\nint x;", "a.c")
    assert result.comments[0].doc is True
    assert result.comments[1].doc is True


def test_decodes_string_escapes():
    result = tokenize('char *s = "a\\nb";', "a.c")
    literal = next(t for t in result.tokens if t.type is TokenType.STRING)
    assert literal.literal == "a\nb"


def test_collects_macros_and_includes():
    source = '#include <stdio.h>\n#define MAX 10\n#define ADD(a, b) ((a) + (b))\nint x;\n'
    result = tokenize(source, "a.c")
    assert result.includes == ["stdio.h"]
    assert result.macros["MAX"].body == "10"
    assert result.macros["ADD"].function_like is True
    assert result.macros["ADD"].params == ("a", "b")


def test_expands_function_like_macro():
    result = tokenize("#define ADD(a, b) ((a) + (b))\n", "a.c")
    assert result.macros["ADD"].expand(["1", "2"]) == "((1) + (2))"


def test_tracks_line_numbers():
    result = tokenize("int a;\nint b;\nint c;\n", "a.c")
    lines = [t.location.line for t in result.tokens if t.type is TokenType.IDENTIFIER]
    assert lines == [1, 2, 3]


def test_longest_match_operators():
    result = tokenize("a <<= 1; a >>= 2; a ... b;", "a.c")
    operators = [t.value for t in result.tokens if t.type is TokenType.PUNCTUATOR]
    assert "<<=" in operators
    assert ">>=" in operators
    assert "..." in operators


def test_cpp_keywords_are_recognised():
    result = tokenize("class Foo { public: void bar(); };", "a.cpp")
    keywords = {t.value for t in result.tokens if t.type is TokenType.KEYWORD}
    assert "class" in keywords
    assert "public" in keywords


def test_counts_code_comment_and_blank_lines():
    result = tokenize("int a;\n\n// comment\nint b;\n", "a.c")
    assert result.lines_total == 4
    assert result.lines_code >= 2
    assert result.lines_comment >= 1


def test_unterminated_string_is_reported():
    result = tokenize('char *s = "abc\n', "a.c")
    assert any("unterminated" in error for error in result.errors)
