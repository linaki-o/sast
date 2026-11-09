"""CodeShield - C/C++ 静态分析、单元测试与需求追踪平台.

The package is organised in layers:

``sast.core``
    Domain model shared by every layer (locations, severities, violations).
``sast.lexer`` / ``sast.ast``
    Front-end: tokenizer, preprocessor handling and a recursive descent
    parser producing a lightweight C/C++ AST.
``sast.analysis``
    Semantic layer: symbol tables, control flow graphs, data-flow and
    taint propagation.
``sast.rules``
    Rule engine plus the bundled rule packs (security / quality /
    standards).
``sast.testing``
    Unit test runtime, stub generation and coverage collection.
``sast.traceability``
    Requirement parsing and the requirement <-> test matrix.
``sast.report``
    Report renderers (HTML, JSON, SARIF, XML) and the project dashboard.
"""

__version__ = "0.1.0"
__all__ = ["__version__"]
