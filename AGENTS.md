# AGENTS.md

Guidance for AI coding agents (and humans) working in this repository.

## What this project is

CodeShield is a C/C++ static analysis, unit testing and requirements traceability
platform written in Python. The Python code is the product: the C/C++ front-end
(lexer, parser, symbol table) is implemented from scratch, so no third party C
parser is involved.

## Ground rules

1. **Never edit files you were not asked to edit.** The repository is organised
   in layers with clear ownership. If a change seems to require touching another
   layer, prefer adding an extension point instead.
2. **No comments in the code.** Docstrings are allowed on public API, inline
   comments are not. The existing code follows this convention.
3. **Keep the core dependency free.** The analysis chain may only use
   `PyYAML` and `pydantic`. `fastapi`, `uvicorn`, `jinja2` and `PySide6` are
   optional extras and must be imported lazily so that `import sast` works
   without them.
4. **Python 3.10+.** Use `from __future__ import annotations` and modern
   typing syntax.

## Architecture

```
sast/core/          domain model (Violation, AnalysisResult), config, baseline
sast/lexer/         tokenizer, preprocessor directives, macro table
sast/ast/           AST node classes + recursive descent parser
sast/analysis/      symbol table, scopes, metrics, value ranges, include graph
sast/rules/         rule engine, registry, builtin packs
sast/testing/       C interpreter, native pipeline, coverage model, runner
sast/traceability/  requirement importers, matrix, matrix reports
sast/report/        HTML / JSON / SARIF / XML renderers
sast/server/        FastAPI application
sast/gui/           PySide6 desktop application
sast/cli.py         command line entry point
benchmarks/         benchmark corpus, ground truth and measurement harness
```

The analysis pipeline is strictly one-directional:

```
source -> Lexer -> Parser -> AST -> SymbolTable -> FileContext -> RuleEngine -> AnalysisResult
```

## Conventions

### Writing a rule

Rules live in `sast/rules/builtin/`. Each rule is a class registered with
`@register`:

```python
@register
class Example(Rule):
    id = "SEC-EXA-001"
    name = "Example rule"
    category = "security"
    severity = Severity.HIGH
    description = "..."
    recommendation = "..."
    cwe = (120,)

    def check(self, ctx):
        for call in ctx.find_calls("strcpy"):
            yield ctx.report(self, call, "the message")
```

Rules must:

- never raise; the engine catches exceptions but a throwing rule is a bug;
- be resilient to unexpected AST shapes (skip rather than crash);
- report through `ctx.report(self, node, message)` so that fingerprints,
  snippets and metadata are filled in consistently;
- use `ctx` helpers instead of re-implementing type reasoning:
  `ctx.resolve`, `ctx.resolve_type`, `ctx.base_identifier`, `ctx.const_int`,
  `ctx.array_size_of`, `ctx.is_null_check`, `ctx.enclosing_function`,
  `ctx.find_calls`, `ctx.doc_comment_for`.

### The parser

`sast/ast/parser.py` is a recursive-descent parser for a practical subset of
C and C++. Two invariants matter and are easy to break:

1. **Every node that owns children must link them with `node.add(child)`.**
   `Node.walk()` traverses `children`, so an unlinked declaration becomes
   invisible to every rule. When adding a node type, wire its children.
2. **Scope resolution is scope aware.** `SymbolTable.lookup_at(name, node)`
   resolves a name as seen from *node*; a flat lookup can return a variable
   belonging to another function.

If a construct fails to parse, prefer fixing the parser over adding a
workaround in a consumer module. Parser workarounds accumulate quickly.

### The interpreter

`sast/testing/interpreter.py` executes a subset of C on the AST. It is the
fallback test engine used when no C compiler is installed, so it must stay
importable and functional on a machine with no toolchain.

Guard rails (step counter, recursion limit) are mandatory: an accidental
infinite loop in the analysed code must not hang the test run.

## Testing

```bash
python -m pytest -q
```

The suite lives in `tests/` and mirrors the package layout. When you change a
layer, add or update the matching test module. A change is not finished until
`python -m pytest -q` is green.

Useful manual checks against the bundled example project:

```bash
python -m sast.cli analyze examples/sample_project
python -m sast.cli test examples/sample_project
python -m sast.cli trace examples/sample_project
python -m sast.cli rules --json | head -20
```

The example project is `examples/sample_project`; it deliberately contains
real defects so the analysers have something to find. Its expected findings
are:

- `QLT-DEPRECATED-001` on `src/utils.c` (`strcpy`)
- `SEC-LEAK-001` on `src/utils.c` (`snprintf` return value ignored)
- `QLT-LOOP-001` / `QLT-LOOP-002` / `QLT-LOOP-003` on `src/buffer.cpp` (the
  unsigned loop counter)

If your change alters those, update the expectation rather than the rule.

## Benchmarking

```bash
python -m benchmarks.run_bench --mode all
```

The benchmark is a regression test, not a decoration. It measures:

- **recall** against the defects planted in `benchmarks/corpus/` and marked
  inline with `/* sast:expect RULE-ID */`;
- **conformance** against `benchmarks/corpus/manifest.yaml`, the frozen
  list of every expected finding;
- **throughput**, **project scaling** and **translation unit size scaling`;
- **cross tool recall** against Cppcheck and Clang-Tidy through the
  canonical defect taxonomy in `benchmarks/mapping.py`.

Two rules for anyone touching a rule:

1. A rule that fires on correct code is a bug. The corpus contains a
   `clean.c` control group and `tests/test_benchmarks.py` fails when a
   security rule fires on it.
2. When the behaviour of a rule changes on purpose, regenerate the baseline
   with `python -m benchmarks.generate_manifest --write` and review the
   diff. Never regenerate it to hide a regression.

`tests/test_fixtures.py` pins the checksums of the example project and of
the corpus. If a fixture fails that check, the file was modified by
accident; restore it rather than updating the checksum.

Adding a rule that covers a new kind of defect means adding it to
`benchmarks/mapping.py` as well, otherwise the cross tool comparison
cannot score it.

## Common tasks

| Task | Where to start |
| --- | --- |
| Add a static analysis rule | `sast/rules/builtin/security.py` or `quality.py` |
| Support a new C/C++ construct | `sast/ast/parser.py` |
| Add a report format | `sast/report/` |
| Extend the coverage model | `sast/testing/coverage.py` |
| Support a new requirement format | `sast/traceability/importer.py` |
| Add a CLI command | `sast/cli.py` |
| Measure or guard a behaviour | `benchmarks/` and `tests/test_benchmarks.py` |

## Do not

- introduce a runtime dependency on a C/C++ parsing library;
- make `import sast` pull in FastAPI, uvicorn, jinja2 or PySide6;
- special case the example project inside the engine or the rules;
- swallow exceptions in the rule engine without recording them in
  `AnalysisResult.warnings`;
- write inline comments.
