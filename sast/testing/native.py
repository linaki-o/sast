"""The native test engine: compile, run and measure with a real C compiler.

The native engine is optional.  When no compiler (or no coverage tool) is
installed the module reports itself as unavailable and the test runner falls
back to the portable interpreter.  Nothing in here is allowed to fail hard
because of a missing tool.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path
from typing import Any, Sequence

from sast.testing.coverage import CoverageCollector, CoverageReport

__all__ = [
    "native_available",
    "find_compiler",
    "find_coverage_tool",
    "generate_harness",
    "compile_harness",
    "run_harness",
    "run_gcov",
    "parse_gcov",
    "NativeRunError",
]

COMPILER_CANDIDATES = ("gcc", "clang", "cc")
GCOV_CANDIDATES = ("gcov", "llvm-cov", "gcov-14", "gcov-13", "gcov-12", "gcov-11")

RESULT_PREFIX = "CS_RESULT"


class NativeRunError(Exception):
    """Raised when the native engine cannot complete a run."""


def find_compiler() -> str | None:
    """Return the path of the first usable C compiler."""
    for name in COMPILER_CANDIDATES:
        path = shutil.which(name)
        if path:
            return path
    return None


def find_coverage_tool(compiler: str | None = None) -> str | None:
    """Return the path of the coverage tool matching *compiler*."""
    for name in GCOV_CANDIDATES:
        path = shutil.which(name)
        if path:
            return path
    return None


def native_available() -> bool:
    """True when a compiler able to build the harness is installed."""
    return find_compiler() is not None


def _c_string(text: str) -> str:
    escaped = (
        str(text)
        .replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("\n", "\\n")
        .replace("\r", "\\r")
        .replace("\t", "\\t")
    )
    return f'"{escaped}"'


def _c_literal(value: Any) -> str:
    if value is None:
        return "0"
    if isinstance(value, bool):
        return "1" if value else "0"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        return repr(value)
    return _c_string(str(value))


def _signature(function: Any) -> tuple[str, bool, bool]:
    """Return (return type description, is pointer, is void)."""
    type_node = getattr(function, "type", None)
    return_type = getattr(type_node, "return_type", None)
    if return_type is None:
        return "int", False, False
    description = return_type.describe()
    is_pointer = "pointer" in description or description.endswith("*")
    is_void = description.strip() == "void"
    return description, is_pointer, is_void


def _argument_plan(
    params: Sequence[Any], functions: dict[str, Any]
) -> tuple[list[str], list[str], list[str]]:
    """Build the C declarations, the call arguments and the local names."""
    declarations: list[str] = []
    arguments: list[str] = []
    names: list[str] = []
    for index, param in enumerate(params):
        name = f"cs_arg{index}"
        declared = getattr(param, "name", "") or name
        if isinstance(param, bool):
            declarations.append(f"        int {declared} = {1 if param else 0};")
            arguments.append(declared)
        elif isinstance(param, int):
            declarations.append(f"        int {declared} = {param};")
            arguments.append(declared)
        elif isinstance(param, float):
            declarations.append(f"        double {declared} = {param!r};")
            arguments.append(declared)
        elif isinstance(param, str) and param.startswith("&"):
            declarations.append(f"        int {declared} = 0;")
            arguments.append(f"&{param[1:].strip() or declared}")
        elif isinstance(param, str):
            declarations.append(f"        const char *{declared} = {_c_literal(param)};")
            arguments.append(declared)
        elif hasattr(param, "size") and hasattr(param, "address"):
            declarations.append(f"        int {declared} = 0;")
            arguments.append(f"&{declared}")
        elif hasattr(param, "capacity"):
            capacity = max(int(getattr(param, "capacity", 16)), 1)
            declarations.append(f"        char {declared}[{capacity}];")
            declarations.append(f"        memset({declared}, 0, sizeof({declared}));")
            arguments.append(declared)
        else:
            declarations.append(f"        int {declared} = 0;")
            arguments.append(declared)
        names.append(declared)
    return declarations, arguments, names


def generate_harness(
    tests: Sequence[Any],
    sources: Sequence[str],
    functions: dict[str, Any] | None = None,
) -> str:
    """Build the C harness that executes *tests* against *sources*."""
    functions = functions or {}
    lines: list[str] = []
    lines.append("#include <stdio.h>")
    lines.append("#include <stdlib.h>")
    lines.append("#include <string.h>")
    lines.append("")
    for source in sources:
        name = Path(source).name
        lines.append(f'#include "{name}"')
    lines.append("")
    lines.append(
        "static void cs_report(const char *id, int ok, const char *actual, const char *detail)"
    )
    lines.append("{")
    lines.append(
        '    printf("%s\\t%s\\t%d\\t%s\\t%s\\n", "CS_RESULT", id, ok, '
        'actual ? actual : "", detail ? detail : "");'
    )
    lines.append("}")
    lines.append("")
    lines.append("int main(void)")
    lines.append("{")
    for test in tests:
        identifier = getattr(test, "id", "test")
        target = getattr(test, "target", "")
        params = list(getattr(test, "params", []) or [])
        expected = getattr(test, "expected", None)
        assert_expr = getattr(test, "assert_expr", "") or ""
        function = functions.get(target)
        _description, is_pointer, is_void = (
            _signature(function) if function else ("int", False, False)
        )
        declarations, arguments, _names = _argument_plan(params, functions)
        lines.append(f"    /* {identifier} */")
        lines.append("    {")
        for declaration in declarations:
            lines.append(declaration)
        call = f"{target}({', '.join(arguments)})" if arguments else f"{target}()"
        if is_void:
            lines.append(f"        {call};")
            lines.append(
                f'        cs_report("{identifier}", 1, "", "");'
            )
        else:
            lines.append(f"        long long actual_value = (long long)({call});")
            lines.append("        char actual_text[128];")
            if is_pointer:
                lines.append(
                    '        snprintf(actual_text, sizeof(actual_text), "%s", '
                    "(const char *)actual_value);"
                )
            else:
                lines.append(
                    '        snprintf(actual_text, sizeof(actual_text), "%lld", actual_value);'
                )
            if expected is None:
                condition = "1"
            elif is_pointer and isinstance(expected, str):
                condition = f"strcmp(actual_text, {_c_literal(expected)}) == 0"
            else:
                condition = f"actual_value == (long long)({_c_literal(expected)})"
            lines.append(f"        int ok = ({condition});")
            if assert_expr:
                lines.append(f"        ok = ok && (({assert_expr}) != 0);")
            lines.append(
                f'        cs_report("{identifier}", ok, actual_text, '
                f'ok ? "passed" : "failed");'
            )
        lines.append("    }")
    lines.append("    return 0;")
    lines.append("}")
    return "\n".join(lines) + "\n"


def compile_harness(
    harness_source: str,
    sources: Sequence[str],
    workdir: str | Path,
    compiler: str | None = None,
    coverage: bool = True,
) -> Path | None:
    """Compile the harness and return the path of the executable."""
    compiler = compiler or find_compiler()
    if compiler is None:
        return None
    directory = Path(workdir)
    directory.mkdir(parents=True, exist_ok=True)
    harness_path = directory / "codeshield_harness.c"
    harness_path.write_text(harness_source, encoding="utf-8")
    executable = directory / "codeshield_harness"
    command = [compiler, "-o", str(executable), str(harness_path)]
    for source in sources:
        parent = Path(source).parent
        if str(parent):
            command.append(f"-I{parent}")
    if coverage:
        command.extend(["-fprofile-arcs", "-ftest-coverage", "--coverage"])
    command.extend(["-w", "-O0", "-g"])
    try:
        completed = subprocess.run(
            command, capture_output=True, text=True, timeout=180, cwd=str(directory)
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise NativeRunError(f"could not run the compiler: {error}") from error
    if completed.returncode != 0:
        raise NativeRunError(
            "the compiler rejected the harness: " + (completed.stderr or "").strip()
        )
    return executable


def run_harness(executable: Path, timeout: float = 60.0) -> tuple[dict[str, dict[str, Any]], str]:
    """Run the harness and parse its machine readable result lines."""
    try:
        completed = subprocess.run(
            [str(executable)], capture_output=True, text=True, timeout=timeout
        )
    except subprocess.TimeoutExpired as error:
        raise NativeRunError("the harness timed out") from error
    except (OSError, subprocess.SubprocessError) as error:
        raise NativeRunError(f"could not run the harness: {error}") from error
    results: dict[str, dict[str, Any]] = {}
    for line in completed.stdout.splitlines():
        if not line.startswith(RESULT_PREFIX):
            continue
        parts = line.split("\t")
        if len(parts) < 5:
            continue
        results[parts[1]] = {
            "passed": parts[2].strip() == "1",
            "actual": parts[3],
            "message": parts[4],
        }
    return results, completed.stdout


_GCOV_LINE = re.compile(r"^\s*(?P<count>[-#0-9]+):\s*(?P<line>\d+):")
_GCOV_BRANCH = re.compile(r"^\s*branch\s+(?P<index>\d+)\s+(?P<rest>.+)$")


def run_gcov(
    directory: str | Path,
    sources: Sequence[str],
    tool: str | None = None,
) -> bool:
    """Produce the ``.gcov`` files of *sources* inside *directory*."""
    tool = tool or find_coverage_tool()
    if tool is None:
        return False
    directory = Path(directory)
    produced = False
    for source in sources:
        command = [tool, "-b", "-c", str(Path(source).resolve())]
        try:
            subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=120,
                cwd=str(directory),
            )
        except (OSError, subprocess.SubprocessError):
            continue
        produced = True
    return produced


def parse_gcov(directory: str | Path, sources: Sequence[str]) -> CoverageReport:
    """Parse the ``.gcov`` files found in *directory* into a coverage report."""
    directory = Path(directory)
    collector = CoverageCollector()
    mapping = {Path(source).name: source for source in sources}
    for gcov_path in sorted(directory.glob("*.gcov")):
        _parse_gcov_file(gcov_path, collector, mapping)
    report = collector.report()
    return report


def _parse_gcov_file(
    path: Path, collector: CoverageCollector, mapping: dict[str, str] | None = None
) -> None:
    source_name = ""
    current_line = 0
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return
    for raw in lines:
        if "Source:" in raw and raw.strip().startswith("-"):
            source_name = raw.split("Source:", 1)[1].strip()
            if mapping:
                source_name = mapping.get(Path(source_name).name, source_name)
            current_line = 0
            continue
        match = _GCOV_LINE.match(raw)
        if match:
            current_line = int(match.group("line"))
            count = match.group("count")
            if count == "-" or not source_name:
                continue
            hits = 0 if count == "#" * len(count) else int(count)
            collector.declare_statement(source_name, current_line)
            if hits > 0:
                collector.hit_statement(source_name, current_line)
            continue
        branch = _GCOV_BRANCH.match(raw)
        if branch and source_name:
            identifier = f"gcov:{current_line}:{branch.group('index')}"
            collector.declare_branch(source_name, current_line, identifier)
            rest = branch.group("rest")
            if "never executed" not in rest:
                taken = re.search(r"taken\s+(\d+)", rest)
                if taken and int(taken.group(1)) > 0:
                    collector.hit_branch(source_name, current_line, identifier)
