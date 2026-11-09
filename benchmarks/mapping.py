"""Cross tool defect taxonomy.

The benchmark corpus describes its defects with the identifiers of the
CodeShield rules.  To compare the analyser with other tools, every defect is
mapped onto a neutral *canonical defect* that lists the identifiers each
tool uses for it.

A canonical defect that a tool does not implement is **not applicable** to
that tool and is left out of its recall denominator, which keeps the
comparison fair: MISRA specific defects do not count against a tool that
does not implement MISRA.
"""

from __future__ import annotations

from typing import Iterable

#: The identifiers of every tool, indexed by canonical defect.
DEFECTS: dict[str, dict[str, object]] = {
    "DEFECT-UNBOUNDED-COPY": {
        "description": "An unbounded string copy writes into a fixed buffer.",
        "codeshield": {"SEC-BUF-001"},
        "cppcheck": {"bufferAccessOutOfBounds", "arrayIndexOutOfBounds"},
        "clang-tidy": {
            "clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling"
        },
    },
    "DEFECT-SPRINTF-BUFFER": {
        "description": "sprintf writes into a fixed buffer without a bound.",
        "codeshield": {"SEC-BUF-003"},
        "cppcheck": {"bufferAccessOutOfBounds"},
        "clang-tidy": {
            "clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling"
        },
    },
    "DEFECT-COPY-SIZE": {
        "description": "memcpy copies more bytes than the destination holds.",
        "codeshield": {"SEC-BUF-004"},
        "cppcheck": {"bufferAccessOutOfBounds"},
        "clang-tidy": {
            "clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling"
        },
    },
    "DEFECT-FORMAT-STRING": {
        "description": "A user controlled string is used as a format string.",
        "codeshield": {"SEC-FMT-001"},
        "cppcheck": {"formatNonPrintf", "printfFormatScanfArgType"},
        "clang-tidy": {"clang-analyzer-security.insecureAPI.printf"},
    },
    "DEFECT-COMMAND-INJECTION": {
        "description": "A command is built from a non constant argument.",
        "codeshield": {"SEC-CMD-001"},
        "cppcheck": set(),
        "clang-tidy": {"bugprone-command-processor"},
    },
    "DEFECT-HARDCODED-CREDENTIAL": {
        "description": "A credential is hard coded in the source.",
        "codeshield": {"SEC-CRED-001"},
        "cppcheck": set(),
        "clang-tidy": set(),
    },
    "DEFECT-UNCHECKED-ALLOCATION": {
        "description": "The result of an allocation is not checked against NULL.",
        "codeshield": {"SEC-NULL-003"},
        "cppcheck": {"nullPointerOutOfMemory", "nullPointer"},
        "clang-tidy": {"cert-err33-c"},
    },
    "DEFECT-DOUBLE-FREE": {
        "description": "The same allocation is released twice.",
        "codeshield": {"SEC-USE-002"},
        "cppcheck": {"doubleFree", "deallocuse"},
        "clang-tidy": set(),
    },
    "DEFECT-USE-AFTER-FREE": {
        "description": "Memory is used after it has been released.",
        "codeshield": {"SEC-USE-001"},
        "cppcheck": {"deallocuse", "useAfterFree"},
        "clang-tidy": {"clang-analyzer-use-after-free"},
    },
    "DEFECT-NULL-DEREFERENCE": {
        "description": "A pointer is dereferenced while it may be NULL.",
        "codeshield": {"SEC-NULL-001"},
        "cppcheck": {"nullPointer", "nullPointerOutOfMemory"},
        "clang-tidy": {"clang-analyzer-core.NullDereference"},
    },
    "DEFECT-TRUNCATION-IGNORED": {
        "description": "The return value of snprintf is ignored.",
        "codeshield": {"SEC-LEAK-001"},
        "cppcheck": set(),
        "clang-tidy": set(),
    },
    "DEFECT-WEAK-RANDOM": {
        "description": "rand() is used where a cryptographic value is needed.",
        "codeshield": {"SEC-RAND-001"},
        "cppcheck": set(),
        "clang-tidy": {"misc-predictable-rand"},
    },
    "DEFECT-WEAK-HASH": {
        "description": "A weak hash function is used.",
        "codeshield": {"SEC-CRYPTO-001"},
        "cppcheck": set(),
        "clang-tidy": set(),
    },
    "DEFECT-DEPRECATED-API": {
        "description": "A deprecated or unsafe standard library function is used.",
        "codeshield": {"QLT-DEPRECATED-001"},
        "cppcheck": set(),
        "clang-tidy": {
            "clang-analyzer-security.insecureAPI.DeprecatedOrUnsafeBufferHandling"
        },
    },
    "DEFECT-UNUSED-VARIABLE": {
        "description": "A local variable is assigned but never read.",
        "codeshield": {"QLT-UNUSED-001"},
        "cppcheck": {"unreadVariable"},
        "clang-tidy": {"clang-diagnostic-unused-variable"},
    },
    "DEFECT-UNUSED-PARAMETER": {
        "description": "A parameter of a function is never used.",
        "codeshield": {"QLT-UNUSED-002"},
        "cppcheck": {"unusedParameter"},
        "clang-tidy": {"misc-unused-parameters"},
    },
    "DEFECT-UNUSED-FUNCTION": {
        "description": "A function is defined but never called.",
        "codeshield": {"QLT-UNUSED-003"},
        "cppcheck": {"unusedFunction"},
        "clang-tidy": {"misc-use-internal-linkage"},
    },
    "DEFECT-VARIABLE-SHADOWING": {
        "description": "A local variable shadows an outer one.",
        "codeshield": {"QLT-SHADOW-001"},
        "cppcheck": {"shadowVariable"},
        "clang-tidy": {"bugprone-shadow-declaration-underscore"},
    },
    "DEFECT-GOTO": {
        "description": "A goto jumps inside the function.",
        "codeshield": {"QLT-GOTO-001"},
        "cppcheck": set(),
        "clang-tidy": {"bugprone-avoid-goto"},
    },
    "DEFECT-MISSING-BRACES": {
        "description": "The body of a control structure is not braced.",
        "codeshield": {"QLT-BRACE-001", "MISRA-15-007"},
        "cppcheck": {"missingBraces"},
        "clang-tidy": {"readability-braces-around-statements"},
    },
    "DEFECT-NULL-COMPARISON": {
        "description": "A pointer is compared with 0 instead of NULL.",
        "codeshield": {"QLT-NULL-002"},
        "cppcheck": {"pointerCompare"},
        "clang-tidy": set(),
    },
    "DEFECT-ASSIGNMENT-IN-CONDITION": {
        "description": "An assignment is used directly as a condition.",
        "codeshield": {"QLT-ASSIGN-001"},
        "cppcheck": set(),
        "clang-tidy": {"bugprone-assignment-in-if-condition"},
    },
    "DEFECT-MAGIC-NUMBER": {
        "description": "A literal with a meaning is used inline.",
        "codeshield": {"QLT-MAGIC-001"},
        "cppcheck": set(),
        "clang-tidy": {"readability-magic-numbers"},
    },
    "DEFECT-NON-TERMINATING-LOOP": {
        "description": "The condition of a loop can never become false.",
        "codeshield": {"QLT-LOOP-001", "QLT-LOOP-002"},
        "cppcheck": {"knownConditionTrueFalse", "tautologicalCondition"},
        "clang-tidy": {"bugprone-infinite-loop"},
    },
    "DEFECT-UNSIGNED-COUNTER": {
        "description": "An unsigned counter wraps around instead of ending.",
        "codeshield": {"QLT-LOOP-003"},
        "cppcheck": {"unsignedPositive"},
        "clang-tidy": set(),
    },
    "DEFECT-TOO-MANY-PARAMETERS": {
        "description": "A function takes more parameters than allowed.",
        "codeshield": {"QLT-PARAM-001"},
        "cppcheck": set(),
        "clang-tidy": {"bugprone-easily-swappable-parameters"},
    },
    "DEFECT-COMPLEXITY": {
        "description": "A function is more complex than the configured limit.",
        "codeshield": {"QLT-COMPLEX-001"},
        "cppcheck": {"functionComplexity"},
        "clang-tidy": {"readability-function-size"},
    },
    "DEFECT-SWITCH-WITHOUT-DEFAULT": {
        "description": "A switch statement has no default label.",
        "codeshield": {"MISRA-16-004"},
        "cppcheck": set(),
        "clang-tidy": {"bugprone-switch-missing-default-case"},
    },
    "DEFECT-DEFAULT-NOT-AT-EDGE": {
        "description": "The default label is neither first nor last.",
        "codeshield": {"MISRA-16-005"},
        "cppcheck": set(),
        "clang-tidy": set(),
    },
    "DEFECT-MULTIPLE-EXITS": {
        "description": "A function has more than one point of exit.",
        "codeshield": {"MISRA-15-005"},
        "cppcheck": set(),
        "clang-tidy": {"readability-function-cognitive-complexity"},
    },
    "DEFECT-COMMA-OPERATOR": {
        "description": "The comma operator is used.",
        "codeshield": {"MISRA-12-003"},
        "cppcheck": set(),
        "clang-tidy": {"bugprone-comma-operator"},
    },
    "DEFECT-TIME-FUNCTION": {
        "description": "A time function of the standard library is used.",
        "codeshield": {"MISRA-21-010"},
        "cppcheck": set(),
        "clang-tidy": set(),
    },
    "DEFECT-DYNAMIC-ALLOCATION": {
        "description": "Dynamic memory allocation is used.",
        "codeshield": {"MISRA-21-006"},
        "cppcheck": set(),
        "clang-tidy": set(),
    },
    "DEFECT-EXCEPTION-HANDLING": {
        "description": "The exception handling features are used.",
        "codeshield": {"MISRA-21-012"},
        "cppcheck": set(),
        "clang-tidy": {"bugprone-empty-catch"},
    },
}


def _build_reverse() -> dict[str, str]:
    reverse: dict[str, str] = {}
    for defect, entry in DEFECTS.items():
        for rule_id in entry.get("codeshield", set()) or set():
            reverse[rule_id] = defect
    return reverse


#: The CodeShield rule id of a canonical defect.
CODESHIELD_TO_DEFECT: dict[str, str] = _build_reverse()


def defect_of(rule_id: str) -> str | None:
    """The canonical defect a CodeShield rule stands for."""
    return CODESHIELD_TO_DEFECT.get(rule_id)


def tool_rules(defect: str, tool: str) -> set[str]:
    """The identifiers a tool uses for a canonical defect."""
    entry = DEFECTS.get(defect)
    if entry is None:
        return set()
    return set(entry.get(tool, set()) or set())


def applicable_defects(tool: str, defects: Iterable[str] | None = None) -> list[str]:
    """The canonical defects a tool can possibly detect."""
    candidates = list(defects) if defects is not None else list(DEFECTS)
    return [defect for defect in candidates if tool_rules(defect, tool)]


def describe(defect: str) -> str:
    entry = DEFECTS.get(defect) or {}
    return str(entry.get("description", ""))
