"""Synthetic project generator for the scale benchmark.

The generator produces a project whose modules are realistic in size but
whose content is deterministic, so that two runs measure exactly the same
work and the scaling behaviour can be compared.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Sequence

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

MODULE_TEMPLATE = """\
/*
 * Generated module {index}.
 *
 * The module mimics the shape of a real driver module: a handful of
 * structures, a set of accessors and a couple of stateful operations.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MODULE_{index}_CAPACITY 16
#define MODULE_{index}_NAME_MAX 32

typedef struct
{{
    int  identifier;
    char name[MODULE_{index}_NAME_MAX];
    long counter;
}} Module{index}Entry;

typedef struct
{{
    Module{index}Entry items[MODULE_{index}_CAPACITY];
    int            count;
}} Module{index}Table;

static Module{index}Table module_{index}_table;

int module_{index}_valid(const Module{index}Entry *entry)
{{
    if (entry == NULL) {{
        return 0;
    }}
    if (entry->identifier < 0) {{
        return 0;
    }}
    if (entry->name[0] == '\\0') {{
        return 0;
    }}
    return 1;
}}

void module_{index}_reset(void)
{{
    int index;

    for (index = 0; index < MODULE_{index}_CAPACITY; index++) {{
        module_{index}_table.items[index].identifier = 0;
        module_{index}_table.items[index].name[0] = '\\0';
        module_{index}_table.items[index].counter = 0;
    }}
    module_{index}_table.count = 0;
}}

int module_{index}_add(int identifier, const char *name)
{{
    Module{index}Entry candidate;

    if (module_{index}_table.count >= MODULE_{index}_CAPACITY) {{
        return -1;
    }}
    if (name == NULL) {{
        return -1;
    }}
    candidate.identifier = identifier;
    candidate.counter = 0;
    strncpy(candidate.name, name, sizeof(candidate.name) - 1);
    candidate.name[sizeof(candidate.name) - 1] = '\\0';
    module_{index}_table.items[module_{index}_table.count] = candidate;
    module_{index}_table.count++;
    return 0;
}}

const Module{index}Entry *module_{index}_find(int identifier)
{{
    int index;

    for (index = 0; index < module_{index}_table.count; index++) {{
        if (module_{index}_table.items[index].identifier == identifier) {{
            return &module_{index}_table.items[index];
        }}
    }}
    return NULL;
}}

long module_{index}_total(void)
{{
    long total = 0;
    int  index;

    for (index = 0; index < module_{index}_table.count; index++) {{
        total += module_{index}_table.items[index].counter;
    }}
    return total;
}}

int module_{index}_count(void)
{{
    return module_{index}_table.count;
}}

int module_{index}_bump(int identifier)
{{
    Module{index}Entry *entry =
        (Module{index}Entry *)module_{index}_find(identifier);

    if (entry == NULL) {{
        return -1;
    }}
    entry->counter++;
    return 0;
}}

static int module_{index}_describe(const Module{index}Entry *entry, char *out, int size)
{{
    int written;

    if (!module_{index}_valid(entry)) {{
        return -1;
    }}
    written = snprintf(out, (size_t)size, "%d:%s", entry->identifier, entry->name);
    if (written < 0) {{
        return -1;
    }}
    return written;
}}

int module_{index}_render(int identifier, char *out, int size)
{{
    return module_{index}_describe(module_{index}_find(identifier), out, size);
}}

void module_{index}_summary(void)
{{
    printf("module {index}: %d entries\\n", module_{index}_table.count);
}}
"""


LARGE_FUNCTION_TEMPLATE = """\
static int large_{index}_value;

int large_{index}_compute(int seed, const char *label)
{{
    int result = seed;

    if (seed == 0) {{
        return 0;
    }}
    if (label == NULL) {{
        return -1;
    }}
    result += (int)strlen(label);
    if (result > 100) {{
        result = 100;
    }}
    large_{index}_value = result;
    return result;
}}

void large_{index}_reset(void)
{{
    large_{index}_value = 0;
}}

"""


def generate_project(target: Path, modules: int = 8, template: Path | None = None) -> Path:
    """Write a project made of *modules* generated modules into *target*."""
    source = target / "src"
    source.mkdir(parents=True, exist_ok=True)
    for index in range(modules):
        content = MODULE_TEMPLATE.format(index=index)
        (source / f"module_{index:04d}.c").write_text(content, encoding="utf-8")
    if template is not None and Path(template).is_file():
        shutil_copy(Path(template), source / "template.c")
    return target


def shutil_copy(source: Path, target: Path) -> None:
    target.write_bytes(source.read_bytes())


def generate_single(target: Path, functions: int = 60) -> Path:
    """Write a project made of one very large translation unit."""
    source = target / "src"
    source.mkdir(parents=True, exist_ok=True)
    parts = [
        "#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>\n\n"
    ]
    for index in range(functions):
        parts.append(LARGE_FUNCTION_TEMPLATE.format(index=index))
    (source / "large.c").write_text("".join(parts), encoding="utf-8")
    return target


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="generate",
        description="Generate a synthetic project for the scale benchmark",
    )
    parser.add_argument("target", help="directory the project is written to")
    parser.add_argument("--modules", type=int, default=8)
    parser.add_argument("--single", type=int, help="write one large file instead")
    parser.add_argument("--template", help="an extra file copied into the project")
    args = parser.parse_args(argv)

    if args.single:
        target = generate_single(Path(args.target), functions=args.single)
    else:
        target = generate_project(
            Path(args.target), modules=args.modules, template=args.template
        )
    files = sorted((target / "src").glob("*.c"))
    lines = sum(len(path.read_text(encoding="utf-8").splitlines()) for path in files)
    print(f"{len(files)} files, {lines} lines written to {target}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
