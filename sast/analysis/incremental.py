"""Incremental analysis and change impact analysis.

When a project grows, re-analysing every file on every commit is wasteful.
The module computes the set of files that actually changed and the files
that depend on them, so that the analysis can be restricted to the code that
could have been affected by the change.
"""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Sequence

from sast.lexer.clexer import Lexer

#: Matches ``#include "foo.h"`` and ``#include <foo/bar.h>``.
INCLUDE_RE = re.compile(r'^\s*#\s*include\s*[<"]([^>"]+)[>"]', re.MULTILINE)


@dataclass
class ChangeSet:
    """The files touched by a change."""

    changed: set[str] = field(default_factory=set)
    added: set[str] = field(default_factory=set)
    removed: set[str] = field(default_factory=set)
    modified: set[str] = field(default_factory=set)
    base_ref: str = "HEAD"
    target_ref: str = "WORKTREE"
    available: bool = True
    message: str = ""

    @property
    def all_touched(self) -> set[str]:
        return self.changed | self.added | self.removed | self.modified

    def to_dict(self) -> dict:
        return {
            "changed": sorted(self.changed),
            "added": sorted(self.added),
            "removed": sorted(self.removed),
            "modified": sorted(self.modified),
            "base_ref": self.base_ref,
            "target_ref": self.target_ref,
            "available": self.available,
            "message": self.message,
        }


class GitClient:
    """A very small wrapper around the git command line."""

    def __init__(self, root: Path) -> None:
        self.root = Path(root)

    def available(self) -> bool:
        try:
            result = subprocess.run(
                ["git", "rev-parse", "--is-inside-work-tree"],
                cwd=self.root,
                capture_output=True,
                text=True,
                timeout=15,
            )
            return result.returncode == 0 and result.stdout.strip() == "true"
        except (OSError, subprocess.SubprocessError):
            return False

    def _run(self, *args: str) -> tuple[int, str]:
        try:
            result = subprocess.run(
                ["git", *args],
                cwd=self.root,
                capture_output=True,
                text=True,
                timeout=60,
            )
            return result.returncode, result.stdout
        except (OSError, subprocess.SubprocessError) as error:
            return 1, str(error)

    def repo_root(self) -> Path | None:
        """The root of the repository the project lives in."""
        code, output = self._run("rev-parse", "--show-toplevel")
        if code != 0:
            return None
        text = output.strip()
        if not text:
            return None
        return Path(text).resolve()

    def _relative(self, path: str, repo_root: Path | None) -> str | None:
        """Turn a repository relative path into a project relative one."""
        candidate = Path(path)
        if repo_root is None:
            return candidate.as_posix()
        absolute = (repo_root / candidate).resolve()
        try:
            return absolute.relative_to(self.root).as_posix()
        except ValueError:
            return None

    def changed_files(self, base: str = "HEAD", target: str = "WORKTREE") -> ChangeSet:
        """Files that differ between *base* and *target*."""
        if not self.available():
            return ChangeSet(available=False, message="not a git repository")

        code, output = self._run("diff", "--name-status", base, target, "--", ".")
        if code != 0:
            code, output = self._run("diff", "--name-status", base, "--", ".")
        if code != 0:
            return ChangeSet(
                available=False,
                message=output.strip() or "unable to compute the diff",
            )

        repo_root = self.repo_root()
        change_set = ChangeSet(base_ref=base, target_ref=target)
        for line in output.splitlines():
            parts = line.split("\t")
            if len(parts) < 2:
                continue
            status = parts[0][:1]
            path = self._relative(parts[-1].replace("\\", "/"), repo_root)
            if path is None:
                continue
            if status == "A":
                change_set.added.add(path)
            elif status == "D":
                change_set.removed.add(path)
            else:
                change_set.modified.add(path)
        change_set.changed = change_set.added | change_set.modified
        return change_set

    def untracked_files(self) -> set[str]:
        code, output = self._run("ls-files", "--others", "--exclude-standard", "--", ".")
        if code != 0:
            return set()
        repo_root = self.repo_root()
        paths: set[str] = set()
        for line in output.splitlines():
            if not line.strip():
                continue
            path = self._relative(line.replace("\\", "/"), repo_root)
            if path is not None:
                paths.add(path)
        return paths


class IncludeGraph:
    """The dependency graph built from the ``#include`` directives."""

    def __init__(self) -> None:
        self.includes: dict[str, set[str]] = {}
        self.by_name: dict[str, str] = {}

    def add_file(self, path: str, source: str) -> None:
        targets: set[str] = set()
        for match in INCLUDE_RE.finditer(source):
            include = match.group(1).replace("\\", "/")
            targets.add(include)
            self.by_name.setdefault(include, path)
            self.by_name.setdefault(Path(include).name, path)
        self.includes[path] = targets

    def dependents(self, paths: Iterable[str]) -> set[str]:
        """Files that include one of *paths* (directly or transitively)."""
        wanted = set(paths)
        for path in list(wanted):
            wanted.add(Path(path).name)
            wanted.add(str(Path(path).with_suffix("")).replace("\\", "/"))

        reverse: dict[str, set[str]] = {}
        for owner, targets in self.includes.items():
            for target in targets:
                reverse.setdefault(target, set()).add(owner)
                reverse.setdefault(Path(target).name, set()).add(owner)

        impacted: set[str] = set()
        queue = list(wanted)
        while queue:
            current = queue.pop()
            for dependent in reverse.get(current, set()):
                if dependent not in impacted:
                    impacted.add(dependent)
                    queue.append(dependent)
        return impacted


def build_include_graph(root: Path, files: Sequence[Path], project_relative) -> IncludeGraph:
    """Build the include graph of *files*."""
    graph = IncludeGraph()
    for path in files:
        try:
            source = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        graph.add_file(project_relative(path), source)
    return graph


def compute_impact(
    root: Path,
    files: Sequence[Path],
    changed: set[str],
    project_relative,
) -> set[str]:
    """The files to re-analyse: the changed ones plus their dependents."""
    graph = build_include_graph(root, files, project_relative)
    impacted = graph.dependents(changed)
    return set(changed) | impacted


def analyze_changes(
    root: Path,
    files: Sequence[Path],
    base: str = "HEAD",
    target: str = "WORKTREE",
    project_relative=None,
) -> tuple[ChangeSet, set[str]]:
    """Compute the change set and the impacted files."""
    client = GitClient(root)
    change_set = client.changed_files(base, target)
    if not change_set.available:
        return change_set, set()
    if target == "WORKTREE":
        change_set.changed |= client.untracked_files()
        change_set.added |= client.untracked_files()
        change_set.changed = change_set.added | change_set.modified
    if project_relative is None:
        def project_relative(path: Path) -> str:
            return path.as_posix()
    impacted = compute_impact(root, files, change_set.changed, project_relative)
    return change_set, impacted
