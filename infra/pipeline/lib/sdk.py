"""What the checks of an SDK repository share: which files are the library's
own source, how a line is exempted, and how results are printed.

The checks run in every Murkio SDK repository, whatever its language. They
are synced from the identity service (libs/pipeline/validators): change them
there, not in a copy.
"""

import re
import sys
from pathlib import Path

GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
RESET = "\033[0m"

# Third-party code, build output, the vendored spec and the pipeline itself
# are not the library's source.
IGNORED_DIRS = {
    ".git", "node_modules", "dist", "build", ".build", ".dart_tool", ".gradle", ".kotlin", "vendor",
    ".venv", "venv", "target", "coverage", "spec", "infra", ".github", "__pycache__", ".swiftpm",
}

SOURCE_SUFFIXES = {
    ".ts", ".tsx", ".js", ".mjs", ".cjs", ".go", ".py", ".php", ".rb", ".java", ".kt", ".swift", ".dart",
}

TEST_DIRS = {"test", "tests", "Tests", "__tests__", "androidTest", "example", "examples", "scripts"}

# A line (or the comment right above it) with this marker and the name of the
# check is a reviewed exception: `murkio:allow <check> <why>`.
ALLOW = re.compile(r"murkio:allow\s+([a-z-]+)")

COMMENT_PREFIXES = ("//", "#", "*", "/*", "--", '"""', "'''")


def root() -> Path:
    return Path(sys.argv[1]) if len(sys.argv) > 1 else Path(".")


def in_scope(path: Path) -> bool:
    return not IGNORED_DIRS.intersection(path.parts)


def is_test(path: Path) -> bool:
    name = path.name
    if TEST_DIRS.intersection(path.parts):
        return True
    return (
        name.endswith(("_test.go", "_test.dart", ".test.ts", ".test.tsx", ".spec.ts", "Test.java", "Test.kt", "Tests.swift"))
        or name.startswith("test_")
        or name in {"tsup.config.ts", "vitest.config.ts", "Package.swift"}
    )


def is_generated(text: str) -> bool:
    return "DO NOT EDIT" in "\n".join(text.splitlines()[:5])


def source_files(include_tests: bool = False) -> list[Path]:
    """The library's own source files, sorted, without generated ones."""
    files = []
    for path in sorted(root().rglob("*")):
        if not path.is_file() or path.suffix not in SOURCE_SUFFIXES or not in_scope(path.relative_to(root())):
            continue
        if not include_tests and is_test(path.relative_to(root())):
            continue
        files.append(path)
    return files


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="ignore")


def is_comment(line: str) -> bool:
    return line.strip().startswith(COMMENT_PREFIXES)


def allowed(lines: list[str], index: int, check: str) -> bool:
    """True when line `index` carries the exemption marker for `check`, on
    itself or in the comment lines right above it."""
    position = index
    while position >= 0:
        marker = ALLOW.search(lines[position])
        if marker and marker.group(1) == check:
            return True
        position -= 1
        if position < 0 or not is_comment(lines[position]):
            break
    return False


def report(tag: str, results: dict[Path, list[str]], checked: list[Path]) -> None:
    """Prints one line per file, the violations under it, and exits 1 when there is any."""
    failed = False
    for path in checked:
        violations = results.get(path, [])
        if violations:
            failed = True
            print(f"{RED}[ERROR][{tag}]{RESET} {path}")
            for violation in violations:
                print(f"  {YELLOW}↳ {violation}{RESET}")
        else:
            print(f"{GREEN}[OK]{RESET} {path}")
    if not checked:
        print("No files to check.")
    if failed:
        sys.exit(1)
