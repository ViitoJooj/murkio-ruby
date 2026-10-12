"""The pipeline itself is not a way in.

The workflows run with a token of this repository and, on release, will hold
the credentials that publish the package. This check fails when a workflow

- does not declare its permissions (the default token can write);
- runs on `pull_request_target` (a fork's code with this repository's token);
- uses an action that is not pinned to a commit (a tag can be moved to new
  code; the version goes in a comment, which Dependabot keeps up to date);
- puts text an outsider controls (a title, a branch name) straight into a
  shell command.
"""

import re
import sys
from pathlib import Path

# The checks leave nothing behind in the repository they inspect.
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).parent / "lib"))
import sdk  # noqa: E402

USES = re.compile(r"^\s*(?:-\s*)?uses:\s*([^\s#]+)")
COMMIT = re.compile(r"^[0-9a-f]{40}$")
UNTRUSTED = re.compile(r"\$\{\{\s*(?:github\.event\.|github\.head_ref|github\.ref_name)")
RUN = re.compile(r"^(\s*)(?:-\s*)?run:\s*(.*)$")


def check(path: Path) -> list[str]:
    violations = []
    lines = sdk.read(path).splitlines()

    if not any(line.startswith("permissions:") for line in lines):
        violations.append("no top-level `permissions:` (declare the least the workflow needs)")

    run_indent = None
    for index, line in enumerate(lines):
        number = index + 1
        if re.match(r"^\s*pull_request_target\s*:", line) or re.search(r"\[[^\]]*pull_request_target", line):
            violations.append(f"Line {number}: `pull_request_target` runs untrusted code with this repository's token")

        uses = USES.match(line)
        if uses and not uses.group(1).startswith(("./", "docker://")):
            action, _, ref = uses.group(1).partition("@")
            if not COMMIT.match(ref):
                violations.append(f"Line {number}: `{action}@{ref}` is not pinned to a commit")

        # A `run:` block lasts while the lines stay indented deeper than its key.
        run = RUN.match(line)
        indent = len(line) - len(line.lstrip())
        if run:
            run_indent = len(run.group(1))
            body = run.group(2)
        elif run_indent is not None and line.strip() and indent <= run_indent:
            run_indent = None
            body = ""
        else:
            body = line if run_indent is not None else ""
        if body and UNTRUSTED.search(body):
            violations.append(f"Line {number}: untrusted `${{{{ github.… }}}}` inside a shell command (pass it through `env:`)")
    return violations


def main() -> None:
    directory = sdk.root() / ".github" / "workflows"
    checked = sorted(list(directory.glob("*.yml")) + list(directory.glob("*.yaml"))) if directory.is_dir() else []
    sdk.report("WORKFLOW", {path: check(path) for path in checked}, checked)


if __name__ == "__main__":
    main()
