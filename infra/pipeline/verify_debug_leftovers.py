"""No debugging leftovers in the library.

An SDK runs inside somebody else's app: what it prints lands in their console
and their logs. The only output it is allowed is a hint to the developer that
integrates it, and those lines carry the `[murkio]` tag. Anything else (a
print left from a debugging session, a breakpoint, a stack trace dump) fails
this check.
"""

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "lib"))
import sdk  # noqa: E402

CHECK = "debug"
TAG = "[murkio]"

SCRIPT = [r"\bconsole\.(?:log|debug|trace|table|dir)\s*\(", r"(?<![\w.])debugger\b", r"(?<![\w.])alert\s*\("]
JVM = [r"\bSystem\.(?:out|err)\.print", r"\.printStackTrace\s*\(", r"(?<![\w.])println\s*\(", r"\bLog\.[vd]\s*\("]

RULES = {
    ".ts": SCRIPT, ".tsx": SCRIPT, ".js": SCRIPT, ".mjs": SCRIPT, ".cjs": SCRIPT,
    ".py": [r"(?<![\w.])print\s*\(", r"(?<![\w.])breakpoint\s*\(", r"\bpdb\.set_trace\s*\(", r"(?<![\w.])pprint\s*\("],
    ".go": [r"\bfmt\.Print(?:f|ln)?\s*\(", r"(?<![\w.])println\s*\(", r"\bspew\.Dump\s*\("],
    ".php": [r"(?<![\w>:$])(?:var_dump|print_r|var_export|dd|dump|debug_print_backtrace)\s*\("],
    ".rb": [r"\bbinding\.(?:pry|irb)\b", r"(?<![\w.])byebug\b", r"^\s*(?:puts|pp|p)\s", r"(?<![\w.])debugger\b"],
    ".java": JVM,
    ".kt": JVM,
    ".swift": [r"(?<![\w.])(?:print|debugPrint|NSLog|dump)\s*\("],
    ".dart": [r"(?<![\w.])print\s*\(", r"(?<![\w.])debugger\s*\("],
}


def main() -> None:
    results: dict[Path, list[str]] = {}
    checked = sdk.source_files()
    for path in checked:
        text = sdk.read(path)
        if sdk.is_generated(text):
            continue
        lines = text.splitlines()
        patterns = [re.compile(pattern) for pattern in RULES.get(path.suffix, [])]
        for index, line in enumerate(lines):
            if sdk.is_comment(line) or TAG in line or sdk.allowed(lines, index, CHECK):
                continue
            # A hint may spread over lines: the tag then sits right below the call.
            following = " ".join(lines[index + 1:index + 3])
            for pattern in patterns:
                match = pattern.search(line)
                if match and TAG not in following:
                    results.setdefault(path, []).append(
                        f"Line {index + 1}: `{match.group(0).strip()}` looks like a debugging leftover (developer hints carry the {TAG} tag)"
                    )
    sdk.report("DEBUG LEFTOVER", results, checked)


if __name__ == "__main__":
    main()
