"""No character of the source is invisible.

A bidirectional control or a zero-width character makes code read one way and
run another ("Trojan Source"), and a raw line separator ends a line for the
JavaScript parser but not in the editor. This check fails on any of them in
the library and in its tests. Where the code really needs such a character it
is written as an escape (`\\u2028`), which every language here has.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "lib"))
import sdk  # noqa: E402

CHECK = "hidden-character"

# Written as code points on purpose: this file obeys its own rule.
RANGES = [
    (0x0000, 0x0008), (0x000B, 0x000C), (0x000E, 0x001F), (0x007F, 0x009F),  # control characters (tab and line ends are fine)
    (0x00AD, 0x00AD),  # soft hyphen
    (0x200B, 0x200F),  # zero width space, joiners, direction marks
    (0x2028, 0x2029),  # line and paragraph separators
    (0x202A, 0x202E),  # bidirectional embeddings and overrides
    (0x2060, 0x2064),  # word joiner, invisible operators
    (0x2066, 0x2069),  # bidirectional isolates
    (0xFEFF, 0xFEFF),  # byte order mark / zero width no-break space
]


def hidden(char: str) -> bool:
    code = ord(char)
    return any(low <= code <= high for low, high in RANGES)


def main() -> None:
    results: dict[Path, list[str]] = {}
    checked = sdk.source_files(include_tests=True)
    for path in checked:
        text = path.read_text(encoding="utf-8", errors="replace")
        if sdk.is_generated(text):
            continue
        # A byte order mark is tolerated only as the very first character.
        lines = text.removeprefix(chr(0xFEFF)).split("\n")
        for index, line in enumerate(lines):
            found = sorted({f"U+{ord(char):04X}" for char in line.rstrip("\r") if hidden(char)})
            if found and not sdk.allowed(lines, index, CHECK):
                results.setdefault(path, []).append(f"Line {index + 1}: invisible character {', '.join(found)} (write it as an escape)")
    sdk.report("HIDDEN CHARACTER", results, checked)


if __name__ == "__main__":
    main()
