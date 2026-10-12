"""Tokens, passwords and codes are never logged.

The SDK holds the user's password for a moment and the session tokens for as
long as the session lasts. A log line is read by people and tools that must
not see them, so this check fails when a logging or printing call receives
something whose name says it is one of those.
"""

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "lib"))
import sdk  # noqa: E402

CHECK = "log-secret"

SENSITIVE = re.compile(
    r"(password|senha|passwd|secret|token|totp|otp|verification_?code|reset_?code|recovery_?code|"
    r"client_?secret|refresh|verifier|credential|authorization|cookie)",
    re.IGNORECASE,
)

LOG_CALL = re.compile(
    r"(?<![\w.])(?:"
    r"console\.(?:log|info|warn|error|debug|trace)"
    r"|print|println|debugPrint|NSLog|os_log|puts|pp|var_dump|print_r|error_log|trigger_error"
    r"|System\.(?:out|err)\.print(?:ln|f)?"
    r"|Log\.[vdiwe]"
    r"|log\.(?:Print|Printf|Println|Fatal|Fatalf|Fatalln|Panic|Panicf)"
    r"|fmt\.(?:Print|Printf|Println)"
    r"|(?:logger|logging|log|Logger)\.(?:debug|info|warn|warning|error|exception|critical|fatal)"
    r"|warnings\.warn"
    r")\s*\("
)

INTERPOLATION = re.compile(r"\$\{([^}]*)\}|#\{([^}]*)\}|\\\(([^)]*)\)|\$([A-Za-z_][A-Za-z0-9_]*)|\{([A-Za-z_][^}:!]*)[^}]*\}")


def arguments(text: str, open_paren: int) -> str:
    """The text between a call's parentheses, across lines."""
    depth = 0
    quote = None
    index = open_paren
    while index < len(text):
        char = text[index]
        if quote:
            if char == "\\":
                index += 2
                continue
            if char == quote:
                quote = None
        elif char in "\"'`":
            quote = char
        elif char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return text[open_paren + 1:index]
        index += 1
    return text[open_paren + 1:]


def identifiers(args: str) -> str:
    """The arguments without what is only text: string literals are dropped,
    but what they interpolate is kept (that is a value, not a word)."""
    kept = []
    quote = None
    literal = []
    index = 0
    while index < len(args):
        char = args[index]
        if quote:
            if char == "\\" and index + 1 < len(args) and args[index + 1] != "(":
                index += 2
                continue
            if char == quote:
                for match in INTERPOLATION.finditer("".join(literal)):
                    kept.append(" " + next(group for group in match.groups() if group) + " ")
                quote = None
                literal = []
            else:
                literal.append(char)
        elif char in "\"'`":
            quote = char
        else:
            kept.append(char)
        index += 1
    return "".join(kept)


def main() -> None:
    results: dict[Path, list[str]] = {}
    checked = sdk.source_files()
    for path in checked:
        text = sdk.read(path)
        if sdk.is_generated(text):
            continue
        lines = text.splitlines()
        for match in LOG_CALL.finditer(text):
            index = text.count("\n", 0, match.start())
            if sdk.is_comment(lines[index]) or sdk.allowed(lines, index, CHECK):
                continue
            found = sorted({word.lower() for word in SENSITIVE.findall(identifiers(arguments(text, match.end() - 1)))})
            if found:
                call = match.group(0).rstrip("( ")
                results.setdefault(path, []).append(f"Line {index + 1}: `{call}` receives a sensitive value ({', '.join(found)})")
    sdk.report("SECRET IN LOG", results, checked)


if __name__ == "__main__":
    main()
