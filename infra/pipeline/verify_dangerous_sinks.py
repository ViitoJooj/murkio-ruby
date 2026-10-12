"""Nothing the SDK receives is run as code or parsed as markup by accident.

The SDK draws a canvas that comes from the network and writes components into
pages. The whole design keeps that data as data: text is set as text,
attributes are escaped, nothing is evaluated. This check fails on the
constructs that break that rule (evaluating strings, raw HTML sinks, unsafe
deserialization, shelling out, marking a string as trusted markup).

A use that is really needed is a reviewed exception: put
`murkio:allow dangerous-sink <why it is safe>` on the line or right above it.
"""

import re
import sys
from pathlib import Path

# The checks leave nothing behind in the repository they inspect.
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).parent / "lib"))
import sdk  # noqa: E402

CHECK = "dangerous-sink"

SCRIPT = [
    r"(?<![\w.])eval\s*\(", r"\bnew\s+Function\s*\(", r"\.innerHTML\b", r"\.outerHTML\b", r"\binsertAdjacentHTML\b",
    r"\bdocument\.write(?:ln)?\s*\(", r"\bdangerouslySetInnerHTML\b", r"\bv-html\b", r"\{@html\b",
    r"\bbypassSecurityTrust\w*", r"\.srcdoc\b", r"\bset(?:Timeout|Interval)\s*\(\s*[\"'`]",
]
JVM = [
    r"\bRuntime\.getRuntime\b", r"\bProcessBuilder\b", r"\bObjectInputStream\b", r"\bScriptEngine\w*", r"\bClass\.forName\b",
    r"\bevaluateJavascript\b", r"\baddJavascriptInterface\b", r"\bWebView\b", r"\bDexClassLoader\b",
]

RULES = {
    ".ts": SCRIPT, ".tsx": SCRIPT, ".js": SCRIPT, ".mjs": SCRIPT, ".cjs": SCRIPT,
    ".py": [
        r"(?<![\w.])eval\s*\(", r"(?<![\w.])exec\s*\(", r"\bpickle\.loads?\b", r"\bmarshal\.loads?\b", r"\byaml\.load\s*\(",
        r"\bsubprocess\b", r"\bos\.(?:system|popen)\s*\(", r"(?<![\w.])__import__\s*\(", r"\bmark_safe\s*\(", r"(?<!class )(?<![\w.])Markup\s*\(",
    ],
    ".go": [
        r"\btemplate\.(?:HTML|HTMLAttr|JS|JSStr|CSS|URL|Srcset)\s*\(", r"\"os/exec\"", r"\"unsafe\"", r"\"text/template\"",
        r"\"reflect\"", r"\bgob\.NewDecoder\b",
    ],
    ".php": [
        r"(?<![\w>:$])(?:eval|unserialize|assert|extract|create_function)\s*\(",
        r"(?<![\w>:$])(?:exec|shell_exec|system|passthru|proc_open|popen|pcntl_exec)\s*\(", r"`[^`\n]+`",
        r"\b(?:include|require)(?:_once)?\s*\(?\s*\$", r"\$\$\w",
    ],
    ".rb": [
        r"(?<![\w.])eval\b", r"\b(?:instance|class|module)_eval\b", r"\bMarshal\.load\b", r"\bYAML\.load\b(?!_file)",
        r"(?<![\w.])(?:system|exec|spawn)\s*\(", r"`[^`\n]+`", r"%x[\[({]", r"\.html_safe\b", r"\bconstantize\b",
        r"(?<![\w.])open\s*\(\s*[^\"']",
    ],
    ".java": JVM,
    ".kt": JVM,
    ".swift": [
        r"\bNSKeyedUnarchiver\b", r"\bevaluateJavaScript\b", r"\bWKWebView\b", r"\bUIWebView\b", r"\bNSExpression\b",
        r"\bdlopen\s*\(", r"\bNSClassFromString\b", r"\bProcess\s*\(\s*\)",
    ],
    ".dart": [
        r"dart:mirrors", r"\bFunction\.apply\b", r"\bsetInnerHtml\b", r"\binnerHtml\b", r"\bHtmlElementView\b",
        r"\bWebView\w*", r"dart:ffi", r"\bProcess\.(?:run|start)\b",
    ],
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
            if sdk.is_comment(line) or sdk.allowed(lines, index, CHECK):
                continue
            for pattern in patterns:
                match = pattern.search(line)
                if match:
                    results.setdefault(path, []).append(
                        f"Line {index + 1}: `{match.group(0).strip()}` (explain why it is safe with `murkio:allow {CHECK} ...`, or remove it)"
                    )
    sdk.report("DANGEROUS SINK", results, checked)


if __name__ == "__main__":
    main()
