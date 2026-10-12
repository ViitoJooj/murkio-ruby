"""A secret key never belongs in an SDK.

An SDK is configured with the publishable key (pk_...) only: it ships inside
apps and pages, where anything it carries is public. This check fails when
something that looks like a secret key (sk_...) shows up in the library's
source or in its documentation. Tests may use made-up ones, to prove that the
SDK refuses them.
"""

import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "lib"))
import sdk  # noqa: E402

CHECK = "secret-key"
SECRET_KEY = re.compile(r"\bsk_[A-Za-z0-9]{3,}[A-Za-z0-9_]*")
DOCS = {".md", ".txt", ".yaml", ".yml", ".json", ".toml", ".xml", ".plist", ".gradle", ".kts"}


def files() -> list[Path]:
    found = sdk.source_files()
    for path in sorted(sdk.root().rglob("*")):
        relative = path.relative_to(sdk.root())
        if path.is_file() and path.suffix in DOCS and sdk.in_scope(relative) and not sdk.is_test(relative):
            found.append(path)
    return found


def main() -> None:
    results: dict[Path, list[str]] = {}
    checked = files()
    for path in checked:
        lines = sdk.read(path).splitlines()
        for index, line in enumerate(lines):
            for match in SECRET_KEY.finditer(line):
                if not sdk.allowed(lines, index, CHECK):
                    results.setdefault(path, []).append(
                        f"Line {index + 1}: `{match.group(0)[:12]}…` looks like a secret key; an SDK only takes the publishable key"
                    )
    sdk.report("SECRET KEY", results, checked)


if __name__ == "__main__":
    main()
