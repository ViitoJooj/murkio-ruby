"""The copy of the shared spec is the one that was synced.

Every Murkio SDK is tested against the same contract: vectors, fixtures,
translations and the default canvas, kept in the identity service and copied
into spec/ here. A copy edited by hand would make this SDK agree with itself
and disagree with the others, so this check fails when a file differs from
the checksum written at the last sync, or when a file is missing or extra.
"""

import hashlib
import sys
from pathlib import Path

# The checks leave nothing behind in the repository they inspect.
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).parent / "lib"))
import sdk  # noqa: E402

MANIFEST = "CHECKSUMS"


def main() -> None:
    spec = sdk.root() / "spec"
    if not spec.is_dir():
        print("This repository has no copy of the spec.")
        return

    manifest = spec / MANIFEST
    if not manifest.is_file():
        print(f"{sdk.RED}[ERROR][SPEC COPY]{sdk.RESET} {manifest} is missing: sync the spec from the identity service")
        sys.exit(1)

    expected = {}
    for line in sdk.read(manifest).splitlines():
        if line.strip():
            digest, name = line.split(None, 1)
            expected[name.strip()] = digest

    actual = {
        path.relative_to(spec).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(spec.rglob("*"))
        if path.is_file() and path.name != MANIFEST
    }

    failed = False
    for name in sorted(set(expected) | set(actual)):
        if name not in actual:
            problem = "is in the manifest but not in the copy"
        elif name not in expected:
            problem = "is not part of the synced spec"
        elif expected[name] != actual[name]:
            problem = "was changed after the sync"
        else:
            print(f"{sdk.GREEN}[OK]{sdk.RESET} spec/{name}")
            continue
        failed = True
        print(f"{sdk.RED}[ERROR][SPEC COPY]{sdk.RESET} spec/{name}")
        print(f"  {sdk.YELLOW}↳ {problem}: the spec is changed in the identity service and synced from there{sdk.RESET}")
    if failed:
        sys.exit(1)


if __name__ == "__main__":
    main()
