"""Every runtime dependency of the SDK is a reviewed decision.

Whatever the SDK depends on ends up inside every app that uses it: more code
to trust, more to keep patched. The dependencies the library ships with are
listed, each with its reason, in infra/pipeline/allowed-dependencies.txt.
This check fails when the manifest and that list disagree, so a new
dependency (or a removed one) is always visible in the review.
"""

import json
import re
import sys
from pathlib import Path

# The checks leave nothing behind in the repository they inspect.
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).parent / "lib"))
import sdk  # noqa: E402

ALLOWLIST = Path("infra/pipeline/allowed-dependencies.txt")


def from_package_json(path: Path) -> set[str]:
    manifest = json.loads(sdk.read(path))
    names: set[str] = set()
    for section in ("dependencies", "peerDependencies", "optionalDependencies"):
        names.update(manifest.get(section, {}))
    return names


def from_go_mod(path: Path) -> set[str]:
    names = set()
    for line in sdk.read(path).splitlines():
        match = re.match(r"^\s*(?:require\s+)?([\w./-]+\.[\w./-]+)\s+v\S+", line)
        if match and "// indirect" not in line:
            names.add(match.group(1))
    return names


def from_pyproject(path: Path) -> set[str]:
    import tomllib

    project = tomllib.loads(sdk.read(path)).get("project", {})
    requirements = list(project.get("dependencies", []))
    for extra in project.get("optional-dependencies", {}).values():
        requirements.extend(extra)
    return {re.split(r"[\s<>=!~;\[]", requirement, maxsplit=1)[0].lower() for requirement in requirements}


def from_composer(path: Path) -> set[str]:
    return {name for name in json.loads(sdk.read(path)).get("require", {}) if name != "php"}


def from_gemspec(path: Path) -> set[str]:
    return set(re.findall(r"add_(?:runtime_)?dependency\s*\(?\s*[\"']([^\"']+)[\"']", sdk.read(path)))


def from_pom(path: Path) -> set[str]:
    names = set()
    text = re.sub(r"<dependencyManagement>.*?</dependencyManagement>", "", sdk.read(path), flags=re.S)
    text = re.sub(r"<build>.*?</build>", "", text, flags=re.S)
    for block in re.findall(r"<dependency>(.*?)</dependency>", text, flags=re.S):
        scope = re.search(r"<scope>(.*?)</scope>", block)
        if scope and scope.group(1).strip() == "test":
            continue
        group = re.search(r"<groupId>(.*?)</groupId>", block)
        artifact = re.search(r"<artifactId>(.*?)</artifactId>", block)
        if group and artifact:
            names.add(f"{group.group(1).strip()}:{artifact.group(1).strip()}")
    return names


def from_pubspec(path: Path) -> set[str]:
    names = set()
    inside = False
    for line in sdk.read(path).splitlines():
        if re.match(r"^\S", line):
            inside = line.startswith("dependencies:")
            continue
        match = re.match(r"^  ([A-Za-z0-9_]+):", line)
        if inside and match:
            names.add(match.group(1))
    return names


def from_gradle(path: Path) -> set[str]:
    return {
        match.group(1).strip()
        for match in re.finditer(r"^\s*(?:api|implementation|compileOnly|runtimeOnly)\s*\(([^)\n]+)\)", sdk.read(path), flags=re.M)
    }


def from_swift_package(path: Path) -> set[str]:
    return set(re.findall(r"\.package\s*\(\s*url:\s*\"([^\"]+)\"", sdk.read(path)))


PARSERS = {
    "package.json": from_package_json,
    "go.mod": from_go_mod,
    "pyproject.toml": from_pyproject,
    "composer.json": from_composer,
    "pom.xml": from_pom,
    "pubspec.yaml": from_pubspec,
    "Package.swift": from_swift_package,
}


def declared() -> dict[str, Path]:
    """Every runtime dependency of the library and the manifest that declares it."""
    found: dict[str, Path] = {}
    base = sdk.root()
    manifests = [(base / name, parser) for name, parser in PARSERS.items()]
    manifests += [(path, from_gemspec) for path in sorted(base.glob("*.gemspec"))]
    manifests += [
        (path, from_gradle)
        for path in sorted(base.rglob("build.gradle.kts"))
        if sdk.in_scope(path.relative_to(base)) and path.parent != base
    ]
    for path, parser in manifests:
        if path.is_file():
            for name in parser(path):
                found[name] = path
    return found


def allowlist() -> set[str]:
    path = sdk.root() / ALLOWLIST
    if not path.is_file():
        return set()
    return {line.split("#", 1)[0].strip() for line in sdk.read(path).splitlines() if line.split("#", 1)[0].strip()}


def main() -> None:
    found = declared()
    allowed = allowlist()
    failed = False

    for name in sorted(found):
        if name in allowed:
            print(f"{sdk.GREEN}[OK]{sdk.RESET} {name} ({found[name]})")
        else:
            failed = True
            print(f"{sdk.RED}[ERROR][DEPENDENCY]{sdk.RESET} {name} ({found[name]})")
            print(f"  {sdk.YELLOW}↳ not in {ALLOWLIST}: add it there with the reason it is needed{sdk.RESET}")
    for name in sorted(allowed - set(found)):
        failed = True
        print(f"{sdk.RED}[ERROR][DEPENDENCY]{sdk.RESET} {name}")
        print(f"  {sdk.YELLOW}↳ listed in {ALLOWLIST} but no longer a dependency: remove it{sdk.RESET}")
    if not found and not allowed:
        print("The library has no runtime dependencies.")
    if failed:
        sys.exit(1)


if __name__ == "__main__":
    main()
