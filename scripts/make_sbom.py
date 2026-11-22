"""CycloneDX 1.5 SBOM of the runtime dependencies a jt-oz-bridge wheel installs.

The component list is `uv export` of `uv.lock` without development tools. Each
component must be installed at that exact version in the interpreter running this
script, which in the full gate is the environment the whole suite was tested in;
its license comes from that installed metadata. The wheel's own hash is recorded.

  python -m scripts.make_sbom --uv uv --wheel dist/<wheel> --output <file>.sbom.cdx.json
"""

import argparse
import email.parser
import hashlib
import importlib.metadata
import json
import re
import subprocess
import sys
import tomllib
import zipfile
from pathlib import Path
from typing import Any

# Only classifiers that name one SPDX license; others stay a plain name.
CLASSIFIERS = {
    "MIT License": "MIT",
    "Mozilla Public License 2.0 (MPL 2.0)": "MPL-2.0",
    "ISC License (ISCL)": "ISC",
}
SPDX_ID = re.compile(r"[A-Za-z0-9.+-]{1,64}")


def normalized(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def license_of(metadata: importlib.metadata.PackageMetadata) -> list[dict[str, object]]:
    expression = metadata.get("License-Expression")
    if expression:
        return [{"expression": expression.strip()}]
    field = (metadata.get("License") or "").strip()
    if SPDX_ID.fullmatch(field):
        return [{"license": {"id": field}}]
    for classifier in metadata.get_all("Classifier") or []:
        if classifier.startswith("License ::"):
            name = classifier.split("::")[-1].strip()
            if name in CLASSIFIERS:
                return [{"license": {"id": CLASSIFIERS[name]}}]
            if name != "OSI Approved":
                return [{"license": {"name": name}}]
    return [{"license": {"name": "NOASSERTION"}}]


def build(root: Path, uv: str, wheel: Path) -> tuple[dict[str, Any], list[str]]:
    """The SBOM, and every way it differs from the tested environment or the wheel."""
    exported = subprocess.run(
        [
            uv,
            "export",
            "--format",
            "cyclonedx1.5",
            "--frozen",
            "--offline",
            "--no-dev",
            "--no-emit-project",
            "--quiet",
        ],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    bom = json.loads(exported)
    problems = []
    version = tomllib.loads((root / "pyproject.toml").read_text())["project"]["version"]
    installed = {
        normalized(distribution.metadata["Name"]): distribution
        for distribution in importlib.metadata.distributions()
    }
    for component in bom["components"]:
        distribution = installed.get(normalized(component["name"]))
        if distribution is None or distribution.version != component["version"]:
            problems.append(
                f"{component['name']} {component['version']} is not the tested version "
                f"({distribution.version if distribution else 'not installed'})"
            )
            continue
        component["licenses"] = license_of(distribution.metadata)
    with wheel.open("rb") as handle:
        digest = hashlib.file_digest(handle, "sha256").hexdigest()
    project = bom["metadata"]["component"]
    if project.get("name") != "jt-oz-bridge" or project.get("version") != version:
        problems.append(f"project component is {project.get('name')} {project.get('version')}")
    project["type"] = "application"
    project["licenses"] = [{"license": {"id": "GPL-3.0-only"}}]
    project["hashes"] = [{"alg": "SHA-256", "content": digest}]
    project["properties"] = [
        *project.get("properties", []),
        {"name": "jt-oz-bridge:wheel", "value": wheel.name},
    ]
    # Every runtime requirement the wheel itself declares is in the SBOM.
    with zipfile.ZipFile(wheel) as archive:
        metadata = archive.read(f"jt_oz_bridge-{version}.dist-info/METADATA").decode()
    head = email.parser.HeaderParser().parsestr(metadata.split("\n\n", 1)[0])
    names = {normalized(component["name"]) for component in bom["components"]}
    for requirement in head.get_all("Requires-Dist") or []:
        if "extra ==" in requirement:
            continue
        name = normalized(re.split(r"[\s\[<>=!~;(]", requirement, maxsplit=1)[0])
        if name not in names:
            problems.append(f"wheel requirement {name} is missing")
    return bom, problems


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--uv", required=True)
    parser.add_argument("--wheel", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    bom, problems = build(root, args.uv, args.wheel)
    for problem in problems:
        print("FAIL:", problem)
    if problems:
        return 1
    args.output.write_text(json.dumps(bom, ensure_ascii=False, indent=1) + "\n")
    print(f"SBOM: {len(bom['components'])} runtime components, {args.output.name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
