#!/usr/bin/env python3
"""Reject example SDK pins that drift from the platform's release recommendation."""

from pathlib import Path
import re
import sys
import xml.etree.ElementTree as ET


ROOT = Path(__file__).resolve().parents[2]
SDK_MAP = ROOT / "platform/shared/sdkcompat/sdkcompat.go"
GO_MODULE = "github.com/getaxonflow/axonflow-sdk-go/v9"
NS = {"m": "http://maven.apache.org/POM/4.0.0"}


def recommended_versions():
    source = SDK_MAP.read_text()
    match = re.search(r"var recommendedVersion = map\[string\]string\{(.*?)\n\}", source, re.S)
    if not match:
        raise ValueError(f"cannot find recommendedVersion in {SDK_MAP}")
    return dict(re.findall(r'"([a-z]+)":\s*"([0-9.]+)"', match.group(1)))


def check_example(path, versions):
    content = path.read_text()
    if path.name == "go.mod":
        match = re.search(rf"(?m)^\s*(?:require\s+)?{re.escape(GO_MODULE)}\s+(v[0-9.]+)\b", content)
        if GO_MODULE in content and not match:
            return f"{path}: could not parse Go SDK requirement"
        if match and match.group(1) != "v" + versions["go"]:
            return f"{path}: Go SDK {match.group(1)}; expected v{versions['go']}"
        if match:
            sums_path = path.with_name("go.sum")
            if not sums_path.exists():
                return f"{path}: missing Go SDK checksums in {sums_path}"
            sums = sums_path.read_text()
            for suffix in ("", "/go.mod"):
                expected = f"{GO_MODULE} {match.group(1)}{suffix} h1:"
                if expected not in sums:
                    return f"{sums_path}: missing {expected}"
    elif path.name == "Cargo.toml":
        match = re.search(r'(?m)^\s*axonflow-sdk-rust\s*=\s*"([0-9.]+)"', content)
        if "axonflow-sdk-rust" in content and not match:
            return f"{path}: could not parse Rust SDK requirement"
        if match and match.group(1) != versions["rust"]:
            return f"{path}: Rust SDK {match.group(1)}; expected {versions['rust']}"
    elif path.name == "pom.xml":
        tree = ET.fromstring(content)
        props = tree.find("m:properties", NS)
        for dependency in tree.findall(".//m:dependency", NS):
            if (dependency.findtext("m:groupId", namespaces=NS) != "com.getaxonflow"
                    or dependency.findtext("m:artifactId", namespaces=NS) != "axonflow-sdk"):
                continue
            version = dependency.findtext("m:version", namespaces=NS)
            if version and version.startswith("${") and version.endswith("}") and props is not None:
                version = props.findtext(f"m:{version[2:-1]}", namespaces=NS)
            if version != versions["java"]:
                return f"{path}: Java SDK {version}; expected {versions['java']}"
    return None


def main():
    versions = recommended_versions()
    errors = []
    total = 0
    for base in (ROOT / "examples", ROOT / "ee/examples"):
        for name in ("go.mod", "Cargo.toml", "pom.xml"):
            for path in base.rglob(name):
                total += 1
                error = check_example(path, versions)
                if error:
                    errors.append(error)
    if not errors:
        readme = (ROOT / "examples/README.md").read_text()
        quickstart = (ROOT / "docs/sdk/rust-quickstart.md").read_text()
        checks = [
            ("examples/README.md Go", readme, f"| v{versions['go']} |"),
            ("examples/README.md Java", readme, f"| {versions['java']} |"),
            ("examples/README.md Rust", readme, f"| {versions['rust']} |"),
            ("Rust quickstart", quickstart, f'axonflow-sdk-rust = "{versions["rust"]}"'),
        ]
        smoke_path = ROOT / "scripts/tests/published-sdk-hosted-smoke.mjs"
        if smoke_path.exists():  # The Community mirror excludes scripts/tests/.
            checks.append(("published SDK smoke", smoke_path.read_text(),
                           f"sdkPackage.version !== '{versions['typescript']}'"))
        for label, content, expected in checks:
            if expected not in content:
                errors.append(f"{label}: expected {expected}")
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    print(f"PASS: {total} example manifests and available current client pins match SDK recommendations")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
