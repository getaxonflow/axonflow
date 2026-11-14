#!/usr/bin/env python3
"""Emit the canonical release image matrix and reproducible source metadata."""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import pathlib
import re
import subprocess


SEMVER = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.]+)?$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")

IMAGES = (
    {
        "name": "agent",
        "context": ".",
        "dockerfile": "./platform/agent/Dockerfile",
        "go": True,
        "version_args": True,
        "edition_arg": True,
        "enterprise_only": False,
    },
    {
        "name": "orchestrator",
        "context": ".",
        "dockerfile": "./platform/orchestrator/Dockerfile",
        "go": True,
        "version_args": True,
        "edition_arg": True,
        "enterprise_only": False,
    },
    {
        "name": "customer-portal",
        "context": ".",
        "dockerfile": "./ee/platform/customer-portal/Dockerfile",
        "go": False,
        "version_args": False,
        "edition_arg": True,
        "enterprise_only": True,
    },
    {
        "name": "customer-portal-ui",
        "context": "./ee/platform/customer-portal-ui",
        "dockerfile": "./ee/platform/customer-portal-ui/Dockerfile",
        "go": False,
        "version_args": False,
        "edition_arg": False,
        "enterprise_only": True,
    },
    {
        "name": "prometheus",
        "context": "./platform/monitoring",
        "dockerfile": "./platform/monitoring/Dockerfile",
        "go": False,
        "version_args": False,
        "edition_arg": False,
        "enterprise_only": False,
    },
    {
        "name": "grafana",
        "context": "./grafana",
        "dockerfile": "./grafana/Dockerfile",
        "go": False,
        "version_args": False,
        "edition_arg": False,
        "enterprise_only": False,
    },
    {
        "name": "performance-testing",
        "context": ".",
        "dockerfile": "./ee/platform/performance-testing/Dockerfile",
        "go": False,
        "version_args": False,
        "edition_arg": False,
        "enterprise_only": True,
    },
    {
        "name": "gateway-adapters",
        "context": ".",
        "dockerfile": "./platform/gateway-adapters/cmd/axonflow-gateway-adapters/Dockerfile",
        "go": True,
        "version_args": True,
        "edition_arg": False,
        "enterprise_only": True,
    },
    {
        "name": "case-workflows",
        "context": "./ee/examples/payment-exception-shadow",
        "dockerfile": "./ee/examples/payment-exception-shadow/Dockerfile",
        "go": False,
        "version_args": True,
        "edition_arg": False,
        "enterprise_only": True,
    },
)


def _git(root: pathlib.Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(root), *args], text=True).strip()


def build_plan(root: pathlib.Path, edition: str, changed: set[str] | None) -> dict:
    commit = _git(root, "rev-parse", "HEAD")
    if not COMMIT.fullmatch(commit):
        raise ValueError("source commit is not a full lowercase Git SHA")
    if _git(root, "status", "--porcelain", "--untracked-files=normal"):
        raise ValueError("release source is dirty")
    source_epoch = int(_git(root, "show", "-s", "--format=%ct", "HEAD"))
    version = (root / "VERSION").read_text(encoding="utf-8").strip()
    if not SEMVER.fullmatch(version):
        raise ValueError("VERSION is not a supported semver")
    if edition not in {"enterprise", "community"}:
        raise ValueError("edition must be enterprise or community")
    known_images = {image["name"] for image in IMAGES}
    if changed is not None and not changed <= known_images:
        raise ValueError("changed image set contains an unknown release image")
    images = []
    for source in IMAGES:
        if source["enterprise_only"] and edition == "community":
            continue
        if changed is not None and source["name"] not in changed:
            continue
        images.append(
            {key: value for key, value in source.items() if key != "enterprise_only"}
        )
    return {
        "schema_version": "1.0",
        "source_commit": commit,
        "source_tree": _git(root, "rev-parse", "HEAD^{tree}"),
        "short_sha": commit[:7],
        "source_date_epoch": source_epoch,
        "build_date": datetime.datetime.fromtimestamp(
            source_epoch, datetime.timezone.utc
        ).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "platform_version": version,
        "edition": edition,
        "architectures": ["amd64", "arm64"],
        "images": images,
        "generator": {
            "path": ".github/scripts/release-build-plan.py",
            "sha256": hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest(),
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=pathlib.Path, default=pathlib.Path.cwd())
    parser.add_argument(
        "--edition", choices=("enterprise", "community"), default="enterprise"
    )
    parser.add_argument(
        "--changed", help="comma-separated image names; omit to build all"
    )
    parser.add_argument("--github-output", type=pathlib.Path)
    args = parser.parse_args()
    changed = (
        None
        if args.changed is None
        else {item for item in args.changed.split(",") if item}
    )
    try:
        plan = build_plan(args.root.resolve(), args.edition, changed)
    except (OSError, subprocess.CalledProcessError, ValueError) as exc:
        parser.error(str(exc))
    encoded = json.dumps(plan, sort_keys=True, separators=(",", ":"))
    if args.github_output:
        with args.github_output.open("a", encoding="utf-8") as output:
            for key in (
                "short_sha",
                "source_date_epoch",
                "build_date",
                "platform_version",
                "source_commit",
                "source_tree",
            ):
                output.write(f"{key}={plan[key]}\n")
            output.write(
                f"images={json.dumps(plan['images'], separators=(',', ':'))}\n"
            )
            output.write(f"has_images={'true' if plan['images'] else 'false'}\n")
    print(encoded)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
