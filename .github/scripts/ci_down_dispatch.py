#!/usr/bin/env python3
"""Start and monitor the fixed schema-1.1 Step Functions build graph."""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import subprocess


SHA256 = re.compile(r"^[0-9a-f]{64}$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")


def aws(*args: str) -> dict:
    output = subprocess.check_output(["aws", *args, "--output", "json"], text=True)
    value = json.loads(output)
    if not isinstance(value, dict):
        raise RuntimeError("AWS response is not an object")
    return value


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--build-plan", required=True, type=pathlib.Path)
    parser.add_argument("--ledger", required=True, type=pathlib.Path)
    parser.add_argument("--state-machine-arn", required=True)
    args = parser.parse_args()
    plan = json.loads(args.build_plan.read_text(encoding="utf-8"))
    ledger = json.loads(args.ledger.read_text(encoding="utf-8"))
    source_commit = str(plan.get("source_commit", ""))
    source_tree = str(plan.get("source_tree", ""))
    cohort = str(ledger.get("build_cohort", ""))
    if not COMMIT.fullmatch(source_commit) or not COMMIT.fullmatch(source_tree):
        raise SystemExit("CI-down dispatch refused invalid source identity")
    if not SHA256.fullmatch(cohort):
        raise SystemExit("CI-down dispatch refused invalid cohort identity")
    images = plan.get("images")
    if not isinstance(images, list) or not images:
        raise SystemExit("CI-down dispatch refused an empty image plan")
    names = [item.get("name") for item in images if isinstance(item, dict)]
    if len(names) != len(images) or any(
        not isinstance(name, str) or not name for name in names
    ):
        raise SystemExit("CI-down dispatch refused an invalid image plan")
    state_input = json.dumps(
        {
            "build_cohort": cohort,
            "images": [{"name": name} for name in names],
            "source_commit": source_commit,
            "source_tree": source_tree,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    result = aws(
        "stepfunctions",
        "start-execution",
        "--state-machine-arn",
        args.state_machine_arn,
        "--name",
        f"ci-down-{cohort}",
        "--input",
        state_input,
    )
    execution = result.get("executionArn")
    if not isinstance(execution, str) or not execution:
        raise RuntimeError("Step Functions did not return an execution ARN")
    print(execution)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
