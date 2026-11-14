#!/usr/bin/env python3
"""Validate a gh-attestation verification result for a client image digest."""

from __future__ import annotations

import argparse
import json
import pathlib
import re


DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")
REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
WORKFLOWS = {
    ".github/workflows/build-client-images.yml",
    ".github/workflows/build.yml",
}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--verification", required=True, type=pathlib.Path)
    parser.add_argument("--digest", required=True)
    parser.add_argument("--subject-name", required=True)
    parser.add_argument("--source-repository", required=True)
    parser.add_argument("--source-commit")
    parser.add_argument("--source-ref", required=True)
    parser.add_argument("--workflow", default=".github/workflows/build-client-images.yml")
    args = parser.parse_args()
    if not DIGEST.fullmatch(args.digest):
        parser.error("digest must be sha256")
    if args.source_commit is not None and not COMMIT.fullmatch(args.source_commit):
        parser.error("source commit must be a full lowercase Git SHA")
    if not REPOSITORY.fullmatch(args.source_repository):
        parser.error("source repository is invalid")
    if args.source_ref != "refs/heads/main":
        parser.error("source ref must be refs/heads/main")
    if args.workflow not in WORKFLOWS:
        parser.error("workflow is not an approved image builder")
    if not args.subject_name or any(char.isspace() for char in args.subject_name):
        parser.error("subject name is invalid")

    verification = json.loads(args.verification.read_text(encoding="utf-8"))
    expected_repository = f"https://github.com/{args.source_repository}"
    expected_subject = args.digest.removeprefix("sha256:")
    invocation = re.compile(
        rf"^https://github\.com/{re.escape(args.source_repository)}/actions/runs/[0-9]+/attempts/[0-9]+$"
    )
    admitted = False
    for item in verification if isinstance(verification, list) else []:
        result = item.get("verificationResult") if isinstance(item, dict) else None
        if not isinstance(result, dict) or not result.get("signature", {}).get("certificate"):
            continue
        if not result.get("verifiedTimestamps"):
            continue
        statement = result.get("statement") or {}
        if not any(
            isinstance(subject, dict)
            and subject.get("name") == args.subject_name
            and (subject.get("digest") or {}).get("sha256") == expected_subject
            for subject in statement.get("subject") or []
        ):
            continue
        predicate = statement.get("predicate") or {}
        build = predicate.get("buildDefinition") or {}
        workflow = (build.get("externalParameters") or {}).get("workflow") or {}
        source_ref = workflow.get("ref", "")
        if build.get("buildType") != "https://actions.github.io/buildtypes/workflow/v1":
            continue
        if workflow.get("repository") not in {args.source_repository, expected_repository}:
            continue
        if workflow.get("path") != args.workflow or source_ref != args.source_ref:
            continue
        run = predicate.get("runDetails") or {}
        builder = (run.get("builder") or {}).get("id")
        if builder != f"{expected_repository}/{args.workflow}@{source_ref}":
            continue
        if ((build.get("internalParameters") or {}).get("github") or {}).get("runner_environment") != "github-hosted":
            continue
        if not invocation.fullmatch(((run.get("metadata") or {}).get("invocationId") or "")):
            continue
        dependencies = build.get("resolvedDependencies") or []
        if not any(
            isinstance(dependency, dict)
            and COMMIT.fullmatch(str((dependency.get("digest") or {}).get("gitCommit") or ""))
            and (
                args.source_commit is None
                or (dependency.get("digest") or {}).get("gitCommit") == args.source_commit
            )
            for dependency in dependencies
        ):
            continue
        admitted = True
        break
    if not admitted:
        raise SystemExit("client image admission is missing the trusted signed workflow/run/source identity")
    print("client image admission passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
