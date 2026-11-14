#!/usr/bin/env python3
"""Write and verify the signed durable admission for a completed image promotion."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import re


DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")
IMAGE_REPOSITORY = re.compile(
    r"^[0-9A-Za-z.-]+(?::[0-9]+)?/[a-z0-9]+(?:[._/-][a-z0-9]+)*$"
)
SOURCE_REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
WORKFLOW = re.compile(r"^\.github/workflows/[A-Za-z0-9_.-]+\.ya?ml$")


def _completion(repository: str, digest: str) -> dict[str, str]:
    if not IMAGE_REPOSITORY.fullmatch(repository):
        raise ValueError("image repository is invalid")
    if not DIGEST.fullmatch(digest):
        raise ValueError("image digest is invalid")
    return {
        "image_digest": digest,
        "image_repository": repository,
        "promotion_status": "complete",
        "schema_version": "1.0",
    }


def _encode(value: dict[str, str]) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def _write(args: argparse.Namespace) -> int:
    encoded = _encode(_completion(args.repository, args.digest))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    temporary = args.output.with_name(f".{args.output.name}.{os.getpid()}.tmp")
    try:
        temporary.write_bytes(encoded)
        os.replace(temporary, args.output)
    finally:
        temporary.unlink(missing_ok=True)
    print(f"promotion completion written for {args.repository}@{args.digest}")
    return 0


def _verify(args: argparse.Namespace) -> int:
    try:
        manifest_bytes = args.manifest.read_bytes()
        verification_bytes = args.verification.read_bytes()
    except OSError as exc:
        raise ValueError(f"cannot read completed promotion admission: {exc}") from exc
    result = verify_bytes(args, manifest_bytes, verification_bytes)
    print(f"completed promotion admission passed for {args.repository}@{args.digest}")
    return result


def verify_bytes(
    args: argparse.Namespace, manifest_bytes: bytes, verification_bytes: bytes
) -> int:
    """Verify one immutable caller-owned snapshot of both evidence files."""

    if not SOURCE_REPOSITORY.fullmatch(args.source_repository):
        raise ValueError("source repository is invalid")
    if not WORKFLOW.fullmatch(args.workflow):
        raise ValueError("workflow is invalid")
    if args.source_ref != "refs/heads/main":
        raise ValueError("source ref must be refs/heads/main")
    if args.source_commit is not None and not COMMIT.fullmatch(args.source_commit):
        raise ValueError("source commit must be a full lowercase Git SHA")

    expected = _completion(args.repository, args.digest)
    try:
        manifest = json.loads(manifest_bytes)
        verification = json.loads(verification_bytes)
    except json.JSONDecodeError as exc:
        raise ValueError(f"cannot read completed promotion admission: {exc}") from exc
    if manifest != expected or manifest_bytes != _encode(expected):
        raise ValueError("promotion completion manifest is not canonical or does not match")

    expected_subject = hashlib.sha256(manifest_bytes).hexdigest()
    expected_repository = f"https://github.com/{args.source_repository}"
    expected_builders = {f"{expected_repository}/{args.workflow}@{args.source_ref}"}
    if args.source_ref.startswith("refs/heads/"):
        expected_builders.add(
            f"{expected_repository}/{args.workflow}@{args.source_ref.removeprefix('refs/heads/')}"
        )
    invocation = re.compile(
        rf"^https://github\.com/{re.escape(args.source_repository)}/actions/runs/[0-9]+/attempts/[0-9]+$"
    )
    for item in verification if isinstance(verification, list) else []:
        result = item.get("verificationResult") if isinstance(item, dict) else None
        if not isinstance(result, dict):
            continue
        if not result.get("signature", {}).get("certificate"):
            continue
        if not result.get("verifiedTimestamps"):
            continue
        statement = result.get("statement") or {}
        if not any(
            isinstance(subject, dict)
            and (subject.get("digest") or {}).get("sha256") == expected_subject
            for subject in statement.get("subject") or []
        ):
            continue
        predicate = statement.get("predicate") or {}
        build = predicate.get("buildDefinition") or {}
        if build.get("buildType") != "https://actions.github.io/buildtypes/workflow/v1":
            continue
        workflow = (build.get("externalParameters") or {}).get("workflow") or {}
        if workflow.get("repository") not in {
            args.source_repository,
            expected_repository,
        }:
            continue
        if workflow.get("path") != args.workflow or workflow.get("ref") != args.source_ref:
            continue
        if (
            ((build.get("internalParameters") or {}).get("github") or {}).get(
                "runner_environment"
            )
            != "github-hosted"
        ):
            continue
        dependencies = build.get("resolvedDependencies") or []
        commits = {
            str((dependency.get("digest") or {}).get("gitCommit") or "")
            for dependency in dependencies
            if isinstance(dependency, dict)
            and COMMIT.fullmatch(
                str((dependency.get("digest") or {}).get("gitCommit") or "")
            )
        }
        if not commits or (
            args.source_commit is not None and args.source_commit not in commits
        ):
            continue
        run = predicate.get("runDetails") or {}
        if (run.get("builder") or {}).get("id") not in expected_builders:
            continue
        if not invocation.fullmatch(((run.get("metadata") or {}).get("invocationId") or "")):
            continue
        return 0
    raise ValueError("completed promotion admission is missing the trusted workflow/source identity")


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    writer = subparsers.add_parser("write")
    writer.add_argument("--output", required=True, type=pathlib.Path)
    writer.add_argument("--repository", required=True)
    writer.add_argument("--digest", required=True)
    writer.set_defaults(handler=_write)

    verifier = subparsers.add_parser("verify")
    verifier.add_argument("--manifest", required=True, type=pathlib.Path)
    verifier.add_argument("--verification", required=True, type=pathlib.Path)
    verifier.add_argument("--repository", required=True)
    verifier.add_argument("--digest", required=True)
    verifier.add_argument("--source-repository", required=True)
    verifier.add_argument("--source-ref", required=True)
    verifier.add_argument("--source-commit")
    verifier.add_argument("--workflow", default=".github/workflows/build.yml")
    verifier.set_defaults(handler=_verify)
    return parser


def main() -> int:
    parser = build_argument_parser()

    args = parser.parse_args()
    try:
        return args.handler(args)
    except ValueError as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    raise SystemExit(main())
