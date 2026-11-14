#!/usr/bin/env python3
"""Promote one exact image digest to immutable ECR tags, retry safely."""

from __future__ import annotations

import argparse
import re
import subprocess
import sys


DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
REPOSITORY = re.compile(r"^[0-9A-Za-z.-]+(?::[0-9]+)?/[a-z0-9]+(?:[._/-][a-z0-9]+)*$")
CANONICAL_TAG = re.compile(r"^[0-9a-f]{40}$")
QUARANTINE_TAG = re.compile(r"^quarantine-[0-9a-f]{40}$")


class PromotionError(ValueError):
    pass


def _run(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, capture_output=True, text=True, check=False)


def _tag_digest(repository_name: str, tag: str) -> str | None:
    result = _run(
        [
            "aws", "ecr", "describe-images", "--repository-name", repository_name,
            "--image-ids", f"imageTag={tag}", "--query", "imageDetails[0].imageDigest",
            "--output", "text",
        ]
    )
    if result.returncode == 0:
        digest = result.stdout.strip()
        if not DIGEST.fullmatch(digest):
            raise PromotionError(f"tag {tag} returned an invalid digest")
        return digest
    if "ImageNotFoundException" in result.stderr:
        return None
    raise PromotionError(f"cannot read tag {tag}: {result.stderr.strip()}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", required=True)
    parser.add_argument("--ecr-repository-name", required=True)
    parser.add_argument("--digest", required=True)
    parser.add_argument("--tag", action="append", default=[])
    parser.add_argument("--quarantine", action="store_true")
    args = parser.parse_args()

    try:
        if not REPOSITORY.fullmatch(args.repository):
            raise PromotionError("repository reference is invalid")
        if not DIGEST.fullmatch(args.digest):
            raise PromotionError("image digest is invalid")
        tags = list(dict.fromkeys(args.tag))
        expected_tag = QUARANTINE_TAG if args.quarantine else CANONICAL_TAG
        if len(tags) != 1 or any(not expected_tag.fullmatch(tag) for tag in tags):
            raise PromotionError(
                "exactly one source-scoped quarantine tag is required"
                if args.quarantine
                else "exactly one canonical full lowercase Git SHA tag is required"
            )

        mutability = _run(
            [
                "aws", "ecr", "describe-repositories", "--repository-names",
                args.ecr_repository_name, "--query",
                "repositories[0].imageTagMutability", "--output", "text",
            ]
        )
        if mutability.returncode != 0 or mutability.stdout.strip() != "IMMUTABLE":
            raise PromotionError("repository is not available with IMMUTABLE tag policy")

        for tag in tags:
            existing = _tag_digest(args.ecr_repository_name, tag)
            if existing == args.digest:
                continue
            if existing is not None:
                raise PromotionError(
                    f"immutable tag {tag} identifies {existing}, expected {args.digest}"
                )
            result = subprocess.run(
                [
                    "docker", "buildx", "imagetools", "create", "-t",
                    f"{args.repository}:{tag}", f"{args.repository}@{args.digest}",
                ],
                check=False,
            )
            # A concurrent identical publisher may win after our preflight.
            # Readback is authoritative: exact digest is success; anything
            # else (including an absent tag) fails closed.
            readback = _tag_digest(args.ecr_repository_name, tag)
            if readback != args.digest:
                detail = f"publisher exited {result.returncode}; " if result.returncode else ""
                raise PromotionError(
                    f"{detail}tag {tag} read back as {readback}, expected {args.digest}"
                )
    except PromotionError as exc:
        print(f"immutable image promotion refused: {exc}", file=sys.stderr)
        return 1

    print(f"immutable image promotion passed for {args.repository}@{args.digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
