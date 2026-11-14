#!/usr/bin/env python3
"""Resolve one immutable image only after both trusted admissions pass."""

from __future__ import annotations

import argparse
import os
import pathlib
import re
import stat
import subprocess
import sys
import tempfile
import types


def _load_ci_down_admission() -> types.ModuleType:
    path = pathlib.Path(__file__).resolve().with_name("ci_down_admission.py")
    flags = os.O_RDONLY | (os.O_NOFOLLOW if hasattr(os, "O_NOFOLLOW") else 0)
    descriptor = os.open(path, flags)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise RuntimeError("CI-down verifier is not a regular file")
        chunks: list[bytes] = []
        while chunk := os.read(descriptor, 1024 * 1024):
            chunks.append(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    ) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    ):
        raise RuntimeError("CI-down verifier changed while it was loaded")
    module = types.ModuleType("ci_down_admission")
    module.__file__ = str(path)
    sys.modules[module.__name__] = module
    exec(compile(b"".join(chunks), str(path), "exec"), module.__dict__)
    return module


ci_down_admission = _load_ci_down_admission()


DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")
TAG = re.compile(r"^[0-9a-f]{7,40}$")
REGISTRY = re.compile(r"^[0-9A-Za-z.-]+(?::[0-9]+)?$")
REPOSITORY = re.compile(r"^[a-z0-9]+(?:[._/-][a-z0-9]+)*$")
SOURCE_REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


def _run(command: list[str], *, stdout: pathlib.Path | None = None) -> str:
    try:
        if stdout is None:
            return subprocess.check_output(
                command, text=True, stderr=subprocess.PIPE
            ).strip()
        with stdout.open("w", encoding="utf-8") as output:
            subprocess.run(
                command, check=True, text=True, stdout=output, stderr=subprocess.PIPE
            )
        return ""
    except subprocess.CalledProcessError as exc:
        detail = (exc.stderr or "").strip()
        raise ValueError(
            f"command failed: {command[0]}: {detail or exc.returncode}"
        ) from exc


def _validate(args: argparse.Namespace) -> None:
    if not REGISTRY.fullmatch(args.registry) or not REGISTRY.fullmatch(
        args.admission_registry
    ):
        raise ValueError("registry is invalid")
    if not REPOSITORY.fullmatch(args.repository):
        raise ValueError("image repository is invalid")
    if not SOURCE_REPOSITORY.fullmatch(args.source_repository):
        raise ValueError("source repository is invalid")
    if args.source_ref != "refs/heads/main":
        raise ValueError("source ref must be refs/heads/main")
    if not COMMIT.fullmatch(args.source_commit):
        raise ValueError("source commit must be a full lowercase Git SHA")
    if not (TAG.fullmatch(args.selector) or DIGEST.fullmatch(args.selector)):
        raise ValueError("selector must be an immutable Git SHA tag or sha256 digest")
    if TAG.fullmatch(args.selector) and not args.source_commit.startswith(
        args.selector
    ):
        raise ValueError("selector does not identify the exact source commit")


def _resolve(args: argparse.Namespace) -> str:
    mutability = _run(
        [
            "aws",
            "ecr",
            "describe-repositories",
            "--repository-names",
            args.repository,
            "--region",
            args.region,
            "--query",
            "repositories[0].imageTagMutability",
            "--output",
            "text",
        ]
    )
    if mutability != "IMMUTABLE":
        raise ValueError("image repository is not immutable")

    image_id = (
        f"imageDigest={args.selector}"
        if DIGEST.fullmatch(args.selector)
        else f"imageTag={args.selector}"
    )
    digest = _run(
        [
            "aws",
            "ecr",
            "describe-images",
            "--repository-name",
            args.repository,
            "--region",
            args.region,
            "--image-ids",
            image_id,
            "--query",
            "imageDetails[0].imageDigest",
            "--output",
            "text",
        ]
    )
    if not DIGEST.fullmatch(digest):
        raise ValueError("selector did not resolve to one immutable image digest")
    if DIGEST.fullmatch(args.selector) and digest != args.selector:
        raise ValueError("resolved image digest does not match selector")
    return digest


def _admit(args: argparse.Namespace, digest: str) -> None:
    args.evidence_dir.mkdir(parents=True, exist_ok=True)
    if args.trust_mode == "aws-kms-ci-down-v1":
        required = (
            args.source_tree,
            args.image,
            args.build_plan,
            args.canonical_job_ledger,
            args.canonical_job_ledger_signature,
            args.index_seal,
            args.index_seal_signature,
            args.amd64_build_receipt,
            args.amd64_build_signature,
            args.arm64_build_receipt,
            args.arm64_build_signature,
            args.consumed_cohorts,
            args.consumed_cohorts_signature,
            args.cohort_claim,
            args.cohort_claim_signature,
            args.expected_oci_index,
        )
        if not all(required):
            raise ValueError("AWS KMS CI-down admission arguments are incomplete")
        try:
            subject = f"{args.admission_registry}/{args.repository}"
            index_bytes = subprocess.check_output(
                [
                    "docker",
                    "buildx",
                    "imagetools",
                    "inspect",
                    f"{subject}@{digest}",
                    "--raw",
                ],
                stderr=subprocess.PIPE,
            )
            with tempfile.NamedTemporaryFile(
                prefix="ci-down-index-", suffix=".json"
            ) as index_file:
                index_file.write(index_bytes)
                index_file.flush()
                if args.expected_oci_index.read_bytes() != index_bytes:
                    raise ValueError(
                        "retained OCI index evidence differs from registry bytes"
                    )
                ci_down_admission.verify(
                    argparse.Namespace(
                        build_plan=args.build_plan,
                        ledger=args.canonical_job_ledger,
                        ledger_signature=args.canonical_job_ledger_signature,
                        index_seal=args.index_seal,
                        index_seal_signature=args.index_seal_signature,
                        amd64_receipt=args.amd64_build_receipt,
                        amd64_signature=args.amd64_build_signature,
                        arm64_receipt=args.arm64_build_receipt,
                        arm64_signature=args.arm64_build_signature,
                        trust_policy=pathlib.Path(__file__).resolve().parent.parent
                        / "release"
                        / "ci-down-trust-policy.json",
                        source_repository=args.source_repository,
                        source_ref=args.source_ref,
                        source_commit=args.source_commit,
                        source_tree=args.source_tree,
                        image=args.image,
                        image_repository=subject,
                        index_digest=digest,
                        oci_index=pathlib.Path(index_file.name),
                        consumed_cohorts=args.consumed_cohorts,
                        consumed_cohorts_signature=args.consumed_cohorts_signature,
                        cohort_claim=args.cohort_claim,
                        cohort_claim_signature=args.cohort_claim_signature,
                        now=None,
                    )
                )
        except ci_down_admission.AdmissionError as exc:
            raise ValueError(str(exc)) from exc
        except (OSError, subprocess.CalledProcessError) as exc:
            raise ValueError(
                "cannot fetch exact OCI index for CI-down admission"
            ) from exc
        return
    script_dir = pathlib.Path(__file__).resolve().parent
    subject = f"{args.admission_registry}/{args.repository}"
    image_admission = (
        args.evidence_dir / f"{args.repository.replace('/', '-')}-image-admission.json"
    )
    completion = (
        args.evidence_dir
        / f"{args.repository.replace('/', '-')}-promotion-completion.json"
    )
    completion_admission = (
        args.evidence_dir
        / f"{args.repository.replace('/', '-')}-promotion-admission.json"
    )
    common = [
        "--repo",
        args.source_repository,
        "--signer-workflow",
        f"{args.source_repository}/.github/workflows/build.yml",
        "--signer-digest",
        args.source_commit,
        "--source-digest",
        args.source_commit,
        "--source-ref",
        args.source_ref,
        "--deny-self-hosted-runners",
        "--format",
        "json",
    ]
    _run(
        ["gh", "attestation", "verify", f"oci://{subject}@{digest}", *common],
        stdout=image_admission,
    )
    _run(
        [
            sys.executable,
            str(script_dir / "validate-client-image-admission.py"),
            "--verification",
            str(image_admission),
            "--digest",
            digest,
            "--subject-name",
            subject,
            "--source-repository",
            args.source_repository,
            "--source-commit",
            args.source_commit,
            "--source-ref",
            args.source_ref,
            "--workflow",
            ".github/workflows/build.yml",
        ]
    )
    _run(
        [
            sys.executable,
            str(script_dir / "promotion-completion.py"),
            "write",
            "--output",
            str(completion),
            "--repository",
            subject,
            "--digest",
            digest,
        ]
    )
    _run(
        ["gh", "attestation", "verify", str(completion), *common],
        stdout=completion_admission,
    )
    _run(
        [
            sys.executable,
            str(script_dir / "promotion-completion.py"),
            "verify",
            "--manifest",
            str(completion),
            "--verification",
            str(completion_admission),
            "--repository",
            subject,
            "--digest",
            digest,
            "--source-repository",
            args.source_repository,
            "--source-ref",
            args.source_ref,
            "--source-commit",
            args.source_commit,
        ]
    )


def main() -> int:
    if not sys.flags.isolated:
        print("resolver requires python3 -I", file=sys.stderr)
        return 1
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--trust-mode",
        choices=("github-actions-v1", "aws-kms-ci-down-v1"),
        required=True,
    )
    parser.add_argument("--registry", required=True)
    parser.add_argument("--admission-registry", required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--region", required=True)
    parser.add_argument("--selector", required=True)
    parser.add_argument("--source-repository", required=True)
    parser.add_argument("--source-ref", default="refs/heads/main")
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--evidence-dir", required=True, type=pathlib.Path)
    parser.add_argument("--source-tree")
    parser.add_argument("--image")
    parser.add_argument("--build-plan", type=pathlib.Path)
    parser.add_argument("--canonical-job-ledger", type=pathlib.Path)
    parser.add_argument("--canonical-job-ledger-signature", type=pathlib.Path)
    parser.add_argument("--index-seal", type=pathlib.Path)
    parser.add_argument("--index-seal-signature", type=pathlib.Path)
    parser.add_argument("--amd64-build-receipt", type=pathlib.Path)
    parser.add_argument("--amd64-build-signature", type=pathlib.Path)
    parser.add_argument("--arm64-build-receipt", type=pathlib.Path)
    parser.add_argument("--arm64-build-signature", type=pathlib.Path)
    parser.add_argument("--consumed-cohorts", type=pathlib.Path)
    parser.add_argument("--consumed-cohorts-signature", type=pathlib.Path)
    parser.add_argument("--cohort-claim", type=pathlib.Path)
    parser.add_argument("--cohort-claim-signature", type=pathlib.Path)
    parser.add_argument("--expected-oci-index", type=pathlib.Path)
    args = parser.parse_args()
    try:
        _validate(args)
        digest = _resolve(args)
        _admit(args, digest)
    except ValueError as exc:
        parser.error(str(exc))
    print(
        f"trusted image admission passed for {args.registry}/{args.repository}:"
        f"{args.selector}@{digest}",
        file=sys.stderr,
    )
    print(digest)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
