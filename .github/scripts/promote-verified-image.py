#!/usr/bin/env python3
"""Promote an admitted digest to immutable run-owned and shared commit tags."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pathlib
import re
import stat
import subprocess
import sys
import tempfile
import time
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


SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
REPOSITORY = re.compile(r"^[0-9A-Za-z.-]+(?::[0-9]+)?/[a-z0-9]+(?:[._/-][a-z0-9]+)*$")
TAG = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$")
SOURCE_REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
WORKFLOW = re.compile(r"^\.github/workflows/[A-Za-z0-9_.-]+\.ya?ml$")


class AdmissionError(ValueError):
    pass


def _load(path: pathlib.Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise AdmissionError(f"cannot read {path}: {exc}") from exc


def _statement_admits(
    verification,
    *,
    digest: str,
    source_repository: str,
    source_commit: str,
    workflow: str,
    source_ref: str,
    run_id: str,
    run_attempt: str,
) -> bool:
    if not isinstance(verification, list):
        return False
    expected_invocation = f"https://github.com/{source_repository}/actions/runs/{run_id}/attempts/{run_attempt}"
    expected_repository = f"https://github.com/{source_repository}"
    ref_names = {source_ref}
    for prefix in ("refs/heads/", "refs/tags/"):
        if source_ref.startswith(prefix):
            ref_names.add(source_ref.removeprefix(prefix))
    expected_builders = {
        f"{expected_repository}/{workflow}@{ref_name}" for ref_name in ref_names
    }
    expected_subject = digest.removeprefix("sha256:")
    for item in verification:
        result = item.get("verificationResult") if isinstance(item, dict) else None
        if not isinstance(result, dict):
            continue
        if not result.get("signature", {}).get("certificate"):
            continue
        if not result.get("verifiedTimestamps"):
            continue
        statement = result.get("statement") or {}
        subjects = statement.get("subject") or []
        if not any(
            isinstance(subject, dict)
            and (subject.get("digest") or {}).get("sha256") == expected_subject
            for subject in subjects
        ):
            continue
        predicate = statement.get("predicate") or {}
        build = predicate.get("buildDefinition") or {}
        if build.get("buildType") != "https://actions.github.io/buildtypes/workflow/v1":
            continue
        external = build.get("externalParameters") or {}
        workflow_identity = external.get("workflow") or {}
        if workflow_identity.get("repository") not in {
            source_repository,
            expected_repository,
        }:
            continue
        if workflow_identity.get("path") != workflow:
            continue
        if workflow_identity.get("ref") != source_ref:
            continue
        run = predicate.get("runDetails") or {}
        if run.get("builder", {}).get("id") not in expected_builders:
            continue
        internal = build.get("internalParameters") or {}
        if (internal.get("github") or {}).get("runner_environment") != "github-hosted":
            continue
        metadata = run.get("metadata") or {}
        if metadata.get("invocationId") != expected_invocation:
            continue
        source = predicate.get("buildDefinition", {}).get("resolvedDependencies") or []
        # gh verification already enforces --source-digest cryptographically.
        # Retain a signed predicate copy of it as a second, explicit admission.
        if not any(
            isinstance(dependency, dict)
            and (dependency.get("digest") or {}).get("gitCommit") == source_commit
            for dependency in source
        ):
            continue
        return True
    return False


def _tag_digest(repository_name: str, tag: str) -> str | None:
    result = subprocess.run(
        [
            "aws",
            "ecr",
            "describe-images",
            "--repository-name",
            repository_name,
            "--image-ids",
            f"imageTag={tag}",
            "--query",
            "imageDetails[0].imageDigest",
            "--output",
            "text",
        ],
        capture_output=True,
        text=True,
    )
    if result.returncode == 0:
        digest = result.stdout.strip()
        if not SHA256.fullmatch(digest):
            raise AdmissionError(f"tag {tag} returned an invalid digest")
        return digest
    if "ImageNotFoundException" in result.stderr:
        return None
    raise AdmissionError(f"cannot preflight tag {tag}: {result.stderr.strip()}")


def _delete_tag(repository_name: str, tag: str) -> None:
    subprocess.run(
        [
            "aws",
            "ecr",
            "batch-delete-image",
            "--repository-name",
            repository_name,
            "--image-ids",
            f"imageTag={tag}",
        ],
        check=True,
        capture_output=True,
        text=True,
    )


def _settled_tag_digest(
    repository_name: str,
    tag: str,
    expected_digest: str | None,
    *,
    attempts: int = 8,
) -> str | None:
    """Read through ECR propagation and transient read failures after a write."""
    last_digest: str | None = None
    last_error: AdmissionError | None = None
    for attempt in range(attempts):
        try:
            last_digest = _tag_digest(repository_name, tag)
            last_error = None
            if last_digest == expected_digest:
                return last_digest
        except AdmissionError as exc:
            last_error = exc
        if attempt + 1 < attempts:
            time.sleep(0.25)
    if last_error is not None:
        raise AdmissionError(
            f"cannot verify promoted tag {tag}: {last_error}"
        ) from last_error
    return last_digest


def _require_immutable_repository(repository_name: str) -> None:
    result = subprocess.run(
        [
            "aws",
            "ecr",
            "describe-repositories",
            "--repository-names",
            repository_name,
            "--query",
            "repositories[0].imageTagMutability",
            "--output",
            "text",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    mutability = result.stdout.strip()
    if result.returncode != 0 or mutability != "IMMUTABLE":
        raise AdmissionError(
            f"repository {repository_name} is {mutability or 'unavailable'}; immutable tags are required"
        )


def _consume_ci_down_claim_once(
    admission: ci_down_admission.VerifiedAdmission,
) -> None:
    """Atomically consume one signed image/cohort claim before registry mutation.

    S3's If-None-Match write is the authoritative compare-and-swap. A failed
    write is always a refusal, even if readback contains identical bytes: that
    is what makes retrying the same signed reservation unable to mutate the
    registry twice. Successful writes must return a version and are read back
    byte-for-byte before promotion can proceed.
    """

    claim_raw = admission.claim_bytes
    bucket, key = ci_down_admission._parse_s3_uri(
        admission.store_uri, "cohort claim"
    )
    with tempfile.NamedTemporaryFile(prefix="ci-down-consume-claim-") as claim_file:
        claim_file.write(claim_raw)
        claim_file.flush()
        put = subprocess.run(
            [
                "aws",
                "s3api",
                "put-object",
                "--bucket",
                bucket,
                "--key",
                key,
                "--body",
                claim_file.name,
                "--content-type",
                "application/json",
                "--if-none-match",
                "*",
                "--output",
                "json",
            ],
            check=False,
            capture_output=True,
            text=True,
        )
    if put.returncode != 0:
        raise AdmissionError(
            "cohort claim was already consumed or its atomic write failed"
        )
    try:
        result = json.loads(put.stdout)
    except json.JSONDecodeError as exc:
        raise AdmissionError("cohort consume write returned invalid metadata") from exc
    version_id, etag = result.get("VersionId"), result.get("ETag")
    if (
        not isinstance(version_id, str)
        or not version_id.strip()
        or version_id.strip().lower() in {"null", "none"}
        or not isinstance(etag, str)
        or not etag.strip()
        or etag.strip().lower() in {"null", "none"}
    ):
        raise AdmissionError("cohort consume write did not return versioned evidence")
    version_id = version_id.strip()
    etag = etag.strip()
    with tempfile.NamedTemporaryFile(prefix="ci-down-consumed-claim-") as readback:
        fetched = subprocess.run(
            [
                "aws",
                "s3api",
                "get-object",
                "--bucket",
                bucket,
                "--key",
                key,
                "--version-id",
                version_id,
                readback.name,
                "--output",
                "json",
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        try:
            fetched_metadata = json.loads(fetched.stdout)
        except json.JSONDecodeError as exc:
            raise AdmissionError("cohort consume readback metadata is invalid") from exc
        if (
            fetched.returncode != 0
            or fetched_metadata.get("VersionId") != version_id
            or fetched_metadata.get("ETag") != etag
            or pathlib.Path(readback.name).read_bytes() != claim_raw
        ):
            raise AdmissionError("cohort consume write did not read back exactly")


def main() -> int:
    if not sys.flags.isolated:
        print("promoter requires python3 -I", file=sys.stderr)
        return 1
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--trust-mode",
        choices=("github-actions-v1", "aws-kms-ci-down-v1"),
        required=True,
    )
    parser.add_argument("--repository", required=True)
    parser.add_argument("--ecr-repository-name", required=True)
    parser.add_argument("--digest", required=True)
    parser.add_argument("--receipt-manifest", type=pathlib.Path)
    parser.add_argument("--image-admission", type=pathlib.Path)
    parser.add_argument("--receipt-admission", type=pathlib.Path)
    parser.add_argument("--source-repository", required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--workflow", required=True)
    parser.add_argument("--source-ref", required=True)
    parser.add_argument("--run-id")
    parser.add_argument("--run-attempt")
    parser.add_argument("--verifier-path", type=pathlib.Path)
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
    parser.add_argument("--shared-immutable-tag", action="append", default=[])
    parser.add_argument("--immutable-tag", action="append", default=[])
    args = parser.parse_args()

    try:
        ci_down_consumption: ci_down_admission.VerifiedAdmission | None = None
        if not REPOSITORY.fullmatch(args.repository):
            raise AdmissionError("repository reference is invalid")
        if not SHA256.fullmatch(args.digest):
            raise AdmissionError("index digest is invalid")
        if not re.fullmatch(r"[0-9a-f]{40}", args.source_commit):
            raise AdmissionError("source commit must be a full lowercase Git SHA")
        if not SOURCE_REPOSITORY.fullmatch(args.source_repository):
            raise AdmissionError(
                "source repository must be an owner/repository identity"
            )
        if not WORKFLOW.fullmatch(args.workflow):
            raise AdmissionError("workflow must be an in-repository workflow path")
        if not args.source_ref.startswith(("refs/heads/", "refs/tags/")):
            raise AdmissionError("source ref must be a full branch or tag ref")
        # Shared tags (currently the short source SHA) may be targeted by
        # overlapping runs for the same commit. Owned tags include the
        # run/attempt identity and are safe for this invocation to clean up.
        # Both classes are immutable; the distinction is rollback ownership.
        shared_tags = args.shared_immutable_tag
        owned_tags = args.immutable_tag
        tags = shared_tags + owned_tags
        if (
            not tags
            or len(tags) != len(set(tags))
            or any(not TAG.fullmatch(tag) for tag in tags)
        ):
            raise AdmissionError("promotion tags are missing, duplicate, or invalid")
        if shared_tags != [args.source_commit[:7]]:
            raise AdmissionError(
                "shared immutable tag must be the seven-character source commit"
            )
        if not owned_tags:
            raise AdmissionError("at least one run-owned immutable tag is required")

        if args.trust_mode == "github-actions-v1":
            if (
                not args.run_id
                or not args.run_id.isdigit()
                or not args.run_attempt
                or not args.run_attempt.isdigit()
            ):
                raise AdmissionError(
                    "run id and attempt must be decimal GitHub identities"
                )
            if not all(
                (
                    args.receipt_manifest,
                    args.image_admission,
                    args.receipt_admission,
                    args.verifier_path,
                )
            ):
                raise AdmissionError("GitHub Actions admission files are required")
            receipt = _load(args.receipt_manifest)
            expected_receipt = {
                "image_repository": args.repository,
                "index_digest": args.digest,
                "source_repository": args.source_repository,
                "source_commit": args.source_commit,
                "workflow": args.workflow,
                "source_ref": args.source_ref,
                "run_id": args.run_id,
                "run_attempt": args.run_attempt,
            }
            if receipt.get("schema_version") != "1.0" or any(
                receipt.get(key) != value for key, value in expected_receipt.items()
            ):
                raise AdmissionError(
                    "receipt manifest identity does not match promotion request"
                )
            verifier = receipt.get("verifier") or {}
            if verifier.get("path") != args.verifier_path.name:
                raise AdmissionError(
                    "receipt verifier identity does not match promotion request"
                )
            if (
                verifier.get("sha256")
                != hashlib.sha256(args.verifier_path.read_bytes()).hexdigest()
            ):
                raise AdmissionError(
                    "receipt verifier digest does not match reviewed verifier"
                )
            evidence = receipt.get("evidence")
            if not isinstance(evidence, list) or not evidence:
                raise AdmissionError("receipt manifest has no retained evidence")
            receipt_root = args.receipt_manifest.parent.resolve()
            evidence_names = set()
            for item in evidence:
                if not isinstance(item, dict) or not re.fullmatch(
                    r"[0-9a-f]{64}", str(item.get("sha256", ""))
                ):
                    raise AdmissionError(
                        "receipt manifest contains invalid evidence metadata"
                    )
                name = str(item.get("name", ""))
                if not name or name in evidence_names:
                    raise AdmissionError(
                        "receipt manifest contains missing or duplicate evidence names"
                    )
                evidence_names.add(name)
                path = (receipt_root / name).resolve()
                if receipt_root not in path.parents:
                    raise AdmissionError(
                        "receipt evidence path escapes the receipt root"
                    )
                if (
                    not path.is_file()
                    or hashlib.sha256(path.read_bytes()).hexdigest() != item["sha256"]
                ):
                    raise AdmissionError(
                        f"receipt evidence digest mismatch for {item.get('name')}"
                    )
            common = {
                "digest": args.digest,
                "source_repository": args.source_repository,
                "source_commit": args.source_commit,
                "workflow": args.workflow,
                "source_ref": args.source_ref,
                "run_id": args.run_id,
                "run_attempt": args.run_attempt,
            }
            if not _statement_admits(_load(args.image_admission), **common):
                raise AdmissionError(
                    "image admission is missing a trusted signed workflow identity"
                )
            receipt_common = dict(common)
            receipt_common["digest"] = (
                f"sha256:{hashlib.sha256(args.receipt_manifest.read_bytes()).hexdigest()}"
            )
            if not _statement_admits(_load(args.receipt_admission), **receipt_common):
                raise AdmissionError(
                    "receipt admission is missing a trusted signed workflow identity"
                )
        else:
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
            )
            if not all(required):
                raise AdmissionError(
                    "AWS KMS CI-down admission arguments are incomplete"
                )
            trust_policy_path = (
                pathlib.Path(__file__).resolve().parent.parent
                / "release"
                / "ci-down-trust-policy.json"
            )
            try:
                index_bytes = subprocess.check_output(
                    [
                        "docker",
                        "buildx",
                        "imagetools",
                        "inspect",
                        f"{args.repository}@{args.digest}",
                        "--raw",
                    ],
                    stderr=subprocess.PIPE,
                )
                with tempfile.NamedTemporaryFile(
                    prefix="ci-down-index-", suffix=".json"
                ) as index_file:
                    index_file.write(index_bytes)
                    index_file.flush()
                    verified_admission = ci_down_admission.verify(
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
                            trust_policy=trust_policy_path,
                            source_repository=args.source_repository,
                            source_ref=args.source_ref,
                            source_commit=args.source_commit,
                            source_tree=args.source_tree,
                            image=args.image,
                            image_repository=args.repository,
                            index_digest=args.digest,
                            oci_index=pathlib.Path(index_file.name),
                            consumed_cohorts=args.consumed_cohorts,
                            consumed_cohorts_signature=args.consumed_cohorts_signature,
                            cohort_claim=args.cohort_claim,
                            cohort_claim_signature=args.cohort_claim_signature,
                            now=None,
                        )
                    )
            except ci_down_admission.AdmissionError as exc:
                raise AdmissionError(str(exc)) from exc
            except (OSError, subprocess.CalledProcessError) as exc:
                raise AdmissionError(
                    "cannot fetch exact OCI index for CI-down admission"
                ) from exc
            expected_owned_tag = (
                f"ci-down-{verified_admission.build_cohort[:16]}"
            )
            if owned_tags != [expected_owned_tag]:
                raise AdmissionError(
                    "CI-down run-owned tag must be the canonical build-cohort identity"
                )
            ci_down_consumption = verified_admission

        _require_immutable_repository(args.ecr_repository_name)
        prior = {tag: _tag_digest(args.ecr_repository_name, tag) for tag in tags}
        for tag in tags:
            if prior[tag] not in {None, args.digest}:
                raise AdmissionError(
                    f"immutable tag {tag} already identifies {prior[tag]}, refusing overwrite"
                )
        owned_tags_to_write = [tag for tag in owned_tags if prior[tag] != args.digest]
        shared_tag = shared_tags[0]

        # This is the final fallible release gate before any registry write.
        # Identical retries lose S3's If-None-Match CAS and fail closed.
        if ci_down_consumption is not None:
            _consume_ci_down_claim_once(ci_down_consumption)

        def publish_one(tag: str) -> None:
            command = [
                "docker",
                "buildx",
                "imagetools",
                "create",
                "-t",
                f"{args.repository}:{tag}",
                f"{args.repository}@{args.digest}",
            ]
            result = subprocess.run(command, check=False)
            readback = _settled_tag_digest(args.ecr_repository_name, tag, args.digest)
            if readback == args.digest:
                # The registry is the authority after an ambiguous client or
                # network failure. Treat an exact immutable readback as
                # success so a landed tag can never belong to a rejected run.
                return
            if result.returncode != 0:
                raise subprocess.CalledProcessError(result.returncode, command)
            raise AdmissionError(
                f"tag {tag} read back as {readback}, expected {args.digest}"
            )

        try:
            # Run-owned identities are published and read back first. They are
            # unique to this run/attempt and therefore safe to remove if the
            # final shared identity cannot be admitted.
            for tag in owned_tags_to_write:
                publish_one(tag)

            # The deployable shared short-SHA is the commit point. It is the
            # final registry mutation and there are no fallible gates after its
            # exact readback. A non-zero client result with exact readback is a
            # successful commit, not a rejected partial promotion.
            if prior[shared_tag] != args.digest:
                publish_one(shared_tag)
        except (AdmissionError, OSError, subprocess.CalledProcessError):
            for tag in reversed(owned_tags_to_write):
                # Run/attempt tags are exclusive to this invocation. If the
                # client returned an ambiguous result, exact registry readback
                # is sufficient proof that this invocation may clean it up.
                if (
                    prior[tag] is None
                    and _settled_tag_digest(args.ecr_repository_name, tag, args.digest)
                    == args.digest
                ):
                    _delete_tag(args.ecr_repository_name, tag)
            for tag in owned_tags_to_write:
                if (
                    _settled_tag_digest(args.ecr_repository_name, tag, prior[tag])
                    != prior[tag]
                ):
                    raise AdmissionError(f"rollback failed for tag {tag}")
            raise
    except (AdmissionError, OSError, subprocess.CalledProcessError) as exc:
        print(f"image promotion refused: {exc}", file=sys.stderr)
        return 1
    print(f"image promotion passed for {args.repository}@{args.digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
