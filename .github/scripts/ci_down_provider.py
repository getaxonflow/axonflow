#!/usr/bin/env python3
"""Produce canonical schema-1.1 evidence for the reviewed CodeBuild provider.

This is a producer, not an admission bypass. The resulting bundle must still
pass ci_down_admission.py using the repository-pinned public keys and project
identities before any immutable tag is written.
"""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import json
import pathlib
import re
import secrets
import subprocess
import tempfile
import urllib.parse

import ci_down_admission as admission


SHA256 = re.compile(r"^[0-9a-f]{64}$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


def canonical(value: object) -> bytes:
    return admission.canonical(value)


def now() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def write(path: pathlib.Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical(value))


def load(path: pathlib.Path) -> tuple[dict, bytes]:
    raw = path.read_bytes()
    value = json.loads(raw)
    if not isinstance(value, dict) or raw != canonical(value):
        raise ValueError(f"{path} is not a canonical JSON object")
    return value, raw


def require_sha(value: str, label: str) -> str:
    if not SHA256.fullmatch(value):
        raise ValueError(f"{label} is not a SHA-256")
    return value


def require_digest(value: str, label: str) -> str:
    if not DIGEST.fullmatch(value):
        raise ValueError(f"{label} is not an OCI digest")
    return value


def command_ledger(args: argparse.Namespace) -> None:
    plan, raw = load(args.build_plan)
    plan_sha = hashlib.sha256(raw).hexdigest()
    source_commit = str(plan.get("source_commit", ""))
    source_tree = str(plan.get("source_tree", ""))
    admission_nonce = secrets.token_hex(32)
    cohort = hashlib.sha256(
        canonical(
            {
                "admission_nonce": admission_nonce,
                "build_plan_sha256": plan_sha,
                "source_commit": source_commit,
                "source_tree": source_tree,
            }
        )
    ).hexdigest()
    created = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    ledger = {
        "admission_nonce": admission_nonce,
        "build_cohort": cohort,
        "build_plan_sha256": plan_sha,
        "coordinator": {
            "id": args.coordinator_builder_id,
            "provider": "aws-codebuild",
        },
        "created_at": created.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "dirty_source": False,
        "expires_at": (created + dt.timedelta(hours=23)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        ),
        "jobs": admission._expected_jobs(
            plan,
            {"amd64": args.amd64_builder_id, "arm64": args.arm64_builder_id},
            args.promoter_builder_id,
        ),
        "schema_version": admission.SCHEMA_VERSION,
        "source_commit": source_commit,
        "source_ref": "refs/heads/main",
        "source_repository": args.source_repository,
        "source_tree": source_tree,
        "trust_mode": admission.TRUST_MODE,
    }
    write(args.out, ledger)


def _kms_public_key(key_arn: str) -> tuple[bytes, str]:
    output = subprocess.check_output(
        [
            "aws",
            "kms",
            "get-public-key",
            "--key-id",
            key_arn,
            "--query",
            "PublicKey",
            "--output",
            "text",
        ],
        text=True,
    ).strip()
    der = base64.b64decode(output, validate=True)
    return der, hashlib.sha256(der).hexdigest()


def _sign_payload(payload: bytes, key_arn: str) -> tuple[dict, bytes]:
    payload_sha = hashlib.sha256(payload).hexdigest()
    der, fingerprint = _kms_public_key(key_arn)
    with tempfile.TemporaryDirectory(prefix="ci-down-kms-sign-") as temporary:
        digest = pathlib.Path(temporary) / "digest.bin"
        digest.write_bytes(hashlib.sha256(payload).digest())
        signature = subprocess.check_output(
            [
                "aws",
                "kms",
                "sign",
                "--key-id",
                key_arn,
                "--message",
                f"fileb://{digest}",
                "--message-type",
                "DIGEST",
                "--signing-algorithm",
                "ECDSA_SHA_256",
                "--query",
                "Signature",
                "--output",
                "text",
            ],
            text=True,
        ).strip()
    return (
        {
            "kms_key_arn": key_arn,
            "kms_public_key_sha256": fingerprint,
            "payload_sha256": payload_sha,
            "schema_version": admission.SCHEMA_VERSION,
            "signature_base64": signature,
            "signing_algorithm": "ECDSA_SHA_256",
            "trust_mode": admission.TRUST_MODE,
        },
        der,
    )


def command_sign(args: argparse.Namespace) -> None:
    payload = args.payload.read_bytes()
    envelope, der = _sign_payload(payload, args.key_arn)
    write(args.out, envelope)
    if args.public_der:
        args.public_der.write_bytes(der)


def command_seal(args: argparse.Namespace) -> None:
    ledger, ledger_raw = load(args.ledger)
    plan, plan_raw = load(args.build_plan)
    seal = {
        "build_cohort": ledger["build_cohort"],
        "build_plan_sha256": hashlib.sha256(plan_raw).hexdigest(),
        "builder": {"id": args.promoter_builder_id, "provider": "aws-codebuild"},
        "child_digests": {
            "amd64": require_digest(args.amd64_child_digest, "amd64 child digest"),
            "arm64": require_digest(args.arm64_child_digest, "arm64 child digest"),
        },
        "created_at": now(),
        "image": args.image,
        "image_repository": args.image_repository,
        "index_digest": require_digest(args.index_digest, "index digest"),
        "job_id": f"seal-index:{args.image}",
        "ledger_sha256": hashlib.sha256(ledger_raw).hexdigest(),
        "schema_version": admission.SCHEMA_VERSION,
        "trust_mode": admission.TRUST_MODE,
    }
    if plan.get("source_commit") != ledger.get("source_commit"):
        raise ValueError("plan and ledger source commits differ")
    write(args.out, seal)


def command_receipt(args: argparse.Namespace) -> None:
    ledger, ledger_raw = load(args.ledger)
    _, plan_raw = load(args.build_plan)
    _, seal_raw = load(args.index_seal)
    manifest, _ = load(args.evidence_manifest)
    evidence = manifest.get("evidence")
    if not isinstance(evidence, list):
        raise ValueError("evidence manifest has no evidence list")
    receipt = {
        "architecture": args.architecture,
        "build_cohort": ledger["build_cohort"],
        "build_plan_sha256": hashlib.sha256(plan_raw).hexdigest(),
        "builder": {
            "host_architecture": args.architecture,
            "id": args.builder_id,
            "native": True,
            "provider": "aws-codebuild",
        },
        "child_digest": require_digest(args.child_digest, "child digest"),
        "created_at": now(),
        "dirty_source": False,
        "evidence": evidence,
        "image": args.image,
        "image_repository": args.image_repository,
        "index_digest": require_digest(args.index_digest, "index digest"),
        "index_seal_sha256": hashlib.sha256(seal_raw).hexdigest(),
        "job_id": f"sign-receipt:{args.image}:{args.architecture}",
        "ledger_sha256": hashlib.sha256(ledger_raw).hexdigest(),
        "receipt_id": secrets.token_hex(32),
        "schema_version": admission.SCHEMA_VERSION,
        "source_commit": ledger["source_commit"],
        "source_ref": ledger["source_ref"],
        "source_repository": ledger["source_repository"],
        "source_tree": ledger["source_tree"],
        "trust_mode": admission.TRUST_MODE,
    }
    write(args.out, receipt)


def command_evidence(args: argparse.Namespace) -> None:
    child_digest = require_digest(args.child_digest, "child digest")
    timestamp = now()
    root = args.out_dir
    root.mkdir(parents=True, exist_ok=True)
    trivy = json.loads(args.trivy_report.read_text(encoding="utf-8"))
    if trivy.get("SchemaVersion") != 2 or trivy.get("ArtifactType") != "container_image":
        raise ValueError("Trivy report is not a completed container-image scan")
    metadata = trivy.get("Metadata") or {}
    repo_digests = metadata.get("RepoDigests") or []
    image_config = metadata.get("ImageConfig") or {}
    if not any(str(item).endswith(f"@{child_digest}") for item in repo_digests):
        raise ValueError("Trivy report is not bound to the exact child digest")
    if image_config.get("architecture") != args.architecture or image_config.get(
        "os"
    ) != "linux":
        raise ValueError("Trivy report platform does not match the native builder")
    results = trivy.get("Results")
    if (
        not isinstance(results, list)
        or not results
        or any(not isinstance(result, dict) or not result.get("Target") for result in results)
    ):
        raise ValueError("Trivy report has no completed non-vacuous result targets")
    vulnerabilities = [
        item
        for result in results
        for item in (result.get("Vulnerabilities") or [])
        if str(item.get("Severity", "")).upper() in {"HIGH", "CRITICAL"}
    ]
    if vulnerabilities:
        raise ValueError("Trivy found HIGH or CRITICAL vulnerabilities")
    sbom = json.loads(args.sbom.read_text(encoding="utf-8"))
    if not str(sbom.get("spdxVersion", "")).startswith("SPDX-"):
        raise ValueError("Syft output is not SPDX JSON")
    trivy_version = json.loads(args.trivy_version.read_text(encoding="utf-8"))
    if trivy_version.get("Version") != "0.70.0":
        raise ValueError("Trivy runtime is not the pinned 0.70.0 scanner")
    bodies: dict[str, object] = {
        "provenance": {
            "architecture": args.architecture,
            "build_cohort": require_sha(args.build_cohort, "build cohort"),
            "child_digest": child_digest,
            "predicate_type": "https://slsa.dev/provenance/v1",
            "source_commit": args.source_commit,
            "source_tree": args.source_tree,
        },
        "sbom": {
            "architecture": args.architecture,
            "child_digest": child_digest,
            "document": sbom,
            "predicate_type": "https://spdx.dev/Document",
            "spdx_version": sbom["spdxVersion"],
        },
        "trivy-report": {
            "architecture": args.architecture,
            "child_digest": child_digest,
            "critical": 0,
            "high": 0,
            "status": "clean",
        },
        "trivy-version": trivy_version,
        "trivy-db": json.loads(args.trivy_db.read_text(encoding="utf-8")),
        "quarantine-disposition": {
            "architecture": args.architecture,
            "critical": 0,
            "high": 0,
            "image_digest": child_digest,
            "status": "admitted",
        },
    }
    items = []
    for evidence_type, body in bodies.items():
        path = root / f"{evidence_type}.json"
        if isinstance(body, str):
            path.write_text(body, encoding="utf-8")
        else:
            write(path, body)
        item = {
            "created_at": timestamp,
            "path": path.name,
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "type": evidence_type,
        }
        if evidence_type == "trivy-version":
            item["version"] = "0.70.0"
        if evidence_type == "trivy-db":
            item["db_updated_at"] = args.trivy_db_updated_at
        items.append(item)
    write(root / "evidence-manifest.json", {"evidence": items})


def command_consumed(args: argparse.Namespace) -> None:
    prior, _ = load(args.prior) if args.prior else (
        {
            "build_cohorts": [],
            "generation": 0,
            "schema_version": admission.SCHEMA_VERSION,
            "trust_mode": admission.TRUST_MODE,
            "version_id": "seed",
        },
        b"",
    )
    value = transition_consumed(prior, args.consume, args.version_id)
    write(args.out, value)


def validate_consumed(value: object) -> dict:
    if not isinstance(value, dict) or set(value) != {
        "build_cohorts",
        "generation",
        "schema_version",
        "trust_mode",
        "version_id",
    }:
        raise ValueError("consumed-cohort ledger schema is not exact")
    cohorts = value.get("build_cohorts")
    if (
        value.get("schema_version") != admission.SCHEMA_VERSION
        or value.get("trust_mode") != admission.TRUST_MODE
        or not isinstance(value.get("generation"), int)
        or value["generation"] < 0
        or not isinstance(value.get("version_id"), str)
        or not value["version_id"]
        or not isinstance(cohorts, list)
        or cohorts != sorted(set(cohorts))
        or any(not SHA256.fullmatch(str(cohort)) for cohort in cohorts)
    ):
        raise ValueError("consumed-cohort ledger is invalid")
    return value


def transition_consumed(prior: dict, consume: str | None, version_id: str) -> dict:
    prior = validate_consumed(prior)
    values = list(prior["build_cohorts"])
    if consume:
        require_sha(consume, "consumed cohort")
        if consume in values:
            raise ValueError("build cohort is already consumed")
        values.append(consume)
    if not version_id or (consume and version_id == prior["version_id"]):
        raise ValueError("consumed-cohort version must advance")
    return {
        "build_cohorts": sorted(values),
        "generation": int(prior["generation"]) + (1 if consume else 0),
        "schema_version": admission.SCHEMA_VERSION,
        "trust_mode": admission.TRUST_MODE,
        "version_id": version_id,
    }


def signed_consumed_envelope(payload: dict, signature: dict) -> dict:
    validate_consumed(payload)
    if not isinstance(signature, dict):
        raise ValueError("consumed-cohort signature is not an object")
    if signature.get("payload_sha256") != hashlib.sha256(canonical(payload)).hexdigest():
        raise ValueError("consumed-cohort signature does not bind the embedded payload")
    return {
        "payload": payload,
        "schema_version": admission.SCHEMA_VERSION,
        "signature": signature,
        "trust_mode": admission.TRUST_MODE,
    }


def parse_signed_consumed_envelope(raw: bytes, key_arn: str) -> tuple[dict, dict]:
    try:
        envelope = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError("consumed-cohort envelope is not JSON") from exc
    if (
        not isinstance(envelope, dict)
        or raw != canonical(envelope)
        or set(envelope) != {"payload", "schema_version", "signature", "trust_mode"}
        or envelope.get("schema_version") != admission.SCHEMA_VERSION
        or envelope.get("trust_mode") != admission.TRUST_MODE
    ):
        raise ValueError("consumed-cohort envelope schema is not exact")
    payload = validate_consumed(envelope.get("payload"))
    signature = envelope.get("signature")
    signed_consumed_envelope(payload, signature)
    der, fingerprint = _kms_public_key(key_arn)
    with tempfile.TemporaryDirectory(prefix="ci-down-ledger-verify-") as temporary:
        root = pathlib.Path(temporary)
        der_path = root / "public.der"
        public_path = root / "public.pem"
        signature_path = root / "signature.json"
        der_path.write_bytes(der)
        write(signature_path, signature)
        subprocess.run(
            [
                "openssl",
                "pkey",
                "-pubin",
                "-inform",
                "DER",
                "-in",
                str(der_path),
                "-out",
                str(public_path),
            ],
            check=True,
            capture_output=True,
        )
        # _verify_signature takes the public key BYTES (it writes its own temp
        # file); handing it the path raised TypeError on the first cohort that
        # ever found a prior consumed-cohorts envelope (eb32edc5, 2026-11-14).
        admission._verify_signature(
            canonical(payload),
            signature_path,
            public_path.read_bytes(),
            key_arn,
            fingerprint,
        )
    return payload, signature


def _parse_s3_prefix(uri: str) -> tuple[str, str]:
    parsed = urllib.parse.urlsplit(uri)
    if (
        parsed.scheme != "s3"
        or not parsed.netloc
        or not parsed.path.strip("/")
        or parsed.query
        or parsed.fragment
        or any(part in {".", ".."} for part in parsed.path.split("/"))
    ):
        raise ValueError("cohort store URI is not an exact S3 prefix")
    return parsed.netloc, parsed.path.strip("/")


def _read_s3_envelope(
    bucket: str, key: str, destination: pathlib.Path, version_id: str | None = None
) -> tuple[bytes, str, str] | None:
    command = ["aws", "s3api", "get-object", "--bucket", bucket, "--key", key]
    if version_id:
        command.extend(["--version-id", version_id])
    command.extend([str(destination), "--output", "json"])
    result = subprocess.run(command, check=False, capture_output=True, text=True)
    if result.returncode != 0:
        if not version_id and any(
            marker in result.stderr
            for marker in ("NoSuchKey", "Not Found", "404")
        ):
            return None
        raise ValueError("cannot read the atomic consumed-cohort envelope")
    try:
        metadata = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise ValueError("consumed-cohort readback metadata is invalid") from exc
    etag, actual_version = metadata.get("ETag"), metadata.get("VersionId")
    if (
        not isinstance(etag, str)
        or not etag
        or not isinstance(actual_version, str)
        or not actual_version
        or actual_version.lower() in {"null", "none"}
    ):
        raise ValueError("consumed-cohort object is not versioned")
    return destination.read_bytes(), etag, actual_version


def _put_s3_envelope(
    *,
    bucket: str,
    key: str,
    body: pathlib.Path,
    prior_etag: str | None,
    evidence_kms_key_arn: str,
) -> tuple[str, str] | None:
    command = [
        "aws",
        "s3api",
        "put-object",
        "--bucket",
        bucket,
        "--key",
        key,
        "--body",
        str(body.resolve()),
        "--content-type",
        "application/json",
        "--server-side-encryption",
        "aws:kms",
        "--ssekms-key-id",
        evidence_kms_key_arn,
    ]
    command.extend(
        ["--if-match", prior_etag] if prior_etag else ["--if-none-match", "*"]
    )
    command.extend(["--output", "json"])
    result = subprocess.run(command, check=False, capture_output=True, text=True)
    if result.returncode != 0:
        if any(
            marker in result.stderr
            for marker in ("PreconditionFailed", "ConditionalRequestConflict", "412", "409")
        ):
            return None
        raise ValueError("atomic consumed-cohort transition failed")
    try:
        metadata = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise ValueError("consumed-cohort transition metadata is invalid") from exc
    etag, version_id = metadata.get("ETag"), metadata.get("VersionId")
    if (
        not isinstance(etag, str)
        or not etag
        or not isinstance(version_id, str)
        or not version_id
        or version_id.lower() in {"null", "none"}
    ):
        raise ValueError("atomic consumed-cohort transition was not versioned")
    return etag, version_id


def command_reserve_cohort(args: argparse.Namespace) -> None:
    cohort = require_sha(args.build_cohort, "build cohort")
    bucket, prefix = _parse_s3_prefix(args.cohort_store_uri)
    key = f"{prefix}/consumed-cohorts.envelope.json"
    seed = {
        "build_cohorts": [],
        "generation": 0,
        "schema_version": admission.SCHEMA_VERSION,
        "trust_mode": admission.TRUST_MODE,
        "version_id": "seed",
    }
    with tempfile.TemporaryDirectory(prefix="ci-down-cohort-cas-") as temporary:
        root = pathlib.Path(temporary)
        current_path = root / "current.json"
        candidate_path = root / "candidate.json"
        readback_path = root / "readback.json"
        for _ in range(args.max_attempts):
            current = _read_s3_envelope(bucket, key, current_path)
            if current is None:
                prior = seed
                prior_signature, _ = _sign_payload(canonical(prior), args.key_arn)
                prior_etag = None
            else:
                current_raw, prior_etag, _ = current
                prior, prior_signature = parse_signed_consumed_envelope(
                    current_raw, args.key_arn
                )
            next_value = transition_consumed(
                prior, cohort, secrets.token_hex(16)
            )
            next_signature, _ = _sign_payload(canonical(next_value), args.key_arn)
            candidate = signed_consumed_envelope(next_value, next_signature)
            write(candidate_path, candidate)
            committed = _put_s3_envelope(
                bucket=bucket,
                key=key,
                body=candidate_path,
                prior_etag=prior_etag,
                evidence_kms_key_arn=args.evidence_kms_key_arn,
            )
            if committed is None:
                continue
            committed_etag, committed_version = committed
            readback = _read_s3_envelope(
                bucket, key, readback_path, committed_version
            )
            if (
                readback is None
                or readback[0] != candidate_path.read_bytes()
                or readback[1] != committed_etag
                or readback[2] != committed_version
            ):
                raise ValueError("atomic consumed-cohort transition did not read back exactly")
            args.prior_out.parent.mkdir(parents=True, exist_ok=True)
            args.prior_out.write_bytes(canonical(prior))
            args.prior_signature_out.parent.mkdir(parents=True, exist_ok=True)
            args.prior_signature_out.write_bytes(canonical(prior_signature))
            args.committed_envelope_out.parent.mkdir(parents=True, exist_ok=True)
            args.committed_envelope_out.write_bytes(candidate_path.read_bytes())
            return
    raise ValueError("consumed-cohort ledger stayed contended; refusing promotion")


def command_claim(args: argparse.Namespace) -> None:
    ledger, _ = load(args.ledger)
    consumed, _ = load(args.consumed)
    cohort = require_sha(ledger["build_cohort"], "build cohort")
    claim = {
        "build_cohort": cohort,
        "created_at": now(),
        "generation": int(consumed["generation"]) + 1,
        "image": args.image,
        "image_repository": args.image_repository,
        "index_digest": require_digest(args.index_digest, "index digest"),
        "prior_generation": consumed["generation"],
        "prior_version_id": consumed["version_id"],
        "schema_version": admission.SCHEMA_VERSION,
        "state": "reserved",
        "store_uri": f"{args.cohort_store_uri.rstrip('/')}/consumed/{cohort}/{args.image}.json",
        "trust_mode": admission.TRUST_MODE,
        "version_id": args.version_id,
    }
    if claim["version_id"] == claim["prior_version_id"]:
        raise ValueError("claim version must differ from prior version")
    write(args.out, claim)


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser()
    sub = root.add_subparsers(dest="command", required=True)

    ledger = sub.add_parser("ledger")
    ledger.add_argument("--build-plan", type=pathlib.Path, required=True)
    ledger.add_argument("--coordinator-builder-id", required=True)
    ledger.add_argument("--amd64-builder-id", required=True)
    ledger.add_argument("--arm64-builder-id", required=True)
    ledger.add_argument("--promoter-builder-id", required=True)
    ledger.add_argument("--source-repository", required=True)
    ledger.add_argument("--out", type=pathlib.Path, required=True)
    ledger.set_defaults(handler=command_ledger)

    sign = sub.add_parser("sign")
    sign.add_argument("--payload", type=pathlib.Path, required=True)
    sign.add_argument("--key-arn", required=True)
    sign.add_argument("--out", type=pathlib.Path, required=True)
    sign.add_argument("--public-der", type=pathlib.Path)
    sign.set_defaults(handler=command_sign)

    seal = sub.add_parser("seal")
    seal.add_argument("--ledger", type=pathlib.Path, required=True)
    seal.add_argument("--build-plan", type=pathlib.Path, required=True)
    seal.add_argument("--promoter-builder-id", required=True)
    seal.add_argument("--image", required=True)
    seal.add_argument("--image-repository", required=True)
    seal.add_argument("--amd64-child-digest", required=True)
    seal.add_argument("--arm64-child-digest", required=True)
    seal.add_argument("--index-digest", required=True)
    seal.add_argument("--out", type=pathlib.Path, required=True)
    seal.set_defaults(handler=command_seal)

    receipt = sub.add_parser("receipt")
    receipt.add_argument("--ledger", type=pathlib.Path, required=True)
    receipt.add_argument("--build-plan", type=pathlib.Path, required=True)
    receipt.add_argument("--index-seal", type=pathlib.Path, required=True)
    receipt.add_argument("--evidence-manifest", type=pathlib.Path, required=True)
    receipt.add_argument("--architecture", choices=("amd64", "arm64"), required=True)
    receipt.add_argument("--builder-id", required=True)
    receipt.add_argument("--image", required=True)
    receipt.add_argument("--image-repository", required=True)
    receipt.add_argument("--child-digest", required=True)
    receipt.add_argument("--index-digest", required=True)
    receipt.add_argument("--out", type=pathlib.Path, required=True)
    receipt.set_defaults(handler=command_receipt)

    evidence = sub.add_parser("evidence")
    evidence.add_argument("--architecture", choices=("amd64", "arm64"), required=True)
    evidence.add_argument("--build-cohort", required=True)
    evidence.add_argument("--child-digest", required=True)
    evidence.add_argument("--source-commit", required=True)
    evidence.add_argument("--source-tree", required=True)
    evidence.add_argument("--trivy-report", type=pathlib.Path, required=True)
    evidence.add_argument("--trivy-version", type=pathlib.Path, required=True)
    evidence.add_argument("--trivy-db", type=pathlib.Path, required=True)
    evidence.add_argument("--trivy-db-updated-at", required=True)
    evidence.add_argument("--sbom", type=pathlib.Path, required=True)
    evidence.add_argument("--out-dir", type=pathlib.Path, required=True)
    evidence.set_defaults(handler=command_evidence)

    consumed = sub.add_parser("consumed")
    consumed.add_argument("--prior", type=pathlib.Path)
    consumed.add_argument("--consume")
    consumed.add_argument("--version-id", required=True)
    consumed.add_argument("--out", type=pathlib.Path, required=True)
    consumed.set_defaults(handler=command_consumed)

    reserve = sub.add_parser("reserve-cohort")
    reserve.add_argument("--cohort-store-uri", required=True)
    reserve.add_argument("--build-cohort", required=True)
    reserve.add_argument("--key-arn", required=True)
    reserve.add_argument("--evidence-kms-key-arn", required=True)
    reserve.add_argument("--prior-out", type=pathlib.Path, required=True)
    reserve.add_argument(
        "--prior-signature-out", type=pathlib.Path, required=True
    )
    reserve.add_argument(
        "--committed-envelope-out", type=pathlib.Path, required=True
    )
    reserve.add_argument("--max-attempts", type=int, default=8)
    reserve.set_defaults(handler=command_reserve_cohort)

    claim = sub.add_parser("claim")
    claim.add_argument("--ledger", type=pathlib.Path, required=True)
    claim.add_argument("--consumed", type=pathlib.Path, required=True)
    claim.add_argument("--image", required=True)
    claim.add_argument("--image-repository", required=True)
    claim.add_argument("--index-digest", required=True)
    claim.add_argument("--cohort-store-uri", required=True)
    claim.add_argument("--version-id", required=True)
    claim.add_argument("--out", type=pathlib.Path, required=True)
    claim.set_defaults(handler=command_claim)
    return root


def main() -> int:
    args = parser().parse_args()
    try:
        args.handler(args)
    except (
        OSError,
        ValueError,
        admission.AdmissionError,
        subprocess.CalledProcessError,
    ) as exc:
        raise SystemExit(f"CI-down evidence production refused: {exc}") from exc
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
