#!/usr/bin/env python3
"""Verify canonical AWS-KMS CI-down build receipts without trusting the executor."""

from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import json
import os
import pathlib
import re
import stat
import subprocess
import tempfile
import types
import urllib.parse
from types import MappingProxyType
from typing import Mapping, NamedTuple


TRUST_MODE = "aws-kms-ci-down-v1"
SCHEMA_VERSION = "1.1"
BUILD_PLAN_SCHEMA_VERSION = "1.0"
SHA256 = re.compile(r"^[0-9a-f]{64}$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")
TREE = re.compile(r"^[0-9a-f]{40}$")
KMS_ARN = re.compile(r"^arn:aws:kms:[a-z0-9-]+:[0-9]{12}:key/[0-9a-f-]+$")
SEMVER = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.]+)?$")
ARCHITECTURES = ("amd64", "arm64")
SIGNING_ROLES = ("coordinator", "amd64", "arm64", "promoter")
EVIDENCE_TYPES = {
    "provenance",
    "sbom",
    "trivy-report",
    "trivy-version",
    "trivy-db",
    "quarantine-disposition",
}
MAX_RECEIPT_AGE = dt.timedelta(hours=24)
MAX_TRIVY_DB_AGE = dt.timedelta(hours=24)
MAX_FUTURE_SKEW = dt.timedelta(minutes=5)


class AdmissionError(ValueError):
    pass


class TrustSourceIdentity(NamedTuple):
    path: pathlib.Path
    device: int
    inode: int
    size: int
    mtime_ns: int
    ctime_ns: int


class TrustSnapshot(NamedTuple):
    """One immutable read of the policy and every cryptographic trust root."""

    policy: Mapping[str, object]
    policy_bytes: bytes
    authorities: Mapping[str, tuple[Mapping[str, str], bytes]]
    release_build_plan_bytes: bytes
    expected_images: tuple[Mapping[str, object], ...]
    sources: tuple[TrustSourceIdentity, ...]


class VerifiedAdmission(NamedTuple):
    """Signed values a caller may consume without reopening evidence paths."""

    build_cohort: str
    image: str
    claim_bytes: bytes
    store_uri: str


def canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def _load_canonical(
    path: pathlib.Path,
    label: str,
    input_store: ImmutableInputStore | None = None,
) -> tuple[dict, bytes]:
    try:
        raw = (
            input_store.read(path, label)
            if input_store is not None
            else path.read_bytes()
        )
        value = json.loads(raw)
    except (OSError, json.JSONDecodeError) as exc:
        raise AdmissionError(f"cannot read {label}: {exc}") from exc
    if not isinstance(value, dict) or raw != canonical(value):
        raise AdmissionError(f"{label} is not a canonical JSON object")
    return value, raw


def _timestamp(value: object, label: str) -> dt.datetime:
    try:
        parsed = dt.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        raise AdmissionError(f"{label} timestamp is invalid") from None
    if parsed.tzinfo is None:
        raise AdmissionError(f"{label} timestamp has no timezone")
    return parsed.astimezone(dt.timezone.utc)


def _public_key_fingerprint(public_key: pathlib.Path | bytes) -> str:
    command = ["openssl", "pkey", "-pubin", "-outform", "DER"]
    kwargs: dict[str, object] = {"stderr": subprocess.PIPE}
    if isinstance(public_key, pathlib.Path):
        command.extend(["-in", str(public_key)])
    else:
        kwargs["input"] = public_key
    try:
        der = subprocess.check_output(command, **kwargs)
    except (OSError, subprocess.CalledProcessError) as exc:
        raise AdmissionError("cannot parse pinned KMS public key") from exc
    return hashlib.sha256(der).hexdigest()


def _source_identity(path: pathlib.Path, metadata: os.stat_result) -> TrustSourceIdentity:
    return TrustSourceIdentity(
        path=path,
        device=metadata.st_dev,
        inode=metadata.st_ino,
        size=metadata.st_size,
        mtime_ns=metadata.st_mtime_ns,
        ctime_ns=metadata.st_ctime_ns,
    )


def _read_trust_source_once(
    path: pathlib.Path, label: str
) -> tuple[bytes, TrustSourceIdentity]:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise AdmissionError(f"cannot read {label}: {exc}") from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise AdmissionError(f"{label} is not a regular file")
        chunks: list[bytes] = []
        while chunk := os.read(descriptor, 1024 * 1024):
            chunks.append(chunk)
        after = os.fstat(descriptor)
    except OSError as exc:
        raise AdmissionError(f"cannot read {label}: {exc}") from exc
    finally:
        os.close(descriptor)
    if _source_identity(path, before) != _source_identity(path, after):
        raise AdmissionError(f"{label} changed while its trust snapshot was loaded")
    return b"".join(chunks), _source_identity(path, after)


class ImmutableInputStore:
    """Cache every evidence pathname as one immutable byte/identity snapshot."""

    def __init__(self) -> None:
        self._snapshots: dict[
            pathlib.Path, tuple[bytes, TrustSourceIdentity]
        ] = {}

    def read(self, path: pathlib.Path, label: str) -> bytes:
        exact_path = path.absolute()
        existing = self._snapshots.get(exact_path)
        if existing is not None:
            return existing[0]
        raw, identity = _read_trust_source_once(exact_path, label)
        self._snapshots[exact_path] = (raw, identity)
        return raw

    def assert_unchanged(self) -> None:
        for expected_path, (_, expected) in self._snapshots.items():
            try:
                current = os.stat(expected_path, follow_symlinks=False)
            except OSError as exc:
                raise AdmissionError(
                    f"CI-down evidence changed after snapshot: {expected_path}"
                ) from exc
            if _source_identity(expected_path, current) != expected:
                raise AdmissionError(
                    f"CI-down evidence changed after snapshot: {expected_path}"
                )


def _release_images_from_bytes(raw: bytes) -> tuple[Mapping[str, object], ...]:
    module = types.ModuleType("ci_down_release_build_plan")
    module.__file__ = ".github/scripts/release-build-plan.py"
    try:
        exec(compile(raw, module.__file__, "exec"), module.__dict__)
    except (SyntaxError, ImportError, OSError) as exc:
        raise AdmissionError("cannot load reviewed build-plan generator") from exc
    images = getattr(module, "IMAGES", None)
    if not isinstance(images, tuple) or not images or any(
        not isinstance(image, dict) for image in images
    ):
        raise AdmissionError("reviewed build-plan generator image matrix is invalid")
    return tuple(MappingProxyType(dict(image)) for image in images)


def load_trust_snapshot(
    path: pathlib.Path, *, release_build_plan_bytes: bytes | None = None
) -> TrustSnapshot:
    """Read and validate policy plus key bytes exactly once.

    Callers must pass this same snapshot to :func:`verify`; verification never
    reopens a checkout trust-root path.
    """

    policy_path = path.absolute()
    raw, policy_source = _read_trust_source_once(policy_path, "CI-down trust policy")
    try:
        policy = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise AdmissionError(f"cannot read CI-down trust policy: {exc}") from exc
    if not isinstance(policy, dict) or raw != canonical(policy):
        raise AdmissionError("CI-down trust policy is not a canonical JSON object")
    if (
        set(policy)
        != {
            "amd64_builder_id",
            "arm64_builder_id",
            "cohort_store_uri",
            "coordinator_builder_id",
            "enabled",
            "promoter_builder_id",
            "schema_version",
            "signing_authorities",
            "trust_mode",
        }
        or policy.get("schema_version") != SCHEMA_VERSION
        or policy.get("trust_mode") != TRUST_MODE
    ):
        raise AdmissionError("CI-down trust policy schema/identity is not exact")
    if policy.get("enabled") is not True:
        raise AdmissionError(
            "CI-down trust policy is disabled until provider infrastructure is reviewed"
        )
    raw_authorities = policy.get("signing_authorities")
    if not isinstance(raw_authorities, dict) or set(raw_authorities) != set(
        SIGNING_ROLES
    ):
        raise AdmissionError("CI-down trust policy signing roles are not exact")
    authorities: dict[str, tuple[Mapping[str, str], bytes]] = {}
    sources = [policy_source]
    key_arns: set[str] = set()
    fingerprints: set[str] = set()
    public_paths: set[pathlib.Path] = set()
    for role in SIGNING_ROLES:
        authority = raw_authorities.get(role)
        if not isinstance(authority, dict) or set(authority) != {
            "kms_key_arn",
            "kms_public_key_path",
            "kms_public_key_sha256",
        }:
            raise AdmissionError(f"CI-down {role} signing authority is not exact")
        key_arn = str(authority.get("kms_key_arn", ""))
        fingerprint = str(authority.get("kms_public_key_sha256", ""))
        if not KMS_ARN.fullmatch(key_arn) or not SHA256.fullmatch(fingerprint):
            raise AdmissionError(f"CI-down {role} KMS identity is invalid")
        public_key_relative = pathlib.Path(
            str(authority.get("kms_public_key_path", ""))
        )
        public_key_candidate = (policy_path.parent / public_key_relative).absolute()
        public_key = public_key_candidate.resolve()
        if (
            public_key_relative.is_absolute()
            or policy_path.parent.resolve() not in public_key.parents
        ):
            raise AdmissionError(
                f"CI-down {role} public key is missing or escapes its root"
            )
        public_key_bytes, public_key_source = _read_trust_source_once(
            public_key_candidate, f"CI-down {role} public key"
        )
        if _public_key_fingerprint(public_key_bytes) != fingerprint:
            raise AdmissionError(
                f"CI-down {role} public key fingerprint does not match"
            )
        if (
            key_arn in key_arns
            or fingerprint in fingerprints
            or public_key in public_paths
        ):
            raise AdmissionError(
                "CI-down signing authorities must use distinct KMS keys and public pins"
            )
        key_arns.add(key_arn)
        fingerprints.add(fingerprint)
        public_paths.add(public_key)
        sources.append(public_key_source)
        authorities[role] = (
            MappingProxyType(
                {
                    "kms_key_arn": key_arn,
                    "kms_public_key_path": str(authority["kms_public_key_path"]),
                    "kms_public_key_sha256": fingerprint,
                }
            ),
            public_key_bytes,
        )
    for name in (
        "coordinator_builder_id",
        "amd64_builder_id",
        "arm64_builder_id",
        "promoter_builder_id",
    ):
        value = policy.get(name)
        if (
            not isinstance(value, str)
            or not value
            or any(char.isspace() for char in value)
        ):
            raise AdmissionError("CI-down trust policy builder identity is invalid")
    _parse_s3_uri(str(policy.get("cohort_store_uri", "")), "cohort store")
    immutable_policy = MappingProxyType(
        {
            **policy,
            "signing_authorities": MappingProxyType(
                {role: authorities[role][0] for role in SIGNING_ROLES}
            ),
        }
    )
    if release_build_plan_bytes is None:
        generator_path = pathlib.Path(__file__).with_name("release-build-plan.py")
        release_build_plan_bytes, generator_source = _read_trust_source_once(
            generator_path, "release build-plan generator"
        )
        sources.append(generator_source)
    expected_images = _release_images_from_bytes(release_build_plan_bytes)
    return TrustSnapshot(
        policy=immutable_policy,
        policy_bytes=raw,
        authorities=MappingProxyType(authorities),
        release_build_plan_bytes=release_build_plan_bytes,
        expected_images=expected_images,
        sources=tuple(sources),
    )


def assert_trust_snapshot_sources_unchanged(snapshot: TrustSnapshot) -> None:
    """Refuse persistent checkout swaps without consuming reopened bytes."""

    for expected in snapshot.sources:
        try:
            current = os.stat(expected.path, follow_symlinks=False)
        except OSError as exc:
            raise AdmissionError(
                f"CI-down trust source changed after snapshot: {expected.path}"
            ) from exc
        if _source_identity(expected.path, current) != expected:
            raise AdmissionError(
                f"CI-down trust source changed after snapshot: {expected.path}"
            )


def _load_trust_policy(
    path: pathlib.Path,
) -> tuple[dict, dict[str, tuple[dict, pathlib.Path]]]:
    snapshot = load_trust_snapshot(path)
    policy = json.loads(snapshot.policy_bytes)
    authorities = {
        role: (
            dict(snapshot.authorities[role][0]),
            snapshot.sources[index + 1].path,
        )
        for index, role in enumerate(SIGNING_ROLES)
    }
    return policy, authorities


def _parse_s3_uri(uri: str, label: str) -> tuple[str, str]:
    parsed = urllib.parse.urlsplit(uri)
    if (
        parsed.scheme != "s3"
        or not parsed.netloc
        or not parsed.path.strip("/")
        or parsed.query
        or parsed.fragment
        or any(part in {".", ".."} for part in parsed.path.split("/"))
    ):
        raise AdmissionError(f"{label} URI is not an exact S3 object/prefix")
    return parsed.netloc, parsed.path.strip("/")


def cohort_consumption_uri(policy: dict, build_cohort: str, image: str) -> str:
    bucket, prefix = _parse_s3_uri(policy["cohort_store_uri"], "cohort store")
    if not SHA256.fullmatch(build_cohort) or not re.fullmatch(
        r"[a-z0-9]+(?:[._-][a-z0-9]+)*", image
    ):
        raise AdmissionError("cohort consumption identity is invalid")
    return f"s3://{bucket}/{prefix}/consumed/{build_cohort}/{image}.json"


def _verify_signature(
    payload: bytes,
    envelope_path: pathlib.Path,
    public_key: bytes,
    expected_key_arn: str,
    expected_fingerprint: str,
    input_store: ImmutableInputStore | None = None,
) -> None:
    envelope, _ = _load_canonical(
        envelope_path, "signature envelope", input_store
    )
    if set(envelope) != {
        "kms_key_arn",
        "kms_public_key_sha256",
        "payload_sha256",
        "schema_version",
        "signature_base64",
        "signing_algorithm",
        "trust_mode",
    }:
        raise AdmissionError("signature envelope schema is not exact")
    expected = {
        "schema_version": SCHEMA_VERSION,
        "trust_mode": TRUST_MODE,
        "kms_key_arn": expected_key_arn,
        "kms_public_key_sha256": expected_fingerprint,
        "signing_algorithm": "ECDSA_SHA_256",
        "payload_sha256": hashlib.sha256(payload).hexdigest(),
    }
    if any(envelope.get(key) != value for key, value in expected.items()):
        raise AdmissionError(
            "signature envelope identity does not match the pinned KMS authority"
        )
    try:
        signature = base64.b64decode(envelope["signature_base64"], validate=True)
    except (KeyError, ValueError) as exc:
        raise AdmissionError("signature envelope has invalid signature bytes") from exc
    with tempfile.TemporaryDirectory(prefix="ci-down-signature-") as temporary:
        root = pathlib.Path(temporary)
        payload_path = root / "payload"
        signature_path = root / "signature"
        public_key_path = root / "public-key.pem"
        payload_path.write_bytes(payload)
        signature_path.write_bytes(signature)
        public_key_path.write_bytes(public_key)
        result = subprocess.run(
            [
                "openssl",
                "dgst",
                "-sha256",
                "-verify",
                str(public_key_path),
                "-signature",
                str(signature_path),
                str(payload_path),
            ],
            capture_output=True,
            text=True,
        )
    if result.returncode != 0:
        raise AdmissionError("KMS signature verification failed")


def _expected_jobs(
    plan: dict, builders: dict[str, str], promoter: str
) -> list[dict[str, str]]:
    images = plan.get("images")
    if not isinstance(images, list) or not images:
        raise AdmissionError("build plan has no images")
    jobs = []
    for image in images:
        name = image.get("name") if isinstance(image, dict) else None
        if not isinstance(name, str) or not name:
            raise AdmissionError("build plan has an invalid image")
        for architecture in ARCHITECTURES:
            jobs.append(
                {
                    "architecture": architecture,
                    "builder_id": builders[architecture],
                    "image": name,
                    "job_id": f"build-child:{name}:{architecture}",
                    "phase": "child-build",
                }
            )
        jobs.append(
            {
                "architecture": "multiarch",
                "builder_id": promoter,
                "image": name,
                "job_id": f"seal-index:{name}",
                "phase": "index-seal",
            }
        )
        for architecture in ARCHITECTURES:
            jobs.append(
                {
                    "architecture": architecture,
                    "builder_id": builders[architecture],
                    "image": name,
                    "job_id": f"sign-receipt:{name}:{architecture}",
                    "phase": "post-index-receipt",
                }
            )
    jobs.append(
        {
            "architecture": "multiarch",
            "builder_id": promoter,
            "image": "*",
            "job_id": "promote",
            "phase": "promotion",
        }
    )
    return jobs


def _validate_build_plan(
    plan: dict, raw: bytes, trust_snapshot: TrustSnapshot
) -> str:
    if (
        set(plan)
        != {
            "architectures",
            "build_date",
            "edition",
            "generator",
            "images",
            "platform_version",
            "schema_version",
            "short_sha",
            "source_commit",
            "source_date_epoch",
            "source_tree",
        }
        or plan.get("schema_version") != BUILD_PLAN_SCHEMA_VERSION
    ):
        raise AdmissionError("build plan schema is not exact")
    if (
        plan.get("architectures") != ["amd64", "arm64"]
        or plan.get("edition") != "enterprise"
    ):
        raise AdmissionError("build plan architecture/edition is not release-capable")
    if not COMMIT.fullmatch(str(plan.get("source_commit", ""))) or not TREE.fullmatch(
        str(plan.get("source_tree", ""))
    ):
        raise AdmissionError("build plan source identity is invalid")
    if plan.get("short_sha") != plan["source_commit"][:7] or not SEMVER.fullmatch(
        str(plan.get("platform_version", ""))
    ):
        raise AdmissionError("build plan source/version metadata is invalid")
    if (
        not isinstance(plan.get("source_date_epoch"), int)
        or plan["source_date_epoch"] <= 0
    ):
        raise AdmissionError("build plan source epoch is invalid")
    expected_date = dt.datetime.fromtimestamp(
        plan["source_date_epoch"], dt.timezone.utc
    ).strftime("%Y-%m-%dT%H:%M:%SZ")
    if plan.get("build_date") != expected_date:
        raise AdmissionError("build plan date is not derived from the source epoch")
    if plan.get("generator") != {
        "path": ".github/scripts/release-build-plan.py",
        "sha256": hashlib.sha256(
            trust_snapshot.release_build_plan_bytes
        ).hexdigest(),
    }:
        raise AdmissionError(
            "build plan generator identity is not the reviewed generator"
        )
    expected_images = [
        {key: value for key, value in image.items() if key != "enterprise_only"}
        for image in trust_snapshot.expected_images
    ]
    images = plan.get("images")
    if not isinstance(images, list) or not images:
        raise AdmissionError("build plan has no images")
    names: set[str] = set()
    for image in images:
        if not isinstance(image, dict) or set(image) != {
            "context",
            "dockerfile",
            "edition_arg",
            "go",
            "name",
            "version_args",
        }:
            raise AdmissionError("build plan image schema is not exact")
        if (
            not isinstance(image["name"], str)
            or not image["name"]
            or image["name"] in names
            or not isinstance(image["context"], str)
            or not image["context"]
            or not isinstance(image["dockerfile"], str)
            or not image["dockerfile"].endswith("/Dockerfile")
            or any(
                not isinstance(image[key], bool)
                for key in ("edition_arg", "go", "version_args")
            )
        ):
            raise AdmissionError("build plan image definition is invalid")
        names.add(image["name"])
    if images != expected_images:
        raise AdmissionError(
            "build plan image matrix differs from the reviewed generator"
        )
    return hashlib.sha256(raw).hexdigest()


def _validate_oci_index(
    path: pathlib.Path,
    index_digest: str,
    receipts: dict[str, dict],
    input_store: ImmutableInputStore | None = None,
) -> dict[str, str]:
    try:
        raw = (
            input_store.read(path, "OCI index")
            if input_store is not None
            else path.read_bytes()
        )
        index = json.loads(raw)
    except (OSError, json.JSONDecodeError) as exc:
        raise AdmissionError(f"cannot read OCI index: {exc}") from exc
    if hashlib.sha256(raw).hexdigest() != index_digest.removeprefix("sha256:"):
        raise AdmissionError("OCI index bytes do not match the admitted digest")
    if not isinstance(index, dict) or index.get("mediaType") not in {
        "application/vnd.oci.image.index.v1+json",
        "application/vnd.docker.distribution.manifest.list.v2+json",
    }:
        raise AdmissionError("admitted image is not an OCI/Docker index")
    manifests = index.get("manifests")
    if not isinstance(manifests, list):
        raise AdmissionError("OCI index has no manifest list")
    runnable: dict[str, str] = {}
    for descriptor in manifests:
        if not isinstance(descriptor, dict):
            raise AdmissionError("OCI index contains a non-object descriptor")
        platform = descriptor.get("platform") or {}
        os_name, architecture = platform.get("os"), platform.get("architecture")
        digest = descriptor.get("digest")
        if not DIGEST.fullmatch(str(digest or "")):
            raise AdmissionError("OCI index contains an invalid descriptor digest")
        if os_name == "linux" and architecture in ARCHITECTURES:
            if architecture in runnable:
                raise AdmissionError(
                    f"OCI index contains duplicate linux/{architecture}"
                )
            runnable[architecture] = digest
        elif (os_name, architecture) == ("unknown", "unknown"):
            if (descriptor.get("annotations") or {}).get(
                "vnd.docker.reference.type"
            ) != "attestation-manifest":
                raise AdmissionError("OCI index contains an unbound unknown platform")
        else:
            raise AdmissionError(
                f"OCI index contains unexpected platform {os_name}/{architecture}"
            )
    if set(runnable) != set(ARCHITECTURES):
        raise AdmissionError("OCI index is missing a required native architecture")
    if runnable["amd64"] == runnable["arm64"]:
        raise AdmissionError("OCI index native architectures share one child digest")
    for architecture in ARCHITECTURES:
        if runnable[architecture] != receipts[architecture]["child_digest"]:
            raise AdmissionError(
                f"{architecture} receipt child digest does not match the OCI index"
            )
    return runnable


def _validate_index_seal(
    seal: dict,
    seal_raw: bytes,
    *,
    ledger: dict,
    ledger_digest: str,
    build_plan_sha256: str,
    image: str,
    image_repository: str,
    index_digest: str,
    promoter_builder_id: str,
    now: dt.datetime,
) -> tuple[str, dt.datetime]:
    if set(seal) != {
        "build_cohort",
        "build_plan_sha256",
        "builder",
        "child_digests",
        "created_at",
        "image",
        "image_repository",
        "index_digest",
        "job_id",
        "ledger_sha256",
        "schema_version",
        "trust_mode",
    }:
        raise AdmissionError("sealed OCI index record schema is not exact")
    expected = {
        "schema_version": SCHEMA_VERSION,
        "trust_mode": TRUST_MODE,
        "build_cohort": ledger["build_cohort"],
        "build_plan_sha256": build_plan_sha256,
        "ledger_sha256": ledger_digest,
        "image": image,
        "image_repository": image_repository,
        "index_digest": index_digest,
        "job_id": f"seal-index:{image}",
    }
    if any(seal.get(key) != value for key, value in expected.items()):
        raise AdmissionError("sealed OCI index identity does not match the cohort")
    if seal.get("builder") != {
        "id": promoter_builder_id,
        "provider": "aws-codebuild",
    }:
        raise AdmissionError("sealed OCI index is not from the pinned promoter")
    child_digests = seal.get("child_digests")
    if (
        not isinstance(child_digests, dict)
        or set(child_digests) != set(ARCHITECTURES)
        or any(not DIGEST.fullmatch(str(value)) for value in child_digests.values())
        or child_digests["amd64"] == child_digests["arm64"]
    ):
        raise AdmissionError("sealed OCI index child cohort is invalid")
    job = {
        "architecture": "multiarch",
        "builder_id": promoter_builder_id,
        "image": image,
        "job_id": f"seal-index:{image}",
        "phase": "index-seal",
    }
    if ledger["jobs"].count(job) != 1:
        raise AdmissionError("sealed OCI index phase is missing or duplicated")
    created = _timestamp(seal.get("created_at"), "index seal created_at")
    if created > now + MAX_FUTURE_SKEW or now - created > MAX_RECEIPT_AGE:
        raise AdmissionError("sealed OCI index is stale or future-dated")
    return hashlib.sha256(seal_raw).hexdigest(), created


def _validate_ledger(
    ledger: dict,
    plan: dict,
    build_plan_sha256: str,
    builders: dict[str, str],
    coordinator: str,
    promoter: str,
    source_repository: str,
    source_ref: str,
    source_commit: str,
    source_tree: str,
    now: dt.datetime,
) -> None:
    if set(ledger) != {
        "admission_nonce",
        "build_cohort",
        "build_plan_sha256",
        "created_at",
        "coordinator",
        "dirty_source",
        "expires_at",
        "jobs",
        "schema_version",
        "source_commit",
        "source_ref",
        "source_repository",
        "source_tree",
        "trust_mode",
    }:
        raise AdmissionError("canonical job ledger schema is not exact")
    expected = {
        "schema_version": SCHEMA_VERSION,
        "trust_mode": TRUST_MODE,
        "source_repository": source_repository,
        "source_ref": source_ref,
        "source_commit": source_commit,
        "source_tree": source_tree,
        "build_plan_sha256": build_plan_sha256,
    }
    if any(ledger.get(key) != value for key, value in expected.items()):
        raise AdmissionError("canonical job ledger source identity does not match")
    if ledger.get("coordinator") != {
        "id": coordinator,
        "provider": "aws-codebuild",
    }:
        raise AdmissionError("canonical job ledger is not from the pinned coordinator")
    if (
        plan.get("source_commit") != source_commit
        or plan.get("source_tree") != source_tree
    ):
        raise AdmissionError("build plan does not identify the exact source tree")
    if ledger.get("dirty_source") is not False:
        raise AdmissionError("canonical job ledger does not attest a clean source tree")
    if not SHA256.fullmatch(str(ledger.get("build_cohort", ""))):
        raise AdmissionError("canonical job ledger has an invalid build cohort")
    if not SHA256.fullmatch(str(ledger.get("admission_nonce", ""))):
        raise AdmissionError("canonical job ledger has an invalid admission nonce")
    if ledger.get("jobs") != _expected_jobs(plan, builders, promoter):
        raise AdmissionError(
            "canonical job ledger does not contain the exact release job matrix"
        )
    created = _timestamp(ledger.get("created_at"), "ledger created_at")
    expires = _timestamp(ledger.get("expires_at"), "ledger expires_at")
    if (
        created > now + MAX_FUTURE_SKEW
        or now - created > MAX_RECEIPT_AGE
        or expires <= now
        or expires - created > MAX_RECEIPT_AGE
    ):
        raise AdmissionError("canonical job ledger is stale, future-dated, or overlong")


def _validate_evidence(
    receipt: dict,
    receipt_path: pathlib.Path,
    now: dt.datetime,
    input_store: ImmutableInputStore | None = None,
) -> dt.datetime:
    evidence = receipt.get("evidence")
    if (
        not isinstance(evidence, list)
        or {item.get("type") for item in evidence if isinstance(item, dict)}
        != EVIDENCE_TYPES
    ):
        raise AdmissionError("build receipt does not contain the exact evidence set")
    root = receipt_path.parent.resolve()
    names: set[str] = set()
    latest_created = dt.datetime.min.replace(tzinfo=dt.timezone.utc)
    for item in evidence:
        if not isinstance(item, dict) or not SHA256.fullmatch(
            str(item.get("sha256", ""))
        ):
            raise AdmissionError("build receipt has invalid evidence metadata")
        name = item.get("path")
        if not isinstance(name, str) or not name or name in names:
            raise AdmissionError(
                "build receipt has missing or duplicate evidence paths"
            )
        names.add(name)
        path = (root / name).resolve()
        if root not in path.parents or not path.is_file():
            raise AdmissionError(
                "build receipt evidence escapes its root or is missing"
            )
        try:
            evidence_bytes = (
                input_store.read(path, f"build receipt evidence {name}")
                if input_store is not None
                else path.read_bytes()
            )
        except OSError as exc:
            raise AdmissionError(f"cannot read evidence {name}: {exc}") from exc
        if hashlib.sha256(evidence_bytes).hexdigest() != item["sha256"]:
            raise AdmissionError(f"evidence digest mismatch for {name}")
        created = _timestamp(item.get("created_at"), f"{item['type']} created_at")
        latest_created = max(latest_created, created)
        if created > now + MAX_FUTURE_SKEW or now - created > MAX_RECEIPT_AGE:
            raise AdmissionError(f"{item['type']} evidence is stale or future-dated")
        if item["type"] == "trivy-version" and item.get("version") != "0.70.0":
            raise AdmissionError("Trivy version is not the pinned release scanner")
        if item["type"] in {"provenance", "sbom", "trivy-report"}:
            try:
                body = json.loads(evidence_bytes)
            except json.JSONDecodeError as exc:
                raise AdmissionError(
                    f"{item['type']} evidence is invalid JSON"
                ) from exc
            identity = {
                "architecture": receipt["architecture"],
                "child_digest": receipt["child_digest"],
            }
            if any(body.get(key) != value for key, value in identity.items()):
                raise AdmissionError(
                    f"{item['type']} evidence is not bound to the child image"
                )
            if item["type"] == "provenance" and (
                body.get("predicate_type") != "https://slsa.dev/provenance/v1"
                or body.get("source_commit") != receipt["source_commit"]
                or body.get("source_tree") != receipt["source_tree"]
                or body.get("build_cohort") != receipt["build_cohort"]
            ):
                raise AdmissionError(
                    "provenance does not bind the exact source/build cohort"
                )
            if item["type"] == "sbom" and (
                body.get("predicate_type") != "https://spdx.dev/Document"
                or not str(body.get("spdx_version", "")).startswith("SPDX-")
            ):
                raise AdmissionError("SBOM is not a bound SPDX document")
            if item["type"] == "trivy-report" and body != {
                "architecture": receipt["architecture"],
                "child_digest": receipt["child_digest"],
                "critical": 0,
                "high": 0,
                "status": "clean",
            }:
                raise AdmissionError(
                    "Trivy report did not clear the exact child digest"
                )
        if item["type"] == "trivy-db":
            updated = _timestamp(item.get("db_updated_at"), "Trivy DB updated_at")
            if updated > now + MAX_FUTURE_SKEW or now - updated > MAX_TRIVY_DB_AGE:
                raise AdmissionError("Trivy DB is stale or future-dated")
        if item["type"] == "quarantine-disposition":
            try:
                disposition = json.loads(evidence_bytes)
            except json.JSONDecodeError as exc:
                raise AdmissionError("quarantine disposition is invalid JSON") from exc
            if disposition != {
                "architecture": receipt["architecture"],
                "critical": 0,
                "high": 0,
                "image_digest": receipt["child_digest"],
                "status": "admitted",
            }:
                raise AdmissionError(
                    "quarantine disposition did not admit the exact child digest"
                )
    return latest_created


def verify(
    args: argparse.Namespace,
    *,
    trust_snapshot: TrustSnapshot | None = None,
    input_store: ImmutableInputStore | None = None,
) -> VerifiedAdmission:
    now = (
        _timestamp(args.now, "verification time")
        if args.now
        else dt.datetime.now(dt.timezone.utc)
    )
    snapshot = trust_snapshot or load_trust_snapshot(args.trust_policy)
    inputs = input_store or ImmutableInputStore()
    assert_trust_snapshot_sources_unchanged(snapshot)
    policy, authorities = snapshot.policy, snapshot.authorities
    if not COMMIT.fullmatch(args.source_commit) or not TREE.fullmatch(args.source_tree):
        raise AdmissionError("source commit/tree identity is invalid")
    if args.source_ref != "refs/heads/main":
        raise AdmissionError(
            "CI-down release admission is restricted to refs/heads/main"
        )
    if not DIGEST.fullmatch(args.index_digest):
        raise AdmissionError("index digest is invalid")
    builders = {
        "amd64": policy["amd64_builder_id"],
        "arm64": policy["arm64_builder_id"],
    }
    promoter_builder_id = policy["promoter_builder_id"]

    plan, plan_raw = _load_canonical(args.build_plan, "build plan", inputs)
    build_plan_sha256 = _validate_build_plan(plan, plan_raw, snapshot)
    ledger, ledger_raw = _load_canonical(
        args.ledger, "canonical job ledger", inputs
    )
    coordinator_authority, coordinator_public_key = authorities["coordinator"]
    _verify_signature(
        ledger_raw,
        args.ledger_signature,
        coordinator_public_key,
        coordinator_authority["kms_key_arn"],
        coordinator_authority["kms_public_key_sha256"],
        inputs,
    )
    _validate_ledger(
        ledger,
        plan,
        build_plan_sha256,
        builders,
        policy["coordinator_builder_id"],
        promoter_builder_id,
        args.source_repository,
        args.source_ref,
        args.source_commit,
        args.source_tree,
        now,
    )
    ledger_digest = hashlib.sha256(ledger_raw).hexdigest()

    seal, seal_raw = _load_canonical(
        args.index_seal, "sealed OCI index record", inputs
    )
    promoter_authority, promoter_public_key = authorities["promoter"]
    _verify_signature(
        seal_raw,
        args.index_seal_signature,
        promoter_public_key,
        promoter_authority["kms_key_arn"],
        promoter_authority["kms_public_key_sha256"],
        inputs,
    )
    index_seal_sha256, index_sealed_at = _validate_index_seal(
        seal,
        seal_raw,
        ledger=ledger,
        ledger_digest=ledger_digest,
        build_plan_sha256=build_plan_sha256,
        image=args.image,
        image_repository=args.image_repository,
        index_digest=args.index_digest,
        promoter_builder_id=promoter_builder_id,
        now=now,
    )

    receipts: dict[str, dict] = {}
    receipt_ids: set[str] = set()
    for architecture, path, signature in (
        ("amd64", args.amd64_receipt, args.amd64_signature),
        ("arm64", args.arm64_receipt, args.arm64_signature),
    ):
        receipt, raw = _load_canonical(
            path, f"{architecture} build receipt", inputs
        )
        if set(receipt) != {
            "architecture",
            "build_cohort",
            "build_plan_sha256",
            "builder",
            "child_digest",
            "created_at",
            "dirty_source",
            "evidence",
            "image",
            "image_repository",
            "index_digest",
            "index_seal_sha256",
            "job_id",
            "ledger_sha256",
            "receipt_id",
            "schema_version",
            "source_commit",
            "source_ref",
            "source_repository",
            "source_tree",
            "trust_mode",
        }:
            raise AdmissionError(f"{architecture} receipt schema is not exact")
        _verify_signature(
            raw,
            signature,
            authorities[architecture][1],
            authorities[architecture][0]["kms_key_arn"],
            authorities[architecture][0]["kms_public_key_sha256"],
            inputs,
        )
        expected = {
            "schema_version": SCHEMA_VERSION,
            "trust_mode": TRUST_MODE,
            "source_repository": args.source_repository,
            "source_ref": args.source_ref,
            "source_commit": args.source_commit,
            "source_tree": args.source_tree,
            "build_cohort": ledger["build_cohort"],
            "ledger_sha256": ledger_digest,
            "build_plan_sha256": build_plan_sha256,
            "image": args.image,
            "image_repository": args.image_repository,
            "index_digest": args.index_digest,
            "index_seal_sha256": index_seal_sha256,
            "architecture": architecture,
            "dirty_source": False,
        }
        if any(receipt.get(key) != value for key, value in expected.items()):
            raise AdmissionError(
                f"{architecture} receipt identity does not match the requested cohort"
            )
        if not DIGEST.fullmatch(str(receipt.get("child_digest", ""))):
            raise AdmissionError(f"{architecture} receipt has an invalid child digest")
        receipt_id = receipt.get("receipt_id")
        if not SHA256.fullmatch(str(receipt_id or "")) or receipt_id in receipt_ids:
            raise AdmissionError(
                "receipt identifiers are invalid or replayed within the cohort"
            )
        receipt_ids.add(receipt_id)
        builder = receipt.get("builder")
        if builder != {
            "host_architecture": architecture,
            "id": builders[architecture],
            "native": True,
            "provider": "aws-codebuild",
        }:
            raise AdmissionError(
                f"{architecture} receipt is not from the pinned native builder"
            )
        job = {
            "architecture": architecture,
            "builder_id": builders[architecture],
            "image": args.image,
            "job_id": f"sign-receipt:{args.image}:{architecture}",
            "phase": "post-index-receipt",
        }
        if ledger["jobs"].count(job) != 1 or receipt.get("job_id") != job["job_id"]:
            raise AdmissionError(
                f"{architecture} post-index receipt phase is missing or duplicated"
            )
        created = _timestamp(
            receipt.get("created_at"), f"{architecture} receipt created_at"
        )
        if created > now + MAX_FUTURE_SKEW or now - created > MAX_RECEIPT_AGE:
            raise AdmissionError(f"{architecture} receipt is stale or future-dated")
        latest_evidence = _validate_evidence(receipt, path, now, inputs)
        if latest_evidence > index_sealed_at or created < index_sealed_at:
            raise AdmissionError(
                f"{architecture} receipt does not prove child-build then index-seal ordering"
            )
        receipts[architecture] = receipt
    if receipts["amd64"]["child_digest"] == receipts["arm64"]["child_digest"]:
        raise AdmissionError(
            "native architectures unexpectedly identify the same child digest"
        )
    runnable = _validate_oci_index(
        args.oci_index, args.index_digest, receipts, inputs
    )
    if seal["child_digests"] != runnable:
        raise AdmissionError("sealed OCI index child cohort does not match the index")

    consumed, consumed_raw = _load_canonical(
        args.consumed_cohorts, "consumed-cohort ledger", inputs
    )
    _verify_signature(
        consumed_raw,
        args.consumed_cohorts_signature,
        promoter_public_key,
        promoter_authority["kms_key_arn"],
        promoter_authority["kms_public_key_sha256"],
        inputs,
    )
    values = consumed.get("build_cohorts")
    if (
        set(consumed)
        != {"build_cohorts", "generation", "schema_version", "trust_mode", "version_id"}
        or consumed.get("schema_version") != SCHEMA_VERSION
        or consumed.get("trust_mode") != TRUST_MODE
        or not isinstance(consumed.get("generation"), int)
        or consumed["generation"] < 0
        or not isinstance(values, list)
        or values != sorted(set(values))
        or any(not SHA256.fullmatch(str(value)) for value in values)
        or ledger["build_cohort"] in values
    ):
        raise AdmissionError(
            "build cohort was already consumed or replay ledger is invalid"
        )
    claim, claim_raw = _load_canonical(
        args.cohort_claim, "cohort reservation claim", inputs
    )
    _verify_signature(
        claim_raw,
        args.cohort_claim_signature,
        promoter_public_key,
        promoter_authority["kms_key_arn"],
        promoter_authority["kms_public_key_sha256"],
        inputs,
    )
    if set(claim) != {
        "build_cohort",
        "created_at",
        "generation",
        "image",
        "image_repository",
        "index_digest",
        "prior_generation",
        "prior_version_id",
        "schema_version",
        "state",
        "store_uri",
        "trust_mode",
        "version_id",
    } or any(
        claim.get(key) != value
        for key, value in {
            "schema_version": SCHEMA_VERSION,
            "trust_mode": TRUST_MODE,
            "build_cohort": ledger["build_cohort"],
            "image": args.image,
            "image_repository": args.image_repository,
            "index_digest": args.index_digest,
            "state": "reserved",
            "prior_generation": consumed["generation"],
            "generation": consumed["generation"] + 1,
            "prior_version_id": consumed["version_id"],
        }.items()
    ):
        raise AdmissionError("cohort reservation is not an atomic monotonic claim")
    if claim.get("store_uri") != cohort_consumption_uri(
        policy, ledger["build_cohort"], args.image
    ):
        raise AdmissionError(
            "cohort reservation does not identify the pinned one-time store object"
        )
    if (
        not all(
            isinstance(claim.get(key), str) and claim[key]
            for key in ("store_uri", "version_id")
        )
        or claim["version_id"] == claim["prior_version_id"]
    ):
        raise AdmissionError("cohort reservation version identity is invalid")
    claimed_at = _timestamp(claim.get("created_at"), "cohort reservation created_at")
    if claimed_at > now + MAX_FUTURE_SKEW or now - claimed_at > MAX_RECEIPT_AGE:
        raise AdmissionError("cohort reservation is stale or future-dated")
    inputs.assert_unchanged()
    assert_trust_snapshot_sources_unchanged(snapshot)
    return VerifiedAdmission(
        build_cohort=ledger["build_cohort"],
        image=args.image,
        claim_bytes=claim_raw,
        store_uri=claim["store_uri"],
    )


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--build-plan", required=True, type=pathlib.Path)
    parser.add_argument("--ledger", required=True, type=pathlib.Path)
    parser.add_argument("--ledger-signature", required=True, type=pathlib.Path)
    parser.add_argument("--index-seal", required=True, type=pathlib.Path)
    parser.add_argument("--index-seal-signature", required=True, type=pathlib.Path)
    parser.add_argument("--amd64-receipt", required=True, type=pathlib.Path)
    parser.add_argument("--amd64-signature", required=True, type=pathlib.Path)
    parser.add_argument("--arm64-receipt", required=True, type=pathlib.Path)
    parser.add_argument("--arm64-signature", required=True, type=pathlib.Path)
    parser.add_argument("--source-repository", required=True)
    parser.add_argument("--source-ref", required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--source-tree", required=True)
    parser.add_argument("--image", required=True)
    parser.add_argument("--image-repository", required=True)
    parser.add_argument("--index-digest", required=True)
    parser.add_argument("--oci-index", required=True, type=pathlib.Path)
    parser.add_argument("--consumed-cohorts", required=True, type=pathlib.Path)
    parser.add_argument(
        "--consumed-cohorts-signature", required=True, type=pathlib.Path
    )
    parser.add_argument("--cohort-claim", required=True, type=pathlib.Path)
    parser.add_argument("--cohort-claim-signature", required=True, type=pathlib.Path)
    parser.add_argument(
        "--now", help="fixed RFC3339 verification time for reproducible tests"
    )
    return parser


def main() -> int:
    parser = build_argument_parser()
    args = parser.parse_args()
    # Standalone verification is diagnostic only and cannot select its own
    # trust root. Production callers consume this same reviewed repository
    # policy rather than accepting a caller-controlled path.
    args.trust_policy = (
        pathlib.Path(__file__).resolve().parent.parent
        / "release"
        / "ci-down-trust-policy.json"
    )
    try:
        verify(args)
    except AdmissionError as exc:
        parser.error(str(exc))
    print(
        f"CI-down KMS admission passed for {args.image_repository}@{args.index_digest}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
