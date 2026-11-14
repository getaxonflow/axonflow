#!/usr/bin/env python3
"""Fail closed unless an OCI index has the reviewed two-arch attestation shape."""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import pathlib
import re
import sys


SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
INDEX_MEDIA_TYPES = {
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
}
ATTESTATION_MEDIA_TYPE = "application/vnd.in-toto+json"
PROVENANCE_PREFIX = "https://slsa.dev/provenance/"
SBOM_PREDICATES = {
    "https://spdx.dev/Document",
    "https://cyclonedx.org/bom",
}
EXPECTED_TRIVY_VERSION = "0.70.0"
MAX_VULNERABILITY_EVIDENCE_AGE = datetime.timedelta(hours=24)


class ValidationError(ValueError):
    pass


def _load(path: pathlib.Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValidationError(f"cannot read {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ValidationError(f"{path} is not a JSON object")
    return value


def _verify_digest(path: pathlib.Path, digest: str, label: str) -> None:
    if not SHA256.fullmatch(digest):
        raise ValidationError(f"{label} has an invalid digest")
    if not path.is_file() or _sha256(path) != digest.removeprefix("sha256:"):
        raise ValidationError(f"{label} bytes do not match {digest}")


def _parse_timestamp(value: object, label: str) -> datetime.datetime:
    try:
        parsed = datetime.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        raise ValidationError(f"{label} timestamp is invalid") from None
    if parsed.tzinfo is None:
        raise ValidationError(f"{label} timestamp has no timezone")
    return parsed.astimezone(datetime.timezone.utc)


def _subject_matches(statement: dict, subject: str) -> bool:
    expected = subject.removeprefix("sha256:")
    subjects = statement.get("subject")
    return isinstance(subjects, list) and any(
        isinstance(item, dict)
        and isinstance(item.get("digest"), dict)
        and item["digest"].get("sha256") == expected
        for item in subjects
    )


def _provenance_matches_source(statement: dict, expected_source_commit: str) -> bool:
    predicate = statement.get("predicate") or {}
    build_definition = predicate.get("buildDefinition") or {}
    external = build_definition.get("externalParameters") or {}
    request = external.get("request") or {}
    root = request.get("root") or {}
    root_request = root.get("request") or {}
    root_args = root_request.get("args") or {}
    run_details = predicate.get("runDetails") or {}
    metadata = run_details.get("metadata") or {}
    buildkit_metadata = metadata.get("buildkit_metadata") or {}
    vcs = buildkit_metadata.get("vcs") or {}
    return (
        root_args.get("vcs:revision") == expected_source_commit
        and vcs.get("revision") == expected_source_commit
    )


def validate(
    index: dict,
    index_path: pathlib.Path,
    expected_index_digest: str,
    children_dir: pathlib.Path,
    attestations_dir: pathlib.Path,
    predicates_dir: pathlib.Path,
    expected_source_commit: str,
    vulnerability_dir: pathlib.Path,
) -> None:
    _verify_digest(index_path, expected_index_digest, "release index")
    if index.get("mediaType") not in INDEX_MEDIA_TYPES:
        raise ValidationError("release image is not an OCI/Docker manifest index")
    manifests = index.get("manifests")
    if not isinstance(manifests, list):
        raise ValidationError("release index has no manifest list")

    runnable: dict[str, str] = {}
    attestations: dict[str, str] = {}
    for descriptor in manifests:
        if not isinstance(descriptor, dict):
            raise ValidationError("release index contains a non-object descriptor")
        digest = descriptor.get("digest")
        if not isinstance(digest, str) or not SHA256.fullmatch(digest):
            raise ValidationError("release index contains an invalid descriptor digest")
        platform = descriptor.get("platform") or {}
        os_name = platform.get("os")
        architecture = platform.get("architecture")
        annotations = descriptor.get("annotations") or {}
        if (os_name, architecture) in {("linux", "amd64"), ("linux", "arm64")}:
            key = f"{os_name}/{architecture}"
            if key in runnable:
                raise ValidationError(f"release index contains duplicate {key} manifests")
            if digest in runnable.values():
                raise ValidationError("runnable architectures must have distinct manifest digests")
            runnable[key] = digest
            continue
        if (os_name, architecture) == ("unknown", "unknown"):
            if annotations.get("vnd.docker.reference.type") != "attestation-manifest":
                raise ValidationError("unknown/unknown descriptor is not an attestation manifest")
            subject = annotations.get("vnd.docker.reference.digest")
            if not isinstance(subject, str) or not SHA256.fullmatch(subject):
                raise ValidationError("attestation descriptor has no valid subject digest")
            if subject in attestations:
                raise ValidationError("release index contains duplicate attestations for one subject")
            attestations[subject] = digest
            continue
        raise ValidationError(f"unexpected runnable platform {os_name}/{architecture}")

    expected_platforms = {"linux/amd64", "linux/arm64"}
    if set(runnable) != expected_platforms:
        raise ValidationError(
            f"release index platforms are {sorted(runnable)}, expected {sorted(expected_platforms)}"
        )
    if len(set(runnable.values())) != len(runnable):
        raise ValidationError("runnable architectures must have distinct manifest digests")
    if set(attestations) != set(runnable.values()):
        raise ValidationError("every runnable manifest must have exactly one bound attestation manifest")

    for platform, digest in runnable.items():
        architecture = platform.split("/", 1)[1]
        manifest_path = children_dir / architecture / "manifest.json"
        _verify_digest(manifest_path, digest, f"{platform} child manifest")
        child = _load(manifest_path)
        config_digest = (child.get("config") or {}).get("digest")
        if not isinstance(config_digest, str) or not SHA256.fullmatch(config_digest):
            raise ValidationError(f"{platform} child manifest has an invalid config digest")
        config_path = children_dir / architecture / "config.json"
        _verify_digest(config_path, config_digest, f"{platform} config")
        config = _load(config_path)
        if config.get("os") != "linux" or config.get("architecture") != architecture:
            raise ValidationError(f"{platform} config declares a different platform")

    for subject, digest in attestations.items():
        path = attestations_dir / f"{digest.removeprefix('sha256:')}.json"
        _verify_digest(path, digest, f"attestation {digest}")
        attestation = _load(path)
        layers = attestation.get("layers")
        if not isinstance(layers, list):
            raise ValidationError(f"attestation {digest} has no layer list")
        predicates = []
        for layer in layers:
            if not isinstance(layer, dict) or layer.get("mediaType") != ATTESTATION_MEDIA_TYPE:
                raise ValidationError(f"attestation {digest} contains a non-in-toto layer")
            layer_digest = layer.get("digest")
            if not isinstance(layer_digest, str) or not SHA256.fullmatch(layer_digest):
                raise ValidationError(f"attestation {digest} contains an invalid layer digest")
            predicate = (layer.get("annotations") or {}).get("in-toto.io/predicate-type")
            if not isinstance(predicate, str) or not predicate:
                raise ValidationError(f"attestation {digest} contains an untyped in-toto layer")
            predicate_path = predicates_dir / f"{layer_digest.removeprefix('sha256:')}.json"
            _verify_digest(predicate_path, layer_digest, f"predicate {layer_digest}")
            statement = _load(predicate_path)
            if statement.get("_type") != "https://in-toto.io/Statement/v1":
                raise ValidationError(f"predicate {layer_digest} is not an in-toto v1 statement")
            if statement.get("predicateType") != predicate:
                raise ValidationError(f"predicate {layer_digest} type does not match its descriptor")
            if not _subject_matches(statement, subject):
                raise ValidationError(f"predicate {layer_digest} is not bound to {subject}")
            predicate_body = statement.get("predicate")
            if not isinstance(predicate_body, dict) or not predicate_body:
                raise ValidationError(f"predicate {layer_digest} has no evidence body")
            if predicate == "https://spdx.dev/Document" and not str(
                predicate_body.get("spdxVersion", "")
            ).startswith("SPDX-"):
                raise ValidationError(f"predicate {layer_digest} is not an SPDX document")
            if predicate == "https://cyclonedx.org/bom" and not predicate_body.get("specVersion"):
                raise ValidationError(f"predicate {layer_digest} is not a CycloneDX document")
            predicates.append((predicate, statement))
        provenance = [item for item in predicates if item[0].startswith(PROVENANCE_PREFIX)]
        sboms = [item for item in predicates if item[0] in SBOM_PREDICATES]
        if len(provenance) != 1:
            raise ValidationError(
                f"attestation for {subject} must contain exactly one SLSA provenance predicate"
            )
        if len(sboms) != 1:
            raise ValidationError(
                f"attestation for {subject} must contain exactly one SPDX or CycloneDX SBOM predicate"
            )
        if not _provenance_matches_source(provenance[0][1], expected_source_commit):
            raise ValidationError(
                f"attestation for {subject} does not bind both BuildKit source fields to {expected_source_commit}"
            )

    now = datetime.datetime.now(datetime.timezone.utc)
    for platform, digest in runnable.items():
        architecture = platform.split("/", 1)[1]
        root = vulnerability_dir / architecture
        disposition_path = root / "disposition.json"
        disposition = _load(disposition_path)
        expected = {
            "architecture": architecture,
            "image_digest": digest,
            "source_commit": expected_source_commit,
            "status": "pass",
        }
        if any(disposition.get(key) != value for key, value in expected.items()):
            raise ValidationError(f"{platform} vulnerability disposition identity is invalid")
        scanned_at = _parse_timestamp(
            disposition.get("scanned_at"), f"{platform} vulnerability scan"
        )
        age = now - scanned_at
        if age < datetime.timedelta(minutes=-5) or age > MAX_VULNERABILITY_EVIDENCE_AGE:
            raise ValidationError(f"{platform} vulnerability evidence is stale")
        for name in ("report.json", "scanner-version.json", "db-metadata.json"):
            expected_hash = disposition.get("evidence", {}).get(name)
            if not re.fullmatch(r"[0-9a-f]{64}", str(expected_hash or "")):
                raise ValidationError(f"{platform} vulnerability evidence hash is invalid")
            if not (root / name).is_file():
                raise ValidationError(f"{platform} vulnerability evidence is missing")
            if _sha256(root / name) != expected_hash:
                raise ValidationError(f"{platform} vulnerability evidence was tampered")
        report = _load(root / "report.json")
        scanner = _load(root / "scanner-version.json")
        if scanner.get("Version") != EXPECTED_TRIVY_VERSION:
            raise ValidationError(f"{platform} vulnerability scanner identity is unapproved")
        db = _load(root / "db-metadata.json")
        if db.get("Version") != 2:
            raise ValidationError(f"{platform} vulnerability database identity is unapproved")
        db_updated = _parse_timestamp(db.get("UpdatedAt"), f"{platform} vulnerability database")
        db_age = now - db_updated
        if db_age < datetime.timedelta(minutes=-5) or db_age > MAX_VULNERABILITY_EVIDENCE_AGE:
            raise ValidationError(f"{platform} vulnerability database is stale")
        if report.get("SchemaVersion") != 2 or report.get("ArtifactType") != "container_image":
            raise ValidationError(f"{platform} vulnerability report schema is invalid")
        repo_digests = (report.get("Metadata") or {}).get("RepoDigests") or []
        if not any(str(item).endswith(f"@{digest}") for item in repo_digests):
            raise ValidationError(f"{platform} vulnerability report is not bound to {digest}")
        image_config = (report.get("Metadata") or {}).get("ImageConfig") or {}
        if image_config.get("architecture") != architecture or image_config.get("os") != "linux":
            raise ValidationError(f"{platform} vulnerability report platform is invalid")
        results = report.get("Results")
        if not isinstance(results, list) or not results or any(
            not isinstance(result, dict) or not result.get("Target") for result in results
        ):
            raise ValidationError(f"{platform} vulnerability report results are vacuous")
        vulnerabilities = [
            vulnerability
            for result in results
            for vulnerability in (result.get("Vulnerabilities") or [])
            if str(vulnerability.get("Severity", "")).upper() in {"HIGH", "CRITICAL"}
        ]
        if vulnerabilities:
            raise ValidationError(f"{platform} vulnerability disposition has HIGH/CRITICAL findings")


def _sha256(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def write_receipt_manifest(
    destination: pathlib.Path,
    *,
    index_path: pathlib.Path,
    attestations_dir: pathlib.Path,
    predicates_dir: pathlib.Path,
    children_dir: pathlib.Path,
    vulnerability_dir: pathlib.Path,
    image_repository: str,
    index_digest: str,
    source_repository: str,
    source_commit: str,
    workflow: str,
    source_ref: str,
    run_id: str,
    run_attempt: str,
) -> None:
    verifier = pathlib.Path(__file__).resolve()
    evidence_paths = [index_path]
    evidence_paths.extend(sorted(attestations_dir.glob("*.json")))
    evidence_paths.extend(sorted(predicates_dir.glob("*.json")))
    evidence_paths.extend(sorted(children_dir.glob("*/*.json")))
    evidence_paths.extend(sorted(vulnerability_dir.glob("*/*.json")))
    evidence = [
        {"name": path.relative_to(index_path.parent).as_posix(), "sha256": _sha256(path)}
        for path in evidence_paths
    ]
    manifest = {
        "schema_version": "1.0",
        "image_repository": image_repository,
        "index_digest": index_digest,
        "source_repository": source_repository,
        "source_commit": source_commit,
        "workflow": workflow,
        "source_ref": source_ref,
        "run_id": run_id,
        "run_attempt": run_attempt,
        "verifier": {"path": verifier.name, "sha256": _sha256(verifier)},
        "evidence": evidence,
    }
    destination.write_text(
        json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--index", required=True, type=pathlib.Path)
    parser.add_argument("--expected-index-digest", required=True)
    parser.add_argument("--children-dir", required=True, type=pathlib.Path)
    parser.add_argument("--attestations-dir", required=True, type=pathlib.Path)
    parser.add_argument("--predicates-dir", required=True, type=pathlib.Path)
    parser.add_argument("--expected-source-commit", required=True)
    parser.add_argument("--vulnerability-dir", required=True, type=pathlib.Path)
    parser.add_argument("--receipt-manifest", type=pathlib.Path)
    parser.add_argument("--image-repository")
    parser.add_argument("--index-digest")
    parser.add_argument("--source-repository")
    parser.add_argument("--workflow")
    parser.add_argument("--source-ref")
    parser.add_argument("--run-id")
    parser.add_argument("--run-attempt")
    args = parser.parse_args()
    if not re.fullmatch(r"[0-9a-f]{40}", args.expected_source_commit):
        parser.error("--expected-source-commit must be a full lowercase 40-character Git SHA")
    try:
        validate(
            _load(args.index),
            args.index,
            args.expected_index_digest,
            args.children_dir,
            args.attestations_dir,
            args.predicates_dir,
            args.expected_source_commit,
            args.vulnerability_dir,
        )
        if args.receipt_manifest:
            metadata = {
                "image_repository": args.image_repository,
                "index_digest": args.index_digest,
                "source_repository": args.source_repository,
                "workflow": args.workflow,
                "source_ref": args.source_ref,
                "run_id": args.run_id,
                "run_attempt": args.run_attempt,
            }
            missing = sorted(name for name, value in metadata.items() if not value)
            if missing:
                raise ValidationError(
                    "receipt manifest metadata is missing: " + ", ".join(missing)
                )
            if not SHA256.fullmatch(args.index_digest):
                raise ValidationError("receipt index digest is invalid")
            write_receipt_manifest(
                args.receipt_manifest,
                index_path=args.index,
                attestations_dir=args.attestations_dir,
                predicates_dir=args.predicates_dir,
                children_dir=args.children_dir,
                vulnerability_dir=args.vulnerability_dir,
                image_repository=args.image_repository,
                index_digest=args.index_digest,
                source_repository=args.source_repository,
                source_commit=args.expected_source_commit,
                workflow=args.workflow,
                source_ref=args.source_ref,
                run_id=args.run_id,
                run_attempt=args.run_attempt,
            )
    except ValidationError as exc:
        print(f"image attestation verification failed: {exc}", file=sys.stderr)
        return 1
    print("image attestation verification passed: linux/amd64 + linux/arm64, SLSA + SBOM")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
