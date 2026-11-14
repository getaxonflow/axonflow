#!/usr/bin/env python3

from __future__ import annotations

import argparse
import base64
import hashlib
import importlib.util
import json
import pathlib
import py_compile
import re
import shutil
import shlex
import subprocess
import tempfile
import unittest
from unittest import mock

import ci_down_admission as admission


NOW = "2026-11-10T08:00:00Z"
COMMIT = "1" * 40
TREE = "2" * 40
KMS_ARNS = {
    role: f"arn:aws:kms:eu-west-1:123456789012:key/12345678-1234-1234-1234-{index:012d}"
    for index, role in enumerate(admission.SIGNING_ROLES, 1)
}


class CiDownAdmissionTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temp.name)
        self.private_keys: dict[str, pathlib.Path] = {}
        self.public_keys: dict[str, pathlib.Path] = {}
        self.fingerprints: dict[str, str] = {}
        for role in admission.SIGNING_ROLES:
            private = self.root / f"{role}-key.pem"
            public = self.root / f"{role}-public.pem"
            subprocess.run(
                [
                    "openssl",
                    "ecparam",
                    "-name",
                    "prime256v1",
                    "-genkey",
                    "-noout",
                    "-out",
                    str(private),
                ],
                check=True,
                capture_output=True,
            )
            subprocess.run(
                [
                    "openssl",
                    "pkey",
                    "-in",
                    str(private),
                    "-pubout",
                    "-out",
                    str(public),
                ],
                check=True,
                capture_output=True,
            )
            self.private_keys[role] = private
            self.public_keys[role] = public
            self.fingerprints[role] = admission._public_key_fingerprint(public)
        self.authorities = {
            role: (
                {
                    "kms_key_arn": KMS_ARNS[role],
                    "kms_public_key_path": self.public_keys[role].name,
                    "kms_public_key_sha256": self.fingerprints[role],
                },
                self.public_keys[role],
            )
            for role in admission.SIGNING_ROLES
        }
        self.trust_policy = self._write(
            "trust-policy.json",
            {
                "amd64_builder_id": "codebuild-amd64",
                "arm64_builder_id": "codebuild-arm64",
                "cohort_store_uri": "s3://ci-down-evidence/ci-down-state",
                "coordinator_builder_id": "codebuild-coordinator",
                "enabled": True,
                "promoter_builder_id": "codebuild-promoter",
                "schema_version": admission.SCHEMA_VERSION,
                "signing_authorities": {
                    role: authority for role, (authority, _) in self.authorities.items()
                },
                "trust_mode": admission.TRUST_MODE,
            },
        )
        generator_path = pathlib.Path(admission.__file__).with_name(
            "release-build-plan.py"
        )
        spec = importlib.util.spec_from_file_location(
            "release_build_plan_test", generator_path
        )
        assert spec is not None and spec.loader is not None
        generator = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(generator)
        self.plan = {
            "architectures": ["amd64", "arm64"],
            "build_date": NOW,
            "edition": "enterprise",
            "generator": {
                "path": ".github/scripts/release-build-plan.py",
                "sha256": hashlib.sha256(
                    pathlib.Path(admission.__file__)
                    .with_name("release-build-plan.py")
                    .read_bytes()
                ).hexdigest(),
            },
            "images": [
                {key: value for key, value in image.items() if key != "enterprise_only"}
                for image in generator.IMAGES
            ],
            "platform_version": "11.5.0",
            "schema_version": admission.BUILD_PLAN_SCHEMA_VERSION,
            "short_sha": COMMIT[:7],
            "source_commit": COMMIT,
            "source_date_epoch": 1794297600,
            "source_tree": TREE,
        }
        self.plan_path = self._write("plan.json", self.plan)
        self.plan_sha256 = hashlib.sha256(self.plan_path.read_bytes()).hexdigest()
        self.ledger = {
            "admission_nonce": "4" * 64,
            "build_cohort": "5" * 64,
            "build_plan_sha256": self.plan_sha256,
            "created_at": "2026-11-10T07:30:00Z",
            "coordinator": {
                "id": "codebuild-coordinator",
                "provider": "aws-codebuild",
            },
            "dirty_source": False,
            "expires_at": "2026-11-10T20:00:00Z",
            "jobs": admission._expected_jobs(
                self.plan,
                {"amd64": "codebuild-amd64", "arm64": "codebuild-arm64"},
                "codebuild-promoter",
            ),
            "schema_version": admission.SCHEMA_VERSION,
            "source_commit": COMMIT,
            "source_ref": "refs/heads/main",
            "source_repository": "getaxonflow/axonflow-enterprise",
            "source_tree": TREE,
            "trust_mode": admission.TRUST_MODE,
        }
        self.ledger_path = self._write("ledger.json", self.ledger)
        self.ledger_signature = self._sign(self.ledger_path, "coordinator")
        self.consumed = self._write(
            "consumed.json",
            {
                "build_cohorts": [],
                "generation": 0,
                "schema_version": admission.SCHEMA_VERSION,
                "trust_mode": admission.TRUST_MODE,
                "version_id": "version-0",
            },
        )
        self.consumed_signature = self._sign(self.consumed, "promoter")
        self.oci_index = self._write(
            "index.json",
            {
                "manifests": [
                    {
                        "digest": "sha256:" + "6" * 64,
                        "mediaType": "application/vnd.oci.image.manifest.v1+json",
                        "platform": {"architecture": "amd64", "os": "linux"},
                    },
                    {
                        "digest": "sha256:" + "7" * 64,
                        "mediaType": "application/vnd.oci.image.manifest.v1+json",
                        "platform": {"architecture": "arm64", "os": "linux"},
                    },
                ],
                "mediaType": "application/vnd.oci.image.index.v1+json",
                "schemaVersion": 2,
            },
        )
        self.index_digest = (
            f"sha256:{hashlib.sha256(self.oci_index.read_bytes()).hexdigest()}"
        )
        self.index_seal = self._write(
            "index-seal.json",
            {
                "build_cohort": self.ledger["build_cohort"],
                "build_plan_sha256": self.plan_sha256,
                "builder": {
                    "id": "codebuild-promoter",
                    "provider": "aws-codebuild",
                },
                "child_digests": {
                    "amd64": "sha256:" + "6" * 64,
                    "arm64": "sha256:" + "7" * 64,
                },
                "created_at": "2026-11-10T07:42:00Z",
                "image": "agent",
                "image_repository": "example.invalid/axonflow-agent",
                "index_digest": self.index_digest,
                "job_id": "seal-index:agent",
                "ledger_sha256": hashlib.sha256(
                    self.ledger_path.read_bytes()
                ).hexdigest(),
                "schema_version": admission.SCHEMA_VERSION,
                "trust_mode": admission.TRUST_MODE,
            },
        )
        self.index_seal_signature = self._sign(self.index_seal, "promoter")
        self.index_seal_sha256 = hashlib.sha256(
            self.index_seal.read_bytes()
        ).hexdigest()
        self.cohort_claim = self._write(
            "cohort-claim.json",
            {
                "build_cohort": self.ledger["build_cohort"],
                "created_at": "2026-11-10T07:55:00Z",
                "generation": 1,
                "image": "agent",
                "image_repository": "example.invalid/axonflow-agent",
                "index_digest": self.index_digest,
                "prior_generation": 0,
                "prior_version_id": "version-0",
                "schema_version": admission.SCHEMA_VERSION,
                "state": "reserved",
                "store_uri": "s3://ci-down-evidence/ci-down-state/consumed/"
                + self.ledger["build_cohort"]
                + "/agent.json",
                "trust_mode": admission.TRUST_MODE,
                "version_id": "version-1",
            },
        )
        self.cohort_claim_signature = self._sign(self.cohort_claim, "promoter")
        self.receipts = {}
        self.signatures = {}
        for architecture, digit in (("amd64", "6"), ("arm64", "7")):
            path = self.root / architecture / "receipt.json"
            path.parent.mkdir()
            receipt = self._receipt(architecture, "sha256:" + digit * 64)
            self._write_evidence(path.parent, receipt)
            self._write_path(path, receipt)
            self.receipts[architecture] = path
            self.signatures[architecture] = self._sign(path, architecture)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _write(self, name: str, value: object) -> pathlib.Path:
        path = self.root / name
        self._write_path(path, value)
        return path

    def _write_path(self, path: pathlib.Path, value: object) -> None:
        path.write_bytes(admission.canonical(value))

    def _sign(self, path: pathlib.Path, role: str) -> pathlib.Path:
        return self._sign_with(
            path,
            self.private_keys[role],
            self.public_keys[role],
            KMS_ARNS[role],
        )

    def _sign_with(
        self,
        path: pathlib.Path,
        private_key: pathlib.Path,
        public_key: pathlib.Path,
        key_arn: str,
    ) -> pathlib.Path:
        signature = path.with_suffix(path.suffix + ".der")
        subprocess.run(
            [
                "openssl",
                "dgst",
                "-sha256",
                "-sign",
                str(private_key),
                "-out",
                str(signature),
                str(path),
            ],
            check=True,
            capture_output=True,
        )
        envelope = {
            "kms_key_arn": key_arn,
            "kms_public_key_sha256": admission._public_key_fingerprint(public_key),
            "payload_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "schema_version": admission.SCHEMA_VERSION,
            "signature_base64": base64.b64encode(signature.read_bytes()).decode(),
            "signing_algorithm": "ECDSA_SHA_256",
            "trust_mode": admission.TRUST_MODE,
        }
        envelope_path = path.with_suffix(path.suffix + ".signature.json")
        self._write_path(envelope_path, envelope)
        return envelope_path

    def _receipt(self, architecture: str, child_digest: str) -> dict:
        return {
            "architecture": architecture,
            "build_cohort": self.ledger["build_cohort"],
            "build_plan_sha256": self.plan_sha256,
            "builder": {
                "host_architecture": architecture,
                "id": f"codebuild-{architecture}",
                "native": True,
                "provider": "aws-codebuild",
            },
            "child_digest": child_digest,
            "created_at": "2026-11-10T07:45:00Z",
            "dirty_source": False,
            "evidence": [],
            "image": "agent",
            "image_repository": "example.invalid/axonflow-agent",
            "index_digest": self.index_digest,
            "index_seal_sha256": self.index_seal_sha256,
            "job_id": f"sign-receipt:agent:{architecture}",
            "ledger_sha256": hashlib.sha256(self.ledger_path.read_bytes()).hexdigest(),
            "receipt_id": ("8" if architecture == "amd64" else "9") * 64,
            "schema_version": admission.SCHEMA_VERSION,
            "source_commit": COMMIT,
            "source_ref": "refs/heads/main",
            "source_repository": "getaxonflow/axonflow-enterprise",
            "source_tree": TREE,
            "trust_mode": admission.TRUST_MODE,
        }

    def _write_evidence(self, root: pathlib.Path, receipt: dict) -> None:
        child = receipt["child_digest"]
        arch = receipt["architecture"]
        bodies = {
            "provenance": {
                "architecture": arch,
                "build_cohort": self.ledger["build_cohort"],
                "child_digest": child,
                "predicate_type": "https://slsa.dev/provenance/v1",
                "source_commit": COMMIT,
                "source_tree": TREE,
            },
            "sbom": {
                "architecture": arch,
                "child_digest": child,
                "predicate_type": "https://spdx.dev/Document",
                "spdx_version": "SPDX-2.3",
            },
            "trivy-report": {
                "architecture": arch,
                "child_digest": child,
                "critical": 0,
                "high": 0,
                "status": "clean",
            },
            "trivy-version": "Version: 0.70.0\n",
            "trivy-db": {"updated_at": "2026-11-10T07:00:00Z"},
            "quarantine-disposition": {
                "architecture": arch,
                "critical": 0,
                "high": 0,
                "image_digest": child,
                "status": "admitted",
            },
        }
        for evidence_type, body in bodies.items():
            path = root / f"{evidence_type}.json"
            if isinstance(body, str):
                path.write_text(body, encoding="utf-8")
            else:
                path.write_bytes(admission.canonical(body))
            item = {
                "created_at": "2026-11-10T07:35:00Z",
                "path": path.name,
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                "type": evidence_type,
            }
            if evidence_type == "trivy-version":
                item["version"] = "0.70.0"
            if evidence_type == "trivy-db":
                item["db_updated_at"] = "2026-11-10T07:00:00Z"
            receipt["evidence"].append(item)

    def _args(self) -> argparse.Namespace:
        return argparse.Namespace(
            build_plan=self.plan_path,
            ledger=self.ledger_path,
            ledger_signature=self.ledger_signature,
            index_seal=self.index_seal,
            index_seal_signature=self.index_seal_signature,
            amd64_receipt=self.receipts["amd64"],
            amd64_signature=self.signatures["amd64"],
            arm64_receipt=self.receipts["arm64"],
            arm64_signature=self.signatures["arm64"],
            trust_policy=self.trust_policy,
            source_repository="getaxonflow/axonflow-enterprise",
            source_ref="refs/heads/main",
            source_commit=COMMIT,
            source_tree=TREE,
            image="agent",
            image_repository="example.invalid/axonflow-agent",
            index_digest=self.index_digest,
            oci_index=self.oci_index,
            consumed_cohorts=self.consumed,
            consumed_cohorts_signature=self.consumed_signature,
            cohort_claim=self.cohort_claim,
            cohort_claim_signature=self.cohort_claim_signature,
            now=NOW,
        )

    def _verified_admission(self) -> admission.VerifiedAdmission:
        claim_bytes = self.cohort_claim.read_bytes()
        claim = json.loads(claim_bytes)
        return admission.VerifiedAdmission(
            build_cohort=self.ledger["build_cohort"],
            image="agent",
            claim_bytes=claim_bytes,
            store_uri=claim["store_uri"],
        )

    def _resign_receipt(self, architecture: str, receipt: dict) -> None:
        self._write_path(self.receipts[architecture], receipt)
        self.signatures[architecture] = self._sign(
            self.receipts[architecture], architecture
        )

    def _resign_index_seal(self, seal: dict) -> None:
        self._write_path(self.index_seal, seal)
        self.index_seal_signature = self._sign(self.index_seal, "promoter")
        self.index_seal_sha256 = hashlib.sha256(
            self.index_seal.read_bytes()
        ).hexdigest()

    def _resign_ledger_and_dependents(self, ledger: dict) -> None:
        self._write_path(self.ledger_path, ledger)
        self.ledger_signature = self._sign(self.ledger_path, "coordinator")
        ledger_sha256 = hashlib.sha256(self.ledger_path.read_bytes()).hexdigest()
        seal = json.loads(self.index_seal.read_text())
        seal["ledger_sha256"] = ledger_sha256
        self._resign_index_seal(seal)
        for architecture in admission.ARCHITECTURES:
            receipt = json.loads(self.receipts[architecture].read_text())
            receipt["ledger_sha256"] = ledger_sha256
            receipt["index_seal_sha256"] = self.index_seal_sha256
            self._resign_receipt(architecture, receipt)

    def _replace_index(self, index: dict) -> argparse.Namespace:
        self._write_path(self.oci_index, index)
        digest = f"sha256:{hashlib.sha256(self.oci_index.read_bytes()).hexdigest()}"
        seal = json.loads(self.index_seal.read_text())
        seal["index_digest"] = digest
        seal["child_digests"] = {
            descriptor["platform"]["architecture"]: descriptor["digest"]
            for descriptor in index["manifests"]
            if descriptor.get("platform", {}).get("os") == "linux"
            and descriptor.get("platform", {}).get("architecture")
            in admission.ARCHITECTURES
        }
        self._resign_index_seal(seal)
        for architecture in ("amd64", "arm64"):
            receipt = json.loads(self.receipts[architecture].read_text())
            receipt["index_digest"] = digest
            receipt["index_seal_sha256"] = self.index_seal_sha256
            self._resign_receipt(architecture, receipt)
        args = self._args()
        args.index_digest = digest
        return args

    def test_valid_exact_native_cohort(self) -> None:
        admission.verify(self._args())

    def test_rejects_policy_and_key_swap_after_snapshot_before_verification(self) -> None:
        snapshot = admission.load_trust_snapshot(
            self.trust_policy,
            release_build_plan_bytes=pathlib.Path(__file__)
            .with_name("release-build-plan.py")
            .read_bytes(),
        )
        for index, source in enumerate(snapshot.sources):
            replacement = source.path.with_name(f"attacker-trust-source-{index}")
            replacement.write_bytes(b"attacker replacement\n")
            replacement.replace(source.path)
        with self.assertRaisesRegex(
            admission.AdmissionError, "trust source changed after snapshot"
        ):
            admission.verify(self._args(), trust_snapshot=snapshot)

    def test_rejects_common_evidence_swap_between_image_verifications(self) -> None:
        inputs = admission.ImmutableInputStore()
        admission.verify(self._args(), input_store=inputs)

        replacement = self.ledger_path.with_name("attacker-ledger.json")
        replacement.write_bytes(self.ledger_path.read_bytes())
        replacement.replace(self.ledger_path)

        with self.assertRaisesRegex(
            admission.AdmissionError, "evidence changed after snapshot"
        ):
            admission.verify(self._args(), input_store=inputs)

    def test_rejects_dirty_source(self) -> None:
        receipt = json.loads(self.receipts["amd64"].read_text())
        receipt["dirty_source"] = True
        self._resign_receipt("amd64", receipt)
        with self.assertRaisesRegex(admission.AdmissionError, "identity"):
            admission.verify(self._args())

    def test_rejects_attacker_key_substitution(self) -> None:
        attacker_private = self.root / "attacker-key.pem"
        attacker_public = self.root / "attacker-public.pem"
        subprocess.run(
            [
                "openssl",
                "ecparam",
                "-name",
                "prime256v1",
                "-genkey",
                "-noout",
                "-out",
                str(attacker_private),
            ],
            check=True,
            capture_output=True,
        )
        subprocess.run(
            [
                "openssl",
                "pkey",
                "-in",
                str(attacker_private),
                "-pubout",
                "-out",
                str(attacker_public),
            ],
            check=True,
            capture_output=True,
        )
        self.ledger_signature = self._sign_with(
            self.ledger_path,
            attacker_private,
            attacker_public,
            "arn:aws:kms:eu-west-1:123456789012:key/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        )
        with self.assertRaisesRegex(admission.AdmissionError, "pinned KMS authority"):
            admission.verify(self._args())

    def test_rejects_promoter_key_signing_amd64_receipt(self) -> None:
        self.signatures["amd64"] = self._sign(self.receipts["amd64"], "promoter")
        with self.assertRaisesRegex(admission.AdmissionError, "pinned KMS authority"):
            admission.verify(self._args())

    def test_rejects_amd64_key_signing_arm64_receipt(self) -> None:
        self.signatures["arm64"] = self._sign(self.receipts["arm64"], "amd64")
        with self.assertRaisesRegex(admission.AdmissionError, "pinned KMS authority"):
            admission.verify(self._args())

    def test_rejects_coordinator_key_signing_promoter_claim(self) -> None:
        self.cohort_claim_signature = self._sign(self.cohort_claim, "coordinator")
        with self.assertRaisesRegex(admission.AdmissionError, "pinned KMS authority"):
            admission.verify(self._args())

    def test_rejects_shared_signing_authority(self) -> None:
        policy = json.loads(self.trust_policy.read_text())
        policy["signing_authorities"]["coordinator"] = policy["signing_authorities"][
            "amd64"
        ]
        self._write_path(self.trust_policy, policy)
        with self.assertRaisesRegex(admission.AdmissionError, "must use distinct"):
            admission.verify(self._args())

    def test_rejects_pinned_fingerprint_substitution(self) -> None:
        policy = json.loads(self.trust_policy.read_text())
        policy["signing_authorities"]["promoter"]["kms_public_key_sha256"] = "a" * 64
        self._write_path(self.trust_policy, policy)
        with self.assertRaisesRegex(admission.AdmissionError, "fingerprint"):
            admission.verify(self._args())

    def test_rejects_schema_downgrade(self) -> None:
        policy = json.loads(self.trust_policy.read_text())
        policy["schema_version"] = "1.0"
        self._write_path(self.trust_policy, policy)
        with self.assertRaisesRegex(admission.AdmissionError, "schema/identity"):
            admission.verify(self._args())

    def test_rejects_unknown_index_seal_shape(self) -> None:
        seal = json.loads(self.index_seal.read_text())
        seal["unreviewed_extension"] = True
        self._resign_index_seal(seal)
        with self.assertRaisesRegex(admission.AdmissionError, "schema is not exact"):
            admission.verify(self._args())

    def test_rejects_receipt_created_before_index_seal(self) -> None:
        receipt = json.loads(self.receipts["amd64"].read_text())
        receipt["created_at"] = "2026-11-10T07:41:59Z"
        self._resign_receipt("amd64", receipt)
        with self.assertRaisesRegex(admission.AdmissionError, "ordering"):
            admission.verify(self._args())

    def test_rejects_child_evidence_created_after_index_seal(self) -> None:
        receipt = json.loads(self.receipts["arm64"].read_text())
        receipt["evidence"][0]["created_at"] = "2026-11-10T07:42:01Z"
        self._resign_receipt("arm64", receipt)
        with self.assertRaisesRegex(admission.AdmissionError, "ordering"):
            admission.verify(self._args())

    def test_rejects_receipt_for_different_index_seal(self) -> None:
        receipt = json.loads(self.receipts["amd64"].read_text())
        receipt["index_seal_sha256"] = "a" * 64
        self._resign_receipt("amd64", receipt)
        with self.assertRaisesRegex(admission.AdmissionError, "identity"):
            admission.verify(self._args())

    def test_rejects_sealed_mixed_child_cohort(self) -> None:
        seal = json.loads(self.index_seal.read_text())
        seal["child_digests"]["arm64"] = "sha256:" + "a" * 64
        self._resign_index_seal(seal)
        for architecture in admission.ARCHITECTURES:
            receipt = json.loads(self.receipts[architecture].read_text())
            receipt["index_seal_sha256"] = self.index_seal_sha256
            self._resign_receipt(architecture, receipt)
        with self.assertRaisesRegex(
            admission.AdmissionError, "does not match the index"
        ):
            admission.verify(self._args())

    def test_rejects_missing_post_index_receipt_phase(self) -> None:
        ledger = json.loads(self.ledger_path.read_text())
        ledger["jobs"] = [
            job for job in ledger["jobs"] if job["job_id"] != "sign-receipt:agent:amd64"
        ]
        self._resign_ledger_and_dependents(ledger)
        with self.assertRaisesRegex(
            admission.AdmissionError, "exact release job matrix"
        ):
            admission.verify(self._args())

    def test_rejects_duplicate_post_index_receipt_phase(self) -> None:
        ledger = json.loads(self.ledger_path.read_text())
        job = next(
            value
            for value in ledger["jobs"]
            if value["job_id"] == "sign-receipt:agent:arm64"
        )
        ledger["jobs"].append(job)
        self._resign_ledger_and_dependents(ledger)
        with self.assertRaisesRegex(
            admission.AdmissionError, "exact release job matrix"
        ):
            admission.verify(self._args())

    def test_repo_trust_policy_is_enabled_and_self_consistent(self) -> None:
        policy_path = (
            pathlib.Path(admission.__file__).resolve().parent.parent
            / "release"
            / "ci-down-trust-policy.json"
        )
        snapshot = admission.load_trust_snapshot(policy_path)
        self.assertIs(snapshot.policy["enabled"], True)
        self.assertEqual(set(snapshot.authorities), set(admission.SIGNING_ROLES))
        self.assertEqual(len(snapshot.sources), 6)

    def test_rejects_non_monotonic_cohort_reservation(self) -> None:
        claim = json.loads(self.cohort_claim.read_text())
        claim["generation"] = 2
        self._write_path(self.cohort_claim, claim)
        self.cohort_claim_signature = self._sign(self.cohort_claim, "promoter")
        with self.assertRaisesRegex(admission.AdmissionError, "atomic monotonic claim"):
            admission.verify(self._args())

    def test_rejects_mixed_build_cohort(self) -> None:
        receipt = json.loads(self.receipts["arm64"].read_text())
        receipt["build_cohort"] = "a" * 64
        self._resign_receipt("arm64", receipt)
        with self.assertRaisesRegex(admission.AdmissionError, "cohort"):
            admission.verify(self._args())

    def test_rejects_unsigned_build_plan_context_mutation(self) -> None:
        plan = json.loads(self.plan_path.read_text())
        plan["images"][0]["context"] = "./attacker"
        self._write_path(self.plan_path, plan)
        with self.assertRaisesRegex(admission.AdmissionError, "image matrix differs"):
            admission.verify(self._args())

    def test_rejects_wrong_build_plan_tree(self) -> None:
        plan = json.loads(self.plan_path.read_text())
        plan["source_tree"] = "a" * 40
        self._write_path(self.plan_path, plan)
        with self.assertRaisesRegex(admission.AdmissionError, "source identity"):
            admission.verify(self._args())

    def test_rejects_wrong_build_plan_edition(self) -> None:
        plan = json.loads(self.plan_path.read_text())
        plan["edition"] = "community"
        self._write_path(self.plan_path, plan)
        with self.assertRaisesRegex(admission.AdmissionError, "architecture/edition"):
            admission.verify(self._args())

    def test_signed_ledger_and_receipts_bind_build_plan_sha256(self) -> None:
        plan = json.loads(self.plan_path.read_text())
        plan["platform_version"] = "11.5.1"
        self._write_path(self.plan_path, plan)
        with self.assertRaisesRegex(admission.AdmissionError, "source identity"):
            admission.verify(self._args())

    def test_rejects_oci_index_child_mismatch(self) -> None:
        index = json.loads(self.oci_index.read_text())
        index["manifests"][0]["digest"] = "sha256:" + "a" * 64
        with self.assertRaisesRegex(
            admission.AdmissionError, "does not match the OCI index"
        ):
            admission.verify(self._replace_index(index))

    def test_rejects_oci_index_raw_digest_mismatch(self) -> None:
        with self.oci_index.open("ab") as output:
            output.write(b" ")
        with self.assertRaisesRegex(admission.AdmissionError, "bytes do not match"):
            admission.verify(self._args())

    def test_rejects_oci_index_missing_architecture(self) -> None:
        index = json.loads(self.oci_index.read_text())
        index["manifests"] = index["manifests"][:1]
        with self.assertRaisesRegex(
            admission.AdmissionError, "child cohort is invalid"
        ):
            admission.verify(self._replace_index(index))

    def test_rejects_oci_index_duplicate_architecture(self) -> None:
        index = json.loads(self.oci_index.read_text())
        index["manifests"][1]["platform"]["architecture"] = "amd64"
        with self.assertRaisesRegex(
            admission.AdmissionError, "child cohort is invalid"
        ):
            admission.verify(self._replace_index(index))

    def test_rejects_oci_index_extra_platform(self) -> None:
        index = json.loads(self.oci_index.read_text())
        index["manifests"].append(
            {
                "digest": "sha256:" + "a" * 64,
                "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "platform": {"architecture": "s390x", "os": "linux"},
            }
        )
        with self.assertRaisesRegex(
            admission.AdmissionError, "unexpected platform linux/s390x"
        ):
            admission.verify(self._replace_index(index))

    def test_rejects_replayed_cohort(self) -> None:
        consumed = self._write(
            "consumed-replay.json",
            {
                "build_cohorts": [self.ledger["build_cohort"]],
                "generation": 1,
                "schema_version": admission.SCHEMA_VERSION,
                "trust_mode": admission.TRUST_MODE,
                "version_id": "version-1",
            },
        )
        args = self._args()
        args.consumed_cohorts = consumed
        args.consumed_cohorts_signature = self._sign(consumed, "promoter")
        with self.assertRaisesRegex(admission.AdmissionError, "already consumed"):
            admission.verify(args)

    def test_rejects_stale_trivy_database(self) -> None:
        receipt = json.loads(self.receipts["amd64"].read_text())
        next(item for item in receipt["evidence"] if item["type"] == "trivy-db")[
            "db_updated_at"
        ] = "2026-11-08T07:00:00Z"
        self._resign_receipt("amd64", receipt)
        with self.assertRaisesRegex(admission.AdmissionError, "Trivy DB is stale"):
            admission.verify(self._args())

    def test_rejects_non_native_builder(self) -> None:
        receipt = json.loads(self.receipts["arm64"].read_text())
        receipt["builder"]["native"] = False
        self._resign_receipt("arm64", receipt)
        with self.assertRaisesRegex(
            admission.AdmissionError, "not from the pinned native builder"
        ):
            admission.verify(self._args())

    def test_rejects_unlisted_builder_identity(self) -> None:
        receipt = json.loads(self.receipts["amd64"].read_text())
        receipt["builder"]["id"] = "codebuild-attacker"
        self._resign_receipt("amd64", receipt)
        with self.assertRaisesRegex(
            admission.AdmissionError, "not from the pinned native builder"
        ):
            admission.verify(self._args())

    def test_rejects_bad_quarantine_disposition(self) -> None:
        receipt = json.loads(self.receipts["amd64"].read_text())
        item = next(
            value
            for value in receipt["evidence"]
            if value["type"] == "quarantine-disposition"
        )
        path = self.receipts["amd64"].parent / item["path"]
        body = json.loads(path.read_text())
        body["high"] = 1
        path.write_bytes(admission.canonical(body))
        item["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
        self._resign_receipt("amd64", receipt)
        with self.assertRaisesRegex(admission.AdmissionError, "did not admit"):
            admission.verify(self._args())

    def test_promoter_exposes_no_caller_selectable_kms_trust_root(self) -> None:
        script = pathlib.Path(__file__).with_name("promote-verified-image.py")
        help_text = subprocess.check_output(
            ["python3", "-I", str(script), "--help"], text=True
        )
        self.assertNotIn("--kms-key-arn", help_text)
        self.assertNotIn("--kms-public-key", help_text)
        source = script.read_text(encoding="utf-8")
        self.assertIn('"ci-down-trust-policy.json"', source)
        self.assertLess(
            source.index("_consume_ci_down_claim_once(ci_down_consumption)"),
            source.index("def publish_one(tag: str)"),
        )
        workflow_root = pathlib.Path(__file__).resolve().parents[1] / "workflows"
        self.assertIn(
            "python3 -I .github/scripts/promote-verified-image.py",
            (workflow_root / "build.yml").read_text(encoding="utf-8"),
        )
        self.assertIn(
            "resolver_args=(python3 -I .github/scripts/resolve-trusted-image.py",
            (workflow_root / "update-stack.yml").read_text(encoding="utf-8"),
        )

    def test_promoter_ignores_actual_unchecked_hash_verifier_pyc(self) -> None:
        root = self.root / "isolated-promoter"
        root.mkdir()
        source_script = pathlib.Path(__file__).with_name("promote-verified-image.py")
        script = root / source_script.name
        shutil.copyfile(source_script, script)
        verifier = root / "ci_down_admission.py"
        verifier.write_text("MARKER = 'attacker-pyc'\n", encoding="utf-8")
        pyc = pathlib.Path(
            py_compile.compile(
                str(verifier),
                invalidation_mode=py_compile.PycInvalidationMode.UNCHECKED_HASH,
            )
        )
        self.assertTrue(pyc.name.startswith("ci_down_admission.cpython-"))
        verifier.write_text("MARKER = 'reviewed-source'\n", encoding="utf-8")

        spec = importlib.util.spec_from_file_location("isolated_promoter", script)
        assert spec is not None and spec.loader is not None
        promoter = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(promoter)

        self.assertEqual(promoter.ci_down_admission.MARKER, "reviewed-source")

    def test_standalone_admission_exposes_no_caller_selected_policy(self) -> None:
        help_text = subprocess.check_output(
            ["python3", admission.__file__, "--help"], text=True
        )
        self.assertNotIn("--trust-policy", help_text)

    def test_promoter_atomically_consumes_identical_claim_only_once(self) -> None:
        script = pathlib.Path(__file__).with_name("promote-verified-image.py")
        spec = importlib.util.spec_from_file_location("ci_down_promoter", script)
        assert spec is not None and spec.loader is not None
        promoter = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(promoter)
        calls = {"put": 0}

        def fake_run(command: list[str], **_: object) -> subprocess.CompletedProcess:
            if "put-object" in command:
                calls["put"] += 1
                if calls["put"] > 1:
                    return subprocess.CompletedProcess(
                        command, 1, "", "PreconditionFailed"
                    )
                return subprocess.CompletedProcess(
                    command, 0, '{"ETag":"etag-1","VersionId":"s3-version-1"}', ""
                )
            destination = pathlib.Path(command[-3])
            destination.write_bytes(self.cohort_claim.read_bytes())
            return subprocess.CompletedProcess(
                command,
                0,
                '{"ETag":"etag-1","VersionId":"s3-version-1"}',
                "",
            )

        verified = self._verified_admission()
        with mock.patch.object(promoter.subprocess, "run", side_effect=fake_run):
            promoter._consume_ci_down_claim_once(verified)
            with self.assertRaisesRegex(promoter.AdmissionError, "already consumed"):
                promoter._consume_ci_down_claim_once(verified)

    def test_promoter_consumes_verified_claim_bytes_after_path_swap(self) -> None:
        script = pathlib.Path(__file__).with_name("promote-verified-image.py")
        spec = importlib.util.spec_from_file_location(
            "ci_down_promoter_verified_context", script
        )
        assert spec is not None and spec.loader is not None
        promoter = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(promoter)
        verified = self._verified_admission()
        self.cohort_claim.write_bytes(
            admission.canonical({"store_uri": "s3://attacker/unsigned"})
        )
        uploaded: list[bytes] = []

        def fake_run(command: list[str], **_: object) -> subprocess.CompletedProcess:
            if "put-object" in command:
                body = pathlib.Path(command[command.index("--body") + 1])
                uploaded.append(body.read_bytes())
                return subprocess.CompletedProcess(
                    command, 0, '{"ETag":"etag-1","VersionId":"s3-version-1"}', ""
                )
            pathlib.Path(command[-3]).write_bytes(uploaded[0])
            return subprocess.CompletedProcess(
                command,
                0,
                '{"ETag":"etag-1","VersionId":"s3-version-1"}',
                "",
            )

        with mock.patch.object(promoter.subprocess, "run", side_effect=fake_run):
            promoter._consume_ci_down_claim_once(verified)

        self.assertEqual(uploaded, [verified.claim_bytes])

    def test_promoter_rejects_failed_atomic_readback(self) -> None:
        script = pathlib.Path(__file__).with_name("promote-verified-image.py")
        spec = importlib.util.spec_from_file_location(
            "ci_down_promoter_readback", script
        )
        assert spec is not None and spec.loader is not None
        promoter = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(promoter)

        def fake_run(command: list[str], **_: object) -> subprocess.CompletedProcess:
            if "put-object" in command:
                return subprocess.CompletedProcess(
                    command, 0, '{"ETag":"etag-1","VersionId":"s3-version-1"}', ""
                )
            pathlib.Path(command[-3]).write_bytes(b"not-the-signed-claim\n")
            return subprocess.CompletedProcess(
                command,
                0,
                '{"ETag":"etag-1","VersionId":"s3-version-1"}',
                "",
            )

        with mock.patch.object(promoter.subprocess, "run", side_effect=fake_run):
            with self.assertRaisesRegex(promoter.AdmissionError, "read back exactly"):
                promoter._consume_ci_down_claim_once(self._verified_admission())

    def test_promoter_rejects_null_or_missing_s3_version_evidence(self) -> None:
        script = pathlib.Path(__file__).with_name("promote-verified-image.py")
        spec = importlib.util.spec_from_file_location(
            "ci_down_promoter_null_version", script
        )
        assert spec is not None and spec.loader is not None
        promoter = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(promoter)
        for version in (None, "", "null", " Null ", "NONE", " \t "):
            with self.subTest(version=version):
                response = {"ETag": "etag-1"}
                if version is not None:
                    response["VersionId"] = version
                put = subprocess.CompletedProcess(
                    ["aws", "s3api", "put-object"],
                    0,
                    json.dumps(response),
                    "",
                )
                with mock.patch.object(promoter.subprocess, "run", return_value=put):
                    with self.assertRaisesRegex(
                        promoter.AdmissionError, "versioned evidence"
                    ):
                        promoter._consume_ci_down_claim_once(
                            self._verified_admission()
                        )

    def test_resolver_rejects_retained_oci_index_mismatch(self) -> None:
        script = pathlib.Path(__file__).with_name("resolve-trusted-image.py")
        spec = importlib.util.spec_from_file_location("ci_down_resolver", script)
        assert spec is not None and spec.loader is not None
        resolver = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(resolver)
        args = argparse.Namespace(
            admission_registry="example.invalid",
            repository="axonflow-agent",
            evidence_dir=self.root / "resolver-evidence",
            trust_mode=admission.TRUST_MODE,
            source_tree=TREE,
            image="agent",
            build_plan=self.plan_path,
            canonical_job_ledger=self.ledger_path,
            canonical_job_ledger_signature=self.ledger_signature,
            index_seal=self.index_seal,
            index_seal_signature=self.index_seal_signature,
            amd64_build_receipt=self.receipts["amd64"],
            amd64_build_signature=self.signatures["amd64"],
            arm64_build_receipt=self.receipts["arm64"],
            arm64_build_signature=self.signatures["arm64"],
            consumed_cohorts=self.consumed,
            consumed_cohorts_signature=self.consumed_signature,
            cohort_claim=self.cohort_claim,
            cohort_claim_signature=self.cohort_claim_signature,
            expected_oci_index=self.oci_index,
        )
        with mock.patch.object(
            resolver.subprocess, "check_output", return_value=b"different-index"
        ):
            with self.assertRaisesRegex(ValueError, "differs from registry bytes"):
                resolver._admit(args, self.index_digest)

    def test_update_stack_wires_explicit_ci_down_evidence(self) -> None:
        workflow = (
            pathlib.Path(__file__).resolve().parent.parent
            / "workflows"
            / "update-stack.yml"
        ).read_text(encoding="utf-8")
        self.assertIn("default: github-actions-v1", workflow)
        self.assertIn("IMAGE_TRUST_MODE: ${{ inputs.image_trust_mode }}", workflow)
        for argument in (
            "--build-plan",
            "--canonical-job-ledger",
            "--index-seal",
            "--amd64-build-receipt",
            "--arm64-build-receipt",
            "--consumed-cohorts",
            "--cohort-claim",
            "--expected-oci-index",
        ):
            self.assertIn(argument, workflow)
        for native_path in (
            "coordinator/build-plan.json",
            "amd64/receipt.json",
            "arm64/receipt.json",
            "index/index-seal.json",
            "index/consumed-cohorts.json",
            "index/cohort-claim.json",
            "index/oci-index.json",
        ):
            self.assertIn(native_path, workflow)
        for flattened_path in (
            '"$image_evidence/amd64-receipt.json"',
            '"$image_evidence/arm64-receipt.json"',
            '"$image_evidence/index-seal.json"',
            '"$image_evidence/cohort-claim.json"',
        ):
            self.assertNotIn(flattened_path, workflow)
        self.assertIn("CI_DOWN_TRUST_POLICY_SHA256", workflow)
        self.assertNotIn("--trust-mode github-actions-v1 \\", workflow)
        names_match = re.search(r"names=\(([^)]*)\)", workflow)
        images_match = re.search(r"canonical_images=\(([^)]*)\)", workflow)
        self.assertIsNotNone(names_match)
        self.assertIsNotNone(images_match)
        output_names = shlex.split(names_match.group(1))
        mapped_images = shlex.split(images_match.group(1))
        self.assertEqual(
            list(zip(output_names, mapped_images, strict=True)),
            [
                ("performance_testing", "performance-testing"),
                ("agent", "agent"),
                ("orchestrator", "orchestrator"),
                ("customer_portal", "customer-portal"),
                ("customer_portal_ui", "customer-portal-ui"),
                ("case_workflows", "case-workflows"),
                ("prometheus", "prometheus"),
                ("grafana", "grafana"),
            ],
        )
        authoritative_images = [
            image["name"]
            for image in self.plan["images"]
            if image["name"] != "gateway-adapters"
        ]
        self.assertEqual(set(mapped_images), set(authoritative_images))
        self.assertIn('--image "$canonical_image"', workflow)
        self.assertIn(
            'image_evidence="$CI_DOWN_IMAGES_EVIDENCE_DIR/$canonical_image"',
            workflow,
        )


class ReleaseBuildPlanTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self.temp.name)
        subprocess.run(["git", "init", "-q", str(self.root)], check=True)
        subprocess.run(
            ["git", "-C", str(self.root), "config", "user.name", "Test"], check=True
        )
        subprocess.run(
            [
                "git",
                "-C",
                str(self.root),
                "config",
                "user.email",
                "test@example.invalid",
            ],
            check=True,
        )
        (self.root / "VERSION").write_text("11.5.0\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(self.root), "add", "VERSION"], check=True)
        subprocess.run(
            ["git", "-C", str(self.root), "commit", "-q", "-m", "fixture"], check=True
        )
        generator_path = pathlib.Path(admission.__file__).with_name(
            "release-build-plan.py"
        )
        spec = importlib.util.spec_from_file_location(
            "release_build_plan_unit", generator_path
        )
        assert spec is not None and spec.loader is not None
        self.generator = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.generator)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_clean_exact_enterprise_matrix(self) -> None:
        plan = self.generator.build_plan(self.root, "enterprise", None)
        self.assertEqual(len(plan["images"]), 9)
        self.assertEqual(plan["architectures"], ["amd64", "arm64"])
        self.assertEqual(
            plan["source_tree"],
            subprocess.check_output(
                ["git", "-C", str(self.root), "rev-parse", "HEAD^{tree}"], text=True
            ).strip(),
        )

    def test_rejects_dirty_source(self) -> None:
        (self.root / "VERSION").write_text("11.5.1\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "source is dirty"):
            self.generator.build_plan(self.root, "enterprise", None)

    def test_rejects_wrong_edition(self) -> None:
        with self.assertRaisesRegex(ValueError, "edition"):
            self.generator.build_plan(self.root, "attacker", None)

    def test_rejects_matrix_drift(self) -> None:
        with self.assertRaisesRegex(ValueError, "unknown release image"):
            self.generator.build_plan(self.root, "enterprise", {"attacker-image"})


if __name__ == "__main__":
    unittest.main()
