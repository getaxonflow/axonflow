#!/usr/bin/env python3

from __future__ import annotations

import base64
import copy
import contextlib
import hashlib
import importlib.util
import io
import json
import pathlib
import re
import subprocess
import sys
import tempfile
import unittest
from argparse import Namespace
from unittest import mock

import yaml


ROOT = pathlib.Path(__file__).resolve().parents[2]
TEMPLATE = ROOT / "infrastructure/cloudformation/ci-down-release-builders.yaml"
PACKET = ROOT / "infrastructure/ci-down-release/deployment-packet.us-east-1.json"
TRUST_POLICY = ROOT / ".github/release/ci-down-trust-policy.json"


class CfnLoader(yaml.SafeLoader):
    pass


def _tag(loader: CfnLoader, suffix: str, node: yaml.Node) -> object:
    if isinstance(node, yaml.ScalarNode):
        value = loader.construct_scalar(node)
    elif isinstance(node, yaml.SequenceNode):
        value = loader.construct_sequence(node)
    else:
        value = loader.construct_mapping(node)
    return {f"Fn::{suffix}": value}


CfnLoader.add_multi_constructor("!", _tag)


def load_template() -> dict:
    return yaml.load(TEMPLATE.read_text(encoding="utf-8"), Loader=CfnLoader)


def load_packet() -> dict:
    raw = PACKET.read_bytes()
    packet = json.loads(raw)
    canonical = (json.dumps(packet, sort_keys=True, separators=(",", ":")) + "\n").encode()
    if raw != canonical:
        raise AssertionError("deployment packet is not canonical JSON")
    return packet


def expected_trust_policy() -> dict:
    return {
        "amd64_builder_id": (
            "arn:aws:codebuild:us-east-1:686831565523:project/"
            "axonflow-v115-ci-down-amd64"
        ),
        "arm64_builder_id": (
            "arn:aws:codebuild:us-east-1:686831565523:project/"
            "axonflow-v115-ci-down-arm64"
        ),
        "cohort_store_uri": (
            "s3://axonflow-v115-ci-down-evidence-686831565523-us-east-1/state"
        ),
        "coordinator_builder_id": (
            "arn:aws:codebuild:us-east-1:686831565523:project/"
            "axonflow-v115-ci-down-coordinator"
        ),
        "enabled": True,
        "promoter_builder_id": (
            "arn:aws:codebuild:us-east-1:686831565523:project/"
            "axonflow-v115-ci-down-promoter"
        ),
        "schema_version": "1.1",
        "signing_authorities": {
            "amd64": {
                "kms_key_arn": (
                    "arn:aws:kms:us-east-1:686831565523:key/"
                    "8785a8fd-9a51-4d29-a7dd-10c5602c9b2c"
                ),
                "kms_public_key_path": "ci-down-public-keys/amd64.der",
                "kms_public_key_sha256": (
                    "f034e4ae3876cc7874d949459fa3f83bd1670967dfcdb49d49a77e08528c86c9"
                ),
            },
            "arm64": {
                "kms_key_arn": (
                    "arn:aws:kms:us-east-1:686831565523:key/"
                    "41db1b6b-cb2d-4d46-a7bd-f472a1265d44"
                ),
                "kms_public_key_path": "ci-down-public-keys/arm64.der",
                "kms_public_key_sha256": (
                    "2be955d7df67116812a32218e0dce419e4bd7235a9a95ef9a0b9e89c2aa0f384"
                ),
            },
            "coordinator": {
                "kms_key_arn": (
                    "arn:aws:kms:us-east-1:686831565523:key/"
                    "39099711-3ad0-4c18-99d0-c40b8e45e775"
                ),
                "kms_public_key_path": "ci-down-public-keys/coordinator.der",
                "kms_public_key_sha256": (
                    "5a1ac477e1bf4baf74c0f10f1ea77445f807c9f3795dc14ca91be2858baddbeb"
                ),
            },
            "promoter": {
                "kms_key_arn": (
                    "arn:aws:kms:us-east-1:686831565523:key/"
                    "2136125f-cc1d-4031-a854-ea2524b0cd8e"
                ),
                "kms_public_key_path": "ci-down-public-keys/promoter.der",
                "kms_public_key_sha256": (
                    "b40632566106705fe8e1404ae34b2fa0d6e6b6a024fdb8d1ab4d47c13f0c8bf5"
                ),
            },
        },
        "trust_mode": "aws-kms-ci-down-v1",
    }


def load_trust_policy() -> dict:
    raw = TRUST_POLICY.read_bytes()
    policy = json.loads(raw)
    canonical = (
        json.dumps(policy, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode()
    if raw != canonical:
        raise AssertionError("CI-down trust policy is not canonical JSON")
    return policy


def validate_trust_keys(policy: dict) -> None:
    policy_root = TRUST_POLICY.parent.resolve()
    authorities = policy["signing_authorities"]
    arns = {authority["kms_key_arn"] for authority in authorities.values()}
    paths = {authority["kms_public_key_path"] for authority in authorities.values()}
    fingerprints = {
        authority["kms_public_key_sha256"] for authority in authorities.values()
    }
    if len(arns) != 4 or len(paths) != 4 or len(fingerprints) != 4:
        raise AssertionError("CI-down signing authorities are not four distinct bindings")
    for role, authority in authorities.items():
        key_path = TRUST_POLICY.parent / authority["kms_public_key_path"]
        if key_path.is_symlink():
            raise AssertionError(f"{role} public key must not be a symlink")
        try:
            key_path.resolve().relative_to(policy_root)
        except ValueError as exc:
            raise AssertionError(f"{role} public key escapes the trust root") from exc
        raw = key_path.read_bytes()
        if hashlib.sha256(raw).hexdigest() != authority["kms_public_key_sha256"]:
            raise AssertionError(
                f"{role} public-key bytes do not match the trust pin"
            )
        normalized = subprocess.run(
            [
                "openssl",
                "pkey",
                "-pubin",
                "-inform",
                "DER",
                "-in",
                str(key_path),
                "-outform",
                "DER",
            ],
            check=True,
            capture_output=True,
        ).stdout
        if normalized != raw:
            raise AssertionError(f"{role} public key is not canonical DER")


def load_provider():
    scripts = ROOT / ".github/scripts"
    if str(scripts) not in sys.path:
        sys.path.insert(0, str(scripts))
    path = scripts / "ci_down_provider.py"
    spec = importlib.util.spec_from_file_location("ci_down_provider_under_test", path)
    assert spec and spec.loader
    provider = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(provider)
    return provider


def statements(role: dict) -> list[dict]:
    return [
        statement
        for policy in role["Properties"]["Policies"]
        for statement in policy["PolicyDocument"]["Statement"]
    ]


def actions(statement: dict) -> set[str]:
    value = statement["Action"]
    return {value} if isinstance(value, str) else set(value)


def resource_set(statement: dict) -> set[str]:
    value = statement["Resource"]
    resources = value if isinstance(value, list) else [value]
    return {json.dumps(resource, sort_keys=True) for resource in resources}


def sub_resource(path: str) -> str:
    return json.dumps({"Fn::Sub": path}, sort_keys=True)


def nested_keys(value: object) -> set[str]:
    if isinstance(value, dict):
        return set(value).union(
            *(nested_keys(item) for item in value.values()), set()
        )
    if isinstance(value, list):
        return set().union(*(nested_keys(item) for item in value), set())
    return set()


def validate_native_scanner_platform(script: str) -> None:
    platform = '"linux/${EXPECTED_ARCHITECTURE}"'
    trivy = script.find(
        '"$TRIVY_IMAGE" image \\\n    --image-src remote --platform ' + platform
    )
    syft = script.find(
        '"$SYFT_IMAGE" \\\n    "registry:${repository}@${child_digest}" --platform '
        + platform
    )
    syft_auth = all(
        token in script
        for token in (
            'export SYFT_REGISTRY_AUTH_AUTHORITY="$registry"',
            "export SYFT_REGISTRY_AUTH_USERNAME=AWS",
            'SYFT_REGISTRY_AUTH_PASSWORD="$(aws ecr get-login-password)"',
            "-e SYFT_REGISTRY_AUTH_AUTHORITY -e SYFT_REGISTRY_AUTH_USERNAME",
            '-e SYFT_REGISTRY_AUTH_PASSWORD "$SYFT_IMAGE"',
            "unset SYFT_REGISTRY_AUTH_AUTHORITY SYFT_REGISTRY_AUTH_USERNAME SYFT_REGISTRY_AUTH_PASSWORD",
        )
    )
    if trivy < 0 or syft < 0 or not syft_auth:
        raise AssertionError(
            "native scanners do not bind the remote image to the native platform and registry auth"
        )


def validate(
    template: dict, policy: dict | None = None, packet: dict | None = None
) -> None:
    resources = template["Resources"]
    if packet is None:
        packet = load_packet()
    expected_packet = {
        "account_id": "686831565523",
        "connection_name": "axonflow-v115-ci-down-github",
        "evidence_bucket_name": (
            "axonflow-v115-ci-down-evidence-686831565523-us-east-1"
        ),
        "project_prefix": "axonflow-v115-ci-down",
        "region": "us-east-1",
        "required_platforms": ["linux/amd64", "linux/arm64"],
        "schema_version": "1.0",
        "source_location": (
            "https://github.com/getaxonflow/axonflow-enterprise.git"
        ),
        "stack_name": "axonflow-v115-ci-down-release-builders",
        "syft_image": (
            "docker.io/anchore/syft@sha256:"
            "03215d0e98b661d0ecbc8575dbc14d65be1743b5de5df6410aecb7e80f95b060"
        ),
        "syft_release_url": (
            "https://github.com/anchore/syft/releases/tag/v1.57.1"
        ),
        "syft_version": "v1.57.1",
        "trivy_image": (
            "public.ecr.aws/aquasecurity/trivy@sha256:"
            "be1190afcb28352bfddc4ddeb71470835d16462af68d310f9f4bca710961a41e"
        ),
        "trivy_release_url": (
            "https://github.com/aquasecurity/trivy/releases/tag/v0.70.0"
        ),
        "trivy_version": "0.70.0",
    }
    if packet != expected_packet:
        raise AssertionError("deployment packet names or scanner pins drifted")
    parameters = template["Parameters"]
    parameter_pins = {
        "ProjectPrefix": "project_prefix",
        "SourceLocation": "source_location",
        "TrivyImage": "trivy_image",
        "SyftImage": "syft_image",
    }
    for parameter, packet_key in parameter_pins.items():
        value = packet[packet_key]
        if parameters[parameter].get("Default") != value or not re.fullmatch(
            parameters[parameter]["AllowedPattern"], value
        ):
            raise AssertionError(f"{parameter} is not pinned to the deployment packet")
    if any(
        resource.get("Type") == "AWS::CodeConnections::Connection"
        for resource in resources.values()
    ):
        raise AssertionError("the provider stack must not create a GitHub installation")
    role_keys = {
        "CoordinatorRole": "CoordinatorSigningKey",
        "Amd64Role": "Amd64SigningKey",
        "Arm64Role": "Arm64SigningKey",
        "PromoterRole": "PromoterSigningKey",
    }
    key_arns = set()
    forbidden = ("cloudformation:", "ecs:", "secretsmanager:", "ssm:", "iam:PassRole")
    for role_name, key_name in role_keys.items():
        role_statements = statements(resources[role_name])
        signers = [item for item in role_statements if "kms:Sign" in actions(item)]
        if len(signers) != 1:
            raise AssertionError(f"{role_name} does not have one signing grant")
        resource_text = json.dumps(signers[0]["Resource"], sort_keys=True)
        if key_name not in resource_text:
            raise AssertionError(f"{role_name} does not use only {key_name}")
        key_arns.add(resource_text)
        all_actions = {action for item in role_statements for action in actions(item)}
        if any(action.startswith(forbidden) for action in all_actions):
            raise AssertionError(f"{role_name} has deployment or secret authority")
        connection = [
            item
            for item in role_statements
            if "codeconnections:UseConnection" in actions(item)
        ]
        if len(connection) != 1 or "SourceConnectionArn" not in json.dumps(
            connection[0]["Resource"]
        ):
            raise AssertionError(f"{role_name} does not use only the reviewed connection")
        required_connection_actions = {
            "codeconnections:GetConnection",
            "codeconnections:GetConnectionToken",
            "codeconnections:UseConnection",
        }
        if actions(connection[0]) != required_connection_actions:
            raise AssertionError(
                f"{role_name} connection grant does not match the reviewed CodeBuild actions"
            )
        if role_name == "CoordinatorRole" and "codebuild:StartBuild" in all_actions:
            raise AssertionError("coordinator can override a signing project build")
    if len(key_arns) != 4:
        raise AssertionError("signing roles do not use four distinct keys")
    native_evidence = {
        "Amd64Role": ("Amd64", "amd64"),
        "Arm64Role": ("Arm64", "arm64"),
    }
    read_actions = {"s3:GetObject", "s3:GetObjectVersion"}
    write_actions = read_actions | {"s3:PutObject"}
    for role_name, (label, architecture) in native_evidence.items():
        role_statements = statements(resources[role_name])
        by_sid = {item["Sid"]: item for item in role_statements}
        read = by_sid.get("ReadCoordinatorAndIndexEvidence")
        write = by_sid.get(f"ReadAndWrite{label}Evidence")
        expected_read = {
            sub_resource("${EvidenceBucket.Arn}/cohorts/*/coordinator/*"),
            sub_resource("${EvidenceBucket.Arn}/cohorts/*/images/*/index/*"),
        }
        expected_write = {
            sub_resource(
                f"${{EvidenceBucket.Arn}}/cohorts/*/images/*/{architecture}/*"
            )
        }
        if (
            read is None
            or actions(read) != read_actions
            or resource_set(read) != expected_read
            or write is None
            or actions(write) != write_actions
            or resource_set(write) != expected_write
            or sum("s3:PutObject" in actions(item) for item in role_statements) != 1
        ):
            raise AssertionError(
                f"{role_name} evidence reads and writes are not architecture-scoped"
            )
    promoter_statements = statements(resources["PromoterRole"])
    promoter_by_sid = {item["Sid"]: item for item in promoter_statements}
    promoter_read = promoter_by_sid.get("ReadAllCohortEvidence")
    promoter_write = promoter_by_sid.get("ReadAndWritePromoterArtifacts")
    if (
        promoter_read is None
        or actions(promoter_read) != read_actions
        or resource_set(promoter_read)
        != {sub_resource("${EvidenceBucket.Arn}/cohorts/*")}
        or promoter_write is None
        or actions(promoter_write) != write_actions
        or resource_set(promoter_write)
        != {
            sub_resource("${EvidenceBucket.Arn}/cohorts/*/images/*/index/*"),
            sub_resource("${EvidenceBucket.Arn}/state/*"),
        }
        or sum(
            "s3:PutObject" in actions(item) for item in promoter_statements
        )
        != 1
    ):
        raise AssertionError(
            "PromoterRole evidence writes are not limited to index and state artifacts"
        )
    for key_name in role_keys.values():
        properties = resources[key_name]["Properties"]
        if properties.get("KeySpec") != "ECC_NIST_P256" or properties.get("KeyUsage") != "SIGN_VERIFY":
            raise AssertionError(f"{key_name} is not an asymmetric signing key")
    if resources["EvidenceEncryptionKey"]["Properties"].get("KeyUsage") == "SIGN_VERIFY":
        raise AssertionError("evidence encryption key is incorrectly a signing key")
    bucket = resources["EvidenceBucket"]["Properties"]
    if bucket["VersioningConfiguration"]["Status"] != "Enabled" or not all(bucket["PublicAccessBlockConfiguration"].values()):
        raise AssertionError("evidence bucket is not versioned and public-blocked")
    repositories = {
        "axonflow-agent",
        "axonflow-orchestrator",
        "axonflow-customer-portal",
        "axonflow-customer-portal-ui",
        "axonflow-prometheus",
        "axonflow-grafana",
        "axonflow-performance-testing",
        "axonflow-gateway-adapters",
        "axonflow-case-workflows",
    }
    native_registry_actions = {
        "ecr:BatchCheckLayerAvailability",
        "ecr:BatchGetImage",
        "ecr:CompleteLayerUpload",
        "ecr:DescribeImages",
        "ecr:GetDownloadUrlForLayer",
        "ecr:InitiateLayerUpload",
        "ecr:PutImage",
        "ecr:UploadLayerPart",
    }
    promoter_registry_actions = {
        "ecr:BatchCheckLayerAvailability",
        "ecr:BatchDeleteImage",
        "ecr:BatchGetImage",
        "ecr:DescribeImages",
        "ecr:DescribeRepositories",
        "ecr:GetDownloadUrlForLayer",
        "ecr:PutImage",
    }
    for role_name in ("Amd64Role", "Arm64Role", "PromoterRole"):
        grants = [
            item
            for item in statements(resources[role_name])
            if any(action.startswith("ecr:") and action != "ecr:GetAuthorizationToken" for action in actions(item))
        ]
        if len(grants) != 1:
            raise AssertionError(f"{role_name} does not have one repository grant")
        expected_registry_actions = (
            promoter_registry_actions
            if role_name == "PromoterRole"
            else native_registry_actions
        )
        if actions(grants[0]) != expected_registry_actions:
            raise AssertionError(
                f"{role_name} registry action set does not match its reviewed duties"
            )
        resource_text = json.dumps(grants[0]["Resource"], sort_keys=True)
        if "repository/*" in resource_text or any(
            f"repository/{name}" not in resource_text for name in repositories
        ):
            raise AssertionError(f"{role_name} repository authority is not the canonical nine")
    projects = {
        "CoordinatorProject": (
            "LINUX_CONTAINER",
            "aws/codebuild/standard:7.0-26.10.28",
        ),
        "Amd64Project": ("LINUX_CONTAINER", "aws/codebuild/standard:7.0-26.10.28"),
        "Arm64Project": (
            "ARM_CONTAINER",
            "aws/codebuild/amazonlinux-aarch64-standard:3.0-26.10.30",
        ),
        "PromoterProject": (
            "LINUX_CONTAINER",
            "aws/codebuild/standard:7.0-26.10.28",
        ),
    }
    for name, (environment_type, image) in projects.items():
        environment = resources[name]["Properties"]["Environment"]
        if environment["Type"] != environment_type or environment["Image"] != image:
            raise AssertionError(f"{name} is not pinned to its reviewed native image")
    coordinator_authorization = [
        variable
        for variable in resources["CoordinatorProject"]["Properties"]["Environment"][
            "EnvironmentVariables"
        ]
        if variable["Name"] == "CI_DOWN_RELEASE_AUTHORIZED"
    ]
    if coordinator_authorization != [
        {
            "Name": "CI_DOWN_RELEASE_AUTHORIZED",
            "Type": "PLAINTEXT",
            "Value": "true",
        }
    ]:
        raise AssertionError("coordinator authorization is not exactly enabled")
    orchestrator_actions = {
        action
        for item in statements(resources["ReleaseOrchestratorRole"])
        for action in actions(item)
    }
    if not {
        "codebuild:BatchGetBuilds",
        "codebuild:StartBuild",
        "codebuild:StopBuild",
    }.issubset(orchestrator_actions) or any(
        action.startswith(("kms:", "ecr:", "s3:", "codeconnections:"))
        for action in orchestrator_actions
    ):
        raise AssertionError("fixed orchestrator authority is not non-signing and exact")
    definition = resources["ReleaseOrchestrator"]["Properties"]["Definition"]
    definition_text = json.dumps(definition, sort_keys=True)
    override_keys = {key for key in nested_keys(definition) if key.endswith("Override")}
    if (
        definition["TimeoutSeconds"] > 23 * 60 * 60
        or definition["States"]["BuildImages"]["MaxConcurrency"] != 3
        or
        definition_text.count("arn:aws:states:::codebuild:startBuild.sync") != 6
        or override_keys != {"EnvironmentVariablesOverride"}
        or not all(
            phase in definition_text
            for phase in (
                "child-build",
                "index-seal",
                "post-index-receipt",
                "promotion",
            )
        )
    ):
        raise AssertionError("fixed orchestration graph can drift or override buildspecs")
    if policy is None:
        policy = load_trust_policy()
    if policy != expected_trust_policy():
        raise AssertionError("CI-down trust policy does not match the reviewed live bindings")
    validate_trust_keys(policy)
    required = {
        "buildspec-coordinator.yml": ("ledger", "ci_down_dispatch.py"),
        "buildspec-native.yml": ("child-build", "post-index-receipt"),
        "buildspec-promoter.yml": ("index-seal", "promotion"),
    }
    for name, tokens in required.items():
        path = ROOT / "infrastructure/ci-down-release" / name
        text = path.read_text()
        buildspec = yaml.safe_load(text)
        if buildspec.get("env", {}).get("shell") != "bash":
            raise AssertionError(f"{name} does not select the required bash shell")
        if "refs/remotes/origin/main" not in text or not all(
            token in text for token in tokens
        ):
            raise AssertionError(f"{name} does not carry the ordered provider phases")
    native_script = (ROOT / "infrastructure/ci-down-release/run-native-phase.sh").read_text()
    validate_native_scanner_platform(native_script)
    validate_native_child_digest_is_the_platform_manifest(native_script)
    promoter = (
        ROOT / "infrastructure/ci-down-release/run-promoter-phase.sh"
    ).read_text()
    reserve = promoter.find("reserve-cohort")
    claim = promoter.find("ci_down_provider.py claim")
    state_upload = promoter.find(
        'upload_file "$state/consumed-cohorts.signature.json"'
    )
    claim_upload = promoter.find(
        'upload_file "$image_root/index/cohort-claim.signature.json"'
    )
    mutation = promoter.find("python3 -I .github/scripts/promote-verified-image.py")
    if (
        reserve < 0
        or state_upload < 0
        or claim < 0
        or claim_upload < 0
        or mutation < 0
        or not reserve < claim < state_upload < claim_upload < mutation
        or "python3 .github/scripts/promote-verified-image.py" in promoter
        or "consumed-next.json" in promoter
        or "consumed-cohorts.signature.json\" \"${COHORT_STORE_URI}" in promoter
    ):
        raise AssertionError(
            "promotion does not retain signed reservation evidence before registry mutation"
        )
    validate_promoter_keeps_sealed_index(promoter)


def validate_native_child_digest_is_the_platform_manifest(native: str) -> None:
    # The native push carries provenance and SBOM attestations, so the digest
    # buildx reports is a per-arch wrapper index. The promoter flattens that
    # wrapper into the sealed release index, which lists the PLATFORM manifest;
    # admission then compares each receipt's child digest with that manifest.
    # The receipt must therefore name the platform manifest selected from the
    # pushed index for exactly this architecture, never the wrapper.
    pushed = native.find('pushed_digest="$(jq -er \'.["containerimage.digest"]\' "$root/build-metadata.json")"')
    select = native.find(
        "'[.manifests[] | select(.platform.os == \"linux\" and .platform.architecture == $arch) | .digest] | select(length == 1) | .[0]'"
    )
    inspect = native.find('docker buildx imagetools inspect "${repository}@${pushed_digest}" --raw')
    recorded = native.find("printf '%s\\n' \"$child_digest\" > \"$root/child-digest.txt\"")
    wrapper_recorded = native.find("printf '%s\\n' \"$pushed_digest\" > \"$root/child-digest.txt\"")
    scan = native.find('"${repository}@${child_digest}"')
    if (
        pushed < 0
        or inspect < 0
        or select < 0
        or recorded < 0
        or wrapper_recorded >= 0
        or not pushed < inspect < select < recorded < scan
        or "--arg arch \"$EXPECTED_ARCHITECTURE\"" not in native
    ):
        raise AssertionError(
            "the native phase must record the platform manifest selected from the pushed index as the child digest"
        )


def validate_promoter_keeps_sealed_index(promoter: str) -> None:
    # ECR deletes an image with its last tag. The index-seal phase gives the
    # sealed multi-arch index exactly one tag (the quarantine tag), so that
    # phase must not delete it; the promotion phase must assert the index still
    # resolves by digest before spending the reservation, and may drop the
    # quarantine tag only after the promoter has written the release tags.
    seal_end = promoter.find("exit 0\nfi\n")
    delete_call = "aws ecr batch-delete-image"
    first_delete = promoter.find(delete_call)
    mutation = promoter.find("python3 -I .github/scripts/promote-verified-image.py")
    precheck = promoter.find(
        'docker buildx imagetools inspect "${repository}@${index_digest}" --raw > /dev/null'
    )
    pre_reserve = promoter.find(
        'docker buildx imagetools inspect "${registry}/axonflow-${image}@${sealed_digest}" --raw > /dev/null'
    )
    reserve = promoter.find("reserve-cohort")
    claim = promoter.find("ci_down_provider.py claim")
    if (
        seal_end < 0
        or first_delete < 0
        or promoter.count(delete_call) != 1
        or first_delete < seal_end
        or first_delete < mutation
        or precheck < 0
        or pre_reserve < 0
        or not pre_reserve < reserve < precheck < claim
        or 'quarantine="quarantine-${BUILD_COHORT:0:16}-${image}"' not in promoter
    ):
        raise AssertionError(
            "the index-seal phase must keep the quarantine tag until promotion has written the release tags"
        )


class ProviderInfrastructureTest(unittest.TestCase):
    def test_template_and_trust_policy_are_exactly_enabled(self) -> None:
        validate(load_template())

    def test_each_native_scanner_requires_the_exact_native_platform(self) -> None:
        script = (
            ROOT / "infrastructure/ci-down-release/run-native-phase.sh"
        ).read_text()
        validate_native_scanner_platform(script)
        mutations = (
            (
                '"$TRIVY_IMAGE" image \\\n    --image-src remote --platform "linux/${EXPECTED_ARCHITECTURE}"',
                '"$TRIVY_IMAGE" image \\\n    --image-src remote --platform "linux/amd64"',
            ),
            (
                '"$SYFT_IMAGE" \\\n    "registry:${repository}@${child_digest}" --platform "linux/${EXPECTED_ARCHITECTURE}"',
                '"$SYFT_IMAGE" \\\n    "registry:${repository}@${child_digest}" --platform "linux/amd64"',
            ),
            (
                "-e SYFT_REGISTRY_AUTH_PASSWORD \"$SYFT_IMAGE\"",
                '"$SYFT_IMAGE"',
            ),
        )
        for original, replacement in mutations:
            with self.subTest(scanner=original.split("_IMAGE")[0]):
                planted = script.replace(original, replacement, 1)
                self.assertNotEqual(planted, script)
                with self.assertRaisesRegex(AssertionError, "native platform"):
                    validate_native_scanner_platform(planted)

    def test_cross_signer_grant_is_rejected(self) -> None:
        planted = copy.deepcopy(load_template())
        for item in statements(planted["Resources"]["Amd64Role"]):
            if "kms:Sign" in actions(item):
                item["Resource"] = {"Fn::GetAtt": "CoordinatorSigningKey.Arn"}
        with self.assertRaisesRegex(AssertionError, "Amd64SigningKey"):
            validate(planted)

    def test_state_machine_buildspec_override_is_rejected(self) -> None:
        planted = copy.deepcopy(load_template())
        planted["Resources"]["ReleaseOrchestrator"]["Properties"]["Definition"][
            "States"
        ]["Promote"]["Parameters"]["BuildspecOverride"] = "unreviewed.yml"
        with self.assertRaisesRegex(AssertionError, "override buildspecs"):
            validate(planted)

    def test_deployment_authority_is_rejected(self) -> None:
        planted = copy.deepcopy(load_template())
        statements(planted["Resources"]["PromoterRole"])[0]["Action"] = "ecs:UpdateService"
        with self.assertRaisesRegex(AssertionError, "deployment or secret"):
            validate(planted)

    def test_non_native_arm_builder_is_rejected(self) -> None:
        planted = copy.deepcopy(load_template())
        planted["Resources"]["Arm64Project"]["Properties"]["Environment"]["Type"] = "LINUX_CONTAINER"
        with self.assertRaisesRegex(AssertionError, "reviewed native image"):
            validate(planted)

    def test_repository_wildcard_is_rejected(self) -> None:
        planted = copy.deepcopy(load_template())
        for item in statements(planted["Resources"]["PromoterRole"]):
            if "ecr:PutImage" in actions(item):
                item["Resource"] = {"Fn::Sub": "arn:${AWS::Partition}:ecr:${AWS::Region}:${AWS::AccountId}:repository/*"}
        with self.assertRaisesRegex(AssertionError, "canonical nine"):
            validate(planted)

    def test_native_recording_the_wrapper_digest_as_the_child_is_rejected(self) -> None:
        script = (
            ROOT / "infrastructure/ci-down-release/run-native-phase.sh"
        ).read_text()
        validate_native_child_digest_is_the_platform_manifest(script)
        select_line = (
            "'[.manifests[] | select(.platform.os == \"linux\" and .platform.architecture == $arch) | .digest] | select(length == 1) | .[0]'"
        )
        mutations = (
            # the wrapper digest written straight into the receipt (the shape of cohorts 0ec9f0b8 and eb32edc5)
            ("printf '%s\\n' \"$child_digest\" > \"$root/child-digest.txt\"",
             "printf '%s\\n' \"$pushed_digest\" > \"$root/child-digest.txt\""),
            # the architecture no longer selected: any linux descriptor would do
            (select_line, "'[.manifests[] | select(.platform.os == \"linux\") | .digest] | .[0]'"),
            # the selection tolerates several matches
            (select_line, "'[.manifests[] | select(.platform.os == \"linux\" and .platform.architecture == $arch) | .digest] | .[0]'"),
        )
        for old, new in mutations:
            self.assertIn(old, script)
            with self.assertRaisesRegex(AssertionError, "platform manifest selected from the pushed index"):
                validate_native_child_digest_is_the_platform_manifest(script.replace(old, new, 1))

    def test_promoter_deleting_the_sealed_index_tag_before_promotion_is_rejected(self) -> None:
        script = (
            ROOT / "infrastructure/ci-down-release/run-promoter-phase.sh"
        ).read_text()
        validate_promoter_keeps_sealed_index(script)
        seal_delete = (
            '  exit 0\nfi\n',
            '  aws ecr batch-delete-image --repository-name "axonflow-${IMAGE_NAME}" '
            '--image-ids "imageTag=${quarantine}" >/dev/null\n  exit 0\nfi\n',
        )
        no_precheck = (
            '  docker buildx imagetools inspect "${repository}@${index_digest}" --raw > /dev/null\n',
            "",
        )
        no_pre_reserve_check = (
            '  docker buildx imagetools inspect "${registry}/axonflow-${image}@${sealed_digest}" --raw > /dev/null\n',
            "",
        )
        delete_before_promote = (
            "  python3 -I .github/scripts/promote-verified-image.py",
            '  aws ecr batch-delete-image --repository-name "axonflow-${image}" '
            '--image-ids "imageTag=quarantine-${BUILD_COHORT:0:16}-${image}" >/dev/null\n'
            "  python3 -I .github/scripts/promote-verified-image.py",
        )
        for old, new in (seal_delete, no_precheck, no_pre_reserve_check, delete_before_promote):
            self.assertIn(old, script)
            with self.assertRaisesRegex(AssertionError, "keep the quarantine tag"):
                validate_promoter_keeps_sealed_index(script.replace(old, new, 1))

    def test_promoter_missing_blob_availability_check_is_rejected(self) -> None:
        planted = copy.deepcopy(load_template())
        for item in statements(planted["Resources"]["PromoterRole"]):
            if item.get("Sid") == "ReadAndPromoteReleaseImages":
                item["Action"].remove("ecr:BatchCheckLayerAvailability")
        with self.assertRaisesRegex(AssertionError, "registry action set"):
            validate(planted)

    def test_promoter_layer_upload_authority_is_rejected(self) -> None:
        planted = copy.deepcopy(load_template())
        for item in statements(planted["Resources"]["PromoterRole"]):
            if item.get("Sid") == "ReadAndPromoteReleaseImages":
                item["Action"].append("ecr:UploadLayerPart")
        with self.assertRaisesRegex(AssertionError, "registry action set"):
            validate(planted)

    def test_coordinator_build_override_authority_is_rejected(self) -> None:
        planted = copy.deepcopy(load_template())
        statements(planted["Resources"]["CoordinatorRole"])[0][
            "Action"
        ] = "codebuild:StartBuild"
        with self.assertRaisesRegex(AssertionError, "override a signing project"):
            validate(planted)

    def test_native_cross_lane_evidence_write_is_rejected(self) -> None:
        planted = copy.deepcopy(load_template())
        for item in statements(planted["Resources"]["Amd64Role"]):
            if item.get("Sid") == "ReadAndWriteAmd64Evidence":
                item["Resource"] = [
                    item["Resource"],
                    {
                        "Fn::Sub": (
                            "${EvidenceBucket.Arn}/cohorts/*/coordinator/*"
                        )
                    },
                ]
        with self.assertRaisesRegex(AssertionError, "architecture-scoped"):
            validate(planted)

    def test_promoter_cross_lane_evidence_write_is_rejected(self) -> None:
        planted = copy.deepcopy(load_template())
        for item in statements(planted["Resources"]["PromoterRole"]):
            if item.get("Sid") == "ReadAndWritePromoterArtifacts":
                item["Resource"].append(
                    {"Fn::Sub": "${EvidenceBucket.Arn}/cohorts/*/coordinator/*"}
                )
        with self.assertRaisesRegex(AssertionError, "index and state"):
            validate(planted)

    def test_disabled_policy_is_rejected(self) -> None:
        planted = copy.deepcopy(expected_trust_policy())
        planted["enabled"] = False
        with self.assertRaisesRegex(AssertionError, "reviewed live bindings"):
            validate(load_template(), planted)

    def test_disabled_coordinator_is_rejected(self) -> None:
        planted = copy.deepcopy(load_template())
        for variable in planted["Resources"]["CoordinatorProject"]["Properties"][
            "Environment"
        ]["EnvironmentVariables"]:
            if variable["Name"] == "CI_DOWN_RELEASE_AUTHORIZED":
                variable["Value"] = "false"
        with self.assertRaisesRegex(AssertionError, "exactly enabled"):
            validate(planted)

    def test_live_trust_binding_drift_is_rejected(self) -> None:
        mutations = (
            (
                "amd64_builder_id",
                "arn:aws:codebuild:us-east-1:686831565523:project/other",
            ),
            (
                "arm64_builder_id",
                "arn:aws:codebuild:us-east-1:686831565523:project/other",
            ),
            (
                "coordinator_builder_id",
                "arn:aws:codebuild:us-east-1:686831565523:project/other",
            ),
            (
                "promoter_builder_id",
                "arn:aws:codebuild:us-east-1:686831565523:project/other",
            ),
            ("cohort_store_uri", "s3://other/state"),
        )
        for field, value in mutations:
            with self.subTest(field=field):
                planted = copy.deepcopy(expected_trust_policy())
                planted[field] = value
                with self.assertRaisesRegex(AssertionError, "reviewed live bindings"):
                    validate(load_template(), planted)
        authority_mutations = (
            ("kms_key_arn", "arn:aws:kms:us-east-1:686831565523:key/other"),
            ("kms_public_key_path", "../other.der"),
            ("kms_public_key_sha256", "0" * 64),
        )
        for role in ("coordinator", "amd64", "arm64", "promoter"):
            for field, value in authority_mutations:
                with self.subTest(role=role, field=field):
                    planted = copy.deepcopy(expected_trust_policy())
                    planted["signing_authorities"][role][field] = value
                    with self.assertRaisesRegex(
                        AssertionError, "reviewed live bindings"
                    ):
                        validate(load_template(), planted)

    def test_duplicate_trust_binding_is_rejected(self) -> None:
        planted = copy.deepcopy(expected_trust_policy())
        planted["signing_authorities"]["promoter"] = copy.deepcopy(
            planted["signing_authorities"]["coordinator"]
        )
        with self.assertRaisesRegex(AssertionError, "four distinct bindings"):
            validate_trust_keys(planted)

    def test_noncanonical_policy_json_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            planted = pathlib.Path(directory) / "policy.json"
            planted.write_text(json.dumps(expected_trust_policy(), indent=2) + "\n")
            with mock.patch.object(sys.modules[__name__], "TRUST_POLICY", planted):
                with self.assertRaisesRegex(AssertionError, "canonical JSON"):
                    load_trust_policy()

    def test_mutable_or_wrong_registry_scanner_pin_is_rejected(self) -> None:
        planted = copy.deepcopy(load_template())
        planted["Parameters"]["SyftImage"]["Default"] = (
            "public.ecr.aws/anchore/syft:latest"
        )
        with self.assertRaisesRegex(AssertionError, "SyftImage"):
            validate(planted)

    def test_deployment_packet_name_drift_is_rejected(self) -> None:
        planted = copy.deepcopy(load_packet())
        planted["evidence_bucket_name"] += "-retry"
        with self.assertRaisesRegex(AssertionError, "packet names"):
            validate(load_template(), packet=planted)

    def test_two_stale_writers_same_generation_only_one_commits(self) -> None:
        provider = load_provider()
        seed = {
            "build_cohorts": [],
            "generation": 0,
            "schema_version": "1.1",
            "trust_mode": "aws-kms-ci-down-v1",
            "version_id": "seed",
        }
        cohort = "a" * 64
        writer_a = provider.transition_consumed(seed, cohort, "writer-a")
        writer_b = provider.transition_consumed(seed, cohort, "writer-b")
        state = {"etag": "etag-0", "payload": seed, "commits": 0}

        def put(expected: str, payload: dict) -> bool:
            if expected != state["etag"]:
                return False
            state.update(
                etag=f"etag-{state['commits'] + 1}",
                payload=payload,
                commits=state["commits"] + 1,
            )
            return True

        self.assertTrue(put("etag-0", writer_a))
        self.assertFalse(put("etag-0", writer_b))
        self.assertEqual(state["commits"], 1)
        self.assertEqual(state["payload"]["generation"], 1)
        self.assertEqual(state["payload"]["build_cohorts"], [cohort])

    def test_atomic_envelope_rejects_crossed_payload_signature_order(self) -> None:
        provider = load_provider()
        seed = {
            "build_cohorts": [],
            "generation": 0,
            "schema_version": "1.1",
            "trust_mode": "aws-kms-ci-down-v1",
            "version_id": "seed",
        }
        first = provider.transition_consumed(seed, "a" * 64, "first")
        second = provider.transition_consumed(seed, "b" * 64, "second")
        signature_for_first = {
            "payload_sha256": __import__("hashlib").sha256(
                provider.canonical(first)
            ).hexdigest()
        }
        provider.signed_consumed_envelope(first, signature_for_first)
        with self.assertRaisesRegex(ValueError, "does not bind"):
            provider.signed_consumed_envelope(second, signature_for_first)

    def test_lost_race_rebases_both_cohorts_or_fails_before_mutation(self) -> None:
        provider = load_provider()
        seed = {
            "build_cohorts": [],
            "generation": 0,
            "schema_version": "1.1",
            "trust_mode": "aws-kms-ci-down-v1",
            "version_id": "seed",
        }
        first_cohort, second_cohort = "a" * 64, "b" * 64
        committed = provider.transition_consumed(seed, first_cohort, "first")
        rebased = provider.transition_consumed(committed, second_cohort, "second")
        self.assertEqual(rebased["generation"], 2)
        self.assertEqual(
            rebased["build_cohorts"], [first_cohort, second_cohort]
        )
        with self.assertRaisesRegex(ValueError, "already consumed"):
            provider.transition_consumed(committed, first_cohort, "retry")
        script = (
            ROOT / "infrastructure/ci-down-release/run-promoter-phase.sh"
        ).read_text()
        self.assertLess(
            script.index("reserve-cohort"),
            script.index("python3 -I .github/scripts/promote-verified-image.py"),
        )
        self.assertNotIn(
            "python3 .github/scripts/promote-verified-image.py", script
        )
        self.assertNotIn("consumed-next.json", script)

    def test_parse_signed_consumed_envelope_verifies_a_real_signature(self) -> None:
        # The reserve step parses the PRIOR consumed-cohorts envelope through
        # this function on every cohort after the first. Every other test
        # mocks it; the first real call (cohort eb32edc5) died with a
        # TypeError because the verifier was handed a path instead of key
        # bytes. This runs the real parser against a locally signed envelope.
        provider = load_provider()
        admission = provider.admission
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            private = root / "key.pem"
            public_pem = root / "public.pem"
            public_der = root / "public.der"
            run = lambda *cmd: subprocess.run(list(cmd), check=True, capture_output=True)
            run("openssl", "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(private))
            run("openssl", "pkey", "-in", str(private), "-pubout", "-out", str(public_pem))
            run("openssl", "pkey", "-in", str(private), "-pubout", "-outform", "DER", "-out", str(public_der))
            der = public_der.read_bytes()
            fingerprint = hashlib.sha256(der).hexdigest()
            key_arn = "arn:aws:kms:us-east-1:000000000000:key/00000000-0000-0000-0000-000000000004"
            seed = {
                "build_cohorts": [],
                "generation": 0,
                "schema_version": "1.1",
                "trust_mode": "aws-kms-ci-down-v1",
                "version_id": "seed",
            }
            payload = provider.transition_consumed(seed, "a" * 64, "first")

            def envelope_for(signed_payload: dict) -> dict:
                body = root / "payload.json"
                body.write_bytes(provider.canonical(signed_payload))
                signature = root / "payload.sig"
                run("openssl", "dgst", "-sha256", "-sign", str(private), "-out", str(signature), str(body))
                return {
                    "kms_key_arn": key_arn,
                    "kms_public_key_sha256": fingerprint,
                    "payload_sha256": hashlib.sha256(body.read_bytes()).hexdigest(),
                    "schema_version": admission.SCHEMA_VERSION,
                    "signature_base64": base64.b64encode(signature.read_bytes()).decode(),
                    "signing_algorithm": "ECDSA_SHA_256",
                    "trust_mode": admission.TRUST_MODE,
                }

            good = provider.canonical(provider.signed_consumed_envelope(payload, envelope_for(payload)))
            with mock.patch.object(provider, "_kms_public_key", return_value=(der, fingerprint)):
                parsed_payload, parsed_signature = provider.parse_signed_consumed_envelope(good, key_arn)
                self.assertEqual(parsed_payload, payload)
                self.assertEqual(parsed_signature["payload_sha256"], hashlib.sha256(provider.canonical(payload)).hexdigest())
                # A signature minted over a different payload must be refused by
                # the real verifier, not by the schema checks in front of it.
                other = provider.transition_consumed(seed, "b" * 64, "other")
                forged_signature = envelope_for(other)
                forged_signature["payload_sha256"] = hashlib.sha256(provider.canonical(payload)).hexdigest()
                forged = provider.canonical(provider.signed_consumed_envelope(payload, forged_signature))
                with self.assertRaisesRegex(admission.AdmissionError, "signature verification failed"):
                    provider.parse_signed_consumed_envelope(forged, key_arn)

    def test_reserve_command_rebases_after_etag_loss(self) -> None:
        provider = load_provider()
        seed = {
            "build_cohorts": [],
            "generation": 0,
            "schema_version": "1.1",
            "trust_mode": "aws-kms-ci-down-v1",
            "version_id": "seed",
        }
        first_cohort, second_cohort = "a" * 64, "b" * 64
        committed_first = provider.transition_consumed(
            seed, first_cohort, "first"
        )
        captured: dict[str, bytes] = {}
        reads = iter(
            [
                (b"stale", '"etag-0"', "version-0"),
                (b"winner", '"etag-1"', "version-1"),
            ]
        )

        def fake_read(_bucket, _key, _destination, version_id=None):
            if version_id:
                return captured["candidate"], '"etag-2"', "version-2"
            return next(reads)

        puts = []

        def fake_put(**kwargs):
            puts.append(kwargs["prior_etag"])
            if len(puts) == 1:
                return None
            captured["candidate"] = kwargs["body"].read_bytes()
            return '"etag-2"', "version-2"

        def fake_sign(payload, _key_arn):
            return (
                {
                    "payload_sha256": __import__("hashlib").sha256(
                        payload
                    ).hexdigest()
                },
                b"public",
            )

        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            args = Namespace(
                build_cohort=second_cohort,
                cohort_store_uri="s3://evidence/state",
                committed_envelope_out=root / "committed.json",
                evidence_kms_key_arn="evidence-key",
                key_arn="promoter-key",
                max_attempts=3,
                prior_out=root / "prior.json",
                prior_signature_out=root / "prior-signature.json",
            )
            with mock.patch.object(
                provider, "_read_s3_envelope", side_effect=fake_read
            ), mock.patch.object(
                provider,
                "parse_signed_consumed_envelope",
                side_effect=[(seed, {"payload_sha256": "seed"}), (committed_first, {"payload_sha256": "first"})],
            ), mock.patch.object(
                provider, "_put_s3_envelope", side_effect=fake_put
            ), mock.patch.object(provider, "_sign_payload", side_effect=fake_sign):
                provider.command_reserve_cohort(args)
            self.assertEqual(puts, ['"etag-0"', '"etag-1"'])
            self.assertEqual(json.loads(args.prior_out.read_text()), committed_first)
            committed = json.loads(args.committed_envelope_out.read_text())
            self.assertEqual(
                committed["payload"]["build_cohorts"],
                [first_cohort, second_cohort],
            )
            self.assertEqual(committed["payload"]["generation"], 2)

    def test_s3_transition_uses_conditional_single_object_put(self) -> None:
        provider = load_provider()
        with tempfile.TemporaryDirectory() as temporary:
            body = pathlib.Path(temporary) / "envelope.json"
            body.write_text("{}\n")
            conflict = subprocess.CompletedProcess(
                args=[], returncode=1, stdout="", stderr="PreconditionFailed (412)"
            )
            with mock.patch.object(
                provider.subprocess, "run", return_value=conflict
            ) as run:
                self.assertIsNone(
                    provider._put_s3_envelope(
                        bucket="evidence",
                        key="state/consumed-cohorts.envelope.json",
                        body=body,
                        prior_etag='"etag-1"',
                        evidence_kms_key_arn="evidence-key",
                    )
                )
            command = run.call_args.args[0]
            self.assertEqual(
                command[command.index("--if-match") + 1], '"etag-1"'
            )
            self.assertNotIn("--if-none-match", command)
            created = subprocess.CompletedProcess(
                args=[],
                returncode=0,
                stdout='{"ETag":"\\\"etag-2\\\"","VersionId":"version-2"}',
                stderr="",
            )
            with mock.patch.object(
                provider.subprocess, "run", return_value=created
            ) as run:
                self.assertEqual(
                    provider._put_s3_envelope(
                        bucket="evidence",
                        key="state/consumed-cohorts.envelope.json",
                        body=body,
                        prior_etag=None,
                        evidence_kms_key_arn="evidence-key",
                    ),
                    ('"etag-2"', "version-2"),
                )
            command = run.call_args.args[0]
            self.assertEqual(command[command.index("--if-none-match") + 1], "*")
            self.assertNotIn("--if-match", command)

    def test_provider_emits_ordered_schema_11_ledger(self) -> None:
        generator_path = ROOT / ".github/scripts/release-build-plan.py"
        spec = importlib.util.spec_from_file_location("release_plan", generator_path)
        assert spec and spec.loader
        generator = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(generator)
        plan = {
            "architectures": ["amd64", "arm64"],
            "build_date": "2026-11-10T00:00:00Z",
            "edition": "enterprise",
            "generator": {"path": ".github/scripts/release-build-plan.py", "sha256": "1" * 64},
            "images": [{key: value for key, value in image.items() if key != "enterprise_only"} for image in generator.IMAGES],
            "platform_version": "11.5.0",
            "schema_version": "1.0",
            "short_sha": "2" * 7,
            "source_commit": "2" * 40,
            "source_date_epoch": 1794268800,
            "source_tree": "3" * 40,
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            plan_path, ledger_path = root / "plan.json", root / "ledger.json"
            plan_path.write_text(json.dumps(plan, sort_keys=True, separators=(",", ":")) + "\n")
            subprocess.run([
                "python3", str(ROOT / ".github/scripts/ci_down_provider.py"), "ledger",
                "--build-plan", str(plan_path), "--coordinator-builder-id", "coordinator",
                "--amd64-builder-id", "amd64", "--arm64-builder-id", "arm64",
                "--promoter-builder-id", "promoter", "--source-repository",
                "getaxonflow/axonflow-enterprise", "--out", str(ledger_path),
            ], check=True)
            ledger = json.loads(ledger_path.read_text())
            self.assertEqual(ledger["schema_version"], "1.1")
            self.assertEqual(len(ledger["jobs"]), len(plan["images"]) * 5 + 1)
            for image in plan["images"]:
                jobs = [item for item in ledger["jobs"] if item["image"] == image["name"]]
                self.assertEqual([item["phase"] for item in jobs], ["child-build", "child-build", "index-seal", "post-index-receipt", "post-index-receipt"])

    def test_provider_emits_exact_bound_evidence_set(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            child_digest = f"sha256:{'2' * 64}"
            (root / "trivy.json").write_text(
                json.dumps(
                    {
                        "ArtifactType": "container_image",
                        "Metadata": {
                            "ImageConfig": {"architecture": "amd64", "os": "linux"},
                            "RepoDigests": [f"repository@{child_digest}"],
                        },
                        "Results": [{"Target": "rootfs", "Vulnerabilities": []}],
                        "SchemaVersion": 2,
                    }
                )
            )
            (root / "trivy-version.json").write_text('{"Version":"0.70.0"}\n')
            (root / "trivy-db.json").write_text(
                '{"UpdatedAt":"2026-11-10T00:00:00Z"}\n'
            )
            (root / "sbom.json").write_text(
                '{"spdxVersion":"SPDX-2.3","packages":[]}\n'
            )
            out = root / "evidence"
            subprocess.run(
                [
                    "python3",
                    str(ROOT / ".github/scripts/ci_down_provider.py"),
                    "evidence",
                    "--architecture",
                    "amd64",
                    "--build-cohort",
                    "1" * 64,
                    "--child-digest",
                    child_digest,
                    "--source-commit",
                    "3" * 40,
                    "--source-tree",
                    "4" * 40,
                    "--trivy-report",
                    str(root / "trivy.json"),
                    "--trivy-version",
                    str(root / "trivy-version.json"),
                    "--trivy-db",
                    str(root / "trivy-db.json"),
                    "--trivy-db-updated-at",
                    "2026-11-10T00:00:00Z",
                    "--sbom",
                    str(root / "sbom.json"),
                    "--out-dir",
                    str(out),
                ],
                check=True,
            )
            manifest = json.loads((out / "evidence-manifest.json").read_text())
            self.assertEqual(
                {item["type"] for item in manifest["evidence"]},
                {
                    "provenance",
                    "quarantine-disposition",
                    "sbom",
                    "trivy-db",
                    "trivy-report",
                    "trivy-version",
                },
            )
            for item in manifest["evidence"]:
                self.assertEqual(
                    item["sha256"],
                    __import__("hashlib").sha256(
                        (out / item["path"]).read_bytes()
                    ).hexdigest(),
                )

    def test_dispatch_preserves_schema_11_phase_order(self) -> None:
        path = ROOT / ".github/scripts/ci_down_dispatch.py"
        spec = importlib.util.spec_from_file_location("ci_down_dispatch", path)
        assert spec and spec.loader
        dispatch = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(dispatch)
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            plan = root / "plan.json"
            ledger = root / "ledger.json"
            plan.write_text(
                json.dumps(
                    {
                        "images": [{"name": "agent"}, {"name": "orchestrator"}],
                        "source_commit": "1" * 40,
                        "source_tree": "2" * 40,
                    }
                )
            )
            ledger.write_text(json.dumps({"build_cohort": "3" * 64}))
            argv = [
                str(path),
                "--build-plan",
                str(plan),
                "--ledger",
                str(ledger),
                "--state-machine-arn",
                "arn:aws:states:eu-west-1:123456789012:stateMachine:release",
            ]
            calls: list[tuple[str, ...]] = []

            def fake_aws(*args: str) -> dict:
                calls.append(args)
                if args[1] == "start-execution":
                    return {
                        "executionArn": "arn:aws:states:eu-west-1:123456789012:execution:release:test"
                    }
                return {"status": "SUCCEEDED"}

            with mock.patch.object(dispatch, "aws", side_effect=fake_aws), mock.patch.object(
                sys, "argv", argv
            ), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(dispatch.main(), 0)
            self.assertEqual(calls[0][:2], ("stepfunctions", "start-execution"))
            state_input = json.loads(calls[0][calls[0].index("--input") + 1])
            self.assertEqual(
                state_input,
                {
                    "build_cohort": "3" * 64,
                    "images": [{"name": "agent"}, {"name": "orchestrator"}],
                    "source_commit": "1" * 40,
                    "source_tree": "2" * 40,
                },
            )
            self.assertEqual(len(calls), 1)


if __name__ == "__main__":
    unittest.main()
