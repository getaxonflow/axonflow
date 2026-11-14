#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
template="$root/infrastructure/cloudformation/fincrime-model1-custody.yaml"
params="$root/config/cloudformation-params-fincrime-model1-custody-production-us.json"
uploader="$root/scripts/fincrime/upload-model1-release-unit.sh"

cfn-lint "$template" --non-zero-exit-code error
python3 - "$template" "$params" <<'PY'
from pathlib import Path
import base64
import json
import sys
import textwrap
import types

template = Path(sys.argv[1]).read_text()
parameters = json.loads(Path(sys.argv[2]).read_text())
values = {item["ParameterKey"]: item["ParameterValue"] for item in parameters}

assert values["EnvironmentName"] == "production-us"
assert values["SigningSecretName"] == "axonflow/fincrime/model1/artifact-signing-private-key"
assert values["ArtifactBucketName"] == "axonflow-production-us-fincrime-model1-686831565523-us-east-1"
assert values["ArtifactRetentionDays"] == "365"
principals = {
    values[name]
    for name in (
        "CustodianPrincipalArn",
        "SeedApproverPrincipalArn",
        "SignerPrincipalArn",
        "DeployerPrincipalArn",
        "ImagePublisherPrincipalArn",
    )
}
assert len(principals) == 5
assert all(value.startswith("arn:aws:iam::686831565523:role/axonflow-production-us-fc-m1-") for value in principals)
assert "DistinctCustodyPrincipals:" in template
assert template.count("Assert: !Not [!Equals") == 10
assert values["ScorerImageRepositoryName"] == "axonflow-fincrime-risk-scorer"

for required in (
    "ObjectLockEnabled: true",
    "Mode: COMPLIANCE",
    "Status: Enabled",
    "SSEAlgorithm: aws:kms",
    "BlockPublicAcls: true",
    "DenyInsecureTransport",
    "DenyUnencryptedObjectWrites",
    "DenyWrongEncryptionKey",
    "DenyNonConditionalReleaseWrites",
    "DenyReleaseDeletion",
    "s3:if-none-match: '*'",
    "Value: DISABLED",
    "DeletionPolicy: Retain",
    "UpdateReplacePolicy: Retain",
):
    assert required in template, required

secret = template.split("  SigningSeedSecret:\n", 1)[1].split("\n  ActiveReleaseParameter:", 1)[0]
assert "GenerateSecretString:" not in secret
assert "SecretString: '{\"state\":\"DISABLED\"}'" in secret

bucket_policy = template.split("  ArtifactBucketPolicy:\n", 1)[1].split("\n  SigningSeedSecret:", 1)[0]
assert "DeletionPolicy: Retain" in bucket_policy
assert "UpdateReplacePolicy: Retain" in bucket_policy

stager = template.split("  SeedStagerRole:\n", 1)[1].split("\n  ActiveReleaseParameter:", 1)[0]
assert 'VersionStages=["AWSPENDING"]' in stager
assert '"AWSPENDING" in labels' in stager
assert 'len(seed) != 32' in stager
assert "ReservedConcurrentExecutions: 1" in stager
assert "logs:" not in stager

lambda_source = template.split("        ZipFile: |\n", 1)[1].split(
    "\n\n  ActiveReleaseParameter:", 1
)[0]
lambda_source = textwrap.dedent(lambda_source)

class FakeSecretsManager:
    def __init__(self):
        self.stages = {"sentinel": ["AWSCURRENT"]}
        self.put = None

    def describe_secret(self, **_kwargs):
        return {"VersionIdsToStages": self.stages}

    def put_secret_value(self, **kwargs):
        self.put = kwargs
        self.stages["pending"] = ["AWSPENDING"]
        return {"VersionId": "pending"}

fake = FakeSecretsManager()
fake_boto3 = types.ModuleType("boto3")
fake_boto3.client = lambda _service: fake
sys.modules["boto3"] = fake_boto3
namespace = {}
exec(lambda_source, namespace)
namespace["os"].environ["SECRET_ID"] = "test-secret"
seed_b64 = base64.b64encode(bytes(range(32))).decode()
result = namespace["handler"](
    {"seed_b64": seed_b64, "client_request_token": "0" * 32}, None
)
assert result == {"version_id": "pending", "stage": "AWSPENDING"}
assert fake.put["SecretString"] == seed_b64
assert fake.put["VersionStages"] == ["AWSPENDING"]
try:
    namespace["handler"](
        {"seed_b64": seed_b64, "client_request_token": "1" * 32}, None
    )
except RuntimeError as exc:
    assert "already exists" in str(exc)
else:
    raise AssertionError("mediator accepted a second AWSPENDING seed")
fake.stages = {"sentinel": ["AWSCURRENT"]}
try:
    namespace["handler"](
        {
            "seed_b64": base64.b64encode(b"short").decode(),
            "client_request_token": "2" * 32,
        },
        None,
    )
except ValueError as exc:
    assert "exactly 32 bytes" in str(exc)
else:
    raise AssertionError("mediator accepted a malformed seed")
fake.stages = {}
try:
    namespace["handler"](
        {"seed_b64": seed_b64, "client_request_token": "3" * 32}, None
    )
except RuntimeError as exc:
    assert "AWSCURRENT" in str(exc)
else:
    raise AssertionError("mediator accepted a seed without the sentinel/current version")

custodian = template.split("  CustodianRole:\n", 1)[1].split("\n  SeedApproverRole:", 1)[0]
assert "lambda:InvokeFunction" in custodian
for forbidden in ("secretsmanager:", "kms:", "s3:", "ssm:", "ecs:"):
    assert forbidden not in custodian, ("custodian", forbidden)

approver = template.split("  SeedApproverRole:\n", 1)[1].split("\n  SignerRole:", 1)[0]
assert "secretsmanager:UpdateSecretVersionStage" in approver
assert "AWSCURRENT" in approver and "AWSPENDING" in approver
for forbidden in ("secretsmanager:GetSecretValue", "secretsmanager:PutSecretValue", "s3:", "ssm:", "ecs:"):
    assert forbidden not in approver, ("approver", forbidden)

signer = template.split("  SignerRole:\n", 1)[1].split("\n  DeployerRole:", 1)[0]
assert "secretsmanager:GetSecretValue" in signer
assert "s3:PutObject" in signer
assert "secretsmanager:VersionStage: AWSCURRENT" in signer
assert "${ArtifactBucket.Arn}/${ReleasePrefix}/*.release.tar" in signer
assert "s3:if-none-match: '*'" in signer
for forbidden in ("UpdateSecretVersionStage", "ssm:", "ecs:"):
    assert forbidden not in signer, ("signer", forbidden)

deployer = template.split("  DeployerRole:\n", 1)[1].split("\n  RuntimeRole:", 1)[0]
assert "ssm:PutParameter" in deployer
assert "s3:GetObjectVersion" in deployer
for forbidden in ("secretsmanager:", "s3:PutObject", "ecs:RegisterTaskDefinition", "ecs:UpdateService"):
    assert forbidden not in deployer, ("deployer", forbidden)

runtime = template.split("  RuntimeRole:\n", 1)[1].split("\nOutputs:", 1)[0]
assert "Service: ecs-tasks.amazonaws.com" in runtime
assert "ssm:GetParameter" in runtime
assert "s3:GetObjectVersion" in runtime
for forbidden in ("secretsmanager:", "s3:PutObject", "ssm:PutParameter", "ecs:"):
    assert forbidden not in runtime, ("runtime", forbidden)

publisher = template.split("  ImagePublisherRole:\n", 1)[1].split("\n  ArtifactBucket:", 1)[0]
for required in (
    "ecr:GetAuthorizationToken",
    "ecr:BatchCheckLayerAvailability",
    "ecr:CompleteLayerUpload",
    "ecr:InitiateLayerUpload",
    "ecr:PutImage",
    "ecr:UploadLayerPart",
    "Resource: !GetAtt ScorerImageRepository.Arn",
):
    assert required in publisher, required
for forbidden in ("secretsmanager:", "s3:", "ssm:", "ecs:"):
    assert forbidden not in publisher, ("publisher", forbidden)

repository = template.split("  ScorerImageRepository:\n", 1)[1].split("\n  ImagePublisherRole:", 1)[0]
for required in (
    "ImageTagMutability: IMMUTABLE",
    "ScanOnPush: true",
    "EncryptionType: KMS",
    "KmsKey: !GetAtt ArtifactKMSKey.Arn",
    '"tagStatus": "untagged"',
    '"countNumber": 365',
    "DeletionPolicy: Retain",
    "UpdateReplacePolicy: Retain",
):
    assert required in repository, required

assert "RoleName: !Sub axonflow-${EnvironmentName}-fc-m1-custodian" in template
assert "RoleName: !Sub axonflow-${EnvironmentName}-fc-m1-seed-approver" in template
assert "RoleName: !Sub axonflow-${EnvironmentName}-fc-m1-signer" in template
assert "RoleName: !Sub axonflow-${EnvironmentName}-fc-m1-deployer" in template
assert "RoleName: !Sub axonflow-${EnvironmentName}-fc-m1-runtime" in template
assert "RoleName: !Sub axonflow-${EnvironmentName}-fc-m1-image-publisher" in template
print("PASS: FinCrime Model 1 custody template is immutable and role-separated")
PY

grep -Fq -- "--if-none-match '*'" "$uploader"
grep -Fq -- "--version-id \"\$version_id\"" "$uploader"
grep -Fq -- 'models/model1/releases/*.release.tar' "$uploader"

tmp=$(mktemp -d /tmp/fincrime-model1-uploader-test.XXXXXX)
trap 'rm -rf -- "$tmp"' EXIT
mkdir -p "$tmp/bin" "$tmp/unit"
printf 'artifact\n' >"$tmp/unit/model.joblib"
printf '{}\n' >"$tmp/unit/model.joblib.manifest.json"
printf '{}\n' >"$tmp/unit/promotion-receipt.json"
COPYFILE_DISABLE=1 tar -cf "$tmp/unit.release.tar" -C "$tmp/unit" \
  model.joblib model.joblib.manifest.json promotion-receipt.json
unit_sha=$(shasum -a 256 "$tmp/unit.release.tar" | awk '{print $1}')

cat >"$tmp/bin/aws" <<'FAKEAWS'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >>"$FAKE_AWS_LOG"
case "$1 $2" in
  "s3api put-object")
    [[ " $* " == *" --if-none-match * "* ]]
    if [[ ${FAKE_AWS_PUT_RESULT:-success} == precondition-failed ]]; then
      echo "PreconditionFailed: 412" >&2
      exit 255
    fi
    printf 'version-123\n'
    ;;
  "s3api head-object")
    [[ " $* " == *" --version-id version-123 "* ]]
    printf '{"Metadata":{"sha256":"%s"},"ServerSideEncryption":"aws:kms","SSEKMSKeyId":"%s"}\n' \
      "$FAKE_AWS_SHA" "$FAKE_AWS_KMS"
    ;;
  "s3api get-object")
    [[ " $* " == *" --version-id version-123 "* ]]
    cp "$FAKE_AWS_SOURCE" "${@: -1}"
    printf '{}\n'
    ;;
  *) exit 90 ;;
esac
FAKEAWS
chmod +x "$tmp/bin/aws"

export PATH="$tmp/bin:$PATH"
export FAKE_AWS_LOG="$tmp/aws.log"
export FAKE_AWS_SHA="$unit_sha"
export FAKE_AWS_KMS='arn:aws:kms:us-east-1:686831565523:key/test'
export FAKE_AWS_SOURCE="$tmp/unit.release.tar"

success=$(
  "$uploader" test-bucket models/model1/releases/test.release.tar \
    "$tmp/unit.release.tar" "$unit_sha" "$FAKE_AWS_KMS"
)
python3 - "$success" "$unit_sha" <<'PY'
import json
import sys

result = json.loads(sys.argv[1])
assert result["version_id"] == "version-123"
assert result["sha256"] == sys.argv[2]
PY

: >"$FAKE_AWS_LOG"
export FAKE_AWS_PUT_RESULT=precondition-failed
if "$uploader" test-bucket models/model1/releases/test.release.tar \
  "$tmp/unit.release.tar" "$unit_sha" "$FAKE_AWS_KMS" >/dev/null 2>&1; then
  echo "FAIL: 412 create-only collision did not abort" >&2
  exit 1
fi
[[ $(wc -l <"$FAKE_AWS_LOG") -eq 1 ]]
grep -Fq 's3api put-object' "$FAKE_AWS_LOG"
if grep -Eq 'head-object|get-object' "$FAKE_AWS_LOG"; then
  echo "FAIL: 412 collision continued to readback" >&2
  exit 1
fi

runbook="$root/technical-docs/runbooks/RUNBOOK_FINCRIME_MODEL1_CUSTODY_INFRASTRUCTURE.md"
for phrase in \
  'enable-termination-protection' \
  'If-None-Match: *' \
  '412 Precondition Failed' \
  'SSM pointer recovery' \
  'role recovery'; do
  grep -Fq "$phrase" "$runbook"
done
# shellcheck disable=SC2016 # Backticks are part of the exact Markdown literal.
grep -Fq 'DeletionPolicy` and `UpdateReplacePolicy` are both `Retain`' "$runbook"

promotion_runbook="$root/technical-docs/runbooks/RUNBOOK_FINCRIME_MODEL1_PROMOTION.md"
for phrase in \
  'complete-unit S3 URI + exact VersionId + SHA-256' \
  '"secretsmanager:VersionStage": "AWSCURRENT"' \
  'The production signer is deliberately unable to read'; do
  grep -Fq "$phrase" "$promotion_runbook"
done
# shellcheck disable=SC2016 # This is an exact Markdown code-block literal, not shell expansion.
repo_root_line=$(grep -nF 'REPO_ROOT=$(git rev-parse --show-toplevel)' "$promotion_runbook" | cut -d: -f1)
# shellcheck disable=SC2016 # This is an exact Markdown code-block literal, not shell expansion.
risk_scorer_cd_line=$(grep -nF 'cd "$REPO_ROOT/ee/platform/risk-scorer"' "$promotion_runbook" | cut -d: -f1)
# shellcheck disable=SC2016 # This is an exact Markdown code-block literal, not shell expansion.
uploader_line=$(grep -nF '"$REPO_ROOT/scripts/fincrime/upload-model1-release-unit.sh"' "$promotion_runbook" | cut -d: -f1)
[[ "$repo_root_line" -lt "$risk_scorer_cd_line" ]]
[[ "$risk_scorer_cd_line" -lt "$uploader_line" ]]
# shellcheck disable=SC2016 # Backticks are part of the exact Markdown literal.
grep -Fq 'emits exactly one `{bucket,key,version_id,sha256}` tuple' "$promotion_runbook"
# shellcheck disable=SC2016 # Backticks are part of the exact Markdown literal.
grep -Fq 'requires `If-None-Match: *`' "$promotion_runbook"
# shellcheck disable=SC2016 # Backticks are part of the exact Markdown literal.
grep -Fq 'The seed approver moves the reviewed pending version to `AWSCURRENT`' "$promotion_runbook"
for stale in \
  'upload all three files' \
  'the object version IDs' \
  'model artifact URI + object version ID + SHA-256' \
  'manifest URI + object version ID + SHA-256' \
  'three staged/read-back object hashes/version IDs' \
  'SIGNING_KEY_STAGE=AWSPENDING'; do
  if grep -Fq "$stale" "$promotion_runbook"; then
    echo "FAIL: stale three-object publication path returned: $stale" >&2
    exit 1
  fi
done
# shellcheck disable=SC2016 # Backticks are part of the exact Markdown literal.
if grep -Fq 'Only after deployment acceptance, move the new version to `AWSCURRENT`' "$promotion_runbook"; then
  echo "FAIL: stale three-object publication path returned: delayed AWSCURRENT promotion" >&2
  exit 1
fi
