#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
RESOLVER="$ROOT/.github/scripts/resolve-client-image-contract.py"
PROMOTER="$ROOT/.github/scripts/promote-immutable-image.py"
ADMISSION="$ROOT/.github/scripts/validate-client-image-admission.py"
COMPLETION="$ROOT/.github/scripts/promotion-completion.py"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT

[[ "$(python3 "$RESOLVER" --client healthcare --environment staging)" == "us-east-1" ]]
if python3 "$RESOLVER" --client healthcare --environment staging --expected-region ap-south-1 >"$WORK/region.log" 2>&1; then
  echo "FAIL: mismatched client image region was accepted" >&2
  exit 1
fi
grep -q 'client image region mismatch' "$WORK/region.log"

full_sha="$(printf '3%.0s' {1..40})"
valid_digest="sha256:$(printf '4%.0s' {1..64})"
if bash "$ROOT/scripts/multi-tenant/deploy-client.sh" \
    --client ecommerce --env staging --version "$full_sha" \
    --image-region us-east-1 \
    --image-registry 999999999999.dkr.ecr.us-east-1.amazonaws.com \
    --backend-digest "$valid_digest" --frontend-digest "$valid_digest" \
    >"$WORK/deploy-registry.log" 2>&1; then
  echo "FAIL: deployment accepted a registry different from the admitted registry" >&2
  exit 1
fi
grep -q 'differs from configured registry' "$WORK/deploy-registry.log"

(
  source "$ROOT/scripts/utilities/ssm-exec-utils.sh"
  for config in "$ROOT"/configs/environments/clients/{ecommerce,travel,healthcare}/staging.env; do
    unset AWS_REGION INSTANCE_IP
    source "$config"
    [[ "$AWS_REGION" == "$(get_instance_region "$INSTANCE_IP")" ]]
  done
)

python3 - "$ROOT" <<'PY'
import pathlib, sys, yaml
root = pathlib.Path(sys.argv[1])
build = yaml.safe_load((root / ".github/workflows/build-client-images.yml").read_text())
deploy = yaml.safe_load((root / ".github/workflows/deploy-clients.yml").read_text())
staging_path = root / ".github/workflows/staging-session.yml"
staging_raw = staging_path.read_text()
staging = yaml.safe_load(staging_raw)
build_steps = build["jobs"]["build-client"]["steps"]
deploy_steps = deploy["jobs"]["deploy-client"]["steps"]
triggers = deploy.get("on", deploy.get(True))
assert "support" not in triggers["workflow_dispatch"]["inputs"]["client"]["options"]
assert deploy["env"]["AWS_ACCOUNT"] == "686831565523"
authority = deploy["jobs"]["authority"]
assert "refs/heads/main" in authority["steps"][0]["run"]
assert deploy["jobs"]["deploy-client"]["needs"] == ["authority"]
assert next(s for s in deploy_steps if s.get("name") == "Checkout code")["with"]["ref"] == "${{ needs.authority.outputs.source_sha }}"
build_triggers = build.get("on", build.get(True))
assert "version" not in build_triggers["workflow_dispatch"]["inputs"]
determine = build["jobs"]["determine-clients"]["steps"]
parse = next(s for s in determine if s.get("name") == "Parse client list")
assert parse["env"]["CLIENTS_INPUT"] == "${{ inputs.clients }}"
assert "${{ inputs.clients }}" not in parse["run"]
assert "unsupported client" in parse["run"]
bind = next(s for s in determine if s.get("name") == "Bind source commit")
assert "git rev-parse HEAD" in bind["run"] and "SOURCE_COMMIT" in bind["env"]
assert 'SOURCE_REF" = "refs/heads/main"' in bind["run"]
assert "resolve-client-image-contract.py" in next(s for s in build_steps if s.get("name") == "Resolve client image region contract")["run"]
deploy_region = next(s for s in deploy_steps if s.get("name") == "Determine AWS Region")["run"]
assert "resolve-client-image-contract.py" in deploy_region
assert "eu-central-1" not in deploy_region and "ap-south-1" not in deploy_region
for steps in (build_steps, deploy_steps):
    account = next(s for s in steps if s.get("name") == "Resolve authenticated AWS account")
    assert "aws sts get-caller-identity" in account["run"]
    assert 'does not match release account' in account["run"]
config = next(s for s in build_steps if s.get("name") == "Set client configuration")
assert config["env"]["CLIENT"] == "${{ matrix.client }}"
assert "${{ matrix.client }}" not in config["run"]
checkout = next(s for s in build_steps if s.get("name") == "Verify exact source checkout")
assert "git rev-parse HEAD" in checkout["run"] and "SOURCE_COMMIT" in checkout["env"]
for name in ("Build and push backend", "Build and push frontend", "Build and push single-container app (banking)"):
    step = next(s for s in build_steps if s.get("name") == name)
    assert "push-by-digest=true" in step["with"]["outputs"]
    assert "tags" not in step["with"]
    expected = {"Build and push backend": "backend_digest", "Build and push frontend": "frontend_digest", "Build and push single-container app (banking)": "app_digest"}[name]
    assert f"steps.reuse.outputs.{expected} == ''" in step["if"]
reuse_index = next(i for i,s in enumerate(build_steps) if s.get("name") == "Resolve existing admitted source images")
build_indices = [next(i for i,s in enumerate(build_steps) if s.get("name") == name) for name in ("Build and push backend", "Build and push frontend", "Build and push single-container app (banking)")]
assert reuse_index < min(build_indices)
reuse = build_steps[reuse_index]["run"]
assert "gh attestation verify" in reuse and "validate-client-image-admission.py" in reuse
assert "promotion-completion.py verify" in reuse
assert '--subject-name "$repository"' in reuse
assert "partial client image publication" not in reuse
assert '"quarantine-$SOURCE_COMMIT"' in reuse
stages = [s for s in build_steps if "quarantine identity" in s.get("name", "")]
assert len(stages) == 3
assert all("--quarantine" in s["run"] and 'quarantine-$SOURCE_COMMIT' in s["run"] for s in stages)
backend_stage = next(i for i,s in enumerate(build_steps) if s.get("name") == "Stage backend quarantine identity")
backend_sign = next(i for i,s in enumerate(build_steps) if s.get("name") == "Sign backend image admission")
frontend_stage = next(i for i,s in enumerate(build_steps) if s.get("name") == "Stage frontend quarantine identity")
frontend_sign = next(i for i,s in enumerate(build_steps) if s.get("name") == "Sign frontend image admission")
assert backend_stage < backend_sign < frontend_stage < frontend_sign
attest = [s for s in build_steps if str(s.get("uses", "")).startswith("actions/attest-build-provenance@")]
assert len(attest) == 6
assert all(s["uses"].endswith("977bb373ede98d70efdf65b84cb5f73e068dcc2a") for s in attest)
promote = next(s for s in build_steps if s.get("name") == "Promote exact client image digests")["run"]
assert "promote-immutable-image.py" in promote
assert promote.count('--tag "$VERSION"') == 1 and "SHORT_VERSION" not in promote
promote_index = next(i for i,s in enumerate(build_steps) if s.get("name") == "Promote exact client image digests")
for component in ("backend", "frontend", "single-container"):
    write_name = f"Write {component} promotion completion"
    sign_name = f"Sign {component} promotion completion"
    write_index = next(i for i,s in enumerate(build_steps) if s.get("name") == write_name)
    sign_index = next(i for i,s in enumerate(build_steps) if s.get("name") == sign_name)
    assert promote_index < write_index < sign_index
verify_completion_index = next(i for i,s in enumerate(build_steps) if s.get("name") == "Verify completed client promotions")
assert all(next(i for i,s in enumerate(build_steps) if s.get("name") == f"Sign {component} promotion completion") < verify_completion_index for component in ("backend", "frontend", "single-container"))
assert "promotion-completion.py verify" in build_steps[verify_completion_index]["run"]

validate = next(s for s in deploy_steps if s.get("name") == "Validate immutable client images")["run"]
assert "--full-sha-only" in validate and "gh attestation verify" in validate
assert "validate-client-image-admission.py" in validate
assert "promotion-completion.py verify" in validate
staging_triggers = staging.get("on", staging.get(True))
client_version = staging_triggers["workflow_dispatch"]["inputs"]["client_version"]
assert client_version["required"] is False and "required when deploying demo clients" in client_version["description"]
preflight = staging["jobs"]["preflight"]
assert preflight["permissions"] == {}
preflight_steps = preflight["steps"]
assert len(preflight_steps) == 1
preflight_step = preflight_steps[0]
assert preflight_step["env"] == {
    "ACTION": "${{ inputs.action }}",
    "DEPLOY_CLIENTS": "${{ inputs.deploy_clients }}",
    "CLIENT_VERSION": "${{ inputs.client_version }}",
}
preflight_run = preflight_step["run"]
assert '[[ "$CLIENT_VERSION" =~ ^[0-9a-f]{40}$ ]]' in preflight_run
assert "aws " not in preflight_run and "gh workflow run" not in preflight_run
deploy_staging = staging["jobs"]["deploy-staging"]
assert deploy_staging["needs"] == ["preflight"]
assert "needs.preflight.result == 'success'" in deploy_staging["if"]
for independent_job in ("check-status", "destroy-staging"):
    assert "needs" not in staging["jobs"][independent_job]
    assert "client_version" not in staging["jobs"][independent_job]["if"]
deploy_invocations = [
    line.strip()
    for line in staging_raw.splitlines()
    if "gh workflow run staging-session.yml -f action=deploy" in line
]
assert deploy_invocations
assert all(
    "client_version=" in line or "deploy_clients=false" in line
    for line in deploy_invocations
), deploy_invocations
staging_dispatch = next(s for s in staging["jobs"]["deploy-clients"]["steps"] if "deploy-clients.yml" in s.get("run", ""))
assert staging_dispatch["env"]["CLIENT_VERSION"] == "${{ inputs.client_version }}"
assert '[[ "$CLIENT_VERSION" =~ ^[0-9a-f]{40}$ ]]' in staging_dispatch["run"]
assert '-f version="$CLIENT_VERSION"' in staging_dispatch["run"]

# Enumerate every workflow-level caller of deploy-clients.yml and pin it to the
# callee's complete required-input contract. This prevents a future caller from
# silently omitting a newly required deployment selector.
deploy_inputs = deploy.get("on", deploy.get(True))["workflow_dispatch"]["inputs"]
required_dispatch_inputs = {
    name for name, spec in deploy_inputs.items()
    if spec.get("required") is True and "default" not in spec
}
dispatch_callers = []
for workflow_path in sorted((root / ".github/workflows").glob("*.y*ml")):
    workflow = yaml.safe_load(workflow_path.read_text()) or {}
    for job in (workflow.get("jobs") or {}).values():
        if not isinstance(job, dict):
            continue
        for step in job.get("steps") or []:
            run = step.get("run", "") if isinstance(step, dict) else ""
            if "gh workflow run deploy-clients.yml" not in run:
                continue
            supplied = set(__import__("re").findall(r"(?:^|\s)-f\s+([A-Za-z_][A-Za-z0-9_]*)=", run))
            dispatch_callers.append((workflow_path.name, step.get("name", ""), supplied))
assert dispatch_callers, "deploy-clients.yml must have at least one workflow dispatch consumer"
for workflow_name, step_name, supplied in dispatch_callers:
    missing = required_dispatch_inputs - supplied
    assert not missing, f"{workflow_name}:{step_name} omits required deploy-clients inputs: {sorted(missing)}"
deploy_run = next(s for s in deploy_steps if s.get("name") == "Deploy Client")["run"]
assert "--image-region" in deploy_run and "--image-registry" in deploy_run
assert "--backend-digest" in deploy_run and "--frontend-digest" in deploy_run and "--app-digest" in deploy_run

expected_target_regions = {"ecommerce": "eu-central-1", "travel": "eu-central-1", "healthcare": "ap-south-1"}
for client, region in expected_target_regions.items():
    config_text = (root / "configs/environments/clients" / client / "staging.env").read_text()
    assert f'AWS_REGION="{region}"' in config_text
deploy_script = (root / "scripts/multi-tenant/deploy-client.sh").read_text()
assert 'aws ecr get-login-password --region $IMAGE_REGION' in deploy_script
assert 'Client config region $AWS_REGION differs from admitted image region' not in deploy_script
assert 'ECR_REGISTRY="$IMAGE_REGISTRY"' in deploy_script

application = (root / ".github/workflows/deploy-application.yml").read_text()
assert "Requested Portal task deployment has no service" in application
assert "Requested Customer Portal UI deployment has no service" in application
assert "Requested Customer Portal UI host service is absent" in application
assert '[ "$DEPLOY_MODE" = "community-saas" ]' in application
assert "customer-portal-ui is not present in the active Portal task definition" in application
assert "Customer Portal service not found in stack outputs - skipping" not in application
assert "Customer Portal UI service not found in stack outputs - skipping" not in application
application_yaml = yaml.safe_load(application)
application_authority = application_yaml["jobs"]["authority"]
assert "refs/heads/main" in application_authority["steps"][0]["run"]
assert application_yaml["jobs"]["prepare"]["needs"] == ["authority"]
service_step = next(s for s in application_yaml["jobs"]["prepare"]["steps"] if s.get("name") == "Determine services to deploy")
assert service_step["env"]["INPUT_SERVICES"] == "${{ inputs.services }}"
assert "${{ inputs.services }}" not in service_step["run"]
assert 'DEPLOYMENT_MODE" = "community-saas"' in service_step["run"]
config_step = next(s for s in application_yaml["jobs"]["prepare"]["steps"] if s.get("name") == "Read environment configuration")
assert config_step["env"]["TARGET_ENVIRONMENT"] == "${{ inputs.environment }}"
assert "${{ inputs.environment }}" not in config_step["run"]
assert "Unsupported environment" in config_step["run"]
portal_step = next(s for s in application_yaml["jobs"]["deploy"]["steps"] if s.get("name") == "Deploy Customer Portal service")
assert 'DEPLOY_MODE" = "community-saas"' in portal_step["run"]
assert '[ "$UPDATE_PORTAL" = "true" ] && UPDATE_UI="true"' not in portal_step["run"]
community = (root / "infrastructure/cloudformation/community-saas-ecs.yaml").read_text()
marketplace = (root / "ee/platform/aws-marketplace/cloudformation-ecs-fargate.yaml").read_text()
assert "- Name: customer-portal-ui" in community
assert "CustomerPortalUIServiceName:" not in community
assert "- Name: customer-portal-ui" in marketplace
assert "CustomerPortalUIServiceName:" in marketplace
PY

python3 - "$ROOT/.github/workflows/deploy-clients.yml" "$WORK/account-guard.sh" <<'PY'
import pathlib, sys, yaml
workflow = yaml.safe_load(pathlib.Path(sys.argv[1]).read_text())
steps = workflow["jobs"]["deploy-client"]["steps"]
run = next(step["run"] for step in steps if step.get("name") == "Resolve authenticated AWS account")
pathlib.Path(sys.argv[2]).write_text(run)
PY
mkdir -p "$WORK/account-bin"
cat > "$WORK/account-bin/aws" <<'SH'
#!/usr/bin/env bash
printf '%s\n' 999999999999
SH
chmod +x "$WORK/account-bin/aws"
if PATH="$WORK/account-bin:$PATH" EXPECTED_ACCOUNT=686831565523 GITHUB_OUTPUT="$WORK/account.out" \
    bash "$WORK/account-guard.sh" >"$WORK/account-mismatch.log" 2>&1; then
  echo "FAIL: authenticated AWS account mismatch was accepted" >&2
  exit 1
fi
grep -q 'does not match release account' "$WORK/account-mismatch.log"

python3 - "$ROOT/.github/workflows/staging-session.yml" "$WORK/staging-preflight.sh" <<'PY'
import pathlib, sys, yaml
workflow = yaml.safe_load(pathlib.Path(sys.argv[1]).read_text())
steps = workflow["jobs"]["preflight"]["steps"]
assert len(steps) == 1
pathlib.Path(sys.argv[2]).write_text(steps[0]["run"])
PY
mkdir -p "$WORK/staging-preflight-bin"
cat > "$WORK/staging-preflight-bin/aws" <<'SH'
#!/usr/bin/env bash
touch "$SIDE_EFFECT_MARKER"
exit 99
SH
cat > "$WORK/staging-preflight-bin/gh" <<'SH'
#!/usr/bin/env bash
touch "$SIDE_EFFECT_MARKER"
exit 99
SH
chmod +x "$WORK/staging-preflight-bin/aws" "$WORK/staging-preflight-bin/gh" "$WORK/staging-preflight.sh"
side_effect_marker="$WORK/staging-preflight-side-effect"
for invalid_version in '' not-a-sha "$(printf 'A%.0s' {1..40})"; do
  if PATH="$WORK/staging-preflight-bin:$PATH" ACTION=deploy DEPLOY_CLIENTS=true \
      CLIENT_VERSION="$invalid_version" SIDE_EFFECT_MARKER="$side_effect_marker" \
      bash "$WORK/staging-preflight.sh" >"$WORK/staging-preflight-invalid.log" 2>&1; then
    echo "FAIL: staging preflight accepted invalid client_version='$invalid_version'" >&2
    exit 1
  fi
  grep -q 'full admitted source Git SHA' "$WORK/staging-preflight-invalid.log"
  [[ ! -e "$side_effect_marker" ]]
done
PATH="$WORK/staging-preflight-bin:$PATH" ACTION=deploy DEPLOY_CLIENTS=true \
  CLIENT_VERSION="$full_sha" SIDE_EFFECT_MARKER="$side_effect_marker" \
  bash "$WORK/staging-preflight.sh"
for independent_case in 'deploy false' 'destroy true' 'status true'; do
  read -r action deploy_clients <<<"$independent_case"
  PATH="$WORK/staging-preflight-bin:$PATH" ACTION="$action" DEPLOY_CLIENTS="$deploy_clients" \
    CLIENT_VERSION='' SIDE_EFFECT_MARKER="$side_effect_marker" \
    bash "$WORK/staging-preflight.sh"
done
[[ ! -e "$side_effect_marker" ]]

python3 - "$ROOT/.github/workflows/staging-session.yml" "$WORK/staging-client-dispatch.sh" <<'PY'
import pathlib, sys, yaml
workflow = yaml.safe_load(pathlib.Path(sys.argv[1]).read_text())
step = next(s for s in workflow["jobs"]["deploy-clients"]["steps"] if "deploy-clients.yml" in s.get("run", ""))
pathlib.Path(sys.argv[2]).write_text(step["run"].replace("${{ matrix.client }}", "ecommerce"))
PY
mkdir -p "$WORK/staging-dispatch-bin"
cat > "$WORK/staging-dispatch-bin/gh" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "$MOCK_DISPATCH_LOG"
SH
chmod +x "$WORK/staging-dispatch-bin/gh" "$WORK/staging-client-dispatch.sh"
if PATH="$WORK/staging-dispatch-bin:$PATH" CLIENT_VERSION=not-a-sha GH_TOKEN=test \
    MOCK_DISPATCH_LOG="$WORK/staging-dispatch.log" bash "$WORK/staging-client-dispatch.sh" \
    >"$WORK/staging-invalid-version.log" 2>&1; then
  echo "FAIL: staging-session accepted an invalid client image version" >&2
  exit 1
fi
grep -q 'full admitted source Git SHA' "$WORK/staging-invalid-version.log"
[[ ! -e "$WORK/staging-dispatch.log" ]]
PATH="$WORK/staging-dispatch-bin:$PATH" CLIENT_VERSION="$full_sha" GH_TOKEN=test \
  MOCK_DISPATCH_LOG="$WORK/staging-dispatch.log" bash "$WORK/staging-client-dispatch.sh"
grep -q "workflow run deploy-clients.yml -f client=ecommerce -f environment=staging -f version=$full_sha" "$WORK/staging-dispatch.log"

python3 - "$ROOT/.github/workflows/deploy-application.yml" "$WORK/environment-guard.sh" <<'PY'
import pathlib, sys, yaml
workflow = yaml.safe_load(pathlib.Path(sys.argv[1]).read_text())
steps = workflow["jobs"]["prepare"]["steps"]
run = next(step["run"] for step in steps if step.get("name") == "Read environment configuration")
pathlib.Path(sys.argv[2]).write_text(run)
PY
injection_marker="$WORK/workflow-call-injection-executed"
if TARGET_ENVIRONMENT="staging\"; touch $injection_marker; #" GITHUB_OUTPUT="$WORK/environment.out" \
    bash "$WORK/environment-guard.sh" >"$WORK/environment-injection.log" 2>&1; then
  echo "FAIL: reusable workflow environment injection was accepted" >&2
  exit 1
fi
grep -q 'Unsupported environment' "$WORK/environment-injection.log"
[[ ! -e "$injection_marker" ]]

python3 - "$ROOT/.github/workflows/deploy-application.yml" "$WORK/deploy-authority.sh" <<'PY'
import pathlib, sys, yaml
workflow = yaml.safe_load(pathlib.Path(sys.argv[1]).read_text())
run = workflow["jobs"]["authority"]["steps"][0]["run"]
pathlib.Path(sys.argv[2]).write_text(run)
PY
if SOURCE_REF=refs/heads/feature \
    WORKFLOW_REF=getaxonflow/axonflow-enterprise/.github/workflows/deploy-application.yml@refs/heads/feature \
    REPOSITORY=getaxonflow/axonflow-enterprise EVENT_NAME=workflow_dispatch \
    bash "$WORK/deploy-authority.sh" >"$WORK/untrusted-deploy-ref.log" 2>&1; then
  echo "FAIL: selected-ref deployment workflow was accepted" >&2
  exit 1
fi
grep -q 'must run from refs/heads/main' "$WORK/untrusted-deploy-ref.log"
SOURCE_REF=refs/heads/main \
  WORKFLOW_REF=getaxonflow/axonflow-enterprise/.github/workflows/release-train.yml@refs/heads/main \
  REPOSITORY=getaxonflow/axonflow-enterprise EVENT_NAME=workflow_call \
  bash "$WORK/deploy-authority.sh"

source_commit="$(printf '1%.0s' {1..40})"
image_digest="sha256:$(printf 'a%.0s' {1..64})"
source_repository="getaxonflow/axonflow-enterprise"
write_client_admission() {
  local destination="$1"
  local subject="${2:-686831565523.dkr.ecr.us-east-1.amazonaws.com/axonflow-ecommerce-backend}"
  jq -n \
    --arg digest "${image_digest#sha256:}" \
    --arg subject "$subject" \
    --arg repository "https://github.com/$source_repository" \
    --arg workflow ".github/workflows/build-client-images.yml" \
    --arg ref "refs/heads/main" \
    --arg builder "https://github.com/$source_repository/.github/workflows/build-client-images.yml@refs/heads/main" \
    --arg invocation "https://github.com/$source_repository/actions/runs/123/attempts/1" \
    --arg commit "$source_commit" \
    '[{verificationResult:{signature:{certificate:{subjectAlternativeName:$builder}},verifiedTimestamps:[{}],statement:{subject:[{name:$subject,digest:{sha256:$digest}}],predicate:{buildDefinition:{buildType:"https://actions.github.io/buildtypes/workflow/v1",externalParameters:{workflow:{repository:$repository,path:$workflow,ref:$ref}},internalParameters:{github:{runner_environment:"github-hosted"}},resolvedDependencies:[{digest:{gitCommit:$commit}}]},runDetails:{builder:{id:$builder},metadata:{invocationId:$invocation}}}}}}]' > "$destination"
}
write_client_admission "$WORK/admission.json"
subject_name="686831565523.dkr.ecr.us-east-1.amazonaws.com/axonflow-ecommerce-backend"
python3 "$ADMISSION" --verification "$WORK/admission.json" --digest "$image_digest" --subject-name "$subject_name" --source-repository "$source_repository" --source-commit "$source_commit" --source-ref refs/heads/main
if python3 "$ADMISSION" --verification "$WORK/admission.json" --digest "$image_digest" --subject-name "$subject_name" --source-repository "$source_repository" --source-commit "$source_commit" --source-ref refs/heads/attacker >"$WORK/untrusted-source-ref.log" 2>&1; then
  echo "FAIL: untrusted client build source ref was accepted" >&2
  exit 1
fi
grep -q 'source ref must be refs/heads/main' "$WORK/untrusted-source-ref.log"

jq '.[0].verificationResult.statement.predicate.buildDefinition.externalParameters.workflow.path=".github/workflows/build.yml" | .[0].verificationResult.statement.predicate.runDetails.builder.id="https://github.com/getaxonflow/axonflow-enterprise/.github/workflows/build.yml@refs/heads/main"' \
  "$WORK/admission.json" > "$WORK/main-build-admission.json"
python3 "$ADMISSION" --verification "$WORK/main-build-admission.json" --digest "$image_digest" --subject-name "$subject_name" --source-repository "$source_repository" --source-commit "$source_commit" --source-ref refs/heads/main --workflow .github/workflows/build.yml
assert_admission_invalid() {
  local label="$1" filter="$2"
  jq "$filter" "$WORK/admission.json" > "$WORK/$label.json"
  if python3 "$ADMISSION" --verification "$WORK/$label.json" --digest "$image_digest" --subject-name "$subject_name" --source-repository "$source_repository" --source-commit "$source_commit" --source-ref refs/heads/main >"$WORK/$label.log" 2>&1; then
    echo "FAIL: $label client admission was accepted" >&2
    exit 1
  fi
  grep -q 'trusted signed workflow/run/source identity' "$WORK/$label.log"
}
assert_admission_invalid wrong-source '.[0].verificationResult.statement.predicate.buildDefinition.resolvedDependencies[0].digest.gitCommit="2222222222222222222222222222222222222222"'
assert_admission_invalid wrong-subject '.[0].verificationResult.statement.subject[0].name="attacker.example/wrong-client"'
assert_admission_invalid untrusted-ref '.[0].verificationResult.statement.predicate.buildDefinition.externalParameters.workflow.ref="refs/heads/attacker" | .[0].verificationResult.statement.predicate.runDetails.builder.id="https://github.com/getaxonflow/axonflow-enterprise/.github/workflows/build-client-images.yml@refs/heads/attacker"'
assert_admission_invalid wrong-workflow '.[0].verificationResult.statement.predicate.buildDefinition.externalParameters.workflow.path=".github/workflows/attacker.yml"'
assert_admission_invalid unsigned 'del(.[0].verificationResult.signature.certificate)'
assert_admission_invalid wrong-runner '.[0].verificationResult.statement.predicate.buildDefinition.internalParameters.github.runner_environment="self-hosted"'

# A canonical client tag is not deployable merely because its pre-promotion
# image provenance is valid. The deterministic completion subject must also be
# signed by the same exact build-client workflow/source identity.
completion_manifest="$WORK/promotion-completion.json"
completion_admission="$WORK/promotion-completion-admission.json"
python3 "$COMPLETION" write --output "$completion_manifest" --repository "$subject_name" --digest "$image_digest"
completion_hash="$(shasum -a 256 "$completion_manifest" | awk '{print $1}')"
jq -n \
  --arg digest "$completion_hash" \
  --arg repository "https://github.com/$source_repository" \
  --arg workflow ".github/workflows/build-client-images.yml" \
  --arg ref "refs/heads/main" \
  --arg builder "https://github.com/$source_repository/.github/workflows/build-client-images.yml@refs/heads/main" \
  --arg invocation "https://github.com/$source_repository/actions/runs/123/attempts/1" \
  --arg commit "$source_commit" \
  '[{verificationResult:{signature:{certificate:{subjectAlternativeName:$builder}},verifiedTimestamps:[{}],statement:{subject:[{digest:{sha256:$digest}}],predicate:{buildDefinition:{buildType:"https://actions.github.io/buildtypes/workflow/v1",externalParameters:{workflow:{repository:$repository,path:$workflow,ref:$ref}},internalParameters:{github:{runner_environment:"github-hosted"}},resolvedDependencies:[{digest:{gitCommit:$commit}}]},runDetails:{builder:{id:$builder},metadata:{invocationId:$invocation}}}}}}]' > "$completion_admission"
python3 "$COMPLETION" verify \
  --manifest "$completion_manifest" --verification "$completion_admission" \
  --repository "$subject_name" --digest "$image_digest" \
  --source-repository "$source_repository" --source-ref refs/heads/main \
  --source-commit "$source_commit" --workflow .github/workflows/build-client-images.yml
assert_completion_invalid() {
  local label="$1" filter="$2"
  jq "$filter" "$completion_admission" > "$WORK/completion-$label.json"
  if python3 "$COMPLETION" verify \
      --manifest "$completion_manifest" --verification "$WORK/completion-$label.json" \
      --repository "$subject_name" --digest "$image_digest" \
      --source-repository "$source_repository" --source-ref refs/heads/main \
      --source-commit "$source_commit" --workflow .github/workflows/build-client-images.yml \
      >"$WORK/completion-$label.log" 2>&1; then
    echo "FAIL: $label completed client promotion was accepted" >&2
    exit 1
  fi
  grep -q 'trusted workflow/source identity' "$WORK/completion-$label.log"
}
assert_completion_invalid stale-subject '.[0].verificationResult.statement.subject[0].digest.sha256="ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"'
assert_completion_invalid wrong-builder '.[0].verificationResult.statement.predicate.runDetails.builder.id="https://github.com/attacker/repo/.github/workflows/build-client-images.yml@refs/heads/main"'
assert_completion_invalid self-hosted '.[0].verificationResult.statement.predicate.buildDefinition.internalParameters.github.runner_environment="self-hosted"'
assert_completion_invalid wrong-commit '.[0].verificationResult.statement.predicate.buildDefinition.resolvedDependencies[0].digest.gitCommit="2222222222222222222222222222222222222222"'
assert_completion_invalid wrong-workflow '.[0].verificationResult.statement.predicate.buildDefinition.externalParameters.workflow.path=".github/workflows/attacker.yml"'
jq '.promotion_status="pending"' "$completion_manifest" > "$WORK/tampered-completion.json"
if python3 "$COMPLETION" verify \
    --manifest "$WORK/tampered-completion.json" --verification "$completion_admission" \
    --repository "$subject_name" --digest "$image_digest" \
    --source-repository "$source_repository" --source-ref refs/heads/main \
    --source-commit "$source_commit" --workflow .github/workflows/build-client-images.yml \
    >"$WORK/tampered-completion.log" 2>&1; then
  echo "FAIL: tampered client completion manifest was accepted" >&2
  exit 1
fi
grep -q 'not canonical or does not match' "$WORK/tampered-completion.log"
# Retry writes are byte-identical and remain bound to the same signed subject.
retry_completion="$WORK/promotion-completion-retry.json"
python3 "$COMPLETION" write --output "$retry_completion" --repository "$subject_name" --digest "$image_digest"
cmp "$completion_manifest" "$retry_completion"
python3 "$COMPLETION" verify \
  --manifest "$retry_completion" --verification "$completion_admission" \
  --repository "$subject_name" --digest "$image_digest" \
  --source-repository "$source_repository" --source-ref refs/heads/main \
  --source-commit "$source_commit" --workflow .github/workflows/build-client-images.yml
if python3 "$COMPLETION" verify \
    --manifest "$WORK/process-death-completion.json" \
    --verification "$WORK/process-death-completion-admission.json" \
    --repository "$subject_name" --digest "$image_digest" \
    --source-repository "$source_repository" --source-ref refs/heads/main \
    --source-commit "$source_commit" --workflow .github/workflows/build-client-images.yml \
    >"$WORK/process-death-completion.log" 2>&1; then
  echo "FAIL: process-death canonical client tag was deployable without completion" >&2
  exit 1
fi
grep -q 'cannot read completed promotion admission' "$WORK/process-death-completion.log"

# Execute the deploy-clients admission block. Even a correctly signed image at
# the requested full-SHA tag must fail before producing deploy outputs when its
# post-promotion completion admission is absent.
banking_subject="686831565523.dkr.ecr.us-east-1.amazonaws.com/axonflow-banking-demo"
banking_image_admission="$WORK/banking-image-admission.json"
banking_completion="$WORK/banking-promotion-completion.json"
banking_completion_admission="$WORK/banking-promotion-completion-admission.json"
write_client_admission "$banking_image_admission" "$banking_subject"
python3 "$COMPLETION" write --output "$banking_completion" --repository "$banking_subject" --digest "$image_digest"
banking_completion_hash="$(shasum -a 256 "$banking_completion" | awk '{print $1}')"
jq --arg digest "$banking_completion_hash" \
  '.[0].verificationResult.statement.subject=[{digest:{sha256:$digest}}]' \
  "$completion_admission" > "$banking_completion_admission"
ecommerce_backend_subject="686831565523.dkr.ecr.us-east-1.amazonaws.com/axonflow-ecommerce-backend"
ecommerce_frontend_subject="686831565523.dkr.ecr.us-east-1.amazonaws.com/axonflow-ecommerce-frontend"
ecommerce_backend_image_admission="$WORK/ecommerce-backend-image-admission.json"
ecommerce_frontend_image_admission="$WORK/ecommerce-frontend-image-admission.json"
ecommerce_backend_completion="$WORK/ecommerce-backend-completion.json"
ecommerce_frontend_completion="$WORK/ecommerce-frontend-completion.json"
ecommerce_backend_completion_admission="$WORK/ecommerce-backend-completion-admission.json"
ecommerce_frontend_completion_admission="$WORK/ecommerce-frontend-completion-admission.json"
write_client_admission "$ecommerce_backend_image_admission" "$ecommerce_backend_subject"
write_client_admission "$ecommerce_frontend_image_admission" "$ecommerce_frontend_subject"
python3 "$COMPLETION" write --output "$ecommerce_backend_completion" --repository "$ecommerce_backend_subject" --digest "$image_digest"
python3 "$COMPLETION" write --output "$ecommerce_frontend_completion" --repository "$ecommerce_frontend_subject" --digest "$image_digest"
ecommerce_backend_hash="$(shasum -a 256 "$ecommerce_backend_completion" | awk '{print $1}')"
ecommerce_frontend_hash="$(shasum -a 256 "$ecommerce_frontend_completion" | awk '{print $1}')"
jq --arg digest "$ecommerce_backend_hash" '.[0].verificationResult.statement.subject=[{digest:{sha256:$digest}}]' \
  "$completion_admission" > "$ecommerce_backend_completion_admission"
jq --arg digest "$ecommerce_frontend_hash" '.[0].verificationResult.statement.subject=[{digest:{sha256:$digest}}]' \
  "$completion_admission" > "$ecommerce_frontend_completion_admission"
python3 - "$ROOT/.github/workflows/deploy-clients.yml" "$WORK/deploy-client-admission.sh" <<'PY'
import pathlib, sys, yaml
workflow = yaml.safe_load(pathlib.Path(sys.argv[1]).read_text())
steps = workflow["jobs"]["deploy-client"]["steps"]
run = next(step["run"] for step in steps if step.get("name") == "Validate immutable client images")
pathlib.Path(sys.argv[2]).write_text(run)
PY
mkdir -p "$WORK/deploy-client-bin" "$WORK/deploy-client-tmp"
cat > "$WORK/deploy-client-bin/aws" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
if [[ "$1 $2" == "ecr describe-repositories" ]]; then
  echo IMMUTABLE
elif [[ "$1 $2" == "ecr describe-images" ]]; then
  printf '%s\n' "$MOCK_EXISTING_DIGEST"
else
  exit 2
fi
SH
cat > "$WORK/deploy-client-bin/gh" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
if printf '%s\n' "$*" | grep -q 'oci://'; then
  if printf '%s\n' "$*" | grep -q 'axonflow-ecommerce-backend'; then
    cat "$MOCK_BACKEND_ADMISSION"
  elif printf '%s\n' "$*" | grep -q 'axonflow-ecommerce-frontend'; then
    cat "$MOCK_FRONTEND_ADMISSION"
  else
    cat "$MOCK_ADMISSION"
  fi
else
  [[ "$MOCK_COMPLETION_MODE" == "signed" ]] || { echo no-completion-admission >&2; exit 1; }
  if [[ "${CLIENT:-}" == "banking" ]]; then
    cat "$MOCK_COMPLETION_ADMISSION"
  elif printf '%s\n' "$*" | grep -q 'completion-0.json'; then
    cat "${MOCK_COMPLETION_ADMISSION_0:-$MOCK_COMPLETION_ADMISSION}"
  elif printf '%s\n' "$*" | grep -q 'completion-1.json'; then
    [[ "${MOCK_PARTIAL_PAIR:-false}" != "true" ]] || { echo missing-frontend-completion >&2; exit 1; }
    cat "$MOCK_COMPLETION_ADMISSION_1"
  else
    cat "$MOCK_COMPLETION_ADMISSION"
  fi
fi
SH
chmod +x "$WORK/deploy-client-bin/aws" "$WORK/deploy-client-bin/gh" "$WORK/deploy-client-admission.sh"
run_deploy_admission() {
  local mode="$1" output="$2" client="${3:-banking}" partial="${4:-false}"
  (
    cd "$ROOT"
    PATH="$WORK/deploy-client-bin:$PATH" CLIENT="$client" VERSION="$source_commit" \
      REGION=us-east-1 AWS_ACCOUNT_ID=686831565523 GITHUB_REPOSITORY="$source_repository" \
      RUNNER_TEMP="$WORK/deploy-client-tmp" GITHUB_OUTPUT="$output" GH_TOKEN=test \
      MOCK_EXISTING_DIGEST="$image_digest" MOCK_ADMISSION="$banking_image_admission" \
      MOCK_COMPLETION_MODE="$mode" MOCK_COMPLETION_ADMISSION="$banking_completion_admission" \
      MOCK_BACKEND_ADMISSION="$ecommerce_backend_image_admission" \
      MOCK_FRONTEND_ADMISSION="$ecommerce_frontend_image_admission" \
      MOCK_COMPLETION_ADMISSION_0="$ecommerce_backend_completion_admission" \
      MOCK_COMPLETION_ADMISSION_1="$ecommerce_frontend_completion_admission" \
      MOCK_PARTIAL_PAIR="$partial" \
      bash "$WORK/deploy-client-admission.sh"
  )
}
if run_deploy_admission missing "$WORK/deploy-client-missing.out" >"$WORK/deploy-client-missing.log" 2>&1; then
  echo "FAIL: deploy-clients accepted a stranded full-SHA client tag" >&2
  exit 1
fi
grep -q 'no-completion-admission' "$WORK/deploy-client-missing.log"
[[ ! -s "$WORK/deploy-client-missing.out" ]]
run_deploy_admission signed "$WORK/deploy-client-valid.out"
grep -q "^app_digest=$image_digest$" "$WORK/deploy-client-valid.out"
if run_deploy_admission signed "$WORK/deploy-client-partial-pair.out" ecommerce true \
    >"$WORK/deploy-client-partial-pair.log" 2>&1; then
  echo "FAIL: deploy-clients accepted a partial backend/frontend completion set" >&2
  exit 1
fi
grep -q 'missing-frontend-completion' "$WORK/deploy-client-partial-pair.log"
[[ ! -s "$WORK/deploy-client-partial-pair.out" ]]

# Execute the real workflow reuse block with a pre-existing admitted backend
# and a missing frontend. Partial two-component publication must resume rather
# than forcing cleanup or rebuilding the already admitted backend. Repeat with
# only the durable quarantine identity present to cover failure after signed
# admission but before canonical promotion.
python3 - "$ROOT/.github/workflows/build-client-images.yml" "$WORK/reuse.sh" <<'PY'
import pathlib, sys, yaml
workflow = yaml.safe_load(pathlib.Path(sys.argv[1]).read_text())
steps = workflow["jobs"]["build-client"]["steps"]
run = next(step["run"] for step in steps if step.get("name") == "Resolve existing admitted source images")
pathlib.Path(sys.argv[2]).write_text(run)
PY
mkdir -p "$WORK/reuse-bin" "$WORK/reuse-tmp"
cat > "$WORK/reuse-bin/aws" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
operation="${1:-} ${2:-}"
repository=""; tag=""
while (($#)); do
  case "$1" in
    --repository-name) repository="$2"; shift 2 ;;
    --image-ids) tag="${2#imageTag=}"; shift 2 ;;
    *) shift ;;
  esac
done
if [[ "$operation" == "ecr batch-delete-image" ]]; then
  touch "$MOCK_DELETE_MARKER"
  exit 0
fi
if [[ -f "$MOCK_DELETE_MARKER" && "$repository" == "axonflow-ecommerce-backend" ]]; then
  echo ImageNotFoundException >&2
  exit 254
fi
if [[ "$repository" == "axonflow-ecommerce-backend" ]] && \
   { [[ "$MOCK_BACKEND_MODE" == "canonical" && "$tag" == "$SOURCE_COMMIT" ]] || \
     [[ "$MOCK_BACKEND_MODE" == "quarantine" && "$tag" == "quarantine-$SOURCE_COMMIT" ]]; }; then
  printf '%s\n' "$MOCK_EXISTING_DIGEST"
  exit 0
fi
echo ImageNotFoundException >&2
exit 254
SH
cat > "$WORK/reuse-bin/gh" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
if printf '%s\n' "$*" | grep -q 'oci://'; then
  [[ "$MOCK_ADMISSION_MODE" == "signed" ]] || exit 1
  cat "$MOCK_ADMISSION"
else
  [[ "$MOCK_COMPLETION_MODE" == "signed" ]] || exit 1
  cat "$MOCK_COMPLETION_ADMISSION"
fi
SH
chmod +x "$WORK/reuse-bin/aws" "$WORK/reuse-bin/gh" "$WORK/reuse.sh"
run_reuse_fixture() {
  local mode="$1"
  local output="$WORK/reuse-$mode.out"
  : > "$output"
  (
    cd "$ROOT"
    PATH="$WORK/reuse-bin:$PATH" \
      CLIENT_TYPE=backend-frontend \
      BACKEND_REPO="$subject_name" \
      FRONTEND_REPO="686831565523.dkr.ecr.us-east-1.amazonaws.com/axonflow-ecommerce-frontend" \
      APP_REPO="" SOURCE_COMMIT="$source_commit" GITHUB_REPOSITORY="$source_repository" \
      RUNNER_TEMP="$WORK/reuse-tmp" GITHUB_OUTPUT="$output" GH_TOKEN=test \
      MOCK_BACKEND_MODE="$mode" MOCK_EXISTING_DIGEST="$image_digest" MOCK_ADMISSION="$WORK/admission.json" \
      MOCK_ADMISSION_MODE=signed MOCK_COMPLETION_MODE=signed MOCK_COMPLETION_ADMISSION="$completion_admission" \
      MOCK_DELETE_MARKER="$WORK/reuse-tmp/deleted-$mode" \
      bash "$WORK/reuse.sh"
  )
  grep -q "^backend_digest=$image_digest$" "$output"
  grep -q '^frontend_digest=$' "$output"
}
run_reuse_fixture canonical
run_reuse_fixture quarantine

# A retry may recover a full-SHA tag stranded by process death or ambiguous
# post-write readback, but it must not claim that tag is completed. The build
# continues only from exact signed image provenance and creates a fresh signed
# completion after its idempotent promotion step.
stranded_output="$WORK/reuse-stranded.out"
(
  cd "$ROOT"
  PATH="$WORK/reuse-bin:$PATH" \
    CLIENT_TYPE=backend-frontend BACKEND_REPO="$subject_name" \
    FRONTEND_REPO="686831565523.dkr.ecr.us-east-1.amazonaws.com/axonflow-ecommerce-frontend" \
    APP_REPO="" SOURCE_COMMIT="$source_commit" GITHUB_REPOSITORY="$source_repository" \
    RUNNER_TEMP="$WORK/reuse-tmp" GITHUB_OUTPUT="$stranded_output" GH_TOKEN=test \
    MOCK_BACKEND_MODE=canonical MOCK_EXISTING_DIGEST="$image_digest" MOCK_ADMISSION="$WORK/admission.json" \
    MOCK_ADMISSION_MODE=signed MOCK_COMPLETION_MODE=missing MOCK_COMPLETION_ADMISSION="$completion_admission" \
    MOCK_DELETE_MARKER="$WORK/reuse-tmp/deleted-stranded" \
    bash "$WORK/reuse.sh"
) >"$WORK/reuse-stranded.log" 2>&1
grep -q "^backend_digest=$image_digest$" "$stranded_output"
grep -q 'recovering canonical client identity without completed-promotion admission' "$WORK/reuse-stranded.log"

unsigned_output="$WORK/reuse-unsigned.out"
unsigned_marker="$WORK/reuse-tmp/deleted-unsigned"
: > "$unsigned_output"
(
  cd "$ROOT"
  PATH="$WORK/reuse-bin:$PATH" \
    CLIENT_TYPE=backend-frontend BACKEND_REPO="$subject_name" \
    FRONTEND_REPO="686831565523.dkr.ecr.us-east-1.amazonaws.com/axonflow-ecommerce-frontend" \
    APP_REPO="" SOURCE_COMMIT="$source_commit" GITHUB_REPOSITORY="$source_repository" \
    RUNNER_TEMP="$WORK/reuse-tmp" GITHUB_OUTPUT="$unsigned_output" GH_TOKEN=test \
    MOCK_BACKEND_MODE=quarantine MOCK_EXISTING_DIGEST="$image_digest" MOCK_ADMISSION="$WORK/admission.json" \
    MOCK_ADMISSION_MODE=unsigned MOCK_COMPLETION_MODE=missing MOCK_COMPLETION_ADMISSION="$completion_admission" \
    MOCK_DELETE_MARKER="$unsigned_marker" \
    bash "$WORK/reuse.sh"
)
[[ -f "$unsigned_marker" ]]
grep -q '^backend_digest=$' "$unsigned_output"
grep -q '^frontend_digest=$' "$unsigned_output"

canonical_unsigned_output="$WORK/reuse-canonical-unsigned.out"
canonical_unsigned_marker="$WORK/reuse-tmp/deleted-canonical-unsigned"
if (
  cd "$ROOT"
  PATH="$WORK/reuse-bin:$PATH" \
    CLIENT_TYPE=backend-frontend BACKEND_REPO="$subject_name" \
    FRONTEND_REPO="686831565523.dkr.ecr.us-east-1.amazonaws.com/axonflow-ecommerce-frontend" \
    APP_REPO="" SOURCE_COMMIT="$source_commit" GITHUB_REPOSITORY="$source_repository" \
    RUNNER_TEMP="$WORK/reuse-tmp" GITHUB_OUTPUT="$canonical_unsigned_output" GH_TOKEN=test \
    MOCK_BACKEND_MODE=canonical MOCK_EXISTING_DIGEST="$image_digest" MOCK_ADMISSION="$WORK/admission.json" \
    MOCK_ADMISSION_MODE=unsigned MOCK_COMPLETION_MODE=missing MOCK_COMPLETION_ADMISSION="$completion_admission" \
    MOCK_DELETE_MARKER="$canonical_unsigned_marker" \
    bash "$WORK/reuse.sh"
) >"$WORK/canonical-unsigned.log" 2>&1; then
  echo "FAIL: unsigned canonical identity was accepted" >&2
  exit 1
fi
grep -q 'canonical client identity lacks trusted signed admission' "$WORK/canonical-unsigned.log"
[[ ! -e "$canonical_unsigned_marker" ]]

mkdir -p "$WORK/bin" "$WORK/tags" "$WORK/markers"
export MOCK_TAG_DIR="$WORK/tags" MOCK_MARKERS="$WORK/markers" MOCK_LOG="$WORK/registry.log" MOCK_RACE_TAG=""
cat > "$WORK/bin/aws" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
printf 'aws %s\n' "$*" >> "$MOCK_LOG"
if [[ "$1 $2" == "ecr describe-repositories" ]]; then
  if [[ -f "$MOCK_MARKERS/mutable" ]]; then echo MUTABLE; else echo IMMUTABLE; fi
elif [[ "$1 $2" == "ecr describe-images" ]]; then
  tag=""; for arg in "$@"; do [[ "$arg" == imageTag=* ]] && tag="${arg#imageTag=}"; done
  if [[ -f "$MOCK_MARKERS/unavailable-$tag" ]]; then echo RegistryUnavailable >&2; exit 70; fi
if [[ -f "$MOCK_MARKERS/race" && "$tag" == "$MOCK_RACE_TAG" && ! -f "$MOCK_MARKERS/seen-$PPID" ]]; then
    touch "$MOCK_MARKERS/seen-$PPID"
    for _ in {1..500}; do
      arrivals=$(find "$MOCK_MARKERS" -name 'seen-*' -type f | wc -l | tr -d ' ')
      if [[ "$arrivals" -ge 2 ]]; then touch "$MOCK_MARKERS/released"; break; fi
      sleep 0.01
    done
    [[ -f "$MOCK_MARKERS/released" ]] || exit 70
    echo ImageNotFoundException >&2; exit 254
  fi
  if [[ -f "$MOCK_TAG_DIR/$tag" ]]; then cat "$MOCK_TAG_DIR/$tag"; else echo ImageNotFoundException >&2; exit 254; fi
else
  exit 2
fi
SH
cat > "$WORK/bin/docker" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
printf 'docker %s\n' "$*" >> "$MOCK_LOG"
tag=""; source="${!#}"; digest="${source##*@}"
while (($#)); do if [[ "$1" == "-t" ]]; then tag="${2##*:}"; shift 2; else shift; fi; done
lock="$MOCK_TAG_DIR/.lock-$tag"
for _ in {1..500}; do mkdir "$lock" 2>/dev/null && break; sleep 0.01; done
[[ -d "$lock" ]] || exit 70
if [[ -f "$MOCK_TAG_DIR/$tag" ]]; then rmdir "$lock"; exit 1; fi
printf '%s\n' "$digest" > "$MOCK_TAG_DIR/$tag"
if [[ -n "${MOCK_PERSISTENT_TAG:-}" && "$tag" == "$MOCK_PERSISTENT_TAG" ]]; then
  touch "$MOCK_MARKERS/unavailable-$tag"
fi
rmdir "$lock"
SH
chmod +x "$WORK/bin/aws" "$WORK/bin/docker"

repository="123456789012.dkr.ecr.us-east-1.amazonaws.com/axonflow-ecommerce-backend"
digest="sha256:$(printf 'a%.0s' {1..64})"
canonical_tag="$(printf 'b%.0s' {1..40})"
promote=(python3 "$PROMOTER" --repository "$repository" --ecr-repository-name axonflow-ecommerce-backend --digest "$digest" --tag "$canonical_tag")
PATH="$WORK/bin:$PATH" "${promote[@]}"
docker_count=$(grep -c '^docker ' "$MOCK_LOG")
PATH="$WORK/bin:$PATH" "${promote[@]}"
[[ "$(grep -c '^docker ' "$MOCK_LOG")" -eq "$docker_count" ]]

# A persistent registry-read failure after the immutable full-SHA write leaves
# the tag in place but the workflow failed before it could sign completion.
# Bare tag + pre-promotion provenance therefore remains non-deployable.
MOCK_PERSISTENT_TAG="$(printf '7%.0s' {1..40})"
export MOCK_PERSISTENT_TAG
if PATH="$WORK/bin:$PATH" python3 "$PROMOTER" \
    --repository "$repository" --ecr-repository-name axonflow-ecommerce-backend \
    --digest "$digest" --tag "$MOCK_PERSISTENT_TAG" >"$WORK/persistent-read.log" 2>&1; then
  echo "FAIL: persistent post-write registry failure was accepted" >&2
  exit 1
fi
grep -q 'cannot read tag' "$WORK/persistent-read.log"
[[ "$(cat "$MOCK_TAG_DIR/$MOCK_PERSISTENT_TAG")" == "$digest" ]]
if python3 "$COMPLETION" verify \
    --manifest "$WORK/persistent-read-completion.json" \
    --verification "$WORK/persistent-read-completion-admission.json" \
    --repository "$repository" --digest "$digest" \
    --source-repository "$source_repository" --source-ref refs/heads/main \
    --source-commit "$source_commit" --workflow .github/workflows/build-client-images.yml \
    >"$WORK/persistent-read-unadmitted.log" 2>&1; then
  echo "FAIL: stranded full-SHA tag was deployable after persistent read failure" >&2
  exit 1
fi
grep -q 'cannot read completed promotion admission' "$WORK/persistent-read-unadmitted.log"
rm "$MOCK_MARKERS/unavailable-$MOCK_PERSISTENT_TAG"
unset MOCK_PERSISTENT_TAG

if PATH="$WORK/bin:$PATH" python3 "$PROMOTER" --repository "$repository" --ecr-repository-name axonflow-ecommerce-backend --digest "$digest" --tag "$(printf 'd%.0s' {1..40})" --tag "$canonical_tag" >"$WORK/multi-tag.log" 2>&1; then
  echo "FAIL: split multi-tag client identity was accepted" >&2
  exit 1
fi
grep -q 'exactly one canonical full' "$WORK/multi-tag.log"

other="sha256:$(printf 'c%.0s' {1..64})"
if PATH="$WORK/bin:$PATH" python3 "$PROMOTER" --repository "$repository" --ecr-repository-name axonflow-ecommerce-backend --digest "$other" --tag "$canonical_tag" >"$WORK/collision.log" 2>&1; then
  echo "FAIL: existing tag with a different digest was accepted" >&2
  exit 1
fi
grep -q 'identifies.*expected' "$WORK/collision.log"

touch "$MOCK_MARKERS/mutable"
if PATH="$WORK/bin:$PATH" python3 "$PROMOTER" --repository "$repository" --ecr-repository-name axonflow-ecommerce-backend --digest "$digest" --tag "$(printf 'e%.0s' {1..40})" >"$WORK/mutable.log" 2>&1; then
  echo "FAIL: mutable repository was accepted" >&2
  exit 1
fi
grep -q 'IMMUTABLE' "$WORK/mutable.log"; rm "$MOCK_MARKERS/mutable"

touch "$MOCK_MARKERS/race"; rm -f "$MOCK_MARKERS"/seen-* "$MOCK_MARKERS/released"
export MOCK_RACE_TAG="$(printf 'f%.0s' {1..40})"
race=(python3 "$PROMOTER" --repository "$repository" --ecr-repository-name axonflow-ecommerce-backend --digest "$digest" --tag "$MOCK_RACE_TAG")
set +e
PATH="$WORK/bin:$PATH" "${race[@]}" >"$WORK/race-a.log" 2>&1 & a=$!
PATH="$WORK/bin:$PATH" "${race[@]}" >"$WORK/race-b.log" 2>&1 & b=$!
wait "$a"; a_status=$?
wait "$b"; b_status=$?
set -e
[[ "$a_status" -eq 0 && "$b_status" -eq 0 ]]
[[ "$(cat "$MOCK_TAG_DIR/$MOCK_RACE_TAG")" == "$digest" ]]

quarantine_tag="quarantine-$(printf '9%.0s' {1..40})"
PATH="$WORK/bin:$PATH" python3 "$PROMOTER" --repository "$repository" --ecr-repository-name axonflow-ecommerce-backend --digest "$digest" --quarantine --tag "$quarantine_tag"
if PATH="$WORK/bin:$PATH" python3 "$PROMOTER" --repository "$repository" --ecr-repository-name axonflow-ecommerce-backend --digest "$other" --quarantine --tag "$quarantine_tag" >"$WORK/quarantine-collision.log" 2>&1; then
  echo "FAIL: pre-promotion retry replaced a different admitted quarantine digest" >&2
  exit 1
fi
grep -q 'identifies.*expected' "$WORK/quarantine-collision.log"

echo "ok: client allowlist, signed source admission, single identity, region, retry, and Portal topology fail closed"
