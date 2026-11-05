#!/usr/bin/env bash
# Production parameter preservation and read-only inventory must stay coupled
# to the update-stack dry-run/apply workflow.
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
bash "$root/scripts/deployment/check-hosted-gate-drift_test.sh"
bash "$root/scripts/deployment/assert-stack-identity_test.sh"
bash "$root/scripts/deployment/assert-image-tag_test.sh"
bash "$root/scripts/deployment/assert-aws-account_test.sh"
bash "$root/scripts/deployment/resolve-running-image-label_test.sh"
bash "$root/scripts/deployment/resolve-running-image-tags_test.sh"
python3 "$root/scripts/deployment/audit-stack-change_test.py"
python3 "$root/scripts/deployment/pin-production-image-digests_test.py"
python3 "$root/scripts/deployment/audit-processed-change-set_test.py"
python3 - "$root/.github/workflows/update-stack.yml" \
  "$root/ee/platform/aws-marketplace/cloudformation-ecs-fargate.yaml" <<'PY'
from pathlib import Path
import sys

workflow = Path(sys.argv[1]).read_text()
partner_template = Path(sys.argv[2]).read_text()
guarded = "inputs.environment == 'community-saas' || inputs.environment == 'production-us'"
assert workflow.count('if: ${{ ' + guarded + ' }}') == 3
assert workflow.count('"$ENVIRONMENT" == community-saas || "$ENVIRONMENT" == production-us') == 5
assert '"$TARGET_ENVIRONMENT" == community-saas || "$TARGET_ENVIRONMENT" == production-us' in workflow
assert workflow.count('"${{ inputs.environment }}" == community-saas || "${{ inputs.environment }}" == production-us') == 2
for name, repository in (
    ('Agent', 'agent'), ('Orchestrator', 'orchestrator'),
    ('CustomerPortal', 'customer-portal'),
    ('CustomerPortalUI', 'customer-portal-ui'),
    ('CaseWorkflows', 'case-workflows'),
    ('Prometheus', 'prometheus'), ('Grafana', 'grafana'),
    ('PerformanceTesting', 'performance-testing'),
):
    assert f'  {name}ImageDigest:' in partner_template
    assert f'  Use{name}ImageDigest:' in partner_template
    assert f'${{ContainerImageRegistry}}/axonflow-{repository}@${{{name}ImageDigest}}' in partner_template
preview = workflow.split("- name: Create change set preview", 1)[1].split(
    "- name: Attach production parameter and template inventory", 1)[0]
apply = workflow.split("- name: Verify reviewed production parameter and template inventory", 1)[1].split(
    "- name: Update CloudFormation stack", 1)[0]
pin = "scripts/deployment/pin-production-image-digests.py"
audit = "scripts/deployment/audit-stack-change.py"
assert preview.index(pin) < preview.index(audit) < preview.index("create-change-set")
assert apply.index(pin) < apply.index(audit)
assert '--source-sha "$EXPECTED_SOURCE_SHA"' in preview
assert '--source-sha "$EXPECTED_SOURCE_SHA"' in apply
assert workflow.index("- name: Verify reviewed production parameter and template inventory") < workflow.index(
    "- name: Update CloudFormation stack")
execute = workflow.split("- name: Update CloudFormation stack", 1)[1].split(
    "- name: Wait for update completion", 1)[0]
assert execute.index("audit-processed-change-set.py") < execute.index("execute-change-set")
assert execute.index("execute-change-set") < execute.index("update-stack")
assert "EXPECTED_CHANGE_SET_ARN" in execute and "EXPECTED_CHANGE_SET_FINGERPRINT" in execute
assert "CLEANUP_CHANGE_SET=false" in preview
assert workflow.count("- name: Assert deployment AWS account") == 3
assert workflow.count('run: bash scripts/deployment/assert-aws-account.sh "$AWS_ACCOUNT_ID"') == 3
resolver = workflow.split("- name: Resolve image tags from running ECS services", 1)[1].split(
    "- name: Override service image tags", 1)[0]
shared_resolver = "scripts/deployment/resolve-running-image-tags.sh"
assert shared_resolver in resolver
assert preview.index(shared_resolver) < preview.index("OVERRIDE_KEYS=") < preview.index(pin)
assert 'TAG="${IMAGE##*:}"' not in resolver
print("PASS: both production stacks pin images and source, retain and execute the exact reviewed change set, and bind AWS account")
PY
actionlint_bin=$(command -v actionlint || true)
if [ -n "$actionlint_bin" ]; then
  "$actionlint_bin" -shellcheck= "$root/.github/workflows/update-stack.yml"
fi
