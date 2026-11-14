#!/usr/bin/env bash
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

expected_up="migrations/community-saas/205_hosted_outcome_module_quota.sql"
expected_down="migrations/community-saas/205_hosted_outcome_module_quota_down.sql"

shopt -s nullglob
all_205=(migrations/community-saas/205_*.sql)
up_205=()
down_205=()
for file in "${all_205[@]}"; do
  if [[ "$file" == *_down.sql ]]; then
    down_205+=("$file")
  else
    up_205+=("$file")
  fi
done

if [[ ${#up_205[@]} -ne 1 || "${up_205[0]:-}" != "$expected_up" ]]; then
  printf 'community-saas migration 205 collision: expected only %s, found: %s\n' \
    "$expected_up" "${up_205[*]:-(none)}" >&2
  exit 1
fi
if [[ ${#down_205[@]} -ne 1 || "${down_205[0]:-}" != "$expected_down" ]]; then
  printf 'community-saas migration 205 down-file mismatch: expected only %s, found: %s\n' \
    "$expected_down" "${down_205[*]:-(none)}" >&2
  exit 1
fi

rg -q "p_module_id NOT IN \('payment_exception', 'support_refund'\)" "$expected_up"
rg -q "capability_not_granted" "$expected_up"
rg -q "hosted_outcome_operation_admissions" "$expected_up"
rg -q "hosted_outcome_monthly_usage_legacy_195" "$expected_up"
rg -q "hosted_customer_authority_keys" "$expected_up"
rg -q "hosted_module_authority_audit" "$expected_up"
rg -q "hosted_module_manifest_trust_history" "$expected_up"
rg -q "manifest_revocation_id" "$expected_up"
rg -q "module_grant_revoked_by_trust" "$expected_up"
rg -q "module_trust_confirmed" "$expected_up"
rg -q "status IN \\('reserved', 'committed', 'released', 'reconciled', 'expired'\\)" "$expected_up"
rg -q "hosted_outcome_commit_operation" "$expected_up"
rg -q "hosted_outcome_release_operation" "$expected_up"
rg -q "hosted_outcome_reconcile_operation" "$expected_up"
rg -q "runtime_artifact_sha256" "$expected_up"
rg -q "readiness_schema_sha256" "$expected_up"
rg -q "policy_artifact_sha256" "$expected_up"
rg -q "policy_active BOOLEAN" "$expected_up"
rg -q "policy_reason TEXT" "$expected_up"
rg -Fq "deployment_mode IN ('hosted', 'self_hosted')" "$expected_up"
rg -q "hosted_outcome_self_hosted_eligibility" "$expected_up"
rg -q "eligibility_active BOOLEAN" "$expected_up"
rg -q "self_hosted_license_expired" "$expected_up"
rg -q "license_deployment_id" "$expected_up"
rg -q "subscription_active BOOLEAN" "$expected_up"
rg -Fq "policy_id = 'payment_exception.retry_approval'" "$expected_up"
rg -Fq "policy_schema_sha256 = '0aaac12614a336ea0e3310620eaf499e9eefd79a4a075ea1765da0c0c50cc839'" "$expected_up"
rg -Fq "policy_artifact_sha256 = '245d20a13a1dc52e40d3a67202119ba2d3dabeda16b3da8314b9805e68e38de5'" "$expected_up"
rg -Fq "policy_id = 'support_refund.issue_approval'" "$expected_up"
rg -Fq "policy_schema_sha256 = '59ba84db8e7d3788dfc3a11149fd027340e8d33ff4a3bc15c032fc223e3db5d7'" "$expected_up"
rg -Fq "policy_artifact_sha256 = 'a66b1698521de773b12c36e620d167dcd9c8f5326ce0c68fc25a1f8034c1f070'" "$expected_up"
rg -q "hosted_outcome_module_identity" "$expected_up"
rg -q "hosted_outcome_admit_operation" \
  ee/examples/payment-exception-shadow/durable_store.py
rg -q "hosted_outcome_commit_operation" \
  ee/examples/payment-exception-shadow/durable_store.py
# There is exactly one production HTTP create seam. It must forward the
# Portal-HMAC-verified raw-body digest into the repository's atomic
# reserve -> case insert -> commit transaction. The old standalone app mode is
# retained only as an explicit fail-closed CLI tombstone for safe upgrades.
rg -Fq 'repository.create(principal.organization_id, principal.tenant_id, module, case_id,' \
  ee/examples/payment-exception-shadow/hosted_service.py
rg -Fq 'self.headers["X-AxonFlow-Internal-Body-SHA256"]' \
  ee/examples/payment-exception-shadow/hosted_service.py
rg -q -- '--durable-hosted was retired; use hosted_service.py with signed module grants' \
  ee/examples/payment-exception-shadow/app.py
if rg -q 'PostgresSyntheticExecutor' \
  ee/examples/payment-exception-shadow/app.py \
  ee/examples/payment-exception-shadow/hosted_service.py; then
  echo 'production payment/refund services must not use the synthetic Postgres executor' >&2
  exit 1
fi
rg -q "forward-only" "$expected_down"

if LC_ALL=C rg -n $'\xE2\x80\x94' "$expected_up" "$expected_down" \
  platform/agent/capabilityplane/module_grant.go \
  platform/agent/capabilityplane/module_grant_test.go \
  ee/platform/hostedmoduleauthority \
  ee/examples/payment-exception-shadow/test_module_quota_realpg.py; then
  echo 'migration 205 change set must not contain an em dash' >&2
  exit 1
fi

echo 'community-saas migration 205 source guard passed'
