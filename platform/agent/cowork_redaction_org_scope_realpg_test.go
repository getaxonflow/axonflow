// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

//go:build enterprise

package agent

// #3048 R3 HIGH-3 (N1) real-PG regression for the cowork/OTLP storage-
// redaction plane — enterprise-tagged because coworkRedactDefault ships in
// the enterprise build. Reuses setup3048Fixture from
// rls_blind_reads_3048_approle_test.go (same package, compiled together
// under the enterprise tag).

import (
	"context"
	"strings"
	"testing"

	sharedpolicy "axonflow/platform/shared/policy"
)

// TestCoworkRedactionOrgTenantSplitUnderAppRole is the #3048 R3 HIGH-3 (N1)
// real-PG regression for the cowork/OTLP storage-redaction plane: an
// org-CUSTOM tenant-tier PII policy (org_id != tenant_id) must be applied at
// REDACTION time, not just derived. The bug was that PoliciesLoadable +
// EnabledPIICategories derived the custom category under the ORG scope, but
// EvaluateResponse evaluated under the TENANT fallback — so on app-role the
// custom pattern was RLS-invisible at evaluation and the content persisted
// UNREDACTED (violating the storage-redactor invariant at
// pii_detector.go:1027). The vacuity control evaluates the SAME content under
// the tenant scope (the pre-fix shape) and proves the marker survives.
func TestCoworkRedactionOrgTenantSplitUnderAppRole(t *testing.T) {
	f := setup3048Fixture(t)
	const orgID = "rls3048-cowork-org"
	const tenantID = "rls3048-cowork-tenant"
	f.seedOrg(t, orgID)
	f.applyMigration(t, "153_backfill_global_policy_org_id.sql")
	f.applyMigration(t, "154_global_policy_org_id_default.sql")

	// Org-custom tenant-tier PII REDACT policy, stamped with the ORG key
	// (org≠tenant). Redaction is response-phase, so action_response='redact'
	// with action_request NULL (the API rejects a request-phase 'redact' via
	// the mig-039/044 check constraint); seed directly on the master pool to
	// pin that exact shape. org_id=orgID is what makes it RLS-invisible under
	// a tenant-scoped read — the whole point of the test.
	if _, err := f.masterDB.Exec(`
		INSERT INTO static_policies (
			id, policy_id, name, category, pattern, severity, action, tier,
			priority, enabled, tenant_id, client_id, org_id,
			phase, action_request, action_response, created_at, updated_at
		) VALUES (
			gen_random_uuid(), 'cowork_custom_pii_marker', 'Cowork Custom PII Marker',
			'pii-singapore', 'CUSTOMPII_[0-9]{6}', 'high', 'redact', 'tenant',
			90, true, $1, $1, $2,
			'response', NULL, 'redact', NOW(), NOW()
		)
	`, tenantID, orgID); err != nil {
		t.Fatalf("seed custom PII policy: %v", err)
	}

	cfg := sharedpolicy.DefaultEngineConfig()
	cfg.RefreshInterval = 0
	cfg.EnableMetrics = false
	engine := sharedpolicy.NewUnifiedPolicyEngine(f.appRoleDB, cfg, &sharedpolicy.NoOpAuditQueue{})
	defer engine.Stop()

	const content = "audit note: leaked CUSTOMPII_123456 in the log"
	row := []map[string]interface{}{{"statement": content}}

	// The custom category is derived under the ORG scope (what the cowork
	// gate does).
	piiCats := engine.EnabledPIICategories(context.Background(), tenantID, sharedpolicy.OrgScopePtr(orgID), sharedpolicy.PhaseResponse)
	if len(piiCats) == 0 {
		t.Fatal("fixture broken: custom pii-singapore policy not derived under the org scope")
	}
	overrides := map[sharedpolicy.PolicyCategory]sharedpolicy.Action{}
	for _, c := range piiCats {
		overrides[c] = sharedpolicy.ActionRedact
	}

	// Vacuity control — pre-fix shape: EvaluateResponse under the TENANT
	// fallback (OrganizationID = tenant). The custom pattern is RLS-invisible
	// at evaluation → NOT redacted → raw marker survives to storage.
	engine.InvalidateCache(tenantID, sharedpolicy.OrgScopePtr(tenantID))
	pre := engine.EvaluateResponse(context.Background(), row, sharedpolicy.EvalOptions{
		TenantID:        tenantID,
		OrganizationID:  sharedpolicy.OrgScopePtr(tenantID), // the pre-fix tenant fallback
		Categories:      piiCats,
		ActionOverrides: overrides,
		MaxRedactions:   100,
	})
	if pre.Redacted {
		t.Fatalf("vacuity control broken: content redacted under the tenant-fallback scope (the bug would be invisible)")
	}

	// Post-fix: EvaluateResponse under the ORG scope (what the N1 fix now
	// threads). The custom pattern is visible → the marker is redacted.
	engine.InvalidateCache(tenantID, sharedpolicy.OrgScopePtr(orgID))
	post := engine.EvaluateResponse(context.Background(), row, sharedpolicy.EvalOptions{
		TenantID:        tenantID,
		OrganizationID:  sharedpolicy.OrgScopePtr(orgID), // the N1 fix
		Categories:      piiCats,
		ActionOverrides: overrides,
		MaxRedactions:   100,
	})
	if post.EvaluationError {
		t.Fatalf("post-fix load failed under the org scope")
	}
	if !post.Redacted {
		t.Fatal("org-custom PII policy NOT applied at redaction under the org scope — the cowork storage-redaction plane persists raw content (#3048 R3 N1)")
	}
	if out, ok := post.Content.([]map[string]interface{}); ok {
		if s, _ := out[0]["statement"].(string); strings.Contains(s, "CUSTOMPII_123456") {
			t.Fatalf("raw custom-PII marker survived redaction: %q", s)
		}
	}

	// End-to-end through the wired cowork entry point: with detection enabled
	// + the engine wired + the caller org in context, coworkRedactDefault must
	// mask the marker (the whole plane, not just the engine call).
	origEngine := sharedpolicy.GetGlobalEngine()
	sharedpolicy.SetGlobalEngine(engine)
	defer sharedpolicy.SetGlobalEngine(origEngine)
	detectionConfigMu.Lock()
	origCfg := cachedMCPConfig
	cachedMCPConfig = &ModeDetectionConfig{Enabled: true, PIIAction: DetectionActionRedact}
	detectionConfigMu.Unlock()
	defer func() {
		detectionConfigMu.Lock()
		cachedMCPConfig = origCfg
		detectionConfigMu.Unlock()
	}()

	coworkCtx := context.WithValue(context.Background(), ContextKeyOrgID, orgID)
	coworkCtx = context.WithValue(coworkCtx, ContextKeyTenantID, tenantID)
	res := coworkRedactDefault(coworkCtx, tenantID, "user-1", "cowork", content)
	if strings.Contains(res.text, "CUSTOMPII_123456") {
		t.Fatalf("coworkRedactDefault persisted the raw custom-PII marker: %q (verdict=%s)", res.text, res.verdict)
	}
}
