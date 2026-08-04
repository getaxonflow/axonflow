//go:build enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package ojk

// Real-Postgres behaviour tests for the OJK module (#3242).
//
// Gated on TEST_PG_INTEGRATION=1 + docker (see ojk_realpg_fixture_test.go for
// why that gate, and not DATABASE_URL). These are the assertions sqlmock cannot
// make: cross-org refusal against real rows, the app-role RLS posture, and every
// readiness check FLIPPING with the state it claims to measure.
//
// Grouped into four top-level tests so the run pays for four throwaway
// containers rather than a dozen.

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// mustJSON renders a whole response so a leak assertion can scan the ENTIRE
// document rather than the fields the test happened to think of.
func mustJSON(t *testing.T, v interface{}) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(b)
}

// -----------------------------------------------------------------------------
// Export sections
// -----------------------------------------------------------------------------

func TestRealPG_ExportSections(t *testing.T) {
	env := newOJKPGEnv(t)
	env.seedExportFixture(t)
	ctx := context.Background()

	// -------------------------------------------------------------------------
	// The cross-org refusal proof. Every section is driven against real rows,
	// and each assertion checks BOTH that org A's evidence is present AND that
	// org B's row -- which carries org A's tenant identifier -- is absent.
	// Reverting any section's predicate to the `(tenant_id = $1 OR org_id = $1)`
	// conflation makes this fail with the leaked row named.
	// -------------------------------------------------------------------------
	t.Run("org-scoped across every section", func(t *testing.T) {
		resp, err := env.svc.ExportAuditData(ctx, fxOrgA, &OJKAuditExportRequest{
			StartDate: "2026-07-01", EndDate: "2026-07-31",
			Framework: OJKFrameworkCombined,
		})
		if err != nil {
			t.Fatalf("ExportAuditData: %v", err)
		}

		if len(resp.Summary.Sections) != len(ojkAllDataTypes()) {
			t.Fatalf("sections = %d, want %d", len(resp.Summary.Sections), len(ojkAllDataTypes()))
		}
		for _, sec := range resp.Summary.Sections {
			if sec.Error != "" {
				t.Errorf("section %q errored on a fully-migrated database: %s (%s)", sec.DataType, sec.Error, sec.ErrorKind)
			}
		}

		body := mustJSON(t, resp)
		for _, leak := range []string{"org B secret", fxOrgB, "gpt-4o", fxPrefix + "al-b1", fxPrefix + "pii-b1", fxPrefix + "br-b1"} {
			if strings.Contains(body, leak) {
				t.Errorf("org A's export contains %q, which belongs to org B", leak)
			}
		}

		if got := len(resp.Data.PolicyViolations); got != 1 {
			t.Errorf("policy_violations = %d, want 1 (org A's blocked decision only)", got)
		} else if resp.Data.PolicyViolations[0].PolicyID != "indonesia_pii_protection" {
			t.Errorf("policy_id = %q", resp.Data.PolicyViolations[0].PolicyID)
		}

		if got := len(resp.Data.LLMCalls); got != 1 {
			t.Errorf("llm_calls = %d, want 1", got)
		} else {
			c := resp.Data.LLMCalls[0]
			if c.Provider != "anthropic" || c.ModelID != "claude-haiku-4-5" {
				t.Errorf("llm call = %s/%s", c.Provider, c.ModelID)
			}
			if c.TransferBasis != "pasal_56b_dpa" {
				t.Errorf("transfer_basis = %q", c.TransferBasis)
			}
		}

		if got := len(resp.Data.DecisionChains); got != 2 {
			t.Errorf("decision_chain steps = %d, want 2", got)
		}
		if got := len(resp.Data.DecisionChainGroups); got != 2 {
			t.Errorf("decision chains = %d, want 2 singleton chains", got)
		}
		if got := len(resp.Data.HITLRecords); got != 1 {
			t.Errorf("hitl_records = %d, want 1 (reviewed only; the pending row must be excluded)", got)
		} else if resp.Data.HITLRecords[0].ReviewTimeMS != 90000 {
			t.Errorf("review_time_ms = %d, want 90000", resp.Data.HITLRecords[0].ReviewTimeMS)
		}

		if got := len(resp.Data.PIIRedactions); got != 2 {
			t.Errorf("pii_redactions = %d, want 2", got)
		} else {
			categories := map[string]bool{}
			for _, r := range resp.Data.PIIRedactions {
				categories[r.OJKCategory] = true
				if r.MaskedValue == "" {
					t.Error("a PII redaction record has no masked value")
				}
			}
			if !categories["national_identity"] || !categories["financial_account"] {
				t.Errorf("OJK categories = %v", categories)
			}
		}

		if got := len(resp.Data.CrossBorder); got != 1 {
			t.Errorf("cross_border_transfers = %d, want 1", got)
		}
		if got := len(resp.Data.BreachNotifications); got != 1 {
			t.Errorf("breach_notifications = %d, want 1", got)
		}
		if resp.Summary.ReportState != OJKReportStatePopulated {
			t.Errorf("report_state = %q, want populated", resp.Summary.ReportState)
		}
	})

	// -------------------------------------------------------------------------
	// The blank-org corpus. audit_logs.org_id is nullable and no core migration
	// constrains it, so a single-identifier deployment writes rows with a blank
	// org and a real tenant. A predicate on org_id ALONE drops them and the
	// section reports enabled_empty -- "the honest answer is zero rows" -- which
	// is a FALSE claim of honesty, the exact defect this workstream removes.
	// -------------------------------------------------------------------------
	t.Run("rows with a blank org are reachable by their tenant", func(t *testing.T) {
		resp, err := env.svc.ExportAuditData(ctx, fxOrgOrphan, &OJKAuditExportRequest{
			StartDate: "2026-07-01", EndDate: "2026-07-31",
			Framework: OJKFrameworkCombined,
		})
		if err != nil {
			t.Fatalf("ExportAuditData: %v", err)
		}
		if got := len(resp.Data.LLMCalls); got != 1 {
			t.Errorf("llm_calls = %d, want 1: the blank-org row is unreachable, so this section reports a confident empty", got)
		}
		if got := len(resp.Data.CrossBorder); got != 1 {
			t.Errorf("cross_border_transfers = %d, want 1", got)
		}
		if got := len(resp.Data.PolicyViolations); got != 1 {
			t.Errorf("policy_violations = %d, want 1", got)
		}

		// And the orphan clause must NOT become a back door: org A and org B own
		// their rows explicitly, so neither may appear here.
		body := mustJSON(t, resp)
		for _, leak := range []string{fxPrefix + "al-a1", fxPrefix + "al-b1", "org B secret"} {
			if strings.Contains(body, leak) {
				t.Errorf("the orphan-org clause returned %q, a row that HAS an owning organisation", leak)
			}
		}
	})

	t.Run("an org with no data is honestly empty", func(t *testing.T) {
		resp, err := env.svc.ExportAuditData(ctx, fxPrefix+"org-with-nothing", &OJKAuditExportRequest{
			StartDate: "2026-07-01", EndDate: "2026-07-31",
		})
		if err != nil {
			t.Fatalf("ExportAuditData: %v", err)
		}
		for _, sec := range resp.Summary.Sections {
			if sec.ReportState != OJKReportStateEnabledEmpty {
				t.Errorf("section %q report_state = %q, want %q", sec.DataType, sec.ReportState, OJKReportStateEnabledEmpty)
			}
			if sec.RecordCount != 0 {
				t.Errorf("section %q count = %d, want 0", sec.DataType, sec.RecordCount)
			}
		}
		if resp.Summary.ReportState != OJKReportStateEnabledEmpty {
			t.Errorf("summary report_state = %q, want %q (NOT not_available: the module is enabled and answered)",
				resp.Summary.ReportState, OJKReportStateEnabledEmpty)
		}
	})

	// -------------------------------------------------------------------------
	// The app-role posture. Run as the table OWNER, RLS does not apply and a
	// missing withOrgScope wrap is completely invisible. This is the only
	// configuration in which the wrap can be shown to matter, and it is the
	// configuration a customer runs.
	// -------------------------------------------------------------------------
	t.Run("withOrgScope wraps are load-bearing under axonflow_app_role", func(t *testing.T) {
		appSvc := &ojkAuditExportServiceImpl{db: env.appRole}

		pii, res := appSvc.queryPIIRedactions(ctx, fxOrgA, fxStart, fxEnd)
		if res.err != nil {
			t.Fatalf("pii_redactions under app_role: %v", res.err)
		}
		if len(pii) != 2 {
			t.Errorf("pii_redactions under app_role = %d, want 2; the withOrgScope wrap is not effective", len(pii))
		}

		hitl, res := appSvc.queryHITLOversight(ctx, fxOrgA, fxStart, fxEnd)
		if res.err != nil {
			t.Fatalf("hitl under app_role: %v", res.err)
		}
		if len(hitl) != 1 {
			t.Errorf("hitl under app_role = %d, want 1", len(hitl))
		}

		// THE VACUITY CONTROL. The same read WITHOUT the wrap must return zero
		// rows under the app role. Without this, the two assertions above would
		// pass just as happily on a connection where RLS is not active at all --
		// which is exactly what makes a superuser-shaped real-PG test useless.
		var unwrapped int
		if err := env.appRole.QueryRow(
			`SELECT COUNT(*) FROM indonesia_pii_detection_events WHERE org_id = $1`, fxOrgA,
		).Scan(&unwrapped); err != nil {
			t.Fatalf("unwrapped control read: %v", err)
		}
		if unwrapped != 0 {
			t.Fatalf("an UNWRAPPED read under app_role returned %d rows; RLS is not active on this connection, so the wrapped assertions above prove nothing", unwrapped)
		}

		// NOT asserted here: "org B's row is absent". On this connection RLS
		// blocks it whatever the SQL says, so the assertion would pass with the
		// predicate fully conflated -- it tests Postgres, not this code. The
		// predicate is asserted on the MASTER connection below, where RLS is not
		// doing the work.
		for _, r := range pii {
			if r.OJKCategory == "tax_identifier" {
				t.Error("org B's detection event leaked into org A's app-role read")
			}
		}

		// The predicate assertion, on the OWNER connection where RLS does not
		// apply and only the SQL stands between the two orgs.
		masterPII, res := env.svc.queryPIIRedactions(ctx, fxOrgA, fxStart, fxEnd)
		if res.err != nil {
			t.Fatalf("pii_redactions on the owner connection: %v", res.err)
		}
		for _, r := range masterPII {
			if r.OJKCategory == "tax_identifier" {
				t.Error("org B's detection event leaked into org A's read on the OWNER connection, where the SQL predicate is the only boundary")
			}
		}
	})
}

// -----------------------------------------------------------------------------
// Readiness
// -----------------------------------------------------------------------------

// TestRealPG_ReadinessChecksFlipWithState is the anti-constant proof. Four of
// the five checks were unconditional "pass" literals, so an assertion of
// "status == pass" would have passed against the old code, the new code, and any
// code at all. Every case below drives a state change and asserts the verdict
// MOVED, and each check is exercised at more than one verdict.
func TestRealPG_ReadinessChecksFlipWithState(t *testing.T) {
	t.Setenv("AXONFLOW_COMPLIANCE_REGION", "ID")
	env := newOJKPGEnv(t)
	ctx := context.Background()
	since := recentTS().Add(-time.Hour)

	t.Run("PII detection", func(t *testing.T) {
		// No Indonesia PII policy visible at all -> FAIL. Reaching that state
		// means disabling the GLOBAL system policy (core/116 seeds
		// sys_pii_indonesia_ktp with org_id='global'), because the check counts
		// what the org can actually SEE. The container is throwaway, so this
		// cannot outlive the test -- against a shared database the earlier
		// version of this was disarming a security control on somebody's box.
		env.exec(t, `UPDATE static_policies SET enabled = false WHERE category = 'pii-indonesia'`)
		if c := env.svc.checkPIIDetection(ctx, fxOrgA, since); c.Status != OJKCheckFail {
			t.Errorf("with every Indonesia PII policy disabled: status = %q (%s), want %q", c.Status, c.Details, OJKCheckFail)
		}
		env.exec(t, `UPDATE static_policies SET enabled = true WHERE category = 'pii-indonesia'`)

		// Policy visible, no detection events -> WARNING.
		c := env.svc.checkPIIDetection(ctx, fxOrgA, since)
		if c.Status != OJKCheckWarning {
			t.Errorf("with a policy and no events: status = %q (%s), want %q", c.Status, c.Details, OJKCheckWarning)
		}

		// Policy visible AND events recorded -> PASS.
		env.exec(t, fxInsertPII, fxPrefix+"rdy-pii-1", fxOrgA, fxTenantA, nil, nil, "decision",
			"nik", "national_identity", "critical", "31**********0001", 0.7, "blocked", recentTS())
		c = env.svc.checkPIIDetection(ctx, fxOrgA, since)
		if c.Status != OJKCheckPass {
			t.Errorf("with a policy and events: status = %q (%s), want %q", c.Status, c.Details, OJKCheckPass)
		}
		if c.Observed == nil || *c.Observed != 1 {
			t.Errorf("observed = %v, want 1 detection event", c.Observed)
		}
	})

	t.Run("human oversight", func(t *testing.T) {
		org := fxPrefix + "rdy-hitl"
		// Nothing queued -> WARNING (nothing required oversight; a legitimate
		// state, and not evidence of a working control either way).
		if c := env.svc.checkHumanOversight(ctx, org, since); c.Status != OJKCheckWarning {
			t.Errorf("with no queue rows: status = %q (%s), want %q", c.Status, c.Details, OJKCheckWarning)
		}

		// Queued and NEVER reviewed -> FAIL. This is the case the old literal
		// "HITL approval gates active via Plans API" reported as a pass.
		env.exec(t, fxInsertHITL, org, fxTenantA, "pending work", "pending",
			nil, nil, nil, time.Now().Add(time.Hour), recentTS())
		if c := env.svc.checkHumanOversight(ctx, org, since); c.Status != OJKCheckFail {
			t.Errorf("with queued-but-unreviewed rows: status = %q (%s), want %q", c.Status, c.Details, OJKCheckFail)
		}

		// A reviewed row appears -> PASS.
		env.exec(t, fxInsertHITL, org, fxTenantA, "reviewed work", "approved",
			"rev-1", "compliance_officer", recentTS().Add(time.Minute), time.Now().Add(time.Hour), recentTS())
		c := env.svc.checkHumanOversight(ctx, org, since)
		if c.Status != OJKCheckPass {
			t.Errorf("with a reviewed row: status = %q (%s), want %q", c.Status, c.Details, OJKCheckPass)
		}
		if c.Observed == nil || *c.Observed != 1 {
			t.Errorf("observed = %v, want 1 reviewed request", c.Observed)
		}
		env.exec(t, `DELETE FROM hitl_approval_queue WHERE org_id = $1`, org)
	})

	t.Run("audit logging", func(t *testing.T) {
		org := fxPrefix + "rdy-audit"
		if c := env.svc.checkAuditLogging(ctx, org, since); c.Status != OJKCheckWarning {
			t.Errorf("with no audit rows: status = %q (%s), want %q", c.Status, c.Details, OJKCheckWarning)
		}
		env.exec(t, fxInsertAudit, fxPrefix+"rdy-al-1", "r", recentTS(), fxTenantA, org, "llm_chat",
			"allowed", `{}`, nil, "llm", nil, nil, nil, 0, 0, 0, nil, nil)
		c := env.svc.checkAuditLogging(ctx, org, since)
		if c.Status != OJKCheckPass {
			t.Errorf("with an audit row: status = %q (%s), want %q", c.Status, c.Details, OJKCheckPass)
		}
		if c.Observed == nil || *c.Observed != 1 {
			t.Errorf("observed = %v, want 1", c.Observed)
		}
	})

	t.Run("breach notification", func(t *testing.T) {
		org := fxPrefix + "rdy-breach"
		if c := env.svc.checkBreachNotification(ctx, org); c.Status != OJKCheckPass {
			t.Errorf("with no breaches: status = %q (%s), want %q", c.Status, c.Details, OJKCheckPass)
		}
		// A never-submitted breach past its 3x24h window -> FAIL. This is the one
		// verdict the check must never soften: it is a live Art. 46 failure.
		discovered := time.Now().UTC().Add(-100 * time.Hour)
		env.exec(t, `
			INSERT INTO ojk_breach_notifications (
				id, org_id, tenant_id, incident_timestamp, discovery_time, notification_deadline,
				data_subjects_affected, data_types_involved, description, remediation_steps,
				notified_authority, status, created_at, updated_at
			) VALUES ($1,$2,$3,$4,$4,$5,5,'nik','late','rotate','MOCDA','draft',NOW(),NOW())`,
			fxPrefix+"rdy-br-1", org, fxTenantA, discovered, discovered.Add(72*time.Hour))
		c := env.svc.checkBreachNotification(ctx, org)
		if c.Status != OJKCheckFail {
			t.Errorf("with an overdue breach: status = %q (%s), want %q", c.Status, c.Details, OJKCheckFail)
		}
		if c.Observed == nil || *c.Observed != 1 {
			t.Errorf("observed = %v, want 1 overdue breach", c.Observed)
		}
		if !strings.Contains(c.Details, "3x24") {
			t.Errorf("details %q does not cite the Art. 46 window", c.Details)
		}
	})

	// The end-to-end anti-constant assertion: the SAME org scores differently
	// before and after the state changes, and readiness is only reached when
	// every dimension is measurable AND passing.
	t.Run("score moves with the underlying state", func(t *testing.T) {
		org := fxPrefix + "rdy-score"
		before, err := env.svc.ValidateComplianceReadiness(ctx, org)
		if err != nil {
			t.Fatalf("readiness: %v", err)
		}
		if before.Ready {
			t.Error("an org with no traffic and no oversight evidence must not be OJK-ready")
		}
		if before.UnknownChecks != 0 {
			t.Errorf("unknown checks = %d on a fully-migrated database, want 0", before.UnknownChecks)
		}
		if got := findCheck(t, before, "PII Detection").Status; got != OJKCheckWarning {
			t.Errorf("PII Detection with no detection events = %q, want %q", got, OJKCheckWarning)
		}
		if got := findCheck(t, before, "Audit Logging").Status; got != OJKCheckWarning {
			t.Errorf("Audit Logging with no rows = %q, want %q", got, OJKCheckWarning)
		}

		env.exec(t, fxInsertPII, fxPrefix+"rdy-pii-2", org, fxTenantA, nil, nil, "decision",
			"nik", "national_identity", "critical", "31**********0001", 0.7, "blocked", recentTS())
		env.exec(t, fxInsertAudit, fxPrefix+"rdy-al-2", "r", recentTS(), fxTenantA, org, "llm_chat",
			"allowed", `{}`, nil, "llm", nil, nil, nil, 0, 0, 0, nil, nil)
		env.exec(t, fxInsertHITL, org, fxTenantA, "reviewed work", "approved",
			"rev-1", "compliance_officer", recentTS().Add(time.Minute), time.Now().Add(time.Hour), recentTS())

		after, err := env.svc.ValidateComplianceReadiness(ctx, org)
		if err != nil {
			t.Fatalf("readiness: %v", err)
		}
		if after.Score <= before.Score {
			t.Errorf("score did not move: before=%d after=%d; the checks are not deriving from the state they name",
				before.Score, after.Score)
		}
		if !after.Ready {
			t.Errorf("expected ready after every dimension passes; score=%d checks=%+v", after.Score, after.Checks)
		}
		for _, c := range after.Checks {
			if c.Status != OJKCheckPass {
				t.Errorf("check %q = %q (%s), want pass", c.Name, c.Status, c.Details)
			}
		}
	})
}

func findCheck(t *testing.T, resp *OJKComplianceReadinessResponse, name string) OJKComplianceCheck {
	t.Helper()
	for _, c := range resp.Checks {
		if c.Name == name {
			return c
		}
	}
	t.Fatalf("check %q not found in %+v", name, resp.Checks)
	return OJKComplianceCheck{}
}

// -----------------------------------------------------------------------------
// Dashboard
// -----------------------------------------------------------------------------

func TestRealPG_Dashboard(t *testing.T) {
	t.Setenv("AXONFLOW_COMPLIANCE_REGION", "ID")
	env := newOJKPGEnv(t)
	ctx := context.Background()
	org := fxPrefix + "dash-org"

	t.Run("every count is derived, none is a literal", func(t *testing.T) {
		before, err := env.svc.GetDashboard(ctx, org)
		if err != nil {
			t.Fatalf("dashboard: %v", err)
		}
		if len(before.Unavailable) != 0 {
			t.Errorf("unavailable = %v on a fully-migrated database, want none", before.Unavailable)
		}
		if before.ActivePolicies == 8 {
			t.Error("active_policies is 8 on an org with no Indonesia policy of its own; that is the old literal, not a count")
		}

		env.exec(t, `
			INSERT INTO static_policies (policy_id, name, category, pattern, severity, description, action, enabled, tenant_id, org_id)
			VALUES ($1, 'ojk3242 dashboard fixture', 'pii-indonesia', 'x', 'critical', 'fixture', 'block', true, $2, $2)`,
			fxPrefix+"dash-policy", org)
		env.exec(t, fxInsertPII, fxPrefix+"dash-pii", org, fxTenantA, nil, nil, "decision",
			"nik", "national_identity", "critical", "31**********0001", 0.7, "blocked", recentTS())
		env.exec(t, fxInsertAudit, fxPrefix+"dash-al", "r", recentTS(), fxTenantA, org, "llm_chat",
			"blocked", `{}`, nil, "llm", nil, nil, nil, 0, 0, 0, nil, nil)

		after, err := env.svc.GetDashboard(ctx, org)
		if err != nil {
			t.Fatalf("dashboard: %v", err)
		}
		if after.ActivePolicies != before.ActivePolicies+1 {
			t.Errorf("active_policies = %d, want %d after seeding one policy", after.ActivePolicies, before.ActivePolicies+1)
		}
		if after.TotalAuditRecords != before.TotalAuditRecords+1 {
			t.Errorf("total_audit_records = %d, want %d", after.TotalAuditRecords, before.TotalAuditRecords+1)
		}
		if after.RecentViolations != before.RecentViolations+1 {
			t.Errorf("recent_violations = %d, want %d after seeding one blocked decision", after.RecentViolations, before.RecentViolations+1)
		}
		if after.IndonesiaPIIEvents != before.IndonesiaPIIEvents+1 {
			t.Errorf("indonesia_pii_events = %d, want %d", after.IndonesiaPIIEvents, before.IndonesiaPIIEvents+1)
		}
		if after.ReadinessUnknownChecks != 0 {
			t.Errorf("readiness_unknown_checks = %d against a real database, want 0", after.ReadinessUnknownChecks)
		}
	})

	t.Run("another org's rows do not move these counts", func(t *testing.T) {
		before, err := env.svc.GetDashboard(ctx, org)
		if err != nil {
			t.Fatalf("dashboard: %v", err)
		}
		// A row for a DIFFERENT org whose tenant_id is this org's identifier.
		env.exec(t, fxInsertAudit, fxPrefix+"dash-al-other", "r", recentTS(), org, fxPrefix+"other-org", "llm_chat",
			"blocked", `{}`, nil, "llm", nil, nil, nil, 0, 0, 0, nil, nil)

		after, err := env.svc.GetDashboard(ctx, org)
		if err != nil {
			t.Fatalf("dashboard: %v", err)
		}
		if after.TotalAuditRecords != before.TotalAuditRecords {
			t.Errorf("total_audit_records moved from %d to %d because of ANOTHER org's row",
				before.TotalAuditRecords, after.TotalAuditRecords)
		}
		if after.RecentViolations != before.RecentViolations {
			t.Errorf("recent_violations moved from %d to %d because of ANOTHER org's row",
				before.RecentViolations, after.RecentViolations)
		}
	})
}

// -----------------------------------------------------------------------------
// Retention
// -----------------------------------------------------------------------------

// retentionCount is the org's PII-redaction retention count, as the module
// reports it.
func retentionCount(t *testing.T, env *ojkPGEnv, ctx context.Context, org string) int64 {
	t.Helper()
	resp, err := env.svc.GetRetentionStatus(ctx, org, &OJKRetentionStatusRequest{
		DataTypes: []OJKAuditDataType{OJKDataTypePIIRedactions},
	})
	if err != nil {
		t.Fatalf("retention: %v", err)
	}
	if len(resp.DataTypes) != 1 {
		t.Fatalf("retention entries = %d, want 1", len(resp.DataTypes))
	}
	return resp.DataTypes[0].TotalRecords
}

func TestRealPG_Retention(t *testing.T) {
	t.Setenv("AXONFLOW_COMPLIANCE_REGION", "ID")
	env := newOJKPGEnv(t)
	ctx := context.Background()
	org := fxPrefix + "ret-org"

	t.Run("entries are derived, not an unconditional empty slice", func(t *testing.T) {
		before, err := env.svc.GetRetentionStatus(ctx, org, &OJKRetentionStatusRequest{})
		if err != nil {
			t.Fatalf("retention: %v", err)
		}
		if len(before.DataTypes) != 7 {
			t.Fatalf("retention entries = %d, want 7 (one per data type)", len(before.DataTypes))
		}
		for _, e := range before.DataTypes {
			if e.Status == OJKRetentionUnknown {
				t.Errorf("data type %q reports unknown against a fully-migrated database", e.DataType)
			}
			if e.Status != OJKRetentionNoData {
				t.Errorf("data type %q status = %q on an org with no rows, want %q", e.DataType, e.Status, OJKRetentionNoData)
			}
		}

		env.exec(t, fxInsertPII, fxPrefix+"ret-pii", org, fxTenantA, nil, nil, "decision",
			"nik", "national_identity", "critical", "31**********0001", 0.7, "blocked", recentTS())
		after, err := env.svc.GetRetentionStatus(ctx, org, &OJKRetentionStatusRequest{
			DataTypes: []OJKAuditDataType{OJKDataTypePIIRedactions},
		})
		if err != nil {
			t.Fatalf("retention: %v", err)
		}
		if len(after.DataTypes) != 1 {
			t.Fatalf("narrowed retention entries = %d, want 1", len(after.DataTypes))
		}
		e := after.DataTypes[0]
		if e.TotalRecords != 1 {
			t.Errorf("total_records = %d, want 1 after seeding one event", e.TotalRecords)
		}
		if e.OldestRecord == nil || e.NewestRecord == nil {
			t.Fatalf("oldest/newest not populated: %+v", e)
		}
		// One row seeded a day ago: the whole history is newer than the 5-year
		// floor, which is short_history -- not compliant and not no_data.
		if e.Status != OJKRetentionShortHistory {
			t.Errorf("status = %q, want %q for a holding entirely inside the retention window", e.Status, OJKRetentionShortHistory)
		}
	})

	t.Run("another org's rows do not appear", func(t *testing.T) {
		// SELF-SEEDING. The earlier version relied on a row the PREVIOUS subtest
		// happened to leave behind, so run alone it failed -- and its single
		// message ("another org's row leaked") covered BOTH an over-count (a real
		// leak) and an under-count (the silent-empty class this workstream exists
		// to remove). Two opposite failures, one diagnosis.
		env.exec(t, fxInsertPII, fxPrefix+"ret-own", org, fxTenantA, nil, nil, "decision",
			"nik", "national_identity", "critical", "31**********0001", 0.7, "blocked", recentTS())
		before := retentionCount(t, env, ctx, org)
		if before < 1 {
			t.Fatalf("own rows = %d after seeding one; the fixture did not land, so a leak assertion here would be vacuous", before)
		}

		env.exec(t, fxInsertPII, fxPrefix+"ret-pii-other", fxPrefix+"ret-other-org", org, nil, nil, "gateway",
			"nik", "national_identity", "critical", "31**********0001", 0.7, "blocked", recentTS())

		after := retentionCount(t, env, ctx, org)
		switch {
		case after > before:
			t.Errorf("total_records rose from %d to %d after seeding a row owned by ANOTHER org and tenant-labelled as this one: it leaked into the retention view", before, after)
		case after < before:
			t.Errorf("total_records FELL from %d to %d: this org's own rows became unreachable, which is the silent-empty defect, not a leak", before, after)
		}
	})

	t.Run("the audit_logs-backed entries use the shared org predicate", func(t *testing.T) {
		// The blank-org row must be reachable by its tenant here too, or the
		// retention view and the export section disagree about the same corpus.
		env.exec(t, fxInsertAudit, fxPrefix+"ret-al-orphan", "r", recentTS(), org, "", "llm_chat",
			"blocked", `{}`, nil, "llm", nil, nil, nil, 0, 0, 0, nil, nil)
		resp, err := env.svc.GetRetentionStatus(ctx, org, &OJKRetentionStatusRequest{
			DataTypes: []OJKAuditDataType{OJKDataTypePolicyViolations},
		})
		if err != nil {
			t.Fatalf("retention: %v", err)
		}
		if resp.DataTypes[0].TotalRecords != 1 {
			t.Errorf("policy_violations retention = %d, want 1: the blank-org row is unreachable in the retention view while the export section can see it",
				resp.DataTypes[0].TotalRecords)
		}
	})
}
