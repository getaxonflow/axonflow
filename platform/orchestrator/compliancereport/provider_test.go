// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

//go:build enterprise

package compliancereport

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"axonflow/platform/orchestrator/euaiact"
	"axonflow/platform/orchestrator/masfeat"
	"axonflow/platform/orchestrator/ojk"
	"axonflow/platform/orchestrator/rbi"
	"axonflow/platform/orchestrator/sebi"
)

// Per-regulator provider tests.
//
// Every provider gets four things:
//
//   - a POPULATED case that proves real module data reaches real report rows;
//   - an EMPTY case that proves enabled_empty, and that every section is still
//     emitted carrying its empty-state sentence (a dropped section makes "no
//     rows" indistinguishable from "not covered by this report");
//   - a SCOPING assertion that the provider handed its module the tenancy
//     dimension that module actually keys on;
//   - an ERROR case that proves a module failure propagates rather than
//     degrading into a silently empty report.

const (
	provOrg    = "prov-org"
	provTenant = "prov-tenant"
)

func provRequest(fw Framework) ProviderRequest {
	return ProviderRequest{
		OrgID:       provOrg,
		TenantID:    provTenant,
		Framework:   fw,
		PeriodStart: time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC),
		PeriodEnd:   time.Date(2026, 6, 30, 0, 0, 0, 0, time.UTC),
	}
}

// assertEverySectionPresent checks the provider emitted every section key it
// promises, populated or not.
func assertEverySectionPresent(t *testing.T, res *ProviderResult, wantKeys ...string) {
	t.Helper()
	got := map[string]Section{}
	for _, s := range res.Sections {
		got[s.Key] = s
	}
	for _, k := range wantKeys {
		s, ok := got[k]
		if !ok {
			t.Errorf("section %q is missing", k)
			continue
		}
		if len(s.Rows) == 0 && len(s.Notes) == 0 && len(s.Summary) == 0 {
			t.Errorf("section %q is empty AND silent - a reader cannot tell 'no rows' from 'not covered'", k)
		}
	}
	if len(got) != len(res.Sections) {
		t.Errorf("duplicate section keys in %v", res.Sections)
	}
}

// -----------------------------------------------------------------------------
// EU AI Act
// -----------------------------------------------------------------------------

func euaiactProviderFor(t *testing.T, repo euaiact.ExportRepository) DataProvider {
	t.Helper()
	p := newEUAIActProvider(&euaiact.Module{ExportRepo: repo})
	if p == nil {
		t.Fatal("newEUAIActProvider returned nil for a wired module")
	}
	return p
}

func TestEUAIActProvider_Populated(t *testing.T) {
	valid := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
	repo := &fakeEUAIActRepo{
		assessments: []*euaiact.ConformityAssessment{{
			ID: "assess-1", SystemID: "sys-1", SystemName: "Credit Scorer",
			RiskCategory: euaiact.RiskCategoryHighRisk, Status: euaiact.AssessmentStatusApproved,
			Version: 2, AssessmentDate: time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC),
			ValidUntil: &valid, ApprovedBy: "notified-body@example.eu",
			Findings: []euaiact.Finding{{ID: "f1", Severity: "minor"}},
		}},
		metrics: []*euaiact.AccuracyMetric{{
			ID: "m1", ModelID: "gpt-x", MetricType: euaiact.MetricTypeAccuracy,
			Value: 0.9312, SampleSize: 1000, Timestamp: time.Date(2026, 5, 2, 0, 0, 0, 0, time.UTC),
		}},
		violations: []euaiact.PolicyViolationRecord{{
			ID: 42, ViolationType: "pii", Severity: "high", ClientID: "c1", UserID: "u1",
			Description: "blocked", CreatedAt: time.Date(2026, 5, 3, 0, 0, 0, 0, time.UTC),
		}},
		hitl: []euaiact.HITLApprovalRecord{{
			ID: 7, RequestID: "r1", Action: "approve", ActorEmail: "reviewer@example.eu",
			PreviousStatus: "pending", NewStatus: "approved",
			CreatedAt: time.Date(2026, 5, 4, 0, 0, 0, 0, time.UTC),
		}},
		decisions: []euaiact.DecisionChainRecord{{
			ID: "d1", DecisionType: "check_input", DecisionOutcome: "blocked",
			CorrelationID: "trace-1", Timestamp: time.Date(2026, 5, 5, 0, 0, 0, 0, time.UTC),
		}},
	}
	res, err := euaiactProviderFor(t, repo).Fetch(context.Background(), provRequest(FrameworkEUAIAct))
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if res.State != ReportStatePopulated {
		t.Errorf("state = %q, want populated", res.State)
	}
	if res.RecordCount != 5 {
		t.Errorf("record_count = %d, want 5", res.RecordCount)
	}
	assertEverySectionPresent(t, res,
		"conformity_assessments", "article_43_summary", "risk_management",
		"accuracy_bias_monitoring", "human_oversight", "audit_trail")

	// The ORG dimension is the key euaiact's repository uses.
	if repo.gotOrgID != provOrg {
		t.Errorf("provider scoped euaiact by %q, want the org %q", repo.gotOrgID, provOrg)
	}

	flat := flattenSections(res.Sections)
	for _, want := range []string{"Credit Scorer", "notified-body@example.eu", "0.93", "trace-1", "reviewer@example.eu"} {
		if !strings.Contains(flat, want) {
			t.Errorf("the report does not carry %q", want)
		}
	}
	// A float must be formatted at fixed precision, not with %v's shortest
	// representation, or the same value renders differently depending on how it
	// was computed.
	if strings.Contains(flat, "0.9312") {
		t.Error("accuracy value was not formatted at fixed precision")
	}
}

func TestEUAIActProvider_EmptyIsEnabledEmpty(t *testing.T) {
	res, err := euaiactProviderFor(t, &fakeEUAIActRepo{}).Fetch(context.Background(), provRequest(FrameworkEUAIAct))
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if res.State != ReportStateEnabledEmpty {
		t.Errorf("state = %q, want enabled_empty", res.State)
	}
	assertEverySectionPresent(t, res,
		"conformity_assessments", "article_43_summary", "risk_management",
		"accuracy_bias_monitoring", "human_oversight", "audit_trail")
}

func TestEUAIActProvider_ModuleErrorPropagates(t *testing.T) {
	repo := &fakeEUAIActRepo{failOn: "violations"}
	_, err := euaiactProviderFor(t, repo).Fetch(context.Background(), provRequest(FrameworkEUAIAct))
	if !errors.Is(err, errFakeModule) {
		t.Fatalf("err = %v, want the module failure to propagate", err)
	}
}

func TestEUAIActProvider_NilModuleIsNotRegistered(t *testing.T) {
	if p := newEUAIActProvider(nil); p != nil {
		t.Error("a nil module produced a live provider - it must be skipped so the regulator reads not_available")
	}
	if p := newEUAIActProvider(&euaiact.Module{}); p != nil {
		t.Error("a module with no export repository produced a live provider")
	}
}

// -----------------------------------------------------------------------------
// SEBI
// -----------------------------------------------------------------------------

func TestSEBIProvider_PopulatedAndScopedByTenant(t *testing.T) {
	svc := &fakeSEBIService{
		export: &sebi.SEBIAuditExportResponse{
			ExportID: "sebi-exp-1", Status: "completed",
			Summary: &sebi.SEBIAuditExportSummary{TotalRecords: 2},
			Data: &sebi.SEBIAuditExportData{
				PolicyViolations: []sebi.SEBIPolicyViolationRecord{{ID: "v1", ViolationType: "pan", Severity: "high", PolicyName: "pii"}},
				LLMCalls:         []sebi.SEBILLMCallRecord{{ID: "c1", Provider: "anthropic", Model: "opus", PolicyDecision: "allowed"}},
			},
		},
		readiness: &sebi.SEBIComplianceReadinessResponse{
			Ready: true, Score: 88,
			Checks:          []sebi.SEBIComplianceCheck{{Name: "retention", Status: "pass", Description: "5y"}},
			Recommendations: []string{"enable decision chain tracing"},
		},
		retention: &sebi.SEBIRetentionStatusResponse{
			ComplianceStatus: "compliant",
			Status:           []sebi.SEBIDataTypeRetentionStatus{{DataType: sebi.SEBIDataTypeLLMCalls, RetentionDays: 1825, TotalRecords: 10, ComplianceStatus: "compliant"}},
		},
	}
	p := newSEBIProvider(&sebi.SEBIModule{AuditService: svc})
	if p == nil {
		t.Fatal("newSEBIProvider returned nil for a wired module")
	}

	res, err := p.Fetch(context.Background(), provRequest(FrameworkSEBIAIML))
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if res.State != ReportStatePopulated {
		t.Errorf("state = %q, want populated", res.State)
	}
	// The TENANT dimension is the key SEBI's service uses. Passing the org here
	// would read a different customer's rows on a deployment where the two
	// differ.
	if svc.gotTenantID != provTenant {
		t.Errorf("provider scoped SEBI by %q, want the tenant %q", svc.gotTenantID, provTenant)
	}
	assertEverySectionPresent(t, res,
		"readiness", "policy_violations", "llm_activity",
		"decision_lineage", "hitl_oversight", "pii_redactions", "retention_posture")

	flat := flattenSections(res.Sections)
	for _, want := range []string{"retention", "enable decision chain tracing", "anthropic"} {
		if !strings.Contains(flat, want) {
			t.Errorf("the report does not carry %q", want)
		}
	}
}

func TestSEBIProvider_EmptyKeepsRetentionPosture(t *testing.T) {
	svc := &fakeSEBIService{
		export:    &sebi.SEBIAuditExportResponse{Summary: &sebi.SEBIAuditExportSummary{}},
		readiness: &sebi.SEBIComplianceReadinessResponse{Ready: false, Score: 10},
		retention: &sebi.SEBIRetentionStatusResponse{ComplianceStatus: "compliant"},
	}
	res, err := newSEBIProvider(&sebi.SEBIModule{AuditService: svc}).Fetch(context.Background(), provRequest(FrameworkSEBIAIML))
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if res.State != ReportStateEnabledEmpty {
		t.Errorf("state = %q, want enabled_empty", res.State)
	}
	// Retention posture is a CONFIGURATION statement, so it must be reported
	// even for a tenant holding no records: "we retain for 5 years and hold
	// none" is a different answer from "retention is not covered".
	flat := flattenSections(res.Sections)
	if !strings.Contains(flat, "compliant") {
		t.Error("the retention posture disappeared for an empty tenant")
	}
}

func TestSEBIProvider_ModuleErrorPropagates(t *testing.T) {
	svc := &fakeSEBIService{failOn: "readiness", export: &sebi.SEBIAuditExportResponse{}}
	_, err := newSEBIProvider(&sebi.SEBIModule{AuditService: svc}).Fetch(context.Background(), provRequest(FrameworkSEBIAIML))
	if !errors.Is(err, errFakeModule) {
		t.Fatalf("err = %v, want the module failure to propagate", err)
	}
}

// -----------------------------------------------------------------------------
// OJK
// -----------------------------------------------------------------------------

func newOJKFixture() *fakeOJKService {
	return &fakeOJKService{
		export: &ojk.OJKAuditExportResponse{
			Data: &ojk.OJKAuditExportData{
				PolicyViolations: []ojk.OJKPolicyViolationRecord{{ID: "v1", PolicyName: "nik_block", Severity: "high"}},
				CrossBorder: []ojk.CrossBorderTransferRecord{{
					ID: "cb1", DestinationCountry: "SG", TransferBasis: "pasal_56b_dpa",
					DataCategories: []string{"nik", "npwp"},
				}},
				BreachNotifications: []ojk.OJKBreachNotificationRecord{{
					ID: "b1", DataSubjectsAffected: 12, Status: "overdue", WithinDeadline: false,
					DataTypesInvolved: []string{"nik"},
				}},
			},
		},
		readiness: &ojk.OJKComplianceReadinessResponse{Ready: false, Score: 61,
			Checks: []ojk.OJKComplianceCheck{{Name: "breach_window", Status: "fail"}}},
		dashboard: &ojk.OJKDashboardResponse{ComplianceScore: 61, TotalAuditRecords: 900, OverdueBreachNotifications: 1},
		retention: &ojk.OJKRetentionStatusResponse{ComplianceStatus: "compliant", RetentionDays: 1825, MinRetentionDays: 1825},
	}
}

func TestOJKProvider_PopulatedAndScopedByTenant(t *testing.T) {
	svc := newOJKFixture()
	p := newOJKProvider(&ojk.OJKModule{AuditService: svc})
	if p == nil {
		t.Fatal("newOJKProvider returned nil for a wired module")
	}

	res, err := p.Fetch(context.Background(), provRequest(FrameworkUUPDP))
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if res.State != ReportStatePopulated {
		t.Errorf("state = %q, want populated", res.State)
	}
	if svc.gotTenantID != provTenant {
		t.Errorf("provider scoped OJK by %q, want the tenant %q", svc.gotTenantID, provTenant)
	}
	// The requested facade framework must reach the module unchanged, or the
	// export is scoped under the wrong Indonesian instrument.
	if svc.gotFramework != ojk.OJKFrameworkUUPDP {
		t.Errorf("module received framework %q, want %q", svc.gotFramework, ojk.OJKFrameworkUUPDP)
	}
	assertEverySectionPresent(t, res,
		"ai_governance_summary", "policy_violations", "llm_decision_activity",
		"hitl_oversight", "pii_redactions", "cross_border_transfers",
		"breach_log", "bi_pjp", "retention_posture")

	flat := flattenSections(res.Sections)
	// The Pasal 56 basis must be surfaced VERBATIM, never translated between
	// its equivalent spellings.
	if !strings.Contains(flat, "pasal_56b_dpa") {
		t.Error("the cross-border transfer basis was not surfaced verbatim")
	}
	if !strings.Contains(flat, "overdue") {
		t.Error("the breach log lost its effective status")
	}
}

// TestOJKProvider_FrameworkMapping pins every facade framework onto the module
// enum, and pins that an unknown one is refused rather than silently falling
// through to AI governance.
func TestOJKProvider_FrameworkMapping(t *testing.T) {
	for facade, want := range map[Framework]ojk.OJKComplianceFramework{
		FrameworkOJKAIGovernance: ojk.OJKFrameworkAIGovernance,
		FrameworkUUPDP:           ojk.OJKFrameworkUUPDP,
		FrameworkBIPJP:           ojk.OJKFrameworkBIPJP,
		FrameworkOJKBICombined:   ojk.OJKFrameworkCombined,
	} {
		got, err := ojkFramework(facade)
		if err != nil {
			t.Errorf("%s: %v", facade, err)
			continue
		}
		if got != want {
			t.Errorf("%s mapped to %q, want %q", facade, got, want)
		}
	}
	if _, err := ojkFramework(FrameworkEUAIAct); err == nil {
		t.Error("a non-OJK framework mapped silently instead of being refused")
	}
}

// TestOJKProvider_BIPJPSectionIsHonestAboutItsLimits pins that the BI PJP
// section says what it does NOT cover. A silently empty BI section would let a
// payment-system regulator conclude the institution has no payment-service AI
// activity, which is a different and possibly false claim.
func TestOJKProvider_BIPJPSectionIsHonestAboutItsLimits(t *testing.T) {
	svc := newOJKFixture()
	p := newOJKProvider(&ojk.OJKModule{AuditService: svc})

	underBI, err := p.Fetch(context.Background(), provRequest(FrameworkBIPJP))
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	bi := sectionByKey(t, underBI, "bi_pjp")
	if len(bi.Notes) == 0 || !strings.Contains(strings.Join(bi.Notes, " "), "KNOWN LIMITATION") {
		t.Errorf("under BI_PJP the section does not state its limitation: %v", bi.Notes)
	}

	underPDP, err := p.Fetch(context.Background(), provRequest(FrameworkUUPDP))
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	bi = sectionByKey(t, underPDP, "bi_pjp")
	if len(bi.Notes) == 0 || !strings.Contains(strings.Join(bi.Notes, " "), "Not applicable") {
		t.Errorf("under UU_PDP the section does not say it is out of scope: %v", bi.Notes)
	}
}

func TestOJKProvider_ModuleErrorPropagates(t *testing.T) {
	svc := newOJKFixture()
	svc.failOn = "dashboard"
	_, err := newOJKProvider(&ojk.OJKModule{AuditService: svc}).Fetch(context.Background(), provRequest(FrameworkUUPDP))
	if !errors.Is(err, errFakeModule) {
		t.Fatalf("err = %v, want the module failure to propagate", err)
	}
}

// -----------------------------------------------------------------------------
// RBI
// -----------------------------------------------------------------------------

func newRBIModuleFixture(ks *fakeRBIKillSwitch) (*rbi.RBIModule, *fakeRBIRegistry) {
	reg := &fakeRBIRegistry{systems: []*rbi.AISystem{{
		ID: "s1", SystemID: "sys-1", SystemName: "Loan Scorer",
		RiskCategory: rbi.RiskCategory("high"), DeploymentStatus: rbi.DeploymentStatus("production"),
		OwnerEmail: "owner@bank.example", BoardApprovalStatus: rbi.BoardApprovalStatus("approved"),
	}}}
	return &rbi.RBIModule{
		RegistryService:   reg,
		ValidationService: &fakeRBIValidation{validations: []*rbi.ModelValidation{{ID: "v1", SystemID: "sys-1", ValidatorName: "MRM", Recommendation: rbi.ValidationRecommendation("approve")}}},
		IncidentService:   &fakeRBIIncident{incidents: []*rbi.AIIncident{{ID: "i1", IncidentID: "INC-1", SystemID: "sys-1", Severity: rbi.IncidentSeverity("high"), Status: rbi.IncidentStatus("open")}}},
		KillSwitchService: ks,
		BoardService:      &fakeRBIBoard{reports: []*rbi.BoardReport{{ID: "r1", ReportType: rbi.ReportType("quarterly"), ComplianceScore: 91.5}}},
	}, reg
}

func TestRBIProvider_PopulatedAndScopedByOrg(t *testing.T) {
	ks := &fakeRBIKillSwitch{
		switches: []*rbi.KillSwitch{{ID: "ks1", SystemID: "sys-1", IsActive: false}},
		history: map[string][]*rbi.KillSwitchHistoryEntry{
			"ks1": {{ID: 1, KillSwitchID: "ks1", Action: rbi.KillSwitchAction("activated"),
				ActorEmail: "risk@bank.example", Reason: "drift",
				CreatedAt: time.Date(2026, 5, 10, 0, 0, 0, 0, time.UTC)}},
		},
	}
	mod, reg := newRBIModuleFixture(ks)
	p := newRBIProvider(mod)
	if p == nil {
		t.Fatal("newRBIProvider returned nil for a wired module")
	}

	res, err := p.Fetch(context.Background(), provRequest(FrameworkRBIFreeAI))
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if res.State != ReportStatePopulated {
		t.Errorf("state = %q, want populated", res.State)
	}
	if reg.gotOrgID != provOrg {
		t.Errorf("provider scoped RBI by %q, want the org %q", reg.gotOrgID, provOrg)
	}
	assertEverySectionPresent(t, res,
		"board_reports", "incidents", "kill_switches", "kill_switch_history",
		"model_validations", "ai_system_registry")

	// The kill-switch history fan-out must carry the CALLER'S org on every
	// call: the switch ids come from that org's own listing, and a fan-out that
	// dropped the org would read another institution's history.
	if len(ks.gotHistoryOrgIDs) == 0 {
		t.Fatal("kill-switch history was never read - the section is fabricated")
	}
	for _, org := range ks.gotHistoryOrgIDs {
		if org != provOrg {
			t.Errorf("history fan-out used org %q, want %q", org, provOrg)
		}
	}
	flat := flattenSections(res.Sections)
	if !strings.Contains(flat, "risk@bank.example") || !strings.Contains(flat, "Loan Scorer") {
		t.Errorf("the report is missing seeded values: %s", truncate(flat))
	}
}

// TestRBIProvider_HistoryOutsideThePeriodIsExcluded pins the date filter the
// provider applies itself, because GetHistory has no date parameter.
func TestRBIProvider_HistoryOutsideThePeriodIsExcluded(t *testing.T) {
	ks := &fakeRBIKillSwitch{
		switches: []*rbi.KillSwitch{{ID: "ks1", SystemID: "sys-1"}},
		history: map[string][]*rbi.KillSwitchHistoryEntry{
			"ks1": {
				{ID: 1, KillSwitchID: "ks1", Action: "activated", CreatedAt: time.Date(2026, 5, 10, 0, 0, 0, 0, time.UTC)},
				{ID: 2, KillSwitchID: "ks1", Action: "released", CreatedAt: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)},
			},
		},
	}
	mod, _ := newRBIModuleFixture(ks)
	res, err := newRBIProvider(mod).Fetch(context.Background(), provRequest(FrameworkRBIFreeAI))
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	hist := sectionByKey(t, res, "kill_switch_history")
	if len(hist.Rows) != 1 {
		t.Fatalf("history rows = %d, want 1 (the 2020 entry is outside the reporting period)", len(hist.Rows))
	}
	if !strings.Contains(strings.Join(hist.Rows[0], " "), "activated") {
		t.Errorf("the wrong history entry survived the period filter: %v", hist.Rows[0])
	}
}

func TestRBIProvider_EmptyIsEnabledEmpty(t *testing.T) {
	mod := &rbi.RBIModule{
		RegistryService:   &fakeRBIRegistry{},
		ValidationService: &fakeRBIValidation{},
		IncidentService:   &fakeRBIIncident{},
		KillSwitchService: &fakeRBIKillSwitch{},
		BoardService:      &fakeRBIBoard{},
	}
	res, err := newRBIProvider(mod).Fetch(context.Background(), provRequest(FrameworkRBIFreeAI))
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if res.State != ReportStateEnabledEmpty {
		t.Errorf("state = %q, want enabled_empty", res.State)
	}
	assertEverySectionPresent(t, res,
		"board_reports", "incidents", "kill_switches", "kill_switch_history",
		"model_validations", "ai_system_registry")
}

func TestRBIProvider_ModuleErrorPropagates(t *testing.T) {
	mod, reg := newRBIModuleFixture(&fakeRBIKillSwitch{})
	reg.failOn = "list"
	_, err := newRBIProvider(mod).Fetch(context.Background(), provRequest(FrameworkRBIFreeAI))
	if !errors.Is(err, errFakeModule) {
		t.Fatalf("err = %v, want the module failure to propagate", err)
	}
}

// -----------------------------------------------------------------------------
// MAS FEAT
// -----------------------------------------------------------------------------

func newMASModuleFixture(assessments []*masfeat.FEATAssessment, ksRepo *fakeMASKillSwitchRepo) (*masfeat.Module, *fakeMASRegistryRepo) {
	regRepo := &fakeMASRegistryRepo{systems: []*masfeat.AISystemRegistry{{
		ID: "m1", SystemID: "sys-1", SystemName: "Fraud Model",
		UseCase: masfeat.AISystemUseCase("fraud_detection"), Status: masfeat.SystemStatus("production"),
		RiskRatingImpact: 4, RiskRatingComplexity: 3, RiskRatingReliance: 5,
		MaterialityClassification: masfeat.MaterialityClassification("high"),
		OwnerEmail:                "owner@mas.example",
	}}}
	return &masfeat.Module{
		RegistryService:   masfeat.NewRegistryService(regRepo),
		AssessmentService: masfeat.NewAssessmentService(&fakeMASAssessmentRepo{assessments: assessments}, regRepo, 12),
		KillSwitchService: masfeat.NewKillSwitchService(ksRepo, 0.1),
	}, regRepo
}

func masScore(v float64) *float64 { return &v }

func TestMASFEATProvider_PopulatedAndScopedByOrg(t *testing.T) {
	inPeriod := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	ksRepo := &fakeMASKillSwitchRepo{history: map[string][]*masfeat.KillSwitchHistory{
		"sys-1": {{ID: "h1", KillSwitchID: "ks1", Action: "triggered", PreviousStatus: "armed",
			NewStatus: "triggered", PerformedBy: "risk@mas.example", PerformedAt: inPeriod}},
	}}
	mod, regRepo := newMASModuleFixture([]*masfeat.FEATAssessment{{
		ID: "fa1", SystemID: "sys-1", AssessmentType: "periodic",
		Status: masfeat.FEATAssessmentStatus("approved"), Version: 1, AssessmentDate: inPeriod,
		FairnessScore: masScore(80), EthicsScore: masScore(70),
		AccountabilityScore: masScore(90), TransparencyScore: masScore(60),
		OverallScore: masScore(75), ApprovedBy: "cro@mas.example",
	}}, ksRepo)

	p := newMASFEATProvider(mod)
	if p == nil {
		t.Fatal("newMASFEATProvider returned nil for a wired module")
	}
	res, err := p.Fetch(context.Background(), provRequest(FrameworkMASFEAT))
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if res.State != ReportStatePopulated {
		t.Errorf("state = %q, want populated", res.State)
	}
	if regRepo.gotOrgID != provOrg {
		t.Errorf("provider scoped MAS FEAT by %q, want the org %q", regRepo.gotOrgID, provOrg)
	}
	assertEverySectionPresent(t, res,
		"feat_assessments", "feat_pillar_summary", "system_registry", "kill_switch_history")

	for _, org := range ksRepo.gotHistoryOrgIDs {
		if org != provOrg {
			t.Errorf("history fan-out used org %q, want %q", org, provOrg)
		}
	}
	pillars := sectionByKey(t, res, "feat_pillar_summary")
	flat := kvString(pillars.Summary)
	for _, want := range []string{"Fairness (mean)", "80.00", "Transparency (mean)", "60.00"} {
		if !strings.Contains(flat, want) {
			t.Errorf("the pillar summary is missing %q: %s", want, flat)
		}
	}
}

// TestMASFEATProvider_AssessmentsOutsideThePeriodAreExcludedAndCounted pins the
// date filter the provider applies (ListAssessments has none) AND that the
// discrepancy is explained, so a reader does not conclude assessments vanished.
func TestMASFEATProvider_AssessmentsOutsideThePeriodAreExcludedAndCounted(t *testing.T) {
	inPeriod := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	outOfPeriod := time.Date(2021, 5, 1, 0, 0, 0, 0, time.UTC)
	mod, _ := newMASModuleFixture([]*masfeat.FEATAssessment{
		{ID: "fa1", SystemID: "sys-1", Status: "approved", AssessmentDate: inPeriod},
		{ID: "fa2", SystemID: "sys-1", Status: "approved", AssessmentDate: outOfPeriod},
	}, &fakeMASKillSwitchRepo{})

	res, err := newMASFEATProvider(mod).Fetch(context.Background(), provRequest(FrameworkMASFEAT))
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	sec := sectionByKey(t, res, "feat_assessments")
	if len(sec.Rows) != 1 {
		t.Fatalf("assessment rows = %d, want 1", len(sec.Rows))
	}
	notes := strings.Join(sec.Notes, " ")
	if !strings.Contains(notes, "holds 2 assessments in total") {
		t.Errorf("the section does not explain why its count differs from the module's own: %v", sec.Notes)
	}
}

// TestMASFEATProvider_UnscoredPillarsReadAsNotScored pins that a missing score
// is reported as "not scored" rather than as 0.00, which on a MAS submission
// would read as a failing score.
func TestMASFEATProvider_UnscoredPillarsReadAsNotScored(t *testing.T) {
	inPeriod := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	mod, _ := newMASModuleFixture([]*masfeat.FEATAssessment{
		{ID: "fa1", SystemID: "sys-1", Status: "draft", AssessmentDate: inPeriod},
	}, &fakeMASKillSwitchRepo{})

	res, err := newMASFEATProvider(mod).Fetch(context.Background(), provRequest(FrameworkMASFEAT))
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	flat := kvString(sectionByKey(t, res, "feat_pillar_summary").Summary)
	if !strings.Contains(flat, "not scored") {
		t.Errorf("an unscored pillar is not reported as such: %s", flat)
	}
	if strings.Contains(flat, "0.00 across") {
		t.Errorf("an unscored pillar rendered as a zero score: %s", flat)
	}
}

func TestMASFEATProvider_EmptyIsEnabledEmpty(t *testing.T) {
	mod := &masfeat.Module{
		RegistryService:   masfeat.NewRegistryService(&fakeMASRegistryRepo{}),
		AssessmentService: masfeat.NewAssessmentService(&fakeMASAssessmentRepo{}, &fakeMASRegistryRepo{}, 12),
		KillSwitchService: masfeat.NewKillSwitchService(&fakeMASKillSwitchRepo{}, 0.1),
	}
	res, err := newMASFEATProvider(mod).Fetch(context.Background(), provRequest(FrameworkMASFEAT))
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if res.State != ReportStateEnabledEmpty {
		t.Errorf("state = %q, want enabled_empty", res.State)
	}
	assertEverySectionPresent(t, res,
		"feat_assessments", "feat_pillar_summary", "system_registry", "kill_switch_history")
}

func TestMASFEATProvider_ModuleErrorPropagates(t *testing.T) {
	mod, regRepo := newMASModuleFixture(nil, &fakeMASKillSwitchRepo{})
	regRepo.failOn = "list"
	_, err := newMASFEATProvider(mod).Fetch(context.Background(), provRequest(FrameworkMASFEAT))
	if !errors.Is(err, errFakeModule) {
		t.Fatalf("err = %v, want the module failure to propagate", err)
	}
}

// -----------------------------------------------------------------------------
// Registry
// -----------------------------------------------------------------------------

// TestRegistry_SkipsNilAndUnknownProviders pins that a half-initialized
// deployment degrades to not_available rather than panicking at request time.
func TestRegistry_SkipsNilAndUnknownProviders(t *testing.T) {
	reg := NewRegistry(nil, populatedProvider(RegulatorSEBI), &fakeProvider{regulator: "fca", available: true})

	if reg.Get(RegulatorSEBI) == nil {
		t.Error("a wired provider is missing from the registry")
	}
	if reg.Get("fca") != nil {
		t.Error("a provider for an unknown regulator was registered")
	}
	for _, r := range []Regulator{RegulatorEUAIAct, RegulatorRBI, RegulatorMASFEAT, RegulatorOJK} {
		if reg.Get(r) != nil {
			t.Errorf("%s has a provider but none was supplied", r)
		}
	}
	avail := reg.Available()
	if len(avail) != 1 || avail[0] != RegulatorSEBI {
		t.Errorf("Available() = %v, want [sebi]", avail)
	}
	// A nil registry must answer, not panic: the community stub path never
	// constructs one.
	var nilReg *Registry
	if nilReg.Get(RegulatorSEBI) != nil {
		t.Error("a nil registry returned a provider")
	}
}

// TestAllProvidersDeclareTheirOwnRegulator pins that no adapter is registered
// under the wrong key, which would route one regulator's request to another's
// data.
func TestAllProvidersDeclareTheirOwnRegulator(t *testing.T) {
	ksRepo := &fakeMASKillSwitchRepo{}
	masMod, _ := newMASModuleFixture(nil, ksRepo)
	rbiMod, _ := newRBIModuleFixture(&fakeRBIKillSwitch{})

	for want, p := range map[Regulator]DataProvider{
		RegulatorEUAIAct: newEUAIActProvider(&euaiact.Module{ExportRepo: &fakeEUAIActRepo{}}),
		RegulatorSEBI:    newSEBIProvider(&sebi.SEBIModule{AuditService: &fakeSEBIService{}}),
		RegulatorRBI:     newRBIProvider(rbiMod),
		RegulatorMASFEAT: newMASFEATProvider(masMod),
		RegulatorOJK:     newOJKProvider(&ojk.OJKModule{AuditService: &fakeOJKService{}}),
	} {
		if p == nil {
			t.Errorf("%s: provider is nil for a wired module", want)
			continue
		}
		if got := p.Regulator(); got != want {
			t.Errorf("provider declares regulator %q, want %q", got, want)
		}
		avail, err := p.Available(context.Background(), provRequest(""))
		if err != nil || !avail {
			t.Errorf("%s: Available() = %v, %v; want true, nil for a wired module", want, avail, err)
		}
	}
}

// TestNilModulesProduceNoProviders is the counterpart: an unwired module must
// be skipped so its regulator answers not_available.
func TestNilModulesProduceNoProviders(t *testing.T) {
	if newSEBIProvider(nil) != nil || newSEBIProvider(&sebi.SEBIModule{}) != nil {
		t.Error("SEBI: an unwired module produced a live provider")
	}
	if newOJKProvider(nil) != nil || newOJKProvider(&ojk.OJKModule{}) != nil {
		t.Error("OJK: an unwired module produced a live provider")
	}
	if newRBIProvider(nil) != nil || newRBIProvider(&rbi.RBIModule{}) != nil {
		t.Error("RBI: an unwired module produced a live provider")
	}
	if newMASFEATProvider(nil) != nil || newMASFEATProvider(&masfeat.Module{}) != nil {
		t.Error("MAS FEAT: an unwired module produced a live provider")
	}
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

func flattenSections(sections []Section) string {
	var b strings.Builder
	for _, s := range sections {
		b.WriteString(s.Title)
		b.WriteString(" ")
		b.WriteString(s.Description)
		b.WriteString(" ")
		b.WriteString(strings.Join(s.Notes, " "))
		b.WriteString(" ")
		b.WriteString(kvString(s.Summary))
		for _, row := range s.Rows {
			b.WriteString(strings.Join(row, " "))
			b.WriteString(" ")
		}
	}
	return b.String()
}

func kvString(kvs []KV) string {
	var b strings.Builder
	for _, kv := range kvs {
		b.WriteString(kv.Key)
		b.WriteString("=")
		b.WriteString(kv.Value)
		b.WriteString(" ")
	}
	return b.String()
}

func sectionByKey(t *testing.T, res *ProviderResult, key string) Section {
	t.Helper()
	for _, s := range res.Sections {
		if s.Key == key {
			return s
		}
	}
	t.Fatalf("section %q not found", key)
	return Section{}
}

// TestOJKDateBounds pins the date conversion the OJK module's parser forces.
//
// The module parses both bounds with time.Parse("2006-01-02", ...) and filters
// `timestamp >= start AND timestamp <= end`. Two failure modes this covers,
// BOTH found by the runtime-e2e suite rather than by reading:
//
//  1. An RFC3339 string is rejected outright, so every OJK report failed with
//     `invalid start_date: ... extra text`.
//  2. The parsed end is MIDNIGHT of that date, so passing the end date verbatim
//     silently drops the final day's records.
func TestOJKDateBounds(t *testing.T) {
	day := func(y int, m time.Month, d, h int) time.Time {
		return time.Date(y, m, d, h, 0, 0, 0, time.UTC)
	}
	for _, tc := range []struct {
		name               string
		start, end         time.Time
		wantStart, wantEnd string
	}{
		{
			// A partial final day must be rolled forward, or every record from
			// 2026-06-30 is dropped.
			name:  "partial final day rolls forward",
			start: day(2026, 4, 1, 0), end: day(2026, 6, 30, 23),
			wantStart: "2026-04-01", wantEnd: "2026-07-01",
		},
		{
			// An exact midnight boundary means "up to, not including" that day,
			// so it is passed through unchanged.
			name:  "exact midnight boundary is unchanged",
			start: day(2026, 4, 1, 0), end: day(2026, 7, 1, 0),
			wantStart: "2026-04-01", wantEnd: "2026-07-01",
		},
		{
			name:  "a start part-way through a day still covers that whole day",
			start: day(2026, 4, 1, 13), end: day(2026, 7, 1, 0),
			wantStart: "2026-04-01", wantEnd: "2026-07-01",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gotStart, gotEnd := ojkDateBounds(tc.start, tc.end)
			if gotStart != tc.wantStart || gotEnd != tc.wantEnd {
				t.Errorf("ojkDateBounds = (%q, %q), want (%q, %q)", gotStart, gotEnd, tc.wantStart, tc.wantEnd)
			}
			// Both must parse under the module's OWN layout, which is the
			// property the e2e failure was about.
			for _, v := range []string{gotStart, gotEnd} {
				if _, err := time.Parse("2006-01-02", v); err != nil {
					t.Errorf("%q does not parse with the OJK module's layout: %v", v, err)
				}
			}
		})
	}
}

// TestOJKProviderStatesItsDateResolution pins that the day-granularity rounding
// is DISCLOSED on the artifact. An unstated rounding on a regulatory report is a
// claim about the period covered.
func TestOJKProviderStatesItsDateResolution(t *testing.T) {
	svc := newOJKFixture()
	res, err := newOJKProvider(&ojk.OJKModule{AuditService: svc}).Fetch(context.Background(), provRequest(FrameworkUUPDP))
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	notes := strings.Join(sectionByKey(t, res, "ai_governance_summary").Notes, " ")
	if !strings.Contains(notes, "whole DATES") {
		t.Errorf("the report does not disclose its date resolution: %s", notes)
	}
}
