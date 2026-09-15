// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package policy

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"

	"axonflow/platform/decision/policypack"
)

func installedTestPack(t *testing.T) *policypack.Pack {
	t.Helper()
	src := &policypack.Source{
		ID: "testpack", Version: 1,
		Approval: &policypack.ApproverPool{Quorum: 1, Group: "testpack-approvers"},
		Detectors: []policypack.Detector{
			// Context-anchored, as eight of the FinCrime pack's are: it matches
			// the canonical JSON of an object-valued parameter.
			{ID: "tp_amount", Name: "Amount", Category: "fincrime", Severity: "high", Phase: "request", Action: "block", Priority: 95, Pattern: `"amount":\s*[1-9][0-9]{4,}`},
			// Statement-anchored.
			{ID: "tp_execute", Name: "Execute", Category: "fincrime", Severity: "medium", Phase: "request", Action: "require_approval", Priority: 85, Pattern: `(?i)\bexecute\b[\s\S]{0,60}?\bpayment\b`},
		},
	}
	raw, err := json.Marshal(src)
	if err != nil {
		t.Fatal(err)
	}
	committed, err := policypack.Render(src)
	if err != nil {
		t.Fatal(err)
	}
	p, err := policypack.Load(raw, committed)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func engineWithInstalled(t *testing.T, globalRows *sqlmock.Rows) *UnifiedPolicyEngine {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	expectScopedLoadPass(mock, "tenant-1", sqlmock.NewRows(loaderTestCols()))
	expectScopedLoadPass(mock, "global", globalRows)
	installed, err := CompileInstalledDetectors([]*policypack.Pack{installedTestPack(t)})
	if err != nil {
		t.Fatalf("CompileInstalledDetectors: %v", err)
	}
	cfg := DefaultEngineConfig()
	cfg.RefreshInterval = 0
	cfg.EnableMetrics = false
	cfg.InstalledDetectors = installed
	e := NewUnifiedPolicyEngine(db, cfg, &NoOpAuditQueue{})
	t.Cleanup(e.Stop)
	return e
}

// An installed pack's detectors ride on the load and report what they found,
// on the lifted context and on the statement, beside the migrated rows' - which
// is what the anchored engine decides the pack's controls from.
func TestInstalledPackDetectorsReportTheirFactsOnEveryLoad(t *testing.T) {
	e := engineWithInstalled(t, systemRow(sqlmock.NewRows(loaderTestCols()), "sys_sqli_drop", 100))
	org := "tenant-1"
	res := e.EvaluateRequest(context.Background(), "please settle the supplier invoice", EvalOptions{
		TenantID: "tenant-1", OrgScope: &org,
		Parameters: map[string]interface{}{
			"fincrime_transaction": map[string]interface{}{"amount": 15000, "currency": "USD"},
		},
	})
	if res.EvaluationError {
		t.Fatalf("the load failed: %+v", res)
	}
	facts := capabilityFacts(t, res.Observation)
	if f := facts["tp_amount"]; !f.Ran || !f.Matched {
		t.Errorf("tp_amount = %+v, want ran and matched: the amount in the lifted context is over the cap", f)
	}
	if f := facts["tp_execute"]; !f.Ran || f.Matched {
		t.Errorf("tp_execute = %+v, want ran and not matched: nothing asks to execute a payment", f)
	}
	if f := facts["sys_sqli_drop"]; !f.Ran {
		t.Errorf("the migrated row's detector did not run beside the pack's: %+v", f)
	}
}

// The pack is the only author of its detectors' verdicts. A row under a pack
// detector's id - the retired seed script's, on a deployment that ran it - is
// not loaded beside the pack, so its pattern cannot report under the pack's id.
func TestARowUnderAnInstalledDetectorsIDIsNotLoaded(t *testing.T) {
	rows := systemRow(sqlmock.NewRows(loaderTestCols()), "sys_sqli_drop", 100)
	// A DROP TABLE pattern under the pack's amount detector's id.
	rows = systemRow(rows, "tp_amount", 95)
	e := engineWithInstalled(t, rows)
	org := "tenant-1"
	res := e.EvaluateRequest(context.Background(), "DROP TABLE invoices", EvalOptions{TenantID: "tenant-1", OrgScope: &org})
	if res.EvaluationError {
		t.Fatalf("the load failed: %+v", res)
	}
	facts := capabilityFacts(t, res.Observation)
	if f := facts["tp_amount"]; !f.Ran || f.Matched {
		t.Errorf("tp_amount = %+v, want ran and not matched: the pack's pattern finds no amount, and the row under its id must not report for it", f)
	}
	if f := facts["sys_sqli_drop"]; !f.Ran || !f.Matched {
		t.Errorf("sys_sqli_drop = %+v, want ran and matched: only the row under the pack's id is dropped", f)
	}
}

// The system-tier floor proves the migrated rows are reachable. A pack's
// detectors are not a migrated row, so a load whose rows are unreachable fails
// closed whatever is installed.
func TestInstalledDetectorsDoNotSatisfyTheSystemFloor(t *testing.T) {
	e := engineWithInstalled(t, sqlmock.NewRows(loaderTestCols()))
	res := e.EvaluateRequest(context.Background(), "hello", EvalOptions{TenantID: "tenant-1"})
	if !res.Blocked || !res.EvaluationError {
		t.Fatalf("a load with no migrated system row passed because a pack is installed: %+v", res)
	}
}

// A call site whose category filter does not admit the pack reports its
// detectors as NOT RUN, which is what the pack restriction relies on: an unrun
// detector is unknown to the anchored engine, never a fabricated "did not fire".
func TestAnInstalledDetectorOutsideTheCategoryFilterDidNotRun(t *testing.T) {
	e := engineWithInstalled(t, systemRow(sqlmock.NewRows(loaderTestCols()), "sys_sqli_drop", 100))
	org := "tenant-1"
	res := e.EvaluateRequest(context.Background(), "execute the payment", EvalOptions{
		TenantID: "tenant-1", OrgScope: &org, Categories: []PolicyCategory{"security-sqli"},
	})
	facts := capabilityFacts(t, res.Observation)
	f, present := facts["tp_execute"]
	if !present || f.Ran || f.Matched {
		t.Fatalf("tp_execute = %+v (present %t), want present, not run and not matched", f, present)
	}
}

// A detector whose phases take different actions carries each on its phase, so
// a reader still on the legacy path sees the pack's own intent per phase.
func TestAnInstalledDetectorCarriesItsActionPerPhase(t *testing.T) {
	src := &policypack.Source{ID: "phasepack", Version: 1, Detectors: []policypack.Detector{
		{ID: "pp_split", Name: "Split", Category: "pii-india", Severity: "high", Phase: "both", Action: "warn", ActionResponse: "redact", Pattern: "split"},
	}}
	raw, err := json.Marshal(src)
	if err != nil {
		t.Fatal(err)
	}
	committed, err := policypack.Render(src)
	if err != nil {
		t.Fatal(err)
	}
	p, err := policypack.Load(raw, committed)
	if err != nil {
		t.Fatal(err)
	}
	compiled, err := CompileInstalledDetectors([]*policypack.Pack{p})
	if err != nil {
		t.Fatal(err)
	}
	if len(compiled) != 1 || compiled[0].PolicyID != "pp_split" {
		t.Fatalf("compiled %d detectors, want pp_split alone: %+v", len(compiled), compiled)
	}
	if got := compiled[0]; string(got.ActionRequest) != "warn" || string(got.ActionResponse) != "redact" {
		t.Errorf("pp_split carries request %q, response %q; want warn on requests and redact on responses", got.ActionRequest, got.ActionResponse)
	}
}

// A pack detector is validated only by the validator its source names. Neither
// its category nor its id picks one: resolved as a row's is, a pii-india
// detector is gated by the Aadhaar checksum and an id carrying "bank_account"
// by a US routing checksum, and neither matches an Indian identifier (#4141).
func TestAPackDetectorIsValidatedOnlyByTheValidatorItNames(t *testing.T) {
	src := &policypack.Source{ID: "valpack", Version: 1, Detectors: []policypack.Detector{
		{ID: "vp_upi_id", Name: "UPI", Category: "pii-india", Severity: "high", Phase: "request", Action: "warn", Pattern: `\b[a-z.]+@[a-z]+\b`},
		{ID: "vp_bank_account", Name: "Bank", Category: "pii-india", Severity: "high", Phase: "request", Action: "warn", Pattern: `\b\d{9,18}\b`},
		{ID: "vp_travel_document", Name: "Passport", Category: "pii-india", Severity: "high", Phase: "request", Action: "warn", Pattern: `\b[A-Z][1-9][0-9]{6}\b`, Validator: "passport"},
	}}
	compiled := compileInstalledTestPack(t, src)

	for _, c := range []struct{ id, value, context string }{
		{"vp_upi_id", "ramesh.k@okaxis", "collect the fee from ramesh.k@okaxis"},
		{"vp_bank_account", "50100123456789", "credit account 50100123456789"},
	} {
		if ok, _ := ValidatorFor(c.id, CategoryPIIIndia)(c.value, c.context); ok {
			t.Fatalf("a row's resolution accepts %q for %s; this test no longer shows what it guards", c.value, c.id)
		}
		v := compiled[c.id].Validator
		if v == nil {
			t.Fatalf("%s compiled with a nil validator, which the evaluator resolves again by category", c.id)
		}
		if ok, conf := v(c.value, c.context); !ok || conf != 1.0 {
			t.Errorf("%s's validator = (%t, %v) on %q, want (true, 1): it names none, so it matches as written", c.id, ok, conf, c.value)
		}
	}

	const value, labelled, unlabelled = "J8369854", "passport number J8369854", "order J8369854"
	wantLabelled, _ := ValidatePassport(value, labelled)
	wantUnlabelled, _ := ValidatePassport(value, unlabelled)
	if wantLabelled == wantUnlabelled {
		t.Fatal("ValidatePassport answers a labelled and an unlabelled value alike; pick inputs it tells apart")
	}
	v := compiled["vp_travel_document"].Validator
	if got, _ := v(value, labelled); got != wantLabelled {
		t.Errorf("vp_travel_document on a labelled passport = %t, want %t: it names the passport validator", got, wantLabelled)
	}
	if got, _ := v(value, unlabelled); got != wantUnlabelled {
		t.Errorf("vp_travel_document on an unlabelled value = %t, want %t: it names the passport validator", got, wantUnlabelled)
	}

	src.Detectors[2].Validator = "no_such_validator"
	raw, err := json.Marshal(src)
	if err != nil {
		t.Fatal(err)
	}
	committed, err := policypack.Render(src)
	if err != nil {
		t.Fatal(err)
	}
	p, err := policypack.Load(raw, committed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := CompileInstalledDetectors([]*policypack.Pack{p}); err == nil || !strings.Contains(err.Error(), "vp_travel_document") || !strings.Contains(err.Error(), "no_such_validator") {
		t.Fatalf("CompileInstalledDetectors(an unknown validator) = %v, want a refusal naming the detector and the validator", err)
	}
}

// compileInstalledTestPack loads and compiles a pack source, keyed by detector id.
func compileInstalledTestPack(t *testing.T, src *policypack.Source) map[string]CompiledPolicy {
	t.Helper()
	raw, err := json.Marshal(src)
	if err != nil {
		t.Fatal(err)
	}
	committed, err := policypack.Render(src)
	if err != nil {
		t.Fatal(err)
	}
	p, err := policypack.Load(raw, committed)
	if err != nil {
		t.Fatal(err)
	}
	compiled, err := CompileInstalledDetectors([]*policypack.Pack{p})
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]CompiledPolicy{}
	for _, c := range compiled {
		out[c.PolicyID] = c
	}
	return out
}

func TestCompileInstalledDetectorsRefusesAPatternRE2CannotCompile(t *testing.T) {
	p := installedTestPack(t)
	p.Source.Detectors[0].Pattern = `(?<=x)y`
	if _, err := CompileInstalledDetectors([]*policypack.Pack{p}); err == nil || !strings.Contains(err.Error(), "tp_amount") {
		t.Fatalf("CompileInstalledDetectors = %v, want a refusal naming the detector", err)
	}
}
