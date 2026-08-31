// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package assurance

import (
	"reflect"
	"strings"
	"testing"
)

const testAction = "Action::mcp.jira.issue.update"

func legacyVersions() map[string]string {
	m := map[string]string{}
	for _, id := range LegacyControlIDs {
		m[id] = "v1"
	}
	return m
}

func registry(t *testing.T, bindings ...ActionBinding) *Registry {
	t.Helper()
	b := NewRegistryBuilder("assurance-test.v1")
	for _, id := range LegacyControlIDs {
		b.AddControl(Control{
			ID: id, Version: "v1", DefaultClass: ClassAdvisory,
			ReportsConfidence: id == "risk_scorer",
			MinCoverage:       coverageFloor(id),
		})
	}
	for _, bind := range bindings {
		b.Bind(bind)
	}
	r, err := b.Build()
	if err != nil {
		t.Fatalf("build registry: %v", err)
	}
	return r
}

func result(id string, outcome Outcome) Result {
	return Result{
		ControlID: id, Version: "v1", Outcome: outcome, Coverage: 1.0,
		InputDigest: "sha256:input", Provenance: ProvenancePlatformInvoked,
	}
}

func hasReason(v Verdict, code string) bool {
	for _, r := range v.Reasons {
		if r == code {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// The class table
// ---------------------------------------------------------------------------

// TestAdvisoryOutageAndRequiredOutageHaveDifferentOutcomes is ADR-065's
// acceptance criterion stated directly: "tests prove advisory outage and
// required-control outage have different, documented outcomes".
//
// Same control, same failure, different class, opposite results. That is the
// whole point of the split, and a single test asserting both halves is the
// only way to show they really are different rather than both happening to be
// deny or both happening to be proceed.
func TestAdvisoryOutageAndRequiredOutageHaveDifferentOutcomes(t *testing.T) {
	failing := result("pii_detector", OutcomeUnavailable)
	failing.Err = "engine timeout"

	t.Run("advisory outage continues and is recorded", func(t *testing.T) {
		reg := registry(t, ActionBinding{ActionID: testAction, ControlID: "pii_detector", Class: ClassAdvisory})
		v := Evaluate(EvaluateInput{Registry: reg, ActionID: testAction, Results: []Result{failing}})
		if v.Decision != DecisionProceed {
			t.Fatalf("decision = %q, want proceed: an advisory control cannot deny. reasons=%v", v.Decision, v.Reasons)
		}
		if len(v.UnavailableAdvisory) != 1 || v.UnavailableAdvisory[0] != "pii_detector" {
			t.Fatalf("unavailable_advisory = %v, want the failed control recorded", v.UnavailableAdvisory)
		}
		if len(v.UnavailableRequired) != 0 {
			t.Errorf("an advisory outage was recorded as a required one: %v", v.UnavailableRequired)
		}
	})

	t.Run("required outage denies", func(t *testing.T) {
		for _, class := range []Class{ClassEnforcement, ClassGatingRisk} {
			reg := registry(t, ActionBinding{ActionID: testAction, ControlID: "pii_detector", Class: class})
			v := Evaluate(EvaluateInput{Registry: reg, ActionID: testAction, Results: []Result{failing}})
			if v.Decision != DecisionDeny {
				t.Fatalf("%s: decision = %q, want deny: a required control's failure cannot permit", class, v.Decision)
			}
			if !hasReason(v, ReasonRequiredControlUnavailable) {
				t.Errorf("%s: reasons = %v, want %q", class, v.Reasons, ReasonRequiredControlUnavailable)
			}
			if len(v.UnavailableRequired) != 1 {
				t.Errorf("%s: unavailable_required = %v", class, v.UnavailableRequired)
			}
		}
	})
}

// TestAnAdvisoryControlCannotDenyEvenWhenItFlags. "Flagged" from an advisory
// control is evidence, not a verdict. Treating flagged as authoritative
// wherever it appears is the easy mistake here.
func TestAnAdvisoryControlCannotDenyEvenWhenItFlags(t *testing.T) {
	reg := registry(t, ActionBinding{ActionID: testAction, ControlID: "pii_detector", Class: ClassAdvisory})
	v := Evaluate(EvaluateInput{Registry: reg, ActionID: testAction, Results: []Result{result("pii_detector", OutcomeFlagged)}})
	if v.Decision != DecisionProceed {
		t.Fatalf("decision = %q, want proceed", v.Decision)
	}
	// The finding is still recorded - advisory means it cannot deny, not that
	// it is thrown away.
	if len(v.Evidence) != 1 || v.Evidence[0].Outcome != OutcomeFlagged {
		t.Fatalf("evidence = %+v, want the flag recorded", v.Evidence)
	}
	if v.Evidence[0].Determining {
		t.Error("an advisory control was marked as determining the outcome")
	}
}

// TestARequiredControlThatFlagsDenies, and is marked determining so the audit
// record names which control decided.
func TestARequiredControlThatFlagsDenies(t *testing.T) {
	reg := registry(t, ActionBinding{ActionID: testAction, ControlID: "sql_injection_detector", Class: ClassEnforcement})
	v := Evaluate(EvaluateInput{Registry: reg, ActionID: testAction, Results: []Result{result("sql_injection_detector", OutcomeFlagged)}})
	if v.Decision != DecisionDeny || !hasReason(v, ReasonRequiredControlFlagged) {
		t.Fatalf("decision = %q reasons = %v", v.Decision, v.Reasons)
	}
	if len(v.Evidence) != 1 || !v.Evidence[0].Determining {
		t.Fatalf("evidence = %+v, want the determining control marked", v.Evidence)
	}
}

// ---------------------------------------------------------------------------
// Enforcement relevance is opt-in
// ---------------------------------------------------------------------------

// TestAControlIsEnforcementRelevantOnlyThroughActionScopedConfiguration.
// A control the action did not bind is ADVISORY, whatever it reports.
func TestAControlIsEnforcementRelevantOnlyThroughActionScopedConfiguration(t *testing.T) {
	// Bound as enforcement for a DIFFERENT action.
	reg := registry(t, ActionBinding{ActionID: "Action::other", ControlID: "pii_detector", Class: ClassEnforcement})

	class, ok := reg.ClassFor(testAction, "pii_detector")
	if !ok || class != ClassAdvisory {
		t.Fatalf("class for the unbound action = %q, want advisory", class)
	}
	class, _ = reg.ClassFor("Action::other", "pii_detector")
	if class != ClassEnforcement {
		t.Fatalf("class for the bound action = %q, want enforcement", class)
	}
}

// TestTheRegistryRefusesANonAdvisoryDefaultClass. If a control could carry
// enforcement relevance with it, "enforcement-relevant only through explicit
// action-scoped configuration" would be a convention rather than a rule.
func TestTheRegistryRefusesANonAdvisoryDefaultClass(t *testing.T) {
	for _, class := range []Class{ClassEnforcement, ClassGatingRisk} {
		b := NewRegistryBuilder("v1")
		b.AddControl(Control{ID: "c", Version: "v1", DefaultClass: class})
		_, err := b.Build()
		if err == nil || !strings.Contains(err.Error(), "action-scoped configuration") {
			t.Fatalf("%s: err = %v, want a refusal naming the rule", class, err)
		}
	}
}

// TestTheShippedControlsAreAllAdvisoryToday. ADR-065 requires ADR-059's
// capability selection to stay behaviourally compatible until cutover, and
// this is what that means: naming the shipped controls here changes nothing
// about how they run.
func TestTheShippedControlsAreAllAdvisoryToday(t *testing.T) {
	reg, err := NewLegacyRegistry("legacy.v1", legacyVersions())
	if err != nil {
		t.Fatalf("legacy registry: %v", err)
	}
	for _, id := range LegacyControlIDs {
		class, ok := reg.ClassFor(testAction, id)
		if !ok {
			t.Fatalf("%s is not registered", id)
		}
		if class != ClassAdvisory {
			t.Errorf("%s is %q on a fresh registry; the shipped posture must be unchanged until an action binds it", id, class)
		}
	}
	// And nothing is selected for any action, so nothing runs differently.
	if sel := reg.SelectedFor(testAction); len(sel) != 0 {
		t.Errorf("selected = %v, want nothing configured on a fresh registry", sel)
	}
}

func TestTheLegacyRegistryRefusesAControlWithNoVersion(t *testing.T) {
	versions := legacyVersions()
	delete(versions, "pii_detector")
	if _, err := NewLegacyRegistry("legacy.v1", versions); err == nil {
		t.Fatal("a shipped control with no version was accepted; decision evidence must name the ruleset version")
	}
}

// ---------------------------------------------------------------------------
// Caller-supplied results are never trusted
// ---------------------------------------------------------------------------

// TestCallerSuppliedResultsAreDiscardedNotDownWeighted. A client that could
// report its own PII scan as clear could disable PII controls by asserting it
// had already run them.
func TestCallerSuppliedResultsAreDiscardedNotDownWeighted(t *testing.T) {
	reg := registry(t, ActionBinding{ActionID: testAction, ControlID: "pii_detector", Class: ClassEnforcement})
	forged := result("pii_detector", OutcomeClear)
	forged.Provenance = ProvenanceCallerSupplied

	v := Evaluate(EvaluateInput{Registry: reg, ActionID: testAction, Results: []Result{forged}})
	if v.Decision != DecisionDeny {
		t.Fatalf("decision = %q, want deny: a caller-supplied 'clear' satisfied a required control", v.Decision)
	}
	if !hasReason(v, ReasonCallerSuppliedResult) {
		t.Errorf("reasons = %v, want %q", v.Reasons, ReasonCallerSuppliedResult)
	}
	// The required control is then MISSING, which is the correct downstream
	// consequence of discarding the only result for it.
	if !hasReason(v, ReasonRequiredControlMissing) {
		t.Errorf("reasons = %v, want the required control also reported missing", v.Reasons)
	}
}

// TestAZeroProvenanceIsNotTrusted. The zero value of Provenance is "", not
// platform_invoked, so a result assembled without setting it is discarded
// rather than trusted. A default of platform_invoked would make forgetting the
// field a silent trust decision.
func TestAZeroProvenanceIsNotTrusted(t *testing.T) {
	reg := registry(t, ActionBinding{ActionID: testAction, ControlID: "pii_detector", Class: ClassAdvisory})
	res := result("pii_detector", OutcomeClear)
	res.Provenance = ""

	v := Evaluate(EvaluateInput{Registry: reg, ActionID: testAction, Results: []Result{res}})
	if len(v.Discarded) != 1 {
		t.Fatalf("discarded = %v, want the unattributed result discarded", v.Discarded)
	}
}

// TestAResultForAnUnselectedOrUnregisteredControlDoesNotContribute. Otherwise
// whoever gathers results could smuggle a control into an action's decision.
func TestAResultForAnUnselectedOrUnregisteredControlDoesNotContribute(t *testing.T) {
	reg := registry(t, ActionBinding{ActionID: testAction, ControlID: "pii_detector", Class: ClassAdvisory})

	t.Run("unregistered", func(t *testing.T) {
		v := Evaluate(EvaluateInput{Registry: reg, ActionID: testAction, Results: []Result{
			result("pii_detector", OutcomeClear),
			result("invented_detector", OutcomeFlagged),
		}})
		if !hasReason(v, ReasonUnregisteredControl) {
			t.Errorf("reasons = %v, want %q", v.Reasons, ReasonUnregisteredControl)
		}
		if v.Decision != DecisionProceed {
			t.Errorf("decision = %q; an unregistered control must not decide anything", v.Decision)
		}
	})

	t.Run("registered but not selected for this action", func(t *testing.T) {
		v := Evaluate(EvaluateInput{Registry: reg, ActionID: testAction, Results: []Result{
			result("pii_detector", OutcomeClear),
			result("risk_scorer", OutcomeFlagged),
		}})
		if !hasReason(v, ReasonUnselectedControl) {
			t.Errorf("reasons = %v, want %q", v.Reasons, ReasonUnselectedControl)
		}
		if v.Decision != DecisionProceed {
			t.Errorf("decision = %q; a control this action did not select must not decide anything", v.Decision)
		}
	})
}

// ---------------------------------------------------------------------------
// Silence, coverage, versions
// ---------------------------------------------------------------------------

// TestASelectedControlThatProducedNoResultIsUnavailableNotClear. Treating
// silence as a clean result is the fail-open.
func TestASelectedControlThatProducedNoResultIsUnavailableNotClear(t *testing.T) {
	reg := registry(t, ActionBinding{ActionID: testAction, ControlID: "pii_detector", Class: ClassEnforcement})
	v := Evaluate(EvaluateInput{Registry: reg, ActionID: testAction, Results: nil})
	if v.Decision != DecisionDeny || !hasReason(v, ReasonRequiredControlMissing) {
		t.Fatalf("decision = %q reasons = %v, want deny with %q", v.Decision, v.Reasons, ReasonRequiredControlMissing)
	}
	if len(v.Evidence) != 1 || v.Evidence[0].Outcome != OutcomeUnavailable {
		t.Fatalf("evidence = %+v, want the silence recorded as unavailable", v.Evidence)
	}
}

// TestARequiredControlClearAtLowCoverageCannotPermit. A pattern matcher that
// saw 99% of a payload and found nothing has not established that the payload
// is clean; the interesting 1% is exactly where an attacker puts it.
func TestARequiredControlClearAtLowCoverageCannotPermit(t *testing.T) {
	reg := registry(t, ActionBinding{ActionID: testAction, ControlID: "pii_detector", Class: ClassEnforcement})
	res := result("pii_detector", OutcomeClear)
	res.Coverage = 0.99

	v := Evaluate(EvaluateInput{Registry: reg, ActionID: testAction, Results: []Result{res}})
	if v.Decision != DecisionDeny || !hasReason(v, ReasonRequiredControlLowCoverage) {
		t.Fatalf("decision = %q reasons = %v, want deny with %q", v.Decision, v.Reasons, ReasonRequiredControlLowCoverage)
	}

	// The same low coverage on an ADVISORY control does not deny.
	advReg := registry(t, ActionBinding{ActionID: testAction, ControlID: "pii_detector", Class: ClassAdvisory})
	if v := Evaluate(EvaluateInput{Registry: advReg, ActionID: testAction, Results: []Result{res}}); v.Decision != DecisionProceed {
		t.Fatalf("advisory low coverage: decision = %q, want proceed", v.Decision)
	}
}

// TestVersionSkewOnARequiredControlCannotPermit: the result came from a
// ruleset the registry does not describe, so its meaning is unknown.
func TestVersionSkewOnARequiredControlCannotPermit(t *testing.T) {
	reg := registry(t, ActionBinding{ActionID: testAction, ControlID: "pii_detector", Class: ClassEnforcement})
	res := result("pii_detector", OutcomeClear)
	res.Version = "v2"

	v := Evaluate(EvaluateInput{Registry: reg, ActionID: testAction, Results: []Result{res}})
	if v.Decision != DecisionDeny || !hasReason(v, ReasonRequiredControlVersionSkew) {
		t.Fatalf("decision = %q reasons = %v, want deny with %q", v.Decision, v.Reasons, ReasonRequiredControlVersionSkew)
	}

	// Advisory: recorded as a note, not a deny.
	advReg := registry(t, ActionBinding{ActionID: testAction, ControlID: "pii_detector", Class: ClassAdvisory})
	av := Evaluate(EvaluateInput{Registry: advReg, ActionID: testAction, Results: []Result{res}})
	if av.Decision != DecisionProceed {
		t.Fatalf("advisory version skew: decision = %q, want proceed", av.Decision)
	}
	if !strings.Contains(av.Evidence[0].Note, "version skew") {
		t.Errorf("the skew was not recorded on the advisory evidence: %+v", av.Evidence[0])
	}
}

// TestAnUnrecognisedOutcomeCannotPermitARequiredControl. An outcome this
// package does not know is version skew or a bug, and for a required control
// neither is a reason to proceed.
func TestAnUnrecognisedOutcomeCannotPermitARequiredControl(t *testing.T) {
	reg := registry(t, ActionBinding{ActionID: testAction, ControlID: "pii_detector", Class: ClassEnforcement})
	res := result("pii_detector", Outcome("probably_fine"))
	v := Evaluate(EvaluateInput{Registry: reg, ActionID: testAction, Results: []Result{res}})
	if v.Decision != DecisionDeny {
		t.Fatalf("decision = %q, want deny", v.Decision)
	}
}

// TestConfidenceIsCarriedOnlyWhereItIsMeaningful. A deterministic pattern
// matcher reporting 1.0 would put a fabricated number into the audit record,
// and someone would later build a threshold on it.
func TestConfidenceIsCarriedOnlyWhereItIsMeaningful(t *testing.T) {
	conf := 0.87
	reg := registry(t,
		ActionBinding{ActionID: testAction, ControlID: "pii_detector", Class: ClassAdvisory},
		ActionBinding{ActionID: testAction, ControlID: "risk_scorer", Class: ClassAdvisory},
	)
	pii := result("pii_detector", OutcomeClear)
	pii.Confidence = &conf
	risk := result("risk_scorer", OutcomeClear)
	risk.Confidence = &conf

	v := Evaluate(EvaluateInput{Registry: reg, ActionID: testAction, Results: []Result{pii, risk}})
	byID := map[string]Evidence{}
	for _, e := range v.Evidence {
		byID[e.ControlID] = e
	}
	if byID["pii_detector"].Confidence != nil {
		t.Error("a confidence was carried for a control that does not report a meaningful one")
	}
	if !strings.Contains(byID["pii_detector"].Note, "confidence discarded") {
		t.Errorf("the discard was not recorded: %+v", byID["pii_detector"])
	}
	if byID["risk_scorer"].Confidence == nil || *byID["risk_scorer"].Confidence != conf {
		t.Errorf("the scorer's confidence was dropped: %+v", byID["risk_scorer"])
	}
}

// TestEveryEvidenceRecordCarriesTheVersionAndInputDigest. ADR-065 requires
// decision evidence to include the ruleset version, coverage, confidence where
// meaningful, and the input digest.
func TestEveryEvidenceRecordCarriesTheVersionAndInputDigest(t *testing.T) {
	reg := registry(t, ActionBinding{ActionID: testAction, ControlID: "pii_detector", Class: ClassAdvisory})
	v := Evaluate(EvaluateInput{Registry: reg, ActionID: testAction, Results: []Result{result("pii_detector", OutcomeClear)}})
	if len(v.Evidence) != 1 {
		t.Fatalf("evidence = %+v", v.Evidence)
	}
	e := v.Evidence[0]
	if e.Version == "" || e.InputDigest == "" || e.Class == "" {
		t.Fatalf("evidence is incomplete: %+v", e)
	}
}

// ---------------------------------------------------------------------------
// Structural
// ---------------------------------------------------------------------------

// TestInspectionCannotGrantAuthorization. ADR-065: "Inspection policy selects
// content controls, but cannot grant authorization." Decision has exactly two
// values and neither of them permits - Proceed means "nothing here contradicted
// the deterministic decision", not "allowed".
func TestInspectionCannotGrantAuthorization(t *testing.T) {
	forbidden := []string{"allow", "permit", "grant", "authorize", "authorise"}
	for _, d := range []Decision{DecisionProceed, DecisionDeny} {
		for _, bad := range forbidden {
			if strings.Contains(strings.ToLower(string(d)), bad) {
				t.Errorf("Decision has a value %q that reads as a grant; inspection cannot grant authorization", d)
			}
		}
	}
	// And the Verdict carries no field that a caller could read as permission.
	vt := reflect.TypeOf(Verdict{})
	for i := 0; i < vt.NumField(); i++ {
		name := strings.ToLower(vt.Field(i).Name)
		for _, bad := range forbidden {
			if strings.Contains(name, bad) {
				t.Errorf("Verdict.%s reads as a grant", vt.Field(i).Name)
			}
		}
	}
}

// TestNoRegistryDenies: with no way to know which controls are required, the
// safe answer is deny. A nil registry silently proceeding would disable every
// enforcement control through a wiring defect.
func TestNoRegistryDenies(t *testing.T) {
	if v := Evaluate(EvaluateInput{ActionID: testAction}); v.Decision != DecisionDeny {
		t.Fatalf("decision = %q, want deny with no registry", v.Decision)
	}
}

func TestRegistryValidationRefusals(t *testing.T) {
	t.Run("no version", func(t *testing.T) {
		if _, err := NewRegistryBuilder("").Build(); err == nil {
			t.Fatal("an unversioned registry was accepted")
		}
	})
	t.Run("duplicate control", func(t *testing.T) {
		b := NewRegistryBuilder("v1")
		b.AddControl(Control{ID: "c", Version: "1", DefaultClass: ClassAdvisory})
		b.AddControl(Control{ID: "c", Version: "2", DefaultClass: ClassAdvisory})
		if _, err := b.Build(); err == nil {
			t.Fatal("a duplicate control id was accepted")
		}
	})
	t.Run("binding to an unregistered control", func(t *testing.T) {
		b := NewRegistryBuilder("v1")
		b.Bind(ActionBinding{ActionID: "a", ControlID: "ghost", Class: ClassEnforcement})
		if _, err := b.Build(); err == nil {
			t.Fatal("a binding to an unregistered control was accepted")
		}
	})
	t.Run("contradictory bindings", func(t *testing.T) {
		b := NewRegistryBuilder("v1")
		b.AddControl(Control{ID: "c", Version: "1", DefaultClass: ClassAdvisory})
		b.Bind(ActionBinding{ActionID: "a", ControlID: "c", Class: ClassEnforcement})
		b.Bind(ActionBinding{ActionID: "a", ControlID: "c", Class: ClassAdvisory})
		_, err := b.Build()
		if err == nil || !strings.Contains(err.Error(), "iteration order") {
			t.Fatalf("err = %v, want a refusal of the contradictory binding", err)
		}
	})
	t.Run("coverage outside the unit interval", func(t *testing.T) {
		b := NewRegistryBuilder("v1")
		b.AddControl(Control{ID: "c", Version: "1", DefaultClass: ClassAdvisory, MinCoverage: 1.5})
		if _, err := b.Build(); err == nil {
			t.Fatal("a min_coverage above 1 was accepted")
		}
	})
}

// TestClassRequiredCoversExactlyTheTwoRequiredClasses. A third class added
// later that nobody wired into Required() would silently be advisory.
func TestClassRequiredCoversExactlyTheTwoRequiredClasses(t *testing.T) {
	if !ClassEnforcement.Required() || !ClassGatingRisk.Required() {
		t.Error("a required class does not report as required")
	}
	if ClassAdvisory.Required() {
		t.Error("advisory reports as required")
	}
	if Class("invented").Required() {
		t.Error("an unknown class reports as required; it must not, or a typo would silently make a control enforcement-relevant")
	}
	if Class("invented").Valid() {
		t.Error("an unknown class validates")
	}
}
