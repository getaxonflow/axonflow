// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
//
// #3968: one detector gives one answer, whichever phase asks.
//
// The operator's ruling (ADR-065 amendment 2026-09-10) is that a detector's
// implementation does not vary by plane. The request path broke it inside the
// shared engine itself: Evaluate took the first regex hit and returned no match
// when the validator refused it, while EvaluateAll skipped the refused hit and
// kept scanning. The input from the issue, measured on main before this change:
//
//	charge 4111111111111112 then charge 4111111111111111 please
//	Evaluate    (request):  match=false
//	EvaluateAll (response): matches=1
//
// # WHAT THESE TESTS ASSERT, AND WHY IT IS THE DETECTION AND NOT A VERDICT
//
// The change moves one observable: which occurrence a row DETECTS. Whether a
// request is then blocked depends on the row's action and on which row sorts
// first, and both have their own owners - so every assertion below is on the
// match (present, and at which span), never on `Blocked`.
//
// Agreement alone is not the assertion either. Two paths that both find
// nothing agree. Each case pins the ANSWER - the accepted occurrence, at its
// index - and carries a control proving the refused occurrence really is
// refused, so a test cannot pass by a detector having been switched off.

package policy

import (
	"context"
	"regexp"
	"strings"
	"testing"
)

const (
	issue3968Input  = "charge 4111111111111112 then charge 4111111111111111 please"
	issue3968Valid  = "4111111111111111"
	issue3968Luhnno = "4111111111111112"
)

func issue3968CardPolicy() CompiledPolicy {
	const pat = `\b\d{16}\b`
	return CompiledPolicy{
		PolicyID: "sys_pii_credit_card", Name: "Credit Card Detection",
		Category: CategoryPIIGlobal, Pattern: regexp.MustCompile(pat), PatternStr: pat,
		Severity: SeverityCritical, Phase: PhaseBoth,
		ActionRequest: ActionWarn, ActionResponse: ActionWarn,
		Enabled: true, Priority: 50, TenantID: "test-tenant",
	}
}

// TestEvaluateFindsTheAcceptedOccurrenceBehindARefusedOne is the issue's
// input through both PatternEvaluator phases.
func TestEvaluateFindsTheAcceptedOccurrenceBehindARefusedOne(t *testing.T) {
	p := issue3968CardPolicy()
	if ValidatorFor(p.PolicyID, p.Category) == nil {
		t.Fatalf("no validator resolves for %s; every case below would be measuring a bare pattern", p.PolicyID)
	}
	e := NewPatternEvaluator(true)
	validAt := strings.Index(issue3968Input, issue3968Valid)

	// CONTROLS: the refused number is refused, and the valid one is accepted,
	// each on its own and on both phases. Without these the headline could pass
	// against a detector that finds nothing or everything.
	if m := e.Evaluate("charge "+issue3968Luhnno+" please", &p); m != nil {
		t.Fatalf("request path matched a lone Luhn-invalid number %q", m.MatchText)
	}
	if ms := e.EvaluateAll("charge "+issue3968Luhnno+" please", &p); len(ms) != 0 {
		t.Fatalf("response path matched a lone Luhn-invalid number: %+v", ms)
	}
	if m := e.Evaluate("charge "+issue3968Valid+" please", &p); m == nil {
		t.Fatalf("request path found no match for a lone Luhn-valid card")
	}
	if ms := e.EvaluateAll("charge "+issue3968Valid+" please", &p); len(ms) != 1 {
		t.Fatalf("response path found %d matches for a lone Luhn-valid card, want 1", len(ms))
	}

	// THE ISSUE: request direction.
	m := e.Evaluate(issue3968Input, &p)
	if m == nil {
		t.Fatalf("request path found no match in %q: a refused occurrence ended the scan, which is #3968", issue3968Input)
	}
	if m.MatchText != issue3968Valid || m.StartIndex != validAt {
		t.Errorf("request path matched %q at %d, want %q at %d", m.MatchText, m.StartIndex, issue3968Valid, validAt)
	}

	// Response direction: still finds exactly the valid card.
	ms := e.EvaluateAll(issue3968Input, &p)
	if len(ms) != 1 || ms[0].MatchText != issue3968Valid || ms[0].StartIndex != validAt {
		t.Errorf("response path returned %+v, want exactly %q at %d", ms, issue3968Valid, validAt)
	}

	// The reversed order must not regress: the first occurrence is the valid one.
	reversed := "charge " + issue3968Valid + " then charge " + issue3968Luhnno
	if m := e.Evaluate(reversed, &p); m == nil || m.StartIndex != strings.Index(reversed, issue3968Valid) {
		t.Errorf("request path on the reversed input returned %+v", m)
	}
	if ms := e.EvaluateAll(reversed, &p); len(ms) != 1 {
		t.Errorf("response path on the reversed input returned %d matches, want 1", len(ms))
	}

	// With validators disabled a row is its pattern: the first hit stands, on
	// both phases. This pins the nil-validator arm of the one scanner.
	bare := NewPatternEvaluator(false)
	if m := bare.Evaluate(issue3968Input, &p); m == nil || m.MatchText != issue3968Luhnno {
		t.Errorf("with validators disabled the request path returned %+v, want the first hit %q", m, issue3968Luhnno)
	}
	if ms := bare.EvaluateAll(issue3968Input, &p); len(ms) != 2 {
		t.Errorf("with validators disabled the response path returned %d matches, want both hits", len(ms))
	}
}

// TestScanAcceptedValidatesEachOccurrenceOnceAndStopsAtTheLimit pins the
// bounded scan: it re-asks the regex for 1, 2, 4... occurrences, and a slip in
// its bookkeeping would either validate an occurrence twice or miss one.
func TestScanAcceptedValidatesEachOccurrenceOnceAndStopsAtTheLimit(t *testing.T) {
	re := regexp.MustCompile(`\b\d{16}\b`)
	var parts []string
	for i := 0; i < 9; i++ {
		parts = append(parts, issue3968Luhnno)
	}
	parts = append(parts, issue3968Valid, issue3968Valid)
	input := strings.Join(parts, " ")

	calls := 0
	counting := func(match, context string) (bool, float64) {
		calls++
		return ValidateCreditCard(match, context)
	}

	got := ScanAccepted(re, input, counting, DefaultContextWindow, 1)
	if len(got) != 1 || got[0].Start != 9*(len(issue3968Luhnno)+1) {
		t.Fatalf("limit 1 returned %+v, want the tenth occurrence", got)
	}
	if calls != 10 {
		t.Errorf("limit 1 validated %d occurrences, want exactly 10 (nine refused, one accepted): an occurrence was "+
			"validated twice or skipped across the bounded re-scans", calls)
	}

	calls = 0
	if got := ScanAccepted(re, input, counting, DefaultContextWindow, 5); len(got) != 2 {
		t.Errorf("a limit above the accepted count returned %d, want both valid occurrences", len(got))
	}
	if calls != 11 {
		t.Errorf("a limit above the accepted count validated %d occurrences, want all 11 once", calls)
	}

	if got := ScanAccepted(re, input, counting, DefaultContextWindow, 0); len(got) != 2 {
		t.Errorf("limit 0 returned %d, want every accepted occurrence (2)", len(got))
	}
	if got := ScanAccepted(re, "no digits here", counting, DefaultContextWindow, 1); len(got) != 0 {
		t.Errorf("an input with no occurrence returned %+v", got)
	}
}

// TestEngineRequestAndResponseDetectTheSameOccurrence drives the issue's
// input through UnifiedPolicyEngine.EvaluateRequest and EvaluateResponse - the
// two call sites every plane of the shared engine goes through - and asserts
// both report the row matching the valid card.
func TestEngineRequestAndResponseDetectTheSameOccurrence(t *testing.T) {
	engine := createTestEngine([]CompiledPolicy{issue3968CardPolicy()})
	opts := EvalOptions{TenantID: "test-tenant"}

	matchedCard := func(phase string, matches []PolicyMatch) {
		t.Helper()
		var found []PolicyMatch
		for _, m := range matches {
			if m.PolicyID == "sys_pii_credit_card" {
				found = append(found, m)
			}
		}
		if len(found) != 1 || found[0].MatchText != issue3968Valid {
			t.Errorf("%s phase detected %+v for sys_pii_credit_card, want exactly the Luhn-valid card %q", phase, found, issue3968Valid)
		}
	}

	req := engine.EvaluateRequest(context.Background(), issue3968Input, opts)
	matchedCard("request", req.MatchedPolicies)

	resp := engine.EvaluateResponse(context.Background(), issue3968Input, opts)
	matchedCard("response", resp.MatchedPolicies)
}

// TestEveryValidatorBearingRowDetectsTheSameOnRequestAndResponse extends the
// issue's input to every row of the shipped corpus that a validator gates.
//
// The population is the census, and the validator is the one the loader
// resolves for that row (censusResolveValidator) - nothing is transcribed. For
// each row the input is a REFUSED occurrence followed by an ACCEPTED one:
//
//   - accepted is the validator's probe from validatorProbes, labelled, which
//     TestEveryResolvedValidatorIsProbedAndClassified already requires to be
//     accepted;
//   - refused is DERIVED: the unlabelled probe when the validator is
//     context-gated, otherwise the first single-character change of the probe
//     the validator refuses.
//
// The pattern is a literal alternation of those two strings. That is
// deliberate: the property is the SCAN - does a refused occurrence end the
// search - and a shipped pattern would make a failure ambiguous between the
// scan and the pattern. The shipped patterns are driven live on
// /api/v1/decide by runtime-e2e/1431_policy_path_alias.
//
// Every refusal and acceptance is checked IN PLACE, by calling the validator
// with the exact context the scan will build, before the scan is asserted. So
// a derivation that produced an occurrence the validator would in fact accept
// fails as a derivation, not as a detector.
func TestEveryValidatorBearingRowDetectsTheSameOnRequestAndResponse(t *testing.T) {
	rows := loadDetectorCensus(t)
	e := NewPatternEvaluator(true)

	algorithmic, checked := 0, 0
	for _, r := range rows {
		if r.Class == classAlgorithmic {
			algorithmic++
		}
		v := censusResolveValidator(r.PolicyID, r.Category)
		if v == nil {
			continue
		}
		name := shortValidatorName(t, v)
		probe, ok := validatorProbes[name]
		if !ok {
			t.Errorf("%s resolves %s, which has no probe in validatorProbes", r.PolicyID, name)
			continue
		}

		accepted := probe.label + probe.value
		d, ok := deriveRefusedThenAccepted(v, probe)
		if !ok {
			t.Errorf("%s (%s): no refused occurrence could be derived from probe %q; the row cannot be measured, "+
				"which is a failure rather than a skip", r.PolicyID, name, probe.value)
			continue
		}
		refused, input, pattern, refusedAt, validAt := d.refused, d.input, d.pattern, d.refusedAt, d.validAt

		// CONTROLS, computed with the pattern and the validator directly - not
		// with the scan under test: exactly two occurrences at the intended
		// spans, the first refused and the second accepted in place.
		locs := pattern.FindAllStringIndex(input, -1)
		if len(locs) != 2 || locs[0][0] != refusedAt || locs[0][1] != refusedAt+len(d.refusedValue) ||
			locs[1][0] != validAt || locs[1][1] != validAt+len(probe.value) {
			t.Errorf("%s: the pattern finds %v in %q, want %q at %d and %q at %d", r.PolicyID, locs, input, d.refusedValue, refusedAt, probe.value, validAt)
			continue
		}
		if ok, _ := v(d.refusedValue, MatchContext(input, refusedAt, refusedAt+len(d.refusedValue), DefaultContextWindow)); ok {
			t.Errorf("%s: %s accepts the derived refused occurrence %q in place", r.PolicyID, name, d.refusedValue)
			continue
		}
		if ok, _ := v(probe.value, MatchContext(input, validAt, validAt+len(probe.value), DefaultContextWindow)); !ok {
			t.Errorf("%s: %s refuses the probe %q in place (accepted form %q)", r.PolicyID, name, probe.value, accepted)
			continue
		}

		p := CompiledPolicy{
			PolicyID: r.PolicyID, Category: PolicyCategory(r.Category),
			Pattern: pattern, PatternStr: pattern.String(), Enabled: true, Validator: v,
		}
		checked++

		if m := e.Evaluate(refused, &p); m != nil {
			t.Errorf("%s: request path matched the lone refused occurrence %q", r.PolicyID, refused)
		}
		if ms := e.EvaluateAll(refused, &p); len(ms) != 0 {
			t.Errorf("%s: response path matched the lone refused occurrence %q", r.PolicyID, refused)
		}
		m := e.Evaluate(input, &p)
		if m == nil || m.StartIndex != validAt {
			t.Errorf("%s (%s): request path returned %+v for %q, want the accepted occurrence at %d", r.PolicyID, name, m, input, validAt)
		}
		ms := e.EvaluateAll(input, &p)
		if len(ms) != 1 || ms[0].StartIndex != validAt {
			t.Errorf("%s (%s): response path returned %+v for %q, want exactly the accepted occurrence at %d", r.PolicyID, name, ms, input, validAt)
		}
	}

	// ANTI-VACUITY. Every assertion above sits in a loop; an emptied or
	// reclassified census would pass them all having compared nothing. The floor
	// is DERIVED from the same census: every algorithmic row must have been
	// measured.
	if checked == 0 || checked != algorithmic {
		t.Fatalf("measured %d validator-gated row(s); the census classifies %d as algorithmic, and each must be measured", checked, algorithmic)
	}
}

// refusedThenAccepted is one derived measurement input:
// `<refused> then <label><probe value>`.
type refusedThenAccepted struct {
	refused, refusedValue, input string
	pattern                      *regexp.Regexp
	refusedAt, validAt           int
}

// deriveRefusedThenAccepted derives an occurrence the validator refuses at the
// head of the input, with the labelled probe after it, checking both verdicts
// IN PLACE - with the exact context the scan will build at each position.
//
// The refused value is always a DIFFERENT string from the probe. An identical
// copy would measure leftContextOf rather than the scan: it locates a match in
// its context window by searching for the match's TEXT, so two identical values
// inside one window both read the FIRST copy's left context.
//
// Candidates, in order: every single-character substitution of the probe and
// every prefix of each - a digit-count validator such as ValidatePhone refuses
// only a shorter value - each first unlabelled, then labelled. The probe value
// is the FIRST alternative of the pattern, so a refused value that happens to be
// a prefix of it can never win at the accepted position.
func deriveRefusedThenAccepted(v ValidatorFunc, probe validatorProbe) (refusedThenAccepted, bool) {
	accepted := probe.label + probe.value
	seen := map[string]bool{}
	try := func(value string) (refusedThenAccepted, bool) {
		if value == "" || seen[value] || strings.Contains(value, probe.value) {
			return refusedThenAccepted{}, false
		}
		seen[value] = true
		for _, label := range []string{"", probe.label} {
			refused := label + value
			d := refusedThenAccepted{
				refused: refused, refusedValue: value, input: refused + " then " + accepted,
				pattern:   regexp.MustCompile(regexp.QuoteMeta(probe.value) + "|" + regexp.QuoteMeta(value)),
				refusedAt: len(label), validAt: len(refused) + len(" then ") + len(probe.label),
			}
			locs := d.pattern.FindAllStringIndex(d.input, -1)
			if len(locs) != 2 || locs[0][0] != d.refusedAt || locs[1][0] != d.validAt || locs[1][1] != d.validAt+len(probe.value) {
				continue
			}
			if ok, _ := v(value, MatchContext(d.input, d.refusedAt, d.refusedAt+len(value), DefaultContextWindow)); ok {
				continue
			}
			if ok, _ := v(probe.value, MatchContext(d.input, d.validAt, d.validAt+len(probe.value), DefaultContextWindow)); !ok {
				continue
			}
			return d, true
		}
		return refusedThenAccepted{}, false
	}

	const alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz.@-"
	for i := 0; i < len(probe.value); i++ {
		for _, c := range alphabet {
			if byte(c) == probe.value[i] {
				continue
			}
			mutated := probe.value[:i] + string(c) + probe.value[i+1:]
			for n := len(mutated); n > 0; n-- {
				if d, ok := try(mutated[:n]); ok {
					return d, true
				}
			}
		}
	}
	return refusedThenAccepted{}, false
}
