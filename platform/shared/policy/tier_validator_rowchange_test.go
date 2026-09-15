// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
//
// #3963's per-row before/after, over the real corpus.
//
// # SINCE #4253 IT RUNS OVER proxy_request
//
// #4253 deleted the tier engine and retired its plane, `proxy_tier`, and with
// it every row's evaluation there. The same twenty algorithmic rows evaluate on
// `proxy_request`, /api/request's one pass, whose only static site
// (EvaluateRequest, reached through proxyDetectorPass) resolves each row's
// validator in the shared engine with a context window built from the match
// location. So the report below now holds what the one pass does with each of
// them; the #3963 narrative that follows is how the tier plane got there.
//
// The issue asks for it in those words: *"A before/after over the real corpus.
// This changes a live enforcement path: things currently blocked on
// `proxy_tier` will stop being blocked, because they were false positives. That
// is a correctness improvement and still a behaviour change, and it needs the
// same per-row treatment as everything else in this release."*
//
// # WHAT CHANGED, AND WHY "TWENTY ROWS GET MORE PRECISE" IS THE WRONG SUMMARY
//
// Twenty rows in `detectors_census.tsv` are class `algorithmic` and evaluate on
// `proxy_tier`. Before this change none of them ran its validator there. After
// it, all twenty do. But they do not all move for the same reason, and one of
// them moves in the OPPOSITE DIRECTION from the other nineteen:
//
//	nineteen rows  a real algorithm or a label requirement rejects values that
//	               were never instances of the thing. FEWER FALSE POSITIVES.
//	sys_pii_booking_ref  its validator rejects EVERY value its pattern can
//	               produce, so the row stops detecting anything at all.
//	               A DETECTION THAT FIRES TODAY DISAPPEARS.
//
// That last row is documented as intentionally validator-inert - a booking
// reference is not PII to redact - and it was inert on every plane except this
// one. So the change makes it consistent, and it is still the row an operator
// would notice, because something they see today stops appearing.
//
// # THE SECOND MECHANISM, WHICH IS NOT VISIBLE IN THE CENSUS AT ALL
//
// EIGHT of the nineteen resolve a CONTEXT-GATED validator - one that requires a
// label IMMEDIATELY PRECEDING the value, read from the `context` argument.
//
// Those eight would ALSO have stopped detecting everything, for a completely
// different reason from booking_ref: the tier engine called `re.MatchString`,
// which yields no match location, and a validator handed an empty context
// rejects every input. Wiring the validator without also building the context
// window would have removed eight detections while looking like the same fix as
// every other row. Two national identity numbers are among them.
//
// THE COUNT WAS DERIVED THREE TIMES AND DISAGREED TWICE, which is why it is now
// measured rather than listed. Four (validators believed gated), then five
// (rows, from those four validators), then seven (a peer's independent
// measurement, adding Aadhaar and Singapore NRIC). The answer is EIGHT rows
// from SEVEN validators: the peer's two were real and my enumeration had missed
// them, `ValidatePassport` serves two rows, and `ValidateSingaporeFIN` is gated
// as well - a row neither derivation had, which the peer had explicitly flagged
// as structurally certain but UNMEASURED because their probe was refused with
// and without a label. It was refused for a different reason: the probe did not
// satisfy the `[FG]\d{7}[A-Z]` shape. With a well-formed one it accepts.
//
// The census cannot see any of this - it records which validator resolves, not
// what that validator needs - so it is MEASURED here, and the behavioural proof
// that the window IS built, for the shared engine's request pass that
// proxy_request runs, lives in one_validator_set_test.go
// (TestEveryValidatorBearingRowDetectsTheSameOnRequestAndResponse); the tier
// engine's own proof was deleted with it (#4253).
//
// # WHY THIS IS DERIVED AND NOT A LIST
//
// The population, the class and the resolved validator all come from the census
// TSV and from ValidatorFor - the same function the engines call. Nothing here
// transcribes a row name except the exceptions, which are the point.

package policy

import (
	"sort"
	"strings"
	"testing"
)

// validatorProbe is one input a validator ACCEPTS when correctly labelled,
// together with the label. Every validator the corpus resolves must have one.
//
// # WHY EVERY VALIDATOR AND NOT JUST THE GATED ONES
//
// The first version of this file carried a map of the FOUR validators believed
// to be context-gated, and the behavioural check skipped anything not in it.
// That holds the listed ones honest and CANNOT DISCOVER an unlisted one — which
// is the "list somebody typed" failure, inside the test written to prevent it.
// It undercounted: `ValidateAadhaar` and `ValidateSingaporeNRIC` are gated and
// were absent, and so is `ValidateSingaporeFIN`, which nobody had.
//
// So the classification is now DERIVED. Every validator gets a probe, each is
// driven three ways, and whether it is context-gated is the answer that comes
// back rather than a property of which map it was written into. A validator
// with no probe fails the census outright: an unmeasured row is worth naming as
// unmeasured, and is never silently in or out of a list.
type validatorProbe struct {
	// value is a string the validator accepts GIVEN the label.
	value string
	// label immediately precedes the value in a well-formed context.
	label string
}

// validatorProbes covers every validator the algorithmic corpus resolves.
//
// The probes are chosen to satisfy each validator's NON-CONTEXT requirements —
// Luhn for a card, the ABA checksum and a 17-to-26-digit length for a bank
// account, the `[FG]\d{7}[A-Z]` shape for a Singapore FIN — so that the only
// thing varying across the three drives is the context. A probe that fails for
// a different reason reports "refuses everything", which the census treats as
// an unmeasured row rather than as evidence of gating.
var validatorProbes = map[string]validatorProbe{
	"ValidatePassport":        {value: "X1234567", label: "passport no "},
	"ValidateDOB":             {value: "03/04/1985", label: "date of birth "},
	"ValidateSingaporePostal": {value: "238823", label: "postal code "},
	"ValidateSingaporeUEN":    {value: "201612345K", label: "UEN "},
	"ValidateAadhaar":         {value: "234567890123", label: "aadhaar "},
	"ValidateSingaporeNRIC":   {value: "S1234567D", label: "NRIC "},
	"ValidateSingaporeFIN":    {value: "F1234567X", label: "FIN: "},
	"ValidateCreditCard":      {value: "4111111111111111", label: "card "},
	"ValidateSSN":             {value: "123-45-6789", label: "ssn "},
	"ValidateIBAN":            {value: "GB82WEST12345698765432", label: "iban "},
	"ValidateEmail":           {value: "a@b.com", label: "email "},
	"ValidatePhone":           {value: "415-555-0132", label: "phone "},
	"ValidateIPAddress":       {value: "192.168.1.1", label: "ip "},
	"ValidateBankAccount":     {value: "02100002112345678", label: "account "},
	"ValidatePAN":             {value: "ABCPD1234E", label: "pan "},
}

// contextGating is the measured answer for one validator.
type contextGating int

const (
	gatingUnmeasured contextGating = iota // the probe is refused even when labelled
	gatingGated                           // labelled accepts, unlabelled and empty refuse
	gatingUngated                         // accepts with no context at all
)

// measureContextGating drives a validator three ways and reports which it is.
//
// The three drives are the whole classification: a validator that needs a
// preceding label accepts only the first; one that does not accepts all three;
// and one whose probe is wrong for some OTHER reason accepts none, which is
// reported as unmeasured rather than quietly counted as gated.
func measureContextGating(v ValidatorFunc, p validatorProbe) contextGating {
	labelledOK, _ := v(p.value, p.label+p.value)
	unlabelledOK, _ := v(p.value, p.value)
	emptyOK, _ := v(p.value, "")
	switch {
	case labelledOK && !unlabelledOK && !emptyOK:
		return gatingGated
	case emptyOK:
		return gatingUngated
	default:
		return gatingUnmeasured
	}
}

// TestEveryAlgorithmicRowOnTheOnePassIsAccountedFor is #3963's before/after,
// held over proxy_request since #4253.
func TestEveryAlgorithmicRowOnTheOnePassIsAccountedFor(t *testing.T) {
	rows := loadDetectorCensus(t)

	var affected []detectorCensusRow
	for _, r := range rows {
		if r.Class != classAlgorithmic {
			continue
		}
		if !planeListContains(r.Planes, "proxy_request") {
			continue
		}
		affected = append(affected, r)
	}
	sort.Slice(affected, func(i, j int) bool { return affected[i].PolicyID < affected[j].PolicyID })

	// ANTI-VACUITY. The whole report below is over this population; if the
	// census stopped classifying or stopped listing the plane, every "no row
	// changed" conclusion would be true of an empty set. Twenty is what the
	// issue counts and what the corpus contains.
	if len(affected) != 20 {
		t.Fatalf("%d algorithmic rows evaluate on proxy_request; #3963 counted 20 on the tier plane, #4253 found the same 20 on the one pass, and the census "+
			"contained 20 when this was written. Either the corpus changed - in which case this "+
			"number moves deliberately - or the class/planes derivation has stopped working, in "+
			"which case every conclusion below is about the wrong set.", len(affected))
	}

	// Every affected row must now be validator-gated ON THIS PLANE. This is the
	// "after" half, read from the same column the census derives.
	var stillBare []string
	for _, r := range affected {
		if !planeListContains(r.ValidatorPlanes, "proxy_request") {
			stillBare = append(stillBare, r.PolicyID)
		}
	}
	if len(stillBare) > 0 {
		t.Errorf("%d algorithmic row(s) run bare on proxy_request: %v. Its only static site is the shared engine's EvaluateRequest, and #3963 is the change that "+
			"makes every one of them validator-gated there.", len(stillBare), stillBare)
	}

	// --- the per-row report, and the two exceptional buckets ---------------
	var losesEverything, contextGated, morePrecise, unmeasured []string
	for _, r := range affected {
		v := ValidatorFor(r.PolicyID, PolicyCategory(r.Category))
		if v == nil {
			t.Errorf("%s: censused algorithmic and ValidatorFor resolves nothing, so the one pass "+
				"validates nothing for it - the class is wrong", r.PolicyID)
			continue
		}
		name := shortValidatorName(t, v)

		probe, hasProbe := validatorProbes[name]
		if !hasProbe {
			t.Errorf("%s resolves %s and no probe covers it, so this row is UNCLASSIFIED: the report "+
				"below neither says it loses a detection nor says it does not. Add a probe.",
				r.PolicyID, name)
			continue
		}
		switch {
		case r.PolicyID == "sys_pii_booking_ref":
			losesEverything = append(losesEverything, r.PolicyID+" ("+name+")")
		default:
			switch measureContextGating(v, probe) {
			case gatingGated:
				contextGated = append(contextGated, r.PolicyID+" ("+name+")")
			case gatingUngated:
				morePrecise = append(morePrecise, r.PolicyID+" ("+name+")")
			default:
				unmeasured = append(unmeasured, r.PolicyID+" ("+name+")")
			}
		}
	}
	sort.Strings(losesEverything)
	sort.Strings(contextGated)
	sort.Strings(morePrecise)
	sort.Strings(unmeasured)

	t.Logf("#3963's report over the real corpus, on the one pass (#4253) - %d algorithmic rows on proxy_request", len(affected))
	t.Logf("")
	t.Logf("  (1) DETECTS NOTHING - its validator rejects every value its pattern produces  [%d]",
		len(losesEverything))
	for _, r := range losesEverything {
		t.Logf("        %s", r)
	}
	t.Logf("  (2) CONTEXT-GATED - would ALSO have stopped detecting, had the context")
	t.Logf("      window not been built; unlabelled values stop matching, labelled")
	t.Logf("      ones still do                                                       [%d]",
		len(contextGated))
	for _, r := range contextGated {
		t.Logf("        %s", r)
	}
	t.Logf("  (3) FEWER FALSE POSITIVES - the value is checked and non-instances stop")
	t.Logf("      matching                                                            [%d]",
		len(morePrecise))
	for _, r := range morePrecise {
		t.Logf("        %s", r)
	}

	// The two exceptional buckets are asserted, not merely printed. A report
	// nobody holds to a number is a report that quietly empties out.
	if len(losesEverything) != 1 {
		t.Errorf("bucket (1) holds %d row(s): %v. Exactly one row - sys_pii_booking_ref - resolves a "+
			"validator that rejects every value its own pattern can produce. If another row joins it, "+
			"that is a detection disappearing and it needs naming in the release notes; if this one "+
			"leaves it, the category default or the token mapping changed.",
			len(losesEverything), losesEverything)
	}
	if len(contextGated) != 8 {
		t.Errorf("bucket (2) holds %d row(s): %v. EIGHT rows resolve a context-gated validator - "+
			"measured, not listed - and they are the ones an empty context would have silently "+
			"killed. This number was derived as four, then five, then seven before it was measured; "+
			"if it moves again, measure before believing it.", len(contextGated), contextGated)
	}
	if len(morePrecise) != 11 {
		t.Errorf("bucket (3) holds %d row(s): %v", len(morePrecise), morePrecise)
	}
	if len(unmeasured) != 0 {
		t.Errorf("%d row(s) could not be classified because their probe was refused even when "+
			"labelled: %v. An unmeasured row is neither in nor out of the report, which is worse "+
			"than either - fix the probe.", len(unmeasured), unmeasured)
	}
}

// TestEveryResolvedValidatorIsProbedAndClassified is what makes the report's
// counts trustworthy, and it is the check whose absence caused them to be wrong.
//
// The first version of this file skipped any validator not in a hand-written
// "context-gated" map. That holds the listed ones honest and is BLIND to an
// unlisted one — so `ValidateAadhaar`, `ValidateSingaporeNRIC` and
// `ValidateSingaporeFIN` were gated, absent from the map, and silently counted
// in the wrong bucket. Two of them govern national identity numbers.
//
// This inverts it: the corpus supplies the population, every validator it
// resolves MUST have a probe, and each is driven three ways. Nothing is skipped
// for not being on a list, because there is no list to be off.
func TestEveryResolvedValidatorIsProbedAndClassified(t *testing.T) {
	rows := loadDetectorCensus(t)

	resolved := map[string]ValidatorFunc{}
	for _, r := range rows {
		if r.Class != classAlgorithmic {
			continue
		}
		if v := ValidatorFor(r.PolicyID, PolicyCategory(r.Category)); v != nil {
			resolved[shortValidatorName(t, v)] = v
		}
	}

	// ANTI-VACUITY: an empty population would satisfy every assertion below.
	if len(resolved) < 10 {
		t.Fatalf("the corpus resolves only %d distinct validators; the census has stopped "+
			"classifying and every count in the report is about the wrong set", len(resolved))
	}

	var gated, ungated, unmeasured []string
	for name, v := range resolved {
		probe, ok := validatorProbes[name]
		if !ok {
			t.Errorf("%s is resolved by the corpus and has NO probe, so its context gating is "+
				"unknown and the before/after report cannot classify the rows that use it. Add one "+
				"to validatorProbes.", name)
			continue
		}
		switch measureContextGating(v, probe) {
		case gatingGated:
			gated = append(gated, name)
		case gatingUngated:
			ungated = append(ungated, name)
		default:
			unmeasured = append(unmeasured, name)
		}
	}
	sort.Strings(gated)
	sort.Strings(ungated)
	sort.Strings(unmeasured)

	t.Logf("context-gated validators (%d): %v", len(gated), gated)
	t.Logf("ungated validators       (%d): %v", len(ungated), ungated)

	// A probe refused even WHEN LABELLED measures nothing: it fails for some
	// reason other than context, and reporting it either way would be a guess.
	// Naming it as unmeasured is the honest outcome and the reason this bucket
	// exists rather than being folded into "ungated" — that fold is exactly how
	// ValidateSingaporeFIN went unclassified in an earlier derivation.
	if len(unmeasured) > 0 {
		t.Errorf("%d validator(s) refuse their probe even when labelled, so their gating is "+
			"UNMEASURED: %v. The probe fails for a reason other than context — fix the probe "+
			"rather than assuming the answer.", len(unmeasured), unmeasured)
	}

	// Both classes must be populated, or the measurement has collapsed to a
	// constant and would classify every row identically.
	if len(gated) == 0 || len(ungated) == 0 {
		t.Errorf("gating measured as %d gated / %d ungated; with either at zero the three drives "+
			"are returning the same answer for everything", len(gated), len(ungated))
	}
	if len(gated) != 7 {
		t.Errorf("%d validators measure as context-gated, expected 7 (%v). This number has been "+
			"derived wrongly three times; if it has genuinely moved, move it here deliberately.",
			len(gated), gated)
	}
}

// planeListContains reports whether a census plane column names a plane. The
// column may carry a "(mixed)" suffix, which is a qualification of the plane
// rather than a different plane.
func planeListContains(list, plane string) bool {
	if list == "-" || list == "" {
		return false
	}
	for _, p := range strings.Split(list, ",") {
		if strings.TrimSuffix(strings.TrimSpace(p), mixedPlaneSuffix) == plane {
			return true
		}
	}
	return false
}

// shortValidatorName returns the bare function name of a resolved validator,
// derived through the census's own runtime.FuncForPC site resolution rather
// than from anything transcribed.
func shortValidatorName(t *testing.T, v ValidatorFunc) string {
	t.Helper()
	site, err := censusValidatorSite(v)
	if err != nil {
		t.Fatalf("resolving the validator's implementation site: %v", err)
	}
	if i := strings.LastIndex(site, "::"); i >= 0 {
		return site[i+2:]
	}
	return site
}
