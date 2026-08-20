// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

// #3360: convertSharedResultToStatic must surface every DOWNWARD posture
// displacement (a matched policy whose stored action the lever weakened) as a
// truthful advisory reason plus a metric, and stay silent for upward/equal
// resolution and for blocked results.

import (
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"

	sharedpolicy "axonflow/platform/shared/policy"
)

func displacedKTPMatch() sharedpolicy.PolicyMatch {
	return sharedpolicy.PolicyMatch{
		PolicyID:     "sys_pii_indonesia_ktp",
		PolicyName:   "Indonesian KTP Detection",
		Category:     sharedpolicy.CategoryPIIIndonesia,
		Action:       sharedpolicy.ActionRedact,
		StoredAction: sharedpolicy.ActionBlock,
	}
}

func TestConvert_DownwardDisplacementEmitsAdvisoryAndMetric(t *testing.T) {
	before := testutil.ToFloat64(policyStoredActionDisplaced.WithLabelValues("pii-indonesia", "block", "redact"))
	res := convertSharedResultToStatic(&sharedpolicy.RequestResult{
		MatchedPolicies: []sharedpolicy.PolicyMatch{displacedKTPMatch()},
	})
	var advisory string
	for _, r := range res.AdvisoryReasons {
		if strings.Contains(r, "stores action=block") {
			advisory = r
		}
	}
	if advisory == "" {
		t.Fatalf("downward displacement must emit an advisory reason, got %v", res.AdvisoryReasons)
	}
	for _, want := range []string{"sys_pii_indonesia_ktp", "resolved to action=redact", "PII_ACTION", "pii-indonesia"} {
		if !strings.Contains(advisory, want) {
			t.Fatalf("advisory must name %q: %q", want, advisory)
		}
	}
	after := testutil.ToFloat64(policyStoredActionDisplaced.WithLabelValues("pii-indonesia", "block", "redact"))
	if after != before+1 {
		t.Fatalf("displacement metric must increment once: before=%v after=%v", before, after)
	}
}

func TestConvert_NoAdvisoryForEqualUpwardBlockedOrLegacy(t *testing.T) {
	displacedNote := func(res *StaticPolicyResult) bool {
		for _, r := range res.AdvisoryReasons {
			if strings.Contains(r, "stores action=") {
				return true
			}
		}
		return false
	}

	equal := displacedKTPMatch()
	equal.StoredAction = sharedpolicy.ActionRedact
	if displacedNote(convertSharedResultToStatic(&sharedpolicy.RequestResult{
		MatchedPolicies: []sharedpolicy.PolicyMatch{equal},
	})) {
		t.Fatalf("equal stored/resolved must not emit a displacement note")
	}

	upward := displacedKTPMatch()
	upward.StoredAction = sharedpolicy.ActionLog
	upward.Action = sharedpolicy.ActionWarn
	if displacedNote(convertSharedResultToStatic(&sharedpolicy.RequestResult{
		MatchedPolicies: []sharedpolicy.PolicyMatch{upward},
	})) {
		t.Fatalf("upward displacement (lever tightening) must not emit a note")
	}

	// A match evaluated by an engine predating #3360 carries no StoredAction;
	// absence must never be treated as displacement.
	legacy := displacedKTPMatch()
	legacy.StoredAction = ""
	if displacedNote(convertSharedResultToStatic(&sharedpolicy.RequestResult{
		MatchedPolicies: []sharedpolicy.PolicyMatch{legacy},
	})) {
		t.Fatalf("empty StoredAction must not emit a note")
	}

	blocked := displacedKTPMatch()
	if displacedNote(convertSharedResultToStatic(&sharedpolicy.RequestResult{
		Blocked:         true,
		BlockReason:     "blocked by another policy",
		MatchedPolicies: []sharedpolicy.PolicyMatch{blocked},
	})) {
		t.Fatalf("a blocked result must not emit displacement notes (nothing weakened into an allow)")
	}
}

func TestConvert_DisplacementDedupedPerPolicy(t *testing.T) {
	res := convertSharedResultToStatic(&sharedpolicy.RequestResult{
		MatchedPolicies: []sharedpolicy.PolicyMatch{displacedKTPMatch(), displacedKTPMatch()},
	})
	count := 0
	for _, r := range res.AdvisoryReasons {
		if strings.Contains(r, "stores action=block") {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("one displacement note per policy id, got %d (%v)", count, res.AdvisoryReasons)
	}
}
