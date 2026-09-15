// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

// #3360: convertSharedResultToStatic counts every DOWNWARD displacement - a
// matched policy whose stored action an organization's recorded detection
// override weakened, since #3961 the only thing that can - and stays silent for
// upward or equal resolution, for a match carrying no stored action, and for a
// blocked result.

import (
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

// displacedCount reads the counter for one (stored, resolved) pair of the KTP
// fixture's category.
func displacedCount(stored, resolved sharedpolicy.Action) float64 {
	return testutil.ToFloat64(policyStoredActionDisplaced.WithLabelValues(string(sharedpolicy.CategoryPIIIndonesia), string(stored), string(resolved)))
}

func TestConvert_DownwardDisplacementIsCounted(t *testing.T) {
	before := displacedCount(sharedpolicy.ActionBlock, sharedpolicy.ActionRedact)
	convertSharedResultToStatic(&sharedpolicy.RequestResult{
		MatchedPolicies: []sharedpolicy.PolicyMatch{displacedKTPMatch()},
	})
	if after := displacedCount(sharedpolicy.ActionBlock, sharedpolicy.ActionRedact); after != before+1 {
		t.Fatalf("a downward displacement must be counted once: %v -> %v", before, after)
	}
}

func TestConvert_NoDisplacementCountedForEqualUpwardBlockedOrLegacy(t *testing.T) {
	for _, c := range []struct {
		name             string
		stored, resolved sharedpolicy.Action
		blocked          bool
	}{
		{"equal stored and resolved", sharedpolicy.ActionRedact, sharedpolicy.ActionRedact, false},
		{"upward: an override tightening", sharedpolicy.ActionLog, sharedpolicy.ActionWarn, false},
		// A match evaluated by an engine predating #3360 carries no StoredAction;
		// absence must never be treated as displacement.
		{"no stored action", "", sharedpolicy.ActionRedact, false},
		// Nothing was weakened into an allow when the request was blocked.
		{"a blocked result", sharedpolicy.ActionBlock, sharedpolicy.ActionRedact, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			match := displacedKTPMatch()
			match.StoredAction, match.Action = c.stored, c.resolved
			result := &sharedpolicy.RequestResult{MatchedPolicies: []sharedpolicy.PolicyMatch{match}}
			if c.blocked {
				result.Blocked, result.BlockReason = true, "blocked by another policy"
			}
			before := displacedCount(c.stored, c.resolved)
			convertSharedResultToStatic(result)
			if after := displacedCount(c.stored, c.resolved); after != before {
				t.Fatalf("counted a displacement: %v -> %v", before, after)
			}
		})
	}
}

func TestConvert_DisplacementCountedOncePerPolicy(t *testing.T) {
	before := displacedCount(sharedpolicy.ActionBlock, sharedpolicy.ActionRedact)
	convertSharedResultToStatic(&sharedpolicy.RequestResult{
		MatchedPolicies: []sharedpolicy.PolicyMatch{displacedKTPMatch(), displacedKTPMatch()},
	})
	if after := displacedCount(sharedpolicy.ActionBlock, sharedpolicy.ActionRedact); after != before+1 {
		t.Fatalf("one displacement per policy id: %v -> %v", before, after)
	}
}
