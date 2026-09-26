// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package anchoredenforcer

import (
	"strings"
	"testing"
	"time"

	"axonflow/platform/decision/contract"
)

// TestAdmittedFactsAreConfinedToTheScorerNamespace holds Call.AdmittedFacts to
// the one namespace it exists for (#3330): a scorer's signal. A detector path,
// a principal path, an argument, or a path the request already carries is
// refused, and Evaluate fails the request closed on it (CauseRequest).
func TestAdmittedFactsAreConfinedToTheScorerNamespace(t *testing.T) {
	now := time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)
	score := contract.Known(0.4, contract.ProvDetector, 1, now)
	t.Run("a scorer signal is taken", func(t *testing.T) {
		shared := contract.AttributeSet{}
		if err := mergeAdmittedFacts(shared, contract.AttributeSet{"signal.scorer.fincrime__fraud": score}); err != nil {
			t.Fatal(err)
		}
		if _, ok := shared["signal.scorer.fincrime__fraud"]; !ok {
			t.Fatal("the scorer's signal was not merged")
		}
	})
	t.Run("nothing stated merges nothing", func(t *testing.T) {
		shared := contract.AttributeSet{}
		if err := mergeAdmittedFacts(shared, nil); err != nil || len(shared) != 0 {
			t.Fatalf("err %v shared %v", err, shared)
		}
	})
	for _, path := range []string{
		"signal.detector.fincrime__high__value__amount__cap", // would restate a detector the observation owns
		"signal.risk_score", // the platform's content floor, not a scorer's
		"principal.region",
		"args.query",
		"env.environment",
		"signal.scorerx.fraud", // the prefix is a namespace, not a string prefix
	} {
		t.Run("refuses "+path, func(t *testing.T) {
			err := mergeAdmittedFacts(contract.AttributeSet{}, contract.AttributeSet{path: score})
			if err == nil || !strings.Contains(err.Error(), path) {
				t.Fatalf("err %v; want a refusal naming %s", err, path)
			}
		})
	}
	t.Run("refuses restating a path the request already carries", func(t *testing.T) {
		shared := contract.AttributeSet{"signal.scorer.fincrime__fraud": score}
		err := mergeAdmittedFacts(shared, contract.AttributeSet{"signal.scorer.fincrime__fraud": contract.Known(0.9, contract.ProvDetector, 1, now)})
		if err == nil || !strings.Contains(err.Error(), "already carries") {
			t.Fatalf("err %v; want a refusal", err)
		}
		if shared["signal.scorer.fincrime__fraud"].Value != 0.4 {
			t.Fatal("the stated value was replaced")
		}
	})
}
