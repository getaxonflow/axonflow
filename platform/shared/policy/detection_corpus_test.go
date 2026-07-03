// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package policy

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// Corpus-driven detection scoring (#2815 / #2806 fixture contract). This test
// consumes the per-category labeled fixtures in testdata/detection-corpus/ and
// scores recall-on-attack + FP-rate-on-benign PER CATEGORY against the shared
// engine loaded with the exact seed-migration patterns (corpusPolicies). It is
// the in-repo proof that the fixture schema is consumable and that the #2801
// capability scoping moves the FP number without regressing recall; Session D's
// scoring script (#2806) consumes the SAME files for the CI gate.
//
// Metric definitions are pinned in the fixtures README and mirror #2815:
//   FP-rate-on-benign = benign cases blocked ÷ benign cases
//   recall            = attack cases meeting `expect` ÷ attack cases

type corpusCase struct {
	ID                        string `json:"id"`
	Label                     string `json:"label"`
	Statement                 string `json:"statement"`
	ToolIdentity              string `json:"tool_identity"`
	Expect                    string `json:"expect"`
	ExpectedPolicyID          string `json:"expected_policy_id"`
	MustTriggerWithoutScoping bool   `json:"must_trigger_without_scoping"`
	Source                    string `json:"source"`
}

type corpusFile struct {
	SchemaVersion int          `json:"schema_version"`
	Category      string       `json:"category"`
	Description   string       `json:"description"`
	Cases         []corpusCase `json:"cases"`
}

// evaluateCorpusCase reports the observed outcome ("block"/"detect"/"allow")
// and the blocking/first-matched policy id for a case. Under a blocking posture
// (ActionBlock via the seeded patterns) a match on an execution/injection
// policy blocks; PII policies default to redact, so they "detect" (a match)
// without blocking — expect:detect covers that.
func evaluateCorpusCase(t *testing.T, engine *UnifiedPolicyEngine, c corpusCase) (outcome, policyID string) {
	t.Helper()
	res := engine.EvaluateRequest(context.Background(), c.Statement, EvalOptions{
		TenantID:     "test-tenant",
		ToolIdentity: c.ToolIdentity,
	})
	if res.Blocked {
		if res.BlockedBy != nil {
			return "block", res.BlockedBy.PolicyID
		}
		return "block", ""
	}
	if len(res.MatchedPolicies) > 0 {
		return "detect", res.MatchedPolicies[0].PolicyID
	}
	return "allow", ""
}

func satisfies(expect, outcome string) bool {
	switch expect {
	case "allow":
		return outcome == "allow"
	case "block":
		return outcome == "block"
	case "detect":
		// A block is a stronger form of detection.
		return outcome == "detect" || outcome == "block"
	}
	return false
}

func TestDetectionCorpus_PerCategoryScoring(t *testing.T) {
	dir := filepath.Join("testdata", "detection-corpus")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read corpus dir: %v", err)
	}

	// The seeded-pattern engine shared with the FP/TP corpus tests. PII
	// policies here default to warn/redact (detect-not-block), matching the
	// posture the `pii` category's expect:detect cases assume.
	engine := createTestEngine(corpusPolicies())

	scored := 0
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		var cf corpusFile
		if err := json.Unmarshal(raw, &cf); err != nil {
			t.Fatalf("parse %s: %v", e.Name(), err)
		}
		if cf.SchemaVersion != 1 {
			t.Errorf("%s: unexpected schema_version %d (want 1)", e.Name(), cf.SchemaVersion)
		}
		if cf.Category == "" || len(cf.Cases) == 0 {
			t.Errorf("%s: category/cases must be non-empty", e.Name())
			continue
		}

		t.Run(cf.Category, func(t *testing.T) {
			var benign, benignBlocked, attacks, recalled int
			ids := map[string]bool{}
			for _, c := range cf.Cases {
				if ids[c.ID] {
					t.Errorf("duplicate case id %q", c.ID)
				}
				ids[c.ID] = true
				if c.Label != "benign" && c.Label != "attack" {
					t.Errorf("case %q: label must be benign|attack, got %q", c.ID, c.Label)
				}

				outcome, gotPolicy := evaluateCorpusCase(t, engine, c)
				if !satisfies(c.Expect, outcome) {
					t.Errorf("case %q: expect %q, observed %q (policy=%q)", c.ID, c.Expect, outcome, gotPolicy)
				}
				if c.ExpectedPolicyID != "" && (outcome == "block" || outcome == "detect") && gotPolicy != c.ExpectedPolicyID {
					t.Errorf("case %q: matched %q, expected_policy_id %q", c.ID, gotPolicy, c.ExpectedPolicyID)
				}

				switch c.Label {
				case "benign":
					benign++
					if outcome == "block" {
						benignBlocked++
					}
					// Corpus-health: a benign case that passes because of
					// capability scoping MUST still trigger its detector under
					// an unclassified identity — else the case is silently
					// passing because the pattern rotted, not because of the fix.
					if c.MustTriggerWithoutScoping {
						oc, _ := evaluateCorpusCase(t, engine, corpusCase{Statement: c.Statement, ToolIdentity: ""})
						if oc == "allow" {
							t.Errorf("case %q: must_trigger_without_scoping but observed allow under empty identity — stale corpus", c.ID)
						}
					}
				case "attack":
					attacks++
					if satisfies(c.Expect, outcome) {
						recalled++
					}
				}
			}

			// Per-category metrics (pinned denominators, #2815). This in-repo
			// gate asserts the strict targets on the curated corpus; Session D's
			// script scores the larger #2806 corpus in CI.
			if attacks > 0 {
				recall := float64(recalled) / float64(attacks)
				if recall < 0.99 {
					t.Errorf("%s recall %.4f < 0.99 (%d/%d)", cf.Category, recall, recalled, attacks)
				}
				t.Logf("%s recall = %d/%d", cf.Category, recalled, attacks)
			}
			if benign > 0 {
				fpRate := float64(benignBlocked) / float64(benign)
				if fpRate > 0.001 {
					t.Errorf("%s FP-rate-on-benign %.4f > 0.001 (%d/%d)", cf.Category, fpRate, benignBlocked, benign)
				}
				t.Logf("%s FP-rate-on-benign = %d/%d", cf.Category, benignBlocked, benign)
			}
			scored++
		})
	}
	if scored == 0 {
		t.Fatal("no corpus categories scored — fixtures missing?")
	}
}
