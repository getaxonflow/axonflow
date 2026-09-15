// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package policy

import (
	"context"
	"testing"
)

// A RESPONSE WITH NO TEXT IN IT IS DECIDED, NOT WITHHELD.
//
// The response phase scans only a content's string values, so rows of numbers -
// `SELECT id` - leave nothing to scan. Every detector that survived the filters
// still looked, and found no text to match: a determined no. Reported as not
// run, each would reach the anchored engine UNKNOWN, and the MCP response pass
// withheld every numeric result as unknown_requirement.
func TestADetectorOverAResponseWithNoTextIsDecidedNotUnknown(t *testing.T) {
	e := createTestEngine(capabilityScopingPolicies())
	ctx := context.Background()
	opts := redactDecidedOpts()

	for _, c := range []struct {
		name    string
		content interface{}
	}{
		{"rows of numbers", []map[string]interface{}{{"id": 1}, {"id": 2}}},
		{"no rows", []map[string]interface{}{}},
	} {
		t.Run(c.name, func(t *testing.T) {
			got := e.EvaluateResponse(ctx, c.content, opts)
			if got.Blocked {
				t.Fatalf("a response with no text was blocked by %v", got.MatchedPolicies)
			}
			for id, f := range capabilityFacts(t, got.Observation) {
				if !f.Ran || f.Matched {
					t.Errorf("%s reports %+v; a detector over no text ran and did not match", id, f)
				}
			}
		})
	}

	t.Run("a detector the category filter removed still did not look", func(t *testing.T) {
		skip := opts
		skip.SkipCategories = []PolicyCategory{"dangerous_queries"}
		got := capabilityFacts(t, e.EvaluateResponse(ctx, []map[string]interface{}{{"id": 1}}, skip).Observation)
		if f := got["test_exec"]; f.Ran {
			t.Fatalf("test_exec reports %+v; the category filter removed it, so it did not look even at no text", f)
		}
		if f := got["test_content"]; !f.Ran || f.Matched {
			t.Fatalf("test_content reports %+v; want ran and unmatched", f)
		}
	})

	t.Run("CONTROL: a response with text is scanned, and a match is reported", func(t *testing.T) {
		got := capabilityFacts(t, e.EvaluateResponse(ctx, []map[string]interface{}{{"note": "the secret-token is here"}}, opts).Observation)
		if f := got["test_content"]; !f.Ran || !f.Matched {
			t.Fatalf("test_content reports %+v; want ran and matched", f)
		}
	})
}
