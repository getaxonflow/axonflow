// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package policy

import (
	"context"
	"strings"
	"testing"
)

// THE PARAMETER SCAN RUNS EVERY DETECTOR PAST A BLOCK TOO (W3-G).
//
// The request pass's parameter scan used to be skipped once the query string
// blocked, to stop inside a parameter at its first block, and to stop at the
// first parameter that blocked. Each stop left a later match unrecorded, and
// the anchored engine reads a detector's facts from this pass. Each case below
// is the one a single restored stop hides, and every case keeps the legacy
// verdict: blocked by the first block, test_block.
func TestTheParameterScanRunsEveryDetectorPastABlock(t *testing.T) {
	e := createTestEngine(redactDecidedPolicies())
	ctx := context.Background()
	withParameters := func(p map[string]interface{}) EvalOptions {
		o := redactDecidedOpts()
		o.Parameters = p
		return o
	}
	matched := func(r *RequestResult, id string) bool {
		if r.Observation == nil {
			t.Fatal("the evaluation returned no detector facts")
		}
		for _, row := range r.Observation.Rows {
			if row.PolicyID == id {
				return row.Matched
			}
		}
		return false
	}

	for _, c := range []struct {
		name        string
		query       string
		params      map[string]interface{}
		blockReason string
	}{
		{
			name:   "the query string blocks and only a parameter carries the SSN: the scan still runs",
			query:  "DROP TABLE t",
			params: map[string]interface{}{"note": "ssn 123-45-6789"},
		},
		{
			name:        "one parameter both blocks and carries the SSN: the scan does not stop at that parameter's block",
			query:       "SELECT name FROM customers",
			params:      map[string]interface{}{"note": "DROP TABLE t WHERE ssn = '123-45-6789'"},
			blockReason: "in parameter 'note'",
		},
		{
			name:        "the first parameter in sorted order blocks and a later one carries the SSN: the scan reaches it",
			query:       "SELECT name FROM customers",
			params:      map[string]interface{}{"a": "DROP TABLE t", "b": "123-45-6789"},
			blockReason: "in parameter 'a'",
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := e.EvaluateRequest(ctx, c.query, withParameters(c.params))
			if !r.Blocked || r.BlockedBy == nil || r.BlockedBy.PolicyID != "test_block" {
				t.Fatalf("blocked=%v by=%v; the first block, test_block, is the verdict", r.Blocked, r.BlockedBy)
			}
			if c.blockReason != "" && !strings.Contains(r.BlockReason, c.blockReason) {
				t.Fatalf("block reason %q; want the first block's, %q", r.BlockReason, c.blockReason)
			}
			if !matched(r, "test_redact") {
				t.Fatal("test_redact did not match the SSN the parameters carry; the scan stopped at a block, and the anchored engine would read that detector as a determined no")
			}
		})
	}
}
