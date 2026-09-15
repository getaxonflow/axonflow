// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
package agent

import "testing"

// #2867: the pre-check may prefetch connector data ONLY for a clean-approved
// request. A blocked request (incl. the #2862 policy-load fail-closed block) and
// an approved-with-redaction request must NOT prefetch: the previous
// else-branch fetched on every outcome except approved-with-redaction, so a
// denied request still executed the query and returned the rows.
func TestShouldPrefetchApprovedData(t *testing.T) {
	cases := []struct {
		name                       string
		blocked, requiresRedaction bool
		want                       bool
	}{
		{"clean approved -> prefetch", false, false, true},
		{"blocked -> no prefetch (data leak on deny)", true, false, false},
		{"approved with redaction -> no prefetch (raw PII)", false, true, false},
		{"blocked + redaction -> no prefetch", true, true, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := shouldPrefetchApprovedData(c.blocked, c.requiresRedaction); got != c.want {
				t.Errorf("shouldPrefetchApprovedData(blocked=%v, redaction=%v) = %v, want %v",
					c.blocked, c.requiresRedaction, got, c.want)
			}
		})
	}
}
