// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestResumePlanActorIdentity pins the plan-resume actor resolution.
//
// R3 round 2: the route read X-User-ID ONLY, while both siblings it claims
// parity with - workflow_control.Handler.getUserID and mapHITLActorIdentity -
// fall back to X-User-Email. With the trust gate on and a caller presenting
// only an email, this route recorded "system" where every other plane
// recorded the human, in workflow_steps.approved_by, the step_approved audit
// row AND (since #3408) the decide-plane mirror's reviewer columns.
//
// The empty case is the one with teeth: mig core/025:77 requires a non-NULL
// reviewer_id on a terminal status, so an empty actor fails the mirror's
// resolution and leaves the row pending - #3408 unfixed on this route. Before
// this test the substitution had no unit pin at all, only the realpg
// backstop.
func TestResumePlanActorIdentity(t *testing.T) {
	cases := []struct {
		name    string
		headers map[string]string
		want    string
	}{
		{"X-User-ID wins", map[string]string{"X-User-ID": "ops@example.com", "X-User-Email": "other@example.com"}, "ops@example.com"},
		{"X-User-Email is the documented fallback", map[string]string{"X-User-Email": "ops@example.com"}, "ops@example.com"},
		{"no identity substitutes system", map[string]string{}, "system"},
		{"whitespace-only is not an identity", map[string]string{"X-User-ID": "   ", "X-User-Email": "  "}, "system"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "/api/v1/plan/p1/resume", nil)
			for k, v := range tc.headers {
				r.Header.Set(k, v)
			}
			if got := resumePlanActorIdentity(r); got != tc.want {
				t.Errorf("resumePlanActorIdentity = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestResumePlanActorIdentityNeverReturnsEmpty is the property the mirror
// resolution depends on, asserted as a property rather than as three examples.
// A future edit that adds a header source and forgets the final fallback would
// pass every case above that happens to set a header.
func TestResumePlanActorIdentityNeverReturnsEmpty(t *testing.T) {
	for _, hdrs := range []map[string]string{
		{}, {"X-User-ID": ""}, {"X-User-Email": ""}, {"X-User-ID": "\t\n "},
		{"X-User-ID": "", "X-User-Email": ""},
		{"X-Tenant-ID": "t1"}, // a header this function must ignore
	} {
		r := httptest.NewRequest(http.MethodPost, "/api/v1/plan/p1/resume", nil)
		for k, v := range hdrs {
			r.Header.Set(k, v)
		}
		if got := resumePlanActorIdentity(r); got == "" {
			t.Errorf("resumePlanActorIdentity returned EMPTY for %v; "+
				"mig core/025:77 refuses a NULL reviewer_id on a terminal status, "+
				"so the #3408 mirror would stay pending", hdrs)
		}
	}
}
