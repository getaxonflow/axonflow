// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
//
// #3897 §2: the same question - "may I do this?" - was answered by five keys in
// two types across the governed surface. `verdict` (string) on /api/v1/decide,
// `approved` (bool) here, `allowed` (bool) on both MCP check endpoints,
// `decision` (bool) on the AuthZEN adapter and `decision` (string) on the
// decisions feed. A client generated from one plane could not deserialise
// another.

package agent

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestPreCheckEmitsTheCanonicalVerdictForEveryState drives the writer and reads
// the bytes, for both verdict states.
func TestPreCheckEmitsTheCanonicalVerdictForEveryState(t *testing.T) {
	for _, tc := range []struct {
		name        string
		in          PreCheckResponse
		wantVerdict string
		wantApprove bool
	}{
		{
			name:        "an allowed request",
			in:          PreCheckResponse{ContextID: "c1", Approved: true},
			wantVerdict: VerdictAllow,
			wantApprove: true,
		},
		{
			name:        "a denied request",
			in:          PreCheckResponse{ContextID: "c2", Approved: false, BlockReason: "policy blocked it"},
			wantVerdict: VerdictDeny,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			writePreCheckResponse(rec, http.StatusOK, tc.in)
			var body map[string]any
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatalf("undecodable: %v\nbody: %s", err, rec.Body.String())
			}
			if got, _ := body["verdict"].(string); got != tc.wantVerdict {
				t.Errorf("`verdict` is %q, want %q. This is the member that lets one client read a "+
					"verdict from this plane and from /api/v1/decide with the same code (#3897 §2)."+
					"\nbody: %s", got, tc.wantVerdict, rec.Body.String())
			}
			// `approved` MUST still be there and still mean what it meant.
			// Every shipped SDK reads it; the canonical member is additive.
			got, ok := body["approved"].(bool)
			if !ok {
				t.Fatalf("`approved` is missing or not a bool; it is what every shipped SDK reads and "+
					"the new member is ADDITIVE, not a replacement.\nbody: %s", rec.Body.String())
			}
			if got != tc.wantApprove {
				t.Errorf("`approved` is %v, want %v", got, tc.wantApprove)
			}
		})
	}
}
