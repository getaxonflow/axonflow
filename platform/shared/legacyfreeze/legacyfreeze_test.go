// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package legacyfreeze

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/lib/pq"
)

// freezeError is what Postgres raises once core/172 has revoked the write.
func freezeError() error {
	return fmt.Errorf("failed to insert policy: %w", &pq.Error{
		Code:    "42501",
		Message: `permission denied for table dynamic_policies`,
	})
}

// rlsError is the OTHER 42501: a WITH CHECK violation, which is a defect in our
// own org scoping and must NOT be reported as the freeze.
func rlsError() error {
	return fmt.Errorf("failed to insert policy: %w", &pq.Error{
		Code:    "42501",
		Message: `new row violates row-level security policy for table "dynamic_policies"`,
	})
}

// TestTheFreezeClassifierMatchesTheCausePositively pins the direction of the
// match, which is the part that decides how an unknown 42501 is reported.
//
// It moved here from package orchestrator with the classifier (#4084): the
// agent could not import the package it lived in, and a copy is how a surface
// keeps answering 500.
func TestTheFreezeClassifierMatchesTheCausePositively(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{
		{"the revoke", freezeError(), true},
		{"the older relation wording", fmt.Errorf("x: %w", &pq.Error{Code: "42501", Message: "permission denied for relation dynamic_policies"}), true},
		{"an RLS WITH CHECK violation", rlsError(), false},
		// A 42501 shape we have not met must fall through to the existing 500
		// rather than be reported to a caller as a retirement notice. This is
		// the fail-CLOSED direction and it is why the match is positive rather
		// than "42501 and not RLS".
		{"an unrecognised 42501", fmt.Errorf("x: %w", &pq.Error{Code: "42501", Message: "permission denied for sequence policy_seq"}), false},
		// THE NEXT FREEZE MUST NOT INHERIT THIS ANSWER. The routes that write
		// the two frozen tables write others too, and "permission denied for
		// table X" is the same sentence whichever X is. One version table per
		// binary, because each is the realistic neighbour on its own path.
		{"a privilege refusal on the orchestrator's version table",
			fmt.Errorf("x: %w", &pq.Error{Code: "42501", Message: `permission denied for table policy_versions`}), false},
		{"a privilege refusal on the agent's version table",
			fmt.Errorf("x: %w", &pq.Error{Code: "42501", Message: `permission denied for table static_policy_versions`}), false},
		// The frozen name must sit in the SUBJECT position. A message that
		// merely mentions the table - in a constraint name, a detail line, a
		// statement echo - is not a refusal to write it.
		{"a frozen table named somewhere other than the subject",
			fmt.Errorf("x: %w", &pq.Error{Code: "42501", Message: `permission denied for table policy_versions (while inserting into dynamic_policies)`}), false},
		{"the other frozen table is covered",
			fmt.Errorf("x: %w", &pq.Error{Code: "42501", Message: `permission denied for table static_policies`}), true},
		// A PREFIX TEST IS NOT SUBJECT POSITION (#4048 R3 round 2, F4).
		// `dynamic_policies_archive` begins with `dynamic_policies`, so a
		// Contains test classified a refusal on a DIFFERENT table as this
		// freeze. No such table exists today; this guards the next migration.
		{"a longer table sharing a frozen table's PREFIX is not this freeze",
			fmt.Errorf("x: %w", &pq.Error{Code: "42501", Message: `permission denied for table dynamic_policies_archive`}), false},
		{"the same, on the other frozen name and the older relation wording",
			fmt.Errorf("x: %w", &pq.Error{Code: "42501", Message: `permission denied for relation static_policies_v2`}), false},
		// The boundary must not cost the real match: a trailing clause after the
		// table name is still this freeze, because the name ended at a space.
		{"the frozen table named as subject with text following it",
			fmt.Errorf("x: %w", &pq.Error{Code: "42501", Message: `permission denied for table dynamic_policies (statement: INSERT)`}), true},
		// And a prefixed sibling must not MASK a real refusal that appears later
		// in the same message - the scan continues past a prefix hit rather than
		// returning on the first one.
		{"a prefixed sibling does not mask a genuine refusal later in the message",
			fmt.Errorf("x: %w", &pq.Error{Code: "42501", Message: `permission denied for table dynamic_policies_archive; permission denied for table dynamic_policies`}), true},
		{"a different SQLSTATE", fmt.Errorf("x: %w", &pq.Error{Code: "23505", Message: "duplicate key value"}), false},
		// The SQLSTATE is checked, not only the wording: the same sentence
		// under another code is not the privilege refusal.
		{"the freeze wording under a different SQLSTATE",
			fmt.Errorf("x: %w", &pq.Error{Code: "42P01", Message: `permission denied for table dynamic_policies`}), false},
		{"the freeze wording in a plain error, with no pq.Error to read", fmt.Errorf("permission denied for table dynamic_policies"), false},
		{"not a pq error at all", fmt.Errorf("plain failure"), false},
		{"no error", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsFrozen(tc.err); got != tc.want {
				t.Fatalf("IsFrozen = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestAnswerFixesTheStatusTheCodeAndTheRemedy is the half every surface
// shares: whatever envelope a caller passes, the status, the code and the
// message are decided here and nowhere else.
func TestAnswerFixesTheStatusTheCodeAndTheRemedy(t *testing.T) {
	type recorded struct {
		status        int
		code, message string
		calls         int
	}
	writerInto := func(rec *recorded) ErrorWriter {
		return func(w http.ResponseWriter, status int, code, message string) {
			rec.calls++
			rec.status, rec.code, rec.message = status, code, message
			w.WriteHeader(status)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]string{"code": code, "message": message}})
		}
	}

	t.Run("the freeze is answered 409 with the code and a message naming the typed route", func(t *testing.T) {
		var rec recorded
		rr := httptest.NewRecorder()
		if !Answer(rr, freezeError(), "Test", "Create", "tenant-a", writerInto(&rec)) {
			t.Fatal("Answer reported it did not answer the freeze")
		}
		if rec.calls != 1 || rec.status != http.StatusConflict || rr.Code != http.StatusConflict {
			t.Fatalf("writer called %d time(s) with status %d (recorder %d), want once with 409", rec.calls, rec.status, rr.Code)
		}
		if rec.code != ErrCode {
			t.Fatalf("code = %q, want %q", rec.code, ErrCode)
		}
		// THE REMEDY MUST BE NAMED. A refusal an operator cannot act on is
		// only marginally better than the 500 it replaced.
		if !strings.Contains(rec.message, TypedAuthoringRoute) {
			t.Fatalf("the refusal does not name the typed authoring route: %q", rec.message)
		}
	})

	// ANTI-VACUITY: an error that is not the freeze must leave the response
	// untouched, or every caller's own 500 below it would be shadowed.
	for name, err := range map[string]error{
		"an RLS violation":                rlsError(),
		"a refusal on a table not frozen": fmt.Errorf("x: %w", &pq.Error{Code: "42501", Message: "permission denied for table policy_versions"}),
		"an ordinary failure":             fmt.Errorf("connection reset"),
		"no error":                        nil,
	} {
		t.Run(name+" is not answered and nothing is written", func(t *testing.T) {
			var rec recorded
			rr := httptest.NewRecorder()
			if Answer(rr, err, "Test", "Create", "tenant-a", writerInto(&rec)) {
				t.Fatal("Answer claimed an error that is not the freeze")
			}
			if rec.calls != 0 || rr.Body.Len() != 0 {
				t.Fatalf("Answer wrote a response (%d call(s), body %q) for an error it did not claim", rec.calls, rr.Body.String())
			}
		})
	}
}
