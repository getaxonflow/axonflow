// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

//go:build enterprise

package sebi

import "testing"

// TestMapDecisionOutcome_CanonicalAndLegacy pins the SEBI outcome mapping
// (#2636/#2653): it must consume the shared normalizer so every writer spelling
// converges before mapping. The critical regression guard is the canonical
// "allowed"/"blocked" row — every forward writer now emits past-tense, and the
// pre-fix mapper (case "allow"/"deny") let "allowed" fall through to a raw,
// un-mapped value in a regulator-facing export. needs_approval MUST flag
// requires-review, never silently downgrade to "approved".
func TestMapDecisionOutcome_CanonicalAndLegacy(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"allowed", "approved"},
		{"blocked", "blocked"},
		{"redacted", "redacted"},
		{"needs_approval", "pending_review"},
		{"error", "error"},
		{"allow", "approved"},
		{"deny", "blocked"},
		{"require_approval", "pending_review"},
		{"pending_approval", "pending_review"},
		{"denied", "blocked"},
		{"  BLOCKED ", "blocked"},
		{"wat", "error"},
		{"", "error"},
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			if got := mapDecisionOutcome(c.in); got != c.want {
				t.Errorf("mapDecisionOutcome(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

// TestMapDecisionOutcome_NeverLeaksAllowedAsApproval is the focused
// regulator-distortion guard.
func TestMapDecisionOutcome_NeverLeaksAllowedAsApproval(t *testing.T) {
	if got := mapDecisionOutcome("needs_approval"); got == "approved" {
		t.Fatalf("needs_approval mapped to approved — regulator distortion")
	}
	if got := mapDecisionOutcome("allowed"); got == "allowed" {
		t.Fatalf("canonical allowed leaked un-mapped into the export")
	}
}

// TestRequiresReview pins that the requires-review flag consumes the shared
// normalizer in lock-step with mapDecisionOutcome. Red-on-revert guard: a raw
// `== "needs_approval" || == "require_approval"` compare returns false for
// pending_approval (and other legacy needs-approval spellings) while
// mapDecisionOutcome maps them to "pending_review" — exporting a human-deferred
// decision with RequiresReview=false (#2636/#2653).
func TestRequiresReview(t *testing.T) {
	mustReview := []string{"needs_approval", "require_approval", "pending_approval", "awaiting_approval", "  NEEDS_APPROVAL "}
	for _, in := range mustReview {
		if !requiresReview(in) {
			t.Errorf("requiresReview(%q) = false, want true", in)
		}
		if mapDecisionOutcome(in) != "pending_review" {
			t.Errorf("mapDecisionOutcome(%q) = %q, want pending_review (out of lock-step)", in, mapDecisionOutcome(in))
		}
	}
	mustNot := []string{"allowed", "allow", "blocked", "deny", "redacted", "error", "override_lifecycle", "", "bogus"}
	for _, in := range mustNot {
		if requiresReview(in) {
			t.Errorf("requiresReview(%q) = true, want false", in)
		}
	}
}
