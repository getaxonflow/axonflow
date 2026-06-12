// Copyright 2026 AxonFlow
// SPDX-License-Identifier: Apache-2.0

//go:build enterprise

package euaiact

import "testing"

// TestMapDecisionVerdict_CanonicalAndLegacy pins the EU AI Act outcome mapping
// (#2636/#2653): it must consume the shared normalizer so every writer spelling
// converges. The critical regression guard is the canonical "allowed"/"blocked"
// row — every forward writer now emits past-tense, and the pre-fix mapper
// (case "allow"/"deny") let "allowed" fall through to a raw, un-mapped value in
// a regulator-facing export. needs_approval (and its legacy require_approval
// spelling) MUST flag requires-review, never silently downgrade to "approved".
func TestMapDecisionVerdict_CanonicalAndLegacy(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		// Canonical (what every forward writer emits today).
		{"allowed", "approved"},
		{"blocked", "blocked"},
		{"redacted", "redacted"},
		{"needs_approval", "pending_review"},
		{"error", "error"},
		// Wire-only / historical present-tense verdicts.
		{"allow", "approved"},
		{"deny", "blocked"},
		// Legacy reader/exporter + workflow spellings.
		{"require_approval", "pending_review"},
		{"pending_approval", "pending_review"},
		{"denied", "blocked"},
		// Case / whitespace insensitivity (via Normalize).
		{"  ALLOWED ", "approved"},
		// Unknown values fail safe to "error" — NEVER "approved".
		{"wat", "error"},
		{"", "error"},
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			if got := mapDecisionVerdict(c.in); got != c.want {
				t.Errorf("mapDecisionVerdict(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

// TestMapDecisionVerdict_NeverLeaksAllowedAsApproval is the focused
// regulator-distortion guard: needs_approval must never be mapped to "approved"
// (which would tell a regulator a human-deferred decision was auto-approved),
// and a clean "allowed" must never leak its raw spelling.
func TestMapDecisionVerdict_NeverLeaksAllowedAsApproval(t *testing.T) {
	if got := mapDecisionVerdict("needs_approval"); got == "approved" {
		t.Fatalf("needs_approval mapped to approved — regulator distortion")
	}
	if got := mapDecisionVerdict("allowed"); got == "allowed" {
		t.Fatalf("canonical allowed leaked un-mapped into the export")
	}
}

// TestRequiresReview pins that the requires-review flag consumes the shared
// normalizer in lock-step with mapDecisionVerdict. Red-on-revert guard: a raw
// `== "needs_approval" || == "require_approval"` compare returns false for
// pending_approval (and other legacy needs-approval spellings) while
// mapDecisionVerdict maps them to "pending_review" — exporting a human-deferred
// decision with RequiresReview=false (#2636/#2653).
func TestRequiresReview(t *testing.T) {
	mustReview := []string{"needs_approval", "require_approval", "pending_approval", "awaiting_approval", "  NEEDS_APPROVAL "}
	for _, in := range mustReview {
		if !requiresReview(in) {
			t.Errorf("requiresReview(%q) = false, want true", in)
		}
		if mapDecisionVerdict(in) != "pending_review" {
			t.Errorf("mapDecisionVerdict(%q) = %q, want pending_review (out of lock-step)", in, mapDecisionVerdict(in))
		}
	}
	mustNot := []string{"allowed", "allow", "blocked", "deny", "redacted", "error", "override_lifecycle", "", "bogus"}
	for _, in := range mustNot {
		if requiresReview(in) {
			t.Errorf("requiresReview(%q) = true, want false", in)
		}
	}
}
