// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package audit

import (
	"reflect"
	"testing"
)

// TestSpellings_Canonical verifies the read-side expansion: each canonical
// verdict expands to every DB spelling that Normalize maps back to it, sorted,
// and always including the canonical value itself. This is the IN/ANY allowlist
// a reader builds to match both canonical rows and legacy/historical rows.
func TestSpellings_Canonical(t *testing.T) {
	cases := []struct {
		canonical string
		want      []string
	}{
		{DecisionAllowed, []string{"allow", "allowed"}},
		{DecisionBlocked, []string{"block", "blocked", "denied", "deny"}},
		{DecisionRedacted, []string{"masked", "modified", "redact", "redacted"}},
		{DecisionNeedsApproval, []string{
			"awaiting_approval", "need_approval", "needs-approval", "needs_approval",
			"pending-approval", "pending_approval", "require_approval",
			"requires-approval", "requires_approval",
		}},
		{DecisionError, []string{"error", "errored", "failed"}},
	}
	for _, c := range cases {
		t.Run(c.canonical, func(t *testing.T) {
			got := Spellings(c.canonical)
			if !reflect.DeepEqual(got, c.want) {
				t.Fatalf("Spellings(%q) = %v, want %v", c.canonical, got, c.want)
			}
			// Invariant: the expansion always contains the canonical value, and
			// every member normalizes back to the canonical value.
			found := false
			for _, s := range got {
				if s == c.canonical {
					found = true
				}
				if Normalize(s) != c.canonical {
					t.Errorf("Spellings(%q) member %q normalizes to %q, not %q",
						c.canonical, s, Normalize(s), c.canonical)
				}
			}
			if !found {
				t.Errorf("Spellings(%q) does not contain the canonical value itself", c.canonical)
			}
		})
	}
}

// TestSpellings_OverrideLifecycle: the recognized non-verdict marker expands to
// just itself (so a reader can match override rows explicitly if it ever needs
// to), and it is NOT mixed into any verdict bucket.
func TestSpellings_OverrideLifecycle(t *testing.T) {
	got := Spellings(DecisionOverrideLifecycle)
	if !reflect.DeepEqual(got, []string{DecisionOverrideLifecycle}) {
		t.Fatalf("Spellings(override_lifecycle) = %v, want [%q]", got, DecisionOverrideLifecycle)
	}
	for _, c := range All() {
		for _, s := range Spellings(c) {
			if s == DecisionOverrideLifecycle {
				t.Errorf("override_lifecycle leaked into Spellings(%q)", c)
			}
		}
	}
}

// TestSpellings_NonCanonicalReturnsNil: an alias spelling, a phantom, or an
// unknown returns nil — Spellings must be fed the canonical value (callers
// Normalize first), and a nil expansion is the safe "match nothing" default for
// a `= ANY('{}')` predicate rather than a silently-widened filter.
func TestSpellings_NonCanonicalReturnsNil(t *testing.T) {
	for _, in := range []string{"allow", "deny", "require_approval", "logged", "alerted", "modified", "wat", ""} {
		if got := Spellings(in); got != nil {
			t.Errorf("Spellings(%q) = %v, want nil (only canonical/override accepted)", in, got)
		}
	}
}
