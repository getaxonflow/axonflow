// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package identity

import "testing"

// TestParse pins the fail-safe trust-gate parse contract shared by the
// platform governance planes (#2896) and the gateway adapters (#2889): only
// the exact string "true" (post-trim) opts in; ""/"false" are the recognized
// off states; everything else is off AND unrecognized (callers log). Any
// loosening here — accepting "1", "TRUE", "yes" — silently widens the trust
// boundary on every plane at once, which is exactly what this test defends.
func TestParse(t *testing.T) {
	tests := []struct {
		raw            string
		wantTrusted    bool
		wantRecognized bool
	}{
		{"true", true, true},
		{"  true \t", true, true}, // whitespace-trimmed
		{"", false, true},
		{"false", false, true},
		{" false ", false, true},
		// Unrecognized values: off + flagged for the caller's warning log.
		{"TRUE", false, false},
		{"True", false, false},
		{"1", false, false},
		{"yes", false, false},
		{"on", false, false},
		{"truthy", false, false},
		{"true false", false, false},
		{"\"true\"", false, false},
	}
	for _, tc := range tests {
		t.Run("value="+tc.raw, func(t *testing.T) {
			trusted, recognized := Parse(tc.raw)
			if trusted != tc.wantTrusted || recognized != tc.wantRecognized {
				t.Errorf("Parse(%q) = (trusted=%v, recognized=%v), want (%v, %v)",
					tc.raw, trusted, recognized, tc.wantTrusted, tc.wantRecognized)
			}
		})
	}
}

// TestFromEnv proves the env plumbing reads EnvVar and defaults to untrusted
// when unset — the secure default the whole #2896 model rests on.
func TestFromEnv(t *testing.T) {
	t.Run("unset → untrusted", func(t *testing.T) {
		t.Setenv(EnvVar, "")
		trusted, recognized := FromEnv()
		if trusted || !recognized {
			t.Errorf("FromEnv() with unset var = (%v, %v), want (false, true)", trusted, recognized)
		}
	})
	t.Run("true → trusted", func(t *testing.T) {
		t.Setenv(EnvVar, "true")
		trusted, recognized := FromEnv()
		if !trusted || !recognized {
			t.Errorf("FromEnv() with true = (%v, %v), want (true, true)", trusted, recognized)
		}
	})
	t.Run("garbage → untrusted + unrecognized", func(t *testing.T) {
		t.Setenv(EnvVar, "TRUE")
		trusted, recognized := FromEnv()
		if trusted || recognized {
			t.Errorf("FromEnv() with TRUE = (%v, %v), want (false, false)", trusted, recognized)
		}
	})
}
