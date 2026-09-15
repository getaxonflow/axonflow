// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package identity

import (
	"encoding/json"
	"testing"
	"time"
)

// The per-path credential builders and the claim readers they share.

// TestACredentialPathIsMatchedExactlyAndNotByPrefix: a truncated or extended
// path name is not a declared path. A prefix match would admit "hs" and "oidc"
// truncations, and validateCredentialPrincipal's refusal of an undeclared path
// would never fire for the shape of typo it exists for.
func TestACredentialPathIsMatchedExactlyAndNotByPrefix(t *testing.T) {
	for _, p := range credentialPaths {
		if !p.IsValid() {
			t.Fatalf("the declared path %q is not valid", p)
		}
	}
	for _, p := range []CredentialPath{"", "hs", "hs2", "hs256x", "oidc2", "api", "trusted", "HS256"} {
		if p.IsValid() {
			t.Fatalf("CredentialPath(%q).IsValid() = true; only the declared names are paths", p)
		}
	}
}

func TestAudienceClaimShapes(t *testing.T) {
	for _, tc := range []struct {
		name   string
		claims map[string]any
		want   []string
	}{
		{"absent yields the deployment audience", map[string]any{}, []string{AudienceDeployment}},
		{"a single string", map[string]any{"aud": "a"}, []string{"a"}},
		{"a []string", map[string]any{"aud": []string{"a", "b"}}, []string{"a", "b"}},
		{"a []any of strings", map[string]any{"aud": []any{"a", "b"}}, []string{"a", "b"}},
		{"a []any with a non-string member drops it", map[string]any{"aud": []any{"a", 7}}, []string{"a"}},
		{"a shape that is not an audience yields NOTHING, which intersects nothing", map[string]any{"aud": 7}, nil},
	} {
		got := audienceClaim(tc.claims)
		if len(got) != len(tc.want) {
			t.Fatalf("%s: audienceClaim = %v, want %v", tc.name, got, tc.want)
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Fatalf("%s: audienceClaim = %v, want %v", tc.name, got, tc.want)
			}
		}
	}
}

func TestTimeClaimShapes(t *testing.T) {
	ts := int64(1788000000)
	for _, tc := range []struct {
		name  string
		value any
		want  time.Time
	}{
		{"float64", float64(ts), time.Unix(ts, 0).UTC()},
		{"int64", ts, time.Unix(ts, 0).UTC()},
		{"int", int(ts), time.Unix(ts, 0).UTC()},
		{"json.Number", json.Number("1788000000"), time.Unix(ts, 0).UTC()},
		{"a string is not a NumericDate", "1788000000", time.Time{}},
		{"a bool is not a NumericDate", true, time.Time{}},
	} {
		got := timeClaim(map[string]any{"exp": tc.value}, "exp")
		if !got.Equal(tc.want) {
			t.Fatalf("%s: timeClaim = %v, want %v", tc.name, got, tc.want)
		}
	}
	if got := timeClaim(map[string]any{}, "exp"); !got.IsZero() {
		t.Fatalf("an absent claim yielded %v", got)
	}
	// Sub-second precision survives: a truncated exp would expire a credential
	// up to a second early, and a truncated nbf would admit one early.
	frac := timeClaim(map[string]any{"exp": float64(ts) + 0.5}, "exp")
	if frac.Nanosecond() == 0 {
		t.Fatalf("a fractional NumericDate was truncated to whole seconds")
	}
}

func TestClaimPresence(t *testing.T) {
	for _, tc := range []struct {
		name        string
		claims      map[string]any
		wantValue   string
		wantPresent bool
	}{
		{"absent", map[string]any{}, "", false},
		{"present and empty", map[string]any{"org_id": ""}, "", true},
		{"present with a value", map[string]any{"org_id": "o"}, "o", true},
		{"present as a non-string is PRESENT, not absent", map[string]any{"org_id": 7}, "", true},
	} {
		v, present := claimPresence(tc.claims, "org_id")
		if v != tc.wantValue || present != tc.wantPresent {
			t.Fatalf("%s: claimPresence = (%q, %v), want (%q, %v)", tc.name, v, present, tc.wantValue, tc.wantPresent)
		}
	}
}
