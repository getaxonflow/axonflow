// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package identity

import (
	"context"
	"testing"
)

type fakeValidator struct{ name string }

func (f *fakeValidator) Name() string { return f.name }
func (f *fakeValidator) Validate(_ context.Context, _, _ string) (*ValidatedIdentity, error) {
	return &ValidatedIdentity{Email: "x@example.com", Validated: true, Source: f.name}, nil
}

func TestCanonicalEmail(t *testing.T) {
	cases := map[string]string{
		"Dev@GetAxonflow.com  ": "dev@getaxonflow.com",
		"  a@b.co":              "a@b.co",
		"":                      "",
		"  ":                    "",
		"UPPER@CASE.IO":         "upper@case.io",
	}
	for in, want := range cases {
		if got := CanonicalEmail(in); got != want {
			t.Errorf("CanonicalEmail(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCheckOIDCEndpointSSRF(t *testing.T) {
	safe := []string{
		"https://oauth.id.jumpcloud.com/.well-known/jwks.json",
		"https://login.microsoftonline.com/common/discovery/keys",
		"http://127.0.0.1:8080/certs", // loopback allowed (local dev)
		"http://localhost:8080/certs", // bare localhost = loopback, allowed
		"http://app.localhost/jwks",   // *.localhost is a loopback zone (RFC 6761)
		"http://App.LocalHost/jwks",   // case-insensitive, same loopback zone
		"https://issuer.example.com",
		"https://8.8.8.8/keys", // public IP literal is fine
	}
	for _, u := range safe {
		if err := CheckOIDCEndpointSSRF(u); err != nil {
			t.Errorf("CheckOIDCEndpointSSRF(%q) = %v, want nil", u, err)
		}
	}

	blocked := []string{
		"http://169.254.169.254/latest/meta-data/",    // AWS/GCP metadata IP
		"https://169.254.169.254/computeMetadata/v1/", // metadata over https
		"http://[fd00::1]/keys",                       // IPv6 ULA
		"https://10.0.0.5/keys",                       // RFC-1918
		"https://172.16.4.4/keys",                     // RFC-1918
		"https://192.168.1.1/keys",                    // RFC-1918
		"https://metadata.google.internal/keys",       // metadata hostname
		"https://vault.internal/keys",                 // .internal
		"https://keys.cluster.local/jwks",             // .local
		"https://0.0.0.0/keys",                        // unspecified
		"https://[fe80::1]/keys",                      // IPv6 link-local
	}
	for _, u := range blocked {
		if err := CheckOIDCEndpointSSRF(u); err == nil {
			t.Errorf("CheckOIDCEndpointSSRF(%q) = nil, want SSRF rejection", u)
		}
	}
}

func TestRegistry_OrderDuplicatesAndLookup(t *testing.T) {
	ResetRegistryForTest()
	t.Cleanup(ResetRegistryForTest)

	a := &fakeValidator{name: "a"}
	b := &fakeValidator{name: "b"}
	if err := RegisterValidator(a); err != nil {
		t.Fatalf("register a: %v", err)
	}
	if err := RegisterValidator(b); err != nil {
		t.Fatalf("register b: %v", err)
	}

	// Duplicate name must be rejected, never silently replaced.
	if err := RegisterValidator(&fakeValidator{name: "a"}); err == nil {
		t.Fatal("duplicate registration must error")
	}
	// Nil must be rejected.
	if err := RegisterValidator(nil); err == nil {
		t.Fatal("nil registration must error")
	}

	got := RegisteredValidators()
	if len(got) != 2 || got[0].Name() != "a" || got[1].Name() != "b" {
		t.Fatalf("registration order not preserved: %#v", got)
	}
	// The returned slice is a copy — mutating it must not corrupt the registry.
	got[0] = nil
	if again := RegisteredValidators(); again[0] == nil || again[0].Name() != "a" {
		t.Fatal("RegisteredValidators must return a copy")
	}

	if LookupValidator("b") != b {
		t.Fatal("LookupValidator(b) mismatch")
	}
	if LookupValidator("nope") != nil {
		t.Fatal("LookupValidator(unknown) must be nil")
	}
}

// #2963: IsFleetRole / FleetRoleNames expose the resolver's closed vocabulary
// so a configuration surface can reject an unrecognized role name up front.
func TestIsFleetRole(t *testing.T) {
	for _, r := range []string{"admin", "owner", "policy_admin", "developer", "viewer"} {
		if !IsFleetRole(r) {
			t.Errorf("IsFleetRole(%q) = false, want true", r)
		}
	}
	// "member" was dropped from the role model in #2993; it is now unknown.
	for _, r := range []string{"", "member", "Admin", "ADMIN", "billing_ops", "superuser", "root", "*"} {
		if IsFleetRole(r) {
			t.Errorf("IsFleetRole(%q) = true, want false", r)
		}
	}
}

// The exposed vocabulary MUST be self-consistent with NormalizeRole — one
// source of truth. (The cross-check against the resolver's rolePrecedence lives
// in the enterprise-tagged scim_role_resolver_vocab_test.go, since
// rolePrecedence is defined only in the enterprise build.)
func TestFleetRoleNames_MatchesNormalize(t *testing.T) {
	names := FleetRoleNames()
	if len(names) != 5 {
		t.Fatalf("FleetRoleNames() has %d entries, want 5 (#2993 dropped member): %v", len(names), names)
	}
	for _, n := range names {
		if NormalizeRole(n) != n {
			t.Errorf("FleetRoleNames contains %q but NormalizeRole rejects it", n)
		}
		if !IsFleetRole(n) {
			t.Errorf("FleetRoleNames contains %q but IsFleetRole is false", n)
		}
	}
}
