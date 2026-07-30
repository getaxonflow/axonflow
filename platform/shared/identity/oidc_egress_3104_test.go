// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
//
// #3104 — CheckOIDCEndpointSSRF's IP-literal branch now consumes the shared
// egress table via egress.OIDCLiteral. Its hostname denylist (.internal,
// .local, the metadata hostnames) and its no-DNS contract are unchanged;
// TestCheckOIDCEndpointSSRF above still pins those.
//
// This classifier was not in #3104's inventory either.

package identity

import (
	"testing"

	"axonflow/platform/shared/egress"
)

// TestOIDCLoopbackExemptionSurvives is the load-bearing one. The loopback
// allowance is deliberate — local-dev issuers — and was previously only a
// prose comment. Moving to a table must not have dropped it.
func TestOIDCLoopbackExemptionSurvives(t *testing.T) {
	for _, u := range []string{
		"http://127.0.0.1:8080/certs",
		"http://127.1.2.3:8080/certs",
		"http://[::1]:8080/certs",
		"http://[::ffff:127.0.0.1]:8080/certs",
	} {
		if err := CheckOIDCEndpointSSRF(u); err != nil {
			t.Errorf("CheckOIDCEndpointSSRF(%q) = %v; loopback is a declared exemption (egress.OIDCLiteral)", u, err)
		}
	}
	if !egress.OIDCLiteral.Exempts(egress.RangeLoopback) {
		t.Error("egress.OIDCLiteral no longer exempts loopback; local-dev OIDC issuers would break")
	}
}

// TestOIDCNewlyBlockedRanges names what the old switch permitted. An OIDC
// issuer or JWKS URI on any of these is refused at the configuration-write
// path now.
func TestOIDCNewlyBlockedRanges(t *testing.T) {
	for _, c := range []struct{ url, why string }{
		{"https://0.1.2.3/keys", "this-network 0.0.0.0/8 — IsUnspecified covered only 0.0.0.0"},
		{"https://100.64.0.1/keys", "CGNAT 100.64.0.0/10 (also Tailscale)"},
		{"https://192.0.0.1/keys", "IETF protocol assignments"},
		{"https://192.0.2.1/keys", "TEST-NET-1"},
		{"https://198.51.100.1/keys", "TEST-NET-2"},
		{"https://203.0.113.1/keys", "TEST-NET-3"},
		{"https://198.18.67.10/keys", "RFC 2544 benchmarking"},
		{"https://240.0.0.1/keys", "reserved 240.0.0.0/4"},
		{"https://255.255.255.255/keys", "limited broadcast"},
		{"https://[2001:db8::1]/keys", "IPv6 documentation"},
		{"https://[64:ff9b::a9fe:a9fe]/keys", "NAT64 wrapping the cloud metadata IP"},
		{"https://[2002:a9fe:a9fe::]/keys", "6to4 wrapping the cloud metadata IP"},
		{"https://[::a9fe:a9fe]/keys", "IPv4-compatible wrapping the cloud metadata IP"},
		{"https://[::ffff:169.254.169.254]/keys", "IPv4-mapped cloud metadata IP"},
	} {
		if err := CheckOIDCEndpointSSRF(c.url); err == nil {
			t.Errorf("CheckOIDCEndpointSSRF(%q) = nil; must be rejected (%s)", c.url, c.why)
		}
	}
}

// TestOIDCPreExistingBlocksDoNotRegress restates the old switch's coverage.
func TestOIDCPreExistingBlocksDoNotRegress(t *testing.T) {
	for _, u := range []string{
		"http://169.254.169.254/latest/meta-data/",
		"https://10.0.0.5/keys", "https://172.16.4.4/keys", "https://192.168.1.1/keys",
		"http://[fd00::1]/keys", "https://[fe80::1]/keys",
		"https://0.0.0.0/keys",
		"https://[ff02::1]/keys", "https://[ff0e::1]/keys", // multicast, both scopes
		"https://224.0.0.1/keys",
	} {
		if err := CheckOIDCEndpointSSRF(u); err == nil {
			t.Errorf("CheckOIDCEndpointSSRF(%q) = nil; this was rejected before #3104", u)
		}
	}
}

// TestOIDCPublicIssuersStayConfigurable is the vacuity control.
func TestOIDCPublicIssuersStayConfigurable(t *testing.T) {
	for _, u := range []string{
		"https://oauth.id.jumpcloud.com/.well-known/jwks.json",
		"https://login.microsoftonline.com/common/discovery/keys",
		"https://8.8.8.8/keys",
		"https://198.17.255.255/keys",
		"https://100.128.0.0/keys",
		"https://[2001:db9::1]/keys",
		"https://issuer.example.com",
	} {
		if err := CheckOIDCEndpointSSRF(u); err != nil {
			t.Errorf("CheckOIDCEndpointSSRF(%q) = %v; a public issuer must stay configurable", u, err)
		}
	}
}

// TestOIDCHostnameDenylistUnchanged pins the part that is NOT the table: this
// guard resolves no DNS, so a hostname is judged by suffix only.
func TestOIDCHostnameDenylistUnchanged(t *testing.T) {
	for _, u := range []string{
		"https://metadata.google.internal/keys",
		"https://metadata/keys",
		"https://vault.internal/keys",
		"https://keys.cluster.local/jwks",
	} {
		if err := CheckOIDCEndpointSSRF(u); err == nil {
			t.Errorf("CheckOIDCEndpointSSRF(%q) = nil; the hostname denylist must be unchanged", u)
		}
	}
	for _, u := range []string{
		"http://localhost:8080/certs",
		"http://app.localhost/jwks",
		"http://App.LocalHost/jwks",
	} {
		if err := CheckOIDCEndpointSSRF(u); err != nil {
			t.Errorf("CheckOIDCEndpointSSRF(%q) = %v; the .localhost loopback zone must stay allowed", u, err)
		}
	}
}
