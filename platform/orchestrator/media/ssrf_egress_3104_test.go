// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
//
// #3104 — fetchURLData is two layers: a pre-flight (validateURLForSSRF ->
// base.ValidateURL) and a socket-level Dialer.Control check. The socket layer
// exists to catch what the pre-flight cannot — a hostname that resolves public
// at validation time and into a reserved range at dial time, or a redirect —
// and it used to be STRICTLY WEAKER than the pre-flight, so that path was open.
//
// Both layers now apply egress.ConnectorEgress.

package media

import (
	"net"
	"testing"

	"axonflow/platform/shared/egress"
)

func parseIP3104(t *testing.T, s string) net.IP {
	t.Helper()
	ip := net.ParseIP(s)
	if ip == nil {
		t.Fatalf("unparseable test address %q", s)
	}
	return ip
}

// probes covers every named range plus the boundary and wrapper cases.
var probes3104 = []string{
	"127.0.0.1", "::1", "0.0.0.0", "::", "0.1.2.3",
	"10.0.0.1", "172.16.0.1", "192.168.1.1", "fc00::1", "fd00::1",
	"169.254.169.254", "fe80::1", "224.0.0.1", "ff02::1",
	"100.64.0.1", "100.127.255.255", "192.0.0.1", "192.0.2.1",
	"198.51.100.1", "203.0.113.1", "198.18.67.10", "239.255.255.255",
	"ff0e::1", "240.0.0.1", "255.255.255.255", "2001:db8::1",
	"64:ff9b::7f00:1", "2002:7f00:1::", "::7f00:1", "::ffff:0:7f00:1",
	"::ffff:127.0.0.1", "::ffff:100.64.0.1",
	"ff12::1", "ff32::1",
	// public controls
	"8.8.8.8", "1.1.1.1", "198.17.255.255", "198.20.0.0", "100.128.0.0",
	"2001:db9::1", "64:ff9b::808:808", "2606:4700:4700::1111",
}

// TestSocketGuardAgreesWithThePreflight is the invariant the old code violated:
// the pre-flight refused 100.64.0.1 while the socket check accepted it.
func TestSocketGuardAgreesWithThePreflight(t *testing.T) {
	for _, addr := range probes3104 {
		ip := parseIP3104(t, addr)
		preflight := mediaEgressPolicy.Blocks(ip) // what validateURLForSSRF applies
		socket := isPrivateIP(ip)
		if preflight != socket {
			t.Errorf("%s: pre-flight blocks=%v but socket guard blocks=%v — the layer that catches DNS "+
				"rebinding and redirects must not be weaker than the one it backstops", addr, preflight, socket)
		}
	}
}

func TestNewlyBlockedOnTheSocketGuard(t *testing.T) {
	for _, c := range []struct{ addr, why string }{
		{"0.1.2.3", "this-network 0.0.0.0/8"},
		{"100.64.0.1", "CGNAT — the pre-flight already refused it"},
		{"192.0.0.1", "IETF protocol assignments"},
		{"192.0.2.1", "TEST-NET-1"},
		{"198.51.100.1", "TEST-NET-2"},
		{"203.0.113.1", "TEST-NET-3"},
		{"239.255.255.255", "multicast beyond the link-local /24"},
		{"240.0.0.1", "reserved"},
		{"255.255.255.255", "limited broadcast"},
		{"2001:db8::1", "IPv6 documentation"},
		{"64:ff9b::7f00:1", "NAT64 wrapping 127.0.0.1"},
		{"2002:7f00:1::", "6to4 wrapping 127.0.0.1"},
		{"198.18.67.10", "RFC 2544 benchmarking — the connector exemption must NOT reach a caller-supplied URL"},
	} {
		if !isPrivateIP(parseIP3104(t, c.addr)) {
			t.Errorf("isPrivateIP(%s) = false; must be blocked (%s)", c.addr, c.why)
		}
	}
}

// TestSurfaceUsesCallbackEgress pins WHICH policy this surface consumes.
//
// It is deliberately NOT ConnectorEgress (#3104 R3 round 2, finding 4). The
// only reason ConnectorEgress exempts 198.18.0.0/15 is a connector test
// harness (runtime-e2e/3067); a media URL is caller-supplied per request in
// the governance API body, so routing it through ConnectorEgress would be the
// one place that test-harness exemption met untrusted input.
func TestSurfaceUsesCallbackEgress(t *testing.T) {
	sentinel := parseIP3104(t, "198.18.67.10")
	if !isPrivateIP(sentinel) {
		t.Error("media permits 198.18.0.0/15; a caller-supplied URL must not inherit the connector test-harness exemption")
	}
	if err := validateURLForSSRF("http://198.18.67.10:8080/x.jpg"); err == nil {
		t.Error("the media PRE-FLIGHT permits 198.18.0.0/15; both layers must state the same posture")
	}
	// The connector layer keeps the exemption — runtime-e2e/3067 depends on it.
	if egress.ConnectorEgress.Blocks(sentinel) {
		t.Error("ConnectorEgress now blocks the benchmarking range; runtime-e2e/3067 depends on it being permitted")
	}
}

func TestFailsClosedOnMalformed(t *testing.T) {
	if !isPrivateIP(nil) {
		t.Error("isPrivateIP(nil) = false; must fail closed")
	}
}
