// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
//
// #3104 — this surface carried an eight-CIDR classifier that TestSSRF_Blocks
// PrivateIPs pinned with seven addresses, none of which covered a range the
// list omitted. That is how it kept permitting 0.0.0.0/8 (dial-routed to
// loopback) years after platform/agent/hitl closed the same bypass.

//go:build enterprise

package circuitbreaker

import (
	"context"
	"net"
	"strings"
	"testing"

	"axonflow/platform/shared/egress"
)

func mustParseIP(t *testing.T, s string) net.IP {
	t.Helper()
	ip := net.ParseIP(s)
	if ip == nil {
		t.Fatalf("unparseable test address %q", s)
	}
	return ip
}

// TestNewlyBlockedRanges covers every range the eight-CIDR list permitted.
func TestNewlyBlockedRanges(t *testing.T) {
	cases := []struct{ addr, why string }{
		{"0.0.0.0", "unspecified — dial-routed to loopback on Linux and macOS (hitl's R3 R2 HIGH-2, never propagated here)"},
		{"0.1.2.3", "this-network 0.0.0.0/8"},
		{"::", "IPv6 unspecified"},
		{"100.64.0.1", "CGNAT 100.64.0.0/10 (also Tailscale)"},
		{"100.127.255.255", "CGNAT last address"},
		{"192.0.0.1", "IETF protocol assignments"},
		{"192.0.2.1", "TEST-NET-1"},
		{"198.51.100.1", "TEST-NET-2"},
		{"203.0.113.1", "TEST-NET-3"},
		{"198.18.67.10", "RFC 2544 benchmarking — a callback surface must refuse it"},
		{"224.0.0.1", "link-local multicast"},
		{"239.255.255.255", "multicast"},
		{"240.0.0.1", "reserved"},
		{"255.255.255.255", "limited broadcast"},
		{"ff02::1", "IPv6 link-local multicast"},
		{"2001:db8::1", "IPv6 documentation"},
		{"64:ff9b::7f00:1", "NAT64 wrapping 127.0.0.1"},
		{"2002:7f00:1::", "6to4 wrapping 127.0.0.1"},
		{"::7f00:1", "IPv4-compatible wrapping 127.0.0.1"},
		{"::ffff:100.64.0.1", "IPv4-mapped CGNAT"},
	}
	for _, c := range cases {
		t.Run(c.addr, func(t *testing.T) {
			if !isPrivateIP(mustParseIP(t, c.addr)) {
				t.Errorf("isPrivateIP(%s) = false; must be blocked (%s)", c.addr, c.why)
			}
		})
	}
}

// TestPreExistingBlocksDoNotRegress re-states the eight-CIDR list's own
// coverage. Moving to a shared policy must not narrow anything.
func TestPreExistingBlocksDoNotRegress(t *testing.T) {
	for _, addr := range []string{
		"127.0.0.1", "127.255.255.255",
		"10.0.0.1", "172.16.0.1", "172.31.255.255", "192.168.1.1",
		"169.254.169.254",
		"::1", "fc00::1", "fd00::1", "fe80::1",
	} {
		if !isPrivateIP(mustParseIP(t, addr)) {
			t.Errorf("isPrivateIP(%s) = false; this was blocked before #3104", addr)
		}
	}
}

// TestPublicStaysReachable is the vacuity control.
func TestPublicStaysReachable(t *testing.T) {
	for _, addr := range []string{
		"8.8.8.8", "1.1.1.1",
		"172.32.0.1",           // immediately above 172.16.0.0/12
		"100.128.0.0",          // immediately above CGNAT
		"198.17.255.255",       // immediately below the benchmarking range
		"198.20.0.0",           // immediately above it
		"223.255.255.255",      // immediately below multicast
		"2001:db9::1",          // immediately above the IPv6 doc range
		"64:ff9b::808:808",     // NAT64 wrapping a public address
		"2606:4700:4700::1111", // Cloudflare
	} {
		if isPrivateIP(mustParseIP(t, addr)) {
			t.Errorf("isPrivateIP(%s) = true; a public address must stay reachable", addr)
		}
	}
}

// TestFailsClosedOnMalformed pins the nil contract.
func TestFailsClosedOnMalformed(t *testing.T) {
	if !isPrivateIP(nil) {
		t.Error("isPrivateIP(nil) = false; must fail closed")
	}
}

// TestSurfaceUsesCallbackEgress pins WHICH policy this surface consumes.
// Swapping it to ConnectorEgress would re-permit the benchmarking range on an
// operator-supplied notification URL.
func TestSurfaceUsesCallbackEgress(t *testing.T) {
	probe := mustParseIP(t, "198.18.67.10")
	if !isPrivateIP(probe) {
		t.Error("this surface permits 198.18.0.0/15; a callback surface must use egress.CallbackEgress")
	}
	if egress.ConnectorEgress.Blocks(probe) {
		t.Error("ConnectorEgress now blocks the benchmarking range; runtime-e2e/3067 depends on it being permitted")
	}
}

// TestDialerRefusesAndNamesTheHatch drives the real transport dialer rather
// than the predicate, so it fails if the surface stops consulting the policy.
func TestDialerRefusesAndNamesTheHatch(t *testing.T) {
	dial := newSSRFSafeDialer(false)
	_, err := dial(context.Background(), "tcp", "100.64.0.1:443")
	if err == nil {
		t.Fatal("dialer accepted a CGNAT address")
	}
	for _, want := range []string{"100.64.0.1", string(egress.RangeCGNAT), NotifyAllowPrivateEnv} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("dialer error %q does not mention %q", err, want)
		}
	}
}

// TestEscapeHatch pins both directions of NotifyAllowPrivateEnv.
func TestEscapeHatch(t *testing.T) {
	for _, v := range []string{"1", "yes", "false", ""} {
		t.Setenv(NotifyAllowPrivateEnv, v)
		if allowPrivateRanges() {
			t.Errorf("%s=%q engaged the hatch; only exact \"true\" may", NotifyAllowPrivateEnv, v)
		}
	}
	t.Setenv(NotifyAllowPrivateEnv, "true")
	if !allowPrivateRanges() {
		t.Fatalf("%s=true did not engage the hatch", NotifyAllowPrivateEnv)
	}

	// With the hatch on, NewSafeDialContext is not installed at all — the
	// transport gets the bare dialer. Asserted structurally rather than by
	// dialing: an earlier revision opened a real socket into CGNAT/Tailscale
	// space from a unit test and then passed for ANY error that did not happen
	// to contain "SSRF protection", which is vacuous (#3104 R3 F10).
	if !egress.CallbackEgress.Blocks(mustParseIP(t, "100.64.0.1")) {
		t.Fatal("CallbackEgress no longer blocks CGNAT; the hatch would be a no-op")
	}
	guarded := newSSRFSafeDialer(false)
	if _, err := guarded(cancelledCtx(), "tcp", "100.64.0.1:1"); err == nil ||
		!strings.Contains(err.Error(), "SSRF protection") {
		t.Errorf("guarded dialer must refuse CGNAT before any dial, got %v", err)
	}
}

// cancelledCtx guarantees no socket is opened even if a future edit removes
// the guard: the dial cannot proceed on an already-cancelled context.
func cancelledCtx() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}
