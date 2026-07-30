// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package egress

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"syscall"
	"testing"
)

// representatives binds every Range to an address inside it. TestEveryRangeHasA
// Representative fails if a range is added to the table without one, so the
// matrix below can never silently skip a range.
var representatives = map[Range]string{
	RangeLoopback:           "127.0.0.1",
	RangeUnspecified:        "0.0.0.0",
	RangeThisNetwork:        "0.1.2.3",
	RangeRFC1918:            "10.0.0.1",
	RangeULA:                "fc00::1",
	RangeLinkLocal:          "169.254.169.254",
	RangeLinkLocalMulticast: "224.0.0.1",
	RangeCGNAT:              "100.64.0.1",
	RangeIETFProtocol:       "192.0.0.1",
	RangeTestNet1:           "192.0.2.1",
	RangeTestNet2:           "198.51.100.1",
	RangeTestNet3:           "203.0.113.1",
	// The literal SENTINEL_IP from
	// runtime-e2e/3067_cross_tenant_cache_isolation/test.sh:92.
	RangeBenchmarking:      "198.18.67.10",
	RangeMulticast:         "239.255.255.255",
	RangeReserved:          "240.0.0.1",
	RangeBroadcast:         "255.255.255.255",
	RangeIPv6Documentation: "2001:db8::1",
}

// allPolicies is every posture any surface consumes. A new preset must be
// added here or the matrix does not cover it.
var allPolicies = []Policy{ConnectorEgress, CallbackEgress, OIDCLiteral}

func mustIP(t *testing.T, s string) net.IP {
	t.Helper()
	ip := net.ParseIP(s)
	if ip == nil {
		t.Fatalf("unparseable test address %q", s)
	}
	return ip
}

func TestEveryRangeHasARepresentative(t *testing.T) {
	for _, r := range AllRanges() {
		addr, ok := representatives[r]
		if !ok {
			t.Errorf("range %q has no representative address — add one to representatives so the policy matrix covers it", r)
			continue
		}
		got, ok := Classify(mustIP(t, addr))
		if !ok || got != r {
			t.Errorf("representative %s for range %q classifies as (%q, %v), want (%q, true)", addr, r, got, ok, r)
		}
	}
	for r := range representatives {
		found := false
		for _, known := range AllRanges() {
			if known == r {
				found = true
			}
		}
		if !found {
			t.Errorf("representatives names range %q which the table no longer reports", r)
		}
	}
}

// TestPolicyMatrix is the cross-surface disagreement test the DoD asks for.
// For every (range, policy) cell it asserts the policy blocks the range unless
// it exempts it BY NAME. A surface that starts permitting a range without
// declaring an exemption fails here, and so does a range added to the table
// that some policy has no stance on.
func TestPolicyMatrix(t *testing.T) {
	for _, r := range AllRanges() {
		addr := representatives[r]
		if addr == "" {
			continue // reported by TestEveryRangeHasARepresentative
		}
		ip := mustIP(t, addr)
		for _, p := range allPolicies {
			t.Run(fmt.Sprintf("%s/%s", p.Name(), r), func(t *testing.T) {
				want := !p.Exempts(r)
				if got := p.Blocks(ip); got != want {
					t.Errorf("policy %q Blocks(%s) [range %s] = %v, want %v — a surface may only permit a range it exempts by name",
						p.Name(), addr, r, got, want)
				}
			})
		}
	}
}

// TestDeclaredDivergences pins the COMPLETE set of exemption cells. Any new
// divergence between two surfaces — in either direction — changes this set and
// fails, which is the point: a divergence must be a deliberate edit here, with
// a reason, not a silent drift.
func TestDeclaredDivergences(t *testing.T) {
	want := []string{
		// ConnectorEgress permits the RFC 2544 benchmarking range because
		// runtime-e2e/3067_cross_tenant_cache_isolation stands its sentinel
		// backend on 198.18.67.0/24. CallbackEgress does not.
		"connector-egress:benchmarking",
		// OIDCLiteral permits loopback for local-dev issuers, in parity with
		// the platform's other http-loopback exemptions.
		"oidc-literal:loopback",
	}
	var got []string
	for _, p := range allPolicies {
		for _, r := range AllRanges() {
			if p.Exempts(r) {
				got = append(got, p.Name()+":"+string(r))
			}
		}
	}
	sort.Strings(got)
	sort.Strings(want)
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("the set of declared egress divergences changed.\n got: %v\nwant: %v\n\n"+
			"Every exemption is a deliberate, documented divergence between two surfaces. "+
			"If you added one, document WHY on the Range constant and update this list.", got, want)
	}
}

// TestCallbackEgressIsStrictSupersetOfConnectorEgress pins the relation the
// two presets are designed around: a callback surface must never permit
// something a connector surface refuses.
func TestCallbackEgressIsStrictSupersetOfConnectorEgress(t *testing.T) {
	stricter := false
	for _, r := range AllRanges() {
		if CallbackEgress.Exempts(r) && !ConnectorEgress.Exempts(r) {
			t.Errorf("CallbackEgress permits %q which ConnectorEgress refuses — callback egress must be at least as strict", r)
		}
		if !CallbackEgress.Exempts(r) && ConnectorEgress.Exempts(r) {
			stricter = true
		}
	}
	if !stricter {
		t.Error("CallbackEgress is no longer STRICTLY stricter than ConnectorEgress; if the benchmarking divergence was resolved, delete this test deliberately")
	}
}

// TestFirstMatchWins pins the ordering contract: exempting a broad range must
// not silently hand over a narrower one nested inside it.
func TestFirstMatchWins(t *testing.T) {
	cases := []struct {
		addr string
		want Range
		why  string
	}{
		{"255.255.255.255", RangeBroadcast, "inside 240.0.0.0/4 but must report broadcast"},
		{"240.0.0.1", RangeReserved, "240.0.0.0/4 proper"},
		{"224.0.0.1", RangeLinkLocalMulticast, "inside 224.0.0.0/4 but must report link-local multicast"},
		{"239.255.255.255", RangeMulticast, "224.0.0.0/4 proper"},
		{"ff02::1", RangeLinkLocalMulticast, "inside ff00::/8 but must report link-local multicast"},
		{"ff12::1", RangeLinkLocalMulticast, "link-local multicast with a non-zero FLAGS nibble — scope 2, not the ff02::/16 prefix"},
		{"ff32::1", RangeLinkLocalMulticast, "same, another flags value"},
		{"ff0e::1", RangeMulticast, "ff00::/8 proper"},
		{"ff1e::1", RangeMulticast, "global scope with flags — still plain multicast"},
		{"0.0.0.0", RangeUnspecified, "inside 0.0.0.0/8 but must report unspecified"},
		{"0.1.2.3", RangeThisNetwork, "0.0.0.0/8 proper"},
		{"127.0.0.1", RangeLoopback, "loopback precedes nothing that contains it"},
	}
	for _, c := range cases {
		t.Run(c.addr, func(t *testing.T) {
			got, ok := Classify(mustIP(t, c.addr))
			if !ok || got != c.want {
				t.Errorf("Classify(%s) = (%q, %v), want (%q, true) — %s", c.addr, got, ok, c.want, c.why)
			}
		})
	}
}

// TestEmbeddedIPv4Unwrapping covers the four IPv6 encodings that carry an
// IPv4 address. Every pre-#3104 classifier reported the loopback-wrapping
// forms as public.
func TestEmbeddedIPv4Unwrapping(t *testing.T) {
	cases := []struct {
		addr  string
		want  Range
		found bool
		why   string
	}{
		{"::ffff:127.0.0.1", RangeLoopback, true, "IPv4-mapped loopback"},
		{"::ffff:169.254.169.254", RangeLinkLocal, true, "IPv4-mapped cloud IMDS"},
		{"::ffff:100.64.0.1", RangeCGNAT, true, "IPv4-mapped CGNAT"},
		{"::ffff:198.18.0.1", RangeBenchmarking, true, "IPv4-mapped benchmarking"},
		{"::ffff:8.8.8.8", "", false, "IPv4-mapped public stays public"},
		{"64:ff9b::7f00:1", RangeLoopback, true, "NAT64 well-known prefix wrapping 127.0.0.1"},
		{"64:ff9b::a9fe:a9fe", RangeLinkLocal, true, "NAT64 wrapping 169.254.169.254"},
		{"64:ff9b::808:808", "", false, "NAT64 wrapping 8.8.8.8 stays public"},
		{"2002:7f00:1::", RangeLoopback, true, "6to4 wrapping 127.0.0.1"},
		{"2002:a9fe:a9fe::", RangeLinkLocal, true, "6to4 wrapping 169.254.169.254"},
		{"2002:808:808::", "", false, "6to4 wrapping 8.8.8.8 stays public"},
		{"::7f00:1", RangeLoopback, true, "deprecated IPv4-compatible wrapping 127.0.0.1"},
		{"::808:808", "", false, "IPv4-compatible wrapping 8.8.8.8 stays public"},

		// The pre-unwrap guard: ::1 and :: sit inside ::/96 and must NOT be
		// reinterpreted as 0.0.0.1 / 0.0.0.0, or OIDCLiteral's documented
		// loopback allowance would stop applying to ::1.
		{"::1", RangeLoopback, true, "IPv6 loopback must not unwrap to 0.0.0.1"},
		{"::", RangeUnspecified, true, "IPv6 unspecified must not unwrap to 0.0.0.0/8"},

		{"::ffff:0:7f00:1", RangeLoopback, true, "RFC 2765 IPv4-translated wrapping 127.0.0.1"},
		{"::ffff:0:a9fe:a9fe", RangeLinkLocal, true, "IPv4-translated wrapping the cloud IMDS"},
		{"::ffff:0:808:808", "", false, "IPv4-translated wrapping 8.8.8.8 stays public"},

		// RFC 8215 local-use NAT64 is deliberately not unwrapped — its prefix
		// length is a deployment choice. Pinned so the omission is visible.
		{"64:ff9b:1::7f00:1", "", false, "RFC 8215 local-use NAT64 deliberately not unwrapped"},

		// Teredo (2001::/32) obfuscates the client IPv4 and also carries the
		// SERVER's, so which one a dial reaches is not decidable from the
		// address. Deliberately not unwrapped; pinned so the gap is visible.
		{"2001::7f00:1", "", false, "Teredo deliberately not unwrapped — see the embeddedIPv4 doc"},
	}
	for _, c := range cases {
		t.Run(c.addr, func(t *testing.T) {
			got, ok := Classify(mustIP(t, c.addr))
			if ok != c.found || (c.found && got != c.want) {
				t.Errorf("Classify(%s) = (%q, %v), want (%q, %v) — %s", c.addr, got, ok, c.want, c.found, c.why)
			}
		})
	}
}

// TestOIDCLoopbackExemptionAppliesInEveryEncoding pins the consequence of
// classifying by the address actually reached: exempting a range exempts it
// however it is spelled.
func TestOIDCLoopbackExemptionAppliesInEveryEncoding(t *testing.T) {
	for _, addr := range []string{"127.0.0.1", "127.1.2.3", "::1", "::ffff:127.0.0.1", "64:ff9b::7f00:1", "2002:7f00:1::"} {
		if OIDCLiteral.Blocks(mustIP(t, addr)) {
			t.Errorf("OIDCLiteral blocks %s; its loopback exemption must hold in every encoding", addr)
		}
		if !CallbackEgress.Blocks(mustIP(t, addr)) {
			t.Errorf("CallbackEgress permits %s; it exempts nothing", addr)
		}
	}
}

// TestPublicAddressesStayReachable is the vacuity control: without it a
// classifier that blocked everything would pass every test above.
func TestPublicAddressesStayReachable(t *testing.T) {
	public := []string{
		"8.8.8.8", "1.1.1.1", "93.184.216.34",
		"198.17.255.255", // immediately below 198.18.0.0/15
		"198.20.0.0",     // immediately above 198.18.0.0/15
		"99.255.255.255", // immediately below 100.64.0.0/10
		"100.128.0.0",    // immediately above 100.64.0.0/10
		"1.0.0.0",        // immediately above 0.0.0.0/8
		"192.0.1.1",      // between 192.0.0.0/24 and 192.0.2.0/24
		"223.255.255.255",
		"2606:4700:4700::1111",
		"2001:db9::1", // immediately above 2001:db8::/32
	}
	for _, addr := range public {
		ip := mustIP(t, addr)
		if r, ok := Classify(ip); ok {
			t.Errorf("Classify(%s) = %q; a public address must be in no named range", addr, r)
		}
		for _, p := range allPolicies {
			if p.Blocks(ip) {
				t.Errorf("policy %q blocks public address %s", p.Name(), addr)
			}
		}
	}
}

// TestBlocksFailsClosedOnMalformed pins the contract change: the previous
// platform/orchestrator/webhooks classifier returned false (permit) for a nil
// IP, so an unparseable resolved address was treated as public.
func TestBlocksFailsClosedOnMalformed(t *testing.T) {
	bad := []net.IP{nil, {}, {1, 2, 3}, make(net.IP, 5), make(net.IP, 17)}
	for _, ip := range bad {
		for _, p := range allPolicies {
			if !p.Blocks(ip) {
				t.Errorf("policy %q permits malformed IP %v (len %d); must fail closed", p.Name(), ip, len(ip))
			}
		}
	}
	if got := CallbackEgress.Reason(nil); !strings.Contains(got, "fail-closed") {
		t.Errorf("Reason(nil) = %q, want it to name the fail-closed path", got)
	}
}

func TestReasonNamesRangeAndPolicy(t *testing.T) {
	got := CallbackEgress.Reason(mustIP(t, "100.64.0.1"))
	for _, want := range []string{"100.64.0.1", string(RangeCGNAT), "callback-egress"} {
		if !strings.Contains(got, want) {
			t.Errorf("Reason = %q, want it to contain %q", got, want)
		}
	}
	if got := ConnectorEgress.Reason(mustIP(t, "198.18.67.10")); got != "" {
		t.Errorf("Reason for a permitted address = %q, want empty", got)
	}
}

func TestNewPolicyRejectsUnknownRange(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("NewPolicy accepted an unknown range name; a typo must fail the build, not silently no-op")
		}
	}()
	_ = NewPolicy("typo", Range("rfc1918"))
}

func TestZeroPolicyBlocksEverythingNamed(t *testing.T) {
	var zero Policy
	for _, r := range AllRanges() {
		if !zero.Blocks(mustIP(t, representatives[r])) {
			t.Errorf("zero-value Policy permits %q; the zero value must be the safe default", r)
		}
	}
}

func TestAllowPrivateFromEnv(t *testing.T) {
	const env = "AXONFLOW_TEST_EGRESS_ALLOW_PRIVATE"

	var captured []string
	orig := logBypass
	logBypass = func(msg string) { captured = append(captured, msg) }
	t.Cleanup(func() { logBypass = orig })

	// Not set, and every near-miss value, must leave the guard on and stay silent.
	for _, v := range []string{"", "1", "yes", "TRUE!", "false", "no", "0", "truthy"} {
		captured = nil
		if v == "" {
			t.Setenv(env, "")
		} else {
			t.Setenv(env, v)
		}
		if AllowPrivateFromEnv(env, "test surface", CallbackEgress) {
			t.Errorf("value %q engaged the bypass; only exact \"true\" may", v)
		}
		if len(captured) != 0 {
			t.Errorf("value %q logged %v; a disengaged hatch must be silent", v, captured)
		}
	}

	for _, v := range []string{"true", "TRUE", "True", " true "} {
		captured = nil
		t.Setenv(env, v)
		if !AllowPrivateFromEnv(env, "test surface", CallbackEgress) {
			t.Errorf("value %q did not engage the bypass", v)
		}
		if len(captured) != 1 {
			t.Fatalf("value %q logged %d messages, want exactly 1", v, len(captured))
		}
		msg := captured[0]
		// The warning must name the surface, the variable, and EVERY range it
		// re-permits — a quiet hatch becomes permanent.
		for _, want := range []string{"WARN", "test surface", env, "Tailscale", "169.254.169.254"} {
			if !strings.Contains(msg, want) {
				t.Errorf("bypass warning does not mention %q: %s", want, msg)
			}
		}
		for _, r := range CallbackEgress.Blocked() {
			if !strings.Contains(msg, string(r)) {
				t.Errorf("bypass warning does not name re-permitted range %q: %s", r, msg)
			}
		}
	}
}

func TestBlockedListsEveryNonExemptRange(t *testing.T) {
	if n := len(CallbackEgress.Blocked()); n != len(AllRanges()) {
		t.Errorf("CallbackEgress.Blocked() has %d entries, want all %d ranges (it exempts nothing)", n, len(AllRanges()))
	}
	for _, r := range ConnectorEgress.Blocked() {
		if r == RangeBenchmarking {
			t.Error("ConnectorEgress.Blocked() lists benchmarking, which it exempts")
		}
	}
}

// --- DNS rebinding (#3104 R3 F1) -------------------------------------------

// rebindingResolver answers the first lookup with a public address and every
// later one with the cloud metadata address — the classic rebinding attack.
type rebindingResolver struct {
	calls int
	first net.IP
	then  net.IP
}

func (r *rebindingResolver) LookupIPAddr(_ context.Context, _ string) ([]net.IPAddr, error) {
	r.calls++
	if r.calls == 1 {
		return []net.IPAddr{{IP: r.first}}, nil
	}
	return []net.IPAddr{{IP: r.then}}, nil
}

// TestSafeDialContextIsRebindingProof is the regression test for R3 F1. The
// pre-#3104 dialers resolved, checked the answer, then dialed the HOSTNAME,
// which resolved a second time — so this resolver got them to open a socket to
// 169.254.169.254 after approving 1.1.1.1.
//
// NewSafeDialContext must issue exactly ONE lookup and dial only what it
// validated, so the second answer is never consulted.
func TestSafeDialContextIsRebindingProof(t *testing.T) {
	res := &rebindingResolver{first: mustIP(t, "1.1.1.1"), then: mustIP(t, "169.254.169.254")}
	rec := &dialRecorder{}
	dial := NewSafeDialContext(CallbackEgress, rec.dialer(), res, func(ip net.IP) error {
		return fmt.Errorf("blocked %s", ip)
	})
	_, _ = dial(context.Background(), "tcp", "evil.example.com:80")

	if res.calls != 1 {
		t.Errorf("resolver was consulted %d times; exactly one lookup may happen or the rebinding window is still open", res.calls)
	}
	if len(rec.addrs) != 1 {
		t.Fatalf("dialed %v, want exactly one address", rec.addrs)
	}
	if rec.addrs[0] != "1.1.1.1:80" {
		t.Errorf("dialed %q; must dial the VALIDATED literal, never the hostname (a hostname re-resolves)", rec.addrs[0])
	}
	for _, a := range rec.addrs {
		if strings.Contains(a, "169.254.169.254") {
			t.Errorf("dialed the cloud metadata address %q after approving a different one — rebinding window open", a)
		}
	}
}

// dialRecorder captures the addresses handed to the underlying dialer without
// opening a socket. Control runs before connect() and returning an error
// aborts the dial, so this test performs no network I/O at all.
type dialRecorder struct{ addrs []string }

func (r *dialRecorder) dialer() *net.Dialer {
	return &net.Dialer{
		Control: func(network, address string, _ syscall.RawConn) error {
			r.addrs = append(r.addrs, address)
			return errRecorded
		},
	}
}

var errRecorded = fmt.Errorf("recorded, not dialed")

// TestSafeDialContextRefusesABlockedAnswer pins that a blocked address is
// refused before any dial, and that the surface's own error is used.
func TestSafeDialContextRefusesABlockedAnswer(t *testing.T) {
	res := &rebindingResolver{first: mustIP(t, "169.254.169.254"), then: mustIP(t, "1.1.1.1")}
	rec := &dialRecorder{}
	dial := NewSafeDialContext(CallbackEgress, rec.dialer(), res, func(ip net.IP) error {
		return fmt.Errorf("surface-specific refusal for %s", ip)
	})
	_, err := dial(context.Background(), "tcp", "evil.example.com:80")
	if err == nil || !strings.Contains(err.Error(), "surface-specific refusal for 169.254.169.254") {
		t.Fatalf("err = %v, want the caller's own refusal naming the address", err)
	}
	if len(rec.addrs) != 0 {
		t.Errorf("dialed %v after refusing; nothing may be dialed", rec.addrs)
	}
}

// TestSafeDialContextRefusesIfANYAnswerIsBlocked: an attacker controls how many
// A records come back and in what order, so checking only the first is not a
// check.
func TestSafeDialContextRefusesIfANYAnswerIsBlocked(t *testing.T) {
	res := &multiResolver{ips: []net.IP{mustIP(t, "1.1.1.1"), mustIP(t, "8.8.8.8"), mustIP(t, "169.254.169.254")}}
	rec := &dialRecorder{}
	dial := NewSafeDialContext(CallbackEgress, rec.dialer(), res, func(ip net.IP) error {
		return fmt.Errorf("blocked %s", ip)
	})
	if _, err := dial(context.Background(), "tcp", "h:80"); err == nil {
		t.Fatal("a answer set containing a blocked address was accepted")
	}
	if len(rec.addrs) != 0 {
		t.Errorf("dialed %v; nothing may be dialed when any answer is blocked", rec.addrs)
	}
}

// TestSafeDialContextPreservesFailover: all-validated answers are tried in
// order, so pinning the dial to a literal does not cost multi-record failover.
func TestSafeDialContextPreservesFailover(t *testing.T) {
	res := &multiResolver{ips: []net.IP{mustIP(t, "1.1.1.1"), mustIP(t, "8.8.8.8"), mustIP(t, "9.9.9.9")}}
	rec := &dialRecorder{}
	dial := NewSafeDialContext(CallbackEgress, rec.dialer(), res, func(ip net.IP) error {
		return fmt.Errorf("blocked %s", ip)
	})
	_, _ = dial(context.Background(), "tcp", "h:443")
	want := []string{"1.1.1.1:443", "8.8.8.8:443", "9.9.9.9:443"}
	if strings.Join(rec.addrs, ",") != strings.Join(want, ",") {
		t.Errorf("dialed %v, want every validated address in resolver order %v", rec.addrs, want)
	}
}

// TestSafeDialContextFailsClosedOnEmptyAnswer: a nil-error empty answer must
// not fall through to a dial that would resolve again.
func TestSafeDialContextFailsClosedOnEmptyAnswer(t *testing.T) {
	rec := &dialRecorder{}
	dial := NewSafeDialContext(CallbackEgress, rec.dialer(), &multiResolver{}, func(ip net.IP) error {
		return fmt.Errorf("blocked %s", ip)
	})
	if _, err := dial(context.Background(), "tcp", "h:80"); err == nil {
		t.Fatal("an empty DNS answer was accepted")
	}
	if len(rec.addrs) != 0 {
		t.Errorf("dialed %v on an empty answer", rec.addrs)
	}
}

type multiResolver struct{ ips []net.IP }

func (m *multiResolver) LookupIPAddr(_ context.Context, _ string) ([]net.IPAddr, error) {
	out := make([]net.IPAddr, 0, len(m.ips))
	for _, ip := range m.ips {
		out = append(out, net.IPAddr{IP: ip})
	}
	return out, nil
}
