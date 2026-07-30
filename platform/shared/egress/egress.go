// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package egress is the single source of truth for which IP addresses an
// AxonFlow surface may dial.
//
// # Why this package exists
//
// Before #3104 the repository carried nine independent IP classifiers with
// five distinct behaviours. 21 of 35 probe addresses were classified
// differently by at least two of them. Some of the divergence was deliberate
// and some was drift, and nothing in the source distinguished the two — the
// deliberate parts lived in prose comments that no test read.
//
// # The model
//
// A reserved range is named once, in [table]. A surface does not carry a range
// list; it carries a [Policy], which is a set of ranges it *exempts* by name.
// Everything in the table that a policy does not name is blocked.
//
// The load-bearing consequence: adding a range to the table blocks it on every
// surface. A surface that needs it back must say so in code, by name, in a
// place TestPolicyMatrix reads. There is no default-permit branch for a range
// the table knows about — which is the failure shape (#3060, #3068, #3095)
// this whole programme keeps finding.
//
// # Fail-closed contract
//
// [Policy.Blocks] returns true for a nil or malformed net.IP. Callers that
// cannot parse a resolved address must therefore refuse it; previously
// platform/orchestrator/webhooks permitted it.
//
// # What is NOT in scope
//
// An address in no named range is permitted. This is a denylist, and a
// denylist cannot enumerate the public internet.
//
// # DNS rebinding
//
// This table cannot defend against rebinding; only the CALL SITE can, and only
// by dialing an address it validated rather than a hostname it validated.
// [NewSafeDialContext] is that call site — use it rather than hand-rolling
// resolve-then-check-then-dial-the-name, which re-resolves and is the exact
// window an attacker's resolver needs.
package egress

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"sort"
	"strings"
	"time"
)

// Range is the name of a reserved IP range. A Policy exempts ranges by this
// name, so the constant is part of the security contract: renaming one
// silently drops any exemption spelled with the old name. TestPolicyMatrix
// enumerates them, so an unnamed range cannot exist.
type Range string

const (
	// RangeLoopback is 127.0.0.0/8 and ::1. Reaching it means reaching the
	// service's own host, including any admin port bound to localhost.
	RangeLoopback Range = "loopback"

	// RangeUnspecified is the single addresses 0.0.0.0 and ::. On Linux and
	// macOS `http://0.0.0.0/` and `http://0/` are dial-routed to loopback,
	// so this is a loopback bypass wearing a different literal.
	RangeUnspecified Range = "unspecified"

	// RangeThisNetwork is the rest of 0.0.0.0/8 (RFC 6890 "this network").
	// Distinct from RangeUnspecified because net.IP.IsUnspecified covers only
	// the single address, which is how 0.1.2.3 slipped past several
	// classifiers that believed they had handled 0/8.
	RangeThisNetwork Range = "this-network"

	// RangeRFC1918 is 10.0.0.0/8, 172.16.0.0/12 and 192.168.0.0/16.
	RangeRFC1918 Range = "rfc1918-private"

	// RangeULA is IPv6 unique-local, fc00::/7 — the IPv6 analogue of RFC 1918.
	RangeULA Range = "ipv6-unique-local"

	// RangeLinkLocal is 169.254.0.0/16 and fe80::/10. It contains the cloud
	// instance metadata service at 169.254.169.254, which is the single most
	// valuable SSRF target in a cloud deployment.
	RangeLinkLocal Range = "link-local"

	// RangeLinkLocalMulticast is IPv4 224.0.0.0/24 and IPv6 multicast at
	// link-local SCOPE — ff02::, ff12::, ff32:: and every other flags nibble,
	// not the ff02::/16 prefix alone. Matched via net.IP.IsLinkLocalMulticast
	// because a CIDR cannot express "scope 2 with any flags".
	RangeLinkLocalMulticast Range = "link-local-multicast"

	// RangeCGNAT is 100.64.0.0/10, RFC 6598 carrier-grade NAT shared address
	// space. Also Tailscale's address range: a receiver reachable over
	// Tailscale has a 100.64.0.0/10 address, so blocking this range breaks
	// that (increasingly common) private-connectivity setup. Named here
	// rather than buried in "private ranges" so the operator note is
	// specific — see the AllowPrivate escape hatches.
	RangeCGNAT Range = "cgnat"

	// RangeIETFProtocol is 192.0.0.0/24, IETF protocol assignments.
	RangeIETFProtocol Range = "ietf-protocol-assignments"

	// RangeTestNet1 is 192.0.2.0/24 (RFC 5737 documentation).
	RangeTestNet1 Range = "test-net-1"

	// RangeTestNet2 is 198.51.100.0/24 (RFC 5737 documentation).
	RangeTestNet2 Range = "test-net-2"

	// RangeTestNet3 is 203.0.113.0/24 (RFC 5737 documentation).
	RangeTestNet3 Range = "test-net-3"

	// RangeBenchmarking is 198.18.0.0/15, RFC 2544 / RFC 6815 inter-network
	// benchmarking. This is the one range where the surfaces genuinely
	// disagree on purpose: ConnectorEgress exempts it because
	// runtime-e2e/3067_cross_tenant_cache_isolation stands its sentinel
	// backend on 198.18.67.0/24, and CallbackEgress does not because an
	// operator-supplied callback pointed at a benchmarking range is a mistake
	// or an attack. Do not collapse the two without moving that suite.
	RangeBenchmarking Range = "benchmarking"

	// RangeMulticast is 224.0.0.0/4 and ff00::/8 outside the link-local
	// sub-ranges above. Never a valid unicast HTTP target.
	RangeMulticast Range = "multicast"

	// RangeReserved is 240.0.0.0/4, reserved for future use.
	RangeReserved Range = "reserved"

	// RangeBroadcast is 255.255.255.255. Inside 240.0.0.0/4 but named
	// separately so exempting RangeReserved does not silently hand over the
	// limited broadcast address.
	RangeBroadcast Range = "broadcast"

	// RangeIPv6Documentation is 2001:db8::/32 (RFC 3849). Rejected by none of
	// the nine pre-#3104 classifiers; closed here.
	RangeIPv6Documentation Range = "ipv6-documentation"
)

// entry binds a CIDR to the Range it is reported as. Order in table matters:
// the FIRST match wins, so more specific ranges precede the blocks that
// contain them (RangeBroadcast before RangeReserved, RangeLinkLocalMulticast
// before RangeMulticast, RangeUnspecified before RangeThisNetwork).
type entry struct {
	r    Range
	cidr *net.IPNet
}

func mustCIDR(s string) *net.IPNet {
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		panic("egress: unparseable CIDR in table: " + s + ": " + err.Error())
	}
	return n
}

// preUnwrap is consulted before any embedded-IPv4 extraction. ::1 and :: both
// sit inside ::/96, so unwrapping first would reclassify ::1 as 0.0.0.1
// (RangeThisNetwork) and :: as 0.0.0.0 — losing RangeLoopback, which
// OIDCLiteral deliberately exempts. That would have turned a documented
// local-dev allowance into a block.
var preUnwrap = []entry{
	{RangeLoopback, mustCIDR("::1/128")},
	{RangeUnspecified, mustCIDR("::/128")},
}

// table is the canonical range list, in first-match-wins order.
var table = []entry{
	// IPv4
	{RangeLoopback, mustCIDR("127.0.0.0/8")},
	{RangeUnspecified, mustCIDR("0.0.0.0/32")},
	{RangeThisNetwork, mustCIDR("0.0.0.0/8")},
	{RangeRFC1918, mustCIDR("10.0.0.0/8")},
	{RangeRFC1918, mustCIDR("172.16.0.0/12")},
	{RangeRFC1918, mustCIDR("192.168.0.0/16")},
	{RangeLinkLocal, mustCIDR("169.254.0.0/16")},
	{RangeCGNAT, mustCIDR("100.64.0.0/10")},
	{RangeIETFProtocol, mustCIDR("192.0.0.0/24")},
	{RangeTestNet1, mustCIDR("192.0.2.0/24")},
	{RangeBenchmarking, mustCIDR("198.18.0.0/15")},
	{RangeTestNet2, mustCIDR("198.51.100.0/24")},
	{RangeTestNet3, mustCIDR("203.0.113.0/24")},
	{RangeBroadcast, mustCIDR("255.255.255.255/32")},
	{RangeLinkLocalMulticast, mustCIDR("224.0.0.0/24")},
	{RangeMulticast, mustCIDR("224.0.0.0/4")},
	{RangeReserved, mustCIDR("240.0.0.0/4")},

	// IPv6
	{RangeLinkLocal, mustCIDR("fe80::/10")},
	{RangeULA, mustCIDR("fc00::/7")},
	{RangeLinkLocalMulticast, mustCIDR("ff02::/16")},
	{RangeMulticast, mustCIDR("ff00::/8")},
	{RangeIPv6Documentation, mustCIDR("2001:db8::/32")},
}

// AllRanges returns every Range the table can report, sorted. TestPolicyMatrix
// iterates this against every Policy, so a range added to the table without a
// stance from each policy reddens CI.
func AllRanges() []Range {
	seen := map[Range]bool{}
	for _, e := range preUnwrap {
		seen[e.r] = true
	}
	for _, e := range table {
		seen[e.r] = true
	}
	out := make([]Range, 0, len(seen))
	for r := range seen {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

var (
	nat64WellKnown = mustCIDR("64:ff9b::/96")    // RFC 6052
	sixToFour      = mustCIDR("2002::/16")       // RFC 3056
	v4Compatible   = mustCIDR("::/96")           // RFC 4291 §2.5.5.1, deprecated
	v4Translated   = mustCIDR("::ffff:0:0:0/96") // RFC 2765 SIIT, deprecated
)

// embeddedIPv4 returns the IPv4 address an IPv6 address carries, or nil.
//
// Four encodings wrap an IPv4 address in an IPv6 one, and every pre-#3104
// classifier reported 64:ff9b::7f00:1, 2002:7f00:1::, ::7f00:1 and
// ::ffff:0:7f00:1 — all four of which encode 127.0.0.1 — as public, because
// net.IP's predicates do not unwrap them.
//
// "Four" is the set this function decodes, NOT a claim that no other IPv4-in-
// IPv6 encoding exists. Teredo (2001::/32, RFC 4380) carries the client's IPv4
// XOR-obfuscated in the low 32 bits and the *server's* address in the middle,
// so which one a dial reaches is not decidable from the address alone; it is
// deliberately not decoded. 192.88.99.0/24 (RFC 3068 6to4 relay anycast) is an
// IPv4 range that routes to a relay rather than a wrapper, and is likewise not
// handled here. Both are follow-ups, not oversights.
//
// This is an OBSERVED gap, not a demonstrated exploit: reaching the embedded
// address requires the host to have a NAT64/DNS64 path or a 6to4 pseudo-
// interface, and that was not verified on any AxonFlow deployment. It is
// closed anyway because a classifier that calls 64:ff9b::7f00:1 public is
// wrong on its face and the fix is mechanical.
//
// Deliberately NOT unwrapped: the RFC 6052 network-specific prefixes and the
// RFC 8215 local-use prefix 64:ff9b:1::/48, whose prefix length is a
// deployment choice this package cannot know. A deployment using one should
// block its own prefix at the network layer.
func embeddedIPv4(ip net.IP) net.IP {
	if v4 := ip.To4(); v4 != nil {
		// Plain IPv4, or IPv4-mapped ::ffff:a.b.c.d (net.IP.To4 unwraps it).
		return v4
	}
	if len(ip) != net.IPv6len {
		return nil
	}
	switch {
	case nat64WellKnown.Contains(ip), v4Compatible.Contains(ip), v4Translated.Contains(ip):
		return net.IPv4(ip[12], ip[13], ip[14], ip[15]).To4()
	case sixToFour.Contains(ip):
		return net.IPv4(ip[2], ip[3], ip[4], ip[5]).To4()
	}
	return nil
}

// Classify reports which named range an address falls in.
//
// DO NOT USE THIS TO MAKE A SECURITY DECISION. It is fail-OPEN by
// construction: it returns ("", false) both for a public address and for a nil
// or malformed net.IP, and those two cases are indistinguishable to the
// caller. [Policy.Blocks] is the decision function and is fail-CLOSED on the
// malformed case; the repo lint in conformance_test.go rejects a delegation
// through Classify for exactly this reason.
//
// This exists for diagnostics, error messages and the policy matrix test.
func Classify(ip net.IP) (Range, bool) {
	if len(ip) != net.IPv4len && len(ip) != net.IPv6len {
		return "", false
	}
	for _, e := range preUnwrap {
		if e.cidr.Contains(ip) {
			return e.r, true
		}
	}
	if v4 := embeddedIPv4(ip); v4 != nil {
		ip = v4
	}
	// Link-local multicast is defined by SCOPE, not by a fixed prefix:
	// ff02::, ff12::, ff32:: … all have scope 2 with different flag nibbles.
	// A CIDR cannot express that, and net.IP.IsLinkLocalMulticast can, so it
	// is consulted ahead of the table (it also covers IPv4 224.0.0.0/24).
	// Without this, ff12::1 reported RangeMulticast, which would matter the
	// day a policy exempts one but not the other.
	if ip.IsLinkLocalMulticast() {
		return RangeLinkLocalMulticast, true
	}
	for _, e := range table {
		if e.cidr.Contains(ip) {
			return e.r, true
		}
	}
	return "", false
}

// Policy is a named egress posture: the set of table ranges a surface exempts.
// The zero value blocks every named range, which is the safe default — but
// construct one with [NewPolicy] so it carries a name for error messages.
type Policy struct {
	name   string
	exempt map[Range]bool
}

// NewPolicy returns a Policy blocking every range in the table except those
// named. Panics on an unknown range name, so a typo is a build-time failure
// rather than a silently-ineffective exemption.
func NewPolicy(name string, exempt ...Range) Policy {
	known := map[Range]bool{}
	for _, r := range AllRanges() {
		known[r] = true
	}
	m := make(map[Range]bool, len(exempt))
	for _, r := range exempt {
		if !known[r] {
			panic(fmt.Sprintf("egress: policy %q exempts unknown range %q", name, r))
		}
		m[r] = true
	}
	return Policy{name: name, exempt: m}
}

// Name returns the policy's name, for error messages and the bypass warning.
func (p Policy) Name() string { return p.name }

// Exempts reports whether this policy permits the named range.
func (p Policy) Exempts(r Range) bool { return p.exempt[r] }

// Blocked returns the ranges this policy refuses, sorted.
func (p Policy) Blocked() []Range {
	var out []Range
	for _, r := range AllRanges() {
		if !p.exempt[r] {
			out = append(out, r)
		}
	}
	return out
}

// Blocks reports whether this policy refuses to dial ip.
//
// Fail-closed: a nil or malformed net.IP is blocked. A caller that could not
// parse a resolved address must not treat it as public.
func (p Policy) Blocks(ip net.IP) bool {
	if len(ip) != net.IPv4len && len(ip) != net.IPv6len {
		return true
	}
	r, ok := Classify(ip)
	if !ok {
		return false
	}
	return !p.exempt[r]
}

// Reason returns an operator-facing explanation for a blocked address, naming
// the range and the policy. Empty string if the address is permitted.
func (p Policy) Reason(ip net.IP) string {
	if !p.Blocks(ip) {
		return ""
	}
	r, ok := Classify(ip)
	if !ok {
		return fmt.Sprintf("address is nil or malformed (policy %q, fail-closed)", p.name)
	}
	return fmt.Sprintf("%s is in the %s range, which policy %q does not permit", ip, r, p.name)
}

// ConnectorEgress governs surfaces whose target is operator-configured
// infrastructure that a test harness may legitimately stand on the RFC 2544
// benchmarking range: connector base_url (platform/connectors) and the
// orchestrator media fetcher.
//
// It exempts RangeBenchmarking. runtime-e2e/3067_cross_tenant_cache_isolation
// depends on that exemption (198.18.67.0/24); removing it breaks the only
// executing cross-tenant connector proof.
var ConnectorEgress = NewPolicy("connector-egress", RangeBenchmarking)

// CallbackEgress governs surfaces whose target is an operator- or
// tenant-supplied callback URL that AxonFlow POSTs to or fetches: HITL
// notify_url, circuit-breaker notifications, orchestrator webhook
// subscriptions, and the SAML metadata fetch.
//
// It exempts nothing. A callback pointed at a reserved range is a mistake or
// an attack, and unlike a connector base_url there is no test-harness use for
// one. CallbackEgress is therefore a strict superset of ConnectorEgress —
// TestPolicySupersetRelation pins that.
var CallbackEgress = NewPolicy("callback-egress")

// OIDCLiteral governs the IP-literal branch of
// identity.CheckOIDCEndpointSSRF, which validates an OIDC issuer / JWKS URL at
// configuration-write time.
//
// It exempts RangeLoopback. That allowance is deliberate and predates this
// package: a local-dev issuer on 127.0.0.1 is supported, and the platform's
// http-loopback exemption elsewhere would contradict a block here. Expressing
// it as a named exemption is the point — it used to be a prose comment that no
// test read.
//
// Note this also permits loopback in its wrapped encodings (::ffff:127.0.0.1,
// 64:ff9b::7f00:1), because embeddedIPv4 reports the range of the address
// actually reached. Exempting a range means exempting it in every encoding.
var OIDCLiteral = NewPolicy("oidc-literal", RangeLoopback)

// AllowPrivateFromEnv reports whether a per-surface escape hatch is engaged,
// and emits a loud WARN naming every range the bypass re-permits.
//
// The hatch exists so that hardening a surface which previously permitted
// reserved ranges is recoverable without a rollback — most realistically for a
// receiver on RangeCGNAT (100.64.0.0/10), which is both carrier-grade NAT and
// Tailscale's address range.
//
// Contract, and the reason this helper exists rather than a bare os.Getenv at
// each call site:
//
//   - It is PER-SURFACE. There is deliberately no global egress bypass; each
//     caller passes its own env var name.
//   - Engaging it LOGS, naming the surface, the variable and every re-permitted
//     range. A quiet escape hatch becomes permanent because nothing reminds
//     anyone it is on.
//   - Only the exact string "true" (case-insensitive) engages it. Any other
//     value, including "1" and "yes", leaves the guard on.
//
// Call it once, at construction, not per request.
func AllowPrivateFromEnv(envVar, surface string, p Policy) bool {
	if !strings.EqualFold(strings.TrimSpace(os.Getenv(envVar)), "true") {
		return false
	}
	names := make([]string, 0, len(p.Blocked()))
	for _, r := range p.Blocked() {
		names = append(names, string(r))
	}
	logBypass(fmt.Sprintf(
		"[egress] WARN SSRF egress guard DISABLED for %s because %s=true. "+
			"Re-permitted: %s. Note %q is carrier-grade NAT AND Tailscale's range, and %q contains the cloud "+
			"instance metadata service 169.254.169.254. This is a migration escape hatch, not a supported "+
			"posture: unset %s once the target is reachable on a public address.",
		surface, envVar, strings.Join(names, ", "), RangeCGNAT, RangeLinkLocal, envVar))
	return true
}

// logBypass is a variable so tests can capture the warning and assert it names
// the re-permitted ranges. Production writes to the standard logger.
var logBypass = func(msg string) { log.Print(msg) }

// Resolver is the DNS interface NewSafeDialContext uses. net.DefaultResolver
// satisfies it; tests substitute a rebinding resolver to prove the window is
// actually closed.
type Resolver interface {
	LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
}

// NewSafeDialContext returns a DialContext that refuses to open a socket to
// any address p blocks.
//
// The ordering is the whole point:
//
//  1. Resolve the host ONCE.
//  2. Refuse if the answer is empty, or if ANY returned address is blocked —
//     not just the first, because an attacker controls how many A records come
//     back and in what order.
//  3. Dial the addresses THAT WERE VALIDATED, by literal, in resolver order.
//
// Step 3 is what makes this rebinding-proof, and it is the step the three
// callback dialers were missing before #3104: they resolved, checked the
// answer, and then handed the untouched `host:port` back to net.Dialer, which
// resolved a SECOND time. A resolver returning a public address on the first
// lookup and 169.254.169.254 on the second was allowed through and the socket
// was genuinely opened to the metadata service. Only the absence of a listener
// stopped it, and on the HITL surface the hostname is tenant-supplied.
//
// Dialing by literal keeps TLS intact: crypto/tls takes ServerName from the
// request URL via http.Transport, not from the dial address.
//
// Trying every validated address in order preserves failover across multiple
// A/AAAA records, so this is not the availability trade-off that dialing only
// ips[0] would be.
//
// blocked builds the surface's own error for a refused address, so each caller
// can name its own escape hatch.
func NewSafeDialContext(p Policy, d *net.Dialer, res Resolver, blocked func(net.IP) error) func(ctx context.Context, network, addr string) (net.Conn, error) {
	if d == nil {
		d = &net.Dialer{Timeout: 5 * time.Second}
	}
	if res == nil {
		res = net.DefaultResolver
	}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, fmt.Errorf("invalid address: %w", err)
		}
		ips, err := res.LookupIPAddr(ctx, host)
		if err != nil {
			return nil, fmt.Errorf("DNS lookup failed: %w", err)
		}
		if len(ips) == 0 {
			// Fail closed: an empty answer with a nil error must not fall
			// through to a dial that would resolve again.
			return nil, fmt.Errorf("DNS lookup for %q returned no addresses", host)
		}
		for _, ip := range ips {
			if p.Blocks(ip.IP) {
				return nil, blocked(ip.IP)
			}
		}
		// Every validated address is tried; all failures are joined so the
		// first (usually most diagnostic) error is not discarded.
		//
		// net.IPAddr.Zone is deliberately dropped: it is only meaningful for
		// addresses that need a scope — fe80::/10 and IPv6 link-local
		// multicast — and every one of those is blocked above by every policy
		// in this package, so no reachable address loses information.
		var dialErrs []error
		for _, ip := range ips {
			conn, dialErr := d.DialContext(ctx, network, net.JoinHostPort(ip.IP.String(), port))
			if dialErr == nil {
				return conn, nil
			}
			dialErrs = append(dialErrs, dialErr)
		}
		return nil, errors.Join(dialErrs...)
	}
}
