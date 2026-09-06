//go:build !enterprise

package agent

// The COMMUNITY half of the MCP plane's capability handshake split (#3766).
//
// A Community build reads, validates, binds and COUNTS a handshake on the MCP
// plane exactly as an Enterprise build does - all of that is
// enterprise_protocol and ships here. What it does not do is DECIDE on the
// strength of one, which is enterprise_implementation and is physically absent
// from this build (ADR-066 Decision 5).
//
// This is not a weaker safety posture; it is today's. An enforcement point that
// declares it cannot substitute a masked statement is still handed one here,
// and it still fails closed at its own seam rather than forwarding the
// unredacted original - which is precisely what happens on this build today,
// because nothing asks. The Enterprise build turns the same outcome into a deny
// the platform can see, audit and count, reached before the masked content is
// handed over.

// applyMCPRedactionRefusal never denies.
//
// The signature is identical to the Enterprise arm's so that each of the three
// MCP call sites has ONE call rather than a build-tagged branch at the caller.
// A branch at the caller is how two arms drift: the community one stops being
// called at all, and the counter it shares goes quiet for a reason nobody can
// see.
func applyMCPRedactionRefusal(_ pepHandshakeResolution, _ bool) (string, bool) {
	return "", false
}
