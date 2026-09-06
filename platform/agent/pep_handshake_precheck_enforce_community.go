//go:build !enterprise

package agent

// The COMMUNITY half of the pre-check plane's capability handshake split
// (#3778).
//
// A Community build reads, validates, binds and COUNTS a handshake on this
// plane exactly as an Enterprise build does - all of that is
// enterprise_protocol and ships here. What it does not do is DECIDE on the
// strength of one, which is enterprise_implementation and is physically absent
// from this build (ADR-066 Decision 5).
//
// This is not a weaker safety posture; it is today's. A caller that declares it
// cannot substitute engine-masked content is still told `requires_redaction:
// true` here and is still expected to act - which is precisely what happens on
// this build today, because nothing asks. The Enterprise build turns the same
// outcome into a deny the platform can see, audit and count.

// applyPreCheckRedactionRefusal never denies.
//
// The signature is identical to the Enterprise arm's so the handler has ONE
// call site rather than a build-tagged branch at the caller. A branch at the
// caller is how two arms drift: the community one stops being called at all,
// and the counter it shares goes quiet for a reason nobody can see.
func applyPreCheckRedactionRefusal(_ pepHandshakeResolution, _ bool) (string, bool) {
	return "", false
}
