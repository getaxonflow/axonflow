//go:build !enterprise

package agent

// The COMMUNITY half of the ADR-065 capability handshake split (#3704).
//
// A Community build reads, validates, binds and COUNTS a handshake exactly as
// an Enterprise build does - all of that is enterprise_protocol and ships here.
// What it does not do is DECIDE on the strength of one, which is
// enterprise_implementation and is physically absent from this build (ADR-066
// Decision 5).
//
// This is not a weaker safety posture; it is today's. An enforcement point that
// declares it cannot discharge a mandatory obligation is still handed that
// obligation here, and it still fails closed at its own seam rather than
// forwarding ungoverned content - which is precisely what happens on this
// build today, because nothing asks. The Enterprise build turns the same
// outcome into a deny the platform can see, audit and count, reached before the
// content is held.

// applyPEPCapabilityRefusal returns the verdict untouched.
//
// The signature is identical to the Enterprise arm's so that handleDecide has
// ONE call site rather than a build-tagged branch at the caller. A branch at
// the caller is how the two arms drift: the community one stops being called at
// all, and the counter it shares goes quiet for a reason nobody can see.
func applyPEPCapabilityRefusal(
	_ string,
	_ pepHandshakeResolution,
	verdict string,
	reasons []string,
	obligations []DecisionObligation,
) (string, []string, []DecisionObligation, bool) {
	return verdict, reasons, obligations, false
}
