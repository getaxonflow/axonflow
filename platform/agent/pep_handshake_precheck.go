package agent

import (
	"context"
	"net/http"

	"axonflow/platform/decision/contract"
)

// The gateway pre-check plane's half of the ADR-065 capability handshake
// (#3778).
//
// #3704 shipped the handshake on the decide and AuthZEN planes; #3766 added the
// MCP plane. This adds the third, and it exists for one client that nothing else
// reaches: `axonflow-litellm` makes no HTTP call of its own, delegating entirely
// to the Python SDK, whose single governed call is `pre_check` against
// POST /api/policy/pre-check. Until this file existed that client had no route
// the platform read a declaration on, so presenting one would have been
// decoration - and the ADR-065 requirement is the DENY, not the header.
//
// # THIS PLANE'S OBLIGATION IS AN INSTRUCTION, NOT AN INLINE MUTATION
//
// The three planes differ in HOW the redaction reaches the caller, and the
// difference is worth stating because it decides where the gate goes:
//
//   - the DECIDE plane EMITS a mandatory `redact_pii` obligation naming a
//     fulfillment endpoint;
//   - the MCP plane IS the fulfillment endpoint - it runs the redactor inline
//     and hands back the masked text;
//   - THIS plane does neither. It answers `requires_redaction: true` and the
//     CALLING SDK is expected to obtain the engine-masked content and forward
//     that in place of the original.
//
// In all three the discharge is the same act: substituting engine-masked
// content for the caller's own, which ADR-056 makes the only sanctioned route
// because a client may not redact for itself. So an enforcement point that has
// declared it cannot perform that substitution must not be answered
// `approved: true, requires_redaction: true` and trusted - it would proceed
// with the original while the record says a redaction applied.
//
// # NO SECOND VOCABULARY, TABLE OR LOOP
//
// The question asked is `field_redact@1` - the same type and schema version the
// decide plane's projection stamps and the MCP plane asks about - so one client
// declaration satisfies all three planes and there is no per-plane dialect for a
// client to get wrong. The equality is pinned by a test that drives the real
// projection. The enforcement loop is the decide plane's own
// firstUnsupportedMandatory, reused.
//
// # WHAT DOES NOT CHANGE
//
// Absent is still not empty. A caller presenting no header resolves to `absent`,
// is asked nothing, and takes byte-for-byte the path it took before.

// preCheckRedactionObligation is the typed obligation this plane's
// `requires_redaction` instruction corresponds to.
//
// Built here rather than projected through mapObligations for the same reason
// the MCP plane builds its own: mapObligations requires a Fulfillment block
// naming the endpoint a PEP must call, and inventing one to reuse a function
// would put a fiction in front of an operator. What IS reused is the part that
// must not drift - the type and the schema version - and that equality is
// asserted against the real projection by
// TestPreCheckRedactionObligationMatchesTheOtherPlanes.
func preCheckRedactionObligation() contract.Obligation {
	return contract.Obligation{
		Type:   contract.ObFieldRedact,
		Target: preCheckRedactionTarget,
		// Mandatory: there is no posture in which ignoring `requires_redaction`
		// is correct. An advisory obligation is dropped by composition rather
		// than denied, which would make this gate a no-op.
		Mandatory:     true,
		SourcePolicy:  preCheckRedactionSourcePolicy,
		SchemaVersion: preCheckRedactionSchemaVersion,
	}
}

const (
	// preCheckRedactionTarget names what the obligation applies to: the query
	// the caller submitted, which is what this plane evaluates.
	preCheckRedactionTarget = "query"
	// preCheckRedactionSourcePolicy records that the obligation was raised by
	// this plane's redaction decision rather than by a named policy, prefixed
	// the way the sibling planes prefix theirs so an audit reader can tell
	// where it came from.
	preCheckRedactionSourcePolicy = "gateway:pre_check_redaction"
	// preCheckRedactionSchemaVersion MUST equal the version the other planes
	// speak, or a client correctly declaring field_redact@1 against /decide
	// would be denied here for a version it could not have known to declare.
	preCheckRedactionSchemaVersion = 1
)

// resolvePreCheckPEPHandshake resolves the handshake for one pre-check request.
//
// # WHERE IT RUNS
//
// Immediately after the authenticated identity is captured, which is #3704
// §4.5's primary rule, and before any policy outcome is acted on.
//
// It is not resolved before the body decode, as the decide plane does. This
// handler decodes the body first in order to reject a request missing `query`
// or `client_id`, and the identity it binds to comes from the middleware rather
// than the body - so the ordering costs only the same denominator skew the MCP
// plane documents (a request refused for a malformed BODY is not counted), in
// the same direction, and it cannot turn a present handshake into an absent one.
func resolvePreCheckPEPHandshake(
	ctx context.Context, r *http.Request, authenticatedClientID string,
) (context.Context, pepHandshakeResolution) {
	return resolveAndRecordPEPHandshakeOnce(ctx, r, authenticatedClientID, PlaneGateway)
}
