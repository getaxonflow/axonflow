package agent

import (
	"context"
	"net/http"

	"axonflow/platform/decision/contract"
)

// The MCP plane's half of the ADR-065 capability handshake (#3766).
//
// #3704 shipped the handshake on the decide plane (/api/v1/decide) and the
// AuthZEN plane (/api/v1/access/evaluation). This file adds the third consumer,
// and it is the one that matters for most of the fleet: the route census on
// #3763 found that SIX of the eight shipped plugins reach the platform ONLY on
// the MCP plane, so until this file existed the handshake was unreachable for
// them and presenting it was decoration.
//
// # THE MCP PLANE'S OBLIGATION IS REAL, IT IS JUST NOT SHAPED LIKE THE DECIDE
// # PLANE'S, AND THAT DIFFERENCE IS THE WHOLE DESIGN
//
// On the decide plane the server EMITS a mandatory `redact_pii` obligation and
// the PEP discharges it by calling a fulfillment endpoint. The capability
// question is asked about that emitted obligation.
//
// The MCP plane has no emitted obligation to ask about, because the MCP plane
// IS the fulfillment endpoint: check-input, check-output and the check_policy /
// check_output tools run the redactor inline and hand the caller
// `redacted_statement` (HTTP) or `redacted_statement` in the tool result. But
// the INSTRUCTION is identical in force - the caller MUST forward the masked
// text instead of the original, and a caller that ignores it forwards raw PII
// while the platform's audit row records a redaction that never reached the
// wire. ADR-056 forbids client-side redaction precisely so that this
// substitution is the only sanctioned discharge.
//
// So the MCP plane's inline redaction is a mandatory field_redact obligation in
// everything but its serialisation, and this file asks the ADR-065 invariant-8
// question about it: an enforcement point that has DECLARED it cannot discharge
// field_redact must be denied rather than handed masked content and trusted to
// substitute it.
//
// # WHY THIS IS NOT A SECOND VOCABULARY, A SECOND TABLE OR A SECOND CHOKE POINT
//
// It reuses contract.ObFieldRedact at schema version 1 - the same type and the
// same version mapObligations already stamps on the decide plane's projection
// of `redact_pii` (authzen_handler.go legacyObligationType). The two planes
// therefore ask the SAME capability question of the SAME declaration, so a
// client that handshakes correctly against /decide is correct here for free and
// there is no per-plane dialect for a client to get wrong.
//
// It reuses firstUnsupportedMandatory, which is the decide plane's own
// enforcement loop, rather than re-deriving "is this supported". One
// implementation of the status mapping, as #3704's own reuse census requires.
//
// # WHAT DOES NOT CHANGE
//
// Absent is still not empty. A caller that presents no header resolves to
// `absent`, is asked nothing, and takes byte-for-byte the path it took before
// this file existed - which is what keeps the six MCP-plane plugins working
// unchanged until they ship a handshake of their own.

// mcpRedactionObligation is the typed obligation the MCP plane's INLINE
// redaction corresponds to.
//
// # WHY IT IS BUILT HERE RATHER THAN PROJECTED THROUGH mapObligations
//
// mapObligations translates an obligation the DECIDE plane emitted, and it
// requires a Fulfillment block naming the endpoint the PEP must call to obtain
// engine-redacted content. On this plane there is no such block and there
// correctly cannot be one: the caller is ALREADY talking to the fulfillment
// endpoint, and the masked text is in the response it is reading. Feeding
// mapObligations a synthetic fulfillment block pointing at the very route being
// served would be a fiction invented to reuse a function, and the fiction would
// reach an operator as a real instruction.
//
// What IS reused is the part that must not drift: the type and the schema
// version. Both are asserted equal to the decide plane's projection by
// TestMCPRedactionObligationMatchesTheDecidePlaneProjection, so the two planes
// cannot start asking different capability questions about the same fact.
//
// Mandatory is true and that is the load-bearing member: the whole point is
// that a caller which cannot substitute the masked text must be refused, and an
// advisory obligation is dropped by composition rather than denied.
func mcpRedactionObligation() contract.Obligation {
	return contract.Obligation{
		Type:   contract.ObFieldRedact,
		Target: mcpRedactionTarget,
		// Mandatory: the caller must forward the masked statement instead of
		// the original. There is no posture in which ignoring it is correct,
		// which is what distinguishes a mandatory obligation from an advisory
		// one.
		Mandatory:     true,
		SourcePolicy:  mcpRedactionSourcePolicy,
		SchemaVersion: mcpRedactionSchemaVersion,
	}
}

const (
	// mcpRedactionTarget names what the obligation applies to. The MCP plane
	// redacts the statement the caller submitted, so the target is that
	// statement - the same target word the AuthZEN projection uses for the
	// decide plane's redaction.
	mcpRedactionTarget = "statement"
	// mcpRedactionSourcePolicy records that this obligation was raised by the
	// MCP plane's inline redactor rather than by a named policy. Prefixed the
	// same way the decide plane's projection prefixes its own ("legacy:"), so a
	// reader of an audit row can tell where an obligation came from.
	mcpRedactionSourcePolicy = "mcp:inline_redaction"
	// mcpRedactionSchemaVersion is the field_redact schema version this plane
	// speaks. It MUST equal the version mapObligations stamps on the decide
	// plane's projection, or a client correctly declaring field_redact@1
	// against /decide would be denied here for a version it could not have
	// known to declare. Pinned by
	// TestMCPRedactionObligationMatchesTheDecidePlaneProjection.
	mcpRedactionSchemaVersion = 1
)

// resolveMCPPEPHandshake resolves the handshake for a request on the MCP plane.
//
// # WHERE IT RUNS, AND THE ONE DELIBERATE DIVERGENCE FROM #3704 §4.5
//
// The decide plane resolves BEFORE the body is decoded, for two reasons: the
// declaration is a header and needs nothing from the body, and counting after
// the decode would drop every malformed-body request out of the `absent`
// denominator that #3564's adoption ratio is read off.
//
// On the MCP plane the FIRST of those still holds and the second cannot: this
// plane authenticates from hints carried IN THE BODY (AuthHints{ClientID,
// UserToken, TenantID}), so the authenticated client identity - which the
// identity binding in §4.2 composes the enforcement point's identifier from -
// does not exist until after the decode. Resolving earlier would have nothing
// to bind to and would refuse every caller with identity_unbindable.
//
// So the rule that survives is the PRIMARY one - resolve immediately after the
// authenticated identity is captured, and before any policy outcome is acted on
// - and the denominator skew it costs is stated rather than left to be
// discovered: on this plane a request refused for a malformed BODY is not
// counted, exactly as a request refused by authentication is not counted on the
// decide plane. Both skews are in the same direction and neither can turn a
// present handshake into an absent one.
func resolveMCPPEPHandshake(
	ctx context.Context, r *http.Request, authenticatedClientID string,
) (context.Context, pepHandshakeResolution) {
	return resolveAndRecordPEPHandshakeOnce(ctx, r, authenticatedClientID, PlaneMCP)
}
