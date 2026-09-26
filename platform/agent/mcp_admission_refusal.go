// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"errors"
	"net/http"
	"strconv"

	"axonflow/platform/agent/license/admission"
)

// THE MCP SERVER'S ANSWER TO A TIER ADMISSION REFUSAL (#4249 row 5682255301).
//
// Authenticate admits the authenticated client as a service principal, and
// authenticateMCPSession admits a validated per-user token as a human
// principal (#3593). A refusal of either is a VALID credential past its
// organization's ceiling. The REST routes answer it 402 with its own
// ERR_TIER_LIMIT_<DIMENSION> code; the MCP server flattened it into the 401
// "Authentication required" (and handleMCPInitialize into a 401 carrying the
// message), which clients act on as a rejected credential - the sibling of
// what #4261 fixed for the per-minute 429.
//
// It is answered in the one shape every tier-family refusal on the MCP server
// takes (#4274, writeMCPGateError -> writeEnvelopeJSONRPC): the envelope as
// JSON text in a JSON-RPC result with isError, the X-Axonflow-Tier-Limit and
// X-Axonflow-Upgrade-URL headers, and the status for the refusal
// (mcpAdmissionStatus). The envelope's limit_type is the refused dimension
// (service_principal / human_principal) and its code the refusal's own.

// admissionRefusalOf returns the tier admission decision behind err, whichever
// of the two forms the refusal travels in: the *AuthError Authenticate returns
// for a service principal, or the *tierLimitRefusal a human-principal
// resolution returns.
func admissionRefusalOf(err error) (admission.Decision, bool) {
	var authErr *AuthError
	if errors.As(err, &authErr) && authErr.admission != nil {
		return *authErr.admission, true
	}
	if ref, ok := asTierLimitRefusal(err); ok {
		return ref.Decision, true
	}
	return admission.Decision{}, false
}

// mcpAdmissionStatus is the status a refusal is answered with on the MCP
// server, by the mapping mcpGateStatus applies to the tier gates: 403 for a
// boundary (the ceiling is reached and has no reset), 429 where the refusal
// is a window that passes - the admission ledger's outage, which carries a
// Retry-After.
func mcpAdmissionStatus(d admission.Decision) int {
	if d.Reason == admission.ReasonDependencyUnreachable {
		return http.StatusTooManyRequests
	}
	return http.StatusForbidden
}

// mcpAdmissionRetrySeconds is the Retry-After an outage refusal carries, and 0
// (no header) for a boundary.
func mcpAdmissionRetrySeconds(d admission.Decision) int {
	if d.Reason != admission.ReasonDependencyUnreachable {
		return 0
	}
	if secs := int(d.RetryAfter.Seconds()); secs > 0 {
		return secs
	}
	return int(admission.RetryAfter.Seconds())
}

// mcpAdmissionEnvelope renders the refusal as the tier-family envelope.
// Upgrade names Enterprise and the pricing page; it carries no buy link,
// because the V1 buy link is Plugin Pro's, which lifts no edition ceiling.
func mcpAdmissionEnvelope(d admission.Decision) rateLimitEnvelope {
	message := d.Message()
	return rateLimitEnvelope{
		Error:     message,
		LimitType: string(d.Dimension),
		Tier:      d.Edition,
		Limit:     d.Limit,
		Remaining: 0,
		Upgrade: upgradeBlock{
			Tier:       "Enterprise",
			Wording:    message,
			CompareURL: v1ProUpgradeCompareURL,
		},
		Code: d.Code,
	}
}

// writeMCPAdmissionRefused answers a tier admission refusal on the MCP server
// and returns true; for every other error it writes nothing and returns false.
func writeMCPAdmissionRefused(w http.ResponseWriter, id interface{}, err error) bool {
	d, ok := admissionRefusalOf(err)
	if !ok {
		return false
	}
	writeEnvelopeJSONRPC(w, id, "", mcpAdmissionEnvelope(d), mcpAdmissionStatus(d), mcpAdmissionRetrySeconds(d))
	return true
}

// writeMCPAdmissionRefusedNoBody answers the refusal on a route that carries no
// JSON-RPC body (the session DELETE): the status and the headers
// writeEnvelopeJSONRPC sets, with no body.
func writeMCPAdmissionRefusedNoBody(w http.ResponseWriter, err error) bool {
	d, ok := admissionRefusalOf(err)
	if !ok {
		return false
	}
	w.Header().Set("X-Axonflow-Tier-Limit", string(d.Dimension))
	w.Header().Set("X-Axonflow-Upgrade-URL", v1ProUpgradeCompareURL)
	if secs := mcpAdmissionRetrySeconds(d); secs > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(secs))
	}
	w.WriteHeader(mcpAdmissionStatus(d))
	return true
}
