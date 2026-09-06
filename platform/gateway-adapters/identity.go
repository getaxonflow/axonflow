// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package gatewayadapters

import (
	"strings"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"

	agwapi "axonflow/platform/gateway-adapters/agentgateway/api"
)

// Identity is the end-user context extracted from the headers agentgateway
// forwards with each callout. Propagating it is what makes the audit row
// attributable to the actual caller instead of the gateway service account:
// Bearer becomes decide's user_token (the PDP validates it and attributes the
// decision; an invalid token is denied server-side), UserEmail/SessionID ride
// the check-output identity headers.
//
// TRUST BOUNDARY: Bearer is safe to forward untrusted — the PDP independently
// resolves it and denies invalid tokens; it is ALSO the channel the engine's
// check-output actually derives audit identity from today. UserEmail /
// SessionID are NOT PDP-validated and are currently IGNORED by the
// check-output handler (a reserved, forward-compat channel — see
// pep.CheckOutput); the adapters still refuse to forward them by default
// (Config.TrustIdentityHeaders=false) because they are client-assertable and
// agentgateway applies route header modifiers AFTER the ext_proc callout, so
// gateway config alone could never strip a forged value if the engine starts
// honoring the headers. A deployment may opt in ONLY when a hop upstream of
// agentgateway strips the inbound X-User-Email / X-Session-Id and re-sets
// them from a validated source (e.g. a jwtAuth claim). The integration docs
// carry the same contract.
type Identity struct {
	// Bearer is the raw token from "Authorization: Bearer <token>" (already
	// validated by agentgateway when its jwtAuth policy is on; the PDP
	// re-resolves it independently).
	Bearer string
	// UserEmail is the X-User-Email header when present.
	UserEmail string
	// SessionID is the X-Session-Id header when present.
	SessionID string
	// Traceparent is the inbound W3C traceparent, forwarded so multi-layer
	// decisions stitch into one trace.
	Traceparent string
}

// Canonical (lower-cased) header names.
const (
	headerAuthorization = "authorization"
	headerUserEmail     = "x-user-email"
	headerSessionID     = "x-session-id"
	headerTraceparent   = "traceparent"
)

// identityFromMap extracts Identity from a lower-cased header map (the
// ext_authz AttributeContext.HttpRequest.headers shape).
func identityFromMap(headers map[string]string) Identity {
	var id Identity
	for k, v := range headers {
		id.absorb(strings.ToLower(k), v)
	}
	return id
}

// identityFromMcpHeaders extracts Identity from ExtMcp's repeated McpHeader
// (raw value bytes; multi-value headers repeat the key — first value wins).
func identityFromMcpHeaders(headers []*agwapi.McpHeader) Identity {
	var id Identity
	for _, h := range headers {
		if h == nil {
			continue
		}
		id.absorb(strings.ToLower(h.GetKey()), string(h.GetValue()))
	}
	return id
}

// identityFromEnvoyHeaderMap extracts Identity from the ext_proc HeaderMap
// (HeaderValue carries value OR raw_value).
func identityFromEnvoyHeaderMap(hm *corev3.HeaderMap) Identity {
	var id Identity
	for _, h := range hm.GetHeaders() {
		id.absorb(strings.ToLower(h.GetKey()), headerValueString(h))
	}
	return id
}

// headerValueString returns the string form of an Envoy HeaderValue,
// preferring raw_value (set when the peer encodes raw headers).
func headerValueString(h *corev3.HeaderValue) string {
	if len(h.GetRawValue()) > 0 {
		return string(h.GetRawValue())
	}
	return h.GetValue()
}

// absorb folds one lower-cased header into the identity; the first non-empty
// value for each field wins.
func (id *Identity) absorb(key, value string) {
	switch key {
	case headerAuthorization:
		if id.Bearer == "" {
			id.Bearer = bearerToken(value)
		}
	case headerUserEmail:
		if id.UserEmail == "" {
			id.UserEmail = value
		}
	case headerSessionID:
		if id.SessionID == "" {
			id.SessionID = value
		}
	case headerTraceparent:
		if id.Traceparent == "" {
			id.Traceparent = value
		}
	}
}

// bearerToken strips a case-insensitive "Bearer " scheme prefix; a
// non-Bearer Authorization value (e.g. Basic gateway credentials) is NOT an
// end-user token and is dropped rather than forwarded to the PDP.
func bearerToken(authorization string) string {
	const prefix = "bearer "
	v := strings.TrimSpace(authorization)
	if len(v) > len(prefix) && strings.EqualFold(v[:len(prefix)], prefix) {
		return strings.TrimSpace(v[len(prefix):])
	}
	return ""
}
