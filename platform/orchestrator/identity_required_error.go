// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"net/http"

	sharedidentity "axonflow/platform/shared/identity"
)

// Actionable "no per-user identity" errors (#3062).
//
// ADR-044 policy overrides are scoped to (tenant, USER, policy), so the
// override endpoints refuse to act without a per-user identity. That refusal
// was correct and its message was not: `401 Authenticated user identity
// required (X-User-Email header)` tells a caller to send a header they very
// probably DID send — the AxonFlow Agent strips X-User-Email from every
// proxied route unless AXONFLOW_TRUST_IDENTITY_HEADERS is exactly "true"
// (default OFF since 9.9.0, deliberately). The result: `axonflow_create_override`
// and `axonflow_revoke_override` are dead out of the box on a default
// self-hosted community stack AND on Community SaaS, across all four host
// plugins, with an error that gives the user no way to discover why.
//
// The remediation depends on which of two situations the caller is in, and
// nothing in the old message distinguished them:
//
//   - The agent dropped an identity the caller sent  → operator sets the trust
//     gate (or the caller presents a validated per-user token).
//   - The caller sent no identity at all             → caller sends one.
//
// The agent stamps sharedidentity.HeaderIdentityGated on exactly the first
// case (gateProxyIdentityHeaders), which is what lets this message name the
// real cause instead of guessing. When the marker is absent the message still
// names the gate as the likely cause, because the overwhelmingly common way to
// reach here is through the agent with the default-off gate — it just phrases
// it as a possibility rather than a diagnosis.
//
// SECURITY: the marker selects prose only. Both branches return the SAME 401
// with the SAME authorization outcome, so a forged marker (only reachable by
// bypassing the agent, which Del()s it) buys nothing but a different sentence.
// Neither branch echoes any caller-supplied value, so the body cannot be used
// to reflect content back at a client.
//
// #3074: it is nevertheless honored ONLY over the trusted proxy-auth channel.
// The marker previously had HALF the pattern every other agent-asserted header
// uses — the agent strips inbound values (gateProxyIdentityHeaders), but the
// orchestrator honored whatever arrived, with no binding. X-Axonflow-User-Role
// and X-Axonflow-Read-Scope are stripped AND channel-bound (read_scope.go), and
// the reason to close the gap here is not that the marker is exploitable — it
// selects a sentence — but that proxy.go's own comment on the strip states the
// class: "'harmless' client-settable headers are exactly the ones that later
// acquire meaning." Binding it is what keeps it harmless. Deliberately NOT made
// load-bearing for authz to justify the binding; its value is that it can only
// change wording.

// #3077: the message BODIES moved to platform/shared/identity
// (identity_required.go) so the MCP-server plane — which lives in
// platform/agent and cannot import this package without an import cycle
// (platform/orchestrator imports platform/agent) — refuses through the SAME
// choke point with its own third cause. What stays here is the one thing only
// this package can answer: whether the agent's advisory marker arrived over the
// channel entitled to assert it, which requires this package's
// proxyTokenValidator.

// identityGateMarkerIsTrusted reports whether the advisory
// X-Axonflow-Identity-Gated marker on r arrived over the channel that is
// allowed to assert it — the AxonFlow Agent's HMAC proxy token (#3074).
//
// It mirrors verifyAgentProxyAuth (agent_proxy_guard.go) and NOT
// resolveCallerReadScope, deliberately. resolveCallerReadScope answers an
// authorization question and so admits Community unconditionally in rule 1;
// this answers "did the agent stamp this?", and the agent stamps it in every
// mode. The distinction that matters is whether a proxy token CAN be verified:
//
//   - validator unset + Community mode → trust it. A default self-hosted
//     community stack has no internal-service secret, so no token exists to
//     check; refusing the marker there would silently drop the diagnostic on
//     exactly the deployment #3062 was reported against.
//   - validator unset + any other mode → do NOT trust it (the deployment is
//     misconfigured; fall back to the generic message, which is already the
//     safe default).
//   - validator set → the token must be present and valid, in every mode.
//
// It deliberately does not log. verifyAgentProxyAuth prints a "BLOCKED" line on
// every failure because a failure there refuses the request; a failure here
// refuses nothing, and labelling a wording choice "BLOCKED" would put a
// misleading security line in the operator's log for every direct-path 401.
func identityGateMarkerIsTrusted(r *http.Request) bool {
	if proxyTokenValidator == nil {
		return isCommunityMode()
	}
	token := r.Header.Get("X-Axonflow-Proxy-Auth")
	if token == "" {
		return false
	}
	valid, _, _ := proxyTokenValidator.ValidateToken(token)
	return valid
}

// identityRequiredMessage builds the actionable 401 body for an endpoint that
// requires a per-user identity and did not receive one. feature names the
// capability being refused (e.g. "policy overrides"), so the caller learns why
// a per-user identity is required here specifically.
func identityRequiredMessage(r *http.Request, feature string) string {
	cause := sharedidentity.RefusalNoIdentity
	if identityGateMarkerIsTrusted(r) &&
		sharedidentity.IdentityWasGated(r.Header.Get(sharedidentity.HeaderIdentityGated)) {
		cause = sharedidentity.RefusalIdentityGated
	}
	return sharedidentity.IdentityRequiredMessage(cause, feature)
}

// sendIdentityRequiredError writes the 401 for a missing per-user identity.
// Single choke point so every endpoint that refuses on this condition refuses
// with the same actionable body — the old two-call-site duplication is how the
// message went stale in the first place.
func sendIdentityRequiredError(w http.ResponseWriter, r *http.Request, feature string) {
	sendErrorResponse(w, identityRequiredMessage(r, feature), http.StatusUnauthorized)
}
