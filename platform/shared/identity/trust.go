// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

// Package identity holds the single trust-gate contract for client-asserted
// identity headers (X-User-Email / X-User-ID / X-Session-Id). The platform
// governance planes (#2896) and the gateway adapters (#2889) both read the
// AXONFLOW_TRUST_IDENTITY_HEADERS opt-in through this package so the parse
// semantics can never drift between the PDP and its PEP adapters.
//
// SECURITY INVARIANT (#2896): a trusted identity header may set audit
// ATTRIBUTION fields only (audit_logs.user_email / session_id). It must never
// influence a verdict, an authz decision, policy selection, or tenant/org
// resolution. The gate defaults to OFF — a deployment that has not declared
// its identity source trusted must not trust a forgeable header.
//
// PER-USER TOKEN ENVELOPES + COLLISION RULE (#2941, decided 2026-07-17): the
// per-user token (#2924/#2930) rides exactly TWO ingest envelopes, one per
// plane, by design — the POST /api/v1/decide request-body user_token (the
// caller is a PEP deciding on behalf of an end user) and the X-User-Token
// header on the MCP-server + agent-proxied REST planes (the caller IS the
// user's client). Both feed the same ResolveToken: same claims, validation,
// fail-closed posture, and CanonicalEmail attribution. The allowed ingest
// points are pinned by a census test (platform/agent
// TestUserTokenIngestCensus) — adding a read site or schema field is a
// conscious, reviewed act, never a silent second identity channel. If any
// single endpoint ever needs BOTH envelopes: both-present-and-different ⇒
// REJECT the request (fail-closed). Never resolve the ambiguity with silent
// precedence — per-endpoint precedence rules are how two identity channels
// drift apart. (The legacy MCP-connector and examples tenant-JWT
// json:"user_token" fields are a DIFFERENT credential class, annotated as
// such in the census — do not conflate them with the per-user token.)
package identity

import (
	"os"
	"strings"
)

// EnvVar is the deployment-level opt-in for trusting client-asserted identity
// headers. Default OFF (unset/"false"). Set to the exact string "true" ONLY
// when every hop that can reach this service strips + re-sets the identity
// headers from a validated source (e.g. the Claude Desktop proxy's
// AXONFLOW_LEADER_EMAIL, a JumpCloud-managed plugin identity, or a gateway
// jwtAuth claim).
const EnvVar = "AXONFLOW_TRUST_IDENTITY_HEADERS"

// Parse applies the fail-safe trust-gate parse contract: only the exact
// string "true" (after whitespace trim) opts in. "" and "false" are the
// recognized off states. Anything else returns recognized=false — callers
// MUST treat that as untrusted and log loudly, so a "1"/"TRUE" typo cannot
// silently downgrade the operator's intent without a trace. These are the
// exact semantics the gateway adapters shipped in #2889
// (ee/platform/agent/gateway_adapters/config.go trustIdentityFromEnv).
func Parse(raw string) (trusted, recognized bool) {
	switch strings.TrimSpace(raw) {
	case "true":
		return true, true
	case "", "false":
		return false, true
	default:
		return false, false
	}
}

// FromEnv reads EnvVar and applies Parse. recognized=false means the env var
// held an unrecognized value (treated as untrusted); the caller owns the
// component-prefixed warning log.
func FromEnv() (trusted, recognized bool) {
	return Parse(os.Getenv(EnvVar))
}
