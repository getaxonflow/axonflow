// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"log"
	"net/http"

	"axonflow/platform/shared/serviceauth"
)

// verifyAgentProxyAuth verifies a request was routed through the AxonFlow
// Agent gateway (X-Axonflow-Proxy-Auth) rather than reaching the
// orchestrator directly (#2896 WS1b). The Agent proxy injects an HMAC-signed
// token on every proxied request AND trust-gates the per-user identity
// headers before forwarding — so a request bearing a valid proxy token
// carries either a trusted identity or none, never a raw client-forged one.
//
// Semantics mirror auditToolCallHandler (run.go) exactly:
//   - validator unset + Community mode → allow (the secret is optional there);
//   - validator unset + any other mode → the deployment is misconfigured —
//     fail closed rather than accept requests that could forge the identity
//     that KEYS override behavior;
//   - validator set → the token must be present and valid, in every mode.
//
// Returns (true, "") when the request may proceed; otherwise (false, msg)
// where msg is the client-facing 403 body (verbatim from auditToolCallHandler
// so the two surfaces respond identically).
func verifyAgentProxyAuth(r *http.Request, surface string) (bool, string) {
	if proxyTokenValidator == nil {
		if isCommunityMode() {
			return true, ""
		}
		log.Printf("[%s] BLOCKED: %s not configured in non-Community deployment — proxy-auth validation cannot run", surface, serviceauth.SecretEnvVar)
		return false, "Unauthorized: internal-service auth not configured"
	}
	proxyToken := r.Header.Get("X-Axonflow-Proxy-Auth")
	if proxyToken == "" {
		log.Printf("[%s] BLOCKED: missing proxy auth header (direct access attempt)", surface)
		return false, "Unauthorized: request must be routed through AxonFlow Agent"
	}
	if valid, _, err := proxyTokenValidator.ValidateToken(proxyToken); !valid {
		log.Printf("[%s] BLOCKED: invalid proxy auth token: %v", surface, err)
		return false, "Unauthorized: invalid proxy authentication"
	}
	return true, ""
}
