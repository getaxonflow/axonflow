// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"log"
	"net/http"
	"sync"

	"github.com/rs/cors"

	logutil "axonflow/platform/shared/logger"
	"axonflow/platform/shared/serviceauth"
)

// The orchestrator is an INTERNAL service (ADR-026 single entry point). Every
// legitimate caller reaches it over a hop that holds
// AXONFLOW_INTERNAL_SERVICE_SECRET and stamps an HMAC-signed
// X-Axonflow-Proxy-Auth token:
//
//   - the Agent reverse proxy       (platform/agent/proxy.go)
//   - the Agent's governed forward  (platform/agent/run.go, /api/v1/process)
//   - the Agent's MCP forwarders    (platform/agent/mcp_server_handler.go)
//   - the customer-portal proxies   (ee/platform/customer-portal/api/*.go)
//
// Before #3068 the orchestrator installed NO authentication middleware at all:
// the only router middlewares were enforceTenantWideAuditExport and
// enforceDomainReadAuthority, which are read-AUTHORITY gates that presuppose an
// authenticated caller. Anything that could route to port 8081 therefore had
// unauthenticated, tenant-selectable read AND write on the governance control
// plane, because X-Tenant-ID — stamped by the agent from a validated credential
// on the intended path — is just a client-supplied header on the direct path.
//
// requireInternalProxyAuth closes that. It is deliberately installed as a
// single choke point wrapping the WHOLE mux rather than as per-route checks:
// a route added tomorrow is protected by default, and no reviewer has to
// re-derive the list of routes that carry tenant data
// ([[feedback_guard_an_invariant_not_the_doors_named]]).

// buildOrchestratorHandler assembles the served handler: the authentication
// gate wraps the mux, and the CORS handler wraps that.
//
// This exists as a named function rather than two inline lines in Run() so the
// WIRING itself is testable. Without it, deleting requireInternalProxyAuth from
// Run() — i.e. reverting the entire fix for #3068 — left every middleware unit
// test passing, because they exercised the middleware in isolation and nothing
// asserted it was actually installed.
//
// Order matters and is asserted in the tests:
//   - the gate is INSIDE the CORS handler, so rs/cors answers browser preflight
//     (which carries no token and must not be refused) before the gate sees it;
//   - the gate is OUTSIDE the mux, so it runs before ANY route match. That
//     covers routes registered by other packages onto the same router, and
//     makes unrouted paths 403 rather than 404, so an unauthenticated caller
//     cannot map which routes exist.
func buildOrchestratorHandler(c *cors.Cors, r http.Handler) http.Handler {
	return c.Handler(requireInternalProxyAuth(r))
}

// orchestratorAuthExemptPaths enumerates the ONLY paths served without a valid
// internal-service token. Each entry is justified individually; the set is
// matched by exact string equality on the raw request path, so no traversal
// spelling ("/health/../api/v1/policies/dynamic") and no prefix extension
// ("/healthz", "/metrics/tenant") can inherit an exemption.
//
// Every exempt path is deployment-scoped, aggregate-only data. None of them
// reads a tenant-scoped table, accepts a tenant selector, or performs a write.
var orchestratorAuthExemptPaths = map[string]struct{}{
	// Liveness/readiness. The ECS container health check, the ALB target-group
	// health check and axonflow-install's verify.sh all probe this, and none of
	// them holds the shared secret or can mint an HMAC token. healthHandler
	// returns component booleans, the platform version and the capability pins
	// — deployment facts, no tenant data.
	"/health": {},

	// Prometheus scrape targets. The bundled Prometheus container
	// (infrastructure/cloudformation/*: PrometheusTaskDefinition) and
	// platform/observability/json-exporter scrape these on the internal
	// network; neither holds the shared secret. Both emit process/aggregate
	// counters only.
	"/metrics":    {},
	"/prometheus": {},
}

// missingSecretWarnOnce keeps the misconfiguration banner to one line per
// process rather than one line per rejected request.
var missingSecretWarnOnce sync.Once

// requireInternalProxyAuth rejects any request that did not arrive over a hop
// holding AXONFLOW_INTERNAL_SERVICE_SECRET.
//
// There is NO carve-out — not for Community mode, not for any DEPLOYMENT_MODE,
// not for any environment variable. That is deliberate. A mode-keyed carve-out
// is precisely the defect this same change fixes in the portal's admin gate
// (#2287 re-opened via DEPLOYMENT_MODE=enterprise), and no carve-out is needed:
// every shipped topology already provisions the secret on both ends —
// docker-compose.yml (agent :216, orchestrator :323) and
// docker-compose.enterprise.yml (:211/:331/:474) default it,
// axonflow-install/docker-compose.yml requires it (bundle prerequisite G1), and
// both CloudFormation templates set it on every task definition that talks to
// the orchestrator.
//
// Consequently an unset secret is a misconfiguration, not a supported posture,
// and is treated as such: the gate fails CLOSED and says so loudly at first
// request. Standalone `go run ./platform/cmd/orchestrator` needs
// AXONFLOW_INTERNAL_SERVICE_SECRET set to the same value as the agent — the
// same requirement compose has encoded since 2026-02.
//
// Ordering: this wraps the mux and is itself wrapped by the CORS handler
// (run.go), so (a) it runs before ANY route match — including paths that would
// 404, so an unauthenticated caller cannot probe route existence — and (b)
// browser CORS preflight is answered by rs/cors before reaching the gate.
func requireInternalProxyAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, exempt := orchestratorAuthExemptPaths[r.URL.Path]; exempt {
			next.ServeHTTP(w, r)
			return
		}

		// No validator means AXONFLOW_INTERNAL_SERVICE_SECRET is unset, so no
		// token CAN be verified. Deny rather than wave everything through.
		if proxyTokenValidator == nil {
			missingSecretWarnOnce.Do(func() {
				log.Printf("[SECURITY] Orchestrator API is refusing every request: %s is not set, "+
					"so the internal-service token cannot be validated. Set %s to the SAME value on the "+
					"agent, the orchestrator and the customer-portal (minimum %d characters).",
					serviceauth.SecretEnvVar, serviceauth.SecretEnvVar, serviceauth.SecretMinLength)
			})
			sendErrorResponse(w, "Unauthorized: internal-service auth not configured", http.StatusForbidden)
			return
		}

		token := r.Header.Get("X-Axonflow-Proxy-Auth")
		if token == "" {
			log.Printf("[OrchestratorAuthn] BLOCKED: missing proxy auth header for %s %s (direct access attempt)",
				logutil.Sanitize(r.Method), logutil.Sanitize(r.URL.Path))
			sendErrorResponse(w, "Unauthorized: request must be routed through AxonFlow Agent", http.StatusForbidden)
			return
		}

		// HMAC only. ValidateToken rejects the legacy plain-secret spelling and
		// the static serviceauth.TokenFallback constant (both return
		// valid=false), so a caller who merely knows a hard-coded string cannot
		// authenticate — only a holder of the shared secret can, and only
		// inside the replay window (serviceauth.DefaultClockSkew).
		if valid, _, err := proxyTokenValidator.ValidateToken(token); !valid {
			log.Printf("[OrchestratorAuthn] BLOCKED: invalid proxy auth token for %s %s: %v",
				logutil.Sanitize(r.Method), logutil.Sanitize(r.URL.Path), err)
			sendErrorResponse(w, "Unauthorized: invalid proxy authentication", http.StatusForbidden)
			return
		}

		next.ServeHTTP(w, r)
	})
}
