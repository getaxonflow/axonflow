// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package agent

import (
	"encoding/json"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"time"

	logutil "axonflow/platform/shared/logger"
	"axonflow/platform/shared/serviceauth"

	"github.com/gorilla/mux"
)

// proxyTokenGenerator signs proxied requests so the orchestrator can verify
// they came through the Agent gateway (not directly from an external caller).
// Uses the same AXONFLOW_INTERNAL_SERVICE_SECRET shared secret as MCP auth.
var proxyTokenGenerator *serviceauth.TokenGenerator

// ProxyConfig holds configuration for the reverse proxy
type ProxyConfig struct {
	OrchestratorInternalURL string
	PortalInternalURL       string
}

// ReverseProxyHandler manages reverse proxy routing to backend services
type ReverseProxyHandler struct {
	orchestratorProxy *httputil.ReverseProxy
	portalProxy       *httputil.ReverseProxy
	orchestratorURL   *url.URL
	portalURL         *url.URL
}

// NewReverseProxyHandler creates a new reverse proxy handler for backend services
func NewReverseProxyHandler(config ProxyConfig) (*ReverseProxyHandler, error) {
	handler := &ReverseProxyHandler{}

	// Initialize proxy token generator for signing proxied requests
	if secret := os.Getenv(serviceauth.SecretEnvVar); secret != "" {
		proxyTokenGenerator = serviceauth.NewTokenGenerator(secret, nil)
		log.Printf("[Proxy] Internal service token signing enabled for proxied requests")
	}

	// Parse and configure Orchestrator proxy
	if config.OrchestratorInternalURL != "" {
		orchURL, err := url.Parse(config.OrchestratorInternalURL)
		if err != nil {
			return nil, err
		}
		handler.orchestratorURL = orchURL
		handler.orchestratorProxy = createReverseProxy(orchURL, "orchestrator")
		log.Printf("[Proxy] Orchestrator proxy configured: %s", config.OrchestratorInternalURL)
	}

	// Parse and configure Portal proxy
	if config.PortalInternalURL != "" {
		portalURL, err := url.Parse(config.PortalInternalURL)
		if err != nil {
			return nil, err
		}
		handler.portalURL = portalURL
		handler.portalProxy = createReverseProxy(portalURL, "portal")
		log.Printf("[Proxy] Portal proxy configured: %s", config.PortalInternalURL)
	}

	return handler, nil
}

// createReverseProxy creates a configured httputil.ReverseProxy for a target URL
func createReverseProxy(target *url.URL, serviceName string) *httputil.ReverseProxy {
	proxy := httputil.NewSingleHostReverseProxy(target)

	// Custom director to preserve headers and set correct host
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)
		// Preserve original headers that are important for tenant isolation
		// X-Tenant-ID, X-User-ID, Authorization, X-License-Key are already in the request
		// Just ensure Host header is set correctly for the target
		req.Host = target.Host

		// Inject internal service token to prove request came through the Agent gateway.
		// The orchestrator can verify this to reject direct access attempts.
		req.Header.Set("X-Axonflow-Proxy-Auth", serviceauth.GetInternalServiceToken(proxyTokenGenerator))
	}

	// Custom error handler for logging and 502 responses
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		log.Printf("[Proxy] Error proxying to %s: %v (path: %s)", logutil.Sanitize(serviceName), err, logutil.Sanitize(r.URL.Path))
		// Record proxy error for circuit breaker auto-trip (#1176 Phase 2B)
		if circuitBreakerInstance != nil {
			orgID := r.Header.Get("X-Org-ID")
			tenantID := r.Header.Get("X-Tenant-ID")
			clientID := tenantID // clientId = tenantId in the unified identity model
			if orgID != "" && tenantID != "" {
				if cbErr := circuitBreakerInstance.RecordError(r.Context(), orgID, tenantID, clientID); cbErr != nil {
					log.Printf("[CircuitBreaker] RecordError (proxy) failed: %v", cbErr)
				}
			}
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte(`{"error":"Backend service unavailable","service":"` + serviceName + `"}`))
	}

	// Custom ModifyResponse for logging successful proxied responses
	proxy.ModifyResponse = func(resp *http.Response) error {
		log.Printf("[Proxy] %s responded: %d %s (path: %s)", logutil.Sanitize(serviceName), resp.StatusCode, resp.Status, logutil.Sanitize(resp.Request.URL.Path))
		return nil
	}

	return proxy
}

// ProxyToOrchestrator handles requests that should be proxied to Orchestrator
func (h *ReverseProxyHandler) ProxyToOrchestrator(w http.ResponseWriter, r *http.Request) {
	if h.orchestratorProxy == nil {
		log.Printf("[Proxy] Orchestrator proxy not configured, returning 503")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"error":"Orchestrator service not configured"}`))
		return
	}

	start := time.Now()
	log.Printf("[Proxy] Proxying to Orchestrator: %s %s", r.Method, logutil.Sanitize(r.URL.Path))
	h.orchestratorProxy.ServeHTTP(w, r)
	log.Printf("[Proxy] Orchestrator request completed in %v", time.Since(start))
}

// ProxyToPortal handles requests that should be proxied to Portal
func (h *ReverseProxyHandler) ProxyToPortal(w http.ResponseWriter, r *http.Request) {
	if h.portalProxy == nil {
		log.Printf("[Proxy] Portal proxy not configured, returning 503")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"error":"Portal service not configured"}`))
		return
	}

	start := time.Now()
	log.Printf("[Proxy] Proxying to Portal: %s %s", r.Method, logutil.Sanitize(r.URL.Path))
	h.portalProxy.ServeHTTP(w, r)
	log.Printf("[Proxy] Portal request completed in %v", time.Since(start))
}

// proxyAuthMiddleware wraps a proxy handler with client credential validation.
// Sets two identity headers for downstream services:
//   - X-Tenant-ID: from clientId in Basic auth (data isolation + client identity)
//   - X-Org-ID: from the cryptographically validated client license payload
//     (client.OrgID, populated by validateViaOrganizations from the signed license).
//
// The client's license is the authoritative source for org identity because the
// Ed25519 signature proves the claim can't be forged — only the license issuer
// holding the signing private key can produce a valid license with any given
// org_id. Trusting the signed claim enables true multi-tenant SaaS: one deployment
// can authenticate many clients, each scoped to their own org_id, without
// cross-contamination.
//
// The deployment ORG_ID env var is still used:
//   - as a fallback in community mode (no license present), and
//   - for the stack's own startup-time license validation (defense in depth:
//     verify the stack was deployed with a boot license matching its env var),
//   - for logging/metrics as a deployment label.
//
// It is NOT the source of truth for per-request org identity.
func proxyAuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Skip auth for CORS preflight
		if r.Method == http.MethodOptions {
			next(w, r)
			return
		}

		// Use unified Authenticate() for all deployment modes.
		// This fixes a latent bug: proxyAuthMiddleware previously had no
		// isCommunitySaasMode() branch — community-saas users couldn't use proxy routes.
		auth, authErr := Authenticate(r, nil)
		if authErr != nil {
			w.Header().Set("Content-Type", "application/json")
			if authErr.RetryAfter != "" {
				w.Header().Set("Retry-After", authErr.RetryAfter)
			}
			w.WriteHeader(authErr.HTTPStatus)
			errBody, _ := json.Marshal(map[string]string{"error": authErr.Message})
			_, _ = w.Write(errBody)
			return
		}

		// Set identity headers from authenticated client for downstream services
		r.Header.Set("X-Tenant-ID", auth.TenantID)
		r.Header.Set("X-Org-ID", auth.OrgID)

		// Populate telemetry identity container (set by outer telemetry middleware)
		SetTelemetryTenantID(r.Context(), auth.TenantID)

		next(w, r)
	}
}

// RegisterProxyRoutes registers all proxy routes on the provided router
// This enables Single Entry Point Architecture (ADR-026)
func (h *ReverseProxyHandler) RegisterProxyRoutes(r *mux.Router) {
	// Auth-wrapped proxy handlers
	orchAuth := proxyAuthMiddleware(h.ProxyToOrchestrator)
	portalAuth := proxyAuthMiddleware(h.ProxyToPortal)

	// Routes proxied to Orchestrator (port 8081)
	// Dynamic policies - new consistent path
	r.PathPrefix("/api/v1/dynamic-policies").HandlerFunc(orchAuth).Methods("GET", "POST", "PUT", "DELETE", "OPTIONS")

	// MCP Process (query processing via orchestrator)
	r.PathPrefix("/api/v1/process").HandlerFunc(orchAuth).Methods("POST", "OPTIONS")

	// MCP Policy Evaluation
	r.PathPrefix("/api/v1/mcp/evaluate-policies").HandlerFunc(orchAuth).Methods("POST", "OPTIONS")

	// Connectors
	r.PathPrefix("/api/v1/connectors").HandlerFunc(orchAuth).Methods("GET", "POST", "PUT", "DELETE", "OPTIONS")

	// Cost Controls
	r.PathPrefix("/api/v1/cost").HandlerFunc(orchAuth).Methods("GET", "POST", "PUT", "DELETE", "OPTIONS")
	r.PathPrefix("/api/v1/budgets").HandlerFunc(orchAuth).Methods("GET", "POST", "PUT", "DELETE", "OPTIONS")
	r.PathPrefix("/api/v1/usage").HandlerFunc(orchAuth).Methods("GET", "POST", "OPTIONS")
	r.PathPrefix("/api/v1/pricing").HandlerFunc(orchAuth).Methods("GET", "OPTIONS")

	// Multi-Agent Planning (MAP)
	r.PathPrefix("/api/v1/plans").HandlerFunc(orchAuth).Methods("GET", "POST", "PUT", "DELETE", "OPTIONS")
	r.PathPrefix("/api/v1/plan").HandlerFunc(orchAuth).Methods("GET", "POST", "PUT", "DELETE", "OPTIONS")

	// Execution Replay
	r.PathPrefix("/api/v1/executions").HandlerFunc(orchAuth).Methods("GET", "POST", "OPTIONS")

	// Execution Viewer UI (served by orchestrator)
	r.PathPrefix("/ui/executions").HandlerFunc(orchAuth).Methods("GET", "OPTIONS")

	// Unified Execution Tracking (#1075) — GET for list/stream, POST for cancel
	r.PathPrefix("/api/v1/unified/executions").HandlerFunc(orchAuth).Methods("GET", "POST", "OPTIONS")

	// Audit Logs
	r.PathPrefix("/api/v1/audit").HandlerFunc(orchAuth).Methods("GET", "POST", "OPTIONS")

	// Plugin Batch 1 (ADR-044 + ADR-043): Session overrides + decision explainability.
	// All plugin + SDK traffic must flow through the agent (never direct to orchestrator)
	// per CLAUDE.md feedback_no_direct_orchestrator. These prefixes route the new
	// platform endpoints through the proxy so plugins can reach them at port 8080.
	r.PathPrefix("/api/v1/overrides").HandlerFunc(orchAuth).Methods("GET", "POST", "DELETE", "OPTIONS")
	r.PathPrefix("/api/v1/decisions").HandlerFunc(orchAuth).Methods("GET", "OPTIONS")

	// LLM Providers
	r.PathPrefix("/api/v1/llm-providers").HandlerFunc(orchAuth).Methods("GET", "POST", "PUT", "DELETE", "OPTIONS")

	// Policy Simulation & Impact Report (Enterprise) — must be before /api/v1/policies
	r.PathPrefix("/api/v1/policies/simulate").HandlerFunc(orchAuth).Methods("POST", "OPTIONS")
	r.PathPrefix("/api/v1/policies/impact-report").HandlerFunc(orchAuth).Methods("POST", "OPTIONS")
	r.PathPrefix("/api/v1/policies/conflicts").HandlerFunc(orchAuth).Methods("POST", "OPTIONS")
	// Dynamic policy CRUD via legacy /api/v1/policies path (orchestrator)
	r.PathPrefix("/api/v1/policies/dynamic").HandlerFunc(orchAuth).Methods("GET", "OPTIONS")
	r.PathPrefix("/api/v1/policies").HandlerFunc(orchAuth).Methods("GET", "POST", "PUT", "DELETE", "OPTIONS")

	// Evidence Export (Enterprise compliance)
	r.PathPrefix("/api/v1/evidence").HandlerFunc(orchAuth).Methods("GET", "POST", "OPTIONS")

	// RBI Compliance (India banking) - Enterprise feature
	r.PathPrefix("/api/v1/rbi").HandlerFunc(orchAuth).Methods("GET", "POST", "PUT", "DELETE", "OPTIONS")

	// SEBI Compliance (India securities) - Enterprise feature
	r.PathPrefix("/api/v1/sebi").HandlerFunc(orchAuth).Methods("GET", "POST", "PUT", "DELETE", "OPTIONS")

	// MAS FEAT Compliance (Singapore) - Enterprise feature
	r.PathPrefix("/api/v1/masfeat").HandlerFunc(orchAuth).Methods("GET", "POST", "PUT", "DELETE", "OPTIONS")

	// Workflow Control Plane (#834)
	r.PathPrefix("/api/v1/workflows").HandlerFunc(orchAuth).Methods("GET", "POST", "PUT", "DELETE", "OPTIONS")

	// Note: HITL endpoints (/api/v1/hitl/*) are registered directly on the agent
	// by hitl.Handler.RegisterRoutes(), NOT proxied to orchestrator.

	// Webhooks
	r.PathPrefix("/api/v1/webhooks").HandlerFunc(orchAuth).Methods("GET", "POST", "PUT", "DELETE", "OPTIONS")

	// Media Governance Config
	r.PathPrefix("/api/v1/media-governance").HandlerFunc(orchAuth).Methods("GET", "PUT", "OPTIONS")

	// Routes proxied to Portal (port 8082)
	// Portal Authentication (login, logout, session) — no auth (login flow)
	r.PathPrefix("/api/v1/auth").HandlerFunc(h.ProxyToPortal).Methods("GET", "POST", "PUT", "DELETE", "OPTIONS")

	// Code Governance
	r.PathPrefix("/api/v1/code-governance").HandlerFunc(portalAuth).Methods("GET", "POST", "PUT", "DELETE", "OPTIONS")

	// Portal Auth & Management
	r.PathPrefix("/api/v1/portal").HandlerFunc(portalAuth).Methods("GET", "POST", "PUT", "DELETE", "OPTIONS")

	// Git Providers
	r.PathPrefix("/api/v1/git-providers").HandlerFunc(portalAuth).Methods("GET", "POST", "PUT", "DELETE", "OPTIONS")

	log.Println("[Proxy] Registered proxy routes for Single Entry Point Architecture (ADR-026)")
}

// GetProxyConfig returns proxy configuration for internal service communication.
// Priority for each URL:
// 1. Environment variable override (ORCHESTRATOR_URL, PORTAL_URL) - required for ECS/K8s
// 2. Docker auto-detection → container names on axonflow-network
// 3. Fallback to localhost for local development
func GetProxyConfig() ProxyConfig {
	config := ProxyConfig{}

	// Orchestrator URL
	if envURL := os.Getenv("ORCHESTRATOR_URL"); envURL != "" {
		config.OrchestratorInternalURL = envURL
		log.Printf("[Proxy] Using ORCHESTRATOR_URL from env: %s", envURL)
	} else if isRunningInDocker() {
		config.OrchestratorInternalURL = DefaultOrchestratorURL
		log.Printf("[Proxy] Docker detected, using orchestrator: %s", DefaultOrchestratorURL)
	} else {
		config.OrchestratorInternalURL = LocalOrchestratorURL
		log.Printf("[Proxy] Local mode, using orchestrator: %s", LocalOrchestratorURL)
	}

	// Portal URL
	if envURL := os.Getenv("PORTAL_URL"); envURL != "" {
		config.PortalInternalURL = envURL
		log.Printf("[Proxy] Using PORTAL_URL from env: %s", envURL)
	} else if isRunningInDocker() {
		config.PortalInternalURL = DefaultPortalURL
		log.Printf("[Proxy] Docker detected, using portal: %s", DefaultPortalURL)
	} else {
		config.PortalInternalURL = LocalPortalURL
		log.Printf("[Proxy] Local mode, using portal: %s", LocalPortalURL)
	}

	return config
}

// IsProxiedPath returns true if the path should be proxied to a backend service
func IsProxiedPath(path string) bool {
	// Orchestrator paths
	if strings.HasPrefix(path, "/api/v1/process") ||
		strings.HasPrefix(path, "/api/v1/mcp/evaluate-policies") ||
		strings.HasPrefix(path, "/api/v1/dynamic-policies") ||
		strings.HasPrefix(path, "/api/v1/connectors") ||
		strings.HasPrefix(path, "/api/v1/cost") ||
		strings.HasPrefix(path, "/api/v1/budgets") ||
		strings.HasPrefix(path, "/api/v1/usage") ||
		strings.HasPrefix(path, "/api/v1/pricing") ||
		strings.HasPrefix(path, "/api/v1/plans") ||
		strings.HasPrefix(path, "/api/v1/plan") ||
		strings.HasPrefix(path, "/api/v1/executions") ||
		strings.HasPrefix(path, "/api/v1/audit") ||
		strings.HasPrefix(path, "/api/v1/llm-providers") ||
		strings.HasPrefix(path, "/api/v1/masfeat") ||
		strings.HasPrefix(path, "/api/v1/rbi") ||
		strings.HasPrefix(path, "/api/v1/sebi") ||
		strings.HasPrefix(path, "/api/v1/webhooks") ||
		strings.HasPrefix(path, "/api/v1/media-governance") ||
		strings.HasPrefix(path, "/api/v1/policies/simulate") ||
		strings.HasPrefix(path, "/api/v1/policies/impact-report") ||
		strings.HasPrefix(path, "/api/v1/policies/conflicts") ||
		strings.HasPrefix(path, "/api/v1/evidence") {
		return true
	}

	// Portal paths
	if strings.HasPrefix(path, "/api/v1/auth") ||
		strings.HasPrefix(path, "/api/v1/code-governance") ||
		strings.HasPrefix(path, "/api/v1/portal") ||
		strings.HasPrefix(path, "/api/v1/git-providers") {
		return true
	}

	return false
}
