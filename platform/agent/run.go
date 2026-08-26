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

// Build trigger: Test AWS OIDC authentication for GitHub Actions

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/lib/pq" // PostgreSQL driver
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/cors"

	"axonflow/platform/agent/circuitbreaker"
	"axonflow/platform/agent/fincrime"
	"axonflow/platform/agent/hitl"
	"axonflow/platform/agent/license"
	"axonflow/platform/agent/marketplace"
	"axonflow/platform/agent/node_enforcement"
	"axonflow/platform/agent/telemetry"
	"axonflow/platform/common/usage"
	"axonflow/platform/orchestrator/cost"
	"axonflow/platform/shared/idempotency"
	sharedidentity "axonflow/platform/shared/identity"
	logutil "axonflow/platform/shared/logger"
	sharedpolicy "axonflow/platform/shared/policy"
	"axonflow/platform/shared/secretenv"
	"axonflow/platform/shared/serviceauth"
)

// AxonFlow Agent - Authentication, Authorization & Static Policy Enforcement Gateway
// This service sits between clients and the AxonFlow Orchestrator

// envIntDefault parses an integer env var, returning the default on missing
// or invalid values (logs a warning so a typo in the override doesn't
// silently fall through to defaults). Centralised so circuit-breaker
// thresholds, future numeric knobs, and the existing bespoke parsers can
// share one bug-for-bug consistent fallback path.
func envIntDefault(key string, def int) int {
	raw := os.Getenv(key)
	if raw == "" {
		return def
	}
	v, err := strconv.Atoi(raw)
	if err != nil {
		log.Printf("[Env] WARNING: %s=%q is not a valid int, using default %d: %v", key, raw, def, err)
		return def
	}
	return v
}

// isCommunityMode reports whether this process runs the Community posture.
//
// Community mode bypasses license validation AND authentication
// (authenticator.go:158 returns a synthetic identity with no credential),
// skips the MCP connector permission check (mcp_handler.go:92), auto-approves
// require_approval policies (gateway_handlers.go:782) and lets a request body
// assert its own tenant (decision_handler.go:717). It is the single most
// permissive posture the agent has.
//
// #3096: it used to be the posture you got by FORGETTING to configure one.
// `mode == ""` was in the true set, so a deployment that simply never set
// DEPLOYMENT_MODE — the standalone docker-compose stacks, a bare `docker run`
// of the published image (neither Dockerfile sets a default), `go run
// ./platform/agent` — silently ran with authentication disabled. That is the
// identical fail-open-on-unset shape #2287/#3068 fixed in the portal's
// isAdminAuthRequired, whose default now denies.
//
// The burden of proof is now inverted: the permissive posture must be ASKED
// for by name, and everything else — including the empty string — gets the
// enterprise posture.
//
//	| DEPLOYMENT_MODE        | Community posture? |
//	|------------------------|--------------------|
//	| "community"            | YES                |
//	| "" (unset)             | no  (was YES)      |
//	| any other known mode   | no                 |
//	| unrecognised / typo    | no                 |
//
// Deliberately NOT trimmed or case-folded, unlike isAdminAuthRequired. There,
// normalising the input could only ever make auth MORE likely, because the
// environment=="production" and adminAPIKey!="" rules dominate the switch.
// Here every widening of the accepting set DISABLES authentication and there is
// no dominating rule, so the set is exactly the canonical token. A value like
// " community" therefore fails closed — and fails loudly, because the agent
// then demands a license it was not given, which is the outcome you want from
// a malformed mode string.
//
// Sibling: platform/orchestrator/run.go carries the same helper with the same
// contract; the two are kept byte-identical in logic on purpose.
func isCommunityMode() bool {
	return os.Getenv("DEPLOYMENT_MODE") == "community"
}

// isCommunitySaasMode returns true when running as the shared community SaaS server.
// community-saas mode: no Ed25519 license, but DOES require registration credentials.
// Rate limits are enforced (20/min + 500/day). Ollama LLM only.
// This is intentionally NOT community mode — isCommunityMode() returns false.
func isCommunitySaasMode() bool {
	return os.Getenv("DEPLOYMENT_MODE") == "community-saas"
}

// getDeploymentOrgID returns the canonical deployment org_id from the ORG_ID env var.
// This is the single source of truth for org identity — set at deployment time in
// docker-compose or platform config. License org_id must match this value.
// Defaults to "local-dev-org" if not set — matches docker-compose.yml default.
// This default MUST NOT change across versions — existing installs rely on the
// implicit value for data continuity via the RLS org_id column.
func getDeploymentOrgID() string {
	orgID := os.Getenv("ORG_ID")
	if orgID == "" {
		return "local-dev-org"
	}
	return orgID
}

// getDeploymentKind returns the deployment-kind signal ("dev" or "production")
// from the DEPLOYMENT_KIND env var. Issue #2320 — defense-in-depth for migration
// 094's Pass-2 backfill: distinguishing dev-default (legitimate local
// docker-compose / community-mode) from prod-forgot-ORG_ID (operator deployed
// to a real stack without setting ORG_ID → getDeploymentOrgID() falls back to
// 'local-dev-org' → Pass-2 would silently stamp historical empty-org_id rows
// across 9 audit tables with the dev sentinel, forward-only + unrecoverable).
//
// CFN templates set DEPLOYMENT_KIND=production on agent + orchestrator task
// defs. docker-compose.yml + docker-compose.enterprise.yml default to "dev".
// Unset → "dev" (matches the docker-compose default; on prod a missing CFN env
// is itself a misconfiguration and the migration 094 precondition is the
// catcher of last resort).
func getDeploymentKind() string {
	kind := os.Getenv("DEPLOYMENT_KIND")
	if kind == "" {
		return "dev"
	}
	return kind
}

// openMigrationDB opens the migration connection WITH a server-message handler.
//
// database/sql's plain Open discards every NOTICE and WARNING the server sends:
// lib/pq only delivers them through pq.ConnectorWithNoticeHandler, and nothing
// on this path installed one. Migrations tell their entire diagnostic story
// through RAISE NOTICE / RAISE WARNING — how many owner assignments were
// backfilled, which orgs were left without one and need the break-glass
// endpoint, and the RLS canaries in core/149 and core/151 that report the
// migration role cannot see `organizations` at all — and none of it has ever
// reached the agent log. A migration that "warns" into a connection that throws
// warnings away is not a signal; it is the silent failure it was written to
// prevent, one layer down.
//
// Errors are NOT routed here: a failed migration comes back through Exec and
// run.go log.Fatalf's on it. This is for the messages that accompany a
// SUCCESSFUL apply, which are exactly the ones that were being lost.
func openMigrationDB(dbURL string) (*sql.DB, error) {
	base, err := pq.NewConnector(dbURL)
	if err != nil {
		return nil, err
	}
	return sql.OpenDB(pq.ConnectorWithNoticeHandler(base, func(n *pq.Error) {
		if n == nil {
			return
		}
		// WARNING is the only elevated severity that can arrive here: lib/pq
		// dispatches this handler on NoticeResponse ('N') only, and an
		// ErrorResponse ('E') goes to the error path instead — which is why the
		// note above says errors are not routed here. Listing ERROR/FATAL/PANIC
		// arms would be dead code contradicting that.
		//
		// Prefixed distinctly because a migration WARNING means the apply
		// SUCCEEDED but did less than it claims, which is the case an operator
		// must not scroll past.
		if n.Severity == "WARNING" {
			log.Printf("⚠️  [migration %s] %s", n.Severity, n.Message)
			return
		}
		log.Printf("[migration %s] %s", n.Severity, n.Message)
	})), nil
}

// setMigrationSessionVars seeds the Postgres session GUCs that downstream
// migration SQL reads via current_setting():
//
//   - app.db_password: required by migration 017's dblink_exec call to
//     create the Grafana database outside transaction context.
//   - app.deployment_org_id: required by migration 094 Pass-2 to backfill
//     empty-org_id audit rows from ORG_ID rather than silently stamping
//     the 'local-dev-org' default.
//
// Migration 094 raises an EXCEPTION ONLY when this GUC is NULL/empty AND
// any non-cs_* empty-org_id row exists (catches the regression where
// run.go skips this helper entirely). When the GUC is 'local-dev-org'
// the migration accepts it (legitimate dev/community-mode default) but
// emits a RAISE WARNING so operators running against real deployments
// see a paper trail. See commit ac704a5d on PR #2309 for the narrowing
// rationale and the follow-up issue tracking proper dev/prod detection
// via an app.deployment_kind GUC.
//
// Errors are logged but not fatal: the historical inline form treated
// app.db_password as non-fatal and we preserve that behavior. The
// migration runner's own per-migration error handling will catch a
// downstream SQL failure if a session var matters.
// buildAPICallClientID returns the credential identity that downstream
// usage_events.client_id rows should carry, per ADR-052 §5 (this is
// client.ClientID — the api_key_id for API-keyed callers post Fix 4 of
// PR #2309 — NOT client.ID which is the legacy compat org_id).
//
// Extracted so the field-mapping has a single mutation-testable surface:
// asserting on `client.ClientID` directly in a test is tautological (the
// test reads back the value it just wrote into the struct). Routing
// both the test AND run.go's usage.APICallEvent construction through
// this helper means reverting the helper's return expression fails the
// test.
//
// Residual: removing the helper call at the RecordAPICall site and
// inlining client.ID directly is NOT caught by the helper test —
// closing that would require driving the handler with a mock recorder.
func buildAPICallClientID(client *Client) string {
	return client.ClientID
}

// stampAuthContext is the canonical AuthResult → request-context mapping
// for authenticated request handlers that bypass apiAuthMiddleware
// (chiefly clientRequestHandler for the /api/request body-style endpoint).
//
// ADR-052 §5: ContextKeyClientID is the credential identity (api_key_id for
// API-keyed callers post Fix 4 of PR #2309), not the org boundary — see the
// contract docstring on auth.go:505-507. apiAuthMiddleware (auth.go:658-661)
// stamps four keys (TenantID, OrgID, ClientID, AuthKind); this helper must
// stamp the same four so callers that build the context directly from
// *Client + AuthKind agree with the middleware path. Issue #2319 (preserved
// by PR #2315's extraction) — AuthKind was missing, leaving AuthKindFromContext
// to silently return the default AuthKindEnterprise for body-auth requests.
//
// Extracted (R3 finding F1-A on PR #2309's gap-closure train) so a single
// unit test can mutation-prove the invariant without driving the full
// HTTP handler. Also picks up telemetry tenant identity so the outer
// telemetry middleware's per-request container is non-empty.
func stampAuthContext(ctx context.Context, client *Client, kind AuthKind) context.Context {
	ctx = context.WithValue(ctx, ContextKeyTenantID, client.TenantID)
	ctx = context.WithValue(ctx, ContextKeyOrgID, client.OrgID)
	ctx = context.WithValue(ctx, ContextKeyClientID, client.ClientID)
	ctx = context.WithValue(ctx, ContextKeyAuthKind, kind)
	SetTelemetryTenantID(ctx, client.TenantID)
	return ctx
}

func setMigrationSessionVars(db *sql.DB, dbPassword, deploymentOrgID, deploymentKind string) {
	if _, err := db.Exec("SELECT set_config('app.db_password', $1, false)", dbPassword); err != nil {
		log.Printf("⚠️  Failed to set session variable app.db_password: %v", err)
	} else {
		log.Println("✅ Set app.db_password session variable for dblink migrations")
	}
	if _, err := db.Exec("SELECT set_config('app.deployment_org_id', $1, false)", deploymentOrgID); err != nil {
		log.Printf("⚠️  Failed to set session variable app.deployment_org_id: %v", err)
	} else {
		log.Printf("✅ Set app.deployment_org_id=%s session variable for migration 094 backfill", deploymentOrgID)
	}
	if _, err := db.Exec("SELECT set_config('app.deployment_kind', $1, false)", deploymentKind); err != nil {
		log.Printf("⚠️  Failed to set session variable app.deployment_kind: %v", err)
	} else {
		log.Printf("✅ Set app.deployment_kind=%s session variable for migration 094 prod-safety precondition (#2320)", deploymentKind)
	}
	// Paper trail (#2320): if DEPLOYMENT_KIND was unset on the agent process,
	// the migration runner will treat this as `dev`. That's correct for local
	// docker-compose + community-mode, but on a real stack this means CFN
	// drift — log a WARNING so operators see it in container logs.
	if os.Getenv("DEPLOYMENT_KIND") == "" {
		log.Println("⚠️  DEPLOYMENT_KIND env unset — defaulted to 'dev'. On real deployments this should be 'production' (CFN templates set it; if you see this on a non-dev stack, the task definition is drifted).")
	}
}

// promoteDeploymentOrgTier upserts the deployment org's organizations row to
// the licensed tier / max_nodes / expires_at via the mig-117 SECURITY DEFINER
// helper promote_deployment_org_license (#2535). This is the durable fix for
// the agent storing the parsed license tier in-memory only: the portal,
// node-limit enforcement, and compliance-evidence paths read organizations.tier
// from the DB, which migration 094 seeds 'Community' (ON CONFLICT DO NOTHING)
// and nothing else promotes.
//
// The write is issued as `SELECT promote_deployment_org_license(...)` so it
// executes as the function's OWNER — the migration/table-owning role, which
// bypasses FORCE RLS on organizations (mig 103). This is the same RLS-safe
// posture register_org (mig 104) relies on, and it means a raw INSERT/UPDATE
// here under AXONFLOW_DB_USE_APP_ROLE (axonflow_app_role is NOBYPASSRLS, so mig
// 103 would reject it) is avoided. The helper's ON CONFLICT DO UPDATE ... WHERE
// (tier|max_nodes|expires_at) IS DISTINCT FROM EXCLUDED guard makes a re-boot
// with the same license a no-op (no error, no flapping).
//
// Failures are logged, NOT fatal: the agent's in-memory tier (and /health) are
// already correct, so a transient DB hiccup here must not crash the agent — the
// next boot re-attempts the sync.
func promoteDeploymentOrgTier(db *sql.DB, orgID, tier string, maxNodes int, expiresAt time.Time) {
	// A zero ExpiresAt (no-expiry / perpetual license) is passed as SQL NULL so
	// it matches organizations.expires_at's nullable column and the portal's
	// "NULL expires_at = unbounded" status logic (license.go).
	var expiresArg interface{}
	if !expiresAt.IsZero() {
		expiresArg = expiresAt.UTC()
	}
	if _, err := db.Exec(
		"SELECT promote_deployment_org_license($1, $2, $3, $4)",
		orgID, tier, maxNodes, expiresArg,
	); err != nil {
		log.Printf("⚠️  Failed to sync licensed tier into organizations row for org=%s: %v "+
			"(agent /health tier is correct in-memory; portal + other DB consumers may show a "+
			"stale tier until the next successful boot)", orgID, err)
		return
	}
	log.Printf("✅ Synced licensed tier into organizations.tier: org=%s tier=%s max_nodes=%d (#2535)", orgID, tier, maxNodes)
}

// Internal service URLs - auto-discovered based on environment (ADR-026: Single Entry Point)
// Docker Compose services communicate via service names on the axonflow-network.
// No configuration required - the Agent detects Docker and uses appropriate URLs.
const (
	// DefaultOrchestratorURL is the internal URL for the Orchestrator service in Docker
	DefaultOrchestratorURL = "http://axonflow-orchestrator:8081"

	// DefaultPortalURL is the internal URL for the Customer Portal service in Docker
	// Service name: axonflow-customer-portal, internal port: 8080 (mapped to 8082 externally)
	DefaultPortalURL = "http://axonflow-customer-portal:8080"

	// LocalOrchestratorURL is used for local development without Docker
	LocalOrchestratorURL = "http://localhost:8081"

	// LocalPortalURL is used for local development without Docker
	LocalPortalURL = "http://localhost:8082"
)

// Configuration
var (
	// JWT_SECRET feeds straight into HMAC-SHA256. Trim via secretenv.Get
	// so an SM-resolved value with trailing whitespace doesn't produce a
	// silently-different signature than what the orchestrator computes
	// from the same logical secret.
	jwtSecret              = []byte(secretenv.Get("JWT_SECRET"))
	orchestratorURL        = getOrchestratorURL()         // Auto-discovered based on environment
	authDB                 *sql.DB                        // Database for Option 3 authentication
	usageDB                *sql.DB                        // Database for usage metering
	tierAwarePolicyEngine  *TierAwarePolicyEngine         // Tier-aware policy engine for tenant-specific policies
	meteringService        *marketplace.MeteringService   // AWS Marketplace metering
	costService            *cost.Service                  // Cost tracking and budget enforcement (Issue #1082)
	circuitBreakerInstance *circuitbreaker.CircuitBreaker // Circuit breaker for auto-trip on error/violation thresholds (#1176)
	// mcpHITLService is the long-lived HITL service the MCP-tool dispatcher
	// reuses for `axonflow_request_approval`. Wiring it here (rather than
	// constructing a new Service per call) means the MCP-tool path inherits
	// the same tier gate, validation, history-write, and pending-cap logic
	// the HTTP handler path uses — single chokepoint, no parallel
	// enforcement layers to drift.
	mcpHITLService *hitl.Service
	// decisionTracerProvider holds the OTel-backed DecisionTracer wired
	// at boot (#2426 WS4). When AXONFLOW_OTEL_ENDPOINT is unset, the
	// provider's Tracer is the noop impl — handlers can call
	// RecordDecision unconditionally without nil-checks. Provider is
	// kept around so Run() can flush spans during graceful shutdown.
	decisionTracerProvider *telemetry.Provider
	// mcpIdempStore is the long-lived idempotency Store used by handlers
	// that authenticate inside their own body (mcp/check-input, hitl/queue
	// via the SetIdempotencyWrap shim). Wired in run.go after the admin
	// pool is opened. nil-safe — handlers tolerate a nil store as a
	// pass-through. Read-only after wiring.
	mcpIdempStore *idempotency.Store
	// decisionChainTracker is the WRITING per-record-signing tracker (#2732,
	// FU-1 of epic #2716). It signs (Ed25519) and prev_hash-chains every live
	// decision into decision_chain so the verify endpoints prove authorship of
	// REAL traffic, not just synthetic records. Distinct from
	// decisionTracerProvider above: that is OTel telemetry, this is the
	// non-repudiation signing chain (#2722). Wired in run.go after usageDB is
	// open; the SAME instance also backs the /api/v1/audit/*/verify endpoints.
	// nil-safe: recordSignedDecision is a no-op when this is nil (DB-less
	// deployments), so no handler needs a nil-check. Signing happens in the
	// tracker's async workers, OFF the decision hot path.
	decisionChainTracker *DecisionChainTracker
	// fincrimeEngine is the Fraud & Risk Add-on Engine A seam (ADR-061 /
	// #3329): context validation, pluggable deterministic evaluators, and
	// the Engine B scorer client. Constructed EXPLICITLY in Run() (never
	// init() factory registration, #3268); nil on community builds and the
	// nil path is a strict no-op inside evaluateInputPolicies, so no caller
	// needs a nil-check.
	fincrimeEngine *fincrime.Engine
	// fincrimeHITLBridge routes scorer above-threshold decisions into the
	// HITL approval queue on the /decide plane (the first real HITLBridge
	// caller; see hitl_bridge.go #3065 note). nil-safe at the call site:
	// when HITL wiring is unavailable the needs_approval verdict still
	// returns, only the queue entry is skipped (logged).
	fincrimeHITLBridge *HITLBridge
)

// proxyPolicyCategories is the set of policy categories evaluated for proxy requests.
// Used by both clientRequestHandler and policyTestHandler to avoid divergence.
//
// #2965: the PII portion is sourced from sharedpolicy.AllTextPIICategories() (the
// single canonical pii-* list) rather than hand-listed here — the old hand list
// omitted pii-indonesia, so the KTP/NIK policy was filtered out BEFORE evaluation
// on this plane and a matching query was silently ungoverned under every posture.
var proxyPolicyCategories = append([]sharedpolicy.PolicyCategory{
	sharedpolicy.CategorySecuritySQLi,
	sharedpolicy.CategorySecurityDangerous,
	sharedpolicy.CategoryAdminAccess,
	sharedpolicy.CategorySensitiveData,
	sharedpolicy.CategoryComplianceRBI,
	sharedpolicy.CategoryComplianceSEBI,
	sharedpolicy.CategoryComplianceEUAIAct,
	sharedpolicy.CategoryComplianceMASFEAT,
}, sharedpolicy.AllTextPIICategories()...)

// Prometheus metrics
var (
	promRequestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "axonflow_agent_requests_total",
			Help: "Total number of requests processed by the agent",
		},
		[]string{"status"},
	)
	promRequestDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "axonflow_agent_request_duration_milliseconds",
			Help:    "Request duration in milliseconds",
			Buckets: []float64{1, 2, 5, 10, 20, 50, 100, 200, 500},
		},
		[]string{"type"},
	)
	promPolicyEvaluations = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "axonflow_agent_policy_evaluations_total",
			Help: "Total number of policy evaluations",
		},
	)
	promBlockedRequests = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "axonflow_agent_blocked_requests_total",
			Help: "Total number of blocked requests",
		},
	)
)

func init() {
	// Register Prometheus metrics
	prometheus.MustRegister(promRequestsTotal)
	prometheus.MustRegister(promRequestDuration)
	prometheus.MustRegister(promPolicyEvaluations)
	prometheus.MustRegister(promBlockedRequests)
}

// AgentMetrics tracks real performance metrics
type AgentMetrics struct {
	mu sync.RWMutex

	// Request counters
	totalRequests   int64
	successRequests int64
	failedRequests  int64
	blockedRequests int64

	// Latency tracking (in nanoseconds)
	latencies     []int64
	lastLatencies []int64 // Keep last 1000 for P99 calculation

	// Throughput
	startTime     time.Time
	lastResetTime time.Time

	// Policy evaluation metrics (end-to-end by policy type)
	staticPolicyLatencies  []int64
	dynamicPolicyLatencies []int64

	// Per-stage timing metrics (in milliseconds)
	authTimings         []int64 // Client + user validation + tenant check
	staticPolicyTimings []int64 // Static policy evaluation only
	networkTimings      []int64 // Agent → Orchestrator network time

	// Request type breakdown (for detailed analysis)
	requestTypeCounters map[string]*RequestTypeMetrics

	// Connector-specific metrics
	connectorMetrics map[string]*ConnectorMetrics

	// Error tracking for error rate calculation
	errorTimestamps []time.Time // Track recent error timestamps for rate calculation

	// Health status tracking
	healthCheckPassed bool
	consecutiveErrors int64
}

// RequestTypeMetrics tracks metrics per request type (sql, llm_chat, rag_search, mcp-query)
type RequestTypeMetrics struct {
	TotalRequests   int64
	SuccessRequests int64
	FailedRequests  int64
	BlockedRequests int64
	Latencies       []int64 // Last 1000 latencies in ms
}

// ConnectorMetrics tracks metrics per MCP connector
type ConnectorMetrics struct {
	ConnectorName   string
	TotalRequests   int64
	SuccessRequests int64
	FailedRequests  int64
	Latencies       []int64 // Last 1000 latencies in ms
	LastError       string
	LastErrorTime   time.Time
}

// Global metrics instance
var agentMetrics *AgentMetrics

// Client request structures
type ClientRequest struct {
	Query       string                 `json:"query"`
	UserToken   string                 `json:"user_token"`
	ClientID    string                 `json:"client_id"`
	RequestType string                 `json:"request_type"`       // "sql", "llm_chat", "rag_search"
	SkipLLM     bool                   `json:"skip_llm,omitempty"` // Skip LLM calls for hourly tests
	Context     map[string]interface{} `json:"context"`
	PlanID      string                 `json:"plan_id,omitempty"` // For execute-plan requests
	Media       []MediaContentRequest  `json:"media,omitempty"`   // Optional media (images) for multimodal governance
}

// MediaContentRequest represents a media item in the client API request.
type MediaContentRequest struct {
	Source     string `json:"source"`                // "base64" or "url"
	Base64Data string `json:"base64_data,omitempty"` // Base64-encoded image data
	URL        string `json:"url,omitempty"`         // Image URL
	MIMEType   string `json:"mime_type"`             // e.g., "image/jpeg"
}

type ClientResponse struct {
	Success     bool                   `json:"success"`
	Data        interface{}            `json:"data,omitempty"`
	Result      string                 `json:"result,omitempty"`   // For multi-agent planning - MUST match SDK type
	PlanID      string                 `json:"plan_id,omitempty"`  // For multi-agent planning
	Steps       []interface{}          `json:"steps,omitempty"`    // For multi-agent planning - workflow steps
	Metadata    map[string]interface{} `json:"metadata,omitempty"` // For multi-agent planning - MUST match SDK type
	Error       string                 `json:"error,omitempty"`
	Blocked     bool                   `json:"blocked"`
	BlockReason string                 `json:"block_reason,omitempty"`
	// ApprovalRequestID is the hitl_approval_queue entry raised for a request
	// this response is holding for human review (#3509). Present only on a
	// require_approval hold, and only when the entry was actually created: an
	// empty value on a held response means no reviewer will see the request
	// (pending cap reached, tier without the queue, or a failed write), and a
	// caller must treat it as a refusal rather than as something pending.
	//
	// It is a SEPARATE field rather than an addition to block_reason precisely
	// because every shipped SDK matches the "require_approval" sentinel
	// literally to enter its HITL branch.
	ApprovalRequestID string                `json:"approval_request_id,omitempty"`
	PolicyInfo        *PolicyEvaluationInfo `json:"policy_info,omitempty"`
	BudgetInfo        *BudgetInfo           `json:"budget_info,omitempty"`    // Issue #1082: Budget enforcement status
	MediaAnalysis     interface{}           `json:"media_analysis,omitempty"` // Media governance analysis results
}

type PolicyEvaluationInfo struct {
	// MatchedPolicies lists the IDs of policies that matched the request.
	// This is the canonical field and what callers should consume going forward.
	MatchedPolicies []string `json:"matched_policies"`
	// PoliciesEvaluated is a backward-compatibility alias that emits the same
	// list under the historical (mislabeled) field name. The original name
	// suggested "every policy the engine ran against the input", but the
	// value has always been the matched-policies list. Keep it populated for
	// existing SDK / dashboard consumers; new code should read MatchedPolicies.
	// TODO(deprecation): drop this on the next major release.
	PoliciesEvaluated []string `json:"policies_evaluated"`
	StaticChecks      []string `json:"static_checks"`
	ProcessingTime    string   `json:"processing_time"`
	TenantID          string   `json:"tenant_id"`
	// CodeArtifact contains metadata about detected code in LLM responses
	// Part of Issue #761: Governed Code Generation
	CodeArtifact *CodeArtifactMetadata `json:"code_artifact,omitempty"`
}

// User represents authenticated user information.
//
// v9 Phase 8 #2384 PR-C1: OrgID is the multi-tenant scope key needed by
// RLS-aware downstream writes (policy_metrics, policy_violations,
// agent_audit_logs). Populated alongside TenantID by the authenticate
// middleware.
type User struct {
	ID          int      `json:"id"`
	Email       string   `json:"email"`
	Name        string   `json:"name"`
	Department  string   `json:"department"`
	Role        string   `json:"role"`
	Region      string   `json:"region"`
	Permissions []string `json:"permissions"`
	TenantID    string   `json:"tenant_id"`
	OrgID       string   `json:"org_id"`
}

// recordLatency adds a latency measurement to the appropriate buckets
func (m *AgentMetrics) recordLatency(latencyMs int64, policyType string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Add to general latencies (for overall P99 calculation)
	m.latencies = append(m.latencies, latencyMs)

	// Keep only last 1000 entries for P99 calculation
	if len(m.lastLatencies) >= 1000 {
		m.lastLatencies = m.lastLatencies[1:]
	}
	m.lastLatencies = append(m.lastLatencies, latencyMs)

	// Add to policy-type specific latencies
	switch policyType {
	case "static":
		if len(m.staticPolicyLatencies) >= 1000 {
			m.staticPolicyLatencies = m.staticPolicyLatencies[1:]
		}
		m.staticPolicyLatencies = append(m.staticPolicyLatencies, latencyMs)
	case "dynamic":
		if len(m.dynamicPolicyLatencies) >= 1000 {
			m.dynamicPolicyLatencies = m.dynamicPolicyLatencies[1:]
		}
		m.dynamicPolicyLatencies = append(m.dynamicPolicyLatencies, latencyMs)
	}
}

// Client represents an authenticated client.
//
// v9 identity model (ADR-052):
//   - OrgID    — customer/account organization identity (RLS boundary).
//   - ClientID — authenticated API credential/app identity. Always equal
//     to ID during the v9 window; carried as a separate field so the
//     codebase can converge on the v9 name without a rename diff.
//   - TenantID — v9 compatibility alias. For the Enterprise whitelist
//     and DB-backed paths it carries the legacy hardcoded scope tag
//     (e.g. "healthcare_tenant") rather than the credential identity;
//     Phase 1/2 of Epic #2230 classifies each remaining row.
type Client struct {
	ID            string    `json:"id"` // Client identifier (from Basic auth username)
	Name          string    `json:"name"`
	OrgID         string    `json:"org_id"`    // Organization ID from license (entitlement scope)
	ClientID      string    `json:"client_id"` // v9 alias of ID; set by every auth path
	TenantID      string    `json:"tenant_id"` // v9 compatibility alias — see struct comment
	Permissions   []string  `json:"permissions"`
	RateLimit     int       `json:"rate_limit"`
	Enabled       bool      `json:"enabled"`
	LicenseTier   string    `json:"license_tier,omitempty"`
	LicenseExpiry time.Time `json:"license_expiry,omitempty"`
	APIKeyID      string    `json:"api_key_id,omitempty"`   // For Option 3 usage tracking
	ServiceName   string    `json:"service_name,omitempty"` // For V2 service licenses

	// ADR-050 §4: per-request client identity captured from the X-Axonflow-Client
	// header on community-saas auth. Empty when the caller didn't set the header
	// (defaults to "full" scope per the ADR). Surfaced for telemetry + future
	// per-client policy gates.
	ClientHeader string `json:"client_header,omitempty"`
	Scope        string `json:"scope,omitempty"` // derived from ClientHeader (plugin/sdk/full)

	// EffectiveTier is the per-tenant SaaS Plugin tier resolved inline by
	// `validateCommunitySaasAuth` (per ADR-049 §3 + ADR-050 §9 Pattern B):
	// the tenant's tier scales WITHIN the deployment ceiling. Free baseline
	// when no X-License-Token header is presented; promotes to the row's
	// tier (Pro / Premium) when a valid token + matching plugin_user_licenses
	// row are present. Self-hosted callers leave this empty — they read the
	// process-wide tier via `license.GetCurrentTier(ctx)`. Downstream
	// handlers that need tenant-scoped limits (audit retention, daily
	// quota, capability gates) read EffectiveTier and call
	// `license.GetTierLimits(EffectiveTier)`.
	EffectiveTier string `json:"effective_tier,omitempty"`
}

// substituteGrafanaPassword substitutes {{GRAFANA_PASSWORD}} in SQL.
// Returns empty string if migration should be skipped (Grafana not deployed).
func substituteGrafanaPassword(sqlContent string) (string, error) {
	if !strings.Contains(sqlContent, "{{GRAFANA_PASSWORD}}") {
		return sqlContent, nil
	}
	password := os.Getenv("GRAFANA_PASSWORD")
	if password == "" || password == "not-deployed" {
		return "", nil // skip migration
	}
	if len(password) < 16 {
		return "", fmt.Errorf("GRAFANA_PASSWORD too short (%d chars, need 16+)", len(password))
	}
	return strings.ReplaceAll(sqlContent, "{{GRAFANA_PASSWORD}}", password), nil
}

// Application readiness state for health checks
// This allows the health endpoint to respond immediately while initialization happens
var appReady atomic.Bool

// licenseTier is captured at license-validation time and surfaced in
// /health so operators (and the setup-e2e-testing script's `jq .tier`
// check) can distinguish Community / Evaluation / Professional /
// Enterprise without hitting a separate license endpoint. Empty string
// means "license not yet validated" (startup phase) or "community
// build" (no license required).
var licenseTier atomic.Value // string

// Global router and server - allows health checks to pass immediately while initialization happens
var (
	globalRouter *mux.Router
	globalCORS   *cors.Cors
)

// initServerImmediately starts the HTTP server immediately with just /health endpoint.
// This allows ECS/ALB health checks to pass during the potentially slow initialization
// phase (database connections, migrations, Redis, etc.). Other routes are added
// after initialization completes. The server NEVER shuts down - eliminating any
// transition gaps that could cause health check failures.
func initServerImmediately(port string) {
	globalRouter = mux.NewRouter()

	// JSON-only error responses for unmatched routes / wrong methods. gorilla/
	// mux's default 404/405 emit Go's plaintext "404 page not found" /
	// "Method Not Allowed". Some MCP clients (Claude Code), after a 401 on the
	// MCP endpoint, probe an open-ended set of OAuth-discovery URLs and parse
	// each non-2xx body as an OAuth error JSON — a plaintext body makes them
	// crash with "HTTP 404: Invalid OAuth error response ... Raw body: 404
	// page not found" and mark the server failed. Returning a parseable,
	// RFC 6749 §5.2-shaped JSON body everywhere makes those probes degrade
	// gracefully instead. (The /.well-known/oauth-* routes registered with the
	// MCP handler return a more specific advisory naming AXONFLOW_AUTH.)
	globalRouter.NotFoundHandler = http.HandlerFunc(jsonNotFoundHandler)
	globalRouter.MethodNotAllowedHandler = http.HandlerFunc(jsonMethodNotAllowedHandler)

	// CORS middleware - configured once, used for all requests.
	// #3096: the origin policy is resolved from configuration rather than
	// hardcoded to `"*"` + AllowCredentials. See resolveCORSOptions (cors.go).
	globalCORS = cors.New(resolveCORSOptions())

	// Register health check immediately - responds even during initialization
	globalRouter.HandleFunc("/health", readinessAwareHealthHandler).Methods("GET")

	// Start server immediately in goroutine - health checks will pass right away
	go func() {
		handler := globalCORS.Handler(globalRouter)
		log.Printf("🚀 AxonFlow Agent starting on port %s (status: starting)", port)
		if err := http.ListenAndServe(":"+port, handler); err != nil {
			log.Fatalf("Server error: %v", err)
		}
	}()

	// Small delay to ensure server is ready to accept connections
	time.Sleep(50 * time.Millisecond)
	log.Println("✅ Health endpoint ready - initialization can proceed safely")
}

// jsonNotFoundHandler / jsonMethodNotAllowedHandler replace gorilla/mux's
// plaintext defaults so every unmatched route / wrong method returns a
// parseable, RFC 6749 §5.2-shaped JSON body. This keeps MCP-client OAuth
// discovery probes (which parse non-2xx bodies as OAuth errors) from crashing
// on plaintext — see initServerImmediately for the full rationale.
func jsonNotFoundHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotFound)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":             "not_found",
		"error_description": "No such endpoint on the AxonFlow agent. If you are an MCP client doing OAuth discovery: this server uses HTTP Basic auth (base64(org_id:license_key)) via AXONFLOW_AUTH, not OAuth.",
	})
}

func jsonMethodNotAllowedHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusMethodNotAllowed)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":             "method_not_allowed",
		"error_description": "HTTP method not allowed on this AxonFlow endpoint.",
	})
}

// readinessAwareHealthHandler returns health status based on initialization state
func readinessAwareHealthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	status := "starting"
	if appReady.Load() {
		status = "healthy"
	}
	if err := json.NewEncoder(w).Encode(map[string]interface{}{
		"status":               status,
		"service":              "axonflow-agent",
		"tier":                 currentLicenseTier(),
		"timestamp":            time.Now().UTC(),
		"version":              GetPlatformVersion(),
		"capabilities":         getCapabilities(),
		"sdk_compatibility":    getSDKCompatibility(),
		"plugin_compatibility": getPluginCompatibility(),
	}); err != nil {
		log.Printf("Error encoding health response: %v", err)
	}
}

// currentLicenseTier returns the tier captured at license validation, or
// "community" for builds that ran without a license (community mode).
// Safe to call before initialization — returns "starting".
func currentLicenseTier() string {
	v := licenseTier.Load()
	if v == nil {
		if appReady.Load() {
			return "community"
		}
		return "starting"
	}
	if s, ok := v.(string); ok && s != "" {
		return s
	}
	return "community"
}

// Run is the exported entry point for the agent service.
//
// Testing Note: This function is currently at 0% test coverage because it:
// 1. Calls log.Fatal() which exits the process (untestable)
// 2. Calls http.ListenAndServe() which blocks forever (untestable)
// 3. Has hard-coded dependencies (env vars, file paths, network calls)
// 4. Performs 10+ different operations (license, migrations, DB, Redis, HTTP server)
//
// To make this testable, it should be refactored to:
// - Extract initialization logic into NewApp(config) (*App, error)
// - Extract server logic into app.Run() error
// - Use dependency injection for all external dependencies
// - Return errors instead of calling log.Fatal()
//
// Refactoring planned for Phase 5 (Open Source Preparation).
// Current architecture is functional but not ideal for testing.
func Run() {
	// Start server IMMEDIATELY with /health endpoint so ECS/ALB health checks pass
	// during initialization. Other routes are added after initialization completes.
	// The server NEVER shuts down - eliminating transition gaps.
	port := getEnv("PORT", "8080")

	// #3068: mint the internal-service signing key BEFORE the server starts
	// accepting requests. /api/request → forwardToOrchestrator is registered
	// long before NewReverseProxyHandler used to initialize this, so any
	// request landing in that window would reach the orchestrator without a
	// proxy-auth token and now be refused. Doing it here also means the
	// package-level generator is written once, before any request goroutine
	// exists, so there is no concurrent read/write on it.
	InitProxyTokenGenerator()

	// #3509: validate AXONFLOW_HITL_GRANT_TTL_SECONDS before anything can serve
	// a request. Deliberately here and not inside the HITL wiring block further
	// down: that block sits behind the DB-connected branch, so an operator who
	// set the value and then hit a database problem would boot with the flag
	// unvalidated. This value decides how long an approved human-oversight
	// decision stays spendable, and guessing at it either way is invisible
	// afterwards.
	hitlGrantTTLOrFatal()

	initServerImmediately(port)

	// License validation (optional for central agent deployments and community mode)
	// Central agents validate CLIENT license keys during request processing
	// Community mode skips license validation entirely (for local development)
	// This validation is only needed for customer-deployed agents
	licenseKey := os.Getenv("AXONFLOW_LICENSE_KEY")

	// Capture the validated license tier/limits so the post-migration step can
	// sync them into the deployment org's organizations.tier row (#2535). The
	// agent surfaces the tier in-memory at /health, but the portal, node-limit
	// enforcement, and compliance-evidence paths all read organizations.tier
	// from the DB — which migration 094 seeds 'Community' and never promotes.
	// licenseValidated stays false in community / community-saas / central-
	// agent (no key) modes, which skip the DB promotion below.
	var (
		licenseValidated  bool
		licensedTier      string
		licensedMaxNodes  int
		licensedExpiresAt time.Time
	)

	if isCommunityMode() {
		log.Println("🏠 Community mode - skipping license validation")
		log.Println("   Perfect for Community contributors and local development")
	} else if isCommunitySaasMode() {
		log.Println("🌐 Community SaaS mode — shared evaluation server (try.getaxonflow.com)")
		log.Println("   Tenants self-register at POST /api/v1/register")
		log.Println("   LLM: Ollama only. Rate limits: enforced. No license required.")
		log.Println("   No SLA, no security guarantee, 30-day data retention.")
	} else if licenseKey == "" {
		log.Println("⚠️  AXONFLOW_LICENSE_KEY not set - running in central agent mode")
		log.Println("   Central agents validate client license keys during request processing")
	} else {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		result, err := license.ValidateWithRetry(ctx, licenseKey, 3)
		if err != nil {
			log.Fatalf("License validation failed: %v", err)
		}

		if !result.Valid {
			log.Fatalf("Invalid license: %s (error: %s)", result.Message, result.Error)
		}

		// Validate license org_id matches deployment ORG_ID.
		// ORG_ID is the canonical deployment identity (set in docker-compose/env).
		// License org_id must match — mismatch means data will split across orgs.
		deploymentOrgID := getDeploymentOrgID()
		if result.OrgID != "" && result.OrgID != deploymentOrgID {
			log.Fatalf("❌ License org_id mismatch: license has org_id=%q but deployment ORG_ID=%q. "+
				"These must match or data will be split across organizations. "+
				"Either update ORG_ID in your docker-compose/env to match the license, "+
				"or request a new license with org_id=%q.",
				result.OrgID, deploymentOrgID, deploymentOrgID)
		}

		log.Printf("✅ License validated successfully")
		log.Printf("   Tier: %s", result.Tier)
		licenseTier.Store(string(result.Tier))
		log.Printf("   Org: %s", deploymentOrgID)
		log.Printf("   Max Nodes: %d", result.MaxNodes)
		log.Printf("   Expires: %s", result.ExpiresAt.Format("2006-01-02"))

		// Hand the licensed tier/limits to the post-migration DB sync (#2535).
		licensedTier = string(result.Tier)
		licensedMaxNodes = result.MaxNodes
		licensedExpiresAt = result.ExpiresAt
		licenseValidated = true

		if result.DaysUntilExpiry <= 3 && result.DaysUntilExpiry > 0 {
			log.Printf("   ⚠️  LICENSE EXPIRING IN %d DAYS — renew at https://getaxonflow.com/evaluation-license", result.DaysUntilExpiry)
		} else if result.DaysUntilExpiry <= 30 {
			log.Printf("   ⚠️  License expires in %d days - contact sales for renewal", result.DaysUntilExpiry)
		}
	}

	// Initialize metrics with all tracking structures
	agentMetrics = &AgentMetrics{
		lastLatencies:          make([]int64, 0, 1000),
		staticPolicyLatencies:  make([]int64, 0, 1000),
		dynamicPolicyLatencies: make([]int64, 0, 1000),
		authTimings:            make([]int64, 0, 1000),
		staticPolicyTimings:    make([]int64, 0, 1000),
		networkTimings:         make([]int64, 0, 1000),
		requestTypeCounters:    make(map[string]*RequestTypeMetrics),
		connectorMetrics:       make(map[string]*ConnectorMetrics),
		errorTimestamps:        make([]time.Time, 0, 1000),
		startTime:              time.Now(),
		lastResetTime:          time.Now(),
		healthCheckPassed:      true,
	}
	// Note: mu (sync.RWMutex) is automatically initialized to zero value (unlocked state)

	// Run database migrations first (Principle 11: Proper setup before operations)
	// Build connection string from separate env vars (12-Factor App methodology)
	// URI format requires URL encoding for password with special characters
	dbHost := os.Getenv("DATABASE_HOST")
	dbPort := os.Getenv("DATABASE_PORT")
	dbName := os.Getenv("DATABASE_NAME")
	dbUser := os.Getenv("DATABASE_USER")
	dbPassword := os.Getenv("DATABASE_PASSWORD")
	dbSSLMode := os.Getenv("DATABASE_SSLMODE")

	// Fallback: Support legacy DATABASE_URL for backward compatibility
	dbURL := os.Getenv("DATABASE_URL")
	if dbHost != "" && dbPassword != "" {
		// Build connection string with URL-encoded password for URI format
		if dbPort == "" {
			dbPort = "5432"
		}
		if dbName == "" {
			dbName = "axonflow"
		}
		if dbUser == "" {
			dbUser = "axonflow_app"
		}
		if dbSSLMode == "" {
			dbSSLMode = "require"
		}
		// URL-encode password to handle special characters in URI format
		dbURL = fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=%s",
			url.QueryEscape(dbUser), url.QueryEscape(dbPassword), dbHost, dbPort, dbName, dbSSLMode)
		log.Println("✅ Built database connection string from separate env vars (12-Factor App)")
	}

	if dbURL != "" {

		log.Println("Running database migrations...")
		// /app/migrations/ is the Docker-mount default. AXONFLOW_MIGRATIONS_PATH
		// overrides it so runtime-e2e tests can exercise the real runner
		// against a temp copy of migrations/ without needing /app/ on disk.
		// Production deployments leave the env var unset and pick up the
		// container's mount.
		migrationsPath := os.Getenv("AXONFLOW_MIGRATIONS_PATH")
		if migrationsPath == "" {
			migrationsPath = "/app/migrations/"
		}

		// Multi-path migration collection (ADR-012)
		// Collects migrations from core/, enterprise/, industry/* based on DEPLOYMENT_MODE
		//
		// A collection failure is FATAL, not a warning. It used to
		// "continue anyway", which then fell through to the len==0 arm
		// and booted with an unmigrated database. Since #3167 the
		// realistic failure is an unrecognised DEPLOYMENT_MODE: the
		// selector refuses to guess a schema rather than applying the
		// widest set, and this is the refusal.
		migrations, err := collectMigrations(migrationsPath)
		if err != nil {
			log.Fatalf("❌ Cannot determine which database migrations to apply: %v", err)
		} else if len(migrations) == 0 {
			log.Println("ℹ️  No migration files found")
		} else {
			// Validate migration dependencies before running
			if err := validateMigrationDependencies(migrations); err != nil {
				log.Fatalf("❌ Migration dependency validation failed: %v", err)
			}

			// Connect to database for migrations with retry logic
			// Retry is needed because Docker DNS (127.0.0.11:53) takes a few seconds to initialize
			// after container startup. Without retry, RDS hostname resolution fails immediately.
			maxRetries := 5
			var migrationDB *sql.DB
			var err error

			for attempt := 1; attempt <= maxRetries; attempt++ {
				migrationDB, err = openMigrationDB(dbURL)
				if err == nil {
					// Test connection with ping
					err = migrationDB.Ping()
					if err == nil {
						log.Printf("✅ Connected to database for migrations (attempt %d/%d)", attempt, maxRetries)
						break
					}
				}

				// Connection or ping failed
				if attempt < maxRetries {
					backoff := time.Duration(attempt*2) * time.Second
					log.Printf("⚠️  Database connection failed (attempt %d/%d): %v", attempt, maxRetries, err)
					log.Printf("   Retrying in %v... (Docker DNS may still be initializing)", backoff)
					time.Sleep(backoff)
				}
			}

			if err != nil {
				log.Printf("❌ Failed to connect to database after %d attempts: %v", maxRetries, err)
				log.Fatalf("Database migrations failed. Exiting to prevent incomplete setup.")
			}

			defer func() { _ = migrationDB.Close() }()

			// Ensure schema_migrations table exists (run migration 020 first if needed)
			ensureSchemaMigrationsTable(migrationDB)

			// Set Postgres session variables that downstream migration SQL
			// reads via current_setting(): app.db_password (migration 017
			// dblink_exec) + app.deployment_org_id (migration 094 Pass-2
			// org_id backfill) + app.deployment_kind (migration 094 prod-
			// safety precondition, #2320). Extracted to
			// setMigrationSessionVars so the wiring is unit-testable; the
			// inline form was untested for years and the v9 Pass-2 backfill
			// regressed on it (Epic #2230 Follow-up A).
			setMigrationSessionVars(migrationDB, dbPassword, getDeploymentOrgID(), getDeploymentKind())

			// Get list of applied migrations (keyed by composite version/name).
			// See migrations/core/096_schema_migrations_dedup_composite.sql
			// for why we cannot dedup on version alone — files like
			// 025_decision_chain.sql + 025_hitl_oversight_queue.sql share
			// the version prefix and must be tracked independently.
			appliedMigrations := getAppliedMigrations(migrationDB)

			successCount := 0
			skippedCount := 0
			for _, migration := range migrations {
				filename := filepath.Base(migration.Path)

				// Skip if already applied (composite version/name key)
				if appliedMigrations[migrationKey(migration.Version, migration.Name)] {
					log.Printf("⏭️  Migration %s [%s] already applied (skipping)", filename, migration.Category)
					skippedCount++
					continue
				}

				// Read migration file
				sqlBytes, err := os.ReadFile(migration.Path)
				if err != nil {
					log.Printf("⚠️  Failed to read migration %s: %v", filename, err)
					continue
				}

				// Substitute GRAFANA_PASSWORD for migration 107 (grafana_database)
				sqlContent, err := substituteGrafanaPassword(string(sqlBytes))
				if err != nil {
					log.Fatalf("Migration %s failed: %v", filename, err)
				}
				if sqlContent == "" {
					log.Printf("⚠️  Skipping %s (Grafana not deployed)", filename)
					skippedCount++
					continue
				}

				// Execute migration (not in transaction to allow migrations to manage their own transactions)
				startTime := time.Now()
				_, err = migrationDB.Exec(sqlContent)
				executionTimeMs := int(time.Since(startTime).Milliseconds())

				if err != nil {
					// Record failure
					recordMigrationFailure(migrationDB, migration.Version, filename, err, executionTimeMs)

					// Fail immediately on migration error (Principle 3: No Silent Failures)
					log.Printf("❌ Migration %s [%s] FAILED: %v", filename, migration.Category, err)
					log.Fatalf("Database migrations failed. Exiting to prevent incomplete setup.")
				}

				// Record success
				recordMigrationSuccess(migrationDB, migration.Version, filename, executionTimeMs)
				log.Printf("✅ Migration %s [%s] applied successfully (%dms)", filename, migration.Category, executionTimeMs)
				successCount++
			}

			log.Printf("✅ Database migrations completed: %d applied, %d skipped, %d total", successCount, skippedCount, len(migrations))

			// #2535: sync the validated license tier into the deployment org's
			// organizations.tier row. Runs here — after migrations, on the
			// migrationDB connection on which the mig-117 helper was just
			// defined. The org_id is passed to the helper explicitly (it does
			// NOT read app.deployment_org_id), so this does not depend on which
			// pooled connection set_config landed on. The promotion goes through
			// the SECURITY DEFINER helper promote_deployment_org_license (a
			// SELECT, executed as the function owner) so the write is RLS-safe
			// under AXONFLOW_DB_USE_APP_ROLE rather than a raw INSERT/UPDATE that
			// FORCE RLS on organizations (mig 103) would reject. No-op in
			// community / central-agent modes (licenseValidated == false).
			if licenseValidated {
				promoteDeploymentOrgTier(migrationDB, getDeploymentOrgID(), licensedTier, licensedMaxNodes, licensedExpiresAt)
			}
		}
	}

	// Initialize database, audit manager, and policy engine.
	// DB mode: full enforcement with DB-loaded policies + DB audit.
	// No-DB mode: engine with nil DB (community fallback) + JSONL audit.
	if dbURL != "" {
		var err error
		bootCtx := context.Background()
		authDB, err = OpenAppRoleConnection(bootCtx, dbURL, 5)
		if err != nil {
			log.Fatalf("Failed to connect to authentication database: %v", err)
		}
		defer func() { _ = authDB.Close() }()

		var connectedRole string
		if err := authDB.QueryRowContext(bootCtx, "SELECT current_user").Scan(&connectedRole); err != nil {
			log.Fatalf("Failed to query current_user on authDB: %v", err)
		}
		log.Printf("✅ authDB connected as current_user=%s (UseAppRoleEnabled=%v, %s=%v)",
			connectedRole, UseAppRoleEnabled(), EnvAppRoleURL, os.Getenv(EnvAppRoleURL) != "")

		usageDB = authDB
		log.Println("✅ Usage metering database connected")

		// #2924 R3: back the decide-plane per-user-token revocation lookup with
		// the mig-135 deny-list over the same app-role pool. Enterprise-only
		// (community NewDBRevocationStore returns ErrEnterpriseOnly → no-op).
		wireUserTokenRevocation(usageDB)

		// #2932: register the fleet/MCP-server per-user token validators NOW —
		// deterministically at startup, with usageDB set above and jwtSecret
		// already initialized from the environment — instead of lazily on the
		// first enterprise MCP request. This closes the silent-disable window
		// where a first request could trip the sync.Once before the wiring was
		// ready, register nothing, and permanently ignore per-user tokens. The
		// per-request ensureFleetValidatorsRegistered() calls remain as
		// idempotent no-ops. Community builds register nothing (constructors
		// return ErrEnterpriseOnly) — a harmless no-op there.
		ensureFleetValidatorsRegistered()

		// Audit manager with DB — writes to Postgres
		initAuditManager(usageDB)
		if auditManager != nil {
			defer func() {
				if err := auditManager.Shutdown(context.Background()); err != nil {
					log.Printf("⚠️ Audit manager shutdown error: %v", err)
				}
			}()
			if recovered, err := auditManager.RecoverEntries(); err != nil {
				log.Printf("⚠️ Failed to recover audit entries: %v", err)
			} else if recovered > 0 {
				log.Printf("✅ Recovered %d audit entries from fallback file", recovered)
			}
		}

		// Tier-aware policy engine (tenant-specific policies from DB)
		tierAwarePolicyEngine = NewTierAwarePolicyEngine(authDB, nil)
		log.Println("✅ Tier-aware policy engine initialized")

		// Per-org detection-action overrides (#2581). Wires the short-TTL cache
		// to authDB so the MCP + gateway check paths can resolve a per-org PII /
		// SQLi / dangerous-* posture on top of the deployment-global env config.
		// No-op in no-DB mode (cache stays nil → global config used everywhere).
		InitDetectionOverrides(authDB)

		// Per-org require_user_token posture (#3476, ADR-060 follow-up). Wires
		// the short-TTL cache to authDB so /decide, the MCP-server plane, and
		// the four MCP REST routes can resolve whether a token-less enterprise
		// caller must be rejected rather than given a synthetic service
		// identity. No-op in no-DB mode (resolution then falls back to the
		// AXONFLOW_REQUIRE_USER_TOKEN env default, unchanged today's behaviour).
		InitRequireUserToken(authDB)

		// Activate integration-specific policies before policy engine init
		// so the shared engine sees enabled rows on first load.
		ActivateIntegrationsFromEnv(usageDB)

		// Shared policy engine with DB — loads policies from database
		var sharedAuditQueue sharedpolicy.AuditQueue
		if auditManager != nil {
			sharedAuditQueue = &SharedPolicyAuditAdapter{queue: auditManager.GetQueue()}
		}
		// #2801: capability-scoping levers (kill switch + Enterprise
		// text-document registry extension) ride the engine config.
		sharedpolicy.SetGlobalEngine(sharedpolicy.NewUnifiedPolicyEngine(authDB, capabilityScopedEngineConfig(), sharedAuditQueue))
		log.Println("✅ Policy enforcement: DB-backed shared engine (with audit)")

		// Cost service for budget enforcement (requires DB)
		costRepo := cost.NewPostgresRepository(authDB)
		costService = cost.NewService(costRepo, nil)
		log.Println("✅ Cost service initialized (budget enforcement enabled)")

		// AWS Marketplace metering (requires DB)
		if os.Getenv("ENABLE_MARKETPLACE_METERING") == "true" {
			productCode := os.Getenv("MARKETPLACE_PRODUCT_CODE")
			if productCode == "" {
				log.Fatal("❌ MARKETPLACE_PRODUCT_CODE required when ENABLE_MARKETPLACE_METERING=true")
			}

			// v9 Brief 11.5 R3-HIGH-3: getActiveNodeCount queries
			// agent_heartbeats CROSS-ORG (no WHERE org_id filter — it counts
			// every active node for the entire deployment for marketplace
			// billing). Under FORCE RLS on agent_heartbeats (mig 107) as
			// axonflow_app_role, this silently returns 0 → undercharging /
			// SoX issue. Route through admin DB if available.
			RequirePlatformAdminOrFatal("Marketplace")
			meteringDB := authDB
			adminDB, adminErr := OpenPlatformAdminConnection(context.Background(), 3)
			// #3159: the guard above only checks the DSN string is set. A DSN
			// that yields no pool used to land in the WARNING branch below and
			// meter on the RLS-blind pool — 0 nodes, undercharge.
			RequirePlatformAdminPoolOrFatal("Marketplace", adminDB, adminErr)
			if adminErr != nil {
				log.Printf("[Marketplace] failed to open admin connection (%v); falling back to authDB", adminErr)
			} else if adminDB != nil {
				log.Println("[Marketplace] using axonflow_platform_admin (BYPASSRLS) connection for cross-org node-count metering")
				meteringDB = adminDB
			} else {
				log.Printf("[Marketplace] WARNING: AXONFLOW_DB_PLATFORM_ADMIN_URL not set; falling back to authDB. Under FORCE RLS as app_role, metering reports 0 nodes — undercharge / SoX risk.")
			}
			var mErr error
			meteringService, mErr = marketplace.NewMeteringService(meteringDB, productCode)
			if mErr != nil {
				log.Fatalf("❌ Failed to create AWS Marketplace metering service: %v", mErr)
			}

			ctx := context.Background()
			if mErr := meteringService.Start(ctx); mErr != nil {
				log.Printf("⚠️  Failed to start AWS Marketplace metering: %v", mErr)
			} else {
				log.Println("✅ AWS Marketplace metering service started")
			}
		}
	} else {
		// AxonFlow requires PostgreSQL for policy enforcement, audit logging,
		// and execution tracking. Without a database, the platform cannot
		// provide governance guarantees. Refuse to start.
		log.Fatal("❌ DATABASE_URL is required. AxonFlow requires PostgreSQL for policy enforcement, " +
			"audit logging, and execution tracking. Set DATABASE_URL or use 'docker compose up -d' " +
			"which includes PostgreSQL. See: https://docs.getaxonflow.com/docs/deployment/quickstart")
	}

	// DB-independent initializations (work in both DB and no-DB mode)
	sharedpolicy.InitGlobalExfiltrationChecker()
	exfilLimits := sharedpolicy.GetGlobalExfiltrationChecker().GetLimits()
	log.Printf("✅ Exfiltration checker initialized (enabled=%v, maxRows=%d, maxBytes=%d)",
		exfilLimits.Enabled, exfilLimits.MaxRowsPerQuery, exfilLimits.MaxBytesPerQuery)

	sharedpolicy.InitGlobalDynamicPolicyEvaluator()
	sharedpolicy.SetGlobalOrchestratorEndpoint(getOrchestratorURL())
	dynamicEval := sharedpolicy.GetGlobalDynamicPolicyEvaluator()
	if dynamicEval != nil {
		config := dynamicEval.GetConfig()
		log.Printf("✅ Dynamic policy evaluator initialized (enabled=%v, endpoint=%s, graceful=%v)",
			config.Enabled, config.OrchestratorEndpoint, config.GracefulDegradation)
	}

	InitDetectionConfigs()
	log.Println("✅ Detection configs cached (MCP + Gateway static policy settings)")

	// Redis rate limiting (works without DB)
	redisURL := os.Getenv("REDIS_URL")
	if redisURL != "" {
		if err := initRedis(redisURL); err != nil {
			log.Printf("Warning: Failed to initialize Redis: %v", err)
			log.Println("Falling back to in-memory rate limiting")
		} else {
			log.Println("✅ Redis rate limiting enabled")
			defer func() {
				if err := closeRedis(); err != nil {
					log.Printf("Error closing Redis: %v", err)
				}
			}()
		}
	} else {
		log.Println("ℹ️  REDIS_URL not set - using in-memory rate limiting")
	}

	// Initialize node enforcement (heartbeat + monitoring)
	var heartbeatService *node_enforcement.HeartbeatService
	var nodeMonitor *node_enforcement.NodeMonitor
	if usageDB != nil {
		// Determine instance type
		instanceType := "agent"

		// Extract orgID from environment (for customer-deployed agents)
		// In central mode, this will be empty and heartbeats won't be recorded
		// In customer mode, ORG_ID must be set to enable node enforcement
		orgID := os.Getenv("ORG_ID")
		if orgID == "" {
			// Central agent mode - skip heartbeat (agents don't have their own orgID)
			log.Println("ℹ️  ORG_ID not set - skipping node enforcement (central agent mode)")
		} else {
			// Customer-deployed agent mode - enable heartbeat
			// Note: licenseKey may be empty for testing, but should be set in production
			heartbeatService = node_enforcement.NewHeartbeatService(
				usageDB,
				instanceType,
				licenseKey,
				orgID,
			)

			// Start heartbeat service
			ctx := context.Background()
			if err := heartbeatService.Start(ctx); err != nil {
				log.Printf("⚠️  Failed to start heartbeat service: %v", err)
			} else {
				log.Println("✅ Heartbeat service started")
			}

			// Initialize node monitor (only if explicitly enabled).
			//
			// v9 Phase 8 (#2305 Brief 11.5, Item 2): NodeMonitor iterates
			// across orgs (checkAllNodeCounts uses GetActiveNodesByOrg's
			// GROUP BY org_id). Under FORCE RLS on agent_heartbeats (mig
			// 107) as axonflow_app_role, cross-org SELECT silently returns
			// 0 rows. Open admin (BYPASSRLS) connection if configured;
			// fall back to usageDB for legacy deployments.
			if os.Getenv("ENABLE_NODE_MONITOR") == "true" {
				RequirePlatformAdminOrFatal("NodeMonitor")
				alerter := node_enforcement.NewMultiChannelAlerter()
				monitorDB := usageDB
				adminDB, adminErr := OpenPlatformAdminConnection(ctx, 3)
				// #3159: a configured-but-unusable admin DSN previously fell
				// through to usageDB, where the cross-org node count reads 0.
				RequirePlatformAdminPoolOrFatal("NodeMonitor", adminDB, adminErr)
				if adminErr != nil {
					log.Printf("[NodeMonitor] failed to open admin connection (%v); falling back to usageDB", adminErr)
				} else if adminDB != nil {
					log.Println("[NodeMonitor] using axonflow_platform_admin (BYPASSRLS) connection for cross-org node counts")
					monitorDB = adminDB
				} else {
					log.Println("[NodeMonitor] WARNING: AXONFLOW_DB_PLATFORM_ADMIN_URL not set; falling back to usageDB. Under FORCE RLS as app_role, NodeMonitor will not observe cross-org rows.")
				}
				nodeMonitor = node_enforcement.NewNodeMonitor(monitorDB, alerter)
				nodeMonitor.Start(ctx)
				log.Println("✅ Node monitoring started")
			}
		}
	}

	// Cleanup services on shutdown
	if heartbeatService != nil {
		defer heartbeatService.Stop()
	}
	if nodeMonitor != nil {
		defer nodeMonitor.Stop()
	}
	if meteringService != nil {
		defer meteringService.Stop()
	}

	// Initialize MCP connector registry (ADR-007: three-tier configuration)
	// Configuration priority: Database > Config File (AXONFLOW_CONFIG_FILE) > Environment Variables
	if configFile := os.Getenv("AXONFLOW_CONFIG_FILE"); configFile != "" {
		log.Printf("[MCP] Using config file from AXONFLOW_CONFIG_FILE: %s", configFile)
	}
	if err := InitializeMCPRegistryWithDB(authDB); err != nil {
		log.Printf("Warning: Failed to initialize MCP registry: %v", err)
		log.Println("Agent will run without MCP connector support")
	} else {
		log.Println("AxonFlow Agent initialized with MCP connector support")
		// Ensure connectors are properly disconnected on shutdown
		defer func() {
			if mcpRegistry != nil {
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				mcpRegistry.DisconnectAll(ctx)
			}
		}()
	}

	// Initialize TenantConnectorRegistry for per-tenant connector management (ADR-007)
	// This provides dynamic connector loading with three-tier configuration:
	// Database > Config File > Environment Variables
	tenantConnectorEnabled := os.Getenv("TENANT_CONNECTOR_REGISTRY_ENABLED") != "false"
	if tenantConnectorEnabled {
		runtimeConfigSvc := GetRuntimeConfigService()
		if runtimeConfigSvc == nil {
			log.Println("Warning: RuntimeConfigService not available, per-tenant connector registry disabled")
			tenantConnectorEnabled = false
		} else {
			connectorFactory := DefaultConnectorFactory()
			tenantRegistry := InitTenantConnectorRegistry(runtimeConfigSvc, connectorFactory)
			if tenantRegistry != nil {
				log.Println("AxonFlow Agent initialized with per-tenant connector registry (ADR-007)")
				// Start periodic cleanup of expired connectors (StartPeriodicCleanup spawns its own goroutine)
				tenantRegistry.StartPeriodicCleanup(context.Background(), 5*time.Minute)
				// Ensure tenant connectors are properly disconnected on shutdown
				defer func() {
					if reg := GetTenantConnectorRegistry(); reg != nil {
						ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
						defer cancel()
						reg.DisconnectAll(ctx)
					}
				}()
			}
		}
	} else {
		log.Println("Per-tenant connector registry disabled via TENANT_CONNECTOR_REGISTRY_ENABLED=false")
	}

	// Community-SaaS inactivity sweep (ADR-048): daily background job that
	// terminates tenants idle for >3 months or past the 1-year hard cap, with
	// cascade-delete of tenant-scoped data. Opt-in per deploy via
	// COMMUNITY_SAAS_SWEEP_ENABLED=true. Only runs in community-saas mode and
	// only when the license tier is community — see the helper.
	if communitySaasSweepShouldStart() {
		// v9 Phase 8 (#2305 Brief 11.5, Item 2): sweep iterates ACROSS orgs
		// (terminates idle tenants from any org). Under FORCE RLS as
		// axonflow_app_role, cross-org queries return 0 rows. Open admin
		// (BYPASSRLS) connection if AXONFLOW_DB_PLATFORM_ADMIN_URL is set;
		// fall back to authDB (master role) for legacy deployments. The
		// admin DB handle is leaked intentionally — sweep runs for the
		// agent process lifetime; the conn closes on process exit.
		RequirePlatformAdminOrFatal("CSAAS-SWEEP")
		sweepDB := authDB
		adminDB, adminErr := OpenPlatformAdminConnection(context.Background(), 3)
		// #3159: a configured-but-unusable admin DSN previously fell through
		// to authDB, where the cross-org sweep observes no rows at all.
		RequirePlatformAdminPoolOrFatal("CSAAS-SWEEP", adminDB, adminErr)
		if adminErr != nil {
			log.Printf("[CSAAS-SWEEP] failed to open admin connection (%v); falling back to authDB", adminErr)
		} else if adminDB != nil {
			log.Printf("[CSAAS-SWEEP] using axonflow_platform_admin (BYPASSRLS) connection for cross-org sweep")
			sweepDB = adminDB
		} else {
			log.Printf("[CSAAS-SWEEP] WARNING: AXONFLOW_DB_PLATFORM_ADMIN_URL not set; falling back to authDB. Under FORCE RLS as app_role, sweep will not observe cross-org rows.")
		}
		StartCommunitySaasSweep(context.Background(), sweepDB)
	}

	// Register all routes on the global router (server is already running with /health)
	// /health was registered in initServerImmediately() - now add all other routes

	// Metrics endpoint for real performance data (JSON format)
	globalRouter.HandleFunc("/metrics", metricsHandler).Methods("GET")

	// Prometheus metrics endpoint (Prometheus exposition format)
	globalRouter.Handle("/prometheus", promhttp.Handler()).Methods("GET")

	// Main client request endpoint - all requests flow through here
	globalRouter.HandleFunc("/api/request", clientRequestHandler).Methods("POST")

	// Client management endpoints
	globalRouter.Handle("/api/clients", apiAuthMiddleware(http.HandlerFunc(listClientsHandler))).Methods("GET")
	globalRouter.Handle("/api/clients", apiAuthMiddleware(http.HandlerFunc(createClientHandler))).Methods("POST")

	// Policy testing endpoint — protected by auth middleware (tenant from credentials)
	globalRouter.Handle("/api/policies/test", apiAuthMiddleware(http.HandlerFunc(policyTestHandler))).Methods("POST")

	// Register MCP connector endpoints
	RegisterMCPHandlers(globalRouter)

	// Register MCP server protocol endpoint (Claude Code plugin — #1484)
	RegisterMCPServerHandler(globalRouter)

	// Register connector refresh API endpoints (ADR-007)
	// These endpoints allow manual cache invalidation for connector configurations.
	// #3067 (S-6): RegisterConnectorRefreshHandlers now wraps every route in
	// apiAuthMiddleware and binds the tenancy to the authenticated credential,
	// so registering here — ahead of the reverse proxy — no longer leaves an
	// anonymous cache-eviction lever exposed. #2883 is the missing-authentication
	// defect this PR closes, NOT a route-ordering ticket. The registration ORDER
	// relative to the proxy prefix is a separate AVAILABILITY concern tracked as
	// #3102: these exact paths win only because gorilla/mux matches in registration
	// order, and a re-order would 404/405 them via the orchestrator rather than
	// making them anonymous — the gate is applied inside the register function.
	if tenantConnectorEnabled {
		RegisterConnectorRefreshHandlers(globalRouter)
	}

	// Wire the OTel decision tracer (#2426 WS4 / Brief 25-C). Empty
	// AXONFLOW_OTEL_ENDPOINT yields the noop tracer — Community-tier
	// safe, no required infra. Handlers call RecordDecision
	// unconditionally; the noop impl returns "" so SDKs receive an
	// empty trace_id field they can ignore.
	decisionTracerProvider = telemetry.NewDecisionTracer(context.Background())

	// Register Gateway Mode endpoints (pre-check and audit)
	RegisterGatewayHandlers(globalRouter)

	// Register Decision Mode endpoint (POST /api/v1/decide) -- ADR-056 / epic #2426.
	// Same shared-policy engine as Gateway Mode pre-check; surfaced for an
	// infrastructure-gateway caller (PEP) rather than application code.
	//
	// Decision Mode env vars (read at request time, no restart needed for the
	// allowlist since decisionContextAllowlist() reads os env per call):
	//   AXONFLOW_DECISION_EXPIRES_AFTER     — PEP-cache TTL (Go duration; default 5m)
	//   AXONFLOW_DECISION_CONTEXT_ALLOWLIST — comma-separated request-context keys
	//       persisted to the audit JSONB + emitted as request.context.<key> OTel
	//       span attributes. Matching is case/separator-insensitive; a trailing
	//       "*" is a prefix match. Default:
	//       "x-ai-agent,x-session-id,x-leader-identity,x-tenant-*" (#2509).
	RegisterDecisionHandlers(globalRouter)

	// Register OpenAI-compatible gateway endpoint (Issue #2351 / Epic #2360).
	// POST /v1/chat/completions accepts standard OpenAI SDK requests, runs
	// the shared policy engine, forwards to upstream, records audit.
	RegisterOpenAICompatHandlers(globalRouter)

	// Register Static Policy API endpoints (ADR-018: Unified Policy Management)
	// This enables the Customer Portal to list static policies from the Agent
	RegisterStaticPolicyHandlers(globalRouter, usageDB)

	// Register the dev-mode token endpoint (#2541, design §2/§4). FAIL-CLOSED:
	// RegisterDevTokenHandler registers POST /api/v1/dev/token ONLY on an
	// explicit non-production environment; otherwise it leaves the route
	// unregistered (→ 404) and logs the production stance. The minter must
	// never be reachable in production.
	RegisterDevTokenHandler(globalRouter)

	// Wire shared idempotency store (#2420). Opens an admin pool once at
	// boot for the background sweep; nil-tolerant if it fails (sweep no-ops
	// with a louder warning). Lookup/Store run on usageDB (axonflow_app_role)
	// under FORCE RLS wrapped in WithOrgAndTenantScope.
	idempAdminDB, idempAdminErr := OpenPlatformAdminConnection(context.Background(), 3)
	// #3159: an unset DSN keeps the documented nil-tolerant fallback (this site
	// never required the pool). A DSN that IS configured and yields nothing is
	// a misconfiguration, not a posture — the sweep silently stops and
	// idempotency_keys grows unbounded.
	RequirePlatformAdminPoolOrFatal("Idempotency", idempAdminDB, idempAdminErr)
	if idempAdminErr != nil {
		log.Printf("[Idempotency] WARN admin pool unavailable, sweep DISABLED — idempotency_keys table will grow unbounded under USE_APP_ROLE=true: %v", idempAdminErr)
		idempAdminDB = nil
	} else {
		log.Printf("✅ [Idempotency] using axonflow_platform_admin (BYPASSRLS) connection for cross-tenant sweep")
	}
	idempStore := idempotency.NewStore(usageDB, idempAdminDB)
	// Inject the wrap fn into the hitl package so the HITL CreateRequest
	// handler can dedup on Idempotency-Key without a hard import edge.
	hitl.SetIdempotencyWrap(func(w http.ResponseWriter, r *http.Request, orgID, tenantID, endpoint string, next func(http.ResponseWriter, *http.Request)) {
		idempotency.Wrap(w, r, idempStore, orgID, tenantID, endpoint, next)
	})
	// And expose to the MCP check-input handler so the same dedup applies
	// on the /api/v1/mcp/check-input path. Read by mcp_handler.go.
	mcpIdempStore = idempStore
	// Start the sweep ticker. Hourly is fine — TTL is 24h so a single
	// missed tick doesn't bloat the table appreciably.
	if idempAdminDB != nil {
		go func() {
			ticker := time.NewTicker(1 * time.Hour)
			defer ticker.Stop()
			for range ticker.C {
				n, err := idempStore.Sweep(context.Background())
				if err != nil {
					log.Printf("[Idempotency] sweep error: %v", err)
				} else if n > 0 {
					log.Printf("[Idempotency] swept %d expired key(s)", n)
				}
			}
		}()
	}

	// HITL expire ticker — open admin pool once and reuse for the process
	// lifetime. The previous shape (open + close per tick) was wasteful
	// AND silently skipped expirations on transient DB blips. Sister fix:
	// uses ExpireStaleAcrossTenants so the cross-tenant scan fires under
	// FORCE RLS (the legacy ExpireStaleRequests path silently matches zero
	// rows for axonflow_app_role with no GUC set — same bug class as #2400).
	hitlExpireAdminDB, hitlExpireErr := OpenPlatformAdminConnection(context.Background(), 3)
	// #3159: same split. Unset DSN → documented fallback; configured but
	// unusable → stale-request expiration stops AND the #3048 by-request-id
	// reads below lose their BYPASSRLS handle, so approve/reject dies on
	// "approval request not found".
	RequirePlatformAdminPoolOrFatal("HITL", hitlExpireAdminDB, hitlExpireErr)
	if hitlExpireErr != nil {
		log.Printf("[HITL] WARN expire-ticker admin pool unavailable — stale-request expiration DISABLED: %v", hitlExpireErr)
		hitlExpireAdminDB = nil
	} else {
		log.Printf("✅ [HITL] expire-ticker using axonflow_platform_admin (BYPASSRLS) for cross-tenant scan")
	}

	// Register HITL (Human-in-the-Loop) API endpoints (EU AI Act Article 14)
	// Enterprise feature: Human oversight queue for high-risk AI decisions
	hitlRepo := hitl.NewRepository(usageDB)
	// #3048: the repo's by-request-id discovery reads (GetByRequestID /
	// GetHistory) and the deployment queue view (List) read ZERO rows through
	// mig 025's RLS on the app-role pool — approve/reject/override flows died
	// on "approval request not found". Route them through the BYPASSRLS admin
	// pool already opened for the expire ticker above; when it is
	// unavailable the repo falls back to the main pool (owner-pool
	// deployments are unaffected, app-role deployments log the WARN above).
	if hitlExpireAdminDB != nil {
		hitlRepo.SetCrossOrgDB(hitlExpireAdminDB)
	}
	// Read pending approval limit from license tier
	hitlLimits := license.GetCurrentLimits(context.Background())
	hitlService := hitl.NewService(hitlRepo, hitl.ServiceConfig{
		MaxPendingApprovals: hitlLimits.MaxPendingApprovals,
	})
	// Wire the outbound webhook dispatcher (#2419). nil-safe — when
	// AXONFLOW_HITL_WEBHOOK_SIGNING_KEY is unset, dispatcher.Enqueue
	// drops the POST with a warning so an operator can spot the
	// misconfiguration in logs without breaking the approve/reject path.
	hitlService.SetWebhookDispatcher(hitl.NewWebhookDispatcher())
	// Expose the HITL service to the MCP-tool dispatcher so
	// `axonflow_request_approval` (mcp_v1_pro_tools.go) routes through the
	// same Service the HTTP handler uses, instead of writing to the
	// `hitl_approval_queue` table directly. Single enforcement chokepoint
	// for the tier gate + pending cap + history.
	mcpHITLService = hitlService
	// ADR-061 / #3329: route FinCrime scorer above-threshold decisions into
	// the same HITL Service chokepoint (tier gate + pending cap + history)
	// via the bridge, so a scored needs_approval verdict is a REVIEWABLE
	// queue entry, not just a wire verdict.
	fincrimeHITLBridge = NewHITLBridge(hitlServiceBridgeAdapter{svc: hitlService})
	hitlHandler := hitl.NewHandler(hitlService)
	// HITL routes need apiAuthMiddleware so X-Org-ID/X-Tenant-ID headers are set
	// from auth credentials (same pattern as circuit breaker).
	hitlSub := globalRouter.NewRoute().Subrouter()
	hitlSub.Use(apiAuthMiddleware)
	hitlHandler.RegisterRoutes(hitlSub)
	// which are set by proxyAuthMiddleware for proxied requests or directly by clients.

	// #2760 (WS-6): Cowork / Claude Code OTEL ingest plane. Enterprise-gated
	// (the community build mounts a 501 stub). Mounts POST /v1/logs behind
	// apiAuthMiddleware so inbound telemetry is authenticated and org/tenant-tagged
	// from the license — never from the (spoofable) OTEL resource attributes. Each
	// event lands as a canonical audit_logs row (redacted at the collector, signed
	// into decision_chain); it is NOT a parallel store.
	registerCoworkOTELIngest(globalRouter)

	// Start HITL expiration background job (1-hour ticker).
	// Enterprise: expires stale pending approval requests + dispatches the
	// notify_url webhook for any expired row that carried one. Community:
	// no-op. Reuses the long-lived admin pool opened above
	// (hitlExpireAdminDB) so the cross-tenant scan fires under FORCE RLS
	// without per-tick churn. If the pool wasn't available at boot, the
	// ticker is skipped entirely (the boot WARN named the failure mode).
	if hitlExpireAdminDB != nil {
		go func() {
			ticker := time.NewTicker(1 * time.Hour)
			defer ticker.Stop()
			for range ticker.C {
				count, err := hitlService.ExpireStaleAcrossTenants(context.Background(), hitlExpireAdminDB)
				if err != nil {
					log.Printf("[HITL] Expiration error: %v", err)
				} else if count > 0 {
					log.Printf("[HITL] Expired %d stale approval requests", count)
				}
			}
		}()
	}

	// Register Circuit Breaker API endpoints (EU AI Act Article 14)
	// Enterprise feature: Emergency stop/interrupt capability for AI operations
	// Issue #1176: Wire circuit breaker into request pipeline with meaningful thresholds
	//
	// Thresholds are overridable via env. Defaults stay at the Article-14
	// production posture (10 errors / 20 policy violations per 5-min window
	// per client). Benchmark stacks need to drive sustained traffic past
	// those thresholds without the breaker pre-empting requests after the
	// first second of load — they set the env vars to high numbers (or 0
	// for "disabled" semantically — 0 still trips on the first violation
	// per the existing logic, so use a large positive value instead).
	cbErrorThreshold := envIntDefault("AXONFLOW_CB_ERROR_THRESHOLD", 10)
	cbPolicyViolationThreshold := envIntDefault("AXONFLOW_CB_POLICY_VIOLATION_THRESHOLD", 20)
	cbRepo := circuitbreaker.NewRepository(usageDB)
	circuitBreakerInstance = circuitbreaker.New(cbRepo, circuitbreaker.Config{
		DefaultTimeout:           5 * time.Minute,
		MaxTimeout:               1 * time.Hour,
		ErrorThreshold:           cbErrorThreshold,
		PolicyViolationThreshold: cbPolicyViolationThreshold,
		PolicyViolationWindow:    5 * time.Minute,
		EnableAutoRecovery:       true,
	})
	if cbErrorThreshold != 10 || cbPolicyViolationThreshold != 20 {
		log.Printf("[CB] thresholds overridden: error=%d policy_violation=%d (defaults are 10/20)", cbErrorThreshold, cbPolicyViolationThreshold)
	}
	// ADR-061 / #3329: Fraud & Risk Add-on Engine A seam. Explicit
	// construction (never init() registration, #3268). Returns nil on
	// community builds; on enterprise builds the engine is always present
	// (context validation is the protocol-integrity control) and the Engine
	// B scorer client attaches only when AXONFLOW_FINCRIME_SCORER_URL is
	// set. Consulted from evaluateInputPolicies, which covers the decide +
	// MCP query/execute/check-input planes from one seam.
	fincrimeEngine = fincrime.NewEngineFromEnv()
	if fincrimeEngine.ScorerConfigured() {
		log.Printf("[FinCrime] Engine A seam wired with Engine B scorer client")
	}

	notifService := circuitbreaker.NewNotificationService(cbRepo)
	circuitBreakerInstance.SetTripCallback(notifService.HandleTripEvent)
	cbHandler := circuitbreaker.NewHandler(circuitBreakerInstance)
	cbHandler.SetNotificationService(notifService)
	cbHandler.RegisterRoutes(globalRouter, mux.MiddlewareFunc(apiAuthMiddleware))
	// Note: In community edition, RegisterRoutes is a no-op (Circuit Breaker is an enterprise feature)

	// Load active circuits from DB so they survive agent restarts
	if err := circuitBreakerInstance.LoadCircuits(context.Background(), ""); err != nil {
		log.Printf("⚠️  Failed to load active circuits: %v", err)
	}

	// Background goroutine to expire open circuits after their timeout
	go func() {
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			if err := circuitBreakerInstance.ExpireCircuits(context.Background()); err != nil {
				log.Printf("[CircuitBreaker] Expiration error: %v", err)
			}
		}
	}()

	// Audit non-repudiation: per-record Ed25519 signing + prev_hash chain over
	// decision_chain (#2722). The signing key is loaded from the environment;
	// when unset, records are hash-chained but unsigned and the verify
	// endpoints report that honestly. Registered before the reverse proxy so
	// the /api/v1/audit/* verification routes are served locally rather than
	// proxied. Reads are RLS-scoped to the authenticated org.
	if usageDB != nil {
		auditSigningKey, auditSigningKeyID, signErr := LoadAuditSigningKeyFromEnv()
		if signErr != nil {
			log.Printf("⚠️  [AuditSigning] %v; decision-chain records will be hash-chained but NOT signed", signErr)
		}
		auditVerifyKeys, verifyErr := LoadAuditVerifyKeysFromEnv()
		if verifyErr != nil {
			log.Printf("⚠️  [AuditSigning] %v; retired verification keys will be ignored", verifyErr)
		}
		// FU-1 (#2732): this is now a WRITING tracker. The live decision points
		// (recordSignedDecision, called from handleDecide and the Gateway
		// pre-check) enqueue real decisions here; the async workers sign +
		// prev_hash-chain each one into decision_chain off the request hot path.
		// AsyncQueueSize:0 takes the default (1000-deep buffer, 2 workers); a
		// full queue degrades to a synchronous write rather than dropping the
		// record. The SAME instance still backs the verify endpoints below, so a
		// record signed here verifies against the keys loaded here.
		var dctErr error
		decisionChainTracker, dctErr = NewDecisionChainTracker(DecisionChainTrackerConfig{
			DB:               usageDB,
			SystemID:         "axonflow-agent/decision-chain",
			AsyncQueueSize:   0, // writing instance: default 1000-deep async queue + workers
			SigningKey:       auditSigningKey,
			SigningKeyID:     auditSigningKeyID,
			VerificationKeys: auditVerifyKeys,
		})
		if dctErr != nil {
			log.Printf("⚠️  [AuditSigning] failed to initialize decision chain tracker: %v", dctErr)
			decisionChainTracker = nil // keep recordSignedDecision a safe no-op
		} else {
			RegisterAuditVerificationHandlers(globalRouter, decisionChainTracker)
			log.Println("✅ Audit verification endpoints enabled: GET /api/v1/audit/{chains,records}/.../verify")
			log.Println("✅ Decision-chain signing ENABLED on the live decision path (signed, hash-chained records)")
		}
	}

	// Register Reverse Proxy routes (ADR-026: Single Entry Point Architecture)
	// Proxies requests to Orchestrator and Portal based on path
	proxyConfig := GetProxyConfig()
	proxyHandler, err := NewReverseProxyHandler(proxyConfig)
	if err != nil {
		log.Printf("⚠️  Failed to initialize reverse proxy: %v", err)
		log.Println("   SDK clients will need to connect directly to backend services")
	} else {
		proxyHandler.RegisterProxyRoutes(globalRouter)
		log.Println("✅ Reverse proxy initialized (ADR-026: Single Entry Point)")
	}

	// Community SaaS: self-registration endpoint (no auth — bootstrap credential)
	// and telemetry middleware for usage tracking
	if isCommunitySaasMode() {
		RegisterCommunityRegistrationHandler(globalRouter, usageDB)
		log.Println("✅ Community SaaS registration endpoint enabled: POST /api/v1/register")

		// W3 tenant-credential recovery (free tier): POST /api/v1/recover and
		// /api/v1/recover/verify. Intentionally NOT behind apiAuthMiddleware —
		// this is the recovery path for users who have lost their auth secret.
		// Magic-link email is delivered via Resend (or Noop in dev).
		// v9 Phase 8 (#2305 Brief 11.5, Item 2): recovery handler is PRE-AUTH
		// (the whole point is to issue magic links to email addresses with no
		// session yet). It reads community_saas_recovery_tokens for rate
		// limits and community_saas_registrations (mig 105 FORCEd) for
		// recovery cap checks. Under app_role + FORCE these silently return 0.
		// Use admin connection if configured; fall back to usageDB.
		RequirePlatformAdminOrFatal("CSAAS-RECOVERY")
		recoveryDB := usageDB
		adminDB, adminErr := OpenPlatformAdminConnection(context.Background(), 3)
		// #3159: recovery is itself a PRE-AUTH lookup — a configured-but-unusable
		// admin DSN previously fell through to usageDB, where every magic-link
		// token and registration read returns nothing and the operator sees an
		// authentication failure for a credential that was never wrong.
		RequirePlatformAdminPoolOrFatal("CSAAS-RECOVERY", adminDB, adminErr)
		if adminErr != nil {
			log.Printf("[CSAAS-RECOVERY] failed to open admin connection (%v); falling back to usageDB", adminErr)
		} else if adminDB != nil {
			log.Println("[CSAAS-RECOVERY] using axonflow_platform_admin (BYPASSRLS) connection for pre-auth recovery lookups")
			recoveryDB = adminDB
		} else {
			log.Println("[CSAAS-RECOVERY] WARNING: AXONFLOW_DB_PLATFORM_ADMIN_URL not set; falling back to usageDB. Under FORCE RLS as app_role, recovery will fail to find tokens/registrations.")
		}
		RegisterCommunityRecoveryHandler(globalRouter, recoveryDB, nil)
		log.Println("✅ Community SaaS recovery endpoints enabled: POST /api/v1/recover[/verify]")

		// GDPR right-to-erasure (issue #1896): two-step email-verified deletion.
		// Intentionally NOT behind apiAuthMiddleware — the auth proof is the
		// single-use confirmation token sent to the email-on-file. Stripe
		// customer archive is best-effort post-DB-commit (the operator-side
		// erasure must complete regardless of Stripe API availability).
		//
		// v9 (#2397): the handler issues per-tenant SELECT/DELETE on
		// community_saas_registrations (mig 105 FORCE-RLS) + usage_events
		// (mig 081 ENABLE-RLS) before any session/org_id is established.
		// Under axonflow_app_role with no app.current_org_id set, the USING
		// predicate evaluates to NULL → rows silently filtered out:
		// delete-request issues no token (SELECT EXISTS = false) and
		// delete-confirm returns HTTP 200 with a tenant_deletion_log row
		// asserting "deletion done" while the registration + usage_events
		// rows remain on disk (silent SoX-class corruption + lying GDPR
		// Article 17 receipt). Route on the admin pool — same pattern as
		// CSAAS-RECOVERY above; same session-less email-validated lifecycle.
		RequirePlatformAdminOrFatal("CSAAS-DELETE")
		deleteDB := usageDB
		// Distinct names from the CSAAS-RECOVERY pair above: both live in this
		// same block scope, so a second `adminDB, adminErr :=` here is a
		// compile error ("no new variables on left side of :="), not a silent
		// rebind. Naming them separately is what keeps the two pools legible.
		deleteAdminDB, deleteAdminErr := OpenPlatformAdminConnection(context.Background(), 3)
		// #3159: a configured-but-unusable admin DSN previously fell through to
		// usageDB, where delete-confirm issues an incomplete cascade under a
		// receipt asserting the erasure completed.
		RequirePlatformAdminPoolOrFatal("CSAAS-DELETE", deleteAdminDB, deleteAdminErr)
		if deleteAdminErr != nil {
			log.Printf("[CSAAS-DELETE] failed to open admin connection (%v); falling back to usageDB", deleteAdminErr)
		} else if deleteAdminDB != nil {
			log.Println("[CSAAS-DELETE] using axonflow_platform_admin (BYPASSRLS) connection for GDPR cascade DELETEs")
			deleteDB = deleteAdminDB
		} else {
			log.Println("[CSAAS-DELETE] WARNING: AXONFLOW_DB_PLATFORM_ADMIN_URL not set; falling back to usageDB. Under FORCE RLS as app_role, delete-confirm will silently issue an incomplete cascade with a lying GDPR receipt and delete-request will issue no tokens.")
		}
		RegisterTenantDeletionHandler(globalRouter, deleteDB, nil)
		log.Println("✅ Community SaaS tenant deletion endpoints enabled: POST /api/v1/tenant/{id}/delete-{request,confirm}")

		// W4 paid Pro v1 tier: Stripe-driven license issuance. The webhook is
		// intentionally NOT behind apiAuthMiddleware — Stripe-Signature HMAC
		// validation + IP allowlist + per-source rate limit are the auth
		// stack. Returns early without registering when STRIPE_WEBHOOK_SIGNING_SECRET
		// is unset (dev / test stacks routinely run without payment config).
		RegisterBillingWebhook(globalRouter, usageDB)

		// SaaS Plugin license validation lives inline in
		// validateCommunitySaasAuth per ADR-049 §3 + ADR-050 §9 — there
		// is no separate plugin-claim middleware. The X-License-Token
		// header, X-Axonflow-Client header, plugin_user_licenses row
		// lookup, and per-tenant tier resolution all happen in the
		// existing community-saas auth path. Downstream handlers read
		// the resolved tier from `Client.EffectiveTier`.

		// V1 SaaS Plugin Pro paid-tier observability gauges (issue #1886).
		// Background poll over plugin_user_licenses → Prometheus gauges
		// (active_total, total, issued_today, expiring_7d). 60s interval.
		// No-op on community builds (build-tagged file).
		startPluginLicenseMetricsPoller(usageDB)

		// Usage telemetry middleware — sends to SQS (disabled when queue URL is empty).
		// Post-#2010 the agent never writes DDB direct: the ingest Lambda
		// (ee/platform/csaas-telemetry-ingest) is the SOLE writer to
		// community-saas-telemetry-events. Local dev / CI without
		// COMMUNITY_SAAS_TELEMETRY_SQS_URL set leaves the middleware
		// disabled exactly as the empty-table case did before.
		telQueueURL := getEnv("COMMUNITY_SAAS_TELEMETRY_SQS_URL", "")
		tel := NewCommunitySaaSTelemetry(telQueueURL, GetPlatformVersion())
		globalRouter.Use(tel.Middleware)
	}

	// Mark application as ready - /health will now return "healthy"
	appReady.Store(true)
	log.Println("✅ All initialization complete - application ready")
	log.Printf("🚀 AxonFlow Agent fully operational on port %s", port)

	// Anonymous platform startup telemetry (#2004 PR2). Fire-and-forget
	// in a goroutine — the call has a 5s ceiling but we don't block the
	// startup log on it, and the agent is already serving requests by
	// this point. AXONFLOW_TELEMETRY=off short-circuits inside the call;
	// community_saas mode also short-circuits per the user-locked design.
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		sent, err := MaybeSendStartupTelemetry(ctx)
		if err != nil {
			log.Printf("[startup-telemetry] error: %v", err)
		} else if sent {
			log.Println("[startup-telemetry] ping delivered")
		}
	}()

	// Wait for SIGTERM/SIGINT so we can flush the OTel decision tracer
	// before the process exits (#2426 WS4). Without a handler the
	// process is killed before BatchSpanProcessor flushes — the
	// telemetry Provider exposes a 5s-bounded Shutdown so this blocks
	// at most that long. The HTTP server stays in its goroutine; this
	// is intentionally a *flush*, not a graceful server drain.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	sig := <-sigCh
	log.Printf("⏸️  Received %s — flushing decision tracer before exit", sig)
	if decisionTracerProvider != nil {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
		if err := decisionTracerProvider.Shutdown(shutdownCtx); err != nil {
			log.Printf("[telemetry] decision tracer Shutdown error: %v", err)
		}
		cancel()
	}
	// Drain the decision-chain signing workers so any decisions still queued at
	// SIGTERM are signed + persisted before exit (#2732). Bounded so a wedged DB
	// can't hang shutdown; unflushed records are simply lost on a timeout, which
	// is the same best-effort posture the live path already holds.
	if decisionChainTracker != nil {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
		if err := decisionChainTracker.Shutdown(shutdownCtx); err != nil {
			log.Printf("[DecisionChain] Shutdown error: %v", err)
		}
		cancel()
	}
	log.Println("👋 Goodbye")
}

//nolint:unused // Used in tests
func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]interface{}{
		"status":               "healthy",
		"service":              "axonflow-agent",
		"tier":                 currentLicenseTier(),
		"timestamp":            time.Now().UTC(),
		"version":              GetPlatformVersion(),
		"capabilities":         getCapabilities(),
		"sdk_compatibility":    getSDKCompatibility(),
		"plugin_compatibility": getPluginCompatibility(),
	}); err != nil {
		log.Printf("Error encoding health response: %v", err)
	}
}

func clientRequestHandler(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	atomic.AddInt64(&agentMetrics.totalRequests, 1)

	// Log incoming request with headers
	log.Printf("📨 Incoming request from %s - Method: %s, Path: %s", r.RemoteAddr, r.Method, logutil.Sanitize(r.URL.Path))
	log.Printf("   Headers: X-License-Key: %s, X-Client-Secret: %s, Content-Type: %s",
		maskString(r.Header.Get("X-License-Key")),
		maskString(r.Header.Get("X-Client-Secret")),
		r.Header.Get("Content-Type"))

	var req ClientRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		atomic.AddInt64(&agentMetrics.failedRequests, 1)
		log.Printf("❌ Request body parse failed: %v", err)
		sendErrorResponse(w, "Invalid request body", http.StatusBadRequest, nil)
		return
	}
	parseTime := time.Since(startTime)
	log.Printf("[TIMING] Request parse: %v", parseTime)
	log.Printf("   Request body: ClientID='%s', RequestType='%s', SkipLLM=%v, Query='%s'",
		logutil.Sanitize(req.ClientID), logutil.Sanitize(req.RequestType), req.SkipLLM, logutil.Sanitize(truncateString(req.Query, 50)))

	// 1. Validate client authentication via unified authenticator
	validateClientStart := time.Now()

	auth, authErr := Authenticate(r, &AuthHints{ClientID: req.ClientID})
	if authErr != nil {
		if authErr.RetryAfter != "" {
			w.Header().Set("Retry-After", authErr.RetryAfter)
		}
		sendErrorResponse(w, authErr.Message, authErr.HTTPStatus, nil)
		return
	}
	client := auth.Client

	validateClientTime := time.Since(validateClientStart)
	log.Printf("[TIMING] Client validation: %v (mode: %s)", validateClientTime, auth.Kind)

	// Set auth-derived identity in request context for downstream use.
	r = r.WithContext(stampAuthContext(r.Context(), client, auth.Kind))

	// 2. Resolve user identity via unified ResolveUser
	validateUserStart := time.Now()
	user, userAuthErr := ResolveUser(auth, req.UserToken)
	if userAuthErr != nil {
		sendErrorResponse(w, userAuthErr.Message, userAuthErr.HTTPStatus, nil)
		return
	}

	// Stamp the v9 UserID into request context now that the user is
	// resolved. RequestIdentityFromContext (ADR-052/053 Step 2) returns
	// an empty UserID before this point, which is the correct shape for
	// service-to-service callers — and we preserve that shape here too:
	// AuthKindInternalService synthesises User{ID:0,...} (no human user
	// behind the call), and a downstream reader of UserIDFromContext that
	// does `if uid != "" { ... }` must NOT see "0" as a real user.
	{
		var stamped string
		if user.ID != 0 {
			stamped = fmt.Sprintf("%d", user.ID)
		}
		ctx := context.WithValue(r.Context(), ContextKeyUserID, stamped)
		r = r.WithContext(ctx)
	}

	validateUserTime := time.Since(validateUserStart)
	log.Printf("[TIMING] User token validation: %v", validateUserTime)

	// 3. Verify tenant isolation
	tenantCheckStart := time.Now()
	log.Printf("🔍 Checking tenant isolation: User TenantID='%s', Client TenantID='%s'", logutil.Sanitize(user.TenantID), logutil.Sanitize(client.TenantID))
	if user.TenantID != client.TenantID {
		log.Printf("❌ TENANT MISMATCH: User TenantID='%s' does not match Client TenantID='%s'", logutil.Sanitize(user.TenantID), logutil.Sanitize(client.TenantID))
		sendErrorResponse(w, "Tenant mismatch", http.StatusForbidden, nil)
		return
	}
	tenantCheckTime := time.Since(tenantCheckStart)
	log.Printf("✅ Tenant isolation check passed")
	log.Printf("[TIMING] Tenant isolation check: %v", tenantCheckTime)

	// Canonical audit_logs coverage for the agent /api/request proxy plane
	// (#2684 — closes the audit-coverage gate DEFERRED for clientRequestHandler).
	// Every TERMINAL deny below — circuit breaker, static/tenant policy, HITL
	// gate, budget — records an explainable plane=agent row through the
	// established decide writer, so the portal /decisions feed + the SEBI/
	// EU-AI-Act/OJK/RBI exporters see the agent-side block. Previously these
	// denies were recorded only on the legacy agent_audit_logs plane, which has
	// NO portal reader and is slated for retirement (#2674, ADR-058 Phase 4); an
	// ALLOW forwards to the orchestrator, which audits the forwarded request.
	// Identity is fixed now (user resolved + tenant verified) so it is stable
	// across every deny branch. plane=agent stores the verdict verbatim (the
	// writer only canonicalizes the decision/openai_compat planes), so the
	// canonical AuditVerdict* / needs_approval values are passed directly.
	proxyTraceID := traceIDFromHeader(r.Header.Get("traceparent"))
	if proxyTraceID == "" {
		proxyTraceID = newW3CTraceID()
	}
	proxyDecisionID := uuid.New().String()
	proxyAudit := &decisionAuditInput{
		clientID:      client.ClientID,
		requestID:     proxyDecisionID,
		userEmail:     user.Email,
		userRole:      user.Role,
		userID:        user.ID,
		query:         req.Query,
		plane:         PlaneAgent,
		correlationID: proxyTraceID,
	}
	auditProxyDeny := func(verdict string, policyIDs, reasons []string) {
		recordDecideDecision(r.Context(), proxyDecisionID, user.OrgID, user.TenantID,
			DecisionStageLLM, verdict, policyIDs, time.Since(startTime).Milliseconds(),
			reasons, proxyTraceID, nil, false, proxyAudit)
	}

	// 3.5 Circuit breaker check — block if circuit is open for this client/tenant/org (#1176)
	//
	// ADR-052 §5 (issue #2318): the CircuitBreaker has four scopes (Client,
	// Policy, Tenant, Global), all namespaced by OrgID. ScopeClient enables
	// surgical per-credential tripping (one bad API key) while ScopeGlobal
	// handles per-org/per-customer billing-abuse mitigation. ClientID is the
	// CREDENTIAL IDENTITY here (api_key_id for API-keyed callers, Basic-auth
	// username for legacy Basic callers), routed through `client.ClientID`
	// per ADR-052 §5 — NOT `client.ID` which is the legacy compat field that
	// for Basic auth still carries the org_id collapse. Same routing as
	// usage_events.client_id (via buildAPICallClientID at line ~1966).
	if circuitBreakerInstance != nil {
		cbResult, cbErr := circuitBreakerInstance.Check(r.Context(), circuitbreaker.CheckInput{
			OrgID:    client.OrgID,
			TenantID: client.TenantID,
			ClientID: client.ClientID,
		})
		if cbErr != nil {
			log.Printf("⚠️ Circuit breaker check error: %v", cbErr)
		} else if !cbResult.Allowed {
			log.Printf("🔴 Request blocked by circuit breaker: scope=%s reason=%s", logutil.Sanitize(string(cbResult.Scope)), logutil.Sanitize(string(cbResult.Reason)))
			auditProxyDeny(AuditVerdictBlocked, []string{"circuit_breaker"},
				[]string{fmt.Sprintf("circuit breaker active (scope=%s, reason=%s)", cbResult.Scope, cbResult.Reason)})
			if retryAfter := circuitBreakerRetryAfter(cbResult.ExpiresAt); retryAfter != "" {
				w.Header().Set("Retry-After", retryAfter)
			}
			sendErrorResponse(w, fmt.Sprintf("Service temporarily unavailable: circuit breaker active (reason: %s)", cbResult.Reason), http.StatusServiceUnavailable, nil)
			return
		}
	}

	// 4. Apply static policy enforcement
	// Uses UnifiedPolicyEngine (shared engine) as primary path, with fallbacks.
	// Phase 2: Tenant-specific policies via tierAwarePolicyEngine (below).
	//
	// #3296: Phase 1 and Phase 2 remain TWO evaluation passes over
	// static_policies here — the passes are not collapsed into one, because
	// they implement genuinely different semantics, not a redundant re-scan.
	// Both phases DO now read static_policies through the same converged
	// substrate (sharedpolicy.PolicyLoader, platform/shared/policy/loader.go:
	// Phase 1 via GetPolicies/EvaluateRequest, Phase 2 via
	// sharedpolicy.ScanEffectivePolicyRows inside StaticPolicyRepository
	// .GetEffective) — see that file's doc for how GetEffective's two-pass
	// org+global scoping, segment filtering, and tier awareness now map onto
	// the loader. What differs between the two evaluation passes, and why,
	// file:line:
	//
	//   - platform/shared/policy/engine.go:100-181 (UnifiedPolicyEngine
	//     .EvaluateRequest) evaluates every category-filtered/segment-filtered
	//     policy and blocks on the FIRST ActionBlock match in
	//     priority/created_at sort order. It applies NO tier-hierarchy
	//     shadowing (system → org → tenant "most specific wins") and NO
	//     Enterprise policy_overrides downgrade.
	//   - platform/agent/tier_aware_policy_engine.go:217-231
	//     (TierAwarePolicyEngine.EvaluatePolicy) walks the FULL tier-ordered
	//     effective set (system → organization → tenant, first match wins —
	//     sortPoliciesByTierAndPriority) with policy.EffectiveOverride
	//     downgrade applied per-policy (static_policy_repository.go
	//     GetEffective/applyEffectiveOverride), THEN combines the strictest
	//     applicable segment-scoped match on top (ADR-060 Decision 1,
	//     combineTierAndSegmentResults) — semantics engine.go does not
	//     implement.
	//   - Category coverage differs, not just combining semantics: Phase 1 is
	//     restricted to proxyPolicyCategories (SQLi/dangerous/admin-access/
	//     sensitive-data/compliance-RBI/compliance-SEBI/PII, see var
	//     proxyPolicyCategories above) via EvalOptions.Categories, while
	//     Phase 2's GetEffectivePolicies has NO category filter — it is the
	//     tier+override authority for every category, including ones Phase 1
	//     skips. Phase 2 is therefore not a redundant re-scan of Phase 1's
	//     work; it is additionally authoritative for out-of-proxy-category
	//     policies and for the override-downgrade/tier-shadow contract.
	//
	// Unifying this into a single pass means moving tier-hierarchy shadowing,
	// override-downgrade, and the ADR-060 segment combiner into the shared
	// engine (engine.go) itself, since that is the component every other
	// verdict surface (gateway pre-check, MCP input/output scan, OpenAI-compat,
	// the response processor) also calls — changing its combining semantics
	// changes behavior for all of those surfaces at once, not just this one.
	// That is a substrate-level change in its own right, not a tail-end of
	// this read-convergence. Reimplementing the same tier/override/segment
	// logic a second time directly in run.go was rejected as the opposite of
	// consolidation: it would leave two independent copies of that logic to
	// keep in sync instead of one.
	//
	// What DID collapse here: cross-phase duplicate identifiers in
	// TriggeredPolicies (see appendTriggeredPolicyID below and its use at
	// both append sites) — TestClientRequestHandler_NoDuplicateTriggeredPolicies
	// and TestPolicyTestHandler_NoDuplicateTriggeredPolicies
	// (run_dedup_triggered_policies_test.go) are the regression tests.
	policyEvalStart := time.Now()
	log.Printf("📋 Evaluating static policies for request type: %s", req.RequestType)
	var policyResult *StaticPolicyResult

	// #3051 (ADR-060 P3) + #3266: resolve the caller's governance-segment set
	// ONCE, up front, so Phase 1 (shared engine, below) and Phase 2
	// (tier-aware engine) evaluate against the SAME membership set instead of
	// Phase 1 running segment-blind. Previously this resolved only inside the
	// Phase 2 block, so the shared engine had no segment context and would
	// both ACT ON and REPORT segment-scoped static_policies rows for callers
	// outside the segment (#3266).
	segmentIDs, segOK := resolveUserSegmentsForEnforcement(r.Context(), user.OrgID, user.Email)

	// #3293 locked invariant: a segment-resolution FAILURE is handled at the
	// resolution SITE and must NEVER be propagated downstream as a nil/empty
	// segment set — unlike the observability-only session-create resolution
	// (mcp_server_handler.go's authenticateMCPSession), a genuine resolution
	// ERROR here must DENY the request, never silently fall back to org-only
	// (ADR-060 §Fail-closed, locked). Deny and return HERE, before Phase 1
	// ever runs, so the shared engine is never called with a nil Segments set
	// that actually means
	// "failed to load" — below this point (Phase 1 and Phase 2 alike),
	// nil/empty Segments means only "resolved to none / no identity"
	// (community mode, no SCIM configured, or zero real memberships), never
	// "failed." segOK=true with a nil/empty set is NOT a failure; it proceeds
	// org-only exactly as pre-#3051.
	if !segOK {
		reason := "segment resolution unavailable — request denied (fail-closed, ADR-060 #2989)"
		triggeredPolicies := []string{"segment_resolution_failed"}
		log.Printf("🛡️ Request denied: segment resolution failed (fail-closed) for org %s", logutil.Sanitize(user.OrgID))

		// Canonical audit row for the fail-closed deny (#2684).
		auditProxyDeny(AuditVerdictBlocked, triggeredPolicies, []string{reason})

		// Record policy violation for auto-trip threshold tracking (#1176),
		// same as the policy-block path below (ADR-052 §5, #2318).
		if circuitBreakerInstance != nil {
			for _, policyID := range triggeredPolicies {
				if err := circuitBreakerInstance.RecordPolicyViolation(r.Context(), client.OrgID, client.TenantID, client.ClientID, policyID); err != nil {
					log.Printf("⚠️ Circuit breaker RecordPolicyViolation error: %v", err)
				}
			}
		}

		// Track blocked request metrics
		if agentMetrics != nil {
			atomic.AddInt64(&agentMetrics.blockedRequests, 1)
			latencyMs := int64(time.Since(startTime).Milliseconds())
			agentMetrics.recordLatency(latencyMs, "static")
		}

		// Record Prometheus metrics
		promRequestsTotal.WithLabelValues("blocked").Inc()
		promBlockedRequests.Inc()
		promPolicyEvaluations.Inc()
		promRequestDuration.WithLabelValues("static").Observe(float64(time.Since(startTime).Milliseconds()))

		response := ClientResponse{
			Success:     false,
			Blocked:     true,
			BlockReason: reason,
			PolicyInfo: &PolicyEvaluationInfo{
				MatchedPolicies:   triggeredPolicies,
				PoliciesEvaluated: triggeredPolicies,
				ProcessingTime:    time.Since(startTime).String(),
				TenantID:          user.TenantID,
			},
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		if err := json.NewEncoder(w).Encode(response); err != nil {
			log.Printf("Error encoding service permission denied response: %v", err)
		}
		return
	}

	// Check if gateway static policies are enabled (proxy uses gateway config)
	// #2581: resolve per-org posture (org with no override → deployment-global).
	gatewayDetectionCfg := ResolveGatewayDetectionConfig(r.Context(), user.OrgID)
	sharedEngine := sharedpolicy.GetGlobalEngine()
	if !gatewayDetectionCfg.Enabled {
		// Static policies disabled — create empty result
		policyResult = &StaticPolicyResult{}
	} else if sharedEngine != nil {
		// Primary path: UnifiedPolicyEngine (same as Gateway handler)
		skipCats := append([]sharedpolicy.PolicyCategory(nil), gatewayDetectionCfg.SkipCategories...)
		// #3001: routed through the shared role predicate rather than a
		// literal `== "admin"`. The literal excluded `owner`, so an owner —
		// a strict SUPERSET of admin since #2993 — was enforced MORE
		// strictly than an admin on admin-access queries. `user` here is the
		// ResolveUser-validated identity, not a client-supplied field.
		if sharedidentity.RoleIsAdministrative(user.Role) {
			skipCats = append(skipCats, sharedpolicy.CategoryAdminAccess)
		}
		requestResult := sharedEngine.EvaluateRequest(r.Context(), req.Query, sharedpolicy.EvalOptions{
			TenantID:        user.TenantID,
			OrgID:           user.OrgID,
			OrgScope:        sharedpolicy.OrgScopePtr(user.OrgID), // #3048 R3 HIGH-3 (N2)
			ConnectorName:   "proxy",
			UserID:          fmt.Sprintf("%d", user.ID),
			Categories:      proxyPolicyCategories,
			SkipCategories:  skipCats,
			ActionOverrides: gatewayDetectionCfg.BuildActionOverrides(),
			// #3266: the caller's already-resolved governance-segment set
			// (above), so a segment-scoped static_policies row can only
			// act/report for a member — closes the Phase-1 cross-segment leak.
			Segments: segmentIDs,
		})
		policyResult = convertSharedResultToStatic(requestResult)
		// #3365: evaluation-time display names for the ids the deny/HITL audit
		// rows below record. The pre-evaluation denies (circuit breaker,
		// segment resolution) carry only builtin-resolvable guard ids.
		proxyAudit.policyNames = policyResult.PolicyNames
		log.Printf("[Proxy] Shared policy engine evaluated %d policies in %dms",
			requestResult.PoliciesEvaluated, requestResult.ProcessingTimeMs)
	} else {
		log.Println("[Proxy] WARNING: No policy engine available (shared engine not initialized)")
		policyResult = &StaticPolicyResult{}
	}

	// Phase 2: Tenant-specific policies (if not already blocked and tier engine available)
	if !policyResult.Blocked && tierAwarePolicyEngine != nil {
		ctx := r.Context()

		// #3051 (ADR-060 P3) + #3293: segmentIDs was resolved once, up front
		// (above, #3266) — a resolution FAILURE (segOK=false) already denied
		// and returned before Phase 1 ran, so by construction this point is
		// only reached with a successfully-resolved (possibly nil/empty) set.
		//
		// Decision 5 (#3490): the org argument was a literal `nil` here, which
		// GetEffective turned into `orgIDStr = ""` and bound to the org leg of
		// its pass-A predicate - so an org-tier policy could never match on
		// this plane, and on an org whose org_id differs from its tenant id
		// the RLS scope fell back to the tenant and matched nothing at all.
		// user.OrgID is the licence-derived org the request already
		// authenticated as (Phase 1 above passes exactly the same value).
		tierResult, err := tierAwarePolicyEngine.EvaluatePolicy(ctx, user.TenantID, sharedpolicy.OrgScopePtr(user.OrgID), segmentIDs, req.Query)
		if err != nil {
			log.Printf("⚠️ Tier-aware policy evaluation error: %v", err)
		} else if tierResult.Matched && tierResult.Action == "block" {
			// Tenant/segment policy triggered a block
			policyResult.Blocked = true
			policyResult.Reason = fmt.Sprintf("Blocked by %s policy: %s", tierResult.Tier, tierResult.PolicyName)
			policyResult.TriggeredPolicies = appendTriggeredPolicyID(policyResult.TriggeredPolicies, tierResult.PolicyID)
			// #3365: the tier engine carries the matched row's display name.
			if tierResult.PolicyID != "" && tierResult.PolicyName != "" {
				proxyAudit.policyNames = mergePolicyNames(proxyAudit.policyNames,
					map[string]string{tierResult.PolicyID: tierResult.PolicyName})
			}
			policyResult.Severity = tierResult.Severity
			log.Printf("🛡️ Tenant policy blocked request: %s (tier: %s)", tierResult.PolicyName, tierResult.Tier)
		} else if tierResult.Matched {
			// Policy matched but action is not block (allow, warn, log, redact, require_approval)
			policyResult.TriggeredPolicies = appendTriggeredPolicyID(policyResult.TriggeredPolicies, tierResult.PolicyID)
			// #3365: name the matched row on the HITL/deny audit paths below.
			if tierResult.PolicyID != "" && tierResult.PolicyName != "" {
				proxyAudit.policyNames = mergePolicyNames(proxyAudit.policyNames,
					map[string]string{tierResult.PolicyID: tierResult.PolicyName})
			}
			log.Printf("📝 Tenant policy matched (action=%s): %s", tierResult.Action, tierResult.PolicyName)

			// Issue #1081: Set RequiresApproval for HITL enforcement (Enterprise only)
			if tierResult.Action == "require_approval" {
				policyResult.RequiresApproval = true
				// #3509: attribute the hold so the queue entry raised below
				// names the rule that caused it. Fill-if-empty, never
				// overwrite: a Phase 1 static/system policy that already
				// resolved to require_approval held this request FIRST, and
				// the entry must name the rule a reviewer will look up, not
				// whichever engine happened to run last.
				if policyResult.ApprovalPolicyID == "" {
					policyResult.ApprovalPolicyID = tierResult.PolicyID
					policyResult.ApprovalPolicyName = tierResult.PolicyName
				}
				log.Printf("⏸️ HITL required by tenant policy: %s", tierResult.PolicyName)
			}
		}
	}

	policyEvalTime := time.Since(policyEvalStart)
	log.Printf("✅ Policy evaluation complete: Blocked=%v, TriggeredPolicies=%d", policyResult.Blocked, len(policyResult.TriggeredPolicies))
	log.Printf("[TIMING] Policy evaluation: %v", policyEvalTime)

	if policyResult.Blocked {
		log.Printf("Request blocked by static policy for user %s: %s", logutil.Sanitize(user.Email), logutil.Sanitize(policyResult.Reason))

		// Canonical audit row for the static/tenant policy block (#2684).
		auditProxyDeny(AuditVerdictBlocked, policyResult.TriggeredPolicies, []string{policyResult.Reason})

		// Record policy violation for auto-trip threshold tracking (#1176)
		// ADR-052 §5 (issue #2318): clientID is the credential identity, not
		// legacy `client.ID`. See contract block at the Check call above.
		if circuitBreakerInstance != nil {
			for _, policyID := range policyResult.TriggeredPolicies {
				if err := circuitBreakerInstance.RecordPolicyViolation(r.Context(), client.OrgID, client.TenantID, client.ClientID, policyID); err != nil {
					log.Printf("⚠️ Circuit breaker RecordPolicyViolation error: %v", err)
				}
			}
		}

		// Track blocked request metrics
		if agentMetrics != nil {
			atomic.AddInt64(&agentMetrics.blockedRequests, 1)
			latencyMs := int64(time.Since(startTime).Milliseconds())
			agentMetrics.recordLatency(latencyMs, "static")
		}

		// Record Prometheus metrics
		promRequestsTotal.WithLabelValues("blocked").Inc()
		promBlockedRequests.Inc()
		promPolicyEvaluations.Inc()
		promRequestDuration.WithLabelValues("static").Observe(float64(time.Since(startTime).Milliseconds()))

		response := ClientResponse{
			Success:     false,
			Blocked:     true,
			BlockReason: policyResult.Reason,
			PolicyInfo: &PolicyEvaluationInfo{
				MatchedPolicies:   policyResult.TriggeredPolicies,
				PoliciesEvaluated: policyResult.TriggeredPolicies,
				StaticChecks:      policyResult.ChecksPerformed,
				ProcessingTime:    time.Since(startTime).String(),
				TenantID:          user.TenantID,
			},
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		if err := json.NewEncoder(w).Encode(response); err != nil {
			log.Printf("Error encoding service permission denied response: %v", err)
		}
		return
	}

	// Issue #1081: HITL (Human-in-the-Loop) enforcement for compliance frameworks
	// HITL is an ENTERPRISE-ONLY feature. It is ONLY triggered by policy evaluation
	// returning require_approval action. We do NOT trust client-provided context metadata.
	requiresHITL := policyResult.RequiresApproval && !isCommunityMode()
	// #3509 defect 2: spend an outstanding single-use approval before the hold
	// is applied. Placed here rather than inside the branch below so an
	// admitted request rejoins the ordinary allow path in one piece - budget
	// check, rate limiting, connector execution and the allow audit row all
	// run exactly as they would for a request no policy ever held.
	if requiresHITL {
		// The FULL principal, not just the user: see the decide plane's note.
		if grantID, admitted := consumeApprovalGrant(r.Context(), hitlPlaneAgentRequest, hitl.GrantSubject{
			OrgID:    client.OrgID,
			TenantID: client.TenantID,
			ClientID: client.ClientID,
			UserID:   fmt.Sprintf("%d", user.ID),
		}, approvalPolicyKey(policyResult.ApprovalPolicyID), req.Query); admitted {
			requiresHITL = false
			// Recorded on the audit identity so that if a LATER, unrelated
			// control refuses this request anyway - the budget check below is
			// the realistic one - the deny row shows a human approval was
			// spent on a request that never ran. The grant is single use and
			// is gone either way; an operator seeing consumed_at set on the
			// queue row deserves to find the reason on this plane too.
			proxyAudit.approvalGrantID = grantID
			log.Printf("✅ [Proxy Mode] HITL hold lifted by approved request %s (single use, now spent)", logutil.Sanitize(grantID))
		}
	}
	if requiresHITL {
		log.Printf("⏸️ [Proxy Mode] HITL required - blocking request for human approval")

		// #3509: raise the reviewable queue entry. Before this, a
		// require_approval policy on this plane returned 403 with an audit row
		// and NOTHING for a reviewer to act on - the caller was refused and,
		// unlike a block, had no override flow and no reviewer surface either.
		hitlEnqueue := enqueuePolicyStepUp(r.Context(), policyStepUpInput{
			Plane:      hitlPlaneAgentRequest,
			OrgID:      client.OrgID,
			TenantID:   client.TenantID,
			ClientID:   client.ClientID,
			UserID:     fmt.Sprintf("%d", user.ID),
			UserEmail:  user.Email,
			PolicyID:   policyResult.ApprovalPolicyID,
			PolicyName: policyResult.ApprovalPolicyName,
			Reason:     "human approval required by policy",
			Severity:   policyResult.Severity,
			DecisionID: proxyDecisionID,
			Stage:      DecisionStageLLM,
			Query:      req.Query,
		})
		proxyAudit.approvalEnqueue = hitlEnqueue.Outcome
		proxyAudit.approvalRequestID = hitlEnqueue.RequestID

		// Canonical audit row for the HITL gate decision (#2684): needs_approval.
		// VerdictNeedsApproval == the canonical audit value "needs_approval", and
		// plane=agent stores it verbatim, so it lands canonical without a remap.
		//
		// #3509: the reason now records whether a reviewable entry was actually
		// raised. A hold whose entry was refused (pending cap, tier, write
		// failure) is the SAME invisible dead end this change removes, and this
		// row is the only durable place it is recorded.
		hitlReasons := []string{"human approval required by policy"}
		if hitlEnqueue.RequestID != "" {
			hitlReasons = append(hitlReasons, policyStepUpReason(hitlEnqueue.RequestID))
		} else if hitlEnqueue.Detail != "" {
			hitlReasons = append(hitlReasons, hitlEnqueue.Detail)
		}
		auditProxyDeny(VerdictNeedsApproval,
			append(policyResult.TriggeredPolicies, "hitl_compliance"),
			hitlReasons)

		// Track HITL blocked request metrics
		if agentMetrics != nil {
			atomic.AddInt64(&agentMetrics.blockedRequests, 1)
			latencyMs := int64(time.Since(startTime).Milliseconds())
			agentMetrics.recordLatency(latencyMs, "hitl")
		}

		// Record Prometheus metrics
		promRequestsTotal.WithLabelValues("hitl_blocked").Inc()
		promBlockedRequests.Inc()
		promPolicyEvaluations.Inc()
		promRequestDuration.WithLabelValues("hitl").Observe(float64(time.Since(startTime).Milliseconds()))

		hitlMatched := append(policyResult.TriggeredPolicies, "hitl_compliance")
		response := ClientResponse{
			Success: false,
			Blocked: true,
			// Pinned literal: every shipped SDK matches this string to enter
			// its HITL branch. #3509's queue-entry id rides ApprovalRequestID.
			BlockReason:       "require_approval",
			ApprovalRequestID: hitlEnqueue.RequestID,
			PolicyInfo: &PolicyEvaluationInfo{
				MatchedPolicies:   hitlMatched,
				PoliciesEvaluated: hitlMatched,
				StaticChecks:      policyResult.ChecksPerformed,
				ProcessingTime:    time.Since(startTime).String(),
				TenantID:          user.TenantID,
			},
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden) // 403 for HITL block
		if err := json.NewEncoder(w).Encode(response); err != nil {
			log.Printf("Error encoding HITL blocked response: %v", err)
		}
		return
	}

	// Rate limiting is now handled inside validateClientCredentials() during authentication
	rateLimitTime := time.Duration(0)

	// Issue #1082: Budget enforcement - check before allowing request
	budgetCheckStart := time.Now()
	var budgetInfo *BudgetInfo
	if costService != nil {
		ctx := r.Context()
		log.Printf("💰 [clientRequestHandler] Checking budget: OrgID=%s, TenantID=%s, UserID=%d", client.OrgID, client.TenantID, user.ID)
		budgetDecision, err := costService.CheckBudget(ctx, client.OrgID, "", "", fmt.Sprintf("%d", user.ID), client.TenantID)
		if err != nil {
			log.Printf("⚠️ [clientRequestHandler] Budget check failed: %v (allowing request)", err)
		} else {
			log.Printf("💰 [clientRequestHandler] Budget decision: Allowed=%v, BudgetID=%s, UsedUSD=%.4f, LimitUSD=%.4f, Percentage=%.2f",
				budgetDecision.Allowed, budgetDecision.BudgetID, budgetDecision.UsedUSD, budgetDecision.LimitUSD, budgetDecision.Percentage)
		}
		if budgetDecision != nil {
			budgetInfo = &BudgetInfo{
				BudgetID:   budgetDecision.BudgetID,
				BudgetName: budgetDecision.BudgetName,
				UsedUSD:    budgetDecision.UsedUSD,
				LimitUSD:   budgetDecision.LimitUSD,
				Percentage: budgetDecision.Percentage,
				Exceeded:   !budgetDecision.Allowed || budgetDecision.Percentage >= 100,
				Action:     string(budgetDecision.Action),
			}

			// Block if budget exceeded and action is block
			if !budgetDecision.Allowed {
				log.Printf("💰 [clientRequestHandler] Request blocked by budget: %s", budgetDecision.Message)
				// Canonical audit row for the budget block (#2684).
				auditProxyDeny(AuditVerdictBlocked, []string{"budget_exceeded"}, []string{budgetDecision.Message})
				response := ClientResponse{
					Success:     false,
					Blocked:     true,
					BlockReason: budgetDecision.Message,
					BudgetInfo:  budgetInfo,
					PolicyInfo: &PolicyEvaluationInfo{
						MatchedPolicies:   []string{"budget_exceeded"},
						PoliciesEvaluated: []string{"budget_exceeded"},
						StaticChecks:      policyResult.ChecksPerformed,
						ProcessingTime:    time.Since(startTime).String(),
						TenantID:          user.TenantID,
					},
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusPaymentRequired) // 402 Payment Required
				_ = json.NewEncoder(w).Encode(response)
				return
			}

			// Warn if exceeded but action is warn
			if budgetDecision.Percentage >= 100 && budgetDecision.Action == cost.OnExceedWarn {
				log.Printf("⚠️ [clientRequestHandler] Budget exceeded with warn action: %s", budgetDecision.Message)
				w.Header().Set("X-Budget-Warning", budgetDecision.Message)
			}
		}
	}
	budgetCheckTime := time.Since(budgetCheckStart)
	log.Printf("[TIMING] Budget check: %v", budgetCheckTime)

	// Calculate auth time (client + user + tenant validation)
	authTime := validateClientTime + validateUserTime + tenantCheckTime

	// Record per-stage metrics (convert to milliseconds)
	if agentMetrics != nil {
		agentMetrics.mu.Lock()
		// Auth timing
		authMs := authTime.Milliseconds()
		if len(agentMetrics.authTimings) >= 1000 {
			agentMetrics.authTimings = agentMetrics.authTimings[1:]
		}
		agentMetrics.authTimings = append(agentMetrics.authTimings, authMs)

		// Static policy timing
		policyMs := policyEvalTime.Milliseconds()
		if len(agentMetrics.staticPolicyTimings) >= 1000 {
			agentMetrics.staticPolicyTimings = agentMetrics.staticPolicyTimings[1:]
		}
		agentMetrics.staticPolicyTimings = append(agentMetrics.staticPolicyTimings, policyMs)
		agentMetrics.mu.Unlock()
	}

	// Send response
	totalProcessingTime := time.Since(startTime)
	log.Printf("[TIMING] Total processing time: %v (parse: %v, client: %v, user: %v, tenant: %v, policy: %v, ratelimit: %v)",
		totalProcessingTime, parseTime, validateClientTime, validateUserTime, tenantCheckTime, policyEvalTime, rateLimitTime)

	// 6. Forward to AxonFlow Orchestrator (include skip_llm flag for hourly tests)
	orchestratorStart := time.Now()
	log.Printf("🚀 Forwarding request to orchestrator: ClientID=%s, RequestType=%s", req.ClientID, req.RequestType)
	orchestratorResp, err := forwardToOrchestrator(req, user, client)
	orchestratorTime := time.Since(orchestratorStart)
	if err != nil {
		log.Printf("❌ Orchestrator forward failed: %v (time: %v)", err, orchestratorTime)
	} else {
		log.Printf("✅ Orchestrator responded successfully (time: %v)", orchestratorTime)
	}

	// Record network timing (Agent → Orchestrator)
	if agentMetrics != nil && err == nil {
		agentMetrics.mu.Lock()
		networkMs := orchestratorTime.Milliseconds()
		if len(agentMetrics.networkTimings) >= 1000 {
			agentMetrics.networkTimings = agentMetrics.networkTimings[1:]
		}
		agentMetrics.networkTimings = append(agentMetrics.networkTimings, networkMs)
		agentMetrics.mu.Unlock()
	}

	if err != nil {
		// Track failed request
		if agentMetrics != nil {
			atomic.AddInt64(&agentMetrics.failedRequests, 1)
		}
		// Record error for circuit breaker auto-trip (#1176 Phase 2B)
		// ADR-052 §5 (issue #2318): clientID = credential identity.
		if circuitBreakerInstance != nil {
			if cbErr := circuitBreakerInstance.RecordError(r.Context(), client.OrgID, client.TenantID, client.ClientID); cbErr != nil {
				log.Printf("[CircuitBreaker] RecordError failed: %v", cbErr)
			}
		}
		sendErrorResponse(w, "Orchestrator error: "+err.Error(), http.StatusInternalServerError, nil)
		return
	}

	// Detect orchestrator-level errors (e.g., 409 cancelled, 410 expired, 403 blocked).
	// forwardToOrchestrator returns nil error for any HTTP response with valid JSON,
	// even non-2xx status codes. We must inspect the response body to determine
	// if the orchestrator reported a business-level failure.
	orchSuccess := true
	orchError := ""
	orchHTTPStatus := 200
	orchMap, _ := orchestratorResp.(map[string]interface{})
	if orchMap != nil {
		if s, exists := orchMap["success"]; exists {
			if sb, ok := s.(bool); ok {
				orchSuccess = sb
				if !sb {
					orchHTTPStatus = 500
				}
			}
		}
		if e, exists := orchMap["error"]; exists {
			if es, ok := e.(string); ok && es != "" {
				orchError = es
			}
		}
	}

	// Track request outcome based on orchestrator response
	latencyMs := int64(time.Since(startTime).Milliseconds())
	if orchSuccess {
		if agentMetrics != nil {
			atomic.AddInt64(&agentMetrics.successRequests, 1)
			agentMetrics.recordLatency(latencyMs, "dynamic")
		}
		promRequestsTotal.WithLabelValues("success").Inc()
	} else {
		if agentMetrics != nil {
			atomic.AddInt64(&agentMetrics.failedRequests, 1)
			agentMetrics.recordLatency(latencyMs, "dynamic")
		}
		promRequestsTotal.WithLabelValues("orchestrator_error").Inc()
		log.Printf("[clientRequestHandler] Orchestrator returned error: %s", orchError)
		// Record orchestrator-level error for circuit breaker auto-trip (#1176 Phase 2B)
		// ADR-052 §5 (issue #2318): clientID = credential identity.
		if circuitBreakerInstance != nil {
			if cbErr := circuitBreakerInstance.RecordError(r.Context(), client.OrgID, client.TenantID, client.ClientID); cbErr != nil {
				log.Printf("[CircuitBreaker] RecordError failed: %v", cbErr)
			}
		}
	}
	promPolicyEvaluations.Inc()
	promRequestDuration.WithLabelValues("dynamic").Observe(float64(latencyMs))

	// Issue #1082: Record cost tracking after successful LLM call
	// This updates budget usage so enforcement works on subsequent requests
	// Skip cost recording for orchestrator errors (no LLM call was made)
	if costService != nil && orchSuccess && orchMap != nil {
		if providerInfoRaw, exists := orchMap["provider_info"]; exists {
			if providerInfoMap, ok := providerInfoRaw.(map[string]interface{}); ok {
				// Extract provider info
				provider := ""
				model := ""
				tokensUsed := 0
				costUSD := 0.0

				if p, ok := providerInfoMap["provider"].(string); ok {
					provider = p
				}
				if m, ok := providerInfoMap["model"].(string); ok {
					model = m
				}
				if t, ok := providerInfoMap["tokens_used"].(float64); ok {
					tokensUsed = int(t)
				}
				if c, ok := providerInfoMap["cost"].(float64); ok {
					costUSD = c
				}

				// Record usage if we have token info
				if tokensUsed > 0 || costUSD > 0 {
					// Generate request ID (ClientRequest doesn't have one, generate based on timestamp)
					requestID := fmt.Sprintf("req_%d", time.Now().UnixNano())
					usageRecord := &cost.UsageRecord{
						RequestID: requestID,
						Timestamp: time.Now().UTC(),
						OrgID:     client.OrgID,
						TenantID:  user.TenantID,
						UserID:    fmt.Sprintf("%d", user.ID),
						Provider:  provider,
						Model:     model,
						TokensIn:  tokensUsed / 2, // Approximate split (tokens_used is total)
						TokensOut: tokensUsed / 2,
						CostUSD:   costUSD,
					}

					// Issue #1082: Record synchronously so budget enforcement works on subsequent requests
					// This ensures budget check sees updated usage before allowing next request
					ctx := context.Background()
					if err := costService.RecordUsage(ctx, usageRecord); err != nil {
						log.Printf("💰 [clientRequestHandler] Failed to record usage: %v", err)
					} else {
						log.Printf("💰 [clientRequestHandler] Recorded cost: provider=%s model=%s tokens=%d cost=$%.6f",
							usageRecord.Provider, usageRecord.Model, usageRecord.TokensIn+usageRecord.TokensOut, usageRecord.CostUSD)
					}
				}
			}
		}
	}

	// 7. Detect code artifacts in response (Issue #761: Governed Code Generation)
	var codeArtifact *CodeArtifactMetadata
	if responseContent := extractResponseContent(orchestratorResp); responseContent != "" {
		codeArtifact = DetectCodeInResponse(responseContent)
		if codeArtifact != nil {
			// Evaluate code-specific policies
			policiesChecked, _ := EvaluateCodePolicies(responseContent)
			codeArtifact.PoliciesChecked = policiesChecked
			log.Printf("[AUDIT] Code artifact detected: language=%s, type=%s, size=%d bytes, secrets=%d, unsafe=%d",
				codeArtifact.Language, codeArtifact.CodeType, codeArtifact.SizeBytes,
				codeArtifact.SecretsDetected, codeArtifact.UnsafePatterns)
		}
	}

	// 8. Return response with policy information
	// Issue #1082: Extract "data" field from orchestratorResp (which now contains full response)
	responseData := orchestratorResp
	if orchMap != nil {
		if data, exists := orchMap["data"]; exists {
			responseData = data
		}
	}

	// orchSuccess and orchError were extracted above (after forwardToOrchestrator)
	// and used for metrics, cost tracking, and now the client response.
	response := ClientResponse{
		Success: orchSuccess,
		Data:    responseData,
		Error:   orchError,
		PolicyInfo: &PolicyEvaluationInfo{
			MatchedPolicies:   policyResult.TriggeredPolicies,
			PoliciesEvaluated: policyResult.TriggeredPolicies,
			StaticChecks:      policyResult.ChecksPerformed,
			ProcessingTime:    time.Since(startTime).String(),
			TenantID:          user.TenantID,
			CodeArtifact:      codeArtifact,
		},
		BudgetInfo: budgetInfo, // Issue #1082: Include budget status in response
	}

	// Extract media_analysis from orchestrator response (media governance results)
	if orchMap != nil {
		if mediaAnalysis, exists := orchMap["media_analysis"]; exists && mediaAnalysis != nil {
			response.MediaAnalysis = mediaAnalysis
		}
	}

	// For multi-agent planning requests (GeneratePlan and ExecutePlan), flatten orchestrator response fields to top level
	// This allows client SDKs to access plan_id, result, metadata directly
	if req.RequestType == "multi-agent-plan" || req.RequestType == "execute-plan" {
		if orchMap, ok := orchestratorResp.(map[string]interface{}); ok {
			if planID, exists := orchMap["plan_id"]; exists {
				if planIDStr, ok := planID.(string); ok {
					response.PlanID = planIDStr
				}
			}
			if result, exists := orchMap["result"]; exists {
				// Convert to string to match SDK ClientResponse type
				if resultStr, ok := result.(string); ok {
					response.Result = resultStr
					log.Printf("[DEBUG] Extracted result from orchestrator: type=string, length=%d", len(resultStr))
				} else {
					// Fallback: convert to string representation
					response.Result = fmt.Sprintf("%v", result)
					log.Printf("[WARN] result field is not a string, type=%T, converted to string", result)
				}
			} else {
				log.Printf("[WARN] No 'result' field found in orchestrator response, keys: %v", getKeys(orchMap))
			}
			if metadata, exists := orchMap["metadata"]; exists {
				// Convert to map[string]interface{} to match SDK ClientResponse type
				if metadataMap, ok := metadata.(map[string]interface{}); ok {
					response.Metadata = metadataMap
				} else {
					log.Printf("[WARN] metadata field is not a map, type=%T", metadata)
				}
			}
			if steps, exists := orchMap["steps"]; exists {
				// Convert steps to []interface{} for SDK
				if stepsSlice, ok := steps.([]interface{}); ok {
					response.Steps = stepsSlice
					log.Printf("[DEBUG] Extracted steps from orchestrator: count=%d", len(stepsSlice))
				} else {
					log.Printf("[WARN] steps field is not a slice, type=%T", steps)
				}
			} else {
				log.Printf("[DEBUG] No 'steps' field in orchestrator response (may be expected for failed plans)")
			}
		} else {
			log.Printf("[WARN] orchestratorResp is not a map, type=%T", orchestratorResp)
		}
	}

	log.Printf("[DEBUG] Sending response: Success=%v, ResultType=%T, ResultLength=%d, PlanID=%s",
		response.Success, response.Result, getStringLength(response.Result), response.PlanID)

	// Marshal to bytes to log actual JSON being sent
	responseBytes, err := json.Marshal(response)
	if err != nil {
		log.Printf("[ERROR] Failed to marshal response: %v", err)
		sendErrorResponse(w, "Internal marshaling error", http.StatusInternalServerError, nil)
		return
	}

	// Log JSON structure (truncate result field for readability)
	var logStruct map[string]interface{}
	if err := json.Unmarshal(responseBytes, &logStruct); err == nil {
		if resultVal, ok := logStruct["result"]; ok {
			if resultStr, ok := resultVal.(string); ok && len(resultStr) > 100 {
				logStruct["result"] = resultStr[:100] + "...[truncated]"
			}
		}
		if logJSON, err := json.Marshal(logStruct); err == nil {
			log.Printf("[DEBUG] Actual JSON being sent: %s", string(logJSON))
		}
	}
	log.Printf("[DEBUG] Full response length: %d bytes", len(responseBytes))

	w.Header().Set("Content-Type", "application/json")
	if _, err := w.Write(responseBytes); err != nil {
		log.Printf("Error writing response: %v", err)
	}

	// Record usage asynchronously (don't block response)
	if usageDB != nil && client != nil && client.OrgID != "" {
		go func() {
			recorder := usage.NewUsageRecorder(usageDB)
			instanceID := os.Getenv("HOSTNAME") // Docker container ID
			if instanceID == "" {
				instanceID = "agent-unknown"
			}

			err := recorder.RecordAPICall(usage.APICallEvent{
				OrgID: client.OrgID,
				// ADR-052 §5: usage_events.client_id is the credential identity.
				// Routed through buildAPICallClientID so the field-mapping has
				// a single mutation-testable surface (R3-F1 on PR #2315).
				ClientID:       buildAPICallClientID(client),
				InstanceID:     instanceID,
				InstanceType:   "agent",
				HTTPMethod:     r.Method,
				HTTPPath:       r.URL.Path,
				HTTPStatusCode: orchHTTPStatus,
				LatencyMs:      time.Since(startTime).Milliseconds(),
			})

			if err != nil {
				log.Printf("[USAGE] Failed to record API call: %v", err)
			}
		}()
	}
}

// validateClient was a legacy mock function that accepted any client_id from
// the request body and returned a fake "Demo Client" with the deployment's
// own org_id. It enabled a critical multi-tenant security hole: in enterprise
// mode, any request without Basic auth but with a client_id in the JSON body
// was silently authenticated as that client, with every workflow, audit log,
// and policy decision attributed to the deployment's own org rather than the
// caller's real identity.
//
// Removed in v6.2.0. All handlers now require proper OAuth2 Client Credentials
// (Basic auth with a cryptographically signed license key) or reject the
// request with 401 Unauthorized.

func validateUserToken(tokenString string, expectedTenantID string) (*User, error) {
	// Community mode: Don't require a token for local development
	// Uses DEPLOYMENT_MODE check - simple and clean pattern
	if isCommunityMode() {
		log.Printf("[Community] Authentication bypassed for tenant %s", expectedTenantID)
		return &User{
			ID:          1,
			Email:       "local-dev@axonflow.local",
			Name:        "Local Development User",
			Role:        "admin",
			Region:      "local",
			Permissions: []string{"query", "llm", "mcp_query", "admin"},
			TenantID:    expectedTenantID,
			// v9 Phase 8 #2384 PR-C1: in community mode tenantID == orgID; no
			// separate identity layer is configured.
			OrgID: expectedTenantID,
		}, nil
	} else if isCommunitySaasMode() {
		// Community-SaaS mode: no JWT required — tenant identity comes from Basic auth.
		// v9 Phase 6 (mig 100) sets community_saas_registrations.org_id = tenant_id
		// for every row, so the OrgID == TenantID invariant holds here too.
		return &User{
			ID:          1,
			Email:       "evaluator@try.getaxonflow.com",
			Name:        "Evaluation User",
			Role:        "evaluator",
			Region:      "us-east-1",
			Permissions: []string{"query", "llm", "mcp_query"},
			TenantID:    expectedTenantID,
			OrgID:       expectedTenantID,
		}, nil
	} else if tokenString == "" {
		return nil, fmt.Errorf("token required")
	}

	// Fail closed on an unconfigured secret (#2541 hardening). Reaching here
	// means a non-community deployment that REQUIRES a user_token. If
	// JWT_SECRET is empty, HMAC-validating against the empty key would accept
	// any token forged with that same empty key — so reject every token
	// instead of silently validating forgeries. (Community / Community-SaaS
	// modes returned above and are unaffected.)
	if len(jwtSecret) == 0 {
		return nil, fmt.Errorf("JWT_SECRET not configured; refusing to validate user_token")
	}

	// Validate JWT token using the configured secret.
	// Generate tokens using: scripts/generate-jwt.sh, or the dev-mode endpoint
	// POST /api/v1/dev/token (non-prod only, #2541).
	//
	// Algorithm pinning (#2541 §5.4): the keyfunc asserts the token's signing
	// method is HMAC before returning the symmetric secret, and
	// WithValidMethods pins the accepted algorithm to HS256. Returning the
	// shared secret without checking the method is the classic
	// algorithm-confusion shape; both guards reject alg:none and any
	// non-HS256 (e.g. RS256/ES256) token.
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method %q (only HS256 accepted)", token.Header["alg"])
		}
		return jwtSecret, nil
	}, jwt.WithValidMethods([]string{"HS256"}))

	if err != nil || !token.Valid {
		return nil, fmt.Errorf("invalid token: %v", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("invalid token claims")
	}

	// Extract user information from token
	// In production, you might need to fetch additional details from database
	tenantID := getClaimString(claims, "tenant_id")
	if tenantID == "" {
		// Tenant-inherit (#2541 §2): when the token omits the tenant_id claim,
		// default to the authenticated credential's tenant (the Basic-auth
		// username, passed as expectedTenantID) rather than the legacy
		// "tenant_1" sentinel. This way a token minted without an explicit
		// tenant_id still satisfies the tenant_id == username binding enforced
		// at gateway_handlers.go:443 / decision_handler.go:304, instead of
		// being rejected as a mismatch. The explicit (claim-present) path is
		// unchanged.
		if expectedTenantID != "" {
			tenantID = expectedTenantID
		} else {
			tenantID = "tenant_1" // last-resort legacy fallback (no credential tenant available)
		}
	}
	// v9 Phase 8 #2384 PR-C1: org_id claim — populated by callers running v9
	// JWTs (post-v9 stack). For legacy JWTs without an org_id claim we fall
	// back to tenantID to preserve the OrgID == TenantID invariant of mig 100.
	orgID := getClaimString(claims, "org_id")
	if orgID == "" {
		orgID = tenantID
	}

	// #2924 R3: revocation takes effect on this plane too. A per-user token
	// minted by the provisioning API carries a jti; if it (or the user's
	// tokens en masse) has been revoked, reject here — not only exp closes it.
	// No-op for jti-less legacy tokens and community builds; fails closed on a
	// revocation-store error (checkUserTokenRevoked).
	if err := checkUserTokenRevoked(claims, orgID); err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	// Extract user_id - handle both string and numeric types
	var userID int
	switch v := claims["user_id"].(type) {
	case float64:
		userID = int(v)
	case string:
		userID = 1 // Default for string-based user IDs
	default:
		userID = 1
	}

	return &User{
		ID:          userID,
		Email:       getClaimString(claims, "email"),
		Name:        getClaimString(claims, "name"),
		Department:  getClaimString(claims, "department"),
		Role:        getClaimString(claims, "role"),
		Region:      getClaimString(claims, "region"),
		Permissions: getClaimStringArray(claims, "permissions"),
		TenantID:    tenantID,
		OrgID:       orgID,
	}, nil
}

// checkRateLimit moved to auth.go as part of license-based authentication

func forwardToOrchestrator(req ClientRequest, user *User, client *Client) (interface{}, error) {
	// Prepare orchestrator request
	// Copy context and add plan_id if present (for execute-plan requests)
	context := req.Context
	if req.PlanID != "" {
		if context == nil {
			context = make(map[string]interface{})
		}
		context["plan_id"] = req.PlanID
	}
	orchestratorReq := map[string]interface{}{
		"query":        req.Query,
		"user":         user,
		"client":       client,
		"request_type": req.RequestType,
		"skip_llm":     req.SkipLLM,
		"context":      context,
		"request_id":   fmt.Sprintf("req_%d", time.Now().UnixNano()),
	}

	// Forward media items (images) to orchestrator for media governance analysis
	if len(req.Media) > 0 {
		orchestratorReq["media"] = req.Media
	}

	jsonData, err := json.Marshal(orchestratorReq)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %v", err)
	}

	// Determine orchestrator endpoint based on request type
	var orchEndpoint string
	switch req.RequestType {
	case "multi-agent-plan", "generate-plan":
		// Route GeneratePlan requests to /api/v1/plan (stores plan without executing)
		orchEndpoint = "/api/v1/plan"
		log.Printf("[ROUTING] GeneratePlan request detected, routing to %s", orchEndpoint)
	case "execute-plan":
		// Route ExecutePlan requests to /api/v1/plan/execute (executes stored plan)
		orchEndpoint = "/api/v1/plan/execute"
		log.Printf("[ROUTING] ExecutePlan request detected, routing to %s", orchEndpoint)
	default:
		// Route all other requests (sql, chat, completion, embedding) to /api/v1/process
		orchEndpoint = "/api/v1/process"
	}

	// Make HTTP call to orchestrator
	orchURL := orchestratorURL + orchEndpoint
	log.Printf("🚀 Forwarding to orchestrator: %s (ClientID: %s, Type: %s, SkipLLM: %v)", orchURL, req.ClientID, req.RequestType, req.SkipLLM)
	orchReq, err := http.NewRequest("POST", orchURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create orchestrator request: %v", err)
	}
	orchReq.Header.Set("Content-Type", "application/json")

	// #3179: stamp the VALIDATED per-user identity onto this hop.
	//
	// validateUserToken has already resolved `user` from verified HS256 claims
	// a few lines above. Until now this forward passed that identity only in the
	// request BODY — a channel the orchestrator cannot distinguish from a
	// client-chosen one, which is exactly what #3152 removed as a trust source.
	// Without this the governed plane would be left with NO identity channel at
	// all: audit_logs.user_email would go empty on POST /api/request, and a
	// {user.role not_in <privileged>} policy would stop EXEMPTING a caller whose
	// JWT says they are privileged.
	//
	// This is not a new forgeable channel. The request is constructed fresh at
	// http.NewRequest above — nothing is copied from the inbound request — so
	// these headers cannot carry a client-supplied value. The competing reverse-
	// proxy path (proxy.go) Dels both headers unconditionally and re-Sets them
	// only from a cryptographically validated per-user token.
	//
	// SAFE ON THE AUTHORIZATION AXIS, established rather than assumed: the role
	// header is consumed for authorization only by read_scope.go:280
	// (RoleCanReadTenant -> AdminAuthority), which runs inside
	// resolveCallerReadScope — called only from the audit / decisions / explain
	// read handlers. This forward targets exactly /api/v1/process, /api/v1/plan
	// and /api/v1/plan/execute, none of which call it and none of which appear
	// in gatedDomainRoutes or tenantWideAuditExportPaths. So the "admin" that
	// community mode synthesises, and the "evaluator" community-SaaS mints,
	// cannot become read authority here. They remain what they already were on
	// this plane: a value policy conditions may match on.
	//
	// NB the JWT `role` claim is NOT vocabulary-normalised (getClaimString is
	// verbatim, unlike the per-user-token path's identity.NormalizeRole). That
	// is acceptable for policy matching and would NOT be acceptable for an
	// authorization decision — which is the reason the paragraph above has to
	// hold, not merely be likely.
	if user != nil {
		if user.Email != "" {
			orchReq.Header.Set("X-User-Email", user.Email)
		}
		if user.Role != "" {
			orchReq.Header.Set(sharedidentity.HeaderUserRole, user.Role)
		}
	}
	// #3068: prove this hop came from the Agent. This is the MAIN governance
	// forward (/api/v1/process, /api/v1/plan, /api/v1/plan/execute) and it is
	// NOT the reverse proxy — proxy.go's Director never runs for it, so it was
	// the one agent→orchestrator path that stamped no internal-service token.
	// The orchestrator now requires one on every non-exempt route
	// (requireInternalProxyAuth), so without this the governed request path
	// itself would 403. Mirrors the MCP forwarders in mcp_server_handler.go.
	if proxyTokenGenerator != nil {
		orchReq.Header.Set("X-Axonflow-Proxy-Auth", serviceauth.GetInternalServiceToken(proxyTokenGenerator))
	}
	// Forward tenant/org/client context so orchestrator handlers can access them.
	// X-Org-ID comes from the authenticated client's license (client.OrgID),
	// matching the Single Entry Point proxy behavior in proxy.go. This enables
	// multi-tenant SaaS where one deployment serves many orgs, each scoped by
	// their own cryptographically validated license. X-Client-ID is the v9
	// successor of X-Tenant-ID (ADR-052 §5 / ADR-053 §Step 2); both are
	// emitted during the v9 compatibility window.
	if user != nil && user.TenantID != "" {
		orchReq.Header.Set("X-Tenant-ID", user.TenantID)
	}
	if client != nil {
		if client.OrgID != "" {
			orchReq.Header.Set("X-Org-ID", client.OrgID)
		}
		if (user == nil || user.TenantID == "") && client.TenantID != "" {
			orchReq.Header.Set("X-Tenant-ID", client.TenantID)
		}
		// v9 ADR-052: prefer ClientID (the canonical field) and fall
		// back to ID for the compat window where every auth path sets
		// both to the same value. Future code that diverges the two
		// MUST land here intentionally.
		if v := client.ClientID; v != "" {
			orchReq.Header.Set("X-Client-ID", v)
		} else if client.ID != "" {
			orchReq.Header.Set("X-Client-ID", client.ID)
		}
	}
	resp, err := http.DefaultClient.Do(orchReq)
	if err != nil {
		log.Printf("❌ ERROR: Failed to call orchestrator at %s: %v", orchURL, err)
		return nil, fmt.Errorf("orchestrator connection failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	log.Printf("✅ Orchestrator responded with status: %d", resp.StatusCode)

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode orchestrator response: %v", err)
	}

	// Issue #1082: Return full response to preserve provider_info for cost tracking
	// The caller will extract "data" as needed, but provider_info is accessible
	return result, nil
}

func listClientsHandler(w http.ResponseWriter, r *http.Request) {
	// Mock client list
	clients := []Client{
		{
			ID:          "client_1",
			Name:        "Customer Support App",
			TenantID:    "tenant_1",
			Permissions: []string{"query", "llm"},
			RateLimit:   100,
			Enabled:     true,
		},
		{
			ID:          "client_2",
			Name:        "Healthcare Analytics",
			TenantID:    "tenant_2",
			Permissions: []string{"query", "llm", "rag"},
			RateLimit:   50,
			Enabled:     true,
		},
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(clients); err != nil {
		log.Printf("Error encoding clients response: %v", err)
	}
}

func createClientHandler(w http.ResponseWriter, r *http.Request) {
	var client Client
	if err := json.NewDecoder(r.Body).Decode(&client); err != nil {
		sendErrorResponse(w, "Invalid request body", http.StatusBadRequest, nil)
		return
	}

	// In production, save to database
	client.Enabled = true

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	if err := json.NewEncoder(w).Encode(client); err != nil {
		log.Printf("Error encoding client response: %v", err)
	}
}

// appendTriggeredPolicyID appends policyID to triggered, unless it is
// already present. #3296 Slice 2 Step D: Phase 1 (the shared engine) and
// Phase 2 (the tier-aware engine) both read static_policies and can each
// independently match the SAME policy ID when their category coverage
// overlaps (see the Step D doc comment above clientRequestHandler's Phase
// 1/2 evaluation block for why the two phases were not collapsed into one
// pass) — a bare append let that policy ID appear twice in
// triggered_policies / matched_policies. This is a reporting-only dedupe: it
// never changes Blocked/Reason/Severity, which are already set independently
// by whichever phase produced them.
func appendTriggeredPolicyID(triggered []string, policyID string) []string {
	for _, id := range triggered {
		if id == policyID {
			return triggered
		}
	}
	return append(triggered, policyID)
}

func policyTestHandler(w http.ResponseWriter, r *http.Request) {
	var testReq struct {
		Query       string `json:"query"`
		UserEmail   string `json:"user_email"`
		RequestType string `json:"request_type"`
	}

	if err := json.NewDecoder(r.Body).Decode(&testReq); err != nil {
		sendErrorResponse(w, "Invalid request body", http.StatusBadRequest, nil)
		return
	}

	// Derive tenant from auth context (set by apiAuthMiddleware or community default)
	tenantID := TenantIDFromContext(r.Context())
	if tenantID == "" {
		tenantID = "community" // default for community mode
	}
	// #3255: the org this preview evaluates under comes from the
	// AUTHENTICATED context, never from the tenant string. On the enterprise
	// service-license path the two differ: TenantID is the Basic-Auth
	// username the caller chooses (db_auth.go), while OrgID is validated from
	// the license (auth.go). This value is passed to the segment resolver
	// below, whose lookup is scoped by exactly this argument (SQL predicate
	// and RLS GUC alike), so a tenant-sourced org let the caller choose whose
	// directory the preview read - and the wrong org also silently matched
	// nothing, making the preview under-report segment-scoped policies.
	// The fallback preserves the previous behavior only where no authenticated
	// org exists (the community shape, where tenant is not caller-influenced).
	orgID := OrgIDFromContext(r.Context())
	if orgID == "" {
		orgID = tenantID
	}
	testUser := &User{
		Email:       testReq.UserEmail,
		Role:        "agent",
		Permissions: []string{"query"},
		TenantID:    tenantID,
		OrgID:       orgID,
	}

	// #3051 (ADR-060 P3) + #3266 + #3293: resolve segments for the
	// caller-supplied testReq.UserEmail ONCE, up front, so both Phase 1 (the
	// shared engine) and Phase 2 (the tier-aware engine) simulate against
	// the SAME membership set — matching what /api/request actually does for
	// that user. The preview is now FULLY CONVERGED with the real request
	// plane on both axes: Phase 1 is segment-aware (Segments: segmentIDs
	// below, same as clientRequestHandler) and resolution failures are
	// fail-closed (failClosed=true below, same contract as the enforcement
	// path) rather than the old fail-open "simulate org-only" carve-out.
	//
	// #3293 invariant: a resolution FAILURE must never reach either engine
	// as a nil/empty segment set. Unlike clientRequestHandler — which DENIES
	// the real request outright on segOK=false — this preview is a DRY-RUN:
	// nothing is actually being granted or enforced against
	// testReq.UserEmail, so there's nothing to deny. Instead, on segOK=false
	// this handler short-circuits BEFORE calling either engine and reports
	// the SIMULATED VERDICT a real /api/request call would produce: a normal
	// 200 response (matching this endpoint's existing shape) with
	// blocked=true and a fail-closed reason. That keeps the #3293 invariant
	// (no possibly-failed set ever reaches Phase 1 or Phase 2) while still
	// answering the preview's actual question — "what would happen?" — with
	// "the caller would be denied."
	//
	// Coordination with #3239: the preview's fail-closed convergence and
	// Phase-1 segment-awareness both live HERE now, not split across #3239 —
	// #3239 predates EvalOptions.Segments and can only do the Phase-2 half.
	// #3239 will be slimmed to drop its now-redundant copy of this
	// convergence and drops the failClosed param resolveUserSegments used to
	// take here; that signature change is expected to land as a follow-up
	// rebase, not a conflict in this file's logic.
	//
	// Signal B — segments_resolved (#3239 M4, ported here as part of the same
	// consolidation): an INFORMATIONAL flag in the response, entirely
	// distinct from the fail-closed deny above (Signal A). It answers "did a
	// real, non-empty segment membership set actually factor into this
	// verdict?" — true only when resolution succeeded AND returned at least
	// one segment; false for every legitimate org-only case (no tier engine,
	// no email supplied, no resolver configured, zero group memberships) AND
	// for the fail-closed-deny path. It lets an admin reading the preview
	// tell "allowed because no segment restricted this" apart from "allowed
	// and a segment was genuinely considered" — it never itself changes the
	// verdict.
	segmentIDs, segOK := resolveUserSegmentsForPreview(r.Context(), testUser.OrgID, testReq.UserEmail)
	segmentsResolved := false

	var result *StaticPolicyResult
	if !segOK {
		log.Printf("🛡️ Policy test: segment resolution failed for %q — simulating the fail-closed deny a real /api/request call would produce (ADR-060 #2989)", logutil.Sanitize(testReq.UserEmail))
		result = &StaticPolicyResult{
			Blocked:           true,
			Reason:            "segment resolution unavailable — a real request would be denied (fail-closed, ADR-060 #2989)",
			TriggeredPolicies: []string{"segment_resolution_failed"},
		}
	} else {
		segmentsResolved = len(segmentIDs) > 0
		// Two-phase evaluation (same as proxy handler — uses shared engine as primary)
		// #2581: resolve per-org posture (org with no override → deployment-global).
		gatewayDetectionCfg := ResolveGatewayDetectionConfig(r.Context(), testUser.OrgID)
		sharedEngine := sharedpolicy.GetGlobalEngine()
		if !gatewayDetectionCfg.Enabled {
			result = &StaticPolicyResult{}
		} else if sharedEngine != nil {
			skipCats := append([]sharedpolicy.PolicyCategory(nil), gatewayDetectionCfg.SkipCategories...)
			// #3001: same shared predicate as the real request plane above. This
			// handler exists to SIMULATE enforcement, so a literal here would make
			// the simulation disagree with what actually happens for an `owner`.
			if sharedidentity.RoleIsAdministrative(testUser.Role) {
				skipCats = append(skipCats, sharedpolicy.CategoryAdminAccess)
			}
			requestResult := sharedEngine.EvaluateRequest(r.Context(), testReq.Query, sharedpolicy.EvalOptions{
				TenantID:        testUser.TenantID,
				OrgID:           testUser.OrgID,
				OrgScope:        sharedpolicy.OrgScopePtr(testUser.OrgID), // #3048 R3 HIGH-3 (N2)
				ConnectorName:   "proxy",
				UserID:          fmt.Sprintf("%d", testUser.ID),
				Categories:      proxyPolicyCategories,
				SkipCategories:  skipCats,
				ActionOverrides: gatewayDetectionCfg.BuildActionOverrides(),
				// #3266: the caller's resolved governance-segment set (above,
				// guaranteed successfully-resolved by the segOK branch), same
				// as clientRequestHandler — a segment-scoped static_policies
				// row can only match/report for a member.
				Segments: segmentIDs,
			})
			result = convertSharedResultToStatic(requestResult)
		} else {
			log.Println("[PolicyTest] WARNING: No policy engine available")
			result = &StaticPolicyResult{}
		}

		// Phase 2: Tier-aware policies (if not blocked and engine available)
		if !result.Blocked && tierAwarePolicyEngine != nil {
			ctx := r.Context()
			// Decision 5 (#3490): same org argument the live plane passes (see
			// clientRequestHandler's Phase 2). A policy TEST that evaluated a
			// different policy set from the live path would be worse than no test.
			tierResult, err := tierAwarePolicyEngine.EvaluatePolicy(ctx, testUser.TenantID, sharedpolicy.OrgScopePtr(testUser.OrgID), segmentIDs, testReq.Query)
			if err != nil {
				log.Printf("⚠️ Tier-aware policy test error: %v", err)
			} else if tierResult.Matched && tierResult.Action == "block" {
				result.Blocked = true
				result.Reason = fmt.Sprintf("Blocked by %s policy: %s", tierResult.Tier, tierResult.PolicyName)
				result.TriggeredPolicies = appendTriggeredPolicyID(result.TriggeredPolicies, tierResult.PolicyID)
				result.Severity = tierResult.Severity
			} else if tierResult.Matched {
				result.TriggeredPolicies = appendTriggeredPolicyID(result.TriggeredPolicies, tierResult.PolicyID)
			}
		}
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]interface{}{
		"blocked":            result.Blocked,
		"reason":             result.Reason,
		"triggered_policies": result.TriggeredPolicies,
		"checks_performed":   result.ChecksPerformed,
		"processing_time_ms": result.ProcessingTimeMs,
		"segments_resolved":  segmentsResolved,
	}); err != nil {
		log.Printf("Error encoding policy test response: %v", err)
	}
}

// Utility functions
func sendErrorResponse(w http.ResponseWriter, message string, statusCode int, policyInfo *PolicyEvaluationInfo) {
	response := ClientResponse{
		Success:    false,
		Error:      message,
		PolicyInfo: policyInfo,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Printf("Error encoding error response: %v", err)
	}
}

// circuitBreakerRetryAfter computes a Retry-After value in seconds from the circuit's ExpiresAt.
// Returns empty string for indefinite/manual trips (no ExpiresAt) so the header is omitted.
func circuitBreakerRetryAfter(expiresAt *time.Time) string {
	if expiresAt == nil {
		return ""
	}
	seconds := int(time.Until(*expiresAt).Seconds())
	if seconds < 1 {
		seconds = 1
	}
	return fmt.Sprintf("%d", seconds)
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// getOrchestratorURL returns the Orchestrator URL based on environment.
// Priority:
// 1. ORCHESTRATOR_URL env var (explicit override, required for ECS/K8s)
// 2. Docker detection (/.dockerenv or hex hostname) → axonflow-orchestrator:8081
// 3. Fallback to localhost:8081 for local development
func getOrchestratorURL() string {
	// Check for explicit override first (required for ECS, Kubernetes, etc.)
	if envURL := os.Getenv("ORCHESTRATOR_URL"); envURL != "" {
		log.Printf("[Agent] Using ORCHESTRATOR_URL from env: %s", envURL)
		return envURL
	}
	// Auto-detect Docker Compose environments
	if isRunningInDocker() {
		log.Printf("[Agent] Docker detected, using orchestrator URL: %s", DefaultOrchestratorURL)
		return DefaultOrchestratorURL
	}
	log.Printf("[Agent] Local mode, using orchestrator URL: %s", LocalOrchestratorURL)
	return LocalOrchestratorURL
}

// isRunningInDocker detects if the process is running inside a Docker container
func isRunningInDocker() bool {
	// Method 1: Check for /.dockerenv file (most reliable)
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return true
	}

	// Method 2: Check if HOSTNAME looks like a container ID (12+ hex chars)
	hostname := os.Getenv("HOSTNAME")
	if len(hostname) >= 12 {
		isHex := true
		for _, c := range hostname[:12] {
			if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
				isHex = false
				break
			}
		}
		if isHex {
			return true
		}
	}

	return false
}

func getClaimString(claims jwt.MapClaims, key string) string {
	if val, ok := claims[key].(string); ok {
		return val
	}
	return ""
}

func getClaimStringArray(claims jwt.MapClaims, key string) []string {
	// Handle JSON array (from standard JWT)
	if arr, ok := claims[key].([]interface{}); ok {
		result := make([]string, 0, len(arr))
		for _, v := range arr {
			if s, ok := v.(string); ok {
				result = append(result, s)
			}
		}
		return result
	}
	// Handle comma-separated string (legacy format)
	if val, ok := claims[key].(string); ok {
		if val == "" {
			return []string{}
		}
		return strings.Split(val, ",")
	}
	return []string{}
}

// metricsHandler returns real-time performance metrics
func metricsHandler(w http.ResponseWriter, r *http.Request) {
	// Safety check for nil metrics
	if agentMetrics == nil {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]interface{}{
			"error":     "Metrics not initialized",
			"timestamp": time.Now().UTC(),
		}); err != nil {
			log.Printf("Error encoding metrics error response: %v", err)
		}
		return
	}

	agentMetrics.mu.RLock()

	// Calculate metrics
	uptime := time.Since(agentMetrics.startTime).Seconds()
	totalReqs := atomic.LoadInt64(&agentMetrics.totalRequests)
	successReqs := atomic.LoadInt64(&agentMetrics.successRequests)
	failedReqs := atomic.LoadInt64(&agentMetrics.failedRequests)
	blockedReqs := atomic.LoadInt64(&agentMetrics.blockedRequests)

	// Calculate RPS
	rps := float64(0)
	if uptime > 0 {
		rps = float64(totalReqs) / uptime
	}

	// Calculate comprehensive latency percentiles (P50, P95, P99)
	staticP50 := calculateP50(agentMetrics.staticPolicyLatencies)
	staticP95 := calculateP95(agentMetrics.staticPolicyLatencies)
	staticP99 := calculateP99(agentMetrics.staticPolicyLatencies)
	avgLatency := calculateAverage(agentMetrics.lastLatencies)

	// Overall latency percentiles
	overallP50 := calculateP50(agentMetrics.lastLatencies)
	overallP95 := calculateP95(agentMetrics.lastLatencies)
	overallP99 := calculateP99(agentMetrics.lastLatencies)

	// Calculate per-stage metrics
	authP50 := calculateP50(agentMetrics.authTimings)
	authP95 := calculateP95(agentMetrics.authTimings)
	authP99 := calculateP99(agentMetrics.authTimings)
	authAvg := calculateAverage(agentMetrics.authTimings)

	staticPolicyP50 := calculateP50(agentMetrics.staticPolicyTimings)
	staticPolicyP95 := calculateP95(agentMetrics.staticPolicyTimings)
	staticPolicyP99 := calculateP99(agentMetrics.staticPolicyTimings)
	staticPolicyAvg := calculateAverage(agentMetrics.staticPolicyTimings)

	networkP50 := calculateP50(agentMetrics.networkTimings)
	networkP95 := calculateP95(agentMetrics.networkTimings)
	networkP99 := calculateP99(agentMetrics.networkTimings)
	networkAvg := calculateAverage(agentMetrics.networkTimings)

	// Calculate error rate (errors per second over last 60 seconds)
	errorRate := calculateErrorRate(agentMetrics.errorTimestamps)

	// Success rate
	successRate := float64(100.0)
	if totalReqs > 0 {
		successRate = float64(successReqs) * 100.0 / float64(totalReqs)
	}

	// Health status determination
	isHealthy := true
	healthStatus := "healthy"
	if agentMetrics.consecutiveErrors > 5 {
		isHealthy = false
		healthStatus = "degraded"
	}
	if agentMetrics.consecutiveErrors > 10 {
		healthStatus = "unhealthy"
	}

	// Release read lock before calling methods that acquire their own locks
	errorTimestampsCopy := make([]time.Time, len(agentMetrics.errorTimestamps))
	copy(errorTimestampsCopy, agentMetrics.errorTimestamps)
	agentMetrics.mu.RUnlock()

	// Get request type and connector metrics (these methods acquire their own locks)
	requestTypeMetrics := agentMetrics.getRequestTypeMetrics()
	connectorMetrics := agentMetrics.getConnectorMetrics()

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]interface{}{
		"agent_metrics": map[string]interface{}{
			// Core counters
			"uptime_seconds":   uptime,
			"total_requests":   totalReqs,
			"success_requests": successReqs,
			"failed_requests":  failedReqs,
			"blocked_requests": blockedReqs,
			"success_rate":     successRate,
			"rps":              rps,

			// Error rate (NEW - for Grafana error rate panel)
			"error_rate_per_sec": errorRate,

			// Overall latency percentiles (NEW - complete distribution)
			"p50_ms":         overallP50,
			"p95_ms":         overallP95,
			"p99_ms":         overallP99,
			"avg_latency_ms": avgLatency,

			// Legacy static policy metrics (backward compatibility)
			"static_policy_p50_ms": staticP50,
			"static_policy_p95_ms": staticP95,
			"static_policy_p99_ms": staticP99,

			// Per-stage authentication metrics
			"auth_p50_ms": authP50,
			"auth_p95_ms": authP95,
			"auth_p99_ms": authP99,
			"auth_avg_ms": authAvg,

			// Per-stage static policy evaluation metrics
			"static_policy_eval_p50_ms": staticPolicyP50,
			"static_policy_eval_p95_ms": staticPolicyP95,
			"static_policy_eval_p99_ms": staticPolicyP99,
			"static_policy_eval_avg_ms": staticPolicyAvg,

			// Per-stage network metrics
			"network_p50_ms": networkP50,
			"network_p95_ms": networkP95,
			"network_p99_ms": networkP99,
			"network_avg_ms": networkAvg,
		},

		// Health status (NEW - for Grafana health status panel)
		"health": map[string]interface{}{
			"status":             healthStatus,
			"healthy":            isHealthy,
			"consecutive_errors": agentMetrics.consecutiveErrors,
			"up":                 1, // Always 1 if responding (for Prometheus up metric)
		},

		// Request type breakdown (NEW - for detailed analysis)
		"request_types": requestTypeMetrics,

		// Connector metrics (NEW - for per-connector dashboards)
		"connectors": connectorMetrics,

		"timestamp": time.Now().UTC(),
	}); err != nil {
		log.Printf("Error encoding metrics response: %v", err)
	}
}

// Helper function to calculate P99
func calculateP99(latencies []int64) float64 {
	if len(latencies) == 0 {
		return 0
	}

	// Make a copy to avoid modifying original
	sorted := make([]int64, len(latencies))
	copy(sorted, latencies)

	// Simple bubble sort for small arrays
	for i := 0; i < len(sorted); i++ {
		for j := i + 1; j < len(sorted); j++ {
			if sorted[i] > sorted[j] {
				sorted[i], sorted[j] = sorted[j], sorted[i]
			}
		}
	}

	// Get 99th percentile
	idx := int(float64(len(sorted)) * 0.99)
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}

	// Return P99 in milliseconds
	return float64(sorted[idx])
}

// Helper function to calculate average
func calculateAverage(latencies []int64) float64 {
	if len(latencies) == 0 {
		return 0
	}

	var sum int64
	for _, lat := range latencies {
		sum += lat
	}

	// Return average in milliseconds
	return float64(sum) / float64(len(latencies))
}

// calculatePercentile calculates any percentile from latencies
func calculatePercentile(latencies []int64, percentile float64) float64 {
	if len(latencies) == 0 {
		return 0
	}

	// Make a copy to avoid modifying original
	sorted := make([]int64, len(latencies))
	copy(sorted, latencies)

	// Simple sort (use sort package for larger arrays in future)
	for i := 0; i < len(sorted); i++ {
		for j := i + 1; j < len(sorted); j++ {
			if sorted[i] > sorted[j] {
				sorted[i], sorted[j] = sorted[j], sorted[i]
			}
		}
	}

	// Calculate index for given percentile
	idx := int(float64(len(sorted)) * percentile)
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}

	return float64(sorted[idx])
}

// calculateP50 calculates the 50th percentile (median)
func calculateP50(latencies []int64) float64 {
	return calculatePercentile(latencies, 0.50)
}

// calculateP95 calculates the 95th percentile
func calculateP95(latencies []int64) float64 {
	return calculatePercentile(latencies, 0.95)
}

// calculateErrorRate calculates errors per second over the last minute
func calculateErrorRate(errorTimestamps []time.Time) float64 {
	if len(errorTimestamps) == 0 {
		return 0
	}

	// Count errors in last 60 seconds
	cutoff := time.Now().Add(-60 * time.Second)
	count := 0
	for _, ts := range errorTimestamps {
		if ts.After(cutoff) {
			count++
		}
	}

	// Return errors per second
	return float64(count) / 60.0
}

// recordError records an error timestamp for error rate calculation
//
//nolint:unused // Used in tests
func (m *AgentMetrics) recordError() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.errorTimestamps = append(m.errorTimestamps, time.Now())

	// Keep only last 1000 error timestamps
	if len(m.errorTimestamps) > 1000 {
		m.errorTimestamps = m.errorTimestamps[len(m.errorTimestamps)-1000:]
	}

	// Update consecutive error tracking
	m.consecutiveErrors++
}

// recordSuccess resets consecutive error counter
//
//nolint:unused // Used in tests
func (m *AgentMetrics) recordSuccess() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.consecutiveErrors = 0
}

// recordRequestTypeMetrics records metrics for a specific request type
//
//nolint:unused // Used in tests
func (m *AgentMetrics) recordRequestTypeMetrics(requestType string, latencyMs int64, success bool, blocked bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.requestTypeCounters == nil {
		m.requestTypeCounters = make(map[string]*RequestTypeMetrics)
	}

	if _, exists := m.requestTypeCounters[requestType]; !exists {
		m.requestTypeCounters[requestType] = &RequestTypeMetrics{
			Latencies: make([]int64, 0, 1000),
		}
	}

	rtm := m.requestTypeCounters[requestType]
	rtm.TotalRequests++

	if blocked {
		rtm.BlockedRequests++
	} else if success {
		rtm.SuccessRequests++
	} else {
		rtm.FailedRequests++
	}

	// Record latency
	rtm.Latencies = append(rtm.Latencies, latencyMs)
	if len(rtm.Latencies) > 1000 {
		rtm.Latencies = rtm.Latencies[1:]
	}
}

// recordConnectorMetrics records metrics for a specific MCP connector
//
//nolint:unused // Used in tests
func (m *AgentMetrics) recordConnectorMetrics(connector string, latencyMs int64, success bool, errMsg string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.connectorMetrics == nil {
		m.connectorMetrics = make(map[string]*ConnectorMetrics)
	}

	if _, exists := m.connectorMetrics[connector]; !exists {
		m.connectorMetrics[connector] = &ConnectorMetrics{
			ConnectorName: connector,
			Latencies:     make([]int64, 0, 1000),
		}
	}

	cm := m.connectorMetrics[connector]
	cm.TotalRequests++

	if success {
		cm.SuccessRequests++
	} else {
		cm.FailedRequests++
		cm.LastError = errMsg
		cm.LastErrorTime = time.Now()
	}

	// Record latency
	cm.Latencies = append(cm.Latencies, latencyMs)
	if len(cm.Latencies) > 1000 {
		cm.Latencies = cm.Latencies[1:]
	}
}

// getRequestTypeMetrics returns a map of request type metrics for export
func (m *AgentMetrics) getRequestTypeMetrics() map[string]map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make(map[string]map[string]interface{})

	for name, rtm := range m.requestTypeCounters {
		successRate := float64(100.0)
		if rtm.TotalRequests > 0 {
			successRate = float64(rtm.SuccessRequests) * 100.0 / float64(rtm.TotalRequests)
		}

		result[name] = map[string]interface{}{
			"total_requests":   rtm.TotalRequests,
			"success_requests": rtm.SuccessRequests,
			"failed_requests":  rtm.FailedRequests,
			"blocked_requests": rtm.BlockedRequests,
			"success_rate":     successRate,
			"p50_ms":           calculateP50(rtm.Latencies),
			"p95_ms":           calculateP95(rtm.Latencies),
			"p99_ms":           calculateP99(rtm.Latencies),
			"avg_ms":           calculateAverage(rtm.Latencies),
		}
	}

	return result
}

// getConnectorMetrics returns a map of connector metrics for export
func (m *AgentMetrics) getConnectorMetrics() map[string]map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make(map[string]map[string]interface{})

	for name, cm := range m.connectorMetrics {
		successRate := float64(100.0)
		if cm.TotalRequests > 0 {
			successRate = float64(cm.SuccessRequests) * 100.0 / float64(cm.TotalRequests)
		}

		result[name] = map[string]interface{}{
			"total_requests":   cm.TotalRequests,
			"success_requests": cm.SuccessRequests,
			"failed_requests":  cm.FailedRequests,
			"success_rate":     successRate,
			"p50_ms":           calculateP50(cm.Latencies),
			"p95_ms":           calculateP95(cm.Latencies),
			"p99_ms":           calculateP99(cm.Latencies),
			"avg_ms":           calculateAverage(cm.Latencies),
			"last_error":       cm.LastError,
			"last_error_time":  cm.LastErrorTime,
		}
	}

	return result
}

// maskString masks a string for logging (shows first 8 chars and last 4)
func maskString(s string) string {
	if s == "" {
		return "<empty>"
	}
	if len(s) <= 12 {
		return s[:4] + "***"
	}
	return s[:8] + "..." + s[len(s)-4:]
}

// truncateString truncates a string for logging
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

func getStringLength(v interface{}) int {
	if v == nil {
		return 0
	}
	if str, ok := v.(string); ok {
		return len(str)
	}
	return -1
}

func getKeys(m map[string]interface{}) []string {
	if m == nil {
		return []string{}
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// encodePostgreSQLPassword manually parses a PostgreSQL URL and encodes the password
// This is necessary because CloudFormation resolves Secrets Manager passwords without URL encoding,
// and special characters in passwords (like ;, <, >, &, etc.) cause url.Parse() to fail.
//
// PostgreSQL URL format: postgresql://username:password@host:port/database?params
//
// We cannot use url.Parse() directly because it fails when the password contains unencoded special chars.
// Instead, we manually extract the password, encode it, and reconstruct the URL.
//
//nolint:unused // Used in tests
func encodePostgreSQLPassword(dbURL string) string {
	// Find the scheme end (://)
	schemeEnd := strings.Index(dbURL, "://")
	if schemeEnd == -1 {
		log.Printf("⚠️  Database URL missing scheme (://), using as-is")
		return dbURL
	}

	// Extract scheme (postgresql)
	scheme := dbURL[:schemeEnd+3] // Include ://

	// Find the @ that separates userinfo from host
	atIndex := strings.Index(dbURL[schemeEnd+3:], "@")
	if atIndex == -1 {
		log.Printf("⚠️  Database URL missing @ separator, using as-is")
		return dbURL
	}
	atIndex += schemeEnd + 3 // Adjust for offset

	// Extract userinfo (username:password)
	userInfo := dbURL[schemeEnd+3 : atIndex]

	// Find the : that separates username from password
	colonIndex := strings.Index(userInfo, ":")
	if colonIndex == -1 {
		// No password, just username
		log.Println("✓ Database URL has no password, no encoding needed")
		return dbURL
	}

	// Extract username and password
	username := userInfo[:colonIndex]
	password := userInfo[colonIndex+1:]

	// Extract everything after @
	hostAndRest := dbURL[atIndex+1:]

	// Use url.UserPassword() for proper userinfo encoding
	// This is the CORRECT way to encode passwords for username:password@host URLs
	// url.QueryEscape() is WRONG - it's for query parameters, not userinfo
	userPassword := url.UserPassword(username, password)
	encodedUserInfo := userPassword.String()

	// Reconstruct the URL
	reconstructed := scheme + encodedUserInfo + "@" + hostAndRest

	log.Printf("✓ Database URL password encoded using url.UserPassword() (%d chars → %d chars)",
		len(password), len(encodedUserInfo))

	return reconstructed
}
