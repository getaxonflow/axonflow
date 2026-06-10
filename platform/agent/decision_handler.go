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

// Decision Mode handler (ADR-056, epic #2426).
//
// POST /api/v1/decide is the Decision API endpoint -- the same policy engine
// Gateway Mode's POST /api/policy/pre-check uses, surfaced for a different
// caller. Gateway Mode is called by application code; Decision Mode is called
// by the customer's infrastructure gateway (PEP), which enforces the verdict.
// Both share the same shared-policy engine; only the request/response shape
// and the caller differ.
//
// M1 scope: static policies only (PII detection, SQL injection, dangerous
// patterns, RBI India PII) to keep the inline RPC budget in single-digit
// milliseconds. Dynamic/custom policy support (orchestrator round-trip) is
// M2 scope per the epic.
//
// OTel: each decision emits an OpenTelemetry span via the
// platform/agent/telemetry package (#2437) and returns a W3C-compatible
// 32-hex trace_id in the response. If the caller passes a W3C traceparent
// header, its trace_id is reused so the gateway can stitch multi-layer
// decisions into one end-to-end trace (WS4). Otherwise a fresh trace_id
// is minted. When AXONFLOW_OTEL_ENDPOINT is unset the noop tracer runs
// and trace_id is locally generated via crypto/rand.

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"axonflow/platform/agent/circuitbreaker"
	"axonflow/platform/agent/telemetry"
	sharedpolicy "axonflow/platform/shared/policy"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus"
)

// Verdict values returned by the Decision API.
const (
	VerdictAllow         = "allow"
	VerdictDeny          = "deny"
	VerdictNeedsApproval = "needs_approval"
	decisionHandlerPath  = "/api/v1/decide"
	// decisionResponseDefaultTTL is the default expires_at delta returned
	// to the PEP. Override with AXONFLOW_DECISION_EXPIRES_AFTER (a Go
	// time.Duration string, e.g. "30s", "2m"). Regulated tenants typically
	// want a shorter cache window than the default 5min.
	decisionResponseDefaultTTL = 5 * time.Minute
	envDecisionExpiresAfter    = "AXONFLOW_DECISION_EXPIRES_AFTER"

	// envDecisionContextAllowlist names the comma-separated allowlist of
	// request-context keys the Decision API persists + traces. Customer-
	// supplied DecideRequest.context may carry arbitrary keys (secrets,
	// PII, oversized values); only keys matching this allowlist survive
	// into the OTel span + audit JSONB. Entries are matched case- and
	// separator-insensitively (X-AI-Agent == x-ai-agent == x_ai_agent);
	// a trailing "*" makes the entry a prefix match (x-tenant-*).
	// Empty / unset falls back to defaultDecisionContextAllowlist.
	envDecisionContextAllowlist = "AXONFLOW_DECISION_CONTEXT_ALLOWLIST"

	// Per-key / per-value / key-count caps applied during canonicalization.
	// The value cap (256 bytes, rune-safe) keeps each emitted span attribute
	// well under the 32 KiB collector ceiling; the key cap (32 chars) keeps
	// attribute names bounded; the count cap (10) bounds the per-span
	// attribute count and trips the truncated flag when exceeded.
	maxContextKeyLen   = 32
	maxContextValueLen = 256
	maxContextKeys     = 10
)

// defaultDecisionContextAllowlist is the default for
// AXONFLOW_DECISION_CONTEXT_ALLOWLIST: the common agent / session / leader
// identity headers. Deployments that capture additional headers (e.g. a
// tenant-scoped family) set AXONFLOW_DECISION_CONTEXT_ALLOWLIST explicitly — a
// trailing "*" is a prefix match. Entries are hyphen form; matching normalizes both sides.
var defaultDecisionContextAllowlist = []string{
	"x-ai-agent",
	"x-session-id",
	"x-leader-identity",
}

// Stage values accepted by the Decision API. Mirrors the three gateway layers
// in the ADR-056 reference architecture (agent / MCP / LLM).
const (
	DecisionStageLLM   = "llm"
	DecisionStageTool  = "tool"
	DecisionStageAgent = "agent"
)

// Plane (surface) discriminator values for the audit_logs.plane column
// (#2592 / ADR-058 Decision-1). Identifies which gateway/surface emitted a
// decision so a single query over audit_logs can return every block across
// every plane. Distinct from the per-request `stage` (llm/tool/agent): plane
// is the SURFACE (which PEP wrote the row), stage is the request shape.
const (
	PlaneDecision     = "decision"      // POST /api/v1/decide (the Decision API itself)
	PlaneMCP          = "mcp"           // MCP check-input / check-output handlers
	PlaneLLM          = "llm"           // LLM gateway PEP
	PlaneAgent        = "agent"         // agent gateway PEP
	PlaneGateway      = "gateway"       // generic reference PEP adapter
	PlaneOpenAICompat = "openai_compat" // OpenAI-compatible chat-completions surface
)

// Obligation contract constants (ADR-056, #2563).
const (
	// ObligationRedactPII is the obligation a PEP discharges by replacing the
	// request content with engine-redacted content before forwarding.
	ObligationRedactPII = "redact_pii"

	// ObligationPhaseRequest / ObligationPhaseResponse are the two fulfillment
	// phases. /decide runs pre-call, so it only ever emits request-phase
	// obligations; the response-phase value is named in the contract for PEP
	// helpers that fan out to the response-redaction endpoint after the call.
	ObligationPhaseRequest  = "request"
	ObligationPhaseResponse = "response"

	// requestRedactionEndpoint is the engine endpoint a PEP POSTs to in order
	// to discharge a request-phase redact_pii obligation. ADR-056 settles the
	// "request-phase redaction has no home" question in favour of extending
	// check-input (the request gate) to return engine-redacted content, keeping
	// it symmetric with check-output (the response gate) and keeping /decide a
	// pure PDP. The "/mcp/" path segment is historical; in gateway/PDP mode the
	// endpoint is connector-agnostic (the PEP passes a synthetic connector tag).
	requestRedactionEndpoint = "/api/v1/mcp/check-input"

	// (The response-phase fulfillment endpoint — /api/v1/mcp/check-output — is
	// not referenced here: /decide runs pre-call and only emits request-phase
	// obligations. Response-phase fulfillment lives in the PEP client, which
	// fans out to check-output after the backend call. See platform/shared/pep.)

	// contentTypeText is the only redaction content-type wired today. Media
	// (image/*, application/pdf) routes to the existing orchestrator media-
	// governance subsystem via the detector seam — see RequestRedactionDetector
	// in request_redaction_detector.go.
	contentTypeText = "text/plain"
)

// newRedactPIIObligation builds a self-describing request-phase redact_pii
// obligation. Centralized so every emission site carries identical, complete
// Fulfillment metadata — a PEP must never have to infer the endpoint OR which
// content modalities the endpoint can redact.
func newRedactPIIObligation(detail string) DecisionObligation {
	return DecisionObligation{
		Type:   ObligationRedactPII,
		Detail: detail,
		Fulfillment: &ObligationFulfillment{
			Endpoint:     requestRedactionEndpoint,
			Method:       http.MethodPost,
			Phase:        ObligationPhaseRequest,
			ContentTypes: requestRedactionContentTypes(),
		},
	}
}

// DecideRequest is the inbound contract for POST /api/v1/decide.
// Required: stage, query. caller_identity.gateway_id is recommended so the
// audit trail records which gateway layer issued the decision. user_token
// is OPTIONAL -- in enterprise mode a PEP that supplies one gets the
// validated-user record on the audit row; a PEP that doesn't (the common
// case for infrastructure gateways) gets a synthesized service user.
type DecideRequest struct {
	Stage          string                 `json:"stage"`
	CallerIdentity DecisionCallerIdentity `json:"caller_identity"`
	Target         DecisionTarget         `json:"target"`
	Query          string                 `json:"query"`
	UserToken      string                 `json:"user_token,omitempty"`
	Context        map[string]interface{} `json:"context,omitempty"`
}

// DecisionCallerIdentity is the gateway-asserted identity for the request.
// org_id / tenant_id are optional in the body -- the auth-derived identity
// from apiAuthMiddleware is authoritative. Body-supplied values are accepted
// only when they match the auth-derived identity (or in community mode).
type DecisionCallerIdentity struct {
	GatewayID string `json:"gateway_id,omitempty"`
	OrgID     string `json:"org_id,omitempty"`
	TenantID  string `json:"tenant_id,omitempty"`
}

// DecisionTarget describes what the gateway is about to call.
type DecisionTarget struct {
	Type     string `json:"type,omitempty"`     // "llm" | "tool" | "agent"
	Model    string `json:"model,omitempty"`    // when type=llm
	Provider string `json:"provider,omitempty"` // when type=llm
	Tool     string `json:"tool,omitempty"`     // when type=tool
}

// DecideResponse is the verdict returned to the PEP.
// trace_id is W3C-format (32 lowercase hex chars). decision_id is a fresh
// UUID per request, used for audit-log correlation. obligations is always a
// non-nil slice so PEP code can iterate without a nil-check.
type DecideResponse struct {
	Verdict           string               `json:"verdict"`
	DecisionID        string               `json:"decision_id"`
	TraceID           string               `json:"trace_id"`
	Reasons           []string             `json:"reasons,omitempty"`
	Obligations       []DecisionObligation `json:"obligations"`
	EvaluatedPolicies []string             `json:"evaluated_policies"`
	Stage             string               `json:"stage,omitempty"`
	ExpiresAt         time.Time            `json:"expires_at"`
}

// DecisionObligation is a PEP-side requirement attached to an allow verdict
// (e.g. redact PII before forwarding the call).
//
// Obligations are SELF-DESCRIBING and ENGINE-FULFILLABLE (ADR-056, #2563):
// `/decide` is a pure PDP and never mutates content, so a redact_pii obligation
// is not "go redact this yourself with your own patterns" — it is "call the
// AxonFlow engine endpoint named in Fulfillment to obtain engine-redacted
// content." The Fulfillment block tells the PEP exactly which endpoint, method,
// and phase discharges the obligation, so no PEP ever hand-rolls a regex
// (which is how the desktop proxy's redact.go ended up punting US SSN). The
// blessed client path is platform/shared/pep.
type DecisionObligation struct {
	Type        string                 `json:"type"`                  // e.g. "redact_pii"
	Detail      string                 `json:"detail,omitempty"`      // human-readable detail for audit logs
	Fulfillment *ObligationFulfillment `json:"fulfillment,omitempty"` // how the PEP discharges this via the engine
}

// ObligationFulfillment names the engine call a PEP makes to discharge an
// obligation. It exists so fulfillment is a property of the contract, not of
// PEP-author discipline: a conforming PEP POSTs the obligation's source content
// to Endpoint and forwards the engine-redacted content the endpoint returns.
// There is no other blessed way to satisfy a redact_pii obligation — client-
// side redaction is forbidden by ADR-056.
//
// Phase distinguishes which content the PEP submits:
//   - "request"  -> the PEP redacts the request it is about to forward
//     (the `query` it asked /decide about), via the request-redaction endpoint.
//   - "response" -> the PEP redacts a backend response before returning it,
//     via the response-redaction endpoint (check-output). /decide itself runs
//     pre-call so it only emits request-phase obligations; the response-phase
//     value is part of the contract for PEP helpers that fan out to both.
//
// ContentTypes advertises the mime-types the endpoint's redaction detectors can
// handle today (e.g. "text/plain"). The contract is deliberately content-type-
// agnostic: a PEP holding content of a type NOT in this list (an image awaiting
// OCR-PII redaction, say) must fail closed rather than forward it unredacted.
// Adding media is a server-side detector registration plus a new entry here —
// NOT a redesign of this shape. This is the same lesson as the connector trap
// (#2563): don't bake a single content modality into the contract.
type ObligationFulfillment struct {
	Endpoint     string   `json:"endpoint"`                // engine path, e.g. "/api/v1/mcp/check-input"
	Method       string   `json:"method"`                  // HTTP method, e.g. "POST"
	Phase        string   `json:"phase"`                   // "request" | "response"
	ContentTypes []string `json:"content_types,omitempty"` // mime-types the endpoint can redact today
}

// Decision Mode Prometheus metrics. Mirrors gateway pre-check shape so
// dashboards already wired for Gateway Mode can be reused.
var (
	decideRequests = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "axonflow_decision_requests_total",
			Help: "Total POST /api/v1/decide requests by verdict and stage",
		},
		[]string{"verdict", "stage"},
	)
	decideDuration = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "axonflow_decision_duration_milliseconds",
			Help:    "POST /api/v1/decide handler duration (ms)",
			Buckets: []float64{1, 2, 5, 10, 20, 50, 100, 200, 500},
		},
	)
)

func init() {
	_ = prometheus.Register(decideRequests)
	_ = prometheus.Register(decideDuration)
}

// handleDecide handles POST /api/v1/decide -- Decision Mode entry point.
//
// Flow mirrors handlePolicyPreCheck (gateway_handlers.go) so a single policy
// engine evaluation answers both Gateway Mode (application caller) and
// Decision Mode (infrastructure-gateway caller). Differences from pre-check:
//
//   - request shape is stage/target oriented (vs. data_sources oriented)
//   - response carries verdict (allow/deny/needs_approval) and a W3C trace_id
//     rather than a context_id, because Decision Mode is one-shot per
//     gateway hop (no follow-up audit call)
//   - circuit-breaker trips return HTTP 503 so the PEP adapter can apply its
//     configured fail-open / fail-closed posture (ADR-056 §Components)
func handleDecide(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()

	var req DecideRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		decideRequests.WithLabelValues("error", "unknown").Inc()
		sendDecideError(w, "Invalid request body", http.StatusBadRequest, "", "")
		return
	}

	// Required field validation. Stage is required so the audit trail records
	// which gateway layer issued the call; query is required so the policy
	// engine has something to evaluate.
	stage := strings.ToLower(strings.TrimSpace(req.Stage))
	if !isValidStage(stage) {
		decideRequests.WithLabelValues("error", "unknown").Inc()
		sendDecideError(w, "stage is required and must be one of: llm, tool, agent", http.StatusBadRequest, "", "")
		return
	}
	if req.Query == "" {
		decideRequests.WithLabelValues("error", stage).Inc()
		sendDecideError(w, "query field is required", http.StatusBadRequest, "", "")
		return
	}

	// Auth-derived identity is authoritative. apiAuthMiddleware has already
	// stamped tenant/org/client into context; we read it back here.
	authClientID := ClientIDFromContext(r.Context())
	tenantID := TenantIDFromContext(r.Context())
	orgID := OrgIDFromContext(r.Context())
	authKind := AuthKindFromContext(r.Context())
	ctx := r.Context()

	// In community mode the middleware defaults the client to "community";
	// fall back to body-supplied caller_identity values so local-dev callers
	// without credentials still get a useful tenant scope for audit records.
	// Mirrors the pre-check community-mode shim.
	effectiveClientID := authClientID
	if isCommunityMode() && (authClientID == "" || authClientID == "community") {
		if req.CallerIdentity.TenantID != "" {
			tenantID = req.CallerIdentity.TenantID
			effectiveClientID = req.CallerIdentity.TenantID
		}
		if req.CallerIdentity.OrgID != "" {
			orgID = req.CallerIdentity.OrgID
		}
	} else {
		// In non-community modes the body MUST NOT override the
		// authenticated identity. We reject any body that asserts a
		// different tenant/org than the credentials carry, to prevent
		// a compromised PEP from impersonating a different tenant.
		if req.CallerIdentity.TenantID != "" && req.CallerIdentity.TenantID != tenantID {
			decideRequests.WithLabelValues("error", stage).Inc()
			sendDecideError(w, "caller_identity.tenant_id does not match authenticated identity", http.StatusForbidden, "", "")
			return
		}
		if req.CallerIdentity.OrgID != "" && req.CallerIdentity.OrgID != orgID {
			decideRequests.WithLabelValues("error", stage).Inc()
			sendDecideError(w, "caller_identity.org_id does not match authenticated identity", http.StatusForbidden, "", "")
			return
		}
	}

	// Resolve user via the unified ResolveUser path so the policy engine
	// receives the same user shape as Gateway Mode. In community mode this
	// returns a synthetic user; in enterprise mode it validates the JWT.
	client := &Client{
		ID:       effectiveClientID,
		ClientID: effectiveClientID,
		Name:     effectiveClientID,
		OrgID:    orgID,
		TenantID: tenantID,
		Enabled:  true,
	}
	authResult := &AuthResult{Kind: authKind, TenantID: tenantID, OrgID: orgID, ClientID: effectiveClientID, Client: client}
	user, userErr := ResolveUser(authResult, req.UserToken)
	if userErr != nil {
		// Enterprise-mode PEP callers are typically services, not humans:
		// an infrastructure gateway acting as a Policy Enforcement Point
		// has no end-user JWT to forward. Mirror the mcp_handler.go pattern
		// (line ~1640) -- synthesize a service user so the decision flow
		// proceeds and the audit row carries a service identity. A caller
		// that DOES supply a valid token still gets the validated record.
		if authKind == AuthKindEnterprise && req.UserToken == "" {
			user = &User{
				ID:       0,
				Email:    effectiveClientID + "@axonflow.local",
				Name:     effectiveClientID,
				TenantID: client.TenantID,
				OrgID:    client.OrgID, // mirror tenant scope so downstream
				// audit / RLS writes (under axonflow_app_role) succeed
				// instead of failing the WITH CHECK with empty org_id.
				Role: "service",
			}
		} else {
			decideRequests.WithLabelValues("error", stage).Inc()
			sendDecideError(w, userErr.Message, userErr.HTTPStatus, "", "")
			return
		}
	}
	if user.TenantID != client.TenantID {
		decideRequests.WithLabelValues("error", stage).Inc()
		sendDecideError(w, "Tenant mismatch", http.StatusForbidden, "", "")
		return
	}

	// W3C trace_id: reuse the incoming traceparent header trace_id when
	// present so multi-layer gateways stitch into one end-to-end trace
	// (WS4 / closes design-partner gap #2). Otherwise mint a fresh
	// 16-byte (32 hex) trace_id.
	traceID := traceIDFromHeader(r.Header.Get("traceparent"))
	if traceID == "" {
		traceID = newW3CTraceID()
	}

	decisionID := uuid.New().String()

	// Canonicalize + sanitize the customer-supplied request context once.
	// The kept map (canonical keys -> sanitized values) is threaded into
	// every verdict's OTel span attributes + audit row; contextTruncated
	// flags that the key-count cap dropped surplus keys. A design partner's
	// Layer-2 headers (X-AI-Agent / X-Session-ID / X-Leader-Identity)
	// land here so the SIEM can join AxonFlow's decision record to BigQuery
	// Cloud Audit Logs by session_id (#2509 / epic #2508).
	reqContext, contextTruncated := canonicalizeRequestContext(req.Context, decisionContextAllowlist())

	// Static identity for the audit_logs row, built once. Each verdict path
	// below passes &decisionAudit so its decision (including the deny early
	// returns) is listable via GET /api/v1/decisions and explainable.
	decisionAudit := &decisionAuditInput{
		clientID:  effectiveClientID,
		requestID: decisionID,
		userEmail: user.Email,
		userRole:  user.Role,
		userID:    user.ID,
		query:     req.Query,
		gatewayID: sanitizeGatewayID(req.CallerIdentity.GatewayID),
		plane:     PlaneDecision, // every /api/v1/decide row records plane=decision
		// correlationID is the SHARED key across the stages of one logical request
		// (#2598). traceID here is the inbound traceparent's W3C trace-id when the
		// PEP propagated one — the SAME value across its llm/tool/agent hops — or a
		// freshly minted id otherwise (a single-shot call → its own singleton).
		// Captured BEFORE recordDecideDecision, which may swap the RETURNED trace_id
		// for an OTel-assigned one; the persisted correlation key stays this stable
		// inbound/minted value so multi-stage grouping survives OTel being on.
		correlationID: traceID,
	}

	// Circuit breaker -- transient deny shape. Returns HTTP 503 so the PEP
	// adapter can apply its configured fail-open / fail-closed posture.
	// ADR-056 §Components calls this out explicitly. A 5xx-class status
	// here is the signal to the adapter that the PDP is degraded -- the
	// body's verdict=deny is the fail-closed default for adapters that
	// don't have a posture configured. cbErr (DB error) is intentionally
	// fail-open: degraded availability of the breaker is logged and the
	// decision falls through to the policy engine. Operators that want
	// fail-closed should configure the PEP adapter accordingly.
	if circuitBreakerInstance != nil {
		cbResult, cbErr := circuitBreakerInstance.Check(ctx, circuitbreaker.CheckInput{
			OrgID:    client.OrgID,
			TenantID: client.TenantID,
			ClientID: client.ID,
		})
		if cbErr != nil {
			log.Printf("⚠️ [Decide] Circuit breaker check error (fail-open): %v", cbErr)
		} else if !cbResult.Allowed {
			if retryAfter := circuitBreakerRetryAfter(cbResult.ExpiresAt); retryAfter != "" {
				w.Header().Set("Retry-After", retryAfter)
			}
			traceID = recordDecideDecision(ctx, decisionID, client.OrgID, client.TenantID, stage, VerdictDeny, nil, time.Since(startTime).Milliseconds(), []string{string(cbResult.Reason)}, traceID, reqContext, contextTruncated, decisionAudit)
			sendDecideError(w, fmt.Sprintf("Service temporarily unavailable: circuit breaker active (reason: %s)", cbResult.Reason), http.StatusServiceUnavailable, decisionID, traceID)
			recordDecideMetrics("circuit_breaker", stage, startTime)
			return
		}
	}

	// Kill switch (RBI FREE-AI) -- policy-controlled deny. Returns
	// verdict=deny over 200 because it's a deliberate policy decision the
	// PEP should enforce as a final answer (not retry).
	killSwitchResult := checkRBIKillSwitch(ctx, client.OrgID, "")
	if killSwitchResult.IsBlocked {
		log.Printf("🛑 [Decide] Request blocked by RBI kill switch: %s", killSwitchResult.Reason)
		traceID = recordDecideDecision(ctx, decisionID, client.OrgID, client.TenantID, stage, VerdictDeny, []string{"rbi_kill_switch"}, time.Since(startTime).Milliseconds(), []string{killSwitchResult.Reason}, traceID, reqContext, contextTruncated, decisionAudit)
		writeDecideResponse(w, http.StatusOK, DecideResponse{
			Verdict:           VerdictDeny,
			DecisionID:        decisionID,
			TraceID:           traceID,
			Stage:             stage,
			Reasons:           []string{killSwitchResult.Reason},
			Obligations:       []DecisionObligation{},
			EvaluatedPolicies: []string{"rbi_kill_switch"},
			ExpiresAt:         time.Now().Add(decisionExpiresAfter()),
		})
		recordDecideMetrics(VerdictDeny, stage, startTime)
		return
	}

	// #2581: resolve per-org posture (org with no override → deployment-global).
	gwDetectionCfg := ResolveGatewayDetectionConfig(ctx, orgID)

	// blockingPolicyID captures the SINGLE policy that produces a deny
	// verdict, when one exists. The shared engine appends non-blocking
	// matches before the blocking match (engine.go:128-156 evaluates each
	// policy in order and breaks at the first ActionBlock), so
	// policyResult.TriggeredPolicies[0] is NOT reliably the blocking one.
	// We read it off requestResult.BlockedBy below and use it directly
	// when recording violations against the circuit breaker.
	var blockingPolicyID string

	// Indonesia PII pre-check runs FIRST so Indonesia-specific bank account
	// patterns (BCA/Mandiri/BRI/BNI) are attributed to indonesia_pii_protection
	// instead of being shadowed by the generic RBI bank-account detector.
	rbiPIIRequiresRedaction := false
	indonesiaPIIRequiresRedaction := false
	blockOnCriticalPII := gwDetectionCfg.Enabled && gwDetectionCfg.PIIAction == DetectionActionBlock

	// OJK/UU PDP Indonesia PII pre-check (NIK / NPWP / +62 / bank accounts).
	indonesiaPIIResult := checkIndonesiaPII(req.Query, blockOnCriticalPII)
	if indonesiaPIIResult.BlockRecommended {
		log.Printf("🛑 [Decide] Request blocked by Indonesia PII detection: %s", indonesiaPIIResult.Reason)
		traceID = recordDecideDecision(ctx, decisionID, client.OrgID, client.TenantID, stage, VerdictDeny, []string{"indonesia_pii_protection"}, time.Since(startTime).Milliseconds(), []string{indonesiaPIIResult.Reason}, traceID, reqContext, contextTruncated, decisionAudit)
		writeDecideResponse(w, http.StatusOK, DecideResponse{
			Verdict:           VerdictDeny,
			DecisionID:        decisionID,
			TraceID:           traceID,
			Stage:             stage,
			Reasons:           []string{indonesiaPIIResult.Reason},
			Obligations:       []DecisionObligation{},
			EvaluatedPolicies: []string{"indonesia_pii_protection"},
			ExpiresAt:         time.Now().Add(decisionExpiresAfter()),
		})
		recordDecideMetrics(VerdictDeny, stage, startTime)
		return
	}
	// Under PII_ACTION=redact, critical Indonesia PII (NIK / NPWP) is detected
	// but not blocked. Flag it for redaction the same way RBI India PII is
	// flagged below — previously it was detected but never flagged, so NIK
	// slipped through unredacted on the allow path while SSN/Aadhaar redacted.
	if indonesiaPIIResult.HasPII && gwDetectionCfg.Enabled && indonesiaPIIResult.CriticalPII && gwDetectionCfg.PIIAction == DetectionActionRedact {
		indonesiaPIIRequiresRedaction = true
	}

	// RBI India PII pre-check (Aadhaar / PAN / UPI / bank-account validators).
	piiResult := checkRBIPII(req.Query, blockOnCriticalPII)
	if piiResult.BlockRecommended {
		log.Printf("🛑 [Decide] Request blocked by RBI PII detection: %s", piiResult.Reason)
		traceID = recordDecideDecision(ctx, decisionID, client.OrgID, client.TenantID, stage, VerdictDeny, []string{"rbi_pii_protection"}, time.Since(startTime).Milliseconds(), []string{piiResult.Reason}, traceID, reqContext, contextTruncated, decisionAudit)
		writeDecideResponse(w, http.StatusOK, DecideResponse{
			Verdict:           VerdictDeny,
			DecisionID:        decisionID,
			TraceID:           traceID,
			Stage:             stage,
			Reasons:           []string{piiResult.Reason},
			Obligations:       []DecisionObligation{},
			EvaluatedPolicies: []string{"rbi_pii_protection"},
			ExpiresAt:         time.Now().Add(decisionExpiresAfter()),
		})
		recordDecideMetrics(VerdictDeny, stage, startTime)
		return
	}
	if piiResult.HasPII && gwDetectionCfg.Enabled && piiResult.CriticalPII && gwDetectionCfg.PIIAction == DetectionActionRedact {
		rbiPIIRequiresRedaction = true
	}

	// Static-policy evaluation via the shared policy engine. Same engine,
	// same category set as Gateway Mode pre-check so a single policy author
	// gets consistent enforcement across both callers.
	var policyResult *StaticPolicyResult
	sharedEngine := sharedpolicy.GetGlobalEngine()
	if !gwDetectionCfg.Enabled {
		policyResult = &StaticPolicyResult{
			Blocked:           false,
			TriggeredPolicies: []string{},
			ChecksPerformed:   []string{"gateway_static_policies_disabled"},
		}
	} else if sharedEngine != nil {
		// Security + compliance categories stay explicit; the PII subset is
		// policy-derived via Session A's canonical EnabledPIICategories (#2565)
		// — the same source of truth the W2 response engines use — so a new
		// pii-* jurisdiction is auto-covered with no hardcoded list to forget.
		// PhaseRequest because /decide is a pre-call (request-phase) decision.
		// The non-PII categories keep the slice non-empty, so the
		// empty-Categories-means-all whitelist footgun can't apply here.
		decideCats := []sharedpolicy.PolicyCategory{
			sharedpolicy.CategorySecuritySQLi,
			sharedpolicy.CategorySecurityDangerous,
			sharedpolicy.CategorySensitiveData,
			sharedpolicy.CategoryComplianceRBI,
			sharedpolicy.CategoryComplianceSEBI,
			sharedpolicy.CategoryComplianceEUAIAct,
			sharedpolicy.CategoryComplianceMASFEAT,
		}
		decideCats = append(decideCats, sharedEngine.EnabledPIICategories(ctx, user.TenantID, nil, sharedpolicy.PhaseRequest)...)
		requestResult := sharedEngine.EvaluateRequest(ctx, req.Query, sharedpolicy.EvalOptions{
			TenantID:        user.TenantID,
			OrgID:           user.OrgID,
			ConnectorName:   "decision",
			UserID:          fmt.Sprintf("%d", user.ID),
			Categories:      decideCats,
			SkipCategories:  gwDetectionCfg.SkipCategories,
			ActionOverrides: gwDetectionCfg.BuildActionOverrides(),
		})
		policyResult = convertSharedResultToStatic(requestResult)
		// Capture the blocking policy ID directly from requestResult so
		// circuit-breaker violation recording targets the right rule
		// regardless of which order the shared engine appended matches in
		// (a request that triggers a non-blocking redact policy AND a
		// blocking SQLi policy must record the SQLi rule).
		if requestResult != nil && requestResult.BlockedBy != nil {
			blockingPolicyID = requestResult.BlockedBy.PolicyID
		}
	} else {
		// No engine wired -- allow (mirrors Gateway Mode bypass shape).
		policyResult = &StaticPolicyResult{
			Blocked:           false,
			TriggeredPolicies: []string{},
			ChecksPerformed:   []string{"no_policy_engine"},
		}
	}

	// Map StaticPolicyResult onto the Decision API verdict/reasons/obligations
	// shape. Pulled out so the mapping is unit-testable without standing up
	// the full shared engine + DB-seeded patterns.
	verdict, reasons, obligations := mapPolicyResultToVerdict(policyResult, isCommunityMode())

	// Merge a redaction obligation when a validator-backed detector flagged
	// critical India *or* Indonesia PII and PII_ACTION=redact. Suppressed on
	// deny (the request won't be forwarded anyway) and on needs_approval (the
	// approver makes the redact call at queue exit). The shared engine's
	// regex-based category may or may not have set the same obligation; we
	// dedup to avoid two redact_pii entries. Indonesia (NIK / NPWP) is included
	// here for the same reason RBI India PII is — previously it was detected but
	// never produced a redact obligation, so NIK slipped through unredacted.
	if (rbiPIIRequiresRedaction || indonesiaPIIRequiresRedaction) && verdict == VerdictAllow {
		alreadyHasRedact := false
		for _, o := range obligations {
			if o.Type == ObligationRedactPII {
				alreadyHasRedact = true
				break
			}
		}
		if !alreadyHasRedact {
			redactReason := piiResult.Reason
			if redactReason == "" && indonesiaPIIRequiresRedaction {
				redactReason = fmt.Sprintf("Indonesia PII detected: %v", indonesiaPIIResult.DetectedTypes)
			}
			obligations = append(obligations, newRedactPIIObligation(redactReason))
		}
	}

	// On deny verdict, record ONE policy violation against the circuit
	// breaker so repeated denies auto-trip it (#1176). We record the
	// blocking policy specifically -- captured from requestResult.BlockedBy
	// above when the shared engine fired, or falls back to the first
	// triggered policy for the engine-bypass paths (no-engine /
	// disabled-detection / empty triggered list).
	if verdict == VerdictDeny && circuitBreakerInstance != nil {
		policyToRecord := blockingPolicyID
		if policyToRecord == "" && len(policyResult.TriggeredPolicies) > 0 {
			policyToRecord = policyResult.TriggeredPolicies[0]
		}
		if policyToRecord != "" {
			if err := circuitBreakerInstance.RecordPolicyViolation(ctx, client.OrgID, client.TenantID, client.ID, policyToRecord); err != nil {
				log.Printf("⚠️ [Decide] Circuit breaker RecordPolicyViolation error: %v", err)
			}
		}
	}

	// Hoist the blocking policy to evaluated_policies[0] so the OpenAPI
	// contract claim ("On deny, the first entry is the blocking policy")
	// holds. Non-blocking matches (PII redact rules that fired but didn't
	// block) follow.
	if verdict == VerdictDeny && blockingPolicyID != "" {
		policyResult.TriggeredPolicies = hoistBlockingPolicy(policyResult.TriggeredPolicies, blockingPolicyID)
	}

	evaluatedPolicies := policyResult.TriggeredPolicies
	if evaluatedPolicies == nil {
		evaluatedPolicies = []string{}
	}

	// Persist the structured obligations (e.g. redact_pii) onto the audit row
	// instead of flattening them into the reason text. Only the terminal
	// allow/deny path carries obligations; the early-return deny paths above
	// (circuit-breaker / kill-switch / PII) have none, so they leave this nil.
	decisionAudit.obligations = obligations

	traceID = recordDecideDecision(ctx, decisionID, client.OrgID, client.TenantID, stage, verdict, evaluatedPolicies, time.Since(startTime).Milliseconds(), reasons, traceID, reqContext, contextTruncated, decisionAudit)

	writeDecideResponse(w, http.StatusOK, DecideResponse{
		Verdict:           verdict,
		DecisionID:        decisionID,
		TraceID:           traceID,
		Stage:             stage,
		Reasons:           reasons,
		Obligations:       obligations,
		EvaluatedPolicies: evaluatedPolicies,
		ExpiresAt:         time.Now().Add(decisionExpiresAfter()),
	})
	recordDecideMetrics(verdict, stage, startTime)
}

// mapPolicyResultToVerdict translates a shared-policy StaticPolicyResult into
// the (verdict, reasons, obligations) triple the Decision API surfaces. Pulled
// out as a pure function so all four verdict transitions can be unit-tested
// without standing up the full shared engine + DB-seeded patterns.
//
// Rules:
//   - Blocked            -> verdict=deny,            reason=block reason
//   - RequiresApproval   -> verdict=needs_approval   (enterprise only;
//     community mode auto-allows because HITL is enterprise-gated)
//   - RequiresRedaction  -> verdict=allow + obligations=[redact_pii]
//   - else               -> verdict=allow
//
// Always returns non-nil slices so the caller can serialize without a nil-check.
func mapPolicyResultToVerdict(result *StaticPolicyResult, communityMode bool) (string, []string, []DecisionObligation) {
	reasons := []string{}
	obligations := []DecisionObligation{}
	if result == nil {
		return VerdictAllow, reasons, obligations
	}
	if result.Blocked {
		if result.Reason != "" {
			reasons = append(reasons, result.Reason)
		}
		return VerdictDeny, reasons, obligations
	}
	if result.RequiresApproval && !communityMode {
		reasons = append(reasons, "require_approval")
		return VerdictNeedsApproval, reasons, obligations
	}
	if result.RequiresRedaction {
		obligations = append(obligations, newRedactPIIObligation(result.Reason))
	}
	return VerdictAllow, reasons, obligations
}

// isValidStage gates the stage field to the three layers in ADR-056.
// Unknown stages are rejected at the API boundary so audit dashboards
// stay bounded.
func isValidStage(s string) bool {
	switch s {
	case DecisionStageLLM, DecisionStageTool, DecisionStageAgent:
		return true
	default:
		return false
	}
}

// hoistBlockingPolicy moves blockingID to position 0 of the slice. If it
// isn't present, prepends it. If it IS at position 0, returns the slice
// unchanged. Used to satisfy the OpenAPI contract that
// `evaluated_policies[0]` is the blocking policy on deny.
func hoistBlockingPolicy(policies []string, blockingID string) []string {
	if len(policies) == 0 {
		return []string{blockingID}
	}
	if policies[0] == blockingID {
		return policies
	}
	for i, p := range policies {
		if p == blockingID {
			policies[0], policies[i] = policies[i], policies[0]
			return policies
		}
	}
	return append([]string{blockingID}, policies...)
}

// decisionExpiresAfter returns the configured PEP-cache TTL.
// AXONFLOW_DECISION_EXPIRES_AFTER overrides the 5-minute default; an
// unparseable value falls back to the default so a typo can't blow up
// every decision in the field.
func decisionExpiresAfter() time.Duration {
	raw := strings.TrimSpace(getEnv(envDecisionExpiresAfter, ""))
	if raw == "" {
		return decisionResponseDefaultTTL
	}
	d, err := time.ParseDuration(raw)
	if err != nil || d <= 0 {
		log.Printf("⚠️ [Decide] invalid %s=%q (using default %s)", envDecisionExpiresAfter, raw, decisionResponseDefaultTTL)
		return decisionResponseDefaultTTL
	}
	return d
}

// newW3CTraceID returns 16 random bytes as a lowercase 32-hex string,
// matching the W3C trace-context trace-id field. Crypto-rand is used so
// trace IDs are sampling-friendly when exporters are wired in #2354.
// Falls back to a uuid-derived hex string if the rand source errors (in
// practice this never returns on Linux/macOS, but guard for completeness).
func newW3CTraceID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		u := uuid.New()
		return hex.EncodeToString(u[:])
	}
	return hex.EncodeToString(b[:])
}

// traceIDFromHeader parses a W3C traceparent header and returns its trace-id
// component. Format: "version-trace_id-parent_id-trace_flags" (W3C TC v1).
// Returns "" if the header is empty, malformed, or carries the invalid
// all-zero trace-id (which W3C says receivers MUST reject).
//
// Robustness:
//   - Leading/trailing whitespace is trimmed (proxies sometimes pad).
//   - HTTP allows comma-joined repeated header values; we use the FIRST
//     value (W3C TC says senders MUST send only one, so subsequent values
//     are noise from a forwarder).
//   - parent_id / trace_flags are not validated; we only need the trace_id.
//     A non-"00" version is silently accepted (W3C says receivers MAY
//     accept future versions in forward-compat mode).
func traceIDFromHeader(h string) string {
	h = strings.TrimSpace(h)
	if h == "" {
		return ""
	}
	if i := strings.IndexByte(h, ','); i >= 0 {
		h = strings.TrimSpace(h[:i])
	}
	parts := strings.Split(h, "-")
	if len(parts) != 4 {
		return ""
	}
	tid := strings.ToLower(parts[1])
	if len(tid) != 32 {
		return ""
	}
	// W3C: trace-id of all-zero is invalid.
	if tid == "00000000000000000000000000000000" {
		return ""
	}
	if _, err := hex.DecodeString(tid); err != nil {
		return ""
	}
	return tid
}

// sendDecideError emits a JSON error body in the same shape as the success
// response (decision_id + trace_id present even on error) so PEP code can
// always parse a single envelope. For request-format errors we don't yet
// have a decision_id/trace_id, so callers pass empty strings.
func sendDecideError(w http.ResponseWriter, message string, statusCode int, decisionID, traceID string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	body := map[string]interface{}{
		"error":   message,
		"verdict": VerdictDeny, // deny on error so PEP fail-closed is the default
	}
	if decisionID != "" {
		body["decision_id"] = decisionID
	}
	if traceID != "" {
		body["trace_id"] = traceID
	}
	_ = json.NewEncoder(w).Encode(body)
}

// writeDecideResponse encodes a DecideResponse with the canonical JSON content
// type. Centralized so the contract stays single-source.
func writeDecideResponse(w http.ResponseWriter, statusCode int, resp DecideResponse) {
	if resp.Obligations == nil {
		resp.Obligations = []DecisionObligation{}
	}
	if resp.EvaluatedPolicies == nil {
		resp.EvaluatedPolicies = []string{}
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(resp)
}

// recordDecideMetrics observes duration + increments the verdict counter.
// Pulled out so both the success and the early-return paths converge on
// one set of metric writes.
func recordDecideMetrics(verdict, stage string, startTime time.Time) {
	decideDuration.Observe(float64(time.Since(startTime).Milliseconds()))
	decideRequests.WithLabelValues(verdict, stage).Inc()
}

// decisionContextAllowlist returns the active request-context key allowlist.
// AXONFLOW_DECISION_CONTEXT_ALLOWLIST (comma-separated) overrides the
// default; blank entries are dropped and a fully-empty override falls back
// to the default so a typo can't silently disable context capture entirely
// without an operator noticing the env var had no effect.
func decisionContextAllowlist() []string {
	raw := strings.TrimSpace(getEnv(envDecisionContextAllowlist, ""))
	if raw == "" {
		return defaultDecisionContextAllowlist
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return defaultDecisionContextAllowlist
	}
	return out
}

// canonicalizeRequestContext filters a raw DecideRequest.context map against
// the allowlist, canonicalizes surviving keys to lower_snake_case, sanitizes
// + length-caps values, and caps the total key count. It is a pure function
// (no I/O, no globals) so the full edge-case matrix is unit-testable.
//
// Returns the kept map (canonical key -> sanitized value) and whether the
// key-count cap dropped any keys (the caller surfaces this as the
// request.context.truncated span attribute + a JSONB marker).
//
// Behavior:
//   - non-string values are dropped silently (the audit pipeline persists
//     strings only — a nested object or number is not a header value)
//   - keys not matching the allowlist are dropped
//   - keys are canonicalized: lowercased, every non-alphanumeric run becomes
//     a single underscore, capped to maxContextKeyLen (X-AI-Agent -> x_ai_agent)
//   - values have control / unprintable runes stripped and are capped to
//     maxContextValueLen bytes on a rune boundary
//   - if more than maxContextKeys survive, keys are sorted and the first
//     maxContextKeys kept (deterministic); truncated=true
func canonicalizeRequestContext(raw map[string]interface{}, allowlist []string) (map[string]string, bool) {
	kept := map[string]string{}
	if len(raw) == 0 {
		return kept, false
	}
	// Iterate raw keys in sorted order so the result is deterministic even
	// when two distinct raw keys canonicalize to the same key (e.g. after the
	// 32-char cap clips a shared prefix): first sorted raw key wins rather than
	// a random map-iteration winner.
	rawKeys := make([]string, 0, len(raw))
	for k := range raw {
		rawKeys = append(rawKeys, k)
	}
	sort.Strings(rawKeys)
	for _, k := range rawKeys {
		s, ok := raw[k].(string)
		if !ok {
			continue // strings only
		}
		if !matchContextAllowlist(k, allowlist) {
			continue
		}
		ck := canonicalContextKey(k)
		if ck == "" {
			continue
		}
		if _, exists := kept[ck]; exists {
			continue // canonical-key collision: keep the first sorted raw key
		}
		kept[ck] = sanitizeContextValue(s)
	}
	if len(kept) <= maxContextKeys {
		return kept, false
	}
	// Deterministic count cap: sort canonical keys, keep the first N.
	keys := make([]string, 0, len(kept))
	for k := range kept {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	capped := make(map[string]string, maxContextKeys)
	for _, k := range keys[:maxContextKeys] {
		capped[k] = kept[k]
	}
	return capped, true
}

// matchContextAllowlist reports whether key matches any allowlist entry.
// Matching is case- and separator-insensitive: both sides are lowercased and
// '_' is folded to '-' so X-AI-Agent, x-ai-agent and x_ai_agent all match the
// "x-ai-agent" entry. A trailing "*" on an entry makes it a prefix match.
func matchContextAllowlist(key string, allowlist []string) bool {
	nk := normalizeContextKeyForMatch(key)
	if nk == "" {
		return false
	}
	for _, entry := range allowlist {
		ne := normalizeContextKeyForMatch(entry)
		if ne == "" {
			continue
		}
		if strings.HasSuffix(ne, "*") {
			if strings.HasPrefix(nk, strings.TrimSuffix(ne, "*")) {
				return true
			}
			continue
		}
		if nk == ne {
			return true
		}
	}
	return false
}

// normalizeContextKeyForMatch lowercases, trims, and folds '_' to '-' so
// allowlist comparison is insensitive to case and separator style. The
// trailing '*' (prefix marker) is preserved.
func normalizeContextKeyForMatch(s string) string {
	return strings.ReplaceAll(strings.ToLower(strings.TrimSpace(s)), "_", "-")
}

// canonicalContextKey converts a header-style key to the canonical
// lower_snake_case form persisted in the JSONB + emitted as a span
// attribute suffix. Non-alphanumeric runs collapse to a single underscore;
// leading/trailing underscores are trimmed; the result is capped to
// maxContextKeyLen. Returns "" if nothing alphanumeric survives.
func canonicalContextKey(k string) string {
	var b strings.Builder
	lastUnderscore := true // suppress a leading underscore
	for _, r := range strings.ToLower(strings.TrimSpace(k)) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			lastUnderscore = false
		} else if !lastUnderscore {
			b.WriteByte('_')
			lastUnderscore = true
		}
		if b.Len() >= maxContextKeyLen {
			break
		}
	}
	out := strings.TrimRight(b.String(), "_")
	if len(out) > maxContextKeyLen {
		out = out[:maxContextKeyLen]
	}
	return strings.TrimRight(out, "_")
}

// sanitizeContextValue strips control / unprintable runes and caps the value
// to maxContextValueLen bytes without cutting a multi-byte rune. Customer
// values can carry arbitrary bytes; the audit + trace pipelines require valid,
// bounded UTF-8.
func sanitizeContextValue(s string) string {
	var b strings.Builder
	for _, r := range s {
		if !unicode.IsPrint(r) {
			continue // drops control chars, zero-width, unprintable
		}
		if b.Len()+utf8.RuneLen(r) > maxContextValueLen {
			break
		}
		b.WriteRune(r)
	}
	return b.String()
}

// decisionAuditInput carries the static, per-request identity fields the
// audit_logs row needs that recordDecideDecision doesn't otherwise receive.
// Built once in handleDecide and passed to every recordDecideDecision call so
// each verdict (including the circuit-breaker / kill-switch / PII early
// returns) produces a complete, explainable audit row.
type decisionAuditInput struct {
	clientID  string
	requestID string
	userEmail string
	userRole  string
	userID    int
	query     string
	// gatewayID is the gateway-asserted origin (caller_identity.gateway_id),
	// e.g. "claude_desktop.<host>" for the Claude Desktop governance proxy
	// (#2520). Recorded at policy_details->>'gateway_id' so Desktop traffic is
	// distinguishable from other PEP layers in the audit trail, and mirrored
	// onto the decision span's decision.gateway_id attribute. Empty for callers
	// that don't assert one.
	gatewayID string
	// plane is the surface that emitted the decision (#2592 / ADR-058):
	// PlaneDecision for /api/v1/decide, PlaneMCP for the MCP handlers, etc.
	// Persisted to the first-class audit_logs.plane column. Empty defaults to
	// PlaneDecision in writeDecisionAuditLog (the /decide path is the only
	// caller that historically left it unset).
	plane string
	// correlationID is the shared key across the decision rows of one logical
	// request (#2598 / ADR-058 Phase 1.5): the W3C trace_id a PEP propagates
	// across its llm/tool/agent hops, so the SEBI/EU-AI-Act exporters can GROUP
	// the stages into one ordered chain. Persisted to the first-class
	// audit_logs.correlation_id column AND mirrored into policy_details JSONB
	// (dual-write, matching decision_id). Empty/"" → NULL column → the row is a
	// singleton chain (legacy + single-shot callers).
	correlationID string
	// obligations is the structured ADR-056/#2563 obligation contract for this
	// decision (e.g. a redact_pii obligation). Persisted to audit_logs.obligations
	// JSONB so obligations are queryable structure, not flattened into the
	// free-text policy_details->>'reason'. Empty/nil → NULL column.
	obligations []DecisionObligation
}

// maxGatewayIDLen bounds a recorded gateway_id. Gateway ids are short origin
// tags (claude_desktop.<host>); the cap keeps a hostile/oversized value from
// bloating the audit JSONB or a span attribute.
const maxGatewayIDLen = 128

// sanitizeGatewayID trims, strips control/unprintable runes, and length-caps a
// caller-supplied gateway_id so the recorded value is bounded valid UTF-8.
// Returns "" for an empty/whitespace input (the common case for callers that
// don't assert an origin).
func sanitizeGatewayID(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	var b strings.Builder
	for _, r := range s {
		if !unicode.IsPrint(r) {
			continue
		}
		if b.Len()+utf8.RuneLen(r) > maxGatewayIDLen {
			break
		}
		b.WriteRune(r)
	}
	return b.String()
}

// recordDecideDecision emits the OTel decision span via the
// decisionTracerProvider from #2437 AND, when audit != nil, persists a
// durable audit_logs row so GET /api/v1/decisions and the explain endpoint
// can surface this decision (including the sanitized request context).
//
// Returns the OTel-assigned trace_id if the provider is wired, or falls back
// to the caller-supplied fallbackTraceID (the inbound traceparent's trace-id
// or a freshly minted W3C ID). The fallback keeps trace_id populated even
// when AXONFLOW_OTEL_ENDPOINT is unset (noop tracer returns "").
//
// reqContext is the canonicalized request-context map (canonical keys ->
// sanitized values); contextTruncated flags that the key-count cap dropped
// keys. Both are threaded into the span attributes and the audit JSONB.
//
// audit == nil means "OTel only" — the OpenAI-compat caller records its own
// llm_call_audits row and must not double-write audit_logs.
func recordDecideDecision(ctx context.Context, decisionID, orgID, tenantID, stage, verdict string, policyIDs []string, latencyMs int64, reasons []string, fallbackTraceID string, reqContext map[string]string, contextTruncated bool, audit *decisionAuditInput) string {
	// Durable audit first so the decision is recoverable even if the OTel
	// collector is down. Best-effort: a DB hiccup never changes the verdict
	// the PEP already holds (the write logs and returns on error).
	if audit != nil {
		writeDecisionAuditLog(ctx, usageDB, decisionID, orgID, tenantID, stage, verdict, policyIDs, reasons, reqContext, contextTruncated, *audit)
	}

	if decisionTracerProvider == nil {
		return fallbackTraceID
	}
	// gateway_id rides on the span when the caller asserted one (audit may be
	// nil for the OpenAI-compat OTel-only path).
	gatewayID := ""
	if audit != nil {
		gatewayID = audit.gatewayID
	}
	otelTraceID := decisionTracerProvider.Tracer.RecordDecision(ctx, telemetry.DecisionEvent{
		DecisionID:       decisionID,
		OrgID:            orgID,
		TenantID:         tenantID,
		GatewayID:        gatewayID,
		Stage:            stage,
		Verdict:          verdict,
		PolicyIDs:        policyIDs,
		LatencyMs:        latencyMs,
		Reasons:          reasons,
		Context:          reqContext,
		ContextTruncated: contextTruncated,
	})
	if otelTraceID != "" {
		return otelTraceID
	}
	return fallbackTraceID
}

// writeDecisionAuditLog persists a Decision Mode verdict to audit_logs so the
// orchestrator's GET /api/v1/decisions list + per-id explain endpoints can
// resolve it (both read policy_details->>'decision_id' against audit_logs).
// Mirrors the established agent-side writer writeExplainableAuditLog: a direct
// INSERT (audit_logs is not FORCE-RLS — migration 101 deliberately left it so
// for the cross-org cleanup worker), best-effort, with NOT-NULL-column
// fallbacks. The sanitized request context lands at policy_details->'context'
// (canonical snake_case keys, string values); truncation is flagged at
// policy_details->'context_truncated'.
func writeDecisionAuditLog(ctx context.Context, db *sql.DB, decisionID, orgID, tenantID, stage, verdict string, policyIDs, reasons []string, reqContext map[string]string, contextTruncated bool, audit decisionAuditInput) {
	if db == nil || decisionID == "" {
		return
	}
	if policyIDs == nil {
		policyIDs = []string{}
	}
	if reasons == nil {
		reasons = []string{}
	}

	details := map[string]interface{}{
		"decision_id": decisionID,
		"source":      "decision_mode",
		"stage":       stage,
		"policy_ids":  policyIDs,
		"reasons":     reasons,
	}
	// gateway_id distinguishes the PEP origin (e.g. claude_desktop.<host>) so a
	// query over Desktop traffic is a single JSONB filter. Omitted when unset.
	if audit.gatewayID != "" {
		details["gateway_id"] = audit.gatewayID
	}
	if len(reasons) > 0 {
		// explain_handler.go reads policy_details->>'reason' (scalar).
		details["reason"] = strings.Join(reasons, "; ")
	}
	if len(reqContext) > 0 {
		details["context"] = reqContext
	}
	if contextTruncated {
		details["context_truncated"] = true
	}
	// #2598 / ADR-058 Phase 1.5: mirror the correlation key into the JSONB copy
	// alongside the first-class column below, so the exporters' COALESCE read path
	// still resolves it if the column is ever dropped/rolled back (matches the
	// decision_id dual-write). Omitted when unset → the row stays a singleton.
	if audit.correlationID != "" {
		details["correlation_id"] = audit.correlationID
	}
	detailsJSON, err := json.Marshal(details)
	if err != nil {
		log.Printf("⚠️ [Decide] audit log marshal failed (non-fatal): %v", err)
		return
	}

	// audit_logs NOT-NULL columns: fall back to placeholders rather than
	// fail the insert (mirrors writeExplainableAuditLog).
	userEmail := audit.userEmail
	if userEmail == "" {
		userEmail = "unknown@axonflow.local"
	}
	userRole := audit.userRole
	if userRole == "" {
		userRole = "service"
	}
	clientID := audit.clientID
	if clientID == "" {
		clientID = "unknown"
	}
	if tenantID == "" {
		tenantID = "unknown"
	}
	query := audit.query
	if query == "" {
		query = "(empty)"
	}
	requestID := audit.requestID
	if requestID == "" {
		requestID = decisionID
	}
	sum := sha256.Sum256([]byte(query))
	queryHash := hex.EncodeToString(sum[:])

	// #2592 / ADR-058 Phase 1: promote decision_id to a first-class column +
	// add the plane discriminator + structured obligations, ALONGSIDE the JSONB
	// copy above (dual-write, no flag-day). plane defaults to PlaneDecision
	// because /api/v1/decide is the only writer that historically left it unset.
	plane := audit.plane
	if plane == "" {
		plane = PlaneDecision
	}
	// obligations → JSONB column (NULL when none). Marshal failure is non-fatal:
	// the row still records the verdict, just without the structured obligations.
	var obligationsJSON interface{}
	if len(audit.obligations) > 0 {
		if b, mErr := json.Marshal(audit.obligations); mErr == nil {
			obligationsJSON = b
		} else {
			log.Printf("⚠️ [Decide] obligations marshal failed (non-fatal): %v", mErr)
		}
	}

	// #2598 / ADR-058 Phase 1.5: correlation_id → first-class column (NULL when
	// unset so the row groups as its own singleton). Dual-written into
	// policy_details above for read-path resilience.
	var correlationIDArg interface{}
	if audit.correlationID != "" {
		correlationIDArg = audit.correlationID
	}

	_, err = db.ExecContext(ctx, `
		INSERT INTO audit_logs (
			id, request_id, timestamp, user_id, user_email, user_role,
			client_id, tenant_id, org_id, request_type, query, query_hash,
			policy_decision, policy_details, decision_id, plane, obligations,
			correlation_id
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)
	`,
		"decide_"+decisionID, // id (PK; one row per decision)
		requestID,            // request_id
		time.Now().UTC(),     // timestamp
		audit.userID,         // user_id
		userEmail,            // user_email
		userRole,             // user_role
		clientID,             // client_id
		tenantID,             // tenant_id
		orgID,                // org_id (nullable)
		"decision_"+stage,    // request_type — bounded: decision_llm|tool|agent
		query,                // query
		queryHash,            // query_hash
		verdict,              // policy_decision — allow|deny|needs_approval
		detailsJSON,          // policy_details (JSONB) — decision_id still mirrored here
		decisionID,           // decision_id (first-class column; #2592)
		plane,                // plane (surface discriminator; #2592)
		obligationsJSON,      // obligations (JSONB or NULL; #2592)
		correlationIDArg,     // correlation_id (first-class column or NULL; #2598)
	)
	if err != nil {
		log.Printf("⚠️ [Decide] audit log insert failed (non-fatal): %v", err)
	}
}

// RegisterDecisionHandlers registers the Decision Mode endpoint.
// Wired in run.go alongside RegisterGatewayHandlers. OPTIONS is registered
// alongside POST so CORS preflight requests don't 404 -- apiAuthMiddleware
// itself shortcircuits OPTIONS so the preflight does not get auth-checked.
func RegisterDecisionHandlers(r *mux.Router) {
	r.Handle(decisionHandlerPath, apiAuthMiddleware(http.HandlerFunc(handleDecide))).Methods("POST", "OPTIONS")
	log.Printf("✅ Decision Mode endpoint registered: POST %s", decisionHandlerPath)
}
