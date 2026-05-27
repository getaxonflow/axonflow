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
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

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
)

// Stage values accepted by the Decision API. Mirrors the three gateway layers
// in the ADR-056 reference architecture (agent / MCP / LLM).
const (
	DecisionStageLLM   = "llm"
	DecisionStageTool  = "tool"
	DecisionStageAgent = "agent"
)

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
type DecisionObligation struct {
	Type   string `json:"type"`             // e.g. "redact_pii"
	Detail string `json:"detail,omitempty"` // human-readable detail for audit logs
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
			traceID = recordDecideDecision(ctx, decisionID, client.OrgID, client.TenantID, stage, VerdictDeny, nil, time.Since(startTime).Milliseconds(), []string{string(cbResult.Reason)}, traceID)
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
		traceID = recordDecideDecision(ctx, decisionID, client.OrgID, client.TenantID, stage, VerdictDeny, []string{"rbi_kill_switch"}, time.Since(startTime).Milliseconds(), []string{killSwitchResult.Reason}, traceID)
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

	gwDetectionCfg := GetGatewayDetectionConfig()

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
	blockOnCriticalPII := gwDetectionCfg.Enabled && gwDetectionCfg.PIIAction == DetectionActionBlock

	// OJK/UU PDP Indonesia PII pre-check (NIK / NPWP / +62 / bank accounts).
	indonesiaPIIResult := checkIndonesiaPII(req.Query, blockOnCriticalPII)
	if indonesiaPIIResult.BlockRecommended {
		log.Printf("🛑 [Decide] Request blocked by Indonesia PII detection: %s", indonesiaPIIResult.Reason)
		traceID = recordDecideDecision(ctx, decisionID, client.OrgID, client.TenantID, stage, VerdictDeny, []string{"indonesia_pii_protection"}, time.Since(startTime).Milliseconds(), []string{indonesiaPIIResult.Reason}, traceID)
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

	// RBI India PII pre-check (Aadhaar / PAN / UPI / bank-account validators).
	piiResult := checkRBIPII(req.Query, blockOnCriticalPII)
	if piiResult.BlockRecommended {
		log.Printf("🛑 [Decide] Request blocked by RBI PII detection: %s", piiResult.Reason)
		traceID = recordDecideDecision(ctx, decisionID, client.OrgID, client.TenantID, stage, VerdictDeny, []string{"rbi_pii_protection"}, time.Since(startTime).Milliseconds(), []string{piiResult.Reason}, traceID)
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
		requestResult := sharedEngine.EvaluateRequest(ctx, req.Query, sharedpolicy.EvalOptions{
			TenantID:      user.TenantID,
			OrgID:         user.OrgID,
			ConnectorName: "decision",
			UserID:        fmt.Sprintf("%d", user.ID),
			Categories: []sharedpolicy.PolicyCategory{
				sharedpolicy.CategorySecuritySQLi,
				sharedpolicy.CategorySecurityDangerous,
				sharedpolicy.CategoryPIIGlobal,
				sharedpolicy.CategoryPIIUS,
				sharedpolicy.CategoryPIIIndia,
				sharedpolicy.CategoryPIIEU,
				sharedpolicy.CategoryPIISingapore,
				sharedpolicy.CategoryPIIIndonesia,
				sharedpolicy.CategorySensitiveData,
				sharedpolicy.CategoryComplianceRBI,
				sharedpolicy.CategoryComplianceSEBI,
				sharedpolicy.CategoryComplianceEUAIAct,
				sharedpolicy.CategoryComplianceMASFEAT,
			},
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

	// Merge RBI-PII redaction obligation when the validator-backed detector
	// flagged critical India PII and PII_ACTION=redact. Suppressed on deny
	// (the request won't be forwarded anyway) and on needs_approval (the
	// approver makes the redact call at queue exit). The shared engine's
	// regex-based India category may or may not have set the same
	// obligation; we dedup to avoid two redact_pii entries.
	if rbiPIIRequiresRedaction && verdict == VerdictAllow {
		alreadyHasRedact := false
		for _, o := range obligations {
			if o.Type == "redact_pii" {
				alreadyHasRedact = true
				break
			}
		}
		if !alreadyHasRedact {
			obligations = append(obligations, DecisionObligation{
				Type:   "redact_pii",
				Detail: piiResult.Reason,
			})
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

	traceID = recordDecideDecision(ctx, decisionID, client.OrgID, client.TenantID, stage, verdict, evaluatedPolicies, time.Since(startTime).Milliseconds(), reasons, traceID)

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
		obligations = append(obligations, DecisionObligation{
			Type:   "redact_pii",
			Detail: result.Reason,
		})
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

// recordDecideDecision emits the OTel decision span via the
// decisionTracerProvider from #2437. Returns the OTel-assigned trace_id
// if the provider is wired, or falls back to the caller-supplied
// fallbackTraceID (which is either the inbound traceparent's trace-id
// or a freshly minted W3C ID). The fallback keeps trace_id populated
// even when AXONFLOW_OTEL_ENDPOINT is unset (noop tracer returns "").
func recordDecideDecision(ctx context.Context, decisionID, orgID, tenantID, stage, verdict string, policyIDs []string, latencyMs int64, reasons []string, fallbackTraceID string) string {
	if decisionTracerProvider == nil {
		return fallbackTraceID
	}
	otelTraceID := decisionTracerProvider.Tracer.RecordDecision(ctx, telemetry.DecisionEvent{
		DecisionID: decisionID,
		OrgID:      orgID,
		TenantID:   tenantID,
		Stage:      stage,
		Verdict:    verdict,
		PolicyIDs:  policyIDs,
		LatencyMs:  latencyMs,
		Reasons:    reasons,
	})
	if otelTraceID != "" {
		return otelTraceID
	}
	return fallbackTraceID
}

// RegisterDecisionHandlers registers the Decision Mode endpoint.
// Wired in run.go alongside RegisterGatewayHandlers. OPTIONS is registered
// alongside POST so CORS preflight requests don't 404 -- apiAuthMiddleware
// itself shortcircuits OPTIONS so the preflight does not get auth-checked.
func RegisterDecisionHandlers(r *mux.Router) {
	r.Handle(decisionHandlerPath, apiAuthMiddleware(http.HandlerFunc(handleDecide))).Methods("POST", "OPTIONS")
	log.Printf("✅ Decision Mode endpoint registered: POST %s", decisionHandlerPath)
}
