// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/mux"

	logutil "axonflow/platform/shared/logger"
	"axonflow/platform/shared/tenantscope"
)

// rateLimitEntry tracks request counts for rate limiting.
type rateLimitEntry struct {
	count     int
	windowEnd time.Time
}

// budgetEntry tracks cost usage for budget enforcement.
type budgetEntry struct {
	used      float64
	periodEnd time.Time
}

// rateLimitStore provides thread-safe in-memory rate limit tracking.
// For distributed deployments, set REDIS_URL to enable Redis-backed storage.
var (
	rateLimitStore   = make(map[string]*rateLimitEntry)
	rateLimitMutex   sync.RWMutex
	budgetStore      = make(map[string]*budgetEntry)
	budgetStoreMutex sync.RWMutex
)

// MCPPolicyEngine is an interface for policy engines that can be used with MCPDynamicPolicyHandler.
// Both DynamicPolicyEngine and DatabaseDynamicPolicyEngine implement this interface.
//
// It declares the TENANT-SCOPED list deliberately, and NOT the raw
// ListActivePolicies() this handler used to call (#3061 R3).
//
// Two reasons, both load-bearing:
//
//   - CORRECTNESS. "Does this policy apply to this tenant?" is a shape-aware
//     question and each engine answers it differently: the database engine
//     treats tenant_id 'global' and 'default' (the NULL sentinel assigned in
//     refreshPolicies) as apply-to-all, the in-memory engine treats an empty
//     TenantID as apply-to-all and knows no sentinels. #3059 made each engine
//     route BOTH enforcement and disclosure through its own single choke point
//     (dbCachedPolicyAppliesToTenant / memPolicyAppliesToTenant) precisely so
//     the two can never diverge. The predicate this handler used to carry
//     locally — `p.TenantID != "" && p.TenantID != req.TenantID` — was the
//     exact INVERSE of the database engine's on every stored shape: it skipped
//     'global' and 'default' (which must apply to everyone) and admitted the
//     empty string (which applies to nobody, and which migration core/155
//     now forbids outright). A deployment-wide content baseline stored as
//     tenant_id='global' therefore blocked on the LLM/MAP/WCP planes and was
//     silently skipped on every MCP tool call. Calling the scoped variant hands
//     the question back to the engine, so there is no fourth predicate to drift.
//
//   - EXPOSURE. Both engines document ListActivePolicies as the raw,
//     DEPLOYMENT-WIDE cache dump — every tenant's policy names, regex
//     conditions and owning tenant_id — with the constraint that it "has no
//     HTTP-reachable caller and must not grow one". getPoliciesForMCP is
//     reached from POST /api/v1/mcp/evaluate-policies, so it was exactly that
//     caller.
type MCPPolicyEngine interface {
	ListActivePoliciesForTenant(tenantID string) []DynamicPolicy
}

// MCPDynamicPolicyHandler handles dynamic policy evaluation requests from MCP Agent.
// This is the Orchestrator endpoint that the Agent calls for Issue #968.
//
// Endpoint: POST /api/v1/mcp/evaluate-policies
type MCPDynamicPolicyHandler struct {
	policyEngine MCPPolicyEngine
}

// NewMCPDynamicPolicyHandler creates a new MCP dynamic policy handler.
func NewMCPDynamicPolicyHandler(engine MCPPolicyEngine) *MCPDynamicPolicyHandler {
	return &MCPDynamicPolicyHandler{
		policyEngine: engine,
	}
}

// RegisterRoutes registers MCP dynamic policy routes.
func (h *MCPDynamicPolicyHandler) RegisterRoutes(r *mux.Router) {
	r.HandleFunc("/api/v1/mcp/evaluate-policies", h.handleEvaluatePolicies).Methods("POST", "OPTIONS")
	log.Println("[MCPDynamicPolicy] Routes registered for /api/v1/mcp/evaluate-policies")
}

// MCPPolicyEvaluationRequest matches the DynamicPolicyRequest from shared/policy.
//
// #3066 C3-4: on the TENANT-AUTHENTICATED plane — a request carrying stamped
// tenancy — TenantID is not a scope selector. See resolveEvaluationScope: the
// body value is authorized against the gateway-stamped identity and can only
// ever name the caller's own tenant, and OrganizationID is overwritten from
// the authenticated scope. On THAT plane neither field can carry a foreign
// tenancy past this handler's front door.
//
// That guarantee is plane-specific and deliberately stated as such, because
// it does NOT hold on the internal-service plane (no stamped tenancy). There:
//
//   - TenantID is the trusted selector by construction — it is the calling
//     agent's own validated credential, not a caller assertion — and is
//     trimmed and used as-is.
//   - OrganizationID passes through VERBATIM and UNVALIDATED. Nothing in this
//     handler reads it, and the plane's only production caller
//     (shared/policy.DynamicPolicyEvaluator, via platform/agent/mcp_handler.go)
//     never sets it, so it is empty in practice — but that is a property of
//     today's caller, not an invariant enforced here. Anything added below
//     that reads this field must treat it as authenticated ONLY on the
//     tenant-authenticated plane, or resolve the org for itself.
//
// The internal plane is reachable only with the HMAC internal-service
// credential (requireInternalProxyAuth, #3068), so this is an operator-trust
// boundary rather than a tenancy one — but the sentence above was previously
// written without the qualifier, which is precisely the trap that invites a
// future reader to assume the field is safe on both planes.
type MCPPolicyEvaluationRequest struct {
	TenantID       string                 `json:"tenant_id"`
	OrganizationID string                 `json:"organization_id,omitempty"`
	UserID         string                 `json:"user_id"`
	UserRole       string                 `json:"user_role,omitempty"`
	ConnectorName  string                 `json:"connector_name"`
	Operation      string                 `json:"operation"`
	Statement      string                 `json:"statement"`
	Parameters     map[string]interface{} `json:"parameters,omitempty"`
	RequestTime    time.Time              `json:"request_time"`
	ClientIP       string                 `json:"client_ip,omitempty"`
	Metadata       map[string]interface{} `json:"metadata,omitempty"`
}

// MCPPolicyEvaluationResponse matches the DynamicPolicyResponse from shared/policy.
type MCPPolicyEvaluationResponse struct {
	Allowed           bool                    `json:"allowed"`
	BlockReason       string                  `json:"block_reason,omitempty"`
	PoliciesEvaluated int                     `json:"policies_evaluated"`
	MatchedPolicies   []MCPDynamicPolicyMatch `json:"matched_policies,omitempty"`
	ProcessingTimeMs  int64                   `json:"processing_time_ms"`
	Metadata          map[string]interface{}  `json:"metadata,omitempty"`
}

// MCPDynamicPolicyMatch represents a matched dynamic policy.
type MCPDynamicPolicyMatch struct {
	PolicyID   string `json:"policy_id"`
	PolicyName string `json:"policy_name"`
	PolicyType string `json:"policy_type"`
	Action     string `json:"action"`
	Reason     string `json:"reason,omitempty"`
}

// handleEvaluatePolicies evaluates dynamic policies for an MCP request.
// POST /api/v1/mcp/evaluate-policies
func (h *MCPDynamicPolicyHandler) handleEvaluatePolicies(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		h.handleCORS(w)
		return
	}

	startTime := time.Now()

	// Parse request
	var req MCPPolicyEvaluationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, "Invalid request body: "+err.Error())
		return
	}

	// #3066 C3-4: resolve the tenancy this request may be evaluated under
	// BEFORE any other validation, and BEFORE any policy is loaded, any
	// counter is touched or any name is echoed back. Authorization precedes
	// input validation here on purpose: a cross-tenant attempt must be
	// refused identically whether or not the rest of the body is well formed,
	// so the 400s cannot be used to probe which shapes reach the evaluator.
	if status, msg := h.resolveEvaluationScope(r, &req); status != 0 {
		h.writeError(w, status, msg)
		return
	}
	if req.ConnectorName == "" {
		h.writeError(w, http.StatusBadRequest, "connector_name is required")
		return
	}

	// Get applicable dynamic policies for this tenant/connector
	policies, err := h.getPoliciesForMCP(req)
	if err != nil {
		log.Printf("[MCPDynamicPolicy] Error loading policies: %v", err)
		h.writeError(w, http.StatusInternalServerError, "Failed to load policies")
		return
	}

	// Evaluate each policy
	response := MCPPolicyEvaluationResponse{
		Allowed:           true,
		PoliciesEvaluated: len(policies),
		MatchedPolicies:   []MCPDynamicPolicyMatch{},
	}

	for _, policy := range policies {
		match, allowed, reason := h.evaluatePolicy(policy, req)
		if match {
			actionType := ""
			if len(policy.Actions) > 0 {
				actionType = policy.Actions[0].Type
			}
			response.MatchedPolicies = append(response.MatchedPolicies, MCPDynamicPolicyMatch{
				PolicyID:   policy.ID,
				PolicyName: policy.Name,
				PolicyType: policy.Type,
				Action:     actionType,
				Reason:     reason,
			})

			if !allowed {
				response.Allowed = false
				response.BlockReason = reason
				break // Stop on first blocking policy
			}
		}
	}

	response.ProcessingTimeMs = time.Since(startTime).Milliseconds()

	// Return response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(response)

	log.Printf("[MCPDynamicPolicy] Evaluated %d policies for connector=%s, allowed=%v, time=%dms",
		response.PoliciesEvaluated, req.ConnectorName, response.Allowed, response.ProcessingTimeMs)
}

// carriesStampedTenancy reports whether this request traversed a hop that
// stamps the caller's AUTHENTICATED tenancy onto the request headers.
//
// It tests PRESENCE, not emptiness, and that distinction is the whole point.
// platform/agent/proxy.go Sets — never Adds — X-Tenant-ID and X-Org-ID from
// the validated credential on every proxied route (proxy.go ~:479, verified on
// origin/main), so on that plane the headers are always present even if the
// credential resolved an empty tenancy. Reading presence rather than value
// means a stamped-but-empty tenancy lands in the fail-closed branch below
// instead of silently falling through to the body — the "empty is
// attacker-selectable" shape tenantscope exists to repudiate.
//
// Either header alone is enough to select the strict branch. The gateway sets
// both together, so a request carrying exactly one did not come from it; the
// only safe reading of a half-stamped request is the stricter one.
func carriesStampedTenancy(r *http.Request) bool {
	return len(r.Header.Values(tenantscope.HeaderTenantID)) > 0 ||
		len(r.Header.Values(tenantscope.HeaderOrgID)) > 0
}

// resolveEvaluationScope decides which tenant this evaluation runs as, and
// rewrites req in place so every downstream consumer — the policy set loaded
// by getPoliciesForMCP, the `tenant_id` condition field, the rate-limit key
// and the budget key — reads one authorized value. Returns (0, "") on success,
// or an HTTP status plus a message to write.
//
// # The defect (#3066 C3-4)
//
// This handler used to scope solely on the request BODY's tenant_id, and never
// read X-Tenant-ID at all — even though POST /api/v1/mcp/evaluate-policies is
// a route the agent gateway proxies (proxy.go:588) and therefore stamps. An
// authenticated tenant A could POST {"tenant_id":"B"} and receive B's
// matched_policies — policy_id, policy_name, action and the human-authored
// reason string, which routinely names the control and the data class it
// guards — while ALSO consuming B's shared rate-limit window and B's budget
// period, because both counters are keyed on the body tenant. Disclosure plus
// resource consumption, from any valid credential in the deployment.
//
// # The contract
//
// Two planes reach this handler, and they are distinguished by whether the
// request carries stamped tenancy, never by anything the body says:
//
//   - TENANT-AUTHENTICATED plane (headers stamped). The authenticated scope is
//     authoritative. tenantscope.Bind fails closed on a missing, empty or
//     whitespace-only dimension → 401. A body tenant_id that names a DIFFERENT
//     tenant is an explicit authorization failure → 403; it is never silently
//     coerced, because a caller that asked for another tenant's policies
//     should be told no rather than handed its own answer under a name it did
//     not ask for. A body tenant_id that is absent or matches is accepted and
//     replaced by the authenticated value.
//
//   - INTERNAL-SERVICE plane (no stamped tenancy). This is the agent's own PEP
//     calling in-process across the network: platform/agent/mcp_handler.go
//     evaluateInputPolicies → shared/policy.DynamicPolicyEvaluator.Evaluate,
//     which sends Content-Type, X-Request-Source and the HMAC
//     X-Axonflow-Proxy-Auth token and NO tenancy headers. Its body tenant_id
//     is the agent's own validated credential, not a caller assertion.
//
//     This branch is not a fallback that a tenant can select. Reaching the
//     handler at all requires a valid HMAC internal-service token:
//     requireInternalProxyAuth (authn_middleware.go, #3068) wraps the entire
//     mux with no exemption for this path, and the agent gateway Sets the
//     tenancy headers on every request it forwards. So a tenant cannot arrive
//     here header-less — only a holder of AXONFLOW_INTERNAL_SERVICE_SECRET
//     can, and that is a deployment-operator credential, not a tenancy
//     boundary. TestMCP3066_RouteIsCoveredByTheInternalProxyAuthGate pins the
//     middleware half of that guarantee so it cannot be quietly removed.
//
// A hard 401 on the header-less plane was considered and rejected: it would
// not have hardened anything (that plane is already behind the HMAC gate) and
// it would have taken the MCP tool-governance plane DOWN in production —
// EvaluateWithGracefulDegradation deliberately refuses to absorb a 401/403
// (errOrchestratorAuthRejected, #3068), so every governed tool call would
// fail closed. The evaluator is the hop that would have to start sending the
// headers, and it is outside this change.
func (h *MCPDynamicPolicyHandler) resolveEvaluationScope(r *http.Request, req *MCPPolicyEvaluationRequest) (int, string) {
	bodyTenant := strings.TrimSpace(req.TenantID)

	if !carriesStampedTenancy(r) {
		if bodyTenant == "" {
			return http.StatusBadRequest, "tenant_id is required"
		}
		req.TenantID = bodyTenant
		return 0, ""
	}

	scope, err := tenantscope.Bind(r)
	if err != nil {
		log.Printf("[MCPDynamicPolicy] REFUSED: request carries stamped tenancy but no usable scope: %v", err)
		return http.StatusUnauthorized, "Unauthorized: authenticated tenant scope is required"
	}

	if bodyTenant != "" && bodyTenant != scope.TenantID {
		// Sanitized: both values are attacker-influenced strings reaching a
		// log line. Logged because a cross-tenant attempt is exactly the
		// event a SIEM wants; the RESPONSE deliberately names neither tenant.
		log.Printf("[MCPDynamicPolicy] REFUSED cross-tenant evaluation: authenticated tenant=%s requested tenant=%s",
			logutil.Sanitize(scope.TenantID), logutil.Sanitize(bodyTenant))
		return http.StatusForbidden, "Forbidden: tenant_id does not match the authenticated tenant"
	}

	req.TenantID = scope.TenantID
	// OrganizationID is unused by this handler today, but it is part of the
	// same client-supplied tenancy surface. Stamping it from the authenticated
	// scope means a future consumer of the field cannot inherit a forged org
	// simply by being added below this line. Overwrite rather than compare: an
	// `a != "" && b != "" && a != b` guard here would be the fail-open idiom
	// TestNoFailOpenOrgCompare exists to reject.
	req.OrganizationID = scope.OrgID
	return 0, ""
}

// getPoliciesForMCP retrieves applicable dynamic policies for the MCP request.
func (h *MCPDynamicPolicyHandler) getPoliciesForMCP(req MCPPolicyEvaluationRequest) ([]DynamicPolicy, error) {
	if h.policyEngine == nil {
		return []DynamicPolicy{}, nil
	}

	// Tenant scoping is the ENGINE's decision, not this handler's (#3061 R3 —
	// see the MCPPolicyEngine doc comment). ListActivePoliciesForTenant routes
	// through the same choke point that decides ENFORCEMENT on the engine the
	// deployment actually runs, so a policy is evaluated here if and only if it
	// would be enforced for this tenant on the LLM/MAP/WCP planes. The local
	// `p.TenantID != "" && p.TenantID != req.TenantID` predicate this replaces
	// was the inverse of the database engine's on all three stored shapes.
	policies := h.policyEngine.ListActivePoliciesForTenant(req.TenantID)

	// Filter by type. Tenant scoping already happened above.
	var filtered []DynamicPolicy
	for _, p := range policies {
		// Only include enabled policies. Both engines' scoped list already
		// drops disabled rows; kept as a defensive second gate so a future
		// engine cannot leak an inert policy into evaluation.
		if !p.Enabled {
			continue
		}
		// Only include policies with MCP-related types.
		//
		// #3061: "content" is admitted here. It is the type the Pro tool
		// axonflow_create_tenant_policy writes (agent/mcp_v1_pro_tools.go) and
		// the type POST /api/v1/policies defaults to (refreshPolicies COALESCEs
		// policy_type to 'content'), so excluding it meant a user-authored
		// tenant policy was dropped BEFORE evaluation and could never enforce on
		// the MCP tool-governance plane — while the tool reported "It will apply
		// to subsequent governed calls." Content policies already enforce on the
		// orchestrator LLM/MAP/WCP planes (db_dynamic_policies.go); those planes
		// are simply never transited by MCP tool calls.
		if p.Type == "mcp" || p.Type == "connector" || p.Type == "content" ||
			p.Type == "rate-limit" || p.Type == "budget" || p.Type == "time-access" ||
			p.Type == "role-access" || p.Type == "anomaly" {
			filtered = append(filtered, p)
		}
	}

	return filtered, nil
}

// evaluatePolicy evaluates a single policy against the request.
// Returns (matched, allowed, reason).
func (h *MCPDynamicPolicyHandler) evaluatePolicy(policy DynamicPolicy, req MCPPolicyEvaluationRequest) (bool, bool, string) {
	// Check policy type and evaluate accordingly
	switch policy.Type {
	case "rate-limit":
		return h.evaluateRateLimit(policy, req)
	case "budget":
		return h.evaluateBudget(policy, req)
	case "time-access":
		return h.evaluateTimeAccess(policy, req)
	case "role-access":
		return h.evaluateRoleAccess(policy, req)
	case "anomaly":
		return h.evaluateAnomaly(policy, req)
	case "mcp", "connector", "content":
		// #3061: "content" routes through the same condition evaluator as
		// "mcp"/"connector" — it carries plain field/operator/value conditions,
		// not the bespoke shape the rate-limit/budget/time-access arms parse.
		return h.evaluateConditions(policy, req)
	default:
		// Unknown policy type, skip
		return false, true, ""
	}
}

// evaluateConditions evaluates policy conditions. All conditions must hold
// (AND); a policy with no conditions never matches.
//
// #3061 fail-safe: the empty-conditions guard below is load-bearing. Without
// it the loop body never runs, control falls through to "all conditions
// matched", and a condition-less policy carrying a block action denies EVERY
// governed tool call for its tenant. That was unreachable-ish while this path
// only saw hand-authored mcp/connector policies; admitting `content` widens it
// to the type the policy API defaults to.
//
// A zero-condition policy is NOT unreachable. The create path rejects one:
// validateCreateRequest fails `len(req.Conditions) == 0` with "At least one
// condition is required". The update path does not — validateUpdateRequest
// guards only on `req.Conditions != nil`, and a JSON `[]` unmarshals to a
// non-nil, length-zero slice, so the validation loop runs zero times and
// nothing is appended. PolicyRepository.Update (policy_api_repository.go)
// persists it under that same `!= nil` guard, marshalling the slice back to
// `[]`.
// Both PUT /api/v1/policies/{id} and PUT /api/v1/dynamic-policies/{id} reach
// it. So a tenant that cleared a policy's conditions through the API while
// leaving a block action attached has exactly this row today.
//
// A stored conditions JSON the engine cannot unmarshal reaches this handler as
// the same shape: cachedPolicyToDynamicPolicy discards the unmarshal error and
// leaves Conditions nil, and this handler reads through
// ListActivePoliciesForTenant, which shares that converter.
//
// Failing such a policy to "does not match" is the safe direction: a row with
// no evaluable conditions must not be able to take governance down for a whole
// tenant. Note the fail-safe is MCP-plane only. EvaluateDynamicPolicies gates
// its AND-loop on `len(conditions) > 0`, so on the LLM/MAP/WCP planes a
// zero-condition policy still falls through to "matched" and still denies.
// (Those planes `continue` past a conditions JSON that fails to unmarshal, so
// only the empty-array shape diverges between the planes.)
func (h *MCPDynamicPolicyHandler) evaluateConditions(policy DynamicPolicy, req MCPPolicyEvaluationRequest) (bool, bool, string) {
	if len(policy.Conditions) == 0 {
		log.Printf("[MCPDynamicPolicy] policy %s (%s) has no evaluable conditions — treating as no-match",
			logutil.Sanitize(policy.ID), logutil.Sanitize(policy.Type))
		return false, true, ""
	}
	for _, cond := range policy.Conditions {
		if !h.evaluateCondition(cond, req) {
			return false, true, ""
		}
	}
	// All conditions matched, check action
	for _, action := range policy.Actions {
		if action.Type == "block" {
			reason := "Policy blocked request"
			if action.Config != nil {
				if r, ok := action.Config["reason"].(string); ok {
					reason = r
				}
			}
			return true, false, reason
		}
	}
	return true, true, ""
}

// evaluateCondition evaluates a single condition.
func (h *MCPDynamicPolicyHandler) evaluateCondition(cond PolicyCondition, req MCPPolicyEvaluationRequest) bool {
	var fieldValue interface{}

	switch cond.Field {
	case "connector":
		fieldValue = req.ConnectorName
	case "operation":
		fieldValue = req.Operation
	case "user.role":
		fieldValue = req.UserRole
	case "tenant_id":
		fieldValue = req.TenantID
	case "parameter_count":
		fieldValue = len(req.Parameters)
	case "query", "statement":
		// #3061: the governed statement — the text the caller is about to run
		// (agent/mcp_handler.go passes it as DynamicPolicyRequest.Statement on
		// every MCP plane). Both spellings resolve here: "query" is what the
		// Pro tool axonflow_create_tenant_policy writes and what the
		// orchestrator content engine uses (db_dynamic_policies.go), "statement"
		// is the wire field's own name. Without this the field fell to the
		// default arm, yielded a nil fieldValue and could only evaluate FALSE.
		fieldValue = req.Statement
	default:
		if strings.HasPrefix(cond.Field, "parameters.") {
			key := strings.TrimPrefix(cond.Field, "parameters.")
			if req.Parameters != nil {
				if v, ok := req.Parameters[key]; ok {
					fieldValue = fmt.Sprintf("%v", v)
				}
			}
		}
		if fieldValue == nil {
			return false
		}
	}

	switch cond.Operator {
	case "equals":
		return fmt.Sprintf("%v", fieldValue) == fmt.Sprintf("%v", cond.Value)
	case "not_equals":
		return fmt.Sprintf("%v", fieldValue) != fmt.Sprintf("%v", cond.Value)
	case "contains":
		return strings.Contains(fmt.Sprintf("%v", fieldValue), fmt.Sprintf("%v", cond.Value))
	case "regex":
		// #3061: semantics deliberately IDENTICAL to the orchestrator content
		// engine's regex arm (db_dynamic_policies.go evaluateOperator) so one
		// stored policy behaves the same on the MCP plane and the LLM/MAP/WCP
		// planes: unanchored, case-sensitive RE2 search over the field's string
		// form, a non-string pattern is a non-match, and a pattern that fails to
		// COMPILE fails SAFE (logged, treated as "did not match") rather than
		// erroring the whole evaluation — one malformed tenant policy must not
		// take down governance for every other policy in the set.
		fieldStr, ok := fieldValue.(string)
		if !ok {
			fieldStr = fmt.Sprintf("%v", fieldValue)
		}
		pattern, ok := cond.Value.(string)
		if !ok {
			return false
		}
		matched, err := regexp.MatchString(pattern, fieldStr)
		if err != nil {
			// Sanitized: the pattern is tenant-authored, so it must not be able
			// to inject newlines/control characters into the log stream.
			log.Printf("[MCPDynamicPolicy] Regex error for pattern %s: %v", logutil.Sanitize(pattern), err)
			return false
		}
		return matched
	default:
		return false
	}
}

// evaluateRateLimit checks rate limiting policies using sliding window counters.
// Uses Redis for distributed deployments when REDIS_URL is set, falls back to in-memory.
func (h *MCPDynamicPolicyHandler) evaluateRateLimit(policy DynamicPolicy, req MCPPolicyEvaluationRequest) (bool, bool, string) {
	// Extract rate limit config from policy conditions
	var maxRequests int
	windowSeconds := 60 // Default 1-minute window

	for _, cond := range policy.Conditions {
		switch cond.Field {
		case "requests_per_minute":
			if limit, ok := cond.Value.(float64); ok {
				maxRequests = int(limit)
				windowSeconds = 60
			}
		case "requests_per_hour":
			if limit, ok := cond.Value.(float64); ok {
				maxRequests = int(limit)
				windowSeconds = 3600
			}
		case "max_requests":
			if limit, ok := cond.Value.(float64); ok {
				maxRequests = int(limit)
			}
		case "window_seconds":
			if window, ok := cond.Value.(float64); ok {
				windowSeconds = int(window)
			}
		}
	}

	if maxRequests <= 0 {
		// No rate limit configured, allow
		return true, true, ""
	}

	// Build rate limit key: tenant + user + connector
	key := fmt.Sprintf("ratelimit:%s:%s:%s", req.TenantID, req.UserID, req.ConnectorName)

	// Try Redis first for distributed rate limiting
	if IsPolicyRedisAvailable() {
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()
		matched, allowed, reason := checkRateLimitRedis(ctx, key, maxRequests, windowSeconds)
		if matched {
			return matched, allowed, reason
		}
		// Redis failed, fall through to in-memory
	}

	// In-memory fallback (single-instance deployments or Redis unavailable)
	rateLimitMutex.Lock()
	defer rateLimitMutex.Unlock()

	now := time.Now()
	entry, exists := rateLimitStore[key]

	if !exists || now.After(entry.windowEnd) {
		// New window
		rateLimitStore[key] = &rateLimitEntry{
			count:     1,
			windowEnd: now.Add(time.Duration(windowSeconds) * time.Second),
		}
		return true, true, ""
	}

	// Check if under limit
	if entry.count >= maxRequests {
		return true, false, fmt.Sprintf("Rate limit exceeded: %d requests per %d seconds", maxRequests, windowSeconds)
	}

	// Increment counter
	entry.count++
	return true, true, ""
}

// evaluateBudget checks budget/cost control policies using usage tracking.
// Uses Redis for distributed deployments when REDIS_URL is set, falls back to in-memory.
func (h *MCPDynamicPolicyHandler) evaluateBudget(policy DynamicPolicy, req MCPPolicyEvaluationRequest) (bool, bool, string) {
	// Extract budget config from policy conditions
	var maxBudget float64
	periodDays := 30        // Default monthly period
	costPerRequest := 0.001 // Default cost estimate per MCP query

	for _, cond := range policy.Conditions {
		switch cond.Field {
		case "max_budget", "budget_limit":
			if limit, ok := cond.Value.(float64); ok {
				maxBudget = limit
			}
		case "period_days":
			if days, ok := cond.Value.(float64); ok {
				periodDays = int(days)
			}
		case "cost_per_request":
			if cost, ok := cond.Value.(float64); ok {
				costPerRequest = cost
			}
		}
	}

	if maxBudget <= 0 {
		// No budget configured, allow
		return true, true, ""
	}

	// Build budget key: tenant + user (or org-level)
	key := fmt.Sprintf("budget:%s:%s", req.TenantID, req.UserID)
	if req.UserID == "" {
		key = fmt.Sprintf("budget:%s:org", req.TenantID)
	}

	// Try Redis first for distributed budget tracking
	if IsPolicyRedisAvailable() {
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()
		matched, allowed, reason := checkBudgetRedis(ctx, key, maxBudget, costPerRequest, periodDays)
		if matched {
			return matched, allowed, reason
		}
		// Redis failed, fall through to in-memory
	}

	// In-memory fallback (single-instance deployments or Redis unavailable)
	budgetStoreMutex.Lock()
	defer budgetStoreMutex.Unlock()

	now := time.Now()
	entry, exists := budgetStore[key]

	if !exists || now.After(entry.periodEnd) {
		// New budget period
		budgetStore[key] = &budgetEntry{
			used:      costPerRequest,
			periodEnd: now.AddDate(0, 0, periodDays),
		}
		return true, true, ""
	}

	// Check if under budget
	if entry.used+costPerRequest > maxBudget {
		return true, false, fmt.Sprintf("Budget exceeded: $%.2f used of $%.2f limit", entry.used, maxBudget)
	}

	// Increment usage
	entry.used += costPerRequest
	return true, true, ""
}

// evaluateTimeAccess checks time-based access policies.
//
// Two forms are supported:
//
//   - Timezone-anchored business-hours window (#2522): when the policy declares a
//     `timezone` + `business_hours_start`/`business_hours_end` band, the request
//     time is interpreted in that timezone and a request outside the band matches.
//     The disposition follows the policy action (block / require_approval hold the
//     request; alert / warn / log surface it for the SIEM) — this is a design
//     partner's R&C §6.2 "off-hours API access (outside 07:00–22:00 WIB)" Layer-4 control.
//   - Legacy UTC hour/day comparison (backward compatible): retained verbatim for
//     existing `hour`/`day` policies.
//
// The request's own RequestTime is honored when supplied (so the PEP can stamp
// the originating instant) and falls back to now.
func (h *MCPDynamicPolicyHandler) evaluateTimeAccess(policy DynamicPolicy, req MCPPolicyEvaluationRequest) (bool, bool, string) {
	now := time.Now()
	if req.RequestTime.IsZero() {
		req.RequestTime = now
	}

	// Timezone-anchored business-hours window takes precedence when declared.
	if window, ok := parseBusinessHoursWindow(policy); ok {
		if outsideBusinessHours(window, req.RequestTime) {
			reason := businessHoursReason(window)
			if r := actionReason(policy); r != "" {
				reason = r
			}
			return true, !actionDenies(firstActionType(policy)), reason
		}
		return false, true, ""
	}

	// Check conditions for time-based policies
	for _, cond := range policy.Conditions {
		switch cond.Field {
		case "hour":
			currentHour := now.Hour()
			if cond.Operator == "greater_than" {
				if limit, ok := cond.Value.(float64); ok {
					if currentHour <= int(limit) {
						return true, false, "Access denied: Outside allowed hours"
					}
				}
			}
			if cond.Operator == "less_than" {
				if limit, ok := cond.Value.(float64); ok {
					if currentHour >= int(limit) {
						return true, false, "Access denied: Outside allowed hours"
					}
				}
			}
		case "day":
			currentDay := now.Weekday().String()
			if cond.Operator == "in" {
				if days, ok := cond.Value.([]interface{}); ok {
					found := false
					for _, day := range days {
						if day == currentDay {
							found = true
							break
						}
					}
					if !found {
						return true, false, "Access denied: Outside allowed days"
					}
				}
			}
		}
	}

	return true, true, ""
}

// evaluateRoleAccess checks role-based access policies.
func (h *MCPDynamicPolicyHandler) evaluateRoleAccess(policy DynamicPolicy, req MCPPolicyEvaluationRequest) (bool, bool, string) {
	for _, cond := range policy.Conditions {
		if cond.Field == "user.role" {
			switch cond.Operator {
			case "in":
				// Check if user role is in allowed list
				if roles, ok := cond.Value.([]interface{}); ok {
					found := false
					for _, role := range roles {
						if role == req.UserRole || role == "*" {
							found = true
							break
						}
					}
					if !found {
						return true, false, "Access denied: Insufficient role permissions"
					}
				}
			case "not_in":
				// Check if user role is in denied list
				if roles, ok := cond.Value.([]interface{}); ok {
					for _, role := range roles {
						if role == req.UserRole {
							return true, false, "Access denied: Role explicitly blocked"
						}
					}
				}
			case "equals":
				if cond.Value != req.UserRole {
					return true, false, "Access denied: Role mismatch"
				}
			}
		}
	}

	return true, true, ""
}

// handleCORS sets CORS headers.
func (h *MCPDynamicPolicyHandler) handleCORS(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Tenant-ID")
	w.WriteHeader(http.StatusOK)
}

// writeError writes an error response.
func (h *MCPDynamicPolicyHandler) writeError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"success": false,
		"error":   message,
	})
}

// Global MCP dynamic policy handler
var globalMCPDynamicPolicyHandler *MCPDynamicPolicyHandler

// InitMCPDynamicPolicyHandler initializes the global handler.
func InitMCPDynamicPolicyHandler(engine *DynamicPolicyEngine) {
	globalMCPDynamicPolicyHandler = NewMCPDynamicPolicyHandler(engine)
}

// GetMCPDynamicPolicyHandler returns the global handler.
func GetMCPDynamicPolicyHandler() *MCPDynamicPolicyHandler {
	return globalMCPDynamicPolicyHandler
}
