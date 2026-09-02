// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"sync"
	"time"

	"axonflow/platform/decision/legacycompile"
	"github.com/gorilla/mux"
)

// PolicySimulationHandler handles policy simulation and impact report endpoints.
// Available to Evaluation tier and above.
type PolicySimulationHandler struct {
	engine interface {
		EvaluateDynamicPolicies(context.Context, OrchestratorRequest) *PolicyEvaluationResult
		ListActivePoliciesForTenant(tenantID string, segmentIDs []string) []DynamicPolicy
	}
	policyService   *PolicyService
	conflictService *PolicyConflictService
	tierChecker     LicenseChecker
	rateLimiter     *simulationRateLimiter
}

// simulationRateLimiter tracks daily simulation usage per tenant.
// NOTE: This is per-process in-memory state. In multi-replica deployments,
// each replica enforces its own limit independently.
type simulationRateLimiter struct {
	mu      sync.Mutex
	counts  map[string]int // tenant → count
	resetAt time.Time      // when to reset (start of next UTC day)
}

var simRateLimiter = &simulationRateLimiter{
	counts:  make(map[string]int),
	resetAt: nextUTCMidnight(),
}

func (rl *simulationRateLimiter) tryConsume(tenantID string, limit int) (bool, int) {
	if limit < 0 { // unlimited (-1)
		return true, 0
	}

	rl.mu.Lock()
	defer rl.mu.Unlock()

	if time.Now().UTC().After(rl.resetAt) {
		rl.counts = make(map[string]int)
		rl.resetAt = nextUTCMidnight()
	}

	current := rl.counts[tenantID]
	if current >= limit {
		return false, current
	}

	rl.counts[tenantID]++
	return true, current + 1
}

// NewPolicySimulationHandler creates a new policy simulation handler.
func NewPolicySimulationHandler(engine interface {
	EvaluateDynamicPolicies(context.Context, OrchestratorRequest) *PolicyEvaluationResult
	ListActivePoliciesForTenant(tenantID string, segmentIDs []string) []DynamicPolicy
}, policyService *PolicyService, conflictService *PolicyConflictService, tierChecker LicenseChecker) *PolicySimulationHandler {
	return &PolicySimulationHandler{
		engine:          engine,
		policyService:   policyService,
		conflictService: conflictService,
		tierChecker:     tierChecker,
		rateLimiter:     simRateLimiter,
	}
}

// RegisterRoutes registers simulation endpoints.
func (h *PolicySimulationHandler) RegisterRoutes(r *mux.Router) {
	r.HandleFunc("/api/v1/policies/simulate", h.SimulatePolicies).Methods("POST", "OPTIONS")
	r.HandleFunc("/api/v1/policies/impact-report", h.ImpactReport).Methods("POST", "OPTIONS")
	r.HandleFunc("/api/v1/policies/conflicts", h.DetectConflicts).Methods("POST", "OPTIONS")
}

// SimulatePolicies handles POST /api/v1/policies/simulate.
// Runs all active policies against the input as a dry run.
func (h *PolicySimulationHandler) SimulatePolicies(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	// License gate
	if !h.tierChecker.IsPolicySimulationEnabled() {
		writeJSONError(w, http.StatusForbidden, ErrCodeFeatureRequiresEvaluation,
			"Policy simulation requires an Evaluation or Enterprise license. Get a free eval license: https://getaxonflow.com/evaluation-license")
		return
	}

	var req SimulatePoliciesRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "BAD_REQUEST", "Invalid request body: "+err.Error())
		return
	}
	if req.Query == "" {
		writeJSONError(w, http.StatusBadRequest, "BAD_REQUEST", "query is required")
		return
	}

	tenantID := resolveTenantOrFail(w, r, "policy/simulate")
	if tenantID == "" {
		return // resolveTenantOrFail already wrote a 401
	}

	// Decision 5 (#3490) R3 round 2: resolved through the shared refusal
	// helper rather than read raw off the header, for two reasons. It trims,
	// so " acme" does not scope the simulation to an organisation that matches
	// nothing while CreatePolicy writes "acme"; and it refuses an unbound
	// caller instead of silently simulating against the global baseline alone.
	// A simulation that evaluated a different policy set from the live path
	// would be worse than no simulation, and it looks convincing either way:
	// the verdict and the policy count are both self-consistent.
	orgID := resolveOrgOrFail(w, r, "policy/simulate")
	if orgID == "" {
		return // resolveOrgOrFail already wrote a 401
	}

	// Rate limit check
	limit := h.tierChecker.MaxSimulationsPerDay()
	allowed, current := h.rateLimiter.tryConsume(tenantID, limit)
	if !allowed {
		writeJSONError(w, http.StatusTooManyRequests, ErrCodeSimulationLimitExceeded,
			"Daily simulation limit reached ("+strconv.Itoa(current)+"/"+strconv.Itoa(limit)+"). Upgrade to Enterprise for unlimited simulations: https://getaxonflow.com/pricing")
		return
	}

	// Build OrchestratorRequest for dry-run evaluation
	orchReq := OrchestratorRequest{
		RequestID:   "sim-" + time.Now().Format("20060102-150405"),
		Query:       req.Query,
		RequestType: req.RequestType,
		User:        req.User,
		Client:      req.Client,
		Context:     req.Context,
		SkipLLM:     true, // Dry run — don't call LLMs
		Timestamp:   time.Now(),
	}
	if orchReq.RequestType == "" {
		orchReq.RequestType = "simulation"
	}

	// Force the tenant the GATEWAY stamped into the evaluation context, so
	// tenant-scoped policies are included in the simulation (not just global
	// ones) — and so the caller cannot choose which tenant is simulated.
	//
	// This used to fill the tenant only when the BODY left it empty, i.e. a
	// body-supplied tenant won. Simulation is a dry run, but not a side-effect
	// free one: EvaluateDynamicPolicies records a policy_metrics analytics row
	// whose org_id is ALSO the app.current_org_id binding its INSERT is checked
	// against, so the RLS WITH CHECK passes for whatever tenant the caller
	// names. Same class as the /policies/test fix in run.go; kept identical
	// here so the two evaluation endpoints cannot diverge.
	// Client.ID still falls back only when unset — it is a client identifier,
	// not a scope, and overwriting it would change which client's policies
	// match.
	//
	// orchReq.User.OrgID is forced from the gateway-stamped X-Org-ID header
	// the same way, and for the same reason as the /policies/test fix in
	// run.go (kept identical so the two evaluation endpoints cannot diverge):
	// after P3b (ADR-060), EvaluateDynamicPolicies feeds User.OrgID and
	// User.Email straight into resolveUserSegments, which resolves
	// against the LIVE SCIM directory of whichever org it is given. A
	// body-sourced OrgID paired with a body-sourced Email would let a caller
	// probe an arbitrary org's SCIM group membership one hypothetical email at
	// a time and read the answer back out of Allowed/AppliedPolicies — a
	// cross-org information-disclosure oracle. Email stays caller-supplied,
	// same as the tenant fix above; OrgID does not.
	//
	// Decision 5 (#3490) R3 BLOCKER: Client.OrgID must be forced here too, and
	// was not. ClientContext.OrgID is on the wire (`json:"org_id"`) and
	// EvaluateDynamicPolicies now reads it FIRST, so a body carrying
	// {"client":{"org_id":"<victim>"}} chose which organisation's policies were
	// evaluated - over a gate cache loaded ALL-TENANTS through the BYPASSRLS
	// pool. That is precisely the cross-org oracle the block above closed for
	// the TENANT dimension; moving the selection key without moving the
	// stamping re-opened it one dimension over. Verified by driving the real
	// handler with a body org that differed from the header.
	//
	// It also bound the policy_metrics write: EvaluateDynamicPolicies derives
	// its org scope from the same value, so the RLS WITH CHECK passed by
	// construction and the caller wrote analytics rows attributed to the
	// victim org.
	orchReq.User.TenantID = tenantID
	orchReq.User.OrgID = orgID
	orchReq.Client.TenantID = tenantID
	orchReq.Client.OrgID = orgID
	if orchReq.Client.ID == "" {
		orchReq.Client.ID = tenantID
	}

	// Evaluate
	orchReq.ShadowPlane = legacycompile.PlanePolicySimulation // ADR-065 decision shadow (#3564)
	result := h.engine.EvaluateDynamicPolicies(r.Context(), orchReq)
	// Count only the policies visible to the CALLER's org. The raw
	// ListActivePolicies cache is deployment-wide, so counting it leaked how
	// many policies exist across ALL tenants in every simulate response.
	// ADR-060 (#2989 P3b): nil segments — this is only a COUNT for usage
	// info, not the policies themselves, and no verified per-user email is
	// available here.
	//
	// Decision 5 (#3490): keyed on orchReq.Client.OrgID - the SAME field
	// EvaluateDynamicPolicies selects by, not merely the same header. Both are
	// forced from X-Org-ID above, but reading the other one would make this a
	// claim about a value rather than about the set actually evaluated, and
	// the two would silently diverge the moment a caller populated one and not
	// the other. That is not hypothetical: it is exactly how the body-org hole
	// above went unnoticed.
	totalPolicies := len(h.engine.ListActivePoliciesForTenant(orchReq.Client.OrgID, nil))

	// Build usage info
	var usage *SimulationDailyUsage
	if limit > 0 {
		usage = &SimulationDailyUsage{
			Used:  current,
			Limit: limit,
		}
	}

	resp := SimulatePoliciesResponse{
		Allowed:          result.Allowed,
		AppliedPolicies:  result.AppliedPolicies,
		RiskScore:        result.RiskScore,
		RequiredActions:  result.RequiredActions,
		ProcessingTimeMs: result.ProcessingTimeMs,
		TotalPolicies:    totalPolicies,
		DryRun:           true,
		SimulatedAt:      time.Now(),
		Tier:             string(h.tierChecker.Tier()),
		DailyUsage:       usage,
		SegmentsResolved: result.SegmentsResolved,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

// ImpactReport handles POST /api/v1/policies/impact-report.
// Tests a single policy against multiple inputs and returns aggregate statistics.
//
// SEGMENT-BLIND (ADR-060 #2989 P3b, M4, #3239 round 2): unlike SimulatePolicies
// above, this handler evaluates the named policy directly rather than going
// through EvaluateDynamicPolicies/resolveUserSegments, so it never
// resolves or reports a caller's segment membership — a segment-scoped
// policy's impact is reported identically to an unscoped one. Documented
// now rather than fixed here (loud, not silent); the fix is tracked as
// follow-up **#3283**.
func (h *PolicySimulationHandler) ImpactReport(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	// License gate
	if !h.tierChecker.IsPolicySimulationEnabled() {
		writeJSONError(w, http.StatusForbidden, ErrCodeFeatureRequiresEvaluation,
			"Impact report requires an Evaluation or Enterprise license. Get a free eval license: https://getaxonflow.com/evaluation-license")
		return
	}

	var req ImpactReportRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "BAD_REQUEST", "Invalid request body: "+err.Error())
		return
	}
	if req.PolicyID == "" {
		writeJSONError(w, http.StatusBadRequest, "BAD_REQUEST", "policy_id is required")
		return
	}
	if len(req.Inputs) == 0 {
		writeJSONError(w, http.StatusBadRequest, "BAD_REQUEST", "at least one input is required")
		return
	}

	// Enforce input limit
	maxInputs := h.tierChecker.MaxImpactReportInputs()
	if maxInputs > 0 && len(req.Inputs) > maxInputs {
		writeJSONError(w, http.StatusBadRequest, "INPUT_LIMIT_EXCEEDED",
			"Too many inputs. Maximum allowed: "+strconv.Itoa(maxInputs))
		return
	}

	tenantID := resolveTenantOrFail(w, r, "policy/impact-report")
	if tenantID == "" {
		return // resolveTenantOrFail already wrote a 401
	}
	// Decision 5 (#3490) R3 round 2: an impact report runs the same evaluation
	// the live plane runs, and the policy set is chosen by org. Resolved through
	// the shared refusal helper rather than a bare header read, so an unbound
	// caller is refused instead of being quietly reported against the global
	// baseline alone - a report computed over a different policy set from the
	// live path is worse than no report.
	orgID := resolveOrgOrFail(w, r, "policy/impact-report")
	if orgID == "" {
		return // resolveOrgOrFail already wrote a 401
	}

	if h.policyService == nil {
		writeJSONError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Policy service not available")
		return
	}

	start := time.Now()
	var matched, blocked int
	results := make([]ImpactReportResult, 0, len(req.Inputs))

	for i, input := range req.Inputs {
		testReq := &TestPolicyRequest{
			Query:       input.Query,
			User:        input.User,
			RequestType: input.RequestType,
			Context:     input.Context,
		}

		testResp, err := h.policyService.TestPolicy(r.Context(), tenantID, orgID, req.PolicyID, testReq)
		if err != nil {
			log.Printf("[ImpactReport] Error testing input %d: %v", i, err)
			writeJSONError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to evaluate input "+strconv.Itoa(i))
			return
		}

		var actions []string
		for _, a := range testResp.Actions {
			actions = append(actions, a.Type)
		}

		result := ImpactReportResult{
			InputIndex: i,
			Matched:    testResp.Matched,
			Blocked:    testResp.Blocked,
			Actions:    actions,
		}
		results = append(results, result)

		if testResp.Matched {
			matched++
		}
		if testResp.Blocked {
			blocked++
		}
	}

	total := len(req.Inputs)
	resp := ImpactReportResponse{
		PolicyID:         req.PolicyID,
		TotalInputs:      total,
		Matched:          matched,
		Blocked:          blocked,
		MatchRate:        float64(matched) / float64(total),
		BlockRate:        float64(blocked) / float64(total),
		Results:          results,
		ProcessingTimeMs: time.Since(start).Milliseconds(),
		GeneratedAt:      time.Now(),
		Tier:             string(h.tierChecker.Tier()),
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

// DetectConflicts handles POST /api/v1/policies/conflicts.
// Analyzes active policies for contradictions, shadows, and redundancies.
//
// SEGMENT-BLIND (ADR-060 #2989 P3b, M4, #3239 round 2): conflict detection
// compares policies pairwise without factoring in segment_id — two policies
// scoped to different, non-overlapping segments (and therefore never
// simultaneously applicable to the same caller) can be reported as
// "conflicting" when they are not. Documented now rather than fixed here
// (loud, not silent); the fix is tracked as follow-up **#3283**.
func (h *PolicySimulationHandler) DetectConflicts(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	// License gate
	if !h.tierChecker.IsPolicySimulationEnabled() {
		writeJSONError(w, http.StatusForbidden, ErrCodeFeatureRequiresEvaluation,
			"Policy conflict detection requires an Evaluation or Enterprise license. Get a free eval license: https://getaxonflow.com/evaluation-license")
		return
	}

	tenantID := r.Header.Get("X-Tenant-ID")
	if tenantID == "" {
		if tid, ok := r.Context().Value("tenant_id").(string); ok {
			tenantID = tid
		}
	}
	if tenantID == "" {
		writeJSONError(w, http.StatusBadRequest, "BAD_REQUEST", "X-Tenant-ID header is required")
		return
	}

	// Decision 5 (#3490) R3 round 2: conflict detection lists the policies it
	// compares, and that list is now org-keyed. Without this the report was
	// built from whatever ListPolicies returned for an empty org - the global
	// baseline - and reported "no conflicts" over a set that excluded every
	// policy the organisation actually authored.
	orgID := resolveOrgOrFail(w, r, "policy/conflicts")
	if orgID == "" {
		return // resolveOrgOrFail already wrote a 401
	}

	// Rate limit check
	limit := h.tierChecker.MaxSimulationsPerDay()
	allowed, current := h.rateLimiter.tryConsume(tenantID, limit)
	if !allowed {
		writeJSONError(w, http.StatusTooManyRequests, ErrCodeSimulationLimitExceeded,
			"Daily simulation limit reached ("+strconv.Itoa(current)+"/"+strconv.Itoa(limit)+"). Upgrade to Enterprise for unlimited simulations: https://getaxonflow.com/pricing")
		return
	}

	var req PolicyConflictRequest
	if r.Body != nil && r.ContentLength > 0 {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSONError(w, http.StatusBadRequest, "BAD_REQUEST", "Invalid request body: "+err.Error())
			return
		}
	}

	resp, err := h.conflictService.DetectConflicts(r.Context(), tenantID, orgID, req.PolicyID)
	if err != nil {
		log.Printf("[DetectConflicts] Error: %v", err)
		writeJSONError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to detect conflicts")
		return
	}

	resp.Tier = string(h.tierChecker.Tier())

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

// writeJSONError writes a JSON error response.
func writeJSONError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":   code,
		"code":    code,
		"message": message,
	})
}
