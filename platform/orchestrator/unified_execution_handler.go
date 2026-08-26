// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"

	"axonflow/platform/agent/license"
	"axonflow/platform/orchestrator/planning"
	"axonflow/platform/shared/execution"
	sharedidentity "axonflow/platform/shared/identity"
	logutil "axonflow/platform/shared/logger"
	"axonflow/platform/shared/tenantscope"
)

// UnifiedExecutionHandler handles HTTP requests for unified execution status tracking.
// This supports both MAP plans and WCP workflows through a common API.
type UnifiedExecutionHandler struct {
	repo              execution.ExecutionRepository
	mapTracker        *MAPExecutionTracker
	wcpTracker        *WCPExecutionTracker
	eventHub          *execution.EventHub
	planService       *planning.Service
	licenseChecker    LicenseChecker
	logger            *log.Logger
	connectionTracker *execution.ConnectionTracker
}

// NewUnifiedExecutionHandler creates a new unified execution handler.
func NewUnifiedExecutionHandler(
	repo execution.ExecutionRepository,
	mapTracker *MAPExecutionTracker,
	wcpTracker *WCPExecutionTracker,
	eventHub *execution.EventHub,
	planService *planning.Service,
) *UnifiedExecutionHandler {
	return &UnifiedExecutionHandler{
		repo:              repo,
		mapTracker:        mapTracker,
		wcpTracker:        wcpTracker,
		eventHub:          eventHub,
		planService:       planService,
		logger:            log.Default(),
		connectionTracker: execution.NewConnectionTracker(),
	}
}

// SetLicenseChecker sets the license checker for tier enforcement.
// Also updates the SSE connection tracker limit from the tier.
func (h *UnifiedExecutionHandler) SetLicenseChecker(lc LicenseChecker) {
	h.licenseChecker = lc
	if h.connectionTracker != nil && lc != nil {
		h.connectionTracker.SetMaxConnections(lc.MaxSSEConnections())
	}
}

// callerHasOrgTenancyScope reports whether this request carries a trusted
// org-wide TENANCY assertion (#3367).
//
// True only when BOTH hold:
//
//  1. the request bears a valid X-Axonflow-Proxy-Auth internal-service token
//     (the #2896 trusted channel, held only by the agent gateway and the
//     customer portal), and
//  2. it carries X-Axonflow-Tenancy-Scope: org.
//
// The agent strips the header from every inbound client request (it is in
// sharedidentity.NeverClientAssertableHeaders), so a governed caller cannot
// launder it through the gateway; a request that reaches the orchestrator
// directly cannot mint one either, because the token is HMAC-signed.
//
// Deliberately NOT granted in Community mode. Community has no customer
// portal to assert this, and community callers already read their own
// executions through the tenant header exactly as before; a blanket community
// grant would widen a plane for a reason that does not apply to it.
func callerHasOrgTenancyScope(r *http.Request) bool {
	if !sharedidentity.TenancyScopeIsOrg(r.Header.Get(sharedidentity.HeaderTenancyScope)) {
		return false
	}
	if proxyTokenValidator == nil {
		return false
	}
	tok := r.Header.Get("X-Axonflow-Proxy-Auth")
	if tok == "" {
		return false
	}
	valid, _, _ := proxyTokenValidator.ValidateToken(tok)
	return valid
}

// checkTenantOwnership validates that the execution belongs to the requesting
// caller for a READ. See checkTenantOwnershipStrict for the write form.
func (h *UnifiedExecutionHandler) checkTenantOwnership(w http.ResponseWriter, r *http.Request, exec *execution.ExecutionStatus) bool {
	return h.authorizeExecution(w, r, exec, callerHasOrgTenancyScope(r))
}

// checkTenantOwnershipStrict is the WRITE form: it never accepts the org-wide
// tenancy assertion, so a mutating route keeps the exact pre-#3367 compare.
//
// #3367 R3 round 1: the org-only relaxation is a READ decision. Letting it
// reach CancelExecution would silently mean "any org-bound session may abort an
// execution started by any credential in the org", which is a separate
// authorization question nobody has reviewed. It is not reachable today (the
// cancel route is absent from the portal proxy allowlist, so the catch-all
// refuses it with 403 ROUTE_NOT_PROXIED, and enforceDomainReadAuthority
// additionally demands admin authority) - which is exactly why it must be
// closed here rather than left to be discovered by whoever adds the route.
// It would also only half-work: CancelExecution forwards the caller's
// X-Tenant-ID into AbortWorkflow, which runs its own tenancy check against a
// value an org-bound session does not hold.
func (h *UnifiedExecutionHandler) checkTenantOwnershipStrict(w http.ResponseWriter, r *http.Request, exec *execution.ExecutionStatus) bool {
	return h.authorizeExecution(w, r, exec, false)
}

// authorizeExecution validates that the execution belongs to the requesting
// caller. Returns true if the request is allowed, false if denied.
//
// Multi-tenant isolation: returns 404 on mismatch (not 403) to avoid leaking
// execution existence across tenants. Requires X-Org-ID, plus X-Tenant-ID
// unless the caller carries a trusted org-wide tenancy assertion -- the
// permissive fallback is removed because it was a cross-tenant data leak
// vector (executions without tenant_id were accessible to any caller).
//
// #3367: a caller whose authority IS the org (the customer portal session
// plane) is authorized on org_id alone. The row's tenant_id is the executing
// credential's id, which a portal session never holds, so comparing it there
// 404'd every execution the session was entitled to open from its own list.
//
// The org compare runs through tenantscope rather than a raw `!=`, so this
// half of the fix and the repository half agree on what a usable org key is:
// blank, whitespace-only and the migration core/156 unowned sentinel all fail
// closed, on BOTH the caller's side and the row's. A raw compare would have
// let a deployment whose ORG_ID is the sentinel open every unowned row here
// while the list refused them.
//
// Note the status split, which is deliberate and asymmetric. A caller that
// presented NO tenancy key at all gets 401 (an authentication problem it can
// see and fix). Everything after that -- an unusable caller key, an unusable
// row key, a mismatch -- is 404, including the tenantscope.ErrNoCallerScope
// the package documents as a 401: past the presence check, distinguishing
// "your org is the unowned sentinel" from "that execution is not yours" would
// be an existence oracle across the tenancy boundary this function guards.
//
// R3 round 2: only the PRESENCE decision looks at a trimmed value; the
// comparisons use the raw one. The writer (repository Create) stamps
// tenant_id/org_id raw, so a reader that silently trimmed before comparing
// would be a second call site normalizing one value differently. The org
// dimension is safe either way because AuthorizeOrgOnly trims BOTH sides
// symmetrically.
func (h *UnifiedExecutionHandler) authorizeExecution(w http.ResponseWriter, r *http.Request, exec *execution.ExecutionStatus, orgScoped bool) bool {
	tenantID := r.Header.Get("X-Tenant-ID")
	orgID := r.Header.Get("X-Org-ID")

	// Require authenticated identity on every request. The agent's auth
	// middleware sets these headers from the validated client license; if
	// they're missing here, the request bypassed auth and should be denied.
	// An org-scoped caller still MUST present an org: that predicate is the
	// entire tenancy boundary once the tenant compare is dropped.
	if strings.TrimSpace(orgID) == "" || (strings.TrimSpace(tenantID) == "" && !orgScoped) {
		h.writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "Missing tenant or org identity")
		return false
	}

	// Executions that lack a usable org_id (or, for a credential-scoped
	// caller, a tenant_id) are treated as not-owned-by-anyone.
	if tenantscope.NewOrgOnly(orgID).AuthorizeOrgOnly(exec.OrgID) != nil {
		h.writeError(w, http.StatusNotFound, "NOT_FOUND", "Execution not found")
		return false
	}
	if !orgScoped && (exec.TenantID == "" || exec.TenantID != tenantID) {
		h.writeError(w, http.StatusNotFound, "NOT_FOUND", "Execution not found")
		return false
	}
	return true
}

// RegisterRoutes registers the unified execution API routes.
// These are registered at /api/v1/unified/executions to avoid conflict with replay API.
func (h *UnifiedExecutionHandler) RegisterRoutes(r *mux.Router) {
	// Unified execution status API - separate from replay
	r.HandleFunc("/api/v1/unified/executions", h.ListExecutions).Methods("GET", "OPTIONS")
	r.HandleFunc("/api/v1/unified/executions/{id}", h.GetExecutionStatus).Methods("GET", "OPTIONS")
	r.HandleFunc("/api/v1/unified/executions/{id}/cancel", h.CancelExecution).Methods("POST", "OPTIONS")
	r.HandleFunc("/api/v1/unified/executions/{id}/stream", h.StreamExecutionStatus).Methods("GET", "OPTIONS")
}

// ListExecutions handles GET /api/v1/unified/executions
func (h *UnifiedExecutionHandler) ListExecutions(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		h.handleCORS(w, r)
		return
	}

	req := execution.ListExecutionsRequest{
		Limit:  20,
		Offset: 0,
	}

	// Cap results to tier-based execution history limit
	maxHistory := 100 // default max
	if h.licenseChecker != nil {
		tierMax := h.licenseChecker.MaxExecutionHistory()
		if tierMax > 0 && tierMax < maxHistory {
			maxHistory = tierMax
		}
	}

	// Parse query parameters
	if limit := r.URL.Query().Get("limit"); limit != "" {
		if l, err := strconv.Atoi(limit); err == nil && l > 0 && l <= maxHistory {
			req.Limit = l
		}
	}
	if offset := r.URL.Query().Get("offset"); offset != "" {
		if o, err := strconv.Atoi(offset); err == nil && o >= 0 {
			req.Offset = o
		}
	}
	if execType := r.URL.Query().Get("execution_type"); execType != "" {
		t := execution.ExecutionType(execType)
		req.ExecutionType = &t
	}
	if status := r.URL.Query().Get("status"); status != "" {
		s := execution.ExecutionStatusValue(status)
		req.Status = &s
	}

	// Get tenant context from headers.
	req.TenantID = r.Header.Get("X-Tenant-ID")
	req.OrgID = r.Header.Get("X-Org-ID")

	// #3367: drop the credential narrowing for a caller bound to the ORG.
	//
	// execution_history.tenant_id holds the EXECUTING CALLER'S CREDENTIAL id
	// (the Basic-auth username the agent derives the scope from), while a
	// portal session's X-Tenant-ID is portal_default_tenant_id's arbitrary
	// display default for the org. ANDing the two matched zero rows on any
	// deployment whose app credentials are not named after the org, so the
	// dashboard "Workflows Run" tile and the whole Executions page rendered a
	// confident 0 over an org with live workflows.
	//
	// The org predicate is the entire tenancy boundary here, and OrgWide is
	// what makes it mandatory: the repository validates the org key and
	// refuses the read without a usable one.
	//
	// This is the same resolution #3377 reached on the sibling approvals
	// queue: the org scope was the security win and the tenant narrowing was
	// the defect, because it HID an org's own rows one scope level down.
	//
	// Narrow, on purpose: the branch requires a trusted org-tenancy assertion
	// AND a bound org, so agent-proxied SDK callers keep reading exactly their
	// own credential's executions. Widening THAT path is a separate decision
	// about who may see a sibling credential's step names, models and costs,
	// and is not smuggled in here.
	//
	// OrgWide is set rather than the tenant merely cleared, because "org set,
	// tenant empty" is a shape any caller can produce by OMITTING a header,
	// and the repository must not serve a BYPASSRLS read off a shape (R3
	// round 1). A caller with no tenant header and no assertion keeps the old
	// behaviour exactly: an RLS-scoped org-only read.
	//
	// The org is tested TRIMMED (R3 round 2): the repository judges the key
	// with tenantscope, which trims, so gating on a raw `!= ""` here would let
	// a whitespace-only X-Org-ID set OrgWide and then be refused downstream as
	// a 500, where the by-id path answers the same input with a 401.
	if strings.TrimSpace(req.OrgID) != "" && callerHasOrgTenancyScope(r) {
		req.TenantID = ""
		req.OrgWide = true
	}

	// R3 MAJOR-1: a request carrying NEITHER key is a caller bug or a
	// degenerate session, never a deliberate cross-tenant listing. It used to
	// fall through to an unscoped `WHERE 1=1` read of every org's executions.
	// Refuse with the same status authorizeExecution gives the same input, so
	// the two halves of this handler answer a missing identity identically.
	if strings.TrimSpace(req.TenantID) == "" && strings.TrimSpace(req.OrgID) == "" {
		h.writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "Tenant or org identity required")
		return
	}

	// R3 MINOR-3: normalize the org key ONCE, here, so the guard above and the
	// repository predicate judge the same string. The repository refuses an
	// unnormalized key (deliberately: the writer stamps raw, and two call sites
	// normalizing one value differently WILL diverge), which previously made a
	// padded X-Org-ID a 500 on this path while the by-id path answered 200.
	req.OrgID = strings.TrimSpace(req.OrgID)
	req.TenantID = strings.TrimSpace(req.TenantID)

	// Use the base tracker for listing
	tracker := execution.NewBaseExecutionTracker(h.repo)
	resp, err := tracker.ListExecutions(r.Context(), req)
	if err != nil {
		h.logger.Printf("[UnifiedExecution] ListExecutions error: %v", err)
		h.writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to list executions")
		return
	}

	h.writeJSON(w, http.StatusOK, resp)
}

// resolveExecution resolves an execution by trying multiple strategies:
// 1. Direct execution ID lookup in the unified execution_history table
// 2. Workflow ID lookup for WCP workflows (checks metadata)
// 3. Plan ID lookup for MAP plans (checks metadata)
// 4. Fallback metadata search across both WCP and MAP
func (h *UnifiedExecutionHandler) resolveExecution(ctx context.Context, executionID string) (*execution.ExecutionStatus, error) {
	// Track the first non-not-found error so we can propagate backend failures
	// instead of masking them as 404.
	var firstErr error

	captureErr := func(err error) {
		if err != nil && !errors.Is(err, execution.ErrExecutionNotFound) && firstErr == nil {
			firstErr = err
		}
	}

	// Strategy 1: Direct lookup by execution ID
	exec, err := h.repo.Get(ctx, executionID)
	if err == nil {
		exec.ProgressPercent = exec.CalculateProgress()
		exec.Duration = exec.CalculateDuration()
		if exec.ActualCostUSD == nil {
			cost := exec.TotalCost()
			if cost > 0 {
				exec.ActualCostUSD = &cost
			}
		}
		// #3442: a WCP row's cached step snapshot is written at /gate time
		// (approval_status=pending); reconcile it against the live
		// workflow_steps before returning. This used to happen only in
		// GetWorkflowStatus, i.e. only for a caller who passed the WORKFLOW
		// id - never for the portal Executions page, which passes the
		// EXECUTION id and is answered right here. Now that a WCP execution
		// row IS addressed by its workflow id, every caller lands on this
		// strategy, so the merge has to live here or it would have been
		// retired by the convergence.
		if exec.ExecutionType == execution.ExecutionTypeWCP && h.wcpTracker != nil {
			if workflowID, _ := exec.Metadata["workflow_id"].(string); workflowID != "" {
				h.wcpTracker.ReconcileStepApprovals(ctx, workflowID, exec)
			}
		}
		return exec, nil
	}
	captureErr(err)

	// Strategy 2: Check if it's a WCP workflow ID
	if h.wcpTracker != nil && (strings.HasPrefix(executionID, "wf_") || strings.HasPrefix(executionID, "wcp_")) {
		exec, err = h.wcpTracker.GetWorkflowStatus(ctx, executionID)
		if err == nil {
			return exec, nil
		}
		captureErr(err)
	}

	// Strategy 3: Check if it's a MAP plan ID
	if h.mapTracker != nil && strings.HasPrefix(executionID, "plan_") {
		exec, err = h.mapTracker.GetPlanStatus(ctx, executionID)
		if err == nil {
			return exec, nil
		}
		captureErr(err)
	}

	// Strategy 4: Search by workflow_id or plan_id in metadata
	if h.wcpTracker != nil {
		exec, err = h.wcpTracker.GetWorkflowStatus(ctx, executionID)
		if err == nil {
			return exec, nil
		}
		captureErr(err)
	}
	if h.mapTracker != nil {
		exec, err = h.mapTracker.GetPlanStatus(ctx, executionID)
		if err == nil {
			return exec, nil
		}
		captureErr(err)
	}

	// If any strategy returned a non-not-found error (e.g. DB connection failure),
	// propagate it so callers can return 500 instead of 404.
	if firstErr != nil {
		return nil, firstErr
	}
	return nil, execution.ErrExecutionNotFound
}

// GetExecutionStatus handles GET /api/v1/unified/executions/{id}
func (h *UnifiedExecutionHandler) GetExecutionStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		h.handleCORS(w, r)
		return
	}

	executionID := mux.Vars(r)["id"]
	if executionID == "" {
		h.writeError(w, http.StatusBadRequest, "BAD_REQUEST", "Execution ID is required")
		return
	}

	exec, err := h.resolveExecution(r.Context(), executionID)
	if err != nil {
		if errors.Is(err, execution.ErrExecutionNotFound) {
			h.writeError(w, http.StatusNotFound, "NOT_FOUND", "Execution not found: "+executionID)
			return
		}
		h.logger.Printf("[UnifiedExecution] GetExecutionStatus error for %s: %v", logutil.Sanitize(executionID), err)
		h.writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to resolve execution")
		return
	}

	if !h.checkTenantOwnership(w, r, exec) {
		return
	}

	h.writeJSON(w, http.StatusOK, exec)
}

// CancelExecution handles POST /api/v1/unified/executions/{id}/cancel
// Propagates cancellation to the appropriate subsystem (WCP or MAP).
func (h *UnifiedExecutionHandler) CancelExecution(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		h.handleCORS(w, r)
		return
	}

	executionID := mux.Vars(r)["id"]
	if executionID == "" {
		h.writeError(w, http.StatusBadRequest, "BAD_REQUEST", "Execution ID is required")
		return
	}

	// Parse optional reason from body
	var req execution.CancelExecutionRequest
	if r.Body != nil {
		_ = json.NewDecoder(r.Body).Decode(&req) // Ignore decode errors — reason is optional
	}
	if req.Reason == "" {
		req.Reason = "cancelled via unified API"
	}

	ctx := r.Context()

	// Resolve execution using multi-strategy lookup
	exec, err := h.resolveExecution(ctx, executionID)
	if err != nil {
		if errors.Is(err, execution.ErrExecutionNotFound) {
			h.writeError(w, http.StatusNotFound, "NOT_FOUND", "Execution not found: "+executionID)
			return
		}
		h.logger.Printf("[UnifiedExecution] CancelExecution lookup error for %s: %v", logutil.Sanitize(executionID), err)
		h.writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to resolve execution")
		return
	}

	// Verify tenant ownership. STRICT: cancel is a write, so it keeps the
	// pre-#3367 credential compare (see checkTenantOwnershipStrict).
	if !h.checkTenantOwnershipStrict(w, r, exec) {
		return
	}

	// Check if already terminal
	if exec.IsTerminal() {
		h.writeError(w, http.StatusConflict, "CONFLICT",
			fmt.Sprintf("Execution is already in terminal state: %s", exec.Status))
		return
	}

	// Propagate to subsystem based on execution type
	switch exec.ExecutionType {
	case execution.ExecutionTypeWCP:
		// WCP: abort the workflow
		workflowID, _ := exec.Metadata["workflow_id"].(string)
		if workflowID == "" {
			h.writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Missing workflow_id in execution metadata")
			return
		}
		if h.wcpTracker == nil || h.wcpTracker.wcpService == nil {
			h.writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "WCP service not available")
			return
		}
		if err := h.wcpTracker.wcpService.AbortWorkflow(ctx, workflowID, req.Reason, r.Header.Get("X-Tenant-ID"), r.Header.Get("X-Org-ID")); err != nil {
			h.logger.Printf("[UnifiedExecution] WCP AbortWorkflow error for %s: %v", logutil.Sanitize(workflowID), err)
			h.writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to cancel WCP workflow")
			return
		}

	case execution.ExecutionTypeMAP:
		// MAP: cancel the plan
		planID, _ := exec.Metadata["plan_id"].(string)
		if planID == "" {
			h.writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Missing plan_id in execution metadata")
			return
		}
		if h.planService == nil {
			h.writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Plan service not available")
			return
		}
		orgID, _ := exec.Metadata["org_id"].(string)
		if err := h.planService.CancelPlan(ctx, planID, orgID, req.Reason); err != nil {
			h.logger.Printf("[UnifiedExecution] MAP CancelPlan error for %s: %v", logutil.Sanitize(planID), err)
			h.writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to cancel MAP plan")
			return
		}
		// Sync status to execution_history
		if h.mapTracker != nil {
			if syncErr := h.mapTracker.SyncPlanStatus(ctx, planID, planning.PlanStatusCancelled, req.Reason); syncErr != nil {
				h.logger.Printf("[WARN] SyncPlanStatus failed for %s: %v", logutil.Sanitize(executionID), syncErr)
			}
		}

	default:
		h.writeError(w, http.StatusBadRequest, "BAD_REQUEST",
			fmt.Sprintf("Unknown execution type: %s", exec.ExecutionType))
		return
	}

	// Return updated status
	updated, err := h.resolveExecution(ctx, exec.ExecutionID)
	if err != nil {
		// Cancel succeeded but couldn't fetch updated status — return a generic success
		h.writeJSON(w, http.StatusOK, map[string]interface{}{
			"execution_id": exec.ExecutionID,
			"status":       "cancelled",
			"message":      "Execution cancelled successfully",
		})
		return
	}
	h.writeJSON(w, http.StatusOK, updated)
}

// StreamExecutionStatus handles GET /api/v1/unified/executions/{id}/stream
// Streams execution state changes via Server-Sent Events (SSE).
func (h *UnifiedExecutionHandler) StreamExecutionStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		h.handleCORS(w, r)
		return
	}

	executionID := mux.Vars(r)["id"]
	if executionID == "" {
		h.writeError(w, http.StatusBadRequest, "BAD_REQUEST", "Execution ID is required")
		return
	}

	// Resolve execution using multi-strategy lookup
	exec, err := h.resolveExecution(r.Context(), executionID)
	if err != nil {
		if errors.Is(err, execution.ErrExecutionNotFound) {
			h.writeError(w, http.StatusNotFound, "NOT_FOUND", "Execution not found: "+executionID)
			return
		}
		h.logger.Printf("[UnifiedExecution] StreamExecutionStatus error for %s: %v", logutil.Sanitize(executionID), err)
		h.writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to resolve execution")
		return
	}

	// Use the resolved execution ID for SSE subscription
	resolvedID := exec.ExecutionID

	// Verify tenant ownership
	if !h.checkTenantOwnership(w, r, exec) {
		return
	}

	// Check SSE support
	flusher, ok := w.(http.Flusher)
	if !ok {
		h.writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Streaming not supported")
		return
	}

	if h.eventHub == nil {
		h.writeError(w, http.StatusServiceUnavailable, "SERVICE_UNAVAILABLE", "Event streaming not available")
		return
	}

	// Enforce per-tenant SSE connection limits
	tenantID := r.Header.Get("X-Tenant-ID")
	if tenantID == "" {
		h.writeError(w, http.StatusBadRequest, "BAD_REQUEST", "X-Tenant-ID header is required for SSE connections")
		return
	}
	if h.connectionTracker != nil {
		if err := h.connectionTracker.TryConnect(tenantID); err != nil {
			upgradeURL := "https://getaxonflow.com/evaluation-license"
			if tierChecker != nil && license.IsEvaluationOrHigher(tierChecker.Tier()) {
				upgradeURL = "https://getaxonflow.com/enterprise"
			}
			h.writeError(w, http.StatusTooManyRequests, "TOO_MANY_REQUESTS",
				fmt.Sprintf("SSE connection limit reached for tenant %s (max %d). Upgrade your license for higher limits: %s", tenantID, h.connectionTracker.MaxConnections(), upgradeURL))
			return
		}
		defer h.connectionTracker.Disconnect(tenantID)
	}

	// Set SSE headers
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.WriteHeader(http.StatusOK)

	// Send initial state
	h.writeSSEEvent(w, "status", exec)
	flusher.Flush()

	// If already terminal, close immediately
	if exec.IsTerminal() {
		return
	}

	// Subscribe to events using the resolved execution ID
	ch := h.eventHub.Subscribe(resolvedID)
	defer h.eventHub.Unsubscribe(resolvedID, ch)

	// Heartbeat ticker to prevent proxy idle timeouts
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// Send SSE comment as keepalive
			if _, err := fmt.Fprintf(w, ":keepalive\n\n"); err != nil {
				return
			}
			flusher.Flush()
		case event, ok := <-ch:
			if !ok {
				return
			}
			h.writeSSEEvent(w, event.EventType, event.Data)
			flusher.Flush()

			// Close on terminal state
			if event.Data != nil && event.Data.IsTerminal() {
				return
			}
		}
	}
}

// --- Helper methods ---

func (h *UnifiedExecutionHandler) handleCORS(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Tenant-ID, X-Org-ID")
	w.WriteHeader(http.StatusNoContent)
}

func (h *UnifiedExecutionHandler) writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Printf("[UnifiedExecution] JSON encode error: %v", err)
	}
}

func (h *UnifiedExecutionHandler) writeError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	resp := map[string]interface{}{
		"error": map[string]string{
			"code":    code,
			"message": message,
		},
	}
	_ = json.NewEncoder(w).Encode(resp) // Error intentionally ignored for error responses
}

func (h *UnifiedExecutionHandler) writeSSEEvent(w http.ResponseWriter, eventType string, data interface{}) {
	jsonData, err := json.Marshal(data)
	if err != nil {
		h.logger.Printf("[UnifiedExecution] SSE marshal error: %v", err)
		return
	}
	if _, err := fmt.Fprintf(w, "id: %d\nevent: %s\ndata: %s\n\n", time.Now().UnixMilli(), eventType, jsonData); err != nil {
		h.logger.Printf("[UnifiedExecution] SSE write error: %v", err)
	}
}
