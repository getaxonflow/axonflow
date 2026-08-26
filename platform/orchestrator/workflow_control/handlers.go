// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package workflow_control

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/gorilla/mux"

	logutil "axonflow/platform/shared/logger"
	"axonflow/platform/shared/tenantscope"
)

// ProxyAuthCheck verifies that a request was routed through the AxonFlow
// Agent gateway (X-Axonflow-Proxy-Auth) rather than reaching the
// orchestrator directly. Returns (true, "") to proceed; (false, msg) where
// msg is the client-facing 403 body. Wired by the orchestrator (#2896 WS1b)
// so the step-gate — whose per-user identity keys the ADR-044 override
// apply, a deny→allow flip — only accepts identity a trusted hop set. A nil
// check = not enforced (tests, embedded use).
type ProxyAuthCheck func(r *http.Request) (bool, string)

// Handler handles HTTP requests for the Workflow Control Plane
type Handler struct {
	service        *Service
	logger         *log.Logger
	proxyAuthCheck ProxyAuthCheck
}

// SetProxyAuthCheck installs the agent proxy-auth verification the workflow
// routes enforce before touching a workflow (see ProxyAuthCheck).
func (h *Handler) SetProxyAuthCheck(check ProxyAuthCheck) {
	h.proxyAuthCheck = check
}

// requireProxyAuth enforces the agent proxy-auth gate, writing the 403 and
// returning false when the request did not arrive through a trusted hop.
//
// #3065 (F1): RegisterRoutes + RegisterEvaluationRoutes + RegisterEnterpriseRoutes
// register 14 routes and only three of them (StepGate, ResumeFromLastCheckpoint,
// ResumeFromCheckpoint) ran this gate. The other id-addressed routes accepted
// the caller's self-asserted X-Tenant-ID / X-Org-ID — and accepted their
// ABSENCE, which the old workflowBelongsTo read as "trusted caller, allow".
// Every route that reads or mutates a workflow by id now runs the same gate
// its three siblings did, so the tenancy headers a handler reads were set by
// an authenticating hop (the Agent's proxyAuthMiddleware or the customer
// portal's orchestrator proxy — both Set them from a validated credential and
// both attach the HMAC proxy token).
//
// A nil check means the gate is not wired (embedded use, unit tests); the
// orchestrator always wires it, and verifyAgentProxyAuth itself fails closed
// when the internal-service secret is unset outside Community mode.
func (h *Handler) requireProxyAuth(w http.ResponseWriter, r *http.Request) bool {
	if h.proxyAuthCheck == nil {
		return true
	}
	if ok, msg := h.proxyAuthCheck(r); !ok {
		h.writeError(w, http.StatusForbidden, "FORBIDDEN", msg)
		return false
	}
	return true
}

// requireScope resolves the caller's authenticated tenancy, writing a 401 and
// returning ok=false when the request carries none.
//
// #3065: the by-id handlers used to read X-Tenant-ID / X-Org-ID individually
// and pass whatever they got — including nothing — down to a check that read
// "nothing" as "trusted". Binding once, up front, means a request with no
// authenticated tenancy is refused before any workflow id is looked up, so the
// refusal cannot double as an existence oracle either. 401 (not 404) is
// correct here: the answer does not depend on the id.
//
// Mirrors UnifiedExecutionHandler.checkTenantOwnership, the posture this
// package is being brought in line with.
func (h *Handler) requireScope(w http.ResponseWriter, r *http.Request) (tenantscope.Scope, bool) {
	scope, err := tenantscope.Bind(r)
	if err != nil {
		h.writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "Missing tenant or org identity")
		return tenantscope.Scope{}, false
	}
	return scope, true
}

// NewHandler creates a new workflow control handler
func NewHandler(service *Service) *Handler {
	return &Handler{
		service: service,
		logger:  log.Default(),
	}
}

// NewHandlerWithLogger creates a new workflow control handler with a custom logger
func NewHandlerWithLogger(service *Service, logger *log.Logger) *Handler {
	if logger == nil {
		logger = log.Default()
	}
	return &Handler{
		service: service,
		logger:  logger,
	}
}

// RegisterRoutes registers core workflow control API routes with a gorilla/mux router.
// Core routes include workflow lifecycle and step gates (available in all editions).
func (h *Handler) RegisterRoutes(r *mux.Router) {
	// Workflow lifecycle
	r.HandleFunc("/api/v1/workflows", h.CreateWorkflow).Methods("POST", "OPTIONS")
	r.HandleFunc("/api/v1/workflows", h.ListWorkflows).Methods("GET", "OPTIONS")
	r.HandleFunc("/api/v1/workflows/{id}", h.GetWorkflow).Methods("GET", "OPTIONS")
	r.HandleFunc("/api/v1/workflows/{id}/complete", h.CompleteWorkflow).Methods("POST", "OPTIONS")
	r.HandleFunc("/api/v1/workflows/{id}/fail", h.FailWorkflow).Methods("POST", "OPTIONS")
	r.HandleFunc("/api/v1/workflows/{id}/abort", h.AbortWorkflow).Methods("POST", "OPTIONS")
	r.HandleFunc("/api/v1/workflows/{id}/resume", h.ResumeWorkflow).Methods("POST", "OPTIONS")

	// Step gates - the core governance endpoint
	r.HandleFunc("/api/v1/workflows/{id}/steps/{step_id}/gate", h.StepGate).Methods("POST", "OPTIONS")
	r.HandleFunc("/api/v1/workflows/{id}/steps/{step_id}/complete", h.MarkStepCompleted).Methods("POST", "OPTIONS")

	// Checkpoints — available to all tiers (read-only for Community)
	r.HandleFunc("/api/v1/workflows/{id}/checkpoints", h.GetCheckpoints).Methods("GET", "OPTIONS")
}

// RegisterEvaluationRoutes registers approval routes available to Evaluation tier and above.
// Same endpoints as Enterprise but accessed via eval license validation at runtime.
func (h *Handler) RegisterEvaluationRoutes(r *mux.Router) {
	r.HandleFunc("/api/v1/workflows/{id}/steps/{step_id}/approve", h.ApproveStep).Methods("POST", "OPTIONS")
	r.HandleFunc("/api/v1/workflows/{id}/steps/{step_id}/reject", h.RejectStep).Methods("POST", "OPTIONS")
	r.HandleFunc("/api/v1/workflows/approvals/pending", h.GetPendingApprovals).Methods("GET", "OPTIONS")

	// Checkpoint resume — Evaluation can resume from last checkpoint only
	r.HandleFunc("/api/v1/workflows/{id}/checkpoints/resume", h.ResumeFromLastCheckpoint).Methods("POST", "OPTIONS")
}

// RegisterEnterpriseRoutes registers enterprise-only approval routes with a gorilla/mux router.
// Approval endpoints (approve, reject, pending) are only available in enterprise mode.
func (h *Handler) RegisterEnterpriseRoutes(r *mux.Router) {
	r.HandleFunc("/api/v1/workflows/{id}/steps/{step_id}/approve", h.ApproveStep).Methods("POST", "OPTIONS")
	r.HandleFunc("/api/v1/workflows/{id}/steps/{step_id}/reject", h.RejectStep).Methods("POST", "OPTIONS")
	r.HandleFunc("/api/v1/workflows/approvals/pending", h.GetPendingApprovals).Methods("GET", "OPTIONS")

	// Checkpoint resume — Enterprise can resume from any checkpoint
	r.HandleFunc("/api/v1/workflows/{id}/checkpoints/{checkpoint_id}/resume", h.ResumeFromCheckpoint).Methods("POST", "OPTIONS")
}

// CreateWorkflow handles POST /api/v1/workflows
func (h *Handler) CreateWorkflow(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		h.handleCORS(w, r)
		return
	}

	// #3065 (F1): same proxy-auth gate as StepGate — see requireProxyAuth.
	if !h.requireProxyAuth(w, r) {
		return
	}
	scope, ok := h.requireScope(w, r)
	if !ok {
		return
	}

	var req CreateWorkflowRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, "BAD_REQUEST", "Invalid request body")
		return
	}

	if req.WorkflowName == "" {
		h.writeError(w, http.StatusBadRequest, "BAD_REQUEST", "workflow_name is required")
		return
	}

	// Tenant/org come from the bound scope (#3065); user/client identity is
	// attribution only and keeps its existing resolution.
	tenantID := scope.TenantID
	orgID := scope.OrgID
	userID := h.getUserID(r)
	clientID := h.getClientID(r)

	workflow, err := h.service.CreateWorkflow(r.Context(), &req, tenantID, orgID, userID, clientID)
	if err != nil {
		// #3065: the service refuses to persist a workflow with no tenancy
		// key. requireScope above already guarantees a bound scope, so this
		// is a belt-and-braces mapping for embedded/nil-check callers.
		if errors.Is(err, tenantscope.ErrNoCallerScope) {
			h.writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "Missing tenant or org identity")
			return
		}
		if strings.Contains(err.Error(), "trace_id exceeds") {
			h.writeJSON(w, http.StatusBadRequest, map[string]interface{}{
				"error":   "validation_error",
				"code":    "INVALID_TRACE_ID",
				"message": err.Error(),
			})
			return
		}
		if strings.Contains(err.Error(), "concurrent execution limit reached") {
			h.writeError(w, http.StatusTooManyRequests, "CONCURRENT_EXECUTION_LIMIT",
				"Maximum concurrent executions reached. Upgrade your license for higher limits: https://getaxonflow.com/evaluation-license")
			return
		}
		h.logger.Printf("[WorkflowControl] CreateWorkflow error: %v", logutil.Sanitize(err.Error()))
		h.writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to create workflow")
		return
	}

	h.writeJSON(w, http.StatusCreated, workflow.ToCreateResponse())
}

// GetWorkflow handles GET /api/v1/workflows/{id}.
// Enforces multi-tenant isolation: only returns workflows belonging to the
// authenticated caller's tenant and org. Returns 404 (not 403) on mismatch
// to avoid leaking workflow existence across tenants.
func (h *Handler) GetWorkflow(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		h.handleCORS(w, r)
		return
	}

	// #3065 (F1): same proxy-auth gate as StepGate — see requireProxyAuth.
	if !h.requireProxyAuth(w, r) {
		return
	}
	scope, ok := h.requireScope(w, r)
	if !ok {
		return
	}

	workflowID := mux.Vars(r)["id"]
	if workflowID == "" {
		h.writeError(w, http.StatusBadRequest, "BAD_REQUEST", "Workflow ID is required")
		return
	}

	tenantID := scope.TenantID
	orgID := scope.OrgID

	workflow, err := h.service.GetWorkflow(r.Context(), workflowID, tenantID, orgID)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			h.writeError(w, http.StatusNotFound, "NOT_FOUND", "Workflow not found")
			return
		}
		h.logger.Printf("[WorkflowControl] GetWorkflow error for %s: %v", workflowID, err)
		h.writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to get workflow")
		return
	}

	h.writeJSON(w, http.StatusOK, workflow.ToStatusResponse())
}

// ListWorkflows handles GET /api/v1/workflows
func (h *Handler) ListWorkflows(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		h.handleCORS(w, r)
		return
	}

	// #3065 (F1): same proxy-auth gate as StepGate — see requireProxyAuth.
	if !h.requireProxyAuth(w, r) {
		return
	}
	scope, ok := h.requireScope(w, r)
	if !ok {
		return
	}

	opts := ListWorkflowsOptions{
		Limit:  20,
		Offset: 0,
	}

	// Parse query parameters
	if limit := r.URL.Query().Get("limit"); limit != "" {
		if l, err := strconv.Atoi(limit); err == nil && l > 0 {
			opts.Limit = l
		}
	}
	if offset := r.URL.Query().Get("offset"); offset != "" {
		if o, err := strconv.Atoi(offset); err == nil && o >= 0 {
			opts.Offset = o
		}
	}
	if status := r.URL.Query().Get("status"); status != "" {
		s := WorkflowStatus(status)
		opts.Status = &s
	}
	if source := r.URL.Query().Get("source"); source != "" {
		s := WorkflowSource(source)
		opts.Source = &s
	}
	if traceID := r.URL.Query().Get("trace_id"); traceID != "" {
		opts.TraceID = traceID
	}

	// #3065 (F1, R3 round 1): the listing routes were NOT on the issue's list
	// of nine ungated routes, so the first pass gated the by-id routes and left
	// these two reading self-asserted headers — the very "census of the doors a
	// review named" that epic #3071 exists to end. A direct caller sending
	// `X-Org-ID: victim-org` got the victim's whole workflow list.
	opts.TenantID = scope.TenantID
	opts.OrgID = scope.OrgID

	response, err := h.service.ListWorkflows(r.Context(), opts)
	if err != nil {
		// #3065: an unbound scope is a 401, never a 500 — the service refuses
		// rather than widening, and the response code must say so.
		if errors.Is(err, tenantscope.ErrNoCallerScope) {
			h.writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "Missing tenant or org identity")
			return
		}
		h.logger.Printf("[WorkflowControl] ListWorkflows error: %v", err)
		h.writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to list workflows")
		return
	}

	h.writeJSON(w, http.StatusOK, response)
}

// StepGate handles POST /api/v1/workflows/{id}/steps/{step_id}/gate
// This is the core governance endpoint - called before each step in an external workflow
func (h *Handler) StepGate(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		h.handleCORS(w, r)
		return
	}

	// #2896 WS1b: the step-gate identity (X-User-ID / X-User-Email via
	// getUserID below) keys the ADR-044 override apply inside
	// EvaluateStepGate — a deny→allow flip. Only agent-routed requests
	// (trust-gated identity + HMAC proxy token) may drive it; a direct
	// caller with a forged identity is rejected before any evaluation.
	if !h.requireProxyAuth(w, r) {
		return
	}
	scope, ok := h.requireScope(w, r)
	if !ok {
		return
	}

	vars := mux.Vars(r)
	workflowID := vars["id"]
	stepID := vars["step_id"]

	if workflowID == "" {
		h.writeError(w, http.StatusBadRequest, "BAD_REQUEST", "Workflow ID is required")
		return
	}
	if stepID == "" {
		h.writeError(w, http.StatusBadRequest, "BAD_REQUEST", "Step ID is required")
		return
	}

	var req StepGateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, "BAD_REQUEST", "Invalid request body")
		return
	}

	if req.StepType == "" {
		h.writeError(w, http.StatusBadRequest, "BAD_REQUEST", "step_type is required")
		return
	}

	if req.ToolContext != nil && req.ToolContext.ToolName == "" {
		h.writeJSON(w, http.StatusBadRequest, map[string]interface{}{
			"error":   "validation_error",
			"code":    "INVALID_TOOL_CONTEXT",
			"message": "tool_name is required when tool_context is provided",
		})
		return
	}

	if !ValidRetryPolicy(req.RetryPolicy) {
		h.writeError(w, http.StatusBadRequest, "BAD_REQUEST",
			"retry_policy must be \"idempotent\" or \"reevaluate\"")
		return
	}

	// Issue #1673 Phase 2: idempotency_key max-length validation (matches DB
	// column length). Reject oversized keys early with a clear 400 so callers
	// don't get a less-helpful DB error downstream.
	// Rune count, not byte count — Postgres VARCHAR(N) is N characters, not
	// N bytes, and a 255-char UTF-8 string can exceed 255 bytes with
	// multi-byte characters. Matches the convention used by CreateWorkflow's
	// trace_id validation.
	if utf8.RuneCountInString(req.IdempotencyKey) > 255 {
		h.writeError(w, http.StatusBadRequest, "BAD_REQUEST",
			"idempotency_key must be at most 255 characters")
		return
	}

	// Issue #1673 Phase 1: include_prior_output is an opt-in query param.
	// Parse into the request struct so the service layer can pass it through
	// to buildRetryContext.
	if r.URL.Query().Get("include_prior_output") == "true" {
		req.IncludePriorOutput = true
	}

	// Tenant/org come from the bound scope (#3065); user/client identity is
	// attribution only and keeps its existing resolution.
	tenantID := scope.TenantID
	orgID := scope.OrgID
	userID := h.getUserID(r)
	clientID := h.getClientID(r)

	// #3281 (ADR-060 #2989 P3b): read X-User-Email directly rather than via
	// getUserID, whose fallback chain can return a non-email X-User-ID -
	// resolveUserSegments must never resolve from an unverified/
	// non-email identifier (see StepGateRequest.Email's doc). This header is
	// trust-gated the same way applyAuthoritativePrincipal's X-User-Email
	// read is on the /api/v1/process plane (run.go): requireProxyAuth above
	// has already confirmed this request carries a valid HMAC proxy token
	// from the agent's governed forward, so the header cannot be a direct
	// caller's self-asserted value.
	req.Email = r.Header.Get("X-User-Email")

	response, err := h.service.StepGate(r.Context(), workflowID, stepID, &req, tenantID, orgID, userID, clientID)
	if err != nil {
		// Issue #1673 Phase 2: 409 IDEMPOTENCY_KEY_MISMATCH
		var mismatchErr *IdempotencyKeyMismatchError
		if errors.As(err, &mismatchErr) {
			h.writeIdempotencyKeyMismatch(w, mismatchErr)
			return
		}
		if strings.Contains(err.Error(), "not found") {
			h.writeError(w, http.StatusNotFound, "NOT_FOUND", "Workflow not found")
			return
		}
		if strings.Contains(err.Error(), "terminal state") {
			h.writeError(w, http.StatusConflict, "WORKFLOW_TERMINAL", err.Error())
			return
		}
		if strings.Contains(err.Error(), "pending approval") {
			h.writeError(w, http.StatusConflict, "APPROVAL_PENDING", err.Error())
			return
		}
		h.logger.Printf("[WorkflowControl] StepGate error for %s/%s: %v", workflowID, stepID, err)
		h.writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to evaluate step gate")
		return
	}

	h.writeJSON(w, http.StatusOK, response)
}

// MarkStepCompleted handles POST /api/v1/workflows/{id}/steps/{step_id}/complete
func (h *Handler) MarkStepCompleted(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		h.handleCORS(w, r)
		return
	}

	// #3065 (F1): same proxy-auth gate as StepGate — see requireProxyAuth.
	if !h.requireProxyAuth(w, r) {
		return
	}
	scope, ok := h.requireScope(w, r)
	if !ok {
		return
	}

	vars := mux.Vars(r)
	workflowID := vars["id"]
	stepID := vars["step_id"]

	if workflowID == "" || stepID == "" {
		h.writeError(w, http.StatusBadRequest, "BAD_REQUEST", "Workflow ID and Step ID are required")
		return
	}

	// Parse optional request body with post-execution metrics.
	// Empty body is allowed for backward compatibility (the previous contract).
	// Non-empty body that fails JSON decoding returns 400.
	var req *StepCompleteRequest
	if r.Body != nil && r.ContentLength != 0 {
		var parsed StepCompleteRequest
		if err := json.NewDecoder(r.Body).Decode(&parsed); err != nil {
			h.writeError(w, http.StatusBadRequest, "BAD_REQUEST", "Invalid request body: "+err.Error())
			return
		}
		req = &parsed
	}

	// Issue #1673 Phase 2: idempotency_key max-length validation.
	// Rune count, not byte count — see StepGate for rationale.
	if req != nil && utf8.RuneCountInString(req.IdempotencyKey) > 255 {
		h.writeError(w, http.StatusBadRequest, "BAD_REQUEST",
			"idempotency_key must be at most 255 characters")
		return
	}

	// Inconsistency fix (Issue #1673 drive-by): this handler previously passed
	// getClientID as the service's tenantID parameter, while StepGate passes
	// the client-id getter. That meant a real X-Tenant-ID header worked for gate but
	// broke complete on the isolation check. Align with StepGate — tenantID
	// is the proper parameter.
	if err := h.service.MarkStepCompleted(r.Context(), workflowID, stepID, req, scope.TenantID, scope.OrgID); err != nil {
		// Issue #1673 Phase 2: 409 IDEMPOTENCY_KEY_MISMATCH
		var mismatchErr *IdempotencyKeyMismatchError
		if errors.As(err, &mismatchErr) {
			h.writeIdempotencyKeyMismatch(w, mismatchErr)
			return
		}
		if strings.Contains(err.Error(), "not found") {
			h.writeError(w, http.StatusNotFound, "NOT_FOUND", "Step not found")
			return
		}
		h.logger.Printf("[WorkflowControl] MarkStepCompleted error for %s/%s: %v", workflowID, stepID, err)
		h.writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to mark step completed")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// writeIdempotencyKeyMismatch emits the structured 409 response for
// *IdempotencyKeyMismatchError (Issue #1673 Phase 2). Wire shape matches
// technical-docs/WCP_RETRY_IDEMPOTENCY_WIRE_CONTRACT.md §5.
func (h *Handler) writeIdempotencyKeyMismatch(w http.ResponseWriter, e *IdempotencyKeyMismatchError) {
	resp := APIErrorResponse{
		Error: APIError{
			Code:    ErrorCodeIdempotencyKeyMismatch,
			Message: "idempotency_key does not match the key recorded on gate",
			Details: APIErrorDetails{
				WorkflowID:             e.WorkflowID,
				StepID:                 e.StepID,
				ExpectedIdempotencyKey: e.ExpectedKey,
				ReceivedIdempotencyKey: e.ReceivedKey,
			},
		},
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusConflict)
	_ = json.NewEncoder(w).Encode(resp)
}

// CompleteWorkflow handles POST /api/v1/workflows/{id}/complete.
// Enforces multi-tenant isolation: only completes workflows belonging to the
// authenticated caller's tenant and org.
func (h *Handler) CompleteWorkflow(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		h.handleCORS(w, r)
		return
	}

	// #3065 (F1): same proxy-auth gate as StepGate — see requireProxyAuth.
	if !h.requireProxyAuth(w, r) {
		return
	}
	scope, ok := h.requireScope(w, r)
	if !ok {
		return
	}

	workflowID := mux.Vars(r)["id"]
	if workflowID == "" {
		h.writeError(w, http.StatusBadRequest, "BAD_REQUEST", "Workflow ID is required")
		return
	}

	tenantID := scope.TenantID
	orgID := scope.OrgID

	if err := h.service.CompleteWorkflow(r.Context(), workflowID, tenantID, orgID); err != nil {
		if strings.Contains(err.Error(), "not found") {
			h.writeError(w, http.StatusNotFound, "NOT_FOUND", "Workflow not found")
			return
		}
		if strings.Contains(err.Error(), "terminal state") {
			h.writeError(w, http.StatusConflict, "WORKFLOW_TERMINAL", err.Error())
			return
		}
		if strings.Contains(err.Error(), "pending approval") {
			h.writeError(w, http.StatusConflict, "APPROVAL_PENDING", err.Error())
			return
		}
		h.logger.Printf("[WorkflowControl] CompleteWorkflow error for %s: %v", workflowID, err)
		h.writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to complete workflow")
		return
	}

	h.writeJSON(w, http.StatusOK, map[string]interface{}{
		"workflow_id": workflowID,
		"status":      WorkflowStatusCompleted,
		"message":     "Workflow completed successfully",
	})
}

// FailWorkflow handles POST /api/v1/workflows/{id}/fail
func (h *Handler) FailWorkflow(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		h.handleCORS(w, r)
		return
	}

	// #3065 (F1): same proxy-auth gate as StepGate — see requireProxyAuth.
	if !h.requireProxyAuth(w, r) {
		return
	}
	scope, ok := h.requireScope(w, r)
	if !ok {
		return
	}

	workflowID := mux.Vars(r)["id"]
	if workflowID == "" {
		h.writeError(w, http.StatusBadRequest, "BAD_REQUEST", "Workflow ID is required")
		return
	}

	var req FailWorkflowRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		req.Reason = "Failed"
	}
	if req.Reason == "" {
		req.Reason = "Failed"
	}

	if err := h.service.FailWorkflow(r.Context(), workflowID, req.Reason, scope.TenantID, scope.OrgID); err != nil {
		if strings.Contains(err.Error(), "not found") {
			h.writeError(w, http.StatusNotFound, "NOT_FOUND", "Workflow not found")
			return
		}
		if strings.Contains(err.Error(), "terminal state") {
			h.writeError(w, http.StatusConflict, "WORKFLOW_TERMINAL", err.Error())
			return
		}
		h.logger.Printf("[WorkflowControl] FailWorkflow error for %s: %v", logutil.Sanitize(workflowID), logutil.Sanitize(err.Error()))
		h.writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to fail workflow")
		return
	}

	h.writeJSON(w, http.StatusOK, map[string]interface{}{
		"workflow_id": workflowID,
		"status":      WorkflowStatusFailed,
		"message":     "Workflow marked as failed",
		"reason":      req.Reason,
	})
}

// AbortWorkflow handles POST /api/v1/workflows/{id}/abort.
// Enforces multi-tenant isolation: only aborts workflows belonging to the
// authenticated caller's tenant and org.
func (h *Handler) AbortWorkflow(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		h.handleCORS(w, r)
		return
	}

	// #3065 (F1): same proxy-auth gate as StepGate — see requireProxyAuth.
	if !h.requireProxyAuth(w, r) {
		return
	}
	scope, ok := h.requireScope(w, r)
	if !ok {
		return
	}

	workflowID := mux.Vars(r)["id"]
	if workflowID == "" {
		h.writeError(w, http.StatusBadRequest, "BAD_REQUEST", "Workflow ID is required")
		return
	}

	var req AbortWorkflowRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		// Allow empty body
		req.Reason = "Aborted by user"
	}
	if req.Reason == "" {
		req.Reason = "Aborted by user"
	}

	tenantID := scope.TenantID
	orgID := scope.OrgID

	if err := h.service.AbortWorkflow(r.Context(), workflowID, req.Reason, tenantID, orgID); err != nil {
		if strings.Contains(err.Error(), "not found") {
			h.writeError(w, http.StatusNotFound, "NOT_FOUND", "Workflow not found")
			return
		}
		if strings.Contains(err.Error(), "terminal state") {
			h.writeError(w, http.StatusConflict, "WORKFLOW_TERMINAL", err.Error())
			return
		}
		h.logger.Printf("[WorkflowControl] AbortWorkflow error for %s: %v", workflowID, err)
		h.writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to abort workflow")
		return
	}

	h.writeJSON(w, http.StatusOK, map[string]interface{}{
		"workflow_id": workflowID,
		"status":      WorkflowStatusAborted,
		"message":     "Workflow aborted",
		"reason":      req.Reason,
	})
}

// ResumeWorkflow handles POST /api/v1/workflows/{id}/resume
func (h *Handler) ResumeWorkflow(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		h.handleCORS(w, r)
		return
	}

	// #3065 (F1): same proxy-auth gate as StepGate — see requireProxyAuth.
	if !h.requireProxyAuth(w, r) {
		return
	}
	scope, ok := h.requireScope(w, r)
	if !ok {
		return
	}

	workflowID := mux.Vars(r)["id"]
	if workflowID == "" {
		h.writeError(w, http.StatusBadRequest, "BAD_REQUEST", "Workflow ID is required")
		return
	}

	if err := h.service.ResumeWorkflow(r.Context(), workflowID, scope.TenantID, scope.OrgID); err != nil {
		if strings.Contains(err.Error(), "not found") {
			h.writeError(w, http.StatusNotFound, "NOT_FOUND", "Workflow not found")
			return
		}
		if strings.Contains(err.Error(), "terminal state") {
			h.writeError(w, http.StatusConflict, "WORKFLOW_TERMINAL", err.Error())
			return
		}
		if strings.Contains(err.Error(), "pending approval") {
			h.writeError(w, http.StatusConflict, "APPROVAL_PENDING", err.Error())
			return
		}
		if strings.Contains(err.Error(), "rejected") {
			h.writeError(w, http.StatusConflict, "STEP_REJECTED", err.Error())
			return
		}
		h.logger.Printf("[WorkflowControl] ResumeWorkflow error for %s: %v", workflowID, err)
		h.writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to resume workflow")
		return
	}

	h.writeJSON(w, http.StatusOK, map[string]interface{}{
		"workflow_id": workflowID,
		"status":      WorkflowStatusInProgress,
		"message":     "Workflow resumed",
	})
}

// ApproveStep handles POST /api/v1/workflows/{id}/steps/{step_id}/approve (Enterprise)
func (h *Handler) ApproveStep(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		h.handleCORS(w, r)
		return
	}

	// #3065 (F1): same proxy-auth gate as StepGate — see requireProxyAuth.
	if !h.requireProxyAuth(w, r) {
		return
	}
	scope, ok := h.requireScope(w, r)
	if !ok {
		return
	}

	vars := mux.Vars(r)
	workflowID := vars["id"]
	stepID := vars["step_id"]

	if workflowID == "" || stepID == "" {
		h.writeError(w, http.StatusBadRequest, "BAD_REQUEST", "Workflow ID and Step ID are required")
		return
	}

	// Get approver identity
	approvedBy := h.getUserID(r)
	if approvedBy == "" {
		approvedBy = "system"
	}

	// Parse request body for approval comment (required, min 10 characters)
	var comment string
	if r.Body != nil {
		var body struct {
			Comment string `json:"comment"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			h.writeError(w, http.StatusBadRequest, "BAD_REQUEST", "Invalid request body")
			return
		}
		comment = strings.TrimSpace(body.Comment)
	}
	if len(comment) < 10 {
		h.writeError(w, http.StatusBadRequest, "BAD_REQUEST", "Comment is required (minimum 10 characters)")
		return
	}

	if err := h.service.ApproveStep(r.Context(), workflowID, stepID, scope.TenantID, scope.OrgID, approvedBy, comment); err != nil {
		if strings.Contains(err.Error(), "not found") {
			h.writeError(w, http.StatusNotFound, "NOT_FOUND", "Step not found")
			return
		}
		if strings.Contains(err.Error(), "does not require") {
			h.writeError(w, http.StatusConflict, "NO_APPROVAL_NEEDED", err.Error())
			return
		}
		if strings.Contains(err.Error(), "not pending") {
			h.writeError(w, http.StatusConflict, "NOT_PENDING", err.Error())
			return
		}
		h.logger.Printf("[WorkflowControl] ApproveStep error for %s/%s: %v", workflowID, stepID, err)
		h.writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to approve step")
		return
	}

	// Project the rich StepGateHTTPResponse — same helper that MAP calls, so
	// cross-plane parity is structural rather than hand-maintained (Issue #1677).
	step, err := h.service.GetStep(r.Context(), workflowID, stepID, scope.TenantID, scope.OrgID)
	if err != nil {
		// Post-approval fetch failure shouldn't fail the approval; surface the
		// minimal response but log loudly so it's observable.
		h.logger.Printf("[WorkflowControl] ApproveStep post-fetch error for %s/%s: %v", workflowID, stepID, err)
		h.writeJSON(w, http.StatusOK, ProjectStepGateToHTTP(workflowID, "", nil, ApproverMeta{}, "Step approved", false))
		return
	}

	approver := ApproverMeta{ApprovalID: deriveHITLApprovalID(workflowID, stepID)}
	h.writeJSON(w, http.StatusOK, ProjectStepGateToHTTP(workflowID, "", step, approver, "Step approved", false))
}

// RejectStep handles POST /api/v1/workflows/{id}/steps/{step_id}/reject (Enterprise)
func (h *Handler) RejectStep(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		h.handleCORS(w, r)
		return
	}

	// #3065 (F1): same proxy-auth gate as StepGate — see requireProxyAuth.
	if !h.requireProxyAuth(w, r) {
		return
	}
	scope, ok := h.requireScope(w, r)
	if !ok {
		return
	}

	vars := mux.Vars(r)
	workflowID := vars["id"]
	stepID := vars["step_id"]

	if workflowID == "" || stepID == "" {
		h.writeError(w, http.StatusBadRequest, "BAD_REQUEST", "Workflow ID and Step ID are required")
		return
	}

	// Get rejector identity
	rejectedBy := h.getUserID(r)
	if rejectedBy == "" {
		rejectedBy = "system"
	}

	// Parse request body for rejection reason (required, min 10 characters)
	var reason string
	if r.Body != nil {
		var body struct {
			Reason string `json:"reason"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			h.writeError(w, http.StatusBadRequest, "BAD_REQUEST", "Invalid request body")
			return
		}
		reason = strings.TrimSpace(body.Reason)
	}
	if len(reason) < 10 {
		h.writeError(w, http.StatusBadRequest, "BAD_REQUEST", "Reason is required (minimum 10 characters)")
		return
	}

	if err := h.service.RejectStep(r.Context(), workflowID, stepID, scope.TenantID, scope.OrgID, rejectedBy, reason); err != nil {
		if strings.Contains(err.Error(), "not found") {
			h.writeError(w, http.StatusNotFound, "NOT_FOUND", "Step not found")
			return
		}
		if strings.Contains(err.Error(), "does not require") {
			h.writeError(w, http.StatusConflict, "NO_APPROVAL_NEEDED", err.Error())
			return
		}
		if strings.Contains(err.Error(), "not pending") {
			h.writeError(w, http.StatusConflict, "NOT_PENDING", err.Error())
			return
		}
		h.logger.Printf("[WorkflowControl] RejectStep error for %s/%s: %v", workflowID, stepID, err)
		h.writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to reject step")
		return
	}

	// Rich response via the shared projector — same shape as ApproveStep so
	// cross-plane parity stays structural (Issue #1677).
	step, err := h.service.GetStep(r.Context(), workflowID, stepID, scope.TenantID, scope.OrgID)
	if err != nil {
		h.logger.Printf("[WorkflowControl] RejectStep post-fetch error for %s/%s: %v", workflowID, stepID, err)
		h.writeJSON(w, http.StatusOK, ProjectStepGateToHTTP(workflowID, "", nil, ApproverMeta{}, "Step rejected, workflow aborted", false))
		return
	}

	approver := ApproverMeta{ApprovalID: deriveHITLApprovalID(workflowID, stepID)}
	h.writeJSON(w, http.StatusOK, ProjectStepGateToHTTP(workflowID, "", step, approver, "Step rejected, workflow aborted", false))
}

// GetPendingApprovals handles GET /api/v1/workflows/approvals/pending (Enterprise)
func (h *Handler) GetPendingApprovals(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		h.handleCORS(w, r)
		return
	}

	// #3065 (F1): same proxy-auth gate as StepGate — see requireProxyAuth.
	if !h.requireProxyAuth(w, r) {
		return
	}
	scope, ok := h.requireScope(w, r)
	if !ok {
		return
	}

	// #3065 (F1, R3 round 1): bound, not self-asserted — and 401 rather than
	// the old 400, matching every converted sibling.
	tenantID := scope.TenantID

	limit := 20
	if l := r.URL.Query().Get("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 {
			limit = parsed
		}
	}

	steps, err := h.service.GetPendingApprovals(r.Context(), tenantID, limit)
	if err != nil {
		if errors.Is(err, tenantscope.ErrNoCallerScope) {
			h.writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "Missing tenant or org identity")
			return
		}
		h.logger.Printf("[WorkflowControl] GetPendingApprovals error: %v", err)
		h.writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to get pending approvals")
		return
	}

	totalCount, countErr := h.service.CountPendingApprovals(r.Context(), tenantID)
	if countErr != nil {
		h.logger.Printf("[WorkflowControl] CountPendingApprovals error: %v", countErr)
		// Fall back to len(steps) if count query fails
		totalCount = len(steps)
	}

	// Emit an empty list instead of nil so JSON stays `[]` not `null` —
	// reviewer UIs rely on the array shape. Matches the MAP plane-scoped
	// listing's behavior (Issue #1680).
	if steps == nil {
		steps = []PendingApprovalResponse{}
	}

	h.writeJSON(w, http.StatusOK, map[string]interface{}{
		"pending_approvals": steps,
		"count":             totalCount,
	})
}

// Helper types

// ErrorResponse represents an API error
type ErrorResponse struct {
	Error   string `json:"error"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

// Helper methods

// #3065: getTenantID and getOrgID are GONE. Every handler in this package
// resolves tenancy through requireScope (tenantscope.Bind), so there is no
// longer a way to read a tenancy value out of a raw header here — which is
// the structural half of the fix. The linter flagged them as unused the
// moment the last caller was converted; that is the invariant reporting
// itself, so they are deleted rather than silenced.
//
// getUserID and getClientID remain: they carry ATTRIBUTION (who acted, which
// credential), never authorization, and the trust-gate contract in
// platform/shared/identity governs them.

// getUserID extracts user ID from request.
//
// Plugin Batch 1 convention (ADR-043/044): plugins carry per-user identity
// via X-User-Email. Treat that as the canonical user ID when no numeric
// X-User-ID is supplied — so the workflows row captures the email and
// cache invalidation on override create (which scopes by workflows.user_id)
// matches correctly.
func (h *Handler) getUserID(r *http.Request) string {
	if userID := r.Header.Get("X-User-ID"); userID != "" {
		return userID
	}
	if email := r.Header.Get("X-User-Email"); email != "" {
		return email
	}
	if userID, ok := r.Context().Value("user_id").(string); ok {
		return userID
	}
	return ""
}

// getClientID extracts client ID from request
func (h *Handler) getClientID(r *http.Request) string {
	if clientID := r.Header.Get("X-Tenant-ID"); clientID != "" {
		return clientID
	}
	if clientID, ok := r.Context().Value("client_id").(string); ok {
		return clientID
	}
	return ""
}

// allowedOrigins for CORS
var allowedOrigins = map[string]bool{
	"https://app.getaxonflow.com":      true,
	"https://staging.getaxonflow.com":  true,
	"https://demo.getaxonflow.com":     true,
	"https://customer.getaxonflow.com": true,
	"http://localhost:3000":            true,
	"http://localhost:8080":            true,
	"http://localhost:8081":            true,
}

// handleCORS sets CORS headers for OPTIONS requests
func (h *Handler) handleCORS(w http.ResponseWriter, r *http.Request) {
	origin := r.Header.Get("Origin")
	if origin != "" && allowedOrigins[origin] {
		w.Header().Set("Access-Control-Allow-Origin", origin)
	}
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Tenant-ID, X-Org-ID, X-User-ID")
	w.Header().Set("Access-Control-Max-Age", "86400")
	w.WriteHeader(http.StatusOK)
}

// writeJSON writes a JSON response
func (h *Handler) writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	// Set permissive CORS for non-preflight requests
	// Preflight (OPTIONS) is handled by handleCORS with origin checking
	if w.Header().Get("Access-Control-Allow-Origin") == "" {
		w.Header().Set("Access-Control-Allow-Origin", "*")
	}
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

// writeError writes an error response
func (h *Handler) writeError(w http.ResponseWriter, status int, code, message string) {
	h.writeJSON(w, status, ErrorResponse{
		Error:   strings.ToLower(code),
		Code:    code,
		Message: message,
	})
}

// --- Checkpoint handlers ---

// GetCheckpoints handles GET /api/v1/workflows/{id}/checkpoints
// Available to all tiers — Community can list checkpoints (read-only visibility).
func (h *Handler) GetCheckpoints(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		h.handleCORS(w, r)
		return
	}

	// #3065 (F1): same proxy-auth gate as StepGate — see requireProxyAuth.
	if !h.requireProxyAuth(w, r) {
		return
	}
	scope, ok := h.requireScope(w, r)
	if !ok {
		return
	}

	vars := mux.Vars(r)
	workflowID := vars["id"]
	if workflowID == "" {
		h.writeError(w, http.StatusBadRequest, "BAD_REQUEST", "Workflow ID is required")
		return
	}

	tenantID := scope.TenantID
	orgID := scope.OrgID

	resp, err := h.service.GetCheckpoints(r.Context(), workflowID, tenantID, orgID)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			h.writeError(w, http.StatusNotFound, "NOT_FOUND", "Workflow not found")
			return
		}
		h.logger.Printf("[WorkflowControl] GetCheckpoints error for %s: %v", workflowID, err)
		h.writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to list checkpoints")
		return
	}

	h.writeJSON(w, http.StatusOK, resp)
}

// ResumeFromLastCheckpoint handles POST /api/v1/workflows/{id}/checkpoints/resume
// Evaluation+ — resume from the last resumable checkpoint with fresh policy evaluation.
func (h *Handler) ResumeFromLastCheckpoint(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		h.handleCORS(w, r)
		return
	}

	// #2896 WS1c: resuming a checkpoint re-evaluates its step and applies any
	// ADR-044 override, a deny-to-allow flip. #3281 REKEYED that override on
	// the LIVE resumer's trust-gated X-User-Email (wcp_policy_adapter.go's
	// overrideEmail, falling back to the step's UserID only when no email is
	// present), NOT on the checkpoint's stored actor identity: the flip must
	// be authorised by whoever is performing the resume, or user A's override
	// would authorise user B's resume. Only agent-routed requests
	// (trust-gated identity + HMAC proxy token) may drive it; a direct caller
	// is rejected before any re-evaluation. Mirrors the StepGate guard.
	if !h.requireProxyAuth(w, r) {
		return
	}
	scope, ok := h.requireScope(w, r)
	if !ok {
		return
	}

	vars := mux.Vars(r)
	workflowID := vars["id"]
	if workflowID == "" {
		h.writeError(w, http.StatusBadRequest, "BAD_REQUEST", "Workflow ID is required")
		return
	}

	tenantID := scope.TenantID
	orgID := scope.OrgID

	// #3281: a resume re-enters the SAME Service.StepGate evaluation the gate
	// route runs (retry_policy=reevaluate, so the cache is deliberately
	// bypassed). Read the trust-gated X-User-Email off THIS request exactly as
	// the StepGate handler does -- this route is behind the identical
	// requireProxyAuth gate above and receives the header through the same
	// /api/v1/workflows proxy prefix, so the value cannot be a direct caller's
	// self-asserted one. Without it the fresh verdict is computed with no
	// verified identity and every segment-scoped policy stops applying.
	resp, err := h.service.ResumeFromLastCheckpoint(r.Context(), workflowID, tenantID, orgID, r.Header.Get("X-User-Email"))
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			h.writeError(w, http.StatusNotFound, "NOT_FOUND", err.Error())
			return
		}
		if strings.Contains(err.Error(), "no resumable checkpoint") || strings.Contains(err.Error(), "cannot resume") {
			h.writeError(w, http.StatusConflict, "NOT_RESUMABLE", err.Error())
			return
		}
		h.logger.Printf("[WorkflowControl] ResumeFromLastCheckpoint error for %s: %v", workflowID, err)
		h.writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to resume from checkpoint")
		return
	}

	h.writeJSON(w, http.StatusOK, resp)
}

// ResumeFromCheckpoint handles POST /api/v1/workflows/{id}/checkpoints/{checkpoint_id}/resume
// Enterprise only — resume from a specific checkpoint with fresh policy evaluation.
func (h *Handler) ResumeFromCheckpoint(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		h.handleCORS(w, r)
		return
	}

	// #2896 WS1c: resuming a specific checkpoint re-evaluates its step and
	// applies any ADR-044 override, a deny-to-allow flip. Since #3281 that
	// override is keyed on the LIVE resumer's trust-gated X-User-Email, not
	// on the checkpoint's stored actor identity (see ResumeFromLastCheckpoint
	// above for why). Require the Agent gateway's proxy token (mirrors
	// StepGate / ResumeFromLastCheckpoint).
	if !h.requireProxyAuth(w, r) {
		return
	}
	scope, ok := h.requireScope(w, r)
	if !ok {
		return
	}

	vars := mux.Vars(r)
	workflowID := vars["id"]
	checkpointIDStr := vars["checkpoint_id"]

	if workflowID == "" {
		h.writeError(w, http.StatusBadRequest, "BAD_REQUEST", "Workflow ID is required")
		return
	}
	if checkpointIDStr == "" {
		h.writeError(w, http.StatusBadRequest, "BAD_REQUEST", "Checkpoint ID is required")
		return
	}

	checkpointID, err := strconv.ParseInt(checkpointIDStr, 10, 64)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, "BAD_REQUEST", "Invalid checkpoint ID")
		return
	}

	tenantID := scope.TenantID
	orgID := scope.OrgID

	// #3281: same as ResumeFromLastCheckpoint above -- the trust-gated
	// X-User-Email carried by THIS resume request, threaded into the fresh
	// step-gate re-evaluation so segment-scoped policies keep applying.
	resp, err := h.service.ResumeFromCheckpoint(r.Context(), workflowID, checkpointID, tenantID, orgID, r.Header.Get("X-User-Email"))
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			h.writeError(w, http.StatusNotFound, "NOT_FOUND", err.Error())
			return
		}
		if strings.Contains(err.Error(), "not resumable") || strings.Contains(err.Error(), "cannot resume") {
			h.writeError(w, http.StatusConflict, "NOT_RESUMABLE", err.Error())
			return
		}
		h.logger.Printf("[WorkflowControl] ResumeFromCheckpoint error for %s/%d: %v", workflowID, checkpointID, err)
		h.writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to resume from checkpoint")
		return
	}

	h.writeJSON(w, http.StatusOK, resp)
}
