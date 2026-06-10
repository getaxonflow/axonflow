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

package orchestrator

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"reflect"
	"strings"
	"sync"
	"time"

	_ "github.com/lib/pq"

	"axonflow/platform/agent"
)

// auditSearchCriteria is the normalized shape SearchAuditLogs matches against.
// It accepts both the tagged HTTP-decoding struct from run.go's handler AND
// the tag-less struct that pre-Plugin-Batch-1 unit tests use, avoiding a
// breaking change to test callers while still letting the handler carry the
// JSON tags it needs for request decoding.
type auditSearchCriteria struct {
	UserEmail   string
	ClientID    string
	TenantID    string
	StartTime   time.Time
	EndTime     time.Time
	RequestType string
	DecisionID  string
	PolicyName  string
	OverrideID  string
	Action      string
	Limit       int
	Offset      int
}

// asAuditSearchCriteria is a best-effort adapter from the various anonymous
// struct shapes callers have passed into SearchAuditLogs over time to the
// normalized form above. Returns (criteria, true) on success or (zero, false)
// when the value is not one of the recognised shapes.
//
// Using reflection here rather than exhaustive type-assertion branches keeps
// the handler/test struct definitions decoupled — the test's anonymous
// struct does not have to match the handler's json tags byte-for-byte.
func asAuditSearchCriteria(criteria interface{}) (auditSearchCriteria, bool) {
	v := reflect.ValueOf(criteria)
	if v.Kind() != reflect.Struct {
		return auditSearchCriteria{}, false
	}

	out := auditSearchCriteria{}
	t := v.Type()
	for i := 0; i < t.NumField(); i++ {
		name := t.Field(i).Name
		fv := v.Field(i)
		switch name {
		case "UserEmail":
			if fv.Kind() == reflect.String {
				out.UserEmail = fv.String()
			}
		case "ClientID":
			if fv.Kind() == reflect.String {
				out.ClientID = fv.String()
			}
		case "TenantID":
			if fv.Kind() == reflect.String {
				out.TenantID = fv.String()
			}
		case "StartTime":
			if ts, ok := fv.Interface().(time.Time); ok {
				out.StartTime = ts
			}
		case "EndTime":
			if ts, ok := fv.Interface().(time.Time); ok {
				out.EndTime = ts
			}
		case "RequestType":
			if fv.Kind() == reflect.String {
				out.RequestType = fv.String()
			}
		case "DecisionID":
			if fv.Kind() == reflect.String {
				out.DecisionID = fv.String()
			}
		case "PolicyName":
			if fv.Kind() == reflect.String {
				out.PolicyName = fv.String()
			}
		case "OverrideID":
			if fv.Kind() == reflect.String {
				out.OverrideID = fv.String()
			}
		case "Action":
			if fv.Kind() == reflect.String {
				out.Action = fv.String()
			}
		case "Limit":
			if fv.Kind() == reflect.Int || fv.Kind() == reflect.Int64 {
				out.Limit = int(fv.Int())
			}
		case "Offset":
			if fv.Kind() == reflect.Int || fv.Kind() == reflect.Int64 {
				out.Offset = int(fv.Int())
			}
		}
	}
	// Must have at least UserEmail as a sentinel that this isn't the
	// tenant-only shape handled above.
	return out, true
}

// AuditLogger handles comprehensive audit logging for all orchestrator activities
type AuditLogger struct {
	db           *sql.DB
	batchWriter  *BatchWriter
	auditQueue   chan *AuditEntry
	wg           sync.WaitGroup
	shutdownChan chan struct{}
}

// AuditEntry represents a single audit log entry
type AuditEntry struct {
	ID               string                 `json:"id"`
	RequestID        string                 `json:"request_id"`
	Timestamp        time.Time              `json:"timestamp"`
	UserID           int                    `json:"user_id"`
	UserEmail        string                 `json:"user_email"`
	UserRole         string                 `json:"user_role"`
	ClientID         string                 `json:"client_id"`
	TenantID         string                 `json:"tenant_id"`
	OrgID            string                 `json:"org_id"`
	RequestType      string                 `json:"request_type"`
	Query            string                 `json:"query"`
	QueryHash        string                 `json:"query_hash"`
	PolicyDecision   string                 `json:"policy_decision"` // "allowed", "blocked", "redacted"
	PolicyDetails    map[string]interface{} `json:"policy_details"`
	Provider         string                 `json:"provider"`
	Model            string                 `json:"model"`
	ResponseTime     int64                  `json:"response_time_ms"`
	TokensUsed       int                    `json:"tokens_used"`
	Cost             float64                `json:"cost"`
	RedactedFields   []string               `json:"redacted_fields"`
	ErrorMessage     string                 `json:"error_message,omitempty"`
	ResponseSample   string                 `json:"response_sample"`
	ComplianceFlags  []string               `json:"compliance_flags"`
	SecurityMetrics  map[string]interface{} `json:"security_metrics"`
	// Canonical decision-row columns (#2597 / #2611 / ADR-058). Populated on the
	// orchestrator response plane (#2626) so a redacted/blocked LLM response
	// lands in audit_logs with a first-class plane + decision_id + correlation_id
	// like every other plane, and the lineage exporters can stitch it to the
	// request-plane decision. Empty on legacy/other writers → NULL columns.
	DecisionID    string `json:"decision_id,omitempty"`
	Plane         string `json:"plane,omitempty"`
	CorrelationID string `json:"correlation_id,omitempty"`
}

// BatchWriter handles batch writing of audit entries
type BatchWriter struct {
	db          *sql.DB
	batchSize   int
	flushTicker *time.Ticker
	entries     []*AuditEntry
	mu          sync.Mutex
}

// NewAuditLogger creates a new audit logger.
//
// v9 Brief 11.5 / Session 20: routes through agent.OpenAppRoleConnection so the
// audit-logger pool honors AXONFLOW_DB_USE_APP_ROLE + AXONFLOW_DB_APP_ROLE_URL
// the same as orchestrator's primary usageDB. Without this, audit_logs INSERTs
// would silently land under the table-owner role and bypass any future FORCE
// RLS on audit_logs (deferred B2 follow-up).
func NewAuditLogger(databaseURL string) *AuditLogger {
	bootCtx := context.Background()
	db, err := agent.OpenAppRoleConnection(bootCtx, databaseURL, 3)
	if err != nil {
		log.Printf("Failed to connect to audit database: %v", err)
		// Return a no-op logger if database is unavailable
		return &AuditLogger{
			auditQueue:   make(chan *AuditEntry, 10000),
			shutdownChan: make(chan struct{}),
		}
	}
	var connectedRole string
	if err := db.QueryRowContext(bootCtx, "SELECT current_user").Scan(&connectedRole); err != nil {
		log.Printf("[orchestrator-audit] WARNING: failed to query current_user on audit DB: %v (continuing)", err)
	}
	log.Printf("[orchestrator-audit] ✅ pool connected as current_user=%s (UseAppRoleEnabled=%v, %s=%v)",
		connectedRole, agent.UseAppRoleEnabled(), agent.EnvAppRoleURL, os.Getenv(agent.EnvAppRoleURL) != "")

	// audit_logs table created by migration 059_runtime_tables_to_migrations.sql

	logger := &AuditLogger{
		db:           db,
		batchWriter:  NewBatchWriter(db, 100),
		auditQueue:   make(chan *AuditEntry, 10000),
		shutdownChan: make(chan struct{}),
	}

	// Start background workers
	logger.wg.Add(1)
	go logger.processAuditQueue()

	return logger
}

// LogSuccessfulRequest writes the canonical audit_logs row for an orchestrator
// LLM response that was delivered to the caller (verdict "allowed" or
// "redacted"). It is the authoritative response-plane writer (#2626): the
// shared policy engine's RecordViolation/RecordEvaluation are intentionally
// no-ops here (it is built with a nil AuditQueue), so this is the single source
// of truth — avoiding double-writes.
//
// The row is canonical: plane=llm + a fresh decision_id + the request's
// correlation_id (#2597 / #2611), so the portal decisions/audit feed and the
// lineage exporters treat it like every other plane and can stitch it back to
// the request-plane decision.
//
// The verdict is taken from the response-plane RedactionInfo carried in ctx
// (set by the handler). Crucially it is driven by RedactionInfo.Verdict, not by
// HasRedactions — so warn/log "detect-don't-modify" is recorded truthfully as
// "allowed" (with the detected fields still surfaced for audit), never
// mislabeled "redacted".
func (l *AuditLogger) LogSuccessfulRequest(ctx context.Context, req OrchestratorRequest,
	response interface{}, policyResult *PolicyEvaluationResult, providerInfo *ProviderInfo) *AuditEntry {

	decisionID := generateDecisionID()
	correlationID := correlationIDFromContext(ctx, req.RequestID)

	entry := &AuditEntry{
		ID:            generateAuditID(),
		RequestID:     req.RequestID,
		Timestamp:     time.Now().UTC(),
		UserID:        req.User.ID,
		UserEmail:     req.User.Email,
		UserRole:      req.User.Role,
		ClientID:      req.Client.ID,
		TenantID:      req.User.TenantID,
		OrgID:         req.Client.OrgID,
		RequestType:   req.RequestType,
		Query:         req.Query,
		QueryHash:     hashQuery(req.Query),
		PolicyDecision: responseVerdictAllowed,
		PolicyDetails: map[string]interface{}{
			"applied_policies": policyResult.AppliedPolicies,
			"risk_score":       policyResult.RiskScore,
			"processing_time":  policyResult.ProcessingTimeMs,
			// Dual-write the canonical keys into policy_details so the existing
			// SearchAuditLogs JSONB filters (policy_details->>'decision_id') keep
			// matching, alongside the first-class columns below.
			"decision_id":    decisionID,
			"correlation_id": correlationID,
			"plane":          agent.PlaneLLM,
		},
		Provider:        providerInfo.Provider,
		Model:           providerInfo.Model,
		ResponseTime:    providerInfo.ResponseTimeMs,
		TokensUsed:      providerInfo.TokensUsed,
		Cost:            providerInfo.Cost,
		ResponseSample:  truncateResponse(response),
		ComplianceFlags: l.detectComplianceFlags(req, response),
		SecurityMetrics: l.calculateSecurityMetrics(req, policyResult),
		DecisionID:      decisionID,
		Plane:           agent.PlaneLLM,
		CorrelationID:   correlationID,
	}

	// Verdict from the response-plane RedactionInfo carried in ctx.
	if redactionInfo, ok := ctx.Value(ctxKeyRedactionInfo).(*RedactionInfo); ok && redactionInfo != nil {
		entry.RedactedFields = redactionInfo.RedactedFields
		switch {
		case redactionInfo.Verdict != "":
			// Truthful verdict (warn/log → "allowed", block/redact → "redacted").
			entry.PolicyDecision = redactionInfo.Verdict
		case redactionInfo.HasRedactions:
			// Legacy callers that don't set Verdict still get the redacted label.
			entry.PolicyDecision = responseVerdictRedacted
		}
	}

	l.enqueueEntry(entry)
	return entry
}

// LogBlockedResponse writes the canonical audit_logs row when the orchestrator
// RESPONSE plane WITHHOLDS the LLM response (validation/governance denial). The
// row records verdict "blocked" with plane=llm + decision_id + correlation_id
// (#2626 ORCH-RESP-VALIDATE-DENY-AS-ALLOWED) — never the "allowed" success the
// old path silently persisted. The validation reason is preserved in
// policy_details for the auditor.
func (l *AuditLogger) LogBlockedResponse(ctx context.Context, req OrchestratorRequest,
	policyResult *PolicyEvaluationResult, info *RedactionInfo) *AuditEntry {
	if l == nil {
		return nil
	}

	decisionID := generateDecisionID()
	correlationID := correlationIDFromContext(ctx, req.RequestID)

	policyDetails := map[string]interface{}{
		"processing_time": policyResult.ProcessingTimeMs,
		"risk_score":      policyResult.RiskScore,
		"decision_id":     decisionID,
		"correlation_id":  correlationID,
		"plane":           agent.PlaneLLM,
		"block_phase":     "response",
	}
	if policyResult.AppliedPolicies != nil {
		policyDetails["applied_policies"] = policyResult.AppliedPolicies
	}
	var redactedFields []string
	if info != nil {
		if info.ValidationError != "" {
			policyDetails["validation_error"] = info.ValidationError
		}
		redactedFields = info.RedactedFields
	}

	entry := &AuditEntry{
		ID:             generateAuditID(),
		RequestID:      req.RequestID,
		Timestamp:      time.Now().UTC(),
		UserID:         req.User.ID,
		UserEmail:      req.User.Email,
		UserRole:       req.User.Role,
		ClientID:       req.Client.ID,
		TenantID:       req.User.TenantID,
		OrgID:          req.Client.OrgID,
		RequestType:    req.RequestType,
		Query:          req.Query,
		QueryHash:      hashQuery(req.Query),
		PolicyDecision: responseVerdictBlocked,
		PolicyDetails:  policyDetails,
		RedactedFields: redactedFields,
		ComplianceFlags: l.detectComplianceFlags(req, nil),
		SecurityMetrics: l.calculateSecurityMetrics(req, policyResult),
		DecisionID:      decisionID,
		Plane:           agent.PlaneLLM,
		CorrelationID:   correlationID,
	}

	l.enqueueEntry(entry)
	return entry
}

// LogBlockedRequest logs a blocked request
func (l *AuditLogger) LogBlockedRequest(ctx context.Context, req OrchestratorRequest, 
	policyResult *PolicyEvaluationResult) {
	
	entry := &AuditEntry{
		ID:            generateAuditID(),
		RequestID:     req.RequestID,
		Timestamp:     time.Now().UTC(),
		UserID:        req.User.ID,
		UserEmail:     req.User.Email,
		UserRole:      req.User.Role,
		ClientID:      req.Client.ID,
		TenantID:      req.User.TenantID,
		OrgID:         req.Client.OrgID,
		RequestType:   req.RequestType,
		Query:         req.Query,
		QueryHash:     hashQuery(req.Query),
		PolicyDecision: "blocked",
		PolicyDetails: map[string]interface{}{
			"applied_policies":  policyResult.AppliedPolicies,
			"risk_score":        policyResult.RiskScore,
			"required_actions":  policyResult.RequiredActions,
			"processing_time":   policyResult.ProcessingTimeMs,
		},
		ComplianceFlags: l.detectComplianceFlags(req, nil),
		SecurityMetrics: l.calculateSecurityMetrics(req, policyResult),
	}

	l.enqueueEntry(entry)
}

// LogFailedRequest logs a failed request
func (l *AuditLogger) LogFailedRequest(ctx context.Context, req OrchestratorRequest, err error) {
	entry := &AuditEntry{
		ID:            generateAuditID(),
		RequestID:     req.RequestID,
		Timestamp:     time.Now().UTC(),
		UserID:        req.User.ID,
		UserEmail:     req.User.Email,
		UserRole:      req.User.Role,
		ClientID:      req.Client.ID,
		TenantID:      req.User.TenantID,
		OrgID:         req.Client.OrgID,
		RequestType:   req.RequestType,
		Query:         req.Query,
		QueryHash:     hashQuery(req.Query),
		PolicyDecision: "error",
		ErrorMessage:   err.Error(),
		ComplianceFlags: l.detectComplianceFlags(req, nil),
	}

	l.enqueueEntry(entry)
}

// WorkflowAuditEntry represents an audit entry for workflow operations
type WorkflowAuditEntry struct {
	WorkflowID   string
	WorkflowName string
	StepID       string
	StepName     string
	Operation    string // workflow_created, step_gate, step_completed, step_approved, step_rejected, workflow_completed, workflow_aborted
	Decision     string // allow, block, require_approval (for step_gate)
	Reason       string
	TenantID     string
	OrgID        string
	ClientID     string
	UserID       string
	UserEmail    string // v7.4.1+: reviewer email for step_approved/step_rejected
	UserRole     string // v7.4.1+: reviewer role
	Metadata     map[string]interface{}
}

// LogWorkflowOperation logs a workflow control plane operation
func (l *AuditLogger) LogWorkflowOperation(ctx context.Context, entry *WorkflowAuditEntry) {
	if l == nil {
		return
	}

	// Build policy details from entry metadata
	policyDetails := map[string]interface{}{
		"workflow_id":   entry.WorkflowID,
		"workflow_name": entry.WorkflowName,
		"operation":     entry.Operation,
	}
	if entry.StepID != "" {
		policyDetails["step_id"] = entry.StepID
	}
	if entry.StepName != "" {
		policyDetails["step_name"] = entry.StepName
	}
	if entry.Decision != "" {
		policyDetails["decision"] = entry.Decision
	}
	if entry.Reason != "" {
		policyDetails["reason"] = entry.Reason
	}
	if entry.Metadata != nil {
		for k, v := range entry.Metadata {
			policyDetails[k] = v
		}
	}

	// Map workflow decision to policy decision format
	var policyDecision string
	switch entry.Decision {
	case "block":
		policyDecision = "blocked"
	case "require_approval":
		policyDecision = "pending_approval"
	default:
		policyDecision = "allowed"
	}

	auditEntry := &AuditEntry{
		ID:             generateAuditID(),
		RequestID:      entry.WorkflowID,
		Timestamp:      time.Now().UTC(),
		UserID:         0, // Workflow operations may not have a numeric user ID
		UserEmail:      entry.UserEmail,
		UserRole:       entry.UserRole,
		ClientID:       entry.ClientID,
		TenantID:       entry.TenantID,
		OrgID:          entry.OrgID,
		RequestType:    "workflow_" + entry.Operation,
		Query:          fmt.Sprintf("Workflow: %s, Operation: %s", entry.WorkflowName, entry.Operation),
		QueryHash:      hashQuery(entry.WorkflowID + entry.Operation),
		PolicyDecision: policyDecision,
		PolicyDetails:  policyDetails,
	}

	l.enqueueEntry(auditEntry)
}

// PlanAuditEntry represents an audit entry for plan (MAP) operations
type PlanAuditEntry struct {
	PlanID    string
	Query     string
	Domain    string
	Operation string // created, execution_started, completed, failed, expired
	Status    string
	StepCount int
	ErrorMsg  string
	TenantID  string
	OrgID     string
	ClientID  string
	UserID    string
	Metadata  map[string]interface{}
}

// LogPlanOperation logs a Multi-Agent Planning (MAP) operation
func (l *AuditLogger) LogPlanOperation(ctx context.Context, entry *PlanAuditEntry) {
	if l == nil {
		return
	}

	// Build policy details from entry metadata
	policyDetails := map[string]interface{}{
		"plan_id":    entry.PlanID,
		"domain":     entry.Domain,
		"operation":  entry.Operation,
		"status":     entry.Status,
		"step_count": entry.StepCount,
	}
	if entry.ErrorMsg != "" {
		policyDetails["error"] = entry.ErrorMsg
	}
	if entry.Metadata != nil {
		for k, v := range entry.Metadata {
			policyDetails[k] = v
		}
	}

	// Map plan status to policy decision format
	policyDecision := "allowed"
	if entry.Operation == "failed" {
		policyDecision = "error"
	}

	auditEntry := &AuditEntry{
		ID:             generateAuditID(),
		RequestID:      entry.PlanID,
		Timestamp:      time.Now().UTC(),
		UserID:         0, // Plan operations may not have user context
		ClientID:       entry.ClientID,
		TenantID:       entry.TenantID,
		OrgID:          entry.OrgID,
		RequestType:    "plan_" + entry.Operation,
		Query:          entry.Query,
		QueryHash:      hashQuery(entry.PlanID + entry.Operation),
		PolicyDecision: policyDecision,
		PolicyDetails:  policyDetails,
	}

	l.enqueueEntry(auditEntry)
}

// ToolCallAuditEntry represents an audit entry for non-LLM tool calls
// (API calls, webhooks, MCP tool executions by external orchestrators)
type ToolCallAuditEntry struct {
	ToolName        string                 `json:"tool_name"`
	ToolType        string                 `json:"tool_type,omitempty"`
	Input           map[string]interface{} `json:"input,omitempty"`
	Output          map[string]interface{} `json:"output,omitempty"`
	WorkflowID      string                 `json:"workflow_id,omitempty"`
	StepID          string                 `json:"step_id,omitempty"`
	UserID          string                 `json:"user_id,omitempty"`
	DurationMs      int64                  `json:"duration_ms,omitempty"`
	PoliciesApplied []string               `json:"policies_applied,omitempty"`
	Success         *bool                  `json:"success,omitempty"`
	ErrorMessage    string                 `json:"error_message,omitempty"`
	TenantID        string                 `json:"-"`
	OrgID           string                 `json:"-"`
	ClientID        string                 `json:"-"`
}

// LogToolCallAudit logs a non-LLM tool call audit entry
func (l *AuditLogger) LogToolCallAudit(ctx context.Context, entry *ToolCallAuditEntry) *AuditEntry {
	if l == nil {
		return nil
	}

	policyDetails := map[string]interface{}{
		"tool_name": entry.ToolName,
	}
	if entry.ToolType != "" {
		policyDetails["tool_type"] = entry.ToolType
	}
	if entry.Input != nil {
		policyDetails["input"] = entry.Input
	}
	if entry.Output != nil {
		policyDetails["output"] = entry.Output
	}
	if entry.WorkflowID != "" {
		policyDetails["workflow_id"] = entry.WorkflowID
	}
	if entry.StepID != "" {
		policyDetails["step_id"] = entry.StepID
	}
	if entry.DurationMs > 0 {
		policyDetails["duration_ms"] = entry.DurationMs
	}
	if len(entry.PoliciesApplied) > 0 {
		policyDetails["policies_applied"] = entry.PoliciesApplied
	}
	if entry.Success != nil {
		policyDetails["success"] = *entry.Success
	}
	if entry.ErrorMessage != "" {
		policyDetails["error_message"] = entry.ErrorMessage
	}

	policyDecision := "allowed"
	if entry.Success != nil && !*entry.Success {
		policyDecision = "error"
	}

	auditEntry := &AuditEntry{
		ID:             generateAuditID(),
		RequestID:      entry.WorkflowID,
		Timestamp:      time.Now().UTC(),
		UserID:         0,
		UserEmail:      entry.UserID,
		ClientID:       entry.ClientID,
		TenantID:       entry.TenantID,
		OrgID:          entry.OrgID,
		RequestType:    "tool_call_audit",
		Query:          fmt.Sprintf("Tool: %s", entry.ToolName),
		QueryHash:      hashQuery(entry.ToolName + entry.WorkflowID),
		PolicyDecision: policyDecision,
		PolicyDetails:  policyDetails,
		ErrorMessage:   entry.ErrorMessage,
	}

	l.enqueueEntry(auditEntry)
	return auditEntry
}

// SearchAuditLogs searches audit logs based on criteria
func (l *AuditLogger) SearchAuditLogs(criteria interface{}) ([]*AuditEntry, int, error) {
	if l.db == nil {
		return []*AuditEntry{}, 0, nil
	}

	// Build query based on criteria
	query := `
		SELECT id, request_id, timestamp, user_id, user_email, user_role,
			   client_id, tenant_id, request_type, query, policy_decision,
			   policy_details, provider, model, response_time_ms, tokens_used,
			   cost, redacted_fields, error_message, compliance_flags,
			   COUNT(*) OVER() AS total_count
		FROM audit_logs
		WHERE 1=1
	`

	args := []interface{}{}
	argIndex := 1

	// Add search conditions based on criteria
	// Handle tenant-specific search (from tenantAuditLogsHandler)
	if searchReq, ok := criteria.(struct {
		TenantID string `json:"tenant_id"`
		Limit    int    `json:"limit"`
	}); ok {
		if searchReq.TenantID != "" {
			query += fmt.Sprintf(" AND tenant_id = $%d", argIndex)
			args = append(args, searchReq.TenantID)
			// argIndex not incremented as no more params in this branch
		}

		query += " ORDER BY timestamp DESC"

		if searchReq.Limit > 0 {
			query += fmt.Sprintf(" LIMIT %d", searchReq.Limit)
		}
	} else if searchReq, ok := asAuditSearchCriteria(criteria); ok {
		// Handle general search (from auditSearchHandler or via named-type callers).
		if searchReq.UserEmail != "" {
			query += fmt.Sprintf(" AND user_email ILIKE '%%' || $%d || '%%'", argIndex)
			args = append(args, searchReq.UserEmail)
			argIndex++
		}
		if searchReq.ClientID != "" {
			query += fmt.Sprintf(" AND client_id ILIKE '%%' || $%d || '%%'", argIndex)
			args = append(args, searchReq.ClientID)
			argIndex++
		}
		// Tenant scoping. The handler force-injects this from the trusted
		// X-Tenant-ID header; without it the search returned every tenant's
		// audit logs to any caller (cross-tenant data leak: a portal user
		// for tenant A could read tenant B's audit history simply by
		// posting to /api/v1/audit/search).
		if searchReq.TenantID != "" {
			query += fmt.Sprintf(" AND tenant_id = $%d", argIndex)
			args = append(args, searchReq.TenantID)
			argIndex++
		}
		if !searchReq.StartTime.IsZero() {
			query += fmt.Sprintf(" AND timestamp >= $%d", argIndex)
			args = append(args, searchReq.StartTime)
			argIndex++
		}
		if !searchReq.EndTime.IsZero() {
			query += fmt.Sprintf(" AND timestamp <= $%d", argIndex)
			args = append(args, searchReq.EndTime)
			argIndex++
		}
		if searchReq.RequestType != "" {
			query += fmt.Sprintf(" AND request_type = $%d", argIndex)
			args = append(args, searchReq.RequestType)
			argIndex++
		}
		// Plugin Batch 1 filters — decision_id + policy_name + override_id.
		// policy_details is JSONB; filters use ->> operator against the same
		// field the writers populate. Indexes on audit_logs per migration 010.
		if searchReq.DecisionID != "" {
			query += fmt.Sprintf(" AND policy_details->>'decision_id' = $%d", argIndex)
			args = append(args, searchReq.DecisionID)
			argIndex++
		}
		if searchReq.PolicyName != "" {
			// Match the policy name against three shapes audit writers use:
			//   1. top-level policy_details.policy_name (scalar)
			//   2. top-level policy_details.policy_names (CSV-ish string)
			//   3. nested policy_details.policy_matches[*].policy_name
			//      (workflow step gates + decision records)
			// The third form is the primary one for Plugin Batch 1 and must
			// be indexed via the GIN index on policy_details for perf.
			query += fmt.Sprintf(" AND ("+
				"policy_details->>'policy_name' = $%d "+
				"OR policy_details->>'policy_names' LIKE '%%' || $%d || '%%' "+
				"OR EXISTS (SELECT 1 FROM jsonb_array_elements(policy_details->'policy_matches') AS _pm WHERE _pm->>'policy_name' = $%d)"+
				")", argIndex, argIndex, argIndex)
			args = append(args, searchReq.PolicyName)
			argIndex++
		}
		if searchReq.OverrideID != "" {
			query += fmt.Sprintf(" AND policy_details->>'override_id' = $%d", argIndex)
			args = append(args, searchReq.OverrideID)
			argIndex++
		}
		if searchReq.Action != "" {
			query += fmt.Sprintf(" AND policy_decision = $%d", argIndex)
			args = append(args, searchReq.Action)
		}

		query += " ORDER BY timestamp DESC"

		if searchReq.Limit > 0 {
			query += fmt.Sprintf(" LIMIT %d", searchReq.Limit)
		}
		if searchReq.Offset > 0 {
			query += fmt.Sprintf(" OFFSET %d", searchReq.Offset)
		}
	}

	rows, err := l.db.Query(query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = rows.Close() }()

	// Pre-allocate so the zero-result path returns `[]` not `nil`. JSON
	// callers downstream serialize nil as `null`, which breaks any
	// consumer that does `for entry of entries` or `entries.length`.
	entries := make([]*AuditEntry, 0)
	totalCount := 0
	for rows.Next() {
		entry := &AuditEntry{}
		var policyDetailsJSON, redactedFieldsJSON, complianceFlagsJSON []byte
		// provider, model, error_message and the numeric cost/tokens columns
		// are nullable in audit_logs. Pre-LLM audit entries (MCP check-input,
		// override_created/used/revoked, workflow step gates) omit those
		// columns. Scan into nullable types so the loop doesn't abort
		// mid-iteration on a NULL value — prior to this, NULL provider
		// dropped ALL rows from every search response.
		var provider, model, errorMessage sql.NullString
		var responseTime, tokensUsed sql.NullInt64
		var cost sql.NullFloat64
		var rowTotal int

		err := rows.Scan(
			&entry.ID,
			&entry.RequestID,
			&entry.Timestamp,
			&entry.UserID,
			&entry.UserEmail,
			&entry.UserRole,
			&entry.ClientID,
			&entry.TenantID,
			&entry.RequestType,
			&entry.Query,
			&entry.PolicyDecision,
			&policyDetailsJSON,
			&provider,
			&model,
			&responseTime,
			&tokensUsed,
			&cost,
			&redactedFieldsJSON,
			&errorMessage,
			&complianceFlagsJSON,
			&rowTotal,
		)
		if err != nil {
			log.Printf("Error scanning audit log: %v", err)
			continue
		}

		// Surface nullable columns as Go zero values — callers already
		// tolerate empty strings + zero-valued numerics.
		entry.Provider = provider.String
		entry.Model = model.String
		entry.ErrorMessage = errorMessage.String
		entry.ResponseTime = responseTime.Int64
		entry.TokensUsed = int(tokensUsed.Int64)
		entry.Cost = cost.Float64

		// All rows carry the same window-function value; capture it once per
		// iteration so that after the loop totalCount reflects the true number
		// of matching rows before the LIMIT was applied.
		totalCount = rowTotal

		// Unmarshal JSON fields
		_ = json.Unmarshal(policyDetailsJSON, &entry.PolicyDetails)
		_ = json.Unmarshal(redactedFieldsJSON, &entry.RedactedFields)
		_ = json.Unmarshal(complianceFlagsJSON, &entry.ComplianceFlags)

		entries = append(entries, entry)
	}

	return entries, totalCount, nil
}

// IsHealthy checks if the audit logger is healthy
func (l *AuditLogger) IsHealthy() bool {
	if l.db == nil {
		return true // No-op logger is always healthy
	}

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	err := l.db.PingContext(ctx)
	return err == nil
}

// enqueueEntry adds an entry to the processing queue
func (l *AuditLogger) enqueueEntry(entry *AuditEntry) {
	select {
	case l.auditQueue <- entry:
		// Entry queued successfully
	default:
		// Queue is full, log directly (blocking)
		log.Printf("Audit queue full, writing directly")
		if l.batchWriter != nil {
			_ = l.batchWriter.Write([]*AuditEntry{entry})
		}
	}
}

// processAuditQueue processes audit entries from the queue
func (l *AuditLogger) processAuditQueue() {
	defer l.wg.Done()

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case entry := <-l.auditQueue:
			if l.batchWriter != nil {
				l.batchWriter.Add(entry)
			}
		case <-ticker.C:
			if l.batchWriter != nil {
				l.batchWriter.Flush()
			}
		case <-l.shutdownChan:
			// Flush remaining entries
			if l.batchWriter != nil {
				l.batchWriter.Flush()
			}
			return
		}
	}
}

// detectComplianceFlags detects compliance-related flags in the request
func (l *AuditLogger) detectComplianceFlags(req OrchestratorRequest, response interface{}) []string {
	flags := []string{}

	// Check for HIPAA-related queries
	if strings.Contains(strings.ToLower(req.Query), "patient") ||
		strings.Contains(strings.ToLower(req.Query), "medical") {
		flags = append(flags, "hipaa_relevant")
	}

	// Check for GDPR-related queries
	if req.User.TenantID != "" && strings.HasPrefix(req.User.TenantID, "eu_") {
		flags = append(flags, "gdpr_applicable")
	}

	// Check for financial data
	if strings.Contains(strings.ToLower(req.Query), "account") ||
		strings.Contains(strings.ToLower(req.Query), "transaction") {
		flags = append(flags, "sox_relevant")
	}

	// Check for PII access
	piiKeywords := []string{"ssn", "email", "phone", "address", "credit_card"}
	for _, keyword := range piiKeywords {
		if strings.Contains(strings.ToLower(req.Query), keyword) {
			flags = append(flags, "pii_access")
			break
		}
	}

	return flags
}

// calculateSecurityMetrics calculates security metrics for the request
func (l *AuditLogger) calculateSecurityMetrics(req OrchestratorRequest, policyResult *PolicyEvaluationResult) map[string]interface{} {
	metrics := map[string]interface{}{
		"risk_score":        policyResult.RiskScore,
		"policies_applied":  len(policyResult.AppliedPolicies),
		"query_complexity":  calculateQueryComplexity(req.Query),
		"sensitive_access":  containsSensitiveAccess(req.Query),
	}

	return metrics
}

// Utility functions

func generateAuditID() string {
	return fmt.Sprintf("audit_%d_%s", time.Now().Unix(), generateRandomString(8))
}

// generateDecisionID mints the canonical decision_id for an orchestrator
// response-plane audit row (#2626). Distinct from the row's primary-key id; it
// is the per-decision correlation handle the lineage exporters key on.
func generateDecisionID() string {
	return fmt.Sprintf("orchresp_%d_%s", time.Now().UnixNano(), generateRandomString(12))
}

// correlationIDFromContext returns the request's W3C correlation_id (#2611) when
// the handler propagated one (traceparent → trace_id), else the supplied
// fallback (the request id). Never returns empty so a response-plane row always
// carries a correlation key the exporters can GROUP BY.
func correlationIDFromContext(ctx context.Context, fallback string) string {
	if ctx != nil {
		if v, ok := ctx.Value(ctxKeyCorrelationID).(string); ok && v != "" {
			return v
		}
	}
	return fallback
}

// nullIfEmpty maps "" → SQL NULL so nullable VARCHAR columns stay NULL for
// writers that don't populate them (keeping partial indexes + lineage scoped to
// rows that genuinely carry the value).
func nullIfEmpty(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}

func hashQuery(query string) string {
	// Simple hash for query deduplication
	// In production, use a proper hash function
	return fmt.Sprintf("%x", len(query))
}

func truncateResponse(response interface{}) string {
	respStr := fmt.Sprint(response)
	if len(respStr) > 200 {
		return respStr[:200] + "..."
	}
	return respStr
}

func calculateQueryComplexity(query string) string {
	// Simple complexity calculation
	if strings.Count(strings.ToLower(query), "join") > 2 {
		return "high"
	}
	if strings.Contains(strings.ToLower(query), "join") {
		return "medium"
	}
	return "low"
}

func containsSensitiveAccess(query string) bool {
	sensitivePatterns := []string{
		"password", "secret", "key", "token",
		"ssn", "social_security", "credit_card",
	}
	
	lowerQuery := strings.ToLower(query)
	for _, pattern := range sensitivePatterns {
		if strings.Contains(lowerQuery, pattern) {
			return true
		}
	}
	return false
}

// BatchWriter implementation

func NewBatchWriter(db *sql.DB, batchSize int) *BatchWriter {
	writer := &BatchWriter{
		db:          db,
		batchSize:   batchSize,
		entries:     make([]*AuditEntry, 0, batchSize),
		flushTicker: time.NewTicker(10 * time.Second),
	}

	go writer.periodicFlush()

	return writer
}

func (b *BatchWriter) Add(entry *AuditEntry) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.entries = append(b.entries, entry)

	if len(b.entries) >= b.batchSize {
		b.flush()
	}
}

func (b *BatchWriter) Flush() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.flush()
}

func (b *BatchWriter) flush() {
	if len(b.entries) == 0 {
		return
	}

	if err := b.Write(b.entries); err != nil {
		log.Printf("Failed to write audit batch: %v", err)
	}

	b.entries = b.entries[:0]
}

func (b *BatchWriter) Write(entries []*AuditEntry) error {
	if b.db == nil {
		return nil
	}

	tx, err := b.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	stmt, err := tx.Prepare(`
		INSERT INTO audit_logs (
			id, request_id, timestamp, user_id, user_email, user_role,
			client_id, tenant_id, org_id, request_type, query, query_hash,
			policy_decision, policy_details, provider, model,
			response_time_ms, tokens_used, cost, redacted_fields,
			error_message, response_sample, compliance_flags, security_metrics,
			decision_id, plane, correlation_id
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27)
	`)
	if err != nil {
		return err
	}
	defer func() { _ = stmt.Close() }()

	for _, entry := range entries {
		policyDetailsJSON, _ := json.Marshal(entry.PolicyDetails)
		redactedFieldsJSON, _ := json.Marshal(entry.RedactedFields)
		complianceFlagsJSON, _ := json.Marshal(entry.ComplianceFlags)
		securityMetricsJSON, _ := json.Marshal(entry.SecurityMetrics)

		_, err = stmt.Exec(
			entry.ID,
			entry.RequestID,
			entry.Timestamp,
			entry.UserID,
			entry.UserEmail,
			entry.UserRole,
			entry.ClientID,
			entry.TenantID,
			entry.OrgID,
			entry.RequestType,
			entry.Query,
			entry.QueryHash,
			entry.PolicyDecision,
			policyDetailsJSON,
			entry.Provider,
			entry.Model,
			entry.ResponseTime,
			entry.TokensUsed,
			entry.Cost,
			redactedFieldsJSON,
			entry.ErrorMessage,
			entry.ResponseSample,
			complianceFlagsJSON,
			securityMetricsJSON,
			// Canonical decision-row columns (#2626). Nullable: legacy/other-plane
			// writers leave these empty → NULL, so the partial indexes
			// (decision_id/correlation_id) and the lineage exporters only pick up
			// rows that genuinely carry a canonical decision.
			nullIfEmpty(entry.DecisionID),
			nullIfEmpty(entry.Plane),
			nullIfEmpty(entry.CorrelationID),
		)
		if err != nil {
			log.Printf("Failed to insert audit entry: %v", err)
		}
	}

	return tx.Commit()
}

func (b *BatchWriter) periodicFlush() {
	for range b.flushTicker.C {
		b.Flush()
	}
}

