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

	"github.com/lib/pq"

	"axonflow/platform/agent"
	sharedaudit "axonflow/platform/shared/audit"
)

// auditSearchCriteria is the normalized shape SearchAuditLogs matches against.
// It accepts both the tagged HTTP-decoding struct from run.go's handler AND
// the tag-less struct that pre-Plugin-Batch-1 unit tests use, avoiding a
// breaking change to test callers while still letting the handler carry the
// JSON tags it needs for request decoding.
type auditSearchCriteria struct {
	UserEmail  string
	ClientID   string
	TenantID   string
	StartTime  time.Time
	EndTime    time.Time
	DecisionID string
	PolicyName string
	OverrideID string
	Action     string
	// SessionID filters to a single AI-tool session (#2753/#2754, core/129),
	// mirroring the DecisionID/OverrideID JSONB filters below but against the
	// first-class audit_logs.session_id column. Lets a session-summary bucket
	// (#2759) drill down into its raw events via ?session_id=X.
	SessionID string
	// ScopeUserEmail is the ENFORCED own-rows read scope (#2922) — the
	// canonical email of a non-tenant-wide caller, applied as an exact
	// case-insensitive predicate (LOWER(user_email) = $n) that a caller-
	// supplied UserEmail filter can only narrow, never widen. It is derived
	// server-side from resolveCallerReadScope and MUST NEVER be populated
	// from a request body or query string. Distinct from UserEmail (the
	// ILIKE substring FILTER) because a substring match is not a security
	// boundary: an injected substring over-matches sibling identities
	// ("dev@x.com" ⊂ "otherdev@x.com").
	ScopeUserEmail string
	Limit          int
	Offset         int
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
		case "SessionID":
			if fv.Kind() == reflect.String {
				out.SessionID = fv.String()
			}
		case "ScopeUserEmail":
			if fv.Kind() == reflect.String {
				out.ScopeUserEmail = fv.String()
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
	ID             string                 `json:"id"`
	RequestID      string                 `json:"request_id"`
	Timestamp      time.Time              `json:"timestamp"`
	UserID         int                    `json:"user_id"`
	UserEmail      string                 `json:"user_email"`
	UserRole       string                 `json:"user_role"`
	ClientID       string                 `json:"client_id"`
	TenantID       string                 `json:"tenant_id"`
	OrgID          string                 `json:"org_id"`
	RequestType    string                 `json:"request_type"`
	Query          string                 `json:"query"`
	QueryHash      string                 `json:"query_hash"`
	PolicyDecision string                 `json:"policy_decision"` // "allowed", "blocked", "redacted"
	PolicyDetails  map[string]interface{} `json:"policy_details"`
	Provider       string                 `json:"provider"`
	Model          string                 `json:"model"`
	// ResponseTime is the measured duration for this row in whole milliseconds,
	// or nil when this row's writer measured nothing (#3424).
	//
	// It is a POINTER because the absence of a measurement is a fact this struct
	// has to be able to hold. Only LogSuccessfulRequest populates it; the seven
	// other AuditEntry producers here -- blocked request / response / media,
	// failed request, workflow, plan and tool-call rows -- have no duration to
	// record, and while this was a plain int64 their zero VALUE was
	// indistinguishable from a measured zero. That was wrong twice over: the
	// BatchWriter INSERT bound a literal 0 into a column whose reader treats a
	// value as a sample, and, worse, /api/v1/audit/search serialized
	// `"response_time_ms": 0` for every one of those rows, which the portal's
	// Latency column rendered as a confident "0ms" one panel below the Avg
	// Latency tile this issue exists to stop fabricating.
	//
	// omitempty, so an unmeasured row OMITS the key rather than emitting an
	// explicit null. AuditLogEntry declares no `required` list, so the field
	// was ALREADY optional in the published contract and every conforming
	// client must already handle its absence -- which makes this the one shape
	// that fixes the lie without changing the contract at all. On a POINTER
	// omitempty drops only nil, so a measured 0 (a decision faster than the
	// column's 1ms resolution) still serializes as 0; a value-typed omitempty
	// would have swallowed exactly that sample.
	//
	// Bind it with sharedaudit.LatencyValue and render it with the portal's
	// formatRowLatency; both sides of that pair agree with
	// sharedaudit.LatencyMeasuredPredicate.
	ResponseTime *int64 `json:"response_time_ms,omitempty"`
	// TokensUsed and Cost are the provider round trip's usage for this row, or
	// nil when the row carries no RECORDED provider usage (#3427 M19).
	//
	// NIL MEANS "NOT RECORDED", NOT "NO PROVIDER WAS CALLED", and the
	// distinction is load-bearing because a published contract states it.
	// LogSuccessfulRequest is the only writer that RECORDS usage, but it is
	// not the only writer HANDED a ProviderInfo: LogBlockedResponse takes one
	// too, and it is a post-forward path (run.go forwards, then the response
	// plane withholds the answer), so its rows are round trips that were paid
	// for and discarded. It records none of that usage today - a gap in that
	// writer, deliberately not closed here because stamping it would move
	// SUM(tokens_used)/SUM(cost) in the session summary and the OJK LLM-call
	// section, which is a compliance-figure change and not a table-layout one.
	//
	// POINTERS for the same reason ResponseTime is one: while these were plain
	// value types every producer that records no usage had its zero value
	// bound into the INSERT as a literal 0 and re-serialized to
	// /api/v1/audit/search as
	// `"tokens_used": 0, "cost": 0`, which the portal's detail panel rendered
	// as "Tokens 0" and "Cost $0.0000" beneath a request that was blocked
	// before any model saw it.
	//
	// omitempty, so an unmeasured row OMITS the key. AuditLogEntry declares no
	// `required` list, so both properties were already optional in the
	// published contract. On a pointer omitempty drops only nil, so a genuine
	// zero-cost round trip (a local or free-tier model) still serializes.
	TokensUsed      *int                   `json:"tokens_used,omitempty"`
	Cost            *float64               `json:"cost,omitempty"`
	RedactedFields  []string               `json:"redacted_fields"`
	ErrorMessage    string                 `json:"error_message,omitempty"`
	ResponseSample  string                 `json:"response_sample"`
	ComplianceFlags []string               `json:"compliance_flags"`
	SecurityMetrics map[string]interface{} `json:"security_metrics"`
	// Canonical decision-row columns (#2597 / #2611 / ADR-058). Populated on the
	// orchestrator response plane (#2626) so a redacted/blocked LLM response
	// lands in audit_logs with a first-class plane + decision_id + correlation_id
	// like every other plane, and the lineage exporters can stitch it to the
	// request-plane decision. Empty on legacy/other writers → NULL columns.
	DecisionID    string `json:"decision_id,omitempty"`
	Plane         string `json:"plane,omitempty"`
	CorrelationID string `json:"correlation_id,omitempty"`
	// UU PDP Pasal 56 cross-border transfer fields (#2718, core migration 126).
	// Auto-stamped on the LLM-forward path via stampCrossBorderTransfer (enterprise
	// only); empty on every other writer and in community builds → NULL columns.
	// TransferBasis is the declared legal basis (adequacy/safeguards/pasal_56b_dpa/
	// consent); DataResidency is the ISO 3166-1 alpha-2 destination country.
	TransferBasis string `json:"transfer_basis,omitempty"`
	DataResidency string `json:"data_residency,omitempty"`
	// SessionID is the AI-tool session id (Claude Code / Desktop) forwarded via
	// X-Session-Id (#2753/#2754, core migration 129). Sibling of UserEmail:
	// asserted attribution, not an auth boundary. Empty on every writer that
	// doesn't carry a session → NULL column (partial index skips it).
	SessionID string `json:"session_id,omitempty"`
}

// stampCrossBorderTransfer auto-stamps the UU PDP Pasal 56 transfer_basis +
// data_residency onto an LLM-forward audit row. It is wired by the enterprise
// build (cross_border_audit.go init); in a community build it stays nil so the
// columns are written NULL and behavior is byte-identical (#2718).
var stampCrossBorderTransfer func(entry *AuditEntry, req OrchestratorRequest, providerInfo *ProviderInfo)

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

// nullLatencyPtr converts the scanned audit_logs.response_time_ms into
// AuditEntry.ResponseTime (#3424): a SQL NULL becomes a nil pointer, which
// omitempty then drops from the JSON entirely, which the portal renders as
// "-". Surfacing it as the int64 zero value instead -- which every one of
// these read paths used to do -- re-manufactured on the WIRE exactly the
// fabricated "0ms" the write path had just stopped storing.
func nullLatencyPtr(n sql.NullInt64) *int64 {
	if !n.Valid {
		return nil
	}
	v := n.Int64
	return &v
}

// nullTokensPtr / nullCostPtr are the token and cost twins of nullLatencyPtr
// (#3427, sub-finding M19). audit_logs.tokens_used and audit_logs.cost are
// nullable and NULL on every row that recorded no provider usage: a blocked
// request, a redaction, a pre-check deny, a workflow step, a tool call -- and
// also a RESPONSE-plane block, which is the one member of that list where a
// round trip really did happen and LogBlockedResponse simply records none of
// the usage it is handed (see providerUsagePtrs below). All
// three read paths scanned them into sql.Null* and then took .Int64 / .Float64
// WITHOUT checking .Valid, so "this row recorded no usage" left the
// orchestrator as `"tokens_used": 0, "cost": 0` -- and the portal's expanded
// detail panel, whose `!= null` guards were written for exactly this case,
// rendered "Tokens 0" and "Cost $0.0000" under a governed block. That is the
// same defect class #3424 fixed for latency, on the two columns it did not
// cover, and it reads as a measurement of a thing that never happened.
func nullTokensPtr(n sql.NullInt64) *int {
	if !n.Valid {
		return nil
	}
	v := int(n.Int64)
	return &v
}

func nullCostPtr(n sql.NullFloat64) *float64 {
	if !n.Valid {
		return nil
	}
	v := n.Float64
	return &v
}

// providerUsagePtrs lifts a provider round trip's token count and cost onto
// AuditEntry (#3427 M19).
//
// Unlike the latency twin below, a 0 here is KEPT when the round trip really
// happened: a locally hosted or free-tier model genuinely costs 0.0000, and
// discarding that would replace a measured zero with "not recorded" - the
// mirror image of the bug. The absence signal is the CALL to this helper:
// LogSuccessfulRequest is the only writer that makes it, and every other
// AuditEntry producer leaves both fields nil. That is not the same as "the
// only writer with a ProviderInfo" - LogBlockedResponse is handed one too and
// simply does not record it (see the AuditEntry.TokensUsed doc above).
func providerUsagePtrs(tokens int, cost float64) (*int, *float64) {
	t, c := tokens, cost
	return &t, &c
}

// providerLatencyPtr lifts a provider round-trip duration onto
// AuditEntry.ResponseTime (#3424).
//
// ProviderInfo.ResponseTimeMs is a plain int64 filled in by the LLM adapters
// from time.Since(start), so it has no way to say "absent": a provider info
// assembled on an error path, or by an adapter that never timed the call,
// carries a 0 that means nothing was measured rather than a call that returned
// instantly. A network round trip to a third-party API cannot complete in under
// a millisecond, so treating a non-positive value here as unmeasured cannot
// discard a real sample -- unlike the enforcement planes, where 0 IS a real
// sub-millisecond result and is kept.
func providerLatencyPtr(ms int64) *int64 {
	if ms <= 0 {
		return nil
	}
	v := ms
	return &v
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

	// #3427 M19: this is the ONE writer that RECORDS a token count and a cost.
	// Every other producer leaves both nil and stores NULL - including
	// LogBlockedResponse, which is handed a ProviderInfo for a round trip that
	// really happened and records none of it.
	tokensPtr, costPtr := providerUsagePtrs(providerInfo.TokensUsed, providerInfo.Cost)

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
		Provider: providerInfo.Provider,
		Model:    providerInfo.Model,
		// #3424: the ONE AuditEntry producer that has a duration to record. It
		// is the PROVIDER round trip, not an enforcement duration (see the
		// KNOWN SEMANTIC table on sharedaudit.MeasuredLatencyMs), which is why
		// sharedaudit.LatencyEnforcementPredicate excludes plane='llm' from the
		// portal's Avg Latency tile rather than averaging the two together.
		ResponseTime:    providerLatencyPtr(providerInfo.ResponseTimeMs),
		TokensUsed:      tokensPtr,
		Cost:            costPtr,
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

	// LLM-forward path: this is the moment data leaves the deployment, so it is
	// the cross-border write path. Auto-stamp the UU PDP Pasal 56 transfer_basis
	// + data_residency (enterprise only; no-op hook in community). Must run BEFORE
	// enqueue so the stamped fields are visible to the BatchWriter without a race
	// on the shared entry pointer (#2718).
	if stampCrossBorderTransfer != nil {
		stampCrossBorderTransfer(entry, req, providerInfo)
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
//
// This is a POST-forward path: the request already reached the LLM (only the
// response is withheld), so the cross-border transfer completed and is stamped
// like the success path (#2718). providerInfo carries the resolved destination.
//
// KNOWN GAP (#3427 R3): because the forward completed, providerInfo also
// carries the round trip's Provider, Model, TokensUsed and Cost - usage that
// was genuinely spent and then discarded - and this writer records NONE of it.
// The row therefore stores an empty provider and, since #3427, a NULL token
// count and cost rather than the fabricated 0s it used to store. Not closed
// here on purpose: stamping it moves SUM(tokens_used)/SUM(cost) in
// session_summary_handler.go (unfiltered by plane) and the OJK export's
// LLM-call section, and populates model_id on SEBI / EU AI Act decision
// chains. That is a change to reported compliance figures and needs its own
// runtime proof, not a fold into a table-layout fix. What #3427 does fix is
// the CLAIM: nothing now tells a reader that an omitted token count means no
// provider was called.
func (l *AuditLogger) LogBlockedResponse(ctx context.Context, req OrchestratorRequest,
	policyResult *PolicyEvaluationResult, info *RedactionInfo, providerInfo *ProviderInfo) *AuditEntry {
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
	policyDetails = withAppliedPolicyIdentity(policyDetails, policyResult.AppliedPoliciesDetail)
	var redactedFields []string
	if info != nil {
		if info.ValidationError != "" {
			policyDetails["validation_error"] = info.ValidationError
		}
		redactedFields = info.RedactedFields
	}

	entry := &AuditEntry{
		ID:              generateAuditID(),
		RequestID:       req.RequestID,
		Timestamp:       time.Now().UTC(),
		UserID:          req.User.ID,
		UserEmail:       req.User.Email,
		UserRole:        req.User.Role,
		ClientID:        req.Client.ID,
		TenantID:        req.User.TenantID,
		OrgID:           req.Client.OrgID,
		RequestType:     req.RequestType,
		Query:           req.Query,
		QueryHash:       hashQuery(req.Query),
		PolicyDecision:  responseVerdictBlocked,
		PolicyDetails:   policyDetails,
		RedactedFields:  redactedFields,
		ComplianceFlags: l.detectComplianceFlags(req, nil),
		SecurityMetrics: l.calculateSecurityMetrics(req, policyResult),
		DecisionID:      decisionID,
		Plane:           agent.PlaneLLM,
		CorrelationID:   correlationID,
	}

	// Post-forward cross-border stamp (enterprise only; no-op hook in community).
	// Must run BEFORE enqueue to avoid a race on the shared entry pointer (#2718).
	if stampCrossBorderTransfer != nil {
		stampCrossBorderTransfer(entry, req, providerInfo)
	}

	l.enqueueEntry(entry)
	return entry
}

// LogBlockedMedia writes the canonical audit_logs row when the orchestrator
// WITHHOLDS a request because media-governance analysis failed under the
// fail-closed enforcement strategy (#2680). This deny ran BEFORE policy
// evaluation (so there is no PolicyEvaluationResult), yet it is a terminal deny
// the auditor must see — previously it only emitted a log.Printf before the 403,
// leaving no audit row.
//
// The row is canonical like every other plane: verdict "blocked" + plane=media +
// a fresh decision_id + the request's correlation_id (#2597 / #2611), so the
// portal decisions/audit feed and the lineage exporters treat it uniformly. The
// analysis failure reason is preserved (error_message + policy_details) for the
// auditor; it is an operational analyzer error, never media content.
func (l *AuditLogger) LogBlockedMedia(ctx context.Context, req OrchestratorRequest, mediaErr error) *AuditEntry {
	if l == nil {
		return nil
	}

	decisionID := generateDecisionID()
	correlationID := correlationIDFromContext(ctx, req.RequestID)

	reason := ""
	if mediaErr != nil {
		reason = mediaErr.Error()
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
		PolicyDecision: sharedaudit.DecisionBlocked,
		PolicyDetails: map[string]interface{}{
			"decision_id":      decisionID,
			"correlation_id":   correlationID,
			"plane":            agent.PlaneMedia,
			"block_phase":      "media_analysis",
			"enforcement":      "fail_closed",
			"media_item_count": len(req.Media),
			"reason":           reason,
		},
		ErrorMessage:    reason,
		ComplianceFlags: l.detectComplianceFlags(req, nil),
		DecisionID:      decisionID,
		Plane:           agent.PlaneMedia,
		CorrelationID:   correlationID,
	}

	l.enqueueEntry(entry)
	return entry
}

// LogBlockedRequest logs a blocked request
func (l *AuditLogger) LogBlockedRequest(ctx context.Context, req OrchestratorRequest,
	policyResult *PolicyEvaluationResult) {

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
		PolicyDecision: sharedaudit.DecisionBlocked,
		PolicyDetails: withAppliedPolicyIdentity(map[string]interface{}{
			"applied_policies": policyResult.AppliedPolicies,
			"risk_score":       policyResult.RiskScore,
			"required_actions": policyResult.RequiredActions,
			"processing_time":  policyResult.ProcessingTimeMs,
		}, policyResult.AppliedPoliciesDetail),
		ComplianceFlags: l.detectComplianceFlags(req, nil),
		SecurityMetrics: l.calculateSecurityMetrics(req, policyResult),
	}

	l.enqueueEntry(entry)
}

// LogFailedRequest logs a failed request
func (l *AuditLogger) LogFailedRequest(ctx context.Context, req OrchestratorRequest, err error) {
	entry := &AuditEntry{
		ID:              generateAuditID(),
		RequestID:       req.RequestID,
		Timestamp:       time.Now().UTC(),
		UserID:          req.User.ID,
		UserEmail:       req.User.Email,
		UserRole:        req.User.Role,
		ClientID:        req.Client.ID,
		TenantID:        req.User.TenantID,
		OrgID:           req.Client.OrgID,
		RequestType:     req.RequestType,
		Query:           req.Query,
		QueryHash:       hashQuery(req.Query),
		PolicyDecision:  sharedaudit.DecisionError,
		ErrorMessage:    err.Error(),
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
	UserEmail    string // v7.4.1+: reviewer email for step_approved/step_rejected; #3281: also the trust-gated caller email on step_gate, whose verdict is identity-dependent
	UserRole     string // v7.4.1+: reviewer role
	Metadata     map[string]interface{}
}

// workflowAuditDecision maps a workflow-control decision (WorkflowAuditEntry.Decision:
// allow | block | require_approval) onto the canonical audit_logs.policy_decision
// vocabulary (platform/shared/audit, #2638). require_approval → needs_approval —
// NOT the off-set "pending_approval" this writer historically emitted, which is
// neither canonical nor accepted by the migration-123 CHECK (it would have made
// every step_gate row fail to persist once the constraint lands). Any other value
// (the common "allow" + an empty/unknown step decision) maps to allowed, matching
// the pre-existing default.
func workflowAuditDecision(decision string) string {
	switch decision {
	case "block":
		return sharedaudit.DecisionBlocked
	case "require_approval":
		return sharedaudit.DecisionNeedsApproval
	case "error":
		// #2698: a fail-open-on-policy-ERROR gate verdict (HITL) records the
		// errored decision as canonical `error` — it must NEVER fall through to
		// the `allowed` default, which would silently inflate the allowed counts.
		return sharedaudit.DecisionError
	default:
		return sharedaudit.DecisionAllowed
	}
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

	// Map the workflow-control decision onto the canonical audit vocabulary.
	policyDecision := workflowAuditDecision(entry.Decision)

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

	// Map plan status to the canonical audit vocabulary (platform/shared/audit).
	policyDecision := sharedaudit.DecisionAllowed
	if entry.Operation == "failed" {
		policyDecision = sharedaudit.DecisionError
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
	ToolName string `json:"tool_name"`
	// CallerName identifies which client/integration made the call (#2912) —
	// e.g. claude_code, codex, cursor, openclaw. Preferred over the legacy
	// ToolType field below.
	CallerName string `json:"caller_name,omitempty"`
	// ToolType is DEPRECATED (#2912) — it was misnamed for what every real
	// caller actually used it for (client identity, not a tool-kind concept).
	// Kept as a legacy input fallback: a caller that hasn't upgraded to
	// CallerName yet still works. auditToolCallHandler/LogToolCallAudit
	// resolve the fallback chain (CallerName -> ToolType -> "unknown" default,
	// #2903) and stop writing policy_details.tool_type for new rows — only
	// policy_details.caller_name is written going forward.
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
	// UserEmail is the per-developer identity forwarded by the Agent proxy as
	// the X-User-Email header (issue #2754). It is header-sourced, never read
	// from the request body — like TenantID/OrgID/ClientID above — so a caller
	// cannot spoof the attributed user via the JSON payload. Populated by
	// auditToolCallHandler; lands in audit_logs.user_email so the portal User
	// column shows the real developer instead of NULL/N/A.
	UserEmail string `json:"-"`
	// SessionID is the AI-tool session id forwarded via the X-Session-Id header
	// (#2753 addendum, core migration 129). Header-sourced (json:"-") for the
	// same anti-spoofing reason; lands in audit_logs.session_id.
	SessionID string `json:"-"`
}

// LogToolCallAudit logs a non-LLM tool call audit entry
func (l *AuditLogger) LogToolCallAudit(ctx context.Context, entry *ToolCallAuditEntry) *AuditEntry {
	if l == nil {
		return nil
	}

	policyDetails := map[string]interface{}{
		"tool_name": entry.ToolName,
	}
	// #2912: caller_name replaces tool_type going forward. Fallback chain:
	// CallerName if supplied -> legacy ToolType if supplied -> "unknown"
	// default (#2903 — an unidentified caller must not be silently attributed
	// to the specific client "claude_code"). policy_details.tool_type is no
	// longer written for new rows — only policy_details.caller_name.
	callerName := entry.CallerName
	if callerName == "" {
		callerName = entry.ToolType
	}
	if callerName == "" {
		callerName = "unknown"
	}
	policyDetails["caller_name"] = callerName
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

	policyDecision := sharedaudit.DecisionAllowed
	if entry.Success != nil && !*entry.Success {
		policyDecision = sharedaudit.DecisionError
	}

	auditEntry := &AuditEntry{
		ID:        generateAuditID(),
		RequestID: entry.WorkflowID,
		Timestamp: time.Now().UTC(),
		UserID:    0,
		// #2754: was `entry.UserID` — a copy-paste bug that wrote the (always
		// empty) UserID into user_email, producing NULL/N/A in the portal User
		// column. Use the real per-developer email forwarded via X-User-Email.
		UserEmail:      entry.UserEmail,
		SessionID:      entry.SessionID, // #2753: X-Session-Id → audit_logs.session_id
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
			   COALESCE(response_sample, ''), COALESCE(session_id, ''),
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
		//
		// #2922 enforced read scope — FIRST, so it can never be displaced by a
		// caller filter. Exact case-insensitive match on the canonical email
		// (write paths canonicalize via sharedidentity.CanonicalEmail; LOWER()
		// on the column keeps pre-canonicalization historical rows readable by
		// their owner). Deliberately NOT the ILIKE substring filter below —
		// substring matching over-matches sibling identities and is not a
		// security boundary.
		if searchReq.ScopeUserEmail != "" {
			query += fmt.Sprintf(" AND LOWER(user_email) = $%d", argIndex)
			args = append(args, strings.ToLower(searchReq.ScopeUserEmail))
			argIndex++
		}
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
		// session_id drill-down (#2759): lets a client page through a
		// session-summary bucket's raw events by its real session_id, mirroring
		// the decision_id/override_id filters above but against the first-class
		// column rather than a JSONB path.
		if searchReq.SessionID != "" {
			query += fmt.Sprintf(" AND session_id = $%d", argIndex)
			args = append(args, searchReq.SessionID)
			argIndex++
		}
		if searchReq.Action != "" {
			// Canonical-first action filter (#2636/#2653; supersedes PR #2637).
			// Normalize the filter input to its canonical verdict, then expand to
			// every DB spelling that verdict covers (sharedaudit.Spellings) so the
			// filter matches BOTH the canonical value every writer emits today
			// AND any legacy/historical row. This replaces #2637's
			// expandActionValues, which keyed on the frontend's phantom display
			// labels (logged/alerted/modified) and codified the divergence; the
			// portal now sends the canonical verdict directly.
			query += fmt.Sprintf(" AND policy_decision = ANY($%d)", argIndex)
			args = append(args, pq.Array(sharedaudit.Spellings(sharedaudit.Normalize(searchReq.Action))))
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
			&entry.ResponseSample,
			&entry.SessionID,
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
		entry.ResponseTime = nullLatencyPtr(responseTime)
		entry.TokensUsed = nullTokensPtr(tokensUsed)
		entry.Cost = nullCostPtr(cost)

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
		"risk_score":       policyResult.RiskScore,
		"policies_applied": len(policyResult.AppliedPolicies),
		"query_complexity": calculateQueryComplexity(req.Query),
		"sensitive_access": containsSensitiveAccess(req.Query),
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
			decision_id, plane, correlation_id,
			transfer_basis, data_residency, session_id
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24, $25, $26, $27, $28, $29, $30)
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
			// #3424: NULL when this writer had nothing to measure. Only
			// LogSuccessfulRequest populates ResponseTime (from the provider
			// round trip); the seven other AuditEntry producers here -- blocked
			// request / response / media, failed request, workflow, plan and
			// tool-call rows -- leave it nil. Before this change the field was a
			// plain int64 and their zero VALUE was written as a literal 0, which
			// is a claim of a measured zero-millisecond operation and only stayed
			// out of the portal's average by the grace of the reader's `> 0`
			// filter -- a filter #3424 then had to relax so sub-millisecond
			// enforcement decisions stop vanishing. Migration core/161 clears the
			// zeros those writers already stored.
			sharedaudit.LatencyValue(entry.ResponseTime),
			// #3427 M19: nil -> NULL. Bound as pointers so a writer with no
			// provider round trip stores "not applicable" rather than a
			// literal 0 that every reader below is then obliged to believe.
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
			// UU PDP Pasal 56 cross-border fields (#2718). Only the LLM-forward
			// path populates these; every other writer leaves them empty → NULL,
			// so the partial index + the OJK export only pick up declared transfers.
			nullIfEmpty(entry.TransferBasis),
			nullIfEmpty(entry.DataResidency),
			// Per-session identity (#2753, core migration 129). Nullable: writers
			// that don't forward X-Session-Id leave it empty → NULL, so the
			// partial index only picks up rows that carry a session.
			nullIfEmpty(entry.SessionID),
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

// withAppliedPolicyIdentity stamps the shared reader's policy_names key
// (platform/shared/audit/policy_identity.go) onto a blocked-row details map
// from the evaluation-time AppliedPoliciesDetail (#3365). Until this,
// orchestrator LLM-plane blocks carried identity only under applied_policies,
// which NO reader resolves, so freshly-written acted rows rendered the
// pre-9.16.1 placeholder ("Not recorded") on compliance exports and resolved
// nothing in the portal.
//
// policy_ids is deliberately NOT stamped here, unlike the agent-side writers.
// On this plane AppliedPolicyDetail.PolicyID is the dynamic policy's UUID
// (db_dynamic_policies.go sources it from _metadata.id so it joins
// policy_overrides.policy_id), and the shared identity chain resolves
// policy_ids[0] BEFORE policy_names[0]. Stamping the UUID would therefore put
// an opaque "550e8400-..." in the single Policy column of every SEBI / OJK /
// EU-AI-Act export row, trading a false placeholder for an unreadable one.
// Stamping names only lets the identity chain fall to policy_names[0], so the
// export and the portal both render the human-readable policy name the
// evaluation actually matched. Names come exclusively from the
// evaluation-time detail (never a write-time catalog lookup); rows whose
// evaluation produced no structured detail are left unchanged.
func withAppliedPolicyIdentity(details map[string]interface{}, applied []AppliedPolicyDetail) map[string]interface{} {
	if details == nil || len(applied) == 0 {
		return details
	}
	names := make([]string, 0, len(applied))
	seenName := make(map[string]bool, len(applied))
	for _, p := range applied {
		if p.PolicyName == "" || seenName[p.PolicyName] {
			continue
		}
		seenName[p.PolicyName] = true
		names = append(names, p.PolicyName)
	}
	if len(names) == 0 {
		return details
	}
	details["policy_names"] = names
	return details
}
