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
	"net/http"
	"strings"
	"time"

	"github.com/lib/pq"

	"axonflow/platform/shared/audit"
	logutil "axonflow/platform/shared/logger"
)

// AuditSummaryRequest is the request body for POST /api/v1/audit/summary
type AuditSummaryRequest struct {
	StartTime string `json:"start_time"` // RFC3339
	EndTime   string `json:"end_time"`   // RFC3339
}

// ComplianceSummary is the response for POST /api/v1/audit/summary.
//
// The card-view fields (total_requests / allowed_requests / blocked_requests /
// modified_requests / block_rate_percent / avg_latency_ms) power the
// "Compliance Summary" strip at the top of the audit logs page. They were
// added in v7.4.1 — prior versions only emitted total_events / by_severity /
// by_action / top_policies / compliance_score, which the portal UI did not
// read, producing a visibly all-zero summary even on tenants with heavy
// traffic. The legacy fields are retained so existing API consumers aren't
// broken.
type ComplianceSummary struct {
	// Card-view aggregates (v7.4.1+). Primary contract with the portal UI.
	// total_requests is the sum of the five verdict buckets — allowed + blocked +
	// modified(=redacted) + needs_approval + error — so it always closes against
	// them. It excludes non-verdict override-lifecycle rows (those are routed out
	// of the verdict triage); total_events below still counts every audit row.
	TotalRequests         int     `json:"total_requests"`
	AllowedRequests       int     `json:"allowed_requests"`
	BlockedRequests       int     `json:"blocked_requests"`
	ModifiedRequests      int     `json:"modified_requests"`
	NeedsApprovalRequests int     `json:"needs_approval_requests"`
	ErrorRequests         int     `json:"error_requests"`
	BlockRatePercent      float64 `json:"block_rate_percent"`

	// AvgLatencyMs is the mean enforcement latency over the rows that actually
	// carry a measurement, and is NULL on the wire when there are none (#3424).
	//
	// It used to be a bare float64 fed by COALESCE(AVG(...), 0), which collapsed
	// two different facts onto the same value: "the measured average is zero"
	// and "nothing in this range was measured at all". That is the case the
	// portal rendered as a confident "0ms" on a stack that had just served
	// governed traffic. A pointer makes the absence explicit instead of letting
	// it wear a measurement's costume.
	//
	// The two facts are BOTH reachable now, which is why the pointer is not
	// optional. response_time_ms is BIGINT milliseconds, so a decision faster
	// than that resolution stores the 0 its clock produced, and the query below
	// admits it (the predicate is IS NOT NULL, not `> 0`). A mean below 1.0 --
	// even exactly 0 -- is therefore a real answer, and LatencySampleCount is
	// what tells it apart from an empty range. The portal renders the pair as
	// "<1ms" plus its basis.
	//
	// LatencySampleCount is also how many rows backed the average, so a reader
	// can tell an average over 3 rows from one over 30,000. Older clients that
	// decode avg_latency_ms into a plain float64 are unaffected: encoding/json
	// reads a JSON null onto a float64 as a no-op, leaving the zero value they
	// saw before.
	AvgLatencyMs       *float64 `json:"avg_latency_ms"`
	LatencySampleCount int      `json:"latency_sample_count"`

	// Legacy aggregates retained for backward compatibility.
	TotalEvents int                `json:"total_events"`
	BySeverity  map[string]int     `json:"by_severity"`
	ByAction    map[string]int     `json:"by_action"`
	TopPolicies []PolicyHitSummary `json:"top_policies"`
	// TotalPolicies is how many DISTINCT policies fired in range, before
	// audit.TopPoliciesLimit truncated TopPolicies. Pre-#3426 the aggregation
	// could only see rows carrying the singular policy_name and the limit
	// effectively never bit; a widened reader reaches ten on one busy day, and
	// a list that silently stops at ten reads as the whole set. Zero when
	// nothing fired.
	TotalPolicies int `json:"total_policies"`
	// TopPoliciesUnavailable is true when the top-policies aggregation did not
	// complete (it failed, or it exceeded audit.TopPoliciesTimeout). The rest of
	// the summary is still returned, so without this flag a failed aggregation
	// is INDISTINGUISHABLE from "no policies fired": TopPolicies empty,
	// TotalPolicies 0, and the truncation disclosure computing "nothing hidden".
	// That is a fail-quiet on a compliance surface, which is the same family as
	// the under-reporting defect #3426 fixed. Renderers must say so.
	TopPoliciesUnavailable bool    `json:"top_policies_unavailable,omitempty"`
	ComplianceScore        float64 `json:"compliance_score"`
}

// PolicyHitSummary represents a policy's trigger/block counts in the summary
type PolicyHitSummary struct {
	// PolicyName carries whatever the shared identity chain resolved for this
	// policy, which is IDENTITY-first: a policy id on every row whose writer
	// stamped one, a display name only when it did not.
	//
	// IdentityIsName says which of the two PolicyName is, so a renderer can mark
	// a raw id instead of styling it as a display name. It is a property of the
	// RESOLVED STRING and NOT a claim about the writer: since #3365 a
	// decide-plane row stamps policy_names beside policy_ids, so it records a
	// name AND reports IdentityIsName false. Rendering the row-level
	// POLICY_NAME_NOT_RECORDED_MARKER off this field states a falsehood about
	// such a row (#3438 R3); the neutral POLICY_IDENTIFIER_MARKER is what
	// belongs here.
	PolicyName     string `json:"policy_name"`
	IdentityIsName bool   `json:"identity_is_name"`
	TriggerCount   int    `json:"trigger_count"`
	BlockCount     int    `json:"block_count"`
}

// AuditSummaryHandler handles the audit summary endpoint
type AuditSummaryHandler struct {
	db *sql.DB
}

// NewAuditSummaryHandler creates a new AuditSummaryHandler
func NewAuditSummaryHandler(db *sql.DB) *AuditSummaryHandler {
	return &AuditSummaryHandler{db: db}
}

// HandleSummary handles POST /api/v1/audit/summary
func (h *AuditSummaryHandler) HandleSummary(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Tenant-ID, X-Org-ID")
		w.WriteHeader(http.StatusOK)
		return
	}

	var req AuditSummaryRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendErrorResponse(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	startTime, err := time.Parse(time.RFC3339, req.StartTime)
	if err != nil {
		sendErrorResponse(w, "Invalid start_time: must be RFC3339 format", http.StatusBadRequest)
		return
	}

	endTime, err := time.Parse(time.RFC3339, req.EndTime)
	if err != nil {
		sendErrorResponse(w, "Invalid end_time: must be RFC3339 format", http.StatusBadRequest)
		return
	}

	if !endTime.After(startTime) {
		sendErrorResponse(w, "end_time must be after start_time", http.StatusBadRequest)
		return
	}

	maxRange := 365 * 24 * time.Hour
	if endTime.Sub(startTime) > maxRange {
		sendErrorResponse(w, "Date range must not exceed 1 year", http.StatusBadRequest)
		return
	}

	// Get tenant ID from request headers — require X-Tenant-ID explicitly.
	// The agent's auth middleware always sets this header from the authenticated
	// client's session, so its absence means the request bypassed auth entirely.
	// v6.2.0 removed the X-Org-ID fallback that was a permissive safety net
	// because it's not needed in normal operation and obscures misconfig.
	tenantID := r.Header.Get("X-Tenant-ID")
	if tenantID == "" {
		sendErrorResponse(w, "Missing tenant scope: X-Tenant-ID header required (set by auth middleware)", http.StatusBadRequest)
		return
	}

	// #2922 role-scoped reads: a non-tenant-wide caller's summary aggregates
	// only their own rows. Empty identity ⇒ the zero-events summary
	// (fail-closed; same shape as an empty window).
	//
	// #3060 (#2991 coverage gap): the zero-events summary below is a
	// ComplianceScore:100 "all clear" — the most misleading possible shape for
	// a fail-closed read. Stamp the scope header + log line so it is legible.
	scopeUserEmail := ""
	scope := resolveCallerReadScope(r)
	applyReadScopeHeader(w, r, scope)
	if !scope.TenantWide {
		if scope.UserEmail == "" {
			empty := &ComplianceSummary{
				BySeverity:      map[string]int{},
				ByAction:        map[string]int{},
				TopPolicies:     []PolicyHitSummary{},
				ComplianceScore: 100, // No visible events = fully compliant
			}
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(empty); err != nil {
				log.Printf("[AuditSummary] error encoding response: %v", err)
			}
			return
		}
		scopeUserEmail = scope.UserEmail
	}

	summary, err := h.queryAuditSummary(r.Context(), tenantID, scopeUserEmail, startTime, endTime)
	if err != nil {
		log.Printf("[AuditSummary] query failed for tenant %s: %v", logutil.Sanitize(tenantID), err)
		sendErrorResponse(w, "Failed to generate audit summary", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(summary); err != nil {
		log.Printf("[AuditSummary] error encoding response: %v", err)
	}
}

// queryAuditSummary runs aggregation queries against audit_logs.
//
// scopeUserEmail is the #2922 enforced own-rows read scope (exact canonical
// match on LOWER(user_email)); empty means tenant-wide. A non-admin's
// "policy stats" are the stats of THEIR OWN governed traffic — the tenant-wide
// aggregate reveals other users' activity volumes and block patterns.
func (h *AuditSummaryHandler) queryAuditSummary(ctx context.Context, tenantID, scopeUserEmail string, startTime, endTime time.Time) (*ComplianceSummary, error) {
	if h.db == nil {
		return &ComplianceSummary{
			BySeverity:      map[string]int{},
			ByAction:        map[string]int{},
			TopPolicies:     []PolicyHitSummary{},
			ComplianceScore: 100, // No events = fully compliant
		}, nil
	}

	summary := &ComplianceSummary{
		BySeverity:  map[string]int{},
		ByAction:    map[string]int{},
		TopPolicies: []PolicyHitSummary{},
	}

	// #2922 read-scope fragment shared by all three queries below. Appended
	// after the fixed predicates with an explicit positional arg so the three
	// query literals stay readable; scopeArgs mirrors the base args plus the
	// canonical email when scoped.
	scopeFragment := ""
	baseArgs := []interface{}{tenantID, startTime, endTime}
	if scopeUserEmail != "" {
		scopeFragment = " AND LOWER(user_email) = $4"
		baseArgs = append(baseArgs, strings.ToLower(scopeUserEmail))
	}

	// Query 1: Total events + by action (request_type) + blocked count
	actionQuery := `
		SELECT request_type, policy_decision, COUNT(*) as cnt
		FROM audit_logs
		WHERE tenant_id = $1
		  AND timestamp >= $2
		  AND timestamp <= $3
	` + scopeFragment + `
		GROUP BY request_type, policy_decision
	`

	rows, err := h.db.Query(actionQuery, baseArgs...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	totalEvents := 0  // every audit row in the window (legacy total_events)
	verdictTotal := 0 // verdict rows only — drives total_requests + rates
	allowedCount := 0
	blockedCount := 0
	modifiedCount := 0
	needsApprovalCount := 0
	errorCount := 0
	for rows.Next() {
		var requestType, policyDecision string
		var cnt int
		if err := rows.Scan(&requestType, &policyDecision, &cnt); err != nil {
			return nil, err
		}
		totalEvents += cnt
		if requestType != "" {
			summary.ByAction[requestType] += cnt
		}
		// Triage for the card view, keyed on the canonical verdict from the
		// shared normalizer (audit.Normalize) rather than a hand-maintained
		// switch. This makes every write-path spelling converge — the agent
		// check_policy path records a denied tool call as "deny" while
		// gateway-mode records "blocked"; both normalize to DecisionBlocked, so
		// a real block (e.g. an SSN caught by sys_pii_ssn) can never be silently
		// counted as allowed. Crucially, needs_approval and error are NO LONGER
		// swept into "allowed" by a default arm (the #2636 metric-corruption
		// bug): Normalize fails an UNKNOWN value safe to DecisionError, never to
		// allowed, and each canonical verdict gets its own bucket so
		// total_requests = allowed + blocked + modified + needs_approval + error
		// always closes. Override grant/revoke lifecycle rows
		// (DecisionOverrideLifecycle) are NOT verdicts — they are routed out of
		// the triage entirely (still counted in total_events / by_action above,
		// but excluded from total_requests and the block-rate so a lifecycle
		// event can never move a compliance metric).
		switch audit.Normalize(policyDecision) {
		case audit.DecisionOverrideLifecycle:
			continue
		case audit.DecisionBlocked:
			blockedCount += cnt
			summary.BySeverity["critical"] += cnt
		case audit.DecisionRedacted:
			modifiedCount += cnt
			summary.BySeverity["warning"] += cnt
		case audit.DecisionNeedsApproval:
			needsApprovalCount += cnt
			summary.BySeverity["info"] += cnt
		case audit.DecisionError:
			errorCount += cnt
			summary.BySeverity["warning"] += cnt
		default: // DecisionAllowed
			allowedCount += cnt
			summary.BySeverity["info"] += cnt
		}
		verdictTotal += cnt
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	summary.TotalEvents = totalEvents
	summary.TotalRequests = verdictTotal
	summary.AllowedRequests = allowedCount
	summary.BlockedRequests = blockedCount
	summary.ModifiedRequests = modifiedCount
	summary.NeedsApprovalRequests = needsApprovalCount
	summary.ErrorRequests = errorCount

	// Compliance score + block rate are ratios over the verdict total (override
	// lifecycle rows excluded), so a burst of override events can't dilute them.
	if verdictTotal > 0 {
		summary.ComplianceScore = float64(verdictTotal-blockedCount) / float64(verdictTotal) * 100
		summary.BlockRatePercent = float64(blockedCount) / float64(verdictTotal) * 100
	} else {
		summary.ComplianceScore = 100 // No verdict events = fully compliant
		summary.BlockRatePercent = 0
	}

	// Query 2a: average response time. Separate query because we need AVG
	// not COUNT, and we want to skip the rows that carry no measured latency
	// (HITL approvals, workflow lifecycle events).
	//
	// #3424: no COALESCE. AVG over an empty set is SQL NULL, which is the
	// truthful answer to "what was the average latency" when nothing was
	// measured, and COUNT(*) under the same predicate reports how many rows
	// backed it. Coalescing to 0 here is what turned a missing measurement
	// into an authoritative-looking zero on the portal's Avg Latency tile.
	// One predicate governs both, so the average and the sample count can
	// never disagree about which rows they cover.
	//
	// The predicate is LatencyEnforcementPredicate, not the bare measured one:
	// this tile is the ENFORCEMENT number an operator reads next to the block
	// rate, so provider-round-trip rows (plane='llm') are excluded rather than
	// averaged in with it, and override-lifecycle rows are excluded because
	// total_requests above already routes them out of the verdict triage --
	// without that, latency_sample_count could exceed the total the tile
	// reports it as a fraction of.
	latencyQuery := `
		SELECT AVG(response_time_ms), COUNT(*)
		FROM audit_logs
		WHERE tenant_id = $1
		  AND timestamp >= $2
		  AND timestamp <= $3
		  AND ` + audit.LatencyEnforcementPredicate + `
	` + scopeFragment
	var avgLatency sql.NullFloat64
	var latencySamples int
	if err := h.db.QueryRow(latencyQuery, baseArgs...).Scan(&avgLatency, &latencySamples); err != nil {
		// Non-fatal: leave avg_latency_ms absent (NULL) and log. A failed
		// query is "unknown", which is what a null already communicates.
		log.Printf("[AuditSummary] latency query failed: %v", err)
	} else if avgLatency.Valid {
		avg := avgLatency.Float64
		summary.AvgLatencyMs = &avg
		summary.LatencySampleCount = latencySamples
	}

	// Query 2: Top policies by trigger count
	// block_count counts the blocking verdicts via audit.Spellings(DecisionBlocked)
	// -- every DB spelling that normalizes to "blocked" (blocked/block/deny/denied)
	// -- rather than a hardcoded IN list that can drift from the shared vocabulary.
	// The blocked-spellings array lands after the (possibly scoped) base args,
	// so its placeholder is positional on len(baseArgs)+1 -- $4 tenant-wide,
	// $5 under the #2922 scope.
	//
	// #3426: the query text itself now comes from audit.TopPoliciesQuery, shared
	// with the Compliance Report export (ReportByAction). Both surfaces used to
	// carry a hand-copied duplicate that grouped on the SINGULAR
	// policy_details->>'policy_name' and filtered it IS NOT NULL, which dropped
	// every decide-plane / MCP / FinCrime-seam row (they stamp the plural
	// policy_names array and policy_ids) BEFORE grouping. See top_policies.go.
	spellingsPos := fmt.Sprintf("$%d", len(baseArgs)+1)
	policyQuery := audit.TopPoliciesQuery(`
		tenant_id = $1
		  AND timestamp >= $2
		  AND timestamp <= $3
	`+scopeFragment, spellingsPos)

	policyArgs := append(append([]interface{}{}, baseArgs...), pq.Array(audit.Spellings(audit.DecisionBlocked)))

	// BOUNDED. The aggregation is linear in in-scope rows (~2.9us each, measured
	// on PG 16.14) and the range cap above is 365 DAYS, so a single-tenant
	// self-hosted stack with three million in-scope rows takes ~8.5s. Unbounded,
	// that holds a pool connection for the whole time on a tile that is not on
	// the critical path. See audit.TopPoliciesTimeout.
	policyCtx, cancelPolicy := context.WithTimeout(ctx, audit.TopPoliciesTimeout)
	defer cancelPolicy()

	// LEGIBLE ON FAILURE. This block stays non-fatal - the rest of the summary
	// is real and worth returning - but "non-fatal" previously meant returning
	// an EMPTY TopPolicies with TotalPolicies 0, which the tile renders as
	// "no policies fired" and the truncation disclosure reads as "nothing
	// hidden". A compliance surface must not report a failed read as a clean
	// zero, so every exit that did not complete the aggregation sets the flag.
	policyRows, err := h.db.QueryContext(policyCtx, policyQuery, policyArgs...)
	if err != nil {
		log.Printf("[AuditSummary] policy query failed: %v", err)
		summary.TopPoliciesUnavailable = true
		return summary, nil
	}
	defer policyRows.Close()

	scanFailed := false
	for policyRows.Next() {
		var entry PolicyHitSummary
		// total_policies is a window over the grouped rows, so it is the same
		// value on every row; read it into the response once. It is the count
		// BEFORE TopPoliciesLimit truncated, which is the only way the tile can
		// say "top 5 of 37" instead of implying 37 does not exist.
		var totalPolicies int
		if err := policyRows.Scan(&entry.PolicyName, &entry.IdentityIsName,
			&entry.TriggerCount, &entry.BlockCount, &totalPolicies); err != nil {
			log.Printf("[AuditSummary] error scanning policy row: %v", err)
			// A dropped row makes TotalPolicies disagree with what is rendered,
			// so the set on screen is no longer the set the server computed.
			scanFailed = true
			continue
		}
		summary.TopPolicies = append(summary.TopPolicies, entry)
		summary.TotalPolicies = totalPolicies
	}
	// The deadline can surface on EITHER path and both are handled. Measured on
	// a 3M-row single-tenant corpus with a 2s deadline against an ~8.5s query,
	// it came back on QueryContext as `pq: canceling statement due to user
	// request` at 2.00s with zero backends left running (pg_stat_activity,
	// excluding the probe's own pid); a cancellation that lands after the first
	// row has streamed surfaces here instead. Checking only one of the two would
	// report a TIMED-OUT aggregation as a complete empty one.
	if err := policyRows.Err(); err != nil {
		log.Printf("[AuditSummary] policy rows iteration error: %v", err)
		summary.TopPoliciesUnavailable = true
	} else if scanFailed {
		summary.TopPoliciesUnavailable = true
	}

	return summary, nil
}
