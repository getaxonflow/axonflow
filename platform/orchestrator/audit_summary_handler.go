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
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"time"

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
	TotalRequests    int     `json:"total_requests"`
	AllowedRequests  int     `json:"allowed_requests"`
	BlockedRequests  int     `json:"blocked_requests"`
	ModifiedRequests int     `json:"modified_requests"`
	BlockRatePercent float64 `json:"block_rate_percent"`
	AvgLatencyMs     float64 `json:"avg_latency_ms"`

	// Legacy aggregates retained for backward compatibility.
	TotalEvents     int                `json:"total_events"`
	BySeverity      map[string]int     `json:"by_severity"`
	ByAction        map[string]int     `json:"by_action"`
	TopPolicies     []PolicyHitSummary `json:"top_policies"`
	ComplianceScore float64            `json:"compliance_score"`
}

// PolicyHitSummary represents a policy's trigger/block counts in the summary
type PolicyHitSummary struct {
	PolicyName   string `json:"policy_name"`
	TriggerCount int    `json:"trigger_count"`
	BlockCount   int    `json:"block_count"`
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

	summary, err := h.queryAuditSummary(tenantID, startTime, endTime)
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

// queryAuditSummary runs aggregation queries against audit_logs
func (h *AuditSummaryHandler) queryAuditSummary(tenantID string, startTime, endTime time.Time) (*ComplianceSummary, error) {
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

	// Query 1: Total events + by action (request_type) + blocked count
	actionQuery := `
		SELECT request_type, policy_decision, COUNT(*) as cnt
		FROM audit_logs
		WHERE tenant_id = $1
		  AND timestamp >= $2
		  AND timestamp <= $3
		GROUP BY request_type, policy_decision
	`

	rows, err := h.db.Query(actionQuery, tenantID, startTime, endTime)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	totalEvents := 0
	allowedCount := 0
	blockedCount := 0
	modifiedCount := 0
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
		// Triage for the card view. Two explicit blocking categories
		// (`blocked`, `redacted=modified`); everything else rolls into
		// "allowed" so Total = Allowed + Blocked + Modified always closes.
		// `pending_approval` (emitted when workflow_step_gate fires
		// require_approval) and `error` are "not blocked" outcomes — the
		// HITL decision that follows writes its own workflow_step_approved /
		// workflow_step_rejected row. Unknown values also fall through to
		// allowed; we err on the side of not inflating the blocked count.
		switch policyDecision {
		case "blocked":
			blockedCount += cnt
			summary.BySeverity["critical"] += cnt
		case "redacted":
			modifiedCount += cnt
			summary.BySeverity["warning"] += cnt
		default:
			allowedCount += cnt
			summary.BySeverity["info"] += cnt
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	summary.TotalEvents = totalEvents
	summary.TotalRequests = totalEvents
	summary.AllowedRequests = allowedCount
	summary.BlockedRequests = blockedCount
	summary.ModifiedRequests = modifiedCount

	// Compliance score: ratio of non-blocked events
	if totalEvents > 0 {
		summary.ComplianceScore = float64(totalEvents-blockedCount) / float64(totalEvents) * 100
		summary.BlockRatePercent = float64(blockedCount) / float64(totalEvents) * 100
	} else {
		summary.ComplianceScore = 100 // No events = fully compliant
		summary.BlockRatePercent = 0
	}

	// Query 2a: average response time. Separate query because we need AVG
	// not COUNT, and we want to skip NULL / zero values that represent
	// events with no measured latency (HITL approvals, workflow lifecycle
	// events). COALESCE guards empty result sets.
	latencyQuery := `
		SELECT COALESCE(AVG(response_time_ms), 0)
		FROM audit_logs
		WHERE tenant_id = $1
		  AND timestamp >= $2
		  AND timestamp <= $3
		  AND response_time_ms IS NOT NULL
		  AND response_time_ms > 0
	`
	var avgLatency sql.NullFloat64
	if err := h.db.QueryRow(latencyQuery, tenantID, startTime, endTime).Scan(&avgLatency); err != nil {
		// Non-fatal: leave avg_latency_ms at zero and log.
		log.Printf("[AuditSummary] latency query failed: %v", err)
	} else if avgLatency.Valid {
		summary.AvgLatencyMs = avgLatency.Float64
	}

	// Query 2: Top policies by trigger count
	policyQuery := `
		SELECT
			COALESCE(policy_details->>'policy_name', 'unknown') as policy_name,
			COUNT(*) as trigger_count,
			COUNT(*) FILTER (WHERE policy_decision = 'blocked') as block_count
		FROM audit_logs
		WHERE tenant_id = $1
		  AND timestamp >= $2
		  AND timestamp <= $3
		  AND policy_details IS NOT NULL
		  AND policy_details->>'policy_name' IS NOT NULL
		GROUP BY policy_details->>'policy_name'
		ORDER BY trigger_count DESC
		LIMIT 10
	`

	policyRows, err := h.db.Query(policyQuery, tenantID, startTime, endTime)
	if err != nil {
		// Non-fatal: log and return partial results
		log.Printf("[AuditSummary] policy query failed: %v", err)
		return summary, nil
	}
	defer policyRows.Close()

	for policyRows.Next() {
		var entry PolicyHitSummary
		if err := policyRows.Scan(&entry.PolicyName, &entry.TriggerCount, &entry.BlockCount); err != nil {
			log.Printf("[AuditSummary] error scanning policy row: %v", err)
			continue
		}
		summary.TopPolicies = append(summary.TopPolicies, entry)
	}
	if err := policyRows.Err(); err != nil {
		log.Printf("[AuditSummary] policy rows iteration error: %v", err)
	}

	return summary, nil
}
