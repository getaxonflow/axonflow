// Copyright 2026 AxonFlow
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
	"encoding/csv"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"axonflow/platform/agent/license"

	"github.com/gorilla/mux"
)

// MediaGovernanceAuditHandler handles media-specific audit export endpoints (Enterprise only).
type MediaGovernanceAuditHandler struct {
	db             *sql.DB
	licenseChecker LicenseChecker
}

// NewMediaGovernanceAuditHandler creates a new audit export handler.
func NewMediaGovernanceAuditHandler(db *sql.DB, lc LicenseChecker) *MediaGovernanceAuditHandler {
	return &MediaGovernanceAuditHandler{
		db:             db,
		licenseChecker: lc,
	}
}

// RegisterRoutes registers audit export routes.
func (h *MediaGovernanceAuditHandler) RegisterRoutes(r *mux.Router) {
	r.HandleFunc("/api/v1/media-governance/audit/export", h.handleExport).Methods("GET", "OPTIONS")
}

// MediaAuditRecord represents a single media governance audit entry.
type MediaAuditRecord struct {
	RequestID       string                 `json:"request_id"`
	TenantID        string                 `json:"tenant_id"`
	Timestamp       time.Time              `json:"timestamp"`
	MediaType       string                 `json:"media_type"`
	AnalysisResults map[string]interface{} `json:"analysis_results"`
	PolicyActions   []string               `json:"policy_actions"`
	Blocked         bool                   `json:"blocked"`
}

func (h *MediaGovernanceAuditHandler) handleExport(w http.ResponseWriter, r *http.Request) {
	if r.Method == "OPTIONS" {
		h.handleCORS(w, r)
		return
	}

	// Enterprise only
	tier := h.licenseChecker.Tier()
	if !license.IsPaidTier(tier) {
		h.writeError(w, http.StatusForbidden, "ENTERPRISE_REQUIRED",
			"Media governance audit export requires Enterprise license")
		return
	}

	// Parse query params
	tenantID := r.Header.Get("X-Tenant-ID")
	if tenantID == "" {
		h.writeError(w, http.StatusBadRequest, "MISSING_TENANT_ID", "X-Tenant-ID header is required")
		return
	}

	fromStr := r.URL.Query().Get("from")
	toStr := r.URL.Query().Get("to")
	format := r.URL.Query().Get("format")
	if format == "" {
		format = "json"
	}

	if format != "json" && format != "csv" {
		h.writeError(w, http.StatusBadRequest, "INVALID_FORMAT", "Format must be 'json' or 'csv'")
		return
	}

	// Parse time range
	var fromTime, toTime time.Time
	var err error
	if fromStr != "" {
		fromTime, err = time.Parse(time.RFC3339, fromStr)
		if err != nil {
			h.writeError(w, http.StatusBadRequest, "INVALID_FROM", "Invalid 'from' timestamp (use RFC3339)")
			return
		}
	} else {
		fromTime = time.Now().AddDate(0, 0, -7) // Default: last 7 days
	}
	if toStr != "" {
		toTime, err = time.Parse(time.RFC3339, toStr)
		if err != nil {
			h.writeError(w, http.StatusBadRequest, "INVALID_TO", "Invalid 'to' timestamp (use RFC3339)")
			return
		}
	} else {
		toTime = time.Now()
	}

	// Query audit records
	records, err := h.queryMediaAuditRecords(r.Context(), tenantID, fromTime, toTime)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "QUERY_ERROR", "Failed to query audit records")
		return
	}

	if format == "csv" {
		safeTenantID := strings.Map(func(r rune) rune {
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
				return r
			}
			return '_'
		}, tenantID)
		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition",
			fmt.Sprintf("attachment; filename=media-audit-%s-%s.csv", safeTenantID, time.Now().Format("20060102")))
		h.writeCSV(w, records)
	} else {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]interface{}{
			"records":   records,
			"tenant_id": tenantID,
			"from":      fromTime,
			"to":        toTime,
			"count":     len(records),
		}); err != nil {
			log.Printf("[MediaGovernanceAudit] Error encoding JSON response: %v", err)
		}
	}
}

func (h *MediaGovernanceAuditHandler) queryMediaAuditRecords(ctx context.Context, tenantID string, from, to time.Time) ([]MediaAuditRecord, error) {
	query := `
		SELECT request_id, tenant_id, timestamp,
			COALESCE(policy_details->>'media_type', 'image') as media_type,
			COALESCE(policy_details->'analysis_results', '{}') as analysis_results,
			COALESCE(policy_details->'policy_actions', '[]') as policy_actions,
			COALESCE((policy_details->>'blocked')::boolean, false) as blocked
		FROM audit_logs
		WHERE tenant_id = $1
			AND timestamp >= $2
			AND timestamp <= $3
			AND policy_details ? 'media_type'
		ORDER BY timestamp DESC
		LIMIT 10000
	`

	rows, err := h.db.QueryContext(ctx, query, tenantID, from, to)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var records []MediaAuditRecord
	for rows.Next() {
		var rec MediaAuditRecord
		var analysisJSON, actionsJSON []byte
		if err := rows.Scan(&rec.RequestID, &rec.TenantID, &rec.Timestamp,
			&rec.MediaType, &analysisJSON, &actionsJSON, &rec.Blocked); err != nil {
			return nil, err
		}
		if len(analysisJSON) > 0 {
			if err := json.Unmarshal(analysisJSON, &rec.AnalysisResults); err != nil {
				log.Printf("[MediaGovernanceAudit] Warning: failed to unmarshal analysis results: %v", err)
			}
		}
		if len(actionsJSON) > 0 {
			if err := json.Unmarshal(actionsJSON, &rec.PolicyActions); err != nil {
				log.Printf("[MediaGovernanceAudit] Warning: failed to unmarshal policy actions: %v", err)
			}
		}
		records = append(records, rec)
	}

	return records, rows.Err()
}

func (h *MediaGovernanceAuditHandler) writeCSV(w http.ResponseWriter, records []MediaAuditRecord) {
	writer := csv.NewWriter(w)
	defer writer.Flush()

	_ = writer.Write([]string{"request_id", "tenant_id", "timestamp", "media_type", "blocked", "policy_actions"})
	for _, rec := range records {
		actionsStr := ""
		if len(rec.PolicyActions) > 0 {
			actionsJSON, _ := json.Marshal(rec.PolicyActions)
			actionsStr = string(actionsJSON)
		}
		_ = writer.Write([]string{
			rec.RequestID,
			rec.TenantID,
			rec.Timestamp.Format(time.RFC3339),
			rec.MediaType,
			fmt.Sprintf("%v", rec.Blocked),
			actionsStr,
		})
	}
}

func (h *MediaGovernanceAuditHandler) handleCORS(w http.ResponseWriter, r *http.Request) {
	origin := r.Header.Get("Origin")
	if origin != "" && allowedOrigins[origin] {
		w.Header().Set("Access-Control-Allow-Origin", origin)
	}
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Tenant-ID")
	w.Header().Set("Access-Control-Max-Age", "86400")
	w.WriteHeader(http.StatusOK)
}

func (h *MediaGovernanceAuditHandler) writeError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(map[string]interface{}{
		"error": map[string]string{
			"code":    code,
			"message": message,
		},
	}); err != nil {
		log.Printf("[MediaGovernanceAudit] Error encoding error response: %v", err)
	}
}
