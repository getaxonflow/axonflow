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

// Package agent provides the AxonFlow Agent service.
//
// This file implements the Static Policies REST API for ADR-018: Unified Policy Management.
// Static policies are pattern-based enforcement rules (PII detection, SQL injection blocking)
// that are stored in the static_policies table and evaluated by the Agent.
//
// The API enables the Customer Portal to display both static (Agent) and dynamic (Orchestrator)
// policies in a unified view.
package agent

import (
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/gorilla/mux"
)

// StaticPolicy represents a static policy from the database
type StaticPolicy struct {
	ID          string          `json:"id"`
	PolicyID    string          `json:"policy_id"`
	Name        string          `json:"name"`
	Category    string          `json:"category"`
	Pattern     string          `json:"pattern"`
	Severity    string          `json:"severity"`
	Description string          `json:"description,omitempty"`
	Action      string          `json:"action"`
	Enabled     bool            `json:"enabled"`
	TenantID    string          `json:"tenant_id"`
	Metadata    json.RawMessage `json:"metadata,omitempty"`
	CreatedAt   time.Time       `json:"created_at"`
	UpdatedAt   time.Time       `json:"updated_at"`
	Version     int             `json:"version"`
}

// StaticPoliciesListResponse is the response for listing static policies
type StaticPoliciesListResponse struct {
	Policies   []StaticPolicy `json:"policies"`
	Pagination PaginationMeta `json:"pagination"`
}

// PaginationMeta contains pagination metadata
type PaginationMeta struct {
	Page       int `json:"page"`
	PageSize   int `json:"page_size"`
	TotalItems int `json:"total_items"`
	TotalPages int `json:"total_pages"`
}

// StaticPolicyAPIHandler handles static policy API requests
type StaticPolicyAPIHandler struct {
	db *sql.DB
}

// NewStaticPolicyAPIHandler creates a new handler for static policy API
func NewStaticPolicyAPIHandler(db *sql.DB) *StaticPolicyAPIHandler {
	return &StaticPolicyAPIHandler{db: db}
}

// RegisterStaticPolicyHandlers registers the static policy API routes
func RegisterStaticPolicyHandlers(router *mux.Router, db *sql.DB) {
	if db == nil {
		log.Println("⚠️ Database not available - Static Policy API disabled")
		return
	}

	handler := NewStaticPolicyAPIHandler(db)

	// GET /api/v1/static-policies - List static policies with filtering and pagination
	router.HandleFunc("/api/v1/static-policies", handler.HandleListStaticPolicies).Methods("GET")

	// GET /api/v1/static-policies/{id} - Get a specific static policy by ID
	router.HandleFunc("/api/v1/static-policies/{id}", handler.HandleGetStaticPolicy).Methods("GET")

	log.Println("✅ Static Policy API routes registered")
}

// HandleListStaticPolicies handles GET /api/v1/static-policies
// Query parameters:
// - page: Page number (default: 1)
// - page_size: Items per page (default: 20, max: 100)
// - category: Filter by category (sql_injection, dangerous_queries, admin_access, pii_detection)
// - severity: Filter by severity (low, medium, high, critical)
// - enabled: Filter by enabled status (true/false)
// Headers:
// - X-Tenant-ID: Tenant ID for filtering (required in SaaS mode)
func (h *StaticPolicyAPIHandler) HandleListStaticPolicies(w http.ResponseWriter, r *http.Request) {
	// Get tenant ID from header
	tenantID := r.Header.Get("X-Tenant-ID")

	// Parse pagination parameters
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}

	pageSize, _ := strconv.Atoi(r.URL.Query().Get("page_size"))
	if pageSize < 1 {
		pageSize = 20
	}
	if pageSize > 100 {
		pageSize = 100
	}

	// Parse filter parameters
	categoryFilter := r.URL.Query().Get("category")
	severityFilter := r.URL.Query().Get("severity")
	enabledFilter := r.URL.Query().Get("enabled")

	// Build query with filters
	query, countQuery, args := h.buildListQuery(tenantID, categoryFilter, severityFilter, enabledFilter, page, pageSize)

	// Get total count first
	var totalItems int
	if err := h.db.QueryRow(countQuery, args[:len(args)-2]...).Scan(&totalItems); err != nil {
		log.Printf("[StaticPolicyAPI] Error counting policies: %v", err)
		writeJSONError(w, "Failed to count policies", http.StatusInternalServerError)
		return
	}

	// Execute query
	rows, err := h.db.Query(query, args...)
	if err != nil {
		log.Printf("[StaticPolicyAPI] Error querying policies: %v", err)
		writeJSONError(w, "Failed to query policies", http.StatusInternalServerError)
		return
	}
	defer func() {
		if closeErr := rows.Close(); closeErr != nil {
			log.Printf("[StaticPolicyAPI] Error closing rows: %v", closeErr)
		}
	}()

	// Collect results
	policies := make([]StaticPolicy, 0)
	for rows.Next() {
		var p StaticPolicy
		var description, metadata sql.NullString
		err := rows.Scan(
			&p.ID, &p.PolicyID, &p.Name, &p.Category, &p.Pattern,
			&p.Severity, &description, &p.Action, &p.Enabled,
			&p.TenantID, &metadata, &p.CreatedAt, &p.UpdatedAt, &p.Version,
		)
		if err != nil {
			log.Printf("[StaticPolicyAPI] Error scanning policy row: %v", err)
			continue
		}

		if description.Valid {
			p.Description = description.String
		}
		if metadata.Valid && metadata.String != "" {
			p.Metadata = json.RawMessage(metadata.String)
		}

		policies = append(policies, p)
	}

	if err := rows.Err(); err != nil {
		log.Printf("[StaticPolicyAPI] Error iterating rows: %v", err)
		writeJSONError(w, "Failed to read policies", http.StatusInternalServerError)
		return
	}

	// Calculate pagination metadata
	totalPages := (totalItems + pageSize - 1) / pageSize

	response := StaticPoliciesListResponse{
		Policies: policies,
		Pagination: PaginationMeta{
			Page:       page,
			PageSize:   pageSize,
			TotalItems: totalItems,
			TotalPages: totalPages,
		},
	}

	log.Printf("[StaticPolicyAPI] Returning %d policies (page %d/%d, tenant: %s)",
		len(policies), page, totalPages, tenantID)

	writeJSONResponse(w, response, http.StatusOK)
}

// HandleGetStaticPolicy handles GET /api/v1/static-policies/{id}
func (h *StaticPolicyAPIHandler) HandleGetStaticPolicy(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	policyID := vars["id"]

	tenantID := r.Header.Get("X-Tenant-ID")

	query := `
		SELECT
			id, policy_id, name, category, pattern, severity,
			description, action, enabled, tenant_id,
			metadata::text, created_at, updated_at, version
		FROM static_policies
		WHERE (policy_id = $1 OR id::text = $1)
		  AND (tenant_id = 'global' OR tenant_id = $2 OR $2 = '')`

	var p StaticPolicy
	var description, metadata sql.NullString
	err := h.db.QueryRow(query, policyID, tenantID).Scan(
		&p.ID, &p.PolicyID, &p.Name, &p.Category, &p.Pattern,
		&p.Severity, &description, &p.Action, &p.Enabled,
		&p.TenantID, &metadata, &p.CreatedAt, &p.UpdatedAt, &p.Version,
	)

	if err == sql.ErrNoRows {
		writeJSONError(w, "Policy not found", http.StatusNotFound)
		return
	}
	if err != nil {
		log.Printf("[StaticPolicyAPI] Error getting policy %s: %v", policyID, err)
		writeJSONError(w, "Failed to get policy", http.StatusInternalServerError)
		return
	}

	if description.Valid {
		p.Description = description.String
	}
	if metadata.Valid && metadata.String != "" {
		p.Metadata = json.RawMessage(metadata.String)
	}

	writeJSONResponse(w, p, http.StatusOK)
}

// buildListQuery builds the SQL query for listing policies with filters
func (h *StaticPolicyAPIHandler) buildListQuery(tenantID, category, severity, enabled string, page, pageSize int) (string, string, []interface{}) {
	baseWhere := "WHERE (tenant_id = 'global' OR tenant_id = $1 OR $1 = '')"
	args := []interface{}{tenantID}
	argNum := 2

	// Add category filter
	if category != "" {
		baseWhere += " AND category = $" + strconv.Itoa(argNum)
		args = append(args, category)
		argNum++
	}

	// Add severity filter
	if severity != "" {
		baseWhere += " AND severity = $" + strconv.Itoa(argNum)
		args = append(args, severity)
		argNum++
	}

	// Add enabled filter
	if enabled != "" {
		enabledBool := enabled == "true"
		baseWhere += " AND enabled = $" + strconv.Itoa(argNum)
		args = append(args, enabledBool)
		argNum++
	}

	// Count query
	countQuery := "SELECT COUNT(*) FROM static_policies " + baseWhere

	// Main query with pagination
	query := `
		SELECT
			id, policy_id, name, category, pattern, severity,
			description, action, enabled, tenant_id,
			metadata::text, created_at, updated_at, version
		FROM static_policies
		` + baseWhere + `
		ORDER BY
			CASE severity
				WHEN 'critical' THEN 1
				WHEN 'high' THEN 2
				WHEN 'medium' THEN 3
				WHEN 'low' THEN 4
			END,
			name ASC
		LIMIT $` + strconv.Itoa(argNum) + ` OFFSET $` + strconv.Itoa(argNum+1)

	offset := (page - 1) * pageSize
	args = append(args, pageSize, offset)

	return query, countQuery, args
}

// writeJSONResponse writes a JSON response with the given status code
func writeJSONResponse(w http.ResponseWriter, data interface{}, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		log.Printf("[StaticPolicyAPI] Error encoding response: %v", err)
	}
}

// writeJSONError writes a JSON error response
func writeJSONError(w http.ResponseWriter, message string, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	response := map[string]interface{}{
		"error": map[string]interface{}{
			"code":    statusCode,
			"message": message,
		},
	}
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Printf("[StaticPolicyAPI] Error encoding error response: %v", err)
	}
}
