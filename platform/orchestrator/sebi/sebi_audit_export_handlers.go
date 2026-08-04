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

//go:build enterprise

package sebi

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"axonflow/platform/orchestrator/compliancereport/renderer"
	logutil "axonflow/platform/shared/logger"
)

// SEBIAuditExportHandler handles HTTP requests for SEBI audit export operations.
// This is an Enterprise-only feature for Indian regulatory compliance.
type SEBIAuditExportHandler struct {
	service SEBIAuditExportService
}

// NewSEBIAuditExportHandler creates a new SEBI audit export handler
func NewSEBIAuditExportHandler(service SEBIAuditExportService) *SEBIAuditExportHandler {
	return &SEBIAuditExportHandler{service: service}
}

// RegisterRoutes registers SEBI audit export routes with the provided mux.
// All routes are prefixed with /api/v1/sebi/audit.
//
// Endpoints:
//   - POST /api/v1/sebi/audit/export - Export audit data for SEBI compliance
//   - GET  /api/v1/sebi/audit/export/{id} - Get status of an async export
//   - GET  /api/v1/sebi/audit/retention - Get retention status for audit data
//   - GET  /api/v1/sebi/audit/readiness - Check compliance readiness
func (h *SEBIAuditExportHandler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/v1/sebi/audit/export", h.handleExport)
	mux.HandleFunc("/api/v1/sebi/audit/export/", h.handleExportByID)
	mux.HandleFunc("/api/v1/sebi/audit/retention", h.handleRetentionStatus)
	mux.HandleFunc("/api/v1/sebi/audit/readiness", h.handleComplianceReadiness)
}

// maxExportRequestBodySize limits request body to 1MB
const maxExportRequestBodySize = 1 << 20 // 1MB

// handleExport handles POST /api/v1/sebi/audit/export
func (h *SEBIAuditExportHandler) handleExport(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		h.exportAuditData(w, r)
	case http.MethodOptions:
		h.handleCORS(w, r)
	default:
		h.writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Method not allowed")
	}
}

// handleExportByID handles GET /api/v1/sebi/audit/export/{id}
func (h *SEBIAuditExportHandler) handleExportByID(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.getExportStatus(w, r)
	case http.MethodOptions:
		h.handleCORS(w, r)
	default:
		h.writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Method not allowed")
	}
}

// handleRetentionStatus handles GET /api/v1/sebi/audit/retention
func (h *SEBIAuditExportHandler) handleRetentionStatus(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.getRetentionStatus(w, r)
	case http.MethodOptions:
		h.handleCORS(w, r)
	default:
		h.writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Method not allowed")
	}
}

// handleComplianceReadiness handles GET /api/v1/sebi/audit/readiness
func (h *SEBIAuditExportHandler) handleComplianceReadiness(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.getComplianceReadiness(w, r)
	case http.MethodOptions:
		h.handleCORS(w, r)
	default:
		h.writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Method not allowed")
	}
}

// exportAuditData handles POST /api/v1/sebi/audit/export
// This endpoint exports audit data for SEBI regulatory compliance.
//
// Request body:
//
//	{
//	  "start_date": "2024-01-01T00:00:00Z",
//	  "end_date": "2024-12-31T23:59:59Z",
//	  "data_types": ["policy_violations", "llm_calls"],
//	  "format": "json",
//	  "framework": "SEBI_AI_ML",
//	  "include_archived": false,
//	  "redact_pii": true
//	}
//
// Response:
//
//	{
//	  "export_id": "exp_123",
//	  "status": "completed",
//	  "summary": { ... },
//	  "data": { ... }
//	}
func (h *SEBIAuditExportHandler) exportAuditData(w http.ResponseWriter, r *http.Request) {
	tenantID := h.getTenantID(r)
	if tenantID == "" {
		h.writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "Missing tenant ID")
		return
	}

	// Limit request body size
	r.Body = http.MaxBytesReader(w, r.Body, maxExportRequestBodySize)

	var req SEBIAuditExportRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, "INVALID_JSON", "Invalid JSON body")
		return
	}

	// Validate request
	if err := h.validateExportRequest(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, "VALIDATION_ERROR", logutil.Sanitize(err.Error()))
		return
	}

	// Set defaults
	if req.Format == "" {
		req.Format = SEBIFormatJSON
	}
	if req.Framework == "" {
		req.Framework = SEBIFrameworkAIML
	}
	if len(req.DataTypes) == 0 {
		req.DataTypes = []SEBIAuditDataType{SEBIDataTypeAll}
	}

	// Export audit data
	response, err := h.service.ExportAuditData(r.Context(), tenantID, &req)
	if err != nil {
		log.Printf("[SEBIAudit] ExportAuditData error for tenant %s: %v", logutil.Sanitize(tenantID), err)
		h.writeError(w, http.StatusInternalServerError, "EXPORT_FAILED", "Failed to export audit data")
		return
	}

	// Emit the artifact in the requested format (#3241, epic #2892).
	//
	// This block used to set a text/csv or application/xml Content-Type and
	// then call writeJSON: every "CSV" and "XML" export was a JSON body under a
	// lying header. A spreadsheet cannot open it and an XML parser rejects it,
	// so both formats were unusable while appearing to work.
	switch req.Format {
	case SEBIFormatCSV:
		payload, renderErr := renderer.NewCSV().Render(buildAuditExportReport(tenantID, &req, response))
		if renderErr != nil {
			log.Printf("[SEBIAudit] CSV render error for tenant %s: %v", logutil.Sanitize(tenantID), renderErr)
			h.writeError(w, http.StatusInternalServerError, "RENDER_FAILED", "Failed to render the CSV export")
			return
		}
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", "attachment; filename=sebi-audit-export.csv")
		w.WriteHeader(http.StatusOK)
		if _, writeErr := w.Write(payload); writeErr != nil {
			log.Printf("[SEBIAudit] CSV write error for tenant %s: %v", logutil.Sanitize(tenantID), writeErr)
		}
	case SEBIFormatXML:
		// HONEST 501 rather than JSON under an application/xml header.
		//
		// BEHAVIOR CHANGE, called out for the release train's semver decision:
		// callers that requested format=xml previously received HTTP 200 with a
		// JSON body. They now receive 501. Nothing could have been consuming the
		// old response AS XML - it never was XML - so this removes a capability
		// that never existed, but it is a status-code change on a public
		// surface and is flagged as such rather than slipped in.
		//
		// XML is not implemented rather than emitted best-effort because there
		// is no SEBI-published schema to target; inventing one would produce a
		// document that looks authoritative and matches nothing.
		h.writeError(w, http.StatusNotImplemented, "XML_NOT_IMPLEMENTED",
			"XML rendering is not implemented for SEBI audit exports. Use format=json or format=csv; "+
				"for a formatted regulatory artifact use POST /api/v1/compliance/reports with regulator=sebi.")
	default:
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", "attachment; filename=sebi-audit-export.json")
		h.writeJSON(w, http.StatusOK, response)
	}
}

// getExportStatus handles GET /api/v1/sebi/audit/export/{id}
//
// # This route has no backing store, and says so (#3246(b))
//
// It queried `sebi_audit_exports`, a table NO migration creates - grep the
// whole migrations/ tree and it does not appear once - and which nothing in the
// codebase ever writes to. So every call returned
//
//	500 INTERNAL_ERROR
//	pq: relation "sebi_audit_exports" does not exist
//
// on every deployment, always. It survived because the only tests were sqlmock
// tests: the mock supplied rows for a table that does not exist, so the suite
// certified the behaviour of a query that can never run.
//
// WHY NOT MIGRATION enterprise/139 (which was reserved for this)
//
// Creating the table would fix the error message and nothing else. SEBI audit
// export is SYNCHRONOUS - ExportAuditData collects and returns the data inline,
// there is no job record, no worker, and no code anywhere that would ever
// INSERT a row. A new table would therefore be empty forever, and this endpoint
// would return a permanent, confident "Export not found" for every id a caller
// ever presents. That is a worse failure than the current one: it looks like an
// answer.
//
// Building async SEBI exports is a feature, not a defect fix, and it is not in
// this PR's scope. So the endpoint now states its actual status, with the route
// that does do this job. Same treatment, and same reasoning, as the XML branch
// above.
//
// A caller cannot be relying on the old behaviour: the old behaviour was a 500.
func (h *SEBIAuditExportHandler) getExportStatus(w http.ResponseWriter, r *http.Request) {
	tenantID := h.getTenantID(r)
	if tenantID == "" {
		h.writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "Missing tenant ID")
		return
	}

	// Extract export ID from URL
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/sebi/audit/export/")
	exportID := strings.TrimSuffix(path, "/")
	if exportID == "" {
		h.writeError(w, http.StatusBadRequest, "BAD_REQUEST", "Export ID is required")
		return
	}

	h.writeError(w, http.StatusNotImplemented, "ASYNC_EXPORT_NOT_IMPLEMENTED",
		"SEBI audit export is synchronous: POST /api/v1/sebi/audit/export returns the data in the "+
			"response, so there is no export job to poll and no status to report. "+
			"For an asynchronous, downloadable regulatory artifact use "+
			"POST /api/v1/compliance/reports with regulator=sebi, then poll "+
			"GET /api/v1/compliance/reports/{id}.")
}

// getRetentionStatus handles GET /api/v1/sebi/audit/retention
// Returns the retention status for audit data, including compliance status.
//
// Query parameters:
//   - data_types: comma-separated list of data types to check (optional)
//
// Response:
//
//	{
//	  "tenant_id": "travel-us",
//	  "framework": "SEBI_AI_ML",
//	  "status": [...],
//	  "compliance_status": "COMPLIANT"
//	}
func (h *SEBIAuditExportHandler) getRetentionStatus(w http.ResponseWriter, r *http.Request) {
	tenantID := h.getTenantID(r)
	if tenantID == "" {
		h.writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "Missing tenant ID")
		return
	}

	// Parse query parameters
	var req SEBIRetentionStatusRequest
	if dataTypesStr := r.URL.Query().Get("data_types"); dataTypesStr != "" {
		dataTypes := strings.Split(dataTypesStr, ",")
		for _, dt := range dataTypes {
			req.DataTypes = append(req.DataTypes, SEBIAuditDataType(strings.TrimSpace(dt)))
		}
	}

	response, err := h.service.GetRetentionStatus(r.Context(), tenantID, &req)
	if err != nil {
		log.Printf("[SEBIAudit] GetRetentionStatus error for tenant %s: %v", logutil.Sanitize(tenantID), err)
		h.writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to get retention status")
		return
	}

	h.writeJSON(w, http.StatusOK, response)
}

// getComplianceReadiness handles GET /api/v1/sebi/audit/readiness
// Validates that the organization is ready for a SEBI audit.
//
// Response:
//
//	{
//	  "ready": true,
//	  "score": 95,
//	  "checks": [...],
//	  "recommendations": [...]
//	}
func (h *SEBIAuditExportHandler) getComplianceReadiness(w http.ResponseWriter, r *http.Request) {
	tenantID := h.getTenantID(r)
	if tenantID == "" {
		h.writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "Missing tenant ID")
		return
	}

	response, err := h.service.ValidateComplianceReadiness(r.Context(), tenantID)
	if err != nil {
		log.Printf("[SEBIAudit] ValidateComplianceReadiness error for tenant %s: %v", logutil.Sanitize(tenantID), err)
		h.writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to validate compliance readiness")
		return
	}

	h.writeJSON(w, http.StatusOK, response)
}

// validateExportRequest validates the export request
func (h *SEBIAuditExportHandler) validateExportRequest(req *SEBIAuditExportRequest) error {
	// Validate date range
	if req.StartDate.IsZero() {
		return &ValidationError{Errors: []PolicyFieldError{{Field: "start_date", Message: "Start date is required"}}}
	}
	if req.EndDate.IsZero() {
		return &ValidationError{Errors: []PolicyFieldError{{Field: "end_date", Message: "End date is required"}}}
	}
	if req.EndDate.Before(req.StartDate) {
		return &ValidationError{Errors: []PolicyFieldError{{Field: "end_date", Message: "End date must be after start date"}}}
	}

	// Validate date range is not more than 5 years (SEBI retention period)
	maxRange := 5 * 365 * 24 * time.Hour // 5 years
	if req.EndDate.Sub(req.StartDate) > maxRange {
		return &ValidationError{Errors: []PolicyFieldError{{Field: "date_range", Message: "Date range cannot exceed 5 years"}}}
	}

	// Validate format
	if req.Format != "" {
		validFormats := map[SEBIExportFormat]bool{
			SEBIFormatJSON: true,
			SEBIFormatCSV:  true,
			SEBIFormatXML:  true,
		}
		if !validFormats[req.Format] {
			return &ValidationError{Errors: []PolicyFieldError{{Field: "format", Message: "Invalid format. Must be json, csv, or xml"}}}
		}
	}

	// Validate framework
	if req.Framework != "" {
		validFrameworks := map[SEBIComplianceFramework]bool{
			SEBIFrameworkAIML:     true,
			SEBIFrameworkDPDP:     true,
			SEBIFrameworkCombined: true,
		}
		if !validFrameworks[req.Framework] {
			return &ValidationError{Errors: []PolicyFieldError{{Field: "framework", Message: "Invalid framework. Must be SEBI_AI_ML, DPDP_ACT_2023, or SEBI_DPDP_COMBINED"}}}
		}
	}

	// Validate data types
	if len(req.DataTypes) > 0 {
		validDataTypes := map[SEBIAuditDataType]bool{
			SEBIDataTypePolicyViolations: true,
			SEBIDataTypeLLMCalls:         true,
			SEBIDataTypeDecisionChain:    true,
			SEBIDataTypeHITLOversight:    true,
			SEBIDataTypePIIRedactions:    true,
			SEBIDataTypeAll:              true,
		}
		for _, dt := range req.DataTypes {
			if !validDataTypes[dt] {
				return &ValidationError{Errors: []PolicyFieldError{{Field: "data_types", Message: "Invalid data type: " + string(dt)}}}
			}
		}
	}

	return nil
}

// =============================================================================
// Helper Methods
// =============================================================================

// getTenantID extracts tenant ID from request headers or context.
// Checks X-Tenant-ID first (portal proxy), then X-Org-ID (legacy/service calls),
// then falls back to context values.
func (h *SEBIAuditExportHandler) getTenantID(r *http.Request) string {
	// Try X-Tenant-ID header first (set by portal proxy)
	if tenantID := r.Header.Get("X-Tenant-ID"); tenantID != "" {
		return tenantID
	}
	// Try X-Org-ID header (for legacy/internal service calls)
	if orgID := r.Header.Get("X-Org-ID"); orgID != "" {
		return orgID
	}
	// Try from context (set by auth middleware)
	if tenantID, ok := r.Context().Value("tenant_id").(string); ok {
		return tenantID
	}
	if orgID, ok := r.Context().Value("org_id").(string); ok {
		return orgID
	}
	// Legacy middleware may store org_id as int
	if orgID, ok := r.Context().Value("org_id").(int); ok && orgID > 0 {
		return fmt.Sprintf("%d", orgID)
	}
	return ""
}

// getUserID extracts user ID from request
func (h *SEBIAuditExportHandler) getUserID(r *http.Request) string {
	if userID := r.Header.Get("X-User-ID"); userID != "" {
		return userID
	}
	if userID, ok := r.Context().Value("user_id").(string); ok {
		return userID
	}
	return "system"
}

// sebiAllowedOrigins defines permitted CORS origins for SEBI endpoints
var sebiAllowedOrigins = map[string]bool{
	"https://app.getaxonflow.com":      true,
	"https://customer.getaxonflow.com": true,
	"http://localhost:3000":            true,
}

// handleCORS sets CORS headers for OPTIONS requests
func (h *SEBIAuditExportHandler) handleCORS(w http.ResponseWriter, r *http.Request) {
	origin := r.Header.Get("Origin")
	if origin != "" && sebiAllowedOrigins[origin] {
		w.Header().Set("Access-Control-Allow-Origin", origin)
	}
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Tenant-ID, X-Org-ID, X-User-ID")
	w.Header().Set("Access-Control-Max-Age", "86400")
	w.WriteHeader(http.StatusOK)
}

// writeJSON writes a JSON response
func (h *SEBIAuditExportHandler) writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		log.Printf("[SEBIAudit] Error encoding JSON response: %v", err)
	}
}

// SEBIAPIError is the error response format for SEBI API
type SEBIAPIError struct {
	Error SEBIAPIErrorDetail `json:"error"`
}

// SEBIAPIErrorDetail contains error information
type SEBIAPIErrorDetail struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// writeError writes an error response
func (h *SEBIAuditExportHandler) writeError(w http.ResponseWriter, status int, code, message string) {
	h.writeJSON(w, status, SEBIAPIError{
		Error: SEBIAPIErrorDetail{
			Code:    code,
			Message: message,
		},
	})
}

// ValidationError represents a validation error (shared with policy API)
type ValidationError struct {
	Errors []PolicyFieldError
}

func (e *ValidationError) Error() string {
	if len(e.Errors) > 0 {
		return e.Errors[0].Message
	}
	return "validation error"
}

// PolicyFieldError is defined in policy_api_types.go but we need it here
// for the Enterprise package. This redefinition avoids import cycles.
type PolicyFieldError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}
