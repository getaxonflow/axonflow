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
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"axonflow/platform/orchestrator/cloudstorage"
	"axonflow/platform/shared/audit"
	logutil "axonflow/platform/shared/logger"
)

// SEBIAuditExportServiceImpl implements the SEBIAuditExportService interface.
// It provides SEBI compliance audit export functionality for Indian regulatory requirements.
type SEBIAuditExportServiceImpl struct {
	db             *sql.DB
	storageBackend cloudstorage.StorageBackend
}

// NewSEBIAuditExportService creates a new SEBI audit export service
func NewSEBIAuditExportService(db *sql.DB, storageBackend cloudstorage.StorageBackend) *SEBIAuditExportServiceImpl {
	return &SEBIAuditExportServiceImpl{db: db, storageBackend: storageBackend}
}

// ExportAuditData exports audit data for SEBI compliance.
// This method queries audit logs, policy violations, and other compliance-relevant
// data for the specified date range and returns it in the requested format.
//
// SEBI AI/ML Guidelines Compliance:
//   - Exports include all AI/ML decision records
//   - Maintains complete audit trail for 5-year retention period
//   - Supports filtering by data type and severity
//   - Optional PII redaction for external auditor sharing
func (s *SEBIAuditExportServiceImpl) ExportAuditData(ctx context.Context, tenantID string, req *SEBIAuditExportRequest) (*SEBIAuditExportResponse, error) {
	exportID := generateExportID()
	startTime := time.Now()

	log.Printf("[SEBIAudit] Starting export %s for tenant %s, date range: %s to %s",
		exportID, logutil.Sanitize(tenantID), req.StartDate.Format(time.RFC3339), req.EndDate.Format(time.RFC3339))

	// Initialize response
	response := &SEBIAuditExportResponse{
		ExportID:   exportID,
		Status:     "processing",
		Framework:  req.Framework,
		ExportedAt: time.Now().UTC(),
		Metadata: &SEBIExportMetadata{
			ExportVersion:       "1.0.0",
			GeneratedBy:         "AxonFlow Enterprise",
			GeneratedAt:         time.Now().UTC(),
			TenantID:            tenantID,
			ComplianceFramework: req.Framework,
			RetentionDays:       1825, // 5 years SEBI default
		},
	}

	// Get org name
	orgName, err := s.getOrgName(ctx, tenantID)
	if err != nil {
		log.Printf("[SEBIAudit] Warning: could not get org name for %s: %v", logutil.Sanitize(tenantID), err)
		orgName = fmt.Sprintf("Tenant-%s", tenantID)
	}
	response.Metadata.OrgName = orgName

	// Determine which data types to export
	dataTypes := req.DataTypes
	if len(dataTypes) == 0 || (len(dataTypes) == 1 && dataTypes[0] == SEBIDataTypeAll) {
		dataTypes = []SEBIAuditDataType{
			SEBIDataTypePolicyViolations,
			SEBIDataTypeLLMCalls,
			SEBIDataTypeDecisionChain,
			SEBIDataTypeHITLOversight,
			SEBIDataTypePIIRedactions,
		}
	}

	// Initialize export data
	exportData := &SEBIAuditExportData{}
	summary := &SEBIAuditExportSummary{
		RecordsByType: make(map[SEBIAuditDataType]int),
		DateRange: &DateRange{
			Start: req.StartDate,
			End:   req.EndDate,
		},
	}

	// Export each data type
	for _, dataType := range dataTypes {
		switch dataType {
		case SEBIDataTypePolicyViolations:
			violations, count, err := s.exportPolicyViolations(ctx, tenantID, req)
			if err != nil {
				log.Printf("[SEBIAudit] Error exporting policy violations: %v", err)
				continue
			}
			exportData.PolicyViolations = violations
			summary.RecordsByType[SEBIDataTypePolicyViolations] = count
			summary.TotalRecords += count

		case SEBIDataTypeLLMCalls:
			calls, count, err := s.exportLLMCalls(ctx, tenantID, req)
			if err != nil {
				log.Printf("[SEBIAudit] Error exporting LLM calls: %v", err)
				continue
			}
			exportData.LLMCalls = calls
			summary.RecordsByType[SEBIDataTypeLLMCalls] = count
			summary.TotalRecords += count

		case SEBIDataTypeDecisionChain:
			chains, count, err := s.exportDecisionChain(ctx, tenantID, req)
			if err != nil {
				log.Printf("[SEBIAudit] Error exporting decision chain: %v", err)
				continue
			}
			exportData.DecisionChain = chains
			// #2598: reconstruct the logical chains (rows sharing a correlation_id)
			// alongside the flat chronological list. RecordsByType stays the
			// decision-record (step) count for retention/volume reporting.
			exportData.DecisionChains = groupSEBIDecisionChain(chains)
			summary.RecordsByType[SEBIDataTypeDecisionChain] = count
			summary.TotalRecords += count

		case SEBIDataTypeHITLOversight:
			hitl, count, err := s.exportHITLOversight(ctx, tenantID, req)
			if err != nil {
				log.Printf("[SEBIAudit] Error exporting HITL oversight: %v", err)
				continue
			}
			exportData.HITLOversight = hitl
			summary.RecordsByType[SEBIDataTypeHITLOversight] = count
			summary.TotalRecords += count

		case SEBIDataTypePIIRedactions:
			redactions, count, err := s.exportPIIRedactions(ctx, tenantID, req)
			if err != nil {
				log.Printf("[SEBIAudit] Error exporting PII redactions: %v", err)
				continue
			}
			exportData.PIIRedactions = redactions
			summary.RecordsByType[SEBIDataTypePIIRedactions] = count
			summary.TotalRecords += count
		}
	}

	// Calculate violations summary if we have violations
	if len(exportData.PolicyViolations) > 0 {
		summary.ViolationsSummary = s.calculateViolationsSummary(exportData.PolicyViolations)
	}

	// Calculate compliance score
	summary.ComplianceScore = s.calculateComplianceScore(exportData, summary)

	// Generate checksum
	if dataJSON, err := json.Marshal(exportData); err == nil {
		hash := sha256.Sum256(dataJSON)
		response.Metadata.Checksum = hex.EncodeToString(hash[:])
	}

	response.Status = "completed"
	response.Summary = summary
	response.Data = exportData

	// For large exports, upload to cloud storage and return a presigned URL
	if s.storageBackend != nil && summary.TotalRecords > 1000 {
		exportJSON, marshalErr := json.Marshal(exportData)
		if marshalErr != nil {
			log.Printf("[SEBIAudit] Warning: failed to marshal export data for cloud upload: %v", marshalErr)
		} else {
			storageKey := fmt.Sprintf("sebi/%s/audit-export-%s.json", tenantID, exportID)
			uploadReq := &cloudstorage.UploadRequest{
				Key:         storageKey,
				Body:        bytes.NewReader(exportJSON),
				ContentType: "application/json",
				Metadata: map[string]string{
					"export_id": exportID,
					"tenant_id": tenantID,
					"framework": string(req.Framework),
					"checksum":  response.Metadata.Checksum,
				},
			}

			if _, uploadErr := s.storageBackend.Upload(ctx, uploadReq); uploadErr != nil {
				log.Printf("[SEBIAudit] Warning: failed to upload export to cloud storage: %v", logutil.Sanitize(uploadErr.Error()))
			} else {
				presignedURL, presignErr := s.storageBackend.GeneratePresignedURL(ctx, storageKey, 1*time.Hour)
				if presignErr != nil {
					log.Printf("[SEBIAudit] Warning: failed to generate presigned URL: %v", logutil.Sanitize(presignErr.Error()))
				} else {
					response.DownloadURL = presignedURL
					response.Data = nil
					response.ExpiresAt = time.Now().Add(1 * time.Hour)
					log.Printf("[SEBIAudit] Large export %s uploaded to cloud storage: %s", exportID, logutil.Sanitize(storageKey))
				}
			}
		}
	}

	elapsedMs := time.Since(startTime).Milliseconds()
	log.Printf("[SEBIAudit] Export %s completed for tenant %s: %d records in %dms",
		exportID, logutil.Sanitize(tenantID), summary.TotalRecords, elapsedMs)

	return response, nil
}

// GetRetentionStatus returns the retention status for audit data
func (s *SEBIAuditExportServiceImpl) GetRetentionStatus(ctx context.Context, tenantID string, req *SEBIRetentionStatusRequest) (*SEBIRetentionStatusResponse, error) {
	response := &SEBIRetentionStatusResponse{
		TenantID:  tenantID,
		Framework: SEBIFrameworkAIML,
		Status:    []SEBIDataTypeRetentionStatus{},
	}

	// Determine which data types to check
	dataTypes := req.DataTypes
	if len(dataTypes) == 0 {
		dataTypes = []SEBIAuditDataType{
			SEBIDataTypePolicyViolations,
			SEBIDataTypeLLMCalls,
			SEBIDataTypeDecisionChain,
			SEBIDataTypeHITLOversight,
			SEBIDataTypePIIRedactions,
		}
	}

	allCompliant := true

	// Check each data type
	for _, dataType := range dataTypes {
		status := SEBIDataTypeRetentionStatus{
			DataType:         dataType,
			RetentionDays:    1825, // 5 years SEBI default
			ComplianceStatus: "COMPLIANT",
		}

		// Get retention config for this data type
		retentionDays, lastCleanup, err := s.getRetentionConfig(ctx, tenantID, string(dataType))
		if err == nil {
			status.RetentionDays = retentionDays
			status.LastCleanup = lastCleanup
		}

		// Get record counts and date ranges
		stats, err := s.getDataTypeStats(ctx, tenantID, dataType)
		if err != nil {
			log.Printf("[SEBIAudit] Warning: could not get stats for %s: %v", logutil.Sanitize(string(dataType)), err)
		} else {
			status.OldestRecord = stats.OldestRecord
			status.NewestRecord = stats.NewestRecord
			status.TotalRecords = stats.TotalRecords
			status.ArchivedRecords = stats.ArchivedRecords
			status.StorageBytes = stats.StorageBytes
		}

		// Check compliance: retention must be >= 1825 days (5 years)
		if status.RetentionDays < 1825 {
			status.ComplianceStatus = "NON_COMPLIANT"
			allCompliant = false
		}

		response.Status = append(response.Status, status)
	}

	if allCompliant {
		response.ComplianceStatus = "COMPLIANT"
	} else {
		response.ComplianceStatus = "NON_COMPLIANT"
	}

	return response, nil
}

// GetExportStatus returns the status of an async export
func (s *SEBIAuditExportServiceImpl) GetExportStatus(ctx context.Context, tenantID string, exportID string) (*SEBIAuditExportResponse, error) {
	// Query export status from database
	query := `
		SELECT export_id, status, exported_at, framework, summary_json, download_url, expires_at
		FROM sebi_audit_exports
		WHERE export_id = $1 AND tenant_id = $2
	`

	var response SEBIAuditExportResponse
	var summaryJSON []byte
	var downloadURL, framework sql.NullString
	var expiresAt sql.NullTime

	err := s.db.QueryRowContext(ctx, query, exportID, tenantID).Scan(
		&response.ExportID,
		&response.Status,
		&response.ExportedAt,
		&framework,
		&summaryJSON,
		&downloadURL,
		&expiresAt,
	)

	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("export not found: %s", exportID)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get export status: %w", err)
	}

	if framework.Valid {
		response.Framework = SEBIComplianceFramework(framework.String)
	}
	if downloadURL.Valid {
		response.DownloadURL = downloadURL.String
	}
	if expiresAt.Valid {
		response.ExpiresAt = expiresAt.Time
	}

	if len(summaryJSON) > 0 {
		var summary SEBIAuditExportSummary
		if err := json.Unmarshal(summaryJSON, &summary); err == nil {
			response.Summary = &summary
		}
	}

	return &response, nil
}

// ValidateComplianceReadiness checks if the org is ready for SEBI audit
func (s *SEBIAuditExportServiceImpl) ValidateComplianceReadiness(ctx context.Context, tenantID string) (*SEBIComplianceReadinessResponse, error) {
	response := &SEBIComplianceReadinessResponse{
		Ready:  true,
		Score:  100,
		Checks: []SEBIComplianceCheck{},
	}

	// Check 1: Retention configuration
	retentionCheck := SEBIComplianceCheck{
		Name:        "Retention Configuration",
		Description: "Verify 5-year retention is configured for all audit data types",
		Status:      "pass",
	}
	retentionOK, retentionDetails := s.checkRetentionCompliance(ctx, tenantID)
	if !retentionOK {
		retentionCheck.Status = "fail"
		retentionCheck.Details = retentionDetails
		response.Ready = false
		response.Score -= 25
	} else {
		retentionCheck.Details = "All data types configured for 5-year retention"
	}
	response.Checks = append(response.Checks, retentionCheck)

	// Check 2: PII Detection policies
	piiCheck := SEBIComplianceCheck{
		Name:        "PII Detection Policies",
		Description: "Verify PAN and Aadhaar detection policies are enabled",
		Status:      "pass",
	}
	piiOK, piiDetails := s.checkPIIPolicies(ctx, tenantID)
	if !piiOK {
		piiCheck.Status = "fail"
		piiCheck.Details = piiDetails
		response.Ready = false
		response.Score -= 25
	} else {
		piiCheck.Details = "PAN and Aadhaar detection enabled"
	}
	response.Checks = append(response.Checks, piiCheck)

	// Check 3: Human oversight configuration
	hitlCheck := SEBIComplianceCheck{
		Name:        "Human Oversight",
		Description: "Verify human-in-the-loop is configured for high-risk decisions",
		Status:      "pass",
	}
	hitlOK, hitlDetails := s.checkHITLConfiguration(ctx, tenantID)
	if !hitlOK {
		hitlCheck.Status = "warning"
		hitlCheck.Details = hitlDetails
		response.Score -= 10
	} else {
		hitlCheck.Details = "HITL configured for high-risk decisions"
	}
	response.Checks = append(response.Checks, hitlCheck)

	// Check 4: Audit logging enabled
	auditCheck := SEBIComplianceCheck{
		Name:        "Audit Logging",
		Description: "Verify comprehensive audit logging is enabled",
		Status:      "pass",
	}
	auditOK, auditDetails := s.checkAuditLogging(ctx, tenantID)
	if !auditOK {
		auditCheck.Status = "fail"
		auditCheck.Details = auditDetails
		response.Ready = false
		response.Score -= 25
	} else {
		auditCheck.Details = "Comprehensive audit logging enabled"
	}
	response.Checks = append(response.Checks, auditCheck)

	// Check 5: Decision chain tracing
	chainCheck := SEBIComplianceCheck{
		Name:        "Decision Chain Tracing",
		Description: "Verify decision chain tracing is enabled for AI/ML decisions",
		Status:      "pass",
	}
	chainOK, chainDetails := s.checkDecisionChainTracing(ctx, tenantID)
	if !chainOK {
		chainCheck.Status = "warning"
		chainCheck.Details = chainDetails
		response.Score -= 10
	} else {
		chainCheck.Details = "Decision chain tracing enabled"
	}
	response.Checks = append(response.Checks, chainCheck)

	// Generate recommendations
	if response.Score < 100 {
		response.Recommendations = s.generateRecommendations(response.Checks)
	}

	return response, nil
}

// =============================================================================
// Export Helper Methods
// =============================================================================

func (s *SEBIAuditExportServiceImpl) exportPolicyViolations(ctx context.Context, tenantID string, req *SEBIAuditExportRequest) ([]SEBIPolicyViolationRecord, int, error) {
	// policy_violations table is keyed by org_id (not tenant_id)
	query := `
		SELECT id, created_at, violation_type, severity, description,
		       policy_id, client_id, user_id, action, details
		FROM policy_violations
		WHERE org_id = $1 AND created_at >= $2 AND created_at <= $3
		ORDER BY created_at DESC
		LIMIT 100000
	`

	rows, err := s.db.QueryContext(ctx, query, tenantID, req.StartDate, req.EndDate)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to query policy violations: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var violations []SEBIPolicyViolationRecord
	for rows.Next() {
		var v SEBIPolicyViolationRecord
		var detailsJSON []byte
		var policyID, clientID sql.NullString
		var userID sql.NullInt64

		err := rows.Scan(
			&v.ID, &v.Timestamp, &v.ViolationType, &v.Severity, &v.Description,
			&policyID, &clientID, &userID, &v.Action, &detailsJSON,
		)
		if err != nil {
			log.Printf("[SEBIAudit] Error scanning policy violation: %v", err)
			continue
		}

		if policyID.Valid {
			v.PolicyID = policyID.String
		}
		if clientID.Valid {
			v.AgentID = clientID.String
		}
		if userID.Valid {
			v.UserID = int(userID.Int64)
		}
		if len(detailsJSON) > 0 {
			_ = json.Unmarshal(detailsJSON, &v.Details)
		}

		violations = append(violations, v)
	}

	return violations, len(violations), nil
}

func (s *SEBIAuditExportServiceImpl) exportLLMCalls(ctx context.Context, tenantID string, req *SEBIAuditExportRequest) ([]SEBILLMCallRecord, int, error) {
	query := `
		SELECT id, request_id, timestamp, provider, model,
		       input_tokens, output_tokens, response_time_ms, cost,
		       policy_decision, user_id, client_id, redacted_fields, compliance_flags
		FROM llm_call_audits
		WHERE tenant_id = $1 AND timestamp >= $2 AND timestamp <= $3
		ORDER BY timestamp DESC
		LIMIT 100000
	`

	rows, err := s.db.QueryContext(ctx, query, tenantID, req.StartDate, req.EndDate)
	if err != nil {
		// Table might not exist - return empty result
		if isTableNotExistsError(err) {
			return []SEBILLMCallRecord{}, 0, nil
		}
		return nil, 0, fmt.Errorf("failed to query LLM calls: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var calls []SEBILLMCallRecord
	for rows.Next() {
		var c SEBILLMCallRecord
		var redactedJSON, flagsJSON []byte
		var userID sql.NullInt64
		var clientID sql.NullString

		err := rows.Scan(
			&c.ID, &c.RequestID, &c.Timestamp, &c.Provider, &c.Model,
			&c.InputTokens, &c.OutputTokens, &c.LatencyMs, &c.Cost,
			&c.PolicyDecision, &userID, &clientID, &redactedJSON, &flagsJSON,
		)
		if err != nil {
			log.Printf("[SEBIAudit] Error scanning LLM call: %v", err)
			continue
		}

		if userID.Valid {
			c.UserID = int(userID.Int64)
		}
		if clientID.Valid {
			c.AgentID = clientID.String
		}
		if len(redactedJSON) > 0 {
			_ = json.Unmarshal(redactedJSON, &c.RedactedFields)
		}
		if len(flagsJSON) > 0 {
			_ = json.Unmarshal(flagsJSON, &c.ComplianceFlags)
		}

		calls = append(calls, c)
	}

	return calls, len(calls), nil
}

// exportDecisionChain returns the per-decision audit rows for SEBI's audit
// trail, in chronological order — one row per governance decision (a
// /api/v1/decide call or an MCP check). The caller groups them into logical
// chains via groupSEBIDecisionChain (#2598).
//
// Rows are derived from the canonical audit_logs decision rows — the rows the
// Decision Mode PEP and the MCP check planes persist via writeDecisionAuditLog,
// identified by policy_details->>'decision_id'. The legacy decision_chain table
// has no production writer (#2588: its only writer, DecisionChainTracker, is
// instantiated solely in tests), so the previous FROM decision_chain query
// returned zero rows in every deployment and this section was silently empty in
// regulator exports. This converges the read onto audit_logs per the #2585
// audit-log northstar rather than reviving a parallel table.
//
// correlation_id (#2598) is the shared key the writers stamp on every decision
// row of one logical request (the W3C trace_id a PEP propagates across its
// llm/tool/agent hops). It is read here — COALESCEd with the dual-written JSONB
// copy — so groupSEBIDecisionChain can reconstruct a real chain. Rows without
// one (legacy + single-shot callers) carry "" and become singleton chains.
// Ordering stays chronological (timestamp, id) so the flat list AND each chain's
// steps read in step order.
//
// audit_logs is NOT FORCE ROW LEVEL SECURITY (migration 101 deliberately left
// it unprotected for the cross-org cleanup worker), so this read needs no
// withOrgScope wrap — unlike the FORCE-RLS reads elsewhere in this file. The
// SEBI tenantID argument is used loosely as either the org_id or tenant_id
// label across callers, so both columns are matched.
func (s *SEBIAuditExportServiceImpl) exportDecisionChain(ctx context.Context, tenantID string, req *SEBIAuditExportRequest) ([]SEBIDecisionChainRecord, int, error) {
	query := `
		SELECT id, request_id, timestamp,
		       COALESCE(NULLIF(policy_details->>'stage', ''), request_type) AS decision_type,
		       policy_decision,
		       COALESCE(model, '')                                          AS model_id,
		       COALESCE((policy_details->'policy_ids')::text, '')           AS policies_evaluated,
		       COALESCE(policy_details->'policy_ids'->>0, '')               AS policy_triggered,
		       response_time_ms,
		       COALESCE(correlation_id, policy_details->>'correlation_id', '') AS correlation_id
		FROM audit_logs
		WHERE (tenant_id = $1 OR org_id = $1)
		  AND timestamp >= $2 AND timestamp <= $3
		  AND policy_details->>'decision_id' IS NOT NULL
		ORDER BY timestamp ASC, id ASC
		LIMIT 100000
	`

	rows, err := s.db.QueryContext(ctx, query, tenantID, req.StartDate, req.EndDate)
	if err != nil {
		if isTableNotExistsError(err) {
			return []SEBIDecisionChainRecord{}, 0, nil
		}
		return nil, 0, fmt.Errorf("failed to query decision chain: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var chains []SEBIDecisionChainRecord
	for rows.Next() {
		var c SEBIDecisionChainRecord
		var decisionType, policyDecision, modelID, policiesEvaluated, policyTriggered, correlationID string
		var processingTimeMs sql.NullInt64

		err := rows.Scan(
			&c.ID, &c.RequestID, &c.Timestamp, &decisionType, &policyDecision,
			&modelID, &policiesEvaluated, &policyTriggered, &processingTimeMs, &correlationID,
		)
		if err != nil {
			log.Printf("[SEBIAudit] Error scanning decision chain: %v", err)
			continue
		}

		c.DecisionType = decisionType
		c.DecisionOutcome = mapDecisionOutcome(policyDecision)
		c.RequiresReview = requiresReview(policyDecision)
		c.ModelID = modelID
		if policiesEvaluated != "" && policiesEvaluated != "null" {
			c.PoliciesEvaluated = policiesEvaluated
		}
		c.PolicyTriggered = policyTriggered
		if processingTimeMs.Valid {
			v := int(processingTimeMs.Int64)
			c.ProcessingTimeMs = &v
		}
		c.CorrelationID = correlationID
		// RiskLevel is not captured on canonical decision rows; left empty
		// (omitempty) rather than fabricated.

		chains = append(chains, c)
	}

	return chains, len(chains), rows.Err()
}

// groupSEBIDecisionChain reconstructs logical decision chains from the flat,
// chronologically-ordered decision rows (#2598). Rows sharing a non-empty
// correlation_id collapse into one chain in step order; rows without one (legacy
// + single-shot callers) each become a singleton chain. Group order is
// first-appearance, which — because the input is ordered by (timestamp, id) — is
// chronological by each chain's earliest step, preserving the chronological
// behavior for ungrouped rows. Pure function (no I/O) so the grouping is
// unit-testable on its own.
func groupSEBIDecisionChain(records []SEBIDecisionChainRecord) []SEBIDecisionChain {
	if len(records) == 0 {
		return nil
	}
	groups := make([]SEBIDecisionChain, 0, len(records))
	indexByCorrelation := make(map[string]int, len(records))
	for _, r := range records {
		key := r.CorrelationID
		if key != "" {
			if i, ok := indexByCorrelation[key]; ok {
				g := &groups[i]
				g.Steps = append(g.Steps, r)
				g.StepCount = len(g.Steps)
				if r.Timestamp.After(g.EndedAt) {
					g.EndedAt = r.Timestamp
				}
				if r.Timestamp.Before(g.StartedAt) {
					g.StartedAt = r.Timestamp
				}
				continue
			}
			indexByCorrelation[key] = len(groups)
		}
		groups = append(groups, SEBIDecisionChain{
			CorrelationID: r.CorrelationID,
			StepCount:     1,
			StartedAt:     r.Timestamp,
			EndedAt:       r.Timestamp,
			Steps:         []SEBIDecisionChainRecord{r},
		})
	}
	return groups
}

// mapDecisionOutcome translates an audit_logs policy_decision verdict into the
// SEBI decision-outcome vocabulary used by regulator-facing exports. The raw
// value is run through the shared normalizer (audit.Normalize) FIRST so every
// writer spelling and era converges before mapping — critically, the canonical
// "allowed"/"blocked" that all forward writers now emit map to approved/blocked,
// where the old present-tense switch ("allow"/"deny") let them fall through to
// the raw value and leak an un-mapped "allowed" into a regulator export.
// needs_approval is flagged as requires-review ("pending_review"), never
// silently downgraded to approved.
func mapDecisionOutcome(verdict string) string {
	switch audit.Normalize(verdict) {
	case audit.DecisionAllowed:
		return "approved"
	case audit.DecisionBlocked:
		return "blocked"
	case audit.DecisionRedacted:
		return "redacted"
	case audit.DecisionNeedsApproval:
		return "pending_review"
	case audit.DecisionError:
		return "error"
	default:
		// Recognized non-verdict marker (override_lifecycle): surface it as-is
		// rather than a distorted decision outcome. Normalize guarantees an
		// unrecognized value can never reach here as "approved".
		return audit.Normalize(verdict)
	}
}

// requiresReview reports whether a raw policy_decision is a human-deferred
// (needs-approval) verdict. It consumes the shared normalizer so it stays in
// lock-step with mapDecisionOutcome — a raw string compare against
// "needs_approval"/"require_approval" would miss legacy/defensive spellings
// (e.g. pending_approval), which mapDecisionOutcome maps to "pending_review"
// while RequiresReview reported false, telling a regulator a human-deferred
// decision needed no review (#2636/#2653).
func requiresReview(policyDecision string) bool {
	return audit.Normalize(policyDecision) == audit.DecisionNeedsApproval
}

func (s *SEBIAuditExportServiceImpl) exportHITLOversight(ctx context.Context, tenantID string, req *SEBIAuditExportRequest) ([]SEBIHITLRecord, int, error) {
	query := `
		SELECT id, request_id, created_at, trigger_reason,
		       reviewer_id, decision, notes, review_time_ms
		FROM hitl_queue
		WHERE tenant_id = $1 AND created_at >= $2 AND created_at <= $3 AND status = 'completed'
		ORDER BY created_at DESC
		LIMIT 100000
	`

	rows, err := s.db.QueryContext(ctx, query, tenantID, req.StartDate, req.EndDate)
	if err != nil {
		if isTableNotExistsError(err) {
			return []SEBIHITLRecord{}, 0, nil
		}
		return nil, 0, fmt.Errorf("failed to query HITL records: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var records []SEBIHITLRecord
	for rows.Next() {
		var r SEBIHITLRecord
		var notes sql.NullString
		var reviewTimeMs sql.NullInt64

		err := rows.Scan(
			&r.ID, &r.RequestID, &r.Timestamp, &r.TriggerReason,
			&r.ReviewerID, &r.Decision, &notes, &reviewTimeMs,
		)
		if err != nil {
			log.Printf("[SEBIAudit] Error scanning HITL record: %v", err)
			continue
		}

		if notes.Valid {
			r.Notes = notes.String
		}
		if reviewTimeMs.Valid {
			r.ReviewTimeMs = reviewTimeMs.Int64
		}

		records = append(records, r)
	}

	return records, len(records), nil
}

func (s *SEBIAuditExportServiceImpl) exportPIIRedactions(ctx context.Context, tenantID string, req *SEBIAuditExportRequest) ([]SEBIPIIRedactionRecord, int, error) {
	query := `
		SELECT id, request_id, created_at, pii_type, redaction_method,
		       location, detection_confidence, user_id, compliance_framework
		FROM pii_redaction_log
		WHERE tenant_id = $1 AND created_at >= $2 AND created_at <= $3
		ORDER BY created_at DESC
		LIMIT 100000
	`

	rows, err := s.db.QueryContext(ctx, query, tenantID, req.StartDate, req.EndDate)
	if err != nil {
		if isTableNotExistsError(err) {
			return []SEBIPIIRedactionRecord{}, 0, nil
		}
		return nil, 0, fmt.Errorf("failed to query PII redactions: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var redactions []SEBIPIIRedactionRecord
	for rows.Next() {
		var r SEBIPIIRedactionRecord
		var userID sql.NullInt64
		var framework sql.NullString

		err := rows.Scan(
			&r.ID, &r.RequestID, &r.Timestamp, &r.PIIType, &r.RedactionMethod,
			&r.Location, &r.DetectionConfidence, &userID, &framework,
		)
		if err != nil {
			log.Printf("[SEBIAudit] Error scanning PII redaction: %v", err)
			continue
		}

		if userID.Valid {
			r.UserID = int(userID.Int64)
		}
		if framework.Valid {
			r.ComplianceFramework = framework.String
		}

		redactions = append(redactions, r)
	}

	return redactions, len(redactions), nil
}

// =============================================================================
// Compliance Check Helper Methods
// =============================================================================

func (s *SEBIAuditExportServiceImpl) checkRetentionCompliance(ctx context.Context, tenantID string) (bool, string) {
	// audit_retention_config table is keyed by org_id (not tenant_id).
	// v9 Phase 8 B2 (migration 100): audit_retention_config is FORCE ROW LEVEL
	// SECURITY enforced. Wrap the read in withOrgScope so the policy
	// org_id = current_setting('app.current_org_id', true) evaluates to TRUE
	// for the tenant's rows. The WHERE clause stays as a defense-in-depth.
	query := `
		SELECT data_type, retention_days
		FROM audit_retention_config
		WHERE org_id = $1 AND is_active = true
	`

	var nonCompliant []string
	scopeErr := withOrgScope(ctx, s.db, tenantID, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, query, tenantID)
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()

		for rows.Next() {
			var dataType string
			var retentionDays int
			if err := rows.Scan(&dataType, &retentionDays); err != nil {
				continue
			}
			if retentionDays < 1825 {
				nonCompliant = append(nonCompliant, fmt.Sprintf("%s (%d days)", dataType, retentionDays))
			}
		}
		return rows.Err()
	})
	if scopeErr != nil {
		if isTableNotExistsError(scopeErr) {
			return true, "Using default 5-year retention"
		}
		return false, fmt.Sprintf("Failed to check retention config: %v", scopeErr)
	}

	if len(nonCompliant) > 0 {
		return false, fmt.Sprintf("Non-compliant retention for: %v", nonCompliant)
	}
	return true, ""
}

func (s *SEBIAuditExportServiceImpl) checkPIIPolicies(ctx context.Context, tenantID string) (bool, string) {
	// Check for PAN and Aadhaar detection policies
	query := `
		SELECT COUNT(*)
		FROM policies
		WHERE tenant_id = $1 AND enabled = true
		AND (name ILIKE '%pan%' OR name ILIKE '%aadhaar%' OR name ILIKE '%indian pii%')
	`

	var count int
	err := s.db.QueryRowContext(ctx, query, tenantID).Scan(&count)
	if err != nil {
		if isTableNotExistsError(err) {
			// Static policies are enabled by default
			return true, ""
		}
		return false, fmt.Sprintf("Failed to check PII policies: %v", err)
	}

	if count == 0 {
		return false, "No PAN/Aadhaar detection policies found"
	}
	return true, ""
}

func (s *SEBIAuditExportServiceImpl) checkHITLConfiguration(ctx context.Context, tenantID string) (bool, string) {
	query := `
		SELECT COUNT(*)
		FROM hitl_config
		WHERE tenant_id = $1 AND enabled = true
	`

	var count int
	err := s.db.QueryRowContext(ctx, query, tenantID).Scan(&count)
	if err != nil {
		if isTableNotExistsError(err) {
			return false, "HITL configuration not found"
		}
		return false, fmt.Sprintf("Failed to check HITL config: %v", err)
	}

	if count == 0 {
		return false, "HITL not configured for any workflows"
	}
	return true, ""
}

func (s *SEBIAuditExportServiceImpl) checkAuditLogging(ctx context.Context, tenantID string) (bool, string) {
	// Check if audit logging is enabled and working
	query := `
		SELECT COUNT(*)
		FROM audit_logs
		WHERE tenant_id = $1 AND timestamp >= NOW() - INTERVAL '24 hours'
	`

	var count int
	err := s.db.QueryRowContext(ctx, query, tenantID).Scan(&count)
	if err != nil {
		if isTableNotExistsError(err) {
			return false, "Audit logs table not found"
		}
		return false, fmt.Sprintf("Failed to check audit logging: %v", err)
	}

	if count == 0 {
		return false, "No audit logs in last 24 hours"
	}
	return true, ""
}

func (s *SEBIAuditExportServiceImpl) checkDecisionChainTracing(ctx context.Context, tenantID string) (bool, string) {
	// Decision records now live in audit_logs (#2588); the decision_chain table
	// has no live writer. Count canonical decision rows in the last 24h to
	// verify decision recording is actually producing records.
	query := `
		SELECT COUNT(*)
		FROM audit_logs
		WHERE (tenant_id = $1 OR org_id = $1)
		  AND policy_details->>'decision_id' IS NOT NULL
		  AND timestamp >= NOW() - INTERVAL '24 hours'
	`

	var count int
	err := s.db.QueryRowContext(ctx, query, tenantID).Scan(&count)
	if err != nil {
		if isTableNotExistsError(err) {
			return false, "Decision chain tracing not configured"
		}
		return false, fmt.Sprintf("Failed to check decision chain: %v", err)
	}

	if count == 0 {
		return false, "No decision chain records in last 24 hours"
	}
	return true, ""
}

// =============================================================================
// Utility Methods
// =============================================================================

func (s *SEBIAuditExportServiceImpl) getOrgName(ctx context.Context, tenantID string) (string, error) {
	// Try org_id first (string identifier like "travel-us"), then fall back to
	// numeric id for legacy callers that pass the integer surrogate key.
	//
	// v9 Phase 8 B9 (migration 103): organizations is now FORCE ROW LEVEL
	// SECURITY. Without withOrgScope, the master/app-role connection runs
	// these SELECTs with app.current_org_id unset → the per-org isolation
	// policy evaluates to FALSE and the query returns 0 rows for every
	// tenant. ExportAuditData (line 77) silently falls back to
	// "Tenant-<id>" on error, so the failure mode under FORCE is degraded
	// metadata on every SEBI export — quiet but operator-visible. The
	// withOrgScope wrap sets app.current_org_id = tenantID for the
	// transaction so the row's org_id matches the GUC.
	var name string
	scopeErr := withOrgScope(ctx, s.db, tenantID, func(tx *sql.Tx) error {
		err := tx.QueryRowContext(ctx, "SELECT name FROM organizations WHERE org_id = $1", tenantID).Scan(&name)
		if err == nil {
			return nil
		}
		// Fallback: try numeric id lookup for backwards compatibility. Still
		// inside the same tx so app.current_org_id stays set for the FORCE
		// RLS policy. The numeric-id branch only fires for legacy callers
		// passing the integer surrogate key, which is a no-op for the
		// SaaS / portal path where tenantID is always the string org_id.
		return tx.QueryRowContext(ctx, "SELECT name FROM organizations WHERE id = $1", tenantID).Scan(&name)
	})
	return name, scopeErr
}

func (s *SEBIAuditExportServiceImpl) getRetentionConfig(ctx context.Context, tenantID string, dataType string) (int, time.Time, error) {
	// audit_retention_config table is keyed by org_id (not tenant_id).
	// v9 Phase 8 B2 (migration 100): wrap in withOrgScope so app.current_org_id
	// matches the row's org_id under FORCE ROW LEVEL SECURITY.
	query := `
		SELECT retention_days, COALESCE(last_cleanup_at, '1970-01-01'::timestamp)
		FROM audit_retention_config
		WHERE org_id = $1 AND data_type = $2 AND is_active = true
	`

	var retentionDays int
	var lastCleanup time.Time
	scopeErr := withOrgScope(ctx, s.db, tenantID, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, query, tenantID, dataType).Scan(&retentionDays, &lastCleanup)
	})
	if scopeErr == sql.ErrNoRows {
		return 1825, time.Time{}, nil // Default 5-year retention
	}
	return retentionDays, lastCleanup, scopeErr
}

type dataTypeStats struct {
	OldestRecord    time.Time
	NewestRecord    time.Time
	TotalRecords    int64
	ArchivedRecords int64
	StorageBytes    int64
}

func (s *SEBIAuditExportServiceImpl) getDataTypeStats(ctx context.Context, tenantID string, dataType SEBIAuditDataType) (*dataTypeStats, error) {
	stats := &dataTypeStats{}

	// Decision-record stats come from audit_logs decision rows (#2588), not the
	// dead decision_chain table. It needs a bespoke query (decision_id predicate
	// + `timestamp` column, both tenant/org columns matched) so it can't use the
	// generic table/tenantCol builder below.
	if dataType == SEBIDataTypeDecisionChain {
		query := `
			SELECT MIN(timestamp), MAX(timestamp), COUNT(*)
			FROM audit_logs
			WHERE (tenant_id = $1 OR org_id = $1)
			  AND policy_details->>'decision_id' IS NOT NULL
		`
		var oldest, newest sql.NullTime
		err := s.db.QueryRowContext(ctx, query, tenantID).Scan(&oldest, &newest, &stats.TotalRecords)
		if err != nil {
			return stats, err
		}
		if oldest.Valid {
			stats.OldestRecord = oldest.Time
		}
		if newest.Valid {
			stats.NewestRecord = newest.Time
		}
		return stats, nil
	}

	// Map data type to table name and tenant column
	// policy_violations uses org_id; all others use tenant_id
	tableName := ""
	tenantCol := "tenant_id"
	switch dataType {
	case SEBIDataTypePolicyViolations:
		tableName = "policy_violations"
		tenantCol = "org_id"
	case SEBIDataTypeLLMCalls:
		tableName = "llm_call_audits"
	case SEBIDataTypeHITLOversight:
		tableName = "hitl_queue"
	case SEBIDataTypePIIRedactions:
		tableName = "pii_redaction_log"
	default:
		return stats, nil
	}

	query := fmt.Sprintf(`
		SELECT
			MIN(created_at) as oldest,
			MAX(created_at) as newest,
			COUNT(*) as total
		FROM %s
		WHERE %s = $1
	`, tableName, tenantCol)

	var oldest, newest sql.NullTime
	err := s.db.QueryRowContext(ctx, query, tenantID).Scan(&oldest, &newest, &stats.TotalRecords)
	if err != nil {
		return stats, err
	}

	if oldest.Valid {
		stats.OldestRecord = oldest.Time
	}
	if newest.Valid {
		stats.NewestRecord = newest.Time
	}

	return stats, nil
}

func (s *SEBIAuditExportServiceImpl) calculateViolationsSummary(violations []SEBIPolicyViolationRecord) *ViolationsSummary {
	summary := &ViolationsSummary{
		Total:      len(violations),
		BySeverity: make(map[string]int),
		ByType:     make(map[string]int),
	}

	typeCount := make(map[string]int)
	for _, v := range violations {
		summary.BySeverity[v.Severity]++
		summary.ByType[v.ViolationType]++
		typeCount[v.ViolationType]++
	}

	// Get top 5 violations
	type kv struct {
		Type  string
		Count int
	}
	var sortedTypes []kv
	for t, c := range typeCount {
		sortedTypes = append(sortedTypes, kv{t, c})
	}
	// Simple sort by count descending
	for i := 0; i < len(sortedTypes); i++ {
		for j := i + 1; j < len(sortedTypes); j++ {
			if sortedTypes[j].Count > sortedTypes[i].Count {
				sortedTypes[i], sortedTypes[j] = sortedTypes[j], sortedTypes[i]
			}
		}
	}

	limit := 5
	if len(sortedTypes) < limit {
		limit = len(sortedTypes)
	}
	for i := 0; i < limit; i++ {
		summary.TopViolations = append(summary.TopViolations, ViolationCount{
			Type:  sortedTypes[i].Type,
			Count: sortedTypes[i].Count,
		})
	}

	return summary
}

func (s *SEBIAuditExportServiceImpl) calculateComplianceScore(data *SEBIAuditExportData, summary *SEBIAuditExportSummary) float64 {
	// Base score of 100
	score := 100.0

	// Deduct points for critical violations
	if summary.ViolationsSummary != nil {
		critical := summary.ViolationsSummary.BySeverity["critical"]
		high := summary.ViolationsSummary.BySeverity["high"]

		score -= float64(critical) * 5  // -5 points per critical
		score -= float64(high) * 2      // -2 points per high
	}

	// Ensure score doesn't go below 0
	if score < 0 {
		score = 0
	}

	return score
}

func (s *SEBIAuditExportServiceImpl) generateRecommendations(checks []SEBIComplianceCheck) []string {
	var recommendations []string

	for _, check := range checks {
		if check.Status != "pass" {
			switch check.Name {
			case "Retention Configuration":
				recommendations = append(recommendations, "Update retention configuration to meet 5-year SEBI requirement")
			case "PII Detection Policies":
				recommendations = append(recommendations, "Enable PAN and Aadhaar detection policies for DPDP Act compliance")
			case "Human Oversight":
				recommendations = append(recommendations, "Configure human-in-the-loop review for high-risk AI decisions")
			case "Audit Logging":
				recommendations = append(recommendations, "Ensure comprehensive audit logging is enabled for all AI/ML operations")
			case "Decision Chain Tracing":
				recommendations = append(recommendations, "Enable decision chain tracing to maintain full audit trail of AI decisions")
			}
		}
	}

	return recommendations
}

func generateExportID() string {
	return fmt.Sprintf("exp_%d_%s", time.Now().Unix(), randomString(8))
}

func randomString(n int) string {
	const chars = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, n)

	// Use crypto/rand for secure random bytes
	randomBytes := make([]byte, n)
	if _, err := rand.Read(randomBytes); err != nil {
		// Fallback to timestamp-based if crypto fails (shouldn't happen)
		for i := range b {
			b[i] = chars[(time.Now().UnixNano()+int64(i))%int64(len(chars))]
		}
		return string(b)
	}

	for i := range b {
		b[i] = chars[int(randomBytes[i])%len(chars)]
	}
	return string(b)
}

func isTableNotExistsError(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	return contains(errStr, "does not exist") ||
		   contains(errStr, "relation") ||
		   contains(errStr, "no such table")
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsAt(s, substr, 0))
}

func containsAt(s, substr string, start int) bool {
	for i := start; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
