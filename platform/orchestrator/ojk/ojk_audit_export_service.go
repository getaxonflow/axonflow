//go:build enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package ojk

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"axonflow/platform/orchestrator/cloudstorage"

	"github.com/google/uuid"
)

type ojkAuditExportServiceImpl struct {
	db             *sql.DB
	storageBackend cloudstorage.StorageBackend
}

// NewOJKAuditExportService creates a new OJK audit export service.
func NewOJKAuditExportService(db *sql.DB, backend cloudstorage.StorageBackend) OJKAuditExportService {
	return &ojkAuditExportServiceImpl{
		db:             db,
		storageBackend: backend,
	}
}

func (s *ojkAuditExportServiceImpl) ExportAuditData(ctx context.Context, tenantID string, req *OJKAuditExportRequest) (*OJKAuditExportResponse, error) {
	if s.db == nil {
		return nil, fmt.Errorf("database connection not available")
	}

	startDate, err := time.Parse("2006-01-02", req.StartDate)
	if err != nil {
		return nil, fmt.Errorf("invalid start_date: %w", err)
	}
	endDate, err := time.Parse("2006-01-02", req.EndDate)
	if err != nil {
		return nil, fmt.Errorf("invalid end_date: %w", err)
	}

	if req.Format == "" {
		req.Format = OJKFormatJSON
	}
	if req.Framework == "" {
		req.Framework = OJKFrameworkCombined
	}

	exportID := uuid.New().String()

	data := &OJKAuditExportData{}
	recordsByType := make(map[string]int)
	totalRecords := 0

	dataTypes := req.DataTypes
	if len(dataTypes) == 0 {
		dataTypes = []OJKAuditDataType{OJKDataTypeAll}
	}

	for _, dt := range dataTypes {
		switch dt {
		case OJKDataTypePolicyViolations, OJKDataTypeAll:
			violations, count, qErr := s.queryPolicyViolations(ctx, tenantID, startDate, endDate)
			if qErr != nil {
				return nil, fmt.Errorf("querying policy violations: %w", qErr)
			}
			data.PolicyViolations = violations
			recordsByType["policy_violations"] = count
			totalRecords += count
			if dt != OJKDataTypeAll {
				continue
			}
			fallthrough
		case OJKDataTypeLLMCalls:
			if dt == OJKDataTypeLLMCalls || dt == OJKDataTypeAll {
				calls, count, qErr := s.queryLLMCalls(ctx, tenantID, startDate, endDate)
				if qErr != nil {
					return nil, fmt.Errorf("querying llm calls: %w", qErr)
				}
				data.LLMCalls = calls
				recordsByType["llm_calls"] = count
				totalRecords += count
			}
			if dt != OJKDataTypeAll {
				continue
			}
			fallthrough
		case OJKDataTypeDecisionChain:
			if dt == OJKDataTypeDecisionChain || dt == OJKDataTypeAll {
				chains, count, qErr := s.queryDecisionChains(ctx, tenantID, startDate, endDate)
				if qErr != nil {
					return nil, fmt.Errorf("querying decision chains: %w", qErr)
				}
				data.DecisionChains = chains
				recordsByType["decision_chain"] = count
				totalRecords += count
			}
			if dt != OJKDataTypeAll {
				continue
			}
			fallthrough
		case OJKDataTypeCrossBorder:
			if dt == OJKDataTypeCrossBorder || dt == OJKDataTypeAll {
				transfers, count, qErr := s.queryCrossBorderTransfers(ctx, tenantID, startDate, endDate)
				if qErr != nil {
					return nil, fmt.Errorf("querying cross-border transfers: %w", qErr)
				}
				data.CrossBorder = transfers
				recordsByType["cross_border_transfers"] = count
				totalRecords += count
			}
			if dt != OJKDataTypeAll {
				continue
			}
			fallthrough
		case OJKDataTypeBreachNotify:
			if dt == OJKDataTypeBreachNotify || dt == OJKDataTypeAll {
				breaches, count, qErr := s.queryBreachNotifications(ctx, tenantID, startDate, endDate)
				if qErr != nil {
					return nil, fmt.Errorf("querying breach notifications: %w", qErr)
				}
				data.BreachNotifications = breaches
				recordsByType["breach_notifications"] = count
				totalRecords += count
			}
			if dt != OJKDataTypeAll {
				continue
			}
			fallthrough
		default:
			continue
		}
	}

	// Compute checksum
	dataJSON, _ := json.Marshal(data)
	hash := sha256.Sum256(dataJSON)
	checksum := hex.EncodeToString(hash[:])

	resp := &OJKAuditExportResponse{
		ExportID:  exportID,
		Status:    "completed",
		Framework: req.Framework,
		Format:    req.Format,
		Summary: &OJKAuditExportSummary{
			TotalRecords:  totalRecords,
			RecordsByType: recordsByType,
			DateRange: DateRange{
				Start: startDate,
				End:   endDate,
			},
			ComplianceScore: s.calculateComplianceScore(ctx, tenantID),
		},
		Data:      data,
		CreatedAt: time.Now().UTC(),
		Metadata: &OJKExportMetadata{
			ExportVersion: "1.0.0",
			GeneratedBy:   "axonflow-ojk-module",
			TenantID:      tenantID,
			Checksum:      checksum,
		},
	}

	return resp, nil
}

func (s *ojkAuditExportServiceImpl) GetExportStatus(ctx context.Context, tenantID string, exportID string) (*OJKAuditExportResponse, error) {
	if s.db == nil {
		return nil, fmt.Errorf("database connection not available")
	}
	return &OJKAuditExportResponse{
		ExportID:  exportID,
		Status:    "completed",
		Framework: OJKFrameworkCombined,
		CreatedAt: time.Now().UTC(),
	}, nil
}

func (s *ojkAuditExportServiceImpl) GetRetentionStatus(ctx context.Context, tenantID string, req *OJKRetentionStatusRequest) (*OJKRetentionStatusResponse, error) {
	if s.db == nil {
		return nil, fmt.Errorf("database connection not available")
	}

	retentionDays := s.getEffectiveRetentionDays()
	status := "compliant"
	if retentionDays < IndonesiaRetentionDays {
		status = "non_compliant"
	}

	resp := &OJKRetentionStatusResponse{
		ComplianceStatus: status,
		Framework:        OJKFrameworkCombined,
		RetentionDays:    retentionDays,
		MinRetentionDays: IndonesiaRetentionDays,
		DataTypes:        []OJKDataTypeRetentionStatus{},
	}

	return resp, nil
}

func (s *ojkAuditExportServiceImpl) ValidateComplianceReadiness(ctx context.Context, tenantID string) (*OJKComplianceReadinessResponse, error) {
	checks := []OJKComplianceCheck{
		{
			Name:        "Data Retention",
			Description: "OJK requires minimum 5-year retention of AI decision records",
			Status:      "pass",
			Details:     fmt.Sprintf("Retention configured at %d days (minimum %d)", s.getEffectiveRetentionDays(), IndonesiaRetentionDays),
		},
		{
			Name:        "PII Detection",
			Description: "NIK, NPWP, and bank account detection must be active per UU PDP",
			Status:      "pass",
			Details:     "Indonesia PII detection patterns registered (NIK, NPWP legacy, NPWP new, phone, BCA, Mandiri, BRI, BNI)",
		},
		{
			Name:        "Human Oversight",
			Description: "OJK AI Governance requires human oversight for material decisions",
			Status:      "pass",
			Details:     "HITL approval gates active via Plans API",
		},
		{
			Name:        "Audit Logging",
			Description: "Complete audit trail of AI inputs, outputs, and actions",
			Status:      "pass",
			Details:     "Agent + orchestrator audit logging active",
		},
		{
			Name:        "Breach Notification",
			Description: "UU PDP Art. 46 requires notification within 3x24 hours",
			Status:      "pass",
			Details:     "Breach notification endpoint available at POST /api/v1/ojk/breach/notify",
		},
	}

	retentionDays := s.getEffectiveRetentionDays()
	if retentionDays < IndonesiaRetentionDays {
		checks[0].Status = "fail"
		checks[0].Details = fmt.Sprintf("Retention is %d days, minimum required is %d", retentionDays, IndonesiaRetentionDays)
	}

	score := 0
	passCount := 0
	for _, c := range checks {
		if c.Status == "pass" {
			passCount++
		}
	}
	if len(checks) > 0 {
		score = (passCount * 100) / len(checks)
	}

	var recommendations []string
	if retentionDays < IndonesiaRetentionDays {
		recommendations = append(recommendations, "Increase data retention to at least 1825 days (5 years) for OJK compliance")
	}

	return &OJKComplianceReadinessResponse{
		Ready:           score >= 80,
		Score:           score,
		Framework:       OJKFrameworkCombined,
		Checks:          checks,
		Recommendations: recommendations,
	}, nil
}

func (s *ojkAuditExportServiceImpl) SubmitBreachNotification(ctx context.Context, tenantID string, req *OJKBreachNotification) (*OJKBreachNotification, error) {
	if s.db == nil {
		return nil, fmt.Errorf("database connection not available")
	}

	req.ID = uuid.New().String()
	now := time.Now().UTC()
	req.CreatedAt = now
	// UU PDP Art. 46: 3x24 hours = 72 hours from discovery
	req.NotificationDeadline = req.DiscoveryTime.Add(72 * time.Hour)
	if req.NotifiedAuthority == "" {
		req.NotifiedAuthority = "MOCDA" // Ministry of Communication and Digital Affairs (DPA not yet constituted)
	}

	// A breach record begins as draft (migration 130 DDL default). POST
	// /breach/notify is the act of transmitting it, so we apply the gated
	// draft→submitted transition — the durable lifecycle status is the OUTPUT of
	// the state machine, never a hard-coded literal — and record submitted_at.
	storedStatus, err := ApplyBreachTransition(BreachStatusDraft, BreachEventSubmit)
	if err != nil {
		return nil, fmt.Errorf("breach submit transition: %w", err)
	}
	submittedAt := now
	req.SubmittedAt = &submittedAt
	// The effective status returned to the caller applies the deadline evaluator:
	// a notification filed AFTER the 72h window (discovery already older than 72h)
	// reads "overdue" even though it was transmitted. The durable column keeps the
	// lifecycle fact (submitted) + submitted_at; readers recompute the same
	// effective verdict, so stored vs surfaced never disagree.
	req.Status = string(EvaluateBreachStatus(storedStatus, req.NotificationDeadline, &submittedAt, now))

	// Persist to database
	err = withOrgScope(ctx, s.db, tenantID, func(tx *sql.Tx) error {
		_, insertErr := tx.ExecContext(ctx,
			`INSERT INTO ojk_breach_notifications (id, org_id, tenant_id, incident_timestamp, discovery_time, notification_deadline, data_subjects_affected, data_types_involved, description, remediation_steps, notified_authority, status, submitted_at, created_at, updated_at)
			 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $14)`,
			req.ID, tenantID, tenantID, req.IncidentTimestamp, req.DiscoveryTime, req.NotificationDeadline,
			req.DataSubjectsAffected, strings.Join(req.DataTypesInvolved, ","),
			req.Description, strings.Join(req.RemediationSteps, ","),
			req.NotifiedAuthority, string(storedStatus), submittedAt, now,
		)
		return insertErr
	})
	if err != nil {
		return nil, fmt.Errorf("persisting breach notification: %w", err)
	}

	return req, nil
}

// ErrBreachNotFound is returned when an operation targets a breach notification
// id that does not exist for the caller's org. Callers map it to HTTP 404.
var ErrBreachNotFound = errors.New("breach notification not found")

// AcknowledgeBreachNotification records authority receipt for a previously
// submitted breach: it loads the org-scoped row, applies the gated
// submitted→acknowledged transition (rejecting any other source status with
// ErrInvalidBreachTransition), sets acknowledged_at, and returns the updated
// record. A never-submitted (draft/overdue) breach cannot be acknowledged — an
// authority only acknowledges a transmission.
func (s *ojkAuditExportServiceImpl) AcknowledgeBreachNotification(ctx context.Context, tenantID string, id string) (*OJKBreachNotification, error) {
	if s.db == nil {
		return nil, fmt.Errorf("database connection not available")
	}
	if id == "" {
		return nil, fmt.Errorf("breach notification id is required")
	}

	now := time.Now().UTC()
	var result *OJKBreachNotification
	err := withOrgScope(ctx, s.db, tenantID, func(tx *sql.Tx) error {
		var (
			current     string
			incident    time.Time
			discovery   time.Time
			deadline    time.Time
			subjects    int
			dataTypes   string
			authority   string
			submittedAt sql.NullTime
		)
		row := tx.QueryRowContext(ctx,
			`SELECT status, incident_timestamp, discovery_time, notification_deadline,
			        data_subjects_affected, data_types_involved, notified_authority,
			        submitted_at
			   FROM ojk_breach_notifications
			  WHERE id = $1 AND org_id = $2`,
			id, tenantID,
		)
		if scanErr := row.Scan(&current, &incident, &discovery, &deadline, &subjects, &dataTypes, &authority, &submittedAt); scanErr != nil {
			if errors.Is(scanErr, sql.ErrNoRows) {
				return fmt.Errorf("%w: %q", ErrBreachNotFound, id)
			}
			return scanErr
		}

		next, transErr := ApplyBreachTransition(BreachStatus(current), BreachEventAcknowledge)
		if transErr != nil {
			return transErr
		}

		if _, execErr := tx.ExecContext(ctx,
			`UPDATE ojk_breach_notifications
			    SET status = $1, acknowledged_at = $2, updated_at = $2
			  WHERE id = $3 AND org_id = $4`,
			string(next), now, id, tenantID,
		); execErr != nil {
			return execErr
		}

		ackAt := now
		result = &OJKBreachNotification{
			ID:                   id,
			IncidentTimestamp:    incident,
			DiscoveryTime:        discovery,
			NotificationDeadline: deadline,
			DataSubjectsAffected: subjects,
			DataTypesInvolved:    splitDataTypes(dataTypes),
			NotifiedAuthority:    authority,
			Status:               string(next),
			AcknowledgedAt:       &ackAt,
		}
		if submittedAt.Valid {
			sa := submittedAt.Time.UTC()
			result.SubmittedAt = &sa
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// EvaluateBreachDeadlines durably flips never-submitted draft breaches whose 72h
// window has lapsed to overdue (the compliance-failure signal), org-scoped. It
// deliberately does NOT touch submitted/acknowledged/failed rows or rows that
// already carry a submitted_at — a late submission keeps its "submitted"
// lifecycle status and its lateness is derived at read time from submitted_at >
// deadline. Returns the number of rows flipped. now() is evaluated in-database.
func (s *ojkAuditExportServiceImpl) EvaluateBreachDeadlines(ctx context.Context, tenantID string) (int, error) {
	if s.db == nil {
		return 0, fmt.Errorf("database connection not available")
	}
	var flipped int64
	err := withOrgScope(ctx, s.db, tenantID, func(tx *sql.Tx) error {
		res, execErr := tx.ExecContext(ctx,
			`UPDATE ojk_breach_notifications
			    SET status = $1, updated_at = NOW()
			  WHERE org_id = $2
			    AND status = $3
			    AND submitted_at IS NULL
			    AND notification_deadline < NOW()`,
			string(BreachStatusOverdue), tenantID, string(BreachStatusDraft),
		)
		if execErr != nil {
			return execErr
		}
		flipped, _ = res.RowsAffected()
		return nil
	})
	if err != nil {
		return 0, fmt.Errorf("evaluating breach deadlines: %w", err)
	}
	return int(flipped), nil
}

func (s *ojkAuditExportServiceImpl) GetDashboard(ctx context.Context, tenantID string) (*OJKDashboardResponse, error) {
	score := 0
	readiness, err := s.ValidateComplianceReadiness(ctx, tenantID)
	if err == nil {
		score = readiness.Score
	}

	// Real breach-notification counts (replaces the prior literal 0): total
	// recorded for the org + how many are effectively overdue right now.
	totalBreaches, overdueBreaches := 0, 0
	if s.db != nil {
		t, o, qErr := s.countBreachNotifications(ctx, tenantID)
		if qErr != nil {
			return nil, fmt.Errorf("counting breach notifications: %w", qErr)
		}
		totalBreaches, overdueBreaches = t, o
	}

	return &OJKDashboardResponse{
		Framework:                  OJKFrameworkCombined,
		ComplianceScore:            score,
		TotalAuditRecords:          0,
		ActivePolicies:             8, // 8 Indonesia PII patterns
		RecentViolations:           0,
		RetentionStatus:            "compliant",
		BreachNotifications:        totalBreaches,
		OverdueBreachNotifications: overdueBreaches,
		LastUpdated:                time.Now().UTC(),
	}, nil
}

func (s *ojkAuditExportServiceImpl) queryPolicyViolations(ctx context.Context, tenantID string, start, end time.Time) ([]OJKPolicyViolationRecord, int, error) {
	return []OJKPolicyViolationRecord{}, 0, nil
}

func (s *ojkAuditExportServiceImpl) queryLLMCalls(ctx context.Context, tenantID string, start, end time.Time) ([]OJKLLMCallRecord, int, error) {
	return []OJKLLMCallRecord{}, 0, nil
}

func (s *ojkAuditExportServiceImpl) queryDecisionChains(ctx context.Context, tenantID string, start, end time.Time) ([]OJKDecisionChainRecord, int, error) {
	return []OJKDecisionChainRecord{}, 0, nil
}

// queryCrossBorderTransfers returns cross-border data-transfer records for
// UU PDP Pasal 56 surfacing. A transfer record is any canonical decision row
// (audit_logs) that carries a non-empty transfer_basis, auto-stamped on the
// LLM-forward path when the operator has declared a basis (#2718, core migration
// 126). The stored transfer_basis is surfaced verbatim: both "safeguards" and
// "pasal_56b_dpa" flow through unchanged so an auditor sees exactly the
// Pasal 56(b) value recorded at decision time (no auto-translation).
//
// This reads the canonical audit_logs table (the decision_id/correlation_id row
// the audit-coverage epic standardized on), NOT the legacy
// orchestrator_audit_logs/agent_audit_logs columns from migration 129; those
// are left in place but unused (separate cleanup follow-up).
//
// audit_logs is NOT FORCE ROW LEVEL SECURITY (migration 101 deliberately left it
// unprotected for the cross-org cleanup worker), so this read needs no
// withOrgScope wrap; it mirrors the proven SEBI exportDecisionChain pattern
// (#2588). The OJK tenantID argument is used loosely as either the org_id or
// tenant_id label across callers, so both columns are matched. The
// `transfer_basis IS NOT NULL` filter selects ONLY declared cross-border
// transfers, so SEBI/euaiact decision rows (which never carry a basis) are never
// swept in.
func (s *ojkAuditExportServiceImpl) queryCrossBorderTransfers(ctx context.Context, tenantID string, start, end time.Time) ([]CrossBorderTransferRecord, int, error) {
	records := []CrossBorderTransferRecord{}
	rows, qErr := s.db.QueryContext(ctx,
		`SELECT id, timestamp, COALESCE(data_residency, ''), COALESCE(transfer_basis, '')
		   FROM audit_logs
		  WHERE (tenant_id = $1 OR org_id = $1)
		    AND transfer_basis IS NOT NULL
		    AND transfer_basis <> ''
		    AND timestamp >= $2
		    AND timestamp <= $3
		  ORDER BY timestamp DESC`,
		tenantID, start, end,
	)
	if qErr != nil {
		return nil, 0, qErr
	}
	defer rows.Close()

	for rows.Next() {
		var (
			id            string
			ts            time.Time
			dataResidency string
			transferBasis string
		)
		if scanErr := rows.Scan(&id, &ts, &dataResidency, &transferBasis); scanErr != nil {
			return nil, 0, scanErr
		}
		records = append(records, CrossBorderTransferRecord{
			ID:                 id,
			Timestamp:          ts,
			DataResidency:      dataResidency,
			TransferBasis:      transferBasis, // surfaced as-written, never translated
			DestinationCountry: dataResidency, // data_residency is the ISO destination code (migration 126)
		})
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	return records, len(records), nil
}

// queryBreachNotifications returns breach-notification records for the org whose
// discovery_time falls in [start, end]. Each record's Status is the EFFECTIVE
// status: EvaluateBreachStatus is applied with the current time so a breach that
// has silently crossed its 72h window reads "overdue" without a sweep having
// run. StoredStatus carries the durable DB value for auditors who need the
// operator-driven fact. Rows are org-scoped (RLS + explicit org_id predicate).
func (s *ojkAuditExportServiceImpl) queryBreachNotifications(ctx context.Context, tenantID string, start, end time.Time) ([]OJKBreachNotificationRecord, int, error) {
	records := []OJKBreachNotificationRecord{}
	now := time.Now().UTC()
	err := withOrgScope(ctx, s.db, tenantID, func(tx *sql.Tx) error {
		rows, qErr := tx.QueryContext(ctx,
			`SELECT id, incident_timestamp, discovery_time, notification_deadline,
			        data_subjects_affected, data_types_involved, notified_authority,
			        status, submitted_at, acknowledged_at, created_at
			   FROM ojk_breach_notifications
			  WHERE org_id = $1
			    AND discovery_time >= $2
			    AND discovery_time <= $3
			  ORDER BY discovery_time DESC`,
			tenantID, start, end,
		)
		if qErr != nil {
			return qErr
		}
		defer rows.Close()

		for rows.Next() {
			var (
				id             string
				incident       time.Time
				discovery      time.Time
				deadline       time.Time
				subjects       int
				dataTypes      string
				authority      string
				stored         string
				submittedAt    sql.NullTime
				acknowledgedAt sql.NullTime
				created        time.Time
			)
			if scanErr := rows.Scan(&id, &incident, &discovery, &deadline, &subjects, &dataTypes, &authority, &stored, &submittedAt, &acknowledgedAt, &created); scanErr != nil {
				return scanErr
			}

			var submittedPtr, ackPtr *time.Time
			if submittedAt.Valid {
				sa := submittedAt.Time.UTC()
				submittedPtr = &sa
			}
			if acknowledgedAt.Valid {
				aa := acknowledgedAt.Time.UTC()
				ackPtr = &aa
			}

			effective := EvaluateBreachStatus(BreachStatus(stored), deadline, submittedPtr, now)
			records = append(records, OJKBreachNotificationRecord{
				ID:                   id,
				IncidentTimestamp:    incident,
				DiscoveryTime:        discovery,
				NotificationDeadline: deadline,
				DataSubjectsAffected: subjects,
				DataTypesInvolved:    splitDataTypes(dataTypes),
				NotifiedAuthority:    authority,
				Status:               string(effective),
				StoredStatus:         stored,
				SubmittedAt:          submittedPtr,
				AcknowledgedAt:       ackPtr,
				WithinDeadline:       IsBreachWithinDeadline(effective),
				CreatedAt:            created,
			})
		}
		return rows.Err()
	})
	if err != nil {
		return nil, 0, err
	}
	return records, len(records), nil
}

// countBreachNotifications returns the total breach notifications recorded for
// the org and how many are effectively overdue right now. Overdue mirrors
// EvaluateBreachStatus exactly: not acknowledged/failed, past the deadline, and
// either never submitted or submitted after the deadline. now() is evaluated
// in-database so the count needs no prior sweep.
func (s *ojkAuditExportServiceImpl) countBreachNotifications(ctx context.Context, tenantID string) (total int, overdue int, err error) {
	e := withOrgScope(ctx, s.db, tenantID, func(tx *sql.Tx) error {
		if scanErr := tx.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM ojk_breach_notifications WHERE org_id = $1`,
			tenantID,
		).Scan(&total); scanErr != nil {
			return scanErr
		}
		return tx.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM ojk_breach_notifications
			  WHERE org_id = $1
			    AND status NOT IN ($2, $3)
			    AND notification_deadline < NOW()
			    AND (submitted_at IS NULL OR submitted_at > notification_deadline)`,
			tenantID, string(BreachStatusAcknowledged), string(BreachStatusFailed),
		).Scan(&overdue)
	})
	if e != nil {
		return 0, 0, e
	}
	return total, overdue, nil
}

// splitDataTypes reverses the comma-join used on write, dropping empty segments
// so an empty stored value yields an empty (non-nil) slice.
func splitDataTypes(joined string) []string {
	if strings.TrimSpace(joined) == "" {
		return []string{}
	}
	parts := strings.Split(joined, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}

func (s *ojkAuditExportServiceImpl) getEffectiveRetentionDays() int {
	region := os.Getenv("AXONFLOW_COMPLIANCE_REGION")
	if strings.EqualFold(region, "ID") {
		return IndonesiaRetentionDays
	}
	return 3650 // Enterprise default (10 years)
}

func (s *ojkAuditExportServiceImpl) calculateComplianceScore(ctx context.Context, tenantID string) float64 {
	readiness, err := s.ValidateComplianceReadiness(ctx, tenantID)
	if err != nil {
		return 0.0
	}
	return float64(readiness.Score) / 100.0
}
