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

// ExportAuditData produces the OJK / BI / UU PDP regulator pack for one
// organisation and window.
//
// orgID is the ORGANISATION the export is scoped to (resolveOrgID). Every
// section query predicates on it explicitly; audit_logs has no RLS, so that
// predicate IS the tenant boundary.
//
// # What changed, and why the old shape had to go
//
// The previous dispatcher was a fallthrough chain whose `default: continue`
// swallowed any data type it did not recognise. Two DECLARED types
// (hitl_oversight, pii_redactions) had no case at all, so requesting either
// returned HTTP 200 with a successful, empty, indistinguishable-from-"nothing
// happened" section -- the worst possible answer to a regulator. Three more
// were served by `return []T{}, 0, nil` stubs.
//
// The replacement is exhaustive BY CONSTRUCTION: sections are dispatched
// through ojkSectionHandlers(), whose key set is driven from ojkAllDataTypes(),
// and a lookup MISS produces an explicit per-section error rather than silence.
// A test walks the declared OJKAuditDataType constants and fails if any lacks a
// handler, so adding a constant without wiring it can no longer degrade to an
// empty section.
//
// # Failure posture
//
// A failing section does NOT fail the whole export: the other sections are
// still evidence, and a regulator pack that 500s because one table is missing
// is less useful than one that says which section could not be served. Each
// section reports its own report_state and error, and the summary rolls them
// up. The response Status stays "completed" -- the export did complete; read
// summary.report_state and summary.sections for what is in it.
func (s *ojkAuditExportServiceImpl) ExportAuditData(ctx context.Context, orgID string, req *OJKAuditExportRequest) (*OJKAuditExportResponse, error) {
	if s.db == nil {
		return nil, fmt.Errorf("database connection not available")
	}
	if strings.TrimSpace(orgID) == "" {
		return nil, errOrgScopeRequired
	}

	startDate, err := time.Parse("2006-01-02", req.StartDate)
	if err != nil {
		return nil, fmt.Errorf("invalid start_date: %w", err)
	}
	endDate, err := time.Parse("2006-01-02", req.EndDate)
	if err != nil {
		return nil, fmt.Errorf("invalid end_date: %w", err)
	}
	// end_date is a DATE; a caller asking for 2026-08-03 means the whole of that
	// day. Parsed as-is it is midnight, so every row after 00:00:00 on the final
	// day silently fell outside the window. Extend to the end of the day.
	//
	// The window is UTC at BOTH ends, deliberately and explicitly: audit_logs
	// timestamps are written UTC, so a UTC window slices them without an offset
	// artefact. An Indonesian reader should know that a request for
	// "2026-08-03" therefore covers 2026-08-03T00:00Z..T23:59Z, which is
	// 07:00..07:00 WIB (UTC+7), not local midnight to midnight. Interpreting the
	// dates in WIB would make the boundary depend on a deployment config value
	// and silently re-slice every historical export; the documented UTC window
	// is the honest choice and is stated in the API reference.
	endDate = endDate.Add(24*time.Hour - time.Nanosecond)

	if req.Format == "" {
		req.Format = OJKFormatJSON
	}
	if req.Framework == "" {
		req.Framework = OJKFrameworkCombined
	}

	profile := resolveFrameworkProfile(req.Framework)
	requested, fromFramework := resolveRequestedDataTypes(req.DataTypes, profile)
	handlers := ojkSectionHandlers()

	data := &OJKAuditExportData{}
	recordsByType := make(map[string]int, len(requested))
	sections := make([]OJKSectionStatus, 0, len(requested))
	totalRecords := 0

	for _, dt := range requested {
		status := OJKSectionStatus{
			DataType:         dt,
			InFrameworkScope: profile.inScope(dt),
		}

		handler, known := handlers[dt]
		if !known {
			// EXPLICIT, not silent. This is the class the old `default: continue`
			// hid: an unknown or not-yet-implemented data type now names itself.
			status.ReportState = OJKReportStateNotAvailable
			status.ErrorKind = OJKSectionErrorNotImplemented
			status.Error = fmt.Sprintf("unknown data type %q: no export section is implemented for it (supported: %s)",
				string(dt), joinDataTypes(ojkAllDataTypes()))
			sections = append(sections, status)
			continue
		}

		res := handler(ctx, s, orgID, startDate, endDate, data)
		status.RecordCount = res.count
		switch {
		case res.err != nil:
			// Both a missing table and a hard query failure are not_available --
			// the section could not be produced either way, and neither may be
			// read as a clean zero. They are DISTINGUISHED by ErrorKind, because
			// "this deployment structurally cannot produce human-oversight
			// evidence" and "that read failed once" are different things to tell
			// a regulator. Before this the `unavailable` flag was computed and
			// never surfaced.
			status.ReportState = OJKReportStateNotAvailable
			status.ErrorKind = OJKSectionErrorQueryFailed
			if res.unavailable {
				status.ErrorKind = OJKSectionErrorStoreAbsent
			}
			status.Error = res.err.Error()
		case res.count == 0:
			status.ReportState = OJKReportStateEnabledEmpty
		default:
			status.ReportState = OJKReportStatePopulated
		}
		if status.Error == "" {
			recordsByType[string(dt)] = res.count
			totalRecords += res.count
		}
		status.Note = sectionNote(profile, dt, res, status)
		sections = append(sections, status)
	}

	// Checksum over the DATA only -- the summary, timestamps and export id are
	// excluded so re-running the SAME request over the SAME rows is verifiably
	// reproducible. It is NOT stable across frameworks: a framework selects the
	// sections, so BI_PJP (no model-activity register) and OJK_BI_COMBINED over
	// identical rows legitimately produce different data and different
	// checksums. An auditor comparing two packs must compare like for like.
	dataJSON, marshalErr := json.Marshal(data)
	if marshalErr != nil {
		return nil, fmt.Errorf("serializing export data: %w", marshalErr)
	}
	hash := sha256.Sum256(dataJSON)
	checksum := hex.EncodeToString(hash[:])

	summary := &OJKAuditExportSummary{
		TotalRecords:  totalRecords,
		RecordsByType: recordsByType,
		DateRange: DateRange{
			Start: startDate,
			End:   endDate,
		},
		ReportState:      rollUpReportState(sections),
		Sections:         sections,
		FrameworkSummary: profile.frameworkSummary(req.Framework),
	}
	// The compliance score rides on every export, so it must carry the same
	// observability qualifier the readiness endpoint does -- a bare float that
	// cannot say "four of five dimensions were unreadable" is exactly the kind of
	// unqualified number a regulator pack should not contain.
	if readiness, rErr := s.ValidateComplianceReadiness(ctx, orgID); rErr == nil {
		summary.ComplianceScore = float64(readiness.Score) / 100.0
		summary.ComplianceScoreUnknownChecks = readiness.UnknownChecks
	} else {
		summary.ComplianceScore = 0
		summary.ComplianceScoreUnknownChecks = -1
	}
	if !fromFramework {
		summary.FrameworkSummary.Notes = strings.TrimSpace(summary.FrameworkSummary.Notes +
			" Sections were selected by an explicit data_types request, not by the framework; out-of-scope sections are flagged per section.")
	}

	// The body this handler writes is ALWAYS JSON (writeJSON sets
	// Content-Type: application/json and marshals Data inline). csv and xml are
	// accepted by the request validator and are produced by no renderer on this
	// endpoint -- the async facade owns rendering (#2892 D2). So the response
	// reports the format it IS, and says so explicitly when that differs from
	// what was asked for, rather than echoing the request back as a label on
	// content that does not match it.
	producedFormat := OJKFormatJSON
	requestedFormat := OJKExportFormat("")
	formatNote := ""
	if req.Format != OJKFormatJSON {
		requestedFormat = req.Format
		formatNote = fmt.Sprintf(
			"This response body is JSON. %q was requested but is not produced by this endpoint; "+
				"the data is inline above. Use the compliance-report facade for rendered output.",
			string(req.Format))
	}

	return &OJKAuditExportResponse{
		ExportID:        uuid.New().String(),
		Status:          "completed",
		Framework:       req.Framework,
		Format:          producedFormat,
		RequestedFormat: requestedFormat,
		FormatNote:      formatNote,
		Summary:         summary,
		Data:            data,
		CreatedAt:       time.Now().UTC(),
		Metadata: &OJKExportMetadata{
			ExportVersion: ojkExportVersion,
			GeneratedBy:   "axonflow-ojk-module",
			TenantID:      orgID,
			Checksum:      checksum,
		},
	}, nil
}

// ojkExportVersion is bumped when the export CONTRACT changes in a way a
// consumer must notice. 2.0.0: per-section report_state + explicit section
// errors + framework-driven section selection (#3242). A 1.0.0 consumer that
// inferred "module not enabled" from an empty body must move to
// summary.report_state.
const ojkExportVersion = "2.0.0"

// sectionHandler produces one export section, writing its records into data and
// returning the outcome. Signature is uniform across sections so the dispatcher
// is a table lookup rather than a switch that can grow a silent default.
type sectionHandler func(ctx context.Context, s *ojkAuditExportServiceImpl, orgID string, start, end time.Time, data *OJKAuditExportData) sectionResult

// ojkSectionHandlers is the single dispatch table. Its key set MUST equal
// ojkAllDataTypes(); TestEveryDeclaredDataTypeHasASectionHandler enforces that
// against the DECLARED OJKAuditDataType constants (parsed from source), so a
// new constant without a handler fails a test instead of silently producing an
// empty section.
func ojkSectionHandlers() map[OJKAuditDataType]sectionHandler {
	return map[OJKAuditDataType]sectionHandler{
		OJKDataTypePolicyViolations: func(ctx context.Context, s *ojkAuditExportServiceImpl, orgID string, start, end time.Time, data *OJKAuditExportData) sectionResult {
			records, res := s.queryPolicyViolations(ctx, orgID, start, end)
			data.PolicyViolations = records
			return res
		},
		OJKDataTypeLLMCalls: func(ctx context.Context, s *ojkAuditExportServiceImpl, orgID string, start, end time.Time, data *OJKAuditExportData) sectionResult {
			records, res := s.queryLLMCalls(ctx, orgID, start, end)
			data.LLMCalls = records
			return res
		},
		OJKDataTypeDecisionChain: func(ctx context.Context, s *ojkAuditExportServiceImpl, orgID string, start, end time.Time, data *OJKAuditExportData) sectionResult {
			records, res := s.queryDecisionChains(ctx, orgID, start, end)
			data.DecisionChains = records
			data.DecisionChainGroups = groupOJKDecisionChains(records)
			return res
		},
		OJKDataTypeHITLOversight: func(ctx context.Context, s *ojkAuditExportServiceImpl, orgID string, start, end time.Time, data *OJKAuditExportData) sectionResult {
			records, res := s.queryHITLOversight(ctx, orgID, start, end)
			data.HITLRecords = records
			return res
		},
		OJKDataTypePIIRedactions: func(ctx context.Context, s *ojkAuditExportServiceImpl, orgID string, start, end time.Time, data *OJKAuditExportData) sectionResult {
			records, res := s.queryPIIRedactions(ctx, orgID, start, end)
			data.PIIRedactions = records
			return res
		},
		OJKDataTypeCrossBorder: func(ctx context.Context, s *ojkAuditExportServiceImpl, orgID string, start, end time.Time, data *OJKAuditExportData) sectionResult {
			records, res := s.queryCrossBorderTransfers(ctx, orgID, start, end)
			data.CrossBorder = records
			return res
		},
		OJKDataTypeBreachNotify: func(ctx context.Context, s *ojkAuditExportServiceImpl, orgID string, start, end time.Time, data *OJKAuditExportData) sectionResult {
			records, res := s.queryBreachNotifications(ctx, orgID, start, end)
			data.BreachNotifications = records
			return res
		},
	}
}

// rollUpReportState reduces the per-section states to one summary state.
// populated wins over everything (there IS evidence); not_available is reported
// only when NO section could be served, so one missing table never makes a
// populated pack read as "module not enabled".
func rollUpReportState(sections []OJKSectionStatus) OJKReportState {
	if len(sections) == 0 {
		return OJKReportStateNotAvailable
	}
	allUnavailable := true
	for _, sec := range sections {
		if sec.ReportState == OJKReportStatePopulated {
			return OJKReportStatePopulated
		}
		if sec.ReportState != OJKReportStateNotAvailable {
			allUnavailable = false
		}
	}
	if allUnavailable {
		return OJKReportStateNotAvailable
	}
	return OJKReportStateEnabledEmpty
}

// sectionNote explains a section to the reader: the framework relevance when it
// is in scope, why it is present when it is not, and any truncation.
func sectionNote(p frameworkProfile, dt OJKAuditDataType, res sectionResult, status OJKSectionStatus) string {
	parts := make([]string, 0, 2)
	if status.InFrameworkScope {
		if rel := p.relevance[dt]; rel != "" {
			parts = append(parts, rel)
		}
	} else if status.Error == "" {
		parts = append(parts, "Supplementary: explicitly requested, outside the selected framework's scope.")
	}
	if res.truncated {
		parts = append(parts, fmt.Sprintf("TRUNCATED at the %d-row section limit; narrow the date range for a complete section.", ojkSectionLimit))
	}
	return strings.Join(parts, " ")
}

// joinDataTypes renders a data-type list for an error message.
func joinDataTypes(types []OJKAuditDataType) string {
	out := make([]string, 0, len(types))
	for _, t := range types {
		out = append(out, string(t))
	}
	return strings.Join(out, ", ")
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

// GetRetentionStatus is implemented in retention.go, where each data type's
// entry is derived from its backing store rather than returned as an
// unconditional empty slice.

// ValidateComplianceReadiness is implemented in readiness.go, where each check
// QUERIES the state it claims to measure or reports "unknown".

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

// GetDashboard is implemented in readiness.go, where every count is derived
// from an org-scoped query rather than a literal.

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
// (#2588). The `transfer_basis IS NOT NULL` filter selects ONLY declared
// cross-border transfers, so SEBI/euaiact decision rows (which never carry a
// basis) are never swept in.
//
// TENANCY (#3242): the predicate was `(tenant_id = $1 OR org_id = $1)`, a
// cross-tenant leak with no RLS backstop on this table. It now uses the shared
// ojkOrgPredicate, which every audit_logs read in this module uses verbatim --
// see its doc comment for why neither the bare OR nor a bare `org_id = $1` is
// correct.
func (s *ojkAuditExportServiceImpl) queryCrossBorderTransfers(ctx context.Context, orgID string, start, end time.Time) ([]CrossBorderTransferRecord, sectionResult) {
	records := []CrossBorderTransferRecord{}
	if strings.TrimSpace(orgID) == "" {
		return records, sectionResult{err: errOrgScopeRequired}
	}
	rows, qErr := s.db.QueryContext(ctx,
		`SELECT id, timestamp, COALESCE(data_residency, ''), COALESCE(transfer_basis, '')
		   FROM audit_logs
		  WHERE `+ojkOrgPredicate+`
		    AND transfer_basis IS NOT NULL
		    AND transfer_basis <> ''
		    AND timestamp >= $2
		    AND timestamp <= $3
		  ORDER BY timestamp DESC
		  LIMIT $4`,
		orgID, start, end, ojkSectionLimit,
	)
	if qErr != nil {
		if isUndefinedTableErr(qErr) {
			return records, sectionResult{unavailable: true, err: fmt.Errorf("audit_logs is not present on this deployment: %w", qErr)}
		}
		return records, sectionResult{err: qErr}
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
			return records, sectionResult{err: scanErr}
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
		return records, sectionResult{err: err}
	}
	return records, sectionResult{count: len(records), truncated: len(records) == ojkSectionLimit}
}

// queryBreachNotifications returns breach-notification records for the org whose
// discovery_time falls in [start, end]. Each record's Status is the EFFECTIVE
// status: EvaluateBreachStatus is applied with the current time so a breach that
// has silently crossed its 72h window reads "overdue" without a sweep having
// run. StoredStatus carries the durable DB value for auditors who need the
// operator-driven fact. Rows are org-scoped (RLS + explicit org_id predicate).
func (s *ojkAuditExportServiceImpl) queryBreachNotifications(ctx context.Context, orgID string, start, end time.Time) ([]OJKBreachNotificationRecord, sectionResult) {
	records := []OJKBreachNotificationRecord{}
	if strings.TrimSpace(orgID) == "" {
		return records, sectionResult{err: errOrgScopeRequired}
	}
	now := time.Now().UTC()
	err := withOrgScope(ctx, s.db, orgID, func(tx *sql.Tx) error {
		rows, qErr := tx.QueryContext(ctx,
			`SELECT id, incident_timestamp, discovery_time, notification_deadline,
			        data_subjects_affected, data_types_involved, notified_authority,
			        status, submitted_at, acknowledged_at, created_at
			   FROM ojk_breach_notifications
			  WHERE org_id = $1
			    AND discovery_time >= $2
			    AND discovery_time <= $3
			  ORDER BY discovery_time DESC
			  LIMIT $4`,
			orgID, start, end, ojkSectionLimit,
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
		if isUndefinedTableErr(err) {
			return records, sectionResult{unavailable: true, err: fmt.Errorf("ojk_breach_notifications is not present on this deployment (enterprise migration 130 not applied): %w", err)}
		}
		return records, sectionResult{err: err}
	}
	return records, sectionResult{count: len(records), truncated: len(records) == ojkSectionLimit}
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
