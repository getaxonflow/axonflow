// Copyright 2026 AxonFlow
//
// Licensed under the Business Source License 1.1 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License in the LICENSE file or at
// https://mariadb.com/bsl11/
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.

package orchestrator

// audit_read_handlers.go — WS-2 (#2755 / #2756 / #2757).
//
// Read/report/export surface over audit_logs that the customer portal's log UX
// is built against:
//
//   - GET  /api/v1/audit/{id}      — full single-record detail (expandable row)
//   - POST /api/v1/audit/export    — bounded CSV/JSON export of filtered rows
//   - POST /api/v1/audit/report    — per-action counts + latency + top policies
//
// Every handler forces tenant scoping from the trusted X-Tenant-ID header (set
// by the auth middleware / portal proxy) exactly like auditSearchHandler — a
// missing or client-controlled tenant filter would leak cross-tenant rows.
//
// Redaction is preserved end-to-end: these handlers only ever return the
// query / response_sample columns as they are already stored in audit_logs.
// The write path masks PII before persistence, so reading a row back cannot
// surface raw PII the engine redacted; nothing here re-derives raw content.
//
// New funcs only — this file does not touch the WS-1 write path
// (auditToolCallHandler / ToolCallAuditEntry / LogToolCallAudit).

import (
	"context"
	"database/sql"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/lib/pq"

	sharedaudit "axonflow/platform/shared/audit"
	sharedidentity "axonflow/platform/shared/identity"
	logutil "axonflow/platform/shared/logger"
)

// ErrAuditLogNotFound is returned by GetAuditLogByID when no row matches the id
// within the caller's tenant scope. Callers map it to HTTP 404.
var ErrAuditLogNotFound = errors.New("audit log not found")

// auditExportMaxRows bounds a single export so a wide date range can't OOM the
// orchestrator or the portal proxy. A caller that hits the cap gets the most
// recent auditExportMaxRows rows (ORDER BY timestamp DESC) and the response
// carries an X-Audit-Export-Truncated: true header so the UI can warn. This cap
// is documented in the #2756 PR and the endpoint's error/response contract.
const auditExportMaxRows = 50000

// GetAuditLogByID returns the full audit record for id, scoped to tenantID.
//
// tenantID MUST be the trusted X-Tenant-ID value: the WHERE clause filters on
// it so a caller can never read another tenant's record by guessing an id
// (cross-tenant leak guard, mirroring auditSearchHandler's tenant filter).
// Returns ErrAuditLogNotFound when no row matches within the tenant scope —
// deliberately indistinguishable from "id belongs to another tenant" so the
// endpoint is not a cross-tenant existence oracle.
//
// session_id completes the #2755 detail contract; its column lands via WS-1's
// migration core/129 (#2754) and is populated by the write path (X-Session-Id →
// audit_logs.session_id). COALESCE keeps pre-129 rows returning "".
func (l *AuditLogger) GetAuditLogByID(id, tenantID string) (*AuditEntry, error) {
	if l.db == nil {
		return nil, ErrAuditLogNotFound
	}

	const q = `
		SELECT id, request_id, timestamp, user_id, user_email, user_role,
		       client_id, tenant_id, COALESCE(org_id, ''), request_type, query,
		       policy_decision, policy_details, provider, model, response_time_ms,
		       tokens_used, cost, redacted_fields, error_message, response_sample,
		       compliance_flags, COALESCE(correlation_id, ''),
		       COALESCE(decision_id, ''), COALESCE(plane, ''), COALESCE(session_id, '')
		FROM audit_logs
		WHERE id = $1 AND tenant_id = $2
	`

	entry := &AuditEntry{}
	var policyDetailsJSON, redactedFieldsJSON, complianceFlagsJSON []byte
	var provider, model, errorMessage, responseSample sql.NullString
	var responseTime, tokensUsed sql.NullInt64
	var cost sql.NullFloat64

	err := l.db.QueryRow(q, id, tenantID).Scan(
		&entry.ID, &entry.RequestID, &entry.Timestamp, &entry.UserID,
		&entry.UserEmail, &entry.UserRole, &entry.ClientID, &entry.TenantID,
		&entry.OrgID, &entry.RequestType, &entry.Query, &entry.PolicyDecision,
		&policyDetailsJSON, &provider, &model, &responseTime, &tokensUsed, &cost,
		&redactedFieldsJSON, &errorMessage, &responseSample, &complianceFlagsJSON,
		&entry.CorrelationID, &entry.DecisionID, &entry.Plane, &entry.SessionID,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrAuditLogNotFound
	}
	if err != nil {
		return nil, err
	}

	entry.Provider = provider.String
	entry.Model = model.String
	entry.ErrorMessage = errorMessage.String
	entry.ResponseSample = responseSample.String
	entry.ResponseTime = nullLatencyPtr(responseTime)
	entry.TokensUsed = nullTokensPtr(tokensUsed)
	entry.Cost = nullCostPtr(cost)

	// policy_details carries the nested detail the #2755 contract asks for:
	// policy_ids / reasons / latency_ms plus gateway_id and tool_name, exactly
	// as the writers stored them. Surfacing the map verbatim keeps redaction
	// intact (no re-derivation) and avoids a lossy re-shape.
	_ = json.Unmarshal(policyDetailsJSON, &entry.PolicyDetails)
	_ = json.Unmarshal(redactedFieldsJSON, &entry.RedactedFields)
	_ = json.Unmarshal(complianceFlagsJSON, &entry.ComplianceFlags)

	return entry, nil
}

// auditSearchMethodNotAllowedHandler serves GET/HEAD /api/v1/audit/search.
//
// #3060: audit search takes its criteria as a JSON request body, so it is
// POST-only. Before this handler existed a GET fell through to the greedy
// GET /api/v1/audit/{id} route with id="search" and came back 404 "audit
// record not found" — a status and a message that both describe the wrong
// thing, pointing an operator at a missing-data theory instead of at their
// HTTP method. 405 + a populated Allow header is the honest answer, and it
// keeps the endpoint self-describing for anyone probing the API by hand.
//
// Deliberately NOT a working GET variant: a query-string mirror of the search
// criteria would be a second, silently-diverging spelling of a contract the
// SDKs and plugins already drive over POST (see axonflow-client.ts
// searchAuditEvents / searchAuditEventsStrict). One shape, one code path.
func auditSearchMethodNotAllowedHandler(w http.ResponseWriter, r *http.Request) {
	// Set before sendErrorResponse — it writes the status line, after which
	// header mutations are silently dropped.
	w.Header().Set("Allow", "POST, OPTIONS")
	sendErrorResponse(w,
		"audit search requires POST /api/v1/audit/search with a JSON criteria body (start_time, end_time, limit, …); GET is not supported on this endpoint",
		http.StatusMethodNotAllowed)
}

// auditGetByIDHandler serves GET /api/v1/audit/{id}.
func auditGetByIDHandler(w http.ResponseWriter, r *http.Request) {
	tenantID := r.Header.Get("X-Tenant-ID")
	if tenantID == "" {
		log.Printf("[audit/detail] BLOCKED: missing X-Tenant-ID header from %s", r.RemoteAddr)
		sendErrorResponse(w, "tenant scoping required", http.StatusUnauthorized)
		return
	}

	id := mux.Vars(r)["id"]
	if id == "" {
		sendErrorResponse(w, "audit id required", http.StatusBadRequest)
		return
	}

	if auditLogger == nil {
		sendErrorResponse(w, "audit subsystem unavailable", http.StatusServiceUnavailable)
		return
	}

	// #3060 (#2991 coverage gap): resolve + stamp the read scope BEFORE the
	// lookup so the header and the fail-closed log line go out on EVERY
	// outcome — including the 404 a scoped-out caller receives, which is by
	// design indistinguishable in the BODY from "no such record" (non-oracle).
	// The header is the operator-side channel that tells the two apart; the
	// client-visible body is unchanged, and nothing keys authorization off it.
	scope := resolveCallerReadScope(r)
	applyReadScopeHeader(w, r, scope)

	entry, err := auditLogger.GetAuditLogByID(id, tenantID)
	if errors.Is(err, ErrAuditLogNotFound) {
		sendErrorResponse(w, "audit record not found", http.StatusNotFound)
		return
	}
	if err != nil {
		log.Printf("[audit/detail] query failed for id=%s tenant=%s: %v",
			logutil.Sanitize(id), logutil.Sanitize(tenantID), err)
		sendErrorResponse(w, "audit detail lookup failed", http.StatusInternalServerError)
		return
	}

	// #2922 role-scoped reads: a non-tenant-wide caller may fetch only their
	// own rows. Same 404 as "no such id" — NOT 403 — so the endpoint is not a
	// cross-user existence oracle (mirrors the cross-tenant posture above).
	// Rows written without per-user attribution (blank user_email) are hidden
	// from non-admins by the same comparison (fail-closed).
	if !scope.TenantWide {
		if scope.UserEmail == "" ||
			sharedidentity.CanonicalEmail(entry.UserEmail) != scope.UserEmail {
			sendErrorResponse(w, "audit record not found", http.StatusNotFound)
			return
		}
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(entry); err != nil {
		log.Printf("[audit/detail] error encoding response: %v", err)
	}
}

// ExportAuditLogs returns up to auditExportMaxRows rows matching the criteria,
// tenant-scoped, newest first. The bool return is true when the result was
// truncated at the cap (there were more matching rows). It shares the exact
// filter semantics of SearchAuditLogs (user_email ILIKE, canonical action
// expansion, date range) so an export always reconciles with the on-screen
// search for the same filters. crit.TenantID MUST already be the trusted
// header value; this method does not read headers.
func (l *AuditLogger) ExportAuditLogs(crit auditSearchCriteria) ([]*AuditEntry, bool, error) {
	if l.db == nil {
		return []*AuditEntry{}, false, nil
	}
	if crit.TenantID == "" {
		// Defense in depth: never run an unscoped export even if a caller
		// forgets to set it. The handler already rejects the missing header.
		return nil, false, errors.New("export requires tenant scope")
	}

	rowCap := crit.Limit
	if rowCap <= 0 || rowCap > auditExportMaxRows {
		rowCap = auditExportMaxRows
	}

	query := `
		SELECT id, request_id, timestamp, user_id, user_email, user_role,
		       client_id, tenant_id, COALESCE(org_id, ''), request_type, query,
		       policy_decision, policy_details, provider, model, response_time_ms,
		       tokens_used, cost, redacted_fields, error_message, response_sample,
		       COALESCE(correlation_id, ''), COALESCE(session_id, '')
		FROM audit_logs
		WHERE tenant_id = $1
	`
	args := []interface{}{crit.TenantID}
	argIndex := 2

	// #2922 enforced read scope — exact canonical-email predicate, first, so a
	// caller filter can only narrow it (see SearchAuditLogs for the full
	// rationale; the two must stay in lockstep so an export always reconciles
	// with the on-screen search under the same scope).
	if crit.ScopeUserEmail != "" {
		query += fmt.Sprintf(" AND LOWER(user_email) = $%d", argIndex)
		args = append(args, strings.ToLower(crit.ScopeUserEmail))
		argIndex++
	}
	if crit.UserEmail != "" {
		query += fmt.Sprintf(" AND user_email ILIKE '%%' || $%d || '%%'", argIndex)
		args = append(args, crit.UserEmail)
		argIndex++
	}
	if crit.ClientID != "" {
		query += fmt.Sprintf(" AND client_id ILIKE '%%' || $%d || '%%'", argIndex)
		args = append(args, crit.ClientID)
		argIndex++
	}
	if crit.SessionID != "" {
		// Exact match, mirroring SearchAuditLogs' session_id drill-down
		// (#2857): a session-filtered export must reconcile with the on-screen
		// search for the same session bucket.
		query += fmt.Sprintf(" AND session_id = $%d", argIndex)
		args = append(args, crit.SessionID)
		argIndex++
	}
	// Plugin Batch 1 filters (decision_id / policy_name / override_id), identical
	// to SearchAuditLogs. Without these an export narrowed by one of them in the
	// search API silently returned the whole tenant window (same silent-dropped-
	// filter class as the session_id gap #2857 fixed) — a "filtered" export must
	// carry every filter the search endpoint honors.
	if crit.DecisionID != "" {
		query += fmt.Sprintf(" AND policy_details->>'decision_id' = $%d", argIndex)
		args = append(args, crit.DecisionID)
		argIndex++
	}
	if crit.PolicyName != "" {
		// Three shapes audit writers use — scalar, CSV-ish, and nested
		// policy_matches[*].policy_name — identical to SearchAuditLogs so a
		// policy-name-filtered export reconciles with the on-screen search.
		query += fmt.Sprintf(" AND ("+
			"policy_details->>'policy_name' = $%d "+
			"OR policy_details->>'policy_names' LIKE '%%' || $%d || '%%' "+
			"OR EXISTS (SELECT 1 FROM jsonb_array_elements(policy_details->'policy_matches') AS _pm WHERE _pm->>'policy_name' = $%d)"+
			")", argIndex, argIndex, argIndex)
		args = append(args, crit.PolicyName)
		argIndex++
	}
	if crit.OverrideID != "" {
		query += fmt.Sprintf(" AND policy_details->>'override_id' = $%d", argIndex)
		args = append(args, crit.OverrideID)
		argIndex++
	}
	if !crit.StartTime.IsZero() {
		query += fmt.Sprintf(" AND timestamp >= $%d", argIndex)
		args = append(args, crit.StartTime)
		argIndex++
	}
	if !crit.EndTime.IsZero() {
		query += fmt.Sprintf(" AND timestamp <= $%d", argIndex)
		args = append(args, crit.EndTime)
		argIndex++
	}
	if crit.Action != "" {
		// Canonical-first action filter, identical to SearchAuditLogs, so the
		// export matches every DB spelling the chosen verdict covers. This is the
		// last dynamic predicate, so argIndex is not incremented (nothing reads it
		// after) — matches SearchAuditLogs and keeps the linter happy.
		query += fmt.Sprintf(" AND policy_decision = ANY($%d)", argIndex)
		args = append(args, pq.Array(sharedaudit.Spellings(sharedaudit.Normalize(crit.Action))))
	}

	// Fetch cap+1 so we can report truncation without a second COUNT query.
	query += fmt.Sprintf(" ORDER BY timestamp DESC LIMIT %d", rowCap+1)

	rows, err := l.db.Query(query, args...)
	if err != nil {
		return nil, false, err
	}
	defer func() { _ = rows.Close() }()

	entries := make([]*AuditEntry, 0, rowCap)
	for rows.Next() {
		entry := &AuditEntry{}
		var policyDetailsJSON, redactedFieldsJSON []byte
		var provider, model, errorMessage, responseSample sql.NullString
		var responseTime, tokensUsed sql.NullInt64
		var cost sql.NullFloat64

		if err := rows.Scan(
			&entry.ID, &entry.RequestID, &entry.Timestamp, &entry.UserID,
			&entry.UserEmail, &entry.UserRole, &entry.ClientID, &entry.TenantID,
			&entry.OrgID, &entry.RequestType, &entry.Query, &entry.PolicyDecision,
			&policyDetailsJSON, &provider, &model, &responseTime, &tokensUsed, &cost,
			&redactedFieldsJSON, &errorMessage, &responseSample, &entry.CorrelationID,
			&entry.SessionID,
		); err != nil {
			log.Printf("[audit/export] error scanning row: %v", err)
			continue
		}

		entry.Provider = provider.String
		entry.Model = model.String
		entry.ErrorMessage = errorMessage.String
		entry.ResponseSample = responseSample.String
		entry.ResponseTime = nullLatencyPtr(responseTime)
		entry.TokensUsed = nullTokensPtr(tokensUsed)
		entry.Cost = nullCostPtr(cost)
		_ = json.Unmarshal(policyDetailsJSON, &entry.PolicyDetails)
		_ = json.Unmarshal(redactedFieldsJSON, &entry.RedactedFields)

		entries = append(entries, entry)
	}
	if err := rows.Err(); err != nil {
		return nil, false, err
	}

	truncated := false
	if len(entries) > rowCap {
		entries = entries[:rowCap]
		truncated = true
	}
	return entries, truncated, nil
}

// auditExportHandler serves POST /api/v1/audit/export?format=csv|json.
// Filters mirror /api/v1/audit/search (user_email, client_id, action, date
// range); tenant is forced from the header. The response is streamed and
// bounded by auditExportMaxRows.
func auditExportHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Tenant-ID, X-Org-ID")
		w.WriteHeader(http.StatusOK)
		return
	}

	tenantID := r.Header.Get("X-Tenant-ID")
	if tenantID == "" {
		log.Printf("[audit/export] BLOCKED: missing X-Tenant-ID header from %s", r.RemoteAddr)
		sendErrorResponse(w, "tenant scoping required", http.StatusUnauthorized)
		return
	}

	format := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("format")))
	if format == "" {
		format = "json"
	}
	if format != "csv" && format != "json" {
		sendErrorResponse(w, "format must be 'csv' or 'json'", http.StatusBadRequest)
		return
	}

	var body struct {
		UserEmail string `json:"user_email,omitempty"`
		ClientID  string `json:"client_id,omitempty"`
		Action    string `json:"action,omitempty"`
		// SessionID mirrors the /audit/search filter (#2857): without it a
		// session-filtered export silently returns the whole tenant window.
		SessionID string `json:"session_id,omitempty"`
		// Plugin Batch 1 filters — same silent-dropped-filter class as SessionID:
		// the search API honors these, so a filtered export must too.
		DecisionID string    `json:"decision_id,omitempty"`
		PolicyName string    `json:"policy_name,omitempty"`
		OverrideID string    `json:"override_id,omitempty"`
		StartTime  time.Time `json:"start_time"`
		EndTime    time.Time `json:"end_time"`
	}
	// Body is optional (empty body => unfiltered export within tenant + retention).
	// A present-but-malformed body is a client error.
	if r.Body != nil {
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil && !errors.Is(err, io.EOF) {
			sendErrorResponse(w, "invalid request body", http.StatusBadRequest)
			return
		}
	}

	if auditLogger == nil {
		sendErrorResponse(w, "audit subsystem unavailable", http.StatusServiceUnavailable)
		return
	}

	crit := auditSearchCriteria{
		UserEmail:  body.UserEmail,
		ClientID:   body.ClientID,
		Action:     body.Action,
		SessionID:  body.SessionID,
		DecisionID: body.DecisionID,
		PolicyName: body.PolicyName,
		OverrideID: body.OverrideID,
		TenantID:   tenantID,
		StartTime:  body.StartTime,
		EndTime:    body.EndTime,
		Limit:      auditExportMaxRows,
	}

	// #2922 role-scoped reads: an export must honor the same scope as search —
	// a non-tenant-wide caller exports only their own rows; the body's
	// user_email ILIKE filter can only narrow further. Empty identity ⇒ empty
	// export (fail-closed).
	scope := resolveCallerReadScope(r)
	applyReadScopeHeader(w, r, scope)
	if !scope.TenantWide {
		if scope.UserEmail == "" {
			ts := time.Now().UTC().Format("20060102-150405")
			if format == "csv" {
				writeAuditExportCSV(w, []*AuditEntry{}, ts)
				return
			}
			writeAuditExportJSON(w, []*AuditEntry{}, false, ts)
			return
		}
		crit.ScopeUserEmail = scope.UserEmail
	}

	// Apply the same tier-based retention floor as search so an export can't
	// reach past the tenant's allowed window.
	if auditCleanupService != nil {
		cutoff := auditCleanupService.RetentionCutoff()
		if !cutoff.IsZero() && (crit.StartTime.IsZero() || crit.StartTime.Before(cutoff)) {
			crit.StartTime = cutoff
		}
	}

	entries, truncated, err := auditLogger.ExportAuditLogs(crit)
	if err != nil {
		log.Printf("[audit/export] query failed for tenant=%s: %v", logutil.Sanitize(tenantID), err)
		sendErrorResponse(w, "audit export failed", http.StatusInternalServerError)
		return
	}

	if truncated {
		// Signal the cap-hit so the UI can warn the operator the file is partial.
		w.Header().Set("X-Audit-Export-Truncated", "true")
		w.Header().Set("X-Audit-Export-Row-Cap", strconv.Itoa(auditExportMaxRows))
	}

	ts := time.Now().UTC().Format("20060102-150405")
	if format == "csv" {
		writeAuditExportCSV(w, entries, ts)
		return
	}
	writeAuditExportJSON(w, entries, truncated, ts)
}

// auditExportCSVHeader is the CSV column order. Kept as a package var so the
// unit test can assert the header without duplicating the literal.
var auditExportCSVHeader = []string{
	"id", "timestamp", "user_email", "tenant_id", "org_id", "policy_decision",
	"request_type", "query", "response_sample", "provider", "model",
	"response_time_ms", "tokens", "correlation_id", "session_id",
}

// csvLatencyCell renders audit_logs.response_time_ms for the CSV export. It
// draws the same MEASURED-vs-UNMEASURED line as the portal's tile and its
// Latency column (#3424) -- an unmeasured row has no value, so the cell is
// EMPTY rather than "0" -- but it renders the measured side differently on
// purpose, and the difference is the point of the column:
//
//   - UNMEASURED -> empty. A "0" here is worse than on screen. The operator
//     opening this file in a spreadsheet gets a numeric column they will
//     average, chart or threshold, and every unmeasured row would vote that
//     average towards zero with nothing to signal it was never a measurement.
//     An empty cell is skipped by AVERAGE() in Excel and Sheets alike, which is
//     the same treatment sharedaudit.LatencyMeasuredPredicate gives it.
//   - MEASURED SUB-MILLISECOND -> "0", not the portal's "<1ms". This column is
//     numeric: "<1ms" would turn the whole column into text in a spreadsheet
//     and break the aggregate the empty cell above exists to protect. 0 is the
//     honest numeric form of the same fact -- the platform timed the decision
//     and it finished inside the column's 1ms resolution -- and it is what the
//     server itself averages.
func csvLatencyCell(ms *int64) string {
	if ms == nil {
		return ""
	}
	return strconv.FormatInt(*ms, 10)
}

// csvTokensCell is the token-count twin of csvLatencyCell (#3427 M19), and it
// exists for the harder half of the same argument: a row that recorded no
// provider usage has no token count, so its cell is not zero, it is absent.
// Writing "0" would put every governed BLOCK into an AVERAGE() or a SUM() over
// the column as a real zero-token call, which is precisely the population an
// analyst filters the export to look at. Empty is skipped by both
// spreadsheets. A measured zero, if a provider ever reports one, still renders
// as "0".
//
// "No RECORDED usage" is deliberately weaker than "never reached a model".
// Most of this population never did -- a blocked request, a redaction, a
// pre-check deny, a workflow step, a tool call -- but LogBlockedResponse runs
// AFTER the forward, so its rows ARE a paid-for round trip whose usage that
// writer does not record (a gap tracked separately). The empty cell is right
// for both: neither carries a measurement to export.
func csvTokensCell(tokens *int) string {
	if tokens == nil {
		return ""
	}
	return strconv.Itoa(*tokens)
}

func writeAuditExportCSV(w http.ResponseWriter, entries []*AuditEntry, ts string) {
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"audit-export-%s.csv\"", ts))
	w.WriteHeader(http.StatusOK)

	cw := csv.NewWriter(w)
	_ = cw.Write(auditExportCSVHeader)
	for _, e := range entries {
		// query / response_sample come straight from audit_logs (already
		// redacted by the write path) — never re-derived here. They ARE
		// attacker-influenceable (an audited prompt/tool arg), so each free-text
		// cell is passed through csvFormulaSafe to neutralize spreadsheet formula
		// injection when the operator opens the export in Excel/Sheets.
		_ = cw.Write([]string{
			csvFormulaSafe(e.ID),
			e.Timestamp.UTC().Format(time.RFC3339),
			csvFormulaSafe(e.UserEmail),
			csvFormulaSafe(e.TenantID),
			csvFormulaSafe(e.OrgID),
			e.PolicyDecision,
			csvFormulaSafe(e.RequestType),
			csvFormulaSafe(e.Query),
			csvFormulaSafe(e.ResponseSample),
			csvFormulaSafe(e.Provider),
			csvFormulaSafe(e.Model),
			csvLatencyCell(e.ResponseTime),
			csvTokensCell(e.TokensUsed),
			csvFormulaSafe(e.CorrelationID),
			// session_id is server-generated (uuid/opaque id) but formula-safed
			// like every other string cell for uniformity.
			csvFormulaSafe(e.SessionID),
		})
	}
	cw.Flush()
}

// csvFormulaSafe neutralizes CSV/spreadsheet formula injection: a cell that a
// spreadsheet would interpret as a formula (leading =, +, -, @, or a
// tab/CR that some parsers treat as a formula lead-in) is prefixed with a
// single quote so Excel/Sheets render it as literal text. Empty cells are left
// as-is. This is standard defense for exports of attacker-influenceable data.
func csvFormulaSafe(s string) string {
	if s == "" {
		return s
	}
	switch s[0] {
	case '=', '+', '-', '@', '\t', '\r':
		return "'" + s
	}
	return s
}

func writeAuditExportJSON(w http.ResponseWriter, entries []*AuditEntry, truncated bool, ts string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"audit-export-%s.json\"", ts))
	w.WriteHeader(http.StatusOK)

	payload := struct {
		Entries   []*AuditEntry `json:"entries"`
		Count     int           `json:"count"`
		Truncated bool          `json:"truncated"`
		RowCap    int           `json:"row_cap"`
	}{
		Entries:   entries,
		Count:     len(entries),
		Truncated: truncated,
		RowCap:    auditExportMaxRows,
	}
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		log.Printf("[audit/export] error encoding json: %v", err)
	}
}

// ActionReport is the per-action aggregate the #2757 report view renders.
// ByAction always carries the full canonical verdict set (allowed / blocked /
// redacted / needs_approval / error) — a verdict with no rows reports 0 rather
// than being absent, so the UI can render a stable set of cards. "modified" in
// the partner's vocabulary maps to "redacted" (handled in the UI layer / label).
type ActionReport struct {
	TenantID  string         `json:"tenant_id"`
	UserEmail string         `json:"user_email,omitempty"`
	StartTime time.Time      `json:"start_time"`
	EndTime   time.Time      `json:"end_time"`
	Total     int            `json:"total"`
	ByAction  map[string]int `json:"by_action"`

	// AvgLatencyMs / LatencySampleCount carry the same contract as the
	// compliance summary's pair (see ComplianceSummary in
	// audit_summary_handler.go): NULL when no row in the range carried a
	// measurement, never a synthesized 0.
	//
	// #3424: this surface had a second, worse bug than the summary's. It
	// divided the latency SUM (which only measured rows contribute to) by
	// report.Total (EVERY verdict row), so each unmeasured row acted as a
	// zero-latency sample and dragged the mean down -- one 50ms row among ten
	// unmeasured ones reported 5ms. That is a plausible-looking wrong number
	// rather than an obviously empty one, so it is the harder of the two to
	// notice. Both sides of the ratio are now restricted to measured rows.
	AvgLatencyMs       *float64           `json:"avg_latency_ms"`
	LatencySampleCount int                `json:"latency_sample_count"`
	TopPolicies        []PolicyHitSummary `json:"top_policies"`
	// TotalPolicies is how many DISTINCT policies fired in range, before
	// audit.TopPoliciesLimit truncated TopPolicies. See the identical field on
	// ComplianceSummary: on THIS surface, the regulator-facing Compliance
	// Report, an undisclosed truncation is the sharper of the two.
	TotalPolicies int `json:"total_policies"`
}

// foldDecisionCount folds a raw policy_decision + its row count onto the
// canonical verdict bucket in byAction (allowed/blocked/redacted/
// needs_approval/error), returning the count actually folded. Non-verdict rows
// — LogOverrideEvent's "override_lifecycle" is the one writer that isn't a
// verdict — normalize to a non-canonical value and are skipped (return 0), so
// a caller accumulating Total/latency alongside byAction never counts a
// lifecycle event as though it were a governed decision. Shared by
// ReportByAction (#2757) and the session-summary bucket aggregation (#2759)
// so the canonical-folding rule has one implementation.
func foldDecisionCount(byAction map[string]int, decision string, cnt int) int {
	canonical := sharedaudit.Normalize(decision)
	if !sharedaudit.IsCanonical(canonical) {
		return 0
	}
	byAction[canonical] += cnt
	return cnt
}

// ReportByAction aggregates audit_logs for the window into per-action counts +
// average latency + top policies, tenant-scoped and optionally filtered by
// user_email and a single canonical action. Counts reconcile with
// SearchAuditLogs for the same filters (same tenant filter, same ILIKE user
// match, same canonical action expansion).
//
// scopeUserEmail is the #2922 enforced own-rows read scope (exact canonical
// match, AND'ed before the optional userEmail ILIKE filter so the filter can
// only narrow it). Empty means tenant-wide (the handler resolves the scope and
// passes "" only for tenant-wide callers).
func (l *AuditLogger) ReportByAction(ctx context.Context, tenantID, scopeUserEmail, userEmail, action string, start, end time.Time) (*ActionReport, error) {
	report := &ActionReport{
		TenantID:    tenantID,
		UserEmail:   userEmail,
		StartTime:   start,
		EndTime:     end,
		ByAction:    map[string]int{},
		TopPolicies: []PolicyHitSummary{},
	}
	// Seed the full canonical verdict set so absent verdicts report 0.
	for _, v := range sharedaudit.All() {
		report.ByAction[v] = 0
	}
	if l.db == nil {
		return report, nil
	}

	// Shared predicate so the count and top-policy queries filter identically.
	// Held WITHOUT the "WHERE" keyword: audit.TopPoliciesQuery parenthesises it
	// before ANDing its own policy_details filter on, which a ready-made WHERE
	// clause could not be.
	predicate := "tenant_id = $1 AND timestamp >= $2 AND timestamp <= $3"
	args := []interface{}{tenantID, start, end}
	argIndex := 4
	// #2922 enforced read scope — exact canonical-email predicate, first, so
	// the optional userEmail ILIKE filter below can only narrow it.
	if scopeUserEmail != "" {
		predicate += fmt.Sprintf(" AND LOWER(user_email) = $%d", argIndex)
		args = append(args, strings.ToLower(scopeUserEmail))
		argIndex++
	}
	if userEmail != "" {
		predicate += fmt.Sprintf(" AND user_email ILIKE '%%' || $%d || '%%'", argIndex)
		args = append(args, userEmail)
		argIndex++
	}
	if action != "" {
		predicate += fmt.Sprintf(" AND policy_decision = ANY($%d)", argIndex)
		args = append(args, pq.Array(sharedaudit.Spellings(sharedaudit.Normalize(action))))
		argIndex++
	}

	// Query 1 — per-decision count + latency sum (weighted avg computed in Go).
	//
	// #3424: the SUM and the COUNT that divides it must range over the SAME
	// rows. Both are now FILTERed with the identical predicate the compliance
	// summary uses -- measured rows, enforcement planes only -- so the report
	// footer and the tile above it on the same page answer "average enforcement
	// latency" the same way.
	measuredFilter := " FILTER (WHERE " + sharedaudit.LatencyEnforcementPredicate + ")"
	countRows, err := l.db.Query(
		"SELECT policy_decision, COUNT(*), COALESCE(SUM(response_time_ms)"+measuredFilter+", 0), "+
			"COUNT(*)"+measuredFilter+" FROM audit_logs WHERE "+predicate+" GROUP BY policy_decision",
		args...,
	)
	if err != nil {
		return nil, err
	}
	defer func() { _ = countRows.Close() }()

	var latencySum int64
	var latencySamples int
	for countRows.Next() {
		var decision string
		var cnt int
		var sumLatency int64
		var measuredCnt int
		if err := countRows.Scan(&decision, &cnt, &sumLatency, &measuredCnt); err != nil {
			log.Printf("[audit/report] error scanning count row: %v", err)
			continue
		}
		// foldDecisionCount returns 0 for a non-verdict row (e.g. LogOverrideEvent's
		// "override_lifecycle") so it's excluded from Total/latencySum too — see
		// the function doc for why that matters.
		added := foldDecisionCount(report.ByAction, decision, cnt)
		report.Total += added
		if added > 0 {
			latencySum += sumLatency
			latencySamples += measuredCnt
		}
	}
	if err := countRows.Err(); err != nil {
		return nil, err
	}
	// #3424: divide by the number of MEASURED rows, not by every verdict row,
	// and report absence as absence. The mean can legitimately be below 1.0
	// (or exactly 0) now that a sub-millisecond decision records the 0 its
	// clock produced instead of a NULL; latencySamples is what tells a reader
	// that such an average is real rather than empty.
	if latencySamples > 0 {
		avg := float64(latencySum) / float64(latencySamples)
		report.AvgLatencyMs = &avg
		report.LatencySampleCount = latencySamples
	}

	// Query 2 -- top policies by trigger count. THE SAME QUERY TEXT the portal
	// summary tile uses, not a mirror of it (#3426): both surfaces used to hold
	// a hand-copied duplicate grouping on the SINGULAR
	// policy_details->>'policy_name', so every decide-plane / MCP / FinCrime-seam
	// row (plural policy_names + policy_ids) was excluded before grouping and
	// this REGULATOR-FACING report under-reported which policies fired. The
	// shared builder resolves identity through the #3243 chain the OJK, SEBI and
	// EU AI Act exporters already use. See platform/shared/audit/top_policies.go.
	// BOUNDED, for the same reason the summary tile is: the aggregation is
	// linear in in-scope rows (~2.9us each on PG 16.14) against a range the
	// caller controls, so a single-tenant stack with three million in-scope rows
	// takes ~8.7s holding a pool connection. See audit.TopPoliciesTimeout.
	//
	// Unlike the tile, EVERY failure here is fatal to the whole response. This
	// is the regulator-facing artifact: a Top Triggered Policies table that
	// quietly omits rows reads as "these are the policies that fired", so a
	// partial answer is worse than an explicit 500.
	topCtx, cancelTop := context.WithTimeout(ctx, sharedaudit.TopPoliciesTimeout)
	defer cancelTop()

	topRows, err := l.db.QueryContext(topCtx,
		sharedaudit.TopPoliciesQuery(predicate, "$"+strconv.Itoa(argIndex)),
		append(args, pq.Array(sharedaudit.Spellings(sharedaudit.DecisionBlocked)))...,
	)
	if err != nil {
		return nil, err
	}
	defer func() { _ = topRows.Close() }()

	for topRows.Next() {
		var p PolicyHitSummary
		// Same window-over-groups total the summary reads; identical on every
		// row, so the last scan wins and the value is the pre-LIMIT count.
		var totalPolicies int
		if err := topRows.Scan(&p.PolicyName, &p.IdentityIsName,
			&p.TriggerCount, &p.BlockCount, &totalPolicies); err != nil {
			// Was `continue`, which dropped the row from the compliance report
			// and left total_policies claiming it was there - the report then
			// disclosed "showing top 9 of 12" while holding 8 rows.
			log.Printf("[audit/report] error scanning top-policy row: %v", err)
			return nil, fmt.Errorf("scanning top-policy row: %w", err)
		}
		report.TopPolicies = append(report.TopPolicies, p)
		report.TotalPolicies = totalPolicies
	}
	if err := topRows.Err(); err != nil {
		return nil, err
	}

	return report, nil
}

// auditReportHandler serves POST /api/v1/audit/report.
func auditReportHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Tenant-ID, X-Org-ID")
		w.WriteHeader(http.StatusOK)
		return
	}

	tenantID := r.Header.Get("X-Tenant-ID")
	if tenantID == "" {
		log.Printf("[audit/report] BLOCKED: missing X-Tenant-ID header from %s", r.RemoteAddr)
		sendErrorResponse(w, "tenant scoping required", http.StatusUnauthorized)
		return
	}

	var req struct {
		StartTime string `json:"start_time"`
		EndTime   string `json:"end_time"`
		UserEmail string `json:"user_email,omitempty"`
		Action    string `json:"action,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		sendErrorResponse(w, "invalid request body", http.StatusBadRequest)
		return
	}

	start, err := time.Parse(time.RFC3339, req.StartTime)
	if err != nil {
		sendErrorResponse(w, "invalid start_time: must be RFC3339", http.StatusBadRequest)
		return
	}
	end, err := time.Parse(time.RFC3339, req.EndTime)
	if err != nil {
		sendErrorResponse(w, "invalid end_time: must be RFC3339", http.StatusBadRequest)
		return
	}
	if !end.After(start) {
		sendErrorResponse(w, "end_time must be after start_time", http.StatusBadRequest)
		return
	}
	if end.Sub(start) > 365*24*time.Hour {
		sendErrorResponse(w, "date range must not exceed 1 year", http.StatusBadRequest)
		return
	}

	if auditLogger == nil {
		sendErrorResponse(w, "audit subsystem unavailable", http.StatusServiceUnavailable)
		return
	}

	// #2922 role-scoped reads: a non-tenant-wide caller's report aggregates
	// only their own rows (their governance activity), never the whole
	// tenant's. Empty identity ⇒ the seeded all-zeroes report (fail-closed;
	// same shape as "no rows in window" so clients render normally).
	scopeUserEmail := ""
	scope := resolveCallerReadScope(r)
	applyReadScopeHeader(w, r, scope)
	if !scope.TenantWide {
		if scope.UserEmail == "" {
			empty := &ActionReport{
				TenantID:    tenantID,
				UserEmail:   req.UserEmail,
				StartTime:   start,
				EndTime:     end,
				ByAction:    map[string]int{},
				TopPolicies: []PolicyHitSummary{},
			}
			for _, v := range sharedaudit.All() {
				empty.ByAction[v] = 0
			}
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(empty); err != nil {
				log.Printf("[audit/report] error encoding response: %v", err)
			}
			return
		}
		scopeUserEmail = scope.UserEmail
	}

	report, err := auditLogger.ReportByAction(r.Context(), tenantID, scopeUserEmail, req.UserEmail, req.Action, start, end)
	if err != nil {
		log.Printf("[audit/report] query failed for tenant=%s: %v", logutil.Sanitize(tenantID), err)
		// Same standard as the portal's compliance tile: say that the failure
		// is a failure (not an empty result), name the timeout as a cause, and
		// give the one action the caller can actually take. The top-policies
		// aggregation is linear in in-scope rows and bounded by
		// audit.TopPoliciesTimeout, so a wide range is the likeliest way to
		// land here, and a bare "audit report failed" leaves the caller with
		// nothing to try. Deliberately no server internals: this is the
		// caller-facing body, the cause is in the log line above.
		sendErrorResponse(w,
			"audit report failed: the aggregation failed or timed out. No report was produced - this is NOT a report that nothing was found. Narrow the date range and try again.",
			http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(report); err != nil {
		log.Printf("[audit/report] error encoding response: %v", err)
	}
}
