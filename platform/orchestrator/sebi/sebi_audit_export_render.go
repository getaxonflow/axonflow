// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

//go:build enterprise

package sebi

import (
	"sort"
	"strconv"
	"time"

	"axonflow/platform/orchestrator/compliancereport/renderer"
)

// Real CSV rendering for the SEBI audit export (#3241, epic #2892).
//
// # What this replaces
//
// exportAuditData set `Content-Type: text/csv` (or `application/xml`) and then
// wrote the JSON response body. Every "CSV" export was JSON under a CSV header:
// a spreadsheet cannot open it, and a caller that trusted the header got a
// parse error rather than data. The XML path is now an honest 501; see the
// handler.
//
// # Scope
//
// The sections below are the LEGACY content this endpoint already returns, now
// in a real container. The richer canonical SEBI report - readiness pillars,
// retention posture, decision lineage - lives behind the unified facade
// (POST /api/v1/compliance/reports, regulator=sebi), which is where new
// sections belong. Keeping this one legacy-shaped means an existing consumer
// sees the same DATA it always did, in a format it can finally read.
//
// Rendering goes through platform/orchestrator/compliancereport/renderer, so the
// artifact inherits its ordering guarantees: no map iteration, stable section
// and row order, no font or locale dependence.
//
// IT DOES NOT INHERIT "no wall-clock reads", and an earlier version of this
// comment claimed it did (#3241 round 2, R3). SEBI audit export is
// SYNCHRONOUS: ExportAuditData collects and returns in one call, stamping
// ExportedAt and Metadata.GeneratedAt with time.Now() (sebi_audit_export_service.go),
// and there is no persisted export record to derive a stable timestamp from -
// that absence is #3246(b). So two separate export CALLS legitimately produce
// different bytes, because they are different exports.
//
// What the contract does hold, and all that is needed here: the render is a
// pure function of the response value. The same response renders to the same
// bytes every time. Nothing checksums or stores a SEBI export for later
// re-derivation, so there is no checksum for a differing timestamp to break -
// unlike the RBI path, where the artifact IS stored and the timestamp is
// therefore taken from the persisted row (exportGeneratedAt).
//
// If SEBI export ever becomes asynchronous with a stored artifact, the
// timestamp must move to the job record at the same time.

// buildAuditExportReport converts a SEBI audit export response into the
// renderer-facing model.
func buildAuditExportReport(tenantID string, req *SEBIAuditExportRequest, resp *SEBIAuditExportResponse) *renderer.Report {
	rep := &renderer.Report{
		Regulator:     "sebi",
		RegulatorName: "SEBI (India)",
		Framework:     string(SEBIFrameworkAIML),
		OrgID:         tenantID,
		ReportState:   "enabled_empty",
		RetentionNote: "SEBI: records retained 5 years.",
	}
	if req != nil {
		rep.PeriodStart = req.StartDate
		rep.PeriodEnd = req.EndDate
		if req.Framework != "" {
			rep.Framework = string(req.Framework)
		}
	}
	if resp == nil {
		rep.Sections = []renderer.Section{{
			Key:   "export",
			Title: "SEBI audit export",
			Notes: []string{"The export produced no response."},
		}}
		return rep
	}

	rep.JobID = resp.ExportID
	// The export's OWN completion timestamp, never time.Now(): re-rendering the
	// same export must reproduce the same bytes.
	rep.GeneratedAt = resp.ExportedAt
	if m := resp.Metadata; m != nil {
		if !m.GeneratedAt.IsZero() {
			rep.GeneratedAt = m.GeneratedAt
		}
		if m.TenantID != "" {
			rep.OrgID = m.TenantID
		}
	}
	if resp.Framework != "" {
		rep.Framework = string(resp.Framework)
	}
	if resp.Summary != nil {
		rep.RecordCount = resp.Summary.TotalRecords
	}
	if rep.RecordCount > 0 {
		rep.ReportState = "populated"
	}

	data := resp.Data
	if data == nil {
		data = &SEBIAuditExportData{}
	}
	rep.Sections = []renderer.Section{
		sebiSummarySection(resp),
		sebiViolationsSection(data.PolicyViolations),
		sebiLLMCallsSection(data.LLMCalls),
		sebiDecisionChainSection(data.DecisionChain),
		sebiHITLSection(data.HITLOversight),
		sebiPIISection(data.PIIRedactions),
	}
	return rep
}

func sebiSummarySection(resp *SEBIAuditExportResponse) renderer.Section {
	s := renderer.Section{
		Key:         "summary",
		Title:       "Export summary",
		Description: "Record counts and compliance score for the exported period.",
	}
	if resp.Summary == nil {
		s.Notes = append(s.Notes, "No summary was produced for this export.")
		return s
	}
	s.Summary = []renderer.KV{
		{Key: "Export ID", Value: resp.ExportID},
		{Key: "Status", Value: resp.Status},
		{Key: "Total records", Value: sebiItoa(resp.Summary.TotalRecords)},
		{Key: "Compliance score", Value: strconv.FormatFloat(resp.Summary.ComplianceScore, 'f', 2, 64)},
	}
	if dr := resp.Summary.DateRange; dr != nil {
		s.Summary = append(s.Summary,
			renderer.KV{Key: "Range start", Value: sebiRFC3339(dr.Start)},
			renderer.KV{Key: "Range end", Value: sebiRFC3339(dr.End)},
		)
	}
	// RecordsByType is a MAP. Ordering it here is what keeps two renders of the
	// same export byte-identical; ranging it directly would not.
	for _, k := range sortedDataTypeKeys(resp.Summary.RecordsByType) {
		s.Summary = append(s.Summary, renderer.KV{
			Key:   "Records: " + string(k),
			Value: sebiItoa(resp.Summary.RecordsByType[k]),
		})
	}
	if vs := resp.Summary.ViolationsSummary; vs != nil {
		s.Summary = append(s.Summary, renderer.KV{Key: "Violations total", Value: sebiItoa(vs.Total)})
		for _, k := range sortedStringKeys(vs.BySeverity) {
			s.Summary = append(s.Summary, renderer.KV{Key: "Violations by severity: " + k, Value: sebiItoa(vs.BySeverity[k])})
		}
		for _, k := range sortedStringKeys(vs.ByType) {
			s.Summary = append(s.Summary, renderer.KV{Key: "Violations by type: " + k, Value: sebiItoa(vs.ByType[k])})
		}
	}
	return s
}

func sebiViolationsSection(rows []SEBIPolicyViolationRecord) renderer.Section {
	s := renderer.Section{
		Key:     "policy_violations",
		Title:   "Policy violations",
		Columns: []string{"ID", "Timestamp", "Type", "Severity", "Policy", "Action", "Description", "Remediation"},
	}
	for i := range rows {
		v := rows[i]
		s.Rows = append(s.Rows, []string{
			v.ID, sebiRFC3339(v.Timestamp), v.ViolationType, v.Severity,
			v.PolicyName, v.Action, v.Description, v.Remediation,
		})
	}
	return sebiFinish(s, "No policy violations were recorded for this tenant in the exported period.")
}

func sebiLLMCallsSection(rows []SEBILLMCallRecord) renderer.Section {
	s := renderer.Section{
		Key:     "llm_calls",
		Title:   "LLM calls",
		Columns: []string{"ID", "Timestamp", "Request", "Provider", "Model", "Decision", "Input tokens", "Output tokens", "Latency (ms)"},
	}
	for i := range rows {
		c := rows[i]
		s.Rows = append(s.Rows, []string{
			c.ID, sebiRFC3339(c.Timestamp), c.RequestID, c.Provider, c.Model, c.PolicyDecision,
			sebiItoa(c.InputTokens), sebiItoa(c.OutputTokens), strconv.FormatInt(c.LatencyMs, 10),
		})
	}
	return sebiFinish(s, "No governed model calls were recorded for this tenant in the exported period.")
}

func sebiDecisionChainSection(rows []SEBIDecisionChainRecord) renderer.Section {
	s := renderer.Section{
		Key:     "decision_chain",
		Title:   "Decision chain",
		Columns: []string{"ID", "Timestamp", "Correlation", "Type", "Outcome", "Risk level", "Policy triggered", "Human review"},
	}
	for i := range rows {
		d := rows[i]
		review := "no"
		if d.RequiresReview {
			review = "yes"
		}
		s.Rows = append(s.Rows, []string{
			d.ID, sebiRFC3339(d.Timestamp), d.CorrelationID, d.DecisionType,
			d.DecisionOutcome, d.RiskLevel, d.PolicyTriggered, review,
		})
	}
	return sebiFinish(s, "No governed decisions were recorded for this tenant in the exported period.")
}

func sebiHITLSection(rows []SEBIHITLRecord) renderer.Section {
	s := renderer.Section{
		Key:     "hitl_oversight",
		Title:   "Human oversight",
		Columns: []string{"ID", "Timestamp", "Request", "Trigger", "Reviewer", "Decision", "Review time (ms)"},
	}
	for i := range rows {
		h := rows[i]
		s.Rows = append(s.Rows, []string{
			h.ID, sebiRFC3339(h.Timestamp), h.RequestID, h.TriggerReason,
			h.ReviewerEmail, h.Decision, strconv.FormatInt(h.ReviewTimeMs, 10),
		})
	}
	return sebiFinish(s, "No human-oversight reviews were recorded for this tenant in the exported period.")
}

func sebiPIISection(rows []SEBIPIIRedactionRecord) renderer.Section {
	s := renderer.Section{
		Key:     "pii_redactions",
		Title:   "PII redactions",
		Columns: []string{"ID", "Timestamp", "Request", "PII type", "Method", "Location", "Confidence"},
	}
	for i := range rows {
		r := rows[i]
		s.Rows = append(s.Rows, []string{
			r.ID, sebiRFC3339(r.Timestamp), r.RequestID, r.PIIType,
			r.RedactionMethod, r.Location, strconv.FormatFloat(r.DetectionConfidence, 'f', 2, 64),
		})
	}
	return sebiFinish(s, "No PII redactions were recorded for this tenant in the exported period.")
}

// sebiFinish emits the honest empty-state sentence so a reader can tell "no
// rows in this period" from "this export does not cover that data class".
func sebiFinish(s renderer.Section, emptyReason string) renderer.Section {
	if len(s.Rows) == 0 {
		s.Notes = append(s.Notes, emptyReason)
	}
	return s
}

func sebiItoa(n int) string { return strconv.Itoa(n) }

func sebiRFC3339(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// sortedDataTypeKeys / sortedStringKeys give a deterministic iteration order for
// the summary maps. Ranging a Go map directly would make two renders of the
// SAME export differ, which breaks the artifact's checksum contract.
func sortedDataTypeKeys(m map[SEBIAuditDataType]int) []SEBIAuditDataType {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, string(k))
	}
	sort.Strings(keys)
	out := make([]SEBIAuditDataType, 0, len(keys))
	for _, k := range keys {
		out = append(out, SEBIAuditDataType(k))
	}
	return out
}

func sortedStringKeys(m map[string]int) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
