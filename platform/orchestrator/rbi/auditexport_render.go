// Copyright 2026 AxonFlow
// SPDX-License-Identifier: Apache-2.0

//go:build enterprise

package rbi

import (
	"fmt"
	"os"
	"strconv"
	"time"

	"axonflow/platform/orchestrator/compliancereport/renderer"
)

// Real PDF / XLSX rendering for the RBI audit export (#3241, epic #2892).
//
// # What this replaces
//
// generatePDFFile wrote a PLAIN TEXT file, then `os.Rename`d it to `.pdf`. A
// caller who asked for PDF received a text file with a .pdf extension: no PDF
// viewer opens it, and the service then SHA-256'd that text and stored the
// digest as the export's checksum, so the artifact verified successfully as
// exactly the wrong thing. generateXLSXFile was a one-line
// `return s.generateCSVFile(filePath, data)` - a CSV named .xlsx, which Excel
// refuses. Both are consumer-visible: an RBI FREE-AI submission pack built from
// them is not openable by the recipient.
//
// # What it renders
//
// The same five sections the CSV export already writes (AI systems, model
// validations, incidents, kill switches, board reports) plus the summary block,
// so the four formats of this endpoint now agree on content and differ only in
// container. The section shapes are deliberately the LEGACY ones this endpoint
// already emits; the new unified facade
// (platform/orchestrator/compliancereport) defines the richer canonical report
// and is where new sections belong.
//
// Rendering goes through platform/orchestrator/compliancereport/renderer, so
// these artifacts inherit its determinism contract: fixed fonts, no wall-clock
// reads, no map iteration. GeneratedAt comes off the export's own metadata.

// buildAuditExportReport converts the collected export data into the
// renderer-facing model.
func buildAuditExportReport(data *ExportData) *renderer.Report {
	rep := &renderer.Report{
		Regulator:     "rbi",
		RegulatorName: "RBI FREE-AI (India)",
		Framework:     "RBI_FREE_AI",
		ReportState:   "populated",
		RetentionNote: "RBI FREE-AI: retention per the FREE-AI framework and the institution's board-approved policy.",
	}
	if data == nil {
		rep.ReportState = "enabled_empty"
		return rep
	}
	rep.RecordCount = data.TotalRecords
	if data.TotalRecords == 0 {
		rep.ReportState = "enabled_empty"
	}
	if m := data.ExportMeta; m != nil {
		rep.JobID = m.ExportID
		rep.OrgID = m.OrgID
		// The export's OWN generation timestamp, never time.Now(): re-rendering
		// the same export must reproduce the same bytes and the same checksum.
		rep.GeneratedAt = m.GeneratedAt
		if m.StartDate != nil {
			rep.PeriodStart = *m.StartDate
		}
		if m.EndDate != nil {
			rep.PeriodEnd = *m.EndDate
		}
	}

	rep.Sections = []renderer.Section{
		auditSummarySection(data),
		auditSystemsSection(data.Systems),
		auditValidationsSection(data.Validations),
		auditIncidentsSection(data.Incidents),
		auditKillSwitchesSection(data.KillSwitches),
		auditBoardReportsSection(data.Reports),
	}
	return rep
}

func auditSummarySection(data *ExportData) renderer.Section {
	s := renderer.Section{
		Key:         "summary",
		Title:       "Export summary",
		Description: "Record counts for the exported period.",
	}
	if data.Summary == nil {
		s.Notes = append(s.Notes, "No summary was produced for this export.")
		return s
	}
	s.Summary = []renderer.KV{
		{Key: "AI systems", Value: itoa(data.Summary.TotalSystems)},
		{Key: "Model validations", Value: itoa(data.Summary.TotalValidations)},
		{Key: "Incidents", Value: itoa(data.Summary.TotalIncidents)},
		{Key: "Kill switches", Value: itoa(data.Summary.TotalKillSwitches)},
		{Key: "Board reports", Value: itoa(data.Summary.TotalReports)},
		{Key: "Total records", Value: itoa(data.TotalRecords)},
	}
	if m := data.ExportMeta; m != nil {
		if m.Purpose != "" {
			s.Summary = append(s.Summary, renderer.KV{Key: "Purpose", Value: m.Purpose})
		}
		if m.GeneratedBy != "" {
			s.Summary = append(s.Summary, renderer.KV{Key: "Requested by", Value: m.GeneratedBy})
		}
	}
	return s
}

func auditSystemsSection(rows []*AISystem) renderer.Section {
	s := renderer.Section{
		Key:     "ai_systems",
		Title:   "AI systems",
		Columns: []string{"ID", "System name", "Description", "Risk category", "Deployment status", "Created at"},
	}
	for _, sys := range rows {
		if sys == nil {
			continue
		}
		s.Rows = append(s.Rows, []string{
			sys.ID, sys.SystemName, sys.Description,
			string(sys.RiskCategory), string(sys.DeploymentStatus), rfc3339(sys.CreatedAt),
		})
	}
	return finishAuditSection(s, "No AI systems fall in the exported period.")
}

func auditValidationsSection(rows []*ModelValidation) renderer.Section {
	s := renderer.Section{
		Key:     "model_validations",
		Title:   "Model validations",
		Columns: []string{"ID", "System ID", "Validator name", "Validation type", "Recommendation", "Created at"},
	}
	for _, v := range rows {
		if v == nil {
			continue
		}
		s.Rows = append(s.Rows, []string{
			v.ID, v.SystemID, v.ValidatorName,
			string(v.ValidationType), string(v.Recommendation), rfc3339(v.CreatedAt),
		})
	}
	return finishAuditSection(s, "No model validations fall in the exported period.")
}

func auditIncidentsSection(rows []*AIIncident) renderer.Section {
	s := renderer.Section{
		Key:     "incidents",
		Title:   "Incidents",
		Columns: []string{"ID", "System ID", "Title", "Severity", "Status", "Created at"},
	}
	for _, i := range rows {
		if i == nil {
			continue
		}
		s.Rows = append(s.Rows, []string{
			i.ID, i.SystemID, i.Title, string(i.Severity), string(i.Status), rfc3339(i.CreatedAt),
		})
	}
	return finishAuditSection(s, "No incidents fall in the exported period.")
}

func auditKillSwitchesSection(rows []*KillSwitch) renderer.Section {
	s := renderer.Section{
		Key:     "kill_switches",
		Title:   "Kill switches",
		Columns: []string{"ID", "Scope", "System ID", "Activation reason", "Is active", "Created at"},
	}
	for _, k := range rows {
		if k == nil {
			continue
		}
		active := "false"
		if k.IsActive {
			active = "true"
		}
		s.Rows = append(s.Rows, []string{
			k.ID, string(k.Scope), k.SystemID, k.ActivationReason, active, rfc3339(k.CreatedAt),
		})
	}
	return finishAuditSection(s, "No kill switches fall in the exported period.")
}

func auditBoardReportsSection(rows []*BoardReport) renderer.Section {
	s := renderer.Section{
		Key:     "board_reports",
		Title:   "Board reports",
		Columns: []string{"ID", "Report type", "Period start", "Period end", "Approval status", "Created at"},
	}
	for _, r := range rows {
		if r == nil {
			continue
		}
		start, end := "", ""
		if r.ReportPeriodStart != nil {
			start = r.ReportPeriodStart.UTC().Format("2006-01-02")
		}
		if r.ReportPeriodEnd != nil {
			end = r.ReportPeriodEnd.UTC().Format("2006-01-02")
		}
		s.Rows = append(s.Rows, []string{
			r.ID, string(r.ReportType), start, end, string(r.ApprovalStatus), rfc3339(r.CreatedAt),
		})
	}
	return finishAuditSection(s, "No board reports fall in the exported period.")
}

// finishAuditSection emits the honest empty-state sentence. A section is always
// present, so "no incidents were recorded" is never confused with "this export
// does not cover incidents".
func finishAuditSection(s renderer.Section, emptyReason string) renderer.Section {
	if len(s.Rows) == 0 {
		s.Notes = append(s.Notes, emptyReason)
	}
	return s
}

func itoa(n int) string { return strconv.Itoa(n) }

func rfc3339(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// renderAuditExportTo renders the export in the requested format and writes it
// to filePath. Shared by the PDF and XLSX generators so the two cannot drift.
func renderAuditExportTo(filePath string, data *ExportData, r renderer.Renderer, label string) error {
	payload, err := r.Render(buildAuditExportReport(data))
	if err != nil {
		return fmt.Errorf("render %s export: %w", label, err)
	}
	// 0o600: an export file is regulatory evidence about a bank's AI systems
	// sitting on a shared export directory; it should not be world-readable.
	// Written in ONE call to the final path - the old PDF path wrote a .txt and
	// then renamed it, which is what made the artifact's extension a lie.
	if err := os.WriteFile(filePath, payload, 0o600); err != nil {
		return fmt.Errorf("write %s export: %w", label, err)
	}
	return nil
}
