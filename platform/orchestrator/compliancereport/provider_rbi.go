// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

//go:build enterprise

package compliancereport

import (
	"context"
	"fmt"
	"sort"
	"time"

	"axonflow/platform/orchestrator/rbi"
)

// rbiProvider adapts the RBI FREE-AI module.
//
// Sections (epic #2892 per-regulator criteria): board report, incidents,
// kill-switch history, model validations, AI system registry.
type rbiProvider struct {
	mod *rbi.RBIModule
}

func newRBIProvider(mod *rbi.RBIModule) DataProvider {
	if mod == nil || mod.RegistryService == nil {
		return nil
	}
	return &rbiProvider{mod: mod}
}

func (p *rbiProvider) Regulator() Regulator { return RegulatorRBI }

func (p *rbiProvider) Available(ctx context.Context, req ProviderRequest) (bool, error) {
	return p != nil && p.mod != nil && p.mod.RegistryService != nil, nil
}

// listPageSize bounds each service list call. The services page, so the
// provider pages too rather than asking for "everything" and hoping the
// repository's own default is generous.
const listPageSize = 500

func (p *rbiProvider) Fetch(ctx context.Context, req ProviderRequest) (*ProviderResult, error) {
	// orgID: every RBI service signature is (ctx, orgID, ...) after #3066/#3103,
	// so the ORG dimension is the right key on this module.
	orgID := req.OrgID
	start, end := req.PeriodStart, req.PeriodEnd

	systems, _, err := p.mod.RegistryService.ListSystems(ctx, orgID, &rbi.ListAISystemsParams{Limit: listPageSize})
	if err != nil {
		return nil, fmt.Errorf("rbi registry: %w", err)
	}
	validations, _, err := p.mod.ValidationService.ListValidations(ctx, orgID, &rbi.ListValidationsParams{
		StartDate: &start, EndDate: &end, Limit: listPageSize,
	})
	if err != nil {
		return nil, fmt.Errorf("rbi validations: %w", err)
	}
	incidents, _, err := p.mod.IncidentService.ListIncidents(ctx, orgID, &rbi.ListIncidentsParams{
		StartDate: &start, EndDate: &end, Limit: listPageSize,
	})
	if err != nil {
		return nil, fmt.Errorf("rbi incidents: %w", err)
	}
	switches, _, err := p.mod.KillSwitchService.ListKillSwitches(ctx, orgID, &rbi.ListKillSwitchParams{Limit: listPageSize})
	if err != nil {
		return nil, fmt.Errorf("rbi kill switches: %w", err)
	}
	reports, _, err := p.mod.BoardService.ListReports(ctx, orgID, &rbi.ListBoardReportsParams{
		StartDate: &start, EndDate: &end, Limit: listPageSize,
	})
	if err != nil {
		return nil, fmt.Errorf("rbi board reports: %w", err)
	}

	history, err := p.killSwitchHistory(ctx, orgID, switches, start, end)
	if err != nil {
		return nil, err
	}

	sections := []Section{
		p.boardReportSection(reports),
		p.incidentsSection(incidents),
		p.killSwitchSection(switches, history),
		p.killSwitchHistorySection(history),
		p.validationsSection(validations),
		p.registrySection(systems),
	}

	total := len(reports) + len(incidents) + len(switches) + len(history) + len(validations) + len(systems)
	return &ProviderResult{
		State:       stateFromCount(total),
		Sections:    sections,
		RecordCount: total,
	}, nil
}

// historyPerSwitch bounds the history pulled for one kill switch. A switch that
// flapped thousands of times would otherwise dominate the report; the cap is
// surfaced in the section note rather than applied silently.
const historyPerSwitch = 200

// killSwitchHistory collects the per-switch history entries that fall inside
// the reporting period.
//
// The service exposes history PER kill switch (GetHistory takes a switch id),
// so this fans out over the switches the org owns. Every call carries the same
// orgID the caller was authenticated for, so the fan-out cannot reach another
// organization's history - the switch ids themselves come from that org's own
// ListKillSwitches result, never from client input.
func (p *rbiProvider) killSwitchHistory(ctx context.Context, orgID string, switches []*rbi.KillSwitch, start, end time.Time) ([]*rbi.KillSwitchHistoryEntry, error) {
	var out []*rbi.KillSwitchHistoryEntry
	for _, k := range switches {
		if k == nil {
			continue
		}
		entries, err := p.mod.KillSwitchService.GetHistory(ctx, orgID, k.ID, historyPerSwitch)
		if err != nil {
			return nil, fmt.Errorf("rbi kill switch history for %s: %w", k.ID, err)
		}
		for _, e := range entries {
			if e == nil || !withinPeriod(e.CreatedAt, start, end) {
				continue
			}
			out = append(out, e)
		}
	}
	// Stable order: the entries arrive grouped by switch, and a report that
	// reorders between two renders is not reproducible. Sort by (time, id).
	sort.SliceStable(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.Before(out[j].CreatedAt)
		}
		return out[i].ID < out[j].ID
	})
	return out, nil
}

func (p *rbiProvider) boardReportSection(rows []*rbi.BoardReport) Section {
	s := Section{
		Key:         "board_reports",
		Title:       "Board reports",
		Description: "Board-level AI governance reports generated for the reporting period.",
		Columns:     []string{"ID", "Type", "Period start", "Period end", "Systems", "Incidents", "Compliance score", "Approval", "Approved by", "Generated at"},
	}
	for _, r := range rows {
		if r == nil {
			continue
		}
		s.Rows = append(s.Rows, []string{
			r.ID,
			string(r.ReportType),
			fmtDatePtr(r.ReportPeriodStart),
			fmtDatePtr(r.ReportPeriodEnd),
			fmtInt(r.TotalAISystems),
			fmtInt(r.TotalIncidents),
			fmtFloat(r.ComplianceScore),
			string(r.ApprovalStatus),
			r.ApprovedByEmail,
			fmtTime(r.GeneratedAt),
		})
	}
	return finishSection(s, "No board reports were generated for this organization in the reporting period.")
}

func (p *rbiProvider) incidentsSection(rows []*rbi.AIIncident) Section {
	s := Section{
		Key:         "incidents",
		Title:       "AI incidents",
		Description: "Incidents detected in the reporting period, with their board and RBI notification state.",
		Columns:     []string{"Incident", "System", "Type", "Severity", "Status", "Detected at", "Resolved at", "Board notified", "RBI notified"},
	}
	bySeverity := map[string]int{}
	openCount := 0
	for _, i := range rows {
		if i == nil {
			continue
		}
		bySeverity[string(i.Severity)]++
		if i.ResolvedAt == nil {
			openCount++
		}
		s.Rows = append(s.Rows, []string{
			i.IncidentID,
			i.SystemID,
			string(i.IncidentType),
			string(i.Severity),
			string(i.Status),
			fmtTime(i.DetectedAt),
			fmtTimePtr(i.ResolvedAt),
			fmtBool(i.BoardNotified),
			fmtBool(i.RBINotified),
		})
	}
	s.Summary = append(s.Summary, KV{Key: "Unresolved at report time", Value: fmtInt(openCount)})
	for _, kv := range SortedKV(bySeverity) {
		s.Summary = append(s.Summary, KV{Key: "Severity: " + kv.Key, Value: kv.Value})
	}
	return finishSection(s, "No AI incidents were recorded for this organization in the reporting period.")
}

func (p *rbiProvider) killSwitchSection(switches []*rbi.KillSwitch, history []*rbi.KillSwitchHistoryEntry) Section {
	s := Section{
		Key:         "kill_switches",
		Title:       "Kill switches and activation history",
		Description: "Configured kill switches and every activation or release recorded in the reporting period.",
		Columns:     []string{"Kill switch", "Scope", "System", "Active", "Activated at", "Activated by", "Reason", "Auto-triggered"},
	}
	active := 0
	for _, k := range switches {
		if k == nil {
			continue
		}
		if k.IsActive {
			active++
		}
		s.Rows = append(s.Rows, []string{
			k.ID,
			string(k.Scope),
			k.SystemID,
			fmtBool(k.IsActive),
			fmtTimePtr(k.ActivatedAt),
			k.ActivatedByEmail,
			k.ActivationReason,
			fmtBool(k.AutoTriggered),
		})
	}
	s.Summary = append(s.Summary,
		KV{Key: "Configured kill switches", Value: fmtInt(len(switches))},
		KV{Key: "Currently active", Value: fmtInt(active)},
		KV{Key: "History entries in period", Value: fmtInt(len(history))},
	)
	return finishSection(s, "No kill switches are configured for this organization.")
}

func (p *rbiProvider) killSwitchHistorySection(history []*rbi.KillSwitchHistoryEntry) Section {
	s := Section{
		Key:         "kill_switch_history",
		Title:       "Kill-switch activation history",
		Description: "Every kill-switch activation or release recorded in the reporting period, with the acting principal.",
		Columns:     []string{"Recorded at", "Kill switch", "Action", "Actor", "Actor role", "Actor IP", "Reason"},
	}
	byAction := map[string]int{}
	for _, h := range history {
		if h == nil {
			continue
		}
		byAction[string(h.Action)]++
		s.Rows = append(s.Rows, []string{
			fmtTime(h.CreatedAt),
			h.KillSwitchID,
			string(h.Action),
			h.ActorEmail,
			h.ActorRole,
			h.ActorIP,
			h.Reason,
		})
	}
	for _, kv := range SortedKV(byAction) {
		s.Summary = append(s.Summary, KV{Key: "Action: " + kv.Key, Value: kv.Value})
	}
	if len(history) > 0 {
		s.Notes = append(s.Notes, fmt.Sprintf(
			"At most %d history entries are read per kill switch; a switch that exceeded that in the period is reported only in part.",
			historyPerSwitch))
	}
	return finishSection(s, "No kill-switch activations or releases were recorded for this organization in the reporting period.")
}

func (p *rbiProvider) validationsSection(rows []*rbi.ModelValidation) Section {
	s := Section{
		Key:         "model_validations",
		Title:       "Model validations",
		Description: "Independent and internal model validations performed in the reporting period.",
		Columns:     []string{"ID", "System", "Type", "Validator", "Validator type", "Validated on", "Recommendation", "Remediation required", "Next review"},
	}
	byRecommendation := map[string]int{}
	for _, v := range rows {
		if v == nil {
			continue
		}
		byRecommendation[string(v.Recommendation)]++
		s.Rows = append(s.Rows, []string{
			v.ID,
			v.SystemID,
			string(v.ValidationType),
			v.ValidatorName,
			string(v.ValidatorType),
			fmtDate(v.ValidationDate),
			string(v.Recommendation),
			fmtBool(v.RemediationRequired),
			fmtDatePtr(v.NextReviewDate),
		})
	}
	for _, kv := range SortedKV(byRecommendation) {
		s.Summary = append(s.Summary, KV{Key: "Recommendation: " + kv.Key, Value: kv.Value})
	}
	return finishSection(s, "No model validations were recorded for this organization in the reporting period.")
}

func (p *rbiProvider) registrySection(rows []*rbi.AISystem) Section {
	s := Section{
		Key:         "ai_system_registry",
		Title:       "AI system registry",
		Description: "AI systems registered by this organization, with their risk classification and board-approval state. The registry is a POINT-IN-TIME inventory, so it is not filtered to the reporting period.",
		Columns:     []string{"System ID", "Name", "Risk", "Deployment", "Owner", "Board approval", "Last validation", "Next validation due"},
	}
	byRisk := map[string]int{}
	for _, a := range rows {
		if a == nil {
			continue
		}
		byRisk[string(a.RiskCategory)]++
		s.Rows = append(s.Rows, []string{
			a.SystemID,
			a.SystemName,
			string(a.RiskCategory),
			string(a.DeploymentStatus),
			a.OwnerEmail,
			string(a.BoardApprovalStatus),
			fmtDatePtr(a.LastValidationDate),
			fmtDatePtr(a.NextValidationDue),
		})
	}
	for _, kv := range SortedKV(byRisk) {
		s.Summary = append(s.Summary, KV{Key: "Risk category: " + kv.Key, Value: kv.Value})
	}
	return finishSection(s, "No AI systems are registered for this organization.")
}
