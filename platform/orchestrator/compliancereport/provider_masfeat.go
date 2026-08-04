// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

//go:build enterprise

package compliancereport

import (
	"context"
	"fmt"
	"sort"
	"time"

	"axonflow/platform/orchestrator/masfeat"
)

// masfeatProvider adapts the MAS FEAT module.
//
// This is MAS FEAT's FIRST export path. Before it, the module had no export
// subsystem at all - masfeat/doc.go documented three endpoints that were never
// implemented (corrected in the same change). Everything the module records is
// therefore reachable by an auditor for the first time here.
//
// Sections (epic #2892 per-regulator criteria): FEAT four-pillar assessments,
// AI system registry, kill-switch history.
type masfeatProvider struct {
	mod *masfeat.Module
}

func newMASFEATProvider(mod *masfeat.Module) DataProvider {
	if mod == nil || mod.RegistryService == nil {
		return nil
	}
	return &masfeatProvider{mod: mod}
}

func (p *masfeatProvider) Regulator() Regulator { return RegulatorMASFEAT }

func (p *masfeatProvider) Available(ctx context.Context, req ProviderRequest) (bool, error) {
	return p != nil && p.mod != nil && p.mod.RegistryService != nil, nil
}

func (p *masfeatProvider) Fetch(ctx context.Context, req ProviderRequest) (*ProviderResult, error) {
	// orgID: every MAS FEAT service signature is (ctx, orgID, ...) after #3141,
	// so the ORG dimension is the right key on this module.
	orgID := req.OrgID

	systems, err := p.mod.RegistryService.ListSystems(ctx, orgID, masfeat.ListParams{Limit: listPageSize})
	if err != nil {
		return nil, fmt.Errorf("masfeat registry: %w", err)
	}
	assessments, err := p.mod.AssessmentService.ListAssessments(ctx, orgID, masfeat.ListParams{Limit: listPageSize})
	if err != nil {
		return nil, fmt.Errorf("masfeat assessments: %w", err)
	}
	// ListAssessments has no date filter, so the period bound is applied here.
	// Filtering in the provider rather than asking the module for a new query
	// keeps this adapter strictly read-only over the existing service surface.
	inPeriod := make([]*masfeat.FEATAssessment, 0, len(assessments))
	for _, a := range assessments {
		if a != nil && withinPeriod(a.AssessmentDate, req.PeriodStart, req.PeriodEnd) {
			inPeriod = append(inPeriod, a)
		}
	}

	history, err := p.killSwitchHistory(ctx, orgID, systems, req.PeriodStart, req.PeriodEnd)
	if err != nil {
		return nil, err
	}

	sections := []Section{
		p.assessmentsSection(inPeriod, len(assessments)),
		p.pillarSummarySection(inPeriod),
		p.registrySection(systems),
		p.killSwitchHistorySection(history),
	}

	total := len(inPeriod) + len(systems) + len(history)
	return &ProviderResult{
		State:       stateFromCount(total),
		Sections:    sections,
		RecordCount: total,
	}, nil
}

// killSwitchHistory fans out over the org's own registered systems. GetHistory
// is keyed by (orgID, systemID) and the system ids come from this org's
// registry listing, never from client input, so the fan-out is org-bounded.
func (p *masfeatProvider) killSwitchHistory(ctx context.Context, orgID string, systems []*masfeat.AISystemRegistry, start, end time.Time) ([]*masfeat.KillSwitchHistory, error) {
	if p.mod.KillSwitchService == nil {
		return nil, nil
	}
	var out []*masfeat.KillSwitchHistory
	for _, sys := range systems {
		if sys == nil {
			continue
		}
		entries, err := p.mod.KillSwitchService.GetHistory(ctx, orgID, sys.SystemID, historyPerSwitch)
		if err != nil {
			return nil, fmt.Errorf("masfeat kill switch history for %s: %w", sys.SystemID, err)
		}
		for _, e := range entries {
			if e == nil || !withinPeriod(e.PerformedAt, start, end) {
				continue
			}
			out = append(out, e)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if !out[i].PerformedAt.Equal(out[j].PerformedAt) {
			return out[i].PerformedAt.Before(out[j].PerformedAt)
		}
		return out[i].ID < out[j].ID
	})
	return out, nil
}

func (p *masfeatProvider) assessmentsSection(rows []*masfeat.FEATAssessment, totalHeld int) Section {
	s := Section{
		Key:         "feat_assessments",
		Title:       "FEAT assessments",
		Description: "Fairness, Ethics, Accountability and Transparency assessments whose assessment date falls in the reporting period.",
		Columns:     []string{"ID", "System", "Type", "Status", "Version", "Assessment date", "Valid until", "Fairness", "Ethics", "Accountability", "Transparency", "Overall", "Approved by"},
	}
	for _, a := range rows {
		s.Rows = append(s.Rows, []string{
			a.ID,
			a.SystemID,
			a.AssessmentType,
			string(a.Status),
			fmtInt(a.Version),
			fmtDate(a.AssessmentDate),
			fmtDatePtr(a.ValidUntil),
			fmtFloatPtr(a.FairnessScore),
			fmtFloatPtr(a.EthicsScore),
			fmtFloatPtr(a.AccountabilityScore),
			fmtFloatPtr(a.TransparencyScore),
			fmtFloatPtr(a.OverallScore),
			a.ApprovedBy,
		})
	}
	if totalHeld > len(rows) {
		// Say WHY the count differs from the module's own dashboards, so a
		// reader does not conclude assessments went missing.
		s.Notes = append(s.Notes, fmt.Sprintf(
			"This organization holds %d assessments in total; %d have an assessment date inside the reporting period and are listed here.",
			totalHeld, len(rows)))
	}
	return finishSection(s, "No FEAT assessments have an assessment date inside the reporting period for this organization.")
}

// pillarSummarySection is the four-pillar posture a MAS submission leads with.
func (p *masfeatProvider) pillarSummarySection(rows []*masfeat.FEATAssessment) Section {
	s := Section{
		Key:         "feat_pillar_summary",
		Title:       "FEAT four-pillar summary",
		Description: "Mean pillar scores across the assessments in the reporting period, and their status distribution.",
	}
	if len(rows) == 0 {
		s.Notes = append(s.Notes, "No assessments in the period, so no pillar posture can be summarised.")
		return s
	}
	type pillar struct {
		name string
		get  func(*masfeat.FEATAssessment) *float64
	}
	// Declared as an ordered slice, not a map: this is rendered.
	pillars := []pillar{
		{"Fairness", func(a *masfeat.FEATAssessment) *float64 { return a.FairnessScore }},
		{"Ethics", func(a *masfeat.FEATAssessment) *float64 { return a.EthicsScore }},
		{"Accountability", func(a *masfeat.FEATAssessment) *float64 { return a.AccountabilityScore }},
		{"Transparency", func(a *masfeat.FEATAssessment) *float64 { return a.TransparencyScore }},
		{"Overall", func(a *masfeat.FEATAssessment) *float64 { return a.OverallScore }},
	}
	for _, pl := range pillars {
		sum, n := 0.0, 0
		for _, a := range rows {
			if v := pl.get(a); v != nil {
				sum += *v
				n++
			}
		}
		if n == 0 {
			// "not scored" is a real MAS finding, so it is reported as such
			// rather than as a 0.00 that reads like a failing score.
			s.Summary = append(s.Summary, KV{Key: pl.name + " (mean)", Value: "not scored"})
			continue
		}
		s.Summary = append(s.Summary, KV{
			Key:   pl.name + " (mean)",
			Value: fmt.Sprintf("%s across %d scored assessments", fmtFloat(sum/float64(n)), n),
		})
	}
	byStatus := map[string]int{}
	for _, a := range rows {
		byStatus[string(a.Status)]++
	}
	for _, kv := range SortedKV(byStatus) {
		s.Summary = append(s.Summary, KV{Key: "Status: " + kv.Key, Value: kv.Value})
	}
	return s
}

func (p *masfeatProvider) registrySection(rows []*masfeat.AISystemRegistry) Section {
	s := Section{
		Key:         "system_registry",
		Title:       "AI system registry",
		Description: "Registered AI systems with their MAS three-dimensional risk rating and materiality classification. The registry is a POINT-IN-TIME inventory, so it is not filtered to the reporting period.",
		Columns:     []string{"System ID", "Name", "Use case", "Status", "Impact", "Complexity", "Reliance", "Materiality", "Owner", "Last assessment", "Next assessment due"},
	}
	byMateriality := map[string]int{}
	for _, sys := range rows {
		if sys == nil {
			continue
		}
		byMateriality[string(sys.MaterialityClassification)]++
		s.Rows = append(s.Rows, []string{
			sys.SystemID,
			sys.SystemName,
			string(sys.UseCase),
			string(sys.Status),
			fmtInt(sys.RiskRatingImpact),
			fmtInt(sys.RiskRatingComplexity),
			fmtInt(sys.RiskRatingReliance),
			string(sys.MaterialityClassification),
			sys.OwnerEmail,
			fmtDatePtr(sys.LastAssessmentDate),
			fmtDatePtr(sys.NextAssessmentDue),
		})
	}
	for _, kv := range SortedKV(byMateriality) {
		s.Summary = append(s.Summary, KV{Key: "Materiality: " + kv.Key, Value: kv.Value})
	}
	return finishSection(s, "No AI systems are registered for this organization.")
}

func (p *masfeatProvider) killSwitchHistorySection(rows []*masfeat.KillSwitchHistory) Section {
	s := Section{
		Key:         "kill_switch_history",
		Title:       "Kill-switch history",
		Description: "Kill-switch transitions recorded in the reporting period.",
		Columns:     []string{"Performed at", "Kill switch", "Action", "From", "To", "Performed by", "Reason"},
	}
	byAction := map[string]int{}
	for _, h := range rows {
		if h == nil {
			continue
		}
		byAction[h.Action]++
		s.Rows = append(s.Rows, []string{
			fmtTime(h.PerformedAt),
			h.KillSwitchID,
			h.Action,
			h.PreviousStatus,
			h.NewStatus,
			h.PerformedBy,
			h.Reason,
		})
	}
	for _, kv := range SortedKV(byAction) {
		s.Summary = append(s.Summary, KV{Key: "Action: " + kv.Key, Value: kv.Value})
	}
	return finishSection(s, "No kill-switch transitions were recorded for this organization in the reporting period.")
}
