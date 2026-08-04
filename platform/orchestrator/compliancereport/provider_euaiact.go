// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

//go:build enterprise

package compliancereport

import (
	"context"
	"fmt"

	"axonflow/platform/orchestrator/euaiact"
)

// euaiactProvider adapts the EU AI Act module.
//
// Sections (epic #2892 per-regulator criteria): conformity assessments,
// risk management, accuracy/bias monitoring, audit trail, and an Article 43
// conformity summary derived from the assessment rows.
//
// It reads through the module's EXPORT repository, whose queries are already
// org-scoped and date-bounded, so the facade adds no new SQL against the EU AI
// Act tables and inherits the org predicate those readers carry.
type euaiactProvider struct {
	mod *euaiact.Module
}

func newEUAIActProvider(mod *euaiact.Module) DataProvider {
	if mod == nil || mod.ExportRepo == nil {
		// A nil provider is skipped by NewRegistry and the regulator answers
		// not_available. Returning a live provider wrapping a nil repo would
		// turn a deployment fact into a nil-pointer panic at request time.
		return nil
	}
	return &euaiactProvider{mod: mod}
}

func (p *euaiactProvider) Regulator() Regulator { return RegulatorEUAIAct }

func (p *euaiactProvider) Available(ctx context.Context, req ProviderRequest) (bool, error) {
	return p != nil && p.mod != nil && p.mod.ExportRepo != nil, nil
}

func (p *euaiactProvider) Fetch(ctx context.Context, req ProviderRequest) (*ProviderResult, error) {
	// orgID: the EU AI Act repository keys on org_id (see
	// euaiact/export_repository.go), so the ORG dimension of the caller scope
	// is the right key here — not tenant.
	orgID := req.OrgID
	repo := p.mod.ExportRepo

	assessments, err := repo.GetConformityAssessments(ctx, orgID, req.PeriodStart, req.PeriodEnd)
	if err != nil {
		return nil, fmt.Errorf("conformity assessments: %w", err)
	}
	metrics, err := repo.GetAccuracyMetrics(ctx, orgID, req.PeriodStart, req.PeriodEnd)
	if err != nil {
		return nil, fmt.Errorf("accuracy metrics: %w", err)
	}
	violations, err := repo.GetPolicyViolations(ctx, orgID, req.PeriodStart, req.PeriodEnd)
	if err != nil {
		return nil, fmt.Errorf("policy violations: %w", err)
	}
	hitl, err := repo.GetHITLApprovalHistory(ctx, orgID, req.PeriodStart, req.PeriodEnd)
	if err != nil {
		return nil, fmt.Errorf("HITL approval history: %w", err)
	}
	decisions, err := repo.GetDecisionChain(ctx, orgID, req.PeriodStart, req.PeriodEnd)
	if err != nil {
		return nil, fmt.Errorf("decision chain: %w", err)
	}

	sections := []Section{
		p.conformitySection(assessments),
		p.article43Section(assessments),
		p.riskManagementSection(violations),
		p.accuracySection(metrics),
		p.oversightSection(hitl),
		p.auditTrailSection(decisions),
	}

	total := len(assessments) + len(metrics) + len(violations) + len(hitl) + len(decisions)
	return &ProviderResult{
		State:       stateFromCount(total),
		Sections:    sections,
		RecordCount: total,
	}, nil
}

func (p *euaiactProvider) conformitySection(rows []*euaiact.ConformityAssessment) Section {
	s := Section{
		Key:         "conformity_assessments",
		Title:       "Conformity assessments (Art. 43)",
		Description: "Conformity assessments whose assessment date falls in the reporting period.",
		Columns:     []string{"Assessment ID", "System", "Risk category", "Status", "Version", "Assessment date", "Valid until", "Approved by", "Findings"},
	}
	for _, a := range rows {
		if a == nil {
			continue
		}
		s.Rows = append(s.Rows, []string{
			a.ID,
			fmt.Sprintf("%s (%s)", a.SystemName, a.SystemID),
			string(a.RiskCategory),
			string(a.Status),
			fmtInt(a.Version),
			fmtDate(a.AssessmentDate),
			fmtDatePtr(a.ValidUntil),
			a.ApprovedBy,
			fmtInt(len(a.Findings)),
		})
	}
	return finishSection(s, "No conformity assessments were recorded for this organization in the reporting period.")
}

// article43Section is the derived summary a notified body reads first: how many
// assessments reached each status. Counted from the SAME rows the section above
// lists, so the two can never disagree.
func (p *euaiactProvider) article43Section(rows []*euaiact.ConformityAssessment) Section {
	byStatus := map[string]int{}
	byRisk := map[string]int{}
	approved := 0
	for _, a := range rows {
		if a == nil {
			continue
		}
		byStatus[string(a.Status)]++
		byRisk[string(a.RiskCategory)]++
		if a.Status == euaiact.AssessmentStatusApproved {
			approved++
		}
	}
	s := Section{
		Key:         "article_43_summary",
		Title:       "Article 43 conformity summary",
		Description: "Aggregate conformity posture over the reporting period.",
	}
	s.Summary = append(s.Summary, KV{Key: "Assessments in period", Value: fmtInt(len(rows))})
	s.Summary = append(s.Summary, KV{Key: "Approved", Value: fmtInt(approved)})
	// SortedKV, not a map range: a map range here would reorder the summary
	// between two renders of the same job.
	for _, kv := range SortedKV(byStatus) {
		s.Summary = append(s.Summary, KV{Key: "Status: " + kv.Key, Value: kv.Value})
	}
	for _, kv := range SortedKV(byRisk) {
		s.Summary = append(s.Summary, KV{Key: "Risk category: " + kv.Key, Value: kv.Value})
	}
	if len(rows) == 0 {
		s.Notes = append(s.Notes, "No conformity assessments in the period, so no Article 43 posture can be summarised.")
	}
	return s
}

func (p *euaiactProvider) riskManagementSection(rows []euaiact.PolicyViolationRecord) Section {
	s := Section{
		Key:         "risk_management",
		Title:       "Risk management (Arts. 9-17)",
		Description: "Policy violations recorded in the period: the operational evidence of the risk-management system.",
		Columns:     []string{"ID", "Detected at", "Type", "Severity", "Client", "User", "Description"},
	}
	bySeverity := map[string]int{}
	for i := range rows {
		v := rows[i]
		bySeverity[v.Severity]++
		s.Rows = append(s.Rows, []string{
			fmtInt64(v.ID),
			fmtTime(v.CreatedAt),
			v.ViolationType,
			v.Severity,
			v.ClientID,
			v.UserID,
			v.Description,
		})
	}
	for _, kv := range SortedKV(bySeverity) {
		s.Summary = append(s.Summary, KV{Key: "Severity: " + kv.Key, Value: kv.Value})
	}
	return finishSection(s, "No policy violations were recorded for this organization in the reporting period.")
}

func (p *euaiactProvider) accuracySection(rows []*euaiact.AccuracyMetric) Section {
	s := Section{
		Key:         "accuracy_bias_monitoring",
		Title:       "Accuracy and bias monitoring (Art. 15)",
		Description: "Recorded accuracy and bias measurements for the organization's AI systems.",
		Columns:     []string{"Metric ID", "Model", "Metric", "Value", "Sample size", "Window start", "Window end", "Measured at"},
	}
	for _, m := range rows {
		if m == nil {
			continue
		}
		s.Rows = append(s.Rows, []string{
			m.ID,
			m.ModelID,
			string(m.MetricType),
			fmtFloat(m.Value),
			fmtInt(m.SampleSize),
			fmtTime(m.WindowStart),
			fmtTime(m.WindowEnd),
			fmtTime(m.Timestamp),
		})
	}
	return finishSection(s, "No accuracy or bias measurements were recorded for this organization in the reporting period.")
}

func (p *euaiactProvider) oversightSection(rows []euaiact.HITLApprovalRecord) Section {
	s := Section{
		Key:         "human_oversight",
		Title:       "Human oversight (Art. 14)",
		Description: "Human-in-the-loop approval decisions recorded in the period.",
		Columns:     []string{"ID", "Request", "Action", "Reviewer", "From", "To", "Justification", "Recorded at"},
	}
	for i := range rows {
		h := rows[i]
		s.Rows = append(s.Rows, []string{
			fmtInt64(h.ID),
			h.RequestID,
			h.Action,
			h.ActorEmail,
			h.PreviousStatus,
			h.NewStatus,
			h.Justification,
			fmtTime(h.CreatedAt),
		})
	}
	return finishSection(s, "No human-oversight decisions were recorded for this organization in the reporting period.")
}

func (p *euaiactProvider) auditTrailSection(rows []euaiact.DecisionChainRecord) Section {
	s := Section{
		Key:         "audit_trail",
		Title:       "Audit trail (Art. 12 record-keeping)",
		Description: "Per-decision governance records for the period, in chronological order.",
		Columns:     []string{"Decision ID", "Timestamp", "Correlation", "Type", "Outcome", "Policy triggered", "Human review", "Model"},
	}
	for i := range rows {
		d := rows[i]
		s.Rows = append(s.Rows, []string{
			d.ID,
			fmtTime(d.Timestamp),
			d.CorrelationID,
			d.DecisionType,
			d.DecisionOutcome,
			d.PolicyTriggered,
			fmtBool(d.RequiresReview),
			d.ModelID,
		})
	}
	return finishSection(s, "No governed decisions were recorded for this organization in the reporting period.")
}
