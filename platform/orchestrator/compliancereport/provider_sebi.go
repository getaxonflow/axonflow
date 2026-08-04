// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

//go:build enterprise

package compliancereport

import (
	"context"
	"fmt"

	"axonflow/platform/orchestrator/sebi"
)

// sebiProvider adapts the SEBI module.
//
// Sections (epic #2892 per-regulator criteria): readiness (the six pillars,
// live-derived), audit export, retention posture, decision-chain lineage.
type sebiProvider struct {
	mod *sebi.SEBIModule
}

func newSEBIProvider(mod *sebi.SEBIModule) DataProvider {
	if mod == nil || mod.AuditService == nil {
		return nil
	}
	return &sebiProvider{mod: mod}
}

func (p *sebiProvider) Regulator() Regulator { return RegulatorSEBI }

func (p *sebiProvider) Available(ctx context.Context, req ProviderRequest) (bool, error) {
	return p != nil && p.mod != nil && p.mod.AuditService != nil, nil
}

func (p *sebiProvider) Fetch(ctx context.Context, req ProviderRequest) (*ProviderResult, error) {
	// tenantID: the SEBI service signature is (ctx, tenantID, ...) and its SQL
	// predicates on tenant_id, so the TENANT dimension of the caller scope is
	// the right key here. Passing OrgID would silently read the wrong rows
	// under a single enterprise license, where org != tenant (#3071).
	tenantID := req.TenantID
	svc := p.mod.AuditService

	export, err := svc.ExportAuditData(ctx, tenantID, &sebi.SEBIAuditExportRequest{
		StartDate: req.PeriodStart,
		EndDate:   req.PeriodEnd,
		Framework: sebi.SEBIFrameworkAIML,
		Format:    sebi.SEBIFormatJSON,
		DataTypes: []sebi.SEBIAuditDataType{sebi.SEBIDataTypeAll},
	})
	if err != nil {
		return nil, fmt.Errorf("sebi audit export: %w", err)
	}
	readiness, err := svc.ValidateComplianceReadiness(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("sebi compliance readiness: %w", err)
	}
	retention, err := svc.GetRetentionStatus(ctx, tenantID, &sebi.SEBIRetentionStatusRequest{})
	if err != nil {
		return nil, fmt.Errorf("sebi retention status: %w", err)
	}

	data := &sebi.SEBIAuditExportData{}
	if export != nil && export.Data != nil {
		data = export.Data
	}

	sections := []Section{
		p.readinessSection(readiness),
		p.violationsSection(data.PolicyViolations),
		p.llmActivitySection(data.LLMCalls),
		p.decisionLineageSection(data.DecisionChain),
		p.oversightSection(data.HITLOversight),
		p.piiSection(data.PIIRedactions),
		p.retentionSection(retention),
	}

	total := len(data.PolicyViolations) + len(data.LLMCalls) + len(data.DecisionChain) +
		len(data.HITLOversight) + len(data.PIIRedactions)
	return &ProviderResult{
		State:       stateFromCount(total),
		Sections:    sections,
		RecordCount: total,
	}, nil
}

func (p *sebiProvider) readinessSection(r *sebi.SEBIComplianceReadinessResponse) Section {
	s := Section{
		Key:         "readiness",
		Title:       "SEBI AI/ML readiness",
		Description: "Live-derived readiness checks against the SEBI AI/ML Guidelines.",
		Columns:     []string{"Check", "Status", "Description", "Details"},
	}
	if r == nil {
		return finishSection(s, "The readiness assessment returned no result.")
	}
	s.Summary = append(s.Summary,
		KV{Key: "Ready", Value: fmtBool(r.Ready)},
		KV{Key: "Readiness score", Value: fmtInt(r.Score) + "/100"},
	)
	for _, c := range r.Checks {
		s.Rows = append(s.Rows, []string{c.Name, c.Status, c.Description, c.Details})
	}
	for i, rec := range r.Recommendations {
		s.Notes = append(s.Notes, fmt.Sprintf("Recommendation %d: %s", i+1, rec))
	}
	return finishSection(s, "The readiness assessment produced no checks.")
}

func (p *sebiProvider) violationsSection(rows []sebi.SEBIPolicyViolationRecord) Section {
	s := Section{
		Key:         "policy_violations",
		Title:       "Policy violations",
		Description: "Governance policy violations recorded in the reporting period.",
		Columns:     []string{"ID", "Timestamp", "Type", "Severity", "Policy", "Action", "Description", "Remediation"},
	}
	bySeverity := map[string]int{}
	for i := range rows {
		v := rows[i]
		bySeverity[v.Severity]++
		s.Rows = append(s.Rows, []string{
			v.ID, fmtTime(v.Timestamp), v.ViolationType, v.Severity,
			v.PolicyName, v.Action, v.Description, v.Remediation,
		})
	}
	for _, kv := range SortedKV(bySeverity) {
		s.Summary = append(s.Summary, KV{Key: "Severity: " + kv.Key, Value: kv.Value})
	}
	// sebi_audit_export_service.go:454 is `ORDER BY created_at DESC` with no
	// unique tie-break, so two violations written in the same instant come back
	// in either order. Reproduce that order and break only the ties.
	stabilizeTiesByID(s.Rows, 1, 0, true)
	return finishSection(s, "No policy violations were recorded for this tenant in the reporting period.")
}

func (p *sebiProvider) llmActivitySection(rows []sebi.SEBILLMCallRecord) Section {
	s := Section{
		Key:         "llm_activity",
		Title:       "LLM activity",
		Description: "Governed model calls recorded in the reporting period.",
		Columns:     []string{"ID", "Timestamp", "Provider", "Model", "Decision", "Input tokens", "Output tokens", "Latency (ms)"},
	}
	byDecision := map[string]int{}
	for i := range rows {
		c := rows[i]
		byDecision[c.PolicyDecision]++
		s.Rows = append(s.Rows, []string{
			c.ID, fmtTime(c.Timestamp), c.Provider, c.Model, c.PolicyDecision,
			fmtInt(c.InputTokens), fmtInt(c.OutputTokens), fmtInt64(c.LatencyMs),
		})
	}
	for _, kv := range SortedKV(byDecision) {
		s.Summary = append(s.Summary, KV{Key: "Decision: " + kv.Key, Value: kv.Value})
	}
	// sebi_audit_export_service.go:506 is `ORDER BY timestamp DESC`, non-total.
	stabilizeTiesByID(s.Rows, 1, 0, true)
	return finishSection(s, "No governed model calls were recorded for this tenant in the reporting period.")
}

func (p *sebiProvider) decisionLineageSection(rows []sebi.SEBIDecisionChainRecord) Section {
	s := Section{
		Key:         "decision_lineage",
		Title:       "Decision-chain lineage",
		Description: "Per-decision governance records, with the correlation id that ties the stages of one logical request together.",
		Columns:     []string{"ID", "Timestamp", "Correlation", "Type", "Outcome", "Risk level", "Policy triggered", "Human review"},
	}
	for i := range rows {
		d := rows[i]
		s.Rows = append(s.Rows, []string{
			d.ID, fmtTime(d.Timestamp), d.CorrelationID, d.DecisionType,
			d.DecisionOutcome, d.RiskLevel, d.PolicyTriggered, fmtBool(d.RequiresReview),
		})
	}
	// NOT stabilized, deliberately: sebi_audit_export_service.go:597 is
	// `ORDER BY timestamp ASC, id ASC`, which is already a total order.
	return finishSection(s, "No governed decisions were recorded for this tenant in the reporting period.")
}

func (p *sebiProvider) oversightSection(rows []sebi.SEBIHITLRecord) Section {
	s := Section{
		Key:         "hitl_oversight",
		Title:       "Human oversight",
		Description: "Human-in-the-loop reviews recorded in the reporting period.",
		Columns:     []string{"ID", "Timestamp", "Request", "Trigger", "Reviewer", "Decision", "Review time (ms)"},
	}
	for i := range rows {
		h := rows[i]
		s.Rows = append(s.Rows, []string{
			h.ID, fmtTime(h.Timestamp), h.RequestID, h.TriggerReason,
			h.ReviewerEmail, h.Decision, fmtInt64(h.ReviewTimeMs),
		})
	}
	// sebi_audit_export_service.go:735 is `ORDER BY created_at DESC`, non-total.
	stabilizeTiesByID(s.Rows, 1, 0, true)
	return finishSection(s, "No human-oversight reviews were recorded for this tenant in the reporting period.")
}

func (p *sebiProvider) piiSection(rows []sebi.SEBIPIIRedactionRecord) Section {
	s := Section{
		Key:         "pii_redactions",
		Title:       "PII redactions",
		Description: "PII detections and redactions recorded in the reporting period.",
		Columns:     []string{"ID", "Timestamp", "Request", "PII type", "Method", "Location", "Confidence"},
	}
	byType := map[string]int{}
	for i := range rows {
		r := rows[i]
		byType[r.PIIType]++
		s.Rows = append(s.Rows, []string{
			r.ID, fmtTime(r.Timestamp), r.RequestID, r.PIIType,
			r.RedactionMethod, r.Location, fmtFloat(r.DetectionConfidence),
		})
	}
	for _, kv := range SortedKV(byType) {
		s.Summary = append(s.Summary, KV{Key: "PII type: " + kv.Key, Value: kv.Value})
	}
	// sebi_audit_export_service.go:782 is `ORDER BY created_at DESC`, non-total.
	stabilizeTiesByID(s.Rows, 1, 0, true)
	return finishSection(s, "No PII redactions were recorded for this tenant in the reporting period.")
}

func (p *sebiProvider) retentionSection(r *sebi.SEBIRetentionStatusResponse) Section {
	s := Section{
		Key:         "retention_posture",
		Title:       "Retention posture",
		Description: "Configured retention per data type, and the age span of the records held.",
		Columns:     []string{"Data type", "Retention (days)", "Records", "Oldest", "Newest", "Status"},
	}
	if r == nil {
		return finishSection(s, "The retention status query returned no result.")
	}
	s.Summary = append(s.Summary, KV{Key: "Overall retention status", Value: r.ComplianceStatus})
	for _, d := range r.Status {
		s.Rows = append(s.Rows, []string{
			string(d.DataType), fmtInt(d.RetentionDays), fmtInt64(d.TotalRecords),
			fmtTime(d.OldestRecord), fmtTime(d.NewestRecord), d.ComplianceStatus,
		})
	}
	// Retention posture is a CONFIGURATION statement, so it is reported even
	// when the tenant holds no records at all - "we retain audit data for 5
	// years and currently hold none" is a different and useful answer from
	// "this report does not cover retention".
	return finishSection(s, "No per-data-type retention rows were reported for this tenant.")
}
