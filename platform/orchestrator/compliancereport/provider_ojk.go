// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

//go:build enterprise

package compliancereport

import (
	"context"
	"fmt"
	"time"

	"axonflow/platform/orchestrator/ojk"
)

// ojkProvider adapts the OJK / BI / UU PDP module.
//
// Sections (epic #2892 per-regulator criteria): AI governance summary, policy
// violations, LLM/decision activity, HITL oversight, PII redactions, UU PDP
// Pasal 56 cross-border transfers, the 72h breach log, and the BI PJP section.
//
// This is the one regulator with SUB-FRAMEWORKS: an Indonesian deployment
// reports against AI governance (OJK), personal data protection (UU PDP) and
// payment systems (BI PJP) under three different instruments. The requested
// Framework is passed straight through to the module so the export it produces
// is the one the framework defines.
//
// WS-B (#3242) owns the DATA completeness of this module. Where a section is
// thin today, this provider renders what the module actually returns and says
// so, rather than fabricating a section - a fabricated "compliant" section on a
// regulatory artifact is worse than an honest empty one.
type ojkProvider struct {
	mod *ojk.OJKModule
}

func newOJKProvider(mod *ojk.OJKModule) DataProvider {
	if mod == nil || mod.AuditService == nil {
		return nil
	}
	return &ojkProvider{mod: mod}
}

func (p *ojkProvider) Regulator() Regulator { return RegulatorOJK }

func (p *ojkProvider) Available(ctx context.Context, req ProviderRequest) (bool, error) {
	return p != nil && p.mod != nil && p.mod.AuditService != nil, nil
}

// ojkFramework maps the facade's framework token to the module's own enum.
// A one-to-one mapping today; written as an explicit switch so adding a facade
// framework without an OJK counterpart is a compile-visible gap rather than a
// silent fall-through to AI governance.
func ojkFramework(fw Framework) (ojk.OJKComplianceFramework, error) {
	switch fw {
	case FrameworkOJKAIGovernance:
		return ojk.OJKFrameworkAIGovernance, nil
	case FrameworkUUPDP:
		return ojk.OJKFrameworkUUPDP, nil
	case FrameworkBIPJP:
		return ojk.OJKFrameworkBIPJP, nil
	case FrameworkOJKBICombined:
		return ojk.OJKFrameworkCombined, nil
	default:
		return "", fmt.Errorf("framework %q is not an OJK framework", fw)
	}
}

// ojkDateBounds converts the facade's instant-precision period into the
// DATE-ONLY strings the OJK module accepts.
//
// ojk_audit_export_service.go parses both bounds with `time.Parse("2006-01-02",
// ...)` and then filters `timestamp >= start AND timestamp <= end`. Two
// consequences, both of which this function exists to handle:
//
//   - An RFC3339 string is REJECTED outright ("extra text"). Sending one made
//     every OJK report fail; found by the runtime-e2e suite, not by reading.
//   - Because the parsed end is MIDNIGHT of that date, passing the end date
//     verbatim silently drops every record from the final day. The end bound is
//     therefore rolled forward to the next date whenever the requested period
//     ends part-way through a day - the same "a date-only end means through the
//     end of that day" convention evidence_export_handler.go applies. A period
//     that ends exactly on a midnight boundary is passed through unchanged,
//     because there the caller means "up to, not including" that day.
//
// The residual imprecision is one instant at the boundary, which is stated on
// the report rather than hidden: see ojkResolutionNote.
func ojkDateBounds(periodStart, periodEnd time.Time) (string, string) {
	const dateOnly = "2006-01-02"
	start := periodStart.UTC()
	end := periodEnd.UTC()
	if !end.Equal(end.Truncate(24 * time.Hour)) {
		end = end.AddDate(0, 0, 1)
	}
	return start.Format(dateOnly), end.Format(dateOnly)
}

// ojkResolutionNote states the day-granularity limitation on the artifact. An
// unstated rounding on a regulatory report is a claim about the period covered.
const ojkResolutionNote = "The Indonesian module filters on whole DATES, so this report covers complete days: the period was widened to the day boundary at each end."

func (p *ojkProvider) Fetch(ctx context.Context, req ProviderRequest) (*ProviderResult, error) {
	// tenantID: the OJK service signature is (ctx, tenantID, ...) and its SQL
	// predicates on tenant_id, so the TENANT dimension of the caller scope is
	// the right key here.
	tenantID := req.TenantID
	svc := p.mod.AuditService

	framework, err := ojkFramework(req.Framework)
	if err != nil {
		return nil, err
	}

	start, end := ojkDateBounds(req.PeriodStart, req.PeriodEnd)
	export, err := svc.ExportAuditData(ctx, tenantID, &ojk.OJKAuditExportRequest{
		StartDate: start,
		EndDate:   end,
		Framework: framework,
		Format:    ojk.OJKFormatJSON,
		DataTypes: []ojk.OJKAuditDataType{ojk.OJKDataTypeAll},
	})
	if err != nil {
		return nil, fmt.Errorf("ojk audit export: %w", err)
	}
	readiness, err := svc.ValidateComplianceReadiness(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("ojk compliance readiness: %w", err)
	}
	dashboard, err := svc.GetDashboard(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("ojk dashboard: %w", err)
	}
	retention, err := svc.GetRetentionStatus(ctx, tenantID, &ojk.OJKRetentionStatusRequest{})
	if err != nil {
		return nil, fmt.Errorf("ojk retention status: %w", err)
	}

	data := &ojk.OJKAuditExportData{}
	if export != nil && export.Data != nil {
		data = export.Data
	}

	sections := []Section{
		p.governanceSummarySection(readiness, dashboard),
		p.violationsSection(data.PolicyViolations),
		p.activitySection(data.LLMCalls, data.DecisionChains),
		p.oversightSection(data.HITLRecords),
		p.piiSection(data.PIIRedactions),
		p.crossBorderSection(data.CrossBorder),
		p.breachSection(data.BreachNotifications),
		p.biPJPSection(req.Framework),
		p.retentionSection(retention),
	}

	total := len(data.PolicyViolations) + len(data.LLMCalls) + len(data.DecisionChains) +
		len(data.HITLRecords) + len(data.PIIRedactions) + len(data.CrossBorder) +
		len(data.BreachNotifications)
	return &ProviderResult{
		State:       stateFromCount(total),
		Sections:    sections,
		RecordCount: total,
	}, nil
}

func (p *ojkProvider) governanceSummarySection(r *ojk.OJKComplianceReadinessResponse, d *ojk.OJKDashboardResponse) Section {
	s := Section{
		Key:         "ai_governance_summary",
		Title:       "AI governance summary",
		Description: "Readiness checks against the selected Indonesian framework, with the current governance posture.",
		Columns:     []string{"Check", "Status", "Description", "Details"},
	}
	if d != nil {
		s.Summary = append(s.Summary,
			KV{Key: "Compliance score", Value: fmtInt(d.ComplianceScore) + "/100"},
			KV{Key: "Total audit records", Value: fmtInt64(d.TotalAuditRecords)},
			KV{Key: "Active policies", Value: fmtInt(d.ActivePolicies)},
			KV{Key: "Recent violations", Value: fmtInt(d.RecentViolations)},
			KV{Key: "Breach notifications", Value: fmtInt(d.BreachNotifications)},
			KV{Key: "Overdue breach notifications", Value: fmtInt(d.OverdueBreachNotifications)},
			KV{Key: "Retention status", Value: d.RetentionStatus},
		)
	}
	s.Notes = append(s.Notes, ojkResolutionNote)
	if r != nil {
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
	}
	return finishSection(s, "The readiness assessment produced no checks.")
}

func (p *ojkProvider) violationsSection(rows []ojk.OJKPolicyViolationRecord) Section {
	s := Section{
		Key:         "policy_violations",
		Title:       "Policy violations",
		Description: "Governance policy violations recorded in the reporting period.",
		Columns:     []string{"ID", "Timestamp", "Policy", "Severity", "Action", "Description"},
	}
	bySeverity := map[string]int{}
	for i := range rows {
		v := rows[i]
		bySeverity[v.Severity]++
		s.Rows = append(s.Rows, []string{
			v.ID, fmtTime(v.Timestamp), v.PolicyName, v.Severity, v.Action, v.Description,
		})
	}
	for _, kv := range SortedKV(bySeverity) {
		s.Summary = append(s.Summary, KV{Key: "Severity: " + kv.Key, Value: kv.Value})
	}
	return finishSection(s, "No policy violations were recorded for this tenant in the reporting period.")
}

func (p *ojkProvider) activitySection(calls []ojk.OJKLLMCallRecord, decisions []ojk.OJKDecisionChainRecord) Section {
	s := Section{
		Key:         "llm_decision_activity",
		Title:       "LLM and decision activity",
		Description: "Governed model calls in the reporting period, with the count of decision records they produced.",
		Columns:     []string{"ID", "Timestamp", "Provider", "Model", "Decision", "Total tokens", "Latency (ms)"},
	}
	byDecision := map[string]int{}
	for i := range calls {
		c := calls[i]
		byDecision[c.PolicyDecision]++
		s.Rows = append(s.Rows, []string{
			c.ID, fmtTime(c.Timestamp), c.Provider, c.ModelID, c.PolicyDecision,
			fmtInt(c.TotalTokens), fmtInt64(c.LatencyMS),
		})
	}
	s.Summary = append(s.Summary, KV{Key: "Decision records", Value: fmtInt(len(decisions))})
	for _, kv := range SortedKV(byDecision) {
		s.Summary = append(s.Summary, KV{Key: "Decision: " + kv.Key, Value: kv.Value})
	}
	return finishSection(s, "No governed model calls were recorded for this tenant in the reporting period.")
}

func (p *ojkProvider) oversightSection(rows []ojk.OJKHITLRecord) Section {
	s := Section{
		Key:         "hitl_oversight",
		Title:       "Human oversight",
		Description: "Human-in-the-loop reviews recorded in the reporting period.",
		Columns:     []string{"ID", "Timestamp", "Trigger", "Reviewer", "Decision", "Review time (ms)"},
	}
	for i := range rows {
		h := rows[i]
		s.Rows = append(s.Rows, []string{
			h.ID, fmtTime(h.Timestamp), h.TriggerReason, h.ReviewerID, h.Decision, fmtInt64(h.ReviewTimeMS),
		})
	}
	return finishSection(s, "No human-oversight reviews were recorded for this tenant in the reporting period.")
}

func (p *ojkProvider) piiSection(rows []ojk.OJKPIIRedactionRecord) Section {
	s := Section{
		Key:         "pii_redactions",
		Title:       "PII redactions",
		Description: "Indonesian PII detections and redactions (NIK, NPWP, bank account and the other detected categories) recorded in the reporting period.",
		Columns:     []string{"ID", "Timestamp", "PII type", "Method", "Confidence"},
	}
	byType := map[string]int{}
	for i := range rows {
		r := rows[i]
		byType[r.PIIType]++
		s.Rows = append(s.Rows, []string{
			r.ID, fmtTime(r.Timestamp), r.PIIType, r.RedactionMethod, fmtFloat(r.Confidence),
		})
	}
	for _, kv := range SortedKV(byType) {
		s.Summary = append(s.Summary, KV{Key: "PII type: " + kv.Key, Value: kv.Value})
	}
	return finishSection(s, "No PII redactions were recorded for this tenant in the reporting period.")
}

func (p *ojkProvider) crossBorderSection(rows []ojk.CrossBorderTransferRecord) Section {
	s := Section{
		Key:         "cross_border_transfers",
		Title:       "Cross-border transfers (UU PDP Pasal 56)",
		Description: "Cross-border personal-data transfers with the legal basis recorded at decision time. The basis is surfaced VERBATIM, never translated between its Pasal 56(a)/(b)/(c) spellings, so an auditor sees exactly what was recorded.",
		Columns:     []string{"ID", "Timestamp", "Destination", "Residency", "Transfer basis", "Data categories", "Approval"},
	}
	byBasis := map[string]int{}
	for i := range rows {
		t := rows[i]
		byBasis[t.TransferBasis]++
		s.Rows = append(s.Rows, []string{
			t.ID, fmtTime(t.Timestamp), t.DestinationCountry, t.DataResidency,
			t.TransferBasis, fmtStrings(t.DataCategories), t.ApprovalStatus,
		})
	}
	for _, kv := range SortedKV(byBasis) {
		s.Summary = append(s.Summary, KV{Key: "Basis: " + kv.Key, Value: kv.Value})
	}
	return finishSection(s, "No cross-border personal-data transfers were recorded for this tenant in the reporting period.")
}

func (p *ojkProvider) breachSection(rows []ojk.OJKBreachNotificationRecord) Section {
	s := Section{
		Key:         "breach_log",
		Title:       "Breach notifications (UU PDP Art. 46, 72h)",
		Description: "Personal-data breaches and their 72-hour notification state. Status is the EFFECTIVE status at report time: a breach past its window without a timely submission reads overdue even if it was never explicitly flipped.",
		Columns:     []string{"ID", "Incident", "Discovered", "Deadline", "Subjects affected", "Data types", "Authority", "Status", "Within deadline", "Submitted", "Acknowledged"},
	}
	byStatus := map[string]int{}
	overdue := 0
	for i := range rows {
		b := rows[i]
		byStatus[b.Status]++
		if !b.WithinDeadline {
			overdue++
		}
		s.Rows = append(s.Rows, []string{
			b.ID,
			fmtTime(b.IncidentTimestamp),
			fmtTime(b.DiscoveryTime),
			fmtTime(b.NotificationDeadline),
			fmtInt(b.DataSubjectsAffected),
			fmtStrings(b.DataTypesInvolved),
			b.NotifiedAuthority,
			b.Status,
			fmtBool(b.WithinDeadline),
			fmtTimePtr(b.SubmittedAt),
			fmtTimePtr(b.AcknowledgedAt),
		})
	}
	s.Summary = append(s.Summary, KV{Key: "Breaches outside the 72h window", Value: fmtInt(overdue)})
	for _, kv := range SortedKV(byStatus) {
		s.Summary = append(s.Summary, KV{Key: "Status: " + kv.Key, Value: kv.Value})
	}
	return finishSection(s, "No personal-data breach notifications were recorded for this tenant in the reporting period.")
}

// biPJPSection reports the Bank Indonesia payment-system framework.
//
// BI PJP is ENUM-ONLY in the platform today: selecting it scopes the export,
// but no BI-specific data class is collected yet (WS-B #3242 owns making it
// first-class). Saying that on the artifact is the point - a payment-system
// regulator reading a silently empty BI section would reasonably conclude the
// institution has no payment-system AI activity, which is a different and
// possibly false claim.
func (p *ojkProvider) biPJPSection(fw Framework) Section {
	s := Section{
		Key:         "bi_pjp",
		Title:       "Bank Indonesia payment services (BI PJP)",
		Description: "Bank Indonesia payment-service-provider framework coverage.",
	}
	if fw != FrameworkBIPJP && fw != FrameworkOJKBICombined {
		s.Notes = append(s.Notes, fmt.Sprintf(
			"Not applicable: this report was generated under the %s framework. Select BI_PJP or OJK_BI_COMBINED to include payment-service coverage.", fw))
		return s
	}
	s.Notes = append(s.Notes,
		"The BI PJP framework currently scopes the export but contributes no payment-service-specific data class of its own; "+
			"the governance, oversight and PII sections above cover the same activity under the OJK and UU PDP instruments. "+
			"This section is reported as a KNOWN LIMITATION rather than shown empty, so an absent BI-specific table is not read as an absence of payment-service AI activity.")
	return s
}

func (p *ojkProvider) retentionSection(r *ojk.OJKRetentionStatusResponse) Section {
	s := Section{
		Key:         "retention_posture",
		Title:       "Retention posture",
		Description: "Configured retention per data type against the Indonesian minimum, and the age span of the records held.",
		Columns:     []string{"Data type", "Records", "Oldest", "Newest", "Status"},
	}
	if r == nil {
		return finishSection(s, "The retention status query returned no result.")
	}
	s.Summary = append(s.Summary,
		KV{Key: "Overall retention status", Value: r.ComplianceStatus},
		KV{Key: "Configured retention (days)", Value: fmtInt(r.RetentionDays)},
		KV{Key: "Required minimum (days)", Value: fmtInt(r.MinRetentionDays)},
	)
	for _, d := range r.DataTypes {
		s.Rows = append(s.Rows, []string{
			string(d.DataType), fmtInt64(d.TotalRecords),
			fmtTimePtr(d.OldestRecord), fmtTimePtr(d.NewestRecord), d.Status,
		})
	}
	return finishSection(s, "No per-data-type retention rows were reported for this tenant.")
}
