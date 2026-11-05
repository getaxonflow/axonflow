// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package usage

// CapabilityEvent is bounded, case-free usage evidence for an internal
// capability. OrgID and TenantID must come from verified server context;
// EventKey is a SHA-256 hex digest of the invocation and phase, never a case ID.
// Cost is deliberately absent: an unpriced model call is not a zero-cost call.
type CapabilityEvent struct {
	OrgID             string
	TenantID          string
	EventKey          string
	Capability        string // case_specialist | fincrime_risk_facts | curated_review_template
	Kind              string // capability_source_read | capability_model_usage | capability_preview | capability_invocation | capability_outcome
	Status            string // attempted | succeeded | refused | partial | failed
	CostStatus        string // unpriced_infrastructure | unknown | not_applicable
	OutcomeStatus     string // not_measured
	Provider          string // ollama for model usage; empty otherwise
	Model             string // bounded model identifier; empty otherwise
	InputTokens       int
	OutputTokens      int
	ReplayFingerprint string // optional SHA-256 hex folded into the replay digest; never stored directly
}

// CapabilityUsageSummary is a tenant-scoped read of persisted advisory
// evidence. Counts are event counts, not resolved cases or business impact.
type CapabilityUsageSummary struct {
	RecordedEvents      int64  `json:"recorded_events"`
	SourceReadAttempts  int64  `json:"source_read_attempts"`
	SourceReadSuccesses int64  `json:"source_read_successes"`
	ModelAttempts       int64  `json:"model_attempts"`
	InputTokens         int64  `json:"input_tokens"`
	OutputTokens        int64  `json:"output_tokens"`
	TotalTokens         int64  `json:"total_tokens"`
	UnpricedRuns        int64  `json:"unpriced_runs"`
	UnknownCostRuns     int64  `json:"unknown_cost_runs"`
	PreviewRequests     int64  `json:"preview_requests"`
	PreviewSuccesses    int64  `json:"preview_successes"`
	Invocations         int64  `json:"invocations"`
	BusinessOutcome     string `json:"business_outcome_status"`
}
