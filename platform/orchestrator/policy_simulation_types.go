// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import "time"

// SimulatePoliciesRequest is the request body for POST /api/v1/policies/simulate.
// Runs all active policies against the provided input as a dry run (no audit writes, no action application).
type SimulatePoliciesRequest struct {
	Query       string                 `json:"query"`
	RequestType string                 `json:"request_type,omitempty"`
	User        UserContext            `json:"user,omitempty"`
	Client      ClientContext          `json:"client,omitempty"`
	Context     map[string]interface{} `json:"context,omitempty"`
}

// SimulatePoliciesResponse is the response for POST /api/v1/policies/simulate.
type SimulatePoliciesResponse struct {
	Allowed          bool                  `json:"allowed"`
	AppliedPolicies  []string              `json:"applied_policies"`
	RiskScore        float64               `json:"risk_score"`
	RequiredActions  []string              `json:"required_actions"`
	ProcessingTimeMs int64                 `json:"processing_time_ms"`
	TotalPolicies    int                   `json:"total_policies"`
	DryRun           bool                  `json:"dry_run"`
	SimulatedAt      time.Time             `json:"simulated_at"`
	Tier             string                `json:"tier"`
	DailyUsage       *SimulationDailyUsage `json:"daily_usage,omitempty"`

	// SegmentsResolved is Signal B (#3239 round 2, M4) — mirrors
	// PolicyEvaluationResult.SegmentsResolved: true only when a resolved,
	// non-empty ADR-060 governance-segment set was actually factored into
	// this simulated verdict. false covers every legitimate org-only case
	// (no email supplied, no resolver wired, zero group memberships) — an
	// admin must not mistake an org-only Allowed for a segment-aware one.
	SegmentsResolved bool `json:"segments_resolved"`
}

// SimulationDailyUsage tracks simulation quota usage.
type SimulationDailyUsage struct {
	Used  int `json:"used"`
	Limit int `json:"limit"` // -1 = unlimited
}

// ImpactReportRequest is the request body for POST /api/v1/policies/impact-report.
// Tests a single policy against multiple inputs and returns aggregate stats.
type ImpactReportRequest struct {
	PolicyID string              `json:"policy_id"`
	Inputs   []ImpactReportInput `json:"inputs"`
}

// ImpactReportInput is a single test input for the impact report.
type ImpactReportInput struct {
	Query       string                 `json:"query"`
	RequestType string                 `json:"request_type,omitempty"`
	User        map[string]interface{} `json:"user,omitempty"`
	Context     map[string]interface{} `json:"context,omitempty"`
}

// ImpactReportResponse is the response for POST /api/v1/policies/impact-report.
type ImpactReportResponse struct {
	PolicyID         string               `json:"policy_id"`
	PolicyName       string               `json:"policy_name,omitempty"`
	TotalInputs      int                  `json:"total_inputs"`
	Matched          int                  `json:"matched"`
	Blocked          int                  `json:"blocked"`
	MatchRate        float64              `json:"match_rate"`
	BlockRate        float64              `json:"block_rate"`
	Results          []ImpactReportResult `json:"results"`
	ProcessingTimeMs int64                `json:"processing_time_ms"`
	GeneratedAt      time.Time            `json:"generated_at"`
	Tier             string               `json:"tier"`
}

// ImpactReportResult is the result for a single input in the impact report.
type ImpactReportResult struct {
	InputIndex int      `json:"input_index"`
	Matched    bool     `json:"matched"`
	Blocked    bool     `json:"blocked"`
	Actions    []string `json:"actions,omitempty"`
}
