// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package usage

import (
	"database/sql"
	"time"
)

// UsageRecorder handles recording usage events to the database.
// In Community builds, all methods are no-ops.
// In Enterprise builds, events are persisted to PostgreSQL.
type UsageRecorder struct {
	db *sql.DB
}

// APICallEvent represents an API call event to be recorded
type APICallEvent struct {
	OrgID          string
	ClientID       string // Optional: extracted from license key or API key
	InstanceID     string // Which agent/orchestrator processed this
	InstanceType   string // "agent" or "orchestrator"
	HTTPMethod     string
	HTTPPath       string
	HTTPStatusCode int
	LatencyMs      int64
	// Governance metrics (optional). Populated by the MCP-server governance
	// path (check_policy / check_output) so the Usage page reflects policy
	// activity, not just raw request counts. Zero for non-governance API
	// calls (e.g. the SDK /process path). The usage_events table has carried
	// these columns since migration 081; they were simply never written on
	// the governance path (#2758).
	PoliciesEvaluated int
	PolicyViolations  int
}

// OTELMetricEvent is one OTLP metric datapoint from the authenticated
// /v1/metrics ingest (#2832), landing as a usage_events row with
// event_type='claude_code_metric'. Value carries the datapoint exactly as
// exported; the recorder normalizes it to a DELTA before insert (cumulative
// streams are converted using the prior datapoint of the same series), so
// SUM(metric_value) per metric_name is always correct.
//
// SessionID / UserEmail are ASSERTED attribution labels from the telemetry —
// the org scope on the row comes from the authenticated license, never from
// these fields.
type OTELMetricEvent struct {
	ClientID     string
	InstanceID   string
	InstanceType string

	SessionID   string
	UserEmail   string
	MetricName  string            // e.g. "claude_code.token.usage"
	Value       float64           // datapoint value as exported (see Temporality)
	Temporality string            // TemporalityDelta or TemporalityCumulative
	SeriesKey   string            // sha256 hex over org + metric name + full attribute set
	Attributes  map[string]string // allowlisted structural attributes only
	Time        time.Time         // datapoint TimeUnixNano (zero → NULL)
	StartTime   time.Time         // datapoint StartTimeUnixNano (zero → NULL)

	// Legacy-column mirroring: when set, the normalized delta is also written
	// into the existing token/cost columns so the usage_hourly / usage_daily
	// rollups (which sum those columns) carry Claude Code usage unchanged.
	CountsTokens  bool   // metric counts tokens → prompt/completion/total_tokens
	TokenType     string // "input" | "output" | cache types (from the `type` attribute)
	CountsCostUSD bool   // metric counts USD cost → estimated_cost_cents (rounded)
}

// Aggregation temporality values for OTELMetricEvent.Temporality.
const (
	TemporalityDelta      = "delta"
	TemporalityCumulative = "cumulative"
)

// LLMRequestEvent represents an LLM API call event to be recorded
type LLMRequestEvent struct {
	OrgID            string
	ClientID         string
	InstanceID       string
	InstanceType     string // Usually "orchestrator"
	LLMProvider      string // "openai", "anthropic", etc.
	LLMModel         string // "gpt-4o", "claude-sonnet-4", etc.
	PromptTokens     int
	CompletionTokens int
	TotalTokens      int
	LatencyMs        int64
	HTTPStatusCode   int
}
