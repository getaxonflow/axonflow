// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package usage

import "database/sql"

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
}

// LLMRequestEvent represents an LLM API call event to be recorded
type LLMRequestEvent struct {
	OrgID            string
	ClientID         string
	InstanceID       string
	InstanceType     string // Usually "orchestrator"
	LLMProvider      string // "openai", "anthropic", etc.
	LLMModel         string // "gpt-4", "claude-3-sonnet", etc.
	PromptTokens     int
	CompletionTokens int
	TotalTokens      int
	LatencyMs        int64
	HTTPStatusCode   int
}
