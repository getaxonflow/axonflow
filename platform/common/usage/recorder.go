// Copyright 2025 AxonFlow
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package usage

import (
	"database/sql"
	"log"
)

// UsageRecorder handles recording usage events to the database
type UsageRecorder struct {
	db *sql.DB
}

// NewUsageRecorder creates a new usage recorder with a database connection
func NewUsageRecorder(db *sql.DB) *UsageRecorder {
	return &UsageRecorder{db: db}
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

// RecordAPICall records an API call event to the database
// Uses goroutine-safe async pattern - errors are logged but don't block responses
func (r *UsageRecorder) RecordAPICall(event APICallEvent) error {
	_, err := r.db.Exec(`
		INSERT INTO usage_events (
			org_id, client_id, event_type, instance_id, instance_type,
			http_method, http_path, http_status_code, latency_ms
		) VALUES ($1, $2, 'api_call', $3, $4, $5, $6, $7, $8)
	`, event.OrgID, nullString(event.ClientID), event.InstanceID,
		event.InstanceType, event.HTTPMethod, event.HTTPPath,
		event.HTTPStatusCode, event.LatencyMs)

	if err != nil {
		log.Printf("[USAGE] Failed to record API call: %v", err)
	}

	return err
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

// RecordLLMRequest records an LLM API call event with token usage and cost
// Uses goroutine-safe async pattern - errors are logged but don't block responses
func (r *UsageRecorder) RecordLLMRequest(event LLMRequestEvent) error {
	// Calculate cost based on provider pricing
	costCents := CalculateCost(event.LLMProvider, event.LLMModel,
		event.PromptTokens, event.CompletionTokens)

	_, err := r.db.Exec(`
		INSERT INTO usage_events (
			org_id, client_id, event_type, instance_id, instance_type,
			llm_provider, llm_model, prompt_tokens, completion_tokens,
			total_tokens, estimated_cost_cents, latency_ms, http_status_code
		) VALUES ($1, $2, 'llm_request', $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
	`, event.OrgID, nullString(event.ClientID), event.InstanceID,
		event.InstanceType, event.LLMProvider, event.LLMModel,
		event.PromptTokens, event.CompletionTokens, event.TotalTokens,
		costCents, event.LatencyMs, event.HTTPStatusCode)

	if err != nil {
		log.Printf("[USAGE] Failed to record LLM request: %v", err)
	}

	return err
}

// nullString converts an empty string to NULL for database insertion
func nullString(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
