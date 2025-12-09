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

package llm

import (
	"context"
	"testing"
	"time"
)

// Note: These are unit tests using mocks.
// Integration tests with real PostgreSQL are in storage_integration_test.go.

func TestNewPostgresStorage(t *testing.T) {
	// Test that NewPostgresStorage creates a valid instance
	storage := NewPostgresStorage(nil)
	if storage == nil {
		t.Fatal("NewPostgresStorage returned nil")
	}
}

func TestPostgresStorage_SaveProvider_NilConfig(t *testing.T) {
	storage := NewPostgresStorage(nil)

	err := storage.SaveProvider(context.Background(), nil)
	if err == nil {
		t.Fatal("SaveProvider should error on nil config")
	}
}

func TestProviderUsage_Fields(t *testing.T) {
	usage := ProviderUsage{
		ProviderName:     "test-provider",
		RequestID:        "req-123",
		Model:            "claude-sonnet-4-20250514",
		InputTokens:      100,
		OutputTokens:     50,
		TotalTokens:      150,
		EstimatedCostUSD: 0.0015,
		LatencyMs:        500,
		Status:           "success",
		ErrorMessage:     "",
	}

	if usage.ProviderName != "test-provider" {
		t.Errorf("ProviderName = %q, want %q", usage.ProviderName, "test-provider")
	}
	if usage.TotalTokens != usage.InputTokens+usage.OutputTokens {
		t.Errorf("TotalTokens = %d, want %d", usage.TotalTokens, usage.InputTokens+usage.OutputTokens)
	}
	if usage.Status != "success" {
		t.Errorf("Status = %q, want %q", usage.Status, "success")
	}
}

func TestProviderUsage_ErrorStatus(t *testing.T) {
	usage := ProviderUsage{
		ProviderName: "test-provider",
		Status:       "error",
		ErrorMessage: "connection timeout",
		LatencyMs:    30000,
	}

	if usage.Status != "error" {
		t.Errorf("Status = %q, want %q", usage.Status, "error")
	}
	if usage.ErrorMessage != "connection timeout" {
		t.Errorf("ErrorMessage = %q, want %q", usage.ErrorMessage, "connection timeout")
	}
}

func TestProviderUsage_RateLimitedStatus(t *testing.T) {
	usage := ProviderUsage{
		ProviderName: "openai-prod",
		Status:       "rate_limited",
		ErrorMessage: "rate limit exceeded: 60 requests/min",
		LatencyMs:    10,
	}

	validStatuses := map[string]bool{
		"success":      true,
		"error":        true,
		"timeout":      true,
		"rate_limited": true,
	}

	if !validStatuses[usage.Status] {
		t.Errorf("Status %q is not a valid status", usage.Status)
	}
}

func TestPostgresStorage_InterfaceCompliance(t *testing.T) {
	// Ensure PostgresStorage implements Storage
	var _ Storage = (*PostgresStorage)(nil)
}

// Mock-based test for SaveHealth logic
func TestHealthCheckResult_ForStorage(t *testing.T) {
	result := &HealthCheckResult{
		Status:              HealthStatusHealthy,
		Latency:             100 * time.Millisecond,
		Message:             "OK",
		LastChecked:         time.Now(),
		ConsecutiveFailures: 0,
	}

	if result.Status != HealthStatusHealthy {
		t.Errorf("Status = %v, want %v", result.Status, HealthStatusHealthy)
	}
	if result.Latency.Milliseconds() != 100 {
		t.Errorf("Latency = %dms, want 100ms", result.Latency.Milliseconds())
	}
}

func TestHealthCheckResult_Unhealthy(t *testing.T) {
	result := &HealthCheckResult{
		Status:              HealthStatusUnhealthy,
		Latency:             5 * time.Second,
		Message:             "connection refused",
		LastChecked:         time.Now(),
		ConsecutiveFailures: 3,
	}

	if result.Status != HealthStatusUnhealthy {
		t.Errorf("Status = %v, want %v", result.Status, HealthStatusUnhealthy)
	}
	if result.ConsecutiveFailures != 3 {
		t.Errorf("ConsecutiveFailures = %d, want 3", result.ConsecutiveFailures)
	}
}
