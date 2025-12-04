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
	"testing"
)

// TestNewUsageRecorder tests recorder creation
func TestNewUsageRecorder(t *testing.T) {
	// Use nil db for testing (integration tests would use real DB)
	recorder := NewUsageRecorder(nil)
	if recorder == nil {
		t.Error("NewUsageRecorder() returned nil")
	}
	if recorder.db != nil {
		t.Error("Expected nil database connection in unit test")
	}
}

// TestNullString tests the nullString helper function
func TestNullString(t *testing.T) {
	tests := []struct {
		name  string
		input string
		isNil bool
	}{
		{"Empty string returns nil", "", true},
		{"Non-empty string returns pointer", "test", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := nullString(tt.input)
			if tt.isNil && result != nil {
				t.Errorf("nullString(%q) should return nil", tt.input)
			}
			if !tt.isNil && result == nil {
				t.Errorf("nullString(%q) should not return nil", tt.input)
			}
			if !tt.isNil && *result != tt.input {
				t.Errorf("nullString(%q) = %q, want %q", tt.input, *result, tt.input)
			}
		})
	}
}

// TestAPICallEvent_Fields tests that APICallEvent has all required fields
func TestAPICallEvent_Fields(t *testing.T) {
	event := APICallEvent{
		OrgID:          "test-org",
		ClientID:       "test-client",
		InstanceID:     "agent-1",
		InstanceType:   "agent",
		HTTPMethod:     "POST",
		HTTPPath:       "/api/request",
		HTTPStatusCode: 200,
		LatencyMs:      15,
	}

	if event.OrgID == "" {
		t.Error("OrgID should not be empty")
	}
	if event.InstanceType != "agent" && event.InstanceType != "orchestrator" {
		t.Error("InstanceType should be 'agent' or 'orchestrator'")
	}
	if event.HTTPStatusCode < 100 || event.HTTPStatusCode > 599 {
		t.Error("HTTPStatusCode should be valid HTTP status code")
	}
	if event.LatencyMs < 0 {
		t.Error("LatencyMs should not be negative")
	}
}

// TestLLMRequestEvent_Fields tests that LLMRequestEvent has all required fields
func TestLLMRequestEvent_Fields(t *testing.T) {
	event := LLMRequestEvent{
		OrgID:            "test-org",
		ClientID:         "test-client",
		InstanceID:       "orchestrator-1",
		InstanceType:     "orchestrator",
		LLMProvider:      "openai",
		LLMModel:         "gpt-4",
		PromptTokens:     150,
		CompletionTokens: 300,
		TotalTokens:      450,
		LatencyMs:        2500,
		HTTPStatusCode:   200,
	}

	if event.OrgID == "" {
		t.Error("OrgID should not be empty")
	}
	if event.LLMProvider == "" {
		t.Error("LLMProvider should not be empty")
	}
	if event.LLMModel == "" {
		t.Error("LLMModel should not be empty")
	}
	if event.TotalTokens != event.PromptTokens+event.CompletionTokens {
		t.Error("TotalTokens should equal PromptTokens + CompletionTokens")
	}
}

// Integration test helpers (commented out - requires real database)
// Uncomment and run with DATABASE_URL set for full integration testing

/*
func setupTestDB(t *testing.T) *sql.DB {
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		t.Skip("DATABASE_URL not set, skipping integration test")
	}

	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatalf("Failed to connect to database: %v", err)
	}

	if err := db.Ping(); err != nil {
		t.Fatalf("Failed to ping database: %v", err)
	}

	return db
}

func TestRecordAPICall_Integration(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	recorder := NewUsageRecorder(db)

	event := APICallEvent{
		OrgID:          "test-org-integration",
		ClientID:       "test-client",
		InstanceID:     "agent-test",
		InstanceType:   "agent",
		HTTPMethod:     "POST",
		HTTPPath:       "/api/request",
		HTTPStatusCode: 200,
		LatencyMs:      15,
	}

	err := recorder.RecordAPICall(event)
	if err != nil {
		t.Errorf("RecordAPICall() error = %v", err)
	}
}

func TestRecordLLMRequest_Integration(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	recorder := NewUsageRecorder(db)

	event := LLMRequestEvent{
		OrgID:            "test-org-integration",
		ClientID:         "test-client",
		InstanceID:       "orchestrator-test",
		InstanceType:     "orchestrator",
		LLMProvider:      "openai",
		LLMModel:         "gpt-4",
		PromptTokens:     150,
		CompletionTokens: 300,
		TotalTokens:      450,
		LatencyMs:        2500,
		HTTPStatusCode:   200,
	}

	err := recorder.RecordLLMRequest(event)
	if err != nil {
		t.Errorf("RecordLLMRequest() error = %v", err)
	}
}
*/
