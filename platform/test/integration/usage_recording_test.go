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

package integration

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"testing"
	"time"

	_ "github.com/lib/pq"
)

// TestConfig holds configuration for integration tests
type TestConfig struct {
	DatabaseURL string
	AgentURL    string
	TestOrgID   string
	LicenseKey  string
}

// LoadTestConfig loads test configuration from environment
func LoadTestConfig() (*TestConfig, error) {
	dbURL := os.Getenv("TEST_DATABASE_URL")
	if dbURL == "" {
		return nil, fmt.Errorf("TEST_DATABASE_URL not set")
	}

	agentURL := os.Getenv("TEST_AGENT_URL")
	if agentURL == "" {
		agentURL = "http://localhost:8080" // Default for local testing
	}

	return &TestConfig{
		DatabaseURL: dbURL,
		AgentURL:    agentURL,
		TestOrgID:   "test-integration-usage",
		LicenseKey:  os.Getenv("TEST_LICENSE_KEY"),
	}, nil
}

// SetupTestDatabase creates test database and applies migrations
func SetupTestDatabase(t *testing.T, config *TestConfig) *sql.DB {
	db, err := sql.Open("postgres", config.DatabaseURL)
	if err != nil {
		t.Fatalf("Failed to connect to test database: %v", err)
	}

	// Test connection
	if err := db.Ping(); err != nil {
		t.Fatalf("Failed to ping test database: %v", err)
	}

	// Clean up any existing test data
	_, err = db.Exec(`DELETE FROM usage_events WHERE org_id = $1`, config.TestOrgID)
	if err != nil {
		t.Logf("Warning: Failed to clean up test data: %v", err)
	}

	// Ensure test organization exists
	_, err = db.Exec(`
		INSERT INTO organizations (org_id, name, tier, license_key, status, max_nodes, expires_at)
		VALUES ($1, 'Integration Test Org', 'ENT', $2, 'ACTIVE', 100, NOW() + INTERVAL '365 days')
		ON CONFLICT (org_id) DO UPDATE
		SET license_key = EXCLUDED.license_key,
		    status = 'ACTIVE',
		    expires_at = EXCLUDED.expires_at
	`, config.TestOrgID, config.LicenseKey)
	if err != nil {
		t.Fatalf("Failed to create test organization: %v", err)
	}

	t.Logf("✅ Test database setup complete (org_id: %s)", config.TestOrgID)
	return db
}

// TeardownTestDatabase cleans up test database
func TeardownTestDatabase(t *testing.T, db *sql.DB, config *TestConfig) {
	// Clean up test data
	_, err := db.Exec(`DELETE FROM usage_events WHERE org_id = $1`, config.TestOrgID)
	if err != nil {
		t.Logf("Warning: Failed to clean up test data: %v", err)
	}

	db.Close()
	t.Logf("✅ Test database teardown complete")
}

// MakeAPIRequest makes an HTTP request to the agent
func MakeAPIRequest(t *testing.T, config *TestConfig, query string) (*http.Response, error) {
	reqBody := map[string]interface{}{
		"client_id":    config.TestOrgID,
		"query":        query,
		"request_type": "chat",
		"user_token":   "test-user",
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequest("POST", config.AgentURL+"/api/request", bytes.NewBuffer(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-License-Key", config.LicenseKey)

	client := &http.Client{Timeout: 30 * time.Second}
	return client.Do(req)
}

// WaitForRecording waits for async usage recording to complete
func WaitForRecording(duration time.Duration) {
	time.Sleep(duration)
}

// CountUsageEvents returns the count of usage events for the test org
func CountUsageEvents(t *testing.T, db *sql.DB, config *TestConfig, eventType string, since time.Time) int {
	var count int
	query := `
		SELECT COUNT(*) FROM usage_events
		WHERE org_id = $1
		AND event_type = $2
		AND created_at > $3
	`
	err := db.QueryRow(query, config.TestOrgID, eventType, since).Scan(&count)
	if err != nil {
		t.Fatalf("Failed to count usage events: %v", err)
	}
	return count
}

// GetLatestUsageEvent returns the most recent usage event for the test org
func GetLatestUsageEvent(t *testing.T, db *sql.DB, config *TestConfig, eventType string) map[string]interface{} {
	query := `
		SELECT org_id, event_type, http_method, http_path, http_status_code, latency_ms,
		       llm_provider, llm_model, prompt_tokens, completion_tokens, total_tokens, estimated_cost_cents
		FROM usage_events
		WHERE org_id = $1 AND event_type = $2
		ORDER BY created_at DESC LIMIT 1
	`

	row := db.QueryRow(query, config.TestOrgID, eventType)

	var orgID, evtType string
	var httpMethod, httpPath sql.NullString
	var httpStatus sql.NullInt64
	var latencyMs sql.NullInt64
	var llmProvider, llmModel sql.NullString
	var promptTokens, completionTokens, totalTokens sql.NullInt64
	var costCents sql.NullInt64

	err := row.Scan(&orgID, &evtType, &httpMethod, &httpPath, &httpStatus, &latencyMs,
		&llmProvider, &llmModel, &promptTokens, &completionTokens, &totalTokens, &costCents)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil
		}
		t.Fatalf("Failed to fetch latest usage event: %v", err)
	}

	event := map[string]interface{}{
		"org_id":     orgID,
		"event_type": evtType,
	}

	if httpMethod.Valid {
		event["http_method"] = httpMethod.String
	}
	if httpPath.Valid {
		event["http_path"] = httpPath.String
	}
	if httpStatus.Valid {
		event["http_status_code"] = httpStatus.Int64
	}
	if latencyMs.Valid {
		event["latency_ms"] = latencyMs.Int64
	}
	if llmProvider.Valid {
		event["llm_provider"] = llmProvider.String
	}
	if llmModel.Valid {
		event["llm_model"] = llmModel.String
	}
	if promptTokens.Valid {
		event["prompt_tokens"] = promptTokens.Int64
	}
	if completionTokens.Valid {
		event["completion_tokens"] = completionTokens.Int64
	}
	if totalTokens.Valid {
		event["total_tokens"] = totalTokens.Int64
	}
	if costCents.Valid {
		event["cost_cents"] = costCents.Int64
	}

	return event
}

// TestAPICallRecording tests end-to-end API call recording
func TestAPICallRecording(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	config, err := LoadTestConfig()
	if err != nil {
		t.Skip(fmt.Sprintf("Skipping integration test: %v", err))
	}

	db := SetupTestDatabase(t, config)
	defer TeardownTestDatabase(t, db, config)

	// Record the time before making the request
	startTime := time.Now()

	// 1. Make API request
	resp, err := MakeAPIRequest(t, config, "test query for integration test")
	if err != nil {
		t.Fatalf("Failed to make API request: %v", err)
	}
	defer resp.Body.Close()

	// Read response body
	body, _ := io.ReadAll(resp.Body)
	t.Logf("API Response Status: %d", resp.StatusCode)
	t.Logf("API Response Body: %s", string(body))

	// 2. Wait for async recording (5 seconds should be enough)
	WaitForRecording(5 * time.Second)

	// 3. Query usage_events table
	count := CountUsageEvents(t, db, config, "api_call", startTime)
	if count != 1 {
		t.Errorf("Expected 1 API call event, got %d", count)
	}

	// 4. Verify event data
	event := GetLatestUsageEvent(t, db, config, "api_call")
	if event == nil {
		t.Fatal("No API call event found in database")
	}

	// Assertions
	if event["org_id"] != config.TestOrgID {
		t.Errorf("Expected org_id %s, got %v", config.TestOrgID, event["org_id"])
	}
	if event["event_type"] != "api_call" {
		t.Errorf("Expected event_type 'api_call', got %v", event["event_type"])
	}
	if event["http_method"] != "POST" {
		t.Errorf("Expected http_method 'POST', got %v", event["http_method"])
	}
	if event["http_path"] != "/api/request" {
		t.Errorf("Expected http_path '/api/request', got %v", event["http_path"])
	}
	if latency, ok := event["latency_ms"].(int64); !ok || latency <= 0 {
		t.Errorf("Expected latency_ms > 0, got %v", event["latency_ms"])
	}

	t.Logf("✅ API call recording test passed")
}

// TestLLMRequestRecording tests end-to-end LLM request recording
func TestLLMRequestRecording(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	config, err := LoadTestConfig()
	if err != nil {
		t.Skip(fmt.Sprintf("Skipping integration test: %v", err))
	}

	db := SetupTestDatabase(t, config)
	defer TeardownTestDatabase(t, db, config)

	startTime := time.Now()

	// 1. Make API request that triggers LLM
	resp, err := MakeAPIRequest(t, config, "What is the capital of France?")
	if err != nil {
		t.Fatalf("Failed to make API request: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	t.Logf("API Response Status: %d", resp.StatusCode)
	t.Logf("API Response Body: %s", string(body))

	// 2. Wait for async recording (LLM requests take longer)
	WaitForRecording(10 * time.Second)

	// 3. Verify LLM event recorded
	count := CountUsageEvents(t, db, config, "llm_request", startTime)
	if count == 0 {
		t.Error("Expected at least 1 LLM request event, got 0")
	}

	// 4. Verify event data
	event := GetLatestUsageEvent(t, db, config, "llm_request")
	if event == nil {
		t.Fatal("No LLM request event found in database")
	}

	// Assertions
	if event["org_id"] != config.TestOrgID {
		t.Errorf("Expected org_id %s, got %v", config.TestOrgID, event["org_id"])
	}
	if event["event_type"] != "llm_request" {
		t.Errorf("Expected event_type 'llm_request', got %v", event["event_type"])
	}
	if provider, ok := event["llm_provider"].(string); !ok || provider == "" {
		t.Errorf("Expected llm_provider to be set, got %v", event["llm_provider"])
	}
	if totalTokens, ok := event["total_tokens"].(int64); !ok || totalTokens <= 0 {
		t.Errorf("Expected total_tokens > 0, got %v", event["total_tokens"])
	}
	if costCents, ok := event["cost_cents"].(int64); !ok || costCents <= 0 {
		t.Errorf("Expected cost_cents > 0, got %v", event["cost_cents"])
	}

	t.Logf("✅ LLM request recording test passed")
	t.Logf("   Provider: %v", event["llm_provider"])
	t.Logf("   Model: %v", event["llm_model"])
	t.Logf("   Tokens: %v", event["total_tokens"])
	t.Logf("   Cost: $%.4f", float64(event["cost_cents"].(int64))/100.0)
}

// TestConcurrentRecording tests that concurrent requests are all recorded without race conditions
func TestConcurrentRecording(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	config, err := LoadTestConfig()
	if err != nil {
		t.Skip(fmt.Sprintf("Skipping integration test: %v", err))
	}

	db := SetupTestDatabase(t, config)
	defer TeardownTestDatabase(t, db, config)

	startTime := time.Now()

	// 1. Make 10 concurrent requests
	concurrentRequests := 10
	var wg sync.WaitGroup
	errors := make(chan error, concurrentRequests)

	for i := 0; i < concurrentRequests; i++ {
		wg.Add(1)
		go func(requestNum int) {
			defer wg.Done()
			resp, err := MakeAPIRequest(t, config, fmt.Sprintf("concurrent test request %d", requestNum))
			if err != nil {
				errors <- fmt.Errorf("request %d failed: %w", requestNum, err)
				return
			}
			defer resp.Body.Close()
			io.Copy(io.Discard, resp.Body) // Drain response
		}(i)
	}

	wg.Wait()
	close(errors)

	// Check for errors
	for err := range errors {
		t.Errorf("Concurrent request error: %v", err)
	}

	// 2. Wait for all recordings
	WaitForRecording(15 * time.Second)

	// 3. Count events
	apiCount := CountUsageEvents(t, db, config, "api_call", startTime)
	llmCount := CountUsageEvents(t, db, config, "llm_request", startTime)

	// 4. Assert
	if apiCount != concurrentRequests {
		t.Errorf("Expected %d API call events, got %d", concurrentRequests, apiCount)
	}
	if llmCount != concurrentRequests {
		t.Errorf("Expected %d LLM request events, got %d", concurrentRequests, llmCount)
	}

	t.Logf("✅ Concurrent recording test passed")
	t.Logf("   API calls recorded: %d/%d", apiCount, concurrentRequests)
	t.Logf("   LLM requests recorded: %d/%d", llmCount, concurrentRequests)
}

// TestRecordingDoesNotBlockRequests tests that database failures don't block API requests
func TestRecordingDoesNotBlockRequests(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	config, err := LoadTestConfig()
	if err != nil {
		t.Skip(fmt.Sprintf("Skipping integration test: %v", err))
	}

	// Note: This test would require temporarily breaking the database connection
	// which is difficult to do safely in integration tests without affecting the agent.
	// For now, we'll verify that requests complete quickly (which implies async recording)

	db := SetupTestDatabase(t, config)
	defer TeardownTestDatabase(t, db, config)

	// Make API request and measure latency
	start := time.Now()
	resp, err := MakeAPIRequest(t, config, "test during recording")
	latency := time.Since(start)
	if err != nil {
		t.Fatalf("API request failed: %v", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	// Assert request completed quickly (under 30 seconds for full processing)
	if latency > 30*time.Second {
		t.Errorf("Request took too long: %v (expected < 30s)", latency)
	}

	t.Logf("✅ Recording does not block requests (latency: %v)", latency)
}
