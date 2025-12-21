// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
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
	"os"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
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

// TestRecordAPICall tests the RecordAPICall function with sqlmock
func TestRecordAPICall(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create mock: %v", err)
	}
	defer db.Close()

	recorder := NewUsageRecorder(db)

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

	// Expect the INSERT query
	mock.ExpectExec("INSERT INTO usage_events").
		WithArgs(event.OrgID, &event.ClientID, event.InstanceID, event.InstanceType,
			event.HTTPMethod, event.HTTPPath, event.HTTPStatusCode, event.LatencyMs).
		WillReturnResult(sqlmock.NewResult(1, 1))

	err = recorder.RecordAPICall(event)
	if err != nil {
		t.Errorf("RecordAPICall() error = %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("Unfulfilled expectations: %v", err)
	}
}

// TestRecordAPICall_EmptyClientID tests RecordAPICall with empty client ID
func TestRecordAPICall_EmptyClientID(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create mock: %v", err)
	}
	defer db.Close()

	recorder := NewUsageRecorder(db)

	event := APICallEvent{
		OrgID:          "test-org",
		ClientID:       "", // Empty client ID should result in nil
		InstanceID:     "agent-1",
		InstanceType:   "agent",
		HTTPMethod:     "GET",
		HTTPPath:       "/health",
		HTTPStatusCode: 200,
		LatencyMs:      5,
	}

	mock.ExpectExec("INSERT INTO usage_events").
		WithArgs(event.OrgID, nil, event.InstanceID, event.InstanceType,
			event.HTTPMethod, event.HTTPPath, event.HTTPStatusCode, event.LatencyMs).
		WillReturnResult(sqlmock.NewResult(1, 1))

	err = recorder.RecordAPICall(event)
	if err != nil {
		t.Errorf("RecordAPICall() error = %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("Unfulfilled expectations: %v", err)
	}
}

// TestRecordAPICall_Error tests error handling in RecordAPICall
func TestRecordAPICall_Error(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create mock: %v", err)
	}
	defer db.Close()

	recorder := NewUsageRecorder(db)

	event := APICallEvent{
		OrgID:          "test-org",
		InstanceID:     "agent-1",
		InstanceType:   "agent",
		HTTPMethod:     "POST",
		HTTPPath:       "/api/request",
		HTTPStatusCode: 200,
		LatencyMs:      15,
	}

	// Expect the INSERT to fail
	mock.ExpectExec("INSERT INTO usage_events").
		WillReturnError(sqlmock.ErrCancelled)

	err = recorder.RecordAPICall(event)
	if err == nil {
		t.Error("Expected error from RecordAPICall")
	}
}

// TestRecordAPICall_CommunityMode tests that RecordAPICall is a no-op in community mode
func TestRecordAPICall_CommunityMode(t *testing.T) {
	os.Setenv("DEPLOYMENT_MODE", "community")
	defer os.Unsetenv("DEPLOYMENT_MODE")

	recorder := NewUsageRecorder(nil)
	err := recorder.RecordAPICall(APICallEvent{})
	if err != nil {
		t.Fatalf("Expected no-op but failed instead: %v", err)
	}
}

// TestRecordAPICall_EmptyDeploymentMode tests that RecordAPICall is a no-op when DEPLOYMENT_MODE is unset
func TestRecordAPICall_EmptyDeploymentMode(t *testing.T) {
	os.Unsetenv("DEPLOYMENT_MODE")

	recorder := NewUsageRecorder(nil)
	err := recorder.RecordAPICall(APICallEvent{})
	if err != nil {
		t.Fatalf("Expected no-op but failed instead: %v", err)
	}
}

// TestRecordLLMRequest_CommunityMode tests that RecordLLMRequest is a no-op in community mode
func TestRecordLLMRequest_CommunityMode(t *testing.T) {
	os.Setenv("DEPLOYMENT_MODE", "community")
	defer os.Unsetenv("DEPLOYMENT_MODE")

	recorder := NewUsageRecorder(nil)
	err := recorder.RecordLLMRequest(LLMRequestEvent{})
	if err != nil {
		t.Fatalf("Expected no-op but failed instead: %v", err)
	}
}

// TestRecordLLMRequest_EmptyDeploymentMode tests that RecordLLMRequest is a no-op when DEPLOYMENT_MODE is unset
func TestRecordLLMRequest_EmptyDeploymentMode(t *testing.T) {
	os.Unsetenv("DEPLOYMENT_MODE")

	recorder := NewUsageRecorder(nil)
	err := recorder.RecordLLMRequest(LLMRequestEvent{})
	if err != nil {
		t.Fatalf("Expected no-op but failed instead: %v", err)
	}
}

// TestRecordLLMRequest tests the RecordLLMRequest function with sqlmock
func TestRecordLLMRequest(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create mock: %v", err)
	}
	defer db.Close()

	recorder := NewUsageRecorder(db)

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

	// Calculate expected cost (based on CalculateCost)
	expectedCost := CalculateCost(event.LLMProvider, event.LLMModel,
		event.PromptTokens, event.CompletionTokens)

	mock.ExpectExec("INSERT INTO usage_events").
		WithArgs(event.OrgID, &event.ClientID, event.InstanceID, event.InstanceType,
			event.LLMProvider, event.LLMModel, event.PromptTokens, event.CompletionTokens,
			event.TotalTokens, expectedCost, event.LatencyMs, event.HTTPStatusCode).
		WillReturnResult(sqlmock.NewResult(1, 1))

	err = recorder.RecordLLMRequest(event)
	if err != nil {
		t.Errorf("RecordLLMRequest() error = %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("Unfulfilled expectations: %v", err)
	}
}

// TestRecordLLMRequest_Error tests error handling in RecordLLMRequest
func TestRecordLLMRequest_Error(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create mock: %v", err)
	}
	defer db.Close()

	recorder := NewUsageRecorder(db)

	event := LLMRequestEvent{
		OrgID:            "test-org",
		InstanceID:       "orchestrator-1",
		InstanceType:     "orchestrator",
		LLMProvider:      "anthropic",
		LLMModel:         "claude-3-sonnet",
		PromptTokens:     100,
		CompletionTokens: 200,
		TotalTokens:      300,
		LatencyMs:        1500,
		HTTPStatusCode:   200,
	}

	// Expect the INSERT to fail
	mock.ExpectExec("INSERT INTO usage_events").
		WillReturnError(sqlmock.ErrCancelled)

	err = recorder.RecordLLMRequest(event)
	if err == nil {
		t.Error("Expected error from RecordLLMRequest")
	}
}

// TestRecordLLMRequest_EmptyClientID tests RecordLLMRequest with empty client ID
func TestRecordLLMRequest_EmptyClientID(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("Failed to create mock: %v", err)
	}
	defer db.Close()

	recorder := NewUsageRecorder(db)

	event := LLMRequestEvent{
		OrgID:            "test-org",
		ClientID:         "", // Empty should result in nil
		InstanceID:       "orchestrator-1",
		InstanceType:     "orchestrator",
		LLMProvider:      "bedrock",
		LLMModel:         "claude-3-haiku",
		PromptTokens:     50,
		CompletionTokens: 100,
		TotalTokens:      150,
		LatencyMs:        800,
		HTTPStatusCode:   200,
	}

	expectedCost := CalculateCost(event.LLMProvider, event.LLMModel,
		event.PromptTokens, event.CompletionTokens)

	mock.ExpectExec("INSERT INTO usage_events").
		WithArgs(event.OrgID, nil, event.InstanceID, event.InstanceType,
			event.LLMProvider, event.LLMModel, event.PromptTokens, event.CompletionTokens,
			event.TotalTokens, expectedCost, event.LatencyMs, event.HTTPStatusCode).
		WillReturnResult(sqlmock.NewResult(1, 1))

	err = recorder.RecordLLMRequest(event)
	if err != nil {
		t.Errorf("RecordLLMRequest() error = %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("Unfulfilled expectations: %v", err)
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
