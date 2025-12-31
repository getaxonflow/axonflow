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

package agent

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	_ "github.com/lib/pq"
)

// TestGatewayPreCheckIntegration tests the full pre-check flow with a real database
func TestGatewayPreCheckIntegration(t *testing.T) {
	// Skip if DATABASE_URL not provided
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		t.Skip("DATABASE_URL not set, skipping integration test")
	}

	// Enable community mode for testing (no license validation)
	originalDeploymentMode := os.Getenv("DEPLOYMENT_MODE")
	os.Setenv("DEPLOYMENT_MODE", "community")
	defer func() {
		if originalDeploymentMode != "" {
			os.Setenv("DEPLOYMENT_MODE", originalDeploymentMode)
		} else {
			os.Unsetenv("DEPLOYMENT_MODE")
		}
	}()

	// Connect to database
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatalf("Failed to connect to database: %v", err)
	}
	defer db.Close()

	// Test database connection
	if err := db.Ping(); err != nil {
		t.Fatalf("Database ping failed: %v", err)
	}

	// Set global authDB for handlers
	authDB = db

	// Run migration for gateway tables if not exists
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS gateway_contexts (
			context_id VARCHAR(36) PRIMARY KEY,
			client_id VARCHAR(255) NOT NULL,
			user_token_hash VARCHAR(64) NOT NULL,
			query_hash VARCHAR(64) NOT NULL,
			data_sources TEXT[],
			policies_evaluated TEXT[],
			approved BOOLEAN DEFAULT true,
			block_reason TEXT,
			expires_at TIMESTAMP NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)
	`)
	if err != nil {
		t.Fatalf("Failed to create gateway_contexts table: %v", err)
	}

	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS llm_call_audits (
			audit_id VARCHAR(36) PRIMARY KEY,
			context_id VARCHAR(36) REFERENCES gateway_contexts(context_id),
			client_id VARCHAR(255) NOT NULL,
			provider VARCHAR(50) NOT NULL,
			model VARCHAR(100) NOT NULL,
			prompt_tokens INTEGER NOT NULL DEFAULT 0,
			completion_tokens INTEGER NOT NULL DEFAULT 0,
			total_tokens INTEGER NOT NULL DEFAULT 0,
			latency_ms INTEGER NOT NULL DEFAULT 0,
			estimated_cost_usd DECIMAL(10, 6) DEFAULT 0,
			metadata JSONB,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		)
	`)
	if err != nil {
		t.Fatalf("Failed to create llm_call_audits table: %v", err)
	}

	t.Run("Pre-check approved request", func(t *testing.T) {
		// Create test request
		// Use test mode token that bypasses JWT parsing (see run.go:validateUserToken)
		reqBody := PreCheckRequest{
			UserToken:   "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjox.test",
			ClientID:    "test-client-integration",
			Query:       "What is the capital of France?",
			DataSources: []string{"postgres"},
		}
		bodyBytes, _ := json.Marshal(reqBody)

		req := httptest.NewRequest("POST", "/api/policy/pre-check", bytes.NewReader(bodyBytes))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-License-Key", "test-key")

		// Create response recorder
		rr := httptest.NewRecorder()

		// Call handler
		handlePolicyPreCheck(rr, req)

		// Check status
		if rr.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d: %s", rr.Code, rr.Body.String())
		}

		// Parse response
		var resp PreCheckResponse
		if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
			t.Fatalf("Failed to decode response: %v", err)
		}

		// Verify response
		if resp.ContextID == "" {
			t.Error("Expected context_id to be set")
		}
		if !resp.Approved {
			t.Errorf("Expected approved=true, got approved=%v, reason=%s", resp.Approved, resp.BlockReason)
		}
		if resp.ExpiresAt.Before(time.Now()) {
			t.Error("Expected expires_at to be in the future")
		}

		t.Logf("Pre-check approved: contextID=%s, expires=%v", resp.ContextID, resp.ExpiresAt)

		// Verify context was stored in database
		var storedClientID string
		err := db.QueryRow(`SELECT client_id FROM gateway_contexts WHERE context_id = $1`, resp.ContextID).Scan(&storedClientID)
		if err != nil {
			t.Errorf("Failed to query stored context: %v", err)
		}
		if storedClientID != reqBody.ClientID {
			t.Errorf("Expected stored client_id=%s, got %s", reqBody.ClientID, storedClientID)
		}
	})

	t.Run("Audit LLM call after pre-check", func(t *testing.T) {
		// First, do a pre-check to get context ID
		// Use test mode token that bypasses JWT parsing (see run.go:validateUserToken)
		preCheckReq := PreCheckRequest{
			UserToken: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjox.audit-test",
			ClientID:  "test-client-audit",
			Query:     "Test query for audit flow",
		}
		preCheckBody, _ := json.Marshal(preCheckReq)

		req := httptest.NewRequest("POST", "/api/policy/pre-check", bytes.NewReader(preCheckBody))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-License-Key", "test-key")

		rr := httptest.NewRecorder()
		handlePolicyPreCheck(rr, req)

		var preCheckResp PreCheckResponse
		json.NewDecoder(rr.Body).Decode(&preCheckResp)

		if !preCheckResp.Approved {
			t.Skip("Pre-check not approved, skipping audit test")
		}

		// Now submit audit
		auditReq := AuditLLMCallRequest{
			ContextID:       preCheckResp.ContextID,
			ClientID:        preCheckReq.ClientID,
			ResponseSummary: "Paris is the capital of France",
			Provider:        "openai",
			Model:           "gpt-4",
			TokenUsage: TokenUsage{
				PromptTokens:     50,
				CompletionTokens: 25,
				TotalTokens:      75,
			},
			LatencyMs: 500,
			Metadata: map[string]interface{}{
				"session_id": "test-session-123",
			},
		}
		auditBody, _ := json.Marshal(auditReq)

		auditHTTP := httptest.NewRequest("POST", "/api/audit/llm-call", bytes.NewReader(auditBody))
		auditHTTP.Header.Set("Content-Type", "application/json")
		auditHTTP.Header.Set("X-License-Key", "test-key")

		auditRR := httptest.NewRecorder()
		handleAuditLLMCall(auditRR, auditHTTP)

		// Check status
		if auditRR.Code != http.StatusOK {
			t.Errorf("Expected status 200, got %d: %s", auditRR.Code, auditRR.Body.String())
		}

		// Parse response
		var auditResp AuditLLMCallResponse
		if err := json.NewDecoder(auditRR.Body).Decode(&auditResp); err != nil {
			t.Fatalf("Failed to decode audit response: %v", err)
		}

		// Verify response
		if !auditResp.Success {
			t.Error("Expected audit success=true")
		}
		if auditResp.AuditID == "" {
			t.Error("Expected audit_id to be set")
		}

		t.Logf("Audit recorded: auditID=%s", auditResp.AuditID)

		// Verify audit was stored in database
		var storedProvider string
		var storedTokens int
		err := db.QueryRow(`
			SELECT provider, total_tokens FROM llm_call_audits WHERE audit_id = $1
		`, auditResp.AuditID).Scan(&storedProvider, &storedTokens)
		if err != nil {
			t.Errorf("Failed to query stored audit: %v", err)
		}
		if storedProvider != "openai" {
			t.Errorf("Expected stored provider=openai, got %s", storedProvider)
		}
		if storedTokens != 75 {
			t.Errorf("Expected stored tokens=75, got %d", storedTokens)
		}
	})

	// Cleanup test data
	t.Cleanup(func() {
		db.Exec(`DELETE FROM llm_call_audits WHERE client_id LIKE 'test-client%'`)
		db.Exec(`DELETE FROM gateway_contexts WHERE client_id LIKE 'test-client%'`)
	})
}

// TestGatewayValidationErrors tests validation error cases
func TestGatewayValidationErrors(t *testing.T) {
	// Enable community mode (no license validation)
	originalDeploymentMode := os.Getenv("DEPLOYMENT_MODE")
	os.Setenv("DEPLOYMENT_MODE", "community")
	defer func() {
		if originalDeploymentMode != "" {
			os.Setenv("DEPLOYMENT_MODE", originalDeploymentMode)
		} else {
			os.Unsetenv("DEPLOYMENT_MODE")
		}
	}()

	tests := []struct {
		name           string
		request        PreCheckRequest
		expectedStatus int
		expectedError  string
	}{
		{
			name: "Missing query",
			request: PreCheckRequest{
				ClientID:  "test-client",
				UserToken: "test-token",
			},
			expectedStatus: http.StatusBadRequest,
			expectedError:  "query field is required",
		},
		{
			name: "Missing client_id",
			request: PreCheckRequest{
				Query:     "test query",
				UserToken: "test-token",
			},
			expectedStatus: http.StatusBadRequest,
			expectedError:  "client_id field is required",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			bodyBytes, _ := json.Marshal(tc.request)
			req := httptest.NewRequest("POST", "/api/policy/pre-check", bytes.NewReader(bodyBytes))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-License-Key", "test-key")

			rr := httptest.NewRecorder()
			handlePolicyPreCheck(rr, req)

			if rr.Code != tc.expectedStatus {
				t.Errorf("Expected status %d, got %d", tc.expectedStatus, rr.Code)
			}

			var resp map[string]interface{}
			json.NewDecoder(rr.Body).Decode(&resp)
			if errMsg, ok := resp["error"].(string); ok {
				if errMsg != tc.expectedError {
					t.Errorf("Expected error '%s', got '%s'", tc.expectedError, errMsg)
				}
			}
		})
	}
}

// TestAuditValidationErrors tests audit endpoint validation
func TestAuditValidationErrors(t *testing.T) {
	// Enable community mode (no license validation)
	originalDeploymentMode := os.Getenv("DEPLOYMENT_MODE")
	os.Setenv("DEPLOYMENT_MODE", "community")
	defer func() {
		if originalDeploymentMode != "" {
			os.Setenv("DEPLOYMENT_MODE", originalDeploymentMode)
		} else {
			os.Unsetenv("DEPLOYMENT_MODE")
		}
	}()

	tests := []struct {
		name           string
		request        AuditLLMCallRequest
		expectedStatus int
		expectedError  string
	}{
		{
			name: "Missing context_id",
			request: AuditLLMCallRequest{
				ClientID: "test-client",
				Provider: "openai",
				Model:    "gpt-4",
			},
			expectedStatus: http.StatusBadRequest,
			expectedError:  "context_id field is required",
		},
		{
			name: "Missing provider",
			request: AuditLLMCallRequest{
				ContextID: "ctx-123",
				ClientID:  "test-client",
				Model:     "gpt-4",
			},
			expectedStatus: http.StatusBadRequest,
			expectedError:  "provider field is required",
		},
		{
			name: "Missing model",
			request: AuditLLMCallRequest{
				ContextID: "ctx-123",
				ClientID:  "test-client",
				Provider:  "openai",
			},
			expectedStatus: http.StatusBadRequest,
			expectedError:  "model field is required",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			bodyBytes, _ := json.Marshal(tc.request)
			req := httptest.NewRequest("POST", "/api/audit/llm-call", bytes.NewReader(bodyBytes))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-License-Key", "test-key")

			rr := httptest.NewRecorder()
			handleAuditLLMCall(rr, req)

			if rr.Code != tc.expectedStatus {
				t.Errorf("Expected status %d, got %d", tc.expectedStatus, rr.Code)
			}

			var resp map[string]interface{}
			json.NewDecoder(rr.Body).Decode(&resp)
			if errMsg, ok := resp["error"].(string); ok {
				if errMsg != tc.expectedError {
					t.Errorf("Expected error '%s', got '%s'", tc.expectedError, errMsg)
				}
			}
		})
	}
}

// TestLLMCostCalculation tests the cost calculation function
func TestLLMCostCalculation(t *testing.T) {
	tests := []struct {
		name         string
		provider     string
		model        string
		tokens       TokenUsage
		expectedCost float64
	}{
		{
			name:     "OpenAI GPT-4",
			provider: "openai",
			model:    "gpt-4",
			tokens: TokenUsage{
				TotalTokens: 1000,
			},
			expectedCost: 0.03, // $0.03 per 1K tokens
		},
		{
			name:     "Anthropic Claude 3 Sonnet",
			provider: "anthropic",
			model:    "claude-3-sonnet",
			tokens: TokenUsage{
				TotalTokens: 1000,
			},
			expectedCost: 0.003, // $0.003 per 1K tokens
		},
		{
			name:     "Ollama local (free)",
			provider: "ollama",
			model:    "llama2",
			tokens: TokenUsage{
				TotalTokens: 1000,
			},
			expectedCost: 0.0, // Local, no cost
		},
		{
			name:     "Unknown provider",
			provider: "unknown-provider",
			model:    "unknown-model",
			tokens: TokenUsage{
				TotalTokens: 1000,
			},
			expectedCost: 0.01, // Conservative default
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cost := calculateLLMCost(tc.provider, tc.model, tc.tokens)
			if cost != tc.expectedCost {
				t.Errorf("Expected cost $%.6f, got $%.6f", tc.expectedCost, cost)
			}
		})
	}
}

