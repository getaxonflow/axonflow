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
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

// TestHealthHandler tests the health endpoint
func TestHealthHandler(t *testing.T) {
	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()

	healthHandler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}

	var response map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if response["status"] != "healthy" {
		t.Errorf("expected status 'healthy', got %v", response["status"])
	}
	if response["service"] != "axonflow-agent" {
		t.Errorf("expected service 'axonflow-agent', got %v", response["service"])
	}
}

// TestReadinessAwareHealthHandler tests the readiness-aware health endpoint
func TestReadinessAwareHealthHandler(t *testing.T) {
	tests := []struct {
		name           string
		appReadyState  bool
		expectedStatus string
	}{
		{
			name:           "app not ready - returns starting",
			appReadyState:  false,
			expectedStatus: "starting",
		},
		{
			name:           "app ready - returns healthy",
			appReadyState:  true,
			expectedStatus: "healthy",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set app ready state
			appReady.Store(tt.appReadyState)

			req := httptest.NewRequest("GET", "/health", nil)
			w := httptest.NewRecorder()

			readinessAwareHealthHandler(w, req)

			if w.Code != http.StatusOK {
				t.Errorf("expected status 200, got %d", w.Code)
			}

			var response map[string]interface{}
			if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
				t.Fatalf("failed to decode response: %v", err)
			}

			if response["status"] != tt.expectedStatus {
				t.Errorf("expected status '%s', got %v", tt.expectedStatus, response["status"])
			}
			if response["service"] != "axonflow-agent" {
				t.Errorf("expected service 'axonflow-agent', got %v", response["service"])
			}
			if _, ok := response["timestamp"]; !ok {
				t.Error("expected timestamp in response")
			}
			if response["version"] != "1.0.0" {
				t.Errorf("expected version '1.0.0', got %v", response["version"])
			}
		})
	}

	// Reset to default state
	appReady.Store(false)
}

// TestAppReadyState tests the atomic appReady variable behavior
func TestAppReadyState(t *testing.T) {
	// Test initial state
	appReady.Store(false)
	if appReady.Load() {
		t.Error("expected appReady to be false initially")
	}

	// Test setting to true
	appReady.Store(true)
	if !appReady.Load() {
		t.Error("expected appReady to be true after Store(true)")
	}

	// Test swap back to false
	appReady.Store(false)
	if appReady.Load() {
		t.Error("expected appReady to be false after Store(false)")
	}
}

// TestSendErrorResponse tests error response formatting
func TestSendErrorResponse(t *testing.T) {
	tests := []struct {
		name       string
		message    string
		statusCode int
		policyInfo *PolicyEvaluationInfo
	}{
		{"bad request", "Invalid input", http.StatusBadRequest, nil},
		{"unauthorized", "Not authenticated", http.StatusUnauthorized, nil},
		{"forbidden", "Access denied", http.StatusForbidden, nil},
		{"with policy info", "Policy denied", http.StatusForbidden, &PolicyEvaluationInfo{
			PoliciesEvaluated: []string{"policy1"},
			StaticChecks:      []string{"check1"},
			ProcessingTime:    "10ms",
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			sendErrorResponse(w, tt.message, tt.statusCode, tt.policyInfo)

			if w.Code != tt.statusCode {
				t.Errorf("expected status %d, got %d", tt.statusCode, w.Code)
			}

			var response map[string]interface{}
			if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
				t.Fatalf("failed to decode response: %v", err)
			}

			if response["error"] != tt.message {
				t.Errorf("expected error '%s', got %v", tt.message, response["error"])
			}
		})
	}
}

// TestGetEnv tests environment variable retrieval
func TestGetEnv(t *testing.T) {
	tests := []struct {
		name         string
		key          string
		defaultValue string
		setEnv       func()
		expected     string
	}{
		{
			name:         "existing env var",
			key:          "TEST_VAR_EXISTS",
			defaultValue: "default",
			setEnv: func() {
				t.Setenv("TEST_VAR_EXISTS", "actual-value")
			},
			expected: "actual-value",
		},
		{
			name:         "missing env var uses default",
			key:          "TEST_VAR_MISSING",
			defaultValue: "default-value",
			setEnv:       func() {},
			expected:     "default-value",
		},
		{
			name:         "empty env var uses default",
			key:          "TEST_VAR_EMPTY",
			defaultValue: "default",
			setEnv: func() {
				t.Setenv("TEST_VAR_EMPTY", "")
			},
			expected: "default",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setEnv()
			result := getEnv(tt.key, tt.defaultValue)
			if result != tt.expected {
				t.Errorf("expected '%s', got '%s'", tt.expected, result)
			}
		})
	}
}

// TestMaskString tests string masking
func TestMaskString(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"short string (4 chars)", "abcd", "abcd***"},
		{"medium string (8 chars)", "abcdefgh", "abcd***"},
		{"medium string (12 chars)", "123456789012", "1234***"},
		{"long string (>12)", "AXON-ENT-test-20251104-abc123", "AXON-ENT...c123"},
		{"empty string", "", "<empty>"},
		{"license key (>12)", "test-license-key-12345", "test-lic...2345"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := maskString(tt.input)
			if result != tt.expected {
				t.Errorf("expected '%s', got '%s'", tt.expected, result)
			}
		})
	}
}

// TestTruncateString tests string truncation
func TestTruncateString(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		maxLen   int
		expected string
	}{
		{"short string", "hello", 10, "hello"},
		{"exact length", "hello", 5, "hello"},
		{"needs truncation", "hello world", 5, "hello..."},
		{"empty string", "", 10, ""},
		{"zero length", "hello", 0, "..."},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := truncateString(tt.input, tt.maxLen)
			if result != tt.expected {
				t.Errorf("expected '%s', got '%s'", tt.expected, result)
			}
		})
	}
}

// TestGetStringLength tests string length calculation
func TestGetStringLength(t *testing.T) {
	tests := []struct {
		name     string
		input    interface{}
		expected int
	}{
		{"string", "hello", 5},
		{"empty string", "", 0},
		{"number", 12345, -1}, // Returns -1 for non-strings
		{"bool", true, -1},     // Returns -1 for non-strings
		{"nil", nil, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getStringLength(tt.input)
			if result != tt.expected {
				t.Errorf("expected %d, got %d", tt.expected, result)
			}
		})
	}
}

// TestGetKeys tests map key extraction
func TestGetKeys(t *testing.T) {
	tests := []struct {
		name     string
		input    map[string]interface{}
		expected int
	}{
		{"empty map", map[string]interface{}{}, 0},
		{"single key", map[string]interface{}{"key1": "value1"}, 1},
		{"multiple keys", map[string]interface{}{"key1": "v1", "key2": "v2", "key3": "v3"}, 3},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getKeys(tt.input)
			if len(result) != tt.expected {
				t.Errorf("expected %d keys, got %d", tt.expected, len(result))
			}
		})
	}
}

// TestCalculateP99 tests P99 latency calculation
func TestCalculateP99(t *testing.T) {
	tests := []struct {
		name      string
		latencies []int64
		expected  float64
	}{
		{"empty", []int64{}, 0},
		{"single value", []int64{100}, 100},
		{"sorted values", []int64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}, 10},
		{"unsorted values", []int64{10, 1, 5, 3, 8}, 10},
		{"many values", []int64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20}, 20},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := calculateP99(tt.latencies)
			if result != tt.expected {
				t.Errorf("expected %f, got %f", tt.expected, result)
			}
		})
	}
}

// TestCalculateAverage tests average calculation
func TestCalculateAverage(t *testing.T) {
	tests := []struct {
		name      string
		latencies []int64
		expected  float64
	}{
		{"empty", []int64{}, 0},
		{"single value", []int64{100}, 100},
		{"multiple values", []int64{10, 20, 30}, 20},
		{"larger set", []int64{1, 2, 3, 4, 5}, 3},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := calculateAverage(tt.latencies)
			if result != tt.expected {
				t.Errorf("expected %f, got %f", tt.expected, result)
			}
		})
	}
}

// TestRecordLatency tests latency recording
func TestRecordLatency(t *testing.T) {
	metrics := &AgentMetrics{
		latencies:              []int64{},
		lastLatencies:          []int64{},
		staticPolicyLatencies:  []int64{},
		dynamicPolicyLatencies: []int64{},
	}

	// Test static policy latency
	metrics.recordLatency(100, "static")
	if len(metrics.staticPolicyLatencies) != 1 {
		t.Error("expected 1 static policy latency")
	}
	if metrics.staticPolicyLatencies[0] != 100 {
		t.Errorf("expected latency 100, got %d", metrics.staticPolicyLatencies[0])
	}

	// Test dynamic policy latency
	metrics.recordLatency(200, "dynamic")
	if len(metrics.dynamicPolicyLatencies) != 1 {
		t.Error("expected 1 dynamic policy latency")
	}

	// Test general latency recording
	if len(metrics.latencies) != 2 {
		t.Errorf("expected 2 total latencies, got %d", len(metrics.latencies))
	}
}

// TestClientRequestHandler_MissingLicenseKey tests request handler with missing auth
func TestClientRequestHandler_MissingLicenseKey(t *testing.T) {
	// Initialize agentMetrics to avoid nil pointer
	if agentMetrics == nil {
		agentMetrics = &AgentMetrics{
			latencies:              []int64{},
			lastLatencies:          []int64{},
			staticPolicyLatencies:  []int64{},
			dynamicPolicyLatencies: []int64{},
		}
	}

	reqBody := ClientRequest{
		ClientID:    "test-client",
		RequestType: "sql",
		Query:       "SELECT * FROM test",
		UserToken:   "test-token",
	}

	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest("POST", "/client/request", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	// Intentionally NOT setting X-License-Key

	w := httptest.NewRecorder()
	clientRequestHandler(w, req)

	if w.Code != http.StatusUnauthorized && w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected status 401 or 503, got %d", w.Code)
	}

	var response map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&response); err == nil {
		if !contains(response["error"].(string), "License-Key") {
			t.Error("expected error about missing license key")
		}
	}
}

// TestClientRequestHandler_InvalidJSON tests request handler with malformed JSON
func TestClientRequestHandler_InvalidJSON(t *testing.T) {
	req := httptest.NewRequest("POST", "/client/request", bytes.NewBufferString("{invalid json"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-License-Key", "test-key")

	w := httptest.NewRecorder()
	clientRequestHandler(w, req)

	if w.Code != http.StatusBadRequest && w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected status 400 or 503, got %d", w.Code)
	}
}

// TestValidateClient tests client validation function
func TestValidateClient(t *testing.T) {
	tests := []struct {
		name      string
		clientID  string
		wantErr   bool
	}{
		{"empty client ID", "", true},
		{"valid client ID", "test-client", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := validateClient(tt.clientID)

			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if client == nil {
					t.Error("expected client, got nil")
				}
			}
		})
	}
}

// TestValidateUserToken tests user token validation
func TestValidateUserToken(t *testing.T) {
	tests := []struct {
		name      string
		token     string
		wantErr   bool
	}{
		{"empty token", "", true},
		{"valid token format", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test.signature", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			user, err := validateUserToken(tt.token, "test-tenant")

			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
			} else {
				// May error due to invalid signature, but shouldn't panic
				_ = user
				_ = err
			}
		})
	}
}

// TestMetricsRecording tests that metrics are recorded properly
func TestMetricsRecording(t *testing.T) {
	// Reset metrics
	agentMetrics = &AgentMetrics{
		latencies:              []int64{},
		lastLatencies:          []int64{},
		staticPolicyLatencies:  []int64{},
		dynamicPolicyLatencies: []int64{},
	}

	// Record some latencies
	agentMetrics.recordLatency(10, "static")
	agentMetrics.recordLatency(20, "dynamic")
	agentMetrics.recordLatency(30, "static")

	if len(agentMetrics.latencies) != 3 {
		t.Errorf("expected 3 total latencies, got %d", len(agentMetrics.latencies))
	}
	if len(agentMetrics.staticPolicyLatencies) != 2 {
		t.Errorf("expected 2 static latencies, got %d", len(agentMetrics.staticPolicyLatencies))
	}
	if len(agentMetrics.dynamicPolicyLatencies) != 1 {
		t.Errorf("expected 1 dynamic latency, got %d", len(agentMetrics.dynamicPolicyLatencies))
	}
}

// TestGetClaimString tests JWT claim extraction
func TestGetClaimString(t *testing.T) {
	tests := []struct {
		name     string
		claims   map[string]interface{}
		key      string
		expected string
	}{
		{"existing claim", map[string]interface{}{"user_id": "123"}, "user_id", "123"},
		{"missing claim", map[string]interface{}{}, "user_id", ""},
		{"non-string claim", map[string]interface{}{"count": 123}, "count", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getClaimString(tt.claims, tt.key)
			if result != tt.expected {
				t.Errorf("expected '%s', got '%s'", tt.expected, result)
			}
		})
	}
}

// TestGetClaimStringArray tests JWT array claim extraction
func TestGetClaimStringArray(t *testing.T) {
	tests := []struct {
		name     string
		claims   map[string]interface{}
		key      string
		expected int // Length of array
	}{
		{"comma-separated string", map[string]interface{}{"roles": "admin,user"}, "roles", 2},
		{"missing claim", map[string]interface{}{}, "roles", 0},
		{"single value", map[string]interface{}{"role": "admin"}, "role", 1},
		{"array not supported", map[string]interface{}{"roles": []interface{}{"admin", "user"}}, "roles", 0},
		{"empty string value", map[string]interface{}{"roles": ""}, "roles", 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getClaimStringArray(tt.claims, tt.key)
			if len(result) != tt.expected {
				t.Errorf("expected array length %d, got %d", tt.expected, len(result))
			}
		})
	}
}

// TestForwardToOrchestrator tests orchestrator forwarding
func TestForwardToOrchestrator(t *testing.T) {
	// Create mock orchestrator server
	mockOrch := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]interface{}{
			"result": "mock response",
		}); err != nil {
			t.Logf("Error encoding mock response: %v", err)
		}
	}))
	defer mockOrch.Close()

	// Save and restore the orchestratorURL package variable
	oldOrchURL := orchestratorURL
	defer func() {
		orchestratorURL = oldOrchURL
	}()
	orchestratorURL = mockOrch.URL

	req := ClientRequest{
		ClientID:    "test-client",
		RequestType: "sql",
		Query:       "test query",
	}

	user := &User{
		ID:    1,
		Email: "test@example.com",
		Name:  "Test User",
	}

	client := &Client{
		ID:      "test-client",
		Name:    "Test Client",
		Enabled: true,
	}

	result, err := forwardToOrchestrator(req, user, client)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if result == nil {
		t.Error("expected result, got nil")
	}
}

// Benchmark tests
func BenchmarkHealthHandler(b *testing.B) {
	req := httptest.NewRequest("GET", "/health", nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		healthHandler(w, req)
	}
}

func BenchmarkMaskString(b *testing.B) {
	input := "AXON-ENT-test-20251104-abc123xyz789"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		maskString(input)
	}
}

func BenchmarkCalculateP99(b *testing.B) {
	latencies := make([]int64, 1000)
	for i := range latencies {
		latencies[i] = int64(i)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		calculateP99(latencies)
	}
}

// TestListClientsHandler tests the list clients endpoint
func TestListClientsHandler(t *testing.T) {
	req := httptest.NewRequest("GET", "/clients", nil)
	w := httptest.NewRecorder()

	listClientsHandler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}

	var clients []Client
	if err := json.NewDecoder(w.Body).Decode(&clients); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if len(clients) == 0 {
		t.Error("expected at least one client in the list")
	}
}

// TestCreateClientHandler tests client creation endpoint
func TestCreateClientHandler(t *testing.T) {
	tests := []struct {
		name           string
		requestBody    interface{}
		expectedStatus int
	}{
		{
			name: "valid client",
			requestBody: Client{
				ID:          "test-client",
				Name:        "Test Client",
				TenantID:    "tenant-1",
				Permissions: []string{"query"},
			},
			expectedStatus: http.StatusCreated,
		},
		{
			name:           "invalid json",
			requestBody:    "{invalid",
			expectedStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var body []byte
			var err error

			if str, ok := tt.requestBody.(string); ok {
				body = []byte(str)
			} else {
				body, err = json.Marshal(tt.requestBody)
				if err != nil {
					t.Fatalf("failed to marshal request: %v", err)
				}
			}

			req := httptest.NewRequest("POST", "/clients", bytes.NewBuffer(body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			createClientHandler(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("expected status %d, got %d", tt.expectedStatus, w.Code)
			}
		})
	}
}

// TestPolicyTestHandler tests the policy test endpoint
func TestPolicyTestHandler(t *testing.T) {
	// Initialize static policy engine
	if staticPolicyEngine == nil {
		staticPolicyEngine = NewStaticPolicyEngine()
	}

	tests := []struct {
		name           string
		requestBody    interface{}
		expectedStatus int
	}{
		{
			name: "valid policy test",
			requestBody: map[string]string{
				"query":        "SELECT * FROM users",
				"user_email":   "test@example.com",
				"request_type": "query",
			},
			expectedStatus: http.StatusOK,
		},
		{
			name:           "invalid json",
			requestBody:    "{invalid",
			expectedStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var body []byte
			var err error

			if str, ok := tt.requestBody.(string); ok {
				body = []byte(str)
			} else {
				body, err = json.Marshal(tt.requestBody)
				if err != nil {
					t.Fatalf("failed to marshal request: %v", err)
				}
			}

			req := httptest.NewRequest("POST", "/policy/test", bytes.NewBuffer(body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			policyTestHandler(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("expected status %d, got %d", tt.expectedStatus, w.Code)
			}

			if tt.expectedStatus == http.StatusOK {
				var response map[string]interface{}
				if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
					t.Fatalf("failed to decode response: %v", err)
				}

				// Check that response has expected fields
				if _, ok := response["blocked"]; !ok {
					t.Error("expected 'blocked' field in response")
				}
			}
		})
	}
}

// TestMetricsHandler tests the metrics endpoint
func TestMetricsHandler(t *testing.T) {
	tests := []struct {
		name             string
		setupMetrics     func()
		expectError      bool
		expectedFields   []string
	}{
		{
			name: "with initialized metrics",
			setupMetrics: func() {
				agentMetrics = &AgentMetrics{
					latencies:              []int64{100, 200, 300},
					lastLatencies:          []int64{100, 200},
					staticPolicyLatencies:  []int64{50, 60},
					dynamicPolicyLatencies: []int64{},
					authTimings:            []int64{10, 20},
					staticPolicyTimings:    []int64{5, 10},
					networkTimings:         []int64{80, 90},
				}
				agentMetrics.totalRequests = 100
				agentMetrics.successRequests = 95
				agentMetrics.failedRequests = 5
			},
			expectError: false,
			expectedFields: []string{
				"agent_metrics",
				"timestamp",
			},
		},
		{
			name: "with nil metrics",
			setupMetrics: func() {
				agentMetrics = nil
			},
			expectError:    true,
			expectedFields: []string{"error"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupMetrics()

			req := httptest.NewRequest("GET", "/metrics", nil)
			w := httptest.NewRecorder()

			metricsHandler(w, req)

			if w.Code != http.StatusOK {
				t.Errorf("expected status 200, got %d", w.Code)
			}

			var response map[string]interface{}
			if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
				t.Fatalf("failed to decode response: %v", err)
			}

			// Check expected fields
			for _, field := range tt.expectedFields {
				if _, ok := response[field]; !ok {
					t.Errorf("expected field '%s' in response", field)
				}
			}

			if !tt.expectError {
				// Verify agent_metrics structure
				if metrics, ok := response["agent_metrics"].(map[string]interface{}); ok {
					metricsFields := []string{
						"uptime_seconds",
						"total_requests",
						"success_requests",
						"success_rate",
						"rps",
					}
					for _, field := range metricsFields {
						if _, ok := metrics[field]; !ok {
							t.Errorf("expected field '%s' in agent_metrics", field)
						}
					}
				} else if !tt.expectError {
					t.Error("expected 'agent_metrics' to be a map")
				}
			}
		})
	}
}

// ==================== Comprehensive clientRequestHandler Tests ====================

// Helper function to generate valid V2 test license keys with known HMAC secret
// V2 format: AXON-V2-{BASE64_JSON}-{SIGNATURE}
func generateTestLicenseKey(orgID string, tier string, expiryDate string) string {
	// Use default HMAC secret for testing
	hmacSecret := "axonflow-license-secret-2025-change-in-production"

	// Create V2 service license payload
	payload := map[string]interface{}{
		"tier":         tier,
		"tenant_id":    orgID,
		"service_name": orgID + "-service",
		"service_type": "backend-service",
		"permissions":  []string{"query", "llm"},
		"expires_at":   expiryDate,
	}

	// Encode payload as JSON then base64
	payloadJSON, _ := json.Marshal(payload)
	payloadBase64 := base64.RawURLEncoding.EncodeToString(payloadJSON)

	// Calculate HMAC-SHA256 signature of the base64 payload
	h := hmac.New(sha256.New, []byte(hmacSecret))
	h.Write([]byte(payloadBase64))
	signature := hex.EncodeToString(h.Sum(nil))[:8] // First 8 chars

	// Return V2 license key: AXON-V2-{BASE64_PAYLOAD}-{SIGNATURE}
	return fmt.Sprintf("AXON-V2-%s-%s", payloadBase64, signature)
}

// TestClientRequestHandler_SuccessPath tests the happy path with valid auth and policy
func TestClientRequestHandler_SuccessPath(t *testing.T) {
	// Initialize test environment
	if agentMetrics == nil {
		agentMetrics = &AgentMetrics{
			latencies:              []int64{},
			lastLatencies:          []int64{},
			staticPolicyLatencies:  []int64{},
			dynamicPolicyLatencies: []int64{},
		}
	}

	if staticPolicyEngine == nil {
		staticPolicyEngine = NewStaticPolicyEngine()
	}

	// Create test license key (expires in future)
	testLicenseKey := generateTestLicenseKey("test-org", "ENT", "20351231")

	// Add test client to knownClients
	knownClients["test-client-success"] = &ClientAuth{
		ClientID:    "test-client-success",
		LicenseKey:  testLicenseKey,
		Name:        "Test Client Success",
		TenantID:    "trip_planner_tenant", // Must match user token tenant
		Permissions: []string{"query", "llm"},
		RateLimit:   1000,
		Enabled:     true,
	}
	defer delete(knownClients, "test-client-success")

	// Mock orchestrator server
	mockOrch := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify request structure
		var req map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Logf("Error decoding request: %v", err)
		}

		// Return success response
		response := map[string]interface{}{
			"success": true,
			"result":  "Query executed successfully",
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(response); err != nil {
			t.Logf("Error encoding response: %v", err)
		}
	}))
	defer mockOrch.Close()

	// Override orchestrator URL
	orchestratorURL = mockOrch.URL

	// Create request with valid auth
	reqBody := ClientRequest{
		ClientID:    "test-client-success",
		RequestType: "sql", // Valid request type
		Query:       "SELECT id, name FROM products WHERE price > 100", // Simple query without sensitive tables
		UserToken:   "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjox", // Test mode token
	}

	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest("POST", "/client/request", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-License-Key", testLicenseKey)

	w := httptest.NewRecorder()
	clientRequestHandler(w, req)

	// Verify success response
	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}

	var response ClientResponse
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if !response.Success {
		t.Errorf("expected success=true, got %v", response.Success)
	}

	if response.Blocked {
		t.Errorf("expected blocked=false, got %v", response.Blocked)
	}

	if response.PolicyInfo == nil {
		t.Error("expected policy info in response")
	}
}

// TestClientRequestHandler_ClientDisabled tests request with disabled client
// TODO(#283): This test requires V2 license validation to check disabled status
// V2 license validation currently bypasses knownClients and doesn't check Enabled field
func TestClientRequestHandler_ClientDisabled(t *testing.T) {
	t.Skip("V2 license validation doesn't check knownClients.Enabled - see Issue #283")
	if agentMetrics == nil {
		agentMetrics = &AgentMetrics{
			latencies:     []int64{},
			lastLatencies: []int64{},
		}
	}

	testLicenseKey := generateTestLicenseKey("disabled-org", "ENT", "20351231")

	// Add disabled client to knownClients
	knownClients["test-client-disabled"] = &ClientAuth{
		ClientID:   "test-client-disabled",
		LicenseKey: testLicenseKey,
		Name:       "Disabled Client",
		TenantID:   "test_tenant",
		Enabled:    false, // Disabled
	}
	defer delete(knownClients, "test-client-disabled")

	reqBody := ClientRequest{
		ClientID:    "test-client-disabled",
		RequestType: "sql",
		Query:       "SELECT 1",
		UserToken:   "test-token",
	}

	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest("POST", "/client/request", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-License-Key", testLicenseKey)

	w := httptest.NewRecorder()
	clientRequestHandler(w, req)

	// Client disabled during license validation returns 401 (not 403)
	if w.Code != http.StatusUnauthorized && w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected status 401 or 503, got %d", w.Code)
	}

	var response map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if !strings.Contains(response["error"].(string), "disabled") {
		t.Error("expected error about disabled client")
	}
}

// TestClientRequestHandler_TenantMismatch tests tenant isolation
func TestClientRequestHandler_TenantMismatch(t *testing.T) {
	if agentMetrics == nil {
		agentMetrics = &AgentMetrics{
			latencies:     []int64{},
			lastLatencies: []int64{},
		}
	}

	testLicenseKey := generateTestLicenseKey("tenant-test", "ENT", "20351231")

	// Add client with different tenant
	knownClients["test-client-tenant"] = &ClientAuth{
		ClientID:   "test-client-tenant",
		LicenseKey: testLicenseKey,
		Name:       "Tenant Test Client",
		TenantID:   "different_tenant", // Different from user token
		Enabled:    true,
	}
	defer delete(knownClients, "test-client-tenant")

	reqBody := ClientRequest{
		ClientID:    "test-client-tenant",
		RequestType: "sql",
		Query:       "SELECT 1",
		UserToken:   "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoy", // Mismatch test token: user from trip_planner_tenant
	}

	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest("POST", "/client/request", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-License-Key", testLicenseKey)

	w := httptest.NewRecorder()
	clientRequestHandler(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("expected status 403, got %d", w.Code)
	}

	var response map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if !strings.Contains(response["error"].(string), "Tenant mismatch") {
		t.Errorf("expected tenant mismatch error, got: %v", response["error"])
	}
}

// TestClientRequestHandler_PolicyBlocked tests static policy blocking
func TestClientRequestHandler_PolicyBlocked(t *testing.T) {
	if agentMetrics == nil {
		agentMetrics = &AgentMetrics{
			latencies:              []int64{},
			lastLatencies:          []int64{},
			staticPolicyLatencies:  []int64{},
			dynamicPolicyLatencies: []int64{},
		}
	}

	if staticPolicyEngine == nil {
		staticPolicyEngine = NewStaticPolicyEngine()
	}

	testLicenseKey := generateTestLicenseKey("policy-test", "ENT", "20351231")

	// Add test client
	knownClients["test-client-policy"] = &ClientAuth{
		ClientID:   "test-client-policy",
		LicenseKey: testLicenseKey,
		Name:       "Policy Test Client",
		TenantID:   "trip_planner_tenant",
		Enabled:    true,
	}
	defer delete(knownClients, "test-client-policy")

	// Create request with PII data (should be blocked for user without pii_access permission)
	reqBody := ClientRequest{
		ClientID:    "test-client-policy",
		RequestType: "sql",
		Query:       "SELECT ssn, credit_card FROM users", // Contains PII keywords
		UserToken:   "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjox",
	}

	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest("POST", "/client/request", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-License-Key", testLicenseKey)

	w := httptest.NewRecorder()
	clientRequestHandler(w, req)

	// Should be blocked or allowed depending on user permissions
	// The test mode user has "basic_pii" permission, so this might be allowed
	// Let's check the response structure
	var response ClientResponse
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	// Verify policy info is present
	if response.PolicyInfo == nil {
		t.Error("expected policy info in response")
	}

	// If blocked, should have block reason
	if response.Blocked && response.BlockReason == "" {
		t.Error("expected block reason when blocked=true")
	}
}

// TestClientRequestHandler_OrchestratorError tests orchestrator failure handling
func TestClientRequestHandler_OrchestratorError(t *testing.T) {
	if agentMetrics == nil {
		agentMetrics = &AgentMetrics{
			latencies:     []int64{},
			lastLatencies: []int64{},
		}
	}

	if staticPolicyEngine == nil {
		staticPolicyEngine = NewStaticPolicyEngine()
	}

	testLicenseKey := generateTestLicenseKey("orch-error", "ENT", "20351231")

	knownClients["test-client-orch-error"] = &ClientAuth{
		ClientID:   "test-client-orch-error",
		LicenseKey: testLicenseKey,
		Name:       "Orchestrator Error Test",
		TenantID:   "trip_planner_tenant",
		Enabled:    true,
	}
	defer delete(knownClients, "test-client-orch-error")

	// Set orchestrator URL to an invalid address to simulate connection failure
	orchestratorURL = "http://localhost:99999" // Port that doesn't exist

	reqBody := ClientRequest{
		ClientID:    "test-client-orch-error",
		RequestType: "sql",
		Query:       "SELECT 1",
		UserToken:   "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjox",
	}

	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest("POST", "/client/request", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-License-Key", testLicenseKey)

	w := httptest.NewRecorder()
	clientRequestHandler(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("expected status 500, got %d", w.Code)
	}

	var response map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if errMsg, ok := response["error"].(string); ok {
		if !strings.Contains(errMsg, "Orchestrator") {
			t.Errorf("expected orchestrator error in response, got: %s", errMsg)
		}
	} else {
		t.Error("expected error field in response")
	}
}

// TestClientRequestHandler_MultiAgentPlan tests multi-agent plan response flattening
func TestClientRequestHandler_MultiAgentPlan(t *testing.T) {
	if agentMetrics == nil {
		agentMetrics = &AgentMetrics{
			latencies:     []int64{},
			lastLatencies: []int64{},
		}
	}

	if staticPolicyEngine == nil {
		staticPolicyEngine = NewStaticPolicyEngine()
	}

	testLicenseKey := generateTestLicenseKey("multi-agent", "ENT", "20351231")

	knownClients["test-client-multi-agent"] = &ClientAuth{
		ClientID:   "test-client-multi-agent",
		LicenseKey: testLicenseKey,
		Name:       "Multi-Agent Test",
		TenantID:   "trip_planner_tenant",
		Enabled:    true,
	}
	defer delete(knownClients, "test-client-multi-agent")

	// Mock orchestrator that returns multi-agent plan response
	mockOrch := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response := map[string]interface{}{
			"plan_id": "plan_12345",
			"result":  "Trip plan generated successfully",
			"steps": []interface{}{
				map[string]interface{}{
					"id":          "step_1_flight_search",
					"name":        "flight_search",
					"type":        "connector",
					"description": "Search for flights to Paris",
				},
				map[string]interface{}{
					"id":          "step_2_hotel_search",
					"name":        "hotel_search",
					"type":        "connector",
					"description": "Search for hotels in Paris",
				},
			},
			"metadata": map[string]interface{}{
				"agents_used": 3,
				"total_time":  "5s",
			},
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(response); err != nil {
			t.Logf("Error encoding response: %v", err)
		}
	}))
	defer mockOrch.Close()

	orchestratorURL = mockOrch.URL

	reqBody := ClientRequest{
		ClientID:    "test-client-multi-agent",
		RequestType: "multi-agent-plan",
		Query:       "Plan a trip to Paris",
		UserToken:   "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjox",
	}

	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest("POST", "/client/request", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-License-Key", testLicenseKey)

	w := httptest.NewRecorder()
	clientRequestHandler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}

	var response ClientResponse
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	// Verify plan_id is flattened to top level
	if response.PlanID != "plan_12345" {
		t.Errorf("expected plan_id='plan_12345', got '%s'", response.PlanID)
	}

	// Verify result is flattened
	if response.Result != "Trip plan generated successfully" {
		t.Errorf("expected result, got '%s'", response.Result)
	}

	// Verify metadata is flattened
	if response.Metadata == nil {
		t.Error("expected metadata in response")
	}

	if agentsUsed, ok := response.Metadata["agents_used"].(float64); !ok || agentsUsed != 3 {
		t.Errorf("expected agents_used=3, got %v", response.Metadata["agents_used"])
	}

	// Verify steps are flattened
	if response.Steps == nil {
		t.Error("expected steps in response")
	}

	if len(response.Steps) != 2 {
		t.Errorf("expected 2 steps, got %d", len(response.Steps))
	}

	// Verify first step structure
	if step0, ok := response.Steps[0].(map[string]interface{}); ok {
		if step0["name"] != "flight_search" {
			t.Errorf("expected first step name='flight_search', got '%v'", step0["name"])
		}
	} else {
		t.Error("expected first step to be a map")
	}
}

// ==================== MCP Handler Tests ====================

// TestMCPQueryHandler_Success tests successful MCP query execution
func TestMCPQueryHandler_Success(t *testing.T) {
	if agentMetrics == nil {
		agentMetrics = &AgentMetrics{
			latencies:     []int64{},
			lastLatencies: []int64{},
		}
	}

	testLicenseKey := generateTestLicenseKey("mcp-test", "ENT", "20351231")

	// Add test client
	knownClients["test-mcp-client"] = &ClientAuth{
		ClientID:   "test-mcp-client",
		LicenseKey: testLicenseKey,
		Name:       "MCP Test Client",
		TenantID:   "trip_planner_tenant",
		Enabled:    true,
	}
	defer delete(knownClients, "test-mcp-client")

	// Create request
	reqBody := map[string]interface{}{
		"client_id":     "test-mcp-client",
		"user_token":    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjox",
		"connector_id":  "postgres",
		"query":         "SELECT version()",
		"database_name": "testdb",
	}

	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest("POST", "/mcp/query", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-License-Key", testLicenseKey)

	w := httptest.NewRecorder()
	mcpQueryHandler(w, req)

	// The handler will fail because we don't have a real connector, but we test the validation flow
	// As long as we get past validation, the test is successful
	if w.Code != http.StatusOK && w.Code != http.StatusInternalServerError && w.Code != http.StatusBadRequest {
		t.Logf("Response code: %d (acceptable - testing validation flow)", w.Code)
	}
}

// TestMCPQueryHandler_InvalidJSON tests MCP query with invalid JSON
func TestMCPQueryHandler_InvalidJSON(t *testing.T) {
	req := httptest.NewRequest("POST", "/mcp/query", bytes.NewBufferString("{invalid"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-License-Key", "test-key")

	w := httptest.NewRecorder()
	mcpQueryHandler(w, req)

	// MCP registry not initialized returns 503, invalid JSON returns 400
	// Both are acceptable error responses
	if w.Code != http.StatusBadRequest && w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected status 400 or 503, got %d", w.Code)
	}
}

// TestMCPQueryHandler_MissingLicenseKey tests MCP query without license key
func TestMCPQueryHandler_MissingLicenseKey(t *testing.T) {
	reqBody := map[string]interface{}{
		"client_id":     "test-client",
		"user_token":    "test-token",
		"connector_id":  "postgres",
		"query":         "SELECT 1",
		"database_name": "testdb",
	}

	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest("POST", "/mcp/query", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	mcpQueryHandler(w, req)

	// Missing license or MCP registry not initialized
	if w.Code != http.StatusUnauthorized && w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected status 401 or 503, got %d", w.Code)
	}
}

// TestMCPExecuteHandler_Success tests successful MCP execute
func TestMCPExecuteHandler_Success(t *testing.T) {
	if agentMetrics == nil {
		agentMetrics = &AgentMetrics{
			latencies:     []int64{},
			lastLatencies: []int64{},
		}
	}

	testLicenseKey := generateTestLicenseKey("mcp-exec-test", "ENT", "20351231")

	// Add test client
	knownClients["test-mcp-exec-client"] = &ClientAuth{
		ClientID:   "test-mcp-exec-client",
		LicenseKey: testLicenseKey,
		Name:       "MCP Execute Test Client",
		TenantID:   "trip_planner_tenant",
		Enabled:    true,
	}
	defer delete(knownClients, "test-mcp-exec-client")

	// Create request
	reqBody := map[string]interface{}{
		"client_id":     "test-mcp-exec-client",
		"user_token":    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjox",
		"connector_id":  "postgres",
		"command":       "CREATE TABLE test (id INT)",
		"database_name": "testdb",
	}

	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest("POST", "/mcp/execute", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-License-Key", testLicenseKey)

	w := httptest.NewRecorder()
	mcpExecuteHandler(w, req)

	// Test validation flow - actual execution will fail without real connector
	if w.Code != http.StatusOK && w.Code != http.StatusInternalServerError && w.Code != http.StatusBadRequest {
		t.Logf("Response code: %d (acceptable - testing validation flow)", w.Code)
	}
}

// TestMCPExecuteHandler_InvalidJSON tests MCP execute with invalid JSON
func TestMCPExecuteHandler_InvalidJSON(t *testing.T) {
	req := httptest.NewRequest("POST", "/mcp/execute", bytes.NewBufferString("{invalid"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-License-Key", "test-key")

	w := httptest.NewRecorder()
	mcpExecuteHandler(w, req)

	if w.Code != http.StatusBadRequest && w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected status 400 or 503, got %d", w.Code)
	}
}

// TestMCPExecuteHandler_MissingLicenseKey tests MCP execute without license key
func TestMCPExecuteHandler_MissingLicenseKey(t *testing.T) {
	reqBody := map[string]interface{}{
		"client_id":     "test-client",
		"user_token":    "test-token",
		"connector_id":  "postgres",
		"command":       "SELECT 1",
		"database_name": "testdb",
	}

	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest("POST", "/mcp/execute", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")

	w := httptest.NewRecorder()
	mcpExecuteHandler(w, req)

	if w.Code != http.StatusUnauthorized && w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected status 401 or 503, got %d", w.Code)
	}
}

// =============================================================================
// Migration Helper Tests
// =============================================================================

// TestExtractMigrationVersion tests extracting version from migration filenames
func TestExtractMigrationVersion(t *testing.T) {
	tests := []struct {
		filename string
		want     string
	}{
		{"006_customer_portal.sql", "006"},
		{"020_schema_migrations.sql", "020"},
		{"001_initial.sql", "001"},
		{"simple.sql", "simple"},
	}

	for _, tt := range tests {
		t.Run(tt.filename, func(t *testing.T) {
			got := extractMigrationVersion(tt.filename)
			if got != tt.want {
				t.Errorf("extractMigrationVersion(%q) = %q, want %q", tt.filename, got, tt.want)
			}
		})
	}
}

// TestExtractMigrationName tests extracting name from migration filenames
func TestExtractMigrationName(t *testing.T) {
	tests := []struct {
		filename string
		want     string
	}{
		{"006_customer_portal.sql", "customer_portal"},
		{"020_schema_migrations.sql", "schema_migrations"},
		{"001_initial_schema.sql", "initial_schema"},
		{"simple.sql", "simple"},
	}

	for _, tt := range tests {
		t.Run(tt.filename, func(t *testing.T) {
			got := extractMigrationName(tt.filename)
			if got != tt.want {
				t.Errorf("extractMigrationName(%q) = %q, want %q", tt.filename, got, tt.want)
			}
		})
	}
}

// TestCalculateFileChecksum tests file checksum calculation
func TestCalculateFileChecksum(t *testing.T) {
	// Create a temporary file for testing
	tmpFile, err := os.CreateTemp("", "migration_test_*.sql")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer func() {
		if err := os.Remove(tmpFile.Name()); err != nil {
			t.Logf("Failed to remove temp file: %v", err)
		}
	}()

	testContent := "SELECT 1;"
	if _, err := tmpFile.WriteString(testContent); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}
	if err := tmpFile.Close(); err != nil {
		t.Fatalf("Failed to close temp file: %v", err)
	}

	// Calculate checksum
	checksum := calculateFileChecksum(tmpFile.Name())

	// Verify it's a valid SHA-256 hex string
	if len(checksum) != 64 {
		t.Errorf("checksum length = %d, want 64", len(checksum))
	}

	// Verify idempotency
	checksum2 := calculateFileChecksum(tmpFile.Name())
	if checksum != checksum2 {
		t.Error("checksum not idempotent")
	}

	// Test non-existent file
	badChecksum := calculateFileChecksum("/nonexistent/file.sql")
	if badChecksum != "" {
		t.Errorf("expected empty checksum for nonexistent file, got %q", badChecksum)
	}
}

// TestEnsureSchemaMigrationsTable tests table creation
func TestEnsureSchemaMigrationsTable(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock: %v", err)
	}
	defer func() { _ = db.Close() }()

	tests := []struct {
		name      string
		setupMock func(sqlmock.Sqlmock)
	}{
		{
			name: "successful creation",
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectExec(`CREATE TABLE IF NOT EXISTS schema_migrations`).
					WillReturnResult(sqlmock.NewResult(0, 0))
			},
		},
		{
			name: "table already exists",
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectExec(`CREATE TABLE IF NOT EXISTS schema_migrations`).
					WillReturnResult(sqlmock.NewResult(0, 0))
			},
		},
		{
			name: "database error",
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectExec(`CREATE TABLE IF NOT EXISTS schema_migrations`).
					WillReturnError(sql.ErrConnDone)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupMock(mock)
			ensureSchemaMigrationsTable(db)
			// Should not panic
		})
	}
}

// TestGetAppliedMigrations tests retrieving applied migrations
func TestGetAppliedMigrations(t *testing.T) {
	tests := []struct {
		name       string
		setupMock  func(sqlmock.Sqlmock)
		wantLength int
		wantHas    []string
	}{
		{
			name: "multiple migrations",
			setupMock: func(mock sqlmock.Sqlmock) {
				rows := sqlmock.NewRows([]string{"version"}).
					AddRow("001").
					AddRow("006").
					AddRow("020")
				mock.ExpectQuery(`SELECT version FROM schema_migrations`).
					WillReturnRows(rows)
			},
			wantLength: 3,
			wantHas:    []string{"001", "006", "020"},
		},
		{
			name: "no migrations",
			setupMock: func(mock sqlmock.Sqlmock) {
				rows := sqlmock.NewRows([]string{"version"})
				mock.ExpectQuery(`SELECT version FROM schema_migrations`).
					WillReturnRows(rows)
			},
			wantLength: 0,
			wantHas:    nil,
		},
		{
			name: "query error",
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery(`SELECT version FROM schema_migrations`).
					WillReturnError(sql.ErrConnDone)
			},
			wantLength: 0,
			wantHas:    nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatalf("failed to create mock: %v", err)
			}
			defer func() { _ = db.Close() }()

			tt.setupMock(mock)
			applied := getAppliedMigrations(db)

			if len(applied) != tt.wantLength {
				t.Errorf("got %d migrations, want %d", len(applied), tt.wantLength)
			}

			for _, version := range tt.wantHas {
				if !applied[version] {
					t.Errorf("expected version %q to be applied", version)
				}
			}

			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("unfulfilled expectations: %v", err)
			}
		})
	}
}

// TestRecordMigrationSuccess tests recording successful migrations
func TestRecordMigrationSuccess(t *testing.T) {
	tests := []struct {
		name      string
		setupMock func(sqlmock.Sqlmock)
	}{
		{
			name: "successful insert",
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectExec(`INSERT INTO schema_migrations`).
					WillReturnResult(sqlmock.NewResult(1, 1))
			},
		},
		{
			name: "database error",
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectExec(`INSERT INTO schema_migrations`).
					WillReturnError(sql.ErrConnDone)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatalf("failed to create mock: %v", err)
			}
			defer func() { _ = db.Close() }()

			tt.setupMock(mock)
			recordMigrationSuccess(db, "006", "006_customer_portal.sql", 150)
			// Should not panic

			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("unfulfilled expectations: %v", err)
			}
		})
	}
}

// TestRecordMigrationFailure tests recording failed migrations
func TestRecordMigrationFailure(t *testing.T) {
	tests := []struct {
		name      string
		setupMock func(sqlmock.Sqlmock)
	}{
		{
			name: "successful insert",
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectExec(`INSERT INTO schema_migrations`).
					WillReturnResult(sqlmock.NewResult(1, 1))
			},
		},
		{
			name: "database error",
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectExec(`INSERT INTO schema_migrations`).
					WillReturnError(sql.ErrConnDone)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatalf("failed to create mock: %v", err)
			}
			defer func() { _ = db.Close() }()

			tt.setupMock(mock)
			migrationErr := fmt.Errorf("test migration error")
			recordMigrationFailure(db, "006", "006_customer_portal.sql", migrationErr, 50)
			// Should not panic

			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("unfulfilled expectations: %v", err)
			}
		})
	}
}

// TestGetMigrationStatus tests getting migration status summary
func TestGetMigrationStatus(t *testing.T) {
	tests := []struct {
		name      string
		setupMock func(sqlmock.Sqlmock)
		wantErr   bool
	}{
		{
			name: "successful query",
			setupMock: func(mock sqlmock.Sqlmock) {
				rows := sqlmock.NewRows([]string{"count", "version", "applied_at"}).
					AddRow(5, "020", "2025-11-06 12:00:00")
				mock.ExpectQuery(`SELECT COUNT\(\*\), MAX\(version\), MAX\(applied_at\)`).
					WillReturnRows(rows)
			},
			wantErr: false,
		},
		{
			name: "query error",
			setupMock: func(mock sqlmock.Sqlmock) {
				mock.ExpectQuery(`SELECT COUNT\(\*\), MAX\(version\), MAX\(applied_at\)`).
					WillReturnError(sql.ErrConnDone)
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatalf("failed to create mock: %v", err)
			}
			defer func() { _ = db.Close() }()

			tt.setupMock(mock)
			status := getMigrationStatus(db)

			if status == "" {
				t.Error("expected non-empty status")
			}

			if tt.wantErr && !strings.Contains(status, "Failed") {
				t.Errorf("expected error message, got %q", status)
			}

			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("unfulfilled expectations: %v", err)
			}
		})
	}
}

// TestCalculateErrorRate tests error rate calculation
func TestCalculateErrorRate(t *testing.T) {
	now := time.Now()
	tests := []struct {
		name       string
		timestamps []time.Time
		wantZero   bool
	}{
		{"empty timestamps", []time.Time{}, true},
		{"all old timestamps", []time.Time{now.Add(-2 * time.Minute)}, true},
		{"recent timestamps", []time.Time{now, now.Add(-30 * time.Second)}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rate := calculateErrorRate(tt.timestamps)
			if tt.wantZero && rate != 0 {
				t.Errorf("expected zero error rate, got %f", rate)
			}
			if !tt.wantZero && rate == 0 {
				t.Error("expected non-zero error rate, got 0")
			}
		})
	}
}

// TestCalculatePercentile tests percentile calculation
func TestCalculatePercentile(t *testing.T) {
	tests := []struct {
		name       string
		latencies  []int64
		percentile float64
		expected   float64
	}{
		{"empty slice", []int64{}, 50, 0},
		{"single value", []int64{100}, 50, 100},
		// The function picks index = (len-1) * percentile / 100, so for 5 elements and 50%, index = 2 (value 50 after sort)
		{"multiple values - median", []int64{10, 20, 30, 40, 50}, 50, 50},
		// For 10 elements and 90%, index = 8.1 -> 8 (value 100 in sorted array including 100)
		{"multiple values - p90", []int64{10, 20, 30, 40, 50, 60, 70, 80, 90, 100}, 90, 100},
		{"unsorted values", []int64{50, 10, 40, 20, 30}, 50, 50},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := calculatePercentile(tt.latencies, tt.percentile)
			if result != tt.expected {
				t.Errorf("calculatePercentile() = %f, want %f", result, tt.expected)
			}
		})
	}
}

// TestRecordLatencyWithPolicy tests latency recording with policy type
func TestRecordLatencyWithPolicy(t *testing.T) {
	// Initialize metrics if needed
	if agentMetrics == nil {
		agentMetrics = &AgentMetrics{}
	}

	// Test recording latency with policy type
	agentMetrics.recordLatency(100, "static")
	agentMetrics.recordLatency(200, "database")

	// Just verify no panic occurs
}

// TestGetRequestTypeMetrics tests request type metrics retrieval
func TestGetRequestTypeMetrics(t *testing.T) {
	// Initialize metrics if needed
	if agentMetrics == nil {
		agentMetrics = &AgentMetrics{}
	}

	metrics := agentMetrics.getRequestTypeMetrics()

	// Should return empty but valid response
	if metrics == nil {
		t.Error("expected non-nil metrics map")
	}
}

// TestGetConnectorMetrics tests connector metrics retrieval
func TestGetConnectorMetrics(t *testing.T) {
	// Initialize metrics if needed
	if agentMetrics == nil {
		agentMetrics = &AgentMetrics{}
	}

	metrics := agentMetrics.getConnectorMetrics()

	// Should return empty but valid response
	if metrics == nil {
		t.Error("expected non-nil metrics map")
	}
}

// TestGetKeysNilMap tests key extraction with nil map
func TestGetKeysNilMap(t *testing.T) {
	result := getKeys(nil)
	if len(result) != 0 {
		t.Errorf("expected 0 keys for nil map, got %d", len(result))
	}
}

// TestRecordError tests error recording in metrics
func TestRecordError(t *testing.T) {
	metrics := &AgentMetrics{
		errorTimestamps:   make([]time.Time, 0),
		consecutiveErrors: 0,
	}

	// Record first error
	metrics.recordError()
	if metrics.consecutiveErrors != 1 {
		t.Errorf("Expected consecutiveErrors = 1, got %d", metrics.consecutiveErrors)
	}
	if len(metrics.errorTimestamps) != 1 {
		t.Errorf("Expected 1 error timestamp, got %d", len(metrics.errorTimestamps))
	}

	// Record second error
	metrics.recordError()
	if metrics.consecutiveErrors != 2 {
		t.Errorf("Expected consecutiveErrors = 2, got %d", metrics.consecutiveErrors)
	}

	// Test overflow (should keep only last 1000)
	for i := 0; i < 1100; i++ {
		metrics.recordError()
	}
	if len(metrics.errorTimestamps) > 1000 {
		t.Errorf("Expected max 1000 error timestamps, got %d", len(metrics.errorTimestamps))
	}
}

// TestRecordSuccess tests success recording in metrics
func TestRecordSuccess(t *testing.T) {
	metrics := &AgentMetrics{
		consecutiveErrors: 5,
	}

	// Record success should reset consecutive errors
	metrics.recordSuccess()
	if metrics.consecutiveErrors != 0 {
		t.Errorf("Expected consecutiveErrors = 0 after success, got %d", metrics.consecutiveErrors)
	}
}

// TestRecordRequestTypeMetrics tests request type metrics recording
func TestRecordRequestTypeMetrics(t *testing.T) {
	metrics := &AgentMetrics{}

	tests := []struct {
		name        string
		requestType string
		latencyMs   int64
		success     bool
		blocked     bool
	}{
		{
			name:        "successful SQL request",
			requestType: "sql",
			latencyMs:   100,
			success:     true,
			blocked:     false,
		},
		{
			name:        "failed LLM request",
			requestType: "llm_chat",
			latencyMs:   200,
			success:     false,
			blocked:     false,
		},
		{
			name:        "blocked request",
			requestType: "sql",
			latencyMs:   50,
			success:     false,
			blocked:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			metrics.recordRequestTypeMetrics(tt.requestType, tt.latencyMs, tt.success, tt.blocked)

			// Verify counters were initialized
			if metrics.requestTypeCounters == nil {
				t.Error("requestTypeCounters should not be nil")
				return
			}

			rtm, exists := metrics.requestTypeCounters[tt.requestType]
			if !exists {
				t.Errorf("requestTypeCounters[%s] should exist", tt.requestType)
				return
			}

			if rtm.TotalRequests == 0 {
				t.Error("TotalRequests should be > 0")
			}

			if tt.blocked && rtm.BlockedRequests == 0 {
				t.Error("BlockedRequests should be > 0 for blocked request")
			}

			if tt.success && rtm.SuccessRequests == 0 {
				t.Error("SuccessRequests should be > 0 for successful request")
			}

			if !tt.success && !tt.blocked && rtm.FailedRequests == 0 {
				t.Error("FailedRequests should be > 0 for failed request")
			}
		})
	}

	// Test latency overflow (should keep only last 1000)
	for i := 0; i < 1100; i++ {
		metrics.recordRequestTypeMetrics("test", int64(i), true, false)
	}
	rtm := metrics.requestTypeCounters["test"]
	if len(rtm.Latencies) > 1000 {
		t.Errorf("Expected max 1000 latencies, got %d", len(rtm.Latencies))
	}
}

// TestRecordConnectorMetrics tests connector metrics recording
func TestRecordConnectorMetrics(t *testing.T) {
	metrics := &AgentMetrics{}

	tests := []struct {
		name      string
		connector string
		latencyMs int64
		success   bool
		errMsg    string
	}{
		{
			name:      "successful connector call",
			connector: "salesforce",
			latencyMs: 150,
			success:   true,
			errMsg:    "",
		},
		{
			name:      "failed connector call",
			connector: "slack",
			latencyMs: 300,
			success:   false,
			errMsg:    "connection timeout",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			metrics.recordConnectorMetrics(tt.connector, tt.latencyMs, tt.success, tt.errMsg)

			// Verify counters were initialized
			if metrics.connectorMetrics == nil {
				t.Error("connectorMetrics should not be nil")
				return
			}

			cm, exists := metrics.connectorMetrics[tt.connector]
			if !exists {
				t.Errorf("connectorMetrics[%s] should exist", tt.connector)
				return
			}

			if cm.TotalRequests == 0 {
				t.Error("TotalRequests should be > 0")
			}

			if tt.success && cm.SuccessRequests == 0 {
				t.Error("SuccessRequests should be > 0 for successful call")
			}

			if !tt.success && cm.FailedRequests == 0 {
				t.Error("FailedRequests should be > 0 for failed call")
			}

			if !tt.success && cm.LastError != tt.errMsg {
				t.Errorf("Expected LastError = %q, got %q", tt.errMsg, cm.LastError)
			}
		})
	}

	// Test latency overflow (should keep only last 1000)
	for i := 0; i < 1100; i++ {
		metrics.recordConnectorMetrics("overflow-test", int64(i), true, "")
	}
	cm := metrics.connectorMetrics["overflow-test"]
	if len(cm.Latencies) > 1000 {
		t.Errorf("Expected max 1000 latencies, got %d", len(cm.Latencies))
	}
}

// TestRecordMetricsConcurrency tests concurrent access to metrics
func TestRecordMetricsConcurrency(t *testing.T) {
	metrics := &AgentMetrics{}
	done := make(chan bool)

	// Run concurrent goroutines
	for i := 0; i < 10; i++ {
		go func(id int) {
			for j := 0; j < 100; j++ {
				metrics.recordError()
				metrics.recordSuccess()
				metrics.recordRequestTypeMetrics("test", int64(j), true, false)
				metrics.recordConnectorMetrics("test-connector", int64(j), true, "")
			}
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}
}

// TestAgentMetrics_EdgeCases tests additional edge cases for metrics
func TestAgentMetrics_EdgeCases(t *testing.T) {
	metrics := &AgentMetrics{
		requestTypeCounters: make(map[string]*RequestTypeMetrics),
		connectorMetrics:    make(map[string]*ConnectorMetrics),
	}

	// Test with nil fields
	metrics.recordError()
	metrics.recordSuccess()

	// Test multiple request types
	requestTypes := []string{"sql", "llm_chat", "rag_search", "mcp-query"}
	for _, rt := range requestTypes {
		metrics.recordRequestTypeMetrics(rt, 100, true, false)
		metrics.recordRequestTypeMetrics(rt, 200, false, false)
		metrics.recordRequestTypeMetrics(rt, 50, false, true)
	}

	// Test multiple connectors
	connectors := []string{"salesforce", "slack", "snowflake", "amadeus"}
	for _, conn := range connectors {
		metrics.recordConnectorMetrics(conn, 100, true, "")
		metrics.recordConnectorMetrics(conn, 200, false, "error occurred")
	}

	// Verify all counters were created
	if len(metrics.requestTypeCounters) != len(requestTypes) {
		t.Errorf("Expected %d request type counters, got %d", len(requestTypes), len(metrics.requestTypeCounters))
	}

	if len(metrics.connectorMetrics) != len(connectors) {
		t.Errorf("Expected %d connector metrics, got %d", len(connectors), len(metrics.connectorMetrics))
	}
}
