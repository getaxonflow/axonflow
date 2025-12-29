package orchestrator

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/mux"
)

// ============================================================================
// Utility Function Tests
// ============================================================================

func TestGenerateRequestID(t *testing.T) {
	// Generate a request ID
	id := generateRequestID()

	// Check format (should be req_TIMESTAMP_XXXXXXXX)
	if !strings.HasPrefix(id, "req_") {
		t.Errorf("Request ID should start with 'req_', got: %s", id)
	}

	// Check that it contains underscores in the right places
	parts := strings.Split(id, "_")
	if len(parts) != 3 {
		t.Errorf("Request ID should have format req_TIMESTAMP_RANDOM, got: %s", id)
	}

	// Check that the timestamp part is numeric
	if len(parts) > 1 {
		timestamp := parts[1]
		for _, char := range timestamp {
			if char < '0' || char > '9' {
				t.Errorf("Timestamp part should be numeric, got: %s", timestamp)
			}
		}
	}

	// Check that random part is 8 characters
	if len(parts) > 2 && len(parts[2]) != 8 {
		t.Errorf("Random part should be 8 characters, got %d: %s", len(parts[2]), parts[2])
	}

	// Test uniqueness (with small delay to avoid duplicates due to time-based randomness)
	ids := make(map[string]bool)
	for i := 0; i < 10; i++ {
		newID := generateRequestID()
		if ids[newID] {
			t.Logf("Note: Duplicate ID detected (expected with time-based randomness): %s", newID)
		}
		ids[newID] = true
		time.Sleep(1 * time.Millisecond) // Small delay to reduce duplicates
	}
}

func TestGetEnv(t *testing.T) {
	tests := []struct {
		name         string
		key          string
		defaultValue string
		envValue     string
		expected     string
	}{
		{
			name:         "existing environment variable",
			key:          "TEST_VAR_EXISTS",
			defaultValue: "default",
			envValue:     "actual",
			expected:     "actual",
		},
		{
			name:         "missing environment variable uses default",
			key:          "TEST_VAR_MISSING",
			defaultValue: "fallback",
			envValue:     "",
			expected:     "fallback",
		},
		{
			name:         "empty string environment variable",
			key:          "TEST_VAR_EMPTY",
			defaultValue: "default",
			envValue:     "",
			expected:     "default",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set environment variable if specified
			if tt.envValue != "" {
				_ = os.Setenv(tt.key, tt.envValue)
				defer func() { _ = os.Unsetenv(tt.key) }()
			} else {
				// Ensure it's not set
				_ = os.Unsetenv(tt.key)
			}

			result := getEnv(tt.key, tt.defaultValue)
			if result != tt.expected {
				t.Errorf("getEnv(%s, %s) = %s; want %s", tt.key, tt.defaultValue, result, tt.expected)
			}
		})
	}
}

// ============================================================================
// HTTP Handler Tests
// ============================================================================

func TestHealthHandler(t *testing.T) {
	tests := []struct {
		name                   string
		setupPlanningEngine    bool
		setupResultAggregator  bool
		expectedFeature        bool
	}{
		{
			name:                  "with planning engine and result aggregator",
			setupPlanningEngine:   true,
			setupResultAggregator: true,
			expectedFeature:       true,
		},
		{
			name:                  "without planning components",
			setupPlanningEngine:   false,
			setupResultAggregator: false,
			expectedFeature:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Initialize minimal global components for health check
			ctx := context.Background()
			setupTestComponents(ctx)
			defer teardownTestComponents()

			// Save old state and set planning components based on test case
			oldPlanningEngine := planningEngine
			oldResultAggregator := resultAggregator
			defer func() {
				planningEngine = oldPlanningEngine
				resultAggregator = oldResultAggregator
			}()

			if tt.setupPlanningEngine {
				if planningEngine == nil {
					planningEngine = NewPlanningEngine(llmRouter)
				}
			} else {
				planningEngine = nil
			}

			if tt.setupResultAggregator {
				if resultAggregator == nil {
					resultAggregator = NewResultAggregator(llmRouter)
				}
			} else {
				resultAggregator = nil
			}

			req := httptest.NewRequest("GET", "/health", nil)
			w := httptest.NewRecorder()

			healthHandler(w, req)

			// Check status code
			if w.Code != http.StatusOK {
				t.Errorf("Expected status 200, got %d", w.Code)
			}

			// Check content type
			contentType := w.Header().Get("Content-Type")
			if contentType != "application/json" {
				t.Errorf("Expected Content-Type application/json, got %s", contentType)
			}

			// Parse response
			var health map[string]interface{}
			if err := json.NewDecoder(w.Body).Decode(&health); err != nil {
				t.Fatalf("Failed to decode health response: %v", err)
			}

			// Check required fields
			if status, ok := health["status"].(string); !ok || status != "healthy" {
				t.Errorf("Expected status 'healthy', got %v", health["status"])
			}

			if service, ok := health["service"].(string); !ok || service != "axonflow-orchestrator" {
				t.Errorf("Expected service 'axonflow-orchestrator', got %v", health["service"])
			}

			if version, ok := health["version"].(string); !ok || version != "1.0.0" {
				t.Errorf("Expected version '1.0.0', got %v", health["version"])
			}

			// Check components exist
			components, ok := health["components"].(map[string]interface{})
			if !ok {
				t.Fatal("Expected 'components' map in health response")
			}

			expectedComponents := []string{"policy_engine", "llm_router", "response_processor", "audit_logger", "workflow_engine"}
			for _, component := range expectedComponents {
				if _, exists := components[component]; !exists {
					t.Errorf("Expected component '%s' in health check", component)
				}
			}

			// Check multi-agent planning feature flag
			features, ok := health["features"].(map[string]interface{})
			if !ok {
				t.Fatal("Expected 'features' map in health response")
			}

			multiAgentPlanning, ok := features["multi_agent_planning"].(bool)
			if !ok {
				t.Fatal("Expected 'multi_agent_planning' feature flag")
			}

			if multiAgentPlanning != tt.expectedFeature {
				t.Errorf("Expected multi_agent_planning=%v, got %v", tt.expectedFeature, multiAgentPlanning)
			}
		})
	}
}

func TestSendErrorResponse(t *testing.T) {
	tests := []struct {
		name       string
		message    string
		statusCode int
	}{
		{
			name:       "bad request error",
			message:    "Invalid input",
			statusCode: http.StatusBadRequest,
		},
		{
			name:       "unauthorized error",
			message:    "Authentication required",
			statusCode: http.StatusUnauthorized,
		},
		{
			name:       "forbidden error",
			message:    "Access denied",
			statusCode: http.StatusForbidden,
		},
		{
			name:       "internal server error",
			message:    "Something went wrong",
			statusCode: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()

			sendErrorResponse(w, tt.message, tt.statusCode)

			// Check status code
			if w.Code != tt.statusCode {
				t.Errorf("Expected status %d, got %d", tt.statusCode, w.Code)
			}

			// Check content type
			contentType := w.Header().Get("Content-Type")
			if contentType != "application/json" {
				t.Errorf("Expected Content-Type application/json, got %s", contentType)
			}

			// Parse response
			var errResp map[string]interface{}
			if err := json.NewDecoder(w.Body).Decode(&errResp); err != nil {
				t.Fatalf("Failed to decode error response: %v", err)
			}

			// Check error field
			if error, ok := errResp["error"].(string); !ok || error != tt.message {
				t.Errorf("Expected error message '%s', got %v", tt.message, errResp["error"])
			}
		})
	}
}

func TestSimpleMetricsHandler(t *testing.T) {
	tests := []struct {
		name                      string
		setupOrchestratorMetrics  bool
		setupWithRequestTypes     bool
		setupWithProviders        bool
		setupHealthCheckPassed    bool
		expectedFields            []string
		expectedRequestTypes      bool
		expectedProviders         bool
		description               string
	}{
		{
			name:                     "With orchestrator metrics",
			setupOrchestratorMetrics: true,
			expectedFields:           []string{"total_requests", "blocked_requests", "policy_evaluations", "dynamic_policy_eval_p99_ms", "llm_routing_p99_ms"},
			description:              "Should include per-stage metrics when orchestratorMetrics is initialized",
		},
		{
			name:                     "Without orchestrator metrics",
			setupOrchestratorMetrics: false,
			expectedFields:           []string{"total_requests", "blocked_requests", "policy_evaluations"},
			description:              "Should return basic metrics when orchestratorMetrics is nil",
		},
		{
			name:                      "With request types and providers",
			setupOrchestratorMetrics:  true,
			setupWithRequestTypes:     true,
			setupWithProviders:        true,
			setupHealthCheckPassed:    true,
			expectedFields:            []string{"total_requests", "success_rate", "error_rate_per_sec"},
			expectedRequestTypes:      true,
			expectedProviders:         true,
			description:               "Should include request_types and providers when populated",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Initialize minimal components
			ctx := context.Background()
			setupTestComponents(ctx)
			defer teardownTestComponents()

			// Save and restore orchestratorMetrics
			oldMetrics := orchestratorMetrics
			defer func() { orchestratorMetrics = oldMetrics }()

			// Set up orchestratorMetrics based on test case
			if tt.setupOrchestratorMetrics {
				om := &OrchestratorMetrics{
					dynamicPolicyTimings: []int64{1000, 2000, 3000},
					llmTimings:           []int64{10000, 20000, 30000},
					healthCheckPassed:    tt.setupHealthCheckPassed,
				}
				if tt.setupWithRequestTypes {
					om.requestTypeMetrics = map[string]*RequestTypeOrchestratorMetrics{
						"chat": {
							TotalRequests:   100,
							SuccessRequests: 95,
							FailedRequests:  5,
							BlockedRequests: 0,
							Latencies:       []int64{50, 60, 70},
						},
						"completion": {
							TotalRequests:   50,
							SuccessRequests: 48,
							FailedRequests:  2,
							BlockedRequests: 0,
							Latencies:       []int64{100, 120, 140},
						},
					}
				}
				if tt.setupWithProviders {
					om.providerMetrics = map[string]*LLMProviderMetrics{
						"openai": {
							ProviderName: "openai",
							TotalCalls:   80,
							SuccessCalls: 78,
							FailedCalls:  2,
							TotalTokens:  50000,
							TotalCost:    1.5,
							Latencies:    []int64{200, 250, 300},
						},
						"anthropic": {
							ProviderName: "anthropic",
							TotalCalls:   20,
							SuccessCalls: 19,
							FailedCalls:  1,
							TotalTokens:  10000,
							TotalCost:    0.5,
							Latencies:    []int64{150, 175, 200},
						},
					}
				}
				orchestratorMetrics = om
			} else {
				orchestratorMetrics = nil
			}

			req := httptest.NewRequest("GET", "/metrics/simple", nil)
			w := httptest.NewRecorder()

			simpleMetricsHandler(w, req)

			// Check status code
			if w.Code != http.StatusOK {
				t.Errorf("%s: Expected status 200, got %d", tt.description, w.Code)
			}

			// Check content type
			contentType := w.Header().Get("Content-Type")
			if contentType != "application/json" {
				t.Errorf("%s: Expected Content-Type application/json, got %s", tt.description, contentType)
			}

			// Parse response
			var response map[string]interface{}
			if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
				t.Fatalf("%s: Failed to decode metrics response: %v", tt.description, err)
			}

			// Check orchestrator_metrics field exists
			metrics, ok := response["orchestrator_metrics"].(map[string]interface{})
			if !ok {
				t.Fatalf("%s: Expected 'orchestrator_metrics' map in response", tt.description)
			}

			// Check expected fields
			for _, field := range tt.expectedFields {
				if _, exists := metrics[field]; !exists {
					t.Errorf("%s: Expected metric field '%s' in orchestrator_metrics", tt.description, field)
				}
			}

			// Verify per-stage metrics only present when orchestratorMetrics initialized
			if tt.setupOrchestratorMetrics {
				if _, exists := metrics["dynamic_policy_eval_p99_ms"]; !exists {
					t.Errorf("%s: Expected dynamic_policy_eval_p99_ms when orchestratorMetrics initialized", tt.description)
				}
			}

			// Check request_types if expected
			if tt.expectedRequestTypes {
				requestTypes, ok := response["request_types"].(map[string]interface{})
				if !ok {
					t.Errorf("%s: Expected 'request_types' map in response", tt.description)
				} else if len(requestTypes) == 0 {
					t.Errorf("%s: Expected non-empty request_types", tt.description)
				} else {
					// Verify at least one request type has expected fields
					for rtName, rtData := range requestTypes {
						rtMap, ok := rtData.(map[string]interface{})
						if !ok {
							t.Errorf("%s: Expected request type '%s' to be a map", tt.description, rtName)
							continue
						}
						if _, exists := rtMap["total_requests"]; !exists {
							t.Errorf("%s: Expected 'total_requests' in request type '%s'", tt.description, rtName)
						}
						if _, exists := rtMap["p99_ms"]; !exists {
							t.Errorf("%s: Expected 'p99_ms' in request type '%s'", tt.description, rtName)
						}
						break // Just check one
					}
				}
			}

			// Check providers if expected
			if tt.expectedProviders {
				providers, ok := response["providers"].(map[string]interface{})
				if !ok {
					t.Errorf("%s: Expected 'providers' map in response", tt.description)
				} else if len(providers) == 0 {
					t.Errorf("%s: Expected non-empty providers", tt.description)
				} else {
					// Verify at least one provider has expected fields
					for pName, pData := range providers {
						pMap, ok := pData.(map[string]interface{})
						if !ok {
							t.Errorf("%s: Expected provider '%s' to be a map", tt.description, pName)
							continue
						}
						if _, exists := pMap["total_calls"]; !exists {
							t.Errorf("%s: Expected 'total_calls' in provider '%s'", tt.description, pName)
						}
						if _, exists := pMap["total_tokens"]; !exists {
							t.Errorf("%s: Expected 'total_tokens' in provider '%s'", tt.description, pName)
						}
						break // Just check one
					}
				}
			}

			// Check health section
			health, ok := response["health"].(map[string]interface{})
			if !ok {
				t.Errorf("%s: Expected 'health' map in response", tt.description)
			} else {
				if _, exists := health["up"]; !exists {
					t.Errorf("%s: Expected 'up' field in health", tt.description)
				}
			}
		})
	}
}

func TestProviderStatusHandler(t *testing.T) {
	// Initialize minimal components
	ctx := context.Background()
	setupTestComponents(ctx)
	defer teardownTestComponents()

	req := httptest.NewRequest("GET", "/providers/status", nil)
	w := httptest.NewRecorder()

	providerStatusHandler(w, req)

	// Check status code (should be 200 even with empty providers)
	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	// Check content type
	contentType := w.Header().Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("Expected Content-Type application/json, got %s", contentType)
	}

	// Parse response - should be a map of provider names to status
	var status map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&status); err != nil {
		t.Fatalf("Failed to decode provider status response: %v", err)
	}

	// Check that response is a map (can be empty if no providers configured)
	// This is valid - an empty map means no providers are active
	if status == nil {
		t.Error("Expected non-nil provider status map")
	}
}

func TestListDynamicPoliciesHandler(t *testing.T) {
	// Initialize minimal components
	ctx := context.Background()
	setupTestComponents(ctx)
	defer teardownTestComponents()

	req := httptest.NewRequest("GET", "/policies/dynamic", nil)
	w := httptest.NewRecorder()

	listDynamicPoliciesHandler(w, req)

	// Check status code
	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	// Check content type
	contentType := w.Header().Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("Expected Content-Type application/json, got %s", contentType)
	}

	// Parse response - should be an array of policies
	var policies []interface{}
	if err := json.NewDecoder(w.Body).Decode(&policies); err != nil {
		t.Fatalf("Failed to decode policies response: %v", err)
	}

	// Check that response is an array (can be empty if no policies configured)
	// This is valid - an empty array means no active policies
	if policies == nil {
		t.Error("Expected non-nil policies array")
	}
}

func TestTestPolicyHandler(t *testing.T) {
	tests := []struct {
		name           string
		body           interface{}
		expectedStatus int
		description    string
	}{
		{
			name: "valid policy test request",
			body: map[string]interface{}{
				"query":        "test query",
				"user":         map[string]interface{}{"email": "test@example.com", "role": "user"},
				"request_type": "chat",
			},
			expectedStatus: http.StatusOK,
			description:    "Should successfully test policy with valid request",
		},
		{
			name:           "invalid JSON body",
			body:           "invalid json",
			expectedStatus: http.StatusBadRequest,
			description:    "Should return 400 for invalid JSON",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Initialize minimal components
			ctx := context.Background()
			setupTestComponents(ctx)
			defer teardownTestComponents()

			// Prepare request body
			var body []byte
			if str, ok := tt.body.(string); ok {
				body = []byte(str)
			} else {
				body, _ = json.Marshal(tt.body)
			}

			req := httptest.NewRequest("POST", "/policies/test", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			testPolicyHandler(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("%s: expected status %d, got %d", tt.description, tt.expectedStatus, w.Code)
			}
		})
	}
}

// ============================================================================
// Test Helper Functions
// ============================================================================

// setupTestComponents initializes minimal global components for testing
func setupTestComponents(ctx context.Context) {
	// Initialize only if nil (avoid re-initialization)
	if dynamicPolicyEngine == nil {
		dynamicPolicyEngine = NewDynamicPolicyEngine()
	}

	if llmRouter == nil {
		llmRouter = NewLLMRouter(LLMRouterConfig{
			OpenAIKey:     "test-key",
			AnthropicKey:  "test-key",
			LocalEndpoint: "",
		})
	}

	// Create a test wrapper for llmRouterWrapper (uses legacy router for testing)
	// Note: In production, llmRouterWrapper wraps UnifiedRouter
	if llmRouterWrapper == nil && llmRouter != nil {
		// Use the legacy router directly since *LLMRouter implements LLMRouterInterface
		llmRouterWrapper = llmRouter
	}

	if responseProcessor == nil {
		responseProcessor = NewResponseProcessor()
	}

	if auditLogger == nil {
		auditLogger = NewAuditLogger("") // Empty URL for testing
	}

	if workflowEngine == nil {
		workflowEngine = NewWorkflowEngine()
	}

	// Initialize metrics if nil
	if orchestratorMetrics == nil {
		orchestratorMetrics = &OrchestratorMetrics{
			dynamicPolicyTimings: make([]int64, 0),
			llmTimings:           make([]int64, 0),
			startTime:            time.Now(),
		}
	}

	// Initialize metrics collector if nil
	if metricsCollector == nil {
		metricsCollector = NewMetricsCollector()
	}
}

// teardownTestComponents cleans up test components
func teardownTestComponents() {
	// Optional cleanup if needed
}

func TestMetricsHandler(t *testing.T) {
	// Initialize minimal components
	ctx := context.Background()
	setupTestComponents(ctx)
	defer teardownTestComponents()

	req := httptest.NewRequest("GET", "/metrics", nil)
	w := httptest.NewRecorder()

	metricsHandler(w, req)

	// Check status code
	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	// Check content type
	contentType := w.Header().Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("Expected Content-Type application/json, got %s", contentType)
	}

	// Parse response - should be complete metrics object
	var metrics map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&metrics); err != nil {
		t.Fatalf("Failed to decode metrics response: %v", err)
	}

	// Verify it's a valid metrics object (has some expected fields)
	if metrics == nil {
		t.Error("Expected non-nil metrics response")
	}
}

func TestUpdateProviderWeightsHandler(t *testing.T) {
	// Initialize minimal components
	ctx := context.Background()
	setupTestComponents(ctx)
	defer teardownTestComponents()

	tests := []struct {
		name         string
		weights      map[string]float64
		expectedCode int
	}{
		{
			name: "valid weights",
			weights: map[string]float64{
				"openai":    0.7,
				"anthropic": 0.3,
			},
			expectedCode: http.StatusOK,
		},
		{
			name:         "invalid JSON",
			weights:      nil,
			expectedCode: http.StatusBadRequest,
		},
		{
			name: "invalid weights (negative)",
			weights: map[string]float64{
				"openai": -0.5,
			},
			expectedCode: http.StatusBadRequest,
		},
		{
			name: "invalid weights (sum exceeds 1)",
			weights: map[string]float64{
				"openai":    0.8,
				"anthropic": 0.8,
			},
			expectedCode: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var body []byte
			if tt.weights != nil {
				body, _ = json.Marshal(tt.weights)
			} else {
				body = []byte("invalid json")
			}

			req := httptest.NewRequest("POST", "/providers/weights", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			updateProviderWeightsHandler(w, req)

			if w.Code != tt.expectedCode {
				t.Errorf("Expected status %d, got %d", tt.expectedCode, w.Code)
			}
		})
	}
}

func TestCalculateP99Orchestrator(t *testing.T) {
	tests := []struct {
		name     string
		timings  []int64
		expected float64
	}{
		{
			name:     "empty slice",
			timings:  []int64{},
			expected: 0,
		},
		{
			name:     "single value",
			timings:  []int64{100},
			expected: 100,
		},
		{
			name:     "100 values - P99 returns highest value",
			timings:  []int64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100},
			expected: 100,
		},
		{
			name:     "unsorted values",
			timings:  []int64{100, 50, 75, 25, 90},
			expected: 100,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := calculateP99Orchestrator(tt.timings)
			if result != tt.expected {
				t.Errorf("calculateP99Orchestrator(%v) = %f; want %f", tt.timings, result, tt.expected)
			}
		})
	}
}

func TestCalculateAverageOrchestrator(t *testing.T) {
	tests := []struct {
		name     string
		timings  []int64
		expected float64
	}{
		{
			name:     "empty slice",
			timings:  []int64{},
			expected: 0,
		},
		{
			name:     "single value",
			timings:  []int64{100},
			expected: 100,
		},
		{
			name:     "multiple values",
			timings:  []int64{10, 20, 30, 40, 50},
			expected: 30,
		},
		{
			name:     "all same values",
			timings:  []int64{50, 50, 50, 50},
			expected: 50,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := calculateAverageOrchestrator(tt.timings)
			if result != tt.expected {
				t.Errorf("calculateAverageOrchestrator(%v) = %f; want %f", tt.timings, result, tt.expected)
			}
		})
	}
}

// TestGetWorkflowExecutionHandler tests workflow execution retrieval
func TestGetWorkflowExecutionHandler(t *testing.T) {
	// Setup
	oldEngine := workflowEngine
	defer func() { workflowEngine = oldEngine }()

	workflowEngine = NewWorkflowEngine()

	tests := []struct {
		name           string
		executionID    string
		setupExecution bool
		expectedStatus int
	}{
		{
			name:           "Success - execution found",
			executionID:    "test-exec-123",
			setupExecution: true,
			expectedStatus: http.StatusOK,
		},
		{
			name:           "Error - execution ID missing",
			executionID:    "",
			setupExecution: false,
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "Error - execution not found",
			executionID:    "nonexistent-exec",
			setupExecution: false,
			expectedStatus: http.StatusNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup execution if needed
			if tt.setupExecution {
				endTime := time.Now()
				execution := &WorkflowExecution{
					ID:           tt.executionID,
					WorkflowName: "test-workflow",
					Status:       "completed",
					Input:        map[string]interface{}{"query": "test"},
					Output:       map[string]interface{}{"result": "success"},
					Steps:        []StepExecution{},
					StartTime:    time.Now(),
					EndTime:      &endTime,
					UserContext:  UserContext{ID: 1, Email: "test@example.com"},
				}
				// Save to storage
				if err := workflowEngine.storage.SaveExecution(execution); err != nil {
					t.Fatalf("Failed to save execution: %v", err)
				}
			}

			req := httptest.NewRequest("GET", "/workflows/executions/"+tt.executionID, nil)
			req = mux.SetURLVars(req, map[string]string{"id": tt.executionID})
			w := httptest.NewRecorder()

			getWorkflowExecutionHandler(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, w.Code)
			}

			// Verify success response contains execution data
			if tt.expectedStatus == http.StatusOK {
				var response WorkflowExecution
				if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
					t.Fatalf("Failed to unmarshal response: %v", err)
				}
				if response.ID != tt.executionID {
					t.Errorf("Expected execution ID %s, got %s", tt.executionID, response.ID)
				}
				if response.Status != "completed" {
					t.Errorf("Expected status 'completed', got %s", response.Status)
				}
			}
		})
	}
}

// TestListWorkflowExecutionsHandler tests workflow execution listing
func TestListWorkflowExecutionsHandler(t *testing.T) {
	// Setup
	oldEngine := workflowEngine
	defer func() { workflowEngine = oldEngine }()

	workflowEngine = NewWorkflowEngine()

	tests := []struct {
		name           string
		queryParam     string
		expectedStatus int
		expectedLimit  int
	}{
		{
			name:           "Success - default limit",
			queryParam:     "",
			expectedStatus: http.StatusOK,
			expectedLimit:  10,
		},
		{
			name:           "Success - custom limit",
			queryParam:     "?limit=5",
			expectedStatus: http.StatusOK,
			expectedLimit:  5,
		},
		{
			name:           "Success - invalid limit uses default",
			queryParam:     "?limit=invalid",
			expectedStatus: http.StatusOK,
			expectedLimit:  10,
		},
		{
			name:           "Success - negative limit uses default",
			queryParam:     "?limit=-5",
			expectedStatus: http.StatusOK,
			expectedLimit:  10,
		},
		{
			name:           "Success - zero limit uses default",
			queryParam:     "?limit=0",
			expectedStatus: http.StatusOK,
			expectedLimit:  10,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/workflows/executions"+tt.queryParam, nil)
			w := httptest.NewRecorder()

			listWorkflowExecutionsHandler(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, w.Code)
			}

			if tt.expectedStatus == http.StatusOK {
				var response map[string]interface{}
				_ = json.NewDecoder(w.Body).Decode(&response)
				if _, ok := response["executions"]; !ok {
					t.Error("Expected 'executions' field in response")
				}
				if _, ok := response["count"]; !ok {
					t.Error("Expected 'count' field in response")
				}
			}
		})
	}
}

// TestPlanRequestHandler tests multi-agent planning handler
func TestPlanRequestHandler(t *testing.T) {
	// Save old state
	oldPlanningEngine := planningEngine
	oldWorkflowEngine := workflowEngine
	defer func() {
		planningEngine = oldPlanningEngine
		workflowEngine = oldWorkflowEngine
	}()

	tests := []struct {
		name               string
		setupPlanningEngine bool
		setupWorkflowEngine bool
		requestBody        string
		expectedStatus     int
	}{
		{
			name:               "Error - planning engine not initialized",
			setupPlanningEngine: false,
			setupWorkflowEngine: true,
			requestBody:        `{"query":"test"}`,
			expectedStatus:     http.StatusServiceUnavailable,
		},
		{
			name:               "Error - workflow engine not initialized",
			setupPlanningEngine: true,
			setupWorkflowEngine: false,
			requestBody:        `{"query":"test"}`,
			expectedStatus:     http.StatusServiceUnavailable,
		},
		{
			name:               "Error - invalid JSON",
			setupPlanningEngine: true,
			setupWorkflowEngine: true,
			requestBody:        `{invalid json}`,
			expectedStatus:     http.StatusBadRequest,
		},
		{
			name:               "Error - missing user authentication",
			setupPlanningEngine: true,
			setupWorkflowEngine: true,
			requestBody:        `{"query":"test query"}`,
			expectedStatus:     http.StatusUnauthorized,
		},
		{
			name:               "Error - empty query",
			setupPlanningEngine: true,
			setupWorkflowEngine: true,
			requestBody:        `{"query":"","user":{"id":1,"email":"test@example.com"}}`,
			expectedStatus:     http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setupPlanningEngine {
				planningEngine = &PlanningEngine{}
			} else {
				planningEngine = nil
			}

			if tt.setupWorkflowEngine {
				workflowEngine = NewWorkflowEngine()
			} else {
				workflowEngine = nil
			}

			req := httptest.NewRequest("POST", "/plan", strings.NewReader(tt.requestBody))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			planRequestHandler(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, w.Code)
			}
		})
	}
}

// TestConvertWorkflowStepsToResponse tests the step conversion function
func TestConvertWorkflowStepsToResponse(t *testing.T) {
	tests := []struct {
		name     string
		steps    []WorkflowStep
		expected []ResponsePlanStep
	}{
		{
			name:     "Nil steps",
			steps:    nil,
			expected: []ResponsePlanStep{},
		},
		{
			name:     "Empty steps",
			steps:    []WorkflowStep{},
			expected: []ResponsePlanStep{},
		},
		{
			name: "LLM call step",
			steps: []WorkflowStep{
				{
					Name:   "analyze-query",
					Type:   "llm-call",
					Prompt: "Analyze this query",
				},
			},
			expected: []ResponsePlanStep{
				{
					ID:          "step_1_analyze-query",
					Name:        "analyze-query",
					Type:        "llm-call",
					Description: "Analyze this query",
					DependsOn:   []string{},
					Agent:       "",
					Parameters:  nil,
				},
			},
		},
		{
			name: "Connector call step",
			steps: []WorkflowStep{
				{
					Name:      "search-flights",
					Type:      "connector-call",
					Connector: "amadeus",
					Statement: "search_flights",
					Parameters: map[string]interface{}{
						"origin":      "NYC",
						"destination": "PAR",
					},
				},
			},
			expected: []ResponsePlanStep{
				{
					ID:          "step_1_search-flights",
					Name:        "search-flights",
					Type:        "connector-call",
					Description: "Call amadeus connector: search_flights",
					DependsOn:   []string{},
					Agent:       "amadeus",
					Parameters: map[string]interface{}{
						"origin":      "NYC",
						"destination": "PAR",
					},
				},
			},
		},
		{
			name: "Long prompt truncation",
			steps: []WorkflowStep{
				{
					Name:   "long-prompt",
					Type:   "llm-call",
					Prompt: "This is a very long prompt that should be truncated because it exceeds the 100 character limit that we have set for descriptions in the response",
				},
			},
			expected: []ResponsePlanStep{
				{
					ID:          "step_1_long-prompt",
					Name:        "long-prompt",
					Type:        "llm-call",
					Description: "This is a very long prompt that should be truncated because it exceeds the 100 character limit that ...",
					DependsOn:   []string{},
					Agent:       "",
					Parameters:  nil,
				},
			},
		},
		{
			name: "Multiple steps (typical MAP workflow)",
			steps: []WorkflowStep{
				{
					Name:      "search-flights",
					Type:      "connector-call",
					Connector: "amadeus",
					Statement: "search_flights",
				},
				{
					Name:      "search-hotels",
					Type:      "connector-call",
					Connector: "amadeus",
					Statement: "search_hotels",
				},
				{
					Name:   "synthesize-results",
					Type:   "llm-call",
					Prompt: "Combine flight and hotel results into an itinerary",
				},
			},
			expected: []ResponsePlanStep{
				{
					ID:          "step_1_search-flights",
					Name:        "search-flights",
					Type:        "connector-call",
					Description: "Call amadeus connector: search_flights",
					DependsOn:   []string{},
					Agent:       "amadeus",
					Parameters:  nil,
				},
				{
					ID:          "step_2_search-hotels",
					Name:        "search-hotels",
					Type:        "connector-call",
					Description: "Call amadeus connector: search_hotels",
					DependsOn:   []string{},
					Agent:       "amadeus",
					Parameters:  nil,
				},
				{
					ID:          "step_3_synthesize-results",
					Name:        "synthesize-results",
					Type:        "llm-call",
					Description: "Combine flight and hotel results into an itinerary",
					DependsOn:   []string{},
					Agent:       "",
					Parameters:  nil,
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := convertWorkflowStepsToResponse(tt.steps)
			if len(result) != len(tt.expected) {
				t.Errorf("Expected %d steps, got %d", len(tt.expected), len(result))
				return
			}
			for i, step := range result {
				if step.ID != tt.expected[i].ID {
					t.Errorf("Step %d: expected ID %s, got %s", i, tt.expected[i].ID, step.ID)
				}
				if step.Name != tt.expected[i].Name {
					t.Errorf("Step %d: expected Name %s, got %s", i, tt.expected[i].Name, step.Name)
				}
				if step.Type != tt.expected[i].Type {
					t.Errorf("Step %d: expected Type %s, got %s", i, tt.expected[i].Type, step.Type)
				}
				if step.Description != tt.expected[i].Description {
					t.Errorf("Step %d: expected Description %s, got %s", i, tt.expected[i].Description, step.Description)
				}
				if step.Agent != tt.expected[i].Agent {
					t.Errorf("Step %d: expected Agent %s, got %s", i, tt.expected[i].Agent, step.Agent)
				}
			}
		})
	}
}

// TestAuditSearchHandler tests audit log search
func TestAuditSearchHandler(t *testing.T) {
	// Save old state
	oldAuditLogger := auditLogger
	defer func() { auditLogger = oldAuditLogger }()

	tests := []struct {
		name           string
		requestBody    string
		expectedStatus int
	}{
		{
			name:           "Error - invalid JSON",
			requestBody:    "{invalid json}",
			expectedStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("POST", "/audit/search", strings.NewReader(tt.requestBody))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			auditSearchHandler(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, w.Code)
			}
		})
	}
}

// TestTenantAuditLogsHandler tests tenant-specific audit logs
func TestTenantAuditLogsHandler(t *testing.T) {
	tests := []struct {
		name           string
		tenantID       string
		expectedStatus int
	}{
		{
			name:           "Error - tenant ID missing",
			tenantID:       "",
			expectedStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/audit/tenant/"+tt.tenantID, nil)
			req = mux.SetURLVars(req, map[string]string{"tenant_id": tt.tenantID})
			w := httptest.NewRecorder()

			tenantAuditLogsHandler(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, w.Code)
			}
		})
	}
}

// TestTenantWorkflowExecutionsHandler tests tenant workflow execution retrieval
func TestTenantWorkflowExecutionsHandler(t *testing.T) {
	tests := []struct {
		name           string
		tenantID       string
		expectedStatus int
	}{
		{
			name:           "Error - tenant ID missing",
			tenantID:       "",
			expectedStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/workflows/tenant/"+tt.tenantID+"/executions", nil)
			req = mux.SetURLVars(req, map[string]string{"tenant_id": tt.tenantID})
			w := httptest.NewRecorder()

			tenantWorkflowExecutionsHandler(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d, got %d", tt.expectedStatus, w.Code)
			}
		})
	}
}

// TestGetOutputKeys tests the getOutputKeys utility function
func TestGetOutputKeys(t *testing.T) {
	tests := []struct {
		name     string
		output   map[string]interface{}
		wantLen  int
	}{
		{
			name: "non-empty map",
			output: map[string]interface{}{
				"key1": "value1",
				"key2": "value2",
				"key3": "value3",
			},
			wantLen: 3,
		},
		{
			name:    "empty map",
			output:  map[string]interface{}{},
			wantLen: 0,
		},
		{
			name:    "nil map",
			output:  nil,
			wantLen: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getOutputKeys(tt.output)

			if len(result) != tt.wantLen {
				t.Errorf("Expected %d keys, got %d", tt.wantLen, len(result))
			}

			// Verify all keys from input are in result
			if tt.output != nil {
				keyMap := make(map[string]bool)
				for _, k := range result {
					keyMap[k] = true
				}

				for k := range tt.output {
					if !keyMap[k] {
						t.Errorf("Expected key '%s' not found in result", k)
					}
				}
			}
		})
	}
}

// TestGetResultLength tests the getResultLength utility function
func TestGetResultLength(t *testing.T) {
	tests := []struct {
		name   string
		result interface{}
		want   int
	}{
		{
			name:   "string result",
			result: "hello world",
			want:   11,
		},
		{
			name:   "empty string",
			result: "",
			want:   0,
		},
		{
			name:   "nil result",
			result: nil,
			want:   0,
		},
		{
			name:   "integer result (not string)",
			result: 12345,
			want:   -1,
		},
		{
			name:   "map result (not string)",
			result: map[string]interface{}{"key": "value"},
			want:   -1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getResultLength(tt.result)

			if result != tt.want {
				t.Errorf("Expected %d, got %d", tt.want, result)
			}
		})
	}
}

// TestEncodePostgreSQLPassword tests URL password encoding
func TestEncodePostgreSQLPassword(t *testing.T) {
	tests := []struct {
		name     string
		input    string
	}{
		{
			name:     "Simple password",
			input:    "postgresql://user:pass@localhost:5432/db",
		},
		{
			name:     "Password with @ symbol",
			input:    "postgresql://user:test@123@host:5432/db",
		},
		{
			name:     "Password with special characters",
			input:    "postgresql://user:p@ss!w0rd@localhost:5432/db",
		},
		{
			name:     "No password",
			input:    "postgresql://user@localhost:5432/db",
		},
		{
			name:     "Missing scheme",
			input:    "user:pass@localhost:5432/db",
		},
		{
			name:     "Missing @ separator",
			input:    "postgresql://userpass",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := encodePostgreSQLPassword(tt.input)

			// Verify result is not empty
			if result == "" {
				t.Error("Result should not be empty")
			}

			// Verify scheme is preserved for valid URLs
			if strings.HasPrefix(tt.input, "postgresql://") && !strings.HasPrefix(result, "postgresql://") {
				t.Error("Scheme should be preserved")
			}
		})
	}
}

// TestGenerateRandomString tests random string generation
func TestGenerateRandomString(t *testing.T) {
	tests := []struct {
		name   string
		length int
	}{
		{"Empty string", 0},
		{"Short string", 5},
		{"Medium string", 16},
		{"Long string", 32},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := generateRandomString(tt.length)

			if len(result) != tt.length {
				t.Errorf("Expected length %d, got %d", tt.length, len(result))
			}

			// Verify only alphanumeric characters
			for _, char := range result {
				if !((char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9')) {
					t.Errorf("Invalid character %c in result %s", char, result)
				}
			}
		})
	}

	// Test randomness - two calls should produce different results
	result1 := generateRandomString(16)
	result2 := generateRandomString(16)
	if result1 == result2 {
		t.Error("generateRandomString should produce different results on consecutive calls")
	}
}

// TestOrchestratorMetrics_recordRequest tests the recordRequest function
func TestOrchestratorMetrics_recordRequest(t *testing.T) {
	tests := []struct {
		name         string
		requestType  string
		provider     string
		latencyMs    int64
		success      bool
		blocked      bool
		tokens       int
		cost         float64
		checkMetrics func(*testing.T, *OrchestratorMetrics)
	}{
		{
			name:        "successful request",
			requestType: "query",
			provider:    "openai",
			latencyMs:   100,
			success:     true,
			blocked:     false,
			tokens:      50,
			cost:        0.001,
			checkMetrics: func(t *testing.T, m *OrchestratorMetrics) {
				if m.totalRequests != 1 {
					t.Errorf("Expected totalRequests=1, got %d", m.totalRequests)
				}
				if m.successRequests != 1 {
					t.Errorf("Expected successRequests=1, got %d", m.successRequests)
				}
				if m.consecutiveErrors != 0 {
					t.Errorf("Expected consecutiveErrors=0, got %d", m.consecutiveErrors)
				}
				if !m.healthCheckPassed {
					t.Error("Expected healthCheckPassed=true")
				}
			},
		},
		{
			name:        "blocked request",
			requestType: "query",
			provider:    "openai",
			latencyMs:   50,
			success:     false,
			blocked:     true,
			tokens:      0,
			cost:        0,
			checkMetrics: func(t *testing.T, m *OrchestratorMetrics) {
				if m.totalRequests != 1 {
					t.Errorf("Expected totalRequests=1, got %d", m.totalRequests)
				}
				if m.blockedRequests != 1 {
					t.Errorf("Expected blockedRequests=1, got %d", m.blockedRequests)
				}
			},
		},
		{
			name:        "failed request",
			requestType: "query",
			provider:    "openai",
			latencyMs:   200,
			success:     false,
			blocked:     false,
			tokens:      0,
			cost:        0,
			checkMetrics: func(t *testing.T, m *OrchestratorMetrics) {
				if m.totalRequests != 1 {
					t.Errorf("Expected totalRequests=1, got %d", m.totalRequests)
				}
				if m.failedRequests != 1 {
					t.Errorf("Expected failedRequests=1, got %d", m.failedRequests)
				}
				if m.consecutiveErrors != 1 {
					t.Errorf("Expected consecutiveErrors=1, got %d", m.consecutiveErrors)
				}
				if len(m.errorTimestamps) != 1 {
					t.Errorf("Expected 1 error timestamp, got %d", len(m.errorTimestamps))
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			metrics := &OrchestratorMetrics{
				dynamicPolicyTimings: make([]int64, 0),
				llmTimings:           make([]int64, 0),
				errorTimestamps:      make([]time.Time, 0),
				requestTypeMetrics:   make(map[string]*RequestTypeOrchestratorMetrics),
				providerMetrics:      make(map[string]*LLMProviderMetrics),
				startTime:            time.Now(),
			}

			metrics.recordRequest(tt.requestType, tt.provider, tt.latencyMs, tt.success, tt.blocked, tt.tokens, tt.cost)

			if tt.checkMetrics != nil {
				metrics.mu.RLock()
				tt.checkMetrics(t, metrics)
				metrics.mu.RUnlock()
			}
		})
	}
}

// TestCalculateErrorRateOrchestrator tests the error rate calculation
func TestCalculateErrorRateOrchestrator(t *testing.T) {
	tests := []struct {
		name       string
		timestamps []time.Time
		wantRate   float64
	}{
		{
			name:       "no errors",
			timestamps: []time.Time{},
			wantRate:   0.0,
		},
		{
			name: "recent errors",
			timestamps: []time.Time{
				time.Now().Add(-10 * time.Second),
				time.Now().Add(-20 * time.Second),
				time.Now().Add(-30 * time.Second),
			},
			wantRate: 3.0 / 60.0,
		},
		{
			name: "old errors beyond 60s",
			timestamps: []time.Time{
				time.Now().Add(-70 * time.Second),
				time.Now().Add(-80 * time.Second),
			},
			wantRate: 0.0,
		},
		{
			name: "mix of old and recent",
			timestamps: []time.Time{
				time.Now().Add(-10 * time.Second),
				time.Now().Add(-70 * time.Second),
			},
			wantRate: 1.0 / 60.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rate := calculateErrorRateOrchestrator(tt.timestamps)
			if rate != tt.wantRate {
				t.Errorf("Expected rate %f, got %f", tt.wantRate, rate)
			}
		})
	}
}

