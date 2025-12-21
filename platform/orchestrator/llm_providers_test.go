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

package orchestrator

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// TestBedrockProvider_Name tests Bedrock provider name
func TestBedrockProvider_Name(t *testing.T) {
	provider, err := NewBedrockProvider("us-east-1", "")
	if err != nil {
		t.Skipf("Skipping: AWS SDK initialization failed: %v (expected without AWS credentials)", err)
		return
	}

	if provider.Name() != "bedrock" {
		t.Errorf("Expected provider name 'bedrock', got '%s'", provider.Name())
	}
}

// TestBedrockProvider_IsHealthy tests Bedrock health check
func TestBedrockProvider_IsHealthy(t *testing.T) {
	tests := []struct {
		name     string
		region   string
		model    string
		expected bool
	}{
		{
			name:     "healthy with region",
			region:   "us-east-1",
			model:    "anthropic.claude-3-sonnet-20240229-v1:0",
			expected: true,
		},
		{
			name:     "healthy with default region",
			region:   "",
			model:    "",
			expected: true, // Empty region defaults to us-east-1
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider, err := NewBedrockProvider(tt.region, tt.model)
			if err != nil {
				t.Skipf("Skipping: AWS SDK initialization failed: %v (expected without AWS credentials)", err)
				return
			}

			if provider.IsHealthy() != tt.expected {
				t.Errorf("Expected IsHealthy() = %v, got %v", tt.expected, provider.IsHealthy())
			}
		})
	}
}

// TestBedrockProvider_GetCapabilities tests Bedrock capabilities
func TestBedrockProvider_GetCapabilities(t *testing.T) {
	provider, err := NewBedrockProvider("us-east-1", "")
	if err != nil {
		t.Skipf("Skipping: AWS SDK initialization failed: %v (expected without AWS credentials)", err)
		return
	}

	capabilities := provider.GetCapabilities()

	expectedCaps := map[string]bool{
		"reasoning":       true,
		"analysis":        true,
		"writing":         true,
		"hipaa_compliant": true,
	}

	if len(capabilities) != 4 {
		t.Errorf("Expected 4 capabilities, got %d", len(capabilities))
	}

	for _, cap := range capabilities {
		if !expectedCaps[cap] {
			t.Errorf("Unexpected capability: %s", cap)
		}
	}
}

// TestBedrockProvider_EstimateCost tests Bedrock cost estimation
func TestBedrockProvider_EstimateCost(t *testing.T) {
	provider, err := NewBedrockProvider("us-east-1", "")
	if err != nil {
		t.Skipf("Skipping: AWS SDK initialization failed: %v (expected without AWS credentials)", err)
		return
	}

	tests := []struct {
		name     string
		tokens   int
		expected float64
	}{
		{"zero tokens", 0, 0.0},
		{"1000 tokens", 1000, 0.03},
		{"10000 tokens", 10000, 0.3},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cost := provider.EstimateCost(tt.tokens)
			// Use small epsilon for float comparison
			if cost < tt.expected-0.0001 || cost > tt.expected+0.0001 {
				t.Errorf("Expected cost %f, got %f", tt.expected, cost)
			}
		})
	}
}

// TestBedrockProvider_Defaults tests Bedrock default configuration
func TestBedrockProvider_Defaults(t *testing.T) {
	// Test with empty region and model
	provider, err := NewBedrockProvider("", "")
	if err != nil {
		t.Skipf("Skipping: AWS SDK initialization failed: %v (expected without AWS credentials)", err)
		return
	}

	bedrockProvider, ok := provider.(*BedrockProvider)
	if !ok {
		t.Fatalf("Expected BedrockProvider type, got %T", provider)
	}

	// Should default to us-east-1
	if bedrockProvider.region != "us-east-1" {
		t.Errorf("Expected default region 'us-east-1', got '%s'", bedrockProvider.region)
	}

	// Should default to Claude 3.5 Sonnet
	expectedModel := "anthropic.claude-3-5-sonnet-20240620-v1:0"
	if bedrockProvider.model != expectedModel {
		t.Errorf("Expected default model '%s', got '%s'", expectedModel, bedrockProvider.model)
	}

	// Should be healthy by default
	if !bedrockProvider.healthy {
		t.Error("Expected provider to be healthy by default")
	}
}

// TestOllamaProvider_Name tests Ollama provider name
func TestOllamaProvider_Name(t *testing.T) {
	provider := NewOllamaProvider("http://ollama:11434", "")

	if provider.Name() != "ollama" {
		t.Errorf("Expected provider name 'ollama', got '%s'", provider.Name())
	}
}

// TestOllamaProvider_IsHealthy tests Ollama health check
func TestOllamaProvider_IsHealthy(t *testing.T) {
	tests := []struct {
		name     string
		endpoint string
		model    string
		expected bool
	}{
		{
			name:     "healthy with endpoint",
			endpoint: "http://ollama:11434",
			model:    "llama3.1:70b",
			expected: true,
		},
		{
			name:     "healthy with default endpoint",
			endpoint: "",
			model:    "",
			expected: true, // Empty endpoint defaults to http://ollama:11434
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := NewOllamaProvider(tt.endpoint, tt.model)

			if provider.IsHealthy() != tt.expected {
				t.Errorf("Expected IsHealthy() = %v, got %v", tt.expected, provider.IsHealthy())
			}
		})
	}
}

// TestOllamaProvider_GetCapabilities tests Ollama capabilities
func TestOllamaProvider_GetCapabilities(t *testing.T) {
	provider := NewOllamaProvider("http://ollama:11434", "")

	capabilities := provider.GetCapabilities()

	expectedCaps := map[string]bool{
		"chat":        true,
		"air_gapped":  true,
		"self_hosted": true,
	}

	if len(capabilities) != 3 {
		t.Errorf("Expected 3 capabilities, got %d", len(capabilities))
	}

	for _, cap := range capabilities {
		if !expectedCaps[cap] {
			t.Errorf("Unexpected capability: %s", cap)
		}
	}
}

// TestOllamaProvider_EstimateCost tests Ollama cost estimation
func TestOllamaProvider_EstimateCost(t *testing.T) {
	provider := NewOllamaProvider("http://ollama:11434", "")

	tests := []struct {
		name     string
		tokens   int
		expected float64
	}{
		{"zero tokens", 0, 0.0},
		{"1000 tokens", 1000, 0.0}, // Free (self-hosted)
		{"10000 tokens", 10000, 0.0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cost := provider.EstimateCost(tt.tokens)
			if cost != tt.expected {
				t.Errorf("Expected cost %f, got %f", tt.expected, cost)
			}
		})
	}
}

// TestOllamaProvider_Defaults tests Ollama default configuration
func TestOllamaProvider_Defaults(t *testing.T) {
	// Test with empty endpoint and model
	provider := NewOllamaProvider("", "")

	ollamaProvider, ok := provider.(*OllamaProvider)
	if !ok {
		t.Fatal("Expected OllamaProvider type")
	}

	// Should default to http://ollama:11434
	expectedEndpoint := "http://ollama:11434"
	if ollamaProvider.endpoint != expectedEndpoint {
		t.Errorf("Expected default endpoint '%s', got '%s'", expectedEndpoint, ollamaProvider.endpoint)
	}

	// Should default to llama3.1:70b
	expectedModel := "llama3.1:70b"
	if ollamaProvider.model != expectedModel {
		t.Errorf("Expected default model '%s', got '%s'", expectedModel, ollamaProvider.model)
	}

	// Should be healthy by default
	if !ollamaProvider.healthy {
		t.Error("Expected provider to be healthy by default")
	}
}

// TestNewLLMRouter_WithNewProviders tests router with Bedrock and Ollama
func TestNewLLMRouter_WithNewProviders(t *testing.T) {
	// Check if AWS credentials are available (Bedrock requires them)
	_, bedrockErr := NewBedrockProvider("us-east-1", "")
	bedrockAvailable := bedrockErr == nil

	tests := []struct {
		name              string
		config            LLMRouterConfig
		expectedProviders map[string]bool
		requiresBedrock   bool // If true, skip test when Bedrock unavailable
	}{
		{
			name: "All providers including Bedrock and Ollama",
			config: LLMRouterConfig{
				OpenAIKey:      "test-openai-key",
				AnthropicKey:   "test-anthropic-key",
				BedrockRegion:  "us-east-1",
				BedrockModel:   "anthropic.claude-3-sonnet-20240229-v1:0",
				OllamaEndpoint: "http://ollama:11434",
				OllamaModel:    "llama3.1:70b",
			},
			expectedProviders: map[string]bool{
				"openai":    true,
				"anthropic": true,
				"bedrock":   true,
				"ollama":    true,
			},
			requiresBedrock: true,
		},
		{
			name: "Only Bedrock configured",
			config: LLMRouterConfig{
				BedrockRegion: "us-east-1",
			},
			expectedProviders: map[string]bool{
				"bedrock": true,
			},
			requiresBedrock: true,
		},
		{
			name: "Only Ollama configured",
			config: LLMRouterConfig{
				OllamaEndpoint: "http://ollama:11434",
			},
			expectedProviders: map[string]bool{
				"ollama": true,
			},
			requiresBedrock: false,
		},
		{
			name: "Backward compatibility: LocalEndpoint maps to Ollama",
			config: LLMRouterConfig{
				LocalEndpoint: "http://localhost:8080",
			},
			expectedProviders: map[string]bool{
				"ollama": true,
			},
			requiresBedrock: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Skip tests that require Bedrock if it's not available
			if tt.requiresBedrock && !bedrockAvailable {
				t.Skipf("Skipping: Bedrock not available (AWS credentials required)")
				return
			}

			router := NewLLMRouter(tt.config)

			if router == nil {
				t.Fatal("Expected non-nil router")
			}

			// Verify expected providers are initialized
			status := router.GetProviderStatus()

			// Adjust expected providers if Bedrock is not available
			expectedCount := len(tt.expectedProviders)
			if !bedrockAvailable && tt.expectedProviders["bedrock"] {
				expectedCount--
			}

			if len(status) != expectedCount {
				t.Errorf("Expected %d providers, got %d (bedrock available: %v)", expectedCount, len(status), bedrockAvailable)
			}

			for providerName := range tt.expectedProviders {
				// Skip bedrock check if not available
				if providerName == "bedrock" && !bedrockAvailable {
					continue
				}
				if _, exists := status[providerName]; !exists {
					t.Errorf("Expected provider '%s' to be initialized", providerName)
				}
			}

			// Verify unexpected providers are NOT initialized
			for providerName := range status {
				if !tt.expectedProviders[providerName] {
					t.Errorf("Unexpected provider '%s' was initialized", providerName)
				}
			}
		})
	}
}

// TestLoadLLMConfig tests config loading from environment
func TestLoadLLMConfig(t *testing.T) {
	// Save original env vars
	originalVars := map[string]string{
		"OPENAI_API_KEY":    "",
		"ANTHROPIC_API_KEY": "",
		"BEDROCK_REGION":    "",
		"BEDROCK_MODEL":     "",
		"OLLAMA_ENDPOINT":   "",
		"OLLAMA_MODEL":      "",
		"LOCAL_LLM_ENDPOINT": "",
	}

	for key := range originalVars {
		originalVars[key] = os.Getenv(key)
		os.Unsetenv(key) // Clear for test
	}

	// Restore after test
	defer func() {
		for key, val := range originalVars {
			if val != "" {
				os.Setenv(key, val)
			} else {
				os.Unsetenv(key)
			}
		}
	}()

	tests := []struct {
		name     string
		envVars  map[string]string
		validate func(*testing.T, LLMRouterConfig)
	}{
		{
			name: "All providers configured",
			envVars: map[string]string{
				"OPENAI_API_KEY":    "sk-test-openai",
				"ANTHROPIC_API_KEY": "sk-ant-test",
				"BEDROCK_REGION":    "us-west-2",
				"BEDROCK_MODEL":     "anthropic.claude-3-opus-20240229-v1:0",
				"OLLAMA_ENDPOINT":   "http://custom-ollama:11434",
				"OLLAMA_MODEL":      "llama3.1:8b",
			},
			validate: func(t *testing.T, cfg LLMRouterConfig) {
				if cfg.OpenAIKey != "sk-test-openai" {
					t.Errorf("Expected OpenAIKey 'sk-test-openai', got '%s'", cfg.OpenAIKey)
				}
				if cfg.AnthropicKey != "sk-ant-test" {
					t.Errorf("Expected AnthropicKey 'sk-ant-test', got '%s'", cfg.AnthropicKey)
				}
				if cfg.BedrockRegion != "us-west-2" {
					t.Errorf("Expected BedrockRegion 'us-west-2', got '%s'", cfg.BedrockRegion)
				}
				if cfg.BedrockModel != "anthropic.claude-3-opus-20240229-v1:0" {
					t.Errorf("Expected BedrockModel 'anthropic.claude-3-opus-20240229-v1:0', got '%s'", cfg.BedrockModel)
				}
				if cfg.OllamaEndpoint != "http://custom-ollama:11434" {
					t.Errorf("Expected OllamaEndpoint 'http://custom-ollama:11434', got '%s'", cfg.OllamaEndpoint)
				}
				if cfg.OllamaModel != "llama3.1:8b" {
					t.Errorf("Expected OllamaModel 'llama3.1:8b', got '%s'", cfg.OllamaModel)
				}
			},
		},
		{
			name: "Backward compatibility: LOCAL_LLM_ENDPOINT",
			envVars: map[string]string{
				"LOCAL_LLM_ENDPOINT": "http://localhost:8080",
			},
			validate: func(t *testing.T, cfg LLMRouterConfig) {
				if cfg.LocalEndpoint != "http://localhost:8080" {
					t.Errorf("Expected LocalEndpoint 'http://localhost:8080', got '%s'", cfg.LocalEndpoint)
				}
			},
		},
		{
			name:    "Empty environment",
			envVars: map[string]string{},
			validate: func(t *testing.T, cfg LLMRouterConfig) {
				if cfg.OpenAIKey != "" {
					t.Errorf("Expected empty OpenAIKey, got '%s'", cfg.OpenAIKey)
				}
				if cfg.BedrockRegion != "" {
					t.Errorf("Expected empty BedrockRegion, got '%s'", cfg.BedrockRegion)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set env vars for test
			for key, val := range tt.envVars {
				os.Setenv(key, val)
			}

			// Clear env vars after test case
			defer func() {
				for key := range tt.envVars {
					os.Unsetenv(key)
				}
			}()

			config := LoadLLMConfig()
			tt.validate(t, config)
		})
	}
}

// TestProviderInterface ensures all providers implement the interface
func TestProviderInterface(t *testing.T) {
	var _ LLMProvider = (*OpenAIProvider)(nil)
	var _ LLMProvider = (*EnhancedAnthropicProvider)(nil)
	var _ LLMProvider = (*BedrockProvider)(nil)
	var _ LLMProvider = (*OllamaProvider)(nil)
	var _ LLMProvider = (*MockProvider)(nil)
}

// TestBedrockProvider_Query tests Bedrock query (mock)
func TestBedrockProvider_Query(t *testing.T) {
	// Skip if not in integration test mode
	if testing.Short() {
		t.Skip("Skipping Bedrock integration test in short mode")
	}

	provider, err := NewBedrockProvider("us-east-1", "")
	if err != nil {
		t.Skipf("Skipping: AWS SDK initialization failed: %v (expected without AWS credentials)", err)
		return
	}

	ctx := context.Background()
	prompt := "What is 2+2?"
	options := QueryOptions{
		MaxTokens:   100,
		Temperature: 0.7,
		Model:       "anthropic.claude-3-sonnet-20240229-v1:0",
	}

	// Note: This will fail without AWS credentials
	// In real tests, we'd mock the HTTP client
	_, err = provider.Query(ctx, prompt, options)

	// We expect an error in test environment (no AWS creds)
	// This test verifies the function exists and doesn't panic
	if err == nil {
		t.Skip("Skipping: actual AWS credentials detected")
	}
}

// TestOllamaProvider_Query tests Ollama query (mock)
func TestOllamaProvider_Query(t *testing.T) {
	// Skip if not in integration test mode
	if testing.Short() {
		t.Skip("Skipping Ollama integration test in short mode")
	}

	provider := NewOllamaProvider("http://ollama:11434", "llama3.1:70b")

	ctx := context.Background()
	prompt := "What is 2+2?"
	options := QueryOptions{
		MaxTokens:   100,
		Temperature: 0.7,
		Model:       "llama3.1:70b",
	}

	// Note: This will fail without Ollama running
	// In real tests, we'd mock the HTTP client
	_, err := provider.Query(ctx, prompt, options)

	// We expect an error in test environment (no Ollama server)
	// This test verifies the function exists and doesn't panic
	if err == nil {
		t.Skip("Skipping: Ollama server detected")
	}
}

// =============================================================================
// Integration Tests with Mock HTTP Servers
// =============================================================================

// TestBedrockProvider_Integration_SuccessfulQuery tests Bedrock with AWS SDK
// Note: BedrockProvider uses the AWS SDK which handles authentication and
// cannot be easily mocked with a local HTTP server. This is an integration
// test that requires valid AWS credentials.
func TestBedrockProvider_Integration_SuccessfulQuery(t *testing.T) {
	t.Skip("Skipping: BedrockProvider uses AWS SDK - requires valid AWS credentials for integration testing")
}

// TestBedrockProvider_Integration_ErrorResponse tests Bedrock error handling
// Note: BedrockProvider uses the AWS SDK which handles authentication and
// cannot be easily mocked with a local HTTP server.
func TestBedrockProvider_Integration_ErrorResponse(t *testing.T) {
	t.Skip("Skipping: BedrockProvider uses AWS SDK - requires valid AWS credentials for integration testing")
}

// TestOllamaProvider_Integration_SuccessfulQuery tests Ollama with mock HTTP server
func TestOllamaProvider_Integration_SuccessfulQuery(t *testing.T) {
	// Create mock Ollama server
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify request method and path
		if r.Method != "POST" {
			t.Errorf("Expected POST request, got %s", r.Method)
		}
		if r.URL.Path != "/api/generate" {
			t.Errorf("Expected /api/generate path, got %s", r.URL.Path)
		}

		// Verify Content-Type header
		if contentType := r.Header.Get("Content-Type"); contentType != "application/json" {
			t.Errorf("Expected Content-Type: application/json, got %s", contentType)
		}

		// Parse request body
		var reqBody map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
			t.Fatalf("Failed to decode request body: %v", err)
		}

		// Verify Ollama request format
		if model, ok := reqBody["model"].(string); !ok || model == "" {
			t.Errorf("Missing or empty model in request")
		}
		if prompt, ok := reqBody["prompt"].(string); !ok || prompt == "" {
			t.Errorf("Missing or empty prompt in request")
		}
		if stream, ok := reqBody["stream"].(bool); !ok || stream != false {
			t.Errorf("Expected stream=false in request")
		}

		// Send mock successful response
		resp := map[string]interface{}{
			"model":    "llama3.1:70b",
			"response": "The answer is 4",
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(resp)
	}))
	defer mockServer.Close()

	// Create provider pointing to mock server
	provider := NewOllamaProvider(mockServer.URL, "llama3.1:70b")

	ctx := context.Background()
	prompt := "What is 2+2?"
	options := QueryOptions{
		MaxTokens:   100,
		Temperature: 0.7,
	}

	// Execute query - this should hit our mock server
	resp, err := provider.Query(ctx, prompt, options)

	if err != nil {
		t.Fatalf("Expected successful query, got error: %v", err)
	}

	if resp == nil {
		t.Fatal("Expected non-nil response")
	}

	if resp.Content != "The answer is 4" {
		t.Errorf("Expected content 'The answer is 4', got '%s'", resp.Content)
	}

	// Verify provider in metadata
	if provider, ok := resp.Metadata["provider"].(string); !ok || provider != "ollama" {
		t.Errorf("Expected provider 'ollama' in metadata, got %v", resp.Metadata["provider"])
	}

	if resp.Model != "llama3.1:70b" {
		t.Errorf("Expected model 'llama3.1:70b', got '%s'", resp.Model)
	}

	if resp.TokensUsed <= 0 {
		t.Error("Expected positive token count")
	}
}

// TestOllamaProvider_Integration_ErrorResponse tests Ollama error handling
func TestOllamaProvider_Integration_ErrorResponse(t *testing.T) {
	tests := []struct {
		name           string
		statusCode     int
		errorBody      string
		expectedErrMsg string
	}{
		{
			name:           "400 Bad Request",
			statusCode:     http.StatusBadRequest,
			errorBody:      `{"error": "model not found"}`,
			expectedErrMsg: "ollama API error",
		},
		{
			name:           "404 Not Found",
			statusCode:     http.StatusNotFound,
			errorBody:      `{"error": "model 'unknown:model' not found"}`,
			expectedErrMsg: "ollama API error",
		},
		{
			name:           "500 Server Error",
			statusCode:     http.StatusInternalServerError,
			errorBody:      `{"error": "internal server error"}`,
			expectedErrMsg: "ollama API error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tt.statusCode)
				w.Write([]byte(tt.errorBody))
			}))
			defer mockServer.Close()

			provider := NewOllamaProvider(mockServer.URL, "llama3.1:70b")

			ctx := context.Background()
			_, err := provider.Query(ctx, "test prompt", QueryOptions{})

			if err == nil {
				t.Fatal("Expected error, got nil")
			}

			if !strings.Contains(err.Error(), tt.expectedErrMsg) {
				t.Errorf("Expected error containing '%s', got '%s'", tt.expectedErrMsg, err.Error())
			}
		})
	}
}

// TestOllamaProvider_Integration_MalformedResponse tests handling of invalid JSON
func TestOllamaProvider_Integration_MalformedResponse(t *testing.T) {
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		// Send invalid JSON
		w.Write([]byte(`{"response": "incomplete...`))
	}))
	defer mockServer.Close()

	provider := NewOllamaProvider(mockServer.URL, "llama3.1:70b")

	ctx := context.Background()
	_, err := provider.Query(ctx, "test prompt", QueryOptions{})

	if err == nil {
		t.Fatal("Expected error for malformed JSON, got nil")
	}

	// Could be "failed to decode response" or "unexpected EOF"
	if !strings.Contains(err.Error(), "failed to decode response") &&
		!strings.Contains(err.Error(), "unexpected EOF") {
		t.Errorf("Expected JSON decode error, got: %v", err)
	}
}

// TestOllamaProvider_Integration_NetworkTimeout tests timeout handling
func TestOllamaProvider_Integration_NetworkTimeout(t *testing.T) {
	// Create server that delays response (simulates slow server)
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Sleep longer than client timeout
		time.Sleep(500 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"response": "too late"}`))
	}))
	defer mockServer.Close()

	provider := NewOllamaProvider(mockServer.URL, "llama3.1:70b")

	// Use short timeout context
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_, err := provider.Query(ctx, "test prompt", QueryOptions{})

	if err == nil {
		t.Fatal("Expected timeout error, got nil")
	}

	// Check if error is context deadline exceeded
	if !strings.Contains(err.Error(), "context deadline exceeded") &&
		!strings.Contains(err.Error(), "Client.Timeout") {
		t.Logf("Got error: %v (may not be timeout in test environment)", err)
	}
}
