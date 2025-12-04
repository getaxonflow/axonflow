package axonflow

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestNewClient tests client initialization
func TestNewClient(t *testing.T) {
	client := NewClient(AxonFlowConfig{
		AgentURL:     "http://localhost:8080",
		ClientID:     "test-client",
		ClientSecret: "test-secret",
	})

	if client == nil {
		t.Fatal("Expected client to be created")
	}
	if client.config.AgentURL != "http://localhost:8080" {
		t.Errorf("Expected AgentURL 'http://localhost:8080', got '%s'", client.config.AgentURL)
	}
	if client.config.Mode != "production" {
		t.Errorf("Expected default mode 'production', got '%s'", client.config.Mode)
	}
	if client.config.Timeout != 60*time.Second {
		t.Errorf("Expected default timeout 60s, got '%v'", client.config.Timeout)
	}
}

// TestNewClientSimple tests simple client initialization
func TestNewClientSimple(t *testing.T) {
	client := NewClientSimple("http://localhost:8080", "test-client", "test-secret")

	if client == nil {
		t.Fatal("Expected client to be created")
	}
	if client.config.ClientID != "test-client" {
		t.Errorf("Expected ClientID 'test-client', got '%s'", client.config.ClientID)
	}
}

// TestSandbox tests sandbox client creation
func TestSandbox(t *testing.T) {
	client := Sandbox("my-api-key")

	if client == nil {
		t.Fatal("Expected client to be created")
	}
	if client.config.Mode != "sandbox" {
		t.Errorf("Expected mode 'sandbox', got '%s'", client.config.Mode)
	}
	if !client.config.Debug {
		t.Error("Expected debug mode to be enabled in sandbox")
	}
}

// TestGetPolicyApprovedContext tests the gateway mode pre-check method
func TestGetPolicyApprovedContext(t *testing.T) {
	// Create mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify request
		if r.Method != "POST" {
			t.Errorf("Expected POST method, got %s", r.Method)
		}
		if r.URL.Path != "/api/policy/pre-check" {
			t.Errorf("Expected path '/api/policy/pre-check', got '%s'", r.URL.Path)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("Expected Content-Type 'application/json', got '%s'", r.Header.Get("Content-Type"))
		}
		if r.Header.Get("X-License-Key") != "test-license" {
			t.Errorf("Expected X-License-Key 'test-license', got '%s'", r.Header.Get("X-License-Key"))
		}

		// Parse request body
		var reqBody map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
			t.Errorf("Failed to parse request body: %v", err)
		}

		if reqBody["query"] != "Find patients with diabetes" {
			t.Errorf("Expected query 'Find patients with diabetes', got '%v'", reqBody["query"])
		}

		// Send response
		resp := map[string]interface{}{
			"context_id": "ctx-123",
			"approved":   true,
			"policies":   []string{"hipaa-compliance"},
			"expires_at": time.Now().Add(5 * time.Minute).Format(time.RFC3339),
			"approved_data": map[string]interface{}{
				"patients": []map[string]interface{}{
					{"id": 1, "name": "John Doe"},
				},
			},
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	// Create client
	client := NewClient(AxonFlowConfig{
		AgentURL:     server.URL,
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		LicenseKey:   "test-license",
	})

	// Test GetPolicyApprovedContext
	result, err := client.GetPolicyApprovedContext(
		"user-token",
		[]string{"postgres"},
		"Find patients with diabetes",
		nil,
	)

	if err != nil {
		t.Fatalf("GetPolicyApprovedContext failed: %v", err)
	}
	if result.ContextID != "ctx-123" {
		t.Errorf("Expected ContextID 'ctx-123', got '%s'", result.ContextID)
	}
	if !result.Approved {
		t.Error("Expected request to be approved")
	}
	if len(result.Policies) != 1 || result.Policies[0] != "hipaa-compliance" {
		t.Errorf("Unexpected policies: %v", result.Policies)
	}
	if result.ApprovedData == nil {
		t.Error("Expected approved data to be returned")
	}
}

// TestGetPolicyApprovedContext_Blocked tests blocked request handling
func TestGetPolicyApprovedContext_Blocked(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]interface{}{
			"context_id":   "ctx-456",
			"approved":     false,
			"policies":     []string{"sql-injection-prevention"},
			"block_reason": "SQL injection detected",
			"expires_at":   time.Now().Add(5 * time.Minute).Format(time.RFC3339),
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		AgentURL:     server.URL,
		ClientID:     "test-client",
		ClientSecret: "test-secret",
	})

	result, err := client.GetPolicyApprovedContext(
		"user-token",
		nil,
		"SELECT * FROM users UNION SELECT * FROM passwords",
		nil,
	)

	if err != nil {
		t.Fatalf("GetPolicyApprovedContext failed: %v", err)
	}
	if result.Approved {
		t.Error("Expected request to be blocked")
	}
	if result.BlockReason != "SQL injection detected" {
		t.Errorf("Expected block reason 'SQL injection detected', got '%s'", result.BlockReason)
	}
}

// TestGetPolicyApprovedContext_ServerError tests server error handling
func TestGetPolicyApprovedContext_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Internal server error"))
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		AgentURL:     server.URL,
		ClientID:     "test-client",
		ClientSecret: "test-secret",
	})

	_, err := client.GetPolicyApprovedContext(
		"user-token",
		nil,
		"test query",
		nil,
	)

	if err == nil {
		t.Error("Expected error for server error response")
	}
}

// TestAuditLLMCall tests the gateway mode audit method
func TestAuditLLMCall(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify request
		if r.Method != "POST" {
			t.Errorf("Expected POST method, got %s", r.Method)
		}
		if r.URL.Path != "/api/audit/llm-call" {
			t.Errorf("Expected path '/api/audit/llm-call', got '%s'", r.URL.Path)
		}

		// Parse request body
		var reqBody map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
			t.Errorf("Failed to parse request body: %v", err)
		}

		if reqBody["context_id"] != "ctx-123" {
			t.Errorf("Expected context_id 'ctx-123', got '%v'", reqBody["context_id"])
		}
		if reqBody["provider"] != "openai" {
			t.Errorf("Expected provider 'openai', got '%v'", reqBody["provider"])
		}
		if reqBody["model"] != "gpt-4" {
			t.Errorf("Expected model 'gpt-4', got '%v'", reqBody["model"])
		}

		tokenUsage := reqBody["token_usage"].(map[string]interface{})
		if tokenUsage["total_tokens"].(float64) != 150 {
			t.Errorf("Expected total_tokens 150, got %v", tokenUsage["total_tokens"])
		}

		// Send response
		resp := map[string]interface{}{
			"success":  true,
			"audit_id": "audit-789",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		AgentURL:     server.URL,
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		LicenseKey:   "test-license",
	})

	result, err := client.AuditLLMCall(
		"ctx-123",
		"Found 5 patients with diabetes",
		"openai",
		"gpt-4",
		TokenUsage{
			PromptTokens:     100,
			CompletionTokens: 50,
			TotalTokens:      150,
		},
		250,
		map[string]interface{}{
			"session_id": "session-123",
		},
	)

	if err != nil {
		t.Fatalf("AuditLLMCall failed: %v", err)
	}
	if !result.Success {
		t.Error("Expected audit to succeed")
	}
	if result.AuditID != "audit-789" {
		t.Errorf("Expected AuditID 'audit-789', got '%s'", result.AuditID)
	}
}

// TestAuditLLMCall_ServerError tests server error handling
func TestAuditLLMCall_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("Internal server error"))
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		AgentURL:     server.URL,
		ClientID:     "test-client",
		ClientSecret: "test-secret",
	})

	_, err := client.AuditLLMCall(
		"ctx-123",
		"summary",
		"openai",
		"gpt-4",
		TokenUsage{TotalTokens: 100},
		100,
		nil,
	)

	if err == nil {
		t.Error("Expected error for server error response")
	}
}

// TestTokenUsage tests TokenUsage struct
func TestTokenUsage(t *testing.T) {
	usage := TokenUsage{
		PromptTokens:     100,
		CompletionTokens: 50,
		TotalTokens:      150,
	}

	if usage.PromptTokens != 100 {
		t.Errorf("Expected PromptTokens 100, got %d", usage.PromptTokens)
	}
	if usage.CompletionTokens != 50 {
		t.Errorf("Expected CompletionTokens 50, got %d", usage.CompletionTokens)
	}
	if usage.TotalTokens != 150 {
		t.Errorf("Expected TotalTokens 150, got %d", usage.TotalTokens)
	}
}

// TestRateLimitInfo tests RateLimitInfo struct
func TestRateLimitInfo(t *testing.T) {
	info := RateLimitInfo{
		Limit:     100,
		Remaining: 50,
		ResetAt:   time.Now().Add(time.Hour),
	}

	if info.Limit != 100 {
		t.Errorf("Expected Limit 100, got %d", info.Limit)
	}
	if info.Remaining != 50 {
		t.Errorf("Expected Remaining 50, got %d", info.Remaining)
	}
}

// TestPolicyApprovalResult tests PolicyApprovalResult struct
func TestPolicyApprovalResult(t *testing.T) {
	result := PolicyApprovalResult{
		ContextID:    "ctx-123",
		Approved:     true,
		Policies:     []string{"policy1", "policy2"},
		ExpiresAt:    time.Now().Add(5 * time.Minute),
		ApprovedData: map[string]interface{}{"key": "value"},
	}

	if result.ContextID != "ctx-123" {
		t.Errorf("Expected ContextID 'ctx-123', got '%s'", result.ContextID)
	}
	if !result.Approved {
		t.Error("Expected Approved to be true")
	}
	if len(result.Policies) != 2 {
		t.Errorf("Expected 2 policies, got %d", len(result.Policies))
	}
}

// TestAuditResult tests AuditResult struct
func TestAuditResult(t *testing.T) {
	result := AuditResult{
		Success: true,
		AuditID: "audit-123",
	}

	if !result.Success {
		t.Error("Expected Success to be true")
	}
	if result.AuditID != "audit-123" {
		t.Errorf("Expected AuditID 'audit-123', got '%s'", result.AuditID)
	}
}

// TestHealthCheck tests the health check method
func TestHealthCheck(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/health" {
			t.Errorf("Expected path '/health', got '%s'", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"healthy"}`))
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		AgentURL:     server.URL,
		ClientID:     "test-client",
		ClientSecret: "test-secret",
	})

	err := client.HealthCheck()
	if err != nil {
		t.Errorf("HealthCheck failed: %v", err)
	}
}

// TestHealthCheck_Unhealthy tests unhealthy status
func TestHealthCheck_Unhealthy(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		AgentURL:     server.URL,
		ClientID:     "test-client",
		ClientSecret: "test-secret",
	})

	err := client.HealthCheck()
	if err == nil {
		t.Error("Expected error for unhealthy status")
	}
}

// TestCache tests the caching functionality
func TestCache(t *testing.T) {
	c := newCache(100 * time.Millisecond)

	// Test set and get
	c.set("key1", "value1")
	val, found := c.get("key1")
	if !found {
		t.Error("Expected to find cached value")
	}
	if val != "value1" {
		t.Errorf("Expected 'value1', got '%v'", val)
	}

	// Test missing key
	_, found = c.get("missing")
	if found {
		t.Error("Expected not to find missing key")
	}

	// Test expiration
	time.Sleep(150 * time.Millisecond)
	_, found = c.get("key1")
	if found {
		t.Error("Expected cached value to be expired")
	}
}

// BenchmarkGetPolicyApprovedContext benchmarks pre-check
func BenchmarkGetPolicyApprovedContext(b *testing.B) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]interface{}{
			"context_id": "ctx-123",
			"approved":   true,
			"policies":   []string{},
			"expires_at": time.Now().Add(5 * time.Minute).Format(time.RFC3339),
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		AgentURL:     server.URL,
		ClientID:     "test-client",
		ClientSecret: "test-secret",
	})

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		client.GetPolicyApprovedContext("token", nil, "test query", nil)
	}
}

// BenchmarkAuditLLMCall benchmarks audit
func BenchmarkAuditLLMCall(b *testing.B) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]interface{}{
			"success":  true,
			"audit_id": "audit-123",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		AgentURL:     server.URL,
		ClientID:     "test-client",
		ClientSecret: "test-secret",
	})

	usage := TokenUsage{TotalTokens: 100}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		client.AuditLLMCall("ctx-123", "summary", "openai", "gpt-4", usage, 100, nil)
	}
}

// TestExecuteQuery tests the main query execution
func TestExecuteQuery(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/request" {
			t.Errorf("Expected path '/api/request', got '%s'", r.URL.Path)
		}
		if r.Header.Get("X-Client-Secret") != "test-secret" {
			t.Errorf("Expected X-Client-Secret 'test-secret', got '%s'", r.Header.Get("X-Client-Secret"))
		}

		var reqBody map[string]interface{}
		json.NewDecoder(r.Body).Decode(&reqBody)

		resp := ClientResponse{
			Success: true,
			Data:    "Paris is the capital of France",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		AgentURL:     server.URL,
		ClientID:     "test-client",
		ClientSecret: "test-secret",
	})

	result, err := client.ExecuteQuery("user-token", "What is the capital of France?", "chat", nil)
	if err != nil {
		t.Fatalf("ExecuteQuery failed: %v", err)
	}
	if !result.Success {
		t.Error("Expected success")
	}
}

// TestExecuteQuery_Blocked tests blocked request handling
func TestExecuteQuery_Blocked(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := ClientResponse{
			Success:     false,
			Blocked:     true,
			BlockReason: "PII detected",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		AgentURL:     server.URL,
		ClientID:     "test-client",
		ClientSecret: "test-secret",
	})

	result, err := client.ExecuteQuery("user-token", "SSN: 123-45-6789", "chat", nil)
	if err != nil {
		t.Fatalf("ExecuteQuery failed: %v", err)
	}
	if !result.Blocked {
		t.Error("Expected request to be blocked")
	}
	if result.BlockReason != "PII detected" {
		t.Errorf("Expected block reason 'PII detected', got '%s'", result.BlockReason)
	}
}

// TestExecuteQuery_FailOpen tests fail-open behavior in production mode
func TestExecuteQuery_FailOpen(t *testing.T) {
	// Server that always fails
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte("AxonFlow unavailable"))
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		AgentURL:     server.URL,
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		Mode:         "production",
		Retry: RetryConfig{
			Enabled:      true,
			MaxAttempts:  1, // Single attempt for faster test
			InitialDelay: 1 * time.Millisecond,
		},
	})

	result, err := client.ExecuteQuery("user-token", "test query", "chat", nil)
	// Should not return error in production mode (fail-open)
	if err != nil {
		t.Fatalf("Expected fail-open, got error: %v", err)
	}
	if !result.Success {
		t.Error("Expected success in fail-open mode")
	}
	if result.Error == "" {
		t.Error("Expected warning message in fail-open mode")
	}
}

// TestExecuteQuery_CacheHit tests caching functionality
func TestExecuteQuery_CacheHit(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		resp := ClientResponse{
			Success: true,
			Data:    "cached response",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		AgentURL:     server.URL,
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		Cache: CacheConfig{
			Enabled: true,
			TTL:     5 * time.Second,
		},
	})

	// First call
	result1, _ := client.ExecuteQuery("user-token", "test query", "chat", nil)
	// Second call (should hit cache)
	result2, _ := client.ExecuteQuery("user-token", "test query", "chat", nil)

	if callCount != 1 {
		t.Errorf("Expected 1 server call (cache hit), got %d", callCount)
	}
	if result1.Data != result2.Data {
		t.Error("Cache should return same response")
	}
}

// TestListConnectors tests listing connectors
func TestListConnectors(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/connectors" {
			t.Errorf("Expected path '/api/connectors', got '%s'", r.URL.Path)
		}
		connectors := []ConnectorMetadata{
			{ID: "postgres", Name: "PostgreSQL", Type: "database"},
			{ID: "redis", Name: "Redis", Type: "cache"},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(connectors)
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		AgentURL:     server.URL,
		ClientID:     "test-client",
		ClientSecret: "test-secret",
	})

	connectors, err := client.ListConnectors()
	if err != nil {
		t.Fatalf("ListConnectors failed: %v", err)
	}
	if len(connectors) != 2 {
		t.Errorf("Expected 2 connectors, got %d", len(connectors))
	}
}

// TestInstallConnector tests installing a connector
func TestInstallConnector(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/connectors/install" {
			t.Errorf("Expected path '/api/connectors/install', got '%s'", r.URL.Path)
		}
		if r.Method != "POST" {
			t.Errorf("Expected POST, got %s", r.Method)
		}
		w.WriteHeader(http.StatusCreated)
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		AgentURL:     server.URL,
		ClientID:     "test-client",
		ClientSecret: "test-secret",
	})

	err := client.InstallConnector(ConnectorInstallRequest{
		ConnectorID: "postgres",
		Name:        "my-postgres",
		TenantID:    "tenant-1",
	})
	if err != nil {
		t.Fatalf("InstallConnector failed: %v", err)
	}
}

// TestQueryConnector tests querying a connector
func TestQueryConnector(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/mcp/resources/query" {
			t.Errorf("Expected path '/mcp/resources/query', got '%s'", r.URL.Path)
		}
		resp := map[string]interface{}{
			"success": true,
			"data":    []map[string]interface{}{{"id": 1, "name": "test"}},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		AgentURL:     server.URL,
		ClientID:     "test-client",
		ClientSecret: "test-secret",
	})

	result, err := client.QueryConnector("user-token", "postgres", "query", map[string]interface{}{"sql": "SELECT * FROM users"})
	if err != nil {
		t.Fatalf("QueryConnector failed: %v", err)
	}
	if !result.Success {
		t.Error("Expected success")
	}
}

// TestGeneratePlan tests plan generation
func TestGeneratePlan(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := ClientResponse{
			Success: true,
			PlanID:  "plan-123",
			Data: map[string]interface{}{
				"steps": []map[string]interface{}{
					{"id": "step-1", "name": "Search flights", "type": "search"},
				},
				"domain":     "travel",
				"complexity": 2,
				"parallel":   false,
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		AgentURL:     server.URL,
		ClientID:     "test-client",
		ClientSecret: "test-secret",
	})

	plan, err := client.GeneratePlan("Book a flight to Paris", "travel")
	if err != nil {
		t.Fatalf("GeneratePlan failed: %v", err)
	}
	if plan.PlanID != "plan-123" {
		t.Errorf("Expected PlanID 'plan-123', got '%s'", plan.PlanID)
	}
}

// TestExecutePlan tests plan execution
func TestExecutePlan(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := ClientResponse{
			Success: true,
			Result:  "Flight booked successfully",
			Metadata: map[string]interface{}{
				"duration": "5s",
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		AgentURL:     server.URL,
		ClientID:     "test-client",
		ClientSecret: "test-secret",
	})

	result, err := client.ExecutePlan("plan-123")
	if err != nil {
		t.Fatalf("ExecutePlan failed: %v", err)
	}
	if result.Status != "completed" {
		t.Errorf("Expected status 'completed', got '%s'", result.Status)
	}
	if result.Result != "Flight booked successfully" {
		t.Errorf("Expected result 'Flight booked successfully', got '%s'", result.Result)
	}
}

// TestGetPlanStatus tests getting plan status
func TestGetPlanStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/plans/plan-123" {
			t.Errorf("Expected path '/api/plans/plan-123', got '%s'", r.URL.Path)
		}
		resp := PlanExecutionResponse{
			PlanID: "plan-123",
			Status: "running",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		AgentURL:     server.URL,
		ClientID:     "test-client",
		ClientSecret: "test-secret",
	})

	status, err := client.GetPlanStatus("plan-123")
	if err != nil {
		t.Fatalf("GetPlanStatus failed: %v", err)
	}
	if status.Status != "running" {
		t.Errorf("Expected status 'running', got '%s'", status.Status)
	}
}

// TestHttpError tests HTTP error type
func TestHttpError(t *testing.T) {
	err := &httpError{statusCode: 500, message: "Internal error"}
	expected := "HTTP 500: Internal error"
	if err.Error() != expected {
		t.Errorf("Expected '%s', got '%s'", expected, err.Error())
	}
}

// TestHelperFunctions tests helper functions
func TestHelperFunctions(t *testing.T) {
	// Test min
	if min(5, 10) != 5 {
		t.Error("min(5, 10) should be 5")
	}
	if min(10, 5) != 5 {
		t.Error("min(10, 5) should be 5")
	}

	// Test contains
	if !contains("hello world", "world") {
		t.Error("'hello world' should contain 'world'")
	}
	if contains("hello", "world") {
		t.Error("'hello' should not contain 'world'")
	}
	if contains("", "test") {
		t.Error("empty string should not contain 'test'")
	}
	if contains("test", "") {
		t.Error("'test' should not contain empty string (edge case)")
	}

	// Test getBool, getString, getMap
	m := map[string]interface{}{
		"bool_val":   true,
		"string_val": "test",
		"map_val":    map[string]interface{}{"nested": "value"},
	}

	if !getBool(m, "bool_val") {
		t.Error("getBool should return true")
	}
	if getBool(m, "missing") {
		t.Error("getBool should return false for missing key")
	}

	if getString(m, "string_val") != "test" {
		t.Error("getString should return 'test'")
	}
	if getString(m, "missing") != "" {
		t.Error("getString should return empty for missing key")
	}

	nested := getMap(m, "map_val")
	if nested == nil || nested["nested"] != "value" {
		t.Error("getMap should return nested map")
	}
	if getMap(m, "missing") != nil {
		t.Error("getMap should return nil for missing key")
	}
}

// TestSandboxEmptyKey tests sandbox with empty key
func TestSandboxEmptyKey(t *testing.T) {
	client := Sandbox("")
	if client.config.ClientID != "demo-key" {
		t.Errorf("Expected default 'demo-key', got '%s'", client.config.ClientID)
	}
}

// TestRetryLogic tests retry with exponential backoff
func TestRetryLogic(t *testing.T) {
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts < 2 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		resp := ClientResponse{Success: true}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		AgentURL:     server.URL,
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		Retry: RetryConfig{
			Enabled:      true,
			MaxAttempts:  3,
			InitialDelay: 1 * time.Millisecond,
		},
	})

	result, err := client.ExecuteQuery("token", "test", "chat", nil)
	if err != nil {
		t.Fatalf("Expected retry to succeed, got error: %v", err)
	}
	if !result.Success {
		t.Error("Expected success after retry")
	}
	if attempts != 2 {
		t.Errorf("Expected 2 attempts (1 fail + 1 success), got %d", attempts)
	}
}

// TestRetryNoRetryOn4xx tests that 4xx errors are not retried
func TestRetryNoRetryOn4xx(t *testing.T) {
	attempts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Bad request"))
	}))
	defer server.Close()

	client := NewClient(AxonFlowConfig{
		AgentURL:     server.URL,
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		Mode:         "sandbox", // Not production, so no fail-open
		Retry: RetryConfig{
			Enabled:      true,
			MaxAttempts:  3,
			InitialDelay: 1 * time.Millisecond,
		},
	})

	_, err := client.ExecuteQuery("token", "test", "chat", nil)
	if err == nil {
		t.Error("Expected error for 400 response")
	}
	if attempts != 1 {
		t.Errorf("Expected 1 attempt (no retry for 4xx), got %d", attempts)
	}
}

// TestNewClientDefaults tests default configuration values
func TestNewClientDefaults(t *testing.T) {
	client := NewClient(AxonFlowConfig{
		AgentURL:     "http://localhost:8080",
		ClientID:     "test",
		ClientSecret: "test",
	})

	if !client.config.Retry.Enabled {
		t.Error("Expected retry to be enabled by default")
	}
	if client.config.Retry.MaxAttempts != 3 {
		t.Errorf("Expected default MaxAttempts 3, got %d", client.config.Retry.MaxAttempts)
	}
	if !client.config.Cache.Enabled {
		t.Error("Expected cache to be enabled by default")
	}
	if client.config.Cache.TTL != 60*time.Second {
		t.Errorf("Expected default TTL 60s, got %v", client.config.Cache.TTL)
	}
	if client.cache == nil {
		t.Error("Expected cache to be initialized")
	}
}
