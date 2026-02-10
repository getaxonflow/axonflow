// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/mux"
)

// newTestEngine creates a DynamicPolicyEngine for testing with the given policies.
// This is a test helper that directly sets the policies slice.
func newTestEngine(policies []DynamicPolicy) *DynamicPolicyEngine {
	engine := &DynamicPolicyEngine{
		policies:       policies,
		riskCalculator: NewRiskCalculator(),
		cache:          NewPolicyCache(5 * time.Minute),
		stopCh:         make(chan struct{}),
	}
	return engine
}

func TestNewMCPDynamicPolicyHandler(t *testing.T) {
	engine := newTestEngine(nil)
	defer engine.Close()
	handler := NewMCPDynamicPolicyHandler(engine)

	if handler == nil {
		t.Fatal("expected non-nil handler")
	}
	if handler.policyEngine == nil {
		t.Error("expected non-nil policyEngine")
	}
}

func TestNewMCPDynamicPolicyHandler_NilEngine(t *testing.T) {
	handler := NewMCPDynamicPolicyHandler(nil)

	if handler == nil {
		t.Fatal("expected non-nil handler even with nil engine")
	}
}

func TestMCPDynamicPolicyHandler_RegisterRoutes(t *testing.T) {
	engine := newTestEngine(nil)
	defer engine.Close()
	handler := NewMCPDynamicPolicyHandler(engine)

	router := mux.NewRouter()
	handler.RegisterRoutes(router)

	// Verify route is registered by making a request
	req := httptest.NewRequest("OPTIONS", "/api/v1/mcp/evaluate-policies", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status 200 for OPTIONS, got %d", rr.Code)
	}
}

func TestMCPDynamicPolicyHandler_HandleCORS(t *testing.T) {
	engine := newTestEngine(nil)
	defer engine.Close()
	handler := NewMCPDynamicPolicyHandler(engine)

	router := mux.NewRouter()
	handler.RegisterRoutes(router)

	req := httptest.NewRequest("OPTIONS", "/api/v1/mcp/evaluate-policies", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rr.Code)
	}
	if rr.Header().Get("Access-Control-Allow-Origin") != "*" {
		t.Error("expected Access-Control-Allow-Origin header")
	}
	if rr.Header().Get("Access-Control-Allow-Methods") != "POST, OPTIONS" {
		t.Error("expected Access-Control-Allow-Methods header")
	}
}

func TestMCPDynamicPolicyHandler_InvalidJSON(t *testing.T) {
	engine := newTestEngine(nil)
	defer engine.Close()
	handler := NewMCPDynamicPolicyHandler(engine)

	router := mux.NewRouter()
	handler.RegisterRoutes(router)

	req := httptest.NewRequest("POST", "/api/v1/mcp/evaluate-policies", bytes.NewBufferString("invalid json"))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", rr.Code)
	}

	var resp map[string]interface{}
	json.NewDecoder(rr.Body).Decode(&resp)
	if resp["success"] != false {
		t.Error("expected success=false")
	}
}

func TestMCPDynamicPolicyHandler_MissingTenantID(t *testing.T) {
	engine := newTestEngine(nil)
	defer engine.Close()
	handler := NewMCPDynamicPolicyHandler(engine)

	router := mux.NewRouter()
	handler.RegisterRoutes(router)

	body := MCPPolicyEvaluationRequest{
		ConnectorName: "postgres",
	}
	jsonBody, _ := json.Marshal(body)

	req := httptest.NewRequest("POST", "/api/v1/mcp/evaluate-policies", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", rr.Code)
	}

	var resp map[string]interface{}
	json.NewDecoder(rr.Body).Decode(&resp)
	if resp["error"] != "tenant_id is required" {
		t.Errorf("expected tenant_id error, got %v", resp["error"])
	}
}

func TestMCPDynamicPolicyHandler_MissingConnectorName(t *testing.T) {
	engine := newTestEngine(nil)
	defer engine.Close()
	handler := NewMCPDynamicPolicyHandler(engine)

	router := mux.NewRouter()
	handler.RegisterRoutes(router)

	body := MCPPolicyEvaluationRequest{
		TenantID: "tenant-1",
	}
	jsonBody, _ := json.Marshal(body)

	req := httptest.NewRequest("POST", "/api/v1/mcp/evaluate-policies", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", rr.Code)
	}

	var resp map[string]interface{}
	json.NewDecoder(rr.Body).Decode(&resp)
	if resp["error"] != "connector_name is required" {
		t.Errorf("expected connector_name error, got %v", resp["error"])
	}
}

func TestMCPDynamicPolicyHandler_NoPolicies(t *testing.T) {
	engine := newTestEngine(nil)
	defer engine.Close()
	handler := NewMCPDynamicPolicyHandler(engine)

	router := mux.NewRouter()
	handler.RegisterRoutes(router)

	body := MCPPolicyEvaluationRequest{
		TenantID:      "tenant-1",
		ConnectorName: "postgres",
		Operation:     "query",
		Statement:     "SELECT * FROM users",
	}
	jsonBody, _ := json.Marshal(body)

	req := httptest.NewRequest("POST", "/api/v1/mcp/evaluate-policies", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rr.Code)
	}

	var resp MCPPolicyEvaluationResponse
	json.NewDecoder(rr.Body).Decode(&resp)

	if !resp.Allowed {
		t.Error("expected Allowed=true with no policies")
	}
	if resp.PoliciesEvaluated != 0 {
		t.Errorf("expected 0 policies evaluated, got %d", resp.PoliciesEvaluated)
	}
}

func TestMCPDynamicPolicyHandler_NilEngine(t *testing.T) {
	handler := NewMCPDynamicPolicyHandler(nil)

	router := mux.NewRouter()
	handler.RegisterRoutes(router)

	body := MCPPolicyEvaluationRequest{
		TenantID:      "tenant-1",
		ConnectorName: "postgres",
	}
	jsonBody, _ := json.Marshal(body)

	req := httptest.NewRequest("POST", "/api/v1/mcp/evaluate-policies", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rr.Code)
	}

	var resp MCPPolicyEvaluationResponse
	json.NewDecoder(rr.Body).Decode(&resp)
	if !resp.Allowed {
		t.Error("expected Allowed=true with nil engine")
	}
}

func TestMCPDynamicPolicyHandler_RateLimitPolicy(t *testing.T) {
	policies := []DynamicPolicy{
		{
			ID:       "rate-1",
			Name:     "Rate Limit",
			Type:     "rate-limit",
			Enabled:  true,
			TenantID: "tenant-1",
		},
	}
	engine := newTestEngine(policies)
	defer engine.Close()
	handler := NewMCPDynamicPolicyHandler(engine)

	router := mux.NewRouter()
	handler.RegisterRoutes(router)

	body := MCPPolicyEvaluationRequest{
		TenantID:      "tenant-1",
		ConnectorName: "postgres",
	}
	jsonBody, _ := json.Marshal(body)

	req := httptest.NewRequest("POST", "/api/v1/mcp/evaluate-policies", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rr.Code)
	}

	var resp MCPPolicyEvaluationResponse
	json.NewDecoder(rr.Body).Decode(&resp)

	if !resp.Allowed {
		t.Error("expected Allowed=true (rate-limit returns allow for MVP)")
	}
	if resp.PoliciesEvaluated != 1 {
		t.Errorf("expected 1 policy evaluated, got %d", resp.PoliciesEvaluated)
	}
}

func TestMCPDynamicPolicyHandler_BudgetPolicy(t *testing.T) {
	policies := []DynamicPolicy{
		{
			ID:       "budget-1",
			Name:     "Budget Control",
			Type:     "budget",
			Enabled:  true,
			TenantID: "tenant-1",
		},
	}
	engine := newTestEngine(policies)
	defer engine.Close()
	handler := NewMCPDynamicPolicyHandler(engine)

	router := mux.NewRouter()
	handler.RegisterRoutes(router)

	body := MCPPolicyEvaluationRequest{
		TenantID:      "tenant-1",
		ConnectorName: "postgres",
	}
	jsonBody, _ := json.Marshal(body)

	req := httptest.NewRequest("POST", "/api/v1/mcp/evaluate-policies", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rr.Code)
	}

	var resp MCPPolicyEvaluationResponse
	json.NewDecoder(rr.Body).Decode(&resp)

	if !resp.Allowed {
		t.Error("expected Allowed=true (budget returns allow for MVP)")
	}
}

func TestMCPDynamicPolicyHandler_RoleAccessPolicy_Allowed(t *testing.T) {
	policies := []DynamicPolicy{
		{
			ID:       "role-1",
			Name:     "Role Access",
			Type:     "role-access",
			Enabled:  true,
			TenantID: "tenant-1",
			Conditions: []PolicyCondition{
				{
					Field:    "user.role",
					Operator: "in",
					Value:    []interface{}{"admin", "analyst"},
				},
			},
		},
	}
	engine := newTestEngine(policies)
	defer engine.Close()
	handler := NewMCPDynamicPolicyHandler(engine)

	router := mux.NewRouter()
	handler.RegisterRoutes(router)

	body := MCPPolicyEvaluationRequest{
		TenantID:      "tenant-1",
		ConnectorName: "postgres",
		UserRole:      "admin",
	}
	jsonBody, _ := json.Marshal(body)

	req := httptest.NewRequest("POST", "/api/v1/mcp/evaluate-policies", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	var resp MCPPolicyEvaluationResponse
	json.NewDecoder(rr.Body).Decode(&resp)

	if !resp.Allowed {
		t.Error("expected Allowed=true for admin role")
	}
}

func TestMCPDynamicPolicyHandler_RoleAccessPolicy_Denied(t *testing.T) {
	policies := []DynamicPolicy{
		{
			ID:       "role-1",
			Name:     "Role Access",
			Type:     "role-access",
			Enabled:  true,
			TenantID: "tenant-1",
			Conditions: []PolicyCondition{
				{
					Field:    "user.role",
					Operator: "in",
					Value:    []interface{}{"admin", "analyst"},
				},
			},
		},
	}
	engine := newTestEngine(policies)
	defer engine.Close()
	handler := NewMCPDynamicPolicyHandler(engine)

	router := mux.NewRouter()
	handler.RegisterRoutes(router)

	body := MCPPolicyEvaluationRequest{
		TenantID:      "tenant-1",
		ConnectorName: "postgres",
		UserRole:      "viewer",
	}
	jsonBody, _ := json.Marshal(body)

	req := httptest.NewRequest("POST", "/api/v1/mcp/evaluate-policies", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	var resp MCPPolicyEvaluationResponse
	json.NewDecoder(rr.Body).Decode(&resp)

	if resp.Allowed {
		t.Error("expected Allowed=false for viewer role")
	}
	if resp.BlockReason != "Access denied: Insufficient role permissions" {
		t.Errorf("expected specific block reason, got %s", resp.BlockReason)
	}
}

func TestMCPDynamicPolicyHandler_RoleAccessPolicy_NotIn(t *testing.T) {
	policies := []DynamicPolicy{
		{
			ID:       "role-block-1",
			Name:     "Block Guest",
			Type:     "role-access",
			Enabled:  true,
			TenantID: "tenant-1",
			Conditions: []PolicyCondition{
				{
					Field:    "user.role",
					Operator: "not_in",
					Value:    []interface{}{"guest", "anonymous"},
				},
			},
		},
	}
	engine := newTestEngine(policies)
	defer engine.Close()
	handler := NewMCPDynamicPolicyHandler(engine)

	router := mux.NewRouter()
	handler.RegisterRoutes(router)

	body := MCPPolicyEvaluationRequest{
		TenantID:      "tenant-1",
		ConnectorName: "postgres",
		UserRole:      "guest",
	}
	jsonBody, _ := json.Marshal(body)

	req := httptest.NewRequest("POST", "/api/v1/mcp/evaluate-policies", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	var resp MCPPolicyEvaluationResponse
	json.NewDecoder(rr.Body).Decode(&resp)

	if resp.Allowed {
		t.Error("expected Allowed=false for guest role")
	}
	if resp.BlockReason != "Access denied: Role explicitly blocked" {
		t.Errorf("expected block reason, got %s", resp.BlockReason)
	}
}

func TestMCPDynamicPolicyHandler_RoleAccessPolicy_Equals(t *testing.T) {
	policies := []DynamicPolicy{
		{
			ID:       "role-exact-1",
			Name:     "Exact Role Match",
			Type:     "role-access",
			Enabled:  true,
			TenantID: "tenant-1",
			Conditions: []PolicyCondition{
				{
					Field:    "user.role",
					Operator: "equals",
					Value:    "super-admin",
				},
			},
		},
	}
	engine := newTestEngine(policies)
	defer engine.Close()
	handler := NewMCPDynamicPolicyHandler(engine)

	router := mux.NewRouter()
	handler.RegisterRoutes(router)

	body := MCPPolicyEvaluationRequest{
		TenantID:      "tenant-1",
		ConnectorName: "postgres",
		UserRole:      "admin",
	}
	jsonBody, _ := json.Marshal(body)

	req := httptest.NewRequest("POST", "/api/v1/mcp/evaluate-policies", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	var resp MCPPolicyEvaluationResponse
	json.NewDecoder(rr.Body).Decode(&resp)

	if resp.Allowed {
		t.Error("expected Allowed=false when role doesn't match exactly")
	}
}

func TestMCPDynamicPolicyHandler_RoleAccessPolicy_Wildcard(t *testing.T) {
	policies := []DynamicPolicy{
		{
			ID:       "role-wildcard-1",
			Name:     "Allow All Roles",
			Type:     "role-access",
			Enabled:  true,
			TenantID: "tenant-1",
			Conditions: []PolicyCondition{
				{
					Field:    "user.role",
					Operator: "in",
					Value:    []interface{}{"*"},
				},
			},
		},
	}
	engine := newTestEngine(policies)
	defer engine.Close()
	handler := NewMCPDynamicPolicyHandler(engine)

	router := mux.NewRouter()
	handler.RegisterRoutes(router)

	body := MCPPolicyEvaluationRequest{
		TenantID:      "tenant-1",
		ConnectorName: "postgres",
		UserRole:      "any-role",
	}
	jsonBody, _ := json.Marshal(body)

	req := httptest.NewRequest("POST", "/api/v1/mcp/evaluate-policies", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	var resp MCPPolicyEvaluationResponse
	json.NewDecoder(rr.Body).Decode(&resp)

	if !resp.Allowed {
		t.Error("expected Allowed=true with wildcard role")
	}
}

func TestMCPDynamicPolicyHandler_ConnectorPolicy_Block(t *testing.T) {
	policies := []DynamicPolicy{
		{
			ID:       "connector-1",
			Name:     "Block Production Connector",
			Type:     "connector",
			Enabled:  true,
			TenantID: "tenant-1",
			Conditions: []PolicyCondition{
				{
					Field:    "connector",
					Operator: "equals",
					Value:    "prod-db",
				},
			},
			Actions: []PolicyAction{
				{
					Type: "block",
					Config: map[string]interface{}{
						"reason": "Production database access denied",
					},
				},
			},
		},
	}
	engine := newTestEngine(policies)
	defer engine.Close()
	handler := NewMCPDynamicPolicyHandler(engine)

	router := mux.NewRouter()
	handler.RegisterRoutes(router)

	body := MCPPolicyEvaluationRequest{
		TenantID:      "tenant-1",
		ConnectorName: "prod-db",
	}
	jsonBody, _ := json.Marshal(body)

	req := httptest.NewRequest("POST", "/api/v1/mcp/evaluate-policies", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	var resp MCPPolicyEvaluationResponse
	json.NewDecoder(rr.Body).Decode(&resp)

	if resp.Allowed {
		t.Error("expected Allowed=false for blocked connector")
	}
	if resp.BlockReason != "Production database access denied" {
		t.Errorf("expected specific block reason, got %s", resp.BlockReason)
	}
}

func TestMCPDynamicPolicyHandler_ConnectorPolicy_Allow(t *testing.T) {
	policies := []DynamicPolicy{
		{
			ID:       "connector-1",
			Name:     "Block Production Connector",
			Type:     "connector",
			Enabled:  true,
			TenantID: "tenant-1",
			Conditions: []PolicyCondition{
				{
					Field:    "connector",
					Operator: "equals",
					Value:    "prod-db",
				},
			},
			Actions: []PolicyAction{
				{
					Type: "block",
				},
			},
		},
	}
	engine := newTestEngine(policies)
	defer engine.Close()
	handler := NewMCPDynamicPolicyHandler(engine)

	router := mux.NewRouter()
	handler.RegisterRoutes(router)

	// Request for different connector should be allowed
	body := MCPPolicyEvaluationRequest{
		TenantID:      "tenant-1",
		ConnectorName: "dev-db",
	}
	jsonBody, _ := json.Marshal(body)

	req := httptest.NewRequest("POST", "/api/v1/mcp/evaluate-policies", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	var resp MCPPolicyEvaluationResponse
	json.NewDecoder(rr.Body).Decode(&resp)

	if !resp.Allowed {
		t.Error("expected Allowed=true for non-matching connector")
	}
}

func TestMCPDynamicPolicyHandler_MCPPolicy_OperationContains(t *testing.T) {
	policies := []DynamicPolicy{
		{
			ID:       "mcp-1",
			Name:     "Block Delete Operations",
			Type:     "mcp",
			Enabled:  true,
			TenantID: "tenant-1",
			Conditions: []PolicyCondition{
				{
					Field:    "operation",
					Operator: "contains",
					Value:    "delete",
				},
			},
			Actions: []PolicyAction{
				{
					Type: "block",
					Config: map[string]interface{}{
						"reason": "Delete operations not allowed",
					},
				},
			},
		},
	}
	engine := newTestEngine(policies)
	defer engine.Close()
	handler := NewMCPDynamicPolicyHandler(engine)

	router := mux.NewRouter()
	handler.RegisterRoutes(router)

	body := MCPPolicyEvaluationRequest{
		TenantID:      "tenant-1",
		ConnectorName: "postgres",
		Operation:     "bulk_delete",
	}
	jsonBody, _ := json.Marshal(body)

	req := httptest.NewRequest("POST", "/api/v1/mcp/evaluate-policies", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	var resp MCPPolicyEvaluationResponse
	json.NewDecoder(rr.Body).Decode(&resp)

	if resp.Allowed {
		t.Error("expected Allowed=false for operation containing 'delete'")
	}
}

func TestMCPDynamicPolicyHandler_MCPPolicy_NotEquals(t *testing.T) {
	policies := []DynamicPolicy{
		{
			ID:       "mcp-2",
			Name:     "Only Allow Query",
			Type:     "mcp",
			Enabled:  true,
			TenantID: "tenant-1",
			Conditions: []PolicyCondition{
				{
					Field:    "operation",
					Operator: "not_equals",
					Value:    "query",
				},
			},
			Actions: []PolicyAction{
				{
					Type: "block",
				},
			},
		},
	}
	engine := newTestEngine(policies)
	defer engine.Close()
	handler := NewMCPDynamicPolicyHandler(engine)

	router := mux.NewRouter()
	handler.RegisterRoutes(router)

	body := MCPPolicyEvaluationRequest{
		TenantID:      "tenant-1",
		ConnectorName: "postgres",
		Operation:     "execute",
	}
	jsonBody, _ := json.Marshal(body)

	req := httptest.NewRequest("POST", "/api/v1/mcp/evaluate-policies", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	var resp MCPPolicyEvaluationResponse
	json.NewDecoder(rr.Body).Decode(&resp)

	if resp.Allowed {
		t.Error("expected Allowed=false for non-query operation")
	}
}

func TestMCPDynamicPolicyHandler_TenantFiltering(t *testing.T) {
	policies := []DynamicPolicy{
		{
			ID:       "t1-policy",
			Name:     "Tenant 1 Policy",
			Type:     "connector",
			Enabled:  true,
			TenantID: "tenant-1",
			Conditions: []PolicyCondition{
				{
					Field:    "connector",
					Operator: "equals",
					Value:    "postgres",
				},
			},
			Actions: []PolicyAction{
				{
					Type: "block",
				},
			},
		},
	}
	engine := newTestEngine(policies)
	defer engine.Close()
	handler := NewMCPDynamicPolicyHandler(engine)

	router := mux.NewRouter()
	handler.RegisterRoutes(router)

	// Request from tenant-2 should not be affected by tenant-1's policy
	body := MCPPolicyEvaluationRequest{
		TenantID:      "tenant-2",
		ConnectorName: "postgres",
	}
	jsonBody, _ := json.Marshal(body)

	req := httptest.NewRequest("POST", "/api/v1/mcp/evaluate-policies", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	var resp MCPPolicyEvaluationResponse
	json.NewDecoder(rr.Body).Decode(&resp)

	if !resp.Allowed {
		t.Error("expected Allowed=true for tenant-2 (tenant-1's policy should not apply)")
	}
}

func TestMCPDynamicPolicyHandler_GlobalTenantPolicy(t *testing.T) {
	policies := []DynamicPolicy{
		{
			ID:       "global-policy",
			Name:     "Global Block",
			Type:     "connector",
			Enabled:  true,
			TenantID: "", // Global
			Conditions: []PolicyCondition{
				{
					Field:    "connector",
					Operator: "equals",
					Value:    "restricted-db",
				},
			},
			Actions: []PolicyAction{
				{
					Type: "block",
				},
			},
		},
	}
	engine := newTestEngine(policies)
	defer engine.Close()
	handler := NewMCPDynamicPolicyHandler(engine)

	router := mux.NewRouter()
	handler.RegisterRoutes(router)

	// Any tenant should be affected by global policy
	body := MCPPolicyEvaluationRequest{
		TenantID:      "any-tenant",
		ConnectorName: "restricted-db",
	}
	jsonBody, _ := json.Marshal(body)

	req := httptest.NewRequest("POST", "/api/v1/mcp/evaluate-policies", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	var resp MCPPolicyEvaluationResponse
	json.NewDecoder(rr.Body).Decode(&resp)

	if resp.Allowed {
		t.Error("expected Allowed=false due to global policy")
	}
}

func TestMCPDynamicPolicyHandler_DisabledPolicy(t *testing.T) {
	policies := []DynamicPolicy{
		{
			ID:       "disabled-1",
			Name:     "Disabled Policy",
			Type:     "connector",
			Enabled:  false, // Disabled
			TenantID: "tenant-1",
			Conditions: []PolicyCondition{
				{
					Field:    "connector",
					Operator: "equals",
					Value:    "postgres",
				},
			},
			Actions: []PolicyAction{
				{
					Type: "block",
				},
			},
		},
	}
	engine := newTestEngine(policies)
	defer engine.Close()
	handler := NewMCPDynamicPolicyHandler(engine)

	router := mux.NewRouter()
	handler.RegisterRoutes(router)

	body := MCPPolicyEvaluationRequest{
		TenantID:      "tenant-1",
		ConnectorName: "postgres",
	}
	jsonBody, _ := json.Marshal(body)

	req := httptest.NewRequest("POST", "/api/v1/mcp/evaluate-policies", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	var resp MCPPolicyEvaluationResponse
	json.NewDecoder(rr.Body).Decode(&resp)

	if !resp.Allowed {
		t.Error("expected Allowed=true (disabled policy should not be evaluated)")
	}
}

func TestMCPDynamicPolicyHandler_UnknownPolicyType(t *testing.T) {
	policies := []DynamicPolicy{
		{
			ID:       "unknown-1",
			Name:     "Unknown Type",
			Type:     "unknown-type",
			Enabled:  true,
			TenantID: "tenant-1",
		},
	}
	engine := newTestEngine(policies)
	defer engine.Close()
	handler := NewMCPDynamicPolicyHandler(engine)

	router := mux.NewRouter()
	handler.RegisterRoutes(router)

	body := MCPPolicyEvaluationRequest{
		TenantID:      "tenant-1",
		ConnectorName: "postgres",
	}
	jsonBody, _ := json.Marshal(body)

	req := httptest.NewRequest("POST", "/api/v1/mcp/evaluate-policies", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	var resp MCPPolicyEvaluationResponse
	json.NewDecoder(rr.Body).Decode(&resp)

	// Unknown type should not match and should not affect the result
	if !resp.Allowed {
		t.Error("expected Allowed=true (unknown policy type should be skipped)")
	}
	if resp.PoliciesEvaluated != 0 {
		t.Errorf("expected 0 policies evaluated (unknown type filtered), got %d", resp.PoliciesEvaluated)
	}
}

func TestMCPDynamicPolicyHandler_TimeAccessPolicy(t *testing.T) {
	policies := []DynamicPolicy{
		{
			ID:       "time-1",
			Name:     "Business Hours Only",
			Type:     "time-access",
			Enabled:  true,
			TenantID: "tenant-1",
			Conditions: []PolicyCondition{
				{
					Field:    "hour",
					Operator: "greater_than",
					Value:    8.0,
				},
				{
					Field:    "hour",
					Operator: "less_than",
					Value:    18.0,
				},
			},
		},
	}
	engine := newTestEngine(policies)
	defer engine.Close()
	handler := NewMCPDynamicPolicyHandler(engine)

	router := mux.NewRouter()
	handler.RegisterRoutes(router)

	body := MCPPolicyEvaluationRequest{
		TenantID:      "tenant-1",
		ConnectorName: "postgres",
		RequestTime:   time.Now(),
	}
	jsonBody, _ := json.Marshal(body)

	req := httptest.NewRequest("POST", "/api/v1/mcp/evaluate-policies", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	var resp MCPPolicyEvaluationResponse
	json.NewDecoder(rr.Body).Decode(&resp)

	// Result depends on current time - just verify the policy was evaluated
	if resp.PoliciesEvaluated != 1 {
		t.Errorf("expected 1 policy evaluated, got %d", resp.PoliciesEvaluated)
	}
}

func TestMCPDynamicPolicyHandler_MultiplePolicies_FirstBlock(t *testing.T) {
	policies := []DynamicPolicy{
		{
			ID:       "block-1",
			Name:     "Block Policy",
			Type:     "connector",
			Priority: 1,
			Enabled:  true,
			TenantID: "tenant-1",
			Conditions: []PolicyCondition{
				{
					Field:    "connector",
					Operator: "equals",
					Value:    "postgres",
				},
			},
			Actions: []PolicyAction{
				{
					Type:   "block",
					Config: map[string]interface{}{"reason": "First block"},
				},
			},
		},
		{
			ID:       "block-2",
			Name:     "Allow Policy",
			Type:     "connector",
			Priority: 2,
			Enabled:  true,
			TenantID: "tenant-1",
			Conditions: []PolicyCondition{
				{
					Field:    "connector",
					Operator: "equals",
					Value:    "postgres",
				},
			},
			Actions: []PolicyAction{
				{
					Type: "allow",
				},
			},
		},
	}
	engine := newTestEngine(policies)
	defer engine.Close()
	handler := NewMCPDynamicPolicyHandler(engine)

	router := mux.NewRouter()
	handler.RegisterRoutes(router)

	body := MCPPolicyEvaluationRequest{
		TenantID:      "tenant-1",
		ConnectorName: "postgres",
	}
	jsonBody, _ := json.Marshal(body)

	req := httptest.NewRequest("POST", "/api/v1/mcp/evaluate-policies", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	var resp MCPPolicyEvaluationResponse
	json.NewDecoder(rr.Body).Decode(&resp)

	if resp.Allowed {
		t.Error("expected Allowed=false (first blocking policy should stop evaluation)")
	}
	if resp.BlockReason != "First block" {
		t.Errorf("expected 'First block' reason, got %s", resp.BlockReason)
	}
}

func TestMCPDynamicPolicyHandler_UnknownConditionField(t *testing.T) {
	policies := []DynamicPolicy{
		{
			ID:       "unknown-field-1",
			Name:     "Unknown Field",
			Type:     "mcp",
			Enabled:  true,
			TenantID: "tenant-1",
			Conditions: []PolicyCondition{
				{
					Field:    "unknown_field",
					Operator: "equals",
					Value:    "test",
				},
			},
			Actions: []PolicyAction{
				{
					Type: "block",
				},
			},
		},
	}
	engine := newTestEngine(policies)
	defer engine.Close()
	handler := NewMCPDynamicPolicyHandler(engine)

	router := mux.NewRouter()
	handler.RegisterRoutes(router)

	body := MCPPolicyEvaluationRequest{
		TenantID:      "tenant-1",
		ConnectorName: "postgres",
	}
	jsonBody, _ := json.Marshal(body)

	req := httptest.NewRequest("POST", "/api/v1/mcp/evaluate-policies", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	var resp MCPPolicyEvaluationResponse
	json.NewDecoder(rr.Body).Decode(&resp)

	// Unknown field should return false (condition not met), so policy shouldn't block
	if !resp.Allowed {
		t.Error("expected Allowed=true (unknown field should not match)")
	}
}

func TestMCPDynamicPolicyHandler_UnknownOperator(t *testing.T) {
	policies := []DynamicPolicy{
		{
			ID:       "unknown-op-1",
			Name:     "Unknown Operator",
			Type:     "mcp",
			Enabled:  true,
			TenantID: "tenant-1",
			Conditions: []PolicyCondition{
				{
					Field:    "connector",
					Operator: "unknown_operator",
					Value:    "postgres",
				},
			},
			Actions: []PolicyAction{
				{
					Type: "block",
				},
			},
		},
	}
	engine := newTestEngine(policies)
	defer engine.Close()
	handler := NewMCPDynamicPolicyHandler(engine)

	router := mux.NewRouter()
	handler.RegisterRoutes(router)

	body := MCPPolicyEvaluationRequest{
		TenantID:      "tenant-1",
		ConnectorName: "postgres",
	}
	jsonBody, _ := json.Marshal(body)

	req := httptest.NewRequest("POST", "/api/v1/mcp/evaluate-policies", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	var resp MCPPolicyEvaluationResponse
	json.NewDecoder(rr.Body).Decode(&resp)

	// Unknown operator should return false, so condition not met
	if !resp.Allowed {
		t.Error("expected Allowed=true (unknown operator should not match)")
	}
}

func TestMCPDynamicPolicyHandler_MatchedPoliciesResponse(t *testing.T) {
	policies := []DynamicPolicy{
		{
			ID:       "match-1",
			Name:     "Matched Policy",
			Type:     "mcp",
			Enabled:  true,
			TenantID: "tenant-1",
			Conditions: []PolicyCondition{
				{
					Field:    "connector",
					Operator: "equals",
					Value:    "postgres",
				},
			},
			Actions: []PolicyAction{
				{
					Type: "log",
				},
			},
		},
	}
	engine := newTestEngine(policies)
	defer engine.Close()
	handler := NewMCPDynamicPolicyHandler(engine)

	router := mux.NewRouter()
	handler.RegisterRoutes(router)

	body := MCPPolicyEvaluationRequest{
		TenantID:      "tenant-1",
		ConnectorName: "postgres",
	}
	jsonBody, _ := json.Marshal(body)

	req := httptest.NewRequest("POST", "/api/v1/mcp/evaluate-policies", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	var resp MCPPolicyEvaluationResponse
	json.NewDecoder(rr.Body).Decode(&resp)

	if !resp.Allowed {
		t.Error("expected Allowed=true (log action doesn't block)")
	}
	if len(resp.MatchedPolicies) != 1 {
		t.Fatalf("expected 1 matched policy, got %d", len(resp.MatchedPolicies))
	}
	if resp.MatchedPolicies[0].PolicyID != "match-1" {
		t.Errorf("expected PolicyID=match-1, got %s", resp.MatchedPolicies[0].PolicyID)
	}
	if resp.MatchedPolicies[0].PolicyName != "Matched Policy" {
		t.Errorf("expected PolicyName='Matched Policy', got %s", resp.MatchedPolicies[0].PolicyName)
	}
}

func TestMCPDynamicPolicyHandler_GlobalHandlerFunctions(t *testing.T) {
	// Reset
	globalMCPDynamicPolicyHandler = nil

	if GetMCPDynamicPolicyHandler() != nil {
		t.Error("expected nil before initialization")
	}

	engine := newTestEngine(nil)
	defer engine.Close()
	InitMCPDynamicPolicyHandler(engine)

	handler := GetMCPDynamicPolicyHandler()
	if handler == nil {
		t.Fatal("expected non-nil after initialization")
	}

	// Cleanup
	globalMCPDynamicPolicyHandler = nil
}

func TestMCPDynamicPolicyHandler_ProcessingTime(t *testing.T) {
	engine := newTestEngine(nil)
	defer engine.Close()
	handler := NewMCPDynamicPolicyHandler(engine)

	router := mux.NewRouter()
	handler.RegisterRoutes(router)

	body := MCPPolicyEvaluationRequest{
		TenantID:      "tenant-1",
		ConnectorName: "postgres",
	}
	jsonBody, _ := json.Marshal(body)

	req := httptest.NewRequest("POST", "/api/v1/mcp/evaluate-policies", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	var resp MCPPolicyEvaluationResponse
	json.NewDecoder(rr.Body).Decode(&resp)

	// ProcessingTimeMs should be set (can be 0 for very fast responses)
	if resp.ProcessingTimeMs < 0 {
		t.Error("expected ProcessingTimeMs >= 0")
	}
}

func TestMCPDynamicPolicyHandler_TenantIDCondition(t *testing.T) {
	policies := []DynamicPolicy{
		{
			ID:       "tenant-cond-1",
			Name:     "Tenant ID Condition",
			Type:     "mcp",
			Enabled:  true,
			TenantID: "",
			Conditions: []PolicyCondition{
				{
					Field:    "tenant_id",
					Operator: "equals",
					Value:    "blocked-tenant",
				},
			},
			Actions: []PolicyAction{
				{
					Type: "block",
					Config: map[string]interface{}{
						"reason": "Tenant blocked",
					},
				},
			},
		},
	}
	engine := newTestEngine(policies)
	defer engine.Close()
	handler := NewMCPDynamicPolicyHandler(engine)

	router := mux.NewRouter()
	handler.RegisterRoutes(router)

	body := MCPPolicyEvaluationRequest{
		TenantID:      "blocked-tenant",
		ConnectorName: "postgres",
	}
	jsonBody, _ := json.Marshal(body)

	req := httptest.NewRequest("POST", "/api/v1/mcp/evaluate-policies", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	var resp MCPPolicyEvaluationResponse
	json.NewDecoder(rr.Body).Decode(&resp)

	if resp.Allowed {
		t.Error("expected Allowed=false for blocked tenant")
	}
}

func TestMCPDynamicPolicyHandler_NoActionsPolicy(t *testing.T) {
	policies := []DynamicPolicy{
		{
			ID:       "no-action-1",
			Name:     "No Actions",
			Type:     "mcp",
			Enabled:  true,
			TenantID: "tenant-1",
			Conditions: []PolicyCondition{
				{
					Field:    "connector",
					Operator: "equals",
					Value:    "postgres",
				},
			},
			Actions: []PolicyAction{}, // Empty actions
		},
	}
	engine := newTestEngine(policies)
	defer engine.Close()
	handler := NewMCPDynamicPolicyHandler(engine)

	router := mux.NewRouter()
	handler.RegisterRoutes(router)

	body := MCPPolicyEvaluationRequest{
		TenantID:      "tenant-1",
		ConnectorName: "postgres",
	}
	jsonBody, _ := json.Marshal(body)

	req := httptest.NewRequest("POST", "/api/v1/mcp/evaluate-policies", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	var resp MCPPolicyEvaluationResponse
	json.NewDecoder(rr.Body).Decode(&resp)

	// No actions means allow
	if !resp.Allowed {
		t.Error("expected Allowed=true with no actions")
	}
	if len(resp.MatchedPolicies) != 1 {
		t.Errorf("expected 1 matched policy, got %d", len(resp.MatchedPolicies))
	}
}

// Benchmarks

func BenchmarkMCPDynamicPolicyHandler_NoPolicies(b *testing.B) {
	engine := newTestEngine(nil)
	defer engine.Close()
	handler := NewMCPDynamicPolicyHandler(engine)

	router := mux.NewRouter()
	handler.RegisterRoutes(router)

	body := MCPPolicyEvaluationRequest{
		TenantID:      "tenant-1",
		ConnectorName: "postgres",
	}
	jsonBody, _ := json.Marshal(body)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest("POST", "/api/v1/mcp/evaluate-policies", bytes.NewBuffer(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
	}
}

func BenchmarkMCPDynamicPolicyHandler_WithPolicies(b *testing.B) {
	policies := make([]DynamicPolicy, 10)
	for i := 0; i < 10; i++ {
		policies[i] = DynamicPolicy{
			ID:       "policy-" + string(rune('0'+i)),
			Name:     "Policy " + string(rune('0'+i)),
			Type:     "mcp",
			Enabled:  true,
			TenantID: "tenant-1",
			Conditions: []PolicyCondition{
				{Field: "connector", Operator: "equals", Value: "other"},
			},
		}
	}
	engine := newTestEngine(policies)
	defer engine.Close()
	handler := NewMCPDynamicPolicyHandler(engine)

	router := mux.NewRouter()
	handler.RegisterRoutes(router)

	body := MCPPolicyEvaluationRequest{
		TenantID:      "tenant-1",
		ConnectorName: "postgres",
	}
	jsonBody, _ := json.Marshal(body)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest("POST", "/api/v1/mcp/evaluate-policies", bytes.NewBuffer(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
	}
}

// =============================================================================
// Rate Limit and Budget Tracking Tests (Issue #1071 - Tech Debt)
// These tests verify that rate limiting and budget tracking actually enforce
// limits rather than returning stub "true" values.
// =============================================================================

func TestEvaluateRateLimit_WithinLimit(t *testing.T) {
	// Clear the rate limit store for clean test
	rateLimitMutex.Lock()
	rateLimitStore = make(map[string]*rateLimitEntry)
	rateLimitMutex.Unlock()

	handler := NewMCPDynamicPolicyHandler(nil)
	policy := DynamicPolicy{
		ID:   "rate-limit-test",
		Name: "Test Rate Limit",
		Type: "rate-limit",
		Conditions: []PolicyCondition{
			{Field: "max_requests", Operator: "equals", Value: float64(10)},
			{Field: "window_seconds", Operator: "equals", Value: float64(60)},
		},
	}
	req := MCPPolicyEvaluationRequest{
		TenantID:      "tenant-1",
		ConnectorName: "postgres",
		UserID:        "user-1",
	}

	// First request should be allowed
	matched, allowed, reason := handler.evaluateRateLimit(policy, req)
	if !matched {
		t.Error("expected rate limit policy to match")
	}
	if !allowed {
		t.Errorf("expected allowed=true for first request, got reason: %s", reason)
	}

	// Make 9 more requests (total 10)
	for i := 0; i < 9; i++ {
		_, allowed, _ = handler.evaluateRateLimit(policy, req)
		if !allowed {
			t.Errorf("request %d should be allowed", i+2)
		}
	}

	// 11th request should be denied
	_, allowed, reason = handler.evaluateRateLimit(policy, req)
	if allowed {
		t.Error("expected 11th request to be denied")
	}
	if reason == "" {
		t.Error("expected non-empty reason for denial")
	}
}

func TestEvaluateRateLimit_DifferentUsers(t *testing.T) {
	rateLimitMutex.Lock()
	rateLimitStore = make(map[string]*rateLimitEntry)
	rateLimitMutex.Unlock()

	handler := NewMCPDynamicPolicyHandler(nil)
	policy := DynamicPolicy{
		ID:   "rate-limit-user",
		Name: "Per-User Rate Limit",
		Type: "rate-limit",
		Conditions: []PolicyCondition{
			{Field: "max_requests", Operator: "equals", Value: float64(5)},
			{Field: "window_seconds", Operator: "equals", Value: float64(60)},
		},
	}

	req1 := MCPPolicyEvaluationRequest{TenantID: "tenant-1", ConnectorName: "pg", UserID: "user-A"}
	req2 := MCPPolicyEvaluationRequest{TenantID: "tenant-1", ConnectorName: "pg", UserID: "user-B"}

	// User A makes 5 requests
	for i := 0; i < 5; i++ {
		_, allowed, _ := handler.evaluateRateLimit(policy, req1)
		if !allowed {
			t.Errorf("user-A request %d should be allowed", i+1)
		}
	}

	// User A's 6th request should be denied
	_, allowed, _ := handler.evaluateRateLimit(policy, req1)
	if allowed {
		t.Error("user-A's 6th request should be denied")
	}

	// User B's request should be allowed (separate counter)
	_, allowed, _ = handler.evaluateRateLimit(policy, req2)
	if !allowed {
		t.Error("user-B's first request should be allowed")
	}
}

func TestEvaluateRateLimit_DefaultLimits(t *testing.T) {
	rateLimitMutex.Lock()
	rateLimitStore = make(map[string]*rateLimitEntry)
	rateLimitMutex.Unlock()

	handler := NewMCPDynamicPolicyHandler(nil)
	// Policy without explicit limits - should allow (no rate limit configured)
	policy := DynamicPolicy{
		ID:         "rate-limit-default",
		Name:       "Default Rate Limit",
		Type:       "rate-limit",
		Conditions: []PolicyCondition{},
	}
	req := MCPPolicyEvaluationRequest{TenantID: "t1", ConnectorName: "pg", UserID: "u1"}

	// Should be allowed with default limits (no limit configured)
	_, allowed, _ := handler.evaluateRateLimit(policy, req)
	if !allowed {
		t.Error("first request should be allowed with default limits")
	}
}

func TestEvaluateBudget_WithinBudget(t *testing.T) {
	budgetStoreMutex.Lock()
	budgetStore = make(map[string]*budgetEntry)
	budgetStoreMutex.Unlock()

	handler := NewMCPDynamicPolicyHandler(nil)
	// Budget policy with $0.10 max budget and $0.01 cost per request = 10 requests max
	policy := DynamicPolicy{
		ID:   "budget-test",
		Name: "Test Budget",
		Type: "budget",
		Conditions: []PolicyCondition{
			{Field: "max_budget", Operator: "equals", Value: float64(0.10)},
			{Field: "cost_per_request", Operator: "equals", Value: float64(0.01)},
			{Field: "period_days", Operator: "equals", Value: float64(30)},
		},
	}
	req := MCPPolicyEvaluationRequest{
		TenantID:      "tenant-1",
		ConnectorName: "postgres",
		UserID:        "user-1",
	}

	// First request should be allowed
	matched, allowed, reason := handler.evaluateBudget(policy, req)
	if !matched {
		t.Error("expected budget policy to match")
	}
	if !allowed {
		t.Errorf("expected allowed=true, got reason: %s", reason)
	}

	// Make more requests up to budget (9 more = 10 total at $0.01 each = $0.10)
	for i := 0; i < 9; i++ {
		_, allowed, _ = handler.evaluateBudget(policy, req)
		if !allowed {
			t.Errorf("request %d should be allowed", i+2)
		}
	}

	// 11th request should be denied (exceeds $0.10 budget)
	_, allowed, reason = handler.evaluateBudget(policy, req)
	if allowed {
		t.Error("request exceeding budget should be denied")
	}
	if reason == "" {
		t.Error("expected non-empty reason for budget exceeded")
	}
}

func TestEvaluateBudget_DifferentTenants(t *testing.T) {
	budgetStoreMutex.Lock()
	budgetStore = make(map[string]*budgetEntry)
	budgetStoreMutex.Unlock()

	handler := NewMCPDynamicPolicyHandler(nil)
	// $0.05 budget with $0.03 per request = 1 request allowed
	policy := DynamicPolicy{
		ID:   "budget-tenant",
		Name: "Per-Tenant Budget",
		Type: "budget",
		Conditions: []PolicyCondition{
			{Field: "max_budget", Operator: "equals", Value: float64(0.05)},
			{Field: "cost_per_request", Operator: "equals", Value: float64(0.03)},
		},
	}

	reqT1 := MCPPolicyEvaluationRequest{TenantID: "tenant-1", ConnectorName: "pg", UserID: "user-1"}
	reqT2 := MCPPolicyEvaluationRequest{TenantID: "tenant-2", ConnectorName: "pg", UserID: "user-2"}

	// Tenant 1 uses $0.03
	_, allowed, _ := handler.evaluateBudget(policy, reqT1)
	if !allowed {
		t.Error("tenant-1 first request should be allowed")
	}

	// Tenant 1 tries to use another $0.03 (total $0.06, exceeds $0.05)
	_, allowed, _ = handler.evaluateBudget(policy, reqT1)
	if allowed {
		t.Error("tenant-1 second request should be denied (exceeds budget)")
	}

	// Tenant 2 should be allowed (separate budget)
	_, allowed, _ = handler.evaluateBudget(policy, reqT2)
	if !allowed {
		t.Error("tenant-2 first request should be allowed")
	}
}

func TestEvaluateBudget_DefaultBudget(t *testing.T) {
	budgetStoreMutex.Lock()
	budgetStore = make(map[string]*budgetEntry)
	budgetStoreMutex.Unlock()

	handler := NewMCPDynamicPolicyHandler(nil)
	// Policy without explicit budget - should allow (no budget configured means unlimited)
	policy := DynamicPolicy{
		ID:         "budget-default",
		Name:       "Default Budget",
		Type:       "budget",
		Conditions: []PolicyCondition{},
	}
	req := MCPPolicyEvaluationRequest{TenantID: "t1", ConnectorName: "pg", UserID: "u1"}

	// Should be allowed with default limits
	_, allowed, _ := handler.evaluateBudget(policy, req)
	if !allowed {
		t.Error("first request should be allowed with default budget")
	}
}

func TestEvaluateBudget_SmallBudgetLimit(t *testing.T) {
	budgetStoreMutex.Lock()
	budgetStore = make(map[string]*budgetEntry)
	budgetStoreMutex.Unlock()

	handler := NewMCPDynamicPolicyHandler(nil)
	// Budget of $5 with $1 per request = 5 requests max
	// Using integer-friendly values to avoid floating point issues
	policy := DynamicPolicy{
		ID:   "budget-small",
		Name: "Small Budget Test",
		Type: "budget",
		Conditions: []PolicyCondition{
			{Field: "max_budget", Operator: "equals", Value: float64(5)},
			{Field: "cost_per_request", Operator: "equals", Value: float64(1)},
		},
	}
	req := MCPPolicyEvaluationRequest{TenantID: "t1", ConnectorName: "pg", UserID: "u1"}

	// With $5 budget and $1 per request, 5 requests should be allowed
	for i := 0; i < 5; i++ {
		_, allowed, _ := handler.evaluateBudget(policy, req)
		if !allowed {
			t.Errorf("request %d should be allowed (under $5 budget)", i+1)
			break
		}
	}

	// 6th request should exceed budget
	_, allowed, _ := handler.evaluateBudget(policy, req)
	if allowed {
		t.Error("6th request should exceed budget")
	}
}

func TestMCPDynamicPolicyHandler_RateLimitPolicyIntegration(t *testing.T) {
	// Clear stores for clean test
	rateLimitMutex.Lock()
	rateLimitStore = make(map[string]*rateLimitEntry)
	rateLimitMutex.Unlock()

	policies := []DynamicPolicy{
		{
			ID:       "rate-int-1",
			Name:     "Integration Rate Limit",
			Type:     "rate-limit",
			Enabled:  true,
			TenantID: "tenant-1",
			Conditions: []PolicyCondition{
				{Field: "max_requests", Operator: "equals", Value: float64(3)},
				{Field: "window_seconds", Operator: "equals", Value: float64(60)},
			},
		},
	}
	engine := newTestEngine(policies)
	defer engine.Close()
	handler := NewMCPDynamicPolicyHandler(engine)

	router := mux.NewRouter()
	handler.RegisterRoutes(router)

	body := MCPPolicyEvaluationRequest{
		TenantID:      "tenant-1",
		ConnectorName: "postgres",
		UserID:        "test-user",
	}

	// Make 3 requests - all should be allowed
	for i := 0; i < 3; i++ {
		jsonBody, _ := json.Marshal(body)
		req := httptest.NewRequest("POST", "/api/v1/mcp/evaluate-policies", bytes.NewBuffer(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		var resp MCPPolicyEvaluationResponse
		json.NewDecoder(rr.Body).Decode(&resp)

		if !resp.Allowed {
			t.Errorf("request %d should be allowed, got blocked: %s", i+1, resp.BlockReason)
		}
	}

	// 4th request should be blocked
	jsonBody, _ := json.Marshal(body)
	req := httptest.NewRequest("POST", "/api/v1/mcp/evaluate-policies", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	var resp MCPPolicyEvaluationResponse
	json.NewDecoder(rr.Body).Decode(&resp)

	if resp.Allowed {
		t.Error("4th request should be blocked due to rate limit")
	}
}

func TestMCPDynamicPolicyHandler_BudgetPolicyIntegration(t *testing.T) {
	// Clear stores for clean test
	budgetStoreMutex.Lock()
	budgetStore = make(map[string]*budgetEntry)
	budgetStoreMutex.Unlock()

	policies := []DynamicPolicy{
		{
			ID:       "budget-int-1",
			Name:     "Integration Budget",
			Type:     "budget",
			Enabled:  true,
			TenantID: "tenant-1",
			Conditions: []PolicyCondition{
				// $0.002 budget with $0.001 per request = 2 requests max
				{Field: "max_budget", Operator: "equals", Value: float64(0.002)},
				{Field: "cost_per_request", Operator: "equals", Value: float64(0.001)},
			},
		},
	}
	engine := newTestEngine(policies)
	defer engine.Close()
	handler := NewMCPDynamicPolicyHandler(engine)

	router := mux.NewRouter()
	handler.RegisterRoutes(router)

	body := MCPPolicyEvaluationRequest{
		TenantID:      "tenant-1",
		ConnectorName: "postgres",
		UserID:        "test-user",
	}

	// First 2 requests should be allowed
	for i := 0; i < 2; i++ {
		jsonBody, _ := json.Marshal(body)
		req := httptest.NewRequest("POST", "/api/v1/mcp/evaluate-policies", bytes.NewBuffer(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		var resp MCPPolicyEvaluationResponse
		json.NewDecoder(rr.Body).Decode(&resp)

		if !resp.Allowed {
			t.Errorf("request %d should be allowed, got blocked: %s", i+1, resp.BlockReason)
		}
	}

	// 3rd request should exceed budget
	jsonBody, _ := json.Marshal(body)
	req := httptest.NewRequest("POST", "/api/v1/mcp/evaluate-policies", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	var resp MCPPolicyEvaluationResponse
	json.NewDecoder(rr.Body).Decode(&resp)

	if resp.Allowed {
		t.Error("3rd request should be blocked due to budget exceeded")
	}
}

// =============================================================================
// Time Access Policy Tests - Additional Coverage (Issue #966/#968)
// =============================================================================

// TestMCPDynamicPolicyHandler_TimeAccess_HourGreaterThan tests hour > X condition.
func TestMCPDynamicPolicyHandler_TimeAccess_HourGreaterThan(t *testing.T) {
	// Create a policy that denies access if current hour <= 23 (always denies)
	policies := []DynamicPolicy{
		{
			ID:       "time-hour-gt",
			Name:     "Block if hour <= 23",
			Type:     "time-access",
			Enabled:  true,
			TenantID: "tenant-1",
			Conditions: []PolicyCondition{
				{
					Field:    "hour",
					Operator: "greater_than",
					Value:    float64(23), // Hour must be > 23, so it always fails
				},
			},
		},
	}
	engine := newTestEngine(policies)
	defer engine.Close()
	handler := NewMCPDynamicPolicyHandler(engine)

	router := mux.NewRouter()
	handler.RegisterRoutes(router)

	body := MCPPolicyEvaluationRequest{
		TenantID:      "tenant-1",
		ConnectorName: "postgres",
		RequestTime:   time.Now(),
	}
	jsonBody, _ := json.Marshal(body)

	req := httptest.NewRequest("POST", "/api/v1/mcp/evaluate-policies", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	var resp MCPPolicyEvaluationResponse
	json.NewDecoder(rr.Body).Decode(&resp)

	// Should be blocked because hour is never > 23
	if resp.Allowed {
		t.Error("expected Allowed=false because no hour > 23")
	}
	if resp.BlockReason == "" {
		t.Error("expected block reason to be set")
	}
}

// TestMCPDynamicPolicyHandler_TimeAccess_HourLessThan tests hour < X condition.
func TestMCPDynamicPolicyHandler_TimeAccess_HourLessThan(t *testing.T) {
	// Create a policy that denies access if current hour >= 0 (always denies)
	policies := []DynamicPolicy{
		{
			ID:       "time-hour-lt",
			Name:     "Block if hour >= 0",
			Type:     "time-access",
			Enabled:  true,
			TenantID: "tenant-1",
			Conditions: []PolicyCondition{
				{
					Field:    "hour",
					Operator: "less_than",
					Value:    float64(0), // Hour must be < 0, which is impossible
				},
			},
		},
	}
	engine := newTestEngine(policies)
	defer engine.Close()
	handler := NewMCPDynamicPolicyHandler(engine)

	router := mux.NewRouter()
	handler.RegisterRoutes(router)

	body := MCPPolicyEvaluationRequest{
		TenantID:      "tenant-1",
		ConnectorName: "postgres",
		RequestTime:   time.Now(),
	}
	jsonBody, _ := json.Marshal(body)

	req := httptest.NewRequest("POST", "/api/v1/mcp/evaluate-policies", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	var resp MCPPolicyEvaluationResponse
	json.NewDecoder(rr.Body).Decode(&resp)

	// Should be blocked because hour is never < 0
	if resp.Allowed {
		t.Error("expected Allowed=false because no hour < 0")
	}
}

// TestMCPDynamicPolicyHandler_TimeAccess_DayInList tests day in allowed list.
func TestMCPDynamicPolicyHandler_TimeAccess_DayInList(t *testing.T) {
	// Create a policy that allows access only on "InvalidDay" (no such day)
	policies := []DynamicPolicy{
		{
			ID:       "time-day-in",
			Name:     "Weekdays Only",
			Type:     "time-access",
			Enabled:  true,
			TenantID: "tenant-1",
			Conditions: []PolicyCondition{
				{
					Field:    "day",
					Operator: "in",
					Value:    []interface{}{"InvalidDay"}, // No such day exists
				},
			},
		},
	}
	engine := newTestEngine(policies)
	defer engine.Close()
	handler := NewMCPDynamicPolicyHandler(engine)

	router := mux.NewRouter()
	handler.RegisterRoutes(router)

	body := MCPPolicyEvaluationRequest{
		TenantID:      "tenant-1",
		ConnectorName: "postgres",
		RequestTime:   time.Now(),
	}
	jsonBody, _ := json.Marshal(body)

	req := httptest.NewRequest("POST", "/api/v1/mcp/evaluate-policies", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	var resp MCPPolicyEvaluationResponse
	json.NewDecoder(rr.Body).Decode(&resp)

	// Should be blocked because today is never "InvalidDay"
	if resp.Allowed {
		t.Error("expected Allowed=false because day is not in list")
	}
	if resp.BlockReason == "" {
		t.Error("expected block reason to be set")
	}
}

// TestMCPDynamicPolicyHandler_TimeAccess_AllDaysAllowed tests allowing all days.
func TestMCPDynamicPolicyHandler_TimeAccess_AllDaysAllowed(t *testing.T) {
	// Create a policy that allows all days of the week
	allDays := []interface{}{"Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"}
	policies := []DynamicPolicy{
		{
			ID:       "time-day-all",
			Name:     "All Days",
			Type:     "time-access",
			Enabled:  true,
			TenantID: "tenant-1",
			Conditions: []PolicyCondition{
				{
					Field:    "day",
					Operator: "in",
					Value:    allDays,
				},
			},
		},
	}
	engine := newTestEngine(policies)
	defer engine.Close()
	handler := NewMCPDynamicPolicyHandler(engine)

	router := mux.NewRouter()
	handler.RegisterRoutes(router)

	body := MCPPolicyEvaluationRequest{
		TenantID:      "tenant-1",
		ConnectorName: "postgres",
		RequestTime:   time.Now(),
	}
	jsonBody, _ := json.Marshal(body)

	req := httptest.NewRequest("POST", "/api/v1/mcp/evaluate-policies", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	var resp MCPPolicyEvaluationResponse
	json.NewDecoder(rr.Body).Decode(&resp)

	// Should be allowed because today is always one of the days
	if !resp.Allowed {
		t.Error("expected Allowed=true because today is in the list")
	}
}
