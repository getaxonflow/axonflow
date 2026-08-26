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

// testMCPPolicyEngine is a minimal MCPPolicyEngine test double: a fixed,
// directly-set policy slice, filtered by tenant/segment applicability.
//
// #3319: replaces the retired in-memory DynamicPolicyEngine this package's
// MCP handler tests used to construct directly via newTestEngine. That
// engine no longer exists, but MCPPolicyEngine only ever needed
// ListActivePoliciesForTenant, so this double reproduces just that method —
// an empty TenantID/SegmentID applies to everyone, mirroring the retired
// engine's applicability rule (memPolicyAppliesToTenant), which is what
// every test using this double already assumes. No test in this package
// exercises the database engine's 'global'/'default' sentinels through this
// double.
type testMCPPolicyEngine struct {
	policies []DynamicPolicy
	// orgs maps a policy ID to the org that owns it, for the fixtures where
	// org and tenant DIVERGE. Decision 5 (#3490) made org the selection key,
	// and DynamicPolicy has no OrgID field - the real engine reads org_id out
	// of the raw cache entry's _metadata precisely because the converted
	// struct cannot carry it, and that reasoning did not stop being true. A
	// policy absent from this map falls back to its TenantID, the org ==
	// tenant identity every single-tenant deployment has and every fixture
	// written before this change assumed.
	orgs map[string]string
}

// newTestEngine builds a testMCPPolicyEngine holding exactly the supplied
// policies, with each policy's org taken to equal its tenant.
func newTestEngine(policies []DynamicPolicy) *testMCPPolicyEngine {
	return &testMCPPolicyEngine{policies: policies}
}

// newTestEngineWithOrgs is newTestEngine for fixtures whose org and tenant
// differ - the shape a multi-tenant org actually has, and the one that makes
// a Decision 5 assertion non-vacuous.
func newTestEngineWithOrgs(policies []DynamicPolicy, orgs map[string]string) *testMCPPolicyEngine {
	return &testMCPPolicyEngine{policies: policies, orgs: orgs}
}

// orgOf returns the org that owns p, defaulting to its tenant.
func (e *testMCPPolicyEngine) orgOf(p DynamicPolicy) string {
	if org, ok := e.orgs[p.ID]; ok {
		return org
	}
	return p.TenantID
}

// Close is a no-op, kept so every `defer engine.Close()` call site across
// this package's MCP handler tests (inherited from when newTestEngine
// returned a real engine with background goroutines to stop) keeps
// compiling unchanged.
func (e *testMCPPolicyEngine) Close() {}

// ListActivePoliciesForTenant implements MCPPolicyEngine.
//
// Decision 5 (#3490): the argument is the caller's ORG. DynamicPolicy has no
// OrgID field - the real engine reads org_id out of the raw cache entry's
// _metadata precisely because the converted struct cannot carry it - so this
// double resolves each policy's owner through orgOf (the explicit orgs map,
// else the org == tenant identity). That keeps the double's answer equal to
// the real gate's without pretending the wire struct grew a field it did not.
func (e *testMCPPolicyEngine) ListActivePoliciesForTenant(orgID string, segmentIDs []string) []DynamicPolicy {
	var active []DynamicPolicy
	for _, p := range e.policies {
		if !p.Enabled {
			continue
		}
		if owner := e.orgOf(p); owner != "" && owner != orgID {
			continue
		}
		if p.SegmentID != "" && !segmentSetContains(segmentIDs, p.SegmentID) {
			continue
		}
		active = append(active, p)
	}
	return active
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
		TenantID:       "tenant-1",
		OrganizationID: "tenant-1",
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
		TenantID:       "tenant-1",
		OrganizationID: "tenant-1",
		ConnectorName:  "postgres",
		Operation:      "query",
		Statement:      "SELECT * FROM users",
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
		TenantID:       "tenant-1",
		OrganizationID: "tenant-1",
		ConnectorName:  "postgres",
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
		TenantID:       "tenant-1",
		OrganizationID: "tenant-1",
		ConnectorName:  "postgres",
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
		TenantID:       "tenant-1",
		OrganizationID: "tenant-1",
		ConnectorName:  "postgres",
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
		TenantID:       "tenant-1",
		OrganizationID: "tenant-1",
		ConnectorName:  "postgres",
		UserRole:       "admin",
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
		TenantID:       "tenant-1",
		OrganizationID: "tenant-1",
		ConnectorName:  "postgres",
		UserRole:       "viewer",
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
		TenantID:       "tenant-1",
		OrganizationID: "tenant-1",
		ConnectorName:  "postgres",
		UserRole:       "guest",
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
		TenantID:       "tenant-1",
		OrganizationID: "tenant-1",
		ConnectorName:  "postgres",
		UserRole:       "admin",
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
		TenantID:       "tenant-1",
		OrganizationID: "tenant-1",
		ConnectorName:  "postgres",
		UserRole:       "any-role",
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
		TenantID:       "tenant-1",
		OrganizationID: "tenant-1",
		ConnectorName:  "prod-db",
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
		TenantID:       "tenant-1",
		OrganizationID: "tenant-1",
		ConnectorName:  "dev-db",
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
		TenantID:       "tenant-1",
		OrganizationID: "tenant-1",
		ConnectorName:  "postgres",
		Operation:      "bulk_delete",
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

// TestMCPDynamicPolicyHandler_ContainsIsNowCaseInsensitive is the #3296
// convergence-1 test for this call site: `contains` used to be
// case-SENSITIVE here, the one legacy impl that diverged from the other
// three (in-memory engine, database engine, policy-test evaluator), which
// all lowercased both sides before comparing
// (mcp_dynamic_policy_handler.go legacy:551-552, no strings.ToLower). That
// divergence is gone — this handler now matches case-insensitively like
// every other caller, so a blocking policy on this shape fires MORE often
// than it used to.
func TestMCPDynamicPolicyHandler_ContainsIsNowCaseInsensitive(t *testing.T) {
	policies := []DynamicPolicy{
		{
			ID:       "case-insensitive-1",
			Name:     "Uppercase DELETE only",
			Type:     "mcp",
			Enabled:  true,
			TenantID: "tenant-1",
			Conditions: []PolicyCondition{
				{Field: "operation", Operator: "contains", Value: "DELETE"},
			},
			Actions: []PolicyAction{{Type: "block", Config: map[string]interface{}{"reason": "blocked"}}},
		},
	}
	engine := newTestEngine(policies)
	defer engine.Close()
	handler := NewMCPDynamicPolicyHandler(engine)

	router := mux.NewRouter()
	handler.RegisterRoutes(router)

	// Lowercase "delete" now matches a condition value of "DELETE" — before
	// #3296 this handler was the sole case-sensitive call site and would
	// have allowed this request through.
	body := MCPPolicyEvaluationRequest{
		TenantID:       "tenant-1",
		OrganizationID: "tenant-1",
		ConnectorName:  "postgres",
		Operation:      "bulk_delete",
	}
	jsonBody, _ := json.Marshal(body)
	req := httptest.NewRequest("POST", "/api/v1/mcp/evaluate-policies", bytes.NewBuffer(jsonBody))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	var resp MCPPolicyEvaluationResponse
	json.NewDecoder(rr.Body).Decode(&resp)
	if resp.Allowed {
		t.Error("expected Allowed=false: lowercase 'bulk_delete' must case-insensitively match condition value 'DELETE' on the MCP handler now (#3296 convergence 1)")
	}
}

// TestMCPDynamicPolicyHandler_EvaluateCondition_AllTenOperatorsSupported is
// the #3296 convergence 5 proof for this call site — the standing #3061
// getPoliciesForMCP parity gap. The legacy handler recognized only 4 of 10
// operators (equals, not_equals, contains, regex); a policy using any of the
// other six was silently inert on the MCP plane while still enforcing on
// LLM/MAP/WCP, violating the documented invariant that a policy is evaluated
// here if and only if it would be enforced on those other planes. All ten
// now evaluate for real, exercised directly through the handler's own
// evaluateCondition (bypassing the empty-conditions fail-safe and HTTP
// plumbing, neither of which this test is about).
func TestMCPDynamicPolicyHandler_EvaluateCondition_AllTenOperatorsSupported(t *testing.T) {
	handler := NewMCPDynamicPolicyHandler(nil)
	req := MCPPolicyEvaluationRequest{
		ConnectorName: "postgres",
		Operation:     "select",
		UserRole:      "admin",
		TenantID:      "tenant-1",
		Parameters:    map[string]interface{}{"a": 1, "b": 2},
	}

	tests := []struct {
		operator string
		cond     PolicyCondition
		want     bool
	}{
		{"equals", PolicyCondition{Field: "operation", Operator: "equals", Value: "select"}, true},
		{"not_equals", PolicyCondition{Field: "operation", Operator: "not_equals", Value: "delete"}, true},
		{"contains", PolicyCondition{Field: "operation", Operator: "contains", Value: "sel"}, true},
		{"not_contains", PolicyCondition{Field: "operation", Operator: "not_contains", Value: "del"}, true},
		{"contains_any", PolicyCondition{Field: "operation", Operator: "contains_any", Value: []interface{}{"del", "sel"}}, true},
		{"greater_than", PolicyCondition{Field: "parameter_count", Operator: "greater_than", Value: float64(1)}, true},
		{"less_than", PolicyCondition{Field: "parameter_count", Operator: "less_than", Value: float64(10)}, true},
		{"regex", PolicyCondition{Field: "operation", Operator: "regex", Value: "^sel"}, true},
		{"in", PolicyCondition{Field: "operation", Operator: "in", Value: []interface{}{"select", "insert"}}, true},
		{"not_in", PolicyCondition{Field: "operation", Operator: "not_in", Value: []interface{}{"delete", "drop"}}, true},
	}
	if len(tests) != 10 {
		t.Fatalf("expected exactly 10 operators under test, got %d", len(tests))
	}

	for _, tt := range tests {
		t.Run(tt.operator, func(t *testing.T) {
			got := handler.evaluateCondition(tt.cond, req)
			if got != tt.want {
				t.Errorf("operator %q must evaluate for real on the MCP handler, got %v want %v", tt.operator, got, tt.want)
			}
		})
	}
}

// TestMCPDynamicPolicyHandler_ZeroConditionPolicyMatchesEverything is this
// handler's own version of the restored-vacuous-truth regression test — the
// scenario every one of the four call sites now agrees on
// (dynamic_policy_engine.go, db_dynamic_policies.go, policy_api_service.go,
// and this handler). This handler used to be the ONE exception (#3061's
// fail-safe, evaluateConditions); that guard is now removed, aligning it
// with the other three planes. See condition_evaluator.go's "Withdrawn" doc
// section for why: the exposure the guard existed to prevent is closed at
// the authoring/load boundary instead (validateCreateRequest/
// validateUpdateRequest reject a customer-authored zero-condition policy;
// cachedPolicyToDynamicPolicy excludes a row whose conditions fail to
// unmarshal rather than caching it as indistinguishable from a genuinely
// empty one), so a zero-condition policy reaching this handler at all can
// only be a deliberate, platform-seeded one.
func TestMCPDynamicPolicyHandler_ZeroConditionPolicyMatchesEverything(t *testing.T) {
	policy := DynamicPolicy{
		ID:   "unconditional-log-policy",
		Name: "unconditional-log-policy",
		Type: "mcp",
		// No Conditions — the platform-seeded shape, meaning "applies to
		// everything."
		Actions: []PolicyAction{
			{Type: "log", Config: map[string]interface{}{"message": "logged"}},
		},
	}
	handler := NewMCPDynamicPolicyHandler(nil)

	matched, allowed, _ := handler.evaluatePolicy(policy, MCPPolicyEvaluationRequest{
		ConnectorName: "postgres",
		Operation:     "select",
	})

	if !matched {
		t.Fatalf("a zero-condition policy must match (applies to everything), got matched=false")
	}
	if !allowed {
		t.Fatalf("a zero-condition log-only policy must not deny, got allowed=false")
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
		TenantID:       "tenant-1",
		OrganizationID: "tenant-1",
		ConnectorName:  "postgres",
		Operation:      "execute",
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
		TenantID:       "tenant-2",
		OrganizationID: "tenant-2",
		ConnectorName:  "postgres",
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
		TenantID:       "any-tenant",
		OrganizationID: "any-tenant",
		ConnectorName:  "restricted-db",
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
		TenantID:       "tenant-1",
		OrganizationID: "tenant-1",
		ConnectorName:  "postgres",
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
		TenantID:       "tenant-1",
		OrganizationID: "tenant-1",
		ConnectorName:  "postgres",
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
		TenantID:       "tenant-1",
		OrganizationID: "tenant-1",
		ConnectorName:  "postgres",
		RequestTime:    time.Now(),
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
		TenantID:       "tenant-1",
		OrganizationID: "tenant-1",
		ConnectorName:  "postgres",
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
		TenantID:       "tenant-1",
		OrganizationID: "tenant-1",
		ConnectorName:  "postgres",
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
		TenantID:       "tenant-1",
		OrganizationID: "tenant-1",
		ConnectorName:  "postgres",
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
		TenantID:       "tenant-1",
		OrganizationID: "tenant-1",
		ConnectorName:  "postgres",
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

// TestMCPDynamicPolicyHandler_GlobalHandlerFunctions was deleted here
// (#3319): it tested InitMCPDynamicPolicyHandler / GetMCPDynamicPolicyHandler
// / globalMCPDynamicPolicyHandler, a global-handler wiring apparatus with
// zero production callers (the live wiring is NewMCPDynamicPolicyHandler,
// interface-typed, called directly from run.go) — dead code kept alive only
// by this one test and the deleted InitMCPDynamicPolicyHandler(*DynamicPolicyEngine)
// constructor. All three were removed together.

func TestMCPDynamicPolicyHandler_ProcessingTime(t *testing.T) {
	engine := newTestEngine(nil)
	defer engine.Close()
	handler := NewMCPDynamicPolicyHandler(engine)

	router := mux.NewRouter()
	handler.RegisterRoutes(router)

	body := MCPPolicyEvaluationRequest{
		TenantID:       "tenant-1",
		OrganizationID: "tenant-1",
		ConnectorName:  "postgres",
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
		TenantID:       "blocked-tenant",
		OrganizationID: "blocked-tenant",
		ConnectorName:  "postgres",
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
		TenantID:       "tenant-1",
		OrganizationID: "tenant-1",
		ConnectorName:  "postgres",
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
		TenantID:       "tenant-1",
		OrganizationID: "tenant-1",
		ConnectorName:  "postgres",
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
		TenantID:       "tenant-1",
		OrganizationID: "tenant-1",
		ConnectorName:  "postgres",
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
		TenantID:       "tenant-1",
		OrganizationID: "tenant-1",
		ConnectorName:  "postgres",
		UserID:         "user-1",
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

	req1 := MCPPolicyEvaluationRequest{TenantID: "tenant-1", OrganizationID: "tenant-1", ConnectorName: "pg", UserID: "user-A"}
	req2 := MCPPolicyEvaluationRequest{TenantID: "tenant-1", OrganizationID: "tenant-1", ConnectorName: "pg", UserID: "user-B"}

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
	req := MCPPolicyEvaluationRequest{TenantID: "t1", OrganizationID: "t1", ConnectorName: "pg", UserID: "u1"}

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
		TenantID:       "tenant-1",
		OrganizationID: "tenant-1",
		ConnectorName:  "postgres",
		UserID:         "user-1",
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

	reqT1 := MCPPolicyEvaluationRequest{TenantID: "tenant-1", OrganizationID: "tenant-1", ConnectorName: "pg", UserID: "user-1"}
	reqT2 := MCPPolicyEvaluationRequest{TenantID: "tenant-2", OrganizationID: "tenant-2", ConnectorName: "pg", UserID: "user-2"}

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
	req := MCPPolicyEvaluationRequest{TenantID: "t1", OrganizationID: "t1", ConnectorName: "pg", UserID: "u1"}

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
	req := MCPPolicyEvaluationRequest{TenantID: "t1", OrganizationID: "t1", ConnectorName: "pg", UserID: "u1"}

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
		TenantID:       "tenant-1",
		OrganizationID: "tenant-1",
		ConnectorName:  "postgres",
		UserID:         "test-user",
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
		TenantID:       "tenant-1",
		OrganizationID: "tenant-1",
		ConnectorName:  "postgres",
		UserID:         "test-user",
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
		TenantID:       "tenant-1",
		OrganizationID: "tenant-1",
		ConnectorName:  "postgres",
		RequestTime:    time.Now(),
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
		TenantID:       "tenant-1",
		OrganizationID: "tenant-1",
		ConnectorName:  "postgres",
		RequestTime:    time.Now(),
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
		TenantID:       "tenant-1",
		OrganizationID: "tenant-1",
		ConnectorName:  "postgres",
		RequestTime:    time.Now(),
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
		TenantID:       "tenant-1",
		OrganizationID: "tenant-1",
		ConnectorName:  "postgres",
		RequestTime:    time.Now(),
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

func TestEvaluateCondition_ParametersDotKey(t *testing.T) {
	engine := newTestEngine(nil)
	defer engine.Close()
	handler := NewMCPDynamicPolicyHandler(engine)

	cond := PolicyCondition{
		Field:    "parameters.table_name",
		Operator: "equals",
		Value:    "users",
	}

	req := MCPPolicyEvaluationRequest{
		TenantID:      "tenant-1",
		ConnectorName: "postgres",
		Operation:     "query",
		Parameters: map[string]interface{}{
			"table_name": "users",
		},
	}

	if !handler.evaluateCondition(cond, req) {
		t.Error("expected evaluateCondition to return true when parameters.table_name matches")
	}
}

func TestEvaluateCondition_ParameterCount(t *testing.T) {
	engine := newTestEngine(nil)
	defer engine.Close()
	handler := NewMCPDynamicPolicyHandler(engine)

	cond := PolicyCondition{
		Field:    "parameter_count",
		Operator: "equals",
		Value:    3,
	}

	req := MCPPolicyEvaluationRequest{
		TenantID:      "tenant-1",
		ConnectorName: "postgres",
		Operation:     "query",
		Parameters: map[string]interface{}{
			"table_name": "users",
			"limit":      100,
			"offset":     0,
		},
	}

	if !handler.evaluateCondition(cond, req) {
		t.Error("expected evaluateCondition to return true when parameter_count equals 3")
	}
}

func TestEvaluateCondition_ParametersMissingKey(t *testing.T) {
	engine := newTestEngine(nil)
	defer engine.Close()
	handler := NewMCPDynamicPolicyHandler(engine)

	cond := PolicyCondition{
		Field:    "parameters.missing_key",
		Operator: "equals",
		Value:    "anything",
	}

	req := MCPPolicyEvaluationRequest{
		TenantID:      "tenant-1",
		ConnectorName: "postgres",
		Operation:     "query",
		Parameters: map[string]interface{}{
			"table_name": "users",
		},
	}

	if handler.evaluateCondition(cond, req) {
		t.Error("expected evaluateCondition to return false when parameter key does not exist")
	}
}

// TestMCPDynamicPolicyHandler_HeaderlessWithoutOrgIsRefused pins the Decision 5
// (#3490) version-skew guard on the header-less internal-service plane.
//
// A caller that sends tenant_id but no organization_id predates the org-keyed
// selection contract. Evaluating it anyway would return 200 with only the
// global baseline evaluated - every tenant-authored dynamic policy silently
// dropped, indistinguishable from "this tenant has no policies" (#3048/#3049
// shape). The refusal is 403 SPECIFICALLY because the agent's
// EvaluateWithGracefulDegradation absorbs a transient failure but refuses to
// absorb a 401/403, so the governed tool call fails CLOSED. A 400 would be
// absorbed into allow-all, which is why the missing-tenant branch's 400 is
// NOT the right status here.
func TestMCPDynamicPolicyHandler_HeaderlessWithoutOrgIsRefused(t *testing.T) {
	engine := newTestEngine([]DynamicPolicy{
		{ID: "p1", Type: "content", Enabled: true, TenantID: "tenant-1"},
	})
	defer engine.Close()
	router := mux.NewRouter()
	NewMCPDynamicPolicyHandler(engine).RegisterRoutes(router)

	post := func(body MCPPolicyEvaluationRequest) *httptest.ResponseRecorder {
		jsonBody, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		req := httptest.NewRequest("POST", "/api/v1/mcp/evaluate-policies", bytes.NewBuffer(jsonBody))
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)
		return rr
	}

	// No organization_id: refused.
	rr := post(MCPPolicyEvaluationRequest{
		TenantID:      "tenant-1",
		ConnectorName: "postgres",
		Operation:     "query",
		Statement:     "SELECT 1",
	})
	if rr.Code != 403 {
		t.Fatalf("status = %d, want 403 (a 400 would be absorbed by graceful degradation into allow-all): %s",
			rr.Code, rr.Body.String())
	}

	// VACUITY CONTROL: the identical request WITH an organization_id is
	// served, so the 403 above is about the missing org and not about the
	// route, the fixture or the engine.
	rr = post(MCPPolicyEvaluationRequest{
		TenantID:       "tenant-1",
		OrganizationID: "tenant-1",
		ConnectorName:  "postgres",
		Operation:      "query",
		Statement:      "SELECT 1",
	})
	if rr.Code != 200 {
		t.Fatalf("vacuity control failed: the same request WITH organization_id must be served, got %d: %s",
			rr.Code, rr.Body.String())
	}
}
