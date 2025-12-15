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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// mockPolicyService implements PolicyServicer for testing
type mockPolicyService struct {
	createPolicyFunc      func(ctx context.Context, tenantID string, req *CreatePolicyRequest, createdBy string) (*PolicyResource, error)
	getPolicyFunc         func(ctx context.Context, tenantID, policyID string) (*PolicyResource, error)
	listPoliciesFunc      func(ctx context.Context, tenantID string, params ListPoliciesParams) (*PoliciesListResponse, error)
	updatePolicyFunc      func(ctx context.Context, tenantID, policyID string, req *UpdatePolicyRequest, updatedBy string) (*PolicyResource, error)
	deletePolicyFunc      func(ctx context.Context, tenantID, policyID string, deletedBy string) error
	testPolicyFunc        func(ctx context.Context, tenantID, policyID string, req *TestPolicyRequest) (*TestPolicyResponse, error)
	getPolicyVersionsFunc func(ctx context.Context, tenantID, policyID string) (*PolicyVersionResponse, error)
	exportPoliciesFunc    func(ctx context.Context, tenantID string) (*ExportPoliciesResponse, error)
	importPoliciesFunc    func(ctx context.Context, tenantID string, req *ImportPoliciesRequest, importedBy string) (*ImportPoliciesResponse, error)
}

func (m *mockPolicyService) CreatePolicy(ctx context.Context, tenantID string, req *CreatePolicyRequest, createdBy string) (*PolicyResource, error) {
	if m.createPolicyFunc != nil {
		return m.createPolicyFunc(ctx, tenantID, req, createdBy)
	}
	return nil, nil
}

func (m *mockPolicyService) GetPolicy(ctx context.Context, tenantID, policyID string) (*PolicyResource, error) {
	if m.getPolicyFunc != nil {
		return m.getPolicyFunc(ctx, tenantID, policyID)
	}
	return nil, nil
}

func (m *mockPolicyService) ListPolicies(ctx context.Context, tenantID string, params ListPoliciesParams) (*PoliciesListResponse, error) {
	if m.listPoliciesFunc != nil {
		return m.listPoliciesFunc(ctx, tenantID, params)
	}
	return nil, nil
}

func (m *mockPolicyService) UpdatePolicy(ctx context.Context, tenantID, policyID string, req *UpdatePolicyRequest, updatedBy string) (*PolicyResource, error) {
	if m.updatePolicyFunc != nil {
		return m.updatePolicyFunc(ctx, tenantID, policyID, req, updatedBy)
	}
	return nil, nil
}

func (m *mockPolicyService) DeletePolicy(ctx context.Context, tenantID, policyID string, deletedBy string) error {
	if m.deletePolicyFunc != nil {
		return m.deletePolicyFunc(ctx, tenantID, policyID, deletedBy)
	}
	return nil
}

func (m *mockPolicyService) TestPolicy(ctx context.Context, tenantID, policyID string, req *TestPolicyRequest) (*TestPolicyResponse, error) {
	if m.testPolicyFunc != nil {
		return m.testPolicyFunc(ctx, tenantID, policyID, req)
	}
	return nil, nil
}

func (m *mockPolicyService) GetPolicyVersions(ctx context.Context, tenantID, policyID string) (*PolicyVersionResponse, error) {
	if m.getPolicyVersionsFunc != nil {
		return m.getPolicyVersionsFunc(ctx, tenantID, policyID)
	}
	return nil, nil
}

func (m *mockPolicyService) ExportPolicies(ctx context.Context, tenantID string) (*ExportPoliciesResponse, error) {
	if m.exportPoliciesFunc != nil {
		return m.exportPoliciesFunc(ctx, tenantID)
	}
	return nil, nil
}

func (m *mockPolicyService) ImportPolicies(ctx context.Context, tenantID string, req *ImportPoliciesRequest, importedBy string) (*ImportPoliciesResponse, error) {
	if m.importPoliciesFunc != nil {
		return m.importPoliciesFunc(ctx, tenantID, req, importedBy)
	}
	return nil, nil
}

// Helper to create a test policy resource
func testPolicyResource() *PolicyResource {
	return &PolicyResource{
		ID:          "550e8400-e29b-41d4-a716-446655440000",
		Name:        "Test Policy",
		Description: "A test policy",
		Type:        "content",
		Conditions: []PolicyCondition{
			{Field: "query", Operator: "contains", Value: "sensitive"},
		},
		Actions: []PolicyAction{
			{Type: "block", Config: map[string]interface{}{"message": "Blocked"}},
		},
		Priority:  100,
		Enabled:   true,
		Version:   1,
		TenantID:  "tenant-123",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		CreatedBy: "user-1",
		UpdatedBy: "user-1",
	}
}

func TestNewPolicyAPIHandler(t *testing.T) {
	mock := &mockPolicyService{}
	handler := NewPolicyAPIHandler(mock)

	if handler == nil {
		t.Fatal("Expected non-nil handler")
	}
	if handler.service != mock {
		t.Error("Expected handler to have the provided service")
	}
}

func TestPolicyAPIHandler_RegisterRoutes(t *testing.T) {
	mock := &mockPolicyService{}
	handler := NewPolicyAPIHandler(mock)
	mux := http.NewServeMux()

	handler.RegisterRoutes(mux)

	// Verify routes are registered by checking the mux
	// We can't directly check registered routes, but we can verify no panic
}

func TestPolicyAPIHandler_HandlePolicies_NoTenantID(t *testing.T) {
	mock := &mockPolicyService{}
	handler := NewPolicyAPIHandler(mock)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/policies", nil)
	w := httptest.NewRecorder()

	handler.handlePolicies(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status %d, got %d", http.StatusUnauthorized, w.Code)
	}

	var resp PolicyAPIError
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}
	if resp.Error.Code != "UNAUTHORIZED" {
		t.Errorf("Expected code UNAUTHORIZED, got %s", resp.Error.Code)
	}
}

func TestPolicyAPIHandler_HandlePolicies_List(t *testing.T) {
	policies := []PolicyResource{*testPolicyResource()}
	mock := &mockPolicyService{
		listPoliciesFunc: func(ctx context.Context, tenantID string, params ListPoliciesParams) (*PoliciesListResponse, error) {
			return &PoliciesListResponse{
				Policies: policies,
				Pagination: PaginationMeta{
					Page:       1,
					PageSize:   20,
					TotalItems: 1,
					TotalPages: 1,
				},
			}, nil
		},
	}
	handler := NewPolicyAPIHandler(mock)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/policies?page=1&page_size=20&type=content&enabled=true", nil)
	req.Header.Set("X-Tenant-ID", "tenant-123")
	w := httptest.NewRecorder()

	handler.handlePolicies(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
	}

	var resp PoliciesListResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}
	if len(resp.Policies) != 1 {
		t.Errorf("Expected 1 policy, got %d", len(resp.Policies))
	}
}

func TestPolicyAPIHandler_HandlePolicies_ListError(t *testing.T) {
	mock := &mockPolicyService{
		listPoliciesFunc: func(ctx context.Context, tenantID string, params ListPoliciesParams) (*PoliciesListResponse, error) {
			return nil, errors.New("database error")
		},
	}
	handler := NewPolicyAPIHandler(mock)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/policies", nil)
	req.Header.Set("X-Tenant-ID", "tenant-123")
	w := httptest.NewRecorder()

	handler.handlePolicies(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("Expected status %d, got %d", http.StatusInternalServerError, w.Code)
	}
}

func TestPolicyAPIHandler_HandlePolicies_Create(t *testing.T) {
	policy := testPolicyResource()
	mock := &mockPolicyService{
		createPolicyFunc: func(ctx context.Context, tenantID string, req *CreatePolicyRequest, createdBy string) (*PolicyResource, error) {
			return policy, nil
		},
	}
	handler := NewPolicyAPIHandler(mock)

	body := `{
		"name": "Test Policy",
		"description": "A test policy",
		"type": "content",
		"conditions": [{"field": "query", "operator": "contains", "value": "sensitive"}],
		"actions": [{"type": "block", "config": {"message": "Blocked"}}],
		"priority": 100,
		"enabled": true
	}`

	req := httptest.NewRequest(http.MethodPost, "/api/v1/policies", strings.NewReader(body))
	req.Header.Set("X-Tenant-ID", "tenant-123")
	req.Header.Set("X-User-ID", "user-1")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.handlePolicies(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("Expected status %d, got %d", http.StatusCreated, w.Code)
	}

	var resp PolicyResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}
	if resp.Policy.Name != "Test Policy" {
		t.Errorf("Expected policy name 'Test Policy', got '%s'", resp.Policy.Name)
	}
}

func TestPolicyAPIHandler_HandlePolicies_CreateInvalidJSON(t *testing.T) {
	mock := &mockPolicyService{}
	handler := NewPolicyAPIHandler(mock)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/policies", strings.NewReader("invalid json"))
	req.Header.Set("X-Tenant-ID", "tenant-123")
	w := httptest.NewRecorder()

	handler.handlePolicies(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, w.Code)
	}

	var resp PolicyAPIError
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}
	if resp.Error.Code != "INVALID_JSON" {
		t.Errorf("Expected code INVALID_JSON, got %s", resp.Error.Code)
	}
}

func TestPolicyAPIHandler_HandlePolicies_CreateValidationError(t *testing.T) {
	mock := &mockPolicyService{
		createPolicyFunc: func(ctx context.Context, tenantID string, req *CreatePolicyRequest, createdBy string) (*PolicyResource, error) {
			return nil, &ValidationError{
				Errors: []PolicyFieldError{
					{Field: "name", Message: "Name is required"},
				},
			}
		},
	}
	handler := NewPolicyAPIHandler(mock)

	body := `{"name": "", "type": "content", "conditions": [], "actions": []}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/policies", strings.NewReader(body))
	req.Header.Set("X-Tenant-ID", "tenant-123")
	w := httptest.NewRecorder()

	handler.handlePolicies(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, w.Code)
	}

	var resp PolicyAPIError
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}
	if resp.Error.Code != "VALIDATION_ERROR" {
		t.Errorf("Expected code VALIDATION_ERROR, got %s", resp.Error.Code)
	}
}

func TestPolicyAPIHandler_HandlePolicies_CreateServiceError(t *testing.T) {
	mock := &mockPolicyService{
		createPolicyFunc: func(ctx context.Context, tenantID string, req *CreatePolicyRequest, createdBy string) (*PolicyResource, error) {
			return nil, errors.New("database error")
		},
	}
	handler := NewPolicyAPIHandler(mock)

	body := `{"name": "Test", "type": "content", "conditions": [{"field": "query", "operator": "contains", "value": "x"}], "actions": [{"type": "block"}]}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/policies", strings.NewReader(body))
	req.Header.Set("X-Tenant-ID", "tenant-123")
	w := httptest.NewRecorder()

	handler.handlePolicies(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("Expected status %d, got %d", http.StatusInternalServerError, w.Code)
	}
}

func TestPolicyAPIHandler_HandlePolicies_Options(t *testing.T) {
	mock := &mockPolicyService{}
	handler := NewPolicyAPIHandler(mock)

	req := httptest.NewRequest(http.MethodOptions, "/api/v1/policies", nil)
	req.Header.Set("X-Tenant-ID", "tenant-123")
	req.Header.Set("Origin", "http://localhost:3000")
	w := httptest.NewRecorder()

	handler.handlePolicies(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
	}
}

func TestPolicyAPIHandler_HandlePolicies_MethodNotAllowed(t *testing.T) {
	mock := &mockPolicyService{}
	handler := NewPolicyAPIHandler(mock)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/policies", nil)
	req.Header.Set("X-Tenant-ID", "tenant-123")
	w := httptest.NewRecorder()

	handler.handlePolicies(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected status %d, got %d", http.StatusMethodNotAllowed, w.Code)
	}
}

func TestPolicyAPIHandler_HandlePolicyByID_NoTenantID(t *testing.T) {
	mock := &mockPolicyService{}
	handler := NewPolicyAPIHandler(mock)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/policies/550e8400-e29b-41d4-a716-446655440000", nil)
	w := httptest.NewRecorder()

	handler.handlePolicyByID(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status %d, got %d", http.StatusUnauthorized, w.Code)
	}
}

func TestPolicyAPIHandler_HandlePolicyByID_NoPolicyID(t *testing.T) {
	mock := &mockPolicyService{}
	handler := NewPolicyAPIHandler(mock)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/policies/", nil)
	req.Header.Set("X-Tenant-ID", "tenant-123")
	w := httptest.NewRecorder()

	handler.handlePolicyByID(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestPolicyAPIHandler_HandlePolicyByID_InvalidUUID(t *testing.T) {
	mock := &mockPolicyService{}
	handler := NewPolicyAPIHandler(mock)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/policies/not-a-uuid", nil)
	req.Header.Set("X-Tenant-ID", "tenant-123")
	w := httptest.NewRecorder()

	handler.handlePolicyByID(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, w.Code)
	}

	var resp PolicyAPIError
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}
	if !strings.Contains(resp.Error.Message, "Invalid policy ID format") {
		t.Errorf("Expected message about invalid UUID, got %s", resp.Error.Message)
	}
}

func TestPolicyAPIHandler_GetPolicy(t *testing.T) {
	policy := testPolicyResource()
	mock := &mockPolicyService{
		getPolicyFunc: func(ctx context.Context, tenantID, policyID string) (*PolicyResource, error) {
			return policy, nil
		},
	}
	handler := NewPolicyAPIHandler(mock)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/policies/550e8400-e29b-41d4-a716-446655440000", nil)
	req.Header.Set("X-Tenant-ID", "tenant-123")
	w := httptest.NewRecorder()

	handler.handlePolicyByID(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
	}

	var resp PolicyResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}
	if resp.Policy.ID != policy.ID {
		t.Errorf("Expected policy ID %s, got %s", policy.ID, resp.Policy.ID)
	}
}

func TestPolicyAPIHandler_GetPolicy_NotFound(t *testing.T) {
	mock := &mockPolicyService{
		getPolicyFunc: func(ctx context.Context, tenantID, policyID string) (*PolicyResource, error) {
			return nil, nil
		},
	}
	handler := NewPolicyAPIHandler(mock)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/policies/550e8400-e29b-41d4-a716-446655440000", nil)
	req.Header.Set("X-Tenant-ID", "tenant-123")
	w := httptest.NewRecorder()

	handler.handlePolicyByID(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("Expected status %d, got %d", http.StatusNotFound, w.Code)
	}
}

func TestPolicyAPIHandler_GetPolicy_Error(t *testing.T) {
	mock := &mockPolicyService{
		getPolicyFunc: func(ctx context.Context, tenantID, policyID string) (*PolicyResource, error) {
			return nil, errors.New("database error")
		},
	}
	handler := NewPolicyAPIHandler(mock)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/policies/550e8400-e29b-41d4-a716-446655440000", nil)
	req.Header.Set("X-Tenant-ID", "tenant-123")
	w := httptest.NewRecorder()

	handler.handlePolicyByID(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("Expected status %d, got %d", http.StatusInternalServerError, w.Code)
	}
}

func TestPolicyAPIHandler_UpdatePolicy(t *testing.T) {
	policy := testPolicyResource()
	mock := &mockPolicyService{
		updatePolicyFunc: func(ctx context.Context, tenantID, policyID string, req *UpdatePolicyRequest, updatedBy string) (*PolicyResource, error) {
			return policy, nil
		},
	}
	handler := NewPolicyAPIHandler(mock)

	body := `{"name": "Updated Policy"}`
	req := httptest.NewRequest(http.MethodPut, "/api/v1/policies/550e8400-e29b-41d4-a716-446655440000", strings.NewReader(body))
	req.Header.Set("X-Tenant-ID", "tenant-123")
	req.Header.Set("X-User-ID", "user-1")
	w := httptest.NewRecorder()

	handler.handlePolicyByID(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
	}
}

func TestPolicyAPIHandler_UpdatePolicy_InvalidJSON(t *testing.T) {
	mock := &mockPolicyService{}
	handler := NewPolicyAPIHandler(mock)

	req := httptest.NewRequest(http.MethodPut, "/api/v1/policies/550e8400-e29b-41d4-a716-446655440000", strings.NewReader("invalid"))
	req.Header.Set("X-Tenant-ID", "tenant-123")
	w := httptest.NewRecorder()

	handler.handlePolicyByID(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestPolicyAPIHandler_UpdatePolicy_ValidationError(t *testing.T) {
	mock := &mockPolicyService{
		updatePolicyFunc: func(ctx context.Context, tenantID, policyID string, req *UpdatePolicyRequest, updatedBy string) (*PolicyResource, error) {
			return nil, &ValidationError{
				Errors: []PolicyFieldError{
					{Field: "name", Message: "Name too short"},
				},
			}
		},
	}
	handler := NewPolicyAPIHandler(mock)

	body := `{"name": "X"}`
	req := httptest.NewRequest(http.MethodPut, "/api/v1/policies/550e8400-e29b-41d4-a716-446655440000", strings.NewReader(body))
	req.Header.Set("X-Tenant-ID", "tenant-123")
	w := httptest.NewRecorder()

	handler.handlePolicyByID(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestPolicyAPIHandler_UpdatePolicy_NotFound(t *testing.T) {
	mock := &mockPolicyService{
		updatePolicyFunc: func(ctx context.Context, tenantID, policyID string, req *UpdatePolicyRequest, updatedBy string) (*PolicyResource, error) {
			return nil, nil
		},
	}
	handler := NewPolicyAPIHandler(mock)

	body := `{"name": "Updated Policy"}`
	req := httptest.NewRequest(http.MethodPut, "/api/v1/policies/550e8400-e29b-41d4-a716-446655440000", strings.NewReader(body))
	req.Header.Set("X-Tenant-ID", "tenant-123")
	w := httptest.NewRecorder()

	handler.handlePolicyByID(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("Expected status %d, got %d", http.StatusNotFound, w.Code)
	}
}

func TestPolicyAPIHandler_DeletePolicy(t *testing.T) {
	policy := testPolicyResource()
	mock := &mockPolicyService{
		getPolicyFunc: func(ctx context.Context, tenantID, policyID string) (*PolicyResource, error) {
			return policy, nil
		},
		deletePolicyFunc: func(ctx context.Context, tenantID, policyID string, deletedBy string) error {
			return nil
		},
	}
	handler := NewPolicyAPIHandler(mock)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/policies/550e8400-e29b-41d4-a716-446655440000", nil)
	req.Header.Set("X-Tenant-ID", "tenant-123")
	req.Header.Set("X-User-ID", "user-1")
	w := httptest.NewRecorder()

	handler.handlePolicyByID(w, req)

	if w.Code != http.StatusNoContent {
		t.Errorf("Expected status %d, got %d", http.StatusNoContent, w.Code)
	}
}

func TestPolicyAPIHandler_DeletePolicy_NotFound(t *testing.T) {
	mock := &mockPolicyService{
		getPolicyFunc: func(ctx context.Context, tenantID, policyID string) (*PolicyResource, error) {
			return nil, nil
		},
	}
	handler := NewPolicyAPIHandler(mock)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/policies/550e8400-e29b-41d4-a716-446655440000", nil)
	req.Header.Set("X-Tenant-ID", "tenant-123")
	w := httptest.NewRecorder()

	handler.handlePolicyByID(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("Expected status %d, got %d", http.StatusNotFound, w.Code)
	}
}

func TestPolicyAPIHandler_DeletePolicy_GetError(t *testing.T) {
	mock := &mockPolicyService{
		getPolicyFunc: func(ctx context.Context, tenantID, policyID string) (*PolicyResource, error) {
			return nil, errors.New("database error")
		},
	}
	handler := NewPolicyAPIHandler(mock)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/policies/550e8400-e29b-41d4-a716-446655440000", nil)
	req.Header.Set("X-Tenant-ID", "tenant-123")
	w := httptest.NewRecorder()

	handler.handlePolicyByID(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("Expected status %d, got %d", http.StatusInternalServerError, w.Code)
	}
}

func TestPolicyAPIHandler_DeletePolicy_DeleteError(t *testing.T) {
	policy := testPolicyResource()
	mock := &mockPolicyService{
		getPolicyFunc: func(ctx context.Context, tenantID, policyID string) (*PolicyResource, error) {
			return policy, nil
		},
		deletePolicyFunc: func(ctx context.Context, tenantID, policyID string, deletedBy string) error {
			return errors.New("delete error")
		},
	}
	handler := NewPolicyAPIHandler(mock)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/policies/550e8400-e29b-41d4-a716-446655440000", nil)
	req.Header.Set("X-Tenant-ID", "tenant-123")
	w := httptest.NewRecorder()

	handler.handlePolicyByID(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("Expected status %d, got %d", http.StatusInternalServerError, w.Code)
	}
}

func TestPolicyAPIHandler_TestPolicy(t *testing.T) {
	mock := &mockPolicyService{
		testPolicyFunc: func(ctx context.Context, tenantID, policyID string, req *TestPolicyRequest) (*TestPolicyResponse, error) {
			return &TestPolicyResponse{
				Matched:     true,
				Blocked:     true,
				Explanation: "Policy matched",
				EvalTimeMs:  1.5,
			}, nil
		},
	}
	handler := NewPolicyAPIHandler(mock)

	body := `{"query": "show me passwords"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/policies/550e8400-e29b-41d4-a716-446655440000/test", strings.NewReader(body))
	req.Header.Set("X-Tenant-ID", "tenant-123")
	w := httptest.NewRecorder()

	handler.handlePolicyByID(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
	}

	var resp TestPolicyResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}
	if !resp.Matched {
		t.Error("Expected policy to match")
	}
}

func TestPolicyAPIHandler_TestPolicy_InvalidJSON(t *testing.T) {
	mock := &mockPolicyService{}
	handler := NewPolicyAPIHandler(mock)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/policies/550e8400-e29b-41d4-a716-446655440000/test", strings.NewReader("invalid"))
	req.Header.Set("X-Tenant-ID", "tenant-123")
	w := httptest.NewRecorder()

	handler.handlePolicyByID(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestPolicyAPIHandler_TestPolicy_MissingQuery(t *testing.T) {
	mock := &mockPolicyService{}
	handler := NewPolicyAPIHandler(mock)

	body := `{}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/policies/550e8400-e29b-41d4-a716-446655440000/test", strings.NewReader(body))
	req.Header.Set("X-Tenant-ID", "tenant-123")
	w := httptest.NewRecorder()

	handler.handlePolicyByID(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestPolicyAPIHandler_TestPolicy_NotFound(t *testing.T) {
	mock := &mockPolicyService{
		testPolicyFunc: func(ctx context.Context, tenantID, policyID string, req *TestPolicyRequest) (*TestPolicyResponse, error) {
			return nil, errors.New("policy not found")
		},
	}
	handler := NewPolicyAPIHandler(mock)

	body := `{"query": "test"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/policies/550e8400-e29b-41d4-a716-446655440000/test", strings.NewReader(body))
	req.Header.Set("X-Tenant-ID", "tenant-123")
	w := httptest.NewRecorder()

	handler.handlePolicyByID(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("Expected status %d, got %d", http.StatusNotFound, w.Code)
	}
}

func TestPolicyAPIHandler_TestPolicy_Error(t *testing.T) {
	mock := &mockPolicyService{
		testPolicyFunc: func(ctx context.Context, tenantID, policyID string, req *TestPolicyRequest) (*TestPolicyResponse, error) {
			return nil, errors.New("some other error")
		},
	}
	handler := NewPolicyAPIHandler(mock)

	body := `{"query": "test"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/policies/550e8400-e29b-41d4-a716-446655440000/test", strings.NewReader(body))
	req.Header.Set("X-Tenant-ID", "tenant-123")
	w := httptest.NewRecorder()

	handler.handlePolicyByID(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("Expected status %d, got %d", http.StatusInternalServerError, w.Code)
	}
}

func TestPolicyAPIHandler_GetPolicyVersions(t *testing.T) {
	mock := &mockPolicyService{
		getPolicyVersionsFunc: func(ctx context.Context, tenantID, policyID string) (*PolicyVersionResponse, error) {
			return &PolicyVersionResponse{
				Versions: []PolicyVersionEntry{
					{
						Version:    1,
						ChangedBy:  "user-1",
						ChangedAt:  time.Now(),
						ChangeType: "create",
					},
				},
			}, nil
		},
	}
	handler := NewPolicyAPIHandler(mock)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/policies/550e8400-e29b-41d4-a716-446655440000/versions", nil)
	req.Header.Set("X-Tenant-ID", "tenant-123")
	w := httptest.NewRecorder()

	handler.handlePolicyByID(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
	}

	var resp PolicyVersionResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}
	if len(resp.Versions) != 1 {
		t.Errorf("Expected 1 version, got %d", len(resp.Versions))
	}
}

func TestPolicyAPIHandler_GetPolicyVersions_Error(t *testing.T) {
	mock := &mockPolicyService{
		getPolicyVersionsFunc: func(ctx context.Context, tenantID, policyID string) (*PolicyVersionResponse, error) {
			return nil, errors.New("database error")
		},
	}
	handler := NewPolicyAPIHandler(mock)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/policies/550e8400-e29b-41d4-a716-446655440000/versions", nil)
	req.Header.Set("X-Tenant-ID", "tenant-123")
	w := httptest.NewRecorder()

	handler.handlePolicyByID(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("Expected status %d, got %d", http.StatusInternalServerError, w.Code)
	}
}

func TestPolicyAPIHandler_HandlePolicyByID_Options(t *testing.T) {
	mock := &mockPolicyService{}
	handler := NewPolicyAPIHandler(mock)

	req := httptest.NewRequest(http.MethodOptions, "/api/v1/policies/550e8400-e29b-41d4-a716-446655440000", nil)
	req.Header.Set("X-Tenant-ID", "tenant-123")
	req.Header.Set("Origin", "https://app.getaxonflow.com")
	w := httptest.NewRecorder()

	handler.handlePolicyByID(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
	}
}

func TestPolicyAPIHandler_HandlePolicyByID_MethodNotAllowed(t *testing.T) {
	mock := &mockPolicyService{}
	handler := NewPolicyAPIHandler(mock)

	req := httptest.NewRequest(http.MethodPatch, "/api/v1/policies/550e8400-e29b-41d4-a716-446655440000", nil)
	req.Header.Set("X-Tenant-ID", "tenant-123")
	w := httptest.NewRecorder()

	handler.handlePolicyByID(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected status %d, got %d", http.StatusMethodNotAllowed, w.Code)
	}
}

func TestPolicyAPIHandler_HandleImport(t *testing.T) {
	mock := &mockPolicyService{
		importPoliciesFunc: func(ctx context.Context, tenantID string, req *ImportPoliciesRequest, importedBy string) (*ImportPoliciesResponse, error) {
			return &ImportPoliciesResponse{
				Created: 2,
				Updated: 0,
				Skipped: 0,
			}, nil
		},
	}
	handler := NewPolicyAPIHandler(mock)

	body := `{
		"policies": [
			{"name": "Policy 1", "type": "content", "conditions": [{"field": "query", "operator": "contains", "value": "x"}], "actions": [{"type": "block"}]},
			{"name": "Policy 2", "type": "content", "conditions": [{"field": "query", "operator": "contains", "value": "y"}], "actions": [{"type": "block"}]}
		],
		"overwrite_mode": "skip"
	}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/policies/import", strings.NewReader(body))
	req.Header.Set("X-Tenant-ID", "tenant-123")
	req.Header.Set("X-User-ID", "user-1")
	w := httptest.NewRecorder()

	handler.handleImport(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
	}

	var resp ImportPoliciesResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}
	if resp.Created != 2 {
		t.Errorf("Expected 2 created, got %d", resp.Created)
	}
}

func TestPolicyAPIHandler_HandleImport_Options(t *testing.T) {
	mock := &mockPolicyService{}
	handler := NewPolicyAPIHandler(mock)

	req := httptest.NewRequest(http.MethodOptions, "/api/v1/policies/import", nil)
	req.Header.Set("Origin", "http://localhost:3000")
	w := httptest.NewRecorder()

	handler.handleImport(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
	}
}

func TestPolicyAPIHandler_HandleImport_MethodNotAllowed(t *testing.T) {
	mock := &mockPolicyService{}
	handler := NewPolicyAPIHandler(mock)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/policies/import", nil)
	w := httptest.NewRecorder()

	handler.handleImport(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected status %d, got %d", http.StatusMethodNotAllowed, w.Code)
	}
}

func TestPolicyAPIHandler_HandleImport_NoTenantID(t *testing.T) {
	mock := &mockPolicyService{}
	handler := NewPolicyAPIHandler(mock)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/policies/import", strings.NewReader(`{}`))
	w := httptest.NewRecorder()

	handler.handleImport(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status %d, got %d", http.StatusUnauthorized, w.Code)
	}
}

func TestPolicyAPIHandler_HandleImport_InvalidJSON(t *testing.T) {
	mock := &mockPolicyService{}
	handler := NewPolicyAPIHandler(mock)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/policies/import", strings.NewReader("invalid"))
	req.Header.Set("X-Tenant-ID", "tenant-123")
	w := httptest.NewRecorder()

	handler.handleImport(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestPolicyAPIHandler_HandleImport_EmptyPolicies(t *testing.T) {
	mock := &mockPolicyService{}
	handler := NewPolicyAPIHandler(mock)

	body := `{"policies": []}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/policies/import", strings.NewReader(body))
	req.Header.Set("X-Tenant-ID", "tenant-123")
	w := httptest.NewRecorder()

	handler.handleImport(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, w.Code)
	}

	var resp PolicyAPIError
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}
	if !strings.Contains(resp.Error.Message, "At least one policy") {
		t.Errorf("Expected message about empty policies, got %s", resp.Error.Message)
	}
}

func TestPolicyAPIHandler_HandleImport_TooManyPolicies(t *testing.T) {
	mock := &mockPolicyService{}
	handler := NewPolicyAPIHandler(mock)

	// Create 101 policies
	policies := make([]CreatePolicyRequest, 101)
	for i := range policies {
		policies[i] = CreatePolicyRequest{
			Name:       "Policy",
			Type:       "content",
			Conditions: []PolicyCondition{{Field: "query", Operator: "contains", Value: "x"}},
			Actions:    []PolicyAction{{Type: "block"}},
		}
	}
	bodyBytes, _ := json.Marshal(ImportPoliciesRequest{Policies: policies})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/policies/import", bytes.NewReader(bodyBytes))
	req.Header.Set("X-Tenant-ID", "tenant-123")
	w := httptest.NewRecorder()

	handler.handleImport(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, w.Code)
	}

	var resp PolicyAPIError
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}
	if !strings.Contains(resp.Error.Message, "Maximum 100") {
		t.Errorf("Expected message about max policies, got %s", resp.Error.Message)
	}
}

func TestPolicyAPIHandler_HandleImport_ValidationError(t *testing.T) {
	mock := &mockPolicyService{
		importPoliciesFunc: func(ctx context.Context, tenantID string, req *ImportPoliciesRequest, importedBy string) (*ImportPoliciesResponse, error) {
			return nil, &ValidationError{
				Errors: []PolicyFieldError{
					{Field: "policies[0].name", Message: "Invalid"},
				},
			}
		},
	}
	handler := NewPolicyAPIHandler(mock)

	body := `{"policies": [{"name": "Test", "type": "content", "conditions": [{"field": "query", "operator": "contains", "value": "x"}], "actions": [{"type": "block"}]}]}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/policies/import", strings.NewReader(body))
	req.Header.Set("X-Tenant-ID", "tenant-123")
	w := httptest.NewRecorder()

	handler.handleImport(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, w.Code)
	}
}

func TestPolicyAPIHandler_HandleImport_Error(t *testing.T) {
	mock := &mockPolicyService{
		importPoliciesFunc: func(ctx context.Context, tenantID string, req *ImportPoliciesRequest, importedBy string) (*ImportPoliciesResponse, error) {
			return nil, errors.New("database error")
		},
	}
	handler := NewPolicyAPIHandler(mock)

	body := `{"policies": [{"name": "Test", "type": "content", "conditions": [{"field": "query", "operator": "contains", "value": "x"}], "actions": [{"type": "block"}]}]}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/policies/import", strings.NewReader(body))
	req.Header.Set("X-Tenant-ID", "tenant-123")
	w := httptest.NewRecorder()

	handler.handleImport(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("Expected status %d, got %d", http.StatusInternalServerError, w.Code)
	}
}

func TestPolicyAPIHandler_HandleExport(t *testing.T) {
	mock := &mockPolicyService{
		exportPoliciesFunc: func(ctx context.Context, tenantID string) (*ExportPoliciesResponse, error) {
			return &ExportPoliciesResponse{
				Policies:   []PolicyResource{*testPolicyResource()},
				ExportedAt: time.Now(),
				TenantID:   tenantID,
			}, nil
		},
	}
	handler := NewPolicyAPIHandler(mock)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/policies/export", nil)
	req.Header.Set("X-Tenant-ID", "tenant-123")
	w := httptest.NewRecorder()

	handler.handleExport(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
	}

	// Check Content-Disposition header
	if w.Header().Get("Content-Disposition") != "attachment; filename=policies-export.json" {
		t.Errorf("Expected Content-Disposition header, got %s", w.Header().Get("Content-Disposition"))
	}

	var resp ExportPoliciesResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}
	if len(resp.Policies) != 1 {
		t.Errorf("Expected 1 policy, got %d", len(resp.Policies))
	}
}

func TestPolicyAPIHandler_HandleExport_Options(t *testing.T) {
	mock := &mockPolicyService{}
	handler := NewPolicyAPIHandler(mock)

	req := httptest.NewRequest(http.MethodOptions, "/api/v1/policies/export", nil)
	req.Header.Set("Origin", "http://localhost:8080")
	w := httptest.NewRecorder()

	handler.handleExport(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
	}
}

func TestPolicyAPIHandler_HandleExport_MethodNotAllowed(t *testing.T) {
	mock := &mockPolicyService{}
	handler := NewPolicyAPIHandler(mock)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/policies/export", nil)
	w := httptest.NewRecorder()

	handler.handleExport(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("Expected status %d, got %d", http.StatusMethodNotAllowed, w.Code)
	}
}

func TestPolicyAPIHandler_HandleExport_NoTenantID(t *testing.T) {
	mock := &mockPolicyService{}
	handler := NewPolicyAPIHandler(mock)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/policies/export", nil)
	w := httptest.NewRecorder()

	handler.handleExport(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status %d, got %d", http.StatusUnauthorized, w.Code)
	}
}

func TestPolicyAPIHandler_HandleExport_Error(t *testing.T) {
	mock := &mockPolicyService{
		exportPoliciesFunc: func(ctx context.Context, tenantID string) (*ExportPoliciesResponse, error) {
			return nil, errors.New("database error")
		},
	}
	handler := NewPolicyAPIHandler(mock)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/policies/export", nil)
	req.Header.Set("X-Tenant-ID", "tenant-123")
	w := httptest.NewRecorder()

	handler.handleExport(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("Expected status %d, got %d", http.StatusInternalServerError, w.Code)
	}
}

func TestPolicyAPIHandler_GetTenantID(t *testing.T) {
	handler := &PolicyAPIHandler{}

	tests := []struct {
		name     string
		setupReq func(*http.Request)
		expected string
	}{
		{
			name: "from header",
			setupReq: func(r *http.Request) {
				r.Header.Set("X-Tenant-ID", "tenant-from-header")
			},
			expected: "tenant-from-header",
		},
		{
			name: "from context",
			setupReq: func(r *http.Request) {
				ctx := context.WithValue(r.Context(), "tenant_id", "tenant-from-context")
				*r = *r.WithContext(ctx)
			},
			expected: "tenant-from-context",
		},
		{
			name:     "empty when neither",
			setupReq: func(r *http.Request) {},
			expected: "",
		},
		{
			name: "header takes precedence",
			setupReq: func(r *http.Request) {
				r.Header.Set("X-Tenant-ID", "header-tenant")
				ctx := context.WithValue(r.Context(), "tenant_id", "context-tenant")
				*r = *r.WithContext(ctx)
			},
			expected: "header-tenant",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			tt.setupReq(req)

			got := handler.getTenantID(req)
			if got != tt.expected {
				t.Errorf("getTenantID() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestPolicyAPIHandler_GetUserID(t *testing.T) {
	handler := &PolicyAPIHandler{}

	tests := []struct {
		name     string
		setupReq func(*http.Request)
		expected string
	}{
		{
			name: "from header",
			setupReq: func(r *http.Request) {
				r.Header.Set("X-User-ID", "user-from-header")
			},
			expected: "user-from-header",
		},
		{
			name: "from context",
			setupReq: func(r *http.Request) {
				ctx := context.WithValue(r.Context(), "user_id", "user-from-context")
				*r = *r.WithContext(ctx)
			},
			expected: "user-from-context",
		},
		{
			name:     "default to system",
			setupReq: func(r *http.Request) {},
			expected: "system",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			tt.setupReq(req)

			got := handler.getUserID(req)
			if got != tt.expected {
				t.Errorf("getUserID() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestPolicyAPIHandler_WriteValidationError(t *testing.T) {
	handler := &PolicyAPIHandler{}

	errors := []PolicyFieldError{
		{Field: "name", Message: "Name is required"},
		{Field: "type", Message: "Invalid type"},
	}

	w := httptest.NewRecorder()
	handler.writeValidationError(w, errors)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, w.Code)
	}

	var resp PolicyAPIError
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("Failed to decode response: %v", err)
	}

	if resp.Error.Code != "VALIDATION_ERROR" {
		t.Errorf("Expected code VALIDATION_ERROR, got %s", resp.Error.Code)
	}
	if len(resp.Error.Details) != 2 {
		t.Errorf("Expected 2 error details, got %d", len(resp.Error.Details))
	}
}

func TestPolicyService_ValidateCreateRequest(t *testing.T) {
	service := &PolicyService{}

	tests := []struct {
		name    string
		req     CreatePolicyRequest
		wantErr bool
	}{
		{
			name: "valid request",
			req: CreatePolicyRequest{
				Name:        "Test Policy",
				Description: "A test policy",
				Type:        "content",
				Conditions: []PolicyCondition{
					{Field: "query", Operator: "contains", Value: "sensitive"},
				},
				Actions: []PolicyAction{
					{Type: "block", Config: map[string]interface{}{"message": "Blocked"}},
				},
				Priority: 100,
				Enabled:  true,
			},
			wantErr: false,
		},
		{
			name: "missing name",
			req: CreatePolicyRequest{
				Type: "content",
				Conditions: []PolicyCondition{
					{Field: "query", Operator: "contains", Value: "sensitive"},
				},
				Actions: []PolicyAction{
					{Type: "block", Config: map[string]interface{}{}},
				},
			},
			wantErr: true,
		},
		{
			name: "invalid type",
			req: CreatePolicyRequest{
				Name: "Test Policy",
				Type: "invalid_type",
				Conditions: []PolicyCondition{
					{Field: "query", Operator: "contains", Value: "sensitive"},
				},
				Actions: []PolicyAction{
					{Type: "block", Config: map[string]interface{}{}},
				},
			},
			wantErr: true,
		},
		{
			name: "missing conditions",
			req: CreatePolicyRequest{
				Name: "Test Policy",
				Type: "content",
				Actions: []PolicyAction{
					{Type: "block", Config: map[string]interface{}{}},
				},
			},
			wantErr: true,
		},
		{
			name: "missing actions",
			req: CreatePolicyRequest{
				Name: "Test Policy",
				Type: "content",
				Conditions: []PolicyCondition{
					{Field: "query", Operator: "contains", Value: "sensitive"},
				},
			},
			wantErr: true,
		},
		{
			name: "invalid operator",
			req: CreatePolicyRequest{
				Name: "Test Policy",
				Type: "content",
				Conditions: []PolicyCondition{
					{Field: "query", Operator: "invalid_op", Value: "sensitive"},
				},
				Actions: []PolicyAction{
					{Type: "block", Config: map[string]interface{}{}},
				},
			},
			wantErr: true,
		},
		{
			name: "invalid action type",
			req: CreatePolicyRequest{
				Name: "Test Policy",
				Type: "content",
				Conditions: []PolicyCondition{
					{Field: "query", Operator: "contains", Value: "sensitive"},
				},
				Actions: []PolicyAction{
					{Type: "invalid_action", Config: map[string]interface{}{}},
				},
			},
			wantErr: true,
		},
		{
			name: "priority out of range",
			req: CreatePolicyRequest{
				Name: "Test Policy",
				Type: "content",
				Conditions: []PolicyCondition{
					{Field: "query", Operator: "contains", Value: "sensitive"},
				},
				Actions: []PolicyAction{
					{Type: "block", Config: map[string]interface{}{}},
				},
				Priority: 2000, // Max is 1000
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := service.validateCreateRequest(&tt.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateCreateRequest() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestPolicyService_EvaluateCondition(t *testing.T) {
	service := &PolicyService{}

	tests := []struct {
		name      string
		condition PolicyCondition
		request   *TestPolicyRequest
		want      bool
	}{
		{
			name:      "contains - match",
			condition: PolicyCondition{Field: "query", Operator: "contains", Value: "password"},
			request:   &TestPolicyRequest{Query: "Show me the password for admin"},
			want:      true,
		},
		{
			name:      "contains - no match",
			condition: PolicyCondition{Field: "query", Operator: "contains", Value: "password"},
			request:   &TestPolicyRequest{Query: "Show me the weather"},
			want:      false,
		},
		{
			name:      "equals - match",
			condition: PolicyCondition{Field: "request_type", Operator: "equals", Value: "query"},
			request:   &TestPolicyRequest{RequestType: "query"},
			want:      true,
		},
		{
			name:      "equals - no match",
			condition: PolicyCondition{Field: "request_type", Operator: "equals", Value: "mutation"},
			request:   &TestPolicyRequest{RequestType: "query"},
			want:      false,
		},
		{
			name:      "regex - match SSN pattern",
			condition: PolicyCondition{Field: "query", Operator: "regex", Value: `\d{3}-\d{2}-\d{4}`},
			request:   &TestPolicyRequest{Query: "Find record for 123-45-6789"},
			want:      true,
		},
		{
			name:      "regex - no match",
			condition: PolicyCondition{Field: "query", Operator: "regex", Value: `\d{3}-\d{2}-\d{4}`},
			request:   &TestPolicyRequest{Query: "Find record for John Doe"},
			want:      false,
		},
		{
			name:      "user field - match",
			condition: PolicyCondition{Field: "user.role", Operator: "equals", Value: "admin"},
			request:   &TestPolicyRequest{User: map[string]interface{}{"role": "admin"}},
			want:      true,
		},
		{
			name: "contains_any - match",
			condition: PolicyCondition{
				Field:    "query",
				Operator: "contains_any",
				Value:    []interface{}{"ssn", "password", "secret"},
			},
			request: &TestPolicyRequest{Query: "Show me the password"},
			want:    true,
		},
		{
			name: "in - match",
			condition: PolicyCondition{
				Field:    "request_type",
				Operator: "in",
				Value:    []interface{}{"query", "mutation"},
			},
			request: &TestPolicyRequest{RequestType: "query"},
			want:    true,
		},
		{
			name: "not_in - match",
			condition: PolicyCondition{
				Field:    "request_type",
				Operator: "not_in",
				Value:    []interface{}{"admin", "delete"},
			},
			request: &TestPolicyRequest{RequestType: "query"},
			want:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := service.evaluateCondition(tt.condition, tt.request)
			if got != tt.want {
				t.Errorf("evaluateCondition() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPolicyAPIHandler_CORSHeaders(t *testing.T) {
	handler := &PolicyAPIHandler{}

	tests := []struct {
		name           string
		origin         string
		expectAllowed  bool
	}{
		{
			name:          "localhost:3000 allowed",
			origin:        "http://localhost:3000",
			expectAllowed: true,
		},
		{
			name:          "localhost:8080 allowed",
			origin:        "http://localhost:8080",
			expectAllowed: true,
		},
		{
			name:          "app.getaxonflow.com allowed",
			origin:        "https://app.getaxonflow.com",
			expectAllowed: true,
		},
		{
			name:          "staging.getaxonflow.com allowed",
			origin:        "https://staging.getaxonflow.com",
			expectAllowed: true,
		},
		{
			name:          "demo.getaxonflow.com allowed",
			origin:        "https://demo.getaxonflow.com",
			expectAllowed: true,
		},
		{
			name:          "customer.getaxonflow.com allowed",
			origin:        "https://customer.getaxonflow.com",
			expectAllowed: true,
		},
		{
			name:          "evil.com not allowed",
			origin:        "https://evil.com",
			expectAllowed: false,
		},
		{
			name:          "empty origin not allowed",
			origin:        "",
			expectAllowed: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodOptions, "/api/v1/policies", nil)
			if tt.origin != "" {
				r.Header.Set("Origin", tt.origin)
			}
			w := httptest.NewRecorder()

			handler.handleCORS(w, r)

			if w.Code != http.StatusOK {
				t.Errorf("Expected status 200, got %d", w.Code)
			}

			allowOrigin := w.Header().Get("Access-Control-Allow-Origin")
			if tt.expectAllowed {
				if allowOrigin != tt.origin {
					t.Errorf("Expected Access-Control-Allow-Origin to be %s, got %s", tt.origin, allowOrigin)
				}
			} else {
				if allowOrigin != "" {
					t.Errorf("Expected no Access-Control-Allow-Origin header for disallowed origin, got %s", allowOrigin)
				}
			}

			// Always check other CORS headers are set
			if w.Header().Get("Access-Control-Allow-Methods") == "" {
				t.Error("Expected Access-Control-Allow-Methods header")
			}
			if w.Header().Get("Access-Control-Allow-Headers") == "" {
				t.Error("Expected Access-Control-Allow-Headers header")
			}
			if w.Header().Get("Access-Control-Max-Age") != "86400" {
				t.Errorf("Expected Access-Control-Max-Age to be 86400, got %s", w.Header().Get("Access-Control-Max-Age"))
			}
		})
	}
}

func TestPolicyAPIHandler_ErrorResponses(t *testing.T) {
	handler := &PolicyAPIHandler{}

	tests := []struct {
		name    string
		code    string
		message string
		status  int
	}{
		{
			name:    "not found",
			code:    "NOT_FOUND",
			message: "Policy not found",
			status:  http.StatusNotFound,
		},
		{
			name:    "unauthorized",
			code:    "UNAUTHORIZED",
			message: "Missing tenant ID",
			status:  http.StatusUnauthorized,
		},
		{
			name:    "validation error",
			code:    "VALIDATION_ERROR",
			message: "Invalid request",
			status:  http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			handler.writeError(w, tt.status, tt.code, tt.message)

			if w.Code != tt.status {
				t.Errorf("Expected status %d, got %d", tt.status, w.Code)
			}

			var resp PolicyAPIError
			if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
				t.Fatalf("Failed to decode response: %v", err)
			}

			if resp.Error.Code != tt.code {
				t.Errorf("Expected code %s, got %s", tt.code, resp.Error.Code)
			}

			if resp.Error.Message != tt.message {
				t.Errorf("Expected message %s, got %s", tt.message, resp.Error.Message)
			}
		})
	}
}

func TestCreatePolicyRequest_JSON(t *testing.T) {
	jsonData := `{
		"name": "Test Policy",
		"description": "A test policy for validation",
		"type": "content",
		"conditions": [
			{"field": "query", "operator": "contains", "value": "password"}
		],
		"actions": [
			{"type": "block", "config": {"message": "Blocked for security"}}
		],
		"priority": 100,
		"enabled": true
	}`

	var req CreatePolicyRequest
	if err := json.NewDecoder(bytes.NewBufferString(jsonData)).Decode(&req); err != nil {
		t.Fatalf("Failed to decode JSON: %v", err)
	}

	// Validate parsed values
	tests := []struct {
		name     string
		got      interface{}
		expected interface{}
	}{
		{"Name", req.Name, "Test Policy"},
		{"Type", req.Type, "content"},
		{"ConditionsLen", len(req.Conditions), 1},
		{"ActionsLen", len(req.Actions), 1},
		{"Priority", req.Priority, 100},
		{"Enabled", req.Enabled, true},
	}

	for _, tt := range tests {
		if tt.got != tt.expected {
			t.Errorf("%s: expected %v, got %v", tt.name, tt.expected, tt.got)
		}
	}
}

func TestPolicyAPIHandler_ListPolicies_QueryParams(t *testing.T) {
	var capturedParams ListPoliciesParams
	mock := &mockPolicyService{
		listPoliciesFunc: func(ctx context.Context, tenantID string, params ListPoliciesParams) (*PoliciesListResponse, error) {
			capturedParams = params
			return &PoliciesListResponse{
				Policies:   []PolicyResource{},
				Pagination: PaginationMeta{Page: params.Page, PageSize: params.PageSize},
			}, nil
		},
	}
	handler := NewPolicyAPIHandler(mock)

	tests := []struct {
		name             string
		query            string
		expectedPage     int
		expectedPageSize int
		expectedType     string
		expectedSearch   string
		expectedEnabled  *bool
	}{
		{
			name:             "default values",
			query:            "",
			expectedPage:     1,
			expectedPageSize: 20,
		},
		{
			name:             "custom page and page_size",
			query:            "page=3&page_size=50",
			expectedPage:     3,
			expectedPageSize: 50,
		},
		{
			name:             "page_size capped at 100",
			query:            "page_size=200",
			expectedPage:     1,
			expectedPageSize: 20, // Should stay at default when out of range
		},
		{
			name:             "type filter",
			query:            "type=content",
			expectedPage:     1,
			expectedPageSize: 20,
			expectedType:     "content",
		},
		{
			name:             "search filter",
			query:            "search=security",
			expectedPage:     1,
			expectedPageSize: 20,
			expectedSearch:   "security",
		},
		{
			name:             "enabled filter true",
			query:            "enabled=true",
			expectedPage:     1,
			expectedPageSize: 20,
			expectedEnabled:  boolPtr(true),
		},
		{
			name:             "enabled filter false",
			query:            "enabled=false",
			expectedPage:     1,
			expectedPageSize: 20,
			expectedEnabled:  boolPtr(false),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			url := "/api/v1/policies"
			if tt.query != "" {
				url += "?" + tt.query
			}
			req := httptest.NewRequest(http.MethodGet, url, nil)
			req.Header.Set("X-Tenant-ID", "tenant-123")
			w := httptest.NewRecorder()

			handler.handlePolicies(w, req)

			if w.Code != http.StatusOK {
				t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
			}

			if capturedParams.Page != tt.expectedPage {
				t.Errorf("Expected page %d, got %d", tt.expectedPage, capturedParams.Page)
			}
			if capturedParams.PageSize != tt.expectedPageSize {
				t.Errorf("Expected page_size %d, got %d", tt.expectedPageSize, capturedParams.PageSize)
			}
			if capturedParams.Type != tt.expectedType {
				t.Errorf("Expected type %s, got %s", tt.expectedType, capturedParams.Type)
			}
			if capturedParams.Search != tt.expectedSearch {
				t.Errorf("Expected search %s, got %s", tt.expectedSearch, capturedParams.Search)
			}
			if tt.expectedEnabled != nil {
				if capturedParams.Enabled == nil {
					t.Error("Expected enabled to be set")
				} else if *capturedParams.Enabled != *tt.expectedEnabled {
					t.Errorf("Expected enabled %v, got %v", *tt.expectedEnabled, *capturedParams.Enabled)
				}
			}
		})
	}
}

func boolPtr(b bool) *bool {
	return &b
}

func stringPtr(s string) *string {
	return &s
}

func intPtr(i int) *int {
	return &i
}

func TestPolicyService_ValidateUpdateRequest(t *testing.T) {
	service := &PolicyService{}

	tests := []struct {
		name    string
		req     UpdatePolicyRequest
		wantErr bool
	}{
		{
			name:    "empty request is valid",
			req:     UpdatePolicyRequest{},
			wantErr: false,
		},
		{
			name: "valid name update",
			req: UpdatePolicyRequest{
				Name: stringPtr("Updated Name"),
			},
			wantErr: false,
		},
		{
			name: "name too short",
			req: UpdatePolicyRequest{
				Name: stringPtr("AB"),
			},
			wantErr: true,
		},
		{
			name: "name too long",
			req: UpdatePolicyRequest{
				Name: stringPtr(strings.Repeat("a", 101)),
			},
			wantErr: true,
		},
		{
			name: "description too long",
			req: UpdatePolicyRequest{
				Description: stringPtr(strings.Repeat("a", 501)),
			},
			wantErr: true,
		},
		{
			name: "valid description",
			req: UpdatePolicyRequest{
				Description: stringPtr("A valid description"),
			},
			wantErr: false,
		},
		{
			name: "invalid type",
			req: UpdatePolicyRequest{
				Type: stringPtr("invalid_type"),
			},
			wantErr: true,
		},
		{
			name: "valid type",
			req: UpdatePolicyRequest{
				Type: stringPtr("content"),
			},
			wantErr: false,
		},
		{
			name: "invalid condition in update",
			req: UpdatePolicyRequest{
				Conditions: []PolicyCondition{
					{Field: "", Operator: "contains", Value: "test"},
				},
			},
			wantErr: true,
		},
		{
			name: "valid conditions",
			req: UpdatePolicyRequest{
				Conditions: []PolicyCondition{
					{Field: "query", Operator: "contains", Value: "test"},
				},
			},
			wantErr: false,
		},
		{
			name: "invalid action in update",
			req: UpdatePolicyRequest{
				Actions: []PolicyAction{
					{Type: "invalid_action"},
				},
			},
			wantErr: true,
		},
		{
			name: "valid actions",
			req: UpdatePolicyRequest{
				Actions: []PolicyAction{
					{Type: "block"},
				},
			},
			wantErr: false,
		},
		{
			name: "priority too low",
			req: UpdatePolicyRequest{
				Priority: intPtr(-1),
			},
			wantErr: true,
		},
		{
			name: "priority too high",
			req: UpdatePolicyRequest{
				Priority: intPtr(1001),
			},
			wantErr: true,
		},
		{
			name: "valid priority",
			req: UpdatePolicyRequest{
				Priority: intPtr(500),
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := service.validateUpdateRequest(&tt.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateUpdateRequest() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestPolicyService_EvaluateConditions(t *testing.T) {
	service := &PolicyService{}

	tests := []struct {
		name       string
		conditions []PolicyCondition
		request    *TestPolicyRequest
		want       bool
	}{
		{
			name: "all conditions match",
			conditions: []PolicyCondition{
				{Field: "query", Operator: "contains", Value: "password"},
				{Field: "request_type", Operator: "equals", Value: "query"},
			},
			request: &TestPolicyRequest{
				Query:       "show me the password",
				RequestType: "query",
			},
			want: true,
		},
		{
			name: "first condition fails",
			conditions: []PolicyCondition{
				{Field: "query", Operator: "contains", Value: "secret"},
				{Field: "request_type", Operator: "equals", Value: "query"},
			},
			request: &TestPolicyRequest{
				Query:       "show me the password",
				RequestType: "query",
			},
			want: false,
		},
		{
			name: "second condition fails",
			conditions: []PolicyCondition{
				{Field: "query", Operator: "contains", Value: "password"},
				{Field: "request_type", Operator: "equals", Value: "mutation"},
			},
			request: &TestPolicyRequest{
				Query:       "show me the password",
				RequestType: "query",
			},
			want: false,
		},
		{
			name:       "empty conditions matches",
			conditions: []PolicyCondition{},
			request: &TestPolicyRequest{
				Query: "anything",
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := service.evaluateConditions(tt.conditions, tt.request)
			if got != tt.want {
				t.Errorf("evaluateConditions() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPolicyService_EvaluateOperator_Additional(t *testing.T) {
	service := &PolicyService{}

	tests := []struct {
		name           string
		operator       string
		fieldValue     interface{}
		conditionValue interface{}
		want           bool
	}{
		{
			name:           "not_equals match",
			operator:       "not_equals",
			fieldValue:     "foo",
			conditionValue: "bar",
			want:           true,
		},
		{
			name:           "not_equals no match",
			operator:       "not_equals",
			fieldValue:     "foo",
			conditionValue: "foo",
			want:           false,
		},
		{
			name:           "not_contains match",
			operator:       "not_contains",
			fieldValue:     "hello world",
			conditionValue: "foo",
			want:           true,
		},
		{
			name:           "not_contains no match",
			operator:       "not_contains",
			fieldValue:     "hello world",
			conditionValue: "world",
			want:           false,
		},
		{
			name:           "contains_any no match",
			operator:       "contains_any",
			fieldValue:     "hello world",
			conditionValue: []interface{}{"foo", "bar"},
			want:           false,
		},
		{
			name:           "regex invalid pattern",
			operator:       "regex",
			fieldValue:     "test",
			conditionValue: "[invalid",
			want:           false,
		},
		{
			name:           "regex non-string value",
			operator:       "regex",
			fieldValue:     "test",
			conditionValue: 123,
			want:           false,
		},
		{
			name:           "in no match",
			operator:       "in",
			fieldValue:     "foo",
			conditionValue: []interface{}{"bar", "baz"},
			want:           false,
		},
		{
			name:           "not_in match when value not in list",
			operator:       "not_in",
			fieldValue:     "foo",
			conditionValue: []interface{}{"bar", "baz"},
			want:           true,
		},
		{
			name:           "not_in no match when value in list",
			operator:       "not_in",
			fieldValue:     "bar",
			conditionValue: []interface{}{"bar", "baz"},
			want:           false,
		},
		{
			name:           "unknown operator",
			operator:       "unknown_op",
			fieldValue:     "foo",
			conditionValue: "bar",
			want:           false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := service.evaluateOperator(tt.operator, tt.fieldValue, tt.conditionValue)
			if got != tt.want {
				t.Errorf("evaluateOperator() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPolicyService_EvaluateCondition_Additional(t *testing.T) {
	service := &PolicyService{}

	tests := []struct {
		name      string
		condition PolicyCondition
		request   *TestPolicyRequest
		want      bool
	}{
		{
			name:      "context field match",
			condition: PolicyCondition{Field: "context.env", Operator: "equals", Value: "production"},
			request: &TestPolicyRequest{
				Context: map[string]interface{}{"env": "production"},
			},
			want: true,
		},
		{
			name:      "context field no match",
			condition: PolicyCondition{Field: "context.env", Operator: "equals", Value: "production"},
			request: &TestPolicyRequest{
				Context: map[string]interface{}{"env": "staging"},
			},
			want: false,
		},
		{
			name:      "user field nil user",
			condition: PolicyCondition{Field: "user.role", Operator: "equals", Value: "admin"},
			request:   &TestPolicyRequest{User: nil},
			want:      false,
		},
		{
			name:      "unknown field",
			condition: PolicyCondition{Field: "unknown_field", Operator: "equals", Value: "test"},
			request:   &TestPolicyRequest{Query: "test"},
			want:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := service.evaluateCondition(tt.condition, tt.request)
			if got != tt.want {
				t.Errorf("evaluateCondition() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPolicyService_ValidateCondition(t *testing.T) {
	service := &PolicyService{}

	tests := []struct {
		name      string
		condition PolicyCondition
		wantErr   bool
	}{
		{
			name:      "missing field",
			condition: PolicyCondition{Field: "", Operator: "contains", Value: "test"},
			wantErr:   true,
		},
		{
			name:      "missing operator",
			condition: PolicyCondition{Field: "query", Operator: "", Value: "test"},
			wantErr:   true,
		},
		{
			name:      "invalid operator",
			condition: PolicyCondition{Field: "query", Operator: "invalid_op", Value: "test"},
			wantErr:   true,
		},
		{
			name:      "valid regex",
			condition: PolicyCondition{Field: "query", Operator: "regex", Value: `\d{3}-\d{2}-\d{4}`},
			wantErr:   false,
		},
		{
			name:      "invalid regex",
			condition: PolicyCondition{Field: "query", Operator: "regex", Value: `[invalid`},
			wantErr:   true,
		},
		{
			name:      "valid contains",
			condition: PolicyCondition{Field: "query", Operator: "contains", Value: "test"},
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := service.validateCondition(tt.condition)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateCondition() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidationError_Error(t *testing.T) {
	err := &ValidationError{
		Errors: []PolicyFieldError{
			{Field: "name", Message: "Name is required"},
			{Field: "type", Message: "Invalid type"},
		},
	}

	got := err.Error()
	want := "name: Name is required; type: Invalid type"
	if got != want {
		t.Errorf("ValidationError.Error() = %v, want %v", got, want)
	}
}

func TestValidationError_Error_SingleError(t *testing.T) {
	err := &ValidationError{
		Errors: []PolicyFieldError{
			{Field: "name", Message: "Name is required"},
		},
	}

	got := err.Error()
	want := "name: Name is required"
	if got != want {
		t.Errorf("ValidationError.Error() = %v, want %v", got, want)
	}
}

func TestPolicyService_IsValidPolicyType(t *testing.T) {
	service := &PolicyService{}

	tests := []struct {
		policyType string
		want       bool
	}{
		{"content", true},
		{"user", true},
		{"risk", true},
		{"cost", true},
		{"invalid", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.policyType, func(t *testing.T) {
			got := service.isValidPolicyType(tt.policyType)
			if got != tt.want {
				t.Errorf("isValidPolicyType(%s) = %v, want %v", tt.policyType, got, tt.want)
			}
		})
	}
}

func TestPolicyAPIHandler_UpdatePolicy_ServiceError(t *testing.T) {
	mock := &mockPolicyService{
		updatePolicyFunc: func(ctx context.Context, tenantID, policyID string, req *UpdatePolicyRequest, updatedBy string) (*PolicyResource, error) {
			return nil, errors.New("database error")
		},
	}
	handler := NewPolicyAPIHandler(mock)

	body := `{"name": "Updated Policy"}`
	req := httptest.NewRequest(http.MethodPut, "/api/v1/policies/550e8400-e29b-41d4-a716-446655440000", strings.NewReader(body))
	req.Header.Set("X-Tenant-ID", "tenant-123")
	w := httptest.NewRecorder()

	handler.handlePolicyByID(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("Expected status %d, got %d", http.StatusInternalServerError, w.Code)
	}
}
