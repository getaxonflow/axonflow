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

	"github.com/google/uuid"
	"github.com/gorilla/mux"
)

// mockDynamicPolicyService implements PolicyServicer for testing
type mockDynamicPolicyService struct {
	listFunc     func(ctx context.Context, tenantID string, params ListPoliciesParams) (*PoliciesListResponse, error)
	getFunc      func(ctx context.Context, tenantID, policyID string) (*PolicyResource, error)
	createFunc   func(ctx context.Context, tenantID string, req *CreatePolicyRequest, userID string) (*PolicyResource, error)
	updateFunc   func(ctx context.Context, tenantID, policyID string, req *UpdatePolicyRequest, userID string) (*PolicyResource, error)
	deleteFunc   func(ctx context.Context, tenantID, policyID, userID string) error
	testFunc     func(ctx context.Context, tenantID, policyID string, req *TestPolicyRequest) (*TestPolicyResponse, error)
	versionsFunc func(ctx context.Context, tenantID, policyID string) (*PolicyVersionResponse, error)
	importFunc   func(ctx context.Context, tenantID string, req *ImportPoliciesRequest, userID string) (*ImportPoliciesResponse, error)
	exportFunc   func(ctx context.Context, tenantID string) (*ExportPoliciesResponse, error)
}

func (m *mockDynamicPolicyService) ListPolicies(ctx context.Context, tenantID string, params ListPoliciesParams) (*PoliciesListResponse, error) {
	if m.listFunc != nil {
		return m.listFunc(ctx, tenantID, params)
	}
	return &PoliciesListResponse{}, nil
}

func (m *mockDynamicPolicyService) GetPolicy(ctx context.Context, tenantID, policyID string) (*PolicyResource, error) {
	if m.getFunc != nil {
		return m.getFunc(ctx, tenantID, policyID)
	}
	return nil, nil
}

func (m *mockDynamicPolicyService) CreatePolicy(ctx context.Context, tenantID string, req *CreatePolicyRequest, userID string) (*PolicyResource, error) {
	if m.createFunc != nil {
		return m.createFunc(ctx, tenantID, req, userID)
	}
	return nil, nil
}

func (m *mockDynamicPolicyService) UpdatePolicy(ctx context.Context, tenantID, policyID string, req *UpdatePolicyRequest, userID string) (*PolicyResource, error) {
	if m.updateFunc != nil {
		return m.updateFunc(ctx, tenantID, policyID, req, userID)
	}
	return nil, nil
}

func (m *mockDynamicPolicyService) DeletePolicy(ctx context.Context, tenantID, policyID, userID string) error {
	if m.deleteFunc != nil {
		return m.deleteFunc(ctx, tenantID, policyID, userID)
	}
	return nil
}

func (m *mockDynamicPolicyService) TestPolicy(ctx context.Context, tenantID, policyID string, req *TestPolicyRequest) (*TestPolicyResponse, error) {
	if m.testFunc != nil {
		return m.testFunc(ctx, tenantID, policyID, req)
	}
	return nil, nil
}

func (m *mockDynamicPolicyService) GetPolicyVersions(ctx context.Context, tenantID, policyID string) (*PolicyVersionResponse, error) {
	if m.versionsFunc != nil {
		return m.versionsFunc(ctx, tenantID, policyID)
	}
	return nil, nil
}

func (m *mockDynamicPolicyService) ImportPolicies(ctx context.Context, tenantID string, req *ImportPoliciesRequest, userID string) (*ImportPoliciesResponse, error) {
	if m.importFunc != nil {
		return m.importFunc(ctx, tenantID, req, userID)
	}
	return nil, nil
}

func (m *mockDynamicPolicyService) ExportPolicies(ctx context.Context, tenantID string) (*ExportPoliciesResponse, error) {
	if m.exportFunc != nil {
		return m.exportFunc(ctx, tenantID)
	}
	return nil, nil
}

func TestDynamicPolicyAPI_ListDynamicPolicies(t *testing.T) {
	mockService := &mockDynamicPolicyService{
		listFunc: func(ctx context.Context, tenantID string, params ListPoliciesParams) (*PoliciesListResponse, error) {
			// Default: no category filter (returns all dynamic + media policies)
			if params.Category != "" {
				t.Errorf("Expected empty category filter (no filter), got '%s'", params.Category)
			}
			return &PoliciesListResponse{
				Policies: []PolicyResource{
					{
						ID:       uuid.New().String(),
						Name:     "Cost Limit Policy",
						Category: "dynamic-cost",
						Type:     "cost",
						Enabled:  true,
					},
				},
				Pagination: PaginationMeta{Page: 1, PageSize: 20, TotalItems: 1, TotalPages: 1},
			}, nil
		},
	}

	handler := NewDynamicPolicyAPIHandler(mockService)
	r := mux.NewRouter()
	handler.RegisterRoutes(r)

	req := httptest.NewRequest("GET", "/api/v1/dynamic-policies", nil)
	req.Header.Set("X-Tenant-ID", "test-tenant")
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var resp PoliciesListResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	if len(resp.Policies) != 1 {
		t.Errorf("Expected 1 policy, got %d", len(resp.Policies))
	}
}

func TestDynamicPolicyAPI_ListDynamicPolicies_MissingTenantID(t *testing.T) {
	handler := NewDynamicPolicyAPIHandler(&mockDynamicPolicyService{})
	r := mux.NewRouter()
	handler.RegisterRoutes(r)

	req := httptest.NewRequest("GET", "/api/v1/dynamic-policies", nil)
	// No X-Tenant-ID header
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401, got %d", w.Code)
	}
}

func TestDynamicPolicyAPI_CreateDynamicPolicy(t *testing.T) {
	policyID := uuid.New().String()
	mockService := &mockDynamicPolicyService{
		createFunc: func(ctx context.Context, tenantID string, req *CreatePolicyRequest, userID string) (*PolicyResource, error) {
			return &PolicyResource{
				ID:        policyID,
				Name:      req.Name,
				Category:  req.Category,
				Type:      req.Type,
				Enabled:   req.Enabled,
				CreatedAt: time.Now(),
			}, nil
		},
	}

	handler := NewDynamicPolicyAPIHandler(mockService)
	r := mux.NewRouter()
	handler.RegisterRoutes(r)

	body := `{"name":"Cost Limit Policy","category":"dynamic-cost","type":"cost","conditions":[],"actions":[],"priority":100,"enabled":true}`
	req := httptest.NewRequest("POST", "/api/v1/dynamic-policies", bytes.NewBufferString(body))
	req.Header.Set("X-Tenant-ID", "test-tenant")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("Expected status 201, got %d: %s", w.Code, w.Body.String())
	}
}

func TestDynamicPolicyAPI_CreateDynamicPolicy_InvalidCategory(t *testing.T) {
	handler := NewDynamicPolicyAPIHandler(&mockDynamicPolicyService{})
	r := mux.NewRouter()
	handler.RegisterRoutes(r)

	// Try to create with non-dynamic category
	body := `{"name":"Static Policy","category":"pii","type":"content","conditions":[],"actions":[],"priority":100,"enabled":true}`
	req := httptest.NewRequest("POST", "/api/v1/dynamic-policies", bytes.NewBufferString(body))
	req.Header.Set("X-Tenant-ID", "test-tenant")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", w.Code)
	}
}

func TestDynamicPolicyAPI_CreateDynamicPolicy_MissingCategory(t *testing.T) {
	handler := NewDynamicPolicyAPIHandler(&mockDynamicPolicyService{})
	r := mux.NewRouter()
	handler.RegisterRoutes(r)

	// Try to create without category
	body := `{"name":"Policy Without Category","type":"cost","conditions":[],"actions":[],"priority":100,"enabled":true}`
	req := httptest.NewRequest("POST", "/api/v1/dynamic-policies", bytes.NewBufferString(body))
	req.Header.Set("X-Tenant-ID", "test-tenant")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", w.Code)
	}
}

func TestDynamicPolicyAPI_GetDynamicPolicy(t *testing.T) {
	policyID := uuid.New().String()
	mockService := &mockDynamicPolicyService{
		getFunc: func(ctx context.Context, tenantID, id string) (*PolicyResource, error) {
			return &PolicyResource{
				ID:       policyID,
				Name:     "Dynamic Risk Policy",
				Category: "dynamic-risk",
				Type:     "risk",
				Enabled:  true,
			}, nil
		},
	}

	handler := NewDynamicPolicyAPIHandler(mockService)
	r := mux.NewRouter()
	handler.RegisterRoutes(r)

	req := httptest.NewRequest("GET", "/api/v1/dynamic-policies/"+policyID, nil)
	req.Header.Set("X-Tenant-ID", "test-tenant")
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}
}

func TestDynamicPolicyAPI_GetDynamicPolicy_NotDynamic(t *testing.T) {
	policyID := uuid.New().String()
	mockService := &mockDynamicPolicyService{
		getFunc: func(ctx context.Context, tenantID, id string) (*PolicyResource, error) {
			// Return a non-dynamic policy
			return &PolicyResource{
				ID:       policyID,
				Name:     "Static PII Policy",
				Category: "pii", // Not a dynamic category
				Type:     "content",
				Enabled:  true,
			}, nil
		},
	}

	handler := NewDynamicPolicyAPIHandler(mockService)
	r := mux.NewRouter()
	handler.RegisterRoutes(r)

	req := httptest.NewRequest("GET", "/api/v1/dynamic-policies/"+policyID, nil)
	req.Header.Set("X-Tenant-ID", "test-tenant")
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("Expected status 404, got %d: %s", w.Code, w.Body.String())
	}
}

func TestDynamicPolicyAPI_GetDynamicPolicy_NotFound(t *testing.T) {
	mockService := &mockDynamicPolicyService{
		getFunc: func(ctx context.Context, tenantID, id string) (*PolicyResource, error) {
			return nil, nil
		},
	}

	handler := NewDynamicPolicyAPIHandler(mockService)
	r := mux.NewRouter()
	handler.RegisterRoutes(r)

	policyID := uuid.New().String()
	req := httptest.NewRequest("GET", "/api/v1/dynamic-policies/"+policyID, nil)
	req.Header.Set("X-Tenant-ID", "test-tenant")
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("Expected status 404, got %d", w.Code)
	}
}

func TestDynamicPolicyAPI_GetDynamicPolicy_InvalidID(t *testing.T) {
	handler := NewDynamicPolicyAPIHandler(&mockDynamicPolicyService{})
	r := mux.NewRouter()
	handler.RegisterRoutes(r)

	// "BAD_ID!" — uppercase + bang — fails UUID parse, sys_* prefix, AND the
	// legacy snake-case regex (^[a-z][a-z0-9_-]+$). Plain "not-a-uuid" is now
	// a legitimate legacy ID (e.g. sensitive_data_control from migration 010).
	req := httptest.NewRequest("GET", "/api/v1/dynamic-policies/BAD_ID%21", nil)
	req.Header.Set("X-Tenant-ID", "test-tenant")
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", w.Code)
	}
}

func TestDynamicPolicyAPI_UpdateDynamicPolicy(t *testing.T) {
	policyID := uuid.New().String()
	mockService := &mockDynamicPolicyService{
		getFunc: func(ctx context.Context, tenantID, id string) (*PolicyResource, error) {
			return &PolicyResource{
				ID:       policyID,
				Name:     "Original Name",
				Category: "dynamic-cost",
				Type:     "cost",
				Enabled:  true,
			}, nil
		},
		updateFunc: func(ctx context.Context, tenantID, id string, req *UpdatePolicyRequest, userID string) (*PolicyResource, error) {
			return &PolicyResource{
				ID:        policyID,
				Name:      *req.Name,
				Category:  "dynamic-cost",
				Type:      "cost",
				Enabled:   true,
				UpdatedAt: time.Now(),
			}, nil
		},
	}

	handler := NewDynamicPolicyAPIHandler(mockService)
	r := mux.NewRouter()
	handler.RegisterRoutes(r)

	body := `{"name":"Updated Name"}`
	req := httptest.NewRequest("PUT", "/api/v1/dynamic-policies/"+policyID, bytes.NewBufferString(body))
	req.Header.Set("X-Tenant-ID", "test-tenant")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestDynamicPolicyAPI_UpdateDynamicPolicy_InvalidCategory(t *testing.T) {
	policyID := uuid.New().String()
	mockService := &mockDynamicPolicyService{
		getFunc: func(ctx context.Context, tenantID, id string) (*PolicyResource, error) {
			return &PolicyResource{
				ID:       policyID,
				Name:     "Dynamic Policy",
				Category: "dynamic-cost",
				Type:     "cost",
				Enabled:  true,
			}, nil
		},
	}

	handler := NewDynamicPolicyAPIHandler(mockService)
	r := mux.NewRouter()
	handler.RegisterRoutes(r)

	// Try to change category to non-dynamic
	body := `{"category":"pii"}`
	req := httptest.NewRequest("PUT", "/api/v1/dynamic-policies/"+policyID, bytes.NewBufferString(body))
	req.Header.Set("X-Tenant-ID", "test-tenant")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", w.Code)
	}
}

func TestDynamicPolicyAPI_DeleteDynamicPolicy(t *testing.T) {
	policyID := uuid.New().String()
	deleted := false
	mockService := &mockDynamicPolicyService{
		getFunc: func(ctx context.Context, tenantID, id string) (*PolicyResource, error) {
			return &PolicyResource{
				ID:       policyID,
				Name:     "Policy To Delete",
				Category: "dynamic-risk",
				Type:     "risk",
				Enabled:  true,
			}, nil
		},
		deleteFunc: func(ctx context.Context, tenantID, id, userID string) error {
			deleted = true
			return nil
		},
	}

	handler := NewDynamicPolicyAPIHandler(mockService)
	r := mux.NewRouter()
	handler.RegisterRoutes(r)

	req := httptest.NewRequest("DELETE", "/api/v1/dynamic-policies/"+policyID, nil)
	req.Header.Set("X-Tenant-ID", "test-tenant")
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Errorf("Expected status 204, got %d", w.Code)
	}

	if !deleted {
		t.Error("Delete function was not called")
	}
}

func TestDynamicPolicyAPI_Import(t *testing.T) {
	mockService := &mockDynamicPolicyService{
		importFunc: func(ctx context.Context, tenantID string, req *ImportPoliciesRequest, userID string) (*ImportPoliciesResponse, error) {
			return &ImportPoliciesResponse{
				Created: len(req.Policies),
				Skipped: 0,
				Errors:  nil,
			}, nil
		},
	}

	handler := NewDynamicPolicyAPIHandler(mockService)
	r := mux.NewRouter()
	handler.RegisterRoutes(r)

	body := `{"policies":[{"name":"Policy 1","category":"dynamic-risk","type":"risk","conditions":[],"actions":[],"priority":1,"enabled":true}]}`
	req := httptest.NewRequest("POST", "/api/v1/dynamic-policies/import", bytes.NewBufferString(body))
	req.Header.Set("X-Tenant-ID", "test-tenant")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestDynamicPolicyAPI_Import_InvalidCategory(t *testing.T) {
	handler := NewDynamicPolicyAPIHandler(&mockDynamicPolicyService{})
	r := mux.NewRouter()
	handler.RegisterRoutes(r)

	// Import with non-dynamic category
	body := `{"policies":[{"name":"Static Policy","category":"pii","type":"content","conditions":[],"actions":[],"priority":1,"enabled":true}]}`
	req := httptest.NewRequest("POST", "/api/v1/dynamic-policies/import", bytes.NewBufferString(body))
	req.Header.Set("X-Tenant-ID", "test-tenant")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", w.Code)
	}
}

func TestDynamicPolicyAPI_Export(t *testing.T) {
	mockService := &mockDynamicPolicyService{
		exportFunc: func(ctx context.Context, tenantID string) (*ExportPoliciesResponse, error) {
			return &ExportPoliciesResponse{
				Policies: []PolicyResource{
					{ID: uuid.New().String(), Name: "Dynamic Policy", Category: "dynamic-risk"},
					{ID: uuid.New().String(), Name: "Static Policy", Category: "pii"}, // Should be filtered out
				},
			}, nil
		},
	}

	handler := NewDynamicPolicyAPIHandler(mockService)
	r := mux.NewRouter()
	handler.RegisterRoutes(r)

	req := httptest.NewRequest("GET", "/api/v1/dynamic-policies/export", nil)
	req.Header.Set("X-Tenant-ID", "test-tenant")
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	var resp ExportPoliciesResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	// Should only have dynamic policies
	if len(resp.Policies) != 1 {
		t.Errorf("Expected 1 dynamic policy in export, got %d", len(resp.Policies))
	}
}

func TestDynamicPolicyAPI_Effective(t *testing.T) {
	mockService := &mockDynamicPolicyService{
		listFunc: func(ctx context.Context, tenantID string, params ListPoliciesParams) (*PoliciesListResponse, error) {
			// Verify enabled filter is applied
			if params.Enabled == nil || !*params.Enabled {
				t.Error("Expected enabled=true filter for effective policies")
			}
			if params.SortBy != "priority" {
				t.Errorf("Expected sort by priority, got %s", params.SortBy)
			}
			return &PoliciesListResponse{
				Policies: []PolicyResource{
					{ID: uuid.New().String(), Name: "High Priority", Priority: 1, Enabled: true, Category: "dynamic-risk"},
					{ID: uuid.New().String(), Name: "Low Priority", Priority: 100, Enabled: true, Category: "dynamic-cost"},
				},
				Pagination: PaginationMeta{Page: 1, PageSize: 100, TotalItems: 2, TotalPages: 1},
			}, nil
		},
	}

	handler := NewDynamicPolicyAPIHandler(mockService)
	r := mux.NewRouter()
	handler.RegisterRoutes(r)

	req := httptest.NewRequest("GET", "/api/v1/dynamic-policies/effective", nil)
	req.Header.Set("X-Tenant-ID", "test-tenant")
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}
}

func TestDynamicPolicyAPI_CORS(t *testing.T) {
	handler := NewDynamicPolicyAPIHandler(&mockDynamicPolicyService{})
	r := mux.NewRouter()
	handler.RegisterRoutes(r)

	req := httptest.NewRequest("OPTIONS", "/api/v1/dynamic-policies", nil)
	req.Header.Set("Origin", "http://localhost:3000")
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Errorf("Expected status 204, got %d", w.Code)
	}

	if w.Header().Get("Access-Control-Allow-Methods") == "" {
		t.Error("Expected CORS headers to be set")
	}
}

func TestDynamicPolicyAPI_TestPolicy(t *testing.T) {
	mockService := &mockDynamicPolicyService{
		getFunc: func(ctx context.Context, tenantID, policyID string) (*PolicyResource, error) {
			return &PolicyResource{ID: policyID, Name: "Test Policy", Category: "dynamic-risk"}, nil
		},
		testFunc: func(ctx context.Context, tenantID, policyID string, req *TestPolicyRequest) (*TestPolicyResponse, error) {
			return &TestPolicyResponse{
				Matched:     true,
				Blocked:     false,
				Actions:     []TriggeredAction{{Type: "log"}, {Type: "alert"}},
				Explanation: "Policy matched",
				EvalTimeMs:  1.5,
			}, nil
		},
	}

	handler := NewDynamicPolicyAPIHandler(mockService)
	r := mux.NewRouter()
	handler.RegisterRoutes(r)

	testReq := TestPolicyRequest{
		Query: "test query for policy evaluation",
		Context: map[string]interface{}{
			"prompt": "test prompt",
			"model":  "gpt-4",
		},
	}
	body, _ := json.Marshal(testReq)

	policyID := uuid.New().String()
	req := httptest.NewRequest("POST", "/api/v1/dynamic-policies/"+policyID+"/test", bytes.NewReader(body))
	req.Header.Set("X-Tenant-ID", "test-tenant")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestDynamicPolicyAPI_TestPolicy_InvalidJSON(t *testing.T) {
	mockService := &mockDynamicPolicyService{
		getFunc: func(ctx context.Context, tenantID, policyID string) (*PolicyResource, error) {
			return &PolicyResource{ID: policyID, Name: "Test Policy", Category: "dynamic-risk"}, nil
		},
	}
	handler := NewDynamicPolicyAPIHandler(mockService)
	r := mux.NewRouter()
	handler.RegisterRoutes(r)

	policyID := uuid.New().String()
	req := httptest.NewRequest("POST", "/api/v1/dynamic-policies/"+policyID+"/test", bytes.NewReader([]byte("invalid json")))
	req.Header.Set("X-Tenant-ID", "test-tenant")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", w.Code)
	}
}

func TestDynamicPolicyAPI_GetVersions(t *testing.T) {
	mockService := &mockDynamicPolicyService{
		getFunc: func(ctx context.Context, tenantID, policyID string) (*PolicyResource, error) {
			return &PolicyResource{ID: policyID, Name: "Test Policy", Category: "dynamic-risk"}, nil
		},
		versionsFunc: func(ctx context.Context, tenantID, policyID string) (*PolicyVersionResponse, error) {
			return &PolicyVersionResponse{
				Versions: []PolicyVersionEntry{
					{Version: 1, ChangedAt: time.Now().Add(-time.Hour), ChangedBy: "user1", ChangeType: "create"},
					{Version: 2, ChangedAt: time.Now(), ChangedBy: "user2", ChangeType: "update"},
				},
			}, nil
		},
	}

	handler := NewDynamicPolicyAPIHandler(mockService)
	r := mux.NewRouter()
	handler.RegisterRoutes(r)

	policyID := uuid.New().String()
	req := httptest.NewRequest("GET", "/api/v1/dynamic-policies/"+policyID+"/versions", nil)
	req.Header.Set("X-Tenant-ID", "test-tenant")
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestDynamicPolicyAPI_Delete_Success(t *testing.T) {
	mockService := &mockDynamicPolicyService{
		getFunc: func(ctx context.Context, tenantID, policyID string) (*PolicyResource, error) {
			return &PolicyResource{ID: policyID, Name: "Test Policy", Category: "dynamic-risk"}, nil
		},
		deleteFunc: func(ctx context.Context, tenantID, policyID, userID string) error {
			return nil
		},
	}

	handler := NewDynamicPolicyAPIHandler(mockService)
	r := mux.NewRouter()
	handler.RegisterRoutes(r)

	policyID := uuid.New().String()
	req := httptest.NewRequest("DELETE", "/api/v1/dynamic-policies/"+policyID, nil)
	req.Header.Set("X-Tenant-ID", "test-tenant")
	req.Header.Set("X-User-ID", "user123")
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Errorf("Expected status 204, got %d", w.Code)
	}
}

func TestDynamicPolicyAPI_Update_InvalidJSON(t *testing.T) {
	mockService := &mockDynamicPolicyService{
		getFunc: func(ctx context.Context, tenantID, policyID string) (*PolicyResource, error) {
			return &PolicyResource{ID: policyID, Name: "Test Policy", Category: "dynamic-risk"}, nil
		},
	}
	handler := NewDynamicPolicyAPIHandler(mockService)
	r := mux.NewRouter()
	handler.RegisterRoutes(r)

	policyID := uuid.New().String()
	req := httptest.NewRequest("PUT", "/api/v1/dynamic-policies/"+policyID, bytes.NewReader([]byte("invalid json")))
	req.Header.Set("X-Tenant-ID", "test-tenant")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", w.Code)
	}
}

func TestDynamicPolicyAPI_List_WithFilters(t *testing.T) {
	mockService := &mockDynamicPolicyService{
		listFunc: func(ctx context.Context, tenantID string, params ListPoliciesParams) (*PoliciesListResponse, error) {
			// Verify filters are passed
			if params.Type != "cost" {
				t.Errorf("Expected type filter 'cost', got '%s'", params.Type)
			}
			if params.Category != "dynamic-cost" {
				t.Errorf("Expected category filter 'dynamic-cost', got '%s'", params.Category)
			}
			return &PoliciesListResponse{
				Policies:   []PolicyResource{},
				Pagination: PaginationMeta{Page: 1, PageSize: 20},
			}, nil
		},
	}

	handler := NewDynamicPolicyAPIHandler(mockService)
	r := mux.NewRouter()
	handler.RegisterRoutes(r)

	req := httptest.NewRequest("GET", "/api/v1/dynamic-policies?type=cost&category=dynamic-cost", nil)
	req.Header.Set("X-Tenant-ID", "test-tenant")
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}
}

func TestDynamicPolicyAPI_Import_InvalidJSON(t *testing.T) {
	handler := NewDynamicPolicyAPIHandler(&mockDynamicPolicyService{})
	r := mux.NewRouter()
	handler.RegisterRoutes(r)

	req := httptest.NewRequest("POST", "/api/v1/dynamic-policies/import", bytes.NewReader([]byte("invalid json")))
	req.Header.Set("X-Tenant-ID", "test-tenant")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", w.Code)
	}
}

func TestDynamicPolicyAPI_Create_ValidationError(t *testing.T) {
	mockService := &mockDynamicPolicyService{
		createFunc: func(ctx context.Context, tenantID string, req *CreatePolicyRequest, userID string) (*PolicyResource, error) {
			return nil, &ValidationError{
				Errors: []PolicyFieldError{
					{Field: "name", Message: "Name is required"},
					{Field: "category", Message: "Invalid category"},
				},
			}
		},
	}

	handler := NewDynamicPolicyAPIHandler(mockService)
	r := mux.NewRouter()
	handler.RegisterRoutes(r)

	createReq := CreatePolicyRequest{
		Name:     "Test",
		Category: "dynamic-risk",
	}
	body, _ := json.Marshal(createReq)

	req := httptest.NewRequest("POST", "/api/v1/dynamic-policies", bytes.NewReader(body))
	req.Header.Set("X-Tenant-ID", "test-tenant")
	req.Header.Set("X-User-ID", "user123")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d: %s", w.Code, w.Body.String())
	}

	// Verify it's a validation error response
	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err == nil {
		if errObj, ok := resp["error"].(map[string]interface{}); ok {
			if errObj["code"] != "VALIDATION_ERROR" {
				t.Errorf("Expected VALIDATION_ERROR code, got %v", errObj["code"])
			}
		}
	}
}

func TestDynamicPolicyAPI_Update_Success(t *testing.T) {
	policyID := uuid.New().String()
	name := "Updated Policy"
	enabled := true
	mockService := &mockDynamicPolicyService{
		getFunc: func(ctx context.Context, tenantID, id string) (*PolicyResource, error) {
			return &PolicyResource{ID: id, Name: "Test Policy", Category: "dynamic-risk"}, nil
		},
		updateFunc: func(ctx context.Context, tenantID, id string, req *UpdatePolicyRequest, userID string) (*PolicyResource, error) {
			return &PolicyResource{
				ID:       id,
				Name:     name,
				Category: "dynamic-risk",
				Enabled:  enabled,
			}, nil
		},
	}

	handler := NewDynamicPolicyAPIHandler(mockService)
	r := mux.NewRouter()
	handler.RegisterRoutes(r)

	updateReq := UpdatePolicyRequest{
		Name:    &name,
		Enabled: &enabled,
	}
	body, _ := json.Marshal(updateReq)

	req := httptest.NewRequest("PUT", "/api/v1/dynamic-policies/"+policyID, bytes.NewReader(body))
	req.Header.Set("X-Tenant-ID", "test-tenant")
	req.Header.Set("X-User-ID", "user123")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d: %s", w.Code, w.Body.String())
	}
}

func TestDynamicPolicyAPI_List_ServiceError(t *testing.T) {
	mockService := &mockDynamicPolicyService{
		listFunc: func(ctx context.Context, tenantID string, params ListPoliciesParams) (*PoliciesListResponse, error) {
			return nil, errors.New("database connection failed")
		},
	}

	handler := NewDynamicPolicyAPIHandler(mockService)
	r := mux.NewRouter()
	handler.RegisterRoutes(r)

	req := httptest.NewRequest("GET", "/api/v1/dynamic-policies", nil)
	req.Header.Set("X-Tenant-ID", "test-tenant")
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("Expected status 500, got %d", w.Code)
	}
}

func TestDynamicPolicyAPI_Export_ServiceError(t *testing.T) {
	mockService := &mockDynamicPolicyService{
		exportFunc: func(ctx context.Context, tenantID string) (*ExportPoliciesResponse, error) {
			return nil, errors.New("database error")
		},
	}

	handler := NewDynamicPolicyAPIHandler(mockService)
	r := mux.NewRouter()
	handler.RegisterRoutes(r)

	req := httptest.NewRequest("GET", "/api/v1/dynamic-policies/export", nil)
	req.Header.Set("X-Tenant-ID", "test-tenant")
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("Expected status 500, got %d", w.Code)
	}
}

func TestDynamicPolicyAPI_Create_TierError(t *testing.T) {
	mockService := &mockDynamicPolicyService{
		createFunc: func(ctx context.Context, tenantID string, req *CreatePolicyRequest, userID string) (*PolicyResource, error) {
			return nil, NewTierValidationError("Cannot create system policies", ErrCodeSystemTierImmutable)
		},
	}

	handler := NewDynamicPolicyAPIHandler(mockService)
	r := mux.NewRouter()
	handler.RegisterRoutes(r)

	createReq := CreatePolicyRequest{
		Name:     "System Policy",
		Category: "dynamic-risk",
		Tier:     TierSystem,
	}
	body, _ := json.Marshal(createReq)

	req := httptest.NewRequest("POST", "/api/v1/dynamic-policies", bytes.NewReader(body))
	req.Header.Set("X-Tenant-ID", "test-tenant")
	req.Header.Set("X-User-ID", "user123")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("Expected status 403, got %d: %s", w.Code, w.Body.String())
	}
}

func TestDynamicPolicyAPI_Create_Success(t *testing.T) {
	policyID := uuid.New().String()
	mockService := &mockDynamicPolicyService{
		createFunc: func(ctx context.Context, tenantID string, req *CreatePolicyRequest, userID string) (*PolicyResource, error) {
			return &PolicyResource{
				ID:       policyID,
				Name:     req.Name,
				Category: req.Category,
				Enabled:  true,
			}, nil
		},
	}

	handler := NewDynamicPolicyAPIHandler(mockService)
	r := mux.NewRouter()
	handler.RegisterRoutes(r)

	createReq := CreatePolicyRequest{
		Name:     "New Policy",
		Category: "dynamic-risk",
	}
	body, _ := json.Marshal(createReq)

	req := httptest.NewRequest("POST", "/api/v1/dynamic-policies", bytes.NewReader(body))
	req.Header.Set("X-Tenant-ID", "test-tenant")
	req.Header.Set("X-User-ID", "user123")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("Expected status 201, got %d: %s", w.Code, w.Body.String())
	}
}

func TestDynamicPolicyAPI_Create_InternalError(t *testing.T) {
	mockService := &mockDynamicPolicyService{
		createFunc: func(ctx context.Context, tenantID string, req *CreatePolicyRequest, userID string) (*PolicyResource, error) {
			return nil, errors.New("unexpected database error")
		},
	}

	handler := NewDynamicPolicyAPIHandler(mockService)
	r := mux.NewRouter()
	handler.RegisterRoutes(r)

	createReq := CreatePolicyRequest{
		Name:     "New Policy",
		Category: "dynamic-risk",
	}
	body, _ := json.Marshal(createReq)

	req := httptest.NewRequest("POST", "/api/v1/dynamic-policies", bytes.NewReader(body))
	req.Header.Set("X-Tenant-ID", "test-tenant")
	req.Header.Set("X-User-ID", "user123")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("Expected status 500, got %d", w.Code)
	}
}

func TestDynamicPolicyAPI_Get_ServiceError(t *testing.T) {
	policyID := uuid.New().String()
	mockService := &mockDynamicPolicyService{
		getFunc: func(ctx context.Context, tenantID, id string) (*PolicyResource, error) {
			return nil, errors.New("database error")
		},
	}

	handler := NewDynamicPolicyAPIHandler(mockService)
	r := mux.NewRouter()
	handler.RegisterRoutes(r)

	req := httptest.NewRequest("GET", "/api/v1/dynamic-policies/"+policyID, nil)
	req.Header.Set("X-Tenant-ID", "test-tenant")
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	// Generic errors are converted to 500
	if w.Code != http.StatusInternalServerError {
		t.Errorf("Expected status 500, got %d", w.Code)
	}
}

func TestDynamicPolicyAPI_Effective_ServiceError(t *testing.T) {
	mockService := &mockDynamicPolicyService{
		listFunc: func(ctx context.Context, tenantID string, params ListPoliciesParams) (*PoliciesListResponse, error) {
			return nil, errors.New("database error")
		},
	}

	handler := NewDynamicPolicyAPIHandler(mockService)
	r := mux.NewRouter()
	handler.RegisterRoutes(r)

	req := httptest.NewRequest("GET", "/api/v1/dynamic-policies/effective", nil)
	req.Header.Set("X-Tenant-ID", "test-tenant")
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("Expected status 500, got %d", w.Code)
	}
}

func TestDynamicPolicyAPI_Delete_ServiceError(t *testing.T) {
	policyID := uuid.New().String()
	mockService := &mockDynamicPolicyService{
		getFunc: func(ctx context.Context, tenantID, id string) (*PolicyResource, error) {
			return &PolicyResource{ID: id, Name: "Test", Category: "dynamic-risk"}, nil
		},
		deleteFunc: func(ctx context.Context, tenantID, policyID, userID string) error {
			return errors.New("database error")
		},
	}

	handler := NewDynamicPolicyAPIHandler(mockService)
	r := mux.NewRouter()
	handler.RegisterRoutes(r)

	req := httptest.NewRequest("DELETE", "/api/v1/dynamic-policies/"+policyID, nil)
	req.Header.Set("X-Tenant-ID", "test-tenant")
	req.Header.Set("X-User-ID", "user123")
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("Expected status 500, got %d", w.Code)
	}
}

func TestDynamicPolicyAPI_Update_ServiceError(t *testing.T) {
	policyID := uuid.New().String()
	name := "Updated"
	mockService := &mockDynamicPolicyService{
		getFunc: func(ctx context.Context, tenantID, id string) (*PolicyResource, error) {
			return &PolicyResource{ID: id, Name: "Test", Category: "dynamic-risk"}, nil
		},
		updateFunc: func(ctx context.Context, tenantID, id string, req *UpdatePolicyRequest, userID string) (*PolicyResource, error) {
			return nil, errors.New("database error")
		},
	}

	handler := NewDynamicPolicyAPIHandler(mockService)
	r := mux.NewRouter()
	handler.RegisterRoutes(r)

	updateReq := UpdatePolicyRequest{Name: &name}
	body, _ := json.Marshal(updateReq)

	req := httptest.NewRequest("PUT", "/api/v1/dynamic-policies/"+policyID, bytes.NewReader(body))
	req.Header.Set("X-Tenant-ID", "test-tenant")
	req.Header.Set("X-User-ID", "user123")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("Expected status 500, got %d", w.Code)
	}
}

func TestDynamicPolicyAPI_TestPolicy_ServiceError(t *testing.T) {
	policyID := uuid.New().String()
	mockService := &mockDynamicPolicyService{
		getFunc: func(ctx context.Context, tenantID, id string) (*PolicyResource, error) {
			return &PolicyResource{ID: id, Name: "Test", Category: "dynamic-risk"}, nil
		},
		testFunc: func(ctx context.Context, tenantID, policyID string, req *TestPolicyRequest) (*TestPolicyResponse, error) {
			return nil, errors.New("evaluation error")
		},
	}

	handler := NewDynamicPolicyAPIHandler(mockService)
	r := mux.NewRouter()
	handler.RegisterRoutes(r)

	testReq := TestPolicyRequest{Query: "test query"}
	body, _ := json.Marshal(testReq)

	req := httptest.NewRequest("POST", "/api/v1/dynamic-policies/"+policyID+"/test", bytes.NewReader(body))
	req.Header.Set("X-Tenant-ID", "test-tenant")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("Expected status 500, got %d", w.Code)
	}
}

func TestDynamicPolicyAPI_Versions_ServiceError(t *testing.T) {
	policyID := uuid.New().String()
	mockService := &mockDynamicPolicyService{
		getFunc: func(ctx context.Context, tenantID, id string) (*PolicyResource, error) {
			return &PolicyResource{ID: id, Name: "Test", Category: "dynamic-risk"}, nil
		},
		versionsFunc: func(ctx context.Context, tenantID, policyID string) (*PolicyVersionResponse, error) {
			return nil, errors.New("database error")
		},
	}

	handler := NewDynamicPolicyAPIHandler(mockService)
	r := mux.NewRouter()
	handler.RegisterRoutes(r)

	req := httptest.NewRequest("GET", "/api/v1/dynamic-policies/"+policyID+"/versions", nil)
	req.Header.Set("X-Tenant-ID", "test-tenant")
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("Expected status 500, got %d", w.Code)
	}
}

func TestDynamicPolicyAPI_Import_ServiceError(t *testing.T) {
	mockService := &mockDynamicPolicyService{
		importFunc: func(ctx context.Context, tenantID string, req *ImportPoliciesRequest, userID string) (*ImportPoliciesResponse, error) {
			return nil, errors.New("database error")
		},
	}

	handler := NewDynamicPolicyAPIHandler(mockService)
	r := mux.NewRouter()
	handler.RegisterRoutes(r)

	importReq := ImportPoliciesRequest{
		Policies: []CreatePolicyRequest{
			{Name: "Policy 1", Category: "dynamic-risk"},
		},
	}
	body, _ := json.Marshal(importReq)

	req := httptest.NewRequest("POST", "/api/v1/dynamic-policies/import", bytes.NewReader(body))
	req.Header.Set("X-Tenant-ID", "test-tenant")
	req.Header.Set("X-User-ID", "user123")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Errorf("Expected status 500, got %d", w.Code)
	}
}

func TestDynamicPolicyAPI_Update_NotFound(t *testing.T) {
	policyID := uuid.New().String()
	mockService := &mockDynamicPolicyService{
		getFunc: func(ctx context.Context, tenantID, id string) (*PolicyResource, error) {
			return nil, nil // Policy not found
		},
	}

	handler := NewDynamicPolicyAPIHandler(mockService)
	r := mux.NewRouter()
	handler.RegisterRoutes(r)

	name := "Updated Policy"
	updateReq := UpdatePolicyRequest{Name: &name}
	body, _ := json.Marshal(updateReq)

	req := httptest.NewRequest("PUT", "/api/v1/dynamic-policies/"+policyID, bytes.NewReader(body))
	req.Header.Set("X-Tenant-ID", "test-tenant")
	req.Header.Set("X-User-ID", "user123")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("Expected status 404, got %d", w.Code)
	}
}

func TestDynamicPolicyAPI_Update_NotDynamicPolicy(t *testing.T) {
	policyID := uuid.New().String()
	mockService := &mockDynamicPolicyService{
		getFunc: func(ctx context.Context, tenantID, id string) (*PolicyResource, error) {
			return &PolicyResource{ID: id, Name: "Test", Category: "static-security"}, nil // Not a dynamic policy
		},
	}

	handler := NewDynamicPolicyAPIHandler(mockService)
	r := mux.NewRouter()
	handler.RegisterRoutes(r)

	name := "Updated Policy"
	updateReq := UpdatePolicyRequest{Name: &name}
	body, _ := json.Marshal(updateReq)

	req := httptest.NewRequest("PUT", "/api/v1/dynamic-policies/"+policyID, bytes.NewReader(body))
	req.Header.Set("X-Tenant-ID", "test-tenant")
	req.Header.Set("X-User-ID", "user123")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("Expected status 404, got %d", w.Code)
	}
}

func TestDynamicPolicyAPI_Update_InvalidCategoryChange(t *testing.T) {
	policyID := uuid.New().String()
	mockService := &mockDynamicPolicyService{
		getFunc: func(ctx context.Context, tenantID, id string) (*PolicyResource, error) {
			return &PolicyResource{ID: id, Name: "Test", Category: "dynamic-risk"}, nil
		},
	}

	handler := NewDynamicPolicyAPIHandler(mockService)
	r := mux.NewRouter()
	handler.RegisterRoutes(r)

	newCategory := "static-security" // Invalid - not a dynamic category
	updateReq := UpdatePolicyRequest{Category: &newCategory}
	body, _ := json.Marshal(updateReq)

	req := httptest.NewRequest("PUT", "/api/v1/dynamic-policies/"+policyID, bytes.NewReader(body))
	req.Header.Set("X-Tenant-ID", "test-tenant")
	req.Header.Set("X-User-ID", "user123")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", w.Code)
	}
}

func TestDynamicPolicyAPI_Update_ValidationError(t *testing.T) {
	policyID := uuid.New().String()
	mockService := &mockDynamicPolicyService{
		getFunc: func(ctx context.Context, tenantID, id string) (*PolicyResource, error) {
			return &PolicyResource{ID: id, Name: "Test", Category: "dynamic-risk"}, nil
		},
		updateFunc: func(ctx context.Context, tenantID, policyID string, req *UpdatePolicyRequest, userID string) (*PolicyResource, error) {
			return nil, &ValidationError{Errors: []PolicyFieldError{{Field: "name", Message: "name is required"}}}
		},
	}

	handler := NewDynamicPolicyAPIHandler(mockService)
	r := mux.NewRouter()
	handler.RegisterRoutes(r)

	name := ""
	updateReq := UpdatePolicyRequest{Name: &name}
	body, _ := json.Marshal(updateReq)

	req := httptest.NewRequest("PUT", "/api/v1/dynamic-policies/"+policyID, bytes.NewReader(body))
	req.Header.Set("X-Tenant-ID", "test-tenant")
	req.Header.Set("X-User-ID", "user123")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("Expected status 400, got %d", w.Code)
	}
}

func TestDynamicPolicyAPI_Update_TierError(t *testing.T) {
	policyID := uuid.New().String()
	mockService := &mockDynamicPolicyService{
		getFunc: func(ctx context.Context, tenantID, id string) (*PolicyResource, error) {
			return &PolicyResource{ID: id, Name: "Test", Category: "dynamic-risk"}, nil
		},
		updateFunc: func(ctx context.Context, tenantID, policyID string, req *UpdatePolicyRequest, userID string) (*PolicyResource, error) {
			return nil, NewTierValidationError("enterprise feature required", "ENTERPRISE_REQUIRED")
		},
	}

	handler := NewDynamicPolicyAPIHandler(mockService)
	r := mux.NewRouter()
	handler.RegisterRoutes(r)

	name := "Updated"
	updateReq := UpdatePolicyRequest{Name: &name}
	body, _ := json.Marshal(updateReq)

	req := httptest.NewRequest("PUT", "/api/v1/dynamic-policies/"+policyID, bytes.NewReader(body))
	req.Header.Set("X-Tenant-ID", "test-tenant")
	req.Header.Set("X-User-ID", "user123")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("Expected status 403, got %d", w.Code)
	}
}

func TestDynamicPolicyAPI_Update_NilPolicyAfterUpdate(t *testing.T) {
	policyID := uuid.New().String()
	mockService := &mockDynamicPolicyService{
		getFunc: func(ctx context.Context, tenantID, id string) (*PolicyResource, error) {
			return &PolicyResource{ID: id, Name: "Test", Category: "dynamic-risk"}, nil
		},
		updateFunc: func(ctx context.Context, tenantID, policyID string, req *UpdatePolicyRequest, userID string) (*PolicyResource, error) {
			return nil, nil // Success but nil policy
		},
	}

	handler := NewDynamicPolicyAPIHandler(mockService)
	r := mux.NewRouter()
	handler.RegisterRoutes(r)

	name := "Updated"
	updateReq := UpdatePolicyRequest{Name: &name}
	body, _ := json.Marshal(updateReq)

	req := httptest.NewRequest("PUT", "/api/v1/dynamic-policies/"+policyID, bytes.NewReader(body))
	req.Header.Set("X-Tenant-ID", "test-tenant")
	req.Header.Set("X-User-ID", "user123")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("Expected status 404, got %d", w.Code)
	}
}

func TestDynamicPolicyAPI_Delete_NotFound(t *testing.T) {
	policyID := uuid.New().String()
	mockService := &mockDynamicPolicyService{
		getFunc: func(ctx context.Context, tenantID, id string) (*PolicyResource, error) {
			return nil, nil // Policy not found
		},
	}

	handler := NewDynamicPolicyAPIHandler(mockService)
	r := mux.NewRouter()
	handler.RegisterRoutes(r)

	req := httptest.NewRequest("DELETE", "/api/v1/dynamic-policies/"+policyID, nil)
	req.Header.Set("X-Tenant-ID", "test-tenant")
	req.Header.Set("X-User-ID", "user123")
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("Expected status 404, got %d", w.Code)
	}
}

func TestDynamicPolicyAPI_Delete_NotDynamicPolicy(t *testing.T) {
	policyID := uuid.New().String()
	mockService := &mockDynamicPolicyService{
		getFunc: func(ctx context.Context, tenantID, id string) (*PolicyResource, error) {
			return &PolicyResource{ID: id, Name: "Test", Category: "static-security"}, nil // Not dynamic
		},
	}

	handler := NewDynamicPolicyAPIHandler(mockService)
	r := mux.NewRouter()
	handler.RegisterRoutes(r)

	req := httptest.NewRequest("DELETE", "/api/v1/dynamic-policies/"+policyID, nil)
	req.Header.Set("X-Tenant-ID", "test-tenant")
	req.Header.Set("X-User-ID", "user123")
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("Expected status 404, got %d", w.Code)
	}
}

func TestDynamicPolicyAPI_Delete_TierError(t *testing.T) {
	policyID := uuid.New().String()
	mockService := &mockDynamicPolicyService{
		getFunc: func(ctx context.Context, tenantID, id string) (*PolicyResource, error) {
			return &PolicyResource{ID: id, Name: "Test", Category: "dynamic-risk"}, nil
		},
		deleteFunc: func(ctx context.Context, tenantID, policyID, userID string) error {
			return NewTierValidationError("enterprise feature required", "ENTERPRISE_REQUIRED")
		},
	}

	handler := NewDynamicPolicyAPIHandler(mockService)
	r := mux.NewRouter()
	handler.RegisterRoutes(r)

	req := httptest.NewRequest("DELETE", "/api/v1/dynamic-policies/"+policyID, nil)
	req.Header.Set("X-Tenant-ID", "test-tenant")
	req.Header.Set("X-User-ID", "user123")
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("Expected status 403, got %d", w.Code)
	}
}

func TestDynamicPolicyAPI_Test_NotFound(t *testing.T) {
	policyID := uuid.New().String()
	mockService := &mockDynamicPolicyService{
		getFunc: func(ctx context.Context, tenantID, id string) (*PolicyResource, error) {
			return nil, nil // Policy not found
		},
	}

	handler := NewDynamicPolicyAPIHandler(mockService)
	r := mux.NewRouter()
	handler.RegisterRoutes(r)

	testReq := TestPolicyRequest{Query: "test query"}
	body, _ := json.Marshal(testReq)

	req := httptest.NewRequest("POST", "/api/v1/dynamic-policies/"+policyID+"/test", bytes.NewReader(body))
	req.Header.Set("X-Tenant-ID", "test-tenant")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("Expected status 404, got %d", w.Code)
	}
}

func TestDynamicPolicyAPI_Test_NotDynamicPolicy(t *testing.T) {
	policyID := uuid.New().String()
	mockService := &mockDynamicPolicyService{
		getFunc: func(ctx context.Context, tenantID, id string) (*PolicyResource, error) {
			return &PolicyResource{ID: id, Name: "Test", Category: "static-security"}, nil
		},
	}

	handler := NewDynamicPolicyAPIHandler(mockService)
	r := mux.NewRouter()
	handler.RegisterRoutes(r)

	testReq := TestPolicyRequest{Query: "test query"}
	body, _ := json.Marshal(testReq)

	req := httptest.NewRequest("POST", "/api/v1/dynamic-policies/"+policyID+"/test", bytes.NewReader(body))
	req.Header.Set("X-Tenant-ID", "test-tenant")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("Expected status 404, got %d", w.Code)
	}
}

func TestDynamicPolicyAPI_Versions_NotFound(t *testing.T) {
	policyID := uuid.New().String()
	mockService := &mockDynamicPolicyService{
		getFunc: func(ctx context.Context, tenantID, id string) (*PolicyResource, error) {
			return nil, nil // Policy not found
		},
	}

	handler := NewDynamicPolicyAPIHandler(mockService)
	r := mux.NewRouter()
	handler.RegisterRoutes(r)

	req := httptest.NewRequest("GET", "/api/v1/dynamic-policies/"+policyID+"/versions", nil)
	req.Header.Set("X-Tenant-ID", "test-tenant")
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("Expected status 404, got %d", w.Code)
	}
}

func TestDynamicPolicyAPI_Versions_NotDynamicPolicy(t *testing.T) {
	policyID := uuid.New().String()
	mockService := &mockDynamicPolicyService{
		getFunc: func(ctx context.Context, tenantID, id string) (*PolicyResource, error) {
			return &PolicyResource{ID: id, Name: "Test", Category: "static-security"}, nil
		},
	}

	handler := NewDynamicPolicyAPIHandler(mockService)
	r := mux.NewRouter()
	handler.RegisterRoutes(r)

	req := httptest.NewRequest("GET", "/api/v1/dynamic-policies/"+policyID+"/versions", nil)
	req.Header.Set("X-Tenant-ID", "test-tenant")
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("Expected status 404, got %d", w.Code)
	}
}

func TestDynamicPolicyAPI_List_Pagination(t *testing.T) {
	mockService := &mockDynamicPolicyService{
		listFunc: func(ctx context.Context, tenantID string, params ListPoliciesParams) (*PoliciesListResponse, error) {
			return &PoliciesListResponse{
				Policies: []PolicyResource{
					{ID: "1", Name: "Policy 1", Category: "dynamic-risk"},
					{ID: "2", Name: "Policy 2", Category: "dynamic-risk"},
				},
				Pagination: PaginationMeta{TotalItems: 10, Page: 2, PageSize: 2},
			}, nil
		},
	}

	handler := NewDynamicPolicyAPIHandler(mockService)
	r := mux.NewRouter()
	handler.RegisterRoutes(r)

	req := httptest.NewRequest("GET", "/api/v1/dynamic-policies?page=2&page_size=2&enabled=true&category=dynamic-risk", nil)
	req.Header.Set("X-Tenant-ID", "test-tenant")
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}
}

func TestDynamicPolicyAPI_CORS_Preflight(t *testing.T) {
	mockService := &mockDynamicPolicyService{}

	handler := NewDynamicPolicyAPIHandler(mockService)
	r := mux.NewRouter()
	handler.RegisterRoutes(r)

	req := httptest.NewRequest("OPTIONS", "/api/v1/dynamic-policies", nil)
	req.Header.Set("X-Tenant-ID", "test-tenant")
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Errorf("Expected status 204, got %d", w.Code)
	}
}

func TestDynamicPolicyAPI_HandlePolicyByID_Options(t *testing.T) {
	policyID := uuid.New().String()
	mockService := &mockDynamicPolicyService{}

	handler := NewDynamicPolicyAPIHandler(mockService)
	r := mux.NewRouter()
	handler.RegisterRoutes(r)

	req := httptest.NewRequest("OPTIONS", "/api/v1/dynamic-policies/"+policyID, nil)
	req.Header.Set("X-Tenant-ID", "test-tenant")
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Errorf("Expected status 204, got %d", w.Code)
	}
}

func TestDynamicPolicyAPI_Import_Options(t *testing.T) {
	mockService := &mockDynamicPolicyService{}

	handler := NewDynamicPolicyAPIHandler(mockService)
	r := mux.NewRouter()
	handler.RegisterRoutes(r)

	req := httptest.NewRequest("OPTIONS", "/api/v1/dynamic-policies/import", nil)
	req.Header.Set("X-Tenant-ID", "test-tenant")
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Errorf("Expected status 204, got %d", w.Code)
	}
}

func TestDynamicPolicyAPI_Export_Options(t *testing.T) {
	mockService := &mockDynamicPolicyService{}

	handler := NewDynamicPolicyAPIHandler(mockService)
	r := mux.NewRouter()
	handler.RegisterRoutes(r)

	req := httptest.NewRequest("OPTIONS", "/api/v1/dynamic-policies/export", nil)
	req.Header.Set("X-Tenant-ID", "test-tenant")
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Errorf("Expected status 204, got %d", w.Code)
	}
}

func TestDynamicPolicyAPI_Effective_Options(t *testing.T) {
	mockService := &mockDynamicPolicyService{}

	handler := NewDynamicPolicyAPIHandler(mockService)
	r := mux.NewRouter()
	handler.RegisterRoutes(r)

	req := httptest.NewRequest("OPTIONS", "/api/v1/dynamic-policies/effective", nil)
	req.Header.Set("X-Tenant-ID", "test-tenant")
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Errorf("Expected status 204, got %d", w.Code)
	}
}

// TestIsValidPolicyID locks in the three ID shapes the handler must accept
// and the shapes it must reject. Without the legacy snake_case branch, every
// Test / Edit / Delete / Versions action on policies seeded by
// migrations/core/010_policy_tables.sql (e.g. sensitive_data_control,
// high_risk_block, sql_injection_union) 400s with "Invalid policy ID format".
// These tests exist so the next refactor can't silently bring that
// regression back.
func TestIsValidPolicyID(t *testing.T) {
	t.Run("accepts valid UUIDs", func(t *testing.T) {
		for _, id := range []string{
			"550e8400-e29b-41d4-a716-446655440000",
			"00000000-0000-0000-0000-000000000000",
			"AABBCCDD-AABB-CCDD-AABB-CCDDEEFF0011", // uppercase hex accepted by uuid.Parse
		} {
			if !isValidPolicyID(id) {
				t.Errorf("UUID %q should be valid", id)
			}
		}
	})

	t.Run("accepts sys_* prefix", func(t *testing.T) {
		for _, id := range []string{
			"sys_pii_ssn",
			"sys_dyn_tenant_isolation", // seeded in a later migration
			"sys_media_pii",
		} {
			if !isValidPolicyID(id) {
				t.Errorf("sys_* id %q should be valid", id)
			}
		}
	})

	t.Run("accepts legacy snake_case seed IDs (migration 010)", func(t *testing.T) {
		// Exact identifiers seeded by migrations/core/010_policy_tables.sql.
		// Verified against the SQL INSERT statements — do not replace with
		// synthetic names; these are the real IDs users will click on.
		for _, id := range []string{
			// dynamic_policies seeds
			"high_risk_block",
			"sensitive_data_control",
			// static_policies seeds
			"sql_injection_union",
			"sql_injection_or",
			"drop_table_prevention",
			"truncate_prevention",
			"pii_ssn_detection",
			// shape coverage (not real seeds, but within the regex)
			"a-b-c",      // hyphens allowed
			"policy_1_2", // digits allowed
		} {
			if !isValidPolicyID(id) {
				t.Errorf("legacy seed id %q should be valid (accepted by ^[a-z][a-z0-9_-]{1,127}$)", id)
			}
		}
	})

	t.Run("accepts 128-char legacy ID boundary", func(t *testing.T) {
		// Regex is ^[a-z][a-z0-9_-]{1,127}$ — total length 2..128. Confirm
		// the upper bound explicitly so a future tweak to the quantifier
		// surfaces immediately.
		boundary := "a" + strings.Repeat("b", 127) // 128 chars total
		if !isValidPolicyID(boundary) {
			t.Errorf("128-char legacy id should be valid; got rejection for len=%d", len(boundary))
		}
	})

	t.Run("rejects obviously invalid inputs", func(t *testing.T) {
		for _, id := range []string{
			"",                             // empty
			"a",                            // single char — regex requires min length 2 (first char + at least 1 more)
			"UPPERCASE_ID",                 // caps forbidden — prevents accidental matches on arbitrary headers
			"123leading_digit",             // must start with letter
			"name with spaces",             // space forbidden
			"name\nwith\nnewline",          // newline forbidden
			"name;drop_table",              // semicolon forbidden
			"_leading_underscore",          // must start with [a-z]
			"-leading-hyphen",              // must start with [a-z]
			"' OR 1=1 --",                  // SQLi-ish; SQL is parameterized but the validator is the outer guard
			"a" + strings.Repeat("b", 128), // 129 chars — over the 128 cap
			"café",                         // non-ASCII outside [a-z0-9_-]
		} {
			if isValidPolicyID(id) {
				t.Errorf("invalid id %q (len %d) should be rejected", id, len(id))
			}
		}
	})
}
