// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package cost

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
)

func setupTestHandler() (*Handler, *MockRepository) {
	repo := NewMockRepository()
	service := NewService(repo, nil)
	handler := NewHandler(service)
	return handler, repo
}

func TestNewHandler(t *testing.T) {
	repo := NewMockRepository()
	service := NewService(repo, nil)
	handler := NewHandler(service)

	if handler == nil {
		t.Fatal("expected non-nil handler")
	}
}

func TestRegisterRoutes(t *testing.T) {
	handler, _ := setupTestHandler()
	r := mux.NewRouter()

	handler.RegisterRoutes(r)

	// Verify routes are registered
	routes := []struct {
		path   string
		method string
	}{
		{"/api/v1/budgets", "POST"},
		{"/api/v1/budgets", "GET"},
		{"/api/v1/budgets/check", "POST"},
		{"/api/v1/budgets/{id}", "GET"},
		{"/api/v1/budgets/{id}", "PUT"},
		{"/api/v1/budgets/{id}", "DELETE"},
		{"/api/v1/budgets/{id}/status", "GET"},
		{"/api/v1/budgets/{id}/alerts", "GET"},
		{"/api/v1/usage", "GET"},
		{"/api/v1/usage/breakdown", "GET"},
		{"/api/v1/usage/records", "GET"},
		{"/api/v1/pricing", "GET"},
	}

	for _, route := range routes {
		req := httptest.NewRequest(route.method, route.path, nil)
		match := &mux.RouteMatch{}
		if !r.Match(req, match) {
			t.Errorf("route %s %s not registered", route.method, route.path)
		}
	}
}

func TestCreateBudgetHandler(t *testing.T) {
	handler, _ := setupTestHandler()
	r := mux.NewRouter()
	handler.RegisterRoutes(r)

	body := CreateBudgetRequest{
		ID:       "test-budget-1",
		Name:     "Test Budget",
		Scope:    ScopeOrganization,
		LimitUSD: 100.0,
		Period:   PeriodMonthly,
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest("POST", "/api/v1/budgets", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Org-ID", "org-1")

	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusCreated {
		t.Errorf("status = %v, want %v, body = %s", rr.Code, http.StatusCreated, rr.Body.String())
	}

	var result Budget
	json.Unmarshal(rr.Body.Bytes(), &result)

	if result.ID != "test-budget-1" {
		t.Errorf("ID = %v, want test-budget-1", result.ID)
	}
}

func TestCreateBudgetHandlerInvalidBody(t *testing.T) {
	handler, _ := setupTestHandler()
	r := mux.NewRouter()
	handler.RegisterRoutes(r)

	req := httptest.NewRequest("POST", "/api/v1/budgets", bytes.NewReader([]byte("invalid json")))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %v, want %v", rr.Code, http.StatusBadRequest)
	}
}

func TestCreateBudgetHandlerDuplicate(t *testing.T) {
	handler, _ := setupTestHandler()
	r := mux.NewRouter()
	handler.RegisterRoutes(r)

	body := CreateBudgetRequest{
		ID:       "dup-test",
		Name:     "Dup Test",
		Scope:    ScopeOrganization,
		LimitUSD: 100.0,
		Period:   PeriodMonthly,
	}
	bodyBytes, _ := json.Marshal(body)

	// First request
	req := httptest.NewRequest("POST", "/api/v1/budgets", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("first create failed: %v", rr.Code)
	}

	// Second request (duplicate)
	req = httptest.NewRequest("POST", "/api/v1/budgets", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	rr = httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusConflict {
		t.Errorf("status = %v, want %v", rr.Code, http.StatusConflict)
	}
}

func TestListBudgetsHandler(t *testing.T) {
	handler, repo := setupTestHandler()
	r := mux.NewRouter()
	handler.RegisterRoutes(r)

	// Create some budgets directly in repo
	repo.budgets["b1"] = &Budget{ID: "b1", Name: "Budget 1", OrgID: "org-1", Scope: ScopeOrganization, LimitUSD: 100, Period: PeriodMonthly}
	repo.budgets["b2"] = &Budget{ID: "b2", Name: "Budget 2", OrgID: "org-1", Scope: ScopeOrganization, LimitUSD: 200, Period: PeriodMonthly}

	req := httptest.NewRequest("GET", "/api/v1/budgets?org_id=org-1", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %v, want %v", rr.Code, http.StatusOK)
	}

	var result map[string]interface{}
	json.Unmarshal(rr.Body.Bytes(), &result)

	if result["total"].(float64) != 2 {
		t.Errorf("total = %v, want 2", result["total"])
	}
}

func TestGetBudgetHandler(t *testing.T) {
	handler, repo := setupTestHandler()
	r := mux.NewRouter()
	handler.RegisterRoutes(r)

	repo.budgets["get-test"] = &Budget{ID: "get-test", Name: "Get Test", Scope: ScopeOrganization, LimitUSD: 100, Period: PeriodMonthly}

	req := httptest.NewRequest("GET", "/api/v1/budgets/get-test", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %v, want %v", rr.Code, http.StatusOK)
	}

	var result Budget
	json.Unmarshal(rr.Body.Bytes(), &result)

	if result.ID != "get-test" {
		t.Errorf("ID = %v, want get-test", result.ID)
	}
}

func TestGetBudgetHandlerNotFound(t *testing.T) {
	handler, _ := setupTestHandler()
	r := mux.NewRouter()
	handler.RegisterRoutes(r)

	req := httptest.NewRequest("GET", "/api/v1/budgets/nonexistent", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("status = %v, want %v", rr.Code, http.StatusNotFound)
	}
}

func TestUpdateBudgetHandler(t *testing.T) {
	handler, repo := setupTestHandler()
	r := mux.NewRouter()
	handler.RegisterRoutes(r)

	repo.budgets["update-test"] = &Budget{ID: "update-test", Name: "Original", Scope: ScopeOrganization, LimitUSD: 100, Period: PeriodMonthly}

	update := Budget{Name: "Updated", Scope: ScopeOrganization, LimitUSD: 200, Period: PeriodMonthly}
	bodyBytes, _ := json.Marshal(update)

	req := httptest.NewRequest("PUT", "/api/v1/budgets/update-test", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-User-ID", "user-1")

	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %v, want %v, body = %s", rr.Code, http.StatusOK, rr.Body.String())
	}
}

func TestUpdateBudgetHandlerNotFound(t *testing.T) {
	handler, _ := setupTestHandler()
	r := mux.NewRouter()
	handler.RegisterRoutes(r)

	update := Budget{Name: "Updated", Scope: ScopeOrganization, LimitUSD: 200, Period: PeriodMonthly}
	bodyBytes, _ := json.Marshal(update)

	req := httptest.NewRequest("PUT", "/api/v1/budgets/nonexistent", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("status = %v, want %v", rr.Code, http.StatusNotFound)
	}
}

func TestDeleteBudgetHandler(t *testing.T) {
	handler, repo := setupTestHandler()
	r := mux.NewRouter()
	handler.RegisterRoutes(r)

	repo.budgets["delete-test"] = &Budget{ID: "delete-test", Name: "To Delete", Scope: ScopeOrganization, LimitUSD: 100, Period: PeriodMonthly}

	req := httptest.NewRequest("DELETE", "/api/v1/budgets/delete-test", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Errorf("status = %v, want %v", rr.Code, http.StatusNoContent)
	}
}

func TestDeleteBudgetHandlerNotFound(t *testing.T) {
	handler, _ := setupTestHandler()
	r := mux.NewRouter()
	handler.RegisterRoutes(r)

	req := httptest.NewRequest("DELETE", "/api/v1/budgets/nonexistent", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("status = %v, want %v", rr.Code, http.StatusNotFound)
	}
}

func TestGetBudgetStatusHandler(t *testing.T) {
	handler, repo := setupTestHandler()
	r := mux.NewRouter()
	handler.RegisterRoutes(r)

	repo.budgets["status-test"] = &Budget{
		ID:       "status-test",
		Name:     "Status Test",
		Scope:    ScopeOrganization,
		ScopeID:  "org-1",
		LimitUSD: 100,
		Period:   PeriodMonthly,
		OrgID:    "org-1",
		Enabled:  true,
	}
	repo.SetUsageForScope(ScopeOrganization, "org-1", "org-1", 50.0)

	req := httptest.NewRequest("GET", "/api/v1/budgets/status-test/status", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %v, want %v, body = %s", rr.Code, http.StatusOK, rr.Body.String())
	}

	var result BudgetStatus
	json.Unmarshal(rr.Body.Bytes(), &result)

	if result.UsedUSD != 50.0 {
		t.Errorf("UsedUSD = %v, want 50", result.UsedUSD)
	}
}

func TestGetBudgetAlertsHandler(t *testing.T) {
	handler, repo := setupTestHandler()
	r := mux.NewRouter()
	handler.RegisterRoutes(r)

	repo.budgets["alerts-test"] = &Budget{ID: "alerts-test", Name: "Alerts Test", Scope: ScopeOrganization, LimitUSD: 100, Period: PeriodMonthly}
	repo.alerts = []BudgetAlert{
		{ID: 1, BudgetID: "alerts-test", Threshold: 80, AlertType: AlertTypeThresholdReached},
		{ID: 2, BudgetID: "alerts-test", Threshold: 100, AlertType: AlertTypeBudgetExceeded},
	}

	req := httptest.NewRequest("GET", "/api/v1/budgets/alerts-test/alerts", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %v, want %v", rr.Code, http.StatusOK)
	}

	var result map[string]interface{}
	json.Unmarshal(rr.Body.Bytes(), &result)

	if result["count"].(float64) != 2 {
		t.Errorf("count = %v, want 2", result["count"])
	}
}

func TestGetUsageSummaryHandler(t *testing.T) {
	handler, _ := setupTestHandler()
	r := mux.NewRouter()
	handler.RegisterRoutes(r)

	req := httptest.NewRequest("GET", "/api/v1/usage?org_id=org-1&period=monthly", nil)
	req.Header.Set("X-Org-ID", "org-1")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %v, want %v", rr.Code, http.StatusOK)
	}
}

func TestGetUsageBreakdownHandler(t *testing.T) {
	handler, _ := setupTestHandler()
	r := mux.NewRouter()
	handler.RegisterRoutes(r)

	req := httptest.NewRequest("GET", "/api/v1/usage/breakdown?group_by=provider&period=monthly", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %v, want %v", rr.Code, http.StatusOK)
	}
}

func TestGetUsageBreakdownHandlerInvalidGroupBy(t *testing.T) {
	handler, _ := setupTestHandler()
	r := mux.NewRouter()
	handler.RegisterRoutes(r)

	req := httptest.NewRequest("GET", "/api/v1/usage/breakdown?group_by=invalid", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %v, want %v", rr.Code, http.StatusBadRequest)
	}
}

func TestListUsageRecordsHandler(t *testing.T) {
	handler, _ := setupTestHandler()
	r := mux.NewRouter()
	handler.RegisterRoutes(r)

	req := httptest.NewRequest("GET", "/api/v1/usage/records?org_id=org-1", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %v, want %v", rr.Code, http.StatusOK)
	}
}

func TestGetPricingHandler(t *testing.T) {
	handler, _ := setupTestHandler()
	r := mux.NewRouter()
	handler.RegisterRoutes(r)

	req := httptest.NewRequest("GET", "/api/v1/pricing", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %v, want %v", rr.Code, http.StatusOK)
	}

	var result map[string]interface{}
	json.Unmarshal(rr.Body.Bytes(), &result)

	if result["providers"] == nil {
		t.Error("expected providers in response")
	}
}

func TestGetPricingHandlerByProvider(t *testing.T) {
	handler, _ := setupTestHandler()
	r := mux.NewRouter()
	handler.RegisterRoutes(r)

	req := httptest.NewRequest("GET", "/api/v1/pricing?provider=anthropic", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %v, want %v", rr.Code, http.StatusOK)
	}
}

func TestGetPricingHandlerByModel(t *testing.T) {
	handler, _ := setupTestHandler()
	r := mux.NewRouter()
	handler.RegisterRoutes(r)

	req := httptest.NewRequest("GET", "/api/v1/pricing?provider=anthropic&model=claude-sonnet-4", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %v, want %v", rr.Code, http.StatusOK)
	}
}

func TestGetPricingHandlerUnknownModel(t *testing.T) {
	handler, _ := setupTestHandler()
	r := mux.NewRouter()
	handler.RegisterRoutes(r)

	req := httptest.NewRequest("GET", "/api/v1/pricing?provider=unknown&model=unknown", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Errorf("status = %v, want %v", rr.Code, http.StatusNotFound)
	}
}

func TestCheckBudgetHandler(t *testing.T) {
	handler, repo := setupTestHandler()
	r := mux.NewRouter()
	handler.RegisterRoutes(r)

	repo.budgets["check-test"] = &Budget{
		ID:       "check-test",
		Name:     "Check Test",
		Scope:    ScopeOrganization,
		ScopeID:  "org-1",
		LimitUSD: 100,
		Period:   PeriodMonthly,
		OrgID:    "org-1",
		OnExceed: OnExceedBlock,
		Enabled:  true,
	}

	body := CheckBudgetRequest{
		OrgID: "org-1",
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest("POST", "/api/v1/budgets/check", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %v, want %v, body = %s", rr.Code, http.StatusOK, rr.Body.String())
	}

	var result BudgetDecision
	json.Unmarshal(rr.Body.Bytes(), &result)

	if !result.Allowed {
		t.Error("expected request to be allowed (under budget)")
	}
}

func TestCheckBudgetHandlerBlocked(t *testing.T) {
	handler, repo := setupTestHandler()
	r := mux.NewRouter()
	handler.RegisterRoutes(r)

	repo.budgets["block-test"] = &Budget{
		ID:       "block-test",
		Name:     "Block Test",
		Scope:    ScopeOrganization,
		ScopeID:  "org-1",
		LimitUSD: 100,
		Period:   PeriodMonthly,
		OrgID:    "org-1",
		OnExceed: OnExceedBlock,
		Enabled:  true,
	}
	repo.SetUsageForScope(ScopeOrganization, "org-1", "org-1", 150.0)

	body := CheckBudgetRequest{
		OrgID: "org-1",
	}
	bodyBytes, _ := json.Marshal(body)

	req := httptest.NewRequest("POST", "/api/v1/budgets/check", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %v, want %v", rr.Code, http.StatusOK)
	}

	var result BudgetDecision
	json.Unmarshal(rr.Body.Bytes(), &result)

	if result.Allowed {
		t.Error("expected request to be blocked (over budget)")
	}
}

func TestCheckBudgetHandlerInvalidBody(t *testing.T) {
	handler, _ := setupTestHandler()
	r := mux.NewRouter()
	handler.RegisterRoutes(r)

	req := httptest.NewRequest("POST", "/api/v1/budgets/check", bytes.NewReader([]byte("invalid")))
	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %v, want %v", rr.Code, http.StatusBadRequest)
	}
}

func TestCORSPreflight(t *testing.T) {
	handler, _ := setupTestHandler()
	r := mux.NewRouter()
	handler.RegisterRoutes(r)

	endpoints := []string{
		"/api/v1/budgets",
		"/api/v1/budgets/test-id",
		"/api/v1/budgets/test-id/status",
		"/api/v1/usage",
		"/api/v1/pricing",
	}

	for _, endpoint := range endpoints {
		req := httptest.NewRequest("OPTIONS", endpoint, nil)
		rr := httptest.NewRecorder()
		r.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("OPTIONS %s: status = %v, want %v", endpoint, rr.Code, http.StatusOK)
		}
	}
}

func TestFirstOrDefault(t *testing.T) {
	tests := []struct {
		name   string
		values []string
		want   string
	}{
		{"first non-empty", []string{"first", "second"}, "first"},
		{"second non-empty", []string{"", "second"}, "second"},
		{"all empty", []string{"", ""}, ""},
		{"no values", []string{}, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := firstOrDefault(tt.values...)
			if got != tt.want {
				t.Errorf("firstOrDefault() = %v, want %v", got, tt.want)
			}
		})
	}
}
