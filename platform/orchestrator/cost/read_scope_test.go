// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package cost

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"
)

// #2934: org/tenant isolation of the by-id budget routes and spend redaction
// on the budget-check enforcement plane. The unhappy paths (cross-org IDOR,
// cross-org DELETE, redacted decision) are first-class here, not the happy
// path.

func seedOrgBudget(repo *MockRepository, id, orgID string) {
	repo.budgets[id] = &Budget{
		ID:       id,
		Name:     "Budget " + id,
		Scope:    ScopeOrganization,
		ScopeID:  orgID,
		LimitUSD: 100,
		Period:   PeriodMonthly,
		OrgID:    orgID,
		OnExceed: OnExceedBlock,
		Enabled:  true,
	}
}

func TestGetBudgetHandler_CrossOrgIsNotFound(t *testing.T) {
	handler, repo := setupTestHandler()
	r := mux.NewRouter()
	handler.RegisterRoutes(r)
	seedOrgBudget(repo, "b-org-a", "org-a")

	// The IDOR variant: a caller from org-b knows/guesses org-a's budget id.
	req := httptest.NewRequest("GET", "/api/v1/budgets/b-org-a", nil)
	req.Header.Set("X-Tenant-ID", "tenant-1")
	req.Header.Set("X-Org-ID", "org-b")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Fatalf("cross-org budget read must be 404, got %d body=%s", rr.Code, rr.Body.String())
	}

	// Control (non-vacuous): the owning org still reads it.
	req = httptest.NewRequest("GET", "/api/v1/budgets/b-org-a", nil)
	req.Header.Set("X-Tenant-ID", "tenant-1")
	req.Header.Set("X-Org-ID", "org-a")
	rr = httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("same-org budget read must be 200, got %d", rr.Code)
	}
}

func TestUpdateBudgetHandler_CrossOrgIsNotFound(t *testing.T) {
	handler, repo := setupTestHandler()
	r := mux.NewRouter()
	handler.RegisterRoutes(r)
	seedOrgBudget(repo, "b-org-a", "org-a")

	body, _ := json.Marshal(Budget{Name: "hijacked"})
	req := httptest.NewRequest("PUT", "/api/v1/budgets/b-org-a", bytes.NewReader(body))
	req.Header.Set("X-Tenant-ID", "tenant-1")
	req.Header.Set("X-Org-ID", "org-b")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Fatalf("cross-org budget update must be 404, got %d", rr.Code)
	}
	if repo.budgets["b-org-a"].Name == "hijacked" {
		t.Fatal("cross-org update must not mutate the budget")
	}
}

func TestDeleteBudgetHandler_CrossOrgIsNotFound(t *testing.T) {
	handler, repo := setupTestHandler()
	r := mux.NewRouter()
	handler.RegisterRoutes(r)
	seedOrgBudget(repo, "b-org-a", "org-a")

	req := httptest.NewRequest("DELETE", "/api/v1/budgets/b-org-a", nil)
	req.Header.Set("X-Tenant-ID", "tenant-1")
	req.Header.Set("X-Org-ID", "org-b")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Fatalf("cross-org budget delete must be 404, got %d", rr.Code)
	}
	if _, still := repo.budgets["b-org-a"]; !still {
		t.Fatal("cross-org delete must not remove the budget")
	}

	// Control: the owning org can delete.
	req = httptest.NewRequest("DELETE", "/api/v1/budgets/b-org-a", nil)
	req.Header.Set("X-Tenant-ID", "tenant-1")
	req.Header.Set("X-Org-ID", "org-a")
	rr = httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("same-org budget delete must be 204, got %d", rr.Code)
	}
}

func TestBudgetStatusAndAlertsHandlers_CrossOrgIsNotFound(t *testing.T) {
	handler, repo := setupTestHandler()
	r := mux.NewRouter()
	handler.RegisterRoutes(r)
	seedOrgBudget(repo, "b-org-a", "org-a")
	repo.SetUsageForScope(ScopeOrganization, "org-a", "org-a", 42.0)

	for _, path := range []string{
		"/api/v1/budgets/b-org-a/status",
		"/api/v1/budgets/b-org-a/alerts",
	} {
		req := httptest.NewRequest("GET", path, nil)
		req.Header.Set("X-Tenant-ID", "tenant-1")
		req.Header.Set("X-Org-ID", "org-b")
		rr := httptest.NewRecorder()
		r.ServeHTTP(rr, req)
		if rr.Code != http.StatusNotFound {
			t.Fatalf("cross-org %s must be 404, got %d", path, rr.Code)
		}

		req = httptest.NewRequest("GET", path, nil)
		req.Header.Set("X-Tenant-ID", "tenant-1")
		req.Header.Set("X-Org-ID", "org-a")
		rr = httptest.NewRecorder()
		r.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("same-org %s must be 200, got %d", path, rr.Code)
		}
	}
}

func TestGetBudgetHandler_GlobalBudgetVisibleToAnyOrg(t *testing.T) {
	handler, repo := setupTestHandler()
	r := mux.NewRouter()
	handler.RegisterRoutes(r)
	// Deployment-global budget: no org/tenant stamp.
	repo.budgets["b-global"] = &Budget{
		ID: "b-global", Name: "Global", Scope: ScopeOrganization,
		LimitUSD: 100, Period: PeriodMonthly, Enabled: true, OnExceed: OnExceedWarn,
	}

	req := httptest.NewRequest("GET", "/api/v1/budgets/b-global", nil)
	req.Header.Set("X-Tenant-ID", "tenant-1")
	req.Header.Set("X-Org-ID", "org-b")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("global budget must stay visible, got %d", rr.Code)
	}
}

func TestCheckBudgetHandler_RedactsSpendWhenRequested(t *testing.T) {
	handler, repo := setupTestHandler()
	r := mux.NewRouter()
	handler.RegisterRoutes(r)
	seedOrgBudget(repo, "block-test", "org-1")
	repo.SetUsageForScope(ScopeOrganization, "org-1", "org-1", 150.0)

	do := func(redact bool) BudgetDecision {
		body, _ := json.Marshal(CheckBudgetRequest{OrgID: "org-1"})
		req := httptest.NewRequest("POST", "/api/v1/budgets/check", bytes.NewReader(body))
		req.Header.Set("X-Org-ID", "org-1")
		req.Header.Set("X-Tenant-ID", "tenant-1")
		req.Header.Set("Content-Type", "application/json")
		if redact {
			req = req.WithContext(WithSpendRedaction(req.Context()))
		}
		rr := httptest.NewRecorder()
		r.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("budget check must stay reachable, got %d", rr.Code)
		}
		var d BudgetDecision
		if err := json.Unmarshal(rr.Body.Bytes(), &d); err != nil {
			t.Fatalf("decode: %v", err)
		}
		return d
	}

	// Control (non-vacuous): tenant-wide callers see the spend figures.
	full := do(false)
	if full.Allowed || full.UsedUSD != 150.0 || full.LimitUSD != 100.0 {
		t.Fatalf("control decision must carry spend figures, got %+v", full)
	}

	redacted := do(true)
	if redacted.Allowed {
		t.Fatal("redaction must not change the verdict")
	}
	if redacted.UsedUSD != 0 || redacted.LimitUSD != 0 || redacted.Percentage != 0 {
		t.Fatalf("redacted decision leaked spend figures: %+v", redacted)
	}
	// #2934 R3: budget identity is an oracle for another scope's budget — it
	// must be stripped too, along with the name in the message.
	if redacted.BudgetID != "" || redacted.BudgetName != "" {
		t.Fatalf("redaction must strip budget identity, got %+v", redacted)
	}
	if strings.Contains(redacted.Message, "E2E") || strings.Contains(redacted.Message, "block-test") {
		t.Fatalf("redacted message must not leak the budget name/id, got %q", redacted.Message)
	}
}

func TestSpendRedactionContext(t *testing.T) {
	ctx := context.Background()
	if SpendRedactionRequested(ctx) {
		t.Fatal("bare context must not request redaction")
	}
	if !SpendRedactionRequested(WithSpendRedaction(ctx)) {
		t.Fatal("marked context must request redaction")
	}
}

func TestRedactSpend_StripsFiguresAndIdentity(t *testing.T) {
	d := &BudgetDecision{
		Allowed: false, Action: OnExceedBlock, BudgetID: "b", BudgetName: "Monthly",
		UsedUSD: 120, LimitUSD: 100, Percentage: 120,
		Message: "Budget 'Monthly' exceeded - 120.0%",
	}
	d.redactSpend()
	if d.UsedUSD != 0 || d.LimitUSD != 0 || d.Percentage != 0 {
		t.Fatalf("spend figures must be zeroed, got %+v", d)
	}
	if d.BudgetID != "" || d.BudgetName != "" {
		t.Fatalf("budget identity must be stripped, got %+v", d)
	}
	if strings.Contains(d.Message, "Monthly") || strings.Contains(d.Message, "120") {
		t.Fatalf("message must not leak name/percentage, got %q", d.Message)
	}
	if d.Action != OnExceedBlock || d.Allowed {
		t.Fatalf("verdict (allowed/action) must be preserved, got %+v", d)
	}
}

// Service-level scoped accessors: tenant filter and empty-scope behavior.
func TestServiceScopedBudgetAccessors(t *testing.T) {
	repo := NewMockRepository()
	service := NewService(repo, nil)
	ctx := context.Background()
	seedOrgBudget(repo, "b1", "org-a")
	repo.budgets["b1"].TenantID = "tenant-a"

	if _, err := service.GetBudgetScoped(ctx, "b1", "org-a", "tenant-a"); err != nil {
		t.Fatalf("same org+tenant must resolve: %v", err)
	}
	if _, err := service.GetBudgetScoped(ctx, "b1", "org-a", "tenant-b"); err != ErrBudgetNotFound {
		t.Fatalf("cross-tenant must be ErrBudgetNotFound, got %v", err)
	}
	// Empty scope (single-tenant Community, internal callers) is unfiltered.
	if _, err := service.GetBudgetScoped(ctx, "b1", "", ""); err != nil {
		t.Fatalf("empty scope must resolve: %v", err)
	}
	if err := service.DeleteBudgetScoped(ctx, "b1", "org-b", ""); err != ErrBudgetNotFound {
		t.Fatalf("cross-org scoped delete must be ErrBudgetNotFound, got %v", err)
	}
	if err := service.DeleteBudgetScoped(ctx, "b1", "org-a", "tenant-a"); err != nil {
		t.Fatalf("same-org scoped delete must succeed: %v", err)
	}
}
