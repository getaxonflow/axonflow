// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package cost

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/gorilla/mux"
)

// #3065 F4 — cross-tenant BUDGET DELETE via header omission.
//
// budgetOrgScopeSQL carried the fail-open compare rewritten as SQL:
//
//	AND ($2 = '' OR org_id IS NULL OR org_id = '' OR org_id = $2)
//
// and the caller's org fell back to the `org_id` QUERY PARAMETER. So
// `DELETE /api/v1/budgets/{id}` with neither the header nor the parameter
// matched the `$2 = ''` disjunct and removed another tenant's budget. The
// #2934 fix that introduced this predicate described it as "isolated in the
// SQL WHERE clause — never post-fetch", which is true and irrelevant:
// isolation in SQL is not the same property as failing closed.
//
// `budgets` has no RLS in any posture, so nothing underneath caught it.

// budgetByIDRoutes enumerates the id-addressed budget surfaces.
func budgetByIDRoutes(id string) []struct {
	name, method, path string
} {
	return []struct{ name, method, path string }{
		{"GetBudget", http.MethodGet, "/api/v1/budgets/" + id},
		{"UpdateBudget", http.MethodPut, "/api/v1/budgets/" + id},
		{"DeleteBudget", http.MethodDelete, "/api/v1/budgets/" + id},
		{"GetBudgetStatus", http.MethodGet, "/api/v1/budgets/" + id + "/status"},
		{"GetBudgetAlerts", http.MethodGet, "/api/v1/budgets/" + id + "/alerts"},
	}
}

func TestBudget_CallerOmitsTenancy_IsDeniedBeforeAnySQL(t *testing.T) {
	handler, _ := setupTestHandler()
	r := mux.NewRouter()
	handler.RegisterRoutes(r)

	for _, route := range budgetByIDRoutes("b1") {
		for _, tc := range []struct {
			name string
			url  string
			hdrs map[string]string
		}{
			{"no headers, no params", route.path, nil},
			{"org param only — the pre-fix fallback channel", route.path + "?org_id=org-victim", nil},
			{"tenant header only", route.path, map[string]string{"X-Tenant-ID": "tenant-a"}},
			{"org header only", route.path, map[string]string{"X-Org-ID": "org-a"}},
		} {
			t.Run(route.name+"/"+tc.name, func(t *testing.T) {
				req := httptest.NewRequest(route.method, tc.url, nil)
				for k, v := range tc.hdrs {
					req.Header.Set(k, v)
				}
				rr := httptest.NewRecorder()
				r.ServeHTTP(rr, req)
				if rr.Code != http.StatusUnauthorized {
					t.Fatalf("pre-fix an unbound caller reached the SQL and matched every row; got %d: %s",
						rr.Code, rr.Body.String())
				}
			})
		}
	}
}

// TestBudget_ListIsNeverTenantWide: the listing carried the same query-param
// fallback and the same empty-disables-the-predicate behaviour.
func TestBudget_ListIsNeverTenantWide(t *testing.T) {
	handler, _ := setupTestHandler()
	r := mux.NewRouter()
	handler.RegisterRoutes(r)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/budgets?org_id=org-victim&tenant_id=tenant-victim", nil)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("a caller naming someone else's org in a query param must be refused, got %d: %s",
			rr.Code, rr.Body.String())
	}
}

// TestBudgetRepository_UnboundCallerIssuesNoSQL is the layer-below proof: the
// repository refuses before the statement is built, so there is no window in
// which the predicate could match an unstamped row.
func TestBudgetRepository_UnboundCallerIssuesNoSQL(t *testing.T) {
	for _, tc := range []struct{ name, org, tenant string }{
		{"neither", "", ""},
		{"org missing", "", "tenant-a"},
		{"tenant missing", "org-a", ""},
		{"whitespace", "  ", "\t"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatalf("sqlmock.New: %v", err)
			}
			defer db.Close()
			repo := NewPostgresRepository(db)

			if _, err := repo.GetBudgetScoped(context.Background(), "b1", tc.org, tc.tenant); err != ErrBudgetNotFound {
				t.Errorf("GetBudgetScoped must be ErrBudgetNotFound, got %v", err)
			}
			if err := repo.DeleteBudgetScoped(context.Background(), "b1", tc.org, tc.tenant); err != ErrBudgetNotFound {
				t.Errorf("DeleteBudgetScoped must be ErrBudgetNotFound, got %v", err)
			}
			if _, _, err := repo.ListBudgets(context.Background(), ListBudgetsOptions{OrgID: tc.org, TenantID: tc.tenant}); err != ErrBudgetNotFound {
				t.Errorf("ListBudgets must be ErrBudgetNotFound, got %v", err)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("an unbound caller must issue no SQL at all: %v", err)
			}
		})
	}
}

// TestBudgetRepository_RefusesUnownedWrite: make the empty state
// unrepresentable — CreateBudget wrote org/tenant through nullString(), so an
// absent header produced the NULL org that every tenant could then reach.
func TestBudgetRepository_RefusesUnownedWrite(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()
	repo := NewPostgresRepository(db)

	if err := repo.CreateBudget(context.Background(), &Budget{ID: "b1", Name: "n"}); err == nil {
		t.Error("persisting a budget with no tenancy key manufactures a row every tenant can delete")
	}
	if err := repo.UpdateBudget(context.Background(), &Budget{ID: "b1", Name: "n"}); err != ErrBudgetNotFound {
		t.Errorf("an unbound update must be ErrBudgetNotFound, got %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("an unowned write must issue no SQL: %v", err)
	}
}

// TestBudget_SameTenantStillWorks is the positive control.
func TestBudget_SameTenantStillWorks(t *testing.T) {
	handler, _ := setupTestHandler()
	r := mux.NewRouter()
	handler.RegisterRoutes(r)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/budgets", nil)
	req.Header.Set("X-Org-ID", "org-1")
	req.Header.Set("X-Tenant-ID", "tenant-1")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("a fully-scoped caller must still list its own budgets, got %d: %s", rr.Code, rr.Body.String())
	}
}
