// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"testing"
	"time"

	"github.com/gorilla/mux"

	"axonflow/platform/shared/policypath"
)

// TestLegacyTenantExport_RealPG_NullCategoryRowIsExported proves #4293 on a real
// table: a row the policy-CRUD import writes lands with category NULL, and the
// tenant-policy export returns it on both spellings, beside a dynamic- row
// and a pii row.
//
// The NULL is asserted from the table itself, not assumed: if the writer ever
// starts naming a category, this cell says so instead of passing over a class
// that no longer exists.
//
// BOTH TENANCY SHAPES. #4306 (e8d6076fd, ea9254ec3) fixed the other half of
// this export: where the caller's tenant is not its organization's id (every
// Community client), the organization's rows were missing from both the list
// and the export. A regression there is invisible on the Enterprise shape, so
// both run here, and the category fix and the tenancy fix are pinned together.
func TestLegacyTenantExport_RealPG_NullCategoryRowIsExported(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()
	stamp := time.Now().Format("20060102150405")

	for _, shape := range []struct{ name, tenantID, orgID string }{
		{"enterprise: tenant is the organization", "test-tenant-4293-ent-" + stamp, "test-tenant-4293-ent-" + stamp},
		{"community: tenant is a client id, not the organization", "test-client-4293-ce-" + stamp, "test-org-4293-ce-" + stamp},
	} {
		t.Run(shape.name, func(t *testing.T) {
			exportAllRowsOfTheOrganization(t, db, shape.tenantID, shape.orgID)
		})
	}
}

func exportAllRowsOfTheOrganization(t *testing.T, db *sql.DB, tenantID, orgID string) {
	t.Helper()
	repo := NewPolicyRepository(db)
	defer cleanupTestPolicies(t, db, tenantID)
	ctx := context.Background()

	reqs := []CreatePolicyRequest{
		{Name: "CRUD-written", Description: "no category", Type: "content",
			Conditions: []PolicyCondition{{Field: "query", Operator: "contains", Value: "a"}},
			Actions:    []PolicyAction{{Type: "block", Config: map[string]interface{}{}}}, Priority: 1, Enabled: true},
		{Name: "Dynamic", Description: "dynamic- category", Type: "content",
			Conditions: []PolicyCondition{{Field: "query", Operator: "contains", Value: "b"}},
			Actions:    []PolicyAction{{Type: "block", Config: map[string]interface{}{}}}, Priority: 2, Enabled: true},
		{Name: "PII", Description: "pii category", Type: "content",
			Conditions: []PolicyCondition{{Field: "query", Operator: "contains", Value: "c"}},
			Actions:    []PolicyAction{{Type: "block", Config: map[string]interface{}{}}}, Priority: 3, Enabled: true},
	}
	res, err := repo.ImportBulk(ctx, tenantID, orgID, reqs, "error", "test-user")
	if err != nil {
		t.Fatalf("ImportBulk() error = %v", err)
	}
	if len(res.Errors) != 0 {
		t.Fatalf("ImportBulk() row errors = %v", res.Errors)
	}
	for name, category := range map[string]string{"Dynamic": "dynamic-risk", "PII": "pii"} {
		if _, err := db.Exec(`UPDATE dynamic_policies SET category = $1 WHERE tenant_id = $2 AND name = $3`, category, tenantID, name); err != nil {
			t.Fatalf("set category of %s: %v", name, err)
		}
	}

	var nullRows int
	if err := db.QueryRow(`SELECT count(*) FROM dynamic_policies WHERE tenant_id = $1 AND category IS NULL`, tenantID).Scan(&nullRows); err != nil {
		t.Fatalf("count NULL-category rows: %v", err)
	}
	if nullRows != 1 {
		t.Fatalf("the CRUD import writer left %d rows with category NULL, want 1: the premise of #4293's class moved", nullRows)
	}

	handler := NewDynamicPolicyAPIHandler(&mockDynamicPolicyService{
		exportFunc: func(ctx context.Context, _ string) (*ExportPoliciesResponse, error) {
			policies, err := repo.ExportAll(ctx, tenantID, orgID)
			if err != nil {
				return nil, err
			}
			return &ExportPoliciesResponse{Policies: policies, TenantID: tenantID}, nil
		},
	})
	r := mux.NewRouter()
	registerLegacyPolicyRoutes(r, handler, nil)

	want := []string{"CRUD-written", "Dynamic", "PII"}
	// Both spellings from policypath, the one home of these prefixes.
	for _, path := range []string{policypath.TenantPolicies + "/export", policypath.LegacyTenantPolicies + "/export"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("X-Tenant-ID", tenantID)
		req.Header.Set("X-Org-ID", orgID)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("%s: status %d: %s", path, w.Code, w.Body.String())
		}
		var resp ExportPoliciesResponse
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("%s: unmarshal: %v", path, err)
		}
		var got []string
		for _, p := range resp.Policies {
			if p.TenantID == tenantID {
				got = append(got, p.Name)
			}
		}
		sort.Strings(got)
		if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] || got[2] != want[2] {
			t.Errorf("%s exported the organization's rows %v, want %v (the NULL-category row included)", path, got, want)
		}
	}
}
