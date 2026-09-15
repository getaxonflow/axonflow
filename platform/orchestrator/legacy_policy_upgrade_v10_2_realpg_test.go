// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

// #3894 clause (a), the orchestrator's half. On a database the agent's own
// runner upgraded from v10.2.0 to v11, an organization's own dynamic row, written
// on v10.2.0, is still returned by the routes it reads and exports its policies
// through (PRD v11 §1.11), and the routes it wrote them through answer the
// freeze (§1.5, the class #4237 made true): 409 LEGACY_POLICY_WRITE_FROZEN
// naming the typed route, with the row untouched. Both spellings of the tenant
// policy API, through the real registrar, over the application role.
//
// The agent's half, platform/agent/migration_v10_2_upgrade_realpg_test.go,
// holds the runner, the survival of the rows, the freeze in SQL, the decide,
// the restart and the rollback on the same upgrade path.

import (
	"database/sql"
	"encoding/json"
	"errors"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"axonflow/platform/agent"
	"axonflow/platform/agent/approletest"
	"axonflow/platform/agent/upgradepin"
	"axonflow/platform/shared/legacyfreeze"
)

const (
	upgV1020CustomID     = "w3x3894_orch_custom_dynamic"
	upgV1020CustomName   = "W3X 3894 orchestrator custom dynamic"
	upgV1020AppRolePass  = "w3x3894-orch-app-role"
	upgV1020SessionOrgID = "local-dev-org"
)

func TestTheV1020DynamicRowsAreReadableAndFrozenAfterTheUpgrade_RealPostgres(t *testing.T) {
	approletest.SkipUnlessEnabled(t)
	repoRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ mode, org, tenant string }{
		// Community is one organization, the deployment's.
		{"community", upgV1020SessionOrgID, "w3x3894-client"},
		{"community-saas", "w3x3894-org", "w3x3894-org"},
		{"saas", "w3x3894-org", "w3x3894-org"},
	} {
		t.Run(c.mode, func(t *testing.T) { runV1020OrchestratorUpgrade(t, repoRoot, c.mode, c.org, c.tenant) })
	}
}

func runV1020OrchestratorUpgrade(t *testing.T, repoRoot, mode, org, tenant string) {
	t.Setenv("DEPLOYMENT_MODE", mode)
	t.Setenv("GRAFANA_PASSWORD", "")

	pinnedDir := t.TempDir()
	pinned, err := upgradepin.Materialize(repoRoot, mode, pinnedDir)
	if err != nil {
		t.Fatalf("materializing v10.2.0's %s set: %v", mode, err)
	}
	if len(pinned.Absent) > 0 {
		if _, statErr := os.Stat(filepath.Join(repoRoot, "ee")); errors.Is(statErr, fs.ErrNotExist) {
			t.Skipf("community mirror: %v not carried", pinned.Absent)
		}
		t.Fatalf("categories %v are absent from a checkout with ee/", pinned.Absent)
	}
	old, err := agent.CollectMigrations(pinnedDir)
	if err != nil {
		t.Fatal(err)
	}
	live, err := agent.CollectMigrations(filepath.Join(repoRoot, "migrations"))
	if err != nil {
		t.Fatal(err)
	}

	dsn, cleanup := approletest.StartPostgres(t)
	t.Cleanup(cleanup)
	owner := upgV1020Open(t, dsn)
	vars := agent.MigrationSessionVars{DBPassword: "testpass", DeploymentOrgID: upgV1020SessionOrgID, DeploymentKind: "dev"}
	if _, _, err := agent.RunMigrations(upgV1020Open(t, dsn), old, vars); err != nil {
		t.Fatalf("the v10.2.0 boot: %v", err)
	}
	if _, err := owner.Exec(`INSERT INTO dynamic_policies (policy_id, name, description, policy_type, conditions, actions, priority, enabled,
	                                                      tenant_id, client_id, org_id, tier, category, created_by, updated_by)
		VALUES ($1, $2, 'an organization''s own legacy row, written on v10.2.0', 'content',
		        '[{"field":"query","operator":"contains","value":"w3x3894-orch-marker"}]'::jsonb,
		        '[{"type":"block","config":{"reason":"W3X 3894"}}]'::jsonb, 900, true, $3, $3, $4, 'tenant', 'dynamic-security', 'w3x-3894', 'w3x-3894')`,
		upgV1020CustomID, upgV1020CustomName, tenant, org); err != nil {
		t.Fatalf("seeding the custom dynamic row on v10.2.0: %v", err)
	}
	rowState := func(t *testing.T) string {
		t.Helper()
		var s string
		if err := owner.QueryRow(`SELECT row_to_json(r)::text FROM (SELECT name, conditions, actions, enabled, deleted_at, updated_at
			FROM dynamic_policies WHERE policy_id = $1) r`, upgV1020CustomID).Scan(&s); err != nil {
			t.Fatalf("reading the custom row as the owner: %v", err)
		}
		return s
	}
	before := rowState(t)
	if applied, _, err := agent.RunMigrations(upgV1020Open(t, dsn), live, vars); err != nil || applied == 0 {
		t.Fatalf("the v11 boot applied %d (%v); want the migrations added since v10.2.0", applied, err)
	}

	if _, err := owner.Exec(`ALTER ROLE axonflow_app_role WITH LOGIN PASSWORD '` + upgV1020AppRolePass + `'`); err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	u.User = url.UserPassword("axonflow_app_role", upgV1020AppRolePass)
	app := upgV1020Open(t, u.String())
	approletest.AssertCurrentUser(t, app, "axonflow_app_role")
	router := legacyImportRouter(t, NewPolicyService(NewPolicyRepository(app), nil))
	headers := map[string]string{"X-Tenant-ID": tenant, "X-Org-ID": org, "X-User-ID": "w3x-3894"}

	for _, prefix := range []string{"/api/v1/dynamic-policies", "/api/v1/tenant-policies"} {
		t.Run("PRD v11 §1.11: the reads and the export on "+prefix+" return the row", func(t *testing.T) {
			for _, path := range []string{prefix, prefix + "/export"} {
				rr, _ := legacyImport(t, router, http.MethodGet, path, "", headers)
				var out struct {
					Policies []PolicyResource `json:"policies"`
				}
				if err := json.Unmarshal(rr.Body.Bytes(), &out); rr.Code != http.StatusOK || err != nil || !upgV1020Holds(out.Policies) {
					t.Errorf("GET %s: HTTP %d (decode err %v); want 200 listing %s. body=%s", path, rr.Code, err, upgV1020CustomID, rr.Body.String())
				}
			}
			rr, _ := legacyImport(t, router, http.MethodGet, prefix+"/"+upgV1020CustomID, "", headers)
			if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), upgV1020CustomName) {
				t.Errorf("GET %s/%s: HTTP %d; want 200 naming the row. body=%s", prefix, upgV1020CustomID, rr.Code, rr.Body.String())
			}
		})

		t.Run("PRD v11 §1.5: the writes on "+prefix+" answer the freeze", func(t *testing.T) {
			row := `{"name":"W3X 3894 after the upgrade","type":"content","category":"dynamic-security",` +
				`"conditions":[{"field":"query","operator":"contains","value":"x"}],"actions":[{"type":"block"}],"priority":10,"enabled":true}`
			for _, w := range []struct{ method, path, body string }{
				{http.MethodPost, prefix, row},
				{http.MethodPut, prefix + "/" + upgV1020CustomID, `{"name":"W3X 3894 renamed"}`},
				{http.MethodDelete, prefix + "/" + upgV1020CustomID, ""},
				{http.MethodPost, prefix + "/import", `{"policies":[` + row + `]}`},
			} {
				rr, _ := legacyImport(t, router, w.method, w.path, w.body, headers)
				if rr.Code != http.StatusConflict {
					t.Errorf("%s %s: HTTP %d; want 409. body=%s", w.method, w.path, rr.Code, rr.Body.String())
					continue
				}
				if out := decodeCoded(t, rr); out.Error.Code != legacyfreeze.ErrCode || !strings.Contains(out.Error.Message, TypedAuthoringRoutePrefix) {
					t.Errorf("%s %s: code %q message %q; want %s naming %s", w.method, w.path, out.Error.Code, out.Error.Message, legacyfreeze.ErrCode, TypedAuthoringRoutePrefix)
				}
			}
			if after := rowState(t); after != before {
				t.Errorf("the refused writes changed the row:\nbefore %s\nafter  %s", before, after)
			}
		})
	}
}

func upgV1020Holds(policies []PolicyResource) bool {
	for _, p := range policies {
		if p.ID == upgV1020CustomID {
			return true
		}
	}
	return false
}

func upgV1020Open(t *testing.T, dsn string) *sql.DB {
	t.Helper()
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.Ping(); err != nil {
		t.Fatalf("connecting: %v", err)
	}
	return db
}
