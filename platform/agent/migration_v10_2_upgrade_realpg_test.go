// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

// #3894 clause (a): "Test upgrade from an actual Community database with custom
// policies, before and after switching, including rollback and restart."
//
// A database-level upgrade on a real PostgreSQL, per deployment mode, driven by
// the REAL boot runner, RunMigrations, and never a copy of it:
//
//	run 1   v10.2.0's migration set, pinned by digest (platform/agent/upgradepin):
//	        the database a v10.2.0 deployment of the mode runs.
//	seed    the organization's own legacy rows, written as the owner: a custom
//	        static row, a custom dynamic row, and a recorded sqli=block detection
//	        override. They are captured over v10.2.0's columns as the "before
//	        switching" expectation table. The live v10.2.0 binary is #4236's
//	        image-swap suite (v11.1.0); here "before" is the rows as v10.2.0's
//	        schema holds them.
//	run 2   the v11 set: it applies exactly the migrations added since v10.2.0.
//	then    the rows survive byte for byte over v10.2.0's columns; the freeze
//	        holds in SQL (42501 for the application role on both tables) and on
//	        the route (409 LEGACY_POLICY_WRITE_FROZEN); the legacy reads return
//	        the rows (PRD v11 §1.11); a decide on the custom pattern does not
//	        refuse and never names either custom row (§1.2), while a shipped
//	        control still refuses in the same state.
//	run 3   the restart: it applies nothing.
//	down    172_down, the freeze's rollback: the application role writes again,
//	        in SQL and through the route. A restart after it does not re-freeze,
//	        because schema_migrations still records 172; re-applying 172 by hand
//	        does. The runbook section says so.
//
// Modes, measured rather than remembered: community; saas, which production-us
// runs (CloudFormation DeploymentMode=saas, measured 2026-09-13); and
// community-saas, which master's ruling added. The two modes the design named
// are extended, not replaced.
//
// The shipped control that still refuses is sqli under the organization's
// recorded override: every shipped sys_sqli_* row stores warn (#4017), so with
// no override a SQL-injection query is allowed, and the override, which v11
// carries, is what refuses it. Deleting the override lets the same query
// through, so the refusal is the override's.

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"github.com/lib/pq"

	"axonflow/platform/agent/upgradepin"
	"axonflow/platform/decision/activation"
	sharedidentity "axonflow/platform/shared/identity"
	"axonflow/platform/shared/legacyfreeze"
	sharedpolicy "axonflow/platform/shared/policy"
)

type v1020UpgradeMode struct {
	mode     string
	authKind AuthKind
	org      string // the organization a deployment of this mode decides for
	tenant   string
	client   string
}

const (
	v1020CustomStaticID  = "w3x3894_custom_static"
	v1020CustomDynamicID = "w3x3894_custom_dynamic"
	v1020TemplateCopyID  = "w3x3894_template_copy"
	v1020Marker          = "w3x3894-custom-marker-271828"
	v1020SQLiQuery       = "SELECT * FROM users UNION SELECT password FROM admin"
	v1020AppRolePassword = "w3x3894-app-role"
)

func TestTheV1020DatabaseUpgradesToV11WithCustomRowsRestartsAndRollsBack_RealPostgres(t *testing.T) {
	if os.Getenv("TEST_PG_INTEGRATION") != "1" {
		t.Skip("TEST_PG_INTEGRATION=1 not set — skipping the v10.2.0 -> v11 database upgrade test")
	}
	repoRoot, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range []v1020UpgradeMode{
		// Community stamps the deployment organization (ORG_ID, unset here,
		// so local-dev-org) and the client id as the tenant.
		{mode: "community", authKind: AuthKindCommunity, org: "local-dev-org", tenant: "w3x3894-client", client: "w3x3894-client"},
		{mode: "community-saas", authKind: AuthKindCommunitySaaS, org: "w3x3894-org", tenant: "w3x3894-org", client: "w3x3894-client"},
		{mode: "saas", authKind: AuthKindEnterprise, org: "w3x3894-org", tenant: "w3x3894-org", client: "auth-client"},
	} {
		t.Run(m.mode, func(t *testing.T) { runV1020Upgrade(t, repoRoot, m) })
	}
}

func runV1020Upgrade(t *testing.T, repoRoot string, m v1020UpgradeMode) {
	t.Setenv("DEPLOYMENT_MODE", m.mode)
	t.Setenv("GRAFANA_PASSWORD", "")
	t.Setenv("ORG_ID", "")
	t.Setenv("AXONFLOW_LICENSE_KEY", "")

	// ---- the two migration sets ----------------------------------------
	pinnedDir := t.TempDir()
	pinned, err := upgradepin.Materialize(repoRoot, m.mode, pinnedDir)
	if err != nil {
		t.Fatalf("materializing v10.2.0's %s set: %v", m.mode, err)
	}
	if len(pinned.Absent) > 0 {
		if _, statErr := os.Stat(filepath.Join(repoRoot, "ee")); errors.Is(statErr, fs.ErrNotExist) {
			t.Skipf("community mirror: %v not carried, so the %s mode's v10.2.0 database cannot be built here", pinned.Absent, m.mode)
		}
		t.Fatalf("categories %v are absent from a checkout with ee/", pinned.Absent)
	}
	old, err := collectMigrations(pinnedDir)
	if err != nil || len(old) != pinned.Files {
		t.Fatalf("collecting the pinned set: %d files (%v), want the %d materialized", len(old), err, pinned.Files)
	}
	live, err := collectMigrations(filepath.Join(repoRoot, "migrations"))
	if err != nil {
		t.Fatalf("collecting the live set: %v", err)
	}
	liveKeys := map[string]bool{}
	for _, f := range live {
		liveKeys[migrationKey(f.Version, f.Name)] = true
	}
	for _, f := range old {
		if !liveKeys[migrationKey(f.Version, f.Name)] {
			t.Fatalf("v10.2.0's %s [%s] is not in the live set, so the v11 boot would not recognise it as applied", filepath.Base(f.Path), f.Category)
		}
	}
	added := len(live) - len(old)
	if added <= 0 {
		t.Fatalf("the live %s set (%d) adds nothing to v10.2.0's (%d)", m.mode, len(live), len(old))
	}
	grafanaOld, grafanaLive := v1020GrafanaSkips(t, old), v1020GrafanaSkips(t, live)
	t.Logf("%s: v10.2.0 set %d up-migrations (%d from a pin), live set %d, added since v10.2.0 %d; Grafana-skipped %d and %d",
		m.mode, len(old), pinned.Pinned, len(live), added, grafanaOld, grafanaLive)

	// ---- the database ---------------------------------------------------
	dsn, cleanup := startCountTestPostgres(t)
	t.Cleanup(cleanup)
	owner := v1020Open(t, dsn)
	migrationDB, err := openMigrationDB(dsn)
	if err != nil {
		t.Fatalf("opening the migration connection as the boot does: %v", err)
	}
	t.Cleanup(func() { _ = migrationDB.Close() })
	vars := MigrationSessionVars{DBPassword: "testpass", DeploymentOrgID: getDeploymentOrgID(), DeploymentKind: "dev"}

	// ---- run 1: the v10.2.0 boot ---------------------------------------
	applied1, skipped1, err := RunMigrations(migrationDB, old, vars)
	if err != nil {
		t.Fatalf("run 1 (v10.2.0's set): %v", err)
	}
	if applied1 != len(old)-grafanaOld || skipped1 != grafanaOld {
		t.Fatalf("run 1 applied %d and skipped %d; want %d and %d", applied1, skipped1, len(old)-grafanaOld, grafanaOld)
	}
	t.Logf("run 1, the v10.2.0 boot: applied %d, skipped %d", applied1, skipped1)

	// ---- seed the organization's own rows on v10.2.0 -------------------
	v1020Exec(t, owner, "seed the custom static row",
		`INSERT INTO static_policies (policy_id, name, description, category, pattern, severity, action, enabled,
		                              tenant_id, client_id, org_id, tier, priority, created_by, updated_by)
		 VALUES ($1, 'W3X 3894 custom static', 'an organization''s own legacy row, written on v10.2.0',
		         'security-sqli', 'w3x3894-custom-marker-[0-9]{6}', 'high', 'block', true,
		         $2, $2, $3, 'tenant', 900, 'w3x-3894', 'w3x-3894')`,
		v1020CustomStaticID, m.tenant, m.org)
	v1020Exec(t, owner, "seed the custom dynamic row",
		`INSERT INTO dynamic_policies (policy_id, name, description, policy_type, conditions, actions, priority, enabled,
		                               tenant_id, client_id, org_id, tier, category, created_by, updated_by)
		 VALUES ($1, 'W3X 3894 custom dynamic', 'an organization''s own legacy row, written on v10.2.0', 'content',
		         '[{"field":"query","operator":"contains","value":"w3x3894-custom-marker"}]'::jsonb,
		         '[{"type":"block","config":{"reason":"W3X 3894 custom dynamic"}}]'::jsonb, 900, true,
		         $2, $2, $3, 'tenant', 'dynamic-security', 'w3x-3894', 'w3x-3894')`,
		v1020CustomDynamicID, m.tenant, m.org)
	v1020Exec(t, owner, "record the sqli=block override",
		`INSERT INTO detection_action_overrides (org_id, category, action, updated_by) VALUES ($1, $2, $3, 'w3x-3894')`,
		m.org, DetectionCategorySQLI, string(DetectionActionBlock))
	// An organization's copy of the organization template's sql_injection_union
	// row, whose literal core/185 rewrites in every organization: the one
	// change the upgrade makes to an organization's own row, by design.
	v1020Exec(t, owner, "seed an organization's copy of a template row",
		`INSERT INTO static_policies (policy_id, name, description, category, pattern, severity, action, enabled,
		                              tenant_id, client_id, org_id, tier, priority, created_by, updated_by)
		 VALUES ($1, 'W3X 3894 template copy', 'an organization''s copy of the sql_injection_union template row, written on v10.2.0',
		         'security-sqli', 'union\s+select', 'high', 'block', true,
		         $2, $2, $3, 'tenant', 900, 'w3x-3894', 'w3x-3894')`,
		v1020TemplateCopyID, m.tenant, m.org)

	// The "before switching" expectation table: each row over the columns
	// v10.2.0's schema gives its table.
	type captured struct {
		label, table, where string
		args                []any
		cols                []string
		before              string
	}
	rows := []*captured{
		{label: "the custom static row", table: "static_policies", where: "policy_id = $1", args: []any{v1020CustomStaticID}},
		{label: "the custom dynamic row", table: "dynamic_policies", where: "policy_id = $1", args: []any{v1020CustomDynamicID}},
		{label: "the recorded override", table: "detection_action_overrides", where: "org_id = $1 AND category = $2", args: []any{m.org, DetectionCategorySQLI}},
	}
	for _, r := range rows {
		r.cols = v1020Columns(t, owner, r.table)
		r.before = v1020Row(t, owner, r.table, r.cols, r.where, r.args...)
		t.Logf("before switching, %s over v10.2.0's %d %s columns: %s", r.label, len(r.cols), r.table, r.before)
	}
	templateCols := v1020Columns(t, owner, "static_policies")
	templateBefore := v1020Row(t, owner, "static_policies", templateCols, "policy_id = $1", v1020TemplateCopyID)

	// ---- run 2: the v11 boot -------------------------------------------
	applied2, skipped2, err := RunMigrations(migrationDB, live, vars)
	if err != nil {
		t.Fatalf("run 2 (the v11 set): %v", err)
	}
	if want := added - (grafanaLive - grafanaOld); applied2 != want || skipped2 != len(live)-applied2 {
		t.Fatalf("run 2 applied %d and skipped %d; want %d applied (the migrations added since v10.2.0) and %d skipped",
			applied2, skipped2, want, len(live)-want)
	}
	t.Logf("run 2, the v11 boot: applied %d (every migration added since v10.2.0), skipped %d", applied2, skipped2)

	t.Run("the organization's rows survive byte for byte over v10.2.0's columns", func(t *testing.T) {
		for _, r := range rows {
			if after := v1020Row(t, owner, r.table, r.cols, r.where, r.args...); after != r.before {
				t.Errorf("%s changed across the upgrade:\nbefore %s\nafter  %s", r.label, r.before, after)
			}
		}
	})

	t.Run("core/185 rewrites an organization's copy of a template literal, and nothing else about it", func(t *testing.T) {
		after := v1020Row(t, owner, "static_policies", templateCols, "policy_id = $1", v1020TemplateCopyID)
		var b, a map[string]any
		if err := json.Unmarshal([]byte(templateBefore), &b); err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal([]byte(after), &a); err != nil {
			t.Fatal(err)
		}
		if b["pattern"] != `union\s+select` || a["pattern"] != `\bunion\s+select\b` {
			t.Errorf("pattern %v -> %v; want core/185's rewrite of the template literal to its whole-word form", b["pattern"], a["pattern"])
		}
		if reflect.DeepEqual(b["updated_at"], a["updated_at"]) {
			t.Errorf("updated_at did not move (%v); core/185 sets it", a["updated_at"])
		}
		for k := range b {
			if k != "pattern" && k != "updated_at" && !reflect.DeepEqual(b[k], a[k]) {
				t.Errorf("%s changed: %v -> %v; core/185 changes only the pattern and updated_at", k, b[k], a[k])
			}
		}
	})

	// The application role, as a v11 deployment connects: one pinned
	// connection for the SQL legs, org-scoped, and one pool as the boot's.
	v1020Exec(t, owner, "give the application role a login", `ALTER ROLE axonflow_app_role WITH LOGIN PASSWORD '`+v1020AppRolePassword+`'`)
	appDSN := v1020AsAppRole(t, dsn)
	appSQL := v1020Open(t, appDSN)
	appSQL.SetMaxOpenConns(1)
	v1020Exec(t, appSQL, "scope the application role's connection", `SELECT set_config('app.current_org_id', $1, false)`, m.org)
	appPool := v1020Open(t, appDSN)
	var who string
	if err := appSQL.QueryRow(`SELECT current_user`).Scan(&who); err != nil || who != "axonflow_app_role" {
		t.Fatalf("the application-role connection is %q (%v)", who, err)
	}

	writes := []struct {
		name string
		sql  string
		args []any
	}{
		{"INSERT INTO static_policies", `INSERT INTO static_policies (policy_id, name, category, pattern, severity, action, tenant_id, org_id)
			VALUES ('w3x3894_probe_static', 'probe', 'security-sqli', 'probe', 'low', 'warn', $1, $2)`, []any{m.tenant, m.org}},
		{"UPDATE static_policies", `UPDATE static_policies SET name = 'W3X 3894 changed' WHERE policy_id = $1`, []any{v1020CustomStaticID}},
		{"DELETE FROM static_policies", `DELETE FROM static_policies WHERE policy_id = 'w3x3894_probe_static'`, nil},
		{"INSERT INTO dynamic_policies", `INSERT INTO dynamic_policies (policy_id, name, policy_type, conditions, actions, tenant_id, org_id, category)
			VALUES ('w3x3894_probe_dynamic', 'probe', 'content', '[]'::jsonb, '[]'::jsonb, $1, $2, 'dynamic-security')`, []any{m.tenant, m.org}},
		{"UPDATE dynamic_policies", `UPDATE dynamic_policies SET name = 'W3X 3894 changed' WHERE policy_id = $1`, []any{v1020CustomDynamicID}},
		{"DELETE FROM dynamic_policies", `DELETE FROM dynamic_policies WHERE policy_id = 'w3x3894_probe_dynamic'`, nil},
	}

	t.Run("the freeze holds in SQL: the application role's writes on both legacy tables are 42501", func(t *testing.T) {
		for _, w := range writes {
			_, err := appSQL.Exec(w.sql, w.args...)
			var pqErr *pq.Error
			if !errors.As(err, &pqErr) || pqErr.Code != "42501" {
				t.Errorf("%s as axonflow_app_role: %v; want SQLSTATE 42501 (insufficient_privilege) from core/172", w.name, err)
			}
		}
		v1020WantFrozen(t, appSQL, true, "after the upgrade")
		for _, table := range []string{"static_policies", "dynamic_policies"} {
			var n int
			if err := appSQL.QueryRow(`SELECT count(*) FROM `+table+` WHERE policy_id IN ($1, $2)`, v1020CustomStaticID, v1020CustomDynamicID).Scan(&n); err != nil || n != 1 {
				t.Errorf("the application role reads %d custom row(s) from %s (%v); want 1, the freeze revokes writes only", n, table, err)
			}
		}
	})

	handler := NewStaticPolicyAPIHandler(appPool)
	serve := func(method, target, body string, id string, route func(*StaticPolicyAPIHandler) http.HandlerFunc) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, target, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		ctx := context.WithValue(req.Context(), ContextKeyTenantID, m.tenant)
		ctx = context.WithValue(ctx, ContextKeyOrgID, m.org)
		req = req.WithContext(ctx)
		if id != "" {
			req = mux.SetURLVars(req, map[string]string{"id": id})
		}
		rr := httptest.NewRecorder()
		route(handler)(rr, req)
		return rr
	}
	createBody := `{"name":"W3X 3894 written after the upgrade","pattern":"w3x3894-after-[0-9]{9}","category":"security-sqli","action":"block","tier":"tenant"}`

	t.Run("the freeze holds on the route: the legacy writes answer 409 LEGACY_POLICY_WRITE_FROZEN", func(t *testing.T) {
		for _, c := range []struct {
			name string
			rr   *httptest.ResponseRecorder
		}{
			{"create", serve(http.MethodPost, "/api/v1/static-policies", createBody, "", func(h *StaticPolicyAPIHandler) http.HandlerFunc { return h.HandleCreateStaticPolicy })},
			{"update", serve(http.MethodPut, "/api/v1/static-policies/"+v1020CustomStaticID, `{"name":"W3X 3894 renamed"}`, v1020CustomStaticID,
				func(h *StaticPolicyAPIHandler) http.HandlerFunc { return h.HandleUpdateStaticPolicy })},
			{"toggle", serve(http.MethodPatch, "/api/v1/static-policies/"+v1020CustomStaticID, `{"enabled":false}`, v1020CustomStaticID,
				func(h *StaticPolicyAPIHandler) http.HandlerFunc { return h.HandleTogglePolicy })},
			{"delete", serve(http.MethodDelete, "/api/v1/static-policies/"+v1020CustomStaticID, "", v1020CustomStaticID,
				func(h *StaticPolicyAPIHandler) http.HandlerFunc { return h.HandleDeleteStaticPolicy })},
		} {
			var out struct {
				Error struct {
					Code    string `json:"code"`
					Message string `json:"message"`
				} `json:"error"`
			}
			if err := json.Unmarshal(c.rr.Body.Bytes(), &out); c.rr.Code != http.StatusConflict || err != nil ||
				out.Error.Code != legacyfreeze.ErrCode || out.Error.Message != legacyfreeze.Message {
				t.Errorf("%s: HTTP %d code %q (decode err %v); want 409 %s with legacyfreeze.Message. body=%s",
					c.name, c.rr.Code, out.Error.Code, err, legacyfreeze.ErrCode, c.rr.Body.String())
			}
		}
		if after := v1020Row(t, owner, rows[0].table, rows[0].cols, rows[0].where, rows[0].args...); after != rows[0].before {
			t.Errorf("the refused writes changed the custom static row:\nbefore %s\nafter  %s", rows[0].before, after)
		}
	})

	t.Run("PRD v11 §1.11: the legacy reads still return the organization's rows", func(t *testing.T) {
		list := serve(http.MethodGet, "/api/v1/static-policies?tier=tenant&limit=100", "", "", func(h *StaticPolicyAPIHandler) http.HandlerFunc { return h.HandleListStaticPolicies })
		if list.Code != http.StatusOK || !strings.Contains(list.Body.String(), v1020CustomStaticID) {
			t.Errorf("list: HTTP %d, and the body names %s: %v. body=%s", list.Code, v1020CustomStaticID, strings.Contains(list.Body.String(), v1020CustomStaticID), list.Body.String())
		}
		get := serve(http.MethodGet, "/api/v1/static-policies/"+v1020CustomStaticID, "", v1020CustomStaticID, func(h *StaticPolicyAPIHandler) http.HandlerFunc { return h.HandleGetStaticPolicy })
		if get.Code != http.StatusOK || !strings.Contains(get.Body.String(), "W3X 3894 custom static") {
			t.Errorf("get: HTTP %d; want 200 naming the row. body=%s", get.Code, get.Body.String())
		}
	})

	// ---- the decide, with the engines the boot builds -------------------
	enfNoCircuitBreaker(t)
	rutInstallCache(t, m.org, false)
	prevUsage := usageDB
	usageDB = appPool
	t.Cleanup(func() { usageDB = prevUsage })
	prevEngine := sharedpolicy.GetGlobalEngine()
	sharedpolicy.SetGlobalEngine(sharedpolicy.NewUnifiedPolicyEngine(appPool, capabilityScopedEngineConfig(), nil))
	t.Cleanup(func() { sharedpolicy.SetGlobalEngine(prevEngine) })
	prevEnforcer := anchoredEnforcerInstance.Load()
	boot, err := sharedidentity.BootstrapAdmission(sharedidentity.AdmissionBootstrapConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if err := installAnchoredEnforcer(appPool, boot); err != nil {
		t.Fatalf("installing the anchored enforcer over the upgraded database as the boot does: %v", err)
	}
	t.Cleanup(func() { anchoredEnforcerInstance.Store(prevEnforcer) })
	prevOverrides := getDetectionOverrideCache()
	InitDetectionOverrides(appPool)
	t.Cleanup(func() {
		globalDetectionOverrideCacheMu.Lock()
		globalDetectionOverrideCache = prevOverrides
		globalDetectionOverrideCacheMu.Unlock()
	})

	decide := func(t *testing.T, query string) enfResponse {
		t.Helper()
		b, _ := json.Marshal(DecideRequest{Stage: DecisionStageLLM, Target: DecisionTarget{Type: DecisionStageLLM}, Query: query})
		req := httptest.NewRequest(http.MethodPost, decisionHandlerPath, bytes.NewReader(b))
		req.Header.Set("Content-Type", "application/json")
		ctx := context.WithValue(req.Context(), ContextKeyTenantID, m.tenant)
		ctx = context.WithValue(ctx, ContextKeyOrgID, m.org)
		ctx = context.WithValue(ctx, ContextKeyClientID, m.client)
		ctx = context.WithValue(ctx, ContextKeyAuthKind, m.authKind)
		rr := httptest.NewRecorder()
		handleDecide(rr, req.WithContext(ctx))
		out := enfResponse{code: rr.Code, raw: rr.Body.Bytes(), body: map[string]json.RawMessage{}}
		if err := json.Unmarshal(rr.Body.Bytes(), &out.body); err != nil {
			t.Fatalf("the decide response is not a JSON object: %v\n%s", err, rr.Body.String())
		}
		return out
	}
	matched := func(t *testing.T, query string) []string {
		t.Helper()
		outcome := evaluateInputPolicies(context.Background(), m.tenant, m.org, "0", "decision", "", query, nil,
			ResolveGatewayDetectionConfig(context.Background(), m.org))
		if outcome.StaticResult == nil {
			return nil
		}
		ids := make([]string, 0, len(outcome.StaticResult.MatchedPolicies))
		for _, p := range outcome.StaticResult.MatchedPolicies {
			ids = append(ids, p.PolicyID)
		}
		return ids
	}
	auditDetails := func(t *testing.T, decisionID string) string {
		t.Helper()
		var details string
		if err := owner.QueryRow(`SELECT COALESCE(policy_details::text, '') FROM audit_logs WHERE decision_id = $1`, decisionID).Scan(&details); err != nil {
			t.Fatalf("reading the audit row of decision %s: %v", decisionID, err)
		}
		return details
	}

	t.Run("PRD v11 §1.2: the organization's own legacy rows decide nothing", func(t *testing.T) {
		query := "please summarise " + v1020Marker + " for the quarterly review"
		// Not vacuous: the shared engine's tenant pass loads the custom static
		// row on this database and it matches, as a detector fact.
		if ids := matched(t, query); !slices.Contains(ids, v1020CustomStaticID) {
			t.Fatalf("the shared engine matched %v; the custom static row is not a detector fact for its own pattern, so 'it does not decide' would prove nothing", ids)
		}
		r := decide(t, query)
		t.Logf("decide on the custom pattern: HTTP %d verdict %q engine %q evaluated %v", r.code, r.str(t, "verdict"), r.str(t, "engine"), r.strings(t, "evaluated_policies"))
		if r.code != http.StatusOK || r.str(t, "verdict") == VerdictDeny || r.str(t, "engine") != decisionEngineAnchored {
			t.Errorf("HTTP %d verdict %q engine %q; want 200, not deny, from the anchored engine. body=%s", r.code, r.str(t, "verdict"), r.str(t, "engine"), r.raw)
		}
		// The dynamic id is a tripwire: no v11 plane evaluates dynamic rows
		// (§1.2), so today it cannot appear; a plane that starts evaluating them
		// fails here.
		for _, id := range []string{v1020CustomStaticID, v1020CustomDynamicID} {
			if bytes.Contains(r.raw, []byte(id)) {
				t.Errorf("the decide response names %s. body=%s", id, r.raw)
			}
			if d := auditDetails(t, r.str(t, "decision_id")); strings.Contains(d, id) {
				t.Errorf("the decision's audit row names %s: %s", id, d)
			}
		}
	})

	t.Run("a shipped control still refuses in the same state: sqli under the recorded override", func(t *testing.T) {
		ids := matched(t, v1020SQLiQuery)
		shipped := ""
		for _, id := range ids {
			if strings.HasPrefix(id, "sys_sqli_") {
				shipped = id
				break
			}
		}
		if shipped == "" {
			t.Fatalf("no shipped sys_sqli_* row matches %q on this database (matched %v), so the twin would prove nothing", v1020SQLiQuery, ids)
		}
		r := decide(t, v1020SQLiQuery)
		evaluated := r.strings(t, "evaluated_policies")
		t.Logf("decide on the SQL injection: HTTP %d verdict %q engine %q evaluated %v (detector %s)", r.code, r.str(t, "verdict"), r.str(t, "engine"), evaluated, shipped)
		if r.code != http.StatusOK || r.str(t, "verdict") != VerdictDeny || r.str(t, "engine") != decisionEngineAnchored ||
			len(evaluated) == 0 || !strings.HasPrefix(evaluated[0], activation.OverridePolicyIDPrefix) {
			t.Fatalf("HTTP %d verdict %q engine %q evaluated %v; want the anchored deny by the organization's override of a shipped control. body=%s",
				r.code, r.str(t, "verdict"), r.str(t, "engine"), evaluated, r.raw)
		}
		// CONTROL: without the override the same query is the stored warn.
		v1020Exec(t, owner, "delete the override", `DELETE FROM detection_action_overrides WHERE org_id = $1`, m.org)
		InvalidateOrgDetectionOverrides(m.org)
		c := decide(t, v1020SQLiQuery)
		if c.code != http.StatusOK || c.str(t, "verdict") == VerdictDeny {
			t.Errorf("CONTROL: with the override deleted got HTTP %d verdict %q; want the stored warn to allow, so the refusal above is the override's. body=%s",
				c.code, c.str(t, "verdict"), c.raw)
		}
		// And §1.2 again: the organization's own copy of the union-select template
		// row, action block, matches this query as a detector fact and decides
		// nothing.
		if ids := matched(t, v1020SQLiQuery); !slices.Contains(ids, v1020TemplateCopyID) {
			t.Errorf("the organization's template copy is not a detector fact for %q (matched %v)", v1020SQLiQuery, ids)
		}
		if bytes.Contains(c.raw, []byte(v1020TemplateCopyID)) {
			t.Errorf("the decide response names the organization's template copy. body=%s", c.raw)
		}
	})

	// ---- run 3: the restart ---------------------------------------------
	t.Run("the restart applies nothing", func(t *testing.T) {
		applied3, skipped3, err := RunMigrations(migrationDB, live, vars)
		if err != nil || applied3 != 0 || skipped3 != len(live) {
			t.Fatalf("run 3 applied %d, skipped %d (%v); want 0 and %d", applied3, skipped3, err, len(live))
		}
	})

	// ---- the rollback -----------------------------------------------------
	t.Run("172_down restores the application role's writes, in SQL and through the route", func(t *testing.T) {
		v1020ExecFile(t, owner, filepath.Join(repoRoot, "migrations", "core", "172_legacy_policy_tables_read_only_down.sql"))
		v1020WantFrozen(t, appSQL, false, "after 172_down")
		for _, w := range writes {
			if _, err := appSQL.Exec(w.sql, w.args...); err != nil {
				t.Errorf("%s as axonflow_app_role after 172_down: %v", w.name, err)
			}
		}
		if rr := serve(http.MethodPost, "/api/v1/static-policies", createBody, "", func(h *StaticPolicyAPIHandler) http.HandlerFunc { return h.HandleCreateStaticPolicy }); rr.Code != http.StatusCreated {
			t.Errorf("create through the route after 172_down: HTTP %d; want 201, the guard's probe now answers that the role may write. body=%s", rr.Code, rr.Body.String())
		}
	})

	t.Run("a restart after the rollback does not re-freeze; re-applying 172 does", func(t *testing.T) {
		applied4, _, err := RunMigrations(migrationDB, live, vars)
		if err != nil || applied4 != 0 {
			t.Fatalf("the restart after 172_down applied %d (%v); want 0: schema_migrations still records 172", applied4, err)
		}
		v1020WantFrozen(t, appSQL, false, "after a restart that followed 172_down")
		if _, err := appSQL.Exec(`UPDATE static_policies SET name = 'W3X 3894 after the restart' WHERE policy_id = $1`, v1020CustomStaticID); err != nil {
			t.Fatalf("after the restart the application role cannot write (%v); the runbook's statement that a restart does not re-freeze would be wrong", err)
		}
		v1020ExecFile(t, owner, filepath.Join(repoRoot, "migrations", "core", "172_legacy_policy_tables_read_only.sql"))
		v1020WantFrozen(t, appSQL, true, "after re-applying 172 by hand")
		_, err = appSQL.Exec(`UPDATE static_policies SET name = 'W3X 3894 refrozen' WHERE policy_id = $1`, v1020CustomStaticID)
		var pqErr *pq.Error
		if !errors.As(err, &pqErr) || pqErr.Code != "42501" {
			t.Fatalf("after re-applying 172 by hand the application role's UPDATE: %v; want 42501", err)
		}
	})

	// The boot exits with migrationFailureLines' text; this drives RunMigrations
	// itself into two of its failures, so the file and category it names are the
	// runner's, not the formatter's.
	t.Run("each failure stage exits with its own message, through RunMigrations", func(t *testing.T) {
		dir := t.TempDir()
		write := func(name, version, body string) MigrationFile {
			t.Helper()
			p := filepath.Join(dir, name)
			if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
				t.Fatal(err)
			}
			return MigrationFile{Path: p, Category: "core", Version: version, Name: strings.TrimSuffix(strings.TrimPrefix(name, version+"_"), ".sql")}
		}
		_, _, err := RunMigrations(migrationDB, []MigrationFile{write("9901_w3x3894_fails.sql", "9901", "SELECT * FROM w3x3894_no_such_table;\n")}, vars)
		if logLine, fatalLine := migrationFailureLines(err); !strings.HasPrefix(logLine, "❌ Migration 9901_w3x3894_fails.sql [core] FAILED: ") ||
			fatalLine != "Database migrations failed. Exiting to prevent incomplete setup." {
			t.Errorf("a failing migration: log %q, fatal %q (err %v)", logLine, fatalLine, err)
		}
		t.Setenv("GRAFANA_PASSWORD", "short")
		_, _, err = RunMigrations(migrationDB, []MigrationFile{write("9902_w3x3894_grafana.sql", "9902", "SELECT '{{GRAFANA_PASSWORD}}';\n")}, vars)
		if logLine, fatalLine := migrationFailureLines(err); logLine != "" ||
			!strings.HasPrefix(fatalLine, "Migration 9902_w3x3894_grafana.sql failed: GRAFANA_PASSWORD too short") {
			t.Errorf("a refused Grafana substitution: log %q, fatal %q (err %v)", logLine, fatalLine, err)
		}
	})
}

// v1020WantFrozen is the runbook's 42501 check (RUNBOOK_DEPLOYMENT_ROLLBACK.md,
// "Which state the tables are in"), run verbatim as the application role: a
// write that changes nothing is 42501 on a frozen table and succeeds on one
// whose writes are restored.
func v1020WantFrozen(t *testing.T, app *sql.DB, frozen bool, when string) {
	t.Helper()
	for _, table := range []string{"static_policies", "dynamic_policies"} {
		_, err := app.Exec(`UPDATE ` + table + ` SET name = name WHERE false`)
		var pqErr *pq.Error
		switch {
		case frozen && (!errors.As(err, &pqErr) || pqErr.Code != "42501"):
			t.Errorf("%s, the runbook's check on %s: %v; want 42501, the table frozen", when, table, err)
		case !frozen && err != nil:
			t.Errorf("%s, the runbook's check on %s: %v; want UPDATE 0, the writes restored", when, table, err)
		}
	}
}

func v1020Open(t *testing.T, dsn string) *sql.DB {
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

func v1020AsAppRole(t *testing.T, dsn string) string {
	t.Helper()
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	u.User = url.UserPassword("axonflow_app_role", v1020AppRolePassword)
	return u.String()
}

func v1020Exec(t *testing.T, db *sql.DB, what, stmt string, args ...any) {
	t.Helper()
	if _, err := db.Exec(stmt, args...); err != nil {
		t.Fatalf("%s: %v", what, err)
	}
}

func v1020ExecFile(t *testing.T, db *sql.DB, path string) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	v1020Exec(t, db, "applying "+filepath.Base(path), string(b))
}

// v1020Columns lists a table's columns in order, as the schema holds them now.
func v1020Columns(t *testing.T, db *sql.DB, table string) []string {
	t.Helper()
	rows, err := db.Query(`SELECT column_name FROM information_schema.columns
		WHERE table_schema = 'public' AND table_name = $1 ORDER BY ordinal_position`, table)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var cols []string
	for rows.Next() {
		var c string
		if err := rows.Scan(&c); err != nil {
			t.Fatal(err)
		}
		cols = append(cols, c)
	}
	if err := rows.Err(); err != nil || len(cols) == 0 {
		t.Fatalf("%s has no columns (%v)", table, err)
	}
	return cols
}

// v1020Row renders one row over cols as JSON text, the byte-for-byte form the
// survive assertion compares.
func v1020Row(t *testing.T, db *sql.DB, table string, cols []string, where string, args ...any) string {
	t.Helper()
	quoted := make([]string, len(cols))
	for i, c := range cols {
		quoted[i] = pq.QuoteIdentifier(c)
	}
	var out string
	q := fmt.Sprintf(`SELECT row_to_json(r)::text FROM (SELECT %s FROM %s WHERE %s) r`, strings.Join(quoted, ", "), pq.QuoteIdentifier(table), where)
	if err := db.QueryRow(q, args...).Scan(&out); err != nil {
		t.Fatalf("reading %s where %s: %v", table, where, err)
	}
	return out
}

// v1020GrafanaSkips counts the files the runner skips because Grafana is not
// deployed, through the runner's own substitution.
func v1020GrafanaSkips(t *testing.T, files []MigrationFile) int {
	t.Helper()
	n := 0
	for _, f := range files {
		b, err := os.ReadFile(f.Path)
		if err != nil {
			t.Fatal(err)
		}
		s, err := substituteGrafanaPassword(string(b))
		if err != nil {
			t.Fatal(err)
		}
		if s == "" {
			n++
		}
	}
	return n
}
