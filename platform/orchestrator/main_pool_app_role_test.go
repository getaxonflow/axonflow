// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strconv"
	"strings"
	"testing"

	"axonflow/platform/agent"
	"axonflow/platform/agent/approletest"
	"axonflow/platform/connectors/registry"
)

// TestOrchestratorMainPoolConnectsAsAppRole_RealPostgres pins the orchestrator
// usageDB boot path. The Session 20 brief identified this site (run.go:941)
// as one of three release-blocker call sites that fell through the v9.0.0
// AXONFLOW_DB_USE_APP_ROLE default-true flip because no service main pool
// actually invoked agent.OpenAppRoleConnection.
//
// Wire is identical to the agent's authDB: a fresh pool MUST connect as
// axonflow_app_role under USE_APP_ROLE=true + APP_ROLE_URL set, and the
// helper's role assertion MUST reject the silent fallback to master.
//
// Mutation-test: reverting platform/orchestrator/run.go:941 to raw sql.Open
// is caught by TestOrchestratorRunGoCallsOpenAppRoleConnection below.
func TestOrchestratorMainPoolConnectsAsAppRole_RealPostgres(t *testing.T) {
	approletest.SkipUnlessEnabled(t)
	env := approletest.Setup(t, "../../migrations/core")

	t.Run("UsageDBWireSetsCurrentUserToAppRole", func(t *testing.T) {
		t.Setenv(agent.EnvUseAppRole, "true")
		t.Setenv(agent.EnvAppRoleURL, env.AppRoleDSN)
		db, err := agent.OpenAppRoleConnection(context.Background(), env.MasterDSN, 3)
		if err != nil {
			t.Fatalf("agent.OpenAppRoleConnection: %v", err)
		}
		defer func() { _ = db.Close() }()
		approletest.AssertCurrentUser(t, db, "axonflow_app_role")
	})

	t.Run("UsageDBRejectsMasterDSNUnderAppRoleGate", func(t *testing.T) {
		t.Setenv(agent.EnvUseAppRole, "true")
		_ = os.Unsetenv(agent.EnvAppRoleURL)
		db, err := agent.OpenAppRoleConnection(context.Background(), env.MasterDSN, 1)
		if err == nil {
			_ = db.Close()
			t.Fatalf("agent.OpenAppRoleConnection unexpectedly succeeded on master fallback under gate=on")
		}
	})

	t.Run("UsageDBGateOffFallsBackToMaster", func(t *testing.T) {
		t.Setenv(agent.EnvUseAppRole, "false")
		db, err := agent.OpenAppRoleConnection(context.Background(), env.MasterDSN, 3)
		if err != nil {
			t.Fatalf("agent.OpenAppRoleConnection with gate off: %v", err)
		}
		defer func() { _ = db.Close() }()
		approletest.AssertCurrentUser(t, db, "postgres")
	})

	// R3-round-1 HIGH-1 fold: connector_registry runtime pool used to open
	// via raw sql.Open while connectors + connector_configs are FORCE-RLS
	// per migration 107. Verifies the schema-init-under-master / runtime-
	// under-app-role split actually lands the runtime pool on
	// axonflow_app_role when the WithAppRoleOpener option is passed.
	t.Run("ConnectorRegistryRuntimePoolUsesAppRole", func(t *testing.T) {
		t.Setenv(agent.EnvUseAppRole, "true")
		t.Setenv(agent.EnvAppRoleURL, env.AppRoleDSN)
		storage, err := registry.NewPostgreSQLStorageWithOpener(env.MasterDSN, agent.OpenAppRoleConnection)
		if err != nil {
			t.Fatalf("NewPostgreSQLStorageWithOpener: %v", err)
		}
		defer func() { _ = storage.Close() }()
		approletest.AssertCurrentUser(t, storage.UnsafeRuntimeDBForTests(), "axonflow_app_role")
	})

	// Mutation guard: omitting the opener (legacy NewPostgreSQLStorage path)
	// must keep current_user on master — proves the opener IS the
	// differentiator, not some other env wire.
	t.Run("ConnectorRegistryLegacyConstructorStaysOnMaster", func(t *testing.T) {
		storage, err := registry.NewPostgreSQLStorage(env.MasterDSN)
		if err != nil {
			t.Fatalf("NewPostgreSQLStorage: %v", err)
		}
		defer func() { _ = storage.Close() }()
		approletest.AssertCurrentUser(t, storage.UnsafeRuntimeDBForTests(), "postgres")
	})
}

// TestOrchestratorRunGoCallsOpenAppRoleConnection is the source-level
// regression guard for the orchestrator's usageDB site + the auxiliary pools
// that the §3 audit folded into the same fix (audit_logger, db_dynamic_policies
// main+metrics). #3319: the dynamic_policy_engine.go case was removed here —
// that file (the retired in-memory DynamicPolicyEngine's fallback dial) no
// longer exists; there is one engine now, and its dial is covered by the
// db_dynamic_policies.go case below.
//
// Mutation-test: reverting any of the audited call sites to raw sql.Open
// fails this test with an actionable file:line message.
func TestOrchestratorRunGoCallsOpenAppRoleConnection(t *testing.T) {
	cases := []struct {
		name     string
		path     string
		mustHave string
		mustNot  string
	}{
		{
			name:     "run.go_usageDB",
			path:     "run.go",
			mustHave: `usageDB, err = agent.OpenAppRoleConnection(`,
			mustNot:  `usageDB, err = sql.Open("postgres", dbURL)`,
		},
		{
			name:     "audit_logger.go",
			path:     "audit_logger.go",
			mustHave: `agent.OpenAppRoleConnection(bootCtx, databaseURL, 3)`,
			mustNot:  `db, err := sql.Open("postgres", databaseURL)`,
		},
		{
			// #3319: the dial moved into connectDB (called both from the
			// constructor and, lazily, from refreshPolicies when e.db is
			// still nil), so the DSN and retry count are now the engine's
			// own dbURL field and a maxRetries parameter instead of a bare
			// local `dbURL`/literal `3` — still routed through
			// agent.OpenAppRoleConnection, never a raw sql.Open.
			name:     "db_dynamic_policies.go",
			path:     "db_dynamic_policies.go",
			mustHave: `agent.OpenAppRoleConnection(bootCtx, e.dbURL, maxRetries)`,
			mustNot:  `db, err := sql.Open("postgres", dbURL)`,
		},
		{
			name:     "connector_marketplace_handlers.go",
			path:     "connector_marketplace_handlers.go",
			mustHave: `registry.WithAppRoleOpener(agent.OpenAppRoleConnection)`,
			mustNot:  `registry.NewRegistryWithStorage(dbURL, registry.WithEncryptor(credentialEncryptor))`,
		},
		{
			// Follow-up to the Session 20 wire (#2381 follow-up train):
			// GetActiveNodesByOrg is a cross-org sweep against FORCE-RLS
			// agent_heartbeats. NodeMonitor MUST open through
			// agent.OpenPlatformAdminConnection (BYPASSRLS) with a warning
			// fallback to usageDB; reverting to the bare
			// `NewNodeMonitor(usageDB, alerter)` form silently returns 0
			// rows per org under axonflow_app_role + FORCE RLS and license
			// violations stop firing.
			name:     "run.go_nodeMonitor_admin",
			path:     "run.go",
			mustHave: `agent.OpenPlatformAdminConnection(ctx, 3)`,
			mustNot:  `nodeMonitor = node_enforcement.NewNodeMonitor(usageDB, alerter)`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src, err := os.ReadFile(tc.path)
			if err != nil {
				t.Fatalf("read %s: %v", tc.path, err)
			}
			s := string(src)
			if !containsSubstrSession20(s, tc.mustHave) {
				t.Errorf("platform/orchestrator/%s: missing required call site `%s` — Session 20 regression",
					tc.path, tc.mustHave)
			}
			if containsSubstrSession20(s, tc.mustNot) {
				t.Errorf("platform/orchestrator/%s: forbidden raw sql.Open `%s` — Session 20 release-blocker regressed",
					tc.path, tc.mustNot)
			}
		})
	}
}

// TestConnectorRegistryEnvNameDriftGuard pins the env-name constants in
// platform/connectors/registry to match agent.EnvUseAppRole +
// agent.EnvAppRoleURL byte-for-byte. The registry can't import the agent
// package (circular: agent already imports registry via the MCP connector
// surface), so its boot-log emission relies on a duplicated const + helper
// pair. A future rename of either side would silently desync the operator-
// facing log labels. This test fails the build if the values drift.
//
// Mutation-test: change envAppRoleURLName in postgres_storage.go to a
// different literal → this test fails with an actionable mismatch error.
func TestConnectorRegistryEnvNameDriftGuard(t *testing.T) {
	src, err := os.ReadFile("../connectors/registry/postgres_storage.go")
	if err != nil {
		t.Fatalf("read postgres_storage.go: %v", err)
	}
	s := string(src)

	for _, c := range []struct{ wantConst, wantValue string }{
		{`envUseAppRoleName = "` + agent.EnvUseAppRole + `"`, agent.EnvUseAppRole},
		{`envAppRoleURLName = "` + agent.EnvAppRoleURL + `"`, agent.EnvAppRoleURL},
	} {
		if !containsSubstrSession20(s, c.wantConst) {
			t.Errorf("registry/postgres_storage.go: expected const literal `%s` matching agent package — drift will silently break operator log labels", c.wantConst)
		}
	}
}

// TestBootLogCanonicalShape pins the boot-log shape across all 9 pool sites
// that emit a `connected as current_user=` line (#3319: was 10 sites before
// dynamic_policy_engine.go — the retired in-memory DynamicPolicyEngine's
// fallback dial — was deleted along with that engine). The Session 20
// follow-up normalized 3 divergent shapes into one canonical:
//
//	connected as current_user=<role> (UseAppRoleEnabled=<bool>, <ENV_NAME>=<bool>)
//
// The check uses go/parser instead of a substring grep: it parses each file
// into an AST and inspects EVERY `log.Printf` / `logger.Printf` call's first
// argument (the format string). A future refactor that drops the env-name
// segment from one site's actual log.Printf — even if the canonical text
// happens to appear in a comment or const block — fails this test.
//
// Why AST not substring: the original Session 22 follow-up test used
// `strings.Contains` over the whole file. That had a (non-blocking)
// observation gap: a hostile or sloppy refactor could leave the canonical
// text in a comment while changing the actual log emission to the legacy
// shape, and the substring check would pass falsely. The AST walker closes
// that gap by binding the assertion to real log call sites, not arbitrary
// file text.
//
// Mutation-test: change ANY of the 9 log.Printf format strings to drop the
// "(UseAppRoleEnabled=%v, %s=%v)" suffix — this test fails with the file +
// the line number of the offending call.
func TestBootLogCanonicalShape(t *testing.T) {
	// On community-sync checkouts, ee/platform/customer-portal/main.go is
	// excluded from the sync filter. The boot-log canonical-shape check
	// validates the full 9-pool set including the customer-portal main pool,
	// so it can only run on a checkout where every file is present. Skip
	// cleanly when the customer-portal file is absent — that's the signal
	// we're on a community checkout.
	if _, err := os.Stat("../../ee/platform/customer-portal/main.go"); os.IsNotExist(err) {
		t.Skip("skipping canonical-shape check: customer-portal main.go is not present in this checkout (excluded from community sync); the test runs on a full-tree checkout where all 9 pools exist")
	}
	// File paths relative to platform/orchestrator/ — orchestrator file
	// paths are bare; cross-package paths use ../ prefix.
	files := []string{
		"../agent/run.go",
		"run.go",
		"audit_logger.go",
		"db_dynamic_policies.go",
		"../connectors/registry/postgres_storage.go",
		"../../ee/platform/customer-portal/main.go",
	}
	const canonicalSuffix = "(UseAppRoleEnabled=%v, %s=%v)"
	const bootLogMarker = "connected as current_user=%s"

	totalEmitters := 0
	for _, path := range files {
		t.Run(path, func(t *testing.T) {
			fset := token.NewFileSet()
			file, err := parser.ParseFile(fset, path, nil, 0)
			if err != nil {
				t.Fatalf("parse %s: %v", path, err)
			}

			// Visit every CallExpr in the AST; pick out Printf-family calls
			// whose first argument is a string literal containing the
			// boot-log marker. Each such call MUST also contain the
			// canonical suffix.
			ast.Inspect(file, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok || len(call.Args) == 0 {
					return true
				}
				if !isPrintfCall(call.Fun) {
					return true
				}
				lit, ok := call.Args[0].(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					return true
				}
				format, err := strconv.Unquote(lit.Value)
				if err != nil {
					return true
				}
				if !strings.Contains(format, bootLogMarker) {
					return true
				}
				totalEmitters++
				if !strings.Contains(format, canonicalSuffix) {
					pos := fset.Position(lit.Pos())
					t.Errorf("%s:%d: Printf format `%s` is missing canonical suffix `%s` — follow-up FU1 regressed",
						path, pos.Line, format, canonicalSuffix)
				}
				return true
			})
		})
	}

	// Pin the global emitter count too: if a future refactor deletes a
	// boot-log line entirely (rather than mangling its shape), the per-file
	// subtest passes (zero emitters in that file) but the global count
	// drops below 9 and this assertion catches it.
	//
	// #3319: was 10 (dynamic_policy_engine.go's fallback-engine dial
	// contributed a 10th emitter); that file and the engine it dialed for
	// no longer exist, so db_dynamic_policies.go's 3 emitters (main pool,
	// metrics pool, and the BYPASSRLS gate-cache refresh pool, #3039) are
	// now the only dynamic-policy-engine sites.
	const wantEmitters = 9
	if totalEmitters != wantEmitters {
		t.Errorf("found %d boot-log emitters across %d files; want %d — a site was added or removed without updating this audit",
			totalEmitters, len(files), wantEmitters)
	}
}

// isPrintfCall returns true when fun is `log.Printf`, `logger.Printf`,
// `s.logger.Printf`, or any chained receiver ending in `.Printf`. We don't
// pin the exact receiver because the orchestrator package mixes the
// std-lib `log.Printf` with `*log.Logger.Printf` instance methods (e.g.
// `storage.logger.Printf` inside the connector-registry boot log).
func isPrintfCall(fun ast.Expr) bool {
	sel, ok := fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	return sel.Sel.Name == "Printf"
}

func containsSubstrSession20(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
