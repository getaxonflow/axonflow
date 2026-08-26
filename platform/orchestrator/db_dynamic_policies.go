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
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	_ "github.com/lib/pq"

	"axonflow/platform/agent"
	sharedpolicy "axonflow/platform/shared/policy"
)

// dbConditionEvaluator is the shared substrate (#3296,
// platform/shared/policy/condition_evaluator.go). This engine's legacy
// switch was already the ten-operator union, so convergence 5 (#3296) is a
// no-op here; convergences 2 and 3 are not — contains_any now stringifies a
// non-string list item instead of silently skipping it, and greater_than/
// less_than no longer silently coerce an unparseable operand to 0.0 (a real
// false-positive bug this engine had). See the shared type's doc comment for
// the full convergence record. Slice 2 removed the last knob, the per-caller
// unknown-operator log hook — this engine's unevaluable conditions (unknown
// operator, non-numeric operand, non-string regex pattern, and a conditions
// JSON that fails to unmarshal in cachedPolicyToDynamicPolicy below) now
// report through dbUnevaluableRecorder (condition_unevaluable_metrics.go),
// passed into Match per call instead of configured on the struct. A
// zero-condition policy vacuously matches — see EvaluateDynamicPolicies below
// and the shared type's "Withdrawn" doc section for why a brief attempt at
// making that a non-match was reverted. A package-level value for the same
// reason as memoryConditionEvaluator used to carry in the now-deleted
// dynamic_policy_engine.go (#3319): no per-engine state, so every
// construction path (including the direct `&DatabaseDynamicPolicyEngine{...}`
// struct literals used throughout this package's tests) gets the same
// configured evaluator, constructed once rather than per request.
var dbConditionEvaluator = sharedpolicy.ConditionEvaluator{}

// dbRiskCalculator computes the platform-sourced "risk_score" condition
// field (#3321). Package-level for the same reason as dbConditionEvaluator
// above — no per-engine state, so every construction path (including the
// direct `&DatabaseDynamicPolicyEngine{...}` struct literals this package's
// tests use) sees the same calculator, built once rather than per request.
var dbRiskCalculator = NewRiskCalculator()

type DatabaseDynamicPolicyEngine struct {
	db        *sql.DB
	metricsDB *sql.DB
	// refreshDB serves the cache-refresh SELECT and the boot-time policy
	// COUNT — both deliberate ALL-tenants reads feeding the multi-tenant
	// gate cache. dynamic_policies is RLS-enabled (mig 018, org_id =
	// get_current_org_id()), so on an app-role deployment these reads MUST
	// run on the BYPASSRLS axonflow_platform_admin pool: on the app-role
	// pool with no org GUC they match 0 rows and the gate cache silently
	// empties — tenant dynamic policies stop being enforced (#3039). Falls
	// back to db (with a loud log) on deployments without the admin role,
	// where db is the table owner and sees everything anyway.
	refreshDB *sql.DB
	// refreshPoolIsRLSScoped (#3322 item 3, review of #3319) is true iff
	// refreshDB is NOT a dedicated BYPASSRLS pool (the platform-admin open
	// above failed or was never attempted) AND the app-role gate is active
	// — i.e. the all-tenants read refreshPolicies performs on refreshDB
	// actually runs through axonflow_app_role's RLS restriction, exactly
	// the #3039 shape (get_current_org_id() -> NULL with no org GUC set ->
	// org_id = NULL matches nothing -> zero rows, no error). Computed once
	// in connectDB from the SAME facts its warning log line already checks,
	// not read fresh from agent.UseAppRoleEnabled() on every refresh — the
	// pool selection at connect time is what actually determines whether a
	// later empty result is trustworthy, and freezing it avoids a refresh
	// tick disagreeing with the pool it is actually reading from if the env
	// var changed after boot (it does not, in practice, but the field
	// should describe the connection actually in hand, not global state).
	//
	// Zero value is false ("trust a zero-row result") so every existing
	// test that constructs this engine via a direct struct literal (16+
	// call sites across this package) keeps its current behavior unless it
	// explicitly opts in — those fixtures are exercising the SQL/caching
	// plumbing, not the #3039 RLS-blind-pool shape, and defaulting to
	// "guard active" would fail closed on all of them for a condition (the
	// production app-role gate) they never asked to simulate.
	refreshPoolIsRLSScoped bool
	// dbURL is the DSN this engine was constructed with — "" when
	// DATABASE_URL was unset at boot (a legitimate community-mode
	// deployment). Retained (rather than discarded after the constructor's
	// initial attempt) so a later refresh tick can lazily open the pools
	// itself when db is still nil — see connectDB and refreshPolicies.
	// That lazy retry, running on the SAME 30s cadence as every other
	// refresh, is what makes a process that booted with no reachable
	// database able to reach the database-loaded state without a restart
	// (#3319).
	dbURL        string
	policies     map[string]interface{}
	mu           sync.RWMutex
	lastRefresh  time.Time
	cacheTimeout time.Duration
	refreshing   bool
	refreshMu    sync.Mutex
	stopCh       chan struct{}
	// connectMu serializes connectDB attempts. Without it, two concurrent
	// refresh triggers (backgroundRefresh's tick and a manually invoked
	// RefreshPolicies()) racing while e.db is still nil could each open a
	// full set of pools; the second writer under e.mu would silently orphan
	// the first's pools (a connection leak, never closed). Only matters
	// before the first successful connect — once e.db is non-nil,
	// refreshPolicies never calls connectDB again.
	connectMu sync.Mutex

	// policySetSource (#3319) is "defaults" until the first successful
	// database load, then "database" for the rest of the process
	// lifetime — see the policySetSource* constants and PolicySetSource.
	// Guarded by mu alongside policies/lastRefresh because all three
	// change together, atomically, on the same success path
	// (refreshPolicies) and must never be observed out of sync with each
	// other.
	policySetSource string
}

// policySetSource values (#3319). "Fallback" describes the policy SET, not
// a component — there is exactly one engine, and this field is the only
// thing that varies between "serving what the customer configured" and
// "serving the built-in safety net because no load has ever succeeded."
const (
	// policySetSourceDefaults is the source from construction until the
	// first successful load — including for the entire lifetime of a
	// process that never reaches a database (DATABASE_URL unset, or every
	// connection/query attempt so far has failed). Not an error state: it
	// is what NewDatabaseDynamicPolicyEngine always starts as.
	policySetSourceDefaults = "defaults"
	// policySetSourceDatabase is the source from the first successful
	// load onward. Once set it is NEVER reverted by a later failed
	// refresh — refreshPolicies returns on every error path before it
	// would touch e.policies/e.policySetSource — so a transient outage
	// after promotion is a no-op, not a downgrade. See
	// TestRefreshPolicies_FailedRefreshNeverDowngradesSource.
	policySetSourceDatabase = "database"
)

// NewDatabaseDynamicPolicyEngine always constructs and returns a usable
// engine (#3319) — it does not require a reachable database, or even a
// configured one, to exist. It begins serving the built-in default fallback
// policy set (loadDefaultDynamicPolicies, policy_defaults.go) with
// PolicySetSource() == "defaults", and if DATABASE_URL is set, makes one
// best-effort attempt to connect and load before returning. Whether that
// attempt succeeds or fails, construction itself does not fail because of
// it: a boot-time database blip (or booting entirely without a database, a
// legitimate community-mode deployment) is not a permanent condition —
// backgroundRefresh's ordinary 30s tick keeps retrying, and the engine
// reaches PolicySetSource() == "database" on its own the moment a load
// finally succeeds, without reconstruction.
//
// The error return is retained for a genuinely fatal misconfiguration that
// would need to stop the process outright; there is no such case as of
// #3319, so this always returns a nil error today. Callers must not assume
// that stays true forever, but MUST NOT treat "err == nil" as "database
// reachable" — check PolicySetSource() for that.
func NewDatabaseDynamicPolicyEngine() (*DatabaseDynamicPolicyEngine, error) {
	dbURL := os.Getenv("DATABASE_URL")

	engine := &DatabaseDynamicPolicyEngine{
		dbURL:           dbURL,
		policies:        loadDefaultPoliciesCache(),
		policySetSource: policySetSourceDefaults,
		cacheTimeout:    30 * time.Second,
		stopCh:          make(chan struct{}),
	}
	setPolicySetSourceMetric(policySetSourceDefaults)

	if dbURL == "" {
		log.Println("[dynamic-policy-engine] DATABASE_URL not set — serving built-in default policies (no database configured)")
	} else if err := engine.connectDB(3); err != nil {
		log.Printf("[dynamic-policy-engine] database unavailable at boot (%v) — serving built-in default policies until the next successful load (#3319)", err)
	} else if err := engine.refreshPolicies(); err != nil {
		log.Printf("[dynamic-policy-engine] initial policy load failed: %v — serving built-in default policies", err)
	}

	// Start background refresh. Runs unconditionally regardless of the
	// outcome above: if the pools never opened, refreshPolicies retries
	// connectDB itself on the next tick (see refreshPolicies) — this
	// goroutine IS the recovery path, not a poller gated on a boot-time
	// availability flag that only ever gets set once (the defect #3319
	// retires).
	go engine.backgroundRefresh()

	// Start metrics reporter
	go engine.reportMetrics()

	return engine, nil
}

// connectDB opens this engine's three connection pools against e.dbURL and,
// on success, wires them onto the engine and seeds default data. It is used
// both by the constructor's initial attempt (maxRetries=3, matching the
// pre-#3319 constructor's blocking budget) and by refreshPolicies' lazy
// reconnect on a later tick when e.db is still nil (maxRetries=1, so a
// still-unreachable database costs this tick one ~5s ping instead of a
// multi-attempt stall — the NEXT tick, 30s later, is the next retry, and
// that ticking IS the retry loop; see the dbURL field comment).
func (e *DatabaseDynamicPolicyEngine) connectDB(maxRetries int) error {
	e.connectMu.Lock()
	defer e.connectMu.Unlock()

	// Another caller may have already connected while this one waited for
	// connectMu (see the field comment) — nothing to do.
	e.mu.RLock()
	alreadyConnected := e.db != nil
	e.mu.RUnlock()
	if alreadyConnected {
		return nil
	}

	// Main connection pool for reads.
	// v9 Brief 11.5 / Session 20: route through agent.OpenAppRoleConnection so
	// AXONFLOW_DB_USE_APP_ROLE=true (default in v9.0.0) actually flips the
	// connection role to axonflow_app_role. Without this wrap, dynamic-policy
	// queries against dynamic_policies (and future RLS-FORCEd tables) silently
	// run as the table-owner role and bypass RLS.
	bootCtx := context.Background()
	db, err := agent.OpenAppRoleConnection(bootCtx, e.dbURL, maxRetries)
	if err != nil {
		return fmt.Errorf("failed to open database: %w", err)
	}

	// Configure connection pool
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)

	var connectedRole string
	if err := db.QueryRowContext(bootCtx, "SELECT current_user").Scan(&connectedRole); err != nil {
		log.Printf("[dynamic-policy-engine] WARNING: failed to query current_user: %v (continuing)", err)
	}
	log.Printf("[dynamic-policy-engine] ✅ db pool connected as current_user=%s (UseAppRoleEnabled=%v, %s=%v)",
		connectedRole, agent.UseAppRoleEnabled(), agent.EnvAppRoleURL, os.Getenv(agent.EnvAppRoleURL) != "")

	// Separate connection for metrics to avoid blocking.
	// Same OpenAppRoleConnection wrap so the metrics pool also honors the gate.
	metricsDB, err := agent.OpenAppRoleConnection(bootCtx, e.dbURL, maxRetries)
	if err != nil {
		_ = db.Close()
		return fmt.Errorf("failed to open metrics database: %w", err)
	}
	metricsDB.SetMaxOpenConns(5)
	metricsDB.SetMaxIdleConns(2)
	var metricsRole string
	if err := metricsDB.QueryRowContext(bootCtx, "SELECT current_user").Scan(&metricsRole); err != nil {
		log.Printf("[dynamic-policy-engine] WARNING: failed to query current_user on metricsDB: %v (continuing)", err)
	}
	log.Printf("[dynamic-policy-engine] ✅ metricsDB pool connected as current_user=%s (UseAppRoleEnabled=%v, %s=%v)",
		metricsRole, agent.UseAppRoleEnabled(), agent.EnvAppRoleURL, os.Getenv(agent.EnvAppRoleURL) != "")

	// Cross-org read pool for the gate cache (see refreshDB field comment).
	// Same OpenAppRoleConnection-vs-admin split as NodeMonitor (run.go) and
	// the idempotency sweep: prefer axonflow_platform_admin (BYPASSRLS).
	//
	// This is the POLICY ENFORCEMENT path: on an app-role deployment a
	// silent fallback to the main pool means the gate cache loads empty and
	// tenant dynamic policies stop being enforced. The refuse-to-boot guard
	// (RequirePlatformAdminOrFatal) fires at the run.go boot path, not
	// here — tests construct the engine directly under app-role fixtures
	// without an admin DSN and must not os.Exit the suite.
	refreshDB := db
	// #3159 R3: NO RequirePlatformAdminPoolOrFatal here, deliberately — the
	// comment directly above states the invariant and it still holds. This is a
	// CONSTRUCTOR with 16 test call sites, and a log.Fatalf reached from one of
	// them kills the whole orchestrator test binary with no test-level failure
	// message. The refuse-to-boot guard belongs at the run.go boot path, where
	// RequirePlatformAdminOrFatal already fires for the unset-DSN case.
	//
	// The residual gap is real and stated rather than papered over: a
	// CONFIGURED-but-unusable admin DSN still degrades the gate cache to the
	// main pool here, where under app-role it reads zero rows and tenant
	// dynamic policies stop being enforced. Closing it needs the pool to be
	// opened at the boot path and injected, not a fatal in a constructor.
	adminDB, adminErr := agent.OpenPlatformAdminConnection(bootCtx, maxRetries)
	if adminErr != nil || adminDB == nil {
		// Reachable only when the gate is off (guard above no-ops) or the
		// configured admin DSN is broken. nil-with-nil-err = DSN unset.
		log.Printf("[dynamic-policy-engine] ⚠️  platform-admin pool unavailable (err=%v, dsn_configured=%v) — gate-cache refresh falls back to the main pool; "+
			"under AXONFLOW_DB_USE_APP_ROLE=true this reads 0 rows through RLS and tenant dynamic policies will NOT be enforced (#3039)",
			adminErr, os.Getenv(agent.EnvPlatformAdminURL) != "")
	} else {
		adminDB.SetMaxOpenConns(3)
		adminDB.SetMaxIdleConns(1)
		refreshDB = adminDB
		var refreshRole string
		if err := adminDB.QueryRowContext(bootCtx, "SELECT current_user").Scan(&refreshRole); err == nil {
			log.Printf("[dynamic-policy-engine] ✅ gate-cache refresh pool (BYPASSRLS cross-org reads) connected as current_user=%s (UseAppRoleEnabled=%v, %s=%v)",
				refreshRole, agent.UseAppRoleEnabled(), agent.EnvPlatformAdminURL, os.Getenv(agent.EnvPlatformAdminURL) != "")
		}
	}

	// See refreshPoolIsRLSScoped's field doc: true only in the exact #3039
	// shape — no dedicated BYPASSRLS pool AND the app-role gate active, so
	// refreshDB's all-tenants read runs through RLS and a zero-row result
	// cannot be trusted as "genuinely zero" without corroboration.
	refreshPoolIsRLSScoped := refreshDB == db && agent.UseAppRoleEnabled()

	e.mu.Lock()
	e.db = db
	e.metricsDB = metricsDB
	e.refreshDB = refreshDB
	e.refreshPoolIsRLSScoped = refreshPoolIsRLSScoped
	e.mu.Unlock()

	// Tables created by migration 010_policy_tables.sql
	// Seed default data (system media policies, sample policies if empty)
	if err := e.seedDefaultData(); err != nil {
		log.Printf("Warning: Failed to seed default data: %v", err)
	}

	return nil
}

func (e *DatabaseDynamicPolicyEngine) seedDefaultData() error {
	// Seed system media policies (idempotent — ON CONFLICT DO NOTHING)
	if err := e.seedSystemMediaPolicies(); err != nil {
		log.Printf("Warning: Failed to seed system media policies: %v", err)
	}

	// Insert sample policies if table is empty. Cross-org COUNT — must run
	// on the refresh pool: on the app-role pool RLS filters every row and
	// the count reads 0 on every boot, re-attempting the sample seed. SQL
	// lives in the shared substrate now (sharedpolicy.CountAllDynamicPolicies,
	// #3319/#3293) — this call site owns only the pool selection.
	count, err := sharedpolicy.CountAllDynamicPolicies(context.Background(), e.crossOrgDB())
	if err != nil {
		return err
	}

	if count == 0 {
		return e.insertSamplePolicies()
	}

	return nil
}

// seedSystemMediaPolicies seeds the 5 default system media governance policies.
// Uses ON CONFLICT DO NOTHING for idempotent upgrades — existing policies are never overwritten.
func (e *DatabaseDynamicPolicyEngine) seedSystemMediaPolicies() error {
	type systemMediaPolicy struct {
		policyID    string
		name        string
		description string
		category    string
		conditions  string
		actions     string
		priority    int
	}

	policies := []systemMediaPolicy{
		{
			policyID:    "sys_media_nsfw_block",
			name:        "NSFW Content Blocking",
			description: "Blocks media with high NSFW confidence scores",
			category:    "media-safety",
			conditions:  `[{"field":"media.nsfw_score","operator":"greater_than","value":0.8}]`,
			actions:     `[{"type":"block","config":{"reason":"Media blocked: NSFW content detected (score > 0.8)"}}]`,
			priority:    1000,
		},
		{
			policyID:    "sys_media_violence_warn",
			name:        "Violence Content Warning",
			description: "Alerts on media with high violence scores",
			category:    "media-safety",
			conditions:  `[{"field":"media.violence_score","operator":"greater_than","value":0.7}]`,
			actions:     `[{"type":"alert","config":{"message":"Violence detected in media (score > 0.7)"}},{"type":"log","config":{}}]`,
			priority:    950,
		},
		{
			policyID:    "sys_media_biometric_log",
			name:        "Biometric Data Audit",
			description: "Logs media containing biometric data for compliance audit",
			category:    "media-biometric",
			conditions:  `[{"field":"media.has_biometric_data","operator":"equals","value":true}]`,
			actions:     `[{"type":"log","config":{"message":"Biometric data detected in media"}}]`,
			priority:    900,
		},
		{
			policyID:    "sys_media_pii_block",
			name:        "Image PII Blocking",
			description: "Blocks media containing personally identifiable information",
			category:    "media-pii",
			conditions:  `[{"field":"media.has_pii","operator":"equals","value":true}]`,
			actions:     `[{"type":"block","config":{"reason":"Media blocked: PII detected in image content"}}]`,
			priority:    950,
		},
		{
			policyID:    "sys_media_sensitive_doc_warn",
			name:        "Sensitive Document Detection",
			description: "Alerts when sensitive documents are detected in media",
			category:    "media-document",
			conditions:  `[{"field":"media.is_sensitive_document","operator":"equals","value":true}]`,
			actions:     `[{"type":"alert","config":{"message":"Sensitive document detected in media"}},{"type":"log","config":{}}]`,
			priority:    900,
		},
	}

	// v9 Phase 8 PR-C2 (#2384): seeder writes 'global' wildcard policies that
	// apply across orgs. dynamic_policies is mig 018 ENABLE RLS with policy
	// `org_id = get_current_org_id()`. Wrap with WithOrgScope('global') +
	// populate org_id='global' so the WITH CHECK GUC-vs-column match holds
	// under axonflow_app_role. The 'global' sentinel is read-side-recognized
	// by getApplicablePolicies which treats tenant_id='global' as
	// matching-all-tenants — same shape for org_id here.
	wrapErr := agent.WithOrgScope(context.Background(), e.db, "global", func(tx *sql.Tx) error {
		for _, p := range policies {
			// v9 compat (Epic #2230 Phase 2/4): client_id literal 'global'
			// mirrors the tenant_id 'global' wildcard sentinel (migration 090).
			if _, err := tx.ExecContext(context.Background(), `
				INSERT INTO dynamic_policies (
					policy_id, name, description, policy_type, category, tier,
					conditions, actions, tenant_id, client_id, org_id, priority, enabled,
					version, created_by, updated_by, created_at, updated_at
				) VALUES ($1, $2, $3, 'media', $4, 'system', $5::jsonb, $6::jsonb, 'global', 'global', 'global', $7, true, 1, 'system', 'system', NOW(), NOW())
				ON CONFLICT (policy_id) DO NOTHING
			`, p.policyID, p.name, p.description, p.category, p.conditions, p.actions, p.priority); err != nil {
				return fmt.Errorf("failed to seed system media policy %s: %w", p.policyID, err)
			}
		}
		return nil
	})
	if wrapErr != nil {
		return wrapErr
	}

	log.Println("System media policies seeded (5 policies, idempotent)")
	return nil
}

func (e *DatabaseDynamicPolicyEngine) insertSamplePolicies() error {
	samplePolicies := []struct {
		name        string
		description string
		policyData  string
		tenantID    string
		priority    int
	}{
		{
			name:        "healthcare_compliance_policy",
			description: "HIPAA compliance for healthcare data",
			policyData: `{
				"type": "healthcare",
				"rules": {
					"data_classification": ["PHI", "PII"],
					"encryption_required": true,
					"audit_level": "detailed",
					"max_tokens": 4000,
					"allowed_models": ["gpt-4", "claude-3"],
					"rate_limit": {
						"requests_per_minute": 100,
						"tokens_per_hour": 100000
					}
				}
			}`,
			tenantID: "healthcare",
			priority: 10,
		},
		{
			name:        "ecommerce_optimization_policy",
			description: "Performance optimization for e-commerce",
			policyData: `{
				"type": "ecommerce",
				"rules": {
					"cache_enabled": true,
					"cache_ttl": 300,
					"max_parallel_requests": 5,
					"fallback_model": "gpt-4o-mini",
					"cost_optimization": true,
					"rate_limit": {
						"requests_per_minute": 500,
						"burst_size": 50
					}
				}
			}`,
			tenantID: "ecommerce",
			priority: 5,
		},
		{
			name:        "global_rate_limiting",
			description: "Global rate limiting policy",
			policyData: `{
				"type": "rate_limit",
				"rules": {
					"global_rpm": 1000,
					"per_user_rpm": 50,
					"per_ip_rpm": 100,
					"burst_multiplier": 2
				}
			}`,
			tenantID: "global",
			priority: 1,
		},
	}

	for _, p := range samplePolicies {
		// Parse the policy data to extract conditions and actions
		var policyMap map[string]interface{}
		_ = json.Unmarshal([]byte(p.policyData), &policyMap)

		// None of these three sample payloads carries a "conditions" key, so
		// policyMap["conditions"] is nil and marshals to the JSON literal
		// `null` — deliberately: these platform-seeded rows are meant to
		// apply unconditionally, and "no conditions" is exactly how that is
		// expressed (see condition_evaluator.go's "Withdrawn" doc section).
		conditions, _ := json.Marshal(policyMap["conditions"])
		actions, _ := json.Marshal(policyMap["actions"])

		// v9 Phase 8 PR-C2 (#2384): each sample policy is scoped to its own
		// tenantID. Wrap per iteration so the GUC matches the row's org_id
		// (which mirrors tenant_id at this writer).
		wrapErr := agent.WithOrgScope(context.Background(), e.db, p.tenantID, func(tx *sql.Tx) error {
			// v9 compat (Epic #2230 Phase 2/4): client_id + org_id both mirror tenant_id ($7).
			_, err := tx.ExecContext(context.Background(), `
				INSERT INTO dynamic_policies (policy_id, name, description, policy_type, conditions, actions, tenant_id, client_id, org_id, priority)
				VALUES ($1, $2, $3, $4, $5, $6, $7, $7, $7, $8)
				ON CONFLICT (policy_id) DO UPDATE SET
					conditions = EXCLUDED.conditions,
					actions = EXCLUDED.actions,
					updated_at = CURRENT_TIMESTAMP
			`, p.name, p.name, p.description, "test", string(conditions), string(actions), p.tenantID, p.priority)
			return err
		})
		if wrapErr != nil {
			return fmt.Errorf("failed to insert policy %s: %w", p.name, wrapErr)
		}
	}

	return nil
}

// crossOrgDB returns the pool for deliberate all-tenants reads (gate-cache
// refresh, boot COUNT). Falls back to the main pool when refreshDB is unset —
// tests construct the engine via struct literals without the admin pool, and
// non-app-role deployments read everything through db anyway.
func (e *DatabaseDynamicPolicyEngine) crossOrgDB() *sql.DB {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if e.refreshDB != nil {
		return e.refreshDB
	}
	return e.db
}

func (e *DatabaseDynamicPolicyEngine) refreshPolicies() error {
	e.mu.RLock()
	db := e.db
	e.mu.RUnlock()

	if db == nil {
		if e.dbURL == "" {
			// R3 finding 3 (#3319 hostile review): deliberately NOT
			// recordPolicyRefreshFailure here. "No DATABASE_URL configured"
			// is a steady, intentional state for a community deployment —
			// every 30s tick would otherwise increment
			// axonflow_policy_refresh_failures_total{reason="database_not_configured"}
			// forever, and a naive `rate(...) > 0` alert would then fire
			// permanently for every correctly-configured no-database
			// install. axonflow_policy_set_source{source="defaults"}
			// already exposes this state continuously; nothing is lost by
			// not also counting it as a failure. The error return below is
			// unchanged — callers (backgroundRefresh) still see "this tick
			// did not load anything new," just not as a counted failure.
			return fmt.Errorf("database not configured (DATABASE_URL unset)")
		}
		// #3319: no live pool yet — either boot found the database
		// unreachable, or an earlier tick's lazy reconnect failed. Try
		// once more now with a single attempt (see connectDB's doc for why
		// maxRetries=1 here specifically): this tick's job is to notice
		// recovery, not to block waiting for it — the NEXT tick, 30s from
		// now, is the next retry.
		if err := e.connectDB(1); err != nil {
			recordPolicyRefreshFailure(reasonDatabaseUnreachable)
			return fmt.Errorf("database unreachable: %w", err)
		}
	}

	// Plugin Batch 1 (ADR-044): also load risk_level + allow_override so
	// the evaluator can populate AppliedPoliciesDetail for override
	// enforcement. description + id surface as metadata fields consumed by
	// the matcher path and downstream richer-context consumers.
	//
	// ALL-tenants read feeding the multi-tenant gate cache — must run on the
	// BYPASSRLS refresh pool (see refreshDB field comment / #3039). On the
	// app-role pool this SELECT silently returns 0 rows and every dynamic
	// policy stops being enforced at the gate. The SQL itself lives in the
	// shared substrate (sharedpolicy.RefreshDynamicPolicies, #3319/#3293) —
	// this call site owns pool selection (e.crossOrgDB()) and the
	// missing-column retry decision, not the query text.
	ctx := context.Background()
	rows, err := sharedpolicy.RefreshDynamicPolicies(ctx, e.crossOrgDB(), true)
	if err != nil {
		var riErr *sharedpolicy.RowIterationError
		if errors.As(err, &riErr) {
			recordPolicyRefreshFailure(reasonRowIterationFailed)
			return fmt.Errorf("error iterating policies: %w", riErr.Unwrap())
		}
		if !isMissingColumnError(err, "segment_id") {
			recordPolicyRefreshFailure(reasonQueryFailed)
			return fmt.Errorf("failed to query policies: %w", err)
		}
		// H3 (#3239 round 2): booted against a dynamic_policies table that
		// predates migration 159 — retry segment-less. Correct pre-159: no
		// segment_id rows can exist yet, so this keeps enforcement live and
		// segment-unaware instead of failing the refresh outright.
		log.Printf("[Policy] ADR-060 (#2989 P3b): dynamic_policies.segment_id not found (pre-migration-159) — loading segment-less until the column is migrated")
		rows, err = sharedpolicy.RefreshDynamicPolicies(ctx, e.crossOrgDB(), false)
		if err != nil {
			if errors.As(err, &riErr) {
				recordPolicyRefreshFailure(reasonRowIterationFailed)
				return fmt.Errorf("error iterating policies (segment-less retry): %w", riErr.Unwrap())
			}
			recordPolicyRefreshFailure(reasonQueryFailed)
			return fmt.Errorf("failed to query policies (segment-less retry): %w", err)
		}
	}

	newPolicies := make(map[string]interface{})

	for _, row := range rows {
		// Handle NULL tenant_id
		tenantIDStr := "default"
		if row.TenantID.Valid {
			tenantIDStr = row.TenantID.String
		}

		// Decision 5 (#3490): org_id is what the applicability choke point
		// reads. An invalid (NULL) or blank org_id is NOT given a
		// "applies-to-everyone" sentinel the way tenant_id's NULL is: this
		// gate is the only thing bounding a cache that is deliberately
		// loaded ALL-TENANTS through the BYPASSRLS pool, so an unkeyed row
		// must apply to nobody. Migration 165 makes that state
		// unrepresentable going forward; the empty string here is what a row
		// written by a pre-165 deployment mid-upgrade resolves to, and
		// dbCachedPolicyAppliesToOrg excludes it.
		orgIDStr := ""
		if row.OrgID.Valid {
			orgIDStr = strings.TrimSpace(row.OrgID.String)
		}

		// ADR-060 (#2989 P3b): "" (not present, or SQL NULL, or simply not
		// selected by the segment-less retry) means "not segment-scoped" —
		// the same convention as the in-memory engine's
		// DynamicPolicy.SegmentID and migration 159's nullable column.
		segmentIDStr := ""
		if row.SegmentID.Valid {
			segmentIDStr = row.SegmentID.String
		}

		// Critical-risk policies can never be overridable (ADR-044 DB trigger
		// guarantees this but we enforce again in memory to survive stale
		// cached rows).
		allowOverride := row.AllowOverride
		if row.RiskLevel == "critical" {
			allowOverride = false
		}

		// Create policy data from conditions and actions
		policyData := map[string]interface{}{
			"policy_id":   row.PolicyID,
			"name":        row.Name,
			"description": row.Description,
			"type":        row.PolicyType,
			"category":    row.Category,
			"conditions":  json.RawMessage(row.Conditions),
			"actions":     json.RawMessage(row.Actions),
			"tenant_id":   tenantIDStr,
			"priority":    row.Priority,
		}

		// createdAt (#3321 follow-up) rides alongside priority in _metadata
		// as the evaluation-order tiebreaker sortedDynamicPolicyEntries
		// sorts by — see that function's doc. An invalid (NULL) created_at
		// is a data anomaly on a NOT-NULL-by-default column; it sorts as
		// the zero time.Time (the earliest possible value, i.e. LAST under
		// created_at DESC) rather than panicking or silently matching every
		// other zero-value row by coincidence.
		var createdAt time.Time
		if row.CreatedAt.Valid {
			createdAt = row.CreatedAt.Time
		}

		// Add metadata — plug in the UUID and ADR-044 risk/override flags so
		// the evaluator can attach them to AppliedPoliciesDetail for
		// downstream override enforcement.
		//
		// segment_id (ADR-060 #2989 P3b) rides alongside tenant_id here —
		// the choke point (dbCachedPolicyAppliesToTenant) reads BOTH out of
		// this same _metadata map. Every writer of e.policies (this
		// function and loadDefaultPolicies) populates _metadata, so a cache
		// entry missing it entirely is a programming defect, not a shape
		// this function is expected to produce — see that function's doc
		// for how it now fails closed on that case.
		policyData["_metadata"] = map[string]interface{}{
			"id":             row.ID,
			"name":           row.Name,
			"tenant_id":      tenantIDStr,
			"org_id":         orgIDStr,
			"segment_id":     segmentIDStr,
			"priority":       row.Priority,
			"created_at":     createdAt,
			"loaded_at":      time.Now().Unix(),
			"risk_level":     row.RiskLevel,
			"allow_override": allowOverride,
		}

		// Use policy_id as cache key to avoid cross-tenant name collisions.
		// Different tenants can have policies with the same name, and using name
		// as the key caused the second policy to overwrite the first.
		// Fall back to name for backward compatibility with legacy policies that
		// might not have a policy_id set.
		cacheKey := row.PolicyID
		if cacheKey == "" {
			cacheKey = row.Name
		}
		newPolicies[cacheKey] = policyData
	}

	// #3322 item 3 (review of #3319): a zero-row result on an RLS-scoped
	// refresh pool is not distinguishable, from the query's own success/error
	// signal, from the #3039 shape — get_current_org_id() returns NULL with
	// no org GUC set, org_id = NULL matches nothing, and the all-tenants read
	// silently returns zero rows with no error. #3320's predecessor engine
	// had an explicit fallback guard here; treating a coincident zero-row +
	// RLS-scoped-pool load as an ordinary successful (if empty) load — and
	// promoting on it — would swap away whatever was previously enforced
	// (last-good database rows, or the built-in defaults) for an empty set,
	// while reporting source="database" as if the swap were trustworthy. The
	// static plane already fails closed on the equivalent shape
	// (shared/policy.ErrEmptySystemPolicySet); this refuses the promotion
	// the same way — as a FAILED refresh, so #3319 item B's swap-only-on-
	// success invariant (below) leaves the last-good set in place — rather
	// than accept the read at face value. e.refreshPoolIsRLSScoped is false
	// (trust the read) whenever a dedicated BYPASSRLS pool served this read,
	// or the app-role gate is off entirely — see its field doc for both
	// conditions.
	if len(newPolicies) == 0 && e.refreshPoolIsRLSScoped {
		recordPolicyRefreshFailure(reasonZeroRowRLSBlind)
		return fmt.Errorf("zero-row load on an RLS-scoped refresh pool with no dedicated BYPASSRLS admin pool (AXONFLOW_DB_USE_APP_ROLE=true) — refusing to promote a possibly RLS-blind read (#3039 class); last-good policy set unchanged")
	}

	// Update cache. #3319 item B (swap-only-on-success): every error return
	// above happens BEFORE this line, so a failed refresh NEVER reaches
	// here and NEVER touches e.policies/e.policySetSource — the last-good
	// set (or the built-in defaults, if no load has ever succeeded) keeps
	// being enforced. See TestRefreshPolicies_FailedRefreshNeverDowngradesSource.
	e.mu.Lock()
	e.policies = newPolicies
	e.lastRefresh = time.Now()
	promoted := e.policySetSource != policySetSourceDatabase
	e.policySetSource = policySetSourceDatabase
	e.mu.Unlock()

	if promoted {
		log.Println("[dynamic-policy-engine] first successful load — policy-set source promoted defaults -> database (#3319)")
	}
	setPolicySetSourceMetric(policySetSourceDatabase)
	setPolicyCacheAgeSeconds(0)

	if len(newPolicies) == 0 {
		// #3039 class: this SUCCEEDED — it is not a failed refresh, and
		// must not be folded into policyRefreshFailuresTotal, or a
		// deployment with genuinely zero policies configured would be
		// indistinguishable from a broken one. But zero rows is ALSO
		// exactly what an all-tenants read returns on the app-role pool
		// with no org GUC set (get_current_org_id() -> NULL, org_id =
		// NULL never true) — "loaded successfully, zero policies" and
		// "the read is RLS-blind" must not look identical from outside
		// the process either, so this gets its own counter.
		recordPolicyZeroRowLoad()
	}

	log.Printf("Loaded %d policies from database", len(newPolicies))
	return nil
}

// RefreshPolicies triggers an immediate policy refresh from the database.
// This is useful when policies are created/updated/deleted via the API and
// you need the changes to be available immediately without waiting for
// the background refresh cycle (default 30 seconds).
// Issue #1082: Used by WCP HITL integration for immediate policy availability.
func (e *DatabaseDynamicPolicyEngine) RefreshPolicies() error {
	return e.refreshPolicies()
}

func (e *DatabaseDynamicPolicyEngine) backgroundRefresh() {
	ticker := time.NewTicker(e.cacheTimeout)
	defer ticker.Stop()

	for {
		select {
		case <-e.stopCh:
			return
		case <-ticker.C:
			// Non-blocking refresh
			e.refreshMu.Lock()
			if !e.refreshing {
				e.refreshing = true
				e.refreshMu.Unlock()

				go func() {
					if err := e.refreshPolicies(); err != nil {
						log.Printf("Background policy refresh failed: %v", err)
					}
					e.refreshMu.Lock()
					e.refreshing = false
					e.refreshMu.Unlock()
				}()
			} else {
				e.refreshMu.Unlock()
			}
		}
	}
}

// reportMetrics periodically republishes this engine's health as Prometheus
// gauges (#3319) — axonflow_policy_set_source and
// axonflow_policy_cache_age_seconds. This is what keeps cache age climbing
// between successful loads (refreshPolicies itself resets it to 0 on
// success, and re-asserts the source gauge on promotion, but only this
// ticking loop advances the age while nothing has changed). Replaces the
// pre-#3319 health-probe row this function used to INSERT into
// policy_metrics: it wrote time-since-refresh into a column named
// execution_time_ms under a synthetic sentinel policy name, on metricsDB —
// not scrapable, semantically mislabeled, and the same class of connection
// failing in the scenario it was meant to report.
func (e *DatabaseDynamicPolicyEngine) reportMetrics() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-e.stopCh:
			return
		case <-ticker.C:
		}
		e.reportMetricsTick()
	}
}

// reportMetricsTick runs one iteration of reportMetrics' body — split out
// so tests can exercise the metric-publishing logic directly instead of
// waiting on the real 10s ticker.
func (e *DatabaseDynamicPolicyEngine) reportMetricsTick() {
	e.mu.RLock()
	policyCount := len(e.policies)
	lastRefresh := e.lastRefresh
	source := e.policySetSource
	e.mu.RUnlock()

	setPolicySetSourceMetric(source)

	if lastRefresh.IsZero() {
		setPolicyCacheAgeSeconds(0)
		log.Printf("Policy engine health: %d policies loaded, never refreshed (source=%s)", policyCount, source)
	} else {
		age := time.Since(lastRefresh)
		setPolicyCacheAgeSeconds(age)
		log.Printf("Policy engine health: %d policies loaded, last refresh: %v ago (source=%s)",
			policyCount, age, source)
	}
}

func (e *DatabaseDynamicPolicyEngine) GetPolicy(name string) (map[string]interface{}, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	// Try direct cache key lookup first (policy_id or name)
	if policy, exists := e.policies[name]; exists {
		if policyMap, ok := policy.(map[string]interface{}); ok {
			policyMap["database_accessed"] = true
			return policyMap, true
		}
	}

	// Fall back to searching by name field (cache key may be policy_id)
	for _, policy := range e.policies {
		if policyMap, ok := policy.(map[string]interface{}); ok {
			if policyMap["name"] == name {
				policyMap["database_accessed"] = true
				return policyMap, true
			}
		}
	}

	return nil, false
}

func (e *DatabaseDynamicPolicyEngine) GetAllPolicies() map[string]interface{} {
	e.mu.RLock()
	defer e.mu.RUnlock()

	// Deep copy to avoid race conditions
	result := make(map[string]interface{})
	for k, v := range e.policies {
		result[k] = v
	}

	// Mark that database was accessed
	result["database_accessed"] = true

	return result
}

// loadDefaultPolicies resets the cache to the built-in default fallback
// policy set — loadDefaultDynamicPolicies (policy_defaults.go, unmodified
// here) — and marks the policy-set source "defaults" (#3319). This set is
// never APPENDED to a database-loaded set (unlike the retired in-memory
// engine's loadPoliciesFromDB, which
// unioned the two on every load and duplicated rules like
// pol_high_risk_block / sys_dyn_high_risk_block under two ids) — it is the
// whole cache or it is absent.
//
// Each converted entry is routed through the SAME cache shape
// refreshPolicies writes, _metadata included, so a built-in default is
// evaluated through the exact same dbCachedPolicyAppliesToTenant /
// EvaluateDynamicPolicies path as a database-loaded policy — no second,
// parallel evaluation path for "defaults" to keep in sync with the first.
func (e *DatabaseDynamicPolicyEngine) loadDefaultPolicies() {
	e.mu.Lock()
	e.policies = loadDefaultPoliciesCache()
	e.policySetSource = policySetSourceDefaults
	e.mu.Unlock()

	setPolicySetSourceMetric(policySetSourceDefaults)
}

// loadDefaultPoliciesCache converts loadDefaultDynamicPolicies()'s
// []DynamicPolicy into this engine's map[string]interface{} cache shape,
// keyed the same way refreshPolicies keys a database-loaded set (policy_id,
// falling back to name).
func loadDefaultPoliciesCache() map[string]interface{} {
	defaults := loadDefaultDynamicPolicies()
	out := make(map[string]interface{}, len(defaults))
	for _, p := range defaults {
		key := p.ID
		if key == "" {
			key = p.Name
		}
		out[key] = defaultDynamicPolicyCacheEntry(p)
	}
	return out
}

// defaultDynamicPolicyCacheEntry converts one built-in default policy into
// one cache entry, mirroring the policyData + _metadata shape refreshPolicies
// builds per row.
//
// Every loadDefaultDynamicPolicies() entry has TenantID == "" (the
// in-memory engine's "unscoped, applies to every tenant" convention). On
// THIS engine an empty key in _metadata means "applies to nobody" -
// dbCachedPolicyAppliesToOrg's all-orgs sentinels are "global" and
// "default" — so it is translated to "global" here, the same sentinel
// refreshPolicies' own NULL-tenant_id row already resolves to.
//
// Decision 5 (#3490): org_id is written for the same reason and to the same
// value. These are the built-in fallback policies the engine serves when the
// database is unreachable; they are deployment-wide by construction, so
// 'global' is the truthful key, not a convenience. Omitting it would make
// every fallback policy apply to nobody the moment the gate started reading
// org_id - a silent, total loss of the degraded-mode baseline.
func defaultDynamicPolicyCacheEntry(p DynamicPolicy) map[string]interface{} {
	conditions, _ := json.Marshal(p.Conditions)
	actions, _ := json.Marshal(p.Actions)

	tenantID := p.TenantID
	if tenantID == "" {
		tenantID = "global"
	}

	riskLevel := p.RiskLevel
	if riskLevel == "critical" {
		// Mirrors refreshPolicies' in-memory re-assertion of the ADR-044
		// DB-trigger invariant (critical-risk policies are never
		// overridable), for the same "survive a future edit that forgets
		// it" reason — no built-in ships allow_override=true today, but a
		// future one might, and this keeps the invariant enforced here too.
		p.AllowOverride = false
	}

	return map[string]interface{}{
		"policy_id":   p.ID,
		"name":        p.Name,
		"description": p.Description,
		"type":        p.Type,
		"category":    p.Category,
		"conditions":  json.RawMessage(conditions),
		"actions":     json.RawMessage(actions),
		"tenant_id":   tenantID,
		"priority":    p.Priority,
		"_metadata": map[string]interface{}{
			"id":             p.ID,
			"name":           p.Name,
			"tenant_id":      tenantID,
			"org_id":         tenantID,
			"segment_id":     "",
			"priority":       p.Priority,
			"created_at":     p.CreatedAt,
			"loaded_at":      time.Now().Unix(),
			"risk_level":     riskLevel,
			"allow_override": p.AllowOverride,
		},
	}
}

// dynamicPolicyCacheEntry is one policy pulled out of the map-backed cache
// for evaluation, with its ordering keys already extracted so
// sortedDynamicPolicyEntries can sort without re-parsing _metadata per
// comparison.
type dynamicPolicyCacheEntry struct {
	cacheKey  string
	priority  int
	createdAt time.Time
	policyMap map[string]interface{}
}

// sortedDynamicPolicyEntries snapshots policies into a slice ordered
// priority DESC, created_at DESC, cacheKey ASC — a TOTAL order, so two
// policies tied on both priority and created_at still evaluate in the same
// fixed sequence every time rather than falling back to whatever order
// remains undetermined.
//
// # Why this exists (#3321 follow-up)
//
// e.policies is a map[string]interface{}, and Go deliberately randomizes
// map iteration order on every `range`. EvaluateDynamicPolicies seeds a
// running result.RiskScore that an earlier-evaluated policy's
// rules.risk_score (max-wins) or modify_risk (additive) action can raise,
// and a LATER-evaluated policy's own risk_score condition reads that live
// value — so which policy counts as "earlier" is not cosmetic, it can flip
// Allowed. Ranging over the map directly meant the SAME request, SAME
// stored policies, and SAME everything else could reach a different verdict
// from one call to the next: a governance product whose enforcement a
// customer cannot reproduce.
//
// The retired in-memory engine never had this problem — it held its
// policies as a slice, populated from a query already carrying
// `ORDER BY priority DESC, created_at DESC`
// (dynamicPoliciesQueryWithSegment / dynamicPoliciesQueryWithoutSegment,
// platform/shared/policy/loader.go), so it evaluated in that fixed
// sequence by construction. This function reproduces that exact ordering
// over the map-backed cache: the ORDER BY was always being computed by the
// database, and then discarded the moment rows landed in newPolicies
// (refreshPolicies) — restoring it here, not inventing a new policy.
//
// cacheKey (not the policy_id field, which can be "" for a legacy row
// keyed by name — see refreshPolicies' cacheKey fallback) is the final
// tiebreaker because it is always present and unique by construction: it
// is literally the map key every entry is stored under.
func sortedDynamicPolicyEntries(policies map[string]interface{}) []dynamicPolicyCacheEntry {
	entries := make([]dynamicPolicyCacheEntry, 0, len(policies))
	for cacheKey, policy := range policies {
		policyMap, ok := policy.(map[string]interface{})
		if !ok {
			continue
		}
		entry := dynamicPolicyCacheEntry{cacheKey: cacheKey, policyMap: policyMap}
		if p, ok := policyMap["priority"].(int); ok {
			entry.priority = p
		}
		if metadata, ok := policyMap["_metadata"].(map[string]interface{}); ok {
			if ca, ok := metadata["created_at"].(time.Time); ok {
				entry.createdAt = ca
			}
		}
		entries = append(entries, entry)
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].priority != entries[j].priority {
			return entries[i].priority > entries[j].priority // priority DESC
		}
		if !entries[i].createdAt.Equal(entries[j].createdAt) {
			return entries[i].createdAt.After(entries[j].createdAt) // created_at DESC
		}
		return entries[i].cacheKey < entries[j].cacheKey // cacheKey ASC (total order)
	})
	return entries
}

// EvaluateDynamicPolicies evaluates every applicable cached policy for req.
//
// ADR-060 (#2989 P3b): resolves the caller's governance-segment set
// in-process (resolveUserSegments, segment_policy_gate.go) BEFORE
// touching the policy cache, fail-closed — a genuine resolution error denies
// the whole request immediately. This engine carries no per-request verdict
// cache (only the cross-tenant policy SET cache refreshed in the background,
// e.policies), so there is no cache-key collision concern here the way
// #3142 is for the in-memory engine's verdictCacheKey — only the
// choke-point predicate (dbCachedPolicyAppliesToTenant) needs the resolved
// set. orgID/email come straight from req.User.OrgID / req.User.Email,
// composed above the already-resolved tenantscope scope (#3065) — never
// re-derived from a header here.
func (e *DatabaseDynamicPolicyEngine) EvaluateDynamicPolicies(ctx context.Context, req OrchestratorRequest) *PolicyEvaluationResult {
	startTime := time.Now()

	segmentIDs, segOK := resolveUserSegments(ctx, req.User.OrgID, req.User.Email)
	if !segOK {
		// S1 (#3239 round 2): EvaluationError=true is the typed availability
		// signal — this is NOT a policy match, so AppliedPolicies carries no
		// entry for it (the magic string "segment_resolution_failed" this
		// replaced made an availability failure indistinguishable from a
		// real policy block without string-matching).
		return &PolicyEvaluationResult{
			Allowed:          false,
			AppliedPolicies:  []string{},
			EvaluationError:  true,
			DatabaseAccessed: true,
			RequiredActions:  []string{"blocked: segment resolution failed (fail-closed, ADR-060 #2989 P3b)"},
			ProcessingTimeMs: time.Since(startTime).Milliseconds(),
		}
	}

	// Get all policies from cache (refreshed in background)
	e.mu.RLock()
	policies := e.policies
	lastRefresh := e.lastRefresh
	e.mu.RUnlock()

	result := &PolicyEvaluationResult{
		Allowed:          true,
		AppliedPolicies:  []string{},
		DatabaseAccessed: true, // Mark that we're using DB-backed policies
		ProcessingTimeMs: 0,    // Will be set at the end
		RequiredActions:  []string{},
		// Signal B (#3239 round 2): true only when a resolved, non-empty
		// segment set is actually in scope for this verdict — see
		// PolicyEvaluationResult.SegmentsResolved's doc.
		SegmentsResolved: len(segmentIDs) > 0,
	}

	// #3321: seed the platform-computed risk score HERE, before any policy
	// is evaluated, so the "risk_score" condition field (getFieldValue
	// below) reads a real signal instead of the caller-suppliable
	// req.Context zero-value it used to fall back to. Computed inside the
	// evaluator rather than at request ingress so the simulate and
	// policy-test planes — which call EvaluateDynamicPolicies the same way
	// enforcement does — see the identical value (the #3283 class of defect
	// is exactly ingress/evaluation divergence). This is a floor, not a
	// final figure: a matched policy's legacy rules.risk_score (max-wins,
	// below) or modify_risk action (additive, below) can still raise it
	// mid-loop, and — restoring the retired in-memory engine's semantics,
	// not introducing new behavior — that raised value becomes visible to a
	// later-evaluated policy's own risk_score condition, making evaluation
	// order-dependent on priority sort. That sort is real: see
	// sortedDynamicPolicyEntries below, which makes this loop deterministic
	// (priority DESC, created_at DESC, cacheKey ASC) rather than at the
	// mercy of Go's randomized map iteration.
	result.RiskScore = dbRiskCalculator.CalculateRiskScore(req)

	// Apply policies based on the caller's ORGANIZATION.
	//
	// Decision 5 (#3490): this used to read req.Client.TenantID (falling back
	// to req.User.TenantID) and hand it to the applicability gate. Both are
	// the Basic-auth username; processRequestHandler binds them from the
	// stamped X-Tenant-ID, which the agent in turn sets from that username,
	// so the value is authenticated as "what the caller typed", not as a
	// tenancy. org_id has a different provenance: it comes from the signed
	// licence payload and processRequestHandler overwrites both copies from
	// the gateway scope unconditionally (see its `req.User.OrgID =
	// scope.OrgID` block), so it cannot be chosen by the body either.
	//
	// The Client copy is preferred over the User copy for the same reason the
	// tenant read did: the two are written from the same scope value on the
	// governed plane, and the Client one is the ADR-052 credential identity.
	orgID := ""
	if req.Client.OrgID != "" {
		orgID = req.Client.OrgID
	}
	if orgID == "" && req.User.OrgID != "" {
		orgID = req.User.OrgID
	}

	// Check for tenant-specific policies. Evaluated in a FIXED order
	// (sortedDynamicPolicyEntries: priority DESC, created_at DESC, cacheKey
	// ASC) rather than a bare `range policies` — see that function's doc
	// for why a plain map range made the risk_score escalation above
	// order-dependent on Go's randomized map iteration, not just on
	// priority as intended.
	for _, entry := range sortedDynamicPolicyEntries(policies) {
		cacheKey := entry.cacheKey
		policyMap := entry.policyMap

		// Use the policy name from the data (cache key may be policy_id)
		name, _ := policyMap["name"].(string)
		if name == "" {
			name = cacheKey
		}

		// Check if policy applies to this ORG AND resolved segment set.
		// Shared choke point with ListActivePoliciesForTenant — see
		// dbCachedPolicyAppliesToOrg.
		if !dbCachedPolicyAppliesToOrg(policyMap, orgID, segmentIDs, cacheKey) {
			continue
		}

		// CRITICAL: Evaluate conditions BEFORE applying actions
		// Parse conditions from policy
		var conditions []map[string]interface{}
		explicitEmpty := false
		switch condRaw := policyMap["conditions"].(type) {
		case json.RawMessage:
			if err := json.Unmarshal(condRaw, &conditions); err != nil {
				log.Printf("[POLICY_EVAL] Failed to parse conditions for %s: %v", name, err)
				continue
			}
		case []byte:
			if err := json.Unmarshal(condRaw, &conditions); err != nil {
				log.Printf("[POLICY_EVAL] Failed to parse conditions for %s: %v", name, err)
				continue
			}
		case []interface{}:
			// Pre-parsed shape: no current cache writer stores it
			// (refreshPolicies stores json.RawMessage; loadDefaultPolicies
			// omits the key), but if one ever does, an explicitly-empty
			// slice must carry the SAME #3384 exclusion as `[]` bytes — a
			// convention-only invariant here would silently invert the
			// semantics under a future writer (R3 finding LOW-1).
			if len(condRaw) == 0 {
				explicitEmpty = true
			}
			for _, c := range condRaw {
				if cm, ok := c.(map[string]interface{}); ok {
					conditions = append(conditions, cm)
				}
			}
		}

		// #3384: an EXPLICITLY-EMPTY stored array is excluded from
		// enforcement, mirroring cachedPolicyToDynamicPolicy's read-side
		// skip. The two sides must stay in lockstep BY HAND: the list/
		// enforce parity gate (TestDBCachedPolicyListEnforceParity_
		// RealPostgres) canNOT see this hunk — its enforcement leg probes
		// dbCachedPolicyAppliesToTenant, which runs before the conditions
		// parse (R3 finding HIGH-2) — so the pin for THIS side is
		// TestEvaluateDynamicPolicies_LegacyEmptyArrayNotEnforced. Only the
		// RawMessage/[]byte arms distinguish `null` (nil slice, vacuous
		// match, platform-seeded intent) from `[]` (empty non-nil slice,
		// released-update-gap residue); the []interface{} arm sets
		// explicitEmpty above.
		if explicitEmpty || (conditions != nil && len(conditions) == 0) {
			dbUnevaluableRecorder.RecordUnevaluable(sharedpolicy.ReasonEmptyConditions)
			continue
		}

		// If policy has conditions, ALL must match (AND logic). No
		// conditions means the policy applies to everything — vacuous truth,
		// the same as an empty `WHERE` clause matching every row. See the
		// shared evaluator's "Withdrawn" doc section (condition_evaluator.go)
		// for why a stricter "zero conditions never matches" guard briefly
		// lived here and was reverted: that exposure (a zero-condition row
		// nobody meant to write, carrying a block action) is now closed at
		// the authoring/load boundary instead of by making the construct
		// itself unusable — validateCreateRequest/validateUpdateRequest both
		// reject an empty/cleared conditions list, a conditions JSON that
		// fails to unmarshal is skipped above (`continue`), and a legacy
		// explicitly-empty `[]` is excluded by the #3384 guard directly
		// above, never evaluated as indistinguishable from `null`.
		if len(conditions) > 0 {
			allMatch := true
			for _, cond := range conditions {
				condResult := e.evaluateCondition(cond, req, result)
				if !condResult {
					allMatch = false
					break
				}
			}
			if !allMatch {
				continue // Skip this policy - conditions don't match
			}
		}

		// Plugin Batch 1 (ADR-044): capture structured policy detail so the
		// override enforcement layer (ApplyOverrideToResult) has something to
		// iterate against. This engine populates AppliedPoliciesDetail at this
		// point (the now-deleted in-memory DynamicPolicyEngine, #3319, used to
		// need the same population), or WCP-path overrides never flip
		// deny -> allow.
		//
		// Source the policy UUID from _metadata.id when present so it matches
		// what policy_overrides.policy_id stores; fall back to the cacheKey.
		policyUUID := cacheKey
		riskLevel := ""
		allowOverride := false
		segmentID := ""
		description, _ := policyMap["description"].(string)
		if metadata, ok := policyMap["_metadata"].(map[string]interface{}); ok {
			if id, ok := metadata["id"].(string); ok && id != "" {
				policyUUID = id
			}
			if rl, ok := metadata["risk_level"].(string); ok {
				riskLevel = rl
			}
			if ao, ok := metadata["allow_override"].(bool); ok {
				allowOverride = ao
			}
			if sid, ok := metadata["segment_id"].(string); ok {
				segmentID = sid
			}
		}
		if riskLevel == "" {
			riskLevel = "medium"
		}
		// Critical-risk policies never surface as overridable (ADR-044 invariant).
		if riskLevel == "critical" {
			allowOverride = false
		}
		// ADR-060: a segment-scoped policy uses the SAME session-override
		// contract (ADR-044) as a tenant policy — overridable iff its own
		// allow_override column is true and it is not critical-risk (forced
		// false above). There is no segment-specific carve-out: additive-
		// restriction-only (Decision 1) is a property of the applicable-set
		// combiner earlier in this evaluation, not of ApplyOverrideToResult,
		// so honoring a segment policy's own allow_override in a later,
		// separately-authorized, identity-keyed override does not weaken it.
		// A hard-floor segment policy (compliance) simply ships with
		// allow_override=false or risk_level=critical, which
		// createOverrideHandler already refuses to override at creation time
		// (overrides_handler.go). SegmentID is still carried on the detail
		// below purely for attribution/audit — it is no longer read as an
		// override-exclusion signal anywhere.
		// Determine top action for the detail record — "block",
		// "require_approval", etc. Peek at actions without consuming them
		// here; the existing loop below still runs.
		detailAction := "log_only"
		if actRaw, ok := policyMap["actions"]; ok {
			var peekActions []interface{}
			switch av := actRaw.(type) {
			case []interface{}:
				peekActions = av
			case json.RawMessage:
				_ = json.Unmarshal(av, &peekActions)
			case []byte:
				_ = json.Unmarshal(av, &peekActions)
			}
			if len(peekActions) > 0 {
				if am, ok := peekActions[0].(map[string]interface{}); ok {
					if at, ok := am["type"].(string); ok && at != "" {
						detailAction = at
					}
				}
			}
		}
		result.AppliedPoliciesDetail = append(result.AppliedPoliciesDetail, AppliedPolicyDetail{
			PolicyID:      policyUUID,
			PolicyName:    name,
			Description:   description,
			Action:        detailAction,
			RiskLevel:     riskLevel,
			AllowOverride: allowOverride,
			SegmentID:     segmentID,
		})

		// Apply rate limiting if present
		if rules, ok := policyMap["rules"].(map[string]interface{}); ok {
			// Check for required actions
			if actions, ok := rules["required_actions"].([]interface{}); ok {
				for _, action := range actions {
					if actionStr, ok := action.(string); ok {
						result.RequiredActions = append(result.RequiredActions, actionStr)
					}
				}
			}

			// Calculate risk score if present
			if riskScore, ok := rules["risk_score"].(float64); ok {
				if riskScore > result.RiskScore {
					result.RiskScore = riskScore
				}
			}
		}

		// Apply actions from the new JSON format (Issue #883 - strict provider enforcement)
		// Actions may be stored as json.RawMessage ([]byte), so we need to parse it first
		var actions []interface{}
		switch actionsRaw := policyMap["actions"].(type) {
		case json.RawMessage:
			if err := json.Unmarshal(actionsRaw, &actions); err != nil {
				log.Printf("[POLICY_ROUTE] Failed to parse actions JSON: %v", err)
			}
		case []byte:
			if err := json.Unmarshal(actionsRaw, &actions); err != nil {
				log.Printf("[POLICY_ROUTE] Failed to parse actions bytes: %v", err)
			}
		case []interface{}:
			actions = actionsRaw
		}

		for _, action := range actions {
			actionMap, ok := action.(map[string]interface{})
			if !ok {
				continue
			}

			actionType, _ := actionMap["type"].(string)
			actionConfig, _ := actionMap["config"].(map[string]interface{})

			switch actionType {
			case "route":
				// Handle LLM routing override for compliance
				if preferred, ok := actionConfig["preferred_provider"].(string); ok && preferred != "" {
					result.PreferredProvider = preferred
				}
				if reason, ok := actionConfig["reason"].(string); ok {
					result.RoutingReason = reason
				}
				// Handle allowed_providers for strict compliance
				// Use INTERSECTION logic: if multiple policies specify allowed_providers,
				// only providers in ALL lists are allowed (most restrictive wins)
				if allowedRaw, ok := actionConfig["allowed_providers"]; ok {
					var policyAllowed []string
					switch v := allowedRaw.(type) {
					case []interface{}:
						for _, p := range v {
							if ps, ok := p.(string); ok {
								policyAllowed = append(policyAllowed, ps)
							}
						}
					case []string:
						policyAllowed = v
					}

					if len(policyAllowed) > 0 {
						if len(result.AllowedProviders) == 0 {
							// First policy with allowed_providers - set the initial list
							result.AllowedProviders = policyAllowed
						} else {
							// Compute intersection with existing allowed list
							intersection := make([]string, 0)
							for _, p := range result.AllowedProviders {
								for _, ap := range policyAllowed {
									if p == ap {
										intersection = append(intersection, p)
										break
									}
								}
							}
							result.AllowedProviders = intersection
						}
					}
				}
				log.Printf("[POLICY_ROUTE] Applied routing: preferred=%s, allowed=%v, reason=%s",
					result.PreferredProvider, result.AllowedProviders, result.RoutingReason)

			case "block":
				result.Allowed = false
				if reason, ok := actionConfig["reason"].(string); ok {
					result.RequiredActions = append(result.RequiredActions, "blocked: "+reason)
				}

			case "modify_risk":
				// Config key is "add", applied additively. This is the
				// established contract of THIS engine's switch, not the
				// retired in-memory engine's (dynamic_policy_engine.go,
				// deleted by #3319) — that one read a "modifier" key
				// multiplicatively, but the two engines' modify_risk arms
				// were never the same implementation, and this one is the
				// survivor. Proof it's load-bearing: migration 031 seeds
				// sys_dyn_llm_cost, a real enabled system policy, with
				// `{"type": "modify_risk", "config": {"add": 0.2}}` — an
				// already-shipped, customer-visible row this switch has
				// always read correctly. policy_defaults.go's
				// pol_expensive_query_limit and pol_anomaly_detection used
				// to set "modifier" instead (a copy-paste from the retired
				// engine's own convention that never matched this one) and
				// are fixed to "add" alongside this comment, rather than
				// changing the key here and silently breaking every
				// already-deployed sys_dyn_llm_cost row.
				if add, ok := actionConfig["add"].(float64); ok {
					result.RiskScore += add
				}

			case "log":
				// "Enhanced logging for the request" (dynamic_policy_types.go).
				// No separate log sink exists for policy actions beyond this
				// process's own structured log, which the audit/observability
				// pipeline already ingests.
				level, _ := actionConfig["level"].(string)
				if level == "" {
					level = "info"
				}
				message, _ := actionConfig["message"].(string)
				if message == "" {
					message = "policy matched"
				}
				log.Printf("[POLICY_LOG] level=%s policy=%q: %s (config=%v)", level, name, message, actionConfig)

			case "alert":
				// "Send alert to monitoring" (dynamic_policy_types.go). This
				// codebase has no dedicated alert-dispatch integration (no
				// paging/webhook sink) for dynamic-policy actions, so "send to
				// monitoring" is realized the same way every other subsystem here
				// surfaces an operational signal: a structured log line plus a
				// RequiredActions entry, so it is visible both in the process log
				// stream and in the audit trail (audit_logger.go records
				// RequiredActions verbatim) rather than silently discarded.
				severity, _ := actionConfig["severity"].(string)
				if severity == "" {
					severity = "medium"
				}
				channel, _ := actionConfig["channel"].(string)
				message, _ := actionConfig["message"].(string)
				log.Printf("[POLICY_ALERT] severity=%s channel=%s policy=%q: %s", severity, channel, name, message)
				result.RequiredActions = append(result.RequiredActions, fmt.Sprintf("alert: %s (severity=%s)", name, severity))

			case "warn":
				// ActionWarn (shared/policy/types.go) — allow-but-annotate, the
				// same shape as the neighbouring "log"/"alert" arms above and
				// consistent with its ActionRestrictiveness ranking of 2
				// (agent/policy_categories.go: block=5 > require_approval=4 >
				// redact=3 > warn=2 > log=1). Added because migration 036
				// downgraded sys_dyn_high_risk_block from "block" to "warn" but
				// this switch had no "warn" case at the time, so the downgraded
				// policy matched its condition, fell through the switch with no
				// matching case, and applied nothing at all — a policy an
				// operator believes is warning was actually silently inert.
				reason, _ := actionConfig["reason"].(string)
				if reason == "" {
					reason, _ = actionConfig["message"].(string)
				}
				if reason == "" {
					reason = "policy matched"
				}
				log.Printf("[POLICY_WARN] policy=%q: %s", name, reason)
				result.RequiredActions = append(result.RequiredActions, fmt.Sprintf("warn: %s (policy=%s)", reason, name))

			case "redact":
				// "Mark fields for redaction" (dynamic_policy_types.go) —
				// deliberately a signal, not an in-place content transform: this
				// function only ever computes a PolicyEvaluationResult verdict, it
				// never has access to the request/response body content that
				// would need redacting (that lives in the separate
				// response_processor.go Redactor pipeline, driven by PII
				// detection). The same signal-not-execute pattern already governs
				// "require_approval" above, whose actual approval workflow lives
				// entirely outside this function too. A downstream consumer that
				// wants to act on the requested fields reads RequiredActions, the
				// same channel require_approval and block already use.
				var fields []string
				switch fv := actionConfig["fields"].(type) {
				case []interface{}:
					for _, f := range fv {
						if fs, ok := f.(string); ok {
							fields = append(fields, fs)
						}
					}
				case []string:
					fields = fv
				}
				if len(fields) > 0 {
					log.Printf("[POLICY_REDACT] policy=%q requested redaction of fields=%v", name, fields)
					result.RequiredActions = append(result.RequiredActions, fmt.Sprintf("redact_requested: fields=%v", fields))
				}

			case "require_approval":
				// Issue #1082: Trigger HITL workflow - requires human approval before continuing
				result.Allowed = false
				result.RequiredActions = append(result.RequiredActions, "require_approval")
				if reason, ok := actionConfig["reason"].(string); ok {
					result.RequiredActions = append(result.RequiredActions, "approval_reason: "+reason)
				}
				// Extract and validate severity from policy action config for risk-tiered routing.
				// Invalid values are logged and ignored (risk score fallback applies).
				if severity, ok := actionConfig["severity"].(string); ok {
					if severity == "low" || severity == "medium" || severity == "high" || severity == "critical" {
						if result.Severity == "" || severityOrdinal(severity) > severityOrdinal(result.Severity) {
							result.Severity = severity
							result.SeverityPolicyID = name
						}
					} else {
						log.Printf("[POLICY] Invalid severity %q in require_approval action for policy %q, ignoring", severity, name)
					}
				}
				log.Printf("[POLICY] Require approval action applied - step will need human approval")
			}
		}

		result.AppliedPolicies = append(result.AppliedPolicies, name)
	}

	// Clamp RiskScore to the documented [0,1] range AFTER the loop, not
	// inside it. Nothing re-clamped following a "modify_risk" action's
	// additive result.RiskScore += add (above) or the legacy
	// rules.risk_score max-wins assignment, so e.g. an SQLi-detected 0.9
	// floor plus one 0.2 "modify_risk" policy produced 1.1 — outside the
	// 0.0-1.0 range CalculateRiskScore itself always documents and enforces
	// (risk_calculator.go), and that out-of-range value flowed into audit
	// rows and the compliance evidence export
	// (evidence_export_handler.go) verbatim. Clamping once here, after every
	// policy has had a chance to add to the running score, lets multiple
	// modify_risk policies compose additively and THEN clamps the total —
	// clamping inside the loop would instead cap each individual
	// contribution, which is a different (and wrong) semantics.
	if result.RiskScore > 1.0 {
		result.RiskScore = 1.0
	} else if result.RiskScore < 0.0 {
		result.RiskScore = 0.0
	}

	// Record metrics
	// v9 Phase 8 PR-C2 (#2384): policy_metrics RLS gates this per-eval row by
	// org_id. The goroutine runs independent of the eval txn so it owns its
	// own wrap - falling back to the 'system' sentinel when the caller carries
	// no org (no real request scope on the cache-warmup path).
	//
	// Decision 5 (#3490): the org scope now comes from orgID, the licence org
	// this evaluation was actually performed under, rather than from the
	// tenant string that used to stand in for it ("tenantID is the orgID at
	// this writer", per the note this replaces - true only under the
	// single-tenant collapse). The data column tenant_id keeps the caller's
	// tenant verbatim, ATTRIBUTION only: it says which credential produced
	// the row and never again which policies were selected for it.
	//
	// The 2-second timeout bounds the wrap tx so shutdown doesn't dangle on a
	// stuck metric INSERT — pre-PR-C2 the bare Exec inherited the request's
	// context-or-Background; the wrap's BeginTx now ties up a connection until
	// timeout, hence the explicit ctx scope.
	// R3 finding 1 (#3319 hostile review): metricsDB must be captured under
	// e.mu.RLock() HERE, in the calling goroutine, before the background
	// goroutine below reads it. Before #3319 this field could not race —
	// the engine was never handed to a caller until connectDB had already
	// populated db/metricsDB under the constructor's synchronous path. This
	// branch deliberately removed that invariant: the engine now serves
	// live traffic in "defaults" mode with metricsDB == nil while the 30s
	// background tick's connectDB call populates it concurrently under
	// e.mu.Lock() (connectDB, above). A bare `e.metricsDB` read inside the
	// spawned goroutine below raced with that write. metricsDB may
	// legitimately be nil here (defaults mode, no successful connect yet);
	// skip the metrics write entirely in that case rather than let
	// rls.WithOrgScope's nil-db error path fire — and log — on every single
	// evaluation for the entire lifetime of a DATABASE_URL-unset deployment.
	e.mu.RLock()
	metricsDB := e.metricsDB
	e.mu.RUnlock()
	if metricsDB != nil {
		metricTenantID := req.Client.TenantID
		if metricTenantID == "" {
			metricTenantID = req.User.TenantID
		}
		go func() {
			orgScope := orgID
			if orgScope == "" {
				orgScope = "system"
			}
			bgCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			wrapErr := agent.WithOrgScope(bgCtx, metricsDB, orgScope, func(tx *sql.Tx) error {
				_, err := tx.ExecContext(bgCtx, `
					INSERT INTO policy_metrics (policy_name, execution_time_ms, success, tenant_id, org_id)
					VALUES ('evaluation', $1, $2, $3, $4)
				`, int(time.Since(startTime).Milliseconds()), result.Allowed, metricTenantID, orgScope)
				return err
			})

			if wrapErr != nil {
				log.Printf("Failed to record policy metrics: %v", wrapErr)
			}
		}()
	}

	result.ProcessingTimeMs = int64(time.Since(startTime).Milliseconds())

	log.Printf("Policy evaluation completed in %v. Applied %d policies. Cache age: %v",
		time.Since(startTime), len(result.AppliedPolicies), time.Since(lastRefresh))

	return result
}

// evaluateCondition checks if a single condition matches the request.
// Supports operators: equals, not_equals, contains, not_contains, contains_any, regex, greater_than, less_than, in, not_in
//
// #3296: delegates to dbConditionEvaluator (the shared substrate).
// MapCondition reproduces this engine's exact untyped-map key lookup
// (field/operator/value, missing-key-safe via type assertion), and
// getFieldValue — untouched — supplies field resolution unconditionally
// (ok=true always: this engine's legacy evaluateCondition never
// short-circuited on field resolvability the way the MCP handler and
// policy-test evaluator do).
//
// The shared evaluator's matchRegexCondition deliberately discards a regex
// compile error rather than logging it (condition_evaluator.go: "outside
// this pure-function evaluator's job") — legacy evaluateCondition logged
// "[POLICY_EVAL] Regex error for pattern %s: %v" on a bad, string-typed
// pattern (never for a non-string Value, which legacy never attempted to
// compile at all). Reproduced here with a side-effect-free pre-check so that
// diagnostic stays intact; the verdict (false on a bad pattern) is
// unaffected either way.
//
// result carries the in-progress evaluation's running state (#3321) — today
// only "risk_score" reads it (see getFieldValue), restoring the retired
// in-memory engine's three-parameter getFieldValue signature. Every other
// field is still sourced from req.
func (e *DatabaseDynamicPolicyEngine) evaluateCondition(cond map[string]interface{}, req OrchestratorRequest, result *PolicyEvaluationResult) bool {
	mc, _ := sharedpolicy.MapCondition(cond)
	if mc.Operator == "regex" {
		if pattern, ok := mc.Value.(string); ok {
			if _, err := regexp.Compile(pattern); err != nil {
				log.Printf("[POLICY_EVAL] Regex error for pattern %s: %v", pattern, err)
			}
		}
	}
	return dbConditionEvaluator.Match(mc, func(field string) (any, bool) {
		return e.getFieldValue(field, req, result), true
	}, dbUnevaluableRecorder)
}

// getFieldValue extracts the value of a field from the request.
// Supports dotted notation like "user.role" or "client.tenant_id"
//
// # Provenance of the user.* fields (#3152) — read before adding one
//
// These cases resolve straight off req.User, so whatever fills req.User decides
// what a policy condition is evaluated against. Until #3152 that was the request
// BODY: /api/v1/process is registered on the agent's reverse proxy, which
// validates the caller's credential, stamps the tenancy headers and forwards the
// caller's body byte for byte — so `{user.role not_equals "admin"} → block`, the
// shape shipped as a built-in HIPAA template and offered in the portal's policy
// builder, was evadable by asserting "user":{"role":"admin"}. A grep for
// `User.Role =` across the orchestrator and agent returned zero assignments:
// nothing had ever set it from a credential, a header or a JWT claim.
//
// req.User is now bound by applyAuthoritativePrincipal (run.go) on every handler
// that decodes one and evaluates policy: user.email from the trust-gated
// X-User-Email header, user.role from X-Axonflow-User-Role (settable only from a
// validated per-user token — the agent Del()s any inbound value), and user.id /
// user.region zeroed because no authenticated source for them exists on this
// plane. The binding lives at the HANDLER, not here — that fix covered every
// caller, including the now-deleted in-memory sibling engine's own
// getFieldValue (dynamic_policy_engine.go, removed by #3319).
//
// Consequence for a new case: a `user.*` field is only as trustworthy as the
// channel the handler binds it from. Adding one whose value still comes from the
// body re-opens this issue.
//
// result supplies the sole field sourced from the evaluation itself rather
// than the request: "risk_score" (#3321). Restores the retired in-memory
// engine's three-parameter getFieldValue — the field could not be served
// without it, and was wired to req.Context as an unintended substitute in
// the interim (see the risk_score case below and RiskCalculator in
// risk_calculator.go). "context.risk_score" is unaffected: it still resolves
// through the generic "context.*" branch in the default case, an explicit,
// distinct, caller-asserted field under its own namespace — not a carve-out
// of this one.
func (e *DatabaseDynamicPolicyEngine) getFieldValue(field string, req OrchestratorRequest, result *PolicyEvaluationResult) interface{} {
	switch field {
	// Top-level fields
	case "query":
		return req.Query
	case "request_type":
		return req.RequestType
	case "request_id":
		return req.RequestID

	// User fields
	case "user.id", "user_id":
		return req.User.ID
	case "user.email", "user_email":
		return req.User.Email
	case "user.role", "user_role":
		return req.User.Role
	case "user.region", "user_region", "region":
		return req.User.Region
	case "user.tenant_id":
		return req.User.TenantID

	// Client fields
	case "client.id", "client_id", "agent_id":
		return req.Client.ID
	case "client.org_id", "org_id":
		return req.Client.OrgID
	case "client.tenant_id", "tenant_id":
		return req.Client.TenantID

	// Context fields (from map)
	case "environment", "env":
		if req.Context != nil {
			if env, ok := req.Context["environment"].(string); ok {
				return env
			}
		}
		// Also check environment variable
		return os.Getenv("ENVIRONMENT")

	case "risk_score":
		// #3321: platform-computed, not caller-suppliable. Seeded onto
		// result at the top of EvaluateDynamicPolicies and potentially
		// raised mid-evaluation by an earlier-matched policy's
		// rules.risk_score or modify_risk action — see that function's
		// seeding comment for why this is a floor, not a final figure.
		// result is never nil on the production evaluation path
		// (EvaluateDynamicPolicies always constructs one before the first
		// evaluateCondition call); a nil result (e.g. a test calling
		// getFieldValue directly) resolves to 0.0 rather than panicking.
		if result == nil {
			return 0.0
		}
		return result.RiskScore

	case "cost_estimate":
		if req.Context != nil {
			if ce, ok := req.Context["cost_estimate"].(float64); ok {
				return ce
			}
		}
		return 0.0

	default:
		// Media governance fields — resolved from context["media_analysis"]
		if strings.HasPrefix(field, "media.") && req.Context != nil {
			mediaField := field[len("media."):]
			if analysis, ok := req.Context["media_analysis"].(map[string]interface{}); ok {
				return analysis[mediaField]
			}
			return nil
		}

		// Try to get from context map for custom fields
		if req.Context != nil {
			// Handle dotted notation like "context.step_input.query"
			// Issue #1082: Support nested context paths for WCP step input
			parts := strings.Split(field, ".")
			if len(parts) >= 2 && parts[0] == "context" {
				// Join all parts after "context" to form the context key
				// e.g., "context.step_input.query" -> "step_input.query"
				contextKey := strings.Join(parts[1:], ".")
				if val, ok := req.Context[contextKey]; ok {
					return val
				}
			}
			// Direct lookup
			if val, ok := req.Context[field]; ok {
				return val
			}
		}
		return nil
	}
}

// #3296: the (e *DatabaseDynamicPolicyEngine) toFloat64 method was
// deleted here — its numeric-comparison logic now lives in
// platform/shared/policy/condition_evaluator.go's toFloat64. That shared
// version does NOT reproduce this method's own behavior: this method
// silently coerced any ParseFloat failure (and any non-numeric type) to
// 0.0, which was a live false positive — e.g. a non-numeric string field
// value under `less_than 100` evaluated `0 < 100` = true, a spurious match
// on a blocking rule. The converged toFloat64 treats an unparseable operand
// as NOT COMPARABLE (false) instead; see the shared type's convergence
// record for the full before/after. Grep confirmed this method's only
// callers were the old evaluateCondition's greater_than/less_than arms
// (db_dynamic_policies.go:1192-1193,1197-1198, deleted above) and its own
// test, TestDatabaseDynamicPolicyEngine_ToFloat64 (deleted).

// dbCachedPolicyAppliesToOrg decides whether one cached policy applies to one
// ORGANIZATION AND (ADR-060 #2989 P3b) one resolved segment set. It is the
// SINGLE choke point for that decision on this engine: both
// EvaluateDynamicPolicies (enforcement) and ListActivePoliciesForTenant
// (disclosure) call it, so list and enforce cannot diverge by construction —
// not by two predicates that merely look alike. P3b folds the segment test
// INSIDE this existing choke point rather than adding a second, parallel
// predicate (#3070 was rejected for exactly that; #3059 established the
// single-choke-point-per-engine rule this preserves).
//
// # Decision 5 (#3490): this gate reads org_id, not tenant_id
//
// It used to compare the cached tenant_id against the CALLER's tenant_id,
// which is the Basic-auth username (db_auth.go's Client.TenantID) forwarded
// as X-Tenant-ID - caller-chosen, validated by nothing. That mattered more
// here than anywhere else in the platform, because this engine's cache is
// deliberately loaded ALL-TENANTS through the platform-admin (BYPASSRLS)
// pool, so no row-level security bounded the read behind it: the string
// compare WAS the boundary. Measured pre-fix on a live stack, one licence
// and three usernames selected three different dynamic policy sets, and a
// username no policy named ("zzz") was governed by none of them.
//
// The org half is shape-aware over one legitimate shape:
//
//   - _metadata PRESENT with org_id: it must be "global", "default" (the
//     all-orgs sentinels - the NULL-tenant_id row's resolution in
//     refreshPolicies and the sentinel loadDefaultPolicies assigns its
//     fallback entries) or an exact match against the caller's licence org.
//     A present-but-EMPTY org_id therefore applies to NOBODY, and so does
//     every row when the CALLER is unbound - an empty-matches-empty compare
//     is the #3065 fail-open idiom and is refused explicitly.
//   - _metadata ABSENT, or present without org_id: every writer of the
//     cache (refreshPolicies AND loadDefaultPolicies) populates both, so
//     neither
//     shape is a valid cache state; they can only occur if a future writer
//     forgets. Rather than silently applying such a policy to every org (a
//     fail-OPEN bug that would have shipped as "it just works"), this
//     function treats it as a defect and fails CLOSED: the entry is excluded
//     from both enforcement and disclosure, and a [BUG] line is logged so the
//     missing writer gets fixed instead of quietly relied on.
//
// DynamicPolicy.TenantID cannot express the present-but-empty vs.
// legitimately-global distinction — it is "" for both — which is why the
// scoped list works over the raw cache entries and not over the converted
// structs. The same is true of org_id, which the converted struct does not
// carry at all.
//
// The segment half (ADR-060 Decision 2, additive/orthogonal to tenancy, same
// shape as the now-deleted in-memory engine's memPolicyAppliesToTenant used
// to carry, dynamic_policy_engine.go, removed by #3319): an empty/absent
// segment_id means "not segment-scoped" and passes UNCONDITIONALLY once the
// org test above has already passed - this is what makes an org with zero
// segment-scoped policies byte-identical to pre-P3b behavior. A non-empty
// segment_id additionally requires it to be present in callerSegments;
// nil/empty callerSegments therefore excludes every segment-scoped policy
// (the fail-closed caller contract lives one layer up, in
// resolveUserSegments). Segments remain the platform's VERIFIED sub-org
// dimension, and after Decision 5 they are the only one.
//
// cacheKey identifies the entry for the [BUG] log line only (e.g. the
// policy_id/name the caller's loop is already keyed on); it plays no role
// in the org/segment decision itself.
func dbCachedPolicyAppliesToOrg(policyMap map[string]interface{}, orgID string, callerSegments []string, cacheKey string) bool {
	metadata, ok := policyMap["_metadata"].(map[string]interface{})
	if !ok {
		// Every writer (refreshPolicies, loadDefaultPolicies) must populate
		// _metadata. Reaching here means one didn't — fail closed (exclude)
		// rather than silently applying the policy to every org.
		log.Printf("[BUG] dbCachedPolicyAppliesToOrg: cache entry %q has no _metadata - excluding (fail-closed); every writer (refreshPolicies, loadDefaultPolicies) must populate _metadata", cacheKey)
		return false
	}
	policyOrg, hasOrg := metadata["org_id"].(string)
	if !hasOrg {
		// Same class as the missing-_metadata case above and the same
		// answer. Both in-tree writers set org_id (Decision 5, #3490); an
		// entry without it came from a writer that predates or forgot the
		// key, and admitting it would apply one org's policy to every org
		// through a cache that is deliberately loaded ALL-TENANTS on a
		// BYPASSRLS pool.
		log.Printf("[BUG] dbCachedPolicyAppliesToOrg: cache entry %q has _metadata but no org_id - excluding (fail-closed); every writer (refreshPolicies, loadDefaultPolicies) must populate org_id", cacheKey)
		return false
	}
	// An unbound CALLER matches nothing but the shared baseline. Without this
	// the empty-string caller would match a row whose org_id is likewise
	// empty - the #3065 fail-open idiom, in the one place where a single
	// match decides enforcement for a whole plane.
	if orgID == "" {
		if policyOrg != "global" && policyOrg != "default" {
			return false
		}
	} else if policyOrg != "global" && policyOrg != "default" && policyOrg != orgID {
		// "global" and "default" (NULL tenant_id rows, and the built-in
		// fallback set) apply to every org.
		return false
	}
	policySegment, _ := metadata["segment_id"].(string)
	if policySegment == "" {
		return true
	}
	return segmentSetContains(callerSegments, policySegment)
}

// cachedPolicyToDynamicPolicy converts one raw cache entry into the wire
// struct. Shared by ListActivePolicies and ListActivePoliciesForTenant so the
// two views can never drift in what they expose per policy.
//
// ok is false when the stored conditions blob exists but fails to unmarshal —
// the caller MUST drop the entry entirely rather than surface it with
// Conditions left at its nil zero value. Now that zero/absent conditions
// vacuously matches everything (condition_evaluator.go's "Withdrawn" doc
// section), nil'ing out a corrupt blob and a genuinely condition-less policy
// would be indistinguishable to every downstream consumer — including the
// MCP handler, which reads through ListActivePoliciesForTenant and would
// then enforce a corrupted row as if it were a legitimate, deliberately
// unconditional one. A malformed policy must not be evaluated under any
// semantics, so it is excluded at this single conversion point instead.
func cachedPolicyToDynamicPolicy(cacheKey string, policyMap map[string]interface{}) (DynamicPolicy, bool) {
	// The cache is keyed by policy_id (refreshPolicies uses policy_id as the
	// map key to avoid cross-tenant name collisions), so the loop variable is
	// the UUID, NOT a human-readable name. Default Name to the key only as a
	// fallback; the real human name lives in policyMap["name"] and is set
	// below. Without this, every matched-policy surfaced to callers (e.g. the
	// MCP dynamic-policy evaluator's matched_policies → the decision feed the
	// Risk Committee reads) showed the opaque UUID instead of the policy name.
	dp := DynamicPolicy{
		Name:     cacheKey,
		Type:     "database",
		Enabled:  true,
		Priority: 0,
	}

	// Extract the human-readable name (refreshPolicies stores it under "name").
	if n, ok := policyMap["name"].(string); ok && n != "" {
		dp.Name = n
	}

	// Extract policy_id
	if policyID, ok := policyMap["policy_id"].(string); ok {
		dp.ID = policyID
	}

	// Extract metadata
	if metadata, ok := policyMap["_metadata"].(map[string]interface{}); ok {
		if priority, ok := metadata["priority"].(int); ok {
			dp.Priority = priority
		}
		if tenantID, ok := metadata["tenant_id"].(string); ok {
			dp.TenantID = tenantID
		}
		if segmentID, ok := metadata["segment_id"].(string); ok {
			dp.SegmentID = segmentID
		}
	}

	// Extract conditions from stored JSON. A failed unmarshal means this
	// entry is corrupt and must not be evaluated under any semantics — the
	// caller is told via the (DynamicPolicy{}, false) return and must skip
	// the policy entirely rather than cache/surface it with Conditions nil
	// (epic #3293; see this function's own doc for why that distinction is
	// now load-bearing). dbUnevaluableRecorder is told separately
	// (ReasonConditionsUnmarshalFailed) so the occurrence is counted.
	// Shape handling mirrors the EvaluateDynamicPolicies conditions switch
	// (RawMessage / []byte / pre-parsed []interface{}) so the two sides of
	// the cache can never diverge on a shape one of them does not recognize
	// (R3 round-2 NEW-2: a []byte or pre-parsed value used to fail the
	// RawMessage-only assertion here, leave Conditions nil, and vacuously
	// match on THIS side while enforcement excluded it). No current writer
	// stores those shapes; the lockstep is defensive, like explicitEmpty.
	var conditionsRaw json.RawMessage
	preParsedEmpty := false
	switch v := policyMap["conditions"].(type) {
	case json.RawMessage:
		conditionsRaw = v
	case []byte:
		conditionsRaw = json.RawMessage(v)
	case []interface{}:
		if len(v) == 0 {
			preParsedEmpty = true
		} else if b, err := json.Marshal(v); err == nil {
			conditionsRaw = json.RawMessage(b)
		} else {
			dbUnevaluableRecorder.RecordUnevaluable(sharedpolicy.ReasonConditionsUnmarshalFailed)
			return DynamicPolicy{}, false
		}
	}
	if preParsedEmpty {
		dbUnevaluableRecorder.RecordUnevaluable(sharedpolicy.ReasonEmptyConditions)
		return DynamicPolicy{}, false
	}
	if conditionsRaw != nil {
		var conditions []PolicyCondition
		if err := json.Unmarshal(conditionsRaw, &conditions); err != nil {
			dbUnevaluableRecorder.RecordUnevaluable(sharedpolicy.ReasonConditionsUnmarshalFailed)
			return DynamicPolicy{}, false
		}
		// #3384: an EXPLICITLY-EMPTY stored array (`[]`) is skipped, while
		// JSON `null` / an absent key passes through with Conditions nil.
		// The two shapes are distinguishable here by construction —
		// json.Unmarshal leaves the slice nil for `null` and allocates an
		// empty non-nil slice for `[]` — and they carry OPPOSITE intent:
		//
		//   null = platform-seeded "applies to everything" (the seeders
		//          write no conditions key; the restored vacuous-match
		//          semantics exist FOR this shape), and
		//   []   = residue of the released update-API gap. Every released
		//          create rejected len==0 conditions; only the pre-9.19
		//          validateUpdateRequest let a PUT clear conditions to `[]`
		//          (verified against the v9.18.0 tag). So a stored `[]` can
		//          ONLY be that bug's output — and under vacuous-match it
		//          would go from "inert everywhere" (the old #3061 MCP
		//          guard, gone since #3320) to matching every governed MCP
		//          call for its tenant at upgrade, with a block-action row
		//          becoming a tenant-wide denial nobody authored.
		//
		// Skipping `[]` here makes "zero-condition policies are
		// platform-only" true by construction rather than by assumption.
		// Same contract as the corrupt-skip above: the caller drops the
		// policy, and the occurrence is counted under the reserved
		// empty_conditions label so an operator can SEE that a legacy row
		// was excluded instead of silently losing it.
		if conditions != nil && len(conditions) == 0 {
			dbUnevaluableRecorder.RecordUnevaluable(sharedpolicy.ReasonEmptyConditions)
			return DynamicPolicy{}, false
		}
		dp.Conditions = conditions
	}

	// Extract actions from stored JSON
	if actionsRaw, ok := policyMap["actions"].(json.RawMessage); ok {
		var actions []PolicyAction
		if err := json.Unmarshal(actionsRaw, &actions); err == nil {
			dp.Actions = actions
		}
	}

	// Extract type
	if pType, ok := policyMap["type"].(string); ok {
		dp.Type = pType
	}

	// Extract category
	if cat, ok := policyMap["category"].(string); ok {
		dp.Category = cat
	}

	return dp, true
}

// ListActivePolicies returns the raw, DEPLOYMENT-WIDE view of the in-memory
// policy cache — every tenant's policies (the cache is loaded cross-tenant on
// the BYPASSRLS admin pool because the evaluator enforces every tenant's
// policies in one process). That is correct for enforcement, but this view
// must NEVER be returned to an HTTP caller: HTTP consumers use
// ListActivePoliciesForTenant. This method has no HTTP-reachable caller and
// must not grow one.
func (e *DatabaseDynamicPolicyEngine) ListActivePolicies() []DynamicPolicy {
	e.mu.RLock()
	defer e.mu.RUnlock()

	var policies []DynamicPolicy
	for cacheKey, policy := range e.policies {
		policyMap, ok := policy.(map[string]interface{})
		if !ok {
			continue
		}
		dp, ok := cachedPolicyToDynamicPolicy(cacheKey, policyMap)
		if !ok {
			continue
		}
		policies = append(policies, dp)
	}
	return policies
}

// ListActivePoliciesForTenant returns the active policies visible to a single
// ORGANIZATION. It walks the RAW cache entries - not the converted structs -
// and gates each one through dbCachedPolicyAppliesToOrg, the very function
// EvaluateDynamicPolicies uses to decide enforcement. Same input, same
// function, same answer: a policy is listed to a caller if and only if it is
// enforced for that caller.
//
// Decision 5 (#3490) changed the KEY, not the shape: the first argument is
// now the caller's licence org, not its Basic-auth username. The method name
// is deliberately unchanged - it is an interface method with three
// implementors' worth of call sites and a "ForTenant" name that still
// describes what the DISCLOSURE endpoint is for, which is showing one caller
// the policies that govern it. What the caller must not do is keep passing a
// tenant id; every in-tree call site was updated in the same change.
//
// Walking the raw entries is load-bearing. DynamicPolicy.TenantID is "" both
// for a policy whose _metadata carries an empty key (enforced for NOBODY)
// and for a policy with no _metadata at all (a defect, excluded - see
// dbCachedPolicyAppliesToOrg); filtering the converted structs would collapse
// those meanings. The converted struct carries no org_id at all, which is a
// second, independent reason.
//
// This is the ONLY list variant HTTP handlers may consume.
// segmentIDs (ADR-060 #2989 P3b) mirrors the parameter of the same name that
// the now-deleted in-memory engine's own ListActivePoliciesForTenant used to
// carry (dynamic_policy_engine.go, removed by #3319) — every call site
// passes nil today because no verified per-user identity is available at
// those disclosure endpoints (see run.go's dynamicPolicyEngine interface).
func (e *DatabaseDynamicPolicyEngine) ListActivePoliciesForTenant(orgID string, segmentIDs []string) []DynamicPolicy {
	e.mu.RLock()
	defer e.mu.RUnlock()

	scoped := make([]DynamicPolicy, 0, len(e.policies))
	for cacheKey, policy := range e.policies {
		policyMap, ok := policy.(map[string]interface{})
		if !ok {
			continue
		}
		if !dbCachedPolicyAppliesToOrg(policyMap, orgID, segmentIDs, cacheKey) {
			continue
		}
		dp, ok := cachedPolicyToDynamicPolicy(cacheKey, policyMap)
		if !ok {
			continue
		}
		scoped = append(scoped, dp)
	}
	return scoped
}

// PolicySetSource returns whether this engine is currently enforcing a
// database-loaded policy set ("database") or the built-in default fallback
// set ("defaults") — see the policySetSource field and
// policySetSourceDefaults/policySetSourceDatabase constants (#3319). This
// is the programmatic form of the axonflow_policy_set_source metric: "there
// is one engine; what varies is the source of its policy set," made
// queryable in-process rather than only observable externally via Prometheus.
func (e *DatabaseDynamicPolicyEngine) PolicySetSource() string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.policySetSource
}

// LookupSegmentID returns the SegmentID (ADR-060 #2989 P3b) of a cached
// policy by its ID (policy_id — matching PolicyResource.ID and
// dynamic_policies.policy_id, see refreshPolicies), and whether the policy
// was found in this engine's cache.
//
// #3319: this is the DatabaseDynamicPolicyEngine equivalent of the retired
// in-memory DynamicPolicyEngine's LookupSegmentID (dynamic_policy_engine.go),
// used by PolicyService.TestPolicy (policy_api_service.go) as a best-effort
// source of a policy's segment scope. PolicyResource does not carry a
// SegmentID field, and PolicyRepository.GetByID's SELECT does not fetch
// dynamic_policies.segment_id — a structural gap in those types, not
// something TestPolicy can fix locally. This engine's already-loaded cache
// (populated from the SAME dynamic_policies table, including segment_id) is
// the best available source until that gap is closed.
//
// found=false means "not cached on this engine" — NOT "not segment-scoped".
// Callers MUST NOT conflate the two: treating a lookup miss as "definitely
// unscoped" could let a segment-scoped policy's test-preview report a match
// for a non-member, the exact #3266 disclosure class this epic exists to
// close. See TestPolicy's doc for how a miss is handled (degrade
// observably, never silently widen).
func (e *DatabaseDynamicPolicyEngine) LookupSegmentID(policyID string) (segmentID string, found bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	// Direct cache-key lookup first — refreshPolicies and
	// loadDefaultPolicies both key by policy_id when one is present (see
	// refreshPolicies' cacheKey comment).
	if policy, exists := e.policies[policyID]; exists {
		if sid, ok := segmentIDFromCacheEntry(policy); ok {
			return sid, true
		}
	}

	// Fall back to scanning by the policy_id field — the cache key may be
	// the policy name instead (refreshPolicies' fallback for a legacy row
	// with no policy_id set), mirroring GetPolicy's same two-tier lookup.
	for _, policy := range e.policies {
		policyMap, ok := policy.(map[string]interface{})
		if !ok {
			continue
		}
		if pid, _ := policyMap["policy_id"].(string); pid == policyID {
			if sid, ok := segmentIDFromCacheEntry(policy); ok {
				return sid, true
			}
		}
	}

	return "", false
}

// segmentIDFromCacheEntry extracts _metadata.segment_id from one raw cache
// entry. ok=false means the entry itself is not the expected
// map[string]interface{}-with-_metadata shape (a defect elsewhere, not a
// legitimate "unscoped" state) — LookupSegmentID treats that the same as
// "not found" rather than guessing.
func segmentIDFromCacheEntry(policy interface{}) (segmentID string, ok bool) {
	policyMap, ok := policy.(map[string]interface{})
	if !ok {
		return "", false
	}
	metadata, ok := policyMap["_metadata"].(map[string]interface{})
	if !ok {
		return "", false
	}
	sid, _ := metadata["segment_id"].(string)
	return sid, true
}

// IsHealthy reports whether this engine is currently serving a usable
// policy set — NOT whether e.db happens to be populated (R3 finding 2,
// #3319 hostile review).
//
// Predicate: healthy iff (a) at least one policy is loaded, AND (b) if the
// engine has been promoted to policySetSourceDatabase, its database
// dependency is actually live (pool reachable, cache refreshed within the
// last 5 minutes).
//
// Before this fix, IsHealthy() returned false whenever e.db == nil — true
// for the entire lifetime of a legitimate DATABASE_URL-unset community
// deployment, and for any window (including a boot-time blip that
// backgroundRefresh is actively recovering from) where the engine is
// correctly serving loadDefaultDynamicPolicies(). Pre-#3319 the retired
// in-memory engine's IsHealthy() was simply len(policies) > 0 — always
// true — so this was a real regression in what /health's
// components.policy_engine reported for a deployment whose enforcement was
// entirely correct.
//
// A policySetSourceDefaults engine has no live database dependency to
// report on — construction always pre-loads it with the non-empty
// built-in default set, so "serving defaults" is judged healthy on that
// alone, whatever the reason (no DSN, an unreachable database, or the
// window before the first successful load). A policySetSourceDatabase
// engine, by contrast, has made a real promise to keep enforcing what the
// database says: once promoted, a closed/unreachable pool or a refresh
// loop that has silently stopped succeeding (cache age > 5m) is a genuine
// degradation worth surfacing, even though the last-good policy set is
// still being enforced (refreshPolicies never reverts on a failed refresh
// — see policySetSourceDatabase's doc). This is what
// TestDatabaseDynamicPolicyEngine_HealthCheck (integration) already
// depends on: IsHealthy() must go false after Close(), which only a live
// ping (or an explicit nil check) can detect, since Close() does not nil
// out e.db, only closes the pool underneath it.
//
// The one case reported unhealthy regardless of source: zero policies
// loaded. This is NOT structurally impossible — construction always starts
// non-empty, but a policySetSourceDatabase engine CAN legitimately reach
// zero via a trusted (refreshPoolIsRLSScoped == false) zero-row database
// load; see TestRefreshPolicies_ZeroRowLoadDistinguishableFromFailedLoad,
// which promotes on exactly that. (A zero-row load on a pool this engine
// does NOT trust is refused before it ever reaches e.policies — #3322 item
// 3, TestRefreshPolicies_ZeroRowLoadOnRLSScopedPoolIsRefused — so it cannot
// produce this state either.) Reporting that legitimate-but-empty state as
// unhealthy is a deliberate operational choice, not a bug: "this process is
// currently enforcing nothing" is worth an operator's attention even when
// it was reached honestly, and IsHealthy() has no way to tell "genuinely
// zero policies configured" apart from a mistake without asking a human.
func (e *DatabaseDynamicPolicyEngine) IsHealthy() bool {
	e.mu.RLock()
	db := e.db
	source := e.policySetSource
	lastRefresh := e.lastRefresh
	policyCount := len(e.policies)
	e.mu.RUnlock()

	if policyCount == 0 {
		log.Printf("No policies loaded")
		return false
	}

	if source != policySetSourceDatabase {
		// Serving the built-in defaults (by design or by degradation the
		// background refresh is already retrying) is a fully functional
		// state with no database dependency to check.
		return true
	}

	// Promoted to database-loaded: health now legitimately depends on the
	// database this engine is tracking.
	if db == nil {
		return false
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if err := db.PingContext(ctx); err != nil {
		log.Printf("Database health check failed: %v", err)
		return false
	}

	if cacheAge := time.Since(lastRefresh); cacheAge > 5*time.Minute {
		log.Printf("Policy cache is stale: %v old", cacheAge)
		return false
	}

	return true
}

// UnsafePoolsForTests exposes the engine's two pools for integration tests
// that need to assert the connected Postgres role under USE_APP_ROLE=true.
// NOT for production use — the returned handles bypass the engine's
// concurrency + policy-cache invariants. Named "Unsafe...ForTests" to
// discourage accidental usage.
func (e *DatabaseDynamicPolicyEngine) UnsafePoolsForTests() (db, metricsDB *sql.DB) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.db, e.metricsDB
}

func (e *DatabaseDynamicPolicyEngine) Close() error {
	if e.stopCh != nil {
		select {
		case <-e.stopCh:
			// already closed
		default:
			close(e.stopCh)
		}
	}
	e.mu.RLock()
	db, metricsDB, refreshDB := e.db, e.metricsDB, e.refreshDB
	e.mu.RUnlock()
	if refreshDB != nil && refreshDB != db {
		_ = refreshDB.Close()
	}
	if db != nil {
		_ = db.Close()
	}
	if metricsDB != nil {
		_ = metricsDB.Close()
	}
	return nil
}
