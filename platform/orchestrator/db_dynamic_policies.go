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
	"fmt"
	"log"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	_ "github.com/lib/pq"

	"axonflow/platform/agent"
)

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
	refreshDB    *sql.DB
	policies     map[string]interface{}
	mu           sync.RWMutex
	lastRefresh  time.Time
	cacheTimeout time.Duration
	refreshing   bool
	refreshMu    sync.Mutex
	stopCh       chan struct{}
}

func NewDatabaseDynamicPolicyEngine() (*DatabaseDynamicPolicyEngine, error) {
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		return nil, fmt.Errorf("DATABASE_URL environment variable not set")
	}

	// Main connection pool for reads.
	// v9 Brief 11.5 / Session 20: route through agent.OpenAppRoleConnection so
	// AXONFLOW_DB_USE_APP_ROLE=true (default in v9.0.0) actually flips the
	// connection role to axonflow_app_role. Without this wrap, dynamic-policy
	// queries against dynamic_policies (and future RLS-FORCEd tables) silently
	// run as the table-owner role and bypass RLS.
	bootCtx := context.Background()
	db, err := agent.OpenAppRoleConnection(bootCtx, dbURL, 3)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
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
	metricsDB, err := agent.OpenAppRoleConnection(bootCtx, dbURL, 3)
	if err != nil {
		return nil, fmt.Errorf("failed to open metrics database: %w", err)
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
	adminDB, adminErr := agent.OpenPlatformAdminConnection(bootCtx, 3)
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

	engine := &DatabaseDynamicPolicyEngine{
		db:           db,
		metricsDB:    metricsDB,
		refreshDB:    refreshDB,
		policies:     make(map[string]interface{}),
		cacheTimeout: 30 * time.Second,
		lastRefresh:  time.Now(), // Initialize to prevent zero-time issues
		stopCh:       make(chan struct{}),
	}

	// Tables created by migration 010_policy_tables.sql
	// Seed default data (system media policies, sample policies if empty)
	if err := engine.seedDefaultData(); err != nil {
		log.Printf("Warning: Failed to seed default data: %v", err)
	}

	// Load initial policies. Two failure shapes can leave the cache
	// empty: (a) refreshPolicies returns an error, or (b) refreshPolicies
	// returns nil but the SELECT got zero rows because seedDefaultData
	// silently failed (the Warning log above is the only signal). The v1
	// fallback only handled case (a); under -race in CI the (b) case
	// flaked TestDatabaseDynamicPolicyEngine_Initialization +
	// _HealthCheck (IsHealthy() returns false when policyCount == 0).
	// Fall back to default policies on BOTH paths so a fresh engine
	// always reports healthy.
	if err := engine.refreshPolicies(); err != nil {
		log.Printf("Warning: Failed to load initial policies: %v", err)
		engine.loadDefaultPolicies()
	} else {
		engine.mu.RLock()
		empty := len(engine.policies) == 0
		engine.mu.RUnlock()
		if empty {
			log.Println("Warning: refreshPolicies returned 0 rows (seed likely failed) — falling back to default policies")
			engine.loadDefaultPolicies()
		}
	}

	// Start background refresh
	go engine.backgroundRefresh()

	// Start metrics reporter
	go engine.reportMetrics()

	return engine, nil
}

func (e *DatabaseDynamicPolicyEngine) seedDefaultData() error {
	// Seed system media policies (idempotent — ON CONFLICT DO NOTHING)
	if err := e.seedSystemMediaPolicies(); err != nil {
		log.Printf("Warning: Failed to seed system media policies: %v", err)
	}

	// Insert sample policies if table is empty. Cross-org COUNT — must run
	// on the refresh pool: on the app-role pool RLS filters every row and
	// the count reads 0 on every boot, re-attempting the sample seed.
	var count int
	err := e.crossOrgDB().QueryRow("SELECT COUNT(*) FROM dynamic_policies").Scan(&count)
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
	if e.refreshDB != nil {
		return e.refreshDB
	}
	return e.db
}

// refreshPoliciesQueryWithSegment / refreshPoliciesQueryWithoutSegment: two
// shapes of the same SELECT, split out so refreshPolicies can retry
// column-less against a not-yet-migrated dynamic_policies table — see H3
// (segment_column_probe.go's isMissingColumnError doc) for why this
// tolerance exists.
const refreshPoliciesQueryWithSegment = `
	SELECT id::text, name, COALESCE(description, '') AS description,
	       conditions, actions, tenant_id, priority, policy_id,
	       COALESCE(policy_type, 'content') as policy_type,
	       COALESCE(category, '') as category,
	       COALESCE(risk_level, 'medium') as risk_level,
	       COALESCE(allow_override, false) as allow_override,
	       segment_id
	FROM dynamic_policies
	WHERE enabled = true
	ORDER BY priority DESC, created_at DESC
`

const refreshPoliciesQueryWithoutSegment = `
	SELECT id::text, name, COALESCE(description, '') AS description,
	       conditions, actions, tenant_id, priority, policy_id,
	       COALESCE(policy_type, 'content') as policy_type,
	       COALESCE(category, '') as category,
	       COALESCE(risk_level, 'medium') as risk_level,
	       COALESCE(allow_override, false) as allow_override
	FROM dynamic_policies
	WHERE enabled = true
	ORDER BY priority DESC, created_at DESC
`

func (e *DatabaseDynamicPolicyEngine) refreshPolicies() error {
	// Plugin Batch 1 (ADR-044): also load risk_level + allow_override so
	// the evaluator can populate AppliedPoliciesDetail for override
	// enforcement. description + id surface as metadata fields consumed by
	// the matcher path and downstream richer-context consumers.
	//
	// ALL-tenants read feeding the multi-tenant gate cache — must run on the
	// BYPASSRLS refresh pool (see refreshDB field comment / #3039). On the
	// app-role pool this SELECT silently returns 0 rows and every dynamic
	// policy stops being enforced at the gate.
	hasSegmentColumn := true
	rows, err := e.crossOrgDB().Query(refreshPoliciesQueryWithSegment)
	if err != nil {
		if !isMissingColumnError(err, "segment_id") {
			return fmt.Errorf("failed to query policies: %w", err)
		}
		// H3 (#3239 round 2): booted against a dynamic_policies table that
		// predates migration 159 — retry segment-less. Correct pre-159: no
		// segment_id rows can exist yet, so this keeps enforcement live and
		// segment-unaware instead of failing the refresh outright.
		log.Printf("[Policy] ADR-060 (#2989 P3b): dynamic_policies.segment_id not found (pre-migration-159) — loading segment-less until the column is migrated")
		hasSegmentColumn = false
		rows, err = e.crossOrgDB().Query(refreshPoliciesQueryWithoutSegment)
		if err != nil {
			return fmt.Errorf("failed to query policies (segment-less retry): %w", err)
		}
	}
	defer func() { _ = rows.Close() }()

	newPolicies := make(map[string]interface{})

	for rows.Next() {
		var id, name, description, conditionsJSON, actionsJSON, policyID, policyType, category, riskLevel string
		var tenantID sql.NullString
		var segmentID sql.NullString
		var priority int
		var allowOverride bool

		var err error
		if hasSegmentColumn {
			err = rows.Scan(&id, &name, &description, &conditionsJSON, &actionsJSON, &tenantID, &priority, &policyID, &policyType, &category, &riskLevel, &allowOverride, &segmentID)
		} else {
			err = rows.Scan(&id, &name, &description, &conditionsJSON, &actionsJSON, &tenantID, &priority, &policyID, &policyType, &category, &riskLevel, &allowOverride)
		}
		if err != nil {
			log.Printf("Error scanning policy row: %v", err)
			continue
		}

		// Handle NULL tenant_id
		tenantIDStr := "default"
		if tenantID.Valid {
			tenantIDStr = tenantID.String
		}

		// ADR-060 (#2989 P3b): "" (not present, or SQL NULL) means "not
		// segment-scoped" — the same convention as the in-memory engine's
		// DynamicPolicy.SegmentID and migration 159's nullable column.
		segmentIDStr := ""
		if segmentID.Valid {
			segmentIDStr = segmentID.String
		}

		// Critical-risk policies can never be overridable (ADR-044 DB trigger
		// guarantees this but we enforce again in memory to survive stale
		// cached rows).
		if riskLevel == "critical" {
			allowOverride = false
		}

		// Create policy data from conditions and actions
		policyData := map[string]interface{}{
			"policy_id":   policyID,
			"name":        name,
			"description": description,
			"type":        policyType,
			"category":    category,
			"conditions":  json.RawMessage(conditionsJSON),
			"actions":     json.RawMessage(actionsJSON),
			"tenant_id":   tenantIDStr,
			"priority":    priority,
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
			"id":             id,
			"name":           name,
			"tenant_id":      tenantIDStr,
			"segment_id":     segmentIDStr,
			"priority":       priority,
			"loaded_at":      time.Now().Unix(),
			"risk_level":     riskLevel,
			"allow_override": allowOverride,
		}

		// Use policy_id as cache key to avoid cross-tenant name collisions.
		// Different tenants can have policies with the same name, and using name
		// as the key caused the second policy to overwrite the first.
		// Fall back to name for backward compatibility with legacy policies that
		// might not have a policy_id set.
		cacheKey := policyID
		if cacheKey == "" {
			cacheKey = name
		}
		newPolicies[cacheKey] = policyData
	}

	if err = rows.Err(); err != nil {
		return fmt.Errorf("error iterating policies: %w", err)
	}

	// Update cache
	e.mu.Lock()
	e.policies = newPolicies
	e.lastRefresh = time.Now()
	e.mu.Unlock()

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

func (e *DatabaseDynamicPolicyEngine) reportMetrics() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-e.stopCh:
			return
		case <-ticker.C:
		}

		e.mu.RLock()
		policyCount := len(e.policies)
		lastRefresh := e.lastRefresh
		e.mu.RUnlock()

		// Calculate time since last refresh, handling zero-time case
		var timeSinceRefresh time.Duration
		var timeSinceRefreshMs int
		if lastRefresh.IsZero() {
			timeSinceRefresh = 0
			timeSinceRefreshMs = 0
		} else {
			timeSinceRefresh = time.Since(lastRefresh)
			timeSinceRefreshMs = int(timeSinceRefresh.Milliseconds())
			// Cap at max int32 to prevent overflow (24 days)
			if timeSinceRefreshMs > 2147483647 {
				timeSinceRefreshMs = 2147483647
			}
		}

		// v9 Phase 8 PR-C2 (#2384): policy_metrics is mig 018 ENABLE RLS with
		// policy `org_id = get_current_org_id()`. The legacy INSERT here is a
		// process-level health probe with no per-tenant context. Use the
		// 'system' sentinel for both the GUC and the org_id column so the
		// WITH CHECK matches — this is the same shape getApplicablePolicies
		// uses to read system metrics back.
		wrapErr := agent.WithOrgScope(context.Background(), e.metricsDB, "system", func(tx *sql.Tx) error {
			_, err := tx.ExecContext(context.Background(), `
				INSERT INTO policy_metrics (policy_name, execution_time_ms, success, tenant_id, org_id)
				VALUES ('system_health', $1, true, 'system', 'system')
			`, timeSinceRefreshMs)
			return err
		})
		if wrapErr != nil {
			log.Printf("Failed to report metrics: %v", wrapErr)
		}

		// Log health status
		if lastRefresh.IsZero() {
			log.Printf("Policy engine health: %d policies loaded, never refreshed", policyCount)
		} else {
			log.Printf("Policy engine health: %d policies loaded, last refresh: %v ago",
				policyCount, timeSinceRefresh)
		}
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

func (e *DatabaseDynamicPolicyEngine) loadDefaultPolicies() {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.policies = map[string]interface{}{
		"default": map[string]interface{}{
			"type": "fallback",
			"rules": map[string]interface{}{
				"max_tokens":            2000,
				"temperature":           0.7,
				"allowed_models":        []string{"gpt-4o-mini"},
				"rate_limit_per_minute": 60,
			},
			// _metadata mirrors the shape refreshPolicies writes (see
			// _metadata there) so this is the SAME writer contract, not a
			// second one. tenant_id: "default" routes the fallback's
			// existing apply-to-all-tenants behavior through the legitimate
			// sentinel dbCachedPolicyAppliesToTenant already honors for a
			// NULL tenant_id row, instead of the absent-_metadata branch —
			// no behavior change here, just the correct path. segment_id:
			// "" keeps it segment-agnostic (ADR-060 #2989 P3b convention).
			"_metadata": map[string]interface{}{
				"id":             "default",
				"name":           "fallback",
				"tenant_id":      "default",
				"segment_id":     "",
				"priority":       0,
				"loaded_at":      time.Now().Unix(),
				"risk_level":     "",
				"allow_override": false,
			},
		},
	}
}

// EvaluateDynamicPolicies evaluates every applicable cached policy for req.
//
// ADR-060 (#2989 P3b): resolves the caller's governance-segment set
// in-process (resolveSegmentsForPolicy, segment_policy_gate.go) BEFORE
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

	segmentIDs, segOK := resolveSegmentsForPolicy(ctx, req.User.OrgID, req.User.Email)
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
		RiskScore:        0.0,
		RequiredActions:  []string{},
		// Signal B (#3239 round 2): true only when a resolved, non-empty
		// segment set is actually in scope for this verdict — see
		// PolicyEvaluationResult.SegmentsResolved's doc.
		SegmentsResolved: len(segmentIDs) > 0,
	}

	// Apply policies based on tenant/client
	tenantID := ""
	if req.Client.TenantID != "" {
		tenantID = req.Client.TenantID
	}
	if tenantID == "" && req.User.TenantID != "" {
		tenantID = req.User.TenantID
	}

	// Check for tenant-specific policies
	for cacheKey, policy := range policies {
		policyMap, ok := policy.(map[string]interface{})
		if !ok {
			continue
		}

		// Use the policy name from the data (cache key may be policy_id)
		name, _ := policyMap["name"].(string)
		if name == "" {
			name = cacheKey
		}

		// Check if policy applies to this tenant AND resolved segment set.
		// Shared choke point with ListActivePoliciesForTenant — see
		// dbCachedPolicyAppliesToTenant.
		if !dbCachedPolicyAppliesToTenant(policyMap, tenantID, segmentIDs, cacheKey) {
			continue
		}

		// CRITICAL: Evaluate conditions BEFORE applying actions
		// Parse conditions from policy
		var conditions []map[string]interface{}
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
			for _, c := range condRaw {
				if cm, ok := c.(map[string]interface{}); ok {
					conditions = append(conditions, cm)
				}
			}
		}

		// If policy has conditions, ALL must match (AND logic)
		if len(conditions) > 0 {
			allMatch := true
			for _, cond := range conditions {
				condResult := e.evaluateCondition(cond, req)
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
		// iterate against. The in-memory DynamicPolicyEngine already populates
		// AppliedPoliciesDetail at this point; the DB-backed engine must
		// match, or WCP-path overrides never flip deny -> allow.
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
				if add, ok := actionConfig["add"].(float64); ok {
					result.RiskScore += add
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

	// Record metrics
	// v9 Phase 8 PR-C2 (#2384): policy_metrics RLS gates this per-eval row by
	// org_id. tenantID is the orgID at this writer (Phase-6 schema collapse).
	// The goroutine runs independent of the eval txn so it owns its own wrap
	// — falling back to 'system' sentinel when tenantID is empty (no real
	// request scope on cache-warmup path). The data column tenant_id keeps
	// its original (possibly empty) value to preserve eval-row provenance;
	// org_id is what RLS checks and uses the resolved orgScope.
	//
	// The 2-second timeout bounds the wrap tx so shutdown doesn't dangle on a
	// stuck metric INSERT — pre-PR-C2 the bare Exec inherited the request's
	// context-or-Background; the wrap's BeginTx now ties up a connection until
	// timeout, hence the explicit ctx scope.
	go func() {
		orgScope := tenantID
		if orgScope == "" {
			orgScope = "system"
		}
		bgCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		wrapErr := agent.WithOrgScope(bgCtx, e.metricsDB, orgScope, func(tx *sql.Tx) error {
			_, err := tx.ExecContext(bgCtx, `
				INSERT INTO policy_metrics (policy_name, execution_time_ms, success, tenant_id, org_id)
				VALUES ('evaluation', $1, $2, $3, $4)
			`, int(time.Since(startTime).Milliseconds()), result.Allowed, tenantID, orgScope)
			return err
		})
		err := wrapErr

		if err != nil {
			log.Printf("Failed to record policy metrics: %v", err)
		}
	}()

	result.ProcessingTimeMs = int64(time.Since(startTime).Milliseconds())

	log.Printf("Policy evaluation completed in %v. Applied %d policies. Cache age: %v",
		time.Since(startTime), len(result.AppliedPolicies), time.Since(lastRefresh))

	return result
}

// evaluateCondition checks if a single condition matches the request.
// Supports operators: equals, not_equals, contains, not_contains, contains_any, regex, greater_than, less_than, in, not_in
func (e *DatabaseDynamicPolicyEngine) evaluateCondition(cond map[string]interface{}, req OrchestratorRequest) bool {
	field, _ := cond["field"].(string)
	operator, _ := cond["operator"].(string)
	value := cond["value"]

	// Get the field value from the request
	fieldValue := e.getFieldValue(field, req)

	switch operator {
	case "equals":
		return fmt.Sprintf("%v", fieldValue) == fmt.Sprintf("%v", value)

	case "not_equals":
		return fmt.Sprintf("%v", fieldValue) != fmt.Sprintf("%v", value)

	case "contains":
		fieldStr, ok := fieldValue.(string)
		if !ok {
			fieldStr = fmt.Sprintf("%v", fieldValue)
		}
		valueStr, ok := value.(string)
		if !ok {
			valueStr = fmt.Sprintf("%v", value)
		}
		return strings.Contains(strings.ToLower(fieldStr), strings.ToLower(valueStr))

	case "not_contains":
		fieldStr, ok := fieldValue.(string)
		if !ok {
			fieldStr = fmt.Sprintf("%v", fieldValue)
		}
		valueStr, ok := value.(string)
		if !ok {
			valueStr = fmt.Sprintf("%v", value)
		}
		return !strings.Contains(strings.ToLower(fieldStr), strings.ToLower(valueStr))

	case "contains_any":
		fieldStr, ok := fieldValue.(string)
		if !ok {
			fieldStr = fmt.Sprintf("%v", fieldValue)
		}
		fieldLower := strings.ToLower(fieldStr)
		// Value should be an array of strings
		switch v := value.(type) {
		case []interface{}:
			for _, item := range v {
				if itemStr, ok := item.(string); ok {
					if strings.Contains(fieldLower, strings.ToLower(itemStr)) {
						return true
					}
				}
			}
		case []string:
			for _, item := range v {
				if strings.Contains(fieldLower, strings.ToLower(item)) {
					return true
				}
			}
		}
		return false

	case "regex":
		fieldStr, ok := fieldValue.(string)
		if !ok {
			fieldStr = fmt.Sprintf("%v", fieldValue)
		}
		pattern, ok := value.(string)
		if !ok {
			return false
		}
		matched, err := regexp.MatchString(pattern, fieldStr)
		if err != nil {
			log.Printf("[POLICY_EVAL] Regex error for pattern %s: %v", pattern, err)
			return false
		}
		return matched

	case "greater_than":
		fieldFloat := e.toFloat64(fieldValue)
		valueFloat := e.toFloat64(value)
		return fieldFloat > valueFloat

	case "less_than":
		fieldFloat := e.toFloat64(fieldValue)
		valueFloat := e.toFloat64(value)
		return fieldFloat < valueFloat

	case "in":
		fieldStr := fmt.Sprintf("%v", fieldValue)
		switch v := value.(type) {
		case []interface{}:
			for _, item := range v {
				if fmt.Sprintf("%v", item) == fieldStr {
					return true
				}
			}
		case []string:
			for _, item := range v {
				if item == fieldStr {
					return true
				}
			}
		}
		return false

	case "not_in":
		fieldStr := fmt.Sprintf("%v", fieldValue)
		switch v := value.(type) {
		case []interface{}:
			for _, item := range v {
				if fmt.Sprintf("%v", item) == fieldStr {
					return false
				}
			}
		case []string:
			for _, item := range v {
				if item == fieldStr {
					return false
				}
			}
		}
		return true

	default:
		log.Printf("[POLICY_EVAL] Unknown operator: %s", operator)
		return false
	}
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
// plane. The binding lives at the HANDLER, not here, so the in-memory sibling
// engine (dynamic_policy_engine.go getFieldValue) is covered by the same fix.
//
// Consequence for a new case: a `user.*` field is only as trustworthy as the
// channel the handler binds it from. Adding one whose value still comes from the
// body re-opens this issue.
func (e *DatabaseDynamicPolicyEngine) getFieldValue(field string, req OrchestratorRequest) interface{} {
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
		if req.Context != nil {
			if rs, ok := req.Context["risk_score"].(float64); ok {
				return rs
			}
		}
		return 0.0

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

// toFloat64 converts various types to float64 for numeric comparisons
func (e *DatabaseDynamicPolicyEngine) toFloat64(v interface{}) float64 {
	switch val := v.(type) {
	case float64:
		return val
	case float32:
		return float64(val)
	case int:
		return float64(val)
	case int64:
		return float64(val)
	case string:
		f, _ := strconv.ParseFloat(val, 64)
		return f
	default:
		return 0
	}
}

// dbCachedPolicyAppliesToTenant decides whether one cached policy applies to
// one tenant AND (ADR-060 #2989 P3b) one resolved segment set. It is the
// SINGLE choke point for that decision on this engine: both
// EvaluateDynamicPolicies (enforcement) and ListActivePoliciesForTenant
// (disclosure) call it, so list and enforce cannot diverge by construction —
// not by two predicates that merely look alike. P3b folds the segment test
// INSIDE this existing choke point rather than adding a second, parallel
// predicate (#3070 was rejected for exactly that; #3059 established the
// single-choke-point-per-engine rule this preserves).
//
// The tenant half is shape-aware over one legitimate shape:
//
//   - _metadata PRESENT: tenant_id must be "global", "default" (the NULL
//     tenant_id sentinel assigned in refreshPolicies, and the same sentinel
//     loadDefaultPolicies assigns its fallback entry) or an exact match. A
//     present-but-EMPTY tenant_id therefore applies to NOBODY.
//   - _metadata ABSENT: every writer of the cache — refreshPolicies AND
//     loadDefaultPolicies — populates _metadata, so this shape is not a
//     valid cache state; it can only occur if a future writer forgets to
//     set it. Rather than silently applying such a policy to every tenant
//     (a fail-OPEN bug that would have shipped as "it just works"), this
//     function treats it as a defect and fails CLOSED: the entry is
//     excluded from both enforcement and disclosure, and a [BUG] line is
//     logged so the missing writer gets fixed instead of quietly relied on.
//
// DynamicPolicy.TenantID cannot express the present-but-empty-tenant vs.
// legitimately-global distinction — it is "" for both — which is why the
// scoped list works over the raw cache entries and not over the converted
// structs.
//
// The segment half (ADR-060 Decision 2, additive/orthogonal to tenant, same
// shape as the in-memory engine's memPolicyAppliesToTenant): an empty/absent
// segment_id means "not segment-scoped" and passes UNCONDITIONALLY once the
// tenant test above has already passed — this is what makes an org with zero
// segment-scoped policies byte-identical to pre-P3b behavior. A non-empty
// segment_id additionally requires it to be present in callerSegments;
// nil/empty callerSegments therefore excludes every segment-scoped policy
// (the fail-closed caller contract lives one layer up, in
// resolveSegmentsForPolicy).
//
// cacheKey identifies the entry for the [BUG] log line only (e.g. the
// policy_id/name the caller's loop is already keyed on); it plays no role
// in the tenant/segment decision itself.
func dbCachedPolicyAppliesToTenant(policyMap map[string]interface{}, tenantID string, callerSegments []string, cacheKey string) bool {
	metadata, ok := policyMap["_metadata"].(map[string]interface{})
	if !ok {
		// Every writer (refreshPolicies, loadDefaultPolicies) must populate
		// _metadata. Reaching here means one didn't — fail closed (exclude)
		// rather than silently applying the policy to every tenant.
		log.Printf("[BUG] dbCachedPolicyAppliesToTenant: cache entry %q has no _metadata — excluding (fail-closed); every writer (refreshPolicies, loadDefaultPolicies) must populate _metadata", cacheKey)
		return false
	}
	policyTenant, _ := metadata["tenant_id"].(string)
	// "global" and "default" (NULL tenant_id) apply to all tenants.
	if policyTenant != "global" && policyTenant != "default" && policyTenant != tenantID {
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
func cachedPolicyToDynamicPolicy(cacheKey string, policyMap map[string]interface{}) DynamicPolicy {
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

	// Extract conditions from stored JSON
	if conditionsRaw, ok := policyMap["conditions"].(json.RawMessage); ok {
		var conditions []PolicyCondition
		if err := json.Unmarshal(conditionsRaw, &conditions); err == nil {
			dp.Conditions = conditions
		}
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

	return dp
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
		policies = append(policies, cachedPolicyToDynamicPolicy(cacheKey, policyMap))
	}
	return policies
}

// ListActivePoliciesForTenant returns the active policies visible to a single
// tenant. It walks the RAW cache entries — not the converted structs — and
// gates each one through dbCachedPolicyAppliesToTenant, the very function
// EvaluateDynamicPolicies uses to decide enforcement. Same input, same
// function, same answer: a policy is listed to a tenant if and only if it is
// enforced for that tenant.
//
// Walking the raw entries is load-bearing. DynamicPolicy.TenantID is "" both
// for a policy whose _metadata carries an empty tenant_id (enforced for
// NOBODY) and for a policy with no _metadata at all (a defect, excluded —
// see dbCachedPolicyAppliesToTenant); filtering the converted structs would
// collapse those meanings.
//
// This is the ONLY list variant HTTP handlers may consume.
// segmentIDs (ADR-060 #2989 P3b) mirrors the in-memory engine's
// ListActivePoliciesForTenant parameter of the same name — see that
// function's doc for why today's callers all pass nil.
func (e *DatabaseDynamicPolicyEngine) ListActivePoliciesForTenant(tenantID string, segmentIDs []string) []DynamicPolicy {
	e.mu.RLock()
	defer e.mu.RUnlock()

	scoped := make([]DynamicPolicy, 0, len(e.policies))
	for cacheKey, policy := range e.policies {
		policyMap, ok := policy.(map[string]interface{})
		if !ok {
			continue
		}
		if !dbCachedPolicyAppliesToTenant(policyMap, tenantID, segmentIDs, cacheKey) {
			continue
		}
		scoped = append(scoped, cachedPolicyToDynamicPolicy(cacheKey, policyMap))
	}
	return scoped
}

func (e *DatabaseDynamicPolicyEngine) IsHealthy() bool {
	// Check if DB connection is alive
	if e.db == nil {
		return false
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if err := e.db.PingContext(ctx); err != nil {
		log.Printf("Database health check failed: %v", err)
		return false
	}

	// Check if cache is fresh (not older than 5 minutes)
	e.mu.RLock()
	cacheAge := time.Since(e.lastRefresh)
	policyCount := len(e.policies)
	e.mu.RUnlock()

	if cacheAge > 5*time.Minute {
		log.Printf("Policy cache is stale: %v old", cacheAge)
		return false
	}

	if policyCount == 0 {
		log.Printf("No policies loaded")
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
	if e.refreshDB != nil && e.refreshDB != e.db {
		_ = e.refreshDB.Close()
	}
	if e.db != nil {
		_ = e.db.Close()
	}
	if e.metricsDB != nil {
		_ = e.metricsDB.Close()
	}
	return nil
}
