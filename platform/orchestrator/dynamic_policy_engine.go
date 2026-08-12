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
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"axonflow/platform/agent"
	"axonflow/platform/agent/sqli"
	sharedidentity "axonflow/platform/shared/identity"

	_ "github.com/lib/pq"
)

// DynamicPolicyEngine evaluates policies based on request content and context.
// It supports both in-memory and database-backed policy storage with automatic
// refresh. The engine calculates risk scores and can block, redact, or alert
// based on policy conditions.
//
// Key features:
//   - Risk scoring based on query patterns and user context
//   - Tenant-specific policy support for multi-tenancy
//   - Caching for performance (5-minute TTL by default)
//   - Automatic policy reload from database every 30 seconds
//
// Thread Safety: DynamicPolicyEngine is safe for concurrent use.
type DynamicPolicyEngine struct {
	db *sql.DB
	// refreshDB serves the ALL-tenants policy reload (loadPoliciesFromDB) —
	// a deliberate cross-org read that must run on the BYPASSRLS
	// platform-admin pool under axonflow_app_role (#3048; mirrors
	// DatabaseDynamicPolicyEngine.refreshDB / #3039). Falls back to db when
	// unset (tests, non-app-role deployments where db sees everything).
	refreshDB      *sql.DB
	policies       []DynamicPolicy
	policyMutex    sync.RWMutex
	riskCalculator *RiskCalculator
	cache          *PolicyCache
	lastDBRefresh  time.Time
	dbAvailable    bool
	stopCh         chan struct{}
}

// DynamicPolicy represents a runtime policy that can be evaluated against
// incoming requests. Policies are stored in the dynamic_policies database
// table and can be created, updated, and deleted via the Policy Management API.
//
// Policy evaluation is performed in priority order (highest first).
// All conditions must match for a policy to trigger (AND logic).
type DynamicPolicy struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Type        string            `json:"type"` // "content", "user", "risk", "cost", "media"
	Category    string            `json:"category,omitempty"`
	Conditions  []PolicyCondition `json:"conditions"`
	Actions     []PolicyAction    `json:"actions"`
	Priority    int               `json:"priority"`
	Enabled     bool              `json:"enabled"`
	TenantID    string            `json:"tenant_id,omitempty"`
	// SegmentID (ADR-060 #2989 P3b) is the stable scim_groups.id this policy
	// is scoped to, or "" when the policy is not segment-scoped (the
	// overwhelming majority — every pre-P3b policy, and every org that never
	// authors a segment-scoped policy). Orthogonal to TenantID, mirroring
	// migration 159 / static_policies.SegmentID (P3): a policy can be
	// tenant-scoped, segment-scoped, both, or neither. Empty string (not a
	// pointer) matches this engine's existing TenantID convention.
	SegmentID     string    `json:"segment_id,omitempty"`
	RiskLevel     string    `json:"risk_level,omitempty"` // low|medium|high|critical (ADR-044). Default "medium".
	AllowOverride bool      `json:"allow_override"`       // Session override allowed? Forced false for critical risk (ADR-044).
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// IsOverridable returns true if the policy's deny decision can be overridden
// by an active session override. Critical-risk policies cannot be overridden
// regardless of the AllowOverride flag (ADR-044 invariant).
func (p *DynamicPolicy) IsOverridable() bool {
	if p.RiskLevel == "critical" {
		return false
	}
	return p.AllowOverride
}

// PolicyCondition defines when a policy should trigger.
//
// Supported operators:
//   - contains: Field value contains the specified string (case-insensitive)
//   - equals: Field value exactly matches the specified value
//   - not_equals: Field value does not match the specified value
//   - greater_than: Numeric field is greater than the specified value
//   - less_than: Numeric field is less than the specified value
//   - regex: Field value matches the specified regular expression
//   - in: Field value is in the specified list
//
// Supported fields:
//   - query: The raw query text
//   - request_type: Type of request
//   - user.role, user.email, user.tenant_id: User context
//   - client.id, client.name: Client context
//   - risk_score: Calculated risk score (0.0-1.0)
//   - context.<key>: Custom context values
type PolicyCondition struct {
	Field    string      `json:"field"`    // "query", "user.role", "risk_score", etc.
	Operator string      `json:"operator"` // "contains", "equals", "greater_than", etc.
	Value    interface{} `json:"value"`
}

// PolicyAction defines what happens when a policy triggers.
//
// Supported action types:
//   - block: Deny the request (Config: {"reason": "string"})
//   - redact: Mark fields for redaction (Config: {"fields": ["field1", "field2"]})
//   - alert: Send alert to monitoring (Config varies by alerting system)
//   - log: Enhanced logging for the request
//   - modify_risk: Adjust the risk score (Config: {"modifier": 1.5})
type PolicyAction struct {
	Type   string                 `json:"type"` // "block", "redact", "alert", "log"
	Config map[string]interface{} `json:"config"`
}

// RiskCalculator calculates risk scores for requests based on query patterns
// and user context. Scores range from 0.0 (no risk) to 1.0 (maximum risk).
//
// Risk factors:
//   - SQL injection patterns: +0.9 (uses unified sqli package for detection)
//   - Sensitive data keywords: +0.7
//   - Admin role: +0.5
//   - SELECT * queries: +0.3
type RiskCalculator struct {
	sqliScanner       sqli.Scanner     // Unified SQL injection scanner from sqli package
	sensitivePatterns []*regexp.Regexp // Non-SQLi sensitive data patterns (passwords, secrets)
	riskWeights       map[string]float64
	detectionConfig   agent.DetectionConfig // Unified detection configuration (Issue #891)
}

// PolicyCache caches policy evaluation results to improve performance.
// Cache entries expire based on TTL and are periodically cleaned up.
//
// The cache is a single process-global structure shared by every tenant in the
// deployment, so the ONLY thing keeping one tenant's verdict away from another
// is the key — see verdictCacheKey.
type PolicyCache struct {
	cache  sync.Map
	ttl    time.Duration
	stopCh chan struct{}
}

// verdictCacheKey identifies one cached policy verdict.
//
// #3142. This is a STRUCT rather than a formatted string, and PolicyCache
// accepts nothing else, for two reasons:
//
//  1. The tenancy cannot be left out. There is no accessor that takes a bare
//     request-shaped key any more, so the compiler enumerates the call sites
//     instead of a reviewer having to remember a filter. That is the same
//     shape #3078 gave the connector and LLM registries, and for the same
//     reason: "a filter someone must remember to call is the thing that
//     failed here".
//  2. Field boundaries are structural. A struct key cannot be forged by
//     embedding a delimiter in a field value, so there is no escaping scheme
//     to get right between the tenancy and the request.
//
// Before this, the key was `email:role:request_type:query[:context]` with no
// tenancy at all. `User.Email` is empty on the agent's governed forward for
// every non-per-user-token caller and `User.Role` is frequently empty too, so
// in practice it collapsed to `::<request_type>:<query>` — deployment-wide.
// Two tenants issuing the same query shared one verdict, which leaked the
// first tenant's applied_policies_detail to the second AND skipped the
// second's own blocking policies entirely.
type verdictCacheKey struct {
	// OrgID is req.User.OrgID verbatim — the field the evaluation itself
	// reads, in getTenantSpecificPolicies. Not Client.OrgID, and not a
	// normalized variant: a key that resolves tenancy differently from the
	// code that USES it can still collide across tenancies.
	//
	// logPolicyHit is deliberately NOT cited here: its first parameter is
	// named orgID but is fed req.User.TenantID at the call site, so it stamps
	// policy_metrics.org_id with a tenant id wherever the two diverge. That is
	// a pre-existing defect of the #2964 class, filed as #3180, and this key
	// must not be argued from it.
	//
	// Note that Client.OrgID is carried in the Request half instead — see
	// generateCacheKey. Keeping this field equal to User.OrgID is what makes
	// "the resolver matches the writer" true; the WCP step-gate plane, which
	// populates only Client.OrgID, is covered by the Request half.
	OrgID string

	// TenantID is effectiveTenantID(req) — the exact function
	// getApplicablePolicies calls to choose which policies to evaluate. This
	// is the load-bearing coupling: the key must be derived by the same
	// resolver as the policy set it is caching the verdict of, or two requests
	// that select DIFFERENT policy sets can still land on the same key.
	// Keying on req.User.TenantID alone would do exactly that, because the
	// selector falls back to req.Client.ID when User.TenantID is empty.
	TenantID string

	// Segments (ADR-060 #2989 P3b) is the request's resolved
	// governance-segment set, normalized (deduped + sorted,
	// normalizeSegmentIDs) and joined — mirroring P3's buildCacheKey suffix
	// on the agent's TierAwarePolicyEngine (PR #3057). LOAD-BEARING (#3142):
	// getApplicablePolicies now selects a DIFFERENT policy set depending on
	// the caller's resolved segments (memPolicyAppliesToTenant folds segment
	// membership into the same choke point that selects the tenant-scoped
	// set), so two requests with the same OrgID/TenantID/Request but
	// DIFFERENT resolved segments can legitimately evaluate to different
	// applicable-policy sets and therefore different verdicts. Omitting this
	// field would let the second request's segment-scoped policies be
	// silently skipped — served the first request's cached verdict instead —
	// which is exactly the collision class this struct exists to make
	// impossible by construction (see the struct doc above).
	Segments string

	// Request is every remaining input the evaluator can read.
	Request string
}

// effectiveTenantID resolves the tenancy a request is evaluated under ON THIS
// ENGINE.
//
// Single choke point for the in-memory engine, shared by getApplicablePolicies
// (which uses it to select the policy set) and generateCacheKey (which uses it
// to key the cached verdict of that selection). Those two must not be able to
// disagree — see the TenantID field comment on verdictCacheKey.
//
// Deliberately NOT shared with DatabaseDynamicPolicyEngine, which resolves
// tenancy with the opposite precedence (Client.TenantID first, see
// db_dynamic_policies.go). Unifying the two is a behaviour change to policy
// selection, not a cache fix, and does not belong here — the same deliberate
// asymmetry memPolicyAppliesToTenant documents for the tenant predicate.
func effectiveTenantID(req OrchestratorRequest) string {
	if req.User.TenantID != "" {
		return req.User.TenantID
	}
	return req.Client.ID
}

// cloneEvaluationResult returns a deep copy of a verdict.
//
// #3142. The cache used to hand every caller the SAME pointer it stored, and
// ApplyOverrideToResult (override_enforcement.go) mutates a result in place —
// flipping Allowed from false to true and stamping OverrideID/OverrideReason.
// One tenant's ADR-044 session override was therefore written INTO the shared
// cache entry, and every later reader of that entry, in any tenancy, saw a
// verdict that had been overridden for somebody else. Copy on the way in and
// on the way out so a cached verdict is reachable only through the cache.
//
// Every slice is copied; AppliedPolicyDetail contains only value fields, so
// copying the backing array is a full copy of the elements too.
//
// EMPTY IS NOT NIL. `append([]string(nil), src...)` with zero elements returns
// nil, and EvaluateDynamicPolicies initialises AppliedPolicies and
// RequiredActions to empty non-nil slices that carry no `omitempty`. Copying
// with append would therefore have made the wire shape depend on cache state:
// `"applied_policies":[]` on a miss and `"applied_policies":null` on a hit, for
// the same request. make+copy preserves emptiness, and nil stays nil.
func copySlice[T any](src []T) []T {
	if src == nil {
		return nil
	}
	dst := make([]T, len(src))
	copy(dst, src)
	return dst
}

func cloneEvaluationResult(src *PolicyEvaluationResult) *PolicyEvaluationResult {
	if src == nil {
		return nil
	}
	dst := *src
	dst.AppliedPolicies = copySlice(src.AppliedPolicies)
	dst.RequiredActions = copySlice(src.RequiredActions)
	dst.AppliedPoliciesDetail = copySlice(src.AppliedPoliciesDetail)
	dst.AllowedProviders = copySlice(src.AllowedProviders)
	return &dst
}

// NewDynamicPolicyEngine creates a new dynamic policy engine with in-memory
// policy storage. If DATABASE_URL is set, it attempts to connect and load
// policies from PostgreSQL. Policies are automatically refreshed every 30 seconds.
//
// Example:
//
//	engine := NewDynamicPolicyEngine()
//	result := engine.EvaluateDynamicPolicies(ctx, request)
//	if !result.Allowed {
//	    return errors.New("request blocked by policy")
//	}
func NewDynamicPolicyEngine() *DynamicPolicyEngine {
	engine := &DynamicPolicyEngine{
		policies:       loadDefaultDynamicPolicies(),
		riskCalculator: NewRiskCalculator(),
		cache:          NewPolicyCache(5 * time.Minute),
		stopCh:         make(chan struct{}),
	}

	// Try to connect to database.
	// v9 Brief 11.5 / Session 20: route through agent.OpenAppRoleConnection so
	// even the in-memory fallback engine's optional DB pool honors
	// AXONFLOW_DB_USE_APP_ROLE. Helper internally pings + asserts role — no
	// separate Ping call needed, and a Ping-vs-connect failure now collapses
	// into a single error.
	if dbURL := os.Getenv("DATABASE_URL"); dbURL != "" {
		bootCtx := context.Background()
		db, err := agent.OpenAppRoleConnection(bootCtx, dbURL, 3)
		if err == nil {
			engine.db = db
			engine.dbAvailable = true
			var connectedRole string
			if err := db.QueryRowContext(bootCtx, "SELECT current_user").Scan(&connectedRole); err != nil {
				log.Printf("[dynamic-policy-fallback] WARNING: failed to query current_user: %v (continuing)", err)
			}
			log.Printf("[dynamic-policy-fallback] ✅ db pool connected as current_user=%s (UseAppRoleEnabled=%v, %s=%v)",
				connectedRole, agent.UseAppRoleEnabled(), agent.EnvAppRoleURL, os.Getenv(agent.EnvAppRoleURL) != "")

			// #3048: loadPoliciesFromDB is an ALL-tenants read feeding the
			// in-memory policy set — the same cross-org class as
			// DatabaseDynamicPolicyEngine's gate-cache refresh (#3039). On
			// the app-role pool RLS filters every row and the fallback
			// engine silently enforces only the built-in defaults. Route
			// the refresh through the BYPASSRLS platform-admin pool; the
			// production boot path already refuses to start without the
			// admin DSN under app-role (RequirePlatformAdminOrFatal in
			// initializeComponents).
			// #3159 R3: NO RequirePlatformAdminPoolOrFatal here. This engine is
			// only constructed when the database-backed engine ALREADY failed
			// to initialise, so the process is degraded by definition by the
			// time this runs; a fatal would convert a partial degradation into
			// a total outage. Same constructor-with-test-callers hazard as
			// db_dynamic_policies.go.
			adminDB, adminErr := agent.OpenPlatformAdminConnection(bootCtx, 3)
			if adminErr != nil || adminDB == nil {
				log.Printf("[dynamic-policy-fallback] ⚠️ platform-admin pool unavailable (err=%v) — policy reloads fall back to the main pool (under app-role RLS they read 0 rows)", adminErr)
			} else {
				adminDB.SetMaxOpenConns(2)
				adminDB.SetMaxIdleConns(1)
				engine.refreshDB = adminDB
			}

			// Load initial policies from DB
			if err := engine.loadPoliciesFromDB(); err != nil {
				log.Printf("Failed to load dynamic policies from DB: %v", err)
			}
		} else {
			log.Printf("Failed to connect to database: %v", err)
		}
	}

	// Start policy reload routine
	go engine.reloadPoliciesRoutine()

	return engine
}

// EvaluateDynamicPolicies evaluates all applicable policies for a request
// and returns the evaluation result. The evaluation includes:
//
//  1. Cache lookup for previously evaluated identical requests
//  2. Risk score calculation based on query patterns
//  3. Policy evaluation in priority order
//  4. Action application (block, redact, alert, etc.)
//
// The result includes whether the request is allowed, applied policies,
// risk score, and required actions (e.g., fields to redact).
//
// ADR-060 (#2989 P3b): resolves the caller's governance-segment set
// in-process (resolveSegmentsForPolicy, segment_policy_gate.go) BEFORE the
// cache lookup, fail-closed. A genuine resolution error denies the whole
// request without ever touching the cache — never cached, and never treated
// as "caller has zero segments" (that would be the exact org-only fallback
// ADR-060 §Fail-closed forbids). orgID/email come straight from
// req.User.OrgID / req.User.Email, composed above the already-resolved
// tenantscope scope (#3065) — never re-derived from a header here.
func (e *DynamicPolicyEngine) EvaluateDynamicPolicies(ctx context.Context, req OrchestratorRequest) *PolicyEvaluationResult {
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
			RequiredActions:  []string{"blocked: segment resolution failed (fail-closed, ADR-060 #2989 P3b)"},
			ProcessingTimeMs: time.Since(startTime).Milliseconds(),
		}
	}
	normSegments := normalizeSegmentIDs(segmentIDs)

	// Check cache first. The key carries the tenancy AND resolved segment set
	// this request evaluates under, so a hit cannot be another tenant's or
	// another segment-set's verdict (#3142), and the cache returns a copy, so
	// the caller cannot mutate the shared entry.
	cacheKey := e.generateCacheKey(req, normSegments)
	if cached, found := e.cache.Get(cacheKey); found {
		return cached
	}

	result := &PolicyEvaluationResult{
		Allowed:         true,
		AppliedPolicies: []string{},
		RequiredActions: []string{},
		// Signal B (#3239 round 2): true only when a resolved, non-empty
		// segment set is actually in scope for this verdict — see
		// PolicyEvaluationResult.SegmentsResolved's doc.
		SegmentsResolved: len(segmentIDs) > 0,
	}

	// Calculate risk score
	result.RiskScore = e.riskCalculator.CalculateRiskScore(req)

	// For database-backed policies, also check tenant-specific rules
	if e.dbAvailable && req.User.TenantID != "" {
		// Query tenant-specific dynamic rules (simulating DB access latency)
		tenantPolicies := e.getTenantSpecificPolicies(req.User.OrgID, req.User.TenantID)
		if len(tenantPolicies) > 0 {
			log.Printf("Evaluating %d tenant-specific policies for tenant %s", len(tenantPolicies), req.User.TenantID)
		}
	}

	// Get applicable policies. ADR-060 Decision 1 (additive
	// restriction-only): folding segment-matched policies into this SAME
	// applicable set, evaluated by the existing OR-across-matches /
	// MAX-across-matches aggregation below (Allowed goes false the moment
	// ANY matched policy blocks; RiskScore takes the max of every match), is
	// what makes segment membership able to only ADD a match — and therefore
	// only tighten the outcome — never remove one. No separate tier/segment
	// combiner is needed for that half of Decision 1 to hold; it falls out
	// of the aggregation already here, the same way P3's EvaluateAllPolicies
	// doc explains for the agent's aggregate (non-first-match) evaluator.
	// Additive-restriction-only is a property of THIS combiner only; it says
	// nothing about session overrides (ADR-044), which are a separate,
	// post-verdict, identity-keyed, audited exception applied per-policy
	// after the verdict below. See the AppliedPoliciesDetail comment where
	// AllowOverride is computed.
	e.policyMutex.RLock()
	applicablePolicies := e.getApplicablePolicies(req, normSegments)
	e.policyMutex.RUnlock()

	// Evaluate each policy
	for _, policy := range applicablePolicies {
		if e.evaluatePolicy(ctx, policy, req, result) {
			result.AppliedPolicies = append(result.AppliedPolicies, policy.Name)

			// Capture structured detail for ADR-044/ADR-043 downstream consumers.
			// Risk level defaults to "medium" if unset (migration 010 backfills).
			riskLevel := policy.RiskLevel
			if riskLevel == "" {
				riskLevel = "medium"
			}
			action := "log_only"
			if len(policy.Actions) > 0 {
				action = policy.Actions[0].Type
			}
			// ADR-060: a segment-scoped policy uses the SAME session-override
			// contract (ADR-044) as a tenant policy — overridable iff its own
			// allow_override column is true AND it is not critical-risk
			// (IsOverridable forces false for critical regardless of the
			// column). There is no segment-specific carve-out here: the
			// additive-restriction-only guarantee (Decision 1) is a property
			// of the combiner above, not of ApplyOverrideToResult, so
			// honoring a segment policy's own allow_override in a later,
			// separately-authorized, identity-keyed override does not
			// weaken it. A hard-floor segment policy (compliance) simply
			// ships with allow_override=false or risk_level=critical, which
			// createOverrideHandler already refuses to override at creation
			// time (overrides_handler.go). SegmentID is still carried on the
			// detail below purely for attribution/audit of which segment the
			// policy targeted — it is no longer read as an override-exclusion
			// signal anywhere.
			allowOverride := policy.IsOverridable()
			result.AppliedPoliciesDetail = append(result.AppliedPoliciesDetail, AppliedPolicyDetail{
				PolicyID:      policy.ID,
				PolicyName:    policy.Name,
				Description:   policy.Description,
				Action:        action,
				RiskLevel:     riskLevel,
				AllowOverride: allowOverride,
				SegmentID:     policy.SegmentID,
			})

			// Apply policy actions
			for _, action := range policy.Actions {
				e.applyPolicyAction(ctx, action, req, result)
			}

			// Log policy hit to database for analytics
			if e.dbAvailable {
				e.logPolicyHit(req.User.TenantID, policy.ID, fmt.Sprintf("%d", req.User.ID), result.Allowed)
			}
		}
	}

	result.ProcessingTimeMs = time.Since(startTime).Milliseconds()

	// Cache result
	e.cache.Set(cacheKey, result)

	return result
}

// getTenantSpecificPolicies queries database for tenant-specific policies
// scopeOrg is the caller's validated org (#3048 R3 HIGH-3); empty falls
// back to the org_id==tenant_id identity.
func (e *DynamicPolicyEngine) getTenantSpecificPolicies(scopeOrg, tenantID string) []DynamicPolicy {
	if !e.dbAvailable || e.db == nil {
		return nil
	}

	// This simulates a real DB query that would add latency
	query := `
		SELECT COUNT(*) FROM dynamic_policies
		WHERE tenant_id = $1 AND enabled = true
	`

	// #3048: org-scoped — dynamic_policies is RLS-enabled (mig 018) and the
	// bare COUNT read 0 under axonflow_app_role.
	if scopeOrg == "" {
		scopeOrg = tenantID
	}
	var count int
	err := agent.WithOrgScope(context.Background(), e.db, scopeOrg, func(tx *sql.Tx) error {
		return tx.QueryRow(query, tenantID).Scan(&count)
	})
	if err != nil {
		log.Printf("Failed to query tenant policies: %v", err)
	}

	// Return already loaded policies filtered by tenant
	e.policyMutex.RLock()
	defer e.policyMutex.RUnlock()

	var tenantPolicies []DynamicPolicy
	for _, p := range e.policies {
		if p.TenantID == tenantID {
			tenantPolicies = append(tenantPolicies, p)
		}
	}
	return tenantPolicies
}

// logPolicyHit logs policy evaluation metrics.
//
// v9 Phase 8 PR-C2 (#2384): orgID is required so the wrap can set
// app.current_org_id before INSERT — mig 018 ENABLE RLS gates policy_metrics
// on `org_id = get_current_org_id()`, and the legacy INSERT col list omitted
// the column entirely. Empty orgID (cache-warmup, system path) falls back to
// the 'system' sentinel like the per-eval metric writer in
// db_dynamic_policies.go::EvaluateDynamicPolicies.
func (e *DynamicPolicyEngine) logPolicyHit(orgID, policyID, userID string, allowed bool) {
	if !e.dbAvailable || e.db == nil {
		return
	}
	_ = userID // retained in signature for future per-user dashboards

	orgScope := orgID
	if orgScope == "" {
		orgScope = "system"
	}

	// Update metrics in database
	updateQuery := `
		INSERT INTO policy_metrics (policy_id, policy_type, hit_count, block_count, date, org_id)
		VALUES ($1, 'dynamic', 1, $2, CURRENT_DATE, $3)
		ON CONFLICT (policy_id, date) DO UPDATE SET
			hit_count = policy_metrics.hit_count + 1,
			block_count = policy_metrics.block_count + $2
	`

	blockCount := 0
	if !allowed {
		blockCount = 1
	}

	if err := agent.WithOrgScope(context.Background(), e.db, orgScope, func(tx *sql.Tx) error {
		_, execErr := tx.ExecContext(context.Background(), updateQuery, policyID, blockCount, orgScope)
		return execErr
	}); err != nil {
		log.Printf("Failed to update policy metrics: %v", err)
	}
}

// evaluatePolicy checks if a policy's conditions are met
func (e *DynamicPolicyEngine) evaluatePolicy(ctx context.Context, policy DynamicPolicy, req OrchestratorRequest, result *PolicyEvaluationResult) bool {
	// All conditions must be met (AND logic)
	for _, condition := range policy.Conditions {
		if !e.evaluateCondition(condition, req, result) {
			return false
		}
	}
	return true
}

// evaluateCondition checks if a single condition is met
func (e *DynamicPolicyEngine) evaluateCondition(condition PolicyCondition, req OrchestratorRequest, result *PolicyEvaluationResult) bool {
	fieldValue := e.getFieldValue(condition.Field, req, result)

	switch condition.Operator {
	case "contains":
		return strings.Contains(strings.ToLower(fmt.Sprint(fieldValue)), strings.ToLower(fmt.Sprint(condition.Value)))
	case "equals":
		return fmt.Sprint(fieldValue) == fmt.Sprint(condition.Value)
	case "not_equals":
		return fmt.Sprint(fieldValue) != fmt.Sprint(condition.Value)
	case "greater_than":
		return compareNumeric(fieldValue, condition.Value, ">")
	case "less_than":
		return compareNumeric(fieldValue, condition.Value, "<")
	case "regex":
		return matchRegex(fmt.Sprint(fieldValue), fmt.Sprint(condition.Value))
	case "in":
		return contains(condition.Value, fieldValue)
	default:
		log.Printf("Unknown operator: %s", condition.Operator)
		return false
	}
}

// getFieldValue extracts a field value from the request or result
func (e *DynamicPolicyEngine) getFieldValue(field string, req OrchestratorRequest, result *PolicyEvaluationResult) interface{} {
	parts := strings.Split(field, ".")

	switch parts[0] {
	case "query":
		return req.Query
	case "request_type":
		return req.RequestType
	case "user":
		if len(parts) > 1 {
			switch parts[1] {
			case "role":
				return req.User.Role
			case "email":
				return req.User.Email
			case "region":
				return req.User.Region
			case "tenant_id":
				return req.User.TenantID
			case "permissions":
				return req.User.Permissions
			}
		}
		return req.User
	case "client":
		if len(parts) > 1 {
			switch parts[1] {
			case "id":
				return req.Client.ID
			case "name":
				return req.Client.Name
			}
		}
		return req.Client
	case "risk_score":
		return result.RiskScore
	case "context":
		if len(parts) > 1 {
			key := strings.Join(parts[1:], ".")
			return req.Context[key]
		}
		return req.Context
	case "step_input", "tool_input":
		// Step/tool input fields are stored in context as "step_input.fieldName" / "tool_input.fieldName"
		// by WCPPolicyAdapter.convertToOrchestratorRequest. Allow policies to reference them
		// directly (e.g. "step_input.recipient_count") without requiring the "context." prefix.
		if len(parts) > 1 && req.Context != nil {
			key := strings.Join(parts, ".")
			return req.Context[key]
		}
		return nil
	case "step":
		// Retry-aware step fields (Issue #1673 Phase 1 + 2). Populated by
		// WCPPolicyAdapter.convertToOrchestratorRequest as "step.gate_count",
		// "step.completion_count", "step.prior_completion_status",
		// "step.prior_output_available", "step.last_decision",
		// "step.first_attempt_age_seconds", and "step.idempotency_key".
		//
		// Note: policy semantics for step.last_decision differ from the
		// response-side first-call invariant — it is empty on the first
		// gate call so policies can distinguish "no prior call" from
		// "prior allow" without a separate step.gate_count check.
		if len(parts) > 1 && req.Context != nil {
			key := strings.Join(parts, ".")
			return req.Context[key]
		}
		return nil
	case "media":
		// Media governance fields — resolved from context["media_analysis"]
		// These are populated by the media analysis pipeline before policy evaluation.
		if len(parts) > 1 && req.Context != nil {
			if analysis, ok := req.Context["media_analysis"].(map[string]interface{}); ok {
				return analysis[parts[1]]
			}
		}
		return nil
	default:
		return nil
	}
}

// applyPolicyAction applies an action when a policy triggers
func (e *DynamicPolicyEngine) applyPolicyAction(ctx context.Context, action PolicyAction, req OrchestratorRequest, result *PolicyEvaluationResult) {
	switch action.Type {
	case "block":
		result.Allowed = false
		if reason, ok := action.Config["reason"].(string); ok {
			result.RequiredActions = append(result.RequiredActions, "blocked: "+reason)
		}
	case "redact":
		result.RequiredActions = append(result.RequiredActions, "redact: "+fmt.Sprint(action.Config["fields"]))
	case "alert":
		// Send alert (implementation depends on alerting system)
		log.Printf("ALERT: Policy triggered for user %s: %v", req.User.Email, action.Config)
	case "log":
		// Enhanced logging
		log.Printf("Policy action: %v for request %s", action.Config, req.RequestID)
	case "modify_risk":
		if modifier, ok := action.Config["modifier"].(float64); ok {
			result.RiskScore *= modifier
		}
	case "route":
		// LLM routing override for compliance (GDPR, PII, cost control)
		if policyDebugEnabled() {
			log.Printf("[POLICY][DEBUG] Route action triggered")
		}
		if preferred, ok := action.Config["preferred_provider"].(string); ok && preferred != "" {
			result.PreferredProvider = preferred
			if policyDebugEnabled() {
				log.Printf("[POLICY][DEBUG] Preferred provider set: %s", preferred)
			}
		}
		if reason, ok := action.Config["reason"].(string); ok {
			result.RoutingReason = reason
		}
		// Handle allowed_providers for strict compliance
		// This ensures failover only happens within compliant providers
		if allowedRaw, ok := action.Config["allowed_providers"]; ok {
			switch v := allowedRaw.(type) {
			case []interface{}:
				for _, p := range v {
					if ps, ok := p.(string); ok {
						result.AllowedProviders = append(result.AllowedProviders, ps)
					}
				}
			case []string:
				result.AllowedProviders = append(result.AllowedProviders, v...)
			}
		}
		// If no explicit allowed_providers, build from preferred + fallback
		if len(result.AllowedProviders) == 0 {
			if result.PreferredProvider != "" {
				result.AllowedProviders = append(result.AllowedProviders, result.PreferredProvider)
			}
			if fallback, ok := action.Config["fallback_provider"].(string); ok && fallback != "" {
				result.AllowedProviders = append(result.AllowedProviders, fallback)
			}
		}
		log.Printf("[POLICY] Route action applied: preferred=%s, allowed=%v, reason=%s",
			result.PreferredProvider, result.AllowedProviders, result.RoutingReason)
	case "require_approval":
		// Trigger HITL workflow - requires human approval before continuing
		result.Allowed = false
		result.RequiredActions = append(result.RequiredActions, "require_approval")
		if reason, ok := action.Config["reason"].(string); ok {
			result.RequiredActions = append(result.RequiredActions, "approval_reason: "+reason)
		}
		// Extract and validate severity from policy action config for risk-tiered routing.
		// Keep highest severity when multiple policies match. Invalid values are ignored.
		if severity, ok := action.Config["severity"].(string); ok {
			if severity == "low" || severity == "medium" || severity == "high" || severity == "critical" {
				if result.Severity == "" || severityOrdinal(severity) > severityOrdinal(result.Severity) {
					result.Severity = severity
					// Note: applyPolicyAction doesn't have access to the policy name here.
					// The db_dynamic_policies path sets SeverityPolicyID. For the in-memory
					// engine, the severity is derived from risk score in deriveSeverityFromResult.
				}
			} else {
				log.Printf("[POLICY] Invalid severity %q in require_approval action, ignoring", severity)
			}
		}
		log.Printf("[POLICY] Require approval action applied - step will need human approval")
	}
}

// severityOrdinal returns the ordinal for severity comparison. Higher = more severe.
func severityOrdinal(s string) int {
	switch s {
	case "critical":
		return 3
	case "high":
		return 2
	case "medium":
		return 1
	case "low":
		return 0
	default:
		return -1
	}
}

// getApplicablePolicies returns policies that should be evaluated for this
// request.
//
// callerSegments (ADR-060 #2989 P3b) is the request's resolved,
// ALREADY-NORMALIZED governance-segment set — resolved once by
// EvaluateDynamicPolicies (resolveSegmentsForPolicy) and threaded through
// here so selection and the verdict cache key (generateCacheKey) agree on
// the exact same set. nil/empty is exactly pre-P3b behavior: every
// segment-scoped policy is excluded, byte-identical selection for an org
// with none.
func (e *DynamicPolicyEngine) getApplicablePolicies(req OrchestratorRequest, callerSegments []string) []DynamicPolicy {
	var applicable []DynamicPolicy

	// Determine effective tenant ID from User.TenantID or Client.ID (SDK uses
	// ClientID). Shared with the verdict cache key — see effectiveTenantID.
	callerTenant := effectiveTenantID(req)

	for _, policy := range e.policies {
		if !policy.Enabled {
			continue
		}

		// Check tenant-specific AND segment-specific applicability. Shared
		// choke point with ListActivePoliciesForTenant — see
		// memPolicyAppliesToTenant. Segment is additive/orthogonal: it
		// narrows the tenant-scoped candidate set, never widens it.
		if !memPolicyAppliesToTenant(policy.TenantID, callerTenant, policy.SegmentID, callerSegments) {
			continue
		}

		applicable = append(applicable, policy)
	}

	// Sort by priority (higher priority first)
	// Implement sorting logic here if needed

	return applicable
}

// ListActivePolicies returns all active policies.
//
// SECURITY: this is the raw, DEPLOYMENT-WIDE view of the in-memory policy
// cache — every tenant's policies, including their conditions (regex
// patterns) and owning tenant_id. The cache is deliberately cross-tenant
// (the evaluator enforces every tenant's policies in one process), but that
// view must NEVER be returned to an HTTP caller. HTTP consumers use
// ListActivePoliciesForTenant instead; this method has no HTTP-reachable
// caller and must not grow one.
func (e *DynamicPolicyEngine) ListActivePolicies() []DynamicPolicy {
	e.policyMutex.RLock()
	defer e.policyMutex.RUnlock()

	var active []DynamicPolicy
	for _, policy := range e.policies {
		if policy.Enabled {
			active = append(active, policy)
		}
	}
	return active
}

// memPolicyAppliesToTenant decides whether one in-memory policy applies to
// one tenant AND (ADR-060 #2989 P3b) one resolved segment set. It is the
// SINGLE choke point for that decision on this engine: both
// getApplicablePolicies (enforcement) and ListActivePoliciesForTenant
// (disclosure) call it, so list and enforce cannot diverge by construction —
// P3b folds the segment test INSIDE this existing choke point rather than
// adding a second, parallel predicate (#3070 was rejected for exactly that;
// #3059 established the single-choke-point-per-engine rule this preserves).
//
// The tenant rule is this engine's long-standing one, unchanged: an empty
// TenantID means "applies to every request" (community mode); anything else
// must match the caller exactly.
//
// The segment rule (ADR-060 Decision 2, additive/orthogonal to tenant): an
// empty policySegment means "not segment-scoped" and passes UNCONDITIONALLY
// regardless of callerSegments — this is what makes an org with zero
// segment-scoped policies byte-identical to pre-P3b behavior. A non-empty
// policySegment additionally requires it to be present in callerSegments —
// nil/empty callerSegments therefore excludes every segment-scoped policy
// (the fail-closed caller contract lives one layer up, in
// resolveSegmentsForPolicy: a genuine resolution error must deny the whole
// request before ever reaching here).
//
// NOTE the deliberate tenant-rule asymmetry with the database engine, which
// additionally treats "global" and "default" as apply-to-all sentinels. This
// engine does NOT, and this function must not "helpfully" add them: a policy
// this engine would not ENFORCE for a tenant must not be LISTED to that
// tenant. Each engine's list predicate mirrors its OWN enforcement predicate,
// and there is deliberately no single predicate shared across the two. The
// segment rule, by contrast, IS the same shape on both engines (empty =
// apply-to-all, non-empty = membership test) — ADR-060 Decision 2 is
// engine-agnostic even though the tenant rule is not.
func memPolicyAppliesToTenant(policyTenant, callerTenant string, policySegment string, callerSegments []string) bool {
	if policyTenant != "" && policyTenant != callerTenant {
		return false
	}
	if policySegment == "" {
		return true
	}
	return segmentSetContains(callerSegments, policySegment)
}

// ListActivePoliciesForTenant returns the active policies visible to a single
// tenant, gated by the same memPolicyAppliesToTenant that decides
// enforcement. This is the ONLY list variant HTTP handlers may consume (GET
// /api/v1/policies/dynamic used to return the whole deployment-wide cache —
// every tenant's policy names, regex conditions and owning tenant_id — to any
// authenticated tenant).
//
// segmentIDs (ADR-060 #2989 P3b) mirrors getApplicablePolicies' parameter:
// today's three callers (mcp_dynamic_policy_handler.go, run.go's
// listDynamicPoliciesHandler, PolicySimulationHandler's usage count) have no
// verified per-user email on hand to resolve real segments from, so they all
// pass nil — which conservatively excludes segment-scoped policies from
// disclosure (a strict subset of the pre-P3b list, never an over-disclosure)
// rather than guessing at an unverified identity. The parameter exists so a
// future caller that DOES carry a verified identity can list exactly what it
// would enforce, through this same choke point, without a second predicate.
func (e *DynamicPolicyEngine) ListActivePoliciesForTenant(tenantID string, segmentIDs []string) []DynamicPolicy {
	e.policyMutex.RLock()
	defer e.policyMutex.RUnlock()

	var active []DynamicPolicy
	for _, policy := range e.policies {
		if !policy.Enabled {
			continue
		}
		if !memPolicyAppliesToTenant(policy.TenantID, tenantID, policy.SegmentID, segmentIDs) {
			continue
		}
		active = append(active, policy)
	}
	return active
}

// IsHealthy checks if the policy engine is healthy
func (e *DynamicPolicyEngine) IsHealthy() bool {
	e.policyMutex.RLock()
	defer e.policyMutex.RUnlock()
	return len(e.policies) > 0
}

// generateCacheKey creates a cache key for policy evaluation.
//
// The tenancy travels in dedicated struct fields (see verdictCacheKey); this
// function's string half covers the request itself. Every field the evaluator
// can read must appear in it, because a verdict cached under a key that omits
// one of its own inputs is served to a request that would have evaluated
// differently.
//
// getFieldValue reaches query, request_type, user.{role, email, region,
// tenant_id, permissions}, client.{id, name}, risk_score and context.*.
// risk_score is derived from Query and User.Role, both present.
//
// It also reaches MORE than that named list, and the extras are the subtle
// part. Neither inner switch has a default: an unrecognised sub-field falls
// through to `return req.User` / `return req.Client` — the WHOLE struct, which
// evaluateCondition renders with fmt.Sprint. So a condition on `user.id`,
// `client.org_id` or `client.tenant_id` (all real field names on the
// database-backed engine) compares against a string containing UserContext.ID,
// ClientContext.OrgID and ClientContext.TenantID. Those three are written here
// too, or two requests differing only in one of them would share a verdict.
//
// Client.OrgID in particular is load-bearing for the WCP step-gate plane:
// wcp_policy_adapter.convertToOrchestratorRequest populates Client.OrgID and
// leaves User.OrgID empty, so the key's OrgID field — which is User.OrgID
// verbatim, matching the writer — is empty for every step gate. Carrying
// Client.OrgID in this half keeps two orgs from sharing an entry on that plane
// without making the OrgID field disagree with the code that uses it.
//
// Uses length-prefixed encoding for context values to prevent collisions
// where keys/values containing delimiters could produce identical serializations.
//
// normSegments MUST already be normalized (normalizeSegmentIDs — deduped +
// sorted) by the caller (EvaluateDynamicPolicies resolves once and passes
// the same normalized set to both this function and getApplicablePolicies) —
// see the Segments field doc on verdictCacheKey for why this field exists at
// all (#3142).
func (e *DynamicPolicyEngine) generateCacheKey(req OrchestratorRequest, normSegments []string) verdictCacheKey {
	var sb strings.Builder
	for _, part := range []string{
		req.User.Email,
		req.User.Role,
		req.User.Region,
		req.User.TenantID,
		strconv.Itoa(req.User.ID),
		strings.Join(req.User.Permissions, "\x1f"),
		req.Client.ID,
		req.Client.Name,
		req.Client.OrgID,
		req.Client.TenantID,
		req.RequestType,
		req.Query,
	} {
		// Length-prefix every part for the same reason the context entries are
		// length-prefixed: a value containing the delimiter must not be able to
		// impersonate a different split.
		fmt.Fprintf(&sb, "%d:%s|", len(part), part)
	}
	if len(req.Context) > 0 {
		// Include sorted context keys/values to ensure deterministic cache keys
		keys := make([]string, 0, len(req.Context))
		for k := range req.Context {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			v := fmt.Sprint(req.Context[k])
			// Length-prefix both key and value to prevent collisions
			fmt.Fprintf(&sb, "%d:%s=%d:%s,", len(k), k, len(v), v)
		}
	}
	return verdictCacheKey{
		OrgID:    req.User.OrgID,
		TenantID: effectiveTenantID(req),
		Segments: strings.Join(normSegments, "\x1f"),
		Request:  sb.String(),
	}
}

// loadPoliciesFromDBQueryWithSegment / loadPoliciesFromDBQueryWithoutSegment:
// two shapes of the same SELECT, split out so loadPoliciesFromDB can retry
// column-less against a not-yet-migrated dynamic_policies table — see H3
// (segment_column_probe.go's isMissingColumnError doc) for why this
// tolerance exists.
const loadPoliciesFromDBQueryWithSegment = `
	SELECT
		id::text, policy_id, name, description, policy_type,
		COALESCE(category, '') as category,
		conditions, actions, priority, enabled, tenant_id, segment_id,
		created_at, updated_at
	FROM dynamic_policies
	WHERE enabled = true
	ORDER BY priority DESC, created_at DESC
`

const loadPoliciesFromDBQueryWithoutSegment = `
	SELECT
		id::text, policy_id, name, description, policy_type,
		COALESCE(category, '') as category,
		conditions, actions, priority, enabled, tenant_id,
		created_at, updated_at
	FROM dynamic_policies
	WHERE enabled = true
	ORDER BY priority DESC, created_at DESC
`

// loadPoliciesFromDB loads dynamic policies from database
func (e *DynamicPolicyEngine) loadPoliciesFromDB() error {
	if !e.dbAvailable || e.db == nil {
		return fmt.Errorf("database not available")
	}

	// ALL-tenants read — runs on the BYPASSRLS refresh pool (see refreshDB
	// field comment, #3048). On the app-role pool this SELECT silently
	// returns 0 rows and the fallback engine enforces only built-ins.
	pool := e.db
	if e.refreshDB != nil {
		pool = e.refreshDB
	}
	hasSegmentColumn := true
	rows, err := pool.Query(loadPoliciesFromDBQueryWithSegment)
	if err != nil {
		if !isMissingColumnError(err, "segment_id") {
			return fmt.Errorf("failed to query dynamic policies: %v", err)
		}
		// H3 (#3239 round 2): booted against a dynamic_policies table that
		// predates migration 159 — retry segment-less. Correct pre-159: no
		// segment_id rows can exist yet, so this keeps enforcement live and
		// segment-unaware instead of failing the load outright (which would
		// otherwise fall back to loadDefaultDynamicPolicies-only coverage).
		log.Printf("[Policy] ADR-060 (#2989 P3b): dynamic_policies.segment_id not found (pre-migration-159) — loading segment-less until the column is migrated")
		hasSegmentColumn = false
		rows, err = pool.Query(loadPoliciesFromDBQueryWithoutSegment)
		if err != nil {
			return fmt.Errorf("failed to query dynamic policies (segment-less retry): %v", err)
		}
	}
	defer func() { _ = rows.Close() }()

	var policies []DynamicPolicy
	policiesLoaded := 0

	for rows.Next() {
		var policy DynamicPolicy
		var conditionsJSON, actionsJSON json.RawMessage
		var dbID string
		var policyID sql.NullString
		var tenantID sql.NullString
		var segmentID sql.NullString

		scanTargets := []interface{}{
			&dbID,
			&policyID,
			&policy.Name,
			&policy.Description,
			&policy.Type,
			&policy.Category,
			&conditionsJSON,
			&actionsJSON,
			&policy.Priority,
			&policy.Enabled,
			&tenantID,
		}
		if hasSegmentColumn {
			scanTargets = append(scanTargets, &segmentID)
		}
		scanTargets = append(scanTargets, &policy.CreatedAt, &policy.UpdatedAt)

		if err := rows.Scan(scanTargets...); err != nil {
			log.Printf("Error scanning dynamic policy row: %v", err)
			continue
		}

		if policyID.Valid && policyID.String != "" {
			policy.ID = policyID.String
		} else {
			policy.ID = dbID
		}

		// Parse conditions and actions
		if err := json.Unmarshal(conditionsJSON, &policy.Conditions); err != nil {
			log.Printf("Error parsing conditions for policy %s: %v", policy.ID, err)
			continue
		}

		if err := json.Unmarshal(actionsJSON, &policy.Actions); err != nil {
			log.Printf("Error parsing actions for policy %s: %v", policy.ID, err)
			continue
		}
		if policyDebugEnabled() {
			// DEBUG: Log loaded actions for route policies
			for _, action := range policy.Actions {
				if action.Type == "route" {
					log.Printf("[POLICY][DEBUG] Loaded route policy: %s, action_type=%s, config=%v",
						policy.Name, action.Type, action.Config)
				}
			}
		}

		if tenantID.Valid {
			policy.TenantID = tenantID.String
		}
		if segmentID.Valid {
			policy.SegmentID = segmentID.String
		}

		policies = append(policies, policy)
		policiesLoaded++
	}

	if err := rows.Err(); err != nil {
		return fmt.Errorf("error iterating dynamic policies: %v", err)
	}

	// Also keep default policies for fallback
	defaultPolicies := loadDefaultDynamicPolicies()
	policies = append(policies, defaultPolicies...)

	// Update policies atomically
	e.policyMutex.Lock()
	e.policies = policies
	e.lastDBRefresh = time.Now()
	e.policyMutex.Unlock()

	if policyDebugEnabled() {
		log.Printf("[POLICY][DEBUG] Loaded %d policies from DB (marker to verify build)", policiesLoaded)
	}
	log.Printf("Loaded %d dynamic policies from database (+ %d defaults)", policiesLoaded, len(defaultPolicies))

	// Log audit event
	e.logAuditEvent("dynamic_policy_refresh", fmt.Sprintf("Loaded %d policies", policiesLoaded))

	return nil
}

// logAuditEvent logs audit events to database
func (e *DynamicPolicyEngine) logAuditEvent(action, details string) {
	if !e.dbAvailable || e.db == nil {
		return
	}

	// orchestrator_audit_logs schema (migration 011) has `service_id`,
	// not `client_id`. The hardcoded literal "orchestrator" is the
	// service identity for the orchestrator process, matching the
	// column's intent. Pre-fix the code wrote to a non-existent
	// `client_id` column, producing silent "Failed to log audit event:
	// pq: column \"client_id\" of relation \"orchestrator_audit_logs\"
	// does not exist" errors on every dynamic-policy decision and zero
	// rows landing in the table.
	// v9 Phase 8 PR-C2 (#2384): orchestrator_audit_logs is mig 018 ENABLE RLS
	// with policy `org_id = get_current_org_id()`. logAuditEvent fires from
	// process-level workers (policy refresh, etc.) with no per-request scope,
	// so use the 'system' sentinel for both the GUC and the org_id column —
	// same shape as system-health metric writes.
	insertQuery := `
		INSERT INTO orchestrator_audit_logs (service_id, action, resource, timestamp, org_id)
		VALUES ($1, $2, $3, $4, 'system')
	`

	if err := agent.WithOrgScope(context.Background(), e.db, "system", func(tx *sql.Tx) error {
		_, execErr := tx.ExecContext(context.Background(), insertQuery, "orchestrator", action, details, time.Now())
		return execErr
	}); err != nil {
		log.Printf("Failed to log audit event: %v", err)
	}
}

// reloadPoliciesRoutine periodically reloads policies from storage
// Close stops background goroutines and releases resources.
func (e *DynamicPolicyEngine) Close() {
	select {
	case <-e.stopCh:
		// already closed
	default:
		close(e.stopCh)
	}
	if e.cache != nil {
		e.cache.Close()
	}
	if e.db != nil {
		_ = e.db.Close()
	}
}

func (e *DynamicPolicyEngine) reloadPoliciesRoutine() {
	ticker := time.NewTicker(30 * time.Second) // More frequent for dynamic policies
	defer ticker.Stop()

	for {
		select {
		case <-e.stopCh:
			return
		case <-ticker.C:
			if e.dbAvailable {
				if err := e.loadPoliciesFromDB(); err != nil {
					log.Printf("Failed to reload dynamic policies from DB: %v", err)
				}
			} else {
				log.Println("Policy reload check completed (using defaults - no DB)")
			}
		}
	}
}

// RefreshPolicies triggers an immediate policy refresh from the database.
// This is useful when policies are created/updated/deleted via the API and
// you need the changes to be available immediately without waiting for
// the background refresh cycle (default 30 seconds).
// Issue #1082: Used by WCP HITL integration for immediate policy availability.
func (e *DynamicPolicyEngine) RefreshPolicies() error {
	if !e.dbAvailable {
		return fmt.Errorf("database not available")
	}
	return e.loadPoliciesFromDB()
}

// RiskCalculator implementation
func NewRiskCalculator() *RiskCalculator {
	// Load unified detection configuration from environment (Issue #891)
	detectionCfg := agent.DetectionConfigFromEnv()

	return &RiskCalculator{
		// Use unified sqli package for SQL injection detection
		// This provides 35+ patterns with category-based severity classification
		// and consistent detection across input and response scanning
		sqliScanner: sqli.NewBasicScanner(),
		// Sensitive data patterns (non-SQLi) for risk calculation
		// TODO: Issue #891 - migrate these to database for customization
		sensitivePatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)(password|secret|key|token)`),
		},
		riskWeights: map[string]float64{
			"sql_injection":    0.9,
			"sensitive_data":   0.7,
			"large_result_set": 0.3,
			"admin_query":      0.5,
		},
		detectionConfig: detectionCfg,
	}
}

func (r *RiskCalculator) CalculateRiskScore(req OrchestratorRequest) float64 {
	score := 0.0

	// Check for SQL injection patterns using unified sqli scanner
	// This provides consistent detection with the agent and MCP response scanning
	sqliResult := r.sqliScanner.Scan(context.Background(), req.Query, sqli.ScanTypeInput)
	if sqliResult.Detected {
		score += r.riskWeights["sql_injection"]
	}

	// Check for sensitive data keywords (non-SQLi patterns)
	for _, pattern := range r.sensitivePatterns {
		if pattern.MatchString(req.Query) {
			score += r.riskWeights["sensitive_data"]
		}
	}

	// Check user role. #3001: routed through the shared role predicate rather
	// than a literal `== "admin"`, which excluded `owner` — so an owner, a
	// strict SUPERSET of admin since #2993, scored LOWER risk than an admin
	// for the identical query. Same inversion as the response-plane bypass,
	// in the risk engine.
	if sharedidentity.RoleIsAdministrative(req.User.Role) {
		score += r.riskWeights["admin_query"]
	}

	// Check query type
	if strings.Contains(strings.ToLower(req.Query), "select *") {
		score += r.riskWeights["large_result_set"]
	}

	// Normalize score to 0-1 range
	if score > 1.0 {
		score = 1.0
	}

	return score
}

// PolicyCache implementation
func NewPolicyCache(ttl time.Duration) *PolicyCache {
	cache := &PolicyCache{
		ttl:    ttl,
		stopCh: make(chan struct{}),
	}

	// Start cleanup routine
	go cache.cleanupRoutine()

	return cache
}

// Close stops the background cleanup goroutine.
func (c *PolicyCache) Close() {
	select {
	case <-c.stopCh:
		// already closed
	default:
		close(c.stopCh)
	}
}

// Get returns a copy of the verdict cached under key, if any.
//
// The parameter is a verdictCacheKey, not a string: the tenancy is part of the
// type, so there is no way to look up a verdict without naming the tenancy it
// was computed under (#3142). The return type is concrete for the same reason
// the key is — the caller no longer performs an unchecked type assertion on an
// interface{} that used to be the only thing standing between this cache and a
// panic.
//
// The returned value is a deep copy. Callers mutate verdicts in place
// (ApplyOverrideToResult), and the cached entry must not be reachable from
// anything a caller holds.
func (c *PolicyCache) Get(key verdictCacheKey) (*PolicyEvaluationResult, bool) {
	v, ok := c.cache.Load(key)
	if !ok {
		return nil, false
	}
	result, ok := v.(*PolicyEvaluationResult)
	if !ok {
		return nil, false
	}
	return cloneEvaluationResult(result), true
}

// Set stores a copy of value under key. Copying on the way in matters as much
// as copying on the way out: the caller keeps the original and goes on to hand
// it to the override enforcer, which mutates it.
func (c *PolicyCache) Set(key verdictCacheKey, value *PolicyEvaluationResult) {
	c.cache.Store(key, cloneEvaluationResult(value))
}

func (c *PolicyCache) cleanupRoutine() {
	ticker := time.NewTicker(c.ttl)
	defer ticker.Stop()

	for {
		select {
		case <-c.stopCh:
			return
		case <-ticker.C:
			// Simple cleanup - in production, track expiration times
			c.cache.Range(func(key, _ interface{}) bool {
				c.cache.Delete(key)
				return true
			})
		}
	}
}

func policyDebugEnabled() bool {
	return strings.EqualFold(os.Getenv("AXONFLOW_DEBUG_POLICIES"), "true")
}

// Utility functions
func compareNumeric(a, b interface{}, operator string) bool {
	aFloat, aOk := toFloat64(a)
	bFloat, bOk := toFloat64(b)

	if !aOk || !bOk {
		return false
	}

	switch operator {
	case ">":
		return aFloat > bFloat
	case "<":
		return aFloat < bFloat
	case ">=":
		return aFloat >= bFloat
	case "<=":
		return aFloat <= bFloat
	default:
		return false
	}
}

func toFloat64(v interface{}) (float64, bool) {
	switch val := v.(type) {
	case float64:
		return val, true
	case float32:
		return float64(val), true
	case int:
		return float64(val), true
	case int64:
		return float64(val), true
	default:
		return 0, false
	}
}

func matchRegex(text, pattern string) bool {
	matched, err := regexp.MatchString(pattern, text)
	if err != nil {
		log.Printf("Regex error: %v", err)
		return false
	}
	return matched
}

func contains(slice interface{}, item interface{}) bool {
	switch s := slice.(type) {
	case []string:
		for _, v := range s {
			if v == fmt.Sprint(item) {
				return true
			}
		}
	case []interface{}:
		for _, v := range s {
			if fmt.Sprint(v) == fmt.Sprint(item) {
				return true
			}
		}
	}
	return false
} // Build marker: 1767635481
