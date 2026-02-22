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
	"strings"
	"sync"
	"time"

	"axonflow/platform/agent"
	"axonflow/platform/agent/sqli"

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
	db             *sql.DB
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
	CreatedAt   time.Time         `json:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
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
type PolicyCache struct {
	cache  sync.Map
	ttl    time.Duration
	stopCh chan struct{}
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

	// Try to connect to database
	if dbURL := os.Getenv("DATABASE_URL"); dbURL != "" {
		db, err := sql.Open("postgres", dbURL)
		if err == nil {
			// Test connection
			if err := db.Ping(); err == nil {
				engine.db = db
				engine.dbAvailable = true
				log.Println("Dynamic policy engine connected to database")

				// Load initial policies from DB
				if err := engine.loadPoliciesFromDB(); err != nil {
					log.Printf("Failed to load dynamic policies from DB: %v", err)
				}
			} else {
				log.Printf("Failed to ping database: %v", err)
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
func (e *DynamicPolicyEngine) EvaluateDynamicPolicies(ctx context.Context, req OrchestratorRequest) *PolicyEvaluationResult {
	startTime := time.Now()

	// Check cache first
	cacheKey := e.generateCacheKey(req)
	if cached, found := e.cache.Get(cacheKey); found {
		return cached.(*PolicyEvaluationResult)
	}

	result := &PolicyEvaluationResult{
		Allowed:         true,
		AppliedPolicies: []string{},
		RequiredActions: []string{},
	}

	// Calculate risk score
	result.RiskScore = e.riskCalculator.CalculateRiskScore(req)

	// For database-backed policies, also check tenant-specific rules
	if e.dbAvailable && req.User.TenantID != "" {
		// Query tenant-specific dynamic rules (simulating DB access latency)
		tenantPolicies := e.getTenantSpecificPolicies(req.User.TenantID)
		if len(tenantPolicies) > 0 {
			log.Printf("Evaluating %d tenant-specific policies for tenant %s", len(tenantPolicies), req.User.TenantID)
		}
	}

	// Get applicable policies
	e.policyMutex.RLock()
	applicablePolicies := e.getApplicablePolicies(req)
	e.policyMutex.RUnlock()

	// Evaluate each policy
	for _, policy := range applicablePolicies {
		if e.evaluatePolicy(ctx, policy, req, result) {
			result.AppliedPolicies = append(result.AppliedPolicies, policy.Name)

			// Apply policy actions
			for _, action := range policy.Actions {
				e.applyPolicyAction(ctx, action, req, result)
			}

			// Log policy hit to database for analytics
			if e.dbAvailable {
				e.logPolicyHit(policy.ID, fmt.Sprintf("%d", req.User.ID), result.Allowed)
			}
		}
	}

	result.ProcessingTimeMs = time.Since(startTime).Milliseconds()

	// Cache result
	e.cache.Set(cacheKey, result)

	return result
}

// getTenantSpecificPolicies queries database for tenant-specific policies
func (e *DynamicPolicyEngine) getTenantSpecificPolicies(tenantID string) []DynamicPolicy {
	if !e.dbAvailable || e.db == nil {
		return nil
	}

	// This simulates a real DB query that would add latency
	query := `
		SELECT COUNT(*) FROM dynamic_policies
		WHERE tenant_id = $1 AND enabled = true
	`

	var count int
	err := e.db.QueryRow(query, tenantID).Scan(&count)
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

// logPolicyHit logs policy evaluation metrics
func (e *DynamicPolicyEngine) logPolicyHit(policyID, userID string, allowed bool) {
	if !e.dbAvailable || e.db == nil {
		return
	}

	// Update metrics in database
	updateQuery := `
		INSERT INTO policy_metrics (policy_id, policy_type, hit_count, block_count, date)
		VALUES ($1, 'dynamic', 1, $2, CURRENT_DATE)
		ON CONFLICT (policy_id, date) DO UPDATE SET
			hit_count = policy_metrics.hit_count + 1,
			block_count = policy_metrics.block_count + $2
	`

	blockCount := 0
	if !allowed {
		blockCount = 1
	}

	_, err := e.db.Exec(updateQuery, policyID, blockCount)
	if err != nil {
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
			return req.Context[parts[1]]
		}
		return req.Context
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
	}
}

// getApplicablePolicies returns policies that should be evaluated for this request
func (e *DynamicPolicyEngine) getApplicablePolicies(req OrchestratorRequest) []DynamicPolicy {
	var applicable []DynamicPolicy

	// Determine effective tenant ID from User.TenantID or Client.ID (SDK uses ClientID)
	effectiveTenantID := req.User.TenantID
	if effectiveTenantID == "" {
		effectiveTenantID = req.Client.ID
	}

	for _, policy := range e.policies {
		if !policy.Enabled {
			continue
		}

		// Check tenant-specific policies
		// Policies with empty TenantID apply to all requests (community mode)
		// Policies with TenantID only apply if it matches User.TenantID or Client.ID
		if policy.TenantID != "" && policy.TenantID != effectiveTenantID {
			continue
		}

		applicable = append(applicable, policy)
	}

	// Sort by priority (higher priority first)
	// Implement sorting logic here if needed

	return applicable
}

// ListActivePolicies returns all active policies
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

// IsHealthy checks if the policy engine is healthy
func (e *DynamicPolicyEngine) IsHealthy() bool {
	e.policyMutex.RLock()
	defer e.policyMutex.RUnlock()
	return len(e.policies) > 0
}

// generateCacheKey creates a cache key for policy evaluation
func (e *DynamicPolicyEngine) generateCacheKey(req OrchestratorRequest) string {
	// Simple cache key - can be improved
	return fmt.Sprintf("%s:%s:%s:%s", req.User.Email, req.User.Role, req.RequestType, req.Query)
}

// loadPoliciesFromDB loads dynamic policies from database
func (e *DynamicPolicyEngine) loadPoliciesFromDB() error {
	if !e.dbAvailable || e.db == nil {
		return fmt.Errorf("database not available")
	}

	query := `
		SELECT
			id::text, policy_id, name, description, policy_type,
			COALESCE(category, '') as category,
			conditions, actions, priority, enabled, tenant_id,
			created_at, updated_at
		FROM dynamic_policies
		WHERE enabled = true
		ORDER BY priority DESC, created_at DESC
	`

	rows, err := e.db.Query(query)
	if err != nil {
		return fmt.Errorf("failed to query dynamic policies: %v", err)
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

		if err := rows.Scan(
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
			&policy.CreatedAt,
			&policy.UpdatedAt,
		); err != nil {
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

	insertQuery := `
		INSERT INTO orchestrator_audit_logs (client_id, action, resource, timestamp)
		VALUES ($1, $2, $3, $4)
	`

	_, err := e.db.Exec(insertQuery, "orchestrator", action, details, time.Now())
	if err != nil {
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

	// Check user role
	if req.User.Role == "admin" {
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

func (c *PolicyCache) Get(key string) (interface{}, bool) {
	return c.cache.Load(key)
}

func (c *PolicyCache) Set(key string, value interface{}) {
	c.cache.Store(key, value)
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
