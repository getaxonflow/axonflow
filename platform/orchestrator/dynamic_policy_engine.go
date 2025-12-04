// Copyright 2025 AxonFlow
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

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

	_ "github.com/lib/pq"
)

// DynamicPolicyEngine evaluates policies based on request content and context
type DynamicPolicyEngine struct {
	db             *sql.DB
	policies       []DynamicPolicy
	policyMutex    sync.RWMutex
	riskCalculator *RiskCalculator
	cache          *PolicyCache
	lastDBRefresh  time.Time
	dbAvailable    bool
}

// DynamicPolicy represents a runtime policy that can be evaluated
type DynamicPolicy struct {
	ID          string              `json:"id"`
	Name        string              `json:"name"`
	Description string              `json:"description"`
	Type        string              `json:"type"` // "content", "user", "risk", "cost"
	Conditions  []PolicyCondition   `json:"conditions"`
	Actions     []PolicyAction      `json:"actions"`
	Priority    int                 `json:"priority"`
	Enabled     bool                `json:"enabled"`
	TenantID    string              `json:"tenant_id,omitempty"`
	CreatedAt   time.Time           `json:"created_at"`
	UpdatedAt   time.Time           `json:"updated_at"`
}

// PolicyCondition defines when a policy should trigger
type PolicyCondition struct {
	Field    string      `json:"field"`    // "query", "user.role", "risk_score", etc.
	Operator string      `json:"operator"` // "contains", "equals", "greater_than", etc.
	Value    interface{} `json:"value"`
}

// PolicyAction defines what happens when a policy triggers
type PolicyAction struct {
	Type   string                 `json:"type"` // "block", "redact", "alert", "log"
	Config map[string]interface{} `json:"config"`
}

// RiskCalculator calculates risk scores for requests
type RiskCalculator struct {
	sensitivePatterns []*regexp.Regexp
	riskWeights       map[string]float64
}

// PolicyCache caches policy evaluation results
type PolicyCache struct {
	cache sync.Map
	ttl   time.Duration
}

// NewDynamicPolicyEngine creates a new dynamic policy engine
func NewDynamicPolicyEngine() *DynamicPolicyEngine {
	engine := &DynamicPolicyEngine{
		policies:       loadDefaultDynamicPolicies(),
		riskCalculator: NewRiskCalculator(),
		cache:          NewPolicyCache(5 * time.Minute),
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
	}
}

// getApplicablePolicies returns policies that should be evaluated for this request
func (e *DynamicPolicyEngine) getApplicablePolicies(req OrchestratorRequest) []DynamicPolicy {
	var applicable []DynamicPolicy
	
	for _, policy := range e.policies {
		if !policy.Enabled {
			continue
		}
		
		// Check tenant-specific policies
		if policy.TenantID != "" && policy.TenantID != req.User.TenantID {
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
		var tenantID sql.NullString

		if err := rows.Scan(
			&policy.ID,
			&policy.ID, // Use policy_id as ID for now
			&policy.Name,
			&policy.Description,
			&policy.Type,
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

		// Parse conditions and actions
		if err := json.Unmarshal(conditionsJSON, &policy.Conditions); err != nil {
			log.Printf("Error parsing conditions for policy %s: %v", policy.ID, err)
			continue
		}

		if err := json.Unmarshal(actionsJSON, &policy.Actions); err != nil {
			log.Printf("Error parsing actions for policy %s: %v", policy.ID, err)
			continue
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
func (e *DynamicPolicyEngine) reloadPoliciesRoutine() {
	ticker := time.NewTicker(30 * time.Second) // More frequent for dynamic policies
	defer ticker.Stop()

	for range ticker.C {
		if e.dbAvailable {
			if err := e.loadPoliciesFromDB(); err != nil {
				log.Printf("Failed to reload dynamic policies from DB: %v", err)
			}
		} else {
			log.Println("Policy reload check completed (using defaults - no DB)")
		}
	}
}

// RiskCalculator implementation
func NewRiskCalculator() *RiskCalculator {
	return &RiskCalculator{
		sensitivePatterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)(password|secret|key|token)`),
			regexp.MustCompile(`(?i)(drop\s+table|delete\s+from|truncate)`),
			regexp.MustCompile(`(?i)(union\s+select|or\s+1=1)`),
		},
		riskWeights: map[string]float64{
			"sql_injection":    0.9,
			"sensitive_data":   0.7,
			"large_result_set": 0.3,
			"admin_query":      0.5,
		},
	}
}

func (r *RiskCalculator) CalculateRiskScore(req OrchestratorRequest) float64 {
	score := 0.0
	
	// Check for SQL injection patterns
	for _, pattern := range r.sensitivePatterns {
		if pattern.MatchString(req.Query) {
			score += r.riskWeights["sql_injection"]
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
		ttl: ttl,
	}
	
	// Start cleanup routine
	go cache.cleanupRoutine()
	
	return cache
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
	
	for range ticker.C {
		// Simple cleanup - in production, track expiration times
		c.cache = sync.Map{}
	}
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
}