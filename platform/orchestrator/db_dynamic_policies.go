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
	"sync"
	"time"

	_ "github.com/lib/pq"
)

type DatabaseDynamicPolicyEngine struct {
	db           *sql.DB
	metricsDB    *sql.DB
	policies     map[string]interface{}
	mu           sync.RWMutex
	lastRefresh  time.Time
	cacheTimeout time.Duration
	refreshing   bool
	refreshMu    sync.Mutex
}

func NewDatabaseDynamicPolicyEngine() (*DatabaseDynamicPolicyEngine, error) {
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		return nil, fmt.Errorf("DATABASE_URL environment variable not set")
	}

	// Main connection pool for reads
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Configure connection pool
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)

	// Test connection
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	// Separate connection for metrics to avoid blocking
	metricsDB, err := sql.Open("postgres", dbURL)
	if err != nil {
		return nil, fmt.Errorf("failed to open metrics database: %w", err)
	}
	metricsDB.SetMaxOpenConns(5)
	metricsDB.SetMaxIdleConns(2)

	engine := &DatabaseDynamicPolicyEngine{
		db:           db,
		metricsDB:    metricsDB,
		policies:     make(map[string]interface{}),
		cacheTimeout: 30 * time.Second,
		lastRefresh:  time.Now(), // Initialize to prevent zero-time issues
	}

	// Initialize schema
	if err := engine.initializeSchema(); err != nil {
		log.Printf("Warning: Failed to initialize schema: %v", err)
	}

	// Load initial policies
	if err := engine.refreshPolicies(); err != nil {
		log.Printf("Warning: Failed to load initial policies: %v", err)
		// Continue with default policies
		engine.loadDefaultPolicies()
	}

	// Start background refresh
	go engine.backgroundRefresh()

	// Start metrics reporter
	go engine.reportMetrics()

	return engine, nil
}

func (e *DatabaseDynamicPolicyEngine) initializeSchema() error {
	schema := `
	CREATE TABLE IF NOT EXISTS dynamic_policies (
		id SERIAL PRIMARY KEY,
		policy_id VARCHAR(100) UNIQUE NOT NULL,
		name VARCHAR(255) NOT NULL,
		description TEXT,
		policy_type VARCHAR(50),
		conditions JSONB,
		actions JSONB,
		tenant_id VARCHAR(100),
		environment VARCHAR(50),
		priority INTEGER DEFAULT 0,
		enabled BOOLEAN DEFAULT true,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);

	CREATE INDEX IF NOT EXISTS idx_policies_tenant ON dynamic_policies(tenant_id);
	CREATE INDEX IF NOT EXISTS idx_policies_enabled ON dynamic_policies(enabled);
	CREATE INDEX IF NOT EXISTS idx_policies_priority ON dynamic_policies(priority DESC);

	CREATE TABLE IF NOT EXISTS policy_metrics (
		id SERIAL PRIMARY KEY,
		timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		policy_name VARCHAR(255),
		execution_time_ms INTEGER,
		success BOOLEAN,
		tenant_id VARCHAR(100)
	);

	CREATE INDEX IF NOT EXISTS idx_metrics_timestamp ON policy_metrics(timestamp DESC);
	`

	_, err := e.db.Exec(schema)
	if err != nil {
		return fmt.Errorf("failed to create schema: %w", err)
	}

	// Insert sample policies if table is empty
	var count int
	err = e.db.QueryRow("SELECT COUNT(*) FROM dynamic_policies").Scan(&count)
	if err != nil {
		return err
	}

	if count == 0 {
		return e.insertSamplePolicies()
	}

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
					"fallback_model": "gpt-3.5-turbo",
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

		_, err := e.db.Exec(`
			INSERT INTO dynamic_policies (policy_id, name, description, policy_type, conditions, actions, tenant_id, priority)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
			ON CONFLICT (policy_id) DO UPDATE SET
				conditions = EXCLUDED.conditions,
				actions = EXCLUDED.actions,
				updated_at = CURRENT_TIMESTAMP
		`, p.name, p.name, p.description, "test", string(conditions), string(actions), p.tenantID, p.priority)
		if err != nil {
			return fmt.Errorf("failed to insert policy %s: %w", p.name, err)
		}
	}

	return nil
}

func (e *DatabaseDynamicPolicyEngine) refreshPolicies() error {
	query := `
		SELECT name, conditions, actions, tenant_id, priority, policy_id
		FROM dynamic_policies
		WHERE enabled = true
		ORDER BY priority DESC, created_at DESC
	`

	rows, err := e.db.Query(query)
	if err != nil {
		return fmt.Errorf("failed to query policies: %w", err)
	}
	defer func() { _ = rows.Close() }()

	newPolicies := make(map[string]interface{})

	for rows.Next() {
		var name, conditionsJSON, actionsJSON, policyID string
		var tenantID sql.NullString
		var priority int

		err := rows.Scan(&name, &conditionsJSON, &actionsJSON, &tenantID, &priority, &policyID)
		if err != nil {
			log.Printf("Error scanning policy row: %v", err)
			continue
		}

		// Handle NULL tenant_id
		tenantIDStr := "default"
		if tenantID.Valid {
			tenantIDStr = tenantID.String
		}

		// Create policy data from conditions and actions
		policyData := map[string]interface{}{
			"policy_id":  policyID,
			"name":       name,
			"conditions": json.RawMessage(conditionsJSON),
			"actions":    json.RawMessage(actionsJSON),
			"tenant_id":  tenantIDStr,
			"priority":   priority,
		}

		// Add metadata
		policyData["_metadata"] = map[string]interface{}{
			"name":      name,
			"tenant_id": tenantIDStr,
			"priority":  priority,
			"loaded_at": time.Now().Unix(),
		}

		newPolicies[name] = policyData
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

func (e *DatabaseDynamicPolicyEngine) backgroundRefresh() {
	ticker := time.NewTicker(e.cacheTimeout)
	defer ticker.Stop()

	for range ticker.C {
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

func (e *DatabaseDynamicPolicyEngine) reportMetrics() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
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

		// Report to metrics table
		_, err := e.metricsDB.Exec(`
			INSERT INTO policy_metrics (policy_name, execution_time_ms, success, tenant_id)
			VALUES ('system_health', $1, true, 'system')
		`, timeSinceRefreshMs)

		if err != nil {
			log.Printf("Failed to report metrics: %v", err)
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

	policy, exists := e.policies[name]
	if !exists {
		return nil, false
	}

	policyMap, ok := policy.(map[string]interface{})
	if !ok {
		return nil, false
	}

	// Mark that database was accessed
	policyMap["database_accessed"] = true

	return policyMap, true
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
				"allowed_models":        []string{"gpt-3.5-turbo"},
				"rate_limit_per_minute": 60,
			},
		},
	}
}

func (e *DatabaseDynamicPolicyEngine) EvaluateDynamicPolicies(ctx context.Context, req OrchestratorRequest) *PolicyEvaluationResult {
	startTime := time.Now()

	// Get all policies from cache (refreshed in background)
	e.mu.RLock()
	policies := e.policies
	lastRefresh := e.lastRefresh
	e.mu.RUnlock()

	result := &PolicyEvaluationResult{
		Allowed:          true,
		AppliedPolicies:  []string{},
		DatabaseAccessed: true, // Mark that we're using DB-backed policies
		ProcessingTimeMs: 0, // Will be set at the end
		RiskScore:        0.0,
		RequiredActions:  []string{},
	}

	// Apply policies based on tenant/client
	tenantID := ""
	if req.Client.ID != "" {
		tenantID = req.Client.ID
	}
	if tenantID == "" && req.User.TenantID != "" {
		tenantID = req.User.TenantID
	}

	// Check for tenant-specific policies
	for name, policy := range policies {
		policyMap, ok := policy.(map[string]interface{})
		if !ok {
			continue
		}

		// Check if policy applies to this tenant
		metadata, ok := policyMap["_metadata"].(map[string]interface{})
		if ok {
			policyTenant, _ := metadata["tenant_id"].(string)
			if policyTenant != "global" && policyTenant != tenantID {
				continue
			}
		}

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

		result.AppliedPolicies = append(result.AppliedPolicies, name)
	}

	// Record metrics
	go func() {
		_, err := e.metricsDB.Exec(`
			INSERT INTO policy_metrics (policy_name, execution_time_ms, success, tenant_id)
			VALUES ('evaluation', $1, $2, $3)
		`, int(time.Since(startTime).Milliseconds()), result.Allowed, tenantID)

		if err != nil {
			log.Printf("Failed to record policy metrics: %v", err)
		}
	}()

	result.ProcessingTimeMs = int64(time.Since(startTime).Milliseconds())

	log.Printf("Policy evaluation completed in %v. Applied %d policies. Cache age: %v",
		time.Since(startTime), len(result.AppliedPolicies), time.Since(lastRefresh))

	return result
}

func (e *DatabaseDynamicPolicyEngine) ListActivePolicies() []DynamicPolicy {
	e.mu.RLock()
	defer e.mu.RUnlock()

	var policies []DynamicPolicy

	for name, policy := range e.policies {
		policyMap, ok := policy.(map[string]interface{})
		if !ok {
			continue
		}

		dp := DynamicPolicy{
			Name:     name,
			Type:     "database",
			Enabled:  true,
			Priority: 0,
		}

		// Extract metadata
		if metadata, ok := policyMap["_metadata"].(map[string]interface{}); ok {
			if priority, ok := metadata["priority"].(int); ok {
				dp.Priority = priority
			}
			if tenantID, ok := metadata["tenant_id"].(string); ok {
				dp.TenantID = tenantID
			}
		}

		// Extract conditions and actions from rules
		if rules, ok := policyMap["rules"].(map[string]interface{}); ok {
			// Convert rules to conditions for compatibility
			for k, v := range rules {
				dp.Conditions = append(dp.Conditions, PolicyCondition{
					Field:    k,
					Operator: "equals",
					Value:    v,
				})
			}
		}

		// Extract type
		if pType, ok := policyMap["type"].(string); ok {
			dp.Type = pType
		}

		policies = append(policies, dp)
	}

	return policies
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

func (e *DatabaseDynamicPolicyEngine) Close() error {
	if e.db != nil {
		_ = e.db.Close()
	}
	if e.metricsDB != nil {
		_ = e.metricsDB.Close()
	}
	return nil
}