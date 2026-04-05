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
	stopCh       chan struct{}
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
		stopCh:       make(chan struct{}),
	}

	// Tables created by migration 010_policy_tables.sql
	// Seed default data (system media policies, sample policies if empty)
	if err := engine.seedDefaultData(); err != nil {
		log.Printf("Warning: Failed to seed default data: %v", err)
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

func (e *DatabaseDynamicPolicyEngine) seedDefaultData() error {
	// Seed system media policies (idempotent — ON CONFLICT DO NOTHING)
	if err := e.seedSystemMediaPolicies(); err != nil {
		log.Printf("Warning: Failed to seed system media policies: %v", err)
	}

	// Insert sample policies if table is empty
	var count int
	err := e.db.QueryRow("SELECT COUNT(*) FROM dynamic_policies").Scan(&count)
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

	for _, p := range policies {
		_, err := e.db.Exec(`
			INSERT INTO dynamic_policies (
				policy_id, name, description, policy_type, category, tier,
				conditions, actions, tenant_id, priority, enabled,
				version, created_by, updated_by, created_at, updated_at
			) VALUES ($1, $2, $3, 'media', $4, 'system', $5::jsonb, $6::jsonb, 'global', $7, true, 1, 'system', 'system', NOW(), NOW())
			ON CONFLICT (policy_id) DO NOTHING
		`, p.policyID, p.name, p.description, p.category, p.conditions, p.actions, p.priority)

		if err != nil {
			return fmt.Errorf("failed to seed system media policy %s: %w", p.policyID, err)
		}
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
		SELECT name, conditions, actions, tenant_id, priority, policy_id,
		       COALESCE(policy_type, 'content') as policy_type,
		       COALESCE(category, '') as category
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
		var name, conditionsJSON, actionsJSON, policyID, policyType, category string
		var tenantID sql.NullString
		var priority int

		err := rows.Scan(&name, &conditionsJSON, &actionsJSON, &tenantID, &priority, &policyID, &policyType, &category)
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
			"type":       policyType,
			"category":   category,
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

		// Check if policy applies to this tenant
		metadata, ok := policyMap["_metadata"].(map[string]interface{})
		if ok {
			policyTenant, _ := metadata["tenant_id"].(string)
			// "global" and "default" (NULL tenant_id) apply to all tenants
			if policyTenant != "global" && policyTenant != "default" && policyTenant != tenantID {
				continue
			}
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
				log.Printf("[POLICY] Require approval action applied - step will need human approval")
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
	if e.stopCh != nil {
		select {
		case <-e.stopCh:
			// already closed
		default:
			close(e.stopCh)
		}
	}
	if e.db != nil {
		_ = e.db.Close()
	}
	if e.metricsDB != nil {
		_ = e.metricsDB.Close()
	}
	return nil
}