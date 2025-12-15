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

package main

import (
	"context"
	"fmt"
	"log"
	"regexp"
	"strings"
	"time"
)

// PolicyEngine manages data loss prevention and security policies.
// It provides three layers of protection:
//   1. Blocked Query Rules - Prevents dangerous SQL operations (DROP, TRUNCATE, etc.)
//   2. Security Policies - Enforces access control based on user roles and data sensitivity
//   3. DLP Rules - Detects and redacts PII (SSN, credit cards, phone numbers, etc.)
//
// The engine evaluates queries in this order and can block, redact, or audit based on policy.
type PolicyEngine struct {
	policies       []SecurityPolicy   // Role-based access control policies
	dlpRules       []DLPRule          // Data Loss Prevention patterns (PII detection)
	blockedQueries []BlockedQueryRule // SQL injection and dangerous query prevention
}

// SecurityPolicy defines a security policy with conditions and actions
type SecurityPolicy struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Priority    int               `json:"priority"`
	Enabled     bool              `json:"enabled"`
	Conditions  []PolicyCondition `json:"conditions"`
	Actions     []PolicyAction    `json:"actions"`
	CreatedAt   time.Time         `json:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
}

// PolicyCondition defines when a policy should trigger
type PolicyCondition struct {
	Type     string      `json:"type"`     // "user_role", "data_type", "query_pattern", "time_window"
	Operator string      `json:"operator"` // "equals", "contains", "matches", "not_in"
	Value    interface{} `json:"value"`
}

// PolicyAction defines what happens when a policy triggers
type PolicyAction struct {
	Type       string                 `json:"type"` // "block", "redact", "audit", "alert", "require_approval"
	Parameters map[string]interface{} `json:"parameters"`
}

// DLPRule defines data loss prevention rules for pattern detection
type DLPRule struct {
	ID          string         `json:"id"`
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Pattern     *regexp.Regexp `json:"-"`
	PatternStr  string         `json:"pattern"`
	DataType    string         `json:"data_type"` // "ssn", "credit_card", "medical_record", "api_key"
	Severity    string         `json:"severity"`  // "low", "medium", "high", "critical"
	RedactWith  string         `json:"redact_with"`
	Enabled     bool           `json:"enabled"`
}

// BlockedQueryRule defines queries that should be blocked
type BlockedQueryRule struct {
	ID          string         `json:"id"`
	Name        string         `json:"name"`
	Pattern     *regexp.Regexp `json:"-"`
	PatternStr  string         `json:"pattern"`
	Reason      string         `json:"reason"`
	Severity    string         `json:"severity"`
	Enabled     bool           `json:"enabled"`
}

// PolicyViolation represents a policy violation event
type PolicyViolation struct {
	ID            string                 `json:"id"`
	PolicyID      string                 `json:"policy_id"`
	UserEmail     string                 `json:"user_email"`
	ViolationType string                 `json:"violation_type"`
	Description   string                 `json:"description"`
	Severity      string                 `json:"severity"`
	Data          map[string]interface{} `json:"data"`
	Timestamp     time.Time              `json:"timestamp"`
	Resolved      bool                   `json:"resolved"`
}

// PolicyEvaluationResult contains the result of policy evaluation
type PolicyEvaluationResult struct {
	Allowed           bool              `json:"allowed"`
	BlockedBy         []string          `json:"blocked_by"`
	Violations        []PolicyViolation `json:"violations"`
	RedactionRequired bool              `json:"redaction_required"`
	ApprovalRequired  bool              `json:"approval_required"`
	ModifiedQuery     string            `json:"modified_query"`
}

// NewPolicyEngine creates a new policy engine with default rules
func NewPolicyEngine() *PolicyEngine {
	engine := &PolicyEngine{
		policies:       []SecurityPolicy{},
		dlpRules:       []DLPRule{},
		blockedQueries: []BlockedQueryRule{},
	}
	
	// Initialize with default policies
	engine.loadDefaultPolicies()
	engine.loadDefaultDLPRules()
	engine.loadDefaultBlockedQueries()
	
	return engine
}

// EvaluateQuery evaluates a query against all security policies and returns the result.
// It performs three checks in order:
//   1. Blocked Queries - Checks for dangerous SQL patterns (highest priority, immediate block)
//   2. Security Policies - Evaluates role-based access rules
//   3. DLP Rules - Scans for PII patterns that may need redaction
//
// Returns a PolicyEvaluationResult containing:
//   - Allowed: whether the query can proceed
//   - BlockedBy: list of policy IDs that blocked the query
//   - Violations: detailed violation records for audit
//   - RedactionRequired: whether PII redaction is needed
func (pe *PolicyEngine) EvaluateQuery(ctx context.Context, user User, query string, queryType string) *PolicyEvaluationResult {
	result := &PolicyEvaluationResult{
		Allowed:     true,
		BlockedBy:   []string{},
		Violations:  []PolicyViolation{},
		ModifiedQuery: query,
	}
	
	// 1. Check blocked query patterns first
	if blockedRule := pe.checkBlockedQueries(query); blockedRule != nil {
		result.Allowed = false
		result.BlockedBy = append(result.BlockedBy, blockedRule.ID)
		
		violation := PolicyViolation{
			ID:            generateViolationID(),
			PolicyID:      blockedRule.ID,
			UserEmail:     user.Email,
			ViolationType: "blocked_query",
			Description:   fmt.Sprintf("Query blocked by rule: %s", blockedRule.Reason),
			Severity:      blockedRule.Severity,
			Timestamp:     time.Now(),
			Data: map[string]interface{}{
				"query":     query,
				"rule_name": blockedRule.Name,
			},
		}
		result.Violations = append(result.Violations, violation)
		
		// Log violation
		pe.logViolation(violation)
		return result
	}
	
	// 2. Evaluate security policies
	for _, policy := range pe.policies {
		if !policy.Enabled {
			continue
		}
		
		if pe.evaluatePolicyConditions(policy, user, query, queryType) {
			// Policy triggered - execute actions
			for _, action := range policy.Actions {
				switch action.Type {
				case "block":
					result.Allowed = false
					result.BlockedBy = append(result.BlockedBy, policy.ID)
					
				case "redact":
					result.RedactionRequired = true
					
				case "require_approval":
					result.ApprovalRequired = true
					
				case "audit":
					// Enhanced audit logging will be handled by caller
					
				case "alert":
					// Send alert (implementation depends on alerting system)
					pe.sendAlert(policy, user, query)
				}
			}
			
			// Create violation record
			violation := PolicyViolation{
				ID:            generateViolationID(),
				PolicyID:      policy.ID,
				UserEmail:     user.Email,
				ViolationType: "policy_violation",
				Description:   fmt.Sprintf("Policy triggered: %s", policy.Name),
				Severity:      pe.getPolicySeverity(policy),
				Timestamp:     time.Now(),
				Data: map[string]interface{}{
					"query":       query,
					"policy_name": policy.Name,
				},
			}
			result.Violations = append(result.Violations, violation)
			pe.logViolation(violation)
		}
	}
	
	// 3. Apply DLP rules for data redaction
	dlpResults := pe.evaluateDLPRules(query, user)
	if len(dlpResults) > 0 {
		result.RedactionRequired = true
		
		for _, dlpResult := range dlpResults {
			violation := PolicyViolation{
				ID:            generateViolationID(),
				PolicyID:      dlpResult.RuleID,
				UserEmail:     user.Email,
				ViolationType: "dlp_detection",
				Description:   fmt.Sprintf("DLP rule triggered: %s", dlpResult.DataType),
				Severity:      dlpResult.Severity,
				Timestamp:     time.Now(),
				Data: map[string]interface{}{
					"query":     query,
					"data_type": dlpResult.DataType,
					"matches":   dlpResult.Matches,
				},
			}
			result.Violations = append(result.Violations, violation)
			pe.logViolation(violation)
		}
	}
	
	return result
}

// evaluatePolicyConditions checks if policy conditions are met
func (pe *PolicyEngine) evaluatePolicyConditions(policy SecurityPolicy, user User, query string, queryType string) bool {
	for _, condition := range policy.Conditions {
		if !pe.evaluateCondition(condition, user, query, queryType) {
			return false // All conditions must be true (AND logic)
		}
	}
	return len(policy.Conditions) > 0
}

// evaluateCondition evaluates a single policy condition
func (pe *PolicyEngine) evaluateCondition(condition PolicyCondition, user User, query string, queryType string) bool {
	switch condition.Type {
	case "user_role":
		return pe.matchStringCondition(user.Role, condition.Operator, condition.Value)
		
	case "user_department":
		return pe.matchStringCondition(user.Department, condition.Operator, condition.Value)
		
	case "query_pattern":
		pattern, ok := condition.Value.(string)
		if !ok {
			return false
		}
		regex, err := regexp.Compile(pattern)
		if err != nil {
			return false
		}
		return regex.MatchString(strings.ToLower(query))
		
	case "data_type":
		// Check if query accesses specific data types
		queryLower := strings.ToLower(query)
		dataType, ok := condition.Value.(string)
		if !ok {
			return false
		}
		
		switch dataType {
		case "pii":
			return pe.containsPII(query)
		case "financial":
			return strings.Contains(queryLower, "payment") || strings.Contains(queryLower, "billing")
		case "medical":
			return strings.Contains(queryLower, "medical") || strings.Contains(queryLower, "health")
		}
		
	case "time_window":
		// Check if current time is within allowed window
		// Implementation depends on time window format in condition.Value
		
	}
	
	return false
}

// matchStringCondition evaluates string matching conditions
func (pe *PolicyEngine) matchStringCondition(value string, operator string, conditionValue interface{}) bool {
	conditionStr, ok := conditionValue.(string)
	if !ok {
		return false
	}
	
	switch operator {
	case "equals":
		return value == conditionStr
	case "contains":
		return strings.Contains(strings.ToLower(value), strings.ToLower(conditionStr))
	case "not_equals":
		return value != conditionStr
	case "matches":
		regex, err := regexp.Compile(conditionStr)
		if err != nil {
			return false
		}
		return regex.MatchString(value)
	}
	
	return false
}

// checkBlockedQueries checks if query matches any blocked patterns
func (pe *PolicyEngine) checkBlockedQueries(query string) *BlockedQueryRule {
	queryLower := strings.ToLower(query)
	
	for _, rule := range pe.blockedQueries {
		if !rule.Enabled {
			continue
		}
		
		if rule.Pattern.MatchString(queryLower) {
			return &rule
		}
	}
	
	return nil
}

// DLPResult represents the result of DLP rule evaluation
type DLPResult struct {
	RuleID   string   `json:"rule_id"`
	DataType string   `json:"data_type"`
	Severity string   `json:"severity"`
	Matches  []string `json:"matches"`
}

// evaluateDLPRules applies DLP rules to detect sensitive data patterns
func (pe *PolicyEngine) evaluateDLPRules(text string, user User) []DLPResult {
	var results []DLPResult
	
	for _, rule := range pe.dlpRules {
		if !rule.Enabled {
			continue
		}
		
		matches := rule.Pattern.FindAllString(text, -1)
		if len(matches) > 0 {
			result := DLPResult{
				RuleID:   rule.ID,
				DataType: rule.DataType,
				Severity: rule.Severity,
				Matches:  matches,
			}
			results = append(results, result)
		}
	}
	
	return results
}

// containsPII checks if text contains PII patterns
func (pe *PolicyEngine) containsPII(text string) bool {
	dlpResults := pe.evaluateDLPRules(text, User{})
	return len(dlpResults) > 0
}

// RedactSensitiveData applies DLP rules to redact PII based on user permissions.
// It scans the text for sensitive patterns (SSN, credit cards, etc.) and replaces
// them with redaction tokens if the user doesn't have permission to view them.
//
// Parameters:
//   - text: The content to scan and potentially redact
//   - user: The user whose permissions determine what gets redacted
//
// Returns:
//   - redacted: The text with sensitive data replaced (e.g., "[REDACTED_SSN]")
//   - detectedTypes: List of PII types that were found (e.g., ["ssn", "credit_card"])
func (pe *PolicyEngine) RedactSensitiveData(text string, user User) (string, []string) {
	redacted := text
	var detectedTypes []string
	
	for _, rule := range pe.dlpRules {
		if !rule.Enabled {
			continue
		}
		
		matches := rule.Pattern.FindAllString(text, -1)
		if len(matches) > 0 {
			detectedTypes = append(detectedTypes, rule.DataType)
			
			// Apply redaction if user doesn't have permission to see this data type
			if !pe.canUserSeePII(user, rule.DataType) {
				redacted = rule.Pattern.ReplaceAllString(redacted, rule.RedactWith)
			}
		}
	}
	
	return redacted, detectedTypes
}

// canUserSeePII checks if user has permission to see specific PII types
func (pe *PolicyEngine) canUserSeePII(user User, dataType string) bool {
	// Check user permissions for specific data types
	switch dataType {
	case "ssn":
		return contains(user.Permissions, "read_ssn") || contains(user.Permissions, "read_pii")
	case "credit_card":
		return contains(user.Permissions, "read_financial") || contains(user.Permissions, "read_pii")
	case "medical_record":
		return contains(user.Permissions, "read_medical") || contains(user.Permissions, "admin")
	default:
		return contains(user.Permissions, "read_pii") || contains(user.Permissions, "admin")
	}
}

// Utility functions
func generateViolationID() string {
	return fmt.Sprintf("violation_%d", time.Now().UnixNano())
}

func (pe *PolicyEngine) getPolicySeverity(policy SecurityPolicy) string {
	// Determine severity based on policy actions
	for _, action := range policy.Actions {
		if action.Type == "block" {
			return "high"
		}
	}
	return "medium"
}

func (pe *PolicyEngine) logViolation(violation PolicyViolation) {
	// In production, this would write to a dedicated violations table
	log.Printf("Policy violation: %s - %s - %s", violation.ViolationType, violation.UserEmail, violation.Description)
}

func (pe *PolicyEngine) sendAlert(policy SecurityPolicy, user User, query string) {
	// In production, this would integrate with alerting systems (email, Slack, etc.)
	log.Printf("ALERT: Policy %s triggered by user %s with query: %.100s", policy.Name, user.Email, query)
}