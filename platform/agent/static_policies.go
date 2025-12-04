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
	"fmt"
	"regexp"
	"strings"
	"time"
)

// StaticPolicyEngine handles fast, rule-based policy enforcement
// These are policies that can be evaluated quickly without external context
type StaticPolicyEngine struct {
	sqlInjectionPatterns  []*PolicyPattern
	dangerousQueryPatterns []*PolicyPattern
	adminAccessPatterns   []*PolicyPattern
	piiPatterns           []*PolicyPattern // PII detection (passports, credit cards, etc.)
}

// PolicyPattern represents a static policy rule
type PolicyPattern struct {
	ID          string
	Name        string
	Pattern     *regexp.Regexp
	PatternStr  string
	Severity    string // "low", "medium", "high", "critical"
	Description string
	Enabled     bool
}

// StaticPolicyResult contains the result of static policy evaluation
type StaticPolicyResult struct {
	Blocked            bool
	Reason             string
	TriggeredPolicies  []string
	ChecksPerformed    []string
	ProcessingTimeMs   int64
	Severity           string
}

// NewStaticPolicyEngine creates a new static policy engine with default rules
func NewStaticPolicyEngine() *StaticPolicyEngine {
	engine := &StaticPolicyEngine{}
	engine.loadDefaultPolicies()
	return engine
}

// EvaluateStaticPolicies evaluates a query against all static policies
func (spe *StaticPolicyEngine) EvaluateStaticPolicies(user *User, query string, requestType string) *StaticPolicyResult {
	startTime := time.Now()
	
	result := &StaticPolicyResult{
		Blocked:           false,
		TriggeredPolicies: []string{},
		ChecksPerformed:   []string{},
	}
	
	queryLower := strings.ToLower(strings.TrimSpace(query))
	
	// 1. SQL Injection Detection (Critical - Always block)
	if blockedPattern := spe.checkPatterns(queryLower, spe.sqlInjectionPatterns); blockedPattern != nil {
		result.Blocked = true
		result.Reason = fmt.Sprintf("SQL injection attempt detected: %s", blockedPattern.Description)
		result.TriggeredPolicies = append(result.TriggeredPolicies, blockedPattern.ID)
		result.Severity = "critical"
		result.ChecksPerformed = append(result.ChecksPerformed, "sql_injection")
		result.ProcessingTimeMs = time.Since(startTime).Nanoseconds() / 1000000
		return result
	}
	result.ChecksPerformed = append(result.ChecksPerformed, "sql_injection")
	
	// 2. Dangerous Query Detection (Critical - Always block)
	if blockedPattern := spe.checkPatterns(queryLower, spe.dangerousQueryPatterns); blockedPattern != nil {
		result.Blocked = true
		result.Reason = fmt.Sprintf("Dangerous query detected: %s", blockedPattern.Description)
		result.TriggeredPolicies = append(result.TriggeredPolicies, blockedPattern.ID)
		result.Severity = "critical"
		result.ChecksPerformed = append(result.ChecksPerformed, "dangerous_queries")
		result.ProcessingTimeMs = time.Since(startTime).Nanoseconds() / 1000000
		return result
	}
	result.ChecksPerformed = append(result.ChecksPerformed, "dangerous_queries")
	
	// 3. Admin Access Control (High - Block based on user role)
	if !spe.hasPermission(user, "admin") {
		if blockedPattern := spe.checkPatterns(queryLower, spe.adminAccessPatterns); blockedPattern != nil {
			result.Blocked = true
			result.Reason = fmt.Sprintf("Administrative access required: %s", blockedPattern.Description)
			result.TriggeredPolicies = append(result.TriggeredPolicies, blockedPattern.ID)
			result.Severity = "high"
			result.ChecksPerformed = append(result.ChecksPerformed, "admin_access")
			result.ProcessingTimeMs = time.Since(startTime).Nanoseconds() / 1000000
			return result
		}
	}
	result.ChecksPerformed = append(result.ChecksPerformed, "admin_access")
	
	// 4. Request Type Validation
	if !spe.isValidRequestType(requestType) {
		result.Blocked = true
		result.Reason = "Invalid request type"
		result.Severity = "medium"
		result.ChecksPerformed = append(result.ChecksPerformed, "request_type")
		result.ProcessingTimeMs = time.Since(startTime).Nanoseconds() / 1000000
		return result
	}
	result.ChecksPerformed = append(result.ChecksPerformed, "request_type")
	
	// 5. Basic Query Validation
	if strings.TrimSpace(query) == "" {
		result.Blocked = true
		result.Reason = "Empty query not allowed"
		result.Severity = "low"
		result.ProcessingTimeMs = time.Since(startTime).Nanoseconds() / 1000000
		return result
	}
	result.ChecksPerformed = append(result.ChecksPerformed, "basic_validation")

	// 6. PII Detection (High - Log and flag for redaction, don't block)
	// For travel/planning requests, detect PII but allow processing with redaction
	if piiPattern := spe.checkPatterns(query, spe.piiPatterns); piiPattern != nil {
		// Don't block for PII - just log and trigger redaction in Orchestrator
		result.TriggeredPolicies = append(result.TriggeredPolicies, piiPattern.ID)
		// Note: For severity "critical" PII (credit cards, SSNs), could optionally block
		// For now, we allow with redaction for better UX in travel planning
	}
	result.ChecksPerformed = append(result.ChecksPerformed, "pii_detection")

	result.ProcessingTimeMs = time.Since(startTime).Nanoseconds() / 1000000
	return result
}

// checkPatterns checks if query matches any pattern in the given list
func (spe *StaticPolicyEngine) checkPatterns(query string, patterns []*PolicyPattern) *PolicyPattern {
	for _, pattern := range patterns {
		if !pattern.Enabled {
			continue
		}
		
		if pattern.Pattern.MatchString(query) {
			return pattern
		}
	}
	return nil
}

// hasPermission checks if user has a specific permission
func (spe *StaticPolicyEngine) hasPermission(user *User, permission string) bool {
	for _, perm := range user.Permissions {
		if perm == permission {
			return true
		}
	}
	return false
}

// isValidRequestType validates the request type
func (spe *StaticPolicyEngine) isValidRequestType(requestType string) bool {
	validTypes := []string{"sql", "llm_chat", "rag_search", "test", "multi-agent-plan", "chat", "completion", "embedding"}
	for _, validType := range validTypes {
		if requestType == validType {
			return true
		}
	}
	return false
}

// loadDefaultPolicies initializes the static policy engine with default rules
func (spe *StaticPolicyEngine) loadDefaultPolicies() {
	// SQL Injection Patterns (Critical)
	spe.sqlInjectionPatterns = []*PolicyPattern{
		{
			ID:          "sql_injection_union",
			Name:        "SQL Injection - UNION Attack",
			Pattern:     regexp.MustCompile(`union\s+select`),
			PatternStr:  `union\s+select`,
			Severity:    "critical",
			Description: "UNION-based SQL injection attempt",
			Enabled:     true,
		},
		{
			ID:          "sql_injection_or_condition",
			Name:        "SQL Injection - OR Condition",
			Pattern:     regexp.MustCompile(`(\bor\b|\band\b).*['"]?\s*[=<>].*['"]?\s*(or|and)\s*['"]?\s*[=<>]`),
			PatternStr:  `(\bor\b|\band\b).*['"]?\s*[=<>].*['"]?\s*(or|and)\s*['"]?\s*[=<>]`,
			Severity:    "critical",
			Description: "Boolean-based SQL injection attempt",
			Enabled:     true,
		},
		{
			ID:          "sql_injection_comment",
			Name:        "SQL Injection - Comment Bypass",
			Pattern:     regexp.MustCompile(`--|\*\/|\/\*`),
			PatternStr:  `--|\*\/|\/\*`,
			Severity:    "critical",
			Description: "SQL comment injection attempt",
			Enabled:     true,
		},
		{
			ID:          "sql_injection_always_true",
			Name:        "SQL Injection - Always True",
			Pattern:     regexp.MustCompile(`1\s*=\s*1|''\s*=\s*''|"\s*=\s*"`),
			PatternStr:  `1\s*=\s*1|''\s*=\s*''|"\s*=\s*"`,
			Severity:    "critical",
			Description: "Always-true condition injection",
			Enabled:     true,
		},
	}
	
	// Dangerous Query Patterns (Critical)
	spe.dangerousQueryPatterns = []*PolicyPattern{
		{
			ID:          "drop_table_prevention",
			Name:        "DROP TABLE Prevention",
			Pattern:     regexp.MustCompile(`drop\s+table`),
			PatternStr:  `drop\s+table`,
			Severity:    "critical",
			Description: "DROP TABLE operations are not allowed through the API",
			Enabled:     true,
		},
		{
			ID:          "drop_database_prevention",
			Name:        "DROP DATABASE Prevention", 
			Pattern:     regexp.MustCompile(`drop\s+database`),
			PatternStr:  `drop\s+database`,
			Severity:    "critical",
			Description: "DROP DATABASE operations are not allowed",
			Enabled:     true,
		},
		{
			ID:          "truncate_prevention",
			Name:        "TRUNCATE Prevention",
			Pattern:     regexp.MustCompile(`truncate\s+table`),
			PatternStr:  `truncate\s+table`,
			Severity:    "critical",
			Description: "TRUNCATE operations are not allowed through the API",
			Enabled:     true,
		},
		{
			ID:          "delete_all_prevention",
			Name:        "DELETE ALL Prevention",
			Pattern:     regexp.MustCompile(`delete\s+from\s+\w+\s*(?:;|$)`),
			PatternStr:  `delete\s+from\s+\w+\s*(?:;|$)`,
			Severity:    "high",
			Description: "DELETE operations without WHERE clause are not allowed",
			Enabled:     true,
		},
		{
			ID:          "alter_table_prevention",
			Name:        "ALTER TABLE Prevention",
			Pattern:     regexp.MustCompile(`alter\s+table`),
			PatternStr:  `alter\s+table`,
			Severity:    "high",
			Description: "Schema modifications are not allowed through the API",
			Enabled:     true,
		},
		{
			ID:          "create_user_prevention",
			Name:        "CREATE USER Prevention",
			Pattern:     regexp.MustCompile(`create\s+user`),
			PatternStr:  `create\s+user`,
			Severity:    "high",
			Description: "User creation is not allowed through the API",
			Enabled:     true,
		},
		{
			ID:          "grant_revoke_prevention", 
			Name:        "GRANT/REVOKE Prevention",
			Pattern:     regexp.MustCompile(`(grant|revoke)\s`),
			PatternStr:  `(grant|revoke)\s`,
			Severity:    "high",
			Description: "Permission changes are not allowed through the API",
			Enabled:     true,
		},
	}
	
	// Admin Access Patterns (High)
	spe.adminAccessPatterns = []*PolicyPattern{
		{
			ID:          "users_table_access",
			Name:        "Users Table Access",
			Pattern:     regexp.MustCompile(`\busers\b`),
			PatternStr:  `\busers\b`,
			Severity:    "high",
			Description: "Access to users table requires admin privileges",
			Enabled:     true,
		},
		{
			ID:          "audit_log_access",
			Name:        "Audit Log Access",
			Pattern:     regexp.MustCompile(`audit_log`),
			PatternStr:  `audit_log`,
			Severity:    "high",
			Description: "Access to audit logs requires admin privileges",
			Enabled:     true,
		},
		{
			ID:          "config_table_access",
			Name:        "Configuration Table Access",
			Pattern:     regexp.MustCompile(`config_|admin_|system_`),
			PatternStr:  `config_|admin_|system_`,
			Severity:    "high",
			Description: "Access to system configuration requires admin privileges",
			Enabled:     true,
		},
		{
			ID:          "information_schema_access",
			Name:        "Information Schema Access",
			Pattern:     regexp.MustCompile(`information_schema|pg_catalog|mysql\.user`),
			PatternStr:  `information_schema|pg_catalog|mysql\.user`,
			Severity:    "medium",
			Description: "System schema access requires admin privileges",
			Enabled:     true,
		},
	}

	// PII Patterns (High) - Travel-specific
	spe.piiPatterns = []*PolicyPattern{
		{
			ID:          "passport_number_detection",
			Name:        "Passport Number Detection",
			Pattern:     regexp.MustCompile(`\b[A-Z]{1,2}[0-9]{6,9}\b`), // Common passport format
			PatternStr:  `\b[A-Z]{1,2}[0-9]{6,9}\b`,
			Severity:    "high",
			Description: "Passport numbers detected in query - automatic redaction required",
			Enabled:     true,
		},
		{
			ID:          "credit_card_detection",
			Name:        "Credit Card Number Detection",
			Pattern:     regexp.MustCompile(`\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b`), // Visa, MC, Amex, Discover
			PatternStr:  `\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b`,
			Severity:    "critical",
			Description: "Credit card numbers detected - automatic redaction required for PCI compliance",
			Enabled:     true,
		},
		{
			ID:          "ssn_detection",
			Name:        "SSN Detection",
			Pattern:     regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`), // SSN format
			PatternStr:  `\b\d{3}-\d{2}-\d{4}\b`,
			Severity:    "critical",
			Description: "Social Security Number detected - automatic redaction required",
			Enabled:     true,
		},
		{
			ID:          "booking_reference_logging",
			Name:        "Booking Reference Logging",
			Pattern:     regexp.MustCompile(`\b[A-Z0-9]{6}\b`), // Common booking reference format
			PatternStr:  `\b[A-Z0-9]{6}\b`,
			Severity:    "low",
			Description: "Booking reference detected - logged for audit trail (not blocked)",
			Enabled:     true,
		},
	}
}

// GetPolicyStats returns statistics about loaded policies
func (spe *StaticPolicyEngine) GetPolicyStats() map[string]interface{} {
	return map[string]interface{}{
		"sql_injection_patterns":  len(spe.sqlInjectionPatterns),
		"dangerous_query_patterns": len(spe.dangerousQueryPatterns),
		"admin_access_patterns":    len(spe.adminAccessPatterns),
		"pii_patterns":             len(spe.piiPatterns),
		"total_patterns":           len(spe.sqlInjectionPatterns) + len(spe.dangerousQueryPatterns) + len(spe.adminAccessPatterns) + len(spe.piiPatterns),
	}
}