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
	"time"
)

// loadDefaultDynamicPolicies returns the default set of dynamic policies
func loadDefaultDynamicPolicies() []DynamicPolicy {
	now := time.Now()
	
	return []DynamicPolicy{
		// High-risk query blocking
		{
			ID:          "pol_high_risk_block",
			Name:        "Block High-Risk Queries",
			Description: "Block queries with risk score above threshold",
			Type:        "risk",
			Priority:    100,
			Enabled:     true,
			Conditions: []PolicyCondition{
				{
					Field:    "risk_score",
					Operator: "greater_than",
					Value:    0.8,
				},
			},
			Actions: []PolicyAction{
				{
					Type: "block",
					Config: map[string]interface{}{
						"reason": "Query risk score exceeds safety threshold",
					},
				},
				{
					Type: "alert",
					Config: map[string]interface{}{
						"severity": "high",
						"channel":  "security",
					},
				},
			},
			CreatedAt: now,
			UpdatedAt: now,
		},
		
		// Sensitive data access control
		{
			ID:          "pol_sensitive_data_control",
			Name:        "Control Sensitive Data Access",
			Description: "Restrict access to sensitive data based on user role",
			Type:        "content",
			Priority:    90,
			Enabled:     true,
			Conditions: []PolicyCondition{
				{
					Field:    "query",
					Operator: "contains",
					Value:    "salary",
				},
				{
					Field:    "user.role",
					Operator: "not_equals",
					Value:    "admin",
				},
			},
			Actions: []PolicyAction{
				{
					Type: "redact",
					Config: map[string]interface{}{
						"fields":  []string{"salary", "compensation"},
						"pattern": "[REDACTED]",
					},
				},
				{
					Type: "log",
					Config: map[string]interface{}{
						"level": "warning",
						"message": "Non-admin attempted to access salary data",
					},
				},
			},
			CreatedAt: now,
			UpdatedAt: now,
		},
		
		// Medical data HIPAA compliance
		{
			ID:          "pol_hipaa_compliance",
			Name:        "HIPAA Compliance for Medical Data",
			Description: "Ensure medical data access complies with HIPAA",
			Type:        "content",
			Priority:    95,
			Enabled:     true,
			Conditions: []PolicyCondition{
				{
					Field:    "query",
					Operator: "regex",
					Value:    "(?i)(patient|medical|diagnosis|treatment)",
				},
				{
					Field:    "context.industry",
					Operator: "equals",
					Value:    "healthcare",
				},
			},
			Actions: []PolicyAction{
				{
					Type: "log",
					Config: map[string]interface{}{
						"audit_type": "hipaa_access",
						"retention":  "7_years",
					},
				},
				{
					Type: "redact",
					Config: map[string]interface{}{
						"fields": []string{"ssn", "patient_id", "diagnosis_details"},
						"unless_permission": "view_phi",
					},
				},
			},
			CreatedAt: now,
			UpdatedAt: now,
		},
		
		// Financial data protection
		{
			ID:          "pol_financial_data_protection",
			Name:        "Financial Data Protection",
			Description: "Protect financial data according to SOX compliance",
			Type:        "content",
			Priority:    85,
			Enabled:     true,
			Conditions: []PolicyCondition{
				{
					Field:    "query",
					Operator: "regex",
					Value:    "(?i)(account_number|routing_number|credit_card)",
				},
			},
			Actions: []PolicyAction{
				{
					Type: "redact",
					Config: map[string]interface{}{
						"fields":  []string{"account_number", "routing_number", "credit_card"},
						"pattern": "****[LAST4]",
					},
				},
				{
					Type: "log",
					Config: map[string]interface{}{
						"audit_type": "financial_access",
						"compliance": "sox",
					},
				},
			},
			CreatedAt: now,
			UpdatedAt: now,
		},
		
		// Rate limiting for expensive queries
		{
			ID:          "pol_expensive_query_limit",
			Name:        "Limit Expensive Query Access",
			Description: "Restrict access to computationally expensive queries",
			Type:        "cost",
			Priority:    70,
			Enabled:     true,
			Conditions: []PolicyCondition{
				{
					Field:    "query",
					Operator: "contains",
					Value:    "JOIN",
				},
				{
					Field:    "user.role",
					Operator: "equals",
					Value:    "basic",
				},
			},
			Actions: []PolicyAction{
				{
					Type: "modify_risk",
					Config: map[string]interface{}{
						"modifier": 1.5,
					},
				},
				{
					Type: "log",
					Config: map[string]interface{}{
						"message": "Basic user executing expensive query",
					},
				},
			},
			CreatedAt: now,
			UpdatedAt: now,
		},
		
		// GDPR compliance for EU users
		{
			ID:          "pol_gdpr_compliance",
			Name:        "GDPR Compliance for EU Users",
			Description: "Ensure GDPR compliance for EU region users",
			Type:        "user",
			Priority:    88,
			Enabled:     true,
			Conditions: []PolicyCondition{
				{
					Field:    "context.user_region",
					Operator: "in",
					Value:    []string{"eu", "europe"},
				},
				{
					Field:    "query",
					Operator: "regex",
					Value:    "(?i)(email|phone|address|name)",
				},
			},
			Actions: []PolicyAction{
				{
					Type: "log",
					Config: map[string]interface{}{
						"audit_type": "gdpr_access",
						"retention":  "3_years",
					},
				},
				{
					Type: "redact",
					Config: map[string]interface{}{
						"consent_required": true,
						"fields": []string{"email", "phone", "address"},
					},
				},
			},
			CreatedAt: now,
			UpdatedAt: now,
		},
		
		// Anomaly detection
		{
			ID:          "pol_anomaly_detection",
			Name:        "Detect Anomalous Access Patterns",
			Description: "Flag unusual query patterns for review",
			Type:        "user",
			Priority:    60,
			Enabled:     true,
			Conditions: []PolicyCondition{
				{
					Field:    "context.query_count_last_hour",
					Operator: "greater_than",
					Value:    100,
				},
			},
			Actions: []PolicyAction{
				{
					Type: "alert",
					Config: map[string]interface{}{
						"severity": "medium",
						"message":  "Unusual query volume detected",
					},
				},
				{
					Type: "modify_risk",
					Config: map[string]interface{}{
						"modifier": 1.3,
					},
				},
			},
			CreatedAt: now,
			UpdatedAt: now,
		},
		
		// Cross-tenant access prevention
		{
			ID:          "pol_tenant_isolation",
			Name:        "Enforce Tenant Isolation",
			Description: "Prevent cross-tenant data access",
			Type:        "user",
			Priority:    100,
			Enabled:     true,
			Conditions: []PolicyCondition{
				{
					Field:    "query",
					Operator: "regex",
					Value:    "tenant_id\\s*=\\s*'[^']*'",
				},
				{
					Field:    "query",
					Operator: "not_contains",
					Value:    "user.tenant_id",
				},
			},
			Actions: []PolicyAction{
				{
					Type: "block",
					Config: map[string]interface{}{
						"reason": "Cross-tenant access attempt detected",
					},
				},
				{
					Type: "alert",
					Config: map[string]interface{}{
						"severity": "critical",
						"channel":  "security",
					},
				},
			},
			CreatedAt: now,
			UpdatedAt: now,
		},
		
		// LLM cost optimization
		{
			ID:          "pol_llm_cost_optimization",
			Name:        "Optimize LLM Provider Selection",
			Description: "Route queries to cost-effective providers when appropriate",
			Type:        "cost",
			Priority:    50,
			Enabled:     true,
			Conditions: []PolicyCondition{
				{
					Field:    "request_type",
					Operator: "equals",
					Value:    "simple_query",
				},
				{
					Field:    "risk_score",
					Operator: "less_than",
					Value:    0.3,
				},
			},
			Actions: []PolicyAction{
				{
					Type: "route",
					Config: map[string]interface{}{
						"preferred_provider": "local_llm",
						"fallback_provider":  "openai",
					},
				},
			},
			CreatedAt: now,
			UpdatedAt: now,
		},
		
		// Debug mode restrictions
		{
			ID:          "pol_debug_mode_restriction",
			Name:        "Restrict Debug Mode Access",
			Description: "Limit debug mode to development environments",
			Type:        "content",
			Priority:    80,
			Enabled:     true,
			Conditions: []PolicyCondition{
				{
					Field:    "context.debug_mode",
					Operator: "equals",
					Value:    true,
				},
				{
					Field:    "context.environment",
					Operator: "not_equals",
					Value:    "development",
				},
			},
			Actions: []PolicyAction{
				{
					Type: "block",
					Config: map[string]interface{}{
						"reason": "Debug mode not allowed in production",
					},
				},
			},
			CreatedAt: now,
			UpdatedAt: now,
		},
	}
}