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
	"regexp"
	"time"
)

// loadDefaultPolicies loads the default security policies
func (pe *PolicyEngine) loadDefaultPolicies() {
	defaultPolicies := []SecurityPolicy{
		{
			ID:          "pii_access_control",
			Name:        "PII Access Control",
			Description: "Restrict PII access to authorized roles",
			Priority:    10,
			Enabled:     true,
			Conditions: []PolicyCondition{
				{
					Type:     "query_pattern",
					Operator: "matches",
					Value:    `(ssn|social.*security|credit.*card|medical.*record)`,
				},
				{
					Type:     "user_role",
					Operator: "not_equals",
					Value:    "manager",
				},
			},
			Actions: []PolicyAction{
				{
					Type: "redact",
					Parameters: map[string]interface{}{
						"redact_level": "full",
					},
				},
				{
					Type: "audit",
					Parameters: map[string]interface{}{
						"audit_level": "detailed",
					},
				},
			},
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},
		{
			ID:          "admin_table_access",
			Name:        "Administrative Table Protection",
			Description: "Block non-admin access to administrative tables",
			Priority:    20,
			Enabled:     true,
			Conditions: []PolicyCondition{
				{
					Type:     "query_pattern",
					Operator: "matches",
					Value:    `(users|audit_log|admin_|config_)`,
				},
				{
					Type:     "user_role",
					Operator: "not_equals",
					Value:    "admin",
				},
			},
			Actions: []PolicyAction{
				{
					Type: "block",
					Parameters: map[string]interface{}{
						"reason": "Administrative table access requires admin privileges",
					},
				},
				{
					Type: "alert",
					Parameters: map[string]interface{}{
						"severity": "high",
						"channels": []string{"security_team", "admin"},
					},
				},
			},
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},
		{
			ID:          "bulk_data_extraction",
			Name:        "Bulk Data Extraction Prevention",
			Description: "Prevent large data extraction attempts",
			Priority:    15,
			Enabled:     true,
			Conditions: []PolicyCondition{
				{
					Type:     "query_pattern",
					Operator: "matches",
					Value:    `select.*\*.*from.*(limit\s+([5-9]\d{2,}|\d{4,})|without.*limit)`,
				},
			},
			Actions: []PolicyAction{
				{
					Type: "require_approval",
					Parameters: map[string]interface{}{
						"approvers": []string{"manager", "admin"},
						"reason":    "Large data extraction requires approval",
					},
				},
				{
					Type: "audit",
					Parameters: map[string]interface{}{
						"audit_level": "detailed",
					},
				},
			},
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},
		{
			ID:          "after_hours_access",
			Name:        "After Hours Data Access",
			Description: "Restrict sensitive data access during non-business hours",
			Priority:    12,
			Enabled:     true,
			Conditions: []PolicyCondition{
				{
					Type:     "time_window",
					Operator: "not_in",
					Value:    "business_hours", // 9 AM - 6 PM Mon-Fri
				},
				{
					Type:     "data_type",
					Operator: "equals",
					Value:    "pii",
				},
				{
					Type:     "user_role",
					Operator: "equals",
					Value:    "agent",
				},
			},
			Actions: []PolicyAction{
				{
					Type: "require_approval",
					Parameters: map[string]interface{}{
						"approvers": []string{"manager"},
						"reason":    "After-hours PII access requires manager approval",
					},
				},
				{
					Type: "alert",
					Parameters: map[string]interface{}{
						"severity": "medium",
						"channels": []string{"security_team"},
					},
				},
			},
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},
		{
			ID:          "cross_region_access",
			Name:        "Cross-Region Data Access",
			Description: "Monitor and control cross-region data access",
			Priority:    14,
			Enabled:     true,
			Conditions: []PolicyCondition{
				{
					Type:     "query_pattern",
					Operator: "matches",
					Value:    `region\s*[!=<>]+\s*['"]?(us-west|us-east|eu-west|eu-central)['"]?`,
				},
				{
					Type:     "user_department",
					Operator: "not_equals",
					Value:    "compliance",
				},
			},
			Actions: []PolicyAction{
				{
					Type: "audit",
					Parameters: map[string]interface{}{
						"audit_level": "detailed",
						"flag":        "cross_region_access",
					},
				},
				{
					Type: "alert",
					Parameters: map[string]interface{}{
						"severity": "low",
						"channels": []string{"compliance_team"},
					},
				},
			},
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},
	}
	
	pe.policies = defaultPolicies
}

// loadDefaultDLPRules loads the default data loss prevention rules
func (pe *PolicyEngine) loadDefaultDLPRules() {
	defaultDLPRules := []DLPRule{
		{
			ID:          "ssn_detection",
			Name:        "Social Security Number",
			Description: "Detects US Social Security Numbers",
			Pattern:     regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`),
			PatternStr:  `\b\d{3}-\d{2}-\d{4}\b`,
			DataType:    "ssn",
			Severity:    "high",
			RedactWith:  "[REDACTED_SSN]",
			Enabled:     true,
		},
		{
			ID:          "credit_card_detection",
			Name:        "Credit Card Number",
			Description: "Detects credit card numbers",
			Pattern:     regexp.MustCompile(`\b(?:\d{4}[-\s]?){3}\d{4}\b`),
			PatternStr:  `\b(?:\d{4}[-\s]?){3}\d{4}\b`,
			DataType:    "credit_card",
			Severity:    "high",
			RedactWith:  "[REDACTED_CARD]",
			Enabled:     true,
		},
		{
			ID:          "phone_detection",
			Name:        "Phone Number",
			Description: "Detects US phone numbers",
			Pattern:     regexp.MustCompile(`\b\d{3}[-.]?\d{3}[-.]?\d{4}\b`),
			PatternStr:  `\b\d{3}[-.]?\d{3}[-.]?\d{4}\b`,
			DataType:    "phone",
			Severity:    "medium",
			RedactWith:  "[REDACTED_PHONE]",
			Enabled:     true,
		},
		{
			ID:          "email_detection",
			Name:        "Email Address",
			Description: "Detects email addresses",
			Pattern:     regexp.MustCompile(`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b`),
			PatternStr:  `\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b`,
			DataType:    "email",
			Severity:    "low",
			RedactWith:  "[REDACTED_EMAIL]",
			Enabled:     true,
		},
		{
			ID:          "api_key_detection",
			Name:        "API Key",
			Description: "Detects common API key patterns",
			Pattern:     regexp.MustCompile(`\b(sk-[a-zA-Z0-9]{32,}|AIza[0-9A-Za-z-_]{35}|ya29\.[0-9A-Za-z\-_]+)\b`),
			PatternStr:  `\b(sk-[a-zA-Z0-9]{32,}|AIza[0-9A-Za-z-_]{35}|ya29\.[0-9A-Za-z\-_]+)\b`,
			DataType:    "api_key",
			Severity:    "critical",
			RedactWith:  "[REDACTED_API_KEY]",
			Enabled:     true,
		},
		{
			ID:          "medical_record_detection",
			Name:        "Medical Record Number",
			Description: "Detects medical record numbers",
			Pattern:     regexp.MustCompile(`\b(MRN|MR|MEDICAL)[-_\s]*\#?\s*[A-Z0-9]{6,12}\b`),
			PatternStr:  `\b(MRN|MR|MEDICAL)[-_\s]*\#?\s*[A-Z0-9]{6,12}\b`,
			DataType:    "medical_record",
			Severity:    "high",
			RedactWith:  "[REDACTED_MEDICAL]",
			Enabled:     true,
		},
		{
			ID:          "bank_account_detection",
			Name:        "Bank Account Number",
			Description: "Detects bank account numbers",
			Pattern:     regexp.MustCompile(`\b(account|acct)[-_\s]*\#?\s*[0-9]{6,17}\b`),
			PatternStr:  `\b(account|acct)[-_\s]*\#?\s*[0-9]{6,17}\b`,
			DataType:    "bank_account",
			Severity:    "high",
			RedactWith:  "[REDACTED_ACCOUNT]",
			Enabled:     true,
		},
		{
			ID:          "ip_address_detection",
			Name:        "IP Address",
			Description: "Detects IPv4 addresses",
			Pattern:     regexp.MustCompile(`\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`),
			PatternStr:  `\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b`,
			DataType:    "ip_address",
			Severity:    "low",
			RedactWith:  "[REDACTED_IP]",
			Enabled:     true,
		},
	}
	
	pe.dlpRules = defaultDLPRules
}

// loadDefaultBlockedQueries loads the default blocked query patterns
func (pe *PolicyEngine) loadDefaultBlockedQueries() {
	defaultBlockedQueries := []BlockedQueryRule{
		{
			ID:         "drop_table_prevention",
			Name:       "DROP TABLE Prevention",
			Pattern:    regexp.MustCompile(`drop\s+table`),
			PatternStr: `drop\s+table`,
			Reason:     "DROP TABLE operations are not allowed through the API",
			Severity:   "critical",
			Enabled:    true,
		},
		{
			ID:         "truncate_prevention",
			Name:       "TRUNCATE Prevention",
			Pattern:    regexp.MustCompile(`truncate\s+table`),
			PatternStr: `truncate\s+table`,
			Reason:     "TRUNCATE operations are not allowed through the API",
			Severity:   "critical",
			Enabled:    true,
		},
		{
			ID:         "delete_all_prevention",
			Name:       "DELETE ALL Prevention",
			Pattern:    regexp.MustCompile(`delete\s+from\s+\w+\s*(?:;|$)`),
			PatternStr: `delete\s+from\s+\w+\s*(?:;|$)`,
			Reason:     "DELETE operations without WHERE clause are not allowed",
			Severity:   "high",
			Enabled:    true,
		},
		{
			ID:         "alter_table_prevention",
			Name:       "ALTER TABLE Prevention",
			Pattern:    regexp.MustCompile(`alter\s+table`),
			PatternStr: `alter\s+table`,
			Reason:     "Schema modifications are not allowed through the API",
			Severity:   "high",
			Enabled:    true,
		},
		{
			ID:         "create_user_prevention",
			Name:       "CREATE USER Prevention",
			Pattern:    regexp.MustCompile(`create\s+user`),
			PatternStr: `create\s+user`,
			Reason:     "User creation is not allowed through the API",
			Severity:   "high",
			Enabled:    true,
		},
		{
			ID:         "grant_revoke_prevention",
			Name:       "GRANT/REVOKE Prevention",
			Pattern:    regexp.MustCompile(`(grant|revoke)\s`),
			PatternStr: `(grant|revoke)\s`,
			Reason:     "Permission changes are not allowed through the API",
			Severity:   "high",
			Enabled:    true,
		},
		{
			ID:         "information_schema_restriction",
			Name:       "Information Schema Access",
			Pattern:    regexp.MustCompile(`information_schema|pg_catalog|mysql\.user`),
			PatternStr: `information_schema|pg_catalog|mysql\.user`,
			Reason:     "System schema access is restricted",
			Severity:   "medium",
			Enabled:    true,
		},
		{
			ID:         "sql_injection_prevention",
			Name:       "SQL Injection Prevention",
			Pattern:    regexp.MustCompile(`(\bor\b|\band\b).*['"]\s*[=<>]|union\s+select|exec\s*\(|sp_executesql`),
			PatternStr: `(\bor\b|\band\b).*['"]\s*[=<>]|union\s+select|exec\s*\(|sp_executesql`,
			Reason:     "Potential SQL injection attempt detected",
			Severity:   "critical",
			Enabled:    true,
		},
		{
			ID:         "admin_bypass_attempt",
			Name:       "Admin Bypass Attempt",
			Pattern:    regexp.MustCompile(`admin['"]\s*or\s*['"]\s*1\s*=\s*1|role\s*=\s*['"]\s*admin`),
			PatternStr: `admin['"]\s*or\s*['"]\s*1\s*=\s*1|role\s*=\s*['"]\s*admin`,
			Reason:     "Potential privilege escalation attempt",
			Severity:   "critical",
			Enabled:    true,
		},
		{
			ID:         "bulk_extraction_prevention",
			Name:       "Bulk Data Extraction",
			Pattern:    regexp.MustCompile(`select\s+\*\s+from\s+\w+\s+limit\s+([5-9]\d{2,}|\d{4,})`),
			PatternStr: `select\s+\*\s+from\s+\w+\s+limit\s+([5-9]\d{2,}|\d{4,})`,
			Reason:     "Large data extraction attempts require approval",
			Severity:   "medium",
			Enabled:    true,
		},
	}
	
	pe.blockedQueries = defaultBlockedQueries
}