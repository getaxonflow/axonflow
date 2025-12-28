// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

// SystemPolicySeed defines a system policy to be seeded into the database.
// These policies are immutable (tier=system) and cannot be deleted by customers.
type SystemPolicySeed struct {
	ID          string         `json:"id"`
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Category    PolicyCategory `json:"category"`
	Pattern     string         `json:"pattern"`
	Severity    PolicySeverity `json:"severity"`
	Action      string         `json:"action"`
	Priority    int            `json:"priority"`
}

// DynamicPolicySeed defines a dynamic system policy to be seeded.
type DynamicPolicySeed struct {
	ID          string         `json:"id"`
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Category    PolicyCategory `json:"category"`
	PolicyType  string         `json:"policy_type"`
	Conditions  string         `json:"conditions"` // JSON string
	Actions     string         `json:"actions"`    // JSON string
	Priority    int            `json:"priority"`
}

// GetStaticSystemPolicies returns all static system policies to be seeded.
// These are organized by category as defined in ADR-020.
//
// Categories:
// - security-sqli: SQL injection detection patterns (37 patterns)
// - security-admin: Admin access control patterns (4 patterns)
// - pii-global: Global PII patterns (7 patterns)
// - pii-us: US-specific PII patterns (2 patterns)
// - pii-eu: EU-specific PII patterns (1 pattern)
// - pii-india: India-specific PII patterns (2 patterns)
// - code-secrets: Secret detection in generated code (8 patterns) - Issue #761
// - code-unsafe: Unsafe code pattern detection (7 patterns) - Issue #761
//
// Total: 68 static system policies
func GetStaticSystemPolicies() []SystemPolicySeed {
	policies := []SystemPolicySeed{}

	// ========================================================================
	// SQL Injection Patterns (security-sqli) - 37 patterns
	// ========================================================================
	sqliPatterns := getSQLiPatterns()
	policies = append(policies, sqliPatterns...)

	// ========================================================================
	// Admin Access Patterns (security-admin) - 4 patterns
	// ========================================================================
	adminPatterns := getAdminAccessPatterns()
	policies = append(policies, adminPatterns...)

	// ========================================================================
	// PII Detection Patterns - 12 patterns
	// ========================================================================
	piiPatterns := getPIIPatterns()
	policies = append(policies, piiPatterns...)

	// ========================================================================
	// Code Governance Patterns (Issue #761) - 15 patterns
	// ========================================================================
	codePatterns := getCodeGovernancePatterns()
	policies = append(policies, codePatterns...)

	return policies
}

// getSQLiPatterns returns all SQL injection detection patterns.
// These patterns are categorized under security-sqli.
func getSQLiPatterns() []SystemPolicySeed {
	return []SystemPolicySeed{
		// UNION-based SQL injection (2 patterns)
		{
			ID:          "sys_sqli_union_select",
			Name:        "UNION SELECT Detection",
			Description: "Detects UNION SELECT statements used to extract data",
			Category:    CategorySecuritySQLi,
			Pattern:     `(?i)\bUNION\s+(ALL\s+)?SELECT\b`,
			Severity:    SeverityCritical,
			Action:      "block",
			Priority:    100,
		},
		{
			ID:          "sys_sqli_union_injection",
			Name:        "UNION Injection After Termination",
			Description: "Detects UNION injection after string termination",
			Category:    CategorySecuritySQLi,
			Pattern:     `(?i)['"\)]\s*UNION\s+(ALL\s+)?SELECT`,
			Severity:    SeverityCritical,
			Action:      "block",
			Priority:    100,
		},
		// Boolean-based blind SQL injection (3 patterns)
		{
			ID:          "sys_sqli_or_true",
			Name:        "OR True Condition",
			Description: "Detects OR with always-true numeric comparison (OR 1=1)",
			Category:    CategorySecuritySQLi,
			Pattern:     `(?i)\bOR\s+['"]?\d+['"]?\s*=\s*['"]?\d+['"]?`,
			Severity:    SeverityHigh,
			Action:      "block",
			Priority:    90,
		},
		{
			ID:          "sys_sqli_or_string",
			Name:        "OR String Condition",
			Description: "Detects OR with always-true string comparison (OR 'a'='a')",
			Category:    CategorySecuritySQLi,
			Pattern:     `(?i)\bOR\s+['"][^'"]*['"]\s*=\s*['"][^'"]*['"]\s*`,
			Severity:    SeverityHigh,
			Action:      "block",
			Priority:    90,
		},
		{
			ID:          "sys_sqli_and_false",
			Name:        "AND False Condition",
			Description: "Detects AND with numeric comparison for boolean blind",
			Category:    CategorySecuritySQLi,
			Pattern:     `(?i)\bAND\s+['"]?\d+['"]?\s*=\s*['"]?\d+['"]?`,
			Severity:    SeverityHigh,
			Action:      "block",
			Priority:    90,
		},
		// Time-based blind SQL injection (4 patterns)
		{
			ID:          "sys_sqli_sleep",
			Name:        "MySQL SLEEP Function",
			Description: "Detects MySQL SLEEP function for time-based blind injection",
			Category:    CategorySecuritySQLi,
			Pattern:     `(?i)\bSLEEP\s*\(\s*\d+\s*\)`,
			Severity:    SeverityCritical,
			Action:      "block",
			Priority:    100,
		},
		{
			ID:          "sys_sqli_waitfor",
			Name:        "SQL Server WAITFOR DELAY",
			Description: "Detects SQL Server WAITFOR DELAY for time-based blind injection",
			Category:    CategorySecuritySQLi,
			Pattern:     `(?i)\bWAITFOR\s+DELAY\s+['"][^'"]+['"]\s*`,
			Severity:    SeverityCritical,
			Action:      "block",
			Priority:    100,
		},
		{
			ID:          "sys_sqli_pg_sleep",
			Name:        "PostgreSQL pg_sleep",
			Description: "Detects PostgreSQL pg_sleep function",
			Category:    CategorySecuritySQLi,
			Pattern:     `(?i)\bPG_SLEEP\s*\(\s*\d+\s*\)`,
			Severity:    SeverityCritical,
			Action:      "block",
			Priority:    100,
		},
		{
			ID:          "sys_sqli_benchmark",
			Name:        "MySQL BENCHMARK Function",
			Description: "Detects MySQL BENCHMARK function for time-based injection",
			Category:    CategorySecuritySQLi,
			Pattern:     `(?i)\bBENCHMARK\s*\(\s*\d+\s*,`,
			Severity:    SeverityCritical,
			Action:      "block",
			Priority:    100,
		},
		// Error-based SQL injection (3 patterns)
		{
			ID:          "sys_sqli_extractvalue",
			Name:        "EXTRACTVALUE Function",
			Description: "Detects EXTRACTVALUE function used in error-based injection",
			Category:    CategorySecuritySQLi,
			Pattern:     `(?i)\bEXTRACTVALUE\s*\(`,
			Severity:    SeverityHigh,
			Action:      "block",
			Priority:    90,
		},
		{
			ID:          "sys_sqli_updatexml",
			Name:        "UPDATEXML Function",
			Description: "Detects UPDATEXML function used in error-based injection",
			Category:    CategorySecuritySQLi,
			Pattern:     `(?i)\bUPDATEXML\s*\(`,
			Severity:    SeverityHigh,
			Action:      "block",
			Priority:    90,
		},
		{
			ID:          "sys_sqli_convert_int",
			Name:        "CONVERT INT Injection",
			Description: "Detects CONVERT(INT, ...) for error-based injection",
			Category:    CategorySecuritySQLi,
			Pattern:     `(?i)\bCONVERT\s*\(\s*INT\s*,`,
			Severity:    SeverityHigh,
			Action:      "block",
			Priority:    90,
		},
		// Stacked queries (5 patterns)
		{
			ID:          "sys_sqli_stacked_drop",
			Name:        "Stacked DROP Statement",
			Description: "Detects stacked DROP TABLE/DATABASE statement",
			Category:    CategorySecuritySQLi,
			Pattern:     `(?i);\s*DROP\s+(TABLE|DATABASE)\b`,
			Severity:    SeverityCritical,
			Action:      "block",
			Priority:    100,
		},
		{
			ID:          "sys_sqli_stacked_delete",
			Name:        "Stacked DELETE Statement",
			Description: "Detects stacked DELETE statement",
			Category:    CategorySecuritySQLi,
			Pattern:     `(?i);\s*DELETE\s+FROM\b`,
			Severity:    SeverityCritical,
			Action:      "block",
			Priority:    100,
		},
		{
			ID:          "sys_sqli_stacked_update",
			Name:        "Stacked UPDATE Statement",
			Description: "Detects stacked UPDATE statement",
			Category:    CategorySecuritySQLi,
			Pattern:     `(?i);\s*UPDATE\s+\w+\s+SET\b`,
			Severity:    SeverityCritical,
			Action:      "block",
			Priority:    100,
		},
		{
			ID:          "sys_sqli_stacked_insert",
			Name:        "Stacked INSERT Statement",
			Description: "Detects stacked INSERT statement",
			Category:    CategorySecuritySQLi,
			Pattern:     `(?i);\s*INSERT\s+INTO\b`,
			Severity:    SeverityCritical,
			Action:      "block",
			Priority:    100,
		},
		{
			ID:          "sys_sqli_stacked_exec",
			Name:        "Stacked EXEC Statement",
			Description: "Detects stacked EXEC/EXECUTE statement",
			Category:    CategorySecuritySQLi,
			Pattern:     `(?i);\s*(EXEC|EXECUTE)\s*\(`,
			Severity:    SeverityCritical,
			Action:      "block",
			Priority:    100,
		},
		// Comment-based injection (3 patterns)
		{
			ID:          "sys_sqli_inline_comment",
			Name:        "Inline Comment Injection",
			Description: "Detects SQL commands after inline comment",
			Category:    CategorySecuritySQLi,
			Pattern:     `(?i)/\*.*\*/\s*(UNION|SELECT|INSERT|UPDATE|DELETE|DROP)`,
			Severity:    SeverityHigh,
			Action:      "block",
			Priority:    90,
		},
		{
			ID:          "sys_sqli_line_comment_mysql",
			Name:        "MySQL Line Comment Injection",
			Description: "Detects SQL commands after MySQL line comment",
			Category:    CategorySecuritySQLi,
			Pattern:     `(?i)#\s*(UNION|SELECT|INSERT|UPDATE|DELETE|DROP)`,
			Severity:    SeverityHigh,
			Action:      "block",
			Priority:    90,
		},
		{
			ID:          "sys_sqli_line_comment_dash",
			Name:        "Double-Dash Comment Injection",
			Description: "Detects SQL commands after double-dash comment",
			Category:    CategorySecuritySQLi,
			Pattern:     `(?i)--\s*(UNION|SELECT|INSERT|UPDATE|DELETE|DROP)`,
			Severity:    SeverityHigh,
			Action:      "block",
			Priority:    90,
		},
		// Generic patterns (9 patterns)
		{
			ID:          "sys_sqli_select_from",
			Name:        "SELECT FROM After Termination",
			Description: "Detects SELECT ... FROM after string termination",
			Category:    CategorySecuritySQLi,
			Pattern:     `(?i)['"\)]\s*;\s*SELECT\s+.+\s+FROM\b`,
			Severity:    SeverityCritical,
			Action:      "block",
			Priority:    100,
		},
		{
			ID:          "sys_sqli_admin_bypass",
			Name:        "Authentication Bypass",
			Description: "Detects authentication bypass pattern with comment",
			Category:    CategorySecuritySQLi,
			Pattern:     `(?i)['"]?\s*OR\s+['"]?[^'"]*['"]?\s*=\s*['"]?[^'"]*['"]?\s*--`,
			Severity:    SeverityCritical,
			Action:      "block",
			Priority:    100,
		},
		{
			ID:          "sys_sqli_hex_encoding",
			Name:        "Hex-Encoded Payload",
			Description: "Detects potential hex-encoded SQL injection payload",
			Category:    CategorySecuritySQLi,
			Pattern:     `(?i)0x[0-9a-f]{8,}`,
			Severity:    SeverityMedium,
			Action:      "block",
			Priority:    70,
		},
		{
			ID:          "sys_sqli_char_function",
			Name:        "CHAR Function Obfuscation",
			Description: "Detects CHAR() function used to obfuscate injection",
			Category:    CategorySecuritySQLi,
			Pattern:     `(?i)\bCHAR\s*\(\s*\d+(\s*,\s*\d+)+\s*\)`,
			Severity:    SeverityHigh,
			Action:      "block",
			Priority:    90,
		},
		{
			ID:          "sys_sqli_concat_select",
			Name:        "CONCAT with Embedded SELECT",
			Description: "Detects CONCAT with embedded SELECT",
			Category:    CategorySecuritySQLi,
			Pattern:     `(?i)\bCONCAT\s*\([^)]*SELECT\b`,
			Severity:    SeverityHigh,
			Action:      "block",
			Priority:    90,
		},
		{
			ID:          "sys_sqli_information_schema",
			Name:        "INFORMATION_SCHEMA Access",
			Description: "Detects access to INFORMATION_SCHEMA for database enumeration",
			Category:    CategorySecuritySQLi,
			Pattern:     `(?i)\bINFORMATION_SCHEMA\b`,
			Severity:    SeverityHigh,
			Action:      "block",
			Priority:    90,
		},
		{
			ID:          "sys_sqli_sys_tables",
			Name:        "System Tables Access",
			Description: "Detects access to system tables for database enumeration",
			Category:    CategorySecuritySQLi,
			Pattern:     `(?i)\b(sysobjects|syscolumns|sys\.tables|sys\.columns)\b`,
			Severity:    SeverityHigh,
			Action:      "block",
			Priority:    90,
		},
		{
			ID:          "sys_sqli_load_file",
			Name:        "LOAD_FILE Function",
			Description: "Detects LOAD_FILE function for file access",
			Category:    CategorySecuritySQLi,
			Pattern:     `(?i)\bLOAD_FILE\s*\(`,
			Severity:    SeverityCritical,
			Action:      "block",
			Priority:    100,
		},
		{
			ID:          "sys_sqli_into_outfile",
			Name:        "INTO OUTFILE/DUMPFILE",
			Description: "Detects INTO OUTFILE/DUMPFILE for file writing",
			Category:    CategorySecuritySQLi,
			Pattern:     `(?i)\bINTO\s+(OUT|DUMP)FILE\b`,
			Severity:    SeverityCritical,
			Action:      "block",
			Priority:    100,
		},
		// Dangerous query patterns (8 patterns)
		{
			ID:          "sys_sqli_drop_table",
			Name:        "DROP TABLE Statement",
			Description: "Detects DROP TABLE statement",
			Category:    CategorySecuritySQLi,
			Pattern:     `(?i)\bDROP\s+TABLE\b`,
			Severity:    SeverityCritical,
			Action:      "block",
			Priority:    100,
		},
		{
			ID:          "sys_sqli_drop_database",
			Name:        "DROP DATABASE Statement",
			Description: "Detects DROP DATABASE statement",
			Category:    CategorySecuritySQLi,
			Pattern:     `(?i)\bDROP\s+DATABASE\b`,
			Severity:    SeverityCritical,
			Action:      "block",
			Priority:    100,
		},
		{
			ID:          "sys_sqli_truncate",
			Name:        "TRUNCATE TABLE Statement",
			Description: "Detects TRUNCATE TABLE statement",
			Category:    CategorySecuritySQLi,
			Pattern:     `(?i)\bTRUNCATE\s+TABLE\b`,
			Severity:    SeverityCritical,
			Action:      "block",
			Priority:    100,
		},
		{
			ID:          "sys_sqli_alter_table",
			Name:        "ALTER TABLE Statement",
			Description: "Detects ALTER TABLE statement (schema modification)",
			Category:    CategorySecuritySQLi,
			Pattern:     `(?i)\bALTER\s+TABLE\b`,
			Severity:    SeverityHigh,
			Action:      "block",
			Priority:    90,
		},
		{
			ID:          "sys_sqli_delete_no_where",
			Name:        "DELETE Without WHERE",
			Description: "Detects DELETE FROM without WHERE clause",
			Category:    CategorySecuritySQLi,
			Pattern:     `(?i)\bDELETE\s+FROM\s+\w+\s*(?:;|$)`,
			Severity:    SeverityCritical,
			Action:      "block",
			Priority:    100,
		},
		{
			ID:          "sys_sqli_create_user",
			Name:        "CREATE USER Statement",
			Description: "Detects CREATE USER statement",
			Category:    CategorySecuritySQLi,
			Pattern:     `(?i)\bCREATE\s+USER\b`,
			Severity:    SeverityCritical,
			Action:      "block",
			Priority:    100,
		},
		{
			ID:          "sys_sqli_grant",
			Name:        "GRANT Privileges Statement",
			Description: "Detects GRANT privilege statement",
			Category:    CategorySecuritySQLi,
			Pattern:     `(?i)\bGRANT\s+`,
			Severity:    SeverityCritical,
			Action:      "block",
			Priority:    100,
		},
		{
			ID:          "sys_sqli_revoke",
			Name:        "REVOKE Privileges Statement",
			Description: "Detects REVOKE privilege statement",
			Category:    CategorySecuritySQLi,
			Pattern:     `(?i)\bREVOKE\s+`,
			Severity:    SeverityCritical,
			Action:      "block",
			Priority:    100,
		},
	}
}

// getAdminAccessPatterns returns admin access control patterns.
// These patterns are categorized under security-admin.
func getAdminAccessPatterns() []SystemPolicySeed {
	return []SystemPolicySeed{
		{
			ID:          "sys_admin_users_table",
			Name:        "Users Table Access",
			Description: "Access to users table requires admin privileges",
			Category:    CategorySecurityAdmin,
			Pattern:     `\busers\b`,
			Severity:    SeverityHigh,
			Action:      "block",
			Priority:    80,
		},
		{
			ID:          "sys_admin_audit_log",
			Name:        "Audit Log Access",
			Description: "Access to audit logs requires admin privileges",
			Category:    CategorySecurityAdmin,
			Pattern:     `audit_log`,
			Severity:    SeverityHigh,
			Action:      "block",
			Priority:    80,
		},
		{
			ID:          "sys_admin_config_table",
			Name:        "Configuration Table Access",
			Description: "Access to system configuration requires admin privileges",
			Category:    CategorySecurityAdmin,
			Pattern:     `config_|admin_|system_`,
			Severity:    SeverityHigh,
			Action:      "block",
			Priority:    80,
		},
		{
			ID:          "sys_admin_info_schema",
			Name:        "Information Schema Access",
			Description: "System schema access requires admin privileges",
			Category:    CategorySecurityAdmin,
			Pattern:     `information_schema|pg_catalog|mysql\.user`,
			Severity:    SeverityMedium,
			Action:      "block",
			Priority:    70,
		},
	}
}

// getPIIPatterns returns PII detection patterns organized by region.
func getPIIPatterns() []SystemPolicySeed {
	return []SystemPolicySeed{
		// ====================================================================
		// pii-global (7 patterns)
		// ====================================================================
		{
			ID:          "sys_pii_credit_card",
			Name:        "Credit Card Number Detection",
			Description: "Credit card numbers detected - automatic redaction required for PCI compliance",
			Category:    CategoryPIIGlobal,
			Pattern: `\b(?:` +
				`4\d{12}(?:\d{3})?|` + // Visa
				`5[1-5]\d{14}|` + // Mastercard (51-55)
				`2[2-7]\d{14}|` + // Mastercard 2-series
				`3[47]\d{13}|` + // Amex
				`6(?:011|5\d{2})\d{12}|` + // Discover
				`3(?:0[0-5]|[68]\d)\d{11}|` + // Diners
				`(?:2131|1800|35\d{3})\d{11}` + // JCB
				`)\b|` +
				`\b(?:` +
				`\d{4}[- ]\d{4}[- ]\d{4}[- ]\d{4}|` + // 16-digit formatted
				`3[47]\d{2}[- ]\d{4}[- ]\d{4}[- ]\d{3}|` + // Amex formatted
				`3(?:0[0-5]|[68]\d)\d[- ]\d{4}[- ]\d{4}[- ]\d{2}` + // Diners formatted
				`)\b`,
			Severity: SeverityCritical,
			Action:   "block",
			Priority: 100,
		},
		{
			ID:          "sys_pii_email",
			Name:        "Email Address Detection",
			Description: "Email address detected - may require redaction under GDPR",
			Category:    CategoryPIIGlobal,
			Pattern:     `\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b`,
			Severity:    SeverityMedium,
			Action:      "log",
			Priority:    50,
		},
		{
			ID:          "sys_pii_phone",
			Name:        "Phone Number Detection",
			Description: "Phone number detected - may require redaction for privacy",
			Category:    CategoryPIIGlobal,
			Pattern:     `(?:\+?1[-.\s]?)?(?:\(?[0-9]{3}\)?[-.\s]?)?[0-9]{3}[-.\s]?[0-9]{4}\b|\+[0-9]{1,3}[-.\s]?[0-9]{6,14}\b`,
			Severity:    SeverityMedium,
			Action:      "log",
			Priority:    50,
		},
		{
			ID:          "sys_pii_ip_address",
			Name:        "IP Address Detection",
			Description: "IP address detected - may identify user location",
			Category:    CategoryPIIGlobal,
			Pattern:     `\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b`,
			Severity:    SeverityMedium,
			Action:      "log",
			Priority:    50,
		},
		{
			ID:          "sys_pii_passport",
			Name:        "Passport Number Detection",
			Description: "Passport numbers detected in query - automatic redaction required",
			Category:    CategoryPIIGlobal,
			Pattern:     `\b[A-Z]{1,2}[0-9]{6,9}\b`,
			Severity:    SeverityHigh,
			Action:      "block",
			Priority:    80,
		},
		{
			ID:          "sys_pii_dob",
			Name:        "Date of Birth Detection",
			Description: "Date detected - may be date of birth requiring protection",
			Category:    CategoryPIIGlobal,
			Pattern:     `\b(?:(?:0?[1-9]|1[0-2])[/\-](?:0?[1-9]|[12][0-9]|3[01])[/\-](?:19|20)\d{2}|(?:19|20)\d{2}[/\-](?:0?[1-9]|1[0-2])[/\-](?:0?[1-9]|[12][0-9]|3[01]))\b`,
			Severity:    SeverityHigh,
			Action:      "log",
			Priority:    60,
		},
		{
			ID:          "sys_pii_booking_ref",
			Name:        "Booking Reference Logging",
			Description: "Booking reference detected - logged for audit trail (not blocked)",
			Category:    CategoryPIIGlobal,
			Pattern:     `\b[A-Z0-9]{6}\b`,
			Severity:    SeverityLow,
			Action:      "log",
			Priority:    10,
		},
		// ====================================================================
		// pii-us (2 patterns)
		// ====================================================================
		{
			ID:          "sys_pii_ssn",
			Name:        "SSN Detection",
			Description: "Social Security Number detected - automatic redaction required",
			Category:    CategoryPIIUS,
			Pattern:     `\b(\d{3})[- ]?(\d{2})[- ]?(\d{4})\b`,
			Severity:    SeverityCritical,
			Action:      "block",
			Priority:    100,
		},
		{
			ID:          "sys_pii_bank_account",
			Name:        "Bank Account Detection",
			Description: "Bank account information detected - automatic redaction required",
			Category:    CategoryPIIUS,
			Pattern:     `\b[0-9]{9}[- ]?[0-9]{8,17}\b`,
			Severity:    SeverityCritical,
			Action:      "block",
			Priority:    100,
		},
		// ====================================================================
		// pii-eu (1 pattern)
		// ====================================================================
		{
			ID:          "sys_pii_iban",
			Name:        "IBAN Detection",
			Description: "International Bank Account Number detected - automatic redaction required",
			Category:    CategoryPIIEU,
			Pattern:     `\b[A-Z]{2}[0-9]{2}[A-Z0-9]{4}[0-9]{7}(?:[A-Z0-9]?){0,16}\b`,
			Severity:    SeverityCritical,
			Action:      "block",
			Priority:    100,
		},
		// ====================================================================
		// pii-india (2 patterns)
		// ====================================================================
		{
			ID:          "sys_pii_pan",
			Name:        "Indian PAN Detection",
			Description: "Indian Permanent Account Number (PAN) detected - automatic redaction required under SEBI guidelines",
			Category:    CategoryPIIIndia,
			Pattern:     `\b[A-Z]{3}[PCHABGJLFT][A-Z][0-9]{4}[A-Z]\b|(?i)PAN[:\s]+\b[A-Z0-9]{10}\b`,
			Severity:    SeverityCritical,
			Action:      "block",
			Priority:    100,
		},
		{
			ID:          "sys_pii_aadhaar",
			Name:        "Indian Aadhaar Detection",
			Description: "Indian Aadhaar number detected - automatic redaction required under DPDP Act 2023",
			Category:    CategoryPIIIndia,
			Pattern:     `\b[2-9][0-9]{3}\s?[0-9]{4}\s?[0-9]{4}\b|(?i)aadhaar[:\s]+[2-9][0-9]{11}|(?i)UID[:\s]+[2-9][0-9]{11}`,
			Severity:    SeverityCritical,
			Action:      "block",
			Priority:    100,
		},
	}
}

// GetDynamicSystemPolicies returns all dynamic system policies to be seeded.
// These policies use conditions and actions evaluated by the Orchestrator.
//
// Categories:
// - dynamic-risk: Risk-based policies (2 policies)
// - dynamic-compliance: Compliance policies (3 policies)
// - dynamic-security: Security policies (2 policies)
// - dynamic-cost: Cost control policies (2 policies)
// - dynamic-access: Access control policies (1 policy)
//
// Total: 10 dynamic system policies
func GetDynamicSystemPolicies() []DynamicPolicySeed {
	return []DynamicPolicySeed{
		// ====================================================================
		// dynamic-risk (2 policies)
		// ====================================================================
		{
			ID:          "sys_dyn_high_risk_block",
			Name:        "Block High-Risk Queries",
			Description: "Block queries with risk score above safety threshold",
			Category:    CategoryDynamicRisk,
			PolicyType:  "risk_based",
			Conditions:  `[{"field": "risk_score", "operator": "greater_than", "value": 0.8}]`,
			Actions:     `[{"type": "block", "config": {"reason": "Query risk score exceeds safety threshold"}}]`,
			Priority:    1000,
		},
		{
			ID:          "sys_dyn_anomalous_access",
			Name:        "Anomalous Access Detection",
			Description: "Detect and flag anomalous access patterns for review",
			Category:    CategoryDynamicRisk,
			PolicyType:  "risk_based",
			Conditions:  `[{"field": "risk_score", "operator": "greater_than", "value": 0.6}, {"field": "user.access_pattern", "operator": "equals", "value": "anomalous"}]`,
			Actions:     `[{"type": "alert", "config": {"severity": "warning", "message": "Anomalous access pattern detected"}}]`,
			Priority:    900,
		},
		// ====================================================================
		// dynamic-compliance (3 policies)
		// ====================================================================
		{
			ID:          "sys_dyn_hipaa",
			Name:        "HIPAA Compliance",
			Description: "Enforce HIPAA compliance for healthcare data access",
			Category:    CategoryDynamicCompliance,
			PolicyType:  "compliance",
			Conditions:  `[{"field": "query", "operator": "contains_any", "value": ["patient", "diagnosis", "treatment", "medical_record", "prescription"]}]`,
			Actions:     `[{"type": "redact", "config": {"fields": ["patient_id", "ssn", "medical_record_number"]}}, {"type": "log", "config": {"compliance": "hipaa"}}]`,
			Priority:    950,
		},
		{
			ID:          "sys_dyn_gdpr",
			Name:        "GDPR Compliance",
			Description: "Enforce GDPR compliance for EU personal data",
			Category:    CategoryDynamicCompliance,
			PolicyType:  "compliance",
			Conditions:  `[{"field": "user.region", "operator": "in", "value": ["EU", "EEA", "UK"]}]`,
			Actions:     `[{"type": "redact", "config": {"fields": ["email", "phone", "address", "ip_address"]}}, {"type": "log", "config": {"compliance": "gdpr"}}]`,
			Priority:    950,
		},
		{
			ID:          "sys_dyn_financial",
			Name:        "Financial Data Protection",
			Description: "Protect financial data with additional access controls",
			Category:    CategoryDynamicCompliance,
			PolicyType:  "compliance",
			Conditions:  `[{"field": "query", "operator": "contains_any", "value": ["account_balance", "transaction", "credit_score", "salary"]}]`,
			Actions:     `[{"type": "redact", "config": {"fields": ["account_number", "credit_card", "ssn"]}}, {"type": "log", "config": {"compliance": "pci-dss"}}]`,
			Priority:    950,
		},
		// ====================================================================
		// dynamic-security (2 policies)
		// ====================================================================
		{
			ID:          "sys_dyn_tenant_isolation",
			Name:        "Tenant Isolation",
			Description: "Ensure strict tenant data isolation in multi-tenant environment",
			Category:    CategoryDynamicSecurity,
			PolicyType:  "context_aware",
			Conditions:  `[{"field": "query", "operator": "regex", "value": "tenant_id\\s*[!=<>]+"}]`,
			Actions:     `[{"type": "block", "config": {"reason": "Cross-tenant data access attempt blocked"}}]`,
			Priority:    1000,
		},
		{
			ID:          "sys_dyn_debug_restrict",
			Name:        "Debug Mode Restriction",
			Description: "Restrict debug mode queries to development environments",
			Category:    CategoryDynamicSecurity,
			PolicyType:  "context_aware",
			Conditions:  `[{"field": "query", "operator": "contains", "value": "debug"}, {"field": "environment", "operator": "not_equals", "value": "development"}]`,
			Actions:     `[{"type": "block", "config": {"reason": "Debug queries are only allowed in development environment"}}]`,
			Priority:    800,
		},
		// ====================================================================
		// dynamic-cost (2 policies)
		// ====================================================================
		{
			ID:          "sys_dyn_expensive_query",
			Name:        "Expensive Query Limit",
			Description: "Limit execution of resource-intensive queries",
			Category:    CategoryDynamicCost,
			PolicyType:  "cost",
			Conditions:  `[{"field": "cost_estimate", "operator": "greater_than", "value": 100}]`,
			Actions:     `[{"type": "alert", "config": {"severity": "warning", "message": "High-cost query detected"}}, {"type": "log", "config": {"metric": "query_cost"}}]`,
			Priority:    700,
		},
		{
			ID:          "sys_dyn_llm_cost",
			Name:        "LLM Cost Optimization",
			Description: "Optimize LLM usage to control costs",
			Category:    CategoryDynamicCost,
			PolicyType:  "cost",
			Conditions:  `[{"field": "request_type", "operator": "equals", "value": "llm_chat"}, {"field": "user.monthly_llm_usage", "operator": "greater_than", "value": 1000}]`,
			Actions:     `[{"type": "modify_risk", "config": {"add": 0.2}}, {"type": "alert", "config": {"severity": "info", "message": "User approaching LLM usage limit"}}]`,
			Priority:    600,
		},
		// ====================================================================
		// dynamic-access (1 policy)
		// ====================================================================
		{
			ID:          "sys_dyn_sensitive_data",
			Name:        "Sensitive Data Control",
			Description: "Redact sensitive data fields in responses",
			Category:    CategoryDynamicAccess,
			PolicyType:  "context_aware",
			Conditions:  `[{"field": "query", "operator": "contains_any", "value": ["salary", "ssn", "medical_record"]}]`,
			Actions:     `[{"type": "redact", "config": {"fields": ["salary", "ssn", "medical_record"]}}]`,
			Priority:    900,
		},
	}
}

// GetSystemPolicyCounts returns the count of system policies by category.
func GetSystemPolicyCounts() map[PolicyCategory]int {
	counts := make(map[PolicyCategory]int)

	for _, p := range GetStaticSystemPolicies() {
		counts[p.Category]++
	}

	for _, p := range GetDynamicSystemPolicies() {
		counts[p.Category]++
	}

	return counts
}

// GetTotalSystemPolicyCount returns the total number of system policies.
func GetTotalSystemPolicyCount() int {
	return len(GetStaticSystemPolicies()) + len(GetDynamicSystemPolicies())
}

// getCodeGovernancePatterns returns code governance patterns for Issue #761.
// These patterns detect secrets, unsafe code constructs, and compliance issues
// in LLM-generated code, enabling governed code generation.
//
// Categories:
// - code-secrets: API keys, tokens, passwords, private keys (8 patterns)
// - code-unsafe: eval(), exec(), shell injection, insecure deserialization (7 patterns)
//
// Total: 15 patterns
func getCodeGovernancePatterns() []SystemPolicySeed {
	return []SystemPolicySeed{
		// ====================================================================
		// code-secrets (8 patterns)
		// ====================================================================
		{
			ID:          "sys_code_aws_key",
			Name:        "AWS Access Key Detection",
			Description: "Detects AWS access keys in generated code - keys should be loaded from environment variables",
			Category:    CategoryCodeSecrets,
			Pattern:     `AKIA[0-9A-Z]{16}`,
			Severity:    SeverityCritical,
			Action:      "block",
			Priority:    100,
		},
		{
			ID:          "sys_code_aws_secret",
			Name:        "AWS Secret Key Detection",
			Description: "Detects potential AWS secret keys in generated code - 40-character base64 strings in assignment context",
			Category:    CategoryCodeSecrets,
			Pattern:     `(?i)(?:aws|secret|key)\s*[:=]\s*["']?[A-Za-z0-9/+=]{40}["']?`,
			Severity:    SeverityCritical,
			Action:      "block",
			Priority:    100,
		},
		{
			ID:          "sys_code_github_token",
			Name:        "GitHub Token Detection",
			Description: "Detects GitHub personal access tokens, OAuth tokens, and app tokens in generated code",
			Category:    CategoryCodeSecrets,
			Pattern:     `gh[pousr]_[A-Za-z0-9_]{36,}`,
			Severity:    SeverityCritical,
			Action:      "block",
			Priority:    100,
		},
		{
			ID:          "sys_code_openai_key",
			Name:        "OpenAI API Key Detection",
			Description: "Detects OpenAI API keys in generated code - should use environment variables",
			Category:    CategoryCodeSecrets,
			Pattern:     `sk-(?:proj-)?[A-Za-z0-9]{32,}`,
			Severity:    SeverityCritical,
			Action:      "block",
			Priority:    100,
		},
		{
			ID:          "sys_code_anthropic_key",
			Name:        "Anthropic API Key Detection",
			Description: "Detects Anthropic API keys in generated code - should use environment variables",
			Category:    CategoryCodeSecrets,
			Pattern:     `sk-ant-[A-Za-z0-9-]{95}`,
			Severity:    SeverityCritical,
			Action:      "block",
			Priority:    100,
		},
		{
			ID:          "sys_code_jwt",
			Name:        "JWT Token Detection",
			Description: "Detects hardcoded JWT tokens in generated code - tokens should be dynamically generated",
			Category:    CategoryCodeSecrets,
			Pattern:     `eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_.+/]*`,
			Severity:    SeverityHigh,
			Action:      "block",
			Priority:    90,
		},
		{
			ID:          "sys_code_private_key",
			Name:        "Private Key Detection",
			Description: "Detects private keys (RSA, EC, OpenSSH) embedded in generated code",
			Category:    CategoryCodeSecrets,
			Pattern:     `-----BEGIN (RSA|EC|OPENSSH) PRIVATE KEY-----`,
			Severity:    SeverityCritical,
			Action:      "block",
			Priority:    100,
		},
		{
			ID:          "sys_code_password_assign",
			Name:        "Hardcoded Password Detection",
			Description: "Detects hardcoded password assignments in generated code",
			Category:    CategoryCodeSecrets,
			Pattern:     `(?i)password\s*[:=]\s*["'][^"']{4,}["']`,
			Severity:    SeverityHigh,
			Action:      "block",
			Priority:    90,
		},
		// ====================================================================
		// code-unsafe (7 patterns)
		// ====================================================================
		{
			ID:          "sys_code_eval_js",
			Name:        "JavaScript eval() Detection",
			Description: "Detects eval() calls in JavaScript/TypeScript code - use safer alternatives like JSON.parse()",
			Category:    CategoryCodeUnsafe,
			Pattern:     `\beval\s*\(`,
			Severity:    SeverityHigh,
			Action:      "warn",
			Priority:    80,
		},
		{
			ID:          "sys_code_exec_python",
			Name:        "Python exec() Detection",
			Description: "Detects exec() calls in Python code - use safer alternatives like ast.literal_eval()",
			Category:    CategoryCodeUnsafe,
			Pattern:     `\bexec\s*\(`,
			Severity:    SeverityHigh,
			Action:      "warn",
			Priority:    80,
		},
		{
			ID:          "sys_code_shell_injection",
			Name:        "Shell Injection Risk Detection",
			Description: "Detects subprocess calls with shell=True in Python - use shell=False with explicit args",
			Category:    CategoryCodeUnsafe,
			Pattern:     `subprocess\.(?:call|run|Popen)\s*\([^)]*shell\s*=\s*True`,
			Severity:    SeverityCritical,
			Action:      "block",
			Priority:    95,
		},
		{
			ID:          "sys_code_sql_format",
			Name:        "SQL String Formatting Detection",
			Description: "Detects SQL queries built with string formatting - use parameterized queries instead",
			Category:    CategoryCodeUnsafe,
			Pattern:     `(?i)(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE).*(?:\.format\s*\(|%s|%d|\{[^}]+\})`,
			Severity:    SeverityHigh,
			Action:      "warn",
			Priority:    80,
		},
		{
			ID:          "sys_code_os_system",
			Name:        "OS Command Execution Detection",
			Description: "Detects os.system() calls which are vulnerable to command injection - use subprocess with explicit args",
			Category:    CategoryCodeUnsafe,
			Pattern:     `os\.system\s*\(`,
			Severity:    SeverityHigh,
			Action:      "warn",
			Priority:    80,
		},
		{
			ID:          "sys_code_pickle",
			Name:        "Insecure Deserialization Detection",
			Description: "Detects pickle.load/loads usage which can execute arbitrary code - use json or safer alternatives",
			Category:    CategoryCodeUnsafe,
			Pattern:     `pickle\.loads?\s*\(`,
			Severity:    SeverityCritical,
			Action:      "warn",
			Priority:    85,
		},
		{
			ID:          "sys_code_yaml_unsafe",
			Name:        "Unsafe YAML Load Detection",
			Description: "Detects yaml.load() without safe Loader - use yaml.safe_load() instead",
			Category:    CategoryCodeUnsafe,
			Pattern:     `yaml\.load\s*\([^)]*(?:Loader\s*=\s*None|[^L][^o][^a][^d][^e][^r])?\s*\)`,
			Severity:    SeverityHigh,
			Action:      "warn",
			Priority:    80,
		},
	}
}
