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
// - pii-singapore: Singapore-specific PII patterns (5 patterns) - Issue #1076
// - code-secrets: Secret detection in generated code (8 patterns) - Issue #761
// - code-unsafe: Unsafe code pattern detection (7 patterns) - Issue #761
// - pii-indonesia: Indonesia PII incl. KTP (9 patterns) - OJK/BI/UU PDP, #2522
// - security-dangerous: Indirect prompt-injection (4 patterns) - #2522
//
// Total: 86 static system policies
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

	// ========================================================================
	// Dangerous-Instruction Patterns (security-dangerous) - 4 patterns (#2522)
	// Indirect prompt-injection protection (R&C §5.1, R03, OWASP LLM01).
	// ========================================================================
	dangerousPatterns := getDangerousInstructionPatterns()
	policies = append(policies, dangerousPatterns...)

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
// Includes global, US, EU, India, and Singapore patterns.
func getPIIPatterns() []SystemPolicySeed {
	patterns := []SystemPolicySeed{
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
			// Match a 6-char alphanumeric token ONLY when it follows a
			// booking-context label (booking, reservation, reference, ref,
			// PNR, confirmation, conf). The previous pattern \b[A-Z0-9]{6}\b
			// matched any 6-char uppercase token — including every common SQL
			// keyword (SELECT, INSERT, DELETE, UPDATE, CREATE) — and fired on
			// every benign query, polluting audit logs and inflating
			// "PII detected" counts in compliance reports.
			Pattern:  `(?i)\b(?:booking|reservation|reference|ref|pnr|conf(?:irmation)?)\b\s*[:#]?\s*\b([A-Z0-9]{6})\b`,
			Severity: SeverityLow,
			Action:   "log",
			Priority: 10,
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

	// Append Singapore PII patterns
	singaporePatterns := getSingaporePIIPatterns()
	patterns = append(patterns, singaporePatterns...)

	// Append Indonesia PII patterns
	indonesiaPatterns := getIndonesiaPIIPatterns()
	patterns = append(patterns, indonesiaPatterns...)

	return patterns
}

// getSingaporePIIPatterns returns Singapore-specific PII detection patterns.
// These patterns support MAS FEAT compliance in Community Edition (Issue #1076).
//
// Patterns include:
// - NRIC: National Registration Identity Card (S, T, F, G, M prefixes)
// - FIN: Foreign Identification Number (F, G prefixes)
// - UEN: Unique Entity Number (8-9 digits + letter suffix)
// - Phone: Singapore phone numbers (+65 format)
// - Postal: Singapore postal codes (6 digits)
//
// Note: These are pattern-based only. Checksum validation is Enterprise-only.
func getSingaporePIIPatterns() []SystemPolicySeed {
	return []SystemPolicySeed{
		// ====================================================================
		// pii-singapore (5 patterns) - Issue #1076
		// ====================================================================
		{
			ID:          "sys_pii_singapore_nric",
			Name:        "Singapore NRIC Detection",
			Description: "Singapore National Registration Identity Card detected - automatic redaction for MAS FEAT compliance",
			Category:    CategoryPIISingapore,
			// NRIC format: [STFGM]XXXXXXX[A-Z]
			// S = Singapore Citizen born before 2000
			// T = Singapore Citizen born 2000 onwards
			// F = Foreigner issued before 2000
			// G = Foreigner issued 2000 onwards
			// M = Foreigner issued 2022 onwards
			Pattern:  `\b[STFGM]\d{7}[A-Z]\b`,
			Severity: SeverityCritical,
			Action:   "redact",
			Priority: 100,
		},
		{
			ID:          "sys_pii_singapore_fin",
			Name:        "Singapore FIN Detection",
			Description: "Singapore Foreign Identification Number detected - automatic redaction for MAS FEAT compliance",
			Category:    CategoryPIISingapore,
			// FIN format: [FG]XXXXXXX[A-Z]
			// Note: FIN is subset of NRIC pattern but kept separate for explicit audit logging
			Pattern:  `\b[FG]\d{7}[A-Z]\b`,
			Severity: SeverityCritical,
			Action:   "redact",
			Priority: 100,
		},
		{
			ID:          "sys_pii_singapore_uen",
			Name:        "Singapore UEN Detection",
			Description: "Singapore Unique Entity Number detected - automatic redaction for MAS FEAT compliance",
			Category:    CategoryPIISingapore,
			// UEN formats:
			// - Business (ROB): 8 digits + 1 letter (e.g., 53276128A)
			// - Local Company (ROC): 9 digits + 1 letter (e.g., 200312345A)
			// - Others: 10 alphanumeric characters (e.g., T08GA0001A)
			Pattern:  `\b\d{8,9}[A-Z]\b|\b[TS]\d{2}[A-Z]{2}\d{4}[A-Z]\b`,
			Severity: SeverityHigh,
			Action:   "redact",
			Priority: 90,
		},
		{
			ID:          "sys_pii_singapore_phone",
			Name:        "Singapore Phone Detection",
			Description: "Singapore phone number detected - redaction recommended for privacy",
			Category:    CategoryPIISingapore,
			// Singapore phone: +65 followed by 8 digits starting with 6, 8, or 9
			// 6XXX XXXX = landline
			// 8XXX XXXX, 9XXX XXXX = mobile
			Pattern:  `\+65\s?[689]\d{3}\s?\d{4}\b`,
			Severity: SeverityMedium,
			Action:   "redact",
			Priority: 70,
		},
		{
			ID:          "sys_pii_singapore_postal",
			Name:        "Singapore Postal Code Detection",
			Description: "Singapore postal code detected - may reveal location, logged for audit",
			Category:    CategoryPIISingapore,
			// Singapore postal code: 6 digits (ranges 01-82)
			// Using word boundary to avoid false positives with other numbers
			Pattern:  `\b(?:0[1-9]|[1-7]\d|8[0-2])\d{4}\b`,
			Severity: SeverityLow,
			Action:   "warn",
			Priority: 30,
		},
	}
}

// getIndonesiaPIIPatterns returns Indonesia-specific PII detection patterns.
// These patterns support OJK AI Governance, BI payment system, and UU PDP compliance.
//
// Patterns include:
// - NIK: Nomor Induk Kependudukan (16-digit national ID, province-code validated)
// - NPWP Legacy: Nomor Pokok Wajib Pajak (15-digit dotted format, pre-2024)
// - NPWP New: 16-digit format (context-anchored to avoid credit card false positives)
// - Phone: Indonesian mobile numbers (+62 / 08xx format)
// - Bank accounts: BCA (10-digit), Mandiri (13-digit), BRI (15-digit), BNI (10-digit) — all context-anchored
func getIndonesiaPIIPatterns() []SystemPolicySeed {
	return []SystemPolicySeed{
		// ====================================================================
		// pii-indonesia (8 patterns)
		// ====================================================================
		{
			ID:   "sys_pii_indonesia_nik",
			Name: "Indonesian NIK Detection",
			Description: "Indonesian Nomor Induk Kependudukan (national ID) detected — " +
				"automatic blocking required under UU PDP Art. 4 and OJK POJK 11/2022",
			Category: CategoryPIIIndonesia,
			// NIK format: PPRRSSDDMMYYNNNN (16 digits)
			// PP = province code (11-94 with gaps: valid provinces listed below)
			// RRSS = regency/city + sub-district
			// DD = day of birth (01-31 male, 41-71 female with +40 offset)
			// MM = month (01-12), YY = year, NNNN = sequence
			// Province codes: 11-21, 31-36, 51-53, 61-65, 71-76, 81-82, 91-94
			Pattern: `\b(?:` +
				`1[1-9]|21|` + // Aceh(11)-Riau Islands(21)
				`3[1-6]|` + // DKI Jakarta(31)-Banten(36)
				`5[1-3]|` + // Bali(51)-NTT(53)
				`6[1-5]|` + // West Kalimantan(61)-North Kalimantan(65)
				`7[1-6]|` + // North Sulawesi(71)-West Sulawesi(76)
				`8[12]|` + // Maluku(81)-North Maluku(82)
				`9[1-4]` + // West Papua(91)-Papua(94; includes new provinces)
				`)` +
				`\d{4}` + // RRSS: regency/sub-district
				`(?:0[1-9]|[12]\d|3[01]|4[1-9]|[56]\d|7[01])` + // DD: 01-31 male or 41-71 female
				`(?:0[1-9]|1[0-2])` + // MM: month
				`\d{2}` + // YY: year
				`\d{4}\b`, // NNNN: sequence
			Severity: SeverityCritical,
			Action:   "block",
			Priority: 100,
		},
		{
			ID:   "sys_pii_indonesia_ktp",
			Name: "Indonesian KTP Detection",
			Description: "Indonesian KTP (Kartu Tanda Penduduk / national ID card) number detected — " +
				"the 16-digit KTP number IS the NIK; this keyword-anchored pattern also catches " +
				"separator-formatted (dotted/dashed/spaced) KTP numbers and connector words between " +
				"the label and the number (\"KTP number is 3201-…\"). Blocked under UU PDP Art. 4 " +
				"and OJK POJK 11/2022 (a design partner's R&C §4.1 KYC identity, #2522)",
			Category: CategoryPIIIndonesia,
			// KTP keyword anchor + optional connector words + 16 digits allowing
			// dot/dash/space separators. Byte-identical to the runtime Enterprise
			// detector pattern (ee/.../indonesia), which additionally validates the
			// digit-normalized core as a real NIK before blocking.
			Pattern:  `(?i)(?:no[\s._-]*ktp|nomor[\s_-]*ktp|kartu[\s_-]*tanda[\s_-]*penduduk|ktp)(?:[\s:#=]+(?:no\.?|nomor|number|num|adalah|is))*[\s:#=]*[0-9][0-9.\s-]{14,22}[0-9]`,
			Severity: SeverityCritical,
			Action:   "block",
			Priority: 100,
		},
		{
			ID:          "sys_pii_indonesia_npwp_legacy",
			Name:        "Indonesian NPWP Legacy Detection",
			Description: "Indonesian Nomor Pokok Wajib Pajak (tax ID, legacy 15-digit format) detected — redaction required under UU PDP",
			Category:    CategoryPIIIndonesia,
			// Legacy NPWP format: XX.XXX.XXX.X-XXX.XXX (15 digits with dots and dash)
			Pattern:  `\b\d{2}\.\d{3}\.\d{3}\.\d{1}-\d{3}\.\d{3}\b`,
			Severity: SeverityCritical,
			Action:   "block",
			Priority: 100,
		},
		{
			ID:          "sys_pii_indonesia_npwp_new",
			Name:        "Indonesian NPWP New Format Detection",
			Description: "Indonesian tax ID (new 16-digit format, post-2024) detected — context-anchored to reduce false positives",
			Category:    CategoryPIIIndonesia,
			// New NPWP is 16 digits (same as NIK for individuals, different prefix for corporates)
			// Context-anchored: requires keyword prefix to avoid matching credit cards/timestamps
			Pattern:  `(?i)(?:NPWP|npwp|tax[\s_-]*(?:id|number|no)|nomor[\s_-]*pokok)[:\s]+\d{16}\b`,
			Severity: SeverityCritical,
			Action:   "block",
			Priority: 100,
		},
		{
			ID:          "sys_pii_indonesia_phone",
			Name:        "Indonesian Phone Detection",
			Description: "Indonesian phone number detected — redaction recommended for privacy under UU PDP",
			Category:    CategoryPIIIndonesia,
			// Indonesian mobile: +62 or 08xx, followed by 8-11 digits
			// Carriers: Telkomsel (0811-0813,0821-0823,0852-0853,0851),
			//   Indosat (0814-0816,0855-0858), XL (0817-0819,0859,0877-0878),
			//   Tri (0895-0899,0896-0897), Smartfren (0881-0889)
			Pattern:  `\b(?:\+?62|0)8[1-9]\d{7,11}\b`,
			Severity: SeverityMedium,
			Action:   "redact",
			Priority: 70,
		},
		{
			ID:          "sys_pii_indonesia_bca",
			Name:        "Indonesian BCA Bank Account Detection",
			Description: "BCA bank account number detected — context-anchored for OJK compliance",
			Category:    CategoryPIIIndonesia,
			// BCA accounts: 10 digits, context-anchored to avoid timestamp false positives
			Pattern:  `(?i)(?:BCA|bank[\s_-]*central[\s_-]*asia|rek(?:ening)?)[:\s]+\d{10}\b`,
			Severity: SeverityHigh,
			Action:   "redact",
			Priority: 90,
		},
		{
			ID:          "sys_pii_indonesia_mandiri",
			Name:        "Indonesian Mandiri Bank Account Detection",
			Description: "Mandiri bank account number detected — context-anchored for OJK compliance",
			Category:    CategoryPIIIndonesia,
			// Mandiri accounts: 13 digits, context-anchored
			Pattern:  `(?i)(?:mandiri|bank[\s_-]*mandiri|rek(?:ening)?[\s_-]*mandiri)[:\s]+\d{13}\b`,
			Severity: SeverityHigh,
			Action:   "redact",
			Priority: 90,
		},
		{
			ID:          "sys_pii_indonesia_bri",
			Name:        "Indonesian BRI Bank Account Detection",
			Description: "BRI bank account number detected — context-anchored for OJK compliance",
			Category:    CategoryPIIIndonesia,
			// BRI accounts: 15 digits, context-anchored
			Pattern:  `(?i)(?:BRI|bank[\s_-]*rakyat[\s_-]*indonesia|rek(?:ening)?[\s_-]*BRI)[:\s]+\d{15}\b`,
			Severity: SeverityHigh,
			Action:   "redact",
			Priority: 90,
		},
		{
			ID:          "sys_pii_indonesia_bni",
			Name:        "Indonesian BNI Bank Account Detection",
			Description: "BNI bank account number detected — context-anchored for OJK compliance",
			Category:    CategoryPIIIndonesia,
			// BNI accounts: 10 digits, context-anchored
			Pattern:  `(?i)(?:BNI|bank[\s_-]*negara[\s_-]*indonesia|rek(?:ening)?[\s_-]*BNI)[:\s]+\d{10}\b`,
			Severity: SeverityHigh,
			Action:   "redact",
			Priority: 90,
		},
	}
}

// getDangerousInstructionPatterns returns indirect-prompt-injection detection
// patterns (security-dangerous). These guard merchant-controlled free-text fields
// that flow into Claude's context, per a design partner's R&C §5.1 ("strip or escape
// bracket patterns and common injection phrases") and risk R03 (OWASP LLM01).
//
// They are evaluated by the shared policy engine alongside security-sqli in
// Gateway Mode pre-check, so a merchant note containing an injection attempt is
// blocked before it reaches the model. Patterns are RE2-safe (no backreferences
// or lookarounds) and scoped to instruction-like language to limit false
// positives on ordinary merchant text.
func getDangerousInstructionPatterns() []SystemPolicySeed {
	return []SystemPolicySeed{
		{
			ID:          "sys_dangerous_injection_override",
			Name:        "Prompt Injection — Instruction Override",
			Description: "Detects attempts to ignore/override prior instructions, prompts, or guardrails in free-text",
			Category:    CategorySecurityDangerous,
			// Two branches: (a) a "previous/prior/system/…" qualifier before any
			// instruction-class object (incl. the FP-prone "rules"); or (b) no
			// qualifier but an explicit instruction/prompt/directive/guardrail
			// object (catches the classic "ignore all instructions" while keeping
			// benign "ignore the discount rules" / "forget the previous context
			// note" out, because bare "rules" only matches via branch (a)).
			Pattern:  `(?i)\b(?:ignore|disregard|forget|override|bypass)\s+(?:all\s+|any\s+|the\s+|your\s+|these\s+|those\s+)*(?:(?:previous|prior|above|earlier|preceding|initial|system|original)\s+(?:instruction|instructions|prompt|prompts|directive|directives|rule|rules|guardrail|guardrails)|(?:instruction|instructions|prompt|prompts|directive|directives|guardrail|guardrails))\b`,
			Severity: SeverityHigh,
			Action:   "block",
			Priority: 95,
		},
		{
			ID:          "sys_dangerous_injection_role_override",
			Name:        "Prompt Injection — Role Reassignment",
			Description: "Detects attempts to reassign the assistant's role to a privileged/jailbreak persona",
			Category:    CategorySecurityDangerous,
			// Requires a privileged/jailbreak target (admin/root/unrestricted/DAN/
			// developer-mode/…) so benign role talk ("act as a developer",
			// "pretend you are happy") does not match; the open "from now on you
			// are/will/must" branch is a strong standalone signal.
			Pattern:  `(?i)(?:\b(?:you\s+are\s+now|act\s+as|pretend\s+(?:to\s+be|you\s+are)|roleplay\s+as)\s+(?:an?\s+|the\s+)?(?:admin|administrator|root|superuser|system\s+administrator|unrestricted|jailbroken|jailbreak|dan\s+mode|developer\s+mode|do\s+anything\s+now|a\s+different\s+(?:ai|model|assistant))\b|\bfrom\s+now\s+on,?\s+you\s+(?:are|will|must)\b)`,
			Severity: SeverityHigh,
			Action:   "block",
			Priority: 95,
		},
		{
			ID:          "sys_dangerous_injection_system_exfil",
			Name:        "Prompt Injection — System Prompt Exfiltration",
			Description: "Detects attempts to reveal/print/repeat the system prompt or hidden instructions",
			Category:    CategorySecurityDangerous,
			Pattern:     `(?i)\b(?:reveal|show|print|repeat|display|output|leak|expose)\b[^.\n]{0,30}\b(?:system\s+prompt|your\s+(?:instructions|prompt|rules|system)|initial\s+(?:prompt|instructions)|the\s+prompt\s+above)\b`,
			Severity:    SeverityHigh,
			Action:      "block",
			Priority:    95,
		},
		{
			ID:          "sys_dangerous_injection_bracket_marker",
			Name:        "Prompt Injection — Template/Bracket Marker",
			Description: "Detects injected chat-template or role-delimiter markers ([system], <im_start>, ### system)",
			Category:    CategorySecurityDangerous,
			// Note: the angle-bracket branch is limited to im_start/im_end/system to
			// avoid matching ordinary HTML like <s>/</s> (strikethrough) in merchant text.
			Pattern:  `(?i)(?:\[\s*(?:system|assistant|inst|/inst|user)\s*\]|<\s*(?:system|im_start|im_end)\s*>|###\s*(?:system|instruction)\b|<\|(?:im_start|im_end|system)\|>)`,
			Severity: SeverityHigh,
			Action:   "block",
			Priority: 95,
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
