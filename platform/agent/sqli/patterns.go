package sqli

import (
	"regexp"
)

// Pattern represents a SQL injection detection pattern.
type Pattern struct {
	// Name is a human-readable identifier for the pattern.
	Name string

	// Category classifies the type of SQL injection this pattern detects.
	Category Category

	// Regex is the compiled regular expression.
	Regex *regexp.Regexp

	// Description explains what this pattern detects.
	Description string

	// Severity indicates the risk level (1-10).
	Severity int
}

// PatternSet holds a collection of SQL injection patterns.
type PatternSet struct {
	patterns []*Pattern
}

// NewPatternSet creates a new pattern set with the default SQL injection patterns.
func NewPatternSet() *PatternSet {
	return &PatternSet{
		patterns: defaultPatterns(),
	}
}

// Patterns returns all patterns in the set.
func (ps *PatternSet) Patterns() []*Pattern {
	return ps.patterns
}

// PatternsByCategory returns patterns filtered by category.
func (ps *PatternSet) PatternsByCategory(category Category) []*Pattern {
	var result []*Pattern
	for _, p := range ps.patterns {
		if p.Category == category {
			result = append(result, p)
		}
	}
	return result
}

// defaultPatterns returns the built-in SQL injection patterns.
// These patterns are designed to balance detection accuracy with performance.
func defaultPatterns() []*Pattern {
	return []*Pattern{
		// UNION-based SQL injection
		{
			Name:        "union_select",
			Category:    CategoryUnionBased,
			Regex:       regexp.MustCompile(`(?i)\bUNION\s+(ALL\s+)?SELECT\b`),
			Description: "Detects UNION SELECT statements used to extract data",
			Severity:    9,
		},
		{
			Name:        "union_injection",
			Category:    CategoryUnionBased,
			Regex:       regexp.MustCompile(`(?i)['"\)]\s*UNION\s+(ALL\s+)?SELECT`),
			Description: "Detects UNION injection after string termination",
			Severity:    10,
		},

		// Boolean-based blind SQL injection
		{
			Name:        "or_true_condition",
			Category:    CategoryBooleanBlind,
			Regex:       regexp.MustCompile(`(?i)\bOR\s+['"]?\d+['"]?\s*=\s*['"]?\d+['"]?`),
			Description: "Detects OR with always-true numeric comparison (OR 1=1)",
			Severity:    8,
		},
		{
			Name:        "or_string_condition",
			Category:    CategoryBooleanBlind,
			Regex:       regexp.MustCompile(`(?i)\bOR\s+['"][^'"]*['"]\s*=\s*['"][^'"]*['"]`),
			Description: "Detects OR with always-true string comparison (OR 'a'='a')",
			Severity:    8,
		},
		{
			Name:        "and_false_condition",
			Category:    CategoryBooleanBlind,
			Regex:       regexp.MustCompile(`(?i)\bAND\s+['"]?\d+['"]?\s*=\s*['"]?\d+['"]?`),
			Description: "Detects AND with numeric comparison for boolean blind",
			Severity:    7,
		},

		// Time-based blind SQL injection
		{
			Name:        "sleep_function",
			Category:    CategoryTimeBased,
			Regex:       regexp.MustCompile(`(?i)\bSLEEP\s*\(\s*\d+\s*\)`),
			Description: "Detects MySQL SLEEP function for time-based blind injection",
			Severity:    9,
		},
		{
			Name:        "waitfor_delay",
			Category:    CategoryTimeBased,
			Regex:       regexp.MustCompile(`(?i)\bWAITFOR\s+DELAY\s+['"][^'"]+['"]`),
			Description: "Detects SQL Server WAITFOR DELAY for time-based blind injection",
			Severity:    9,
		},
		{
			Name:        "pg_sleep",
			Category:    CategoryTimeBased,
			Regex:       regexp.MustCompile(`(?i)\bPG_SLEEP\s*\(\s*\d+\s*\)`),
			Description: "Detects PostgreSQL pg_sleep function",
			Severity:    9,
		},
		{
			Name:        "benchmark_function",
			Category:    CategoryTimeBased,
			Regex:       regexp.MustCompile(`(?i)\bBENCHMARK\s*\(\s*\d+\s*,`),
			Description: "Detects MySQL BENCHMARK function for time-based injection",
			Severity:    9,
		},

		// Error-based SQL injection
		{
			Name:        "extractvalue",
			Category:    CategoryErrorBased,
			Regex:       regexp.MustCompile(`(?i)\bEXTRACTVALUE\s*\(`),
			Description: "Detects EXTRACTVALUE function used in error-based injection",
			Severity:    8,
		},
		{
			Name:        "updatexml",
			Category:    CategoryErrorBased,
			Regex:       regexp.MustCompile(`(?i)\bUPDATEXML\s*\(`),
			Description: "Detects UPDATEXML function used in error-based injection",
			Severity:    8,
		},
		{
			Name:        "convert_int",
			Category:    CategoryErrorBased,
			Regex:       regexp.MustCompile(`(?i)\bCONVERT\s*\(\s*INT\s*,`),
			Description: "Detects CONVERT(INT, ...) for error-based injection",
			Severity:    7,
		},

		// Stacked queries
		{
			Name:        "semicolon_drop",
			Category:    CategoryStackedQueries,
			Regex:       regexp.MustCompile(`(?i);\s*DROP\s+(TABLE|DATABASE)\b`),
			Description: "Detects stacked DROP TABLE/DATABASE statement",
			Severity:    10,
		},
		{
			Name:        "semicolon_delete",
			Category:    CategoryStackedQueries,
			Regex:       regexp.MustCompile(`(?i);\s*DELETE\s+FROM\b`),
			Description: "Detects stacked DELETE statement",
			Severity:    10,
		},
		{
			Name:        "semicolon_update",
			Category:    CategoryStackedQueries,
			Regex:       regexp.MustCompile(`(?i);\s*UPDATE\s+\w+\s+SET\b`),
			Description: "Detects stacked UPDATE statement",
			Severity:    9,
		},
		{
			Name:        "semicolon_insert",
			Category:    CategoryStackedQueries,
			Regex:       regexp.MustCompile(`(?i);\s*INSERT\s+INTO\b`),
			Description: "Detects stacked INSERT statement",
			Severity:    9,
		},
		{
			Name:        "semicolon_exec",
			Category:    CategoryStackedQueries,
			Regex:       regexp.MustCompile(`(?i);\s*(EXEC|EXECUTE)\s*\(`),
			Description: "Detects stacked EXEC/EXECUTE statement",
			Severity:    10,
		},

		// Comment-based injection
		{
			Name:        "inline_comment",
			Category:    CategoryCommentInjection,
			Regex:       regexp.MustCompile(`(?i)/\*.*\*/\s*(UNION|SELECT|INSERT|UPDATE|DELETE|DROP)`),
			Description: "Detects SQL commands after inline comment",
			Severity:    8,
		},
		{
			Name:        "line_comment_mysql",
			Category:    CategoryCommentInjection,
			Regex:       regexp.MustCompile(`(?i)#\s*(UNION|SELECT|INSERT|UPDATE|DELETE|DROP)`),
			Description: "Detects SQL commands after MySQL line comment",
			Severity:    8,
		},
		{
			Name:        "line_comment_double_dash",
			Category:    CategoryCommentInjection,
			Regex:       regexp.MustCompile(`(?i)--\s*(UNION|SELECT|INSERT|UPDATE|DELETE|DROP)`),
			Description: "Detects SQL commands after double-dash comment",
			Severity:    8,
		},

		// Generic patterns
		{
			Name:        "select_from",
			Category:    CategoryGeneric,
			Regex:       regexp.MustCompile(`(?i)['"\)]\s*;\s*SELECT\s+.+\s+FROM\b`),
			Description: "Detects SELECT ... FROM after string termination",
			Severity:    9,
		},
		{
			Name:        "admin_bypass",
			Category:    CategoryGeneric,
			Regex:       regexp.MustCompile(`(?i)['"]?\s*OR\s+['"]?[^'"]*['"]?\s*=\s*['"]?[^'"]*['"]?\s*--`),
			Description: "Detects authentication bypass pattern with comment",
			Severity:    10,
		},
		{
			Name:        "hex_encoding",
			Category:    CategoryGeneric,
			Regex:       regexp.MustCompile(`(?i)0x[0-9a-f]{8,}`),
			Description: "Detects potential hex-encoded SQL injection payload",
			Severity:    6,
		},
		{
			Name:        "char_function",
			Category:    CategoryGeneric,
			Regex:       regexp.MustCompile(`(?i)\bCHAR\s*\(\s*\d+(\s*,\s*\d+)+\s*\)`),
			Description: "Detects CHAR() function used to obfuscate injection",
			Severity:    7,
		},
		{
			Name:        "concat_function",
			Category:    CategoryGeneric,
			Regex:       regexp.MustCompile(`(?i)\bCONCAT\s*\([^)]*SELECT\b`),
			Description: "Detects CONCAT with embedded SELECT",
			Severity:    8,
		},
		{
			Name:        "information_schema",
			Category:    CategoryGeneric,
			Regex:       regexp.MustCompile(`(?i)\bINFORMATION_SCHEMA\b`),
			Description: "Detects access to INFORMATION_SCHEMA for database enumeration",
			Severity:    8,
		},
		{
			Name:        "sys_tables",
			Category:    CategoryGeneric,
			Regex:       regexp.MustCompile(`(?i)\b(sysobjects|syscolumns|sys\.tables|sys\.columns)\b`),
			Description: "Detects access to system tables for database enumeration",
			Severity:    8,
		},
		{
			Name:        "load_file",
			Category:    CategoryGeneric,
			Regex:       regexp.MustCompile(`(?i)\bLOAD_FILE\s*\(`),
			Description: "Detects LOAD_FILE function for file access",
			Severity:    10,
		},
		{
			Name:        "into_outfile",
			Category:    CategoryGeneric,
			Regex:       regexp.MustCompile(`(?i)\bINTO\s+(OUT|DUMP)FILE\b`),
			Description: "Detects INTO OUTFILE/DUMPFILE for file writing",
			Severity:    10,
		},

		// Dangerous query patterns - DDL and privilege operations
		{
			Name:        "drop_table",
			Category:    CategoryDangerousQuery,
			Regex:       regexp.MustCompile(`(?i)\bDROP\s+TABLE\b`),
			Description: "Detects DROP TABLE statement",
			Severity:    10,
		},
		{
			Name:        "drop_database",
			Category:    CategoryDangerousQuery,
			Regex:       regexp.MustCompile(`(?i)\bDROP\s+DATABASE\b`),
			Description: "Detects DROP DATABASE statement",
			Severity:    10,
		},
		{
			Name:        "truncate_table",
			Category:    CategoryDangerousQuery,
			Regex:       regexp.MustCompile(`(?i)\bTRUNCATE\s+TABLE\b`),
			Description: "Detects TRUNCATE TABLE statement",
			Severity:    10,
		},
		{
			Name:        "alter_table",
			Category:    CategoryDangerousQuery,
			Regex:       regexp.MustCompile(`(?i)\bALTER\s+TABLE\b`),
			Description: "Detects ALTER TABLE statement (schema modification)",
			Severity:    8,
		},
		{
			Name:        "delete_without_where",
			Category:    CategoryDangerousQuery,
			Regex:       regexp.MustCompile(`(?i)\bDELETE\s+FROM\s+\w+\s*(?:;|$)`),
			Description: "Detects DELETE FROM without WHERE clause",
			Severity:    9,
		},
		{
			Name:        "create_user",
			Category:    CategoryDangerousQuery,
			Regex:       regexp.MustCompile(`(?i)\bCREATE\s+USER\b`),
			Description: "Detects CREATE USER statement",
			Severity:    9,
		},
		{
			Name:        "grant_privileges",
			Category:    CategoryDangerousQuery,
			Regex:       regexp.MustCompile(`(?i)\bGRANT\s+`),
			Description: "Detects GRANT privilege statement",
			Severity:    9,
		},
		{
			Name:        "revoke_privileges",
			Category:    CategoryDangerousQuery,
			Regex:       regexp.MustCompile(`(?i)\bREVOKE\s+`),
			Description: "Detects REVOKE privilege statement",
			Severity:    9,
		},
	}
}

// TestOnlyPattern creates a pattern for testing purposes.
// This function should only be used in tests.
func TestOnlyPattern(name string, regex string, category Category) *Pattern {
	return &Pattern{
		Name:        name,
		Category:    category,
		Regex:       regexp.MustCompile(regex),
		Description: "Test pattern",
		Severity:    5,
	}
}
