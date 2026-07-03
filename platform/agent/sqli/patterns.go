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
		{
			Name:     "string_term_comment",
			Category: CategoryCommentInjection,
			// Mirrors the sys_sqli_string_term_comment row (migration core/139,
			// #2811). The OWASP comment-out auth bypass (admin' --, x'--, x'#)
			// breaks out of the surrounding SQL literal with a lone trailing
			// quote and comments out the rest of the line. Two gates keep
			// benign input out: (1) first-quote breakout ^[^'"]*['"] — the value
			// has no earlier quote, so a balanced quoted token (echo 'done' #,
			// region='EU' --) whose first quote is followed by its own content
			// does not match; (2) the comment ends the line, so prose/doc text
			// after the comment does not match. The fully-concatenated form
			// (WHERE user='admin' --' AND ...) is a documented residual —
			// regex-indistinguishable from a benign trailing SQL comment.
			Regex:       regexp.MustCompile(`(?m)^[^'"\r\n]*['"][ \t)]*(?:--|#)[ \t-]*\r?$`),
			Description: "Detects a breakout string-literal terminator directly followed by a line comment ending the line (comment-out auth bypass)",
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
			Name:     "admin_bypass",
			Category: CategoryGeneric,
			// Mirrors the sys_sqli_admin_bypass row (migration core/135, #2802).
			// Requires a quote/paren breakout before OR (or a bare digit tautology)
			// and the `--` comment on the same line, so Markdown table dividers and
			// newline-spanning prose no longer satisfy the pattern.
			Regex:       regexp.MustCompile(`(?i)(?:['"][\s)]*OR\s+\(?['"]?[^'"\r\n]{0,64}?['"]?\s*=\s*\(?['"]?[^'"\r\n]{0,64}?['"]?[ \t]*--|\bOR\s+\d{1,10}\s*=\s*\d{1,10}[ \t]*--)`),
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
			Regex:       regexp.MustCompile(`(?im)\bDROP\s+TABLE\s+(?:IF\s+EXISTS\s+)?(?:(?s:/\*.*?\*/)\s*)?[\x60"'\w.$\[\]]+\s*(?:;|,|--|\#|\z|\bCASCADE\b|\bRESTRICT\b)`),
			Description: "Detects DROP TABLE statement",
			Severity:    10,
		},
		{
			Name:        "drop_database",
			Category:    CategoryDangerousQuery,
			Regex:       regexp.MustCompile(`(?im)\bDROP\s+DATABASE\s+(?:IF\s+EXISTS\s+)?(?:(?s:/\*.*?\*/)\s*)?[\x60"'\w.$\[\]]+\s*(?:;|,|--|\#|\z)`),
			Description: "Detects DROP DATABASE statement",
			Severity:    10,
		},
		{
			Name:        "truncate_table",
			Category:    CategoryDangerousQuery,
			Regex:       regexp.MustCompile(`(?im)\bTRUNCATE\s+TABLE\s+(?:(?s:/\*.*?\*/)\s*)?[\x60"'\w.$\[\]]+\s*(?:;|,|--|\#|\z|\bCASCADE\b|\bRESTART\b|\bCONTINUE\b)`),
			Description: "Detects TRUNCATE TABLE statement",
			Severity:    10,
		},
		{
			Name:        "alter_table",
			Category:    CategoryDangerousQuery,
			Regex:       regexp.MustCompile(`(?im)\bALTER\s+TABLE\s+(?:IF\s+EXISTS\s+)?(?:(?s:/\*.*?\*/)\s*)?[\x60"'\w.$\[\]]+\s+(?:ADD|DROP|ALTER|RENAME|MODIFY|CHANGE|ENABLE|DISABLE|OWNER|SET)\b`),
			Description: "Detects ALTER TABLE statement (schema modification)",
			Severity:    8,
		},
		{
			Name:        "delete_without_where",
			Category:    CategoryDangerousQuery,
			Regex:       regexp.MustCompile(`(?im)\bDELETE\s+FROM\s+[\x60"'\w.$\[\]]+\s*(?:;|--|\#|\z)`),
			Description: "Detects DELETE FROM without WHERE clause",
			Severity:    9,
		},
		{
			Name:        "create_user",
			Category:    CategoryDangerousQuery,
			Regex:       regexp.MustCompile(`(?im)\bCREATE\s+USER\s+(?:IF\s+NOT\s+EXISTS\s+)?(?:(?s:/\*.*?\*/)\s*)?[\x60"'\w.$\[\]]+\s*(?:;|,|--|\#|@|(?:\bWITH\s+)?\b(?:IDENTIFIED|SUPERUSER|CREATEDB|CREATEROLE|LOGIN|NOLOGIN|PASSWORD|VALID)\b)`),
			Description: "Detects CREATE USER statement",
			Severity:    9,
		},
		{
			Name:        "grant_privileges",
			Category:    CategoryDangerousQuery,
			Regex:       regexp.MustCompile(`(?im)\bGRANT\s+(?:ALL(?:\s+PRIVILEGES)?|SELECT|INSERT|UPDATE|DELETE|TRUNCATE|MAINTAIN|EXECUTE|USAGE|CREATE|CONNECT|TEMPORARY|TEMP|TRIGGER|REFERENCES|INDEX|ALTER|DROP)\b[^;]{0,200}?\bON\b[^;]{0,200}?\bTO\s+(?:GROUP\s+|ROLE\s+|USER\s+)?(?:[\x60'"]|\w+\s*(?:;|,|@|$|--|\#|\bWITH\b|\bCASCADE\b))`),
			Description: "Detects GRANT privilege statement",
			Severity:    9,
		},
		{
			Name:     "revoke_privileges",
			Category: CategoryDangerousQuery,
			// Mirrors the sys_sqli_revoke row (migration core/135, #2802). Requires
			// SQL grammar — a privilege keyword plus ON ... FROM with an SQL-shaped
			// grantee (quoted/backtick, user@host, or a bareword terminated by
			// ;/,/@/end-of-line, optionally GROUP/ROLE/USER-qualified), or the MySQL
			// `..., GRANT OPTION FROM` form — so English uses of the verb ("will
			// revoke immediately after the single edit call") no longer match.
			// Newlines are tolerated between REVOKE/ON/FROM (attacker-controlled
			// formatting).
			Regex:       regexp.MustCompile(`(?im)\bREVOKE\s+(?:GRANT\s+OPTION\s+FOR\s+)?(?:ALL(?:\s+PRIVILEGES)?|SELECT|INSERT|UPDATE|DELETE|TRUNCATE|MAINTAIN|EXECUTE|USAGE|CREATE|CONNECT|TEMPORARY|TEMP|TRIGGER|REFERENCES|INDEX|ALTER|DROP)\b(?:[^;]{0,200}?\bON\b[^;]{0,200}?\bFROM\s+(?:GROUP\s+|ROLE\s+|USER\s+)?(?:[\x60'"]|\w+\s*(?:;|,|@|$|--|\#|\bCASCADE\b|\bRESTRICT\b))|\s*,\s*GRANT\s+OPTION\s+FROM\b)`),
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
