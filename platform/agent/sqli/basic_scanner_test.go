package sqli

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestNewBasicScanner(t *testing.T) {
	t.Run("default configuration", func(t *testing.T) {
		scanner := NewBasicScanner()
		if scanner == nil {
			t.Fatal("NewBasicScanner returned nil")
		}
		if scanner.patterns == nil {
			t.Error("patterns should not be nil")
		}
		if scanner.maxInputLen != 1048576 {
			t.Errorf("maxInputLen = %d, want %d", scanner.maxInputLen, 1048576)
		}
		if scanner.snippetLen != 100 {
			t.Errorf("snippetLen = %d, want %d", scanner.snippetLen, 100)
		}
	})

	t.Run("with custom options", func(t *testing.T) {
		customPatterns := &PatternSet{patterns: []*Pattern{}}
		scanner := NewBasicScanner(
			WithPatternSet(customPatterns),
			WithMaxInputLength(500),
			WithSnippetLength(50),
		)
		if scanner.patterns != customPatterns {
			t.Error("custom pattern set not applied")
		}
		if scanner.maxInputLen != 500 {
			t.Errorf("maxInputLen = %d, want %d", scanner.maxInputLen, 500)
		}
		if scanner.snippetLen != 50 {
			t.Errorf("snippetLen = %d, want %d", scanner.snippetLen, 50)
		}
	})
}

func TestBasicScanner_Mode(t *testing.T) {
	scanner := NewBasicScanner()
	if got := scanner.Mode(); got != ModeBasic {
		t.Errorf("Mode() = %v, want %v", got, ModeBasic)
	}
}

func TestBasicScanner_IsEnterprise(t *testing.T) {
	scanner := NewBasicScanner()
	if got := scanner.IsEnterprise(); got != false {
		t.Errorf("IsEnterprise() = %v, want false", got)
	}
}

func TestBasicScanner_Scan_Detection(t *testing.T) {
	scanner := NewBasicScanner()
	ctx := context.Background()

	tests := []struct {
		name           string
		input          string
		scanType       ScanType
		wantDetected   bool
		wantCategory   Category
		wantPatternIn  []string // Pattern name should contain one of these
	}{
		// UNION-based injections
		{
			name:          "union select",
			input:         "SELECT * FROM users WHERE id=1 UNION SELECT password FROM admin",
			scanType:      ScanTypeInput,
			wantDetected:  true,
			wantCategory:  CategoryUnionBased,
			wantPatternIn: []string{"union"},
		},
		{
			name:          "union all select",
			input:         "1 UNION ALL SELECT username, password FROM users",
			scanType:      ScanTypeInput,
			wantDetected:  true,
			wantCategory:  CategoryUnionBased,
			wantPatternIn: []string{"union"},
		},
		{
			name:          "union injection after quote",
			input:         "' UNION SELECT * FROM users--",
			scanType:      ScanTypeInput,
			wantDetected:  true,
			wantCategory:  CategoryUnionBased,
			wantPatternIn: []string{"union"},
		},

		// Boolean-based blind injections
		{
			name:          "or 1=1",
			input:         "admin' OR 1=1--",
			scanType:      ScanTypeInput,
			wantDetected:  true,
			wantCategory:  CategoryBooleanBlind,
			wantPatternIn: []string{"or"},
		},
		{
			name:          "or 'a'='a'",
			input:         "' OR 'a'='a'",
			scanType:      ScanTypeInput,
			wantDetected:  true,
			wantCategory:  CategoryBooleanBlind,
			wantPatternIn: []string{"or"},
		},

		// Time-based blind injections
		{
			name:          "sleep function",
			input:         "1; SELECT SLEEP(5)--",
			scanType:      ScanTypeInput,
			wantDetected:  true,
			wantCategory:  CategoryTimeBased,
			wantPatternIn: []string{"sleep"},
		},
		{
			name:          "waitfor delay",
			input:         "'; WAITFOR DELAY '0:0:5'--",
			scanType:      ScanTypeInput,
			wantDetected:  true,
			wantCategory:  CategoryTimeBased,
			wantPatternIn: []string{"waitfor"},
		},
		{
			name:          "pg_sleep",
			input:         "'; SELECT PG_SLEEP(5)--",
			scanType:      ScanTypeInput,
			wantDetected:  true,
			wantCategory:  CategoryTimeBased,
			wantPatternIn: []string{"pg_sleep"},
		},
		{
			name:          "benchmark",
			input:         "SELECT BENCHMARK(10000000, SHA1('test'))",
			scanType:      ScanTypeInput,
			wantDetected:  true,
			wantCategory:  CategoryTimeBased,
			wantPatternIn: []string{"benchmark"},
		},

		// Stacked queries
		{
			name:          "drop table",
			input:         "1; DROP TABLE users--",
			scanType:      ScanTypeInput,
			wantDetected:  true,
			wantCategory:  CategoryStackedQueries,
			wantPatternIn: []string{"drop"},
		},
		{
			name:          "drop database",
			input:         "'; DROP DATABASE production--",
			scanType:      ScanTypeInput,
			wantDetected:  true,
			wantCategory:  CategoryStackedQueries,
			wantPatternIn: []string{"drop"},
		},
		{
			name:          "delete from",
			input:         "1; DELETE FROM users WHERE 1=1--",
			scanType:      ScanTypeInput,
			wantDetected:  true,
			wantCategory:  CategoryStackedQueries,
			wantPatternIn: []string{"delete"},
		},
		{
			name:          "update set",
			input:         "'; UPDATE users SET admin=1--",
			scanType:      ScanTypeInput,
			wantDetected:  true,
			wantCategory:  CategoryStackedQueries,
			wantPatternIn: []string{"update"},
		},
		{
			name:          "insert into",
			input:         "'; INSERT INTO users VALUES('hacker','password')--",
			scanType:      ScanTypeInput,
			wantDetected:  true,
			wantCategory:  CategoryStackedQueries,
			wantPatternIn: []string{"insert"},
		},

		// Dangerous query patterns (non-stacked DDL/privilege operations)
		{
			name:          "truncate table",
			input:         "TRUNCATE TABLE users",
			scanType:      ScanTypeInput,
			wantDetected:  true,
			wantCategory:  CategoryDangerousQuery,
			wantPatternIn: []string{"truncate"},
		},
		{
			name:          "alter table",
			input:         "ALTER TABLE users ADD COLUMN backdoor VARCHAR(255)",
			scanType:      ScanTypeInput,
			wantDetected:  true,
			wantCategory:  CategoryDangerousQuery,
			wantPatternIn: []string{"alter"},
		},
		{
			name:          "delete without where",
			input:         "DELETE FROM users;",
			scanType:      ScanTypeInput,
			wantDetected:  true,
			wantCategory:  CategoryDangerousQuery,
			wantPatternIn: []string{"delete"},
		},
		{
			name:          "create user",
			input:         "CREATE USER hacker IDENTIFIED BY 'password123'",
			scanType:      ScanTypeInput,
			wantDetected:  true,
			wantCategory:  CategoryDangerousQuery,
			wantPatternIn: []string{"create_user"},
		},
		{
			name:          "grant privileges",
			input:         "GRANT ALL PRIVILEGES ON *.* TO 'hacker'@'%'",
			scanType:      ScanTypeInput,
			wantDetected:  true,
			wantCategory:  CategoryDangerousQuery,
			wantPatternIn: []string{"grant"},
		},
		{
			name:          "revoke privileges",
			input:         "REVOKE SELECT ON database.* FROM 'user'@'localhost'",
			scanType:      ScanTypeInput,
			wantDetected:  true,
			wantCategory:  CategoryDangerousQuery,
			wantPatternIn: []string{"revoke"},
		},
		{
			name:          "standalone drop table",
			input:         "DROP TABLE sensitive_data",
			scanType:      ScanTypeInput,
			wantDetected:  true,
			wantCategory:  CategoryDangerousQuery,
			wantPatternIn: []string{"drop"},
		},

		// Generic patterns
		{
			name:          "information_schema",
			input:         "SELECT * FROM INFORMATION_SCHEMA.TABLES",
			scanType:      ScanTypeInput,
			wantDetected:  true,
			wantCategory:  CategoryGeneric,
			wantPatternIn: []string{"information_schema"},
		},
		{
			name:          "load_file",
			input:         "SELECT LOAD_FILE('/etc/passwd')",
			scanType:      ScanTypeInput,
			wantDetected:  true,
			wantCategory:  CategoryGeneric,
			wantPatternIn: []string{"load_file"},
		},
		{
			name:          "into outfile",
			input:         "SELECT '<?php system($_GET[\"cmd\"]); ?>' INTO OUTFILE '/var/www/shell.php'",
			scanType:      ScanTypeInput,
			wantDetected:  true,
			wantCategory:  CategoryGeneric,
			wantPatternIn: []string{"outfile"},
		},

		// Safe inputs (no detection expected)
		{
			name:         "normal select",
			input:        "What are the top 10 products by sales?",
			scanType:     ScanTypeInput,
			wantDetected: false,
		},
		{
			name:         "normal text",
			input:        "Hello, how can I help you today?",
			scanType:     ScanTypeInput,
			wantDetected: false,
		},
		{
			name:         "empty input",
			input:        "",
			scanType:     ScanTypeInput,
			wantDetected: false,
		},
		{
			name:         "json response",
			input:        `{"name": "John", "email": "john@example.com"}`,
			scanType:     ScanTypeResponse,
			wantDetected: false,
		},
		{
			name:         "safe sql-like text",
			input:        "Please select your favorite option from the dropdown",
			scanType:     ScanTypeInput,
			wantDetected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := scanner.Scan(ctx, tt.input, tt.scanType)

			if result.Detected != tt.wantDetected {
				t.Errorf("Detected = %v, want %v", result.Detected, tt.wantDetected)
			}

			if tt.wantDetected {
				if result.Category != tt.wantCategory {
					t.Errorf("Category = %v, want %v", result.Category, tt.wantCategory)
				}

				if len(tt.wantPatternIn) > 0 {
					found := false
					for _, sub := range tt.wantPatternIn {
						if strings.Contains(strings.ToLower(result.Pattern), strings.ToLower(sub)) {
							found = true
							break
						}
					}
					if !found {
						t.Errorf("Pattern = %v, want to contain one of %v", result.Pattern, tt.wantPatternIn)
					}
				}

				if result.Confidence != 1.0 {
					t.Errorf("Confidence = %v, want 1.0", result.Confidence)
				}

				if !result.Blocked {
					t.Error("Blocked should be true when detected")
				}
			}

			if result.ScanType != tt.scanType {
				t.Errorf("ScanType = %v, want %v", result.ScanType, tt.scanType)
			}

			if result.Mode != ModeBasic {
				t.Errorf("Mode = %v, want %v", result.Mode, ModeBasic)
			}

			if result.Duration <= 0 {
				t.Error("Duration should be positive")
			}
		})
	}
}

func TestBasicScanner_Scan_ResponseType(t *testing.T) {
	scanner := NewBasicScanner()
	ctx := context.Background()

	// Test that response scanning works the same as input scanning
	maliciousResponse := "The query returned: admin' UNION SELECT password FROM users--"
	result := scanner.Scan(ctx, maliciousResponse, ScanTypeResponse)

	if !result.Detected {
		t.Error("Should detect SQL injection in response")
	}
	if result.ScanType != ScanTypeResponse {
		t.Errorf("ScanType = %v, want %v", result.ScanType, ScanTypeResponse)
	}
}

func TestBasicScanner_Scan_ContextCancellation(t *testing.T) {
	scanner := NewBasicScanner()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	result := scanner.Scan(ctx, "UNION SELECT * FROM users", ScanTypeInput)

	if result.Detected {
		t.Error("Should not detect when context is cancelled")
	}
	if result.Metadata == nil || result.Metadata["error"] != "context cancelled" {
		t.Error("Should have error metadata for context cancellation")
	}
}

func TestBasicScanner_Scan_LongInput(t *testing.T) {
	scanner := NewBasicScanner(WithMaxInputLength(100))
	ctx := context.Background()

	// Create input longer than max
	longInput := strings.Repeat("a", 50) + "UNION SELECT * FROM users" + strings.Repeat("b", 100)

	result := scanner.Scan(ctx, longInput, ScanTypeInput)

	// Should not detect because injection is beyond truncation point
	if result.Detected {
		t.Error("Should not detect injection beyond truncation point")
	}

	// Create input with injection within truncation
	shortInput := "UNION SELECT * FROM users" + strings.Repeat("b", 200)
	result = scanner.Scan(ctx, shortInput, ScanTypeInput)

	if !result.Detected {
		t.Error("Should detect injection within truncation point")
	}
}

func TestBasicScanner_Scan_InputSnippet(t *testing.T) {
	scanner := NewBasicScanner(WithSnippetLength(20))
	ctx := context.Background()

	longMalicious := "UNION SELECT password, username, email, address FROM users WHERE 1=1"
	result := scanner.Scan(ctx, longMalicious, ScanTypeInput)

	if !result.Detected {
		t.Fatal("Should detect injection")
	}

	// Input snippet should be truncated
	if len(result.Input) > 25 { // 20 + "..."
		t.Errorf("Input snippet should be truncated, got length %d", len(result.Input))
	}
}

func TestBasicScanner_Registration(t *testing.T) {
	// Test that basic scanner is properly registered
	scanner, err := NewScanner(ModeBasic)
	if err != nil {
		t.Fatalf("NewScanner(ModeBasic) error = %v", err)
	}
	if scanner == nil {
		t.Fatal("NewScanner(ModeBasic) returned nil")
	}
	if _, ok := scanner.(*BasicScanner); !ok {
		t.Errorf("NewScanner(ModeBasic) returned %T, want *BasicScanner", scanner)
	}
}

func TestBasicScanner_Scan_Performance(t *testing.T) {
	scanner := NewBasicScanner()
	ctx := context.Background()

	// Typical input size
	input := "What is the weather forecast for tomorrow in New York?"

	start := time.Now()
	iterations := 1000
	for i := 0; i < iterations; i++ {
		scanner.Scan(ctx, input, ScanTypeInput)
	}
	elapsed := time.Since(start)

	avgTime := elapsed / time.Duration(iterations)
	if avgTime > time.Millisecond {
		t.Errorf("Average scan time = %v, want < 1ms", avgTime)
	}
}

func TestPatternSet(t *testing.T) {
	ps := NewPatternSet()

	t.Run("has patterns", func(t *testing.T) {
		patterns := ps.Patterns()
		if len(patterns) == 0 {
			t.Error("PatternSet should have patterns")
		}
	})

	t.Run("patterns by category", func(t *testing.T) {
		categories := []Category{
			CategoryUnionBased,
			CategoryBooleanBlind,
			CategoryTimeBased,
			CategoryErrorBased,
			CategoryStackedQueries,
			CategoryCommentInjection,
			CategoryGeneric,
		}

		for _, cat := range categories {
			patterns := ps.PatternsByCategory(cat)
			if len(patterns) == 0 {
				t.Errorf("No patterns for category %v", cat)
			}
			for _, p := range patterns {
				if p.Category != cat {
					t.Errorf("Pattern %s has category %v, expected %v", p.Name, p.Category, cat)
				}
			}
		}
	})

	t.Run("all patterns have required fields", func(t *testing.T) {
		for _, p := range ps.Patterns() {
			if p.Name == "" {
				t.Error("Pattern should have a name")
			}
			if p.Regex == nil {
				t.Errorf("Pattern %s should have a regex", p.Name)
			}
			if p.Category == "" {
				t.Errorf("Pattern %s should have a category", p.Name)
			}
			if p.Description == "" {
				t.Errorf("Pattern %s should have a description", p.Name)
			}
			if p.Severity < 1 || p.Severity > 10 {
				t.Errorf("Pattern %s severity %d should be 1-10", p.Name, p.Severity)
			}
		}
	})
}

func TestTestOnlyPattern(t *testing.T) {
	p := TestOnlyPattern("test", `\bTEST\b`, CategoryGeneric)
	if p.Name != "test" {
		t.Errorf("Name = %v, want test", p.Name)
	}
	if p.Category != CategoryGeneric {
		t.Errorf("Category = %v, want %v", p.Category, CategoryGeneric)
	}
	if !p.Regex.MatchString("TEST pattern") {
		t.Error("Regex should match TEST")
	}
}

// Benchmark tests
func BenchmarkBasicScanner_SafeInput(b *testing.B) {
	scanner := NewBasicScanner()
	ctx := context.Background()
	input := "What is the weather forecast for tomorrow?"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		scanner.Scan(ctx, input, ScanTypeInput)
	}
}

func BenchmarkBasicScanner_MaliciousInput(b *testing.B) {
	scanner := NewBasicScanner()
	ctx := context.Background()
	input := "admin' OR 1=1--"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		scanner.Scan(ctx, input, ScanTypeInput)
	}
}

func BenchmarkBasicScanner_LongInput(b *testing.B) {
	scanner := NewBasicScanner()
	ctx := context.Background()
	input := strings.Repeat("This is a normal text without any SQL injection. ", 100)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		scanner.Scan(ctx, input, ScanTypeInput)
	}
}

// TestSanitizeForLog tests the sanitization of sensitive data in log output
func TestSanitizeForLog(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "password field redacted",
			input:    "SELECT * FROM users WHERE password='secret123'",
			expected: "SELECT * FROM users WHERE [REDACTED_PASSWORD]",
		},
		{
			name:     "api_key redacted",
			input:    "api_key=sk-12345678 AND user_id=1",
			expected: "[REDACTED_KEY] AND user_id=1",
		},
		{
			name:     "token redacted",
			input:    "Authorization: token=abc123xyz",
			expected: "Authorization: [REDACTED_TOKEN]",
		},
		{
			name:     "newlines replaced with spaces",
			input:    "line1\nline2\nline3",
			expected: "line1 line2 line3",
		},
		{
			name:     "no sensitive data unchanged",
			input:    "SELECT id, name FROM users WHERE id = 1",
			expected: "SELECT id, name FROM users WHERE id = 1",
		},
		{
			name:     "multiple sensitive fields",
			input:    "password=secret api_key=key123",
			expected: "[REDACTED_PASSWORD] [REDACTED_KEY]",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sanitizeForLog(tt.input)
			if result != tt.expected {
				t.Errorf("sanitizeForLog(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}
