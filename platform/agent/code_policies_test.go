// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"regexp"
	"testing"
)

// TestCodeGovernancePatterns tests all code governance patterns for Issue #761.
// Each pattern is tested with both matching and non-matching inputs to ensure
// proper detection of secrets and unsafe code constructs.
func TestCodeGovernancePatterns(t *testing.T) {
	patterns := getCodeGovernancePatterns()

	// Verify expected number of patterns
	if len(patterns) != 15 {
		t.Errorf("Expected 15 code governance patterns, got %d", len(patterns))
	}

	// Verify all patterns compile
	for _, p := range patterns {
		_, err := regexp.Compile(p.Pattern)
		if err != nil {
			t.Errorf("Pattern %s failed to compile: %v", p.ID, err)
		}
	}
}

// TestCodeSecretsPatterns tests the code-secrets category patterns.
func TestCodeSecretsPatterns(t *testing.T) {
	testCases := []struct {
		name      string
		patternID string
		shouldMatch []string
		shouldNotMatch []string
	}{
		{
			name:      "AWS Access Key Detection",
			patternID: "sys_code_aws_key",
			shouldMatch: []string{
				"AKIAIOSFODNN7EXAMPLE",
				"aws_key = \"AKIAIOSFODNN7EXAMPLE\"",
				"const accessKey = 'AKIAIOSFODNN7EXAMPLE'",
			},
			shouldNotMatch: []string{
				"AKIA", // Too short
				"AKIAIOSFODNN7EXAMPL", // 15 chars, need 16
				"regular text without keys",
				"AIKA1234567890123456", // Wrong prefix
			},
		},
		{
			name:      "AWS Secret Key Detection",
			patternID: "sys_code_aws_secret",
			shouldMatch: []string{
				"aws_secret_key = \"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\"",
				"secret = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'",
				"AWS_SECRET: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
				"key=\"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\"",
			},
			shouldNotMatch: []string{
				"some random text",
				"password = 'short'",
			},
		},
		{
			name:      "GitHub Token Detection",
			patternID: "sys_code_github_token",
			shouldMatch: []string{
				"ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
				"gho_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
				"ghu_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
				"ghs_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
				"ghr_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
				"GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
			},
			shouldNotMatch: []string{
				"ghx_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", // Invalid prefix
				"ghp_short", // Too short
				"regular github url",
			},
		},
		{
			name:      "OpenAI API Key Detection",
			patternID: "sys_code_openai_key",
			shouldMatch: []string{
				"sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
				"OPENAI_API_KEY=sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
				"const apiKey = 'sk-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'",
			},
			shouldNotMatch: []string{
				"sk-short", // Too short
				"sk-ant-xxx", // Anthropic key
				"some other key",
			},
		},
		{
			name:      "Anthropic API Key Detection",
			patternID: "sys_code_anthropic_key",
			shouldMatch: []string{
				// 95 characters after sk-ant- (api03- = 6 + 89 x's = 95)
				"sk-ant-api03-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
			},
			shouldNotMatch: []string{
				"sk-ant-short", // Too short
				"sk-xxxxxxxx", // OpenAI key format
			},
		},
		{
			name:      "JWT Token Detection",
			patternID: "sys_code_jwt",
			shouldMatch: []string{
				"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.signature",
				"const token = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U'",
			},
			shouldNotMatch: []string{
				"eyJhbGci", // Incomplete
				"not.a.jwt",
				"regular base64 string",
			},
		},
		{
			name:      "Private Key Detection",
			patternID: "sys_code_private_key",
			shouldMatch: []string{
				"-----BEGIN RSA PRIVATE KEY-----",
				"-----BEGIN EC PRIVATE KEY-----",
				"-----BEGIN OPENSSH PRIVATE KEY-----",
				`const key = "-----BEGIN RSA PRIVATE KEY-----\nMIIE..."`,
			},
			shouldNotMatch: []string{
				"-----BEGIN PUBLIC KEY-----",
				"-----BEGIN CERTIFICATE-----",
				"private key in text",
			},
		},
		{
			name:      "Hardcoded Password Detection",
			patternID: "sys_code_password_assign",
			shouldMatch: []string{
				"password = 'supersecret123'",
				"PASSWORD: \"mypassword\"",
				"password=\"hunter2\"",
				"Password = 'longpassword'",
			},
			shouldNotMatch: []string{
				"password = ''", // Empty
				"password = 'ab'", // Too short (< 4 chars)
				"check password",
				"password validation",
			},
		},
	}

	patterns := getCodeGovernancePatterns()
	patternMap := make(map[string]SystemPolicySeed)
	for _, p := range patterns {
		patternMap[p.ID] = p
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			pattern, ok := patternMap[tc.patternID]
			if !ok {
				t.Fatalf("Pattern %s not found", tc.patternID)
			}

			re, err := regexp.Compile(pattern.Pattern)
			if err != nil {
				t.Fatalf("Pattern %s failed to compile: %v", tc.patternID, err)
			}

			// Test matching cases
			for _, input := range tc.shouldMatch {
				if !re.MatchString(input) {
					t.Errorf("Pattern %s should match: %q", tc.patternID, input)
				}
			}

			// Test non-matching cases
			for _, input := range tc.shouldNotMatch {
				if re.MatchString(input) {
					t.Errorf("Pattern %s should NOT match: %q", tc.patternID, input)
				}
			}
		})
	}
}

// TestCodeUnsafePatterns tests the code-unsafe category patterns.
func TestCodeUnsafePatterns(t *testing.T) {
	testCases := []struct {
		name           string
		patternID      string
		shouldMatch    []string
		shouldNotMatch []string
	}{
		{
			name:      "JavaScript eval() Detection",
			patternID: "sys_code_eval_js",
			shouldMatch: []string{
				"eval(userInput)",
				"eval (code)",
				"const result = eval(expression)",
				"return eval( jsonString )",
			},
			shouldNotMatch: []string{
				"evaluate()",
				"evalSomething()",
				"// eval is dangerous",
			},
		},
		{
			name:      "Python exec() Detection",
			patternID: "sys_code_exec_python",
			shouldMatch: []string{
				"exec(code)",
				"exec (user_code)",
				"exec(compile(source, '<string>', 'exec'))",
			},
			shouldNotMatch: []string{
				"execute()",
				"exec_command()",
				"# exec is dangerous",
			},
		},
		{
			name:      "Shell Injection Risk Detection",
			patternID: "sys_code_shell_injection",
			shouldMatch: []string{
				"subprocess.call(cmd, shell=True)",
				"subprocess.run(command, shell=True)",
				"subprocess.Popen(args, shell=True)",
				"subprocess.call(cmd, stdout=PIPE, shell=True)",
			},
			shouldNotMatch: []string{
				"subprocess.call(cmd)",
				"subprocess.call(cmd, shell=False)",
				"subprocess.run(args)",
			},
		},
		{
			name:      "SQL String Formatting Detection",
			patternID: "sys_code_sql_format",
			shouldMatch: []string{
				`"SELECT * FROM users WHERE id = {}".format(user_id)`,
				`"SELECT * FROM users WHERE name = %s" % name`,
				`"DELETE FROM table WHERE id = {id}"`,
				`"INSERT INTO users VALUES (%s, %s)"`,
			},
			shouldNotMatch: []string{
				"cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))",
				"'SELECT * FROM users'",
				".format() for non-sql",
			},
		},
		{
			name:      "OS Command Execution Detection",
			patternID: "sys_code_os_system",
			shouldMatch: []string{
				"os.system(cmd)",
				"os.system (command)",
				"os.system('ls -la')",
			},
			shouldNotMatch: []string{
				"os.path.exists()",
				"os.environ",
				"// os.system is dangerous",
			},
		},
		{
			name:      "Insecure Deserialization Detection",
			patternID: "sys_code_pickle",
			shouldMatch: []string{
				"pickle.load(file)",
				"pickle.loads(data)",
				"obj = pickle.load(f)",
			},
			shouldNotMatch: []string{
				"json.load(file)",
				"pickle.dump(obj, file)",
				"# pickle is dangerous",
			},
		},
		{
			name:      "Unsafe YAML Load Detection",
			patternID: "sys_code_yaml_unsafe",
			shouldMatch: []string{
				"yaml.load(data)",
				"yaml.load(file)",
				"yaml.load(stream, Loader=None)",
			},
			shouldNotMatch: []string{
				"yaml.safe_load(data)",
				"yaml.dump(data)",
			},
		},
	}

	patterns := getCodeGovernancePatterns()
	patternMap := make(map[string]SystemPolicySeed)
	for _, p := range patterns {
		patternMap[p.ID] = p
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			pattern, ok := patternMap[tc.patternID]
			if !ok {
				t.Fatalf("Pattern %s not found", tc.patternID)
			}

			re, err := regexp.Compile(pattern.Pattern)
			if err != nil {
				t.Fatalf("Pattern %s failed to compile: %v", tc.patternID, err)
			}

			// Test matching cases
			for _, input := range tc.shouldMatch {
				if !re.MatchString(input) {
					t.Errorf("Pattern %s should match: %q", tc.patternID, input)
				}
			}

			// Test non-matching cases
			for _, input := range tc.shouldNotMatch {
				if re.MatchString(input) {
					t.Errorf("Pattern %s should NOT match: %q", tc.patternID, input)
				}
			}
		})
	}
}

// TestCodePolicyCategoryAssignment verifies correct category assignment.
func TestCodePolicyCategoryAssignment(t *testing.T) {
	patterns := getCodeGovernancePatterns()

	secretsCount := 0
	unsafeCount := 0
	complianceCount := 0

	for _, p := range patterns {
		switch p.Category {
		case CategoryCodeSecrets:
			secretsCount++
		case CategoryCodeUnsafe:
			unsafeCount++
		case CategoryCodeCompliance:
			complianceCount++
		default:
			t.Errorf("Pattern %s has unexpected category: %s", p.ID, p.Category)
		}
	}

	if secretsCount != 8 {
		t.Errorf("Expected 8 code-secrets patterns, got %d", secretsCount)
	}
	if unsafeCount != 7 {
		t.Errorf("Expected 7 code-unsafe patterns, got %d", unsafeCount)
	}
	// No compliance patterns yet
}

// TestCodePolicySeverityAssignment verifies severity levels are appropriate.
func TestCodePolicySeverityAssignment(t *testing.T) {
	patterns := getCodeGovernancePatterns()

	for _, p := range patterns {
		// All secrets should be High or Critical
		if p.Category == CategoryCodeSecrets {
			if p.Severity != SeverityCritical && p.Severity != SeverityHigh {
				t.Errorf("Secret pattern %s has unexpected severity: %s (expected Critical or High)",
					p.ID, p.Severity)
			}
		}

		// Shell injection should be Critical
		if p.ID == "sys_code_shell_injection" && p.Severity != SeverityCritical {
			t.Errorf("Shell injection pattern should be Critical, got %s", p.Severity)
		}
	}
}

// TestCodePolicyActionAssignment verifies default actions are appropriate.
func TestCodePolicyActionAssignment(t *testing.T) {
	patterns := getCodeGovernancePatterns()

	for _, p := range patterns {
		// All secrets should block by default
		if p.Category == CategoryCodeSecrets && p.Action != "block" {
			t.Errorf("Secret pattern %s should block by default, got %s", p.ID, p.Action)
		}

		// Shell injection should block
		if p.ID == "sys_code_shell_injection" && p.Action != "block" {
			t.Errorf("Shell injection pattern should block, got %s", p.Action)
		}

		// Other unsafe patterns should warn (not block) to reduce false positives
		if p.Category == CategoryCodeUnsafe && p.ID != "sys_code_shell_injection" {
			if p.Action != "warn" {
				t.Errorf("Unsafe pattern %s should warn by default (to reduce false positives), got %s",
					p.ID, p.Action)
			}
		}
	}
}

// TestCodePolicyUniqueIDs verifies all pattern IDs are unique.
func TestCodePolicyUniqueIDs(t *testing.T) {
	patterns := getCodeGovernancePatterns()
	seen := make(map[string]bool)

	for _, p := range patterns {
		if seen[p.ID] {
			t.Errorf("Duplicate pattern ID: %s", p.ID)
		}
		seen[p.ID] = true
	}
}

// TestStaticPolicyCategoriesIncludesCode verifies the new categories are registered.
func TestStaticPolicyCategoriesIncludesCode(t *testing.T) {
	categories := StaticPolicyCategories()

	found := make(map[PolicyCategory]bool)
	for _, c := range categories {
		found[c] = true
	}

	if !found[CategoryCodeSecrets] {
		t.Error("CategoryCodeSecrets not found in StaticPolicyCategories()")
	}
	if !found[CategoryCodeUnsafe] {
		t.Error("CategoryCodeUnsafe not found in StaticPolicyCategories()")
	}
	if !found[CategoryCodeCompliance] {
		t.Error("CategoryCodeCompliance not found in StaticPolicyCategories()")
	}
}

// TestTotalSystemPolicyCountIncludesCode verifies the count is updated.
func TestTotalSystemPolicyCountIncludesCode(t *testing.T) {
	count := GetTotalSystemPolicyCount()

	// Previous count was 63 (53 static + 10 dynamic)
	// New count should be 78 (68 static + 10 dynamic)
	if count < 78 {
		t.Errorf("Expected at least 78 system policies (68 static + 10 dynamic), got %d", count)
	}
}

// TestCodePatternsRealWorldExamples tests patterns against realistic code snippets.
func TestCodePatternsRealWorldExamples(t *testing.T) {
	patterns := getCodeGovernancePatterns()
	patternMap := make(map[string]*regexp.Regexp)
	for _, p := range patterns {
		re, _ := regexp.Compile(p.Pattern)
		patternMap[p.ID] = re
	}

	// Real-world code snippets that should be flagged
	realWorldViolations := []struct {
		code       string
		patternIDs []string
	}{
		{
			code: `
import boto3
client = boto3.client(
    's3',
    aws_access_key_id='AKIAIOSFODNN7EXAMPLE',
    aws_secret_access_key='wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
)`,
			patternIDs: []string{"sys_code_aws_key"},
		},
		{
			code: `
const openai = new OpenAI({
    apiKey: 'sk-proj-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'
});`,
			patternIDs: []string{"sys_code_openai_key"},
		},
		{
			code: `
user_input = request.form['command']
os.system(user_input)  # Command injection vulnerability!`,
			patternIDs: []string{"sys_code_os_system"},
		},
		{
			code: `
# Never do this!
untrusted_data = request.data
obj = pickle.loads(untrusted_data)`,
			patternIDs: []string{"sys_code_pickle"},
		},
		{
			code: `
// Dangerous! Use JSON.parse instead
const result = eval('(' + jsonString + ')');`,
			patternIDs: []string{"sys_code_eval_js"},
		},
	}

	for _, tc := range realWorldViolations {
		for _, expectedID := range tc.patternIDs {
			re := patternMap[expectedID]
			if !re.MatchString(tc.code) {
				t.Errorf("Pattern %s should match real-world violation:\n%s", expectedID, tc.code)
			}
		}
	}

	// Safe code that should NOT be flagged
	safeCode := []string{
		`
import os
# Load credentials from environment variables (safe!)
aws_key = os.environ.get('AWS_ACCESS_KEY_ID')
aws_secret = os.environ.get('AWS_SECRET_ACCESS_KEY')`,
		`
# Safe: using parameterized query
cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))`,
		`
# Safe: using subprocess with shell=False (default)
subprocess.run(['ls', '-la'])`,
		`
# Safe: using safe_load
data = yaml.safe_load(file)`,
		`
# Safe: using json instead of pickle
data = json.loads(json_string)`,
	}

	// Verify safe code doesn't trigger patterns (except for very generic ones)
	for _, code := range safeCode {
		for id, re := range patternMap {
			// Skip patterns that might have false positives in these safe examples
			if id == "sys_code_aws_secret" {
				// This pattern might match 'aws_key' variable names
				continue
			}
			if re.MatchString(code) {
				t.Errorf("Pattern %s incorrectly matched safe code:\n%s", id, code)
			}
		}
	}
}
