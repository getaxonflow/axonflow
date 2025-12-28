// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"testing"
)

func TestDetectCodeInResponse_NoCode(t *testing.T) {
	tests := []struct {
		name     string
		response string
	}{
		{"empty string", ""},
		{"plain text", "This is just a plain text response without any code."},
		{"markdown without code", "# Heading\n\nSome **bold** text and a [link](https://example.com)"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := DetectCodeInResponse(tt.response)
			if result != nil {
				t.Errorf("Expected nil for non-code response, got %+v", result)
			}
		})
	}
}

func TestDetectCodeInResponse_WithCode(t *testing.T) {
	tests := []struct {
		name        string
		response    string
		wantLang    string
		wantType    string
		wantCodeLen bool
		wantSecrets int
		wantUnsafe  int
	}{
		{
			name:        "Python function",
			response:    "Here's a function:\n```python\ndef hello(name):\n    return f\"Hello, {name}!\"\n```",
			wantLang:    "python",
			wantType:    "function",
			wantCodeLen: true,
		},
		{
			name:     "Python class",
			response: "```python\nclass User:\n    def __init__(self, name):\n        self.name = name\n```",
			wantLang: "python",
			wantType: "class",
		},
		{
			name:     "Go function",
			response: "```go\nfunc main() {\n    fmt.Println(\"Hello\")\n}\n```",
			wantLang: "go",
			wantType: "function", // func main() is detected as function first, script detection needs full pattern
		},
		{
			name:       "JavaScript with eval",
			response:   "```javascript\nfunction run(code) {\n    return eval(code);\n}\n```",
			wantLang:   "javascript",
			wantUnsafe: 1,
		},
		{
			name:        "Code with AWS key",
			response:    "```python\naws_access_key_id = \"AKIAIOSFODNN7EXAMPLE\"\naws_secret_access_key = \"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\"\n```",
			wantLang:    "python",
			wantSecrets: 2,
		},
		{
			name:     "TypeScript interface",
			response: "```typescript\ninterface User {\n    name: string;\n    age: number;\n}\n```",
			wantLang: "typescript",
		},
		{
			name:     "SQL query",
			response: "```sql\nSELECT * FROM users WHERE id = 1;\n```",
			wantLang: "sql",
		},
		{
			name:     "Dockerfile",
			response: "```dockerfile\nFROM node:18\nRUN npm install\nCOPY . .\n```",
			wantLang: "dockerfile",
			wantType: "config",
		},
		{
			name:     "YAML config",
			response: "```yaml\napiVersion: v1\nkind: Pod\nmetadata:\n  name: test\n```",
			wantLang: "yaml",
			wantType: "config",
		},
		{
			name:     "Empty code fence",
			response: "```python\n```",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := DetectCodeInResponse(tt.response)

			// Handle empty code fence case
			if tt.name == "Empty code fence" {
				if result != nil {
					t.Errorf("Expected nil for empty code fence, got %+v", result)
				}
				return
			}

			if result == nil {
				t.Fatal("Expected non-nil result for code response")
			}

			if !result.IsCodeOutput {
				t.Error("Expected IsCodeOutput to be true")
			}

			if tt.wantLang != "" && result.Language != tt.wantLang {
				t.Errorf("Language = %q, want %q", result.Language, tt.wantLang)
			}

			if tt.wantType != "" && result.CodeType != tt.wantType {
				t.Errorf("CodeType = %q, want %q", result.CodeType, tt.wantType)
			}

			if tt.wantCodeLen && result.SizeBytes == 0 {
				t.Error("Expected SizeBytes > 0")
			}

			if tt.wantSecrets > 0 && result.SecretsDetected != tt.wantSecrets {
				t.Errorf("SecretsDetected = %d, want %d", result.SecretsDetected, tt.wantSecrets)
			}

			if tt.wantUnsafe > 0 && result.UnsafePatterns != tt.wantUnsafe {
				t.Errorf("UnsafePatterns = %d, want %d", result.UnsafePatterns, tt.wantUnsafe)
			}
		})
	}
}

func TestDetectCodeInResponse_MultipleBlocks(t *testing.T) {
	response := `Here's the solution:

` + "```python" + `
def add(a, b):
    return a + b
` + "```" + `

And the test:

` + "```python" + `
def test_add():
    assert add(1, 2) == 3
` + "```"

	result := DetectCodeInResponse(response)
	if result == nil {
		t.Fatal("Expected non-nil result")
	}

	if result.Language != "python" {
		t.Errorf("Language = %q, want python", result.Language)
	}

	// Should count lines from both blocks
	if result.LineCount < 4 {
		t.Errorf("LineCount = %d, expected at least 4", result.LineCount)
	}
}

func TestDetectLanguage(t *testing.T) {
	tests := []struct {
		name     string
		code     string
		expected string
	}{
		{
			name:     "Go package",
			code:     "package main\n\nimport \"fmt\"",
			expected: "go",
		},
		{
			name:     "Python import",
			code:     "import os\nimport sys",
			expected: "python",
		},
		{
			name:     "TypeScript interface",
			code:     "interface Props {\n    name: string;\n}",
			expected: "typescript",
		},
		{
			name:     "JavaScript const",
			code:     "const x = 5;\nlet y = 10;",
			expected: "javascript",
		},
		{
			name:     "Java class",
			code:     "public class Main {\n    public static void main(String[] args) {}\n}",
			expected: "java",
		},
		{
			name:     "Rust function",
			code:     "fn main() {\n    println!(\"Hello\");\n}",
			expected: "rust",
		},
		{
			name:     "Ruby class",
			code:     "class User < ActiveRecord::Base\nend",
			expected: "ruby",
		},
		{
			name:     "Bash script",
			code:     "#!/bin/bash\necho \"Hello\"",
			expected: "bash",
		},
		{
			name:     "Unknown",
			code:     "just some random text",
			expected: "unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detectLanguage(tt.code)
			if result != tt.expected {
				t.Errorf("detectLanguage() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestDetectCodeType(t *testing.T) {
	tests := []struct {
		name     string
		code     string
		language string
		expected string
	}{
		{
			name:     "Python function",
			code:     "def hello():\n    pass",
			language: "python",
			expected: "function",
		},
		{
			name:     "Python class",
			code:     "class User:\n    pass",
			language: "python",
			expected: "class",
		},
		{
			name:     "Python script",
			code:     "if __name__ == '__main__':\n    main()",
			language: "python",
			expected: "script",
		},
		{
			name:     "Go function",
			code:     "func hello() {\n}",
			language: "go",
			expected: "function",
		},
		{
			name:     "Go main",
			code:     "func main() {\n    fmt.Println(\"hi\")\n}",
			language: "go",
			expected: "function", // func is detected before main pattern
		},
		{
			name:     "Go struct",
			code:     "type User struct {\n    Name string\n}",
			language: "go",
			expected: "class",
		},
		{
			name:     "YAML config",
			code:     "apiVersion:\nkind: Service\n",
			language: "yaml",
			expected: "config",
		},
		{
			name:     "Short snippet",
			code:     "x = 1",
			language: "python",
			expected: "snippet",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := detectCodeType(tt.code, tt.language)
			if result != tt.expected {
				t.Errorf("detectCodeType() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestSecretDetection(t *testing.T) {
	tests := []struct {
		name     string
		code     string
		expected int
	}{
		{
			name:     "No secrets",
			code:     "const x = 5;",
			expected: 0,
		},
		{
			name:     "AWS access key",
			code:     "aws_access_key_id = 'AKIAIOSFODNN7EXAMPLE'",
			expected: 1,
		},
		{
			name:     "GitHub token",
			code:     "token := \"ghp_abcdefghijklmnopqrstuvwxyz0123456789\"",
			expected: 1,
		},
		{
			name:     "Private key",
			code:     "-----BEGIN RSA PRIVATE KEY-----\nMIIE...",
			expected: 1,
		},
		{
			name:     "JWT token",
			code:     "token = \"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U\"",
			expected: 1,
		},
		{
			name:     "Multiple secrets",
			code:     "api_key = 'sk_live_abcdefghijklmnop12345'\npassword = 'supersecret123'",
			expected: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := countMatches(tt.code, secretPatterns)
			if result != tt.expected {
				t.Errorf("countMatches(secretPatterns) = %d, want %d", result, tt.expected)
			}
		})
	}
}

func TestUnsafePatternDetection(t *testing.T) {
	tests := []struct {
		name     string
		code     string
		expected int
	}{
		{
			name:     "No unsafe patterns",
			code:     "const x = 5;",
			expected: 0,
		},
		{
			name:     "eval call",
			code:     "result = eval(userInput)",
			expected: 1,
		},
		{
			name:     "exec call",
			code:     "exec(\"rm -rf /\")",
			expected: 1,
		},
		{
			name:     "Python os.system",
			code:     "os.system('ls -la')",
			expected: 1,
		},
		{
			name:     "Python subprocess",
			code:     "subprocess.run(['ls'])",
			expected: 1,
		},
		{
			name:     "Python pickle",
			code:     "data = pickle.load(f)",
			expected: 1,
		},
		{
			name:     "Unsafe YAML",
			code:     "yaml.load(data)",
			expected: 1,
		},
		{
			name:     "Java runtime exec",
			code:     "Runtime.getRuntime().exec(cmd)",
			expected: 2, // matches exec and Runtime.getRuntime().exec patterns
		},
		{
			name:     "React dangerouslySetInnerHTML",
			code:     "<div dangerouslySetInnerHTML={{__html: userContent}} />",
			expected: 2, // matches dangerouslySetInnerHTML and ${...} template injection
		},
		{
			name:     "DOM innerHTML",
			code:     "element.innerHTML = userContent;",
			expected: 1,
		},
		{
			name:     "K8s privileged",
			code:     "securityContext:\n  privileged: true",
			expected: 1,
		},
		{
			name:     "Multiple unsafe",
			code:     "eval(x)\nexec(y)",
			expected: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := countMatches(tt.code, unsafePatterns)
			if result != tt.expected {
				t.Errorf("countMatches(unsafePatterns) = %d, want %d", result, tt.expected)
			}
		})
	}
}

func TestExtractCodeBlocks(t *testing.T) {
	tests := []struct {
		name          string
		text          string
		expectedCount int
		expectedLang  string
	}{
		{
			name:          "No code blocks",
			text:          "Just plain text",
			expectedCount: 0,
		},
		{
			name:          "Single block with language",
			text:          "```python\nprint('hello')\n```",
			expectedCount: 1,
			expectedLang:  "python",
		},
		{
			name:          "Single block without language",
			text:          "```\nsome code\n```",
			expectedCount: 1,
			expectedLang:  "",
		},
		{
			name:          "Multiple blocks",
			text:          "```go\nfunc main() {}\n```\n\n```python\ndef main():\n    pass\n```",
			expectedCount: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			blocks := extractCodeBlocks(tt.text)
			if len(blocks) != tt.expectedCount {
				t.Errorf("extractCodeBlocks() returned %d blocks, want %d", len(blocks), tt.expectedCount)
			}

			if tt.expectedCount > 0 && tt.expectedLang != "" {
				if blocks[0].language != tt.expectedLang {
					t.Errorf("First block language = %q, want %q", blocks[0].language, tt.expectedLang)
				}
			}
		})
	}
}

func TestExtractResponseContent(t *testing.T) {
	tests := []struct {
		name     string
		response interface{}
		expected string
	}{
		{
			name:     "String response",
			response: "Hello world",
			expected: "Hello world",
		},
		{
			name:     "Map with content",
			response: map[string]interface{}{"content": "Hello from content"},
			expected: "Hello from content",
		},
		{
			name:     "Map with response",
			response: map[string]interface{}{"response": "Hello from response"},
			expected: "Hello from response",
		},
		{
			name: "OpenAI format",
			response: map[string]interface{}{
				"choices": []interface{}{
					map[string]interface{}{
						"message": map[string]interface{}{
							"content": "Hello from OpenAI",
						},
					},
				},
			},
			expected: "Hello from OpenAI",
		},
		{
			name:     "Empty map",
			response: map[string]interface{}{},
			expected: "",
		},
		{
			name:     "Nil",
			response: nil,
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractResponseContent(tt.response)
			if result != tt.expected {
				t.Errorf("extractResponseContent() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestCodeArtifactMetadata_Fields(t *testing.T) {
	// Test that all fields are properly set
	metadata := CodeArtifactMetadata{
		IsCodeOutput:    true,
		Language:        "python",
		CodeType:        "function",
		SizeBytes:       100,
		LineCount:       10,
		PoliciesChecked: []string{"code-secrets", "code-unsafe"},
		SecretsDetected: 1,
		UnsafePatterns:  2,
	}

	if !metadata.IsCodeOutput {
		t.Error("IsCodeOutput should be true")
	}
	if metadata.Language != "python" {
		t.Errorf("Language = %q, want python", metadata.Language)
	}
	if metadata.CodeType != "function" {
		t.Errorf("CodeType = %q, want function", metadata.CodeType)
	}
	if metadata.SizeBytes != 100 {
		t.Errorf("SizeBytes = %d, want 100", metadata.SizeBytes)
	}
	if metadata.LineCount != 10 {
		t.Errorf("LineCount = %d, want 10", metadata.LineCount)
	}
	if len(metadata.PoliciesChecked) != 2 {
		t.Errorf("PoliciesChecked length = %d, want 2", len(metadata.PoliciesChecked))
	}
	if metadata.SecretsDetected != 1 {
		t.Errorf("SecretsDetected = %d, want 1", metadata.SecretsDetected)
	}
	if metadata.UnsafePatterns != 2 {
		t.Errorf("UnsafePatterns = %d, want 2", metadata.UnsafePatterns)
	}
}
