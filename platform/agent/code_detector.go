// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
//
// Code Artifact Detection for Issue #761: Governed Code Generation
// Detects code artifacts in LLM responses for audit logging and policy evaluation.

package agent

import (
	"regexp"
	"strings"
)

// CodeArtifactMetadata contains metadata about detected code in LLM responses.
// This is included in audit logs for governance and compliance purposes.
type CodeArtifactMetadata struct {
	// IsCodeOutput indicates whether the response contains code
	IsCodeOutput bool `json:"is_code_output"`

	// Language is the detected programming language (e.g., "python", "go", "javascript")
	Language string `json:"language,omitempty"`

	// CodeType categorizes the code (e.g., "function", "class", "script", "config", "snippet")
	CodeType string `json:"code_type,omitempty"`

	// SizeBytes is the total size of detected code in bytes
	SizeBytes int `json:"size_bytes,omitempty"`

	// LineCount is the number of lines of code detected
	LineCount int `json:"line_count,omitempty"`

	// PoliciesChecked lists the code governance policies that were evaluated
	PoliciesChecked []string `json:"policies_checked,omitempty"`

	// SecretsDetected is the count of potential secrets/credentials detected
	SecretsDetected int `json:"secrets_detected,omitempty"`

	// UnsafePatterns is the count of unsafe code patterns detected
	UnsafePatterns int `json:"unsafe_patterns,omitempty"`
}

// languagePattern represents a language detection pattern with its name
type languagePattern struct {
	name    string
	pattern *regexp.Regexp
}

// Ordered slice of language patterns for deterministic detection
// Order matters: more specific patterns should come first
var languagePatterns = []languagePattern{
	// Go - check before others due to distinctive syntax
	{name: "go", pattern: regexp.MustCompile(`(?m)^package\s+\w+|^func\s+\w+\(|^import\s+\(|^type\s+\w+\s+struct`)},

	// Python - check before Ruby due to similar syntax
	{name: "python", pattern: regexp.MustCompile(`(?m)^def\s+\w+\s*\(|^class\s+\w+[:\(]|^import\s+\w+|^from\s+\w+\s+import|^\s*@\w+`)},

	// TypeScript - check before JavaScript
	{name: "typescript", pattern: regexp.MustCompile(`(?m)^interface\s+\w+|:\s*(string|number|boolean|void)\s*[;,\)]|^type\s+\w+\s*=|^enum\s+\w+`)},

	// JavaScript
	{name: "javascript", pattern: regexp.MustCompile(`(?m)^const\s+\w+\s*=|^let\s+\w+\s*=|^function\s+\w+|^class\s+\w+\s*\{|=>\s*\{|module\.exports`)},

	// Java
	{name: "java", pattern: regexp.MustCompile(`(?m)^public\s+(class|interface|enum)|^private\s+\w+|^protected\s+\w+|^import\s+java\.|System\.out\.print`)},

	// SQL
	{name: "sql", pattern: regexp.MustCompile(`(?i)^\s*(SELECT|INSERT|UPDATE|DELETE|CREATE|ALTER|DROP)\s+`)},

	// Ruby
	{name: "ruby", pattern: regexp.MustCompile(`(?m)^def\s+\w+|^class\s+\w+\s*<|^module\s+\w+|^require\s+['"]|\.each\s+do\s*\|`)},

	// Rust
	{name: "rust", pattern: regexp.MustCompile(`(?m)^fn\s+\w+|^let\s+mut\s+|^impl\s+\w+|^use\s+\w+::|^struct\s+\w+`)},

	// C/C++
	{name: "c", pattern: regexp.MustCompile(`(?m)^#include\s*<|^int\s+main\s*\(|^void\s+\w+\s*\(|^struct\s+\w+\s*\{`)},

	// Shell/Bash
	{name: "bash", pattern: regexp.MustCompile(`(?m)^#!/bin/(ba)?sh|^\s*if\s+\[\s+|^\s*for\s+\w+\s+in|^\s*while\s+\[`)},

	// YAML
	{name: "yaml", pattern: regexp.MustCompile(`(?m)^\w+:\s*$|^\s+-\s+\w+:|^\s+\w+:\s+\w+`)},

	// JSON (basic check)
	{name: "json", pattern: regexp.MustCompile(`^\s*\{[\s\S]*"[^"]+"\s*:`)},

	// Dockerfile
	{name: "dockerfile", pattern: regexp.MustCompile(`(?m)^FROM\s+\w+|^RUN\s+|^COPY\s+|^ENTRYPOINT\s+`)},

	// Terraform/HCL
	{name: "terraform", pattern: regexp.MustCompile(`(?m)^resource\s+"[^"]+"|^provider\s+"[^"]+"|^variable\s+"[^"]+"`)},
}

// Code fence pattern for extracting code blocks from markdown
// Uses non-greedy match (.+?) to handle code containing backticks (e.g., Go raw strings)
var codeFencePattern = regexp.MustCompile("(?s)```(\\w*)\\n(.+?)\\n```")

// Secret detection patterns (for counting, not blocking - that's policy engine's job)
var secretPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(aws_access_key_id|aws_secret_access_key)\s*[=:]\s*['"]?[A-Za-z0-9/+=]{20,}`),
	regexp.MustCompile(`(?i)api[_-]?key\s*[=:]\s*['"]?[A-Za-z0-9_-]{20,}`),
	regexp.MustCompile(`ghp_[A-Za-z0-9]{36}`),                                        // GitHub personal token
	regexp.MustCompile(`(?i)password\s*[=:]\s*['"][^'"]{8,}['"]`),                     // Password assignment
	regexp.MustCompile(`(?i)secret\s*[=:]\s*['"][^'"]{8,}['"]`),                       // Secret assignment
	regexp.MustCompile(`-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----`),                // Private keys
	regexp.MustCompile(`eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`),        // JWT tokens
	regexp.MustCompile(`(?i)(bearer|authorization)\s*[=:]\s*['"]?[A-Za-z0-9_-]{20,}`), // Bearer tokens
}

// Unsafe code pattern detection
var unsafePatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\beval\s*\(`),                                // eval() calls
	regexp.MustCompile(`(?i)\bexec\s*\(`),                                // exec() calls
	regexp.MustCompile(`(?i)os\.(system|popen|exec)`),                    // Shell execution
	regexp.MustCompile(`(?i)subprocess\.(call|run|Popen)`),               // Python subprocess
	regexp.MustCompile(`(?i)child_process\.(exec|spawn)`),                // Node.js child process
	regexp.MustCompile(`(?i)pickle\.(load|loads)`),                       // Python pickle
	regexp.MustCompile(`(?i)yaml\.(unsafe_load|load)\s*\(`), // YAML unsafe load (yaml.load without Loader param)
	regexp.MustCompile(`(?i)Runtime\.getRuntime\(\)\.exec`),              // Java runtime exec
	regexp.MustCompile(`(?i)\$\{.*\}`),                                   // Template injection
	regexp.MustCompile(`(?i)(shell_exec|system|passthru|exec)\s*\(\$`),   // PHP shell with variable
	regexp.MustCompile(`(?i)dangerouslySetInnerHTML`),                    // React XSS risk
	regexp.MustCompile(`(?i)innerHTML\s*=`),                              // DOM XSS risk
	regexp.MustCompile(`(?i)allowPrivilegeEscalation:\s*true`),           // K8s privilege escalation
	regexp.MustCompile(`(?i)securityContext:\s*\n\s*privileged:\s*true`), // K8s privileged container
}

// DetectCodeInResponse analyzes a response and extracts code artifact metadata.
func DetectCodeInResponse(response string) *CodeArtifactMetadata {
	if response == "" {
		return nil
	}

	// Extract code blocks from markdown fences
	codeBlocks := extractCodeBlocks(response)
	if len(codeBlocks) == 0 {
		return nil
	}

	// Combine all code for analysis
	var combinedCode strings.Builder
	var declaredLanguage string

	for _, block := range codeBlocks {
		if block.language != "" && declaredLanguage == "" {
			declaredLanguage = strings.ToLower(block.language)
		}
		combinedCode.WriteString(block.code)
		combinedCode.WriteString("\n")
	}

	codeStr := combinedCode.String()
	if strings.TrimSpace(codeStr) == "" {
		return nil
	}

	// Detect language (prefer declared, fall back to detection)
	language := declaredLanguage
	if language == "" {
		language = detectLanguage(codeStr)
	}

	// Detect code type
	codeType := detectCodeType(codeStr, language)

	// Count potential issues
	secretsCount := countMatches(codeStr, secretPatterns)
	unsafeCount := countMatches(codeStr, unsafePatterns)

	return &CodeArtifactMetadata{
		IsCodeOutput:    true,
		Language:        language,
		CodeType:        codeType,
		SizeBytes:       len(codeStr),
		LineCount:       strings.Count(codeStr, "\n") + 1,
		SecretsDetected: secretsCount,
		UnsafePatterns:  unsafeCount,
	}
}

// codeBlock represents an extracted code block
type codeBlock struct {
	language string
	code     string
}

// extractCodeBlocks extracts code blocks from markdown-style fenced code
func extractCodeBlocks(text string) []codeBlock {
	matches := codeFencePattern.FindAllStringSubmatch(text, -1)
	blocks := make([]codeBlock, 0, len(matches))

	for _, match := range matches {
		if len(match) >= 3 {
			blocks = append(blocks, codeBlock{
				language: match[1],
				code:     match[2],
			})
		}
	}

	return blocks
}

// detectLanguage attempts to detect the programming language from code content
func detectLanguage(code string) string {
	// Check patterns in order (more specific first)
	for _, lp := range languagePatterns {
		if lp.pattern.MatchString(code) {
			return lp.name
		}
	}
	return "unknown"
}

// detectCodeType categorizes the type of code
func detectCodeType(code, language string) string {
	// Check for class definitions first (more specific)
	classPatterns := map[string]*regexp.Regexp{
		"python":     regexp.MustCompile(`(?m)^class\s+\w+`),
		"java":       regexp.MustCompile(`(?m)^public\s+class\s+\w+`),
		"typescript": regexp.MustCompile(`(?m)^(export\s+)?class\s+\w+`),
		"javascript": regexp.MustCompile(`(?m)^class\s+\w+`),
		"go":         regexp.MustCompile(`(?m)^type\s+\w+\s+struct`),
		"ruby":       regexp.MustCompile(`(?m)^class\s+\w+`),
		"rust":       regexp.MustCompile(`(?m)^(pub\s+)?struct\s+\w+`),
	}

	if pattern, ok := classPatterns[language]; ok {
		if pattern.MatchString(code) {
			return "class"
		}
	}

	// Check for function definitions
	funcPatterns := map[string]*regexp.Regexp{
		"python":     regexp.MustCompile(`(?m)^def\s+\w+`),
		"go":         regexp.MustCompile(`(?m)^func\s+`),
		"javascript": regexp.MustCompile(`(?m)^(async\s+)?function\s+\w+|^const\s+\w+\s*=\s*(async\s+)?\(`),
		"typescript": regexp.MustCompile(`(?m)^(async\s+)?function\s+\w+|^(export\s+)?(const|let)\s+\w+\s*=\s*(async\s+)?\(`),
		"java":       regexp.MustCompile(`(?m)^(public|private|protected)\s+\w+\s+\w+\s*\(`),
		"ruby":       regexp.MustCompile(`(?m)^def\s+\w+`),
		"rust":       regexp.MustCompile(`(?m)^(pub\s+)?fn\s+\w+`),
	}

	if pattern, ok := funcPatterns[language]; ok {
		if pattern.MatchString(code) {
			return "function"
		}
	}

	// Check for configuration files
	configPatterns := []struct {
		lang    string
		pattern *regexp.Regexp
	}{
		{"yaml", regexp.MustCompile(`(?m)^\w+:\s*\n`)},
		{"json", regexp.MustCompile(`^\s*\{`)},
		{"terraform", regexp.MustCompile(`(?m)^(resource|provider|variable)\s+`)},
		{"dockerfile", regexp.MustCompile(`(?m)^FROM\s+`)},
	}

	for _, cp := range configPatterns {
		if language == cp.lang && cp.pattern.MatchString(code) {
			return "config"
		}
	}

	// Check for script-like code (has shebang or main execution)
	if strings.HasPrefix(strings.TrimSpace(code), "#!") {
		return "script"
	}

	// Check for main function/entry point
	mainPatterns := []*regexp.Regexp{
		regexp.MustCompile(`(?m)^if\s+__name__\s*==\s*['"]__main__['"]\s*:`), // Python
		regexp.MustCompile(`(?m)^func\s+main\s*\(\s*\)`),                     // Go
		regexp.MustCompile(`(?m)^public\s+static\s+void\s+main\s*\(`),        // Java
	}

	for _, pattern := range mainPatterns {
		if pattern.MatchString(code) {
			return "script"
		}
	}

	// Default to snippet for short code or unclassified
	lines := strings.Count(code, "\n")
	if lines < 10 {
		return "snippet"
	}

	return "module"
}

// countMatches counts how many patterns match in the code
func countMatches(code string, patterns []*regexp.Regexp) int {
	count := 0
	for _, pattern := range patterns {
		matches := pattern.FindAllString(code, -1)
		count += len(matches)
	}
	return count
}

// EvaluateCodePolicies returns the code governance policy categories that were evaluated.
// This is used for audit logging to track which policy categories were checked.
func EvaluateCodePolicies(code string, policyEngine *StaticPolicyEngine) ([]string, error) {
	if code == "" {
		return nil, nil
	}

	// Return the code governance categories that are always evaluated
	return []string{
		string(CategoryCodeSecrets),
		string(CategoryCodeUnsafe),
		string(CategoryCodeCompliance),
	}, nil
}

// extractResponseContent extracts the main content from an orchestrator response
func extractResponseContent(response interface{}) string {
	switch v := response.(type) {
	case string:
		return v
	case map[string]interface{}:
		// Try common response field names (including "data" for orchestrator responses)
		for _, key := range []string{"data", "content", "response", "message", "text", "result"} {
			if content, ok := v[key]; ok {
				if str, ok := content.(string); ok {
					return str
				}
				// Handle nested structure (e.g., {"data": {"data": "content"}})
				if nested, ok := content.(map[string]interface{}); ok {
					if nestedData, ok := nested["data"].(string); ok {
						return nestedData
					}
					// Also try content field in nested structure
					if nestedContent, ok := nested["content"].(string); ok {
						return nestedContent
					}
				}
			}
		}
		// Try nested choices (OpenAI format)
		if choices, ok := v["choices"].([]interface{}); ok && len(choices) > 0 {
			if choice, ok := choices[0].(map[string]interface{}); ok {
				if msg, ok := choice["message"].(map[string]interface{}); ok {
					if content, ok := msg["content"].(string); ok {
						return content
					}
				}
			}
		}
	}
	return ""
}
