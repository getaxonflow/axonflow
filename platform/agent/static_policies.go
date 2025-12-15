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

package agent

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"axonflow/platform/agent/sqli"
)

// StaticPolicyEngine handles fast, rule-based policy enforcement
// These are policies that can be evaluated quickly without external context
type StaticPolicyEngine struct {
	sqliScanner         sqli.Scanner      // Unified SQL injection + dangerous query scanner
	adminAccessPatterns []*PolicyPattern
	piiPatterns         []*PolicyPattern // PII detection (passports, credit cards, etc.)
}

// PolicyPattern represents a static policy rule
type PolicyPattern struct {
	ID          string
	Name        string
	Pattern     *regexp.Regexp
	PatternStr  string
	Severity    string // "low", "medium", "high", "critical"
	Description string
	Enabled     bool
}

// StaticPolicyResult contains the result of static policy evaluation
type StaticPolicyResult struct {
	Blocked            bool
	Reason             string
	TriggeredPolicies  []string
	ChecksPerformed    []string
	ProcessingTimeMs   int64
	Severity           string
}

// NewStaticPolicyEngine creates a new static policy engine with default rules
func NewStaticPolicyEngine() *StaticPolicyEngine {
	engine := &StaticPolicyEngine{
		sqliScanner: sqli.NewBasicScanner(),
	}
	engine.loadDefaultPolicies()
	return engine
}

// EvaluateStaticPolicies evaluates a query against all static policies
func (spe *StaticPolicyEngine) EvaluateStaticPolicies(user *User, query string, requestType string) *StaticPolicyResult {
	startTime := time.Now()

	result := &StaticPolicyResult{
		Blocked:           false,
		TriggeredPolicies: []string{},
		ChecksPerformed:   []string{},
	}

	queryLower := strings.ToLower(strings.TrimSpace(query))

	// 1. SQL Injection + Dangerous Query Detection using unified sqli scanner
	// This covers both SQL injection attacks and dangerous DDL operations
	sqliResult := spe.sqliScanner.Scan(context.Background(), query, sqli.ScanTypeInput)
	if sqliResult.Detected {
		result.Blocked = true
		// Determine check type based on category
		checkType := "sql_injection"
		reason := "SQL injection attempt detected"
		if sqliResult.Category == sqli.CategoryDangerousQuery {
			checkType = "dangerous_queries"
			reason = "Dangerous query detected"
		}
		result.Reason = fmt.Sprintf("%s: %s", reason, sqliResult.Pattern)
		result.TriggeredPolicies = append(result.TriggeredPolicies, sqliResult.Pattern)
		result.Severity = sqli.CategorySeverity(sqliResult.Category)
		result.ChecksPerformed = append(result.ChecksPerformed, checkType)
		result.ProcessingTimeMs = time.Since(startTime).Nanoseconds() / 1000000
		return result
	}
	result.ChecksPerformed = append(result.ChecksPerformed, "sql_injection")
	result.ChecksPerformed = append(result.ChecksPerformed, "dangerous_queries")
	
	// 3. Admin Access Control (High - Block based on user role)
	if !spe.hasPermission(user, "admin") {
		if blockedPattern := spe.checkPatterns(queryLower, spe.adminAccessPatterns); blockedPattern != nil {
			result.Blocked = true
			result.Reason = fmt.Sprintf("Administrative access required: %s", blockedPattern.Description)
			result.TriggeredPolicies = append(result.TriggeredPolicies, blockedPattern.ID)
			result.Severity = "high"
			result.ChecksPerformed = append(result.ChecksPerformed, "admin_access")
			result.ProcessingTimeMs = time.Since(startTime).Nanoseconds() / 1000000
			return result
		}
	}
	result.ChecksPerformed = append(result.ChecksPerformed, "admin_access")
	
	// 4. Request Type Validation
	if !spe.isValidRequestType(requestType) {
		result.Blocked = true
		result.Reason = "Invalid request type"
		result.Severity = "medium"
		result.ChecksPerformed = append(result.ChecksPerformed, "request_type")
		result.ProcessingTimeMs = time.Since(startTime).Nanoseconds() / 1000000
		return result
	}
	result.ChecksPerformed = append(result.ChecksPerformed, "request_type")
	
	// 5. Basic Query Validation
	if strings.TrimSpace(query) == "" {
		result.Blocked = true
		result.Reason = "Empty query not allowed"
		result.Severity = "low"
		result.ProcessingTimeMs = time.Since(startTime).Nanoseconds() / 1000000
		return result
	}
	result.ChecksPerformed = append(result.ChecksPerformed, "basic_validation")

	// 6. PII Detection (High - Log and flag for redaction, don't block)
	// For travel/planning requests, detect PII but allow processing with redaction
	if piiPattern := spe.checkPatterns(query, spe.piiPatterns); piiPattern != nil {
		// Don't block for PII - just log and trigger redaction in Orchestrator
		result.TriggeredPolicies = append(result.TriggeredPolicies, piiPattern.ID)
		// Note: For severity "critical" PII (credit cards, SSNs), could optionally block
		// For now, we allow with redaction for better UX in travel planning
	}
	result.ChecksPerformed = append(result.ChecksPerformed, "pii_detection")

	result.ProcessingTimeMs = time.Since(startTime).Nanoseconds() / 1000000
	return result
}

// checkPatterns checks if query matches any pattern in the given list
func (spe *StaticPolicyEngine) checkPatterns(query string, patterns []*PolicyPattern) *PolicyPattern {
	for _, pattern := range patterns {
		if !pattern.Enabled {
			continue
		}
		
		if pattern.Pattern.MatchString(query) {
			return pattern
		}
	}
	return nil
}

// hasPermission checks if user has a specific permission
func (spe *StaticPolicyEngine) hasPermission(user *User, permission string) bool {
	for _, perm := range user.Permissions {
		if perm == permission {
			return true
		}
	}
	return false
}

// isValidRequestType validates the request type
func (spe *StaticPolicyEngine) isValidRequestType(requestType string) bool {
	validTypes := []string{"sql", "llm_chat", "rag_search", "test", "multi-agent-plan", "chat", "completion", "embedding"}
	for _, validType := range validTypes {
		if requestType == validType {
			return true
		}
	}
	return false
}

// loadDefaultPolicies initializes the static policy engine with default rules
func (spe *StaticPolicyEngine) loadDefaultPolicies() {
	// Note: SQL injection and dangerous query patterns are now handled by the
	// unified sqli.Scanner (see sqliScanner field). This provides:
	// - 35+ patterns covering injection and dangerous operations
	// - Consistent detection across agent and MCP response scanning
	// - Category-based severity classification

	// Admin Access Patterns (High)
	spe.adminAccessPatterns = []*PolicyPattern{
		{
			ID:          "users_table_access",
			Name:        "Users Table Access",
			Pattern:     regexp.MustCompile(`\busers\b`),
			PatternStr:  `\busers\b`,
			Severity:    "high",
			Description: "Access to users table requires admin privileges",
			Enabled:     true,
		},
		{
			ID:          "audit_log_access",
			Name:        "Audit Log Access",
			Pattern:     regexp.MustCompile(`audit_log`),
			PatternStr:  `audit_log`,
			Severity:    "high",
			Description: "Access to audit logs requires admin privileges",
			Enabled:     true,
		},
		{
			ID:          "config_table_access",
			Name:        "Configuration Table Access",
			Pattern:     regexp.MustCompile(`config_|admin_|system_`),
			PatternStr:  `config_|admin_|system_`,
			Severity:    "high",
			Description: "Access to system configuration requires admin privileges",
			Enabled:     true,
		},
		{
			ID:          "information_schema_access",
			Name:        "Information Schema Access",
			Pattern:     regexp.MustCompile(`information_schema|pg_catalog|mysql\.user`),
			PatternStr:  `information_schema|pg_catalog|mysql\.user`,
			Severity:    "medium",
			Description: "System schema access requires admin privileges",
			Enabled:     true,
		},
	}

	// PII Patterns - Comprehensive detection with validation
	// Phase 1: Core PII patterns with improved accuracy
	// Note: Order matters - more specific patterns should come first to avoid
	// generic patterns (like phone) matching region-specific IDs (like Aadhaar)
	spe.piiPatterns = []*PolicyPattern{
		// =============================================================================
		// Indian PII Detection (SEBI AI/ML Guidelines & DPDP Act 2023)
		// These patterns are placed first because they're more specific than generic
		// patterns like phone detection, which could otherwise match Aadhaar numbers.
		// =============================================================================

		// PAN - Indian Permanent Account Number (Income Tax ID)
		// Format: 5 letters + 4 digits + 1 letter (e.g., ABCPD1234E)
		// 4th character indicates entity type: P=Person, C=Company, H=HUF,
		// A=AOP, B=BOI, G=Government, J=AJP, L=Local Authority, F=Firm, T=Trust
		// Reference: SEBI AI/ML Guidelines - Data Privacy Pillar
		{
			ID:          "pan_detection",
			Name:        "Indian PAN Detection",
			Pattern:     regexp.MustCompile(`\b[A-Z]{3}[PCHABGJLFT][A-Z][0-9]{4}[A-Z]\b|(?i)PAN[:\s]+\b[A-Z0-9]{10}\b`),
			PatternStr:  `\b[A-Z]{3}[PCHABGJLFT][A-Z][0-9]{4}[A-Z]\b|(?i)PAN[:\s]+\b[A-Z0-9]{10}\b`,
			Severity:    "critical",
			Description: "Indian Permanent Account Number (PAN) detected - automatic redaction required under SEBI guidelines",
			Enabled:     true,
		},
		// Aadhaar - Indian Unique Identification Number
		// Format: 12 digits, first digit 2-9 (never 0 or 1), often written with spaces
		// Verhoeff checksum validated by UIDAI
		// Reference: DPDP Act 2023, SEBI AI/ML Guidelines - Data Privacy Pillar
		{
			ID:          "aadhaar_detection",
			Name:        "Indian Aadhaar Detection",
			Pattern:     regexp.MustCompile(`\b[2-9][0-9]{3}\s?[0-9]{4}\s?[0-9]{4}\b|(?i)aadhaar[:\s]+[2-9][0-9]{11}|(?i)UID[:\s]+[2-9][0-9]{11}`),
			PatternStr:  `\b[2-9][0-9]{3}\s?[0-9]{4}\s?[0-9]{4}\b|(?i)aadhaar[:\s]+[2-9][0-9]{11}|(?i)UID[:\s]+[2-9][0-9]{11}`,
			Severity:    "critical",
			Description: "Indian Aadhaar number detected - automatic redaction required under DPDP Act 2023",
			Enabled:     true,
		},

		// =============================================================================
		// Global PII Patterns
		// =============================================================================

		// SSN - Enhanced pattern with format validation
		{
			ID:          "ssn_detection",
			Name:        "SSN Detection",
			Pattern:     regexp.MustCompile(`\b(\d{3})[- ]?(\d{2})[- ]?(\d{4})\b`),
			PatternStr:  `\b(\d{3})[- ]?(\d{2})[- ]?(\d{4})\b`,
			Severity:    "critical",
			Description: "Social Security Number detected - automatic redaction required",
			Enabled:     true,
		},
		// Credit Card - All major networks with separators
		{
			ID:          "credit_card_detection",
			Name:        "Credit Card Number Detection",
			Pattern:     regexp.MustCompile(`\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|2[2-7][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12}|3(?:0[0-5]|[68][0-9])[0-9]{11}|(?:2131|1800|35\d{3})\d{11})\b|\b(\d{4})[- ]?(\d{4})[- ]?(\d{4})[- ]?(\d{4})\b`),
			PatternStr:  `credit_card_comprehensive`,
			Severity:    "critical",
			Description: "Credit card numbers detected - automatic redaction required for PCI compliance",
			Enabled:     true,
		},
		// Email - RFC 5322 compliant
		{
			ID:          "email_detection",
			Name:        "Email Address Detection",
			Pattern:     regexp.MustCompile(`\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b`),
			PatternStr:  `\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b`,
			Severity:    "medium",
			Description: "Email address detected - may require redaction under GDPR",
			Enabled:     true,
		},
		// Phone - US and international formats
		{
			ID:          "phone_detection",
			Name:        "Phone Number Detection",
			Pattern:     regexp.MustCompile(`(?:\+?1[-.\s]?)?(?:\(?[0-9]{3}\)?[-.\s]?)?[0-9]{3}[-.\s]?[0-9]{4}\b|\+[0-9]{1,3}[-.\s]?[0-9]{6,14}\b`),
			PatternStr:  `phone_comprehensive`,
			Severity:    "medium",
			Description: "Phone number detected - may require redaction for privacy",
			Enabled:     true,
		},
		// IP Address - IPv4 with range validation
		{
			ID:          "ip_address_detection",
			Name:        "IP Address Detection",
			Pattern:     regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b`),
			PatternStr:  `\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b`,
			Severity:    "medium",
			Description: "IP address detected - may identify user location",
			Enabled:     true,
		},
		// IBAN - International Bank Account Number
		{
			ID:          "iban_detection",
			Name:        "IBAN Detection",
			Pattern:     regexp.MustCompile(`\b[A-Z]{2}[0-9]{2}[A-Z0-9]{4}[0-9]{7}(?:[A-Z0-9]?){0,16}\b`),
			PatternStr:  `\b[A-Z]{2}[0-9]{2}[A-Z0-9]{4}[0-9]{7}(?:[A-Z0-9]?){0,16}\b`,
			Severity:    "critical",
			Description: "International Bank Account Number detected - automatic redaction required",
			Enabled:     true,
		},
		// Passport - Multiple country formats
		{
			ID:          "passport_number_detection",
			Name:        "Passport Number Detection",
			Pattern:     regexp.MustCompile(`\b[A-Z]{1,2}[0-9]{6,9}\b`),
			PatternStr:  `\b[A-Z]{1,2}[0-9]{6,9}\b`,
			Severity:    "high",
			Description: "Passport numbers detected in query - automatic redaction required",
			Enabled:     true,
		},
		// Date of Birth - Multiple formats (context-dependent)
		{
			ID:          "dob_detection",
			Name:        "Date of Birth Detection",
			Pattern:     regexp.MustCompile(`\b(?:(?:0?[1-9]|1[0-2])[/\-](?:0?[1-9]|[12][0-9]|3[01])[/\-](?:19|20)\d{2}|(?:19|20)\d{2}[/\-](?:0?[1-9]|1[0-2])[/\-](?:0?[1-9]|[12][0-9]|3[01]))\b`),
			PatternStr:  `date_format`,
			Severity:    "high",
			Description: "Date detected - may be date of birth requiring protection",
			Enabled:     true,
		},
		// Bank Account - US routing + account format
		{
			ID:          "bank_account_detection",
			Name:        "Bank Account Detection",
			Pattern:     regexp.MustCompile(`\b[0-9]{9}[- ]?[0-9]{8,17}\b`),
			PatternStr:  `\b[0-9]{9}[- ]?[0-9]{8,17}\b`,
			Severity:    "critical",
			Description: "Bank account information detected - automatic redaction required",
			Enabled:     true,
		},
		// Booking Reference - For audit trail (non-blocking)
		{
			ID:          "booking_reference_logging",
			Name:        "Booking Reference Logging",
			Pattern:     regexp.MustCompile(`\b[A-Z0-9]{6}\b`),
			PatternStr:  `\b[A-Z0-9]{6}\b`,
			Severity:    "low",
			Description: "Booking reference detected - logged for audit trail (not blocked)",
			Enabled:     true,
		},
	}
}

// ValidatePAN validates Indian Permanent Account Number format
// Returns true if the PAN matches the valid format with correct entity type
func ValidatePAN(pan string) bool {
	if len(pan) != 10 {
		return false
	}

	// First 3 characters must be uppercase letters
	for i := 0; i < 3; i++ {
		if pan[i] < 'A' || pan[i] > 'Z' {
			return false
		}
	}

	// 4th character must be valid entity type
	entityTypes := "PCHABGJLFT"
	validEntity := false
	for _, c := range entityTypes {
		if rune(pan[3]) == c {
			validEntity = true
			break
		}
	}
	if !validEntity {
		return false
	}

	// 5th character must be uppercase letter
	if pan[4] < 'A' || pan[4] > 'Z' {
		return false
	}

	// Characters 6-9 must be digits
	for i := 5; i < 9; i++ {
		if pan[i] < '0' || pan[i] > '9' {
			return false
		}
	}

	// 10th character must be uppercase letter
	if pan[9] < 'A' || pan[9] > 'Z' {
		return false
	}

	return true
}

// ValidateAadhaar validates Indian Aadhaar number format
// Returns true if the Aadhaar matches the basic format validation
// Note: Full Verhoeff checksum validation requires additional logic
func ValidateAadhaar(aadhaar string) bool {
	// Remove spaces efficiently
	var clean strings.Builder
	clean.Grow(12)
	for _, r := range aadhaar {
		if r >= '0' && r <= '9' {
			clean.WriteRune(r)
		}
	}
	cleanStr := clean.String()

	if len(cleanStr) != 12 {
		return false
	}

	// First digit must be 2-9 (never 0 or 1)
	if cleanStr[0] < '2' || cleanStr[0] > '9' {
		return false
	}

	return true
}

// ValidateSSN validates US Social Security Numbers
// Returns false for invalid area numbers (000, 666, 900-999)
// and invalid group/serial numbers (00, 0000)
func ValidateSSN(ssn string) bool {
	// Remove separators efficiently
	var clean strings.Builder
	clean.Grow(9) // SSN has 9 digits
	for _, r := range ssn {
		if r >= '0' && r <= '9' {
			clean.WriteRune(r)
		}
	}
	cleanStr := clean.String()

	if len(cleanStr) != 9 {
		return false
	}

	// Parse components
	area := 0
	for _, r := range cleanStr[0:3] {
		area = area*10 + int(r-'0')
	}
	group := 0
	for _, r := range cleanStr[3:5] {
		group = group*10 + int(r-'0')
	}
	serial := 0
	for _, r := range cleanStr[5:9] {
		serial = serial*10 + int(r-'0')
	}

	// Invalid area numbers: 000, 666, 900-999
	if area == 0 || area == 666 || area >= 900 {
		return false
	}

	// Invalid group or serial
	if group == 0 || serial == 0 {
		return false
	}

	return true
}

// ValidateCreditCard validates credit card numbers using Luhn algorithm
func ValidateCreditCard(cardNumber string) bool {
	// Remove separators efficiently
	var clean strings.Builder
	clean.Grow(19) // Max credit card length
	for _, r := range cardNumber {
		if r >= '0' && r <= '9' {
			clean.WriteRune(r)
		}
	}
	cleanStr := clean.String()

	if len(cleanStr) < 13 || len(cleanStr) > 19 {
		return false
	}

	// Luhn algorithm
	sum := 0
	alternate := false

	for i := len(cleanStr) - 1; i >= 0; i-- {
		digit := int(cleanStr[i] - '0')

		if alternate {
			digit *= 2
			if digit > 9 {
				digit -= 9
			}
		}

		sum += digit
		alternate = !alternate
	}

	return sum%10 == 0
}

// GetPolicyStats returns statistics about loaded policies
func (spe *StaticPolicyEngine) GetPolicyStats() map[string]interface{} {
	// Count sqli patterns by category
	sqliPatterns := sqli.NewPatternSet().Patterns()
	sqliCount := 0
	dangerousCount := 0
	for _, p := range sqliPatterns {
		if p.Category == sqli.CategoryDangerousQuery {
			dangerousCount++
		} else {
			sqliCount++
		}
	}

	return map[string]interface{}{
		"sql_injection_patterns":   sqliCount,
		"dangerous_query_patterns": dangerousCount,
		"admin_access_patterns":    len(spe.adminAccessPatterns),
		"pii_patterns":             len(spe.piiPatterns),
		"total_patterns":           len(sqliPatterns) + len(spe.adminAccessPatterns) + len(spe.piiPatterns),
	}
}