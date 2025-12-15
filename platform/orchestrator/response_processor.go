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

package orchestrator

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"regexp"
	"strings"
	"time"
)

// ResponseProcessor handles PII detection and redaction in LLM responses
type ResponseProcessor struct {
	piiDetector         *PIIDetector
	enhancedPIIDetector *EnhancedPIIDetector
	redactor            *Redactor
	enricher            *ResponseEnricher
	validationRules     []ValidationRule
	useEnhancedDetector bool
}

// RedactionInfo contains information about redactions made
type RedactionInfo struct {
	HasRedactions  bool     `json:"has_redactions"`
	RedactedFields []string `json:"redacted_fields"`
	RedactionCount int      `json:"redaction_count"`
}

// PIIDetector detects various types of PII in text
type PIIDetector struct {
	patterns map[string]*regexp.Regexp
}

// Redactor handles the actual redaction of sensitive data
type Redactor struct {
	redactionStrategies map[string]RedactionStrategy
}

// RedactionStrategy defines how to redact specific types of data
type RedactionStrategy interface {
	Redact(value string) string
	GetPlaceholder() string
}

// ResponseEnricher adds metadata to responses
type ResponseEnricher struct {
	enrichmentRules []EnrichmentRule
}

// ValidationRule checks if a response is valid
type ValidationRule struct {
	Name      string
	Validator func(response interface{}) error
}

// EnrichmentRule adds metadata to responses
type EnrichmentRule struct {
	Name     string
	Enricher func(ctx context.Context, response interface{}) map[string]interface{}
}

// NewResponseProcessor creates a new response processor
func NewResponseProcessor() *ResponseProcessor {
	return &ResponseProcessor{
		piiDetector:         NewPIIDetector(),
		enhancedPIIDetector: NewEnhancedPIIDetector(DefaultPIIDetectorConfig()),
		redactor:            NewRedactor(),
		enricher:            NewResponseEnricher(),
		validationRules:     getDefaultValidationRules(),
		useEnhancedDetector: true, // Use enhanced detector by default
	}
}

// NewResponseProcessorWithConfig creates a response processor with custom configuration
func NewResponseProcessorWithConfig(useEnhanced bool, piiConfig PIIDetectorConfig) *ResponseProcessor {
	return &ResponseProcessor{
		piiDetector:         NewPIIDetector(),
		enhancedPIIDetector: NewEnhancedPIIDetector(piiConfig),
		redactor:            NewRedactor(),
		enricher:            NewResponseEnricher(),
		validationRules:     getDefaultValidationRules(),
		useEnhancedDetector: useEnhanced,
	}
}

// SetUseEnhancedDetector enables or disables the enhanced PII detector
func (p *ResponseProcessor) SetUseEnhancedDetector(enabled bool) {
	p.useEnhancedDetector = enabled
}

// ProcessResponse processes an LLM response for PII and applies redactions
func (p *ResponseProcessor) ProcessResponse(ctx context.Context, user UserContext, response *LLMResponse) (interface{}, *RedactionInfo) {
	// Parse response content
	var responseData interface{}
	if err := json.Unmarshal([]byte(response.Content), &responseData); err != nil {
		// If not JSON, treat as plain text
		responseData = response.Content
	}
	
	// Detect PII
	detectedPII := p.detectPII(responseData)
	
	// Apply redactions based on user permissions
	redactedData, redactionInfo := p.applyRedactions(user, responseData, detectedPII)
	
	// Validate response
	if err := p.validateResponse(redactedData); err != nil {
		log.Printf("Response validation failed: %v", err)
		// Return error response
		return map[string]string{
			"error": "Response validation failed",
			"details": err.Error(),
		}, &RedactionInfo{}
	}
	
	// Enrich response with metadata
	enrichedData := p.enrichResponse(ctx, redactedData)
	
	return enrichedData, redactionInfo
}

// detectPII detects PII in the response data
func (p *ResponseProcessor) detectPII(data interface{}) map[string][]string {
	detected := make(map[string][]string)

	// Convert to string for analysis
	dataStr := fmt.Sprint(data)

	// Use enhanced detector if enabled
	if p.useEnhancedDetector && p.enhancedPIIDetector != nil {
		// DetectAll already filters by the detector's configured minConfidence
		results := p.enhancedPIIDetector.DetectAll(dataStr)
		for _, result := range results {
			detected[string(result.Type)] = append(detected[string(result.Type)], result.Value)
		}
	} else {
		// Fallback to legacy detector
		for piiType, pattern := range p.piiDetector.patterns {
			matches := pattern.FindAllString(dataStr, -1)
			if len(matches) > 0 {
				detected[piiType] = matches
			}
		}
	}

	// Deep scan for structured data (field names)
	if mapData, ok := data.(map[string]interface{}); ok {
		p.deepScanForPII(mapData, detected)
	}

	return detected
}

// detectPIIEnhanced returns detailed PII detection results with confidence scores
//
//nolint:unused // Used in tests only
func (p *ResponseProcessor) detectPIIEnhanced(data interface{}) []PIIDetectionResult {
	if p.enhancedPIIDetector == nil {
		return nil
	}

	dataStr := fmt.Sprint(data)
	return p.enhancedPIIDetector.DetectAll(dataStr)
}

// deepScanForPII recursively scans structured data for PII
func (p *ResponseProcessor) deepScanForPII(data map[string]interface{}, detected map[string][]string) {
	for key, value := range data {
		// Check if key name suggests PII
		lowerKey := strings.ToLower(key)
		if contains([]string{"ssn", "social_security", "email", "phone", "credit_card", "account_number"}, lowerKey) {
			detected["field_name_pii"] = append(detected["field_name_pii"], key)
		}
		
		// Recursively check nested structures
		switch v := value.(type) {
		case map[string]interface{}:
			p.deepScanForPII(v, detected)
		case []interface{}:
			for _, item := range v {
				if mapItem, ok := item.(map[string]interface{}); ok {
					p.deepScanForPII(mapItem, detected)
				}
			}
		case string:
			// Check string values for PII patterns
			for piiType, pattern := range p.piiDetector.patterns {
				if pattern.MatchString(v) {
					detected[piiType] = append(detected[piiType], v)
				}
			}
		}
	}
}

// applyRedactions applies redactions based on user permissions
func (p *ResponseProcessor) applyRedactions(user UserContext, data interface{}, detectedPII map[string][]string) (interface{}, *RedactionInfo) {
	redactionInfo := &RedactionInfo{
		HasRedactions:  false,
		RedactedFields: []string{},
		RedactionCount: 0,
	}
	
	// Check user permissions
	allowedPII := p.getAllowedPIITypes(user)
	
	// Apply redactions
	redactedData := p.redactData(data, detectedPII, allowedPII, redactionInfo)
	
	return redactedData, redactionInfo
}

// getAllowedPIITypes returns PII types the user is allowed to see
func (p *ResponseProcessor) getAllowedPIITypes(user UserContext) []string {
	allowed := []string{}
	
	// Map permissions to PII types
	permissionMap := map[string][]string{
		"view_full_pii": {"ssn", "credit_card", "bank_account", "email", "phone", "address"},
		"view_basic_pii": {"email", "phone"},
		"view_financial": {"credit_card", "bank_account"},
		"view_medical": {"medical_record", "diagnosis"},
	}
	
	for _, permission := range user.Permissions {
		if piiTypes, exists := permissionMap[permission]; exists {
			allowed = append(allowed, piiTypes...)
		}
	}
	
	// Admins can see everything
	if user.Role == "admin" {
		return []string{"*"}
	}
	
	return allowed
}

// redactData performs the actual redaction
func (p *ResponseProcessor) redactData(data interface{}, detectedPII map[string][]string, allowedPII []string, info *RedactionInfo) interface{} {
	// Handle different data types
	switch v := data.(type) {
	case string:
		return p.redactString(v, detectedPII, allowedPII, info)
	case map[string]interface{}:
		return p.redactMap(v, detectedPII, allowedPII, info)
	case []interface{}:
		return p.redactSlice(v, detectedPII, allowedPII, info)
	default:
		return data
	}
}

// redactString redacts PII from a string
func (p *ResponseProcessor) redactString(s string, detectedPII map[string][]string, allowedPII []string, info *RedactionInfo) string {
	redacted := s
	
	for piiType, values := range detectedPII {
		if !p.isAllowed(piiType, allowedPII) {
			strategy := p.redactor.getStrategy(piiType)
			for _, value := range values {
				if strings.Contains(redacted, value) {
					redacted = strings.ReplaceAll(redacted, value, strategy.Redact(value))
					info.RedactionCount++
					info.HasRedactions = true
					if !contains(info.RedactedFields, piiType) {
						info.RedactedFields = append(info.RedactedFields, piiType)
					}
				}
			}
		}
	}
	
	return redacted
}

// redactMap redacts PII from a map
func (p *ResponseProcessor) redactMap(m map[string]interface{}, detectedPII map[string][]string, allowedPII []string, info *RedactionInfo) map[string]interface{} {
	redacted := make(map[string]interface{})
	
	for key, value := range m {
		// Check if the key itself suggests PII
		if p.shouldRedactField(key, allowedPII) {
			redacted[key] = "[REDACTED]"
			info.RedactionCount++
			info.HasRedactions = true
			info.RedactedFields = append(info.RedactedFields, key)
		} else {
			redacted[key] = p.redactData(value, detectedPII, allowedPII, info)
		}
	}
	
	return redacted
}

// redactSlice redacts PII from a slice
func (p *ResponseProcessor) redactSlice(s []interface{}, detectedPII map[string][]string, allowedPII []string, info *RedactionInfo) []interface{} {
	redacted := make([]interface{}, len(s))
	
	for i, item := range s {
		redacted[i] = p.redactData(item, detectedPII, allowedPII, info)
	}
	
	return redacted
}

// isAllowed checks if a PII type is allowed for the user
func (p *ResponseProcessor) isAllowed(piiType string, allowedPII []string) bool {
	if contains(allowedPII, "*") {
		return true
	}
	return contains(allowedPII, piiType)
}

// shouldRedactField checks if a field name suggests PII that should be redacted
func (p *ResponseProcessor) shouldRedactField(fieldName string, allowedPII []string) bool {
	sensitiveFields := map[string]string{
		"ssn":              "ssn",
		"social_security":  "ssn",
		"credit_card":      "credit_card",
		"card_number":      "credit_card",
		"account_number":   "bank_account",
		"routing_number":   "bank_account",
		"medical_record":   "medical_record",
		"diagnosis":        "diagnosis",
	}
	
	lowerField := strings.ToLower(fieldName)
	for field, piiType := range sensitiveFields {
		if strings.Contains(lowerField, field) && !p.isAllowed(piiType, allowedPII) {
			return true
		}
	}
	
	return false
}

// validateResponse validates the response against rules
func (p *ResponseProcessor) validateResponse(data interface{}) error {
	for _, rule := range p.validationRules {
		if err := rule.Validator(data); err != nil {
			return fmt.Errorf("%s: %w", rule.Name, err)
		}
	}
	return nil
}

// enrichResponse adds metadata to the response
func (p *ResponseProcessor) enrichResponse(ctx context.Context, data interface{}) interface{} {
	enrichments := make(map[string]interface{})
	
	for _, rule := range p.enricher.enrichmentRules {
		metadata := rule.Enricher(ctx, data)
		for k, v := range metadata {
			enrichments[k] = v
		}
	}
	
	// Wrap response with enrichments
	return map[string]interface{}{
		"data":     data,
		"metadata": enrichments,
	}
}

// IsHealthy checks if the response processor is healthy
func (p *ResponseProcessor) IsHealthy() bool {
	return true
}

// NewPIIDetector creates a new PII detector
func NewPIIDetector() *PIIDetector {
	return &PIIDetector{
		patterns: map[string]*regexp.Regexp{
			"ssn":          regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`),
			"credit_card":  regexp.MustCompile(`\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b`),
			"email":        regexp.MustCompile(`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b`),
			"phone":        regexp.MustCompile(`\b(\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b`),
			"ip_address":   regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`),
			"bank_account": regexp.MustCompile(`\b\d{8,17}\b`), // Simple pattern, could be more specific
		},
	}
}

// NewRedactor creates a new redactor
func NewRedactor() *Redactor {
	return &Redactor{
		redactionStrategies: map[string]RedactionStrategy{
			"ssn":          &MaskingStrategy{keepLast: 4, placeholder: "XXX-XX-"},
			"credit_card":  &MaskingStrategy{keepLast: 4, placeholder: "****-****-****-"},
			"email":        &HashingStrategy{},
			"phone":        &MaskingStrategy{keepLast: 4, placeholder: "***-***-"},
			"ip_address":   &MaskingStrategy{keepLast: 0, placeholder: "***.***.***.***"},
			"bank_account": &MaskingStrategy{keepLast: 4, placeholder: "****"},
			"default":      &DefaultStrategy{},
		},
	}
}

func (r *Redactor) getStrategy(piiType string) RedactionStrategy {
	if strategy, exists := r.redactionStrategies[piiType]; exists {
		return strategy
	}
	return r.redactionStrategies["default"]
}

// Redaction strategies

type MaskingStrategy struct {
	keepLast    int
	placeholder string
}

func (m *MaskingStrategy) Redact(value string) string {
	if m.keepLast > 0 && len(value) > m.keepLast {
		return m.placeholder + value[len(value)-m.keepLast:]
	}
	return m.placeholder
}

func (m *MaskingStrategy) GetPlaceholder() string {
	return m.placeholder
}

type HashingStrategy struct{}

func (h *HashingStrategy) Redact(value string) string {
	// In production, use a proper hash
	return fmt.Sprintf("[HASHED_%d]", len(value))
}

func (h *HashingStrategy) GetPlaceholder() string {
	return "[HASHED]"
}

type DefaultStrategy struct{}

func (d *DefaultStrategy) Redact(value string) string {
	return "[REDACTED]"
}

func (d *DefaultStrategy) GetPlaceholder() string {
	return "[REDACTED]"
}

// NewResponseEnricher creates a new response enricher
func NewResponseEnricher() *ResponseEnricher {
	return &ResponseEnricher{
		enrichmentRules: []EnrichmentRule{
			{
				Name: "timestamp",
				Enricher: func(ctx context.Context, response interface{}) map[string]interface{} {
					return map[string]interface{}{
						"processed_at": time.Now().UTC().Format(time.RFC3339),
					}
				},
			},
			{
				Name: "request_context",
				Enricher: func(ctx context.Context, response interface{}) map[string]interface{} {
					metadata := make(map[string]interface{})
					if reqID := ctx.Value("request_id"); reqID != nil {
						metadata["request_id"] = reqID
					}
					if user := ctx.Value("user"); user != nil {
						if u, ok := user.(UserContext); ok {
							metadata["processed_for_role"] = u.Role
						}
					}
					return metadata
				},
			},
		},
	}
}

// getDefaultValidationRules returns default validation rules
func getDefaultValidationRules() []ValidationRule {
	return []ValidationRule{
		{
			Name: "no_empty_response",
			Validator: func(response interface{}) error {
				if response == nil || response == "" {
					return fmt.Errorf("empty response")
				}
				return nil
			},
		},
		{
			Name: "no_error_messages",
			Validator: func(response interface{}) error {
				// Check for common error patterns
				respStr := fmt.Sprint(response)
				errorPatterns := []string{"error:", "exception:", "failed:", "denied:"}
				for _, pattern := range errorPatterns {
					if strings.Contains(strings.ToLower(respStr), pattern) {
						return fmt.Errorf("response contains error message")
					}
				}
				return nil
			},
		},
		{
			Name: "reasonable_size",
			Validator: func(response interface{}) error {
				respStr := fmt.Sprint(response)
				if len(respStr) > 1000000 { // 1MB limit
					return fmt.Errorf("response too large")
				}
				return nil
			},
		},
	}
}