package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
)

// FieldRedactor applies redactions to content based on matched policies.
// It supports multiple redaction strategies and works with various data types.
type FieldRedactor struct {
	// Strategy implementations
	strategies map[RedactionStrategy]RedactorFunc

	// Default strategy
	defaultStrategy RedactionStrategy

	// Placeholder format
	placeholderFormat string
}

// RedactorFunc transforms a matched value.
type RedactorFunc func(value string, piiType string) string

// NewFieldRedactor creates a new field redactor with default strategies.
func NewFieldRedactor() *FieldRedactor {
	r := &FieldRedactor{
		strategies:        make(map[RedactionStrategy]RedactorFunc),
		defaultStrategy:   StrategyMask,
		placeholderFormat: "[REDACTED:%s]",
	}
	r.registerDefaultStrategies()
	return r
}

// registerDefaultStrategies sets up all built-in redaction strategies.
func (r *FieldRedactor) registerDefaultStrategies() {
	// Mask strategy: Replace middle characters with asterisks
	r.strategies[StrategyMask] = func(value, piiType string) string {
		length := len(value)
		if length <= 4 {
			return strings.Repeat("*", length)
		}
		// Keep first and last character, mask middle
		return value[:1] + strings.Repeat("*", length-2) + value[length-1:]
	}

	// Partial strategy: Show first 2 and last 2 characters
	r.strategies[StrategyPartial] = func(value, piiType string) string {
		length := len(value)
		if length <= 4 {
			return strings.Repeat("*", length)
		}
		if length <= 6 {
			return value[:1] + strings.Repeat("*", length-2) + value[length-1:]
		}
		return value[:2] + strings.Repeat("*", length-4) + value[length-2:]
	}

	// Remove strategy: Replace with typed placeholder
	r.strategies[StrategyRemove] = func(value, piiType string) string {
		return fmt.Sprintf("[REDACTED:%s]", piiType)
	}

	// Hash strategy: Replace with deterministic hash (first 8 chars)
	r.strategies[StrategyHash] = func(value, piiType string) string {
		hash := sha256.Sum256([]byte(value))
		return fmt.Sprintf("HASH_%s", hex.EncodeToString(hash[:])[:8])
	}

	// Tokenize strategy: Replace with reversible token (enterprise feature)
	r.strategies[StrategyTokenize] = func(value, piiType string) string {
		// Simple tokenization - in production this would use a vault
		hash := sha256.Sum256([]byte(value))
		return fmt.Sprintf("TOKEN_%s_%s", strings.ToUpper(piiType), hex.EncodeToString(hash[:])[:6])
	}
}

// Apply applies redactions to content based on the redaction plans.
// Returns the redacted content and a list of what was redacted.
func (r *FieldRedactor) Apply(content interface{}, contentType string, plans []RedactionPlan) (interface{}, []RedactedField) {
	if len(plans) == 0 {
		return content, nil
	}

	switch contentType {
	case "rows":
		return r.applyToRows(content, plans)
	case "json":
		return r.applyToJSON(content, plans)
	case "string":
		return r.applyToString(content, plans)
	default:
		// Try to detect type
		if rows, ok := content.([]map[string]interface{}); ok {
			return r.applyToRows(rows, plans)
		}
		if m, ok := content.(map[string]interface{}); ok {
			return r.applyToMap(m, plans, "")
		}
		if s, ok := content.(string); ok {
			return r.applyToString(s, plans)
		}
		return content, nil
	}
}

// applyToRows applies redactions to database result rows.
// Returns a new copy of the rows with redactions applied (does not modify original).
func (r *FieldRedactor) applyToRows(content interface{}, plans []RedactionPlan) (interface{}, []RedactedField) {
	rows, ok := content.([]map[string]interface{})
	if !ok {
		return content, nil
	}

	var redacted []RedactedField

	// Build pattern map for efficiency
	patternMap := r.buildPatternMap(plans)

	// Create a copy of rows to avoid modifying the original (thread safety)
	resultRows := make([]map[string]interface{}, len(rows))
	for i, row := range rows {
		resultRows[i] = make(map[string]interface{}, len(row))
		for k, v := range row {
			resultRows[i][k] = v
		}
	}

	// Process each row
	for rowIdx, row := range resultRows {
		for fieldName, fieldValue := range row {
			strValue, ok := fieldValue.(string)
			if !ok {
				continue
			}

			newValue := strValue
			for patternStr, patternPlans := range patternMap {
				re, err := regexp.Compile(patternStr)
				if err != nil {
					continue
				}

				matches := re.FindAllStringIndex(newValue, -1)
				if matches == nil {
					continue
				}

				// Apply redactions from end to start to preserve indices
				for i := len(matches) - 1; i >= 0; i-- {
					loc := matches[i]
					plan := patternPlans[0]
					matchText := newValue[loc[0]:loc[1]]

					// Get strategy function
					strategy := r.getStrategy(plan.Strategy)
					piiType := r.getPIIType(plan.Policy)

					// Apply redaction
					redactedValue := strategy(matchText, piiType)
					newValue = newValue[:loc[0]] + redactedValue + newValue[loc[1]:]

					// Record redaction
					redacted = append(redacted, RedactedField{
						Path:        fmt.Sprintf("rows[%d].%s", rowIdx, fieldName),
						OriginalLen: len(matchText),
						RedactedTo:  redactedValue,
						PolicyID:    plan.Policy.PolicyID,
						PIIType:     piiType,
					})
				}
			}

			// Update row if modified
			if newValue != strValue {
				resultRows[rowIdx][fieldName] = newValue
			}
		}
	}

	return resultRows, redacted
}

// applyToMap applies redactions to a single map (JSON object).
// Returns a new copy of the map with redactions applied (does not modify original).
func (r *FieldRedactor) applyToMap(m map[string]interface{}, plans []RedactionPlan, pathPrefix string) (map[string]interface{}, []RedactedField) {
	var redacted []RedactedField
	patternMap := r.buildPatternMap(plans)

	// Create a copy of the map to avoid modifying the original (thread safety)
	result := make(map[string]interface{}, len(m))
	for k, v := range m {
		result[k] = v
	}

	for key, value := range result {
		fieldPath := key
		if pathPrefix != "" {
			fieldPath = pathPrefix + "." + key
		}

		switch v := value.(type) {
		case string:
			newValue := v
			for patternStr, patternPlans := range patternMap {
				re, err := regexp.Compile(patternStr)
				if err != nil {
					continue
				}

				if re.MatchString(newValue) {
					plan := patternPlans[0]
					strategy := r.getStrategy(plan.Strategy)
					piiType := r.getPIIType(plan.Policy)

					originalLen := len(newValue)
					newValue = re.ReplaceAllStringFunc(newValue, func(match string) string {
						return strategy(match, piiType)
					})

					if newValue != v {
						redacted = append(redacted, RedactedField{
							Path:        fieldPath,
							OriginalLen: originalLen,
							RedactedTo:  newValue,
							PolicyID:    plan.Policy.PolicyID,
							PIIType:     piiType,
						})
					}
				}
			}
			if newValue != v {
				result[key] = newValue
			}

		case map[string]interface{}:
			nestedResult, nestedRedacted := r.applyToMap(v, plans, fieldPath)
			result[key] = nestedResult
			redacted = append(redacted, nestedRedacted...)

		case []interface{}:
			newArray := make([]interface{}, len(v))
			copy(newArray, v)
			for i, item := range newArray {
				if itemMap, ok := item.(map[string]interface{}); ok {
					nestedResult, nestedRedacted := r.applyToMap(itemMap, plans, fmt.Sprintf("%s[%d]", fieldPath, i))
					newArray[i] = nestedResult
					redacted = append(redacted, nestedRedacted...)
				}
			}
			result[key] = newArray
		}
	}

	return result, redacted
}

// applyToJSON applies redactions to arbitrary JSON content.
func (r *FieldRedactor) applyToJSON(content interface{}, plans []RedactionPlan) (interface{}, []RedactedField) {
	if m, ok := content.(map[string]interface{}); ok {
		return r.applyToMap(m, plans, "")
	}
	if arr, ok := content.([]interface{}); ok {
		var allRedacted []RedactedField
		for i, item := range arr {
			if m, ok := item.(map[string]interface{}); ok {
				_, redacted := r.applyToMap(m, plans, fmt.Sprintf("[%d]", i))
				allRedacted = append(allRedacted, redacted...)
			}
		}
		return arr, allRedacted
	}
	return content, nil
}

// applyToString applies redactions to a plain string.
func (r *FieldRedactor) applyToString(content interface{}, plans []RedactionPlan) (interface{}, []RedactedField) {
	str, ok := content.(string)
	if !ok {
		return content, nil
	}

	var redacted []RedactedField
	newStr := str
	patternMap := r.buildPatternMap(plans)

	for patternStr, patternPlans := range patternMap {
		re, err := regexp.Compile(patternStr)
		if err != nil {
			continue
		}

		matches := re.FindAllStringIndex(newStr, -1)
		if matches == nil {
			continue
		}

		// Apply redactions from end to start
		for i := len(matches) - 1; i >= 0; i-- {
			loc := matches[i]
			plan := patternPlans[0]
			matchText := newStr[loc[0]:loc[1]]

			strategy := r.getStrategy(plan.Strategy)
			piiType := r.getPIIType(plan.Policy)

			redactedValue := strategy(matchText, piiType)
			newStr = newStr[:loc[0]] + redactedValue + newStr[loc[1]:]

			redacted = append(redacted, RedactedField{
				Path:        fmt.Sprintf("string[%d:%d]", loc[0], loc[1]),
				OriginalLen: len(matchText),
				RedactedTo:  redactedValue,
				PolicyID:    plan.Policy.PolicyID,
				PIIType:     piiType,
			})
		}
	}

	return newStr, redacted
}

// buildPatternMap groups plans by pattern string for efficient matching.
func (r *FieldRedactor) buildPatternMap(plans []RedactionPlan) map[string][]RedactionPlan {
	patternMap := make(map[string][]RedactionPlan)
	for _, plan := range plans {
		patternStr := plan.Policy.PatternStr
		patternMap[patternStr] = append(patternMap[patternStr], plan)
	}
	return patternMap
}

// getStrategy returns the strategy function for a strategy type.
func (r *FieldRedactor) getStrategy(strategy RedactionStrategy) RedactorFunc {
	if fn, ok := r.strategies[strategy]; ok {
		return fn
	}
	return r.strategies[r.defaultStrategy]
}

// getPIIType extracts the PII type from a policy.
func (r *FieldRedactor) getPIIType(policy CompiledPolicy) string {
	// Try to extract from policy ID
	policyID := strings.ToLower(policy.PolicyID)
	piiTypes := []string{
		"ssn", "credit_card", "iban", "aadhaar", "pan",
		"email", "phone", "ip_address", "bank_account",
		"passport", "dob", "driver_license",
	}

	for _, t := range piiTypes {
		if strings.Contains(policyID, t) {
			return t
		}
	}

	// Fallback to category
	return string(policy.Category)
}

// SetDefaultStrategy sets the default redaction strategy.
func (r *FieldRedactor) SetDefaultStrategy(strategy RedactionStrategy) {
	r.defaultStrategy = strategy
}

// RegisterStrategy adds a custom redaction strategy.
func (r *FieldRedactor) RegisterStrategy(name RedactionStrategy, fn RedactorFunc) {
	r.strategies[name] = fn
}

// GetRedactionStrategy returns the appropriate strategy for a policy category.
func GetRedactionStrategy(category PolicyCategory, severity Severity) RedactionStrategy {
	// Critical severity always uses full masking
	if severity == SeverityCritical {
		return StrategyMask
	}

	// Default strategies by category
	switch category {
	case CategoryPIIUS, CategoryPIIIndia, CategoryPIIEU, CategoryPIISingapore:
		return StrategyMask
	case CategoryPIIGlobal:
		if severity == SeverityHigh {
			return StrategyMask
		}
		return StrategyPartial
	default:
		return StrategyRemove
	}
}
