package policy

import (
	"regexp"
	"strings"
	"sync"
)

// PatternEvaluator handles pattern matching with caching and validation.
// It is thread-safe and optimized for high-throughput evaluation.
type PatternEvaluator struct {
	// Configuration
	enableValidators bool

	// Validator registry by PII type
	validators map[string]ValidatorFunc

	// Compiled regex cache
	mu           sync.RWMutex
	regexCache   map[string]*regexp.Regexp
	maxCacheSize int
	cacheSize    int

	// Context extraction window
	contextWindow int
}

// NewPatternEvaluator creates a new pattern evaluator.
func NewPatternEvaluator(enableValidators bool) *PatternEvaluator {
	e := &PatternEvaluator{
		enableValidators: enableValidators,
		validators:       make(map[string]ValidatorFunc),
		regexCache:       make(map[string]*regexp.Regexp),
		maxCacheSize:     1000,
		contextWindow:    50, // Characters before/after match for context
	}

	// Register built-in validators
	if enableValidators {
		e.registerBuiltinValidators()
	}

	return e
}

// registerBuiltinValidators sets up all built-in PII validators.
func (e *PatternEvaluator) registerBuiltinValidators() {
	e.validators["credit_card"] = ValidateCreditCard
	e.validators["ssn"] = ValidateSSN
	e.validators["iban"] = ValidateIBAN
	e.validators["aadhaar"] = ValidateAadhaar
	e.validators["pan"] = ValidatePAN
	e.validators["email"] = ValidateEmail
	e.validators["phone"] = ValidatePhone
	e.validators["ip_address"] = ValidateIPAddress
	e.validators["bank_account"] = ValidateBankAccount
}

// Evaluate checks input against a single policy and returns the first match.
// Returns nil if no match is found.
func (e *PatternEvaluator) Evaluate(input string, policy *CompiledPolicy) *PolicyMatch {
	if !policy.Enabled {
		return nil
	}

	// Get compiled regex
	re := policy.Pattern
	if re == nil {
		var err error
		re, err = e.getCompiledRegex(policy.PatternStr)
		if err != nil {
			return nil
		}
	}

	// Find first match
	loc := re.FindStringIndex(input)
	if loc == nil {
		return nil
	}

	matchText := input[loc[0]:loc[1]]

	// Run validator if enabled and available
	confidence := 1.0
	if e.enableValidators {
		validator := e.getValidator(policy)
		if validator != nil {
			context := e.extractContext(input, loc[0], loc[1])
			valid, conf := validator(matchText, context)
			if !valid {
				return nil // Validator rejected the match
			}
			confidence = conf
		}
	}

	return &PolicyMatch{
		PolicyID:   policy.PolicyID,
		PolicyName: policy.Name,
		Category:   policy.Category,
		Severity:   policy.Severity,
		Action:     policy.GetActionForPhase(PhaseRequest),
		MatchText:  matchText,
		StartIndex: loc[0],
		EndIndex:   loc[1],
		Confidence: confidence,
	}
}

// EvaluateAll checks input against a policy and returns ALL matches.
// Used for response-phase evaluation where multiple PII instances may exist.
func (e *PatternEvaluator) EvaluateAll(input string, policy *CompiledPolicy) []PolicyMatch {
	if !policy.Enabled {
		return nil
	}

	// Get compiled regex
	re := policy.Pattern
	if re == nil {
		var err error
		re, err = e.getCompiledRegex(policy.PatternStr)
		if err != nil {
			return nil
		}
	}

	// Find all matches
	locs := re.FindAllStringIndex(input, -1)
	if locs == nil {
		return nil
	}

	var matches []PolicyMatch
	validator := e.getValidator(policy)

	for _, loc := range locs {
		matchText := input[loc[0]:loc[1]]

		// Run validator if enabled
		confidence := 1.0
		if e.enableValidators && validator != nil {
			context := e.extractContext(input, loc[0], loc[1])
			valid, conf := validator(matchText, context)
			if !valid {
				continue // Skip invalid matches
			}
			confidence = conf
		}

		matches = append(matches, PolicyMatch{
			PolicyID:   policy.PolicyID,
			PolicyName: policy.Name,
			Category:   policy.Category,
			Severity:   policy.Severity,
			Action:     policy.GetActionForPhase(PhaseResponse),
			MatchText:  matchText,
			StartIndex: loc[0],
			EndIndex:   loc[1],
			Confidence: confidence,
		})
	}

	return matches
}

// EvaluateMultiple evaluates input against multiple policies.
// Returns on first blocking match for request-phase (fast path).
func (e *PatternEvaluator) EvaluateMultiple(input string, policies []CompiledPolicy, phase Phase) []PolicyMatch {
	var matches []PolicyMatch

	for i := range policies {
		policy := &policies[i]

		if phase == PhaseRequest {
			// Request phase: return on first match (fast path)
			match := e.Evaluate(input, policy)
			if match != nil {
				match.Action = policy.GetActionForPhase(phase)
				matches = append(matches, *match)

				// For blocking actions, stop immediately
				if match.Action == ActionBlock {
					return matches
				}
			}
		} else {
			// Response phase: collect all matches for redaction
			policyMatches := e.EvaluateAll(input, policy)
			for _, m := range policyMatches {
				m.Action = policy.GetActionForPhase(phase)
				matches = append(matches, m)
			}
		}
	}

	return matches
}

// getCompiledRegex returns a cached compiled regex or compiles and caches it.
func (e *PatternEvaluator) getCompiledRegex(pattern string) (*regexp.Regexp, error) {
	// Fast path: check cache with read lock
	e.mu.RLock()
	if re, exists := e.regexCache[pattern]; exists {
		e.mu.RUnlock()
		return re, nil
	}
	e.mu.RUnlock()

	// Slow path: compile and cache with write lock
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	// Double-check after acquiring write lock
	if cached, exists := e.regexCache[pattern]; exists {
		return cached, nil
	}

	// Add to cache if not full
	if e.cacheSize < e.maxCacheSize {
		e.regexCache[pattern] = re
		e.cacheSize++
	}

	return re, nil
}

// getValidator returns the appropriate validator for a policy.
func (e *PatternEvaluator) getValidator(policy *CompiledPolicy) ValidatorFunc {
	// First check if policy has a custom validator
	if policy.Validator != nil {
		return policy.Validator
	}

	// Try to get validator by policy ID pattern
	policyID := strings.ToLower(policy.PolicyID)

	// Map policy IDs to validator types
	validatorMappings := map[string]string{
		"credit_card": "credit_card",
		"ssn":         "ssn",
		"iban":        "iban",
		"aadhaar":     "aadhaar",
		"pan":         "pan",
		"email":       "email",
		"phone":       "phone",
		"ip_address":  "ip_address",
		"ip":          "ip_address",
		"bank_account": "bank_account",
		"bank":        "bank_account",
	}

	for key, validatorType := range validatorMappings {
		if strings.Contains(policyID, key) {
			return e.validators[validatorType]
		}
	}

	// Fallback: try to get validator by category
	return GetValidatorForCategory(policy.Category)
}

// extractContext extracts surrounding text for context-aware validation.
func (e *PatternEvaluator) extractContext(text string, start, end int) string {
	contextStart := start - e.contextWindow
	if contextStart < 0 {
		contextStart = 0
	}
	contextEnd := end + e.contextWindow
	if contextEnd > len(text) {
		contextEnd = len(text)
	}
	return text[contextStart:contextEnd]
}

// GetStats returns evaluator statistics.
func (e *PatternEvaluator) GetStats() EvaluatorStats {
	e.mu.RLock()
	defer e.mu.RUnlock()

	var registeredTypes []string
	for typeName := range e.validators {
		registeredTypes = append(registeredTypes, typeName)
	}

	return EvaluatorStats{
		CachedPatterns:    e.cacheSize,
		MaxPatternCache:   e.maxCacheSize,
		ValidatorsEnabled: e.enableValidators,
		RegisteredTypes:   registeredTypes,
	}
}

// RegisterValidator adds a custom validator for a PII type.
func (e *PatternEvaluator) RegisterValidator(piiType string, validator ValidatorFunc) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.validators[strings.ToLower(piiType)] = validator
}

// SetContextWindow sets the context extraction window size.
func (e *PatternEvaluator) SetContextWindow(chars int) {
	e.contextWindow = chars
}

// ClearCache clears the compiled regex cache.
func (e *PatternEvaluator) ClearCache() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.regexCache = make(map[string]*regexp.Regexp)
	e.cacheSize = 0
}
