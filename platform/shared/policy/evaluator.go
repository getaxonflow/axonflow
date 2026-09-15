// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

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
		contextWindow:    DefaultContextWindow,
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

// AcceptedMatch is one occurrence of a row's pattern that the row's validator
// accepted: its span in the input and the validator's confidence (1.0 when no
// validator gates the row).
type AcceptedMatch struct {
	Start, End int
	Confidence float64
}

// ScanAccepted is the ONE scan every detector evaluation runs, on every plane
// (#3968; ADR-065 amendment 2026-09-10, "one validator set on every plane").
//
// It walks the occurrences of re in input in order and keeps the ones the
// validator accepts, stopping once limit have been kept; limit <= 0 keeps every
// accepted occurrence. A nil validator accepts every occurrence, so a row with
// no validator still answers with its first regex hit. The context a validator
// sees is MatchContext over window - see there for why that is load-bearing.
//
// # WHY EVERY OCCURRENCE, AND NOT THE FIRST REGEX HIT
//
// The request path used to take re.FindStringIndex - the first hit only - and
// answer "no match" when the validator refused it, while the response path
// skipped a refused hit and kept scanning. So `charge 4111111111111112 then
// charge 4111111111111111` hid a Luhn-valid card from the request path and
// showed it to the response path: one detector, two answers, chosen by which
// phase asked. A validator exists to REMOVE a false occurrence, never to end
// the search, so "does this row detect anything" is answered by the first
// ACCEPTED occurrence.
//
// Every detector evaluation reaches the regex through here - the shared
// engine's Evaluate (limit 1) and EvaluateAll (all), and the proxy-tier
// engine's three walks - so the phases and the engines cannot diverge again by
// each owning a scan loop.
//
// # WHY A BOUNDED FIRST PASS
//
// A limited scan asks the regex for one occurrence, then two, then four, and
// validates only the occurrences it has not seen. FindAllStringIndex(input, n)
// returns a prefix of the full occurrence list, so this visits exactly the
// occurrences a full scan would, in the same order, but stops reading the input
// once enough are accepted. A card near the start of a long prompt costs what
// the old first-hit scan cost, not a read of the whole prompt; the re-scans are
// geometric, so a run of refused hits costs at most twice a single full pass.
func ScanAccepted(re *regexp.Regexp, input string, validator ValidatorFunc, window, limit int) []AcceptedMatch {
	var out []AcceptedMatch
	accept := func(loc []int) bool {
		confidence := 1.0
		if validator != nil {
			valid, conf := validator(input[loc[0]:loc[1]], MatchContext(input, loc[0], loc[1], window))
			if !valid {
				return false
			}
			confidence = conf
		}
		out = append(out, AcceptedMatch{Start: loc[0], End: loc[1], Confidence: confidence})
		return limit > 0 && len(out) >= limit
	}

	if limit <= 0 {
		for _, loc := range re.FindAllStringIndex(input, -1) {
			accept(loc)
		}
		return out
	}

	seen := 0
	for n := limit; ; n *= 2 {
		locs := re.FindAllStringIndex(input, n)
		for _, loc := range locs[seen:] {
			if accept(loc) {
				return out
			}
		}
		if len(locs) < n {
			return out // the input holds no further occurrence
		}
		seen = len(locs)
	}
}

// compiledPattern returns the policy's compiled regex, compiling and caching
// PatternStr when the policy carries none. ok is false when it does not compile.
func (e *PatternEvaluator) compiledPattern(policy *CompiledPolicy) (*regexp.Regexp, bool) {
	if policy.Pattern != nil {
		return policy.Pattern, true
	}
	re, err := e.getCompiledRegex(policy.PatternStr)
	return re, err == nil
}

// validatorFor returns the validator gating this policy, or nil when validators
// are disabled or none resolves.
func (e *PatternEvaluator) validatorFor(policy *CompiledPolicy) ValidatorFunc {
	if !e.enableValidators {
		return nil
	}
	return e.getValidator(policy)
}

// matchFor renders one accepted occurrence as the PolicyMatch both phases return.
func matchFor(input string, policy *CompiledPolicy, phase Phase, m AcceptedMatch) PolicyMatch {
	return PolicyMatch{
		PolicyID:   policy.PolicyID,
		PolicyName: policy.Name,
		Category:   policy.Category,
		Severity:   policy.Severity,
		Action:     policy.GetActionForPhase(phase),
		MatchText:  input[m.Start:m.End],
		StartIndex: m.Start,
		EndIndex:   m.End,
		Confidence: m.Confidence,
	}
}

// Evaluate checks input against a single policy and returns the FIRST
// occurrence its validator accepts - not the first regex hit (#3968; see
// ScanAccepted). Returns nil if no occurrence is accepted.
func (e *PatternEvaluator) Evaluate(input string, policy *CompiledPolicy) *PolicyMatch {
	if !policy.Enabled {
		return nil
	}
	re, ok := e.compiledPattern(policy)
	if !ok {
		return nil
	}
	accepted := ScanAccepted(re, input, e.validatorFor(policy), e.contextWindow, 1)
	if len(accepted) == 0 {
		return nil
	}
	m := matchFor(input, policy, PhaseRequest, accepted[0])
	return &m
}

// EvaluateAll checks input against a policy and returns EVERY occurrence its
// validator accepts. Used for response-phase evaluation where multiple PII
// instances may exist. It runs the same scan as Evaluate (ScanAccepted), so
// Evaluate's answer is always EvaluateAll's first element.
func (e *PatternEvaluator) EvaluateAll(input string, policy *CompiledPolicy) []PolicyMatch {
	if !policy.Enabled {
		return nil
	}
	re, ok := e.compiledPattern(policy)
	if !ok {
		return nil
	}
	accepted := ScanAccepted(re, input, e.validatorFor(policy), e.contextWindow, 0)
	if len(accepted) == 0 {
		return nil
	}
	matches := make([]PolicyMatch, 0, len(accepted))
	for _, m := range accepted {
		matches = append(matches, matchFor(input, policy, PhaseResponse, m))
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

	// The in-memory fallback. DB-loaded policies arrive with Validator already
	// set by the loader, which resolves it through the same ValidatorFor, so
	// the two paths cannot disagree about which validator gates a row.
	return ValidatorFor(policy.PolicyID, policy.Category)
}

// DefaultContextWindow is the number of characters taken either side of a match
// to form the `context` argument every validator receives. It is what
// NewPatternEvaluator uses, and nothing in the tree calls SetContextWindow.
const DefaultContextWindow = 50

// MatchContext builds the `context` string a ValidatorFunc is given: `window`
// characters either side of the match, clamped to the input.
//
// IT IS EXPORTED BECAUSE THE CONTEXT IS LOAD-BEARING, NOT DECORATIVE. Four
// shipped validators - ValidatePassport, ValidateDOB and the two Singapore
// ones - require a label IMMEDIATELY PRECEDING the value, which they read out
// of this string via leftContextOf. Hand any of them an empty context and they
// reject every match: the detection disappears rather than becoming less
// precise.
//
// So a caller that resolves a validator and cannot build this window has not
// wired validation, it has switched four detectors off. #3963 wired the tier
// engine, and that engine called `re.MatchString`, which returns a bool and no
// location - there was nothing to build a window from. Since #3968 both engines
// reach this function through ScanAccepted, which has every occurrence's
// location, rather than through a copy of the arithmetic each.
func MatchContext(text string, start, end, window int) string {
	contextStart := start - window
	if contextStart < 0 {
		contextStart = 0
	}
	contextEnd := end + window
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
