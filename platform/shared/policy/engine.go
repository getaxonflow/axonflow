package policy

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strconv"
	"sync"
	"time"
)

// UnifiedPolicyEngine provides phase-aware policy evaluation for MCP requests.
// It implements the Evaluator interface and is the main entry point for policy enforcement.
//
// Thread Safety: All methods are safe for concurrent use.
// Performance: Designed for <5ms p99 latency with caching and compiled patterns.
type UnifiedPolicyEngine struct {
	// Database connection
	db *sql.DB

	// Components
	loader    *PolicyLoader
	cache     *PolicyCache
	evaluator *PatternEvaluator
	redactor  *FieldRedactor
	metrics   *MetricsCollector

	// Configuration
	config EngineConfig

	// extraTextDocumentTools is the precomputed lookup set from
	// config.ExtraTextDocumentTools (capability-scoped evaluation, #2801).
	// Nil when no operator extension is configured — the built-in registry
	// in capability.go still applies.
	extraTextDocumentTools map[string]bool

	// State
	initialized bool
	stopChan    chan struct{}
	stopOnce    sync.Once
}

// Evaluator is the interface for policy evaluation.
// This allows for different implementations (e.g., mock for testing).
type Evaluator interface {
	EvaluateRequest(ctx context.Context, input string, opts EvalOptions) *RequestResult
	EvaluateResponse(ctx context.Context, content interface{}, opts EvalOptions) *ResponseResult
	InvalidateCache(tenantID string, orgID *string)
	GetStats() map[string]interface{}
}

// Ensure UnifiedPolicyEngine implements Evaluator
var _ Evaluator = (*UnifiedPolicyEngine)(nil)

// NewUnifiedPolicyEngine creates a new unified policy engine.
// It initializes all components and starts background refresh.
func NewUnifiedPolicyEngine(db *sql.DB, config EngineConfig, auditQueue AuditQueue) *UnifiedPolicyEngine {
	engine := &UnifiedPolicyEngine{
		db:                     db,
		config:                 config,
		extraTextDocumentTools: buildToolNameSet(config.ExtraTextDocumentTools),
		stopChan:               make(chan struct{}),
	}

	// Initialize cache
	engine.cache = NewPolicyCache(config.CacheTTL, config.MaxPatternCache)

	// Initialize loader
	engine.loader = NewPolicyLoader(db, engine.cache)

	// Initialize evaluator
	engine.evaluator = NewPatternEvaluator(config.EnableValidators)

	// Initialize redactor
	engine.redactor = NewFieldRedactor()

	// Initialize metrics
	engine.metrics = NewMetricsCollector(auditQueue)

	// Start background refresh if configured
	if config.RefreshInterval > 0 {
		go engine.backgroundRefresh()
	}

	engine.initialized = true
	log.Printf("[PolicyEngine] Initialized with TTL=%v, validators=%v, graceful=%v",
		config.CacheTTL, config.EnableValidators, config.GracefulDegradation)

	return engine
}

// EvaluateRequest evaluates input for REQUEST phase policies.
// This is called before connector.Query() to block dangerous queries.
//
// Performance: Returns immediately on first blocking match for minimal latency.
// Error handling: Graceful degradation if database unavailable (configurable).
func (e *UnifiedPolicyEngine) EvaluateRequest(ctx context.Context, input string, opts EvalOptions) *RequestResult {
	startTime := time.Now()

	// ADR-065 decision shadow (#3564). Nil when the shadow could not observe
	// on this deployment, and every method on a nil trace is a no-op, so an
	// off deployment pays one atomic load and allocates nothing.
	trace := newShadowTrace()

	result := &RequestResult{
		Blocked:         false,
		MatchedPolicies: make([]PolicyMatch, 0),
	}

	// Apply default tenant if not specified
	if opts.TenantID == "" {
		opts.TenantID = e.config.DefaultTenant
	}

	// Load policies from cache or database
	policies, err := e.loader.GetPolicies(ctx, opts.TenantID, opts.OrgScope, PhaseRequest)
	if err != nil {
		e.recordLoadError(err)
		// #2862: fail CLOSED on the request plane, symmetric with #2820's
		// response-plane fix. A request gate that could not load policies has
		// not scanned the input for SQLi / dangerous-command / PII-block
		// content, so it MUST block — regardless of GracefulDegradation. Unlike
		// the response plane there is no "return unprocessed content" middle
		// ground here: the request either proceeds ungoverned or is blocked.
		// EvaluationError marks this as an availability failure (could-not-scan)
		// distinct from a policy verdict, so callers can audit it as such.
		result.EvaluationError = true
		result.Blocked = true
		result.BlockReason = "Policy engine unavailable"
		result.ProcessingTimeMs = time.Since(startTime).Milliseconds()
		log.Printf("[PolicyEngine] Failed to load policies, blocking request (fail-closed): %v", err)
		trace.emit(ctx, PhaseRequest, opts, nil, !result.Blocked, true)
		return result
	}

	result.PoliciesEvaluated = len(policies)
	// The set BEFORE the three filters narrow it: it is what the loader
	// returned for this phase, and its (policy_id, updated_at) pairs are what
	// identify the policy version this evaluation ran against. A row the
	// filters remove is still part of that version - it simply did not run,
	// which the tri-state records as unknown rather than as a non-match.
	trace.setLoaded(policies)

	// Filter by categories if specified
	if len(opts.Categories) > 0 || len(opts.SkipCategories) > 0 {
		policies = e.filterByCategories(policies, opts.Categories, opts.SkipCategories)
	}

	// Capability-scoped evaluation (#2801): skip execution-class detectors for
	// tools positively classified text-document. No-op for empty/unknown
	// identities (fail-closed).
	policies = e.filterByToolCapability(policies, opts.ToolIdentity)

	// Segment applicability gate (ADR-060, #2989/#3266): a segment-scoped
	// policy applies only for a caller whose Segments contains it. Applied
	// BEFORE matching (like the two filters above) so an excluded row is
	// skipped entirely — not matched, not acted on, not reported in
	// MatchedPolicies — closing both the enforcement and the reporting leak.
	policies = e.filterBySegments(policies, opts.Segments)

	// Evaluate each policy
	for i := range policies {
		policy := &policies[i]

		trace.markRan(policy.PolicyID)
		match := e.evaluator.Evaluate(input, policy)
		if match != nil {
			action := policy.GetActionForPhase(PhaseRequest)
			// #3360: keep the row's EXPLICIT stored action beside the
			// posture-resolved one so a lever that silently WEAKENS a stored
			// action is visible to consumers (audit advisories, metrics)
			// instead of discarded. Deliberately the raw column value, NOT
			// GetActionForPhase's output: a NULL phase column resolves through
			// a category FALLBACK, which is not a stored value and must never
			// be reported as displaced (StoredAction stays empty there).
			match.StoredAction = policy.ActionRequest
			if opts.ActionOverrides != nil {
				if override, ok := opts.ActionOverrides[policy.Category]; ok {
					action = override
				}
			}
			match.Action = action
			result.MatchedPolicies = append(result.MatchedPolicies, *match)

			// Check if this is a blocking action
			if match.Action == ActionBlock {
				result.Blocked = true
				result.BlockedBy = policy
				result.BlockReason = policy.Description
				if result.BlockReason == "" {
					result.BlockReason = fmt.Sprintf("Blocked by policy: %s", policy.Name)
				}

				// Record violation
				e.metrics.RecordViolation(ctx, opts, policy, match.MatchText)
				break // Stop on first block for performance
			}
		}
	}

	// Scan parameter values individually (Issue #1287). Track which PolicyIDs
	// already matched in the query-string scan so we don't report the same
	// policy twice in MatchedPolicies — that produced confusing duplicate
	// entries like "matched_policies": ["sys_sqli_grant", "sys_sqli_grant"]
	// in the API response. The FIRST occurrence's FieldPath is preserved;
	// subsequent matches still drive the block decision but don't add another
	// entry to the list.
	if !result.Blocked && len(opts.Parameters) > 0 {
		alreadyMatched := make(map[string]bool, len(result.MatchedPolicies))
		for _, m := range result.MatchedPolicies {
			alreadyMatched[m.PolicyID] = true
		}

		for key, val := range opts.Parameters {
			paramStr := ""
			switch v := val.(type) {
			case string:
				paramStr = v
			case map[string]interface{}, []interface{}:
				if data, err := json.Marshal(v); err == nil {
					paramStr = string(data)
				}
			case float64:
				// JSON decodes numbers as float64. Use decimal notation to preserve
				// digit sequences for PII pattern matching (credit cards, SSNs, etc).
				// fmt.Sprintf("%v") produces scientific notation for large values.
				paramStr = strconv.FormatFloat(v, 'f', -1, 64)
			case int64:
				paramStr = strconv.FormatInt(v, 10)
			case bool:
				continue // booleans have no PII/compliance/injection risk
			default:
				paramStr = fmt.Sprintf("%v", v)
			}
			if paramStr == "" {
				continue
			}

			for i := range policies {
				policy := &policies[i]
				trace.markRan(policy.PolicyID)
				match := e.evaluator.Evaluate(paramStr, policy)
				if match != nil {
					action := policy.GetActionForPhase(PhaseRequest)
					match.StoredAction = policy.ActionRequest // #3360: explicit column only, see the query-scan site
					if opts.ActionOverrides != nil {
						if override, ok := opts.ActionOverrides[policy.Category]; ok {
							action = override
						}
					}
					match.Action = action
					match.FieldPath = fmt.Sprintf("parameter '%s'", key)
					if !alreadyMatched[match.PolicyID] {
						result.MatchedPolicies = append(result.MatchedPolicies, *match)
						alreadyMatched[match.PolicyID] = true
					}

					if match.Action == ActionBlock {
						result.Blocked = true
						result.BlockedBy = policy
						result.BlockReason = fmt.Sprintf("Blocked by policy %s in parameter '%s'", policy.Name, key)
						e.metrics.RecordViolation(ctx, opts, policy, match.MatchText)
						break
					}
				}
			}
			if result.Blocked {
				break
			}
		}
	}

	result.ProcessingTimeMs = time.Since(startTime).Milliseconds()

	// Record metrics asynchronously
	if e.config.EnableMetrics {
		go e.metrics.RecordEvaluation(ctx, "request", opts, result.MatchedPolicies, result.Blocked, result.ProcessingTimeMs)
	}

	// The ADR-065 shadow, LAST, after the verdict is final. It returns
	// nothing: there is no value here for this function to read, so no edit to
	// this function can make the shadow's opinion reach `result`.
	trace.emit(ctx, PhaseRequest, opts, result.MatchedPolicies, !result.Blocked, result.EvaluationError)

	return result
}

// EvaluateResponse evaluates content for RESPONSE phase policies.
// This is called after connector.Query() to redact PII in results.
//
// Returns: Possibly redacted content with metadata about what was changed.
func (e *UnifiedPolicyEngine) EvaluateResponse(ctx context.Context, content interface{}, opts EvalOptions) *ResponseResult {
	startTime := time.Now()

	result := &ResponseResult{
		Blocked:         false,
		Content:         content,
		Redacted:        false,
		RedactedFields:  make([]RedactedField, 0),
		MatchedPolicies: make([]PolicyMatch, 0),
	}

	// ADR-065 decision shadow (#3564); see the request phase for the argument.
	trace := newShadowTrace()

	// Apply default tenant if not specified
	if opts.TenantID == "" {
		opts.TenantID = e.config.DefaultTenant
	}

	// Load policies from cache or database
	policies, err := e.loader.GetPolicies(ctx, opts.TenantID, opts.OrgScope, PhaseResponse)
	if err != nil {
		e.recordLoadError(err)
		// #2820: mark couldn't-scan regardless of the degradation mode so a
		// response-plane redactor can tell this apart from scanned-clean and
		// fail closed. Under GracefulDegradation the content is returned
		// unprocessed here, but the EvaluationError signal lets a storage/
		// response redactor withhold rather than forward raw PII. (The request
		// plane fails CLOSED outright under the same condition — see #2862 in
		// EvaluateRequest; there is no "return unprocessed" middle ground when
		// the decision is proceed-or-block rather than forward-or-withhold.)
		result.EvaluationError = true
		if e.config.GracefulDegradation {
			log.Printf("[PolicyEngine] Failed to load policies, returning unprocessed (evaluation_error): %v", err)
			result.ProcessingTimeMs = time.Since(startTime).Milliseconds()
			trace.emit(ctx, PhaseResponse, opts, nil, !result.Blocked, true)
			return result
		}
		result.Blocked = true
		result.BlockReason = "Policy engine unavailable"
		result.ProcessingTimeMs = time.Since(startTime).Milliseconds()
		trace.emit(ctx, PhaseResponse, opts, nil, !result.Blocked, true)
		return result
	}

	result.PoliciesEvaluated = len(policies)
	// See the request phase: the set BEFORE the filters is the policy version
	// this evaluation ran against.
	trace.setLoaded(policies)

	// Filter by categories if specified
	if len(opts.Categories) > 0 || len(opts.SkipCategories) > 0 {
		policies = e.filterByCategories(policies, opts.Categories, opts.SkipCategories)
	}

	// Capability-scoped evaluation (#2801): same partition as the request
	// phase — a text-document tool's OUTPUT is document text, not a statement
	// any downstream executor runs. The content-borne families (PII,
	// sensitive-data, prompt-injection redaction per core/128) are untouched.
	policies = e.filterByToolCapability(policies, opts.ToolIdentity)

	// Segment applicability gate (ADR-060, #2989/#3266): same rule as the
	// request phase — a segment-scoped policy applies only for a caller
	// whose Segments contains it; excluded rows are skipped entirely (not
	// matched, not redacted/blocked, not reported in MatchedPolicies).
	policies = e.filterBySegments(policies, opts.Segments)

	// Convert content to scannable string
	scannable := e.toScannable(content)
	if scannable == "" {
		result.ProcessingTimeMs = time.Since(startTime).Milliseconds()
		// NOTHING WAS SCANNED, so no detector ran and every row is unknown.
		// This is deliberately still observed: it is a real evaluation the
		// plane performed and permitted, and an empty response body is exactly
		// the kind of traffic that would otherwise make a plane look busier
		// than the window it actually contributes to.
		trace.emit(ctx, PhaseResponse, opts, result.MatchedPolicies, !result.Blocked, result.EvaluationError)
		return result
	}

	// Collect redaction plans
	var redactionPlans []RedactionPlan

	for i := range policies {
		policy := &policies[i]

		trace.markRan(policy.PolicyID)
		matches := e.evaluator.EvaluateAll(scannable, policy)
		for _, match := range matches {
			action := policy.GetActionForPhase(PhaseResponse)
			match.StoredAction = policy.ActionResponse // #3360: explicit column only, see the request-phase site
			if opts.ActionOverrides != nil {
				if override, ok := opts.ActionOverrides[policy.Category]; ok {
					action = override
				}
			}
			match.Action = action
			result.MatchedPolicies = append(result.MatchedPolicies, match)

			switch match.Action {
			case ActionBlock:
				result.Blocked = true
				result.BlockedBy = policy
				result.BlockReason = policy.Description
				if result.BlockReason == "" {
					result.BlockReason = fmt.Sprintf("Blocked by policy: %s", policy.Name)
				}
				e.metrics.RecordViolation(ctx, opts, policy, match.MatchText)

			case ActionRedact:
				redactionPlans = append(redactionPlans, RedactionPlan{
					Match:    match,
					Policy:   *policy,
					Strategy: GetRedactionStrategy(policy.Category, policy.Severity),
				})
			}
		}
	}

	// Apply redactions if not blocked
	if !result.Blocked && len(redactionPlans) > 0 {
		// Limit redactions if configured. Statement-removal plans (prompt-injection
		// sanitization, #2738) are SECURITY-critical and must never be dropped by the
		// cap, so keep them all and apply the cap only to the span (PII) plans -
		// otherwise a response crafted with many PII-shaped tokens ahead of the
		// injection match could push the injection plan past MaxRedactions and let it
		// through unsanitized.
		if opts.MaxRedactions > 0 && len(redactionPlans) > opts.MaxRedactions {
			kept := make([]RedactionPlan, 0, opts.MaxRedactions)
			spanBudget := opts.MaxRedactions
			for _, p := range redactionPlans {
				if p.Strategy == StrategyRemoveStatement {
					kept = append(kept, p)
					continue
				}
				if spanBudget > 0 {
					kept = append(kept, p)
					spanBudget--
					continue
				}
				// DROPPED, AND THE SHADOW HAS TO KNOW. The policy stays in
				// result.MatchedPolicies - it did match - so without this the
				// shadow would attribute a field_redact to a policy that
				// produced no redaction, on BOTH sides, and record the
				// resulting agreement as a match.
				trace.noteRedactionDropped(p.Match.PolicyID)
			}
			redactionPlans = kept
		}

		// Detect content type
		contentType := e.detectContentType(content)

		// Apply redactions
		result.Content, result.RedactedFields = e.redactor.Apply(content, contentType, redactionPlans)
		result.Redacted = len(result.RedactedFields) > 0

		// Record redaction metrics
		e.metrics.RecordRedaction(len(result.RedactedFields))
	}

	result.ProcessingTimeMs = time.Since(startTime).Milliseconds()

	// Record metrics asynchronously
	if e.config.EnableMetrics {
		go e.metrics.RecordEvaluation(ctx, "response", opts, result.MatchedPolicies, result.Blocked, result.ProcessingTimeMs)
	}

	// The ADR-065 shadow, LAST, after the verdict and every redaction are
	// final. It returns nothing.
	trace.emit(ctx, PhaseResponse, opts, result.MatchedPolicies, !result.Blocked, result.EvaluationError)

	return result
}

// recordLoadError records a policy-load failure metric, distinguishing the
// #3048 item-10 empty-system-set state (policy data unreachable — RLS-blind
// read / missing seeds) from a plain load failure (DB unavailable) so
// operators can tell the two apart. Both states fail closed at the gates.
func (e *UnifiedPolicyEngine) recordLoadError(err error) {
	if errors.Is(err, ErrEmptySystemPolicySet) {
		e.metrics.RecordError("load_empty_system_set")
		return
	}
	e.metrics.RecordError("load")
}

// EnabledPIICategories returns the distinct PII categories (by the pii-*/media-pii
// convention, see IsPIIPolicyCategory) that have at least one ENABLED policy for
// the tenant in the given phase. It is the source for policy-derived PII scoping:
// coverage = (enabled policies ∩ the PII convention), so a newly-seeded pii-*
// category is auto-included with no hardcoded category list to maintain.
//
// IMPORTANT: returns nil (not an empty non-nil slice) when no PII policies are
// enabled. Callers MUST treat nil as "no PII to evaluate" and skip the response
// pass — passing an empty Categories to EvaluateResponse evaluates ALL policies
// (the whitelist short-circuits when both include and exclude are empty).
func (e *UnifiedPolicyEngine) EnabledPIICategories(ctx context.Context, tenantID string, orgID *string, phase Phase) []PolicyCategory {
	policies, err := e.loader.GetPolicies(ctx, tenantID, orgID, phase)
	if err != nil {
		return nil
	}
	seen := make(map[PolicyCategory]bool)
	var cats []PolicyCategory
	for i := range policies {
		if !policies[i].Enabled {
			continue
		}
		c := policies[i].Category
		if IsPIIPolicyCategory(c) && !seen[c] {
			seen[c] = true
			cats = append(cats, c)
		}
	}
	return cats
}

// EnabledSensitiveDataCategories returns []{CategorySensitiveData} when this
// tenant has at least one ENABLED sensitive-data (secrets) policy for the phase,
// else nil. It mirrors EnabledPIICategories so the secrets category can be folded
// into the request/response evaluation set the same policy-derived way — without
// the empty-Categories whitelist footgun (nil = "no sensitive-data to evaluate",
// callers must NOT pass it as an empty include set).
//
// Sensitive-data is a seeded system category (migration core/035: passwords, API
// keys, tokens, secrets, credentials, connection strings); its runtime action is
// driven by the profile / SENSITIVE_DATA_ACTION lever via ActionOverrides
// (default warn, strict/compliance block). Folding the category in here is what
// makes that lever reach the request AND response planes (#2705) — previously
// only PII categories were evaluated, so secrets were never block/warn-enforced.
func (e *UnifiedPolicyEngine) EnabledSensitiveDataCategories(ctx context.Context, tenantID string, orgID *string, phase Phase) []PolicyCategory {
	policies, err := e.loader.GetPolicies(ctx, tenantID, orgID, phase)
	if err != nil {
		return nil
	}
	for i := range policies {
		if policies[i].Enabled && policies[i].Category == CategorySensitiveData {
			return []PolicyCategory{CategorySensitiveData}
		}
	}
	return nil
}

// EnabledSecurityDangerousCategories returns []{CategorySecurityDangerous} when
// this tenant has at least one ENABLED security-dangerous policy for the phase,
// else nil. It mirrors EnabledSensitiveDataCategories so the dangerous-command /
// indirect prompt-injection category can be folded into the request/response
// evaluation set the same policy-derived way, without the empty-Categories
// whitelist footgun (nil = "no security-dangerous to evaluate", callers must NOT
// pass it as an empty include set).
//
// security-dangerous is a seeded system category covering dangerous shell
// commands (migration core/059) and indirect prompt-injection patterns
// (migration core/116: instruction-override, role-reassignment, system-prompt
// exfiltration, template/bracket markers; R&C section 5.1, OWASP LLM01). Its
// runtime action is driven by the profile / DANGEROUS_COMMAND_ACTION lever via
// ActionOverrides (default/strict/compliance block, dev warn). Folding the
// category in here on PhaseResponse is what makes a malicious instruction
// returned in tool OUTPUT re-enter governance (#2727); previously only the
// request plane evaluated it (these policies seeded phase='request'), so an
// injection string in a connector free-text field reached the model ungoverned.
func (e *UnifiedPolicyEngine) EnabledSecurityDangerousCategories(ctx context.Context, tenantID string, orgID *string, phase Phase) []PolicyCategory {
	policies, err := e.loader.GetPolicies(ctx, tenantID, orgID, phase)
	if err != nil {
		return nil
	}
	for i := range policies {
		if policies[i].Enabled && policies[i].Category == CategorySecurityDangerous {
			return []PolicyCategory{CategorySecurityDangerous}
		}
	}
	return nil
}

// PoliciesLoadable reports whether the engine can currently load the policy
// set for (tenant, phase) — nil on success, the load error otherwise (#2820).
//
// It exists because the Enabled*Categories helpers return nil on BOTH "tenant
// has no policies in this category" and a load error, so a response-plane
// caller that enumerates categories cannot distinguish "nothing to redact"
// from "could not load policies" and would skip its scan (fail OPEN) on a load
// error. Response-plane redactors MUST call this before category enumeration
// and fail CLOSED (withhold/block) when it returns an error. The call is
// cache-backed (same cache the subsequent Enabled*/EvaluateResponse calls hit),
// so on success it warms the entry those calls reuse within the request.
func (e *UnifiedPolicyEngine) PoliciesLoadable(ctx context.Context, tenantID string, orgID *string, phase Phase) error {
	if tenantID == "" {
		tenantID = e.config.DefaultTenant
	}
	_, err := e.loader.GetPolicies(ctx, tenantID, orgID, phase)
	return err
}

// HasSegmentScopedPolicies reports whether the effective policy set for
// (tenant, org, phase) contains at least one ENABLED segment-scoped row
// (SegmentID != "", ADR-060 #2989/#3266) - that is, whether the verdict for
// this (tenant, org, phase) can depend on the caller's governance-segment
// membership at all.
//
// It exists for the fail-closed question filterBySegments cannot answer on
// its own: a caller whose segment membership is INDETERMINATE (no validated
// per-user identity to resolve against) must not be evaluated against a
// silently narrowed policy set, because a nil Segments excludes every
// segment-scoped row (AppliesToSegments) and that exclusion is
// indistinguishable from "resolved to no segments". A plane that cannot
// determine the caller's segments must therefore DENY when this returns
// true, and may proceed org-only when it returns false. #3430 wires exactly
// that on the agent MCP-server JSON-RPC plane
// (resolveMCPServerSegmentsForPolicy, platform/agent/mcp_identity.go).
//
// Two returns, deliberately: ok == false means the policy set could not be
// LOADED, so the answer is unknown and the caller MUST fail closed - the
// same trap PoliciesLoadable exists for above (a single bool would collapse
// "no segment-scoped rows" and "could not tell" into the fail-OPEN answer).
//
// Deliberately conservative on ONE axis: it inspects the whole enabled
// policy set for the phase, BEFORE the category / tool-capability filters a
// given caller's evaluation would additionally apply. A segment-scoped row
// in a category this particular plane does not evaluate therefore still
// answers true. That direction is the safe one (a spurious deny, never a
// spurious allow), and segment-scoped rows are deliberately operator-created
// and rare; modelling each caller's category set here would duplicate the
// evaluation path's filters and drift from them.
//
// Cache-backed (the same loader cache the subsequent EvaluateRequest /
// EvaluateResponse call hits), so it warms rather than duplicates that load.
func (e *UnifiedPolicyEngine) HasSegmentScopedPolicies(ctx context.Context, tenantID string, orgID *string, phase Phase) (present bool, ok bool) {
	if tenantID == "" {
		tenantID = e.config.DefaultTenant
	}
	policies, err := e.loader.GetPolicies(ctx, tenantID, orgID, phase)
	if err != nil {
		return false, false
	}
	for i := range policies {
		if policies[i].Enabled && policies[i].SegmentID != "" {
			return true, true
		}
	}
	return false, true
}

// InvalidateCache forces a cache refresh for a tenant.
func (e *UnifiedPolicyEngine) InvalidateCache(tenantID string, orgID *string) {
	e.cache.Invalidate(tenantID, orgID)
}

// InvalidateAllCaches clears the entire policy cache for all tenants.
// Used when global policy changes (e.g., integration activation) affect
// every tenant's effective policy set.
func (e *UnifiedPolicyEngine) InvalidateAllCaches() {
	e.cache.InvalidateAll()
}

// GetStats returns engine statistics.
func (e *UnifiedPolicyEngine) GetStats() map[string]interface{} {
	return map[string]interface{}{
		"cache_stats":     e.cache.GetStats(),
		"evaluator_stats": e.evaluator.GetStats(),
		"metrics_stats":   e.metrics.GetStats(),
		"initialized":     e.initialized,
		"config": map[string]interface{}{
			"cache_ttl":            e.config.CacheTTL.String(),
			"max_pattern_cache":    e.config.MaxPatternCache,
			"validators_enabled":   e.config.EnableValidators,
			"metrics_enabled":      e.config.EnableMetrics,
			"graceful_degradation": e.config.GracefulDegradation,
		},
	}
}

// Stop stops the background refresh goroutine.
// It is safe to call multiple times.
func (e *UnifiedPolicyEngine) Stop() {
	e.stopOnce.Do(func() {
		close(e.stopChan)
	})
}

// IsTextDocumentTool reports whether the identity positively classifies as a
// text-document tool under this engine's registry (built-in + the Enterprise
// AXONFLOW_TEXT_DOCUMENT_TOOLS extension), honoring the kill switch. Exposed
// so adjacent execution-class detectors OUTSIDE this engine (the SQLi response
// middleware in the agent) apply the identical scope — plane divergence here
// would re-introduce the FP class on one plane while fixing the other.
func (e *UnifiedPolicyEngine) IsTextDocumentTool(identity string) bool {
	if e.config.DisableCapabilityScoping {
		return false
	}
	return isTextDocumentTool(identity, e.extraTextDocumentTools)
}

// filterByToolCapability drops execution-class policies when — and only when
// — the tool identity positively classifies as text-document (#2801). Both
// legs fail closed: an empty/unclassified identity keeps every policy, and a
// policy not positively classified execution-class keeps evaluating.
func (e *UnifiedPolicyEngine) filterByToolCapability(policies []CompiledPolicy, toolIdentity string) []CompiledPolicy {
	if toolIdentity == "" || !e.IsTextDocumentTool(toolIdentity) {
		return policies
	}
	filtered := make([]CompiledPolicy, 0, len(policies))
	for i := range policies {
		if IsExecutionScopedPolicy(&policies[i]) {
			continue
		}
		filtered = append(filtered, policies[i])
	}
	return filtered
}

// filterBySegments drops segment-scoped policies (SegmentID != "") that the
// caller's Segments set does not contain (ADR-060, #2989/#3266). Mirrors
// filterByToolCapability's shape: applied once, before evaluation, so an
// excluded row never reaches Evaluate/EvaluateAll and therefore never
// matches, never acts, and never appears in MatchedPolicies. Non-segment-
// scoped policies (SegmentID == "") always pass through unchanged — this is
// restriction-only, it can only remove segment-scoped rows, never affect the
// tenant/org-wide policy set that existed before #2989.
func (e *UnifiedPolicyEngine) filterBySegments(policies []CompiledPolicy, segments []string) []CompiledPolicy {
	hasSegmentScoped := false
	for i := range policies {
		if policies[i].SegmentID != "" {
			hasSegmentScoped = true
			break
		}
	}
	if !hasSegmentScoped {
		return policies
	}

	filtered := make([]CompiledPolicy, 0, len(policies))
	for i := range policies {
		if policies[i].AppliesToSegments(segments) {
			filtered = append(filtered, policies[i])
		}
	}
	return filtered
}

// filterByCategories filters policies by category inclusion/exclusion.
func (e *UnifiedPolicyEngine) filterByCategories(policies []CompiledPolicy, include, exclude []PolicyCategory) []CompiledPolicy {
	if len(include) == 0 && len(exclude) == 0 {
		return policies
	}

	includeMap := make(map[PolicyCategory]bool)
	for _, c := range include {
		includeMap[c] = true
	}

	excludeMap := make(map[PolicyCategory]bool)
	for _, c := range exclude {
		excludeMap[c] = true
	}

	filtered := make([]CompiledPolicy, 0, len(policies))
	for _, p := range policies {
		if excludeMap[p.Category] {
			continue
		}
		if len(include) > 0 && !includeMap[p.Category] {
			continue
		}
		filtered = append(filtered, p)
	}

	return filtered
}

// toScannable converts content to a scannable string.
func (e *UnifiedPolicyEngine) toScannable(content interface{}) string {
	switch v := content.(type) {
	case string:
		return v
	case []map[string]interface{}:
		// Database rows - concatenate all string values
		var sb []byte
		for _, row := range v {
			for _, val := range row {
				if s, ok := val.(string); ok {
					sb = append(sb, s...)
					sb = append(sb, ' ')
				}
			}
		}
		return string(sb)
	case map[string]interface{}:
		// Single object - concatenate all string values
		var sb []byte
		e.appendStrings(&sb, v)
		return string(sb)
	default:
		return fmt.Sprintf("%v", v)
	}
}

// appendStrings recursively appends string values from a map.
func (e *UnifiedPolicyEngine) appendStrings(sb *[]byte, m map[string]interface{}) {
	for _, val := range m {
		switch v := val.(type) {
		case string:
			*sb = append(*sb, v...)
			*sb = append(*sb, ' ')
		case map[string]interface{}:
			e.appendStrings(sb, v)
		case []interface{}:
			for _, item := range v {
				if mm, ok := item.(map[string]interface{}); ok {
					e.appendStrings(sb, mm)
				}
			}
		}
	}
}

// detectContentType detects the type of content for redaction.
func (e *UnifiedPolicyEngine) detectContentType(content interface{}) string {
	switch content.(type) {
	case []map[string]interface{}:
		return "rows"
	case map[string]interface{}:
		return "json"
	case string:
		return "string"
	default:
		return "unknown"
	}
}

// backgroundRefresh periodically refreshes the policy cache.
func (e *UnifiedPolicyEngine) backgroundRefresh() {
	ticker := time.NewTicker(e.config.RefreshInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			if err := e.loader.RefreshAll(ctx); err != nil {
				log.Printf("[PolicyEngine] Background refresh failed: %v", err)
			}
			cancel()
		case <-e.stopChan:
			return
		}
	}
}

// Global engine instance (singleton pattern)
var (
	globalEngine     *UnifiedPolicyEngine
	globalEngineMu   sync.RWMutex
	globalEngineOnce sync.Once
)

// InitGlobalEngine initializes the global policy engine.
// This should be called once during application startup.
func InitGlobalEngine(db *sql.DB, config EngineConfig, auditQueue AuditQueue) {
	globalEngineOnce.Do(func() {
		globalEngineMu.Lock()
		defer globalEngineMu.Unlock()
		globalEngine = NewUnifiedPolicyEngine(db, config, auditQueue)
	})
}

// GetGlobalEngine returns the global policy engine.
// Returns nil if not initialized.
func GetGlobalEngine() *UnifiedPolicyEngine {
	globalEngineMu.RLock()
	defer globalEngineMu.RUnlock()
	return globalEngine
}

// SetGlobalEngine sets the global policy engine (for testing).
func SetGlobalEngine(engine *UnifiedPolicyEngine) {
	globalEngineMu.Lock()
	defer globalEngineMu.Unlock()
	globalEngine = engine
}

// Helper functions for API response building

// BuildPolicyInfo creates a PolicyInfo from request and response results.
func BuildPolicyInfo(request *RequestResult, response *ResponseResult) *PolicyInfo {
	var reqInfo, respInfo *PolicyInfo
	if request != nil {
		reqInfo = request.ToInfo()
	}
	if response != nil {
		respInfo = response.ToInfo()
	}
	return MergePolicyInfo(reqInfo, respInfo)
}

// GetRedactedFieldPaths extracts field paths from a ResponseResult.
func GetRedactedFieldPaths(result *ResponseResult) []string {
	if result == nil || len(result.RedactedFields) == 0 {
		return nil
	}
	paths := make([]string, len(result.RedactedFields))
	for i, rf := range result.RedactedFields {
		paths[i] = rf.Path
	}
	return paths
}
