// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package policy

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"sort"
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
	// The installed policy packs' detectors ride on every load (installed_packs.go).
	engine.loader.installed = config.InstalledDetectors

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
// Every detector runs, past a block too: the detector facts it returns are what
// the enforcing seams decide from, and a detector it skipped would read unknown
// to the anchored engine. Blocked, BlockedBy and BlockReason are the first
// block's. A policy load that fails blocks the request, fail-closed (#2862),
// whatever GracefulDegradation says.
func (e *UnifiedPolicyEngine) EvaluateRequest(ctx context.Context, input string, opts EvalOptions) *RequestResult {
	startTime := time.Now()

	// The detector facts every enforcing seam decides from (detector_facts.go).
	trace := newDetectorTrace()

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
		result.Observation = trace.facts(nil)
		return result
	}

	result.PoliciesEvaluated = len(policies)
	// The set BEFORE the three filters narrow it. A row the category or segment
	// filter removes did not run, which the anchored engine reads as unknown
	// rather than as a non-match; a row capability scoping removes was decided
	// not to apply, which it reads as a non-match (detectorTrace.scopeOut).
	trace.setLoaded(policies)

	// Filter by categories if specified
	if len(opts.Categories) > 0 || len(opts.SkipCategories) > 0 {
		policies = e.filterByCategories(policies, opts.Categories, opts.SkipCategories)
	}

	// Capability-scoped evaluation (#2801): skip execution-class detectors for
	// tools positively classified text-document. No-op for empty/unknown
	// identities (fail-closed).
	capabilityScoped := e.filterByToolCapability(policies, opts.ToolIdentity)
	trace.scopeOut(opts.ToolIdentity, policies, capabilityScoped)
	policies = capabilityScoped

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

			// THE FIRST BLOCK IS THE VERDICT, AND THE LOOP DOES NOT STOP THERE.
			// Blocked, BlockedBy, BlockReason and the violation are the first
			// block's, as they always were, so a legacy reader of this result
			// reads what it read before. But every enforcing seam decides from
			// this pass's detector facts, and a detector the loop never reached
			// reads UNKNOWN to the anchored engine: a legacy block row the
			// anchored bundle does not carry (a seeded pack row, an
			// organization's own pre-v11 row) would turn every request it matches
			// into an unknown_constraint refusal. So every detector runs, and a
			// later block changes nothing.
			if match.Action == ActionBlock && !result.Blocked {
				result.Blocked = true
				result.BlockedBy = policy
				result.BlockReason = policy.Description
				if result.BlockReason == "" {
					result.BlockReason = fmt.Sprintf("Blocked by policy: %s", policy.Name)
				}

				// Record violation
				e.metrics.RecordViolation(ctx, opts, policy, match.MatchText)
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
	//
	// The scan runs whether or not the query string blocked, for the reason
	// given at the first loop's block: its matches are detector facts too.
	// The keys are walked in sorted order, so the first block, and with it
	// BlockedBy, is the same on every evaluation of the same request.
	if len(opts.Parameters) > 0 {
		alreadyMatched := make(map[string]bool, len(result.MatchedPolicies))
		for _, m := range result.MatchedPolicies {
			alreadyMatched[m.PolicyID] = true
		}

		keys := make([]string, 0, len(opts.Parameters))
		for key := range opts.Parameters {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			paramStr, scanned := ParameterScanText(opts.Parameters[key])
			if !scanned {
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

					if match.Action == ActionBlock && !result.Blocked {
						result.Blocked = true
						result.BlockedBy = policy
						result.BlockReason = fmt.Sprintf("Blocked by policy %s in parameter '%s'", policy.Name, key)
						e.metrics.RecordViolation(ctx, opts, policy, match.MatchText)
					}
				}
			}
		}
	}

	result.ProcessingTimeMs = time.Since(startTime).Milliseconds()

	// Record metrics asynchronously
	if e.config.EnableMetrics {
		go e.metrics.RecordEvaluation(ctx, "request", opts, result.MatchedPolicies, result.Blocked, result.ProcessingTimeMs)
	}

	// The detector facts, LAST, after the verdict is final: the row facts an
	// enforcing seam reads as its detector inputs (decide, #3895).
	// EvaluateResponse assigns its response pass's facts the same way, for the
	// MCP response seam (#3564).
	result.Observation = trace.facts(result.MatchedPolicies)

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

	// The detector facts; see the request phase.
	trace := newDetectorTrace()

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
			result.Observation = trace.facts(nil)
			return result
		}
		result.Blocked = true
		result.BlockReason = "Policy engine unavailable"
		result.ProcessingTimeMs = time.Since(startTime).Milliseconds()
		result.Observation = trace.facts(nil)
		return result
	}

	result.PoliciesEvaluated = len(policies)
	// See the request phase: the set BEFORE the filters.
	trace.setLoaded(policies)

	// Filter by categories if specified
	if len(opts.Categories) > 0 || len(opts.SkipCategories) > 0 {
		policies = e.filterByCategories(policies, opts.Categories, opts.SkipCategories)
	}

	// Capability-scoped evaluation (#2801): same partition as the request
	// phase — a text-document tool's OUTPUT is document text, not a statement
	// any downstream executor runs. The content-borne families (PII,
	// sensitive-data, prompt-injection redaction per core/128) are untouched.
	capabilityScoped := e.filterByToolCapability(policies, opts.ToolIdentity)
	trace.scopeOut(opts.ToolIdentity, policies, capabilityScoped)
	policies = capabilityScoped

	// Segment applicability gate (ADR-060, #2989/#3266): same rule as the
	// request phase — a segment-scoped policy applies only for a caller
	// whose Segments contains it; excluded rows are skipped entirely (not
	// matched, not redacted/blocked, not reported in MatchedPolicies).
	policies = e.filterBySegments(policies, opts.Segments)

	// Convert content to scannable string
	scannable := e.toScannable(content)
	if scannable == "" {
		result.ProcessingTimeMs = time.Since(startTime).Milliseconds()
		// NOTHING TO SCAN IS A DETERMINED ANSWER, not an unknown one: every
		// detector that survived the filters looked at the content and found no
		// text in it to match - an execute with no message, rows of numbers.
		// Reporting them not-run would read every detector-reading control
		// UNKNOWN on the anchored engine and withhold a response that carries
		// nothing a detector could find. The request phase already reads empty
		// input this way, because its loop runs every detector over it.
		for i := range policies {
			trace.markRan(policies[i].PolicyID)
		}
		result.Observation = trace.facts(result.MatchedPolicies)
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
		redactionPlans = capRedactionPlans(redactionPlans, opts.MaxRedactions, nil)

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

	// The detector facts, LAST, after the verdict and every redaction are final.
	result.Observation = trace.facts(result.MatchedPolicies)

	return result
}

// capRedactionPlans limits the SPAN plans to max (0 means unlimited) and keeps
// every statement-removal plan.
//
// Statement-removal plans (prompt-injection sanitization, #2738) are
// SECURITY-critical and must never be dropped by the cap, so the cap applies to
// the span (PII) plans only - otherwise a response crafted with many PII-shaped
// tokens ahead of the injection match could push the injection plan past the
// limit and let it through unsanitized. dropped, when set, is handed every plan
// the cap discards.
func capRedactionPlans(plans []RedactionPlan, max int, dropped func(RedactionPlan)) []RedactionPlan {
	if max <= 0 || len(plans) <= max {
		return plans
	}
	kept := make([]RedactionPlan, 0, max)
	spanBudget := max
	for _, p := range plans {
		if p.Strategy == StrategyRemoveStatement {
			kept = append(kept, p)
			continue
		}
		if spanBudget > 0 {
			kept = append(kept, p)
			spanBudget--
			continue
		}
		if dropped != nil {
			dropped(p)
		}
	}
	return kept
}

// RedactDecided applies the redaction transform for exactly the policies a
// decision taken ELSEWHERE requires, over the content it is handed (#3564).
//
// # WHY IT IS A TRANSFORM AND NOT AN EVALUATION
//
// An enforcing pass has the anchored engine's decision: which requirements
// matched and demand field_redact. Discharging that obligation is masking what
// those requirements' detectors matched - not re-deciding. So this resolves no
// action (a named policy is redacted whatever its row stores, and an unnamed
// one never is), blocks nothing, records no evaluation metric and returns no
// detector facts: the decision already read the facts of the evaluation that
// produced them, and a transform that re-stated them could only disagree.
//
// # THE PHASE IS THE PASS'S, AND IT IS STATED
//
// phase is the phase whose content is masked: the response pass masks what it
// releases, and the MCP request pass masks the statement it hands back. The
// policies are loaded for that phase, because a detector the phase does not
// load never scanned this content - a request-only row has no response-phase
// span to mask, and masking with it would be a transform no decision required.
//
// It re-runs each named policy's detector because the redactor applies the
// spans a detector matches. The policies are loaded and filtered exactly as the
// phase's evaluation loads and filters them under the same options, and two
// shapes FAIL rather than returning a partial transform:
//
//   - a named policy the phase does not load under these options - the
//     decision requires masking for a detector this content was never scanned
//     by;
//   - a span plan the cap would drop - the obligation would be discharged for
//     some spans and not others while the record says it was discharged.
func (e *UnifiedPolicyEngine) RedactDecided(ctx context.Context, content interface{}, phase Phase, opts EvalOptions, policyIDs []string) (*ResponseResult, error) {
	if phase != PhaseRequest && phase != PhaseResponse {
		return nil, fmt.Errorf("policy engine: redacting needs the request or the response phase, got %q", phase)
	}
	if opts.TenantID == "" {
		opts.TenantID = e.config.DefaultTenant
	}
	loaded, err := e.loader.GetPolicies(ctx, opts.TenantID, opts.OrgScope, phase)
	if err != nil {
		return nil, fmt.Errorf("policy engine: loading the %s-phase policies to redact: %w", phase, err)
	}
	policies := loaded
	if len(opts.Categories) > 0 || len(opts.SkipCategories) > 0 {
		policies = e.filterByCategories(policies, opts.Categories, opts.SkipCategories)
	}
	policies = e.filterByToolCapability(policies, opts.ToolIdentity)
	policies = e.filterBySegments(policies, opts.Segments)

	want := make(map[string]bool, len(policyIDs))
	for _, id := range policyIDs {
		want[id] = true
	}
	result := &ResponseResult{
		Content:           content,
		RedactedFields:    make([]RedactedField, 0),
		MatchedPolicies:   make([]PolicyMatch, 0),
		PoliciesEvaluated: len(loaded),
	}
	scannable := e.toScannable(content)
	var plans []RedactionPlan
	for i := range policies {
		policy := &policies[i]
		if !want[policy.PolicyID] {
			continue
		}
		delete(want, policy.PolicyID)
		if scannable == "" {
			continue
		}
		for _, match := range e.evaluator.EvaluateAll(scannable, policy) {
			match.StoredAction = policy.ActionResponse
			if phase == PhaseRequest {
				match.StoredAction = policy.ActionRequest
			}
			match.Action = ActionRedact
			result.MatchedPolicies = append(result.MatchedPolicies, match)
			plans = append(plans, RedactionPlan{
				Match:    match,
				Policy:   *policy,
				Strategy: GetRedactionStrategy(policy.Category, policy.Severity),
			})
		}
	}
	if len(want) > 0 {
		missing := make([]string, 0, len(want))
		for id := range want {
			missing = append(missing, id)
		}
		sort.Strings(missing)
		return nil, fmt.Errorf("policy engine: the decision requires redacting what %v matched, and the %s phase does not load them under these options", missing, phase)
	}
	if len(plans) == 0 {
		return result, nil
	}
	// A DROPPED PLAN IS NOT NECESSARILY AN UNMASKED SPAN. The redactor groups
	// span plans by pattern and masks every occurrence of a kept pattern, so a
	// dropped plan leaves content unmasked only when no kept plan shares its
	// pattern. That case is refused, naming the policies; the other is the
	// redactor doing what it always does.
	var dropped []RedactionPlan
	plans = capRedactionPlans(plans, opts.MaxRedactions, func(p RedactionPlan) { dropped = append(dropped, p) })
	if len(dropped) > 0 {
		kept := map[string]bool{}
		for _, p := range plans {
			kept[p.Policy.PatternStr] = true
		}
		unmasked := map[string]bool{}
		for _, p := range dropped {
			if !kept[p.Policy.PatternStr] {
				unmasked[p.Policy.PolicyID] = true
			}
		}
		if len(unmasked) > 0 {
			ids := make([]string, 0, len(unmasked))
			for id := range unmasked {
				ids = append(ids, id)
			}
			sort.Strings(ids)
			return nil, fmt.Errorf("policy engine: the redaction limit (%d) would leave what %v matched unmasked, so the decision's redaction cannot be discharged", opts.MaxRedactions, ids)
		}
	}
	result.Content, result.RedactedFields = e.redactor.Apply(content, e.detectContentType(content), plans)
	result.Redacted = len(result.RedactedFields) > 0
	return result, nil
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
// its policies' stored action (warn; core/177 made the phase columns explicit),
// with no override category (#3961). Folding the category in here is what makes
// that action reach the request AND response planes (#2705) — previously
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
// runtime action is its policies' stored action (block on request; redact on the
// injection rows' response phase), replaced only by an organization's recorded
// dangerous_command override (#3961). Folding the
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
