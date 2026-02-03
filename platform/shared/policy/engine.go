package policy

import (
	"context"
	"database/sql"
	"fmt"
	"log"
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
		db:       db,
		config:   config,
		stopChan: make(chan struct{}),
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

	result := &RequestResult{
		Blocked:         false,
		MatchedPolicies: make([]PolicyMatch, 0),
	}

	// Apply default tenant if not specified
	if opts.TenantID == "" {
		opts.TenantID = e.config.DefaultTenant
	}

	// Load policies from cache or database
	policies, err := e.loader.GetPolicies(ctx, opts.TenantID, opts.OrganizationID, PhaseRequest)
	if err != nil {
		e.metrics.RecordError("load")
		if e.config.GracefulDegradation {
			log.Printf("[PolicyEngine] Failed to load policies, allowing request: %v", err)
			result.ProcessingTimeMs = time.Since(startTime).Milliseconds()
			return result
		}
		result.Blocked = true
		result.BlockReason = "Policy engine unavailable"
		result.ProcessingTimeMs = time.Since(startTime).Milliseconds()
		return result
	}

	result.PoliciesEvaluated = len(policies)

	// Filter by categories if specified
	if len(opts.Categories) > 0 || len(opts.SkipCategories) > 0 {
		policies = e.filterByCategories(policies, opts.Categories, opts.SkipCategories)
	}

	// Evaluate each policy
	for i := range policies {
		policy := &policies[i]

		match := e.evaluator.Evaluate(input, policy)
		if match != nil {
			action := policy.GetActionForPhase(PhaseRequest)
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

	result.ProcessingTimeMs = time.Since(startTime).Milliseconds()

	// Record metrics asynchronously
	if e.config.EnableMetrics {
		go e.metrics.RecordEvaluation(ctx, "request", opts, result.MatchedPolicies, result.Blocked, result.ProcessingTimeMs)
	}

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

	// Apply default tenant if not specified
	if opts.TenantID == "" {
		opts.TenantID = e.config.DefaultTenant
	}

	// Load policies from cache or database
	policies, err := e.loader.GetPolicies(ctx, opts.TenantID, opts.OrganizationID, PhaseResponse)
	if err != nil {
		e.metrics.RecordError("load")
		if e.config.GracefulDegradation {
			log.Printf("[PolicyEngine] Failed to load policies, returning unprocessed: %v", err)
			result.ProcessingTimeMs = time.Since(startTime).Milliseconds()
			return result
		}
		result.Blocked = true
		result.BlockReason = "Policy engine unavailable"
		result.ProcessingTimeMs = time.Since(startTime).Milliseconds()
		return result
	}

	result.PoliciesEvaluated = len(policies)

	// Filter by categories if specified
	if len(opts.Categories) > 0 || len(opts.SkipCategories) > 0 {
		policies = e.filterByCategories(policies, opts.Categories, opts.SkipCategories)
	}

	// Convert content to scannable string
	scannable := e.toScannable(content)
	if scannable == "" {
		result.ProcessingTimeMs = time.Since(startTime).Milliseconds()
		return result
	}

	// Collect redaction plans
	var redactionPlans []RedactionPlan

	for i := range policies {
		policy := &policies[i]

		matches := e.evaluator.EvaluateAll(scannable, policy)
		for _, match := range matches {
			action := policy.GetActionForPhase(PhaseResponse)
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
		// Limit redactions if configured
		if opts.MaxRedactions > 0 && len(redactionPlans) > opts.MaxRedactions {
			redactionPlans = redactionPlans[:opts.MaxRedactions]
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

	return result
}

// InvalidateCache forces a cache refresh for a tenant.
func (e *UnifiedPolicyEngine) InvalidateCache(tenantID string, orgID *string) {
	e.cache.Invalidate(tenantID, orgID)
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
