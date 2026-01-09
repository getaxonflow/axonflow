package policy

import (
	"regexp"
	"time"
)

// Phase represents when a policy is evaluated in the request lifecycle.
type Phase string

const (
	// PhaseRequest means the policy is evaluated before connector execution.
	// Used for blocking dangerous queries or PII in input.
	PhaseRequest Phase = "request"

	// PhaseResponse means the policy is evaluated after connector execution.
	// Used for redacting PII in results or blocking large data transfers.
	PhaseResponse Phase = "response"

	// PhaseBoth means the policy is evaluated in both phases.
	// This is the default for backward compatibility.
	PhaseBoth Phase = "both"
)

// Action represents what to do when a policy matches.
type Action string

const (
	// ActionBlock denies the request/response entirely.
	ActionBlock Action = "block"

	// ActionAllow explicitly permits the request/response.
	ActionAllow Action = "allow"

	// ActionRedact masks PII in the content (response phase only).
	ActionRedact Action = "redact"

	// ActionLog records the match for auditing without blocking.
	ActionLog Action = "log"

	// ActionWarn logs a warning and continues processing.
	ActionWarn Action = "warn"
)

// PolicyCategory classifies policies for filtering and organization.
type PolicyCategory string

const (
	// Security categories
	CategorySecuritySQLi      PolicyCategory = "security-sqli"
	CategorySecurityDangerous PolicyCategory = "security-dangerous"
	CategoryAdminAccess       PolicyCategory = "admin-access"

	// PII categories by jurisdiction
	CategoryPIIGlobal PolicyCategory = "pii-global"
	CategoryPIIUS     PolicyCategory = "pii-us"
	CategoryPIIIndia  PolicyCategory = "pii-india"
	CategoryPIIEU     PolicyCategory = "pii-eu"

	// Data governance categories
	CategoryDataExfiltration PolicyCategory = "data-exfiltration"

	// Compliance categories
	CategoryComplianceGDPR  PolicyCategory = "compliance-gdpr"
	CategoryComplianceHIPAA PolicyCategory = "compliance-hipaa"
	CategoryComplianceRBI   PolicyCategory = "compliance-rbi"
	CategoryComplianceSEBI  PolicyCategory = "compliance-sebi"
)

// Severity levels for policies.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
)

// ValidatorFunc validates a match beyond regex pattern matching.
// It returns whether the match is valid and a confidence score (0.0-1.0).
// Used for checksums (Luhn for credit cards, MOD97 for IBAN, etc.)
type ValidatorFunc func(match string, context string) (valid bool, confidence float64)

// CompiledPolicy represents a policy loaded from the database with compiled regex.
type CompiledPolicy struct {
	// Database identifiers
	ID       string // UUID primary key
	PolicyID string // Human-readable policy identifier (e.g., "sys_pii_ssn")
	Name     string // Display name

	// Classification
	Category PolicyCategory
	Tier     string   // "system", "organization", "tenant"
	Severity Severity // "critical", "high", "medium", "low"

	// Pattern matching
	Pattern    *regexp.Regexp // Pre-compiled regex for performance
	PatternStr string         // Original pattern string

	// Phase configuration
	Phase          Phase  // When to evaluate: "request", "response", "both"
	ActionRequest  Action // Action for request phase (may be empty)
	ActionResponse Action // Action for response phase (may be empty)

	// Metadata
	Description string
	Enabled     bool
	Priority    int // Higher = evaluated first

	// Multi-tenancy
	TenantID       string
	OrganizationID *string

	// Optional validator for semantic validation
	Validator ValidatorFunc
}

// GetActionForPhase returns the appropriate action for the given phase.
// Follows the tiered detection philosophy (Issue #891, ADR-026):
// - Security patterns (SQLi, dangerous queries): block
// - PII patterns: redact (non-blocking, preserves UX)
// - Admin access: warn
func (p *CompiledPolicy) GetActionForPhase(phase Phase) Action {
	switch phase {
	case PhaseRequest:
		if p.ActionRequest != "" {
			return p.ActionRequest
		}
	case PhaseResponse:
		if p.ActionResponse != "" {
			return p.ActionResponse
		}
	}
	// Fallback: derive from category and severity for backward compatibility
	// PII policies default to redact (Issue #891: non-blocking PII detection)
	if isPIIPolicyCategory(p.Category) {
		return ActionRedact
	}
	// Security policies (SQLi, dangerous queries) default to block
	if isSecurityPolicyCategory(p.Category) && p.Severity == SeverityCritical {
		return ActionBlock
	}
	// Admin access defaults to warn
	if p.Category == CategoryAdminAccess {
		return ActionWarn
	}
	// Default: log for audit trail
	return ActionLog
}

// isPIIPolicyCategory returns true if the category is a PII-related category.
func isPIIPolicyCategory(cat PolicyCategory) bool {
	switch cat {
	case CategoryPIIGlobal, CategoryPIIUS, CategoryPIIIndia, CategoryPIIEU:
		return true
	}
	return false
}

// isSecurityPolicyCategory returns true if the category is a security category.
func isSecurityPolicyCategory(cat PolicyCategory) bool {
	switch cat {
	case CategorySecuritySQLi, CategorySecurityDangerous:
		return true
	}
	return false
}

// EvalOptions configures policy evaluation behavior.
type EvalOptions struct {
	// Multi-tenancy context
	TenantID       string
	OrganizationID *string
	UserID         string

	// Request context
	ConnectorName string

	// Category filtering
	Categories     []PolicyCategory // Only evaluate these categories (empty = all)
	SkipCategories []PolicyCategory // Exclude these categories

	// Redaction limits
	MaxRedactions int // Maximum redactions per response (0 = unlimited)
}

// RequestResult contains the results of request-phase policy evaluation.
type RequestResult struct {
	// Primary result
	Blocked     bool
	BlockedBy   *CompiledPolicy
	BlockReason string

	// Statistics
	PoliciesEvaluated int
	MatchedPolicies   []PolicyMatch
	ProcessingTimeMs  int64
}

// ResponseResult contains the results of response-phase policy evaluation.
type ResponseResult struct {
	// Primary result
	Blocked     bool
	BlockedBy   *CompiledPolicy
	BlockReason string

	// Content (possibly redacted)
	Content        interface{}
	Redacted       bool
	RedactedFields []RedactedField

	// Statistics
	PoliciesEvaluated int
	MatchedPolicies   []PolicyMatch
	ProcessingTimeMs  int64
}

// PolicyMatch records details of a policy that matched.
type PolicyMatch struct {
	PolicyID   string
	PolicyName string
	Category   PolicyCategory
	Severity   Severity
	Action     Action

	// Match details
	MatchText  string  // The text that triggered the match
	StartIndex int     // Position in input
	EndIndex   int     // End position in input
	Confidence float64 // Validator confidence (0.0-1.0), 1.0 if no validator

	// Context (for debugging/auditing)
	FieldPath string // JSON path for structured data (e.g., "rows[0].ssn")
}

// RedactedField describes a field that was redacted in the response.
type RedactedField struct {
	Path        string // JSON path (e.g., "rows[0].ssn", "data.customer.email")
	OriginalLen int    // Length of original value
	RedactedTo  string // What it was replaced with (e.g., "***REDACTED***")
	PolicyID    string // Policy that triggered redaction
	PIIType     string // Type of PII detected (e.g., "ssn", "credit_card")
}

// PolicyInfo is the serializable structure returned in API responses.
// All fields use JSON tags for API compatibility.
type PolicyInfo struct {
	PoliciesEvaluated int               `json:"policies_evaluated"`
	Blocked           bool              `json:"blocked"`
	BlockReason       string            `json:"block_reason,omitempty"`
	RedactionsApplied int               `json:"redactions_applied"`
	MatchedPolicies   []PolicyMatchInfo `json:"matched_policies,omitempty"`
	ProcessingTimeMs  int64             `json:"processing_time_ms"`
}

// PolicyMatchInfo is the serializable version of PolicyMatch for API responses.
type PolicyMatchInfo struct {
	PolicyID   string `json:"policy_id"`
	PolicyName string `json:"policy_name"`
	Category   string `json:"category"`
	Severity   string `json:"severity"`
	Action     string `json:"action"`
}

// ToInfo converts RequestResult to PolicyInfo for API responses.
func (r *RequestResult) ToInfo() *PolicyInfo {
	info := &PolicyInfo{
		PoliciesEvaluated: r.PoliciesEvaluated,
		Blocked:           r.Blocked,
		BlockReason:       r.BlockReason,
		ProcessingTimeMs:  r.ProcessingTimeMs,
	}

	for _, m := range r.MatchedPolicies {
		info.MatchedPolicies = append(info.MatchedPolicies, PolicyMatchInfo{
			PolicyID:   m.PolicyID,
			PolicyName: m.PolicyName,
			Category:   string(m.Category),
			Severity:   string(m.Severity),
			Action:     string(m.Action),
		})
	}

	return info
}

// ToInfo converts ResponseResult to PolicyInfo for API responses.
func (r *ResponseResult) ToInfo() *PolicyInfo {
	info := &PolicyInfo{
		PoliciesEvaluated: r.PoliciesEvaluated,
		Blocked:           r.Blocked,
		BlockReason:       r.BlockReason,
		RedactionsApplied: len(r.RedactedFields),
		ProcessingTimeMs:  r.ProcessingTimeMs,
	}

	for _, m := range r.MatchedPolicies {
		info.MatchedPolicies = append(info.MatchedPolicies, PolicyMatchInfo{
			PolicyID:   m.PolicyID,
			PolicyName: m.PolicyName,
			Category:   string(m.Category),
			Severity:   string(m.Severity),
			Action:     string(m.Action),
		})
	}

	return info
}

// MergePolicyInfo merges request and response PolicyInfo into a single response.
func MergePolicyInfo(request *PolicyInfo, response *PolicyInfo) *PolicyInfo {
	if request == nil && response == nil {
		return nil
	}
	if request == nil {
		return response
	}
	if response == nil {
		return request
	}

	merged := &PolicyInfo{
		PoliciesEvaluated: request.PoliciesEvaluated + response.PoliciesEvaluated,
		Blocked:           request.Blocked || response.Blocked,
		RedactionsApplied: response.RedactionsApplied,
		ProcessingTimeMs:  request.ProcessingTimeMs + response.ProcessingTimeMs,
	}

	if request.Blocked {
		merged.BlockReason = request.BlockReason
	} else if response.Blocked {
		merged.BlockReason = response.BlockReason
	}

	merged.MatchedPolicies = append(merged.MatchedPolicies, request.MatchedPolicies...)
	merged.MatchedPolicies = append(merged.MatchedPolicies, response.MatchedPolicies...)

	return merged
}

// EngineConfig configures the UnifiedPolicyEngine.
type EngineConfig struct {
	// Cache settings
	CacheTTL        time.Duration // Policy cache TTL (default: 5 minutes)
	MaxPatternCache int           // Maximum compiled regex patterns to cache (default: 1000)

	// Behavior settings
	EnableValidators    bool // Run semantic validators (Luhn, MOD97, etc.) - default: true
	EnableMetrics       bool // Collect metrics via AuditQueue - default: true
	GracefulDegradation bool // Continue if DB unavailable - default: true

	// Defaults
	DefaultTenant string // Default tenant when none specified - default: "global"

	// Background refresh
	RefreshInterval time.Duration // How often to refresh policies - default: 30 seconds
}

// DefaultEngineConfig returns the recommended production configuration.
func DefaultEngineConfig() EngineConfig {
	return EngineConfig{
		CacheTTL:            5 * time.Minute,
		MaxPatternCache:     1000,
		EnableValidators:    true,
		EnableMetrics:       true,
		GracefulDegradation: true,
		DefaultTenant:       "global",
		RefreshInterval:     30 * time.Second,
	}
}

// RedactionStrategy defines how to redact content.
type RedactionStrategy string

const (
	// StrategyMask replaces content with asterisks, preserving length indication.
	// Example: "123-45-6789" -> "***-**-****"
	StrategyMask RedactionStrategy = "mask"

	// StrategyPartial shows first and last characters.
	// Example: "john@example.com" -> "jo***om"
	StrategyPartial RedactionStrategy = "partial"

	// StrategyRemove replaces with a standard placeholder.
	// Example: "123-45-6789" -> "[REDACTED:ssn]"
	StrategyRemove RedactionStrategy = "remove"

	// StrategyHash replaces with a deterministic hash for correlation.
	// Example: "123-45-6789" -> "HASH_a1b2c3d4"
	StrategyHash RedactionStrategy = "hash"

	// StrategyTokenize replaces with a reversible token (enterprise feature).
	// Example: "123-45-6789" -> "TOKEN_SSN_12345"
	StrategyTokenize RedactionStrategy = "tokenize"
)

// RedactionPlan describes a planned redaction operation.
type RedactionPlan struct {
	Match     PolicyMatch
	Policy    CompiledPolicy
	Strategy  RedactionStrategy
	FieldPath string // Path in structured data
}

// CacheStats provides statistics about the policy cache.
type CacheStats struct {
	TotalPolicies   int
	CachedTenants   int
	CacheHits       int64
	CacheMisses     int64
	LastRefresh     time.Time
	RefreshDuration time.Duration
}

// EvaluatorStats provides statistics about the pattern evaluator.
type EvaluatorStats struct {
	CachedPatterns    int
	MaxPatternCache   int
	ValidatorsEnabled bool
	RegisteredTypes   []string
}
