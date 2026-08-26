package policy

import (
	"regexp"
	"slices"
	"strings"
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

	// ActionRequireApproval pauses execution and requires human approval before proceeding.
	// This is used for EU AI Act Article 14 compliance and other HITL requirements.
	// Issue #1081: Added to enable compliance framework HITL enforcement.
	ActionRequireApproval Action = "require_approval"

	// ActionAllow explicitly permits the request/response.
	ActionAllow Action = "allow"

	// ActionRedact masks PII in the content (response phase only).
	ActionRedact Action = "redact"

	// ActionLog records the match for auditing without blocking.
	ActionLog Action = "log"

	// ActionWarn logs a warning and continues processing.
	ActionWarn Action = "warn"
)

// ValidActionTypes is the canonical list of action `type` strings accepted by
// the policy CRUD API and by override requests. It is the union of:
//   - core engine actions defined above (block, redact, log, warn, require_approval)
//   - dynamic-policy executor actions handled in db_dynamic_policies.go
//     (alert, route, modify_risk)
//
// "allow" is excluded — it is an implicit default, not a policy `type`.
//
// This is the single source of truth. Both
// `platform/orchestrator/policy_api_types.go` (POST /api/v1/policies) and
// `ee/platform/customer-portal/api/policy_overrides.go` (override validator)
// reference this list. Adding a new action type requires updating only this
// slice.
var ValidActionTypes = []string{
	"alert",
	"block",
	"log",
	"modify_risk",
	"redact",
	"require_approval",
	"route",
	"warn",
}

// IsValidActionType reports whether action is in ValidActionTypes.
func IsValidActionType(action string) bool {
	for _, a := range ValidActionTypes {
		if action == a {
			return true
		}
	}
	return false
}

// ValidOverrideActions is the canonical list of action `type` strings that are
// valid as the *target* of a policy override (i.e. what an operator can replace
// the policy's existing action with). It is a deliberately narrower set than
// ValidActionTypes:
//
//   - Override semantics only make sense for the engine's terminal actions
//     (block / require_approval / redact / warn / log). Each of these decides
//     what happens to the request once a policy fires.
//   - alert / route / modify_risk are dynamic-policy *authoring* actions
//     (POST /api/v1/policies). They configure a policy's side effects (LLM
//     routing rules, risk-score deltas, alerter wiring) and have no meaning
//     as an override of a different policy's terminal action — the agent's
//     override repository would reject them with ErrInvalidOverrideAction.
//
// The agent's `AllOverrideActions` (`platform/agent/policy_categories.go`)
// historically duplicated this list; the canonical source now lives here so
// the customer-portal override validator and the agent override repository
// stay in sync. Adding a new override action requires updating only this
// slice (and likely ActionRestrictiveness in the agent for ordering).
// Order is intentional — most restrictive first, matching
// agent.ActionRestrictiveness so callers iterating the list see actions in
// "block weakest-allowed override last" order.
var ValidOverrideActions = []string{
	"block",
	"require_approval",
	"redact",
	"warn",
	"log",
}

// IsValidOverrideAction reports whether action can be the target of a policy
// override. See ValidOverrideActions for the rationale on which actions are in
// scope.
func IsValidOverrideAction(action string) bool {
	for _, a := range ValidOverrideActions {
		if action == a {
			return true
		}
	}
	return false
}

// PolicyCategory classifies policies for filtering and organization.
type PolicyCategory string

const (
	// Security categories
	CategorySecuritySQLi      PolicyCategory = "security-sqli"
	CategorySecurityDangerous PolicyCategory = "security-dangerous"
	CategoryAdminAccess       PolicyCategory = "admin-access"

	// PII categories by jurisdiction
	CategoryPIIGlobal    PolicyCategory = "pii-global"
	CategoryPIIUS        PolicyCategory = "pii-us"
	CategoryPIIIndia     PolicyCategory = "pii-india"
	CategoryPIIEU        PolicyCategory = "pii-eu"
	CategoryPIISingapore PolicyCategory = "pii-singapore" // Issue #1076 - MAS FEAT Community
	CategoryPIIIndonesia PolicyCategory = "pii-indonesia" // OJK/BI/UU PDP compliance

	// Data governance categories
	CategoryDataExfiltration PolicyCategory = "data-exfiltration"
	CategorySensitiveData    PolicyCategory = "sensitive-data" // Issue #1081 - HITL policies

	// Dynamic policy categories (Issue #968)
	CategoryDynamicRateLimit  PolicyCategory = "dynamic-rate-limit"
	CategoryDynamicBudget     PolicyCategory = "dynamic-budget"
	CategoryDynamicTimeAccess PolicyCategory = "dynamic-time-access"
	CategoryDynamicRoleAccess PolicyCategory = "dynamic-role-access"

	// Compliance categories
	CategoryComplianceGDPR    PolicyCategory = "compliance-gdpr"
	CategoryComplianceHIPAA   PolicyCategory = "compliance-hipaa"
	CategoryComplianceRBI     PolicyCategory = "compliance-rbi"
	CategoryComplianceSEBI    PolicyCategory = "compliance-sebi"
	CategoryComplianceEUAIAct PolicyCategory = "compliance-euaiact" // Issue #1081 - EU AI Act
	CategoryComplianceMASFEAT PolicyCategory = "compliance-masfeat" // Issue #1081 - MAS FEAT Singapore

	// Financial crime category (ADR-061 / #3329). Carries the FinCrime
	// Policy Pack rows so they are governed neither by the PII/SQLi posture
	// levers (BuildActionOverrides) nor by capability scoping, and are
	// greppable as an add-on surface. Evaluated on the shared
	// evaluateInputPolicies seam (decide + MCP planes).
	CategoryFinCrime PolicyCategory = "fincrime"

	// Media governance categories
	CategoryMediaSafety    PolicyCategory = "media-safety"    // NSFW, violence content detection
	CategoryMediaBiometric PolicyCategory = "media-biometric" // Face/biometric data detection (GDPR Art. 9)
	CategoryMediaDocument  PolicyCategory = "media-document"  // Sensitive document classification
	CategoryMediaPII       PolicyCategory = "media-pii"       // PII detected in images via OCR
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
	TenantID string

	// SegmentID is the governance-segment (org-unit/group) this policy is
	// scoped to (ADR-060, #2989/#3266), or "" when the policy is NOT
	// segment-scoped (applies to every member of the tenant/org, unchanged
	// from pre-#2989 behavior). Mirrors static_policies.segment_id — see
	// StaticPolicyRepository.GetEffective's `sp.segment_id IS NULL OR
	// sp.segment_id = ANY($N)` predicate (platform/agent/
	// static_policy_repository.go), which this field lets the shared engine
	// apply the SAME applicability rule at evaluation time (see
	// UnifiedPolicyEngine's segment gate) instead of not knowing about
	// segments at all.
	SegmentID string

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
	if IsPIIPolicyCategory(p.Category) {
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

// AppliesToSegments reports whether this policy is eligible to match/act/be
// reported for a caller whose resolved governance-segment membership is
// callerSegments (ADR-060, #2989/#3266). The rule mirrors
// StaticPolicyRepository.GetEffective's SQL predicate (`sp.segment_id IS
// NULL OR sp.segment_id = ANY($N)`):
//   - p.SegmentID == "" (not segment-scoped): always applies, regardless of
//     callerSegments — this is the pre-#2989 behavior, unrestricted by
//     segment.
//   - p.SegmentID != "" (segment-scoped): applies iff callerSegments
//     contains it. A nil/empty callerSegments therefore excludes EVERY
//     segment-scoped policy — fail-closed by construction, never fail-open,
//     because the empty side of the OR can only narrow which SegmentID != ""
//     rows apply, never widen it.
//
// Callers MUST gate matching, action, AND reporting (MatchedPolicies /
// triggered-policy identifiers) on this — a policy that fails this check
// must be skipped entirely, not merely left unenforced (#3266 symptom 1: a
// segment-scoped policy leaking into a non-member's triggered_policies is a
// disclosure bug even when it does not block).
func (p *CompiledPolicy) AppliesToSegments(callerSegments []string) bool {
	if p.SegmentID == "" {
		return true
	}
	return slices.Contains(callerSegments, p.SegmentID)
}

// IsPIIPolicyCategory reports whether a category is a TEXT PII category, by
// CONVENTION rather than an enumerated list: any "pii-*" category
// (pii-global/us/india/eu/singapore/indonesia). This is the single source of
// truth for "policy-derived" PII coverage across the agent's text engine AND
// the /decide obligation bridge (platform/agent/policy_result_convert.go) — so
// a newly-seeded pii-* category (e.g. pii-indonesia) is auto-included with no
// list to forget. It is EXPORTED so the agent package converges on it instead
// of maintaining a duplicate enumerated switch, which is exactly the drift that
// left pii-indonesia out of the /decide obligation path (#2965) and out of the
// response phase before it. NOTE: "media-pii" is intentionally EXCLUDED — its
// detector is the orchestrator's media/OCR subsystem (Rekognition/Vision), not
// this text engine; including it here would no-op on text and falsely imply
// agent-side media coverage.
func IsPIIPolicyCategory(cat PolicyCategory) bool {
	return strings.HasPrefix(string(cat), "pii-")
}

// AllTextPIICategories returns every TEXT PII category (the pii-* set) as an
// explicit slice. It is the SINGLE source for "all PII" wherever a caller must
// pass an explicit EvalOptions.Categories whitelist — the proxy and
// openai-compat planes cannot use the prefix-derived EnabledPIICategories (they
// evaluate a fixed category set, not a per-tenant policy scan), so they spread
// this in. Adding a new pii-* jurisdiction is a one-line change HERE, not a hunt
// across call sites (the omission that left pii-indonesia ungoverned on those
// planes — #2965). Kept in lockstep with IsPIIPolicyCategory by
// TestAllTextPIICategories_MatchesConvention.
func AllTextPIICategories() []PolicyCategory {
	return []PolicyCategory{
		CategoryPIIGlobal,
		CategoryPIIUS,
		CategoryPIIIndia,
		CategoryPIIEU,
		CategoryPIISingapore,
		CategoryPIIIndonesia,
	}
}

// PostureLeverForCategory names the detection-posture lever that governs a
// category's runtime action, or "" when no lever governs it.
//
// #3441 (M1), building on the #3360 ruling: for the detection categories the
// shared engine never uses static_policies.action at all. EvalOptions
// .ActionOverrides replaces it unconditionally (engine.go), and that map is
// built from the profile / *_ACTION env / per-org detection override chain. A
// surface that renders the stored action as the operative one is therefore
// stating something the engine ignores, and this function is how a surface
// finds out which rows those are.
//
// It is the SHARED source for that question, deliberately not a third copy:
// agent/detection_config.go BuildActionOverrides decides the set at
// enforcement time, agent/policy_result_convert.go leverNameForCategory names
// it in the audit advisory, and the customer portal has to name it on the
// Policies page. Three independent switches over one fact would diverge, and
// the divergence would be invisible in both directions (a category that gained
// a lever but not a disclosure reads as authoritative; one that lost a lever
// reads as ignored). TestPostureLeverMatchesBuildActionOverrides in the agent
// package - the only package that can see both - pins the two together.
//
// Categories with NO lever entry (compliance-*, fincrime, admin-access,
// data-exfiltration, media-*) return "": no posture lever displaces them.
//
// "" is NOT a promise that static_policies.action is what runs. The shared
// engine's RUNTIME loader (PolicyLoader, loader.go) does not SELECT that
// column on any of its queries - they read phase, action_request,
// action_response - so on every shared-engine plane the base action column is
// read by nothing; GetActionForPhase resolves the phase column, or a
// category/severity fallback when it is NULL. The base column is read only by
// the proxy plane's Phase-2 tier engine, through
// StaticPolicyRepository.GetEffective.
//
// Be precise about the FILE rather than the type: loader.go carries two
// disjoint column sets, and an earlier version of this comment said the file
// never selects the column, which is false. effectivePolicyColumns (same file,
// used by ScanEffectivePolicyRows for the GetEffective admin/API path) selects
// sp.action and none of the phase columns. That disjointness is the mechanism
// by which the two drift, which is why migration core/124 exists. This function answers exactly one
// question - does a POSTURE LEVER replace the resolved action - and callers
// must not widen it into a claim about the action column.
func PostureLeverForCategory(cat PolicyCategory) string {
	switch {
	case IsPIIPolicyCategory(cat):
		return "PII_ACTION"
	case cat == CategorySecuritySQLi:
		return "SQLI_ACTION"
	case cat == CategorySensitiveData:
		return "SENSITIVE_DATA_ACTION"
	case cat == CategorySecurityDangerous:
		return "DANGEROUS_COMMAND_ACTION"
	default:
		return ""
	}
}

// isSecurityPolicyCategory returns true if the category is a security category.
func isSecurityPolicyCategory(cat PolicyCategory) bool {
	switch cat {
	case CategorySecuritySQLi, CategorySecurityDangerous:
		return true
	}
	return false
}

// IsComplianceCategory returns true if the category is a compliance-related category.
// Issue #1081: Added to support compliance framework runtime enforcement.
func IsComplianceCategory(cat PolicyCategory) bool {
	switch cat {
	case CategoryComplianceGDPR, CategoryComplianceHIPAA, CategoryComplianceRBI,
		CategoryComplianceSEBI, CategoryComplianceEUAIAct, CategoryComplianceMASFEAT:
		return true
	}
	return false
}

// AllComplianceCategories returns all compliance-related policy categories.
// Issue #1081: Added for use in gateway evaluation.
func AllComplianceCategories() []PolicyCategory {
	return []PolicyCategory{
		CategoryComplianceGDPR,
		CategoryComplianceHIPAA,
		CategoryComplianceRBI,
		CategoryComplianceSEBI,
		CategoryComplianceEUAIAct,
		CategoryComplianceMASFEAT,
	}
}

// OrgScopePtr converts a caller org string into the *string
// EvalOptions.OrgScope / loader orgID parameter shape: nil when empty
// (single-tenant/community contexts — the loader falls back to the
// org_id==tenant_id identity), a pointer otherwise. #3048 R3 HIGH-3: gates
// MUST pass the validated caller org through this so the loader's tenant
// pass scopes the RLS GUC to the org that actually stamps the rows — an org
// with org_id != tenant_id otherwise silently loses its tenant/org-tier
// policies under app-role RLS (and the zero-system-set guard does NOT trip,
// because the 'global' pass still loads).
func OrgScopePtr(orgID string) *string {
	if orgID == "" {
		return nil
	}
	return &orgID
}

// EvalOptions configures policy evaluation behavior.
type EvalOptions struct {
	// Multi-tenancy context
	//
	// OrgID is the multi-tenant scope key — required by the agent's RLS-aware
	// audit_queue persistence path under axonflow_app_role (v9 Phase 8 #2384
	// PR-C1). When set, RecordViolation propagates it into AuditEntry.OrgID
	// so the downstream INSERT can populate the row's org_id column and
	// satisfy WITH CHECK. Leave empty in cross-org workers (those must run
	// on axonflow_platform_admin / BYPASSRLS, not via WithOrgScope).
	TenantID string
	OrgID    string
	// OrgScope is the organisation the policy LOAD is scoped by: it fills both
	// the RLS GUC and the loader's `org_id = $1` predicate. It is OrgID in
	// pointer form, nil when the caller is unbound (see OrgScopePtr).
	//
	// It was called OrganizationID until #3334. That name collided with the
	// legacy `organization_id` COLUMN on the policy tables - a differently
	// typed, never-populated second org key that migration core/166 drops -
	// and the collision was not cosmetic: #3334 records that it produced
	// several wrong conclusions in two separate pieces of work, because a
	// reader could not tell whether a given OrganizationID meant "the org this
	// caller is scoped to" or "the value in that column". One of the two is
	// now gone and the other says what it is.
	//
	// It is deliberately NOT collapsed into OrgID. Three call sites set this
	// without setting OrgID (mcp_handler.go's response-phase and PII-category
	// paths, cowork_otel_ingest.go), so collapsing them would start populating
	// OrgID on those paths - which changes what RecordViolation writes to
	// AuditEntry.OrgID. That may well be a fix; it is not one to smuggle into
	// a column retirement. Tracked on #3490.
	OrgScope *string
	UserID   string

	// Request context
	ConnectorName string
	Parameters    map[string]interface{} // Optional parameters to scan individually

	// ToolIdentity is the raw identity of the governed tool this content is
	// bound for (or came from), used for capability-scoped evaluation (#2801):
	// when it positively classifies as a text-document tool, execution-class
	// detector families (security-sqli; the enumerated execution-class
	// security-dangerous policies) are skipped. Empty or unclassified =>
	// FULL evaluation (fail-closed). Pass whatever the plane has — the
	// caller-sent connector_type (`claude_code.mcp__atlassian__editJiraIssue`),
	// a managed connector name, or /decide's target.tool — classification
	// happens server-side in capability.go, never from a caller-asserted
	// capability claim. Planes with no tool identity leave it empty.
	ToolIdentity string

	// Category filtering
	Categories     []PolicyCategory // Only evaluate these categories (empty = all)
	SkipCategories []PolicyCategory // Exclude these categories

	// Action overrides
	// ActionOverrides allows overriding the default action for specific categories.
	// Key: PolicyCategory, Value: desired Action.
	// Takes precedence over GetActionForPhase() defaults.
	ActionOverrides map[PolicyCategory]Action

	// Redaction limits
	MaxRedactions int // Maximum redactions per response (0 = unlimited)

	// Segments is the caller's resolved governance-segment set (ADR-060,
	// #2989/#3266) — the group/segment IDs the caller is a MEMBER of. It
	// gates evaluation of segment-scoped static_policies rows (CompiledPolicy
	// .SegmentID != ""): a segment-scoped policy applies iff its SegmentID is
	// in this set, and is otherwise skipped entirely — not matched, not
	// acted on, not reported (see UnifiedPolicyEngine's segment applicability
	// gate). nil/empty means "the caller belongs to no segments" and is
	// FAIL-CLOSED by construction: every segment-scoped row is excluded,
	// which is always the SAFE default for a caller with no resolved
	// identity (this is restriction-only — it can never cause a
	// non-segment-scoped policy, SegmentID == "", to be skipped). Callers
	// that have not yet resolved a segment set for their plane MUST pass nil
	// explicitly rather than omit the field silently — see the call sites in
	// agent/openai_compat_handler.go and orchestrator/response_processor.go
	// for the documented per-plane deferral. agent/gateway_handlers.go
	// resolves and passes a real segment set as of #3312 (ADR-060 Slice 3)
	// and is no longer a deferral; agent/openai_compat_handler.go remains
	// one because that plane has no verified human-actor principal to
	// resolve segments from at all (see its own call-site comment) — its
	// real fix is #3410.
	//
	// agent/mcp_handler.go is NO LONGER a deferral as of #3447.
	// evaluateInputPolicies / evaluateOutputPolicies receive a real,
	// fail-closed-resolved set — request phase and response phase — from
	// BOTH of their caller families:
	//
	//   - the MCP-server JSON-RPC plane's check_policy/check_output tools
	//     (mcp_server_handler.go), via resolveMCPServerSegmentsForPolicy
	//     (agent/mcp_identity.go) since #3430; and
	//   - the four legacy MCP REST handlers in mcp_handler.go itself —
	//     mcpQueryHandler, mcpExecuteHandler, mcpCheckInputHandler,
	//     mcpCheckOutputHandler — via resolveHumanActorSegmentsForPolicy
	//     (agent/human_actor_segment_gate.go) since #3447. Those four
	//     authenticate the end user with ResolveUser's per-user JWT
	//     (validateUserToken), and #3447 keys resolution on that VALIDATED
	//     token's email claim; a verified member is now enforced on both
	//     planes, where before a one-URL edit switched every segment-scoped
	//     policy off for them.
	//
	// agent/decision_handler.go's /decide is NO LONGER a deferral either, as
	// of #3456: handleDecide resolves the same way the four MCP REST handlers
	// do — one fail-closed call to resolveHumanActorSegmentsForPolicy
	// (agent/human_actor_segment_gate.go), keyed on the validated
	// DecideRequest.user_token's email claim — and passes the result here.
	// /decide has only this request-phase call site (runDynamicPolicy=false,
	// no response phase), so that one resolution covers the whole plane.
	//
	// On these planes the "nil is fail-closed by construction" reading
	// above stops being sufficient, and #3430 R3 says why: nil excludes
	// every segment-scoped row, which is safe for the POLICY but not for
	// the PLANE if the caller can choose to arrive without an identity. The
	// two caller families answer that differently, on purpose:
	//
	//   - MCP-server JSON-RPC: a caller with no validated per-user token is
	//     REFUSED before evaluation whenever HasSegmentScopedPolicies
	//     reports the phase's policy set can depend on membership (#3430).
	//   - MCP REST and /decide: a caller with no token gets the unchanged
	//     ADR-060 baseline — org-only, no refusal, no policy census. What
	//     keeps that from being a selectable opt-out is #3476
	//     (require_user_token), which lets an org reject a token-less caller
	//     at AUTHENTICATION. A RESOLVER ERROR for a caller who HAS a
	//     principal still denies there, with guard id
	//     segment_resolution_failed, before this field is ever populated.
	//
	// Either way, read this field's nil as "resolved to no segments / this
	// plane does not resolve one", never as "resolution failed" or
	// "resolution was skipped because identity was weak".
	Segments []string
}

// RequestResult contains the results of request-phase policy evaluation.
type RequestResult struct {
	// Primary result
	Blocked     bool
	BlockedBy   *CompiledPolicy
	BlockReason string

	// EvaluationError distinguishes "could not scan" from "scanned, found
	// nothing" on the request plane — the symmetric counterpart of
	// ResponseResult.EvaluationError (#2820), added by #2862. It is set true
	// when the engine could NOT complete evaluation (a policy-load /
	// graceful-degradation error) as opposed to a clean scan (Blocked=false
	// with EvaluationError=false).
	//
	// Unlike the response plane there is no "return unprocessed content" middle
	// ground on the request plane — a request either proceeds or is blocked — so
	// EvaluateRequest fails CLOSED (Blocked=true) when this is set, regardless of
	// GracefulDegradation. A request gate that could not load policies cannot
	// have scanned the input for SQLi / dangerous-command / PII-block content,
	// so admitting it would silently disable enforcement on a DB blip. The flag
	// lets callers audit this as an availability failure ("could not govern")
	// distinct from a policy verdict.
	EvaluationError bool

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

	// EvaluationError distinguishes "could not scan" from "scanned, found
	// nothing" (#2820). It is set true when the engine could NOT complete
	// evaluation — a policy-load / graceful-degradation error — as opposed to
	// a clean scan (Blocked=false, Redacted=false with EvaluationError=false).
	//
	// Response-plane callers (check-output, gateway, orchestrator, cowork OTEL
	// ingest) MUST fail CLOSED when this is set: a redactor that forwards or
	// stores content it could not scan leaks raw PII. It is DISTINCT from
	// Blocked (a policy verdict): EvaluationError is an availability failure,
	// audited/handled as "could not govern", not "a policy said block".
	//
	// NOTE: the sibling fail-open sub-path — Enabled*Categories returning nil
	// on a load error (so the caller skips EvaluateResponse entirely) — is
	// covered by PoliciesLoadable, which response-plane callers check before
	// category enumeration. EvaluationError is the second line of defense for
	// callers that reach EvaluateResponse.
	EvaluationError bool

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
	// StoredAction is the EXPLICIT action the policy row stores for the
	// evaluated phase (the action_request/action_response column value),
	// BEFORE any EvalOptions.ActionOverrides posture lever replaced it
	// (#3360). Empty when the row stores NULL for the phase: the engine then
	// resolves through GetActionForPhase's category fallback, which is not a
	// stored value and is never reported as displaced. When non-empty and
	// different from Action, the deployment/org posture displaced the stored
	// value; consumers use the pair to make a silent weakening (stored block
	// resolved to warn/redact) visible instead of leaving the row's action
	// column an unexplained lie.
	StoredAction Action

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

	// ExfiltrationCheck contains data extraction limit information (Issue #966).
	// Present when exfiltration checking is enabled, nil otherwise.
	ExfiltrationCheck *ExfiltrationCheckInfo `json:"exfiltration_check,omitempty"`

	// DynamicPolicyInfo contains dynamic policy evaluation results (Issue #968).
	// Present when dynamic policy evaluation is enabled, nil otherwise.
	DynamicPolicyInfo *DynamicPolicyInfo `json:"dynamic_policy_info,omitempty"`
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
	GracefulDegradation bool // Continue if DB unavailable - default: true. NOTE: does NOT apply to the request plane, which always fails CLOSED on a policy-load error (#2862); it governs the response plane's return-unprocessed-with-EvaluationError behavior (#2820) and the dynamic evaluator.

	// Defaults
	DefaultTenant string // Default tenant when none specified - default: "global"

	// Background refresh
	RefreshInterval time.Duration // How often to refresh policies - default: 30 seconds

	// Capability-scoped evaluation (#2801)
	//
	// ExtraTextDocumentTools extends the built-in text-document tool registry
	// (capability.go) with additional tool identities (exact names,
	// case-insensitive, matched against the full identity and its terminal
	// segment). Populated from AXONFLOW_TEXT_DOCUMENT_TOOLS in the Enterprise
	// edition only; community ships the built-in registry.
	ExtraTextDocumentTools []string

	// DisableCapabilityScoping restores pre-#2801 behavior (every policy
	// evaluates regardless of tool identity). Safety valve for the behavior
	// change; strictly MORE evaluation, never less.
	DisableCapabilityScoping bool
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

	// StrategyRemoveStatement replaces the ENTIRE sentence/line containing the
	// match with a typed placeholder, not just the matched span. Used for indirect
	// prompt-injection (security-dangerous) on the response plane (#2738): the
	// migration-116 regexes match only the injection ANCHOR (e.g. "from now on you
	// are", "[system]"), so a span-only removal leaves the residual instruction
	// ("...an admin", "...you are now in dev mode") injectable. Removing the whole
	// statement neutralizes the full threat while OTHER sentences/lines survive.
	// Example: "Note: ignore all previous instructions. Ship it." ->
	//          "[REDACTED:security-dangerous]. Ship it."
	StrategyRemoveStatement RedactionStrategy = "remove_statement"
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

// =============================================================================
// Dynamic Policy Evaluation Types (Issue #968)
// =============================================================================

// DynamicPolicyConfig configures dynamic policy evaluation for MCP requests.
// Dynamic policies are evaluated via Orchestrator before connector execution.
//
// The Orchestrator endpoint is determined automatically using the same logic as
// other Agent→Orchestrator calls (ORCHESTRATOR_URL env var, Docker detection, or localhost).
//
// Configuration via environment variables:
//   - MCP_DYNAMIC_POLICIES_ENABLED: Enable/disable (default: false)
//   - MCP_DYNAMIC_POLICIES_TIMEOUT: Orchestrator call timeout (default: 5s)
//   - MCP_DYNAMIC_POLICIES_GRACEFUL: Continue if Orchestrator unavailable (default: true)
//   - MCP_DYNAMIC_POLICIES_CONNECTORS: Comma-separated connectors (empty = all)
type DynamicPolicyConfig struct {
	// Enabled controls whether dynamic policy evaluation is performed.
	// Disabled by default - must be explicitly enabled.
	Enabled bool `json:"enabled"`

	// OrchestratorEndpoint is the base URL for the Orchestrator service.
	// Default: http://localhost:8081 (same-host deployment)
	OrchestratorEndpoint string `json:"orchestrator_endpoint"`

	// Timeout is the maximum time to wait for Orchestrator response.
	// Default: 5 seconds
	Timeout time.Duration `json:"timeout"`

	// GracefulDegradation controls behavior when Orchestrator is unavailable.
	// If true (default), requests proceed without dynamic policy evaluation.
	// If false, requests are blocked when Orchestrator is unavailable.
	GracefulDegradation bool `json:"graceful_degradation"`

	// EnabledConnectors lists connectors that use dynamic policies.
	// Empty list means all connectors are enabled.
	// Community edition has 2 connectors with custom policies limit, Evaluation has 5.
	EnabledConnectors []string `json:"enabled_connectors"`

	// MaxCustomPolicyConnectorsCommunity is the limit for connectors with custom policies in community edition.
	// All connectors can be registered in all tiers; only tenant-level policies are limited.
	MaxCustomPolicyConnectorsCommunity int `json:"max_custom_policy_connectors_community"`

	// MaxCustomPolicyConnectorsEvaluation is the limit for connectors with custom policies in evaluation edition.
	// Enterprise has unlimited connectors with custom policies.
	MaxCustomPolicyConnectorsEvaluation int `json:"max_custom_policy_connectors_evaluation"`
}

// DefaultDynamicPolicyConfig returns production-safe defaults.
// Dynamic policies are disabled by default for backward compatibility.
func DefaultDynamicPolicyConfig() DynamicPolicyConfig {
	return DynamicPolicyConfig{
		Enabled:                             false,
		OrchestratorEndpoint:                "http://localhost:8081",
		Timeout:                             5 * time.Second,
		GracefulDegradation:                 true,
		EnabledConnectors:                   nil, // All connectors when enabled
		MaxCustomPolicyConnectorsCommunity:  2,   // Community: max connectors with custom policies
		MaxCustomPolicyConnectorsEvaluation: 5,   // Evaluation: max connectors with custom policies
	}
}

// CustomPolicyConnectorLimitForTier returns the custom policy connector limit based on the license tier.
// This limits the number of connectors that can have tenant-level policies (rate limiting, budgets,
// time/role access) enabled. All connectors can be registered in all tiers.
// Returns -1 for unlimited (Enterprise).
func (c *DynamicPolicyConfig) CustomPolicyConnectorLimitForTier(tier string) int {
	switch tier {
	case "enterprise", "Enterprise", "Plus", "Professional":
		return -1 // Unlimited
	case "evaluation", "Evaluation":
		if c.MaxCustomPolicyConnectorsEvaluation > 0 {
			return c.MaxCustomPolicyConnectorsEvaluation
		}
		return 5 // Default Evaluation limit
	default:
		if c.MaxCustomPolicyConnectorsCommunity > 0 {
			return c.MaxCustomPolicyConnectorsCommunity
		}
		return 2 // Default Community limit
	}
}

// DynamicPolicyRequest is sent to Orchestrator for policy evaluation.
type DynamicPolicyRequest struct {
	// Request context
	TenantID       string `json:"tenant_id"`
	OrganizationID string `json:"organization_id,omitempty"`
	UserID         string `json:"user_id"`
	UserRole       string `json:"user_role,omitempty"`

	// SegmentIDs is the caller's governance-segment set (ADR-060), already
	// resolved FAIL-CLOSED by the agent before this request was built
	// (#3447). It exists so the dynamic plane applies the same segment
	// scoping the local static pass does: without it a verified segment
	// member had segment-scoped DYNAMIC policies silently skipped while the
	// static half enforced them — a split verdict on one request.
	//
	// The agent RELAYS the one set it resolved; the orchestrator does NOT
	// resolve independently. The two processes hold separate segment caches
	// with separate TTL clocks (segmentCache, default 60s, one per process),
	// so independent resolution could observe different sets on the SAME
	// request. Relaying makes that impossible by construction and costs one
	// resolution per request instead of two.
	//
	// nil/empty means "resolved to no segments / this plane does not resolve
	// one" — org-only — and NEVER "resolution failed": a caller that resolves
	// fail-closed and gets ok == false must deny before building this
	// request. Same contract as EvalOptions.Segments above.
	SegmentIDs []string `json:"segment_ids,omitempty"`

	// MCP request details
	ConnectorName string                 `json:"connector_name"`
	Operation     string                 `json:"operation"` // "query" or "execute"
	Statement     string                 `json:"statement"`
	Parameters    map[string]interface{} `json:"parameters,omitempty"`

	// Additional context for policy decisions
	RequestTime time.Time              `json:"request_time"`
	ClientIP    string                 `json:"client_ip,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

// DynamicPolicyResponse is the response from Orchestrator policy evaluation.
type DynamicPolicyResponse struct {
	// Primary decision
	Allowed     bool   `json:"allowed"`
	BlockReason string `json:"block_reason,omitempty"`

	// Matched policies
	PoliciesEvaluated int                  `json:"policies_evaluated"`
	MatchedPolicies   []DynamicPolicyMatch `json:"matched_policies,omitempty"`

	// Additional data
	ProcessingTimeMs int64                  `json:"processing_time_ms"`
	Metadata         map[string]interface{} `json:"metadata,omitempty"`
}

// DynamicPolicyMatch represents a dynamic policy that matched the request.
type DynamicPolicyMatch struct {
	PolicyID   string `json:"policy_id"`
	PolicyName string `json:"policy_name"`
	PolicyType string `json:"policy_type"` // rate-limit, budget, time-access, role-access
	Action     string `json:"action"`      // allow, block, warn
	Reason     string `json:"reason,omitempty"`
}

// DynamicPolicyInfo is the API-serializable structure for dynamic policy results.
// Included in PolicyInfo when dynamic policy evaluation is enabled.
type DynamicPolicyInfo struct {
	// Evaluation results
	PoliciesEvaluated int                  `json:"policies_evaluated"`
	MatchedPolicies   []DynamicPolicyMatch `json:"matched_policies,omitempty"`

	// Orchestrator metadata
	OrchestratorReachable bool  `json:"orchestrator_reachable"`
	ProcessingTimeMs      int64 `json:"processing_time_ms"`
}

// =============================================================================
// Exfiltration Detection Types (Issue #966)
// =============================================================================

// ExfiltrationLimits configures data extraction limits for MCP responses.
// These limits prevent large-scale data extraction via MCP queries.
//
// Configuration via environment variables:
//   - MCP_MAX_ROWS_PER_QUERY: Maximum rows per query (default: 10000)
//   - MCP_MAX_BYTES_PER_QUERY: Maximum bytes per response (default: 10MB)
//   - MCP_EXFILTRATION_ENABLED: Enable/disable checks (default: true)
type ExfiltrationLimits struct {
	// MaxRowsPerQuery is the maximum number of rows allowed per query.
	// Queries returning more rows will be blocked with HTTP 403.
	// Default: 10,000 rows. Set to 0 for unlimited.
	MaxRowsPerQuery int `json:"max_rows_per_query"`

	// MaxBytesPerQuery is the maximum response size in bytes.
	// Responses exceeding this will be blocked with HTTP 403.
	// Default: 10MB (10,485,760 bytes). Set to 0 for unlimited.
	MaxBytesPerQuery int64 `json:"max_bytes_per_query"`

	// Enabled controls whether exfiltration checks are performed.
	// When disabled, queries are allowed regardless of size.
	// Default: true
	Enabled bool `json:"enabled"`
}

// DefaultExfiltrationLimits returns production-safe defaults.
// These defaults balance security with usability for typical workloads.
func DefaultExfiltrationLimits() ExfiltrationLimits {
	return ExfiltrationLimits{
		MaxRowsPerQuery:  10000,            // 10K rows
		MaxBytesPerQuery: 10 * 1024 * 1024, // 10MB
		Enabled:          true,
	}
}

// ExfiltrationResult contains the result of an exfiltration check.
type ExfiltrationResult struct {
	// Exceeded is true if any limit was exceeded.
	Exceeded bool `json:"exceeded"`

	// LimitType indicates which limit was exceeded: "rows" or "bytes".
	// Empty if no limit was exceeded.
	LimitType string `json:"limit_type,omitempty"`

	// ActualValue is the actual count/size that triggered the limit.
	ActualValue int64 `json:"actual_value,omitempty"`

	// LimitValue is the configured limit that was exceeded.
	LimitValue int64 `json:"limit_value,omitempty"`

	// BlockReason is a human-readable explanation for blocking.
	BlockReason string `json:"block_reason,omitempty"`
}

// ExfiltrationCheckInfo is the API-serializable version of exfiltration check results.
// Included in PolicyInfo when exfiltration checking is enabled.
type ExfiltrationCheckInfo struct {
	// RowsReturned is the number of rows in the response.
	RowsReturned int64 `json:"rows_returned"`

	// RowLimit is the configured maximum rows per query.
	RowLimit int `json:"row_limit"`

	// BytesReturned is the approximate size of the response in bytes.
	BytesReturned int64 `json:"bytes_returned"`

	// ByteLimit is the configured maximum bytes per query.
	ByteLimit int64 `json:"byte_limit"`

	// WithinLimits is true if all limits were respected.
	WithinLimits bool `json:"within_limits"`
}
