// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

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

	// US compliance categories (#3529, epic #3528 Phase 1). Seeded as policy
	// templates by migrations/enterprise/139_us_compliance_templates.sql, each
	// rule citing the public provision it is modelled on.
	//
	// The spelling is canonical `compliance-<x>` on purpose and the four
	// constants below are the ONLY place it is written in Go: migration
	// core/127 records what happens when a seed invents its own spelling, the
	// exact-match category filter excluded every drifted row and those
	// policies silently never fired.
	CategoryComplianceGLBA        PolicyCategory = "compliance-glba"        // GLBA Safeguards Rule, 16 CFR 314.4
	CategoryComplianceFairLending PolicyCategory = "compliance-fairlending" // ECOA / Regulation B, 12 CFR 1002
	CategoryComplianceBSAAML      PolicyCategory = "compliance-bsa-aml"     // Bank Secrecy Act / SAR, 31 CFR 1020.320
	CategoryComplianceNYDFS       PolicyCategory = "compliance-nydfs"       // NYDFS 23 NYCRR Part 500

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

	// Pre-canonical categories (#4131). migrations/core/010 and core/014 seeded
	// eight organization-template rows under these v10 spellings, and core/127
	// canonicalised only the compliance spellings, so the rows still carry
	// them. They are deliberately NOT members of AllPolicyCategories: no
	// category-default validator and no organization override category reaches
	// them. LegacyTemplateCategories says where they are admitted.
	CategoryLegacySQLInjection     PolicyCategory = "sql_injection"
	CategoryLegacyDangerousQueries PolicyCategory = "dangerous_queries"
	CategoryLegacyPIIDetection     PolicyCategory = "pii_detection"
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
	PatternStr string         // The pattern Pattern compiles: the stored one after the case rule (EffectivePattern)

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
// Follows the tiered detection philosophy (Issue #891, ADR-025):
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

// AllPolicyCategories returns every PolicyCategory constant this package
// declares, in a stable order.
//
// It exists because two ADR-065 migration pin tables - the action-resolution
// table and the declared category table - have to be complete against
// this enum in BOTH directions: a category with no row goes unpinned, and a
// MISSPELLED row pins nothing while inflating the counts a reader trusts.
// Enumerating from a hand-maintained list in each test is the drift those
// tables exist to prevent, so the list lives here, beside the constants, with
// a source-scanning guard in this package's own tests proving it is complete.
//
// Not to be confused with platform/agent.AllPolicyCategories, which enumerates
// the AGENT's own PolicyCategory type over its static/dynamic authoring split.
// They are different types over overlapping vocabularies and neither is
// derived from the other; this one is the one the ADR-065 migration tables are
// pinned against, because it is the type the shared engine evaluates.
func AllPolicyCategories() []PolicyCategory {
	return []PolicyCategory{
		CategorySecuritySQLi, CategorySecurityDangerous, CategoryAdminAccess,
		CategoryPIIGlobal, CategoryPIIUS, CategoryPIIIndia, CategoryPIIEU,
		CategoryPIISingapore, CategoryPIIIndonesia,
		CategoryDataExfiltration, CategorySensitiveData,
		CategoryDynamicRateLimit, CategoryDynamicBudget,
		CategoryDynamicTimeAccess, CategoryDynamicRoleAccess,
		CategoryComplianceGDPR, CategoryComplianceHIPAA, CategoryComplianceRBI,
		CategoryComplianceSEBI, CategoryComplianceEUAIAct, CategoryComplianceMASFEAT,
		CategoryComplianceGLBA, CategoryComplianceFairLending,
		CategoryComplianceBSAAML, CategoryComplianceNYDFS,
		CategoryFinCrime,
		CategoryMediaSafety, CategoryMediaBiometric, CategoryMediaDocument, CategoryMediaPII,
	}
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

// LegacyTemplateCategories returns the three pre-canonical categories the
// organization template's rows still carry (#4131): its DROP and TRUNCATE
// prevention, its two SQL-injection rows and its four PII rows. The /api/request
// proxy spreads them into its category filter so those eight rows bind there,
// as the template's other fourteen already did. No other enforcing plane admits
// them (the policy-test surface shares the proxy's list):
// canonicalising the stored categories would bind them on every plane whose
// filter names the canonical ones, and that is a posture decision (#4230).
// platform/decision/legacycompile restates the list as data (admission.go) and
// the agent's category-admission weld holds the two equal.
func LegacyTemplateCategories() []PolicyCategory {
	return []PolicyCategory{
		CategoryLegacySQLInjection,
		CategoryLegacyDangerousQueries,
		CategoryLegacyPIIDetection,
	}
}

// OrgOverrideCategoryFor names the detection_action_overrides category whose
// RECORDED organization override replaces a policy's resolved action in this
// policy category, or "" when no override category reaches it (#3961).
//
// Since v11 an organization's recorded override is the only thing that can
// replace a stored action. Before, the answer to this question was an
// environment variable (PII_ACTION, SQLI_ACTION, ...) that replaced the action
// for EVERY organization of a deployment, unauthored and unaudited; those are
// gone (agent.RemovedPostureEnvVars). So the portal's Policies page and the
// agent's audit advisory now name an override an organization can see and set,
// not a string in somebody's environment.
//
// It is the SHARED source for that question, deliberately not a third copy:
// agent/detection_config.go BuildActionOverrides decides the set at
// enforcement time, agent/policy_result_convert.go names it in the audit
// advisory, and the customer portal names it on the Policies page. Three
// independent switches over one fact would diverge, and the divergence would be
// invisible in both directions. TestOrgOverrideCategoryMatchesBuildActionOverrides
// in the agent package - the only package that can see both - pins the two
// together.
//
// sensitive-data returns "": the override table's CHECK constraint lists no
// category for it, so its stored action always decides. Categories with no
// override category (compliance-*, fincrime, admin-access, data-exfiltration,
// media-*) likewise keep their stored action.
//
// "" is NOT a promise that static_policies.action is what runs. The shared
// engine's RUNTIME loader (PolicyLoader, loader.go) does not SELECT that
// column on any of its queries - they read phase, action_request,
// action_response - so on every shared-engine plane the base action column is
// read by nothing; GetActionForPhase resolves the phase column, or a
// category/severity fallback when it is NULL. The base column was read at
// runtime only by the proxy plane's Phase-2 tier engine, through
// StaticPolicyRepository.GetEffective, until #4253 deleted it; since then only
// the effective-policies read uses GetEffective.
//
// Be precise about the FILE rather than the type: loader.go carries two
// disjoint column sets. effectivePolicyColumns (same file, used by
// ScanEffectivePolicyRows for the GetEffective admin/API path) selects
// sp.action and none of the phase columns. That disjointness is the mechanism
// by which the two drift, which is why migration core/124 exists. This function
// answers exactly one question - which recorded override can replace the
// resolved action - and callers must not widen it into a claim about the action
// column.
func OrgOverrideCategoryFor(cat PolicyCategory) string {
	switch {
	case IsPIIPolicyCategory(cat):
		return "pii"
	case cat == CategorySecuritySQLi:
		return "sqli"
	case cat == CategorySecurityDangerous:
		return "dangerous_command"
	default:
		return ""
	}
}

// OrgOverrideReach returns the policy categories a recorded override of
// category replaces the action of, in AllPolicyCategories order. It is the
// inverse of OrgOverrideCategoryFor over the declared categories, so which
// categories an override reaches and which override names a category cannot
// disagree. A category that names no override - "", dangerous_query,
// obligation_fallback, or one the table does not admit - reaches nothing.
func OrgOverrideReach(category string) []PolicyCategory {
	if category == "" {
		return nil
	}
	var out []PolicyCategory
	for _, c := range AllPolicyCategories() {
		if OrgOverrideCategoryFor(c) == category {
			out = append(out, c)
		}
	}
	return out
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
		CategoryComplianceSEBI, CategoryComplianceEUAIAct, CategoryComplianceMASFEAT,
		CategoryComplianceGLBA, CategoryComplianceFairLending,
		CategoryComplianceBSAAML, CategoryComplianceNYDFS:
		return true
	}
	return false
}

// AllComplianceCategories returns all compliance-related policy categories.
// Issue #1081: Added for use in gateway evaluation.
//
// #3529: it is now actually USED for that. Until this change the four agent
// plane whitelists (proxyPolicyCategories, gatewayPreCheckPolicyCategories,
// openaiCompatPolicyCategories and the inline mcp_handler list) each hand-listed
// four of the six categories this function returned, and nothing in the
// non-test tree called this function at all. So it declared a vocabulary that
// no plane honoured, and compliance-gdpr / compliance-hipaa were filtered out
// before evaluation on every plane while being advertised as authorable in the
// portal. All four whitelists now spread this function, which is the same fix
// #2965 applied to the PII portion with AllTextPIICategories after a hand list
// dropped pii-indonesia and left Indonesian PII ungoverned.
//
// Consequence for anyone adding a category here: it becomes evaluated on all
// four planes at once. That is the point (a compliance category that no plane
// evaluates is a silent allow) but it means this list is a runtime surface
// now, not a piece of documentation. TestPlaneWhitelistsCoverAllCompliance and
// its independent cross-check pin the relationship in both directions.
func AllComplianceCategories() []PolicyCategory {
	return []PolicyCategory{
		CategoryComplianceGDPR,
		CategoryComplianceHIPAA,
		CategoryComplianceRBI,
		CategoryComplianceSEBI,
		CategoryComplianceEUAIAct,
		CategoryComplianceMASFEAT,
		CategoryComplianceGLBA,
		CategoryComplianceFairLending,
		CategoryComplianceBSAAML,
		CategoryComplianceNYDFS,
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
	// non-segment-scoped policy, SegmentID == "", to be skipped).
	//
	// One plane still passes a resolved set: the /api/request proxy
	// (agent/run.go clientRequestHandler, and its policy-test preview), which
	// resolves it fail-closed before evaluating. Every other caller passes
	// none. The gateway pre-check, /decide, the MCP-server tools and the four
	// MCP REST routes are decided by the anchored engine, which reads no
	// segments (PRD v11 §1.2); agent/openai_compat_handler.go and
	// orchestrator/response_processor.go have no verified human-actor
	// principal to resolve one from (see their call-site comments).
	//
	// Read nil as "resolved to no segments / this plane does not resolve
	// one", never as "resolution failed" or "resolution was skipped because
	// identity was weak".
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

	// Observation is this evaluation's detector facts (detector_facts.go): the
	// row facts an enforcing seam hands the anchored engine as its detector
	// inputs (#3895). Set on every evaluation. A caller reads it; it never
	// constructs one.
	Observation *Observation
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

	// Observation is this evaluation's detector facts: the response-phase twin
	// of RequestResult.Observation, read by an enforcing response pass (#3564).
	Observation *Observation
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
	// BEFORE any EvalOptions.ActionOverrides organization override replaced it
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

	// InstalledDetectors are the detectors of the policy packs this deployment
	// installed (PRD v11 §1.9), compiled by CompileInstalledDetectors. The
	// loader appends them to every load, so every evaluation reports their
	// facts; they are never static_policies rows.
	InstalledDetectors []CompiledPolicy
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
