// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package policy

import "time"

// Override precedence — two independent mechanisms share policy_overrides
// ----------------------------------------------------------------------
//
// The agent and orchestrator each resolve "policy_overrides row(s) ->
// effective action" independently. Those resolutions are NOT all the same
// feature: the table stores rows for two conceptually different override
// mechanisms, and this file unifies the shared logic for each — but the two
// mechanisms remain distinct and must not be conflated.
//
//	Mechanism A — admin-authored tier-downgrade override. An operator sets an
//	override action for an entire tenant or an entire org on a system-tier
//	policy (PolicyOverrideRepository.Create). Queried WITHOUT any
//	requesting-user dimension (no created_by predicate).
//
//	Mechanism B — ADR-044 session break-glass. An individual user requests a
//	temporary, identity-keyed exception for themselves (createOverrideHandler
//	writes created_by=<user>, action_override='allow'). Queried WITH a
//	created_by predicate plus a tool_signature specificity dimension, and
//	gated to action_override IN ('allow', NULL) so a Mechanism-A tightening
//	override (block/warn/redact) can never be misread as a Mechanism-B
//	allow-bypass.
//
// | # | Path (file:line)                                                         | Mechanism | Key                                   | Precedence                                   | Segment-scoped policy                                   | Live prod caller |
// |---|----------------------------------------------------------------------------|-----------|----------------------------------------|-----------------------------------------------|----------------------------------------------------------|-------------------|
// | 1 | agent/policy_override_repository.go GetEffectiveAction (deleted)          | A         | policy_id + tenant_id / organization_id | tenant beats org beats none (two sequential queries, first hit wins) | no segment param at all — caller had to gate separately | none — deleted as dead code; coverage ported to override_test.go |
// | 2 | agent/static_policy_repository.go applyEffectiveOverride (calls EffectiveOverride below) | A | policy_id (UUID) | delegated to EffectiveOverride: tenant beats org beats none, unconditionally | excluded before EffectiveOverride is even consulted (`policy.SegmentID != nil` short-circuits); EffectiveOverride's own segmentID check is redundant defense-in-depth | yes |
// | 3 | orchestrator/override_enforcement.go ApplyOverrideToResult (+ FindActiveOverride) | B | policy_id + created_by(user) + tenant_id(or NULL) + tool_signature | SQL ORDER BY tool-signature-specificity then created_at DESC, LIMIT 1 | not excluded — deliberately (see below) | yes, wcp_policy_adapter.go |
// | 4 | agent/mcp_richer_context.go applyOverrideToCheckInputBlock (+ lookupActiveOverride) | B | policy_id + created_by(user) + tenant_id(or NULL), no tool dimension | SQL ORDER BY created_at DESC, LIMIT 1 | no SegmentID field exists on the input type at all | yes, 3 call sites in mcp_server_handler.go / mcp_handler.go |
//
// Divergence #1 (Mechanism A, rows 1 vs 2, now fixed): the original
// GetEffectiveAction enforced strict tenant-beats-org precedence via two
// sequential, short-circuited queries. The static-policy path's original
// inline implementation instead ran ONE query unioning both scopes, ordered
// by created_at ASC, and let a later map-write clobber an earlier one — so
// an org-level override created AFTER a tenant-level one would win,
// contradicting the "tenant is more specific, tenant always wins" contract.
// EffectiveOverride restores that invariant unconditionally (never dependent
// on row recency), which is the more restrictive/predictable of the two
// behaviors: a caller cannot get a broader (org-level) override to silently
// beat a narrower, more deliberate (tenant-level) one merely by timing its
// creation later. static_policy_repository.go's applyEffectiveOverride now
// delegates to EffectiveOverride, so this divergence no longer exists in the
// shipped code; TestGetEffective_TenantOverrideBeatsLaterCreatedOrgOverride
// (static_policy_repository_test.go) is the regression test pinning it.
//
// Divergence #3 (Mechanism A, row 2, now fixed): EffectiveOverride originally
// modeled a policy_overrides row as "a thing that changes an action" — it
// ignored rows with no action_override and picked exactly one "winning" row
// per policy to source both the action AND the enabled/reason/expires_at
// metadata. That collapsed two independently-nullable columns
// (action_override, enabled_override) onto one axis and broke two ways: a
// disable-only row (action_override NULL, enabled_override=false) never
// registered at all, so a tenant that deliberately disabled a system policy
// found it silently re-enabled; and an action-less tenant row, merely by
// existing, forced scope resolution to "tenant" and then failed to find any
// tenant row whose action matched, discarding a perfectly valid org-level
// action override in the process. EffectiveOverride now resolves Action and
// Enabled as two independent attributes (each with its own tenant-beats-org,
// then latest-within-scope precedence) and reports every contributing row via
// OverrideResolution.Contributions, so a tenant disable and an org action
// downgrade can both be in effect on the same policy simultaneously, each
// correctly attributed to its own row's reason/expiry.
//
// Divergence #2 (Mechanism A vs Mechanism B, rows 1-2 vs 3-4) on segment
// scoping: an earlier revision of the ADR-044 (Mechanism B) design forced
// AppliedPolicyDetail.AllowOverride false for segment-scoped policies at
// construction AND had ApplyOverrideToResult check
// AppliedPolicyDetail.SegmentID independently. That design was deliberately
// reversed before shipping — ApplyOverrideToResult no longer checks
// SegmentID at all — and the shipped code carries an explicit instruction
// not to reintroduce it:
//
//	platform/orchestrator/run.go (AppliedPolicyDetail.SegmentID doc
//	comment): "Do not reintroduce a SegmentID check into that function's
//	[ApplyOverrideToResult's] eligibility logic — see its doc comment for
//	why."
//	platform/orchestrator/override_enforcement.go (ApplyOverrideToResult
//	doc comment): explains at length that a segment-scoped policy is
//	eligible for the SAME session-override contract as a tenant policy
//	(own allow_override + non-critical), and that segment exclusion is a
//	property of the applicable-POLICY COMBINER (additive-restriction-only,
//	ADR-060 Decision 1), not of the post-verdict override step.
//	platform/orchestrator/override_enforcement_test.go: two purpose-built
//	regression tests,
//	TestApplyOverrideToResult_SegmentScopedHonorsOwnAllowOverride and
//	TestApplyOverrideToResult_SegmentScopedStillAFloorWhenNotOverridable
//	(the latter using a "planted but must stay UNCONSUMED" sqlmock
//	expectation specifically so a regression that reintroduces a
//	SegmentID check cannot pass silently).
//
// This is why EffectiveOverride's segment exclusion is NOT wired into
// ApplyOverrideToResult (row 3) or applyOverrideToCheckInputBlock (row 4):
// doing so would reverse a deliberate, tested, and explicitly-guarded design
// decision. It IS the correct behavior for Mechanism A (rows 1-2), which is
// why static_policy_repository.go's applyEffectiveOverride adopts it, and
// why GetEffectiveAction's precedence tests were ported onto
// EffectiveOverride rather than discarded when GetEffectiveAction was
// deleted as dead code.
//
// applyOverrideToCheckInputBlock (row 4) also has no SegmentID field on its
// input (RicherPolicyMatch / sharedpolicy.PolicyMatch) to plumb one through
// even if it were wanted: its own doc comment states it deliberately
// "mirrors orchestrator.ApplyOverrideToResult ... so the plugin and SDK see
// consistent behavior regardless of which surface fired the request." Adding
// a segment exclusion here would break that stated parity with row 3, not
// fix a gap, so no field was added.
//
// What IS shared across Mechanism B's two live implementations (rows 3-4)
// and was also duplicated a third time in SelectOverridablePolicy
// (orchestrator/override_enforcement.go) is the per-policy ELIGIBILITY gate
// itself — "is this specific matched policy even a candidate for a session
// override" — identical two-line logic
// (`RiskLevel == "critical" || !AllowOverride`) copy-pasted three times.
// IsOverrideEligible below is the single implementation; all three call
// sites now route through it.

// OverrideScope is the tenancy at which a Mechanism-A (admin tier-downgrade)
// policy_overrides row was written: tenant_id set (OverrideScopeTenant) or
// organization_id set with tenant_id NULL (OverrideScopeOrg). Mechanism B
// (ADR-044 session override) rows are not modeled by OverrideScope/
// OverrideRow/EffectiveOverride — see the package doc above.
type OverrideScope int

const (
	// OverrideScopeOrg is an override row scoped to an entire organization
	// (organization_id set, tenant_id NULL).
	OverrideScopeOrg OverrideScope = iota
	// OverrideScopeTenant is an override row scoped to a single tenant
	// (tenant_id set). More specific than, and always wins over, an org-level
	// row for the same policy.
	OverrideScopeTenant
)

// OverrideRow is one policy_overrides record relevant to Mechanism-A
// (admin-authored tenant/org override) precedence resolution, reduced to the
// columns EffectiveOverride needs.
//
// policy_overrides models two orthogonal axes: SCOPE (org vs tenant — one
// row is exactly one or the other, schema-enforced) and ATTRIBUTE (what the
// row overrides — action_override and/or enabled_override, BOTH nullable,
// where NULL means "no opinion on this attribute — inherit", not false).
// Action and Enabled below carry that nullability: a row commonly expresses
// an opinion on only one of the two.
//
// Callers are responsible for:
//   - pre-filtering to rows matching the policy's tenant/org identity (rows
//     for OTHER tenants/orgs must not be passed in — EffectiveOverride does
//     not re-check identity beyond PolicyID)
//   - pre-filtering out expired (expires_at <= NOW()) and, if the schema
//     gains one for Mechanism A, revoked rows — expiry is a temporal DB
//     concern this dependency-free package deliberately does not take a
//     clock dependency to resolve; both existing callers already filter it
//     in SQL (`expires_at IS NULL OR expires_at > NOW()`)
//   - passing rows in `created_at ASC` order — EffectiveOverride breaks a
//     same-scope, same-attribute tie by taking the LAST matching row in the
//     slice, i.e. the most recently created one; it does not read a
//     timestamp itself
type OverrideRow struct {
	// PolicyID is the policy this override row applies to. Matched against
	// EffectiveOverride's policyID argument by exact string equality — the
	// caller is responsible for using a consistent identity space (both
	// UUID, or both slug) on both sides, exactly as today's caller already
	// does internally.
	PolicyID string
	// RowID identifies the underlying policy_overrides row (its primary
	// key). Used only for attribution — EffectiveOverride never compares
	// RowID for precedence — so a caller that does not need attribution may
	// leave it empty as long as no two rows passed together share "".
	RowID string
	// Scope is the tenancy this row was written at.
	Scope OverrideScope
	// Action is the row's action_override column value (e.g. "block",
	// "warn", "redact", "log", "require_approval"). Empty means this row has
	// no opinion on the action attribute (action_override IS NULL) — it is
	// not, by itself, evidence of "no override": the row may still carry an
	// opinion on Enabled.
	Action string
	// Enabled is the row's enabled_override column value. Nil means this row
	// has no opinion on the enabled attribute (enabled_override IS NULL).
	// A non-nil false is a deliberate "keep this policy disabled" opinion
	// and must not be dropped merely because Action is also empty.
	Enabled *bool
	// Reason is the row's override_reason (NOT NULL in the schema — one
	// operator, one justification per row).
	Reason string
	// ExpiresAt is the row's optional auto-revert timestamp. nil means no
	// expiry. Carried through only for attribution; EffectiveOverride does
	// not evaluate it (see the pre-filtering contract above).
	ExpiresAt *time.Time
}

// OverrideContribution is one policy_overrides row that supplied part (or
// all) of a policy's effective override state. Reason and ExpiresAt are
// properties of the ROW — one operator, one justification, one expiry,
// possibly covering both attributes — never invented per-attribute: if a
// single row supplied both Action and Enabled, HasAction and HasEnabled are
// both true on the SAME OverrideContribution. If two different rows each
// supplied one attribute, two separate OverrideContributions are returned,
// each with its own Reason/ExpiresAt, each in effect on its own terms.
type OverrideContribution struct {
	RowID      string
	Scope      OverrideScope
	Reason     string
	ExpiresAt  *time.Time
	HasAction  bool
	Action     string
	HasEnabled bool
	Enabled    bool
}

// OverrideResolution is the outcome of resolving a policy's Mechanism-A
// override rows. Action and Enabled are resolved INDEPENDENTLY of one
// another (see EffectiveOverride) — a policy can have an opinion on one
// attribute, the other, both, or neither.
type OverrideResolution struct {
	// HasOverride is true if ANY row contributed an opinion on EITHER
	// attribute. A disable-only row (Action NULL, Enabled=false) sets this
	// true on its own — it must not require an action opinion to register.
	HasOverride bool
	// HasAction reports whether any row had an opinion on the action
	// attribute. Action is meaningful only when HasAction is true.
	HasAction bool
	Action    string
	// HasEnabled reports whether any row had an opinion on the enabled
	// attribute. Enabled is meaningful only when HasEnabled is true.
	HasEnabled bool
	Enabled    bool
	// Contributions is every row that supplied part of this resolution — one
	// entry per distinct RowID, attributed per the OverrideContribution doc
	// comment. Empty when HasOverride is false.
	Contributions []OverrideContribution
}

// EffectiveOverride resolves Mechanism-A (admin tier-downgrade) override
// precedence for one policy, given every override row already known to be in
// scope for the calling tenant/org.
//
// Action and Enabled are resolved as two INDEPENDENT attributes, each by the
// same rule:
//  1. Consider only rows with a non-NULL opinion on that attribute.
//  2. Tenant scope beats org scope, unconditionally — never dependent on row
//     recency (see Divergence #1 in the package doc above for why
//     "unconditionally" matters).
//  3. Within the winning scope, the LAST matching row in the input slice
//     wins (see OverrideRow's doc comment: callers pass rows in created_at
//     ASC order, so this is "latest created_at wins" — a tie-break that
//     applies only within one scope and can never let an org row beat a
//     tenant row).
//
// There is deliberately no single "winner" row: a policy can be disabled by
// a tenant row while its action is downgraded by a DIFFERENT org row, and
// both are in effect simultaneously (see OverrideResolution/
// OverrideContribution).
//
// A segment-scoped policy (segmentID != "") is NEVER overridable through this
// path (Mechanism A only — see Divergence #2 above for why this exclusion
// does NOT extend to Mechanism B / ApplyOverrideToResult /
// applyOverrideToCheckInputBlock): returns a zero OverrideResolution
// unconditionally, mirroring static_policy_repository.go's own
// `policy.SegmentID != nil` short-circuit in applyEffectiveOverride, which
// gates before this function is even called — the check here is redundant
// defense-in-depth for any future caller that does not pre-gate.
func EffectiveOverride(policyID, segmentID string, rows []OverrideRow) OverrideResolution {
	if segmentID != "" || policyID == "" || len(rows) == 0 {
		return OverrideResolution{}
	}

	tenantActionIdx, orgActionIdx := -1, -1
	tenantEnabledIdx, orgEnabledIdx := -1, -1

	for i, r := range rows {
		if r.PolicyID != policyID {
			continue
		}
		switch r.Scope {
		case OverrideScopeTenant:
			if r.Action != "" {
				tenantActionIdx = i
			}
			if r.Enabled != nil {
				tenantEnabledIdx = i
			}
		case OverrideScopeOrg:
			if r.Action != "" {
				orgActionIdx = i
			}
			if r.Enabled != nil {
				orgEnabledIdx = i
			}
		}
	}

	actionIdx := tenantActionIdx
	if actionIdx == -1 {
		actionIdx = orgActionIdx
	}
	enabledIdx := tenantEnabledIdx
	if enabledIdx == -1 {
		enabledIdx = orgEnabledIdx
	}

	if actionIdx == -1 && enabledIdx == -1 {
		return OverrideResolution{}
	}

	res := OverrideResolution{HasOverride: true}
	contributions := make(map[int]*OverrideContribution)
	var order []int
	contribution := func(i int) *OverrideContribution {
		c, ok := contributions[i]
		if !ok {
			r := rows[i]
			c = &OverrideContribution{RowID: r.RowID, Scope: r.Scope, Reason: r.Reason, ExpiresAt: r.ExpiresAt}
			contributions[i] = c
			order = append(order, i)
		}
		return c
	}

	if actionIdx != -1 {
		res.HasAction = true
		res.Action = rows[actionIdx].Action
		c := contribution(actionIdx)
		c.HasAction = true
		c.Action = rows[actionIdx].Action
	}
	if enabledIdx != -1 {
		res.HasEnabled = true
		res.Enabled = *rows[enabledIdx].Enabled
		c := contribution(enabledIdx)
		c.HasEnabled = true
		c.Enabled = *rows[enabledIdx].Enabled
	}

	res.Contributions = make([]OverrideContribution, 0, len(order))
	for _, i := range order {
		res.Contributions = append(res.Contributions, *contributions[i])
	}
	return res
}

// IsOverrideEligible reports whether a single matched policy is a candidate
// for a Mechanism-B (ADR-044 session break-glass) override lookup, given its
// risk level and its own allow_override flag. This is the eligibility gate
// duplicated, byte-for-byte, in three places prior to this change:
//   - orchestrator/override_enforcement.go ApplyOverrideToResult's loop
//     (`p.RiskLevel == "critical" || !p.AllowOverride` -> continue)
//   - orchestrator/override_enforcement.go SelectOverridablePolicy
//     (`p.RiskLevel != "critical" && p.AllowOverride` -> return)
//   - agent/mcp_richer_context.go applyOverrideToCheckInputBlock's loop
//     (`m.RiskLevel == "critical" || !m.AllowOverride` -> continue)
//
// A critical-risk policy is NEVER eligible regardless of allowOverride (the
// DB trigger backing allow_override already forces this at write time for
// critical policies; this is defense-in-depth for in-memory evaluation, per
// the existing ADR-044 invariant tests). Otherwise eligibility echoes
// allowOverride exactly.
func IsOverrideEligible(riskLevel string, allowOverride bool) bool {
	if riskLevel == "critical" {
		return false
	}
	return allowOverride
}
