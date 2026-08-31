package conformance

import (
	"context"
	"sort"
	"strings"
	"testing"
	"time"

	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/pdp"
)

// systemDocWith returns the system document with extra policies appended.
func systemDocWith(extra ...pdp.Policy) *pdp.Document {
	d := SystemDocument()
	d.Policies = append(d.Policies, extra...)
	return d
}

// systemDocWithout returns the system document with policies removed.
func systemDocWithout(ids ...string) *pdp.Document {
	drop := map[string]bool{}
	for _, id := range ids {
		drop[id] = true
	}
	d := SystemDocument()
	var kept []pdp.Policy
	for _, p := range d.Policies {
		if !drop[p.ID] {
			kept = append(kept, p)
		}
	}
	d.Policies = kept
	return d
}

// orgDocWithout returns the organization document with policies removed.
func orgDocWithout(ids ...string) *pdp.Document {
	drop := map[string]bool{}
	for _, id := range ids {
		drop[id] = true
	}
	d := OrganizationDocument()
	var kept []pdp.Policy
	for _, p := range d.Policies {
		if !drop[p.ID] {
			kept = append(kept, p)
		}
	}
	d.Policies = kept
	return d
}

func systemPolicy(d *pdp.Document, id string) *pdp.Policy {
	for i := range d.Policies {
		if d.Policies[i].ID == id {
			return &d.Policies[i]
		}
	}
	return nil
}

// sourceCases are the 47 cases of the Grants and Ceilings draft, transcribed
// into ADR-065 semantics. Where ADR-065 produces a different result from the
// source, the disposition ledger row for that case records why.
func sourceCases() []Case {
	return []Case{
		// ---------------------------------------------------------------
		// A. Baseline
		// ---------------------------------------------------------------
		{
			ID: "EX-01", Title: "Clean permit", Family: "A Baseline", Kind: KindDecision,
			Produces: []string{"ALLOW"},
			Run: func(t *testing.T, rec *Recorder) {
				w := defaultWorld(t)
				d := decide(t, w, Scenario{Principal: "alice", Action: "T1", Resource: "SUP-42",
					Args: map[string]any{"amount_cents": 30000}})
				expectDecision(rec, d, expectation{
					Authorization: contract.AuthzPermit, State: contract.StateAllow, Reason: contract.ReasonPermitted,
					Permissions: []string{"G1"}, Requirements: []string{"C8"},
					Obligations: []string{"quota_reservation"},
				})
			},
		},
		{
			ID: "EX-02", Title: "Permissive posture, zero permissions", Family: "A Baseline", Kind: KindDecision,
			Produces: []string{"DENY"},
			Run: func(t *testing.T, rec *Recorder) {
				w := defaultWorld(t)
				d := decide(t, w, Scenario{Principal: "alice", Action: "T3", Args: map[string]any{"query": "invoices"}})
				// ADR-065 reverses the source's per-tool unmatched=Permit
				// posture. A read-only label is not sufficient reason to fail
				// open: a read can disclose sensitive data, enumerate
				// authorization structure, or feed a later write.
				expectDecision(rec, d, expectation{
					Authorization: contract.AuthzNotApplicable, State: contract.StateDeny,
					Reason: contract.ReasonNoMatchingPermission,
				})
			},
		},
		{
			ID: "EX-03", Title: "Permissions union across groups", Family: "A Baseline", Kind: KindDecision,
			Produces: []string{"CHALLENGE"},
			Run: func(t *testing.T, rec *Recorder) {
				w := defaultWorld(t)
				d := decide(t, w, Scenario{Principal: "carol", Action: "T1", Resource: "SUP-99",
					Args: map[string]any{"amount_cents": 3000000}})
				// Carol's tier-two permission caps at 500000 and requires
				// ownership. Neither constrains her, because a condition on
				// WHEN a permission applies is not a limit on the people it
				// applies to; a more permissive permission from another group
				// simply also applies.
				expectDecision(rec, d, expectation{
					Authorization: contract.AuthzPermit, State: contract.StateChallenge, Reason: contract.ReasonApprovalRequired,
					Permissions: []string{"G2"}, Requirements: []string{"C1", "C8"},
					Obligations: []string{"approval_challenge", "quota_reservation"},
					Approval:    []string{"1 of support-leads"},
				})
				rec.True("the tier-two permission did not match", !contains(d.Determining.MatchedPermissions, "G1"))
			},
		},

		// ---------------------------------------------------------------
		// B. Constraints and segments
		// ---------------------------------------------------------------
		{
			ID: "EX-04", Title: "A restriction group changes the outcome", Family: "B Constraints", Kind: KindDecision,
			Produces: []string{"CHALLENGE"},
			Run: func(t *testing.T, rec *Recorder) {
				w := defaultWorld(t)
				alice := decide(t, w, Scenario{Principal: "alice", Action: "T1", Resource: "SUP-42",
					Args: map[string]any{"amount_cents": 30000}})
				bob := decide(t, w, Scenario{Principal: "bob", Action: "T1", Resource: "SUP-43",
					Args: map[string]any{"amount_cents": 30000}})
				// Same permission, same shape of request, different outcome,
				// explainable in one sentence: the contractors group carries a
				// restriction rather than a permission.
				rec.Equal("alice is allowed outright", alice.State, contract.StateAllow)
				expectDecision(rec, bob, expectation{
					Authorization: contract.AuthzPermit, State: contract.StateChallenge, Reason: contract.ReasonApprovalRequired,
					Permissions: []string{"G1"}, Requirements: []string{"C4", "C8"},
					Obligations: []string{"approval_challenge", "quota_reservation"},
					Approval:    []string{"1 of staff-managers"},
				})
			},
		},
		{
			ID: "EX-05", Title: "A satisfied exception collapses a constraint", Family: "B Constraints", Kind: KindDecision,
			Produces: []string{"CHALLENGE"},
			Run: func(t *testing.T, rec *Recorder) {
				w := defaultWorld(t)
				d := decide(t, w, Scenario{Principal: "dana", Action: "T2", Args: map[string]any{"segment": "all"}})
				// The exception clause collapses C2 to non-applicable, which is
				// the same code path as C2 not existing. "Exception granted"
				// and "rule does not apply here" are not special cases of each
				// other; they are the same case.
				expectDecision(rec, d, expectation{
					Authorization: contract.AuthzPermit, State: contract.StateChallenge, Reason: contract.ReasonApprovalRequired,
					Permissions: []string{"G3"}, Requirements: []string{"C3", "C5", "C6"},
					Obligations: []string{"approval_challenge", "field_mask@response.phone[keep=last4]",
						"field_redact@response.dob", "field_redact@response.ssn"},
					Approval: []string{"2 of security-leads"},
				})
				rec.True("the personal-data egress constraint did not bind", !contains(d.Determining.MatchedConstraints, "C2"))
			},
		},
		{
			ID: "EX-06", Title: "Two independent reasons to deny", Family: "B Constraints", Kind: KindDecision,
			Produces: []string{"DENY"},
			Run: func(t *testing.T, rec *Recorder) {
				w := defaultWorld(t)
				d := decide(t, w, Scenario{Principal: "alice", Action: "T2", Args: map[string]any{"segment": "all"}})
				expectDecision(rec, d, expectation{
					Authorization: contract.AuthzDeny, State: contract.StateDeny,
					Reason: contract.ReasonExplicitConstraint, Constraints: []string{"C2"},
				})
				// The trace must report BOTH reasons. Reporting only the
				// binding constraint sends the requester to fix half the
				// problem and come back.
				rec.True("the trace records that no permission matched either",
					anyContains(d.Trace.Warnings, "no permission matched"))
			},
		},
		{
			ID: "EX-07", Title: "A conjunctive selector exceeds the sum of its parts", Family: "B Constraints", Kind: KindDecision,
			Produces: []string{"CHALLENGE"},
			Run: func(t *testing.T, rec *Recorder) {
				// Two single-tag approval requirements plus the conjunctive
				// one. Under the source's collapsing lattice the meet of two
				// quorum-one clauses stayed at quorum one, so the two-approver
				// requirement was only reachable through the conjunctive
				// selector. Under ADR-065 the clauses do not collapse at all,
				// so all three survive as a conjunction, and the conjunctive
				// SELECTOR is still what makes the two-approver clause apply to
				// exactly the pair of tags rather than to either tag alone.
				doc := systemDocWith(
					pdp.Policy{
						ID: "Ca", Authority: contract.AuthorityRequirement, Root: pdp.RootSystem, Mandatory: true,
						Scope: pdp.Scope{Organization: true}, Actions: pdp.ActionSelector{RequiredTags: []string{"irreversible"}},
						Where: pdp.True(), Obligations: []contract.Obligation{approvalObligation("Ca", 1, "support-leads")},
					},
					pdp.Policy{
						ID: "Cb", Authority: contract.AuthorityRequirement, Root: pdp.RootSystem, Mandatory: true,
						Scope: pdp.Scope{Organization: true}, Actions: pdp.ActionSelector{RequiredTags: []string{"pii_egress"}},
						Where: pdp.True(), Obligations: []contract.Obligation{approvalObligation("Cb", 1, "legal-leads")},
					},
				)
				w := newWorld(t, WithSystemDocument(doc))
				d := decide(t, w, Scenario{Principal: "dana", Action: "T2", Args: map[string]any{"segment": "all"}})
				rec.Produced(string(d.State))
				rec.EqualStrings("all three approval clauses survive", ApprovalKeys(d),
					[]string{"1 of legal-leads", "1 of support-leads", "2 of security-leads"})
				rec.True("the two-approver clause kept its quorum",
					contains(ApprovalKeys(d), "2 of security-leads"))
				// A single-tag action must NOT pick up the conjunctive clause.
				single := decide(t, w, Scenario{Principal: "alice", Action: "T1", Resource: "SUP-42",
					Args: map[string]any{"amount_cents": 30000}})
				rec.True("the conjunctive requirement does not reach a single-tag action",
					!contains(single.Determining.MatchedRequirement, "C3"))
			},
		},

		// ---------------------------------------------------------------
		// C. Approval composition
		// ---------------------------------------------------------------
		{
			ID: "EX-08", Title: "Compound approval is a conjunction, not an intersection", Family: "C Approval", Kind: KindDecision,
			Produces: []string{"CHALLENGE"},
			Run: func(t *testing.T, rec *Recorder) {
				w := defaultWorld(t)
				d := decide(t, w, Scenario{Principal: "frank", Action: "T2", Args: map[string]any{"segment": "all"}})
				// The source reduced two clauses to one over the INTERSECTION
				// of their pools with the maximum quorum. That reduction is
				// unsound: the conjunction of "2 of {A,B}" and "2 of {B,C}" is
				// satisfiable by A, B and C, while "2 of intersection" is not.
				expectDecision(rec, d, expectation{
					Authorization: contract.AuthzPermit, State: contract.StateChallenge, Reason: contract.ReasonApprovalRequired,
					Permissions: []string{"G3"}, Requirements: []string{"C3", "C4", "C5", "C6"},
					Obligations: []string{"approval_challenge", "approval_challenge",
						"field_mask@response.phone[keep=last4]", "field_redact@response.dob", "field_redact@response.ssn"},
					Approval: []string{"1 of staff-managers", "2 of security-leads"},
				})
			},
		},
		{
			ID: "EX-09", Title: "Disjoint pools no longer collapse to a denial", Family: "C Approval", Kind: KindDecision,
			Produces: []string{"CHALLENGE"},
			Run: func(t *testing.T, rec *Recorder) {
				w := defaultWorld(t)
				d := decide(t, w, Scenario{Principal: "frank", Action: "T2", Args: map[string]any{"segment": "all"}})
				// security-leads and staff-managers are disjoint SETS OF
				// GROUPS. Under the source algebra their meet was the empty
				// pool and the request denied; under ADR-065 both clauses stand
				// and each is independently satisfiable, so the request
				// challenges instead of denying for a reason that was an
				// artifact of the algebra.
				rec.Produced(string(d.State))
				rec.Equal("the request challenges rather than denying", d.State, contract.StateChallenge)
				rec.Equal("two clauses survive", len(d.Approval.AllOf), 2)
				// Each clause carries EXACTLY the group its policy declared.
				// Asserting only that no pool is empty would pass on an
				// intersection that happened to be non-empty, which is the
				// collapse this case exists to rule out, so the pools are
				// compared by name.
				rec.EqualStrings("each clause keeps its own declared pool", ApprovalKeys(d),
					[]string{"1 of staff-managers", "2 of security-leads"})
				var pools []string
				for _, c := range d.Approval.AllOf {
					rec.Equal("the clause names one group, not an intersection of two", len(c.Eligible), 1)
					pools = append(pools, c.Eligible[0].Local)
				}
				sort.Strings(pools)
				rec.EqualStrings("and the two pools are the two the policies named",
					pools, []string{"security-leads", "staff-managers"})
			},
		},
		{
			ID: "EX-10", Title: "A pool smaller than the quorum is not silently downgraded", Family: "C Approval", Kind: KindDecision,
			Produces: []string{"CHALLENGE"},
			Run: func(t *testing.T, rec *Recorder) {
				w := defaultWorld(t)
				d := decide(t, w, Scenario{Principal: "frank", Action: "T2", Args: map[string]any{"segment": "all"}})
				var twoOf *contract.ApprovalClause
				for i := range d.Approval.AllOf {
					if d.Approval.AllOf[i].Quorum == 2 {
						twoOf = &d.Approval.AllOf[i]
					}
				}
				if twoOf == nil {
					rec.Fatalf("expected a quorum-two clause, got %v", ApprovalKeys(d))
				}
				// Neither the quorum nor the pool is adjusted by the presence
				// of another clause. The source's meet lowered the pool to an
				// intersection while raising the quorum to the maximum, which
				// is how a satisfiable pair of requirements became unsatisfiable.
				rec.Produced(string(d.State))
				rec.Equal("the quorum is unchanged", twoOf.Quorum, 2)
				rec.Equal("the pool is exactly the declared group", len(twoOf.Eligible), 1)
				rec.Equal("the pool is security-leads", twoOf.Eligible[0].Local, "security-leads")
			},
		},
		{
			ID: "EX-11", Title: "Separation of duties is carried on the requirement", Family: "C Approval", Kind: KindDecision,
			Produces: []string{"CHALLENGE"},
			Run: func(t *testing.T, rec *Recorder) {
				w := defaultWorld(t)
				// mia is a member of security-leads, which is the pool for the
				// clause her own request produces.
				d := decide(t, w, Scenario{Principal: "mia", Action: "T2", Args: map[string]any{"segment": "all"}})
				rec.Produced(string(d.State))
				rec.Equal("the request challenges", d.State, contract.StateChallenge)
				rec.True("separation of duties is required", d.Approval.SeparationOfDuties)
				// The pool is NOT pre-shrunk by the requester's membership.
				// Eligibility is a directory fact resolved when an approval is
				// offered and again immediately before execution; shrinking it
				// at decision time would bake a membership snapshot into the
				// challenge.
				rec.True("the eligible pool is not pre-filtered by the requester",
					contains(ApprovalKeys(d), "2 of security-leads"))
			},
		},

		// ---------------------------------------------------------------
		// D. Group closure
		// ---------------------------------------------------------------
		{
			ID: "EX-12", Title: "An inherited constraint carries a witness", Family: "D Closure", Kind: KindDecision,
			Produces: []string{"CHALLENGE"},
			Run: func(t *testing.T, rec *Recorder) {
				w := defaultWorld(t)
				d := decide(t, w, Scenario{Principal: "bob", Action: "T1", Resource: "SUP-43",
					Args: map[string]any{"amount_cents": 30000}})
				rec.Produced(string(d.State))
				operator, err := d.Trace.Project(contract.AudienceOperator)
				if err != nil {
					rec.Fatalf("projecting the operator trace: %v", err)
				}
				// bob is not a direct member of the contractors umbrella group.
				// Depth plays no part in the decision, only in the explanation,
				// and without a witness a denial from a group the requester has
				// never heard of is unexplainable.
				found := false
				for _, wit := range operator.Witnesses {
					if strings.HasSuffix(wit.Subject, ":all-contractors") {
						found = true
						rec.Equal("the witness names its source class", wit.SourceClass, contract.ProvDirectory)
					}
				}
				rec.True("the operator trace names the inherited group", found)
			},
		},
		{
			ID: "EX-13", Title: "A cyclic directory terminates correctly", Family: "D Closure", Kind: KindDecision,
			Produces: []string{"ALLOW"},
			Run: func(t *testing.T, rec *Recorder) {
				w := defaultWorld(t)
				base := decide(t, w, Scenario{Principal: "alice", Action: "T1", Resource: "SUP-42",
					Args: map[string]any{"amount_cents": 30000}})
				// A cycle in the directory graph is a correctness non-issue:
				// the transitive closure of a cyclic digraph is the reachable
				// set, and breadth-first search with a visited set computes it.
				cyclic := decide(t, w, Scenario{Principal: "alice", Action: "T1", Resource: "SUP-42",
					Args:              map[string]any{"amount_cents": 30000},
					ExtraDirectGroups: []string{"cycle-x"},
					ExtraGroupEdges: map[string][]string{
						"cycle-x": {"cycle-y"}, "cycle-y": {"cycle-z"}, "cycle-z": {"cycle-x"},
					}})
				rec.Produced(string(cyclic.State))
				rec.Equal("the decision is unchanged by the cycle", cyclic.Authorization, base.Authorization)
				rec.Equal("the operational state is unchanged", cyclic.State, base.State)
				rec.EqualStrings("the same permission matched",
					cyclic.Determining.MatchedPermissions, base.Determining.MatchedPermissions)
			},
		},
		{
			ID: "EX-14", Title: "A truncated closure never evaluates partially", Family: "D Closure", Kind: KindDecision,
			Produces: []string{"ERROR", "DENY"},
			Run: func(t *testing.T, rec *Recorder) {
				w := defaultWorld(t)
				truncated := map[string]*contract.Attribute{
					PathPrincipalGroups: UnknownAttr(PathPrincipalGroups, contract.ReasonClosureTruncated),
				}
				spend := decide(t, w, Scenario{Principal: "alice", Action: "T1", Resource: "SUP-42",
					Args: map[string]any{"amount_cents": 30000}, Overrides: truncated})
				// A truncated closure may be missing the very group a policy is
				// scoped to, so no group-scoped policy can be evaluated. Every
				// such policy is UNKNOWN rather than skipped.
				rec.Produced(string(spend.State))
				rec.Equal("a truncated closure is indeterminate, not a denial", spend.Authorization, contract.AuthzIndeterminate)
				rec.Equal("the state is an error rather than a policy denial", spend.State, contract.StateError)
				rec.True("the unknown names the closure as its cause",
					anyContains(unknownKeys(spend), string(contract.ReasonClosureTruncated)))

				// The source resolved this through a per-tool on_error posture
				// whose value could be Permit. ADR-065 removes that option, so
				// the read-only tool does not become a permit. It resolves to
				// NotApplicable instead, and only because the Kleene
				// short-circuit proves that no group-scoped policy could have
				// applied to this action at all: the action selector is
				// determinately false, so the unknown scope cannot matter.
				read := decide(t, w, Scenario{Principal: "alice", Action: "T3",
					Args: map[string]any{"query": "invoices"}, Overrides: truncated})
				rec.Produced(string(read.State))
				rec.Equal("the read-only action does not become a permit", read.State, contract.StateDeny)
				rec.Equal("and it resolves rather than erroring", read.Authorization, contract.AuthzNotApplicable)
			},
		},

		// ---------------------------------------------------------------
		// E. Indeterminacy
		// ---------------------------------------------------------------
		{
			ID: "EX-15", Title: "An unresolvable permission cannot grant", Family: "E Indeterminacy", Kind: KindDecision,
			Produces: []string{"ERROR"},
			Run: func(t *testing.T, rec *Recorder) {
				w := defaultWorld(t)
				d := decide(t, w, Scenario{Principal: "alice", Action: "T1", Resource: "SUP-42",
					Args: map[string]any{"amount_cents": 30000},
					Overrides: map[string]*contract.Attribute{
						PathResourceOwner: UnknownAttr(PathResourceOwner, contract.ReasonResolutionFailed),
					}})
				// The source SKIPPED an unevaluable permission and denied,
				// because routing it through a per-tool on_error posture whose
				// value could be Permit would let an outage increase access.
				// ADR-065 removes that posture, so an unresolvable permission
				// can be reported honestly as indeterminate without any risk of
				// widening: an unknown permission still cannot grant.
				expectDecision(rec, d, expectation{
					Authorization: contract.AuthzIndeterminate, State: contract.StateError,
					Reason: contract.ReasonUnknownPermission,
				})
				rec.EqualStrings("the unknown names the permission and its cause",
					unknownKeys(d), []string{"G1:resolution_failed"})
			},
		},
		{
			ID: "EX-16", Title: "Kleene short-circuit removes spurious indeterminacy", Family: "E Indeterminacy", Kind: KindDecision,
			Produces: []string{"DENY"},
			Run: func(t *testing.T, rec *Recorder) {
				w := defaultWorld(t)
				d := decide(t, w, Scenario{Principal: "alice", Action: "T1", Resource: "SUP-42",
					Args: map[string]any{"amount_cents": 900000},
					Overrides: map[string]*contract.Attribute{
						PathResourceOwner: UnknownAttr(PathResourceOwner, contract.ReasonResolutionFailed),
					}})
				// Identical outage to EX-15, different bookkeeping. A condition
				// with a known-false conjunct is DETERMINATELY false even when
				// another term is unavailable, so the permission is a clean
				// non-match rather than an unknown.
				expectDecision(rec, d, expectation{
					Authorization: contract.AuthzNotApplicable, State: contract.StateDeny,
					Reason: contract.ReasonNoMatchingPermission, Unknown: []string{},
				})
			},
		},
		{
			ID: "EX-17", Title: "An unresolvable constraint is indeterminate", Family: "E Indeterminacy", Kind: KindDecision,
			Produces: []string{"ERROR"},
			Run: func(t *testing.T, rec *Recorder) {
				w := defaultWorld(t)
				d := decide(t, w, Scenario{Principal: "carol", Action: "T1", Resource: "SUP-99",
					Args: map[string]any{"amount_cents": 3000000},
					Overrides: map[string]*contract.Attribute{
						PathResourceRisk: UnknownAttr(PathResourceRisk, contract.ReasonResolutionFailed),
					}})
				// A constraint bounds every permission, so an unknown
				// constraint cannot be skipped. Treating it as "did not apply"
				// raises the roof, which is a silent fail-open rather than a
				// missing grant.
				expectDecision(rec, d, expectation{
					Authorization: contract.AuthzIndeterminate, State: contract.StateError,
					Reason: contract.ReasonUnknownConstraint, Unknown: []string{"C10:resolution_failed"},
				})
			},
		},
		{
			ID: "EX-18", Title: "Constraint uncertainty outranks permission coverage", Family: "E Indeterminacy", Kind: KindDecision,
			Produces: []string{"ERROR"},
			Run: func(t *testing.T, rec *Recorder) {
				w := defaultWorld(t)
				d := decide(t, w, Scenario{Principal: "alice", Action: "T1", Resource: "SUP-42",
					Args: map[string]any{"amount_cents": 3000000},
					Overrides: map[string]*contract.Attribute{
						PathResourceRisk: UnknownAttr(PathResourceRisk, contract.ReasonResolutionFailed),
					}})
				// The source collapsed this to a denial by computing both
				// branches of the unknown constraint and noticing they agreed.
				// ADR-065 does not reproduce that collapse: the combining rule
				// tests constraint uncertainty BEFORE permission coverage, so
				// the outcome does not depend on the state of unrelated
				// policies and each policy's contribution stays locally
				// checkable.
				expectDecision(rec, d, expectation{
					Authorization: contract.AuthzIndeterminate, State: contract.StateError,
					Reason: contract.ReasonUnknownConstraint, Unknown: []string{"C10:resolution_failed"},
				})
			},
		},

		// ---------------------------------------------------------------
		// F. Obligations
		// ---------------------------------------------------------------
		{
			ID: "EX-19", Title: "Obligations union across requirements", Family: "F Obligations", Kind: KindDecision,
			Produces: []string{"ALLOW"},
			Run: func(t *testing.T, rec *Recorder) {
				w := defaultWorld(t)
				d := decide(t, w, Scenario{Principal: "dana", Action: "T4", Args: map[string]any{"contact_id": "c1"}})
				expectDecision(rec, d, expectation{
					Authorization: contract.AuthzPermit, State: contract.StateAllow, Reason: contract.ReasonPermitted,
					Permissions: []string{"G4"}, Requirements: []string{"C5", "C6"},
					Obligations: []string{"field_mask@response.phone[keep=last4]",
						"field_redact@response.dob", "field_redact@response.ssn"},
				})
			},
		},
		{
			ID: "EX-20", Title: "Incomparable transforms on one leaf deny", Family: "F Obligations", Kind: KindDecision,
			Produces: []string{"DENY"},
			Run: func(t *testing.T, rec *Recorder) {
				doc := systemDocWith(pdp.Policy{
					ID: "C7", Authority: contract.AuthorityRequirement, Root: pdp.RootSystem, Mandatory: true,
					Scope: pdp.Scope{Organization: true}, Actions: pdp.ActionSelector{RequiredTags: []string{"pii"}},
					Where: pdp.True(),
					Obligations: []contract.Obligation{{
						Type: contract.ObFieldMask, Target: "response.phone",
						Params: map[string]string{"keep": "first6"}, SourcePolicy: "C7", SchemaVersion: 1,
					}},
				})
				w := newWorld(t, WithSystemDocument(doc))
				d := decide(t, w, Scenario{Principal: "dana", Action: "T4", Args: map[string]any{"contact_id": "c1"}})
				// Two transforms of equal disclosure rank with different
				// parameters are incomparable. Silently picking one would
				// disclose either more or less than an author intended, and
				// nobody would know which.
				rec.Produced(string(d.State))
				rec.Equal("the decision denies", d.Authorization, contract.AuthzDeny)
				rec.Equal("the reason names the conflict", d.Reason, contract.ReasonObligationConflict)
				rec.True("the explanation names the leaf", strings.Contains(d.Trace.Remediation, "response.phone"))
				// The source made this Indeterminate and routed it through a
				// per-tool on_error posture. ADR-065 denies outright, because a
				// conflicting mandatory obligation is a decision the policy set
				// cannot express, not a dependency that failed.
				rec.Equal("the state is a denial, not an error", d.State, contract.StateDeny)
			},
		},
		{
			ID: "EX-21", Title: "Per-leaf resolution is correct in both directions", Family: "F Obligations", Kind: KindDecision,
			Produces: []string{"ALLOW"},
			Run: func(t *testing.T, rec *Recorder) {
				doc := systemDocWith(pdp.Policy{
					ID: "C11", Authority: contract.AuthorityRequirement, Root: pdp.RootSystem, Mandatory: true,
					Scope: pdp.Scope{Organization: true}, Actions: pdp.ActionSelector{RequiredTags: []string{"pii"}},
					Where: pdp.True(),
					Obligations: []contract.Obligation{{
						Type: contract.ObFieldAnnotate, Target: "response",
						SourcePolicy: "C11", SchemaVersion: 1,
					}},
				})
				w := newWorld(t, WithSystemDocument(doc))
				d := decide(t, w, Scenario{Principal: "dana", Action: "T4", Args: map[string]any{"contact_id": "c1"}})
				// A broad low-impact transform never suppresses a narrow
				// high-impact one, and the mirror case must hold too: resolving
				// per leaf by least-disclosing is correct in both directions,
				// where a per-policy "most specific target wins" rule gets the
				// mirror case backwards and fails open.
				rec.Produced(string(d.State))
				rec.EqualStrings("each leaf takes its least disclosing transform", ObligationKeys(d), []string{
					"field_annotate@response.email", "field_annotate@response.name",
					"field_mask@response.phone[keep=last4]",
					"field_redact@response.dob", "field_redact@response.ssn",
				})
			},
		},
		{
			ID: "EX-22", Title: "An unsupported mandatory obligation denies", Family: "F Obligations", Kind: KindDecision,
			Produces: []string{"DENY"},
			Run: func(t *testing.T, rec *Recorder) {
				doc := systemDocWith(pdp.Policy{
					ID: "C14", Authority: contract.AuthorityRequirement, Root: pdp.RootSystem, Mandatory: true,
					Scope: pdp.Scope{Organization: true}, Actions: pdp.ActionSelector{RequiredTags: []string{"pii"}},
					Where: pdp.True(),
					Obligations: []contract.Obligation{{
						Type: contract.ObFieldTokenize, Target: "response.email",
						SourcePolicy: "C14", SchemaVersion: 1,
					}},
				})
				w := newWorld(t, WithSystemDocument(doc))
				d := decide(t, w, Scenario{Principal: "dana", Action: "T4", Args: map[string]any{"contact_id": "c1"}})
				// A rolling deploy that introduces a new transform must not
				// fail open on the enforcement points that have not caught up.
				rec.Produced(string(d.State))
				rec.Equal("the decision denies", d.Authorization, contract.AuthzDeny)
				rec.Equal("the reason names the unsupported obligation", d.Reason, contract.ReasonUnsupportedObligation)
				rec.True("the explanation names the transform",
					strings.Contains(d.Trace.Remediation, string(contract.ObFieldTokenize)))
			},
		},

		// ---------------------------------------------------------------
		// G. Budgets and reservation
		// ---------------------------------------------------------------
		{
			ID: "EX-23", Title: "Reserve then commit", Family: "G Reservation", Kind: KindReservation,
			Produces: []string{"ALLOW"},
			Run: func(t *testing.T, rec *Recorder) {
				w := defaultWorld(t)
				c := NewCoordinator()
				s := Scenario{Principal: "alice", Action: "T1", Resource: "SUP-42",
					Args: map[string]any{"amount_cents": 30000}}
				req, err := w.Request(s)
				if err != nil {
					rec.Fatalf("building the request: %v", err)
				}
				d := decide(t, w, s)
				out, err := c.AdmitReservations(d, req, Now)
				if err != nil {
					rec.Fatalf("reserving: %v", err)
				}
				rec.Produced(string(out.Decision.State))
				rec.Equal("the decision still permits", out.Decision.Authorization, contract.AuthzPermit)
				rec.Equal("exactly one reservation is held", len(out.Held), 1)
				key := ReservationKey(reservationObligation(t, d), req)
				rec.Equal("the held amount is visible to a later check", c.Held(key, Now), int64(30000))
				if err := c.Commit(out.Held[0], 0); err != nil {
					rec.Fatalf("committing: %v", err)
				}
				rec.Equal("the committed amount persists", c.Held(key, Now), int64(30000))
			},
		},
		{
			ID: "EX-24", Title: "A failed execution releases its hold", Family: "G Reservation", Kind: KindReservation,
			Produces: []string{"ALLOW"},
			Run: func(t *testing.T, rec *Recorder) {
				w := defaultWorld(t)
				c := NewCoordinator()
				s := Scenario{Principal: "alice", Action: "T1", Resource: "SUP-42",
					Args: map[string]any{"amount_cents": 30000}}
				req, err := w.Request(s)
				if err != nil {
					rec.Fatalf("building the request: %v", err)
				}
				d := decide(t, w, s)
				out, err := c.AdmitReservations(d, req, Now)
				if err != nil {
					rec.Fatalf("reserving: %v", err)
				}
				key := ReservationKey(reservationObligation(t, d), req)
				if err := c.Release(out.Held[0]); err != nil {
					rec.Fatalf("releasing: %v", err)
				}
				// The decision was correct and stays correct; only the
				// reservation unwinds. A phantom hold is invisible until a
				// legitimate request is refused days later.
				rec.Produced(string(out.Decision.State))
				rec.Equal("the counter returns to zero", c.Held(key, Now), int64(0))
				rec.True("a released reservation cannot be committed", c.Commit(out.Held[0], 1) != nil)
			},
		},
		{
			ID: "EX-25", Title: "Concurrent challenges hold the budget", Family: "G Reservation", Kind: KindReservation,
			Produces: []string{"CHALLENGE", "DENY"},
			Run: func(t *testing.T, rec *Recorder) {
				w := defaultWorld(t)
				c := NewCoordinator()
				build := func(id string) (*contract.Decision, *contract.Request) {
					s := Scenario{Principal: "carol", Action: "T1", Resource: "SUP-99",
						Args: map[string]any{"amount_cents": 3000000}, RequestID: id}
					req, err := w.Request(s)
					if err != nil {
						rec.Fatalf("building the request: %v", err)
					}
					return decide(t, w, s), req
				}
				d1, r1 := build("req_first")
				d2, r2 := build("req_second")
				rec.Produced(string(d1.State))
				rec.Equal("the first request challenges", d1.State, contract.StateChallenge)
				out1, err := c.AdmitReservations(d1, r1, Now)
				if err != nil {
					rec.Fatalf("reserving the first: %v", err)
				}
				rec.Equal("the first holds its amount", len(out1.Held), 1)
				// Reserving at DECISION time rather than at approval time is
				// the whole point. If the hold waited for approval, both
				// requests would pass the check, both would be approved, and
				// the cap would be exceeded by the sum of the two.
				out2, err := c.AdmitReservations(d2, r2, Now)
				if err != nil {
					rec.Fatalf("reserving the second: %v", err)
				}
				rec.Produced(string(out2.Decision.State))
				rec.Equal("the second is denied", out2.Decision.Authorization, contract.AuthzDeny)
				rec.Equal("the reason names the budget", out2.Decision.Reason, contract.ReasonBudgetExhausted)
				rec.True("the trace says the denial happened at reservation, not at a policy",
					anyContains(out2.Decision.Trace.Warnings, "denied at reservation"))
			},
		},
		{
			ID: "EX-26", Title: "An expired challenge releases its hold", Family: "G Reservation", Kind: KindReservation,
			Produces: []string{"DENY"},
			Run: func(t *testing.T, rec *Recorder) {
				w := defaultWorld(t)
				c := NewCoordinator()
				s := Scenario{Principal: "carol", Action: "T1", Resource: "SUP-99",
					Args: map[string]any{"amount_cents": 3000000}}
				req, err := w.Request(s)
				if err != nil {
					rec.Fatalf("building the request: %v", err)
				}
				d := decide(t, w, s)
				out, err := c.AdmitReservations(d, req, Now)
				if err != nil {
					rec.Fatalf("reserving: %v", err)
				}
				key := ReservationKey(reservationObligation(t, d), req)
				rec.Equal("the hold spans the approval window", c.Held(key, Now), int64(3000000))
				// Timeout is always deny, and the hold must not outlive the
				// challenge: without the reaper an unanswered approval consumes
				// budget permanently.
				later := d.Approval.ExpiresAt.Add(10 * time.Minute)
				timedOut, err := c.OnApprovalTimeout(d, out.Held, later)
				if err != nil {
					rec.Fatalf("timing out: %v", err)
				}
				rec.Produced(string(timedOut.State))
				// Timeout is always deny. The source proposal made this a
				// configurable on_timeout with a permitting option; ADR-065
				// prohibits it outright, because a non-response never proves
				// approval and permitting afterwards would additionally admit
				// execution against a hold that has already been released.
				rec.Equal("an expired challenge denies", timedOut.Authorization, contract.AuthzDeny)
				rec.Equal("and says why", timedOut.Reason, contract.ReasonApprovalExpired)
				rec.True("the outstanding approval is gone", timedOut.Approval == nil)
				rec.Equal("the counter is back to zero", c.Held(key, later), int64(0))
				rec.Equal("and the reaper has nothing left to release", c.Reap(later), 0)
			},
		},

		// ---------------------------------------------------------------
		// H. Delegation
		// ---------------------------------------------------------------
		{
			ID: "EX-27", Title: "An agent cannot lend authority to its principal", Family: "H Delegation", Kind: KindDecision,
			Produces: []string{"DENY"},
			Run: func(t *testing.T, rec *Recorder) {
				w := defaultWorld(t)
				alone := decide(t, w, Scenario{Principal: "agent-A", Action: "T1",
					Args: map[string]any{"amount_cents": 3000000}})
				rec.Equal("the agent acting alone is permitted", alone.Authorization, contract.AuthzPermit)
				chained := decide(t, w, Scenario{Principal: "alice", Chain: []string{"alice", "agent-A"},
					Action: "T1", Resource: "SUP-42", Args: map[string]any{"amount_cents": 3000000}})
				// Union across the chain would grant the agent's reach to
				// whoever invoked it, and every policy involved would still
				// look correct in isolation. The chain MEETS.
				rec.Produced(string(chained.State))
				rec.Equal("the chain does not inherit the agent's reach", chained.State, contract.StateDeny)
				rec.Equal("and it is the principal's lack of coverage that binds",
					chained.Reason, contract.ReasonNoMatchingPermission)
			},
		},
		{
			ID: "EX-28", Title: "Delegation depth is checked before any policy", Family: "H Delegation", Kind: KindDecision,
			Produces: []string{"DENY"},
			Run: func(t *testing.T, rec *Recorder) {
				w := defaultWorld(t)
				d := decide(t, w, Scenario{Principal: "alice",
					Chain:  []string{"alice", "agent-A", "sub-B", "sub-C"},
					Action: "T1", Resource: "SUP-42", Args: map[string]any{"amount_cents": 30000}})
				rec.Produced(string(d.State))
				rec.Equal("the request is denied", d.Authorization, contract.AuthzDeny)
				rec.Equal("the reason names the depth", d.Reason, contract.ReasonDelegationDepth)
				// Depth is a topology constraint, not a permission question, so
				// it is answered before any policy is loaded and no policy
				// appears in the determining set.
				rec.Equal("no policy was consulted", len(d.Determining.MatchedPermissions)+
					len(d.Determining.MatchedConstraints)+len(d.Determining.MatchedRequirement), 0)
			},
		},

		// ---------------------------------------------------------------
		// I. Inspection
		// ---------------------------------------------------------------
		{
			ID: "EX-29", Title: "Accumulated evidence crosses a gating threshold", Family: "I Inspection", Kind: KindDecision,
			Produces: []string{"CHALLENGE"},
			Run: func(t *testing.T, rec *Recorder) {
				w := defaultWorld(t)
				d := decide(t, w, Scenario{Principal: "alice", Action: "T1", Resource: "SUP-42",
					Args: map[string]any{"amount_cents": 50000}, RiskScore: 75,
					Overrides: map[string]*contract.Attribute{
						PathStateAnomaly:  KnownAttr(PathStateAnomaly, 30000),
						PathStateVelocity: KnownAttr(PathStateVelocity, 6),
					}})
				// Neither signal alone is worth acting on. Weighted
				// accumulation lets weak evidence combine without making every
				// heuristic independently trigger-happy, and the policy that
				// ACTS on the accumulated score is an ordinary requirement.
				expectDecision(rec, d, expectation{
					Authorization: contract.AuthzPermit, State: contract.StateChallenge, Reason: contract.ReasonApprovalRequired,
					Permissions: []string{"G1"}, Requirements: []string{"C8", "S1-APPROVE"},
					Inspections: []string{"D1", "D2"},
					Obligations: []string{"approval_challenge", "immutable_audit", "quota_reservation"},
					Approval:    []string{"1 of fraud-team"},
				})
			},
		},
		{
			ID: "EX-30", Title: "Inspection cannot raise a decision", Family: "I Inspection", Kind: KindDecision,
			Produces: []string{"DENY"},
			Run: func(t *testing.T, rec *Recorder) {
				w := defaultWorld(t)
				d := decide(t, w, Scenario{Principal: "alice", Action: "T2",
					Args: map[string]any{"segment": "all"}, RiskScore: 0})
				// A clean detection result is not a grant. "Nothing looked
				// wrong" and "this is authorized" are different claims, and
				// only one of them can be made by a heuristic. The authoring
				// validator refuses an inspection policy that tries to be
				// mandatory, so this is structural rather than conventional.
				rec.Produced(string(d.State))
				rec.Equal("a zero score does not rescue a denied request", d.Authorization, contract.AuthzDeny)
				rec.EqualStrings("the constraint still binds", d.Determining.MatchedConstraints, []string{"C2"})
			},
		},
		{
			ID: "EX-31", Title: "An unevaluable advisory detector does not fail the request", Family: "I Inspection", Kind: KindDecision,
			Produces: []string{"ALLOW"},
			Run: func(t *testing.T, rec *Recorder) {
				w := defaultWorld(t)
				d := decide(t, w, Scenario{Principal: "alice", Action: "T1", Resource: "SUP-42",
					Args: map[string]any{"amount_cents": 50000}, RiskScore: 40,
					Overrides: map[string]*contract.Attribute{
						PathStateAnomaly:  KnownAttr(PathStateAnomaly, 30000),
						PathStateVelocity: UnknownAttr(PathStateVelocity, contract.ReasonResolutionFailed),
					}})
				// Two things at once. An advisory control that cannot answer is
				// skipped with a warning rather than taking the gateway down,
				// and an inspection policy that DID match contributes its
				// obligations on evidence rather than on outcome: the score
				// stayed below every threshold, the verdict was unchanged, and
				// the elevated audit record is written anyway.
				expectDecision(rec, d, expectation{
					Authorization: contract.AuthzPermit, State: contract.StateAllow, Reason: contract.ReasonPermitted,
					Permissions: []string{"G1"}, Requirements: []string{"C8"}, Inspections: []string{"D1"},
					Obligations: []string{"immutable_audit", "quota_reservation"},
					Unknown:     []string{"D2:resolution_failed"},
				})
				rec.True("the skipped detector is recorded as a warning",
					anyContains(d.Trace.Warnings, "inspection policy \"D2\""))
			},
		},

		// ---------------------------------------------------------------
		// J. Binding, break-glass, admission
		// ---------------------------------------------------------------
		{
			ID: "EX-32", Title: "A decision binds the arguments it was made on", Family: "J Binding", Kind: KindBinding,
			Produces: []string{"DENY"},
			Run: func(t *testing.T, rec *Recorder) {
				w := defaultWorld(t)
				small, err := w.Request(Scenario{Principal: "alice", Action: "T1", Resource: "SUP-42",
					Args: map[string]any{"amount_cents": 30000}, RequestID: "req_bind"})
				if err != nil {
					rec.Fatalf("building the small request: %v", err)
				}
				large, err := w.Request(Scenario{Principal: "alice", Action: "T1", Resource: "SUP-42",
					Args: map[string]any{"amount_cents": 3000000}, RequestID: "req_bind"})
				if err != nil {
					rec.Fatalf("building the large request: %v", err)
				}
				a, err := small.BindingDigest()
				if err != nil {
					rec.Fatalf("binding the small request: %v", err)
				}
				b, err := large.BindingDigest()
				if err != nil {
					rec.Fatalf("binding the large request: %v", err)
				}
				// Without binding, a human approval degrades into a rubber
				// stamp on a CATEGORY of action rather than on the action
				// itself. A reviewer who approved 300 units has not approved
				// 30000.
				rec.True("a changed amount changes the binding", a != b)
				again, _ := small.BindingDigest()
				rec.Equal("the binding is stable for an unchanged request", again, a)

				// And the binding is ACTED on. A digest that differs and
				// changes nothing would be a decoration; rebinding the decision
				// against the request presented at execution is what turns the
				// difference into a refusal.
				approved := decide(t, w, Scenario{Principal: "alice", Action: "T1", Resource: "SUP-42",
					Args: map[string]any{"amount_cents": 30000}, RequestID: "req_bind"})
				rec.Equal("the small request was allowed", approved.State, contract.StateAllow)
				rebound, err := contract.Rebind(approved, a, large)
				if err != nil {
					rec.Fatalf("rebinding: %v", err)
				}
				rec.Produced(string(rebound.State))
				rec.Equal("presenting it against the larger request denies", rebound.Authorization, contract.AuthzDeny)
				rec.Equal("and names the binding", rebound.Reason, contract.ReasonBindingMismatch)
				unchanged, err := contract.Rebind(approved, a, small)
				if err != nil {
					rec.Fatalf("rebinding the unchanged request: %v", err)
				}
				rec.Equal("while the request it was made on still stands", unchanged.State, contract.StateAllow)
			},
		},
		{
			ID: "EX-33", Title: "Break-glass pierces a pierceable requirement", Family: "J Binding", Kind: KindDecision,
			Produces: []string{"ALLOW"},
			Run: func(t *testing.T, rec *Recorder) {
				w := newWorld(t, WithBreakGlass(func(p contract.ID, at time.Time) []contract.ID {
					if p == Principals["erin"].ID {
						return []contract.ID{group("oncall-sre")}
					}
					return nil
				}))
				d := decide(t, w, Scenario{Principal: "erin", Action: "T1", Resource: "SUP-42",
					Args: map[string]any{"amount_cents": 5000000}})
				// Pretending an organization will never need an emergency
				// override produces exactly one outcome: someone deletes the
				// control during an incident and nobody puts it back. Model it,
				// time-box it, and make it loud.
				rec.Produced(string(d.State))
				rec.Equal("the request is allowed outright", d.State, contract.StateAllow)
				rec.True("the pierced requirement did not apply",
					!contains(d.Determining.MatchedRequirement, "C1"))
				rec.True("an immutable audit record is mandatory",
					contains(ObligationKeys(d), "immutable_audit"))
				rec.True("a notification is mandatory",
					contains(ObligationKeys(d), "notification"))
				rec.True("the trace records the pierce", anyContains(d.Trace.Warnings, "break-glass"))
			},
		},
		{
			ID: "EX-34", Title: "Break-glass cannot pierce a non-pierceable constraint", Family: "J Binding", Kind: KindDecision,
			Produces: []string{"DENY"},
			Run: func(t *testing.T, rec *Recorder) {
				w := newWorld(t, WithBreakGlass(func(p contract.ID, at time.Time) []contract.ID {
					return []contract.ID{group("oncall-sre"), group("security-leads")}
				}))
				d := decide(t, w, Scenario{Principal: "erin", Action: "T2", Args: map[string]any{"segment": "all"}})
				// An empty pierceable list is the difference between a control
				// and a suggestion. Regulatory and contractual constraints get
				// it; operational ones generally should not.
				rec.Produced(string(d.State))
				rec.Equal("the request is denied", d.Authorization, contract.AuthzDeny)
				rec.EqualStrings("the regulatory constraint still binds", d.Determining.MatchedConstraints, []string{"C2"})
			},
		},
		{
			ID: "EX-35", Title: "Authority from untrusted input is rejected at authoring", Family: "J Binding", Kind: KindAuthoring,
			Produces: []string{"REJECTED"},
			Run: func(t *testing.T, rec *Recorder) {
				d := OrganizationDocument()
				d.Attributes = append(d.Attributes, pdp.AttributeSchema{Path: "args.ticket_owner", Type: pdp.TypeString})
				d.Policies = append(d.Policies, pdp.Policy{
					ID: "G7", Authority: contract.AuthorityPermission, Root: pdp.RootOrganization,
					Scope:   pdp.Scope{Groups: []contract.ID{group("support-tier2")}},
					Actions: pdp.ActionSelector{Actions: []contract.ID{Actions["T1"].ID}},
					Where:   pdp.AttrEq("args.ticket_owner", PathPrincipalID),
				})
				errs := d.Validate()
				// The policy reads as "allow if the requester claims they own
				// it". It would pass every test written against well-behaved
				// agents and fail against the first injected ticket body, so
				// static rejection is the only reliable catch.
				rec.Produced("REJECTED")
				rec.True("the document is rejected", len(errs) > 0)
				rec.True("the rule that fired is the authority rule", hasRule(errs, pdp.RuleAuthorityFromUntrusted))
				// The bounding form of the same comparison stays legal, because
				// bounding untrusted input is the entire point of an argument
				// limit.
				clean := OrganizationDocument()
				rec.Equal("the bounding form is accepted", len(clean.Validate()), 0)
			},
		},
		{
			ID: "EX-36", Title: "An unregistered action is refused before policy", Family: "J Binding", Kind: KindDecision,
			Produces: []string{"DENY"},
			Run: func(t *testing.T, rec *Recorder) {
				reg := Registry()
				delete(reg.Actions, Actions["T1"].ID.String())
				w := newWorld(t, WithRegistry(reg))
				d := decide(t, w, Scenario{Principal: "alice", Action: "T1", Resource: "SUP-42",
					Args: map[string]any{"amount_cents": 30000}})
				// An unregistered surface has no declared behaviour to consult,
				// and this must be distinguishable in the trace from a
				// registered action with no matching permission: the two need
				// different fixes.
				rec.Produced(string(d.State))
				rec.Equal("the request is denied", d.Authorization, contract.AuthzDeny)
				rec.Equal("the reason names the registry", d.Reason, contract.ReasonUnknownAction)
				rec.True("the reason differs from an absent permission",
					d.Reason != contract.ReasonNoMatchingPermission)
			},
		},
		{
			ID: "EX-37", Title: "A typed argument schema catches the unit bug", Family: "J Binding", Kind: KindDecision,
			Produces: []string{"DENY"},
			Run: func(t *testing.T, rec *Recorder) {
				w := defaultWorld(t)
				d := decide(t, w, Scenario{Principal: "alice", Action: "T1", Resource: "SUP-42",
					Args: map[string]any{"amount": 300}})
				// The alternative is a policy reading `amount <= 5000` against
				// a cents-denominated interface: a limit of 50 that everyone
				// believes is 5000. Binding the editor to a typed schema with
				// units makes that structural rather than a code review's job.
				rec.Produced(string(d.State))
				rec.Equal("the request is denied", d.Authorization, contract.AuthzDeny)
				rec.Equal("the reason names the schema", d.Reason, contract.ReasonSchemaViolation)
				rec.True("the detail names the unknown field", strings.Contains(d.Trace.Remediation, "amount"))
				rec.True("the detail names the missing required field",
					strings.Contains(d.Trace.Remediation, "amount_cents"))
			},
		},

		// ---------------------------------------------------------------
		// K. Resource containment
		// ---------------------------------------------------------------
		{
			ID: "EX-38", Title: "A named level is a projection, not a traversal", Family: "K Containment", Kind: KindDecision,
			Produces: []string{"ALLOW"},
			Run: func(t *testing.T, rec *Recorder) {
				w := defaultWorld(t)
				d := decide(t, w, Scenario{Principal: "alice", Action: "T5", Resource: "SUP-42",
					Args: map[string]any{"ticket_id": "SUP-42", "to_status": "done"}})
				expectDecision(rec, d, expectation{
					Authorization: contract.AuthzPermit, State: contract.StateAllow, Reason: contract.ReasonPermitted,
					Permissions: []string{"G8"},
				})
				// The mapping named the leaf; the ancestors came from the
				// resolver and never from the caller. Containment is an
				// authority fact.
				req, err := w.Request(Scenario{Principal: "alice", Action: "T5", Resource: "SUP-42",
					Args: map[string]any{"ticket_id": "SUP-42", "to_status": "done"}})
				if err != nil {
					rec.Fatalf("building the request: %v", err)
				}
				rec.Equal("the project ancestor carries resource provenance",
					req.Attributes[PathResourceProject].Source, contract.ProvResource)
			},
		},
		{
			ID: "EX-39", Title: "A requirement scoped by a projected ancestor attribute", Family: "K Containment", Kind: KindDecision,
			Produces: []string{"CHALLENGE"},
			Run: func(t *testing.T, rec *Recorder) {
				w := defaultWorld(t)
				d := decide(t, w, Scenario{Principal: "alice", Action: "T5", Resource: "LEG-7",
					Args: map[string]any{"ticket_id": "LEG-7", "to_status": "done"}})
				// Identical permission, identical action. The entire difference
				// is an attribute of a resource the principal never named,
				// which is what projection buys and what a leaf-only attribute
				// check could not express without denormalizing the
				// classification onto every ticket.
				expectDecision(rec, d, expectation{
					Authorization: contract.AuthzPermit, State: contract.StateChallenge, Reason: contract.ReasonApprovalRequired,
					Permissions: []string{"G8"}, Requirements: []string{"C13"},
					Obligations: []string{"approval_challenge"}, Approval: []string{"1 of legal-leads"},
				})
			},
		},
		{
			ID: "EX-40", Title: "A subtree constraint outranks a segment exception", Family: "K Containment", Kind: KindDecision,
			Produces: []string{"DENY"},
			Run: func(t *testing.T, rec *Recorder) {
				w := defaultWorld(t)
				d := decide(t, w, Scenario{Principal: "dana", Action: "T6", Resource: "P-900",
					Args: map[string]any{"page_id": "P-900"}})
				// Membership of legal exempts dana from the GENERIC egress rule
				// and does nothing about the LEGAL-SPACE rule. Two constraints,
				// two scoping axes, one principal-side and one resource-side.
				// An exception clause only ever relaxes the policy it lives on.
				expectDecision(rec, d, expectation{
					Authorization: contract.AuthzDeny, State: contract.StateDeny,
					Reason: contract.ReasonExplicitConstraint, Constraints: []string{"C12"},
				})
			},
		},
		{
			ID: "EX-41", Title: "A sibling subtree is unaffected", Family: "K Containment", Kind: KindDecision,
			Produces: []string{"CHALLENGE"},
			Run: func(t *testing.T, rec *Recorder) {
				w := defaultWorld(t)
				d := decide(t, w, Scenario{Principal: "dana", Action: "T6", Resource: "P-311",
					Args: map[string]any{"page_id": "P-311"}})
				// Same principal, same action, same policies as the previous
				// case. Closure membership is the only variable, which is what
				// makes the pair a regression test for scope leakage in either
				// direction.
				expectDecision(rec, d, expectation{
					Authorization: contract.AuthzPermit, State: contract.StateChallenge, Reason: contract.ReasonApprovalRequired,
					Permissions: []string{"G9"}, Requirements: []string{"C3", "C5", "C6"},
					Obligations: []string{"approval_challenge", "field_mask@response.phone[keep=last4]",
						"field_redact@response.ssn"},
					Approval: []string{"2 of security-leads"},
				})
			},
		},
		{
			ID: "EX-42", Title: "Reachability by any path is enough", Family: "K Containment", Kind: KindDecision,
			Produces: []string{"DENY"},
			Run: func(t *testing.T, rec *Recorder) {
				w := defaultWorld(t)
				d := decide(t, w, Scenario{Principal: "dana", Action: "T6", Resource: "P-500",
					Args: map[string]any{"page_id": "P-500"}})
				// A page reachable from a restricted space IS restricted, even
				// though it is also filed somewhere benign. Intersecting the
				// scopes along each path instead would let anything escape any
				// constraint simply by also being linked into an open folder.
				expectDecision(rec, d, expectation{
					Authorization: contract.AuthzDeny, State: contract.StateDeny,
					Reason: contract.ReasonExplicitConstraint, Constraints: []string{"C12"},
				})
			},
		},
		{
			ID: "EX-43", Title: "A truncated resource closure fails closed", Family: "K Containment", Kind: KindDecision,
			Produces: []string{"ERROR"},
			Run: func(t *testing.T, rec *Recorder) {
				w := defaultWorld(t)
				d := decide(t, w, Scenario{Principal: "dana", Action: "T6", Resource: "P-deep",
					Args: map[string]any{"page_id": "P-deep"},
					Overrides: map[string]*contract.Attribute{
						PathResourceClosure: UnknownAttr(PathResourceClosure, contract.ReasonClosureTruncated),
					}})
				// A partial closure may be missing the very ancestor a
				// constraint is scoped to. Never evaluate against one. Note
				// that this failure mode is structurally impossible for a
				// non-recursive resource type, which is one reason not to model
				// everything as a graph.
				expectDecision(rec, d, expectation{
					Authorization: contract.AuthzIndeterminate, State: contract.StateError,
					Reason: contract.ReasonUnknownConstraint, Unknown: []string{"C12:closure_truncated"},
				})
			},
		},
		{
			ID: "EX-44", Title: "Reparenting between decision and execution breaks the binding", Family: "K Containment", Kind: KindBinding,
			Produces: []string{"DENY"},
			Run: func(t *testing.T, rec *Recorder) {
				w := defaultWorld(t)
				before, err := w.Request(Scenario{Principal: "alice", Action: "T5", Resource: "SUP-42",
					Args: map[string]any{"ticket_id": "SUP-42", "to_status": "done"}, RequestID: "req_move"})
				if err != nil {
					rec.Fatalf("building the request: %v", err)
				}
				after, err := w.Request(Scenario{Principal: "alice", Action: "T5", Resource: "SUP-42",
					Args: map[string]any{"ticket_id": "SUP-42", "to_status": "done"}, RequestID: "req_move",
					Overrides: map[string]*contract.Attribute{
						PathResourceProject: KnownAttr(PathResourceProject, resource("Project", "LEGAL").String()),
						PathResourceClass:   KnownAttr(PathResourceClass, "restricted"),
					}})
				if err != nil {
					rec.Fatalf("building the reparented request: %v", err)
				}
				a, _ := before.BindingDigest()
				b, _ := after.BindingDigest()
				// The source needed a SECOND hash for this, because its request
				// hash covered only what the caller supplied and the ancestors
				// were materialized afterwards. ADR-065 binds the complete
				// normalized input including every resolver-materialized
				// attribute, so one binding covers both.
				rec.True("a reparented resource changes the binding", a != b)
				// And the reparented request would now decide differently,
				// which is exactly why re-validating matters.
				dec := decide(t, w, Scenario{Principal: "alice", Action: "T5", Resource: "SUP-42",
					Args: map[string]any{"ticket_id": "SUP-42", "to_status": "done"},
					Overrides: map[string]*contract.Attribute{
						PathResourceProject: KnownAttr(PathResourceProject, resource("Project", "LEGAL").String()),
						PathResourceClass:   KnownAttr(PathResourceClass, "restricted"),
					}})
				rec.Equal("the reparented request would challenge rather than allow", dec.State, contract.StateChallenge)

				// A decision made before the move, presented after it, is
				// refused rather than re-evaluated: a proof that does not match
				// its request proves nothing about that request.
				allowed := decide(t, w, Scenario{Principal: "alice", Action: "T5", Resource: "SUP-42",
					Args: map[string]any{"ticket_id": "SUP-42", "to_status": "done"}, RequestID: "req_move"})
				rec.Equal("it was allowed before the move", allowed.State, contract.StateAllow)
				rebound, err := contract.Rebind(allowed, a, after)
				if err != nil {
					rec.Fatalf("rebinding: %v", err)
				}
				rec.Produced(string(rebound.State))
				rec.Equal("presenting it after the move denies", rebound.Authorization, contract.AuthzDeny)
				rec.Equal("and names the binding", rebound.Reason, contract.ReasonBindingMismatch)
			},
		},

		// ---------------------------------------------------------------
		// L. Identity realms
		// ---------------------------------------------------------------
		{
			ID: "EX-45", Title: "An empty closure is authoritative, not an error", Family: "L Realms", Kind: KindDecision,
			Produces: []string{"CHALLENGE"},
			Run: func(t *testing.T, rec *Recorder) {
				w := defaultWorld(t)
				d := decide(t, w, Scenario{Principal: "agent-A", Action: "T1",
					Args: map[string]any{"amount_cents": 3000000}})
				// An unresolvable closure is indeterminate; an ABSENT one is a
				// fact about the realm. Collapsing the two makes every
				// cloud-identity service account permanently indeterminate.
				// Note also that organization-scoped policies still bind: an
				// empty closure removes group-scoped permissions, never the roof.
				expectDecision(rec, d, expectation{
					Authorization: contract.AuthzPermit, State: contract.StateChallenge, Reason: contract.ReasonApprovalRequired,
					Permissions: []string{"G10"}, Requirements: []string{"C1", "C8"},
					Obligations: []string{"approval_challenge", "quota_reservation"},
					Approval:    []string{"1 of support-leads"},
				})
				req, err := w.Request(Scenario{Principal: "agent-A", Action: "T1",
					Args: map[string]any{"amount_cents": 3000000}})
				if err != nil {
					rec.Fatalf("building the request: %v", err)
				}
				groups := req.Context.ActorChain[0].Attributes[PathPrincipalGroups]
				rec.Equal("the closure is KNOWN and empty, not unknown", groups.State, contract.StateKnown)
				rec.Equal("and it really is empty", len(groups.Value.([]any)), 0)
			},
		},
		{
			ID: "EX-46", Title: "An approver pool in a non-interactive realm is rejected", Family: "L Realms", Kind: KindAuthoring,
			Produces: []string{"REJECTED"},
			Run: func(t *testing.T, rec *Recorder) {
				d := SystemDocument()
				d.Policies = append(d.Policies, pdp.Policy{
					ID: "C15", Authority: contract.AuthorityRequirement, Root: pdp.RootSystem, Mandatory: true,
					Scope: pdp.Scope{Organization: true}, Actions: pdp.ActionSelector{Any: true}, Where: pdp.True(),
					Obligations: []contract.Obligation{{
						Type: contract.ObApprovalChallenge, SourcePolicy: "C15", SchemaVersion: 1,
						Params: map[string]string{
							"quorum":   "1",
							"eligible": "Group::" + RealmGCP + ":sre-automation",
						},
					}},
				})
				errs := d.Validate()
				// Service accounts land in approver groups for automation
				// reasons all the time. Without the realm check they inflate
				// the eligible count, the challenge is issued, and it parks
				// until it times out because nothing there can answer.
				// Enforcing this on the REALM keeps the evaluator out of the
				// business of deciding which subjects are people.
				rec.Produced("REJECTED")
				rec.True("the document is rejected", len(errs) > 0)
				rec.True("the rule that fired names the realm", hasRule(errs, pdp.RulePoolNotInteractive))
			},
		},
		{
			ID: "EX-47", Title: "A validly signed token from an undeclared realm is denied", Family: "L Realms", Kind: KindDecision,
			Produces: []string{"DENY"},
			Run: func(t *testing.T, rec *Recorder) {
				reg := Registry()
				delete(reg.Realms, RealmWorkspace)
				w := newWorld(t, WithRegistry(reg))
				d := decide(t, w, Scenario{Principal: "alice", Action: "T1", Resource: "SUP-42",
					Args: map[string]any{"amount_cents": 30000}})
				// Symmetric with the unregistered action: unknown surface and
				// unknown issuer are both refused before any policy loads.
				// Validly signed is not the same as declared. Omit this and the
				// principal reaches evaluation with an undefined realm, where a
				// falsy default reads as "no group graph", making an empty
				// closure look authoritative and silently skipping every
				// group-scoped constraint. A fail-open produced entirely by
				// omission.
				rec.Produced(string(d.State))
				rec.Equal("the request is denied", d.Authorization, contract.AuthzDeny)
				rec.Equal("the reason names the realm", d.Reason, contract.ReasonUnknownRealm)
				rec.True("the detail names the undeclared realm",
					strings.Contains(d.Trace.Remediation, RealmWorkspace))
			},
		},
	}
}

func reservationObligation(t *testing.T, d *contract.Decision) contract.Obligation {
	t.Helper()
	for _, o := range d.Obligations {
		if o.Type == contract.ObQuotaReservation {
			return o
		}
	}
	t.Fatalf("decision carries no quota reservation obligation: %v", ObligationKeys(d))
	return contract.Obligation{}
}

func contains(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}

func anyContains(list []string, substr string) bool {
	for _, v := range list {
		if strings.Contains(v, substr) {
			return true
		}
	}
	return false
}

func hasRule(errs []pdp.ValidationError, rule string) bool {
	for _, e := range errs {
		if e.Rule == rule {
			return true
		}
	}
	return false
}

var _ = context.Background
