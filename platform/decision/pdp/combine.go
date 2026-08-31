package pdp

import (
	"fmt"
	"sort"
	"time"

	"axonflow/platform/decision/contract"
)

// PolicyMeta is everything the combiner needs about a policy that is not its
// tri-state verdict. It is carried out of the typed document rather than
// re-derived from the compiled Rego, because the combining rule is a security
// invariant and must not be readable out of the artifact it constrains.
type PolicyMeta struct {
	ID           string
	Authority    contract.Authority
	Root         Root
	Obligations  []contract.Obligation
	Mandatory    bool
	PierceableBy []contract.ID
	Description  string
	ScopeGroups  []contract.ID
}

// MetaIndex builds the combiner's metadata index from one or more documents.
// A policy ID appearing under two roots is a construction defect: an
// organization bundle that reuses a system policy identifier would make
// "which policy denied this" ambiguous in exactly the place it matters most.
func MetaIndex(docs ...*Document) (map[string]PolicyMeta, error) {
	out := map[string]PolicyMeta{}
	for _, d := range docs {
		if d == nil {
			continue
		}
		for _, p := range d.Policies {
			if prev, dup := out[p.ID]; dup {
				return nil, fmt.Errorf("pdp: policy id %q is declared under root %q and root %q", p.ID, prev.Root, p.Root)
			}
			out[p.ID] = PolicyMeta{
				ID:           p.ID,
				Authority:    p.Authority,
				Root:         p.Root,
				Obligations:  p.Obligations,
				Mandatory:    p.Mandatory,
				PierceableBy: p.PierceableBy,
				Description:  p.Description,
				ScopeGroups:  p.Scope.Groups,
			}
		}
	}
	return out, nil
}

// CombineInput is the complete input to the combining step.
type CombineInput struct {
	Request *contract.Request
	// Outcomes are the per-policy verdicts from every evaluated bundle root.
	Outcomes []PolicyOutcome
	// Meta indexes the policies by ID.
	Meta map[string]PolicyMeta
	// PEP is the advertised enforcement profile.
	PEP *contract.PEPProfile
	// PayloadLeaves is the leaf field schema disclosure obligations expand
	// over.
	PayloadLeaves []string
	// ApprovalExpiry stamps a composed approval requirement.
	ApprovalExpiry time.Time
	// BreakGlassRoles are the roles an active, time-bound, approved break-glass
	// grant confers on this principal. Empty is the normal case.
	BreakGlassRoles []contract.ID
	// InputError, when non-nil, short-circuits to Indeterminate.
	InputError error
	// InputInvalid marks InputError as a REQUEST VALIDATION failure rather
	// than an evaluation failure. Both are Indeterminate and both fail closed,
	// but they need different fixes and therefore different reason codes: one
	// is a malformed request and the other is a dependency this evaluator
	// could not resolve.
	InputInvalid bool
	// DecisionID identifies this decision.
	DecisionID string
	// Attributes are the EFFECTIVE attributes this evaluation ran against:
	// the shared surface merged with one actor's identity attributes. It is
	// passed explicitly rather than read off the request so that a per-hop
	// evaluation cannot accidentally explain itself with another hop's
	// identity.
	Attributes contract.AttributeSet
	// Actor is the chain hop this evaluation is for.
	Actor contract.ID
}

// Combine applies the ADR-065 combining semantics.
//
// The order of the tests below is the specification, not an optimisation, and
// three of the steps are load bearing in ways that are easy to get backwards:
//
//   - A matched constraint determines Deny WITHOUT waiting for unrelated
//     unknown policies. Denying is already the safe direction, so there is
//     nothing to be gained by degrading a determinate deny into an error.
//   - An unknown constraint is checked BEFORE permission coverage. A
//     constraint bounds every permission, so an unknown constraint cannot be
//     skipped; treating it as "did not apply" raises the roof, and that is a
//     silent fail-open rather than a missing grant.
//   - An unknown permission does NOT defeat an independently matched
//     permission, because permissions compose by union. Only when no
//     permission matched does an unknown permission turn absence of coverage
//     into Indeterminate rather than NotApplicable.
func Combine(in CombineInput) (*contract.Decision, error) {
	if in.Request == nil {
		return nil, fmt.Errorf("pdp: combine requires a request")
	}
	dec := &contract.Decision{
		DecisionID: in.DecisionID,
		RequestID:  in.Request.RequestID,
		Snapshot:   in.Request.Snapshot,
	}
	snapshot := in.Request.Snapshot
	trace := &contract.Trace{Snapshot: &snapshot}

	if in.InputError != nil {
		reason := contract.ReasonEvaluationError
		if in.InputInvalid {
			reason = contract.ReasonInvalidInput
		}
		return finish(dec, trace, contract.AuthzIndeterminate, reason,
			in.InputError.Error(), nil, nil, contract.Determining{})
	}

	byAuthority := map[contract.Authority][]PolicyOutcome{}
	var determining contract.Determining
	var warnings []string
	pierced := map[string]struct{}{}

	for _, oc := range in.Outcomes {
		meta, ok := in.Meta[oc.PolicyID]
		if !ok {
			return finish(dec, trace, contract.AuthzIndeterminate, contract.ReasonEvaluationError,
				fmt.Sprintf("policy %q produced a verdict but carries no metadata", oc.PolicyID), nil, nil, determining)
		}
		if meta.Authority != oc.Authority {
			return finish(dec, trace, contract.AuthzIndeterminate, contract.ReasonEvaluationError,
				fmt.Sprintf("policy %q evaluated as authority %q but is declared %q", oc.PolicyID, oc.Authority, meta.Authority), nil, nil, determining)
		}
		// Break-glass suspends a policy that RESTRICTS. Under ADR-065 an
		// approval ceiling is a requirement rather than a constraint, so
		// limiting piercing to constraints would make an emergency override
		// unable to bypass the approval it exists to bypass.
		if (meta.Authority == contract.AuthorityConstraint || meta.Authority == contract.AuthorityRequirement) &&
			isPierced(meta, in.BreakGlassRoles) {
			pierced[oc.PolicyID] = struct{}{}
			warnings = append(warnings, fmt.Sprintf("%s %q was pierced by an active break-glass grant",
				meta.Authority, oc.PolicyID))
			continue
		}
		byAuthority[oc.Authority] = append(byAuthority[oc.Authority], oc)
	}

	// Step 1. An explicit matched constraint denies.
	if matched := firstMatched(byAuthority[contract.AuthorityConstraint]); matched != nil {
		determining.MatchedConstraints = append(determining.MatchedConstraints, matched.PolicyID)
		for _, oc := range byAuthority[contract.AuthorityConstraint] {
			if oc.Verdict == VerdictMatch && oc.PolicyID != matched.PolicyID {
				determining.MatchedConstraints = append(determining.MatchedConstraints, oc.PolicyID)
			}
			if oc.Verdict == VerdictUnknown {
				determining.Unknown = append(determining.Unknown, unknownOf(oc))
			}
		}
		// A denial reports every independent reason it has. Reporting only one
		// sends the requester to fix half the problem and come back.
		if noPermissionMatched(byAuthority[contract.AuthorityPermission]) {
			warnings = append(warnings, "no permission matched this request independently of the binding constraint")
		}
		trace.BindingPolicy = matched.PolicyID
		trace.NextBound = nextBound(byAuthority, in.Meta, matched.PolicyID)
		trace.Warnings = warnings
		return finish(dec, trace, contract.AuthzDeny, contract.ReasonExplicitConstraint,
			describe(in.Meta, matched.PolicyID), nil, nil, determining)
	}

	// Step 2. A potentially applicable constraint that could not be evaluated
	// is indeterminate.
	if unknown := firstUnknown(byAuthority[contract.AuthorityConstraint]); unknown != nil {
		for _, oc := range byAuthority[contract.AuthorityConstraint] {
			if oc.Verdict == VerdictUnknown {
				determining.Unknown = append(determining.Unknown, unknownOf(oc))
			}
		}
		trace.BindingPolicy = unknown.PolicyID
		trace.Warnings = warnings
		return finish(dec, trace, contract.AuthzIndeterminate, contract.ReasonUnknownConstraint,
			describe(in.Meta, unknown.PolicyID), nil, nil, determining)
	}

	// Step 3. Permission coverage.
	permissions := byAuthority[contract.AuthorityPermission]
	var matchedPermissions []string
	for _, oc := range permissions {
		if oc.Verdict == VerdictMatch {
			matchedPermissions = append(matchedPermissions, oc.PolicyID)
		}
		if oc.Verdict == VerdictUnknown {
			determining.Unknown = append(determining.Unknown, unknownOf(oc))
		}
	}
	if len(matchedPermissions) == 0 {
		trace.Warnings = warnings
		if unknown := firstUnknown(permissions); unknown != nil {
			return finish(dec, trace, contract.AuthzIndeterminate, contract.ReasonUnknownPermission,
				describe(in.Meta, unknown.PolicyID), nil, nil, determining)
		}
		return finish(dec, trace, contract.AuthzNotApplicable, contract.ReasonNoMatchingPermission,
			"no permission policy matched this request", nil, nil, determining)
	}
	determining.MatchedPermissions = matchedPermissions

	// Step 4. A mandatory requirement whose applicability could not be
	// established is indeterminate. An advisory requirement and an inspection
	// policy are skipped with a warning instead: a probabilistic control must
	// not be able to take the gateway down, and a control that CAN is an
	// enforcement control that should have been declared as one.
	requirements := byAuthority[contract.AuthorityRequirement]
	for _, oc := range requirements {
		if oc.Verdict != VerdictUnknown {
			continue
		}
		determining.Unknown = append(determining.Unknown, unknownOf(oc))
		if in.Meta[oc.PolicyID].Mandatory {
			trace.BindingPolicy = oc.PolicyID
			trace.Warnings = warnings
			return finish(dec, trace, contract.AuthzIndeterminate, contract.ReasonUnknownRequirement,
				describe(in.Meta, oc.PolicyID), nil, nil, determining)
		}
		warnings = append(warnings, fmt.Sprintf("advisory requirement %q was skipped because it could not be evaluated", oc.PolicyID))
	}
	for _, oc := range byAuthority[contract.AuthorityInspection] {
		if oc.Verdict == VerdictUnknown {
			determining.Unknown = append(determining.Unknown, unknownOf(oc))
			warnings = append(warnings, fmt.Sprintf("inspection policy %q was skipped because it could not be evaluated", oc.PolicyID))
		}
	}

	// Step 5. Permit, with every matched requirement and inspection
	// obligation composed.
	//
	// The two sets are composed SEPARATELY and in that order, because an
	// advisory control cannot return deny. An inspection policy attaches its
	// obligations on evidence rather than on outcome, and if one of those
	// obligations happened to be incomparable with a requirement's, composing
	// them together would let adding a DETECTOR turn a permit into a denial.
	// A probabilistic control that can take the gateway down is an enforcement
	// control that should have been declared as one.
	var required []contract.Obligation
	for _, oc := range requirements {
		if oc.Verdict != VerdictMatch {
			continue
		}
		determining.MatchedRequirement = append(determining.MatchedRequirement, oc.PolicyID)
		required = append(required, markMandatory(in.Meta[oc.PolicyID])...)
	}
	if len(pierced) > 0 {
		required = append(required, breakGlassObligations(sortedKeysOf(pierced))...)
	}
	var advisory []contract.Obligation
	for _, oc := range byAuthority[contract.AuthorityInspection] {
		if oc.Verdict != VerdictMatch {
			continue
		}
		determining.MatchedInspections = append(determining.MatchedInspections, oc.PolicyID)
		for _, o := range in.Meta[oc.PolicyID].Obligations {
			// An inspection policy cannot make an obligation mandatory,
			// whatever the authoring document says, because a mandatory
			// obligation denies when it cannot be discharged and that is the
			// deny an advisory control may not produce.
			o.Mandatory = false
			// The flag is not sufficient on its own. The approval and budget
			// families refuse or hold a request WITHOUT consulting it, so an
			// advisory control carrying one of them would deny through the
			// timeout or the counter. The authoring validator refuses such a
			// policy; this is the runtime half of the same rule, so a bundle
			// compiled before the rule existed cannot reach the combiner with
			// one.
			fam, err := contract.FamilyOf(o.Type)
			if err != nil || (fam != contract.FamilyDisclosure && fam != contract.FamilyAuditNotify) {
				warnings = append(warnings, fmt.Sprintf(
					"inspection policy %q attached a %q obligation, which an advisory control may not carry; it was dropped",
					oc.PolicyID, o.Type))
				continue
			}
			advisory = append(advisory, o)
		}
	}

	// The required and advisory sets are handed to composition TOGETHER. The
	// split that keeps an advisory control from producing a denial lives inside
	// the algebra, not here, because an invariant enforced at one call site is
	// an invariant the next call site will not have, and there are three.
	outcome := contract.ComposeObligations(contract.ComposeInput{
		Obligations:    append(append([]contract.Obligation(nil), required...), advisory...),
		Leaves:         in.PayloadLeaves,
		PEP:            in.PEP,
		ApprovalExpiry: in.ApprovalExpiry,
	})
	if outcome.Denied {
		trace.Warnings = warnings
		return finish(dec, trace, contract.AuthzDeny, outcome.Reason, outcome.Detail, nil, nil, determining)
	}
	if outcome.UnplacedDetail != "" {
		warnings = append(warnings, outcome.UnplacedDetail)
	}
	if len(outcome.DroppedAdvisory) > 0 {
		warnings = append(warnings, fmt.Sprintf(
			"advisory obligations from %v were dropped because they do not compose with the required set: %s",
			determining.MatchedInspections, outcome.DropDetail))
	}

	reason := contract.ReasonPermitted
	if outcome.Approval != nil {
		reason = contract.ReasonApprovalRequired
	}
	trace.Warnings = warnings
	trace.Witnesses = witnessesFor(in, determining)
	return finish(dec, trace, contract.AuthzPermit, reason, "", outcome.Obligations, outcome.Approval, determining)
}

func markMandatory(m PolicyMeta) []contract.Obligation {
	out := make([]contract.Obligation, 0, len(m.Obligations))
	for _, o := range m.Obligations {
		o.Mandatory = m.Mandatory
		out = append(out, o)
	}
	return out
}

// breakGlassObligations are attached unconditionally whenever a constraint was
// pierced. Break-glass without a loud, durable record is indistinguishable from
// the constraint having been deleted during an incident and never restored,
// which is the outcome modelling break-glass exists to avoid.
func breakGlassObligations(pierced []string) []contract.Obligation {
	return []contract.Obligation{
		{
			Type:          contract.ObImmutableAudit,
			Params:        map[string]string{"level": "high", "channel": "break_glass", "delivery": string(contract.DeliveryDurable)},
			Mandatory:     true,
			SourcePolicy:  "break-glass:" + joinIDs(pierced),
			SchemaVersion: 1,
		},
		{
			Type:          contract.ObNotification,
			Params:        map[string]string{"level": "high", "channel": "security-oncall", "delivery": string(contract.DeliveryAtLeastOnce)},
			Mandatory:     true,
			SourcePolicy:  "break-glass:" + joinIDs(pierced),
			SchemaVersion: 1,
		},
	}
}

// isPierced reports whether an active break-glass grant suspends a constraint.
// A constraint with no PierceableBy list is unbreakable by construction, which
// is what a regulatory or contractual constraint declares, and is the
// difference between a control and a suggestion.
func isPierced(m PolicyMeta, active []contract.ID) bool {
	if len(m.PierceableBy) == 0 || len(active) == 0 {
		return false
	}
	allowed := map[string]struct{}{}
	for _, r := range m.PierceableBy {
		allowed[r.String()] = struct{}{}
	}
	for _, r := range active {
		if _, ok := allowed[r.String()]; ok {
			return true
		}
	}
	return false
}

func firstMatched(ocs []PolicyOutcome) *PolicyOutcome {
	var best *PolicyOutcome
	for i := range ocs {
		if ocs[i].Verdict != VerdictMatch {
			continue
		}
		if best == nil || ocs[i].PolicyID < best.PolicyID {
			best = &ocs[i]
		}
	}
	return best
}

func firstUnknown(ocs []PolicyOutcome) *PolicyOutcome {
	var best *PolicyOutcome
	for i := range ocs {
		if ocs[i].Verdict != VerdictUnknown {
			continue
		}
		if best == nil || ocs[i].PolicyID < best.PolicyID {
			best = &ocs[i]
		}
	}
	return best
}

func noPermissionMatched(ocs []PolicyOutcome) bool {
	for _, oc := range ocs {
		if oc.Verdict == VerdictMatch {
			return false
		}
	}
	return true
}

func unknownOf(oc PolicyOutcome) contract.UnknownPolicy {
	up := contract.UnknownPolicy{PolicyID: oc.PolicyID, Authority: oc.Authority}
	for _, c := range oc.Causes {
		up.Paths = append(up.Paths, c.Path)
		if up.Reason == "" {
			up.Reason = c.Reason
		}
	}
	return up
}

func describe(meta map[string]PolicyMeta, id string) string {
	if m, ok := meta[id]; ok && m.Description != "" {
		return m.Description
	}
	return "policy " + id
}

// nextBound reports the next constraint or requirement that would bind if the
// currently binding one were resolved.
//
// It is deliberately modest: the next matched-or-unknown constraint in policy
// identifier order, excluding the one that bound. Reporting only the binding
// constraint produces a support loop in which the requester clears the named
// obstacle, retries, and hits the next one, so naming the successor is worth
// having even when it cannot enumerate the whole chain.
func nextBound(byAuthority map[contract.Authority][]PolicyOutcome, meta map[string]PolicyMeta, binding string) *contract.NextBound {
	var candidates []PolicyOutcome
	for _, oc := range byAuthority[contract.AuthorityConstraint] {
		if oc.PolicyID == binding {
			continue
		}
		if oc.Verdict == VerdictMatch || oc.Verdict == VerdictUnknown {
			candidates = append(candidates, oc)
		}
	}
	for _, oc := range byAuthority[contract.AuthorityRequirement] {
		if oc.Verdict == VerdictMatch && meta[oc.PolicyID].Mandatory {
			candidates = append(candidates, oc)
		}
	}
	if len(candidates) == 0 {
		return nil
	}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].PolicyID < candidates[j].PolicyID })
	c := candidates[0]
	return &contract.NextBound{PolicyID: c.PolicyID, Authority: c.Authority, Summary: describe(meta, c.PolicyID)}
}

// witnessesFor names the group memberships that brought a determining policy
// into scope, so that a decision reached through a group the requester has
// never heard of is explainable.
func witnessesFor(in CombineInput, d contract.Determining) []contract.Witness {
	groups := in.Attributes.Lookup(PrincipalGroupsPath)
	if groups.State != contract.StateKnown {
		return nil
	}
	member := map[string]struct{}{}
	if arr, ok := groups.Value.([]any); ok {
		for _, g := range arr {
			if s, ok := g.(string); ok {
				member[s] = struct{}{}
			}
		}
	}
	if arr, ok := groups.Value.([]string); ok {
		for _, s := range arr {
			member[s] = struct{}{}
		}
	}
	var out []contract.Witness
	seen := map[string]struct{}{}
	all := append(append([]string(nil), d.MatchedConstraints...), d.MatchedPermissions...)
	all = append(all, d.MatchedRequirement...)
	for _, id := range all {
		for _, g := range in.Meta[id].ScopeGroups {
			if _, ok := member[g.String()]; !ok {
				continue
			}
			if _, dup := seen[g.String()]; dup {
				continue
			}
			seen[g.String()] = struct{}{}
			out = append(out, contract.Witness{
				Subject:     g.String(),
				Path:        []string{in.Actor.String(), g.String()},
				SourceClass: contract.ProvDirectory,
			})
		}
	}
	contract.SortWitnesses(out)
	return out
}

func finish(
	dec *contract.Decision,
	trace *contract.Trace,
	authz contract.Authorization,
	reason contract.ReasonCode,
	remediation string,
	obligations []contract.Obligation,
	approval *contract.ApprovalRequirement,
	determining contract.Determining,
) (*contract.Decision, error) {
	state, err := contract.StateFor(authz, approval != nil)
	if err != nil {
		return nil, err
	}
	dec.Authorization = authz
	dec.State = state
	dec.Reason = reason
	dec.Obligations = obligations
	dec.Approval = approval
	dec.Determining = determining.Canonical()

	trace.State = state
	trace.Category = contract.CategoryFor(reason)
	trace.Reason = reason
	trace.Remediation = remediation
	trace.Obligations = obligations
	canonical := dec.Determining
	trace.Determining = &canonical
	if approval != nil {
		expiry := approval.ExpiresAt
		trace.ApprovalExpiresAt = &expiry
	}
	dec.Trace = trace

	if err := dec.Validate(); err != nil {
		return nil, err
	}
	return dec, nil
}

func sortedKeysOf(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func joinIDs(ids []string) string {
	if len(ids) == 0 {
		return "none"
	}
	out := ids[0]
	for _, id := range ids[1:] {
		out += "," + id
	}
	return out
}
