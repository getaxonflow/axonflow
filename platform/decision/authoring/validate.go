package authoring

import (
	"fmt"
	"sort"
	"strings"

	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/pdp"
)

// Validate applies the complete save-time check set to a document.
//
// It returns EVERY finding, not the first, and it is the single entry point:
// NewDocument calls it and Publish calls it again on the document it is about
// to compile. Publish re-running it is not belt and braces, it is the actual
// guard. A document can reach Publish without having gone through NewDocument
// (it can be parsed off the wire, restored from a store, or handed over by a
// migration), and a validator that only the constructor calls is a validator
// with a documented bypass.
//
// The check set has three layers, and which layer a check belongs to is decided
// by what it needs to see:
//
//   - the ENVELOPE layer needs only the document;
//   - the RELAYED layer is the deterministic PDP's own authoring validator,
//     which needs the compiled policy vocabulary and nothing else. It is
//     relayed rather than reimplemented, and a test holds the relay table to
//     pdp.AllRules so a rule added there cannot arrive at a portal as a
//     rejection with no explanation;
//   - the CATALOG layer needs the action, realm and resource registries, which
//     is exactly why these checks cannot live in pdp: a compiled bundle is
//     evaluated offline against no registry at all.
func Validate(d *Document, cat *Catalog) Findings {
	var out Findings
	if d == nil {
		return append(out, newFinding(CodeEnvelopeInvalid, "", "the document is nil"))
	}
	if err := cat.Validate(); err != nil {
		// A catalog defect is reported as an envelope-level rejection rather
		// than as a per-policy one. An author looking at "this action is not
		// registered" cannot tell a typo from an empty registry, and those go
		// to different people.
		return append(out, newFinding(CodeEnvelopeInvalid, "", err.Error()))
	}

	out = append(out, validateEnvelope(d)...)
	out = append(out, validateCatalogAgreement(d, cat)...)
	out = append(out, relayPDP(d)...)
	schema := d.Policy.AttributeIndex()
	for _, p := range d.Policy.Policies {
		out = append(out, validatePolicyAgainstCatalog(p, cat, schema)...)
	}
	out = append(out, validateAcrossPolicies(d, cat)...)
	return out.sorted()
}

// validateEnvelope checks the authoring envelope itself.
func validateEnvelope(d *Document) Findings {
	var out Findings
	reject := func(detail string) { out = append(out, newFinding(CodeEnvelopeInvalid, "", detail)) }

	if d.APIVersion != APIVersion {
		reject(fmt.Sprintf("api_version is %q, this build understands %q", d.APIVersion, APIVersion))
	}
	if strings.TrimSpace(d.Metadata.DocumentID) == "" {
		reject("metadata.document_id is empty, so successive versions of this document could not be related to each other")
	}
	if strings.TrimSpace(d.Metadata.Title) == "" {
		reject("metadata.title is empty")
	}
	if d.Metadata.Author.IsZero() {
		reject("metadata.author is unset, and separation of duties at publication is checked against it")
	} else if d.Metadata.Author.Kind != contract.KindPrincipal {
		reject(fmt.Sprintf("metadata.author names a %q, and an author is a principal", d.Metadata.Author.Kind))
	} else if err := d.Metadata.Author.Validate(); err != nil {
		reject("metadata.author: " + err.Error())
	}
	if d.Metadata.Supersedes != "" && !strings.HasPrefix(d.Metadata.Supersedes, "sha256:") {
		reject(fmt.Sprintf("metadata.supersedes is %q, which is not a content digest", d.Metadata.Supersedes))
	}
	if d.Policy.Version <= 0 {
		reject(fmt.Sprintf("policy.version is %d; a document version is a positive, advancing revision number", d.Policy.Version))
	}
	switch d.Policy.Root {
	case pdp.RootSystem, pdp.RootOrganization:
	default:
		reject(fmt.Sprintf("policy.root is %q, which is not a declared authority root", d.Policy.Root))
	}
	if len(d.Policy.Policies) == 0 {
		reject("the document declares no policies")
	}
	return out
}

// validateCatalogAgreement refuses a document whose carried registry facts
// disagree with the registry it is being validated against.
//
// The compiled bundle has to be self contained, so the document carries a copy
// of which realms are interactive. This check is what stops that copy becoming
// a second, editable source of truth: a hand-assembled document that claims a
// realm is interactive would otherwise publish an approval into a realm where
// nobody can answer, and the challenge would park until it timed out into a
// denial.
func validateCatalogAgreement(d *Document, cat *Catalog) Findings {
	var out Findings
	want := cat.InteractiveRealms()
	got := d.Policy.InteractiveRealms
	for realm, wantVal := range want {
		gotVal, ok := got[realm]
		if !ok {
			out = append(out, newFinding(CodeCatalogDisagreement, "", fmt.Sprintf(
				"the document does not carry realm %q, which the registry declares", realm)))
			continue
		}
		if gotVal != wantVal {
			out = append(out, newFinding(CodeCatalogDisagreement, "", fmt.Sprintf(
				"the document says realm %q has interactive=%t, the registry says interactive=%t", realm, gotVal, wantVal)))
		}
	}
	for realm := range got {
		if _, ok := want[realm]; !ok {
			out = append(out, newFinding(CodeCatalogDisagreement, "", fmt.Sprintf(
				"the document carries realm %q, which the registry does not declare", realm)))
		}
	}
	return out
}

// relayPDP surfaces the deterministic PDP's authoring rejections as findings.
//
// Unlike newFinding, an unrecognised rule here does NOT panic. The codes this
// package owns are compile-time constants, so an undeclared one can only exist
// during development; a pdp rule name arrives from another package and could in
// principle be added there without this table moving. Refusing the save with an
// explicit "undeclared" note fails closed and leaves the drift visible, which a
// panic in a running control plane would not.
func relayPDP(d *Document) Findings {
	var out Findings
	for _, e := range d.Policy.Validate() {
		decl, ok := checkIndex[e.Rule]
		if !ok {
			out = append(out, Finding{
				Code:     e.Rule,
				Severity: SeverityReject,
				PolicyID: e.PolicyID,
				Summary:  "This rejection has no declared explanation in the authoring check table, which is itself a defect. Report it.",
				Detail:   e.Detail,
			})
			continue
		}
		out = append(out, Finding{
			Code:     decl.Code,
			Severity: decl.Severity,
			PolicyID: e.PolicyID,
			Summary:  decl.Summary,
			Detail:   e.Detail,
		})
	}
	return out
}

// validatePolicyAgainstCatalog applies every check that needs the registry.
func validatePolicyAgainstCatalog(p pdp.Policy, cat *Catalog, schema map[string]pdp.AttributeSchema) Findings {
	var out Findings

	// Actions. The named-action check runs first and suppresses the reach
	// check, because an unregistered name makes the reach empty and reporting
	// both would give an author two rejections with one fix.
	unregistered := false
	for _, id := range p.Actions.Actions {
		if _, ok := cat.Actions[id.String()]; !ok {
			unregistered = true
			out = append(out, newFinding(CodeActionNotRegistered, p.ID, fmt.Sprintf(
				"the action selector names %q, which the action registry does not contain", id)))
		}
	}
	reached := cat.actionsReached(p.Actions)
	if !unregistered && len(reached) == 0 {
		out = append(out, newFinding(CodeSelectorMatchesNoRegisteredAction, p.ID, fmt.Sprintf(
			"the action selector reaches no registered action (named %v, required tags %v)",
			idStrings(p.Actions.Actions), p.Actions.RequiredTags)))
	}

	// Realms named by the scope.
	for _, id := range realmsScoped(p.Scope) {
		realm, ok := cat.Realms[id.Qualifier]
		if !ok {
			out = append(out, newFinding(CodeRealmNotDeclared, p.ID, fmt.Sprintf(
				"the scope names %q, whose realm %q is not declared in the realm registry", id, id.Qualifier)))
			continue
		}
		if id.Kind == contract.KindGroup && !realm.HasGroupGraph {
			out = append(out, newFinding(CodeGroupScopeWithoutGraph, p.ID, fmt.Sprintf(
				"the scope names group %q in realm %q, which has no group graph, so the closure is authoritatively empty and this policy can never match",
				id, id.Qualifier)))
		}
	}

	// Conditions read against the registry rather than against the document's
	// own attribute list, which pdp already checks.
	for _, c := range conditionsOf(p) {
		out = append(out, validateConditionAgainstCatalog(p, c, reached, cat, schema)...)
	}

	// Disclosure targets against the reachable payload surface. The runtime
	// deliberately reports an unplaced transform rather than denying, because
	// from the leaf list alone it cannot tell a vacuous match from a schema
	// that has drifted behind the real response. This is the path that can ask
	// the question, and composeDisclosure's own comment says so.
	leaves := payloadLeaves(reached)
	for _, o := range p.Obligations {
		fam, err := contract.FamilyOf(o.Type)
		if err != nil || fam != contract.FamilyDisclosure {
			continue
		}
		if !coversAnyLeaf(o.Target, leaves) {
			out = append(out, newFinding(CodeDisclosureTargetNotALeaf, p.ID, fmt.Sprintf(
				"the %s transform targets %q, which is not a declared payload leaf of any action this policy reaches (declared leaves: %v)",
				o.Type, o.Target, leaves)))
		}
	}

	// A constraint that cannot bind. This is the model's form of the source
	// specification's CEILING_CAPS_PERMIT: an ADR-065 constraint has no verdict
	// field to set to permit, so the no-op-masquerading-as-a-control shape has
	// to be found structurally instead.
	if p.Authority == contract.AuthorityConstraint {
		if neverTrue(p.Where) {
			out = append(out, newFinding(CodeConstraintNeverBinds, p.ID,
				"the constraint condition is structurally false, so the constraint can never bind"))
		}
		if p.Unless != nil && alwaysTrue(*p.Unless) {
			out = append(out, newFinding(CodeConstraintNeverBinds, p.ID,
				"the constraint exception is structurally true, so it collapses the constraint to non-applicable on every request"))
		}
	}

	// Obligations that will certainly apply together and cannot be composed.
	out = append(out, composeConflicts(p.ID, p.Obligations, leaves, fmt.Sprintf("policy %q", p.ID))...)
	return out
}

// validateConditionAgainstCatalog applies the registry-aware condition checks.
func validateConditionAgainstCatalog(p pdp.Policy, c pdp.Condition, reached []pdp.ActionEntry, cat *Catalog, schema map[string]pdp.AttributeSchema) Findings {
	var out Findings
	for _, path := range c.Paths() {
		switch contract.NamespaceOf(path) {
		case contract.NsArgs:
			out = append(out, checkArgumentPath(p, path, reached, schema)...)
		case contract.NsResource:
			out = append(out, checkResourcePath(p, path, cat)...)
		}
	}
	return out
}

// checkArgumentPath is the registry half of the source specification's
// FIELD_NOT_IN_SCHEMA: "a where clause referencing a field absent from the
// schema of any tool the selector matches". pdp checks the condition against
// the document's declared attributes, which is the other half; only the action
// registry knows what a tool actually accepts.
//
// The check runs against EVERY reachable action rather than against any one of
// them. A bound that exists on one action and not on another is a bound that
// silently does not apply to the rest, and the rest is where the incident is.
func checkArgumentPath(p pdp.Policy, path string, reached []pdp.ActionEntry, schema map[string]pdp.AttributeSchema) Findings {
	var out Findings
	name := strings.TrimPrefix(path, string(contract.NsArgs)+".")
	if name == "" || name == path {
		return out
	}
	docSchema, haveDocType := schema[path]
	declaredType := docSchema.Type
	for _, entry := range reached {
		argType, ok := entry.Arguments[name]
		if !ok {
			out = append(out, newFinding(CodeArgumentNotInActionSchema, p.ID, fmt.Sprintf(
				"the condition reads %q, which action %q does not declare in its argument schema", path, entry.ID)))
			continue
		}
		// A type disagreement is the unit bug in its structural form: a policy
		// reading a value the action denominates differently is a limit
		// everybody believes is one number and that is enforced as another.
		if haveDocType && declaredType != pdp.TypeAny && argType != pdp.TypeAny && declaredType != argType {
			out = append(out, newFinding(CodeArgumentNotInActionSchema, p.ID, fmt.Sprintf(
				"the condition reads %q, which this document declares as %q and action %q declares as %q",
				path, declaredType, entry.ID, argType)))
		}
	}
	return out
}

// checkResourcePath applies LEVEL_NOT_DECLARED and SCOPE_REQUIRES_RECURSION.
func checkResourcePath(p pdp.Policy, path string, cat *Catalog) Findings {
	var out Findings
	types := cat.resourceTypesReached()

	if path == pdp.ResourceAncestorsPath {
		// A read of the containment closure is a containment scope. Against a
		// type whose hierarchy is not recursive the closure is always empty, so
		// the condition never holds and the policy reads as active.
		if len(types) == 0 {
			out = append(out, newFinding(CodeScopeRequiresRecursion, p.ID, fmt.Sprintf(
				"the condition reads the containment closure %q, and the registry declares no resource type to check the hierarchy against", path)))
			return out
		}
		var flat []string
		for _, rt := range types {
			if !rt.Recursive {
				flat = append(flat, rt.Type)
			}
		}
		if len(flat) > 0 {
			out = append(out, newFinding(CodeScopeRequiresRecursion, p.ID, fmt.Sprintf(
				"the condition reads the containment closure %q, but resource type(s) %v declare a non-recursive hierarchy, so the closure is always empty there",
				path, flat)))
		}
		return out
	}

	// resource.<level>.<field> is a projection through a named hierarchy level.
	// resource.<field> is a direct attribute of the resource and has no level.
	segments := strings.Split(path, ".")
	if len(segments) < 3 {
		return out
	}
	level := segments[1]
	if len(types) == 0 {
		out = append(out, newFinding(CodeLevelNotDeclared, p.ID, fmt.Sprintf(
			"the condition reads level %q through %q, and the registry declares no resource type to check the level against", level, path)))
		return out
	}
	var missing []string
	for _, rt := range types {
		if !containsString(rt.Ancestors, level) {
			missing = append(missing, rt.Type)
		}
	}
	if len(missing) > 0 {
		out = append(out, newFinding(CodeLevelNotDeclared, p.ID, fmt.Sprintf(
			"the condition reads level %q through %q, which resource type(s) %v do not declare as an ancestor level",
			level, path, missing)))
	}
	return out
}

// validateAcrossPolicies applies the checks that need more than one policy.
func validateAcrossPolicies(d *Document, cat *Catalog) Findings {
	var out Findings
	policies := d.Policy.Policies

	// Obligations from policies that CERTAINLY apply together.
	//
	// "Certainly" is doing real work. Whether two conditional policies can both
	// match is not decidable in general, and a check that guessed would refuse
	// documents that are fine. The decidable case is a pair that is
	// unconditionally applicable over an overlapping population and an
	// overlapping action set: on any request in that intersection both match,
	// so if their obligations cannot compose the request is authorized by
	// policy and refused in production.
	for i := 0; i < len(policies); i++ {
		for j := i + 1; j < len(policies); j++ {
			a, b := policies[i], policies[j]
			if !certainlyCoApply(a, b, cat) {
				continue
			}
			combined := append(append([]contract.Obligation(nil), a.Obligations...), b.Obligations...)
			if len(combined) == 0 {
				continue
			}
			leaves := payloadLeaves(cat.actionsReached(a.Actions))
			out = append(out, composeConflicts(a.ID, combined, leaves,
				fmt.Sprintf("policies %q and %q, which apply together unconditionally", a.ID, b.ID))...)
		}
	}

	// A permission wholly suppressed by an unconditional unbreakable
	// constraint. Reported as a warning, keeping the source specification's own
	// disposition: the policy is well formed, and the author is entitled to
	// stage a permission ahead of relaxing the constraint that covers it.
	for _, perm := range policies {
		if perm.Authority != contract.AuthorityPermission {
			continue
		}
		for _, con := range policies {
			if con.Authority != contract.AuthorityConstraint {
				continue
			}
			if !suppressesEntirely(con, perm, cat) {
				continue
			}
			out = append(out, newFinding(CodeDeadPermission, perm.ID, fmt.Sprintf(
				"constraint %q applies unconditionally to at least everything this permission reaches and declares no break-glass pierce, so this permission can never produce a permit",
				con.ID)))
			break
		}
	}
	return out
}

// composeConflicts runs the real composition algebra over an obligation set and
// reports a conflict.
//
// It calls contract.ComposeObligations rather than reimplementing the family
// algebras, which is the whole point: a second implementation here would
// eventually disagree with the one that runs in production, and the disagreement
// would be invisible in exactly the direction that matters, a save that passes
// and an enforcement that denies.
//
// Only ReasonObligationConflict is treated as a save-time rejection.
// ReasonUnsupportedObligation names an enforcement point that has not advertised
// a capability, which is a fact about a deployment and not about a document: an
// author cannot fix it and a reason code must not name a cause the check cannot
// observe. The synthetic profile below advertises exactly what the set contains
// so that the enforcement axis contributes nothing either way.
func composeConflicts(policyID string, obligations []contract.Obligation, leaves []string, subject string) Findings {
	if len(obligations) == 0 {
		return nil
	}
	hasDisclosure := false
	for _, o := range obligations {
		if fam, err := contract.FamilyOf(o.Type); err == nil && fam == contract.FamilyDisclosure {
			hasDisclosure = true
		}
	}
	if hasDisclosure && len(leaves) == 0 {
		// Already reported as DISCLOSURE_TARGET_NOT_A_LEAF, and composing
		// against an empty leaf schema denies for that same reason. Reporting
		// it twice under two codes would send an author looking for a second
		// defect that does not exist.
		return nil
	}
	caps := make([]contract.Capability, 0, len(obligations))
	for _, o := range obligations {
		caps = append(caps, contract.Capability{Type: o.Type, Version: o.SchemaVersion})
	}
	outcome := contract.ComposeObligations(contract.ComposeInput{
		Obligations: obligations,
		Leaves:      leaves,
		PEP:         &contract.PEPProfile{ID: "authoring-save-time", Capabilities: caps},
	})
	if !outcome.Denied || outcome.Reason != contract.ReasonObligationConflict {
		return nil
	}
	return Findings{newFinding(CodeObligationConflict, policyID, fmt.Sprintf(
		"the obligations attached by %s cannot be composed: %s", subject, outcome.Detail))}
}

// certainlyCoApply reports whether two policies match together on at least one
// request, decided structurally and conservatively.
//
// Every conjunct is a sound over-approximation of "cannot be ruled out", and
// the function returns true only when NONE of them can be ruled out. It is
// deliberately incomplete: it never claims two conditional policies co-apply,
// so it produces no false rejections at the cost of missing conflicts that
// depend on request data.
func certainlyCoApply(a, b pdp.Policy, cat *Catalog) bool {
	if !unconditional(a) || !unconditional(b) {
		return false
	}
	if !scopesOverlap(a.Scope, b.Scope) {
		return false
	}
	return len(intersectActions(cat.actionsReached(a.Actions), cat.actionsReached(b.Actions))) > 0
}

// unconditional reports whether a policy applies to every request its selectors
// reach, with no data-dependent condition at all.
func unconditional(p pdp.Policy) bool {
	if !alwaysTrue(p.Where) {
		return false
	}
	if p.ResourceScope != nil && !alwaysTrue(*p.ResourceScope) {
		return false
	}
	// An exception that is not structurally false may fire, which makes the
	// policy conditional.
	if p.Unless != nil && !neverTrue(*p.Unless) {
		return false
	}
	return true
}

// suppressesEntirely reports whether a constraint denies every request a
// permission could grant.
func suppressesEntirely(con, perm pdp.Policy, cat *Catalog) bool {
	if !unconditional(con) {
		return false
	}
	// A pierceable constraint can be suspended by an approved break-glass
	// grant, so the permission is reachable and is not dead.
	if len(con.PierceableBy) > 0 {
		return false
	}
	if !scopeCovers(con.Scope, perm.Scope) {
		return false
	}
	conReach := cat.actionsReached(con.Actions)
	permReach := cat.actionsReached(perm.Actions)
	if len(permReach) == 0 {
		return false
	}
	return actionsCover(conReach, permReach)
}

// scopesOverlap reports whether two scopes can select the same principal.
func scopesOverlap(a, b pdp.Scope) bool {
	if a.Organization || b.Organization {
		return true
	}
	if sharesID(a.Principals, b.Principals) || sharesID(a.Groups, b.Groups) {
		return true
	}
	// A principal-scoped policy and a group-scoped one can both select the same
	// subject, and whether they do is a directory fact. It cannot be ruled out
	// structurally, so it is not ruled out.
	return (len(a.Principals) > 0 && len(b.Groups) > 0) || (len(a.Groups) > 0 && len(b.Principals) > 0)
}

// scopeCovers reports whether outer selects every principal inner can select.
func scopeCovers(outer, inner pdp.Scope) bool {
	if outer.Organization {
		return true
	}
	if inner.Organization {
		return false
	}
	// A group-scoped outer cannot be shown to cover a principal-scoped inner
	// without asking the directory, so it is not claimed to.
	if len(inner.Principals) > 0 && !containsAllIDs(outer.Principals, inner.Principals) {
		return false
	}
	if len(inner.Groups) > 0 && !containsAllIDs(outer.Groups, inner.Groups) {
		return false
	}
	return len(inner.Principals) > 0 || len(inner.Groups) > 0
}

func actionsCover(outer, inner []pdp.ActionEntry) bool {
	set := make(map[string]struct{}, len(outer))
	for _, e := range outer {
		set[e.ID.String()] = struct{}{}
	}
	for _, e := range inner {
		if _, ok := set[e.ID.String()]; !ok {
			return false
		}
	}
	return true
}

func intersectActions(a, b []pdp.ActionEntry) []string {
	set := make(map[string]struct{}, len(a))
	for _, e := range a {
		set[e.ID.String()] = struct{}{}
	}
	var out []string
	for _, e := range b {
		if _, ok := set[e.ID.String()]; ok {
			out = append(out, e.ID.String())
		}
	}
	sort.Strings(out)
	return out
}

// alwaysTrue and neverTrue decide the truth of a condition's BOOLEAN SKELETON,
// treating every data-reading leaf as neither true nor false.
//
// They are the sound direction of a three-valued structural evaluation: a leaf
// contributes nothing, so alwaysTrue(x) implies x holds on every request, and
// neverTrue(x) implies x holds on none. Nothing in this file may read them as
// "the condition is false" when both return false, which is the ordinary case.
func alwaysTrue(c pdp.Condition) bool {
	switch c.Kind {
	case pdp.CondTrue:
		return true
	case pdp.CondAnd:
		for _, o := range c.Operands {
			if !alwaysTrue(o) {
				return false
			}
		}
		return len(c.Operands) > 0
	case pdp.CondOr:
		for _, o := range c.Operands {
			if alwaysTrue(o) {
				return true
			}
		}
		return false
	case pdp.CondNot:
		return len(c.Operands) == 1 && neverTrue(c.Operands[0])
	default:
		return false
	}
}

func neverTrue(c pdp.Condition) bool {
	switch c.Kind {
	case pdp.CondTrue:
		return false
	case pdp.CondAnd:
		for _, o := range c.Operands {
			if neverTrue(o) {
				return true
			}
		}
		return false
	case pdp.CondOr:
		for _, o := range c.Operands {
			if !neverTrue(o) {
				return false
			}
		}
		return len(c.Operands) > 0
	case pdp.CondNot:
		return len(c.Operands) == 1 && alwaysTrue(c.Operands[0])
	default:
		return false
	}
}

// conditionsOf returns every condition tree a policy carries.
func conditionsOf(p pdp.Policy) []pdp.Condition {
	out := []pdp.Condition{p.Where}
	if p.ResourceScope != nil {
		out = append(out, *p.ResourceScope)
	}
	if p.Unless != nil {
		out = append(out, *p.Unless)
	}
	return out
}

func coversAnyLeaf(target string, leaves []string) bool {
	for _, leaf := range leaves {
		if contract.TargetCovers(target, leaf) {
			return true
		}
	}
	return false
}

func containsString(hay []string, needle string) bool {
	for _, h := range hay {
		if h == needle {
			return true
		}
	}
	return false
}

func sharesID(a, b []contract.ID) bool {
	set := make(map[string]struct{}, len(a))
	for _, x := range a {
		set[x.String()] = struct{}{}
	}
	for _, y := range b {
		if _, ok := set[y.String()]; ok {
			return true
		}
	}
	return false
}

func containsAllIDs(outer, inner []contract.ID) bool {
	set := make(map[string]struct{}, len(outer))
	for _, x := range outer {
		set[x.String()] = struct{}{}
	}
	for _, y := range inner {
		if _, ok := set[y.String()]; !ok {
			return false
		}
	}
	return true
}

func idStrings(ids []contract.ID) []string {
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		out = append(out, id.String())
	}
	return out
}
