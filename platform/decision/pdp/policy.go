// Package pdp is the deterministic policy decision point: a typed authoring
// document, a lossless compiler into Rego v1, an in-process OPA runtime with
// restricted capabilities, and the ADR-065 combining semantics implemented in
// Go above Rego.
//
// The division of labour is deliberate and is the whole design. Rego answers
// exactly one question per policy: does this policy MATCH, NO_MATCH, or is it
// UNKNOWN, and for what reason. It never decides the request. Combining lives
// in Go (see combine.go) because the combining rule is a security invariant
// that must hold even when a bundle is defective, and a rule that lives inside
// the artifact it is meant to constrain constrains nothing.
package pdp

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"axonflow/platform/decision/contract"
)

// ValueType is the declared type of an attribute, checked before any
// comparison so that a wrongly typed value becomes a tagged unknown rather than
// a Rego built-in error.
type ValueType string

const (
	TypeNumber  ValueType = "number"
	TypeString  ValueType = "string"
	TypeBoolean ValueType = "boolean"
	TypeArray   ValueType = "array"
	TypeAny     ValueType = "any"
)

// AttributeSchema declares one policy-visible attribute.
type AttributeSchema struct {
	Path string    `json:"path"`
	Type ValueType `json:"type"`
	// Optional permits authoritative absence to produce NO_MATCH. A required
	// attribute that is absent is a data defect and resolves to unknown.
	Optional bool `json:"optional"`
	// MaxAgeSeconds is the freshness bound. Zero means unbounded.
	MaxAgeSeconds int64 `json:"max_age_seconds,omitempty"`
}

// CompareOp is a comparison operator.
type CompareOp string

const (
	OpEq CompareOp = "eq"
	OpNe CompareOp = "ne"
	OpLt CompareOp = "lt"
	OpLe CompareOp = "le"
	OpGt CompareOp = "gt"
	OpGe CompareOp = "ge"
)

var validOps = map[CompareOp]bool{OpEq: true, OpNe: true, OpLt: true, OpLe: true, OpGt: true, OpGe: true}

// The enumerators below exist so that every declared value of the authoring
// vocabulary can be walked rather than restated. The layer above publishes a
// JSON Schema that a non-Go plane reads, and a schema whose enums were typed
// out by hand is a second declaration of the vocabulary: it drifts the first
// time a value is added here, and the direction it drifts in is permissive,
// because the schema keeps accepting what it always accepted and stops
// describing what the compiler now understands.

// AllValueTypes returns every declared attribute type in a stable order.
func AllValueTypes() []ValueType {
	return []ValueType{TypeNumber, TypeString, TypeBoolean, TypeArray, TypeAny}
}

// AllCompareOps returns every declared comparison operator in a stable order.
func AllCompareOps() []CompareOp {
	return []CompareOp{OpEq, OpNe, OpLt, OpLe, OpGt, OpGe}
}

// AllAbsenceHandlings returns every DECLARABLE absence handling.
//
// AbsentUnspecified is deliberately absent from the list. It is the zero value
// and it is rejected on an optional attribute, so it is the absence of a
// declaration rather than one of the choices, and a schema that offered it as
// an enum member would invite an author to select the thing the validator
// exists to refuse.
func AllAbsenceHandlings() []AbsenceHandling {
	return []AbsenceHandling{AbsentIsNoMatch, AbsentIsUnknown}
}

// AllCondKinds returns every declared condition kind in a stable order.
func AllCondKinds() []CondKind {
	return []CondKind{
		CondTrue, CondCompare, CondMember, CondSuperset, CondIntersects,
		CondAttrCompare, CondAnd, CondOr, CondNot,
	}
}

// AllRoots returns every declared authority root.
func AllRoots() []Root { return []Root{RootSystem, RootOrganization} }

// AbsenceHandling declares what a condition does when the authoritative source
// established that its attribute has NO value.
//
// ADR-065 permits known absence to produce NO_MATCH "only where the schema
// marks the attribute optional AND the policy explicitly handles absence". The
// schema half is AttributeSchema.Optional. This is the policy half, and it
// exists because without it the second conjunct is not merely unenforced, it is
// inexpressible: an author would have no way to say what absence means and the
// compiler would decide on their behalf.
type AbsenceHandling string

const (
	// AbsentUnspecified is the zero value and is rejected on an optional
	// attribute, so that a new condition over an optional attribute cannot
	// inherit a default nobody chose.
	AbsentUnspecified AbsenceHandling = ""
	// AbsentIsNoMatch means the condition does not hold when the attribute is
	// authoritatively absent. It is the right answer for a bound on a value
	// that may legitimately not exist.
	AbsentIsNoMatch AbsenceHandling = "no_match"
	// AbsentIsUnknown means absence cannot be interpreted and the policy is
	// unknown. It is the right answer where absence of the attribute is itself
	// a fact the policy cannot act on.
	AbsentIsUnknown AbsenceHandling = "unknown"
)

// CondKind is the discriminator of a typed condition node.
type CondKind string

const (
	// CondTrue is the unconditional condition.
	CondTrue CondKind = "true"
	// CondCompare compares one attribute against a literal. This is the shape
	// that BOUNDS untrusted input, which is legitimate and is the entire point
	// of an argument bound.
	CondCompare CondKind = "compare"
	// CondMember tests membership of a literal in an attribute collection.
	CondMember CondKind = "member"
	// CondSuperset tests that an attribute collection contains every literal.
	CondSuperset CondKind = "superset"
	// CondIntersects tests that an attribute collection shares a member with
	// the literal set.
	CondIntersects CondKind = "intersects"
	// CondAttrCompare compares two attributes. With an identity operator this
	// is the shape that can ESTABLISH authority, and the authority rule
	// constrains it; with an ordering operator it is a bound, which is
	// legitimate.
	CondAttrCompare CondKind = "attr_compare"
	CondAnd         CondKind = "and"
	CondOr          CondKind = "or"
	CondNot         CondKind = "not"
)

// Condition is one node of the typed condition tree. It is a struct rather than
// an interface so that the whole document is plain JSON: the typed authoring
// document, not generated Rego, is the source of truth, and it has to survive a
// lossless round trip through the API.
type Condition struct {
	Kind CondKind `json:"kind"`
	// Path is the attribute path for compare, member, superset, intersects,
	// and the left operand of attr_eq.
	Path string `json:"path,omitempty"`
	// RightPath is the right operand of attr_compare.
	RightPath string `json:"right_path,omitempty"`
	// Op is the comparison operator for compare and attr_compare.
	Op CompareOp `json:"op,omitempty"`
	// Literal is the right operand of compare and the needle of member.
	Literal any `json:"literal,omitempty"`
	// Literals is the literal set of superset and intersects.
	Literals []any `json:"literals,omitempty"`
	// OnAbsent declares what this condition does when its attribute is
	// authoritatively absent. It is required on a condition reading an
	// attribute the schema marks optional, and forbidden otherwise.
	OnAbsent AbsenceHandling `json:"on_absent,omitempty"`
	// Operands are the children of and, or and not.
	Operands []Condition `json:"operands,omitempty"`
}

// HandlingAbsence returns a copy of the condition with its absence handling
// declared.
func (c Condition) HandlingAbsence(h AbsenceHandling) Condition {
	c.OnAbsent = h
	return c
}

// True builds the unconditional condition.
func True() Condition { return Condition{Kind: CondTrue} }

// Compare builds an attribute-against-literal comparison.
func Compare(path string, op CompareOp, literal any) Condition {
	return Condition{Kind: CondCompare, Path: path, Op: op, Literal: literal}
}

// Member builds a membership test.
func Member(path string, literal any) Condition {
	return Condition{Kind: CondMember, Path: path, Literal: literal}
}

// Superset builds a conjunctive collection test.
func Superset(path string, literals ...any) Condition {
	return Condition{Kind: CondSuperset, Path: path, Literals: literals}
}

// Intersects builds a disjunctive collection test.
func Intersects(path string, literals ...any) Condition {
	return Condition{Kind: CondIntersects, Path: path, Literals: literals}
}

// AttrCompare builds an attribute-to-attribute comparison.
func AttrCompare(left string, op CompareOp, right string) Condition {
	return Condition{Kind: CondAttrCompare, Path: left, Op: op, RightPath: right}
}

// AttrEq builds an attribute-to-attribute identity comparison.
func AttrEq(left, right string) Condition { return AttrCompare(left, OpEq, right) }

// And builds a conjunction.
func And(ops ...Condition) Condition { return Condition{Kind: CondAnd, Operands: ops} }

// Or builds a disjunction.
func Or(ops ...Condition) Condition { return Condition{Kind: CondOr, Operands: ops} }

// Not builds a negation.
func Not(op Condition) Condition { return Condition{Kind: CondNot, Operands: []Condition{op}} }

// Paths returns every attribute path the condition reads, sorted and
// duplicate-free. The tri-state corpus generator uses it to enumerate the
// attributes a bundle can reference, which is what makes "generate a missing,
// absent, stale, malformed and resolver-failed variant for every referenced
// attribute" mechanical rather than a list somebody maintains.
func (c Condition) Paths() []string {
	set := map[string]struct{}{}
	c.collectPaths(set)
	out := make([]string, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

func (c Condition) collectPaths(set map[string]struct{}) {
	if c.Path != "" {
		set[c.Path] = struct{}{}
	}
	if c.RightPath != "" {
		set[c.RightPath] = struct{}{}
	}
	for _, o := range c.Operands {
		o.collectPaths(set)
	}
}

// Scope selects which principals a policy applies to.
type Scope struct {
	// Organization applies the policy to every principal in the organization.
	Organization bool `json:"organization"`
	// Principals applies the policy to named principals. A principal-scoped
	// policy is how a subject in a realm with no group graph reaches its
	// permissions at all.
	Principals []contract.ID `json:"principals,omitempty"`
	// Groups applies the policy to members of named groups, resolved through
	// the principal.groups attribute. Group membership therefore participates
	// in three-valued logic like any other attribute: an unresolvable closure
	// makes a group-scoped constraint UNKNOWN rather than silently
	// inapplicable.
	Groups []contract.ID `json:"groups,omitempty"`
}

// ActionSelector selects which actions a policy applies to.
type ActionSelector struct {
	// Actions names specific registered actions.
	Actions []contract.ID `json:"actions,omitempty"`
	// RequiredTags is CONJUNCTIVE: the action must carry every tag. A
	// constraint over the pair {irreversible, pii_egress} expresses something
	// that no combination of single-tag constraints reaches, so conjunctive
	// selectors are load bearing rather than sugar.
	RequiredTags []string `json:"required_tags,omitempty"`
	// Any selects every action. It must be set explicitly, so that an empty
	// selector is a construction defect rather than an accidental match-all.
	Any bool `json:"any,omitempty"`
}

// Root is the signing authority root a policy was published under.
type Root string

const (
	// RootSystem is the platform authority. System constraints bound
	// everything.
	RootSystem Root = "system"
	// RootOrganization is the customer authority. An organization policy can
	// grant only within system constraints and can never modify them.
	RootOrganization Root = "organization"
)

// Policy is one typed authoring document entry.
type Policy struct {
	ID        string             `json:"id"`
	Authority contract.Authority `json:"authority"`
	Root      Root               `json:"root"`
	Scope     Scope              `json:"scope"`
	Actions   ActionSelector     `json:"actions"`
	// ResourceScope is the resource-side selector. It is a condition rather
	// than a separate language because an unresolvable resource scope must
	// participate in three-valued logic exactly like an unresolvable
	// condition: a scope that silently fails to match is a constraint that
	// silently does not apply.
	ResourceScope *Condition `json:"resource_scope,omitempty"`
	// Where is the policy condition.
	Where Condition `json:"where"`
	// Unless is an exception clause. A satisfied Unless collapses the policy
	// to non-applicable, which is the same code path as the policy not
	// existing. Exceptions live inside the policy they modify rather than in a
	// competing policy of the opposite authority.
	Unless *Condition `json:"unless,omitempty"`
	// Obligations are attached by requirement and inspection policies.
	Obligations []contract.Obligation `json:"obligations,omitempty"`
	// Mandatory marks a requirement whose obligations must be discharged.
	Mandatory bool `json:"mandatory,omitempty"`
	// PierceableBy names the break-glass roles that may suspend a constraint.
	// Nil means the constraint is unbreakable by construction, which is what a
	// regulatory or contractual constraint declares.
	PierceableBy []contract.ID `json:"pierceable_by,omitempty"`
	// Description is operator-facing text carried into the trace.
	Description string `json:"description,omitempty"`
}

// ReferencedPaths returns every attribute path this policy reads, including
// the paths its scope and action selectors read.
//
// It is exported because the tri-state corpus generates a missing, absent,
// stale, malformed and resolver-failure variant for EVERY referenced attribute,
// and deriving that list from the policy rather than from a hand-maintained
// table is what makes the corpus complete by construction instead of complete
// as of the last time somebody checked.
func (p Policy) ReferencedPaths() []string {
	set := map[string]struct{}{}
	add := func(c Condition) {
		for _, path := range c.Paths() {
			set[path] = struct{}{}
		}
	}
	add(p.Where)
	if p.Unless != nil {
		add(*p.Unless)
	}
	if p.ResourceScope != nil {
		add(*p.ResourceScope)
	}
	if len(p.Scope.Principals) > 0 {
		set[PrincipalIDPath] = struct{}{}
	}
	if len(p.Scope.Groups) > 0 {
		set[PrincipalGroupsPath] = struct{}{}
	}
	if len(p.Actions.Actions) > 0 {
		set[ActionIDPath] = struct{}{}
	}
	if len(p.Actions.RequiredTags) > 0 {
		set[ActionTagsPath] = struct{}{}
	}
	out := make([]string, 0, len(set))
	for path := range set {
		out = append(out, path)
	}
	sort.Strings(out)
	return out
}

// ReferencedPaths returns every attribute path any policy in the document
// reads.
func (d *Document) ReferencedPaths() []string {
	set := map[string]struct{}{}
	for _, p := range d.Policies {
		for _, path := range p.ReferencedPaths() {
			set[path] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for path := range set {
		out = append(out, path)
	}
	sort.Strings(out)
	return out
}

// Document is the complete typed authoring document for one bundle root.
type Document struct {
	Root       Root              `json:"root"`
	Version    int               `json:"version"`
	Attributes []AttributeSchema `json:"attributes"`
	Policies   []Policy          `json:"policies"`
	// InteractiveRealms records, per realm identifier, whether a person can be
	// asked a question there. It is authoring-time context rather than runtime
	// data: an approval pool that resolves only in a non-interactive realm can
	// never be discharged, so it is rejected at save time rather than issued
	// and left to expire. Enforcing this on the REALM keeps the evaluator out
	// of the business of deciding which subjects are people; a service account
	// sitting in an approver group for automation reasons is the ordinary case
	// this rule exists for.
	InteractiveRealms map[string]bool `json:"interactive_realms,omitempty"`
}

// AttributeIndex returns the schema by path.
func (d *Document) AttributeIndex() map[string]AttributeSchema {
	out := make(map[string]AttributeSchema, len(d.Attributes))
	for _, a := range d.Attributes {
		out[a.Path] = a
	}
	return out
}

// ValidationError is one authoring rejection. Rejections are named so that a
// test can assert WHICH rule fired rather than that something failed.
type ValidationError struct {
	Rule     string
	PolicyID string
	Detail   string
}

func (e ValidationError) Error() string {
	return fmt.Sprintf("%s: policy %q: %s", e.Rule, e.PolicyID, e.Detail)
}

// Authoring rejection rule names.
const (
	RuleAuthorityFromUntrusted = "AUTHORITY_FROM_UNTRUSTED"
	RuleFieldNotInSchema       = "FIELD_NOT_IN_SCHEMA"
	RulePermissionEmitsDeny    = "PERMISSION_EMITS_DENY"
	RuleConstraintObligations  = "CONSTRAINT_CARRIES_OBLIGATIONS"
	RuleInspectionGrants       = "INSPECTION_GRANTS"
	RuleEmptySelector          = "SELECTOR_MATCHES_NOTHING"
	RuleApprovalUnsatisfiable  = "APPROVAL_CLAUSE_UNSATISFIABLE"
	RuleOrgPolicyPiercesSystem = "ORG_POLICY_PIERCES_SYSTEM"
	RuleMalformedCondition     = "MALFORMED_CONDITION"
	RuleDuplicatePolicyID      = "DUPLICATE_POLICY_ID"
	RuleRootMismatch           = "ROOT_MISMATCH"
	RulePoolNotInteractive     = "POOL_NOT_INTERACTIVE"
	RuleAbsenceNotHandled      = "ABSENCE_NOT_HANDLED"
)

// AllRules returns every authoring rejection rule this validator can emit, in
// a stable order.
//
// It is data rather than documentation because the layer above relays these
// rules to an operator with a rendered explanation per code, and a rule added
// here without an explanation there would reach a portal as a refusal nobody
// can act on. Enumerating the set is what lets that layer's test fail on the
// addition rather than on the first customer who trips it.
func AllRules() []string {
	return []string{
		RuleAbsenceNotHandled,
		RuleApprovalUnsatisfiable,
		RuleAuthorityFromUntrusted,
		RuleConstraintObligations,
		RuleDuplicatePolicyID,
		RuleEmptySelector,
		RuleFieldNotInSchema,
		RuleInspectionGrants,
		RuleMalformedCondition,
		RuleOrgPolicyPiercesSystem,
		RulePermissionEmitsDeny,
		RulePoolNotInteractive,
		RuleRootMismatch,
	}
}

// readsAttributeValue reports whether a condition kind consults the OPTIONAL
// flag, which is the set of kinds that compare an attribute against a literal.
// An attribute-to-attribute comparison is excluded: absence on either side of
// one is unknown regardless, because "no value" is not equal to, less than, or
// greater than anything.
func readsAttributeValue(k CondKind) bool {
	switch k {
	case CondCompare, CondMember, CondSuperset, CondIntersects:
		return true
	default:
		return false
	}
}

// Validate applies every authoring rule and returns all violations, not the
// first. A compile failure blocks publication, and an author fixing one
// rejection at a time through five publish attempts is how a rule set stops
// being enforced in practice.
func (d *Document) Validate() []ValidationError {
	var errs []ValidationError
	schema := d.AttributeIndex()
	seen := map[string]struct{}{}

	for _, p := range d.Policies {
		if _, dup := seen[p.ID]; dup {
			errs = append(errs, ValidationError{RuleDuplicatePolicyID, p.ID, "policy id appears more than once in one document"})
		}
		seen[p.ID] = struct{}{}

		if p.Root != d.Root {
			errs = append(errs, ValidationError{RuleRootMismatch, p.ID,
				fmt.Sprintf("policy declares root %q inside a %q document", p.Root, d.Root)})
		}
		if err := p.Authority.Validate(); err != nil {
			errs = append(errs, ValidationError{RuleMalformedCondition, p.ID, err.Error()})
			continue
		}

		// A permission may only widen. It carries no obligations of its own
		// and cannot deny, which is what lets one team author permissions
		// without a cross-team review of every constraint.
		if p.Authority == contract.AuthorityPermission {
			if len(p.Obligations) > 0 {
				errs = append(errs, ValidationError{RulePermissionEmitsDeny, p.ID,
					"a permission policy cannot attach obligations; use a requirement policy with the same condition"})
			}
			if len(p.PierceableBy) > 0 {
				errs = append(errs, ValidationError{RulePermissionEmitsDeny, p.ID,
					"pierceable_by is meaningful only on a policy that restricts: a constraint or a requirement"})
			}
		}
		// A constraint only restricts. Obligations belong to requirement
		// policies, so that "this denies" and "this attaches a redaction" are
		// never the same object with a nullable field deciding which.
		if p.Authority == contract.AuthorityConstraint && len(p.Obligations) > 0 {
			errs = append(errs, ValidationError{RuleConstraintObligations, p.ID,
				"a constraint policy cannot attach obligations; split it into a constraint and a requirement"})
		}
		// An inspection policy may attach only obligations that RECORD or
		// TRANSFORM. An approval challenge is a stateful requirement whose
		// timeout is always deny, and a quota reservation refuses when the
		// counter is exhausted, so either would let an advisory control produce
		// a denial by a route the mandatory flag does not cover: forcing the
		// flag off does not help, because neither family consults it.
		if p.Authority == contract.AuthorityInspection {
			for _, o := range p.Obligations {
				fam, err := contract.FamilyOf(o.Type)
				if err != nil {
					continue
				}
				if fam != contract.FamilyDisclosure && fam != contract.FamilyAuditNotify {
					errs = append(errs, ValidationError{RuleInspectionGrants, p.ID, fmt.Sprintf(
						"an inspection policy may not attach a %q obligation: the %s family can refuse or hold a request, "+
							"and an advisory control cannot deny", o.Type, fam)})
				}
			}
		}
		// An inspection policy cannot grant. A detector can never attest that
		// a request is legitimate, only that nothing looked wrong.
		if p.Authority == contract.AuthorityInspection && len(p.PierceableBy) > 0 {
			errs = append(errs, ValidationError{RuleInspectionGrants, p.ID,
				"pierceable_by is meaningful only on a policy that restricts: a constraint or a requirement"})
		}
		if p.Authority == contract.AuthorityInspection && p.Mandatory {
			errs = append(errs, ValidationError{RuleInspectionGrants, p.ID,
				"an inspection policy cannot be mandatory; a required deterministic control is a constraint or a requirement"})
		}
		if p.Authority == contract.AuthorityRequirement && len(p.Obligations) == 0 {
			errs = append(errs, ValidationError{RuleEmptySelector, p.ID,
				"a requirement policy that attaches no obligation does nothing"})
		}
		// An organization policy cannot declare a pierce of a system
		// constraint, and cannot publish a constraint under the system root.
		if p.Root == RootOrganization && len(p.PierceableBy) > 0 {
			errs = append(errs, ValidationError{RuleOrgPolicyPiercesSystem, p.ID,
				"break-glass piercing is declared by the authority that owns the constraint, and an organization root cannot declare it"})
		}

		if !p.Actions.Any && len(p.Actions.Actions) == 0 && len(p.Actions.RequiredTags) == 0 {
			errs = append(errs, ValidationError{RuleEmptySelector, p.ID,
				"action selector names no action, no required tag, and is not explicitly any"})
		}
		if !p.Scope.Organization && len(p.Scope.Principals) == 0 && len(p.Scope.Groups) == 0 {
			errs = append(errs, ValidationError{RuleEmptySelector, p.ID,
				"scope names no principal, no group, and is not organization wide"})
		}

		conds := []Condition{p.Where}
		if p.ResourceScope != nil {
			conds = append(conds, *p.ResourceScope)
		}
		if p.Unless != nil {
			conds = append(conds, *p.Unless)
		}
		for _, c := range conds {
			errs = append(errs, validateCondition(p.ID, p.Authority, c, schema)...)
		}
		for _, o := range p.Obligations {
			if err := o.Validate(); err != nil {
				errs = append(errs, ValidationError{RuleMalformedCondition, p.ID, err.Error()})
				continue
			}
			if o.Type == contract.ObApprovalChallenge {
				errs = append(errs, validateApprovalObligation(p.ID, o)...)
				errs = append(errs, validateApprovalRealms(p.ID, o, d.InteractiveRealms)...)
			}
		}
	}
	return errs
}

// validateApprovalObligation rejects a clause that is STRUCTURALLY
// undischargeable: a non-positive quorum, or an empty or unparseable eligible
// set.
//
// It does NOT check the quorum against the pool's membership, and cannot: how
// many people a group contains is a directory fact, and this validator sees a
// policy document. That gap is real and is raised on the ADR rather than
// papered over here, because ADR-065 makes approval a conjunction of immutable
// threshold clauses and does not collapse an unsatisfiable one at decision
// time the way the source proposal's normalize step did, so the outcome today
// is a challenge that expires rather than a denial.
func validateApprovalObligation(policyID string, o contract.Obligation) []ValidationError {
	quorum := o.Params["quorum"]
	eligible := o.Params["eligible"]
	if quorum == "" || eligible == "" {
		return []ValidationError{{RuleApprovalUnsatisfiable, policyID,
			"approval_challenge requires params quorum and eligible"}}
	}
	// strconv rather than Sscanf: Sscanf stops at the first non-digit and
	// reports success, so "3abc" would parse as three.
	q, err := strconv.Atoi(quorum)
	if err != nil || q < 1 {
		return []ValidationError{{RuleApprovalUnsatisfiable, policyID,
			fmt.Sprintf("approval_challenge quorum %q is not a positive integer", quorum)}}
	}
	groups := 0
	for _, raw := range strings.Split(eligible, ",") {
		if strings.TrimSpace(raw) == "" {
			continue
		}
		if _, err := contract.ParseID(contract.KindGroup, strings.TrimSpace(raw)); err != nil {
			return []ValidationError{{RuleApprovalUnsatisfiable, policyID, err.Error()}}
		}
		groups++
	}
	if groups == 0 {
		return []ValidationError{{RuleApprovalUnsatisfiable, policyID,
			"approval_challenge names no eligible group"}}
	}
	return nil
}

// validateApprovalRealms rejects an approval clause whose eligible groups all
// resolve in realms where no person can answer.
//
// Without it the eligible count is inflated by subjects that cannot approve,
// the challenge is issued, and it parks until it times out. Timeout is always
// deny, so the outcome is a denial reached after a delay rather than at
// decision time, which is strictly worse for everyone.
func validateApprovalRealms(policyID string, o contract.Obligation, interactive map[string]bool) []ValidationError {
	if len(interactive) == 0 {
		return nil
	}
	var nonInteractive []string
	any := false
	for _, raw := range strings.Split(o.Params["eligible"], ",") {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		id, err := contract.ParseID(contract.KindGroup, raw)
		if err != nil {
			continue
		}
		any = true
		if ok, declared := interactive[id.Qualifier]; declared && !ok {
			nonInteractive = append(nonInteractive, raw)
		}
	}
	if !any || len(nonInteractive) == 0 {
		return nil
	}
	if len(nonInteractive) == countEligible(o) {
		return []ValidationError{{RulePoolNotInteractive, policyID, fmt.Sprintf(
			"every eligible group (%s) resolves in a realm declared non-interactive, so no person can discharge this approval",
			strings.Join(nonInteractive, ", "))}}
	}
	return nil
}

func countEligible(o contract.Obligation) int {
	n := 0
	for _, raw := range strings.Split(o.Params["eligible"], ",") {
		if strings.TrimSpace(raw) != "" {
			n++
		}
	}
	return n
}

// validateCondition applies FIELD_NOT_IN_SCHEMA and AUTHORITY_FROM_UNTRUSTED.
func validateCondition(policyID string, authority contract.Authority, c Condition, schema map[string]AttributeSchema) []ValidationError {
	var errs []ValidationError
	for _, p := range c.Paths() {
		if err := contract.ValidateAttributePath(p); err != nil {
			errs = append(errs, ValidationError{RuleFieldNotInSchema, policyID, err.Error()})
			continue
		}
		if _, ok := schema[p]; !ok {
			errs = append(errs, ValidationError{RuleFieldNotInSchema, policyID,
				fmt.Sprintf("condition references %q, which is not declared in the attribute schema", p)})
		}
	}
	errs = append(errs, checkAuthorityRule(policyID, authority, c)...)
	if readsAttributeValue(c.Kind) && c.Path != "" {
		schemaEntry, declared := schema[c.Path]
		switch {
		case declared && schemaEntry.Optional && c.OnAbsent == AbsentUnspecified:
			errs = append(errs, ValidationError{RuleAbsenceNotHandled, policyID, fmt.Sprintf(
				"the condition reads %q, which the schema marks optional, without declaring what absence means; "+
					"known absence may produce a non-match only where the policy says so explicitly", c.Path)})
		case contract.NamespaceOf(c.Path) == contract.NsArgs && c.OnAbsent == AbsentIsNoMatch:
			// Caller-supplied absence is caller-CONTROLLED absence. Letting it
			// resolve a condition determinately hands the caller a way to
			// decide that a constraint does not apply, by omitting a field.
			errs = append(errs, ValidationError{RuleAbsenceNotHandled, policyID, fmt.Sprintf(
				"the condition reads the caller-supplied attribute %q and treats its absence as a non-match; "+
					"a caller can then suppress the condition by omitting the field, so absence of caller data is always unknown", c.Path)})
		case declared && !schemaEntry.Optional && c.OnAbsent != AbsentUnspecified:
			errs = append(errs, ValidationError{RuleAbsenceNotHandled, policyID, fmt.Sprintf(
				"the condition declares absence handling for %q, which the schema marks required; "+
					"the absence of a required attribute is a data defect and is always unknown", c.Path)})
		case c.OnAbsent != AbsentUnspecified && c.OnAbsent != AbsentIsNoMatch && c.OnAbsent != AbsentIsUnknown:
			errs = append(errs, ValidationError{RuleAbsenceNotHandled, policyID, fmt.Sprintf(
				"absence handling %q is not declared", c.OnAbsent)})
		}
	}
	if !readsAttributeValue(c.Kind) && c.OnAbsent != AbsentUnspecified {
		errs = append(errs, ValidationError{RuleAbsenceNotHandled, policyID, fmt.Sprintf(
			"condition kind %q does not consult absence handling, so declaring it is misleading", c.Kind)})
	}
	switch c.Kind {
	case CondTrue:
	case CondCompare:
		if !validOps[c.Op] {
			errs = append(errs, ValidationError{RuleMalformedCondition, policyID,
				fmt.Sprintf("comparison operator %q is not declared", c.Op)})
		}
		if c.Path == "" {
			errs = append(errs, ValidationError{RuleMalformedCondition, policyID, "compare has no attribute path"})
		}
	case CondMember:
		if c.Path == "" || c.Literal == nil {
			errs = append(errs, ValidationError{RuleMalformedCondition, policyID, "member requires a path and a literal"})
		}
	case CondSuperset, CondIntersects:
		if c.Path == "" || len(c.Literals) == 0 {
			errs = append(errs, ValidationError{RuleMalformedCondition, policyID,
				fmt.Sprintf("%s requires a path and at least one literal", c.Kind)})
		}
	case CondAttrCompare:
		if c.Path == "" || c.RightPath == "" {
			errs = append(errs, ValidationError{RuleMalformedCondition, policyID, "attr_compare requires two attribute paths"})
		}
		if !validOps[c.Op] {
			errs = append(errs, ValidationError{RuleMalformedCondition, policyID,
				fmt.Sprintf("comparison operator %q is not declared", c.Op)})
		}
	case CondAnd, CondOr:
		if len(c.Operands) < 2 {
			errs = append(errs, ValidationError{RuleMalformedCondition, policyID,
				fmt.Sprintf("%s requires at least two operands, got %d", c.Kind, len(c.Operands))})
		}
	case CondNot:
		if len(c.Operands) != 1 {
			errs = append(errs, ValidationError{RuleMalformedCondition, policyID,
				fmt.Sprintf("not requires exactly one operand, got %d", len(c.Operands))})
		}
	default:
		errs = append(errs, ValidationError{RuleMalformedCondition, policyID,
			fmt.Sprintf("condition kind %q is not declared", c.Kind)})
	}
	for _, o := range c.Operands {
		errs = append(errs, validateCondition(policyID, authority, o, schema)...)
	}
	return errs
}

// checkAuthorityRule rejects a condition in which untrusted input establishes
// authority.
//
// Untrusted input may be BOUNDED. It may never ESTABLISH AUTHORITY. Bounding
// looks like `args.amount_cents <= 500000` and is the entire point of an
// argument limit. Establishing authority looks like
// `args.ticket_owner == principal.id`, which reads as "allow if the requester
// claims they own it": anything that can influence the model, an injected
// ticket body or a poisoned retrieval hit, can make that claim, and the policy
// passes every test written against well-behaved agents.
func checkAuthorityRule(policyID string, authority contract.Authority, c Condition) []ValidationError {
	// An INSPECTION policy is exempt, and the exemption is narrow enough to
	// state precisely: it can neither grant nor deny, so nothing can be
	// ESTABLISHED through it. Comparing a caller-supplied amount against a
	// platform-computed baseline is how anomaly detection works, and refusing
	// it would make the whole inspection plane inexpressible in order to
	// protect an authority decision an inspection policy cannot reach. Its
	// obligations still take effect, which is why the authoring validator
	// separately refuses an approval or budget obligation on one.
	if authority == contract.AuthorityInspection {
		return nil
	}
	switch c.Kind {
	case CondAttrCompare:
		// The rule fires on EVERY operator, not only on identity.
		//
		// An earlier version exempted ordering comparisons on the grounds that
		// a bound on untrusted input is legitimate. It is, against a LITERAL.
		// Against a trusted attribute it is not a bound, for two reasons. A
		// conjunction of two ordering comparisons over one operand pair is
		// identity written in two lines, so the exemption was a hole in the
		// shape of a syntax the rule declared safe. And a limit that lives in
		// the directory is the same hole more slowly: whoever can edit that
		// attribute can raise their own cap without touching a policy. A
		// per-tenant bound belongs in a governed attribute the typed control
		// plane can hold to the policy change path, which does not exist yet,
		// so until it does the answer is a literal.
		left, right := contract.NamespaceOf(c.Path), contract.NamespaceOf(c.RightPath)
		if (left == contract.NsArgs && right.Trusted()) || (right == contract.NsArgs && left.Trusted()) {
			return []ValidationError{{RuleAuthorityFromUntrusted, policyID, fmt.Sprintf(
				"%q is caller-supplied and is compared against the trusted term %q; untrusted input may be bounded against a literal, never against a trusted attribute, because a conjunction of two ordering comparisons over one pair is identity and a limit held in the directory is editable by whoever holds the directory",
				c.Path, c.RightPath)}}
		}
	case CondMember, CondSuperset, CondIntersects, CondCompare:
		if contract.NamespaceOf(c.Path) != contract.NsArgs {
			return nil
		}
		lits := c.Literals
		if c.Literal != nil {
			lits = append(append([]any(nil), lits...), c.Literal)
		}
		for _, l := range lits {
			s, ok := l.(string)
			if !ok {
				continue
			}
			// A group or role literal on the other side of a caller-supplied
			// term is the same hole with the trusted operand written out by
			// hand instead of read from an attribute.
			if _, err := contract.ParseID(contract.KindGroup, s); err == nil {
				return []ValidationError{{RuleAuthorityFromUntrusted, policyID, fmt.Sprintf(
					"caller-supplied term %q is compared against the group literal %q; group membership is an authority fact and cannot be asserted by the caller",
					c.Path, s)}}
			}
		}
	}
	return nil
}
