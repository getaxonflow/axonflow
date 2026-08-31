package authoring

import (
	"fmt"
	"sort"
	"strings"

	"axonflow/platform/decision/pdp"
)

// Severity separates a refusal from a warning.
//
// The distinction is carried in data rather than in the caller's head because
// the source specification's save-time table has both, and collapsing them in
// either direction is a real product defect. Promoting every warning to a
// refusal makes a legitimate document unsavable: a group-scoped policy written
// before the directory connector is wired up is an ordinary intermediate state.
// Demoting every refusal to a warning is worse, and is the state the legacy
// policy tables are in.
type Severity string

const (
	// SeverityReject blocks the save. The document cannot be stored, compiled,
	// signed or published while a rejection stands.
	SeverityReject Severity = "reject"
	// SeverityWarn is surfaced and recorded and does not block. Every warning
	// here describes a policy that is well formed and cannot match, which is
	// the author's mistake to make knowingly.
	SeverityWarn Severity = "warn"
)

// Reason codes owned by this package. The relayed pdp rule names are NOT
// duplicated here; they are referenced through pdp's own constants in the
// declaration table below, so renaming one there fails this compilation rather
// than silently orphaning a code a portal is rendering.
const (
	// CodeActionNotRegistered rejects a selector naming an action the registry
	// does not contain. The legacy evaluators matched on terminal names and
	// string heuristics, so a typo produced a policy that quietly governed
	// nothing.
	CodeActionNotRegistered = "ACTION_NOT_REGISTERED"
	// CodeSelectorMatchesNoRegisteredAction rejects a selector whose required
	// tags no registered action carries. It is the catalog-aware half of
	// pdp.RuleEmptySelector: pdp can see that a selector names nothing, and
	// only the registry can see that a selector names something that does not
	// exist.
	CodeSelectorMatchesNoRegisteredAction = "SELECTOR_MATCHES_NO_REGISTERED_ACTION"
	// CodeArgumentNotInActionSchema rejects a condition reading a caller
	// argument that is not in the declared argument schema of every action the
	// selector reaches. This is the source specification's FIELD_NOT_IN_SCHEMA
	// as written ("absent from the schema of any tool the selector matches");
	// pdp checks the condition against the document's attribute list, which is
	// the other half of the same rule and cannot see the registry.
	CodeArgumentNotInActionSchema = "ARGUMENT_NOT_IN_ACTION_SCHEMA"
	// CodeLevelNotDeclared rejects a read of resource.<level>.* where the
	// level is not an ancestor of every resource type the selector reaches. An
	// undeclared level resolves to nothing, and a constraint scoped by nothing
	// is a constraint that silently does not apply.
	CodeLevelNotDeclared = "LEVEL_NOT_DECLARED"
	// CodeScopeRequiresRecursion rejects a containment scope over a resource
	// type whose hierarchy is not recursive. The closure would always be
	// empty, so the scope never matches and the policy reads as active.
	CodeScopeRequiresRecursion = "SCOPE_REQUIRES_RECURSION"
	// CodeRealmNotDeclared rejects a scope naming a realm the registry does
	// not declare. A validly formed identifier from an undeclared realm is not
	// a trusted identifier, and admitting one lets a policy be scoped to a
	// population nothing vouches for.
	CodeRealmNotDeclared = "REALM_NOT_DECLARED"
	// CodeGroupScopeWithoutGraph warns that a policy is scoped to a group in a
	// realm with no group graph. The closure is authoritatively empty there, so
	// the policy can never match and the author probably meant to scope to the
	// principal.
	CodeGroupScopeWithoutGraph = "GROUP_SCOPE_WITHOUT_GRAPH"
	// CodeObligationConflict rejects obligations that will certainly co-apply
	// and that the family algebra refuses to compose. Detecting it at save time
	// matters because the runtime behaviour is a denial: the composition step
	// denies rather than silently picking one, so an undetected conflict is an
	// action that is authorized by policy and refused in production.
	CodeObligationConflict = "OBLIGATION_CONFLICT"
	// CodeDisclosureTargetNotALeaf rejects a disclosure transform whose target
	// covers no declared payload leaf of any action the selector reaches. A
	// redaction that lands on nothing is indistinguishable at runtime from a
	// redaction that was applied.
	CodeDisclosureTargetNotALeaf = "DISCLOSURE_TARGET_NOT_A_LEAF"
	// CodeConstraintNeverBinds rejects a constraint that is structurally
	// incapable of binding: its exception is unconditional, or its condition is
	// the negation of the unconditional truth. It is this model's form of the
	// source specification's CEILING_CAPS_PERMIT, which is inexpressible here
	// because an ADR-065 constraint has no verdict field to set to permit.
	CodeConstraintNeverBinds = "CONSTRAINT_NEVER_BINDS"
	// CodeDeadPermission warns that a permission is wholly suppressed by an
	// unconditional non-pierceable constraint of at least its scope and action
	// reach. The permission is well formed and can never produce a permit.
	CodeDeadPermission = "DEAD_PERMISSION"
	// CodeCatalogDisagreement rejects a document whose derived registry copy
	// disagrees with the catalog it is being validated against. The copy exists
	// because the compiled bundle has to be self contained; this rule is what
	// stops the copy becoming a second, editable source of truth.
	CodeCatalogDisagreement = "CATALOG_DISAGREEMENT"
	// CodeEnvelopeInvalid rejects a malformed authoring envelope: an
	// unrecognised api_version, a missing document identifier, a
	// non-positive version, or a version that does not advance the version it
	// supersedes.
	CodeEnvelopeInvalid = "DOCUMENT_ENVELOPE_INVALID"
	// CodeApproverIsAuthor rejects a publication whose approver set does not
	// contain an approver distinct from the author. ADR-065 requires the
	// configured separation of author and approver duties at activation, and
	// self-approval is the way that requirement is usually lost.
	CodeApproverIsAuthor = "APPROVER_IS_AUTHOR"
)

// CheckDeclaration is one declared save-time check. Keeping the set as data
// rather than as a switch is what lets a test enumerate it, assert every code
// has a case that fires and a mutant that kills the case, and assert that a
// code cannot be added without a description an operator can read.
type CheckDeclaration struct {
	Code     string   `json:"code"`
	Severity Severity `json:"severity"`
	// Summary is rendered verbatim by a portal beside the offending policy. It
	// says what was refused, not what the implementation did.
	Summary string `json:"summary"`
	// FromPDP marks a check the deterministic PDP owns and this layer relays.
	// A relayed check is not reimplemented here.
	FromPDP bool `json:"from_pdp"`
}

// declaredChecks is the complete active save-time check set.
var declaredChecks = []CheckDeclaration{
	// Relayed from the PDP's own authoring validator. These are listed rather
	// than reimplemented, and the list is held to pdp.AllRules by a test, so a
	// rule added there that nothing relays fails a named assertion instead of
	// becoming a rejection with no description.
	{pdp.RuleAuthorityFromUntrusted, SeverityReject, "Caller-supplied input may be bounded against a literal, never compared against a trusted term: that reads as \"allow if the requester says so\".", true},
	{pdp.RuleFieldNotInSchema, SeverityReject, "A condition references an attribute that is not declared in the document's attribute schema.", true},
	{pdp.RulePermissionEmitsDeny, SeverityReject, "A permission policy can only widen. It cannot attach obligations and cannot declare a break-glass pierce.", true},
	{pdp.RuleConstraintObligations, SeverityReject, "A constraint policy can only restrict. Split it into a constraint and a requirement that share the condition.", true},
	{pdp.RuleInspectionGrants, SeverityReject, "An inspection policy cannot grant, cannot be mandatory, and cannot attach an obligation whose family can refuse or hold a request.", true},
	{pdp.RuleEmptySelector, SeverityReject, "A selector that names no action, no principal or no obligation does nothing.", true},
	{pdp.RuleApprovalUnsatisfiable, SeverityReject, "An approval clause needs a positive quorum and at least one well-formed eligible group.", true},
	{pdp.RuleOrgPolicyPiercesSystem, SeverityReject, "Break-glass piercing is declared by the authority that owns the constraint, and an organization root cannot declare it.", true},
	{pdp.RuleMalformedCondition, SeverityReject, "A condition, obligation or authority is structurally malformed.", true},
	{pdp.RuleDuplicatePolicyID, SeverityReject, "A policy identifier appears more than once, so \"which policy decided this\" would be ambiguous.", true},
	{pdp.RuleRootMismatch, SeverityReject, "A policy declares a different authority root from the document that carries it.", true},
	{pdp.RulePoolNotInteractive, SeverityReject, "Every eligible group of this approval resolves in a realm where no person can answer, so the challenge could only expire.", true},
	{pdp.RuleAbsenceNotHandled, SeverityReject, "A condition over an optional attribute must say what absence means, and absence of caller-supplied data is always unknown.", true},

	// Owned by this layer. Each needs the registry, the publication actors or
	// a cross-policy view, none of which a single compiled document has.
	{CodeActionNotRegistered, SeverityReject, "The action selector names an action that is not in the action registry.", false},
	{CodeSelectorMatchesNoRegisteredAction, SeverityReject, "The action selector requires a tag combination that no registered action carries, so it governs nothing.", false},
	{CodeArgumentNotInActionSchema, SeverityReject, "A condition reads a caller argument that is not in the declared argument schema of every action this policy reaches.", false},
	{CodeLevelNotDeclared, SeverityReject, "A condition reads a resource hierarchy level that is not declared for every resource type this policy reaches.", false},
	{CodeScopeRequiresRecursion, SeverityReject, "A containment scope is used against a resource type whose hierarchy is not recursive, so the closure is always empty.", false},
	{CodeRealmNotDeclared, SeverityReject, "The policy is scoped to a principal or group in a realm the registry does not declare.", false},
	{CodeGroupScopeWithoutGraph, SeverityWarn, "The policy is scoped to a group in a realm with no group graph, so it can never match. Scope it to the principal instead.", false},
	{CodeObligationConflict, SeverityReject, "Two obligations that will certainly apply together cannot be composed, so this policy would deny at runtime rather than enforce.", false},
	{CodeDisclosureTargetNotALeaf, SeverityReject, "A disclosure transform targets a field that is not a declared payload leaf of any action this policy reaches.", false},
	{CodeConstraintNeverBinds, SeverityReject, "The constraint is structurally incapable of binding, which is a control in name only.", false},
	{CodeDeadPermission, SeverityWarn, "An unconditional non-pierceable constraint of wider reach suppresses this permission entirely, so it can never produce a permit.", false},
	{CodeCatalogDisagreement, SeverityReject, "The registry facts carried in the document disagree with the registry it is being validated against.", false},
	{CodeEnvelopeInvalid, SeverityReject, "The authoring envelope is malformed: check api_version, the document identifier and the version.", false},
	{CodeApproverIsAuthor, SeverityReject, "Publication requires an approver who is not the author.", false},
}

// retiredCheck records a source-specification check that ADR-065 does not
// carry forward, and why. It is data rather than prose so that a test can
// assert every retired code is genuinely absent from the active set: a
// disposition nothing executes is a claim, and the point of recording one is
// that it stops being re-argued from memory.
type retiredCheck struct {
	Code   string
	Reason string
}

var retiredChecks = []retiredCheck{
	{
		Code: "ESCALATE_IN_ALLOW_POSTURE",
		Reason: "The source check warns that an escalating grant on a tool whose posture is already permit is a no-op. " +
			"ADR-065 removes the per-tool unmatched=Permit posture entirely and owns default deny, so there is no allow " +
			"posture for an escalation to be a no-op against. The check is not weakened, it is unreachable.",
	},
	{
		Code: "CEILING_CAPS_PERMIT",
		Reason: "The source check rejects a ceiling whose cap is Permit. An ADR-065 constraint has no verdict field: a " +
			"matched constraint is a deny by construction, so the shape cannot be written. The product intent, a control " +
			"that cannot control, is re-expressed as " + CodeConstraintNeverBinds + " over the shapes that remain expressible.",
	},
	{
		Code: "GRANT_EMITS_DENY",
		Reason: "Re-expressed as " + pdp.RulePermissionEmitsDeny + " and relayed. The name changes with the vocabulary: " +
			"storage, APIs and code use permission and constraint, and the UI may call them grants and ceilings.",
	},
	{
		Code: "SEGMENT_SCOPE_WITHOUT_GRAPH",
		Reason: "Re-expressed as " + CodeGroupScopeWithoutGraph + ". ADR-065 replaces segments with canonical realm-qualified " +
			"groups, and keeps the source disposition of warning rather than rejection.",
	},
	{
		Code:   "DEAD_GRANT",
		Reason: "Re-expressed as " + CodeDeadPermission + ", keeping the source disposition of warning rather than rejection.",
	},
}

// AllChecks returns every active declared check, ordered by code.
func AllChecks() []CheckDeclaration {
	out := append([]CheckDeclaration(nil), declaredChecks...)
	sort.Slice(out, func(i, j int) bool { return out[i].Code < out[j].Code })
	return out
}

// RetiredChecks returns the source-specification checks ADR-065 does not carry
// forward, with the reason each was retired.
func RetiredChecks() map[string]string {
	out := make(map[string]string, len(retiredChecks))
	for _, r := range retiredChecks {
		out[r.Code] = r.Reason
	}
	return out
}

var checkIndex = func() map[string]CheckDeclaration {
	out := make(map[string]CheckDeclaration, len(declaredChecks))
	for _, c := range declaredChecks {
		out[c.Code] = c
	}
	return out
}()

// Finding is one save-time result. It is what a portal renders and what an
// automated caller branches on, so it carries a stable code, a severity, the
// policy it is about and a sentence written for a person.
type Finding struct {
	Code     string   `json:"code"`
	Severity Severity `json:"severity"`
	PolicyID string   `json:"policy_id,omitempty"`
	// Summary is the declared, code-level explanation. It is filled from the
	// declaration table rather than written at the call site so that one code
	// cannot acquire two explanations.
	Summary string `json:"summary"`
	// Detail names the specific offending value. It is the half a person needs
	// in order to fix the policy, and it is deliberately separate from Summary
	// so a portal can group by code without losing the specifics.
	Detail string `json:"detail"`
}

func (f Finding) String() string {
	if f.PolicyID == "" {
		return fmt.Sprintf("%s [%s]: %s", f.Code, f.Severity, f.Detail)
	}
	return fmt.Sprintf("%s [%s] policy %q: %s", f.Code, f.Severity, f.PolicyID, f.Detail)
}

// newFinding builds a finding from the declaration table.
//
// It PANICS on an undeclared code, and that is the point rather than an
// oversight. An undeclared code is unreachable in a built binary because every
// call site passes one of the constants above, so the panic can only fire
// during development, where the alternative is a finding that reaches a portal
// with an empty severity and no explanation. A reason code with nothing behind
// it is exactly the defect this table exists to prevent.
func newFinding(code, policyID, detail string) Finding {
	decl, ok := checkIndex[code]
	if !ok {
		panic(fmt.Sprintf("authoring: reason code %q is not declared in the check table", code))
	}
	return Finding{Code: decl.Code, Severity: decl.Severity, PolicyID: policyID, Summary: decl.Summary, Detail: detail}
}

// Findings is an ordered, complete result set.
type Findings []Finding

// Rejected reports whether any finding blocks the save.
func (f Findings) Rejected() bool {
	for _, x := range f {
		if x.Severity == SeverityReject {
			return true
		}
	}
	return false
}

// Rejections returns only the blocking findings.
func (f Findings) Rejections() Findings {
	var out Findings
	for _, x := range f {
		if x.Severity == SeverityReject {
			out = append(out, x)
		}
	}
	return out
}

// Warnings returns only the non-blocking findings.
func (f Findings) Warnings() Findings {
	var out Findings
	for _, x := range f {
		if x.Severity == SeverityWarn {
			out = append(out, x)
		}
	}
	return out
}

// Has reports whether a code is present.
func (f Findings) Has(code string) bool {
	for _, x := range f {
		if x.Code == code {
			return true
		}
	}
	return false
}

// Codes returns the distinct codes present, sorted.
func (f Findings) Codes() []string {
	set := map[string]struct{}{}
	for _, x := range f {
		set[x.Code] = struct{}{}
	}
	out := make([]string, 0, len(set))
	for c := range set {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

// sorted returns the findings in a stable order so that two runs over one
// document produce the same result set. A validator whose output order depends
// on map iteration cannot be diffed between two saves, which is what the
// portal's dry-run needs to do.
func (f Findings) sorted() Findings {
	out := append(Findings(nil), f...)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].PolicyID != out[j].PolicyID {
			return out[i].PolicyID < out[j].PolicyID
		}
		if out[i].Code != out[j].Code {
			return out[i].Code < out[j].Code
		}
		return out[i].Detail < out[j].Detail
	})
	return out
}

// Error renders the blocking findings as one error, or nil if none block.
func (f Findings) Error() error {
	rej := f.Rejections()
	if len(rej) == 0 {
		return nil
	}
	msgs := make([]string, 0, len(rej))
	for _, x := range rej {
		msgs = append(msgs, x.String())
	}
	return fmt.Errorf("authoring: the document was refused:\n  %s", strings.Join(msgs, "\n  "))
}
