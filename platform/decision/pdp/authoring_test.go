package pdp

import (
	"context"
	"crypto/ed25519"
	"strings"
	"testing"
	"time"

	"axonflow/platform/decision/contract"
)

func authoringDoc(policies ...Policy) *Document {
	return &Document{
		Root: RootOrganization, Version: 1,
		Attributes: []AttributeSchema{
			{Path: "principal.id", Type: TypeString},
			{Path: "principal.refund_limit", Type: TypeNumber},
			{Path: "args.amount_cents", Type: TypeNumber, Optional: true},
			{Path: "args.ticket_owner", Type: TypeString, Optional: true},
			{Path: "resource.owner", Type: TypeString, Optional: true},
		},
		Policies: policies,
	}
}

func permissionOver(where Condition) Policy {
	return Policy{
		ID: "P", Authority: contract.AuthorityPermission, Root: RootOrganization,
		Scope: Scope{Organization: true}, Actions: ActionSelector{Any: true}, Where: where,
	}
}

func rulesFired(errs []ValidationError) []string {
	out := make([]string, 0, len(errs))
	for _, e := range errs {
		out = append(out, e.Rule)
	}
	return out
}

func firedRule(errs []ValidationError, rule string) bool {
	for _, e := range errs {
		if e.Rule == rule {
			return true
		}
	}
	return false
}

// TestAuthorityRuleIsNotEvadedByOrderingComparisons pins the widened rule.
//
// An earlier version fired only on identity operators, on the reasoning that an
// ordering comparison is a bound. A conjunction of two ordering comparisons
// over one operand pair IS identity, written in two lines, so the exemption was
// a hole in the shape of a syntax the rule declared safe. It is also the same
// hole more slowly on its own: a limit held in a directory attribute is
// editable by whoever holds the directory.
func TestAuthorityRuleIsNotEvadedByOrderingComparisons(t *testing.T) {
	for name, where := range map[string]Condition{
		"identity against a trusted attribute": AttrEq("args.ticket_owner", "principal.id"),
		"the inverse identity":                 AttrCompare("args.ticket_owner", OpNe, "principal.id"),
		"identity written as two bounds": And(
			AttrCompare("args.ticket_owner", OpLe, "principal.id"),
			AttrCompare("args.ticket_owner", OpGe, "principal.id")),
		"a single ordering bound against a directory attribute": AttrCompare(
			"args.amount_cents", OpLe, "principal.refund_limit"),
		"the comparison written the other way round": AttrCompare(
			"principal.id", OpEq, "args.ticket_owner"),
		"buried inside a disjunction": Or(
			Compare("args.amount_cents", OpLe, 100).HandlingAbsence(AbsentIsUnknown),
			AttrEq("args.ticket_owner", "resource.owner")),
	} {
		errs := authoringDoc(permissionOver(where)).Validate()
		if !firedRule(errs, RuleAuthorityFromUntrusted) {
			t.Errorf("%s was accepted; rules fired: %v", name, rulesFired(errs))
		}
	}

	// Bounding caller input against a LITERAL stays legal, which is the entire
	// point of an argument limit, and comparing two trusted attributes stays
	// legal, which is what makes an ownership check meaningful.
	for name, where := range map[string]Condition{
		"a bound against a literal":            Compare("args.amount_cents", OpLe, 500000).HandlingAbsence(AbsentIsUnknown),
		"two trusted attributes compared":      AttrEq("resource.owner", "principal.id"),
		"an equality against a string literal": Compare("args.ticket_owner", OpEq, "SUP-42").HandlingAbsence(AbsentIsUnknown),
	} {
		errs := authoringDoc(permissionOver(where)).Validate()
		if firedRule(errs, RuleAuthorityFromUntrusted) {
			t.Errorf("%s was refused: %v", name, errs)
		}
	}

	// An INSPECTION policy is exempt, because it can neither grant nor deny, so
	// nothing can be established through it. The exemption is narrow: the
	// authoring validator separately refuses an obligation family that could
	// refuse or hold a request on one.
	inspection := authoringDoc(Policy{
		ID: "D", Authority: contract.AuthorityInspection, Root: RootOrganization,
		Scope: Scope{Organization: true}, Actions: ActionSelector{Any: true},
		Where: AttrCompare("args.amount_cents", OpGt, "principal.refund_limit"),
	}).Validate()
	if firedRule(inspection, RuleAuthorityFromUntrusted) {
		t.Errorf("an inspection policy was held to the authority rule: %v", inspection)
	}
}

// TestCallerControlledAbsenceCannotResolveACondition pins the args half of the
// absence rule.
//
// Caller-supplied absence is caller-CONTROLLED absence. Letting it resolve a
// condition determinately hands the caller a way to decide that a constraint
// does not apply, by omitting a field.
func TestCallerControlledAbsenceCannotResolveACondition(t *testing.T) {
	refused := authoringDoc(permissionOver(
		Compare("args.amount_cents", OpLe, 500000).HandlingAbsence(AbsentIsNoMatch))).Validate()
	if !firedRule(refused, RuleAbsenceNotHandled) {
		t.Errorf("a caller-supplied attribute whose absence resolves the condition was accepted: %v", rulesFired(refused))
	}
	accepted := authoringDoc(permissionOver(
		Compare("args.amount_cents", OpLe, 500000).HandlingAbsence(AbsentIsUnknown))).Validate()
	if firedRule(accepted, RuleAbsenceNotHandled) {
		t.Errorf("treating caller-supplied absence as unknown was refused: %v", accepted)
	}
	// A resolver-established absence still may resolve the condition, where the
	// policy says so.
	resource := authoringDoc(permissionOver(
		Compare("resource.owner", OpEq, "x").HandlingAbsence(AbsentIsNoMatch))).Validate()
	if firedRule(resource, RuleAbsenceNotHandled) {
		t.Errorf("a resolver-established absence handling was refused: %v", resource)
	}
}

// TestEngineBindsItsDocumentsToItsBundles pins the metadata provenance.
//
// The combiner reads which policies may be pierced, which obligations they
// attach and which are mandatory out of the DOCUMENTS, which are not signed. If
// they are not bound to the bundles they claim to be the source of, a caller
// can hand over byte-identical signed bundles and an edited document and
// suspend an unbreakable constraint through a struct nothing verified.
func TestEngineBindsItsDocumentsToItsBundles(t *testing.T) {
	doc := &Document{
		Root: RootSystem, Version: 1,
		Attributes: []AttributeSchema{{Path: "principal.id", Type: TypeString}},
		Policies: []Policy{{
			ID: "C1", Authority: contract.AuthorityConstraint, Root: RootSystem,
			Scope: Scope{Organization: true}, Actions: ActionSelector{Any: true},
			Where: Compare("principal.id", OpEq, "User::realm_ws:alice"),
		}},
	}
	b, err := BuildBundle(doc)
	if err != nil {
		t.Fatalf("building: %v", err)
	}
	pub, priv, _ := ed25519.GenerateKey(nil)
	if err := b.Sign("k", priv); err != nil {
		t.Fatalf("signing: %v", err)
	}
	ts := NewTrustStore()
	ts.Authorize(RootSystem, "k", pub)
	registry := &Registry{
		Actions: map[string]ActionEntry{"Action::a.b": {
			ID: contract.MustParseID(contract.KindAction, "Action::a.b"), MaxDelegationDepth: 2,
		}},
		Realms: map[string]bool{"realm_ws": true, "conn": true},
	}
	cfg := func(docs []*Document) EngineConfig {
		return EngineConfig{Bundles: []*Bundle{b}, Documents: docs, TrustStore: ts, Registry: registry}
	}
	if _, err := NewEngine(context.Background(), cfg([]*Document{doc})); err != nil {
		t.Fatalf("the honest configuration was refused: %v", err)
	}

	// The tamper: the same signed bundle, and a document that suspends the
	// constraint through break-glass.
	tampered := &Document{
		Root: doc.Root, Version: doc.Version, Attributes: doc.Attributes,
		Policies: []Policy{{
			ID: "C1", Authority: contract.AuthorityConstraint, Root: RootSystem,
			Scope: Scope{Organization: true}, Actions: ActionSelector{Any: true},
			Where:        Compare("principal.id", OpEq, "User::realm_ws:alice"),
			PierceableBy: []contract.ID{contract.MustParseID(contract.KindGroup, "Group::realm_ws:anyone")},
		}},
	}
	_, err = NewEngine(context.Background(), cfg([]*Document{tampered}))
	if err == nil {
		t.Fatal("an edited source document was accepted alongside the bundle it does not match")
	}
	if !strings.Contains(err.Error(), "the same policy set") {
		t.Errorf("the refusal does not explain itself: %v", err)
	}

	if _, err := NewEngine(context.Background(), cfg(nil)); err == nil {
		t.Error("a bundle with no source document at all was accepted")
	}
}

// TestAdmissionRefusesAnUndeclaredDelegationDepth pins the zero value.
//
// Reading a missing field as "unbounded" turns an incomplete registry entry
// into the most permissive setting available.
func TestAdmissionRefusesAnUndeclaredDelegationDepth(t *testing.T) {
	action := contract.MustParseID(contract.KindAction, "Action::a.b")
	principal := contract.MustParseID(contract.KindPrincipal, "User::realm_ws:alice")
	req := &contract.Request{
		RequestID:    "r",
		Organization: contract.MustParseID(contract.KindOrganization, "Organization::org_acme"),
		Principal:    principal,
		Action:       action,
		Resource:     contract.MustParseID(contract.KindResource, "Ticket::conn:T-1"),
		Context:      contract.Context{ActorChain: []contract.Actor{{ID: principal, Attributes: contract.AttributeSet{}}}},
		Snapshot:     contract.Snapshot{SchemaVersion: contract.SchemaVersion, PolicyBundle: "sha256:aa"},
		Attributes:   contract.AttributeSet{},
		EvaluatedAt:  time.Now(),
	}
	undeclared := &Registry{
		Actions: map[string]ActionEntry{action.String(): {ID: action}},
		Realms:  map[string]bool{"realm_ws": true, "conn": true},
	}
	got := undeclared.Admit(req)
	if !got.Failed {
		t.Error("an action declaring no maximum delegation depth was admitted")
	}

	declared := &Registry{
		Actions: map[string]ActionEntry{action.String(): {ID: action, MaxDelegationDepth: 1}},
		Realms:  map[string]bool{"realm_ws": true, "conn": true},
	}
	if got := declared.Admit(req); got.Failed {
		t.Errorf("a correctly declared action was refused: %s", got.Detail)
	}
}

// TestARequiredArgumentMustBeResolved pins the argument schema check.
//
// Counting the ENTRY rather than its state would let a caller satisfy a
// required field by naming it and supplying nothing.
func TestARequiredArgumentMustBeResolved(t *testing.T) {
	action := contract.MustParseID(contract.KindAction, "Action::a.b")
	principal := contract.MustParseID(contract.KindPrincipal, "User::realm_ws:alice")
	registry := &Registry{
		Actions: map[string]ActionEntry{action.String(): {
			ID: action, MaxDelegationDepth: 2,
			Arguments:         map[string]ValueType{"amount_cents": TypeNumber},
			RequiredArguments: []string{"amount_cents"},
		}},
		Realms: map[string]bool{"realm_ws": true, "conn": true},
	}
	build := func(a contract.Attribute) *contract.Request {
		return &contract.Request{
			RequestID:    "r",
			Organization: contract.MustParseID(contract.KindOrganization, "Organization::org_acme"),
			Principal:    principal,
			Action:       action,
			Resource:     contract.MustParseID(contract.KindResource, "Ticket::conn:T-1"),
			Context:      contract.Context{ActorChain: []contract.Actor{{ID: principal, Attributes: contract.AttributeSet{}}}},
			Snapshot:     contract.Snapshot{SchemaVersion: contract.SchemaVersion, PolicyBundle: "sha256:aa"},
			Attributes:   contract.AttributeSet{"args.amount_cents": a},
			EvaluatedAt:  time.Now(),
		}
	}
	now := time.Now()
	if got := registry.Admit(build(contract.Known(1, contract.ProvCaller, 0, now))); got.Failed {
		t.Errorf("a resolved required argument was refused: %s", got.Detail)
	}
	for name, a := range map[string]contract.Attribute{
		"an absent required argument":  contract.Absent(contract.ProvCaller, 0, now),
		"an unknown required argument": contract.Unknown(contract.ReasonResolutionFailed, contract.ProvCaller, 0, now),
	} {
		got := registry.Admit(build(a))
		if !got.Failed {
			t.Errorf("%s satisfied the schema", name)
		} else if got.Reason != contract.ReasonSchemaViolation {
			t.Errorf("%s was refused for the wrong reason: %s", name, got.Reason)
		}
	}
}
