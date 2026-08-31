package pdp

import (
	"context"
	"crypto/ed25519"
	"testing"
	"time"

	"axonflow/platform/decision/contract"
)

func testDoc() *Document {
	return &Document{
		Root:    RootSystem,
		Version: 1,
		Attributes: []AttributeSchema{
			{Path: "principal.id", Type: TypeString},
			{Path: "principal.groups", Type: TypeArray},
			{Path: "action.id", Type: TypeString},
			{Path: "action.tags", Type: TypeArray},
			{Path: "args.amount_cents", Type: TypeNumber},
			{Path: "resource.owner", Type: TypeString},
		},
		Policies: []Policy{
			{
				ID:        "P1",
				Authority: contract.AuthorityPermission,
				Root:      RootSystem,
				Scope:     Scope{Groups: []contract.ID{contract.MustParseID(contract.KindGroup, "Group::realm_ws:support-tier2")}},
				Actions:   ActionSelector{Actions: []contract.ID{contract.MustParseID(contract.KindAction, "Action::stripe.create_refund")}},
				Where: And(
					Compare("args.amount_cents", OpLe, 500000),
					AttrEq("resource.owner", "principal.id"),
				),
			},
			{
				ID:        "C1",
				Authority: contract.AuthorityConstraint,
				Root:      RootSystem,
				Scope:     Scope{Organization: true},
				Actions:   ActionSelector{RequiredTags: []string{"spend"}},
				Where:     Compare("args.amount_cents", OpGt, 100000),
			},
		},
	}
}

func buildTestEngine(t *testing.T, d *Document) *Engine {
	t.Helper()
	b, err := BuildBundle(d)
	if err != nil {
		t.Fatalf("BuildBundle: %v", err)
	}
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if err := b.Sign("k1", priv); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	ts := NewTrustStore()
	ts.Authorize(d.Root, "k1", pub)
	e, err := NewEngine(context.Background(), EngineConfig{
		Bundles:       []*Bundle{b},
		Documents:     []*Document{d},
		TrustStore:    ts,
		PayloadLeaves: []string{"response.ssn", "response.name"},
		PEP:           &contract.PEPProfile{ID: "test-pep"},
		Registry: &Registry{
			Actions: map[string]ActionEntry{
				"Action::stripe.create_refund": {
					ID:                 contract.MustParseID(contract.KindAction, "Action::stripe.create_refund"),
					Tags:               []string{"spend"},
					MaxDelegationDepth: 3,
					Arguments:          map[string]ValueType{"amount_cents": TypeNumber},
				},
			},
			Realms: map[string]bool{"realm_ws": true, "jira": true},
		},
	})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	return e
}

func testRequest(attrs contract.AttributeSet) *contract.Request {
	now := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)
	principal := contract.MustParseID(contract.KindPrincipal, "User::realm_ws:alice")
	identity := contract.AttributeSet{}
	for _, p := range []string{"principal.id", "principal.groups"} {
		if a, ok := attrs[p]; ok {
			identity[p] = a
			delete(attrs, p)
		}
	}
	return &contract.Request{
		RequestID:    "req_1",
		Organization: contract.MustParseID(contract.KindOrganization, "Organization::org_acme"),
		Principal:    principal,
		Action:       contract.MustParseID(contract.KindAction, "Action::stripe.create_refund"),
		Resource:     contract.MustParseID(contract.KindResource, "Ticket::jira:T-1"),
		Context:      contract.Context{ActorChain: []contract.Actor{{ID: principal, Attributes: identity}}},
		Snapshot: contract.Snapshot{
			SchemaVersion: contract.SchemaVersion,
			PolicyBundle:  "sha256:deadbeef",
		},
		Attributes:  attrs,
		EvaluatedAt: now,
	}
}

func baseAttrs() contract.AttributeSet {
	now := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)
	return contract.AttributeSet{
		"principal.id":      contract.Known("User::realm_ws:alice", contract.ProvAuthentication, 1, now),
		"principal.groups":  contract.Known([]any{"Group::realm_ws:support-tier2"}, contract.ProvDirectory, 83, now),
		"action.id":         contract.Known("Action::stripe.create_refund", contract.ProvPlatform, 18, now),
		"action.tags":       contract.Known([]any{"spend", "irreversible"}, contract.ProvPlatform, 18, now),
		"args.amount_cents": contract.Known(30000, contract.ProvCaller, 0, now),
		"resource.owner":    contract.Known("User::realm_ws:alice", contract.ProvResource, 14, now),
	}
}

// TestSmokePermit is the end-to-end proof that the restricted capabilities
// document, the generated Rego, the helper module and the Go combiner agree.
func TestSmokePermit(t *testing.T) {
	e := buildTestEngine(t, testDoc())
	dec, err := e.Decide(context.Background(), testRequest(baseAttrs()))
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if dec.Authorization != contract.AuthzPermit || dec.State != contract.StateAllow {
		t.Fatalf("want permit/ALLOW, got %s/%s reason=%s", dec.Authorization, dec.State, dec.Reason)
	}
	if len(dec.Determining.MatchedPermissions) != 1 || dec.Determining.MatchedPermissions[0] != "P1" {
		t.Fatalf("want P1 matched, got %v", dec.Determining.MatchedPermissions)
	}
}

// TestNilRequestBecomesIndeterminate pins the Decider contract at its outer
// boundary. Invalid input is an authorization outcome, not a panic a caller
// must remember to recover and map to fail closed.
func TestNilRequestBecomesIndeterminate(t *testing.T) {
	e := buildTestEngine(t, testDoc())
	dec, err := e.Decide(context.Background(), nil)
	if err != nil {
		t.Fatalf("Decide(nil) returned an error instead of an indeterminate decision: %v", err)
	}
	if dec.Authorization != contract.AuthzIndeterminate || dec.State != contract.StateError {
		t.Fatalf("Decide(nil) = authorization %q state %q, want indeterminate/ERROR", dec.Authorization, dec.State)
	}
	if dec.Reason != contract.ReasonInvalidInput {
		t.Fatalf("Decide(nil) reason = %q, want %q", dec.Reason, contract.ReasonInvalidInput)
	}
	if dec.DecisionID == "" || dec.RequestID != "req_unvalidated" {
		t.Fatalf("Decide(nil) did not produce stable shell identifiers: decision=%q request=%q", dec.DecisionID, dec.RequestID)
	}
}

// TestSmokeUnknownConstraintIsIndeterminate is the case the whole tri-state
// model exists for: an unevaluable constraint must not read as inapplicable.
func TestSmokeUnknownConstraintIsIndeterminate(t *testing.T) {
	attrs := baseAttrs()
	attrs["args.amount_cents"] = contract.Unknown(contract.ReasonResolutionFailed, contract.ProvCaller, 0, time.Now())
	e := buildTestEngine(t, testDoc())
	dec, err := e.Decide(context.Background(), testRequest(attrs))
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if dec.Authorization != contract.AuthzIndeterminate || dec.Reason != contract.ReasonUnknownConstraint {
		t.Fatalf("want indeterminate/unknown_constraint, got %s/%s", dec.Authorization, dec.Reason)
	}
	if dec.State != contract.StateError {
		t.Fatalf("want ERROR state, got %s", dec.State)
	}
}

// TestSmokeMissingAttributeDoesNotVanish proves that an attribute the Policy
// Information Point never produced reaches the combiner as a tagged unknown
// rather than as a Rego undefined that reads like a non-match.
func TestSmokeMissingAttributeDoesNotVanish(t *testing.T) {
	attrs := baseAttrs()
	delete(attrs, "args.amount_cents")
	e := buildTestEngine(t, testDoc())
	dec, err := e.Decide(context.Background(), testRequest(attrs))
	if err != nil {
		t.Fatalf("Decide: %v", err)
	}
	if dec.Authorization != contract.AuthzIndeterminate {
		t.Fatalf("a missing attribute must not resolve; got %s/%s", dec.Authorization, dec.Reason)
	}
	found := false
	for _, u := range dec.Determining.Unknown {
		if u.PolicyID == "C1" && u.Reason == contract.ReasonNotSupplied {
			found = true
		}
	}
	if !found {
		t.Fatalf("want C1 unknown with attribute_not_supplied, got %+v", dec.Determining.Unknown)
	}
}

// TestRestrictedCapabilitiesExcludeSideEffects proves the capabilities document
// cannot reach the network, the clock or randomness.
func TestRestrictedCapabilitiesExcludeSideEffects(t *testing.T) {
	caps := RestrictedCapabilities()
	present := map[string]bool{}
	for _, b := range caps.Builtins {
		present[b.Name] = true
	}
	for _, forbidden := range ForbiddenBuiltinExamples {
		if present[forbidden] {
			t.Errorf("built-in %q is reachable from policy", forbidden)
		}
	}
	if len(caps.Builtins) != len(allowedBuiltins) {
		t.Errorf("capabilities carry %d built-ins, allow list declares %d", len(caps.Builtins), len(allowedBuiltins))
	}
}
