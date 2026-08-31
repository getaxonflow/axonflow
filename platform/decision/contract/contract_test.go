package contract

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestIdentifierRoundTrip(t *testing.T) {
	cases := []struct {
		kind Kind
		wire string
	}{
		{KindOrganization, "Organization::org_acme"},
		{KindPrincipal, "User::realm_okta:00u123"},
		{KindPrincipal, "Agent::realm_axonflow:agent_7"},
		// A SPIFFE subject identifier contains colons of its own. Splitting on
		// the LAST colon, or on every colon, silently reinterprets it, which is
		// the reason parsing is kind-directed and takes the qualifier up to the
		// FIRST colon after the separator.
		{KindPrincipal, "Workload::realm_spiffe:spiffe://acme.example/workload/jira-bot"},
		{KindGroup, "Group::realm_okta:security"},
		{KindResource, "JiraIssue::cloud_42:FIN-17"},
		{KindAction, "Action::mcp.jira.issue.update"},
		{KindTool, "Tool::mcp.jira.update_issue"},
		{KindClient, "Client::client_prod_gateway"},
		{KindSession, "Session::ses_abc"},
	}
	for _, c := range cases {
		id, err := ParseID(c.kind, c.wire)
		if err != nil {
			t.Fatalf("parsing %q as %s: %v", c.wire, c.kind, err)
		}
		if got := id.String(); got != c.wire {
			t.Errorf("round trip of %q produced %q", c.wire, got)
		}
	}

	spiffe := MustParseID(KindPrincipal, "Workload::realm_spiffe:spiffe://acme.example/workload/jira-bot")
	if spiffe.Qualifier != "realm_spiffe" {
		t.Errorf("qualifier is %q, expected realm_spiffe", spiffe.Qualifier)
	}
	if spiffe.Local != "spiffe://acme.example/workload/jira-bot" {
		t.Errorf("the subject identifier was re-split at one of its own colons: %q", spiffe.Local)
	}
}

func TestIdentifierRejections(t *testing.T) {
	for name, tc := range map[string]struct {
		kind Kind
		wire string
	}{
		"a missing separator":                     {KindPrincipal, "User:realm:alice"},
		"a missing qualifier on a qualified kind": {KindPrincipal, "User::alice"},
		"an empty local segment":                  {KindPrincipal, "User::realm_ws:"},
		"a colon in an unqualified local":         {KindAction, "Action::a:b"},
		"an empty type":                           {KindAction, "::x"},
		"whitespace around the local":             {KindAction, "Action:: x"},
		"an unknown kind":                         {Kind("nonsense"), "X::y"},
	} {
		if _, err := ParseID(tc.kind, tc.wire); err == nil {
			t.Errorf("%s was accepted: %q as %s", name, tc.wire, tc.kind)
		}
	}
}

func TestEveryKindDeclaresItsQualification(t *testing.T) {
	for _, k := range AllKinds() {
		if _, err := IsQualifiedKind(k); err != nil {
			t.Errorf("kind %q has no declared qualification: %v", k, err)
		}
	}
	if _, err := IsQualifiedKind(Kind("invented")); err == nil {
		t.Error("an undeclared kind was accepted")
	}
}

func TestAttributeStateAndPayloadMustAgree(t *testing.T) {
	now := time.Now()
	for name, a := range map[string]Attribute{
		"the zero value":           {},
		"known with no value":      {State: StateKnown, Source: ProvPlatform},
		"known carrying a reason":  {State: StateKnown, Value: 1, Source: ProvPlatform, Reason: ReasonStale},
		"absent carrying a value":  {State: StateAbsent, Value: 1, Source: ProvPlatform},
		"unknown with no reason":   {State: StateUnknown, Source: ProvPlatform},
		"unknown carrying a value": {State: StateUnknown, Value: 1, Source: ProvPlatform, Reason: ReasonStale},
		"an undeclared reason":     {State: StateUnknown, Source: ProvPlatform, Reason: UnknownReason("invented")},
		"an undeclared state":      {State: AttrState("maybe"), Source: ProvPlatform},
		"an undeclared provenance": {State: StateAbsent, Source: Provenance("hearsay")},
	} {
		if err := a.Validate("x.y"); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	for name, a := range map[string]Attribute{
		"a resolved value": Known("v", ProvPlatform, 1, now),
		"an absent value":  Absent(ProvPlatform, 1, now),
		"an unknown value": Unknown(ReasonStale, ProvPlatform, 1, now),
	} {
		if err := a.Validate("x.y"); err != nil {
			t.Errorf("%s was rejected: %v", name, err)
		}
	}
}

func TestFreshnessBoundDowngradesToUnknown(t *testing.T) {
	now := time.Date(2026, 8, 29, 12, 0, 0, 0, time.UTC)
	fresh := Known("v", ProvDirectory, 1, now.Add(-time.Minute))
	fresh.MaxAgeSeconds = 300
	if got := fresh.AtFreshness(now); got.State != StateKnown {
		t.Errorf("a value inside its bound was downgraded to %s", got.State)
	}
	stale := Known("v", ProvDirectory, 1, now.Add(-time.Hour))
	stale.MaxAgeSeconds = 300
	got := stale.AtFreshness(now)
	if got.State != StateUnknown || got.Reason != ReasonStale {
		t.Errorf("a value outside its bound is %s/%s, expected unknown/stale", got.State, got.Reason)
	}
	if got.Value != nil {
		t.Error("a downgraded value still carries its value")
	}
	// A known value with a declared bound and no observation time cannot be
	// shown to be inside its bound, so it is not.
	undated := Known("v", ProvDirectory, 1, time.Time{})
	undated.MaxAgeSeconds = 300
	if got := undated.AtFreshness(now); got.State != StateUnknown {
		t.Errorf("an undated value with a declared bound resolved as %s", got.State)
	}
	// Absence does not go stale, and an unknown keeps its more specific reason.
	if got := Absent(ProvDirectory, 1, time.Time{}).AtFreshness(now); got.State != StateAbsent {
		t.Errorf("an absent attribute became %s", got.State)
	}
	if got := Unknown(ReasonResolutionFailed, ProvDirectory, 1, time.Time{}).AtFreshness(now); got.Reason != ReasonResolutionFailed {
		t.Errorf("an unknown attribute's reason was overwritten with %s", got.Reason)
	}
}

func TestAttributeLookupSynthesisesATaggedUnknown(t *testing.T) {
	s := AttributeSet{}
	got := s.Lookup("principal.department")
	if got.State != StateUnknown || got.Reason != ReasonNotSupplied {
		t.Fatalf("a missing attribute resolved as %s/%s, expected unknown/attribute_not_supplied", got.State, got.Reason)
	}
	if got.Source != ProvAuthentication {
		t.Errorf("the synthesised unknown carries source %q, expected the namespace default", got.Source)
	}
}

func TestNamespaceProvenanceIsEnforced(t *testing.T) {
	now := time.Now()
	// Caller-supplied data in a trusted namespace is exactly the substitution
	// the namespace split exists to make impossible.
	bad := AttributeSet{"principal.id": Known("alice", ProvCaller, 0, now)}
	if err := bad.Validate(); err == nil {
		t.Error("a caller-supplied value was accepted in the principal namespace")
	}
	worse := AttributeSet{"resource.owner": Known("alice", ProvCaller, 0, now)}
	if err := worse.Validate(); err == nil {
		t.Error("a caller-supplied value was accepted in the resource namespace")
	}
	good := AttributeSet{"args.amount_cents": Known(1, ProvCaller, 0, now)}
	if err := good.Validate(); err != nil {
		t.Errorf("caller data was rejected in its own namespace: %v", err)
	}
	if NsArgs.Trusted() {
		t.Error("the args namespace must not be trusted")
	}
	for _, ns := range []Namespace{NsPrincipal, NsAgent, NsResource, NsAction, NsEnv, NsState, NsSignal} {
		if !ns.Trusted() {
			t.Errorf("namespace %q should be trusted", ns)
		}
	}
}

func TestCanonicalJSONFixesRepresentation(t *testing.T) {
	// Key order, number spelling and unicode composition must not change the
	// digest, or two gateways that agree on a decision disagree on its identity.
	a, err := CanonicalJSON(map[string]any{"b": 1, "a": json.Number("1.0")})
	if err != nil {
		t.Fatalf("canonicalizing: %v", err)
	}
	b, err := CanonicalJSON(map[string]any{"a": 1, "b": json.Number("1e0")})
	if err != nil {
		t.Fatalf("canonicalizing: %v", err)
	}
	if string(a) != string(b) {
		t.Errorf("two spellings of one value canonicalized differently: %s vs %s", a, b)
	}
	if string(a) != `{"a":1,"b":1}` {
		t.Errorf("canonical form is %s", a)
	}

	// The same grapheme composed two ways must hash identically. The two
	// literals below are NOT the same bytes: the first carries U+00E9 and the
	// second carries U+0065 followed by the combining acute U+0301. They look
	// alike in an editor, which is exactly why a copy-paste through a
	// normalizing tool would otherwise change a decision binding.
	precomposed, err := Digest("café")
	if err != nil {
		t.Fatalf("digesting the precomposed form: %v", err)
	}
	decomposed, err := Digest("café")
	if err != nil {
		t.Fatalf("digesting the decomposed form: %v", err)
	}
	if precomposed != decomposed {
		t.Errorf("unicode composition changed the digest: %s vs %s", precomposed, decomposed)
	}
	// And a genuinely different string must NOT collide, or the assertion
	// above could pass because normalization had flattened everything.
	if different, _ := Digest("cafe"); different == precomposed {
		t.Error("normalization collapsed two different strings into one digest")
	}
}

func TestTraceProjectionCoversEveryField(t *testing.T) {
	// A field added to Trace without a row in the permission table would
	// default to invisible, which is safe, but it would also be invisible to
	// the audience that needs it and nobody would notice. Enumerating the
	// struct by reflection makes the omission an error rather than a silence.
	typ := reflect.TypeOf(Trace{})
	table := TraceFieldAudiences()
	for i := 0; i < typ.NumField(); i++ {
		name := typ.Field(i).Name
		if _, ok := table[name]; !ok {
			t.Errorf("Trace field %q has no audience row; add one rather than relying on the invisible default", name)
		}
	}
	for name := range table {
		if _, ok := typ.FieldByName(name); !ok {
			t.Errorf("the audience table names %q, which is not a field of Trace", name)
		}
	}
}

func TestRequesterAudienceReceivesNoPolicyStructure(t *testing.T) {
	full := &Trace{
		Audience: AudienceAuditor, State: StateDeny, Category: CategoryNotPermitted,
		Reason: ReasonExplicitConstraint, BindingPolicy: "C2",
		Determining:       &Determining{MatchedConstraints: []string{"C2"}},
		NextBound:         &NextBound{PolicyID: "C3", Authority: AuthorityRequirement, Summary: "s"},
		Witnesses:         []Witness{{Subject: "Group::realm:g", Path: []string{"p"}, SourceClass: ProvDirectory}},
		ResolvedAncestors: map[string]string{"project": "Project::c:LEGAL"},
		Warnings:          []string{"internal detail"},
	}
	got, err := full.Project(AudienceRequester)
	if err != nil {
		t.Fatalf("projecting: %v", err)
	}
	raw, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("encoding: %v", err)
	}
	for _, leak := range []string{"C2", "C3", "Group::realm:g", "LEGAL", "internal detail", "explicit_constraint"} {
		if strings.Contains(string(raw), leak) {
			t.Errorf("the requester projection leaked %q: %s", leak, raw)
		}
	}
	if got.Category != CategoryNotPermitted {
		t.Errorf("the requester lost its coarse category: %q", got.Category)
	}
}

func TestSchemasCompile(t *testing.T) {
	for _, s := range AllSchemas() {
		if err := ValidateAgainstSchema(s, map[string]any{}); err == nil {
			t.Errorf("schema %q accepted an empty object", s)
		} else if strings.Contains(err.Error(), "compiling schema") {
			t.Errorf("schema %q does not compile: %v", s, err)
		}
	}
}

func TestStateForRefusesAnImpossibleCombination(t *testing.T) {
	for _, a := range []Authorization{AuthzDeny, AuthzNotApplicable, AuthzIndeterminate} {
		if _, err := StateFor(a, true); err == nil {
			t.Errorf("an outstanding approval was accepted alongside authorization %q", a)
		}
	}
	if s, err := StateFor(AuthzPermit, true); err != nil || s != StateChallenge {
		t.Errorf("a permit with an outstanding approval is %q (%v), expected CHALLENGE", s, err)
	}
	if s, err := StateFor(AuthzPermit, false); err != nil || s != StateAllow {
		t.Errorf("a clean permit is %q (%v), expected ALLOW", s, err)
	}
	if s, err := StateFor(AuthzNotApplicable, false); err != nil || s != StateDeny {
		t.Errorf("not applicable maps to %q (%v), expected DENY", s, err)
	}
	if s, err := StateFor(AuthzIndeterminate, false); err != nil || s != StateError {
		t.Errorf("indeterminate maps to %q (%v), expected ERROR", s, err)
	}
	if _, err := StateFor(Authorization("maybe"), false); err == nil {
		t.Error("an undeclared authorization was mapped to a state")
	}
}
