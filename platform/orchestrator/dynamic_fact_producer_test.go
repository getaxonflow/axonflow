// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"axonflow/platform/shared/anchoredenforcer"
	sharedidentity "axonflow/platform/shared/identity"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"axonflow/platform/decision/activation"
	"axonflow/platform/decision/authoring"
	"axonflow/platform/decision/authoringcatalog"
	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/legacycompile"
	"axonflow/platform/decision/pdp"
	"axonflow/platform/shared/activationinputs"
	"axonflow/platform/shared/authoringvocabulary"
)

// seedDynamicMigrations are the core migrations that seed the shipped dynamic
// rows: the ten sys_dyn rows (031) and the five media rows (173).
var seedDynamicMigrations = []string{
	"../../migrations/core/031_seed_system_policies.sql",
	"../../migrations/core/173_seed_system_media_policies.sql",
}

// seedDynamicRows is every dynamic_policies row the core migrations seed, read
// from the SQL rather than copied, as the organization-scoped list returns a
// global row. Every dynamic control the shipped corpus compiles must come from
// one of them: a seed file missing here would read as facts nobody needs.
func seedDynamicRows(t *testing.T) []DynamicPolicy {
	t.Helper()
	conds, err := legacycompile.SeedDynamicConditions(seedDynamicMigrations...)
	if err != nil {
		t.Fatal(err)
	}
	corpus, err := pdp.SystemCorpusDocument()
	if err != nil {
		t.Fatal(err)
	}
	for _, pol := range corpus.Policies {
		control, _, ok := legacycompile.CorpusControlOf(pol.ID)
		if !ok || !strings.HasPrefix(control, "corpus:dynamic_policies:") {
			continue
		}
		seeded := false
		for id := range conds {
			if legacycompile.CorpusPolicyIDFor("dynamic_policies", id) == control {
				seeded = true
				break
			}
		}
		if !seeded {
			t.Fatalf("the shipped corpus compiles %s and no seed migration read here inserts its row", control)
		}
	}
	rows := make([]DynamicPolicy, 0, len(conds))
	for id, raw := range conds {
		var c []PolicyCondition
		if err := json.Unmarshal([]byte(raw), &c); err != nil {
			t.Fatalf("the seeded conditions of %s do not parse: %v", id, err)
		}
		rows = append(rows, DynamicPolicy{ID: id, Name: id, Conditions: c, Enabled: true})
	}
	return rows
}

func withoutRow(rows []DynamicPolicy, id string) []DynamicPolicy {
	out := make([]DynamicPolicy, 0, len(rows))
	for _, r := range rows {
		if r.ID != id {
			out = append(out, r)
		}
	}
	return out
}

func testFactProducer(t *testing.T, rows []DynamicPolicy) *dynamicFactProducer {
	t.Helper()
	p, err := newDynamicFactProducer(func(string, []string) []DynamicPolicy { return rows })
	if err != nil {
		t.Fatal(err)
	}
	p.segments = func(context.Context, string, string) ([]string, bool) { return nil, true }
	p.now = func() time.Time { return time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC) }
	return p
}

func stepFactRequest(query string, ctxData map[string]interface{}) OrchestratorRequest {
	return OrchestratorRequest{
		RequestID:   "wf_1_step_1",
		Query:       query,
		RequestType: "workflow_step_gate",
		User:        UserContext{TenantID: "t1", OrgID: "org-a"},
		Client:      ClientContext{ID: "client-a", TenantID: "t1", OrgID: "org-a"},
		Context:     ctxData,
	}
}

func produceFacts(t *testing.T, p *dynamicFactProducer, req OrchestratorRequest) contract.AttributeSet {
	t.Helper()
	facts, _, err := p.Produce(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	return facts
}

func wantKnown(t *testing.T, facts contract.AttributeSet, path string, want any) {
	t.Helper()
	f, stated := facts[path]
	if !stated {
		t.Errorf("%s is not stated; want KNOWN %v", path, want)
		return
	}
	if f.State != contract.StateKnown || !reflect.DeepEqual(f.Value, want) {
		t.Errorf("%s is %s %v (%s); want KNOWN %v", path, f.State, f.Value, f.Reason, want)
	}
}

// conditionPaths is every attribute path a policy's conditions read.
func conditionPaths(t *testing.T, pol pdp.Policy) []string {
	t.Helper()
	var out []string
	var walk func(v any)
	walk = func(v any) {
		switch x := v.(type) {
		case map[string]any:
			if p, ok := x["path"].(string); ok {
				out = append(out, p)
			}
			for _, c := range x {
				walk(c)
			}
		case []any:
			for _, c := range x {
				walk(c)
			}
		}
	}
	for _, c := range []any{pol.Where, pol.Unless} {
		b, err := json.Marshal(c)
		if err != nil {
			t.Fatal(err)
		}
		var v any
		if err := json.Unmarshal(b, &v); err != nil {
			t.Fatal(err)
		}
		walk(v)
	}
	return out
}

// #4254 (R2): the producer states every attribute the shipped controls bound on
// wcp and map read, from the rows the seed migrations install, and states none
// of them unknown on a clean request from a process that declares its
// environment. principal.region is ABSENT.
func TestTheProducerStatesEveryFactTheShippedDynamicControlsRead(t *testing.T) {
	t.Setenv("ENVIRONMENT", "production")
	facts := produceFacts(t, testFactProducer(t, seedDynamicRows(t)), stepFactRequest("", map[string]interface{}{}))
	for _, plane := range []legacycompile.Plane{legacycompile.PlaneWCP, legacycompile.PlaneMAP} {
		restricted, _, err := activation.RestrictToScope(legacycompile.MustScopeFor(plane, ""))
		if err != nil {
			t.Fatal(err)
		}
		read := map[string]bool{}
		for _, pol := range restricted.Policies {
			for _, path := range conditionPaths(t, pol) {
				read[path] = true
			}
		}
		if len(read) == 0 {
			t.Fatalf("PREMISE: no shipped control bound on %s reads an attribute, so the census proves nothing", plane)
		}
		for path := range read {
			if path == "signal.cost_estimate" {
				// Never stated: its only source is a caller claim, which the
				// contract does not admit as a signal
				// (TestTheCostEstimateIsNotStatedBecauseItsOnlySourceIsACallerClaim).
				continue
			}
			f, stated := facts[path]
			if !stated {
				t.Errorf("%s: the shipped controls read %s and the producer does not state it", plane, path)
				continue
			}
			if f.State == contract.StateUnknown {
				t.Errorf("%s: %s is stated UNKNOWN (%s) on a clean request", plane, path, f.Reason)
			}
		}
	}
	if f := facts["principal.region"]; f.State != contract.StateAbsent {
		t.Errorf("principal.region is %s; want ABSENT, because the orchestrator has no authenticated source for it", f.State)
	}
}

// The producer holds no verdict: its one exported method returns facts, the
// route effects of the rows that apply, and an error, and nothing else. The
// route effects are fact-layer output (PRD v11 §1.2 ruling R2, #4254): they
// steer which provider serves an admitted request and carry no verdict, which
// the second half of this test pins field by field.
func TestTheProducerHoldsNoVerdict(t *testing.T) {
	typ := reflect.TypeOf(&dynamicFactProducer{})
	if typ.NumMethod() != 1 {
		var names []string
		for i := 0; i < typ.NumMethod(); i++ {
			names = append(names, typ.Method(i).Name)
		}
		t.Fatalf("the producer exposes %v; want Produce alone", names)
	}
	m := typ.Method(0)
	if m.Name != "Produce" || m.Type.NumOut() != 3 ||
		m.Type.Out(0) != reflect.TypeOf(contract.AttributeSet{}) ||
		m.Type.Out(1) != reflect.TypeOf(routeEffects{}) ||
		m.Type.Out(2) != reflect.TypeOf((*error)(nil)).Elem() {
		t.Fatalf("the producer's method is %s %v; want Produce returning (contract.AttributeSet, routeEffects, error)", m.Name, m.Type)
	}
	effects := reflect.TypeOf(routeEffects{})
	var fields []string
	for i := 0; i < effects.NumField(); i++ {
		fields = append(fields, effects.Field(i).Name)
	}
	if want := []string{"PreferredProvider", "RoutingReason", "AllowedProviders"}; !reflect.DeepEqual(fields, want) {
		t.Errorf("routeEffects carries %v; want only the routing hints %v, so no verdict rides beside the facts", fields, want)
	}
}

// Each detector fact is its row's content verdict: every content condition of
// the row, as the seed declares it, over the request's query.
func TestTheDynamicDetectorFactsAreEachRowsContentVerdict(t *testing.T) {
	p := testFactProducer(t, seedDynamicRows(t))
	rows := []string{"sys_dyn_tenant_isolation", "sys_dyn_debug_restrict", "sys_dyn_hipaa", "sys_dyn_financial", "sys_dyn_sensitive_data"}
	cases := []struct {
		query string
		fires string
	}{
		{"SELECT * FROM orders WHERE tenant_id != 42", "sys_dyn_tenant_isolation"},
		{"please debug the parser", "sys_dyn_debug_restrict"},
		{"summarise the patient history", "sys_dyn_hipaa"},
		{"show the account_balance", "sys_dyn_financial"},
		{"export the ssn column", "sys_dyn_sensitive_data"},
		{"hello there", ""},
	}
	for _, tc := range cases {
		facts := produceFacts(t, p, stepFactRequest(tc.query, nil))
		for _, row := range rows {
			wantKnown(t, facts, legacycompile.DynamicContentDetectorPath(row), row == tc.fires)
		}
	}
}

// A row that does not govern the caller states no detector fact: the engine
// reads the missing fact as unknown, and a constraint over it answers
// unknown_constraint rather than a permit.
func TestAFactNoGoverningRowReadsIsNotStated(t *testing.T) {
	path := legacycompile.DynamicContentDetectorPath("sys_dyn_tenant_isolation")
	facts := produceFacts(t, testFactProducer(t, seedDynamicRows(t)), stepFactRequest("hello", nil))
	if _, stated := facts[path]; !stated {
		t.Fatalf("PREMISE: with every seeded row, %s is not stated", path)
	}
	dropped := produceFacts(t, testFactProducer(t, withoutRow(seedDynamicRows(t), "sys_dyn_tenant_isolation")), stepFactRequest("hello", nil))
	if f, stated := dropped[path]; stated {
		t.Fatalf("with the tenant isolation row dropped, %s is still stated %s %v", path, f.State, f.Value)
	}
}

// #4254 ruling (b): env.environment is the deployment's, read from the process's
// ENVIRONMENT alone. A caller's context.environment is a claim about the
// request and changes nothing, and a process that declares no environment
// states none.
func TestTheEnvironmentFactIsTheDeploymentsNeverTheCallers(t *testing.T) {
	p := testFactProducer(t, seedDynamicRows(t))
	t.Setenv("ENVIRONMENT", "production")
	wantKnown(t, produceFacts(t, p, stepFactRequest("", map[string]interface{}{"environment": "development"})), "env.environment", "production")
	t.Setenv("ENVIRONMENT", "development")
	wantKnown(t, produceFacts(t, p, stepFactRequest("", nil)), "env.environment", "development")
	t.Setenv("ENVIRONMENT", "")
	if f, stated := produceFacts(t, p, stepFactRequest("", map[string]interface{}{"environment": "development"}))["env.environment"]; stated {
		t.Errorf("with no process ENVIRONMENT and a caller claiming development, env.environment is stated %s %v; want not stated", f.State, f.Value)
	}
}

// With no media attached every media fact is KNOWN at its zero, and a caller's
// context.media_analysis changes nothing (R3 A-H2).
func TestTheMediaFactsAreKnownAtZeroWithoutMediaWhateverTheCallerClaims(t *testing.T) {
	p := testFactProducer(t, seedDynamicRows(t))
	none := produceFacts(t, p, stepFactRequest("", nil))
	wantKnown(t, none, "signal.media.nsfw__score", float64(0))
	wantKnown(t, none, "signal.media.has__pii", false)
	claimed := produceFacts(t, p, stepFactRequest("", map[string]interface{}{
		"media_analysis": map[string]interface{}{"nsfw_score": 0.93, "has_pii": true},
	}))
	wantKnown(t, claimed, "signal.media.nsfw__score", float64(0))
	wantKnown(t, claimed, "signal.media.has__pii", false)
}

// With media attached the facts are the analysis this process wrote, and
// UNKNOWN when it wrote none or the analysis lacks the signal: an analysis that
// failed, media governance disabled, or a caller who sent only a
// context.media_analysis of its own (R3 A-H2).
func TestTheMediaFactsWithMediaAreTheAnalysisThisProcessWroteAndUnknownWithoutIt(t *testing.T) {
	p := testFactProducer(t, seedDynamicRows(t))
	attached := []MediaContentRequest{{Source: "url", URL: "https://example.com/a.jpg", MIMEType: "image/jpeg"}}
	withMedia := func(ctxData map[string]interface{}, analysis map[string]interface{}) OrchestratorRequest {
		r := stepFactRequest("", ctxData)
		r.Media = attached
		r.mediaAnalysis = analysis
		return r
	}

	analysed := produceFacts(t, p, withMedia(nil, map[string]interface{}{"nsfw_score": 0.93, "has_pii": true}))
	wantKnown(t, analysed, "signal.media.nsfw__score", 0.93)
	wantKnown(t, analysed, "signal.media.has__pii", true)

	cases := map[string]OrchestratorRequest{
		"no analysis written":            withMedia(nil, nil),
		"an analysis without the signal": withMedia(nil, map[string]interface{}{"face_count": 0}),
		"only the caller's context.media_analysis": withMedia(map[string]interface{}{
			"media_analysis": map[string]interface{}{"nsfw_score": 0.0, "has_pii": false},
		}, nil),
	}
	for name, req := range cases {
		facts := produceFacts(t, p, req)
		for _, path := range []string{"signal.media.nsfw__score", "signal.media.has__pii"} {
			f, stated := facts[path]
			if !stated || f.State != contract.StateUnknown || f.Reason != contract.ReasonNotSupplied {
				t.Errorf("%s: %s stated=%v is %s %v (%s); want UNKNOWN %s", name, path, stated, f.State, f.Value, f.Reason, contract.ReasonNotSupplied)
			}
		}
	}
}

// signal.risk_score is the platform floor, and no matched row raises it.
func TestTheRiskScoreFactIsThePlatformFloorAndNothingRaisesIt(t *testing.T) {
	req := stepFactRequest("SELECT * FROM users WHERE password = 'x'", nil)
	floor := dbRiskCalculator.CalculateRiskScore(req)
	if floor <= 0 {
		t.Fatalf("PREMISE: the query scores %v; a zero floor cannot show that nothing raised it", floor)
	}
	wantKnown(t, produceFacts(t, testFactProducer(t, seedDynamicRows(t)), req), "signal.risk_score", floor)
}

// #4254 ruling (a): signal.cost_estimate is never stated. Its only source is the
// caller's context, and the decision contract states a signal only as a
// detector's finding; a caller's claim does not become one by relabelling.
func TestTheCostEstimateIsNotStatedBecauseItsOnlySourceIsACallerClaim(t *testing.T) {
	p := testFactProducer(t, seedDynamicRows(t))
	if _, declared := p.types["signal.cost_estimate"]; !declared {
		t.Fatal("PREMISE: the shipped documents declare no signal.cost_estimate, so not stating it proves nothing")
	}
	for _, ctx := range []map[string]interface{}{{"cost_estimate": 150.0}, nil} {
		if f, stated := produceFacts(t, p, stepFactRequest("", ctx))["signal.cost_estimate"]; stated {
			t.Errorf("with context %v, signal.cost_estimate is stated %s %v; want not stated", ctx, f.State, f.Value)
		}
	}
}

// args.request_type is the request's own type.
func TestTheRequestTypeFactIsTheRequestsType(t *testing.T) {
	req := stepFactRequest("", nil)
	req.RequestType = "llm_chat"
	wantKnown(t, produceFacts(t, testFactProducer(t, seedDynamicRows(t)), req), "args.request_type", "llm_chat")
}

// A caller-context argument is known at its type, absent when the context does
// not carry it, and UNKNOWN when it carries a value of the wrong type.
func TestAContextArgumentIsKnownAbsentOrUnknownNeverAGuess(t *testing.T) {
	p := testFactProducer(t, seedDynamicRows(t))
	path := legacycompile.Options{}.AttributePathFor("user.monthly_llm_usage")
	wantKnown(t, produceFacts(t, p, stepFactRequest("", map[string]interface{}{"user.monthly_llm_usage": 1500.0})), path, 1500.0)
	if f := produceFacts(t, p, stepFactRequest("", nil))[path]; f.State != contract.StateAbsent {
		t.Errorf("with no usage in the context %s is %s; want ABSENT", path, f.State)
	}
	if f := produceFacts(t, p, stepFactRequest("", map[string]interface{}{"user.monthly_llm_usage": "lots"}))[path]; f.State != contract.StateUnknown || f.Reason != contract.ReasonMalformedValue {
		t.Errorf("with a non-numeric usage %s is %s (%s); want UNKNOWN malformed_value", path, f.State, f.Reason)
	}
}

// principal.region is ABSENT even when the request carries one: nothing
// authenticated supplies it on this process.
func TestTheRegionIsAbsentEvenWhenTheRequestCarriesOne(t *testing.T) {
	req := stepFactRequest("", nil)
	req.User.Region = "EU"
	if f := produceFacts(t, testFactProducer(t, seedDynamicRows(t)), req)["principal.region"]; f.State != contract.StateAbsent {
		t.Fatalf("principal.region is %s %v; want ABSENT", f.State, f.Value)
	}
}

// When the caller's segments cannot be resolved nothing is produced, and the
// producer says why.
func TestAnUnresolvableSegmentSetProducesNoFacts(t *testing.T) {
	p := testFactProducer(t, seedDynamicRows(t))
	p.segments = func(context.Context, string, string) ([]string, bool) { return nil, false }
	facts, _, err := p.Produce(context.Background(), stepFactRequest("hello", nil))
	if !errors.Is(err, errDynamicFactsUnavailable) || facts != nil {
		t.Fatalf("with segments unresolvable: facts %v, err %v; want none and errDynamicFactsUnavailable", facts, err)
	}
}

// A producer needs its rows.
func TestAProducerWithNoRowsSourceIsRefused(t *testing.T) {
	if _, err := newDynamicFactProducer(nil); err == nil {
		t.Fatal("a producer was built with no rows source")
	}
}

// A row's detector fact is the AND of every content condition the row carries:
// one content condition that does not hold leaves the detector false. No seeded
// row carries two, so the row here is the test's own.
func TestADetectorFactRequiresEveryContentConditionOfItsRow(t *testing.T) {
	const id = "sys_dyn_two_content_fixture"
	path := legacycompile.DynamicContentDetectorPath(id)
	row := DynamicPolicy{ID: id, Name: id, Enabled: true, Conditions: []PolicyCondition{
		{Field: "query", Operator: "contains", Value: "ledger"},
		{Field: "query", Operator: "contains", Value: "export"},
	}}
	p := testFactProducer(t, []DynamicPolicy{row})
	p.types[path] = pdp.TypeBoolean
	wantKnown(t, produceFacts(t, p, stepFactRequest("export the ledger", nil)), path, true)
	wantKnown(t, produceFacts(t, p, stepFactRequest("export the report", nil)), path, false)
	wantKnown(t, produceFacts(t, p, stepFactRequest("read the ledger", nil)), path, false)
}

// Nothing the shipped documents do not declare is stated, detector or field:
// the engine refuses a request carrying an attribute its documents do not
// declare, so stating one would refuse every request the row reads.
func TestAnAttributeTheCorpusDoesNotDeclareIsNotStated(t *testing.T) {
	const id = "sys_dyn_undeclared_fixture"
	row := DynamicPolicy{ID: id, Name: id, Enabled: true, Conditions: []PolicyCondition{
		{Field: "query", Operator: "contains", Value: "ledger"},
		{Field: "user.favourite_colour", Operator: "equals", Value: "blue"},
	}}
	facts := produceFacts(t, testFactProducer(t, []DynamicPolicy{row}), stepFactRequest("the ledger", map[string]interface{}{"user.favourite_colour": "blue"}))
	for _, path := range []string{legacycompile.DynamicContentDetectorPath(id), legacycompile.Options{}.AttributePathFor("user.favourite_colour")} {
		if f, stated := facts[path]; stated {
			t.Errorf("%s, which the shipped documents do not declare, was stated %s %v", path, f.State, f.Value)
		}
	}
}

// Every fact the producer states is one the decision contract admits: a
// provenance class its namespace permits. The engine refuses a request carrying
// any other as invalid_input, which on the step gate would refuse every step,
// so each fact is validated on its own, on a request that makes the producer
// state every family it can.
func TestEveryFactTheProducerStatesIsAdmittedByTheContract(t *testing.T) {
	t.Setenv("ENVIRONMENT", "production")
	req := stepFactRequest("please debug the patient ssn ledger", map[string]interface{}{
		"cost_estimate":          150.0,
		"user.monthly_llm_usage": 1500.0,
		"media_analysis":         map[string]interface{}{"nsfw_score": 0.93, "has_pii": true},
	})
	req.RequestType = "llm_chat"
	facts := produceFacts(t, testFactProducer(t, seedDynamicRows(t)), req)
	for _, family := range []string{"signal.detector.", "signal.media.", "signal.risk_score", "args.", "env.", "principal."} {
		stated := false
		for path := range facts {
			if strings.HasPrefix(path, family) {
				stated = true
				break
			}
		}
		if !stated {
			t.Errorf("PREMISE: the producer stated no %s fact, so its admission is not checked", family)
		}
	}
	for path, f := range facts {
		if err := (contract.AttributeSet{path: f}).Validate(); err != nil {
			t.Errorf("the producer states a fact the contract refuses: %v", err)
		}
	}
}

// #4254: a plane that presents NO CONTENT states each row's content verdict
// KNOWN false as a statement about the plane, without running the detector over
// anything.
//
// The premise is what makes the false meaningful: the very same request DOES
// match when content is presented, so the false below reports the plane's
// contract and not a broken detector. The workflow step gate is such a plane -
// it builds its policy request with no content field at all - and presenting
// its step input is the v11.1.0 follow-up (#4249).
func TestAPlaneThatPresentsNoContentStatesEveryDetectorFalse(t *testing.T) {
	t.Setenv("ENVIRONMENT", "production")
	rows := seedDynamicRows(t)
	const query = "please debug the parser"
	debug := legacycompile.DynamicContentDetectorPath("sys_dyn_debug_restrict")

	// PREMISE: with content presented, this query matches the debug row.
	wantKnown(t, produceFacts(t, testFactProducer(t, rows), stepFactRequest(query, nil)), debug, true)

	p := testFactProducer(t, rows)
	p.presentsNoContent = true
	facts := produceFacts(t, p, stepFactRequest(query, nil))
	wantKnown(t, facts, debug, false)

	// And EVERY dynamic detector the shipped controls read is false, not just
	// the one the query would have matched: nothing was presented for any of
	// them, so none of them looked.
	stated := 0
	for path, f := range facts {
		if !strings.HasPrefix(path, "signal.detector.dyn.") {
			continue
		}
		stated++
		if f.State != contract.StateKnown || f.Value != false {
			t.Errorf("%s is %s %v on a plane that presents no content; want KNOWN false", path, f.State, f.Value)
		}
	}
	if stated == 0 {
		t.Fatal("PREMISE: no dynamic detector fact was stated at all, so this proves nothing about their value")
	}
}

// wcpActivation activates the workflow control plane against the shipped
// corpus for one organization, on the Enterprise edition, with the inputs the
// orchestrator's enforcer takes from activationinputs.
func wcpActivation(t *testing.T) *activation.Activation {
	t.Helper()
	t.Setenv("DEPLOYMENT_MODE", string(authoring.EditionEnterprise))
	snap, err := authoringvocabulary.ResolveCatalogValue(authoringcatalog.SourceDeployment, authoringvocabulary.CatalogDeployment{})
	if err != nil {
		t.Fatal(err)
	}
	profile, err := authoring.ProfileFor(authoring.EditionEnterprise)
	if err != nil {
		t.Fatal(err)
	}
	system, composition, err := activationinputs.NewAuthorities()
	if err != nil {
		t.Fatal(err)
	}
	in, err := activationinputs.Builder{
		Snapshot: snap, Trust: authoring.StaticTrust(pdp.NewTrustStore()),
		System: system, Composition: composition, Profile: profile,
		RefuseConstructsOutsideEdition: true, OrganizationID: "org-a",
	}.For(context.Background(), legacycompile.PlaneWCP, "")
	if err != nil {
		t.Fatal(err)
	}
	act, err := activation.Activate(context.Background(), in)
	if err != nil {
		t.Fatalf("activating wcp: %v", err)
	}
	return act
}

// decideStep decides one tool.call step on the workflow control plane from the
// produced facts through a real Enforcer.Evaluate (R3 A-M3): the enforcer
// activates the plane for the organization, admits the step's credential
// subject, merges the facts under its own rules and decides. A regression in
// that merge - a principal fact placed in the shared set, a collision taken
// rather than refused - reaches this proof. act is the activation the premise
// reads the action from.
func decideStep(t *testing.T, act *activation.Activation, query string, facts contract.AttributeSet) *contract.Decision {
	t.Helper()
	action := contract.MustParseID(contract.KindAction, "Action::"+authoringcatalog.ActionToolCall)
	if _, ok := act.Snapshot.Catalog.Actions[action.String()]; !ok {
		t.Fatalf("PREMISE: %s is not in the activated deployment vocabulary", action)
	}
	h := http.Header{}
	h.Set("X-Org-ID", "org-a")
	h.Set("X-Client-ID", "client-a")
	v := stepDecisionEnforcer(t).Evaluate(context.Background(), anchoredenforcer.Call{
		Scope:     wcpSeamScope,
		OrgID:     "org-a",
		RequestID: "wf_1_step_1",
		Action:    authoringcatalog.ActionToolCall,
		Subject:   headerCredentialSubject(h),
		Query:     query,
		Facts:     facts,
	})
	if v.Unavailable != "" || v.Refusal != nil || v.Decision == nil {
		t.Fatalf("PREMISE: the enforcer reached no decision for %q (unavailable %q, refusal %+v)", query, v.Unavailable, v.Refusal)
	}
	dec := v.Decision
	if dec.Reason == contract.ReasonInvalidInput {
		var detail []string
		if dec.Trace != nil {
			detail = append([]string{dec.Trace.Remediation}, dec.Trace.Warnings...)
		}
		t.Fatalf("PREMISE: the engine refused the request as invalid_input, so no verdict below is about the facts: %v", detail)
	}
	return dec
}

// stepDecisionEnforcer is a real shared enforcer over the shipped corpus, with no
// organization document active and no recorded override. It is installed
// nowhere: decideStep calls its Evaluate directly.
func stepDecisionEnforcer(t *testing.T) anchoredEnforcement {
	t.Helper()
	isolateOrchestratorEnforcer(t)
	setDetectionOverrideCacheForTest(testOverrideCache(noOverrides))
	snap, err := authoringvocabulary.ResolveCatalogValue(authoringcatalog.SourceDeployment, authoringvocabulary.CatalogDeployment{})
	if err != nil || snap == nil {
		t.Fatalf("resolving the deployment vocabulary: %v", err)
	}
	boot, err := sharedidentity.BootstrapAdmission(sharedidentity.AdmissionBootstrapConfig{})
	if err != nil {
		t.Fatal(err)
	}
	e, err := anchoredenforcer.New(respDocuments{}, func() (*authoringcatalog.Snapshot, error) { return snap, nil }, boot.Admitter, boot.Registry.Epoch,
		anchoredenforcer.Options{Overrides: orchestratorRecordedOverrides, Delivers: orchestratorSeamDelivers, EditionBoundary: orchestratorEditionBoundary})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func namesUnknown(dec *contract.Decision, policyID string) bool {
	for _, u := range dec.Determining.Unknown {
		if u.PolicyID == policyID {
			return true
		}
	}
	return false
}

// #4254: the workflow control plane is decided by the anchored engine from the
// produced facts, and the environment the debug constraint reads is the
// deployment's. sys__dyn__debug__restrict ships as a block on wcp
// (shipped_posture.json). A dropped signal answers unknown_constraint naming
// the constraint that reads it (ruling R2's acceptance).
func TestTheEngineDecidesAStepFromTheProducedFacts(t *testing.T) {
	const (
		debug  = "corpus:dynamic_policies:sys__dyn__debug__restrict"
		tenant = "corpus:dynamic_policies:sys__dyn__tenant__isolation"
	)
	act := wcpActivation(t)
	rows := seedDynamicRows(t)

	t.Run("a caller claiming development on a production deployment is still refused by the debug constraint", func(t *testing.T) {
		t.Setenv("ENVIRONMENT", "production")
		const query = "please debug the parser"
		dec := decideStep(t, act, query, produceFacts(t, testFactProducer(t, rows), stepFactRequest(query, map[string]interface{}{"environment": "development"})))
		if dec.State != contract.StateDeny || !slices.Contains(dec.Determining.MatchedConstraints, debug) {
			t.Fatalf("decision %s %s, matched constraints %v; want DENY by %s", dec.State, dec.Reason, dec.Determining.MatchedConstraints, debug)
		}
	})
	t.Run("a development deployment is not refused by the debug constraint", func(t *testing.T) {
		t.Setenv("ENVIRONMENT", "development")
		const query = "please debug the parser"
		dec := decideStep(t, act, query, produceFacts(t, testFactProducer(t, rows), stepFactRequest(query, nil)))
		if slices.Contains(dec.Determining.MatchedConstraints, debug) || dec.State == contract.StateError {
			t.Fatalf("decision %s %s, matched constraints %v; want %s unmatched and a decided request", dec.State, dec.Reason, dec.Determining.MatchedConstraints, debug)
		}
	})
	t.Run("with no deployment environment a debug query is refused unknown_constraint naming the debug constraint", func(t *testing.T) {
		t.Setenv("ENVIRONMENT", "")
		const query = "please debug the parser"
		dec := decideStep(t, act, query, produceFacts(t, testFactProducer(t, rows), stepFactRequest(query, map[string]interface{}{"environment": "development"})))
		if dec.State != contract.StateError || dec.Reason != contract.ReasonUnknownConstraint || !namesUnknown(dec, debug) {
			t.Fatalf("decision %s %s, unknown %v; want ERROR unknown_constraint naming %s", dec.State, dec.Reason, dec.Determining.Unknown, debug)
		}
	})
	t.Run("with no deployment environment a query the debug detector does not fire on is decided", func(t *testing.T) {
		t.Setenv("ENVIRONMENT", "")
		const query = "hello there"
		dec := decideStep(t, act, query, produceFacts(t, testFactProducer(t, rows), stepFactRequest(query, nil)))
		if dec.State == contract.StateError {
			t.Fatalf("decision %s %s, unknown %v; a known-false detector must decide the constraint without the environment", dec.State, dec.Reason, dec.Determining.Unknown)
		}
	})
	t.Run("a planted signal drop answers unknown_constraint naming the constraint that reads it", func(t *testing.T) {
		t.Setenv("ENVIRONMENT", "production")
		const query = "hello there"
		facts := produceFacts(t, testFactProducer(t, rows), stepFactRequest(query, nil))
		clean := decideStep(t, act, query, facts)
		if clean.State == contract.StateError {
			t.Fatalf("PREMISE: the clean request is %s %s (%v); a drop from an erroring request proves nothing", clean.State, clean.Reason, clean.Determining.Unknown)
		}
		delete(facts, legacycompile.DynamicContentDetectorPath("sys_dyn_tenant_isolation"))
		dec := decideStep(t, act, query, facts)
		if dec.State != contract.StateError || dec.Reason != contract.ReasonUnknownConstraint || !namesUnknown(dec, tenant) {
			t.Fatalf("decision %s %s, unknown %v; want ERROR unknown_constraint naming %s", dec.State, dec.Reason, dec.Determining.Unknown, tenant)
		}
	})
}
