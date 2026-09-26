// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"crypto/ed25519"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	promtestutil "github.com/prometheus/client_golang/prometheus/testutil"

	"axonflow/platform/decision/authoring"
	"axonflow/platform/decision/authoringcatalog"
	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/legacycompile"
	"axonflow/platform/decision/pdp"
	"axonflow/platform/orchestrator/workflow_control"
	"axonflow/platform/shared/anchoredenforcer"
	"axonflow/platform/shared/authoringvocabulary"
)

// #4249 row 5666236540: the workflow step gate presents the step's input as
// content, whole, as the unescaped projection of its keys and values, and the
// shipped content controls decide over it on the real engine.

const (
	debugRestrictControl   = "corpus:dynamic_policies:sys__dyn__debug__restrict"
	tenantIsolationControl = "corpus:dynamic_policies:sys__dyn__tenant__isolation"
)

// withSeededStepGate installs the real shared enforcer over docs and the step
// gate's producer, as production builds it, over the shipped dynamic rows.
func withSeededStepGate(t *testing.T, docs anchoredenforcer.ActiveDocumentSource) {
	t.Helper()
	installResponseEnforcer(t, docs, nil)
	rows := seedDynamicRows(t)
	previous, previousEngine := newWCPFactProducer, dynamicPolicyEngine
	// The production constructor builds the producer, so whatever it states
	// about the plane is what these cells decide under; only its row source and
	// segment resolver are the fixture's.
	dynamicPolicyEngine = &mockPolicyEngineForWCP{}
	newWCPFactProducer = func() (*dynamicFactProducer, error) {
		p, err := previous()
		if err != nil {
			return nil, err
		}
		p.rows = fixedFactRows(rows)
		p.segments = func(context.Context, string, string) ([]string, bool) { return nil, true }
		return p, nil
	}
	resetWCPFacts()
	t.Cleanup(func() {
		newWCPFactProducer, dynamicPolicyEngine = previous, previousEngine
		resetWCPFacts()
	})
}

func contentStep(stepType workflow_control.StepType, input map[string]interface{}, tool *workflow_control.ToolContext) *workflow_control.StepGateContext {
	return &workflow_control.StepGateContext{
		WorkflowID: "wf_content", StepID: "step_content", StepName: "work",
		StepType: stepType, OrgID: "org-seam", TenantID: "tenant-seam", ClientID: "client-seam",
		StepInput: input, ToolContext: tool,
	}
}

// decideContentStep decides step through the seam as the adapter does, and
// returns the engine's decision. A plane that failed closed is a premise failure.
func decideContentStep(t *testing.T, step *workflow_control.StepGateContext) *contract.Decision {
	t.Helper()
	req := (&WCPPolicyAdapter{}).convertToOrchestratorRequest(step)
	evaluation, _, v := stepGateDecide(wcpSubjectContext(), step, req)
	if v == nil || v.Unavailable != "" || v.Refusal != nil || v.Decision == nil {
		t.Fatalf("PREMISE: no engine decision for %v (evaluation %+v)", step.StepInput, evaluation)
	}
	if v.Decision.Reason == contract.ReasonInvalidInput {
		t.Fatalf("PREMISE: the engine refused the step as invalid_input: %+v", v.Decision.Trace)
	}
	return v.Decision
}

func stepGateCounter(verdict, reason string) float64 {
	return promtestutil.ToFloat64(anchoredenforcer.Decisions.WithLabelValues(wcpSeamScope.String(), anchoredenforcer.EngineAnchored, verdict, reason))
}

func deniedBy(dec *contract.Decision, control string) bool {
	if dec.State != contract.StateDeny {
		return false
	}
	return slices.ContainsFunc(dec.Determining.MatchedConstraints, func(id string) bool { return strings.HasPrefix(id, control) })
}

func TestTheStepGateDecidesTheDebugRestrictionOverTheStepsInput(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", string(authoring.EditionEnterprise))
	withSeededStepGate(t, respDocuments{})
	input := map[string]interface{}{"prompt": "please debug the parser"}

	t.Setenv("ENVIRONMENT", "production")
	dec := decideContentStep(t, contentStep(workflow_control.StepTypeLLMCall, input, nil))
	if !deniedBy(dec, debugRestrictControl) {
		t.Fatalf("outside development: decision %s %s, matched %v, unknown %v; want DENY by %s", dec.State, dec.Reason, dec.Determining.MatchedConstraints, dec.Determining.Unknown, debugRestrictControl)
	}

	t.Setenv("ENVIRONMENT", "development")
	dec = decideContentStep(t, contentStep(workflow_control.StepTypeLLMCall, input, nil))
	if dec.State != contract.StateAllow {
		t.Fatalf("in development: decision %s %s, matched %v, unknown %v; want ALLOW", dec.State, dec.Reason, dec.Determining.MatchedConstraints, dec.Determining.Unknown)
	}
}

func TestTheStepGateDecidesTenantIsolationOverTheStepsInput(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", string(authoring.EditionEnterprise))
	t.Setenv("ENVIRONMENT", "production")
	withSeededStepGate(t, respDocuments{})

	dec := decideContentStep(t, contentStep(workflow_control.StepTypeToolCall, map[string]interface{}{"filter": "tenant_id = 1"}, nil))
	if !deniedBy(dec, tenantIsolationControl) {
		t.Fatalf("a tenant_id comparison: decision %s %s, matched %v, unknown %v; want DENY by %s", dec.State, dec.Reason, dec.Determining.MatchedConstraints, dec.Determining.Unknown, tenantIsolationControl)
	}
	// The row's regex needs a comparison operator after the name: a key named
	// tenant_id is presented as the line "tenant_id" followed by the line "x",
	// which it does not match.
	dec = decideContentStep(t, contentStep(workflow_control.StepTypeToolCall, map[string]interface{}{"tenant_id": "x"}, nil))
	if dec.State != contract.StateAllow {
		t.Fatalf("a tenant_id key: decision %s %s, matched %v; want ALLOW", dec.State, dec.Reason, dec.Determining.MatchedConstraints)
	}
}

// A tool step presents its tool's input beside its step input: a pattern only
// the tool input carries is decided.
func TestTheStepGateDecidesOverAToolStepsToolInput(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", string(authoring.EditionEnterprise))
	t.Setenv("ENVIRONMENT", "production")
	withSeededStepGate(t, respDocuments{})

	tool := &workflow_control.ToolContext{ToolName: "shell", ToolInput: map[string]interface{}{"args": "run the debug build"}}
	dec := decideContentStep(t, contentStep(workflow_control.StepTypeToolCall, nil, tool))
	if !deniedBy(dec, debugRestrictControl) {
		t.Fatalf("decision %s %s, matched %v; want DENY by %s over the tool's input", dec.State, dec.Reason, dec.Determining.MatchedConstraints, debugRestrictControl)
	}
}

// Nothing is cut before the detectors: a pattern past a long input still
// decides.
func TestTheStepGateDecidesOverAPatternPastALongInput(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", string(authoring.EditionEnterprise))
	t.Setenv("ENVIRONMENT", "production")
	withSeededStepGate(t, respDocuments{})

	input := map[string]interface{}{"a": strings.Repeat("x", 512<<10), "z": "debug"}
	dec := decideContentStep(t, contentStep(workflow_control.StepTypeLLMCall, input, nil))
	if !deniedBy(dec, debugRestrictControl) {
		t.Fatalf("decision %s %s, matched %v; want DENY by %s for a pattern past 512 KiB", dec.State, dec.Reason, dec.Determining.MatchedConstraints, debugRestrictControl)
	}
}

// A step with no input presents empty content, and every detector's answer is
// determined: the step is permitted, as it was before content was presented.
func TestAStepWithNoInputPresentsEmptyContent(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", string(authoring.EditionEnterprise))
	t.Setenv("ENVIRONMENT", "production")
	for _, tool := range []*workflow_control.ToolContext{nil, {ToolName: "shell"}} {
		step := contentStep(workflow_control.StepTypeToolCall, map[string]interface{}{}, tool)
		query, err := stepGateContent(step)
		if err != nil || query != "" {
			t.Fatalf("tool %v: content %q, err %v; want empty", tool, query, err)
		}
		d := withStepGateEngine(t, allowedStepVerdict())
		req := (&WCPPolicyAdapter{}).convertToOrchestratorRequest(step)
		stepGateDecide(wcpSubjectContext(), step, req)
		call := d.lastCall(t)
		if call.Query != "" || !call.EmptyContent {
			t.Errorf("tool %v: the call carries query %q empty %v; want empty content", tool, call.Query, call.EmptyContent)
		}
	}
	withSeededStepGate(t, respDocuments{})
	if dec := decideContentStep(t, contentStep(workflow_control.StepTypeLLMCall, nil, nil)); dec.State != contract.StateAllow {
		t.Fatalf("a step with no input: decision %s %s, unknown %v; want ALLOW", dec.State, dec.Reason, dec.Determining.Unknown)
	}
}

// The seam hands the engine the content it built: the query and EmptyContent
// false for a step with input.
func TestTheStepGateHandsTheEngineItsContent(t *testing.T) {
	d := withStepGateEngine(t, allowedStepVerdict())
	step := contentStep(workflow_control.StepTypeLLMCall, map[string]interface{}{"prompt": "hello"}, nil)
	req := (&WCPPolicyAdapter{}).convertToOrchestratorRequest(step)
	stepGateDecide(wcpSubjectContext(), step, req)
	call := d.lastCall(t)
	if call.Query != "prompt\nhello" || call.EmptyContent {
		t.Errorf("the call carries query %q empty %v; want the step input and not empty", call.Query, call.EmptyContent)
	}
}

// The content is the unescaped projection: key order does not move it, a
// string is its own text (a decomposed character kept, a newline a newline),
// a number its JSON text, and a tool step's tool input follows its step input.
func TestTheStepGateContentIsTheUnescapedProjection(t *testing.T) {
	a, errA := stepGateContent(contentStep(workflow_control.StepTypeLLMCall, map[string]interface{}{"b": 1, "a": "e\u0301\n\t\"q\" C:\\x"}, nil))
	b, errB := stepGateContent(contentStep(workflow_control.StepTypeLLMCall, map[string]interface{}{"a": "e\u0301\n\t\"q\" C:\\x", "b": 1}, nil))
	if errA != nil || errB != nil {
		t.Fatal(errA, errB)
	}
	if a != b || a != "a\ne\u0301\n\t\"q\" C:\\x\nb\n1" {
		t.Errorf("content %q and %q; want one sorted projection with every character as sent", a, b)
	}
	tool, err := stepGateContent(contentStep(workflow_control.StepTypeToolCall, map[string]interface{}{"s": "x"}, &workflow_control.ToolContext{ToolName: "t", ToolInput: map[string]interface{}{"k": []interface{}{"v", true}}}))
	if err != nil || tool != "s\nx\nk\nv\ntrue" {
		t.Errorf("tool content %q, err %v; want the step input then the tool input", tool, err)
	}
}

// A pattern the tool receives is the pattern the detector sees: whitespace
// inside a value is whitespace, not its JSON escape (R3 round 1 finding 1).
func TestTheStepGateDecidesTenantIsolationAcrossWhitespaceInAValue(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", string(authoring.EditionEnterprise))
	t.Setenv("ENVIRONMENT", "production")
	withSeededStepGate(t, respDocuments{})
	for _, filter := range []string{"tenant_id\n!= 42", "tenant_id\t!= 42"} {
		dec := decideContentStep(t, contentStep(workflow_control.StepTypeToolCall, map[string]interface{}{"filter": filter}, nil))
		if !deniedBy(dec, tenantIsolationControl) {
			t.Errorf("filter %q: decision %s %s, matched %v; want DENY by %s", filter, dec.State, dec.Reason, dec.Determining.MatchedConstraints, tenantIsolationControl)
		}
	}
}

// An organization's contains row matches a value holding a quote or a
// backslash as written.
func TestAContainsRowMatchesAQuoteAndABackslashAsWritten(t *testing.T) {
	for _, needle := range []string{`say "hi"`, `C:\temp`} {
		row := DynamicPolicy{ID: "org_quote", Name: "org_quote", Enabled: true,
			Conditions: []PolicyCondition{{Field: "query", Operator: "contains", Value: needle}}}
		p := testFactProducer(t, []DynamicPolicy{row})
		path := legacycompile.DynamicContentDetectorPath(row.ID)
		p.types[path] = pdp.TypeBoolean
		step := contentStep(workflow_control.StepTypeLLMCall, map[string]interface{}{"note": "please " + needle + " now"}, nil)
		query, err := stepGateContent(step)
		if err != nil {
			t.Fatal(err)
		}
		req := (&WCPPolicyAdapter{}).convertToOrchestratorRequest(step)
		req.Query = query
		wantKnown(t, produceFacts(t, p, req), path, true)
	}
}

// Input that cannot be encoded as sent is refused, never presented empty.
func TestStepInputThatIsNotValidUTF8IsRefused(t *testing.T) {
	d := withStepGateEngine(t, allowedStepVerdict())
	step := contentStep(workflow_control.StepTypeLLMCall, map[string]interface{}{"prompt": "debug \xff"}, nil)
	req := (&WCPPolicyAdapter{}).convertToOrchestratorRequest(step)
	before := stepGateCounter("unavailable", anchoredenforcer.CauseRequest)
	evaluation, _, v := stepGateDecide(wcpSubjectContext(), step, req)
	if v != nil || evaluation.Decision != workflow_control.GateDecisionBlock {
		t.Fatalf("decision %s verdict %v; want a block before the engine", evaluation.Decision, v)
	}
	if !strings.Contains(evaluation.Reason, anchoredenforcer.CauseRequest) {
		t.Errorf("reason %q does not name %s", evaluation.Reason, anchoredenforcer.CauseRequest)
	}
	if n := d.callCount(); n != 0 {
		t.Errorf("the engine was called %d times for content that could not be encoded", n)
	}
	if got := stepGateCounter("unavailable", anchoredenforcer.CauseRequest) - before; got != 1 {
		t.Errorf("recorded %v refusal(s), want 1", got)
	}
}

// THE ARGUMENT HALF IS UNCHANGED: the context entries a row reads by field, and
// the 50-key tool_input context bound, are what they were.
func TestPresentingContentLeavesTheStepContextArgumentsUnchanged(t *testing.T) {
	toolInput := map[string]interface{}{}
	for i := 0; i < 60; i++ {
		toolInput[string(rune('A'+i/26))+string(rune('a'+i%26))] = i
	}
	step := contentStep(workflow_control.StepTypeToolCall, map[string]interface{}{"note": "hi"}, &workflow_control.ToolContext{ToolName: "t", ToolInput: toolInput})
	req := (&WCPPolicyAdapter{}).convertToOrchestratorRequest(step)
	if req.Context["step_input.note"] != "hi" {
		t.Errorf("step_input.note = %v; want the step input in the context", req.Context["step_input.note"])
	}
	n := 0
	for k := range req.Context {
		if strings.HasPrefix(k, "tool_input.") {
			n++
		}
	}
	if n != 50 {
		t.Errorf("%d tool_input context entries; want the 50-key bound", n)
	}
	content, err := stepGateContent(step)
	if err != nil {
		t.Fatal(err)
	}
	for k := range toolInput {
		if !slices.Contains(strings.Split(content, "\n"), k) {
			t.Fatalf("the content lost tool_input key %s: the 50-key bound is the context's, never the content's", k)
		}
	}
}

// A row over a step_input context field decides from the context value, which
// the producer resolves once the plane presents content (#4249 correction 7).
func TestARowOverAStepInputFieldDecidesFromTheContextValue(t *testing.T) {
	row := DynamicPolicy{ID: "org_step_note", Name: "org_step_note", Enabled: true,
		Conditions: []PolicyCondition{{Field: "context.step_input.note", Operator: "contains", Value: "debug"}}}
	p := testFactProducer(t, []DynamicPolicy{row})
	path := legacycompile.DynamicContentDetectorPath(row.ID)
	// An organization's row is declared where its document declares it; the
	// fixture declares it here, as the shipped rows are declared by the corpus.
	p.types[path] = pdp.TypeBoolean
	step := contentStep(workflow_control.StepTypeLLMCall, map[string]interface{}{"note": "turn on debug"}, nil)
	req := (&WCPPolicyAdapter{}).convertToOrchestratorRequest(step)
	wantKnown(t, produceFacts(t, p, req), path, true)
	req = (&WCPPolicyAdapter{}).convertToOrchestratorRequest(contentStep(workflow_control.StepTypeLLMCall, map[string]interface{}{"note": "hello"}, nil))
	wantKnown(t, produceFacts(t, p, req), path, false)
}

// CONSEQUENCE, stated: an organization-authored policy reading a STATIC
// detector on the step plane. No static detector runs on wcp (row 5705226487).
// At base the plane presented no content and the detector was filled KNOWN
// false, so the policy never applied. #4360 presented content, so the detector
// became ABSENT and the constraint withheld every content-bearing step as
// unknown_constraint. Since #4249 row 5674230432 an organization control that
// reads a registry detector is LEFT OFF a scope that runs none (activation's
// DetectorUnboundControls), so the step is decided on the rest of the document:
// neither a known-false it was never shown nor a withhold of every step.
func TestAnOrganizationConstraintOnAStaticDetectorIsLeftOffTheStepGate(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", string(authoring.EditionEnterprise))
	t.Setenv("ENVIRONMENT", "production")
	const id = "ceiling.no_or_true_4249"
	const path = "signal.detector.sys__sqli__or__true"
	docs := publishContentConstraint(t, id, path)
	withSeededStepGate(t, docs)

	t.Run("base-shaped: no content, decided", func(t *testing.T) {
		d := orchestratorEnforcer()
		if d == nil {
			t.Fatal("PREMISE: no real enforcer installed")
		}
		v := d.Evaluate(context.Background(), anchoredenforcer.Call{
			Scope: wcpSeamScope, OrgID: "org-seam", RequestID: "wf_content_step_content",
			Action: authoringcatalog.ActionToolCall, Subject: headerCredentialSubject(agentCredentialHeaders("org-seam", "tenant-seam", "client-seam")),
			Query: "", EmptyContent: true, Facts: baseStepGateFacts(t),
		})
		if v.Decision == nil || v.Decision.State != contract.StateAllow {
			t.Fatalf("decision %+v; want ALLOW", v.Decision)
		}
	})
	t.Run("content presented: the constraint is left off, the step decided", func(t *testing.T) {
		dec := decideContentStep(t, contentStep(workflow_control.StepTypeToolCall, map[string]interface{}{"q": "hello"}, nil))
		if dec.State != contract.StateAllow || dec.Reason == contract.ReasonUnknownConstraint {
			t.Fatalf("decision %s %s, unknown %v; want ALLOW, not withheld as %s", dec.State, dec.Reason, dec.Determining.Unknown, contract.ReasonUnknownConstraint)
		}
		if slices.ContainsFunc(dec.Determining.Unknown, func(u contract.UnknownPolicy) bool { return strings.HasSuffix(u.PolicyID, id) }) {
			t.Fatalf("unknown %v names %s: the constraint was carried on wcp", dec.Determining.Unknown, id)
		}
	})
}

// THE ROUTES, THE SAME ANSWER (#4249 row 5674230432): /api/v1/process states no
// registry detector, so before the arm an organization constraint reading one
// withheld EVERY request as unknown_constraint. Through the real route seam and
// enforcer it is now decided.
func TestAnOrganizationConstraintOnAStaticDetectorIsLeftOffTheRoutes(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", string(authoring.EditionEnterprise))
	t.Setenv("ENVIRONMENT", "production")
	const id = "ceiling.no_or_true_route_4249"
	const path = "signal.detector.sys__sqli__or__true"
	docs := publishDetectorConstraint(t, id, path, authoringcatalog.ActionLLMCompletion)
	withSeededStepGate(t, docs)
	rows := seedDynamicRows(t)
	previousFactory := newRouteRequestFactProducer
	newRouteRequestFactProducer = func() (routeFactSource, error) { return testFactProducer(t, rows), nil }
	resetRouteRequestFacts()
	t.Cleanup(func() {
		newRouteRequestFactProducer = previousFactory
		resetRouteRequestFacts()
	})
	h := agentCredentialHeaders("org-seam", "tenant-seam", "client-seam")
	req := OrchestratorRequest{
		RequestID: "req-route-4249", Query: "hello there", RequestType: "llm_chat",
		User:   UserContext{OrgID: "org-seam", TenantID: "tenant-seam"},
		Client: ClientContext{ID: "client-seam", OrgID: "org-seam", TenantID: "tenant-seam"},
	}
	r := decideRouteRequest(context.Background(), h, req, processRouteAction).result
	if !r.Allowed {
		t.Fatalf("allowed=%v required_actions=%v applied=%v; want the request decided and allowed, not withheld as %s",
			r.Allowed, r.RequiredActions, r.AppliedPolicies, contract.ReasonUnknownConstraint)
	}

	// THE NEGATIVE HALF: the document still governs this route. The same
	// organization, the same route, a constraint that reads NO detector - so
	// the arm leaves it in place - refuses the request. Without this the allow
	// above is equally consistent with a route no document reaches at all.
	const governs = "ceiling.always_route_4249"
	withSeededStepGate(t, publishDetectorConstraint(t, governs, "", authoringcatalog.ActionLLMCompletion))
	resetRouteRequestFacts()
	blocked := decideRouteRequest(context.Background(), h, req, processRouteAction).result
	if blocked.Allowed || !slices.ContainsFunc(blocked.AppliedPolicies, func(id string) bool { return strings.HasSuffix(id, governs) }) {
		t.Fatalf("allowed=%v applied=%v; want the route REFUSED by %s: the document governs this route, so the allow above is the arm's",
			blocked.Allowed, blocked.AppliedPolicies, governs)
	}
}

// baseStepGateFacts are the facts the step gate produced before it presented
// content: the shipped rows under a producer that presents none.
func baseStepGateFacts(t *testing.T) contract.AttributeSet {
	t.Helper()
	p := testFactProducer(t, seedDynamicRows(t))
	p.presentsNoContent = true
	return produceFacts(t, p, stepFactRequest("", nil))
}

// contentDocuments serves one published, promoted organization document.
type contentDocuments struct {
	api    *authoring.API
	keyID  string
	orgPub ed25519.PublicKey
}

func (d *contentDocuments) ActiveTip(ctx context.Context, _ string) (string, int64, error) {
	art, ok, err := d.api.Store().Active(ctx, pdp.RootOrganization)
	if err != nil || !ok {
		return "", 0, err
	}
	history, err := d.api.Store().History(ctx, pdp.RootOrganization)
	return art.Digest(), int64(len(history)), err
}

func (d *contentDocuments) Load(ctx context.Context, _, digest string) (*authoring.Artifact, *pdp.TrustStore, error) {
	art, ok, err := d.api.Store().Get(ctx, pdp.RootOrganization, digest)
	if err != nil {
		return nil, nil, err
	}
	if !ok {
		return nil, nil, errors.New("no artifact under that digest")
	}
	trust := pdp.NewTrustStore()
	trust.Authorize(pdp.RootOrganization, d.keyID, d.orgPub)
	return art, trust, nil
}

// publishContentConstraint publishes and promotes an organization document with
// one tool.call constraint, id, matching when the boolean detector at path is
// true.
func publishContentConstraint(t *testing.T, id, path string) *contentDocuments {
	t.Helper()
	return publishDetectorConstraint(t, id, path, authoringcatalog.ActionToolCall)
}

// publishDetectorConstraint is publishContentConstraint on action. An empty
// path publishes a constraint that always matches and reads no detector, which
// the detector arm never leaves off a scope.
func publishDetectorConstraint(t *testing.T, id, path, action string) *contentDocuments {
	t.Helper()
	snap, err := authoringvocabulary.ResolveCatalogValue(authoringcatalog.SourceDeployment, authoringvocabulary.CatalogDeployment{})
	if err != nil {
		t.Fatal(err)
	}
	pub, priv, _ := ed25519.GenerateKey(nil)
	trust := pdp.NewTrustStore()
	trust.Authorize(pdp.RootOrganization, "org-key", pub)
	profile, err := authoring.ProfileFor(authoring.EditionEnterprise)
	if err != nil {
		t.Fatal(err)
	}
	api, err := authoring.NewAPI(snap.Catalog, authoring.StaticTrust(trust), profile)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	tool := "Action::" + action
	attrs := []pdp.AttributeSchema{
		{Path: pdp.ActionIDPath, Type: pdp.TypeString},
		{Path: pdp.ActionTagsPath, Type: pdp.TypeArray},
	}
	where := pdp.True()
	if path != "" {
		attrs = append(attrs, pdp.AttributeSchema{Path: path, Type: pdp.TypeBoolean})
		where = pdp.Compare(path, pdp.OpEq, true)
	}
	doc := pdp.Document{
		Root: pdp.RootOrganization, Version: 1, Attributes: attrs,
		Policies: []pdp.Policy{{
			ID: id, Authority: contract.AuthorityConstraint, Root: pdp.RootOrganization,
			Scope:   pdp.Scope{Organization: true},
			Actions: pdp.ActionSelector{Actions: []contract.ID{contract.MustParseID(contract.KindAction, tool)}},
			Where:   where,
		}},
	}
	fixture := authoring.Fixture{
		Name: "the constraint matches",
		Attributes: contract.AttributeSet{
			pdp.ActionIDPath:   contract.Known(tool, contract.ProvPlatform, 1, now),
			pdp.ActionTagsPath: contract.Known([]any{"stage:" + strings.SplitN(action, ".", 2)[0]}, contract.ProvPlatform, 1, now),
		},
		Expect: map[string]pdp.Verdict{id: pdp.VerdictMatch},
	}
	if path != "" {
		fixture.Name = "the detector fired"
		fixture.Attributes[path] = contract.Known(true, contract.ProvDetector, 1, now)
	}
	author := contract.MustParseID(contract.KindPrincipal, "User::axonflow-trusted-header:installer")
	d, findings, err := authoring.NewDocument(authoring.Document{
		Metadata: authoring.Metadata{DocumentID: "step-content-4249", Title: "a static detector", Author: author},
		Policy:   doc,
	}, snap.Catalog)
	if err != nil {
		t.Fatalf("NewDocument: %v\n%v", err, findings)
	}
	art, findings, err := api.Publish(context.Background(), d, authoring.PublishOptions{
		Root: pdp.RootOrganization, KeyID: "org-key", PrivateKey: priv, Now: now,
		// The Enterprise profile admits a signal predicate and refuses a sole
		// author's publication.
		Approvers: []contract.ID{contract.MustParseID(contract.KindPrincipal, "User::axonflow-trusted-header:second-approver")},
		Fixtures:  []authoring.Fixture{fixture},
	})
	if err != nil {
		t.Fatalf("publish: %v\n%v", err, findings)
	}
	approver := contract.MustParseID(contract.KindPrincipal, "User::axonflow-trusted-header:second-approver")
	if _, err := api.Promote(context.Background(), pdp.RootOrganization, art.Digest(), approver, now, "step content fixture"); err != nil {
		t.Fatalf("promote: %v", err)
	}
	return &contentDocuments{api: api, keyID: "org-key", orgPub: pub}
}
