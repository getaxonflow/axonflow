// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"crypto/ed25519"
	"errors"
	"net/http"
	"slices"
	"testing"
	"time"

	"axonflow/platform/decision/authoring"
	"axonflow/platform/decision/authoringcatalog"
	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/legacycompile"
	"axonflow/platform/decision/pdp"
	"axonflow/platform/shared/anchoredenforcer"
	"axonflow/platform/shared/authoringvocabulary"
	sharedidentity "axonflow/platform/shared/identity"
)

// #4249 row 5670275054: an organization's own document governs a workflow step
// or a multi-agent step by the step's name (args.context.step__name) and a tool
// step by its tool (args.context.tool__name). The producer states both on the
// two step planes, with caller provenance, and the real engine decides the step
// from them under a published organization document.

const (
	stepNameFact = "args.context.step__name"
	toolNameFact = "args.context.tool__name"
)

// stepPlaneProducer is the step planes' producer as production configures it
// (asStepPlane) over the shipped dynamic rows.
func stepPlaneProducer(t *testing.T) *dynamicFactProducer {
	t.Helper()
	return asStepPlane(testFactProducer(t, seedDynamicRows(t)))
}

func TestTheStepPlanesStateTheStepsNameAndToolAsCallerFacts(t *testing.T) {
	t.Setenv("ENVIRONMENT", "production")
	p := stepPlaneProducer(t)

	t.Run("a named tool step states both, KNOWN, with caller provenance", func(t *testing.T) {
		facts := produceFacts(t, p, stepFactRequest("", map[string]interface{}{"step_name": "export_ledger", "tool_name": "ledger.export"}))
		for path, want := range map[string]string{stepNameFact: "export_ledger", toolNameFact: "ledger.export"} {
			f, ok := facts[path]
			if !ok || f.State != contract.StateKnown || f.Value != want {
				t.Fatalf("%s = %+v (stated %t); want KNOWN %q", path, f, ok, want)
			}
			if f.Source != contract.ProvCaller {
				t.Fatalf("%s is stated with provenance %q; a body-supplied label is the caller's", path, f.Source)
			}
			if err := contract.NamespaceOf(path).ValidateProvenance(path, f.Source); err != nil {
				t.Fatalf("the contract refuses %s's provenance: %v", path, err)
			}
		}
	})
	t.Run("a step with no tool context states the tool ABSENT, never a guess", func(t *testing.T) {
		facts := produceFacts(t, p, stepFactRequest("", map[string]interface{}{"step_name": "summarize"}))
		if f, ok := facts[toolNameFact]; !ok || f.State != contract.StateAbsent {
			t.Fatalf("%s = %+v (stated %t); want ABSENT", toolNameFact, f, ok)
		}
	})
	t.Run("an empty step name, which the gate forwards when the body omits it, is ABSENT", func(t *testing.T) {
		facts := produceFacts(t, p, stepFactRequest("", map[string]interface{}{"step_name": ""}))
		if f, ok := facts[stepNameFact]; !ok || f.State != contract.StateAbsent {
			t.Fatalf("%s = %+v (stated %t); want ABSENT", stepNameFact, f, ok)
		}
	})
	t.Run("a non-string name is UNKNOWN malformed_value", func(t *testing.T) {
		facts := produceFacts(t, p, stepFactRequest("", map[string]interface{}{"step_name": 42}))
		if f, ok := facts[stepNameFact]; !ok || f.State != contract.StateUnknown || f.Reason != contract.ReasonMalformedValue {
			t.Fatalf("%s = %+v (stated %t); want UNKNOWN malformed_value", stepNameFact, f, ok)
		}
	})
	t.Run("both production constructors configure a step plane", func(t *testing.T) {
		prev := dynamicPolicyEngine
		t.Cleanup(func() { dynamicPolicyEngine = prev })
		dynamicPolicyEngine = newScopeTestDBEngine()
		for name, build := range map[string]func() (*dynamicFactProducer, error){"wcp": newWCPFactProducer, "map": newMAPFactProducer} {
			got, err := build()
			if err != nil || !got.statesStepContext || got.presentsNoContent {
				t.Fatalf("%s: %+v (err %v); want a step plane that presents the step's content", name, got, err)
			}
		}
		// The route producer (/api/v1/process and the plan-execute pre-gate) is
		// NOT a step plane: a caller's context.step_name there must change no
		// decision (TestACallerSuppliedStepNameChangesNoDecisionOffAStepPlane).
		route, err := productionRouteRequestFactProducer()
		if err != nil {
			t.Fatalf("building the route producer: %v", err)
		}
		if rp, ok := route.(*dynamicFactProducer); !ok || rp.statesStepContext {
			t.Fatalf("the route producer is %T (step context %t); want a *dynamicFactProducer that states no step context", route, ok && rp.statesStepContext)
		}
	})
}

// stepDocuments serves one published, promoted organization document for every
// organization, verified under its own trust store.
type stepDocuments struct {
	api    *authoring.API
	keyID  string
	orgPub ed25519.PublicKey
}

func (d *stepDocuments) ActiveTip(ctx context.Context, _ string) (string, int64, error) {
	art, ok, err := d.api.Store().Active(ctx, pdp.RootOrganization)
	if err != nil || !ok {
		return "", 0, err
	}
	history, err := d.api.Store().History(ctx, pdp.RootOrganization)
	return art.Digest(), int64(len(history)), err
}

func (d *stepDocuments) Load(ctx context.Context, _, digest string) (*authoring.Artifact, *pdp.TrustStore, error) {
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

// publishStepConstraint publishes and promotes an organization document with one
// constraint, id, over actions, matching when path equals value. The document
// declares the path itself, as the ruling requires.
func publishStepConstraint(t *testing.T, id, path, value string, actions pdp.ActionSelector) *stepDocuments {
	t.Helper()
	snap, err := authoringvocabulary.ResolveCatalogValue(authoringcatalog.SourceDeployment, authoringvocabulary.CatalogDeployment{})
	if err != nil {
		t.Fatal(err)
	}
	pub, priv, _ := ed25519.GenerateKey(nil)
	trust := pdp.NewTrustStore()
	trust.Authorize(pdp.RootOrganization, "org-key", pub)
	profile, err := authoring.ProfileFor(authoring.EditionCommunity)
	if err != nil {
		t.Fatal(err)
	}
	api, err := authoring.NewAPI(snap.Catalog, authoring.StaticTrust(trust), profile)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	doc := pdp.Document{
		Root: pdp.RootOrganization, Version: 1,
		Attributes: []pdp.AttributeSchema{
			{Path: pdp.ActionIDPath, Type: pdp.TypeString},
			{Path: pdp.ActionTagsPath, Type: pdp.TypeArray},
			// A caller-typed label is declared optional, and read with
			// on_absent no_match (pdp checkCallerTypedLabels).
			{Path: path, Type: pdp.TypeString, Optional: true},
		},
		Policies: []pdp.Policy{{
			ID: id, Authority: contract.AuthorityConstraint, Root: pdp.RootOrganization,
			Scope: pdp.Scope{Organization: true}, Actions: actions,
			Where: pdp.Compare(path, pdp.OpEq, value).HandlingAbsence(pdp.AbsentIsNoMatch),
		}},
	}
	meta := authoring.Metadata{
		DocumentID: "step-context-4249", Title: "a named step",
		Author: contract.MustParseID(contract.KindPrincipal, "User::axonflow-trusted-header:installer"),
	}
	d, findings, err := authoring.NewDocument(authoring.Document{Metadata: meta, Policy: doc}, snap.Catalog)
	if err != nil {
		t.Fatalf("NewDocument: %v\n%v", err, findings)
	}
	tool := "Action::" + authoringcatalog.ActionToolCall
	art, findings, err := api.Publish(context.Background(), d, authoring.PublishOptions{
		Root: pdp.RootOrganization, KeyID: "org-key", PrivateKey: priv, Now: now,
		Fixtures: []authoring.Fixture{{
			Name: "the named tool step",
			Attributes: contract.AttributeSet{
				pdp.ActionIDPath:   contract.Known(tool, contract.ProvPlatform, 1, now),
				pdp.ActionTagsPath: contract.Known([]any{"stage:tool"}, contract.ProvPlatform, 1, now),
				path:               contract.Known(value, contract.ProvCaller, 1, now),
			},
			Expect: map[string]pdp.Verdict{id: pdp.VerdictMatch},
		}},
	})
	if err != nil {
		t.Fatalf("publish: %v\n%v", err, findings)
	}
	author := contract.MustParseID(contract.KindPrincipal, "User::axonflow-trusted-header:installer")
	if _, err := api.Promote(context.Background(), pdp.RootOrganization, art.Digest(), author, now, "step context fixture"); err != nil {
		t.Fatalf("promote: %v", err)
	}
	return &stepDocuments{api: api, keyID: "org-key", orgPub: pub}
}

// stepEnforcer is a real shared enforcer over docs, installed nowhere.
func stepEnforcer(t *testing.T, docs anchoredenforcer.ActiveDocumentSource) anchoredEnforcement {
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
	e, err := anchoredenforcer.New(docs, func() (*authoringcatalog.Snapshot, error) { return snap, nil }, boot.Admitter, boot.Registry.Epoch, sharedidentity.NoGraphOnlyResolver{},
		anchoredenforcer.Options{Overrides: orchestratorRecordedOverrides, Delivers: orchestratorSeamDelivers, EditionBoundary: orchestratorEditionBoundary})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// decideNamedStep decides one step that carries no input on scope as the seam
// does: no content, the step planes' produced facts, the credential subject.
func decideNamedStep(t *testing.T, e anchoredEnforcement, scope legacycompile.EnforcementScope, action string, stepCtx map[string]interface{}) *contract.Decision {
	t.Helper()
	facts := produceFacts(t, stepPlaneProducer(t), stepFactRequest("", stepCtx))
	h := http.Header{}
	h.Set("X-Org-ID", "org-a")
	h.Set("X-Client-ID", "client-a")
	v := e.Evaluate(context.Background(), anchoredenforcer.Call{
		Scope: scope, OrgID: "org-a", RequestID: "wf_1_step_1", Action: action,
		Subject: headerCredentialSubject(h), Query: "", EmptyContent: true, Facts: facts,
	})
	if v.Unavailable != "" || v.Refusal != nil || v.Decision == nil {
		t.Fatalf("PREMISE: no decision on %s for %v (unavailable %q, refusal %+v)", scope, stepCtx, v.Unavailable, v.Refusal)
	}
	if v.Decision.Reason == contract.ReasonInvalidInput {
		t.Fatalf("PREMISE: the engine refused the step as invalid_input on %s for %v: %+v", scope, stepCtx, v.Decision.Trace)
	}
	return v.Decision
}

func TestAnOrganizationDocumentWithholdsAStepByItsName(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", string(authoring.EditionEnterprise))
	t.Setenv("ENVIRONMENT", "production")
	const id = "ceiling.no_export_ledger"
	tool := pdp.ActionSelector{Actions: []contract.ID{contract.MustParseID(contract.KindAction, "Action::"+authoringcatalog.ActionToolCall)}}
	e := stepEnforcer(t, publishStepConstraint(t, id, stepNameFact, "export_ledger", tool))

	for _, scope := range []legacycompile.EnforcementScope{wcpSeamScope, mapSeamScope} {
		t.Run(scope.String()+": the named step is withheld by the constraint, not unknown", func(t *testing.T) {
			dec := decideNamedStep(t, e, scope, authoringcatalog.ActionToolCall, map[string]interface{}{"step_name": "export_ledger"})
			if dec.State != contract.StateDeny || !slices.Contains(dec.Determining.MatchedConstraints, id) {
				t.Fatalf("decision %s %s, matched %v, unknown %v; want DENY by %s", dec.State, dec.Reason, dec.Determining.MatchedConstraints, dec.Determining.Unknown, id)
			}
		})
		t.Run(scope.String()+": another step is permitted", func(t *testing.T) {
			dec := decideNamedStep(t, e, scope, authoringcatalog.ActionToolCall, map[string]interface{}{"step_name": "verify_booking"})
			if dec.State != contract.StateAllow {
				t.Fatalf("decision %s %s, matched %v, unknown %v; want ALLOW", dec.State, dec.Reason, dec.Determining.MatchedConstraints, dec.Determining.Unknown)
			}
		})
		t.Run(scope.String()+": a step with no name is not caught by the name constraint", func(t *testing.T) {
			// A caller-typed label: an omitted name is the same dodge as a
			// renamed step, so the constraint does not apply to it (ruling A).
			dec := decideNamedStep(t, e, scope, authoringcatalog.ActionToolCall, map[string]interface{}{"step_name": ""})
			if dec.State != contract.StateAllow || namesUnknown(dec, id) {
				t.Fatalf("decision %s %s, unknown %v; want ALLOW, the name constraint not applying to a nameless step", dec.State, dec.Reason, dec.Determining.Unknown)
			}
		})
	}
}

// TestAToolConstraintScopedToTheToolActionNeverReachesAnLLMStep is the authoring
// recipe the ruling names: a constraint over the tool is scoped to the tool
// ACTION, so an LLM step - which has no tool, and whose tool fact is ABSENT -
// never evaluates the condition (Kleene false AND unknown is false).
func TestAToolConstraintScopedToTheToolActionNeverReachesAnLLMStep(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", string(authoring.EditionEnterprise))
	t.Setenv("ENVIRONMENT", "production")
	const id = "ceiling.no_ledger_export_tool"
	tool := pdp.ActionSelector{Actions: []contract.ID{contract.MustParseID(contract.KindAction, "Action::"+authoringcatalog.ActionToolCall)}}
	e := stepEnforcer(t, publishStepConstraint(t, id, toolNameFact, "export_ledger", tool))

	t.Run("an LLM step is permitted", func(t *testing.T) {
		dec := decideNamedStep(t, e, wcpSeamScope, authoringcatalog.ActionLLMCompletion, map[string]interface{}{"step_name": "summarize"})
		if dec.State != contract.StateAllow {
			t.Fatalf("decision %s %s, unknown %v; want ALLOW: the tool constraint must not reach an LLM step", dec.State, dec.Reason, dec.Determining.Unknown)
		}
	})
	t.Run("the tool step using export_ledger is withheld", func(t *testing.T) {
		dec := decideNamedStep(t, e, wcpSeamScope, authoringcatalog.ActionToolCall, map[string]interface{}{"step_name": "s", "tool_name": "export_ledger"})
		if dec.State != contract.StateDeny || !slices.Contains(dec.Determining.MatchedConstraints, id) {
			t.Fatalf("decision %s %s, matched %v; want DENY by %s", dec.State, dec.Reason, dec.Determining.MatchedConstraints, id)
		}
	})
	t.Run("another tool step is permitted", func(t *testing.T) {
		dec := decideNamedStep(t, e, wcpSeamScope, authoringcatalog.ActionToolCall, map[string]interface{}{"step_name": "s", "tool_name": "read_ledger"})
		if dec.State != contract.StateAllow {
			t.Fatalf("decision %s %s, unknown %v; want ALLOW", dec.State, dec.Reason, dec.Determining.Unknown)
		}
	})
}

// TestALegacyRowOnTheStepNameStillDecidesNothing is suite 3281's property kept
// true (PRD v11 §1 item 2): with no organization document, a tenant dynamic row
// that blocks a step by name produces the fact and decides nothing.
func TestALegacyRowOnTheStepNameStillDecidesNothing(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", string(authoring.EditionEnterprise))
	t.Setenv("ENVIRONMENT", "production")
	e := stepEnforcer(t, respDocuments{})
	rows := append(seedDynamicRows(t), DynamicPolicy{
		ID: "tenant_block_export_ledger", Name: "block export_ledger", Enabled: true, Priority: 900,
		Conditions: []PolicyCondition{{Field: "step_name", Operator: "equals", Value: "export_ledger"}},
		Actions:    []PolicyAction{{Type: "block"}},
	})
	facts := produceFacts(t, asStepPlane(testFactProducer(t, rows)), stepFactRequest("", map[string]interface{}{"step_name": "export_ledger"}))
	if f := facts[stepNameFact]; f.State != contract.StateKnown || f.Value != "export_ledger" {
		t.Fatalf("PREMISE: %s = %+v; the legacy row's field must be stated so this proves the row, not a missing fact", stepNameFact, f)
	}
	h := http.Header{}
	h.Set("X-Org-ID", "org-a")
	h.Set("X-Client-ID", "client-a")
	v := e.Evaluate(context.Background(), anchoredenforcer.Call{
		Scope: wcpSeamScope, OrgID: "org-a", RequestID: "wf_1_step_1", Action: authoringcatalog.ActionToolCall,
		Subject: headerCredentialSubject(h), Query: "", EmptyContent: true, Facts: facts,
	})
	if v.Decision == nil || v.Decision.State != contract.StateAllow {
		t.Fatalf("decision %+v (unavailable %q); want ALLOW: a legacy row decides nothing in v11", v.Decision, v.Unavailable)
	}
}

// TestAStepNameConstraintDoesNotWithholdARequestThatIsNotAStep is the hazard
// master's ruling (A) closes. Every deployment action declares the step labels,
// and the enforcer pre-states each declared argument ABSENT, so a request that
// is not a step - a decide-stage tool call, an MCP tool call - carries no step
// name. Before the ruling the constraint answered unknown_constraint for it and
// every such tool call was withheld; now absence is a non-match and the request
// is decided by the other policies.
func TestAStepNameConstraintDoesNotWithholdARequestThatIsNotAStep(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", string(authoring.EditionEnterprise))
	t.Setenv("ENVIRONMENT", "production")
	const id = "ceiling.no_export_ledger"
	tool := pdp.ActionSelector{Actions: []contract.ID{contract.MustParseID(contract.KindAction, "Action::"+authoringcatalog.ActionToolCall)}}
	e := stepEnforcer(t, publishStepConstraint(t, id, stepNameFact, "export_ledger", tool))
	// Not a step plane: the route producer, no step context, a real query.
	facts := produceFacts(t, testFactProducer(t, seedDynamicRows(t)), stepFactRequest("list the open tickets", nil))
	if _, stated := facts[stepNameFact]; stated {
		t.Fatalf("PREMISE: the non-step producer stated %s; the enforcer's own ABSENT is what this proves", stepNameFact)
	}
	h := http.Header{}
	h.Set("X-Org-ID", "org-a")
	h.Set("X-Client-ID", "client-a")
	v := e.Evaluate(context.Background(), anchoredenforcer.Call{
		Scope: wcpSeamScope, OrgID: "org-a", RequestID: "decide_1", Action: authoringcatalog.ActionToolCall,
		Subject: headerCredentialSubject(h), Query: "list the open tickets", Facts: facts,
	})
	if v.Decision == nil || v.Unavailable != "" || v.Refusal != nil {
		t.Fatalf("PREMISE: no decision (unavailable %q, refusal %+v)", v.Unavailable, v.Refusal)
	}
	if v.Decision.State != contract.StateAllow || namesUnknown(v.Decision, id) {
		t.Fatalf("a tool.call that is not a step: decision %s %s, unknown %v; want ALLOW - a step-name constraint must not withhold a request that carries no step name",
			v.Decision.State, v.Decision.Reason, v.Decision.Determining.Unknown)
	}
}

// TestALegacyRowReadingTheStepNameDoesNotStateItOffAStepPlane is R3 round 1's
// finding 4: the label path is declared, so a legacy row whose condition reads
// step_name reaches fact() on every plane. Off a step plane nothing may be
// stated for it - otherwise an organization's constraint on /api/v1/process
// would fire or not depending on an unrelated legacy row.
func TestALegacyRowReadingTheStepNameDoesNotStateItOffAStepPlane(t *testing.T) {
	t.Setenv("ENVIRONMENT", "production")
	rows := append(seedDynamicRows(t), DynamicPolicy{
		ID: "tenant_block_export_ledger", Name: "block export_ledger", Enabled: true, Priority: 900,
		Conditions: []PolicyCondition{{Field: "step_name", Operator: "equals", Value: "export_ledger"}},
		Actions:    []PolicyAction{{Type: "block"}},
	})
	req := stepFactRequest("list the open tickets", map[string]interface{}{"step_name": "export_ledger", "tool_name": "x"})
	route := produceFacts(t, testFactProducer(t, rows), req)
	for _, path := range []string{stepNameFact, toolNameFact} {
		if f, stated := route[path]; stated {
			t.Fatalf("off a step plane, with a legacy row reading step_name, %s was stated %+v; want not stated", path, f)
		}
	}
	// PREMISE: the same row and body on a step plane DO state it, so the cell
	// above is about the plane and not about a row that never reached fact().
	if f := produceFacts(t, asStepPlane(testFactProducer(t, rows)), req)[stepNameFact]; f.State != contract.StateKnown {
		t.Fatalf("PREMISE: on a step plane %s = %+v; want KNOWN", stepNameFact, f)
	}
}

// TestACallerSuppliedStepNameChangesNoDecisionOffAStepPlane: off a step plane
// the value is never stated, so a body naming a step changes nothing there: the
// enforcer's ABSENT stands and the published step-name constraint does not
// match it.
func TestACallerSuppliedStepNameChangesNoDecisionOffAStepPlane(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", string(authoring.EditionEnterprise))
	t.Setenv("ENVIRONMENT", "production")
	const id = "ceiling.no_export_ledger"
	tool := pdp.ActionSelector{Actions: []contract.ID{contract.MustParseID(contract.KindAction, "Action::"+authoringcatalog.ActionToolCall)}}
	e := stepEnforcer(t, publishStepConstraint(t, id, stepNameFact, "export_ledger", tool))
	req := stepFactRequest("list the open tickets", map[string]interface{}{"step_name": "export_ledger"})
	facts := produceFacts(t, testFactProducer(t, seedDynamicRows(t)), req)
	h := http.Header{}
	h.Set("X-Org-ID", "org-a")
	h.Set("X-Client-ID", "client-a")
	v := e.Evaluate(context.Background(), anchoredenforcer.Call{
		Scope: wcpSeamScope, OrgID: "org-a", RequestID: "decide_1", Action: authoringcatalog.ActionToolCall,
		Subject: headerCredentialSubject(h), Query: "list the open tickets", Facts: facts,
	})
	if v.Decision == nil || v.Unavailable != "" || v.Refusal != nil {
		t.Fatalf("PREMISE: no decision (unavailable %q, refusal %+v)", v.Unavailable, v.Refusal)
	}
	if v.Decision.State != contract.StateAllow || slices.Contains(v.Decision.Determining.MatchedConstraints, id) {
		t.Fatalf("a non-step request naming export_ledger in its body: decision %s %s, matched %v; want ALLOW - the caller's value must change no decision off a step plane",
			v.Decision.State, v.Decision.Reason, v.Decision.Determining.MatchedConstraints)
	}
}

// TestTheMultiAgentPlaneStatesNoToolName pins R3 round 1's finding 5 as ruled
// (option i): args.context.tool__name is the workflow step gate's attribute
// (tool_context.tool_name). A multi-agent step presents no tool name, so the
// label is ABSENT there and a tool-name constraint never matches a multi-agent
// step. A later row may state it from the step's connector or function.
func TestTheMultiAgentPlaneStatesNoToolName(t *testing.T) {
	t.Setenv("ENVIRONMENT", "production")
	d := withMAPEngine(t, anchoredenforcer.Verdict{Decision: &contract.Decision{State: contract.StateAllow}}, seedDynamicRows(t)...)
	step := WorkflowStep{Name: "export_ledger", Type: "connector-call"}
	exec := &WorkflowExecution{ID: "exec_1", UserContext: UserContext{OrgID: "org-a", TenantID: "t1"}}
	mapStepPolicyCheck(mapSubjectContext(), step, StepContent{}, exec)
	if d.callCount() != 1 {
		t.Fatalf("PREMISE: the multi-agent seam made %d enforcer calls; want 1", d.callCount())
	}
	call := d.lastCall(t)
	if f := call.Facts[stepNameFact]; f.State != contract.StateKnown || f.Value != "export_ledger" {
		t.Fatalf("PREMISE: the multi-agent plane stated %s = %+v; want KNOWN export_ledger", stepNameFact, f)
	}
	if f, stated := call.Facts[toolNameFact]; !stated || f.State != contract.StateAbsent {
		t.Fatalf("the multi-agent plane stated %s = %+v (stated %t); want ABSENT: it presents no tool name", toolNameFact, f, stated)
	}
}
