// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package anchoredenforcer

import (
	"context"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"axonflow/platform/decision/activation"
	"axonflow/platform/decision/authoring"
	"axonflow/platform/decision/authoringcatalog"
	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/legacycompile"
	"axonflow/platform/decision/pdp"
	"axonflow/platform/decision/registry"
	"axonflow/platform/shared/activationinputs"
	"axonflow/platform/shared/authoringvocabulary"
	sharedpolicy "axonflow/platform/shared/policy"
)

var factsNow = time.Date(2026, 9, 14, 12, 0, 0, 0, time.UTC)

// factsActivation activates the workflow control plane against the shipped
// corpus for one organization, with the inputs every enforcing process builds.
func factsActivation(t *testing.T) *activation.Activation {
	t.Helper()
	return factsActivationFor(t, legacycompile.PlaneWCP, "")
}

// factsActivationFor activates one plane and phase the same way. The proxy
// request plane is the one whose shipped controls read the censused detectors
// (DetectorSignalPaths); the workflow plane's detectors are the dynamic ones,
// which no observation or empty content states.
func factsActivationFor(t *testing.T, plane legacycompile.Plane, phase legacycompile.Phase) *activation.Activation {
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
	}.For(context.Background(), plane, phase)
	if err != nil {
		t.Fatal(err)
	}
	act, err := activation.Activate(context.Background(), in)
	if err != nil {
		t.Fatalf("activating %s %s: %v", plane, phase, err)
	}
	return act
}

// factsEntry is the tool.call action the requests below are normalized for.
func factsEntry(t *testing.T, act *activation.Activation) (contract.ID, pdp.ActionEntry) {
	t.Helper()
	action := contract.MustParseID(contract.KindAction, "Action::"+authoringcatalog.ActionToolCall)
	entry, ok := act.Snapshot.Catalog.Actions[action.String()]
	if !ok {
		t.Fatalf("PREMISE: %s is not in the activated deployment vocabulary", action)
	}
	return action, entry
}

// factsRequest normalizes call as Evaluate does, after the subject is admitted.
func factsRequest(t *testing.T, act *activation.Activation, call Call) (*contract.Request, error) {
	t.Helper()
	action, entry := factsEntry(t, act)
	principal := contract.MustParseID(contract.KindPrincipal, "User::axonflow-trusted-header:alice")
	call.OrgID, call.RequestID, call.Query = "org-a", "req-1", "hello there"
	return anchoredRequest(act, entry, action, principal, call, 1, 1, factsNow)
}

func mustFactsRequest(t *testing.T, act *activation.Activation, call Call) *contract.Request {
	t.Helper()
	req, err := factsRequest(t, act, call)
	if err != nil {
		t.Fatalf("normalizing %+v: %v", call.Facts, err)
	}
	return req
}

func sortedPaths(s contract.AttributeSet) []string {
	out := make([]string, 0, len(s))
	for p := range s {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// Rule 4 (#4254): a seam that states no facts gets the request the enforcer
// built before Call.Facts existed - the action, its tags, the query KNOWN,
// every other declared argument ABSENT, and principal.id on the actor - so the
// seams that pass none are unchanged.
func TestNoFactsBuildTheRequestTheEnforcerBuiltBefore(t *testing.T) {
	act := factsActivation(t)
	_, entry := factsEntry(t, act)
	withNil := mustFactsRequest(t, act, Call{})
	withEmpty := mustFactsRequest(t, act, Call{Facts: contract.AttributeSet{}})
	if !reflect.DeepEqual(withNil, withEmpty) {
		t.Fatalf("nil and empty facts built different requests:\nnil:   %+v\nempty: %+v", withNil, withEmpty)
	}
	want := []string{"action.id", "action.tags", "args." + authoringcatalog.ArgumentQuery}
	for name := range entry.Arguments {
		if name != authoringcatalog.ArgumentQuery {
			want = append(want, "args."+name)
		}
	}
	sort.Strings(want)
	if got := sortedPaths(withNil.Attributes); !reflect.DeepEqual(got, want) {
		t.Fatalf("the request with no facts states %v; want exactly %v", got, want)
	}
	if got := sortedPaths(withNil.Context.ActorChain[0].Attributes); !reflect.DeepEqual(got, []string{"principal.id"}) {
		t.Fatalf("the actor with no facts carries %v; want exactly [principal.id]", got)
	}
}

// Rule 1 (#4254): a fact at a path the enforcer builds itself is refused, naming
// the path, and never overrides what the enforcer built. Evaluate refuses the
// request as CauseRequest on any error normalization returns.
func TestAFactAtAPathTheEnforcerBuildsIsRefused(t *testing.T) {
	act := factsActivation(t)
	// The empty-content arm needs a scope whose controls read the censused
	// detectors; the proxy request plane's do.
	proxy := factsActivationFor(t, legacycompile.PlaneProxyRequest, "")
	emptyDetectors := proxy.DetectorSignalPaths()
	if len(emptyDetectors) == 0 {
		t.Fatal("PREMISE: the proxy request activation reads no censused detector signal, so the empty-content arm proves nothing")
	}
	const rowPolicy = "sys_sqli_admin_bypass"
	rowPath := registry.DetectorID(rowPolicy).SignalPath()
	cases := []struct {
		name string
		act  *activation.Activation
		call Call
		path string
	}{
		{"action.id", act, Call{Facts: contract.AttributeSet{"action.id": contract.Known("Action::"+authoringcatalog.ActionLLMCompletion, contract.ProvPlatform, 1, factsNow)}}, "action.id"},
		{"action.tags", act, Call{Facts: contract.AttributeSet{"action.tags": contract.Known([]any{"stage:llm"}, contract.ProvPlatform, 1, factsNow)}}, "action.tags"},
		// A path under action.* the enforcer never builds: only the prefix refuses it.
		{"action.seam_stated", act, Call{Facts: contract.AttributeSet{"action.seam_stated": contract.Known("high", contract.ProvPlatform, 1, factsNow)}}, "action.seam_stated"},
		{"args.query", act, Call{Facts: contract.AttributeSet{"args." + authoringcatalog.ArgumentQuery: contract.Known("a different query", contract.ProvCaller, 1, factsNow)}}, "args." + authoringcatalog.ArgumentQuery},
		{"principal.id", act, Call{Facts: contract.AttributeSet{"principal.id": contract.Known("User::axonflow-trusted-header:mallory", contract.ProvAuthentication, 1, factsNow)}}, "principal.id"},
		{"a detector an observation row stated", act, Call{
			Observation: &sharedpolicy.Observation{Rows: []sharedpolicy.DetectorFact{{PolicyID: rowPolicy, Ran: true, Matched: true}}},
			Facts:       contract.AttributeSet{rowPath: contract.Known(false, contract.ProvDetector, 1, factsNow)},
		}, rowPath},
		{"a detector empty content stated", proxy, Call{
			EmptyContent: true,
			Facts:        contract.AttributeSet{emptyDetectors[0]: contract.Known(true, contract.ProvDetector, 1, factsNow)},
		}, emptyDetectors[0]},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req, err := factsRequest(t, tc.act, tc.call)
			if err == nil {
				t.Fatalf("a fact at %s was accepted; the request states %v", tc.path, req.Attributes[tc.path])
			}
			if !strings.Contains(err.Error(), tc.path) {
				t.Fatalf("the refusal %q does not name %s", err, tc.path)
			}
			if !strings.Contains(err.Error(), "a path the enforcer builds itself") {
				t.Fatalf("the refusal %q is not the rule for a path the enforcer builds", err)
			}
		})
	}
}

// Rule 5 (R3 A-M1): a seam may state only the principal attributes on the
// allowlist. principal.role is request-bound and is refused by that rule, naming
// the path; principal.region, the one a seam states, lands on the actor.
func TestAPrincipalFactOutsideTheSeamAllowlistIsRefused(t *testing.T) {
	act := factsActivation(t)
	_, err := factsRequest(t, act, Call{Facts: contract.AttributeSet{
		"principal.role": contract.Known("admin", contract.ProvAuthentication, 1, factsNow),
	}})
	if err == nil || !strings.Contains(err.Error(), "principal.role") || !strings.Contains(err.Error(), "no seam may state") {
		t.Fatalf("a principal.role fact = %v; want the allowlist's refusal naming principal.role", err)
	}
	req := mustFactsRequest(t, act, Call{Facts: contract.AttributeSet{
		"principal.region": contract.Absent(contract.ProvAuthentication, 1, factsNow),
	}})
	if _, onActor := req.Context.ActorChain[0].Attributes["principal.region"]; !onActor {
		t.Error("the allowlisted principal.region did not land on the actor")
	}
}

// The detector arm refuses only a path the enforcer built for THIS request: a
// seam that passes no observation and no empty content, and whose own reader is
// the detector source, may state the detector facts it produced - the workflow
// plane's dynamic content detectors, which no observation carries.
func TestADetectorFactTheEnforcerDidNotBuildIsStated(t *testing.T) {
	act := factsActivation(t)
	path := legacycompile.DynamicContentDetectorPath("sys_dyn_debug_restrict")
	if !strings.HasPrefix(path, registry.DetectorSignalPrefix) {
		t.Fatalf("PREMISE: %s is not a detector signal path, so accepting it proves nothing about the detector arm", path)
	}
	req := mustFactsRequest(t, act, Call{Facts: contract.AttributeSet{path: contract.Known(true, contract.ProvDetector, 1, factsNow)}})
	if f := req.Attributes[path]; f.State != contract.StateKnown || f.Value != true {
		t.Fatalf("%s is %s %v; want the stated KNOWN true", path, f.State, f.Value)
	}
}

// Rule 2 (#4254): a declared argument the enforcer would mark ABSENT may be
// stated by a fact, and is then KNOWN with the fact's value.
func TestAFactStatesADeclaredArgumentTheEnforcerWouldMarkAbsent(t *testing.T) {
	act := factsActivation(t)
	_, entry := factsEntry(t, act)
	const name = "request_type"
	if _, declared := entry.Arguments[name]; !declared {
		t.Fatalf("PREMISE: %s declares no argument %s", authoringcatalog.ActionToolCall, name)
	}
	path := "args." + name
	if f := mustFactsRequest(t, act, Call{}).Attributes[path]; f.State != contract.StateAbsent {
		t.Fatalf("with no facts %s is %s; want ABSENT", path, f.State)
	}
	req := mustFactsRequest(t, act, Call{Facts: contract.AttributeSet{path: contract.Known("workflow_step_gate", contract.ProvCaller, 1, factsNow)}})
	if f := req.Attributes[path]; f.State != contract.StateKnown || f.Value != "workflow_step_gate" {
		t.Fatalf("with the argument stated %s is %s %v; want KNOWN workflow_step_gate", path, f.State, f.Value)
	}
}

// Rule 3 (#4254): a principal fact describes the subject, so it goes onto the
// root actor; every other fact goes to the shared set. The merged request is
// one the contract admits.
func TestAPrincipalFactGoesOntoTheRootActor(t *testing.T) {
	act := factsActivation(t)
	req := mustFactsRequest(t, act, Call{Facts: contract.AttributeSet{
		"principal.region": contract.Absent(contract.ProvAuthentication, 1, factsNow),
		"env.environment":  contract.Known("production", contract.ProvPlatform, 1, factsNow),
	}})
	actor := req.Context.ActorChain[0].Attributes
	if _, onActor := actor["principal.region"]; !onActor {
		t.Errorf("principal.region is not on the root actor: %v", sortedPaths(actor))
	}
	if _, shared := req.Attributes["principal.region"]; shared {
		t.Error("principal.region was put in the shared set")
	}
	if _, shared := req.Attributes["env.environment"]; !shared {
		t.Errorf("env.environment is not in the shared set: %v", sortedPaths(req.Attributes))
	}
	if _, onActor := actor["env.environment"]; onActor {
		t.Error("env.environment was put on the actor")
	}
	if err := req.Validate(); err != nil {
		t.Fatalf("the merged request is one the contract refuses: %v", err)
	}
}
