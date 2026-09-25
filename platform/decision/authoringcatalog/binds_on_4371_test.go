// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package authoringcatalog_test

import (
	"sort"
	"strings"
	"testing"

	"axonflow/platform/decision/authoring"
	"axonflow/platform/decision/authoringcatalog"
	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/legacycompile"
	"axonflow/platform/decision/pdp"
	"axonflow/platform/decision/registry"
)

// TestScopeActionsNameOnlyDeploymentActions welds legacycompile's restated
// action names (#4371) to the deployment vocabulary's: every action a scope
// presents is a deployment action, and every deployment action is presented
// somewhere, so a control selecting it has a scope it can bind on.
func TestScopeActionsNameOnlyDeploymentActions(t *testing.T) {
	deployment := map[string]bool{}
	for _, a := range authoringcatalog.DeploymentActions() {
		deployment[a] = true
	}
	presented := map[string]bool{}
	for _, name := range legacycompile.EnforcingScopes() {
		plane, phase, _ := strings.Cut(name, ":")
		for _, a := range legacycompile.ScopeActions(legacycompile.MustScopeFor(legacycompile.Plane(plane), legacycompile.Phase(phase))) {
			if !deployment[a] {
				t.Errorf("scope %s presents %q, which is not a deployment action", name, a)
			}
			presented[a] = true
		}
	}
	for a := range deployment {
		if !presented[a] {
			t.Errorf("deployment action %q is presented on no scope", a)
		}
	}
}

// TestTheDeploymentStatesThePlanesEachActionIsPresentedOn pins, per edition,
// the scopes the deployment vocabulary lets a control name for each action:
// the plane matrix of #4371 as the vocabulary carries it. Both editions carry
// the same ten scopes - the tenth is orchestrator_request, the orchestrator's
// two request routes (#4249 row 5706695827), which presents llm.completion and
// agent.invoke on every edition - and Enterprise an eleventh: the cowork ingest
// storage pass (#4259), whose plane only the Enterprise build registers
// (registry/legacy_plane_peps.tsv).
func TestTheDeploymentStatesThePlanesEachActionIsPresentedOn(t *testing.T) {
	community := map[string][]string{
		authoringcatalog.ActionToolCall:      {"decide", "gateway_request", "map", "mcp:request", "mcp:response", "wcp"},
		authoringcatalog.ActionLLMCompletion: {"decide", "gateway_request", "map", "openai_compatible", "orchestrator_request", "orchestrator_response", "proxy_request", "wcp"},
		authoringcatalog.ActionAgentInvoke:   {"decide", "orchestrator_request", "wcp"},
	}
	enterprise := map[string][]string{
		authoringcatalog.ActionToolCall:      {"cowork_ingest", "decide", "gateway_request", "map", "mcp:request", "mcp:response", "wcp"},
		authoringcatalog.ActionLLMCompletion: {"cowork_ingest", "decide", "gateway_request", "map", "openai_compatible", "orchestrator_request", "orchestrator_response", "proxy_request", "wcp"},
		authoringcatalog.ActionAgentInvoke:   {"decide", "orchestrator_request", "wcp"},
	}
	for _, edition := range []registry.Edition{registry.EditionCommunity, registry.EditionEnterprise} {
		want := community
		if edition == registry.EditionEnterprise {
			want = enterprise
		}
		dep := testDeployment()
		dep.Edition = edition
		snap, err := authoringcatalog.Resolve(authoringcatalog.SourceDeployment, dep)
		if err != nil {
			t.Fatal(err)
		}
		for local, planes := range want {
			entry, ok := snap.Catalog.Actions["Action::"+local]
			if !ok {
				t.Fatalf("%s: the deployment vocabulary has no %s", edition, local)
			}
			if strings.Join(entry.Planes, ",") != strings.Join(planes, ",") {
				t.Errorf("%s: %s is presented on %v, want %v", edition, local, entry.Planes, planes)
			}
			if !sort.StringsAreSorted(entry.Planes) {
				t.Errorf("%s: %s's planes %v are not sorted", edition, local, entry.Planes)
			}
		}
	}
}

// approvalOnToolCall is the document the EQwise install could not write on
// v11.0.0 (#4249 row 5763392959): an organization-wide approval requirement on
// Action::tool.call, now scoped by binds_on (nil = unscoped).
func approvalOnToolCall(binds []string) pdp.Document {
	return pdp.Document{
		Root: pdp.RootOrganization, Version: 1,
		Attributes: []pdp.AttributeSchema{
			{Path: pdp.ActionIDPath, Type: pdp.TypeString},
			{Path: pdp.ActionTagsPath, Type: pdp.TypeArray},
		},
		Policies: []pdp.Policy{{
			ID: "approve.tool_calls", Authority: contract.AuthorityRequirement, Root: pdp.RootOrganization,
			Scope:   pdp.Scope{Organization: true},
			Actions: pdp.ActionSelector{Actions: []contract.ID{toolCallID()}},
			Where:   pdp.True(),
			Obligations: []contract.Obligation{{
				Type: contract.ObApprovalChallenge, Mandatory: true, SourcePolicy: "approve.tool_calls", SchemaVersion: 1,
				Params: map[string]string{"quorum": "1", "eligible": "Group::axonflow-minted:approvers"},
			}},
			Mandatory: true,
			BindsOn:   pdp.BindingScopes(binds),
		}},
	}
}

// TestBindsOnIsCheckedAgainstTheDeploymentVocabulary publishes through the
// real authoring API over the real deployment vocabulary (not a fixture world):
// each refusal of #4371 arrives as its code naming the offending scope, and the
// document the customer wanted publishes.
func TestBindsOnIsCheckedAgainstTheDeploymentVocabulary(t *testing.T) {
	cases := []struct {
		name     string
		binds    []string
		code     string
		fragment string
	}{
		{"the step gate and the multi-agent plane", []string{"wcp", "map"}, "", ""},
		{"unscoped, as before #4371", nil, "", ""},
		{"an empty list", []string{}, authoring.CodeBindsOnEmpty, "binds_on is []"},
		{"the issue's first name for the step gate", []string{"workflow_step_gate"}, authoring.CodePlaneNotDeclared, `"workflow_step_gate"`},
		{"a two-phase plane without its phase", []string{"mcp"}, authoring.CodePlaneNotDeclared, `"mcp"`},
		{"a plane with no enforcing seam", []string{"policy_test"}, authoring.CodePlaneNotDeclared, `"policy_test"`},
		{"a plane that presents no tool call", []string{"wcp", "openai_compatible"}, authoring.CodeActionNotPresentedOnPlane, `"openai_compatible"`},
		{"the response of an MCP call is a tool call too", []string{"mcp:response"}, "", ""},
		{"a repeated plane", []string{"wcp", "wcp"}, authoring.CodeBindsOnDuplicatePlane, `"wcp"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fixture := []authoring.Fixture{{
				Name: "a tool call",
				Attributes: contract.AttributeSet{
					pdp.ActionIDPath:   contract.Known(toolCallID().String(), contract.ProvPlatform, 1, stepAt),
					pdp.ActionTagsPath: contract.Known([]any{"stage:tool"}, contract.ProvPlatform, 1, stepAt),
				},
				Expect: map[string]pdp.Verdict{"approve.tool_calls": pdp.VerdictMatch},
			}}
			findings, err := publishStepDocument(t, authoring.EditionEnterprise, approvalOnToolCall(tc.binds), fixture)
			if tc.code == "" {
				if err != nil {
					t.Fatalf("refused: %v\nfindings: %v", err, findings)
				}
				return
			}
			if err == nil {
				t.Fatalf("published; want %s", tc.code)
			}
			if !findingNaming(findings, tc.code, tc.fragment) {
				t.Fatalf("want %s naming %s, got %v", tc.code, tc.fragment, findings)
			}
		})
	}
}

// TestAnApprovalBindingOnTheMCPResponsePassIsWarned: the response pass has no
// approval hold, so an approval requirement that binds there - by naming
// mcp:response, or by an absent binds_on, which binds everywhere - is warned
// at publication, and still published: absent is what every document before
// #4371 means. Scoping it to the request pass is the author's answer and is
// not warned.
func TestAnApprovalBindingOnTheMCPResponsePassIsWarned(t *testing.T) {
	fixture := []authoring.Fixture{{
		Name: "a tool call",
		Attributes: contract.AttributeSet{
			pdp.ActionIDPath:   contract.Known(toolCallID().String(), contract.ProvPlatform, 1, stepAt),
			pdp.ActionTagsPath: contract.Known([]any{"stage:tool"}, contract.ProvPlatform, 1, stepAt),
		},
		Expect: map[string]pdp.Verdict{"approve.tool_calls": pdp.VerdictMatch},
	}}
	for _, tc := range []struct {
		name     string
		binds    []string
		warned   bool
		fragment string
	}{
		{"named", []string{"mcp:response", "wcp"}, true, "binds_on names mcp:response"},
		{"absent", nil, true, "binds_on is absent"},
		{"scoped to the request pass", []string{"mcp:request"}, false, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			findings, err := publishStepDocument(t, authoring.EditionEnterprise, approvalOnToolCall(tc.binds), fixture)
			if err != nil {
				t.Fatalf("refused; a warning must not refuse: %v\n%v", err, findings)
			}
			got := findingNaming(findings, authoring.CodeBindsOnMCPResponse, tc.fragment)
			if tc.warned && !got {
				t.Fatalf("want %s naming %q, got %v", authoring.CodeBindsOnMCPResponse, tc.fragment, findings)
			}
			if !tc.warned && findingNaming(findings, authoring.CodeBindsOnMCPResponse, "") {
				t.Fatalf("warned although binds_on does not reach mcp:response: %v", findings)
			}
		})
	}
}
