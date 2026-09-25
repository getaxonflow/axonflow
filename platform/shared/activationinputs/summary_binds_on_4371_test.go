// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package activationinputs_test

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"axonflow/platform/decision/authoring"
	"axonflow/platform/decision/authoringcatalog"
	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/legacycompile"
	"axonflow/platform/decision/pdp"
	"axonflow/platform/shared/activationinputs"
)

// TestTheSummaryNamesTheControlsNotBoundOnItsScope (#4371): a published
// document's control scoped to the step gate is counted on wcp and, on every
// other scope, neither counted nor enforced but named in not_bound_here. A
// summary of a document that scopes nothing carries no not_bound_here member,
// so it is byte-identical to what it was.
func TestTheSummaryNamesTheControlsNotBoundOnItsScope(t *testing.T) {
	ctx := context.Background()
	b := deploymentBuilder(t)
	pub, priv, _ := ed25519.GenerateKey(nil)
	trust := pdp.NewTrustStore()
	trust.Authorize(pdp.RootOrganization, "org-key", pub)
	b.Trust = authoring.StaticTrust(trust)
	api, err := authoring.NewAPI(b.Snapshot.Catalog, b.Trust, b.Profile)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)
	toolCall := contract.MustParseID(contract.KindAction, "Action::"+authoringcatalog.ActionToolCall)
	publish := func(binds []string) *authoring.Artifact {
		pack, err := authoringcatalog.BaselinePermissionPack(b.Snapshot)
		if err != nil {
			t.Fatal(err)
		}
		doc := pdp.Document{Root: pdp.RootOrganization, Version: 1, Attributes: []pdp.AttributeSchema{},
			Policies: append(append([]pdp.Policy(nil), pack.Policies...), pdp.Policy{
				ID: "no.tool_steps", Authority: contract.AuthorityConstraint, Root: pdp.RootOrganization,
				Scope: pdp.Scope{Organization: true}, Actions: pdp.ActionSelector{Actions: []contract.ID{toolCall}},
				Where: pdp.True(), BindsOn: pdp.BindingScopes(binds),
			})}
		var fixtures []authoring.Fixture
		for _, p := range pack.Policies {
			local := strings.TrimPrefix(p.ID, "baseline.permit.")
			fixtures = append(fixtures, authoring.Fixture{
				Name: local,
				Attributes: contract.AttributeSet{
					"action.id":   contract.Known("Action::"+local, contract.ProvPlatform, 1, now),
					"action.tags": contract.Known([]any{"stage:" + strings.SplitN(local, ".", 2)[0]}, contract.ProvPlatform, 1, now),
					"args.query":  contract.Known("hello", contract.ProvCaller, 1, now),
				},
				Expect: map[string]pdp.Verdict{p.ID: pdp.VerdictMatch, "no.tool_steps": map[bool]pdp.Verdict{true: pdp.VerdictMatch, false: pdp.VerdictNoMatch}[local == authoringcatalog.ActionToolCall]},
			})
		}
		meta := authoring.Metadata{DocumentID: "scoped", Title: "scoped", Author: contract.MustParseID(contract.KindPrincipal, "User::axonflow-trusted-header:author")}
		d, findings, err := authoring.NewDocument(authoring.Document{Metadata: meta, Policy: doc}, b.Snapshot.Catalog)
		if err != nil {
			t.Fatalf("%v\n%v", err, findings)
		}
		art, findings, err := api.Publish(ctx, d, authoring.PublishOptions{Root: pdp.RootOrganization, KeyID: "org-key", PrivateKey: priv, Fixtures: fixtures, Now: now})
		if err != nil {
			t.Fatalf("%v\n%v", err, findings)
		}
		return art
	}
	summary := func(art *authoring.Artifact, plane legacycompile.Plane, phase legacycompile.Phase) activationinputs.Summary {
		s, err := activationinputs.ActiveSummary(ctx, b.Source(plane, phase), art, false)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}

	scoped := publish([]string{"wcp"})
	onWCP := summary(scoped, legacycompile.PlaneWCP, "")
	onMCP := summary(scoped, legacycompile.PlaneMCP, legacycompile.PhaseRequest)
	if onWCP.NotBoundHere != nil {
		t.Errorf("wcp: not_bound_here %v; the control binds there", onWCP.NotBoundHere)
	}
	if !reflect.DeepEqual(onMCP.NotBoundHere, []string{"no.tool_steps"}) {
		t.Errorf("mcp:request: not_bound_here %v; want [no.tool_steps]", onMCP.NotBoundHere)
	}
	if onWCP.Organization != onMCP.Organization+1 {
		t.Errorf("the organization's count is %d on wcp and %d on mcp:request; the scoped control counts only where it binds",
			onWCP.Organization, onMCP.Organization)
	}

	unscoped := summary(publish(nil), legacycompile.PlaneMCP, legacycompile.PhaseRequest)
	raw, err := json.Marshal(unscoped)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "not_bound_here") {
		t.Errorf("a summary of a document that scopes nothing carries not_bound_here: %s", raw)
	}
}
