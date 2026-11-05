// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"axonflow/platform/decision/authoring"
	"axonflow/platform/decision/authoringcatalog"
	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/pdp"
	"axonflow/platform/orchestrator/workflow_control"
	"axonflow/platform/shared/authoringvocabulary"
)

func TestStepGateStatesTypedMoneyFromInputsItRuns(t *testing.T) {
	step := contentStep(workflow_control.StepTypeToolCall,
		map[string]interface{}{"amount_minor": float64(94900), "currency": "USD"},
		&workflow_control.ToolContext{ToolName: "support-ops.issue_refund",
			ToolInput: map[string]interface{}{"amount_minor": float64(94900), "currency": "USD"}})
	req := (&WCPPolicyAdapter{}).convertToOrchestratorRequest(step)
	facts, _, err := stepPlaneProducer(t).Produce(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]any{
		"args.step_input.amount_minor": float64(94900), "args.step_input.currency": "USD",
		"args.tool_input.amount_minor": float64(94900), "args.tool_input.currency": "USD",
	} {
		got := facts[path]
		if got.State != contract.StateKnown || got.Value != want || got.Source != contract.ProvCaller {
			t.Errorf("%s = %+v, want known caller value %v", path, got, want)
		}
	}
	step.ToolContext.ToolInput["amount_minor"] = "94900"
	req = (&WCPPolicyAdapter{}).convertToOrchestratorRequest(step)
	facts, _, err = stepPlaneProducer(t).Produce(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if facts["args.tool_input.amount_minor"].State != contract.StateUnknown {
		t.Fatalf("a string amount was accepted: %+v", facts["args.tool_input.amount_minor"])
	}
}

func TestPublishedRefundThresholdHoldsTheActualWCPStep(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", string(authoring.EditionEnterprise))
	t.Setenv("ENVIRONMENT", "production")
	content, err := os.ReadFile(filepath.Join("..", "..", "ee", "examples", "payment-exception-shadow", "fixtures", "refund-step-policy-example.json"))
	if err != nil {
		t.Fatal(err)
	}
	var policy pdp.Document
	if err := json.Unmarshal(content, &policy); err != nil {
		t.Fatal(err)
	}
	if len(policy.Policies) != 1 || policy.Policies[0].ID != "support.refund.usd.step_review" {
		t.Fatal("refund step example must name one threshold policy")
	}
	snap, err := authoringvocabulary.ResolveCatalogValue(authoringcatalog.SourceDeployment, authoringvocabulary.CatalogDeployment{})
	if err != nil {
		t.Fatal(err)
	}
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
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
	meta := authoring.Metadata{DocumentID: "refund-step-threshold", Title: "Refund step threshold",
		Author: contract.MustParseID(contract.KindPrincipal, "User::axonflow-minted:installer")}
	doc, findings, err := authoring.NewDocument(authoring.Document{Metadata: meta, Policy: policy}, snap.Catalog)
	if err != nil {
		t.Fatalf("refund step document: %v\n%v", err, findings)
	}
	now := time.Now().UTC()
	artifact, findings, err := api.Publish(context.Background(), doc, authoring.PublishOptions{
		Root: pdp.RootOrganization, KeyID: "org-key", PrivateKey: priv, Now: now,
		Approvers: []contract.ID{contract.MustParseID(contract.KindPrincipal, "User::axonflow-minted:reviewer")},
		Fixtures: []authoring.Fixture{{
			Name: "USD refund above the step gate threshold",
			Attributes: contract.AttributeSet{
				pdp.ActionIDPath:               contract.Known("Action::"+authoringcatalog.ActionToolCall, contract.ProvPlatform, 1, now),
				pdp.ActionTagsPath:             contract.Known([]any{"stage:tool"}, contract.ProvPlatform, 1, now),
				"args.context.tool__name":      contract.Known("support-ops.issue_refund", contract.ProvCaller, 1, now),
				"args.tool_input.currency":     contract.Known("USD", contract.ProvCaller, 1, now),
				"args.tool_input.amount_minor": contract.Known(float64(94900), contract.ProvCaller, 1, now),
			},
			Expect: map[string]pdp.Verdict{"support.refund.usd.step_review": pdp.VerdictMatch},
		}},
	})
	if err != nil {
		t.Fatalf("publish refund step document: %v\n%v", err, findings)
	}
	reviewer := contract.MustParseID(contract.KindPrincipal, "User::axonflow-minted:reviewer")
	if _, err := api.Promote(context.Background(), pdp.RootOrganization, artifact.Digest(), reviewer, now, "refund threshold test"); err != nil {
		t.Fatal(err)
	}
	e := stepEnforcer(t, &stepDocuments{api: api, keyID: "org-key", orgPub: pub})
	previous := orchestratorEnforcerInstance.Load()
	orchestratorEnforcerInstance.Store(&orchestratorEnforcerSlot{enforcement: e})
	t.Cleanup(func() { orchestratorEnforcerInstance.Store(previous) })
	withStepGateFacts(t, true, seedDynamicRows(t)...)

	for _, tc := range []struct {
		name     string
		tool     string
		amount   any
		currency string
		want     workflow_control.GateDecision
	}{
		{"over threshold", "support-ops.issue_refund", float64(94900), "USD", workflow_control.GateDecisionRequireApproval},
		{"below threshold", "support-ops.issue_refund", float64(49900), "USD", workflow_control.GateDecisionAllow},
		{"missing amount", "support-ops.issue_refund", nil, "USD", workflow_control.GateDecisionBlock},
		{"malformed amount", "support-ops.issue_refund", "94900", "USD", workflow_control.GateDecisionBlock},
		{"other currency", "support-ops.issue_refund", float64(94900), "EUR", workflow_control.GateDecisionAllow},
		{"other tool", "support-ops.lookup", float64(94900), "USD", workflow_control.GateDecisionAllow},
	} {
		t.Run(tc.name, func(t *testing.T) {
			step := contentStep(workflow_control.StepTypeToolCall, nil,
				&workflow_control.ToolContext{ToolName: tc.tool, ToolInput: map[string]interface{}{"amount_minor": tc.amount, "currency": tc.currency}})
			step.OrgID = "org-a"
			step.TenantID = "tenant-a"
			step.ClientID = "client-a"
			h := http.Header{}
			h.Set("X-Org-ID", "org-a")
			h.Set("X-Client-ID", "client-a")
			ctx := withWCPPlaneSubject(context.Background(), headerCredentialSubject(h))
			got := NewWCPPolicyAdapter().EvaluateStepGate(ctx, step)
			if got.Decision != tc.want {
				t.Fatalf("gate decision %s, want %s; reason %s; policies %v", got.Decision, tc.want, got.Reason, got.PolicyIDs)
			}
			if tc.want == workflow_control.GateDecisionRequireApproval && !slices.Contains(got.PolicyIDs, policy.Policies[0].ID) {
				t.Fatalf("hold did not name typed refund policy: %+v", got)
			}
		})
	}
}
