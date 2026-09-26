// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"context"
	"database/sql/driver"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"

	"axonflow/platform/decision/activation"
	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/legacycompile"
	"axonflow/platform/decision/pdp"
	sharedpolicy "axonflow/platform/shared/policy"
)

// AN ADMISSION REFUSAL IS NAMED ON THE WIRE (#4249). For a day every
// OIDC-admitted user on the MCP-server session was answered
// {"allowed": false, "block_reason": "unknown_realm"}; the sentence naming the
// realm was on the engine's trace and nowhere a caller or an audit row could
// read it. Each rendering site is driven with the decision the real registry
// refuses with.

func unknownRealmRefusal(t *testing.T) (*contract.Decision, string) {
	t.Helper()
	oidc := contract.MustParseID(contract.KindPrincipal, "User::oidc:00u-alice")
	adm := (&pdp.Registry{
		Actions: map[string]pdp.ActionEntry{"Action::tool.call": {MaxDelegationDepth: 1}},
		Realms:  map[string]bool{"axonflow-minted": true},
	}).Admit(&contract.Request{
		Principal: oidc,
		Action:    contract.MustParseID(contract.KindAction, "Action::tool.call"),
		Context:   contract.Context{ActorChain: []contract.Actor{{ID: oidc}}},
	})
	if !adm.Failed || adm.Reason != contract.ReasonUnknownRealm || adm.Detail == "" {
		t.Fatalf("the registry did not refuse the undeclared realm: %+v", adm)
	}
	return &contract.Decision{
		Authorization: contract.AuthzDeny, State: contract.StateDeny, Reason: adm.Reason,
		Trace: &contract.Trace{State: contract.StateDeny, Reason: adm.Reason, Remediation: adm.Detail},
	}, adm.Detail
}

// TestDecideAndCheckPolicyNameTheRealmAnAdmissionRefused: mapAnchoredDecision
// is decide's rendering and the MCP request pass's, and projectMCPStatement
// joins its reasons into check_policy's block_reason, which is also what the
// explainable audit row records.
func TestDecideAndCheckPolicyNameTheRealmAnAdmissionRefused(t *testing.T) {
	dec, detail := unknownRealmRefusal(t)
	for _, scope := range []struct {
		name string
		act  *activation.Activation
	}{
		{"decide", &activation.Activation{PolicyBundle: "sha256:bundle-under-test", Scope: decideSeamScope}},
		{"mcp request pass", &activation.Activation{PolicyBundle: "sha256:bundle-under-test", Scope: mcpRequestSeamScope}},
	} {
		got := mapAnchoredDecision(requestPassEnforcement{engine: decisionEngineAnchored}, dec, scope.act, "")
		if got.verdict != VerdictDeny || got.reasonCode != string(contract.ReasonUnknownRealm) {
			t.Fatalf("%s: verdict %q reason %q; want deny unknown_realm", scope.name, got.verdict, got.reasonCode)
		}
		if want := []string{"unknown_realm", detail}; !reflect.DeepEqual(got.reasons, want) {
			t.Fatalf("%s: reasons %q; want %q", scope.name, got.reasons, want)
		}
		if scope.act.Scope != mcpRequestSeamScope {
			continue
		}
		projected := projectMCPStatement(context.Background(), "org-under-test", got, pepHandshakeResolution{}, "SELECT 1", "SELECT 1", sharedpolicy.EvalOptions{}, nil)
		want := `unknown_realm; actor_chain[0] "User::oidc:00u-alice" resolves in realm "oidc", which has no declared trust realm`
		if projected.blockReason != want || projected.reasonCode != string(contract.ReasonUnknownRealm) {
			t.Fatalf("check_policy block_reason %q (code %q); want %q", projected.blockReason, projected.reasonCode, want)
		}
	}
}

// TestCheckOutputNamesTheRealmAnAdmissionRefused: anchoredResponse is the MCP
// response pass's rendering.
func TestCheckOutputNamesTheRealmAnAdmissionRefused(t *testing.T) {
	dec, _ := unknownRealmRefusal(t)
	act := &activation.Activation{PolicyBundle: "sha256:bundle-under-test", Scope: mcpResponseSeamScope}
	res, verdict, reason, err := anchoredResponse(context.Background(), anchoredVerdict{decision: dec, act: act}, pepHandshakeResolution{}, nil, sharedpolicy.EvalOptions{}, 0, nil)
	if err != nil || verdict != VerdictDeny || reason != string(contract.ReasonUnknownRealm) {
		t.Fatalf("verdict %q reason %q err %v; want deny unknown_realm", verdict, reason, err)
	}
	const want = `unknown_realm; actor_chain[0] "User::oidc:00u-alice" resolves in realm "oidc", which has no declared trust realm`
	if !res.Blocked || res.BlockReason != want {
		t.Fatalf("blocked=%v block_reason %q; want %q", res.Blocked, res.BlockReason, want)
	}
	if res.BlockedBy != nil {
		t.Fatalf("blocked_by %+v; no policy ran, so none blocked", res.BlockedBy)
	}
}

// TestNothingAPolicyWroteReachesTheWireAsAnAdmissionDetail: what may appear is
// the caller's own identity and request; nothing from storage. The trace's
// remediation is also written by obligation composition after policies
// MATCHED (the same schema_violation code, a detail naming what a policy
// attached) and by policy refusals, so each carries a storage-shaped marker and
// neither rendering site may show it.
func TestNothingAPolicyWroteReachesTheWireAsAnAdmissionDetail(t *testing.T) {
	const marker = "typed_policy_artifacts row org-4249 source: SECRET-POLICY-TEXT"
	for name, dec := range map[string]*contract.Decision{
		"a composed schema_violation after a permission matched": {
			Authorization: contract.AuthzDeny, State: contract.StateDeny, Reason: contract.ReasonSchemaViolation,
			Determining: contract.Determining{MatchedPermissions: []string{"grant.x"}},
			Trace:       &contract.Trace{State: contract.StateDeny, Reason: contract.ReasonSchemaViolation, Remediation: marker},
		},
		"an unknown_realm code with a constraint determining": {
			Authorization: contract.AuthzDeny, State: contract.StateDeny, Reason: contract.ReasonUnknownRealm,
			Determining: contract.Determining{MatchedConstraints: []string{"ceiling.x"}},
			Trace:       &contract.Trace{State: contract.StateDeny, Reason: contract.ReasonUnknownRealm, Remediation: marker},
		},
		"an evaluation error with nothing determining": {
			Authorization: contract.AuthzDeny, State: contract.StateDeny, Reason: contract.ReasonEvaluationError,
			Trace: &contract.Trace{State: contract.StateDeny, Reason: contract.ReasonEvaluationError, Remediation: marker},
		},
		"an explicit constraint": {
			Authorization: contract.AuthzDeny, State: contract.StateDeny, Reason: contract.ReasonExplicitConstraint,
			Determining: contract.Determining{MatchedConstraints: []string{"ceiling.x"}},
			Trace:       &contract.Trace{State: contract.StateDeny, Reason: contract.ReasonExplicitConstraint, Remediation: marker},
		},
	} {
		for _, scope := range []legacycompile.EnforcementScope{decideSeamScope, mcpRequestSeamScope} {
			got := mapAnchoredDecision(requestPassEnforcement{engine: decisionEngineAnchored}, dec, &activation.Activation{PolicyBundle: "sha256:b", Scope: scope}, "")
			for _, r := range got.reasons {
				if strings.Contains(r, "SECRET-POLICY-TEXT") {
					t.Fatalf("%s on %s: reasons %q carry the policy-written remediation", name, scope, got.reasons)
				}
			}
		}
		res, _, _, err := anchoredResponse(context.Background(), anchoredVerdict{decision: dec, act: &activation.Activation{PolicyBundle: "sha256:b", Scope: mcpResponseSeamScope}}, pepHandshakeResolution{}, nil, sharedpolicy.EvalOptions{}, 0, nil)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(res.BlockReason, "SECRET-POLICY-TEXT") {
			t.Fatalf("%s: check_output block_reason %q carries the policy-written remediation", name, res.BlockReason)
		}
	}
}

// TestACallersArgumentNameCannotForgeAReason: an argument name is the caller's
// own text, and it may contain "; " and spaces (contract.ValidateAttributePath
// allows both). The admission detail follows the bare code joined by "; ", so an
// unquoted name could read as a second reason the engine never gave; every name
// arrives quoted, on the wire and in the stored audit reason (#4249, R3 round 1).
func TestACallersArgumentNameCannotForgeAReason(t *testing.T) {
	const forged = "x; explicit_constraint ceiling.forged"
	minted := contract.MustParseID(contract.KindPrincipal, "User::axonflow-minted:alice")
	adm := (&pdp.Registry{
		Actions: map[string]pdp.ActionEntry{"Action::tool.call": {MaxDelegationDepth: 1, Arguments: map[string]pdp.ValueType{"query": pdp.TypeString}}},
		Realms:  map[string]bool{"axonflow-minted": true},
	}).Admit(&contract.Request{
		Principal: minted, Action: contract.MustParseID(contract.KindAction, "Action::tool.call"),
		Context:    contract.Context{ActorChain: []contract.Actor{{ID: minted}}},
		Attributes: contract.AttributeSet{"args." + forged: contract.Known("v", contract.ProvCaller, 1, time.Now())},
	})
	if !adm.Failed || adm.Reason != contract.ReasonSchemaViolation {
		t.Fatalf("admission %+v; want schema_violation", adm)
	}
	dec := &contract.Decision{Authorization: contract.AuthzDeny, State: contract.StateDeny, Reason: adm.Reason,
		Trace: &contract.Trace{State: contract.StateDeny, Reason: adm.Reason, Remediation: adm.Detail}}
	const want = `schema_violation; unknown argument fields "x; explicit_constraint ceiling.forged"`

	got := mapAnchoredDecision(requestPassEnforcement{engine: decisionEngineAnchored}, dec, &activation.Activation{PolicyBundle: "sha256:b", Scope: mcpRequestSeamScope}, "")
	projected := projectMCPStatement(context.Background(), "org-under-test", got, pepHandshakeResolution{}, "SELECT 1", "SELECT 1", sharedpolicy.EvalOptions{}, nil)
	if projected.blockReason != want {
		t.Fatalf("check_policy block_reason %q; want %q", projected.blockReason, want)
	}
	res, _, _, err := anchoredResponse(context.Background(), anchoredVerdict{decision: dec, act: &activation.Activation{PolicyBundle: "sha256:b", Scope: mcpResponseSeamScope}}, pepHandshakeResolution{}, nil, sharedpolicy.EvalOptions{}, 0, nil)
	if err != nil || res.BlockReason != want {
		t.Fatalf("check_output block_reason %q err %v; want %q", res.BlockReason, err, want)
	}

	// The stored reason: the explainable audit row check_policy writes with that
	// block_reason (mcp_server_handler.go), read back from its policy_details.
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var details []byte
	args := make([]driver.Value, 19)
	for i := range args {
		args[i] = sqlmock.AnyArg()
	}
	args[13] = captureArg{dst: &details}
	mock.ExpectExec("INSERT INTO audit_logs").WithArgs(args...).WillReturnResult(sqlmock.NewResult(1, 1))
	writeExplainableAuditLog(context.Background(), db, "dec-4249-forged", "req-4249", "tenant", "org", "client", "a@b.c", "1", "user",
		"mcp_check_policy", "descriptor", "hash", projected.blockReason, "", nil, "", 0)
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("the audit row was not written: %v", err)
	}
	var stored map[string]any
	if err := json.Unmarshal(details, &stored); err != nil || stored["reason"] != want {
		t.Fatalf("the audit row stores reason %v (err %v); want %q", stored["reason"], err, want)
	}
}
