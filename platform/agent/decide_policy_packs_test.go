// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"database/sql/driver"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"

	"axonflow/platform/decision/activation"
	"axonflow/platform/decision/policypack"
	sharedpolicy "axonflow/platform/shared/policy"
)

// AN INSTALLED POLICY PACK ON /api/v1/decide (PRD v11 §1.9, #4126), through the
// real handler, seam, enforcer and detector layer: the pack's controls decide
// from the detector facts its detectors produce, and the wire and the audit
// row name the pack by digest. The pack is synthetic, so this runs on every
// edition's test build; the FinCrime pack itself is exercised by
// runtime-e2e/3329_fincrime_pack.

func decidePackUnderTest(t *testing.T) *policypack.Pack {
	t.Helper()
	src := &policypack.Source{
		ID: "testpack", Version: 1,
		Approval: &policypack.ApproverPool{Quorum: 1, Group: "testpack-approvers"},
		Detectors: []policypack.Detector{
			// Context-anchored: it matches only through decide's lift of the
			// fincrime context objects into the scanned parameters.
			{ID: "tp_amount", Name: "Amount cap", Category: "fincrime", Severity: "high", Phase: "request", Action: "block", Priority: 95, Pattern: `"amount":\s*[1-9][0-9]{4,}`},
			// Statement-anchored.
			{ID: "tp_execute", Name: "Execution step-up", Category: "fincrime", Severity: "medium", Phase: "request", Action: "require_approval", Priority: 85, Pattern: `(?i)\bexecute\b[\s\S]{0,60}?\bpayment\b`},
		},
	}
	raw, err := json.Marshal(src)
	if err != nil {
		t.Fatal(err)
	}
	committed, err := policypack.Render(src)
	if err != nil {
		t.Fatal(err)
	}
	p, err := policypack.Load(raw, committed)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// enfDecideWithContext is enfDecide with DecideRequest.Context set.
func enfDecideWithContext(t *testing.T, org, stage, query string, reqContext map[string]interface{}) enfResponse {
	t.Helper()
	body := DecideRequest{Stage: stage, Target: DecisionTarget{Type: stage}, Query: query,
		UserToken: enfMintUserToken(t, org, enfUser), Context: reqContext}
	rr := httptest.NewRecorder()
	handleDecide(rr, decideEnterpriseReq(t, body, org, org))
	out := enfResponse{code: rr.Code, raw: rr.Body.Bytes(), body: map[string]json.RawMessage{}}
	if err := json.Unmarshal(rr.Body.Bytes(), &out.body); err != nil {
		t.Fatalf("the response is not a JSON object: %v\n%s", err, rr.Body.String())
	}
	return out
}

// policyPacksMatcher asserts the audit row's policy_details names exactly the
// given packs.
type policyPacksMatcher struct{ refs []string }

func (m policyPacksMatcher) Match(v driver.Value) bool {
	raw, ok := jsonbBytes(v)
	if !ok {
		return false
	}
	var d struct {
		PolicyPacks []string `json:"policy_packs"`
	}
	if json.Unmarshal(raw, &d) != nil {
		return false
	}
	return slices.Equal(d.PolicyPacks, m.refs)
}

func TestDecideDecidesAnInstalledPackAndNamesItByDigest(t *testing.T) {
	enfSetup(t)
	pack := decidePackUnderTest(t)
	detectors, err := sharedpolicy.CompileInstalledDetectors([]*policypack.Pack{pack})
	if err != nil {
		t.Fatal(err)
	}
	// The shared engine again, with the pack's detectors on its every load; no
	// shipped row is probed, so the only detectors that can fire are the pack's.
	enfInstallDetectorsWithPacks(t, nil, nil, detectors)

	// THE CONTROL: the enforcer enfSetup installed carries no pack, so the same
	// request names none - what the next leg reads is the pack's doing.
	if r := enfDecide(t, enfOrgImplicit, true, DecisionStageLLM, "What is the weather today?"); r.code != http.StatusOK || r.str(t, "verdict") != VerdictAllow {
		t.Fatalf("without a pack: HTTP %d verdict %q. body=%s", r.code, r.str(t, "verdict"), r.raw)
	} else if _, named := r.body["policy_packs"]; named {
		t.Fatalf("without a pack installed the response names one. body=%s", r.raw)
	}

	// A fresh enforcer with the pack installed, as the agent's boot installs it:
	// its activations are built with the pack from the first request.
	enfInstallSeam(t, enfPublishDocument(t, enfSnapshot(t)))
	installed, err := activation.InstallPacks(enfSnapshot(t), []*policypack.Pack{pack})
	if err != nil {
		t.Fatal(err)
	}
	anchoredEnforcerInstance.Load().Packs = installed
	ref := installed[0].Ref()
	blockID := policypack.PolicyID("testpack", "tp_amount")
	stepID := policypack.PolicyID("testpack", "tp_execute")

	t.Run("an allowed request names the pack it was decided under, on the wire and the audit row", func(t *testing.T) {
		mock := withMockUsageDB(t)
		mock.MatchExpectationsInOrder(false)
		mock.ExpectExec("INSERT INTO audit_logs").
			WithArgs(decideAuditInsertArgs(AuditVerdictAllowed, policyPacksMatcher{refs: []string{ref}})...).
			WillReturnResult(sqlmock.NewResult(0, 1))
		r := enfDecide(t, enfOrgImplicit, true, DecisionStageLLM, "What is the weather today?")
		if r.code != http.StatusOK || r.str(t, "verdict") != VerdictAllow {
			t.Fatalf("HTTP %d verdict %q; want 200 allow. body=%s", r.code, r.str(t, "verdict"), r.raw)
		}
		if got := r.strings(t, "policy_packs"); !slices.Equal(got, []string{ref}) {
			t.Fatalf("policy_packs %v; want [%s]", got, ref)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatalf("the audit row does not name the pack: %v", err)
		}
	})

	t.Run("a step-up the pack's detector matches is refused approval_required, naming the plane", func(t *testing.T) {
		r := enfDecide(t, enfOrgImplicit, true, DecisionStageLLM, "please execute the vendor payment today")
		if r.code != http.StatusOK || r.str(t, "verdict") != VerdictDeny {
			t.Fatalf("HTTP %d verdict %q; want 200 deny. body=%s", r.code, r.str(t, "verdict"), r.raw)
		}
		reasons := r.strings(t, "reasons")
		if len(reasons) != 1 || !strings.HasPrefix(reasons[0], "approval_required") || !strings.Contains(reasons[0], "decide") {
			t.Fatalf("reasons %v; want one approval_required naming the decide plane (PRD v11 §1.13)", reasons)
		}
		if !slices.Contains(r.strings(t, "evaluated_policies"), stepID) {
			t.Fatalf("evaluated_policies %v does not name the pack's step-up %s", r.strings(t, "evaluated_policies"), stepID)
		}
	})

	t.Run("a context over the pack's cap is denied by the pack's block, through decide's context lift", func(t *testing.T) {
		r := enfDecideWithContext(t, enfOrgImplicit, DecisionStageLLM, "settle the approved supplier balance", map[string]interface{}{
			"fincrime_transaction": map[string]interface{}{"amount": 48500, "currency": "USD"},
		})
		if r.code != http.StatusOK || r.str(t, "verdict") != VerdictDeny {
			t.Fatalf("HTTP %d verdict %q; want 200 deny. body=%s", r.code, r.str(t, "verdict"), r.raw)
		}
		if policies := r.strings(t, "evaluated_policies"); len(policies) == 0 || policies[0] != blockID {
			t.Fatalf("evaluated_policies %v; the pack's block %s must decide", policies, blockID)
		}
		if got := r.strings(t, "policy_packs"); !slices.Equal(got, []string{ref}) {
			t.Fatalf("policy_packs %v; want [%s]", got, ref)
		}
	})

	t.Run("the same statement with no context is not denied by the block: the lift is what it read", func(t *testing.T) {
		r := enfDecideWithContext(t, enfOrgImplicit, DecisionStageLLM, "settle the approved supplier balance", nil)
		if r.code != http.StatusOK || r.str(t, "verdict") != VerdictAllow {
			t.Fatalf("HTTP %d verdict %q; want 200 allow. body=%s", r.code, r.str(t, "verdict"), r.raw)
		}
	})
}
