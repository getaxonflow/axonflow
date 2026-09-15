// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"context"
	"database/sql/driver"
	"encoding/json"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"

	"axonflow/platform/connectors/base"
	"axonflow/platform/decision/activation"
	"axonflow/platform/decision/policypack"
	sharedpolicy "axonflow/platform/shared/policy"
)

// THE MCP RESPONSE PASS NAMES ITS POLICY PACKS (#4196, PRD v11 §1.9), through
// the real handlers, seam and enforcer: a pack whose control binds on the
// response pass is named by digest on check-output's body, on the query and
// execute success bodies, and on the canonical audit row each writes, exactly
// as /api/v1/decide names it. With no pack installed the field is ABSENT, not
// empty. The pack is synthetic, so this runs on every edition's test build.

// responsePackUnderTest is a pack with one advisory response-phase control, so
// it binds on the MCP response pass and changes no verdict. A pack control binds
// on a scope only where that scope's call sites admit its detector's category
// (activation.InstallPacks), so the category is one the MCP response pass
// admits: RBI's UPI detector, which binds there, is pii-india.
func responsePackUnderTest(t *testing.T) *policypack.Pack {
	t.Helper()
	src := &policypack.Source{
		ID: "resppack", Version: 1,
		Detectors: []policypack.Detector{
			{ID: "rp_note", Name: "Response note", Category: "pii-india", Severity: "low", Phase: "response", Action: "log", Priority: 10, Pattern: `resppack-probe-4196`},
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

// mcpPackWorld is the response pass's world (mrsSetup) with pack installed, as
// the agent's boot installs it; it returns the ref the wire must carry.
func mcpPackWorld(t *testing.T, w *mrsWorld, pack *policypack.Pack) string {
	t.Helper()
	return mcpPackWorldWith(t, w, pack, w.docs)
}

// mcpPackWorldWith is mcpPackWorld with the organization's documents docs.
func mcpPackWorldWith(t *testing.T, w *mrsWorld, pack *policypack.Pack, docs activeDocumentSource) string {
	t.Helper()
	detectors, err := sharedpolicy.CompileInstalledDetectors([]*policypack.Pack{pack})
	if err != nil {
		t.Fatal(err)
	}
	redact, redactProbe, stripped := mrsResponseProbes(t)
	enfInstallDetectorsWithPacks(t, map[string]string{redact: regexp.QuoteMeta(redactProbe), stripped: mrsInjectionProbe}, nil, detectors)
	w.mrsWire(t, docs)
	installed, err := activation.InstallPacks(enfSnapshot(t), []*policypack.Pack{pack})
	if err != nil {
		t.Fatal(err)
	}
	anchoredEnforcerInstance.Load().Packs = installed
	return installed[0].Ref()
}

// expectMCPDetailsRow expects ONE audit_logs INSERT of columns arguments on the
// MCP plane and captures its policy_details (index 13 on every writer).
func expectMCPDetailsRow(t *testing.T, columns int) (read func(t *testing.T) map[string]json.RawMessage) {
	t.Helper()
	mock := withMockUsageDB(t)
	mock.MatchExpectationsInOrder(false)
	var details []byte
	args := make([]driver.Value, columns)
	for i := range args {
		args[i] = sqlmock.AnyArg()
	}
	args[13], args[15] = captureArg{dst: &details}, PlaneMCP
	mock.ExpectExec("INSERT INTO audit_logs").WithArgs(args...).WillReturnResult(sqlmock.NewResult(0, 1))
	return func(t *testing.T) map[string]json.RawMessage {
		t.Helper()
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatalf("no audit row was written on the MCP plane: %v", err)
		}
		out := map[string]json.RawMessage{}
		if err := json.Unmarshal(details, &out); err != nil {
			t.Fatalf("policy_details is not a JSON object: %v (raw=%s)", err, details)
		}
		return out
	}
}

// packsOf reads a JSON object's policy_packs, reporting whether the key is there.
func packsOf(t *testing.T, obj map[string]json.RawMessage) ([]string, bool) {
	t.Helper()
	raw, ok := obj["policy_packs"]
	if !ok {
		return nil, false
	}
	var packs []string
	if err := json.Unmarshal(raw, &packs); err != nil {
		t.Fatalf("policy_packs is not a string list: %s", raw)
	}
	return packs, true
}

func TestTheMCPResponsePassNamesItsPolicyPacks(t *testing.T) {
	w := mrsSetup(t)
	ref := mcpPackWorld(t, w, responsePackUnderTest(t))
	token := mrsToken(t)

	t.Run("check-output: the body and the canonical row name the pack by digest", func(t *testing.T) {
		read := expectMCPDetailsRow(t, decideAuditColumns)
		out := mrsCheckOutput(t, token, mrsBenign)
		if out.code != http.StatusOK || !out.body.Allowed {
			t.Fatalf("check-output: HTTP %d allowed=%v; want 200 allowed. body=%s", out.code, out.body.Allowed, out.raw)
		}
		if !slices.Equal(out.body.PolicyPacks, []string{ref}) {
			t.Fatalf("check-output policy_packs %v; want [%s]. body=%s", out.body.PolicyPacks, ref, out.raw)
		}
		if packs, _ := packsOf(t, read(t)); !slices.Equal(packs, []string{ref}) {
			t.Fatalf("the check-output row's policy_packs %v; want [%s]", packs, ref)
		}
	})

	for _, route := range []struct {
		name      string
		connector *mockConnector
		post      func() (int, map[string]json.RawMessage, string)
	}{
		{"resources/query", &mockConnector{queryResult: &base.QueryResult{Rows: []map[string]interface{}{{"note": "benign"}}, RowCount: 1}}, func() (int, map[string]json.RawMessage, string) {
			rr := mrsPost("/mcp/resources/query", MCPQueryRequest{Connector: "test-db", Statement: "SELECT note FROM orders", UserToken: token}, mcpQueryHandler)
			body := map[string]json.RawMessage{}
			_ = json.Unmarshal(rr.Body.Bytes(), &body)
			return rr.Code, body, rr.Body.String()
		}},
		{"tools/execute", &mockConnector{executeResult: &base.CommandResult{RowsAffected: 1, Message: "benign"}}, func() (int, map[string]json.RawMessage, string) {
			rr := mrsPost("/mcp/tools/execute", MCPExecuteRequest{Connector: "test-db", Action: "UPDATE", Statement: "UPDATE orders SET x=1", UserToken: token}, mcpExecuteHandler)
			body := map[string]json.RawMessage{}
			_ = json.Unmarshal(rr.Body.Bytes(), &body)
			return rr.Code, body, rr.Body.String()
		}},
	} {
		t.Run(route.name+": the success body and the canonical row name the pack by digest", func(t *testing.T) {
			read := expectMCPDetailsRow(t, mcpDecisionAuditColumns)
			registerExecConnector(t, route.connector)
			code, body, raw := route.post()
			if code != http.StatusOK {
				t.Fatalf("%s: HTTP %d; want 200. body=%s", route.name, code, raw)
			}
			if packs, _ := packsOf(t, body); !slices.Equal(packs, []string{ref}) {
				t.Fatalf("%s policy_packs %v; want [%s]. body=%s", route.name, packs, ref, raw)
			}
			if packs, _ := packsOf(t, read(t)); !slices.Equal(packs, []string{ref}) {
				t.Fatalf("the %s row's policy_packs %v; want [%s]", route.name, packs, ref)
			}
		})
	}
}

// THE CONTROL: with no pack installed the response pass names none, and the
// key is ABSENT from the body and the row - not an empty list - so omitempty is
// what a caller relies on.
func TestTheMCPResponsePassOmitsPolicyPacksWhenNoPackBinds(t *testing.T) {
	w := mrsSetup(t)
	w.mrsWire(t, w.docs)
	read := expectMCPDetailsRow(t, decideAuditColumns)
	out := mrsCheckOutput(t, mrsToken(t), mrsBenign)
	if out.code != http.StatusOK || !out.body.Allowed {
		t.Fatalf("check-output: HTTP %d allowed=%v; want 200 allowed. body=%s", out.code, out.body.Allowed, out.raw)
	}
	body := map[string]json.RawMessage{}
	if err := json.Unmarshal([]byte(out.raw), &body); err != nil {
		t.Fatalf("check-output body is not a JSON object: %v", err)
	}
	if _, present := packsOf(t, body); present {
		t.Fatalf("with no pack installed the check-output body carries policy_packs; want the key absent. body=%s", out.raw)
	}
	if _, present := packsOf(t, read(t)); present {
		t.Fatal("with no pack installed the check-output row carries policy_packs; want the key absent")
	}

	// The map-built bodies omit it by stamp()'s own guard, not omitempty: pinned
	// on resources/query, body and row.
	readQuery := expectMCPDetailsRow(t, mcpDecisionAuditColumns)
	registerExecConnector(t, &mockConnector{queryResult: &base.QueryResult{Rows: []map[string]interface{}{{"note": "benign"}}, RowCount: 1}})
	rr := mrsPost("/mcp/resources/query", MCPQueryRequest{Connector: "test-db", Statement: "SELECT note FROM orders", UserToken: mrsToken(t)}, mcpQueryHandler)
	queryBody := map[string]json.RawMessage{}
	if rr.Code != http.StatusOK || json.Unmarshal(rr.Body.Bytes(), &queryBody) != nil {
		t.Fatalf("resources/query: HTTP %d; want 200 with a JSON body. body=%s", rr.Code, rr.Body.String())
	}
	if _, present := packsOf(t, queryBody); present {
		t.Fatalf("with no pack installed the query body carries policy_packs; want the key absent. body=%s", rr.Body.String())
	}
	if _, present := packsOf(t, readQuery(t)); present {
		t.Fatal("with no pack installed the query row carries policy_packs; want the key absent")
	}
}

// A REFUSED check-output names the packs too, on the blocked body and its row:
// the refund document's ceiling cannot be evaluated on this pass (#4227), so
// the response is refused unknown_constraint under a bundle the pack composed
// into.
func TestABlockedMCPResponseNamesItsPolicyPacks(t *testing.T) {
	w := mrsSetup(t)
	ref := mcpPackWorldWith(t, w, responsePackUnderTest(t), enfPublishRefundDocument(t))
	read := expectMCPDetailsRow(t, decideAuditColumns)
	out := mrsCheckOutput(t, mrsToken(t), mrsBenign)
	if out.code != http.StatusForbidden || out.body.Allowed {
		t.Fatalf("check-output: HTTP %d allowed=%v; want the 403 refusal. body=%s", out.code, out.body.Allowed, out.raw)
	}
	if !slices.Equal(out.body.PolicyPacks, []string{ref}) {
		t.Fatalf("the blocked check-output policy_packs %v; want [%s]. body=%s", out.body.PolicyPacks, ref, out.raw)
	}
	if packs, _ := packsOf(t, read(t)); !slices.Equal(packs, []string{ref}) {
		t.Fatalf("the blocked check-output row's policy_packs %v; want [%s]", packs, ref)
	}
}

// THE REFUSAL PATH NAMES THE PACKS TOO. A subject the identity plane refuses -
// a user token that did not verify - withholds the response under the bundle
// the activation decided with, and the pass records that activation's packs as
// it records its bundle. The route's own authentication answers such a token
// 401 before the pass runs, so the pass is driven directly, with the refused
// subject on its seam.
func TestAnMCPResponseRefusalOfTheSubjectNamesItsPolicyPacks(t *testing.T) {
	w := mrsSetup(t)
	ref := mcpPackWorld(t, w, responsePackUnderTest(t))
	auth := &AuthResult{Kind: AuthKindEnterprise, OrgID: w.org, TenantID: "route-tenant", ClientID: "route-client"}
	ctx := withMCPResponseSeam(context.Background(), "route-request", requestSubject(w.org, auth, nil, userUnverified), pepHandshakeResolution{})
	out := evaluateOutputPolicies(ctx, "t1", w.org, "u1", "postgres", "", nil, mrsBenign, nil, 0, false, false)
	if out.StaticResult == nil || !out.StaticResult.Blocked {
		t.Fatalf("a refused subject's response was not withheld: %+v", out.StaticResult)
	}
	if reason := out.StaticResult.BlockReason; strings.HasPrefix(reason, "response withheld:") {
		t.Fatalf("block_reason %q is an unavailable withhold; want the identity plane's refusal, so the refusal branch ran", reason)
	}
	if got := mcpResponseSeamFrom(ctx).packsRecorded(); !slices.Equal(got, []string{ref}) {
		t.Fatalf("the refused response's seam recorded packs %v; want [%s]", got, ref)
	}
}
