// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"database/sql/driver"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"

	"axonflow/platform/connectors/base"
	"axonflow/platform/decision/activation"
	"axonflow/platform/decision/authoringcatalog"
	"axonflow/platform/decision/contract"
	sharedpolicy "axonflow/platform/shared/policy"
)

// EVERY TYPED DECISION NAMES WHAT DECIDED IT (PRD v11 §1.14, #4127), through the
// real handlers, seam and enforcer. Each assertion reads what a caller or an
// auditor reads - the encoded body and the audit row - never the producing
// functions.

// identityRow is what an audit row's policy_details says about the policies it
// names.
type identityRow struct {
	PolicyIDs       []string          `json:"policy_ids"`
	PolicyNames     []string          `json:"policy_names"`
	PolicySources   map[string]string `json:"policy_sources"`
	PolicyVersions  map[string]int    `json:"policy_versions"`
	DocumentVersion int               `json:"document_version"`
	ActionName      string            `json:"action_name"`
}

// The audit_logs INSERT arity of each writer a typed decision's row goes
// through: recordDecideDecision's (decide, the gateway pre-check, MCP
// check-output and check-input's allow), writeMCPDecisionAudit's (the MCP
// connector routes) and
// writeExplainableAuditLog's (the MCP request pass's check-input and
// check_policy refusals). All three put policy_details at index 13 and plane
// at 15.
const (
	decideAuditColumns         = 21
	mcpDecisionAuditColumns    = 20
	mcpExplainableAuditColumns = 19
)

// expectIdentityRow expects ONE audit_logs INSERT of columns arguments on plane
// and captures its policy_details; read returns what it said.
func expectIdentityRow(t *testing.T, plane string, columns int) (read func(t *testing.T) identityRow) {
	t.Helper()
	mock := withMockUsageDB(t)
	mock.MatchExpectationsInOrder(false)
	var details []byte
	args := make([]driver.Value, columns)
	for i := range args {
		args[i] = sqlmock.AnyArg()
	}
	args[13], args[15] = captureArg{dst: &details}, plane
	mock.ExpectExec("INSERT INTO audit_logs").WithArgs(args...).WillReturnResult(sqlmock.NewResult(0, 1))
	return func(t *testing.T) identityRow {
		t.Helper()
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatalf("no audit row was written on %s: %v", plane, err)
		}
		var row identityRow
		if err := json.Unmarshal(details, &row); err != nil {
			t.Fatalf("policy_details is not what an identity reader decodes: %v (raw=%s)", err, details)
		}
		return row
	}
}

// wireIdentities is the body's policy_identities.
func (r enfResponse) wireIdentities(t *testing.T) []PolicyIdentity {
	t.Helper()
	var out []PolicyIdentity
	if raw, ok := r.body["policy_identities"]; ok {
		if err := json.Unmarshal(raw, &out); err != nil {
			t.Fatalf("policy_identities does not decode: %v. body=%s", err, r.raw)
		}
	}
	return out
}

// wireDocumentVersion is the body's document_version, zero when omitted.
func (r enfResponse) wireDocumentVersion(t *testing.T) int {
	t.Helper()
	var v int
	if raw, ok := r.body["document_version"]; ok {
		if err := json.Unmarshal(raw, &v); err != nil {
			t.Fatalf("document_version does not decode: %v. body=%s", err, r.raw)
		}
	}
	return v
}

// actionLabel is the deployment vocabulary's display name for a registered
// action, failing the test when it carries none.
func actionLabel(t *testing.T, local string) string {
	t.Helper()
	label := enfSnapshot(t).Catalog.ActionLabels["Action::"+local].DisplayName
	if label == "" {
		t.Fatalf("the deployment vocabulary labels no %s, so an action_name assertion would be vacuous", local)
	}
	return label
}

func TestADecideDecisionNamesEveryPolicyItMatched(t *testing.T) {
	constraintPolicy := enfSetup(t)
	const aliceTool = "ceiling.no_tool_for_alice"

	t.Run("the organization's own constraint: named, the organization's, at its document's version", func(t *testing.T) {
		read := expectIdentityRow(t, PlaneDecision, decideAuditColumns)
		r := enfDecide(t, enfOrgPublished, true, DecisionStageTool, "list the open tickets")
		if r.code != http.StatusOK || r.str(t, "verdict") != VerdictDeny {
			t.Fatalf("HTTP %d verdict %q; want 200 deny. body=%s", r.code, r.str(t, "verdict"), r.raw)
		}
		evaluated, identities := r.strings(t, "evaluated_policies"), r.wireIdentities(t)
		want := PolicyIdentity{ID: aliceTool, Name: enfConstraintName(aliceTool), Source: "organization", Version: 1}
		if len(identities) != len(evaluated) || len(identities) == 0 || identities[0] != want {
			t.Fatalf("policy_identities %+v beside evaluated_policies %v; want one per entry, the first %+v", identities, evaluated, want)
		}
		for i, p := range identities {
			if p.ID != evaluated[i] {
				t.Fatalf("policy_identities[%d] names %s, evaluated_policies[%d] is %s; they must agree entry for entry", i, p.ID, i, evaluated[i])
			}
		}
		if got := r.wireDocumentVersion(t); got != 1 {
			t.Fatalf("document_version %d; want the published document's 1", got)
		}

		row := read(t)
		if !slices.Contains(row.PolicyNames, want.Name) || slices.Contains(row.PolicyNames, aliceTool) {
			t.Errorf("row policy_names %v; want the constraint's name %q and never its id", row.PolicyNames, want.Name)
		}
		if row.PolicySources[aliceTool] != "organization" || row.PolicyVersions[aliceTool] != 1 {
			t.Errorf("row source %q version %d for %s; want organization at 1", row.PolicySources[aliceTool], row.PolicyVersions[aliceTool], aliceTool)
		}
		if row.DocumentVersion != 1 || row.ActionName != actionLabel(t, authoringcatalog.ActionToolCall) {
			t.Errorf("row document_version %d action_name %q; want 1 and the tool.call label", row.DocumentVersion, row.ActionName)
		}
	})

	t.Run("a shipped control: named by the corpus, shipped, and versioned by nothing but the bundle", func(t *testing.T) {
		var name string
		for _, c := range enfScopeControls(t, decideSeamScope) {
			if c.policy.ID == constraintPolicy {
				name = c.policy.Name
			}
		}
		if name == "" {
			t.Fatalf("the decide restriction names no %s; the arm would be vacuous", constraintPolicy)
		}
		read := expectIdentityRow(t, PlaneDecision, decideAuditColumns)
		r := enfDecide(t, enfOrgPublished, true, DecisionStageLLM, "please run "+enfConstraintProbe+" now")
		identities := r.wireIdentities(t)
		if want := (PolicyIdentity{ID: constraintPolicy, Name: name, Source: "shipped"}); len(identities) == 0 || identities[0] != want {
			t.Fatalf("policy_identities %+v; want the first %+v. body=%s", identities, want, r.raw)
		}
		row := read(t)
		if _, versioned := row.PolicyVersions[constraintPolicy]; versioned || row.PolicySources[constraintPolicy] != "shipped" {
			t.Errorf("row version map %v source %q for %s; want shipped and no version", row.PolicyVersions, row.PolicySources[constraintPolicy], constraintPolicy)
		}
		if !slices.Contains(row.PolicyNames, name) {
			t.Errorf("row policy_names %v; want the corpus name %q", row.PolicyNames, name)
		}
	})

	t.Run("the implicit baseline: nothing is the organization's, and no document version", func(t *testing.T) {
		read := expectIdentityRow(t, PlaneDecision, decideAuditColumns)
		r := enfDecide(t, enfOrgImplicit, true, DecisionStageTool, "list the open tickets")
		if r.code != http.StatusOK || r.str(t, "verdict") != VerdictAllow {
			t.Fatalf("HTTP %d verdict %q; want 200 allow. body=%s", r.code, r.str(t, "verdict"), r.raw)
		}
		identities := r.wireIdentities(t)
		if len(identities) == 0 {
			t.Fatalf("an allow the baseline pack's permission matched names no policy. body=%s", r.raw)
		}
		for _, p := range identities {
			if p.Source != "shipped" || p.Version != 0 {
				t.Errorf("%+v under the implicit baseline; want shipped with no version", p)
			}
		}
		if _, has := r.body["document_version"]; has {
			t.Errorf("the implicit baseline carries a document_version. body=%s", r.raw)
		}
		if row := read(t); row.DocumentVersion != 0 || len(row.PolicyVersions) != 0 {
			t.Errorf("row document_version %d versions %v; want neither under the implicit baseline", row.DocumentVersion, row.PolicyVersions)
		}
	})
}

// The gateway's row names the anchored decision's policies by the anchored
// engine's names. The names its shared-engine evaluation threads map that
// engine's ids, and captioned nothing the anchored decision recorded.
func TestAGatewayPreCheckRowNamesTheAnchoredDecisionsPolicies(t *testing.T) {
	enfSetup(t)
	const blockBob = "ceiling.block_bob"
	read := expectIdentityRow(t, PlaneGateway, decideAuditColumns)
	r := enfPreCheck(t, enfOrgPublished, enfMintUserToken(t, enfOrgPublished, enfBob), "What is the weather today?")
	if r.code != http.StatusOK || r.approved(t) {
		t.Fatalf("HTTP %d approved=%v; bob's constraint must refuse the pre-check. body=%s", r.code, r.approved(t), r.raw)
	}
	row := read(t)
	if !slices.Contains(row.PolicyNames, enfConstraintName(blockBob)) || row.PolicySources[blockBob] != "organization" || row.PolicyVersions[blockBob] != 1 {
		t.Errorf("row names %v source %q version %d for %s; want its name, the organization's, at 1", row.PolicyNames, row.PolicySources[blockBob], row.PolicyVersions[blockBob], blockBob)
	}
	if row.DocumentVersion != 1 || row.ActionName != actionLabel(t, authoringcatalog.ActionLLMCompletion) {
		t.Errorf("row document_version %d action_name %q; want 1 and the llm.completion label", row.DocumentVersion, row.ActionName)
	}
}

// /api/request's row names the anchored decision's policies the same way, and
// since #4253 the anchored engine authors every verdict there.
func TestAProxyRequestRowNamesTheAnchoredDecisionsPolicies(t *testing.T) {
	enfProxySetup(t)
	const blockBob = "ceiling.block_bob"
	read := expectIdentityRow(t, PlaneAgent, decideAuditColumns)
	r := enfProxy(t, enfOrgPublished, enfMintUserToken(t, enfOrgPublished, enfBob), "SELECT id FROM products")
	if r.code != http.StatusForbidden || !r.blocked(t) {
		t.Fatalf("HTTP %d blocked=%v; bob's constraint must refuse the request. body=%s", r.code, r.blocked(t), r.raw)
	}
	row := read(t)
	if !slices.Contains(row.PolicyNames, enfConstraintName(blockBob)) || row.PolicySources[blockBob] != "organization" || row.PolicyVersions[blockBob] != 1 {
		t.Errorf("row names %v source %q version %d for %s; want its name, the organization's, at 1", row.PolicyNames, row.PolicySources[blockBob], row.PolicyVersions[blockBob], blockBob)
	}
	if row.DocumentVersion != 1 || row.ActionName != actionLabel(t, authoringcatalog.ActionLLMCompletion) {
		t.Errorf("row document_version %d action_name %q; want 1 and the llm.completion label", row.DocumentVersion, row.ActionName)
	}
}

// The OpenAI-compatible route's refusal row names the anchored decision's
// policies too. Its principal is the client credential, which no fixture
// constraint names, so the refusal comes from a shipped control its own scope
// keeps: named by the corpus, shipped, and versioned by nothing but the bundle.
// The caller is the proxy fixture's licensed client, which the middleware
// authenticates on every build.
func TestAnOpenAICompatibleRefusalRowNamesTheAnchoredDecisionsPolicies(t *testing.T) {
	enfProxySetup(t)
	clientID := enfProxyClientFor(enfOrgPublished)
	credential := "Basic " + base64.StdEncoding.EncodeToString([]byte(clientID+":"+knownClients[clientID].LicenseKey))
	var rowID, control, name string
	for _, c := range enfScopeControls(t, openaiCompatibleSeamScope) {
		if c.policy.Authority == contract.AuthorityConstraint && c.row.Tier == "system" && c.row.Enabled &&
			sharedpolicy.ValidatorFor(c.row.PolicyID, sharedpolicy.PolicyCategory(c.row.Category)) == nil {
			rowID, control, name = c.row.PolicyID, c.policy.ID, c.policy.Name
			break
		}
	}
	if control == "" || name == "" {
		t.Fatalf("the openai_compatible restriction keeps no named constraint reading a validator-free system detector (%q)", control)
	}
	enfInstallDetectors(t, map[string]string{rowID: enfConstraintProbe}, nil)
	read := expectIdentityRow(t, PlaneOpenAICompat, decideAuditColumns)
	rr := openaiCompatForTest(t, makeChatBody("gpt-4o", simpleMessages("please run "+enfConstraintProbe+" now"), nil),
		map[string]string{"X-Provider-Key": "test-provider-key", "Authorization": credential})
	if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "policy_denied") {
		t.Fatalf("HTTP %d; the shipped control %s must refuse the request policy_denied. body=%s", rr.Code, control, rr.Body.String())
	}
	row := read(t)
	if _, versioned := row.PolicyVersions[control]; versioned || row.PolicySources[control] != "shipped" || !slices.Contains(row.PolicyNames, name) {
		t.Errorf("row names %v source %q versions %v for %s; want its corpus name %q, shipped, and no version", row.PolicyNames, row.PolicySources[control], row.PolicyVersions, control, name)
	}
	if row.DocumentVersion != 1 || row.ActionName != actionLabel(t, authoringcatalog.ActionLLMCompletion) {
		t.Errorf("row document_version %d action_name %q; want the active document's 1 and the llm.completion label", row.DocumentVersion, row.ActionName)
	}
}

// THE RESPONSE PASS NEVER PRESENTS AN IDENTIFIER AS A NAME. A refused response
// recorded its blocking constraint's id as that constraint's display name
// (blockedResponse), and on check-output's row no name at all: exactly what
// #3347's audit view must never show, and never hide. check-output is the one
// MCP route a subject constraint still reaches on this pass; on a connector
// route the request pass refuses it first, so the connector routes' response
// pass is driven by TestAConnectorRouteResponseRefusalNeverNamesItsPolicyByItsID.
func TestAnMCPResponseRefusalNamesItsConstraintAndNeverByItsID(t *testing.T) {
	const aliceTool = "ceiling.no_tool_for_alice"
	w := mrsSetup(t)
	w.mrsWire(t, enfPublishConstraints(t, enfSnapshot(t), enfConstraint{aliceTool, enfUser, []string{authoringcatalog.ActionToolCall}}))
	read := expectIdentityRow(t, PlaneMCP, decideAuditColumns)
	if code := mrsCheckOutput(t, mrsToken(t), mrsBenign).code; code != http.StatusForbidden {
		t.Fatalf("check-output: HTTP %d; the constraint must refuse the response", code)
	}
	row := read(t)
	if slices.Contains(row.PolicyNames, aliceTool) || !slices.Contains(row.PolicyNames, enfConstraintName(aliceTool)) {
		t.Errorf("row policy_names %v; want the constraint's name %q, and never its id", row.PolicyNames, enfConstraintName(aliceTool))
	}
	if row.PolicySources[aliceTool] != "organization" || row.PolicyVersions[aliceTool] != 1 || row.DocumentVersion != 1 {
		t.Errorf("row source %q version %d document_version %d; want the organization's, at 1, under document 1", row.PolicySources[aliceTool], row.PolicyVersions[aliceTool], row.DocumentVersion)
	}
	if row.ActionName != actionLabel(t, authoringcatalog.ActionToolCall) {
		t.Errorf("row action_name %q; want the tool.call label", row.ActionName)
	}
}

// A CONNECTOR ROUTE'S RESPONSE-PASS REFUSAL NEVER PRESENTS AN IDENTIFIER AS A
// NAME either. A subject constraint cannot reach this pass on a connector
// route - the request pass refuses it first, and
// TestAnMCPRequestPassRowNamesWhatDecidedIt proves that refusal's row - so a
// response-only trigger drives it: the PII probe in the connector's result
// under the organization's recorded pii=block, which the organization root's
// replacement of the shipped control refuses, named by the shipped control's
// own name (#4211). Each leg first proves the RESPONSE pass refused ("Response
// blocked: "; the request pass answers "Request blocked: "), so a leg the
// request pass comes to decide fails here rather than passing on the other
// pass's verdict.
func TestAConnectorRouteResponseRefusalNeverNamesItsPolicyByItsID(t *testing.T) {
	w := mrsSetup(t)
	shippedNames := map[string]string{}
	for _, c := range enfScopeControls(t, mcpResponseSeamScope) {
		shippedNames[c.policy.ID] = c.policy.Name
	}
	reader := &fakeOverrideReader{data: map[string]map[string]DetectionAction{}}
	installTestOverrideCache(t, reader, time.Minute)
	w.mrsWire(t, w.docs)
	reader.mu.Lock()
	reader.data[w.org] = map[string]DetectionAction{DetectionCategoryPII: DetectionActionBlock}
	reader.mu.Unlock()
	InvalidateOrgDetectionOverrides(w.org)
	token, pii := mrsToken(t), mrsRedactContent(w.redactProbe)
	for _, route := range []struct {
		name      string
		connector *mockConnector
		post      func() *httptest.ResponseRecorder
	}{
		{"resources/query", &mockConnector{queryResult: &base.QueryResult{Rows: []map[string]interface{}{{"note": pii}}, RowCount: 1}}, func() *httptest.ResponseRecorder {
			return mrsPost("/mcp/resources/query", MCPQueryRequest{Connector: "test-db", Statement: "SELECT note FROM orders", UserToken: token}, mcpQueryHandler)
		}},
		{"tools/execute", &mockConnector{executeResult: &base.CommandResult{RowsAffected: 1, Message: pii}}, func() *httptest.ResponseRecorder {
			return mrsPost("/mcp/tools/execute", MCPExecuteRequest{Connector: "test-db", Action: "UPDATE", Statement: "UPDATE orders SET x=1", UserToken: token}, mcpExecuteHandler)
		}},
	} {
		t.Run(route.name, func(t *testing.T) {
			read := expectIdentityRow(t, PlaneMCP, mcpDecisionAuditColumns)
			registerExecConnector(t, route.connector)
			rr := route.post()
			if message, _ := mrqRefusal(t, rr)["error"].(string); rr.Code != http.StatusForbidden || !strings.HasPrefix(message, "Response blocked: ") {
				t.Fatalf("HTTP %d error %q; want the RESPONSE pass's 403. body=%s", rr.Code, message, rr.Body.String())
			}
			row := read(t)
			if len(row.PolicyIDs) == 0 {
				t.Fatal("the refusal's row names no policy")
			}
			replaced := 0
			for _, id := range row.PolicyIDs {
				if slices.Contains(row.PolicyNames, id) {
					t.Errorf("row policy_names %v presents the id %q as a name", row.PolicyNames, id)
				}
				if row.PolicySources[id] != "shipped" {
					t.Errorf("row source %q for %s; an override's replacement of a shipped control is shipped", row.PolicySources[id], id)
				}
				if shipped, ok := strings.CutPrefix(id, activation.OverridePolicyIDPrefix); ok {
					replaced++
					if name := shippedNames[shipped]; name == "" || !slices.Contains(row.PolicyNames, name) {
						t.Errorf("row policy_names %v; want the name of the shipped control %s the override replaced, %q", row.PolicyNames, shipped, name)
					}
				}
			}
			if replaced == 0 {
				t.Errorf("row policy_ids %v carry no override replacement; the recorded pii=block did not decide this refusal", row.PolicyIDs)
			}
			if row.DocumentVersion != 1 || row.ActionName != actionLabel(t, authoringcatalog.ActionToolCall) {
				t.Errorf("row document_version %d action_name %q; want 1 and the tool.call label", row.DocumentVersion, row.ActionName)
			}
		})
	}
}

// THE MCP REQUEST PASS NAMES WHAT DECIDED IT. Since W3-H's cutover it is a
// typed decision, so its rows carry what every other typed decision's do: each
// refusal - check-input's, check_policy's and a connector route's - names the
// organization's constraint by its name, whose it is and the version it was
// published at, beside the document's version and the action's name; an allow
// names the document and the action; under the implicit baseline there is no
// document version. The seam records them from the one enforcement that
// decided (recordRequestPass), and mergeEnforcementPosture stamps every writer
// the pass reaches.
func TestAnMCPRequestPassRowNamesWhatDecidedIt(t *testing.T) {
	const bobTool = "ceiling.block_bob" // the constraint mrsSetup's document publishes
	toolCall := actionLabel(t, authoringcatalog.ActionToolCall)
	w := mrsSetup(t)
	w.mrsWire(t, w.docs)
	bobToken := mrsTokenFor(t, enfBob)
	for _, route := range []struct {
		name    string
		columns int
		refused func(t *testing.T) bool
	}{
		{"check-input, through writeExplainableAuditLog", mcpExplainableAuditColumns, func(t *testing.T) bool {
			code, _, _ := mrqCheckInput(t, bobToken, mrsBenign, "")
			return code == http.StatusForbidden
		}},
		{"check_policy, through writeExplainableAuditLog", mcpExplainableAuditColumns, func(t *testing.T) bool {
			got, err := mrqCheckPolicy(t, w.org, mrqSession(t, w.org, enfBob), mrsBenign)
			return err == nil && got["allowed"] == false
		}},
		{"a connector route's refusal, through writeMCPDecisionAudit", mcpDecisionAuditColumns, func(t *testing.T) bool {
			registerExecConnector(t, &mockConnector{queryResult: &base.QueryResult{Rows: []map[string]interface{}{{"note": "unreached"}}, RowCount: 1}})
			return mrsPost("/mcp/resources/query", MCPQueryRequest{Connector: "test-db", Statement: "SELECT note FROM orders", UserToken: bobToken}, mcpQueryHandler).Code == http.StatusForbidden
		}},
	} {
		t.Run(route.name, func(t *testing.T) {
			read := expectIdentityRow(t, PlaneMCP, route.columns)
			if !route.refused(t) {
				t.Fatal("the document's constraint must refuse bob's request")
			}
			row := read(t)
			if slices.Contains(row.PolicyNames, bobTool) || !slices.Contains(row.PolicyNames, enfConstraintName(bobTool)) {
				t.Errorf("row policy_names %v; want the constraint's name %q, and never its id", row.PolicyNames, enfConstraintName(bobTool))
			}
			if row.PolicySources[bobTool] != "organization" || row.PolicyVersions[bobTool] != 1 || row.DocumentVersion != 1 {
				t.Errorf("row source %q version %d document_version %d; want the organization's, at 1, under document 1", row.PolicySources[bobTool], row.PolicyVersions[bobTool], row.DocumentVersion)
			}
			if row.ActionName != toolCall {
				t.Errorf("row action_name %q; want %q", row.ActionName, toolCall)
			}
		})
	}

	t.Run("an allow names the document and the action", func(t *testing.T) {
		read := expectIdentityRow(t, PlaneMCP, decideAuditColumns)
		if code, raw, _ := mrqCheckInput(t, mrsToken(t), mrsBenign, ""); code != http.StatusOK {
			t.Fatalf("alice: HTTP %d; want 200. body=%s", code, raw)
		}
		if row := read(t); row.DocumentVersion != 1 || row.ActionName != toolCall {
			t.Errorf("row document_version %d action_name %q; want 1 and %q", row.DocumentVersion, row.ActionName, toolCall)
		}
	})

	t.Run("under the implicit baseline an allow carries no document version", func(t *testing.T) {
		w.mrsWire(t, mrsDocuments{enfDocuments: w.docs, none: true})
		read := expectIdentityRow(t, PlaneMCP, decideAuditColumns)
		if code, raw, _ := mrqCheckInput(t, bobToken, mrsBenign, ""); code != http.StatusOK {
			t.Fatalf("bob, with nothing published: HTTP %d; want 200. body=%s", code, raw)
		}
		if row := read(t); row.DocumentVersion != 0 || len(row.PolicyVersions) != 0 || row.ActionName != toolCall {
			t.Errorf("row document_version %d versions %v action_name %q; want neither, and %q", row.DocumentVersion, row.PolicyVersions, row.ActionName, toolCall)
		}
	})
}

func TestStampAnchoredIdentityWritesOnlyForTheRowsOwnIDsAndLetsTheRowWin(t *testing.T) {
	identities := []PolicyIdentity{
		{ID: "ceiling.own", Name: "Own", Source: "organization", Version: 3},
		{ID: "corpus:shipped", Name: "Shipped", Source: "shipped"},
		{ID: "pack:ctl", Source: "pack", Version: 2},
		{ID: "indonesia_pii_protection"},
		{ID: "ceiling.not_on_the_row", Source: "organization", Version: 3},
	}
	details := map[string]interface{}{
		"policy_ids":      []string{"ceiling.own", "corpus:shipped", "pack:ctl", "indonesia_pii_protection"},
		"policy_versions": map[string]interface{}{"pack:ctl": "model-7"},
	}
	stampAnchoredIdentity(details, identities, 3, "Call a tool")

	wantSources := map[string]string{"ceiling.own": "organization", "corpus:shipped": "shipped", "pack:ctl": "pack"}
	if got := details["policy_sources"]; !reflect.DeepEqual(got, wantSources) {
		t.Errorf("policy_sources %v; want %v: an id not on the row, and one no engine activated, name no source", got, wantSources)
	}
	wantVersions := map[string]interface{}{"ceiling.own": 3, "pack:ctl": "model-7"}
	if got := details["policy_versions"]; !reflect.DeepEqual(got, wantVersions) {
		t.Errorf("policy_versions %v; want %v: a shipped control unversioned, and the row's own entry kept", got, wantVersions)
	}
	if details["document_version"] != 3 || details["action_name"] != "Call a tool" {
		t.Errorf("document_version %v action_name %v; want 3 and the action's name", details["document_version"], details["action_name"])
	}

	set := map[string]interface{}{"policy_ids": []string{"ceiling.own"}, "document_version": 9, "action_name": "kept"}
	stampAnchoredIdentity(set, identities, 3, "Call a tool")
	if set["document_version"] != 9 || set["action_name"] != "kept" {
		t.Errorf("document_version %v action_name %v; an entry the writer set wins", set["document_version"], set["action_name"])
	}

	bare := map[string]interface{}{"policy_ids": []string{"x"}}
	stampAnchoredIdentity(bare, nil, 0, "")
	for _, key := range []string{"policy_sources", "policy_versions", "document_version", "action_name"} {
		if _, has := bare[key]; has {
			t.Errorf("a row with nothing anchored to name gained %s", key)
		}
	}
}

func TestAlignPolicyIdentitiesFollowsTheResponsesOwnOrder(t *testing.T) {
	identities := []PolicyIdentity{{ID: "a", Name: "A", Source: "organization", Version: 1}, {ID: "b", Source: "shipped"}}
	// The blocking policy hoisted to the front, one the seam never named - a
	// checksum validator's - prepended by hoistBlockingPolicy.
	got := alignPolicyIdentities([]string{"indonesia_pii_protection", "b", "a"}, identities)
	want := []PolicyIdentity{{ID: "indonesia_pii_protection"}, identities[1], identities[0]}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("aligned %+v; want %+v", got, want)
	}
	if got := alignPolicyIdentities(nil, identities); got != nil {
		t.Errorf("aligned %+v for no evaluated policy; want nothing, so the body omits the member", got)
	}
}

func TestCarryAnchoredIdentityReplacesTheSharedEnginesNames(t *testing.T) {
	audit := decisionAuditInput{policyNames: map[string]string{"sys_legacy_row": "A legacy row's name"}}
	audit.carryAnchoredIdentity(requestPassEnforcement{
		policyIdentities: []PolicyIdentity{{ID: "ceiling.own", Name: "Own", Source: "organization", Version: 2}, {ID: "corpus:unnamed", Source: "shipped"}},
		documentVersion:  2, actionName: "Call a tool",
	})
	if want := map[string]string{"ceiling.own": "Own"}; !reflect.DeepEqual(audit.policyNames, want) {
		t.Errorf("policyNames %v; want %v: the shared engine's names dropped, and none minted for an unnamed policy", audit.policyNames, want)
	}
	if audit.documentVersion != 2 || audit.actionName != "Call a tool" || len(audit.policyIdentities) != 2 {
		t.Errorf("carried %+v; want the enforcement's identities, document version and action name", audit)
	}
	audit.carryAnchoredIdentity(requestPassEnforcement{})
	if audit.policyNames != nil || audit.policyIdentities != nil || audit.documentVersion != 0 || audit.actionName != "" {
		t.Errorf("after an enforcement that named nothing: %+v; want every anchored field cleared", audit)
	}
}
