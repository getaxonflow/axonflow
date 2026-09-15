// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"context"
	"database/sql/driver"
	"encoding/base64"
	"net/http"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/lib/pq"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"axonflow/platform/connectors/base"
	"axonflow/platform/decision/activation"
	"axonflow/platform/decision/authoring"
	"axonflow/platform/decision/authoringcatalog"
	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/legacycompile"
	"axonflow/platform/decision/pdp"
	sharedpolicy "axonflow/platform/shared/policy"
)

// AN UNKNOWN_CONSTRAINT DENY NAMES THE CONSTRAINT AND THE ATTRIBUTE (#4227, PRD
// v11 §1.14): on an indeterminate deny, the constraints that could not be
// evaluated are the policies that decided it, binding first. Each plane is
// asserted where the seam's output lands - the encoded body, the audit row, the
// MCP query audit - never on the producing functions alone.

// enfRefundTool is the action the platform's publish fixture governs.
const enfRefundTool = "Action::" + authoringcatalog.ActionToolCall

// enfPublishRefundDocument publishes the platform's own publish fixture - the
// document communityDocument builds in
// platform/orchestrator/typed_authoring_route_test.go, of which sdk-python's
// tests/fixtures/typed_policy_publish_body.json is the byte-identical copy - on
// this world's principal: grant.refund permits and ceiling.refund constrains
// tool.call, both reading args.request_type, which the document declares
// required. The Decision API supplies no args.request_type, so ceiling.refund
// cannot be evaluated (required_attribute_absent): what W3-O found on Community
// once the SDK example activated this document.
func enfPublishRefundDocument(t *testing.T) *enfDocuments {
	t.Helper()
	principal := enfMintedPrincipal(enfUser)
	toolCall := []contract.ID{contract.MustParseID(contract.KindAction, enfRefundTool)}
	now := time.Now().UTC()
	doc := pdp.Document{
		Root: pdp.RootOrganization, Version: 1,
		Attributes: []pdp.AttributeSchema{
			{Path: pdp.PrincipalIDPath, Type: pdp.TypeString},
			{Path: pdp.ActionIDPath, Type: pdp.TypeString},
			{Path: pdp.ActionTagsPath, Type: pdp.TypeArray},
			{Path: "args.request_type", Type: pdp.TypeString},
		},
		Policies: []pdp.Policy{
			{
				ID: "grant.refund", Authority: contract.AuthorityPermission, Root: pdp.RootOrganization,
				Scope:   pdp.Scope{Principals: []contract.ID{contract.MustParseID(contract.KindPrincipal, principal)}},
				Actions: pdp.ActionSelector{Actions: toolCall},
				Where:   pdp.Compare("args.request_type", pdp.OpEq, "refund"),
			},
			{
				ID: "ceiling.refund", Authority: contract.AuthorityConstraint, Root: pdp.RootOrganization,
				Scope:   pdp.Scope{Organization: true},
				Actions: pdp.ActionSelector{Actions: toolCall},
				Where:   pdp.Compare("args.request_type", pdp.OpEq, "wire_transfer"),
			},
		},
	}
	return enfPublishPolicyDocument(t, enfSnapshot(t), doc, []authoring.Fixture{{
		Name: "a refund under the ceiling",
		Attributes: contract.AttributeSet{
			pdp.PrincipalIDPath: contract.Known(principal, contract.ProvAuthentication, 1, now),
			pdp.ActionIDPath:    contract.Known(enfRefundTool, contract.ProvPlatform, 1, now),
			pdp.ActionTagsPath:  contract.Known([]any{"stage:" + authzenActionStage[authoringcatalog.ActionToolCall]}, contract.ProvPlatform, 1, now),
			"args.request_type": contract.Known("refund", contract.ProvCaller, 1, now),
		},
		Expect: map[string]pdp.Verdict{"grant.refund": pdp.VerdictMatch, "ceiling.refund": pdp.VerdictNoMatch},
	}})
}

func TestAnUnknownConstraintDenyNamesTheConstraintAndTheAttribute(t *testing.T) {
	enfSetup(t)
	enfInstallSeam(t, enfPublishRefundDocument(t))
	read := expectIdentityRow(t, PlaneDecision, decideAuditColumns)
	r := enfDecide(t, enfOrgPublished, true, DecisionStageTool, "list the open tickets")
	if r.code != http.StatusOK || r.str(t, "verdict") != VerdictDeny {
		t.Fatalf("HTTP %d verdict %q; want 200 deny. body=%s", r.code, r.str(t, "verdict"), r.raw)
	}
	want := []string{
		string(contract.ReasonUnknownConstraint),
		"ceiling.refund (organization, document version 1) could not be evaluated: no value was supplied for args.request_type, which the document requires",
	}
	if reasons := r.strings(t, "reasons"); !reflect.DeepEqual(reasons, want) {
		t.Fatalf("reasons %q; want %q. body=%s", reasons, want, r.raw)
	}
	if evaluated := r.strings(t, "evaluated_policies"); len(evaluated) == 0 || evaluated[0] != "ceiling.refund" {
		t.Fatalf("evaluated_policies %v; want ceiling.refund first, the constraint that decided", evaluated)
	}
	if ids := r.wireIdentities(t); len(ids) == 0 || ids[0] != (PolicyIdentity{ID: "ceiling.refund", Source: "organization", Version: 1}) {
		t.Fatalf("policy_identities %+v; want ceiling.refund first, the organization's, at 1", ids)
	}
	row := read(t)
	if len(row.PolicyIDs) == 0 || row.PolicyIDs[0] != "ceiling.refund" || row.PolicySources["ceiling.refund"] != "organization" ||
		row.PolicyVersions["ceiling.refund"] != 1 || row.DocumentVersion != 1 {
		t.Errorf("row ids %v sources %v versions %v document_version %d; want ceiling.refund first, the organization's, at 1, under document 1",
			row.PolicyIDs, row.PolicySources, row.PolicyVersions, row.DocumentVersion)
	}
}

// bindingUnknownConstraint reads the constraint a refusal's text names as the
// one it could not evaluate: the bare code, then the binding constraint. With no
// shared engine it is a shipped control whose detector signal nothing supplied.
func bindingUnknownConstraint(t *testing.T, plane, text string) string {
	t.Helper()
	const code = string(contract.ReasonUnknownConstraint) + "; "
	rest, coded := strings.CutPrefix(text, code)
	id, _, named := strings.Cut(rest, " (shipped) could not be evaluated: no value was supplied for signal.detector.")
	if !coded || !named || id == "" {
		t.Fatalf("%s: %q does not name the constraint it could not evaluate right after %q", plane, text, code)
	}
	return id
}

// expectMCPQueryAuditMatchedPolicies installs an audit queue whose
// mcp_query_audits INSERT is captured; matched drains the queue and returns the
// row's request_matched_policies.
func expectMCPQueryAuditMatchedPolicies(t *testing.T) (matched func(t *testing.T) []string) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	aq, err := NewAuditQueue(AuditModePerformance, 16, 1, db, filepath.Join(t.TempDir(), "mcp-audit-fallback.log"))
	if err != nil {
		t.Fatal(err)
	}
	prev := auditManager
	auditManager = &AuditManager{queue: aq}
	t.Cleanup(func() { auditManager = prev })
	var policies []byte
	args := make([]driver.Value, 24)
	for i := range args {
		args[i] = sqlmock.AnyArg()
	}
	args[13] = captureArg{dst: &policies}
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id'`).WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec("INSERT INTO mcp_query_audits").WithArgs(args...).WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()
	return func(t *testing.T) []string {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = aq.Shutdown(ctx)
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatalf("the query audit was not written: %v", err)
		}
		var out pq.StringArray
		if err := out.Scan(policies); err != nil {
			t.Fatalf("request_matched_policies %q is not a Postgres text array: %v", policies, err)
		}
		return out
	}
}

func TestAnUnknownConstraintRefusalIsNamedOnEveryAnchoredPlane(t *testing.T) {
	t.Run("the gateway pre-check: block_reason names it, and policies lists it first", func(t *testing.T) {
		enfSetup(t)
		nilGlobalPolicyEngines(t)
		r := enfPreCheck(t, enfOrgPublished, enfMintUserToken(t, enfOrgPublished, enfUser), "What is the weather today?")
		if r.code != http.StatusOK || r.approved(t) {
			t.Fatalf("HTTP %d approved=%v; with no engine the pre-check must refuse. body=%s", r.code, r.approved(t), r.raw)
		}
		binding := bindingUnknownConstraint(t, "the pre-check", r.str(t, "block_reason"))
		if policies := r.strings(t, "policies"); len(policies) == 0 || policies[0] != binding {
			t.Fatalf("policies %v; want %s first, the constraint block_reason names", policies, binding)
		}
	})

	t.Run("/api/request: block_reason names it, and the matched policies list it first", func(t *testing.T) {
		enfProxySetup(t)
		nilGlobalPolicyEngines(t)
		r := enfProxy(t, enfOrgPublished, enfMintUserToken(t, enfOrgPublished, enfUser), "SELECT id FROM products")
		if r.code != http.StatusForbidden || !r.blocked(t) {
			t.Fatalf("HTTP %d blocked=%v; with no engine the request must be refused. body=%s", r.code, r.blocked(t), r.raw)
		}
		binding := bindingUnknownConstraint(t, "/api/request", r.str(t, "block_reason"))
		if matched := enfProxyMatchedPolicies(t, r); len(matched) == 0 || matched[0] != binding {
			t.Fatalf("matched policies %v; want %s first, the constraint block_reason names", matched, binding)
		}
	})

	t.Run("the OpenAI-compatible route: its policy_denied message names it", func(t *testing.T) {
		enfProxySetup(t)
		nilGlobalPolicyEngines(t)
		clientID := enfProxyClientFor(enfOrgPublished)
		credential := "Basic " + base64.StdEncoding.EncodeToString([]byte(clientID+":"+knownClients[clientID].LicenseKey))
		rr := openaiCompatForTest(t, makeChatBody("gpt-4o", simpleMessages("hello"), nil),
			map[string]string{"X-Provider-Key": "test-provider-key", "Authorization": credential})
		body := rr.Body.String()
		at := strings.Index(body, string(contract.ReasonUnknownConstraint)+"; ")
		if rr.Code != http.StatusBadRequest || !strings.Contains(body, "policy_denied") || at < 0 {
			t.Fatalf("HTTP %d; with no engine the route must refuse policy_denied, naming the constraint after the code. body=%s", rr.Code, body)
		}
		bindingUnknownConstraint(t, "the OpenAI-compatible route", body[at:])
	})

	t.Run("the MCP request pass: check-input, check_policy's blocked_by, and the query audit's matched policies", func(t *testing.T) {
		w := mrsSetup(t)
		w.mrsWire(t, w.docs)
		nilGlobalPolicyEngines(t)

		code, raw, out := mrqCheckInput(t, mrsToken(t), mrsBenign, "")
		if code != http.StatusForbidden || out.Allowed {
			t.Fatalf("check-input: HTTP %d; with no engine it must refuse. body=%s", code, raw)
		}
		binding := bindingUnknownConstraint(t, "check-input", out.BlockReason)

		got, err := mrqCheckPolicy(t, w.org, mrqSession(t, w.org, ""), mrsBenign)
		if err != nil || got["allowed"] != false {
			t.Fatalf("check_policy: %v err=%v; with no engine it must refuse", got, err)
		}
		reason, _ := got["block_reason"].(string)
		if by := bindingUnknownConstraint(t, "check_policy", reason); got["blocked_by"] != binding || by != binding {
			t.Fatalf("check_policy blocked_by %v, block_reason naming %s; want %s for both", got["blocked_by"], by, binding)
		}

		matched := expectMCPQueryAuditMatchedPolicies(t)
		registerExecConnector(t, &mockConnector{queryResult: &base.QueryResult{Rows: []map[string]interface{}{{"note": "unreached"}}, RowCount: 1}})
		rr := mrsPost("/mcp/resources/query", MCPQueryRequest{Connector: "test-db", Statement: "SELECT note FROM orders", UserToken: mrsToken(t)}, mcpQueryHandler)
		message, _ := mrqRefusal(t, rr)["error"].(string)
		if rr.Code != http.StatusForbidden || !strings.HasPrefix(message, "Request blocked: ") {
			t.Fatalf("resources/query: HTTP %d error %q; want the request pass's 403", rr.Code, message)
		}
		if by := bindingUnknownConstraint(t, "resources/query", strings.TrimPrefix(message, "Request blocked: ")); by != binding {
			t.Fatalf("resources/query names %s; want %s", by, binding)
		}
		if policies := matched(t); len(policies) == 0 || policies[0] != binding {
			t.Fatalf("the query audit's request_matched_policies %v; want %s first", policies, binding)
		}
	})
}

// THE MCP RESPONSE PASS, through check-output: the refund document's ceiling
// governs tool.call, the action this pass decides, and nothing on the pass
// supplies args.request_type, so the response is refused unknown_constraint.
// Its body names the constraint, and its audit row names it as the
// organization's at its version: the row's identities come from the same
// decidingPolicies the wire reads.
func TestAnMCPResponseRefusalNamesTheConstraintItCouldNotEvaluate(t *testing.T) {
	w := mrsSetup(t)
	w.mrsWire(t, enfPublishRefundDocument(t))
	read := expectIdentityRow(t, PlaneMCP, decideAuditColumns)
	out := mrsCheckOutput(t, mrsToken(t), mrsBenign)
	const want = "unknown_constraint; ceiling.refund (organization, document version 1) could not be evaluated: no value was supplied for args.request_type, which the document requires"
	if out.code != http.StatusForbidden || !strings.HasSuffix(out.body.BlockReason, want) {
		t.Fatalf("check-output: HTTP %d block_reason %q; want 403 ending %q. body=%s", out.code, out.body.BlockReason, want, out.raw)
	}
	row := read(t)
	if len(row.PolicyIDs) == 0 || row.PolicyIDs[0] != "ceiling.refund" || row.PolicySources["ceiling.refund"] != "organization" || row.PolicyVersions["ceiling.refund"] != 1 {
		t.Errorf("row ids %v sources %v versions %v; want ceiling.refund first, the organization's, at 1", row.PolicyIDs, row.PolicySources, row.PolicyVersions)
	}
}

// THE MCP RESPONSE PASS names the constraint too, in anchoredResponse, where
// the decision becomes the refused response. It is driven here with the
// decision built: with no shared engine a handler's response pass is decided
// unknown_requirement, since no shipped constraint on that scope is unknown.
func TestTheMCPResponsePassNamesAnUnknownConstraint(t *testing.T) {
	act := &activation.Activation{PolicyBundle: "sha256:bundle-under-test", Scope: mcpResponseSeamScope}
	dec := &contract.Decision{State: contract.StateError, Reason: contract.ReasonUnknownConstraint, Determining: contract.Determining{
		Unknown: []contract.UnknownPolicy{{PolicyID: "ceiling.refund", Authority: contract.AuthorityConstraint, Reason: contract.ReasonNotSupplied, Paths: []string{"args.request_type"}}},
	}}
	res, verdict, reason, err := anchoredResponse(context.Background(), anchoredVerdict{decision: dec, act: act}, pepHandshakeResolution{}, nil, sharedpolicy.EvalOptions{}, 0, nil)
	if err != nil || verdict != VerdictDeny || reason != string(contract.ReasonUnknownConstraint) {
		t.Fatalf("verdict %q reason %q err %v; want deny unknown_constraint", verdict, reason, err)
	}
	const want = "unknown_constraint; ceiling.refund could not be evaluated: no value was supplied for args.request_type"
	if !res.Blocked || res.BlockReason != want {
		t.Fatalf("blocked=%v block_reason %q; want %q", res.Blocked, res.BlockReason, want)
	}
	if res.BlockedBy == nil || res.BlockedBy.PolicyID != "ceiling.refund" {
		t.Fatalf("blocked_by %+v; want the binding constraint ceiling.refund", res.BlockedBy)
	}
}

// DECIDE'S METRIC NEVER CARRIES AN ORGANIZATION'S ID (#4227). A deny with no
// blocking policy - an unknown_requirement, or an allow the obligation gates
// turned into a deny (#2958) - is keyed on the first policy it names, at the
// binding path's bounded tier: an organization's id collapses to tenant_custom,
// and a shipped control keeps its id.
func TestADecideDenyWithNoBlockingPolicyIsLabelledAtTheBoundedTier(t *testing.T) {
	const origin = "test-origin-4227"
	const orgID = "grant.org-authored-4227"
	before := testutil.ToFloat64(decideBlocks.WithLabelValues("tenant_custom", origin))
	recordDecideOutcomeMetrics(VerdictDeny, "llm", origin, nil, "", "", []string{orgID}, nil)
	if got := testutil.ToFloat64(decideBlocks.WithLabelValues("tenant_custom", origin)); got != before+1 {
		t.Fatalf("decideBlocks{tenant_custom} = %v, want %v", got, before+1)
	}
	if leaked := testutil.ToFloat64(decideBlocks.WithLabelValues(orgID, origin)); leaked != 0 {
		t.Fatalf("an organization's id leaked as a label value: %v", leaked)
	}
	shipped := legacycompile.CorpusPolicyIDFor("static_policies", "sys_under_test_4227")
	before = testutil.ToFloat64(decideBlocks.WithLabelValues(shipped, origin))
	recordDecideOutcomeMetrics(VerdictDeny, "llm", origin, nil, "", "", []string{shipped}, nil)
	if got := testutil.ToFloat64(decideBlocks.WithLabelValues(shipped, origin)); got != before+1 {
		t.Fatalf("decideBlocks{%s} = %v, want %v: a shipped control keeps its id", shipped, got, before+1)
	}
}
