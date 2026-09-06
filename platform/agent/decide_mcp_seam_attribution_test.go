// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

// =============================================================================
// THE MCP SEAM'S AUDIT ATTRIBUTION (#3717, child of the audit umbrella #3709)
//
//	An audit row for a governed tool call names the tool it governed.
//
// #3717 was the absence of that: the ext_mcp adapter built every decide request
// with Target.Type = "mcp_tool" while the PDP's tool-attribution gate compared
// against "tool", so the branch that copies Target.Server / Target.Tool onto the
// audit identity never ran. Every MCP-seam row was written with tool_server and
// tool_name empty. Nothing failed: the row was valid and the decision was
// enforced — the row just did not say what it was about.
//
// FIXING IT IS NOT PURELY A RECORD CHANGE, AND SAYING SO WAS THIS CHANGE'S OWN
// FIRST DEFECT. The same gate that fills those two audit fields also used to
// supply the capability-scoping key, so restoring the canonical target type
// handed the seam's client-chosen tool name to an enforcement input. Test 3
// below is that boundary; the split lives in handleDecide.
//
// WHY THIS TEST LOOKS THE WAY IT DOES. The defect lived in the gap between two
// packages that each tested clean:
//
//   - platform/gateway-adapters asserted the decide BODY carries the tool
//     (TestExtMcpCheckRequestAllow), which it always did;
//   - platform/agent asserted the gate copies Server/Tool for a "tool" target
//     (decision_earlydeny_audit_realpg_test.go), which it always did.
//
// Both sides were green for three releases. A test of either side alone cannot
// see this class, so this one drives the REAL ExtMcpServer into the REAL
// handleDecide over HTTP and reads the REAL audit INSERT — the whole path the
// mismatch sat in the middle of. It deliberately does not assert on the decide
// request's post-parse shape, because asserting the shape is what the two
// existing tests already do.
// =============================================================================

import (
	"context"
	"database/sql/driver"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"

	"axonflow/platform/decision/legacycompile"
	gatewayadapters "axonflow/platform/gateway-adapters"
	agwapi "axonflow/platform/gateway-adapters/agentgateway/api"
	"axonflow/platform/shared/pep"
)

// toolAttributionMatcher asserts what audit_logs.policy_details says about the
// tool this decision governed. Empty strings mean the key must be ABSENT —
// writeDecisionAuditRow omits tool_server/tool_name when they are empty, so
// "absent" and "empty" are the same state on the wire and the matcher must not
// pretend to tell them apart.
type toolAttributionMatcher struct {
	wantServer string
	wantTool   string
}

func (m toolAttributionMatcher) Match(v driver.Value) bool {
	raw, ok := jsonbBytes(v)
	if !ok {
		return false
	}
	var d map[string]interface{}
	if json.Unmarshal(raw, &d) != nil {
		return false
	}
	got := func(key string) string {
		s, _ := d[key].(string)
		return s
	}
	return got("tool_server") == m.wantServer && got("tool_name") == m.wantTool
}

// decidePDPServer serves the REAL handleDecide at the decide path, stamping the
// authenticated identity apiAuthMiddleware would have put on the context. The
// middleware is bypassed rather than reimplemented: this test is about what the
// handler records, and the identity is an input to that, not the subject.
func decidePDPServer(t *testing.T, tenant, org string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc(decisionHandlerPath, func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		ctx = context.WithValue(ctx, ContextKeyTenantID, tenant)
		ctx = context.WithValue(ctx, ContextKeyOrgID, org)
		ctx = context.WithValue(ctx, ContextKeyClientID, "auth-client")
		ctx = context.WithValue(ctx, ContextKeyAuthKind, AuthKindEnterprise)
		handleDecide(w, r.WithContext(ctx))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// mcpSeamHarness wires enterprise mode, the JWT secret, a sqlmock usageDB, the
// real /decide handler and the real ext_mcp adapter, and returns the mock plus
// the adapter.
func mcpSeamHarness(t *testing.T) (sqlmock.Sqlmock, *gatewayadapters.ExtMcpServer) {
	t.Helper()
	t.Setenv("DEPLOYMENT_MODE", "enterprise")
	orig := jwtSecret
	jwtSecret = []byte(testJWTSecret)
	t.Cleanup(func() { jwtSecret = orig })

	mock := withMockUsageDB(t)
	srv := decidePDPServer(t, mcpSeamTenant, mcpSeamTenant)

	pdp, err := gatewayadapters.NewPDP(gatewayadapters.Config{
		ListenAddr:       "127.0.0.1:0",
		AxonFlowEndpoint: srv.URL,
		// The adapter's OrgID/TenantID are asserted as caller_identity on the
		// wire and must match the identity the handler is stamping, or the PDP
		// denies for impersonation before it ever reaches the gate under test.
		OrgID:            mcpSeamTenant,
		LicenseKey:       "lic-1",
		TenantID:         mcpSeamTenant,
		GatewayID:        "agw-test",
		ConnectorTag:     "agentgateway",
		DefaultStage:     gatewayadapters.StageTool,
		FailMode:         gatewayadapters.FailModeClosed,
		RequestTimeout:   10 * time.Second,
		MaxBodyBytes:     1 << 20,
		BreakerThreshold: 100,
		BreakerCooldown:  time.Second,
	})
	if err != nil {
		t.Fatalf("NewPDP: %v", err)
	}
	cfg := gatewayadapters.Config{GatewayID: "agw-test", MaxBodyBytes: 1 << 20}
	return mock, gatewayadapters.NewExtMcpServer(pdp, cfg)
}

const mcpSeamTenant = "seam-tenant"

// mcpToolsCall is a tools/call, carrying a user token the PDP will validate.
// ext_mcp.proto specifies exactly one service_names entry for a single-target
// method such as this one, and that entry is where tool_server comes from.
func mcpToolsCall(t *testing.T, serviceNames []string, toolName string) *agwapi.McpRequest {
	t.Helper()
	return mcpCall(t, "tools/call", serviceNames,
		`{"name":"`+toolName+`","arguments":{"account":"12345"}}`)
}

// mcpCall builds an arbitrary governed MCP request. Fanout methods (`*/list`)
// carry one service_names entry PER BACKEND, which is the only shape in which
// this seam legitimately sees more than one.
func mcpCall(t *testing.T, method string, serviceNames []string, params string) *agwapi.McpRequest {
	t.Helper()
	return &agwapi.McpRequest{
		ServiceNames: serviceNames,
		Method:       method,
		McpRequest:   []byte(params),
		Headers: []*agwapi.McpHeader{
			{Key: "authorization", Value: []byte("Bearer " + mintUserTokenWithTenant(t, mcpSeamTenant))},
			{Key: "traceparent", Value: []byte("00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")},
		},
	}
}

// --- 1. The populated case: a governed MCP tool call names its tool. --------
//
// This is the assertion #3717 existed for, and the one whose absence let the
// defect ship. It FAILS on the pre-fix tree (Target.Type "mcp_tool" against a
// gate reading "tool" → both fields empty → the INSERT argument list does not
// match → ExpectationsWereMet reports the unmet expectation).
func TestMCPSeamAuditRowCarriesToolServerAndToolName(t *testing.T) {
	mock, seam := mcpSeamHarness(t)

	args := decideAuditInsertArgs(AuditVerdictAllowed, toolAttributionMatcher{
		wantServer: "payments",
		wantTool:   "refund",
	})
	mock.ExpectExec("INSERT INTO audit_logs").WithArgs(args...).
		WillReturnResult(sqlmock.NewResult(0, 1))

	res, err := seam.CheckRequest(context.Background(), mcpToolsCall(t, []string{"payments"}, "refund"))
	if err != nil {
		t.Fatalf("CheckRequest: %v", err)
	}
	// Reachability: without a Pass the decide call never reached a verdict and
	// the audit assertion below would be about a path that did not run.
	if res.GetPass() == nil {
		t.Fatalf("expected the seam to pass the call through; got %+v", res)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("the MCP seam's audit row must carry policy_details.tool_server=payments "+
			"and .tool_name=refund. An empty pair here is #3717: the decision was enforced "+
			"correctly and the compliance record does not say what it was about: %v", err)
	}
}

// --- 2. A fanned-out call names no server rather than the wrong one. -------
//
// service_names carries one entry per backend for FANOUT methods, so there is
// no single server to attribute. The pair with test 1 is what makes either
// real: with only test 1, `Server: names[0]` would pass while writing "docs"
// onto a row that also touched two other backends.
//
// The fixture is a genuine fanout method (`tools/list`), not a `tools/call`
// with three names. An earlier version used the latter, which ext_mcp.proto
// says agentgateway cannot emit — the mutant died against a request shape that
// does not exist, which is a pin on a fiction. On this path extractMcpCall
// falls through to its generic branch, so the tool slot carries the METHOD;
// that is this seam's declared unit of governance for a non-tools/call request
// and is asserted here rather than left implicit.
func TestMCPSeamFanoutCallAttributesNoServer(t *testing.T) {
	mock, seam := mcpSeamHarness(t)

	args := decideAuditInsertArgs(AuditVerdictAllowed, toolAttributionMatcher{
		wantServer: "", // must be absent — naming one of three is a WRONG row
		wantTool:   "tools/list",
	})
	mock.ExpectExec("INSERT INTO audit_logs").WithArgs(args...).
		WillReturnResult(sqlmock.NewResult(0, 1))

	res, err := seam.CheckRequest(context.Background(),
		mcpCall(t, "tools/list", []string{"docs", "payments", "search"}, `{"cursor":""}`))
	if err != nil {
		t.Fatalf("CheckRequest: %v", err)
	}
	if res.GetPass() == nil {
		t.Fatalf("expected Pass; got %+v", res)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("a fanout call must leave tool_server absent, not name one of the backends: %v", err)
	}
}

// --- 3. ATTRIBUTION MUST NOT BUY A DETECTOR BYPASS. ------------------------
//
// Restoring the canonical target type on this seam restores the audit row AND,
// through the same value, would have handed the seam's tool name to
// capability-scoped evaluation (#2801) — where a name that positively
// classifies as a text-document tool makes the engine SKIP execution-class
// detectors. Measured before the split, end to end through this same harness
// with policy rows installed: the SAME payload came back BLOCKED under
// tool="run_sql_query" and ALLOWED under tool="editJiraIssue". A client of an
// in-path gateway chooses that name; an audit fix must not be the thing that
// makes it load-bearing.
//
// THE PAIR IS THE TEST. Asserting only the seam's deny would also pass if
// capability scoping had been disabled outright, which would silently undo
// #2801 for every advisory PEP. The second half drives the SAME tool name and
// the SAME payload through an advisory-shaped target — one that names no
// hosting server — and requires the relaxation to still apply there.
func TestMCPSeamGetsFullEvaluationRegardlessOfToolName(t *testing.T) {
	// Prose that trips the execution-class SQLi detector, and is exactly the
	// kind of content capability scoping exists to stop flagging on a document
	// tool. Same string as TestHandleDecide_ToolTargetCapabilityScope.
	const docProse = "We will revoke the temporary access immediately after the single edit call."

	// EVERY service_names SHAPE, because the first version of this fix keyed
	// only on Target.Server and mcpTargetServer returns "" for nil, empty AND
	// multi — so three of these four rows got the relaxation back on a fully
	// client-chosen name while the fourth passed and the suite went green. The
	// shapes are the axis; the tool name is the payload.
	serviceNameShapes := map[string][]string{
		"one-backend":  {"payments"},
		"nil-backends": nil,
		"no-backends":  {},
		"two-backends": {"payments", "docs"},
	}
	t.Run("through the gateway seam: full evaluation, tool name is not a lever", func(t *testing.T) {
		for shape, names := range serviceNameShapes {
			for _, tool := range []string{"run_sql_query", "editJiraIssue"} {
				t.Run(shape+"/"+tool, func(t *testing.T) {
					t.Setenv("ENVIRONMENT", "development")
					t.Setenv("SQLI_ACTION", "block")
					installSharedEngineWithPolicyRows(t)
					installCircuitBreakerWithMockDB(t)
					_, seam := mcpSeamHarness(t)

					req := mcpToolsCall(t, names, tool)
					req.McpRequest = []byte(`{"name":"` + tool + `","arguments":{"note":"` + docProse + `"}}`)
					res, err := seam.CheckRequest(context.Background(), req)
					if err != nil {
						t.Fatalf("CheckRequest: %v", err)
					}
					if res.GetPass() != nil {
						t.Errorf("service_names=%v: the seam ALLOWED a payload the execution-class "+
							"detector blocks, because the client named its tool %q. On an in-path "+
							"gateway the tool name is a field of the MCP client's own request body, and "+
							"capability scoping's premise — that the party naming the tool is the party "+
							"enforcing, and could equally not call the PEP at all — does not hold. "+
							"Restoring the audit row must not hand a caller a detector switch, and it "+
							"must not do so on ANY service_names shape: the value comes from an external "+
							"binary whose behaviour no test here has observed.", names, tool)
					}
				})
			}
		}
	})

	// The control. Without it, disabling capability scoping globally would pass
	// the half above while regressing #2801 for every advisory PEP — the fix
	// overshooting in the direction nothing else would catch.
	t.Run("advisory target with no server: the relaxation still applies", func(t *testing.T) {
		t.Setenv("DEPLOYMENT_MODE", "community")
		t.Setenv("ENVIRONMENT", "development")
		t.Setenv("SQLI_ACTION", "block")
		installSharedEngineWithPolicyRows(t)
		installCircuitBreakerWithMockDB(t)

		verdictFor := func(target DecisionTarget) interface{} {
			t.Helper()
			body, _ := json.Marshal(DecideRequest{
				Stage:          DecisionStageTool,
				CallerIdentity: DecisionCallerIdentity{GatewayID: "test-gw", TenantID: "test-tenant"},
				Target:         target,
				Query:          docProse,
			})
			rr := decideForTest(t, body)
			if rr.Code != http.StatusOK {
				t.Fatalf("status: got %d want 200; body=%s", rr.Code, rr.Body.String())
			}
			var env map[string]interface{}
			if err := json.Unmarshal(rr.Body.Bytes(), &env); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			return env["verdict"]
		}

		// Anti-vacuity FIRST: this engine must actually block the payload for an
		// unclassified tool, or "allowed" below proves nothing about scoping.
		if got := verdictFor(DecisionTarget{Type: pep.TargetTypeTool, Tool: "run_sql_query"}); got != VerdictDeny {
			t.Fatalf("control failed: an unclassified advisory tool target must still DENY this payload, got %v — "+
				"the assertion below would be vacuous", got)
		}
		if got := verdictFor(DecisionTarget{Type: pep.TargetTypeTool, Tool: "editJiraIssue"}); got != VerdictAllow {
			t.Errorf("capability scoping no longer relaxes for an advisory text-document target (got %v): the "+
				"#3717 split has overshot and disabled #2801 for every PEP, not only for server-named targets", got)
		}
		// And the discriminator itself: the SAME advisory tool name, with a
		// server added, must stop relaxing. This is the one-field difference
		// the rule is made of, asserted directly rather than inferred.
		if got := verdictFor(DecisionTarget{Type: pep.TargetTypeTool, Server: "payments", Tool: "editJiraIssue"}); got != VerdictDeny {
			t.Errorf("a target naming a hosting SERVER must not supply a capability-scoping key (got %v): the "+
				"caller is routing to a backend it does not execute, which is where the trust premise fails", got)
		}
	})
}

// TestAdvisoryPlaneStillScopesWhenBothIdentitiesAgree pins the OTHER side of
// the #3717 split, which nothing else covers on a runnable path.
//
// The four advisory-plane call sites pass the same identity for both roles —
// attribution and capability scoping — because there the caller executes the
// tool and reports its own name. If one of them were "simplified" to pass ""
// for the scoping key, those planes would silently lose #2801 relaxation and
// every test would stay green: handleDecide is the only other caller and it
// withholds the key deliberately, so the existing scoping test cannot witness
// the advisory contract at all. R3 proved that mutant survived.
//
// It asserts through evaluateInputPolicies' own observable outcome rather than
// through a handler, because the property is about what the shared helper does
// when the two identities agree.
func TestAdvisoryPlaneStillScopesWhenBothIdentitiesAgree(t *testing.T) {
	const docProse = "We will revoke the temporary access immediately after the single edit call."
	t.Setenv("DEPLOYMENT_MODE", "community")
	t.Setenv("ENVIRONMENT", "development")
	t.Setenv("SQLI_ACTION", "block")
	installSharedEngineWithPolicyRows(t)

	blocked := func(o InputPolicyOutcome) bool {
		return o.StaticResult != nil && o.StaticResult.Blocked
	}
	// The SAME detection config handleDecide resolves, so this exercises the
	// wrapper under the configuration the advisory planes actually run with —
	// a zero-value ModeDetectionConfig disables the detector families and the
	// control below (correctly) refuses to let the test proceed on it.
	cfg := ResolveGatewayDetectionConfig(context.Background(), "o-1")
	call := func(tool string) InputPolicyOutcome {
		return evaluateInputPolicies(context.Background(),
			"t-1", "o-1", "1", "developer", "conn",
			tool /* toolIdentity */, tool, /* capabilityScopeIdentity: the advisory-plane pairing */
			// PlaneMCP: the four advisory call sites this models all name that
			// plane, and a test naming a different one would be modelling a
			// caller that does not exist.
			"check_input", docProse, nil, cfg, false, nil, legacycompile.PlaneMCP)
	}

	// Anti-vacuity FIRST: an unclassified tool must BLOCK this payload, or the
	// allow below would prove nothing about scoping.
	if !blocked(call("run_sql_query")) {
		t.Fatal("control failed: an unclassified tool identity must still block this payload — " +
			"the assertion below would be vacuous")
	}
	if blocked(call("editJiraIssue")) {
		t.Error("passing the same identity for both roles no longer applies capability scoping to a " +
			"text-document tool. That pairing is what the four ADVISORY-plane call sites use — the " +
			"enforcing client executes the tool and reports its own name — and the #3717 split must " +
			"not have changed it (#2801).")
	}
}

// --- 4. THE OPPOSITE-DIRECTION PIN: one canonical value, no second word. ---
//
// #3717 had two available fixes: send the canonical value from the adapter, or
// widen the PDP gate to accept "mcp_tool" as well. The second would have made
// the audit row correct AND forked the vocabulary permanently, with every later
// producer free to pick either and no way to tell which was meant. This test
// pins the direction NOT taken: the retired spelling must attribute NOTHING, so
// re-adding it — as an `||`, an accepting set, or a normalisation table — reds.
//
// CASE IS NOT A SECOND WORD, AND THE TEST SAYS SO OUT LOUD. The gate is
// strings.EqualFold, so "TOOL" and "Tool" attribute exactly as "tool" does.
// That is a case folding of ONE value, not a second accepted spelling — but an
// earlier version of this test never tried a case variant while its name
// claimed to establish that only one spelling is accepted, and the docs it was
// paired with said "no alias". A test whose name asserts a property it does not
// exercise is the shape this whole audit is about, so the variants are here and
// the assertion about them is explicit.
//
// The accepted vocabulary is read from pep.TargetTypes rather than enumerated,
// so a value added there without a decision about attribution reds too: a new
// target shape is exactly when someone must think about whether Server/Tool
// mean anything for it.
func TestDecideToolAttributionAcceptsOneValueFoldedNotASecondSpelling(t *testing.T) {
	// retiredMCPToolSpelling is a LITERAL on purpose — a constant shared with
	// the production code would move with a rename and stop pinning anything.
	const retiredMCPToolSpelling = "mcp_tool"

	type probe struct {
		spelling  string
		attribute bool
	}
	var probes []probe
	for _, v := range pep.TargetTypes {
		probes = append(probes, probe{v, v == pep.TargetTypeTool})
	}
	// Case variants of the canonical value: same value, folded. They MUST
	// attribute, and asserting that is what makes the "no alias" claim precise
	// rather than merely strict-sounding.
	//
	// DERIVED FROM THE VOCABULARY, not appended unconditionally. Appending them
	// is what an earlier version of this test did, and it set sawAttributed by
	// construction — quietly disarming the one anti-vacuity check here, in the
	// same edit that deleted its sibling for exactly that defect. Built this
	// way, a vocabulary that loses its tool entry produces no attributed probe
	// and the floor below fires.
	for _, v := range pep.TargetTypes {
		if v != pep.TargetTypeTool {
			continue
		}
		probes = append(probes,
			probe{strings.ToUpper(v), true},
			probe{strings.ToUpper(v[:1]) + v[1:], true},
		)
	}
	// A different WORD, however spelled, must not attribute.
	probes = append(probes,
		probe{retiredMCPToolSpelling, false},
		probe{strings.ToUpper(retiredMCPToolSpelling), false},
		probe{"", false},
	)

	sawAttributed := false
	for _, p := range probes {
		name := p.spelling
		if name == "" {
			name = "empty"
		}
		t.Run("type="+name, func(t *testing.T) {
			t.Setenv("DEPLOYMENT_MODE", "enterprise")
			mock := withMockUsageDB(t)

			want := toolAttributionMatcher{}
			if p.attribute {
				want = toolAttributionMatcher{wantServer: "payments", wantTool: "refund"}
				sawAttributed = true
			}

			args := decideAuditInsertArgs(AuditVerdictAllowed, want)
			mock.ExpectExec("INSERT INTO audit_logs").WithArgs(args...).
				WillReturnResult(sqlmock.NewResult(0, 1))

			req := decideEnterpriseReq(t, DecideRequest{
				Stage:  DecisionStageTool,
				Target: DecisionTarget{Type: p.spelling, Server: "payments", Tool: "refund"},
				Query:  "refund order 42",
			}, "auth-tenant", "auth-tenant")
			rr := httptest.NewRecorder()
			handleDecide(rr, req)

			if rr.Code != http.StatusOK {
				t.Fatalf("status: got %d want 200; body=%s", rr.Code, rr.Body.String())
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				if p.attribute {
					t.Errorf("target type %q is the canonical value (case-folded) and must attribute "+
						"the tool: %v", p.spelling, err)
					return
				}
				t.Errorf("target type %q must attribute NOTHING — %q is the one value that records "+
					"tool_server/tool_name, and a second accepted WORD forks the vocabulary this fix "+
					"exists to close: %v", p.spelling, pep.TargetTypeTool, err)
			}
		})
	}

	// Anti-vacuity: the loop must have exercised the ATTRIBUTED case. A
	// vocabulary that lost its tool entry would otherwise leave this test green
	// while testing only refusals — and that is exactly what M9 does, so this
	// check is mutation-proved rather than assumed.
	//
	// There is deliberately no matching sawUnattributed check. Review showed it
	// COULD NOT FIRE: the probe list appends the retired spelling and the empty
	// string unconditionally, so the unattributed branch is taken by
	// construction. An assertion that cannot fail is indistinguishable from one
	// that passes, and leaving it in would have made this comment a lie.
	if !sawAttributed {
		t.Error("no subtest exercised the ATTRIBUTED case — pep.TargetTypes no longer contains the tool type")
	}
}
