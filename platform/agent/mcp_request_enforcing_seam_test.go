// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"bytes"
	"context"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"axonflow/platform/connectors/base"
	"axonflow/platform/decision/activation"
	"axonflow/platform/decision/authoringcatalog"
	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/legacycompile"
	"axonflow/platform/decision/policypack"
	sharedidentity "axonflow/platform/shared/identity"
	sharedpolicy "axonflow/platform/shared/policy"
)

// THE MCP REQUEST PASS'S ENFORCING SEAM, THROUGH THE REAL HANDLERS (#3564).
//
// Every assertion reads what a caller or an auditor reads - the encoded body,
// the tool result, the audit row, a counter - except the one branch no handler
// can reach on its own: a redaction the pass cannot perform after the engine
// decided. The world is the response pass's (mrsSetup): Basic auth over a
// minted licence, the identity plane's admission of the subject, activation of
// the restriction, and a document constraining bob's tool.call published
// through the real authoring API. Only storage and the connector are in memory.

// mrqCheckInput posts statement to check-input as the harness credential with
// userToken ("" presents none) from an enforcement point presenting handshake
// ("" presents none).
func mrqCheckInput(t *testing.T, userToken, statement, handshake string) (int, string, MCPCheckInputResponse) {
	t.Helper()
	body, _ := json.Marshal(MCPCheckInputRequest{ConnectorType: "postgres", Statement: statement, UserToken: userToken})
	req := httptest.NewRequest("POST", "/api/v1/mcp/check-input", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", utrBasicAuthHeader())
	if handshake != "" {
		req.Header.Set(contract.PEPHandshakeHeader, handshake)
	}
	rr := httptest.NewRecorder()
	mcpCheckInputHandler(rr, req)
	var out MCPCheckInputResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("the check-input body is not a JSON object: %v\n%s", err, rr.Body.String())
	}
	return rr.Code, rr.Body.String(), out
}

// mrqSession is an MCP server session whose per-user token a validator accepted
// for email, or - for "" - the session's client credential alone.
func mrqSession(t *testing.T, org, email string) *mcpSession {
	t.Helper()
	s := &mcpSession{tenantID: utrTestTenant, orgID: org, clientID: utrTestClientID, authKind: AuthKindEnterprise}
	if email == "" {
		return s
	}
	user, authErr := ResolveUser(&AuthResult{Kind: AuthKindEnterprise, OrgID: org, TenantID: utrTestTenant, ClientID: utrTestClientID}, mrsTokenFor(t, email))
	if authErr != nil {
		t.Fatalf("resolving %s's minted token: %v", email, authErr.Message)
	}
	s.identityInputs = mcpIdentityInputs{tokenResolvedIdentity: true, validatedToken: &sharedidentity.ValidatedIdentity{
		Email: email, OrgID: org, Source: sharedidentity.ValidatorNameHS256, Validated: true, Claims: user.TokenClaims,
	}}
	return s
}

// mrqCheckPolicy calls the MCP server's check_policy tool for statement.
func mrqCheckPolicy(t *testing.T, org string, session *mcpSession, statement string) (map[string]interface{}, error) {
	t.Helper()
	ctx := context.WithValue(context.Background(), ContextKeyOrgID, org)
	resp, err := mcpToolCheckPolicy(ctx, session, map[string]interface{}{"connector_type": "postgres", "statement": statement}, pepHandshakeResolution{})
	if err != nil {
		return nil, err
	}
	return resp.(map[string]interface{}), nil
}

// mrqRefusal decodes a connector route's refusal envelope.
func mrqRefusal(t *testing.T, rr *httptest.ResponseRecorder) map[string]interface{} {
	t.Helper()
	var body map[string]interface{}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("the refusal is not a JSON object: %v\n%s", err, rr.Body.String())
	}
	return body
}

func mrqDenyCounter(reason string) float64 {
	return testutil.ToFloat64(anchoredEnforceDecisions.WithLabelValues(mcpRequestSeamScope.String(), decisionEngineAnchored, VerdictDeny, reason))
}

func TestMCPRequestEnforcingSeam(t *testing.T) {
	w := mrsSetup(t)
	w.mrsWire(t, w.docs)

	t.Run("a verified user's clean statement is ALLOWED by the anchored engine, and the body says so", func(t *testing.T) {
		code, raw, r := mrqCheckInput(t, mrsToken(t), mrsBenign, "")
		if code != http.StatusOK || !r.Allowed || !r.RedactionEvaluated || r.Redacted {
			t.Fatalf("got HTTP %d allowed=%v redaction_evaluated=%v redacted=%v; want a clean evaluated 200 allow. body=%s", code, r.Allowed, r.RedactionEvaluated, r.Redacted, raw)
		}
		if r.Engine != decisionEngineAnchored || r.SubjectType != string(sharedidentity.SubjectUser) || r.PolicyBundle == "" {
			t.Fatalf("engine=%q subject_type=%q policy_bundle=%q; want anchored/User with the bundle named. body=%s", r.Engine, r.SubjectType, r.PolicyBundle, raw)
		}
	})

	// PRD v11 §1.6: a caller with no user identity is evaluated for its client
	// credential, recorded as a Client, whom the document's constraint does not
	// name.
	t.Run("a credential-only caller is evaluated as a Client", func(t *testing.T) {
		code, raw, r := mrqCheckInput(t, "", mrsBenign, "")
		if code != http.StatusOK || !r.Allowed || r.SubjectType != string(sharedidentity.SubjectClient) {
			t.Fatalf("got HTTP %d allowed=%v subject_type %q; want a 200 allow for a Client. body=%s", code, r.Allowed, r.SubjectType, raw)
		}
	})

	t.Run("a principal the document constrains is refused explicit_constraint, and counted on mcp:request", func(t *testing.T) {
		before := mrqDenyCounter(string(contract.ReasonExplicitConstraint))
		code, raw, r := mrqCheckInput(t, mrsTokenFor(t, enfBob), mrsBenign, "")
		if code != http.StatusForbidden || r.Allowed || r.Engine != decisionEngineAnchored || r.BlockReason != string(contract.ReasonExplicitConstraint) {
			t.Fatalf("got HTTP %d allowed=%v engine=%q block_reason=%q; want 403 anchored explicit_constraint for bob. body=%s", code, r.Allowed, r.Engine, r.BlockReason, raw)
		}
		if len(r.PolicyMatches) == 0 || r.DecisionID == "" {
			t.Fatalf("policy_matches=%v decision_id=%q; a refusal names the controls that determined it and the decision. body=%s", r.PolicyMatches, r.DecisionID, raw)
		}
		if after := mrqDenyCounter(string(contract.ReasonExplicitConstraint)); after != before+1 {
			t.Fatalf("the mcp:request explicit_constraint counter moved %v -> %v; want +1", before, after)
		}
	})
}

// TestTheRequestPassIsDecidedAtEveryEntryPoint drives the four entry points the
// request pass has. On each the principal the document constrains is refused
// and a verified user is not, so a route that skipped the seam - or decided for
// the wrong principal - fails here by name. A refused connector route never
// runs its statement: the connector's result must not reach the caller.
func TestTheRequestPassIsDecidedAtEveryEntryPoint(t *testing.T) {
	w := mrsSetup(t)
	w.mrsWire(t, w.docs)
	const ran = "mrq-connector-ran"
	bobToken, aliceToken := mrsTokenFor(t, enfBob), mrsToken(t)

	t.Run("check-input", func(t *testing.T) {
		if code, raw, _ := mrqCheckInput(t, bobToken, mrsBenign, ""); code != http.StatusForbidden {
			t.Fatalf("bob: HTTP %d; want 403. body=%s", code, raw)
		}
		if code, raw, _ := mrqCheckInput(t, aliceToken, mrsBenign, ""); code != http.StatusOK {
			t.Fatalf("alice: HTTP %d; want 200. body=%s", code, raw)
		}
	})

	t.Run("check_policy", func(t *testing.T) {
		got, err := mrqCheckPolicy(t, w.org, mrqSession(t, w.org, enfBob), mrsBenign)
		if err != nil {
			t.Fatal(err)
		}
		if got["allowed"] != false || got["block_reason"] != string(contract.ReasonExplicitConstraint) || got["engine"] != decisionEngineAnchored {
			t.Fatalf("bob's session got %v; want an anchored explicit_constraint refusal", got)
		}
		if got, err = mrqCheckPolicy(t, w.org, mrqSession(t, w.org, enfUser), mrsBenign); err != nil || got["allowed"] != true || got["subject_type"] != string(sharedidentity.SubjectUser) {
			t.Fatalf("alice's session got %v (err %v); want an anchored allow for a User", got, err)
		}
	})

	for _, route := range []struct {
		name string
		conn *mockConnector
		post func(token string) *httptest.ResponseRecorder
	}{
		{"resources/query", &mockConnector{queryResult: &base.QueryResult{Rows: []map[string]interface{}{{"note": ran}}, RowCount: 1}},
			func(token string) *httptest.ResponseRecorder {
				return mrsPost("/mcp/resources/query", MCPQueryRequest{Connector: "test-db", Statement: "SELECT note FROM orders", UserToken: token}, mcpQueryHandler)
			}},
		{"tools/execute", &mockConnector{executeResult: &base.CommandResult{RowsAffected: 1, Message: ran}},
			func(token string) *httptest.ResponseRecorder {
				return mrsPost("/mcp/tools/execute", MCPExecuteRequest{Connector: "test-db", Action: "UPDATE", Statement: "UPDATE orders SET x=1", UserToken: token}, mcpExecuteHandler)
			}},
	} {
		t.Run(route.name, func(t *testing.T) {
			registerExecConnector(t, route.conn)
			before := mrqDenyCounter(string(contract.ReasonExplicitConstraint))
			rr := route.post(bobToken)
			body := mrqRefusal(t, rr)
			if rr.Code != http.StatusForbidden || body["error"] != "Request blocked: "+string(contract.ReasonExplicitConstraint) || body["engine"] != decisionEngineAnchored {
				t.Fatalf("bob: HTTP %d body %v; want 403 anchored explicit_constraint", rr.Code, body)
			}
			if strings.Contains(rr.Body.String(), ran) {
				t.Fatalf("the refused statement ran: its connector result reached the caller: %s", rr.Body.String())
			}
			if after := mrqDenyCounter(string(contract.ReasonExplicitConstraint)); after != before+1 {
				t.Fatalf("the mcp:request explicit_constraint counter moved %v -> %v; want +1", before, after)
			}
			if rr = route.post(aliceToken); rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), ran) {
				t.Fatalf("alice: HTTP %d; want 200 carrying the connector's result. body=%s", rr.Code, rr.Body.String())
			}
		})
	}
}

// mrqErrorRowArgs is a check-input "error" row's INSERT arguments
// (writeMCPDecisionAudit's 20 columns): the request type, the verdict and the
// plane pinned.
func mrqErrorRowArgs() []driver.Value {
	args := make([]driver.Value, 20)
	for i := range args {
		args[i] = sqlmock.AnyArg()
	}
	args[9] = "mcp_check_input"
	args[12] = mcpVerdictError
	args[15] = PlaneMCP
	return args
}

func TestMCPRequestSeamFailsClosedNamingEachCause(t *testing.T) {
	w := mrsSetup(t)
	token := mrsToken(t)
	for _, c := range []struct {
		name    string
		cause   string
		arrange func(t *testing.T)
	}{
		{"the organization's active document cannot be read", enforceCauseActiveDocument, func(t *testing.T) {
			w.mrsWire(t, mrsDocuments{enfDocuments: w.docs, broken: true})
		}},
		{"no enforcer is wired in this process", enforceCauseNotWired, func(t *testing.T) {
			w.mrsWire(t, w.docs)
			anchoredEnforcerInstance.Store(nil)
		}},
		{"the deployment vocabulary cannot be resolved", enforceCauseActivation, func(t *testing.T) {
			enfInstallSeamWith(t, w.docs, func() (*authoringcatalog.Snapshot, error) {
				return nil, errors.New("the catalog is unreadable")
			})
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			c.arrange(t)
			counter := anchoredEnforceDecisions.WithLabelValues(mcpRequestSeamScope.String(), decisionEngineAnchored, "unavailable", c.cause)
			before := testutil.ToFloat64(counter)

			mock := withMockUsageDB(t)
			mock.MatchExpectationsInOrder(false)
			mock.ExpectExec("INSERT INTO audit_logs").WithArgs(mrqErrorRowArgs()...).WillReturnResult(sqlmock.NewResult(0, 1))
			code, raw, _ := mrqCheckInput(t, token, mrsBenign, "")
			if code != http.StatusServiceUnavailable || !strings.Contains(raw, enforceCauseMessages[c.cause]) {
				t.Fatalf("check-input: HTTP %d; want 503 naming %q. body=%s", code, enforceCauseMessages[c.cause], raw)
			}
			if strings.Contains(raw, "unreadable") || strings.Contains(raw, "unreachable") {
				t.Fatalf("the refusal leaked the underlying error to the caller: %s", raw)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatalf("the refused attempt wrote no canonical error row: %v", err)
			}

			if _, err := mrqCheckPolicy(t, w.org, mrqSession(t, w.org, enfUser), mrsBenign); err == nil || err.Error() != c.cause+": "+enforceCauseMessages[c.cause] {
				t.Fatalf("check_policy returned %v; want the error %q", err, c.cause+": "+enforceCauseMessages[c.cause])
			}

			registerExecConnector(t, &mockConnector{queryResult: &base.QueryResult{Rows: []map[string]interface{}{{"note": mrsBenign}}, RowCount: 1}})
			rr := mrsPost("/mcp/resources/query", MCPQueryRequest{Connector: "test-db", Statement: "SELECT note FROM orders", UserToken: token}, mcpQueryHandler)
			if rr.Code != http.StatusServiceUnavailable || mrqRefusal(t, rr)["error"] != enforceCauseMessages[c.cause] {
				t.Fatalf("resources/query: HTTP %d; want 503 naming the cause. body=%s", rr.Code, rr.Body.String())
			}

			if after := testutil.ToFloat64(counter); after != before+3 {
				t.Fatalf("the unavailable counter for %s moved %v -> %v; want +3, one per refused entry point", c.cause, before, after)
			}
		})
	}
}

// TestMCPRequestSeamWritesEngineSubjectTypeAndBundleOnTheAuditRow reads a clean
// check-input allow's canonical row, for a published document and for a client
// credential under the implicit baseline.
func TestMCPRequestSeamWritesEngineSubjectTypeAndBundleOnTheAuditRow(t *testing.T) {
	w := mrsSetup(t)
	for _, tc := range []struct {
		name        string
		docs        activeDocumentSource
		token       string
		subjectType string
	}{
		{"a published document, a verified user", w.docs, mrsToken(t), string(sharedidentity.SubjectUser)},
		{"the implicit baseline, a client credential", mrsDocuments{enfDocuments: w.docs, none: true}, "", string(sharedidentity.SubjectClient)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w.mrsWire(t, tc.docs)
			mock := withMockUsageDB(t)
			mock.MatchExpectationsInOrder(false)
			mock.ExpectExec("INSERT INTO audit_logs").WithArgs(mrsPostureArgs(AuditVerdictAllowed, tc.subjectType)...).WillReturnResult(sqlmock.NewResult(0, 1))
			if code, raw, _ := mrqCheckInput(t, tc.token, mrsBenign, ""); code != http.StatusOK {
				t.Fatalf("HTTP %d: %s", code, raw)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatalf("the audit row did not record engine=anchored subject_type=%s with a policy bundle: %v", tc.subjectType, err)
			}
		})
	}
}

// mrqRedactWorld records the organization's pii=redact posture and returns a
// shipped PII row that posture reaches, with a value its detector (and any
// checksum validator behind it) matches. The posture is what makes the request
// pass compose a redaction of the statement at all: the corpus binds this
// pass's PII controls as advisory requirements (warn, log), and an
// organization's recorded category action folds over them (#4095).
func mrqRedactWorld(t *testing.T, org string) (row, probe string) {
	t.Helper()
	reader := &fakeOverrideReader{data: map[string]map[string]DetectionAction{}}
	installTestOverrideCache(t, reader, time.Minute)
	enfRecordOverride(reader, org, DetectionCategoryPII, DetectionActionRedact)
	for _, c := range enfScopeControls(t, mcpRequestSeamScope) {
		if c.row.Tier != "system" || !c.row.Enabled || c.policy.Authority != contract.AuthorityRequirement ||
			sharedpolicy.OrgOverrideCategoryFor(sharedpolicy.PolicyCategory(c.row.Category)) != DetectionCategoryPII {
			continue
		}
		validator := sharedpolicy.ValidatorFor(c.row.PolicyID, sharedpolicy.PolicyCategory(c.row.Category))
		for _, candidate := range mrsRedactCandidates {
			if validator == nil {
				return c.row.PolicyID, candidate
			}
			if ok, _ := validator(candidate, mrsRedactContent(candidate)); ok {
				return c.row.PolicyID, candidate
			}
		}
	}
	t.Fatal("the mcp:request restriction keeps no enabled system PII requirement a recorded pii override reaches with a value that fires it; the fixture cannot choose a probe")
	return "", ""
}

// TestARequestRedactionIsDischargedOnlyWhereTheWireHandsTheStatementBack: under
// the organization's pii=redact posture a permit composes a redaction of the
// statement (mrqRedactWorld), which is discharged by check-input
// and check_policy, which hand the caller the statement to forward, masked by
// exactly what the detector matched. A connector route runs the statement
// itself, so it cannot discharge the redaction and refuses the request
// unsupported_obligation (ADR-065 invariant 8).
func TestARequestRedactionIsDischargedOnlyWhereTheWireHandsTheStatementBack(t *testing.T) {
	w := mrsSetup(t)
	row, probe := mrqRedactWorld(t, w.org)
	enfInstallDetectors(t, map[string]string{row: regexp.QuoteMeta(probe)}, nil)
	w.mrsWire(t, w.docs)
	statement := mrsRedactContent(probe)

	t.Run("check-input hands back the statement masked", func(t *testing.T) {
		code, raw, r := mrqCheckInput(t, mrsToken(t), statement, "")
		if code != http.StatusOK || !r.Allowed || !r.Redacted || strings.Contains(r.RedactedStatement, probe) || !strings.Contains(r.RedactedStatement, "order note:") {
			t.Fatalf("got HTTP %d allowed=%v redacted=%v statement %q; want 200 with the probe masked and the rest kept. body=%s", code, r.Allowed, r.Redacted, r.RedactedStatement, raw)
		}
	})

	t.Run("check_policy hands back the statement masked", func(t *testing.T) {
		got, err := mrqCheckPolicy(t, w.org, mrqSession(t, w.org, enfUser), statement)
		if err != nil {
			t.Fatal(err)
		}
		masked, _ := got["redacted_statement"].(string)
		if got["allowed"] != true || got["requires_redaction"] != true || masked == "" || strings.Contains(masked, probe) {
			t.Fatalf("check_policy got %v; want an allow requiring redaction with the probe masked", got)
		}
	})

	t.Run("a connector route cannot discharge it, so it refuses", func(t *testing.T) {
		registerExecConnector(t, &mockConnector{queryResult: &base.QueryResult{Rows: []map[string]interface{}{{"note": mrsBenign}}, RowCount: 1}})
		before := mrqDenyCounter(string(contract.ReasonUnsupportedObligation))
		rr := mrsPost("/mcp/resources/query", MCPQueryRequest{Connector: "test-db", Statement: statement, UserToken: mrsToken(t)}, mcpQueryHandler)
		errText, _ := mrqRefusal(t, rr)["error"].(string)
		if rr.Code != http.StatusForbidden || !strings.HasPrefix(errText, "Request blocked: "+string(contract.ReasonUnsupportedObligation)) {
			t.Fatalf("HTTP %d error %q; want 403 unsupported_obligation. body=%s", rr.Code, errText, rr.Body.String())
		}
		if after := mrqDenyCounter(string(contract.ReasonUnsupportedObligation)); after != before+1 {
			t.Fatalf("the mcp:request unsupported_obligation counter moved %v -> %v; want +1", before, after)
		}
	})
}

// TestARedactionThePassCannotPerformFailsClosed: after the engine permitted a
// statement with a redaction of it, a redaction the pass cannot attempt fails
// the request closed as an OUTAGE naming its cause (no engine: the enforcer not
// wired; rows it cannot load: the evaluation), and one that masks nothing in
// the statement is REFUSED unsupported_obligation (#4264). Neither forwards the
// statement unmasked (ADR-065 invariant 8). No handler can swap the engine
// between its own detector pass and its projection, so the two halves are
// driven directly, with the masking control first.
func TestARedactionThePassCannotPerformFailsClosed(t *testing.T) {
	w := mrsSetup(t)
	row, probe := mrqRedactWorld(t, w.org)
	enfInstallDetectors(t, map[string]string{row: regexp.QuoteMeta(probe)}, nil)
	w.mrsWire(t, w.docs)
	statement := mrsRedactContent(probe)

	decide := func(t *testing.T) (context.Context, requestPassEnforcement, sharedpolicy.EvalOptions, *sharedpolicy.Observation) {
		t.Helper()
		ctx := withMCPRequestSeam(context.WithValue(context.Background(), ContextKeyOrgID, w.org))
		outcome := evaluateInputPolicies(ctx, utrTestTenant, w.org, "1", "postgres", "", statement, nil, ResolveMCPDetectionConfig(ctx, w.org))
		observation := observationOf(outcome.StaticResult)
		enforced := enforceMCPRequest(ctx, requestPassInput{
			orgID: w.org, decisionID: "mrq-redactor", query: statement, observation: observation,
			subject: sessionSubject(mrqSession(t, w.org, "")),
		}, pepHandshakeResolution{})
		if enforced.verdict != VerdictAllow {
			t.Fatalf("the engine did not permit the statement (verdict %q, reasons %v); the fixture cannot reach the redactor", enforced.verdict, enforced.reasons)
		}
		return ctx, enforced, outcome.Options, observation
	}

	t.Run("CONTROL: the installed engine masks the statement", func(t *testing.T) {
		ctx, enforced, opts, observation := decide(t)
		v := projectMCPStatement(ctx, w.org, enforced, pepHandshakeResolution{}, statement, statement, opts, observation)
		if !v.allowed || !v.redacted || strings.Contains(v.statement, probe) {
			t.Fatalf("got %+v; want an allow with the probe masked", v)
		}
	})

	for _, breaker := range []struct {
		name    string
		arrange func(t *testing.T)
		// cause is the outage the request fails closed under, 503; "" is a
		// refusal of the obligation, 403 unsupported_obligation (#4264).
		cause string
	}{
		{"the engine cannot load the rows the decision names", installLoadErroringEngine, enforceCauseEvaluation},
		// The control the split must keep: no engine to apply the redaction is
		// the enforcer not wired, an outage, never the caller's refusal.
		{"no policy engine is installed", func(t *testing.T) {
			prev := sharedpolicy.GetGlobalEngine()
			sharedpolicy.SetGlobalEngine(nil)
			t.Cleanup(func() { sharedpolicy.SetGlobalEngine(prev) })
		}, enforceCauseNotWired},
		// The rows reload between the pass's detection and its redaction, and
		// the row the decision names no longer matches the statement: the
		// redactor runs and masks nothing. The pass cannot tell that from a
		// redaction of content outside the statement, and refuses.
		{"the redactor masks nothing the decision names", func(t *testing.T) {
			enfInstallDetectors(t, map[string]string{row: regexp.QuoteMeta("a marker the statement does not contain")}, nil)
		}, ""},
	} {
		t.Run(breaker.name, func(t *testing.T) {
			ctx, enforced, opts, observation := decide(t)
			breaker.arrange(t)
			v := projectMCPStatement(ctx, w.org, enforced, pepHandshakeResolution{}, statement, statement, opts, observation)
			if v.allowed || v.statement != "" {
				t.Fatalf("got %+v; want nothing forwarded", v)
			}
			if breaker.cause != "" {
				if v.unavailable != breaker.cause || v.reasonCode != "" || v.blockReason != "" {
					t.Fatalf("got %+v; want the request failed closed under %s, an outage and not a refusal", v, breaker.cause)
				}
				return
			}
			if v.unavailable != "" || v.reasonCode != string(contract.ReasonUnsupportedObligation) {
				t.Fatalf("got %+v; want a refusal with reason %s, not an outage", v, contract.ReasonUnsupportedObligation)
			}
			assertRedactionRefusalNamesTheObligation(t, v.blockReason, row, "it masks nothing in the statement, the only content this wire hands back")
			// The request carried no parameters, so the refusal must name none:
			// neither an empty list nor a cause the pass cannot know.
			if strings.Contains(v.blockReason, "parameters") {
				t.Fatalf("the refusal names parameters where the request carried none: %q", v.blockReason)
			}
		})
	}
}

// assertRedactionRefusalNamesTheObligation holds a refusal of a redaction this
// wire cannot discharge to its reason code, the obligation it names - its type,
// its target and the organization override on row that attached it - and why.
func assertRedactionRefusalNamesTheObligation(t *testing.T, reason, row, why string) {
	t.Helper()
	want := string(contract.ReasonUnsupportedObligation) + ": the mandatory field_redact obligation on \"args.query\" attached by organization_override:"
	if !strings.HasPrefix(reason, want) || !strings.Contains(reason, strings.ReplaceAll(row, "_", "__")) ||
		!strings.Contains(reason, "cannot be discharged on "+mcpRequestPassName) || !strings.Contains(reason, why) {
		t.Fatalf("block_reason %q; want it to start %q, name %s's override, the pass and %q", reason, want, row, why)
	}
}

// TestTheParameterProbeNeverTurnsACertainRefusalIntoAnOutage drives
// redactionOutcome directly (#4264, R3 round 3). The probe loads the policies
// per call, so it can fail on its own; when the statement masked nothing the
// refusal is already certain and the probe's failure must not answer an outage
// instead, which is the 5xx a fail-open client runs the tool on.
func TestTheParameterProbeNeverTurnsACertainRefusalIntoAnOutage(t *testing.T) {
	dec := &contract.Decision{Obligations: []contract.Obligation{{
		Type: contract.ObFieldRedact, Target: legacycompile.DefaultContentTarget, Mandatory: true, SourcePolicy: "organization_override:corpus:static_policies:probe:log",
	}}}
	probeFailed := errors.New("the decision names requirement sys_probe, which the activated engine does not hold")
	for _, c := range []struct {
		name        string
		didMask     bool
		params      []string
		paramsErr   error
		wantRefusal string
		wantErr     bool
	}{
		{"nothing masked, the probe found nothing: refused, naming no parameter", false, nil, nil, "it masks nothing in the statement, the only content this wire hands back", false},
		{"nothing masked, a parameter would be masked: refused, naming it", false, []string{"command"}, nil, "it masks the request's parameters (command)", false},
		{"nothing masked AND the probe FAILED: still refused, never an outage", false, nil, probeFailed, "it masks nothing in the statement, the only content this wire hands back", false},
		// The probe returns no parameters WITH its error, so this row cannot
		// arise in production; it pins that the bare branch reads paramsErr
		// rather than the emptiness of params (R3 round 4).
		{"nothing masked, a probe that FAILED after finding one: refused, naming none", false, []string{"command"}, probeFailed, "it masks nothing in the statement, the only content this wire hands back", false},
		{"the statement masked, a parameter would be masked: refused", true, []string{"card"}, nil, "it also masks the request's parameters (card)", false},
		{"the statement masked and the probe FAILED: an outage, which is what it is", true, nil, probeFailed, "", true},
		{"the statement masked, nothing else: a permit", true, nil, nil, "", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			refusal, err := redactionOutcome(dec, c.didMask, c.params, c.paramsErr)
			if c.wantErr {
				if err == nil || refusal != "" {
					t.Fatalf("got refusal %q err %v; want the probe's error reported as an outage", refusal, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("got err %v; want none", err)
			}
			if c.wantRefusal == "" {
				if refusal != "" {
					t.Fatalf("got refusal %q; want a permit", refusal)
				}
				return
			}
			// The reason code alone survives an empty subject, so hold the
			// refusal to the obligation it must name, as every other case does.
			assertRedactionRefusalNamesTheObligation(t, refusal, "probe", c.wantRefusal)
			// The clause naming parameters appears EXACTLY when the probe
			// established one to name: never after a probe that failed, and
			// never when it found none.
			wantClause := c.paramsErr == nil && len(c.params) > 0
			if got := strings.Contains(refusal, "parameters ("); got != wantClause {
				t.Fatalf("the refusal %q names parameters (%v); want %v", refusal, got, wantClause)
			}
		})
	}
}

// TestARedactionOutsideTheStatementIsRefusedOnCheckInput (#4264): under the
// organization's pii=redact posture, with no handshake, a check-input whose PII
// sits in the parameters composes a redaction this wire cannot discharge, since
// it hands back only the statement. The ADK plugin sends a tool's name as the
// statement and its arguments as the parameters. The request is REFUSED 403
// unsupported_obligation naming the obligation; it was answered 503, an outage,
// and every client that fails open on a 5xx ran the tool on it. A statement and
// a parameter that BOTH carry PII are refused too: they were answered 200 with
// the statement masked and the parameter handed back unmasked. The legitimate
// caller in the same state - the PII in the statement alone, or none - is
// answered 200.
func TestARedactionOutsideTheStatementIsRefusedOnCheckInput(t *testing.T) {
	w := mrsSetup(t)
	row, probe := mrqRedactWorld(t, w.org)
	// The probe's detector also matches the probe's digits without their
	// spaces: how the scan reads the same number sent as a JSON number
	// (sharedpolicy.ParameterScanText).
	digits := strings.ReplaceAll(probe, " ", "")
	probeNumber, err := strconv.ParseFloat(digits, 64)
	if err != nil || strconv.FormatFloat(probeNumber, 'f', -1, 64) != digits {
		t.Fatalf("the fixture's probe %q is not a number a JSON parameter carries exactly; the numeric case needs one", probe)
	}
	enfInstallDetectors(t, map[string]string{row: strings.ReplaceAll(regexp.QuoteMeta(probe), " ", " ?")}, nil)
	w.mrsWire(t, w.docs)

	post := func(t *testing.T, statement string, params map[string]interface{}) (int, map[string]interface{}, string) {
		t.Helper()
		body, _ := json.Marshal(MCPCheckInputRequest{ConnectorType: "adk-tool", Statement: statement, Parameters: params, Operation: "execute"})
		req := httptest.NewRequest("POST", "/api/v1/mcp/check-input", bytes.NewBuffer(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", utrBasicAuthHeader())
		rr := httptest.NewRecorder()
		mcpCheckInputHandler(rr, req)
		var out map[string]interface{}
		if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
			t.Fatalf("the check-input body is not a JSON object: %v\n%s", err, rr.Body.String())
		}
		return rr.Code, out, rr.Body.String()
	}
	outage := func(cause string) float64 {
		return testutil.ToFloat64(anchoredEnforceDecisions.WithLabelValues(mcpRequestSeamScope.String(), decisionEngineAnchored, "unavailable", cause))
	}

	for _, c := range []struct {
		name      string
		statement string
		params    map[string]interface{}
		why       string
	}{
		{"the census shape: the tool's name as the statement, the PII in a parameter",
			"mail", map[string]interface{}{"command": "mail -s statement " + probe}, "masks nothing in the statement, the only content this wire hands back; it masks the request's parameters (command)"},
		{"the PII in a nested object parameter only",
			"mail", map[string]interface{}{"options": map[string]interface{}{"to": probe}}, "masks nothing in the statement, the only content this wire hands back; it masks the request's parameters (options)"},
		{"the PII in the statement AND a parameter",
			mrsRedactContent(probe), map[string]interface{}{"command": "mail -s statement " + probe, "force": true}, "the request's parameters (command)"},
		// The scan reads an array as its JSON encoding, and the check reads
		// the same text.
		{"the PII in the statement AND an array parameter",
			mrsRedactContent(probe), map[string]interface{}{"args": []interface{}{"-s", probe}}, "the request's parameters (args)"},
		// The case a check reading only string leaves would hand back: the
		// scan reads a JSON number in decimal, so a card number sent as a
		// number composes the redaction and must be refused.
		{"the PII in the statement AND a numeric parameter",
			mrsRedactContent(probe), map[string]interface{}{"card": probeNumber}, "the request's parameters (card)"},
	} {
		t.Run("REFUSED: "+c.name, func(t *testing.T) {
			before, outagesBefore := mrqDenyCounter(string(contract.ReasonUnsupportedObligation)), outage(enforceCauseObligation)+outage(enforceCauseEvaluation)+outage(enforceCauseNotWired)
			// Replayed, the answer is the same: nothing in the request pass
			// remembers the first one.
			for attempt := 1; attempt <= 2; attempt++ {
				code, out, raw := post(t, c.statement, c.params)
				allowed, present := out["allowed"]
				if code != http.StatusForbidden || !present || allowed != false {
					t.Fatalf("attempt %d: HTTP %d allowed=%v (present %v); want 403 with allowed false. body=%s", attempt, code, allowed, present, raw)
				}
				reason, _ := out["block_reason"].(string)
				assertRedactionRefusalNamesTheObligation(t, reason, row, c.why)
				if out["engine"] != decisionEngineAnchored {
					t.Fatalf("attempt %d: engine %v; want %s. body=%s", attempt, out["engine"], decisionEngineAnchored, raw)
				}
				// Nothing is handed back to forward, and the refusal is a
				// check-input deny (allowed), not the outage envelope (blocked).
				if _, has := out["redacted_statement"]; has || strings.Contains(raw, probe) || strings.Contains(raw, digits) {
					t.Fatalf("attempt %d: the refusal handed content back: %s", attempt, raw)
				}
				if _, has := out["blocked"]; has {
					t.Fatalf("attempt %d: the refusal carries the outage envelope's blocked member: %s", attempt, raw)
				}
			}
			if after := mrqDenyCounter(string(contract.ReasonUnsupportedObligation)); after != before+2 {
				t.Fatalf("the mcp:request unsupported_obligation counter moved %v -> %v; want +2", before, after)
			}
			if outagesAfter := outage(enforceCauseObligation) + outage(enforceCauseEvaluation) + outage(enforceCauseNotWired); outagesAfter != outagesBefore {
				t.Fatalf("an outage was counted for a refusal: %v -> %v", outagesBefore, outagesAfter)
			}
		})
	}

	// The MCP server's check_policy tool reads parameters too and shares the
	// projection, so the same request is refused there with a deny result, not
	// an error result; its legitimate pair is allowed with the statement masked.
	t.Run("check_policy: the same refusal on the MCP server's tool, and its pair allowed", func(t *testing.T) {
		ctx := context.WithValue(context.Background(), ContextKeyOrgID, w.org)
		call := func(statement string, params map[string]interface{}) map[string]interface{} {
			t.Helper()
			resp, err := mcpToolCheckPolicy(ctx, mrqSession(t, w.org, ""), map[string]interface{}{
				"connector_type": "adk-tool", "statement": statement, "parameters": params,
			}, pepHandshakeResolution{})
			if err != nil {
				t.Fatalf("check_policy answered an error, not a verdict: %v", err)
			}
			return resp.(map[string]interface{})
		}
		refused := call("mail", map[string]interface{}{"command": "mail -s statement " + probe})
		reason, _ := refused["block_reason"].(string)
		if refused["allowed"] != false {
			t.Fatalf("check_policy got %v; want allowed false", refused)
		}
		assertRedactionRefusalNamesTheObligation(t, reason, row, "masks nothing in the statement, the only content this wire hands back; it masks the request's parameters (command)")
		if refused["engine"] != decisionEngineAnchored {
			t.Fatalf("check_policy's refusal carries engine %v; want %s, the pass's own stamp", refused["engine"], decisionEngineAnchored)
		}
		allowed := call(mrsRedactContent(probe), map[string]interface{}{"command": "ls -la /tmp"})
		stmt, _ := allowed["redacted_statement"].(string)
		if allowed["allowed"] != true || allowed["requires_redaction"] != true || stmt == "" || strings.Contains(stmt, probe) {
			t.Fatalf("check_policy's pair got %v; want allowed with the statement masked", allowed)
		}
	})

	// The scan evaluates each parameter's text on its own, so a pattern
	// anchored to a whole parameter matches there. The check redacts each
	// parameter on its own too; one that redacted them joined in one row would
	// find nothing for such a pattern and hand the parameter back.
	t.Run("REFUSED: a parameter a pattern anchored to its whole text matches", func(t *testing.T) {
		enfInstallDetectors(t, map[string]string{row: "^" + digits + "$|" + regexp.QuoteMeta(probe)}, nil)
		code, out, raw := post(t, mrsRedactContent(probe), map[string]interface{}{"card": digits})
		allowed, present := out["allowed"]
		if code != http.StatusForbidden || !present || allowed != false {
			t.Fatalf("HTTP %d allowed=%v (present %v); want 403 with allowed false. body=%s", code, allowed, present, raw)
		}
		reason, _ := out["block_reason"].(string)
		assertRedactionRefusalNamesTheObligation(t, reason, row, "the request's parameters (card)")
	})

	for _, c := range []struct {
		name      string
		statement string
		params    map[string]interface{}
		masked    bool
	}{
		{"the PII in the statement, the parameters absent", mrsRedactContent(probe), nil, true},
		{"the PII in the statement, the parameters present but empty", mrsRedactContent(probe), map[string]interface{}{}, true},
		{"the PII in the statement, a parameter present but an empty text", mrsRedactContent(probe), map[string]interface{}{"command": ""}, true},
		{"the PII in the statement, a clean and a boolean parameter", mrsRedactContent(probe), map[string]interface{}{"command": "ls -la /tmp", "force": true}, true},
		{"no PII anywhere, a clean parameter", "mail", map[string]interface{}{"command": "ls -la /tmp"}, false},
	} {
		t.Run("ALLOWED: "+c.name, func(t *testing.T) {
			code, out, raw := post(t, c.statement, c.params)
			if code != http.StatusOK || out["allowed"] != true {
				t.Fatalf("HTTP %d; want 200 allowed. body=%s", code, raw)
			}
			stmt, _ := out["redacted_statement"].(string)
			if c.masked && (out["redacted"] != true || stmt == "" || strings.Contains(stmt, probe)) {
				t.Fatalf("want the statement handed back masked. body=%s", raw)
			}
			if !c.masked && out["redacted"] == true {
				t.Fatalf("want nothing redacted. body=%s", raw)
			}
		})
	}
}

// TestTheChecksumValidatorActsAheadOfTheRequestPassOnlyUnderRedact: under the
// organization's pii=redact posture the Indonesia checksum validator masks the
// identifier before the engine decides, and is named in legacy_validators;
// under any other posture it modifies nothing and is not named (#4122).
func TestTheChecksumValidatorActsAheadOfTheRequestPassOnlyUnderRedact(t *testing.T) {
	w := mrsSetup(t)
	w.mrsWire(t, w.docs)
	statement := "Customer NIK is " + fixtureNIK

	t.Run("pii=redact: masked ahead of the pass, and named", func(t *testing.T) {
		pinMCPOverride(t, func(c *ModeDetectionConfig) { c.PIIAction = DetectionActionRedact })
		code, raw, r := mrqCheckInput(t, mrsToken(t), statement, "")
		want := []LegacyValidatorAction{{Validator: legacyValidatorIndonesia, Action: legacyActionMasked}}
		if code != http.StatusOK || !r.Redacted || strings.Contains(r.RedactedStatement, fixtureNIK) || !reflect.DeepEqual(r.LegacyValidators, want) {
			t.Fatalf("got HTTP %d redacted=%v statement %q legacy_validators %+v; want 200 masked naming %+v. body=%s", code, r.Redacted, r.RedactedStatement, r.LegacyValidators, want, raw)
		}
		got, err := mrqCheckPolicy(t, w.org, mrqSession(t, w.org, enfUser), statement)
		if masked, _ := got["redacted_statement"].(string); err != nil || got["allowed"] != true || masked == "" || strings.Contains(masked, fixtureNIK) {
			t.Fatalf("check_policy got %v (err %v); want an allow with the identifier masked", got, err)
		}
	})

	t.Run("pii=warn: nothing is modified and nothing is named", func(t *testing.T) {
		pinMCPOverride(t, func(c *ModeDetectionConfig) { c.PIIAction = DetectionActionWarn })
		code, raw, r := mrqCheckInput(t, mrsToken(t), statement, "")
		if code != http.StatusOK || r.Redacted || r.RedactedStatement != "" || len(r.LegacyValidators) != 0 {
			t.Fatalf("got HTTP %d redacted=%v statement %q legacy_validators %+v; want a 200 that modifies and names nothing. body=%s", code, r.Redacted, r.RedactedStatement, r.LegacyValidators, raw)
		}
	})
}

// An installed policy pack (PRD v11 §1.9) that binds on the MCP request pass is
// named by digest on every surface the pass answers - check-input, check_policy
// and a connector route's refusal - and on the audit row, as /api/v1/decide
// names it (#4196). With no pack installed none of them names one. The query
// and execute SUCCESS bodies are the response pass's wire and are not the
// request pass's to change.
func TestTheRequestPassNamesThePolicyPacksThatBound(t *testing.T) {
	w := mrsSetup(t)
	pack := decidePackUnderTest(t)
	detectors, err := sharedpolicy.CompileInstalledDetectors([]*policypack.Pack{pack})
	if err != nil {
		t.Fatal(err)
	}
	enfInstallDetectorsWithPacks(t, nil, nil, detectors)
	w.mrsWire(t, w.docs)

	// THE CONTROL: the enforcer mrsWire installed carries no pack.
	code, raw, control := mrqCheckInput(t, mrsToken(t), mrsBenign, "")
	if code != http.StatusOK || control.PolicyPacks != nil || strings.Contains(raw, "policy_packs") || control.PolicyBundle == "" {
		t.Fatalf("without a pack installed: HTTP %d policy_packs %v bundle %q; want a 200 naming none. body=%s", code, control.PolicyPacks, control.PolicyBundle, raw)
	}

	// The pack installed on the SAME enforcer that decided the control. It
	// memoized that scope's activation, and the memo is keyed by the installed
	// pack set as well as the document and the overrides, so the next request
	// is decided under a new activation that composes the pack - never the
	// memoized one without it.
	installed, err := activation.InstallPacks(enfSnapshot(t), []*policypack.Pack{pack})
	if err != nil {
		t.Fatal(err)
	}
	anchoredEnforcerInstance.Load().Packs = installed
	ref := installed[0].Ref()

	t.Run("check-input names the pack it was decided under, on the wire and the audit row", func(t *testing.T) {
		mock := withMockUsageDB(t)
		mock.MatchExpectationsInOrder(false)
		args := decideAuditInsertArgs(AuditVerdictAllowed, policyPacksMatcher{refs: []string{ref}})
		args[15] = PlaneMCP
		mock.ExpectExec("INSERT INTO audit_logs").WithArgs(args...).WillReturnResult(sqlmock.NewResult(0, 1))
		code, raw, r := mrqCheckInput(t, mrsToken(t), mrsBenign, "")
		if code != http.StatusOK || !slices.Equal(r.PolicyPacks, []string{ref}) {
			t.Fatalf("HTTP %d policy_packs %v; want 200 naming [%s]. body=%s", code, r.PolicyPacks, ref, raw)
		}
		// The evidence the pack composed on mcp:request, not only that a field
		// was filled: the bundle it was decided under is another digest.
		if r.PolicyBundle == "" || r.PolicyBundle == control.PolicyBundle {
			t.Fatalf("policy_bundle %q with the pack installed, %q without; the pack did not compose into the bundle", r.PolicyBundle, control.PolicyBundle)
		}
		if err := mock.ExpectationsWereMet(); err != nil {
			t.Fatalf("the audit row does not name the pack: %v", err)
		}
	})

	t.Run("check_policy names the pack", func(t *testing.T) {
		got, err := mrqCheckPolicy(t, w.org, mrqSession(t, w.org, enfUser), mrsBenign)
		if err != nil {
			t.Fatal(err)
		}
		if packs, _ := got["policy_packs"].([]string); got["allowed"] != true || !slices.Equal(packs, []string{ref}) {
			t.Fatalf("got %v; want an allow naming [%s]", got, ref)
		}
	})

	t.Run("a connector route's refusal names the pack", func(t *testing.T) {
		registerExecConnector(t, &mockConnector{queryResult: &base.QueryResult{Rows: []map[string]interface{}{{"note": "unreached"}}, RowCount: 1}})
		rr := mrsPost("/mcp/resources/query", MCPQueryRequest{Connector: "test-db", Statement: "SELECT note FROM orders", UserToken: mrsTokenFor(t, enfBob)}, mcpQueryHandler)
		body := mrqRefusal(t, rr)
		if packs, _ := body["policy_packs"].([]interface{}); rr.Code != http.StatusForbidden || len(packs) != 1 || packs[0] != ref {
			t.Fatalf("HTTP %d body %v; want a 403 refusal naming [%s]", rr.Code, body, ref)
		}
	})
}

// mrqCounter reads the mcp:request counter for one verdict and reason.
func mrqCounter(verdict, reason string) float64 {
	return testutil.ToFloat64(anchoredEnforceDecisions.WithLabelValues(mcpRequestSeamScope.String(), decisionEngineAnchored, verdict, reason))
}

// TestTheRequestPassCountsTheVerdictAtEveryEntryPoint pins the counts the
// tests above leave unread: an allow at each of the four entry points, and
// check_policy's refusal. runtime-e2e 3564 reads the same series live, so an
// entry point that answered without counting would show the pass allowing
// nothing it allowed.
func TestTheRequestPassCountsTheVerdictAtEveryEntryPoint(t *testing.T) {
	w := mrsSetup(t)
	w.mrsWire(t, w.docs)
	permitted := string(contract.ReasonPermitted)
	counted := func(t *testing.T, verdict, reason string, answer func()) {
		t.Helper()
		before := mrqCounter(verdict, reason)
		answer()
		if after := mrqCounter(verdict, reason); after != before+1 {
			t.Fatalf("the mcp:request %s/%s counter moved %v -> %v; want +1", verdict, reason, before, after)
		}
	}

	t.Run("check-input counts its allow", func(t *testing.T) {
		counted(t, VerdictAllow, permitted, func() {
			if code, raw, _ := mrqCheckInput(t, mrsToken(t), mrsBenign, ""); code != http.StatusOK {
				t.Fatalf("alice: HTTP %d; want 200. body=%s", code, raw)
			}
		})
	})

	t.Run("check_policy counts its allow and its refusal", func(t *testing.T) {
		counted(t, VerdictAllow, permitted, func() {
			if got, err := mrqCheckPolicy(t, w.org, mrqSession(t, w.org, enfUser), mrsBenign); err != nil || got["allowed"] != true {
				t.Fatalf("alice's session got %v (err %v); want an allow", got, err)
			}
		})
		counted(t, VerdictDeny, string(contract.ReasonExplicitConstraint), func() {
			if got, err := mrqCheckPolicy(t, w.org, mrqSession(t, w.org, enfBob), mrsBenign); err != nil || got["allowed"] != false {
				t.Fatalf("bob's session got %v (err %v); want an explicit_constraint refusal", got, err)
			}
		})
	})

	for _, route := range []struct {
		name string
		conn *mockConnector
		post func(token string) *httptest.ResponseRecorder
	}{
		{"resources/query", &mockConnector{queryResult: &base.QueryResult{Rows: []map[string]interface{}{{"note": "counted"}}, RowCount: 1}},
			func(token string) *httptest.ResponseRecorder {
				return mrsPost("/mcp/resources/query", MCPQueryRequest{Connector: "test-db", Statement: "SELECT note FROM orders", UserToken: token}, mcpQueryHandler)
			}},
		{"tools/execute", &mockConnector{executeResult: &base.CommandResult{RowsAffected: 1, Message: "counted"}},
			func(token string) *httptest.ResponseRecorder {
				return mrsPost("/mcp/tools/execute", MCPExecuteRequest{Connector: "test-db", Action: "UPDATE", Statement: "UPDATE orders SET x=1", UserToken: token}, mcpExecuteHandler)
			}},
	} {
		t.Run(route.name+" counts its allow", func(t *testing.T) {
			registerExecConnector(t, route.conn)
			counted(t, VerdictAllow, permitted, func() {
				if rr := route.post(mrsToken(t)); rr.Code != http.StatusOK {
					t.Fatalf("alice: HTTP %d; want 200. body=%s", rr.Code, rr.Body.String())
				}
			})
		})
	}
}
