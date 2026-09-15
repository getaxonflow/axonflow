// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"bytes"
	"context"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/golang-jwt/jwt/v5"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"axonflow/platform/connectors/base"
	"axonflow/platform/decision/authoringcatalog"
	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/legacycompile"
	"axonflow/platform/decision/pdp"
	"axonflow/platform/decision/registry"
	sharedidentity "axonflow/platform/shared/identity"
	sharedpolicy "axonflow/platform/shared/policy"
)

// THE MCP RESPONSE PASS'S ENFORCING SEAM, THROUGH THE REAL HANDLERS (#3564).
//
// Every assertion reads what a caller or an auditor reads - the encoded body,
// the audit row, a counter - never the seam's producing functions. The pieces
// are the production ones: Basic auth over a minted licence, the identity
// plane's admission of the subject, activation of the mcp:response restriction
// and either a document published through the real authoring API or the
// implicit baseline, and the shared engine's real response pass over the
// census's system rows. Only storage and the connector are in memory.

const (
	mrsBenign         = "the order shipped on tuesday"
	mrsInjectionProbe = "w2a-injection-probe-token"
	// mrsOrg is the organization this fixture's licence authenticates to.
	mrsOrg = "org-w2a-mcp"
)

// mrsDocuments serves the published document to every organization, or reports
// none - the implicit baseline - or fails.
type mrsDocuments struct {
	*enfDocuments
	none, broken bool
}

func (d mrsDocuments) ActiveTip(ctx context.Context, orgID string) (string, int64, error) {
	switch {
	case d.broken:
		return "", 0, errors.New("the typed-authoring tables are unreachable")
	case d.none:
		return "", 0, nil
	}
	return d.enfDocuments.ActiveTip(ctx, orgID)
}

// mrsRedactCandidates are realistic values a shipped PII detector's validator
// can accept. The fixture does not assume which detector binds on the response
// pass: it asks each redaction control's own validator.
var mrsRedactCandidates = []string{
	"alice.w2a@example.com", "123-45-6789", "4111 1111 1111 1111", "192.168.10.20", "+1 415 555 0100",
	"GB82 WEST 1234 5698 7654 32", "S1234567D",
}

// mrsRedactContent is the message a redaction probe is sent in.
func mrsRedactContent(probe string) string { return "order note: " + probe + " ends" }

// redactsResponseContent is redactsContent for the response pass's targets;
// the probe chooser below is its only caller.
func redactsResponseContent(p pdp.Policy) bool {
	return redactsContent(p, dischargesAsResponseContent)
}

// mrsResponseProbes chooses, from the mcp:response RESTRICTION rather than by
// name, two shipped controls the pass redacts:
//
//   - a PII redaction control, together with a value ITS validator accepts in
//     the exact content the test sends, because every shipped PII row carries
//     one and the shared engine applies it as the anchored engine's detector
//     input;
//   - a control the corpus SPLIT by scope whose response variant redacts and
//     whose row carries no validator, so a probe token fires it; the fixture
//     stores its row's response-phase action as the corpus binds it, which for
//     these controls is core/128's redact (the real-Postgres oracle in
//     TestSystemPolicyCount_MigrationsAreSingleSourceOfTruth holds that equality).
//
// The restriction binds no constraint on this pass - the prompt-injection
// controls the request pass blocks, this pass strips (#4016) - so the fixture
// chooses none.
func mrsResponseProbes(t *testing.T) (redact, redactProbe, stripped string) {
	t.Helper()
	for _, c := range enfScopeControls(t, mcpResponseSeamScope) {
		validator := sharedpolicy.ValidatorFor(c.row.PolicyID, sharedpolicy.PolicyCategory(c.row.Category))
		pii := strings.HasPrefix(c.row.Category, "pii-")
		if !redactsResponseContent(c.policy) {
			continue
		}
		if _, action, _ := legacycompile.CorpusControlOf(c.policy.ID); stripped == "" && action != "" && !pii && validator == nil {
			stripped = c.row.PolicyID
		}
		if redact != "" || !pii {
			continue
		}
		for _, candidate := range mrsRedactCandidates {
			if validator == nil {
				redact, redactProbe = c.row.PolicyID, candidate
				break
			}
			if ok, _ := validator(candidate, mrsRedactContent(candidate)); ok {
				redact, redactProbe = c.row.PolicyID, candidate
				break
			}
		}
	}
	if redact == "" || stripped == "" {
		t.Fatalf("the mcp:response restriction yields no PII redaction control a candidate value satisfies (%q) or no validator-free split control it redacts (%q); the fixture cannot choose probes", redact, stripped)
	}
	return redact, redactProbe, stripped
}

type mrsWorld struct {
	org  string
	docs *enfDocuments
	// redactProbe is the value the chosen redaction control's detector matches.
	redactProbe string
	// stripped is the census row of the split control mrsInjectionProbe matches.
	stripped string
}

// mrsSetup wires the enterprise REST harness, the census rows with the two
// probes - the split control's row storing the response-phase action the corpus
// binds for it - and a document constraining bob's tool.call. The enforcer is
// installed by mrsWire.
func mrsSetup(t *testing.T) *mrsWorld {
	t.Helper()
	setupMCPUserTokenRejectedTest(t)
	// This suite's organization is mrsOrg, not the harness's, so its licence
	// names that one; the keypair override and the whitelist restore are the
	// harness's own.
	knownClients[utrTestClientID].LicenseKey = utrGenTestLicenseKey("Enterprise", mrsOrg)
	origExfil := sharedpolicy.GetGlobalExfiltrationChecker()
	sharedpolicy.ResetGlobalExfiltrationChecker()
	t.Cleanup(func() { sharedpolicy.SetGlobalExfiltrationChecker(origExfil) })
	redact, redactProbe, stripped := mrsResponseProbes(t)
	enfInstallDetectors(t, map[string]string{redact: regexp.QuoteMeta(redactProbe), stripped: mrsInjectionProbe}, nil)

	probe := httptest.NewRequest("POST", "/api/v1/mcp/check-output", nil)
	probe.Header.Set("Authorization", utrBasicAuthHeader())
	auth, authErr := Authenticate(probe, &AuthHints{})
	if authErr != nil || auth.OrgID == "" {
		t.Fatalf("the harness credential does not authenticate to an organization: %v", authErr)
	}
	return &mrsWorld{
		org: auth.OrgID, redactProbe: redactProbe, stripped: stripped,
		docs: enfPublishConstraints(t, enfSnapshot(t), enfConstraint{"ceiling.block_bob", enfBob, []string{authoringcatalog.ActionToolCall}}),
	}
}

// mrsWire installs the anchored enforcer over docs, restored at cleanup.
func (w *mrsWorld) mrsWire(t *testing.T, docs activeDocumentSource) {
	t.Helper()
	enfInstallSeam(t, docs)
}

// mrsToken mints enfUser's user token (mrsTokenFor).
func mrsToken(t *testing.T) string {
	t.Helper()
	return mrsTokenFor(t, enfUser)
}

// mrsTokenFor mints email's user token in the portal's production claim set,
// for the harness tenant.
func mrsTokenFor(t *testing.T, email string) string {
	t.Helper()
	now := time.Now()
	tok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iss": sharedidentity.UserTokenIssuer, "sub": email, "email": email, "role": "user",
		"tenant_id": utrTestTenant, "org_id": mrsOrg, "jti": "jti-w2a-" + email,
		"iat": jwt.NewNumericDate(now.Add(-time.Minute)), "nbf": jwt.NewNumericDate(now.Add(-time.Minute)),
		"exp": jwt.NewNumericDate(now.Add(time.Hour)),
	}).SignedString(jwtSecret)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

type mrsResponse struct {
	code int
	raw  string
	body MCPCheckOutputResponse
}

func mrsCheckOutput(t *testing.T, userToken, message string) mrsResponse {
	t.Helper()
	return mrsCheckOutputWith(t, userToken, message, "")
}

// mrsCheckOutputWith is mrsCheckOutput from an enforcement point presenting
// handshake as its PEP capability declaration ("" presents none).
func mrsCheckOutputWith(t *testing.T, userToken, message, handshake string) mrsResponse {
	t.Helper()
	body, _ := json.Marshal(MCPCheckOutputRequest{ConnectorType: "postgres", Message: message, UserToken: userToken})
	req := httptest.NewRequest("POST", "/api/v1/mcp/check-output", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", utrBasicAuthHeader())
	if handshake != "" {
		req.Header.Set(contract.PEPHandshakeHeader, handshake)
	}
	rr := httptest.NewRecorder()
	mcpCheckOutputHandler(rr, req)
	out := mrsResponse{code: rr.Code, raw: rr.Body.String()}
	if err := json.Unmarshal(rr.Body.Bytes(), &out.body); err != nil {
		t.Fatalf("the check-output body is not a JSON object: %v\n%s", err, rr.Body.String())
	}
	if strings.Contains(out.raw, `"mode"`) {
		t.Fatalf("the check-output body carries a mode member; v11 has no decision mode. body=%s", out.raw)
	}
	return out
}

func TestMCPResponseEnforcingSeam(t *testing.T) {
	w := mrsSetup(t)
	w.mrsWire(t, w.docs)
	token := mrsToken(t)

	t.Run("a verified user's clean response is ALLOWED by the anchored engine, and the body says so", func(t *testing.T) {
		r := mrsCheckOutput(t, token, mrsBenign)
		if r.code != http.StatusOK || !r.body.Allowed || r.body.RedactedData != nil {
			t.Fatalf("got HTTP %d allowed=%v redacted=%v; want a clean 200 allow. body=%s", r.code, r.body.Allowed, r.body.RedactedData, r.raw)
		}
		if r.body.Engine != decisionEngineAnchored || r.body.SubjectType != string(sharedidentity.SubjectUser) || r.body.PolicyBundle == "" {
			t.Fatalf("engine=%q subject_type=%q policy_bundle=%q; want anchored/User with the bundle named. body=%s", r.body.Engine, r.body.SubjectType, r.body.PolicyBundle, r.raw)
		}
	})

	t.Run("content a shipped redaction control detects is RELEASED MASKED by the anchored engine's own redaction", func(t *testing.T) {
		r := mrsCheckOutput(t, token, "order note: "+w.redactProbe+" ends")
		if r.code != http.StatusOK || !r.body.Allowed || r.body.Engine != decisionEngineAnchored {
			t.Fatalf("got HTTP %d allowed=%v engine=%q; want 200 anchored allow. body=%s", r.code, r.body.Allowed, r.body.Engine, r.raw)
		}
		masked, ok := r.body.RedactedData.(string)
		if !ok || strings.Contains(masked, w.redactProbe) || !strings.Contains(masked, "order note:") {
			t.Fatalf("redacted_data %v: the probe span must be masked and the rest of the content released. body=%s", r.body.RedactedData, r.raw)
		}
	})

	// PRD v11 §1.6: a caller with no user identity is evaluated for its client
	// credential, recorded as a Client. The document constrains bob, not the
	// credential, so the response is released.
	t.Run("a credential-only caller is evaluated as a Client, whom the document's constraint does not name", func(t *testing.T) {
		r := mrsCheckOutput(t, "", mrsBenign)
		if r.code != http.StatusOK || !r.body.Allowed || r.body.SubjectType != string(sharedidentity.SubjectClient) {
			t.Fatalf("got HTTP %d allowed=%v subject_type %q; want a 200 release for a Client. body=%s", r.code, r.body.Allowed, r.body.SubjectType, r.raw)
		}
	})

	t.Run("a principal the document constrains is refused explicit_constraint, so the session's subject is load bearing", func(t *testing.T) {
		counter := anchoredEnforceDecisions.WithLabelValues(mcpResponseSeamScope.String(), decisionEngineAnchored, VerdictDeny, string(contract.ReasonExplicitConstraint))
		before := testutil.ToFloat64(counter)
		r := mrsCheckOutput(t, mrsTokenFor(t, enfBob), mrsBenign)
		if r.code != http.StatusForbidden || r.body.Engine != decisionEngineAnchored || !strings.HasPrefix(r.body.BlockReason, "Response blocked: "+string(contract.ReasonExplicitConstraint)) {
			t.Fatalf("got HTTP %d engine=%q block_reason=%q; want 403 anchored explicit_constraint for bob. body=%s", r.code, r.body.Engine, r.body.BlockReason, r.raw)
		}
		if after := testutil.ToFloat64(counter); after != before+1 {
			t.Fatalf("the mcp:response explicit_constraint counter moved %v -> %v; want +1", before, after)
		}
	})
}

// TestMCPResponseAConstrainedToolCallIsRefused: the response pass decides
// tool.call, so a document constraining the verified user's tool.call refuses
// the response.
func TestMCPResponseAConstrainedToolCallIsRefused(t *testing.T) {
	w := mrsSetup(t)
	w.mrsWire(t, enfPublishConstraints(t, enfSnapshot(t), enfConstraint{"ceiling.no_tool_for_alice", enfUser, []string{authoringcatalog.ActionToolCall}}))
	r := mrsCheckOutput(t, mrsToken(t), mrsBenign)
	if r.code != http.StatusForbidden || !strings.HasPrefix(r.body.BlockReason, "Response blocked: "+string(contract.ReasonExplicitConstraint)) {
		t.Fatalf("got HTTP %d block_reason %q; want 403 explicit_constraint. body=%s", r.code, r.body.BlockReason, r.raw)
	}
}

// TestAnInjectionSpanIsStrippedAndTheResponseReleased is the reversal #4065
// routed to #4016, closed on this pass: the corpus binds this pass the
// control's core/128 redact variant, so the anchored engine strips the span and
// releases the rest, where it once withheld the whole response by the request
// pass's block. The CONTROL is that the request pass still binds the control as
// a constraint: without it this test could pass on a control the corpus never
// split.
func TestAnInjectionSpanIsStrippedAndTheResponseReleased(t *testing.T) {
	w := mrsSetup(t)
	blocksOnRequest := false
	for _, c := range enfScopeControls(t, legacycompile.MustScopeFor(legacycompile.PlaneMCP, legacycompile.PhaseRequest)) {
		if c.row.PolicyID == w.stripped && c.policy.Authority == contract.AuthorityConstraint {
			blocksOnRequest = true
		}
	}
	if !blocksOnRequest {
		t.Fatalf("CONTROL: mcp:request does not bind %s as a constraint; this test's subject is a control the request pass blocks and the response pass strips", w.stripped)
	}
	w.mrsWire(t, w.docs)
	r := mrsCheckOutput(t, mrsToken(t), "note "+mrsInjectionProbe+". The order shipped.")
	data, _ := r.body.RedactedData.(string)
	if r.code != http.StatusOK || !r.body.Allowed || r.body.Engine != decisionEngineAnchored || data == "" ||
		strings.Contains(data, mrsInjectionProbe) || !strings.Contains(data, "The order shipped.") {
		t.Fatalf("got HTTP %d allowed=%v engine=%q redacted_data=%v; want a 200 anchored release with the injection span stripped and the rest released. body=%s",
			r.code, r.body.Allowed, r.body.Engine, r.body.RedactedData, r.raw)
	}
}

// TestMCPResponseWithNoActiveDocumentIsDecidedUnderTheImplicitBaseline: an
// organization that has published nothing is decided by the anchored engine
// under the implicit baseline (PRD v11 §1.4), and every body names that
// baseline's digest. The baseline grants every principal of the organization,
// so a clean response is released, a PII span masked and an injection span
// stripped exactly as under a document that grants tool.call.
func TestMCPResponseWithNoActiveDocumentIsDecidedUnderTheImplicitBaseline(t *testing.T) {
	w := mrsSetup(t)
	w.mrsWire(t, mrsDocuments{enfDocuments: w.docs, none: true})
	implicitBundle := enfImplicitBundle(t, mcpResponseSeamScope, w.org)
	token := mrsToken(t)
	for _, c := range []struct {
		name, content, absent, kept string
	}{
		{"a clean response", mrsBenign, "", ""},
		{"a PII span", mrsRedactContent(w.redactProbe), w.redactProbe, "order note:"},
		{"an injection span", "note " + mrsInjectionProbe + ". The order shipped.", mrsInjectionProbe, "The order shipped."},
	} {
		t.Run(c.name, func(t *testing.T) {
			r := mrsCheckOutput(t, token, c.content)
			if r.code != http.StatusOK || !r.body.Allowed || r.body.Engine != decisionEngineAnchored || r.body.PolicyBundle != implicitBundle {
				t.Fatalf("got HTTP %d allowed=%v engine=%q policy_bundle=%q; want a 200 anchored release under the implicit baseline %q. body=%s",
					r.code, r.body.Allowed, r.body.Engine, r.body.PolicyBundle, implicitBundle, r.raw)
			}
			if c.absent != "" {
				data, _ := r.body.RedactedData.(string)
				if strings.Contains(data, c.absent) || !strings.Contains(data, c.kept) {
					t.Fatalf("redacted_data %q: want %q gone and %q kept. body=%s", data, c.absent, c.kept, r.raw)
				}
			}
		})
	}
	t.Run("a credential-only caller is released as a Client", func(t *testing.T) {
		r := mrsCheckOutput(t, "", mrsBenign)
		if r.code != http.StatusOK || !r.body.Allowed || r.body.SubjectType != string(sharedidentity.SubjectClient) {
			t.Fatalf("got HTTP %d allowed=%v subject_type=%q; want a 200 release for a Client under the implicit baseline. body=%s", r.code, r.body.Allowed, r.body.SubjectType, r.raw)
		}
	})
}

// TestMCPResponseSeamFailsClosedNamingEachCause: every dependency failure
// withholds the response with the cause named, and counts it.
func TestMCPResponseSeamFailsClosedNamingEachCause(t *testing.T) {
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
			counter := anchoredEnforceDecisions.WithLabelValues(mcpResponseSeamScope.String(), decisionEngineAnchored, "unavailable", c.cause)
			before := testutil.ToFloat64(counter)
			r := mrsCheckOutput(t, token, mrsBenign)
			want := "Response blocked: response withheld: " + enforceCauseMessages[c.cause]
			if r.code != http.StatusForbidden || r.body.Allowed || r.body.BlockReason != want {
				t.Fatalf("got HTTP %d allowed=%v block_reason %q; want 403 %q. body=%s", r.code, r.body.Allowed, r.body.BlockReason, want, r.raw)
			}
			if strings.Contains(r.raw, "unreadable") || strings.Contains(r.raw, "unreachable") {
				t.Fatalf("the refusal leaked the underlying error to the caller: %s", r.raw)
			}
			if after := testutil.ToFloat64(counter); after != before+1 {
				t.Fatalf("the unavailable counter for %s moved %v -> %v; want +1", c.cause, before, after)
			}
		})
	}

	t.Run("a response pass reached with no seam on its context is withheld, not decided", func(t *testing.T) {
		w.mrsWire(t, w.docs)
		ctx := context.WithValue(context.Background(), ContextKeyOrgID, w.org)
		out := evaluateOutputPolicies(ctx, utrTestTenant, w.org, "1", "postgres", "", nil, mrsBenign, nil, 0, false, true)
		want := "response withheld: " + enforceCauseMessages[enforceCauseSubjectUnverifiable]
		if out.StaticResult == nil || !out.StaticResult.Blocked || out.StaticResult.BlockReason != want {
			t.Fatalf("an evaluation with no installed subject returned %+v; want the %s withhold", out.StaticResult, enforceCauseSubjectUnverifiable)
		}
	})
}

// mrsPostureArgs is a check-output row's INSERT arguments for a verdict, with
// the engine and subject type pinned: recordDecideDecision's layout on the MCP
// plane.
func mrsPostureArgs(verdict, subjectType string) []driver.Value {
	args := decideAuditInsertArgs(verdict, enfPostureMatcher{engine: decisionEngineAnchored, subjectType: subjectType})
	args[15] = PlaneMCP
	return args
}

// TestMCPResponseSeamWritesEngineSubjectTypeAndBundleOnTheAuditRow reads the
// record for a published document, for the implicit baseline and for a client
// credential under it.
func TestMCPResponseSeamWritesEngineSubjectTypeAndBundleOnTheAuditRow(t *testing.T) {
	w := mrsSetup(t)
	for _, tc := range []struct {
		name        string
		docs        activeDocumentSource
		token       string
		subjectType string
	}{
		{"a published document, a verified user", w.docs, mrsToken(t), string(sharedidentity.SubjectUser)},
		{"the implicit baseline, a verified user", mrsDocuments{enfDocuments: w.docs, none: true}, mrsToken(t), string(sharedidentity.SubjectUser)},
		{"the implicit baseline, a client credential", mrsDocuments{enfDocuments: w.docs, none: true}, "", string(sharedidentity.SubjectClient)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w.mrsWire(t, tc.docs)
			mock := withMockUsageDB(t)
			mock.MatchExpectationsInOrder(false)
			mock.ExpectExec("INSERT INTO audit_logs").WithArgs(mrsPostureArgs(AuditVerdictAllowed, tc.subjectType)...).WillReturnResult(sqlmock.NewResult(0, 1))
			if r := mrsCheckOutput(t, tc.token, mrsBenign); r.code != http.StatusOK {
				t.Fatalf("HTTP %d: %s", r.code, r.raw)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatalf("the audit row did not record engine=anchored subject_type=%s with a policy bundle: %v", tc.subjectType, err)
			}
		})
	}
}

// mrsNoEngineMatcher asserts an audit row's policy_details carries no engine:
// no engine decided the row it is on.
type mrsNoEngineMatcher struct{}

func (mrsNoEngineMatcher) Match(v driver.Value) bool {
	raw, ok := jsonbBytes(v)
	if !ok {
		return false
	}
	var d map[string]interface{}
	if json.Unmarshal(raw, &d) != nil {
		return false
	}
	_, hasEngine := d["engine"]
	return !hasEngine
}

// TestAResponseWithheldBeforeTheSeamCarriesNoEngine: the pass can refuse before
// the anchored engine runs - here the #2820 withhold, when the shared engine
// cannot load the response-phase policies. That refusal is an availability
// failure outside the policy engines, like the circuit breaker, so neither its
// body nor its audit row claims an engine decided it.
func TestAResponseWithheldBeforeTheSeamCarriesNoEngine(t *testing.T) {
	w := mrsSetup(t)
	w.mrsWire(t, w.docs)
	unloadable, _, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unloadable.Close() })
	prev := sharedpolicy.GetGlobalEngine()
	sharedpolicy.SetGlobalEngine(sharedpolicy.NewUnifiedPolicyEngine(unloadable, sharedpolicy.EngineConfig{CacheTTL: time.Hour}, nil))
	t.Cleanup(func() { sharedpolicy.SetGlobalEngine(prev) })

	args := decideAuditInsertArgs(AuditVerdictBlocked, mrsNoEngineMatcher{})
	args[15] = PlaneMCP
	mock := withMockUsageDB(t)
	mock.MatchExpectationsInOrder(false)
	mock.ExpectExec("INSERT INTO audit_logs").WithArgs(args...).WillReturnResult(sqlmock.NewResult(0, 1))
	r := mrsCheckOutput(t, mrsToken(t), mrsBenign)
	if r.code != http.StatusForbidden || !strings.Contains(r.body.BlockReason, "could not evaluate") || r.body.Engine != "" {
		t.Fatalf("got HTTP %d block_reason=%q engine=%q; want the #2820 withhold with no engine named. body=%s", r.code, r.body.BlockReason, r.body.Engine, r.raw)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("the withheld response's audit row names an engine: %v", err)
	}
}

// TestAnOrganizationsDetectionOverrideReachesTheAnchoredResponsePass is #4045
// on the response pass: with no override the shipped control masks the probe,
// and an organization's recorded pii override moves the anchored engine - block
// withholds the response, redact releases it masked, and log releases it
// unmasked, which is the weakening the organization recorded.
func TestAnOrganizationsDetectionOverrideReachesTheAnchoredResponsePass(t *testing.T) {
	w := mrsSetup(t)
	redact, _, _ := mrsResponseProbes(t)
	category := ""
	for _, c := range enfScopeControls(t, mcpResponseSeamScope) {
		if c.row.PolicyID == redact {
			category = c.row.Category
		}
	}
	if sharedpolicy.OrgOverrideCategoryFor(sharedpolicy.PolicyCategory(category)) != DetectionCategoryPII {
		t.Fatalf("PREMISE: the probe's control %s (category %q) is not one a recorded pii override reaches", redact, category)
	}
	reader := &fakeOverrideReader{data: map[string]map[string]DetectionAction{}}
	installTestOverrideCache(t, reader, time.Minute)
	w.mrsWire(t, w.docs)
	token := mrsToken(t)
	content := mrsRedactContent(w.redactProbe)

	for _, c := range []struct {
		name     string
		action   DetectionAction
		code     int
		released bool
		masked   bool
	}{
		{"CONTROL: no override, the shipped redaction", "", http.StatusOK, false, true},
		{"pii=block", DetectionActionBlock, http.StatusForbidden, false, false},
		{"pii=redact", DetectionActionRedact, http.StatusOK, false, true},
		{"pii=log", DetectionActionLog, http.StatusOK, true, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			reader.mu.Lock()
			if c.action == "" {
				delete(reader.data, w.org)
			} else {
				reader.data[w.org] = map[string]DetectionAction{DetectionCategoryPII: c.action}
			}
			reader.mu.Unlock()
			InvalidateOrgDetectionOverrides(w.org)

			r := mrsCheckOutput(t, token, content)
			if r.code != c.code || r.body.Engine != decisionEngineAnchored {
				t.Fatalf("got HTTP %d engine=%q; want %d from the anchored engine. body=%s", r.code, r.body.Engine, c.code, r.raw)
			}
			if c.released && r.body.RedactedData != nil {
				t.Fatalf("pii=log must release the content unmasked: redacted=%v", r.body.RedactedData)
			}
			if c.masked {
				if masked, ok := r.body.RedactedData.(string); !ok || strings.Contains(masked, w.redactProbe) || !strings.Contains(masked, "order note:") {
					t.Fatalf("want the content released masked: redacted=%v", r.body.RedactedData)
				}
			}
		})
	}
}

// TestMCPServerCheckOutputAdmitsTheSessionsValidatedToken drives the MCP server's
// check_output tool: its subject is the per-user token a validator accepted
// when the session was created, and a session without one is evaluated for its
// client credential.
func TestMCPServerCheckOutputAdmitsTheSessionsValidatedToken(t *testing.T) {
	w := mrsSetup(t)
	w.mrsWire(t, w.docs)
	user, authErr := ResolveUser(&AuthResult{Kind: AuthKindEnterprise, OrgID: w.org, TenantID: utrTestTenant, ClientID: utrTestClientID}, mrsToken(t))
	if authErr != nil {
		t.Fatalf("resolving the minted token: %v", authErr.Message)
	}
	ctx := context.WithValue(context.Background(), ContextKeyOrgID, w.org)
	args := map[string]interface{}{"connector_type": "postgres", "message": mrsBenign}
	session := func(vid *sharedidentity.ValidatedIdentity) *mcpSession {
		return &mcpSession{tenantID: utrTestTenant, orgID: w.org, clientID: utrTestClientID, authKind: AuthKindEnterprise,
			identityInputs: mcpIdentityInputs{tokenResolvedIdentity: vid != nil, validatedToken: vid}}
	}

	result, err := mcpToolCheckOutput(ctx, session(&sharedidentity.ValidatedIdentity{
		Email: enfUser, OrgID: w.org, Source: sharedidentity.ValidatorNameHS256, Validated: true, Claims: user.TokenClaims,
	}), args, pepHandshakeResolution{})
	if err != nil {
		t.Fatal(err)
	}
	got := result.(map[string]interface{})
	if got["allowed"] != true || got["engine"] != decisionEngineAnchored || got["subject_type"] != string(sharedidentity.SubjectUser) {
		t.Fatalf("a session whose token a validator accepted got %v; want an anchored allow for a User", got)
	}
	if _, has := got["mode"]; has {
		t.Fatalf("the check_output result carries a mode member: %v", got)
	}

	result, err = mcpToolCheckOutput(ctx, session(nil), args, pepHandshakeResolution{})
	if err != nil {
		t.Fatal(err)
	}
	got = result.(map[string]interface{})
	if got["allowed"] != true || got["subject_type"] != string(sharedidentity.SubjectClient) {
		t.Fatalf("a session with no validated token got %v; want an allow recorded for a Client - the credential is the principal, and the document constrains bob", got)
	}
}

// mrsPost drives a connector route handler with the harness credential.
func mrsPost(path string, body interface{}, handler http.HandlerFunc) *httptest.ResponseRecorder {
	b, _ := json.Marshal(body)
	req := httptest.NewRequest("POST", path, bytes.NewBuffer(b))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", utrBasicAuthHeader())
	rr := httptest.NewRecorder()
	handler(rr, req)
	return rr
}

// TestMCPConnectorRoutesEnforceTheResponsePass drives resources/query and
// tools/execute: both install the seam, both release a connector result the
// anchored engine masks with the span gone, and both bodies say which engine
// decided and for which type of principal.
func TestMCPConnectorRoutesEnforceTheResponsePass(t *testing.T) {
	w := mrsSetup(t)
	w.mrsWire(t, w.docs)
	token := mrsToken(t)
	query := func() *httptest.ResponseRecorder {
		return mrsPost("/mcp/resources/query", MCPQueryRequest{Connector: "test-db", Statement: "SELECT note FROM orders", UserToken: token}, mcpQueryHandler)
	}
	execute := func() *httptest.ResponseRecorder {
		return mrsPost("/mcp/tools/execute", MCPExecuteRequest{Connector: "test-db", Action: "UPDATE", Statement: "UPDATE orders SET x=1", UserToken: token}, mcpExecuteHandler)
	}
	injected := "note " + mrsInjectionProbe + " ends"

	for _, c := range []struct {
		name      string
		connector *mockConnector
		post      func() *httptest.ResponseRecorder
	}{
		{"query: a clean row set is released by the anchored engine",
			&mockConnector{queryResult: &base.QueryResult{Rows: []map[string]interface{}{{"note": mrsBenign}}, RowCount: 1}}, query},
		{"query: a row a shipped injection control detects is released with the span masked",
			&mockConnector{queryResult: &base.QueryResult{Rows: []map[string]interface{}{{"note": injected}}, RowCount: 1}}, query},
		{"execute: a clean message is released by the anchored engine",
			&mockConnector{executeResult: &base.CommandResult{RowsAffected: 1, Message: mrsBenign}}, execute},
		{"execute: a message a shipped injection control detects is released with the span masked",
			&mockConnector{executeResult: &base.CommandResult{RowsAffected: 1, Message: injected}}, execute},
	} {
		t.Run(c.name, func(t *testing.T) {
			registerExecConnector(t, c.connector)
			rr := c.post()
			if rr.Code != http.StatusOK {
				t.Fatalf("HTTP %d; want 200. body=%s", rr.Code, rr.Body.String())
			}
			if strings.Contains(rr.Body.String(), mrsInjectionProbe) {
				t.Fatalf("the released body still carries the injection span: %s", rr.Body.String())
			}
			var body map[string]interface{}
			if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			_, hasMode := body["mode"]
			if body["engine"] != decisionEngineAnchored || body["subject_type"] != string(sharedidentity.SubjectUser) || hasMode {
				t.Fatalf("engine=%v subject_type=%v mode present=%v; want anchored/User and no mode. body=%s", body["engine"], body["subject_type"], hasMode, rr.Body.String())
			}
		})
	}
}

// TestAnAdvisoryRedactionNeitherMasksNorWithholds: the disclosure an inspection
// policy attaches is advisory, and an advisory control cannot deny, so it neither
// demands masking nor refuses the response. The same obligation made mandatory,
// with no determining requirement behind it, is the control: it cannot be
// discharged, so the response is withheld.
func TestAnAdvisoryRedactionNeitherMasksNorWithholds(t *testing.T) {
	redaction := contract.Obligation{Type: contract.ObFieldRedact, Target: legacycompile.DefaultContentTarget, SourcePolicy: "inspect.pii_note"}
	ids, unsupported, err := responseRedactionPolicies(&contract.Decision{Obligations: []contract.Obligation{redaction}}, nil, nil)
	if err != nil || unsupported != "" || len(ids) != 0 {
		t.Fatalf("an advisory field_redact returned ids=%v unsupported=%q err=%v; want nothing masked and nothing refused", ids, unsupported, err)
	}
	redaction.Mandatory = true
	if _, _, err := responseRedactionPolicies(&contract.Decision{Obligations: []contract.Obligation{redaction}}, nil, nil); err == nil {
		t.Fatal("CONTROL: a mandatory field_redact with no determining requirement behind it was accepted; this test's premise is gone")
	}
}

// TestAResponseContentRequirementIsMaskedBesideAndWithoutAnEvaluatedContentOne
// drives the masking loop with a requirement whose field_redact targets
// response.content - the target a document published before #4046 carries -
// with and without a system requirement on the evaluated content, each read by
// its own detector that ran and matched. Every such requirement's detector is
// named for masking, and a mandatory field_redact on any other target refuses the
// response as unsupported. Counting a response.content redaction as discharged
// while naming no detector for it would release its span unmasked.
func TestAResponseContentRequirementIsMaskedBesideAndWithoutAnEvaluatedContentOne(t *testing.T) {
	requirement := func(id, detector, target string) pdp.Policy {
		return pdp.Policy{
			ID: id, Authority: contract.AuthorityRequirement, Root: pdp.RootOrganization,
			Where:       pdp.Compare(registry.DetectorID(detector).SignalPath(), pdp.OpEq, true),
			Obligations: []contract.Obligation{{Type: contract.ObFieldRedact, Target: target, Mandatory: true, SourcePolicy: id, SchemaVersion: 1}},
		}
	}
	org := requirement("org.passport_redaction", "sys_pii_passport", "response.content")
	system := requirement("corpus:static_policies:sys__pii__ssn:redact", "sys_pii_ssn", legacycompile.DefaultContentTarget)
	activated := map[string]pdp.Policy{org.ID: org, system.ID: system}
	lookup := func(id string) (pdp.Policy, bool) {
		p, ok := activated[id]
		return p, ok
	}
	observation := &sharedpolicy.Observation{Rows: []sharedpolicy.DetectorFact{
		{PolicyID: "sys_pii_passport", Ran: true, Matched: true},
		{PolicyID: "sys_pii_ssn", Ran: true, Matched: true},
	}}
	decided := func(ps ...pdp.Policy) *contract.Decision {
		dec := &contract.Decision{}
		for _, p := range ps {
			dec.Obligations = append(dec.Obligations, p.Obligations...)
			dec.Determining.MatchedRequirement = append(dec.Determining.MatchedRequirement, p.ID)
		}
		return dec
	}
	for _, c := range []struct {
		name string
		dec  *contract.Decision
		want string
	}{
		{"beside a system redaction of the evaluated content", decided(org, system), "sys_pii_passport,sys_pii_ssn"},
		{"on its own", decided(org), "sys_pii_passport"},
		{"CONTROL: the evaluated content on its own", decided(system), "sys_pii_ssn"},
	} {
		ids, unsupported, err := responseRedactionPolicies(c.dec, lookup, observation)
		if err != nil || unsupported != "" || strings.Join(ids, ",") != c.want {
			t.Errorf("%s: masked %v (unsupported %q, err %v); want %s", c.name, ids, unsupported, err, c.want)
		}
	}
	other := requirement("org.tool_name_redaction", "sys_pii_passport", "args.tool_name")
	activated[other.ID] = other
	if _, unsupported, _ := responseRedactionPolicies(decided(other), lookup, observation); !strings.HasPrefix(unsupported, string(contract.ReasonUnsupportedObligation)) {
		t.Fatalf("CONTROL: a mandatory field_redact on args.tool_name returned unsupported=%q; a target this pass does not hold must refuse the response", unsupported)
	}
}

// TestAnEmptyResponseIsDecidedByThePolicyNotWithheld: a connector result with no
// content - an execute whose command returned no message, a query that returned
// no rows - is decided by the organization's policy and the identity, not
// withheld because no detector had anything to scan. The release is the
// response pass's. A refusal of an empty result has no response-only trigger:
// no detector matches empty content, and the request pass refuses a subject
// constraint on the user's tool.call before the connector runs, so that arm
// pins the request pass's refusal by its prefix. Both envelopes carry the
// engine, the subject type and the policy bundle like every other body.
func TestAnEmptyResponseIsDecidedByThePolicyNotWithheld(t *testing.T) {
	w := mrsSetup(t)
	token := mrsToken(t)
	empty := []struct {
		name      string
		connector *mockConnector
		post      func() *httptest.ResponseRecorder
	}{
		{"execute with no message",
			&mockConnector{executeResult: &base.CommandResult{RowsAffected: 1}},
			func() *httptest.ResponseRecorder {
				return mrsPost("/mcp/tools/execute", MCPExecuteRequest{Connector: "test-db", Action: "UPDATE", Statement: "UPDATE orders SET x=1", UserToken: token}, mcpExecuteHandler)
			}},
		{"query with no rows",
			&mockConnector{queryResult: &base.QueryResult{Rows: []map[string]interface{}{}}},
			func() *httptest.ResponseRecorder {
				return mrsPost("/mcp/resources/query", MCPQueryRequest{Connector: "test-db", Statement: "SELECT note FROM orders", UserToken: token}, mcpQueryHandler)
			}},
	}
	for _, g := range []struct {
		name     string
		docs     func() activeDocumentSource
		wantCode int
		reason   string
		// prefix is the pass a refusal must be answered by.
		prefix string
	}{
		{"a document that does not constrain it releases it", func() activeDocumentSource { return w.docs }, http.StatusOK, "", ""},
		{"a constraint on the user's tool.call is refused by the request pass before the connector runs", func() activeDocumentSource {
			return enfPublishConstraints(t, enfSnapshot(t), enfConstraint{"ceiling.no_tool_for_alice", enfUser, []string{authoringcatalog.ActionToolCall}})
		}, http.StatusForbidden, string(contract.ReasonExplicitConstraint), "Request blocked: "},
	} {
		t.Run(g.name, func(t *testing.T) {
			w.mrsWire(t, g.docs())
			for _, c := range empty {
				t.Run(c.name, func(t *testing.T) {
					registerExecConnector(t, c.connector)
					rr := c.post()
					var body map[string]interface{}
					if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
						t.Fatalf("HTTP %d with a body that is not JSON: %s", rr.Code, rr.Body.String())
					}
					if rr.Code != g.wantCode || body["engine"] != decisionEngineAnchored || !strings.Contains(rr.Body.String(), g.reason) {
						t.Fatalf("HTTP %d engine=%v; want %d from the anchored engine naming %q. body=%s", rr.Code, body["engine"], g.wantCode, g.reason, rr.Body.String())
					}
					if body["subject_type"] != string(sharedidentity.SubjectUser) || body["policy_bundle"] == nil {
						t.Fatalf("subject_type=%v policy_bundle=%v; every body the pass decided names both. body=%s", body["subject_type"], body["policy_bundle"], rr.Body.String())
					}
					if message, _ := body["error"].(string); g.prefix != "" && !strings.HasPrefix(message, g.prefix) {
						t.Fatalf("error %q; want the refusal answered %q. body=%s", message, g.prefix, rr.Body.String())
					}
				})
			}
		})
	}
}

// AN MCP CONNECTOR ROUTE'S REFUSAL SAYS IT BLOCKED. A 403 is a block whichever
// pass refused - the request pass before the connector runs, the response pass
// after it - so the body carries blocked=true beside it; it carried false, which
// a client reading `blocked` took for an allow. A request nothing decided
// carries blocked=false: a malformed one (400), and one the engine could not
// decide (503).
func TestAnMCPConnectorRefusalSaysItBlocked(t *testing.T) {
	w := mrsSetup(t)
	reader := &fakeOverrideReader{data: map[string]map[string]DetectionAction{}}
	installTestOverrideCache(t, reader, time.Minute)
	w.mrsWire(t, w.docs)
	query := func(token string) *httptest.ResponseRecorder {
		return mrsPost("/mcp/resources/query", MCPQueryRequest{Connector: "test-db", Statement: "SELECT note FROM orders", UserToken: token}, mcpQueryHandler)
	}
	rows := func(note string) *mockConnector {
		return &mockConnector{queryResult: &base.QueryResult{Rows: []map[string]interface{}{{"note": note}}, RowCount: 1}}
	}
	// The undecidable request runs last: it rewires the enforcer over documents
	// whose tables cannot be read.
	for _, c := range []struct {
		name    string
		setup   func(t *testing.T)
		post    func() *httptest.ResponseRecorder
		code    int
		prefix  string
		blocked bool
	}{
		{"the request pass's refusal", func(t *testing.T) { registerExecConnector(t, rows("unreached")) },
			func() *httptest.ResponseRecorder { return query(mrsTokenFor(t, enfBob)) }, http.StatusForbidden, "Request blocked: ", true},
		{"the response pass's refusal", func(t *testing.T) {
			reader.mu.Lock()
			reader.data[w.org] = map[string]DetectionAction{DetectionCategoryPII: DetectionActionBlock}
			reader.mu.Unlock()
			InvalidateOrgDetectionOverrides(w.org)
			t.Cleanup(func() {
				reader.mu.Lock()
				delete(reader.data, w.org)
				reader.mu.Unlock()
				InvalidateOrgDetectionOverrides(w.org)
			})
			registerExecConnector(t, rows(mrsRedactContent(w.redactProbe)))
		}, func() *httptest.ResponseRecorder { return query(mrsToken(t)) }, http.StatusForbidden, "Response blocked: ", true},
		{"a malformed request", nil,
			func() *httptest.ResponseRecorder {
				return mrsPost("/mcp/resources/query", "not an object", mcpQueryHandler)
			}, http.StatusBadRequest, "", false},
		{"a request the engine could not decide", func(t *testing.T) {
			w.mrsWire(t, mrsDocuments{enfDocuments: w.docs, broken: true})
			registerExecConnector(t, rows("unreached"))
		}, func() *httptest.ResponseRecorder { return query(mrsToken(t)) }, http.StatusServiceUnavailable, "", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			if c.setup != nil {
				c.setup(t)
			}
			rr := c.post()
			body := mrqRefusal(t, rr)
			message, _ := body["error"].(string)
			if rr.Code != c.code || body["blocked"] != c.blocked || !strings.HasPrefix(message, c.prefix) {
				t.Fatalf("HTTP %d blocked=%v error %q; want %d, blocked=%v, answered %q. body=%s", rr.Code, body["blocked"], message, c.code, c.blocked, c.prefix, rr.Body.String())
			}
		})
	}
}

// TestTheResponseSeamIsInstalledAtEveryResponsePassEntryPoint is the census
// beside the behavioural tests above: every production function that runs the
// response pass installs the seam before it, so a new entry point cannot reach
// evaluateOutputPolicies undecidable. It is a TRIPWIRE, not the proof - the
// seam also fails closed on its absence (see the withhold case above).
func TestTheResponseSeamIsInstalledAtEveryResponsePassEntryPoint(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	callers := 0
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		file, err := parser.ParseFile(fset, f, src, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil || fn.Name.Name == "evaluateOutputPolicies" {
				continue
			}
			seamAt, callAt := token.NoPos, token.NoPos
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				if id, ok := call.Fun.(*ast.Ident); ok {
					switch id.Name {
					case "withMCPResponseSeam":
						if seamAt == token.NoPos {
							seamAt = call.Pos()
						}
					case "evaluateOutputPolicies":
						if callAt == token.NoPos {
							callAt = call.Pos()
						}
					}
				}
				return true
			})
			if callAt == token.NoPos {
				continue
			}
			callers++
			if seamAt == token.NoPos || seamAt > callAt {
				t.Errorf("%s (%s) runs the MCP response pass without installing the response seam before it", fn.Name.Name, fset.Position(callAt))
			}
		}
	}
	if callers < 4 {
		t.Fatalf("found %d production callers of evaluateOutputPolicies; resources/query, tools/execute, check-output and check_output are four, so the census is not reading the package", callers)
	}
}
