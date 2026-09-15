// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"axonflow/platform/decision/authoringcatalog"
	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/legacycompile"
	"axonflow/platform/orchestrator/cost"
	sharedidentity "axonflow/platform/shared/identity"
)

// THE GATEWAY PRE-CHECK'S ENFORCING SEAM, THROUGH THE REAL HANDLER (#3564 wave
// two). The fixtures are the decide seam's (decision_handler_enforcing_test.go):
// the same published document, the same implicit baseline and the same shipped
// detectors. Every assertion reads the ENCODED pre-check response or the audit
// row the handler wrote.

// enfPreCheck drives one request through handlePolicyPreCheck as an Enterprise
// caller authenticated for org, with the user token given ("" for none).
func enfPreCheck(t *testing.T, org, userToken, query string, dataSources ...string) enfResponse {
	t.Helper()
	return enfPreCheckWithHandshake(t, org, userToken, query, "", dataSources...)
}

// enfPreCheckWithHandshake is enfPreCheck from an enforcement point presenting
// handshake as its PEP capability declaration ("" presents none).
func enfPreCheckWithHandshake(t *testing.T, org, userToken, query, handshake string, dataSources ...string) enfResponse {
	t.Helper()
	body, err := json.Marshal(PreCheckRequest{ClientID: "auth-client", UserToken: userToken, Query: query, DataSources: dataSources})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("POST", "/api/policy/pre-check", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if handshake != "" {
		req.Header.Set(contract.PEPHandshakeHeader, handshake)
	}
	ctx := req.Context()
	ctx = context.WithValue(ctx, ContextKeyTenantID, org)
	ctx = context.WithValue(ctx, ContextKeyOrgID, org)
	ctx = context.WithValue(ctx, ContextKeyClientID, "auth-client")
	ctx = context.WithValue(ctx, ContextKeyAuthKind, AuthKindEnterprise)
	rr := httptest.NewRecorder()
	handlePolicyPreCheck(rr, req.WithContext(ctx))
	out := enfResponse{code: rr.Code, raw: rr.Body.Bytes(), body: map[string]json.RawMessage{}}
	if err := json.Unmarshal(rr.Body.Bytes(), &out.body); err != nil {
		t.Fatalf("the response is not a JSON object: %v\n%s", err, rr.Body.String())
	}
	return out
}

// approved reads the pre-check's boolean verdict, failing when it is absent:
// `approved` is always encoded, so its absence is a different response shape.
func (r enfResponse) approved(t *testing.T) bool {
	t.Helper()
	v, ok := r.body["approved"]
	if !ok {
		t.Fatalf("the response carries no approved member: %s", r.raw)
	}
	var b bool
	if err := json.Unmarshal(v, &b); err != nil {
		t.Fatalf("member approved is not a boolean: %s", v)
	}
	return b
}

// enfGatewayConstraintPolicy is the policy id the gateway restriction keeps for
// the fixture's constraint detector: what a pre-check refusal names first.
func enfGatewayConstraintPolicy(t *testing.T) string {
	t.Helper()
	row, _ := enfConstraintPolicy(t)
	for _, c := range enfScopeControls(t, gatewayRequestSeamScope) {
		if c.row.PolicyID == row {
			if c.policy.Authority != contract.AuthorityConstraint {
				t.Fatalf("the gateway restriction keeps %s for %s as a %s; the fixture needs a constraint", c.policy.ID, row, c.policy.Authority)
			}
			return c.policy.ID
		}
	}
	t.Fatalf("the gateway restriction keeps no policy reading %s, the constraint the fixture installs", row)
	return ""
}

// enfGatewayCounted sums every decision series the gateway pre-check has,
// whatever its engine, verdict or reason.
func enfGatewayCounted(t *testing.T) float64 {
	t.Helper()
	total := 0.0
	for _, engine := range []string{decisionEngineAnchored} {
		for _, verdict := range []string{VerdictAllow, VerdictDeny, VerdictNeedsApproval, "unavailable"} {
			for _, reason := range []string{string(contract.ReasonPermitted), "subject_type_rejected", string(contract.ReasonNoMatchingPermission), string(contract.ReasonExplicitConstraint)} {
				total += testutil.ToFloat64(anchoredEnforceDecisions.WithLabelValues(gatewayRequestSeamScope.String(), engine, verdict, reason))
			}
		}
	}
	return total
}

func TestGatewayPreCheckEnforcingSeam(t *testing.T) {
	enfSetup(t)
	constraintPolicy := enfGatewayConstraintPolicy(t)
	implicitBundle := enfImplicitBundle(t, gatewayRequestSeamScope, enfOrgImplicit)
	alice := func() string { return enfMintUserToken(t, enfOrgPublished, enfUser) }

	t.Run("a published document + verified user: the ANCHORED engine approves, and the body says so", func(t *testing.T) {
		counter := anchoredEnforceDecisions.WithLabelValues(gatewayRequestSeamScope.String(), decisionEngineAnchored, VerdictAllow, string(contract.ReasonPermitted))
		before := testutil.ToFloat64(counter)
		r := enfPreCheck(t, enfOrgPublished, alice(), "What is the weather today?")
		if r.code != http.StatusOK || !r.approved(t) || r.str(t, "verdict") != VerdictAllow {
			t.Fatalf("got HTTP %d approved=%v verdict %q; want 200 approved allow. body=%s", r.code, r.approved(t), r.str(t, "verdict"), r.raw)
		}
		if r.str(t, "engine") != decisionEngineAnchored || r.str(t, "subject_type") != string(sharedidentity.SubjectUser) {
			t.Fatalf("engine=%q subject_type=%q; want anchored/User. body=%s", r.str(t, "engine"), r.str(t, "subject_type"), r.raw)
		}
		r.noMode(t)
		if bundle := r.str(t, "policy_bundle"); bundle == "" || bundle == implicitBundle {
			t.Fatalf("policy_bundle %q; want the published document's bundle, not the implicit baseline's %q", bundle, implicitBundle)
		}
		if !slices.Contains(r.strings(t, "policies"), "baseline.permit."+authoringcatalog.ActionLLMCompletion) {
			t.Fatalf("policies %v does not name the deployment pack's permission, which permits this beside the document", r.strings(t, "policies"))
		}
		// COUNTED ON THIS PLANE: decide's restriction binds the same controls, so
		// a pre-check decided under decide's scope would give the same verdict and
		// be counted under the wrong plane.
		if after := testutil.ToFloat64(counter); after != before+1 {
			t.Fatalf("the gateway_request allow counter moved %v -> %v; want +1", before, after)
		}
	})

	t.Run("a published document: a principal it constrains is DENIED explicit_constraint", func(t *testing.T) {
		r := enfPreCheck(t, enfOrgPublished, enfMintUserToken(t, enfOrgPublished, enfBob), "What is the weather today?")
		if r.code != http.StatusOK || r.approved(t) || r.str(t, "verdict") != VerdictDeny || r.str(t, "engine") != decisionEngineAnchored {
			t.Fatalf("got HTTP %d approved=%v verdict %q engine %q; want 200 deny anchored. body=%s", r.code, r.approved(t), r.str(t, "verdict"), r.str(t, "engine"), r.raw)
		}
		if got := r.str(t, "block_reason"); got != string(contract.ReasonExplicitConstraint) {
			t.Fatalf("block_reason %q; want %s", got, contract.ReasonExplicitConstraint)
		}
	})

	t.Run("a published document denies an action it constrains, and the implicit baseline approves it", func(t *testing.T) {
		r := enfPreCheck(t, enfOrgPublished, alice(), "list the open tickets", "postgres")
		if r.code != http.StatusOK || r.approved(t) || r.str(t, "block_reason") != string(contract.ReasonExplicitConstraint) {
			t.Fatalf("got HTTP %d approved=%v block_reason %q; want the tool stage denied explicit_constraint. body=%s", r.code, r.approved(t), r.str(t, "block_reason"), r.raw)
		}
		implicit := enfPreCheck(t, enfOrgImplicit, enfMintUserToken(t, enfOrgImplicit, enfUser), "list the open tickets", "postgres")
		if implicit.code != http.StatusOK || !implicit.approved(t) || implicit.str(t, "engine") != decisionEngineAnchored {
			t.Fatalf("CONTROL: got HTTP %d approved=%v engine %q for an organization that has published nothing; the implicit baseline grants this action. body=%s",
				implicit.code, implicit.approved(t), implicit.str(t, "engine"), implicit.raw)
		}
		if got := implicit.str(t, "policy_bundle"); got != implicitBundle {
			t.Fatalf("policy_bundle %q; want the implicit baseline's %q", got, implicitBundle)
		}
	})

	t.Run("a published document: content a shipped block control detects is DENIED by that constraint, named first", func(t *testing.T) {
		r := enfPreCheck(t, enfOrgPublished, alice(), "please run "+enfConstraintProbe+" now")
		if r.code != http.StatusOK || r.approved(t) || r.str(t, "engine") != decisionEngineAnchored {
			t.Fatalf("got HTTP %d approved=%v engine %q; want 200 refused by the anchored engine. body=%s", r.code, r.approved(t), r.str(t, "engine"), r.raw)
		}
		if got := r.str(t, "block_reason"); got != string(contract.ReasonExplicitConstraint) {
			t.Fatalf("block_reason %q; want %s", got, contract.ReasonExplicitConstraint)
		}
		if policies := r.strings(t, "policies"); len(policies) == 0 || policies[0] != constraintPolicy {
			t.Fatalf("policies %v; the blocking shipped control %s must come first", policies, constraintPolicy)
		}
	})

	t.Run("an Enterprise caller presenting NO user token is refused at the authentication boundary, before any engine counts it", func(t *testing.T) {
		before := enfGatewayCounted(t)
		r := enfPreCheck(t, enfOrgPublished, "", "What is the weather today?")
		if r.code != http.StatusUnauthorized {
			t.Fatalf("got HTTP %d; an Enterprise pre-check with no user token is refused 401 before any policy runs. body=%s", r.code, r.raw)
		}
		if after := enfGatewayCounted(t); after != before {
			t.Fatalf("the gateway decisions moved %v -> %v for a request the handler refused before the seam", before, after)
		}
	})

	// PRD v11 §1.6: where no per-user identity can be verified the client
	// credential is the principal. A token presented there is not a user
	// identity at all - validateUserToken returns a fixed user for any token on
	// community - so it changes nothing.
	t.Run("where no user identity can be verified, the credential is the principal, recorded as a Client, token or no token", func(t *testing.T) {
		t.Setenv("DEPLOYMENT_MODE", "community")
		for _, token := range []string{"", "not-a-token-the-deployment-could-verify"} {
			implicit := enfPreCheck(t, enfOrgImplicit, token, "What is the weather today?")
			if implicit.code != http.StatusOK || !implicit.approved(t) || implicit.str(t, "subject_type") != string(sharedidentity.SubjectClient) {
				t.Fatalf("token %q under the implicit baseline: HTTP %d approved=%v subject_type %q; want 200 approved for a Client. body=%s",
					token, implicit.code, implicit.approved(t), implicit.str(t, "subject_type"), implicit.raw)
			}
			// The tool stage alice is denied: the credential is not alice, so the
			// document's constraint does not bind it.
			published := enfPreCheck(t, enfOrgPublished, token, "list the open tickets", "postgres")
			if published.code != http.StatusOK || !published.approved(t) || published.str(t, "subject_type") != string(sharedidentity.SubjectClient) {
				t.Fatalf("token %q under a document whose constraints name alice and bob: HTTP %d approved=%v subject_type %q block_reason %q; want 200 approved for a Client. body=%s",
					token, published.code, published.approved(t), published.str(t, "subject_type"), published.str(t, "block_reason"), published.raw)
			}
		}
	})

	t.Run("a budget refusal after the anchored approval carries the engine and is counted under its own reason", func(t *testing.T) {
		prev := costService
		costService = cost.NewService(&mockCostRepository{
			budgets: map[string]*cost.Budget{
				"budget-published": {
					ID: "budget-published", Name: "published budget", Scope: cost.ScopeOrganization, ScopeID: enfOrgPublished,
					LimitUSD: 100, Period: cost.PeriodMonthly, OnExceed: cost.OnExceedBlock,
					OrgID: enfOrgPublished, TenantID: enfOrgPublished, Enabled: true,
				},
			},
			usageSum: map[string]float64{"organization:" + enfOrgPublished: 150},
		}, nil)
		t.Cleanup(func() { costService = prev })
		counter := anchoredEnforceDecisions.WithLabelValues(gatewayRequestSeamScope.String(), decisionEngineAnchored, VerdictDeny, enforceReasonBudgetExceeded)
		before := testutil.ToFloat64(counter)
		r := enfPreCheck(t, enfOrgPublished, alice(), "What is the weather today?")
		if r.code != http.StatusPaymentRequired || r.approved(t) {
			t.Fatalf("got HTTP %d approved=%v; want the 402 budget refusal. body=%s", r.code, r.approved(t), r.raw)
		}
		if r.str(t, "engine") != decisionEngineAnchored {
			t.Fatalf("engine=%q; the budget refusal of an anchored approval must say which engine approved it. body=%s", r.str(t, "engine"), r.raw)
		}
		r.noMode(t)
		if after := testutil.ToFloat64(counter); after != before+1 {
			t.Fatalf("the final deny under the budget reason moved %v -> %v; want +1", before, after)
		}
	})
}

// TestAValidatorsRedactionReachesTheAnchoredVerdictOnlyAsItsObligation is R3 round one's
// finding 2 of #3564 wave two, held now that every pre-check verdict is the
// anchored engine's.
//
// The India and Indonesia validators detect critical PII independently of the
// shared engine. Under an organization's pii=redact override their redaction
// flags used to be OR'd into requires_redaction after the anchored verdict, so
// the response instructed a redaction that decision never attached - and
// through applyPreCheckRedactionRefusal a declaring caller could be DENIED for
// it, recorded under the decision's own reason code. requires_redaction is the
// decision's alone.
//
// Removing the flags entirely then dropped the redaction for identifiers only a
// validator detects (no shipped control matches an Aadhaar or a NIK): an
// override reaches the decision through activation only through a control. So
// the requirement now enters the anchored pass as the DECISION'S OWN mandatory
// obligation, judged by the engine's rule (attachValidatorRedactions, a W3-G
// stopgap #4122 replaces): requires_redaction is still the decision's alone, a
// caller that cannot discharge it is refused by the decision rather than by a
// later handler, and the verdict is never captioned with the validator, which
// legacy_validators names instead.
// indiaPII is critical India PII: a checksum-valid Aadhaar number, so
// checkRBIPII reports it critical.
const indiaPII = "please summarise aadhaar 234567890123 for me"

func TestAValidatorsRedactionReachesTheAnchoredVerdictOnlyAsItsObligation(t *testing.T) {
	if got := checkRBIPII(indiaPII, false); !got.HasPII || !got.CriticalPII {
		t.Fatalf("CONTROL: the validator does not see critical India PII in %q (%+v), so the absence below would prove nothing", indiaPII, got)
	}

	enfSetup(t)
	pinGatewayOverride(t, func(c *ModeDetectionConfig) { c.PIIAction = DetectionActionRedact })
	r := enfPreCheck(t, enfOrgPublished, enfMintUserToken(t, enfOrgPublished, enfUser), indiaPII)
	if r.code != http.StatusOK || r.str(t, "engine") != decisionEngineAnchored {
		t.Fatalf("HTTP %d engine %q: %s", r.code, r.str(t, "engine"), r.raw)
	}
	var got bool
	if raw, ok := r.body["requires_redaction"]; ok {
		if err := json.Unmarshal(raw, &got); err != nil {
			t.Fatalf("requires_redaction is not a boolean: %s", raw)
		}
	}
	// This caller declares no redaction capability, so the decision refuses it.
	if r.approved(t) || !strings.HasPrefix(r.str(t, "block_reason"), string(contract.ReasonUnsupportedObligation)) {
		t.Fatalf("a caller that cannot discharge the validator's redaction was not refused unsupported_obligation: %s", r.raw)
	}
	if got {
		t.Fatalf("requires_redaction=true on a refusal: an instruction the caller cannot carry out. body=%s", r.raw)
	}
	var legacy []LegacyValidatorAction
	if raw, ok := r.body["legacy_validators"]; ok {
		if err := json.Unmarshal(raw, &legacy); err != nil {
			t.Fatalf("legacy_validators is not a list: %s", raw)
		}
	}
	if want := []LegacyValidatorAction{{Validator: legacyValidatorIndia, Action: legacyActionRedactionRequired}}; !reflect.DeepEqual(legacy, want) {
		t.Fatalf("legacy_validators = %+v; want %+v naming the validator whose redaction the decision carried", legacy, want)
	}
	if slices.Contains(r.strings(t, "policies"), "rbi_pii_protection") {
		t.Fatalf("policies %v names rbi_pii_protection: a verdict must not be captioned with a control the engine that decided it never applied", r.strings(t, "policies"))
	}
}

// TestGatewayPreCheckFailsClosedNamingEachCause drives every fail-closed cause
// a pre-check can reach and reads the encoded 503.
func TestGatewayPreCheckFailsClosedNamingEachCause(t *testing.T) {
	enfSetup(t)
	good := enfPublishDocument(t, enfSnapshot(t))
	cases := []struct {
		name, org, cause, leak string
		arrange                func(t *testing.T)
	}{
		{name: "the organization's active document cannot be read", org: enfOrgBroken, cause: enforceCauseActiveDocument, leak: "unreachable", arrange: func(*testing.T) {}},
		{name: "no enforcer is wired in this process", org: enfOrgPublished, cause: enforceCauseNotWired, arrange: func(t *testing.T) {
			prev := anchoredEnforcerInstance.Load()
			anchoredEnforcerInstance.Store(nil)
			t.Cleanup(func() { anchoredEnforcerInstance.Store(prev) })
		}},
		{name: "the deployment vocabulary cannot be resolved", org: enfOrgPublished, cause: enforceCauseActivation, leak: "the catalog is unreadable", arrange: func(t *testing.T) {
			enfInstallSeamWith(t, good, func() (*authoringcatalog.Snapshot, error) { return nil, errors.New("the catalog is unreadable") })
		}},
		{name: "the active document cannot be loaded", org: enfOrgPublished, cause: enforceCauseActivation, leak: "the artifact row is unreadable", arrange: func(t *testing.T) {
			enfInstallSeam(t, enfUnloadableDocuments{good})
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			c.arrange(t)
			counter := anchoredEnforceDecisions.WithLabelValues(gatewayRequestSeamScope.String(), decisionEngineAnchored, "unavailable", c.cause)
			before := testutil.ToFloat64(counter)
			r := enfPreCheck(t, c.org, enfMintUserToken(t, c.org, enfUser), "What is the weather today?")
			if r.code != http.StatusServiceUnavailable || r.approved(t) || r.str(t, "verdict") != VerdictDeny {
				t.Fatalf("got HTTP %d approved=%v verdict %q; want the 503 fail-closed refusal. body=%s", r.code, r.approved(t), r.str(t, "verdict"), r.raw)
			}
			if got, want := r.str(t, "block_reason"), enforceCauseMessages[c.cause]; got != want {
				t.Fatalf("the 503 says %q; want the %s cause, %q", got, c.cause, want)
			}
			if r.str(t, "engine") != decisionEngineAnchored {
				t.Fatalf("engine=%q; a fail-closed refusal is the anchored engine's. body=%s", r.str(t, "engine"), r.raw)
			}
			r.noMode(t)
			if c.leak != "" && strings.Contains(string(r.raw), c.leak) {
				t.Fatalf("the 503 leaked the underlying error to the caller: %s", r.raw)
			}
			if after := testutil.ToFloat64(counter); after != before+1 {
				t.Fatalf("the unavailable counter for %s moved %v -> %v; want +1", c.cause, before, after)
			}
		})
	}

	t.Run("CONTROL: with nothing broken the same request is decided by the anchored engine", func(t *testing.T) {
		r := enfPreCheck(t, enfOrgPublished, enfMintUserToken(t, enfOrgPublished, enfUser), "What is the weather today?")
		if r.code != http.StatusOK || r.str(t, "engine") != decisionEngineAnchored {
			t.Fatalf("got HTTP %d engine %q; want 200 from the anchored engine. body=%s", r.code, r.str(t, "engine"), r.raw)
		}
	})
}

// TestGatewayPreCheckWritesEngineSubjectTypeAndBundleOnTheAuditRow reads the
// decision RECORD the pre-check writes, for a published document and for the
// implicit baseline.
func TestGatewayPreCheckWritesEngineSubjectTypeAndBundleOnTheAuditRow(t *testing.T) {
	enfSetup(t)
	for _, org := range []string{enfOrgPublished, enfOrgImplicit} {
		t.Run(org, func(t *testing.T) {
			mock := withMockUsageDB(t)
			mock.MatchExpectationsInOrder(false)
			mock.ExpectExec("INSERT INTO audit_logs").
				WithArgs(
					sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
					sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
					"decision_llm", sqlmock.AnyArg(), sqlmock.AnyArg(),
					gatewayAuditAllowed,
					enfPostureMatcher{engine: decisionEngineAnchored, subjectType: string(sharedidentity.SubjectUser)},
					sqlmock.AnyArg(), PlaneGateway, sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
					nil, sqlmock.AnyArg(),
				).
				WillReturnResult(sqlmock.NewResult(0, 1))
			r := enfPreCheck(t, org, enfMintUserToken(t, org, enfUser), "What is the weather today?")
			if r.code != http.StatusOK || !r.approved(t) {
				t.Fatalf("HTTP %d approved=%v: %s", r.code, r.approved(t), r.raw)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatalf("the audit row did not record the engine, the subject type and a policy bundle: %v", err)
			}
		})
	}
}

// TestTheRequestPassProjectionTellsOnlyWhatItsWireCarries holds the projection
// to the renderer it projects: every obligation below is produced by
// redactObligationFor for a request scope, so a change to how a field_redact is
// rendered moves these cases with it.
//
// EVERY WIRE IS JUDGED ON THE SAME INPUT. The pre-check can instruct a
// redaction of the request and /api/request and the OpenAI-compatible route
// cannot, so the identical decision must be approved with the instruction on
// one and REFUSED on the others; a projection that ignored its wire would pass
// one of them.
func TestTheRequestPassProjectionTellsOnlyWhatItsWireCarries(t *testing.T) {
	redaction := func(target string) DecisionObligation {
		return redactObligationFor(contract.Obligation{Type: contract.ObFieldRedact, Target: target, Mandatory: true, SchemaVersion: 1, SourcePolicy: "org:pii"}, gatewayRequestSeamScope)
	}
	allow := requestPassEnforcement{engine: decisionEngineAnchored, verdict: VerdictAllow, reasonCode: "permitted", evaluatedPolicies: []string{"org:pii"}}
	scopes := []legacycompile.EnforcementScope{gatewayRequestSeamScope, proxyRequestSeamScope, openaiCompatibleSeamScope}

	t.Run("an allow with no obligation is approved on every wire, with nothing to redact", func(t *testing.T) {
		for _, scope := range scopes {
			got, code := allow.staticPolicyResult(scope)
			if got.Blocked || got.RequiresRedaction || code != "permitted" {
				t.Fatalf("%s: blocked=%v requires_redaction=%v code=%q; want an approval under the engine's reason", scope, got.Blocked, got.RequiresRedaction, code)
			}
		}
	})

	t.Run("a redaction of the evaluated content is told where the wire carries it, and refuses where it does not", func(t *testing.T) {
		in := allow
		in.obligations = []DecisionObligation{redaction(legacycompile.DefaultContentTarget)}

		told, code := in.staticPolicyResult(gatewayRequestSeamScope)
		if told.Blocked || !told.RequiresRedaction || code != "permitted" {
			t.Fatalf("the pre-check: blocked=%v requires_redaction=%v code=%q; want an approval that instructs the redaction", told.Blocked, told.RequiresRedaction, code)
		}
		for scope, wire := range map[legacycompile.EnforcementScope]string{proxyRequestSeamScope: proxyRequestWire, openaiCompatibleSeamScope: openaiCompatibleWire} {
			refused, code := in.staticPolicyResult(scope)
			if !refused.Blocked || refused.RequiresRedaction || code != string(contract.ReasonUnsupportedObligation) {
				t.Fatalf("%s: blocked=%v requires_redaction=%v code=%q; a wire that cannot tell the redaction must refuse the request", scope, refused.Blocked, refused.RequiresRedaction, code)
			}
			if !strings.Contains(refused.Reason, wire) {
				t.Fatalf("%s: reason %q does not name the wire that could not carry the obligation", scope, refused.Reason)
			}
		}
	})

	t.Run("a redaction fulfilled after the call is refused on every wire", func(t *testing.T) {
		in := allow
		in.obligations = []DecisionObligation{redaction(legacycompile.DefaultContentTarget), redaction("response.ssn")}
		for _, scope := range scopes {
			got, code := in.staticPolicyResult(scope)
			if !got.Blocked || got.RequiresRedaction {
				t.Fatalf("%s: blocked=%v requires_redaction=%v; a redaction this wire cannot tell must refuse, and withhold the instruction", scope, got.Blocked, got.RequiresRedaction)
			}
			if code != string(contract.ReasonUnsupportedObligation) || !strings.HasPrefix(got.Reason, string(contract.ReasonUnsupportedObligation)+": ") {
				t.Fatalf("%s: code=%q reason=%q; want the refusal recorded and explained as %s", scope, code, got.Reason, contract.ReasonUnsupportedObligation)
			}
		}
	})

	t.Run("a deny is refused on every wire with the engine's reasons, and names its policies", func(t *testing.T) {
		deny := requestPassEnforcement{engine: decisionEngineAnchored, verdict: VerdictDeny, reasonCode: string(contract.ReasonExplicitConstraint),
			reasons: []string{string(contract.ReasonExplicitConstraint)}, evaluatedPolicies: []string{"corpus:static_policies:sys__sqli"}}
		for _, scope := range scopes {
			got, code := deny.staticPolicyResult(scope)
			if !got.Blocked || got.Reason != string(contract.ReasonExplicitConstraint) || code != string(contract.ReasonExplicitConstraint) {
				t.Fatalf("%s: blocked=%v reason=%q code=%q; want the constraint refusal", scope, got.Blocked, got.Reason, code)
			}
			if !slices.Equal(got.TriggeredPolicies, deny.evaluatedPolicies) {
				t.Fatalf("%s: triggered %v; want the decision's %v", scope, got.TriggeredPolicies, deny.evaluatedPolicies)
			}
		}
	})
}
