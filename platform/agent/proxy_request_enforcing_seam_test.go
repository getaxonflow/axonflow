// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"axonflow/platform/decision/activation"
	"axonflow/platform/decision/authoringcatalog"
	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/pdp"
	"axonflow/platform/decision/registry"
	"axonflow/platform/orchestrator/cost"
	sharedidentity "axonflow/platform/shared/identity"
	sharedpolicy "axonflow/platform/shared/policy"
)

// THE PROXY'S PHASE 1 ENFORCING SEAM, THROUGH THE REAL HANDLER (#3564 wave
// two). The fixtures are the decide seam's - the same published document, the
// same implicit baseline and the same shipped detectors - and the licence,
// orchestrator plumbing is the proxy suite's.
//
// THE USER TOKEN IS THE PRODUCTION CLAIM SET (enfMintUserToken), not this
// suite's generateTestJWT: the legacy body-token shape carries no issuer, so the
// identity plane cannot admit it as a user and every anchored assertion below
// would be measuring a subject refusal instead of a grant.

// enfProxyClientFor is the credential the organization's requests authenticate
// with. One per organization, because a licence is bound to one org_id.
func enfProxyClientFor(org string) string { return "w3d-proxy-" + org }

// enfProxySetup wires the decide seam's fixtures plus what /api/request needs:
// an orchestrator to forward to and a licence per organization.
func enfProxySetup(t *testing.T) {
	t.Helper()
	enfSetup(t)
	if agentMetrics == nil {
		agentMetrics = &AgentMetrics{
			latencies:              []int64{},
			lastLatencies:          []int64{},
			staticPolicyLatencies:  []int64{},
			dynamicPolicyLatencies: []int64{},
		}
	}
	prevCost := costService
	costService = nil
	t.Cleanup(func() { costService = prevCost })

	orch := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"success": true, "result": "forwarded"})
	}))
	t.Cleanup(orch.Close)
	prevURL := orchestratorURL
	orchestratorURL = orch.URL
	t.Cleanup(func() { orchestratorURL = prevURL })

	for _, org := range []string{enfOrgPublished, enfOrgImplicit, enfOrgBroken} {
		clientID := enfProxyClientFor(org)
		knownClients[clientID] = &ClientAuth{
			ClientID:    clientID,
			LicenseKey:  generateTestLicenseKey(org, "Enterprise", "20351231"),
			Name:        clientID,
			TenantID:    org,
			Permissions: []string{"query", "llm"},
			RateLimit:   1000,
			Enabled:     true,
		}
		t.Cleanup(func() { delete(knownClients, clientID) })
	}
}

// enfProxy drives one /api/request through clientRequestHandler, authenticated
// by the organization's licence, with the user token given ("" for none).
func enfProxy(t *testing.T, org, userToken, query string) enfResponse {
	t.Helper()
	clientID := enfProxyClientFor(org)
	body, err := json.Marshal(ClientRequest{ClientID: clientID, RequestType: "sql", Query: query, UserToken: userToken})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("POST", "/api/request", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	setOAuth2BasicAuth(req, clientID, knownClients[clientID].LicenseKey)
	rr := httptest.NewRecorder()
	clientRequestHandler(rr, req)
	out := enfResponse{code: rr.Code, raw: rr.Body.Bytes(), body: map[string]json.RawMessage{}}
	if err := json.Unmarshal(rr.Body.Bytes(), &out.body); err != nil {
		t.Fatalf("the response is not a JSON object: %v\n%s", err, rr.Body.String())
	}
	return out
}

// blocked reads /api/request's refusal flag, failing when it is absent.
func (r enfResponse) blocked(t *testing.T) bool {
	t.Helper()
	v, ok := r.body["blocked"]
	if !ok {
		t.Fatalf("the response carries no blocked member: %s", r.raw)
	}
	var b bool
	if err := json.Unmarshal(v, &b); err != nil {
		t.Fatalf("member blocked is not a boolean: %s", v)
	}
	return b
}

// enfProxyMatchedPolicies is the ids the response attributes its verdict to.
func enfProxyMatchedPolicies(t *testing.T, r enfResponse) []string {
	t.Helper()
	var info struct {
		MatchedPolicies []string `json:"matched_policies"`
	}
	raw, ok := r.body["policy_info"]
	if !ok {
		return nil
	}
	if err := json.Unmarshal(raw, &info); err != nil {
		t.Fatalf("policy_info is not readable: %s", raw)
	}
	return info.MatchedPolicies
}

// enfProxyConstraintPolicy is the policy id the proxy restriction keeps for the
// fixture's constraint detector.
func enfProxyConstraintPolicy(t *testing.T) string {
	t.Helper()
	row, _ := enfConstraintPolicy(t)
	for _, c := range enfScopeControls(t, proxyRequestSeamScope) {
		if c.row.PolicyID == row {
			return c.policy.ID
		}
	}
	t.Fatalf("the proxy restriction keeps no policy reading %s, the constraint the fixture installs", row)
	return ""
}

// enfProxyCounted sums the proxy_request decision series for the verdicts and
// reasons a request through the seam produces.
func enfProxyCounted(t *testing.T) float64 {
	t.Helper()
	total := 0.0
	for _, engine := range []string{decisionEngineAnchored} {
		for _, verdict := range []string{VerdictAllow, VerdictDeny, VerdictNeedsApproval, "unavailable"} {
			for _, reason := range []string{string(contract.ReasonPermitted), "subject_type_rejected", string(contract.ReasonNoMatchingPermission)} {
				total += testutil.ToFloat64(anchoredEnforceDecisions.WithLabelValues(proxyRequestSeamScope.String(), engine, verdict, reason))
			}
		}
	}
	return total
}

func TestProxyRequestEnforcingSeam(t *testing.T) {
	enfProxySetup(t)
	constraintPolicy := enfProxyConstraintPolicy(t)
	implicitBundle := enfImplicitBundle(t, proxyRequestSeamScope, enfOrgImplicit)
	alice := func(org string) string { return enfMintUserToken(t, org, enfUser) }

	t.Run("a published document + verified user: the ANCHORED engine allows, and the body says so", func(t *testing.T) {
		counter := anchoredEnforceDecisions.WithLabelValues(proxyRequestSeamScope.String(), decisionEngineAnchored, VerdictAllow, string(contract.ReasonPermitted))
		before := testutil.ToFloat64(counter)
		r := enfProxy(t, enfOrgPublished, alice(enfOrgPublished), "SELECT id FROM products")
		if r.code != http.StatusOK || r.blocked(t) {
			t.Fatalf("got HTTP %d blocked=%v; want the forwarded request. body=%s", r.code, r.blocked(t), r.raw)
		}
		if r.str(t, "engine") != decisionEngineAnchored || r.str(t, "subject_type") != string(sharedidentity.SubjectUser) {
			t.Fatalf("engine=%q subject_type=%q; want anchored/User. body=%s", r.str(t, "engine"), r.str(t, "subject_type"), r.raw)
		}
		r.noMode(t)
		if bundle := r.str(t, "policy_bundle"); bundle == "" || bundle == implicitBundle {
			t.Fatalf("policy_bundle %q; want the published document's bundle, not the implicit baseline's %q", bundle, implicitBundle)
		}
		if after := testutil.ToFloat64(counter); after != before+1 {
			t.Fatalf("the proxy_request allow counter moved %v -> %v; want +1", before, after)
		}
	})

	t.Run("a published document: a principal it constrains is REFUSED explicit_constraint, naming the constraint", func(t *testing.T) {
		r := enfProxy(t, enfOrgPublished, enfMintUserToken(t, enfOrgPublished, enfBob), "SELECT id FROM products")
		if r.code != http.StatusForbidden || !r.blocked(t) || r.str(t, "engine") != decisionEngineAnchored {
			t.Fatalf("got HTTP %d blocked=%v engine=%q; want a 403 from the anchored engine. body=%s", r.code, r.blocked(t), r.str(t, "engine"), r.raw)
		}
		if got := r.str(t, "block_reason"); got != string(contract.ReasonExplicitConstraint) {
			t.Fatalf("block_reason %q; want %s", got, contract.ReasonExplicitConstraint)
		}
		if matched := enfProxyMatchedPolicies(t, r); len(matched) == 0 || matched[0] != "ceiling.block_bob" {
			t.Fatalf("matched_policies %v; bob's constraint must decide", matched)
		}
	})

	t.Run("a published document: content a shipped block control detects is REFUSED by that constraint, named first", func(t *testing.T) {
		r := enfProxy(t, enfOrgPublished, alice(enfOrgPublished), "please run "+enfConstraintProbe+" now")
		if r.code != http.StatusForbidden || !r.blocked(t) || r.str(t, "engine") != decisionEngineAnchored {
			t.Fatalf("got HTTP %d blocked=%v engine=%q; want a 403 from the anchored engine. body=%s", r.code, r.blocked(t), r.str(t, "engine"), r.raw)
		}
		if got := r.str(t, "block_reason"); got != string(contract.ReasonExplicitConstraint) {
			t.Fatalf("block_reason %q; want %s", got, contract.ReasonExplicitConstraint)
		}
		if matched := enfProxyMatchedPolicies(t, r); len(matched) == 0 || matched[0] != constraintPolicy {
			t.Fatalf("matched_policies %v; the blocking shipped control %s must come first", matched, constraintPolicy)
		}
	})

	t.Run("an organization that has published nothing is decided under the implicit baseline, named by its digest", func(t *testing.T) {
		r := enfProxy(t, enfOrgImplicit, alice(enfOrgImplicit), "SELECT id FROM products")
		if r.code != http.StatusOK || r.blocked(t) || r.str(t, "engine") != decisionEngineAnchored {
			t.Fatalf("got HTTP %d blocked=%v engine=%q; want the anchored engine's forward. body=%s", r.code, r.blocked(t), r.str(t, "engine"), r.raw)
		}
		if got := r.str(t, "policy_bundle"); got != implicitBundle {
			t.Fatalf("policy_bundle %q; want the implicit baseline's %q", got, implicitBundle)
		}
	})

	t.Run("an Enterprise caller presenting NO user token is refused at the authentication boundary, before any engine counts it", func(t *testing.T) {
		before := enfProxyCounted(t)
		r := enfProxy(t, enfOrgPublished, "", "SELECT id FROM products")
		if r.code != http.StatusUnauthorized {
			t.Fatalf("got HTTP %d; an Enterprise /api/request with no user token is refused 401 before any policy runs. body=%s", r.code, r.raw)
		}
		if after := enfProxyCounted(t); after != before {
			t.Fatalf("the proxy decisions moved %v -> %v for a request the handler refused before the seam", before, after)
		}
	})

	// PRD v11 §1.6. A community deployment synthesizes a user from no
	// credential, so the client credential is the principal. ITS ORG IS THE
	// DEPLOYMENT'S, not the licence's (Authenticate's community branch reads
	// getDeploymentOrgID), so the organization under test is set through ORG_ID.
	t.Run("where no user identity can be verified, the credential is the principal, recorded as a Client, token or no token", func(t *testing.T) {
		t.Setenv("DEPLOYMENT_MODE", "community")
		for _, token := range []string{"", "not-a-token-the-deployment-could-verify"} {
			t.Setenv("ORG_ID", enfOrgImplicit)
			implicit := enfProxy(t, enfOrgImplicit, token, "SELECT id FROM products")
			if implicit.code != http.StatusOK || implicit.blocked(t) || implicit.str(t, "subject_type") != string(sharedidentity.SubjectClient) {
				t.Fatalf("token %q under the implicit baseline: HTTP %d blocked=%v subject_type %q; want the forward for a Client. body=%s",
					token, implicit.code, implicit.blocked(t), implicit.str(t, "subject_type"), implicit.raw)
			}
			t.Setenv("ORG_ID", enfOrgPublished)
			published := enfProxy(t, enfOrgPublished, token, "SELECT id FROM products")
			if published.code != http.StatusOK || published.blocked(t) || published.str(t, "subject_type") != string(sharedidentity.SubjectClient) {
				t.Fatalf("token %q under a document whose constraints name alice and bob: HTTP %d blocked=%v subject_type %q; want the forward for a Client, whom neither names. body=%s",
					token, published.code, published.blocked(t), published.str(t, "subject_type"), published.raw)
			}
		}
	})
}

// TestProxyRequestFailsClosedNamingEachCause drives every fail-closed cause a
// proxy request can reach and reads the encoded 503.
func TestProxyRequestFailsClosedNamingEachCause(t *testing.T) {
	enfProxySetup(t)
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
			counter := anchoredEnforceDecisions.WithLabelValues(proxyRequestSeamScope.String(), decisionEngineAnchored, "unavailable", c.cause)
			before := testutil.ToFloat64(counter)
			r := enfProxy(t, c.org, enfMintUserToken(t, c.org, enfUser), "SELECT id FROM products")
			if r.code != http.StatusServiceUnavailable || !r.blocked(t) {
				t.Fatalf("got HTTP %d blocked=%v; want the 503 fail-closed refusal. body=%s", r.code, r.blocked(t), r.raw)
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
		r := enfProxy(t, enfOrgPublished, enfMintUserToken(t, enfOrgPublished, enfUser), "SELECT id FROM products")
		if r.code != http.StatusOK || r.str(t, "engine") != decisionEngineAnchored {
			t.Fatalf("got HTTP %d engine=%q; want 200 from the anchored engine. body=%s", r.code, r.str(t, "engine"), r.raw)
		}
	})
}

// TestProxyRequestWritesEngineSubjectTypeAndBundleOnTheAuditRow reads the
// decision RECORD a refused proxy request writes, for a published document and
// for the implicit baseline. A refusal, because an allowed /api/request is
// audited by the orchestrator it is forwarded to, not here.
func TestProxyRequestWritesEngineSubjectTypeAndBundleOnTheAuditRow(t *testing.T) {
	enfProxySetup(t)
	for _, org := range []string{enfOrgPublished, enfOrgImplicit} {
		t.Run(org, func(t *testing.T) {
			mock := withMockUsageDB(t)
			mock.MatchExpectationsInOrder(false)
			mock.ExpectExec("INSERT INTO audit_logs").
				WithArgs(
					sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
					sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
					"decision_llm", sqlmock.AnyArg(), sqlmock.AnyArg(),
					AuditVerdictBlocked,
					enfPostureMatcher{engine: decisionEngineAnchored, subjectType: string(sharedidentity.SubjectUser)},
					sqlmock.AnyArg(), PlaneAgent, sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(),
					nil, sqlmock.AnyArg(),
				).
				WillReturnResult(sqlmock.NewResult(0, 1))
			r := enfProxy(t, org, enfMintUserToken(t, org, enfUser), "please run "+enfConstraintProbe+" now")
			if r.code != http.StatusForbidden || !r.blocked(t) {
				t.Fatalf("HTTP %d blocked=%v: the constraint must refuse this request. body=%s", r.code, r.blocked(t), r.raw)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatalf("the audit row did not record the engine, the subject type and a policy bundle: %v", err)
			}
		})
	}
}

// TestAProxyBudgetRefusalOfAnAnchoredApprovalCarriesTheEngineAndIsCounted holds
// the exit no policy engine decides: the budget refuses a request the anchored
// engine approved, and that refusal must still say which engine approved it and
// be countable under its own reason.
func TestAProxyBudgetRefusalOfAnAnchoredApprovalCarriesTheEngineAndIsCounted(t *testing.T) {
	enfProxySetup(t)
	costService = cost.NewService(&mockCostRepository{
		budgets: map[string]*cost.Budget{
			"budget-proxy-published": {
				ID: "budget-proxy-published", Name: "proxy published budget", Scope: cost.ScopeOrganization, ScopeID: enfOrgPublished,
				LimitUSD: 100, Period: cost.PeriodMonthly, OnExceed: cost.OnExceedBlock,
				OrgID: enfOrgPublished, TenantID: enfOrgPublished, Enabled: true,
			},
		},
		usageSum: map[string]float64{"organization:" + enfOrgPublished: 150},
	}, nil)

	counter := anchoredEnforceDecisions.WithLabelValues(proxyRequestSeamScope.String(), decisionEngineAnchored, VerdictDeny, enforceReasonBudgetExceeded)
	before := testutil.ToFloat64(counter)
	r := enfProxy(t, enfOrgPublished, enfMintUserToken(t, enfOrgPublished, enfUser), "SELECT id FROM products")
	if r.code != http.StatusPaymentRequired || !r.blocked(t) {
		t.Fatalf("got HTTP %d blocked=%v; want the 402 budget refusal. body=%s", r.code, r.blocked(t), r.raw)
	}
	if r.str(t, "engine") != decisionEngineAnchored {
		t.Fatalf("engine=%q; the budget refusal of an anchored approval must say which engine approved it. body=%s", r.str(t, "engine"), r.raw)
	}
	r.noMode(t)
	if after := testutil.ToFloat64(counter); after != before+1 {
		t.Fatalf("the final deny under the budget reason moved %v -> %v; want +1", before, after)
	}
}

// administratorSkipHiddenControls names the controls a restriction keeps whose
// detector sits in a category the caller's evaluation SKIPPED. It is a pure
// function of (restriction, census, skipped categories) so the test below can
// drive it with planted data and watch it report - the guard it replaces could
// not fail, and a guard nobody has seen fail is worth nothing.
func administratorSkipHiddenControls(doc *pdp.Document, byPath map[string]registry.CensusRow, skipped map[string]bool) []string {
	var hidden []string
	for _, p := range doc.Policies {
		for _, path := range p.ReferencedPaths() {
			if r, ok := byPath[path]; ok && skipped[r.Category] {
				hidden = append(hidden, p.ID)
				break
			}
		}
	}
	return hidden
}

// TestTheProxyRestrictionBindsNoRedaction measures the population of the one
// divergence this plane has that the legacy engine cannot express: /api/request
// tells its caller no obligation, so the anchored engine REFUSES a decision
// carrying a field_redact (unsupported_obligation) where the legacy engine -
// which never reads RequiresRedaction on this plane - forwards the request
// unredacted.
//
// The count is ZERO today, which is exactly why this guard is written
// population-first. A zero that nobody can distinguish from "the restriction is
// empty" or "the obligation type is spelled differently" is not evidence, so the
// restriction is asserted non-empty first, the counting is proven able to find
// obligations on a scope that HAS them, and a planted obligation must be
// reported. Without those three, "0 redactions" would pass against a broken
// count for as long as it stayed broken.
//
// THE POPULATION IS EVERYTHING THE SCOPE DECIDES WITH (#4131): the system
// restriction AND the organization template the implicit bundle composes
// restricted to this scope. Counting the system restriction alone could never
// see a template control, and eu_gdpr_cross_border_pii bound a mandatory
// field_redact here unseen until the template was counted.
func TestTheProxyRestrictionBindsNoRedaction(t *testing.T) {
	system, _, err := activation.RestrictToScope(proxyRequestSeamScope)
	if err != nil {
		t.Fatal(err)
	}
	template, err := activation.OrganizationTemplateForScope(proxyRequestSeamScope)
	if err != nil {
		t.Fatal(err)
	}
	// THE POPULATION, FIRST, and each half of it on its own.
	if len(system.Policies) == 0 || len(template.Policies) == 0 {
		t.Fatalf("the proxy restriction keeps %d system and %d template policies; a half that keeps none would be judged by nothing", len(system.Policies), len(template.Policies))
	}
	doc := &pdp.Document{Root: system.Root, Version: system.Version,
		Policies: append(append([]pdp.Policy(nil), system.Policies...), template.Policies...)}

	redactions := func(d *pdp.Document) []string {
		var out []string
		for _, pol := range d.Policies {
			for _, o := range pol.Obligations {
				if o.Type == contract.ObFieldRedact {
					out = append(out, fmt.Sprintf("%s(mandatory=%v)", pol.ID, o.Mandatory))
				}
			}
		}
		return out
	}

	if got := redactions(doc); len(got) != 0 {
		t.Fatalf("the proxy restriction keeps %d control(s) carrying a field_redact obligation %v. On this wire the anchored engine REFUSES each one "+
			"(unsupported_obligation) while the legacy engine forwards the request unredacted, so this is a behavioural divergence on %d shipped "+
			"control(s) and must be stated in the seam header, the PR body and the CHANGELOG before it ships.", len(got), got, len(got))
	}
	t.Logf("proxy_request keeps %d controls, 0 carrying field_redact", len(doc.Policies))

	// THE COUNTING WORKS: a scope that HAS redactions must report them, or the
	// zero above is a property of the counter rather than of this plane.
	respDoc, _, err := activation.RestrictToScope(mcpResponseSeamScope)
	if err != nil {
		t.Fatal(err)
	}
	if got := redactions(respDoc); len(got) == 0 {
		t.Fatalf("mcp:response reported 0 field_redact obligations; it carries them, so the counter above is not measuring what it claims")
	} else {
		t.Logf("control: mcp:response keeps %d controls, %d carrying field_redact", len(respDoc.Policies), len(got))
	}

	// THE PLANT: a field_redact attached to a control this restriction DOES keep
	// must be reported, or the assertion above cannot fail.
	planted := *doc
	planted.Policies = append([]pdp.Policy(nil), doc.Policies...)
	planted.Policies[0].Obligations = append([]contract.Obligation(nil), planted.Policies[0].Obligations...)
	planted.Policies[0].Obligations = append(planted.Policies[0].Obligations, contract.Obligation{Type: contract.ObFieldRedact, Mandatory: true})
	if got := redactions(&planted); len(got) != 1 {
		t.Fatalf("with a field_redact planted on %s the census reported %v; want exactly one. A guard that cannot report a redaction cannot be "+
			"trusted when it reports none.", planted.Policies[0].ID, got)
	}
}

// TestTheProxyRestrictionKeepsNoControlTheAdministratorSkipHides mechanises the
// measurement behind this seam's admin-access note.
//
// Phase 1 drops sharedpolicy.CategoryAdminAccess for an administrative caller,
// and a detector that did not run reaches the anchored engine as ABSENT, which
// it reads as UNKNOWN. A control reading such a detector would therefore refuse
// every administrator's request.
//
// THE FIRST VERSION OF THIS TEST COULD NOT FAIL. It swept for census rows whose
// category equalled the constant ("admin-access"); the shipped rows spell theirs
// "security-admin" (core/031), so it matched nothing and passed. So this asserts
// the POPULATION first, sweeps on both spellings, and plants a control it must
// report.
func TestTheProxyRestrictionKeepsNoControlTheAdministratorSkipHides(t *testing.T) {
	rows, err := registry.ShippedCensus()
	if err != nil {
		t.Fatal(err)
	}
	byPath := map[string]registry.CensusRow{}
	for _, r := range rows {
		byPath[registry.DetectorID(r.PolicyID).SignalPath()] = r
	}
	doc, _, err := activation.RestrictToScope(proxyRequestSeamScope)
	if err != nil {
		t.Fatal(err)
	}
	if len(byPath) == 0 || len(doc.Policies) == 0 {
		t.Fatalf("census paths %d, restriction policies %d; every assertion below would judge nothing", len(byPath), len(doc.Policies))
	}

	// THE POPULATION, FIRST. The census's own administrative rows must exist, or
	// "none of them is hidden" is a statement about an empty set. Their category
	// is read from the census rather than named here, so a rename fails loudly.
	censusAdminCategories := map[string]bool{}
	adminRows := 0
	for _, r := range rows {
		if strings.Contains(r.PolicyID, "sys_admin_") {
			censusAdminCategories[r.Category] = true
			adminRows++
		}
	}
	if adminRows == 0 || len(censusAdminCategories) == 0 {
		t.Fatal("the shipped census carries no sys_admin_* row, so this guard is watching a population that does not exist")
	}
	t.Logf("census administrative rows: %d, categories %v; the skip removes %q", adminRows, censusAdminCategories, sharedpolicy.CategoryAdminAccess)

	// 1. Nothing the restriction keeps is hidden by the skip's own category.
	if hidden := administratorSkipHiddenControls(doc, byPath, map[string]bool{string(sharedpolicy.CategoryAdminAccess): true}); len(hidden) != 0 {
		t.Fatalf("the proxy restriction keeps %d control(s) reading a detector in the category Phase 1 skips for an administrator (%v). Each would reach "+
			"the anchored engine UNKNOWN and refuse every administrator's request.", len(hidden), hidden)
	}

	// 2. WHAT IT KEEPS UNDER THE CENSUS'S OWN SPELLING IS EXACTLY THE FOUR
	// sys_admin_* BLOCKS (#4253). /api/request admits security-admin on this
	// plane alone, so the category filter no longer drops them, and the skip
	// removes admin-access, not security-admin, so their detectors run for an
	// administrator and the administrator is refused, as the retired tier pass
	// refused one.
	kept := administratorSkipHiddenControls(doc, byPath, censusAdminCategories)
	wantKept := map[string]bool{
		"corpus:static_policies:sys__admin__audit__log:block":    true,
		"corpus:static_policies:sys__admin__config__table:block": true,
		"corpus:static_policies:sys__admin__info__schema:block":  true,
		"corpus:static_policies:sys__admin__users__table:block":  true,
	}
	matched := 0
	for _, id := range kept {
		if wantKept[id] {
			matched++
		}
	}
	if len(kept) != len(wantKept) || matched != len(wantKept) {
		t.Fatalf("the proxy restriction keeps administrative control(s) %v under the census's own categories %v; want exactly the four sys_admin_* "+
			":block policies, the controls the retired tier pass refused an administrator on", kept, censusAdminCategories)
	}

	// 3. THE PLANT: a control the restriction DOES keep, moved into the skipped
	// category, must be reported - otherwise assertions 1 and 2 are vacuous.
	var plantedPolicy, plantedPath string
	for _, pol := range doc.Policies {
		for _, path := range pol.ReferencedPaths() {
			if _, ok := byPath[path]; ok {
				plantedPolicy, plantedPath = pol.ID, path
				break
			}
		}
		if plantedPolicy != "" {
			break
		}
	}
	if plantedPolicy == "" {
		t.Fatal("no policy in the restriction reads a censused detector, so the plant below could not be built")
	}
	planted := map[string]registry.CensusRow{}
	for path, row := range byPath {
		if path == plantedPath {
			row.Category = string(sharedpolicy.CategoryAdminAccess)
		}
		planted[path] = row
	}
	got := administratorSkipHiddenControls(doc, planted, map[string]bool{string(sharedpolicy.CategoryAdminAccess): true})
	if len(got) != 1 || got[0] != plantedPolicy {
		t.Fatalf("with %s's detector planted into the skipped category the guard reported %v; want exactly [%s]. A guard that cannot report a "+
			"hidden control cannot be trusted when it reports none.", plantedPolicy, got, plantedPolicy)
	}
}
