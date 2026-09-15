// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/mux"

	"axonflow/platform/decision/authoring"
	"axonflow/platform/decision/authoringcatalog"
	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/pdp"
	"axonflow/platform/shared/authoringvocabulary"
	"axonflow/platform/shared/identity"
)

// These tests drive the ROUTE, through a router, on a community-mode binary.
//
// That last part is the DoD's own condition and it is worth saying what makes
// it true rather than asserting it: this file carries no build tag, so `go test
// ./platform/orchestrator/` with no -tags compiles it into the community build
// and every request below goes through mux.Router and net/http exactly as a
// proxied request does. Nothing here calls a handler method directly except the
// two tests whose subject IS the handler's internal state (workspace eviction
// and the edition rebuild), and those say so.
//
// A test that imported platform/decision/authoring and published in-process
// would prove the LIBRARY works on a community build, which was never in doubt
// - it is what ee/platform/customer-portal already does on the enterprise one.
// What #3907 is about is whether a community DEPLOYMENT has a way in.

const (
	testOrg   = "org-community"
	testUser  = "admin"
	testDocID = "org-baseline"
	// THE DEPLOYMENT VOCABULARY, not the conformance fixture (#3895). These
	// tests drive ACTIVATION, and a fixture vocabulary may be published against
	// and can never be activated - so a fixture here would make every
	// activation assertion a test of the fixture refusal instead of the thing
	// it names. The realm is the one the route stamps authors in.
	testRealm   = "axonflow-trusted-header"
	testAction  = "Action::tool.call"
	testPrinc   = "User::" + testRealm + ":alice"
	testGroupID = "Group::" + testRealm + ":finance"
)

var fixtureObservedAt = time.Unix(1_700_000_000, 0).UTC()

// newRouteHandler builds an available handler at a named edition, with no
// database behind the admission wiring.
//
// tierAdmitter is left NIL on purpose for the unit tests: admitOrgRootPolicies
// then admits by default and counts the unwired metric, which is the shipped
// behaviour during the boot window and keeps these tests about the ROUTE. The
// ceiling itself is driven against a real Postgres ledger in
// typed_authoring_limit_realpg_test.go, because a limit asserted against a fake
// counter is an assertion about the fake.
func newRouteHandler(t *testing.T, edition authoring.Edition) *TypedAuthoringRouteHandler {
	t.Helper()
	h := &TypedAuthoringRouteHandler{
		// nil ON PURPOSE: this helper builds the IN-PROCESS posture, which is
		// what every test below asserts against. A durable workspace needs a
		// real postgres and lives in the runtime suite, not here. Named
		// explicitly because TestEveryTypedAuthoringHandlerLiteralDeclaresItsDB
		// requires every literal to say which posture it is.
		db:           nil,
		catalogValue: authoringcatalog.SourceDeployment,
		deploymentFor: func() authoringvocabulary.CatalogDeployment {
			return authoringvocabulary.CatalogDeployment{HasDirectory: true}
		},
		profileFor: func(context.Context) authoring.Profile { return mustProfile(t, edition) },
		workspaces: map[string]*typedAuthoringWorkspace{},
	}
	// RESOLVED THROUGH THE HANDLER'S OWN LAZY PATH, not by assigning its
	// fields: these tests are about the route, and a hand-assembled handler
	// would stop exercising the resolution the route actually performs.
	snap, err := h.vocabulary()
	if err != nil || snap == nil {
		t.Fatalf("the deployment vocabulary must resolve: %v", err)
	}
	return h
}

// mustProfile is authoring.ProfileFor with the error handled. It always builds
// an ESTABLISHED profile: a test that means "this process could not establish
// its tier" says so with authoring.ProfileForUnestablishedTier, so the two
// cases are never spelled the same way by accident.
func mustProfile(t *testing.T, e authoring.Edition) authoring.Profile {
	t.Helper()
	p, err := authoring.ProfileFor(e)
	if err != nil {
		t.Fatalf("ProfileFor(%q): %v", e, err)
	}
	return p
}

func routerFor(h *TypedAuthoringRouteHandler) *mux.Router {
	r := mux.NewRouter()
	h.RegisterRoutes(r)
	return r
}

// call issues one request through the router with the headers the agent
// gateway stamps.
func call(t *testing.T, r *mux.Router, method, path string, body any, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			t.Fatal(err)
		}
	}
	req := httptest.NewRequest(method, path, &buf)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	return rr
}

func gatewayHeaders() map[string]string {
	return map[string]string{"X-Org-ID": testOrg, "X-User-ID": testUser}
}

// communityDocument is a document a Community deployment can actually write:
// principal-scoped rather than group-scoped, reading only args.* and the
// well-known principal and action paths.
//
// The AUTHOR IS DELIBERATELY WRONG. A caller can put anything in a field that
// lives inside the signed source, and the route overwrites it from the
// gateway-stamped identity; a fixture that already carried the right value
// could not tell an overwrite from a coincidence.
func communityDocument() *authoring.Document {
	return &authoring.Document{
		APIVersion: authoring.APIVersion,
		Metadata: authoring.Metadata{
			DocumentID: testDocID,
			Title:      "Organization baseline",
			Author:     contract.MustParseID(contract.KindPrincipal, "User::"+testRealm+":someone-else"),
		},
		Policy: pdp.Document{
			Root:    pdp.RootOrganization,
			Version: 1,
			Attributes: []pdp.AttributeSchema{
				{Path: pdp.PrincipalIDPath, Type: pdp.TypeString},
				{Path: pdp.ActionIDPath, Type: pdp.TypeString},
				{Path: pdp.ActionTagsPath, Type: pdp.TypeArray},
				{Path: "args.request_type", Type: pdp.TypeString},
			},
			Policies: []pdp.Policy{
				{
					ID:        "grant.refund",
					Authority: contract.AuthorityPermission,
					Root:      pdp.RootOrganization,
					Scope:     pdp.Scope{Principals: []contract.ID{contract.MustParseID(contract.KindPrincipal, testPrinc)}},
					Actions:   pdp.ActionSelector{Actions: []contract.ID{contract.MustParseID(contract.KindAction, testAction)}},
					Where:     pdp.Compare("args.request_type", pdp.OpEq, "refund"),
				},
				{
					ID:        "ceiling.refund",
					Authority: contract.AuthorityConstraint,
					Root:      pdp.RootOrganization,
					Scope:     pdp.Scope{Organization: true},
					Actions:   pdp.ActionSelector{Actions: []contract.ID{contract.MustParseID(contract.KindAction, testAction)}},
					Where:     pdp.Compare("args.request_type", pdp.OpEq, "wire_transfer"),
				},
			},
		},
	}
}

// groupScopedDocument is the same document using the ONE construct PRD 5.2
// rules Enterprise-only. It is the control that says the edition boundary is
// applied through this route rather than only in the library's own tests.
func groupScopedDocument() *authoring.Document {
	d := communityDocument()
	d.Policy.Attributes = append(d.Policy.Attributes, pdp.AttributeSchema{Path: pdp.PrincipalGroupsPath, Type: pdp.TypeArray})
	d.Policy.Policies[0].Scope = pdp.Scope{Groups: []contract.ID{contract.MustParseID(contract.KindGroup, testGroupID)}}
	return d
}

func refundFixtures() []authoring.Fixture {
	return []authoring.Fixture{{
		Name: "a refund under the ceiling",
		Attributes: contract.AttributeSet{
			pdp.PrincipalIDPath:     contract.Known(testPrinc, contract.ProvDirectory, 1, fixtureObservedAt),
			pdp.PrincipalGroupsPath: contract.Known([]any{testGroupID}, contract.ProvDirectory, 1, fixtureObservedAt),
			pdp.ActionIDPath:        contract.Known(testAction, contract.ProvPlatform, 1, fixtureObservedAt),
			pdp.ActionTagsPath:      contract.Known([]any{"irreversible", "spend"}, contract.ProvPlatform, 1, fixtureObservedAt),
			"args.request_type":     contract.Known("refund", contract.ProvCaller, 1, fixtureObservedAt),
		},
		Expect: map[string]pdp.Verdict{
			"grant.refund":   pdp.VerdictMatch,
			"ceiling.refund": pdp.VerdictNoMatch,
		},
	}}
}

func publishBody(d *authoring.Document) typedAuthoringDocumentRequest {
	return typedAuthoringDocumentRequest{Document: d, Fixtures: refundFixtures()}
}

func decodeBody(t *testing.T, rr *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
		t.Fatalf("response is not JSON (%d): %s", rr.Code, rr.Body.String())
	}
	return out
}

// ---------------------------------------------------------------------------
// The thing #3907 exists for
// ---------------------------------------------------------------------------

// TestASoleAdministratorAuthorsAPolicyEndToEndThroughTheRoute is the assertion
// the issue is about, driven through the router on a community build.
//
// Publish AND activate, by ONE person, with no approver named anywhere. Before
// this change the first half was refused by checkSeparationOfDuties and the
// second by checkActivationAuthority, so a Community deployment could not put a
// single policy into force however many routes or stores it was given.
func TestASoleAdministratorAuthorsAPolicyEndToEndThroughTheRoute(t *testing.T) {
	for _, edition := range []authoring.Edition{authoring.EditionCommunity, authoring.EditionEvaluation} {
		t.Run(string(edition), func(t *testing.T) {
			r := routerFor(newRouteHandler(t, edition))

			rr := call(t, r, http.MethodPost, TypedAuthoringRoutePrefix+"/publish", publishBody(communityDocument()), gatewayHeaders())
			if rr.Code != http.StatusOK {
				t.Fatalf("publish: status=%d body=%s", rr.Code, rr.Body.String())
			}
			body := decodeBody(t, rr)
			digest, _ := body["digest"].(string)
			if digest == "" {
				t.Fatalf("publication returned no digest: %s", rr.Body.String())
			}
			// PRD v11 §1.4: the document carries none of the organization
			// template's controls, so publish says which it drops.
			assertOmitsTheWholeTemplate(t, "publish", body)

			rr = call(t, r, http.MethodPost, TypedAuthoringRoutePrefix+"/activate",
				typedAuthoringActivateRequest{Digest: digest, Reason: "first activation"}, gatewayHeaders())
			if rr.Code != http.StatusOK {
				t.Fatalf("activate: status=%d body=%s", rr.Code, rr.Body.String())
			}

			// The activation is ATTRIBUTED. Relaxing the second-person rule must
			// not relax the audit trail, so the record has to name who did it.
			activated := decodeBody(t, rr)
			assertOmitsTheWholeTemplate(t, "activate", activated)
			act, ok := activated["activation"].(map[string]any)
			if !ok {
				t.Fatalf("no activation record: %s", rr.Body.String())
			}
			actor, _ := act["actor"].(map[string]any)
			if actor["local"] != testUser {
				t.Fatalf("the activation record names local subject %v, want the caller %q", actor["local"], testUser)
			}
			if actor["qualifier"] != string(typedAuthoringAuthorRealm) {
				t.Fatalf("the activation record names realm %v, want %q — the realm says WHO ASSERTED the subject, "+
					"and the gateway-stamped header is the trusted-header path", actor["qualifier"], typedAuthoringAuthorRealm)
			}

			// And the policy is in force and renders back.
			rr = call(t, r, http.MethodGet, TypedAuthoringRoutePrefix+"/active", nil, gatewayHeaders())
			if rr.Code != http.StatusOK {
				t.Fatalf("active: status=%d body=%s", rr.Code, rr.Body.String())
			}
			doc, err := authoring.Parse(rr.Body.Bytes())
			if err != nil {
				t.Fatalf("what the route rendered back does not parse as the document that was signed: %v", err)
			}
			if doc.Metadata.DocumentID != testDocID {
				t.Fatalf("rendered document id = %q, want %q", doc.Metadata.DocumentID, testDocID)
			}
			// THE AUTHOR IS THE CALLER, not the one the request asked for.
			if doc.Metadata.Author.Local != testUser {
				t.Fatalf("the signed source names author %q; the route must stamp the gateway-resolved caller over "+
					"whatever the request claimed", doc.Metadata.Author)
			}
		})
	}
}

// assertOmitsTheWholeTemplate holds a response's template omission report for a
// document carrying none of the organization template's controls: present, and
// naming every one of them.
func assertOmitsTheWholeTemplate(t *testing.T, step string, body map[string]any) {
	t.Helper()
	report, ok := body["template_omissions"].(map[string]any)
	if !ok {
		t.Fatalf("%s: the response carries no template_omissions report: %v", step, body)
	}
	omitted, _ := report["omitted"].([]any)
	of, _ := report["of"].(float64)
	if of == 0 || len(omitted) != int(of) {
		t.Fatalf("%s: the report omits %d of %v; a document carrying none of the template omits all of it: %v", step, len(omitted), of, report)
	}
}

// ---------------------------------------------------------------------------
// The edition boundary, applied through the route
// ---------------------------------------------------------------------------

// TestTheEditionBoundaryIsAppliedThroughTheRouteAndNotOnlyInTheLibrary drives
// the same document at three editions.
//
// It matters as a ROUTE test rather than a library test because the library's
// boundary is only real if the transport hands it the deployment's edition
// rather than one of its own choosing.
func TestTheEditionBoundaryIsAppliedThroughTheRouteAndNotOnlyInTheLibrary(t *testing.T) {
	for _, edition := range []authoring.Edition{authoring.EditionCommunity, authoring.EditionEvaluation} {
		t.Run(string(edition)+" refuses group scope", func(t *testing.T) {
			r := routerFor(newRouteHandler(t, edition))
			rr := call(t, r, http.MethodPost, TypedAuthoringRoutePrefix+"/publish", publishBody(groupScopedDocument()), gatewayHeaders())
			if rr.Code != http.StatusUnprocessableEntity {
				t.Fatalf("status=%d, want 422; body=%s", rr.Code, rr.Body.String())
			}
			// THE REASON, not merely the refusal. A 422 satisfied by any
			// rejection would pass if the document were malformed for an
			// unrelated reason, and this test would then say nothing about
			// editions at all.
			if !strings.Contains(rr.Body.String(), authoring.CodeGroupScopeNotInEdition) {
				t.Fatalf("refused, but not for the group-scope edition reason: %s", rr.Body.String())
			}
		})
	}

	// THE NEGATIVE TWIN, at the construct level: the same group-scoped document
	// that Community refuses is a construct Enterprise carries. The Enterprise
	// publication is refused too, but for a DIFFERENT reason - it has no
	// approver - and that difference is the assertion.
	t.Run("enterprise carries group scope and refuses only for want of an approver", func(t *testing.T) {
		r := routerFor(newRouteHandler(t, authoring.EditionEnterprise))
		rr := call(t, r, http.MethodPost, TypedAuthoringRoutePrefix+"/publish", publishBody(groupScopedDocument()), gatewayHeaders())
		if rr.Code != http.StatusUnprocessableEntity {
			t.Fatalf("status=%d, want 422; body=%s", rr.Code, rr.Body.String())
		}
		if strings.Contains(rr.Body.String(), authoring.CodeGroupScopeNotInEdition) {
			t.Fatalf("Enterprise was refused group scope, which PRD 5.2 rules Full for it: %s", rr.Body.String())
		}
		if !strings.Contains(rr.Body.String(), authoring.CodeApproverIsAuthor) {
			t.Fatalf("Enterprise was refused for neither reason this test knows about: %s", rr.Body.String())
		}
	})
}

// TestEnterpriseCannotPublishThroughThisRouteAndTheRefusalSaysWhy pins a
// DELIBERATE limitation rather than an oversight.
//
// This route names no approver and offers no field for one, because on
// Community and Evaluation there is nobody to name. On Enterprise separation of
// duties applies, so every publication here is refused - correctly, since an
// Enterprise deployment has the portal, which resolves approvers against the
// organization's own directory. A second approver-resolution path here would be
// a second opinion on who may approve a policy.
//
// It is a test rather than a comment because the alternative is that somebody
// "fixes" it later by letting the request name its own approvers, which is the
// same defect as letting it name its own edition.
func TestEnterpriseCannotPublishThroughThisRouteAndTheRefusalSaysWhy(t *testing.T) {
	r := routerFor(newRouteHandler(t, authoring.EditionEnterprise))
	rr := call(t, r, http.MethodPost, TypedAuthoringRoutePrefix+"/publish", publishBody(communityDocument()), gatewayHeaders())
	if rr.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status=%d, want 422; body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), authoring.CodeApproverIsAuthor) {
		t.Fatalf("the refusal does not name separation of duties as the cause: %s", rr.Body.String())
	}
}

// TestTheEditionEndpointReportsTheBoundaryBeforeAnAuthorMeetsIt covers the
// endpoint a deployment with no UI has instead of a greyed-out control.
func TestTheEditionEndpointReportsTheBoundaryBeforeAnAuthorMeetsIt(t *testing.T) {
	r := routerFor(newRouteHandler(t, authoring.EditionCommunity))
	rr := call(t, r, http.MethodGet, TypedAuthoringRoutePrefix+"/edition", nil, gatewayHeaders())
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rr.Code, rr.Body.String())
	}
	body := decodeBody(t, rr)
	constructs, ok := body["constructs"].(map[string]any)
	if !ok {
		t.Fatalf("no constructs report: %s", rr.Body.String())
	}
	if constructs["edition"] != string(authoring.EditionCommunity) {
		t.Fatalf("report names edition %v", constructs["edition"])
	}
	if constructs["group_scope"] != false {
		t.Fatal("the community report claims group scope")
	}
	if constructs["separation_of_duties"] != false {
		t.Fatal("the community report claims separation of duties")
	}
	// The ceiling travels with the constructs: "what may I write" and "how much
	// of it" are one question for an author.
	if body["max_documents"] != float64(20) {
		t.Fatalf("max_documents = %v, want 20", body["max_documents"])
	}
}

// ---------------------------------------------------------------------------
// The transport's own guards
// ---------------------------------------------------------------------------

// TestTheRouteRefusesARequestTheGatewayDidNotStamp covers both headers
// separately, because they protect different things: the org decides WHOSE
// policy this is, and the user is signed into the document as its author.
func TestTheRouteRefusesARequestTheGatewayDidNotStamp(t *testing.T) {
	cases := []struct {
		name    string
		headers map[string]string
		reason  string
	}{
		{"no org", map[string]string{"X-User-ID": testUser}, "org_not_stamped"},
		{"no user", map[string]string{"X-Org-ID": testOrg}, "author_not_stamped"},
		{"neither", map[string]string{}, "org_not_stamped"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := routerFor(newRouteHandler(t, authoring.EditionCommunity))
			rr := call(t, r, http.MethodPost, TypedAuthoringRoutePrefix+"/publish", publishBody(communityDocument()), tc.headers)
			if rr.Code != http.StatusUnauthorized {
				t.Fatalf("status=%d, want 401; body=%s", rr.Code, rr.Body.String())
			}
			if got := decodeBody(t, rr)["reason"]; got != tc.reason {
				t.Fatalf("reason=%v, want %q", got, tc.reason)
			}
		})
	}
}

// TestOneOrganizationCannotReachAnothersDocuments is the isolation assertion.
//
// It is structural rather than checked - the workspace map is keyed on the
// gateway-stamped org and no route accepts an organization anywhere - so what
// this test really pins is that no path was added that takes one from the
// request.
func TestOneOrganizationCannotReachAnothersDocuments(t *testing.T) {
	r := routerFor(newRouteHandler(t, authoring.EditionCommunity))
	rr := call(t, r, http.MethodPost, TypedAuthoringRoutePrefix+"/publish", publishBody(communityDocument()), gatewayHeaders())
	if rr.Code != http.StatusOK {
		t.Fatalf("publish: status=%d body=%s", rr.Code, rr.Body.String())
	}
	digest, _ := decodeBody(t, rr)["digest"].(string)

	other := map[string]string{"X-Org-ID": "org-somebody-else", "X-User-ID": testUser}
	rr = call(t, r, http.MethodPost, TypedAuthoringRoutePrefix+"/activate",
		typedAuthoringActivateRequest{Digest: digest, Reason: "reaching across"}, other)
	if rr.Code == http.StatusOK {
		t.Fatal("another organization activated a digest published in the first one's workspace")
	}
	rr = call(t, r, http.MethodGet, TypedAuthoringRoutePrefix+"/active", nil, other)
	if rr.Code == http.StatusOK {
		t.Fatalf("another organization read the first one's active document: %s", rr.Body.String())
	}
}

// TestValidateIsEditionIndependent pins the placement decision.
//
// The same document that Community REFUSES to publish must still validate the
// same way on every edition, because well-formedness is a fact about the
// document and entitlement is a fact about the licence. Collapsing them would
// leave an author unable to tell a broken policy from an unlicensed one.
func TestValidateIsEditionIndependent(t *testing.T) {
	var bodies []string
	for _, edition := range []authoring.Edition{authoring.EditionCommunity, authoring.EditionEvaluation, authoring.EditionEnterprise} {
		r := routerFor(newRouteHandler(t, edition))
		rr := call(t, r, http.MethodPost, TypedAuthoringRoutePrefix+"/validate",
			typedAuthoringDocumentRequest{Document: groupScopedDocument()}, gatewayHeaders())
		if rr.Code != http.StatusOK {
			t.Fatalf("%s: validate status=%d body=%s", edition, rr.Code, rr.Body.String())
		}
		if strings.Contains(rr.Body.String(), authoring.CodeGroupScopeNotInEdition) {
			t.Fatalf("%s: validate applied the edition boundary; it belongs at publication", edition)
		}
		bodies = append(bodies, rr.Body.String())
	}
	for i := 1; i < len(bodies); i++ {
		if bodies[i] != bodies[0] {
			t.Fatalf("validate answered differently across editions:\n%s\nvs\n%s", bodies[0], bodies[i])
		}
	}
}

// TestAnUnusableVocabularyAnswersRatherThanDisappearing covers the 503. Unset
// is the deployment vocabulary (PRD §1.5), so the value here is one nobody
// recognises: the orchestrator keeps its other routes and this surface answers
// naming the variable.
func TestAnUnusableVocabularyAnswersRatherThanDisappearing(t *testing.T) {
	h := &TypedAuthoringRouteHandler{
		db:           nil, // in-process posture; see newRouteHandler
		catalogValue: "whatever-somebody-typed",
		workspaces:   map[string]*typedAuthoringWorkspace{},
		profileFor:   func(context.Context) authoring.Profile { return mustProfile(t, authoring.EditionCommunity) },
	}
	r := routerFor(h)
	for _, path := range []string{"/edition", "/validate", "/publish", "/activate", "/active", "/active/summary"} {
		rr := call(t, r, http.MethodGet, TypedAuthoringRoutePrefix+path, nil, gatewayHeaders())
		if rr.Code == http.StatusNotFound {
			// GET on a POST-only route is a router-level miss, which the prefix
			// guard answers; that is covered by its own test below.
			continue
		}
		if rr.Code != http.StatusServiceUnavailable {
			t.Fatalf("%s: status=%d, want 503 naming the catalog variable; body=%s", path, rr.Code, rr.Body.String())
		}
		if !strings.Contains(rr.Body.String(), authoringcatalog.Env) {
			t.Fatalf("%s: the 503 does not name the variable an operator must set: %s", path, rr.Body.String())
		}
	}
}

// TestAStockDeploymentAuthorsWithTheVariableUnset is #4133's acceptance
// (PRD §1.5): a process that boots with AXONFLOW_TYPED_AUTHORING_CATALOG unset
// or empty publishes and activates a document, through the constructor run.go
// calls. Before §1.5 both answered 503 catalog_not_configured.
func TestAStockDeploymentAuthorsWithTheVariableUnset(t *testing.T) {
	for _, tc := range []struct {
		name  string
		unset bool
	}{{"unset", true}, {"empty", false}} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(authoringcatalog.Env, "")
			if tc.unset {
				if err := os.Unsetenv(authoringcatalog.Env); err != nil {
					t.Fatal(err)
				}
			}
			h := NewTypedAuthoringRouteHandler(nil, func() authoringvocabulary.CatalogDeployment {
				return authoringvocabulary.CatalogDeployment{HasDirectory: true}
			})
			// The edition comes from the deployment's licence, which this unit
			// has none of; the catalog default is what is under test.
			h.profileFor = func(context.Context) authoring.Profile { return mustProfile(t, authoring.EditionCommunity) }
			r := routerFor(h)

			rr := call(t, r, http.MethodPost, TypedAuthoringRoutePrefix+"/publish", publishBody(communityDocument()), gatewayHeaders())
			if rr.Code != http.StatusOK {
				t.Fatalf("publish with the variable %s: status=%d body=%s - a stock deployment must author (PRD §1.5)",
					tc.name, rr.Code, rr.Body.String())
			}
			digest, _ := decodeBody(t, rr)["digest"].(string)
			if digest == "" {
				t.Fatalf("publication returned no digest: %s", rr.Body.String())
			}
			rr = call(t, r, http.MethodPost, TypedAuthoringRoutePrefix+"/activate",
				typedAuthoringActivateRequest{Digest: digest, Reason: "a stock deployment"}, gatewayHeaders())
			if rr.Code != http.StatusOK {
				t.Fatalf("activate with the variable %s: status=%d body=%s", tc.name, rr.Code, rr.Body.String())
			}
		})
	}
}

// TestTheUnenumeratedGuardAnswersRatherThanFallingThrough pins the prefix guard.
func TestTheUnenumeratedGuardAnswersRatherThanFallingThrough(t *testing.T) {
	r := routerFor(newRouteHandler(t, authoring.EditionCommunity))
	for _, req := range []struct{ method, path string }{
		{http.MethodGet, TypedAuthoringRoutePrefix + "/not-a-thing"},
		{http.MethodDelete, TypedAuthoringRoutePrefix + "/publish"},
		{http.MethodPut, TypedAuthoringRoutePrefix + "/active"},
	} {
		rr := call(t, r, req.method, req.path, nil, gatewayHeaders())
		if rr.Code != http.StatusNotFound {
			t.Fatalf("%s %s: status=%d, want 404", req.method, req.path, rr.Code)
		}
		if got := decodeBody(t, rr)["reason"]; got != "no_such_endpoint" {
			t.Fatalf("%s %s: reason=%v", req.method, req.path, got)
		}
	}
}

// TestAWorkspaceIsRebuiltWhenTheDeploymentsEditionChanges is a direct test of
// handler state, and says so.
//
// The window it closes is narrow and real: authoring.API binds its edition at
// construction, so a workspace cached while a licence was valid would keep the
// Enterprise construct set after that licence expired, until somebody
// restarted the orchestrator.
func TestAWorkspaceIsRebuiltWhenTheDeploymentsEditionChanges(t *testing.T) {
	h := newRouteHandler(t, authoring.EditionEnterprise)
	edition := authoring.EditionEnterprise
	h.profileFor = func(context.Context) authoring.Profile { return mustProfile(t, edition) }

	first, err := h.workspaceFor(context.Background(), testOrg)
	if err != nil {
		t.Fatal(err)
	}
	if first.profile.Edition() != authoring.EditionEnterprise {
		t.Fatalf("workspace built at %q", first.profile.Edition())
	}
	same, err := h.workspaceFor(context.Background(), testOrg)
	if err != nil {
		t.Fatal(err)
	}
	if same != first {
		t.Fatal("an unchanged edition rebuilt the workspace; the cache is doing nothing")
	}

	edition = authoring.EditionCommunity
	narrowed, err := h.workspaceFor(context.Background(), testOrg)
	if err != nil {
		t.Fatal(err)
	}
	if narrowed == first {
		t.Fatal("the licence narrowed to Community and the workspace kept its Enterprise boundary")
	}
	if narrowed.profile.Edition() != authoring.EditionCommunity {
		t.Fatalf("rebuilt workspace is at %q", narrowed.profile.Edition())
	}
}

// TestTheWorkspaceCapEvictsOnlyEmptyWorkspaces pins the memory bound.
func TestTheWorkspaceCapEvictsOnlyEmptyWorkspaces(t *testing.T) {
	h := newRouteHandler(t, authoring.EditionCommunity)
	for i := 0; i < maxTypedAuthoringWorkspaces; i++ {
		if _, err := h.workspaceFor(context.Background(), string(rune('a'+i%26))+string(rune('a'+i/26))); err != nil {
			t.Fatalf("filling to the cap failed at %d: %v", i, err)
		}
	}
	// One more evicts an idle empty workspace rather than refusing.
	if _, err := h.workspaceFor(context.Background(), "one-more"); err != nil {
		t.Fatalf("the cap refused while empty workspaces were evictable: %v", err)
	}
	// Now make every workspace non-empty and assert the cap REFUSES rather than
	// dropping somebody's artifacts.
	h.mu.Lock()
	for _, ws := range h.workspaces {
		ws.digests["planted"] = struct{}{}
	}
	h.mu.Unlock()
	if _, err := h.workspaceFor(context.Background(), "no-room-at-all"); err == nil {
		t.Fatal("the cap evicted a workspace holding artifacts rather than refusing")
	}
}

// TestTheRegisteredPathsAllCarryThePrefix holds the literal paths in
// RegisterRoutes to the prefix constant.
//
// The paths must be literals - two censuses in ee/platform/customer-portal walk
// this package's syntax tree and refuse a path they cannot resolve - so the
// constant cannot be used at the registration site, and without this test the
// two could drift silently: a route registered under a prefix the guard does
// not know about is exactly what those censuses exist to catch, reintroduced
// one directory away.
func TestTheRegisteredPathsAllCarryThePrefix(t *testing.T) {
	r := routerFor(newRouteHandler(t, authoring.EditionCommunity))
	seen := 0
	err := r.Walk(func(route *mux.Route, _ *mux.Router, _ []*mux.Route) error {
		tpl, err := route.GetPathTemplate()
		if err != nil {
			// A PathPrefix route has no path template; check its regexp instead.
			re, rerr := route.GetPathRegexp()
			if rerr != nil {
				t.Fatalf("a registered route exposes neither a template nor a regexp: %v / %v", err, rerr)
			}
			if !strings.Contains(re, TypedAuthoringRoutePrefix) {
				t.Errorf("prefix route %q does not carry %q", re, TypedAuthoringRoutePrefix)
			}
			seen++
			return nil
		}
		if !strings.HasPrefix(tpl, TypedAuthoringRoutePrefix) {
			t.Errorf("route %q does not carry the prefix %q", tpl, TypedAuthoringRoutePrefix)
		}
		seen++
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// ANTI-VACUITY: a walk that visited nothing would pass every assertion above.
	if seen != 8 {
		t.Fatalf("the walk visited %d routes; RegisterRoutes registers 8 (seven endpoints and the prefix guard), "+
			"so this test is either blind or the surface changed without it", seen)
	}
}

// TestTheAuthorFallsBackToTheAuthENTICATEDClientWhenNoUserIsStamped covers the
// path a DEFAULT deployment actually takes, which is most Community ones.
//
// X-User-ID is client-assertable and the agent's #2896 identity trust gate
// STRIPS it unless the deployment has declared its identity source trusted. A
// route that required it would refuse every publication on a default
// deployment - the population this whole change exists for - so the author
// falls back to X-Client-ID, which the proxy sets from the validated credential
// and no caller can forge.
//
// The assertion that makes this more than a fallback is the REALM and the TYPE:
// they are what let a reader of the signed provenance see which of the two
// asserted the subject, rather than having to assume.
func TestTheAuthorFallsBackToTheAuthenticatedClientWhenNoUserIsStamped(t *testing.T) {
	r := routerFor(newRouteHandler(t, authoring.EditionCommunity))
	headers := map[string]string{"X-Org-ID": testOrg, "X-Client-ID": "acme-prod-credential"}

	rr := call(t, r, http.MethodPost, TypedAuthoringRoutePrefix+"/publish", publishBody(communityDocument()), headers)
	if rr.Code != http.StatusOK {
		t.Fatalf("a request carrying only the auth-derived client identity was refused: status=%d body=%s", rr.Code, rr.Body.String())
	}

	rr = call(t, r, http.MethodGet, TypedAuthoringRoutePrefix+"/active", nil, headers)
	if rr.Code != http.StatusOK {
		// Nothing is active yet - publication does not activate - so this is a
		// 404 and that is correct. Assert on the published provenance instead
		// by activating first.
		digest := ""
		rr2 := call(t, r, http.MethodPost, TypedAuthoringRoutePrefix+"/publish", publishBody(communityDocument()), headers)
		if b := decodeBody(t, rr2); b["digest"] != nil {
			digest, _ = b["digest"].(string)
		}
		if digest == "" {
			t.Fatalf("no digest to activate: %s", rr2.Body.String())
		}
		if rr3 := call(t, r, http.MethodPost, TypedAuthoringRoutePrefix+"/activate",
			typedAuthoringActivateRequest{Digest: digest, Reason: "fallback author"}, headers); rr3.Code != http.StatusOK {
			t.Fatalf("the client-identity author could not activate its own version: status=%d body=%s", rr3.Code, rr3.Body.String())
		}
		rr = call(t, r, http.MethodGet, TypedAuthoringRoutePrefix+"/active", nil, headers)
		if rr.Code != http.StatusOK {
			t.Fatalf("active: status=%d body=%s", rr.Code, rr.Body.String())
		}
	}

	doc, err := authoring.Parse(rr.Body.Bytes())
	if err != nil {
		t.Fatalf("the rendered document does not parse: %v", err)
	}
	if doc.Metadata.Author.Local != "acme-prod-credential" {
		t.Fatalf("signed author local = %q, want the client id the gateway stamped", doc.Metadata.Author.Local)
	}
	// THE REALM AND THE TYPE ARE THE POINT. A Client in the api-credential
	// realm says "a credential wrote this"; a User in the trusted-header realm
	// says "a person the deployment vouches for wrote this". Collapsing them
	// would make the signed provenance unable to distinguish the two.
	if want := string(identity.BuiltinRealmAPICredential); doc.Metadata.Author.Qualifier != want {
		t.Fatalf("signed author realm = %q, want %q", doc.Metadata.Author.Qualifier, want)
	}
	if want := string(identity.SubjectClient); doc.Metadata.Author.Type != want {
		t.Fatalf("signed author type = %q, want %q", doc.Metadata.Author.Type, want)
	}

	// AND THE PER-USER HEADER STILL WINS WHEN IT IS THERE, or the fallback
	// would have silently become the only path.
	r2 := routerFor(newRouteHandler(t, authoring.EditionCommunity))
	both := map[string]string{"X-Org-ID": testOrg, "X-Client-ID": "acme-prod-credential", "X-User-ID": testUser}
	rr = call(t, r2, http.MethodPost, TypedAuthoringRoutePrefix+"/publish", publishBody(communityDocument()), both)
	if rr.Code != http.StatusOK {
		t.Fatalf("publish with both headers: status=%d body=%s", rr.Code, rr.Body.String())
	}
	digest, _ := decodeBody(t, rr)["digest"].(string)
	if rr := call(t, r2, http.MethodPost, TypedAuthoringRoutePrefix+"/activate",
		typedAuthoringActivateRequest{Digest: digest, Reason: "user wins"}, both); rr.Code != http.StatusOK {
		t.Fatalf("activate with both headers: status=%d body=%s", rr.Code, rr.Body.String())
	}
	rr = call(t, r2, http.MethodGet, TypedAuthoringRoutePrefix+"/active", nil, both)
	doc, err = authoring.Parse(rr.Body.Bytes())
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if doc.Metadata.Author.Local != testUser {
		t.Fatalf("with both headers present the author is %q; the per-user identity must win", doc.Metadata.Author.Local)
	}
	if doc.Metadata.Author.Type != string(identity.SubjectUser) {
		t.Fatalf("with both headers present the author type is %q, want a user", doc.Metadata.Author.Type)
	}
}

// TestTheClientFallbackDoesNotReachAnEditionWithSeparationOfDuties closes a
// hazard that is currently unreachable, which is why it needs a test rather
// than a comment.
//
// Where the two-person rule applies, an author who is a CLIENT CREDENTIAL and
// an approver who is a directory USER are different principals — correctly, the
// comparison is over subject, realm and type — but they may be the same PERSON,
// holding the credential and their own login. The rule is about people. That is
// the same axis error #3876 fixed one step along: it compared a rendered TYPE
// where it meant subject; this compares SUBJECT where the rule means human.
//
// It cannot arise today only because this route sets no approvers at all, so an
// SoD edition refuses every publication before the author is compared with
// anybody. That safety lives in a DIFFERENT function, and the first person to
// add an approver field to this transport would make the hazard live without
// touching the author resolution. This is what makes the property structural.
func TestTheClientFallbackDoesNotReachAnEditionWithSeparationOfDuties(t *testing.T) {
	clientOnly := map[string]string{"X-Org-ID": testOrg, "X-Client-ID": "acme-prod-credential"}

	// Community: the fallback applies and the publication succeeds.
	com := routerFor(newRouteHandler(t, authoring.EditionCommunity))
	if rr := call(t, com, http.MethodPost, TypedAuthoringRoutePrefix+"/publish",
		publishBody(communityDocument()), clientOnly); rr.Code != http.StatusOK {
		t.Fatalf("community refused a credential-authored publication: status=%d body=%s", rr.Code, rr.Body.String())
	}

	// Enterprise: the fallback does NOT apply, and the refusal is about the
	// missing author rather than about the approver — which is the assertion.
	// A 422 for APPROVER_IS_AUTHOR would mean the request got as far as being
	// authored by the credential, which is the state this prevents.
	ent := routerFor(newRouteHandler(t, authoring.EditionEnterprise))
	rr := call(t, ent, http.MethodPost, TypedAuthoringRoutePrefix+"/publish",
		publishBody(communityDocument()), clientOnly)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d, want 401; an edition carrying separation of duties must not accept a client "+
			"credential as an author, because the credential and a directory user may be the same person and "+
			"the two-person rule is about people. body=%s", rr.Code, rr.Body.String())
	}
	body := decodeBody(t, rr)
	if body["reason"] != "author_not_stamped" {
		t.Fatalf("reason=%v, want author_not_stamped", body["reason"])
	}
	// The refusal has to say what to configure, or an operator meets a 401 with
	// no way to act on it.
	if msg, _ := body["error"].(string); !strings.Contains(msg, "X-User-ID") || !strings.Contains(msg, "two-person") {
		t.Fatalf("the refusal does not name the header to configure or why a credential will not do: %q", msg)
	}

	// AND the per-user identity still works on Enterprise, or the guard above
	// would be indistinguishable from Enterprise having no author path at all.
	both := map[string]string{"X-Org-ID": testOrg, "X-Client-ID": "acme-prod-credential", "X-User-ID": testUser}
	rr = call(t, ent, http.MethodPost, TypedAuthoringRoutePrefix+"/publish", publishBody(communityDocument()), both)
	if rr.Code == http.StatusUnauthorized {
		t.Fatalf("Enterprise refused a request carrying a per-user identity: %s", rr.Body.String())
	}
	// It is still refused, for the SEPARATION reason, which is the documented
	// behaviour of this route on that edition.
	if !strings.Contains(rr.Body.String(), authoring.CodeApproverIsAuthor) {
		t.Fatalf("Enterprise with a user identity was refused for neither known reason: %s", rr.Body.String())
	}
}

// TestAFailedVocabularyResolutionIsNotMemoised pins the half of the lazy
// resolution that has no other guard (#3895).
//
// # THE FAILURE IT PREVENTS
//
// The vocabulary's realm attributes are derived from a directory resolver built
// over the database. If that derivation fails transiently at the FIRST request -
// a restart, a failover, a connection blip - memoising the failure would freeze
// the wrong vocabulary, and therefore the wrong catalog DIGEST, for the life of
// the process. That is the same reproducibility failure the lazy resolution
// exists to avoid, moved from boot to first request, and nothing else in the
// tree would notice it: every later request would answer 503 and the deployment
// would look consistently unconfigured rather than intermittently so.
//
// A SUCCESS is memoised, deliberately: the vocabulary is deployment state, and
// re-deriving it per request would put a registry build on the authoring path.
// So the two directions are asserted separately.
func TestAFailedVocabularyResolutionIsNotMemoised(t *testing.T) {
	calls := 0
	h := &TypedAuthoringRouteHandler{
		db: nil,
		// An UNRECOGNISED value, so the resolver refuses every time.
		catalogValue: "not-a-vocabulary",
		deploymentFor: func() authoringvocabulary.CatalogDeployment {
			calls++
			return authoringvocabulary.CatalogDeployment{HasDirectory: true}
		},
		profileFor: func(context.Context) authoring.Profile { return mustProfile(t, authoring.EditionCommunity) },
		workspaces: map[string]*typedAuthoringWorkspace{},
	}
	for i := 1; i <= 3; i++ {
		if snap, err := h.vocabulary(); err == nil || snap != nil {
			t.Fatalf("attempt %d resolved an unrecognised vocabulary: %v, %v", i, snap, err)
		}
	}
	if calls != 3 {
		t.Fatalf("the resolver ran %d time(s) across three failing attempts; a memoised FAILURE freezes the wrong "+
			"vocabulary until the process restarts, which is the reproducibility defect the lazy resolution exists "+
			"to avoid", calls)
	}

	// THE OTHER DIRECTION, and it is the control: a SUCCESS is memoised, so the
	// assertion above is about failures rather than about the resolution never
	// caching at all.
	ok := &TypedAuthoringRouteHandler{
		db:           nil,
		catalogValue: authoringcatalog.SourceDeployment,
		deploymentFor: func() authoringvocabulary.CatalogDeployment {
			calls++
			return authoringvocabulary.CatalogDeployment{HasDirectory: true}
		},
		profileFor: func(context.Context) authoring.Profile { return mustProfile(t, authoring.EditionCommunity) },
		workspaces: map[string]*typedAuthoringWorkspace{},
	}
	calls = 0
	for i := 1; i <= 3; i++ {
		if snap, err := ok.vocabulary(); err != nil || snap == nil {
			t.Fatalf("attempt %d could not resolve the deployment vocabulary: %v", i, err)
		}
	}
	if calls != 1 {
		t.Fatalf("the resolver ran %d time(s) across three successful attempts; a success must be memoised or every "+
			"request pays a registry build on the authoring path", calls)
	}
}
