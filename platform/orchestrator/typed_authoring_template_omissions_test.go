// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"axonflow/platform/decision/activation"
	"axonflow/platform/decision/authoring"
	"axonflow/platform/decision/pdp"
	"axonflow/platform/policy/authoringstore"
)

// #4249 row 5672856881, the orchestrator's activate: a document that omits or
// changes organization-template policies is activated only when the request
// names exactly those ids; otherwise 409 activation_refused with
// TEMPLATE_OMISSIONS_UNACKNOWLEDGED and the report. The rule's own cells are in
// platform/decision/activation; these hold the route's wire, field by field.

// templateCarryingDocument is communityDocument with every organization-template
// policy (and the attributes they read) added, so it omits nothing.
func templateCarryingDocument(t *testing.T) *authoring.Document {
	t.Helper()
	template, err := pdp.SystemCorpusOrganizationTemplate()
	if err != nil {
		t.Fatal(err)
	}
	d := communityDocument()
	have := map[string]bool{}
	for _, a := range d.Policy.Attributes {
		have[a.Path] = true
	}
	for _, a := range template.Attributes {
		if !have[a.Path] {
			d.Policy.Attributes = append(d.Policy.Attributes, a)
			have[a.Path] = true
		}
	}
	d.Policy.Policies = append(d.Policy.Policies, template.Policies...)
	return d
}

func activate(t *testing.T, h *TypedAuthoringRouteHandler, digest string, acknowledged []string, reason string) (*httptest.ResponseRecorder, map[string]any) {
	t.Helper()
	rr := call(t, routerFor(h), http.MethodPost, TypedAuthoringRoutePrefix+"/activate",
		typedAuthoringActivateRequest{Digest: digest, Reason: reason, AcknowledgeTemplateOmissions: acknowledged}, gatewayHeaders())
	var body map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("activate answered a body that is not JSON (status %d): %v: %s", rr.Code, err, rr.Body.String())
	}
	return rr, body
}

func published(t *testing.T, h *TypedAuthoringRouteHandler, doc *authoring.Document) string {
	t.Helper()
	rr := call(t, routerFor(h), http.MethodPost, TypedAuthoringRoutePrefix+"/publish", publishBody(doc), gatewayHeaders())
	if rr.Code != http.StatusOK {
		t.Fatalf("publish: status=%d body=%s", rr.Code, rr.Body.String())
	}
	digest, _ := decodeBody(t, rr)["digest"].(string)
	if digest == "" {
		t.Fatalf("publication returned no digest: %s", rr.Body.String())
	}
	return digest
}

func activeCode(t *testing.T, h *TypedAuthoringRouteHandler) int {
	t.Helper()
	return call(t, routerFor(h), http.MethodGet, TypedAuthoringRoutePrefix+"/active", nil, gatewayHeaders()).Code
}

// assertUnacknowledgedRefusal holds a 409 body field by field. wantOmitted and
// wantModified both nil means the document carries the template as shipped, so
// the refusal carries no report.
func assertUnacknowledgedRefusal(t *testing.T, rr *httptest.ResponseRecorder, body map[string]any, wantOmitted, wantModified []string) {
	t.Helper()
	if rr.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409: %s", rr.Code, rr.Body.String())
	}
	if body["success"] != false {
		t.Errorf("success = %v, want false", body["success"])
	}
	if body["reason"] != "activation_refused" {
		t.Errorf("reason = %v, want activation_refused", body["reason"])
	}
	if body["code"] != activation.CodeTemplateOmissionsUnacknowledged {
		t.Errorf("code = %v, want %s", body["code"], activation.CodeTemplateOmissionsUnacknowledged)
	}
	msg, _ := body["error"].(string)
	if !strings.Contains(msg, "acknowledge_template_omissions") {
		t.Errorf("error %q does not say which field to send", msg)
	}
	if wantOmitted == nil && wantModified == nil {
		if _, present := body["template_omissions"]; present {
			t.Errorf("template_omissions present for a document carrying the template as shipped: %v", body["template_omissions"])
		}
		return
	}
	report, ok := body["template_omissions"].(map[string]any)
	if !ok {
		t.Fatalf("template_omissions missing from the refusal: %v", body)
	}
	ids := func(member string) []string {
		list, ok := report[member].([]any)
		if !ok {
			t.Fatalf("template_omissions.%s is %T, want an array (never null): %v", member, report[member], report)
		}
		out := []string{}
		for _, v := range list {
			out = append(out, v.(string))
		}
		return out
	}
	if got, want := ids("omitted"), append([]string{}, wantOmitted...); !slices.Equal(got, want) {
		t.Errorf("template_omissions.omitted = %v, want %v", got, want)
	}
	if got, want := ids("modified"), append([]string{}, wantModified...); !slices.Equal(got, want) {
		t.Errorf("template_omissions.modified = %v, want %v", got, want)
	}
	template, _ := pdp.SystemCorpusOrganizationTemplate()
	if of, _ := report["of"].(float64); int(of) != len(template.Policies) {
		t.Errorf("template_omissions.of = %v, want %d", report["of"], len(template.Policies))
	}
	if m, _ := report["message"].(string); !strings.HasPrefix(m, "this document ") {
		t.Errorf("template_omissions.message = %q", m)
	}
	for _, id := range append(slices.Clone(wantOmitted), wantModified...) {
		if !strings.Contains(msg, id) {
			t.Errorf("error %q does not name %s, which the caller must send", msg, id)
			break
		}
	}
}

func TestActivatingADocumentThatOmitsTemplateControlsRequiresNamingThem(t *testing.T) {
	omitted := acknowledgedOmissions(t, communityDocument())
	if len(omitted) < 2 {
		t.Fatalf("PREMISE: the community document omits %d template policies; the cells need at least 2", len(omitted))
	}
	for _, edition := range []authoring.Edition{authoring.EditionCommunity, authoring.EditionEvaluation} {
		t.Run(string(edition), func(t *testing.T) {
			t.Run("no acknowledgement: 409 with the report, nothing activated", func(t *testing.T) {
				h := newRouteHandler(t, edition)
				digest := published(t, h, communityDocument())
				rr, body := activate(t, h, digest, nil, "go live")
				assertUnacknowledgedRefusal(t, rr, body, omitted, []string{})
				if code := activeCode(t, h); code == http.StatusOK {
					t.Fatalf("GET active = %d after a refused activation; nothing may be active", code)
				}
			})
			t.Run("a subset: 409", func(t *testing.T) {
				h := newRouteHandler(t, edition)
				rr, body := activate(t, h, published(t, h, communityDocument()), omitted[:len(omitted)-1], "go live")
				assertUnacknowledgedRefusal(t, rr, body, omitted, []string{})
			})
			t.Run("a superset: 409", func(t *testing.T) {
				h := newRouteHandler(t, edition)
				rr, body := activate(t, h, published(t, h, communityDocument()), append(slices.Clone(omitted), "organization.not-in-the-template"), "go live")
				assertUnacknowledgedRefusal(t, rr, body, omitted, []string{})
			})
			t.Run("exactly the omitted ids: 200, the report kept, the reason records the list", func(t *testing.T) {
				h := newRouteHandler(t, edition)
				rr, body := activate(t, h, published(t, h, communityDocument()), omitted, "go live")
				if rr.Code != http.StatusOK {
					t.Fatalf("status = %d, want 200: %s", rr.Code, rr.Body.String())
				}
				assertOmitsTheWholeTemplate(t, "acknowledged activate", body)
				act, _ := body["activation"].(map[string]any)
				reason, _ := act["reason"].(string)
				if want := activation.RecordAcknowledgedTemplateOmissions(authoring.ActivationPromote, "go live", omitted); reason != want {
					t.Errorf("activation.reason = %q, want %q", reason, want)
				}
				if !strings.HasPrefix(reason, "go live [acknowledged template omissions: ") {
					t.Errorf("activation.reason %q does not carry the acknowledged list after the caller's reason", reason)
				}
				if code := activeCode(t, h); code != http.StatusOK {
					t.Fatalf("GET active = %d after an acknowledged activation", code)
				}
			})
			t.Run("a full document, nothing acknowledged: 200 as before, no report", func(t *testing.T) {
				h := newRouteHandler(t, edition)
				rr, body := activate(t, h, published(t, h, templateCarryingDocument(t)), nil, "go live")
				if rr.Code != http.StatusOK {
					t.Fatalf("status = %d, want 200: %s", rr.Code, rr.Body.String())
				}
				if _, present := body["template_omissions"]; present {
					t.Errorf("template_omissions present for a document carrying the whole template: %v", body)
				}
				act, _ := body["activation"].(map[string]any)
				if act["reason"] != "go live" {
					t.Errorf("activation.reason = %v, want the caller's reason unchanged", act["reason"])
				}
			})
			t.Run("a full document, something acknowledged: 409, no report", func(t *testing.T) {
				h := newRouteHandler(t, edition)
				rr, body := activate(t, h, published(t, h, templateCarryingDocument(t)), omitted[:1], "go live")
				assertUnacknowledgedRefusal(t, rr, body, nil, nil)
			})
			t.Run("an unknown digest: Promote's own refusal, never the omission code", func(t *testing.T) {
				h := newRouteHandler(t, edition)
				rr, body := activate(t, h, "sha256:"+strings.Repeat("0", 64), nil, "go live")
				if rr.Code != http.StatusConflict || body["reason"] != "activation_refused" {
					t.Fatalf("status %d body %v; want Promote's 409 activation_refused", rr.Code, body)
				}
				if _, present := body["code"]; present {
					t.Errorf("an unknown digest was answered with code %v; it must reach Promote's refusal", body["code"])
				}
			})
			for _, malformed := range []struct {
				name   string
				ids    []string
				reason string
			}{
				{"an id named twice", []string{omitted[0], omitted[0]}, "go live"},
				{"an empty id", []string{omitted[0], ""}, "go live"},
				{"a reason carrying the recorded acknowledgement's note", omitted, "go live [acknowledged template omissions: " + omitted[0] + "]"},
			} {
				t.Run("malformed request, "+malformed.name+": 400 before the rule", func(t *testing.T) {
					h := newRouteHandler(t, edition)
					rr, body := activate(t, h, published(t, h, communityDocument()), malformed.ids, malformed.reason)
					if rr.Code != http.StatusBadRequest || body["reason"] != "malformed_request" {
						t.Fatalf("status %d body %v; want 400 malformed_request", rr.Code, body)
					}
					if _, present := body["code"]; present {
						t.Errorf("a malformed list carried code %v", body["code"])
					}
				})
			}
		})
	}
}

// THE EXPECTATION SPELLED OUT, NOT COMPUTED. Every other cell derives the list
// with ReportTemplateOmissions, the function the server uses; this one writes the
// two dropped template policy ids as literals, so a server that computed the
// omissions wrongly would be caught by something other than itself.
func TestTheOmittedIDsAreTheOnesTheDocumentDropped(t *testing.T) {
	dropped := []string{
		"corpus:static_policies:drop__table__prevention",
		"corpus:static_policies:eu__ai__act__pricing__fairness",
	}
	doc := templateCarryingDocument(t)
	kept := doc.Policy.Policies[:0]
	for _, p := range doc.Policy.Policies {
		if p.ID != dropped[0] && p.ID != dropped[1] {
			kept = append(kept, p)
		}
	}
	if removed := len(doc.Policy.Policies) - len(kept); removed != 2 {
		t.Fatalf("PREMISE: removed %d policies; the template must carry both literal ids", removed)
	}
	doc.Policy.Policies = kept

	h := newRouteHandler(t, authoring.EditionCommunity)
	digest := published(t, h, doc)
	rr, body := activate(t, h, digest, nil, "")
	assertUnacknowledgedRefusal(t, rr, body, dropped, []string{})

	// The acknowledged activation records the list; no orchestrator READ route
	// returns activation records (edition, active, active/summary and system
	// carry none), so the activation record the route answered is where a
	// caller reads it back.
	rr, body = activate(t, h, digest, []string{dropped[1], dropped[0]}, "")
	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rr.Code, rr.Body.String())
	}
	act, _ := body["activation"].(map[string]any)
	if want := "acknowledged template omissions: corpus:static_policies:drop__table__prevention, corpus:static_policies:eu__ai__act__pricing__fairness"; act["reason"] != want {
		t.Errorf("activation.reason = %v, want %q", act["reason"], want)
	}
}

// A STORE THAT CANNOT BE READ refuses as the active-document read does, so the
// caller is told whether a retry can help; a REPORT THAT CANNOT BE COMPUTED
// refuses with TEMPLATE_OMISSIONS_UNAVAILABLE. Either way the store's error goes
// to the log only (#4271) and the activation never proceeds.
func TestAnActivationWhoseOmissionsCannotBeReadIsRefused(t *testing.T) {
	profile, err := authoring.ProfileFor(authoring.EditionCommunity)
	if err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(prev) })

	for _, c := range []struct {
		name      string
		err       error
		status    int
		reason    string
		errorHint string
	}{
		{"a signing key not loaded: 503 key_not_loaded", fmt.Errorf("%w (%s)", authoringstore.ErrSigningKeyNotLoaded, plantedStoreError), http.StatusServiceUnavailable, "key_not_loaded", "retry in a few seconds"},
		{"an artifact that does not verify: 500 artifact_unverifiable", fmt.Errorf("%w (%s)", authoringstore.ErrArtifactUnverifiable, plantedStoreError), http.StatusInternalServerError, "artifact_unverifiable", "a retry will not change that"},
		{"any other store failure: 503 storage_unavailable", errors.New(plantedStoreError), http.StatusServiceUnavailable, "storage_unavailable", "retry once the database is reachable"},
	} {
		t.Run(c.name, func(t *testing.T) {
			logs.Reset()
			store, err := authoring.NewStoreWithBackend(authoring.StaticTrust(pdp.NewTrustStore()), profile,
				readBackFailingBackend{Backend: authoring.NewMemoryBackend(), err: c.err})
			if err != nil {
				t.Fatal(err)
			}
			rr := httptest.NewRecorder()
			if !refuseUnacknowledgedTemplateOmissions(context.Background(), rr, store, testOrg, "sha256:planted-p10-digest", nil) {
				t.Fatal("a store read that failed let the activation proceed")
			}
			body := decodeBody(t, rr)
			if rr.Code != c.status || body["success"] != false || body["reason"] != c.reason {
				t.Fatalf("status %d body %v; want %d %s", rr.Code, body, c.status, c.reason)
			}
			msg, _ := body["error"].(string)
			if !strings.Contains(msg, c.errorHint) {
				t.Errorf("error %q, want it to say %q", msg, c.errorHint)
			}
			for _, fragment := range []string{"pq:", "10.42.255.7", "planted-4255-store-error"} {
				if strings.Contains(msg, fragment) {
					t.Fatalf("the refusal carries %q from the store's own error: %q", fragment, msg)
				}
			}
			if _, present := body["code"]; present {
				t.Errorf("a store refusal carried code %v; the omission codes are the rule's", body["code"])
			}
			if !strings.Contains(logs.String(), "planted-4255-store-error") {
				t.Errorf("the store's error was not logged: %s", logs.String())
			}
		})
	}

	t.Run("a report that cannot be computed: 409 TEMPLATE_OMISSIONS_UNAVAILABLE", func(t *testing.T) {
		logs.Reset()
		rr := httptest.NewRecorder()
		writeTemplateOmissionRefusal(rr, testOrg, "sha256:planted-p10-digest", nil, errors.New(plantedStoreError))
		body := decodeBody(t, rr)
		if rr.Code != http.StatusConflict || body["reason"] != "activation_refused" || body["code"] != activation.CodeTemplateOmissionsUnavailable {
			t.Fatalf("status %d body %v; want 409 activation_refused %s", rr.Code, body, activation.CodeTemplateOmissionsUnavailable)
		}
		msg, _ := body["error"].(string)
		if strings.Contains(msg, "planted-4255-store-error") || !strings.Contains(msg, "retry the activation") {
			t.Errorf("error %q; want the fixed sentence and none of the report's error", msg)
		}
		if !strings.Contains(logs.String(), "planted-4255-store-error") {
			t.Errorf("the report's error was not logged: %s", logs.String())
		}
	})

	// CONTROL: a store that simply does not hold the digest passes through.
	empty, err := authoring.NewStoreWithBackend(authoring.StaticTrust(pdp.NewTrustStore()), profile, authoring.NewMemoryBackend())
	if err != nil {
		t.Fatal(err)
	}
	if refuseUnacknowledgedTemplateOmissions(context.Background(), httptest.NewRecorder(), empty, testOrg, "sha256:planted-p10-digest", nil) {
		t.Fatal("an unknown digest was refused by the omission rule; Promote must answer it")
	}
}

// A TEMPLATE POLICY KEPT BY ID BUT CHANGED is acknowledged like an omitted one.
// The ids are literals: drop__table__prevention's condition is hollowed (it now
// asks for a detector verdict of false, which a flagged request never is), and
// the pricing detector's attribute is redeclared with a freshness bound, which
// changes the one template policy that reads it. (Redeclaring it optional is
// refused at publish, ABSENCE_NOT_HANDLED, unless the policy also says what
// absence means - which changes the policy itself.)
func TestActivatingADocumentThatChangesTemplateControlsRequiresNamingThem(t *testing.T) {
	const (
		hollowed    = "corpus:static_policies:drop__table__prevention"
		pricing     = "corpus:static_policies:eu__ai__act__pricing__fairness"
		pricingPath = "signal.detector.eu__ai__act__pricing__fairness"
	)
	doc := templateCarryingDocument(t)
	found := 0
	for i := range doc.Policy.Policies {
		if doc.Policy.Policies[i].ID == hollowed {
			doc.Policy.Policies[i].Where.Literal = false
			found++
		}
	}
	for i := range doc.Policy.Attributes {
		if doc.Policy.Attributes[i].Path == pricingPath {
			doc.Policy.Attributes[i].MaxAgeSeconds = 60
			found++
		}
	}
	if found != 2 {
		t.Fatalf("PREMISE: edited %d of the 2 literal template rows", found)
	}
	for _, edition := range []authoring.Edition{authoring.EditionCommunity, authoring.EditionEvaluation} {
		t.Run(string(edition), func(t *testing.T) {
			h := newRouteHandler(t, edition)
			digest := published(t, h, doc)

			rr, body := activate(t, h, digest, nil, "go live")
			assertUnacknowledgedRefusal(t, rr, body, []string{}, []string{hollowed, pricing})
			report, _ := body["template_omissions"].(map[string]any)
			if m, _ := report["message"].(string); !strings.Contains(m, "attribute "+pricingPath+" declares max_age_seconds 60, shipped 0") {
				t.Errorf("template_omissions.message %q does not name the attribute and what differs", m)
			}

			rr, body = activate(t, h, digest, []string{hollowed}, "go live")
			assertUnacknowledgedRefusal(t, rr, body, []string{}, []string{hollowed, pricing})

			rr, body = activate(t, h, digest, []string{pricing, hollowed}, "go live")
			if rr.Code != http.StatusOK {
				t.Fatalf("exactly the changed ids: status %d: %s", rr.Code, rr.Body.String())
			}
			act, _ := body["activation"].(map[string]any)
			if want := "go live [acknowledged template omissions: " + hollowed + ", " + pricing + "]"; act["reason"] != want {
				t.Errorf("activation.reason = %v, want %q", act["reason"], want)
			}
		})
	}
}

// ANOTHER ORGANIZATION'S EXACT LIST DOES NOT REACH ITS DIGEST. The rule reads the
// artifact from the CALLER's workspace, so org B naming exactly the ids org A's
// document omits is answered by Promote's "not admitted", never activated.
func TestAnotherOrganizationsAcknowledgementDoesNotActivateItsDigest(t *testing.T) {
	h := newRouteHandler(t, authoring.EditionCommunity)
	r := routerFor(h)
	digest := published(t, h, communityDocument())
	list := acknowledgedOmissions(t, communityDocument())
	other := map[string]string{"X-Org-ID": "org-somebody-else", "X-User-ID": testUser}
	rr := call(t, r, http.MethodPost, TypedAuthoringRoutePrefix+"/activate",
		typedAuthoringActivateRequest{Digest: digest, Reason: "reaching across", AcknowledgeTemplateOmissions: list}, other)
	body := decodeBody(t, rr)
	if rr.Code != http.StatusConflict || body["reason"] != "activation_refused" {
		t.Fatalf("status %d body %v; want Promote's 409 activation_refused", rr.Code, body)
	}
	if _, present := body["code"]; present {
		t.Errorf("org B's activation of org A's digest was answered by the omission rule (code %v); it must not find the artifact at all", body["code"])
	}
	if msg, _ := body["error"].(string); !strings.Contains(msg, "not admitted") {
		t.Errorf("error %q, want Promote's not-admitted refusal", msg)
	}
	if code := call(t, r, http.MethodGet, TypedAuthoringRoutePrefix+"/active", nil, other).Code; code == http.StatusOK {
		t.Fatal("org B has an active document after activating org A's digest")
	}
}

// THE TEMPLATE ROUTE: the portal's HandleTemplate on this route set, gated as
// system is gated, answering the same envelope over the same rendering.
func TestTheTemplateRouteServesTheShippedOrganizationTemplate(t *testing.T) {
	view, err := authoring.ShippedOrganizationTemplateView()
	if err != nil {
		t.Fatal(err)
	}
	want, err := json.Marshal(map[string]any{"success": true, "template": view})
	if err != nil {
		t.Fatal(err)
	}
	for _, edition := range []authoring.Edition{authoring.EditionCommunity, authoring.EditionEvaluation, authoring.EditionEnterprise} {
		t.Run(string(edition), func(t *testing.T) {
			r := routerFor(newRouteHandler(t, edition))
			rr := call(t, r, http.MethodGet, TypedAuthoringRoutePrefix+"/template", nil, gatewayHeaders())
			if rr.Code != http.StatusOK {
				t.Fatalf("status = %d: %s", rr.Code, rr.Body.String())
			}
			if got := bytes.TrimSpace(rr.Body.Bytes()); !bytes.Equal(got, want) {
				t.Fatalf("the template route's body is not {success, template: ShippedOrganizationTemplateView()}:\n got %s\nwant %s", got, want)
			}
			// The same gating as system: an unstamped caller is refused, identically.
			for _, path := range []string{"/template", "/system"} {
				rr := call(t, r, http.MethodGet, TypedAuthoringRoutePrefix+path, nil, map[string]string{})
				if rr.Code != http.StatusUnauthorized || decodeBody(t, rr)["reason"] != "org_not_stamped" {
					t.Errorf("GET %s with no gateway stamp: status %d body %s; want 401 org_not_stamped", path, rr.Code, rr.Body.String())
				}
			}
			// GET only: a write verb reaches the unenumerated guard.
			if rr := call(t, r, http.MethodPost, TypedAuthoringRoutePrefix+"/template", map[string]any{}, gatewayHeaders()); rr.Code == http.StatusOK {
				t.Errorf("POST /template answered 200; the template has no write verb")
			}
		})
	}
}
