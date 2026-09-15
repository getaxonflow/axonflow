// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"axonflow/platform/decision/activation"
	"axonflow/platform/decision/authoring"
	"axonflow/platform/decision/pdp"
	"axonflow/platform/policy/authoringstore"
)

const summaryPath = "/api/v1/typed-policies/active/summary"

// summaryOf reads the summary route through the router and decodes its 200.
func summaryOf(t *testing.T, h *TypedAuthoringRouteHandler) map[string]any {
	t.Helper()
	rr := call(t, routerFor(h), http.MethodGet, summaryPath, nil, gatewayHeaders())
	if rr.Code != http.StatusOK {
		t.Fatalf("summary: status %d, want 200: %s", rr.Code, rr.Body.String())
	}
	return decodeBody(t, rr)
}

// countOf reads one count from a decoded summary.
func countOf(t *testing.T, body map[string]any, field string) int {
	t.Helper()
	n, ok := body[field].(float64)
	if !ok {
		t.Fatalf("summary field %q is %v, not a number: %v", field, body[field], body)
	}
	return int(n)
}

// assertNothingOfThePlantedError holds a refusal's body free of the planted
// store error: the cause goes to the log only.
func assertNothingOfThePlantedError(t *testing.T, raw string) {
	t.Helper()
	for _, fragment := range []string{"pq:", "10.42.255.7", "5432", "planted-4255", "authoringstore:"} {
		if strings.Contains(raw, fragment) {
			t.Fatalf("the body carries %q from the error; it belongs in the log only: %s", fragment, raw)
		}
	}
}

// failingStoreHandler is a handler whose organization workspace reads its
// store through backend.
func failingStoreHandler(t *testing.T, backend authoring.Backend) *TypedAuthoringRouteHandler {
	t.Helper()
	h := newRouteHandler(t, authoring.EditionCommunity)
	ws, err := h.workspaceFor(context.Background(), testOrg)
	if err != nil {
		t.Fatal(err)
	}
	snap, err := h.vocabulary()
	if err != nil || snap == nil {
		t.Fatalf("the deployment vocabulary must resolve: %v", err)
	}
	if ws.api, err = authoring.NewAPIWithBackend(snap.Catalog, authoring.StaticTrust(pdp.NewTrustStore()), ws.profile, backend); err != nil {
		t.Fatal(err)
	}
	return h
}

// GET /api/v1/typed-policies/active/summary COUNTS WHAT IS IN FORCE (#4152).
// With nothing active the organization root is the implicit baseline, which
// is enforced and counted, with nothing the organization's. A published
// document is not in force until it is activated; once it is, each of its
// policies is the organization's.
func TestTheSummaryRouteCountsTheImplicitBaselineAndThenTheActivatedDocument(t *testing.T) {
	h := newRouteHandler(t, authoring.EditionCommunity)
	r := routerFor(h)

	before := summaryOf(t, h)
	if before["success"] != true || before["scope"] != "decide" || before["pack"] != nil || before["packs_counted"] != false {
		t.Fatalf("summary %v; want success, scope decide, pack null and packs_counted false", before)
	}
	if countOf(t, before, "organization") != 0 || countOf(t, before, "shipped") == 0 || countOf(t, before, "total") != countOf(t, before, "shipped") {
		t.Fatalf("summary %v with nothing active; want every policy shipped", before)
	}

	doc := communityDocument()
	rr := call(t, r, http.MethodPost, TypedAuthoringRoutePrefix+"/publish", publishBody(doc), gatewayHeaders())
	if rr.Code != http.StatusOK {
		t.Fatalf("publish: status %d: %s", rr.Code, rr.Body.String())
	}
	digest, _ := decodeBody(t, rr)["digest"].(string)
	if published := summaryOf(t, h); countOf(t, published, "organization") != 0 {
		t.Fatalf("summary %v; a published document that is not active is not in force", published)
	}

	rr = call(t, r, http.MethodPost, TypedAuthoringRoutePrefix+"/activate",
		typedAuthoringActivateRequest{Digest: digest, Reason: "count it"}, gatewayHeaders())
	if rr.Code != http.StatusOK {
		t.Fatalf("activate: status %d: %s", rr.Code, rr.Body.String())
	}
	after := summaryOf(t, h)
	if got, want := countOf(t, after, "organization"), len(doc.Policy.Policies); got != want {
		t.Fatalf("organization = %d with the document active; it carries %d policies: %v", got, want, after)
	}
	if countOf(t, after, "total") != countOf(t, after, "shipped")+countOf(t, after, "organization") || countOf(t, after, "disabled") != 0 {
		t.Fatalf("summary %v; want total = shipped + organization and nothing disabled", after)
	}
}

// The summary refuses wherever /active refuses (#4255), with the same answer,
// and never counts the implicit baseline in place of a document it could not
// read: that count would tell an operator their document is not in force.
func TestTheSummaryRouteRefusesWhereTheActiveRouteRefuses(t *testing.T) {
	t.Run("a workspace whose durable store could not be opened answers 503 storage_unavailable", func(t *testing.T) {
		h := newRouteHandler(t, authoring.EditionCommunity)
		db, err := sql.Open("postgres", "postgres://planted-4255@10.42.255.7:5432/none?sslmode=disable")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = db.Close() })
		h.db = db
		h.openForSigning = func(context.Context, *sql.DB, pdp.Root, string, string, ed25519.PublicKey, string) (*authoringstore.Store, authoring.TrustSource, string, error) {
			return nil, nil, "", errors.New(plantedStoreError)
		}
		assertStorageUnavailable(t, call(t, routerFor(h), http.MethodGet, summaryPath, nil, gatewayHeaders()))
	})

	t.Run("a store that could not be read answers 503 storage_unavailable", func(t *testing.T) {
		h := failingStoreHandler(t, activeReadFailingBackend{Backend: authoring.NewMemoryBackend(), err: errors.New(plantedStoreError)})
		assertStorageUnavailable(t, call(t, routerFor(h), http.MethodGet, summaryPath, nil, gatewayHeaders()))
	})

	t.Run("an active document that does not verify answers 500 active_unverifiable", func(t *testing.T) {
		unverifiable := fmt.Errorf("%w: under root %q: %w", authoringstore.ErrArtifactUnverifiable, pdp.RootOrganization, errors.New(plantedStoreError))
		h := failingStoreHandler(t, unverifiableActiveBackend{Backend: authoring.NewMemoryBackend(), err: unverifiable})
		rr := call(t, routerFor(h), http.MethodGet, summaryPath, nil, gatewayHeaders())
		if rr.Code != http.StatusInternalServerError || decodeBody(t, rr)["reason"] != "active_unverifiable" {
			t.Fatalf("status %d %s; want 500 active_unverifiable", rr.Code, rr.Body.String())
		}
		assertNothingOfThePlantedError(t, rr.Body.String())
	})

	t.Run("a signing key not loaded answers 503 key_not_loaded", func(t *testing.T) {
		notLoaded := fmt.Errorf("authoringstore: a stored artifact under root %q: %w: %w", pdp.RootOrganization, authoringstore.ErrSigningKeyNotLoaded, errors.New(plantedStoreError))
		h := failingStoreHandler(t, unverifiableActiveBackend{Backend: authoring.NewMemoryBackend(), err: notLoaded})
		rr := call(t, routerFor(h), http.MethodGet, summaryPath, nil, gatewayHeaders())
		if rr.Code != http.StatusServiceUnavailable || decodeBody(t, rr)["reason"] != "key_not_loaded" {
			t.Fatalf("status %d %s; want 503 key_not_loaded", rr.Code, rr.Body.String())
		}
		assertNothingOfThePlantedError(t, rr.Body.String())
	})

	t.Run("an activation that cannot be built answers 503 summary_unavailable", func(t *testing.T) {
		h := newRouteHandler(t, authoring.EditionCommunity)
		ws, err := h.workspaceFor(context.Background(), testOrg)
		if err != nil {
			t.Fatal(err)
		}
		ws.activationInputs = func(context.Context) (activation.Inputs, error) {
			return activation.Inputs{}, errors.New(plantedStoreError)
		}
		rr := call(t, routerFor(h), http.MethodGet, summaryPath, nil, gatewayHeaders())
		if rr.Code != http.StatusServiceUnavailable || decodeBody(t, rr)["reason"] != "summary_unavailable" {
			t.Fatalf("status %d %s; want 503 summary_unavailable", rr.Code, rr.Body.String())
		}
		assertNothingOfThePlantedError(t, rr.Body.String())
	})
}

// A control the document disables is reported as disabled through the route,
// and leaves shipped and the total, because the engine does not carry it. The
// same document is activated with and without the control disabled, so every
// other count is the control's own difference.
func TestTheSummaryRouteReportsAControlTheDocumentDisabled(t *testing.T) {
	activated := func(t *testing.T, controls []authoring.SystemControlEntry) map[string]any {
		t.Helper()
		h := newRouteHandler(t, authoring.EditionCommunity)
		r := routerFor(h)
		doc := communityDocument()
		doc.SystemControls = controls
		rr := call(t, r, http.MethodPost, TypedAuthoringRoutePrefix+"/publish", publishBody(doc), gatewayHeaders())
		if rr.Code != http.StatusOK {
			t.Fatalf("publish: status %d: %s", rr.Code, rr.Body.String())
		}
		digest, _ := decodeBody(t, rr)["digest"].(string)
		rr = call(t, r, http.MethodPost, TypedAuthoringRoutePrefix+"/activate",
			typedAuthoringActivateRequest{Digest: digest, Reason: "count it"}, gatewayHeaders())
		if rr.Code != http.StatusOK {
			t.Fatalf("activate: status %d: %s", rr.Code, rr.Body.String())
		}
		return summaryOf(t, h)
	}
	off := false
	plain := activated(t, nil)
	disabled := activated(t, []authoring.SystemControlEntry{{Control: "corpus:static_policies:sys__sqli__union__select", Enabled: &off}})
	n := countOf(t, disabled, "disabled")
	if countOf(t, plain, "disabled") != 0 || n == 0 {
		t.Fatalf("disabled = %d with the control disabled and %d without; want it counted", n, countOf(t, plain, "disabled"))
	}
	if countOf(t, disabled, "total") != countOf(t, plain, "total")-n || countOf(t, disabled, "shipped") != countOf(t, plain, "shipped")-n ||
		countOf(t, disabled, "organization") != countOf(t, plain, "organization") {
		t.Fatalf("summary %v with the control disabled, %v without; want its %d policy(ies) moved from shipped and the total to disabled", disabled, plain, n)
	}
}
