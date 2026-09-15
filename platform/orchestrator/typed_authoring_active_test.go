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
	"net/http/httptest"
	"strings"
	"testing"

	"axonflow/platform/decision/authoring"
	"axonflow/platform/decision/pdp"
	"axonflow/platform/policy/authoringstore"
)

// activeReadFailingBackend is the in-process authoring backend whose
// active-digest read fails, as the durable store's does when postgres cannot be
// reached after the workspace was built.
type activeReadFailingBackend struct {
	authoring.Backend
	err error
}

func (b activeReadFailingBackend) ActiveDigest(context.Context, pdp.Root) (string, error) {
	return "", b.err
}

// unverifiableActiveBackend is the in-process authoring backend whose active
// artifact does not verify on load, as the durable store reports one whose key
// was de-authorized or whose signature no longer holds.
type unverifiableActiveBackend struct {
	authoring.Backend
	err error
}

func (b unverifiableActiveBackend) ActiveDigest(context.Context, pdp.Root) (string, error) {
	return "sha256:planted-4255-active", nil
}

func (b unverifiableActiveBackend) GetArtifact(context.Context, pdp.Root, string) (*authoring.Artifact, bool, error) {
	return nil, false, b.err
}

// plantedStoreError is distinctive on purpose: each fragment of it is asserted
// ABSENT from the response body, so the rule that the store's error goes to the
// log and never to the caller has a test that fails when it is broken.
const plantedStoreError = "pq: connection to 10.42.255.7:5432 refused (planted-4255-store-error)"

// assertStorageUnavailable holds a response to /active's refusal of a store it
// cannot use: 503 storage_unavailable, the retry sentence, and nothing of the
// planted store error.
func assertStorageUnavailable(t *testing.T, rr *httptest.ResponseRecorder) {
	t.Helper()
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status %d, want 503 for a store that cannot be used: %s", rr.Code, rr.Body.String())
	}
	body := decodeBody(t, rr)
	if body["success"] != false || body["reason"] != "storage_unavailable" {
		t.Fatalf("body %v; want success false and reason storage_unavailable", body)
	}
	if msg, _ := body["error"].(string); !strings.Contains(msg, "retry once the database is reachable") {
		t.Fatalf("error %q does not tell the caller to retry once the database is reachable", msg)
	}
	raw := rr.Body.String()
	for _, fragment := range []string{"pq:", "10.42.255.7", "5432", "connection to", "planted-4255-store-error"} {
		if strings.Contains(raw, fragment) {
			t.Fatalf("the body carries %q from the store's own error; it belongs in the log only: %s", fragment, raw)
		}
	}
}

// GET /api/v1/typed-policies/active TELLS "NOTHING ACTIVE" FROM "THE STORE
// COULD NOT BE READ" (#4255). It answered 404 nothing_active for both, and every
// SDK maps that 404 to "no active document", so a database blip told an
// operator their organization had no policy in force.
func TestTheActiveRouteTellsNothingActiveFromAStoreThatCouldNotBeRead(t *testing.T) {
	const path = "/api/v1/typed-policies/active"

	t.Run("nothing active answers 404 nothing_active", func(t *testing.T) {
		rr := call(t, routerFor(newRouteHandler(t, authoring.EditionCommunity)), http.MethodGet, path, nil, gatewayHeaders())
		if rr.Code != http.StatusNotFound {
			t.Fatalf("status %d, want 404: %s", rr.Code, rr.Body.String())
		}
		if got := decodeBody(t, rr)["reason"]; got != "nothing_active" {
			t.Fatalf("reason %v, want nothing_active", got)
		}
	})

	t.Run("a store that could not be read answers 503 storage_unavailable, never its error", func(t *testing.T) {
		h := newRouteHandler(t, authoring.EditionCommunity)
		ws, err := h.workspaceFor(context.Background(), testOrg)
		if err != nil {
			t.Fatal(err)
		}
		snap, err := h.vocabulary()
		if err != nil || snap == nil {
			t.Fatalf("the deployment vocabulary must resolve: %v", err)
		}
		// The workspace's store is replaced by one whose read fails. The route
		// resolves this same workspace, because workspaceFor caches every
		// workspace that is not degraded, so the request reads through it.
		ws.api, err = authoring.NewAPIWithBackend(snap.Catalog, authoring.StaticTrust(pdp.NewTrustStore()), ws.profile,
			activeReadFailingBackend{Backend: authoring.NewMemoryBackend(), err: errors.New(plantedStoreError)})
		if err != nil {
			t.Fatal(err)
		}
		assertStorageUnavailable(t, call(t, routerFor(h), http.MethodGet, path, nil, gatewayHeaders()))
	})

	// A DEGRADED WORKSPACE (R3 round 1). With the durable store configured but
	// not openable, workspaceFor builds the workspace over the EMPTY in-process
	// store and does not cache it, so without its own check /active answered
	// "nothing active" on the first request after a restart while the database
	// was down.
	t.Run("a workspace whose durable store could not be opened answers 503, never nothing_active", func(t *testing.T) {
		h := newRouteHandler(t, authoring.EditionCommunity)
		// A configured database this workspace cannot open. sql.Open does not
		// dial, and the open itself is the seam's stub, so nothing connects.
		db, err := sql.Open("postgres", "postgres://planted-4255@10.42.255.7:5432/none?sslmode=disable")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = db.Close() })
		h.db = db
		h.openForSigning = func(context.Context, *sql.DB, pdp.Root, string, string, ed25519.PublicKey, string) (*authoringstore.Store, authoring.TrustSource, string, error) {
			return nil, nil, "", errors.New(plantedStoreError)
		}
		assertStorageUnavailable(t, call(t, routerFor(h), http.MethodGet, path, nil, gatewayHeaders()))
	})

	// AN ACTIVE DOCUMENT THAT NO LONGER VERIFIES (R3 round 1). The store answered;
	// what it holds does not verify. That is a 500, not storage_unavailable:
	// retrying cannot clear it.
	t.Run("an active document that does not verify answers 500 active_unverifiable, never its error", func(t *testing.T) {
		h := newRouteHandler(t, authoring.EditionCommunity)
		ws, err := h.workspaceFor(context.Background(), testOrg)
		if err != nil {
			t.Fatal(err)
		}
		snap, err := h.vocabulary()
		if err != nil || snap == nil {
			t.Fatalf("the deployment vocabulary must resolve: %v", err)
		}
		unverifiable := fmt.Errorf("%w: under root %q: %w", authoringstore.ErrArtifactUnverifiable, pdp.RootOrganization, errors.New(plantedStoreError))
		ws.api, err = authoring.NewAPIWithBackend(snap.Catalog, authoring.StaticTrust(pdp.NewTrustStore()), ws.profile,
			unverifiableActiveBackend{Backend: authoring.NewMemoryBackend(), err: unverifiable})
		if err != nil {
			t.Fatal(err)
		}
		rr := call(t, routerFor(h), http.MethodGet, path, nil, gatewayHeaders())
		if rr.Code != http.StatusInternalServerError {
			t.Fatalf("status %d, want 500 for an active document that does not verify: %s", rr.Code, rr.Body.String())
		}
		body := decodeBody(t, rr)
		if body["success"] != false || body["reason"] != "active_unverifiable" {
			t.Fatalf("body %v; want success false and reason active_unverifiable", body)
		}
		raw := rr.Body.String()
		for _, fragment := range []string{"pq:", "10.42.255.7", "5432", "planted-4255", "did not verify on load"} {
			if strings.Contains(raw, fragment) {
				t.Fatalf("the body carries %q from the verification error; it belongs in the log only: %s", fragment, raw)
			}
		}
	})

	// A SIGNING KEY THIS REPLICA HAS NOT LOADED (R3 rounds 2-4). The reload that
	// would load it was deferred, so the answer is 503 key_not_loaded, which a
	// retry may settle, and not the 500 of an artifact that does not verify.
	t.Run("a signing key not loaded answers 503 key_not_loaded, never its error", func(t *testing.T) {
		h := newRouteHandler(t, authoring.EditionCommunity)
		ws, err := h.workspaceFor(context.Background(), testOrg)
		if err != nil {
			t.Fatal(err)
		}
		snap, err := h.vocabulary()
		if err != nil || snap == nil {
			t.Fatalf("the deployment vocabulary must resolve: %v", err)
		}
		notLoaded := fmt.Errorf("authoringstore: a stored artifact under root %q: %w: %w", pdp.RootOrganization, authoringstore.ErrSigningKeyNotLoaded, errors.New(plantedStoreError))
		ws.api, err = authoring.NewAPIWithBackend(snap.Catalog, authoring.StaticTrust(pdp.NewTrustStore()), ws.profile,
			unverifiableActiveBackend{Backend: authoring.NewMemoryBackend(), err: notLoaded})
		if err != nil {
			t.Fatal(err)
		}
		rr := call(t, routerFor(h), http.MethodGet, path, nil, gatewayHeaders())
		if rr.Code != http.StatusServiceUnavailable {
			t.Fatalf("status %d, want 503 for a signing key not loaded: %s", rr.Code, rr.Body.String())
		}
		body := decodeBody(t, rr)
		if body["success"] != false || body["reason"] != "key_not_loaded" {
			t.Fatalf("body %v; want success false and reason key_not_loaded", body)
		}
		if msg, _ := body["error"].(string); !strings.Contains(msg, "retry") {
			t.Fatalf("error %q does not tell the caller to retry", msg)
		}
		raw := rr.Body.String()
		for _, fragment := range []string{"pq:", "10.42.255.7", "5432", "planted-4255", "authoringstore:"} {
			if strings.Contains(raw, fragment) {
				t.Fatalf("the body carries %q from the error; it belongs in the log only: %s", fragment, raw)
			}
		}
	})
}
