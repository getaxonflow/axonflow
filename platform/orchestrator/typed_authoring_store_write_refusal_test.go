// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"

	"axonflow/platform/decision/authoring"
	"axonflow/platform/decision/pdp"
)

// A STORE FAILURE ON THE ROUTE'S WRITES IS NOT THE CALLER'S FAULT (#4283).
// Publish answered it 422 publication_refused and activate 409
// activation_refused, each echoing the database's error; both now answer 503
// storage_unavailable with the error in the log only, or 503
// ledger_inconsistent (since #4439) when an activation finds the ledger's
// active document missing from the store. A refusal stays a
// refusal. And requireWorkspace answers 429 workspace_limit only for the cap:
// anything else is a build that failed, 500 workspace_unavailable (since
// #4439; it was 503), and a waiter that gave up on a build still running is
// 503 workspace_building.

// routeWriteFailingBackend fails the chosen write-path calls.
type routeWriteFailingBackend struct {
	authoring.Backend
	put, appendAct error
	// activeDigest, when set, is what ActiveDigest answers, whatever the
	// ledger holds.
	activeDigest string
}

func (b *routeWriteFailingBackend) ActiveDigest(ctx context.Context, root pdp.Root) (string, error) {
	if b.activeDigest != "" {
		return b.activeDigest, nil
	}
	return b.Backend.ActiveDigest(ctx, root)
}

func (b *routeWriteFailingBackend) PutArtifact(ctx context.Context, root pdp.Root, a *authoring.Artifact) error {
	if b.put != nil {
		return b.put
	}
	return b.Backend.PutArtifact(ctx, root, a)
}

func (b *routeWriteFailingBackend) AppendActivation(ctx context.Context, root pdp.Root, act authoring.Activation, expectPrev string) error {
	if b.appendAct != nil {
		return b.appendAct
	}
	return b.Backend.AppendActivation(ctx, root, act, expectPrev)
}

// routeWithFailingStore builds the organization's workspace and rebuilds its
// API over b, with a trust store that authorizes the workspace's own key so a
// publication verifies and reaches the store.
func routeWithFailingStore(t *testing.T, b authoring.Backend) *TypedAuthoringRouteHandler {
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
	minted := pdp.NewTrustStore()
	minted.Authorize(typedAuthoringRoot, ws.keyID, ws.priv.Public().(ed25519.PublicKey))
	ws.api, err = authoring.NewAPIWithBackend(snap.Catalog, authoring.StaticTrust(minted), ws.profile, b)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func assertRouteStoreRefusal(t *testing.T, rr *httptest.ResponseRecorder) {
	t.Helper()
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status %d, want 503: %s", rr.Code, rr.Body.String())
	}
	body := decodeBody(t, rr)
	if body["success"] != false || body["reason"] != "storage_unavailable" {
		t.Fatalf("body %v; want reason storage_unavailable", body)
	}
	for _, fragment := range []string{"pq:", "10.42.255.7", "5432", "planted-4255-store-error"} {
		if strings.Contains(rr.Body.String(), fragment) {
			t.Fatalf("the body carries %q from the store's own error: %s", fragment, rr.Body.String())
		}
	}
}

func TestTheRouteAnswersAStoreFailureOnAWriteAsTheStore(t *testing.T) {
	storeErr := errors.New(plantedStoreError)

	t.Run("publish: the artifact cannot be stored", func(t *testing.T) {
		b := &routeWriteFailingBackend{Backend: authoring.NewMemoryBackend(), put: storeErr}
		r := routerFor(routeWithFailingStore(t, b))
		rr := call(t, r, http.MethodPost, TypedAuthoringRoutePrefix+"/publish", publishBody(communityDocument()), gatewayHeaders())
		assertRouteStoreRefusal(t, rr)
	})

	publish := func(t *testing.T, b *routeWriteFailingBackend) (*mux.Router, string) {
		t.Helper()
		r := routerFor(routeWithFailingStore(t, b))
		rr := call(t, r, http.MethodPost, TypedAuthoringRoutePrefix+"/publish", publishBody(communityDocument()), gatewayHeaders())
		if rr.Code != http.StatusOK {
			t.Fatalf("PREMISE: publish status %d: %s", rr.Code, rr.Body.String())
		}
		digest, _ := decodeBody(t, rr)["digest"].(string)
		return r, digest
	}

	t.Run("activate: the activation cannot be recorded", func(t *testing.T) {
		b := &routeWriteFailingBackend{Backend: authoring.NewMemoryBackend()}
		r, digest := publish(t, b)
		b.appendAct = storeErr
		rr := call(t, r, http.MethodPost, TypedAuthoringRoutePrefix+"/activate",
			typedAuthoringActivateRequest{Digest: digest, Reason: "go live", AcknowledgeTemplateOmissions: acknowledgedOmissions(t, communityDocument())}, gatewayHeaders())
		assertRouteStoreRefusal(t, rr)
	})

	// A STORE THAT DISAGREES WITH ITS OWN LEDGER IS THE STORE'S FAILURE (#4249
	// row 5666782153): promote reads the active digest the ledger names as the
	// document it would replace, and the store does not hold it.
	t.Run("activate: the active digest the ledger names is not in the store", func(t *testing.T) {
		b := &routeWriteFailingBackend{Backend: authoring.NewMemoryBackend()}
		r, digest := publish(t, b)
		b.activeDigest = "sha256:active-but-not-stored"
		var logs bytes.Buffer
		prev := log.Writer()
		log.SetOutput(&logs)
		t.Cleanup(func() { log.SetOutput(prev) })
		rr := call(t, r, http.MethodPost, TypedAuthoringRoutePrefix+"/activate",
			typedAuthoringActivateRequest{Digest: digest, Reason: "go live", AcknowledgeTemplateOmissions: acknowledgedOmissions(t, communityDocument())}, gatewayHeaders())
		// 503 like every store failure, with its own reason since #4249 row
		// 5797853828: a retry will not heal it.
		if body := decodeBody(t, rr); rr.Code != http.StatusServiceUnavailable || body["success"] != false || body["reason"] != "ledger_inconsistent" {
			t.Fatalf("status %d body %v; want 503 ledger_inconsistent", rr.Code, body)
		}
		if strings.Contains(rr.Body.String(), "active-but-not-stored") {
			t.Fatalf("the store's inconsistency reached the body: %s", rr.Body.String())
		}
		// The operator's log names the missing digest, and the body does not, so
		// the log is the only place this inconsistency is told from an outage.
		if !strings.Contains(logs.String(), "the active digest sha256:active-but-not-stored") {
			t.Fatalf("the log does not name the missing active digest: %s", logs.String())
		}
	})

	t.Run("control: a digest never admitted is still 409 activation_refused", func(t *testing.T) {
		b := &routeWriteFailingBackend{Backend: authoring.NewMemoryBackend()}
		r, _ := publish(t, b)
		rr := call(t, r, http.MethodPost, TypedAuthoringRoutePrefix+"/activate",
			typedAuthoringActivateRequest{Digest: "sha256:never-admitted", Reason: "go live"}, gatewayHeaders())
		if rr.Code != http.StatusConflict || decodeBody(t, rr)["reason"] != "activation_refused" || !strings.Contains(rr.Body.String(), "is not admitted") {
			t.Fatalf("status %d body %s; want 409 activation_refused naming the digest as not admitted", rr.Code, rr.Body.String())
		}
	})

	t.Run("control: a lost race is still 409 activation_refused", func(t *testing.T) {
		b := &routeWriteFailingBackend{Backend: authoring.NewMemoryBackend()}
		r, digest := publish(t, b)
		b.appendAct = fmt.Errorf("%w: another replica first", authoring.ErrActivationRaced)
		rr := call(t, r, http.MethodPost, TypedAuthoringRoutePrefix+"/activate",
			typedAuthoringActivateRequest{Digest: digest, Reason: "go live", AcknowledgeTemplateOmissions: acknowledgedOmissions(t, communityDocument())}, gatewayHeaders())
		if rr.Code != http.StatusConflict || decodeBody(t, rr)["reason"] != "activation_refused" {
			t.Fatalf("status %d body %s; want 409 activation_refused", rr.Code, rr.Body.String())
		}
	})
}

func TestRequireWorkspaceAnswersOnlyTheCapAsAQuota(t *testing.T) {
	t.Run("the cap, with no workspace evictable, is 429 workspace_limit", func(t *testing.T) {
		h := newRouteHandler(t, authoring.EditionCommunity)
		for i := 0; i < maxTypedAuthoringWorkspaces; i++ {
			org := fmt.Sprintf("org-full-%02d", i)
			ws, err := h.workspaceFor(context.Background(), org)
			if err != nil {
				t.Fatal(err)
			}
			ws.digests["sha256:held"] = struct{}{}
		}
		rr := httptest.NewRecorder()
		if _, ok := h.requireWorkspace(context.Background(), rr, "org-one-more"); ok {
			t.Fatal("a workspace was built past the cap")
		}
		if rr.Code != http.StatusTooManyRequests || decodeBody(t, rr)["reason"] != "workspace_limit" {
			t.Fatalf("status %d body %s; want 429 workspace_limit", rr.Code, rr.Body.String())
		}
	})
	// A DEFENCE-IN-DEPTH GUARD, NOT A PRODUCTION PATH (master's ruling on
	// #4439). No production input reaches buildWorkspace's "no vocabulary"
	// arm: vocabulary() memoises success only, and every caller of
	// workspaceFor resolves the vocabulary first. This cell reaches it only by
	// mutating the handler's memoised state, so it documents that the guard
	// exists and answers without a cause in the body; it is NOT coverage of
	// the 503 -> 500 change for reachable build failures, which
	// TestAWaiterOnAPanickedBuildIsAnswered500WorkspaceUnavailable carries.
	t.Run("defence-in-depth guard, unreachable from production callers: a build against no vocabulary is 500 workspace_unavailable with no cause in the body", func(t *testing.T) {
		h := newRouteHandler(t, authoring.EditionCommunity)
		// The vocabulary is resolved and then taken away: workspaceFor refuses
		// for a reason that is not the cap.
		h.vocabMu.Lock()
		h.snap, h.snapErr, h.resolved = nil, nil, true
		h.vocabMu.Unlock()
		rr := httptest.NewRecorder()
		if _, ok := h.requireWorkspace(context.Background(), rr, testOrg); ok {
			t.Fatal("a workspace was built with no vocabulary")
		}
		body := decodeBody(t, rr)
		// 500, as the portal answers it: a build that failed is not healed by
		// a retry (#4283, master's ruling on (iv)); it was 503 here.
		if rr.Code != http.StatusInternalServerError || body["reason"] != "workspace_unavailable" {
			t.Fatalf("status %d body %v; want 500 workspace_unavailable (a deployment fault is not a quota)", rr.Code, body)
		}
		if strings.Contains(rr.Body.String(), "vocabulary") {
			t.Fatalf("the cause reached the body: %s", rr.Body.String())
		}
	})
}
