// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"axonflow/platform/decision/authoring"
	"axonflow/platform/decision/legacycompile"
)

// THE ROUTE SIGNS THE SYSTEM_CONTROLS IT IS SENT (PRD v11 §1.5). It rebuilt
// every document from its metadata and policy, so a system_controls section was
// dropped before it was validated or signed: the publish answered 200 with a new
// digest and the organization was decided exactly as before (measured by
// runtime-e2e 3564's E1a). Published through the real router, the stored
// artifact's signed source carries the section, and its provenance names the
// digest of the document WITH it, which differs from the digest without it.
func TestTheRoutePublishesAndSignsTheSystemControlsItIsSent(t *testing.T) {
	h := newRouteHandler(t, authoring.EditionCommunity)
	r := routerFor(h)
	doc := communityDocument()
	sent := []authoring.SystemControlEntry{{Control: "corpus:static_policies:sys__sqli__union__select", Action: legacycompile.ActionBlock}}
	doc.SystemControls = sent

	rr := call(t, r, http.MethodPost, TypedAuthoringRoutePrefix+"/publish", publishBody(doc), gatewayHeaders())
	if rr.Code != http.StatusOK {
		t.Fatalf("publish: status=%d body=%s", rr.Code, rr.Body.String())
	}
	digest, _ := decodeBody(t, rr)["digest"].(string)
	ws, err := h.workspaceFor(context.Background(), testOrg)
	if err != nil {
		t.Fatal(err)
	}
	art, found, err := ws.api.Store().Get(context.Background(), typedAuthoringRoot, digest)
	if err != nil || !found {
		t.Fatalf("the published artifact %q is not in the store (found=%v): %v", digest, found, err)
	}
	stored, err := art.Document()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(stored.SystemControls, sent) {
		t.Fatalf("the signed source carries system_controls %+v; the request sent %+v", stored.SystemControls, sent)
	}
	with, err := authoring.Digest(stored)
	if err != nil {
		t.Fatal(err)
	}
	bare := *stored
	bare.SystemControls = nil
	without, err := authoring.Digest(&bare)
	if err != nil {
		t.Fatal(err)
	}
	if art.Provenance().SourceDigest != with || with == without {
		t.Fatalf("the signed source digests to %s; the document with the section digests to %s and without it to %s",
			art.Provenance().SourceDigest, with, without)
	}
}

// The route VALIDATES the section it is sent: an entry an author could not save
// is refused with its code, rather than dropped and passed.
func TestTheRouteValidatesTheSystemControlsItIsSent(t *testing.T) {
	r := routerFor(newRouteHandler(t, authoring.EditionCommunity))
	doc := communityDocument()
	doc.SystemControls = []authoring.SystemControlEntry{{Control: "corpus:static_policies:sys__sqli__union__select"}}
	rr := call(t, r, http.MethodPost, TypedAuthoringRoutePrefix+"/validate", typedAuthoringDocumentRequest{Document: doc}, gatewayHeaders())
	if !strings.Contains(rr.Body.String(), authoring.CodeSystemControlMalformed) {
		t.Fatalf("validate answered %d %s; want the entry refused %s", rr.Code, rr.Body.String(), authoring.CodeSystemControlMalformed)
	}
}
