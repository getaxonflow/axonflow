// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"encoding/json"
	"net/http"
	"testing"

	"axonflow/platform/decision/authoring"
	"axonflow/platform/decision/pdp"
)

// TestTheSystemCorpusIsReadableAndNotWritableThroughTheRoute drives the read-only
// system view through the router a deployment serves, and every write verb
// against the same path.
func TestTheSystemCorpusIsReadableAndNotWritableThroughTheRoute(t *testing.T) {
	r := routerFor(newRouteHandler(t, authoring.EditionCommunity))

	rr := call(t, r, http.MethodGet, TypedAuthoringRoutePrefix+"/system", nil, gatewayHeaders())
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /system: status=%d body=%s", rr.Code, rr.Body.String())
	}
	var body struct {
		Success bool                       `json:"success"`
		System  authoring.SystemCorpusView `json:"system"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("the system view does not decode: %v", err)
	}
	shipped, err := pdp.SystemCorpusDocument()
	if err != nil {
		t.Fatal(err)
	}
	digest, _ := pdp.SystemCorpusDigest()
	if !body.Success || body.System.Digest != digest || len(body.System.Controls) != len(shipped.Policies) {
		t.Fatalf("the route served success=%v digest=%s with %d controls; the shipped corpus is %s with %d",
			body.Success, body.System.Digest, len(body.System.Controls), digest, len(shipped.Policies))
	}
	for _, c := range body.System.Controls {
		if c.Assurance == "" {
			t.Fatalf("control %s reached the route with no assurance class", c.ID)
		}
	}

	// NO WRITE VERB REACHES A HANDLER THAT COULD ACT ON IT.
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
		rr := call(t, r, method, TypedAuthoringRoutePrefix+"/system", map[string]any{"policies": []any{}}, gatewayHeaders())
		if rr.Code != http.StatusNotFound {
			t.Fatalf("%s /system: status=%d, want the unenumerated 404; body=%.300s", method, rr.Code, rr.Body.String())
		}
	}

	// AND IT IS A GATEWAY-STAMPED READ LIKE EVERY OTHER ON THIS SURFACE.
	if rr := call(t, r, http.MethodGet, TypedAuthoringRoutePrefix+"/system", nil, nil); rr.Code == http.StatusOK {
		t.Fatalf("GET /system without the gateway's stamp answered 200; body=%.300s", rr.Body.String())
	}
}
