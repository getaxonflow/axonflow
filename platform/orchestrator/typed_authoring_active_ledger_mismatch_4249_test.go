// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"bytes"
	"context"
	"errors"
	"log"
	"net/http"
	"strings"
	"testing"

	"axonflow/platform/decision/authoring"
	"axonflow/platform/decision/legacycompile"
)

// THE READ ROUTES DO NOT REPORT "NOTHING ACTIVE" FOR A DOCUMENT THE STORE LOST
// (#4249 row 5797853828). The ledger names an active digest the store does not
// hold. Before, the store answered that as nothing active: GET /active said
// 404 nothing_active, the summary counted the shipped set, and the compliance
// effects reported the organization's own controls as absent - a report
// under-counting what is in force. Each now answers the store's failure.
const ledgerGhost = "sha256:active-but-not-stored"

func ledgerMismatchHandler(t *testing.T) *TypedAuthoringRouteHandler {
	t.Helper()
	b := &routeWriteFailingBackend{Backend: authoring.NewMemoryBackend()}
	h := routeWithFailingStore(t, b)
	b.activeDigest = ledgerGhost
	return h
}

// captureRouteLog records what the route logs for the rest of the test.
func captureRouteLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(prev) })
	return &buf
}

func assertLedgerMismatchRefused(t *testing.T, code int, body string, logs *bytes.Buffer) {
	t.Helper()
	// 503 like every store failure, and since #4249 row 5797853828 with its
	// own reason: a retry will not heal a lost active document.
	if code != http.StatusServiceUnavailable || !strings.Contains(body, `"reason":"ledger_inconsistent"`) {
		t.Fatalf("status %d body %s; want 503 ledger_inconsistent", code, body)
	}
	if strings.Contains(body, ledgerGhost) {
		t.Fatalf("the missing digest reached the body: %s", body)
	}
	// The digest is in the operator's log: the only place the inconsistency is
	// told from an outage.
	if !strings.Contains(logs.String(), "the active digest "+ledgerGhost) {
		t.Fatalf("the log does not name the missing digest: %s", logs.String())
	}
}

func TestTheReadRoutesAnswerALostActiveDocumentAsTheStore(t *testing.T) {
	t.Run("GET /active", func(t *testing.T) {
		h := ledgerMismatchHandler(t)
		logs := captureRouteLog(t)
		rr := call(t, routerFor(h), http.MethodGet, TypedAuthoringRoutePrefix+"/active", nil, gatewayHeaders())
		assertLedgerMismatchRefused(t, rr.Code, rr.Body.String(), logs)
	})
	t.Run("GET /active/summary", func(t *testing.T) {
		h := ledgerMismatchHandler(t)
		logs := captureRouteLog(t)
		rr := call(t, routerFor(h), http.MethodGet, TypedAuthoringRoutePrefix+"/active/summary", nil, gatewayHeaders())
		assertLedgerMismatchRefused(t, rr.Code, rr.Body.String(), logs)
	})
	t.Run("the compliance effects", func(t *testing.T) {
		h := ledgerMismatchHandler(t)
		effects, err := h.ActiveEffects(context.Background(), testOrg, legacycompile.PlaneDecide, "")
		if !errors.Is(err, ErrActiveEffectsUnavailable) || effects != nil {
			t.Fatalf("ActiveEffects answered (%d effects, %v); want ErrActiveEffectsUnavailable, never the shipped set", len(effects), err)
		}
		if !strings.Contains(err.Error(), "the active digest "+ledgerGhost) {
			t.Fatalf("the error its caller logs does not name the missing digest: %v", err)
		}
	})
	t.Run("control: nothing active is still 404 nothing_active", func(t *testing.T) {
		b := &routeWriteFailingBackend{Backend: authoring.NewMemoryBackend()}
		rr := call(t, routerFor(routeWithFailingStore(t, b)), http.MethodGet, TypedAuthoringRoutePrefix+"/active", nil, gatewayHeaders())
		if rr.Code != http.StatusNotFound || !strings.Contains(rr.Body.String(), `"reason":"nothing_active"`) {
			t.Fatalf("status %d body %s; want 404 nothing_active", rr.Code, rr.Body.String())
		}
	})
}
