// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"errors"
	"net/http"
	"strings"
	"testing"

	"axonflow/platform/decision/activation"
	"axonflow/platform/decision/authoring"
	"axonflow/platform/decision/legacycompile"
	"axonflow/platform/decision/pdp"
	"axonflow/platform/policy/authoringstore"
)

const ktpControl = "corpus:static_policies:sys__pii__indonesia__ktp"

// activatedHandler is a handler whose organization has the community document
// active, with controls as its system_controls.
func activatedHandler(t *testing.T, controls []authoring.SystemControlEntry) *TypedAuthoringRouteHandler {
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
		typedAuthoringActivateRequest{Digest: digest, Reason: "report it", AcknowledgeTemplateOmissions: acknowledgedOmissions(t, doc)}, gatewayHeaders())
	if rr.Code != http.StatusOK {
		t.Fatalf("activate: status %d: %s", rr.Code, rr.Body.String())
	}
	return h
}

// ActiveEffects on decide is what the summary route counts, for the same
// organization and document: the compliance readers and the dashboard's Total
// Policies tile read one activation (#4249).
func TestActiveEffectsIsWhatTheSummaryRouteCounts(t *testing.T) {
	off := false
	for name, controls := range map[string][]authoring.SystemControlEntry{
		"nothing disabled":   nil,
		"a control disabled": {{Control: ktpControl, Enabled: &off}},
	} {
		t.Run(name, func(t *testing.T) {
			h := activatedHandler(t, controls)
			effects, err := h.ActiveEffects(context.Background(), testOrg, legacycompile.PlaneDecide, "")
			if err != nil {
				t.Fatal(err)
			}
			counts, err := activation.CountEffects(effects)
			if err != nil {
				t.Fatal(err)
			}
			summary := summaryOf(t, h)
			if countOf(t, summary, "shipped") != counts.Shipped || countOf(t, summary, "organization") != counts.Organization || countOf(t, summary, "disabled") != counts.Disabled {
				t.Fatalf("the summary route counts %v; ActiveEffects counts %+v", summary, counts)
			}
			if counts.Organization == 0 {
				t.Fatal("PREMISE: the active document counted nothing as the organization's")
			}
		})
	}
}

// The scope is the caller's: an Indonesia-PII control is listed on the proxy
// request plane, the one OJK counts, and not on the orchestrator's response
// plane, which the census does not bind it on; the document disabling it lists
// it as disabled there, never as in force.
func TestActiveEffectsListsTheScopeTheCallerNames(t *testing.T) {
	ktpOn := func(t *testing.T, h *TypedAuthoringRouteHandler, plane legacycompile.Plane, phase legacycompile.Phase) []activation.PolicyEffect {
		t.Helper()
		effects, err := h.ActiveEffects(context.Background(), testOrg, plane, phase)
		if err != nil {
			t.Fatal(err)
		}
		var got []activation.PolicyEffect
		for _, e := range effects {
			if e.Control == ktpControl {
				got = append(got, e)
			}
		}
		return got
	}
	ktp := func(t *testing.T, h *TypedAuthoringRouteHandler) []activation.PolicyEffect {
		t.Helper()
		return ktpOn(t, h, legacycompile.PlaneProxyRequest, legacycompile.PhaseRequest)
	}
	h := activatedHandler(t, nil)
	if got := ktpOn(t, h, legacycompile.PlaneOrchestratorResponse, legacycompile.PhaseResponse); len(got) != 0 {
		t.Fatalf("%s is listed on orchestrator_response, which the census does not bind it on: the scope asked is not the scope read", ktpControl)
	}
	on := ktp(t, h)
	if len(on) == 0 {
		t.Fatalf("PREMISE: %s is not listed on proxy_request", ktpControl)
	}
	for _, e := range on {
		if e.Disabled || e.Category != "pii-indonesia" || e.Source != activation.SourceShipped {
			t.Fatalf("%s on proxy_request: %+v; want in force, pii-indonesia, shipped", ktpControl, e)
		}
	}
	off := false
	for _, e := range ktp(t, activatedHandler(t, []authoring.SystemControlEntry{{Control: ktpControl, Enabled: &off}})) {
		if !e.Disabled {
			t.Fatalf("%s disabled by the document is listed as in force: %+v", ktpControl, e)
		}
	}
}

// ActiveEffects refuses wherever the summary route refuses, as
// ErrActiveEffectsUnavailable: a report states the error, never zero policies.
func TestActiveEffectsRefusesWhereTheSummaryRouteRefuses(t *testing.T) {
	// Each refusal is asserted with its REASON, so a guard that stopped firing
	// cannot pass on a later one refusing instead.
	refused := func(t *testing.T, h *TypedAuthoringRouteHandler, reason string) {
		t.Helper()
		effects, err := h.ActiveEffects(context.Background(), testOrg, legacycompile.PlaneProxyRequest, "")
		if !errors.Is(err, ErrActiveEffectsUnavailable) || effects != nil || !strings.Contains(err.Error(), reason) {
			t.Fatalf("listed %d effects with error %v; want ErrActiveEffectsUnavailable naming %q", len(effects), err, reason)
		}
	}
	t.Run("no handler", func(t *testing.T) { refused(t, nil, "no typed-authoring handler is wired") })
	t.Run("a workspace whose durable store could not be opened", func(t *testing.T) {
		h := newRouteHandler(t, authoring.EditionCommunity)
		db, err := sql.Open("postgres", "postgres://planted-4249@10.42.255.7:5432/none?sslmode=disable")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = db.Close() })
		h.db = db
		h.openForSigning = func(context.Context, *sql.DB, pdp.Root, string, string, ed25519.PublicKey, string) (*authoringstore.Store, authoring.TrustSource, string, error) {
			return nil, nil, "", errors.New(plantedStoreError)
		}
		refused(t, h, "durable store could not be opened")
	})
	t.Run("a store that could not be read", func(t *testing.T) {
		refused(t, failingStoreHandler(t, activeReadFailingBackend{Backend: authoring.NewMemoryBackend(), err: errors.New(plantedStoreError)}), "the active document could not be read")
	})
	t.Run("an activation that cannot be built", func(t *testing.T) {
		h := newRouteHandler(t, authoring.EditionCommunity)
		ws, err := h.workspaceFor(context.Background(), testOrg)
		if err != nil {
			t.Fatal(err)
		}
		ws.inputs.Posture = func(context.Context, string) (legacycompile.CategoryActions, error) {
			return nil, errors.New(plantedStoreError)
		}
		refused(t, h, plantedStoreError)
	})
}

// complianceActiveEffects is the ONE late-binding seam: the compliance modules
// are built before Run builds the typed-authoring handler, so they read
// complianceTypedAuthoring, whose single writer is Run. Before Run sets it the
// readers get ErrActiveEffectsUnavailable, never a zero report; once it is set
// they see the activation the summary route counts.
func TestTheComplianceSeamReadsTheHandlerRunSets(t *testing.T) {
	prev := complianceTypedAuthoring
	t.Cleanup(func() { complianceTypedAuthoring = prev })

	complianceTypedAuthoring = nil
	if effects, err := complianceActiveEffects(context.Background(), testOrg, legacycompile.PlaneDecide, ""); !errors.Is(err, ErrActiveEffectsUnavailable) || effects != nil {
		t.Fatalf("before Run sets the handler: %d effects, error %v; want ErrActiveEffectsUnavailable and no report", len(effects), err)
	}

	h := activatedHandler(t, nil)
	complianceTypedAuthoring = h
	effects, err := complianceActiveEffects(context.Background(), testOrg, legacycompile.PlaneDecide, "")
	if err != nil {
		t.Fatal(err)
	}
	counts, err := activation.CountEffects(effects)
	if err != nil {
		t.Fatal(err)
	}
	summary := summaryOf(t, h)
	if countOf(t, summary, "shipped") != counts.Shipped || countOf(t, summary, "organization") != counts.Organization || countOf(t, summary, "disabled") != counts.Disabled || counts.Organization == 0 {
		t.Fatalf("through the seam %+v; the summary route counts %v", counts, summary)
	}
}
