// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package authoring_test

import (
	"encoding/json"
	"testing"

	"axonflow/platform/decision/authoring"
	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/legacycompile"
	"axonflow/platform/decision/pdp"
)

// TestTheSystemViewDescribesTheCorpusTheAnchorChecks holds the read-only view
// to the corpus the engine is anchored to, rather than to itself.
func TestTheSystemViewDescribesTheCorpusTheAnchorChecks(t *testing.T) {
	view, err := authoring.ShippedSystemCorpusView()
	if err != nil {
		t.Fatal(err)
	}
	shipped, err := pdp.SystemCorpusDocument()
	if err != nil {
		t.Fatal(err)
	}
	digest, err := pdp.SystemCorpusDigest()
	if err != nil {
		t.Fatal(err)
	}
	if view.Root != pdp.RootSystem || view.Authority != authoring.ShippedCorpusAuthority {
		t.Fatalf("the view names root %q and authority %q", view.Root, view.Authority)
	}
	if view.Digest != digest {
		t.Fatalf("the view names digest %s; the anchor is %s", view.Digest, digest)
	}

	// THE DOCUMENT BYTES ARE THE ANCHORED ONES: parsed back and digested, they
	// are the corpus the engine checks, not a re-encoding of it.
	var back pdp.Document
	if err := json.Unmarshal(view.Document, &back); err != nil {
		t.Fatalf("the view's document does not parse: %v", err)
	}
	if got, err := contract.ExactDigest(&back); err != nil || got != digest {
		t.Fatalf("the view's document digests to %s (err %v); the anchor is %s", got, err, digest)
	}

	if len(view.Controls) != len(shipped.Policies) {
		t.Fatalf("the view lists %d controls for %d shipped policies", len(view.Controls), len(shipped.Policies))
	}
	counted := 0
	for i, c := range view.Controls {
		if c.ID != shipped.Policies[i].ID || c.Assurance != shipped.Policies[i].Assurance {
			t.Fatalf("control %d is %s/%s; the shipped policy is %s/%s", i, c.ID, c.Assurance, shipped.Policies[i].ID, shipped.Policies[i].Assurance)
		}
		if _, control := pdp.DeriveAssurance(shipped.Policies[i]); control && c.Assurance == "" {
			t.Fatalf("control %s is rendered with no assurance class", c.ID)
		}
		if c.Assurance != "" {
			counted++
		}
	}
	total := 0
	for _, n := range view.AssuranceCounts {
		total += n
	}
	if total != counted || total == 0 {
		t.Fatalf("the view counts %d classified controls and lists %d", total, counted)
	}

	// A WRITE THROUGH THE VIEW DOES NOT REACH THE CORPUS.
	if len(view.Controls[0].Obligations) > 0 {
		view.Controls[0].Obligations[0].Type = "tampered"
	}
	view.Controls[0].ID = "tampered"
	if again, err := pdp.SystemCorpusDigest(); err != nil || again != digest {
		t.Fatalf("editing the view moved the corpus digest to %s (err %v)", again, err)
	}
	fresh, err := authoring.ShippedSystemCorpusView()
	if err != nil || fresh.Controls[0].ID == "tampered" {
		t.Fatalf("an edit to one view reached the next one (err %v)", err)
	}
	for _, p := range shipped.Policies {
		for _, o := range p.Obligations {
			if o.Type == "tampered" {
				t.Fatalf("an edit to the view's obligations reached the shipped policy %s", p.ID)
			}
		}
	}
}

// TestEverySystemControlCarriesItsPolicysName (#4127): the platform-controls
// panel shows each control by the name its legacy row carried, so the view
// hands that name through unchanged, and no shipped control is nameless.
func TestEverySystemControlCarriesItsPolicysName(t *testing.T) {
	view, err := authoring.ShippedSystemCorpusView()
	if err != nil {
		t.Fatal(err)
	}
	shipped, err := pdp.SystemCorpusDocument()
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]string{}
	for _, p := range shipped.Policies {
		names[p.ID] = p.Name
	}
	if len(view.Controls) == 0 {
		t.Fatal("the view lists no control, so this test checks nothing")
	}
	for _, c := range view.Controls {
		if c.Name == "" {
			t.Errorf("control %s carries no name", c.ID)
		}
		if c.Name != names[c.ID] {
			t.Errorf("control %s is named %q in the view and %q in the shipped corpus", c.ID, c.Name, names[c.ID])
		}
	}
}

// TestEverySystemControlNamesTheControlAnOrganizationDocumentAddresses: the
// panel groups the shipped policies by the control a system_controls entry
// names, so every row carries it, and exactly the dynamic controls say so. The
// counts are the posture table's system rows: 85 controls, 15 of them dynamic.
func TestEverySystemControlNamesTheControlAnOrganizationDocumentAddresses(t *testing.T) {
	view, err := authoring.ShippedSystemCorpusView()
	if err != nil {
		t.Fatal(err)
	}
	controls, dynamic := map[string]bool{}, map[string]bool{}
	for _, c := range view.Controls {
		want, _, ok := legacycompile.CorpusControlOf(c.ID)
		if !ok || c.Control != want {
			t.Fatalf("policy %s names control %q; its corpus control is %q (ok=%v)", c.ID, c.Control, want, ok)
		}
		if c.Dynamic != authoring.DynamicSystemControl(c.Control) {
			t.Fatalf("policy %s reports dynamic=%v for control %s", c.ID, c.Dynamic, c.Control)
		}
		controls[c.Control] = true
		if c.Dynamic {
			dynamic[c.Control] = true
		}
	}
	if len(controls) != 85 || len(dynamic) != 15 {
		t.Fatalf("the view names %d controls, %d of them dynamic; the shipped set is 85, 15 of them dynamic", len(controls), len(dynamic))
	}
}
