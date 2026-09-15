// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package authoring

import (
	"reflect"
	"testing"

	"axonflow/platform/decision/legacycompile"
)

// NEWDOCUMENT CARRIES THE AUTHORED ENVELOPE WHOLE (PRD v11 §1.5). A constructor
// that took the members one by one dropped a system_controls section before it
// was validated or signed, and the orchestrator's route published through it.
// Every member the author wrote survives; only the two this package derives are
// overwritten, even when a client sent its own.
func TestNewDocumentCarriesTheAuthoredEnvelopeWhole(t *testing.T) {
	cat := baseCatalog(t)
	sent := []SystemControlEntry{{Control: "corpus:static_policies:sys__sqli__union__select", Action: legacycompile.ActionBlock}}
	// system_controls are the organization root's (SYSTEM_CONTROLS_OUTSIDE_ORGANIZATION),
	// so the clean fixture is re-rooted there with the package's own helper, which
	// also removes the break-glass an organization root cannot declare.
	policy := basePDPDocument(t)
	toOrganizationRoot(&policy)
	in := Document{
		APIVersion:     "authoring.axonflow.com/v0-sent-by-a-client",
		Metadata:       baseMetadata(t),
		Policy:         policy,
		SystemControls: sent,
	}
	in.Policy.InteractiveRealms = map[string]bool{"a-client-copy": true}
	d, findings, err := NewDocument(in, cat)
	if err != nil {
		t.Fatalf("NewDocument refused a valid document: %v\n%v", err, findings)
	}
	if !reflect.DeepEqual(d.SystemControls, sent) {
		t.Fatalf("NewDocument carried system_controls %+v; the author wrote %+v", d.SystemControls, sent)
	}
	if !reflect.DeepEqual(d.Metadata, in.Metadata) || len(d.Policy.Policies) != len(in.Policy.Policies) {
		t.Fatalf("NewDocument changed the author's metadata or policies")
	}
	if d.APIVersion != APIVersion {
		t.Fatalf("NewDocument kept a client's api_version %q; it is %q, this package's", d.APIVersion, APIVersion)
	}
	if !reflect.DeepEqual(d.Policy.InteractiveRealms, cat.InteractiveRealms()) {
		t.Fatalf("NewDocument kept a client's interactive realms %v; they are derived from the catalog", d.Policy.InteractiveRealms)
	}
}
