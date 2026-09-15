// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package authoring

import (
	"encoding/json"
	"os"
	"reflect"
	"sort"
	"testing"

	"axonflow/platform/decision/legacycompile"
)

// NEWDOCUMENT CARRIES EVERY MEMBER THE SCHEMA DECLARES (PRD v11 §1.5). Twice a
// member-by-member copy dropped a section it predated; this reads the member
// list from the published schema itself, so the next section added there is
// held here without anyone remembering to add it. The fixture must populate
// every declared member - a member it leaves unset would be "carried" only
// because nothing was sent - and the two members this package derives are set
// to what it derives, so an overwrite cannot pass for a carry.
func TestNewDocumentCarriesEveryMemberTheSchemaDeclares(t *testing.T) {
	raw, err := os.ReadFile(SchemaFile)
	if err != nil {
		t.Fatal(err)
	}
	var schema struct {
		Properties map[string]json.RawMessage `json:"properties"`
	}
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatal(err)
	}
	members := make([]string, 0, len(schema.Properties))
	for m := range schema.Properties {
		members = append(members, m)
	}
	sort.Strings(members)
	if len(members) < 4 {
		t.Fatalf("the schema declares only %v at the top level; this test is not reading the envelope", members)
	}

	cat := baseCatalog(t)
	// system_controls are the organization root's (SYSTEM_CONTROLS_OUTSIDE_ORGANIZATION),
	// so the clean fixture is re-rooted there with the package's own helper, which
	// also removes the break-glass an organization root cannot declare.
	policy := basePDPDocument(t)
	toOrganizationRoot(&policy)
	in := Document{
		APIVersion:     APIVersion,
		Metadata:       baseMetadata(t),
		Policy:         policy,
		SystemControls: []SystemControlEntry{{Control: "corpus:static_policies:sys__sqli__union__select", Action: legacycompile.ActionBlock}},
	}
	in.Policy.InteractiveRealms = cat.InteractiveRealms()
	out, findings, err := NewDocument(in, cat)
	if err != nil {
		t.Fatalf("NewDocument refused the fixture: %v\n%v", err, findings)
	}

	asMembers := func(d *Document) map[string]any {
		t.Helper()
		b, err := json.Marshal(d)
		if err != nil {
			t.Fatal(err)
		}
		var m map[string]any
		if err := json.Unmarshal(b, &m); err != nil {
			t.Fatal(err)
		}
		return m
	}
	sent, kept := asMembers(&in), asMembers(out)
	for _, m := range members {
		if _, populated := sent[m]; !populated {
			t.Errorf("the schema declares %q and this fixture does not populate it; populate it, so NewDocument is held to carrying it", m)
			continue
		}
		if !reflect.DeepEqual(sent[m], kept[m]) {
			t.Errorf("NewDocument changed or dropped schema member %q: sent %v, kept %v", m, sent[m], kept[m])
		}
	}
}
