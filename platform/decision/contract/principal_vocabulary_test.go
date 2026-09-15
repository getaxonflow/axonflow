// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package contract

import (
	"encoding/json"
	"strings"
	"testing"
)

// The principal vocabulary is closed at BOTH boundaries a request crosses:
// ID.Validate (what the engine consults) and the published schema (what a
// wire request is checked against). Each is pinned by its own test, because
// each can be widened without the other noticing.

// TestAPrincipalTypeOutsideTheVocabularyIsRefusedByValidate pins the v11
// closure (#3711): the type segment of a KindPrincipal identifier must be one
// of PrincipalTypes(), while every other kind keeps the open segment grammar.
func TestAPrincipalTypeOutsideTheVocabularyIsRefusedByValidate(t *testing.T) {
	for _, p := range PrincipalTypes() {
		id := ID{Kind: KindPrincipal, Type: string(p), Qualifier: "okta-prod", Local: "00u1"}
		if err := id.Validate(); err != nil {
			t.Errorf("%q is in the vocabulary and was refused: %v", p, err)
		}
		if _, err := ParseID(KindPrincipal, string(p)+"::okta-prod:00u1"); err != nil {
			t.Errorf("%q does not parse as a principal: %v", p, err)
		}
	}

	outside := []string{"Robot", "Machine.v2", "A-b_c", "user", "USER", "Users"}
	for _, typ := range outside {
		id := ID{Kind: KindPrincipal, Type: typ, Qualifier: "okta-prod", Local: "00u1"}
		err := id.Validate()
		if err == nil {
			t.Errorf("principal type %q is outside the vocabulary and was ACCEPTED; the PDP would evaluate a subject no policy author has seen and no proof can bind", typ)
			continue
		}
		if !strings.Contains(err.Error(), "#3711") || !strings.Contains(err.Error(), typ) {
			t.Errorf("the refusal for %q must name the type and the rule; got %q", typ, err)
		}
		if _, err := ParseID(KindPrincipal, typ+"::okta-prod:00u1"); err == nil {
			t.Errorf("%q parsed as a principal through ParseID", typ)
		}
	}

	// The closure is PER KIND. A resource type is named by its connector and
	// the registry decides which exist; "Robot" is a perfectly good resource.
	for _, kind := range AllKinds() {
		if kind == KindPrincipal {
			continue
		}
		qualified, _ := IsQualifiedKind(kind)
		id := ID{Kind: kind, Type: "Robot", Local: "r1"}
		if qualified {
			id.Qualifier = "fleet"
		}
		if err := id.Validate(); err != nil {
			t.Errorf("kind %q refused type \"Robot\": %v; the vocabulary closes principals only", kind, err)
		}
	}

	if len(PrincipalTypes()) != 6 {
		t.Fatalf("PrincipalTypes() has %d members; the vocabulary is six, and a seventh is a wire change that must be filed, not slipped in", len(PrincipalTypes()))
	}
	got := PrincipalTypes()
	got[0] = "Mutated"
	if PrincipalTypes()[0] == "Mutated" {
		t.Fatal("PrincipalTypes() returned its backing slice; a caller can rewrite the vocabulary")
	}
}

// TestTheSchemaRefusesAPrincipalTypeOutsideTheVocabulary pins the same closure
// at the wire boundary, where a request is validated before any Go value
// exists. The schema carries the six as an enum conditioned on kind, so the
// same document with kind "resource" must pass: the closure is per kind there
// too.
func TestTheSchemaRefusesAPrincipalTypeOutsideTheVocabulary(t *testing.T) {
	mk := func(kind, typ string) any {
		var v any
		doc := `{"kind":"` + kind + `","type":"` + typ + `","qualifier":"okta-prod","local":"00u1"}`
		if err := json.Unmarshal([]byte(doc), &v); err != nil {
			t.Fatal(err)
		}
		return v
	}
	for _, p := range PrincipalTypes() {
		if err := ValidateAgainstSchema(SchemaIdentifier, mk("principal", string(p))); err != nil {
			t.Errorf("the schema refuses principal type %q: %v", p, err)
		}
	}
	if err := ValidateAgainstSchema(SchemaIdentifier, mk("principal", "Robot")); err == nil {
		t.Error("the schema ACCEPTS a principal of type \"Robot\"; the $defs/identifier enum conditioned on kind is missing or widened")
	}
	if err := ValidateAgainstSchema(SchemaIdentifier, mk("resource", "Robot")); err != nil {
		t.Errorf("the schema refuses a RESOURCE of type \"Robot\": %v; the enum must be conditioned on kind = principal", err)
	}
}
