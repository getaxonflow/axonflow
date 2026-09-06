package agent

import (
	"os"
	"testing"

	"gopkg.in/yaml.v3"

	"axonflow/platform/decision/contract"
	"axonflow/platform/shared/pep"
)

// The OpenAPI document restates two things the Go code owns, and until this
// existed nothing held them together.
//
// FOUND BY APPLYING THIS LANE'S OWN REVIEW TEST TO ITS OWN DIFF: "look for a
// check whose membership nobody can name from the code — if the answer to
// 'what does this cover?' is a literal in a file beside it, the coverage claim
// is worth exactly that list." Both enums below were literals in a file beside
// the constants they describe, added by this change, and no review caught them.
//
// Why they matter more than a stale comment would. `docs/api/agent-api.yaml` is
// what a spec-generated client is built from, so a drifted enum is not a
// documentation defect — it is a client that rejects a value the server
// accepts, or sends one the server refuses, and neither end has a test that
// fails.
//
// Modelled on TestBulkEntryCapMatchesThePublishedContract, which pins the
// AuthZEN entry cap the same way and for the same reason.

func loadAgentAPI(t *testing.T) map[string]any {
	t.Helper()
	raw, err := os.ReadFile("../../docs/api/agent-api.yaml")
	if err != nil {
		t.Fatalf("read the published agent API: %v", err)
	}
	var doc map[string]any
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse the published agent API: %v", err)
	}
	return doc
}

func schemaProperty(t *testing.T, doc map[string]any, schema, property string) map[string]any {
	t.Helper()
	comps, _ := doc["components"].(map[string]any)
	schemas, _ := comps["schemas"].(map[string]any)
	s, ok := schemas[schema].(map[string]any)
	if !ok {
		t.Fatalf("%s is missing from components.schemas — the document changed shape and this pin is reading nothing", schema)
	}
	props, _ := s["properties"].(map[string]any)
	p, ok := props[property].(map[string]any)
	if !ok {
		t.Fatalf("%s.%s is missing — same vacuity concern", schema, property)
	}
	return p
}

// TestTheSeamCapabilityEnumMatchesTheGoConstants pins the published enum to the
// vocabulary the server actually accepts, in BOTH directions.
//
// A value in the schema the server does not know makes a generated client send
// something ignored; a constant the schema omits makes a generated client
// unable to send something the server honours. Both are silent.
func TestTheSeamCapabilityEnumMatchesTheGoConstants(t *testing.T) {
	p := schemaProperty(t, loadAgentAPI(t), "DecideRequest", "fulfillment_capabilities")
	items, _ := p["items"].(map[string]any)
	rawEnum, ok := items["enum"].([]any)
	if !ok || len(rawEnum) == 0 {
		t.Fatal("fulfillment_capabilities declares no item enum; the published contract must name the vocabulary the server accepts")
	}
	published := map[string]bool{}
	for _, v := range rawEnum {
		published[v.(string)] = true
	}

	// The Go side is the source of truth. Listed here because Go has no
	// reflection over untyped string constants — so this list is itself
	// author-bounded, and the mitigation is that its members are asserted
	// against the published document rather than against a second list, and
	// that adding one here without the schema fails immediately.
	goConstants := map[string]bool{
		pep.CapabilityRequestBodyRedaction:  true,
		pep.CapabilityRequestHeaderMutation: true,
	}

	for c := range goConstants {
		if !published[c] {
			t.Errorf("the server accepts %q and the published schema does not declare it; a spec-generated client cannot send a capability the server honours", c)
		}
	}
	for c := range published {
		if !goConstants[c] {
			t.Errorf("the published schema declares %q and no Go constant matches it; a spec-generated client would send a value the server silently ignores", c)
		}
	}
	if len(published) != len(goConstants) {
		t.Errorf("published %d values, Go declares %d", len(published), len(goConstants))
	}
}

// TestThePublishedProfileVersionMatchesTheOnlyOneThisBuildAccepts.
//
// The handshake matches its profile by EXACT equality, so a schema declaring a
// version this build refuses is worse than a stale comment: a generated client
// would send it and be refused 400, with the published contract on its side.
func TestThePublishedProfileVersionMatchesTheOnlyOneThisBuildAccepts(t *testing.T) {
	p := schemaProperty(t, loadAgentAPI(t), "PEPHandshake", "profile_version")
	rawEnum, ok := p["enum"].([]any)
	if !ok || len(rawEnum) == 0 {
		t.Fatal("profile_version declares no enum; matching is exact, so the contract must name the version it means")
	}
	if len(rawEnum) != 1 {
		t.Fatalf("the schema declares %d profile versions; this build accepts exactly one, and a contract offering a choice the server does not have is a refusal waiting to happen", len(rawEnum))
	}
	got, ok := rawEnum[0].(int)
	if !ok {
		t.Fatalf("profile_version enum member is %T, not an integer — the JSON number type is part of this contract", rawEnum[0])
	}
	if got != contract.PEPHandshakeProfileV1 {
		t.Errorf("the published schema declares profile version %d and this build accepts only %d; a spec-generated client would be refused 400 with the contract on its side",
			got, contract.PEPHandshakeProfileV1)
	}
}

// TestThePublishedHandshakeBoundsMatchTheDecoder pins the two size bounds the
// document restates, for the same reason: a client that trusts the published
// maxItems and is refused by the server has been misled by the artifact it was
// generated from.
func TestThePublishedHandshakeBoundsMatchTheDecoder(t *testing.T) {
	doc := loadAgentAPI(t)
	caps := schemaProperty(t, doc, "PEPHandshake", "capabilities")
	mi, ok := caps["maxItems"].(int)
	if !ok {
		t.Fatalf("capabilities declares no maxItems, but the decoder refuses above %d", contract.MaxPEPHandshakeCapabilities)
	}
	if mi != contract.MaxPEPHandshakeCapabilities {
		t.Errorf("schema maxItems = %d, decoder refuses above %d", mi, contract.MaxPEPHandshakeCapabilities)
	}

	comps, _ := doc["components"].(map[string]any)
	params, _ := comps["parameters"].(map[string]any)
	hs, ok := params["AxonflowPEPHandshake"].(map[string]any)
	if !ok {
		t.Fatal("the AxonflowPEPHandshake parameter is missing — this pin is reading nothing")
	}
	sch, _ := hs["schema"].(map[string]any)
	ml, ok := sch["maxLength"].(int)
	if !ok {
		t.Fatalf("the header parameter declares no maxLength, but the decoder refuses above %d bytes", contract.MaxPEPHandshakeBytes)
	}
	if ml != contract.MaxPEPHandshakeBytes {
		t.Errorf("schema maxLength = %d, decoder refuses above %d", ml, contract.MaxPEPHandshakeBytes)
	}
}
