// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
//
// #3896's SECOND definition-of-done bullet: "the field-level anchor list covers
// every documented operation, OR the guard fails on an operation that has no
// anchor - so the coverage gap is itself the failure."
//
// openapi_schema_parity_test.go compares a published schema against the Go type
// the platform marshals, by reflection. Its machinery is sound; its ANCHOR LIST
// names four schemas, which is two endpoints out of roughly three hundred
// documented operations. Every other documented operation has nothing comparing
// its declared fields to anything.
//
// WHY THIS IS A RATCHET AND NOT A PASS/FAIL. Two hundred schemas are referenced
// by documented operations and unanchored. Failing on each would red the build
// for a gap nobody can close in one change, and an allowlist with two hundred
// rows is not a decision anyone reads - it is the "coverage that exists as a
// file rather than as a gate" failure with extra steps.
//
// So the gap is a NUMBER in the tree that may only go DOWN. It cannot grow
// silently: documenting a new operation that introduces an unanchored schema
// fails here until somebody either anchors it or raises the number
// deliberately, which is a visible act in a diff. And it cannot rot upward
// either - the assertion is EXACT, so anchoring schemas without lowering the
// number also fails. A ceiling nobody lowers stops measuring anything.

package orchestrator

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"gopkg.in/yaml.v3"
)

// unanchoredSchemaBudget is the number of distinct components.schemas entries
// referenced by a documented operation that NO field-level anchor covers.
//
// THIS NUMBER MAY ONLY DECREASE. Lower it in the same change that adds an
// anchor. Raising it is a deliberate statement that a new documented operation
// ships with no field-level comparison to the type the platform marshals, and
// it needs a reason in the commit message.
var unanchoredSchemaBudget = map[string]int{
	// 59, not 58: #4253 documents the policy-test preview's 200 and 503 as
	// PolicyTestResponse, a schema a documented operation now references and no
	// anchor covers. Anchoring it was tried, and the parity guard refused it by
	// name, as it did EditionConstructReport and AuthoringFinding below: "reached
	// only its own pair and descended into nothing". The schema is flat - a
	// bool, strings, an integer and arrays of strings - so an anchor on it adds
	// nothing to the walk this budget measures. Raised deliberately.
	"agent-api.yaml": 59,
	// 141, not 140: #3949 added `TripletErrorResponse` - the third error
	// envelope, named so two workflow-step operations could stop documenting a
	// combination that matched neither of their two writers. It is a schema a
	// documented operation references and no anchor covers, so it belongs in
	// this count. Raised deliberately, which is what the ratchet is for.
	//
	// 144, not 141: #3907 documents the community typed-authoring surface and
	// its three schemas - TypedAuthoringDocumentRequest, EditionConstructReport
	// and AuthoringFinding. Raised deliberately, and the reason is that the
	// anchor mechanism cannot express these rather than that nobody tried.
	//
	// ANCHORING TWO OF THEM WAS ATTEMPTED AND THE PARITY GUARD REFUSED IT, by
	// name: "reached only its own pair and descended into nothing. #3724 gap 1
	// and gap 3 both live one level below an anchor." EditionConstructReport
	// and AuthoringFinding are flat - strings, bools and arrays of strings -
	// so an anchor on either exercises no descent and adds nothing to the walk
	// this budget measures. That is a property of the schemas rather than a
	// gap in the effort.
	//
	// TypedAuthoringDocumentRequest is unanchorable for a DIFFERENT and more
	// deliberate reason: its `document` member is opaque (`type: object`) on
	// purpose. The authoring package publishes its own JSON Schema for that
	// document and enforces it at the wire boundary in Parse; restating that
	// vocabulary here would be the second declaration this repository refuses
	// everywhere else, and it would drift the first time a field was added to
	// pdp.Policy. The schema points at the authoring envelope instead.
	//
	// 142, not 141: #4262 documents the members the typed-policies responses
	// actually send, and names two schemas for the shapes that appear twice.
	// ONE OF THEM IS ANCHORED rather than counted: TypedAuthoringActivation
	// descends into contract.ID through `actor`, so an anchor on it exercises
	// the descent this budget exists to measure, and specAnchors() carries it.
	// TemplateOmissionReport is flat - an array of strings, an integer and a
	// string - so the parity guard refuses an anchor on it for exactly the
	// reason recorded above, and it is what this +1 is. Raised deliberately.
	"orchestrator-api.yaml": 142,
}

// schemasReferencedByOperations returns every components.schemas name reachable
// from a documented operation's requestBody or responses.
//
// It walks the whole operation node rather than looking in the two or three
// places a $ref is usually written, for the same reason the error-family guard
// classifies by shape: a document has several ways to say the same thing, and a
// walker that knows three of them is blind to the fourth.
func schemasReferencedByOperations(t *testing.T, rel string) (schemas map[string]bool, operations int) {
	t.Helper()
	blob, err := os.ReadFile(rel)
	if err != nil {
		t.Fatalf("read %s: %v", rel, err)
	}
	var doc struct {
		Paths map[string]map[string]any `yaml:"paths"`
	}
	if err := yaml.Unmarshal(blob, &doc); err != nil {
		t.Fatalf("parse %s: %v", rel, err)
	}
	verbs := map[string]bool{
		"get": true, "post": true, "put": true, "patch": true, "delete": true, "head": true,
	}
	schemas = map[string]bool{}
	var walk func(any)
	walk = func(n any) {
		switch v := n.(type) {
		case map[string]any:
			if r, ok := v["$ref"].(string); ok && len(r) > len(schemaRefPrefix) && r[:len(schemaRefPrefix)] == schemaRefPrefix {
				schemas[r[len(schemaRefPrefix):]] = true
			}
			for _, sub := range v {
				walk(sub)
			}
		case []any:
			for _, sub := range v {
				walk(sub)
			}
		}
	}
	for _, item := range doc.Paths {
		for verb, op := range item {
			if !verbs[verb] {
				continue
			}
			opMap, ok := op.(map[string]any)
			if !ok {
				continue
			}
			operations++
			walk(opMap["requestBody"])
			walk(opMap["responses"])
		}
	}
	return schemas, operations
}

// TestTheFieldLevelAnchorCoverageGapIsItselfTheFailure.
func TestTheFieldLevelAnchorCoverageGapIsItselfTheFailure(t *testing.T) {
	// The anchored set is DERIVED from specAnchors(), not restated. A list
	// restated beside the thing it describes is the defect this whole change
	// is about.
	anchoredBy := map[string]map[string]bool{}
	for _, a := range specAnchors() {
		doc := filepath.Base(a.doc)
		if anchoredBy[doc] == nil {
			anchoredBy[doc] = map[string]bool{}
		}
		anchoredBy[doc][a.schema] = true
	}
	if len(anchoredBy) == 0 {
		t.Fatal("specAnchors() named no documents; this test would compare against an empty set")
	}

	for doc, budget := range unanchoredSchemaBudget {
		rel := filepath.Join("..", "..", "docs", "api", doc)
		referenced, operations := schemasReferencedByOperations(t, rel)

		// ANTI-VACUITY. A parse that read nothing finds no unanchored schema
		// and reports a gap of zero, which would read as full coverage - the
		// most flattering possible failure. Both documents have carried well
		// over fifty operations and over forty schemas for many releases.
		if operations < 50 || len(referenced) < 40 {
			t.Fatalf("%s: parsed %d operations referencing %d schemas; the walk is not reading the "+
				"document, and a gap of zero would read as complete coverage", doc, operations, len(referenced))
		}

		var unanchored []string
		for name := range referenced {
			if !anchoredBy[doc][name] {
				unanchored = append(unanchored, name)
			}
		}
		sort.Strings(unanchored)

		if len(unanchored) == budget {
			continue
		}
		sample := unanchored
		if len(sample) > 8 {
			sample = sample[:8]
		}
		direction := "GREW"
		advice := "A documented operation now references a schema with no field-level anchor, so " +
			"nothing compares its declared fields to the type the platform marshals - which is the " +
			"state #3724's four gaps shipped in. Add an anchor to specAnchors(), or raise the budget " +
			"deliberately with a reason in the commit message."
		if len(unanchored) < budget {
			direction = "SHRANK"
			advice = "Coverage improved - lower unanchoredSchemaBudget[\"" + doc + "\"] to " +
				fmt.Sprint(len(unanchored)) + " in this change. A ceiling nobody lowers stops " +
				"measuring anything, which is why this is an exact ratchet and not a maximum."
		}
		t.Errorf("%s: the field-level anchor coverage gap %s from %d to %d.\n  unanchored (%d, first %d): %v\n\n%s",
			doc, direction, budget, len(unanchored), len(unanchored), len(sample), sample, advice)
	}
}
