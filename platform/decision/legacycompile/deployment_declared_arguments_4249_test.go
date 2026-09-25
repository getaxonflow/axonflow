// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package legacycompile

import (
	"slices"
	"strings"
	"testing"

	"axonflow/platform/decision/pdp"
)

// declaredLabels are the two declarations the ruling names, written out rather
// than read from DeploymentDeclaredArguments: a cell that iterates the list under
// test passes with the list emptied, having checked nothing.
var declaredLabels = []pdp.AttributeSchema{
	{Path: "args.context.step__name", Type: pdp.TypeString, Optional: true},
	{Path: "args.context.tool__name", Type: pdp.TypeString, Optional: true},
}

// TestBuildCorpusDeclaresTheStepContextArguments is #4249 row 5670275054's
// vocabulary half, proved through the real BuildCorpus with no capture.
//
// No shipped policy reads a step's name or its tool, so deriveSchema alone would
// never declare them, and a regeneration of the artifact would drop a
// declaration made by hand. This proves the BUILDER emits them, which is what
// keeps the checked-in artifact and a fresh build byte-equal.
func TestBuildCorpusDeclaresTheStepContextArguments(t *testing.T) {
	c, err := newSyntheticCorpus(t).build(t)
	if err != nil {
		t.Fatalf("PREMISE: the synthetic corpus must build: %v", err)
	}
	index := c.System.AttributeIndex()
	for _, want := range declaredLabels {
		got, ok := index[want.Path]
		if !ok {
			t.Fatalf("the system document declares no %s; an organization's document could not read it", want.Path)
		}
		if got != want {
			t.Fatalf("the system document declares %+v; want %+v", got, want)
		}
	}
	if !slices.IsSortedFunc(c.System.Attributes, func(a, b pdp.AttributeSchema) int { return strings.Compare(a.Path, b.Path) }) {
		t.Fatal("the system document's schema is not sorted by path, so the rendered artifact would not be deterministic")
	}
	// The organization template is the customer-editable seed; the labels are
	// the deployment's vocabulary and do not belong in it.
	for _, want := range declaredLabels {
		if _, ok := c.OrganizationTemplate.AttributeIndex()[want.Path]; ok {
			t.Errorf("the organization template declares %s; the declaration is the system document's", want.Path)
		}
	}
}

// TestTheShippedArtifactCarriesTheStepContextArguments holds the checked-in
// artifact to the list, so a hand edit that dropped one is caught without a
// capture (the capture-backed regeneration catches the reverse).
func TestTheShippedArtifactCarriesTheStepContextArguments(t *testing.T) {
	sys, err := pdp.SystemCorpusDocument()
	if err != nil {
		t.Fatal(err)
	}
	index := sys.AttributeIndex()
	for _, want := range declaredLabels {
		if got, ok := index[want.Path]; !ok || got != want {
			t.Errorf("the shipped system corpus declares %s as %+v (declared %t); want %+v", want.Path, got, ok, want)
		}
	}
	for _, a := range sys.Attributes {
		if a.Path == "args.context.step__type" {
			t.Error("the shipped corpus declares args.context.step__type; a step's type is the ACTION it is presented as, selected with the action selector")
		}
	}
}

// TestAShippedPolicyReadingADeclaredArgumentAtAnotherTypeIsRefused: the
// declaration is the contract an organization's document is written against, so
// a shipped policy that read one at another type would be a builder error, not a
// silent widening to TypeAny.
func TestAShippedPolicyReadingADeclaredArgumentAtAnotherTypeIsRefused(t *testing.T) {
	path := DeploymentDeclaredArguments[0].Path
	_, err := withDeploymentDeclaredArguments([]pdp.AttributeSchema{{Path: path, Type: pdp.TypeNumber}})
	if err == nil || !strings.Contains(err.Error(), path) {
		t.Fatalf("a derived %s at number was merged (err %v); want a refusal naming the path", path, err)
	}
	merged, err := withDeploymentDeclaredArguments([]pdp.AttributeSchema{DeploymentDeclaredArguments[0]})
	if err != nil {
		t.Fatalf("a derived declaration equal to the list's was refused: %v", err)
	}
	if n := len(merged); n != len(DeploymentDeclaredArguments) {
		t.Fatalf("merging an equal declaration produced %d attributes; want %d, one per path", n, len(DeploymentDeclaredArguments))
	}
}

// TestEveryDeploymentDeclaredArgumentIsACallerTypedLabel: both arguments are
// forwarded from a request body, so each must be on pdp's label list, or a
// permission could be keyed on one. A future declared argument that is NOT a
// label (an operation's own parameter) has to be argued out of this test on
// purpose.
func TestEveryDeploymentDeclaredArgumentIsACallerTypedLabel(t *testing.T) {
	if len(DeploymentDeclaredArguments) != len(declaredLabels) {
		t.Errorf("DeploymentDeclaredArguments has %d entries; the ruling declares exactly %d, and a change to it is a ruling", len(DeploymentDeclaredArguments), len(declaredLabels))
	}
	for _, a := range declaredLabels {
		if !slices.Contains(DeploymentDeclaredArguments, a) {
			t.Errorf("DeploymentDeclaredArguments does not declare %+v", a)
		}
		if !slices.Contains(pdp.CallerTypedLabelPaths, a.Path) {
			t.Errorf("%s is declared for organizations to read but is not on pdp.CallerTypedLabelPaths, so a permission may be keyed on it", a.Path)
		}
		if a.Type != pdp.TypeString || !a.Optional {
			t.Errorf("%s is declared %s optional=%t; a label is an OPTIONAL string: every request that is not a step carries none, and a condition over one must treat its absence as a non-match", a.Path, a.Type, a.Optional)
		}
	}
}
