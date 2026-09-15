// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package pdp

import (
	"testing"

	"axonflow/platform/decision/contract"
)

// The digest a withdrawal names (PRD v11 §1.15) is the shipped organization
// template's, computed the way the corpus's own digest is: ExactDigest over the
// PARSED document. Pinned against a recomputation here, because every other
// test compares a withdrawal's digest with this same function and so could not
// see it return the wrong document's digest.
func TestTheOrganizationTemplateDigestIsTheExactDigestOfTheParsedTemplate(t *testing.T) {
	template, err := SystemCorpusOrganizationTemplate()
	if err != nil {
		t.Fatal(err)
	}
	want, err := contract.ExactDigest(template)
	if err != nil {
		t.Fatal(err)
	}
	got, err := SystemCorpusOrganizationTemplateDigest()
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("SystemCorpusOrganizationTemplateDigest() = %s; the template's ExactDigest is %s", got, want)
	}
	corpus, err := SystemCorpusDigest()
	if err != nil {
		t.Fatal(err)
	}
	if got == corpus {
		t.Fatal("the template's digest equals the system corpus's; a withdrawal would name the wrong document")
	}
}
