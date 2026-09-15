// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package authoring_test

import (
	"encoding/json"
	"testing"

	"axonflow/platform/decision/authoring"
	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/pdp"
)

// TestTheTemplateViewIsTheShippedOrganizationTemplate holds the view a new
// draft is seeded from to the template this binary shipped, rather than to
// itself: its bytes, parsed back and digested, are the shipped template.
func TestTheTemplateViewIsTheShippedOrganizationTemplate(t *testing.T) {
	view, err := authoring.ShippedOrganizationTemplateView()
	if err != nil {
		t.Fatal(err)
	}
	shipped, err := pdp.SystemCorpusOrganizationTemplate()
	if err != nil {
		t.Fatal(err)
	}
	digest, err := pdp.SystemCorpusOrganizationTemplateDigest()
	if err != nil {
		t.Fatal(err)
	}
	if view.ID != pdp.SystemCorpusOrganizationTemplateID || view.Digest != digest {
		t.Fatalf("the view names %s at %s; the shipped template is %s at %s", view.ID, view.Digest, pdp.SystemCorpusOrganizationTemplateID, digest)
	}
	var back pdp.Document
	if err := json.Unmarshal(view.Document, &back); err != nil {
		t.Fatalf("the view's document does not parse: %v", err)
	}
	if got, err := contract.ExactDigest(&back); err != nil || got != digest {
		t.Fatalf("the view's document digests to %s (err %v); the shipped template is %s", got, err, digest)
	}
	if back.Root != shipped.Root || len(back.Policies) != len(shipped.Policies) || len(back.Policies) == 0 {
		t.Fatalf("the view's document is root %s with %d policies; the shipped template is %s with %d",
			back.Root, len(back.Policies), shipped.Root, len(shipped.Policies))
	}
}
