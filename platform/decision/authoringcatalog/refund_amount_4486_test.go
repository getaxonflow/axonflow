// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package authoringcatalog_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"axonflow/platform/decision/authoring"
	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/pdp"
)

// TestARefundAmountRequirementPublishes proves the organization authoring path
// can compare a typed minor-unit amount on the decide plane. The target label
// narrows the requirement to the refund tool, and unknown caller amount cannot
// be treated as a safe value below the threshold.
func TestARefundAmountRequirementPublishes(t *testing.T) {
	const id = "support.refund.usd.review"
	op := "args.refund.operation"
	amount := "args.refund.amount_minor"
	currency := "args.refund.currency"
	eeRoot := filepath.Join("..", "..", "..", "ee")
	fixture := filepath.Join(eeRoot, "examples", "payment-exception-shadow", "fixtures", "refund-policy-example.json")
	content, err := os.ReadFile(fixture)
	if err != nil {
		if os.IsNotExist(err) {
			if _, eeErr := os.Stat(eeRoot); os.IsNotExist(eeErr) {
				t.Skip("the Enterprise payment-exception example is intentionally absent from the Community mirror")
			}
		}
		t.Fatal(err)
	}
	var doc pdp.Document
	if err := json.Unmarshal(content, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Policies) != 1 || doc.Policies[0].ID != id {
		t.Fatalf("sample refund policy does not contain %s", id)
	}
	fixtures := []authoring.Fixture{{
		Name: "a USD refund over the reviewed threshold",
		Attributes: contract.AttributeSet{
			pdp.ActionIDPath:   contract.Known(toolCallID().String(), contract.ProvPlatform, 1, stepAt),
			pdp.ActionTagsPath: contract.Known([]any{"stage:tool"}, contract.ProvPlatform, 1, stepAt),
			op:                 contract.Known("issue_refund", contract.ProvCaller, 1, stepAt),
			amount:             contract.Known(float64(94900), contract.ProvCaller, 1, stepAt),
			currency:           contract.Known("USD", contract.ProvCaller, 1, stepAt),
		},
		Expect: map[string]pdp.Verdict{id: pdp.VerdictMatch},
	}}
	if findings, err := publishStepDocument(t, authoring.EditionEnterprise, doc, fixtures); err != nil {
		t.Errorf("Enterprise could not publish a typed refund threshold: %v\n%v", err, findings)
	}
}
