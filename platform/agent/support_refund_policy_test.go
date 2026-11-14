// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"os"
	"path/filepath"
	"testing"

	"axonflow/platform/decision/policypack"
)

func validSupportRefundContext() map[string]interface{} {
	return map[string]interface{}{"refund_action": map[string]interface{}{
		"version": float64(1), "case_id": "case-a", "order_id": "order-a",
		"payment_id": "payment-a", "customer_id": "customer-a",
		"idempotency_key": "idem-a", "amount_minor": float64(94925),
		"action": "issue_refund", "refund_destination": "original_payment_method:payment-a",
		"currency": "USD", "evidence_version": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		"requester_id": "analyst@example.com",
	}}
}

func TestSupportRefundRequiresExactBoundAction(t *testing.T) {
	context := validSupportRefundContext()
	target := DecisionTarget{Type: "tool", Server: "support-ops", Tool: "support-ops.issue_refund"}
	if targeted, valid := exactSupportRefund("org-a", "tenant-a", DecisionStageTool, target, context); !targeted || !valid {
		t.Fatal("exact bound refund was not admitted to module-policy evaluation")
	}
	for name, mutate := range map[string]func(map[string]interface{}){
		"wrong tenant":        func(v map[string]interface{}) { v["tenant_id"] = "tenant-b" },
		"zero amount":         func(v map[string]interface{}) { v["amount_minor"] = float64(0) },
		"fractional amount":   func(v map[string]interface{}) { v["amount_minor"] = float64(949.25) },
		"missing payment":     func(v map[string]interface{}) { v["payment_id"] = "" },
		"missing customer":    func(v map[string]interface{}) { v["customer_id"] = "" },
		"wrong action":        func(v map[string]interface{}) { v["action"] = "store_credit" },
		"wrong destination":   func(v map[string]interface{}) { v["refund_destination"] = "wallet:other" },
		"missing idempotency": func(v map[string]interface{}) { v["idempotency_key"] = "" },
		"missing evidence":    func(v map[string]interface{}) { v["evidence_version"] = "" },
		"wrong currency":      func(v map[string]interface{}) { v["currency"] = "usd" },
		"wrong version":       func(v map[string]interface{}) { v["version"] = float64(2) },
	} {
		t.Run(name, func(t *testing.T) {
			copyContext := validSupportRefundContext()
			mutate(copyContext["refund_action"].(map[string]interface{}))
			_, valid := exactSupportRefund("org-a", "tenant-a", DecisionStageTool, target, copyContext)
			if valid {
				t.Fatal("changed refund binding was accepted")
			}
		})
	}
	if targeted, _ := exactSupportRefund("org-a", "tenant-a", DecisionStageTool,
		DecisionTarget{Type: "tool", Server: "payment-ops", Tool: "payment-ops.retry_disbursement"}, context); targeted {
		t.Fatal("payment target selected the support refund module")
	}
}

func TestSupportRefundIdentityRejectsCrossModuleSubstitutionAndDrift(t *testing.T) {
	valid := supportRefundModuleIdentity{
		moduleID: supportRefundModuleID, grantID: "grant-a", grantActive: true,
		manifestSHA256: "manifest", artifactSetSHA256: "artifacts",
		runtimeArtifactName: "case-workflows-image", runtimeArtifactSHA256: "image", sbomSHA256: "sbom",
		capabilityID: supportRefundCapabilityID, capabilityVersion: supportRefundCapabilityVersion,
		capabilitySchemaSHA256: "capability", policyActive: true,
		policyID: supportRefundPolicyID, policyVersion: supportRefundPolicyVersion,
		policySchemaSHA256: supportRefundPolicySchema, policyArtifactName: supportRefundPolicyArtifact,
		policyArtifactSHA256: supportRefundPolicyArtifactSHA,
		healthID:             "support_refund.health", healthVersion: "1.0", healthSchemaSHA256: "health",
		readinessID: "support_refund.readiness", readinessVersion: "1.0", readinessSchemaSHA256: "readiness",
		manifestRevocationID: "revocation", trustRootKeyID: "root", trustRootKeySHA256: "root-sha",
		trustRootKeyRef: "root-ref", trustDocumentID: "trust", trustDocumentSequence: 1,
		trustDocumentSHA256: "trust-sha",
		deploymentMode:      "self_hosted", eligibilityActive: true,
	}
	if !valid.usable() {
		t.Fatal("valid support refund identity was rejected")
	}
	crossModule := valid
	crossModule.policyID = paymentExceptionPolicyID
	crossModule.policySchemaSHA256 = paymentExceptionPolicySchema
	crossModule.policyArtifactName = paymentExceptionPolicyArtifact
	crossModule.policyArtifactSHA256 = paymentExceptionPolicyArtifactSHA
	if crossModule.usable() {
		t.Fatal("payment exception policy substituted for support refund policy")
	}
	drift := valid
	drift.policyArtifactSHA256 = "changed"
	if drift.usable() {
		t.Fatal("drifted support refund policy artifact was accepted")
	}
	revoked := valid
	revoked.policyActive = false
	revoked.policyReason = "manifest_revoked"
	if revoked.usable() {
		t.Fatal("revoked support refund policy was accepted")
	}
	licenceRevoked := valid
	licenceRevoked.eligibilityActive = false
	licenceRevoked.eligibilityReason = "self_hosted_eligibility_invalid"
	if licenceRevoked.usable() {
		t.Fatal("support refund policy remained usable after licence revocation")
	}
}

func TestSupportRefundCommittedPolicyDocumentMatchesSource(t *testing.T) {
	dir := filepath.Join("..", "..", "ee", "policy-packs", "support-refund")
	source, err := os.ReadFile(filepath.Join(dir, "pack.json"))
	if err != nil {
		t.Fatal(err)
	}
	committed, err := os.ReadFile(filepath.Join(dir, "document.json"))
	if err != nil {
		t.Fatal(err)
	}
	pack, err := policypack.Load(source, committed)
	if err != nil {
		t.Fatal(err)
	}
	if pack.Source.ID != "support-refund" || pack.Source.Version != 1 || pack.Source.Approval == nil {
		t.Fatalf("unexpected support refund policy identity: %#v", pack.Source)
	}
}
