// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"os"
	"path/filepath"
	"testing"

	"axonflow/platform/decision/legacycompile"
	"axonflow/platform/decision/policypack"
)

func validPaymentRetryContext() map[string]interface{} {
	return map[string]interface{}{"payment_exception": map[string]interface{}{
		"organization_id": "org-a", "tenant_id": "tenant-a", "case_id": "case-a",
		"transaction_id": "txn-a", "idempotency_key": "idem-a", "payee_id": "payee-a",
		"currency": "USD", "evidence_fingerprint": string(make([]byte, 0)),
		"analyst_id": "analyst@example.com", "action": "retry_disbursement",
		"amount_currency_units": "949.25",
	}}
}

func TestPaymentExceptionRetryRequiresExactBoundAction(t *testing.T) {
	context := validPaymentRetryContext()
	context["payment_exception"].(map[string]interface{})["evidence_fingerprint"] =
		"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	target := DecisionTarget{Type: "tool", Server: "payment-ops", Tool: "payment-ops.retry_disbursement"}
	if targeted, valid := exactPaymentRetry("org-a", "tenant-a", DecisionStageTool, target, context); !targeted || !valid {
		t.Fatal("exact bound retry was not admitted to module-policy evaluation")
	}
	for name, mutate := range map[string]func(map[string]interface{}){
		"wrong tenant":        func(v map[string]interface{}) { v["tenant_id"] = "tenant-b" },
		"zero amount":         func(v map[string]interface{}) { v["amount_currency_units"] = "0" },
		"numeric amount":      func(v map[string]interface{}) { v["amount_currency_units"] = float64(949.25) },
		"noncanonical amount": func(v map[string]interface{}) { v["amount_currency_units"] = "0949.25" },
		"missing destination": func(v map[string]interface{}) { v["payee_id"] = "" },
		"missing idempotency": func(v map[string]interface{}) { v["idempotency_key"] = "" },
		"missing evidence":    func(v map[string]interface{}) { v["evidence_fingerprint"] = "" },
	} {
		t.Run(name, func(t *testing.T) {
			copyContext := validPaymentRetryContext()
			values := copyContext["payment_exception"].(map[string]interface{})
			values["evidence_fingerprint"] = context["payment_exception"].(map[string]interface{})["evidence_fingerprint"]
			mutate(values)
			_, valid := exactPaymentRetry("org-a", "tenant-a", DecisionStageTool, target, copyContext)
			if valid {
				t.Fatal("changed binding was accepted")
			}
		})
	}
	if targeted, _ := exactPaymentRetry("org-a", "tenant-a", DecisionStageTool,
		DecisionTarget{Type: "tool", Server: "other", Tool: "payment-ops.retry_disbursement"}, context); targeted {
		t.Fatal("unrelated target selected the payment module")
	}
}

func TestPaymentExceptionCommittedPolicyDocumentMatchesSource(t *testing.T) {
	dir := filepath.Join("..", "..", "ee", "policy-packs", "payment-exception")
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
	if pack.Source.ID != "payment-exception" || pack.Source.Version != 1 || pack.Source.Approval == nil {
		t.Fatalf("unexpected payment policy identity: %#v", pack.Source)
	}
}

func TestPaymentExceptionIdentityRejectsDeploymentIneligibility(t *testing.T) {
	valid := paymentExceptionModuleIdentity{
		moduleID: paymentExceptionModuleID, grantID: "grant-a", grantActive: true,
		manifestSHA256: "manifest", artifactSetSHA256: "artifacts",
		runtimeArtifactName: "case-workflows-image", runtimeArtifactSHA256: "image", sbomSHA256: "sbom",
		capabilityID: paymentExceptionCapabilityID, capabilityVersion: paymentExceptionCapabilityVersion,
		capabilitySchemaSHA256: "capability", policyActive: true,
		policyID: paymentExceptionPolicyID, policyVersion: paymentExceptionPolicyVersion,
		policySchemaSHA256: paymentExceptionPolicySchema, policyArtifactName: paymentExceptionPolicyArtifact,
		policyArtifactSHA256: paymentExceptionPolicyArtifactSHA,
		healthID:             "payment_exception.health", healthVersion: "1.0", healthSchemaSHA256: "health",
		readinessID: "payment_exception.readiness", readinessVersion: "1.0", readinessSchemaSHA256: "readiness",
		manifestRevocationID: "revocation", trustRootKeyID: "root", trustRootKeySHA256: "root-sha",
		trustRootKeyRef: "root-ref", trustDocumentID: "trust", trustDocumentSequence: 1,
		trustDocumentSHA256: "trust-sha", deploymentMode: "hosted", eligibilityActive: true,
	}
	if !valid.usable() {
		t.Fatal("valid payment exception identity was rejected")
	}
	for name, mutate := range map[string]func(*paymentExceptionModuleIdentity){
		"inactive hosted subscription": func(v *paymentExceptionModuleIdentity) {
			v.eligibilityActive = false
			v.eligibilityReason = "subscription_inactive"
		},
		"expired self-hosted licence": func(v *paymentExceptionModuleIdentity) {
			v.deploymentMode = "self_hosted"
			v.eligibilityActive = false
			v.eligibilityReason = "self_hosted_license_expired"
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := valid
			mutate(&candidate)
			if candidate.usable() {
				t.Fatal("deployment-ineligible payment policy remained usable")
			}
		})
	}
}

func TestOutcomeModulePolicyCategoriesBindOnDecideRequest(t *testing.T) {
	admission, err := legacycompile.AdmissionFor(legacycompile.PlaneDecide, legacycompile.PhaseRequest)
	if err != nil {
		t.Fatal(err)
	}
	for _, category := range []string{"payment-exception", "support-refund"} {
		if !admission.Admits(category) {
			t.Fatalf("decide request admission excludes signed module category %q", category)
		}
	}
}
