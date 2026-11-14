// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math/big"
	"regexp"
	"strings"

	"axonflow/platform/agent/rls"
	"axonflow/platform/decision/activation"
	sharedpolicy "axonflow/platform/shared/policy"
)

const (
	paymentExceptionModuleID          = "payment_exception"
	paymentExceptionCapabilityID      = "payment_exception.workflow"
	paymentExceptionCapabilityVersion = "1.0"
	paymentExceptionPolicyID          = "payment_exception.retry_approval"
	paymentExceptionPolicyVersion     = "1.0"
	paymentExceptionPolicySchema      = "0aaac12614a336ea0e3310620eaf499e9eefd79a4a075ea1765da0c0c50cc839"
	paymentExceptionPolicyArtifact    = "payment-exception-policy-document.json"
	paymentExceptionPolicyArtifactSHA = "245d20a13a1dc52e40d3a67202119ba2d3dabeda16b3da8314b9805e68e38de5"
	paymentExceptionActivationFact    = "payment_exception_activation_block"
	paymentExceptionRetryFact         = "payment_exception_retry_stepup"
)

var paymentEvidenceDigest = regexp.MustCompile(`^[a-f0-9]{64}$`)
var paymentAmount = regexp.MustCompile(`^(0|[1-9][0-9]*)(\.[0-9]+)?$`)

type paymentExceptionModuleIdentity struct {
	moduleID, grantReason, manifestSHA256, artifactSetSHA256 string
	runtimeArtifactName, runtimeArtifactSHA256, sbomSHA256   string
	capabilityID, capabilityVersion, capabilitySchemaSHA256  string
	policyID, policyVersion, policySchemaSHA256              string
	policyArtifactName, policyArtifactSHA256                 string
	policyReason                                             string
	policyActive                                             bool
	healthID, healthVersion, healthSchemaSHA256              string
	readinessID, readinessVersion, readinessSchemaSHA256     string
	manifestRevocationID, trustRootKeyID, trustRootKeySHA256 string
	trustRootKeyRef, trustDocumentID, trustDocumentSHA256    string
	grantID                                                  string
	grantActive                                              bool
	trustDocumentSequence                                    int64
	deploymentMode, eligibilityReason                        string
	eligibilityActive                                        bool
}

func (i paymentExceptionModuleIdentity) usable() bool {
	return i.grantActive && i.grantID != "" && i.grantReason == "" &&
		i.moduleID == paymentExceptionModuleID &&
		i.capabilityID == paymentExceptionCapabilityID &&
		i.capabilityVersion == paymentExceptionCapabilityVersion &&
		i.policyActive && i.policyReason == "" &&
		i.policyID == paymentExceptionPolicyID && i.policyVersion == paymentExceptionPolicyVersion &&
		i.policySchemaSHA256 == paymentExceptionPolicySchema &&
		i.policyArtifactName == paymentExceptionPolicyArtifact &&
		i.policyArtifactSHA256 == paymentExceptionPolicyArtifactSHA &&
		i.manifestSHA256 != "" && i.artifactSetSHA256 != "" &&
		i.runtimeArtifactName == "case-workflows-image" && i.runtimeArtifactSHA256 != "" &&
		i.sbomSHA256 != "" && i.capabilitySchemaSHA256 != "" &&
		i.healthID == "payment_exception.health" && i.healthVersion != "" && i.healthSchemaSHA256 != "" &&
		i.readinessID == "payment_exception.readiness" && i.readinessVersion != "" && i.readinessSchemaSHA256 != "" &&
		i.manifestRevocationID != "" && i.trustRootKeyID != "" && i.trustRootKeySHA256 != "" &&
		i.trustRootKeyRef != "" && i.trustDocumentID != "" &&
		(i.deploymentMode == "hosted" || i.deploymentMode == "self_hosted") &&
		i.eligibilityActive && i.eligibilityReason == "" &&
		i.trustDocumentSequence > 0 && i.trustDocumentSHA256 != ""
}

func loadPaymentExceptionModuleIdentity(ctx context.Context, db *sql.DB, orgID, tenantID string) (paymentExceptionModuleIdentity, error) {
	var out paymentExceptionModuleIdentity
	if db == nil {
		return out, errors.New("payment exception module identity store is unavailable")
	}
	err := rls.WithOrgAndTenantScope(ctx, db, orgID, tenantID, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, `SELECT module_id, coalesce(grant_id::text, ''), grant_active,
			coalesce(grant_reason, ''), coalesce(manifest_sha256, ''), coalesce(artifact_set_sha256, ''),
			coalesce(runtime_artifact_name, ''), coalesce(runtime_artifact_sha256, ''), coalesce(sbom_sha256, ''),
			coalesce(capability_id, ''), coalesce(capability_version, ''), coalesce(capability_schema_sha256, ''),
			policy_active, coalesce(policy_reason, ''), coalesce(policy_id, ''), coalesce(policy_version, ''),
			coalesce(policy_schema_sha256, ''), coalesce(policy_artifact_name, ''), coalesce(policy_artifact_sha256, ''),
			coalesce(health_procedure_id, ''), coalesce(health_procedure_version, ''), coalesce(health_schema_sha256, ''),
			coalesce(readiness_procedure_id, ''), coalesce(readiness_procedure_version, ''), coalesce(readiness_schema_sha256, ''),
			coalesce(manifest_revocation_id, ''), coalesce(trust_root_key_id, ''), coalesce(trust_root_key_sha256, ''),
			coalesce(trust_root_key_ref, ''), coalesce(trust_document_id, ''), coalesce(trust_document_sequence, 0),
			coalesce(trust_document_sha256, ''), coalesce(deployment_mode, ''),
			eligibility_active, coalesce(eligibility_reason, '')
			FROM hosted_outcome_module_identity($1)`, paymentExceptionModuleID).Scan(
			&out.moduleID, &out.grantID, &out.grantActive, &out.grantReason,
			&out.manifestSHA256, &out.artifactSetSHA256, &out.runtimeArtifactName,
			&out.runtimeArtifactSHA256, &out.sbomSHA256, &out.capabilityID,
			&out.capabilityVersion, &out.capabilitySchemaSHA256, &out.policyActive,
			&out.policyReason, &out.policyID, &out.policyVersion, &out.policySchemaSHA256,
			&out.policyArtifactName, &out.policyArtifactSHA256, &out.healthID,
			&out.healthVersion, &out.healthSchemaSHA256, &out.readinessID,
			&out.readinessVersion, &out.readinessSchemaSHA256, &out.manifestRevocationID,
			&out.trustRootKeyID, &out.trustRootKeySHA256, &out.trustRootKeyRef,
			&out.trustDocumentID, &out.trustDocumentSequence, &out.trustDocumentSHA256,
			&out.deploymentMode, &out.eligibilityActive, &out.eligibilityReason,
		)
	})
	if err != nil {
		return out, fmt.Errorf("resolve signed payment exception module identity: %w", err)
	}
	return out, nil
}

func activePaymentExceptionPolicy(ctx context.Context, db *sql.DB, orgID, tenantID string) ([]activation.InstalledPack, paymentExceptionModuleIdentity, error) {
	var identity paymentExceptionModuleIdentity
	if instantiatedPaymentExceptionPack == nil {
		return nil, identity, errors.New("payment exception policy pack is not installed")
	}
	identity, err := loadPaymentExceptionModuleIdentity(ctx, db, orgID, tenantID)
	if err != nil {
		return nil, identity, err
	}
	if !identity.usable() {
		return nil, identity, errors.New("signed payment exception module and policy identity is unavailable")
	}
	packs := append([]activation.InstalledPack(nil), instantiatedDeploymentPolicyPacks...)
	packs = append(packs, *instantiatedPaymentExceptionPack)
	return packs, identity, nil
}

func exactPaymentRetry(orgID, tenantID, stage string, target DecisionTarget, context map[string]interface{}) (bool, bool) {
	if stage != DecisionStageTool || target.Type != "tool" || target.Server != "payment-ops" || target.Tool != "payment-ops.retry_disbursement" {
		return false, false
	}
	v, ok := context["payment_exception"].(map[string]interface{})
	if !ok || v["action"] != "retry_disbursement" {
		return true, false
	}
	for _, key := range []string{"organization_id", "tenant_id", "case_id", "transaction_id", "idempotency_key", "payee_id", "currency", "evidence_fingerprint", "analyst_id"} {
		value, stringOK := v[key].(string)
		if !stringOK || strings.TrimSpace(value) == "" || value != strings.TrimSpace(value) {
			return true, false
		}
	}
	if !paymentEvidenceDigest.MatchString(v["evidence_fingerprint"].(string)) {
		return true, false
	}
	if v["organization_id"] != orgID || v["tenant_id"] != tenantID {
		return true, false
	}
	amount, amountOK := v["amount_currency_units"].(string)
	parsedAmount, parsedOK := new(big.Rat).SetString(amount)
	if !amountOK || !paymentAmount.MatchString(amount) || !parsedOK || parsedAmount.Sign() <= 0 {
		return true, false
	}
	return true, true
}

func applyPaymentExceptionFacts(observation *sharedpolicy.Observation, invalid, retry bool) *sharedpolicy.Observation {
	if observation == nil {
		observation = &sharedpolicy.Observation{}
	}
	rows := make([]sharedpolicy.DetectorFact, 0, len(observation.Rows)+2)
	for _, row := range observation.Rows {
		if row.PolicyID != paymentExceptionActivationFact && row.PolicyID != paymentExceptionRetryFact {
			rows = append(rows, row)
		}
	}
	rows = append(rows,
		sharedpolicy.DetectorFact{PolicyID: paymentExceptionActivationFact, Ran: true, Matched: invalid},
		sharedpolicy.DetectorFact{PolicyID: paymentExceptionRetryFact, Ran: true, Matched: retry},
	)
	return &sharedpolicy.Observation{Rows: rows, CapabilityScoped: observation.CapabilityScoped}
}

// resolvePaymentExceptionPolicy is called after authentication supplied the
// org and tenant. Body fields can make a request malformed, but can never grant
// the module or select another tenant.
func resolvePaymentExceptionPolicy(ctx context.Context, db *sql.DB, orgID, tenantID, stage string, target DecisionTarget, requestContext map[string]interface{}, observation *sharedpolicy.Observation) ([]activation.InstalledPack, bool, *sharedpolicy.Observation, error) {
	targeted, valid := exactPaymentRetry(orgID, tenantID, stage, target, requestContext)
	if !targeted {
		return nil, false, observation, nil
	}
	packs, _, err := activePaymentExceptionPolicy(ctx, db, orgID, tenantID)
	if err != nil {
		return nil, true, observation, err
	}
	return packs, true, applyPaymentExceptionFacts(observation, !valid, valid), nil
}
