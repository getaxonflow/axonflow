// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"regexp"
	"strings"

	"axonflow/platform/agent/rls"
	"axonflow/platform/decision/activation"
	sharedpolicy "axonflow/platform/shared/policy"
)

const (
	supportRefundModuleID          = "support_refund"
	supportRefundCapabilityID      = "support_refund.workflow"
	supportRefundCapabilityVersion = "1.0"
	supportRefundPolicyID          = "support_refund.issue_approval"
	supportRefundPolicyVersion     = "1.0"
	supportRefundPolicySchema      = "59ba84db8e7d3788dfc3a11149fd027340e8d33ff4a3bc15c032fc223e3db5d7"
	supportRefundPolicyArtifact    = "support-refund-policy-document.json"
	supportRefundPolicyArtifactSHA = "a66b1698521de773b12c36e620d167dcd9c8f5326ce0c68fc25a1f8034c1f070"
	supportRefundActivationFact    = "support_refund_activation_block"
	supportRefundIssueFact         = "support_refund_issue_stepup"
)

var supportRefundEvidenceDigest = regexp.MustCompile(`^[a-f0-9]{64}$`)
var supportRefundCurrency = regexp.MustCompile(`^[A-Z]{3}$`)

type supportRefundModuleIdentity paymentExceptionModuleIdentity

func (i supportRefundModuleIdentity) usable() bool {
	return i.grantActive && i.grantID != "" && i.grantReason == "" &&
		i.moduleID == supportRefundModuleID &&
		i.capabilityID == supportRefundCapabilityID &&
		i.capabilityVersion == supportRefundCapabilityVersion &&
		i.policyActive && i.policyReason == "" &&
		i.policyID == supportRefundPolicyID && i.policyVersion == supportRefundPolicyVersion &&
		i.policySchemaSHA256 == supportRefundPolicySchema &&
		i.policyArtifactName == supportRefundPolicyArtifact &&
		i.policyArtifactSHA256 == supportRefundPolicyArtifactSHA &&
		i.manifestSHA256 != "" && i.artifactSetSHA256 != "" &&
		i.runtimeArtifactName == "case-workflows-image" && i.runtimeArtifactSHA256 != "" &&
		i.sbomSHA256 != "" && i.capabilitySchemaSHA256 != "" &&
		i.healthID == "support_refund.health" && i.healthVersion != "" && i.healthSchemaSHA256 != "" &&
		i.readinessID == "support_refund.readiness" && i.readinessVersion != "" && i.readinessSchemaSHA256 != "" &&
		i.manifestRevocationID != "" && i.trustRootKeyID != "" && i.trustRootKeySHA256 != "" &&
		i.trustRootKeyRef != "" && i.trustDocumentID != "" &&
		(i.deploymentMode == "hosted" || i.deploymentMode == "self_hosted") &&
		i.eligibilityActive && i.eligibilityReason == "" &&
		i.trustDocumentSequence > 0 && i.trustDocumentSHA256 != ""
}

func loadSupportRefundModuleIdentity(ctx context.Context, db *sql.DB, orgID, tenantID string) (supportRefundModuleIdentity, error) {
	var out supportRefundModuleIdentity
	if db == nil {
		return out, errors.New("support refund module identity store is unavailable")
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
			FROM hosted_outcome_module_identity($1)`, supportRefundModuleID).Scan(
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
		return out, fmt.Errorf("resolve signed support refund module identity: %w", err)
	}
	return out, nil
}

func activeSupportRefundPolicy(ctx context.Context, db *sql.DB, orgID, tenantID string) ([]activation.InstalledPack, supportRefundModuleIdentity, error) {
	var identity supportRefundModuleIdentity
	if instantiatedSupportRefundPack == nil {
		return nil, identity, errors.New("support refund policy pack is not installed")
	}
	identity, err := loadSupportRefundModuleIdentity(ctx, db, orgID, tenantID)
	if err != nil {
		return nil, identity, err
	}
	if !identity.usable() {
		return nil, identity, errors.New("signed support refund module and policy identity is unavailable")
	}
	packs := append([]activation.InstalledPack(nil), instantiatedDeploymentPolicyPacks...)
	packs = append(packs, *instantiatedSupportRefundPack)
	return packs, identity, nil
}

func exactSupportRefund(orgID, tenantID, stage string, target DecisionTarget, requestContext map[string]interface{}) (bool, bool) {
	if stage != DecisionStageTool || target.Type != "tool" || target.Server != "support-ops" || target.Tool != "support-ops.issue_refund" {
		return false, false
	}
	v, ok := requestContext["refund_action"].(map[string]interface{})
	if !ok || v["version"] != float64(1) {
		return true, false
	}
	for _, key := range []string{"case_id", "order_id", "payment_id", "customer_id", "idempotency_key", "currency", "evidence_version", "requester_id", "action", "refund_destination"} {
		value, stringOK := v[key].(string)
		if !stringOK || strings.TrimSpace(value) == "" || value != strings.TrimSpace(value) {
			return true, false
		}
	}
	if !supportRefundCurrency.MatchString(v["currency"].(string)) ||
		!supportRefundEvidenceDigest.MatchString(v["evidence_version"].(string)) {
		return true, false
	}
	if v["action"] != "issue_refund" ||
		v["refund_destination"] != "original_payment_method:"+v["payment_id"].(string) {
		return true, false
	}
	amount, amountOK := v["amount_minor"].(float64)
	if !amountOK || amount <= 0 || amount > float64(1<<53-1) || math.Trunc(amount) != amount {
		return true, false
	}
	// Organization and tenant are supplied by the authenticated delegation,
	// not by the body. If a client redundantly supplies them, they must agree;
	// they can never select a different module projection.
	for key, expected := range map[string]string{"organization_id": orgID, "tenant_id": tenantID} {
		if supplied, present := v[key]; present {
			value, stringOK := supplied.(string)
			if !stringOK || value != expected {
				return true, false
			}
		}
	}
	return true, true
}

func applySupportRefundFacts(observation *sharedpolicy.Observation, invalid, issue bool) *sharedpolicy.Observation {
	if observation == nil {
		observation = &sharedpolicy.Observation{}
	}
	rows := make([]sharedpolicy.DetectorFact, 0, len(observation.Rows)+2)
	for _, row := range observation.Rows {
		if row.PolicyID != supportRefundActivationFact && row.PolicyID != supportRefundIssueFact {
			rows = append(rows, row)
		}
	}
	rows = append(rows,
		sharedpolicy.DetectorFact{PolicyID: supportRefundActivationFact, Ran: true, Matched: invalid},
		sharedpolicy.DetectorFact{PolicyID: supportRefundIssueFact, Ran: true, Matched: issue},
	)
	return &sharedpolicy.Observation{Rows: rows, CapabilityScoped: observation.CapabilityScoped}
}

func resolveSupportRefundPolicy(ctx context.Context, db *sql.DB, orgID, tenantID, stage string, target DecisionTarget, requestContext map[string]interface{}, observation *sharedpolicy.Observation) ([]activation.InstalledPack, bool, *sharedpolicy.Observation, error) {
	targeted, valid := exactSupportRefund(orgID, tenantID, stage, target, requestContext)
	if !targeted {
		return nil, false, observation, nil
	}
	packs, _, err := activeSupportRefundPolicy(ctx, db, orgID, tenantID)
	if err != nil {
		return nil, true, observation, err
	}
	return packs, true, applySupportRefundFacts(observation, !valid, valid), nil
}

// resolveOutcomeModulePolicy routes only the exact module action to its own
// tenant-scoped signed policy projection. A body cannot select a module: the
// authenticated tool target is the only router and each resolver independently
// validates the exact action binding.
func resolveOutcomeModulePolicy(ctx context.Context, db *sql.DB, orgID, tenantID, stage string, target DecisionTarget, requestContext map[string]interface{}, observation *sharedpolicy.Observation) ([]activation.InstalledPack, bool, *sharedpolicy.Observation, error) {
	if packs, resolved, observed, err := resolvePaymentExceptionPolicy(ctx, db, orgID, tenantID, stage, target, requestContext, observation); resolved || err != nil {
		return packs, resolved, observed, err
	}
	return resolveSupportRefundPolicy(ctx, db, orgID, tenantID, stage, target, requestContext, observation)
}
