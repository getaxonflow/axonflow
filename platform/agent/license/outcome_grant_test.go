// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package license

import (
	"context"
	"testing"

	"axonflow/platform/shared/capabilityresolution"
)

func validOutcomePayload(tier Tier, deploymentID, tenantID string, modules ...OutcomeModuleGrantInput) ServiceLicensePayload {
	grants := make([]SelfHostedCapabilityGrant, 0, len(modules))
	for _, module := range modules {
		grant, err := newOutcomeSelfHostedGrant(deploymentID, tenantID, module)
		if err != nil {
			panic(err)
		}
		grants = append(grants, grant)
	}
	return ServiceLicensePayload{
		Tier:                       string(tier),
		DeploymentID:               deploymentID,
		OrgID:                      deploymentID,
		ServiceName:                "platform",
		ServiceType:                "backend-service",
		Permissions:                []string{"outcome:execute"},
		IssuedAt:                   "20261106",
		ExpiresAt:                  "20991231",
		Aud:                        AudSelfHostedFull,
		SelfHostedCapabilityGrants: grants,
	}
}

func TestOutcomeGrantsResolveIndependentlyForSignedTenant(t *testing.T) {
	_, entPriv := finCrimeGrantTestKeys(t)
	payload := validOutcomePayload(TierEnterprise, "deployment-a", "tenant-a",
		OutcomeModuleGrantInput{Module: capabilityresolution.PaymentExceptionModuleID, CaseAllowance: 41},
		OutcomeModuleGrantInput{Module: capabilityresolution.SupportRefundModuleID, CaseAllowance: 9},
	)
	result, err := ValidateLicense(context.Background(), SignPayloadForTest(entPriv, payload))
	if err != nil || result == nil || !result.Valid {
		t.Fatalf("valid signed outcome grants rejected: result=%+v err=%v", result, err)
	}
	if got, ok := result.OutcomeCaseAllowance(capabilityresolution.PaymentExceptionModuleID, "tenant-a"); !ok || got != 41 {
		t.Fatalf("payment allowance = %d, %v", got, ok)
	}
	if got, ok := result.OutcomeCaseAllowance(capabilityresolution.SupportRefundModuleID, "tenant-a"); !ok || got != 9 {
		t.Fatalf("refund allowance = %d, %v", got, ok)
	}
	for _, query := range [][2]string{
		{capabilityresolution.PaymentExceptionModuleID, "tenant-b"},
		{capabilityresolution.FinCrimeModuleID, "tenant-a"},
		{"caller_asserted_module", "tenant-a"},
	} {
		if got, ok := result.OutcomeCaseAllowance(query[0], query[1]); ok || got != 0 {
			t.Fatalf("untrusted lookup %v resolved allowance %d, %v", query, got, ok)
		}
	}
}

func TestOutcomeGrantDoesNotImplyOtherModule(t *testing.T) {
	_, entPriv := finCrimeGrantTestKeys(t)
	payload := validOutcomePayload(TierEnterprise, "deployment-a", "tenant-a",
		OutcomeModuleGrantInput{Module: capabilityresolution.PaymentExceptionModuleID, CaseAllowance: 10},
	)
	result, err := ValidateLicense(context.Background(), SignPayloadForTest(entPriv, payload))
	if err != nil || result == nil || !result.Valid {
		t.Fatalf("valid payment grant rejected: result=%+v err=%v", result, err)
	}
	if got, ok := result.OutcomeCaseAllowance(capabilityresolution.SupportRefundModuleID, "tenant-a"); ok || got != 0 {
		t.Fatalf("payment grant implied refund allowance %d, %v", got, ok)
	}
	if got, ok := result.FinCrimeScoreRequestAllowance("tenant-a"); ok || got != 0 {
		t.Fatalf("payment grant implied FinCrime allowance %d, %v", got, ok)
	}
}

func TestOutcomeGrantFailsClosedOnInvalidClaims(t *testing.T) {
	_, entPriv := finCrimeGrantTestKeys(t)
	tests := []struct {
		name string
		edit func(*ServiceLicensePayload)
		want string
	}{
		{"wrong tenant", func(p *ServiceLicensePayload) { p.SelfHostedCapabilityGrants[0].TenantID = " " }, "invalid tenant scope"},
		{"wrong deployment", func(p *ServiceLicensePayload) { p.SelfHostedCapabilityGrants[0].DeploymentID = "deployment-b" }, "deployment scope does not match"},
		{"wrong capability", func(p *ServiceLicensePayload) {
			p.SelfHostedCapabilityGrants[0].Capabilities[0].ID = capabilityresolution.SupportRefundWorkflowCapabilityID
		}, "unknown self-hosted payment_exception capability"},
		{"wrong capability version", func(p *ServiceLicensePayload) { p.SelfHostedCapabilityGrants[0].Capabilities[0].Version = "2.0" }, "unknown version"},
		{"wrong limit", func(p *ServiceLicensePayload) {
			p.SelfHostedCapabilityGrants[0].Limits[0].ID = capabilityresolution.SupportRefundCasesLimitID
		}, "unknown self-hosted payment_exception limit"},
		{"wrong period", func(p *ServiceLicensePayload) { p.SelfHostedCapabilityGrants[0].Limits[0].Period = "day" }, "unknown self-hosted payment_exception case period"},
		{"over-quota sentinel", func(p *ServiceLicensePayload) { p.SelfHostedCapabilityGrants[0].Limits[0].Allowance = 0 }, "finite and positive"},
		{"duplicate same module", func(p *ServiceLicensePayload) {
			p.SelfHostedCapabilityGrants = append(p.SelfHostedCapabilityGrants, p.SelfHostedCapabilityGrants[0])
		}, "duplicate self-hosted capability grant"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			payload := validOutcomePayload(TierEnterprise, "deployment-a", "tenant-a",
				OutcomeModuleGrantInput{Module: capabilityresolution.PaymentExceptionModuleID, CaseAllowance: 10},
			)
			test.edit(&payload)
			requireLicenseRejected(t, SignPayloadForTest(entPriv, payload), test.want)
		})
	}
}

func TestExpiredOutcomeGrantCannotResolveAllowance(t *testing.T) {
	_, entPriv := finCrimeGrantTestKeys(t)
	payload := validOutcomePayload(TierEnterprise, "deployment-a", "tenant-a",
		OutcomeModuleGrantInput{Module: capabilityresolution.SupportRefundModuleID, CaseAllowance: 10},
	)
	payload.ExpiresAt = "20200101"
	result, err := ValidateLicense(context.Background(), SignPayloadForTest(entPriv, payload))
	if err != nil || result == nil || result.Valid {
		t.Fatalf("expired result=%+v err=%v", result, err)
	}
	if got, ok := result.OutcomeCaseAllowance(capabilityresolution.SupportRefundModuleID, "tenant-a"); ok || got != 0 {
		t.Fatalf("expired allowance = %d, %v", got, ok)
	}
}
