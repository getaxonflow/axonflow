// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"testing"

	"axonflow/platform/shared/serviceauth"
)

func hostedOutcomeSubject(t *testing.T, org, tenant string) string {
	t.Helper()
	raw, err := json.Marshal(hostedOutcomeDelegation{
		OrganizationID: org, Service: "hosted-outcome-service", TenantID: tenant,
	})
	if err != nil {
		t.Fatal(err)
	}
	return hostedOutcomeDelegationPrefix + base64.RawURLEncoding.EncodeToString(raw)
}

func TestHostedOutcomeSubjectBoundCredentialIsTheTenantAuthority(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "enterprise")
	const secret = "hosted-outcome-delegation-secret-32-bytes-minimum"
	previousDB, previousValidator := authDB, internalTokenValidator
	authDB = nil
	internalTokenValidator = serviceauth.NewTokenValidator(secret, nil, 0)
	t.Cleanup(func() { authDB, internalTokenValidator = previousDB, previousValidator })

	subject := hostedOutcomeSubject(t, "org-a", "tenant-a")
	token, err := serviceauth.NewTokenGenerator(secret, nil).GenerateTokenForSubject(subject)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest("POST", "/api/v1/decide", nil)
	request.Header.Set(serviceauth.SubjectHeader, subject)
	// Neither of these hostile routing headers is authority once the request
	// presents a tenant-delegation subject.
	request.Header.Set("X-Org-ID", "victim-org")
	request.Header.Set("X-Tenant-ID", "victim-tenant")
	result, authErr := Authenticate(request, &AuthHints{
		ClientID: serviceauth.ClientID, UserToken: token, TenantID: "victim-tenant",
	})
	if authErr != nil {
		t.Fatalf("subject-bound delegation was refused: %v", authErr)
	}
	if result.Kind != AuthKindInternalService || result.OrgID != "org-a" || result.TenantID != "tenant-a" ||
		result.ClientID != "hosted-outcome-service" || result.Client.ClientID != "hosted-outcome-service" {
		t.Fatalf("authentication used mutable routing identity: %+v", result)
	}
}

func TestHostedOutcomeSubjectCannotBeReboundOrDowngraded(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "enterprise")
	const secret = "hosted-outcome-delegation-secret-32-bytes-minimum"
	previousDB, previousValidator := authDB, internalTokenValidator
	authDB = nil
	internalTokenValidator = serviceauth.NewTokenValidator(secret, nil, 0)
	t.Cleanup(func() { authDB, internalTokenValidator = previousDB, previousValidator })

	tenantA := hostedOutcomeSubject(t, "org-a", "tenant-a")
	tenantB := hostedOutcomeSubject(t, "org-b", "tenant-b")
	token, err := serviceauth.NewTokenGenerator(secret, nil).GenerateTokenForSubject(tenantA)
	if err != nil {
		t.Fatal(err)
	}
	for name, subject := range map[string]string{
		"another tenant": tenantB,
		"non-canonical JSON": hostedOutcomeDelegationPrefix + base64.RawURLEncoding.EncodeToString(
			[]byte(`{"tenant_id":"tenant-a","service":"hosted-outcome-service","organization_id":"org-a"}`)),
		"unknown subject": "wcp-01",
	} {
		t.Run(name, func(t *testing.T) {
			request := httptest.NewRequest("POST", "/api/v1/decide", nil)
			request.Header.Set(serviceauth.SubjectHeader, subject)
			result, authErr := Authenticate(request, &AuthHints{
				ClientID: serviceauth.ClientID, UserToken: token, TenantID: "tenant-a",
			})
			if result != nil || authErr == nil || authErr.Code != "invalid_credentials" {
				t.Fatalf("invalid bound delegation reached internal auth: result=%+v error=%+v", result, authErr)
			}
		})
	}
}
