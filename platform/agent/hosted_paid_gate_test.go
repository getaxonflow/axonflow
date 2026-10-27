// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestHostedEventFingerprintBindsIdempotencyKeyToRequest(t *testing.T) {
	first := httptest.NewRequest(http.MethodPost, "/api/request?mode=governed", strings.NewReader(`{"amount":1}`))
	first.Header.Set("Content-Type", "application/json")
	firstFingerprint, err := hostedRequestFingerprint(first, nil)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := io.ReadAll(first.Body)
	if err != nil || string(restored) != `{"amount":1}` {
		t.Fatalf("request body was not restored: %q, %v", restored, err)
	}

	retry := httptest.NewRequest(http.MethodPost, "/api/request?mode=governed", strings.NewReader(`{"amount":1}`))
	retry.Header.Set("Content-Type", "application/json")
	retryFingerprint, err := hostedRequestFingerprint(retry, nil)
	if err != nil {
		t.Fatal(err)
	}
	changed := httptest.NewRequest(http.MethodPost, "/api/request?mode=governed", strings.NewReader(`{"amount":2}`))
	changed.Header.Set("Content-Type", "application/json")
	changedFingerprint, err := hostedRequestFingerprint(changed, nil)
	if err != nil {
		t.Fatal(err)
	}
	if firstFingerprint != retryFingerprint || firstFingerprint == changedFingerprint {
		t.Fatalf("fingerprints do not bind retries to request content: first=%s retry=%s changed=%s", firstFingerprint, retryFingerprint, changedFingerprint)
	}
}

func setHostedStarterTestConfig(t *testing.T) {
	t.Helper()
	t.Setenv(hostedSecurityAcceptanceEnv, "4488")
	t.Setenv(hostedWorkflowAcceptanceEnv, "4486")
	t.Setenv(hostedModuleCapabilitiesEnv, "fincrime,payment_exception,support_refund")
	t.Setenv(hostedPublicBaseURLEnv, "https://try-staging.getaxonflow.com")
	t.Setenv("AXONFLOW_HOSTED_INCLUDED_EVENTS", "750")
	t.Setenv("AXONFLOW_HOSTED_INCLUDED_CASES", "100")
	t.Setenv("AXONFLOW_HOSTED_INCLUDED_SEATS", "2")
	t.Setenv("AXONFLOW_HOSTED_INCLUDED_INTEGRATIONS", "1")
	t.Setenv("AXONFLOW_HOSTED_RETENTION_DAYS", "30")
	t.Setenv("COMMUNITY_SAAS_MINUTE_LIMIT_PRO", "60")
}

func TestHostedMonthlyLimitResponseIsStructuredForFailClosedClients(t *testing.T) {
	rec := httptest.NewRecorder()
	writeHostedMonthlyLimitReached(rec)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d", rec.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["error"] != "hosted_monthly_limit_reached" || body["limit_type"] != "monthly_governed_events" {
		t.Fatalf("unexpected response: %v", body)
	}
	if got := rec.Header().Get("X-Axonflow-Tier-Limit"); got != "monthly_governed_events" {
		t.Fatalf("tier limit header = %q", got)
	}
}

func TestHostedPaidLaunchReadyRequiresBothAcceptedDependencies(t *testing.T) {
	t.Setenv(hostedPublicBaseURLEnv, "https://try-staging.getaxonflow.com")
	t.Setenv(hostedSecurityAcceptanceEnv, "4488")
	if hostedPaidLaunchReady() {
		t.Fatal("security acceptance alone must not make the paid workflow launchable")
	}
	t.Setenv(hostedWorkflowAcceptanceEnv, "4486")
	if hostedPaidLaunchReady() {
		t.Fatal("dependency acceptance without deployed module capabilities must not make the launch gate ready")
	}
	t.Setenv(hostedModuleCapabilitiesEnv, "fincrime,payment_exception,support_refund")
	if !hostedPaidLaunchReady() {
		t.Fatal("accepted dependencies and all canonical modules should make the launch gate ready")
	}
	t.Setenv(hostedSecurityAcceptanceEnv, "true")
	if hostedPaidLaunchReady() {
		t.Fatal("a generic truthy value must not bypass the issue-specific acceptance gate")
	}
}

func TestHostedPaymentRequiredUsesConfiguredPublicOrigin(t *testing.T) {
	t.Setenv(hostedPublicBaseURLEnv, "https://try-staging.getaxonflow.com")
	err := hostedPaymentRequiredError("cs_staging")
	if err.CheckoutURL != "https://try-staging.getaxonflow.com"+hostedCheckoutPath {
		t.Fatalf("checkout URL = %q", err.CheckoutURL)
	}
	if endpoint := communitySaasPublicEndpoint(); endpoint != "https://try-staging.getaxonflow.com" {
		t.Fatalf("registration endpoint = %q", endpoint)
	}
}

func TestHostedPaidLaunchReadyRejectsInvalidPublicOrigin(t *testing.T) {
	setHostedStarterTestConfig(t)
	t.Setenv(hostedPublicBaseURLEnv, "https://try-staging.getaxonflow.com/path")
	if hostedPaidLaunchReady() {
		t.Fatal("invalid public origin must keep the launch gate closed")
	}
}

func TestHostedConfiguredModulesRejectsUnknownAndDoesNotAdvertiseMissingModules(t *testing.T) {
	t.Setenv(hostedModuleCapabilitiesEnv, "support_refund,fincrime")
	modules, err := hostedConfiguredModules()
	if err != nil || strings.Join(modules, ",") != "fincrime,support_refund" {
		t.Fatalf("configured modules = %v, %v", modules, err)
	}
	if hostedPaidLaunchReady() {
		t.Fatal("an incomplete module set must keep the complete starter offer closed")
	}
	t.Setenv(hostedModuleCapabilitiesEnv, "fincrime,not-a-module")
	if _, err := hostedConfiguredModules(); err == nil {
		t.Fatal("an unknown module must fail closed")
	}
}

func TestHostedStarterPlanLimitsRequireEveryPublishedLimit(t *testing.T) {
	setHostedStarterTestConfig(t)
	limits, err := hostedStarterPlanLimits()
	if err != nil {
		t.Fatalf("hostedStarterPlanLimits() error = %v", err)
	}
	if limits.GovernedEvents != 750 || limits.Cases != 100 || limits.Seats != 2 ||
		limits.Integrations != 1 || limits.RetentionDays != 30 || limits.BurstPerMinute != 60 {
		t.Fatalf("unexpected hosted limits: %+v", limits)
	}

	t.Setenv("AXONFLOW_HOSTED_INCLUDED_CASES", "")
	if _, err := hostedStarterPlanLimits(); err == nil {
		t.Fatal("missing case limit must keep hosted checkout unavailable")
	}
}

func TestHostedBillingManagementBypassIsExact(t *testing.T) {
	for _, path := range []string{hostedCheckoutPath, hostedBillingStatusPath, hostedBillingPortalPath} {
		if !isHostedBillingManagementPath(httptest.NewRequest("POST", path, nil)) {
			t.Fatalf("%s should be a billing management path", path)
		}
		if isHostedBillingManagementPath(httptest.NewRequest("POST", path+"/free", nil)) {
			t.Fatalf("%s prefix must not bypass hosted governance", path)
		}
	}
}

func TestHostedPaidGateUsesStableTenantCohort(t *testing.T) {
	t.Setenv("AXONFLOW_HOSTED_PAID_GATE", "enforce")
	t.Setenv("AXONFLOW_HOSTED_PAID_GATE_PERCENT", "37")
	want := hostedPaidGateApplies("cs_stable")
	for i := 0; i < 20; i++ {
		if got := hostedPaidGateApplies("cs_stable"); got != want {
			t.Fatalf("cohort assignment changed: got %v want %v", got, want)
		}
	}
}

func TestHostedPaidGateRequiresEveryTenantCreatedAfterCutoff(t *testing.T) {
	t.Setenv("AXONFLOW_HOSTED_PAID_GATE", "enforce")
	t.Setenv("AXONFLOW_HOSTED_PAID_GATE_PERCENT", "0")
	t.Setenv("AXONFLOW_HOSTED_PAID_REQUIRED_AFTER", "2026-10-22T00:00:00Z")
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id'`).WithArgs("cs_new").WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectQuery(`SELECT created_at FROM community_saas_registrations`).WithArgs("cs_new").WillReturnRows(
		sqlmock.NewRows([]string{"created_at"}).AddRow(time.Date(2026, 10, 22, 0, 0, 1, 0, time.UTC)),
	)
	mock.ExpectCommit()
	applies, err := hostedPaidGateAppliesToTenant(context.Background(), db, "cs_new")
	if err != nil || !applies {
		t.Fatalf("new tenant gate = %v, %v", applies, err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
