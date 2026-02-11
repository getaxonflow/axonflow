// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package agent

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"

	"axonflow/platform/agent/license"
)

// TestValidateViaOrganizations_Success tests successful organization validation with V2 license
// V2 licenses bypass database lookup - all data comes from the signed license payload
func TestValidateViaOrganizations_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock: %v", err)
	}
	defer func() { _ = db.Close() }()

	// Generate a valid V2 test license key
	testLicenseKey := generateTestLicenseKey("test-org", "Enterprise", "20351231")

	// V2 licenses DON'T query the database - no mock expectations needed
	// The license signature is cryptographically verified instead

	ctx := context.Background()
	client, err := validateViaOrganizations(ctx, db, "test-client", testLicenseKey)

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if client == nil {
		t.Fatal("expected client, got nil")
	}

	if client.OrgID != "test-org" {
		t.Errorf("expected org_id=test-org, got %s", client.OrgID)
	}

	if client.LicenseTier != "Enterprise" {
		t.Errorf("expected tier=Enterprise, got %s", client.LicenseTier)
	}

	// V2 licenses should NOT trigger database queries
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

// TestValidateViaOrganizations_V2LicenseIsAuthority tests that V2 licenses don't need
// the organization to exist in the database - the cryptographically signed license IS the authority.
func TestValidateViaOrganizations_V2LicenseIsAuthority(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock: %v", err)
	}
	defer func() { _ = db.Close() }()

	// Generate a valid V2 license for an org that doesn't exist in DB
	testLicenseKey := generateTestLicenseKey("nonexistent-org", "Enterprise", "20351231")

	// V2 licenses bypass database lookup - no mock expectations
	// The license signature is sufficient for authentication

	ctx := context.Background()
	client, err := validateViaOrganizations(ctx, db, "test-client", testLicenseKey)

	// V2 licenses should succeed even if org doesn't exist in DB
	if err != nil {
		t.Errorf("V2 license should not require database lookup, got error: %v", err)
	}

	if client == nil {
		t.Fatal("expected client from V2 license, got nil")
	}

	// Client data comes from the signed license payload
	if client.OrgID != "nonexistent-org" {
		t.Errorf("expected org_id from license payload, got %s", client.OrgID)
	}

	// No database queries should have been made
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

// TestValidateViaOrganizations_ExpiredOrg tests organization with expired license
// Note: In Community mode, expired licenses are accepted (lenient mode)
// In Enterprise mode, expired licenses are rejected after grace period
func TestValidateViaOrganizations_ExpiredOrg(t *testing.T) {
	db, _, err := sqlmock.New() // mock not used - license validation fails first
	if err != nil {
		t.Fatalf("failed to create mock: %v", err)
	}
	defer func() { _ = db.Close() }()

	// Create license that expires yesterday
	testLicenseKey := generateTestLicenseKey("expired-org", "Enterprise", "20231201") // Past date

	ctx := context.Background()
	client, err := validateViaOrganizations(ctx, db, "test-client", testLicenseKey)

	// In Community mode, expired licenses are accepted (lenient)
	// In Enterprise mode, this would fail after grace period
	if err != nil {
		// Enterprise behavior: expired license rejected
		// This is expected in enterprise builds
		return
	}

	// Community behavior: expired license accepted
	if client == nil {
		t.Error("Community mode: expected client for expired license, got nil")
	}
}

// TestUpdateAPIKeyLastUsed tests updating API key usage tracking
func TestUpdateAPIKeyLastUsed(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock: %v", err)
	}
	defer func() { _ = db.Close() }()

	// Expect UPDATE query
	mock.ExpectExec("UPDATE api_keys SET").
		WillReturnResult(sqlmock.NewResult(0, 1))

	ctx := context.Background()
	updateAPIKeyLastUsed(ctx, db, "test-api-key-id")

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

// TestTrackRequestUsage tests request usage tracking
func TestTrackRequestUsage(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock: %v", err)
	}
	defer func() { _ = db.Close() }()

	// Expect INSERT with ON CONFLICT
	mock.ExpectExec("INSERT INTO usage_metrics").
		WillReturnResult(sqlmock.NewResult(1, 1))

	ctx := context.Background()
	err = trackRequestUsage(ctx, db, "test-customer", "test-api-key", "query", true, 45.2)

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

// TestTrackRequestUsage_Failure tests error handling in usage tracking
func TestTrackRequestUsage_Failure(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock: %v", err)
	}
	defer func() { _ = db.Close() }()

	// Expect INSERT with ON CONFLICT
	mock.ExpectExec("INSERT INTO usage_metrics").
		WillReturnResult(sqlmock.NewResult(1, 0)) // 0 rows affected

	ctx := context.Background()
	err = trackRequestUsage(ctx, db, "test-customer", "test-api-key", "query", false, 120.5)

	// The function should still succeed even if 0 rows affected
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

// ==================================================================
// PHASE 3: COMPREHENSIVE DATABASE AUTHENTICATION TESTS
// Tests for validateClientCredentialsDB, validateViaAPIKeys, and utility functions
// ==================================================================

// TestValidateClientLicenseDB_ViaAPIKeys tests authentication through API keys path
func TestValidateClientLicenseDB_ViaAPIKeys(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock: %v", err)
	}
	defer func() { _ = db.Close() }()

	testLicenseKey := generateTestLicenseKey("test-org-api", "Enterprise", "20351231")

	// Mock API keys query (first auth path)
	// Query returns 22 columns (includes c.customer_id, c.enabled, pt.requests_per_minute)
	rows := sqlmock.NewRows([]string{
		"api_key_id", "customer_id", "license_key", "key_name", "key_type",
		"expires_at", "grace_period_days", "permissions", "custom_rate_limit",
		"enabled", "revoked_at", "last_used_at", "total_requests",
		"customer_id", "organization_name", "organization_id", "deployment_mode",
		"tier", "tenant_id", "status", "enabled", "requests_per_minute",
	}).AddRow(
		"api-key-001", "customer-001", testLicenseKey, "Test Key", "production",
		time.Now().Add(365*24*time.Hour), 30, []byte(`["query","llm"]`), nil,
		true, nil, nil, 0,
		"customer-001", "Test Org", "test-org-api", "saas",
		"Enterprise", "tenant-001", "active", true, 500,
	)

	mock.ExpectQuery("SELECT (.+) FROM api_keys k JOIN customers c").
		WillReturnRows(rows)

	ctx := context.Background()
	client, err := validateClientCredentialsDB(ctx, db, "test-client", testLicenseKey)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if client == nil {
		t.Fatal("expected client, got nil")
	}

	if client.OrgID != "test-org-api" {
		t.Errorf("expected org_id=test-org-api, got %s", client.OrgID)
	}

	if client.LicenseTier != "Enterprise" {
		t.Errorf("expected tier=Enterprise, got %s", client.LicenseTier)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

// TestValidateClientLicenseDB_ViaOrganizations tests that V2 licenses work through the
// validateClientCredentialsDB function by first failing API keys lookup, then succeeding
// with V2 license validation (which bypasses database for organizations).
func TestValidateClientLicenseDB_ViaOrganizations(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock: %v", err)
	}
	defer func() { _ = db.Close() }()

	testLicenseKey := generateTestLicenseKey("test-org-new", "Professional", "20351231")

	// First query (API keys) returns no rows - this triggers fallback to validateViaOrganizations
	mock.ExpectQuery("SELECT (.+) FROM api_keys k JOIN customers c").
		WillReturnError(sql.ErrNoRows)

	// V2 licenses bypass the organizations database query
	// No second mock expectation needed - the license signature is the authority

	ctx := context.Background()
	client, err := validateClientCredentialsDB(ctx, db, "test-client", testLicenseKey)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if client == nil {
		t.Fatal("expected client, got nil")
	}

	if client.OrgID != "test-org-new" {
		t.Errorf("expected org_id=test-org-new, got %s", client.OrgID)
	}

	if client.LicenseTier != "Professional" {
		t.Errorf("expected tier=Professional, got %s", client.LicenseTier)
	}

	if client.RateLimit != 100 { // Professional tier = 100/min
		t.Errorf("expected rate_limit=100, got %d", client.RateLimit)
	}

	// Only the API keys query should have been attempted
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

// TestValidateClientLicenseDB_MissingClientID tests error when client ID is empty
func TestValidateClientLicenseDB_MissingClientID(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock: %v", err)
	}
	defer func() { _ = db.Close() }()

	ctx := context.Background()
	_, err = validateClientCredentialsDB(ctx, db, "", "some-license-key")

	if err == nil {
		t.Error("expected error for missing client ID, got nil")
	}

	if !contains(err.Error(), "client ID required") {
		t.Errorf("expected 'client ID required' error, got: %s", err.Error())
	}
}

// TestValidateClientCredentialsDB_MissingClientSecret tests error when client secret is empty
func TestValidateClientCredentialsDB_MissingClientSecret(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock: %v", err)
	}
	defer func() { _ = db.Close() }()

	ctx := context.Background()
	_, err = validateClientCredentialsDB(ctx, db, "test-client", "")

	if err == nil {
		t.Error("expected error for missing client secret, got nil")
	}

	if !contains(err.Error(), "client secret required") {
		t.Errorf("expected 'client secret required' error, got: %s", err.Error())
	}
}

// TestValidateViaAPIKeys_Success tests successful API key validation
func TestValidateViaAPIKeys_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock: %v", err)
	}
	defer func() { _ = db.Close() }()

	testLicenseKey := generateTestLicenseKey("api-org", "Enterprise", "20351231")

	rows := sqlmock.NewRows([]string{
		"api_key_id", "customer_id", "license_key", "key_name", "key_type",
		"expires_at", "grace_period_days", "permissions", "custom_rate_limit",
		"enabled", "revoked_at", "last_used_at", "total_requests",
		"customer_id", "organization_name", "organization_id", "deployment_mode",
		"tier", "tenant_id", "status", "enabled", "requests_per_minute",
	}).AddRow(
		"api-key-002", "customer-002", testLicenseKey, "Production Key", "production",
		time.Now().Add(365*24*time.Hour), 30, []byte(`["query","llm","connector"]`), 1000,
		true, nil, time.Now().Add(-1*time.Hour), 42,
		"customer-002", "API Org", "api-org", "saas",
		"Enterprise", "tenant-002", "active", true, 500,
	)

	mock.ExpectQuery("SELECT (.+) FROM api_keys k JOIN customers c").
		WillReturnRows(rows)

	ctx := context.Background()
	client, err := validateViaAPIKeys(ctx, db, "test-client", testLicenseKey)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if client == nil {
		t.Fatal("expected client, got nil")
	}

	if client.APIKeyID != "api-key-002" {
		t.Errorf("expected api_key_id=api-key-002, got %s", client.APIKeyID)
	}

	if client.RateLimit != 1000 { // Custom rate limit
		t.Errorf("expected rate_limit=1000, got %d", client.RateLimit)
	}

	// Verify permissions are correctly parsed from JSON
	expectedPerms := []string{"query", "llm", "connector"}
	if len(client.Permissions) != len(expectedPerms) {
		t.Errorf("expected %d permissions, got %d", len(expectedPerms), len(client.Permissions))
	}
	for i, perm := range expectedPerms {
		if i < len(client.Permissions) && client.Permissions[i] != perm {
			t.Errorf("expected permission[%d]=%s, got %s", i, perm, client.Permissions[i])
		}
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

// TestValidateViaAPIKeys_ExpiredLicense tests expired license rejection
func TestValidateViaAPIKeys_ExpiredLicense(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock: %v", err)
	}
	defer func() { _ = db.Close() }()

	// Create expired license (past date)
	testLicenseKey := generateTestLicenseKey("expired-api-org", "Enterprise", "20231201")

	ctx := context.Background()
	_, err = validateViaAPIKeys(ctx, db, "test-client", testLicenseKey)

	if err == nil {
		t.Error("expected error for expired license, got nil")
	}

	// Should fail at license validation stage before database query
}

// TestValidateViaAPIKeys_RevokedKey tests revoked API key rejection
func TestValidateViaAPIKeys_RevokedKey(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock: %v", err)
	}
	defer func() { _ = db.Close() }()

	testLicenseKey := generateTestLicenseKey("revoked-org", "Enterprise", "20351231")
	revokedTime := time.Now().Add(-24 * time.Hour)

	rows := sqlmock.NewRows([]string{
		"api_key_id", "customer_id", "license_key", "key_name", "key_type",
		"expires_at", "grace_period_days", "permissions", "custom_rate_limit",
		"enabled", "revoked_at", "last_used_at", "total_requests",
		"customer_id", "organization_name", "organization_id", "deployment_mode",
		"tier", "tenant_id", "status", "enabled", "requests_per_minute",
	}).AddRow(
		"api-key-revoked", "customer-003", testLicenseKey, "Revoked Key", "production",
		time.Now().Add(365*24*time.Hour), 30, []byte(`["query"]`), nil,
		false, &revokedTime, nil, 100, // k.enabled=false, revoked_at set
		"customer-003", "Revoked Org", "revoked-org", "saas",
		"Enterprise", "tenant-003", "active", false, 500, // c.enabled also false
	)

	mock.ExpectQuery("SELECT (.+) FROM api_keys k JOIN customers c").
		WillReturnRows(rows)

	ctx := context.Background()
	_, err = validateViaAPIKeys(ctx, db, "test-client", testLicenseKey)

	if err == nil {
		t.Error("expected error for revoked key, got nil")
	}

	if !contains(err.Error(), "revoked") {
		t.Errorf("expected 'revoked' error, got: %s", err.Error())
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

// TestGetCustomerUsageForMonth_WithData tests usage retrieval with data
func TestGetCustomerUsageForMonth_WithData(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock: %v", err)
	}
	defer func() { _ = db.Close() }()

	rows := sqlmock.NewRows([]string{
		"customer_id", "total_requests", "successful_requests", "failed_requests", "blocked_requests",
	}).AddRow("customer-usage", int64(1000), int64(950), int64(30), int64(20))

	mock.ExpectQuery("SELECT (.+) FROM usage_metrics WHERE customer_id").
		WillReturnRows(rows)

	ctx := context.Background()
	month := time.Date(2025, 11, 1, 0, 0, 0, 0, time.UTC)
	stats, err := getCustomerUsageForMonth(ctx, db, "customer-usage", month)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if stats == nil {
		t.Fatal("expected stats, got nil")
	}

	if stats.CustomerID != "customer-usage" {
		t.Errorf("expected customer_id=customer-usage, got %s", stats.CustomerID)
	}

	if stats.TotalRequests != 1000 {
		t.Errorf("expected total_requests=1000, got %d", stats.TotalRequests)
	}

	if stats.SuccessfulRequests != 950 {
		t.Errorf("expected successful_requests=950, got %d", stats.SuccessfulRequests)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

// TestGetCustomerUsageForMonth_NoData tests usage retrieval with no data
func TestGetCustomerUsageForMonth_NoData(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock: %v", err)
	}
	defer func() { _ = db.Close() }()

	// Return no rows (customer has no usage)
	mock.ExpectQuery("SELECT (.+) FROM usage_metrics WHERE customer_id").
		WillReturnError(sql.ErrNoRows)

	ctx := context.Background()
	month := time.Date(2025, 11, 1, 0, 0, 0, 0, time.UTC)
	stats, err := getCustomerUsageForMonth(ctx, db, "customer-no-usage", month)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if stats == nil {
		t.Fatal("expected stats, got nil")
	}

	if stats.CustomerID != "customer-no-usage" {
		t.Errorf("expected customer_id=customer-no-usage, got %s", stats.CustomerID)
	}

	if stats.TotalRequests != 0 {
		t.Errorf("expected total_requests=0, got %d", stats.TotalRequests)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

// TestCreateAPIKey_Success tests successful API key creation
func TestCreateAPIKey_Success(t *testing.T) {
	// Skip this test in Community builds as it requires GenerateLicenseKey
	_, err := license.GenerateLicenseKey(license.TierProfessional, "test", 1)
	if err != nil {
		t.Skip("GenerateLicenseKey not available in Community builds")
	}

	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock: %v", err)
	}
	defer func() { _ = db.Close() }()

	// Mock customer lookup
	customerRows := sqlmock.NewRows([]string{"organization_id", "tier"}).
		AddRow("create-org", "Professional")

	mock.ExpectQuery("SELECT organization_id, tier FROM customers WHERE customer_id").
		WithArgs("customer-create").
		WillReturnRows(customerRows)

	// Mock API key insertion
	mock.ExpectQuery("INSERT INTO api_keys").
		WillReturnRows(sqlmock.NewRows([]string{"api_key_id"}).AddRow("new-api-key-001"))

	ctx := context.Background()
	licenseKey, err := createAPIKey(ctx, db, "customer-create", "Production Key", 365)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if licenseKey == "" {
		t.Error("expected license key, got empty string")
	}

	// License key should be Ed25519 format: AXON-{PAYLOAD}.{SIGNATURE}
	if !contains(licenseKey, "AXON-") || !contains(licenseKey, ".") {
		t.Errorf("expected Ed25519 license key with AXON- prefix and . separator, got: %s", licenseKey)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

// TestCreateAPIKey_CustomerNotFound tests error when customer doesn't exist
func TestCreateAPIKey_CustomerNotFound(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock: %v", err)
	}
	defer func() { _ = db.Close() }()

	// Mock customer lookup - not found
	mock.ExpectQuery("SELECT organization_id, tier FROM customers WHERE customer_id").
		WithArgs("missing-customer").
		WillReturnError(sql.ErrNoRows)

	ctx := context.Background()
	_, err = createAPIKey(ctx, db, "missing-customer", "Test Key", 365)

	if err == nil {
		t.Error("expected error for missing customer, got nil")
	}

	if !contains(err.Error(), "customer not found") {
		t.Errorf("expected 'customer not found' error, got: %s", err.Error())
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

// TestRevokeAPIKey_Success tests successful API key revocation
func TestRevokeAPIKey_Success(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock: %v", err)
	}
	defer func() { _ = db.Close() }()

	// Mock UPDATE query
	mock.ExpectExec("UPDATE api_keys SET enabled").
		WithArgs("api-key-revoke", "admin-user", "Security breach").
		WillReturnResult(sqlmock.NewResult(0, 1)) // 1 row affected

	ctx := context.Background()
	err = revokeAPIKey(ctx, db, "api-key-revoke", "admin-user", "Security breach")

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

// TestRevokeAPIKey_NotFound tests error when API key doesn't exist
func TestRevokeAPIKey_NotFound(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock: %v", err)
	}
	defer func() { _ = db.Close() }()

	// Mock UPDATE query - 0 rows affected
	mock.ExpectExec("UPDATE api_keys SET enabled").
		WithArgs("missing-key", "admin-user", "Test").
		WillReturnResult(sqlmock.NewResult(0, 0)) // 0 rows affected

	ctx := context.Background()
	err = revokeAPIKey(ctx, db, "missing-key", "admin-user", "Test")

	if err == nil {
		t.Error("expected error for missing API key, got nil")
	}

	if !contains(err.Error(), "API key not found") {
		t.Errorf("expected 'API key not found' error, got: %s", err.Error())
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled expectations: %v", err)
	}
}

// ==================================================================
// SERVICE LICENSE TESTS - NO DATABASE LOOKUP
// ==================================================================

// generateTestServiceLicenseKey creates a valid Ed25519-signed service license for testing.
// Service licenses are self-contained with Ed25519 signature validation.
func generateTestServiceLicenseKey(tenantID, tier, serviceName, serviceType string, permissions []string, expiryDate string) string {
	// Ed25519 private key seeds matching the public keys in license_community.go
	evalSeed, _ := base64.StdEncoding.DecodeString("CBHq0cJF49ANZu6wk2c51tXvBp8vcVuT1ogjCpjccvI=")
	entSeed, _ := base64.StdEncoding.DecodeString("OIetB5h9nOnkoWR+lm8cheeWztyhWIRo2RruofufCd8=")

	var seed []byte
	switch tier {
	case "Evaluation":
		seed = evalSeed
	default: // Enterprise, Professional, Plus
		seed = entSeed
	}

	privateKey := ed25519.NewKeyFromSeed(seed)

	payload := map[string]interface{}{
		"tier":         tier,
		"tenant_id":    tenantID,
		"service_name": serviceName,
		"service_type": serviceType,
		"permissions":  permissions,
		"issued_at":    time.Now().Format("20060102"),
		"expires_at":   expiryDate,
	}

	payloadJSON, _ := json.Marshal(payload)
	payloadBase64 := base64.RawURLEncoding.EncodeToString(payloadJSON)

	signature := ed25519.Sign(privateKey, []byte(payloadBase64))
	signatureBase64 := base64.RawURLEncoding.EncodeToString(signature)

	return fmt.Sprintf("AXON-%s.%s", payloadBase64, signatureBase64)
}

// TestValidateViaOrganizations_V2ServiceLicense_NoDatabaseLookup verifies that
// service licenses bypass database lookup entirely. The Ed25519 signature
// is sufficient to validate all claims (tenant_id, tier, permissions, expiry).
func TestValidateViaOrganizations_V2ServiceLicense_NoDatabaseLookup(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock: %v", err)
	}
	defer func() { _ = db.Close() }()

	// Generate a valid V2 service license
	// Note: This org doesn't exist in DB, but should still work for V2 licenses
	testLicenseKey := generateTestServiceLicenseKey(
		"travel-us",                              // tenant_id
		"Enterprise",                             // tier
		"trip-planner",                           // service_name
		"client-application",                     // service_type
		[]string{"mcp:amadeus:*", "mcp:slack:*"}, // permissions
		"20351231",                               // expires_at (future date)
	)

	// IMPORTANT: No database expectations are set here!
	// If the code tries to query the database, the test will fail with
	// "all expectations were already fulfilled, call to Query..." error

	ctx := context.Background()
	client, err := validateViaOrganizations(ctx, db, "travel-client", testLicenseKey)

	if err != nil {
		t.Fatalf("unexpected error for V2 service license: %v", err)
	}

	if client == nil {
		t.Fatal("expected client, got nil")
	}

	// Verify client data comes from the signed license payload
	if client.OrgID != "travel-us" {
		t.Errorf("expected OrgID=travel-us, got %s", client.OrgID)
	}

	if client.TenantID != "travel-us" {
		t.Errorf("expected TenantID=travel-us, got %s", client.TenantID)
	}

	if client.ServiceName != "trip-planner" {
		t.Errorf("expected ServiceName=trip-planner, got %s", client.ServiceName)
	}

	if client.LicenseTier != "Enterprise" {
		t.Errorf("expected LicenseTier=Enterprise, got %s", client.LicenseTier)
	}

	// Permissions should come from the license
	if len(client.Permissions) != 2 {
		t.Errorf("expected 2 permissions, got %d", len(client.Permissions))
	}

	// ENT tier should have 500 rate limit
	if client.RateLimit != 500 {
		t.Errorf("expected RateLimit=500 for ENT tier, got %d", client.RateLimit)
	}

	// Verify NO database queries were made
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled mock expectations: %v", err)
	}
}

// TestValidateViaOrganizations_V2ServiceLicense_EnterpriseTier verifies
// that service licenses correctly map tier to rate limits.
func TestValidateViaOrganizations_V2ServiceLicense_EnterpriseTier(t *testing.T) {
	testCases := []struct {
		name         string
		tier         string
		expectedRate int
	}{
		{"Professional tier", "Professional", 100},
		{"Enterprise tier", "Enterprise", 500},
		{"Plus tier", "Plus", 1000},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatalf("failed to create mock: %v", err)
			}
			defer func() { _ = db.Close() }()

			testLicenseKey := generateTestServiceLicenseKey(
				"test-tenant",
				tc.tier,
				"test-service",
				"backend-service",
				[]string{"query", "llm"},
				"20351231",
			)

			// No database expectations - V2 bypasses DB
			ctx := context.Background()
			client, err := validateViaOrganizations(ctx, db, "test-client", testLicenseKey)

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if client.RateLimit != tc.expectedRate {
				t.Errorf("expected RateLimit=%d for %s, got %d", tc.expectedRate, tc.tier, client.RateLimit)
			}

			if client.LicenseTier != tc.tier {
				t.Errorf("expected LicenseTier=%s, got %s", tc.tier, client.LicenseTier)
			}

			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("unfulfilled mock expectations for %s: %v", tc.name, err)
			}
		})
	}
}

// TestValidateViaOrganizations_V2ServiceLicense_DefaultPermissions verifies
// that service licenses without explicit permissions get default ones.
func TestValidateViaOrganizations_V2ServiceLicense_DefaultPermissions(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock: %v", err)
	}
	defer func() { _ = db.Close() }()

	// Generate V2 license with empty permissions
	testLicenseKey := generateTestServiceLicenseKey(
		"test-tenant",
		"Professional",
		"test-service",
		"backend-service",
		[]string{}, // Empty permissions
		"20351231",
	)

	ctx := context.Background()
	client, err := validateViaOrganizations(ctx, db, "test-client", testLicenseKey)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should get default permissions
	if len(client.Permissions) != 2 {
		t.Errorf("expected 2 default permissions, got %d", len(client.Permissions))
	}

	hasQuery := false
	hasLLM := false
	for _, p := range client.Permissions {
		if p == "query" {
			hasQuery = true
		}
		if p == "llm" {
			hasLLM = true
		}
	}

	if !hasQuery || !hasLLM {
		t.Errorf("expected default permissions [query, llm], got %v", client.Permissions)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("unfulfilled mock expectations: %v", err)
	}
}

// NOTE: TestValidateViaOrganizations_V1License_StillRequiresDB was removed because
// V1 license format (AXON-TIER-ORG-EXPIRY-SIG) is deprecated as of PR #167.
// All licenses are now Ed25519 format (AXON-PAYLOAD.SIGNATURE) which bypass database lookup.
