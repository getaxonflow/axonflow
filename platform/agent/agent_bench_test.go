// Copyright 2025 AxonFlow
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
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
	"database/sql"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

// =============================================================================
// Benchmark Tests for Agent Critical Path Functions
// =============================================================================
//
// These benchmarks measure performance of the hottest code paths in the agent:
// 1. Static policy evaluation (every request)
// 2. Database authentication (every request)
// 3. Pattern matching (multiple times per request)
//
// Run with: go test -bench=. -benchmem
// =============================================================================

// BenchmarkEvaluateStaticPolicies_SimpleQuery benchmarks static policy evaluation
// for a simple, safe query (best case - no policy violations)
func BenchmarkEvaluateStaticPolicies_SimpleQuery(b *testing.B) {
	engine := NewStaticPolicyEngine()
	user := &User{
		Email:       "test@example.com",
		Name:        "Test User",
		Role:        "user",
		Permissions: []string{"read"},
	}
	query := "SELECT * FROM orders WHERE customer_id = 'cust123'"
	requestType := "sql"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result := engine.EvaluateStaticPolicies(user, query, requestType)
		if result.Blocked {
			b.Fatalf("Expected query to pass, but was blocked: %s", result.Reason)
		}
	}
}

// BenchmarkEvaluateStaticPolicies_SQLInjection benchmarks static policy evaluation
// when SQL injection is detected (worst case - immediate blocking)
func BenchmarkEvaluateStaticPolicies_SQLInjection(b *testing.B) {
	engine := NewStaticPolicyEngine()
	user := &User{
		Email:       "test@example.com",
		Name:        "Test User",
		Role:        "user",
		Permissions: []string{"read"},
	}
	query := "SELECT * FROM users WHERE id = '1' OR '1'='1'"
	requestType := "sql"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result := engine.EvaluateStaticPolicies(user, query, requestType)
		if !result.Blocked {
			b.Fatal("Expected SQL injection to be blocked")
		}
	}
}

// BenchmarkEvaluateStaticPolicies_AdminQuery benchmarks static policy evaluation
// for admin-level queries (permission check path)
func BenchmarkEvaluateStaticPolicies_AdminQuery(b *testing.B) {
	engine := NewStaticPolicyEngine()
	user := &User{
		Email:       "admin@example.com",
		Name:        "Admin User",
		Role:        "admin",
		Permissions: []string{"read", "write", "admin"},
	}
	query := "SELECT * FROM pg_stat_activity"
	requestType := "sql"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result := engine.EvaluateStaticPolicies(user, query, requestType)
		if result.Blocked {
			b.Fatalf("Expected admin query to pass, but was blocked: %s", result.Reason)
		}
	}
}

// BenchmarkEvaluateStaticPolicies_PIIDetection benchmarks static policy evaluation
// when PII is detected (triggers redaction but doesn't block)
func BenchmarkEvaluateStaticPolicies_PIIDetection(b *testing.B) {
	engine := NewStaticPolicyEngine()
	user := &User{
		Email:       "test@example.com",
		Name:        "Test User",
		Role:        "user",
		Permissions: []string{"read"},
	}
	query := "Book a flight for John Doe, passport number AB123456"
	requestType := "planning"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result := engine.EvaluateStaticPolicies(user, query, requestType)
		// PII detection should not block for planning requests
		if result.Blocked {
			b.Fatalf("Expected PII query to pass with redaction, but was blocked: %s", result.Reason)
		}
	}
}

// BenchmarkCheckPatterns_NoMatch benchmarks pattern matching when no patterns match
// This represents the common case for legitimate queries
func BenchmarkCheckPatterns_NoMatch(b *testing.B) {
	engine := NewStaticPolicyEngine()
	query := "select name, email from users where id = 123"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result := engine.checkPatterns(query, engine.sqlInjectionPatterns)
		if result != nil {
			b.Fatal("Expected no pattern match for legitimate query")
		}
	}
}

// BenchmarkCheckPatterns_FirstMatch benchmarks pattern matching when first pattern matches
// This represents the best case for malicious query detection
func BenchmarkCheckPatterns_FirstMatch(b *testing.B) {
	engine := NewStaticPolicyEngine()
	query := "select * from users where 1=1 or 1=1"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result := engine.checkPatterns(query, engine.sqlInjectionPatterns)
		if result == nil {
			b.Fatal("Expected SQL injection pattern to match")
		}
	}
}

// BenchmarkCheckPatterns_LastMatch benchmarks pattern matching when last pattern matches
// This represents the worst case for pattern matching (scans all patterns)
func BenchmarkCheckPatterns_LastMatch(b *testing.B) {
	engine := NewStaticPolicyEngine()
	// Use a query that triggers a less common pattern (later in the list)
	query := "drop database production"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result := engine.checkPatterns(query, engine.dangerousQueryPatterns)
		if result == nil {
			b.Fatal("Expected dangerous query pattern to match")
		}
	}
}

// BenchmarkValidateClientLicenseDB_APIKeys benchmarks database authentication
// via the API keys path (legacy authentication)
func BenchmarkValidateClientLicenseDB_APIKeys(b *testing.B) {
	// Create mock database
	db, mock, err := sqlmock.New()
	if err != nil {
		b.Fatalf("Failed to create mock database: %v", err)
	}
	defer func() { _ = db.Close() }()

	// Set up expected query and response
	clientID := "test-client"
	licenseKey := "AXON-ENT-testorg-20251118-abc123"

	rows := sqlmock.NewRows([]string{
		"api_key_id", "customer_id", "license_key", "key_name", "key_type",
		"expires_at", "grace_period_days", "permissions", "custom_rate_limit",
		"enabled", "revoked_at", "last_used_at", "total_requests",
		"customer_id", "organization_name", "organization_id", "deployment_mode",
		"tier", "tenant_id", "status", "enabled", "requests_per_minute",
	}).AddRow(
		"api-key-1", "cust-1", licenseKey, "Test Key", "production",
		time.Now().Add(365*24*time.Hour), 7, []byte(`["read", "write"]`), nil,
		true, nil, nil, int64(1000),
		"cust-1", "Test Org", "testorg", "in-vpc",
		"ENT", "tenant-1", "active", true, 1000,
	)

	// Expect the query to be called
	mock.ExpectQuery("SELECT (.+) FROM api_keys k").
		WithArgs(sqlmock.AnyArg()).
		WillReturnRows(rows)

	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		// Reset mock expectations for each iteration
		mock.ExpectQuery("SELECT (.+) FROM api_keys k").
			WithArgs(sqlmock.AnyArg()).
			WillReturnRows(rows)
		b.StartTimer()

		client, err := validateClientLicenseDB(ctx, db, clientID, licenseKey)
		if err != nil {
			b.Fatalf("Expected successful validation, got error: %v", err)
		}
		if client == nil {
			b.Fatal("Expected client to be returned")
		}
	}
}

// BenchmarkValidateClientLicenseDB_Organizations benchmarks database authentication
// via the organizations path (new authentication method)
func BenchmarkValidateClientLicenseDB_Organizations(b *testing.B) {
	// Create mock database
	db, mock, err := sqlmock.New()
	if err != nil {
		b.Fatalf("Failed to create mock database: %v", err)
	}
	defer func() { _ = db.Close() }()

	clientID := "test-org"
	licenseKey := "AXON-ENT-testorg-20251118-abc123"

	// First query (API keys) will fail
	mock.ExpectQuery("SELECT (.+) FROM api_keys k").
		WithArgs(sqlmock.AnyArg()).
		WillReturnError(sql.ErrNoRows)

	// Second query (organizations) will succeed
	rows := sqlmock.NewRows([]string{
		"org_id", "org_name", "license_key", "tier", "max_nodes",
		"expires_at", "grace_period_days", "enabled", "status",
		"requests_per_minute", "deployment_mode",
	}).AddRow(
		"testorg", "Test Organization", licenseKey, "ENT", 50,
		time.Now().Add(365*24*time.Hour), 7, true, "active",
		1000, "in-vpc",
	)

	mock.ExpectQuery("SELECT (.+) FROM organizations o").
		WithArgs(sqlmock.AnyArg()).
		WillReturnRows(rows)

	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		// Reset mock expectations for each iteration
		mock.ExpectQuery("SELECT (.+) FROM api_keys k").
			WithArgs(sqlmock.AnyArg()).
			WillReturnError(sql.ErrNoRows)
		mock.ExpectQuery("SELECT (.+) FROM organizations o").
			WithArgs(sqlmock.AnyArg()).
			WillReturnRows(rows)
		b.StartTimer()

		client, err := validateClientLicenseDB(ctx, db, clientID, licenseKey)
		if err != nil {
			b.Fatalf("Expected successful validation, got error: %v", err)
		}
		if client == nil {
			b.Fatal("Expected client to be returned")
		}
	}
}

// BenchmarkHasPermission benchmarks permission checking (called for every admin query)
func BenchmarkHasPermission(b *testing.B) {
	engine := NewStaticPolicyEngine()
	user := &User{
		Email:       "admin@example.com",
		Name:        "Admin User",
		Role:        "admin",
		Permissions: []string{"read", "write", "admin", "delete", "create"},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		hasAdminPerm := engine.hasPermission(user, "admin")
		if !hasAdminPerm {
			b.Fatal("Expected user to have admin permission")
		}
	}
}

// BenchmarkIsValidRequestType benchmarks request type validation
func BenchmarkIsValidRequestType(b *testing.B) {
	engine := NewStaticPolicyEngine()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		isValid := engine.isValidRequestType("sql")
		if !isValid {
			b.Fatal("Expected 'sql' to be a valid request type")
		}
	}
}

// BenchmarkDetectPII benchmarks PII detection across different input types
func BenchmarkDetectPII_NoDetection(b *testing.B) {
	engine := NewStaticPolicyEngine()
	query := "Book a flight from New York to London for next Monday"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result := engine.checkPatterns(query, engine.piiPatterns)
		// No PII in this query
		_ = result
	}
}

func BenchmarkDetectPII_PassportDetection(b *testing.B) {
	engine := NewStaticPolicyEngine()
	query := "Book a flight for John Doe, passport AB123456"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result := engine.checkPatterns(query, engine.piiPatterns)
		// Should detect passport number
		_ = result
	}
}

// BenchmarkFullRequestPath benchmarks the complete authentication + policy evaluation path
// This represents the actual overhead added by the agent to every request
func BenchmarkFullRequestPath(b *testing.B) {
	// Create mock database
	db, mock, err := sqlmock.New()
	if err != nil {
		b.Fatalf("Failed to create mock database: %v", err)
	}
	defer func() { _ = db.Close() }()

	// Setup static policy engine
	engine := NewStaticPolicyEngine()

	// Setup authentication mock
	clientID := "test-client"
	licenseKey := "AXON-ENT-testorg-20251118-abc123"
	query := "SELECT * FROM orders WHERE customer_id = 'cust123'"

	rows := sqlmock.NewRows([]string{
		"api_key_id", "customer_id", "license_key", "key_name", "key_type",
		"expires_at", "grace_period_days", "permissions", "custom_rate_limit",
		"enabled", "revoked_at", "last_used_at", "total_requests",
		"customer_id", "organization_name", "organization_id", "deployment_mode",
		"tier", "tenant_id", "status", "enabled", "requests_per_minute",
	}).AddRow(
		"api-key-1", "cust-1", licenseKey, "Test Key", "production",
		time.Now().Add(365*24*time.Hour), 7, []byte(`["read", "write"]`), nil,
		true, nil, nil, int64(1000),
		"cust-1", "Test Org", "testorg", "in-vpc",
		"ENT", "tenant-1", "active", true, 1000,
	)

	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		mock.ExpectQuery("SELECT (.+) FROM api_keys k").
			WithArgs(sqlmock.AnyArg()).
			WillReturnRows(rows)
		b.StartTimer()

		// 1. Authenticate client (database lookup)
		client, err := validateClientLicenseDB(ctx, db, clientID, licenseKey)
		if err != nil {
			b.Fatalf("Authentication failed: %v", err)
		}

		// 2. Evaluate static policies
		user := &User{
			Name:        client.Name,
			Email:       "test@example.com",
			Role:        "user",
			Permissions: []string{"read"},
		}
		result := engine.EvaluateStaticPolicies(user, query, "sql")
		if result.Blocked {
			b.Fatalf("Query was blocked: %s", result.Reason)
		}
	}
}
