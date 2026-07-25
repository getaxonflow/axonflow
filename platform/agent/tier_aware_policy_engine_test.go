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
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestNewTierAwarePolicyEngine(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock db: %v", err)
	}
	defer db.Close()

	tests := []struct {
		name    string
		config  *TierAwarePolicyEngineConfig
		wantTTL time.Duration
	}{
		{
			name:    "nil config uses defaults",
			config:  nil,
			wantTTL: DefaultEffectivePolicyCacheTTL,
		},
		{
			name:    "empty config uses defaults",
			config:  &TierAwarePolicyEngineConfig{},
			wantTTL: DefaultEffectivePolicyCacheTTL,
		},
		{
			name:    "custom TTL",
			config:  &TierAwarePolicyEngineConfig{CacheTTL: 10 * time.Minute},
			wantTTL: 10 * time.Minute,
		},
		{
			name:    "TTL below minimum is clamped",
			config:  &TierAwarePolicyEngineConfig{CacheTTL: 10 * time.Second},
			wantTTL: MinEffectivePolicyCacheTTL,
		},
		{
			name:    "TTL above maximum is clamped",
			config:  &TierAwarePolicyEngineConfig{CacheTTL: 1 * time.Hour},
			wantTTL: MaxEffectivePolicyCacheTTL,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			engine := NewTierAwarePolicyEngine(db, tt.config)

			if engine == nil {
				t.Fatal("expected engine, got nil")
			}
			if engine.db != db {
				t.Error("expected db to be set")
			}
			if engine.policyRepo == nil {
				t.Error("expected policyRepo to be set")
			}
			if engine.cacheTTL != tt.wantTTL {
				t.Errorf("cacheTTL = %v, want %v", engine.cacheTTL, tt.wantTTL)
			}
		})
	}
}


// effectiveCols is StaticPolicyRepository.GetEffective's PER-PASS column list
// (#3048 — the two-pass scoped read carries no override join columns).
func effectiveCols() []string {
	return []string{
		"id", "policy_id", "name", "category", "pattern", "severity",
		"description", "action", "tier", "priority", "enabled",
		"organization_id", "tenant_id", "org_id",
		"tags", "metadata", "version",
		"created_at", "updated_at", "created_by", "updated_by",
	}
}

// emptyOverrideRows is the empty result of GetEffective's pass-A overrides
// fetch.
func emptyOverrideRows() *sqlmock.Rows {
	return sqlmock.NewRows([]string{
		"id", "policy_id", "action_override", "enabled_override", "expires_at", "override_reason",
	})
}

// expectEffectiveTwoPass registers the #3048 GetEffective read shape: pass A
// (caller org scope — tenant/org-tier rows + live overrides) then pass B
// ('global' scope — system-tier rows), each inside a WithOrgScope
// transaction.
func expectEffectiveTwoPass(mock sqlmock.Sqlmock, scopeOrg string, tenantRows, overrideRows, globalRows *sqlmock.Rows) {
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs(scopeOrg).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`SELECT.*FROM static_policies sp`).WillReturnRows(tenantRows)
	mock.ExpectQuery(`SELECT po\.id, po\.policy_id`).WillReturnRows(overrideRows)
	mock.ExpectCommit()
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs(GlobalOrgSentinel).
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`SELECT.*FROM static_policies sp`).WillReturnRows(globalRows)
	mock.ExpectCommit()
}

func TestTierAwarePolicyEngine_GetEffectivePolicies(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock db: %v", err)
	}
	defer db.Close()

	tenantID := "test-tenant"
	testTime := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)

	// Setup mock for GetEffective - this uses a single JOIN query
	// Column order matches StaticPolicyRepository.GetEffective query
	tenantRows := sqlmock.NewRows(effectiveCols()).AddRow(
		"uuid-2", "pii_ssn", "PII SSN Detection", "pii-us", `\d{3}-\d{2}-\d{4}`, "high",
		"Detects SSN patterns", "redact", "tenant", 50, true,
		nil, tenantID, "",
		"[]", "{}", 1,
		testTime, testTime, "user", "user",
	)
	globalRows := sqlmock.NewRows(effectiveCols()).AddRow(
		"uuid-1", "sys_sqli_union", "SQL Injection UNION", "security-sqli", `union\s+select`, "critical",
		"Blocks UNION-based SQL injection", "block", "system", 100, true,
		nil, "global", "",
		"[]", "{}", 1,
		testTime, testTime, "system", "system",
	)
	expectEffectiveTwoPass(mock, tenantID, tenantRows, emptyOverrideRows(), globalRows)

	engine := NewTierAwarePolicyEngine(db, nil)

	// First call - cache miss
	policies, err := engine.GetEffectivePolicies(context.Background(), tenantID, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(policies) != 2 {
		t.Errorf("expected 2 policies, got %d", len(policies))
	}

	// Verify cache stats
	stats := engine.GetCacheStats()
	if stats["total_tenants_cached"].(int) != 1 {
		t.Errorf("expected 1 cached tenant, got %v", stats["total_tenants_cached"])
	}
	if stats["total_policies_cached"].(int) != 2 {
		t.Errorf("expected 2 cached policies, got %v", stats["total_policies_cached"])
	}

	// Second call - should use cache (no new DB calls)
	policies2, err := engine.GetEffectivePolicies(context.Background(), tenantID, nil)
	if err != nil {
		t.Fatalf("unexpected error on cache hit: %v", err)
	}
	if len(policies2) != 2 {
		t.Errorf("expected 2 policies from cache, got %d", len(policies2))
	}
}

func TestTierAwarePolicyEngine_EvaluatePolicy(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock db: %v", err)
	}
	defer db.Close()

	tenantID := "test-tenant"
	testTime := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)

	// Setup mock - uses JOIN query, column order matches StaticPolicyRepository.GetEffective
	tenantRows := sqlmock.NewRows(effectiveCols()).AddRow(
		"uuid-2", "pii_ssn", "PII SSN Detection", "pii-us", `\d{3}-\d{2}-\d{4}`, "high",
		"Detects SSN patterns", "redact", "tenant", 50, true,
		nil, tenantID, "",
		"[]", "{}", 1,
		testTime, testTime, "user", "user",
	)
	globalRows := sqlmock.NewRows(effectiveCols()).AddRow(
		"uuid-1", "sys_sqli_union", "SQL Injection UNION", "security-sqli", `(?i)union\s+select`, "critical",
		"Blocks UNION-based SQL injection", "block", "system", 100, true,
		nil, "global", "",
		"[]", "{}", 1,
		testTime, testTime, "system", "system",
	)
	expectEffectiveTwoPass(mock, tenantID, tenantRows, emptyOverrideRows(), globalRows)

	engine := NewTierAwarePolicyEngine(db, nil)

	tests := []struct {
		name           string
		input          string
		expectMatch    bool
		expectPolicyID string
		expectAction   string
	}{
		{
			name:           "SQL injection detected",
			input:          "SELECT * FROM users UNION SELECT * FROM passwords",
			expectMatch:    true,
			expectPolicyID: "sys_sqli_union",
			expectAction:   "block",
		},
		{
			name:           "SSN detected",
			input:          "My SSN is 123-45-6789",
			expectMatch:    true,
			expectPolicyID: "pii_ssn",
			expectAction:   "redact",
		},
		{
			name:        "No match",
			input:       "Hello world",
			expectMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := engine.EvaluatePolicy(context.Background(), tenantID, nil, tt.input)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if result.Matched != tt.expectMatch {
				t.Errorf("Matched = %v, want %v", result.Matched, tt.expectMatch)
			}

			if tt.expectMatch {
				if result.PolicyID != tt.expectPolicyID {
					t.Errorf("PolicyID = %s, want %s", result.PolicyID, tt.expectPolicyID)
				}
				if result.Action != tt.expectAction {
					t.Errorf("Action = %s, want %s", result.Action, tt.expectAction)
				}
			}

			if result.EvaluationTimeMs < 0 {
				t.Error("expected non-negative evaluation time")
			}
		})
	}
}

func TestTierAwarePolicyEngine_EvaluateAllPolicies(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock db: %v", err)
	}
	defer db.Close()

	tenantID := "test-tenant"
	testTime := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)

	// Both patterns should match - correct column order with override columns
	tenantRows := sqlmock.NewRows(effectiveCols()).AddRow(
		"uuid-2", "pii_phone", "Phone Number Detection", "pii-us", `\d{3}-\d{4}`, "medium",
		"Detects phone numbers", "warn", "tenant", 50, true,
		nil, tenantID, "",
		"[]", "{}", 1,
		testTime, testTime, "user", "user",
	)
	globalRows := sqlmock.NewRows(effectiveCols()).AddRow(
		"uuid-1", "pii_ssn", "PII SSN Detection", "pii-us", `\d{3}-\d{2}-\d{4}`, "high",
		"Detects SSN patterns", "block", "system", 100, true,
		nil, "global", "",
		"[]", "{}", 1,
		testTime, testTime, "system", "system",
	)
	expectEffectiveTwoPass(mock, tenantID, tenantRows, emptyOverrideRows(), globalRows)

	engine := NewTierAwarePolicyEngine(db, nil)

	// Input matches both patterns
	input := "SSN: 123-45-6789, Phone: 555-1234"

	results, err := engine.EvaluateAllPolicies(context.Background(), tenantID, nil, input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(results.Matches) != 2 {
		t.Errorf("expected 2 matches, got %d", len(results.Matches))
	}

	if !results.ShouldBlock {
		t.Error("expected ShouldBlock to be true (one policy has action=block)")
	}

	if results.HighestSeverity != "high" {
		t.Errorf("HighestSeverity = %s, want high", results.HighestSeverity)
	}

	if results.Checked != 2 {
		t.Errorf("Checked = %d, want 2", results.Checked)
	}
}

func TestTierAwarePolicyEngine_InvalidateCache(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock db: %v", err)
	}
	defer db.Close()

	tenantID := "test-tenant"
	testTime := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)

	// First call - correct column order with override columns
	tenantRows := sqlmock.NewRows(effectiveCols())
	globalRows := sqlmock.NewRows(effectiveCols()).AddRow(
		"uuid-1", "test_policy", "Test Policy", "security-sqli", `test`, "medium",
		"Test", "block", "system", 100, true,
		nil, "global", "",
		"[]", "{}", 1,
		testTime, testTime, "system", "system",
	)
	expectEffectiveTwoPass(mock, tenantID, tenantRows, emptyOverrideRows(), globalRows)

	engine := NewTierAwarePolicyEngine(db, nil)

	// First call - cache miss
	_, err = engine.GetEffectivePolicies(context.Background(), tenantID, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	stats := engine.GetCacheStats()
	if stats["total_tenants_cached"].(int) != 1 {
		t.Error("expected cache to have 1 tenant")
	}

	// Invalidate cache for tenant
	engine.InvalidateCache(tenantID, nil)

	stats = engine.GetCacheStats()
	if stats["total_tenants_cached"].(int) != 0 {
		t.Error("expected cache to be empty after invalidation")
	}
}

func TestTierAwarePolicyEngine_InvalidateAllCaches(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock db: %v", err)
	}
	defer db.Close()

	engine := NewTierAwarePolicyEngine(db, nil)

	// Manually add some cache entries
	engine.cacheMutex.Lock()
	engine.policyCache["tenant1"] = &tenantPolicyCache{}
	engine.policyCache["tenant2"] = &tenantPolicyCache{}
	engine.cacheMutex.Unlock()

	stats := engine.GetCacheStats()
	if stats["total_tenants_cached"].(int) != 2 {
		t.Error("expected 2 cached tenants")
	}

	engine.InvalidateAllCaches()

	stats = engine.GetCacheStats()
	if stats["total_tenants_cached"].(int) != 0 {
		t.Error("expected empty cache after invalidation")
	}
}

func TestTierAwarePolicyEngine_GetCacheStats(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock db: %v", err)
	}
	defer db.Close()

	engine := NewTierAwarePolicyEngine(db, &TierAwarePolicyEngineConfig{
		CacheTTL: 10 * time.Minute,
	})

	stats := engine.GetCacheStats()

	if _, ok := stats["total_tenants_cached"]; !ok {
		t.Error("expected total_tenants_cached in stats")
	}
	if _, ok := stats["cache_ttl_seconds"]; !ok {
		t.Error("expected cache_ttl_seconds in stats")
	}
	if stats["cache_ttl_seconds"].(float64) != 600 {
		t.Errorf("cache_ttl_seconds = %v, want 600", stats["cache_ttl_seconds"])
	}
}

func TestSortPoliciesByTierAndPriority(t *testing.T) {
	policies := []EffectiveStaticPolicy{
		{StaticPolicy: StaticPolicy{PolicyID: "tenant-low", Tier: TierTenant, Priority: 10}},
		{StaticPolicy: StaticPolicy{PolicyID: "system-high", Tier: TierSystem, Priority: 100}},
		{StaticPolicy: StaticPolicy{PolicyID: "org-mid", Tier: TierOrganization, Priority: 50}},
		{StaticPolicy: StaticPolicy{PolicyID: "system-low", Tier: TierSystem, Priority: 50}},
		{StaticPolicy: StaticPolicy{PolicyID: "tenant-high", Tier: TierTenant, Priority: 100}},
	}

	sortPoliciesByTierAndPriority(policies)

	// System tier should come first, then Organization, then Tenant
	// Within each tier, higher priority should come first
	expected := []string{"system-high", "system-low", "org-mid", "tenant-high", "tenant-low"}

	for i, p := range policies {
		if p.PolicyID != expected[i] {
			t.Errorf("position %d: got %s, want %s", i, p.PolicyID, expected[i])
		}
	}
}

func TestCompareSeverity(t *testing.T) {
	tests := []struct {
		a, b   string
		expect int
	}{
		{"critical", "high", 1},
		{"high", "critical", -1},
		{"high", "high", 0},
		{"low", "critical", -3},
		{"medium", "low", 1},
	}

	for _, tt := range tests {
		result := compareSeverity(tt.a, tt.b)
		if (tt.expect > 0 && result <= 0) ||
			(tt.expect < 0 && result >= 0) ||
			(tt.expect == 0 && result != 0) {
			t.Errorf("compareSeverity(%s, %s) = %d, want sign of %d", tt.a, tt.b, result, tt.expect)
		}
	}
}

func TestBuildCacheKey(t *testing.T) {
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock db: %v", err)
	}
	defer db.Close()

	engine := NewTierAwarePolicyEngine(db, nil)

	tests := []struct {
		tenantID string
		orgID    *string
		expected string
	}{
		{"tenant1", nil, "tenant1"},
		{"tenant1", strPtr(""), "tenant1"},
		{"tenant1", strPtr("org1"), "tenant1:org1"},
	}

	for _, tt := range tests {
		result := engine.buildCacheKey(tt.tenantID, tt.orgID)
		if result != tt.expected {
			t.Errorf("buildCacheKey(%s, %v) = %s, want %s", tt.tenantID, tt.orgID, result, tt.expected)
		}
	}
}

// strPtr helper is defined in static_policy_repository_test.go

// TestTierAwarePolicyEngine_EvaluatePolicy_RequireApproval tests that the require_approval
// action is correctly returned by the policy engine for HITL enforcement (#1081)
func TestTierAwarePolicyEngine_EvaluatePolicy_RequireApproval(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock db: %v", err)
	}
	defer db.Close()

	tenantID := "test-tenant"
	testTime := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)

	// Setup mock with a require_approval policy (HITL)
	tenantRows := sqlmock.NewRows(effectiveCols()).AddRow(
		"uuid-hitl", "hitl_credit_scoring", "Credit Scoring HITL", "sensitive-data", `(?i)credit\s*scor`, "critical",
		"Requires human approval for credit scoring decisions", "require_approval", "tenant", 100, true,
		nil, tenantID, "",
		"[]", "{}", 1,
		testTime, testTime, "admin", "admin",
	)
	globalRows := sqlmock.NewRows(effectiveCols())
	expectEffectiveTwoPass(mock, tenantID, tenantRows, emptyOverrideRows(), globalRows)

	engine := NewTierAwarePolicyEngine(db, nil)

	tests := []struct {
		name           string
		input          string
		expectMatch    bool
		expectPolicyID string
		expectAction   string
	}{
		{
			name:           "Credit scoring triggers HITL",
			input:          "Calculate credit score for loan applicant",
			expectMatch:    true,
			expectPolicyID: "hitl_credit_scoring",
			expectAction:   "require_approval",
		},
		{
			name:           "Credit scoring with different case triggers HITL",
			input:          "Please calculate CREDIT SCORING for this customer",
			expectMatch:    true,
			expectPolicyID: "hitl_credit_scoring",
			expectAction:   "require_approval",
		},
		{
			name:        "Non-matching query passes through",
			input:       "What is the weather today?",
			expectMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := engine.EvaluatePolicy(context.Background(), tenantID, nil, tt.input)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if result.Matched != tt.expectMatch {
				t.Errorf("Matched = %v, want %v", result.Matched, tt.expectMatch)
			}

			if tt.expectMatch {
				if result.PolicyID != tt.expectPolicyID {
					t.Errorf("PolicyID = %s, want %s", result.PolicyID, tt.expectPolicyID)
				}
				if result.Action != tt.expectAction {
					t.Errorf("Action = %s, want %s", result.Action, tt.expectAction)
				}
			}
		})
	}
}


// TestTierAwarePolicyEngine_GetEffectivePoliciesByCategory tests filtering by category
func TestTierAwarePolicyEngine_GetEffectivePoliciesByCategory(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock db: %v", err)
	}
	defer db.Close()

	tenantID := "test-tenant"
	testTime := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)

	// Setup mock with multiple categories
	tenantRows := sqlmock.NewRows(effectiveCols()).AddRow(
		"uuid-2", "pii_policy", "PII SSN", "pii-us", `\d{3}-\d{2}-\d{4}`, "high",
		"Detects SSN", "redact", "tenant", 50, true,
		nil, tenantID, "",
		"[]", "{}", 1,
		testTime, testTime, "user", "user",
	)
	globalRows := sqlmock.NewRows(effectiveCols()).AddRow(
		"uuid-1", "sqli_policy", "SQL Injection", "security-sqli", `union\s+select`, "critical",
		"Blocks UNION-based SQL injection", "block", "system", 100, true,
		nil, "global", "",
		"[]", "{}", 1,
		testTime, testTime, "system", "system",
	)
	expectEffectiveTwoPass(mock, tenantID, tenantRows, emptyOverrideRows(), globalRows)

	engine := NewTierAwarePolicyEngine(db, nil)

	// Get policies by security-sqli category
	policies, err := engine.GetEffectivePoliciesByCategory(context.Background(), tenantID, nil, "security-sqli")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(policies) != 1 {
		t.Errorf("expected 1 policy for security-sqli category, got %d", len(policies))
	}
	if len(policies) > 0 && policies[0].PolicyID != "sqli_policy" {
		t.Errorf("expected sqli_policy, got %s", policies[0].PolicyID)
	}

	// Get policies by pii-us category (should use cache)
	piiPolicies, err := engine.GetEffectivePoliciesByCategory(context.Background(), tenantID, nil, "pii-us")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(piiPolicies) != 1 {
		t.Errorf("expected 1 policy for pii-us category, got %d", len(piiPolicies))
	}
}

// TestTierAwarePolicyEngine_GetEffectivePoliciesByTier tests filtering by tier
func TestTierAwarePolicyEngine_GetEffectivePoliciesByTier(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create mock db: %v", err)
	}
	defer db.Close()

	tenantID := "test-tenant"
	testTime := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)

	// Setup mock with multiple tiers
	tenantRows := sqlmock.NewRows(effectiveCols()).AddRow(
		"uuid-2", "tenant_policy", "Tenant Policy", "pii-us", `\d{3}-\d{2}-\d{4}`, "high",
		"Tenant-level policy", "redact", "tenant", 50, true,
		nil, tenantID, "",
		"[]", "{}", 1,
		testTime, testTime, "user", "user",
	)
	globalRows := sqlmock.NewRows(effectiveCols()).AddRow(
		"uuid-1", "system_policy", "System Policy", "security-sqli", `union\s+select`, "critical",
		"System-level policy", "block", "system", 100, true,
		nil, "global", "",
		"[]", "{}", 1,
		testTime, testTime, "system", "system",
	)
	expectEffectiveTwoPass(mock, tenantID, tenantRows, emptyOverrideRows(), globalRows)

	engine := NewTierAwarePolicyEngine(db, nil)

	// Get policies by system tier
	systemPolicies, err := engine.GetEffectivePoliciesByTier(context.Background(), tenantID, nil, TierSystem)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(systemPolicies) != 1 {
		t.Errorf("expected 1 system tier policy, got %d", len(systemPolicies))
	}
	if len(systemPolicies) > 0 && systemPolicies[0].PolicyID != "system_policy" {
		t.Errorf("expected system_policy, got %s", systemPolicies[0].PolicyID)
	}

	// Get policies by tenant tier (should use cache)
	tenantPolicies, err := engine.GetEffectivePoliciesByTier(context.Background(), tenantID, nil, TierTenant)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(tenantPolicies) != 1 {
		t.Errorf("expected 1 tenant tier policy, got %d", len(tenantPolicies))
	}
}
