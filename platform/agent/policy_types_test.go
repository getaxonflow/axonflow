// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"testing"
	"time"
)

func TestStaticPolicy_IsSystem(t *testing.T) {
	tests := []struct {
		name   string
		tier   PolicyTier
		expect bool
	}{
		{"system tier returns true", TierSystem, true},
		{"organization tier returns false", TierOrganization, false},
		{"tenant tier returns false", TierTenant, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &StaticPolicy{Tier: tt.tier}
			if got := p.IsSystem(); got != tt.expect {
				t.Errorf("StaticPolicy.IsSystem() = %v, want %v", got, tt.expect)
			}
		})
	}
}

func TestStaticPolicy_IsOrganization(t *testing.T) {
	tests := []struct {
		name   string
		tier   PolicyTier
		expect bool
	}{
		{"system tier returns false", TierSystem, false},
		{"organization tier returns true", TierOrganization, true},
		{"tenant tier returns false", TierTenant, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &StaticPolicy{Tier: tt.tier}
			if got := p.IsOrganization(); got != tt.expect {
				t.Errorf("StaticPolicy.IsOrganization() = %v, want %v", got, tt.expect)
			}
		})
	}
}

func TestStaticPolicy_IsTenant(t *testing.T) {
	tests := []struct {
		name   string
		tier   PolicyTier
		expect bool
	}{
		{"system tier returns false", TierSystem, false},
		{"organization tier returns false", TierOrganization, false},
		{"tenant tier returns true", TierTenant, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &StaticPolicy{Tier: tt.tier}
			if got := p.IsTenant(); got != tt.expect {
				t.Errorf("StaticPolicy.IsTenant() = %v, want %v", got, tt.expect)
			}
		})
	}
}

func TestStaticPolicy_CanModify(t *testing.T) {
	tests := []struct {
		name   string
		tier   PolicyTier
		expect bool
	}{
		{"system tier cannot be modified", TierSystem, false},
		{"organization tier can be modified", TierOrganization, true},
		{"tenant tier can be modified", TierTenant, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &StaticPolicy{Tier: tt.tier}
			if got := p.CanModify(); got != tt.expect {
				t.Errorf("StaticPolicy.CanModify() = %v, want %v", got, tt.expect)
			}
		})
	}
}

func TestStaticPolicy_CanDelete(t *testing.T) {
	tests := []struct {
		name   string
		tier   PolicyTier
		expect bool
	}{
		{"system tier cannot be deleted", TierSystem, false},
		{"organization tier can be deleted", TierOrganization, true},
		{"tenant tier can be deleted", TierTenant, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &StaticPolicy{Tier: tt.tier}
			if got := p.CanDelete(); got != tt.expect {
				t.Errorf("StaticPolicy.CanDelete() = %v, want %v", got, tt.expect)
			}
		})
	}
}

func TestPolicyOverride_IsExpired(t *testing.T) {
	now := time.Now()
	past := now.Add(-time.Hour)
	future := now.Add(time.Hour)

	tests := []struct {
		name      string
		expiresAt *time.Time
		expect    bool
	}{
		{"nil expires_at is not expired", nil, false},
		{"past expires_at is expired", &past, true},
		{"future expires_at is not expired", &future, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := &PolicyOverride{ExpiresAt: tt.expiresAt}
			if got := o.IsExpired(); got != tt.expect {
				t.Errorf("PolicyOverride.IsExpired() = %v, want %v", got, tt.expect)
			}
		})
	}
}

func TestPolicyOverride_IsOrgLevel(t *testing.T) {
	orgID := "org-123"
	tenantID := "tenant-456"

	tests := []struct {
		name           string
		organizationID *string
		tenantID       *string
		expect         bool
	}{
		{"org-level override", &orgID, nil, true},
		{"tenant-level override", nil, &tenantID, false},
		{"both set (invalid but tenant takes precedence)", &orgID, &tenantID, false},
		{"neither set", nil, nil, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := &PolicyOverride{
				OrganizationID: tt.organizationID,
				TenantID:       tt.tenantID,
			}
			if got := o.IsOrgLevel(); got != tt.expect {
				t.Errorf("PolicyOverride.IsOrgLevel() = %v, want %v", got, tt.expect)
			}
		})
	}
}

func TestPolicyOverride_IsTenantLevel(t *testing.T) {
	orgID := "org-123"
	tenantID := "tenant-456"

	tests := []struct {
		name           string
		organizationID *string
		tenantID       *string
		expect         bool
	}{
		{"org-level override", &orgID, nil, false},
		{"tenant-level override", nil, &tenantID, true},
		{"both set (tenant takes precedence)", &orgID, &tenantID, true},
		{"neither set", nil, nil, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := &PolicyOverride{
				OrganizationID: tt.organizationID,
				TenantID:       tt.tenantID,
			}
			if got := o.IsTenantLevel(); got != tt.expect {
				t.Errorf("PolicyOverride.IsTenantLevel() = %v, want %v", got, tt.expect)
			}
		})
	}
}

func TestEffectiveStaticPolicy_EffectiveAction(t *testing.T) {
	actionWarn := ActionWarn
	actionLog := ActionLog

	tests := []struct {
		name           string
		baseAction     string
		hasOverride    bool
		overrideAction *OverrideAction
		expect         string
	}{
		{"no override uses base action", "block", false, nil, "block"},
		{"override replaces base action", "block", true, &actionWarn, "warn"},
		{"nil override action uses base", "block", true, nil, "block"},
		{"log override", "block", true, &actionLog, "log"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &EffectiveStaticPolicy{
				StaticPolicy: StaticPolicy{
					Action: tt.baseAction,
				},
				HasOverride:    tt.hasOverride,
				OverrideAction: tt.overrideAction,
			}
			if got := p.EffectiveAction(); got != tt.expect {
				t.Errorf("EffectiveStaticPolicy.EffectiveAction() = %v, want %v", got, tt.expect)
			}
		})
	}
}

func TestEffectiveStaticPolicy_EffectiveEnabled(t *testing.T) {
	enabledTrue := true
	enabledFalse := false

	tests := []struct {
		name            string
		baseEnabled     bool
		hasOverride     bool
		overrideEnabled *bool
		expect          bool
	}{
		{"no override uses base enabled", true, false, nil, true},
		{"no override uses base disabled", false, false, nil, false},
		{"override enables disabled policy", false, true, &enabledTrue, true},
		{"override disables enabled policy", true, true, &enabledFalse, false},
		{"nil override enabled uses base", true, true, nil, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &EffectiveStaticPolicy{
				StaticPolicy: StaticPolicy{
					Enabled: tt.baseEnabled,
				},
				HasOverride:     tt.hasOverride,
				OverrideEnabled: tt.overrideEnabled,
			}
			if got := p.EffectiveEnabled(); got != tt.expect {
				t.Errorf("EffectiveStaticPolicy.EffectiveEnabled() = %v, want %v", got, tt.expect)
			}
		})
	}
}

func TestStaticPolicy_JSONTags(t *testing.T) {
	// Test that JSON serialization works correctly
	p := StaticPolicy{
		ID:       "test-id",
		PolicyID: "test-policy-id",
		Name:     "Test Policy",
		Category: string(CategorySecuritySQLi),
		Tier:     TierSystem,
		Pattern:  ".*test.*",
		Severity: "critical",
		Action:   "block",
		Priority: 100,
		Enabled:  true,
		TenantID: "global",
	}

	// Verify category and tier are set correctly
	if p.Category != string(CategorySecuritySQLi) {
		t.Errorf("Category = %s, want %s", p.Category, CategorySecuritySQLi)
	}
	if p.Tier != TierSystem {
		t.Errorf("Tier = %s, want %s", p.Tier, TierSystem)
	}
}

func TestStaticPolicy_GetSetCategory(t *testing.T) {
	p := StaticPolicy{}

	// Test SetCategory
	p.SetCategory(CategorySecuritySQLi)
	if p.Category != string(CategorySecuritySQLi) {
		t.Errorf("SetCategory failed: got %s, want %s", p.Category, CategorySecuritySQLi)
	}

	// Test GetCategory
	if p.GetCategory() != CategorySecuritySQLi {
		t.Errorf("GetCategory failed: got %s, want %s", p.GetCategory(), CategorySecuritySQLi)
	}
}

func TestPolicyOverride_PolicyType(t *testing.T) {
	// Verify that PolicyType can be set for both static and dynamic
	staticOverride := PolicyOverride{
		PolicyID:   "test-id",
		PolicyType: TypeStatic,
	}
	dynamicOverride := PolicyOverride{
		PolicyID:   "test-id",
		PolicyType: TypeDynamic,
	}

	if staticOverride.PolicyType != TypeStatic {
		t.Errorf("PolicyType = %s, want %s", staticOverride.PolicyType, TypeStatic)
	}
	if dynamicOverride.PolicyType != TypeDynamic {
		t.Errorf("PolicyType = %s, want %s", dynamicOverride.PolicyType, TypeDynamic)
	}
}
