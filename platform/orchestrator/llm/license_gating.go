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

package llm

import (
	"context"
	"fmt"
	"sync"

	"axonflow/platform/agent/license"
)

// providerTierRequirement maps provider types to their minimum required tier.
// Community-available providers require Community tier (no license needed).
// Enterprise providers require at least Professional tier.
var providerTierRequirement = map[ProviderType]license.Tier{
	// Community providers - available without license
	ProviderTypeOllama:      license.TierCommunity,
	ProviderTypeOpenAI:      license.TierCommunity,
	ProviderTypeAnthropic:   license.TierCommunity,
	ProviderTypeGemini:      license.TierCommunity,      // Gemini available in Community edition
	ProviderTypeAzureOpenAI: license.TierCommunity,      // Azure OpenAI available in Community edition

	// Enterprise providers - require license
	ProviderTypeBedrock: license.TierProfessional,
	ProviderTypeCustom:  license.TierProfessional,
}

// LicenseValidator defines the interface for license validation.
// This allows different implementations for Community and Enterprise builds.
type LicenseValidator interface {
	// GetCurrentTier returns the current license tier.
	GetCurrentTier(ctx context.Context) license.Tier

	// IsProviderAllowed checks if a provider type is allowed by the current license.
	IsProviderAllowed(ctx context.Context, providerType ProviderType) bool

	// ValidateLicense validates and caches the license result.
	ValidateLicense(ctx context.Context, licenseKey string) error

	// GetFeatures returns available features for the current tier.
	GetFeatures() map[string]bool
}

// LicenseError represents an error related to license validation.
type LicenseError struct {
	ProviderType ProviderType
	RequiredTier license.Tier
	CurrentTier  license.Tier
	Message      string
}

func (e *LicenseError) Error() string {
	if e.ProviderType != "" {
		return fmt.Sprintf("license error: provider %q requires %s tier (current: %s) - %s",
			e.ProviderType, e.RequiredTier, e.CurrentTier, e.Message)
	}
	return fmt.Sprintf("license error: %s", e.Message)
}

// CommunityLicenseValidator is the default validator for Community builds.
// It allows only Community-tier providers and doesn't require a license key.
type CommunityLicenseValidator struct {
	mu       sync.RWMutex
	tier     license.Tier
	features map[string]bool
}

// NewCommunityLicenseValidator creates a new Community license validator.
func NewCommunityLicenseValidator() *CommunityLicenseValidator {
	return &CommunityLicenseValidator{
		tier: license.TierCommunity,
		features: map[string]bool{
			"multi_provider":        true,  // Community supports multiple providers
			"load_balancing":        true,  // Basic load balancing
			"health_checks":         true,  // Provider health monitoring
			"bedrock_provider":      false, // Enterprise only
			"gemini_provider":       true,  // Community supports Gemini
			"azure_openai_provider": true,  // Community supports Azure OpenAI
			"custom_providers":      false, // Enterprise only
			"advanced_routing":      false, // Enterprise only
			"provider_priority":     false, // Enterprise only
			"cost_optimization":     false, // Enterprise only
			"dedicated_support":     false, // Enterprise only
			"sla_guarantee":         false, // Enterprise only
			"audit_logging":         true,  // Community includes basic audit
			"metrics_collection":    true,  // Community includes basic metrics
			"advanced_metrics":      false, // Enterprise only
			"provider_rate_limits":  false, // Enterprise only
		},
	}
}

// GetCurrentTier returns the Community tier.
func (v *CommunityLicenseValidator) GetCurrentTier(ctx context.Context) license.Tier {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.tier
}

// IsProviderAllowed checks if a provider is allowed in Community mode.
func (v *CommunityLicenseValidator) IsProviderAllowed(ctx context.Context, providerType ProviderType) bool {
	requiredTier, exists := providerTierRequirement[providerType]
	if !exists {
		// Unknown provider type defaults to requiring Professional tier
		return false
	}
	return requiredTier == license.TierCommunity
}

// ValidateLicense is a no-op in Community mode.
// Community edition doesn't require a license key.
func (v *CommunityLicenseValidator) ValidateLicense(ctx context.Context, licenseKey string) error {
	// Community builds don't validate licenses
	return nil
}

// GetFeatures returns the features available in Community mode.
func (v *CommunityLicenseValidator) GetFeatures() map[string]bool {
	v.mu.RLock()
	defer v.mu.RUnlock()

	// Return a copy to prevent modification
	features := make(map[string]bool)
	for k, val := range v.features {
		features[k] = val
	}
	return features
}

// GetTierForProvider returns the minimum tier required for a provider type.
func GetTierForProvider(providerType ProviderType) license.Tier {
	tier, exists := providerTierRequirement[providerType]
	if !exists {
		return license.TierProfessional // Unknown providers require license
	}
	return tier
}

// IsCommunityProvider returns true if the provider is available in Community mode.
func IsCommunityProvider(providerType ProviderType) bool {
	return GetTierForProvider(providerType) == license.TierCommunity
}

// GetCommunityProviders returns a list of providers available in Community mode.
func GetCommunityProviders() []ProviderType {
	var providers []ProviderType
	for pt, tier := range providerTierRequirement {
		if tier == license.TierCommunity {
			providers = append(providers, pt)
		}
	}
	return providers
}

// GetEnterpriseProviders returns a list of providers that require a license.
func GetEnterpriseProviders() []ProviderType {
	var providers []ProviderType
	for pt, tier := range providerTierRequirement {
		if tier != license.TierCommunity {
			providers = append(providers, pt)
		}
	}
	return providers
}

// DefaultValidator is the global license validator instance.
// In Community builds, this is a CommunityLicenseValidator.
// In Enterprise builds, this is replaced with EnterpriseLicenseValidator.
var DefaultValidator LicenseValidator = NewCommunityLicenseValidator()

// SetDefaultValidator allows replacing the default validator.
// This is primarily used in Enterprise builds to inject the enterprise validator.
func SetDefaultValidator(v LicenseValidator) {
	DefaultValidator = v
}

// ValidateProviderAccess is a convenience function to check if a provider can be used.
func ValidateProviderAccess(ctx context.Context, providerType ProviderType) error {
	if DefaultValidator.IsProviderAllowed(ctx, providerType) {
		return nil
	}

	currentTier := DefaultValidator.GetCurrentTier(ctx)
	requiredTier := GetTierForProvider(providerType)

	return &LicenseError{
		ProviderType: providerType,
		RequiredTier: requiredTier,
		CurrentTier:  currentTier,
		Message:      fmt.Sprintf("upgrade to %s tier to use %s provider - visit https://getaxonflow.com/enterprise", requiredTier, providerType),
	}
}
