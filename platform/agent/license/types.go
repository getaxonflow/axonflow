//go:build enterprise

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

package license

import (
	"strings"
	"time"
)

// LicenseKey represents a parsed and validated AxonFlow license key
// Supports both regular organization licenses and service identity licenses
type LicenseKey struct {
	// Core license fields
	KeyID     string    `json:"key_id"`
	OrgID     string    `json:"org_id"`     // Organization ID (e.g., "travel-eu", "healthcare-eu")
	Tier      Tier      `json:"tier"`        // License tier (Professional, Enterprise, Plus)
	IssuedAt  time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"`
	Signature string    `json:"signature"` // Ed25519 signature for validation

	// Service identity fields (optional - only present for service licenses)
	ServiceName string   `json:"service_name,omitempty"` // e.g., "trip-planner", "booking-api"
	ServiceType string   `json:"service_type,omitempty"` // "client-application", "backend-service", "integration"
	Permissions []string `json:"permissions,omitempty"`  // e.g., ["mcp:amadeus:search_flights", "mcp:slack:*"]

	// Validation metadata
	MaxNodes        int             `json:"max_nodes"`
	DaysUntilExpiry int             `json:"days_until_expiry"`
	Features        map[string]bool `json:"features"`
}

// IsServiceLicense returns true if this is a service identity license
func (k *LicenseKey) IsServiceLicense() bool {
	return k.ServiceName != ""
}

// HasPermission checks if this license has a specific permission
// Supports exact match, wildcard connector (mcp:amadeus:*), and global wildcard (mcp:*)
//
// Permission format: "resource:connector:operation"
// Examples:
//   - "mcp:amadeus:search_flights" - Specific operation
//   - "mcp:amadeus:*" - All Amadeus operations
//   - "mcp:*" - All MCP operations (admin)
//
// Returns true if the license has the requested permission
func (k *LicenseKey) HasPermission(permission string) bool {
	// Non-service licenses have no permissions
	if !k.IsServiceLicense() {
		return false
	}

	// Empty permission list = no permissions
	if len(k.Permissions) == 0 {
		return false
	}

	// Check each permission in the license
	for _, p := range k.Permissions {
		// Exact match
		if p == permission {
			return true
		}

		// Global wildcard: "mcp:*" or "*"
		if p == "*" || p == "mcp:*" {
			return true
		}

		// Wildcard connector: "mcp:amadeus:*" matches "mcp:amadeus:search_flights"
		if strings.HasSuffix(p, ":*") {
			prefix := strings.TrimSuffix(p, "*")
			if strings.HasPrefix(permission, prefix) {
				return true
			}
		}

		// Wildcard operation: "mcp:*:search_flights" matches "mcp:amadeus:search_flights"
		// Not commonly used, but supported for flexibility
		if strings.Contains(p, ":*:") {
			parts := strings.Split(p, ":")
			permParts := strings.Split(permission, ":")
			if len(parts) == len(permParts) {
				match := true
				for i := range parts {
					if parts[i] != "*" && parts[i] != permParts[i] {
						match = false
						break
					}
				}
				if match {
					return true
				}
			}
		}
	}

	return false
}

// GetServiceInfo returns service identity information if this is a service license
func (k *LicenseKey) GetServiceInfo() (serviceName, serviceType string, permissions []string) {
	if !k.IsServiceLicense() {
		return "", "", nil
	}
	return k.ServiceName, k.ServiceType, k.Permissions
}

// String returns a human-readable representation of the license key
// Does NOT include the actual key value for security
func (k *LicenseKey) String() string {
	if k.IsServiceLicense() {
		return "LicenseKey{org=" + k.OrgID + ", service=" + k.ServiceName + ", type=" + k.ServiceType + ", tier=" + string(k.Tier) + ", permissions=" + strings.Join(k.Permissions, ",") + "}"
	}
	return "LicenseKey{org=" + k.OrgID + ", tier=" + string(k.Tier) + "}"
}

// ToValidationResult converts a LicenseKey to a ValidationResult
// This is for backward compatibility with existing code that uses ValidationResult
func (k *LicenseKey) ToValidationResult() *ValidationResult {
	return &ValidationResult{
		Valid:            true,
		Tier:             k.Tier,
		OrgID:            k.OrgID,
		MaxNodes:         k.MaxNodes,
		ExpiresAt:        k.ExpiresAt,
		DaysUntilExpiry:  k.DaysUntilExpiry,
		Features:         k.Features,
		// Service identity fields (may be empty for non-service licenses)
		ServiceName: k.ServiceName,
		ServiceType: k.ServiceType,
		Permissions: k.Permissions,
	}
}
