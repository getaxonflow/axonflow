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

// Package types provides shared type definitions used across AxonFlow components.
// This file defines deployment mode configuration for SaaS vs In-VPC deployments.
package types

// DeploymentMode represents the deployment type
type DeploymentMode string

const (
	// DeploymentModeSaaS is for multi-tenant SaaS deployments with RLS
	DeploymentModeSaaS DeploymentMode = "saas"
	// DeploymentModeInVPC is for single-tenant In-VPC deployments
	DeploymentModeInVPC DeploymentMode = "invpc"
)

// String returns the string representation of the DeploymentMode
func (m DeploymentMode) String() string {
	return string(m)
}

// IsValid returns true if the DeploymentMode is a valid known value
func (m DeploymentMode) IsValid() bool {
	switch m {
	case DeploymentModeSaaS, DeploymentModeInVPC:
		return true
	default:
		return false
	}
}

// DeploymentConfig contains deployment-specific settings that control
// feature visibility and data isolation behavior based on deployment type.
//
// SaaS deployments use strict tenant isolation (RLS) and show request-based usage.
// In-VPC deployments show platform-wide metrics and node-based usage.
type DeploymentConfig struct {
	// Mode is the deployment type (saas or invpc)
	Mode DeploymentMode `json:"mode"`

	// TenantIsolation enables RLS-based data filtering for multi-tenant SaaS
	TenantIsolation bool `json:"tenant_isolation"`

	// ShowNodeUsage enables node/agent count metrics (relevant for In-VPC licensing)
	ShowNodeUsage bool `json:"show_node_usage"`

	// ShowPlatformMetrics enables platform-wide performance metrics (In-VPC only)
	ShowPlatformMetrics bool `json:"show_platform_metrics"`

	// ShowDeployments enables self-managed deployment controls (In-VPC only)
	ShowDeployments bool `json:"show_deployments"`
}

// DefaultSaaSConfig returns the default configuration for SaaS deployments.
// SaaS mode enforces tenant isolation and shows request-based usage metrics.
func DefaultSaaSConfig() DeploymentConfig {
	return DeploymentConfig{
		Mode:                DeploymentModeSaaS,
		TenantIsolation:     true,
		ShowNodeUsage:       false,
		ShowPlatformMetrics: false,
		ShowDeployments:     false,
	}
}

// DefaultInVPCConfig returns the default configuration for In-VPC deployments.
// In-VPC mode shows platform-wide metrics and node-based usage.
func DefaultInVPCConfig() DeploymentConfig {
	return DeploymentConfig{
		Mode:                DeploymentModeInVPC,
		TenantIsolation:     false,
		ShowNodeUsage:       true,
		ShowPlatformMetrics: true,
		ShowDeployments:     true,
	}
}

// IsSaaS returns true if this is a SaaS deployment
func (c DeploymentConfig) IsSaaS() bool {
	return c.Mode == DeploymentModeSaaS
}

// IsInVPC returns true if this is an In-VPC deployment
func (c DeploymentConfig) IsInVPC() bool {
	return c.Mode == DeploymentModeInVPC
}
