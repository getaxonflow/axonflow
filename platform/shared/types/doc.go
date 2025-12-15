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

/*
Package types provides shared type definitions used across AxonFlow components.

# Overview

This package contains common types that are shared between the Agent,
Orchestrator, and other AxonFlow components. It provides a single source
of truth for shared data structures.

# Deployment Modes

AxonFlow supports two deployment modes, configured via DeploymentConfig:

SaaS Mode (multi-tenant):
  - Strict tenant isolation via Row Level Security (RLS)
  - Request-based usage metrics
  - Shared infrastructure

In-VPC Mode (single-tenant):
  - Platform-wide metrics visibility
  - Node-based usage (for per-node licensing)
  - Self-managed deployment controls

# Usage

Determine deployment mode and configure features:

	config := types.DefaultSaaSConfig()  // For SaaS deployments

	// Or for In-VPC deployments
	config := types.DefaultInVPCConfig()

	if config.IsSaaS() {
	    // Enable RLS, request-based billing
	}

	if config.ShowPlatformMetrics {
	    // Show platform-wide metrics in dashboard
	}

# Thread Safety

All types in this package are value types and are safe for concurrent use.
*/
package types
