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

package types

import "testing"

func TestDeploymentMode_String(t *testing.T) {
	tests := []struct {
		mode DeploymentMode
		want string
	}{
		{DeploymentModeSaaS, "saas"},
		{DeploymentModeInVPC, "invpc"},
		{DeploymentMode("custom"), "custom"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.mode.String(); got != tt.want {
				t.Errorf("String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDeploymentMode_IsValid(t *testing.T) {
	tests := []struct {
		mode  DeploymentMode
		valid bool
	}{
		{DeploymentModeSaaS, true},
		{DeploymentModeInVPC, true},
		{DeploymentMode("invalid"), false},
		{DeploymentMode(""), false},
		{DeploymentMode("SAAS"), false}, // case sensitive
	}

	for _, tt := range tests {
		t.Run(string(tt.mode), func(t *testing.T) {
			if got := tt.mode.IsValid(); got != tt.valid {
				t.Errorf("IsValid() = %v, want %v", got, tt.valid)
			}
		})
	}
}

func TestDefaultSaaSConfig(t *testing.T) {
	config := DefaultSaaSConfig()

	if config.Mode != DeploymentModeSaaS {
		t.Errorf("Mode = %v, want %v", config.Mode, DeploymentModeSaaS)
	}
	if !config.TenantIsolation {
		t.Error("expected TenantIsolation to be true for SaaS")
	}
	if config.ShowNodeUsage {
		t.Error("expected ShowNodeUsage to be false for SaaS")
	}
	if config.ShowPlatformMetrics {
		t.Error("expected ShowPlatformMetrics to be false for SaaS")
	}
	if config.ShowDeployments {
		t.Error("expected ShowDeployments to be false for SaaS")
	}
}

func TestDefaultInVPCConfig(t *testing.T) {
	config := DefaultInVPCConfig()

	if config.Mode != DeploymentModeInVPC {
		t.Errorf("Mode = %v, want %v", config.Mode, DeploymentModeInVPC)
	}
	if config.TenantIsolation {
		t.Error("expected TenantIsolation to be false for In-VPC")
	}
	if !config.ShowNodeUsage {
		t.Error("expected ShowNodeUsage to be true for In-VPC")
	}
	if !config.ShowPlatformMetrics {
		t.Error("expected ShowPlatformMetrics to be true for In-VPC")
	}
	if !config.ShowDeployments {
		t.Error("expected ShowDeployments to be true for In-VPC")
	}
}

func TestDeploymentConfig_IsSaaS(t *testing.T) {
	saasConfig := DefaultSaaSConfig()
	if !saasConfig.IsSaaS() {
		t.Error("expected IsSaaS() to return true for SaaS config")
	}
	if saasConfig.IsInVPC() {
		t.Error("expected IsInVPC() to return false for SaaS config")
	}

	invpcConfig := DefaultInVPCConfig()
	if invpcConfig.IsSaaS() {
		t.Error("expected IsSaaS() to return false for In-VPC config")
	}
	if !invpcConfig.IsInVPC() {
		t.Error("expected IsInVPC() to return true for In-VPC config")
	}
}

func TestDeploymentConfig_CustomMode(t *testing.T) {
	config := DeploymentConfig{
		Mode:            DeploymentMode("custom"),
		TenantIsolation: true,
	}

	if config.IsSaaS() {
		t.Error("expected IsSaaS() to return false for custom mode")
	}
	if config.IsInVPC() {
		t.Error("expected IsInVPC() to return false for custom mode")
	}
}

func TestDeploymentMode_Constants(t *testing.T) {
	// Ensure constants have expected values
	if DeploymentModeSaaS != "saas" {
		t.Errorf("DeploymentModeSaaS = %v, want 'saas'", DeploymentModeSaaS)
	}
	if DeploymentModeInVPC != "invpc" {
		t.Errorf("DeploymentModeInVPC = %v, want 'invpc'", DeploymentModeInVPC)
	}
}
