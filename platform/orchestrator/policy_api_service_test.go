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

package orchestrator

import (
	"testing"
)

// mockPolicyRefresher is a test double for PolicyEngineRefresher.
type mockPolicyRefresher struct {
	called bool
}

func (m *mockPolicyRefresher) RefreshPolicies() error {
	m.called = true
	return nil
}

func TestNewPolicyServiceWithRefresher(t *testing.T) {
	repo := &PolicyRepository{} // nil db is fine for constructor test
	refresher := &mockPolicyRefresher{}

	service := NewPolicyServiceWithRefresher(repo, refresher)

	if service == nil {
		t.Fatal("NewPolicyServiceWithRefresher() returned nil")
	}
	if service.repo != repo {
		t.Error("Expected service.repo to match the provided repository")
	}
	if service.policyRefresher == nil {
		t.Error("Expected service.policyRefresher to be set")
	}
	if service.policyEngine != nil {
		t.Error("Expected service.policyEngine to be nil (not provided)")
	}
	if service.licenseChecker == nil {
		t.Error("Expected service.licenseChecker to be set (default env checker)")
	}
}

func TestNewPolicyServiceWithRefresher_NilRefresher(t *testing.T) {
	repo := &PolicyRepository{}

	service := NewPolicyServiceWithRefresher(repo, nil)

	if service == nil {
		t.Fatal("NewPolicyServiceWithRefresher() with nil refresher returned nil")
	}
	if service.policyRefresher != nil {
		t.Error("Expected service.policyRefresher to be nil when nil is passed")
	}
	if service.licenseChecker == nil {
		t.Error("Expected service.licenseChecker to be set")
	}
}

func TestNewPolicyServiceWithLicense(t *testing.T) {
	repo := &PolicyRepository{}
	engine := &DynamicPolicyEngine{}
	lc := NewEnvLicenseChecker()

	service := NewPolicyServiceWithLicense(repo, engine, lc)

	if service == nil {
		t.Fatal("NewPolicyServiceWithLicense() returned nil")
	}
	if service.repo != repo {
		t.Error("Expected service.repo to match")
	}
	if service.policyEngine != engine {
		t.Error("Expected service.policyEngine to match")
	}
	if service.licenseChecker != lc {
		t.Error("Expected service.licenseChecker to match")
	}
}
