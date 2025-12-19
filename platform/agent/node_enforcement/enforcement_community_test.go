//go:build !enterprise

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

package node_enforcement

import (
	"context"
	"testing"
	"time"
)

func TestNewHeartbeatService(t *testing.T) {
	tests := []struct {
		name         string
		instanceType string
		licenseKey   string
		orgID        string
	}{
		{
			name:         "agent instance",
			instanceType: "agent",
			licenseKey:   "test-key",
			orgID:        "org-123",
		},
		{
			name:         "orchestrator instance",
			instanceType: "orchestrator",
			licenseKey:   "test-key-2",
			orgID:        "org-456",
		},
		{
			name:         "empty parameters",
			instanceType: "",
			licenseKey:   "",
			orgID:        "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service := NewHeartbeatService(nil, tt.instanceType, tt.licenseKey, tt.orgID)
			if service == nil {
				t.Error("NewHeartbeatService() returned nil, want non-nil stub")
			}
		})
	}
}

func TestHeartbeatService_Start(t *testing.T) {
	service := NewHeartbeatService(nil, "agent", "test-key", "org-1")
	ctx := context.Background()

	err := service.Start(ctx)
	if err != nil {
		t.Errorf("Start() error = %v, want nil (Community no-op)", err)
	}
}

func TestHeartbeatService_Stop(t *testing.T) {
	service := NewHeartbeatService(nil, "agent", "test-key", "org-1")

	// Should not panic
	service.Stop()
}

func TestHeartbeatService_Lifecycle(t *testing.T) {
	// Test full lifecycle
	ctx := context.Background()
	service := NewHeartbeatService(nil, "agent", "test-key", "org-1")

	// Start
	if err := service.Start(ctx); err != nil {
		t.Errorf("Start() error = %v", err)
	}

	// Stop
	service.Stop()
}

func TestHeartbeatService_MultipleStarts(t *testing.T) {
	ctx := context.Background()
	service := NewHeartbeatService(nil, "agent", "test-key", "org-1")

	for i := 0; i < 3; i++ {
		if err := service.Start(ctx); err != nil {
			t.Errorf("Start() call %d error = %v", i+1, err)
		}
	}
}

func TestHeartbeatService_MultipleStops(t *testing.T) {
	service := NewHeartbeatService(nil, "agent", "test-key", "org-1")

	for i := 0; i < 3; i++ {
		service.Stop()
	}
}

func TestNewNodeMonitor(t *testing.T) {
	tests := []struct {
		name    string
		alerter AlertService
	}{
		{
			name:    "with nil alerter",
			alerter: nil,
		},
		{
			name:    "with alerter",
			alerter: NewMultiChannelAlerter(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			monitor := NewNodeMonitor(nil, tt.alerter)
			if monitor == nil {
				t.Error("NewNodeMonitor() returned nil, want non-nil stub")
			}
		})
	}
}

func TestNodeMonitor_Start(t *testing.T) {
	ctx := context.Background()
	monitor := NewNodeMonitor(nil, nil)

	// Should not panic or return error
	monitor.Start(ctx)
}

func TestNodeMonitor_Stop(t *testing.T) {
	monitor := NewNodeMonitor(nil, nil)

	// Should not panic
	monitor.Stop()
}

func TestNodeMonitor_Lifecycle(t *testing.T) {
	ctx := context.Background()
	monitor := NewNodeMonitor(nil, NewMultiChannelAlerter())

	monitor.Start(ctx)
	monitor.Stop()
}

func TestNewMultiChannelAlerter(t *testing.T) {
	alerter := NewMultiChannelAlerter()
	if alerter == nil {
		t.Error("NewMultiChannelAlerter() returned nil, want non-nil stub")
	}
}

func TestMultiChannelAlerter_SendNodeViolationAlert(t *testing.T) {
	ctx := context.Background()
	alerter := NewMultiChannelAlerter()

	tests := []struct {
		name      string
		violation *ViolationInfo
	}{
		{
			name: "valid violation",
			violation: &ViolationInfo{
				OrgID:             "org-123",
				LicenseKeyHash:    "hash123",
				Tier:              "ENT",
				MaxNodesAllowed:   10,
				ActualNodeCount:   15,
				ExcessNodes:       5,
				ActiveInstances:   []string{"i-1", "i-2"},
				ViolationDuration: 1 * time.Hour,
			},
		},
		{
			name:      "nil violation",
			violation: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := alerter.SendNodeViolationAlert(ctx, tt.violation)
			if err != nil {
				t.Errorf("SendNodeViolationAlert() error = %v, want nil (Community no-op)", err)
			}
		})
	}
}

func TestMultiChannelAlerter_SendNodeCountWarning(t *testing.T) {
	ctx := context.Background()
	alerter := NewMultiChannelAlerter()

	tests := []struct {
		name  string
		orgID string
		usage float64
	}{
		{
			name:  "80% usage",
			orgID: "org-1",
			usage: 0.8,
		},
		{
			name:  "90% usage",
			orgID: "org-2",
			usage: 0.9,
		},
		{
			name:  "empty orgID",
			orgID: "",
			usage: 0.5,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := alerter.SendNodeCountWarning(ctx, tt.orgID, tt.usage)
			if err != nil {
				t.Errorf("SendNodeCountWarning() error = %v, want nil (Community no-op)", err)
			}
		})
	}
}

func TestGetActiveNodeCount(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name           string
		licenseKeyHash string
	}{
		{
			name:           "valid hash",
			licenseKeyHash: "hash123",
		},
		{
			name:           "empty hash",
			licenseKeyHash: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			count, err := GetActiveNodeCount(ctx, nil, tt.licenseKeyHash)
			if err != nil {
				t.Errorf("GetActiveNodeCount() error = %v, want nil (Community stub)", err)
			}
			if count != 0 {
				t.Errorf("GetActiveNodeCount() = %d, want 0 (Community stub)", count)
			}
		})
	}
}

func TestGetActiveNodesByOrg(t *testing.T) {
	ctx := context.Background()

	nodes, err := GetActiveNodesByOrg(ctx, nil)
	if err != nil {
		t.Errorf("GetActiveNodesByOrg() error = %v, want nil (Community stub)", err)
	}
	if nodes == nil {
		t.Error("GetActiveNodesByOrg() returned nil, want empty map")
	}
	if len(nodes) != 0 {
		t.Errorf("GetActiveNodesByOrg() returned %d nodes, want 0 (Community stub)", len(nodes))
	}
}

func TestCleanupStaleHeartbeats(t *testing.T) {
	ctx := context.Background()

	err := CleanupStaleHeartbeats(ctx, nil)
	if err != nil {
		t.Errorf("CleanupStaleHeartbeats() error = %v, want nil (Community no-op)", err)
	}
}

func TestGetViolationHistory(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name  string
		orgID string
	}{
		{
			name:  "valid org",
			orgID: "org-123",
		},
		{
			name:  "empty org",
			orgID: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			violations, err := GetViolationHistory(ctx, nil, tt.orgID)
			if err != nil {
				t.Errorf("GetViolationHistory() error = %v, want nil (Community stub)", err)
			}
			if violations == nil {
				t.Error("GetViolationHistory() returned nil, want empty slice")
			}
			if len(violations) != 0 {
				t.Errorf("GetViolationHistory() returned %d violations, want 0 (Community stub)", len(violations))
			}
		})
	}
}

func TestHostInfo_Fields(t *testing.T) {
	// Verify HostInfo struct can be instantiated with all fields
	_ = HostInfo{
		Hostname:  "test-host",
		IPAddress: "192.168.1.1",
		Port:      8080,
		Version:   "1.0.0",
		OS:        "linux",
		CPUCores:  4,
		MemoryMB:  8192,
		Region:    "us-east-1",
	}
}

func TestViolationInfo_Fields(t *testing.T) {
	// Verify ViolationInfo struct can be instantiated
	_ = ViolationInfo{
		OrgID:             "org-1",
		LicenseKeyHash:    "hash",
		Tier:              "ENT",
		MaxNodesAllowed:   10,
		ActualNodeCount:   15,
		ExcessNodes:       5,
		ActiveInstances:   []string{"i-1", "i-2", "i-3"},
		ViolationDuration: 2 * time.Hour,
	}
}

func TestHeartbeatService_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	service := NewHeartbeatService(nil, "agent", "key", "org")

	// Should handle cancelled context gracefully
	err := service.Start(ctx)
	if err != nil {
		t.Errorf("Start() with cancelled context error = %v, want nil (Community no-op)", err)
	}
}

func TestNodeMonitor_ConcurrentAccess(t *testing.T) {
	ctx := context.Background()
	monitor := NewNodeMonitor(nil, NewMultiChannelAlerter())

	done := make(chan bool)

	// Start multiple goroutines
	for i := 0; i < 5; i++ {
		go func() {
			monitor.Start(ctx)
			monitor.Stop()
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 5; i++ {
		<-done
	}
}

func TestAlerter_AllMethods(t *testing.T) {
	// Test all alerter methods in sequence
	ctx := context.Background()
	alerter := NewMultiChannelAlerter()

	violation := &ViolationInfo{
		OrgID:           "test-org",
		MaxNodesAllowed: 5,
		ActualNodeCount: 10,
	}

	// Send violation alert
	if err := alerter.SendNodeViolationAlert(ctx, violation); err != nil {
		t.Errorf("SendNodeViolationAlert() error = %v", err)
	}

	// Send warning
	if err := alerter.SendNodeCountWarning(ctx, "test-org", 0.85); err != nil {
		t.Errorf("SendNodeCountWarning() error = %v", err)
	}
}

func TestNodeEnforcement_NilDB(t *testing.T) {
	// Verify nil DB doesn't cause panics
	ctx := context.Background()

	// Test all functions with nil DB
	_, err := GetActiveNodeCount(ctx, nil, "test")
	if err != nil {
		t.Errorf("GetActiveNodeCount() with nil DB error = %v", err)
	}

	_, err = GetActiveNodesByOrg(ctx, nil)
	if err != nil {
		t.Errorf("GetActiveNodesByOrg() with nil DB error = %v", err)
	}

	err = CleanupStaleHeartbeats(ctx, nil)
	if err != nil {
		t.Errorf("CleanupStaleHeartbeats() with nil DB error = %v", err)
	}

	_, err = GetViolationHistory(ctx, nil, "org")
	if err != nil {
		t.Errorf("GetViolationHistory() with nil DB error = %v", err)
	}
}

func TestAlertService_Interface(t *testing.T) {
	// Verify MultiChannelAlerter implements AlertService interface
	var _ AlertService = (*MultiChannelAlerter)(nil)
}
