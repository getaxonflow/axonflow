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

package marketplace

import (
	"context"
	"testing"
)

func TestNewMeteringService(t *testing.T) {
	tests := []struct {
		name        string
		productCode string
	}{
		{
			name:        "with product code",
			productCode: "axonflow-enterprise",
		},
		{
			name:        "with empty product code",
			productCode: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service, err := NewMeteringService(nil, tt.productCode)
			if err != nil {
				t.Errorf("NewMeteringService() error = %v, want nil (Community stub)", err)
			}
			if service == nil {
				t.Error("NewMeteringService() returned nil service, want non-nil stub")
			}
		})
	}
}

func TestMeteringService_Start(t *testing.T) {
	service, err := NewMeteringService(nil, "test-product")
	if err != nil {
		t.Fatalf("NewMeteringService() error = %v", err)
	}

	ctx := context.Background()
	err = service.Start(ctx)
	if err != nil {
		t.Errorf("Start() error = %v, want nil (Community no-op)", err)
	}
}

func TestMeteringService_Stop(t *testing.T) {
	service, err := NewMeteringService(nil, "test-product")
	if err != nil {
		t.Fatalf("NewMeteringService() error = %v", err)
	}

	// Should not panic
	service.Stop()
}

func TestMeteringService_RetryFailedRecords(t *testing.T) {
	service, err := NewMeteringService(nil, "test-product")
	if err != nil {
		t.Fatalf("NewMeteringService() error = %v", err)
	}

	ctx := context.Background()
	err = service.RetryFailedRecords(ctx)
	if err != nil {
		t.Errorf("RetryFailedRecords() error = %v, want nil (Community no-op)", err)
	}
}

func TestGetUsageHistory(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name string
		days int
	}{
		{
			name: "7 days",
			days: 7,
		},
		{
			name: "30 days",
			days: 30,
		},
		{
			name: "0 days",
			days: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			records, err := GetUsageHistory(ctx, nil, tt.days)
			if err != nil {
				t.Errorf("GetUsageHistory() error = %v, want nil (Community stub)", err)
			}
			if records == nil {
				t.Error("GetUsageHistory() returned nil, want empty slice")
			}
			if len(records) != 0 {
				t.Errorf("GetUsageHistory() returned %d records, want 0 (Community stub)", len(records))
			}
		})
	}
}

func TestMeteringService_FullLifecycle(t *testing.T) {
	// Test full lifecycle: create -> start -> stop
	ctx := context.Background()

	service, err := NewMeteringService(nil, "lifecycle-test")
	if err != nil {
		t.Fatalf("NewMeteringService() error = %v", err)
	}

	// Start service
	if err := service.Start(ctx); err != nil {
		t.Errorf("Start() error = %v", err)
	}

	// Retry failed records
	if err := service.RetryFailedRecords(ctx); err != nil {
		t.Errorf("RetryFailedRecords() error = %v", err)
	}

	// Stop service
	service.Stop()
}

func TestMeteringService_MultipleStarts(t *testing.T) {
	// Test that multiple Start() calls don't cause issues
	ctx := context.Background()
	service, _ := NewMeteringService(nil, "multi-start")

	for i := 0; i < 3; i++ {
		if err := service.Start(ctx); err != nil {
			t.Errorf("Start() call %d error = %v", i+1, err)
		}
	}
}

func TestMeteringService_MultipleStops(t *testing.T) {
	// Test that multiple Stop() calls don't panic
	service, _ := NewMeteringService(nil, "multi-stop")

	for i := 0; i < 3; i++ {
		service.Stop()
	}
}

func TestMeteringService_StopBeforeStart(t *testing.T) {
	// Test stopping before starting
	service, _ := NewMeteringService(nil, "stop-before-start")
	service.Stop() // Should not panic
}

func TestUsageRecord_Fields(t *testing.T) {
	// Verify UsageRecord struct can be instantiated with all fields
	records, _ := GetUsageHistory(context.Background(), nil, 1)

	// Should be empty but we can create one manually to verify struct
	_ = UsageRecord{
		Quantity:     100,
		Dimension:    "api-calls",
		CustomerID:   "cust-123",
		Status:       "success",
		RequestID:    "req-456",
		ErrorMessage: "",
	}

	if records == nil {
		t.Error("GetUsageHistory() should return non-nil slice")
	}
}

func TestMeteringService_ConcurrentAccess(t *testing.T) {
	// Test concurrent access to metering service
	ctx := context.Background()
	service, _ := NewMeteringService(nil, "concurrent-test")

	done := make(chan bool)

	// Start multiple goroutines
	for i := 0; i < 5; i++ {
		go func() {
			_ = service.Start(ctx)
			_ = service.RetryFailedRecords(ctx)
			service.Stop()
			done <- true
		}()
	}

	// Wait for all goroutines
	for i := 0; i < 5; i++ {
		<-done
	}
}

func TestGetUsageHistory_NilDB(t *testing.T) {
	// Verify nil DB doesn't cause panic
	ctx := context.Background()
	records, err := GetUsageHistory(ctx, nil, 7)

	if err != nil {
		t.Errorf("GetUsageHistory() with nil DB error = %v, want nil", err)
	}
	if records == nil {
		t.Error("GetUsageHistory() returned nil, want empty slice")
	}
}

func TestMeteringService_ContextCancellation(t *testing.T) {
	// Test behavior with cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	service, _ := NewMeteringService(nil, "cancelled-ctx")

	// Should handle cancelled context gracefully (no-op in Community)
	err := service.Start(ctx)
	if err != nil {
		t.Errorf("Start() with cancelled context error = %v, want nil (Community no-op)", err)
	}

	err = service.RetryFailedRecords(ctx)
	if err != nil {
		t.Errorf("RetryFailedRecords() with cancelled context error = %v, want nil (Community no-op)", err)
	}
}
