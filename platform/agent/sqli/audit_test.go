package sqli

import (
	"sync"
	"testing"
	"time"
)

func TestCategorySeverity(t *testing.T) {
	tests := []struct {
		category Category
		want     string
	}{
		{CategoryStackedQueries, SeverityCritical},
		{CategoryDangerousQuery, SeverityCritical},
		{CategoryUnionBased, SeverityHigh},
		{CategoryTimeBased, SeverityHigh},
		{CategoryBooleanBlind, SeverityMedium},
		{CategoryErrorBased, SeverityMedium},
		{CategoryCommentInjection, SeverityMedium},
		{CategoryGeneric, SeverityLow},
		{Category("unknown"), SeverityLow},
	}

	for _, tt := range tests {
		t.Run(string(tt.category), func(t *testing.T) {
			if got := CategorySeverity(tt.category); got != tt.want {
				t.Errorf("CategorySeverity(%v) = %v, want %v", tt.category, got, tt.want)
			}
		})
	}
}

func TestNewAuditEvent(t *testing.T) {
	t.Run("nil result returns nil", func(t *testing.T) {
		if got := NewAuditEvent(nil, "postgres"); got != nil {
			t.Error("NewAuditEvent(nil) should return nil")
		}
	})

	t.Run("undetected result returns nil", func(t *testing.T) {
		result := &Result{Detected: false}
		if got := NewAuditEvent(result, "postgres"); got != nil {
			t.Error("NewAuditEvent with undetected result should return nil")
		}
	})

	t.Run("detected result creates event", func(t *testing.T) {
		result := &Result{
			Detected:   true,
			Blocked:    true,
			Pattern:    "union_select",
			Category:   CategoryUnionBased,
			Confidence: 0.95,
			ScanType:   ScanTypeResponse,
			Mode:       ModeBasic,
			Duration:   5 * time.Millisecond,
			Input:      "admin' UNION SELECT...",
		}

		event := NewAuditEvent(result, "postgres")

		if event == nil {
			t.Fatal("NewAuditEvent returned nil for detected result")
		}
		if event.Type != AuditEventType {
			t.Errorf("Type = %v, want %v", event.Type, AuditEventType)
		}
		if event.ConnectorName != "postgres" {
			t.Errorf("ConnectorName = %v, want postgres", event.ConnectorName)
		}
		if event.Pattern != "union_select" {
			t.Errorf("Pattern = %v, want union_select", event.Pattern)
		}
		if event.Category != CategoryUnionBased {
			t.Errorf("Category = %v, want %v", event.Category, CategoryUnionBased)
		}
		if event.Severity != SeverityHigh {
			t.Errorf("Severity = %v, want %v", event.Severity, SeverityHigh)
		}
		if event.Confidence != 0.95 {
			t.Errorf("Confidence = %v, want 0.95", event.Confidence)
		}
		if !event.Blocked {
			t.Error("Blocked should be true")
		}
		if event.Timestamp.IsZero() {
			t.Error("Timestamp should not be zero")
		}
	})
}

func TestAuditEvent_WithContext(t *testing.T) {
	result := &Result{
		Detected: true,
		Category: CategoryGeneric,
	}
	event := NewAuditEvent(result, "redis")

	event.WithUserContext("user123", "client456", "tenant789")
	event.WithRequestID("req-abc-123")

	if event.UserID != "user123" {
		t.Errorf("UserID = %v, want user123", event.UserID)
	}
	if event.ClientID != "client456" {
		t.Errorf("ClientID = %v, want client456", event.ClientID)
	}
	if event.TenantID != "tenant789" {
		t.Errorf("TenantID = %v, want tenant789", event.TenantID)
	}
	if event.RequestID != "req-abc-123" {
		t.Errorf("RequestID = %v, want req-abc-123", event.RequestID)
	}
}

func TestAuditEvent_ToAuditDetails(t *testing.T) {
	result := &Result{
		Detected:   true,
		Pattern:    "sleep_function",
		Category:   CategoryTimeBased,
		Confidence: 1.0,
		Mode:       ModeAdvanced,
		Blocked:    true,
		Duration:   10 * time.Millisecond,
		Input:      "SELECT SLEEP(5)...",
		ScanType:   ScanTypeInput,
	}
	event := NewAuditEvent(result, "mysql")
	event.WithRequestID("test-request")

	details := event.ToAuditDetails()

	if details["connector_name"] != "mysql" {
		t.Errorf("connector_name = %v, want mysql", details["connector_name"])
	}
	if details["pattern"] != "sleep_function" {
		t.Errorf("pattern = %v, want sleep_function", details["pattern"])
	}
	if details["category"] != string(CategoryTimeBased) {
		t.Errorf("category = %v, want %v", details["category"], CategoryTimeBased)
	}
	if details["mode"] != string(ModeAdvanced) {
		t.Errorf("mode = %v, want %v", details["mode"], ModeAdvanced)
	}
	if details["blocked"] != true {
		t.Error("blocked should be true")
	}
	if details["request_id"] != "test-request" {
		t.Errorf("request_id = %v, want test-request", details["request_id"])
	}
}

func TestSetAuditCallback(t *testing.T) {
	// Save original
	originalCallback := globalAuditCallback
	defer func() { globalAuditCallback = originalCallback }()

	t.Run("set custom callback", func(t *testing.T) {
		callCount := 0
		SetAuditCallback(func(event *AuditEvent) {
			callCount++
		})

		// Emit an event
		event := &AuditEvent{Type: AuditEventType}
		EmitAuditEvent(event)

		if callCount != 1 {
			t.Errorf("Callback called %d times, want 1", callCount)
		}
	})

	t.Run("set nil callback uses default", func(t *testing.T) {
		SetAuditCallback(nil)

		// Should not panic
		event := &AuditEvent{Type: AuditEventType}
		EmitAuditEvent(event)
	})

	t.Run("emit nil event is safe", func(t *testing.T) {
		callCount := 0
		SetAuditCallback(func(event *AuditEvent) {
			callCount++
		})

		EmitAuditEvent(nil)

		if callCount != 0 {
			t.Error("Callback should not be called for nil event")
		}
	})
}

func TestAuditCallback_Concurrent(t *testing.T) {
	// Save original
	originalCallback := globalAuditCallback
	defer func() { globalAuditCallback = originalCallback }()

	var mu sync.Mutex
	events := make([]*AuditEvent, 0)

	SetAuditCallback(func(event *AuditEvent) {
		mu.Lock()
		events = append(events, event)
		mu.Unlock()
	})

	// Emit events concurrently
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			event := &AuditEvent{
				Type:      AuditEventType,
				RequestID: string(rune('A' + i%26)),
			}
			EmitAuditEvent(event)
		}(i)
	}

	wg.Wait()

	if len(events) != 100 {
		t.Errorf("Got %d events, want 100", len(events))
	}
}
