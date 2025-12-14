package sqli

import (
	"context"
	"testing"
	"time"
)

func TestNewScanningMiddleware(t *testing.T) {
	t.Run("default configuration", func(t *testing.T) {
		m, err := NewScanningMiddleware()
		if err != nil {
			t.Fatalf("NewScanningMiddleware() error = %v", err)
		}
		if m == nil {
			t.Fatal("NewScanningMiddleware() returned nil")
		}
	})

	t.Run("with custom config", func(t *testing.T) {
		cfg := DefaultConfig().WithResponseMode(ModeOff)
		m, err := NewScanningMiddleware(WithMiddlewareConfig(cfg))
		if err != nil {
			t.Fatalf("NewScanningMiddleware() error = %v", err)
		}
		if m == nil {
			t.Fatal("NewScanningMiddleware() returned nil")
		}
	})

	t.Run("with invalid config", func(t *testing.T) {
		cfg := Config{
			InputMode:        Mode("invalid"),
			ResponseMode:     ModeBasic,
			MaxContentLength: 1000,
		}
		_, err := NewScanningMiddleware(WithMiddlewareConfig(cfg))
		if err == nil {
			t.Error("NewScanningMiddleware() should return error for invalid config")
		}
	})

	t.Run("with custom scanner", func(t *testing.T) {
		scanner := &NoOpScanner{}
		m, err := NewScanningMiddleware(WithMiddlewareScanner(scanner))
		if err != nil {
			t.Fatalf("NewScanningMiddleware() error = %v", err)
		}
		if m.scanner != scanner {
			t.Error("Custom scanner not applied")
		}
	})
}

func TestScanningMiddleware_ScanQueryResponse(t *testing.T) {
	ctx := context.Background()

	t.Run("clean response passes", func(t *testing.T) {
		m, _ := NewScanningMiddleware()
		rows := []map[string]interface{}{
			{"id": 1, "name": "John Doe", "email": "john@example.com"},
			{"id": 2, "name": "Jane Smith", "email": "jane@example.com"},
		}

		result, err := m.ScanQueryResponse(ctx, "postgres", rows)
		if err != nil {
			t.Fatalf("ScanQueryResponse() error = %v", err)
		}
		if result.Detected {
			t.Error("Should not detect SQL injection in clean data")
		}
		if result.Blocked {
			t.Error("Should not block clean data")
		}
	})

	t.Run("malicious response detected", func(t *testing.T) {
		// Default is monitoring mode (detect but don't block)
		m, _ := NewScanningMiddleware()
		rows := []map[string]interface{}{
			{"id": 1, "data": "admin' UNION SELECT password FROM users--"},
		}

		result, err := m.ScanQueryResponse(ctx, "postgres", rows)
		if err != nil {
			t.Fatalf("ScanQueryResponse() error = %v", err)
		}
		if !result.Detected {
			t.Error("Should detect SQL injection")
		}
		if result.Blocked {
			t.Error("Should not block by default (monitoring mode)")
		}
		if result.Category != CategoryUnionBased {
			t.Errorf("Category = %v, want %v", result.Category, CategoryUnionBased)
		}
	})

	t.Run("malicious response blocked when enabled", func(t *testing.T) {
		cfg := DefaultConfig().WithBlockOnDetection(true)
		m, _ := NewScanningMiddleware(WithMiddlewareConfig(cfg))
		rows := []map[string]interface{}{
			{"id": 1, "data": "admin' UNION SELECT password FROM users--"},
		}

		result, err := m.ScanQueryResponse(ctx, "postgres", rows)
		if err != nil {
			t.Fatalf("ScanQueryResponse() error = %v", err)
		}
		if !result.Detected {
			t.Error("Should detect SQL injection")
		}
		if !result.Blocked {
			t.Error("Should block when BlockOnDetection is true")
		}
	})

	t.Run("detection without blocking", func(t *testing.T) {
		cfg := DefaultConfig().WithBlockOnDetection(false)
		m, _ := NewScanningMiddleware(WithMiddlewareConfig(cfg))
		rows := []map[string]interface{}{
			{"id": 1, "data": "admin' OR 1=1--"},
		}

		result, err := m.ScanQueryResponse(ctx, "postgres", rows)
		if err != nil {
			t.Fatalf("ScanQueryResponse() error = %v", err)
		}
		if !result.Detected {
			t.Error("Should detect SQL injection")
		}
		if result.Blocked {
			t.Error("Should not block when BlockOnDetection is false")
		}
	})

	t.Run("disabled connector skips scanning", func(t *testing.T) {
		cfg := DefaultConfig().WithConnectorOverride("redis", ConnectorConfig{Enabled: false})
		m, _ := NewScanningMiddleware(WithMiddlewareConfig(cfg))
		rows := []map[string]interface{}{
			{"key": "admin' UNION SELECT * FROM users--"},
		}

		result, err := m.ScanQueryResponse(ctx, "redis", rows)
		if err != nil {
			t.Fatalf("ScanQueryResponse() error = %v", err)
		}
		if result.Detected || result.Blocked {
			t.Error("Should skip scanning for disabled connector")
		}
	})

	t.Run("off mode for connector skips scanning", func(t *testing.T) {
		cfg := DefaultConfig().WithConnectorOverride("cache", ConnectorConfig{
			ResponseMode: ModeOff,
			Enabled:      true,
		})
		m, _ := NewScanningMiddleware(WithMiddlewareConfig(cfg))
		rows := []map[string]interface{}{
			{"value": "DROP TABLE users--"},
		}

		result, err := m.ScanQueryResponse(ctx, "cache", rows)
		if err != nil {
			t.Fatalf("ScanQueryResponse() error = %v", err)
		}
		if result.Detected || result.Blocked {
			t.Error("Should skip scanning when mode is off")
		}
	})

	t.Run("empty rows pass", func(t *testing.T) {
		m, _ := NewScanningMiddleware()
		result, err := m.ScanQueryResponse(ctx, "postgres", []map[string]interface{}{})
		if err != nil {
			t.Fatalf("ScanQueryResponse() error = %v", err)
		}
		if result.Detected {
			t.Error("Empty rows should not trigger detection")
		}
	})

	t.Run("duration is recorded", func(t *testing.T) {
		m, _ := NewScanningMiddleware()
		rows := []map[string]interface{}{
			{"id": 1, "name": "test"},
		}
		result, _ := m.ScanQueryResponse(ctx, "postgres", rows)
		if result.Duration <= 0 {
			t.Error("Duration should be positive")
		}
	})
}

func TestScanningMiddleware_ScanCommandResponse(t *testing.T) {
	ctx := context.Background()

	t.Run("clean message passes", func(t *testing.T) {
		m, _ := NewScanningMiddleware()
		result, err := m.ScanCommandResponse(ctx, "postgres", "5 rows updated successfully", nil)
		if err != nil {
			t.Fatalf("ScanCommandResponse() error = %v", err)
		}
		if result.Detected {
			t.Error("Should not detect in clean message")
		}
	})

	t.Run("malicious message detected", func(t *testing.T) {
		m, _ := NewScanningMiddleware()
		result, err := m.ScanCommandResponse(ctx, "postgres",
			"Error: syntax near ' UNION SELECT * FROM admin_passwords--", nil)
		if err != nil {
			t.Fatalf("ScanCommandResponse() error = %v", err)
		}
		if !result.Detected {
			t.Error("Should detect SQL injection in message")
		}
	})

	t.Run("malicious metadata detected", func(t *testing.T) {
		m, _ := NewScanningMiddleware()
		metadata := map[string]interface{}{
			"query": "SELECT * FROM users WHERE id=' OR 1=1--",
		}
		result, err := m.ScanCommandResponse(ctx, "postgres", "OK", metadata)
		if err != nil {
			t.Fatalf("ScanCommandResponse() error = %v", err)
		}
		if !result.Detected {
			t.Error("Should detect SQL injection in metadata")
		}
	})

	t.Run("disabled connector skips", func(t *testing.T) {
		cfg := DefaultConfig().WithConnectorOverride("test", ConnectorConfig{Enabled: false})
		m, _ := NewScanningMiddleware(WithMiddlewareConfig(cfg))
		result, err := m.ScanCommandResponse(ctx, "test", "; DROP TABLE users--", nil)
		if err != nil {
			t.Fatalf("ScanCommandResponse() error = %v", err)
		}
		if result.Detected {
			t.Error("Should skip scanning for disabled connector")
		}
	})
}

func TestScanningMiddleware_ScanInput(t *testing.T) {
	ctx := context.Background()

	t.Run("clean input passes", func(t *testing.T) {
		m, _ := NewScanningMiddleware()
		result, err := m.ScanInput(ctx, "Show me the top 10 customers by revenue")
		if err != nil {
			t.Fatalf("ScanInput() error = %v", err)
		}
		if result.Detected {
			t.Error("Should not detect in clean input")
		}
	})

	t.Run("malicious input detected", func(t *testing.T) {
		m, _ := NewScanningMiddleware()
		result, err := m.ScanInput(ctx, "'; DROP TABLE users; --")
		if err != nil {
			t.Fatalf("ScanInput() error = %v", err)
		}
		if !result.Detected {
			t.Error("Should detect SQL injection in input")
		}
	})

	t.Run("input scanning disabled", func(t *testing.T) {
		cfg := DefaultConfig().WithInputMode(ModeOff)
		m, _ := NewScanningMiddleware(WithMiddlewareConfig(cfg))
		result, err := m.ScanInput(ctx, "'; DROP TABLE users; --")
		if err != nil {
			t.Fatalf("ScanInput() error = %v", err)
		}
		if result.Detected {
			t.Error("Should not detect when input mode is off")
		}
	})
}

func TestScanningMiddleware_Metrics(t *testing.T) {
	ctx := context.Background()
	// Enable blocking to test blocked metrics
	cfg := DefaultConfig().WithBlockOnDetection(true)
	m, _ := NewScanningMiddleware(WithMiddlewareConfig(cfg))

	// Initial metrics should be zero
	metrics := m.GetMetrics()
	if metrics.ScansTotal != 0 || metrics.DetectionsTotal != 0 || metrics.BlockedTotal != 0 {
		t.Error("Initial metrics should be zero")
	}

	// Perform a clean scan
	m.ScanQueryResponse(ctx, "postgres", []map[string]interface{}{{"id": 1}})
	metrics = m.GetMetrics()
	if metrics.ScansTotal != 1 {
		t.Errorf("ScansTotal = %d, want 1", metrics.ScansTotal)
	}
	if metrics.DetectionsTotal != 0 {
		t.Error("DetectionsTotal should be 0 for clean scan")
	}

	// Perform a detection scan
	m.ScanQueryResponse(ctx, "postgres", []map[string]interface{}{
		{"data": "' UNION SELECT * FROM passwords--"},
	})
	metrics = m.GetMetrics()
	if metrics.ScansTotal != 2 {
		t.Errorf("ScansTotal = %d, want 2", metrics.ScansTotal)
	}
	if metrics.DetectionsTotal != 1 {
		t.Errorf("DetectionsTotal = %d, want 1", metrics.DetectionsTotal)
	}
	if metrics.BlockedTotal != 1 {
		t.Errorf("BlockedTotal = %d, want 1", metrics.BlockedTotal)
	}

	// Reset metrics
	m.ResetMetrics()
	metrics = m.GetMetrics()
	if metrics.ScansTotal != 0 || metrics.DetectionsTotal != 0 || metrics.BlockedTotal != 0 {
		t.Error("Metrics should be zero after reset")
	}
}

func TestScanningMiddleware_UpdateConfig(t *testing.T) {
	m, _ := NewScanningMiddleware()

	// Update to valid config
	newCfg := DefaultConfig().WithResponseMode(ModeOff).WithBlockOnDetection(false)
	err := m.UpdateConfig(newCfg)
	if err != nil {
		t.Fatalf("UpdateConfig() error = %v", err)
	}

	// Verify scanning is now off
	ctx := context.Background()
	result, _ := m.ScanQueryResponse(ctx, "postgres", []map[string]interface{}{
		{"data": "' UNION SELECT * FROM users--"},
	})
	if result.Detected {
		t.Error("Should not detect when mode is off")
	}

	// Update to invalid config should fail
	invalidCfg := Config{
		InputMode:        Mode("invalid"),
		ResponseMode:     ModeBasic,
		MaxContentLength: 1000,
	}
	err = m.UpdateConfig(invalidCfg)
	if err == nil {
		t.Error("UpdateConfig() should return error for invalid config")
	}
}

func TestScanningMiddleware_RowsToContent(t *testing.T) {
	m, _ := NewScanningMiddleware()

	t.Run("empty rows", func(t *testing.T) {
		content := m.rowsToContent(nil)
		if content != "" {
			t.Errorf("rowsToContent(nil) = %q, want empty", content)
		}
	})

	t.Run("single row", func(t *testing.T) {
		rows := []map[string]interface{}{
			{"id": 1, "name": "test"},
		}
		content := m.rowsToContent(rows)
		if content == "" {
			t.Error("rowsToContent should return non-empty for rows")
		}
	})

	t.Run("large dataset truncated", func(t *testing.T) {
		// Create rows that would exceed max content length
		cfg := DefaultConfig()
		cfg.MaxContentLength = 100
		m, _ := NewScanningMiddleware(WithMiddlewareConfig(cfg))

		rows := make([]map[string]interface{}, 1000)
		for i := range rows {
			rows[i] = map[string]interface{}{
				"id":   i,
				"data": "This is a very long string that should cause truncation when scanning large datasets",
			}
		}

		content := m.rowsToContent(rows)
		if len(content) > cfg.MaxContentLength {
			t.Errorf("rowsToContent length = %d, want <= %d", len(content), cfg.MaxContentLength)
		}
	})
}

func TestGlobalMiddleware(t *testing.T) {
	// Reset global state for testing
	globalMiddlewareMu.Lock()
	globalMiddleware = nil
	globalMiddlewareMu.Unlock()

	t.Run("get returns initialized middleware", func(t *testing.T) {
		m := GetGlobalMiddleware()
		if m == nil {
			t.Fatal("GetGlobalMiddleware() returned nil")
		}

		// Should return same instance
		m2 := GetGlobalMiddleware()
		if m != m2 {
			t.Error("GetGlobalMiddleware() should return same instance")
		}
	})

	t.Run("set replaces middleware", func(t *testing.T) {
		custom, _ := NewScanningMiddleware(
			WithMiddlewareConfig(DefaultConfig().WithResponseMode(ModeOff)),
		)
		SetGlobalMiddleware(custom)

		m := GetGlobalMiddleware()
		if m != custom {
			t.Error("SetGlobalMiddleware should replace the instance")
		}
	})

	t.Run("init with config", func(t *testing.T) {
		cfg := DefaultConfig().WithInputMode(ModeOff).WithResponseMode(ModeBasic)
		err := InitGlobalMiddleware(cfg)
		if err != nil {
			t.Fatalf("InitGlobalMiddleware() error = %v", err)
		}

		m := GetGlobalMiddleware()
		if m == nil {
			t.Fatal("GetGlobalMiddleware() returned nil after init")
		}
	})

	t.Run("init with invalid config fails", func(t *testing.T) {
		cfg := Config{
			InputMode:        Mode("invalid"),
			ResponseMode:     ModeBasic,
			MaxContentLength: 1000,
		}
		err := InitGlobalMiddleware(cfg)
		if err == nil {
			t.Error("InitGlobalMiddleware should fail with invalid config")
		}
	})
}

func TestScanningMiddleware_ConcurrentAccess(t *testing.T) {
	m, _ := NewScanningMiddleware()
	ctx := context.Background()

	// Run concurrent scans
	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func(i int) {
			rows := []map[string]interface{}{
				{"id": i, "name": "test"},
			}
			m.ScanQueryResponse(ctx, "postgres", rows)
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("Concurrent scan timed out")
		}
	}

	// Verify metrics
	metrics := m.GetMetrics()
	if metrics.ScansTotal != 10 {
		t.Errorf("ScansTotal = %d, want 10", metrics.ScansTotal)
	}
}

func BenchmarkScanningMiddleware_ScanQueryResponse(b *testing.B) {
	m, _ := NewScanningMiddleware()
	ctx := context.Background()
	rows := []map[string]interface{}{
		{"id": 1, "name": "John Doe", "email": "john@example.com"},
		{"id": 2, "name": "Jane Smith", "email": "jane@example.com"},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.ScanQueryResponse(ctx, "postgres", rows)
	}
}

func BenchmarkScanningMiddleware_ScanQueryResponse_LargeDataset(b *testing.B) {
	m, _ := NewScanningMiddleware()
	ctx := context.Background()

	// Create a larger dataset
	rows := make([]map[string]interface{}, 100)
	for i := range rows {
		rows[i] = map[string]interface{}{
			"id":    i,
			"name":  "User " + string(rune('A'+i%26)),
			"email": "user" + string(rune('0'+i%10)) + "@example.com",
			"data":  "Some data content here that needs to be scanned",
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.ScanQueryResponse(ctx, "postgres", rows)
	}
}
