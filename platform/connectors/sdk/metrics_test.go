// Copyright 2025 AxonFlow
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package sdk

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestConnectorMetrics(t *testing.T) {
	t.Run("record query", func(t *testing.T) {
		metrics := NewConnectorMetrics("test-connector")

		metrics.RecordQuery(100*time.Millisecond, nil)
		metrics.RecordQuery(200*time.Millisecond, nil)
		metrics.RecordQuery(50*time.Millisecond, fmt.Errorf("error"))

		stats := metrics.GetStats()

		if stats.QueriesTotal != 3 {
			t.Errorf("expected 3 queries, got %d", stats.QueriesTotal)
		}

		if stats.ErrorsTotal != 1 {
			t.Errorf("expected 1 error, got %d", stats.ErrorsTotal)
		}

		// Average should be around (100+200+50)/3 = 116.67ms
		if stats.AvgQueryLatency < 100*time.Millisecond || stats.AvgQueryLatency > 130*time.Millisecond {
			t.Errorf("unexpected average latency: %v", stats.AvgQueryLatency)
		}
	})

	t.Run("record execute", func(t *testing.T) {
		metrics := NewConnectorMetrics("test-connector")

		metrics.RecordExecute(50*time.Millisecond, nil)
		metrics.RecordExecute(100*time.Millisecond, fmt.Errorf("error"))

		stats := metrics.GetStats()

		if stats.ExecutesTotal != 2 {
			t.Errorf("expected 2 executes, got %d", stats.ExecutesTotal)
		}

		if stats.ErrorsTotal != 1 {
			t.Errorf("expected 1 error, got %d", stats.ErrorsTotal)
		}
	})

	t.Run("record connect/disconnect", func(t *testing.T) {
		metrics := NewConnectorMetrics("test-connector")

		metrics.RecordConnect()
		stats := metrics.GetStats()

		if !stats.Connected {
			t.Error("expected connected to be true")
		}

		if stats.ConnectsTotal != 1 {
			t.Errorf("expected 1 connect, got %d", stats.ConnectsTotal)
		}

		metrics.RecordDisconnect()
		stats = metrics.GetStats()

		if stats.Connected {
			t.Error("expected connected to be false")
		}

		if stats.DisconnectsTotal != 1 {
			t.Errorf("expected 1 disconnect, got %d", stats.DisconnectsTotal)
		}
	})

	t.Run("reset", func(t *testing.T) {
		metrics := NewConnectorMetrics("test-connector")

		metrics.RecordQuery(100*time.Millisecond, nil)
		metrics.RecordExecute(50*time.Millisecond, nil)
		metrics.RecordConnect()

		metrics.Reset()

		stats := metrics.GetStats()

		if stats.QueriesTotal != 0 {
			t.Errorf("expected 0 queries after reset, got %d", stats.QueriesTotal)
		}

		if stats.ExecutesTotal != 0 {
			t.Errorf("expected 0 executes after reset, got %d", stats.ExecutesTotal)
		}
	})

	t.Run("connector type", func(t *testing.T) {
		metrics := NewConnectorMetrics("postgres")
		stats := metrics.GetStats()

		if stats.ConnectorType != "postgres" {
			t.Errorf("expected postgres, got %s", stats.ConnectorType)
		}
	})
}

func TestLatencyHistogram(t *testing.T) {
	t.Run("percentiles", func(t *testing.T) {
		hist := NewLatencyHistogram()

		// Add sorted samples for predictable percentiles
		for i := 1; i <= 100; i++ {
			hist.Record(time.Duration(i) * time.Millisecond)
		}

		p50 := hist.Percentile(0.5)
		if p50 < 45*time.Millisecond || p50 > 55*time.Millisecond {
			t.Errorf("expected p50 around 50ms, got %v", p50)
		}

		p99 := hist.Percentile(0.99)
		if p99 < 95*time.Millisecond {
			t.Errorf("expected p99 around 99ms, got %v", p99)
		}
	})

	t.Run("empty histogram", func(t *testing.T) {
		hist := NewLatencyHistogram()

		p50 := hist.Percentile(0.5)
		if p50 != 0 {
			t.Errorf("expected 0 for empty histogram, got %v", p50)
		}
	})

	t.Run("reset", func(t *testing.T) {
		hist := NewLatencyHistogram()

		hist.Record(100 * time.Millisecond)
		hist.Record(200 * time.Millisecond)

		if hist.Count() != 2 {
			t.Errorf("expected 2 samples, got %d", hist.Count())
		}

		hist.Reset()

		if hist.Count() != 0 {
			t.Errorf("expected 0 samples after reset, got %d", hist.Count())
		}
	})

	t.Run("sample eviction", func(t *testing.T) {
		hist := &LatencyHistogram{
			samples: make([]time.Duration, 0, 100),
			maxSize: 100,
		}

		// Fill beyond max
		for i := 0; i < 150; i++ {
			hist.Record(time.Duration(i) * time.Millisecond)
		}

		if hist.Count() > 100 {
			t.Errorf("expected at most 100 samples, got %d", hist.Count())
		}
	})
}

func TestPrometheusExporter(t *testing.T) {
	t.Run("export metrics", func(t *testing.T) {
		exporter := NewPrometheusExporter("axonflow")

		metrics1 := NewConnectorMetrics("postgres")
		metrics1.RecordConnect()
		metrics1.RecordQuery(100*time.Millisecond, nil)

		metrics2 := NewConnectorMetrics("mysql")
		metrics2.RecordConnect()
		metrics2.RecordExecute(50*time.Millisecond, nil)

		exporter.Register("db-postgres", metrics1)
		exporter.Register("db-mysql", metrics2)

		output := exporter.Export()

		// Check for expected metrics
		if !strings.Contains(output, "axonflow_db_postgres_queries_total 1") {
			t.Error("expected postgres queries metric")
		}

		if !strings.Contains(output, "axonflow_db_mysql_executes_total 1") {
			t.Error("expected mysql executes metric")
		}

		if !strings.Contains(output, "# HELP") {
			t.Error("expected HELP comments")
		}

		if !strings.Contains(output, "# TYPE") {
			t.Error("expected TYPE comments")
		}
	})

	t.Run("unregister", func(t *testing.T) {
		exporter := NewPrometheusExporter("axonflow")

		metrics := NewConnectorMetrics("test")
		exporter.Register("test", metrics)
		exporter.Unregister("test")

		output := exporter.Export()

		if strings.Contains(output, "test") {
			t.Error("unregistered metrics should not appear")
		}
	})
}

func TestSanitizeName(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"simple", "simple"},
		{"with-dash", "with_dash"},
		{"with.dot", "with_dot"},
		{"with spaces", "with_spaces"},
		{"MixedCase123", "MixedCase123"},
		{"special!@#$chars", "special____chars"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := sanitizeName(tt.input)
			if result != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, result)
			}
		})
	}
}

func TestAggregateMetrics(t *testing.T) {
	t.Run("aggregate totals", func(t *testing.T) {
		agg := NewAggregateMetrics()

		m1 := NewConnectorMetrics("type1")
		m1.RecordQuery(100*time.Millisecond, nil)
		m1.RecordQuery(100*time.Millisecond, nil)

		m2 := NewConnectorMetrics("type2")
		m2.RecordQuery(100*time.Millisecond, nil)
		m2.RecordExecute(50*time.Millisecond, nil)

		agg.Add("conn1", m1)
		agg.Add("conn2", m2)

		total := agg.GetTotal()

		if total.QueriesTotal != 3 {
			t.Errorf("expected 3 total queries, got %d", total.QueriesTotal)
		}

		if total.ExecutesTotal != 1 {
			t.Errorf("expected 1 total execute, got %d", total.ExecutesTotal)
		}
	})

	t.Run("get all snapshots", func(t *testing.T) {
		agg := NewAggregateMetrics()

		m1 := NewConnectorMetrics("type1")
		m2 := NewConnectorMetrics("type2")

		agg.Add("conn1", m1)
		agg.Add("conn2", m2)

		snapshots := agg.GetAll()

		if len(snapshots) != 2 {
			t.Errorf("expected 2 snapshots, got %d", len(snapshots))
		}

		if _, ok := snapshots["conn1"]; !ok {
			t.Error("expected conn1 in snapshots")
		}
	})

	t.Run("remove connector", func(t *testing.T) {
		agg := NewAggregateMetrics()

		m1 := NewConnectorMetrics("type1")
		agg.Add("conn1", m1)
		agg.Remove("conn1")

		snapshots := agg.GetAll()

		if len(snapshots) != 0 {
			t.Errorf("expected 0 snapshots after remove, got %d", len(snapshots))
		}
	})

	t.Run("connected status", func(t *testing.T) {
		agg := NewAggregateMetrics()

		m1 := NewConnectorMetrics("type1")
		m2 := NewConnectorMetrics("type2")

		agg.Add("conn1", m1)
		agg.Add("conn2", m2)

		// No connections
		if agg.GetTotal().Connected {
			t.Error("expected not connected when none connected")
		}

		// One connected
		m1.RecordConnect()
		if !agg.GetTotal().Connected {
			t.Error("expected connected when at least one connected")
		}
	})
}

func TestOperationTimer(t *testing.T) {
	timer := NewTimer()

	time.Sleep(10 * time.Millisecond)

	duration := timer.Duration()

	if duration < 10*time.Millisecond {
		t.Errorf("expected at least 10ms, got %v", duration)
	}
}

func TestOperationTimerRecordTo(t *testing.T) {
	timer := NewTimer()

	time.Sleep(5 * time.Millisecond)

	var recordedDuration time.Duration
	var recordedErr error

	expectedErr := fmt.Errorf("test error")

	timer.RecordTo(func(d time.Duration, err error) {
		recordedDuration = d
		recordedErr = err
	}, expectedErr)

	if recordedDuration < 5*time.Millisecond {
		t.Errorf("expected at least 5ms, got %v", recordedDuration)
	}

	if recordedErr != expectedErr {
		t.Errorf("expected error to be passed through")
	}
}

func TestConcurrentMetrics(t *testing.T) {
	metrics := NewConnectorMetrics("concurrent-test")

	var wg sync.WaitGroup

	// Concurrent queries
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				metrics.RecordQuery(time.Millisecond, nil)
			}
		}()
	}

	// Concurrent executes
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				metrics.RecordExecute(time.Millisecond, nil)
			}
		}()
	}

	wg.Wait()

	stats := metrics.GetStats()

	if stats.QueriesTotal != 10000 {
		t.Errorf("expected 10000 queries, got %d", stats.QueriesTotal)
	}

	if stats.ExecutesTotal != 5000 {
		t.Errorf("expected 5000 executes, got %d", stats.ExecutesTotal)
	}
}
