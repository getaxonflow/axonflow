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
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// ConnectorMetrics tracks metrics for a connector
type ConnectorMetrics struct {
	connectorType string

	// Counters
	queriesTotal     int64
	executesTotal    int64
	errorsTotal      int64
	connectsTotal    int64
	disconnectsTotal int64

	// Durations (nanoseconds)
	queryDurationTotal   int64
	executeDurationTotal int64
	queryCount           int64
	executeCount         int64

	// Current state
	connected int32

	// Histograms (simplified)
	queryLatencies   *LatencyHistogram
	executeLatencies *LatencyHistogram
}

// NewConnectorMetrics creates a new metrics collector
func NewConnectorMetrics(connectorType string) *ConnectorMetrics {
	return &ConnectorMetrics{
		connectorType:    connectorType,
		queryLatencies:   NewLatencyHistogram(),
		executeLatencies: NewLatencyHistogram(),
	}
}

// RecordQuery records a query operation
func (m *ConnectorMetrics) RecordQuery(duration time.Duration, err error) {
	atomic.AddInt64(&m.queriesTotal, 1)
	atomic.AddInt64(&m.queryDurationTotal, int64(duration))
	atomic.AddInt64(&m.queryCount, 1)

	if err != nil {
		atomic.AddInt64(&m.errorsTotal, 1)
	}

	m.queryLatencies.Record(duration)
}

// RecordExecute records an execute operation
func (m *ConnectorMetrics) RecordExecute(duration time.Duration, err error) {
	atomic.AddInt64(&m.executesTotal, 1)
	atomic.AddInt64(&m.executeDurationTotal, int64(duration))
	atomic.AddInt64(&m.executeCount, 1)

	if err != nil {
		atomic.AddInt64(&m.errorsTotal, 1)
	}

	m.executeLatencies.Record(duration)
}

// RecordConnect records a connect operation
func (m *ConnectorMetrics) RecordConnect() {
	atomic.AddInt64(&m.connectsTotal, 1)
	atomic.StoreInt32(&m.connected, 1)
}

// RecordDisconnect records a disconnect operation
func (m *ConnectorMetrics) RecordDisconnect() {
	atomic.AddInt64(&m.disconnectsTotal, 1)
	atomic.StoreInt32(&m.connected, 0)
}

// RecordError records an error
func (m *ConnectorMetrics) RecordError() {
	atomic.AddInt64(&m.errorsTotal, 1)
}

// GetStats returns current metrics
func (m *ConnectorMetrics) GetStats() *MetricsSnapshot {
	queryCount := atomic.LoadInt64(&m.queryCount)
	executeCount := atomic.LoadInt64(&m.executeCount)

	var avgQueryLatency, avgExecuteLatency time.Duration
	if queryCount > 0 {
		avgQueryLatency = time.Duration(atomic.LoadInt64(&m.queryDurationTotal) / queryCount)
	}
	if executeCount > 0 {
		avgExecuteLatency = time.Duration(atomic.LoadInt64(&m.executeDurationTotal) / executeCount)
	}

	return &MetricsSnapshot{
		ConnectorType:      m.connectorType,
		QueriesTotal:       atomic.LoadInt64(&m.queriesTotal),
		ExecutesTotal:      atomic.LoadInt64(&m.executesTotal),
		ErrorsTotal:        atomic.LoadInt64(&m.errorsTotal),
		ConnectsTotal:      atomic.LoadInt64(&m.connectsTotal),
		DisconnectsTotal:   atomic.LoadInt64(&m.disconnectsTotal),
		Connected:          atomic.LoadInt32(&m.connected) == 1,
		AvgQueryLatency:    avgQueryLatency,
		AvgExecuteLatency:  avgExecuteLatency,
		QueryLatencyP50:    m.queryLatencies.Percentile(0.5),
		QueryLatencyP95:    m.queryLatencies.Percentile(0.95),
		QueryLatencyP99:    m.queryLatencies.Percentile(0.99),
		ExecuteLatencyP50:  m.executeLatencies.Percentile(0.5),
		ExecuteLatencyP95:  m.executeLatencies.Percentile(0.95),
		ExecuteLatencyP99:  m.executeLatencies.Percentile(0.99),
	}
}

// Reset resets all metrics
func (m *ConnectorMetrics) Reset() {
	atomic.StoreInt64(&m.queriesTotal, 0)
	atomic.StoreInt64(&m.executesTotal, 0)
	atomic.StoreInt64(&m.errorsTotal, 0)
	atomic.StoreInt64(&m.connectsTotal, 0)
	atomic.StoreInt64(&m.disconnectsTotal, 0)
	atomic.StoreInt64(&m.queryDurationTotal, 0)
	atomic.StoreInt64(&m.executeDurationTotal, 0)
	atomic.StoreInt64(&m.queryCount, 0)
	atomic.StoreInt64(&m.executeCount, 0)

	m.queryLatencies.Reset()
	m.executeLatencies.Reset()
}

// MetricsSnapshot represents a point-in-time snapshot of metrics
type MetricsSnapshot struct {
	ConnectorType     string        `json:"connector_type"`
	QueriesTotal      int64         `json:"queries_total"`
	ExecutesTotal     int64         `json:"executes_total"`
	ErrorsTotal       int64         `json:"errors_total"`
	ConnectsTotal     int64         `json:"connects_total"`
	DisconnectsTotal  int64         `json:"disconnects_total"`
	Connected         bool          `json:"connected"`
	AvgQueryLatency   time.Duration `json:"avg_query_latency"`
	AvgExecuteLatency time.Duration `json:"avg_execute_latency"`
	QueryLatencyP50   time.Duration `json:"query_latency_p50"`
	QueryLatencyP95   time.Duration `json:"query_latency_p95"`
	QueryLatencyP99   time.Duration `json:"query_latency_p99"`
	ExecuteLatencyP50 time.Duration `json:"execute_latency_p50"`
	ExecuteLatencyP95 time.Duration `json:"execute_latency_p95"`
	ExecuteLatencyP99 time.Duration `json:"execute_latency_p99"`
}

// LatencyHistogram provides simple percentile calculations
type LatencyHistogram struct {
	samples []time.Duration
	maxSize int
	mu      sync.Mutex
}

// NewLatencyHistogram creates a new latency histogram
func NewLatencyHistogram() *LatencyHistogram {
	return &LatencyHistogram{
		samples: make([]time.Duration, 0, 1000),
		maxSize: 10000,
	}
}

// Record adds a latency sample
func (h *LatencyHistogram) Record(d time.Duration) {
	h.mu.Lock()
	defer h.mu.Unlock()

	if len(h.samples) >= h.maxSize {
		// Remove oldest samples
		h.samples = h.samples[len(h.samples)/2:]
	}
	h.samples = append(h.samples, d)
}

// Percentile calculates the given percentile
func (h *LatencyHistogram) Percentile(p float64) time.Duration {
	h.mu.Lock()
	defer h.mu.Unlock()

	if len(h.samples) == 0 {
		return 0
	}

	sorted := make([]time.Duration, len(h.samples))
	copy(sorted, h.samples)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })

	idx := int(float64(len(sorted)-1) * p)
	return sorted[idx]
}

// Reset clears all samples
func (h *LatencyHistogram) Reset() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.samples = h.samples[:0]
}

// Count returns the number of samples
func (h *LatencyHistogram) Count() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.samples)
}

// PrometheusExporter exports metrics in Prometheus format
type PrometheusExporter struct {
	namespace string
	metrics   map[string]*ConnectorMetrics
	mu        sync.RWMutex
}

// NewPrometheusExporter creates a new Prometheus exporter
func NewPrometheusExporter(namespace string) *PrometheusExporter {
	return &PrometheusExporter{
		namespace: namespace,
		metrics:   make(map[string]*ConnectorMetrics),
	}
}

// Register registers a connector's metrics
func (p *PrometheusExporter) Register(name string, metrics *ConnectorMetrics) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.metrics[name] = metrics
}

// Unregister removes a connector's metrics
func (p *PrometheusExporter) Unregister(name string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.metrics, name)
}

// Export returns metrics in Prometheus text format
func (p *PrometheusExporter) Export() string {
	p.mu.RLock()
	defer p.mu.RUnlock()

	var output string

	for name, m := range p.metrics {
		stats := m.GetStats()
		prefix := fmt.Sprintf("%s_%s", p.namespace, sanitizeName(name))

		// Counters
		output += fmt.Sprintf("# HELP %s_queries_total Total number of queries\n", prefix)
		output += fmt.Sprintf("# TYPE %s_queries_total counter\n", prefix)
		output += fmt.Sprintf("%s_queries_total %d\n", prefix, stats.QueriesTotal)

		output += fmt.Sprintf("# HELP %s_executes_total Total number of executes\n", prefix)
		output += fmt.Sprintf("# TYPE %s_executes_total counter\n", prefix)
		output += fmt.Sprintf("%s_executes_total %d\n", prefix, stats.ExecutesTotal)

		output += fmt.Sprintf("# HELP %s_errors_total Total number of errors\n", prefix)
		output += fmt.Sprintf("# TYPE %s_errors_total counter\n", prefix)
		output += fmt.Sprintf("%s_errors_total %d\n", prefix, stats.ErrorsTotal)

		// Gauges
		connected := 0
		if stats.Connected {
			connected = 1
		}
		output += fmt.Sprintf("# HELP %s_connected Whether the connector is connected\n", prefix)
		output += fmt.Sprintf("# TYPE %s_connected gauge\n", prefix)
		output += fmt.Sprintf("%s_connected %d\n", prefix, connected)

		// Histograms (summary format)
		output += fmt.Sprintf("# HELP %s_query_latency_seconds Query latency distribution\n", prefix)
		output += fmt.Sprintf("# TYPE %s_query_latency_seconds summary\n", prefix)
		output += fmt.Sprintf("%s_query_latency_seconds{quantile=\"0.5\"} %f\n", prefix, stats.QueryLatencyP50.Seconds())
		output += fmt.Sprintf("%s_query_latency_seconds{quantile=\"0.95\"} %f\n", prefix, stats.QueryLatencyP95.Seconds())
		output += fmt.Sprintf("%s_query_latency_seconds{quantile=\"0.99\"} %f\n", prefix, stats.QueryLatencyP99.Seconds())

		output += fmt.Sprintf("# HELP %s_execute_latency_seconds Execute latency distribution\n", prefix)
		output += fmt.Sprintf("# TYPE %s_execute_latency_seconds summary\n", prefix)
		output += fmt.Sprintf("%s_execute_latency_seconds{quantile=\"0.5\"} %f\n", prefix, stats.ExecuteLatencyP50.Seconds())
		output += fmt.Sprintf("%s_execute_latency_seconds{quantile=\"0.95\"} %f\n", prefix, stats.ExecuteLatencyP95.Seconds())
		output += fmt.Sprintf("%s_execute_latency_seconds{quantile=\"0.99\"} %f\n", prefix, stats.ExecuteLatencyP99.Seconds())

		output += "\n"
	}

	return output
}

// sanitizeName converts a name to Prometheus-compatible format
func sanitizeName(name string) string {
	result := make([]byte, 0, len(name))
	for _, c := range []byte(name) {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' {
			result = append(result, c)
		} else {
			result = append(result, '_')
		}
	}
	return string(result)
}

// AggregateMetrics aggregates metrics from multiple connectors
type AggregateMetrics struct {
	connectors map[string]*ConnectorMetrics
	mu         sync.RWMutex
}

// NewAggregateMetrics creates a new aggregate metrics collector
func NewAggregateMetrics() *AggregateMetrics {
	return &AggregateMetrics{
		connectors: make(map[string]*ConnectorMetrics),
	}
}

// Add adds a connector's metrics to the aggregate
func (a *AggregateMetrics) Add(name string, metrics *ConnectorMetrics) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.connectors[name] = metrics
}

// Remove removes a connector's metrics from the aggregate
func (a *AggregateMetrics) Remove(name string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.connectors, name)
}

// GetAll returns all connector snapshots
func (a *AggregateMetrics) GetAll() map[string]*MetricsSnapshot {
	a.mu.RLock()
	defer a.mu.RUnlock()

	result := make(map[string]*MetricsSnapshot)
	for name, m := range a.connectors {
		result[name] = m.GetStats()
	}
	return result
}

// GetTotal returns aggregated totals
func (a *AggregateMetrics) GetTotal() *MetricsSnapshot {
	a.mu.RLock()
	defer a.mu.RUnlock()

	total := &MetricsSnapshot{}
	connectedCount := 0

	for _, m := range a.connectors {
		stats := m.GetStats()
		total.QueriesTotal += stats.QueriesTotal
		total.ExecutesTotal += stats.ExecutesTotal
		total.ErrorsTotal += stats.ErrorsTotal
		total.ConnectsTotal += stats.ConnectsTotal
		total.DisconnectsTotal += stats.DisconnectsTotal
		if stats.Connected {
			connectedCount++
		}
	}

	total.Connected = connectedCount > 0
	return total
}

// OperationTimer provides convenient timing for operations
type OperationTimer struct {
	start time.Time
}

// NewTimer starts a new timer
func NewTimer() *OperationTimer {
	return &OperationTimer{start: time.Now()}
}

// Duration returns the elapsed time since the timer was started
func (t *OperationTimer) Duration() time.Duration {
	return time.Since(t.start)
}

// RecordTo records the duration to the given callback
func (t *OperationTimer) RecordTo(record func(time.Duration, error), err error) {
	record(t.Duration(), err)
}
