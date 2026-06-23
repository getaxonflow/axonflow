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

package telemetry

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

// fakeSink is a controllable CentralStoreSink for exercising the exporter's
// success / sink-down / timeout / breaker / drain paths without a real backend.
type fakeSink struct {
	mu      sync.Mutex
	shipped []DecisionRecord

	err   error         // returned by Ship when set
	block bool          // when set, Ship blocks until ctx is cancelled
	delay time.Duration // when set, Ship sleeps (ctx-aware) before returning

	closedCalls int
}

func (f *fakeSink) Name() string { return "fake" }

func (f *fakeSink) Ship(ctx context.Context, record DecisionRecord) error {
	if f.block {
		<-ctx.Done()
		return ctx.Err()
	}
	if f.delay > 0 {
		select {
		case <-time.After(f.delay):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if f.err != nil {
		return f.err
	}
	f.mu.Lock()
	f.shipped = append(f.shipped, record)
	f.mu.Unlock()
	return nil
}

func (f *fakeSink) Close(context.Context) error {
	f.mu.Lock()
	f.closedCalls++
	f.mu.Unlock()
	return nil
}

func (f *fakeSink) shippedCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.shipped)
}

// waitFor polls cond until it returns true or the deadline passes. Keeps the
// async exporter tests deterministic without fixed sleeps.
func waitFor(t *testing.T, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("condition not met within %s", timeout)
}

func testConfig() exporterConfig {
	return exporterConfig{
		timeout:          50 * time.Millisecond,
		breakerThreshold: 3,
		breakerCooldown:  time.Second,
		buffer:           16,
	}
}

func sampleEvent() DecisionEvent {
	return DecisionEvent{
		DecisionID: "dec-123",
		OrgID:      "org-1",
		TenantID:   "tenant-1",
		Stage:      "tool",
		Verdict:    "allow",
		PolicyIDs:  []string{"indonesia_pii_protection"},
		LatencyMs:  7,
		Reasons:    []string{"ok"},
		Context:    map[string]string{"x_session_id": "sess-9"},
	}
}

func TestCentralStoreExporter_ShipsRecordsOnSuccess(t *testing.T) {
	sink := &fakeSink{}
	exp := newExporterWithSink(sink, testConfig())
	defer exp.Close(context.Background())

	exp.ExportEvent(sampleEvent(), "trace-abc")

	waitFor(t, 2*time.Second, func() bool { return sink.shippedCount() == 1 })

	got := exp.Stats()
	if got.Shipped != 1 || got.Enqueued != 1 || got.Failed != 0 || got.Dropped != 0 || got.Skipped != 0 {
		t.Fatalf("unexpected stats: %+v", got)
	}

	sink.mu.Lock()
	rec := sink.shipped[0]
	sink.mu.Unlock()
	if rec.DecisionID != "dec-123" || rec.TraceID != "trace-abc" {
		t.Fatalf("record fields wrong: %+v", rec)
	}
	if rec.Context["x_session_id"] != "sess-9" {
		t.Fatalf("x_session_id correlation key not shipped: %+v", rec.Context)
	}
	if rec.Timestamp == "" {
		t.Fatal("record must carry a timestamp")
	}
}

func TestCentralStoreExporter_SinkDownTripsBreaker(t *testing.T) {
	sink := &fakeSink{err: errors.New("sink unavailable")}
	cfg := testConfig() // breakerThreshold = 3
	exp := newExporterWithSink(sink, cfg)
	defer exp.Close(context.Background())

	// 3 failures trip the breaker; the 4th+ are short-circuited (skipped).
	for i := 0; i < 6; i++ {
		exp.ExportEvent(sampleEvent(), "")
	}

	waitFor(t, 2*time.Second, func() bool {
		s := exp.Stats()
		return s.Failed == 3 && s.Skipped >= 1
	})

	s := exp.Stats()
	if s.Failed != 3 {
		t.Fatalf("expected exactly 3 ship attempts before breaker opens, got %d", s.Failed)
	}
	if s.Shipped != 0 {
		t.Fatalf("no record should have shipped to a down sink, got %d", s.Shipped)
	}
	if s.Skipped < 1 {
		t.Fatalf("breaker should have skipped post-trip records, got %d", s.Skipped)
	}
	if exp.breaker.State() != breakerOpen {
		t.Fatalf("breaker should be open after repeated failures, got %v", exp.breaker.State())
	}
}

func TestCentralStoreExporter_TimeoutCountsAsFailure(t *testing.T) {
	sink := &fakeSink{block: true} // never returns until ctx times out
	cfg := testConfig()
	cfg.timeout = 30 * time.Millisecond
	exp := newExporterWithSink(sink, cfg)
	defer exp.Close(context.Background())

	exp.ExportEvent(sampleEvent(), "")

	waitFor(t, 2*time.Second, func() bool { return exp.Stats().Failed == 1 })

	if exp.Stats().Shipped != 0 {
		t.Fatal("a timed-out ship must not count as shipped")
	}
}

func TestCentralStoreExporter_FullBufferDropsRecords(t *testing.T) {
	// A blocking sink keeps the worker busy on the first record; with a buffer
	// of 1, everything past (in-flight + buffered) is dropped, never blocking.
	sink := &fakeSink{block: true}
	cfg := exporterConfig{
		timeout:          time.Hour, // worker stays blocked on record #1
		breakerThreshold: 100,
		breakerCooldown:  time.Second,
		buffer:           1,
	}
	exp := newExporterWithSink(sink, cfg)

	const n = 50
	for i := 0; i < n; i++ {
		exp.Export(DecisionRecord{DecisionID: "d", Timestamp: time.Now().UTC().Format(time.RFC3339Nano)})
	}

	s := exp.Stats()
	if s.Enqueued+s.Dropped != n {
		t.Fatalf("every Export must be either enqueued or dropped: enqueued=%d dropped=%d (want sum %d)", s.Enqueued, s.Dropped, n)
	}
	if s.Dropped == 0 {
		t.Fatal("a full buffer with a blocked worker must drop records")
	}

	// Close with a short deadline: the worker is wedged on the blocking sink,
	// so Close must return the deadline error rather than hang forever.
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := exp.Close(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Close on a wedged worker should return DeadlineExceeded, got %v", err)
	}
}

func TestCentralStoreExporter_CloseDrainsBufferedRecords(t *testing.T) {
	sink := &fakeSink{}
	exp := newExporterWithSink(sink, testConfig())

	for i := 0; i < 5; i++ {
		exp.ExportEvent(sampleEvent(), "")
	}
	if err := exp.Close(context.Background()); err != nil {
		t.Fatalf("Close returned error: %v", err)
	}
	if sink.shippedCount() != 5 {
		t.Fatalf("Close should drain all buffered records; shipped %d/5", sink.shippedCount())
	}
	// Sink closed exactly once.
	sink.mu.Lock()
	closes := sink.closedCalls
	sink.mu.Unlock()
	if closes != 1 {
		t.Fatalf("sink Close called %d times, want 1", closes)
	}
}

func TestCentralStoreExporter_AfterCloseExportIsNoop(t *testing.T) {
	sink := &fakeSink{}
	exp := newExporterWithSink(sink, testConfig())
	if err := exp.Close(context.Background()); err != nil {
		t.Fatalf("Close error: %v", err)
	}
	// Idempotent close.
	if err := exp.Close(context.Background()); err != nil {
		t.Fatalf("second Close error: %v", err)
	}
	// Export after close must not panic and must not enqueue.
	exp.ExportEvent(sampleEvent(), "")
	if exp.Stats().Enqueued != 0 {
		t.Fatalf("Export after Close must be a no-op, enqueued=%d", exp.Stats().Enqueued)
	}
}

func TestCentralStoreExporter_DropIsObservable(t *testing.T) {
	// A dropped audit record must not be silent: it increments the dropped
	// metric and fires the (rate-limited) WARN, not just a private counter.
	before := testutil.ToFloat64(centralStoreRecordsTotal.WithLabelValues("dropped"))

	sink := &fakeSink{block: true} // worker wedged on record #1 so the rest drop
	cfg := exporterConfig{timeout: time.Hour, breakerThreshold: 100, breakerCooldown: time.Second, buffer: 1}
	exp := newExporterWithSink(sink, cfg)

	for i := 0; i < 50; i++ {
		exp.Export(DecisionRecord{DecisionID: "d", Timestamp: "2026-06-22T00:00:00Z"})
	}

	if exp.Stats().Dropped == 0 {
		t.Fatal("expected drops to force the observable path")
	}
	after := testutil.ToFloat64(centralStoreRecordsTotal.WithLabelValues("dropped"))
	if delta := after - before; delta < 1 {
		t.Fatalf("dropped metric did not increase: delta=%v", delta)
	}
	// The WARN slot was claimed (lastDropWarnNanos stamped), so the loss was
	// logged rather than silently swallowed.
	if exp.lastDropWarnNanos.Load() == 0 {
		t.Fatal("warnDropped did not fire on the first drop")
	}

	// Don't block on the wedged sink at teardown.
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_ = exp.Close(ctx)
}

func TestCentralStoreExporter_ConcurrentExportAndCloseNoPanic(t *testing.T) {
	// Regression for the shutdown-time "send on closed channel" race: many
	// Exports hammering the queue while Close fires mid-flight must never panic.
	// Run under -race; the loop makes the interleaving likely to hit the window.
	for iter := 0; iter < 50; iter++ {
		sink := &fakeSink{}
		exp := newExporterWithSink(sink, testConfig())

		var wg sync.WaitGroup
		for g := 0; g < 8; g++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for i := 0; i < 200; i++ {
					exp.Export(DecisionRecord{DecisionID: "d", Timestamp: "2026-06-22T00:00:00Z"})
				}
			}()
		}
		// Close concurrently with the in-flight Exports.
		if err := exp.Close(context.Background()); err != nil {
			t.Fatalf("iter %d: Close error: %v", iter, err)
		}
		wg.Wait()
		// Every Export must have been accounted for exactly once.
		s := exp.Stats()
		if s.Enqueued+s.Dropped > 8*200 {
			t.Fatalf("iter %d: over-counted exports: %+v", iter, s)
		}
	}
}

func TestCentralStoreExporter_NilReceiverSafe(t *testing.T) {
	var exp *CentralStoreExporter
	// All entry points must be safe on a nil exporter (the disabled case).
	exp.Export(DecisionRecord{})
	exp.ExportEvent(sampleEvent(), "")
	if (exp.Stats() != Stats{}) {
		t.Fatal("nil exporter Stats must be the zero value")
	}
	if err := exp.Close(context.Background()); err != nil {
		t.Fatalf("nil exporter Close must be nil, got %v", err)
	}
}

func TestRecordFromEvent_ProjectsAllFields(t *testing.T) {
	now := time.Date(2026, 6, 22, 12, 30, 0, 0, time.UTC)
	evt := sampleEvent()
	evt.GatewayID = "claude_desktop.host-1"
	evt.ContextTruncated = true

	rec := RecordFromEvent(evt, "trace-xyz", now)

	if rec.DecisionID != evt.DecisionID || rec.OrgID != evt.OrgID || rec.TenantID != evt.TenantID {
		t.Fatalf("identity fields not projected: %+v", rec)
	}
	if rec.GatewayID != "claude_desktop.host-1" || !rec.ContextTruncated {
		t.Fatalf("gateway/truncated not projected: %+v", rec)
	}
	if rec.Stage != "tool" || rec.Verdict != "allow" || rec.LatencyMs != 7 {
		t.Fatalf("decision fields not projected: %+v", rec)
	}
	if rec.TraceID != "trace-xyz" {
		t.Fatalf("trace id not projected: %q", rec.TraceID)
	}
	if rec.Timestamp != "2026-06-22T12:30:00Z" {
		t.Fatalf("timestamp = %q, want RFC3339 UTC", rec.Timestamp)
	}

	// Round-trips through JSON with the documented snake_case keys.
	data, err := marshalRecord(rec)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if data[len(data)-1] != '\n' {
		t.Fatal("marshalRecord must terminate with a newline (NDJSON)")
	}
	var back map[string]any
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, k := range []string{"timestamp", "decision_id", "stage", "verdict", "latency_ms", "trace_id", "context"} {
		if _, ok := back[k]; !ok {
			t.Fatalf("expected JSON key %q in %s", k, data)
		}
	}
}

func TestResolveExporterConfig_DefaultsAndClamps(t *testing.T) {
	// Clear all knobs → defaults.
	for _, k := range []string{envAuditTimeoutMs, envAuditBreakerThreshold, envAuditBreakerCooldownMs, envAuditBuffer} {
		t.Setenv(k, "")
	}
	cfg := resolveExporterConfig()
	if cfg.timeout != defaultAuditTimeout || cfg.breakerThreshold != defaultBreakerThreshold ||
		cfg.breakerCooldown != defaultBreakerCooldown || cfg.buffer != defaultAuditBuffer {
		t.Fatalf("defaults wrong: %+v", cfg)
	}

	// Out-of-range values clamp.
	t.Setenv(envAuditTimeoutMs, "1")              // below min → clamps up
	t.Setenv(envAuditBreakerCooldownMs, "10")     // below min → clamps up
	t.Setenv(envAuditBuffer, "999999")            // above max → clamps down
	t.Setenv(envAuditBreakerThreshold, "garbage") // invalid → default
	cfg = resolveExporterConfig()
	if cfg.timeout != minAuditTimeout {
		t.Fatalf("timeout = %s, want clamped to min %s", cfg.timeout, minAuditTimeout)
	}
	if cfg.breakerCooldown != minBreakerCooldown {
		t.Fatalf("cooldown = %s, want clamped to min %s", cfg.breakerCooldown, minBreakerCooldown)
	}
	if cfg.buffer != maxAuditBuffer {
		t.Fatalf("buffer = %d, want clamped to max %d", cfg.buffer, maxAuditBuffer)
	}
	if cfg.breakerThreshold != defaultBreakerThreshold {
		t.Fatalf("invalid threshold should fall back to default, got %d", cfg.breakerThreshold)
	}

	// Valid in-range overrides are honored.
	t.Setenv(envAuditTimeoutMs, "2000")
	t.Setenv(envAuditBreakerThreshold, "9")
	t.Setenv(envAuditBreakerCooldownMs, "15000")
	t.Setenv(envAuditBuffer, "42")
	cfg = resolveExporterConfig()
	if cfg.timeout != 2*time.Second || cfg.breakerThreshold != 9 ||
		cfg.breakerCooldown != 15*time.Second || cfg.buffer != 42 {
		t.Fatalf("valid overrides not honored: %+v", cfg)
	}
}

// fakeInnerTracer records the events passed to it and returns a fixed trace id,
// standing in for the noop/OTLP tracer the recording decorator wraps.
type fakeInnerTracer struct {
	traceID string
	mu      sync.Mutex
	events  []DecisionEvent
}

func (f *fakeInnerTracer) RecordDecision(_ context.Context, evt DecisionEvent) string {
	f.mu.Lock()
	f.events = append(f.events, evt)
	f.mu.Unlock()
	return f.traceID
}

func TestRecordingTracer_ShipsAndPreservesTraceID(t *testing.T) {
	inner := &fakeInnerTracer{traceID: "trace-from-inner"}
	sink := &fakeSink{}
	exp := newExporterWithSink(sink, testConfig())
	defer exp.Close(context.Background())

	rt := &recordingTracer{inner: inner, exporter: exp}
	got := rt.RecordDecision(context.Background(), sampleEvent())

	if got != "trace-from-inner" {
		t.Fatalf("recordingTracer must return the inner trace id unchanged, got %q", got)
	}
	waitFor(t, 2*time.Second, func() bool { return sink.shippedCount() == 1 })

	sink.mu.Lock()
	rec := sink.shipped[0]
	sink.mu.Unlock()
	if rec.TraceID != "trace-from-inner" || rec.DecisionID != "dec-123" {
		t.Fatalf("shipped record did not carry the inner trace id / decision: %+v", rec)
	}
}

func TestWrapWithExporter_DecoratesAndDrainsOnShutdown(t *testing.T) {
	inner := &fakeInnerTracer{traceID: "tid"}
	baseShutdownCalled := false
	base := &Provider{
		Tracer:   inner,
		shutdown: func(context.Context) error { baseShutdownCalled = true; return nil },
	}
	sink := &fakeSink{}
	exp := newExporterWithSink(sink, testConfig())

	wrapped := wrapWithExporter(base, exp)

	// RecordDecision flows through the decorator: inner records, record ships.
	if got := wrapped.Tracer.RecordDecision(context.Background(), sampleEvent()); got != "tid" {
		t.Fatalf("wrapped tracer trace id = %q, want tid", got)
	}

	// Shutdown drains + closes the exporter AND calls the base shutdown.
	if err := wrapped.Shutdown(context.Background()); err != nil {
		t.Fatalf("wrapped Shutdown error: %v", err)
	}
	if !baseShutdownCalled {
		t.Fatal("wrapped Shutdown must call the base provider's shutdown")
	}
	if sink.shippedCount() != 1 {
		t.Fatalf("Shutdown should drain the in-flight record, shipped %d", sink.shippedCount())
	}
	sink.mu.Lock()
	closes := sink.closedCalls
	sink.mu.Unlock()
	if closes != 1 {
		t.Fatalf("Shutdown should close the sink once, got %d", closes)
	}
}

func TestNewDecisionTracer_AuditSinkWrapsTracer(t *testing.T) {
	// With no OTel endpoint and no audit sink, the provider is the bare noop.
	t.Setenv("AXONFLOW_OTEL_ENDPOINT", "")
	t.Setenv(envAuditSink, "")
	if p := NewDecisionTracer(context.Background()); p == nil {
		t.Fatal("expected non-nil provider")
	} else if _, ok := p.Tracer.(noopTracer); !ok {
		t.Fatalf("no audit sink: tracer should be bare noop, got %T", p.Tracer)
	}

	// With the s3 audit sink configured, the tracer is wrapped in the recording
	// decorator (exporter active), proving the env-to-wrap path end to end.
	t.Setenv(envAuditSink, "s3")
	t.Setenv(envS3Bucket, "audit-bucket")
	p := NewDecisionTracer(context.Background())
	if _, ok := p.Tracer.(*recordingTracer); !ok {
		t.Fatalf("audit sink set: tracer should be *recordingTracer, got %T", p.Tracer)
	}
	if err := p.Shutdown(context.Background()); err != nil {
		t.Fatalf("Shutdown error: %v", err)
	}
}

func TestNewCentralStoreExporter_DisabledWhenSinkEmpty(t *testing.T) {
	t.Setenv(envAuditSink, "")
	if exp := NewCentralStoreExporter(context.Background()); exp != nil {
		t.Fatalf("empty %s must yield a nil (disabled) exporter, got %T", envAuditSink, exp)
	}
}

func TestNewCentralStoreExporter_UnknownSinkDisables(t *testing.T) {
	t.Setenv(envAuditSink, "kafka") // unsupported
	if exp := NewCentralStoreExporter(context.Background()); exp != nil {
		t.Fatalf("unknown sink must disable the exporter, got %T", exp)
	}
}

func TestNewCentralStoreExporter_S3MissingBucketDisables(t *testing.T) {
	t.Setenv(envAuditSink, "s3")
	t.Setenv(envS3Bucket, "") // required → construction fails → disabled
	if exp := NewCentralStoreExporter(context.Background()); exp != nil {
		t.Fatalf("s3 sink with no bucket must disable the exporter, got %T", exp)
	}
}
