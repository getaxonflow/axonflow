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

// Central-store audit exporter.
//
// The decision tracer (decision_tracer.go) ships one OTel span per decision to
// an OTLP collector. That is the live, low-latency correlation feed. This file
// adds the *durable* half of the Week-3 SIEM story: it ships the same decision
// as a structured JSON record to a central store (S3 today, the landing zone a
// BigQuery / Athena / Snowflake load job reads) so an auditor can join the
// AxonFlow decision row to BigQuery Cloud Audit Logs on decision_id /
// x_session_id long after the trace's retention window has closed.
//
// Turning that from a "documented integration step" into a turnkey path is the
// whole point: set AXONFLOW_AUDIT_SINK=s3 plus a bucket and decisions start
// landing in the central store, no bespoke pipeline to write.
//
// Three safety rules, in priority order, keep this off the hot path:
//
//  1. Non-blocking. Export() enqueues to a bounded buffer and returns. A full
//     buffer drops the record rather than stalling the decision, and because a
//     dropped audit record is silent data loss it is counted, metered, and
//     WARN-logged (rate-limited) so the loss is observable.
//  2. Bounded. Every ship is wrapped in a per-call timeout so a wedged sink
//     cannot pin a worker goroutine forever.
//  3. Self-isolating. A circuit breaker trips after N consecutive failures and
//     short-circuits further ships for a cooldown, so a dead sink stops
//     generating timeout latency and error-log spam until it recovers.
//
// Like the tracer, the exporter is opt-in: AXONFLOW_AUDIT_SINK empty (the
// default) yields a nil exporter and the decision path is byte-for-byte
// unchanged. Any construction failure logs at WARN and disables the exporter;
// audit shipping is observability, never a hard boot dependency.
package telemetry

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// centralStoreRecordsTotal counts decision records by central-store exporter
// outcome so an operator can alert on drops/failures from the agent's existing
// /metrics endpoint. "dropped" in particular is silent audit-record loss (the
// buffer was full), so it MUST be observable, not just a private counter.
var centralStoreRecordsTotal = promauto.NewCounterVec(
	prometheus.CounterOpts{
		Name: "axonflow_central_store_records_total",
		Help: "Decision records processed by the central-store audit exporter, by outcome (shipped, dropped, failed, skipped).",
	},
	[]string{"outcome"},
)

// Env vars consumed by NewCentralStoreExporter.
const (
	// envAuditSink selects the central-store backend. Empty (default) disables
	// the exporter entirely. Supported: "s3". The value is lower-cased and
	// trimmed; an unrecognized value logs WARN and disables the exporter.
	envAuditSink = "AXONFLOW_AUDIT_SINK"

	// envAuditTimeoutMs bounds a single ship to the sink (default 5000ms). The
	// value is clamped to [100, 60000]ms. A sub-100ms budget makes any real
	// network sink fail spuriously; a >60s budget defeats the purpose.
	envAuditTimeoutMs = "AXONFLOW_AUDIT_SINK_TIMEOUT_MS"

	// envAuditBreakerThreshold is the consecutive-failure count that trips the
	// circuit breaker open (default 5, min 1).
	envAuditBreakerThreshold = "AXONFLOW_AUDIT_SINK_BREAKER_THRESHOLD"

	// envAuditBreakerCooldownMs is how long the breaker stays open before it
	// admits a single probe (default 30000ms, min 1000ms).
	envAuditBreakerCooldownMs = "AXONFLOW_AUDIT_SINK_BREAKER_COOLDOWN_MS"

	// envAuditBuffer is the depth of the non-blocking export queue (default
	// 1024, clamped to [1, 65536]). A full queue drops records (counted in the
	// Dropped stat) rather than blocking the decision path.
	envAuditBuffer = "AXONFLOW_AUDIT_SINK_BUFFER"
)

const (
	defaultAuditTimeout     = 5 * time.Second
	minAuditTimeout         = 100 * time.Millisecond
	maxAuditTimeout         = 60 * time.Second
	defaultBreakerThreshold = 5
	defaultBreakerCooldown  = 30 * time.Second
	minBreakerCooldown      = 1 * time.Second
	defaultAuditBuffer      = 1024
	maxAuditBuffer          = 65536

	// dropWarnInterval bounds how often the buffer-full WARN is emitted so a
	// sustained sink outage does not flood the log; the running Dropped total is
	// included so each line is still actionable.
	dropWarnInterval = 30 * time.Second
)

// DecisionRecord is the durable, central-store shape of one policy decision.
// It is a superset of DecisionEvent (the span payload) plus a wall-clock
// Timestamp and the resolved TraceID, with snake_case JSON tags that match the
// AxonFlow audit vocabulary, the reference Layer 1 adapter, and the SIEM
// correlation recipe so a BigQuery/Athena schema maps one-to-one.
//
// The join keys an auditor correlates on are DecisionID (per-call, always
// present) and the x_session_id carried inside Context (per-session, when the
// PEP forwards it). Both are emitted verbatim so the SIEM join is deterministic.
type DecisionRecord struct {
	// Timestamp is the RFC 3339 / ISO 8601 UTC instant the record was emitted,
	// stamped at export time (~decision time). SIEM joins normalize on UTC.
	Timestamp string `json:"timestamp"`

	// DecisionID is the per-call join key (UUID/ULID). Always present.
	DecisionID string `json:"decision_id"`

	// OrgID / TenantID scope the decision to an AxonFlow tenant.
	OrgID    string `json:"org_id,omitempty"`
	TenantID string `json:"tenant_id,omitempty"`

	// GatewayID is the gateway-asserted origin (e.g. claude_desktop.<host>),
	// omitted when the caller asserted none.
	GatewayID string `json:"gateway_id,omitempty"`

	// Stage names the decision plane: "llm" | "tool" | "agent".
	Stage string `json:"stage"`

	// Verdict is the decision outcome span label (allow | deny | needs_approval
	// | error). This is the observability label, NOT the PEP wire verdict.
	Verdict string `json:"verdict"`

	// PolicyIDs lists the policies evaluated for this decision.
	PolicyIDs []string `json:"policy_ids,omitempty"`

	// LatencyMs is the decision-handler latency in milliseconds.
	LatencyMs int64 `json:"latency_ms"`

	// Reasons lists human-readable verdict reasons.
	Reasons []string `json:"reasons,omitempty"`

	// TraceID is the W3C trace id (32-char hex) the tracer allocated, or empty
	// when OTel is disabled. Lets a record stitch back to its span.
	TraceID string `json:"trace_id,omitempty"`

	// Context carries the sanitized, allowlist-filtered request context the PEP
	// attached (x_session_id, x_ai_agent, x_leader_identity, x-tenant-*). Keys
	// are already canonical lower_snake_case. x_session_id here is the
	// per-session SIEM join key.
	Context map[string]string `json:"context,omitempty"`

	// ContextTruncated is set when the request carried more context keys than
	// the cap allowed and the surplus was dropped.
	ContextTruncated bool `json:"context_truncated,omitempty"`
}

// RecordFromEvent projects a DecisionEvent plus its resolved trace id into a
// durable DecisionRecord, stamping the current UTC time. Pure except for the
// clock; the clock is injectable on the exporter for tests.
func RecordFromEvent(evt DecisionEvent, traceID string, now time.Time) DecisionRecord {
	return DecisionRecord{
		Timestamp:        now.UTC().Format(time.RFC3339Nano),
		DecisionID:       evt.DecisionID,
		OrgID:            evt.OrgID,
		TenantID:         evt.TenantID,
		GatewayID:        evt.GatewayID,
		Stage:            evt.Stage,
		Verdict:          evt.Verdict,
		PolicyIDs:        evt.PolicyIDs,
		LatencyMs:        evt.LatencyMs,
		Reasons:          evt.Reasons,
		TraceID:          traceID,
		Context:          evt.Context,
		ContextTruncated: evt.ContextTruncated,
	}
}

// CentralStoreSink is a pluggable durable backend for decision records. Ship is
// expected to be a single synchronous network write; the exporter wraps it in a
// timeout and circuit breaker so the implementation need not. Close flushes and
// releases any held resources.
type CentralStoreSink interface {
	// Name identifies the sink in logs/metrics (e.g. "s3").
	Name() string
	// Ship persists exactly one decision record. It must honor ctx
	// cancellation/deadline. A non-nil error counts as a failure toward the
	// breaker.
	Ship(ctx context.Context, record DecisionRecord) error
	// Close releases resources. Called once at shutdown.
	Close(ctx context.Context) error
}

// exporterStats is the atomically-updated counter set the exporter exposes for
// observability and tests. All reads go through Stats() which snapshots them.
type exporterStats struct {
	enqueued atomic.Int64 // records accepted into the queue
	dropped  atomic.Int64 // records dropped because the queue was full
	shipped  atomic.Int64 // records the sink accepted
	failed   atomic.Int64 // ships that errored or timed out
	skipped  atomic.Int64 // ships short-circuited by an open breaker
}

// Stats is a point-in-time snapshot of the exporter counters.
type Stats struct {
	Enqueued int64
	Dropped  int64
	Shipped  int64
	Failed   int64
	Skipped  int64
}

// CentralStoreExporter ships decision records to a CentralStoreSink off the
// decision path: Export() enqueues to a bounded buffer drained by a single
// background worker that ships each record under a per-call timeout, guarded by
// a circuit breaker. One worker keeps record ordering and bounds sink
// concurrency to one in-flight write, which is the right shape for an
// append-only audit feed.
type CentralStoreExporter struct {
	sink    CentralStoreSink
	breaker *circuitBreaker
	timeout time.Duration
	now     func() time.Time

	queue chan DecisionRecord
	wg    sync.WaitGroup

	// mu guards closed and serializes the queue send against the queue close.
	// Export takes RLock around its non-blocking send; Close takes the write
	// Lock before close(queue). This makes a send-after-close impossible (the
	// classic "send on closed channel" panic) without putting a lock on the
	// hot path beyond an uncontended RLock around a non-blocking select.
	mu     sync.RWMutex
	closed bool

	// lastDropWarnNanos rate-limits the buffer-full WARN (CAS-claimed) so a
	// sustained outage signals loudly on the first drop but does not flood logs.
	lastDropWarnNanos atomic.Int64

	stats exporterStats
}

// exporterConfig is the resolved, validated knob set for an exporter.
type exporterConfig struct {
	timeout          time.Duration
	breakerThreshold int
	breakerCooldown  time.Duration
	buffer           int
}

// defaultExporterConfig returns the config used when no env overrides are set.
func defaultExporterConfig() exporterConfig {
	return exporterConfig{
		timeout:          defaultAuditTimeout,
		breakerThreshold: defaultBreakerThreshold,
		breakerCooldown:  defaultBreakerCooldown,
		buffer:           defaultAuditBuffer,
	}
}

// NewCentralStoreExporter builds the exporter dictated by env vars, or returns
// nil when AXONFLOW_AUDIT_SINK is empty (the default, exporter disabled) or
// when sink construction fails. A nil *CentralStoreExporter is safe to call
// Export/Close on, so callers need not nil-check.
//
// Failure is never fatal: a misconfigured or unreachable sink logs WARN and
// disables the exporter rather than blocking agent boot.
func NewCentralStoreExporter(ctx context.Context) *CentralStoreExporter {
	kind := strings.ToLower(strings.TrimSpace(os.Getenv(envAuditSink)))
	if kind == "" {
		return nil
	}

	cfg := resolveExporterConfig()

	sink, err := buildSink(ctx, kind)
	if err != nil {
		log.Printf("[telemetry] audit sink %q setup failed (%v): central-store export disabled", kind, err)
		return nil
	}

	exp := newExporterWithSink(sink, cfg)
	log.Printf("[telemetry] central-store audit export enabled: sink=%s timeout=%s breaker_threshold=%d cooldown=%s buffer=%d",
		sink.Name(), cfg.timeout, cfg.breakerThreshold, cfg.breakerCooldown, cfg.buffer)
	return exp
}

// buildSink constructs the concrete sink for a kind. Split out so tests can
// drive the env→config path without a live AWS environment.
func buildSink(ctx context.Context, kind string) (CentralStoreSink, error) {
	switch kind {
	case "s3":
		return newS3SinkFromEnv(ctx)
	default:
		return nil, fmt.Errorf("unknown sink %q (supported: s3)", kind)
	}
}

// newExporterWithSink wires an exporter around an explicit sink + config and
// starts its worker. Exported-for-test seam: unit tests inject a fake sink here
// to exercise success / sink-down / timeout / breaker / buffer-drop paths
// without touching the env or a real backend.
func newExporterWithSink(sink CentralStoreSink, cfg exporterConfig) *CentralStoreExporter {
	if cfg.buffer < 1 {
		cfg.buffer = 1
	}
	exp := &CentralStoreExporter{
		sink:    sink,
		breaker: newCircuitBreaker(cfg.breakerThreshold, cfg.breakerCooldown, time.Now),
		timeout: cfg.timeout,
		now:     time.Now,
		queue:   make(chan DecisionRecord, cfg.buffer),
	}
	exp.wg.Add(1)
	go exp.worker()
	return exp
}

// ExportEvent projects a DecisionEvent + trace id into a record and enqueues it.
// Convenience wrapper so callers hold only the event shape.
func (e *CentralStoreExporter) ExportEvent(evt DecisionEvent, traceID string) {
	if e == nil {
		return
	}
	e.Export(RecordFromEvent(evt, traceID, e.now()))
}

// Export enqueues a record for shipping and returns immediately. Never blocks:
// if the buffer is full the record is dropped, and because a dropped audit
// record is silent data loss it is counted (Dropped stat), metered
// (axonflow_central_store_records_total{outcome="dropped"}), AND logged at WARN
// (rate-limited) so an operator notices a slow/dead sink. Safe on a nil
// receiver, concurrently with Close, and after Close (a closed exporter drops
// the record rather than panicking on a send to a closed channel).
func (e *CentralStoreExporter) Export(record DecisionRecord) {
	if e == nil {
		return
	}
	// RLock held across the non-blocking send so Close (write Lock) cannot
	// close the queue between the closed-check and the send. Many Exports run
	// concurrently under RLock; only Close blocks them, briefly, at shutdown.
	e.mu.RLock()
	defer e.mu.RUnlock()
	if e.closed {
		return
	}
	select {
	case e.queue <- record:
		e.stats.enqueued.Add(1)
	default:
		e.stats.dropped.Add(1)
		centralStoreRecordsTotal.WithLabelValues("dropped").Inc()
		e.warnDropped()
	}
}

// warnDropped emits a rate-limited WARN that the buffer is full and audit
// records are being dropped. The CAS claims the log slot so concurrent Exports
// emit at most one line per dropWarnInterval; the first drop logs immediately
// (lastDropWarnNanos starts at zero) so the loss is never silent.
func (e *CentralStoreExporter) warnDropped() {
	now := e.now().UnixNano()
	last := e.lastDropWarnNanos.Load()
	if now-last < int64(dropWarnInterval) {
		return
	}
	if !e.lastDropWarnNanos.CompareAndSwap(last, now) {
		return
	}
	log.Printf("[telemetry] central-store exporter dropping audit records: buffer full, %d dropped so far; sink=%s is slow or unreachable",
		e.stats.dropped.Load(), e.sink.Name())
}

// worker drains the queue until it is closed, shipping each record under the
// guards. Single goroutine: at most one in-flight write, records ship in
// enqueue order.
func (e *CentralStoreExporter) worker() {
	defer e.wg.Done()
	for record := range e.queue {
		e.ship(record)
	}
}

// ship sends one record through the breaker + timeout. The breaker decision is
// taken first so a tripped breaker costs nothing; on a real attempt the result
// feeds back into the breaker so consecutive failures trip it and a success
// closes it.
func (e *CentralStoreExporter) ship(record DecisionRecord) {
	if !e.breaker.Allow() {
		e.stats.skipped.Add(1)
		centralStoreRecordsTotal.WithLabelValues("skipped").Inc()
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), e.timeout)
	defer cancel()

	err := e.sink.Ship(ctx, record)
	e.breaker.Record(err == nil)
	if err != nil {
		e.stats.failed.Add(1)
		centralStoreRecordsTotal.WithLabelValues("failed").Inc()
		log.Printf("[telemetry] central-store ship failed (sink=%s decision_id=%s): %v", e.sink.Name(), record.DecisionID, err)
		return
	}
	e.stats.shipped.Add(1)
	centralStoreRecordsTotal.WithLabelValues("shipped").Inc()
}

// Stats snapshots the exporter counters. Safe on a nil receiver (zero value).
func (e *CentralStoreExporter) Stats() Stats {
	if e == nil {
		return Stats{}
	}
	return Stats{
		Enqueued: e.stats.enqueued.Load(),
		Dropped:  e.stats.dropped.Load(),
		Shipped:  e.stats.shipped.Load(),
		Failed:   e.stats.failed.Load(),
		Skipped:  e.stats.skipped.Load(),
	}
}

// Close stops accepting records, drains the buffer (bounded by ctx), then closes
// the sink. Idempotent and safe on a nil receiver. If ctx expires before the
// worker drains, Close returns ctx.Err() and skips the sink close; the caller's
// shutdown budget governs how long draining is allowed to take.
func (e *CentralStoreExporter) Close(ctx context.Context) error {
	if e == nil {
		return nil
	}
	// Flip closed and close the queue under the write Lock. This waits for any
	// in-flight Export RLocks (each a fast non-blocking send) to release, so no
	// Export can be mid-send when the queue is closed, and none can start a send
	// afterward. Idempotent: a second Close sees closed and returns.
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return nil
	}
	e.closed = true
	close(e.queue)
	e.mu.Unlock()

	done := make(chan struct{})
	go func() {
		e.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-ctx.Done():
		return ctx.Err()
	}
	return e.sink.Close(ctx)
}

// resolveExporterConfig reads + validates the exporter knobs from env, clamping
// each into a safe range and logging any override that was out of range.
func resolveExporterConfig() exporterConfig {
	cfg := defaultExporterConfig()

	if raw := strings.TrimSpace(os.Getenv(envAuditTimeoutMs)); raw != "" {
		if ms, err := strconv.Atoi(raw); err == nil && ms > 0 {
			d := time.Duration(ms) * time.Millisecond
			if d < minAuditTimeout {
				d = minAuditTimeout
			}
			if d > maxAuditTimeout {
				d = maxAuditTimeout
			}
			cfg.timeout = d
		} else {
			log.Printf("[telemetry] invalid %s=%q, using default %s", envAuditTimeoutMs, raw, cfg.timeout)
		}
	}

	if raw := strings.TrimSpace(os.Getenv(envAuditBreakerThreshold)); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n >= 1 {
			cfg.breakerThreshold = n
		} else {
			log.Printf("[telemetry] invalid %s=%q, using default %d", envAuditBreakerThreshold, raw, cfg.breakerThreshold)
		}
	}

	if raw := strings.TrimSpace(os.Getenv(envAuditBreakerCooldownMs)); raw != "" {
		if ms, err := strconv.Atoi(raw); err == nil && ms > 0 {
			d := time.Duration(ms) * time.Millisecond
			if d < minBreakerCooldown {
				d = minBreakerCooldown
			}
			cfg.breakerCooldown = d
		} else {
			log.Printf("[telemetry] invalid %s=%q, using default %s", envAuditBreakerCooldownMs, raw, cfg.breakerCooldown)
		}
	}

	if raw := strings.TrimSpace(os.Getenv(envAuditBuffer)); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n >= 1 {
			if n > maxAuditBuffer {
				n = maxAuditBuffer
			}
			cfg.buffer = n
		} else {
			log.Printf("[telemetry] invalid %s=%q, using default %d", envAuditBuffer, raw, cfg.buffer)
		}
	}

	return cfg
}

// recordingTracer decorates a DecisionTracer so each recorded decision is also
// shipped, as a durable record, to the central store. It delegates to the inner
// tracer for the span + trace id (preserving the existing trace contract), then
// fires a non-blocking Export. The exporter's own buffer/timeout/breaker keep
// this off the decision's critical path.
type recordingTracer struct {
	inner    DecisionTracer
	exporter *CentralStoreExporter
}

// RecordDecision records the span via the inner tracer, ships the record to the
// central store, and returns the inner tracer's trace id unchanged.
func (t *recordingTracer) RecordDecision(ctx context.Context, evt DecisionEvent) string {
	traceID := t.inner.RecordDecision(ctx, evt)
	t.exporter.ExportEvent(evt, traceID)
	return traceID
}

// marshalRecord serializes a record to a single newline-terminated JSON line
// (NDJSON), the line format the central-store load jobs expect. Shared by the
// sinks so the on-the-wire shape is defined in exactly one place.
func marshalRecord(record DecisionRecord) ([]byte, error) {
	data, err := json.Marshal(record)
	if err != nil {
		return nil, fmt.Errorf("marshal decision record: %w", err)
	}
	return append(data, '\n'), nil
}
