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
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	collectortrace "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
	"google.golang.org/grpc"
)

// TestNoopTracer_EmptyEndpointYieldsNoop confirms the env-var contract:
// an empty AXONFLOW_OTEL_ENDPOINT (Community-tier default) produces a
// tracer that emits nothing and returns the empty trace_id. Callers
// can echo "" back to the SDK; omitempty drops it from JSON.
func TestNoopTracer_EmptyEndpointYieldsNoop(t *testing.T) {
	t.Setenv("AXONFLOW_OTEL_ENDPOINT", "")

	provider := NewDecisionTracer(context.Background())

	if provider == nil {
		t.Fatal("expected non-nil provider")
	}
	if _, ok := provider.Tracer.(noopTracer); !ok {
		t.Fatalf("expected noopTracer, got %T", provider.Tracer)
	}

	got := provider.Tracer.RecordDecision(context.Background(), DecisionEvent{DecisionID: "d1", Stage: "llm", Verdict: "allow"})
	if got != "" {
		t.Fatalf("noop tracer must return empty trace_id; got %q", got)
	}

	// Shutdown on a noop provider is a no-op and must not error.
	if err := provider.Shutdown(context.Background()); err != nil {
		t.Fatalf("noop Shutdown returned error: %v", err)
	}
}

// TestNewNoopTracer_DirectConstructor confirms NewNoopTracer is a usable
// public escape hatch for callers that want to wire noop semantics
// without going through env-var resolution.
func TestNewNoopTracer_DirectConstructor(t *testing.T) {
	tr := NewNoopTracer()
	if tr == nil {
		t.Fatal("NewNoopTracer must not return nil")
	}
	got := tr.RecordDecision(context.Background(), DecisionEvent{})
	if got != "" {
		t.Fatalf("NewNoopTracer must return empty trace_id; got %q", got)
	}
}

// TestOTLPTracer_EmitsW3CTraceID stands up a local in-process OTLP/gRPC
// receiver, points the tracer at it, and verifies:
//
//	(a) RecordDecision returns a non-empty W3C trace_id (32 hex chars)
//	(b) the receiver actually received a span with the expected 7
//	    attributes — proving the wire-format export path works
//
// This is a real OTel pipeline (SDK → BatchSpanProcessor → OTLP/gRPC
// → in-process collector stub). Not a mock — the brief explicitly
// forbids mocks in runtime-e2e; we apply the same standard here so the
// unit test catches breakage in the SDK/exporter wiring, not just the
// AxonFlow glue code.
func TestOTLPTracer_EmitsW3CTraceID(t *testing.T) {
	server, addr, recv := startInProcessCollector(t)
	defer server.Stop()

	t.Setenv("AXONFLOW_OTEL_ENDPOINT", addr)
	t.Setenv("AXONFLOW_OTEL_SERVICE_NAME", "axonflow-agent-test")
	t.Setenv("AXONFLOW_OTEL_SAMPLE_RATE", "1.0")

	ctx := context.Background()
	provider := NewDecisionTracer(ctx)
	if _, ok := provider.Tracer.(*otlpTracer); !ok {
		t.Fatalf("expected *otlpTracer, got %T", provider.Tracer)
	}

	evt := DecisionEvent{
		DecisionID: "decision-123",
		OrgID:      "org-acme",
		TenantID:   "tenant-rocket",
		Stage:      "llm",
		Verdict:    "allow",
		PolicyIDs:  []string{"p_pii_us", "p_pii_global"},
		LatencyMs:  7,
		Reasons:    []string{"clean"},
	}

	traceID := provider.Tracer.RecordDecision(ctx, evt)
	if len(traceID) != 32 {
		t.Fatalf("expected 32-char W3C trace_id, got %q (len=%d)", traceID, len(traceID))
	}
	for _, c := range traceID {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Fatalf("trace_id %q contains non-hex char %q", traceID, c)
		}
	}
	if traceID == "00000000000000000000000000000000" {
		t.Fatalf("trace_id must not be all-zero (sampled span dropped)")
	}

	if err := provider.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown returned error: %v", err)
	}

	spans := recv.spans(t, 2*time.Second)
	if len(spans) == 0 {
		t.Fatalf("collector received zero spans after Shutdown flushed")
	}

	got := attrsByKey(spans[0])
	want := map[string]string{
		"decision.id":      "decision-123",
		"decision.stage":   "llm",
		"decision.verdict": "allow",
		"decision.reasons": "clean",
		"org.id":           "org-acme",
		"tenant.id":        "tenant-rocket",
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("span attr %q = %q, want %q", k, got[k], v)
		}
	}
	if got["decision.latency_ms"] != "7" {
		t.Errorf("span attr decision.latency_ms = %q, want %q", got["decision.latency_ms"], "7")
	}
	if got["decision.policy_ids"] != "[p_pii_us,p_pii_global]" {
		t.Errorf("span attr decision.policy_ids = %q, want %q", got["decision.policy_ids"], "[p_pii_us,p_pii_global]")
	}
}

// TestOTLPTracer_EmitsContextAttributes verifies the #2509 request-context
// propagation: a DecisionEvent carrying a sanitized Context map emits one
// request.context.<key> span attribute per entry. Real OTLP pipeline (no
// mocks), same in-process collector as the trace-id test.
func TestOTLPTracer_EmitsContextAttributes(t *testing.T) {
	server, addr, recv := startInProcessCollector(t)
	defer server.Stop()

	t.Setenv("AXONFLOW_OTEL_ENDPOINT", addr)
	t.Setenv("AXONFLOW_OTEL_SAMPLE_RATE", "1.0")

	ctx := context.Background()
	provider := NewDecisionTracer(ctx)

	provider.Tracer.RecordDecision(ctx, DecisionEvent{
		DecisionID: "decision-ctx-1",
		Stage:      "llm",
		Verdict:    "allow",
		Context: map[string]string{
			"x_ai_agent":        "claude-code",
			"x_session_id":      "sess-abc123",
			"x_leader_identity": "leader@example.com",
		},
	})

	if err := provider.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}

	spans := recv.spans(t, 2*time.Second)
	if len(spans) == 0 {
		t.Fatal("collector received zero spans")
	}
	got := attrsByKey(spans[0])

	want := map[string]string{
		"request.context.x_ai_agent":        "claude-code",
		"request.context.x_session_id":      "sess-abc123",
		"request.context.x_leader_identity": "leader@example.com",
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("span attr %q = %q, want %q", k, got[k], v)
		}
	}
	// A non-truncated event must NOT carry the truncated marker.
	if _, present := got["request.context.truncated"]; present {
		t.Errorf("request.context.truncated must be absent when ContextTruncated=false")
	}
}

// TestOTLPTracer_ContextTruncatedFlag verifies that an over-cap context map
// sets request.context.truncated=true and that the tracer-level cap bounds
// the emitted attribute count even when the caller did not pre-flag it.
func TestOTLPTracer_ContextTruncatedFlag(t *testing.T) {
	server, addr, recv := startInProcessCollector(t)
	defer server.Stop()

	t.Setenv("AXONFLOW_OTEL_ENDPOINT", addr)
	t.Setenv("AXONFLOW_OTEL_SAMPLE_RATE", "1.0")

	ctx := context.Background()
	provider := NewDecisionTracer(ctx)

	// 12 keys > maxContextSpanAttrs (10): the tracer drops the surplus and
	// flags truncation even though the caller passed ContextTruncated=false.
	bigCtx := make(map[string]string, 12)
	for i := 0; i < 12; i++ {
		bigCtx[fmt.Sprintf("x_bukuwarung_k%02d", i)] = fmt.Sprintf("v%02d", i)
	}
	provider.Tracer.RecordDecision(ctx, DecisionEvent{
		DecisionID:       "decision-ctx-2",
		Stage:            "llm",
		Verdict:          "allow",
		Context:          bigCtx,
		ContextTruncated: false,
	})

	if err := provider.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	spans := recv.spans(t, 2*time.Second)
	if len(spans) == 0 {
		t.Fatal("collector received zero spans")
	}
	got := attrsByKey(spans[0])

	if got["request.context.truncated"] != "true" {
		t.Errorf("request.context.truncated = %q, want true", got["request.context.truncated"])
	}
	ctxAttrs := 0
	for k := range got {
		if strings.HasPrefix(k, "request.context.") && k != "request.context.truncated" {
			ctxAttrs++
		}
	}
	if ctxAttrs != maxContextSpanAttrs {
		t.Errorf("emitted %d request.context.* attrs, want %d (tracer-level cap)", ctxAttrs, maxContextSpanAttrs)
	}
}

// TestOTLPTracer_InvalidEndpointFallsBack verifies the safety rule: if
// OTel setup fails (or, in this case, if the gRPC endpoint never
// becomes reachable), we still get a Provider that doesn't crash the
// agent. The OTel SDK's gRPC client is lazy — connection is established
// on first export attempt, not at NewDecisionTracer time — so this test
// asserts that record + shutdown both run cleanly even when the
// collector is unreachable.
func TestOTLPTracer_InvalidEndpointFallsBack(t *testing.T) {
	t.Setenv("AXONFLOW_OTEL_ENDPOINT", "127.0.0.1:1")
	t.Setenv("AXONFLOW_OTEL_SAMPLE_RATE", "1.0")

	provider := NewDecisionTracer(context.Background())
	if provider == nil || provider.Tracer == nil {
		t.Fatal("provider must be non-nil even when collector is unreachable")
	}

	traceID := provider.Tracer.RecordDecision(context.Background(), DecisionEvent{DecisionID: "x", Stage: "llm", Verdict: "deny"})
	if len(traceID) != 32 {
		t.Fatalf("trace_id must still be issued client-side; got %q", traceID)
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	_ = provider.Shutdown(shutdownCtx) // must not panic; error is acceptable here
}

// TestSampleRate_InvalidValueFallsBackToDefault confirms the parser
// rejects out-of-range / non-numeric inputs and uses the default
// instead of crashing the agent.
func TestSampleRate_InvalidValueFallsBackToDefault(t *testing.T) {
	server, addr, _ := startInProcessCollector(t)
	defer server.Stop()

	cases := []string{"not-a-float", "-0.1", "1.5", ""}
	for _, raw := range cases {
		t.Run("raw="+raw, func(t *testing.T) {
			t.Setenv("AXONFLOW_OTEL_ENDPOINT", addr)
			t.Setenv("AXONFLOW_OTEL_SAMPLE_RATE", raw)
			provider := NewDecisionTracer(context.Background())
			if provider == nil || provider.Tracer == nil {
				t.Fatal("provider must be non-nil")
			}
			_ = provider.Shutdown(context.Background())
		})
	}
}

// TestTruncateJoined_RespectsLimit guards the reasons attribute size
// boundary. Collector backends commonly cap individual attribute values
// at 32 KiB; we stay well under that and prove truncation kicks in at
// reasonsMaxAttrLen.
func TestTruncateJoined_RespectsLimit(t *testing.T) {
	long := strings.Repeat("abcde; ", 1000) // 7 KiB
	got := truncateJoined([]string{long}, reasonsMaxAttrLen)
	if len(got) > reasonsMaxAttrLen+4 { // +4 for ellipsis
		t.Errorf("truncateJoined produced %d chars, exceeds limit %d", len(got), reasonsMaxAttrLen)
	}
	if !strings.HasSuffix(got, "…") {
		t.Errorf("truncated value must end with ellipsis, got tail %q", got[len(got)-10:])
	}

	short := truncateJoined([]string{"a", "b"}, reasonsMaxAttrLen)
	if short != "a; b" {
		t.Errorf("short input must be returned unchanged: got %q", short)
	}

	empty := truncateJoined(nil, reasonsMaxAttrLen)
	if empty != "" {
		t.Errorf("nil reasons must yield empty string; got %q", empty)
	}
}

// TestTruncateJoined_PreservesUTF8 guards the rune-boundary fallback.
// A long reason with no "; " separator and multi-byte runes
// straddling the cut point must NOT yield invalid UTF-8 — OTLP
// requires valid UTF-8 attribute values and collectors will reject
// spans that violate it.
func TestTruncateJoined_PreservesUTF8(t *testing.T) {
	// Build a string of 3-byte runes (Chinese characters are 3 bytes
	// in UTF-8). With no "; " separator, the truncator must clamp to
	// a rune boundary rather than cut mid-byte.
	rune3 := "中" // 3 bytes
	long := strings.Repeat(rune3, 2000)
	got := truncateJoined([]string{long}, reasonsMaxAttrLen)

	if !utf8.ValidString(got) {
		t.Fatalf("truncated value is not valid UTF-8: bytes=% x", []byte(got))
	}
	if !strings.HasSuffix(got, "…") {
		t.Errorf("truncated value must end with ellipsis")
	}

	// Single very long ASCII run with no "; " — must also clamp cleanly.
	asciiLong := strings.Repeat("a", reasonsMaxAttrLen*2)
	gotAscii := truncateJoined([]string{asciiLong}, reasonsMaxAttrLen)
	if !utf8.ValidString(gotAscii) {
		t.Errorf("ASCII truncation produced invalid UTF-8")
	}
	if len(gotAscii) > reasonsMaxAttrLen+4 {
		t.Errorf("ASCII truncation exceeded limit: got %d", len(gotAscii))
	}
}

// ---------- helpers ----------

// inProcessCollector is a minimal OTLP/gRPC trace receiver used to
// verify spans are actually emitted with the correct attributes.
// Implements the OTLP TraceService server contract.
type inProcessCollector struct {
	collectortrace.UnimplementedTraceServiceServer
	mu     sync.Mutex
	rcv    []*tracepb.ResourceSpans
	pinged chan struct{}
}

func (c *inProcessCollector) Export(ctx context.Context, req *collectortrace.ExportTraceServiceRequest) (*collectortrace.ExportTraceServiceResponse, error) {
	c.mu.Lock()
	c.rcv = append(c.rcv, req.ResourceSpans...)
	c.mu.Unlock()
	select {
	case <-c.pinged:
	default:
		close(c.pinged)
	}
	return &collectortrace.ExportTraceServiceResponse{}, nil
}

// spans returns every Span the collector has received so far. Waits up
// to `wait` for the first export call so tests don't race the
// BatchSpanProcessor's flush.
func (c *inProcessCollector) spans(t *testing.T, wait time.Duration) []*tracepb.Span {
	t.Helper()
	select {
	case <-c.pinged:
	case <-time.After(wait):
		t.Fatalf("no spans exported within %s", wait)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	var out []*tracepb.Span
	for _, rs := range c.rcv {
		for _, ss := range rs.ScopeSpans {
			out = append(out, ss.Spans...)
		}
	}
	return out
}

func startInProcessCollector(t *testing.T) (*grpc.Server, string, *inProcessCollector) {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := grpc.NewServer()
	recv := &inProcessCollector{pinged: make(chan struct{})}
	collectortrace.RegisterTraceServiceServer(srv, recv)
	go func() { _ = srv.Serve(lis) }()
	return srv, lis.Addr().String(), recv
}

// attrsByKey flattens span attributes into a map[string]string for
// assertion. Int and slice attrs are stringified to keep the assertions
// simple; this matches how the OTel SDK encodes them on the wire.
func attrsByKey(span *tracepb.Span) map[string]string {
	out := make(map[string]string)
	for _, kv := range span.Attributes {
		out[kv.Key] = anyValueString(kv.Value)
	}
	return out
}

func anyValueString(v *commonpb.AnyValue) string {
	switch x := v.Value.(type) {
	case *commonpb.AnyValue_StringValue:
		return x.StringValue
	case *commonpb.AnyValue_BoolValue:
		if x.BoolValue {
			return "true"
		}
		return "false"
	case *commonpb.AnyValue_IntValue:
		return intToString(x.IntValue)
	case *commonpb.AnyValue_ArrayValue:
		parts := make([]string, 0, len(x.ArrayValue.Values))
		for _, item := range x.ArrayValue.Values {
			parts = append(parts, anyValueString(item))
		}
		return "[" + strings.Join(parts, ",") + "]"
	default:
		return ""
	}
}

func intToString(n int64) string {
	// Avoid strconv import; small wrapper for readability in assertions.
	var negative bool
	if n < 0 {
		negative = true
		n = -n
	}
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	pos := len(buf)
	for n > 0 {
		pos--
		buf[pos] = byte('0' + n%10)
		n /= 10
	}
	if negative {
		pos--
		buf[pos] = '-'
	}
	return string(buf[pos:])
}
