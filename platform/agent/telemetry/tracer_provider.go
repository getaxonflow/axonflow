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
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.40.0"
)

// Env vars consumed by NewDecisionTracer.
//
// AXONFLOW_OTEL_ENDPOINT — OTLP gRPC endpoint (host:port). Empty value
// is the explicit "OTel disabled" signal and yields the noop tracer.
// Set to e.g. "otel-collector:4317" for the local Jaeger compose, or
// "tempo.svc:4317" for a managed backend.
//
// AXONFLOW_OTEL_SERVICE_NAME — service.name resource attribute (default
// "axonflow-agent"). Backends key dashboards on this; bump per service
// when running multiple AxonFlow components into one collector.
//
// AXONFLOW_OTEL_SAMPLE_RATE — float in [0.0, 1.0]. 1.0 (default) = head
// sample everything. Cut to 0.1 in high-RPS environments. ParentBased
// is the wrapping strategy so callers that already started a parent
// span (e.g. an upstream gateway) propagate their sampling decision.
const (
	envOTelEndpoint    = "AXONFLOW_OTEL_ENDPOINT"
	envOTelServiceName = "AXONFLOW_OTEL_SERVICE_NAME"
	envOTelSampleRate  = "AXONFLOW_OTEL_SAMPLE_RATE"

	defaultServiceName = "axonflow-agent"
	defaultSampleRate  = 1.0
	tracerScope        = "axonflow/platform/agent/telemetry"
)

// Provider bundles the active DecisionTracer with a Shutdown hook so
// callers can flush spans on graceful termination. For the noop impl
// Shutdown is a no-op; for OTLP it stops the batch processor and
// closes the gRPC connection.
//
// Boot-ordering contract: callers MUST initialize the Provider
// exactly once at process startup before any goroutine that calls
// RecordDecision can run, and MUST NOT reassign it later. Handlers
// then read the package-global pointer without locks (this is the
// pattern used in agent/gateway_handlers.go). Re-initializing or
// swapping the Provider at runtime would race with concurrent
// readers — if you need that, add a sync.RWMutex around the access
// site, don't poke at the global directly.
type Provider struct {
	Tracer   DecisionTracer
	shutdown func(context.Context) error
}

// Shutdown flushes any pending spans and closes exporter connections.
// Safe to call against a noop provider — it returns nil. Bound to the
// agent's existing shutdown sequence.
func (p *Provider) Shutdown(ctx context.Context) error {
	if p == nil || p.shutdown == nil {
		return nil
	}
	return p.shutdown(ctx)
}

// NewDecisionTracer constructs the DecisionTracer dictated by env
// vars. Endpoint empty (or unset) returns the noop tracer with a no-op
// Shutdown. Endpoint set wires up an OTLP/gRPC exporter, a parent-based
// trace-id-ratio sampler, and a batch span processor.
//
// Any OTel setup failure logs at WARN and falls back to the noop
// tracer so a misconfigured exporter never blocks agent boot. This is
// the Community-tier-safety rule: OTel is observability, never a hard
// dependency.
func NewDecisionTracer(ctx context.Context) *Provider {
	endpoint := strings.TrimSpace(os.Getenv(envOTelEndpoint))
	if endpoint == "" {
		log.Printf("[telemetry] %s empty — decision tracer disabled (noop)", envOTelEndpoint)
		return &Provider{Tracer: NewNoopTracer()}
	}

	serviceName := strings.TrimSpace(os.Getenv(envOTelServiceName))
	if serviceName == "" {
		serviceName = defaultServiceName
	}

	sampleRate := defaultSampleRate
	if raw := strings.TrimSpace(os.Getenv(envOTelSampleRate)); raw != "" {
		if parsed, err := strconv.ParseFloat(raw, 64); err == nil && parsed >= 0 && parsed <= 1.0 {
			sampleRate = parsed
		} else {
			log.Printf("[telemetry] invalid %s=%q (want float in [0,1]); defaulting to %.2f", envOTelSampleRate, raw, defaultSampleRate)
		}
	}

	provider, err := buildOTLPProvider(ctx, endpoint, serviceName, sampleRate)
	if err != nil {
		log.Printf("[telemetry] OTLP exporter setup failed (%v) — falling back to noop tracer", err)
		return &Provider{Tracer: NewNoopTracer()}
	}

	log.Printf("[telemetry] decision tracer enabled — endpoint=%s service=%s sample_rate=%.2f", endpoint, serviceName, sampleRate)
	return provider
}

// buildOTLPProvider does the real OTel wiring. Split out so the
// fallback logic in NewDecisionTracer stays straight-line.
func buildOTLPProvider(ctx context.Context, endpoint, serviceName string, sampleRate float64) (provider *Provider, rerr error) {
	// Insecure is the right default for the in-cluster otel-collector
	// hop (the collector itself terminates TLS to upstream backends).
	// Operators who terminate TLS at the agent boundary should set
	// AXONFLOW_OTEL_ENDPOINT to an https-scheme URL via a wrapper —
	// out of scope for v1.
	//
	// We use AxonFlow-prefixed env vars (AXONFLOW_OTEL_*) rather than
	// the OTel SDK's own auto-config keys (OTEL_EXPORTER_OTLP_*) so
	// operators with multiple OTel-instrumented services in one host
	// can tune AxonFlow's tracer independently. WithTimeout/WithEndpoint
	// passed here override any SDK auto-config that may be present.
	exporter, err := otlptrace.New(
		ctx,
		otlptracegrpc.NewClient(
			otlptracegrpc.WithEndpoint(endpoint),
			otlptracegrpc.WithInsecure(),
			otlptracegrpc.WithTimeout(10*time.Second),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("create OTLP trace exporter: %w", err)
	}

	// On any downstream error before the Provider is returned, close
	// the exporter so the underlying gRPC connection isn't orphaned
	// for the process lifetime.
	defer func() {
		if rerr != nil {
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			_ = exporter.Shutdown(shutdownCtx)
		}
	}()

	res, err := resource.Merge(
		resource.Default(),
		resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceName(serviceName),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("build resource: %w", err)
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sdktrace.ParentBased(sdktrace.TraceIDRatioBased(sampleRate))),
	)

	return &Provider{
		Tracer: &otlpTracer{tracer: tp.Tracer(tracerScope)},
		shutdown: func(ctx context.Context) error {
			// Flush batched spans + close gRPC client. 5s budget keeps
			// shutdown from hanging the host on a wedged collector.
			shutdownCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			return tp.Shutdown(shutdownCtx)
		},
	}, nil
}
