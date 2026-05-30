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
	"sort"
	"strings"
	"unicode/utf8"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// otlpTracer wraps an OTel Tracer that is wired to an OTLP exporter.
// One DecisionEvent becomes one short-lived span; the span is ended
// inside RecordDecision so the SDK batches it for export immediately.
type otlpTracer struct {
	tracer trace.Tracer
}

// RecordDecision starts and ends a span named "axonflow.decision" with
// the 7 attributes specified in the brief, then returns the W3C
// trace_id from the span context. Span emission is fire-and-forget at
// the SDK boundary — even if export fails downstream, the trace_id
// surfaced here is valid for the PEP to propagate.
func (t *otlpTracer) RecordDecision(ctx context.Context, evt DecisionEvent) string {
	_, span := t.tracer.Start(ctx, "axonflow.decision")
	defer span.End()

	span.SetAttributes(
		attribute.String("decision.id", evt.DecisionID),
		attribute.String("decision.stage", evt.Stage),
		attribute.String("decision.verdict", evt.Verdict),
		attribute.StringSlice("decision.policy_ids", evt.PolicyIDs),
		attribute.Int64("decision.latency_ms", evt.LatencyMs),
		attribute.String("decision.reasons", truncateJoined(evt.Reasons, reasonsMaxAttrLen)),
		attribute.String("org.id", evt.OrgID),
		attribute.String("tenant.id", evt.TenantID),
	)

	setContextAttributes(span, evt)

	return span.SpanContext().TraceID().String()
}

// setContextAttributes emits the sanitized request context as
// request.context.<key> span attributes. Keys are canonical
// lower_snake_case already; we sort them so the kept subset is
// deterministic when the count cap fires, then emit at most
// maxContextSpanAttrs of them. request.context.truncated is set whenever
// the caller flagged truncation OR the tracer-level cap dropped keys —
// either way the auditor learns the context map on the span is partial.
func setContextAttributes(span trace.Span, evt DecisionEvent) {
	truncated := evt.ContextTruncated
	if len(evt.Context) > 0 {
		keys := make([]string, 0, len(evt.Context))
		for k := range evt.Context {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		if len(keys) > maxContextSpanAttrs {
			keys = keys[:maxContextSpanAttrs]
			truncated = true
		}
		attrs := make([]attribute.KeyValue, 0, len(keys))
		for _, k := range keys {
			attrs = append(attrs, attribute.String("request.context."+k, evt.Context[k]))
		}
		span.SetAttributes(attrs...)
	}
	if truncated {
		span.SetAttributes(attribute.Bool("request.context.truncated", true))
	}
}

// truncateJoined joins reasons with "; " and truncates to maxLen so the
// emitted attribute stays under collector size limits. Reasons can be
// nil — returns "" in that case. The result is always valid UTF-8:
// OTLP attribute values are required to be valid UTF-8 strings, and
// collector backends (Jaeger, Tempo) commonly reject spans with
// malformed values. We prefer a separator boundary ("; "), fall back
// to a rune boundary, and never cut mid-multibyte-rune.
func truncateJoined(reasons []string, maxLen int) string {
	if len(reasons) == 0 {
		return ""
	}
	joined := strings.Join(reasons, "; ")
	if len(joined) <= maxLen {
		return joined
	}
	// Prefer a separator boundary if one exists in the kept prefix.
	cut := strings.LastIndex(joined[:maxLen], "; ")
	if cut < maxLen/2 {
		// No nearby separator — clamp to the nearest preceding rune
		// boundary so the slice is always valid UTF-8.
		cut = maxLen
		for cut > 0 && !utf8.RuneStart(joined[cut]) {
			cut--
		}
	}
	return joined[:cut] + "…"
}
