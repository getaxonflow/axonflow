//go:build enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
//
// WS-A (#2832/#2835) — Claude Code OTLP METRICS ingest plane.
//
// Claude Code splits its native telemetry: per-request events (user_prompt,
// api_request, tool_result) go out as OTLP LOGS (→ /v1/logs, handled by
// cowork_otel_ingest.go), while aggregate usage counters — token / cost /
// session / lines-of-code / commit / PR / tool-decision / active-time — go out
// as OTLP METRICS (→ /v1/metrics, enabled with OTEL_METRICS_EXPORTER=otlp).
// Before this file, /v1/metrics 404'd and those counters could never land.
//
// Each accepted datapoint becomes a canonical usage row in usage_events
// (event_type='claude_code_metric', migration core/140), keyed on session_id +
// user_email — the SAME metering store every other plane writes to, feeding the
// same rollups the portal Usage page reads. Metrics are NOT decisions, so no
// audit_logs row and no signed-decision-chain entry is written here (per-request
// decisions ride the /v1/logs plane).
//
// Invariants (mirrors the logs ingest):
//   - Authenticated + tenant-tagged: org/tenant/client come from the
//     authenticated license (apiAuthMiddleware), NEVER from the (spoofable)
//     OTLP attributes. session.id / user.email / organization.id from the
//     telemetry are attribution only.
//   - Nothing content-ish is persisted: metric attributes pass a strict
//     ALLOWLIST of structural identifiers (model, type, tool_name, …); unknown
//     keys are dropped before storage; allowlisted values are length-capped
//     (identifier-sized, never prose fields), bounding what a hostile
//     exporter can smuggle into the store.
//   - Fail-closed on anything we cannot meter correctly: unknown metric names,
//     non-Sum shapes, non-monotonic sums, unspecified temporality, and negative
//     values are REJECTED (reported via OTLP partial_success), never guessed.
//   - Cumulative streams are normalized to deltas at ingest (see
//     platform/common/usage.RecordOTELMetrics), so stored values are always
//     safe to SUM regardless of OTEL_EXPORTER_OTLP_METRICS_TEMPORALITY_PREFERENCE.
package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log"
	"math"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	collectormetrics "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	metricspb "go.opentelemetry.io/proto/otlp/metrics/v1"

	"axonflow/platform/common/usage"
	sharedidentity "axonflow/platform/shared/identity"
)

// coworkOTELMetricsPath is the standard OTLP/HTTP metrics path. Claude Code
// appends /v1/metrics to OTEL_EXPORTER_OTLP_ENDPOINT automatically.
const coworkOTELMetricsPath = "/v1/metrics"

// claudeCodeMetricSpec declares how one allowlisted Claude Code metric maps
// onto the usage row's legacy token/cost mirror columns.
type claudeCodeMetricSpec struct {
	countsTokens  bool
	countsCostUSD bool
}

// claudeCodeMetricSpecs is the ALLOWLIST of metric names we ingest — the full
// set Claude Code emits (code.claude.com/docs monitoring-usage). Names outside
// this set are rejected (visible via partial_success), never stored: we do not
// fabricate usage semantics for counters we do not understand.
var claudeCodeMetricSpecs = map[string]claudeCodeMetricSpec{
	"claude_code.session.count":           {},
	"claude_code.lines_of_code.count":     {},
	"claude_code.pull_request.count":      {},
	"claude_code.commit.count":            {},
	"claude_code.cost.usage":              {countsCostUSD: true},
	"claude_code.token.usage":             {countsTokens: true},
	"claude_code.code_edit_tool.decision": {},
	"claude_code.active_time.total":       {},
}

// otelMetricAttrAllowlist is the closed set of attribute keys persisted into
// metric_attributes. Every key is a structural identifier Claude Code emits
// (enum-valued or an id) — none carries free-form user content. Anything not
// listed (including arbitrary OTEL_RESOURCE_ATTRIBUTES) is DROPPED before
// storage. session.id and user.email are extracted into first-class columns
// and are not duplicated here.
var otelMetricAttrAllowlist = map[string]struct{}{
	"type": {}, "model": {}, "decision": {}, "source": {}, "tool_name": {},
	"language": {}, "start_type": {}, "query_source": {}, "speed": {}, "effort": {},
	"agent.name": {}, "skill.name": {}, "plugin.name": {}, "marketplace.name": {},
	"mcp_server.name": {}, "mcp_tool.name": {}, "terminal.type": {},
	"app.version": {}, "app.entrypoint": {}, "user.id": {}, "user.account_uuid": {},
	"user.account_id": {}, "organization.id": {}, "service.name": {}, "service.version": {},
}

// maxOTELMetricAttrValueLen bounds a persisted attribute value (row-size guard;
// allowlisted values are short identifiers, so truncation is theoretical).
const maxOTELMetricAttrValueLen = 200

// maxOTELMetricDatapointValue rejects absurd counter values (R3: the token/cost
// mirror columns are INTEGER (int32) — a datapoint above this would overflow
// them into a poisoned 503-retry loop, and no legitimate Claude Code counter
// approaches 2^31 within a session). Cost metrics get a tighter bound because
// their mirror is delta×100 cents (R3 round 2).
const (
	maxOTELMetricDatapointValue = float64(1<<31 - 1)
	maxOTELCostDatapointValue   = float64((1<<31 - 1) / 100)
)

// Column widths on usage_events (migration 140). session.id / user.email are
// client-supplied telemetry — truncate rather than let an oversized value abort
// the whole batch as a non-retryable INSERT error surfaced as a 503 (R3).
const (
	maxOTELSessionIDLen = 255
	maxOTELUserEmailLen = 320
)

// truncateOTELString bounds a client-supplied string to a column width and
// makes it safe to persist (R3 round 2: a byte-slice cut through a multibyte
// rune — or client-sent invalid UTF-8 — would abort the INSERT at Postgres,
// turning one hostile value into a permanent whole-batch retry loop).
func truncateOTELString(s string, max int) string {
	if len(s) > max {
		s = s[:max]
	}
	return sanitizeOTELText(s)
}

// sanitizeOTELText repairs invalid UTF-8 and strips NUL plus the other C0/DEL
// control characters (tab/newline/CR survive — legitimate in prose content).
//
// #2840: strings.ToValidUTF8 alone is NOT enough — U+0000 IS valid UTF-8, and
// Postgres rejects 0x00 in text/varchar/jsonb (class-22 errors). Unstripped,
// one NUL in any client-supplied field loses the audit row on the logs plane
// and wholesale-400s the entire batch on the metrics plane. Every client
// string that can reach an INSERT on either ingest plane must pass through
// this function.
func sanitizeOTELText(s string) string {
	s = strings.ToValidUTF8(s, "")
	// Fast path: no control characters (the overwhelmingly common case).
	clean := true
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == 0x7F || (c < 0x20 && c != '\t' && c != '\n' && c != '\r') {
			clean = false
			break
		}
	}
	if clean {
		return s
	}
	return strings.Map(func(r rune) rune {
		if r == 0x7F || (r < 0x20 && r != '\t' && r != '\n' && r != '\r') {
			return -1
		}
		return r
	}, s)
}

// coworkOTELMetricsHandler receives an OTLP/HTTP ExportMetricsServiceRequest
// (protobuf or JSON), maps each accepted datapoint to a canonical usage_events
// row (delta-normalized, org-tagged from auth), and returns an OTLP
// ExportMetricsServiceResponse.
func coworkOTELMetricsHandler(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	orgID := OrgIDFromContext(ctx)
	tenantID := TenantIDFromContext(ctx)
	clientID := ClientIDFromContext(ctx)

	// Defense-in-depth: the route is behind apiAuthMiddleware, but an empty org
	// in a non-community deployment means the tenant tag is missing — reject
	// rather than write untagged usage (and usage_events RLS would reject the
	// row anyway).
	if !isCommunityMode() && orgID == "" {
		writeJSONError(w, "authentication required", http.StatusUnauthorized)
		return
	}

	ct := r.Header.Get("Content-Type")
	body, err := readLimited(r.Body, maxCoworkOTLPBody)
	if err != nil {
		if errors.Is(err, errOTLPBodyTooLarge) {
			writeJSONError(w, "request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		writeJSONError(w, "failed to read request body", http.StatusBadRequest)
		return
	}

	req, err := parseCoworkOTLPMetrics(ct, body)
	if err != nil {
		status := http.StatusBadRequest
		if errors.Is(err, errUnsupportedContentType) {
			status = http.StatusUnsupportedMediaType
		}
		writeJSONError(w, "invalid OTLP metrics payload: "+err.Error(), status)
		return
	}

	events, rejected := extractClaudeCodeMetricEvents(orgID, clientID, req)

	// Fail loud, not silent: an enterprise agent running without a usage store
	// cannot meter anything — a 200 here would be a full-success lie and the
	// exporter would happily keep dropping usage (R3 round 2).
	if len(events) > 0 && usageDB == nil {
		log.Printf("[CoworkOTEL] metrics ingest REFUSED org=%s: no usage database configured — usage metering requires DATABASE_URL", logSanitize(orgID))
		writeJSONError(w, "usage metering store not configured", http.StatusServiceUnavailable)
		return
	}

	accepted := 0
	if len(events) > 0 {
		recorder := usage.NewUsageRecorder(usageDB)
		inserted, recErr := recorder.RecordOTELMetrics(ctx, orgID, events)
		if errors.Is(recErr, usage.ErrOTELMetricsPermanent) {
			// A data/integrity error (SQLSTATE class 22/23) is NOT transient:
			// the exporter would retry the identical payload forever. The
			// canonical case is a deployment whose org has no organizations
			// row (usage_events FK) — surface it loudly and answer 4xx so the
			// client drops the batch instead of looping (R3 round 2 HIGH).
			log.Printf("[CoworkOTEL] metrics ingest PERMANENT storage failure org=%s tenant=%s datapoints=%d: %v — if this is a foreign-key error the org has no organizations row (service-license deployment?); usage metering requires it",
				logSanitize(orgID), logSanitize(tenantID), len(events), recErr)
			writeJSONError(w, "usage rows cannot be stored for this org (permanent)", http.StatusBadRequest)
			return
		}
		if recErr != nil {
			// The whole batch transaction rolled back; nothing was stored. Tell
			// the exporter to RETRY (OTLP/HTTP retryable class) instead of
			// silently dropping usage. Delta normalization re-runs identically
			// on the retry because no prior row was committed.
			log.Printf("[CoworkOTEL] metrics ingest storage failed org=%s tenant=%s datapoints=%d: %v",
				logSanitize(orgID), logSanitize(tenantID), len(events), recErr)
			writeJSONError(w, "usage storage unavailable, retry", http.StatusServiceUnavailable)
			return
		}
		accepted = inserted
	}

	log.Printf("[CoworkOTEL] metrics ingest org=%s tenant=%s accepted=%d stored=%d rejected=%d",
		logSanitize(orgID), logSanitize(tenantID), len(events), accepted, rejected)

	writeOTLPMetricsResponse(w, ct, int64(rejected))
}

// extractClaudeCodeMetricEvents walks the OTLP structure and builds one
// OTELMetricEvent per acceptable Sum datapoint. Returns the events plus the
// count of rejected datapoints (unknown metric name, non-Sum shape,
// non-monotonic sum, unspecified temporality, negative value, or over the
// per-request cap).
func extractClaudeCodeMetricEvents(orgID, clientID string, req *collectormetrics.ExportMetricsServiceRequest) ([]usage.OTELMetricEvent, int) {
	if req == nil {
		return nil, 0
	}

	instanceID := os.Getenv("HOSTNAME") // Docker container ID (mirrors recordMCPToolCallUsage)
	if instanceID == "" {
		instanceID = "agent-unknown"
	}

	var events []usage.OTELMetricEvent
	rejected := 0

	for _, rm := range req.GetResourceMetrics() {
		resAttrs := attrsToMap(rm.GetResource().GetAttributes())
		for _, sm := range rm.GetScopeMetrics() {
			for _, m := range sm.GetMetrics() {
				spec, known := claudeCodeMetricSpecs[m.GetName()]
				if !known {
					rejected += countMetricDataPoints(m)
					continue
				}
				sum := m.GetSum()
				if sum == nil {
					// All Claude Code usage metrics are counters (Sum). A Gauge/
					// Histogram under an allowlisted name is a shape we cannot
					// meter as usage — fail closed.
					rejected += countMetricDataPoints(m)
					continue
				}
				if !sum.GetIsMonotonic() {
					rejected += len(sum.GetDataPoints())
					continue
				}
				var temporality string
				switch sum.GetAggregationTemporality() {
				case metricspb.AggregationTemporality_AGGREGATION_TEMPORALITY_DELTA:
					temporality = usage.TemporalityDelta
				case metricspb.AggregationTemporality_AGGREGATION_TEMPORALITY_CUMULATIVE:
					temporality = usage.TemporalityCumulative
				default:
					// UNSPECIFIED cannot be summed correctly under either
					// interpretation — fail closed.
					rejected += len(sum.GetDataPoints())
					continue
				}

				for _, dp := range sum.GetDataPoints() {
					if dp == nil {
						continue
					}
					if len(events) >= maxCoworkRecordsPerRequest {
						rejected++
						continue
					}
					// OTLP requires TimeUnixNano on every datapoint; without it
					// the duplicate-retry dedup (unique series+time index) has
					// no key and a retried delta export would double-count.
					// Fail closed (R3 round 2). The uint64→int64 overflow
					// guard rides along.
					if ts := dp.GetTimeUnixNano(); ts == 0 || ts > math.MaxInt64 {
						rejected++
						continue
					}
					value := numberDataPointValue(dp)
					// Fail closed on values that cannot be metered: negative
					// (counters are monotonic), non-finite (NaN/±Inf would
					// poison every SUM over the table — R3 HIGH), or absurdly
					// large (would overflow the int32 mirror columns; cost is
					// mirrored ×100 so its bound is tighter).
					bound := maxOTELMetricDatapointValue
					if spec.countsCostUSD {
						bound = maxOTELCostDatapointValue
					}
					if value < 0 || value > bound ||
						math.IsNaN(value) || math.IsInf(value, 0) {
						rejected++
						continue
					}

					merged := mergeOTELAttrs(resAttrs, attrsToMap(dp.GetAttributes()))
					ev := usage.OTELMetricEvent{
						ClientID:     clientID,
						InstanceID:   instanceID,
						InstanceType: "agent",
						// Sanitize before the fallback pick (an all-control first
						// candidate must not shadow a valid alternate — R3 L1).
						SessionID: firstNonEmpty(
							truncateOTELString(merged["session.id"], maxOTELSessionIDLen),
							truncateOTELString(merged["session_id"], maxOTELSessionIDLen)),
						// #2922: canonicalized for read-scope key parity (see
						// cowork_otel_ingest.go).
						UserEmail: sharedidentity.CanonicalEmail(firstNonEmpty(
							truncateOTELString(merged["user.email"], maxOTELUserEmailLen),
							truncateOTELString(merged["user_email"], maxOTELUserEmailLen))),
						MetricName:  m.GetName(),
						Value:       value,
						Temporality: temporality,
						SeriesKey:   otelSeriesKey(orgID, m.GetName(), merged),
						Attributes:  allowlistOTELAttrs(merged),
						Time:        otelNanoTime(dp.GetTimeUnixNano()),
						StartTime:   otelNanoTime(dp.GetStartTimeUnixNano()),

						CountsTokens:  spec.countsTokens,
						TokenType:     merged["type"],
						CountsCostUSD: spec.countsCostUSD,
					}
					events = append(events, ev)
				}
			}
		}
	}
	return events, rejected
}

// mergeOTELAttrs flattens resource + datapoint attributes into one string map;
// datapoint attributes win on key collision (they are more specific).
func mergeOTELAttrs(resource, datapoint map[string]*commonpb.AnyValue) map[string]string {
	merged := make(map[string]string, len(resource)+len(datapoint))
	for k, v := range resource {
		if s := anyValueString(v); s != "" {
			merged[k] = s
		}
	}
	for k, v := range datapoint {
		if s := anyValueString(v); s != "" {
			merged[k] = s
		}
	}
	return merged
}

// anyValueString renders scalar OTLP attribute values as strings (metrics
// attributes are scalar identifiers; composite values are ignored).
func anyValueString(v *commonpb.AnyValue) string {
	if v == nil {
		return ""
	}
	switch v.GetValue().(type) {
	case *commonpb.AnyValue_StringValue:
		return v.GetStringValue()
	case *commonpb.AnyValue_IntValue:
		return strconv.FormatInt(v.GetIntValue(), 10)
	case *commonpb.AnyValue_BoolValue:
		if v.GetBoolValue() {
			return "true"
		}
		return "false"
	default:
		return ""
	}
}

// allowlistOTELAttrs keeps only allowlisted structural attribute keys, with
// values length-capped. Unknown keys are dropped (never stored).
func allowlistOTELAttrs(merged map[string]string) map[string]string {
	out := make(map[string]string)
	for k, v := range merged {
		if _, ok := otelMetricAttrAllowlist[k]; !ok {
			continue
		}
		// truncateOTELString (not a bare slice): a mid-rune cut or a client
		// NUL in an attribute value would abort the JSONB insert and 400 the
		// whole batch (#2840).
		out[k] = truncateOTELString(v, maxOTELMetricAttrValueLen)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// otelSeriesKey identifies one OTLP series for cumulative→delta normalization:
// SHA-256 over org + metric name + the merged attribute set (sorted) as
// rendered by anyValueString — string/int/bool values; double-valued or
// composite attributes are excluded (Claude Code emits none on metrics, and a
// hostile exporter abusing them can only fold ITS OWN series → self-org
// miscount, accepted — R3 L1).
// The full set — not just the allowlisted keys — because two series differing
// only in a non-allowlisted attribute are still distinct series; folding them
// together would corrupt delta computation. Hashing does not persist the
// values, so no content can leak through the key.
func otelSeriesKey(orgID, metricName string, merged map[string]string) string {
	keys := make([]string, 0, len(merged))
	for k := range merged {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	h := sha256.New()
	h.Write([]byte(orgID))
	h.Write([]byte{0})
	h.Write([]byte(metricName))
	for _, k := range keys {
		h.Write([]byte{0})
		h.Write([]byte(k))
		h.Write([]byte{1})
		h.Write([]byte(merged[k]))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// numberDataPointValue reads the datapoint value regardless of int/double encoding.
func numberDataPointValue(dp *metricspb.NumberDataPoint) float64 {
	switch dp.GetValue().(type) {
	case *metricspb.NumberDataPoint_AsInt:
		return float64(dp.GetAsInt())
	default:
		return dp.GetAsDouble()
	}
}

// countMetricDataPoints counts a metric's datapoints across shapes (for
// rejected accounting).
func countMetricDataPoints(m *metricspb.Metric) int {
	switch {
	case m.GetSum() != nil:
		return len(m.GetSum().GetDataPoints())
	case m.GetGauge() != nil:
		return len(m.GetGauge().GetDataPoints())
	case m.GetHistogram() != nil:
		return len(m.GetHistogram().GetDataPoints())
	case m.GetExponentialHistogram() != nil:
		return len(m.GetExponentialHistogram().GetDataPoints())
	case m.GetSummary() != nil:
		return len(m.GetSummary().GetDataPoints())
	default:
		return 1
	}
}

func otelNanoTime(ns uint64) time.Time {
	// ns > MaxInt64 would wrap negative (a pre-1970 time) — treat as absent.
	// TimeUnixNano is additionally REJECTED upstream when out of range; this
	// guard covers StartTimeUnixNano, which is optional and only feeds
	// counter-reset detection (R3 L4).
	if ns == 0 || ns > math.MaxInt64 {
		return time.Time{}
	}
	return time.Unix(0, int64(ns)).UTC()
}

// ------------------------------- parsing/response ---------------------------

func parseCoworkOTLPMetrics(contentType string, body []byte) (*collectormetrics.ExportMetricsServiceRequest, error) {
	req := &collectormetrics.ExportMetricsServiceRequest{}
	ct := strings.ToLower(strings.TrimSpace(contentType))
	switch {
	case strings.Contains(ct, "application/x-protobuf"), strings.Contains(ct, "application/protobuf"), ct == "":
		// OTLP/HTTP default is protobuf.
		if err := proto.Unmarshal(body, req); err != nil {
			return nil, err
		}
	case strings.Contains(ct, "application/json"):
		if err := protojson.Unmarshal(body, req); err != nil {
			return nil, err
		}
	default:
		return nil, errUnsupportedContentType
	}
	return req, nil
}

func writeOTLPMetricsResponse(w http.ResponseWriter, contentType string, rejected int64) {
	resp := &collectormetrics.ExportMetricsServiceResponse{}
	if rejected > 0 {
		resp.PartialSuccess = &collectormetrics.ExportMetricsPartialSuccess{
			RejectedDataPoints: rejected,
			ErrorMessage:       "datapoints skipped: unknown metric name, non-counter shape, invalid value, or over the per-request cap",
		}
	}
	ct := strings.ToLower(strings.TrimSpace(contentType))
	if strings.Contains(ct, "application/json") {
		b, err := protojson.Marshal(resp)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", contentTypeJSON)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(b)
		return
	}
	b, err := proto.Marshal(resp)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", contentTypeProtobuf)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(b)
}
