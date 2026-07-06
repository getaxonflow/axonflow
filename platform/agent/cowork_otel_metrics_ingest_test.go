//go:build enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"bytes"
	"context"
	"database/sql/driver"
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/gorilla/mux"
	"github.com/lib/pq"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	collectormetrics "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	metricspb "go.opentelemetry.io/proto/otlp/metrics/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"
)

// ---- OTLP metrics builders --------------------------------------------------

type metricFixture struct {
	name        string
	temporality metricspb.AggregationTemporality
	monotonic   bool
	gauge       bool // build as Gauge instead of Sum
	points      []*metricspb.NumberDataPoint
}

func dpInt(v int64, attrs ...*commonpb.KeyValue) *metricspb.NumberDataPoint {
	return &metricspb.NumberDataPoint{
		Attributes:        attrs,
		StartTimeUnixNano: 1700000000_000000000,
		TimeUnixNano:      1700000060_000000000,
		Value:             &metricspb.NumberDataPoint_AsInt{AsInt: v},
	}
}

func dpDouble(v float64, attrs ...*commonpb.KeyValue) *metricspb.NumberDataPoint {
	return &metricspb.NumberDataPoint{
		Attributes:        attrs,
		StartTimeUnixNano: 1700000000_000000000,
		TimeUnixNano:      1700000060_000000000,
		Value:             &metricspb.NumberDataPoint_AsDouble{AsDouble: v},
	}
}

func sumMetric(f metricFixture) *metricspb.Metric {
	m := &metricspb.Metric{Name: f.name}
	if f.gauge {
		m.Data = &metricspb.Metric_Gauge{Gauge: &metricspb.Gauge{DataPoints: f.points}}
		return m
	}
	m.Data = &metricspb.Metric_Sum{Sum: &metricspb.Sum{
		AggregationTemporality: f.temporality,
		IsMonotonic:            f.monotonic,
		DataPoints:             f.points,
	}}
	return m
}

func coworkMetricsReq(resAttrs []*commonpb.KeyValue, metrics ...*metricspb.Metric) *collectormetrics.ExportMetricsServiceRequest {
	return &collectormetrics.ExportMetricsServiceRequest{
		ResourceMetrics: []*metricspb.ResourceMetrics{{
			Resource:     &resourcepb.Resource{Attributes: resAttrs},
			ScopeMetrics: []*metricspb.ScopeMetrics{{Metrics: metrics}},
		}},
	}
}

func postCoworkMetrics(t *testing.T, ctx context.Context, contentType string, reqPB *collectormetrics.ExportMetricsServiceRequest) *httptest.ResponseRecorder {
	t.Helper()
	var body []byte
	var err error
	if strings.Contains(contentType, "json") {
		body, err = protojson.Marshal(reqPB)
	} else {
		body, err = proto.Marshal(reqPB)
	}
	if err != nil {
		t.Fatalf("marshal OTLP metrics req: %v", err)
	}
	r := httptest.NewRequest(http.MethodPost, coworkOTELMetricsPath, bytes.NewReader(body)).WithContext(ctx)
	r.Header.Set("Content-Type", contentType)
	rr := httptest.NewRecorder()
	coworkOTELMetricsHandler(rr, r)
	return rr
}

func decodeMetricsResponse(t *testing.T, rr *httptest.ResponseRecorder, contentType string) *collectormetrics.ExportMetricsServiceResponse {
	t.Helper()
	resp := &collectormetrics.ExportMetricsServiceResponse{}
	var err error
	if strings.Contains(contentType, "json") {
		err = protojson.Unmarshal(rr.Body.Bytes(), resp)
	} else {
		err = proto.Unmarshal(rr.Body.Bytes(), resp)
	}
	if err != nil {
		t.Fatalf("decode OTLP metrics response: %v", err)
	}
	return resp
}

// expectMetricsUsageTx registers the WithOrgScope transaction skeleton
// (Begin + set_config) on the mock; the caller adds INSERT/lookup expectations
// in between and then expectCommit.
func expectMetricsUsageTx(mock sqlmock.Sqlmock, org string) {
	mock.ExpectBegin()
	mock.ExpectExec("SELECT set_config\\('app.current_org_id', \\$1, true\\)").
		WithArgs(org).WillReturnResult(sqlmock.NewResult(0, 0))
}

// metricInsertArgs builds the 18-arg matcher slice for the usage_events INSERT
// with every position AnyArg; callers override positions they assert.
func metricInsertArgs() []driver.Value {
	args := make([]driver.Value, 18)
	for i := range args {
		args[i] = sqlmock.AnyArg()
	}
	return args
}

// Flagship: a faithful Claude Code delta export (token.usage input+output,
// cost.usage, session.count) lands one canonical usage row per datapoint,
// keyed on session_id + user_email, org-tagged from AUTH (the telemetry's
// organization.id is attribution data, never the scope), token/cost mirrored
// into the legacy rollup columns.
func TestCoworkOTELMetrics_ClaudeCodeExport_LandsUsageRows(t *testing.T) {
	mockDB, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer mockDB.Close()
	origDB := usageDB
	usageDB = mockDB
	t.Cleanup(func() { usageDB = origDB })

	resAttrs := []*commonpb.KeyValue{
		strAttr("service.name", "claude-code"),
		strAttr("session.id", "sess-cc-1"),
		strAttr("user.email", "dev@design-partner.example"),
		strAttr("organization.id", "org-SPOOFED-FROM-TELEMETRY"),
	}

	expectMetricsUsageTx(mock, "org-auth")

	// input tokens row
	var org1, sess1, email1, name1 string
	a1 := metricInsertArgs()
	a1[0] = capStr{&org1}
	a1[4] = capStr{&sess1}
	a1[5] = capStr{&email1}
	a1[6] = capStr{&name1}
	a1[7] = float64(1200) // metric_value (delta)
	a1[14] = 1200         // prompt_tokens
	a1[15] = 0
	a1[16] = 1200 // total_tokens
	a1[17] = 0
	mock.ExpectExec("INSERT INTO usage_events").WithArgs(a1...).WillReturnResult(sqlmock.NewResult(1, 1))

	// output tokens row
	a2 := metricInsertArgs()
	a2[7] = float64(300)
	a2[14] = 0
	a2[15] = 300 // completion_tokens
	a2[16] = 300
	mock.ExpectExec("INSERT INTO usage_events").WithArgs(a2...).WillReturnResult(sqlmock.NewResult(2, 1))

	// cost row (USD mirrored to telescoped cents; series has no prior rows)
	mock.ExpectQuery("SELECT COALESCE\\(SUM\\(metric_value").
		WithArgs("org-auth", sqlmock.AnyArg()).
		WillReturnRows(sqlmock.NewRows([]string{"sum"}).AddRow(0.0))
	var attrsCap []byte
	a3 := metricInsertArgs()
	a3[6] = "claude_code.cost.usage"
	a3[7] = 0.0742
	a3[11] = capBytes{&attrsCap} // metric_attributes JSONB
	a3[16] = 0
	a3[17] = 7
	mock.ExpectExec("INSERT INTO usage_events").WithArgs(a3...).WillReturnResult(sqlmock.NewResult(3, 1))

	// session count row
	a4 := metricInsertArgs()
	a4[6] = "claude_code.session.count"
	a4[7] = float64(1)
	mock.ExpectExec("INSERT INTO usage_events").WithArgs(a4...).WillReturnResult(sqlmock.NewResult(4, 1))

	mock.ExpectCommit()

	req := coworkMetricsReq(resAttrs,
		sumMetric(metricFixture{
			name: "claude_code.token.usage", monotonic: true,
			temporality: metricspb.AggregationTemporality_AGGREGATION_TEMPORALITY_DELTA,
			points: []*metricspb.NumberDataPoint{
				dpInt(1200, strAttr("type", "input"), strAttr("model", "claude-sonnet-5")),
				dpInt(300, strAttr("type", "output"), strAttr("model", "claude-sonnet-5")),
			},
		}),
		sumMetric(metricFixture{
			name: "claude_code.cost.usage", monotonic: true,
			temporality: metricspb.AggregationTemporality_AGGREGATION_TEMPORALITY_DELTA,
			points: []*metricspb.NumberDataPoint{
				dpDouble(0.0742, strAttr("model", "claude-sonnet-5"), strAttr("secret_note", "free-form content that must not persist")),
			},
		}),
		sumMetric(metricFixture{
			name: "claude_code.session.count", monotonic: true,
			temporality: metricspb.AggregationTemporality_AGGREGATION_TEMPORALITY_DELTA,
			points:      []*metricspb.NumberDataPoint{dpInt(1, strAttr("start_type", "fresh"))},
		}),
	)

	rr := postCoworkMetrics(t, authCtx("org-auth", "tenant-dp", "client-1"), contentTypeProtobuf, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status: got %d body=%s", rr.Code, rr.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("usage INSERTs: %v", err)
	}
	resp := decodeMetricsResponse(t, rr, contentTypeProtobuf)
	if resp.GetPartialSuccess().GetRejectedDataPoints() != 0 {
		t.Errorf("rejected: got %d want 0", resp.GetPartialSuccess().GetRejectedDataPoints())
	}

	// Keyed on session + user; org from AUTH, never the spoofed telemetry attr.
	if org1 != "org-auth" {
		t.Errorf("org_id must come from auth, got %q", org1)
	}
	if sess1 != "sess-cc-1" || email1 != "dev@design-partner.example" {
		t.Errorf("session/user keying: got %q/%q", sess1, email1)
	}
	if name1 != "claude_code.token.usage" {
		t.Errorf("metric_name: got %q", name1)
	}

	// Attribute allowlist: structural attrs persist, unknown keys are DROPPED.
	var storedAttrs map[string]string
	if err := json.Unmarshal(attrsCap, &storedAttrs); err != nil {
		t.Fatalf("metric_attributes not JSON: %v (%q)", err, string(attrsCap))
	}
	if storedAttrs["model"] != "claude-sonnet-5" {
		t.Errorf("allowlisted attr model missing: %v", storedAttrs)
	}
	if _, leaked := storedAttrs["secret_note"]; leaked {
		t.Errorf("non-allowlisted attr persisted: %v", storedAttrs)
	}
	if _, leaked := storedAttrs["session.id"]; leaked {
		t.Errorf("session.id should live in its column, not duplicated in attributes")
	}
}

// Unknown metric names, gauges under known names, non-monotonic sums, and
// unspecified temporality are all REJECTED (partial_success), never stored.
func TestCoworkOTELMetrics_UnsupportedShapesRejected(t *testing.T) {
	mockDB, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer mockDB.Close()
	origDB := usageDB
	usageDB = mockDB
	t.Cleanup(func() { usageDB = origDB })
	// No expectations: nothing may reach the DB.

	req := coworkMetricsReq(nil,
		sumMetric(metricFixture{ // unknown name
			name: "some.other.metric", monotonic: true,
			temporality: metricspb.AggregationTemporality_AGGREGATION_TEMPORALITY_DELTA,
			points:      []*metricspb.NumberDataPoint{dpInt(5)},
		}),
		sumMetric(metricFixture{ // gauge under a known name
			name: "claude_code.token.usage", gauge: true,
			points: []*metricspb.NumberDataPoint{dpInt(5)},
		}),
		sumMetric(metricFixture{ // non-monotonic
			name: "claude_code.cost.usage", monotonic: false,
			temporality: metricspb.AggregationTemporality_AGGREGATION_TEMPORALITY_DELTA,
			points:      []*metricspb.NumberDataPoint{dpDouble(0.5)},
		}),
		sumMetric(metricFixture{ // unspecified temporality
			name: "claude_code.commit.count", monotonic: true,
			temporality: metricspb.AggregationTemporality_AGGREGATION_TEMPORALITY_UNSPECIFIED,
			points:      []*metricspb.NumberDataPoint{dpInt(1)},
		}),
		sumMetric(metricFixture{ // negative value on a valid shape
			name: "claude_code.lines_of_code.count", monotonic: true,
			temporality: metricspb.AggregationTemporality_AGGREGATION_TEMPORALITY_DELTA,
			points:      []*metricspb.NumberDataPoint{dpInt(-10)},
		}),
		sumMetric(metricFixture{ // non-finite + overflow values (R3: NaN poisons SUM; 2^31 overflows the int mirrors)
			name: "claude_code.token.usage", monotonic: true,
			temporality: metricspb.AggregationTemporality_AGGREGATION_TEMPORALITY_DELTA,
			points: []*metricspb.NumberDataPoint{
				dpDouble(math.NaN(), strAttr("type", "input")),
				dpDouble(math.Inf(1), strAttr("type", "output")),
				dpInt(int64(1)<<31, strAttr("type", "input")),
			},
		}),
	)

	rr := postCoworkMetrics(t, authCtx("org-auth", "t", "c"), contentTypeProtobuf, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d", rr.Code)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("no DB call expected: %v", err)
	}
	resp := decodeMetricsResponse(t, rr, contentTypeProtobuf)
	if got := resp.GetPartialSuccess().GetRejectedDataPoints(); got != 8 {
		t.Errorf("rejected datapoints: got %d want 8", got)
	}
}

// Non-community deployment with no authenticated org → 401, nothing stored.
func TestCoworkOTELMetrics_Unauthenticated_Rejected(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "in-vpc-enterprise")

	mockDB, mock, _ := sqlmock.New()
	defer mockDB.Close()
	origDB := usageDB
	usageDB = mockDB
	t.Cleanup(func() { usageDB = origDB })

	req := coworkMetricsReq(nil, sumMetric(metricFixture{
		name: "claude_code.session.count", monotonic: true,
		temporality: metricspb.AggregationTemporality_AGGREGATION_TEMPORALITY_DELTA,
		points:      []*metricspb.NumberDataPoint{dpInt(1)},
	}))
	rr := postCoworkMetrics(t, authCtx("", "", ""), contentTypeProtobuf, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status: got %d want 401", rr.Code)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("no INSERT should have run: %v", err)
	}
}

// A storage failure rolls the batch back and returns 503 so the exporter
// RETRIES — usage is never silently dropped.
func TestCoworkOTELMetrics_StorageFailure_Returns503(t *testing.T) {
	mockDB, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer mockDB.Close()
	origDB := usageDB
	usageDB = mockDB
	t.Cleanup(func() { usageDB = origDB })

	expectMetricsUsageTx(mock, "org-auth")
	mock.ExpectExec("INSERT INTO usage_events").WillReturnError(context.DeadlineExceeded)
	mock.ExpectRollback()

	req := coworkMetricsReq(nil, sumMetric(metricFixture{
		name: "claude_code.session.count", monotonic: true,
		temporality: metricspb.AggregationTemporality_AGGREGATION_TEMPORALITY_DELTA,
		points:      []*metricspb.NumberDataPoint{dpInt(1)},
	}))
	rr := postCoworkMetrics(t, authCtx("org-auth", "t", "c"), contentTypeProtobuf, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status: got %d want 503 (retryable)", rr.Code)
	}
}

// R3 round 2 HIGH: a PERMANENT storage failure (SQLSTATE class 23 — e.g. the
// org has no organizations row for the usage_events FK) answers 400, not 503,
// so the exporter drops the batch instead of retrying it forever.
func TestCoworkOTELMetrics_PermanentStorageFailure_Returns400(t *testing.T) {
	mockDB, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer mockDB.Close()
	origDB := usageDB
	usageDB = mockDB
	t.Cleanup(func() { usageDB = origDB })

	expectMetricsUsageTx(mock, "org-auth")
	mock.ExpectExec("INSERT INTO usage_events").
		WillReturnError(&pq.Error{Code: "23503", Message: "violates foreign key constraint \"fk_usage_org\""})
	mock.ExpectRollback()

	req := coworkMetricsReq(nil, sumMetric(metricFixture{
		name: "claude_code.session.count", monotonic: true,
		temporality: metricspb.AggregationTemporality_AGGREGATION_TEMPORALITY_DELTA,
		points:      []*metricspb.NumberDataPoint{dpInt(1)},
	}))
	rr := postCoworkMetrics(t, authCtx("org-auth", "t", "c"), contentTypeProtobuf, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d want 400 (permanent errors must not become a retry loop)", rr.Code)
	}
}

// R3 round 2: an enterprise agent with NO usage store must refuse (503), not
// answer a full-success 200 while silently dropping every datapoint.
func TestCoworkOTELMetrics_NilUsageDB_Refuses(t *testing.T) {
	origDB := usageDB
	usageDB = nil
	t.Cleanup(func() { usageDB = origDB })

	req := coworkMetricsReq(nil, sumMetric(metricFixture{
		name: "claude_code.session.count", monotonic: true,
		temporality: metricspb.AggregationTemporality_AGGREGATION_TEMPORALITY_DELTA,
		points:      []*metricspb.NumberDataPoint{dpInt(1)},
	}))
	rr := postCoworkMetrics(t, authCtx("org-auth", "t", "c"), contentTypeProtobuf, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status: got %d want 503 (silent 200 drop is a full-success lie)", rr.Code)
	}
}

// JSON OTLP/HTTP is accepted; malformed JSON is a 400; unsupported CT is 415;
// oversize is 413.
func TestCoworkOTELMetrics_ContentTypesAndLimits(t *testing.T) {
	mockDB, mock, _ := sqlmock.New()
	defer mockDB.Close()
	origDB := usageDB
	usageDB = mockDB
	t.Cleanup(func() { usageDB = origDB })

	expectMetricsUsageTx(mock, "org-auth")
	mock.ExpectExec("INSERT INTO usage_events").WithArgs(metricInsertArgs()...).WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectCommit()

	// JSON accepted
	req := coworkMetricsReq(nil, sumMetric(metricFixture{
		name: "claude_code.pull_request.count", monotonic: true,
		temporality: metricspb.AggregationTemporality_AGGREGATION_TEMPORALITY_DELTA,
		points:      []*metricspb.NumberDataPoint{dpInt(2)},
	}))
	rr := postCoworkMetrics(t, authCtx("org-auth", "t", "c"), contentTypeJSON, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("json status %d body %s", rr.Code, rr.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("json INSERT: %v", err)
	}

	// Malformed JSON → 400
	r := httptest.NewRequest(http.MethodPost, coworkOTELMetricsPath, strings.NewReader("{not json")).
		WithContext(authCtx("org-auth", "t", "c"))
	r.Header.Set("Content-Type", contentTypeJSON)
	w := httptest.NewRecorder()
	coworkOTELMetricsHandler(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("malformed json: got %d want 400", w.Code)
	}

	// Unsupported content type → 415
	r = httptest.NewRequest(http.MethodPost, coworkOTELMetricsPath, strings.NewReader("x")).
		WithContext(authCtx("org-auth", "t", "c"))
	r.Header.Set("Content-Type", "text/csv")
	w = httptest.NewRecorder()
	coworkOTELMetricsHandler(w, r)
	if w.Code != http.StatusUnsupportedMediaType {
		t.Errorf("unsupported ct: got %d want 415", w.Code)
	}

	// Oversize body → 413
	r = httptest.NewRequest(http.MethodPost, coworkOTELMetricsPath, bytes.NewReader(make([]byte, maxCoworkOTLPBody+1))).
		WithContext(authCtx("org-auth", "t", "c"))
	r.Header.Set("Content-Type", contentTypeProtobuf)
	w = httptest.NewRecorder()
	coworkOTELMetricsHandler(w, r)
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("oversize: got %d want 413", w.Code)
	}
}

// Route is mounted (both OTLP paths) by registerCoworkOTELIngest.
func TestRegisterCoworkOTELIngest_MetricsRouteMounted(t *testing.T) {
	r := mux.NewRouter()
	registerCoworkOTELIngest(r)
	req := httptest.NewRequest(http.MethodPost, coworkOTELMetricsPath, nil)
	var match mux.RouteMatch
	if !r.Match(req, &match) {
		t.Fatalf("POST %s was not routed after registration", coworkOTELMetricsPath)
	}
}

// ---- pure mapper units -------------------------------------------------------

func TestOtelSeriesKey_DistinguishesSeries(t *testing.T) {
	base := map[string]string{"type": "input", "model": "m1"}
	k1 := otelSeriesKey("org", "claude_code.token.usage", base)
	if k2 := otelSeriesKey("org", "claude_code.token.usage", map[string]string{"type": "output", "model": "m1"}); k1 == k2 {
		t.Error("different attrs must yield different series keys")
	}
	if k2 := otelSeriesKey("org2", "claude_code.token.usage", base); k1 == k2 {
		t.Error("different orgs must yield different series keys")
	}
	if k2 := otelSeriesKey("org", "claude_code.cost.usage", base); k1 == k2 {
		t.Error("different metrics must yield different series keys")
	}
	if k2 := otelSeriesKey("org", "claude_code.token.usage", map[string]string{"model": "m1", "type": "input"}); k1 != k2 {
		t.Error("attr map ordering must not change the series key")
	}
	// Non-allowlisted attrs still distinguish series (they are part of series identity).
	if k2 := otelSeriesKey("org", "claude_code.token.usage", map[string]string{"type": "input", "model": "m1", "custom": "x"}); k1 == k2 {
		t.Error("non-allowlisted attrs must still distinguish series")
	}
}

func TestAllowlistOTELAttrs_DropsUnknownAndCapsValues(t *testing.T) {
	got := allowlistOTELAttrs(map[string]string{
		"model":     "claude-sonnet-5",
		"free_text": "PII-ish content",
		"type":      strings.Repeat("x", 500),
	})
	if _, ok := got["free_text"]; ok {
		t.Error("unknown key must be dropped")
	}
	if got["model"] != "claude-sonnet-5" {
		t.Error("allowlisted key must be kept")
	}
	if len(got["type"]) != maxOTELMetricAttrValueLen {
		t.Errorf("value must be capped to %d, got %d", maxOTELMetricAttrValueLen, len(got["type"]))
	}
	if allowlistOTELAttrs(map[string]string{"junk": "x"}) != nil {
		t.Error("all-dropped map must be nil (NULL column)")
	}
}

func TestAnyValueString_Scalars(t *testing.T) {
	if s := anyValueString(&commonpb.AnyValue{Value: &commonpb.AnyValue_IntValue{IntValue: -42}}); s != "-42" {
		t.Errorf("int: got %q", s)
	}
	if s := anyValueString(&commonpb.AnyValue{Value: &commonpb.AnyValue_BoolValue{BoolValue: true}}); s != "true" {
		t.Errorf("bool: got %q", s)
	}
	if s := anyValueString(nil); s != "" {
		t.Errorf("nil: got %q", s)
	}
}

func TestParseCoworkOTLPMetrics_Errors(t *testing.T) {
	if _, err := parseCoworkOTLPMetrics("text/csv", []byte("x")); err == nil {
		t.Error("expected unsupported content-type error")
	}
	if _, err := parseCoworkOTLPMetrics(contentTypeJSON, []byte("{not json")); err == nil {
		t.Error("expected json parse error")
	}
}

func TestCountMetricDataPoints_AllShapes(t *testing.T) {
	pts := []*metricspb.NumberDataPoint{dpInt(1), dpInt(2)}
	cases := []struct {
		m    *metricspb.Metric
		want int
	}{
		{&metricspb.Metric{Data: &metricspb.Metric_Sum{Sum: &metricspb.Sum{DataPoints: pts}}}, 2},
		{&metricspb.Metric{Data: &metricspb.Metric_Gauge{Gauge: &metricspb.Gauge{DataPoints: pts}}}, 2},
		{&metricspb.Metric{Data: &metricspb.Metric_Histogram{Histogram: &metricspb.Histogram{DataPoints: []*metricspb.HistogramDataPoint{{}}}}}, 1},
		{&metricspb.Metric{Data: &metricspb.Metric_ExponentialHistogram{ExponentialHistogram: &metricspb.ExponentialHistogram{DataPoints: []*metricspb.ExponentialHistogramDataPoint{{}}}}}, 1},
		{&metricspb.Metric{Data: &metricspb.Metric_Summary{Summary: &metricspb.Summary{DataPoints: []*metricspb.SummaryDataPoint{{}, {}, {}}}}}, 3},
		{&metricspb.Metric{}, 1}, // dataless metric still accounts as one rejected point
	}
	for i, c := range cases {
		if got := countMetricDataPoints(c.m); got != c.want {
			t.Errorf("case %d: got %d want %d", i, got, c.want)
		}
	}
}

func TestOtelNanoTime(t *testing.T) {
	if !otelNanoTime(0).IsZero() {
		t.Error("zero nanos must map to zero time (NULL column)")
	}
	if got := otelNanoTime(1700000000_000000000); got.Unix() != 1700000000 {
		t.Errorf("nanos conversion: got %v", got)
	}
}

// Composite / double attribute values are not identifiers — rendered empty (dropped).
func TestAnyValueString_NonScalarDropped(t *testing.T) {
	if s := anyValueString(&commonpb.AnyValue{Value: &commonpb.AnyValue_DoubleValue{DoubleValue: 1.5}}); s != "" {
		t.Errorf("double attr should not render as identifier, got %q", s)
	}
}

// Datapoint attributes override resource attributes on key collision.
func TestMergeOTELAttrs_DatapointWins(t *testing.T) {
	res := attrsToMap([]*commonpb.KeyValue{strAttr("user.email", "resource@example.com"), strAttr("terminal.type", "tmux")})
	dp := attrsToMap([]*commonpb.KeyValue{strAttr("user.email", "datapoint@example.com")})
	merged := mergeOTELAttrs(res, dp)
	if merged["user.email"] != "datapoint@example.com" {
		t.Errorf("datapoint attr must win: got %q", merged["user.email"])
	}
	if merged["terminal.type"] != "tmux" {
		t.Errorf("resource attr must survive: got %q", merged["terminal.type"])
	}
}

// R3 L5 pin (round-2 hardening): a datapoint with TimeUnixNano == 0 or beyond
// MaxInt64 cannot be stored (metric_time is the retry-dedup key and int64(ns)
// would wrap) — it must be REJECTED, never guessed. Red if the ts guard in
// extractClaudeCodeMetricEvents is reverted.
func TestCoworkOTELMetrics_InvalidTimestampRejected(t *testing.T) {
	mockDB, mock, _ := sqlmock.New()
	defer mockDB.Close()
	origDB := usageDB
	usageDB = mockDB
	t.Cleanup(func() { usageDB = origDB })
	mock.MatchExpectationsInOrder(false) // no INSERT may occur

	zeroTS := &metricspb.NumberDataPoint{
		Value: &metricspb.NumberDataPoint_AsInt{AsInt: 5},
		// TimeUnixNano deliberately 0
	}
	wrapTS := &metricspb.NumberDataPoint{
		TimeUnixNano: ^uint64(0), // > MaxInt64 → would wrap negative
		Value:        &metricspb.NumberDataPoint_AsInt{AsInt: 5},
	}
	req := coworkMetricsReq(nil, sumMetric(metricFixture{
		name: "claude_code.commit.count", monotonic: true,
		temporality: metricspb.AggregationTemporality_AGGREGATION_TEMPORALITY_DELTA,
		points:      []*metricspb.NumberDataPoint{zeroTS, wrapTS},
	}))
	rr := postCoworkMetrics(t, authCtx("org-auth", "t", "c"), contentTypeJSON, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d body %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), `"rejectedDataPoints":"2"`) {
		t.Errorf("both invalid-ts datapoints must be rejected, got %s", rr.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Errorf("no storage may happen for invalid-ts datapoints: %v", err)
	}
}

// R3 L5 pin (round-2 hardening): truncateOTELString must repair a truncation
// that splits a multi-byte UTF-8 sequence — postgres rejects invalid UTF-8 in
// text columns, which would fail the whole batch (poisoned-retry class). Red
// if the strings.ToValidUTF8 repair is removed.
func TestTruncateOTELString_UTF8SafeAtCut(t *testing.T) {
	s := strings.Repeat("a", 254) + "é" // 'é' = 2 bytes, spans the 255 boundary
	got := truncateOTELString(s, 255)
	if len(got) != 254 {
		t.Errorf("split rune must be dropped, got len %d", len(got))
	}
	if !utf8.ValidString(got) {
		t.Errorf("truncation produced invalid UTF-8: %q", got)
	}
	if kept := truncateOTELString("héllo", 255); kept != "héllo" {
		t.Errorf("in-bounds string must be untouched, got %q", kept)
	}
}

// R3 L4 pin: a StartTimeUnixNano beyond MaxInt64 must not wrap into a
// pre-1970 time (it feeds counter-reset detection) — it is treated as absent.
func TestOtelNanoTime_WrapGuard(t *testing.T) {
	if got := otelNanoTime(^uint64(0)); !got.IsZero() {
		t.Errorf("ns > MaxInt64 must yield zero time, got %v", got)
	}
}
