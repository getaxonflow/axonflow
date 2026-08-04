// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

//go:build enterprise

package compliancereport

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"

	"axonflow/platform/agent/license"
)

// HTTP-surface tests for the compliance report facade.
//
// These drive the REAL router - Module.RegisterRoutesWithMux on a gorilla mux -
// rather than calling handler methods directly, so path variable extraction,
// method matching and the by-id/download split are all exercised
// (`[[feedback_test_the_path_not_the_post_parse_shape]]`).

type httpHarness struct {
	*harness
	router *mux.Router
	module *Module
}

func newHTTPHarness(t *testing.T, providers ...DataProvider) *httpHarness {
	t.Helper()
	h := newHarness(t, providers...)
	m := &Module{
		Repo:     h.repo,
		Registry: NewRegistry(providers...),
		Service:  h.svc,
		Handler:  NewHandler(h.svc),
	}
	r := mux.NewRouter()
	m.RegisterRoutesWithMux(r)
	return &httpHarness{harness: h, router: r, module: m}
}

// do issues a request. org/tenant of "" omit the header entirely.
func (h *httpHarness) do(method, path, org, tenant, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if org != "" {
		req.Header.Set("X-Org-ID", org)
	}
	if tenant != "" {
		req.Header.Set("X-Tenant-ID", tenant)
	}
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.router.ServeHTTP(rr, req)
	return rr
}

func (h *httpHarness) createBody(reg Regulator, format Format) string {
	req := validRequest(reg, format)
	return fmt.Sprintf(`{"regulator":%q,"framework":%q,"format":%q,"period_start":%q,"period_end":%q}`,
		req.Regulator, req.Framework, req.Format,
		req.PeriodStart.UTC().Format("2006-01-02T15:04:05Z07:00"),
		req.PeriodEnd.UTC().Format("2006-01-02T15:04:05Z07:00"))
}

func decodeJob(t *testing.T, rr *httptest.ResponseRecorder) ReportJob {
	t.Helper()
	var job ReportJob
	if err := json.Unmarshal(rr.Body.Bytes(), &job); err != nil {
		t.Fatalf("response is not a job: %v (body=%s)", err, rr.Body.String())
	}
	return job
}

func decodeError(t *testing.T, rr *httptest.ResponseRecorder) ErrorResponse {
	t.Helper()
	var e ErrorResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &e); err != nil {
		t.Fatalf("response is not an error envelope: %v (body=%s)", err, rr.Body.String())
	}
	return e
}

// -----------------------------------------------------------------------------
// Happy path
// -----------------------------------------------------------------------------

func TestHTTP_CreatePollDownload(t *testing.T) {
	h := newHTTPHarness(t, populatedProvider(RegulatorEUAIAct))

	// CREATE -> 202
	rr := h.do(http.MethodPost, BasePath, "acme-org", "acme-tenant", h.createBody(RegulatorEUAIAct, FormatJSON))
	if rr.Code != http.StatusAccepted {
		t.Fatalf("create: got %d, want 202. body=%s", rr.Code, rr.Body.String())
	}
	created := decodeJob(t, rr)
	if created.ID == "" {
		t.Fatal("create response carries no id")
	}
	// report_state is ALWAYS present as a key, even while undetermined - that
	// is the whole point of the field (no null collapse).
	if !strings.Contains(rr.Body.String(), `"report_state"`) {
		t.Errorf("create response omits report_state: %s", rr.Body.String())
	}
	// Internal fields must not be echoed. Checking for the JSON KEYS, not for
	// the header values: `requested_by` legitimately carries the caller's own
	// credential id (that is the actor record), so a value-substring check
	// would fail on a correct response.
	for _, key := range []string{`"org_id"`, `"tenant_id"`, `"storage_key"`} {
		if strings.Contains(rr.Body.String(), key) {
			t.Errorf("create response serializes the internal field %s: %s", key, rr.Body.String())
		}
	}
	// The actor IS recorded, and it is derived from the authenticated
	// credential rather than from anything in the request body.
	if created.RequestedBy == "" {
		t.Error("create response records no requesting actor")
	}

	h.svc.WaitForProcessing()

	// POLL -> 200 completed
	rr = h.do(http.MethodGet, BasePath+"/"+created.ID, "acme-org", "acme-tenant", "")
	if rr.Code != http.StatusOK {
		t.Fatalf("poll: got %d, want 200. body=%s", rr.Code, rr.Body.String())
	}
	polled := decodeJob(t, rr)
	if polled.Status != StatusCompleted {
		t.Fatalf("poll status = %s (error=%q), want completed", polled.Status, polled.Error)
	}
	if polled.ReportState != ReportStatePopulated {
		t.Errorf("poll report_state = %q, want populated", polled.ReportState)
	}

	// DOWNLOAD -> 307 to the presigned URL
	rr = h.do(http.MethodGet, BasePath+"/"+created.ID+"/download", "acme-org", "acme-tenant", "")
	if rr.Code != http.StatusTemporaryRedirect {
		t.Fatalf("download: got %d, want 307. body=%s", rr.Code, rr.Body.String())
	}
	loc := rr.Header().Get("Location")
	if !strings.Contains(loc, "compliance-reports/acme-org/") {
		t.Errorf("redirect location does not point at the artifact: %s", loc)
	}
}

// -----------------------------------------------------------------------------
// Unhappy paths (Real-World-Path clause: first-class cases, not afterthoughts)
// -----------------------------------------------------------------------------

func TestHTTP_MissingScopeHeadersAreRefused(t *testing.T) {
	h := newHTTPHarness(t, populatedProvider(RegulatorEUAIAct))
	job := h.runToCompletion(t, validRequest(RegulatorEUAIAct, FormatJSON))

	cases := []struct {
		name        string
		org, tenant string
	}{
		{"neither header", "", ""},
		{"org only", "acme-org", ""},
		{"tenant only", "", "acme-tenant"},
		{"whitespace org", "   ", "acme-tenant"},
		{"whitespace tenant", "acme-org", "  "},
	}
	for _, tc := range cases {
		for _, route := range []struct {
			method string
			path   string
			body   string
		}{
			{http.MethodPost, BasePath, h.createBody(RegulatorEUAIAct, FormatJSON)},
			{http.MethodGet, BasePath + "/" + job.ID, ""},
			{http.MethodGet, BasePath + "/" + job.ID + "/download", ""},
		} {
			t.Run(tc.name+" "+route.method+route.path, func(t *testing.T) {
				rr := h.do(route.method, route.path, tc.org, tc.tenant, route.body)
				if rr.Code != http.StatusUnauthorized {
					t.Errorf("got %d, want 401. body=%s", rr.Code, rr.Body.String())
				}
				if e := decodeError(t, rr); e.ErrorCode != ErrCodeScopeRequired {
					t.Errorf("error_code = %s, want %s", e.ErrorCode, ErrCodeScopeRequired)
				}
			})
		}
	}
}

func TestHTTP_CrossOrgByIDIsA404IndistinguishableFromUnknown(t *testing.T) {
	h := newHTTPHarness(t, populatedProvider(RegulatorEUAIAct))
	job := h.runToCompletion(t, validRequest(RegulatorEUAIAct, FormatJSON))

	foreign := h.do(http.MethodGet, BasePath+"/"+job.ID, "attacker-org", "attacker-tenant", "")
	unknown := h.do(http.MethodGet, BasePath+"/creport-does-not-exist", "attacker-org", "attacker-tenant", "")

	if foreign.Code != http.StatusNotFound {
		t.Fatalf("cross-org poll: got %d, want 404. body=%s", foreign.Code, foreign.Body.String())
	}
	if foreign.Code != unknown.Code || foreign.Body.String() != unknown.Body.String() {
		t.Errorf("cross-org and unknown-id responses differ - the endpoint is an existence oracle.\n cross-org: %d %s\n unknown:   %d %s",
			foreign.Code, foreign.Body.String(), unknown.Code, unknown.Body.String())
	}

	dl := h.do(http.MethodGet, BasePath+"/"+job.ID+"/download", "attacker-org", "attacker-tenant", "")
	if dl.Code != http.StatusNotFound {
		t.Errorf("cross-org download: got %d, want 404. body=%s", dl.Code, dl.Body.String())
	}
	if strings.Contains(dl.Header().Get("Location"), "compliance-reports") {
		t.Error("cross-org download minted a redirect to the artifact")
	}
}

func TestHTTP_UnknownRegulatorAndFormat(t *testing.T) {
	h := newHTTPHarness(t, populatedProvider(RegulatorEUAIAct))

	for _, tc := range []struct {
		name string
		body string
		code string
	}{
		{"unknown regulator", `{"regulator":"fca","format":"pdf","period_start":"2026-01-01T00:00:00Z","period_end":"2026-02-01T00:00:00Z"}`, ErrCodeUnknownRegulator},
		{"unknown format", `{"regulator":"euaiact","format":"docx","period_start":"2026-01-01T00:00:00Z","period_end":"2026-02-01T00:00:00Z"}`, ErrCodeUnsupportedFormat},
		{"format not offered", `{"regulator":"euaiact","format":"xlsx","period_start":"2026-01-01T00:00:00Z","period_end":"2026-02-01T00:00:00Z"}`, ErrCodeUnsupportedFormat},
		{"bad period", `{"regulator":"euaiact","format":"pdf","period_start":"nope","period_end":"2026-02-01T00:00:00Z"}`, ErrCodeInvalidPeriod},
		{"inverted period", `{"regulator":"euaiact","format":"pdf","period_start":"2026-02-01T00:00:00Z","period_end":"2026-01-01T00:00:00Z"}`, ErrCodeInvalidPeriod},
		{"malformed json", `{`, ErrCodeInvalidBody},
		{"unknown field", `{"regulator":"euaiact","format":"pdf","period_start":"2026-01-01T00:00:00Z","period_end":"2026-02-01T00:00:00Z","perod_end":"typo"}`, ErrCodeInvalidBody},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rr := h.do(http.MethodPost, BasePath, "acme-org", "acme-tenant", tc.body)
			if rr.Code != http.StatusBadRequest {
				t.Fatalf("got %d, want 400. body=%s", rr.Code, rr.Body.String())
			}
			if e := decodeError(t, rr); e.ErrorCode != tc.code {
				t.Errorf("error_code = %s, want %s (message: %s)", e.ErrorCode, tc.code, e.Error)
			}
		})
	}
}

// TestHTTP_UnwiredRegulatorIs409WithNotAvailable is the three-state contract's
// whole reason for existing: the portal learns "this module is not enabled"
// from an explicit token, never by inferring it from an empty 200.
func TestHTTP_UnwiredRegulatorIs409WithNotAvailable(t *testing.T) {
	h := newHTTPHarness(t, populatedProvider(RegulatorEUAIAct))

	rr := h.do(http.MethodPost, BasePath, "acme-org", "acme-tenant", h.createBody(RegulatorOJK, FormatPDF))
	if rr.Code != http.StatusConflict {
		t.Fatalf("got %d, want 409. body=%s", rr.Code, rr.Body.String())
	}
	e := decodeError(t, rr)
	if e.ErrorCode != ErrCodeNotAvailable {
		t.Errorf("error_code = %s, want %s", e.ErrorCode, ErrCodeNotAvailable)
	}
	if e.ReportState != ReportStateNotAvailable {
		t.Errorf("report_state = %q, want not_available on the refusal body", e.ReportState)
	}
}

func TestHTTP_UnderTierAndOverLimitHaveDistinctStatusesAndCodes(t *testing.T) {
	t.Run("under tier", func(t *testing.T) {
		h := newHTTPHarness(t, populatedProvider(RegulatorEUAIAct))
		h.lic.exportEnabled = false
		h.lic.tier = license.TierCommunity

		rr := h.do(http.MethodPost, BasePath, "acme-org", "acme-tenant", h.createBody(RegulatorEUAIAct, FormatJSON))
		if rr.Code != http.StatusForbidden {
			t.Fatalf("got %d, want 403. body=%s", rr.Code, rr.Body.String())
		}
		if e := decodeError(t, rr); e.ErrorCode != ErrCodeLicenseRequired {
			t.Errorf("error_code = %s, want %s", e.ErrorCode, ErrCodeLicenseRequired)
		}
	})

	t.Run("over limit", func(t *testing.T) {
		h := newHTTPHarness(t, populatedProvider(RegulatorEUAIAct))
		h.lic.maxPerDay = 1

		if rr := h.do(http.MethodPost, BasePath, "acme-org", "acme-tenant", h.createBody(RegulatorEUAIAct, FormatJSON)); rr.Code != http.StatusAccepted {
			t.Fatalf("first create: got %d, want 202", rr.Code)
		}
		rr := h.do(http.MethodPost, BasePath, "acme-org", "acme-tenant", h.createBody(RegulatorEUAIAct, FormatJSON))
		h.svc.WaitForProcessing()
		if rr.Code != http.StatusTooManyRequests {
			t.Fatalf("second create: got %d, want 429. body=%s", rr.Code, rr.Body.String())
		}
		if e := decodeError(t, rr); e.ErrorCode != ErrCodeRateLimitExceeded {
			t.Errorf("error_code = %s, want %s", e.ErrorCode, ErrCodeRateLimitExceeded)
		}
	})
}

func TestHTTP_DownloadOfAnIncompleteReportIs409(t *testing.T) {
	p := populatedProvider(RegulatorEUAIAct)
	p.fetchErr = errUnavailableForTest
	h := newHTTPHarness(t, p)
	job := h.runToCompletion(t, validRequest(RegulatorEUAIAct, FormatJSON))

	rr := h.do(http.MethodGet, BasePath+"/"+job.ID+"/download", "acme-org", "acme-tenant", "")
	if rr.Code != http.StatusConflict {
		t.Fatalf("got %d, want 409. body=%s", rr.Code, rr.Body.String())
	}
	e := decodeError(t, rr)
	if e.ErrorCode != ErrCodeNotCompleted {
		t.Errorf("error_code = %s, want %s", e.ErrorCode, ErrCodeNotCompleted)
	}
	// The refusal must carry the job's failure MESSAGE, or an operator has to
	// poll a second endpoint to learn why their download 409'd.
	//
	// It carries the STAGE, not the provider's raw error (#3241 round 2, M3).
	// The download 409 is reachable by the same non-admin caller the poll is,
	// so anything readable here is readable by a viewer.
	if !strings.Contains(e.Error, "collecting compliance data") {
		t.Errorf("the 409 does not carry the job's failure message: %s", e.Error)
	}
	if strings.Contains(e.Error, "euaiact report data") {
		t.Errorf("the 409 leaks the provider's raw error text: %s", e.Error)
	}
}

// TestHTTP_ServiceNotInitializedIs503WithACause pins the nil-DB path: routes
// still register (that is the established pattern), and a request answers 503
// naming the cause rather than panicking or 404ing like a wrong URL.
func TestHTTP_ServiceNotInitializedIs503WithACause(t *testing.T) {
	m, err := NewModule(ModuleConfig{}) // no DB
	if err != nil {
		t.Fatalf("NewModule: %v", err)
	}
	if m.IsHealthy() {
		t.Fatal("a module with no database must not report healthy")
	}
	r := mux.NewRouter()
	m.RegisterRoutesWithMux(r)

	req := httptest.NewRequest(http.MethodGet, BasePath+"/creport-1", nil)
	req.Header.Set("X-Org-ID", "acme-org")
	req.Header.Set("X-Tenant-ID", "acme-tenant")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("got %d, want 503. body=%s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "database") {
		t.Errorf("the 503 does not name a cause: %s", rr.Body.String())
	}
}

// TestHTTP_PreflightIsAnswered pins that a bare OPTIONS is answered 200 rather
// than turned into a "scope required" 401 by the header gate.
//
// Scope, stated precisely: in production a REAL browser preflight (one carrying
// Access-Control-Request-Method) never reaches this handler - run.go wraps the
// router in rs/cors with no OptionsPassthrough, so rs/cors terminates it and
// supplies the Access-Control-* headers. What this pins is the OTHER OPTIONS:
// a bare one from a health prober, a proxy, or a hand-rolled client, which does
// reach the router. The handler writes no CORS headers of its own and is not
// claimed to.
func TestHTTP_PreflightIsAnswered(t *testing.T) {
	h := newHTTPHarness(t, populatedProvider(RegulatorEUAIAct))
	for _, path := range []string{BasePath, BasePath + "/creport-1", BasePath + "/creport-1/download"} {
		rr := h.do(http.MethodOptions, path, "", "", "")
		if rr.Code != http.StatusOK {
			t.Errorf("OPTIONS %s: got %d, want 200", path, rr.Code)
		}
	}
}

// TestHTTP_HealthCheckReportsPerRegulatorAvailability pins that the health
// payload answers the same three-state question the API does.
func TestHTTP_HealthCheckReportsPerRegulatorAvailability(t *testing.T) {
	h := newHTTPHarness(t, populatedProvider(RegulatorEUAIAct), populatedProvider(RegulatorSEBI))

	status := h.module.HealthCheck()
	if status["provider_euaiact"] != "ok" {
		t.Errorf("provider_euaiact = %q, want ok", status["provider_euaiact"])
	}
	if status["provider_ojk"] != "not_available" {
		t.Errorf("provider_ojk = %q, want not_available", status["provider_ojk"])
	}
	if len(status) != len(AllRegulators())+1 {
		t.Errorf("health map has %d entries, want one per regulator plus the facade", len(status))
	}
}

var errUnavailableForTest = fmt.Errorf("provider is down for this test")

// TestHTTP_ServeMuxRegistrationSurfaceMatchesGorilla exercises the second
// registration surface.
//
// Every sibling compliance module exposes both a gorilla/mux and an
// http.ServeMux registration, and run.go uses only the first. The ServeMux path
// parses the id and the /download suffix out of the URL by hand rather than
// from route variables, so it is a genuinely separate parser - and an untested
// one would be free to authorize differently from the route it mirrors.
func TestHTTP_ServeMuxRegistrationSurfaceMatchesGorilla(t *testing.T) {
	h := newHTTPHarness(t, populatedProvider(RegulatorEUAIAct))
	job := h.runToCompletion(t, validRequest(RegulatorEUAIAct, FormatJSON))

	sm := http.NewServeMux()
	h.module.RegisterRoutes(sm)

	serve := func(method, path, org, tenant string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(""))
		if org != "" {
			req.Header.Set("X-Org-ID", org)
		}
		if tenant != "" {
			req.Header.Set("X-Tenant-ID", tenant)
		}
		rr := httptest.NewRecorder()
		sm.ServeHTTP(rr, req)
		return rr
	}

	if rr := serve(http.MethodGet, BasePath+"/"+job.ID, "acme-org", "acme-tenant"); rr.Code != http.StatusOK {
		t.Errorf("ServeMux poll: got %d, want 200. body=%s", rr.Code, rr.Body.String())
	}
	if rr := serve(http.MethodGet, BasePath+"/"+job.ID+"/download", "acme-org", "acme-tenant"); rr.Code != http.StatusTemporaryRedirect {
		t.Errorf("ServeMux download: got %d, want 307. body=%s", rr.Code, rr.Body.String())
	}
	// The SAME refusals as the gorilla surface, not a laxer set.
	if rr := serve(http.MethodGet, BasePath+"/"+job.ID, "attacker-org", "attacker-tenant"); rr.Code != http.StatusNotFound {
		t.Errorf("ServeMux cross-org poll: got %d, want 404", rr.Code)
	}
	if rr := serve(http.MethodGet, BasePath+"/"+job.ID, "", ""); rr.Code != http.StatusUnauthorized {
		t.Errorf("ServeMux unscoped poll: got %d, want 401", rr.Code)
	}
	// An unknown sub-resource must 404, never fall through to the poll handler
	// with a truncated id.
	if rr := serve(http.MethodGet, BasePath+"/"+job.ID+"/sections/1", "acme-org", "acme-tenant"); rr.Code != http.StatusNotFound {
		t.Errorf("ServeMux unknown sub-resource: got %d, want 404. body=%s", rr.Code, rr.Body.String())
	}
	// A missing id.
	if rr := serve(http.MethodGet, BasePath+"/", "acme-org", "acme-tenant"); rr.Code != http.StatusBadRequest {
		t.Errorf("ServeMux missing id: got %d, want 400. body=%s", rr.Code, rr.Body.String())
	}
	// A wrong verb on the collection.
	if rr := serve(http.MethodDelete, BasePath, "acme-org", "acme-tenant"); rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("ServeMux DELETE on the collection: got %d, want 405", rr.Code)
	}
}

// TestRequestErrorImplementsError pins that a *RequestError reads as its
// message through the error interface, so a wrapped one is not opaque in a log.
func TestRequestErrorImplementsError(t *testing.T) {
	var err error = &RequestError{Code: ErrCodeInvalidPeriod, Message: "period_end must be after period_start"}
	if err.Error() != "period_end must be after period_start" {
		t.Errorf("Error() = %q", err.Error())
	}
	wrapped := fmt.Errorf("create report: %w", err)
	var reqErr *RequestError
	if !errorsAs(wrapped, &reqErr) || reqErr.Code != ErrCodeInvalidPeriod {
		t.Errorf("a wrapped RequestError does not unwrap to its code")
	}
	if !strings.Contains(wrapped.Error(), "period_end must be after period_start") {
		t.Errorf("the wrapped error loses the message: %v", wrapped)
	}
}

// errorsAs is errors.As, aliased so the import is used only here.
func errorsAs(err error, target interface{}) bool { return errors.As(err, target) }
