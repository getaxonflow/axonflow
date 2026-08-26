// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

// Regression tests for #3367 - the dashboard "Workflows Run" tile read 0 on
// deployments that had run workflows.
//
// execution_history.tenant_id holds the EXECUTING CALLER'S CREDENTIAL id (the
// Basic-auth username; migration 049 dropped the organizations FK precisely so
// an SDK client id could live there). A customer-portal session holds no
// credential at all: portal_default_tenant_id hands it the org's canonical or
// oldest tenant as a display default. ANDing that value against the credential
// column matched zero rows on any deployment whose app credentials are not
// named after the org.
//
// The fix is a TENANCY-WIDTH assertion on the trusted proxy-auth channel
// (sharedidentity.HeaderTenancyScope), honoured only there. These tests pin
// both the grant and every way it must fail closed, plus the fact that a
// caller WITHOUT the assertion keeps the exact per-credential narrowing it had
// before - the no-widening property, which is the reason this is an assertion
// rather than an unconditional org-scoped read.

import (
	"context"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"axonflow/platform/shared/execution"
	sharedidentity "axonflow/platform/shared/identity"
	"axonflow/platform/shared/serviceauth"
	"axonflow/platform/shared/tenantscope"
)

// with3367ProxyAuth installs a real HMAC token generator/validator pair for the
// duration of a test and returns a VALID proxy-auth token. The trust gate is
// half the contract here, so the tests exercise the real validator rather than
// a stub that would accept anything.
func with3367ProxyAuth(t *testing.T) string {
	t.Helper()
	const secret = "test-3367-internal-service-secret-0123456789"
	gen := serviceauth.NewTokenGenerator(secret, nil)
	prevValidator := proxyTokenValidator
	proxyTokenValidator = serviceauth.NewTokenValidator(secret, nil, serviceauth.DefaultClockSkew)
	t.Cleanup(func() { proxyTokenValidator = prevValidator })
	return serviceauth.GetInternalServiceToken(gen)
}

func req3367(tenant, org string, extra map[string]string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/api/v1/unified/executions", nil)
	if tenant != "" {
		r.Header.Set("X-Tenant-ID", tenant)
	}
	if org != "" {
		r.Header.Set("X-Org-ID", org)
	}
	for k, v := range extra {
		r.Header.Set(k, v)
	}
	return r
}

func TestCallerHasOrgTenancyScope_RequiresBothAssertionAndTrustedChannel(t *testing.T) {
	tok := with3367ProxyAuth(t)

	cases := []struct {
		name    string
		headers map[string]string
		want    bool
	}{
		{
			name: "assertion over a valid proxy-auth token",
			headers: map[string]string{
				sharedidentity.HeaderTenancyScope: sharedidentity.TenancyScopeOrg,
				"X-Axonflow-Proxy-Auth":           tok,
			},
			want: true,
		},
		{
			// The whole point of the trust gate: a caller reaching the
			// orchestrator without the HMAC secret cannot mint org-wide
			// tenancy by naming it.
			name: "assertion with NO proxy-auth token",
			headers: map[string]string{
				sharedidentity.HeaderTenancyScope: sharedidentity.TenancyScopeOrg,
			},
			want: false,
		},
		{
			name: "assertion with an INVALID proxy-auth token",
			headers: map[string]string{
				sharedidentity.HeaderTenancyScope: sharedidentity.TenancyScopeOrg,
				"X-Axonflow-Proxy-Auth":           "not-a-valid-hmac-token",
			},
			want: false,
		},
		{
			name:    "valid token but no assertion",
			headers: map[string]string{"X-Axonflow-Proxy-Auth": tok},
			want:    false,
		},
		{
			// Anything other than "org" is ignored, so an absent or garbled
			// header can never become an assertion.
			name: "unrecognized assertion value over a valid token",
			headers: map[string]string{
				sharedidentity.HeaderTenancyScope: "everything",
				"X-Axonflow-Proxy-Auth":           tok,
			},
			want: false,
		},
		{
			// Casing/whitespace normalization, so a proxy that rewrites the
			// value does not silently drop the assertion.
			name: "assertion is case and whitespace insensitive",
			headers: map[string]string{
				sharedidentity.HeaderTenancyScope: "  ORG ",
				"X-Axonflow-Proxy-Auth":           tok,
			},
			want: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := callerHasOrgTenancyScope(req3367("t", "o", tc.headers)); got != tc.want {
				t.Fatalf("callerHasOrgTenancyScope = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestCallerHasOrgTenancyScope_FailsClosedWithNoValidatorConfigured(t *testing.T) {
	prev := proxyTokenValidator
	proxyTokenValidator = nil
	t.Cleanup(func() { proxyTokenValidator = prev })

	r := req3367("t", "o", map[string]string{
		sharedidentity.HeaderTenancyScope: sharedidentity.TenancyScopeOrg,
		"X-Axonflow-Proxy-Auth":           "anything",
	})
	if callerHasOrgTenancyScope(r) {
		t.Fatal("org tenancy scope granted with no configured validator - a deployment that forgot " +
			"AXONFLOW_INTERNAL_SERVICE_SECRET must fail closed, not open")
	}
}

// recordingRepo captures the ListExecutionsRequest the handler actually built.
//
// It exists so these tests drive the REAL ListExecutions rather than a local
// re-statement of its tenancy resolution: a mirror would keep passing after the
// handler drifted away from it, which is the whole failure mode this bug is an
// instance of. Every other method is unused here and fails loudly if reached,
// so a future handler change that starts calling one cannot pass silently.
type recordingRepo struct {
	seen   execution.ListExecutionsRequest
	called bool
}

func (m *recordingRepo) List(_ context.Context, req execution.ListExecutionsRequest) ([]execution.ExecutionStatus, int, error) {
	m.seen = req
	m.called = true
	return nil, 0, nil
}

func (m *recordingRepo) Create(context.Context, *execution.ExecutionStatus) error {
	return errUnused3367
}
func (m *recordingRepo) Update(context.Context, *execution.ExecutionStatus) error {
	return errUnused3367
}
func (m *recordingRepo) Get(context.Context, string) (*execution.ExecutionStatus, error) {
	return nil, errUnused3367
}
func (m *recordingRepo) Delete(context.Context, string, string, string) error { return errUnused3367 }
func (m *recordingRepo) GetByPlanID(context.Context, string) (*execution.ExecutionStatus, error) {
	return nil, errUnused3367
}
func (m *recordingRepo) GetByMetadata(context.Context, string, string) (*execution.ExecutionStatus, error) {
	return nil, errUnused3367
}
func (m *recordingRepo) UpdateStatus(context.Context, string, string, string, execution.ExecutionStatusValue, *time.Time, string) error {
	return errUnused3367
}
func (m *recordingRepo) UpdateSteps(context.Context, string, string, string, []execution.StepStatus) error {
	return errUnused3367
}
func (m *recordingRepo) UpdateCost(context.Context, string, string, string, *float64, *float64) error {
	return errUnused3367
}
func (m *recordingRepo) ExpireExecution(context.Context, string, string, string, map[string]interface{}) error {
	return errUnused3367
}
func (m *recordingRepo) CountActive(context.Context, string) (int, error) { return 0, errUnused3367 }
func (m *recordingRepo) PurgeOldest(context.Context, string, string, int) (int64, error) {
	return 0, errUnused3367
}

var errUnused3367 = errors.New("recordingRepo: method not expected in #3367 scope tests")

// listScopeFor drives the real handler and returns the scope it resolved.
func listScopeFor(t *testing.T, r *http.Request) execution.ListExecutionsRequest {
	t.Helper()
	repo := &recordingRepo{}
	h := NewUnifiedExecutionHandler(repo, nil, nil, nil, nil)
	h.logger = log.New(io.Discard, "", 0)
	w := httptest.NewRecorder()
	h.ListExecutions(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("ListExecutions returned %d, want 200 (body: %s)", w.Code, w.Body.String())
	}
	return repo.seen
}

func TestListExecutionsScope_OrgAssertionDropsTheCredentialNarrowing(t *testing.T) {
	tok := with3367ProxyAuth(t)

	// The portal shape: the session's tenant is the org's display default and
	// matches no credential that ever executed anything.
	got := listScopeFor(t, req3367("acme-org", "acme-org", map[string]string{
		sharedidentity.HeaderTenancyScope: sharedidentity.TenancyScopeOrg,
		"X-Axonflow-Proxy-Auth":           tok,
	}))
	if got.TenantID != "" {
		t.Fatalf("TenantID = %q, want empty: an org-bound caller must not be narrowed to a credential id", got.TenantID)
	}
	if got.OrgID != "acme-org" {
		t.Fatalf("OrgID = %q, want acme-org: the org predicate is the entire tenancy boundary here", got.OrgID)
	}
	if !got.OrgWide {
		t.Fatal("OrgWide = false: the repository refuses the BYPASSRLS org-wide read without an explicit " +
			"statement of authority, so clearing the tenant alone would silently keep the RLS narrowing")
	}
}

func TestListExecutionsScope_AgentCallerKeepsItsCredentialNarrowing(t *testing.T) {
	tok := with3367ProxyAuth(t)

	// The agent gateway rides the same trusted channel but asserts no org
	// tenancy scope, so an SDK caller keeps reading exactly its own
	// credential's executions. Widening THAT is a separate decision about who
	// may see a sibling credential's step names, models and costs.
	got := listScopeFor(t, req3367("payments-app", "acme-org", map[string]string{
		"X-Axonflow-Proxy-Auth": tok,
	}))
	if got.TenantID != "payments-app" {
		t.Fatalf("TenantID = %q, want payments-app: the agent path must not be widened by #3367", got.TenantID)
	}
	if got.OrgWide {
		t.Fatal("OrgWide = true for an agent caller: the org-wide read is not the agent path's")
	}
}

func TestListExecutionsScope_AssertionWithoutAnOrgIsNotHonoured(t *testing.T) {
	tok := with3367ProxyAuth(t)

	// Dropping the tenant predicate with no org to replace it would turn the
	// read into a deployment-wide listing. The org must be present for the
	// narrowing to be dropped, and the repository refuses an org-wide read
	// without one as a second, independent guard.
	got := listScopeFor(t, req3367("payments-app", "", map[string]string{
		sharedidentity.HeaderTenancyScope: sharedidentity.TenancyScopeOrg,
		"X-Axonflow-Proxy-Auth":           tok,
	}))
	if got.TenantID != "payments-app" {
		t.Fatalf("TenantID = %q, want payments-app: an org-less assertion must not strip the only predicate left", got.TenantID)
	}
	if got.OrgWide {
		t.Fatal("OrgWide = true with no org: the repository would refuse it, but the handler must not ask")
	}
}

func TestCheckTenantOwnership_3367(t *testing.T) {
	tok := with3367ProxyAuth(t)
	h := &UnifiedExecutionHandler{logger: log.New(io.Discard, "", 0)}

	orgAsserted := map[string]string{
		sharedidentity.HeaderTenancyScope: sharedidentity.TenancyScopeOrg,
		"X-Axonflow-Proxy-Auth":           tok,
	}

	cases := []struct {
		name     string
		tenant   string
		org      string
		extra    map[string]string
		exec     *execution.ExecutionStatus
		wantOK   bool
		wantCode int
	}{
		{
			// The defect: the row the org-scoped list now returns must also
			// open, or the fix would hand the operator a list of 404s.
			name: "org-scoped caller opens a row stamped with another credential",
			// The session's tenant is the org; the row's is the runner app.
			tenant: "acme-org", org: "acme-org", extra: orgAsserted,
			exec:   &execution.ExecutionStatus{TenantID: "payments-app", OrgID: "acme-org"},
			wantOK: true,
		},
		{
			name:   "org-scoped caller is still refused across ORGS",
			tenant: "acme-org", org: "acme-org", extra: orgAsserted,
			exec:     &execution.ExecutionStatus{TenantID: "payments-app", OrgID: "other-org"},
			wantOK:   false,
			wantCode: http.StatusNotFound,
		},
		{
			// A row owned by nobody stays owned by nobody: the org compare is
			// strict, so an empty row org can never alias an empty header.
			name:   "org-scoped caller is refused a row with no org",
			tenant: "acme-org", org: "acme-org", extra: orgAsserted,
			exec:     &execution.ExecutionStatus{TenantID: "payments-app", OrgID: ""},
			wantOK:   false,
			wantCode: http.StatusNotFound,
		},
		{
			name:   "org-scoped caller with no org header is unauthorized",
			tenant: "acme-org", org: "", extra: orgAsserted,
			exec:     &execution.ExecutionStatus{TenantID: "payments-app", OrgID: "acme-org"},
			wantOK:   false,
			wantCode: http.StatusUnauthorized,
		},
		{
			// No assertion: unchanged pre-#3367 behaviour, including the
			// tenant mismatch 404 that IS the cross-credential boundary.
			name:   "credential-scoped caller still 404s on a tenant mismatch",
			tenant: "billing-app", org: "acme-org",
			exec:     &execution.ExecutionStatus{TenantID: "payments-app", OrgID: "acme-org"},
			wantOK:   false,
			wantCode: http.StatusNotFound,
		},
		{
			name:   "credential-scoped caller opens its own row",
			tenant: "payments-app", org: "acme-org",
			exec:   &execution.ExecutionStatus{TenantID: "payments-app", OrgID: "acme-org"},
			wantOK: true,
		},
		{
			name:   "credential-scoped caller with no tenant header is unauthorized",
			tenant: "", org: "acme-org",
			exec:     &execution.ExecutionStatus{TenantID: "payments-app", OrgID: "acme-org"},
			wantOK:   false,
			wantCode: http.StatusUnauthorized,
		},
		{
			// An UNTRUSTED assertion must behave exactly like no assertion.
			name:   "untrusted assertion does not open another credential's row",
			tenant: "acme-org", org: "acme-org",
			extra:    map[string]string{sharedidentity.HeaderTenancyScope: sharedidentity.TenancyScopeOrg},
			exec:     &execution.ExecutionStatus{TenantID: "payments-app", OrgID: "acme-org"},
			wantOK:   false,
			wantCode: http.StatusNotFound,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			got := h.checkTenantOwnership(w, req3367(tc.tenant, tc.org, tc.extra), tc.exec)
			if got != tc.wantOK {
				t.Fatalf("checkTenantOwnership = %v (status %d), want %v", got, w.Code, tc.wantOK)
			}
			if !tc.wantOK && w.Code != tc.wantCode {
				t.Fatalf("status = %d, want %d", w.Code, tc.wantCode)
			}
		})
	}
}

// TestListExecutionsScope_OmittingTheTenantHeaderIsNotAnAssertion is the R3
// round-1 regression guard.
//
// The first revision keyed the repository's BYPASSRLS org-wide read on the
// FILTER SHAPE "org set, tenant empty". That shape is produced by simply
// OMITTING a header, so any caller past the orchestrator's proxy-auth gate
// could reach it without the tenancy assertion - and, worse, a read that was
// previously narrowed by mig 042's RLS would have silently become a bypassing
// one. The authority is now an explicit field the handler sets, and this pins
// that the header-shaped route to it is closed.
func TestListExecutionsScope_OmittingTheTenantHeaderIsNotAnAssertion(t *testing.T) {
	tok := with3367ProxyAuth(t)

	got := listScopeFor(t, req3367("", "acme-org", map[string]string{
		"X-Axonflow-Proxy-Auth": tok,
	}))
	if got.OrgWide {
		t.Fatal("OrgWide = true from an omitted X-Tenant-ID: a BYPASSRLS read must be gated on the " +
			"caller's authority, never on the shape of the headers it happened to send")
	}
	if got.OrgID != "acme-org" || got.TenantID != "" {
		t.Fatalf("scope = %+v, want the unchanged org-only shape", got)
	}
}

// TestCancelKeepsTheStrictCredentialCompare pins that the org-only relaxation
// is a READ decision: the mutating route resolves ownership through the strict
// form and is unaffected by the assertion.
func TestCancelKeepsTheStrictCredentialCompare(t *testing.T) {
	tok := with3367ProxyAuth(t)
	h := &UnifiedExecutionHandler{logger: log.New(io.Discard, "", 0)}

	r := req3367("acme-org", "acme-org", map[string]string{
		sharedidentity.HeaderTenancyScope: sharedidentity.TenancyScopeOrg,
		"X-Axonflow-Proxy-Auth":           tok,
	})
	exec := &execution.ExecutionStatus{TenantID: "payments-app", OrgID: "acme-org"}

	if !h.checkTenantOwnership(httptest.NewRecorder(), r, exec) {
		t.Fatal("read form refused an org-scoped caller; the fix is not in effect")
	}
	w := httptest.NewRecorder()
	if h.checkTenantOwnershipStrict(w, r, exec) {
		t.Fatal("WRITE form accepted the org-wide assertion: cancel would let any org-bound session " +
			"abort another credential's execution, which is a separate unreviewed authorization change")
	}
	if w.Code != http.StatusNotFound {
		t.Fatalf("strict refusal status = %d, want 404", w.Code)
	}
}

// TestAuthorizeExecution_SentinelAndBlankOrgsFailClosed pins that the handler
// half and the repository half agree on what a usable org key is. A raw `!=`
// compare here would have let a deployment whose ORG_ID is the migration
// core/156 unowned sentinel open every unowned row, while the list refused
// them through tenantscope.ValidateOrgKey.
func TestAuthorizeExecution_SentinelAndBlankOrgsFailClosed(t *testing.T) {
	tok := with3367ProxyAuth(t)
	h := &UnifiedExecutionHandler{logger: log.New(io.Discard, "", 0)}
	orgAsserted := map[string]string{
		sharedidentity.HeaderTenancyScope: sharedidentity.TenancyScopeOrg,
		"X-Axonflow-Proxy-Auth":           tok,
	}

	cases := []struct {
		name       string
		callerOrg  string
		rowOrg     string
		wantStatus int
	}{
		{"sentinel on both sides", tenantscope.UnownedOrgSentinel, tenantscope.UnownedOrgSentinel, http.StatusNotFound},
		{"sentinel caller, real row", tenantscope.UnownedOrgSentinel, "acme-org", http.StatusNotFound},
		{"real caller, sentinel row", "acme-org", tenantscope.UnownedOrgSentinel, http.StatusNotFound},
		{"whitespace-only caller org", "   ", "acme-org", http.StatusUnauthorized},
		{"whitespace-only row org", "acme-org", "   ", http.StatusNotFound},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			ok := h.authorizeExecution(w, req3367("acme-org", tc.callerOrg, orgAsserted),
				&execution.ExecutionStatus{TenantID: "payments-app", OrgID: tc.rowOrg}, true)
			if ok {
				t.Fatal("authorized an unusable org key pair")
			}
			if w.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d", w.Code, tc.wantStatus)
			}
		})
	}
}

// R3 MAJOR-1. A request carrying NEITHER identity header used to fall through
// to the repository's filterless arm, which ran `FROM execution_history WHERE
// 1=1` on the owner pool: every org's executions, returned to whoever asked.
// The comment justifying it named an "ops/admin path" that does not exist, so
// the only reachable caller was a bug or a degenerate session. It must refuse,
// with the same status the by-id path gives the same input.
func TestListExecutions_RefusesARequestWithNoIdentity_3367(t *testing.T) {
	repo := &recordingRepo{}
	h := NewUnifiedExecutionHandler(repo, nil, nil, nil, nil)
	h.logger = log.New(io.Discard, "", 0)
	w := httptest.NewRecorder()

	h.ListExecutions(w, req3367("", "", nil))

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("ListExecutions with no tenant and no org returned %d, want 401. An unscoped read of "+
			"execution_history is every org's executions (body: %s)", w.Code, w.Body.String())
	}
	if repo.called {
		t.Fatal("the repository was queried despite the missing identity; the refusal must precede the read")
	}
}

// A whitespace-only pair is the same case wearing a disguise: the guard has to
// judge the trimmed string or the refusal is one space away from bypassed.
func TestListExecutions_RefusesAWhitespaceOnlyIdentity_3367(t *testing.T) {
	repo := &recordingRepo{}
	h := NewUnifiedExecutionHandler(repo, nil, nil, nil, nil)
	h.logger = log.New(io.Discard, "", 0)
	w := httptest.NewRecorder()

	h.ListExecutions(w, req3367("   ", "  ", nil))

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("whitespace-only identity returned %d, want 401 (body: %s)", w.Code, w.Body.String())
	}
}
