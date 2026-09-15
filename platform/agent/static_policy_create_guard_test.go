// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/gorilla/mux"

	"axonflow/platform/shared/legacyfreeze"
)

// #4237 follow-up (family comment issuecomment-5655885447): the system-policy
// create validates its required fields before the write, and update looks the
// row up, checks its tier and pattern and returns early when nothing changes,
// all before the write - so on a deployment whose connection may not write
// static_policies those requests were answered 400, 403, 404 or even 200, never
// the freeze. Create, update and toggle now ask the database first. Delete
// takes no body; its lookup answering an unknown id first is tracked on #4249.

const staticCreateProbe = "SELECT has_table_privilege($1::text, 'INSERT')"

// staticCreateBody records whether anything read the request body.
type staticCreateBody struct {
	r     io.Reader
	reads int
}

func (b *staticCreateBody) Read(p []byte) (int, error) {
	b.reads++
	return b.r.Read(p)
}

// createThroughGuard serves one system-policy create over a sqlmock pool whose
// only expectation is the one the test queues.
func createThroughGuard(t *testing.T, body string, withTenant bool, queue func(sqlmock.Sqlmock)) (*httptest.ResponseRecorder, *staticCreateBody, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherEqual))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	queue(mock)
	rb := &staticCreateBody{r: strings.NewReader(body)}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/system-policies", rb)
	req.Header.Set("Content-Type", "application/json")
	if withTenant {
		ctx := context.WithValue(req.Context(), ContextKeyTenantID, "test-tenant")
		ctx = context.WithValue(ctx, ContextKeyOrgID, "test-org")
		req = req.WithContext(ctx)
	}
	rr := httptest.NewRecorder()
	NewStaticPolicyAPIHandler(db).HandleCreateStaticPolicy(rr, req)
	return rr, rb, mock
}

func probeAnswers(held bool) func(sqlmock.Sqlmock) {
	return func(m sqlmock.Sqlmock) {
		m.ExpectQuery(staticCreateProbe).WithArgs("static_policies").
			WillReturnRows(sqlmock.NewRows([]string{"has_table_privilege"}).AddRow(held))
	}
}

// TestSystemPolicyCreateIsRefusedBeforeItsBodyIsReadWhereTheWriteIsRevoked is
// the guard's contract: every body class is the freeze with the string code,
// the one message and the typed route, and the body is never read.
func TestSystemPolicyCreateIsRefusedBeforeItsBodyIsReadWhereTheWriteIsRevoked(t *testing.T) {
	for _, b := range []struct{ name, body string }{
		{"a realistic body", `{"name":"W3X guard probe","pattern":"w3x-never-matches-[0-9]{40}","category":"security-sqli","action":"block","tier":"tenant"}`},
		{"a body missing its required fields", `{"name":"W3X guard probe"}`},
		{"an empty body", ""},
		{"invalid JSON", "{"},
	} {
		t.Run(b.name, func(t *testing.T) {
			rr, rb, mock := createThroughGuard(t, b.body, true, probeAnswers(false))
			if rr.Code != http.StatusConflict {
				t.Fatalf("status=%d, want 409 - a revoked deployment can create nothing, whatever the body. body=%s", rr.Code, rr.Body.String())
			}
			var out struct {
				Error struct {
					Code    string `json:"code"`
					Message string `json:"message"`
				} `json:"error"`
			}
			if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
				t.Fatalf("decode: %v (%s)", err, rr.Body.String())
			}
			if out.Error.Code != legacyfreeze.ErrCode || out.Error.Message != legacyfreeze.Message {
				t.Fatalf("code=%q message=%q, want %q and legacyfreeze.Message", out.Error.Code, out.Error.Message, legacyfreeze.ErrCode)
			}
			if !strings.Contains(out.Error.Message, legacyfreeze.TypedAuthoringRoute) {
				t.Fatalf("the refusal does not name the typed authoring route: %q", out.Error.Message)
			}
			if rb.reads != 0 {
				t.Fatalf("the body was read %d time(s) before the refusal", rb.reads)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatalf("the probe was not asked: %v", err)
			}
		})
	}
}

// TestSystemPolicyCreateProceedsWhereTheConnectionMayWrite is the twin: where
// the connection may write, or the probe cannot be answered, the create goes on
// to its own required-field refusal, exactly as before the guard.
func TestSystemPolicyCreateProceedsWhereTheConnectionMayWrite(t *testing.T) {
	for name, queue := range map[string]func(sqlmock.Sqlmock){
		"an owner pool": probeAnswers(true),
		"an unanswered probe": func(m sqlmock.Sqlmock) {
			m.ExpectQuery(staticCreateProbe).WithArgs("static_policies").WillReturnError(errors.New("connection reset by peer"))
		},
	} {
		t.Run(name, func(t *testing.T) {
			rr, rb, _ := createThroughGuard(t, `{"pattern":"x","category":"security-sqli","action":"block"}`, true, queue)
			if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "name is required") {
				t.Fatalf("status=%d body=%s, want the create's own 400 \"name is required\"", rr.Code, rr.Body.String())
			}
			if rb.reads == 0 {
				t.Fatal("the body was never read: the create did not proceed past the guard")
			}
		})
	}
}

// TestSystemPolicyCreateAnswersAuthenticationBeforeTheFreeze: a caller with no
// tenant is told so, and the database is not asked - the queued probe stays
// unmet.
func TestSystemPolicyCreateAnswersAuthenticationBeforeTheFreeze(t *testing.T) {
	rr, rb, mock := createThroughGuard(t, `{"name":"W3X guard probe"}`, false, probeAnswers(false))
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d, want 401. body=%s", rr.Code, rr.Body.String())
	}
	if err := mock.ExpectationsWereMet(); err == nil {
		t.Fatal("the probe was asked before authentication")
	}
	if rb.reads != 0 {
		t.Fatalf("the body was read %d time(s) before authentication", rb.reads)
	}
}

// updateOrToggleThroughGuard serves one system-policy update (PUT) or toggle
// (PATCH) over a sqlmock pool whose only expectation is the one the test
// queues. A lookup that ran before the guard would be an unexpected query, so
// a 409 here is also the proof that the guard answered before the lookup.
func updateOrToggleThroughGuard(t *testing.T, method, body string, queue func(sqlmock.Sqlmock)) (*httptest.ResponseRecorder, *staticCreateBody, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherEqual))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	queue(mock)
	rb := &staticCreateBody{r: strings.NewReader(body)}
	req := httptest.NewRequest(method, "/api/v1/system-policies/w3x-guard-probe", rb)
	req.Header.Set("Content-Type", "application/json")
	ctx := context.WithValue(req.Context(), ContextKeyTenantID, "test-tenant")
	ctx = context.WithValue(ctx, ContextKeyOrgID, "test-org")
	req = mux.SetURLVars(req.WithContext(ctx), map[string]string{"id": "w3x-guard-probe"})
	rr := httptest.NewRecorder()
	h := NewStaticPolicyAPIHandler(db)
	if method == http.MethodPut {
		h.HandleUpdateStaticPolicy(rr, req)
	} else {
		h.HandleTogglePolicy(rr, req)
	}
	return rr, rb, mock
}

// TestSystemPolicyUpdateAndToggleAreRefusedBeforeTheBodyOrTheLookup is master's
// 2026-09-14 ruling on R3 round 1's H1: an invalid pattern (a 400 before), a body
// that changes nothing (a 200 before, a false success) and a toggle's invalid
// JSON (a 400 before) are the freeze, the body is never read and the row is
// never looked up.
func TestSystemPolicyUpdateAndToggleAreRefusedBeforeTheBodyOrTheLookup(t *testing.T) {
	for _, c := range []struct{ name, method, body string }{
		{"update, a realistic body", http.MethodPut, `{"name":"W3X renamed"}`},
		{"update, an invalid pattern", http.MethodPut, `{"pattern":"("}`},
		{"update, a body that changes nothing", http.MethodPut, `{}`},
		{"update, invalid JSON", http.MethodPut, "{"},
		{"toggle, a realistic body", http.MethodPatch, `{"enabled":false}`},
		{"toggle, invalid JSON", http.MethodPatch, "{"},
	} {
		t.Run(c.name, func(t *testing.T) {
			rr, rb, mock := updateOrToggleThroughGuard(t, c.method, c.body, probeAnswers(false))
			if rr.Code != http.StatusConflict {
				t.Fatalf("status=%d, want 409 - a revoked deployment can change nothing, whatever the body. body=%s", rr.Code, rr.Body.String())
			}
			var out struct {
				Error struct {
					Code    string `json:"code"`
					Message string `json:"message"`
				} `json:"error"`
			}
			if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
				t.Fatalf("decode: %v (%s)", err, rr.Body.String())
			}
			if out.Error.Code != legacyfreeze.ErrCode || out.Error.Message != legacyfreeze.Message {
				t.Fatalf("code=%q message=%q, want %q and legacyfreeze.Message", out.Error.Code, out.Error.Message, legacyfreeze.ErrCode)
			}
			if !strings.Contains(out.Error.Message, legacyfreeze.TypedAuthoringRoute) {
				t.Fatalf("the refusal does not name the typed authoring route: %q", out.Error.Message)
			}
			if rb.reads != 0 {
				t.Fatalf("the body was read %d time(s) before the refusal", rb.reads)
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatalf("the probe was not asked: %v", err)
			}
		})
	}
}

// TestSystemPolicyUpdateAndToggleProceedWhereTheConnectionMayWrite is the twin:
// where the connection may write, or the probe cannot be answered, update and
// toggle go on to their own decode, exactly as before the guard.
func TestSystemPolicyUpdateAndToggleProceedWhereTheConnectionMayWrite(t *testing.T) {
	for name, queue := range map[string]func(sqlmock.Sqlmock){
		"an owner pool": probeAnswers(true),
		"an unanswered probe": func(m sqlmock.Sqlmock) {
			m.ExpectQuery(staticCreateProbe).WithArgs("static_policies").WillReturnError(errors.New("connection reset by peer"))
		},
	} {
		for _, method := range []string{http.MethodPut, http.MethodPatch} {
			t.Run(name+" "+method, func(t *testing.T) {
				rr, rb, _ := updateOrToggleThroughGuard(t, method, "{", queue)
				if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "Invalid request body") {
					t.Fatalf("status=%d body=%s, want the handler's own 400 \"Invalid request body\"", rr.Code, rr.Body.String())
				}
				if rb.reads == 0 {
					t.Fatal("the body was never read: the handler did not proceed past the guard")
				}
			})
		}
	}
}

// TestTheSystemPolicyProbeWithoutAPoolFallsThrough: a repository with no pool
// reports an error rather than panicking, so a handler built without a
// database behaves as it did before the guard.
func TestTheSystemPolicyProbeWithoutAPoolFallsThrough(t *testing.T) {
	var nilRepo *StaticPolicyRepository
	if may, err := nilRepo.MayWriteLegacyPolicies(context.Background()); !errors.Is(err, errNoStaticPolicyPool) || may {
		t.Fatalf("nil repository: %v, %v; want false and errNoStaticPolicyPool", may, err)
	}
	if may, err := NewStaticPolicyRepository(nil).MayWriteLegacyPolicies(context.Background()); !errors.Is(err, errNoStaticPolicyPool) || may {
		t.Fatalf("repository without a pool: %v, %v; want false and errNoStaticPolicyPool", may, err)
	}
}
