// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"axonflow/platform/shared/legacyfreeze"
)

// #4237 follow-up (family comment issuecomment-5655885447): template apply
// validates its request before PolicyRepository.Create, so on a deployment
// whose connection may not write dynamic_policies a bad request was answered
// 400, never the freeze. It now asks the database first, as the policy routes do.
// readCounter and codedError are legacy_policy_import_guard_test.go's.

func applyThroughGuard(t *testing.T, svc *mockTemplateService, body string, headers map[string]string) (*httptest.ResponseRecorder, *readCounter) {
	t.Helper()
	rc := &readCounter{r: strings.NewReader(body)}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/templates/template-123/apply", rc)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	NewTemplateAPIHandler(svc).HandleApplyTemplate(w, req, "template-123")
	return w, rc
}

// guardedTemplateService counts probes and applies.
func guardedTemplateService(may bool, probeErr error) (*mockTemplateService, *int, *int) {
	probes, applies := 0, 0
	return &mockTemplateService{
		mayWriteFunc: func(context.Context) (bool, error) { probes++; return may, probeErr },
		applyTemplateFunc: func(context.Context, string, string, string, *ApplyTemplateRequest, string) (*ApplyTemplateResponse, error) {
			applies++
			return &ApplyTemplateResponse{Success: true, UsageID: "usage-1"}, nil
		},
	}, &probes, &applies
}

var templateTenantAndOrg = map[string]string{"X-Tenant-ID": "tenant-123", "X-Org-ID": "org-123"}

// TestTemplateApplyIsRefusedBeforeItsBodyIsReadWhereTheWriteIsRevoked: every
// body class is the freeze - the code, the one message, the typed route - the
// body is never read and the service never applies.
func TestTemplateApplyIsRefusedBeforeItsBodyIsReadWhereTheWriteIsRevoked(t *testing.T) {
	for _, b := range []struct{ name, body string }{
		{"a realistic body", `{"variables":{"threshold":100},"policy_name":"My Policy","enabled":true}`},
		{"a body that fails validation", `{"variables":{},"policy_name":""}`},
		{"an empty body", ""},
		{"invalid JSON", "{"},
	} {
		t.Run(b.name, func(t *testing.T) {
			svc, probes, applies := guardedTemplateService(false, nil)
			w, rc := applyThroughGuard(t, svc, b.body, templateTenantAndOrg)
			if w.Code != http.StatusConflict {
				t.Fatalf("status=%d, want 409 - a revoked deployment can apply nothing, whatever the body. body=%s", w.Code, w.Body.String())
			}
			out := decodeCoded(t, w)
			if out.Error.Code != legacyfreeze.ErrCode || out.Error.Message != legacyfreeze.Message {
				t.Fatalf("code=%q message=%q, want %q and legacyfreeze.Message", out.Error.Code, out.Error.Message, legacyfreeze.ErrCode)
			}
			if !strings.Contains(out.Error.Message, TypedAuthoringRoutePrefix) {
				t.Fatalf("the refusal does not name the typed authoring route: %q", out.Error.Message)
			}
			if rc.reads != 0 || *applies != 0 || *probes != 1 {
				t.Fatalf("reads=%d applies=%d probes=%d, want no read, no apply and one probe", rc.reads, *applies, *probes)
			}
		})
	}
}

// TestTemplateApplyProceedsWhereTheConnectionMayWrite is the twin: an owner
// pool, or an unanswered probe, applies as before.
func TestTemplateApplyProceedsWhereTheConnectionMayWrite(t *testing.T) {
	for name, probeErr := range map[string]error{"an owner pool": nil, "an unanswered probe": errors.New("connection reset by peer")} {
		t.Run(name, func(t *testing.T) {
			svc, _, applies := guardedTemplateService(probeErr == nil, probeErr)
			w, rc := applyThroughGuard(t, svc, `{"variables":{"threshold":100},"policy_name":"My Policy","enabled":true}`, templateTenantAndOrg)
			if w.Code != http.StatusCreated || *applies != 1 || rc.reads == 0 {
				t.Fatalf("status=%d applies=%d reads=%d, want 201 with one apply and a read body. body=%s", w.Code, *applies, rc.reads, w.Body.String())
			}
		})
	}
}

// TestTemplateApplyAnswersAuthenticationBeforeTheFreeze: a missing tenant and a
// missing organization are each 401, and the database is not asked.
func TestTemplateApplyAnswersAuthenticationBeforeTheFreeze(t *testing.T) {
	for _, c := range []struct {
		name    string
		headers map[string]string
		code    string
	}{
		{"no tenant", map[string]string{}, "UNAUTHORIZED"},
		{"a tenant but no organization", map[string]string{"X-Tenant-ID": "tenant-123"}, "ORG_REQUIRED"},
	} {
		t.Run(c.name, func(t *testing.T) {
			svc, probes, _ := guardedTemplateService(false, nil)
			w, rc := applyThroughGuard(t, svc, `{"policy_name":"My Policy"}`, c.headers)
			if w.Code != http.StatusUnauthorized || decodeCoded(t, w).Error.Code != c.code {
				t.Fatalf("status=%d body=%s, want 401 %s", w.Code, w.Body.String(), c.code)
			}
			if *probes != 0 || rc.reads != 0 {
				t.Fatalf("probes=%d reads=%d, want neither before authentication", *probes, rc.reads)
			}
		})
	}
}
