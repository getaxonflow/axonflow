// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

// Read-scope observability coverage (#1, #2991): the additive
// X-Axonflow-Read-Scope response header maps 1:1 to the resolved scope, and the
// fail-closed "none" path emits a diagnostic log line. Purely diagnostic — no
// response-body change.

import (
	"bytes"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	sharedidentity "axonflow/platform/shared/identity"
)

func TestReadScopeLabel(t *testing.T) {
	cases := []struct {
		name  string
		scope callerReadScope
		want  string
	}{
		{"tenant-wide", callerReadScope{TenantWide: true}, "tenant"},
		{"own-rows", callerReadScope{UserEmail: "dev@example.com"}, "own-rows"},
		{"none (fail-closed empty)", callerReadScope{}, "none"},
		// TenantWide wins even if an email is also present (admin path).
		{"tenant-wide takes precedence", callerReadScope{TenantWide: true, UserEmail: "dev@example.com"}, "tenant"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := readScopeLabel(c.scope); got != c.want {
				t.Errorf("readScopeLabel(%+v) = %q, want %q", c.scope, got, c.want)
			}
		})
	}
}

func TestApplyReadScopeHeader_SetsHeaderPerScope(t *testing.T) {
	cases := []struct {
		name      string
		scope     callerReadScope
		wantValue string
		wantLog   bool
	}{
		{"tenant", callerReadScope{TenantWide: true}, "tenant", false},
		{"own-rows", callerReadScope{UserEmail: "dev@example.com"}, "own-rows", false},
		{"none logs", callerReadScope{}, "none", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var buf bytes.Buffer
			origOut, origFlags := log.Writer(), log.Flags()
			log.SetOutput(&buf)
			log.SetFlags(0)
			defer func() { log.SetOutput(origOut); log.SetFlags(origFlags) }()

			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/api/v1/audit/report", nil)

			got := applyReadScopeHeader(rec, req, c.scope)
			if got != c.wantValue {
				t.Errorf("returned label = %q, want %q", got, c.wantValue)
			}
			if hv := rec.Header().Get(sharedidentity.HeaderReadScope); hv != c.wantValue {
				t.Errorf("%s header = %q, want %q", sharedidentity.HeaderReadScope, hv, c.wantValue)
			}
			logged := strings.Contains(buf.String(), "[read-scope]")
			if logged != c.wantLog {
				t.Errorf("logged=%v, want %v (log output: %q)", logged, c.wantLog, buf.String())
			}
			if c.wantLog {
				// The diagnostic must point at the docs anchor for the partner.
				if !strings.Contains(buf.String(), "role-scoped-reads") {
					t.Errorf("none-path log must reference the docs anchor; got: %s", buf.String())
				}
			}
		})
	}
}

// TestApplyReadScopeHeader_HeaderNameMatchesInboundConstant documents that the
// response header intentionally reuses the inbound HeaderReadScope name; the
// value vocabulary on the wire is tenant/own-rows/none.
func TestApplyReadScopeHeader_HeaderNameMatchesInboundConstant(t *testing.T) {
	if sharedidentity.HeaderReadScope != "X-Axonflow-Read-Scope" {
		t.Fatalf("HeaderReadScope = %q, want X-Axonflow-Read-Scope", sharedidentity.HeaderReadScope)
	}
	if sharedidentity.ReadScopeTenant != "tenant" {
		t.Fatalf("ReadScopeTenant = %q, want tenant", sharedidentity.ReadScopeTenant)
	}
}
