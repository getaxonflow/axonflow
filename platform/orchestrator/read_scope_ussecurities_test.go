// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestUSSecurities_BasePathMatchesTheExportClassConstant guards the copy of the
// US securities route prefix that read_scope.go carries.
//
// read_scope.go compiles in BOTH editions, so it cannot import the
// Enterprise-tagged ussecurities package to reference its exported path
// constant. The prefix is therefore copied there, and a copy that drifts would
// silently UN-GATE the route: the gate would simply stop matching, and an
// exam-readiness request from a non-admin caller would pass straight through.
//
// This half is edition-independent. The other half - that the copy still matches
// the literal the module ACTUALLY registers, read out of ussecurities/wire.go
// source - is Enterprise-only and lives in
// read_scope_ussecurities_enterprise_test.go.
func TestUSSecurities_BasePathMatchesTheExportClassConstant(t *testing.T) {
	const want = "/api/v1/ussecurities"
	if usSecuritiesBasePath != want {
		t.Fatalf("usSecuritiesBasePath = %q, want %q", usSecuritiesBasePath, want)
	}
}

// TestUSSecuritiesExamReadinessIsGatedAsAWholeTenantExport pins that the route
// is actually IN the export class, not merely adjacent to it.
//
// A constant that names the right prefix but is never added to
// tenantWideAuditExportPaths is a gate in name only. This asserts the predicate
// the middleware consults, which is the thing that decides.
func TestUSSecuritiesExamReadinessIsGatedAsAWholeTenantExport(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{"/api/v1/ussecurities/exam-readiness", true},
		// Prefix matching, so a future route under the module inherits the gate
		// rather than quietly arriving ungated.
		{"/api/v1/ussecurities/anything-added-later", true},
		{"/api/v1/ussecurities", true},
		// And it must not over-reach onto a neighbour that merely shares a
		// prefix string. The third case is the one that matters here: the two
		// US module prefixes are four characters apart.
		{"/api/v1/ussecuritiessomethingelse", false},
		{"/api/v1/usbanking/exam-readiness", true},
		{"/api/v1/usinsurance/inventory", false},
		{"/api/v1/audit/search", false},
	}
	for _, tc := range cases {
		if got := isTenantWideAuditExportPath(tc.path); got != tc.want {
			t.Errorf("isTenantWideAuditExportPath(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}

// TestUSSecuritiesHasNoPollShapeCarveOut pins the difference from the compliance
// report facade.
//
// The facade carves its status POLL out of the export gate (epic #2892 D4),
// because a non-admin must be able to watch a report they cannot generate. The
// US securities module has no viewer-facing route at all, so it takes the whole
// prefix with no carve-out - and if someone later adds one, they have to change
// this test deliberately rather than discovering that a carve-out written for
// the facade also opened this module.
func TestUSSecuritiesHasNoPollShapeCarveOut(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/ussecurities/exam-readiness", nil)
	if !isTenantWideAuditExportRequest(req) {
		t.Error("the exam-readiness GET is not treated as a whole-tenant export request, so the admin gate does not apply to it")
	}
	if complianceReportPollShape(req) {
		t.Error("the compliance report poll carve-out matches a ussecurities path")
	}
}
