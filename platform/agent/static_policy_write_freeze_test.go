// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/gorilla/mux"
	"github.com/lib/pq"

	"axonflow/platform/shared/legacyfreeze"
	"axonflow/platform/shared/policypath"
)

// The three 42501 shapes the system-policy write routes can meet. Only the
// first is the core/172 freeze; the other two must keep answering 500, and
// each is the case that goes red in THIS binary if the shared classifier loses
// one of its two properties.
var (
	// The revoke on the table these routes write.
	agentFreezeError = &pq.Error{Code: "42501", Message: `permission denied for table static_policies`}
	// A row-level security WITH CHECK violation: same SQLSTATE, and a defect
	// in our own org scoping rather than a retired write path.
	agentRLSError = &pq.Error{Code: "42501", Message: `new row violates row-level security policy for table "static_policies"`}
	// A privilege refusal on a table the freeze does not cover - the agent's
	// own version table - which the classifier must not claim however alike
	// the sentence is.
	agentVersionsRefusal = &pq.Error{Code: "42501", Message: `permission denied for table static_policy_versions`}
	// The frozen name OUTSIDE the subject position - in a detail or a
	// statement echo - is not a refusal to write it.
	agentNamedElsewhere = &pq.Error{Code: "42501", Message: `permission denied for table static_policy_versions (while inserting into static_policies)`}
	// A longer table sharing the frozen name as a PREFIX is a different table.
	agentPrefixSibling = &pq.Error{Code: "42501", Message: `permission denied for table static_policies_archive`}
)

// orgOwnedPolicyRow is the row GetByID scans for an organization-owned,
// tenant-tier policy, in the repository's SCAN order: tier, tenant_id and
// org_id decide the system-tier and global-baseline refusals that run before
// the write, so a row in any other order would refuse for the wrong reason.
func orgOwnedPolicyRow() *sqlmock.Rows {
	return sqlmock.NewRows([]string{
		"id", "policy_id", "name", "category", "pattern", "severity",
		"description", "action", "tier", "priority", "enabled",
		"tenant_id", "org_id", "tags", "metadata", "version",
		"created_at", "updated_at", "created_by", "updated_by", "deleted_at",
	}).AddRow(
		"uuid-org-1", "custom_org_policy", "Org policy", "security-sqli", "x", "high",
		"", "block", "tenant", 50, true,
		"test-tenant", "test-org", "[]", "{}", 1,
		testTime, testTime, "u", "u", nil,
	)
}

// expectOrgScoped scripts rls.WithOrgScope around one statement: begin, the
// org GUC, the statement, and commit - or rollback when the statement fails.
func expectOrgScoped(m sqlmock.Sqlmock, org string, statement func(sqlmock.Sqlmock), fails bool) {
	m.ExpectBegin()
	m.ExpectExec(`SELECT set_config\('app.current_org_id', \$1, true\)`).
		WithArgs(org).
		WillReturnResult(sqlmock.NewResult(0, 0))
	statement(m)
	if fails {
		m.ExpectRollback()
	} else {
		m.ExpectCommit()
	}
}

// writeVerb is one system-policy write route and the statements it reaches
// before the write the freeze refuses.
type writeVerb struct {
	name   string
	method string
	suffix string
	body   string
	// script sets up every statement up to and including the frozen write,
	// which returns refusal.
	script func(m sqlmock.Sqlmock, refusal error)
}

func systemPolicyWriteVerbs() []writeVerb {
	lookup := func(m sqlmock.Sqlmock) {
		expectOrgScoped(m, "test-org", func(m sqlmock.Sqlmock) {
			m.ExpectQuery(`SELECT.*FROM static_policies WHERE`).
				WithArgs("custom_org_policy").
				WillReturnRows(orgOwnedPolicyRow())
		}, false)
	}
	return []writeVerb{
		{
			name: "create", method: http.MethodPost, suffix: "",
			body: `{"name":"n","pattern":"x","category":"security-sqli","action":"block","tier":"tenant"}`,
			script: func(m sqlmock.Sqlmock, refusal error) {
				m.ExpectQuery(`SELECT license_tier FROM clients`).
					WithArgs("test-tenant").
					WillReturnRows(sqlmock.NewRows([]string{"license_tier"}).AddRow("Enterprise"))
				expectOrgScoped(m, "test-org", func(m sqlmock.Sqlmock) {
					m.ExpectExec(`INSERT INTO static_policies`).WillReturnError(refusal)
				}, true)
			},
		},
		{
			name: "update", method: http.MethodPut, suffix: "/custom_org_policy",
			body: `{"name":"renamed"}`,
			script: func(m sqlmock.Sqlmock, refusal error) {
				lookup(m)
				expectOrgScoped(m, "test-org", func(m sqlmock.Sqlmock) {
					m.ExpectQuery(`UPDATE static_policies`).WillReturnError(refusal)
				}, true)
			},
		},
		{
			name: "delete", method: http.MethodDelete, suffix: "/custom_org_policy",
			script: func(m sqlmock.Sqlmock, refusal error) {
				lookup(m)
				expectOrgScoped(m, "test-org", func(m sqlmock.Sqlmock) {
					m.ExpectExec(`UPDATE static_policies`).WillReturnError(refusal)
				}, true)
			},
		},
		{
			name: "toggle", method: http.MethodPatch, suffix: "/custom_org_policy",
			body: `{"enabled":false}`,
			script: func(m sqlmock.Sqlmock, refusal error) {
				lookup(m)
				expectOrgScoped(m, "test-org", func(m sqlmock.Sqlmock) {
					m.ExpectExec(`UPDATE static_policies`).WillReturnError(refusal)
				}, true)
			},
		},
	}
}

// serveWrite drives one verb through the REGISTERED router - both prefixes,
// the real auth middleware - with the frozen write returning refusal, and
// fails the test unless every scripted statement was reached. That last check
// is what makes a 409 here a fact about the write: a handler that refused
// before reaching it would leave the INSERT or UPDATE unconsumed.
func serveWrite(t *testing.T, v writeVerb, prefix string, refusal error) *httptest.ResponseRecorder {
	t.Helper()
	stamp := withInternalServiceAuth(t)
	t.Setenv("AXONFLOW_LICENSE_KEY", "")
	r, mock := aliasRouter(t)
	v.script(mock, refusal)

	var body *bytes.Reader
	if v.body != "" {
		body = bytes.NewReader([]byte(v.body))
	} else {
		body = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(v.method, prefix+v.suffix, body)
	req.Header.Set("Content-Type", "application/json")
	stamp(req)
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("%s %s%s did not reach the write the freeze refuses, so its status says nothing about the freeze: %v (status %d, body %s)",
			v.method, prefix, v.suffix, err, rr.Code, rr.Body.String())
	}
	return rr
}

// TestTheSystemPolicyWritesAnswerTheFreezeOnBothPrefixes is #4084.
//
// The agent's create, update, delete and enabled toggle write static_policies,
// which core/172 made read-only to the application roles, and each fell
// through to its switch's default arm and answered a bare 500. They now answer
// what the orchestrator answers: 409, LEGACY_POLICY_WRITE_FROZEN as a STRING
// code, and a message naming the typed authoring route - on the deprecated
// /api/v1/static-policies prefix and its /api/v1/system-policies successor
// alike, because both are registered from one route table against one handler
// value and a divergence would mean the table forked.
func TestTheSystemPolicyWritesAnswerTheFreezeOnBothPrefixes(t *testing.T) {
	for _, v := range systemPolicyWriteVerbs() {
		t.Run(v.name+" answers the freeze on both prefixes", func(t *testing.T) {
			bodies := map[string]string{}
			for _, prefix := range []string{policypath.LegacySystemPolicies, policypath.SystemPolicies} {
				rr := serveWrite(t, v, prefix, agentFreezeError)
				if rr.Code != http.StatusConflict {
					t.Fatalf("%s %s%s: status %d, want 409; a caller told 500 reads a retired write path as our fault and retries. body=%s",
						v.method, prefix, v.suffix, rr.Code, rr.Body.String())
				}
				var out struct {
					Error struct {
						Code    string `json:"code"`
						Message string `json:"message"`
					} `json:"error"`
				}
				if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
					t.Fatalf("%s%s: the refusal is not the agent's error envelope with a string code: %v (%s)",
						prefix, v.suffix, err, rr.Body.String())
				}
				if out.Error.Code != legacyfreeze.ErrCode {
					t.Fatalf("%s%s: code = %q, want %q", prefix, v.suffix, out.Error.Code, legacyfreeze.ErrCode)
				}
				if !strings.Contains(out.Error.Message, legacyfreeze.TypedAuthoringRoute) {
					t.Fatalf("%s%s: the refusal does not name the typed authoring route: %q", prefix, v.suffix, out.Error.Message)
				}
				bodies[prefix] = rr.Body.String()
			}
			if bodies[policypath.LegacySystemPolicies] != bodies[policypath.SystemPolicies] {
				t.Fatalf("the two prefixes refuse with different bodies:\n legacy:    %s\n successor: %s",
					bodies[policypath.LegacySystemPolicies], bodies[policypath.SystemPolicies])
			}
		})

		t.Run(v.name+" does NOT answer an RLS violation as the freeze", func(t *testing.T) {
			rr := serveWrite(t, v, policypath.SystemPolicies, agentRLSError)
			if rr.Code != http.StatusInternalServerError {
				t.Fatalf("status %d, want 500: a WITH CHECK violation is an org-scoping defect on our side, not a retired write path. body=%s",
					rr.Code, rr.Body.String())
			}
		})

		t.Run(v.name+" does NOT answer a refusal on a table the freeze does not cover", func(t *testing.T) {
			rr := serveWrite(t, v, policypath.SystemPolicies, agentVersionsRefusal)
			if rr.Code != http.StatusInternalServerError {
				t.Fatalf("status %d, want 500: static_policy_versions is not a table core/172 froze. body=%s",
					rr.Code, rr.Body.String())
			}
		})

		// THE ANCHOR'S TWO WEAKER FORMS, asserted in this binary and not only
		// where the classifier lives: a classifier that kept the table names but
		// dropped subject position, or dropped the identifier boundary, would
		// pass every case above.
		for label, refusal := range map[string]*pq.Error{
			"the frozen table named outside the subject position": agentNamedElsewhere,
			"a longer table sharing the frozen name as a prefix":   agentPrefixSibling,
		} {
			t.Run(v.name+" does NOT answer "+label, func(t *testing.T) {
				rr := serveWrite(t, v, policypath.SystemPolicies, refusal)
				if rr.Code != http.StatusInternalServerError {
					t.Fatalf("status %d, want 500 for %q. body=%s", rr.Code, refusal.Message, rr.Body.String())
				}
			})
		}
	}
}

// TestTheSystemPolicyCreateKeepsEveryNamedRefusal pins the six named refusals
// of the create route at the HANDLER, where the freeze arm now sits beside
// them.
//
// They were pinned only at the repository (static_policy_repository_test.go),
// which cannot see a handler that answers every error as the freeze: a 403
// "system tier cannot be created" and a 400 "invalid pattern" would both
// become a 409 telling the caller to use a different route, and every
// repository test would stay green.
func TestTheSystemPolicyCreateKeepsEveryNamedRefusal(t *testing.T) {
	communityLicense := func(m sqlmock.Sqlmock) {
		m.ExpectQuery(`SELECT license_tier FROM clients`).
			WithArgs("test-tenant").
			WillReturnRows(sqlmock.NewRows([]string{"license_tier"}).AddRow("Community"))
	}
	for _, tc := range []struct {
		name   string
		body   CreateStaticPolicyRequest
		script func(sqlmock.Sqlmock)
		status int
	}{
		{
			name:   "ErrSystemTierCreation answers 403",
			body:   CreateStaticPolicyRequest{Name: "n", Pattern: "x", Category: "security-sqli", Action: "block", Tier: TierSystem},
			status: http.StatusForbidden,
		},
		{
			name:   "ErrInvalidTier answers 400",
			body:   CreateStaticPolicyRequest{Name: "n", Pattern: "x", Category: "security-sqli", Action: "block", Tier: PolicyTier("not-a-tier")},
			status: http.StatusBadRequest,
		},
		{
			name:   "ErrInvalidCategory answers 400",
			body:   CreateStaticPolicyRequest{Name: "n", Pattern: "x", Category: "not-a-category", Action: "block", Tier: TierTenant},
			status: http.StatusBadRequest,
		},
		{
			name:   "ErrInvalidPattern answers 400",
			body:   CreateStaticPolicyRequest{Name: "n", Pattern: "(", Category: "security-sqli", Action: "block", Tier: TierTenant},
			status: http.StatusBadRequest,
		},
		{
			name:   "ErrOrgTierRequiresEnterprise answers 403",
			body:   CreateStaticPolicyRequest{Name: "n", Pattern: "x", Category: "security-sqli", Action: "block", Tier: TierOrganization},
			script: communityLicense,
			status: http.StatusForbidden,
		},
		{
			name: "ErrTenantPolicyLimitReached answers 403",
			body: CreateStaticPolicyRequest{Name: "n", Pattern: "x", Category: "security-sqli", Action: "block", Tier: TierTenant},
			script: func(m sqlmock.Sqlmock) {
				communityLicense(m)
				expectOrgScoped(m, "test-org", func(m sqlmock.Sqlmock) {
					m.ExpectQuery(`SELECT COUNT\(\*\) FROM static_policies`).
						WithArgs("test-tenant", "test-org").
						WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(MaxTenantPoliciesCommunity))
				}, false)
			},
			status: http.StatusForbidden,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("AXONFLOW_LICENSE_KEY", "")
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatalf("sqlmock: %v", err)
			}
			defer db.Close()
			if tc.script != nil {
				tc.script(mock)
			}

			body, _ := json.Marshal(tc.body)
			req := httptest.NewRequest(http.MethodPost, policypath.SystemPolicies, bytes.NewReader(body))
			ctx := context.WithValue(req.Context(), ContextKeyTenantID, "test-tenant")
			ctx = context.WithValue(ctx, ContextKeyOrgID, "test-org")
			req = mux.SetURLVars(req.WithContext(ctx), nil)
			rr := httptest.NewRecorder()
			NewStaticPolicyAPIHandler(db).HandleCreateStaticPolicy(rr, req)

			if rr.Code != tc.status {
				t.Fatalf("status %d, want %d - the named refusal lost its own answer. body=%s", rr.Code, tc.status, rr.Body.String())
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Fatalf("the refusal was not produced by the path it is named for: %v", err)
			}
		})
	}
}
