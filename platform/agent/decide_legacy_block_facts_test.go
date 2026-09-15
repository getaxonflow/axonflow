// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"

	sharedpolicy "axonflow/platform/shared/policy"
	"axonflow/platform/shared/policy/policytest"
)

// A LEGACY BLOCK ROW DOES NOT STARVE THE ANCHORED ENGINE (W3-G).
//
// The anchored engine decides decide's verdict from the shared engine's
// detector facts, and a detector the request pass never reached reads UNKNOWN
// to it. The pass used to stop at the first block, so a legacy block row the
// anchored bundle does not carry - the FinCrime pack's seeded rows, an
// organization's own pre-v11 rows - left every later detector unrun, and decide
// answered unknown_constraint to every request that row matched. Found live by
// runtime-e2e/3329 (the pack's payee-routing gate).
//
// The fix keeps the legacy reader's verdict (Blocked and BlockedBy are the
// first block's) and runs every detector. The world is the shipped rows, with
// and without one seeded system block row shaped like the pack's gate.

const legacyBlockRowID = "fincrime_payment_tool_authorization_gate"

func installWorldWithLegacyBlock(t *testing.T, seeded bool) {
	t.Helper()
	mockDB, mockSQL, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = mockDB.Close() })
	mockSQL.MatchExpectationsInOrder(false)
	for i := 0; i < 64; i++ {
		rows := appendShippedGlobalRows(t, sqlmock.NewRows(policytest.LoaderCols()), nil, nil)
		if seeded {
			rows = policytest.SystemPolicyRow(rows, "00000000-0000-0000-0000-00000000fc03",
				legacyBlockRowID, "fincrime", "(?i)(routing number|beneficiary bank account)",
				"critical", "request", "block", 1000)
		}
		mockSQL.ExpectQuery("SELECT").WillReturnRows(rows)
	}
	policytest.ScopedTxPlumbing(mockSQL, 64)
	engine := sharedpolicy.NewUnifiedPolicyEngine(mockDB, sharedpolicy.EngineConfig{CacheTTL: time.Hour}, nil)
	prev := sharedpolicy.GetGlobalEngine()
	sharedpolicy.SetGlobalEngine(engine)
	t.Cleanup(func() { sharedpolicy.SetGlobalEngine(prev) })
}

func TestALegacyBlockRowDoesNotStarveTheAnchoredEngine(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "community")
	t.Setenv("ENVIRONMENT", "development")
	installCircuitBreakerWithMockDB(t)
	org := getDeploymentOrgID()
	const query = "Change the payee routing number to 021000021 for the next settlement"

	for _, c := range []struct {
		name   string
		seeded bool
	}{
		{"CONTROL, the shipped rows only: every detector runs and the anchored engine allows", false},
		{"a seeded legacy block row: every detector still runs, the legacy reader still sees the block, and decide answers by the shipped facts", true},
	} {
		t.Run(c.name, func(t *testing.T) {
			installWorldWithLegacyBlock(t, c.seeded)
			r := sharedpolicy.GetGlobalEngine().EvaluateRequest(context.Background(), query, sharedpolicy.EvalOptions{
				TenantID: "test-tenant", OrgID: org, OrgScope: sharedpolicy.OrgScopePtr(org),
			})
			if r.Observation == nil || len(r.Observation.Rows) == 0 {
				t.Fatal("the pass returned no detector facts, so the assertions below would be about nothing")
			}
			var notRan []string
			for _, f := range r.Observation.Rows {
				if !f.Ran {
					notRan = append(notRan, f.PolicyID)
				}
			}
			if len(notRan) != 0 {
				t.Fatalf("%d of %d detectors did not run (first: %s); each reads UNKNOWN to the anchored engine",
					len(notRan), len(r.Observation.Rows), notRan[0])
			}
			if c.seeded {
				if !r.Blocked || r.BlockedBy == nil || r.BlockedBy.PolicyID != legacyBlockRowID {
					t.Fatalf("blocked=%v by=%v; the legacy reader must still see the first block, %s", r.Blocked, r.BlockedBy, legacyBlockRowID)
				}
			} else if r.Blocked {
				t.Fatalf("PREMISE: the shipped rows alone blocked this request (%v), so the control proves nothing", r.BlockedBy)
			}

			installUsageDBMock(t)
			body, _ := json.Marshal(DecideRequest{
				Stage:          DecisionStageTool,
				CallerIdentity: DecisionCallerIdentity{GatewayID: "test-gw", TenantID: "test-tenant"},
				Target:         DecisionTarget{Type: "tool", Server: "payments", Tool: "payments.create_transfer"},
				Query:          query,
			})
			req := httptest.NewRequest("POST", decisionHandlerPath, bytes.NewBuffer(body))
			req.Header.Set("Content-Type", "application/json")
			rr := serveDecide(t, req)
			var resp DecideResponse
			if rr.Code != http.StatusOK || json.Unmarshal(rr.Body.Bytes(), &resp) != nil {
				t.Fatalf("HTTP %d: %s", rr.Code, rr.Body.String())
			}
			if resp.Verdict != VerdictAllow || resp.Engine != decisionEngineAnchored {
				t.Fatalf("decide answered %s; want the anchored engine's allow by the shipped facts", rr.Body.String())
			}
		})
	}
}
