// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"reflect"
	"strings"
	"testing"
)

// THE HOLD'S VOCABULARY IS PUBLISHED ONCE AND HELD TO THE TABLE (#4370).
// approvalHoldReasons is the one table the breaker feed, the decide reasons,
// the MCP refusals and the contract read; these pins keep docs/api/agent-api.yaml
// equal to it in both directions, as TestTheSeamCapabilityEnumMatchesTheGoConstants
// does for the capability vocabulary. A code the document omits is one a
// generated client cannot parse; a code it lists that the table lacks is one
// no server sends.

func agentAPISchema(t *testing.T, name string) map[string]any {
	t.Helper()
	comps, _ := loadAgentAPI(t)["components"].(map[string]any)
	schemas, _ := comps["schemas"].(map[string]any)
	s, ok := schemas[name].(map[string]any)
	if !ok {
		t.Fatalf("%s is missing from components.schemas: the pin would read nothing", name)
	}
	return s
}

func TestTheApprovalHoldReasonsMatchThePublishedContract(t *testing.T) {
	s := agentAPISchema(t, "ApprovalHoldReason")
	raw, _ := s["enum"].([]any)
	published := map[string]bool{}
	for _, v := range raw {
		published[v.(string)] = true
	}
	desc, _ := s["description"].(string)
	table := map[string]bool{}
	for _, r := range approvalHoldReasons {
		table[r.code] = true
		if !published[r.code] {
			t.Errorf("the server answers %q; the published ApprovalHoldReason omits it", r.code)
		}
		// The published sentence is the table's, word for word.
		if !strings.Contains(desc, "- `"+r.code+"`: "+r.meaning) {
			t.Errorf("the published description does not carry %q's meaning as the table states it: %q", r.code, r.meaning)
		}
	}
	for code := range published {
		if !table[code] {
			t.Errorf("the contract publishes %q, which no server answers", code)
		}
	}
	if len(published) != len(approvalHoldReasons) {
		t.Errorf("published %d codes; the table has %d", len(published), len(approvalHoldReasons))
	}
}

func TestThePendingApprovalShapeMatchesThePublishedContract(t *testing.T) {
	props, _ := agentAPISchema(t, "PendingApproval")["properties"].(map[string]any)
	retryProps, _ := props["retry"].(map[string]any)["properties"].(map[string]any)
	for _, c := range []struct {
		typ       reflect.Type
		published map[string]any
	}{
		{reflect.TypeOf(pendingApproval{}), props},
		{reflect.TypeOf(pendingApprovalRetry{}), retryProps},
	} {
		fields := map[string]bool{}
		for i := 0; i < c.typ.NumField(); i++ {
			name := strings.Split(c.typ.Field(i).Tag.Get("json"), ",")[0]
			fields[name] = true
			if _, ok := c.published[name]; !ok {
				t.Errorf("%s.%s is sent; the contract omits it", c.typ.Name(), name)
			}
		}
		for name := range c.published {
			if !fields[name] {
				t.Errorf("the contract publishes %s.%s, which the server never sends", c.typ.Name(), name)
			}
		}
	}
}

func TestDecidesPublishedVerdictAdmitsNeedsApproval(t *testing.T) {
	props, _ := agentAPISchema(t, "DecideResponse")["properties"].(map[string]any)
	verdict, _ := props["verdict"].(map[string]any)
	raw, _ := verdict["enum"].([]any)
	got := map[string]bool{}
	for _, v := range raw {
		got[v.(string)] = true
	}
	for _, want := range []string{VerdictAllow, VerdictDeny, VerdictNeedsApproval} {
		if !got[want] {
			t.Errorf("DecideResponse.verdict does not publish %q, which decide answers", want)
		}
	}
	if len(got) != 3 {
		t.Errorf("DecideResponse.verdict publishes %v; want exactly allow, deny, needs_approval", raw)
	}
}

// The breaker rule for each outcome lives in the table and nowhere else.
func TestTheBreakerFeedReadsTheReasonTable(t *testing.T) {
	want := map[string]bool{
		reasonApprovalPending: false, reasonApprovalReviewerUnattributed: false, reasonApprovalExpired: false,
		reasonApprovalRejected: true, reasonApprovalConsumed: true, reasonApprovalNotFound: true,
		reasonBoundInputChanged: true, reasonApprovalReviewerExcluded: true,
	}
	for code, feeds := range want {
		if got := violationFeedsCircuitBreaker(code); got != feeds {
			t.Errorf("violationFeedsCircuitBreaker(%q) = %v; want %v (master's ruling Q2)", code, got, feeds)
		}
	}
	if len(want) != len(approvalHoldReasons) {
		t.Fatalf("the table has %d reasons; this cell rules on %d", len(approvalHoldReasons), len(want))
	}
}
