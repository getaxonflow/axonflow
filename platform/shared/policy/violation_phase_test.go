// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package policy

// #4249 row 5705939628: a policy_violations row says what happened, in the
// phase it happened. RecordViolation used to stamp the policy's REQUEST-phase
// action on every violation, response-phase ones included, so a response block
// was persisted with the request column's value (warn, for the shipped SSN row)
// or its category fallback. The cells below drive the real engine and read the
// entry the queue receives.

import (
	"context"
	"regexp"
	"strings"
	"sync"
	"testing"
)

// recordingAuditQueue keeps every entry it is given.
type recordingAuditQueue struct {
	mu          sync.Mutex
	violations  []AuditEntry
	evaluations []PolicyEvaluationEntry
}

func (q *recordingAuditQueue) LogViolation(entry AuditEntry) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.violations = append(q.violations, entry)
	return nil
}

func (q *recordingAuditQueue) LogMetric(AuditEntry) error { return nil }

func (q *recordingAuditQueue) LogPolicyEvaluation(entry PolicyEvaluationEntry) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.evaluations = append(q.evaluations, entry)
	return nil
}

func recordingEngine(policies []CompiledPolicy) (*UnifiedPolicyEngine, *recordingAuditQueue) {
	engine := createTestEngine(policies)
	queue := &recordingAuditQueue{}
	engine.metrics = NewMetricsCollector(queue)
	return engine, queue
}

const ssnPattern = `\b\d{3}-\d{2}-\d{4}\b`

// ssnPolicy is a PII row as core/039 stores one: warn on the request, redact on
// the response, unless a column is overridden by the caller.
func ssnPolicy(request, response Action) CompiledPolicy {
	return CompiledPolicy{
		PolicyID:       "sys_pii_ssn_test",
		Name:           "US SSN",
		Description:    "US Social Security Number detected",
		Category:       CategoryPIIUS,
		Tier:           "system",
		Severity:       SeverityHigh,
		Pattern:        regexp.MustCompile(ssnPattern),
		PatternStr:     ssnPattern,
		Phase:          PhaseBoth,
		ActionRequest:  request,
		ActionResponse: response,
		Enabled:        true,
		Priority:       90,
		TenantID:       "test-tenant",
	}
}

func onlyViolation(t *testing.T, q *recordingAuditQueue) AuditEntry {
	t.Helper()
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.violations) != 1 {
		t.Fatalf("the queue received %d violations, want exactly 1: %+v", len(q.violations), q.violations)
	}
	return q.violations[0]
}

func assertDetails(t *testing.T, entry AuditEntry, want map[string]string) {
	t.Helper()
	for key, value := range want {
		got, ok := entry.Details[key]
		if !ok {
			t.Errorf("details has no %q (want %q): %+v", key, value, entry.Details)
			continue
		}
		if got != value {
			t.Errorf("details[%q] = %v, want %q", key, got, value)
		}
	}
}

func responseRows() []map[string]interface{} {
	return []map[string]interface{}{{"name": "Bob", "ssn": "123-45-6789"}}
}

func TestAResponseViolationRecordsTheActionItsPhaseApplied(t *testing.T) {
	t.Run("a row that warns on the request and blocks on the response", func(t *testing.T) {
		engine, q := recordingEngine([]CompiledPolicy{ssnPolicy(ActionWarn, ActionBlock)})
		r := engine.EvaluateResponse(context.Background(), responseRows(), EvalOptions{
			TenantID: "test-tenant", OrgID: "org-a", Categories: []PolicyCategory{CategoryPIIUS},
		})
		if !r.Blocked {
			t.Fatalf("PREMISE: the response was not blocked: %+v", r)
		}
		v := onlyViolation(t, q)
		assertDetails(t, v, map[string]string{
			"action": "block", "stored_action": "block", "phase": "response", "decided_by": "detector_layer",
			"policy_id": "sys_pii_ssn_test", "policy_name": "US SSN",
			"description": "US Social Security Number detected",
		})
		if v.OrgID != "org-a" {
			t.Errorf("OrgID = %q, want org-a", v.OrgID)
		}
	})

	t.Run("a redact row under an organization's block override", func(t *testing.T) {
		engine, q := recordingEngine([]CompiledPolicy{ssnPolicy(ActionWarn, ActionRedact)})
		r := engine.EvaluateResponse(context.Background(), responseRows(), EvalOptions{
			TenantID: "test-tenant", OrgID: "org-a", Categories: []PolicyCategory{CategoryPIIUS},
			ActionOverrides: map[PolicyCategory]Action{CategoryPIIUS: ActionBlock},
		})
		if !r.Blocked {
			t.Fatalf("PREMISE: the override did not block the response: %+v", r)
		}
		assertDetails(t, onlyViolation(t, q), map[string]string{
			"action": "block", "stored_action": "redact", "phase": "response",
		})
	})

	t.Run("a row storing no response action, blocked by an override: the stored action is empty", func(t *testing.T) {
		engine, q := recordingEngine([]CompiledPolicy{ssnPolicy(ActionWarn, "")})
		engine.EvaluateResponse(context.Background(), responseRows(), EvalOptions{
			TenantID: "test-tenant", OrgID: "org-a", Categories: []PolicyCategory{CategoryPIIUS},
			ActionOverrides: map[PolicyCategory]Action{CategoryPIIUS: ActionBlock},
		})
		assertDetails(t, onlyViolation(t, q), map[string]string{
			"action": "block", "stored_action": "", "phase": "response",
		})
	})

	t.Run("a redacting response records no violation", func(t *testing.T) {
		engine, q := recordingEngine([]CompiledPolicy{ssnPolicy(ActionWarn, ActionRedact)})
		engine.EvaluateResponse(context.Background(), responseRows(), EvalOptions{
			TenantID: "test-tenant", OrgID: "org-a", Categories: []PolicyCategory{CategoryPIIUS}, MaxRedactions: 10,
		})
		if n := len(q.violations); n != 0 {
			t.Fatalf("a redaction recorded %d violations; RecordViolation fires on a block only", n)
		}
	})
}

func TestARequestViolationRecordsTheRequestPhase(t *testing.T) {
	sqli := CompiledPolicy{
		PolicyID:       "sqli_union_test",
		Name:           "SQL Injection - UNION",
		Category:       CategorySecuritySQLi,
		Tier:           "system",
		Severity:       SeverityCritical,
		Pattern:        regexp.MustCompile(`(?i)union\s+select`),
		PatternStr:     `(?i)union\s+select`,
		Phase:          PhaseBoth,
		ActionRequest:  ActionBlock,
		ActionResponse: ActionRedact,
		Enabled:        true,
		Priority:       100,
		TenantID:       "test-tenant",
	}
	t.Run("the query-string scan", func(t *testing.T) {
		engine, q := recordingEngine([]CompiledPolicy{sqli})
		r := engine.EvaluateRequest(context.Background(), "SELECT a FROM t UNION SELECT password FROM users", EvalOptions{
			TenantID: "test-tenant", OrgID: "org-a",
		})
		if !r.Blocked {
			t.Fatalf("PREMISE: the request was not blocked: %+v", r)
		}
		v := onlyViolation(t, q)
		assertDetails(t, v, map[string]string{"action": "block", "stored_action": "block", "phase": "request", "decided_by": "detector_layer"})
		// No description on the row: its name stands in.
		assertDetails(t, v, map[string]string{"description": "SQL Injection - UNION"})
	})
	t.Run("the parameter scan", func(t *testing.T) {
		engine, q := recordingEngine([]CompiledPolicy{sqli})
		r := engine.EvaluateRequest(context.Background(), "SELECT 1", EvalOptions{
			TenantID: "test-tenant", OrgID: "org-a",
			Parameters: map[string]interface{}{"q": "x UNION SELECT secret FROM vault"},
		})
		if !r.Blocked {
			t.Fatalf("PREMISE: the parameter did not block: %+v", r)
		}
		assertDetails(t, onlyViolation(t, q), map[string]string{"action": "block", "stored_action": "block", "phase": "request"})
	})
}

// THE MATCHED CONTENT NEVER REACHES THE ROW. policy_violations is kept five
// years and exported to regulators; the text that matched (here an SSN) is the
// customer's data, not a fact about the policy.
func TestAViolationRowCarriesNoMatchedContent(t *testing.T) {
	engine, q := recordingEngine([]CompiledPolicy{ssnPolicy(ActionWarn, ActionBlock)})
	engine.EvaluateResponse(context.Background(), responseRows(), EvalOptions{
		TenantID: "test-tenant", OrgID: "org-a", Categories: []PolicyCategory{CategoryPIIUS},
	})
	v := onlyViolation(t, q)
	for key, value := range v.Details {
		if s, ok := value.(string); ok && strings.Contains(s, "123-45-6789") {
			t.Errorf("details[%q] carries the matched content: %q", key, s)
		}
	}
}

// AN EVALUATION ENTRY NAMES ITS ORGANIZATION AND WHICH MATCHES BLOCKED, so the
// agent can write one policy_metrics row per matched policy under that
// organization with that policy's own block count.
func TestAnEvaluationEntryCarriesItsOrganizationAndTheBlockingPolicies(t *testing.T) {
	scope := "org-scope"
	matches := []PolicyMatch{
		{PolicyID: "p_block", Action: ActionBlock},
		{PolicyID: "p_warn", Action: ActionWarn},
		{PolicyID: "p_redact", Action: ActionRedact},
	}
	for _, c := range []struct {
		name string
		opts EvalOptions
		want string
	}{
		{"OrgID set", EvalOptions{TenantID: "t", OrgID: "org-a", OrgScope: &scope}, "org-a"},
		// The load scope never stands in: a violation row takes OrgID alone,
		// and the metrics row follows the same rule.
		{"only the load scope set", EvalOptions{TenantID: "t", OrgScope: &scope}, ""},
		{"neither set", EvalOptions{TenantID: "t"}, ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			q := &recordingAuditQueue{}
			NewMetricsCollector(q).RecordEvaluation(context.Background(), "response", c.opts, matches, true, 3)
			if len(q.evaluations) != 1 {
				t.Fatalf("got %d evaluation entries, want 1", len(q.evaluations))
			}
			e := q.evaluations[0]
			if e.OrgID != c.want {
				t.Errorf("OrgID = %q, want %q", e.OrgID, c.want)
			}
			if strings.Join(e.MatchedPolicies, ",") != "p_block,p_warn,p_redact" || strings.Join(e.BlockedPolicies, ",") != "p_block" {
				t.Errorf("matched %v blocked %v, want all three and p_block", e.MatchedPolicies, e.BlockedPolicies)
			}
		})
	}
}
