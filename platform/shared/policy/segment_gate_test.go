// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package policy

import (
	"context"
	"regexp"
	"testing"
)

// #3266: the shared UnifiedPolicyEngine evaluated static_policies with no
// governance-segment awareness, so a segment-scoped row (CompiledPolicy.
// SegmentID != "") was loaded and enforced/reported for callers OUTSIDE that
// segment — a live cross-segment enforcement AND reporting leak. These tests
// pin the applicability gate: a segment-scoped policy applies iff the
// caller's EvalOptions.Segments contains its SegmentID, and non-matching
// rows must be excluded from BOTH the verdict (Blocked/Redacted) and the
// reported set (MatchedPolicies) — not merely unenforced.

// TestCompiledPolicy_AppliesToSegments pins the applicability rule directly
// (ADR-060 mirrors StaticPolicyRepository.GetEffective's `segment_id IS NULL
// OR segment_id = ANY($N)` SQL predicate).
func TestCompiledPolicy_AppliesToSegments(t *testing.T) {
	tests := []struct {
		name           string
		policySegment  string
		callerSegments []string
		want           bool
	}{
		{"not segment-scoped, no caller segments", "", nil, true},
		{"not segment-scoped, caller has segments", "", []string{"engineering"}, true},
		{"segment-scoped, caller is member", "finance", []string{"finance"}, true},
		{"segment-scoped, caller is member among several", "finance", []string{"engineering", "finance"}, true},
		{"segment-scoped, caller is non-member", "finance", []string{"engineering"}, false},
		{"segment-scoped, caller has no segments (nil)", "finance", nil, false},
		{"segment-scoped, caller has no segments (empty)", "finance", []string{}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &CompiledPolicy{SegmentID: tt.policySegment}
			if got := p.AppliesToSegments(tt.callerSegments); got != tt.want {
				t.Errorf("AppliesToSegments(%v) with SegmentID=%q = %v, want %v",
					tt.callerSegments, tt.policySegment, got, tt.want)
			}
		})
	}
}

// segmentScopedBlockPolicy returns a request-phase BLOCK policy scoped to
// segmentID, matching the literal string "confidential_ledger". Deliberately
// an action=block, always-registered-as-critical policy so that, absent the
// segment gate, it WOULD block and WOULD be reported for any caller whose
// input matches — making the exclusion tests below fail loudly if the gate
// is removed.
func segmentScopedBlockPolicy(segmentID string) CompiledPolicy {
	return CompiledPolicy{
		PolicyID:      "seg_finance_ledger_block",
		Name:          "Finance ledger block",
		Category:      CategorySensitiveData,
		Pattern:       regexp.MustCompile(`confidential_ledger`),
		PatternStr:    `confidential_ledger`,
		Severity:      SeverityCritical,
		Phase:         PhaseRequest,
		ActionRequest: ActionBlock,
		Enabled:       true,
		Priority:      100,
		SegmentID:     segmentID,
	}
}

// TestEvaluateRequest_SegmentScoped_Member proves a caller whose Segments
// contains the policy's SegmentID is blocked and the policy is reported.
func TestEvaluateRequest_SegmentScoped_Member(t *testing.T) {
	engine := createTestEngine([]CompiledPolicy{segmentScopedBlockPolicy("finance")})

	result := engine.EvaluateRequest(context.Background(),
		"please read the confidential_ledger for Q3",
		EvalOptions{TenantID: "test-tenant", Segments: []string{"finance"}})

	if !result.Blocked {
		t.Fatal("expected a member of segment 'finance' to be blocked by the segment-scoped policy")
	}
	if result.BlockedBy == nil || result.BlockedBy.PolicyID != "seg_finance_ledger_block" {
		t.Errorf("BlockedBy = %+v, want seg_finance_ledger_block", result.BlockedBy)
	}
	if len(result.MatchedPolicies) != 1 || result.MatchedPolicies[0].PolicyID != "seg_finance_ledger_block" {
		t.Errorf("expected the segment-scoped policy reported in MatchedPolicies, got %+v", result.MatchedPolicies)
	}
}

// TestEvaluateRequest_SegmentScoped_NonMember_Excluded is the #3266
// regression test: a caller belonging to a DIFFERENT segment must not be
// blocked, and the policy must not appear in MatchedPolicies (the reporting
// leak, symptom 1 of #3266). This test FAILS if the segment applicability
// gate (filterBySegments / AppliesToSegments) is removed or bypassed: the
// underlying pattern always matches the input, so without the gate this
// policy would both block and be reported, exactly as it does for the member
// case above.
func TestEvaluateRequest_SegmentScoped_NonMember_Excluded(t *testing.T) {
	engine := createTestEngine([]CompiledPolicy{segmentScopedBlockPolicy("finance")})

	result := engine.EvaluateRequest(context.Background(),
		"please read the confidential_ledger for Q3",
		EvalOptions{TenantID: "test-tenant", Segments: []string{"engineering"}})

	if result.Blocked {
		t.Fatal("#3266: a segment-scoped policy must NOT block a caller outside the segment — the segment applicability gate is missing or bypassed")
	}
	if len(result.MatchedPolicies) != 0 {
		t.Errorf("#3266: a segment-scoped policy must NOT be reported for a non-member (triggered_policies leak), got %+v", result.MatchedPolicies)
	}
}

// TestEvaluateRequest_SegmentScoped_EmptySegments_Excluded proves the
// fail-closed default: a caller with a nil/empty Segments set (no resolved
// governance-segment identity — e.g. every plane that has not yet threaded
// segments through, #3266's "other four surfaces") excludes every
// segment-scoped policy rather than admitting it by default.
func TestEvaluateRequest_SegmentScoped_EmptySegments_Excluded(t *testing.T) {
	engine := createTestEngine([]CompiledPolicy{segmentScopedBlockPolicy("finance")})

	result := engine.EvaluateRequest(context.Background(),
		"please read the confidential_ledger for Q3",
		EvalOptions{TenantID: "test-tenant"}) // Segments intentionally nil

	if result.Blocked {
		t.Fatal("#3266: nil Segments must exclude segment-scoped policies (fail-closed), not admit them")
	}
	if len(result.MatchedPolicies) != 0 {
		t.Errorf("expected no matched policies with nil Segments, got %+v", result.MatchedPolicies)
	}
}

// TestEvaluateRequest_NonSegmentScopedPolicy_UnaffectedByGate proves the gate
// is restriction-only: a policy with SegmentID == "" (the pre-#2989 default,
// still the overwhelming majority of static_policies rows) applies exactly
// as before regardless of the caller's Segments — including when Segments is
// empty/nil.
func TestEvaluateRequest_NonSegmentScopedPolicy_UnaffectedByGate(t *testing.T) {
	policies := []CompiledPolicy{
		{
			PolicyID:      "sys_sqli_union",
			Name:          "SQL Injection - UNION",
			Category:      CategorySecuritySQLi,
			Pattern:       regexp.MustCompile(`(?i)union\s+select`),
			PatternStr:    `(?i)union\s+select`,
			Severity:      SeverityCritical,
			Phase:         PhaseRequest,
			ActionRequest: ActionBlock,
			Enabled:       true,
			Priority:      100,
			// SegmentID intentionally left "" — not segment-scoped.
		},
	}
	engine := createTestEngine(policies)

	result := engine.EvaluateRequest(context.Background(),
		"SELECT * FROM users UNION SELECT * FROM passwords",
		EvalOptions{TenantID: "test-tenant"}) // no Segments resolved

	if !result.Blocked {
		t.Fatal("a non-segment-scoped policy must still block with nil Segments — the gate must not restrict tenant/org-wide policies")
	}
	if len(result.MatchedPolicies) != 1 {
		t.Errorf("expected the non-segment-scoped policy reported, got %+v", result.MatchedPolicies)
	}
}

// TestEvaluateResponse_SegmentScoped_NonMember_NotRedacted mirrors the
// request-phase exclusion test on the response plane (redaction + verdict +
// reported set).
func TestEvaluateResponse_SegmentScoped_NonMember_NotRedacted(t *testing.T) {
	policies := []CompiledPolicy{
		{
			PolicyID:       "seg_finance_pii",
			Name:           "Finance SSN redaction",
			Category:       CategoryPIIUS,
			Pattern:        regexp.MustCompile(`\d{3}-\d{2}-\d{4}`),
			PatternStr:     `\d{3}-\d{2}-\d{4}`,
			Severity:       SeverityMedium,
			Phase:          PhaseResponse,
			ActionResponse: ActionRedact,
			Enabled:        true,
			SegmentID:      "finance",
		},
	}
	engine := createTestEngine(policies)

	result := engine.EvaluateResponse(context.Background(),
		"customer SSN 523-45-6789", EvalOptions{TenantID: "test-tenant", Segments: []string{"engineering"}})

	if result.Redacted {
		t.Fatal("#3266: a segment-scoped policy must NOT redact for a non-member")
	}
	if len(result.MatchedPolicies) != 0 {
		t.Errorf("#3266: a segment-scoped policy must NOT be reported for a non-member, got %+v", result.MatchedPolicies)
	}
}

// TestEvaluateResponse_SegmentScoped_Member_Redacted is the positive
// counterpart: a member's response IS redacted and reported.
func TestEvaluateResponse_SegmentScoped_Member_Redacted(t *testing.T) {
	policies := []CompiledPolicy{
		{
			PolicyID:       "seg_finance_pii",
			Name:           "Finance SSN redaction",
			Category:       CategoryPIIUS,
			Pattern:        regexp.MustCompile(`\d{3}-\d{2}-\d{4}`),
			PatternStr:     `\d{3}-\d{2}-\d{4}`,
			Severity:       SeverityMedium,
			Phase:          PhaseResponse,
			ActionResponse: ActionRedact,
			Enabled:        true,
			SegmentID:      "finance",
		},
	}
	engine := createTestEngine(policies)

	result := engine.EvaluateResponse(context.Background(),
		"customer SSN 523-45-6789", EvalOptions{TenantID: "test-tenant", Segments: []string{"finance"}})

	if !result.Redacted {
		t.Fatal("expected a member of segment 'finance' to have the response redacted")
	}
	if len(result.MatchedPolicies) != 1 || result.MatchedPolicies[0].PolicyID != "seg_finance_pii" {
		t.Errorf("expected the segment-scoped policy reported in MatchedPolicies, got %+v", result.MatchedPolicies)
	}
}
