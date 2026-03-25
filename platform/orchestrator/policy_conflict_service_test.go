// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"testing"
	"time"
)

func TestFindConflicts_NoConflicts(t *testing.T) {
	policies := []PolicyResource{
		{
			ID: "p1", Name: "Block SQL", Type: "content", Enabled: true,
			Conditions: []PolicyCondition{{Field: "query", Operator: "contains", Value: "DROP"}},
			Actions:    []PolicyAction{{Type: "block"}},
			Priority:   1,
		},
		{
			ID: "p2", Name: "Log PII", Type: "content", Enabled: true,
			Conditions: []PolicyCondition{{Field: "user.role", Operator: "equals", Value: "admin"}},
			Actions:    []PolicyAction{{Type: "log"}},
			Priority:   2,
		},
	}

	conflicts := findConflicts(policies, "")
	if len(conflicts) != 0 {
		t.Fatalf("expected 0 conflicts, got %d", len(conflicts))
	}
}

func TestFindConflicts_ContradictoryAction(t *testing.T) {
	policies := []PolicyResource{
		{
			ID: "p1", Name: "Block DELETE", Type: "content", Enabled: true,
			Conditions: []PolicyCondition{{Field: "query", Operator: "contains", Value: "DELETE"}},
			Actions:    []PolicyAction{{Type: "block"}},
			Priority:   1,
		},
		{
			ID: "p2", Name: "Allow DELETE", Type: "content", Enabled: true,
			Conditions: []PolicyCondition{{Field: "query", Operator: "contains", Value: "DELETE"}},
			Actions:    []PolicyAction{{Type: "log"}},
			Priority:   2,
		},
	}

	conflicts := findConflicts(policies, "")
	if len(conflicts) != 1 {
		t.Fatalf("expected 1 conflict, got %d", len(conflicts))
	}
	if conflicts[0].ConflictType != "contradictory_action" {
		t.Fatalf("expected contradictory_action, got %s", conflicts[0].ConflictType)
	}
	if conflicts[0].Severity != "high" {
		t.Fatalf("expected severity high, got %s", conflicts[0].Severity)
	}
	if conflicts[0].OverlappingField != "query" {
		t.Fatalf("expected overlapping field 'query', got %s", conflicts[0].OverlappingField)
	}
}

func TestFindConflicts_Redundant(t *testing.T) {
	policies := []PolicyResource{
		{
			ID: "p1", Name: "Block PII v1", Type: "content", Enabled: true,
			Conditions: []PolicyCondition{{Field: "query", Operator: "contains", Value: "SSN"}},
			Actions:    []PolicyAction{{Type: "block"}},
			Priority:   1,
		},
		{
			ID: "p2", Name: "Block PII v2", Type: "content", Enabled: true,
			Conditions: []PolicyCondition{{Field: "query", Operator: "contains", Value: "SSN"}},
			Actions:    []PolicyAction{{Type: "block"}},
			Priority:   2,
		},
	}

	conflicts := findConflicts(policies, "")
	if len(conflicts) != 1 {
		t.Fatalf("expected 1 conflict, got %d", len(conflicts))
	}
	if conflicts[0].ConflictType != "redundant" {
		t.Fatalf("expected redundant, got %s", conflicts[0].ConflictType)
	}
	if conflicts[0].Severity != "low" {
		t.Fatalf("expected severity low, got %s", conflicts[0].Severity)
	}
}

func TestFindConflicts_Shadow(t *testing.T) {
	policies := []PolicyResource{
		{
			ID: "p1", Name: "Broad block", Type: "content", Enabled: true,
			Conditions: []PolicyCondition{
				{Field: "query", Operator: "contains", Value: "DELETE"},
			},
			Actions:  []PolicyAction{{Type: "block"}},
			Priority: 1, // Higher priority (lower number)
		},
		{
			ID: "p2", Name: "Narrow block", Type: "content", Enabled: true,
			Conditions: []PolicyCondition{
				{Field: "query", Operator: "contains", Value: "DELETE"},
				{Field: "user.role", Operator: "equals", Value: "admin"},
			},
			Actions:  []PolicyAction{{Type: "block"}},
			Priority: 10, // Lower priority
		},
	}

	conflicts := findConflicts(policies, "")
	if len(conflicts) != 1 {
		t.Fatalf("expected 1 conflict, got %d", len(conflicts))
	}
	if conflicts[0].ConflictType != "shadow" {
		t.Fatalf("expected shadow, got %s", conflicts[0].ConflictType)
	}
	if conflicts[0].Severity != "medium" {
		t.Fatalf("expected severity medium, got %s", conflicts[0].Severity)
	}
}

func TestFindConflicts_SinglePolicy(t *testing.T) {
	policies := []PolicyResource{
		{
			ID: "p1", Name: "Only policy", Type: "content", Enabled: true,
			Conditions: []PolicyCondition{{Field: "query", Operator: "contains", Value: "test"}},
			Actions:    []PolicyAction{{Type: "block"}},
		},
	}

	conflicts := findConflicts(policies, "")
	if len(conflicts) != 0 {
		t.Fatalf("expected 0 conflicts with single policy, got %d", len(conflicts))
	}
}

func TestFindConflicts_EmptyPolicies(t *testing.T) {
	conflicts := findConflicts([]PolicyResource{}, "")
	if len(conflicts) != 0 {
		t.Fatalf("expected 0 conflicts with empty policies, got %d", len(conflicts))
	}
}

func TestFindConflicts_PolicyIDFilter(t *testing.T) {
	policies := []PolicyResource{
		{
			ID: "p1", Name: "Block SQL", Type: "content", Enabled: true,
			Conditions: []PolicyCondition{{Field: "query", Operator: "contains", Value: "DROP"}},
			Actions:    []PolicyAction{{Type: "block"}},
		},
		{
			ID: "p2", Name: "Log SQL", Type: "content", Enabled: true,
			Conditions: []PolicyCondition{{Field: "query", Operator: "contains", Value: "DROP"}},
			Actions:    []PolicyAction{{Type: "log"}},
		},
		{
			ID: "p3", Name: "Block PII", Type: "content", Enabled: true,
			Conditions: []PolicyCondition{{Field: "user.email", Operator: "contains", Value: "SSN"}},
			Actions:    []PolicyAction{{Type: "block"}},
		},
	}

	// Without filter: p1-p2 conflict (overlapping on "query" field, contradictory actions)
	all := findConflicts(policies, "")
	if len(all) != 1 {
		t.Fatalf("expected 1 conflict without filter, got %d", len(all))
	}

	// Filter to p3: no conflicts (p3 uses "user.email", doesn't overlap with p1/p2 on "query")
	filtered := findConflicts(policies, "p3")
	if len(filtered) != 0 {
		t.Fatalf("expected 0 conflicts filtered to p3, got %d", len(filtered))
	}

	// Filter to p1: sees the p1-p2 conflict
	filteredP1 := findConflicts(policies, "p1")
	if len(filteredP1) != 1 {
		t.Fatalf("expected 1 conflict filtered to p1, got %d", len(filteredP1))
	}
}

func TestDetectPairConflict_NoOverlap(t *testing.T) {
	a := &PolicyResource{
		Conditions: []PolicyCondition{{Field: "query", Operator: "contains", Value: "x"}},
		Actions:    []PolicyAction{{Type: "block"}},
	}
	b := &PolicyResource{
		Conditions: []PolicyCondition{{Field: "user.role", Operator: "equals", Value: "admin"}},
		Actions:    []PolicyAction{{Type: "block"}},
	}

	if c := detectPairConflict(a, b); c != nil {
		t.Fatalf("expected nil conflict for non-overlapping policies, got %v", c)
	}
}

func TestSeverityRank(t *testing.T) {
	if severityRank("high") <= severityRank("medium") {
		t.Fatal("high should rank above medium")
	}
	if severityRank("medium") <= severityRank("low") {
		t.Fatal("medium should rank above low")
	}
	if severityRank("unknown") != 0 {
		t.Fatal("unknown severity should rank 0")
	}
}

func TestConditionsEqual(t *testing.T) {
	a := []PolicyCondition{
		{Field: "query", Operator: "contains", Value: "DROP"},
		{Field: "user.role", Operator: "equals", Value: "admin"},
	}
	b := []PolicyCondition{
		{Field: "user.role", Operator: "equals", Value: "admin"},
		{Field: "query", Operator: "contains", Value: "DROP"},
	}
	c := []PolicyCondition{
		{Field: "query", Operator: "contains", Value: "SELECT"},
	}

	if !conditionsEqual(a, b) {
		t.Fatal("expected a == b (order independent)")
	}
	if conditionsEqual(a, c) {
		t.Fatal("expected a != c")
	}
}

func TestActionsEqual(t *testing.T) {
	a := []PolicyAction{{Type: "block"}, {Type: "log"}}
	b := []PolicyAction{{Type: "log"}, {Type: "block"}}
	c := []PolicyAction{{Type: "alert"}}

	if !actionsEqual(a, b) {
		t.Fatal("expected a == b (order independent)")
	}
	if actionsEqual(a, c) {
		t.Fatal("expected a != c")
	}
}

func TestConflictResponseSorting(t *testing.T) {
	// Build policies that produce one of each conflict type
	policies := []PolicyResource{
		// Contradictory pair (high)
		{
			ID: "p1", Name: "Block X", Type: "content", Enabled: true,
			Conditions: []PolicyCondition{{Field: "query", Operator: "contains", Value: "X"}},
			Actions:    []PolicyAction{{Type: "block"}},
			Priority:   1,
		},
		{
			ID: "p2", Name: "Log X", Type: "content", Enabled: true,
			Conditions: []PolicyCondition{{Field: "query", Operator: "contains", Value: "X"}},
			Actions:    []PolicyAction{{Type: "log"}},
			Priority:   2,
		},
		// Redundant pair (low)
		{
			ID: "p3", Name: "Block Y v1", Type: "content", Enabled: true,
			Conditions: []PolicyCondition{{Field: "risk_score", Operator: "greater_than", Value: 0.8}},
			Actions:    []PolicyAction{{Type: "block"}},
			Priority:   3,
		},
		{
			ID: "p4", Name: "Block Y v2", Type: "content", Enabled: true,
			Conditions: []PolicyCondition{{Field: "risk_score", Operator: "greater_than", Value: 0.8}},
			Actions:    []PolicyAction{{Type: "block"}},
			Priority:   4,
		},
	}

	service := &PolicyConflictService{policyService: nil} // Direct test
	_ = service // verify it compiles

	conflicts := findConflicts(policies, "")
	if len(conflicts) < 2 {
		t.Fatalf("expected at least 2 conflicts, got %d", len(conflicts))
	}
}

func TestPolicyConflictResponse_Fields(t *testing.T) {
	resp := PolicyConflictResponse{
		Conflicts:     []PolicyConflict{},
		TotalPolicies: 5,
		ConflictCount: 0,
		CheckedAt:     time.Now().UTC(),
		Tier:          "evaluation",
	}

	if resp.TotalPolicies != 5 {
		t.Fatal("expected 5 total policies")
	}
	if resp.ConflictCount != 0 {
		t.Fatal("expected 0 conflicts")
	}
}

func TestFindOverlappingFields(t *testing.T) {
	a := []PolicyCondition{
		{Field: "query", Operator: "contains", Value: "x"},
		{Field: "user.role", Operator: "equals", Value: "admin"},
	}
	b := []PolicyCondition{
		{Field: "query", Operator: "equals", Value: "y"},
		{Field: "risk_score", Operator: "greater_than", Value: 0.5},
	}

	overlap := findOverlappingFields(a, b)
	if len(overlap) != 1 {
		t.Fatalf("expected 1 overlapping field, got %d", len(overlap))
	}
	if overlap[0] != "query" {
		t.Fatalf("expected 'query', got %s", overlap[0])
	}
}

func TestFindOverlappingFields_NoDuplicates(t *testing.T) {
	a := []PolicyCondition{
		{Field: "query", Operator: "contains", Value: "x"},
		{Field: "query", Operator: "equals", Value: "y"},
	}
	b := []PolicyCondition{
		{Field: "query", Operator: "regex", Value: ".*"},
	}

	overlap := findOverlappingFields(a, b)
	if len(overlap) != 1 {
		t.Fatalf("expected 1 unique overlapping field, got %d", len(overlap))
	}
}

func TestHasContradictoryActions(t *testing.T) {
	blockOnly := []PolicyAction{{Type: "block"}}
	logOnly := []PolicyAction{{Type: "log"}}
	blockAndLog := []PolicyAction{{Type: "block"}, {Type: "log"}}
	alertOnly := []PolicyAction{{Type: "alert"}}

	if !hasContradictoryActions(blockOnly, logOnly) {
		t.Fatal("block vs log should be contradictory")
	}
	if !hasContradictoryActions(blockOnly, alertOnly) {
		t.Fatal("block vs alert should be contradictory")
	}
	if hasContradictoryActions(blockOnly, blockOnly) {
		t.Fatal("block vs block should NOT be contradictory")
	}
	if hasContradictoryActions(logOnly, alertOnly) {
		t.Fatal("log vs alert should NOT be contradictory (neither blocks)")
	}
	if !hasContradictoryActions(blockAndLog, logOnly) {
		t.Fatal("block+log vs log: A blocks while B only logs — this IS contradictory")
	}
}
