// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"
)

// PolicyConflictService detects conflicts between active policies.
// It operates through PolicyService (not the engine) to ensure proper
// tenant scoping and access control.
type PolicyConflictService struct {
	policyService *PolicyService
}

// NewPolicyConflictService creates a new conflict detection service.
func NewPolicyConflictService(policyService *PolicyService) *PolicyConflictService {
	return &PolicyConflictService{
		policyService: policyService,
	}
}

// PolicyConflictRequest is the request body for POST /api/v1/policies/conflicts.
type PolicyConflictRequest struct {
	PolicyID string `json:"policy_id,omitempty"` // optional: check specific policy against all others
}

// PolicyConflictResponse is the response for POST /api/v1/policies/conflicts.
type PolicyConflictResponse struct {
	Conflicts     []PolicyConflict `json:"conflicts"`
	TotalPolicies int              `json:"total_policies"`
	ConflictCount int              `json:"conflict_count"`
	CheckedAt     time.Time        `json:"checked_at"`
	Tier          string           `json:"tier"`
}

// PolicyConflict describes a detected conflict between two policies.
type PolicyConflict struct {
	PolicyA          PolicyConflictRef `json:"policy_a"`
	PolicyB          PolicyConflictRef `json:"policy_b"`
	ConflictType     string            `json:"conflict_type"` // contradictory_action, shadow, redundant
	Description      string            `json:"description"`
	Severity         string            `json:"severity"` // high, medium, low
	OverlappingField string            `json:"overlapping_field"`
}

// PolicyConflictRef identifies a policy in a conflict pair.
type PolicyConflictRef struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Type string `json:"type"`
}

// DetectConflicts finds conflicts between active policies for a tenant.
// If policyID is non-empty, only conflicts involving that policy are returned.
func (s *PolicyConflictService) DetectConflicts(ctx context.Context, tenantID string, policyID string) (*PolicyConflictResponse, error) {
	enabled := true
	resp, err := s.policyService.ListPolicies(ctx, tenantID, ListPoliciesParams{
		Enabled:  &enabled,
		PageSize: 1000,
		Page:     1,
	})
	if err != nil {
		return nil, fmt.Errorf("list active policies: %w", err)
	}

	policies := resp.Policies

	// If filtering by specific policy, ensure it exists in the set
	if policyID != "" {
		found := false
		for _, p := range policies {
			if p.ID == policyID {
				found = true
				break
			}
		}
		if !found {
			return &PolicyConflictResponse{
				Conflicts:     []PolicyConflict{},
				TotalPolicies: len(policies),
				ConflictCount: 0,
				CheckedAt:     time.Now().UTC(),
			}, nil
		}
	}

	conflicts := findConflicts(policies, policyID)

	// Sort by severity: high > medium > low
	sort.Slice(conflicts, func(i, j int) bool {
		return severityRank(conflicts[i].Severity) > severityRank(conflicts[j].Severity)
	})

	return &PolicyConflictResponse{
		Conflicts:     conflicts,
		TotalPolicies: len(policies),
		ConflictCount: len(conflicts),
		CheckedAt:     time.Now().UTC(),
	}, nil
}

func severityRank(s string) int {
	switch s {
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

// findConflicts compares all policy pairs for conflicts.
func findConflicts(policies []PolicyResource, filterPolicyID string) []PolicyConflict {
	var conflicts []PolicyConflict

	for i := 0; i < len(policies); i++ {
		for j := i + 1; j < len(policies); j++ {
			// If filtering, at least one policy must match
			if filterPolicyID != "" && policies[i].ID != filterPolicyID && policies[j].ID != filterPolicyID {
				continue
			}

			if c := detectPairConflict(&policies[i], &policies[j]); c != nil {
				conflicts = append(conflicts, *c)
			}
		}
	}

	return conflicts
}

// detectPairConflict checks two policies for a conflict.
// Returns nil if no conflict is found.
func detectPairConflict(a, b *PolicyResource) *PolicyConflict {
	// Find overlapping condition fields
	overlapping := findOverlappingFields(a.Conditions, b.Conditions)
	if len(overlapping) == 0 {
		return nil
	}

	// For contradictory/redundant detection, require at least one condition
	// that overlaps on both field AND value (not just field name).
	// This prevents false positives like "query contains DELETE" vs "query contains SELECT".
	hasValueOverlap := conditionsShareValue(a.Conditions, b.Conditions)

	refA := PolicyConflictRef{ID: a.ID, Name: a.Name, Type: a.Type}
	refB := PolicyConflictRef{ID: b.ID, Name: b.Name, Type: b.Type}
	firstOverlap := overlapping[0]

	// Check for contradictory actions (highest severity)
	// Only flag if conditions actually overlap on values, not just field names
	if hasValueOverlap && hasContradictoryActions(a.Actions, b.Actions) {
		return &PolicyConflict{
			PolicyA:          refA,
			PolicyB:          refB,
			ConflictType:     "contradictory_action",
			Description:      fmt.Sprintf("Policies have contradictory actions on overlapping field %q: one blocks while the other allows or logs", firstOverlap),
			Severity:         "high",
			OverlappingField: firstOverlap,
		}
	}

	// Check for redundant policies (same conditions + same actions)
	if conditionsEqual(a.Conditions, b.Conditions) && actionsEqual(a.Actions, b.Actions) {
		return &PolicyConflict{
			PolicyA:          refA,
			PolicyB:          refB,
			ConflictType:     "redundant",
			Description:      fmt.Sprintf("Policies have identical conditions and actions on field %q", firstOverlap),
			Severity:         "low",
			OverlappingField: firstOverlap,
		}
	}

	// Check for shadow (higher priority superset makes lower dead code)
	if shadow := detectShadow(a, b, overlapping); shadow != nil {
		return shadow
	}

	return nil
}

// conditionsShareValue returns true if at least one condition in both sets
// matches on field AND (operator + value). This prevents false positives
// where two policies share a field name but operate on disjoint values
// (e.g., "query contains DELETE" vs "query contains SELECT").
func conditionsShareValue(condA, condB []PolicyCondition) bool {
	sigsA := make(map[string]bool)
	for _, c := range condA {
		sigsA[conditionSignature(c)] = true
	}
	for _, c := range condB {
		if sigsA[conditionSignature(c)] {
			return true
		}
	}
	return false
}

// findOverlappingFields returns condition fields present in both policies.
func findOverlappingFields(condA, condB []PolicyCondition) []string {
	fieldsA := make(map[string]bool)
	for _, c := range condA {
		fieldsA[c.Field] = true
	}

	var overlap []string
	seen := make(map[string]bool)
	for _, c := range condB {
		if fieldsA[c.Field] && !seen[c.Field] {
			overlap = append(overlap, c.Field)
			seen[c.Field] = true
		}
	}
	return overlap
}

// hasContradictoryActions checks if one policy blocks while the other allows/logs.
func hasContradictoryActions(actionsA, actionsB []PolicyAction) bool {
	hasBlock := func(actions []PolicyAction) bool {
		for _, a := range actions {
			if a.Type == "block" {
				return true
			}
		}
		return false
	}

	hasNonBlock := func(actions []PolicyAction) bool {
		for _, a := range actions {
			if a.Type == "log" || a.Type == "alert" {
				return true
			}
		}
		return false
	}

	// One blocks, the other only logs/alerts (no block)
	return (hasBlock(actionsA) && !hasBlock(actionsB) && hasNonBlock(actionsB)) ||
		(hasBlock(actionsB) && !hasBlock(actionsA) && hasNonBlock(actionsA))
}

// conditionsEqual checks if two condition sets are logically identical.
// Uses sorted signature slices to correctly handle duplicates.
func conditionsEqual(a, b []PolicyCondition) bool {
	if len(a) != len(b) {
		return false
	}

	sigsA := make([]string, len(a))
	for i, c := range a {
		sigsA[i] = conditionSignature(c)
	}
	sigsB := make([]string, len(b))
	for i, c := range b {
		sigsB[i] = conditionSignature(c)
	}
	sort.Strings(sigsA)
	sort.Strings(sigsB)

	for i := range sigsA {
		if sigsA[i] != sigsB[i] {
			return false
		}
	}
	return true
}

// actionsEqual checks if two action sets are logically identical.
// Compares action type AND config to avoid false "redundant" on policies
// with the same action types but different configurations.
func actionsEqual(a, b []PolicyAction) bool {
	if len(a) != len(b) {
		return false
	}

	sigsA := make([]string, len(a))
	for i, act := range a {
		sigsA[i] = actionSignature(act)
	}
	sigsB := make([]string, len(b))
	for i, act := range b {
		sigsB[i] = actionSignature(act)
	}
	sort.Strings(sigsA)
	sort.Strings(sigsB)

	for i := range sigsA {
		if sigsA[i] != sigsB[i] {
			return false
		}
	}
	return true
}

// conditionSignature produces a comparable string from a condition.
func conditionSignature(c PolicyCondition) string {
	return fmt.Sprintf("%s|%s|%v", c.Field, c.Operator, c.Value)
}

// actionSignature produces a comparable string from an action, including config.
func actionSignature(a PolicyAction) string {
	return fmt.Sprintf("%s|%v", a.Type, a.Config)
}

// detectShadow checks if one policy completely shadows another.
// A higher-priority policy shadows a lower-priority one when the higher
// policy's conditions are a strict subset of the lower policy's conditions
// AND the overlapping conditions use the same operator and value.
// This prevents false positives where policies share a field name but
// have disjoint predicates (e.g., user.role == admin vs user.role == analyst).
func detectShadow(a, b *PolicyResource, overlappingFields []string) *PolicyConflict {
	// Determine which is higher priority (lower number = higher priority)
	var higher, lower *PolicyResource
	if a.Priority <= b.Priority {
		higher = a
		lower = b
	} else {
		higher = b
		lower = a
	}

	// For shadow: every condition in the higher-priority policy must have
	// an exact match (field + operator + value) in the lower-priority policy.
	// Additionally, the lower policy must have MORE conditions (i.e., the
	// higher policy is strictly less restrictive).
	if len(higher.Conditions) >= len(lower.Conditions) {
		return nil
	}

	lowerSigs := make(map[string]bool)
	for _, c := range lower.Conditions {
		lowerSigs[conditionSignature(c)] = true
	}

	for _, c := range higher.Conditions {
		if !lowerSigs[conditionSignature(c)] {
			return nil // Higher has a condition not matched in lower — no shadow
		}
	}

	fieldList := strings.Join(overlappingFields, ", ")
	return &PolicyConflict{
		PolicyA:          PolicyConflictRef{ID: higher.ID, Name: higher.Name, Type: higher.Type},
		PolicyB:          PolicyConflictRef{ID: lower.ID, Name: lower.Name, Type: lower.Type},
		ConflictType:     "shadow",
		Description:      fmt.Sprintf("Policy %q (priority %d) shadows %q (priority %d) on fields: %s", higher.Name, higher.Priority, lower.Name, lower.Priority, fieldList),
		Severity:         "medium",
		OverlappingField: overlappingFields[0],
	}
}
