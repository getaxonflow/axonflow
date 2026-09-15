// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import "regexp"

// PolicyPattern represents a static policy rule
type PolicyPattern struct {
	ID          string
	Name        string
	Pattern     *regexp.Regexp
	PatternStr  string
	Severity    string // "low", "medium", "high", "critical"
	Description string
	Enabled     bool
}

// StaticPolicyResult contains the result of static policy evaluation.
// Used by both the unified shared engine (via convertSharedResultToStatic)
// and handler response types.
type StaticPolicyResult struct {
	Blocked           bool
	Reason            string
	TriggeredPolicies []string
	ChecksPerformed   []string
	ProcessingTimeMs  int64
	Severity          string
	RequiresRedaction bool // True if PII detected and should be redacted (Issue #891)
	EvaluationError   bool // True when Blocked is a fail-closed availability failure (could-not-scan), not a policy verdict (#2862)
	// PolicyNames maps each TriggeredPolicies id to the display name the engine
	// matched at evaluation time (#3365), so the canonical audit writers can
	// stamp policy_names alongside policy_ids without a write-time catalog
	// lookup. Populated by convertSharedResultToStatic; nil on the engine-bypass
	// constructor paths.
	PolicyNames map[string]string
}
