// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package policy

import (
	"context"
	"reflect"
	"regexp"
	"testing"
)

// CAPABILITY SCOPING IS A DECISION, NOT A DETECTOR THAT DID NOT LOOK (#2801).
//
// For a tool positively classified text-document, an execution-class match is
// not a finding: the tool's content is prose sent to a document API, never a
// statement anything executes. The engine therefore leaves those detectors out
// of the evaluation, and the fact it reports for each is that the detector was
// DECIDED not to apply - ran and unmatched - with the tool that decided it. A
// fact reporting it as not-run would reach the anchored engine as UNKNOWN, and
// every request through such a tool would be refused wherever a control reads
// an execution-class detector.

const (
	capabilityTextTool  = "editJiraIssue" // a built-in text-document tool
	capabilityOtherTool = "run_shell"     // classified as nothing
)

func capabilityScopingPolicies() []CompiledPolicy {
	return []CompiledPolicy{
		{
			ID: "1", PolicyID: "test_exec", Name: "test_exec",
			Category: PolicyCategory("dangerous_queries"), Tier: "system", Severity: SeverityHigh,
			Pattern: regexp.MustCompile(`DROP\s+TABLE`), PatternStr: `DROP\s+TABLE`,
			Phase: PhaseBoth, ActionRequest: ActionBlock, ActionResponse: ActionBlock,
			Enabled: true, Priority: 100, TenantID: "test-tenant",
		},
		{
			ID: "2", PolicyID: "test_content", Name: "test_content",
			Category: CategorySensitiveData, Tier: "system", Severity: SeverityHigh,
			Pattern: regexp.MustCompile(`secret-token`), PatternStr: `secret-token`,
			Phase: PhaseBoth, ActionRequest: ActionWarn, ActionResponse: ActionWarn,
			Enabled: true, Priority: 90, TenantID: "test-tenant",
		},
	}
}

func capabilityOpts(tool string) EvalOptions {
	opts := redactDecidedOpts()
	opts.ToolIdentity = tool
	return opts
}

func capabilityFacts(t *testing.T, o *Observation) map[string]DetectorFact {
	t.Helper()
	if o == nil {
		t.Fatal("the evaluation returned no detector facts")
	}
	out := map[string]DetectorFact{}
	for _, r := range o.Rows {
		out[r.PolicyID] = r
	}
	return out
}

func TestACapabilityScopedDetectorIsDecidedNotToApply(t *testing.T) {
	if !IsExecutionScopedPolicy(&capabilityScopingPolicies()[0]) || IsExecutionScopedPolicy(&capabilityScopingPolicies()[1]) {
		t.Fatal("PREMISE: test_exec must be execution-scoped and test_content must not")
	}
	e := createTestEngine(capabilityScopingPolicies())
	ctx := context.Background()
	const request = "DROP TABLE users; the secret-token is here"

	t.Run("a text-document tool: the execution detector is ran and unmatched, and the scoping names it", func(t *testing.T) {
		result := e.EvaluateRequest(ctx, request, capabilityOpts(capabilityTextTool))
		if result.Blocked {
			t.Fatalf("a text-document tool's request was blocked by %v; the execution-class control does not apply to it", result.BlockedBy)
		}
		got := capabilityFacts(t, result.Observation)
		if f := got["test_exec"]; !f.Ran || f.Matched {
			t.Fatalf("test_exec reports %+v; want ran and unmatched - decided not to apply, not unknown", f)
		}
		if f := got["test_content"]; !f.Ran || !f.Matched {
			t.Fatalf("test_content reports %+v; a content-borne detector is not scoped and must run", f)
		}
		want := &CapabilityScoping{Tool: capabilityTextTool, Detectors: []string{"test_exec"}}
		if !reflect.DeepEqual(result.Observation.CapabilityScoped, want) {
			t.Fatalf("CapabilityScoped = %+v; want %+v", result.Observation.CapabilityScoped, want)
		}
	})

	t.Run("CONTROL: an unclassified tool runs the execution detector, which matches and blocks", func(t *testing.T) {
		result := e.EvaluateRequest(ctx, request, capabilityOpts(capabilityOtherTool))
		if !result.Blocked {
			t.Fatal("the unclassified tool's request was not blocked, so the case above proves nothing about scoping")
		}
		if f := capabilityFacts(t, result.Observation)["test_exec"]; !f.Ran || !f.Matched {
			t.Fatalf("test_exec reports %+v; want ran and matched", f)
		}
		if result.Observation.CapabilityScoped != nil {
			t.Fatalf("CapabilityScoped = %+v for an unclassified tool; want nil", result.Observation.CapabilityScoped)
		}
	})

	t.Run("the response phase scopes the same way", func(t *testing.T) {
		rows := []map[string]interface{}{{"note": request}}
		got := e.EvaluateResponse(ctx, rows, capabilityOpts(capabilityTextTool))
		if f := capabilityFacts(t, got.Observation)["test_exec"]; !f.Ran || f.Matched {
			t.Fatalf("test_exec on the response reports %+v; want ran and unmatched", f)
		}
		if got.Observation.CapabilityScoped == nil || got.Observation.CapabilityScoped.Tool != capabilityTextTool {
			t.Fatalf("CapabilityScoped = %+v on the response; want the text-document tool named", got.Observation.CapabilityScoped)
		}
		control := e.EvaluateResponse(ctx, rows, capabilityOpts(capabilityOtherTool))
		if f := capabilityFacts(t, control.Observation)["test_exec"]; !f.Ran || !f.Matched {
			t.Fatalf("CONTROL: test_exec on an unclassified tool's response reports %+v; want ran and matched", f)
		}
	})
}
