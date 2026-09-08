// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestOrgRootAuthoringCannotOutliveItsAdmitter is the orchestrator half of the
// "does unsetting DATABASE_URL turn the scale limits off?" question. (The agent
// half is TestNoDatabaseMeansNoServingRatherThanNoLimit, which pins that a
// database-free agent refuses to start.)
//
// Unlike the agent, this process HAS a legitimate database-free mode: it serves
// the built-in default policies with no store behind them. So the guarantee
// cannot be "it refuses to boot". It is narrower and structural: the only
// handlers that can reach admitOrgRootPolicy are constructed in the SAME
// if-block that wires the admitter, so the database-free process has no policy
// authoring API at all - every such route answers 503 "Policy API not
// initialized - database connection required" rather than an unlimited yes.
//
// Moving either construction out of that block, or wiring the handler earlier
// "so the routes are always registered", would silently convert a 503 into an
// unbounded org-root authoring surface on a Community deployment. That edit
// looks like a robustness improvement, which is why it gets a test.
func TestOrgRootAuthoringCannotOutliveItsAdmitter(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "run.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}

	// The handlers whose services reach admitOrgRootPolicy, via
	// PolicyService.validateTierForCreate and PolicyService.ImportBulk.
	wantSameBlock := []string{"policyAPIHandler", "dynamicPolicyAPIHandler"}

	// Walk with a block stack so each interesting node can be attributed to
	// the innermost if-body containing it.
	type frame struct {
		ifs  *ast.IfStmt
		body *ast.BlockStmt
	}
	var stack []frame
	admitterBlock := (*ast.BlockStmt)(nil)
	admitterCond := ""
	handlerBlock := map[string]*ast.BlockStmt{}

	var walk func(n ast.Node) bool
	walk = func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.IfStmt:
			stack = append(stack, frame{ifs: node, body: node.Body})
			ast.Inspect(node.Body, walk)
			stack = stack[:len(stack)-1]
			if node.Else != nil {
				ast.Inspect(node.Else, walk)
			}
			return false
		case *ast.CallExpr:
			if id, ok := node.Fun.(*ast.Ident); ok && id.Name == "initTierAdmission" && len(stack) > 0 {
				admitterBlock = stack[len(stack)-1].body
				var buf bytes.Buffer
				if err := printer.Fprint(&buf, fset, stack[len(stack)-1].ifs.Cond); err == nil {
					admitterCond = buf.String()
				}
			}
		case *ast.AssignStmt:
			for _, lhs := range node.Lhs {
				id, ok := lhs.(*ast.Ident)
				if !ok || len(stack) == 0 {
					continue
				}
				for _, want := range wantSameBlock {
					if id.Name == want {
						handlerBlock[want] = stack[len(stack)-1].body
					}
				}
			}
		}
		return true
	}
	ast.Inspect(f, walk)

	// Pin the CONDITION too, not only the block identity. Round 2 found the
	// mirror image of the agent test's hole here: deriving the block but never
	// reading its condition means relaxing it to
	// `if usageDB != nil || os.Getenv("AXONFLOW_POLICY_API_NO_DB") == "1" {`
	// keeps both constructions in the same block and passes. The guarantee is
	// not "these share a block", it is "these share a block gated on having a
	// database".
	if admitterCond != "" && admitterCond != "usageDB != nil" {
		t.Errorf("the tier admitter and the policy-authoring handlers are now wired under the condition %q, "+
			"not `usageDB != nil`. They still share a block, which is what the rest of this test checks, but a "+
			"widened condition is how the pair starts running WITHOUT a database - and then the handlers serve "+
			"organization-root authoring against a ledger that was never wired.", admitterCond)
	}
	if admitterBlock == nil {
		t.Fatal("run.go no longer calls initTierAdmission inside an if-block, so this test cannot tell whether " +
			"the org-root authoring API can be served without the admitter that limits it")
	}
	for _, want := range wantSameBlock {
		got, ok := handlerBlock[want]
		if !ok {
			t.Errorf("%s is no longer assigned inside an if-block in run.go. It is the handler that reaches "+
				"admitOrgRootPolicy, so if it can now be constructed on a database-free path, organization-root "+
				"policy authoring is served with no ledger to count against and the Community limit of 0 is unenforced.", want)
			continue
		}
		if got != admitterBlock {
			t.Errorf("%s is constructed in a DIFFERENT block from initTierAdmission (handler at %s, admitter at %s). "+
				"The #3593 organization-root limit relies on these sharing one condition: a process that can author "+
				"policies but did not wire the admitter admits every org-root policy by default.",
				want, fset.Position(got.Pos()), fset.Position(admitterBlock.Pos()))
		}
	}
}

// TestAnOutageOnTheOrgRootPlaneIsRetryable pins the pairing that separates a
// commercial ceiling from a database blip on this plane.
//
// Both refusals carry ERR_TIER_LIMIT_ORG_ROOT_POLICY and therefore both render
// 402 — deliberately, so there is ONE code and ONE status for "tier admission
// refused" across both binaries. That makes Retry-After the only thing telling
// a client whether to come back, so a 402 without it on an outage is a database
// blip reported as "Payment Required" with nothing to act on. (R3 round 2,
// NIT-R2-3.)
func TestAnOutageOnTheOrgRootPlaneIsRetryable(t *testing.T) {
	ceiling := NewTierValidationError("organization-root policies are not available on Community", "ERR_TIER_LIMIT_ORG_ROOT_POLICY")
	outage := NewTierValidationError("the admission ledger is unreachable", "ERR_TIER_LIMIT_ORG_ROOT_POLICY")
	outage.RetryAfter = 30 * time.Second

	if got := ceiling.HTTPStatus(); got != http.StatusPaymentRequired {
		t.Errorf("a scale ceiling rendered %d, want 402", got)
	}
	if got := outage.HTTPStatus(); got != http.StatusPaymentRequired {
		t.Errorf("the outage refusal rendered %d, want 402 — one status for both, with Retry-After as the discriminator", got)
	}

	h := &PolicyAPIHandler{}
	for _, tc := range []struct {
		name string
		err  *TierValidationError
		want string
	}{
		{"a ceiling has nothing to retry", ceiling, ""},
		{"an outage says when to come back", outage, "30"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			h.writeTierError(rec, tc.err)
			if got := rec.Header().Get("Retry-After"); got != tc.want {
				t.Errorf("Retry-After = %q, want %q. Without it a client cannot tell a ceiling it must "+
					"buy its way past from an outage it should simply retry, because both are 402.", got, tc.want)
			}
			if rec.Code != http.StatusPaymentRequired {
				t.Errorf("status = %d, want 402", rec.Code)
			}
		})
	}
}
