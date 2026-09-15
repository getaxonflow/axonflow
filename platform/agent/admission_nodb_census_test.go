// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"testing"
)

// TestNoDatabaseMeansNoServingRatherThanNoLimit pins the answer to the obvious
// attack on #3593: if the scale limits live in a Postgres ledger, does unsetting
// DATABASE_URL turn them off?
//
// It does not, and the reason is structural rather than a check anyone wrote:
// the branch that wires the admitter is the SAME branch that produces the
// ability to serve at all. This agent's else arm is fatal, so a process with no
// database never reaches a listener. (The orchestrator half of the same
// property - policyAPIHandler is constructed inside the same usageDB != nil
// block as its admitter, so with no database every policy-authoring route
// answers 503 rather than an unlimited yes - is pinned next to that code by
// TestOrgRootAuthoringCannotOutliveItsAdmitter.)
//
// The property is worth a test rather than a comment because it is easy to
// destroy while making something else work: replacing the fatal with a warning
// to let the agent boot in a sandbox would, in one line and with no other
// visible symptom, make every tier scale limit optional in production.
func TestNoDatabaseMeansNoServingRatherThanNoLimit(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "run.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}

	// Find the if-statement that wires the admitter, by looking for the call
	// rather than by matching the condition's source text: the condition is
	// what a future edit is most likely to change, so deriving the block from
	// initTierAdmission keeps this test attached to the thing it is about.
	// The stack is maintained by explicit recursion rather than by popping on
	// ast.Inspect's nil callback: that callback fires on the exit of EVERY
	// node, not only the ones pushed, so a nil-driven pop empties the stack
	// almost immediately and the innermost if is never found.
	var wiring *ast.IfStmt
	var stack []*ast.IfStmt
	var walk func(n ast.Node) bool
	walk = func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.IfStmt:
			stack = append(stack, node)
			ast.Inspect(node.Body, walk)
			stack = stack[:len(stack)-1]
			if node.Else != nil {
				ast.Inspect(node.Else, walk)
			}
			return false
		case *ast.CallExpr:
			if id, ok := node.Fun.(*ast.Ident); ok && id.Name == "initTierAdmission" && len(stack) > 0 {
				wiring = stack[len(stack)-1]
			}
		}
		return true
	}
	ast.Inspect(f, walk)
	if wiring == nil {
		t.Fatal("run.go no longer calls initTierAdmission inside an if-statement; this test can no longer tell " +
			"whether a database-free boot can serve traffic with the tier limits unenforced")
	}

	// The admitter must be wired on a POSITIVE database condition, so that the
	// else arm is the database-free case and not the reverse.
	if got := exprText(fset, wiring.Cond); got != `dbURL != ""` {
		t.Fatalf("initTierAdmission is wired under the condition %q, not the expected `dbURL != \"\"`. "+
			"Re-read the else arm before updating this string: the guarantee is that the database-free arm "+
			"cannot reach a listener, and a changed condition may have moved which arm that is.", got)
	}

	if wiring.Else == nil {
		t.Fatal("the database branch that wires the tier-limit admitter now has NO else arm, so a process with " +
			"no DATABASE_URL falls through it and goes on to serve traffic with every scale limit unenforced")
	}
	body, ok := wiring.Else.(*ast.BlockStmt)
	if !ok {
		t.Fatalf("the else arm is an %T (an else-if), so there is now a database-free path past this branch; "+
			"a database-free agent must not reach a listener", wiring.Else)
	}

	// The fatal must be an UNCONDITIONAL statement of the else body itself,
	// so `body.List` is walked rather than the whole subtree.
	//
	// The first version of this used ast.Inspect over the subtree, i.e. "some
	// log.Fatal appears anywhere below here", and round 2 of the independent
	// R3 walked straight through it with the shape the request actually
	// arrives in:
	//
	//	} else {
	//		if os.Getenv("AXONFLOW_ALLOW_NO_DB") != "true" {
	//			log.Fatal("DATABASE_URL is required...")
	//		}
	//		log.Println("running with NO DATABASE; tier limits are unenforced")
	//	}
	//
	// That passed, and it IS the reported bypass: the arm falls through, every
	// route registers, and the deployment serves with the admitter nil and
	// every principal admitted by default. A test whose own docstring names
	// the edit it prevents has to reject the env-gated version of that edit,
	// because nobody proposes "delete the fatal" - they propose a hatch.
	fatal := ""
	for _, stmt := range body.List {
		expr, ok := stmt.(*ast.ExprStmt)
		if !ok {
			continue
		}
		call, ok := expr.X.(*ast.CallExpr)
		if !ok {
			continue
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			continue
		}
		pkg, ok := sel.X.(*ast.Ident)
		if !ok || pkg.Name != "log" {
			continue
		}
		switch sel.Sel.Name {
		case "Fatal", "Fatalf", "Fatalln":
			fatal = "log." + sel.Sel.Name
		}
	}
	// A conditional wrapped around it is the evasion, so name it separately:
	// "there is a fatal in here somewhere" and "this arm always terminates"
	// are different claims and only the second is the guarantee.
	if fatal == "" {
		for _, stmt := range body.List {
			if _, ok := stmt.(*ast.IfStmt); ok {
				t.Fatal("the no-database arm's log.Fatal is now inside a CONDITIONAL, so there is a way to boot " +
					"without a database - which is a way to serve every principal with the tier limits unenforced. " +
					"An env-gated hatch (AXONFLOW_ALLOW_NO_DB and the like) is the shape this arrives in, and it is " +
					"exactly the edit this test exists to refuse. The fatal must be an unconditional statement of " +
					"the else block itself.")
			}
		}
	}
	if fatal == "" {
		t.Fatal("the no-database arm no longer terminates the process (no log.Fatal/Fatalf/Fatalln). " +
			"Whatever replaced it, the agent can now boot without a database - and an agent that boots " +
			"without a database has no tier-limit ledger, so unsetting DATABASE_URL is a one-variable " +
			"bypass of every limit in #3593. If a database-free mode is genuinely wanted, the limits need " +
			"a store that does not depend on Postgres; relaxing this arm alone is not that.")
	}
}

// exprText renders an expression back to source, for the condition comparison
// above and for its failure message.
func exprText(fset *token.FileSet, e ast.Expr) string {
	var buf bytes.Buffer
	if err := printer.Fprint(&buf, fset, e); err != nil {
		return ""
	}
	return buf.String()
}
