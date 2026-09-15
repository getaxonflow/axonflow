// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"

	"axonflow/platform/decision/authoringcatalog"
	"axonflow/platform/orchestrator/workflow_control"
)

// parseOrchestratorFile parses one file of this package or a subpackage.
func parseOrchestratorFile(t *testing.T, path string) (*token.FileSet, *ast.File) {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
	if err != nil {
		t.Fatalf("parsing %s: %v", path, err)
	}
	return fset, file
}

func sortedAdmissionKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// #4254 (PRD v11 §1.13): every workflow-control step type the plane declares is
// presented as a shipped action, and the table names no type the plane does not
// declare. Read from workflow_control's source, so a new StepType constant
// cannot appear without a row here.
func TestEveryWorkflowStepTypeConstantHasAnAction(t *testing.T) {
	// Every non-test file of the package, and both spellings of a StepType
	// value: a typed spec (`X StepType = "x"`) and a conversion
	// (`X = StepType("x")`), wherever it is declared (R3 A-LOW).
	paths, err := filepath.Glob(filepath.Join("workflow_control", "*.go"))
	if err != nil {
		t.Fatal(err)
	}
	declared := map[string]bool{}
	for _, path := range paths {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		_, file := parseOrchestratorFile(t, path)
		ast.Inspect(file, func(n ast.Node) bool {
			spec, ok := n.(*ast.ValueSpec)
			if !ok {
				return true
			}
			ident, typed := spec.Type.(*ast.Ident)
			typed = typed && ident.Name == "StepType"
			for _, value := range spec.Values {
				var lit *ast.BasicLit
				switch v := value.(type) {
				case *ast.BasicLit:
					if typed {
						lit = v
					}
				case *ast.CallExpr:
					if fn, ok := v.Fun.(*ast.Ident); ok && fn.Name == "StepType" && len(v.Args) == 1 {
						lit, _ = v.Args[0].(*ast.BasicLit)
					}
				}
				if lit == nil || lit.Kind != token.STRING {
					continue
				}
				token, err := strconv.Unquote(lit.Value)
				if err != nil {
					t.Fatalf("%s is not a quoted step type: %v", lit.Value, err)
				}
				declared[token] = true
			}
			return true
		})
	}
	if len(declared) < 4 {
		t.Fatalf("PREMISE: found %d StepType constants in the workflow_control package; the plane declares at least four, so the parse read the wrong thing", len(declared))
	}
	presented := map[string]bool{}
	for stepType := range wcpStepActions {
		presented[string(stepType)] = true
	}
	if !reflect.DeepEqual(sortedAdmissionKeys(declared), sortedAdmissionKeys(presented)) {
		t.Fatalf("workflow_control declares step types %v and the plane presents %v; a declared type with no row is presented as nothing, and a row for an undeclared type is a mapping nobody can reach",
			sortedAdmissionKeys(declared), sortedAdmissionKeys(presented))
	}
}

// #4254: every multi-agent step type the workflow engine can execute is either
// presented as a shipped action or is the conditional, which is not presented.
// Read from the engine's own processor registrations, so a new processor cannot
// appear without a decision about how its steps are governed.
func TestEveryMultiAgentStepProcessorHasAnActionOrIsTheConditional(t *testing.T) {
	_, file := parseOrchestratorFile(t, "workflow_engine.go")
	registered := map[string]bool{}
	ast.Inspect(file, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok {
			return true
		}
		for _, lhs := range assign.Lhs {
			index, ok := lhs.(*ast.IndexExpr)
			if !ok {
				continue
			}
			sel, ok := index.X.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "stepProcessors" {
				continue
			}
			lit, ok := index.Index.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				continue
			}
			name, err := strconv.Unquote(lit.Value)
			if err != nil {
				t.Fatalf("%s is not a quoted step type: %v", lit.Value, err)
			}
			registered[name] = true
		}
		return true
	})
	if len(registered) < 4 {
		t.Fatalf("PREMISE: found %d registered step processors in workflow_engine.go; the engine registers at least four, so the parse read the wrong thing", len(registered))
	}
	if !registered[mapStepTypeConditional] {
		t.Fatalf("PREMISE: the engine registers no %q processor, so this test's one exception is not real", mapStepTypeConditional)
	}
	for name := range registered {
		if name == mapStepTypeConditional {
			continue
		}
		if _, presented := mapStepActions[name]; !presented {
			t.Errorf("the workflow engine executes %q steps and the multi-agent plane presents no action for them, so such a step would be refused as unbuildable on a plane that can run it", name)
		}
	}
	for name := range mapStepActions {
		if !registered[name] {
			t.Errorf("the multi-agent plane presents %q and the workflow engine registers no processor for it, so the row is a mapping nobody can reach", name)
		}
	}
}

// The gate table and the action table are one contract: a step type the plane
// presents is one it gates, and the reverse. Two tables that drift name a type
// the gate accepts and the engine will not decide, or the other way round.
func TestTheMultiAgentGateAndActionMapsNameTheSameTokens(t *testing.T) {
	if len(mapStepActions) == 0 {
		t.Fatal("PREMISE: the multi-agent action table is empty, so agreement proves nothing")
	}
	if !reflect.DeepEqual(sortedAdmissionKeys(mapStepActions), sortedAdmissionKeys(mapStepGateTypes)) {
		t.Fatalf("the multi-agent plane presents %v and gates %v", sortedAdmissionKeys(mapStepActions), sortedAdmissionKeys(mapStepGateTypes))
	}
}

// #4254 (PRD v11 §1.13): each plane presents its step as the shipped action its
// type maps to, and a type its map does not name is refused NAMING the token,
// never defaulted. The tokens are exact: no underscore/hyphen aliasing, no case
// folding.
func TestAStepTypeOutsideItsPlanesMapIsRefusedNamingIt(t *testing.T) {
	t.Run("the workflow control plane", func(t *testing.T) {
		for _, tc := range []struct {
			stepType workflow_control.StepType
			action   string
		}{
			{workflow_control.StepTypeLLMCall, authoringcatalog.ActionLLMCompletion},
			{workflow_control.StepTypeToolCall, authoringcatalog.ActionToolCall},
			{workflow_control.StepTypeConnectorCall, authoringcatalog.ActionToolCall},
			{workflow_control.StepTypeHumanTask, authoringcatalog.ActionAgentInvoke},
		} {
			got, err := actionForWCPStep(tc.stepType)
			if err != nil || got != tc.action {
				t.Errorf("%q is presented as (%q, %v); want %q", tc.stepType, got, err, tc.action)
			}
		}
		// The multi-agent spellings, the tool context's tool types, and a type
		// nobody declares: each is refused rather than aliased.
		for _, unnamed := range []string{"", "llm-call", "tool-call", "connector-call", "human-task", "function", "conditional", "LLM_CALL", " llm_call"} {
			got, err := actionForWCPStep(workflow_control.StepType(unnamed))
			if err == nil {
				t.Errorf("%q was presented as %q; want a refusal", unnamed, got)
				continue
			}
			if !strings.Contains(err.Error(), strconv.Quote(unnamed)) {
				t.Errorf("the refusal of %q does not name it: %v", unnamed, err)
			}
		}
	})
	t.Run("the multi-agent plane", func(t *testing.T) {
		for _, tc := range []struct{ stepType, action string }{
			{"llm-call", authoringcatalog.ActionLLMCompletion},
			{"connector-call", authoringcatalog.ActionToolCall},
			{"function-call", authoringcatalog.ActionToolCall},
			{"api-call", authoringcatalog.ActionToolCall},
		} {
			got, err := actionForMAPStep(tc.stepType)
			if err != nil || got != tc.action {
				t.Errorf("%q is presented as (%q, %v); want %q", tc.stepType, got, err, tc.action)
			}
		}
		// The conditional is refused here too: it is not presented at all, and a
		// caller asking for its action is asking for a verdict on a step this
		// plane does not decide.
		for _, unnamed := range []string{"", "conditional", "llm_call", "tool-call", "tool_call", "connector_call", "some-random-type", "API-CALL"} {
			got, err := actionForMAPStep(unnamed)
			if err == nil {
				t.Errorf("%q was presented as %q; want a refusal", unnamed, got)
				continue
			}
			if !strings.Contains(err.Error(), strconv.Quote(unnamed)) {
				t.Errorf("the refusal of %q does not name it: %v", unnamed, err)
			}
		}
	})
}

// #4254: a conditional step carrying branch steps is refused, because those
// branch steps would execute with no decision; a conditional carrying none
// invokes nothing and is admitted.
func TestAConditionalWithBranchStepsIsRefusedBeforeAnyStepExecutes(t *testing.T) {
	llm := WorkflowStep{Name: "draft", Type: "llm-call"}
	connector := WorkflowStep{Name: "send", Type: "connector-call"}
	for _, tc := range []struct {
		name    string
		steps   []WorkflowStep
		refused bool
	}{
		{"no conditional", []WorkflowStep{llm, connector}, false},
		{"a conditional with no branches", []WorkflowStep{llm, {Name: "check", Type: mapStepTypeConditional, Condition: "{{x == 1}}"}, connector}, false},
		{"a conditional with an if_true branch", []WorkflowStep{llm, {Name: "check", Type: mapStepTypeConditional, IfTrue: []WorkflowStep{connector}}, connector}, true},
		{"a conditional with an if_false branch", []WorkflowStep{{Name: "check", Type: mapStepTypeConditional, IfFalse: []WorkflowStep{llm}}}, true},
		{"a conditional with both branches", []WorkflowStep{{Name: "check", Type: mapStepTypeConditional, IfTrue: []WorkflowStep{llm}, IfFalse: []WorkflowStep{connector}}}, true},
		// A non-conditional step's branch fields are inert: only the conditional
		// processor reads them (TestNothingElseReadsAStepsBranchFields).
		{"branch fields on a non-conditional step", []WorkflowStep{{Name: "draft", Type: "llm-call", IfTrue: []WorkflowStep{connector}}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := refuseUnpresentableSteps(tc.steps)
			if tc.refused && err == nil {
				t.Fatal("the workflow was admitted; want a refusal naming the conditional step")
			}
			if !tc.refused && err != nil {
				t.Fatalf("the workflow was refused: %v", err)
			}
			if tc.refused && !strings.Contains(err.Error(), "check") {
				t.Errorf("the refusal does not name the step: %v", err)
			}
		})
	}
}

// Every route that admits a multi-agent workflow refuses it BEFORE it executes
// anything: the refusal call appears in the handler ahead of every call that
// runs a step. That is what makes "zero processor calls" true of the refused
// plan, on each of the five admission sites those three handlers cover.
func TestEveryPlanAdmissionRefusesBeforeItExecutes(t *testing.T) {
	fset, file := parseOrchestratorFile(t, "run.go")
	executors := map[string]bool{
		"ExecuteWithHITL": true, "ExecuteWorkflow": true,
		"ExecuteWorkflowWithParallelSupport": true, "ExecuteWorkflowBalanced": true,
		"ExecuteWithConfirm": true, "ExecuteWithStep": true, "ExecuteSingleStep": true,
	}
	handlers := []string{"executeWorkflowHandler", "executePlanHandler", "resumePlanHandler"}
	for _, name := range handlers {
		var fn *ast.FuncDecl
		for _, decl := range file.Decls {
			if d, ok := decl.(*ast.FuncDecl); ok && d.Name.Name == name && d.Recv == nil {
				fn = d
			}
		}
		if fn == nil {
			t.Fatalf("PREMISE: run.go declares no %s, so this test reads nothing", name)
		}
		refusedAt, firstExecutionAt := 0, 0
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			pos := fset.Position(call.Pos()).Line
			switch f := call.Fun.(type) {
			case *ast.Ident:
				if f.Name == "refuseUnpresentableSteps" && refusedAt == 0 {
					refusedAt = pos
				}
			case *ast.SelectorExpr:
				if executors[f.Sel.Name] && firstExecutionAt == 0 {
					firstExecutionAt = pos
				}
			}
			return true
		})
		if refusedAt == 0 {
			t.Errorf("%s admits a workflow without calling refuseUnpresentableSteps, so a conditional's branch steps would run undecided", name)
			continue
		}
		if firstExecutionAt == 0 {
			t.Errorf("PREMISE: %s executes nothing this test recognises, so the ordering proves nothing", name)
			continue
		}
		if refusedAt > firstExecutionAt {
			t.Errorf("%s refuses at line %d, after it starts executing at line %d", name, refusedAt, firstExecutionAt)
		}
	}
}

// Two things read a step's branch fields, for opposite reasons, and nothing
// reads Branches at all.
//
// The refusal above is worth exactly as much as that is true: a THIRD reader of
// IfTrue/IfFalse, or any reader of the dead Branches map, would execute nested
// steps that no admission check saw and no policy decided. A change that adds
// one must delete this test on purpose and say how those steps are governed.
func TestNothingElseReadsAStepsBranchFields(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	readers, branchesReaders := map[string]bool{}, []string{}
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		fset, file := parseOrchestratorFile(t, name)
		var enclosing string
		ast.Inspect(file, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.FuncDecl:
				enclosing = x.Name.Name
				if x.Recv != nil && len(x.Recv.List) == 1 {
					if star, ok := x.Recv.List[0].Type.(*ast.StarExpr); ok {
						if id, ok := star.X.(*ast.Ident); ok {
							enclosing = id.Name + "." + x.Name.Name
						}
					}
				}
			case *ast.SelectorExpr:
				switch x.Sel.Name {
				case "IfTrue", "IfFalse":
					readers[enclosing] = true
				case "Branches":
					branchesReaders = append(branchesReaders, enclosing+" ("+fset.Position(x.Pos()).String()+")")
				}
			}
			return true
		})
	}
	// Both legitimate readers are named, rather than admitted by a prefix: the
	// conditional processor EXECUTES the branch steps, and the admission refusal
	// READS them to refuse the workflow and executes nothing. Requiring both to
	// be present is also the anti-vacuity check - a parse that found neither
	// would otherwise pass this test by finding nothing at all.
	const refusal = "refuseUnpresentableSteps"
	for _, expected := range []string{"ConditionalProcessor.ExecuteStep", refusal} {
		if !readers[expected] {
			t.Fatalf("PREMISE: %s does not read a step's branch fields, so the parse read the wrong files and this test proves nothing", expected)
		}
	}
	for reader := range readers {
		if reader == refusal || strings.HasPrefix(reader, "ConditionalProcessor.") {
			continue
		}
		t.Errorf("%s reads a step's branch fields; only the conditional processor, which executes them, and %s, which refuses them, may. A third reader executes nested steps no admission check saw",
			reader, refusal)
	}
	if len(branchesReaders) > 0 {
		t.Errorf("WorkflowStep.Branches is read by %v; it is a second carrier of nested steps that no admission check inspects", branchesReaders)
	}
}
