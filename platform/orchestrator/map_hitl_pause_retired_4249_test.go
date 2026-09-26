// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"sort"
	"strings"
	"testing"
)

// THE IN-MEMORY MULTI-AGENT PAUSE IS RETIRED (#4249 row 5774060413).
//
// Since #4382 every multi-agent execute route runs the declarative
// WorkflowEngine, which decides each step and withholds every challenge, so the
// HITL engine's process-local pause (its execution store, its approval adapter
// and the approve/reject path that scanned that store) ran nothing and held
// nothing. It is removed; the workflow control plane is the one place a
// multi-agent step is held. This census keeps it removed: a production file
// that declares any of those names again fails here, with the name.
var retiredMAPPauseNames = []string{
	"HITLWorkflowEngine",
	"NewHITLWorkflowEngine",
	"HITLWorkflowExecution",
	"HITLStepExecution",
	"HITLApprovalService",
	"HITLExecutionStatus",
	"MAPHITLApprovalAdapter",
	"hitlWorkflowEngine",
	"executionStore",
	"executionStoreMutex",
	"StatusPaused",
	"ExecuteWithHITL",
	"ResumeExecution",
	// The store's key-prefix helper and its not-found error (#4434 round 2:
	// kept by the first head with no caller, which golangci's unused caught).
	"normalizeHITLScope",
	"ErrExecutionNotFound",
}

// productionDeclNames returns every top-level name the package's non-test files
// declare (a method as its bare name), with the file declaring it.
func productionDeclNames(t *testing.T) map[string]string {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	names := map[string]string{}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		for _, decl := range f.Decls {
			switch d := decl.(type) {
			case *ast.FuncDecl:
				names[d.Name.Name] = name
			case *ast.GenDecl:
				for _, spec := range d.Specs {
					switch s := spec.(type) {
					case *ast.TypeSpec:
						names[s.Name.Name] = name
					case *ast.ValueSpec:
						for _, id := range s.Names {
							names[id.Name] = name
						}
					}
				}
			}
		}
	}
	return names
}

func TestTheInMemoryMAPPauseStaysRetired(t *testing.T) {
	names := productionDeclNames(t)
	// The census reads the files it must: the engine that replaced the pause
	// and its step gate are declared.
	for _, live := range []string{"WorkflowEngine", "SetStepGate", "mapStepGate", "getHITLExecutionStatusHandler"} {
		if _, ok := names[live]; !ok {
			t.Fatalf("PREMISE: the census found no declaration of %s; it is not reading the package", live)
		}
	}
	var back []string
	for _, retired := range retiredMAPPauseNames {
		if file, ok := names[retired]; ok {
			back = append(back, retired+" ("+file+")")
		}
	}
	sort.Strings(back)
	if len(back) > 0 {
		t.Errorf("the retired in-memory multi-agent pause is declared again: %s. The workflow control plane holds a multi-agent step (#4249 row 5774060413)", strings.Join(back, ", "))
	}
}
