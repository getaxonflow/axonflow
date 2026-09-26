// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package workflow_control

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"axonflow/platform/shared/tenantscope"
)

// EVERY WORKFLOW LIFECYCLE AUDIT ROW CARRIES THE WORKFLOW'S ORGANIZATION (#4312).
//
// Five of the eight audit sites in this package (created, aborted, completed,
// failed, step_completed) built their WorkflowAuditEntry without OrgID. A
// missing struct field always compiles, and the writer downstream binds the
// empty string without complaint, so the only symptom was an audit_logs row
// with org_id = '' that an org-keyed read cannot see. #3281 fixed the same
// omission on step_gate alone; nothing stopped the other five, or a ninth.
//
// Two halves. The census reads the source and asserts every literal names
// OrgID, so a new site that forgets it is red before it runs. The behavioural
// cells drive each operation through the real service and assert the captured
// entry's org EQUALS the creating scope's org, with tenant and org deliberately
// distinct strings, so a site filled from the wrong value (the tenant, a
// metadata field) is red too - the census cannot see that.

// auditOrgTypeName is the literal the census pins.
const auditOrgTypeName = "WorkflowAuditEntry"

// auditOrgLiteralFloor is the number of WorkflowAuditEntry literals this
// package's writers held when the census was written. The floor is the
// anti-vacuity half: a census that finds fewer has stopped seeing the sites
// (a rename, a moved file, a parse that matches nothing), and a pass over zero
// literals says nothing about the class.
const auditOrgLiteralFloor = 8

type auditOrgLiteral struct {
	file     string
	line     int
	hasOrgID bool
	emptyLit bool // OrgID: "" - named, but still the defect
}

// collectAuditOrgLiterals parses every non-test Go file in this package. A
// parse reads a file regardless of build constraints, so a literal behind a
// tag is still counted (typed_authoring_db_literal_census_test.go's rationale;
// this package has no //go:build file today). Test files are excluded: they
// build entries to feed doubles, and are not writers.
// namesAuditEntry reports whether expr is the entry type, bare, qualified or
// behind a pointer.
func namesAuditEntry(expr ast.Expr) bool {
	if st, ok := expr.(*ast.StarExpr); ok {
		expr = st.X
	}
	switch tn := expr.(type) {
	case *ast.Ident:
		return tn.Name == auditOrgTypeName
	case *ast.SelectorExpr:
		return tn.Sel.Name == auditOrgTypeName
	}
	return false
}

func collectAuditOrgLiterals(t *testing.T) (lits []auditOrgLiteral, unreadable []string, filesScanned int) {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading %s: %v", dir, err)
	}
	fset := token.NewFileSet()
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, perr := parser.ParseFile(fset, filepath.Join(dir, name), nil, 0)
		if perr != nil {
			t.Fatalf("parsing %s: %v", name, perr)
		}
		filesScanned++
		ast.Inspect(f, func(n ast.Node) bool {
			// A value built without a literal the census can read is refused
			// outright: new(WorkflowAuditEntry), a var of the type, and an
			// element literal whose type is elided inside a slice or map of it.
			switch x := n.(type) {
			case *ast.CallExpr:
				if fn, ok := x.Fun.(*ast.Ident); ok && fn.Name == "new" && len(x.Args) == 1 && namesAuditEntry(x.Args[0]) {
					unreadable = append(unreadable, name+":"+strconv.Itoa(fset.Position(x.Pos()).Line)+" builds the entry with new()")
				}
			case *ast.ValueSpec:
				if x.Type != nil && namesAuditEntry(x.Type) {
					unreadable = append(unreadable, name+":"+strconv.Itoa(fset.Position(x.Pos()).Line)+" declares a var of the entry type")
				}
			case *ast.CompositeLit:
				var elt ast.Expr
				switch ct := x.Type.(type) {
				case *ast.ArrayType:
					elt = ct.Elt
				case *ast.MapType:
					elt = ct.Value
				}
				if elt != nil && namesAuditEntry(elt) {
					for _, e := range x.Elts {
						if kv, ok := e.(*ast.KeyValueExpr); ok {
							e = kv.Value
						}
						if u, ok := e.(*ast.UnaryExpr); ok {
							e = u.X
						}
						if inner, ok := e.(*ast.CompositeLit); ok && inner.Type == nil {
							unreadable = append(unreadable, name+":"+strconv.Itoa(fset.Position(inner.Pos()).Line)+" elides the entry type in a slice or map literal")
						}
					}
				}
			}
			cl, ok := n.(*ast.CompositeLit)
			if !ok || cl.Type == nil || !namesAuditEntry(cl.Type) {
				return true
			}
			lit := auditOrgLiteral{file: name, line: fset.Position(cl.Pos()).Line}
			for _, elt := range cl.Elts {
				kv, ok := elt.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				key, ok := kv.Key.(*ast.Ident)
				if !ok || key.Name != "OrgID" {
					continue
				}
				lit.hasOrgID = true
				if bl, ok := kv.Value.(*ast.BasicLit); ok && bl.Kind == token.STRING && (bl.Value == `""` || bl.Value == "``") {
					lit.emptyLit = true
				}
			}
			lits = append(lits, lit)
			return true
		})
	}
	return lits, unreadable, filesScanned
}

func TestEveryWorkflowAuditEntryLiteralNamesItsOrg(t *testing.T) {
	lits, unreadable, filesScanned := collectAuditOrgLiterals(t)

	if filesScanned == 0 {
		t.Fatal("the census scanned no files: it is not reading this package")
	}
	if len(lits) < auditOrgLiteralFloor {
		t.Fatalf("found %d WorkflowAuditEntry literals, floor is %d: the census has stopped seeing the audit sites "+
			"(if sites were genuinely removed, lower the floor in the same change and say why)", len(lits), auditOrgLiteralFloor)
	}

	missing := append([]string(nil), unreadable...)
	for _, l := range lits {
		switch {
		case !l.hasOrgID:
			missing = append(missing, l.file+":"+strconv.Itoa(l.line)+" has no OrgID")
		case l.emptyLit:
			missing = append(missing, l.file+":"+strconv.Itoa(l.line)+" sets OrgID to an empty literal")
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Fatalf("a workflow audit row written without its organization lands org_id = '' and is invisible to an org-keyed audit read (#4312):\n  %s",
			strings.Join(missing, "\n  "))
	}
}

// The creating scope. Tenant and org are DISTINCT strings on purpose: a site
// filled from workflow.TenantID must not pass by coincidence.
const (
	auditOrgTenant = "tenant-4312"
	auditOrgOrg    = "org-4312"
)

func auditOrgService(t *testing.T, evaluator PolicyEvaluator) (*Service, *captureAuditLogger, *MockRepository) {
	t.Helper()
	repo := NewMockRepository()
	svc := NewService(repo, evaluator, nil)
	capture := &captureAuditLogger{}
	svc.SetAuditLogger(capture)
	return svc, capture, repo
}

func auditOrgCreate(t *testing.T, svc *Service) string {
	t.Helper()
	wf, err := svc.CreateWorkflow(context.Background(), &CreateWorkflowRequest{
		WorkflowName: "audit-org-4312",
		// A body-supplied org must never be the source.
		Metadata: map[string]interface{}{"org_id": "org-from-the-body"},
	}, auditOrgTenant, auditOrgOrg, "user-1", "client-1")
	if err != nil {
		t.Fatalf("CreateWorkflow: %v", err)
	}
	return wf.WorkflowID
}

// entriesFor returns the captured entries of one operation for one workflow.
func (c *captureAuditLogger) entriesFor(workflowID, operation string) []*WorkflowAuditEntry {
	var out []*WorkflowAuditEntry
	for _, e := range c.entries {
		if e.WorkflowID == workflowID && e.Operation == operation {
			out = append(out, e)
		}
	}
	return out
}

func assertAuditOrg(t *testing.T, c *captureAuditLogger, workflowID, operation string) {
	t.Helper()
	got := c.entriesFor(workflowID, operation)
	if len(got) != 1 {
		t.Fatalf("want exactly one %s audit entry for %s, got %d (all: %d entries)", operation, workflowID, len(got), len(c.entries))
	}
	if got[0].OrgID != auditOrgOrg {
		t.Errorf("%s audit entry OrgID = %q, want the creating scope's org %q (#4312)", operation, got[0].OrgID, auditOrgOrg)
	}
	if got[0].TenantID != auditOrgTenant {
		t.Errorf("%s audit entry TenantID = %q, want %q", operation, got[0].TenantID, auditOrgTenant)
	}
}

func TestWorkflowAuditRowsCarryTheOrg(t *testing.T) {
	ctx := context.Background()

	t.Run("created, step_gate, step_completed, completed", func(t *testing.T) {
		svc, capture, _ := auditOrgService(t, &fixedEvaluator{decision: GateDecisionAllow, reason: "allowed"})
		id := auditOrgCreate(t, svc)
		if _, err := svc.StepGate(ctx, id, "step-1", &StepGateRequest{StepName: "step-1", StepType: StepTypeToolCall},
			auditOrgTenant, auditOrgOrg, "user-1", "client-1"); err != nil {
			t.Fatalf("StepGate: %v", err)
		}
		if err := svc.MarkStepCompleted(ctx, id, "step-1", nil, auditOrgTenant, auditOrgOrg); err != nil {
			t.Fatalf("MarkStepCompleted: %v", err)
		}
		if err := svc.CompleteWorkflow(ctx, id, auditOrgTenant, auditOrgOrg); err != nil {
			t.Fatalf("CompleteWorkflow: %v", err)
		}
		for _, op := range []string{"created", "step_gate", "step_completed", "completed"} {
			assertAuditOrg(t, capture, id, op)
		}
	})

	t.Run("aborted", func(t *testing.T) {
		svc, capture, _ := auditOrgService(t, nil)
		id := auditOrgCreate(t, svc)
		if err := svc.AbortWorkflow(ctx, id, "operator abort", auditOrgTenant, auditOrgOrg); err != nil {
			t.Fatalf("AbortWorkflow: %v", err)
		}
		assertAuditOrg(t, capture, id, "aborted")
	})

	t.Run("failed", func(t *testing.T) {
		svc, capture, _ := auditOrgService(t, nil)
		id := auditOrgCreate(t, svc)
		if err := svc.FailWorkflow(ctx, id, "tool crashed", auditOrgTenant, auditOrgOrg); err != nil {
			t.Fatalf("FailWorkflow: %v", err)
		}
		assertAuditOrg(t, capture, id, "failed")
	})

	for _, tc := range []struct {
		op      string
		resolve func(svc *Service, id string) error
	}{
		{"step_approved", func(svc *Service, id string) error {
			return svc.ApproveStep(ctx, id, "step-1", auditOrgTenant, auditOrgOrg, "approver@example.com", "ok")
		}},
		{"step_rejected", func(svc *Service, id string) error {
			return svc.RejectStep(ctx, id, "step-1", auditOrgTenant, auditOrgOrg, "approver@example.com", "no")
		}},
	} {
		t.Run(tc.op, func(t *testing.T) {
			svc, capture, _ := auditOrgService(t, &MockApprovalPolicyEvaluator{})
			id := auditOrgCreate(t, svc)
			if _, err := svc.StepGate(ctx, id, "step-1", &StepGateRequest{StepName: "step-1", StepType: StepTypeLLMCall},
				auditOrgTenant, auditOrgOrg, "user-1", "client-1"); err != nil {
				t.Fatalf("StepGate: %v", err)
			}
			if err := tc.resolve(svc, id); err != nil {
				t.Fatalf("%s: %v", tc.op, err)
			}
			assertAuditOrg(t, capture, id, tc.op)
		})
	}
}

// A workflow row owned by the unowned sentinel (migration core/156's backfill
// of orphans) is refused before any audit entry is built, so the four sites
// that read workflow.OrgID can never write the sentinel as an org.
func TestSentinelOwnedWorkflowMutationsWriteNoAuditEntry(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		op     string
		mutate func(svc *Service, id, tenant, org string) error
	}{
		{"aborted", func(svc *Service, id, tenant, org string) error { return svc.AbortWorkflow(ctx, id, "r", tenant, org) }},
		{"completed", func(svc *Service, id, tenant, org string) error { return svc.CompleteWorkflow(ctx, id, tenant, org) }},
		{"failed", func(svc *Service, id, tenant, org string) error { return svc.FailWorkflow(ctx, id, "r", tenant, org) }},
		{"step_completed", func(svc *Service, id, tenant, org string) error {
			return svc.MarkStepCompleted(ctx, id, "step-1", nil, tenant, org)
		}},
	} {
		for _, caller := range []struct{ name, tenant, org string }{
			{"an ordinary caller", auditOrgTenant, auditOrgOrg},
			{"a caller presenting the sentinel", tenantscope.UnownedOrgSentinel, tenantscope.UnownedOrgSentinel},
		} {
			t.Run(tc.op+"/"+caller.name, func(t *testing.T) {
				svc, capture, repo := auditOrgService(t, nil)
				orphan := &Workflow{
					WorkflowName: "orphan",
					TenantID:     tenantscope.UnownedOrgSentinel,
					OrgID:        tenantscope.UnownedOrgSentinel,
				}
				if err := repo.Create(ctx, orphan); err != nil {
					t.Fatalf("seed: %v", err)
				}
				// The step exists, so step_completed cannot be refused for the
				// wrong reason (a missing step) with the ownership check gone.
				if err := repo.AddStep(ctx, &WorkflowStep{WorkflowID: orphan.WorkflowID, StepID: "step-1", StepName: "step-1",
					StepType: StepTypeToolCall, Decision: GateDecisionAllow}); err != nil {
					t.Fatalf("seed step: %v", err)
				}
				err := tc.mutate(svc, orphan.WorkflowID, caller.tenant, caller.org)
				if !errors.Is(err, ErrWorkflowNotFound) {
					t.Fatalf("%s on a sentinel-owned workflow must be refused as not found by the ownership check, got %v", tc.op, err)
				}
				if n := len(capture.entries); n != 0 {
					t.Fatalf("a refused %s wrote %d audit entries; want none (first OrgID %q)", tc.op, n, capture.entries[0].OrgID)
				}
			})
		}
	}
}
