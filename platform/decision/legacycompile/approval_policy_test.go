// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package legacycompile

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/pdp"
)

// TestApprovalPolicyIsTheOneMappingForBothSubstrates pins ApprovalPolicy two
// ways, because each way alone misses a class of re-spelling.
//
//   - BEHAVIOUR: a require_approval compiled on each substrate is exactly
//     ApprovalPolicy's shape over the pool it resolved, with the obligation
//     attributed to the compiled policy's own id. A re-spelled arm that
//     DIVERGES in any field reds here.
//   - CONSTRUCTION: this package builds an approval_challenge in exactly one
//     place, ApprovalPolicy. A re-spelled arm that AGREES with the helper passes
//     every behavioural assertion - it is indistinguishable from the helper by
//     output - so the census over the source is what reds on it.
//
// A runtime check at each call site that the id equals base.ID was the other
// candidate and is refused: both call sites assign base.ID from that id a few
// lines above, so the check could never fail.
func TestApprovalPolicyIsTheOneMappingForBothSubstrates(t *testing.T) {
	// The helper's own shape, asserted field by field. The subtest below
	// compares each substrate against the helper, which cannot see a defect IN
	// the helper: a helper that stopped marking the requirement mandatory would
	// agree with itself.
	t.Run("ApprovalPolicy is a mandatory requirement carrying one mandatory approval_challenge", func(t *testing.T) {
		pool := ApprovalPool{Quorum: 2, Eligible: []string{"Group::r:a", "Group::r:b"}}
		p := ApprovalPolicy(pdp.Policy{ID: "x"}, pool)
		if p.Authority != contract.AuthorityRequirement || !p.Mandatory || len(p.Obligations) != 1 {
			t.Fatalf("ApprovalPolicy = %+v, want a mandatory requirement with one obligation", p)
		}
		o := p.Obligations[0]
		if o.Type != contract.ObApprovalChallenge || !o.Mandatory || o.SourcePolicy != "x" || o.SchemaVersion != 1 ||
			o.Params["quorum"] != "2" || o.Params["eligible"] != "Group::r:a,Group::r:b" || len(o.Params) != 2 {
			t.Fatalf("the approval obligation is %+v", o)
		}
	})

	t.Run("each substrate's approval control is ApprovalPolicy's shape", func(t *testing.T) {
		opts := testOptions()
		pool := opts.ApprovalPools["*"]
		static := staticRow(t, "sys_hitl", map[string]any{
			// A category no plane coerces, so every plane resolves the stored
			// require_approval rather than a forced action.
			"category": "admin-access",
			"action":   "require_approval", "action_request": "require_approval", "action_response": "require_approval",
		})
		dynamic := dynamicRow(t, "dyn_hitl", map[string]any{
			"actions": []map[string]any{{"type": "require_approval", "config": map[string]any{"reason": "needs a person"}}},
		})
		rep, err := Compile([]RawRow{static, dynamic}, opts)
		if err != nil {
			t.Fatalf("Compile: %v", err)
		}
		for _, id := range []string{"sys_hitl", "dyn_hitl"} {
			rec := recordFor(t, rep, id)
			n := 0
			for _, plane := range rec.Planes {
				for _, p := range plane.Policies {
					n++
					base := p
					base.Authority, base.Mandatory, base.Obligations = "", false, nil
					if want := ApprovalPolicy(base, pool); !reflect.DeepEqual(p, *want) {
						t.Errorf("%s on %s compiled to\n  %+v\nwhich is not ApprovalPolicy's\n  %+v", id, plane.Plane, p, *want)
					}
					if len(p.Obligations) != 1 || p.Obligations[0].SourcePolicy != p.ID {
						t.Errorf("%s on %s: the approval obligation is not attributed to the policy it is attached to: %+v", id, plane.Plane, p.Obligations)
					}
				}
			}
			if n == 0 {
				t.Fatalf("%s compiled to no policy on any plane; the shape assertion above would be vacuous", id)
			}
		}
	})

	t.Run("an approval_challenge is constructed in ApprovalPolicy and nowhere else", func(t *testing.T) {
		files, err := filepath.Glob("*.go")
		if err != nil {
			t.Fatal(err)
		}
		var sites []string
		for _, f := range files {
			if strings.HasSuffix(f, "_test.go") {
				continue
			}
			src, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			sites = append(sites, approvalChallengeConstructions(t, f, src)...)
		}
		if len(sites) != 1 || sites[0] != "static.go:ApprovalPolicy" {
			t.Fatalf("an approval_challenge is constructed at %v; ApprovalPolicy is the one approval mapping, and every source "+
				"must reach it rather than re-spell it", sites)
		}
	})

	t.Run("the construction census sees a planted second construction", func(t *testing.T) {
		planted := []byte(`package legacycompile
import "axonflow/platform/decision/contract"
func respelled() []contract.Obligation {
	return []contract.Obligation{{Type: contract.ObApprovalChallenge, Mandatory: true}}
}`)
		if got := approvalChallengeConstructions(t, "planted.go", planted); len(got) != 1 || got[0] != "planted.go:respelled" {
			t.Fatalf("the census found %v in a source with one construction inside respelled", got)
		}
	})
}

// approvalChallengeConstructions returns "file:function" for every composite
// literal in src that sets Type to contract.ObApprovalChallenge. The literal
// inside []contract.Obligation{{...}} has its type elided, so the key is what is
// matched, not the literal's type.
func approvalChallengeConstructions(t *testing.T, name string, src []byte) []string {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), name, src, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", name, err)
	}
	var out []string
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}
		ast.Inspect(fn, func(n ast.Node) bool {
			lit, ok := n.(*ast.CompositeLit)
			if !ok {
				return true
			}
			for _, elt := range lit.Elts {
				kv, ok := elt.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				key, ok := kv.Key.(*ast.Ident)
				if !ok || key.Name != "Type" {
					continue
				}
				if sel, ok := kv.Value.(*ast.SelectorExpr); ok && sel.Sel.Name == "ObApprovalChallenge" {
					out = append(out, filepath.Base(name)+":"+fn.Name.Name)
				}
			}
			return true
		})
	}
	sort.Strings(out)
	return out
}
