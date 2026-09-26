// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"context"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"

	"axonflow/platform/decision/activation"
	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/legacycompile"
	"axonflow/platform/decision/policypack"
	"axonflow/platform/shared/anchoredenforcer"
)

// TestEveryRequestPassWhereTheScoreIsReadStatesItsFinCrimeObjects is the INPUT
// side of TestOnlyTheRequestPassStatesAdmittedFacts (#3330, master R3 round 1
// H1). The score fact is produced from requestPassInput.finCrime; a request
// pass that leaves it unset on a scope where the score is read is never scored,
// and its audit row says `no_transaction` - a false statement about a request
// that DID declare a transaction, on the row a reviewer reads to answer "was
// this scored". Deleting the field from check-input once failed nothing.
//
// Two halves, neither a list someone maintains:
//   - SYNTAX: every requestPassInput handed to a request pass (enforceRequestPass
//     with its scope, or the MCP request pass's enforceMCPRequest[Holding]) is
//     found in the package source, with the scope it is decided on. A scope
//     argument this test cannot name, or an input that is not a literal, fails:
//     the guard cannot see through either.
//   - RUNTIME: for each such scope, the real enforcer, with a score-control pack
//     installed, says whether the score is read there
//     (anchoredenforcer.AdmittedFactsInput.Reads).
//
// Every literal on a scope where the score is read must set finCrime.
//
// The durable shape - decideRequestPass deriving finCrime from the pass's own
// request, so no entry point has to remember it - is filed on #3328.
func TestEveryRequestPassWhereTheScoreIsReadStatesItsFinCrimeObjects(t *testing.T) {
	sites := requestPassSites(t)
	if len(sites) < 9 {
		t.Fatalf("PREMISE: found %d request-pass sites; decide, gateway, two proxy, openai and four MCP request passes make at least nine, so the scan read the wrong files: %v", len(sites), sites)
	}
	named := map[string]legacycompile.EnforcementScope{
		"decideSeamScope":           decideSeamScope,
		"gatewayRequestSeamScope":   gatewayRequestSeamScope,
		"proxyRequestSeamScope":     proxyRequestSeamScope,
		"openaiCompatibleSeamScope": openaiCompatibleSeamScope,
		"mcpRequestSeamScope":       mcpRequestSeamScope,
	}
	reads := scopesThatReadTheScore(t, named)
	var bindable, unbindable []string
	for name := range named {
		if reads[name] {
			bindable = append(bindable, name)
		} else {
			unbindable = append(unbindable, name)
		}
	}
	sort.Strings(bindable)
	if !slices.Contains(bindable, "decideSeamScope") || !slices.Contains(bindable, "mcpRequestSeamScope") || len(unbindable) == 0 {
		t.Fatalf("PREMISE: the score is read on %v and not on %v; the pack binds on decide and mcp:request only, so the runtime half does not discriminate", bindable, unbindable)
	}
	checked := 0
	for _, s := range sites {
		scope, ok := named[s.scope]
		if !ok {
			t.Errorf("%s: a request pass decided on %q, which this test cannot name; add it to the table so its binding is measured", s.pos, s.scope)
			continue
		}
		if !s.literal {
			t.Errorf("%s: the request pass on %s is handed a requestPassInput that is not a literal, so this guard cannot see whether it states finCrime", s.pos, scope)
			continue
		}
		if reads[s.scope] {
			checked++
			if !s.setsFinCrime {
				t.Errorf("%s: a request pass on %s, where the score is read, does not set finCrime: its requests are never scored and their audit rows say no_transaction", s.pos, scope)
			}
		}
	}
	if checked < 5 {
		t.Fatalf("PREMISE: %d literals checked on scopes that read the score; decide and the four MCP request passes make five", checked)
	}
}

type requestPassSite struct {
	pos, scope            string
	literal, setsFinCrime bool
}

// requestPassSites scans the package's non-test source for every request pass.
// The two MCP wrappers pass their own parameter through and are not sites.
func requestPassSites(t *testing.T) []requestPassSite {
	t.Helper()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	var out []requestPassSite
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parsing %s: %v", name, err)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil || fn.Name.Name == "enforceMCPRequest" || fn.Name.Name == "enforceMCPRequestHolding" {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				id, ok := call.Fun.(*ast.Ident)
				if !ok {
					return true
				}
				var scope string
				var in ast.Expr
				switch {
				case id.Name == "enforceRequestPass" && len(call.Args) == 3:
					scope = exprName(call.Args[1])
					in = call.Args[2]
				case (id.Name == "enforceMCPRequestHolding" || id.Name == "enforceMCPRequest") && len(call.Args) >= 2:
					scope, in = "mcpRequestSeamScope", call.Args[1]
				default:
					return true
				}
				site := requestPassSite{pos: fset.Position(call.Pos()).String(), scope: scope}
				if lit, ok := in.(*ast.CompositeLit); ok {
					if typ, ok := lit.Type.(*ast.Ident); ok && typ.Name == "requestPassInput" {
						site.literal = true
						for _, el := range lit.Elts {
							if kv, ok := el.(*ast.KeyValueExpr); ok {
								if key, ok := kv.Key.(*ast.Ident); ok && key.Name == "finCrime" {
									site.setsFinCrime = true
								}
							}
						}
					}
				}
				out = append(out, site)
				return true
			})
		}
	}
	return out
}

func exprName(e ast.Expr) string {
	if id, ok := e.(*ast.Ident); ok {
		return id.Name
	}
	return "<not an identifier>"
}

// scopesThatReadTheScore asks the real enforcer, with a score-control pack
// installed, which of the named scopes read the score: the hook the request
// pass attaches is handed Reads, and the answer is recorded, not listed.
func scopesThatReadTheScore(t *testing.T, named map[string]legacycompile.EnforcementScope) map[string]bool {
	t.Helper()
	enfSetup(t)
	enforcer, _ := enfSeamUnit(t, enfPublishDocument(t, enfSnapshot(t)))
	e := enforcer(t)
	src := &policypack.Source{
		ID: "guardscore", Version: 1,
		Approval: &policypack.ApproverPool{Quorum: 1, Group: "guardscore-approvers"},
		Scores: []policypack.ScoreThreshold{{
			ID: "gs_ml", Name: "ML", Category: "fincrime", Severity: "high", Phase: "request",
			Signal: riskScoreSignal, Threshold: 0.5, ThresholdRule: "test", Description: "test",
		}},
	}
	raw, err := json.Marshal(src)
	if err != nil {
		t.Fatal(err)
	}
	committed, err := policypack.Render(src)
	if err != nil {
		t.Fatal(err)
	}
	pack, err := policypack.Load(raw, committed)
	if err != nil {
		t.Fatal(err)
	}
	installed, err := activation.InstallPacks(enfSnapshot(t), []*policypack.Pack{pack})
	if err != nil {
		t.Fatal(err)
	}
	e.Packs = installed
	action, ok := decideActionForStage(DecisionStageLLM)
	if !ok {
		t.Fatal("PREMISE: the llm stage names no action")
	}
	auth := &AuthResult{Kind: AuthKindEnterprise, OrgID: enfOrgImplicit, TenantID: enfOrgImplicit, ClientID: "input-guard-client"}
	out := map[string]bool{}
	for name, scope := range named {
		asked := false
		v := e.evaluate(context.Background(), anchoredCall{
			scope: scope, orgID: enfOrgImplicit, requestID: "input-guard-" + name, action: action,
			subject: requestSubject(enfOrgImplicit, auth, nil, userAbsent), emptyContent: true,
			admittedFacts: func(_ context.Context, in anchoredenforcer.AdmittedFactsInput) contract.AttributeSet {
				asked = true
				out[name] = in.Reads(riskScorePath)
				return nil
			},
		})
		if !asked {
			t.Fatalf("PREMISE: %s never asked the hook (unavailable %q, refusal %v), so whether it reads the score was not measured", name, v.unavailable, v.refusal)
		}
	}
	return out
}
