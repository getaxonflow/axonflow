// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
//
// #3897 §1: the decision identifier had two names. POST /api/policy/pre-check
// called it `context_id`; POST /api/v1/decide, both MCP check endpoints and the
// AuthZEN adapter all call it `decision_id`. A client reading `decision_id` can
// call GET /api/v1/decisions/{id}/explain and the session-override routes; the same
// client against pre-check found no such member and SILENTLY LOST BOTH.

package agent

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestPreCheckEmitsBothDecisionIdAndItsDeprecatedAlias drives the writer and
// reads the bytes, rather than asserting on the struct tags.
func TestPreCheckEmitsBothDecisionIdAndItsDeprecatedAlias(t *testing.T) {
	const want = "ctx-2f8c1e90-planted"

	for _, status := range []int{http.StatusOK, http.StatusPaymentRequired} {
		rec := httptest.NewRecorder()
		writePreCheckResponse(rec, status, PreCheckResponse{ContextID: want, Approved: true})

		if rec.Code != status {
			t.Errorf("status %d, want %d", rec.Code, status)
		}
		var body map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("pre-check response is not decodable JSON: %v\nbody: %s", err, rec.Body.String())
		}

		// THE CANONICAL NAME. This is the member #3897 asked for.
		if got, _ := body["decision_id"].(string); got != want {
			t.Errorf("at status %d, `decision_id` is %q, want %q. Without it a pre-check caller cannot "+
				"reach GET /api/v1/decisions/{id}/explain or the session-override routes, both of which are "+
				"keyed on this identifier (#3897 §1).", status, got, want)
		}
		// THE DEPRECATED ALIAS, which must NOT disappear: every shipped SDK
		// reads it, and removing it would 404 them all. The deprecation path is
		// "both for at least one release", not a rename.
		if got, _ := body["context_id"].(string); got != want {
			t.Errorf("at status %d, `context_id` is %q, want %q. It is deprecated, NOT removed - a "+
				"silent rename is what #3897's DoD forbids.", status, got, want)
		}
		// AND THEY MUST BE THE SAME VALUE. Two names that can disagree are
		// worse than one name, because a client reconciling them has no way to
		// know which is authoritative.
		if body["decision_id"] != body["context_id"] {
			t.Errorf("at status %d, decision_id=%v and context_id=%v are DIFFERENT values. They are one "+
				"identifier under two names.", status, body["decision_id"], body["context_id"])
		}
	}
}

// TestEveryPreCheckResponseGoesThroughTheOneWriter is the census that makes the
// test above a statement about the ENDPOINT rather than about one helper.
//
// The alias is minted in writePreCheckResponse. A handler that encodes a
// PreCheckResponse directly would emit `context_id` and no `decision_id`, and
// the driven test above would still pass - it exercises the writer, not the
// bypass. Six sites already existed and one of them wrote a 402 rather than a
// 200, so "they all look the same" was false before this test was written.
// preCheckBypassSites is the census, extracted so its CONTROL can drive the
// same code the guard runs. A control that reimplements the rule tests the
// reimplementation.
func preCheckBypassSites(t *testing.T, roots []string) (offenderList []string, allowancesHit map[string]bool, jsonWritesSeen int) {
	t.Helper()

	fset := token.NewFileSet()
	var offenders []string
	var encodeCallsSeen int
	allowanceHits := map[string]bool{}

	// PHASE 1: every function whose RETURN type is a PreCheckResponse.
	//
	// Without this, a constructor returning one and a caller that encodes the
	// call's result never name the type in the same function, and the caller
	// walks straight past a census keyed on mention. R3 round 2 planted exactly
	// that and it was the one bypass of three that survived the first widening.
	returnsPreCheck := map[string]bool{}
	collect := func(root string) {
		_ = filepath.Walk(root, func(pth string, fi os.FileInfo, err error) error {
			if err != nil || fi.IsDir() || !strings.HasSuffix(pth, ".go") || strings.HasSuffix(pth, "_test.go") {
				return nil
			}
			file, perr := parser.ParseFile(fset, pth, nil, 0)
			if perr != nil {
				return nil
			}
			for _, decl := range file.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Type.Results == nil {
					continue
				}
				ast.Inspect(fn.Type.Results, func(n ast.Node) bool {
					switch v := n.(type) {
					case *ast.Ident:
						if v.Name == "PreCheckResponse" {
							returnsPreCheck[fn.Name.Name] = true
						}
					case *ast.SelectorExpr:
						if v.Sel.Name == "PreCheckResponse" {
							returnsPreCheck[fn.Name.Name] = true
						}
					}
					return true
				})
			}
			return nil
		})
	}

	// THE ee/ ROOT IS ABSENT ON THE COMMUNITY MIRROR, and this test SYNCS
	// there - it carries no build tag and is not named `_enterprise_test.go`,
	// so both strip mechanisms miss it. A census that fatals on a missing root
	// would red the mirror's CI on every run, on a checkout where nothing is
	// wrong. platform/ is never absent and a missing one IS fatal; the same
	// split the other synced censuses in this package use.
	//
	// The anti-vacuity floor below is what keeps this honest rather than the
	// root list: a walk that read nothing fails there whether ee/ was present
	// or not.
	for _, root := range roots {
		if _, err := os.Stat(root); err == nil {
			collect(root)
		}
	}
	// NO FLOOR ON len(returnsPreCheck). The live tree builds every
	// PreCheckResponse inline, so there is legitimately no such constructor
	// today, and a floor here would fire on a healthy tree - the same mistake
	// as counting only the Encode calls the offender rule looks at. The arm is
	// proved by TestThePreCheckCensusCatchesEveryBypassShape instead, against a
	// fixture that does contain one.

	for _, root := range roots {
		if _, err := os.Stat(root); err != nil {
			if root == "." {
				t.Fatalf("census root %q unreadable: %v", root, err)
			}
			continue
		}
		err := filepath.Walk(root, func(p string, fi os.FileInfo, err error) error {
			if err != nil || fi.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
				return nil
			}
			file, perr := parser.ParseFile(fset, p, nil, 0)
			if perr != nil {
				return nil
			}
			// THE ANTI-VACUITY COUNTER IS INDEPENDENT OF THE OFFENDER RULE,
			// and it has to be: when a previous version counted only the
			// Encode calls the offender rule looked at, the CORRECT state of
			// the tree drove that count to zero and the floor fired on a
			// healthy tree. A floor that measures the thing being asserted is
			// not a floor.
			ast.Inspect(file, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Encode" {
					encodeCallsSeen++
				}
				return true
			})

			// FLAG ANY FUNCTION THAT MENTIONS THE TYPE AND WRITES JSON.
			//
			// R3 ROUND 1 killed the version that matched `x := PreCheckResponse{}`
			// followed by `Encode(x)`: `Encode(&x)` walked past it. R3 ROUND 2
			// then killed the replacement, which asked "does this function
			// CONSTRUCT the type and call .Encode" - three real bypasses walked
			// past THAT, each emitting `context_id` with no `decision_id` and no
			// `verdict`:
			//
			//   - build in one function, encode in another that takes it as a
			//     PARAMETER;
			//   - a constructor RETURNING one, encoded by its caller;
			//   - `json.Marshal` + `w.Write(b)` instead of `Encode`.
			//
			// The commit message for the round-1 fix claimed the coarser
			// question "has no spellings". It had at least three. So the
			// question is coarser again, and this time it is about MENTION
			// rather than construction: does a function other than the blessed
			// writer refer to this type AT ALL - parameter, return, literal,
			// var - and also serialise JSON by any means. That is wide enough
			// to be uncomfortable, which is why it has an allowance list with a
			// ratchet rather than a silent narrowing.
			for _, decl := range file.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Body == nil {
					continue
				}
				if fn.Name.Name == "writePreCheckResponse" {
					continue // the one blessed writer
				}

				mentionsType := false
				noteIdent := func(n ast.Node) {
					switch v := n.(type) {
					case *ast.Ident:
						if v.Name == "PreCheckResponse" {
							mentionsType = true
						}
					case *ast.SelectorExpr:
						if v.Sel.Name == "PreCheckResponse" {
							mentionsType = true
						}
					}
				}
				ast.Inspect(fn.Type, func(n ast.Node) bool { noteIdent(n); return true })
				ast.Inspect(fn.Body, func(n ast.Node) bool {
					noteIdent(n)
					// A CALL to a function that RETURNS one counts as a
					// mention: the value reaches this function's wire write
					// without its type ever being named here.
					if call, ok := n.(*ast.CallExpr); ok {
						switch f := call.Fun.(type) {
						case *ast.Ident:
							if returnsPreCheck[f.Name] {
								mentionsType = true
							}
						case *ast.SelectorExpr:
							if returnsPreCheck[f.Sel.Name] {
								mentionsType = true
							}
						}
					}
					return true
				})
				if !mentionsType {
					continue
				}

				ast.Inspect(fn.Body, func(n ast.Node) bool {
					call, ok := n.(*ast.CallExpr)
					if !ok {
						return true
					}
					sel, ok := call.Fun.(*ast.SelectorExpr)
					if !ok {
						return true
					}
					// Encode on any encoder, Marshal from encoding/json, and a
					// raw Write - the three ways a body reaches the wire here.
					isWrite := sel.Sel.Name == "Encode" ||
						sel.Sel.Name == "Write" ||
						(sel.Sel.Name == "Marshal" || sel.Sel.Name == "MarshalIndent")
					if !isWrite {
						return true
					}
					posn := fset.Position(call.Pos()).String()
					if _, allowed := preCheckWriterAllowances()[fn.Name.Name]; allowed {
						allowanceHits[fn.Name.Name] = true
						return true
					}
					offenders = append(offenders, posn+"  (in "+fn.Name.Name+", which mentions PreCheckResponse)")
					return true
				})
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", root, err)
		}
	}

	return offenders, allowanceHits, encodeCallsSeen
}

func TestEveryPreCheckResponseGoesThroughTheOneWriter(t *testing.T) {
	offenders, allowanceHits, jsonWrites := preCheckBypassSites(t,
		[]string{".", filepath.Join("..", "..", "ee", "platform", "agent")})

	// ANTI-VACUITY, and it belongs HERE rather than inside the census: it is a
	// statement about the real tree, and the census is also driven by a control
	// against a five-function fixture where a floor of 20 would be nonsense.
	if jsonWrites < 20 {
		t.Fatalf("the census saw only %d json Encode call(s) across the agent roots; it is not reading "+
			"the tree, and the offender list below would be empty for the wrong reason", jsonWrites)
	}

	// THE ALLOWANCE RATCHET. This census is deliberately wide, so a legitimate
	// function that mentions the type and also writes an unrelated body needs
	// somewhere to go that is not "weaken the census" - R3 round 2 noted there
	// was no such place. A row that stops matching fails, so the list cannot
	// outlive its cause.
	for name := range preCheckWriterAllowances() {
		if !allowanceHits[name] {
			t.Errorf("preCheckWriterAllowances allows %q and no JSON write there mentions "+
				"PreCheckResponse any more. Delete the row.", name)
		}
	}

	if len(offenders) > 0 {
		t.Errorf("%d site(s) encode a PreCheckResponse directly instead of calling "+
			"writePreCheckResponse:\n  %s\n\nA direct encode emits `context_id` with NO `decision_id`, "+
			"reopening #3897 §1 on that one code path while every other path stays correct - which is "+
			"the hardest shape of this defect to notice.",
			len(offenders), strings.Join(offenders, "\n  "))
	}
}

// preCheckWriterAllowances names functions that mention PreCheckResponse and
// also write JSON, without being a bypass.
//
// EMPTY TODAY, AND THAT IS THE POINT: the census is wide enough that a
// legitimate case is plausible, and whoever hits one needs a place to record it
// with a reason instead of narrowing the rule until their case disappears -
// which is what the previous two versions of this census invited. Each row must
// say why the function is not writing a PreCheckResponse to the wire.
func preCheckWriterAllowances() map[string]string {
	return map[string]string{}
}
