package agent

import (
	"bytes"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"axonflow/platform/decision/contract"
)

// The convergence guards for #3631: ONE mapping from a decision onto the
// AuthZEN profile payload.
//
// There used to be two. contract.Decision.ToAuthZEN was tested and never
// served; the handler's own struct literal was served and never compared to it.
// They had already drifted on exactly one member - the handler never set
// Approval - so every response POST /api/v1/access/evaluation ever returned
// omitted the approval challenge that capabilities.go and agent-api.yaml both
// advertised, and nothing could see it, because the conformance cases exercised
// the rendering nothing served.
//
// Two guards, and the pairing is the point. The first is BEHAVIOURAL: it
// compares the bytes a real HTTP response carried against ToAuthZEN's rendering
// of the equivalent decision, so a second producer written in any syntax at all
// is caught the moment it differs. The second is SYNTACTIC and is only as wide
// as the syntax it matches, which is exactly why it is not the only one: it
// catches the shape early, at review time, with a message that names the
// rule.

// TestServedAuthZENContextEqualsToAuthZEN is the regression gate the issue asks
// for: the served context and ToAuthZEN's context must agree on EVERY member.
//
// Byte comparison rather than a field list, deliberately. A field-by-field
// assertion is a third hand-maintained enumeration of the same member set and
// would go stale the same way the two mappings did; comparing the encodings
// covers a member added tomorrow without anyone remembering to add it here.
//
// WHERE THE EXPECTED VALUES COME FROM, because a comparison against values read
// out of the response under test proves nothing. The handler is an adapter over
// POST /api/v1/decide, so the independent source is that route: the same query
// goes through it directly, and the expected state, reason and obligation set
// are derived from ITS answer through the same total functions the handler
// uses. Only decision_id is taken from the served response, because it is
// generated per request and the two requests necessarily have different ones;
// it is asserted non-empty separately.
//
// THREE POSTURES, because one is not a comparison. The same PII query under
// PII_ACTION=redact, warn and block gives an ALLOW carrying a mandatory
// obligation, an ALLOW carrying none, and a DENY - three different renderings
// over one query, so the two mappings are compared on the reason code, the
// derived category and the obligation gate rather than on a single shape where
// any mistake would be constant across both sides.
//
// WHAT THIS TEST CANNOT SEE, stated rather than left to be discovered. The two
// renderings differ on a CHALLENGE that carries obligations - the old handler
// literal dropped them, the shared producer carries them - and this surface
// cannot produce that combination in process: the evaluator attaches
// obligations only to an allow. That case is driven directly, over all four
// states, by contract.TestTheProducerDropsInstructionsOnADecisionThatPermitsNothing,
// and the structural half is held by
// TestNothingButTheContractProducesAnAuthZENContext below.
func TestServedAuthZENContextEqualsToAuthZEN(t *testing.T) {
	for _, posture := range []struct {
		action         string
		wantState      contract.OperationalState
		wantObligation bool
	}{
		{"redact", contract.StateAllow, true},
		{"warn", contract.StateAllow, false},
		{"block", contract.StateDeny, false},
	} {
		t.Run(posture.action, func(t *testing.T) {
			installAuthZENPIIWorld(t, posture.action)

			// The independent leg: what the evaluator this route adapts said.
			decideBody := []byte(`{"stage":"llm","caller_identity":{"gateway_id":"llm-gateway-01"},` +
				`"target":{"type":"llm","provider":"openai","model":"gpt-4o"},` +
				`"query":"Customer NIK is 3174042506780001"}`)
			dr := decideForTest(t, decideBody)
			if dr.Code != 200 {
				t.Fatalf("the delegated route answered %d, so there is no evaluation to compare against: %s", dr.Code, dr.Body.String())
			}
			var decided DecideResponse
			if err := json.Unmarshal(dr.Body.Bytes(), &decided); err != nil {
				t.Fatalf("decoding the /decide answer: %v", err)
			}

			state := authzenStateFor(decided.Verdict)
			reason := authzenReasonFor(state)
			obligations, err := mapObligations(decided.Obligations)
			if err != nil {
				t.Fatalf("mapping the evaluator's obligations: %v", err)
			}
			// The posture produced the shape this case is here to compare. A
			// deployment where it did not would make the comparison hold for a
			// reason that has nothing to do with the two renderings.
			if state != posture.wantState {
				t.Fatalf("PII_ACTION=%s produced state %s, want %s; this case is not comparing what it says it is",
					posture.action, state, posture.wantState)
			}
			if (len(obligations) > 0) != posture.wantObligation {
				t.Fatalf("PII_ACTION=%s produced %d obligations, want obligation=%t",
					posture.action, len(obligations), posture.wantObligation)
			}

			// The served leg.
			rr := authzenForTest(t, authzenPIIEnvelope(t), negotiated())
			served := decodeAuthZENResponse(t, rr)
			if served.Context == nil {
				t.Fatal("the negotiated response carried no context")
			}
			if served.Context.DecisionID == "" {
				t.Error("the served context names no decision id, so an operator cannot look the decision up")
			}

			// ToAuthZEN's rendering of the equivalent decision. The snapshot is
			// a test fixture and is honest as one: its value is never emitted
			// (the context carries only schema_version), and a TEST may state
			// what a decision was computed against where the serving adapter may
			// not INVENT it - which is the whole reason the two share a producer
			// rather than a Decision.
			d := &contract.Decision{
				DecisionID:    served.Context.DecisionID,
				RequestID:     "r-convergence",
				Authorization: authorizationProducing(t, state),
				State:         state,
				Reason:        reason,
				Obligations:   obligations,
				Determining:   contract.Determining{MatchedPermissions: []string{"p-1"}},
				Snapshot: contract.Snapshot{
					IdentityEpoch: 1, ResourceEpoch: 1, PolicyBundle: "sha256:fixture",
					RegistryVersion: 1, SchemaVersion: contract.SchemaVersion, PolicyEpoch: 1,
				},
			}
			want, err := d.ToAuthZEN(contract.AuthZENProfileV1)
			if err != nil {
				t.Fatalf("ToAuthZEN refused the equivalent decision: %v", err)
			}

			gotBytes, err := json.Marshal(served.Context)
			if err != nil {
				t.Fatalf("re-encoding the served context: %v", err)
			}
			wantBytes, err := json.Marshal(want.Context)
			if err != nil {
				t.Fatalf("encoding ToAuthZEN's context: %v", err)
			}
			if !bytes.Equal(gotBytes, wantBytes) {
				t.Errorf("the served context and ToAuthZEN's context disagree; a member set at one of the two "+
					"renderings and not the other is how `approval` came to be advertised and never sent.\n served: %s\n  toazn: %s",
					gotBytes, wantBytes)
			}
		})
	}
}

// authorizationProducing returns the deterministic outcome that yields this
// operational state with no approval outstanding.
//
// DERIVED from StateFor by searching the declared enumeration rather than
// written out, so the test fixture cannot disagree with the mapping the
// contract actually uses. DENY is reachable from two outcomes and the first is
// taken; they render identically, because a decision that is not a permit
// carries no obligations and no approval either way.
func authorizationProducing(t *testing.T, state contract.OperationalState) contract.Authorization {
	t.Helper()
	for _, a := range contract.AllAuthorizations() {
		if got, err := contract.StateFor(a, false); err == nil && got == state {
			return a
		}
	}
	t.Fatalf("no declared authorization produces state %s", state)
	return ""
}

// TestTheServedContextOmitsApprovalDeliberately pins the ruling this change
// makes, so that "the member is absent" is a recorded decision rather than an
// omission nobody can distinguish from the bug that was just fixed.
//
// The adapter cannot populate it: DecideResponse carries no approval
// requirement, and contract.ApprovalRequirement.Validate needs an eligible
// group set, a quorum and an expiry that nothing in that response names.
// Synthesising them would hand a PEP a fabricated approval policy to enforce,
// which is worse than the omission. The advertisements now say so.
func TestTheServedContextOmitsApprovalDeliberately(t *testing.T) {
	installAuthZENPIIWorld(t, "redact")
	rr := authzenForTest(t, authzenPIIEnvelope(t), negotiated())
	served := decodeAuthZENResponse(t, rr)
	if served.Context == nil {
		t.Fatal("the negotiated response carried no context")
	}
	if served.Context.Approval != nil {
		t.Errorf("the served context carries an approval requirement. If the adapter has learned to surface a real "+
			"one, that is a capability change: update capabilities.go, agent-api.yaml and this test together, and "+
			"delete the paragraph in the handler that explains why it is nil. got %+v", served.Context.Approval)
	}
	// ...and BOTH ADVERTISEMENTS agree with the wire. This is the half that was
	// wrong: the capability entry and the OpenAPI document each promised a
	// member the surface never sent, and a PEP negotiating the profile
	// specifically to receive it got no error and no signal.
	//
	// The assertions are LITERAL PINS on the old promise and on the new
	// disclaimer, not a search for the phrase "approval challenge". A phrase
	// scan cannot tell a promise from a disclaimer - the corrected text says
	// "what it does NOT carry is an approval challenge" and would fail its own
	// check, which is the marker-collides-with-the-prose-beside-it shape. A pin
	// on the exact clause that was wrong, plus a pin on the exact clause that
	// replaced it, is checkable and does not collide: rewriting either brings
	// the author past this test to re-affirm the wire behaviour.
	entry := capabilityDescription(t, "authzen_evaluation")
	if strings.Contains(entry, obsoleteApprovalPromise) {
		t.Errorf("the authzen_evaluation capability entry still carries the clause that promised the challenge: %q", obsoleteApprovalPromise)
	}
	if !strings.Contains(entry, approvalExclusionClause) {
		t.Errorf("the authzen_evaluation capability entry no longer states the exclusion (%q). A capability list that "+
			"is merely silent about the approval challenge leaves a PEP to discover the absence by waiting for it.",
			approvalExclusionClause)
	}

	// The OpenAPI document is the other customer-facing copy, and it is the one
	// clients are generated from.
	repoRoot, err := findRepoRoot()
	if err != nil {
		t.Fatalf("locate repo root: %v", err)
	}
	spec, err := os.ReadFile(filepath.Join(repoRoot, "docs", "api", "agent-api.yaml"))
	if err != nil {
		// NOT a skip. A guard that stops guarding when it cannot find its input
		// is indistinguishable from one that found nothing wrong (#3639).
		t.Fatalf("reading docs/api/agent-api.yaml from %s: %v", repoRoot, err)
	}
	flattened := strings.Join(strings.Fields(string(spec)), " ")
	if strings.Contains(flattened, obsoleteSpecApprovalPromise) {
		t.Errorf("docs/api/agent-api.yaml still carries the clause that promised the challenge: %q", obsoleteSpecApprovalPromise)
	}
	if !strings.Contains(flattened, specApprovalExclusionClause) {
		t.Errorf("docs/api/agent-api.yaml no longer states the exclusion (%q)", specApprovalExclusionClause)
	}
}

// The literal pins. Each is a clause, not a word, so it cannot collide with
// ordinary prose about approvals elsewhere in either document.
const (
	// obsoleteApprovalPromise is the capability entry's wording that promised
	// the challenge. Its absence is the fix; the constant is kept so the
	// promise cannot be restored by a copy-paste from an older revision.
	obsoleteApprovalPromise = "four-valued operational state, obligations, approval challenge, safe reason"
	// approvalExclusionClause is the wording that replaced it.
	approvalExclusionClause = "What it does NOT carry is an approval challenge"
	// The OpenAPI document's equivalents, matched against whitespace-flattened
	// text because the source is a folded YAML block scalar.
	obsoleteSpecApprovalPromise = "the four-valued state, obligations, the approval challenge, the safe reason code"
	specApprovalExclusionClause = "There is no approval challenge on this surface"
)

// capabilityDescription returns one capability entry's description text.
func capabilityDescription(t *testing.T, name string) string {
	t.Helper()
	for _, c := range getCapabilities() {
		if c.Name == name {
			return c.Description
		}
	}
	t.Fatalf("no capability named %q is advertised", name)
	return ""
}

// TestNothingButTheContractProducesAnAuthZENContext is the syntactic half.
//
// It walks the Go sources and fails on any construction of
// AuthZENResponseContext outside contract.NewAuthZENResponseContext. A second
// producer is how the drift happened, and the message names the rule rather
// than leaving the next author to rediscover it in a review.
//
// IT IS ONLY AS WIDE AS THE SYNTAX IT MATCHES, and that is stated rather than
// hidden: a composite literal, a `new(...)`, and a `var x T` declaration are
// covered; a value obtained some other way and mutated field by field is not.
// TestServedAuthZENContextEqualsToAuthZEN is what covers that case, by
// comparing what the two renderings PRODUCE rather than how they are written.
func TestNothingButTheContractProducesAnAuthZENContext(t *testing.T) {
	repoRoot, err := findRepoRoot()
	if err != nil {
		t.Fatalf("locate repo root: %v", err)
	}
	scanDirs := []string{
		filepath.Join(repoRoot, "platform"),
		filepath.Join(repoRoot, "ee", "platform"),
	}
	var present []string
	for _, d := range scanDirs {
		if _, statErr := os.Stat(d); statErr == nil {
			present = append(present, d)
		}
	}
	if len(present) == 0 {
		t.Fatalf("no scan directory exists under %s, so this walk asserts nothing", repoRoot)
	}

	findings, scanned, err := findAuthZENContextConstructions(repoRoot, present, authzenContextProducerFile)
	if err != nil {
		// NOT a skip. A guard that stops guarding when its input moves is
		// indistinguishable from one that found nothing wrong (#3639).
		t.Fatalf("scanning for AuthZENResponseContext constructions: %v", err)
	}
	// Anti-vacuity: the walk must actually have reached files that mention the
	// type, or a broken path filter reports a clean board.
	if scanned == 0 {
		t.Fatal("no non-test source file mentioning AuthZENResponseContext was scanned; the walk found nothing " +
			"because it looked nowhere, which is indistinguishable from finding nothing because there is nothing")
	}
	if len(findings) > 0 {
		t.Errorf("AuthZENResponseContext is constructed outside contract.NewAuthZENResponseContext at:\n  %s\n\n"+
			"There is ONE producer of the profile payload. Two hand-maintained renderings of this mapping already "+
			"drifted once, on `approval`, and the drift was invisible for a release because the tested rendering "+
			"was not the served one. Call contract.NewAuthZENResponseContext and add what you need to "+
			"contract.AuthZENContextInput.", strings.Join(findings, "\n  "))
	}
}

// authzenContextProducerFile is the one file allowed to build the context.
const authzenContextProducerFile = "platform/decision/contract/authzen.go"

// TestTheContextProducerCensusCanFail proves the census above is load bearing.
//
// It CANNOT be proved by the overlay mutation harness, and that is the reason
// this test exists rather than a mutation entry: the harness points the
// COMPILER at a mutated copy through -overlay, while the census reads the tree
// from disk. A restored literal introduced by an overlay is invisible to it, so
// a mutation entry aimed at this guard would report a survivor and say nothing
// about whether the guard works.
//
// So the scanner is driven over a synthetic tree instead, with all three
// syntaxes it claims to catch and two controls it must NOT flag.
func TestTheContextProducerCensusCanFail(t *testing.T) {
	root := t.TempDir()
	pkg := filepath.Join(root, "platform", "somewhere")
	if err := os.MkdirAll(pkg, 0o755); err != nil {
		t.Fatalf("building the synthetic tree: %v", err)
	}
	write := func(name, body string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(pkg, name), []byte(body), 0o600); err != nil {
			t.Fatalf("writing %s: %v", name, err)
		}
	}
	write("literal.go", authzenFixture("var A = &contract.AuthZENResponseContext{}"))
	write("newcall.go", authzenFixture("var B = new(contract.AuthZENResponseContext)"))
	write("vardecl.go", authzenFixture("var C contract.AuthZENResponseContext"))
	// Controls. A file that merely NAMES the type in a signature or a comment is
	// not a producer, and flagging it would make the guard unusable.
	write("mentions.go", authzenFixture("// AuthZENResponseContext is mentioned here.\nfunc D(c *contract.AuthZENResponseContext) bool { return c != nil }"))
	write("callsproducer.go", authzenFixture("var E = contract.NewAuthZENResponseContext(contract.AuthZENContextInput{})"))

	findings, scanned, err := findAuthZENContextConstructions(root, []string{filepath.Join(root, "platform")}, "")
	if err != nil {
		t.Fatalf("scanning the synthetic tree: %v", err)
	}
	if scanned != 5 {
		t.Fatalf("scanned %d files, want 5; the walk is not reaching the fixture", scanned)
	}
	if len(findings) != 3 {
		t.Fatalf("flagged %d constructions, want 3 (a composite literal, a new(), a var declaration): %s",
			len(findings), strings.Join(findings, ", "))
	}
	for _, want := range []string{"literal.go", "newcall.go", "vardecl.go"} {
		found := false
		for _, f := range findings {
			if strings.Contains(f, want) {
				found = true
			}
		}
		if !found {
			t.Errorf("the census did not flag %s", want)
		}
	}
	for _, mustNot := range []string{"mentions.go", "callsproducer.go"} {
		for _, f := range findings {
			if strings.Contains(f, mustNot) {
				t.Errorf("the census flagged %s, which constructs nothing", mustNot)
			}
		}
	}

	// ...and the allow-list really exempts, so the real run's exemption of the
	// producer is not the reason it reports clean.
	exempt, _, err := findAuthZENContextConstructions(root, []string{filepath.Join(root, "platform")}, "platform/somewhere/literal.go")
	if err != nil {
		t.Fatalf("scanning with an exemption: %v", err)
	}
	if len(exempt) != 2 {
		t.Errorf("with literal.go exempted the census flagged %d, want 2", len(exempt))
	}
}

// authzenFixture wraps one declaration in a compilable synthetic source file.
func authzenFixture(body string) string {
	return "package somewhere\n\nimport \"axonflow/platform/decision/contract\"\n\n" + body + "\n"
}

// findAuthZENContextConstructions walks Go sources under roots and returns the
// positions at which AuthZENResponseContext is constructed, plus the number of
// files that mentioned the type at all.
//
// allowRel is the ONE repo-relative path permitted to construct it.
func findAuthZENContextConstructions(repoRoot string, roots []string, allowRel string) (findings []string, scanned int, err error) {
	for _, root := range roots {
		walkErr := filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if d.IsDir() {
				switch d.Name() {
				case "vendor", "node_modules", ".claude", "testdata":
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			rel, relErr := filepath.Rel(repoRoot, path)
			if relErr != nil {
				return relErr
			}
			if allowRel != "" && filepath.ToSlash(rel) == allowRel {
				return nil
			}
			src, readErr := os.ReadFile(path) //nolint:gosec // a fixed repo subtree
			if readErr != nil {
				return readErr
			}
			// Cheap pre-filter so the parse runs only on files that mention the
			// type. It is also what `scanned` counts, which is what makes the
			// anti-vacuity check meaningful.
			if !strings.Contains(string(src), "AuthZENResponseContext") {
				return nil
			}
			scanned++
			fset := token.NewFileSet()
			file, parseErr := parser.ParseFile(fset, path, src, 0)
			if parseErr != nil {
				return parseErr
			}
			ast.Inspect(file, func(n ast.Node) bool {
				var where token.Pos
				switch node := n.(type) {
				case *ast.CompositeLit:
					if namesAuthZENContext(node.Type) {
						where = node.Pos()
					}
				case *ast.CallExpr:
					if id, ok := node.Fun.(*ast.Ident); ok && id.Name == "new" && len(node.Args) == 1 &&
						namesAuthZENContext(node.Args[0]) {
						where = node.Pos()
					}
				case *ast.ValueSpec:
					if node.Type != nil && namesAuthZENContext(node.Type) {
						where = node.Pos()
					}
				}
				if where.IsValid() {
					findings = append(findings, fset.Position(where).String())
				}
				return true
			})
			return nil
		})
		if walkErr != nil {
			return nil, scanned, walkErr
		}
	}
	return findings, scanned, nil
}

// namesAuthZENContext reports whether an expression names the response context
// type, written bare or package-qualified, with or without a pointer.
func namesAuthZENContext(e ast.Expr) bool {
	switch t := e.(type) {
	case *ast.StarExpr:
		return namesAuthZENContext(t.X)
	case *ast.Ident:
		return t.Name == "AuthZENResponseContext"
	case *ast.SelectorExpr:
		return t.Sel != nil && t.Sel.Name == "AuthZENResponseContext"
	}
	return false
}
