// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

// =============================================================================
// THE Target.Type VOCABULARY (#3717)
//
// Two guards on the same class, from opposite ends:
//
//   - TestDecisionTargetMirrorsPEPTarget compares the two declarations of the
//     decide target — pep.Target (what a PEP sends) and DecisionTarget (what
//     the PDP decodes) — field by field, by reflection. #3717 had a second half
//     that no amount of fixing the string would have reached: pep.Target had no
//     Server field at all, so no PEP built on the blessed client could populate
//     audit_logs.tool_server whatever Type it sent. The struct declarations are
//     kept independent ON PURPOSE (aliasing them would make the wire-contract
//     tests tautological), and independence without a comparison is how a field
//     goes missing on one side for three releases.
//
//   - TestDecideTargetTypeVocabulary walks the tree and fails on any Target.Type
//     string literal that is not in pep.TargetTypes. This is the anti-FORK pin:
//     "mcp_tool" reintroduced anywhere — a new seam, a copy-pasted adapter, an
//     example — reds here rather than shipping as another silently unattributed
//     plane.
// =============================================================================

import (
	"go/ast"
	"go/parser"
	"go/scanner"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	gatewayadapters "axonflow/platform/gateway-adapters"
	"axonflow/platform/shared/pep"
)

// TestDecisionTargetMirrorsPEPTarget pins the two declarations field-for-field.
//
// The field list is DERIVED BY REFLECTION from the structs themselves, not
// enumerated here: an enumeration written by the author of this test is bounded
// by the fields that author knew about, which is the same shape as the defect.
func TestDecisionTargetMirrorsPEPTarget(t *testing.T) {
	server := reflect.TypeOf(DecisionTarget{})
	client := reflect.TypeOf(pep.Target{})

	// DECLARED fields only, keyed by NAME. Not by index: declaration order is
	// invisible on the wire (JSON decoding is order-independent), so an
	// index-wise comparison reds on a reorder that changes nothing — a false
	// red on a correct change, which is how a guard gets deleted. Not promoted
	// either: reflect's FieldByName resolves through an embedded struct, so an
	// embedding would have satisfied a name-presence floor while `Target` itself
	// declared nothing.
	fields := func(rt reflect.Type) map[string]reflect.StructField {
		out := map[string]reflect.StructField{}
		for i := 0; i < rt.NumField(); i++ {
			f := rt.Field(i)
			if f.Anonymous {
				t.Errorf("%s embeds %s: this type is a wire DTO and must declare its fields, "+
					"or a mirror comparison silently compares different things", rt.Name(), f.Type)
				continue
			}
			out[f.Name] = f
		}
		return out
	}
	sf, cf := fields(server), fields(client)

	for name, s := range sf {
		c, ok := cf[name]
		if !ok {
			t.Errorf("DecisionTarget declares %s and pep.Target does not. A field on only one side is "+
				"invisible to every unit test on either side — pep.Target was missing Server until "+
				"#3717, so tool_server could not be SENT at all, whatever type the PEP put on the wire.", name)
			continue
		}
		if s.Type != c.Type {
			t.Errorf("field %s type drift: DecisionTarget %s vs pep.Target %s", name, s.Type, c.Type)
		}
		// The json tag is the contract. A matching Go field under a different
		// tag decodes to the zero value and looks exactly like an absent one.
		if s.Tag.Get("json") != c.Tag.Get("json") {
			t.Errorf("field %s json tag drift: DecisionTarget %q vs pep.Target %q",
				name, s.Tag.Get("json"), c.Tag.Get("json"))
		}
	}
	for name := range cf {
		if _, ok := sf[name]; !ok {
			t.Errorf("pep.Target declares %s and DecisionTarget does not: the PEP can send a field the "+
				"platform silently discards", name)
		}
	}

	// Anti-vacuity: two empty structs satisfy every loop above. The floor names
	// the three fields the tool-attribution gate reads, individually, because
	// those are the ones #3717 emptied — and it checks them against the DECLARED
	// set built above, not via FieldByName.
	for _, f := range []string{"Type", "Server", "Tool"} {
		if _, ok := cf[f]; !ok {
			t.Errorf("pep.Target declares no %s field — the PEP cannot express a tool target", f)
		}
		if _, ok := sf[f]; !ok {
			t.Errorf("DecisionTarget declares no %s field — the PDP cannot read a tool target", f)
		}
	}
}

// TestDecideTargetTypeVocabulary walks every Go source in the repo and fails on
// a `Type:` string literal, inside a decide-target composite literal, that is
// not one of pep.TargetTypes.
//
// WHICH LITERALS IT SEES. The type names are resolved PER FILE rather than
// hardcoded, because three of this guard's four blind spots in review were
// spellings of the same type it did not recognise:
//
//   - `DecisionTarget{…}` (the platform-side decoder, named in its own package);
//   - `<alias>.Target{…}` for whatever local name that file imports
//     platform/shared/pep under — the default `pep`, or any rename;
//   - bare `Target{…}` in the pep package ITSELF, which is where the type and
//     the vocabulary are declared and where the census was entirely absent
//     (platform/shared/pep/frozen_wire_test.go already writes one);
//   - elements with the type ELIDED inside `[]pep.Target{{…}}`,
//     `[]*pep.Target{{…}}` and `map[k]pep.Target{"x": {…}}`, which gofmt -s
//     produces and the first version of this walker skipped silently.
//
// WHAT IT STILL CANNOT SEE, stated rather than left to be rediscovered:
//
//   - a dot-import of the pep package (`import . "…/pep"`), which makes the
//     literal indistinguishable from any other bare `Target`;
//   - a NAMED TYPE or ALIAS over the target — `type TargetList []pep.Target`,
//     `type PT = pep.Target` — whose literals mention neither recognised name.
//     Both are silent: no vocabulary hit and no lexer divergence, because the
//     two instruments key on the same names. This is the widest remaining hole
//     and it is a shape the tree does not have today;
//   - a differently-named local mirror of the same wire shape;
//   - a Type whose value is not a string literal — a constant, a variable, a
//     call, or a concatenation. These are SKIPPED, not failed: the runtime-e2e
//     harnesses legitimately pass the stage through, and a guard that failed on
//     them would be deleted rather than fixed. TestTargetTypeAndStageConstantsAgree
//     is what covers the constant case, which is the one that actually happened.
//   - a value assembled field-by-field after construction.
//
// TestDecideToolAttributionAcceptsOnlyTheCanonicalSpelling covers the behaviour
// regardless of how the value was written; this one covers the way it is
// written, which is where a copy-paste introduces a fork.
func TestDecideTargetTypeVocabulary(t *testing.T) {
	repoRoot, err := findRepoRoot()
	if err != nil {
		t.Fatalf("locate repo root: %v", err)
	}

	// Case-insensitively, because the gate is strings.EqualFold: a census
	// stricter than the comparator it protects would red on `"TOOL"`, which the
	// platform accepts and attributes normally. The two must answer the same
	// question or the guard is about a different vocabulary than the code.
	allowed := map[string]bool{}
	for _, v := range pep.TargetTypes {
		allowed[strings.ToLower(v)] = true
	}

	var literalSites, totalSites int
	lexedByName := map[string]int{}

	walkErr := filepath.Walk(repoRoot, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			switch info.Name() {
			// testdata is excluded because Go itself excludes it from builds:
			// it is where deliberately-unparseable fixtures live, and a parse
			// failure there would red this test for a reason that has nothing
			// to do with the vocabulary.
			case ".git", "node_modules", "vendor", "target", ".venv", "dist", "build", "testdata":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, ".pb.go") {
			return nil
		}
		src, readErr := os.ReadFile(path)
		if readErr != nil {
			// NOT a skip. A guard that stops guarding when it cannot read its
			// input is indistinguishable from one that found nothing wrong.
			return readErr
		}

		fset := token.NewFileSet()
		file, parseErr := parser.ParseFile(fset, path, src, parser.ImportsOnly)
		if parseErr != nil {
			return parseErr
		}
		names := targetTypeNamesFor(file)
		file, parseErr = parser.ParseFile(fset, path, src, 0)
		if parseErr != nil {
			return parseErr
		}
		for name, n := range countTargetLiteralsByLexer(src, names) {
			lexedByName[name] += n
		}
		rel, _ := filepath.Rel(repoRoot, path)

		check := func(lit *ast.CompositeLit) {
			for _, elt := range lit.Elts {
				kv, ok := elt.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				key, ok := kv.Key.(*ast.Ident)
				if !ok || key.Name != "Type" {
					continue
				}
				bl, ok := kv.Value.(*ast.BasicLit)
				if !ok || bl.Kind != token.STRING {
					continue // not a string literal — see the doc comment
				}
				value, unquoteErr := strconv.Unquote(bl.Value)
				if unquoteErr != nil {
					t.Errorf("%s:%d: unparseable Type literal %s", rel, fset.Position(bl.Pos()).Line, bl.Value)
					continue
				}
				literalSites++
				if !allowed[strings.ToLower(value)] {
					t.Errorf("%s:%d: Target.Type = %q is not in the declared vocabulary %v.\n"+
						"A spelling the PDP's tool-attribution gate does not recognise is #3717 again: "+
						"the request is decided and enforced correctly and its audit row is written with "+
						"tool_server and tool_name empty, with nothing failing. Construct from a "+
						"pep.TargetType* constant; if this genuinely needs a new target shape, add it to "+
						"pep.TargetTypes and decide there what attribution it carries.",
						rel, fset.Position(bl.Pos()).Line, value, pep.TargetTypes)
				}
			}
		}

		ast.Inspect(file, func(n ast.Node) bool {
			lit, ok := n.(*ast.CompositeLit)
			if !ok {
				return true
			}
			if isTargetLiteral(lit.Type, names) {
				totalSites++
				check(lit)
				return true
			}
			// An ELIDED element: `[]pep.Target{{Type: …}}` and
			// `map[k]pep.Target{"x": {Type: …}}` give the inner literal a nil
			// Type, so it is only recognisable from its container.
			if elem, ok := containerElemType(lit.Type); ok && isTargetLiteral(elem, names) {
				// ONE site per container, matching what the lexer counts: the
				// two instruments must measure the SAME unit or their
				// comparison is noise in both directions. Counting elements
				// made an empty `[]pep.Target{}` a false RED (lexer 1, walker
				// 0) and a three-element one two sites of SLACK, under which a
				// literal the walker could not see was absorbed silently — the
				// exact failure the floor exists to prevent.
				totalSites++
				// RECURSIVE: the elision nests as deep as the container does.
				// `[][]pep.Target{{{Type: …}}}` has TWO nil-typed levels above
				// the struct literal, and descending one level found a literal
				// whose elements are themselves literals, checked nothing, and
				// reported nothing — the container was counted by both
				// instruments, so there was no divergence to notice either.
				checkElidedDescendants(lit, check)
			}
			return true
		})
		return nil
	})
	if walkErr != nil {
		t.Fatalf("walking %s: %v", repoRoot, walkErr)
	}

	// --- Anti-vacuity, from a SECOND and independent instrument. -------------
	//
	// The failure mode of a source scanner is finding nothing and reporting
	// success, and a floor derived from the walker's own output cannot see
	// that. So the floor comes from a different instrument on the same bytes: a
	// LEXER pass counting `<targetType> {` token sequences. If the parser-side
	// walker stops matching the literal shape, the counts diverge and this reds
	// instead of quietly guarding nothing.
	//
	// go/scanner rather than a byte count on purpose: a byte count is satisfied
	// by this test's own doc comment naming the very string it probes for, and
	// the first version of this floor duly reported two phantom sites from the
	// prose above it. The lexer does not emit comment tokens.
	//
	// The lexer deliberately does NOT count a `{` that opens a function BODY
	// (`func mk() pep.Target {`), which is not a literal and which review
	// showed would have false-RED this test on the obvious follow-up to this
	// very change — a constructor added to stop free construction.
	lexedSites := 0
	for name, n := range lexedByName {
		lexedSites += n
		_ = name
	}
	// EVERY spelling this guard claims to cover gets a zero-check, not just the
	// two obvious ones. targetTypeNamesFor is SHARED by the walker and by this
	// floor, so a defect in it disarms both instruments at once — R3 proved that
	// by breaking its package check ("pep" -> a name that never matches) and
	// watching the whole suite stay green while one of the four documented
	// spellings stopped being covered. Each of these has at least one real site
	// in the tree, so a zero is a broken resolver, not a clean tree.
	for _, name := range []string{"DecisionTarget", "pep.Target", "Target"} {
		// A PATTERN THAT MATCHES NOTHING ANYWHERE IS A BROKEN PATTERN, not a
		// clean tree: both of these names have production construction sites,
		// so a zero here means the matcher cannot fire. An earlier version of
		// this floor had exactly that defect — its window compared ".Target"
		// against "pep.Target", so half the probe was dead, the total came out
		// six short of the parser's, and the `<` check below still passed.
		if lexedByName[name] == 0 {
			t.Errorf("the lexer floor found ZERO `%s{` sequences in the entire tree. "+
				"That is a broken probe, not a clean tree, and a broken probe cannot "+
				"witness a broken walker.", name)
		}
	}
	if totalSites < lexedSites {
		t.Errorf("the AST walker matched %d target composite literals but the lexer found %d "+
			"target-type-followed-by-brace token sequences (%v). The walker has stopped seeing "+
			"sites the lexer sees, so its silence above is not evidence. Teach the WALKER the "+
			"construct it is missing rather than deleting this check.", totalSites, lexedSites, lexedByName)
	}
	if literalSites == 0 {
		t.Errorf("no Target.Type string literal was found anywhere in %s. Either every construction site "+
			"now uses a constant (in which case narrow this to a constant-reference check rather than "+
			"deleting it) or the walker is broken.", repoRoot)
	}
	t.Logf("Target.Type vocabulary: %d composite literals across the tree (lexer floor %d, %v), "+
		"%d with a string-literal Type, all within %v",
		totalSites, lexedSites, lexedByName, literalSites, pep.TargetTypes)
}

// checkElidedDescendants applies check to every type-elided composite literal
// beneath lit, at any nesting depth.
//
// A target struct declares no composite-typed field, so a nil-typed literal
// under a target-typed container is either another container level or a target;
// visiting both is safe, and check ignores anything with no `Type:` key.
func checkElidedDescendants(lit *ast.CompositeLit, check func(*ast.CompositeLit)) {
	for _, elt := range lit.Elts {
		inner, ok := elt.(*ast.CompositeLit)
		if !ok {
			kv, isKV := elt.(*ast.KeyValueExpr)
			if !isKV {
				continue
			}
			inner, ok = kv.Value.(*ast.CompositeLit)
		}
		if !ok || inner == nil || inner.Type != nil {
			continue
		}
		check(inner)
		checkElidedDescendants(inner, check)
	}
}

// pepImportPath is the package whose Target type is the PEP-side decide target.
const pepImportPath = "axonflow/platform/shared/pep"

// targetTypeNamesFor resolves the composite-literal type expressions that name
// a decide target IN THIS FILE: the platform-side decoder, the pep client type
// under whatever local name this file imports it as, and — inside the pep
// package itself — the bare type name.
func targetTypeNamesFor(file *ast.File) []string {
	names := []string{"DecisionTarget"}
	if file.Name != nil && file.Name.Name == "pep" {
		names = append(names, "Target")
	}
	for _, imp := range file.Imports {
		path, err := strconv.Unquote(imp.Path.Value)
		if err != nil || path != pepImportPath {
			continue
		}
		local := "pep"
		if imp.Name != nil {
			// A dot-import makes the literal indistinguishable from any other
			// bare `Target`; it is out of this guard's reach and documented as
			// such rather than matched wrongly.
			if imp.Name.Name == "." || imp.Name.Name == "_" {
				continue
			}
			local = imp.Name.Name
		}
		names = append(names, local+".Target")
	}
	return names
}

// containerElemType returns the element type of a slice/array/map composite
// literal type, so elements written with the type elided can be recognised.
// It unwraps a pointer element type as well: `[]*pep.Target{{…}}` elides the
// element type exactly as the value form does, and a `*ast.StarExpr` that
// nothing unwrapped was a hole the floor could not report while it still had
// slack.
func containerElemType(expr ast.Expr) (ast.Expr, bool) {
	elem := expr
	nested := false
	// RECURSIVE, because one level was not enough: `[][]pep.Target` and
	// `map[string][]pep.Target` reached the lexer floor and not the vocabulary
	// check, which is the half of a divergence that reports nothing.
	for {
		switch tv := elem.(type) {
		case *ast.ArrayType:
			elem, nested = tv.Elt, true
			continue
		case *ast.MapType:
			elem, nested = tv.Value, true
			continue
		case *ast.StarExpr:
			elem = tv.X
			continue
		}
		break
	}
	return elem, nested
}

// countTargetLiteralsByLexer counts `<targetType>{` token sequences in src, per
// target-type name.
//
// It is the second instrument behind this test's anti-vacuity floor, and it is
// deliberately implemented with go/scanner rather than go/ast so that a defect
// in the parser-side walker cannot also silence the floor.
func countTargetLiteralsByLexer(src []byte, names []string) map[string]int {
	var s scanner.Scanner
	fset := token.NewFileSet()
	file := fset.AddFile("", fset.Base(), len(src))
	// A nil error handler with mode 0: comments are not emitted, and a lex
	// error is tolerated here (the parser pass reports it as a hard failure).
	s.Init(file, src, nil, 0)

	counts := map[string]int{}
	window := maxTargetNameWidth(names) + 1 // +1 to see the token BEFORE the name
	var rendered []string
	for {
		_, tok, lit := s.Scan()
		switch {
		case tok == token.EOF:
			return counts
		case tok == token.IDENT:
			rendered = append(rendered, lit)
		case tok == token.PERIOD:
			rendered = append(rendered, ".")
		case tok == token.RPAREN:
			// Kept in the window ONLY as a marker: `) <Type> {` is a function
			// result followed by its body, not a composite literal.
			rendered = append(rendered, ")")
		case tok == token.LBRACE:
			if name, ok := matchTargetName(rendered, names); ok {
				counts[name]++
			}
			rendered = nil
		default:
			rendered = nil
		}
		if len(rendered) > window {
			rendered = rendered[len(rendered)-window:]
		}
	}
}

// maxTargetNameWidth is the token width of the longest name in names.
func maxTargetNameWidth(names []string) int {
	max := 1
	for _, n := range names {
		if w := 2*strings.Count(n, ".") + 1; w > max {
			max = w
		}
	}
	return max
}

// matchTargetName reports which of names the trailing tokens spell, if any.
//
// The window holds each PERIOD as its own element, so a dotted name of n
// segments occupies 2n-1 tokens and the comparison is against the tokens joined
// with NO separator. Getting that wrong is not a near miss: an earlier version
// took the last n elements and joined them with ".", so `pep . Target` compared
// ".Target" against "pep.Target" and that half of the floor could never match
// anything. It counted 40 where the parser saw 46, the floor held with six
// sites of slack, and every test still passed — an assertion that cannot fire
// and one that passes print the same thing.
//
// TWO REJECTIONS, both of which review showed produce false REDS:
//
//   - a `)` immediately before the name is a function RESULT type, and the `{`
//     that follows opens the body, not a literal;
//   - a `.` immediately before an unqualified name means the name is the tail
//     of some OTHER package's selector (`otherpkg.DecisionTarget`), which the
//     AST walker correctly does not match.
func matchTargetName(rendered, names []string) (string, bool) {
	for _, n := range names {
		width := 2*strings.Count(n, ".") + 1
		if width > len(rendered) {
			continue
		}
		at := len(rendered) - width
		if strings.Join(rendered[at:], "") != n {
			continue
		}
		if at > 0 && (rendered[at-1] == ")" || rendered[at-1] == ".") {
			continue
		}
		return n, true
	}
	return "", false
}

// isTargetLiteral reports whether a composite-literal type expression names one
// of the decide-target types, matching both a selector (`pep.Target`) and a
// bare identifier (`DecisionTarget`, or `Target` inside the pep package).
func isTargetLiteral(expr ast.Expr, names []string) bool {
	var rendered string
	switch tv := expr.(type) {
	case *ast.SelectorExpr:
		pkg, ok := tv.X.(*ast.Ident)
		if !ok {
			return false
		}
		rendered = pkg.Name + "." + tv.Sel.Name
	case *ast.Ident:
		rendered = tv.Name
	default:
		return false
	}
	for _, n := range names {
		if rendered == n {
			return true
		}
	}
	return false
}

// TestTargetTypeAndStageConstantsAgree pins the three parallel declarations of
// the same strings against each other.
//
// R3 found a SURVIVOR that every other guard in this change misses. Three sets
// declare "llm"/"tool"/"agent" with nothing linking them:
//
//   - pep.TargetType{LLM,Tool,Agent}          — the target-type vocabulary
//   - agent.DecisionStage{LLM,Tool,Agent}     — the stage vocabulary
//   - gatewayadapters.Stage{LLM,Tool,Agent}   — the adapters' stage vocabulary
//
// and mapTarget (authzen_adapter.go) assigns a STAGE constant DIRECTLY into
// Target.Type — `DecisionTarget{Type: stage}` — for the llm and agent stages.
//
// BE PRECISE ABOUT WHICH ARM, because the first version of this comment was
// not. It claimed that changing DecisionStageTool to "tool_v2" reproduces
// #3717 on the AuthZEN plane; mutation-tested, it does not, because this same
// change moved mapTarget's TOOL arm onto pep.TargetTypeTool. What remains, and
// what this test actually guards, is the llm/agent arms plus isValidStage:
// three declarations of one vocabulary with nothing but this comparison
// linking them, feeding a field whose reader is a string comparison. The
// source census cannot see a divergence there (the value is not a literal at
// the construction site) and the behavioural pin cannot see it (it builds its
// own targets). Only comparing the constants can.
//
// The gateway-adapters set is compared too, because that package's Stage values
// are what its seams put in DecideRequest.Stage, and isValidStage on this side
// admits exactly the same three.
func TestTargetTypeAndStageConstantsAgree(t *testing.T) {
	for _, c := range []struct {
		axis                   string
		targetType, agentStage string
		adapterStage           string
	}{
		{"llm", pep.TargetTypeLLM, DecisionStageLLM, gatewayadapters.StageLLM},
		{"tool", pep.TargetTypeTool, DecisionStageTool, gatewayadapters.StageTool},
		{"agent", pep.TargetTypeAgent, DecisionStageAgent, gatewayadapters.StageAgent},
	} {
		if c.targetType != c.agentStage {
			t.Errorf("%s axis: pep.TargetType=%q but agent.DecisionStage=%q. mapTarget assigns a stage "+
				"constant into Target.Type, so a divergence here makes the AuthZEN plane emit a target "+
				"type the attribution gate does not recognise — #3717, at a production site.",
				c.axis, c.targetType, c.agentStage)
		}
		if c.targetType != c.adapterStage {
			t.Errorf("%s axis: pep.TargetType=%q but gatewayadapters.Stage=%q. The adapters send that "+
				"value as DecideRequest.Stage, which isValidStage on this side must admit.",
				c.axis, c.targetType, c.adapterStage)
		}
	}
}
