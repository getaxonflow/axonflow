// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package pdp

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// THE CENSUS OF EVERY READER OF AN ADVERTISED DIGEST (#3700).
//
// Bundle.Digest is NOT inside view(), so it is not covered by the bundle
// signature: a bundle whose content is genuine and whose advertised digest is
// wrong carries a perfectly valid signature. That is safe if and only if every
// path that TRUSTS the digest recomputes it from content first, and before
// #3700 exactly one place did - TrustStore.Verify - while four consumers read
// the advertised field and were correct only because they happened to sit
// downstream of it. A property held by an ordering is a property the next
// editor can move.
//
// So the rule is now: read .Digest only where the value is MINTED, where it is
// RECOMPUTED, or in DIAGNOSTIC text that carries no authority. Everywhere else
// calls VerifiedDigest, which recomputes and refuses a mismatch with the same
// error Verify uses. This census pins the SET of readers, so a new one cannot
// appear without a human deciding which of those three it is - or discovering
// that it is a fifth trusting path and calling VerifiedDigest instead.
//
// THE SET IS PINNED WITH ITS OCCURRENCE COUNT, not just its keys. A key is
// (file, function, receiver expression), so without the count a SECOND read
// of the same receiver inside an already-declared function would arrive free -
// and "b.Digest appears once in Verify" is a different fact from "b.Digest
// appears in Verify". R3 round 1 found that hole.
//
// WHAT THIS TEST DOES AND DOES NOT PROVE. It parses the module's non-test Go
// files with go/ast and reports every `<expr>.Digest` selector as
// (file, function, receiver expression). It asserts that set equals the
// declared set below, and for the classes where a structural property exists
// it asserts that too. It does NOT prove the receiver's TYPE: doing that needs
// full type resolution, and axonflow/platform/decision keeps a deliberately
// minimal dependency set that golang.org/x/tools/go/packages would widen. The
// class of each row is therefore a human judgement recorded with its reason -
// and the protection that matters is the one this test does give: a reader
// that appears, moves, or changes its receiver is UNDECLARED and fails here,
// where the reason has to be written down.
//
// The positive control #3700 asks for is exactly that: reverting any of the
// four fixed sites to read .Digest makes it an undeclared reader and reds this
// test. TestRevertingAFixedSiteWouldBeUndeclared documents the four by name.

// digestReaderClass is why a site is allowed to read the advertised value.
type digestReaderClass string

const (
	// classMints: the value is COMPUTED here from content. Reading it back is
	// reading what this code just derived.
	classMints digestReaderClass = "mints"
	// classRecomputes: this site recomputes from content and compares. It is
	// the check itself.
	classRecomputes digestReaderClass = "recomputes"
	// classDiagnostic: the value appears only in an error or log message and
	// carries no authority. Asserted structurally: the occurrence must sit
	// inside a formatting call.
	classDiagnostic digestReaderClass = "diagnostic"
	// classNotABundle: the selector is a .Digest on something that is not a
	// pdp.Bundle at all - an Activation, a Pin, an artifact wire struct, an
	// Environment, or the contract.Digest package function. The type is not
	// proved here; see the note above.
	classNotABundle digestReaderClass = "not-a-bundle"
)

type digestReader struct {
	file     string
	function string
	receiver string
	class    digestReaderClass
	why      string
	// occurrences is how many times this exact reader appears. Pinned so an
	// ADDED read inside an already-declared function is a failure rather than
	// a free ride; 0 means "one", so the common case stays readable.
	occurrences int
	// strippedFromMirror marks a row whose file the community sync deletes.
	// Only these rows may be absent, and they may be absent ONLY there.
	//
	// The first version of this excused any row whose file was missing and
	// backstopped it with a count floor. R3 round 3 showed that is unbounded:
	// `mv ee` passed on the enterprise tree, a genuine deletion inside the
	// decision module was excused up to the floor, and a row naming a file
	// that does not exist was accepted - PRE-ARMING an exemption, so creating
	// that file later with real bundle reads stayed green. Declaring which
	// rows may vanish pins the SET rather than a count, and turns each of
	// those three into a failure.
	strippedFromMirror bool
}

// declaredDigestReaders is the whole of what may read .Digest in this module.
//
// A row is (file, function, receiver expression). Adding one is a decision
// that needs a reason; removing the last occurrence of one fails the
// stale-row check below, because a declaration nothing exercises excuses
// whatever it matches next.
func declaredDigestReaders() []digestReader {
	return []digestReader{
		// --- platform/decision: where Bundle lives -------------------------
		{"platform/decision/authoring/gauntlet.go", "gateRoundTrip", "rebuilt", classMints,
			"rebuilt comes from pdp.BuildBundle in this same function, which computes the digest from the rendered-back document", 2, false},
		{"platform/decision/authoring/gauntlet.go", "gateRoundTrip", "bundle", classRecomputes,
			"the round-trip gate compares the freshly built rebuilt.Digest against the bundle being published; a bundle whose advertised digest does not describe its content fails HERE, so this comparison is itself a recomputation", 2, false},
		{"platform/decision/authoring/publish.go", "LoadArtifact", "w", classNotABundle,
			"w is the artifact wire struct; w.Digest is the ARTIFACT digest, which Artifact.verify recomputes over the artifact view", 0, false},
		{"platform/decision/authoring/store.go", "Rollback", "h", classNotABundle,
			"h is an Activation record; h.Digest is the artifact digest that activation named, and Rollback re-verifies the artifact through a.verify before it acts", 0, false},
		{"platform/decision/cmd/decision-replay/main.go", "run", "env", classNotABundle,
			"env.Digest() is the ENVIRONMENT digest, a method over the environment manifest", 0, false},
		{"platform/decision/cmd/decision-replay/main.go", "run", "p", classNotABundle,
			"p is a replay.Pin whose Digest was already RECOMPUTED by Environment.BundleDigests; this only prints it", 0, false},
		{"platform/decision/conformance/scenario.go", "mustDigest", "contract", classNotABundle,
			"contract.Digest is a package function, not a field read", 0, false},
		{"platform/decision/legacycompile/compile.go", "digestRow", "contract", classNotABundle,
			"contract.Digest is a package function, not a field read", 0, false},
		{"platform/decision/pdp/bundle.go", "BuildBundle", "b", classMints,
			"BuildBundle computes ExactDigest(b.view()) and assigns it; this IS the mint", 0, false},
		{"platform/decision/pdp/bundle.go", "Verify", "b", classRecomputes,
			"TrustStore.Verify recomputes ExactDigest(b.view()) and refuses a mismatch; the original, and still the activation-path check", 2, false},
		{"platform/decision/pdp/bundle.go", "VerifiedDigest", "b", classRecomputes,
			"VerifiedDigest compares the advertised value against the recomputation and refuses a mismatch", 2, false},
		{"platform/decision/pdp/bundle.go", "VerifiedDigest", "b (ContentDigest)", classRecomputes,
			"the recomputation itself, through ContentDigest; censused because ContentDigest answers without checking the label, so a consumer of it is a trusting path that produces no .Digest selector at all", 0, false},
		{"platform/decision/replay/environment.go", "BundleDigests", "r.Bundle", classRecomputes,
			"the ADVERTISED value, read only on the refusal path after VerifiedDigest() has already refused it, so the caller can be told which of the two digests is the lie; the function's pinning path is VerifiedDigest and nothing here trusts this value", 0, false},
		{"platform/decision/replay/environment.go", "BundleDigests", "r.Bundle (ContentDigest)", classRecomputes,
			"the recomputation, on that same refusal path: an unpinnable root is reported with both digests because the record's pin is usually the CONTENT digest, and without it the refusal says the environment holds no bundle for a root it demonstrably holds", 0, false},
		{"platform/decision/pdp/engine.go", "NewEngine", "b", classDiagnostic,
			"names the bundle in the error for a manifest entry with no source document; the engine has already verified this bundle", 0, false},
		{"platform/decision/pdp/runtime.go", "NewRuntime", "b", classDiagnostic,
			"names the bundle in a strict-compilation failure message", 0, false},
		{"platform/decision/replay/record.go", "CheckPins", "env", classNotABundle,
			"env.Digest() is the ENVIRONMENT digest, which hashes the whole Environment INCLUDING its bundles - see the note on that method for why it is a superset of the per-bundle pin check", 0, false},
		{"platform/decision/replay/record.go", "CheckPins", "p", classNotABundle,
			"p is a replay.Pin; the environment side of the comparison comes from BundleDigests, which recomputes, and the record side is the pin being checked. SIX, not four: two of them are the unverifiable-bundle note, which compares the record's pin against the CONTENT digest so the refusal only claims the artifact is probably the right one when that is true", 6, false},
		{"platform/decision/replay/record.go", "Validate", "p", classNotABundle,
			"p is a replay.Pin carried by the record; Validate checks it is non-empty", 0, false},

		// --- the rest of platform/, and ee/ ---------------------------------
		// R3 round 1 planted a bundle read in platform/shared/planeshadow and
		// the module-only walk stayed green, so the census now covers both
		// trees. Everything below is a .Digest on something that is not a
		// pdp.Bundle; the value of the rows is that a bundle read appearing
		// here in future is UNDECLARED.
		{"platform/shared/requirements/approval/challenge.go", "IssueChallenge", "req", classNotABundle,
			"req is an approval challenge request; its Digest binds the challenge to the decision, not to a policy bundle", 0, true},
		{"platform/shared/requirements/reservation/memory.go", "Reserve", "req.Key", classNotABundle,
			"a reservation key's digest, which identifies the reserved operation", 0, true},
		{"platform/shared/requirements/reservation/postgres.go", "Reserve", "req.Key", classNotABundle,
			"a reservation key's digest, which identifies the reserved operation", 0, true},
		{"ee/platform/customer-portal/api/typed_authoring.go", "HandlePublish", "art", classNotABundle,
			"art is an authoring.Artifact; art.Digest() is the ARTIFACT digest, recomputed by Artifact.verify", 4, true},
		{"ee/platform/customer-portal/api/typed_authoring.go", "HandleArtifacts", "art", classNotABundle,
			"the artifact digest, as above", 3, true},
		{"ee/platform/customer-portal/api/typed_authoring.go", "HandleArtifacts", "entry", classNotABundle,
			"a stored history entry's artifact digest", 0, true},
		{"ee/platform/customer-portal/api/typed_authoring.go", "HandleActive", "art", classNotABundle,
			"the artifact digest, as above", 2, true},
		{"ee/platform/customer-portal/api/typed_authoring.go", "handleActivation", "req", classNotABundle,
			"the activation REQUEST's digest field, which names the artifact an operator asked to activate", 0, true},
	}
}

type digestOccurrence struct {
	file     string
	function string
	receiver string
	line     int
	// inFormatCall reports whether the occurrence sits inside a formatting
	// call (fmt.Errorf, fmt.Sprintf, say, ...), which is what a diagnostic
	// reader must look like.
	inFormatCall bool
	// funcBody is the enclosing function's source, used to assert that a
	// recomputing or minting site really does recompute or mint.
	funcBody string
}

func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("no ancestor of %s holds go.mod", dir)
		}
		dir = parent
	}
}

// censusRoots are the trees this census walks: BOTH Go modules under
// platform/ and the ee tree, not just the module that defines Bundle.
//
// R3 round 1 showed why the narrower walk was not enough. pdp.Bundle,
// shadow.World.Bundles and shadow.World.BundleDigest are all exported with no
// unexported field to block a struct literal, so a consumer OUTSIDE this
// module can reach past the recomputed value into `world.Bundles[0].Digest`
// and feed Snapshot.PolicyBundle - the ADR-065 proof surface - without this
// test noticing. The reviewer planted exactly that in
// platform/shared/planeshadow and the census stayed green.
//
// Widening costs almost nothing, which is the argument for doing it rather
// than writing a caveat: outside platform/decision the whole tree holds three
// .Digest sites and ee holds five, none of them a bundle.
func censusRoots(t *testing.T) []string {
	t.Helper()
	dir := moduleRoot(t) // .../platform/decision
	platform := filepath.Dir(dir)
	repo := filepath.Dir(platform)
	roots := []string{platform}
	if ee := filepath.Join(repo, "ee"); dirExists(ee) {
		roots = append(roots, ee)
	}
	return roots
}

func dirExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.IsDir()
}

func collectDigestOccurrences(t *testing.T) []digestOccurrence {
	t.Helper()
	var out []digestOccurrence
	for _, root := range censusRoots(t) {
		out = append(out, collectUnder(t, root, filepath.Dir(root))...)
	}
	return out
}

func collectUnder(t *testing.T, root, relTo string) []digestOccurrence {
	t.Helper()
	fset := token.NewFileSet()
	var out []digestOccurrence
	err := filepath.Walk(root, func(p string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if fi.IsDir() {
			if name := fi.Name(); p != root && (name == "testdata" || name == "schema" || strings.HasPrefix(name, ".")) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(fset, p, nil, 0)
		if err != nil {
			return fmt.Errorf("parsing %s: %w", p, err)
		}
		src, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(relTo, p)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		for _, d := range f.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			body := string(src[fset.Position(fn.Pos()).Offset:fset.Position(fn.End()).Offset])
			// Track formatting calls so a diagnostic reader can be recognised
			// structurally rather than taken on trust.
			var formatCalls []*ast.CallExpr
			ast.Inspect(fn, func(n ast.Node) bool {
				if call, ok := n.(*ast.CallExpr); ok && isFormatCall(call) {
					formatCalls = append(formatCalls, call)
				}
				return true
			})
			ast.Inspect(fn, func(n ast.Node) bool {
				sel, ok := n.(*ast.SelectorExpr)
				// ContentDigest is censused TOO. It answers "what does this
				// hash to" without checking the advertised label, so a
				// consumer that calls it and then trusts the value is a
				// trusting path this census could not otherwise see - it
				// produces no `.Digest` selector at all. It is a method this
				// very PR introduces, which is the point: the census has to
				// cover the escape hatch it created.
				if !ok || (sel.Sel.Name != "Digest" && sel.Sel.Name != "ContentDigest") {
					return true
				}
				inFormat := false
				for _, call := range formatCalls {
					if call.Pos() <= sel.Pos() && sel.End() <= call.End() {
						inFormat = true
						break
					}
				}
				name := exprString(sel.X)
				if sel.Sel.Name == "ContentDigest" {
					name += " (ContentDigest)"
				}
				out = append(out, digestOccurrence{
					file:         rel,
					function:     fn.Name.Name,
					receiver:     name,
					line:         fset.Position(sel.Pos()).Line,
					inFormatCall: inFormat,
					funcBody:     body,
				})
				return true
			})
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking %s: %v", root, err)
	}
	return out
}

func isFormatCall(call *ast.CallExpr) bool {
	switch fn := call.Fun.(type) {
	case *ast.Ident:
		return fn.Name == "say"
	case *ast.SelectorExpr:
		pkg, ok := fn.X.(*ast.Ident)
		if !ok {
			return false
		}
		if pkg.Name != "fmt" {
			return false
		}
		switch fn.Sel.Name {
		case "Errorf", "Sprintf", "Fprintf", "Printf":
			return true
		}
	}
	return false
}

func exprString(e ast.Expr) string {
	var sb strings.Builder
	var write func(ast.Expr)
	write = func(e ast.Expr) {
		switch v := e.(type) {
		case *ast.Ident:
			sb.WriteString(v.Name)
		case *ast.SelectorExpr:
			write(v.X)
			sb.WriteString("." + v.Sel.Name)
		case *ast.IndexExpr:
			write(v.X)
			sb.WriteString("[")
			write(v.Index)
			sb.WriteString("]")
		case *ast.CallExpr:
			write(v.Fun)
			sb.WriteString("()")
		case *ast.BasicLit:
			sb.WriteString(v.Value)
		case *ast.StarExpr:
			sb.WriteString("*")
			write(v.X)
		case *ast.ParenExpr:
			write(v.X)
		default:
			sb.WriteString("?")
		}
	}
	write(e)
	return sb.String()
}

func fileExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && !fi.IsDir()
}

// repoRootOf is the directory the census's relative paths are anchored to.
func repoRootOf(t *testing.T) string {
	t.Helper()
	return filepath.Dir(filepath.Dir(moduleRoot(t)))
}

func sortedCopy(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}

func uniqueStrings(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range in {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}

func readerKey(file, function, receiver string) string {
	return file + "\t" + function + "\t" + receiver
}

func TestEveryBundleDigestReaderIsDeclared(t *testing.T) {
	occurrences := collectDigestOccurrences(t)
	if len(occurrences) == 0 {
		t.Fatal("the walk found no .Digest reader at all; pdp/bundle.go has several, so this census is reading nothing")
	}

	declared := map[string]digestReader{}
	for _, d := range declaredDigestReaders() {
		key := readerKey(d.file, d.function, d.receiver)
		if _, dup := declared[key]; dup {
			t.Fatalf("declaredDigestReaders has two rows for %s", key)
		}
		if d.why == "" {
			t.Fatalf("row %s carries no reason; an undeclared reason is an exemption nobody can review", key)
		}
		declared[key] = d
	}

	seen := map[string]int{}
	for _, occ := range occurrences {
		key := readerKey(occ.file, occ.function, occ.receiver)
		seen[key]++
		d, ok := declared[key]
		if !ok {
			t.Errorf("UNDECLARED reader of an advertised digest: %s:%d reads %s.Digest inside %s.\n"+
				"Bundle.Digest is outside the signed view, so a bundle whose content does not hash to it still verifies.\n"+
				"If this reads a pdp.Bundle, call VerifiedDigest() instead - it recomputes and refuses a mismatch.\n"+
				"If it does not, or if it mints/recomputes/only prints, add a row to declaredDigestReaders with the reason.",
				occ.file, occ.line, occ.receiver, occ.function)
			continue
		}
		switch d.class {
		case classDiagnostic:
			if !occ.inFormatCall {
				t.Errorf("%s:%d is declared %q but does not sit inside a formatting call; a value outside a message carries authority, and this one is not recomputed",
					occ.file, occ.line, classDiagnostic)
			}
		case classRecomputes:
			if !strings.Contains(occ.funcBody, "ExactDigest(") && !strings.Contains(occ.funcBody, ".ContentDigest()") && !strings.Contains(occ.funcBody, "BuildBundle(") {
				t.Errorf("%s:%d is declared %q but %s contains no recomputation (ExactDigest / ContentDigest / BuildBundle); the comparison it claims to make is against nothing",
					occ.file, occ.line, classRecomputes, occ.function)
			}
		case classMints:
			if !strings.Contains(occ.funcBody, "ExactDigest(") && !strings.Contains(occ.funcBody, "BuildBundle(") {
				t.Errorf("%s:%d is declared %q but %s never computes a digest; it cannot be minting one",
					occ.file, occ.line, classMints, occ.function)
			}
		}
	}

	for key, d := range declared {
		// The count is dropped only where an added read is SOMEONE ELSE'S
		// business. Keying this on class alone was wrong and R3 round 3
		// proved it: the nine not-a-bundle rows INSIDE platform/decision lost
		// their count too, and a planted `leaked = p.Digest` in
		// cmd/decision-replay inherited the declared replay.Pin row and passed.
		//
		// So the rule is by TREE, not by class. Inside this module every row
		// keeps its count, because an added read here is exactly what this
		// census is for. Outside it, a not-a-bundle row is a benign extra log
		// line in a package this test does not own, and reddening the decision
		// suite for it trains people to edit the table rather than read it.
		if d.class == classNotABundle && !strings.HasPrefix(d.file, "platform/decision/") {
			continue
		}
		want := d.occurrences
		if want == 0 {
			want = 1
		}
		if got := seen[key]; got > 0 && got != want {
			t.Errorf("%s appears %d time(s), the declaration pins %d.\n"+
				"A second read of the same receiver in an already-declared function is a NEW site: say why, and give the row its occurrence count.",
				strings.ReplaceAll(key, "\t", " :: "), got, want)
		}
	}

	// A DECLARED ROW WHOSE FILE IS NOT IN THIS TREE IS INAPPLICABLE, NOT STALE.
	//
	// This module ships to the community mirror and its tests run there, where
	// the sync deletes ee/ wholesale and the build-tag strip removes every
	// //go:build enterprise file. Eight of the rows below name files that do
	// not exist on that tree, so a stale-row check that could not tell
	// "deleted by the sync" from "deleted by an author" failed the census on
	// the mirror's own inputs - the exact shape #3807 is a standing order
	// about, and one an enterprise board can never show because the community
	// job is gated on the public repository.
	//
	// Absence is therefore reported and counted, and the ANTI-VACUITY floor
	// moves to the rows that must exist everywhere: the decision module is
	// mirrored in full, so its rows are present on both trees and a census
	// that lost them is a census of nothing.
	absent := map[string]bool{}
	var missing, unexpected []string
	for key, d := range declared {
		if fileExists(filepath.Join(repoRootOf(t), filepath.FromSlash(d.file))) {
			continue
		}
		absent[key] = true
		if !d.strippedFromMirror {
			// The file is gone and no row said it could be. Either it was
			// deleted and this row is stale, or the path was never right and
			// the row has been silently exempting nothing.
			missing = append(missing, d.file)
		}
	}
	for _, name := range uniqueStrings(sortedCopy(missing)) {
		t.Errorf("declared row names %s, which is not in this tree and is NOT marked as stripped from the community mirror.\n"+
			"A row whose file does not exist exempts nothing and pre-arms an exemption for whatever is created at that path later; delete the row, fix the path, or mark it strippedFromMirror if the sync really removes it.", name)
	}
	// The mirror is the only tree where a stripped row may be absent.
	//
	// THE MARKER IS THE SYNC WORKFLOW, NOT ee/. Deriving "this is the mirror"
	// from the absence of ee/ is circular: the mutation that hides a real
	// deletion - moving ee/ away - is exactly the one that would make the
	// census believe it is on the mirror and excuse itself. R3 round 3 proved
	// that by doing it. The repository's own edition derivation, used by
	// tests/regression-test-required/platform_ee_twin_census_test.sh, keys on
	// sync-community-repo.yml, which exists only on the enterprise tree
	// because the sync excludes itself.
	repoRoot := repoRootOf(t)
	onMirror := !fileExists(filepath.Join(repoRoot, ".github", "workflows", "sync-community-repo.yml"))
	// And the marker itself is checked, for the same reason that guard checks
	// it: a tree that derives as the mirror while still holding ee/platform
	// has a broken marker, and this census would skip precisely where it was
	// written to run.
	if onMirror && dirExists(filepath.Join(repoRoot, "ee", "platform")) {
		t.Fatalf("this tree derives as the community mirror (no sync-community-repo.yml) but ee/platform exists; the marker has moved and this census would excuse absent rows on an enterprise checkout")
	}
	if !onMirror {
		for key, d := range declared {
			if absent[key] && d.strippedFromMirror {
				unexpected = append(unexpected, d.file)
			}
		}
		for _, name := range uniqueStrings(sortedCopy(unexpected)) {
			t.Errorf("declared row names %s, which is marked as stripped from the community mirror but is missing from a tree that still has ee/; on an enterprise checkout every declared file must exist", name)
		}
	}
	if len(absent) > 0 {
		var names []string
		for key := range absent {
			names = append(names, strings.SplitN(key, "\t", 2)[0])
		}
		t.Logf("%d declared row(s) name files the community sync strips and are not checked here: %s",
			len(absent), strings.Join(uniqueStrings(sortedCopy(names)), ", "))
	}

	var stale []string
	for key, d := range declared {
		if absent[key] {
			continue
		}
		if seen[key] == 0 {
			stale = append(stale, fmt.Sprintf("%s (declared %q: %s)", strings.ReplaceAll(key, "\t", " :: "), d.class, d.why))
		}
	}
	sort.Strings(stale)
	for _, s := range stale {
		t.Errorf("STALE declaration, no occurrence exercises it: %s\n"+
			"A declaration nothing hits excuses whatever it matches next; delete the row.", s)
	}

	t.Logf("%d declared reader site(s), %d occurrence(s) across the module", len(declared), len(occurrences))
}

// TestRevertingAFixedSiteWouldBeUndeclared names the four consumers #3700
// moved off the advertised field, so the census's positive control is written
// down rather than remembered.
//
// Each of these called `<bundle>.Digest` before and calls VerifiedDigest now.
// Reverting any one of them re-introduces an occurrence whose
// (file, function, receiver) is in no declared row, and
// TestEveryBundleDigestReaderIsDeclared fails naming that site. This test
// asserts the recomputation is still the shape of those functions, so the
// four cannot quietly become three.
func TestRevertingAFixedSiteWouldBeUndeclared(t *testing.T) {
	root := moduleRoot(t)
	fixed := []struct {
		file, function string
	}{
		{"replay/environment.go", "BundleDigests"},
		{"legacycompile/shadow/world.go", "NewWorld"},
		{"conformance/scenario.go", "Request"},
		{"authoring/publish.go", "Publish"},
	}
	for _, f := range fixed {
		src, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(f.file)))
		if err != nil {
			t.Errorf("%s: %v", f.file, err)
			continue
		}
		if !strings.Contains(string(src), "VerifiedDigest()") {
			t.Errorf("%s no longer calls VerifiedDigest(); %s was one of the four consumers that trusted the advertised digest (#3700), and if it has gone back to reading .Digest the census above must be failing too",
				f.file, f.function)
		}
	}
}
