// Package authzenmutation holds the source-mutation proofs for the AuthZEN
// surface's refusal guards.
//
// WHY IT IS ITS OWN DIRECTORY, and why that directory has no production file.
// Each mutant compiles platform/agent once, and platform/agent is a large
// package behind a coverage-gated CI step with a five-minute budget. Putting
// this harness in that package would spend that budget on compiles; putting it
// here means it is picked up by the "every package the per-service steps do not
// reach" job in test.yml and its community twin, whose selection is `go list
// ./...` minus the three service roots, so this package is in it by
// construction rather than by anyone remembering to add a step.
//
// It follows the pattern platform/decision/{registry,authoring,conformance}
// established, deliberately, so a reader who knows one knows all four. The one
// deliberate difference is that nothing here skips under -short: the sibling
// harnesses skip because they run inside a `-race` full-module sweep where
// their subprocesses are not instrumented, and this one has no such sweep to
// duplicate. A gate that runs everywhere cannot be lost by a workflow edit.
package authzenmutation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// sourceMutation is one proof that a refusal in the AuthZEN adapter is load
// bearing.
//
// A data-level mutation cannot reach these guards: they ARE the refusal rules,
// an `if` that either refuses a request or does not, with no policy document to
// perturb. So each mutant edits the SOURCE, and the edited tree is compiled and
// run through `go test -overlay`.
//
// The proof has three parts and all three are asserted:
//
//  1. the anchor occurs EXACTLY ONCE in the file, so the mutation lands where
//     it was aimed rather than at a similar line elsewhere;
//  2. the mutant COMPILES, because a mutant that fails to build is not a kill,
//     it is a broken mutant that would report every guard as load bearing;
//  3. the named test FAILS on the mutant, and passes on the clean tree.
//
// The tree is never edited in place. The overlay puts the mutated copy in a
// temporary directory the compiler is pointed at, so there is no restore step
// that can fail to run - which is how an earlier session's mutation script left
// a mutation in the working tree after being killed between mutating and
// restoring.
type sourceMutation struct {
	// Name describes the defect being introduced.
	Name string
	// File is the source file, relative to this package.
	File string
	// Package is the Go package the named test lives in, relative to this
	// one. Every mutation here targets platform/agent, which is "..".
	Package string
	// Old is the exact anchor text, which must occur once.
	Old string
	// New is what replaces it.
	New string
	// Test is the test that must go red.
	Test string
	// Property is what that test would stop proving.
	Property string
}

// sourceMutations are aimed at the guards the R3 round-2 fixes added, because
// a guard written in the same round as its test is exactly the pair that needs
// a proof the test can fail.
func sourceMutations() []sourceMutation {
	return []sourceMutation{
		{
			Name:    "an absent subject type reads as the gateway type",
			File:    "../authzen_adapter.go",
			Package: "..",
			Old:     `	if r.Subject.Type == "" {`,
			New:     `	if false && r.Subject.Type == "" {`,
			Test:    "TestAuthZENRefusesAnAbsentRequiredType",
			Property: "an OMITTED subject type is refused rather than read as the one supported value; " +
				"without it a body naming an end-user id binds that id to the gateway identity",
		},
		{
			Name:    "an absent resource type is admitted",
			File:    "../authzen_adapter.go",
			Package: "..",
			Old:     `	if r.Resource.Type == "" {`,
			New:     `	if false && r.Resource.Type == "" {`,
			Test:    "TestTheSchemaAgreesWithTheRouteBoundary",
			Property: "the route refuses what the published schema calls invalid, so a rule the schema states " +
				"is enforced on the request path rather than by nobody",
		},
		{
			Name:    "a plural entry's context discards the shared base's",
			File:    "../authzen_adapter.go",
			Package: "..",
			Old:     `	entry.Context = mergeContext(entry.Context, base.Context)`,
			New: `	if entry.Context == nil {
		entry.Context = base.Context
	}`,
			Test: "TestPluralEntryContextDoesNotDiscardTheBase",
			Property: "an entry that supplies its own context keeps the base's correlation keys, which were " +
				"validated and accepted and would otherwise reach no audit row",
		},
		{
			Name:     "an unrecognised profile falls through to the bare boolean",
			File:     "../authzen_handler.go",
			Package:  "..",
			Old:      `	if negotiated != "" && negotiated != contract.AuthZENProfileV1 {`,
			New:      `	if false && negotiated != "" && negotiated != contract.AuthZENProfileV1 {`,
			Test:     "TestAuthZENRefusesAProfileItCannotEmit",
			Property: "a profile version this build cannot emit is refused rather than answered as if negotiated",
		},
		{
			Name:    "the served context drops the obligations it was handed",
			File:    "../authzen_handler.go",
			Package: "..",
			Old:     `			Obligations:   obligations,`,
			New:     `			Obligations:   nil,`,
			Test:    "TestServedAuthZENContextEqualsToAuthZEN",
			Property: "the served bytes carry what ToAuthZEN renders for the same decision, member for member. " +
				"This is the comparison that did not exist while the two renderings drifted for a whole release; " +
				"the three PII postures are what stop a mutant that is wrong on one shape passing on another",
		},
		{
			Name:     "a stated end-user subject is accepted",
			File:     "../authzen_adapter.go",
			Package:  "..",
			Old:      `		if r.Subject.Type != "" && r.Subject.Type != authzenSubjectGateway {`,
			New:      `		if false && r.Subject.Type != "" && r.Subject.Type != authzenSubjectGateway {`,
			Test:     "TestAuthZENRefusesEveryConstructItCannotEvaluate",
			Property: "a subject naming an end user is refused, because the evaluator derives identity from the credentials",
		},
	}
}

// TestAuthZENSourceMutationsAreKilled compiles and runs every mutant.
func TestAuthZENSourceMutationsAreKilled(t *testing.T) {
	goBin, err := exec.LookPath("go")
	if err != nil {
		// Not a skip. A guard keyed on a possibly absent tool that skips when
		// the tool is missing is invisible exactly where it stopped running,
		// and this test cannot be running at all without a Go toolchain.
		t.Fatalf("the go toolchain is not on PATH, so no mutant can be compiled: %v", err)
	}

	mutations := sourceMutations()
	if len(mutations) == 0 {
		t.Fatalf("no mutations are declared, so this gate proves nothing")
	}

	// The clean run per distinct test, memoized. Without it a mutant that
	// killed a test which was already failing would count as a kill.
	cleanChecked := map[string]bool{}
	for _, m := range mutations {
		key := m.Package + "/" + m.Test
		if cleanChecked[key] {
			continue
		}
		cleanChecked[key] = true
		out, code := runPackageTest(t, goBin, "", m.Package, m.Test)
		if code != 0 {
			t.Fatalf("%s fails on the CLEAN tree, so every mutation against it would prove nothing:\n%s", m.Test, out)
		}
	}

	for _, m := range mutations {
		t.Run(m.Name, func(t *testing.T) {
			overlay := writeMutantOverlay(t, m)
			out, code := runPackageTest(t, goBin, overlay, m.Package, m.Test)

			// A mutant that does not build is not a kill. Checking the exit
			// code alone would count a compile error as one, and every guard
			// would then look load bearing.
			for _, marker := range []string{
				"[build failed]", "syntax error", "undefined:", "cannot use",
				"declared and not used", "too many errors", "missing return",
			} {
				if strings.Contains(out, marker) {
					t.Fatalf("the mutant did not compile (%q), so it proves nothing about %s:\n%s", marker, m.Test, out)
				}
			}
			if code == 0 {
				t.Fatalf("%s still passes after introducing %q, so it does not prove: %s",
					m.Test, m.Name, m.Property)
			}
		})
	}
}

// TestTheMutationGateCanReportASurvivor is the anti-vacuity half of the gate
// above.
//
// Five killed mutants prove the guards are load bearing only if the runner is
// capable of reporting that one was NOT killed. A runner that always reported a
// non-zero exit code, or one whose overlay never reached the compiler, would
// produce exactly the same green result. This introduces a change that alters
// no behaviour and asserts the named test still passes, which is the answer the
// gate reads as a survivor.
func TestTheMutationGateCanReportASurvivor(t *testing.T) {
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Fatalf("the go toolchain is not on PATH: %v", err)
	}
	inert := sourceMutation{
		Name:    "a comment change, which alters no behaviour",
		File:    "../authzen_adapter.go",
		Package: "..",
		Old:     "// mergeContext returns the base's context members overlaid with the entry's.",
		New:     "// mergeContext returns the base's context members with the entry's laid over them.",
		Test:    "TestPluralEntryContextDoesNotDiscardTheBase",
	}
	overlay := writeMutantOverlay(t, inert)
	out, code := runPackageTest(t, goBin, overlay, inert.Package, inert.Test)
	if code != 0 {
		t.Fatalf("an inert mutation killed %s, so the gate above cannot tell a real kill from noise:\n%s", inert.Test, out)
	}
}

// writeMutantOverlay produces the mutated copy and the overlay file pointing
// the compiler at it, and returns the overlay path.
func writeMutantOverlay(t *testing.T, m sourceMutation) string {
	t.Helper()
	original, err := filepath.Abs(m.File)
	if err != nil {
		t.Fatalf("resolving %s: %v", m.File, err)
	}
	src, err := os.ReadFile(filepath.Clean(original))
	if err != nil {
		t.Fatalf("reading %s: %v", m.File, err)
	}
	mutated, err := mutantSource(string(src), m)
	if err != nil {
		t.Fatalf("%v", err)
	}

	dir := t.TempDir()
	copyPath := filepath.Join(dir, filepath.Base(m.File))
	if err := os.WriteFile(copyPath, []byte(mutated), 0o600); err != nil {
		t.Fatalf("writing the mutant: %v", err)
	}
	overlayPath := filepath.Join(dir, "overlay.json")
	doc := struct {
		Replace map[string]string
	}{Replace: map[string]string{original: copyPath}}
	encoded, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("encoding the overlay: %v", err)
	}
	if err := os.WriteFile(overlayPath, encoded, 0o600); err != nil {
		t.Fatalf("writing the overlay: %v", err)
	}
	return overlayPath
}

// runPackageTest runs one test of one package, optionally under an overlay, and
// returns the combined output and the exit code.
func runPackageTest(t *testing.T, goBin, overlay, pkg, testName string) (string, int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	args := []string{"test", "-count=1"}
	if overlay != "" {
		args = append(args, "-overlay="+overlay)
	}
	args = append(args, "-run", "^"+testName+"$", pkg)
	cmd := exec.CommandContext(ctx, goBin, args...)
	cmd.Env = os.Environ()
	out, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("running %s timed out:\n%s", testName, out)
	}
	code := 0
	if err != nil {
		code = 1
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			code = exitErr.ExitCode()
		}
	}
	return string(out), code
}

// mutantSource applies one mutation to a file's text.
//
// Anchor uniqueness is asserted rather than assumed, and it is a pure function
// so the assertion can itself be tested. An anchor matching twice mutates the
// wrong site as well as the right one; an anchor matching zero times produces a
// mutant identical to the clean tree, which would report the guard as NOT load
// bearing while looking like a completed proof.
func mutantSource(text string, m sourceMutation) (string, error) {
	if n := strings.Count(text, m.Old); n != 1 {
		return "", fmt.Errorf("the anchor for %q occurs %d times in %s, expected exactly once", m.Name, n, m.File)
	}
	mutated := strings.Replace(text, m.Old, m.New, 1)
	if mutated == text {
		return "", fmt.Errorf("the mutation for %q changed nothing in %s", m.Name, m.File)
	}
	return mutated, nil
}

// TestTheAnchorCheckRefusesAnAmbiguousOrAbsentAnchor drives the uniqueness rule
// directly, including the case that occurs zero times, which no committed
// mutation exercises.
func TestTheAnchorCheckRefusesAnAmbiguousOrAbsentAnchor(t *testing.T) {
	for name, tc := range map[string]struct {
		text string
		m    sourceMutation
		want string
	}{
		"an anchor that is not there": {
			text: "package p\n", m: sourceMutation{Name: "x", File: "f.go", Old: "absent", New: "y"},
			want: "occurs 0 times",
		},
		"an anchor that occurs twice": {
			text: "a\na\n", m: sourceMutation{Name: "x", File: "f.go", Old: "a", New: "b"},
			want: "occurs 2 times",
		},
		"a replacement identical to the anchor": {
			text: "a\n", m: sourceMutation{Name: "x", File: "f.go", Old: "a", New: "a"},
			want: "changed nothing",
		},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := mutantSource(tc.text, tc.m)
			if err == nil {
				t.Fatalf("the anchor check accepted %s", name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("the anchor check refused %s with the wrong message: %v", name, err)
			}
		})
	}
	got, err := mutantSource("keep a keep\n", sourceMutation{Name: "x", File: "f.go", Old: "a", New: "b"})
	if err != nil {
		t.Fatalf("a unique anchor was refused: %v", err)
	}
	if got != "keep b keep\n" {
		t.Fatalf("the mutation produced %q", got)
	}
}
