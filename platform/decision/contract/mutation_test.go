package contract

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

// The source-mutation proofs for this package's inbound boundary.
//
// platform/decision/{registry,authoring,conformance} each carry one of these
// and this package did not, so the AuthZEN decoder's refusals - the structural
// half of what a generated client is promised - had tests but no proof those
// tests could fail. The pattern is the siblings' one, deliberately, so a reader
// who knows one knows all four.
//
// TWO DELIBERATE DIFFERENCES from the siblings, both because this package is
// small and compiles in about a second:
//
//   - nothing skips under -short, so the gate runs inside the module's own
//     full sweep rather than needing a workflow step of its own. The siblings
//     skip because their harnesses cost minutes; a gate that runs everywhere
//     cannot be lost by a workflow edit.
//   - the mutants are aimed at the DECODER rather than at Project. The decoder
//     is what the route runs; Project is this package's projection step for the
//     PDP. That distinction is the whole reason the schema-agreement test was
//     re-pointed - see the comment on TestTheDecoderAndTheSchemaAgreeOnShape -
//     so the mutation gate is aimed the same way, with one mutant on Project
//     under the name that says whose rule it is.
type sourceMutation struct {
	// Name describes the defect being introduced.
	Name string
	// File is the source file, relative to this package.
	File string
	// Old is the exact anchor text, which must occur once.
	Old string
	// New is what replaces it.
	New string
	// Test is the test that must go red.
	Test string
	// Property is what that test would stop proving.
	Property string
}

func sourceMutations() []sourceMutation {
	return []sourceMutation{
		{
			Name: "an envelope carrying BOTH declared members is accepted",
			File: "authzen.go",
			Old:  `	case hasSingular && hasPlural:`,
			New:  `	case false && hasSingular && hasPlural:`,
			Test: "TestTheDecoderAndTheSchemaAgreeOnShape",
			Property: "exactly one of the two top-level members may be present, so a request cannot mean one " +
				"thing to this decoder and another to a gateway or an audit log that read the other member",
		},
		{
			Name:     "an empty plural array is a request for zero decisions",
			File:     "authzen.go",
			Old:      `	if env.Evaluations != nil && len(env.Evaluations.Evaluations) == 0 {`,
			New:      `	if false && env.Evaluations != nil && len(env.Evaluations.Evaluations) == 0 {`,
			Test:     "TestTheDecoderAndTheSchemaAgreeOnShape",
			Property: "the decision count is fixed by the mapping, and zero decisions is not a mapping",
		},
		{
			Name:     "a null declared member decodes as an envelope",
			File:     "authzen.go",
			Old:      `	if env.Evaluation == nil && env.Evaluations == nil {`,
			New:      `	if false && env.Evaluation == nil && env.Evaluations == nil {`,
			Test:     "TestTheDecoderAndTheSchemaAgreeOnShape",
			Property: "a declared member present as null carries no evaluation, and presence is decided on the key set",
		},
		{
			Name: "an undeclared member is ignored rather than refused",
			File: "authzen.go",
			Old:  `	dec.DisallowUnknownFields()`,
			New:  `	_ = dec.Buffered()`,
			Test: "TestTheDecoderAndTheSchemaAgreeOnShape",
			Property: "strict decoding fails closed, so a request built for another profile version is refused " +
				"rather than evaluated as if it were this one",
		},
		{
			Name:     "the projection admits an evaluation with no subject type",
			File:     "authzen.go",
			Old:      `	if merged.Subject == nil || merged.Subject.ID == "" || merged.Subject.Type == "" {`,
			New:      `	if merged.Subject == nil || merged.Subject.ID == "" {`,
			Test:     "TestProjectRefusesAnIncompleteEvaluation",
			Property: "the projection refuses an evaluation whose merged subject names no type",
		},
	}
}

// TestContractSourceMutationsAreKilled compiles and runs every mutant.
func TestContractSourceMutationsAreKilled(t *testing.T) {
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
		if cleanChecked[m.Test] {
			continue
		}
		cleanChecked[m.Test] = true
		out, code := runPackageTest(t, goBin, "", m.Test)
		if code != 0 {
			t.Fatalf("%s fails on the CLEAN tree, so every mutation against it would prove nothing:\n%s", m.Test, out)
		}
	}

	for _, m := range mutations {
		t.Run(m.Name, func(t *testing.T) {
			overlay := writeMutantOverlay(t, m)
			out, code := runPackageTest(t, goBin, overlay, m.Test)

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

// TestTheContractMutationGateCanReportASurvivor is the anti-vacuity half.
//
// Five killed mutants prove the guards are load bearing only if the runner is
// capable of reporting that one was NOT killed. A runner that always reported a
// non-zero exit code, or one whose overlay never reached the compiler, would
// produce the same green result. This introduces a change that alters no
// behaviour and asserts the named test still passes, which is the answer the
// gate reads as a survivor.
func TestTheContractMutationGateCanReportASurvivor(t *testing.T) {
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Fatalf("the go toolchain is not on PATH: %v", err)
	}
	inert := sourceMutation{
		Name: "a comment change, which alters no behaviour",
		File: "authzen.go",
		Old:  "// DecodeAuthZENEnvelope decodes strictly.",
		New:  "// DecodeAuthZENEnvelope decodes the envelope strictly.",
		Test: "TestTheDecoderAndTheSchemaAgreeOnShape",
	}
	overlay := writeMutantOverlay(t, inert)
	out, code := runPackageTest(t, goBin, overlay, inert.Test)
	if code != 0 {
		t.Fatalf("an inert mutation killed %s, so the gate above cannot tell a real kill from noise:\n%s", inert.Test, out)
	}
}

// writeMutantOverlay produces the mutated copy and the overlay file pointing
// the compiler at it, and returns the overlay path.
//
// The tree is never edited in place: the mutated copy lives in a temporary
// directory the compiler is pointed at, so there is no restore step that can
// fail to run.
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

// runPackageTest runs one test of this package, optionally under an overlay,
// and returns the combined output and the exit code.
func runPackageTest(t *testing.T, goBin, overlay, testName string) (string, int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	args := []string{"test", "-count=1"}
	if overlay != "" {
		args = append(args, "-overlay="+overlay)
	}
	args = append(args, "-run", "^"+testName+"$", ".")
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

// TestTheContractAnchorCheckRefusesAnAmbiguousOrAbsentAnchor drives the
// uniqueness rule directly, including the case that occurs zero times, which no
// committed mutation exercises.
func TestTheContractAnchorCheckRefusesAnAmbiguousOrAbsentAnchor(t *testing.T) {
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
