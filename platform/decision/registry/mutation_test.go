package registry

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

// sourceMutation is one proof that a guard in this package is load bearing.
//
// A data-level mutation cannot reach these guards, because they are the
// registration rules themselves: there is no policy document to perturb, only
// an `if` that either refuses a record or does not. So each mutant edits the
// SOURCE, and the edited tree is compiled and run through `go test -overlay`.
//
// The proof has three parts and all three are asserted:
//
//  1. the anchor occurs EXACTLY ONCE in the file, so the mutation lands where
//     it was aimed rather than at a similar line elsewhere;
//  2. the mutant COMPILES, because a mutant that fails to build is not a kill,
//     it is a broken mutant that would report every guard as load bearing;
//  3. the named test FAILS on the mutant, and passes on the clean tree.
//
// The tree is never edited in place. An earlier session's mutation script was
// killed between mutating and restoring, left the mutation in the working tree,
// and the next run's backup captured it as the good state. The overlay puts the
// mutated copy in a temporary directory that the compiler is pointed at, so
// there is no restore step that can fail to run.
type sourceMutation struct {
	// Name describes the defect being introduced.
	Name string
	// File is the source file, relative to this package.
	File string
	// Package is the Go package the named test lives in, relative to this
	// one. Empty means this package. It exists because two of the guards
	// below live in platform/decision/authoring: the anti-divergence gate
	// between the two containment checks is only meaningful if it can be shown
	// to fail, and it fails on an edit to the derivation rather than to
	// anything here.
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

func sourceMutations() []sourceMutation {
	return []sourceMutation{
		{
			Name: "a missing posture axis is skipped instead of refused",
			File: "posture.go",
			Old: `		if axis.value == "" {
			out = out.errorf(CodePostureNotDeclared, subject,`,
			New: `		if axis.value == "" {
			continue
		}
		if false {
			out = out.errorf(CodePostureNotDeclared, subject,`,
			Test:     "TestBothPostureAxesAreMandatory",
			Property: "an action that declares neither, or only one, of the two posture axes is unregisterable",
		},
		{
			Name: "a permissive error posture gains an exception path",
			File: "posture.go",
			Old:  `	if p.OnError == contract.AuthzPermit {`,
			New:  `	if false && p.OnError == contract.AuthzPermit {`,
			Test: "TestPermissiveErrorPostureHasNoExceptionPath",
			Property: "on_error=permit is refused under every exception, because a permissive error posture " +
				"converts a dependency outage into a widening of access",
		},
		{
			Name: "a permissive unmatched posture no longer needs an exception",
			File: "catalog.go",
			Old:  `	if a.Posture.Unmatched != contract.AuthzPermit {`,
			New:  `	if true || a.Posture.Unmatched != contract.AuthzPermit {`,
			Test: "TestPermissivePostureNeedsALiveException",
			Property: "unmatched=permit is accepted only behind a registered, complete, unexpired compatibility " +
				"exception",
		},
		{
			Name:     "an unregistered tool resolves instead of being refused",
			File:     "query.go",
			Old:      `			Status: ResolutionUnknownTool,`,
			New:      `			Status: ResolutionResolved,`,
			Test:     "TestUnregisteredToolIsRefusedBeforePolicy",
			Property: "a tool the catalog does not hold is refused before any policy loads",
		},
		{
			Name:     "tool schema drift is admitted",
			File:     "query.go",
			Old:      `	if call.RegistryVersion != rec.SchemaVersion {`,
			New:      `	if false && call.RegistryVersion != rec.SchemaVersion {`,
			Test:     "TestToolSchemaDriftInvalidatesTheMapping",
			Property: "a call at a version other than the one the mapping was registered against invalidates the mapping",
		},
		{
			Name:     "a governed-tag removal is recorded without an alarm",
			File:     "catalog.go",
			Old:      `				Code: EventGovernedTagRemoved, Severity: SeverityAlarm, Subject: key, At: at,`,
			New:      `				Code: EventGovernedTagRemoved, Severity: SeverityInfo, Subject: key, At: at,`,
			Test:     "TestGovernedTagRemovalRaisesAnAlarm",
			Property: "removing a governed tag raises an alarm, because every constraint selecting on it stops matching silently",
		},
		{
			Name:     "a governed-tag addition is recorded without an alarm",
			File:     "catalog.go",
			Old:      `				Code: EventGovernedTagAdded, Severity: SeverityAlarm, Subject: key, At: at,`,
			New:      `				Code: EventGovernedTagAdded, Severity: SeverityInfo, Subject: key, At: at,`,
			Test:     "TestGovernedTagAdditionRaisesAnAlarm",
			Property: "adding a governed tag raises an alarm, because every permission selecting on it starts matching silently",
		},
		{
			Name:     "a governed-tag change no longer needs an approval reference",
			File:     "catalog.go",
			Old:      `	if governedMoving && ch.ApprovalRef == "" {`,
			New:      `	if false && governedMoving && ch.ApprovalRef == "" {`,
			Test:     "TestGovernedTagChangeRequiresApproval",
			Property: "a change moving a governed tag goes through the policy-change path",
		},
		{
			Name:     "re-registration overwrites instead of being refused",
			File:     "catalog.go",
			Old:      `	if _, exists := c.actions[key]; exists {`,
			New:      `	if _, exists := c.actions[key]; false && exists {`,
			Test:     "TestRegistrationIsCreateOnly",
			Property: "registration is create-only, so a governed tag cannot be dropped by re-registering the action",
		},
		{
			Name:     "the projection stops validating the catalog",
			File:     "catalog.go",
			Old:      `	if err := c.Validate().Err(); err != nil {`,
			New:      `	if err := c.Validate().Err(); false && err != nil {`,
			Test:     "TestProjectionRefusesAnInvalidCatalog",
			Property: "no record carrying an undeclared posture, risk class or tag can reach an evaluator",
		},
		{
			Name:     "an accessor hands out the catalog's own record",
			File:     "query.go",
			Old:      `	return a.clone(), true`,
			New:      `	return a, true`,
			Test:     "TestTheCatalogHandsOutCopies",
			Property: "no accessor returns a writable reference to the catalog's own state, so no registration rule is advisory",
		},
		{
			Name:     "an absent record answers as a declared-empty set",
			File:     "pep.go",
			Old:      `		out.Status = CapabilityNoRecord`,
			New:      `		out.Status = CapabilityDeclaredNone`,
			Test:     "TestAbsentRecordIsDistinguishableFromDeclaredEmpty",
			Property: "an enforcement point that never advertised anything is distinguishable from one that advertises nothing",
		},
		{
			Name:     "capability versions match by at-least instead of exactly",
			File:     "pep.go",
			Old:      `		if c.Version == o.SchemaVersion {`,
			New:      `		if c.Version >= o.SchemaVersion {`,
			Test:     "TestCapabilityCheckMatchesTheVersionExactly",
			Property: "a build claiming one obligation version is not assumed to implement another's semantics",
		},
		{
			Name: "an out-of-range declaration reports itself valid",
			File: "declaration.go",
			Old: `	case DeclarationUnspecified:
		return false
	default:
		return false
	}
}

// Yes reports whether the declaration is an explicit yes.`,
			New: `	case DeclarationUnspecified:
		return false
	default:
		return true
	}
}

// Yes reports whether the declaration is an explicit yes.`,
			Test: "TestEveryRiskClassIsDeclared",
			Property: "a risk class is validated by membership with a default arm, so a value one past the top of " +
				"the range cannot register as declared",
		},
		{
			Name: "a community enforcement point may advertise an Enterprise-only family",
			File: "pep.go",
			// The mutant moved with #3704: the community rule now reads
			// SplitOverAdvertised, so the one predicate serves both remedies
			// (Validate REFUSES a registered record, the external path DROPS
			// and counts). Disarming the predicate's community arm is what the
			// old `if false &&` did to the inlined check.
			Old:      `		if err != nil || edition != EditionCommunity || !enterpriseOnlyFamilies[family] {`,
			New:      `		if err != nil || edition != EditionCommunity || !enterpriseOnlyFamilies[family] || true {`,
			Test:     "TestCommunityEnforcementPointCannotAdvertiseEnterpriseFamilies",
			Property: "a community enforcement point cannot claim a capability its build does not have",
		},
		{
			Name:     "the derived authoring catalog reports every hierarchy as recursive",
			File:     "../authoring/from_registry.go",
			Package:  "../authoring",
			Old:      `			Recursive:     rec.Recursion.Recursive(),`,
			New:      `			Recursive:     true,`,
			Test:     "TestTheTwoContainmentChecksCannotDisagree",
			Property: "the per-policy containment check and the per-type one answer the same question the same way",
		},
		{
			Name:     "the derivation stops checking that the realm sets agree",
			File:     "../authoring/from_registry.go",
			Package:  "../authoring",
			Old:      `	if len(problems) > 0 {`,
			New:      `	if false && len(problems) > 0 {`,
			Test:     "TestTheDerivationRefusesADisagreementAboutRealms",
			Property: "a realm the registry trusts but nothing describes, or the reverse, is a refusal rather than a silent gap",
		},
		{
			Name:     "publication stops asking whether the obligation can be discharged",
			File:     "query.go",
			Old:      `			out = out.errorf(CodeCapabilityMissing, id, "%s", check.Detail)`,
			New:      `			_ = check`,
			Test:     "TestPublicationRefusesAnUndischargeableObligation",
			Property: "the capability is proved before the policy ships rather than by the first caller through it",
		},
	}
}

// TestSourceMutationsAreKilled compiles and runs every mutant.
func TestSourceMutationsAreKilled(t *testing.T) {
	if testing.Short() {
		// -short is not a licence to skip a correctness gate; it is how the
		// race-detector lane keeps its wall clock down. This gate spawns one
		// compile per mutant, and CI runs the package unfiltered without
		// -short, which is where it bites.
		t.Skip("each mutant compiles the package; the unfiltered run is the one that matters")
	}
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
		key := m.pkg() + "/" + m.Test
		if cleanChecked[key] {
			continue
		}
		cleanChecked[key] = true
		out, code := runPackageTest(t, goBin, "", m.pkg(), m.Test)
		if code != 0 {
			t.Fatalf("%s fails on the CLEAN tree, so every mutation against it would prove nothing:\n%s", m.Test, out)
		}
	}

	for _, m := range mutations {
		t.Run(m.Name, func(t *testing.T) {
			overlay := writeMutantOverlay(t, m)
			out, code := runPackageTest(t, goBin, overlay, m.pkg(), m.Test)

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

// pkg is the package to run, relative to this one.
func (m sourceMutation) pkg() string {
	if m.Package == "" {
		return "."
	}
	return m.Package
}

// runPackageTest runs one test of one package, optionally under an overlay,
// and returns the combined output and the exit code.
func runPackageTest(t *testing.T, goBin, overlay, pkg, testName string) (string, int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
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

// TestTheMutationGateCanReportASurvivor is the anti-vacuity half of the gate
// above.
//
// Fifteen killed mutants prove the guards are load bearing only if the runner
// is capable of reporting that one was NOT killed. A runner that always
// reported a non-zero exit code, or one whose overlay never reached the
// compiler, would produce exactly the same green result. This introduces a
// change that alters no behaviour and asserts the named test still passes,
// which is the answer the gate reads as a survivor.
func TestTheMutationGateCanReportASurvivor(t *testing.T) {
	if testing.Short() {
		t.Skip("this compiles the package once; the unfiltered run is the one that matters")
	}
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Fatalf("the go toolchain is not on PATH: %v", err)
	}
	inert := sourceMutation{
		Name: "a comment change, which alters no behaviour",
		File: "posture.go",
		Old:  "// FailClosedPosture is the production posture",
		New:  "// FailClosedPosture is still the production posture",
		Test: "TestBothPostureAxesAreMandatory",
	}
	overlay := writeMutantOverlay(t, inert)
	out, code := runPackageTest(t, goBin, overlay, inert.pkg(), inert.Test)
	if code != 0 {
		t.Fatalf("an inert mutation killed %s, so the gate above cannot tell a real kill from noise:\n%s", inert.Test, out)
	}
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
