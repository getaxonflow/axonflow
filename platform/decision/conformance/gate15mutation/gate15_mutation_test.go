// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

// Package gate15mutation proves that ADR-065 gate 15's anti-vacuity floors can
// actually fail.
//
// THE REASON THIS PACKAGE EXISTS IS A DEFECT THIS GATE HAD AND DID NOT REPORT.
//
// The first version of TestGate15CrossPlaneOutcomeEquality ran 726 plane-pair
// comparisons over six scenarios and passed. Every one of those comparisons was
// DENY == DENY: the corpus's permit-class scenarios attach a mandatory
// quota_reservation@1 or field_mask@1, no legacy plane advertises either, and
// ADR-065 invariant 8 therefore made all twelve planes refuse identically. The
// gate had three anti-vacuity floors at the time - a non-empty corpus, at least
// two planes, at least two capability groups - and not one of them could see
// it, because each floors a single AXIS and the missing thing was the axes'
// PRODUCT. A floor over one dimension cannot report a missing one.
//
// So the gate gained a floor on the outcome dimension, and floors that have
// never been observed failing are exactly what the previous paragraph is about.
// Each floor below therefore has a MUTANT: a real edit to the real source that
// disables it, compiled and run, with the two halves kept apart -
//
//  1. the mutant must BUILD. `go test` exits non-zero for a compile error and a
//     failed assertion alike, so a harness reading only the exit code reports a
//     mutant that never compiled as proof of a working floor.
//  2. the gate must then FAIL. A surviving mutant means the floor is decorative.
//
// Nothing on disk is modified: `go test -overlay` substitutes the mutated file
// at compile time, so a harness killed mid-run cannot leave the tree mutated.
package gate15mutation

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// edit is one anchored substitution in one file.
type edit struct {
	// file is relative to the decision module root.
	file string
	// from must appear EXACTLY ONCE. An anchor that has drifted is reported as
	// a broken mutant rather than applying nowhere and reporting the floor as
	// guarded - the silent-survivor shape this package exists to prevent.
	from string
	to   string
}

// mutant is one edit set that disables one floor, plus the defect it restores.
type mutant struct {
	name string
	// why states the defect this mutant restores, so a reader can tell a
	// meaningful mutation from a syntactic one.
	why string
	// expect is the test the mutant must make fail.
	expect string
	edits  []edit
}

// inert changes only a comment. It must BUILD and the gate must still PASS,
// which is what separates "the mutants work" from "this package cannot run the
// gate at all". Without it, a harness whose runner is broken reports every
// floor as guarded.
var inert = mutant{
	name:   "INERT_CONTROL",
	why:    "changes nothing; the gate must still pass",
	expect: "TestGate15CrossPlaneOutcomeEquality",
	edits: []edit{{
		file: "conformance/cross_plane_test.go",
		from: "// crossPlaneScenario is one corpus entry with a name.",
		to:   "// crossPlaneScenario is one corpus entry with a name. (inert control)",
	}},
}

func mutants() []mutant {
	return []mutant{
		{
			name: "OUTCOME_SPREAD_FLOOR",
			why: "restores the state the gate actually shipped in for one round: every scenario " +
				"resolving to the same operational state on every plane, so 726 comparisons " +
				"compare DENY to DENY and the gate passes hardest when the permit path is " +
				"most broken",
			expect: "TestGate15CrossPlaneOutcomeEquality",
			// The three scenarios carrying a non-DENY class are REPLACED by
			// DENY ones rather than deleted, so the corpus keeps its size and
			// the corpus-axis floor stays satisfied. That is the point: what
			// remains is exactly the DENY-only corpus the gate shipped with,
			// and only a floor on the OUTCOME axis can see it.
			edits: []edit{
				{
					file: "conformance/cross_plane_test.go",
					from: "\t\t{\"permit_every_plane_discharges\", Scenario{\n\t\t\tPrincipal: \"alice\", Action: \"T5\", Resource: \"SUP-42\",\n\t\t\tArgs: map[string]any{\"ticket_id\": \"SUP-42\", \"to_status\": \"done\"},\n\t\t}},",
					to:   "\t\t{\"permit_every_plane_discharges\", Scenario{\n\t\t\tPrincipal: \"alice\", Action: \"T2\", Args: map[string]any{\"segment\": \"all\"},\n\t\t}},",
				},
				{
					file: "conformance/cross_plane_test.go",
					from: "\t\t{\"challenge_only_capable_planes_can_discharge\", Scenario{\n\t\t\tPrincipal: \"bob\", Action: \"T5\", Resource: \"SUP-42\",\n\t\t\tArgs: map[string]any{\"ticket_id\": \"SUP-42\", \"to_status\": \"done\"},\n\t\t}},",
					to:   "\t\t{\"challenge_only_capable_planes_can_discharge\", Scenario{\n\t\t\tPrincipal: \"dana\", Action: \"T2\", Args: map[string]any{\"segment\": \"all\"},\n\t\t}},",
				},
				{
					file: "conformance/cross_plane_test.go",
					from: "\t\t{\"unresolved_attribute_is_indeterminate\", Scenario{\n\t\t\tPrincipal: \"alice\", Action: \"T5\", Resource: \"LEG-7\",\n\t\t\tArgs: map[string]any{\"ticket_id\": \"LEG-7\", \"to_status\": \"done\"},\n\t\t\tOverrides: map[string]*contract.Attribute{\n\t\t\t\tPathAgentTrust: UnknownAttr(PathAgentTrust, contract.ReasonResolutionFailed),\n\t\t\t},\n\t\t}},",
					to:   "\t\t{\"unresolved_attribute_is_indeterminate\", Scenario{\n\t\t\tPrincipal: \"frank\", Action: \"T2\", Args: map[string]any{\"segment\": \"all\"},\n\t\t}},",
				},
			},
		},
		{
			name: "PERMISSIVE_STATE_FLOOR",
			why: "lets a corpus in which every decision DENIES satisfy the floor, which the " +
				"distinct-state count alone would allow as soon as two DENY reasons produce " +
				"two states - the floor must require a NON-restrictive outcome, not merely a " +
				"second one",
			expect: "TestGate15CrossPlaneOutcomeEquality",
			edits: []edit{
				// Make every non-DENY state count as restrictive, i.e. delete
				// the permissive requirement while leaving the spread check.
				{
					file: "conformance/cross_plane_test.go",
					from: "\t\t\t\tif st != contract.StateDeny {\n\t\t\t\t\tpermissive += n\n\t\t\t\t}",
					to:   "\t\t\t\t_, _ = st, n",
				},
				// ...and remove the permit scenarios, so the weakened floor is
				// the ONLY thing standing between the gate and a DENY-only
				// corpus. Without this the mutant would survive for a reason
				// that has nothing to do with the floor.
				{
					file: "conformance/cross_plane_test.go",
					from: "\t\t{\"permit_every_plane_discharges\", Scenario{\n\t\t\tPrincipal: \"alice\", Action: \"T5\", Resource: \"SUP-42\",\n\t\t\tArgs: map[string]any{\"ticket_id\": \"SUP-42\", \"to_status\": \"done\"},\n\t\t}},",
					to:   "\t\t{\"permit_every_plane_discharges\", Scenario{\n\t\t\tPrincipal: \"alice\", Action: \"T2\", Args: map[string]any{\"segment\": \"all\"},\n\t\t}},",
				},
				// The challenge scenario is left in place, so a CHALLENGE
				// still appears in the enterprise edition and the
				// distinct-state count stays above one. The ONLY thing the
				// weakened floor has to notice is that nothing PERMISSIVE
				// remains in the community edition, where that scenario denies.
			},
		},
		{
			name: "LICENSED_DIFFERENCE_FLOOR",
			why: "lets part 2 of the gate go dead unnoticed: the planes still disagree about a " +
				"capability the corpus demands, but no pair differs any more, and the gate " +
				"reports hundreds of green comparisons while the capability-refusal half " +
				"is never reached",
			expect: "TestGate15CrossPlaneOutcomeEquality",
			// THE DEMAND MUST SURVIVE THE MUTATION, WHICH THE OBVIOUS MUTANT
			// GETS WRONG.
			//
			// Deleting the scenario that demands a discriminating capability
			// removes the DEMAND as well as the DIFFERENCE, and this floor is
			// derived from both - so it correctly stops requiring a difference
			// and the mutant survives while proving nothing. Measured: that
			// version survived.
			//
			// So the capability refusal itself is disabled instead. Every plane
			// then discharges every obligation, no pair differs, and the corpus
			// still demands approval_challenge@1 which five of the twelve
			// enterprise planes advertise and seven do not. The floor is the
			// only thing left that can notice part 2 went dead.
			edits: []edit{{
				file: "contract/obligation.go",
				from: "\t\tif !in.PEP.Supports(o) {",
				to:   "\t\tif false && !in.PEP.Supports(o) {",
			}},
		},
		// THE NEXT TWO INJECT A DEFECT RATHER THAN DELETE AN ASSERTION, AND THE
		// DISTINCTION IS THE WHOLE PROOF.
		//
		// Removing an assertion from a test that currently PASSES can never
		// make it fail, so an `if false &&` mutant on either of these arms
		// survives by construction and says nothing about whether the arm
		// works. Both arms live in assertCapabilityRefusalExplains, which only
		// reports; the thing they assert about is invariant 8 in the PDP. So
		// each mutant below breaks invariant 8 in the way its arm exists to
		// catch, and the arm must be what turns the gate red.
		{
			name: "REFUSAL_MUST_BE_EXPLAINED_BY_A_DEMANDED_CAPABILITY",
			why: "inverts the PEP capability check, so the plane that CAN discharge a mandatory " +
				"obligation is the one that refuses and the plane that cannot is the one that " +
				"permits - a plane denying while holding every capability the scenario " +
				"demanded, which is a plane-private rule wearing a capability difference as a " +
				"disguise, and the permissive direction is the dangerous half of gate 15",
			expect: "TestGate15CrossPlaneOutcomeEquality",
			edits: []edit{{
				file: "contract/obligation.go",
				from: "\t\tif !in.PEP.Supports(o) {",
				to:   "\t\tif in.PEP.Supports(o) {",
			}},
		},
		{
			name: "REFUSAL_REASON_IS_THE_CAPABILITY_ONE",
			why: "makes the capability refusal deny with a DIFFERENT reason code, so a " +
				"divergence that is really about the POLICY would be absorbed as a capability " +
				"difference - the one class of disagreement this gate must never swallow",
			expect: "TestGate15CrossPlaneOutcomeEquality",
			edits: []edit{{
				file: "contract/obligation.go",
				from: "\t\t\t\tDenied: true, Reason: ReasonUnsupportedObligation,\n\t\t\t\tDetail: fmt.Sprintf(\"mandatory obligation %q from policy %q cannot be discharged: %s\", o.Type, o.SourcePolicy, who),",
				to:   "\t\t\t\tDenied: true, Reason: ReasonObligationConflict,\n\t\t\t\tDetail: fmt.Sprintf(\"mandatory obligation %q from policy %q cannot be discharged: %s\", o.Type, o.SourcePolicy, who),",
			}},
		},
		{
			name: "DEMAND_IS_READ_FROM_AN_UNCONSTRAINED_WORLD",
			why: "reads the demanded obligations off a PEP-constrained decision, which is " +
				"circular: a plane that cannot discharge an obligation emits no obligation, " +
				"so the demand vanishes exactly when it is the thing being refused and every " +
				"refusal then looks unexplained",
			expect: "TestGate15CrossPlaneOutcomeEquality",
			edits: []edit{{
				file: "conformance/cross_plane_test.go",
				from: "\tseen := map[string]bool{}\n\tvar out []string\n\tfor _, o := range d.Obligations {\n\t\tif !o.Mandatory {\n\t\t\tcontinue\n\t\t}",
				to:   "\tseen := map[string]bool{}\n\tvar out []string\n\tfor _, o := range d.Obligations {\n\t\tif !o.Mandatory || true {\n\t\t\tcontinue\n\t\t}",
			}},
		},
	}
}

func TestGate15FloorsCanFail(t *testing.T) {
	if testing.Short() {
		t.Skip("this harness compiles the conformance package once per mutant")
	}
	root := moduleRoot(t)

	t.Run(inert.name, func(t *testing.T) {
		built, passed, out := run(t, root, inert)
		if !built {
			t.Fatalf("the control mutant did not build, so every result below is about this "+
				"harness rather than about the floors:\n%s", out)
		}
		if !passed {
			t.Fatalf("the gate fails under a comment-only change, so a failure under a real "+
				"mutant proves nothing:\n%s", out)
		}
	})

	for _, m := range mutants() {
		m := m
		t.Run(m.name, func(t *testing.T) {
			built, passed, out := run(t, root, m)
			if !built {
				// Reported apart from a failing assertion on purpose: a mutant
				// that never compiled is not evidence about anything.
				t.Fatalf("mutant did not build, so it proves nothing about %s (%s):\n%s",
					m.name, m.why, out)
			}
			if passed {
				t.Fatalf("SURVIVOR: %s still passes with %s disabled (%s), so that floor is "+
					"decorative:\n%s", m.expect, m.name, m.why, out)
			}
		})
	}
}

// TestEveryMutantAnchorIsUniqueAndPresent fails fast and separately from the
// kills.
//
// An anchor that has drifted makes writeMutant fail inside a subtest that is
// otherwise reporting on a floor, which reads as "the floor is fine" to anyone
// skimming. Checked here, once, against the real files.
func TestEveryMutantAnchorIsUniqueAndPresent(t *testing.T) {
	root := moduleRoot(t)
	all := append([]mutant{inert}, mutants()...)
	if len(all) < 2 {
		t.Fatal("no mutants; this harness would pass while proving nothing")
	}
	for _, m := range all {
		if m.why == "" || m.expect == "" {
			t.Fatalf("mutant %s does not say what defect it restores or what must fail", m.name)
		}
		if len(m.edits) == 0 {
			t.Fatalf("mutant %s has no edits", m.name)
		}
		// Edits to one file compose in sequence, so uniqueness is checked
		// against the buffer as it will actually be at that point rather than
		// against the pristine file.
		buf := map[string]string{}
		for _, e := range m.edits {
			if _, ok := buf[e.file]; !ok {
				src, err := os.ReadFile(filepath.Join(root, e.file))
				if err != nil {
					t.Fatalf("%s: read %s: %v", m.name, e.file, err)
				}
				buf[e.file] = string(src)
			}
			if n := strings.Count(buf[e.file], e.from); n != 1 {
				t.Errorf("%s: anchor appears %d time(s) in %s, want exactly 1:\n%q",
					m.name, n, e.file, e.from)
				continue
			}
			buf[e.file] = strings.Replace(buf[e.file], e.from, e.to, 1)
		}
	}
}

func moduleRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	root := filepath.Clean(filepath.Join(wd, "..", ".."))
	// SYMLINKS ARE RESOLVED, and this is not tidiness.
	//
	// A -overlay entry is matched by the go command against the PHYSICAL path
	// it computes for a file. Staging this tree under a symlinked prefix -
	// /tmp on macOS is a symlink to /private/tmp, which is exactly where the
	// community-mirror simulation stages it - makes every overlay key miss
	// SILENTLY: the build succeeds because the ORIGINAL file is compiled, the
	// target test passes because nothing was mutated, and the harness reports
	// every mutant as a survivor. That is the worst available failure for a
	// mutation gate, because it accuses the guards rather than itself.
	if resolved, rerr := filepath.EvalSymlinks(root); rerr == nil {
		root = resolved
	}
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("no go.mod at the computed module root %q; this harness's relative path "+
			"assumption is wrong: %v", root, err)
	}
	return root
}

// run builds and runs one mutant, returning (built, passed, output).
func run(t *testing.T, root string, m mutant) (bool, bool, string) {
	t.Helper()
	overlay := writeMutant(t, root, m)

	// The build is its own step, because `go test` exits non-zero for a
	// compile error and a failed assertion alike.
	if out, err := runGo(t, root, []string{"vet", "-overlay", overlay, "./conformance/"}); err != nil {
		return false, false, out
	}
	out, err := runGo(t, root, []string{"test", "-overlay", overlay, "-count=1",
		"-run", "^" + m.expect + "$", "./conformance/"})
	return true, err == nil, out
}

// writeMutant renders every mutated file into a temp dir and returns the path
// of an overlay JSON mapping each original to its mutant. NOTHING ON DISK IS
// MODIFIED.
func writeMutant(t *testing.T, root string, m mutant) string {
	t.Helper()
	dir := t.TempDir()
	replace := map[string]string{}

	// Edits to the SAME file are applied in sequence to one buffer, so a
	// multi-edit mutant on one file produces ONE mutated copy rather than
	// several that overwrite each other - which would silently drop an edit and
	// turn a three-part mutant into a partial one.
	byFile := map[string]string{}
	var order []string
	for _, e := range m.edits {
		if _, ok := byFile[e.file]; !ok {
			src, err := os.ReadFile(filepath.Join(root, e.file))
			if err != nil {
				t.Fatalf("read %s: %v", e.file, err)
			}
			byFile[e.file] = string(src)
			order = append(order, e.file)
		}
		cur := byFile[e.file]
		if strings.Count(cur, e.from) != 1 {
			t.Fatalf("the anchor for %q does not match exactly once in %s; see "+
				"TestEveryMutantAnchorIsUniqueAndPresent", m.name, e.file)
		}
		byFile[e.file] = strings.Replace(cur, e.from, e.to, 1)
	}

	for i, file := range order {
		out := filepath.Join(dir, strings.NewReplacer("/", "_", ".", "_").Replace(file)+
			"_"+string(rune('a'+i))+".go")
		if err := os.WriteFile(out, []byte(byFile[file]), 0o600); err != nil {
			t.Fatalf("write mutant: %v", err)
		}
		replace[filepath.Join(root, file)] = out
	}

	overlay, err := json.Marshal(map[string]any{"Replace": replace})
	if err != nil {
		t.Fatalf("marshal overlay: %v", err)
	}
	path := filepath.Join(dir, "overlay.json")
	if err := os.WriteFile(path, overlay, 0o600); err != nil {
		t.Fatalf("write overlay: %v", err)
	}
	return path
}

func runGo(t *testing.T, root string, args []string) (string, error) {
	t.Helper()
	cmd := exec.Command("go", args...)
	cmd.Dir = root
	// GOFLAGS is cleared so an ambient -mod or -tags from the parent run
	// cannot change what the child compiles.
	cmd.Env = append(os.Environ(), "GOFLAGS=")
	out, err := cmd.CombinedOutput()
	return string(out), err
}
