package authoring

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// A case that has never been observed failing is not evidence that a check
// works. It is evidence that a check and a case agree today, which they would
// also do if the check were deleted and the case were asserting something else.
//
// Every save-time check below therefore has a MUTANT: a real edit to the real
// source that removes or inverts exactly that check, compiled and run. The
// harness demands two separate things of each one, and conflating them is the
// trap this kind of harness usually falls into:
//
//  1. the mutant must BUILD. `go test` exits non-zero for a compile error and
//     for a failing assertion alike, so a harness that only reads the exit code
//     reports a mutant that never compiled as proof of a working guard. The
//     build runs as its own step and a failure there is reported as a broken
//     mutant, not as a passing gate.
//  2. the mutant's own case must then FAIL. If it still passes, the case is not
//     testing the check it names.
//
// Nothing on disk is modified. `go test -overlay` substitutes the mutated file
// at compile time from a temporary directory, so a harness killed between
// mutating and restoring cannot leave the working tree mutated, which is the
// failure mode a copy-and-restore harness has and cannot avoid.

// mutant is one edit that removes a check.
type mutant struct {
	// code is the save-time check this mutant disables, and names the subtest
	// in TestSaveTimeChecks that must consequently fail.
	code string
	// file is relative to the decision module root.
	file string
	// old must appear EXACTLY ONCE in the file. A mutant whose anchor has
	// drifted is reported as a broken mutant rather than silently applying
	// nowhere and reporting the check as unguarded.
	old string
	new string
	// why states the defect this mutant restores, so a reader can tell a
	// meaningful mutation from a syntactic one.
	why string
	// runPattern overrides the test the mutant must turn red.
	//
	// Empty means the default, "TestSaveTimeChecks/<code>$", which is right for
	// every check relayed from the deterministic PDP. A mutant aimed at the
	// PARSE BOUNDARY has no save-time subtest to name, and pointing it at one
	// anyway would report a survivor for a guard that works.
	runPattern string
}

func mutants() []mutant {
	return []mutant{
		// THE PARSE BOUNDARY, not a save-time check - so it names its own test.
		//
		// ValidateAgainstSchema validates a RE-RENDERED document: the bytes go
		// through the decoder into a Go value and back out, so a member the
		// author OMITTED comes back at its zero value and satisfies `required`.
		// Deleting the raw call leaves the boundary accepting a document whose
		// obligation never declared `mandatory`, stored as advisory, with the
		// author's own document saying nothing of the kind.
		//
		// It is here rather than left as a claim because the first version of
		// that change was not held by its own tests: with the call deleted, both
		// new tests stayed green - the top-level members are already refused by
		// the rendered validator's nested constraints, and the comparison test
		// did not yet assert that the rendered validator ACCEPTS. This is the
		// third guard in this lane whose CALL SITE was unpinned while its
		// predicate was tested.
		{
			code: "AUTHORING_RAW_SCHEMA", file: "authoring/document.go",
			why:        "lets Parse accept a document whose obligation omitted `mandatory`, because the re-rendered document supplies it at its zero value",
			old:        "\tif err := ValidateRawAgainstSchema(raw); err != nil {\n\t\treturn nil, err\n\t}\n",
			new:        "",
			runPattern: "TestTheRawValidatorSeesWhatTheRenderedOneCannot$",
		},
		// Relayed from the deterministic PDP. Mutating pdp/policy.go is
		// deliberate: the relayed checks are only as good as the rules behind
		// them, and a harness that mutated only this package would report the
		// relay as guarded while the rule itself was gone.
		{
			code: "AUTHORITY_FROM_UNTRUSTED", file: "pdp/policy.go",
			why: "restores the hole where caller-supplied input may establish authority by comparison against a trusted attribute",
			old: "\t\tif (left == contract.NsArgs && right.Trusted()) || (right == contract.NsArgs && left.Trusted()) {",
			new: "\t\tif false && ((left == contract.NsArgs && right.Trusted()) || (right == contract.NsArgs && left.Trusted())) {",
		},
		{
			code: "FIELD_NOT_IN_SCHEMA", file: "pdp/policy.go",
			why: "lets a condition reference an attribute the document never declared",
			old: "\t\tif _, ok := schema[p]; !ok {\n\t\t\terrs = append(errs, ValidationError{RuleFieldNotInSchema, policyID,\n\t\t\t\tfmt.Sprintf(\"condition references %q, which is not declared in the attribute schema\", p)})\n\t\t}",
			new: "\t\t_ = schema",
		},
		{
			code: "PERMISSION_EMITS_DENY", file: "pdp/policy.go",
			why: "lets a permission policy attach obligations, which is how a widening policy acquires the power to restrict",
			old: "\t\t\tif len(p.Obligations) > 0 {\n\t\t\t\terrs = append(errs, ValidationError{RulePermissionEmitsDeny, p.ID,\n\t\t\t\t\t\"a permission policy cannot attach obligations; use a requirement policy with the same condition\"})\n\t\t\t}",
			new: "\t\t\t_ = p.Obligations",
		},
		{
			code: "CONSTRAINT_CARRIES_OBLIGATIONS", file: "pdp/policy.go",
			why: "lets one object both deny and attach a transform, with a nullable field deciding which",
			old: "\t\tif p.Authority == contract.AuthorityConstraint && len(p.Obligations) > 0 {\n\t\t\terrs = append(errs, ValidationError{RuleConstraintObligations, p.ID,\n\t\t\t\t\"a constraint policy cannot attach obligations; split it into a constraint and a requirement\"})\n\t\t}",
			new: "",
		},
		{
			code: "INSPECTION_GRANTS", file: "pdp/policy.go",
			why: "lets a probabilistic detector declare itself a required control",
			old: "\t\tif p.Authority == contract.AuthorityInspection && p.Mandatory {\n\t\t\terrs = append(errs, ValidationError{RuleInspectionGrants, p.ID,\n\t\t\t\t\"an inspection policy cannot be mandatory; a required deterministic control is a constraint or a requirement\"})\n\t\t}",
			new: "",
		},
		{
			code: "SELECTOR_MATCHES_NOTHING", file: "pdp/policy.go",
			why: "lets a requirement policy attach nothing, which is a control that does nothing",
			old: "\t\tif p.Authority == contract.AuthorityRequirement && len(p.Obligations) == 0 {\n\t\t\terrs = append(errs, ValidationError{RuleEmptySelector, p.ID,\n\t\t\t\t\"a requirement policy that attaches no obligation does nothing\"})\n\t\t}",
			new: "",
		},
		{
			code: "APPROVAL_CLAUSE_UNSATISFIABLE", file: "pdp/policy.go",
			why: "moves the quorum floor off by one so a zero-quorum approval is accepted and discharges itself",
			old: "\tif err != nil || q < 1 {",
			new: "\tif err != nil || q < 0 {",
		},
		{
			code: "ORG_POLICY_PIERCES_SYSTEM", file: "pdp/policy.go",
			why: "lets an organization document declare which of its own constraints break-glass may pierce",
			old: "\t\tif p.Root == RootOrganization && len(p.PierceableBy) > 0 {",
			new: "\t\tif false && p.Root == RootOrganization && len(p.PierceableBy) > 0 {",
		},
		{
			code: "MALFORMED_CONDITION", file: "pdp/policy.go",
			why: "accepts an undeclared condition kind, which then reaches the compiler",
			old: "\tdefault:\n\t\terrs = append(errs, ValidationError{RuleMalformedCondition, policyID,\n\t\t\tfmt.Sprintf(\"condition kind %q is not declared\", c.Kind)})\n\t}",
			new: "\tdefault:\n\t}",
		},
		{
			code: "DUPLICATE_POLICY_ID", file: "pdp/policy.go",
			why: "lets one identifier name two policies, so \"which policy denied this\" has two answers",
			old: "\t\tif _, dup := seen[p.ID]; dup {\n\t\t\terrs = append(errs, ValidationError{RuleDuplicatePolicyID, p.ID, \"policy id appears more than once in one document\"})\n\t\t}",
			new: "",
		},
		{
			code: "ROOT_MISMATCH", file: "pdp/policy.go",
			why: "lets a policy declare an authority root other than the document that carries it",
			old: "\t\tif p.Root != d.Root {",
			new: "\t\tif false && p.Root != d.Root {",
		},
		{
			code: "POOL_NOT_INTERACTIVE", file: "pdp/policy.go",
			why: "makes the all-non-interactive test unreachable, so an approval nobody can answer is issued and expires into a denial",
			old: "\tif len(nonInteractive) == countEligible(o) {",
			new: "\tif len(nonInteractive) > countEligible(o) {",
		},
		{
			code: "ABSENCE_NOT_HANDLED", file: "pdp/policy.go",
			why: "lets a condition over an optional attribute leave absence undeclared, so the compiler decides on the author's behalf",
			old: "\t\tcase declared && schemaEntry.Optional && c.OnAbsent == AbsentUnspecified:",
			new: "\t\tcase false && declared && schemaEntry.Optional && c.OnAbsent == AbsentUnspecified:",
		},

		// Owned by this package.
		{
			code: CodeActionNotRegistered, file: "authoring/validate.go",
			why: "accepts a selector naming an action the registry does not contain, which governs nothing",
			old: "\t\t\tunregistered = true\n\t\t\tout = append(out, newFinding(CodeActionNotRegistered, p.ID, fmt.Sprintf(\n\t\t\t\t\"the action selector names %q, which the action registry does not contain\", id)))",
			new: "\t\t\tunregistered = true",
		},
		{
			code: CodeSelectorMatchesNoRegisteredAction, file: "authoring/validate.go",
			why: "makes the empty-reach test unreachable, so a tag combination nothing carries reads as an active policy",
			old: "\tif !unregistered && len(reached) == 0 {",
			new: "\tif !unregistered && len(reached) < 0 {",
		},
		{
			code: CodeArgumentNotInActionSchema, file: "authoring/validate.go",
			why: "accepts a condition over a caller argument no reachable action declares",
			old: "\t\tif !ok {\n\t\t\tout = append(out, newFinding(CodeArgumentNotInActionSchema, p.ID, fmt.Sprintf(\n\t\t\t\t\"the condition reads %q, which action %q does not declare in its argument schema\", path, entry.ID)))\n\t\t\tcontinue\n\t\t}",
			new: "\t\tif !ok {\n\t\t\tcontinue\n\t\t}",
		},
		{
			code: CodeLevelNotDeclared, file: "authoring/validate.go",
			why: "accepts a projection through a hierarchy level a reachable resource type does not declare",
			old: "\tif len(missing) > 0 {\n\t\tout = append(out, newFinding(CodeLevelNotDeclared, p.ID, fmt.Sprintf(\n\t\t\t\"the condition reads level %q through %q, which resource type(s) %v do not declare as an ancestor level\",\n\t\t\tlevel, path, missing)))\n\t}",
			new: "\t_ = missing",
		},
		{
			code: CodeScopeRequiresRecursion, file: "authoring/validate.go",
			why: "accepts a containment scope over a flat hierarchy, where the closure is always empty",
			old: "\t\tif len(flat) > 0 {\n\t\t\tout = append(out, newFinding(CodeScopeRequiresRecursion, p.ID, fmt.Sprintf(\n\t\t\t\t\"the condition reads the containment closure %q, but resource type(s) %v declare a non-recursive hierarchy, so the closure is always empty there\",\n\t\t\t\tpath, flat)))\n\t\t}",
			new: "\t\t_ = flat",
		},
		{
			code: CodeRealmNotDeclared, file: "authoring/validate.go",
			why: "lets a policy be scoped to a population in a realm nothing vouches for",
			old: "\t\t\tout = append(out, newFinding(CodeRealmNotDeclared, p.ID, fmt.Sprintf(\n\t\t\t\t\"the scope names %q, whose realm %q is not declared in the realm registry\", id, id.Qualifier)))\n\t\t\tcontinue",
			new: "\t\t\tcontinue",
		},
		{
			code: CodeGroupScopeWithoutGraph, file: "authoring/validate.go",
			why: "inverts the graph test, so the warning fires on realms that have a group graph and stays silent on the realms where the closure is empty",
			old: "\t\tif id.Kind == contract.KindGroup && !realm.HasGroupGraph {",
			new: "\t\tif id.Kind == contract.KindGroup && realm.HasGroupGraph {",
		},
		{
			code: CodeObligationConflict, file: "authoring/validate.go",
			why: "inverts the reason test, so the one denial that IS an authoring conflict is the one that is discarded",
			old: "\tif !outcome.Denied || outcome.Reason != contract.ReasonObligationConflict {",
			new: "\tif !outcome.Denied || outcome.Reason == contract.ReasonObligationConflict {",
		},
		{
			code: CodeDisclosureTargetNotALeaf, file: "authoring/validate.go",
			why: "inverts the coverage test, so a redaction that lands on nothing is accepted and one that lands is refused",
			old: "\t\tif !coversAnyLeaf(o.Target, leaves) {",
			new: "\t\tif coversAnyLeaf(o.Target, leaves) {",
		},
		{
			code: CodeConstraintNeverBinds, file: "authoring/validate.go",
			why: "swaps the structural test, so an unconditionally true exception is accepted as a control",
			old: "\t\tif p.Unless != nil && alwaysTrue(*p.Unless) {",
			new: "\t\tif p.Unless != nil && neverTrue(*p.Unless) {",
		},
		{
			code: CodeDeadPermission, file: "authoring/validate.go",
			why: "inverts the suppression test, so a permission that can never grant is reported as live",
			old: "\t\t\tif !suppressesEntirely(con, perm, cat) {\n\t\t\t\tcontinue\n\t\t\t}",
			new: "\t\t\tif suppressesEntirely(con, perm, cat) {\n\t\t\t\tcontinue\n\t\t\t}",
		},
		{
			code: CodeCatalogDisagreement, file: "authoring/validate.go",
			why: "inverts the agreement test, so the carried registry copy becomes a second, editable source of truth",
			old: "\t\tif gotVal != wantVal {",
			new: "\t\tif gotVal == wantVal {",
		},
		{
			code: CodeEnvelopeInvalid, file: "authoring/validate.go",
			why: "accepts a document with no title",
			old: "\tif strings.TrimSpace(d.Metadata.Title) == \"\" {\n\t\treject(\"metadata.title is empty\")\n\t}",
			new: "",
		},
		{
			code: CodeApproverIsAuthor, file: "authoring/publish.go",
			why: "inverts separation of duties, so the author approving themselves is the case that satisfies it",
			old: "\t\tif ap.String() != d.Metadata.Author.String() {\n\t\t\treturn nil\n\t\t}",
			new: "\t\tif ap.String() == d.Metadata.Author.String() {\n\t\t\treturn nil\n\t\t}",
		},
	}
}

// inertMutant is the control. It changes a comment and nothing else, so the
// suite must still PASS under it.
//
// Without it the harness proves only that the tests fail under 27 edits, which
// they would also do if the harness were broken and reported failure for
// everything. A control that must pass is what separates "these cases detect
// the check" from "this harness reports failure".
var inertMutant = mutant{
	code: "INERT_CONTROL", file: "authoring/validate.go",
	why: "changes only a comment; the suite must still pass",
	old: "// Validate applies the complete save-time check set to a document.",
	new: "// Validate applies the complete save-time check set to a document. (control)",
}

func moduleRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	// SYMLINKS ARE RESOLVED, and this is not tidiness (#3564).
	//
	// A -overlay entry is matched by the go command against the PHYSICAL path
	// it computes for a file. With this tree anywhere under a symlinked prefix
	// - /tmp on macOS is a symlink to /private/tmp, which is where the
	// community-mirror simulation (scripts/ci/simulate-community-mirror.sh)
	// stages it - every overlay key misses SILENTLY: the build succeeds
	// because the ORIGINAL file is compiled, the target case passes because
	// nothing was mutated, and this harness reports every proof as a survivor.
	//
	// That is the worst available failure for a mutation gate, because it
	// accuses the checks rather than itself. Measured on the staged mirror
	// before this line existed: all 27 proofs "survived"; with it, all 27 pass.
	// CI never saw it because a GitHub runner's workspace has no symlinked
	// component - so the failure was reserved for exactly the two places it
	// would be least expected, a developer machine and the mirror lane.
	if resolved, rerr := filepath.EvalSymlinks(root); rerr == nil {
		root = resolved
	}
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("expected the decision module root at %s: %v", root, err)
	}
	return root
}

// applyMutant writes the mutated file and returns an overlay path.
func applyMutant(t *testing.T, root string, m mutant) string {
	t.Helper()
	target := filepath.Join(root, filepath.FromSlash(m.file))
	src, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("mutant %s: %v", m.code, err)
	}
	if n := strings.Count(string(src), m.old); n != 1 {
		t.Fatalf("mutant %s: its anchor appears %d times in %s, expected exactly one. The source moved and this mutant is no longer the edit it claims to be.",
			m.code, n, m.file)
	}
	mutated := strings.Replace(string(src), m.old, m.new, 1)
	dir := t.TempDir()
	out := filepath.Join(dir, filepath.Base(m.file))
	if err := os.WriteFile(out, []byte(mutated), 0o600); err != nil {
		t.Fatal(err)
	}
	overlay := filepath.Join(dir, "overlay.json")
	doc, err := json.Marshal(map[string]any{"Replace": map[string]string{target: out}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(overlay, doc, 0o600); err != nil {
		t.Fatal(err)
	}
	return overlay
}

func goCommand(root, overlay string, args ...string) *exec.Cmd {
	full := append([]string{args[0], "-overlay=" + overlay}, args[1:]...)
	cmd := exec.Command("go", full...)
	cmd.Dir = root
	// GOPROXY off so a mutant run can never reach the network: every
	// dependency is already in the module cache, and a harness that could
	// download would turn a compile error into a timeout.
	cmd.Env = append(os.Environ(), "GOPROXY=off", "GOFLAGS=")
	return cmd
}

// runMutant builds the mutant and then runs the case it should break.
func runMutant(t *testing.T, root string, m mutant, pattern string) (built bool, testPassed bool, output string) {
	t.Helper()
	overlay := applyMutant(t, root, m)

	buildOut, buildErr := goCommand(root, overlay, "build", "./...").CombinedOutput()
	if buildErr != nil {
		return false, false, string(buildOut)
	}
	testOut, testErr := goCommand(root, overlay, "test", "-count=1", "-run", pattern, "axonflow/platform/decision/authoring").CombinedOutput()
	return true, testErr == nil, string(testOut)
}

func TestMutationProofsForEverySaveTimeCheck(t *testing.T) {
	if testing.Short() {
		t.Skip("the mutation harness compiles the module once per mutant")
	}
	root := moduleRoot(t)

	t.Run("INERT_CONTROL", func(t *testing.T) {
		built, passed, out := runMutant(t, root, inertMutant, "TestSaveTimeChecks")
		if !built {
			t.Fatalf("the control mutant did not build, so every result below is about the harness rather than about the checks:\n%s", out)
		}
		if !passed {
			t.Fatalf("the suite fails under a comment-only change, so a failure under a real mutant proves nothing:\n%s", out)
		}
	})

	all := mutants()
	covered := map[string]struct{}{}
	for _, m := range all {
		m := m
		t.Run(m.code, func(t *testing.T) {
			pattern := m.runPattern
			if pattern == "" {
				pattern = "TestSaveTimeChecks/" + m.code + "$"
			}
			built, passed, out := runMutant(t, root, m, pattern)
			if !built {
				// Reported apart from a failing assertion on purpose. `go test`
				// exits non-zero for both, and a mutant that never compiled is
				// not evidence about anything.
				t.Fatalf("mutant did not build, so it proves nothing about %s (%s):\n%s", m.code, m.why, out)
			}
			if passed {
				t.Fatalf("the case for %s still passes with the check removed (%s), so the case is not testing that check:\n%s", m.code, m.why, out)
			}
			covered[m.code] = struct{}{}
		})
	}

	t.Run("every declared check has a mutant", func(t *testing.T) {
		declared := map[string]struct{}{}
		for _, c := range AllChecks() {
			declared[c.Code] = struct{}{}
		}
		var missing []string
		for code := range declared {
			found := false
			for _, m := range all {
				if m.code == code {
					found = true
				}
			}
			if !found {
				missing = append(missing, code)
			}
		}
		if len(missing) > 0 {
			sort.Strings(missing)
			t.Fatalf("declared checks with no mutant proving their case can fail: %v", missing)
		}
		// A mutant may name a declared save-time check, OR carry its own
		// runPattern. The second kind exists because not every guard in this
		// package IS a save-time check: the PARSE BOUNDARY is one, and forcing
		// it to invent a check code so this loop accepts it would put a
		// non-existent entry in AllChecks() - which the operator-facing check
		// list is generated from.
		boundary := 0
		for _, m := range all {
			if m.why == "" {
				t.Fatalf("mutant %s does not say what defect it restores", m.code)
			}
			if _, ok := declared[m.code]; ok {
				if m.runPattern != "" {
					t.Fatalf("mutant %s names a declared check AND overrides its test pattern; one of the two is "+
						"wrong, and the override would silently stop exercising the check's own case", m.code)
				}
				continue
			}
			if m.runPattern == "" {
				t.Fatalf("mutant %s names no declared check and no test to turn red, so nothing says what it proves", m.code)
			}
			boundary++
		}
		if len(all)-boundary != len(declared) {
			t.Fatalf("%d save-time mutants for %d declared checks (plus %d boundary mutants)",
				len(all)-boundary, len(declared), boundary)
		}
	})

	t.Logf("%s", fmt.Sprintf("mutation proofs: %d checks, each with a compiling mutant whose case then failed, plus one inert control that passed", len(all)))
}
