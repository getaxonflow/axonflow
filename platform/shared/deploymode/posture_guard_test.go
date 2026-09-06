// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package deploymode

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// scanRoots are the directories walked. Both are relative to the repository
// root. `ee/` does not exist on the community mirror and its absence is
// recorded rather than treated as an error - see postureCensus.MissingRoots.
var scanRoots = []string{"platform", "ee"}

// ownerDir is the package that owns both axes. Its own files necessarily
// compare a mode value against a mode name; that is what "owning the question"
// means, and exempting them by DIRECTORY rather than by line keeps the
// exemption from drifting every time this file is edited.
const ownerDir = "platform/shared/deploymode"

// postureExemptions is the INVENTORY of everything in the tree that still
// derives an answer from the DEPLOYMENT_MODE taxonomy outside this package.
//
// # WHY AN INVENTORY AND NOT A FIX
//
// #3713's disposition is explicit that the wider census - the customer-portal
// reads in particular - is a follow-on rather than part of the consolidation.
// A guard with no exemptions would have forced those into this PR; a guard with
// no guard would have left them uncounted. An exemption list that must stay
// matched is the third option: every remaining site is named, with the reason
// it is still there, and the day one of them is fixed the entry goes stale and
// this test says so.
//
// # KEYED BY file#FUNCTION, AND KEYING ON THE FILE ALONE WAS A HOLE
//
// Not by line, which moves on every edit above it, and not by the mode list the
// census reports, which changes when a mode is added and would red an unrelated
// PR.
//
// The first version keyed on the FILE, and R3 broke it with a compiling plant.
// Five of these files are ALSO on scripts/lint-deployment-mode.sh's allow-list,
// so appending a brand-new
//
//	func plantedFreshCommunityPostureRead() bool {
//	    return os.Getenv("DEPLOYMENT_MODE") == "community"
//	}
//
// to any of them passed BOTH instruments: the lint allows the file, and the
// census exempted the file. The headline property - the posture is decided in
// exactly one place - was unenforced across five files.
//
// Every reason below is about a FUNCTION ("devTokenEndpointEnabled normalises",
// "getMigrationPaths is the schema selector"), so a second reading elsewhere in
// the same file is a different finding wearing the first one's exemption. The
// key is now `path#function`, which is exactly as wide as the reason.
func postureExemptions() map[string]string {
	return map[string]string{
		// ── Deliberate, documented, and staying ──────────────────────────────
		"platform/agent/dev_token_handler.go#devTokenEndpointEnabled": "" +
			"devTokenEndpointEnabled normalises (ToLower+TrimSpace) where every other reading is exact, " +
			"and its own header argues at length that it must NOT take its accepting set from the helper " +
			"whose job is to turn authentication off: coupling them means a future widening of the posture " +
			"predicate silently re-arms an HS256 signing oracle. The wider accepting set is the point, so " +
			"this is not a copy of IsCommunityPosture - it is a different question that happens to name the " +
			"same token. #3713 says so too.",

		"platform/agent/migration_helpers.go#getMigrationPaths": "" +
			"getMigrationPaths is the SCHEMA selector itself. Its `raw == \"\"` arm is where deploymode.Unset " +
			"is applied to a real deployment, and it reaches the taxonomy through deploymode.Resolve rather " +
			"than restating it (migration_helpers.go aliases CanonicalModes/Aliases/Unset). The comparison " +
			"the census sees is the unset branch, not a second table.",

		"platform/shared/heartbeat/heartbeat.go#PlatformDeploymentMode": "" +
			"PlatformDeploymentMode reads through deploymode.Current and deploymode.Resolve; the `raw == \"\"` " +
			"the census sees decides whether to OMIT the wire field rather than what the mode means. Absent " +
			"and \"community\" are deliberately different on that wire, which is a reporting decision this " +
			"package has no opinion about.",

		"platform/agent/client_version_telemetry.go#clientVersionDeploymentModeFor": "" +
			"clientVersionDeploymentModeFor bounds a Prometheus label: \"\" becomes \"unset\" and an " +
			"unrecognised value becomes \"unknown\", both via deploymode.Resolve. The empty-string test is " +
			"label bounding, not a posture decision. (Enterprise-tagged, so absent from the community mirror " +
			"- the staleness check below skips a file it cannot see.)",

		"ee/platform/customer-portal/api/provision_admin_password.go#ShouldProvisionDeploymentOrgPassword": "" +
			"ShouldProvisionDeploymentOrgPassword is deliberately the UNION of deploymode.Resolve and the " +
			"original literal test, and the file argues at length why collapsing it to either alone " +
			"reintroduces a defect: Resolve covers only the values it recognises, and the values it does not " +
			"are exactly the ones that would lose their bootstrap silently.",

		"ee/platform/customer-portal/config/deployment.go#LoadDeploymentConfig": "" +
			"LoadDeploymentConfig maps the mode onto a PORTAL TOPOLOGY (in-VPC vs SaaS), which is a third " +
			"question neither axis here answers, and its default arm sends the three in-vpc verticals to the " +
			"SaaS shape on purpose - documented at the function, because only in-vpc-enterprise was ever " +
			"live-validated and the SaaS shape is the one with tenant isolation ON. Follow-on: #3713's own " +
			"disposition defers the customer-portal reads.",

		// The FIFTH reading - resolveConnectorLimitTier - was exempted here by
		// #3738 as "the finding, not a blessing", reported to #3709 and left
		// byte-identical because consolidating it changes entitlement behaviour
		// and that is not a rider for a de-duplication PR. It is now FIXED
		// (#3713): the classifier asks deploymode.CurrentIsEnterpriseEntitled
		// and no longer reads DEPLOYMENT_MODE at all, so the exemption is gone
		// rather than reworded.
		//
		// This entry's removal was not noticed by a human. #3738's own
		// stale-exemption check found it: the census stopped producing a
		// reading for a site the inventory still named, and it failed with
		// "either the site was fixed and this entry should go, or the census
		// stopped seeing it". That is the mechanism working exactly as its
		// author argued it would.

		"ee/platform/customer-portal/middleware/admin_auth.go#isAdminAuthRequired": "" +
			"isAdminAuthRequired switches over its own hand-maintained copy of the mode taxonomy, with a " +
			"fail-closed default. Adding a canonical mode to this package therefore makes the portal REQUIRE " +
			"admin auth on that mode until somebody edits this switch - a behaviour change discoverable only " +
			"in production. Reported on #3709; deferred by #3713's own disposition, which scopes the " +
			"customer-portal reads to a follow-on.",
	}
}

// postureGuardVerdict is the DECISION half: given a census and an exemption
// list, it reports what is wrong. Pure, so the planted-input test below can
// feed it the shapes it must catch without a tree to read.
//
// It reports three things, and the second is the one that matters most:
//
//  1. unexplained - a reading in a file no exemption names. The defect.
//  2. stale - an exemption whose file EXISTS in the scanned tree and produced
//     no reading. That is either a fix nobody removed the entry for, or - much
//     worse - the analysis quietly going blind, which is indistinguishable from
//     a clean tree unless something insists the known sites are still found.
//  3. skipped - an exemption whose file is not in the tree at all. On the
//     community mirror `ee/` is stripped wholesale and every enterprise-tagged
//     file is deleted, so absence there is expected and must not be called
//     stale. Returned so the caller can refuse to run on skips alone.
func postureGuardVerdict(c postureCensus, exempt map[string]string, fileExists func(string) bool) (unexplained []string, stale []string, skipped []string) {
	matched := map[string]bool{}
	for _, r := range c.readings {
		if r.File == ownerDir || strings.HasPrefix(r.File, ownerDir+"/") {
			continue
		}
		if _, ok := exempt[r.key()]; ok {
			matched[r.key()] = true
			continue
		}
		unexplained = append(unexplained, r.String())
	}
	for key := range exempt {
		if matched[key] {
			continue
		}
		// The path half of the key is what exists on disk.
		if !fileExists(strings.SplitN(key, "#", 2)[0]) {
			skipped = append(skipped, key)
			continue
		}
		stale = append(stale, key)
	}
	sort.Strings(unexplained)
	sort.Strings(stale)
	sort.Strings(skipped)
	return unexplained, stale, skipped
}

// TestTheCommunityPostureIsDecidedInExactlyOnePlace is the fence around #3713,
// and it is DERIVED rather than a list of the four call sites the issue named.
//
// # WHY A TEST AND NOT THE LINT
//
// scripts/lint-deployment-mode.sh greps for the literal
// `os.Getenv("DEPLOYMENT_MODE")`. That is a check on the SPELLING of the env
// read, and three separate escapes from it are live in this tree right now:
//
//   - platform/shared/corspolicy wrote `os.Getenv(deploymentModeEnv)` - a local
//     constant - and was NOT on the allow-list, and the lint was green. One of
//     the four copies #3713 is named for was already invisible to it.
//   - a value obtained from deploymode.Current() is not an env read at all.
//   - ee/platform/customer-portal/main.go reads the variable and hands it to
//     api.ShouldProvisionDeploymentOrgPassword, where the comparison happens -
//     one frame away, across a module whose import path is not its directory.
//
// None of those is what is wrong with a second reading. What is wrong is that
// somewhere a DEPLOYMENT_MODE value meets a mode name, and that shape is what
// this walks the tree for - through assignments, through string normalisation,
// and across function boundaries - whatever route the value took.
//
// # WHY NOT A LIST OF THE FOUR
//
// Because the census immediately found a fifth (platform/shared/policy) whose
// answer for an unset value is the OPPOSITE of the other four, and an
// enumerated pin would have had nothing to say about it. A pin that enumerates
// the sites it knows about certifies the enumeration, not the property.
func TestTheCommunityPostureIsDecidedInExactlyOnePlace(t *testing.T) {
	base := repoRoot(t)
	census, err := scanPostureReadings(base, scanRoots)
	if err != nil {
		t.Fatalf("the census failed: %v", err)
	}

	// ANTI-VACUITY, THREE WAYS, and each is a distinct way to go blind.
	if census.Files == 0 {
		t.Fatal("the census parsed zero Go files; the walk, not the tree, is broken - and a broken " +
			"walk reports a clean tree")
	}
	if census.Seeds == 0 {
		t.Fatalf("the census found no DEPLOYMENT_MODE-derived expression in %d files. The seed "+
			"recognisers (os.Getenv of the variable, deploymode.Current) have stopped matching, so "+
			"every comparison downstream of one is now invisible.", census.Files)
	}
	if len(census.readings) == 0 {
		t.Fatalf("the census found %d seeds and not one comparison against a mode name, in %d files. "+
			"This package's own files contain several by construction, so zero means the comparison "+
			"half stopped working.", census.Seeds, census.Files)
	}

	unexplained, stale, skipped := postureGuardVerdict(census, postureExemptions(), func(rel string) bool {
		_, err := os.Stat(filepath.Join(base, filepath.FromSlash(rel)))
		return err == nil
	})

	for _, u := range unexplained {
		t.Errorf("%s\n\n"+
			"A second reading of the DEPLOYMENT_MODE taxonomy. Ask the question through "+
			"platform/shared/deploymode - IsCommunityPosture / CurrentIsCommunityPosture for the runtime "+
			"posture, AppliesCategory / AppliesEnterpriseSchema for the schema - or, if this site really "+
			"is asking something neither answers, add it to postureExemptions() with the reason. An "+
			"exemption with a reason is a decision; a fresh comparison is how four copies of one predicate "+
			"came to disagree about what an unset value means (#3713, #3128).", u)
	}
	for _, s := range stale {
		t.Errorf("stale exemption: %s exists and produced no reading.\n\n"+
			"Either the site was fixed and this entry should go, or - the case worth checking first - "+
			"the census stopped seeing it. A guard whose known sites quietly stop being found reports a "+
			"clean tree, which is exactly the output it gives when the tree really is clean.", s)
	}

	// A run in which EVERY exemption was skipped proves nothing about the
	// analysis, because nothing was required to be found. That is the community
	// mirror's shape if the platform-side entries ever move under ee/ or behind
	// a build tag, and it would turn this whole guard into a no-op there
	// silently.
	// `len(exempt) > 0 &&` is load-bearing, not defensive. Without it an EMPTY
	// inventory satisfies `len(skipped) == len(exempt)` as 0 == 0 and this
	// Fatalf fires with a message that is false - none were absent, there were
	// none. That is precisely the success state the follow-on work aims at, and
	// the nearer intermediate state is worse: fix only the four platform/
	// entries and the community-mirror lane, where the other four are all
	// skipped, trips it too.
	if len(postureExemptions()) > 0 && len(skipped) == len(postureExemptions()) {
		t.Fatalf("every exemption named a file absent from this tree (%v). Nothing was required to be "+
			"found, so the staleness half asserted nothing on this run.", skipped)
	}
	if len(skipped) > 0 {
		t.Logf("not judged on this tree (file absent - `ee/` and enterprise-tagged files are stripped "+
			"from the community mirror): %v", skipped)
	}
	if len(census.MissingRoots) > 0 {
		t.Logf("scan roots absent on this tree: %v", census.MissingRoots)
	}
}

// TestPostureGuardReportsPlantedShapes is the guard's own failing input, and it
// exists because no mutant can produce one.
//
// The census reads source FROM DISK, so a `go test -overlay` mutant - the only
// mutation mechanism this repo has - is invisible to it: the overlay changes
// what the compiler sees, never what os.ReadFile returns
// ([[feedback_an_overlay_mutant_is_invisible_to_a_source_reading_guard]]). A
// census with no demonstrated failing input is indistinguishable from one whose
// extraction silently returns nothing. So the decision half is fed each shape it
// must report, plus the clean case it must not.
func TestPostureGuardReportsPlantedShapes(t *testing.T) {
	exists := func(present ...string) func(string) bool {
		set := map[string]bool{}
		for _, p := range present {
			set[p] = true
		}
		return func(rel string) bool { return set[rel] }
	}

	// 1. THE DEFECT: a fresh comparison in a file nobody named.
	c := postureCensus{Files: 10, Seeds: 3, readings: []reading{
		{File: "platform/orchestrator/new_gate.go", Func: "newGate", Line: 42, Shape: "==", Detail: `"community"`},
	}}
	un, st, _ := postureGuardVerdict(c, map[string]string{"platform/known.go#known": "known"}, exists("platform/known.go"))
	if len(un) != 1 || !strings.Contains(un[0], "new_gate.go") {
		t.Errorf("an unexplained reading was reported as %v; the guard cannot see a fresh second reading, "+
			"which is the only thing it exists for", un)
	}
	// The known file produced nothing, so it is also stale - both directions in
	// one input, which is what a real regression looks like.
	if len(st) != 1 || st[0] != "platform/known.go#known" {
		t.Errorf("stale was reported as %v, want the one exemption that matched nothing", st)
	}

	// 2. THE OWNER'S OWN FILES ARE NOT VIOLATIONS, by directory and not by line.
	c = postureCensus{Files: 10, Seeds: 3, readings: []reading{
		{File: ownerDir + "/deploymode.go", Func: "Resolve", Line: 141, Shape: "==", Detail: `""`},
		{File: ownerDir + "/deploymode.go", Func: "IsCommunityPosture", Line: 999, Shape: "==", Detail: `"community"`},
	}}
	un, _, _ = postureGuardVerdict(c, map[string]string{}, exists())
	if len(un) != 0 {
		t.Errorf("the owning package's own comparisons were reported as violations (%v); a guard that "+
			"fails on a correct tree gets deleted", un)
	}

	// 3. A FILE THAT IS NOT IN THE TREE IS SKIPPED, NOT STALE. This is the
	//    community mirror: `ee/` is stripped and every enterprise-tagged file is
	//    deleted, so calling those exemptions dead would fail the mirror build
	//    on a considered decision about enterprise-only code.
	c = postureCensus{Files: 10, Seeds: 3}
	_, st, sk := postureGuardVerdict(c,
		map[string]string{"ee/portal/x.go#f": "portal", "platform/present.go#g": "present"},
		exists("platform/present.go"))
	if len(sk) != 1 || sk[0] != "ee/portal/x.go#f" {
		t.Errorf("skipped was reported as %v; a file absent from this tree cannot be judged stale", sk)
	}
	if len(st) != 1 || st[0] != "platform/present.go#g" {
		t.Errorf("stale was reported as %v; a file that IS present and produced nothing is the "+
			"analysis-went-blind signal and must still fire on the mirror", st)
	}

	// 3b. THE H1 HOLE, AS A DECISION. A reading in an EXEMPT FILE but a
	//     DIFFERENT FUNCTION must still be reported. Keying on the file alone
	//     let a compiling plant through both this census and the lint.
	c = postureCensus{Files: 10, Seeds: 3, readings: []reading{
		{File: "platform/agent/dev_token_handler.go", Func: "devTokenEndpointEnabled",
			Line: 195, Shape: "==", Detail: `"community"`},
		{File: "platform/agent/dev_token_handler.go", Func: "plantedFreshCommunityPostureRead",
			Line: 379, Shape: "==", Detail: `"community"`},
	}}
	un, st, _ = postureGuardVerdict(c,
		map[string]string{"platform/agent/dev_token_handler.go#devTokenEndpointEnabled": "the normalising gate"},
		exists("platform/agent/dev_token_handler.go"))
	if len(un) != 1 || !strings.Contains(un[0], "plantedFreshCommunityPostureRead") {
		t.Errorf("a fresh reading in an EXEMPT FILE but a different function was reported as %v. "+
			"The exemption's reason is about one function; keying on the file makes it cover every "+
			"future function in that file, which is how a raw posture read passed both instruments.", un)
	}
	if len(st) != 0 {
		t.Errorf("the genuinely-exempt function was reported stale: %v", st)
	}

	// 4. THE CLEAN CASE. Without it, a decision function that reported
	//    everything unconditionally would satisfy all three checks above.
	c = postureCensus{Files: 10, Seeds: 3, readings: []reading{
		{File: "platform/known.go", Func: "known", Line: 7, Shape: "==", Detail: `"community"`},
	}}
	un, st, sk = postureGuardVerdict(c, map[string]string{"platform/known.go#known": "known"}, exists("platform/known.go"))
	if len(un) != 0 || len(st) != 0 || len(sk) != 0 {
		t.Errorf("a correct tree was reported as defective (unexplained=%v stale=%v skipped=%v); the "+
			"three positives above would then be evidence about a function that always complains",
			un, st, sk)
	}
}

// TestPostureCensusSeesEachDerivationRoute plants a tree containing one site
// per route the analysis claims to follow, and requires every one to be
// reported.
//
// This is the test that would have caught the two blind spots this census
// already had, both of which reported FEWER sites rather than erroring:
//
//   - an unqualified `Current()` was treated as the env read, so four unrelated
//     packages that happen to declare one were reported; narrowing it could
//     just as easily have narrowed too far.
//   - an import path was assumed to equal a directory. ee/go.mod carries
//     `replace axonflow/platform/customer-portal => ./platform/customer-portal`,
//     so the portal's cross-file taint resolved to nothing and one real site
//     vanished from the report - a null result that looks exactly like a clean
//     tree ([[feedback_an_inert_probe_and_a_true_negative_are_the_same_output]]).
func TestPostureCensusSeesEachDerivationRoute(t *testing.T) {
	root := t.TempDir()
	write := func(rel, body string) {
		full := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatalf("plant %s: %v", rel, err)
		}
		if err := os.WriteFile(full, []byte(body), 0o600); err != nil {
			t.Fatalf("plant %s: %v", rel, err)
		}
	}

	// Route 1: the bare env read compared to a literal - the shape the lint
	// already catches, here so a narrowing cannot silently drop it too.
	write("platform/a/direct.go", `package a
import "os"
func f() bool { return os.Getenv("DEPLOYMENT_MODE") == "community" }
`)
	// Route 2: the read spelled through a CONSTANT on both sides. This is
	// corspolicy's shape, and the lint is blind to it.
	write("platform/b/consts.go", `package b
import "os"
const envName = "DEPLOYMENT_MODE"
const communityMode = "community"
func f() bool { return os.Getenv(envName) == communityMode }
`)
	// Route 3: through deploymode.Current(), which is not an env read at all.
	write("platform/c/viacurrent.go", `package c
import "axonflow/platform/shared/deploymode"
func f() bool { return deploymode.Current() == "community-saas" }
`)
	// Route 4: normalised first. dev_token_handler.go's shape.
	write("platform/d/normalised.go", `package d
import (
	"os"
	"strings"
)
func f() bool { return strings.ToLower(strings.TrimSpace(os.Getenv("DEPLOYMENT_MODE"))) == "community" }
`)
	// Route 5: a switch, which is how a whole taxonomy gets restated.
	write("platform/e/switched.go", `package e
import "os"
func f() int {
	switch os.Getenv("DEPLOYMENT_MODE") {
	case "saas", "in-vpc-banking":
		return 1
	}
	return 0
}
`)
	// Route 6: ACROSS A FUNCTION BOUNDARY, and across a module whose import
	// path is not its directory - the portal's exact shape.
	write("ee/platform/customer-portal/main.go", `package main
import (
	"os"
	"axonflow/platform/customer-portal/api"
)
func g() { _ = api.Decide(os.Getenv("DEPLOYMENT_MODE")) }
`)
	write("ee/platform/customer-portal/api/decide.go", `package api
func Decide(mode string) bool { return mode == "evaluation" }
`)
	// Route 7: a PACKAGE-LEVEL var holding the mode, compared inside a
	// function DECLARED ABOVE IT. The earlier version claimed to handle this
	// "because the assignment handler runs first"; neither half was true, and
	// the source order here is what proves the fix rather than the claim.
	write("platform/p/pkgvar.go", `package p
import "os"
func f() bool { return pkgMode == "community" }
var pkgMode = os.Getenv("DEPLOYMENT_MODE")
`)
	// Route 8: a whole taxonomy as a MAP indexed by the mode. No literal is
	// ever compared, so no BinaryExpr shape can see it.
	write("platform/q/maplookup.go", `package q
import "os"
func f() bool {
	allowed := map[string]bool{"community": true, "evaluation": true}
	return allowed[os.Getenv("DEPLOYMENT_MODE")]
}
`)
	// Route 9: a RANGE over a literal list of mode names. The comparison is
	// against a loop variable, so again no literal sits beside it.
	write("platform/r/rangelist.go", `package r
import "os"
func f() bool {
	mode := os.Getenv("DEPLOYMENT_MODE")
	for _, m := range []string{"community", "evaluation"} {
		if mode == m {
			return true
		}
	}
	return false
}
`)
	// Route 10: a comparison spelled as a call inside a TAGLESS SWITCH case,
	// which is a condition position nothing else marked.
	write("platform/s/taglessswitch.go", `package s
import (
	"os"
	"strings"
)
func f() int {
	mode := os.Getenv("DEPLOYMENT_MODE")
	switch {
	case strings.EqualFold(mode, "community"):
		return 1
	}
	return 0
}
`)
	// Route 7: a comparison spelled as a CALL, in condition position.
	write("platform/g/call.go", `package g
import (
	"os"
	"strings"
)
func f() bool {
	if strings.EqualFold(os.Getenv("DEPLOYMENT_MODE"), "community") {
		return true
	}
	return false
}
`)

	// Routes 12-13: the SAME two taxonomy shapes spelled with `var` instead of
	// `:=`. Round 2 found both missed: the map/list learners fired only on an
	// AssignStmt, which is the same omission PASS A exists to correct for
	// `local` - a var may be spelled either way and neither spelling is rarer.
	write("platform/u/varmap.go", `package u
import "os"
var allowedModes = map[string]bool{"community": true, "evaluation": true}
func f() bool { return allowedModes[os.Getenv("DEPLOYMENT_MODE")] }
`)
	write("platform/v/varlist.go", `package v
import "os"
var modeList = []string{"community", "evaluation"}
func f() bool {
	mode := os.Getenv("DEPLOYMENT_MODE")
	for _, m := range modeList {
		if mode == m {
			return true
		}
	}
	return false
}
`)

	// Route 11: a PREFIX over the mode namespace. `in-vpc-` is not a mode, but
	// it partitions the taxonomy using knowledge of how the names are spelled,
	// which is the same re-derivation a whole-name comparison is. Live in the
	// tree today at ee/.../provision_admin_password.go.
	write("platform/t/prefix.go", `package t
import (
	"os"
	"strings"
)
func f() bool {
	if strings.HasPrefix(os.Getenv("DEPLOYMENT_MODE"), "in-vpc-") {
		return true
	}
	return false
}
`)

	// NEGATIVE CONTROLS, in the same tree, so a census that reported
	// everything would fail here rather than pass the seven above.
	//
	// (a) the same value in a LOG line, with a mode-named constant beside it.
	//     Two correct call sites were reported this way before the call shape
	//     was narrowed to results that decide something.
	write("platform/h/logonly.go", `package h
import (
	"log"
	"axonflow/platform/shared/deploymode"
)
func f() { log.Printf("mode=%q cat=%s", deploymode.Current(), deploymode.CategoryEnterprise) }
`)
	// (b) a mode value passed to a function that compares it against
	//     something that is NOT a mode name.
	write("platform/i/other.go", `package i
import "os"
func f() bool { return os.Getenv("DEPLOYMENT_MODE") == "not-a-mode" }
`)
	// (b2) a SHORT prefix. "co" is a prefix of `community` and `community-saas`
	//      but is overwhelmingly likely to be an unrelated string, which is why
	//      the prefix rule has a length floor. Without this the rule would turn
	//      the census into noise and the inventory into something nobody reads.
	write("platform/h2/shortprefix.go", `package h2
import (
	"os"
	"strings"
)
func f() bool { return strings.HasPrefix(os.Getenv("DEPLOYMENT_MODE"), "co") }
`)
	// (c) an unrelated package with its own Current(), and an unrelated
	//     empty-string comparison. This is logger.Sanitize's shape.
	write("platform/j/unrelated.go", `package j
import "strings"
func Current() string { return "x" }
func f(s string) string {
	if Current() == "" {
		return ""
	}
	return strings.ReplaceAll(s, "\x00", "")
}
`)
	// (d) a _test.go file with a real violation in it, which must be ignored.
	write("platform/k/x_test.go", `package k
import "os"
func TestX() bool { return os.Getenv("DEPLOYMENT_MODE") == "community" }
`)

	c, err := scanPostureReadings(root, []string{"platform", "ee"})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	got := map[string]bool{}
	for _, r := range c.readings {
		got[r.File] = true
	}
	for _, want := range []string{
		"platform/a/direct.go",
		"platform/b/consts.go",
		"platform/c/viacurrent.go",
		"platform/d/normalised.go",
		"platform/e/switched.go",
		"ee/platform/customer-portal/api/decide.go",
		"platform/g/call.go",
		"platform/p/pkgvar.go",
		"platform/q/maplookup.go",
		"platform/r/rangelist.go",
		"platform/s/taglessswitch.go",
		"platform/t/prefix.go",
		"platform/u/varmap.go",
		"platform/v/varlist.go",
	} {
		if !got[want] {
			t.Errorf("route not reported: %s. Every entry in this list is a way a mode value has "+
				"actually reached a comparison in this tree; one the census cannot follow is a class "+
				"of second reading it will never report, and its silence will read as a clean tree. "+
				"(reported: %v)", want, sortedKeys(got))
		}
	}
	for _, unwanted := range []string{
		"platform/h/logonly.go",
		"platform/h2/shortprefix.go",
		"platform/i/other.go",
		"platform/j/unrelated.go",
		"platform/k/x_test.go",
	} {
		if got[unwanted] {
			t.Errorf("negative control reported: %s. A census that reports correct code gets an "+
				"exemption written for it, and an exemption list padded with false positives is one "+
				"nobody reads. (reported: %v)", unwanted, sortedKeys(got))
		}
	}
}

// repoRoot resolves the repository root from this package's location.
func repoRoot(t *testing.T) string {
	t.Helper()
	base, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatalf("resolve repository root: %v", err)
	}
	// Prove it IS the root rather than trusting the relative hop: a wrong base
	// makes every scan root missing, and MissingRoots would then read as "the
	// community mirror" instead of "the test is looking in the wrong place".
	if _, err := os.Stat(filepath.Join(base, "platform", "shared", "deploymode")); err != nil {
		t.Fatalf("%s does not look like the repository root: %v", base, err)
	}
	return base
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// TestPostureCensusKnownBlindSpots states, as a measurement, the shapes this
// analysis does NOT follow.
//
// # WHY ASSERT A NEGATIVE
//
// This census is syntactic. It follows a mode value through assignments, string
// transforms, function parameters and package-level vars, and it stops where a
// value enters the heap: a struct field, a map value, a channel, a method on a
// receiver that carries it. Following those needs type information and an
// escape analysis, which is a different tool.
//
// Two further limits are recorded here rather than left to be discovered:
// a mode-family PREFIX shorter than four characters (`in-`), which the length
// floor in isModeFamilyPrefix trades away to keep the report readable; and the
// fact that every PACKAGE-LEVEL reading in one file shares the key `file#`, so
// a single exemption would cover all of them. No exemption is package-level
// today, which is the only reason the second is latent rather than a hole.
//
// A limit nobody wrote down is indistinguishable from a limit nobody has hit
// yet, and the guard's report reads as a clean tree in both cases. So the blind
// spots are planted and their CURRENT verdict is pinned. Two consequences, both
// wanted:
//
//   - a reader of the exemption inventory can see what the inventory does not
//     cover, rather than inferring completeness from its length;
//   - widening the analysis to catch one of these FAILS here, which forces the
//     improvement to be recorded rather than arriving silently.
//
// If you are here because this failed after you widened the census: delete the
// case you fixed and add it to TestPostureCensusSeesEachDerivationRoute.
func TestPostureCensusKnownBlindSpots(t *testing.T) {
	root := t.TempDir()
	write := func(rel, body string) {
		full := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatalf("plant %s: %v", rel, err)
		}
		if err := os.WriteFile(full, []byte(body), 0o600); err != nil {
			t.Fatalf("plant %s: %v", rel, err)
		}
	}

	// The mode stored in a STRUCT FIELD and compared off it.
	write("platform/bs1/structfield.go", `package bs1
import "os"
type cfg struct{ Mode string }
func f() bool {
	c := cfg{Mode: os.Getenv("DEPLOYMENT_MODE")}
	return c.Mode == "community"
}
`)
	// The mode carried by a RECEIVER and compared inside a method.
	write("platform/bs2/method.go", `package bs2
import "os"
type holder struct{ m string }
func (h holder) isCommunity() bool { return h.m == "community" }
func f() bool { return holder{m: os.Getenv("DEPLOYMENT_MODE")}.isCommunity() }
`)
	// The mode passed through a CHANNEL.
	write("platform/bs3/channel.go", `package bs3
import "os"
func f() bool {
	ch := make(chan string, 1)
	ch <- os.Getenv("DEPLOYMENT_MODE")
	return <-ch == "community"
}
`)

	// A POSITIVE CONTROL in the same tree. Without it, a scan that broke
	// entirely would satisfy every "not reported" assertion below and this test
	// would certify blindness it did not measure.
	write("platform/bs0/control.go", `package bs0
import "os"
func f() bool { return os.Getenv("DEPLOYMENT_MODE") == "community" }
`)

	// A 3-CHARACTER FAMILY PREFIX. `in-` partitions all four in-vpc-* modes and
	// is a real derivation, but isModeFamilyPrefix has a length floor of 4 so a
	// one- or two-character prefix cannot flood the report. The floor is a
	// judgement, and this is where its cost is written down.
	write("platform/bs4/shortfamily.go", `package bs4
import (
	"os"
	"strings"
)
func f() bool { return strings.HasPrefix(os.Getenv("DEPLOYMENT_MODE"), "in-") }
`)

	c, err := scanPostureReadings(root, []string{"platform"})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	// A PER-FILE FLOOR, not just a global one. scanPostureReadings SWALLOWS a
	// parse error and drops the file, so a later edit that breaks one of these
	// fixtures would make its "not reported" assertion pass vacuously while the
	// control still reports - a control against a globally broken scan cannot
	// see a locally inert plant.
	if c.Files != 5 {
		t.Fatalf("the scan parsed %d files, want 5. A fixture that fails to parse is silently "+
			"dropped, and its blind-spot assertion below would then hold against nothing.", c.Files)
	}
	got := map[string]bool{}
	for _, r := range c.readings {
		got[r.File] = true
	}
	if !got["platform/bs0/control.go"] {
		t.Fatalf("the positive control was not reported (reported: %v). The scan is broken, so the "+
			"'not reported' assertions below would pass against nothing.", sortedKeys(got))
	}
	for _, blind := range []string{
		"platform/bs1/structfield.go",
		"platform/bs2/method.go",
		"platform/bs3/channel.go",
		"platform/bs4/shortfamily.go",
	} {
		if got[blind] {
			t.Errorf("%s IS now reported. That is an improvement, not a regression: move it into "+
				"TestPostureCensusSeesEachDerivationRoute and delete it here, so the list of things "+
				"this census cannot see stays true.", blind)
		}
	}
}
