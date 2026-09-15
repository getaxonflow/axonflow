// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package identity

// The controls on the #3878 census: proof that it can report a site, and the
// reachability measurement that sizes the correction's cost.

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"axonflow/platform/testutil/gocensus"
)

// plantedBadComparisons is a source file planted into THIS package.
//
// Each declaration is one spelling the class has actually taken. Two are
// verbatim shapes of instances found on main - `hop == p` on a comparable
// struct, and a set keyed on a rendered identifier - and the rest are the
// spellings a future author is most likely to reach for.
const plantedBadComparisons = `package identity

import "axonflow/platform/decision/contract"

func plantedStructEquality(a, b PrincipalID) bool { return a == b }

func plantedRenderedEquality(a, b PrincipalID) bool { return a.String() != b.String() }

func plantedClassifiedSet(ps []PrincipalID) int {
	seen := map[PrincipalID]struct{}{}
	for _, p := range ps {
		seen[p] = struct{}{}
	}
	return len(seen)
}

func plantedRenderedSet(ids []contract.ID) int {
	seen := map[string]struct{}{}
	for _, id := range ids {
		seen[id.String()] = struct{}{}
	}
	return len(seen)
}

func plantedContractEquality(a, b contract.ID) bool { return a == b }
`

// plantedCleanSource is the negative half.
//
// WITHOUT IT, A SCANNER THAT REPORTED EVERY EXPRESSION would pass the planted
// half perfectly. These are comparisons in the same file shapes over values
// that are not identifiers - including a POINTER to a struct that contains
// one, which is the shape that produced forty rows of noise in the first draft
// and is the reason the type walk does not follow a pointer.
const plantedCleanSource = `package identity

type plantedHolder struct {
	P    PrincipalID
	Name string
}

func plantedStringEquality(a, b string) bool { return a == b }

func plantedPointerEquality(h *plantedHolder) bool { return h == nil }

func plantedFieldEquality(h plantedHolder, n string) bool { return h.Name == n }

func plantedOrdering(a, b PrincipalID) bool { return a.String() < b.String() }
`

// TestTheCensusReportsAPlantedComparison drives the census from zero to one.
//
// A census that enumerated nothing would report a clean tree, and a green
// census is exactly what that looks like. This type-checks THIS package with a
// planted file added in memory and requires every planted site to be reported,
// requires the clean file to add none, and requires the same scan WITHOUT the
// plant to report none of them - so the reporting is attributable to the plant
// rather than to something already in the package.
//
// NOTHING IS WRITTEN TO THE TREE. The sources above are parsed from memory; a
// harness that plants by editing a file in a shared clone can be killed
// between the plant and the restore, and the next run then treats the plant as
// the baseline.
func TestTheCensusReportsAPlantedComparison(t *testing.T) {
	root := gocensus.RepoRoot(t)
	modules := gocensus.DiscoverModules(t, root, platformModule, decisionModule)
	platformDir, ok := modules[platformModule]
	if !ok {
		t.Fatalf("module %q was not discovered under %s", platformModule, root)
	}

	scanner, err := gocensus.Load(platformDir, "")
	if err != nil {
		t.Fatalf("resolving %s: %v", platformModule, err)
	}
	const pkg = "axonflow/platform/shared/identity"

	scan := func(extra map[string]string) map[censusKey]comparisonSite {
		t.Helper()
		// A PLANT MUST NOT SHADOW A REAL FILE. The name is only a parser
		// label - nothing is written - but if the tree ever gained a file of
		// the same name, the fset would hold two entries for one path and the
		// control would be reading a mixture of both.
		for name := range extra {
			if _, err := os.Stat(filepath.Join(scanner.Dir(pkg), name)); err == nil {
				t.Fatalf("a real file named %s exists in %s; the plant would shadow it", name, pkg)
			}
		}
		files, _, perr := scanner.Parse(pkg, extra)
		if perr != nil {
			t.Fatalf("parsing %s: %v", pkg, perr)
		}
		sites, terr := scanPackageFiles(scanner.Fset, scanner.Importer, pkg, platformModule, files)
		if terr != nil {
			t.Fatalf("type-checking %s with %d planted file(s): %v", pkg, len(extra), terr)
		}
		out := map[censusKey]comparisonSite{}
		for _, s := range sites {
			out[keyOf(s)] = s
		}
		return out
	}

	// THE BASELINE MUST NOT BE EMPTY. If it were, every assertion below could
	// be satisfied by a scanner that reports its input and nothing else.
	baseline := scan(nil)
	if len(baseline) == 0 {
		t.Fatal("the unplanted scan of this package found no comparison sites at all; the plant below would prove nothing")
	}

	want := []censusKey{
		{pkg, "plantedStructEquality", formCompare, "a == b"},
		{pkg, "plantedRenderedEquality", formCompareRendered, "a.String() != b.String()"},
		{pkg, "plantedClassifiedSet", formMapKey, "map[PrincipalID]struct{}"},
		{pkg, "plantedRenderedSet", formKeyRendered, "seen[id.String()]"},
		{pkg, "plantedContractEquality", formCompare, "a == b"},
	}
	// The two `a == b` rows differ only in their enclosing declaration, which
	// is the point: the key has to separate two identically-spelled
	// comparisons in two functions, or a swap between them would be invisible.
	for _, k := range want {
		if _, already := baseline[k]; already {
			t.Fatalf("%s is reported WITHOUT the plant, so finding it below would not be attributable to the plant", k)
		}
	}

	planted := scan(map[string]string{"zz_planted_bad.go": plantedBadComparisons})
	var missed []string
	for _, k := range want {
		if _, ok := planted[k]; !ok {
			missed = append(missed, "  "+k.String())
		}
	}
	if len(missed) > 0 {
		sort.Strings(missed)
		t.Errorf("the census did not report %d planted comparison(s):\n%s\nA census that cannot see these cannot see the next instance of the class either.",
			len(missed), strings.Join(missed, "\n"))
	}

	// AND THE CENSUS'S OWN REPORTING BRANCH IS DRIVEN, not inferred. Finding
	// the planted sites proves the SCANNER works; it says nothing about the
	// guard that turns an unclassified site into a failure, and that branch is
	// never reached on a healthy tree. Here it is fed the planted scan and
	// required to name every planted site as unclassified.
	unknown := unclassifiedSites(planted, classifiedIndex(t))
	for _, k := range want {
		var named bool
		for _, line := range unknown {
			if strings.Contains(line, k.Expr) && strings.Contains(line, k.Decl) {
				named = true
			}
		}
		if !named {
			t.Errorf("the census's unclassified report does not name the planted site %s; the scanner found it and "+
				"the guard would have stayed green, which is the failure this control exists to catch:\n%s",
				k, strings.Join(unknown, "\n"))
		}
	}

	// THE SECOND REPORTING BRANCH IS DRIVEN TOO. Staleness fires when a
	// classified row stops being found, which on a healthy tree is never - so
	// nothing else proves it can. One real row is withheld from the found set
	// and the branch must name it, and the same call with nothing withheld
	// must name nothing.
	classified := classifiedIndex(t)
	withheld := censusKey{
		Pkg: pkg, Decl: "(ActorChain).ContainsSubject", Form: formIdentity, Expr: "hop.SameSubject(p)",
	}
	if _, ok := classified[withheld]; !ok {
		t.Fatalf("the row chosen to withhold, %s, is not in the inventory, so this control tests nothing", withheld)
	}
	if _, ok := baseline[withheld]; !ok {
		t.Fatalf("the row chosen to withhold, %s, is not found by the scan either, so withholding it changes nothing", withheld)
	}
	// SCOPED TO THE ROWS THIS SCAN ACTUALLY FOUND. The baseline runs under the
	// COMMUNITY tag set, so the package's enterprise-only rows are legitimately
	// absent from it; scoping by package instead would report those twenty as
	// stale and the control would be measuring the tag split rather than the
	// branch.
	foundHere := func(key censusKey, _ censusRow) bool {
		_, ok := baseline[key]
		return ok
	}
	if reported := staleRows(baseline, classified, foundHere); len(reported) > 0 {
		t.Errorf("the staleness branch reported %d row(s) against the very scan they were taken from:\n%s",
			len(reported), strings.Join(reported, "\n"))
	}
	incomplete := map[censusKey]comparisonSite{}
	for k, v := range baseline {
		if k != withheld {
			incomplete[k] = v
		}
	}
	reported := staleRows(incomplete, classified, foundHere)
	if len(reported) != 1 || !strings.Contains(reported[0], withheld.Expr) {
		t.Errorf("withholding %s produced %v; the staleness branch did not name the row that stopped being found",
			withheld, reported)
	}

	// THE CLEAN CONTROL. A scanner that reported everything would satisfy
	// every assertion above.
	clean := scan(map[string]string{"zz_planted_clean.go": plantedCleanSource})
	var spurious []string
	for k := range clean {
		if _, ok := baseline[k]; ok {
			continue
		}
		spurious = append(spurious, "  "+k.String())
	}
	if len(spurious) > 0 {
		sort.Strings(spurious)
		t.Errorf(`the census reported %d site(s) from a file that compares no identifiers:

%s
An ordering, a pointer-to-nil, a string field and a plain string are not
identity comparisons. Reporting them would make the inventory a place to put
noise, which is how a classification stops being read.`, len(spurious), strings.Join(spurious, "\n"))
	}
}

// approvalPathAPI is the ADR-065 approver-pool and chain-admission surface
// whose reachability decides how much the #3878 correction costs a running
// deployment.
var approvalPathAPI = map[string]bool{
	"axonflow/platform/shared/identity.ApproverQuorumReachable": true,
	"axonflow/platform/shared/identity.EligibleApprovers":       true,
	"axonflow/platform/shared/identity.InteractiveMembers":      true,
	"axonflow/platform/shared/identity.ValidateApproverPool":    true,
	"axonflow/platform/shared/identity.AdmitChain":              true,
	"axonflow/platform/shared/identity.VerifyChain":             true,
	// The two exported chain functions state the root rule and delegate here,
	// so these are where chain admission actually runs.
	"axonflow/platform/shared/identity.admitChain":  true,
	"axonflow/platform/shared/identity.verifyChain": true,
}

// approvalPathInternalCallers are the references that exist inside this
// package: each function's own single internal consumer. Nothing else in the
// tree may reference any of them without this test being reconsidered.
var approvalPathInternalCallers = map[reference]string{
	{Pkg: "axonflow/platform/shared/identity", Decl: "ApproverQuorumReachable",
		Target: "axonflow/platform/shared/identity.EligibleApprovers"}: "the quorum arithmetic is taken over the eligible set",
	{Pkg: "axonflow/platform/shared/identity", Decl: "EligibleApprovers",
		Target: "axonflow/platform/shared/identity.InteractiveMembers"}: "the interactive filter runs before self-exclusion",
	{Pkg: "axonflow/platform/shared/identity", Decl: "AdmitChain",
		Target: "axonflow/platform/shared/identity.admitChain"}: "the exported admission is the unexported one with ADR-065 invariant 2's root rule stated",
	{Pkg: "axonflow/platform/shared/identity", Decl: "VerifyChain",
		Target: "axonflow/platform/shared/identity.verifyChain"}: "the exported verification is the unexported one with ADR-065 invariant 2's root rule stated",
	{Pkg: "axonflow/platform/shared/identity", Decl: "verifyChain",
		Target: "axonflow/platform/shared/identity.admitChain"}: "per-credential facts are composed with per-chain facts",
	// THE PRODUCTION CALLER, reviewed (#3895 PR-A2, master ruling A: reuse
	// AdmitChain and name it here). Every enforcing seam admits its request
	// subject through the identity plane's own pipeline: a user through
	// AdmitDecisionSubject, and since the 2026-09-11 (third) amendment a request
	// that carries no user identity through AdmitCredentialSubject. Both reach
	// chain verification here and nowhere else.
	{Pkg: "axonflow/platform/shared/identity", Decl: "(*SubjectAdmitter).admitSubject",
		Target: "axonflow/platform/shared/identity.verifyChain"}: "every enforcing seam verifies a ONE-credential " +
		"chain, so it reaches chain admission only: realm, subject type, cycle and delegation checks over hop subjects. " +
		"None of ApproverQuorumReachable, EligibleApprovers, InteractiveMembers or ValidateApproverPool is reached, so no " +
		"approver pool or quorum is evaluated on any plane and #3878's pool-size consequence is still not live",
}

// TestNoProductionCallerReachesTheApprovalAndChainAdmissionPath is the
// measurement that sizes #3878's correction, and the condition under which it
// has to be re-read.
//
// # WHY THE MEASUREMENT MATTERS
//
// Widening self-exclusion shrinks the approver pool, so a quorum that is
// reachable today can stop being reachable - and on a request-time path, an
// unreachable quorum is an escalation nobody can answer. #3878 asked for that
// to be sized rather than argued. The size is this: NO shipped code path
// reaches ApproverQuorumReachable, EligibleApprovers or ValidateApproverPool.
// Until #3895 PR-A2, AdmitChain was reached only from VerifyChain, which
// nothing called. Since then the decide plane's enforcing seam calls
// VerifyChain through SubjectAdmitter.AdmitDecisionSubject for a ONE-credential
// chain, which exercises chain admission and no approver pool, so no
// deployment's quorum can change yet. The approver-pool half of the surface is
// still unwired (#3551), and the correction still lands before it is.
//
// # WHY IT IS A TEST AND NOT A PARAGRAPH IN A PR BODY
//
// The paragraph is true on the day it is written. This is the REVISIT
// CONDITION, and it is a named observable: the day a plane wires the approval
// surface, this test fails and tells that author that the rollout consequence
// recorded here has just become live for every deployment. A deliberate gap
// with no observable is a gap nobody looks at again.
//
// IT READS types.Info.Uses, NOT CALL SYNTAX, so a function taken as a value
// and called indirectly still counts as a reference. "Nothing reaches this"
// has to survive an indirection or it is a claim about a spelling.
func TestNoProductionCallerReachesTheApprovalAndChainAdmissionPath(t *testing.T) {
	root := gocensus.RepoRoot(t)
	modules := gocensus.DiscoverModules(t, root, platformModule, decisionModule)

	seen := map[reference]bool{}
	scanned := 0
	for _, modPath := range sortedKeys(modules) {
		for _, tags := range gocensus.TagSets {
			refs, failures, err := scanReferences(modules[modPath], tags, approvalPathAPI)
			if err != nil {
				if _, declared := gocensus.Unscannable(modules)[modPath+"|"+tags]; declared {
					continue
				}
				t.Errorf("module %q under tags %q could not be scanned for callers: %v", modPath, tags, err)
				continue
			}
			for _, f := range failures {
				t.Errorf("module %q under tags %q: %s; a package this scan cannot read is a package it reports as having no callers", modPath, tags, f)
			}
			scanned++
			for _, r := range refs {
				seen[r] = true
			}
		}
	}
	if scanned == 0 {
		t.Fatal("no module was scanned; a caller census over nothing reports no callers")
	}

	// THE POSITIVE CONTROL IS BUILT IN. The three internal edges below are
	// real references that this scan must find; if it finds none of them, it
	// is not looking, and its silence about external callers means nothing.
	for want, why := range approvalPathInternalCallers {
		if !seen[want] {
			t.Errorf("the caller scan did not find the known reference %s -> %s (%s). "+
				"An instrument that cannot find a reference it is standing on cannot report the absence of one.",
				want.Decl, want.Target, why)
		}
	}

	var external []string
	for r := range seen {
		if _, known := approvalPathInternalCallers[r]; known {
			continue
		}
		external = append(external, fmt.Sprintf("  %s.%s -> %s", r.Pkg, r.Decl, r.Target))
	}
	if len(external) > 0 {
		sort.Strings(external)
		t.Errorf(`the approver-pool and chain-admission surface now has %d reference(s) beyond its own package:

%s
READ THIS BEFORE CHANGING THE TEST. Beyond the reviewed references recorded in
approvalPathInternalCallers nothing reaches this surface - the decide seam's
one-credential chain admission is the only production caller, and it evaluates
no approver pool - and that is what keeps #3878's correction free: widening self-exclusion by SUBJECT
strikes more members out of an approver pool, so a deployment whose quorum
equals its answerable pool size can go from reachable to QUORUM_UNREACHABLE.
With a plane wired, that consequence is live for every deployment using it.

What is owed at that point, and was deliberately deferred:
  - a count, on a real tenant's configuration, of pool members the corrected
    comparison strikes out that the old one did not;
  - whether any configured quorum becomes unreachable as a result;
  - a release note, because the behaviour change is operator-visible.

TestWideningSelfExclusionCanMakeAQuorumUnreachable already asserts the shape.
Then update approvalPathInternalCallers to record the new reference.`, len(external), strings.Join(external, "\n"))
	}
}
