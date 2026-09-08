// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package edition

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// updateCensus regenerates twin_census.tsv from the tree instead of checking
// against it. THIS FLAG IS THE COMMITTED GENERATOR: the census and the guard
// read the tree through the same code, so a generator that drifts from its
// checker is not possible.
//
//	go test ./shared/edition -run TestTwinCensusMatchesTree -update
//
//go:generate go test . -run TestTwinCensusMatchesTree -update
var updateCensus = flag.Bool("update", false, "regenerate twin_census.tsv from the current tree")

// TestTwinCensusMatchesTree is the guard. It refuses an undeclared pair.
//
// It deliberately does NOT compare the two copies of a pair and call equality
// safety — getPluginCompatibility()'s comment records that such a test was
// tried and is not sufficient, because two copies that are equal and wrong
// pass it and a reformat breaks it. What this asserts instead:
//
//  1. every pair the TREE contains carries a row (the 34th pair cannot arrive
//     unnoticed);
//  2. every row's disposition equals the one ProposeDisposition derives from
//     the tree, so drift cannot be relabelled as an intended boundary to slip
//     under a ratchet;
//  3. a collapsed pair stays collapsed;
//  4. a row cannot outlive the pair it describes;
//  5. each of the three kept buckets only shrinks.
func TestTwinCensusMatchesTree(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	root, err := FindRepoRoot(wd)
	if err != nil {
		t.Fatalf("locate repo root: %v", err)
	}

	if *updateCensus {
		regenerate(t, root)
		return
	}

	// THE DERIVATION MUST NOT LIE, and this is the assertion that makes a lie
	// RED rather than silent.
	//
	// Everything below keys on IsCommunityMirror. If the enterprise tree ever
	// read as the mirror - sync-community-repo.yml renamed, moved, or split -
	// this test would SKIP exactly where it was written to run, and a skipped
	// required context is SATISFIED. Nothing else in the file would notice,
	// because every downstream branch would be taking the mirror path
	// correctly for what it had been told.
	//
	// ee/ present is the one fact the two editions cannot both have: the sync
	// excludes ee/ wholesale and the simulation asserts it never arrives. So a
	// tree with ee/ that derives as the mirror is a broken derivation, and it
	// fails here instead of quietly excusing itself.
	if HasEETree(root) && IsCommunityMirror(root) {
		t.Fatalf("the edition derivation says COMMUNITY MIRROR but ee/platform exists on this tree. " +
			"The marker is lint.yml present + sync-community-repo.yml absent; one of those has moved, " +
			"so this guard would SKIP on the enterprise tree it was written for - and a skipped " +
			"required context is satisfied. Fix the marker, not this assertion.")
	}

	// THE CENSUS IS NOT SYNCED. It names 45 platform paths whose ee counterpart
	// is private and whose platform copy the sync STRIPS (they are
	// enterprise-tagged), so on the mirror those paths are not merely absent -
	// their absence is the edition boundary itself, and a file listing them is
	// the metadata that boundary exists to withhold (master's ruling, #3725).
	//
	// So on the mirror this test SKIPS, loudly and with the reason. It is not a
	// loss: the mirror has no ee/, so "no path exists at both platform/X and
	// ee/platform/X" cannot fail there. On the ENTERPRISE tree an absent census
	// stays FATAL - that is the tree the guard was written for, and a missing
	// subject there is a deleted guard, not a mirror.
	if _, statErr := os.Stat(filepath.Join(root, CensusPath)); os.IsNotExist(statErr) {
		if IsCommunityMirror(root) {
			t.Skipf("community mirror: %s is excluded from the sync (it names enterprise-only "+
				"platform paths the sync strips). Nothing is lost - this tree has no ee/, so no pair "+
				"can exist here and the assertion has no subject. The census is enforced on the "+
				"enterprise tree, where both copies exist.", CensusPath)
		}
		t.Fatalf("%s is absent on a tree that is not the community mirror (lint.yml present + "+
			"sync-community-repo.yml absent is the marker). On the enterprise tree the census is "+
			"the guard's whole subject; a missing one is a deleted guard.", CensusPath)
	}

	rows, err := LoadCensus(root)
	if err != nil {
		t.Fatalf("load census: %v", err)
	}

	// ---------------------------------------------------------------------
	// Anti-vacuity. A census that parsed to nothing, or a walk that reached
	// nothing, must fail rather than pass quietly. These floors bound "the
	// scan stopped reaching"; everything below bounds "the scan decided
	// something different".
	// ---------------------------------------------------------------------
	if len(rows) == 0 {
		t.Fatal("twin_census.tsv parsed to zero rows; the census cannot be empty while the guard claims to enforce it")
	}

	counts := map[Disposition]int{
		DispositionCollapsed:    0,
		DispositionKeepTwin:     0,
		DispositionKeepDrift:    0,
		DispositionKeepBoundary: 0,
	}
	byPath := make(map[string]Row, len(rows))
	for _, r := range rows {
		if _, dup := byPath[r.PlatformPath]; dup {
			t.Errorf("duplicate census row for %s", r.PlatformPath)
		}
		byPath[r.PlatformPath] = r
		if _, ok := counts[r.Disposition]; !ok {
			t.Errorf("%s: disposition %q is not one of collapsed / keep-twin / keep-drift / keep-boundary",
				r.PlatformPath, r.Disposition)
			continue
		}
		counts[r.Disposition]++
		if r.Reason == "" {
			t.Errorf("%s: empty reason; every row states why it is where it is", r.PlatformPath)
		}
		if r.Reason == GeneratorPlaceholderReason {
			t.Errorf("%s: the reason is still the -update generator's placeholder %q. A pair cannot "+
				"enter the census without a human saying why the two copies must both exist — "+
				"otherwise regenerating launders a new fork into a passing board, and the count "+
				"ratchets cannot see it because they count rows, not the set.",
				r.PlatformPath, GeneratorPlaceholderReason)
		}
	}

	// ---------------------------------------------------------------------
	// The census, printed unconditionally and including its zeros, so a
	// reader can tell "nothing is forked" from "this build forgot to look".
	// ---------------------------------------------------------------------
	t.Logf("twin census: %d row(s) — collapsed=%d keep-twin=%d/%d keep-drift=%d/%d keep-boundary=%d/%d",
		len(rows), counts[DispositionCollapsed],
		counts[DispositionKeepTwin], MaxKeepTwinRows,
		counts[DispositionKeepDrift], MaxKeepDriftRows,
		counts[DispositionKeepBoundary], MaxKeepBoundaryRows)

	// THE SET, not just the counts. A swap leaves every count unmoved.
	gotDigest := KeptSetDigestOf(rows)
	t.Logf("kept-set digest: %s", gotDigest)
	if gotDigest != KeptSetDigest {
		t.Errorf("kept-set digest is %s, KeptSetDigest pins %s. The SET of kept pairs changed, which "+
			"the count ratchets cannot see: removing one pair and adding another leaves every count "+
			"identical. If this is a real resolution, regenerate, then update KeptSetDigest and the "+
			"matching ratchet — the diff will show exactly which paths moved.", gotDigest, KeptSetDigest)
	}

	// The collapsed bucket is a FLOOR, and it is asserted rather than printed.
	if counts[DispositionCollapsed] < MinCollapsedRows {
		t.Errorf("collapsed rows: %d < MinCollapsedRows=%d. Collapsed rows are the record of what was "+
			"removed and may only grow: deleting one disarms the COLLAPSED PAIR CAME BACK and MOVED "+
			"checks for that path. If a collapsed file was deleted outright, say so and lower the floor.",
			counts[DispositionCollapsed], MinCollapsedRows)
	}

	ratchet(t, "keep-twin", counts[DispositionKeepTwin], MaxKeepTwinRows, "MaxKeepTwinRows")
	ratchet(t, "keep-drift", counts[DispositionKeepDrift], MaxKeepDriftRows, "MaxKeepDriftRows")
	ratchet(t, "keep-boundary", counts[DispositionKeepBoundary], MaxKeepBoundaryRows, "MaxKeepBoundaryRows")

	// ---------------------------------------------------------------------
	// The community mirror strips ee/ wholesale AND deletes every
	// enterprise-tagged Go file the rsync chain admitted, so on that tree
	// neither side of most pairs survives. Say what cannot be checked rather
	// than passing on assertions that have no subject there.
	// ---------------------------------------------------------------------
	if !HasEETree(root) {
		if _, err := os.Stat(filepath.Join(root, "ee")); err == nil {
			t.Error("ee/ exists but ee/platform does not; this tree is neither the enterprise repo nor the mirror")
		}
		t.Log("community mirror: ee/ is absent, so no pair can exist here. CHECKED: the census parses, " +
			"every row has a known disposition and a reason, no path is listed twice, and all three " +
			"ratchets hold. NOT CHECKED here, for want of a subject: per-pair population, disposition " +
			"against the tree, collapsed pairs staying collapsed, and kept rows still having a pair.")
		return
	}

	// ---------------------------------------------------------------------
	// THE 34th PAIR, and the disposition the tree itself implies.
	// ---------------------------------------------------------------------
	twins, err := DiscoverTwins(root)
	if err != nil {
		t.Fatalf("discover twins: %v", err)
	}
	if len(twins) == 0 {
		t.Fatal("the walk found zero pairs on a tree that has ee/platform; discovery is not reaching the tree")
	}
	t.Logf("tree walk: %d path(s) present at both platform/X and ee/platform/X", len(twins))

	seen := make(map[string]bool, len(twins))
	for _, p := range twins {
		seen[p] = true
		row, ok := byPath[p]
		if !ok {
			t.Errorf("UNDECLARED PAIR: %s exists at both platform/ and ee/platform/ and has no census row.\n"+
				"    Either collapse it (delete the ee copy) or add a row saying which copy the overlaid\n"+
				"    image runs and why the two must differ. Regenerate with:\n"+
				"        go test ./shared/edition -run TestTwinCensusMatchesTree -update", p)
			continue
		}
		if row.Disposition == DispositionCollapsed {
			t.Errorf("COLLAPSED PAIR CAME BACK: %s is recorded collapsed but ee/%s exists again.\n"+
				"    The ee copy was removed because it was the same source as the platform copy;\n"+
				"    re-adding it restores the drift this lane removed (#3725).", p, p)
			continue
		}
		wantDisp, pop, lineDelta, codeDelta, err := ProposeDisposition(root, p)
		if err != nil {
			t.Errorf("%s: classify: %v", p, err)
			continue
		}
		if row.Disposition != wantDisp {
			t.Errorf("%s: census records disposition %q but the tree implies %q. Disposition is derived, "+
				"not chosen — see ProposeDisposition. Regenerate with -update and re-read the reason.",
				p, row.Disposition, wantDisp)
		}
		if pop != row.Population || lineDelta != row.LineDelta || codeDelta != row.CodeDelta {
			t.Errorf("%s: census says population=%s line_delta=%d code_delta=%d; tree says population=%s "+
				"line_delta=%d code_delta=%d. The pair moved — re-read the reason, then regenerate with -update.",
				p, row.Population, row.LineDelta, row.CodeDelta, pop, lineDelta, codeDelta)
		}
	}

	// ---------------------------------------------------------------------
	// A row cannot outlive the pair it describes.
	// ---------------------------------------------------------------------
	for _, r := range rows {
		platformExists := fileExists(filepath.Join(root, r.PlatformPath))
		eeExists := fileExists(filepath.Join(root, "ee", r.PlatformPath))
		switch r.Disposition {
		case DispositionCollapsed:
			if eeExists {
				// Reported by the walk above ONLY when both copies exist.
				// When the platform copy was moved to ee/ instead of the ee
				// copy being re-added, the path is not a pair at all, so
				// DiscoverTwins never saw it and nothing reported it. That is
				// strictly worse than the pre-collapse state, because the
				// Dockerfile branches that used to copy those directories were
				// removed with them: the file would be in ee/ and in no image.
				if !seen[r.PlatformPath] {
					t.Errorf("COLLAPSED PAIR MOVED: %s is recorded collapsed, the platform copy is "+
						"gone (present=%v) and ee/%s exists. The collapse kept the PLATFORM copy as "+
						"the single copy. For agent/rbi, agent/circuitbreaker and agent/connectors "+
						"this puts the file in NO enterprise image, because the overlay branch for "+
						"those directories was removed with the ee copy; for the rest it is in the "+
						"image but absent from every platform-module test.",
						r.PlatformPath, platformExists, r.PlatformPath)
				}
				continue
			}
			if !platformExists {
				t.Errorf("STALE ROW: %s is recorded collapsed but the platform copy is gone too. The "+
					"collapse kept the platform copy as the single copy; if the file was deleted "+
					"outright, delete the row.", r.PlatformPath)
			}
		default:
			if !seen[r.PlatformPath] {
				t.Errorf("STALE ROW: %s is recorded %s but is no longer a pair (platform copy present=%v, "+
					"ee copy present=%v). Delete the row and lower the matching ratchet.",
					r.PlatformPath, r.Disposition, platformExists, eeExists)
			}
		}
	}
}

// ratchet fails in BOTH directions. Above the cap is the class regenerating.
// Below it means a divergence was resolved and the constant is now stale — a
// ratchet nobody tightens stops being one.
func ratchet(t *testing.T, name string, got, max int, constName string) {
	t.Helper()
	switch {
	case got > max:
		t.Errorf("%s rows: %d > %s=%d. A new pair of this kind is the class regenerating, not a new "+
			"baseline: resolve it and delete the row. Raising %s needs the reason recorded on #3725.",
			name, got, constName, max, constName)
	case got < max:
		t.Errorf("%s rows: %d < %s=%d. A pair was resolved — good — now LOWER %s to %d so the ratchet "+
			"holds the new floor.", name, got, constName, max, constName, got)
	}
}

func fileExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && !fi.IsDir()
}

// regenerate rewrites twin_census.tsv from the tree. Rows for pairs that still
// exist are re-derived; rows recorded collapsed are carried forward, because a
// collapsed pair has no ee copy left to classify and the row is the record of
// what was removed. Reasons already written are preserved.
func regenerate(t *testing.T, root string) {
	t.Helper()
	if !HasEETree(root) {
		t.Fatal("-update needs the enterprise tree; ee/platform is absent")
	}
	existing := map[string]Row{}
	if rows, err := LoadCensus(root); err == nil {
		for _, r := range rows {
			existing[r.PlatformPath] = r
		}
	}

	twins, err := DiscoverTwins(root)
	if err != nil {
		t.Fatalf("discover twins: %v", err)
	}
	live := map[string]bool{}
	var out []Row
	for _, p := range twins {
		live[p] = true
		disp, pop, lineDelta, codeDelta, err := ProposeDisposition(root, p)
		if err != nil {
			t.Fatalf("%s: classify: %v", p, err)
		}
		row := Row{
			PlatformPath: p, Population: pop, LineDelta: lineDelta, CodeDelta: codeDelta,
			Disposition: disp, Reason: "TODO: state why both copies must exist",
		}
		if prev, ok := existing[p]; ok && prev.Reason != "" && prev.Disposition == disp {
			row.Reason = prev.Reason
		}
		out = append(out, row)
	}
	var carried []string
	for p, r := range existing {
		if r.Disposition == DispositionCollapsed && !live[p] {
			out = append(out, r)
			carried = append(carried, p)
		}
	}
	sort.Strings(carried)

	path := filepath.Join(root, CensusPath)
	if err := os.WriteFile(path, RenderCensus(out), 0o644); err != nil {
		t.Fatalf("write census: %v", err)
	}
	fmt.Printf("regenerated %s: %d live pair(s) + %d carried-forward collapsed row(s)\n",
		CensusPath, len(twins), len(carried))
}
