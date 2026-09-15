// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// TestGrantedTablesScriptAgreesWithTheGoCensus holds the TWO readers of the
// same property equal.
//
// runtime-e2e/3636_forcerls_grants/granted_tables.py answers the same question
// TestEveryForceRLSTableHasAnApplicationGrant answers - which tables a
// migration GRANTs to an application role - because the two legs need it in
// different places: the census runs on every commit against the tree, and the
// suite runs against a BOOTED stack, where the forced set comes from
// has_table_privilege and the file list comes from that deployment's own
// schema_migrations. Neither can borrow the other's answer at the moment it
// needs it.
//
// Two implementations of one property is the actual hazard here, and it is not
// hypothetical: a reimplementation that AGREES on today's tree is
// indistinguishable from a correct one, and the day they diverge the E2E leg
// starts reporting a verdict the census does not share - in whichever direction
// is less visible. So the agreement is ASSERTED rather than assumed, over the
// same file list, as sets.
//
// The Go side is computed by calling the census's OWN helpers and regexes
// rather than by restating them, so this test cannot drift from the census it
// is anchoring; only the Python can drift, which is the direction that matters.
func TestGrantedTablesScriptAgreesWithTheGoCensus(t *testing.T) {
	root, err := findRepoRoot()
	if err != nil {
		t.Fatalf("locate repo root: %v", err)
	}
	// INAPPLICABLE AND MISSING ARE DIFFERENT ANSWERS, and this file is mirrored
	// while its subject is not. sync-community-repo.yml excludes `runtime-e2e/`
	// wholesale, so on the community mirror the script this test anchors does
	// not exist and cannot - a guard that syncs to the mirror has to prove
	// itself on the mirror's own inputs, and one that Fatal'd there would red
	// the mirror board for a property that tree cannot hold.
	//
	// The two states are told apart by the DIRECTORY, not by the file: no
	// `runtime-e2e/` at all is the mirror, where there is nothing to anchor. A
	// `runtime-e2e/` that exists WITHOUT the script is this repository with the
	// suite's reader moved or deleted, which is exactly the drift this test is
	// for and stays a hard failure.
	suiteRoot := filepath.Join(root, "runtime-e2e")
	if _, err := os.Stat(suiteRoot); os.IsNotExist(err) {
		t.Log("runtime-e2e/ is absent, so this is the community mirror and the script half of " +
			"this property does not exist here; nothing to anchor")
		return
	}
	script := filepath.Join(suiteRoot, "3636_forcerls_grants", "granted_tables.py")
	if _, err := os.Stat(script); err != nil {
		// Not a skip. The script IS the E2E suite's reader; if it has moved,
		// the suite is reading something this test never checked.
		t.Fatalf("granted_tables.py not found at %s, while runtime-e2e/ is present: %v", script, err)
	}
	python, err := exec.LookPath("python3")
	if err != nil {
		// Also not a skip: the suite this anchors cannot run without python3
		// either, so an environment lacking it cannot verify the property at
		// all and should say so rather than report clean.
		t.Fatalf("python3 not on PATH, so the script half of this parity check cannot be evaluated: %v", err)
	}

	up, _ := migrationFiles(t)

	// The Go side, via the census's own extraction.
	goSet := map[string]bool{}
	for _, path := range up {
		body, err := os.ReadFile(path) //nolint:gosec // walking a fixed repo subtree
		if err != nil {
			t.Fatalf("reading %s: %v", path, err)
		}
		text := string(body)
		for _, m := range appGrantRe.FindAllStringSubmatch(text, -1) {
			for _, table := range tablesNamedInGrant(m[0]) {
				goSet[table] = true
			}
		}
		for _, table := range tablesNamedInFormatGrant(text) {
			goSet[table] = true
		}
	}
	if len(goSet) == 0 {
		t.Fatal("the Go census extracted ZERO granted tables; an equality assertion between two empty sets " +
			"would pass while checking nothing")
	}

	// The script side, over the same files.
	out, err := exec.Command(python, append([]string{script}, up...)...).Output() //nolint:gosec // fixed script, repo-local file list
	if err != nil {
		t.Fatalf("running granted_tables.py over %d migrations: %v", len(up), err)
	}
	pySet := map[string]bool{}
	for _, line := range strings.Split(string(out), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			pySet[line] = true
		}
	}

	var onlyGo, onlyPy []string
	for table := range goSet {
		if !pySet[table] {
			onlyGo = append(onlyGo, table)
		}
	}
	for table := range pySet {
		if !goSet[table] {
			onlyPy = append(onlyPy, table)
		}
	}
	sort.Strings(onlyGo)
	sort.Strings(onlyPy)

	if len(onlyGo) > 0 || len(onlyPy) > 0 {
		t.Errorf("the Go census and runtime-e2e/3636_forcerls_grants/granted_tables.py disagree about which tables "+
			"a migration grants to an application role.\n"+
			"  seen by the Go census only: %v\n"+
			"  seen by the script only:    %v\n\n"+
			"They read the same property for two different legs - the per-commit census over the tree, and the "+
			"booted-stack coverage leg over that deployment's own applied migrations - so a divergence means one "+
			"of those legs is answering a question the other would answer differently. Fix the reader that is "+
			"wrong; do not widen either to make this pass.",
			onlyGo, onlyPy)
	}
	t.Logf("both readers name the same %d granted tables across %d up-migrations", len(goSet), len(up))
}
