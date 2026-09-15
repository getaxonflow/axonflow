// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"axonflow/platform/decision/legacycompile"
)

// ONE STATEMENT OF WHAT A SCOPE'S WIRE DELIVERS (#4131).
//
// legacycompile.ScopeDeliveries is what each enforcement scope's wire hands to
// an enforcement point that declares a capability. The corpus build's template
// split reads it to decide where a redaction can be carried out; this binary's
// enforcingSeams, the portal's authoring dry run and the orchestrator's read it
// to build the engine activation judges. With one statement there is nothing
// to weld, so what can drift is a SECOND statement: a site that spells the
// delivery out itself again. The two tests below refuse one, each where the
// other cannot see: the scan by spelling across the tree, the seam check by
// value whatever the spelling.

// secondDeliveryStatement is a delivery built from the Decision API's
// vocabulary directly rather than read from legacycompile.ScopeDeliveries.
var secondDeliveryStatement = regexp.MustCompile(`(?i)\bdelivers\s*:\s*contract\.DecisionWireCapabilities\(\)`)

func TestNoSecondStatementOfWhatAScopesWireDelivers(t *testing.T) {
	root := filepath.Join("..", "..")
	var scanned int
	var offenders []string
	for _, dir := range []string{"platform", "ee"} {
		base := filepath.Join(root, dir)
		if _, err := os.Stat(base); err != nil {
			// The community mirror carries no ee/; platform/ must exist.
			if dir == "platform" {
				t.Fatalf("PREMISE: %s is not readable from the agent package: %v", base, err)
			}
			continue
		}
		err := filepath.WalkDir(base, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				switch d.Name() {
				case "node_modules", "vendor", "testdata", ".git":
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			f, err := os.Open(path)
			if err != nil {
				return err
			}
			defer func() { _ = f.Close() }()
			scanned++
			sc := bufio.NewScanner(f)
			sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
			for n := 1; sc.Scan(); n++ {
				line := strings.TrimSpace(sc.Text())
				if strings.HasPrefix(line, "//") {
					continue
				}
				if secondDeliveryStatement.MatchString(line) {
					offenders = append(offenders, path+":"+itoa(n))
				}
			}
			return sc.Err()
		})
		if err != nil {
			t.Fatalf("walking %s: %v", base, err)
		}
	}
	if scanned < 100 {
		t.Fatalf("scanned %d Go files; the walk did not read the tree, so an absence proves nothing", scanned)
	}
	if len(offenders) > 0 {
		t.Errorf("%d site(s) state a scope's delivery themselves instead of reading legacycompile.ScopeDeliveries: %v", len(offenders), offenders)
	}
	// The one statement is not empty: decide and the gateway pre-check deliver
	// the Decision API's vocabulary, and the seams read it from here.
	for _, s := range []legacycompile.EnforcementScope{decideSeamScope, gatewayRequestSeamScope} {
		if len(legacycompile.ScopeDeliveries(s)) == 0 || len(seamDelivers(s)) == 0 {
			t.Errorf("%s delivers nothing in legacycompile.ScopeDeliveries (%v) or in its seam (%v)", s, legacycompile.ScopeDeliveries(s), seamDelivers(s))
		}
	}
}

// TestEverySeamDeliversWhatScopeDeliveriesStates holds every enforcing seam's
// delivery to legacycompile.ScopeDeliveries by VALUE. A seam that states its
// delivery another way - a capability literal, a variable, an aliased import,
// or nothing where the scope delivers something - is refused whatever its
// spelling; the scan above sees only one spelling, and this cannot see a dry
// run, which the scan covers.
func TestEverySeamDeliversWhatScopeDeliveriesStates(t *testing.T) {
	if len(enforcingSeams) == 0 {
		t.Fatal("PREMISE: this binary registers no enforcing seam")
	}
	for _, s := range enforcingSeams {
		got, want := fmt.Sprint(s.delivers), fmt.Sprint(legacycompile.ScopeDeliveries(s.scope))
		if got != want {
			t.Errorf("%s: its seam delivers %s and legacycompile.ScopeDeliveries states %s", s.scope, got, want)
		}
	}
}

func itoa(n int) string {
	const digits = "0123456789"
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{digits[n%10]}, b...)
		n /= 10
	}
	return string(b)
}
