// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package planeshadow

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"sort"
	"strings"
	"testing"
)

// modeInputFields are the two fields that hold a mode input. Both names are
// unique in this package (asserted below), so a syntactic census is exact.
var modeInputFields = []string{"processMode", "orgModes"}

// permittedModeReaders are the functions allowed to read them.
//
// effectiveMode is the one consultation site. Mode and HasPerOrgSource are
// diagnostics accessors that decide nothing, which is the exemption
// identity.Mode has for the same reason. NewObserver and WithOrgModes WRITE the
// fields; a write is not a consultation, and refusing them would leave the
// fields unsettable.
//
// Config's own methods (Observes, and the parsers) are on the Config VALUE
// rather than on the Observer, so they never appear as a selector on these
// fields - which is exactly why the mode lives in a field of its own rather
// than inside Config.
var permittedModeReaders = map[string]bool{
	// The one consultation site.
	"effectiveMode": true,
	// The two diagnostics accessors, which decide nothing - identity.Mode's
	// own exemption, for the same reason: a startup log line has to say which
	// mode the deployment is in and whether a per-org record can override it.
	"Mode":            true,
	"HasPerOrgSource": true,
	// The constructor's composite literal and the option that sets the source.
	// A WRITE is not a consultation, and refusing them would leave the fields
	// unsettable.
	"NewObserver":  true,
	"WithOrgModes": true,
}

// TestShadowModeIsConsultedAtExactlyOneSite is the structural proof behind this
// package's "the mode is read in exactly one place" claim, and it is the same
// guard #3596 installed for the identity axis.
//
// The failure it prevents is "the flag is honored on some planes and not
// others", which is indistinguishable from a clean window on the planes that
// stopped - the worst possible failure for a mechanism whose entire output is a
// denominator.
//
// It walks every non-test Go file in this package (go/parser does not evaluate
// build constraints, so both halves are covered) and enumerates every selector
// on Observer.cfg and Observer.orgModes.
func TestShadowModeIsConsultedAtExactlyOneSite(t *testing.T) {
	sources := packageSources(t)
	report, err := modeReadCensus(sources)
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range report.violations {
		t.Error(v)
	}
	for _, m := range report.missing {
		t.Error(m)
	}
}

// TestShadowModeCensusCatchesAPlantedSecondSite is the census's own failing
// input, and it is IN-PROCESS by necessity.
//
// The compatmutation-style harness plants mutants through `go test -overlay`,
// which changes what the COMPILER sees and not what os.ReadFile returns, so no
// overlay mutant can ever reach a source-reading guard
// ([[feedback_an_overlay_mutant_is_invisible_to_a_source_reading_guard]]).
// This feeds the census a copy of observer.go with the exact plant a future
// edit would make and requires the violation to be named by file and line.
func TestShadowModeCensusCatchesAPlantedSecondSite(t *testing.T) {
	sources := packageSources(t)

	// Control: the real tree is clean, so a violation below is the plant's.
	if report, err := modeReadCensus(sources); err != nil || len(report.violations) != 0 || len(report.missing) != 0 {
		t.Fatalf("the unmodified tree is not clean (err=%v): %v %v", err, report.violations, report.missing)
	}

	for name, plant := range map[string]struct{ file, from, to string }{
		"evaluate reads the process mode": {
			file: "observer.go",
			from: "\tpost := posture(obs.Posture)",
			to:   "\tif !records(o.processMode) {\n\t\treturn\n\t}\n\tpost := posture(obs.Posture)",
		},
		"a helper consults the org source a second time": {
			file: "observer.go",
			from: "func (o *Observer) OrgModeFailures() uint64 {",
			to:   "func (o *Observer) OrgModeFailures() uint64 {\n\t_, _, _ = o.orgModes.OrgDecisionShadowMode(context.Background(), \"\")",
		},
		"Observe re-reads the process mode after the single site": {
			file: "observer.go",
			from: "\tif !records(mode) {",
			to:   "\tif !records(mode) || !records(o.processMode) {",
		},
	} {
		t.Run(name, func(t *testing.T) {
			planted := map[string][]byte{}
			for k, v := range sources {
				planted[k] = v
			}
			src := string(sources[plant.file])
			if strings.Count(src, plant.from) != 1 {
				t.Fatalf("the plant's anchor %q does not match exactly once in %s; re-anchor the plant", plant.from, plant.file)
			}
			planted[plant.file] = []byte(strings.Replace(src, plant.from, plant.to, 1))
			report, err := modeReadCensus(planted)
			if err != nil {
				t.Fatal(err)
			}
			if len(report.violations) == 0 {
				t.Fatalf("the census did not fire on a planted second consultation site. "+
					"A guard that cannot fail is not a guard, and the defect it names - "+
					"one plane honoring the mode and another not - is invisible in a "+
					"denominator. Planted: %s", plant.to)
			}
		})
	}
}

// packageSources reads every non-test Go file in this package.
func packageSources(t *testing.T) map[string][]byte {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	out := map[string][]byte{}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, rerr := os.ReadFile(name)
		if rerr != nil {
			t.Fatalf("read %s: %v", name, rerr)
		}
		out[name] = src
	}
	if len(out) == 0 {
		t.Fatal("no source files found; the census would pass while reading nothing")
	}
	return out
}

type censusReport struct {
	violations []string
	missing    []string
}

// modeReadCensus enumerates every selector on the mode-input fields.
func modeReadCensus(sources map[string][]byte) (censusReport, error) {
	var rep censusReport
	seen := map[string]bool{}
	names := make([]string, 0, len(sources))
	for name := range sources {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, name, sources[name], 0)
		if err != nil {
			return rep, fmt.Errorf("parsing %s: %w", name, err)
		}
		for _, decl := range f.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			fn := fd.Name.Name
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				sel, ok := n.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				recv, ok := sel.X.(*ast.Ident)
				if !ok || recv.Name != "o" {
					return true
				}
				for _, field := range modeInputFields {
					if sel.Sel.Name != field {
						continue
					}
					seen[fn] = true
					if !permittedModeReaders[fn] {
						pos := fset.Position(sel.Pos())
						rep.violations = append(rep.violations, fmt.Sprintf(
							"%s:%d: %s reads Observer.%s. The mode is read in exactly one "+
								"function, effectiveMode; a second reader is how 'the flag is "+
								"honored on some planes and not others' arrives, and that is "+
								"indistinguishable from a clean window.",
							name, pos.Line, fn, field))
					}
				}
				return true
			})
		}
	}

	// THE OTHER DIRECTION, and it is the one that catches a DELETED guard: a
	// permitted reader that no longer reads anything means the consultation
	// site moved or was removed, and a census asserting only "no extra
	// readers" passes hardest when there are none at all.
	for _, fn := range []string{"effectiveMode"} {
		if !seen[fn] {
			rep.missing = append(rep.missing, fmt.Sprintf(
				"%s no longer reads any mode input. Either the single consultation site moved "+
					"- in which case this census is now pointing at nothing - or the mode "+
					"stopped being consulted at all, which is a shadow that records for "+
					"every organization or for none.", fn))
		}
	}
	return rep, nil
}

// TestModeInputFieldNamesAreUnique is what makes the syntactic census exact.
//
// The census matches on the SELECTOR NAME against a receiver called `o`. If
// another type in this package grew a field with one of these names and a
// method with an `o` receiver, the census would report violations that are not
// about the mode - and, worse, a future rename could make it match nothing
// while still passing.
func TestModeInputFieldNamesAreUnique(t *testing.T) {
	sources := packageSources(t)
	for _, field := range modeInputFields {
		count := 0
		for name, src := range sources {
			fset := token.NewFileSet()
			f, err := parser.ParseFile(fset, name, src, 0)
			if err != nil {
				t.Fatalf("parsing %s: %v", name, err)
			}
			ast.Inspect(f, func(n ast.Node) bool {
				st, ok := n.(*ast.StructType)
				if !ok || st.Fields == nil {
					return true
				}
				for _, fl := range st.Fields.List {
					for _, id := range fl.Names {
						if id.Name == field {
							count++
						}
					}
				}
				return true
			})
		}
		if count != 1 {
			t.Errorf("%d struct fields in this package are named %q; the census matches on that "+
				"name and can only be exact while it is unique", count, field)
		}
	}
}
