// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package identity

import (
	"context"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// mapOrgModeSource is a CompatOrgModeSource over a map, with a call counter
// so a test can prove the source was consulted exactly once per Resolve and
// never when no source is wired.
type mapOrgModeSource struct {
	modes map[string]CompatMode
	err   error
	calls atomic.Int64
	// seenOrgs records the exact keys asked for, so the trimming test can
	// prove the lookup key rather than infer it from the outcome.
	seenOrgs []string
}

func (s *mapOrgModeSource) OrgCompatMode(_ context.Context, orgID string) (CompatMode, bool, error) {
	s.calls.Add(1)
	s.seenOrgs = append(s.seenOrgs, orgID)
	if s.err != nil {
		return CompatModeUnspecified, false, s.err
	}
	m, ok := s.modes[orgID]
	return m, ok, nil
}

// undeclaredIssuerAuth is a legacy-ACCEPTED HS256 credential whose issuer no
// realm declares: Deny(UNKNOWN_REALM) under evaluation, and therefore the one
// input whose outcome differs across all three modes - nothing under off, a
// record under shadow, a refusal under enforce.
func undeclaredIssuerAuth() LegacyAuth {
	claims := mintedClaims()
	claims["iss"] = issuerAcquired
	return HS256LegacyAuth(fixtureOrg, claims, true, "", "")
}

// TestCompatOrgModeCompositionMatrix is the composition rule, every cell.
//
// The matrix is the PRODUCT of the two axes, not a sample of it: a rule that
// says "a record wins" has to be shown winning in the raising direction, the
// lowering direction, and the same-value direction, and the absent column has
// to equal the process row cell for cell.
func TestCompatOrgModeCompositionMatrix(t *testing.T) {
	MarkConformanceCase("AXC-280")
	processModes := []CompatMode{CompatModeOff, CompatModeShadow, CompatModeEnforce}
	type recordCell struct {
		name string
		// absent means no record; otherwise the recorded mode.
		absent bool
		mode   CompatMode
	}
	records := []recordCell{
		{name: "absent", absent: true},
		{name: "record=off", mode: CompatModeOff},
		{name: "record=shadow", mode: CompatModeShadow},
		{name: "record=enforce", mode: CompatModeEnforce},
	}
	cells := 0
	for _, process := range processModes {
		for _, rec := range records {
			cells++
			t.Run("process="+process.String()+"/"+rec.name, func(t *testing.T) {
				src := &mapOrgModeSource{modes: map[string]CompatMode{}}
				if !rec.absent {
					src.modes[fixtureOrg] = rec.mode
				}
				a, recorder, _ := compatFixture(t, process, BuiltinRealmDeployment{}, WithCompatOrgModes(src))

				want := process
				if !rec.absent {
					want = rec.mode
				}
				out := a.Resolve(context.Background(), undeclaredIssuerAuth())

				if out.Mode != want {
					t.Fatalf("resolved mode = %s, want %s (process=%s, %s)", out.Mode, want, process, rec.name)
				}
				if got := src.calls.Load(); got != 1 {
					t.Fatalf("the org-mode source was consulted %d times for one Resolve, want exactly 1", got)
				}
				if out.Evaluated != want.evaluates() {
					t.Fatalf("Evaluated = %t under resolved mode %s", out.Evaluated, want)
				}
				if (out.Refusal() != nil) != (want == CompatModeEnforce) {
					t.Fatalf("refusal = %v under resolved mode %s", out.Refusal(), want)
				}
				if wantRecords := map[bool]int{true: 1, false: 0}[want.evaluates()]; len(recorder.records) != wantRecords {
					t.Fatalf("%d counterfactuals recorded under resolved mode %s, want %d", len(recorder.records), want, wantRecords)
				}
				if want.evaluates() && recorder.records[0].Mode != want {
					t.Fatalf("the counterfactual records mode %s, want the RESOLVED mode %s so a per-org shadow is distinguishable from the deployment default", recorder.records[0].Mode, want)
				}
				if a.OrgModeFailures() != 0 {
					t.Fatalf("a successful read counted as a failure")
				}
			})
		}
	}
	if cells != 12 {
		t.Fatalf("the matrix ran %d cells; the product of 3 process modes and 4 record states is 12", cells)
	}
}

// TestCompatOrgModeAppliesOnlyToTheRecordedOrganization is the release plan's
// promise: shadow ONE organization on a deployment that is otherwise off, and
// the others are untouched - not evaluated, not recorded, mode off.
func TestCompatOrgModeAppliesOnlyToTheRecordedOrganization(t *testing.T) {
	MarkConformanceCase("AXC-281")
	const otherOrg = "org_bystander"
	src := &mapOrgModeSource{modes: map[string]CompatMode{fixtureOrg: CompatModeShadow}}
	a, recorder, _ := compatFixture(t, CompatModeOff, BuiltinRealmDeployment{}, WithCompatOrgModes(src))

	shadowed := a.Resolve(context.Background(), undeclaredIssuerAuth())
	if shadowed.Mode != CompatModeShadow || !shadowed.Evaluated || shadowed.Refusal() != nil {
		t.Fatalf("the recorded organization did not shadow: %+v", shadowed)
	}
	if len(recorder.records) != 1 || recorder.records[0].OrgID != fixtureOrg {
		t.Fatalf("expected exactly one counterfactual for %s, got %+v", fixtureOrg, recorder.records)
	}

	claims := mintedClaims()
	claims["iss"] = issuerAcquired
	claims["org_id"] = otherOrg
	bystander := a.Resolve(context.Background(), HS256LegacyAuth(otherOrg, claims, true, "", ""))
	if bystander.Mode != CompatModeOff || bystander.Evaluated || bystander.Divergence != DivergenceNotEvaluated {
		t.Fatalf("an organization with NO record was evaluated on a process-off deployment: %+v", bystander)
	}
	if len(recorder.records) != 1 {
		t.Fatalf("the bystander organization produced a counterfactual: %+v", recorder.records[1:])
	}
}

// TestCompatOrgModeLoweringExemptsOneOrganization is the incident direction:
// process-wide enforce, one organization recorded off. That organization is
// not refused and the process-level allow-list is irrelevant to it, while an
// organization with no record is still enforced.
func TestCompatOrgModeLoweringExemptsOneOrganization(t *testing.T) {
	const otherOrg = "org_still_enforced"
	src := &mapOrgModeSource{modes: map[string]CompatMode{fixtureOrg: CompatModeOff}}
	a, _, _ := compatFixture(t, CompatModeEnforce, BuiltinRealmDeployment{}, WithCompatOrgModes(src))

	if out := a.Resolve(context.Background(), undeclaredIssuerAuth()); out.Refusal() != nil || out.Evaluated {
		t.Fatalf("the exempted organization was still evaluated/refused: %+v", out)
	}
	claims := mintedClaims()
	claims["iss"] = issuerAcquired
	claims["org_id"] = otherOrg
	if out := a.Resolve(context.Background(), HS256LegacyAuth(otherOrg, claims, true, "", "")); out.Refusal() == nil {
		t.Fatalf("an organization with no record was not enforced on a process-enforce deployment: %+v", out)
	}
}

// TestCompatOrgModeReadFailureFallsBackToTheProcessMode pins the direction of
// the fall-back, in both process modes, and that it is COUNTED.
func TestCompatOrgModeReadFailureFallsBackToTheProcessMode(t *testing.T) {
	MarkConformanceCase("AXC-284")
	for _, process := range []CompatMode{CompatModeOff, CompatModeEnforce} {
		t.Run(process.String(), func(t *testing.T) {
			src := &mapOrgModeSource{err: errors.New("settings store unreachable")}
			a, _, _ := compatFixture(t, process, BuiltinRealmDeployment{}, WithCompatOrgModes(src))
			out := a.Resolve(context.Background(), undeclaredIssuerAuth())
			if out.Mode != process {
				t.Fatalf("resolved mode = %s after a read failure, want the process mode %s", out.Mode, process)
			}
			if (out.Refusal() != nil) != (process == CompatModeEnforce) {
				t.Fatalf("a read failure changed enforcement: refusal=%v under process %s", out.Refusal(), process)
			}
			if a.OrgModeFailures() != 1 {
				t.Fatalf("OrgModeFailures = %d, want 1: a fall-back that is not counted is a fall-back nobody can see", a.OrgModeFailures())
			}
		})
	}
}

// TestCompatOrgModeRefusesAnUndeclaredRecordedValue: a source that answers
// with a value outside the declared modes has not answered. The check is by
// MEMBERSHIP: an inequality against the zero value would let CompatMode(99)
// through, and Resolve would then treat it as whatever the last branch
// happened to be.
func TestCompatOrgModeRefusesAnUndeclaredRecordedValue(t *testing.T) {
	MarkConformanceCase("AXC-283")
	for _, bad := range []CompatMode{CompatModeUnspecified, CompatMode(99), CompatMode(-1)} {
		t.Run(bad.String(), func(t *testing.T) {
			src := &mapOrgModeSource{modes: map[string]CompatMode{fixtureOrg: bad}}
			a, recorder, _ := compatFixture(t, CompatModeOff, BuiltinRealmDeployment{}, WithCompatOrgModes(src))
			out := a.Resolve(context.Background(), undeclaredIssuerAuth())
			if out.Mode != CompatModeOff || out.Evaluated || out.Refusal() != nil {
				t.Fatalf("an undeclared recorded mode %s was acted on: %+v", bad, out)
			}
			if len(recorder.records) != 0 {
				t.Fatalf("an undeclared recorded mode produced a counterfactual")
			}
			if a.OrgModeFailures() != 1 {
				t.Fatalf("an undeclared recorded mode was not counted as a read failure (got %d)", a.OrgModeFailures())
			}
		})
	}
}

// TestCompatOrgModeIsKeyedOnTheTrimmedAuthenticatedOrg: " org_acme " and
// "org_acme" are one organization, and so they must be one record.
func TestCompatOrgModeIsKeyedOnTheTrimmedAuthenticatedOrg(t *testing.T) {
	src := &mapOrgModeSource{modes: map[string]CompatMode{fixtureOrg: CompatModeShadow}}
	a, _, _ := compatFixture(t, CompatModeOff, BuiltinRealmDeployment{}, WithCompatOrgModes(src))
	in := undeclaredIssuerAuth()
	in.AuthenticatedOrgID = "  " + fixtureOrg + "\t"
	out := a.Resolve(context.Background(), in)
	if out.Mode != CompatModeShadow {
		t.Fatalf("a padded authenticated org resolved to mode %s; the record is keyed on the TRIMMED org", out.Mode)
	}
	if len(src.seenOrgs) != 1 || src.seenOrgs[0] != fixtureOrg {
		t.Fatalf("the source was asked for %q, want the trimmed %q", src.seenOrgs, fixtureOrg)
	}
}

// TestCompatOffWithNoRecordTouchesNothingElse is TestCompatOffTouchesNothing
// one level up: with a source wired, an organization with no record on a
// process-off deployment touches the SOURCE, exactly once, and nothing else -
// no clock, no realm source, no recorder.
func TestCompatOffWithNoRecordTouchesNothingElse(t *testing.T) {
	src := &mapOrgModeSource{modes: map[string]CompatMode{}}
	a, err := NewCompatAdapter(CompatModeOff, NewRealmRegistry(), &panicRealmSource{t: t}, &panicRecorder{t: t},
		WithCompatOrgModes(src),
		WithCompatClock(func() time.Time {
			t.Fatalf("the clock was read for an organization whose resolved mode is off")
			return time.Time{}
		}))
	if err != nil {
		t.Fatalf("NewCompatAdapter: %v", err)
	}
	out := a.Resolve(context.Background(), HS256LegacyAuth(fixtureOrg, mintedClaims(), true, "", ""))
	if out.Refusal() != nil || out.Evaluated || out.Divergence != DivergenceNotEvaluated || out.Mode != CompatModeOff {
		t.Fatalf("process off + no record was not off: %+v", out)
	}
	if got := src.calls.Load(); got != 1 {
		t.Fatalf("the source was consulted %d times, want exactly 1", got)
	}
}

// TestCompatNilOrgModeSourceIsTheProcessMode: no source (every community
// build) is exactly #3582's behaviour, with no lookup of any kind.
func TestCompatNilOrgModeSourceIsTheProcessMode(t *testing.T) {
	a, _, _ := compatFixture(t, CompatModeShadow, BuiltinRealmDeployment{}, WithCompatOrgModes(nil))
	out := a.Resolve(context.Background(), undeclaredIssuerAuth())
	if out.Mode != CompatModeShadow || !out.Evaluated {
		t.Fatalf("with no org-mode source the process mode did not apply: %+v", out)
	}
	if a.OrgModeFailures() != 0 {
		t.Fatalf("a nil source was counted as a failure")
	}
}

// TestCompatModeIsConsultedAtExactlyOneSite is the structural proof behind
// compat.go's "the mode is read in exactly one place", extended to the
// per-organization axis.
//
// It walks EVERY non-test Go file in this package - both build-tag halves,
// since go/parser does not evaluate constraints - and enumerates every
// selector expression on the two fields that hold a mode input,
// CompatAdapter.processMode and CompatAdapter.orgModes. Both names are unique
// in the package (asserted below), so a syntactic census is exact. The only
// permitted READERS are effectiveMode (both fields) and Mode (processMode,
// the diagnostics accessor); the only permitted WRITER outside the
// constructor's composite literal is WithCompatOrgModes. A read anywhere else
// is a second consultation site and fails this test naming the file and
// line. The compatmutation harness plants exactly that in refusalFor and in
// record to prove this test can fail.
func TestCompatModeIsConsultedAtExactlyOneSite(t *testing.T) {
	MarkConformanceCase("AXC-282")
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	sources := map[string][]byte{}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, rerr := os.ReadFile(name)
		if rerr != nil {
			t.Fatalf("read %s: %v", name, rerr)
		}
		sources[name] = src
	}
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

// TestCompatModeCensusCatchesAPlantedSecondSite is the census's own failing
// input, and it is IN-PROCESS by necessity: the compatmutation harness plants
// its mutants through `go test -overlay`, which changes what the COMPILER
// sees and not what os.ReadFile returns, so no overlay mutant can ever reach
// a source-reading guard. (That is also why the two planted second sites in
// the harness are aimed at the behavioural matrix, which they do break.) This
// feeds the census a copy of compat.go with the exact plant a future edit
// would make and requires the violation to be named by file and line.
func TestCompatModeCensusCatchesAPlantedSecondSite(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	sources := map[string][]byte{}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, rerr := os.ReadFile(name)
		if rerr != nil {
			t.Fatalf("read %s: %v", name, rerr)
		}
		sources[name] = src
	}
	// Control: the real tree is clean, so a violation below is the plant's.
	if report, err := modeReadCensus(sources); err != nil || len(report.violations) != 0 || len(report.missing) != 0 {
		t.Fatalf("the unmodified tree is not clean (err=%v): %v %v", err, report.violations, report.missing)
	}
	for name, plant := range map[string]struct{ from, to string }{
		"refusalFor reads the process mode": {
			from: "\tif !out.Mode.enforces() {",
			to:   "\tif !a.processMode.enforces() {",
		},
		"record stamps the process mode": {
			from: "\t\tMode:           out.Mode,",
			to:   "\t\tMode:           a.processMode,",
		},
		"a helper consults the org source a second time": {
			from: "func (a *CompatAdapter) OrgModeFailures() uint64 {",
			to:   "func (a *CompatAdapter) OrgModeFailures() uint64 {\n\t_, _, _ = a.orgModes.OrgCompatMode(context.Background(), \"\")",
		},
	} {
		t.Run(name, func(t *testing.T) {
			planted := map[string][]byte{}
			for k, v := range sources {
				planted[k] = v
			}
			target := "compat.go"
			if strings.Contains(plant.from, "OrgModeFailures") {
				target = "compat_org_mode.go"
			}
			if strings.Count(string(sources[target]), plant.from) != 1 {
				t.Fatalf("the plant's anchor %q does not match exactly once in %s; re-anchor the plant", plant.from, target)
			}
			planted[target] = []byte(strings.Replace(string(sources[target]), plant.from, plant.to, 1))
			report, err := modeReadCensus(planted)
			if err != nil {
				t.Fatal(err)
			}
			if len(report.violations) == 0 {
				t.Fatalf("the census did not see the planted second site %q", name)
			}
			if !strings.Contains(report.violations[0], target+":") {
				t.Fatalf("the violation does not name the file: %v", report.violations)
			}
		})
	}
	// And the other direction: hollowing the one permitted site out is
	// reported as a MISSING read, not as a clean tree.
	hollow := map[string][]byte{}
	for k, v := range sources {
		hollow[k] = v
	}
	// effectiveMode reads orgModes twice (the nil check and the call); both
	// are removed, because a hollowed site that still nil-checks the source
	// would count as reading it.
	hollowed := string(sources["compat_org_mode.go"])
	for from, to := range map[string]string{
		"\tif a.orgModes == nil || orgID == \"\" {":                     "\tif orgID == \"\" {",
		"\trecord, found, err := a.orgModes.OrgCompatMode(octx, orgID)": "\trecord, found, err := CompatModeUnspecified, false, error(nil)",
	} {
		if strings.Count(hollowed, from) != 1 {
			t.Fatalf("the hollowing plant's anchor %q does not match exactly once; re-anchor it", from)
		}
		hollowed = strings.Replace(hollowed, from, to, 1)
	}
	hollow["compat_org_mode.go"] = []byte(hollowed)
	report, err := modeReadCensus(hollow)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.missing) == 0 {
		t.Fatalf("hollowing effectiveMode's read of orgModes was not reported")
	}
}

// modeCensusReport is what modeReadCensus finds.
type modeCensusReport struct {
	// violations are reads or writes outside the permitted sites, each
	// naming file:line:col and the function.
	violations []string
	// missing are permitted reads that no longer happen.
	missing []string
}

// modeReadCensus enumerates every selector on CompatAdapter.processMode and
// CompatAdapter.orgModes across the given sources (file name -> contents).
// Both names are unique in the package (asserted), so a syntactic census is
// exact. The only permitted READERS are effectiveMode (both fields) and Mode
// (processMode); the only permitted WRITER outside the constructor's
// composite literal is WithCompatOrgModes.
func modeReadCensus(sources map[string][]byte) (modeCensusReport, error) {
	const (
		fieldProcessMode = "processMode"
		fieldOrgModes    = "orgModes"
	)
	allowedReads := map[string]map[string]bool{
		"(*CompatAdapter).effectiveMode": {fieldProcessMode: true, fieldOrgModes: true},
		"(*CompatAdapter).Mode":          {fieldProcessMode: true},
	}
	allowedWrites := map[string]map[string]bool{
		"WithCompatOrgModes": {fieldOrgModes: true},
	}

	fset := token.NewFileSet()
	var (
		report            modeCensusReport
		fieldDeclarations = map[string]int{}
		readsSeen         = map[string]map[string]bool{}
		names             []string
	)
	for name := range sources {
		names = append(names, name)
	}
	sort.Strings(names)
	if len(names) == 0 {
		return report, fmt.Errorf("no sources were given; this census read nothing")
	}
	for _, name := range names {
		f, perr := parser.ParseFile(fset, name, sources[name], 0)
		if perr != nil {
			return report, fmt.Errorf("parse %s: %w", name, perr)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			st, ok := n.(*ast.StructType)
			if !ok || st.Fields == nil {
				return true
			}
			for _, fld := range st.Fields.List {
				for _, id := range fld.Names {
					if id.Name == fieldProcessMode || id.Name == fieldOrgModes {
						fieldDeclarations[id.Name]++
					}
				}
			}
			return true
		})
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			fnName := funcDisplayName(fn)
			writeTargets := map[ast.Expr]bool{}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				as, ok := n.(*ast.AssignStmt)
				if !ok {
					return true
				}
				for _, lhs := range as.Lhs {
					writeTargets[lhs] = true
				}
				return true
			})
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				sel, ok := n.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				field := sel.Sel.Name
				if field != fieldProcessMode && field != fieldOrgModes {
					return true
				}
				pos := fset.Position(sel.Pos())
				if writeTargets[sel] {
					if !allowedWrites[fnName][field] {
						report.violations = append(report.violations, pos.String()+": "+fnName+" WRITES "+field)
					}
					return true
				}
				if !allowedReads[fnName][field] {
					report.violations = append(report.violations, pos.String()+": "+fnName+" READS "+field+
						" - a second consultation site for the mode; route the decision through the outcome effectiveMode produced")
					return true
				}
				if readsSeen[fnName] == nil {
					readsSeen[fnName] = map[string]bool{}
				}
				readsSeen[fnName][field] = true
				return true
			})
		}
	}
	for _, field := range []string{fieldProcessMode, fieldOrgModes} {
		if fieldDeclarations[field] != 1 {
			return report, fmt.Errorf("field %q is declared %d times; the census depends on the name being unique to CompatAdapter", field, fieldDeclarations[field])
		}
	}
	sort.Strings(report.violations)
	for fn, fields := range allowedReads {
		for field := range fields {
			if !readsSeen[fn][field] {
				report.missing = append(report.missing, fn+" no longer reads "+field+"; the single consultation site has lost one of its inputs")
			}
		}
	}
	sort.Strings(report.missing)
	return report, nil
}

// funcDisplayName renders a FuncDecl as "(*Recv).Name" or "Name".
func funcDisplayName(fn *ast.FuncDecl) string {
	if fn.Recv == nil || len(fn.Recv.List) == 0 {
		return fn.Name.Name
	}
	recv := fn.Recv.List[0].Type
	var typeName string
	star := false
	if se, ok := recv.(*ast.StarExpr); ok {
		star = true
		recv = se.X
	}
	if id, ok := recv.(*ast.Ident); ok {
		typeName = id.Name
	} else {
		typeName = "?"
	}
	if star {
		return "(*" + typeName + ")." + fn.Name.Name
	}
	return "(" + typeName + ")." + fn.Name.Name
}

// The census must cover every file the package compiles in EITHER edition.
// This is a self-check that the walk sees the enterprise half: if the
// per-org settings store's file is absent from the directory listing the
// census has been pointed at the wrong tree.
//
// THE ENTERPRISE HALF IS REQUIRED ONLY IN AN ENTERPRISE BUILD, and that is
// not a weakening. The community sync deletes the enterprise half of every
// build-tag pair, so in the published mirror `compat_org_settings.go` is
// genuinely not on disk and an unconditional list asserts that the mirror is
// malformed for being the mirror. (The mirror-simulation job is where that
// bites: it replays the community jobs against a stripped copy.) The
// conformance registry test makes exactly the same distinction, for exactly
// the same reason, and this is the second half of that fence: in an
// ENTERPRISE build the enterprise half must be there, which is the direction
// that can catch a census pointed at the wrong tree.
func TestCompatModeCensusSeesBothEditions(t *testing.T) {
	must := []string{"compat.go", "compat_org_mode.go", "compat_org_settings_community.go"}
	if conformanceEnterpriseBuild {
		must = append(must, "compat_org_settings.go", "compat_org_mode_enterprise.go")
	}
	// Anti-vacuity: a list that emptied itself would pass having read nothing,
	// and the untagged half is present in BOTH editions, so it can never be
	// legitimately empty.
	if len(must) < 3 {
		t.Fatalf("the file list is %d long; this check would pass having read nothing", len(must))
	}
	for _, name := range must {
		if _, err := os.Stat(filepath.Join(".", name)); err != nil {
			t.Fatalf("%s is not in the package directory the census walks: %v", name, err)
		}
	}
}
