// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package policypath_test

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"

	"axonflow/platform/shared/capability"
	"axonflow/platform/shared/policypath"
	"axonflow/platform/testutil/gocensus"
)

// legacyRegistrars are the functions allowed to register a route in the v11
// deprecated export surface (PRD §1.11), each with how its routes come to carry
// the deprecation signal. A legacy-family registration anywhere else is a route
// that answers unstamped, which is what this census refuses.
//
// Keys are "<package dir>.<func>" or "<package dir>.(<receiver>).<method>".
var legacyRegistrars = map[string]string{
	"platform/orchestrator.registerLegacyPolicyRoutes": "STAMPS: every route it registers sits on a subrouter carrying " +
		"policypath.DeprecateLegacy; TestEveryLegacyPolicyRouteCarriesTheDeprecationSignal walks it",
	"platform/orchestrator.(*DynamicPolicyAPIHandler).RegisterRoutes": "DELEGATE: takes a legacyRouter, which only " +
		"registerLegacyPolicyRoutes constructs (the construction rule below)",
	"platform/orchestrator.(*PolicySimulationHandler).RegisterRoutes": "DELEGATE: takes a legacyRouter, as above",
	"platform/agent.RegisterStaticPolicyHandlers": "STAMPS: mounts policypath.DeprecateLegacy on each prefix's subrouter " +
		"ahead of apiAuthMiddleware; TestDeprecationSignalIsOnBothSpellings drives every route of both prefixes",
	"platform/agent.(*ReverseProxyHandler).RegisterProxyRoutes": "FORWARDS to the orchestrator, whose registrar stamps; " +
		"the reverse proxy copies the header once (runtime-e2e/1431_policy_path_alias asserts it through this hop)",
	"platform/orchestrator/rbi.(*RBIModule).RegisterRoutes": "STAMPS: wraps both policy-template reads in " +
		"policypath.DeprecateLegacyFunc; TestRBIPolicyTemplateReadsCarryTheDeprecationSignal drives them through this registrar",
	"platform/orchestrator/rbi.(*RBIModule).RegisterRoutesWithMux": "STAMPS: as RegisterRoutes, on the gorilla router; " +
		"TestRBIPolicyTemplateReadsCarryTheDeprecationSignal drives both reads through it too",
}

// delegateRouterType is the parameter type every DELEGATE row must take.
const delegateRouterType = "legacyRouter"

// legacyRouterConstructor is the one function in shipping code allowed to build
// a legacyRouter.
const legacyRouterConstructor = "platform/orchestrator.registerLegacyPolicyRoutes"

// censusRoots are the source trees whose binaries serve HTTP.
var censusRoots = []string{"platform", "ee"}

type finding struct{ site, why string }

// legacySiteReport is what the census found in one tree.
type legacySiteReport struct {
	// sites maps each registrar key to the deprecated-family patterns it registers.
	sites map[string][]string
	// outside are deprecated-family registrations in no declared registrar.
	outside []finding
	// delegateShape are DELEGATE rows that do not take a legacyRouter.
	delegateShape []finding
	// constructions are legacyRouter composite literals outside the constructor.
	constructions []finding
	derived       *capability.Derivation
}

// censusTree runs the census over root.
func censusTree(t *testing.T, root string) legacySiteReport {
	t.Helper()
	d, err := capability.Derive(root, censusRoots)
	if err != nil {
		t.Fatalf("derive routes under %s: %v", root, err)
	}
	rep := legacySiteReport{sites: map[string][]string{}, derived: d}
	files := &fileIndex{root: root, parsed: map[string]*ast.File{}, fset: token.NewFileSet()}

	for _, s := range d.Routes {
		if !s.Resolved || !policypath.IsDeprecated(s.Pattern) {
			continue
		}
		where := fmt.Sprintf("%s:%d", s.File, s.Line)
		key, err := files.enclosing(s.File, s.Line)
		if err != nil {
			t.Fatalf("%s: %v", where, err)
		}
		if _, declared := legacyRegistrars[key]; !declared {
			rep.outside = append(rep.outside, finding{where, fmt.Sprintf("%s %s in %s", s.Method, s.Pattern, key)})
			continue
		}
		rep.sites[key] = append(rep.sites[key], s.Pattern)
	}

	for key, how := range legacyRegistrars {
		if !strings.HasPrefix(how, "DELEGATE") {
			continue
		}
		fn := files.funcByKey(key)
		if fn == nil {
			continue // reported as a stale row by the caller
		}
		if got := firstParamType(fn); got != delegateRouterType {
			rep.delegateShape = append(rep.delegateShape, finding{key,
				fmt.Sprintf("takes %s as its router, want %s", got, delegateRouterType)})
		}
	}

	for _, c := range files.compositeLiterals(filepath.Join(root, "platform", "orchestrator"), delegateRouterType) {
		if c.site != legacyRouterConstructor {
			rep.constructions = append(rep.constructions, c)
		}
	}
	return rep
}

// registrarRows sorts the declared registrars that register nothing in one
// tree. On the enterprise tree (ee/ present) every such row is stale, declared
// or not: it is an allowance waiting for a route nobody reviewed. On the
// community mirror, which carries no ee/, a row that registers nothing is not
// in this tree. The sync strips every enterprise-gated registrar and keeps at
// most a !enterprise stub of one (platform/orchestrator/rbi/rbi_community.go
// declares both RBIModule registrars and registers nothing), so the enterprise
// tree is where these rows are checked.
func registrarRows(root string, rep legacySiteReport) (stale, notInTree []string) {
	var keys []string
	for k := range legacyRegistrars {
		if len(rep.sites[k]) == 0 {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	if _, err := os.Stat(filepath.Join(root, "ee")); err == nil {
		return keys, nil
	}
	return nil, keys
}

// TestNoLegacyPolicyRouteIsRegisteredOutsideAStampedRegistrar is the census
// half of the v11 deprecation guard. The router walks in each binary prove every
// route a registrar registers carries the signal; this proves no route in the
// deprecated surface is registered anywhere else, where no walk would see it.
//
// THE POPULATION IS THE REGISTRATIONS, NOT A LIST: every HandleFunc, Handle,
// PathPrefix and Path call in the non-test source of platform/ and ee/, with
// subrouter prefixes composed and constants resolved, as capability.Derive
// finds them. A registration whose path Derive cannot resolve is already a
// reviewed line in the capability registry's route exemptions. Inside a
// STAMPS registrar one is covered anyway: that registrar's router walk drives
// every route it registers, resolvable or not - the agent's table-driven
// suffixes are the case.
func TestNoLegacyPolicyRouteIsRegisteredOutsideAStampedRegistrar(t *testing.T) {
	root := gocensus.RepoRoot(t)
	rep := censusTree(t, root)
	t.Logf("derived %d registration sites from %d files in %d directories",
		len(rep.derived.Routes), rep.derived.FilesParsed, rep.derived.DirsWalked)
	if rep.derived.FilesParsed < 500 {
		t.Fatalf("parsed %d files; the walk has gone blind and every assertion below is vacuous", rep.derived.FilesParsed)
	}

	for _, f := range rep.outside {
		t.Errorf("%s: %s - a route in the deprecated export surface registered outside a stamped registrar "+
			"answers without the deprecation signal. Register it in registerLegacyPolicyRoutes (orchestrator) or "+
			"RegisterStaticPolicyHandlers (agent), or declare the registrar here with how its routes are stamped.", f.site, f.why)
	}
	for _, f := range rep.delegateShape {
		t.Errorf("%s %s: a delegate that takes a bare router can be handed one that does not stamp", f.site, f.why)
	}
	for _, f := range rep.constructions {
		t.Errorf("%s: constructs a %s; only %s may, because the type is what proves a router stamps",
			f.why, delegateRouterType, legacyRouterConstructor)
	}

	// Both directions: a declared registrar that registers nothing in the
	// surface is a stale row, and a stale row is an allowance waiting for a
	// route nobody reviewed. On the community mirror every row that registers
	// nothing is not in this tree (registrarRows).
	var keys []string
	for k := range legacyRegistrars {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if n := len(rep.sites[k]); n > 0 {
			t.Logf("%s: %d site(s)", k, n)
		}
	}
	stale, notInTree := registrarRows(root, rep)
	for _, k := range notInTree {
		t.Logf("%s: not in this tree - there is no ee/, so this is the community mirror, which keeps at most "+
			"a !enterprise stub of an enterprise registrar; the enterprise tree checks this row", k)
	}
	for _, k := range stale {
		t.Errorf("%s is declared a legacy registrar and registers nothing in the deprecated surface; delete the row", k)
	}
}

// TestTheRegistrarCensusFindsWhatItShould plants each defect the census exists
// to catch into a copy of the real registrars, in a temporary tree, and
// requires the census to name it. Without it, a census that found nothing
// would pass on every tree.
func TestTheRegistrarCensusFindsWhatItShould(t *testing.T) {
	root := gocensus.RepoRoot(t)
	planted := t.TempDir()
	for _, rel := range []string{
		"platform/orchestrator/legacy_policy_routes.go",
		"platform/orchestrator/dynamic_policy_handlers.go",
		"platform/orchestrator/policy_simulation_handler.go",
		// The !enterprise stub the community mirror keeps: it declares both
		// RBIModule registrars and registers nothing.
		"platform/orchestrator/rbi/rbi_community.go",
	} {
		copyFile(t, filepath.Join(root, rel), filepath.Join(planted, rel))
	}
	plant := func(rel, src string) { writeFile(t, filepath.Join(planted, rel), src) }

	// 1. A legacy route registered in some other function.
	plant("platform/orchestrator/planted_route.go", `package orchestrator

import "github.com/gorilla/mux"

func plantedRoutes(r *mux.Router) {
	r.HandleFunc("/api/v1/templates/planted", nil).Methods("GET")
}
`)
	// 2. A second legacyRouter built outside the registrar.
	plant("platform/orchestrator/planted_constructor.go", `package orchestrator

import "github.com/gorilla/mux"

func plantedConstructor(r *mux.Router, h *DynamicPolicyAPIHandler) {
	h.RegisterRoutes(legacyRouter{r})
}
`)
	// 3. A declared registrar the tree declares that registers nothing.
	plant("platform/agent/planted_static_handlers.go", `package agent

import "github.com/gorilla/mux"

func RegisterStaticPolicyHandlers(r *mux.Router) {}
`)

	rep := censusTree(t, planted)
	if len(rep.derived.Routes) == 0 {
		t.Fatal("the planted tree derived no routes; every assertion below is vacuous")
	}
	if !containsSite(rep.outside, "planted_route.go") {
		t.Errorf("the census missed a /api/v1/templates route registered outside a registrar: outside=%v", rep.outside)
	}
	if !containsSite(rep.constructions, "planted_constructor.go") {
		t.Errorf("the census missed a legacyRouter constructed outside the registrar: constructions=%v", rep.constructions)
	}
	// The real registrars, copied unchanged, stay clean in the planted tree:
	// a census that flagged everything would pass the two checks above.
	for _, f := range rep.outside {
		if !strings.Contains(f.site, "planted_route.go") {
			t.Errorf("the census flagged an unplanted site: %s %s", f.site, f.why)
		}
	}
	if n := len(rep.sites["platform/orchestrator.registerLegacyPolicyRoutes"]); n == 0 {
		t.Error("the copied registrar registered nothing the census could classify")
	}

	// The stale-row rule, both shapes. The planted tree has no ee/, as the
	// community mirror has none, and it carries the real !enterprise rbi stub:
	// without ee/ every row that registers nothing is not in this tree, a
	// declared stub and a planted empty registrar included.
	const presentButEmpty = "platform/agent.RegisterStaticPolicyHandlers"
	zeroSiteRows := []string{
		presentButEmpty,
		"platform/agent.(*ReverseProxyHandler).RegisterProxyRoutes",
		"platform/orchestrator/rbi.(*RBIModule).RegisterRoutes",
		"platform/orchestrator/rbi.(*RBIModule).RegisterRoutesWithMux",
	}
	for _, k := range zeroSiteRows {
		if n := len(rep.sites[k]); n != 0 {
			t.Fatalf("%s registered %d site(s) in the planted tree; the rows below assume none", k, n)
		}
	}
	stale, notInTree := registrarRows(planted, rep)
	if len(stale) != 0 {
		t.Errorf("without ee/ no row may be stale, a declared stub included: stale=%v", stale)
	}
	for _, k := range zeroSiteRows {
		if !slices.Contains(notInTree, k) {
			t.Errorf("without ee/, %s registers nothing and must be not in this tree: notInTree=%v", k, notInTree)
		}
	}
	// The enterprise tree stays strict: with ee/ present, every row that
	// registers nothing is stale, declared or not.
	if err := os.MkdirAll(filepath.Join(planted, "ee"), 0o755); err != nil {
		t.Fatal(err)
	}
	stale, notInTree = registrarRows(planted, rep)
	if len(notInTree) != 0 {
		t.Errorf("with ee/ present no row may be not in this tree: notInTree=%v", notInTree)
	}
	for _, k := range zeroSiteRows {
		if !slices.Contains(stale, k) {
			t.Errorf("with ee/ present, %s registers nothing and must be stale: stale=%v", k, stale)
		}
	}
}

func containsSite(fs []finding, file string) bool {
	for _, f := range fs {
		if strings.Contains(f.site, file) || strings.Contains(f.why, file) {
			return true
		}
	}
	return false
}

func copyFile(t *testing.T, from, to string) {
	t.Helper()
	b, err := os.ReadFile(from)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, to, string(b))
}

func writeFile(t *testing.T, path, src string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
}

// fileIndex parses the files the census asks about, once each.
type fileIndex struct {
	root   string
	fset   *token.FileSet
	parsed map[string]*ast.File
}

func (x *fileIndex) file(rel string) (*ast.File, error) {
	if f, ok := x.parsed[rel]; ok {
		return f, nil
	}
	f, err := parser.ParseFile(x.fset, filepath.Join(x.root, rel), nil, parser.SkipObjectResolution)
	if err != nil {
		return nil, err
	}
	x.parsed[rel] = f
	return f, nil
}

// enclosing names the top-level declaration holding line in rel, as a
// legacyRegistrars key. A registration in a package-level initialiser has no
// function and is named for its package, which no row can match.
func (x *fileIndex) enclosing(rel string, line int) (string, error) {
	f, err := x.file(rel)
	if err != nil {
		return "", err
	}
	pkg := filepath.ToSlash(filepath.Dir(rel))
	for _, d := range f.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if !ok {
			continue
		}
		if x.fset.Position(fn.Pos()).Line <= line && line <= x.fset.Position(fn.End()).Line {
			return pkg + "." + funcName(fn), nil
		}
	}
	return pkg + ".<package-level>", nil
}

// funcByKey finds a declared registrar's declaration among the files already
// parsed, which hold every file a registration was found in.
func (x *fileIndex) funcByKey(key string) *ast.FuncDecl {
	for rel, f := range x.parsed {
		pkg := filepath.ToSlash(filepath.Dir(rel))
		for _, d := range f.Decls {
			if fn, ok := d.(*ast.FuncDecl); ok && pkg+"."+funcName(fn) == key {
				return fn
			}
		}
	}
	return nil
}

// compositeLiterals finds every `typeName{...}` literal in the non-test Go
// files of dir, named by its enclosing function.
func (x *fileIndex) compositeLiterals(dir, typeName string) []finding {
	var out []finding
	entries, err := os.ReadDir(dir)
	if err != nil {
		return []finding{{dir, err.Error()}}
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		rel, _ := filepath.Rel(x.root, filepath.Join(dir, e.Name()))
		f, err := x.file(rel)
		if err != nil {
			out = append(out, finding{rel, err.Error()})
			continue
		}
		ast.Inspect(f, func(n ast.Node) bool {
			cl, ok := n.(*ast.CompositeLit)
			if !ok {
				return true
			}
			if id, ok := cl.Type.(*ast.Ident); ok && id.Name == typeName {
				line := x.fset.Position(cl.Pos()).Line
				key, _ := x.enclosing(rel, line)
				out = append(out, finding{key, fmt.Sprintf("%s:%d", rel, line)})
			}
			return true
		})
	}
	return out
}

func funcName(fn *ast.FuncDecl) string {
	if fn.Recv == nil || len(fn.Recv.List) == 0 {
		return fn.Name.Name
	}
	return "(" + typeText(fn.Recv.List[0].Type) + ")." + fn.Name.Name
}

func firstParamType(fn *ast.FuncDecl) string {
	if fn.Type.Params == nil || len(fn.Type.Params.List) == 0 {
		return "<none>"
	}
	return typeText(fn.Type.Params.List[0].Type)
}

func typeText(e ast.Expr) string {
	switch v := e.(type) {
	case *ast.Ident:
		return v.Name
	case *ast.StarExpr:
		return "*" + typeText(v.X)
	case *ast.SelectorExpr:
		return typeText(v.X) + "." + v.Sel.Name
	}
	return fmt.Sprintf("%T", e)
}

// retiredPortalRegistrations are the route families the customer portal served
// before v11 and must not serve again: PRD §1.11, the portal shows only the new
// model. W3-I item 2b removed every registration under them, with the proxy
// allowlist rows that would otherwise have forwarded them ungated.
//
// THIS IS THE DECLARED SOURCE for the portal's retired surface (W3-M's taxon
// T4 reads it). Seven rows are the deprecated export families, which SDKs reach
// on the agent and orchestrator directly; TestNoLegacyPolicyRouteIsRegistered-
// OutsideAStampedRegistrar would also catch the portal re-registering one of
// those, because the portal is no longer a declared registrar. The last two are
// NOT deprecated families - they were portal-only - so nothing but this table
// catches their return.
var retiredPortalRegistrations = []struct{ family, reason string }{
	{"/api/v1/static-policies", "a legacy family: its deprecated reads stay on the agent (PRD §1.11)"},
	{"/api/v1/system-policies", "a legacy family: its deprecated reads stay on the agent (PRD §1.11)"},
	{"/api/v1/dynamic-policies", "a legacy family: its deprecated reads stay on the orchestrator (PRD §1.11)"},
	{"/api/v1/tenant-policies", "a legacy family: its deprecated reads stay on the orchestrator (PRD §1.11)"},
	{"/api/v1/policies", "a legacy family: its deprecated reads stay on the orchestrator (PRD §1.11)"},
	{"/api/v1/templates", "a legacy family: its deprecated reads stay on the orchestrator (PRD §1.11)"},
	{"/api/v1/policy-overrides", "a legacy family: its deprecated reads stay on the agent (PRD §1.11)"},
	{"/api/v1/unified-policies", "the portal-only aggregator of the legacy tables, removed with them"},
	{"/api/v1/policy-categories", "the portal-only category registry, built on the legacy aggregator's fetchers"},
}

// portalModuleDir is where the customer portal's Go source lives, repo-relative.
const portalModuleDir = "ee/platform/customer-portal/"

// retiredPortalFindings names every portal registration under a retired family.
func retiredPortalFindings(d *capability.Derivation) []finding {
	var out []finding
	for _, s := range d.Routes {
		if !s.Resolved || !strings.HasPrefix(filepath.ToSlash(s.File), portalModuleDir) {
			continue
		}
		for _, r := range retiredPortalRegistrations {
			if s.Pattern == r.family || strings.HasPrefix(s.Pattern, r.family+"/") {
				out = append(out, finding{fmt.Sprintf("%s:%d", s.File, s.Line),
					fmt.Sprintf("%s %s re-registers the retired portal family %s: %s", s.Method, s.Pattern, r.family, r.reason)})
			}
		}
	}
	return out
}

// TestNoRetiredPortalRegistrationIsRegisteredAgain reds when the customer
// portal registers a route under a family it retired in v11.
func TestNoRetiredPortalRegistrationIsRegisteredAgain(t *testing.T) {
	root := gocensus.RepoRoot(t)
	// KEYED ON ee/, NOT ON THE PORTAL'S ABSENCE: the community mirror carries no
	// ee/, so there is no portal to check there. On the enterprise tree a portal
	// the walk cannot see is the defect the floor below exists to catch.
	if _, err := os.Stat(filepath.Join(root, "ee")); os.IsNotExist(err) {
		t.Skip("no ee/ — community mirror tree, where the customer portal is not synced")
	}
	d, err := capability.Derive(root, censusRoots)
	if err != nil {
		t.Fatalf("derive routes under %s: %v", root, err)
	}
	portalSites := 0
	for _, s := range d.Routes {
		if s.Resolved && strings.HasPrefix(filepath.ToSlash(s.File), portalModuleDir) {
			portalSites++
		}
	}
	// The walk has to have seen the portal, or an empty finding list below
	// proves nothing.
	if portalSites < 100 {
		t.Fatalf("resolved %d portal registration sites; the walk has not seen the portal", portalSites)
	}
	t.Logf("%d resolved portal registration sites checked against %d retired families", portalSites, len(retiredPortalRegistrations))
	for _, f := range retiredPortalFindings(d) {
		t.Errorf("%s: %s", f.site, f.why)
	}
}

// TestTheRetiredPortalCensusFindsWhatItShould plants two retired families and
// one live one in a temporary portal tree, and requires the check to name
// exactly the two retired ones.
func TestTheRetiredPortalCensusFindsWhatItShould(t *testing.T) {
	planted := t.TempDir()
	writeFile(t, filepath.Join(planted, "ee/platform/customer-portal/planted_routes.go"), `package main

import "github.com/gorilla/mux"

func plantedPortalRoutes(r *mux.Router) {
	apiRouter := r.PathPrefix("/api/v1").Subrouter()
	apiRouter.HandleFunc("/unified-policies", nil).Methods("GET")
	apiRouter.HandleFunc("/policy-categories/{id}", nil).Methods("GET")
	apiRouter.HandleFunc("/typed-policies/settings", nil).Methods("GET")
}
`)
	d, err := capability.Derive(planted, censusRoots)
	if err != nil {
		t.Fatalf("derive planted tree: %v", err)
	}
	got := retiredPortalFindings(d)
	// Each planted name is checked BEFORE the count, so a failure says which
	// retired family went unnamed rather than only that the count moved.
	for _, want := range []string{"/api/v1/unified-policies", "/api/v1/policy-categories/{id}"} {
		found := false
		for _, f := range got {
			if strings.Contains(f.why, want) {
				found = true
			}
		}
		if !found {
			t.Errorf("the planted %s was not named: %v", want, got)
		}
	}
	if len(got) != 2 {
		t.Errorf("want exactly the two retired families named, got %d: %v", len(got), got)
	}
}
