// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package legacycompile

import (
	"fmt"
	"sort"
	"strings"
)

// CategoryAdmission is which static_policies categories a plane's call sites
// actually EVALUATE (#3895 PR-A2).
//
// # WHY IT IS A SECOND FACT AND NOT A CORRECTION OF THE FIRST
//
// Record.Planes - and the detector census's `planes` column, derived from it
// against a real migrated database - is this package's LOAD/PHASE model: a row
// is on every plane whose loader returns it for that plane's phases. That is
// right about what it describes, and it is pinned in both directions against a
// capture. What it does not model is that every shared-engine call site then
// narrows the loaded set with EvalOptions.Categories before a single pattern
// runs, so a loaded row outside that filter never evaluates. The two facts
// compose: what a plane EVALUATES is load ∩ admission.
//
// THE CONSUMER IS AN ENFORCING PLANE. activation.RestrictToScope reads it,
// because a control whose detector the plane never runs is UNKNOWN on every
// request there, and an anchored engine then answers ERROR for everything.
// Measured: the decide plane's four system security-admin controls.
//
// THE COMPILER DOES NOT READ IT, deliberately. Making the shadow compile
// load ∩ admission changes what every plane's shadow world contains, which is a
// gate-18 evidence decision rather than a seam decision, and it is tracked as
// its own child of #3895.
//
// # HOW IT IS KEPT TRUE
//
// This module cannot import platform/shared/policy, where the call sites'
// category lists live, so the lists are restated here as data, ONE PER CALL
// SITE (siteAdmissions) - and WELDED. platform/agent and platform/orchestrator
// each read their own call sites' real Categories expressions, keyed on
// legacy_call_sites.tsv (plane, evaluator, function), and fail when a site's
// expression differs from its declaration in either direction, or when a
// static call site nobody classified appears. PlaneSpec.Admission and
// AdmissionFor are both derived from the per-site declarations, so there is
// exactly one statement per site to keep true.
type CategoryAdmission struct {
	// Unfiltered is true when some call site on the plane evaluates with NO
	// category filter. It admits every category. No site declares it since
	// #4253 retired the one that did, the proxy tier engine's EvaluatePolicy,
	// which resolved through GetEffective and never took a Categories
	// argument. The welds still derive it from a site that passes no
	// Categories, so a new unfiltered site is classified rather than missed.
	Unfiltered bool
	// Categories are admitted by exact name: the union of the plane's call
	// sites' fixed Categories lists and of the single categories a site derives
	// from enabled policies (EnabledSensitiveDataCategories and
	// EnabledSecurityDangerousCategories each resolve to that one name or to
	// nothing).
	Categories []string
	// PIIFamily admits every text PII category - how a site that calls
	// EnabledPIICategories filters: by the `pii-*` convention rather than by a
	// list, so a newly seeded PII category is admitted without an edit.
	PIIFamily bool
}

// Admits reports whether a call site on this plane evaluates a row of the
// category.
func (a CategoryAdmission) Admits(category string) bool {
	if a.Unfiltered {
		return true
	}
	if a.PIIFamily && isPIICategory(category) {
		return true
	}
	for _, c := range a.Categories {
		if c == category {
			return true
		}
	}
	return false
}

// Declared reports whether the admission says anything at all. The zero value
// admits nothing, and on a plane that evaluates the static substrate that is a
// missing declaration, never a plane that evaluates no category - so a static
// plane with an undeclared admission is refused rather than restricted to
// nothing.
func (a CategoryAdmission) Declared() bool {
	return a.Unfiltered || a.PIIFamily || len(a.Categories) > 0
}

// Union is what a plane admits when two of its call sites admit a and b: a row
// evaluated by either site is evaluated on the plane.
func (a CategoryAdmission) Union(b CategoryAdmission) CategoryAdmission {
	return CategoryAdmission{
		Unfiltered: a.Unfiltered || b.Unfiltered,
		PIIFamily:  a.PIIFamily || b.PIIFamily,
		Categories: append(append([]string(nil), a.Categories...), b.Categories...),
	}.Canonical()
}

// Canonical is the form two admissions are compared in: an unfiltered
// admission carries nothing else, a name the PII family already covers is
// dropped, and the names are sorted and de-duplicated. Two admissions that
// admit exactly the same categories have equal canonical forms.
func (a CategoryAdmission) Canonical() CategoryAdmission {
	if a.Unfiltered {
		return CategoryAdmission{Unfiltered: true}
	}
	set := map[string]bool{}
	for _, c := range a.Categories {
		if a.PIIFamily && isPIICategory(c) {
			continue
		}
		set[c] = true
	}
	out := CategoryAdmission{PIIFamily: a.PIIFamily}
	for c := range set {
		out.Categories = append(out.Categories, c)
	}
	sort.Strings(out.Categories)
	return out
}

// String renders the admission for a reason string or a failure message.
func (a CategoryAdmission) String() string {
	c := a.Canonical()
	if c.Unfiltered {
		return "unfiltered"
	}
	var parts []string
	if c.PIIFamily {
		parts = append(parts, "pii-*")
	}
	parts = append(parts, c.Categories...)
	if len(parts) == 0 {
		return "none"
	}
	return strings.Join(parts, ",")
}

// The category lists the call sites pass, restated as data and welded by the
// platform-side guards (see CategoryAdmission). Named after the Go expression
// each one mirrors, so a failure message and a reader land on the same line.
var (
	// sharedpolicy.AllComplianceCategories()
	complianceCategories = []string{
		"compliance-gdpr", "compliance-hipaa", "compliance-rbi", "compliance-sebi", "compliance-euaiact",
		"compliance-masfeat", "compliance-glba", "compliance-fairlending", "compliance-bsa-aml", "compliance-nydfs",
	}
	// sharedpolicy.AllTextPIICategories() - an explicit LIST, which is not the
	// PII family: a pii category added to the database and not to that function
	// is admitted by the family and not by this.
	textPIICategories = []string{
		"pii-global", "pii-us", "pii-india", "pii-eu", "pii-singapore", "pii-indonesia",
	}
	// sharedpolicy.LegacyTemplateCategories() (#4131): the v10 spellings the
	// organization template's DROP/TRUNCATE, SQL-injection and PII rows still
	// carry. Only the proxy's one call site admits them (proxyDetectorPass, which
	// /api/request and its preview share); canonicalising them would
	// bind the rows on every plane below that admits the canonical names (#4230).
	legacyTemplateCategories = []string{
		"sql_injection", "dangerous_queries", "pii_detection",
	}

	// platform/agent evaluateInputPolicies: mcpInputPolicyCategories plus the
	// categories EnabledPIICategories derives.
	inputPoliciesAdmission = CategoryAdmission{
		Categories: joinCategories([]string{"security-sqli", "security-dangerous", "sensitive-data", "fincrime"}, complianceCategories),
		PIIFamily:  true,
	}
	// platform/agent evaluateOutputPolicies: EnabledPIICategories +
	// EnabledSensitiveDataCategories + EnabledSecurityDangerousCategories.
	outputPoliciesAdmission = CategoryAdmission{
		Categories: []string{"sensitive-data", "security-dangerous"},
		PIIFamily:  true,
	}
	// A site whose only filter is EnabledPIICategories.
	piiOnlyAdmission = CategoryAdmission{PIIFamily: true}
	// platform/agent gatewayPreCheckPolicyCategories and
	// openaiCompatPolicyCategories, which are the same composition.
	preCheckAdmission = CategoryAdmission{
		Categories: joinCategories([]string{"security-sqli", "security-dangerous", "sensitive-data"}, complianceCategories, textPIICategories),
	}
	// platform/agent proxyPolicyCategories. It names "admin-access", which is
	// the shared constant's spelling and NOT the seeded rows' ("security-admin",
	// core/031) - a legacy defect tracked on #3323. It ALSO names
	// "security-admin" since #4253, on this plane alone: /api/request's retired
	// second pass refused the four sys_admin_* rows, PlaneSpec.EnforcesRetiredTierPassRead
	// binds their stored block here, and a bound control whose detector this
	// plane does not run would be UNKNOWN on every request. It is the one
	// declaration carrying legacyTemplateCategories (#4131).
	proxyAdmission = CategoryAdmission{
		Categories: joinCategories([]string{"security-sqli", "security-dangerous", "admin-access", "security-admin", "sensitive-data"}, complianceCategories, textPIICategories, legacyTemplateCategories),
	}
	// platform/orchestrator responseDetectorPass: EnabledPIICategories +
	// EnabledSensitiveDataCategories.
	responseProcessorAdmission = CategoryAdmission{
		Categories: []string{"sensitive-data"},
		PIIFamily:  true,
	}
)

// siteAdmissions is the category admission of EACH static call site, keyed as
// legacy_call_sites.tsv names it (CallSite.Key).
//
// IT IS DECLARED PER SITE, AND A PLANE'S ADMISSION IS DERIVED FROM IT (#3564).
// It was declared per plane, as a union written beside each PlaneSpec, which
// was right while a plane was the unit of enforcement and is wrong the moment a
// phase is: `mcp`'s request pass admits security-sqli, fincrime and the
// compliance family, and its response pass admits none of them, so a union
// cannot say what either pass evaluates. Keying on the site - the thing the
// platform-side welds already read the real Categories expression of - gives
// both answers from one statement, and PlaneSpec.Admission becomes their union
// rather than a second declaration that could disagree with it.
var siteAdmissions = map[string]CategoryAdmission{
	"cowork_ingest|EvaluateResponse|coworkRedactDefault":          piiOnlyAdmission,
	"decide|EvaluateRequest|evaluateInputPolicies":                inputPoliciesAdmission,
	"gateway_request|EvaluateRequest|handlePolicyPreCheck":        preCheckAdmission,
	"mcp|EvaluateRequest|evaluateInputPolicies":                   inputPoliciesAdmission,
	"mcp|EvaluateResponse|evaluateOutputPolicies":                 outputPoliciesAdmission,
	"openai_compatible|EvaluateRequest|handleOpenAICompat":        preCheckAdmission,
	"orchestrator_response|EvaluateResponse|responseDetectorPass": responseProcessorAdmission,
	"proxy_request|EvaluateRequest|proxyDetectorPass":             proxyAdmission,
}

// SiteAdmission returns what one static call site admits, and whether it is
// declared.
func SiteAdmission(site CallSite) (CategoryAdmission, bool) {
	a, ok := siteAdmissions[site.Key()]
	return a, ok
}

// AdmissionFor is what a plane's call sites for ONE phase admit: the union of
// the declared admissions of the census's static sites on that plane whose
// evaluator loads that phase.
//
// It REFUSES rather than returning a narrower answer when any such site has no
// declaration, and when the plane has no static site in the phase at all,
// because the zero admission reads as "this pass evaluates no category" and
// would restrict an enforcing engine to nothing for a reason nobody stated.
func AdmissionFor(p Plane, ph Phase) (CategoryAdmission, error) {
	sites, err := CallSites()
	if err != nil {
		return CategoryAdmission{}, err
	}
	var out CategoryAdmission
	contributed := false
	for _, s := range sites {
		if s.Plane != p || !s.StaticEvaluator() || s.Phase() != ph {
			continue
		}
		a, ok := SiteAdmission(s)
		if !ok {
			return CategoryAdmission{}, fmt.Errorf("legacycompile: static call site %s evaluates plane %q's %s phase and declares no category admission", s.Key(), p, ph)
		}
		out = out.Union(a)
		contributed = true
	}
	if !contributed {
		return CategoryAdmission{}, fmt.Errorf("legacycompile: plane %q has no static call site in the %q phase, so no admission can be derived for it", p, ph)
	}
	return out, nil
}

// planeAdmissionFromSites derives a plane's admission from its sites. A site
// with no declaration leaves the plane UNDECLARED - the zero admission, which
// activation refuses by name - rather than narrowed to the sites that happen to
// have one.
func planeAdmissionFromSites(p Plane, sites []CallSite) CategoryAdmission {
	var out CategoryAdmission
	for _, s := range sites {
		if s.Plane != p || !s.StaticEvaluator() {
			continue
		}
		a, ok := SiteAdmission(s)
		if !ok {
			return CategoryAdmission{}
		}
		out = out.Union(a)
	}
	return out
}

func init() {
	// A census the reader refuses leaves every admission undeclared, and every
	// static plane's restriction is then refused by name; the reader's own
	// tests say why the census did not parse.
	sites, err := CallSites()
	if err != nil {
		return
	}
	for p, spec := range planeSpecs {
		spec.Admission = planeAdmissionFromSites(p, sites)
		planeSpecs[p] = spec
	}
}

func joinCategories(lists ...[]string) []string {
	var out []string
	for _, l := range lists {
		out = append(out, l...)
	}
	return out
}
