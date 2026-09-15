// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"reflect"
	"sort"
	"strings"
	"testing"

	"axonflow/platform/decision/legacycompile"
	"axonflow/platform/decision/registry"
	sharedpolicy "axonflow/platform/shared/policy"
)

// THE CATEGORY-ADMISSION WELD for the agent's call sites (#3895 PR-A2).
//
// legacycompile.PlaneSpec.Admission states which categories each plane's call
// sites pass to the evaluator, and activation's plane restriction reads it: a
// control whose category no call site on a plane evaluates is left out, because
// its detector signal is never produced there and an enforcing engine would
// otherwise answer ERROR on every request. The decision module cannot import
// this package, so the admission is restated there as data - and this test is
// what keeps the restatement true.
//
// # WHAT IT READS, AND WHAT IT CANNOT
//
// Each classified site's admission is built from the REAL expression the site
// passes: the package vars (mcpInputPolicyCategories and the rest) are read
// directly, so adding or removing a category there moves this test. What cannot
// be read is the SHAPE of a per-request derivation - "this site calls
// EnabledPIICategories" - so those are stated beside the var, once per site,
// and the derived helpers' own semantics are welded below (the pii-* family
// against sharedpolicy.IsPIIPolicyCategory).
//
// # THE THREE WAYS IT FAILS, EACH PLANTED
//
//   - a site's expression admits a category its plane's declaration does not;
//   - the declaration admits a category no site on the plane evaluates;
//   - a static call site appears in legacy_call_sites.tsv that nobody classified
//     here - so a new way of reaching the evaluator cannot join a plane without
//     somebody saying what it filters.
var agentStaticCallSiteAdmissions = map[string]func() legacycompile.CategoryAdmission{
	// evaluateInputPolicies: mcpInputPolicyCategories plus EnabledPIICategories.
	"decide|EvaluateRequest|evaluateInputPolicies": func() legacycompile.CategoryAdmission {
		return admissionFromCategories(mcpInputPolicyCategories, true)
	},
	"mcp|EvaluateRequest|evaluateInputPolicies": func() legacycompile.CategoryAdmission {
		return admissionFromCategories(mcpInputPolicyCategories, true)
	},
	// evaluateOutputPolicies: EnabledPIICategories + EnabledSensitiveDataCategories
	// + EnabledSecurityDangerousCategories, each of which resolves to its one
	// category or to nothing.
	"mcp|EvaluateResponse|evaluateOutputPolicies": func() legacycompile.CategoryAdmission {
		return admissionFromCategories([]sharedpolicy.PolicyCategory{
			sharedpolicy.CategorySensitiveData, sharedpolicy.CategorySecurityDangerous,
		}, true)
	},
	"gateway_request|EvaluateRequest|handlePolicyPreCheck": func() legacycompile.CategoryAdmission {
		return admissionFromCategories(gatewayPreCheckPolicyCategories, false)
	},
	"openai_compatible|EvaluateRequest|handleOpenAICompat": func() legacycompile.CategoryAdmission {
		return admissionFromCategories(openaiCompatPolicyCategories, false)
	},
	// proxyDetectorPass: /api/request's one pass, which its preview also runs (#4253).
	"proxy_request|EvaluateRequest|proxyDetectorPass": func() legacycompile.CategoryAdmission {
		return admissionFromCategories(proxyPolicyCategories, false)
	},
	// coworkRedactDefault: EnabledPIICategories only.
	"cowork_ingest|EvaluateResponse|coworkRedactDefault": func() legacycompile.CategoryAdmission {
		return admissionFromCategories(nil, true)
	},
}

func admissionFromCategories(cats []sharedpolicy.PolicyCategory, derivesPII bool) legacycompile.CategoryAdmission {
	a := legacycompile.CategoryAdmission{PIIFamily: derivesPII}
	for _, c := range cats {
		a.Categories = append(a.Categories, string(c))
	}
	return a.Canonical()
}

func TestEveryAgentStaticCallSiteAdmitsWhatItsPlaneDeclares(t *testing.T) {
	sites, err := legacycompile.CallSites()
	if err != nil {
		t.Fatal(err)
	}

	perPlane := map[legacycompile.Plane]legacycompile.CategoryAdmission{}
	contributors := map[legacycompile.Plane][]string{}
	seen := map[string]bool{}
	for _, s := range sites {
		if !s.StaticEvaluator() || !strings.HasPrefix(s.File, "platform/agent/") {
			continue
		}
		key := string(s.Plane) + "|" + s.Evaluator + "|" + s.Function
		build, ok := agentStaticCallSiteAdmissions[key]
		if !ok {
			t.Errorf("legacy_call_sites.tsv names static call site %s (%s) and nobody classified which categories it "+
				"evaluates; add it to agentStaticCallSiteAdmissions from its real Categories expression, and "+
				"declare the result in legacycompile.PlaneSpec.Admission", key, s.File)
			continue
		}
		seen[key] = true
		perPlane[s.Plane] = perPlane[s.Plane].Union(build())
		contributors[s.Plane] = append(contributors[s.Plane], s.Function)
	}
	// ANTI-VACUITY in the other direction: a classification whose site left the
	// census is a statement about code that no longer reaches the evaluator.
	for key := range agentStaticCallSiteAdmissions {
		if !seen[key] {
			t.Errorf("agentStaticCallSiteAdmissions classifies %s, which legacy_call_sites.tsv no longer names", key)
		}
	}
	if len(perPlane) == 0 {
		t.Fatal("no agent static call site was read; the census reader or the file filter matched nothing")
	}

	planes := make([]string, 0, len(perPlane))
	for p := range perPlane {
		planes = append(planes, string(p))
	}
	sort.Strings(planes)
	for _, name := range planes {
		plane := legacycompile.Plane(name)
		got := perPlane[plane].Canonical()
		declared := legacycompile.MustSpecFor(plane).Admission.Canonical()
		if !reflect.DeepEqual(got, declared) {
			t.Errorf("plane %s: its call sites %v evaluate categories {%v}, but legacycompile.PlaneSpec.Admission declares {%v}. "+
				"The plane restriction reads the declaration, so an enforcing engine would bind a control this plane "+
				"never evaluates (UNKNOWN on every request) or drop one it does. Make the declaration the union of the sites.",
				plane, contributors[plane], got, declared)
		}
	}
}

// TestThePIIFamilyIsTheSharedEnginesPIIConvention welds the one derived rule
// the admission model restates: EnabledPIICategories keeps a category exactly
// when sharedpolicy.IsPIIPolicyCategory says it is PII, and the admission's
// PIIFamily must agree on every category the tree knows - the canonical ones
// and every category the shipped detector census seeds, pre-canonical
// spellings included.
func TestThePIIFamilyIsTheSharedEnginesPIIConvention(t *testing.T) {
	cats := map[string]bool{}
	for _, c := range sharedpolicy.AllPolicyCategories() {
		cats[string(c)] = true
	}
	rows, err := registry.ShippedCensus()
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		cats[r.Category] = true
	}
	family := legacycompile.CategoryAdmission{PIIFamily: true}
	for c := range cats {
		if family.Admits(c) != sharedpolicy.IsPIIPolicyCategory(sharedpolicy.PolicyCategory(c)) {
			t.Errorf("category %q: the admission's PII family says %v, sharedpolicy.IsPIIPolicyCategory says %v",
				c, family.Admits(c), sharedpolicy.IsPIIPolicyCategory(sharedpolicy.PolicyCategory(c)))
		}
	}
	if len(cats) < 20 {
		t.Fatalf("only %d categories were compared; the comparison is not seeing the tree", len(cats))
	}
}
