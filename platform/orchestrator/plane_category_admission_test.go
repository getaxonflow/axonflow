// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"reflect"
	"sort"
	"strings"
	"testing"

	"axonflow/platform/decision/legacycompile"
	sharedpolicy "axonflow/platform/shared/policy"
)

// THE CATEGORY-ADMISSION WELD for the orchestrator's static call sites
// (#3895 PR-A2). See platform/agent/plane_category_admission_test.go for the
// argument; this is the same check over the call sites that live in this
// binary, because a plane's sites are welded where their Categories
// expressions are visible.
//
// Both orchestrator sites filter by per-request derivations only - no package
// var carries a list - so what this reads is each site's classification against
// the census and the declared union, and a static call site nobody classified
// fails here exactly as it does in the agent.
var orchestratorStaticCallSiteAdmissions = map[string]func() legacycompile.CategoryAdmission{
	// responseDetectorPass: EnabledPIICategories + EnabledSensitiveDataCategories.
	"orchestrator_response|EvaluateResponse|responseDetectorPass": func() legacycompile.CategoryAdmission {
		return legacycompile.CategoryAdmission{
			Categories: []string{string(sharedpolicy.CategorySensitiveData)},
			PIIFamily:  true,
		}
	},
}

func TestTheOrchestratorStaticCallSitesAdmitWhatTheirPlaneDeclares(t *testing.T) {
	sites, err := legacycompile.CallSites()
	if err != nil {
		t.Fatal(err)
	}
	perPlane := map[legacycompile.Plane]legacycompile.CategoryAdmission{}
	seen := map[string]bool{}
	for _, s := range sites {
		if !s.StaticEvaluator() || !strings.HasPrefix(s.File, "platform/orchestrator/") {
			continue
		}
		key := string(s.Plane) + "|" + s.Evaluator + "|" + s.Function
		build, ok := orchestratorStaticCallSiteAdmissions[key]
		if !ok {
			t.Errorf("legacy_call_sites.tsv names static call site %s (%s) and nobody classified which categories it "+
				"evaluates; add it to orchestratorStaticCallSiteAdmissions and declare the result in "+
				"legacycompile.PlaneSpec.Admission", key, s.File)
			continue
		}
		seen[key] = true
		perPlane[s.Plane] = perPlane[s.Plane].Union(build())
	}
	for key := range orchestratorStaticCallSiteAdmissions {
		if !seen[key] {
			t.Errorf("orchestratorStaticCallSiteAdmissions classifies %s, which legacy_call_sites.tsv no longer names", key)
		}
	}
	if len(perPlane) == 0 {
		t.Fatal("no orchestrator static call site was read; the census reader or the file filter matched nothing")
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
			t.Errorf("plane %s: its orchestrator call sites evaluate categories {%v}, but legacycompile.PlaneSpec.Admission "+
				"declares {%v}; make the declaration the union of the sites", plane, got, declared)
		}
	}
}
