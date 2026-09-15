// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"strings"
	"testing"

	"axonflow/platform/decision/legacycompile"
	sharedpolicy "axonflow/platform/shared/policy"
)

// clearDetectionNarrowing unsets every narrowing variable for the test, so the
// operator's shell cannot decide the outcome.
func clearDetectionNarrowing(t *testing.T) {
	t.Helper()
	for _, name := range []string{
		EnvMCPStaticPoliciesEnabled, EnvGatewayStaticPoliciesEnabled,
		EnvMCPStaticPoliciesSkipCategories, EnvGatewayStaticPoliciesSkipCategories,
		EnvMCPStaticPoliciesConnectors,
	} {
		t.Setenv(name, "")
	}
}

// admittedAndNotAdmitted derives one category an enforcing scope evaluates and
// one none does, from the same plane registry the refusal reads - so the
// planted category is admitted because the registry says so, not because this
// test listed it.
func admittedAndNotAdmitted(t *testing.T) (admitted, notAdmitted string) {
	t.Helper()
	candidates := []sharedpolicy.PolicyCategory{
		sharedpolicy.CategorySecuritySQLi, sharedpolicy.CategoryPIIUS, sharedpolicy.CategorySensitiveData,
		sharedpolicy.CategoryAdminAccess, sharedpolicy.CategoryDataExfiltration, sharedpolicy.CategoryDynamicRateLimit,
		sharedpolicy.CategoryDynamicBudget, sharedpolicy.CategoryComplianceHIPAA,
	}
	for _, c := range candidates {
		got, err := admittedByAnEnforcingScope([]sharedpolicy.PolicyCategory{c})
		if err != nil {
			t.Fatal(err)
		}
		if len(got) == 1 && admitted == "" {
			admitted = string(c)
		}
		if len(got) == 0 && notAdmitted == "" {
			notAdmitted = string(c)
		}
	}
	if admitted == "" || notAdmitted == "" {
		t.Fatalf("PREMISE: among %v the registry admits %q and leaves out %q; the planted positive and negative need one of each", candidates, admitted, notAdmitted)
	}
	return admitted, notAdmitted
}

func TestTheDefaultDetectionConfigurationBoots(t *testing.T) {
	clearDetectionNarrowing(t)
	if err := refuseNarrowedDetection(); err != nil {
		t.Fatalf("nothing is set and boot was refused: %v", err)
	}
	// The values docker-compose passes through: on, and empty lists.
	t.Setenv(EnvMCPStaticPoliciesEnabled, "true")
	t.Setenv(EnvGatewayStaticPoliciesEnabled, "true")
	if err := refuseNarrowedDetection(); err != nil {
		t.Fatalf("the shipped compose defaults refused boot: %v", err)
	}
}

func TestANarrowingDetectionValueRefusesBootByName(t *testing.T) {
	admitted, _ := admittedAndNotAdmitted(t)
	for _, c := range []struct {
		name, value string
		want        []string
	}{
		{EnvMCPStaticPoliciesEnabled, "false", []string{EnvMCPStaticPoliciesEnabled + `="false"`}},
		{EnvGatewayStaticPoliciesEnabled, "0", []string{EnvGatewayStaticPoliciesEnabled + `="0"`}},
		{EnvMCPStaticPoliciesSkipCategories, admitted, []string{EnvMCPStaticPoliciesSkipCategories, admitted}},
		{EnvGatewayStaticPoliciesSkipCategories, " " + admitted + " ,", []string{EnvGatewayStaticPoliciesSkipCategories, admitted}},
		{EnvMCPStaticPoliciesConnectors, "postgres", []string{EnvMCPStaticPoliciesConnectors + `="postgres"`}},
	} {
		t.Run(c.name+"="+c.value, func(t *testing.T) {
			clearDetectionNarrowing(t)
			t.Setenv(c.name, c.value)
			err := refuseNarrowedDetection()
			if err == nil {
				t.Fatalf("%s=%q booted; a narrowing value must refuse", c.name, c.value)
			}
			for _, want := range append(c.want, "§1.7", "detection_action_overrides") {
				if !strings.Contains(err.Error(), want) {
					t.Fatalf("the refusal does not name %q: %v", want, err)
				}
			}
		})
	}
}

// A skip list that names only categories no enforcing scope evaluates narrows
// nothing the engine decides, so it boots. Without this control the refusal
// above could be refusing every non-empty list.
func TestASkipListNoEnforcingScopeEvaluatesBoots(t *testing.T) {
	_, notAdmitted := admittedAndNotAdmitted(t)
	clearDetectionNarrowing(t)
	t.Setenv(EnvMCPStaticPoliciesSkipCategories, notAdmitted)
	t.Setenv(EnvGatewayStaticPoliciesSkipCategories, notAdmitted)
	if err := refuseNarrowedDetection(); err != nil {
		t.Fatalf("a skip list of %q, which no enforcing scope evaluates, refused boot: %v", notAdmitted, err)
	}
}

// THE ADMISSION IS THE ENFORCING SCOPES', AND EVERY ONE OF THEM COUNTS. A
// category admitted by exactly one scope must still refuse: the union is over
// every seam, not the first.
func TestEveryEnforcingScopeContributesToTheSkipCheck(t *testing.T) {
	for _, seam := range enforcingSeams {
		if !evaluatesStaticSubstrate(seam.scope.Plane) {
			continue
		}
		for _, ph := range seam.scope.Phases() {
			a, err := legacycompile.AdmissionFor(seam.scope.Plane, ph)
			if err != nil {
				t.Fatalf("%s: %v", seam.scope, err)
			}
			for _, c := range a.Categories {
				got, err := admittedByAnEnforcingScope([]string{c})
				if err != nil {
					t.Fatal(err)
				}
				if len(got) != 1 {
					t.Fatalf("%s admits %q and the skip check does not count it", seam.scope, c)
				}
			}
		}
	}
}
