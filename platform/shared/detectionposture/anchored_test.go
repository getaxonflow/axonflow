// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package detectionposture

import (
	"reflect"
	"strings"
	"testing"

	"axonflow/platform/decision/legacycompile"
	sharedpolicy "axonflow/platform/shared/policy"
)

// The fan-out is stated in literals, so a refactor that made the reach and its
// inverse agree on the wrong answer still fails here.
func TestAnchoredCategoryActionsFansEachRecordedCategoryOntoItsPolicyCategories(t *testing.T) {
	want := legacycompile.CategoryActions{
		string(sharedpolicy.CategoryPIIGlobal):         legacycompile.ActionRedact,
		string(sharedpolicy.CategoryPIIUS):             legacycompile.ActionRedact,
		string(sharedpolicy.CategoryPIIIndia):          legacycompile.ActionRedact,
		string(sharedpolicy.CategoryPIIEU):             legacycompile.ActionRedact,
		string(sharedpolicy.CategoryPIISingapore):      legacycompile.ActionRedact,
		string(sharedpolicy.CategoryPIIIndonesia):      legacycompile.ActionRedact,
		string(sharedpolicy.CategorySecuritySQLi):      legacycompile.ActionBlock,
		string(sharedpolicy.CategorySecurityDangerous): legacycompile.ActionWarn,
	}
	got, err := AnchoredCategoryActions(map[string]string{
		CategoryPII: ActionRedact, CategorySQLI: ActionBlock, CategoryDangerousCommand: ActionWarn,
		// Inert: recorded, and assigning nothing on either engine.
		CategoryDangerousQuery: ActionBlock, CategoryObligationFallback: ActionLog,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("the recorded posture folds to %v; want %v", got, want)
	}
}

func TestAnchoredCategoryActionsAssignsNothingForNothingOrOnlyInert(t *testing.T) {
	for _, recorded := range []map[string]string{nil, {}, {CategoryDangerousQuery: ActionBlock}, {CategoryObligationFallback: ActionBlock}} {
		if got, err := AnchoredCategoryActions(recorded); err != nil || got != nil {
			t.Fatalf("%v folds to (%v, %v); want nothing assigned", recorded, got, err)
		}
	}
}

func TestAnchoredCategoryActionsRefusesWhatTheAnchoredEngineCannotExpress(t *testing.T) {
	for _, tc := range []struct {
		recorded map[string]string
		naming   string
	}{
		{map[string]string{"exfiltration": ActionBlock}, `"exfiltration"`},
		{map[string]string{CategoryPII: "allow"}, `"allow"`},
	} {
		got, err := AnchoredCategoryActions(tc.recorded)
		if err == nil || !strings.Contains(err.Error(), tc.naming) {
			t.Fatalf("%v folds to (%v, %v); want a refusal naming %s", tc.recorded, got, err, tc.naming)
		}
	}
}

// InertCategories hands a guard the inert table: it must equal its source, and
// a caller that edits what it returns must leave the source as it was.
func TestInertCategoriesIsACopyOfItsSource(t *testing.T) {
	got := InertCategories()
	if len(got) == 0 || !reflect.DeepEqual(got, inertCategories) {
		t.Fatalf("InertCategories() = %v; want its source %v", got, inertCategories)
	}
	for category := range got {
		got[category] = "edited"
	}
	got["planted"] = "x"
	if reflect.DeepEqual(InertCategories(), got) || inertCategories[CategoryDangerousQuery] == "edited" {
		t.Fatal("editing the table InertCategories returned edited its source")
	}
}
