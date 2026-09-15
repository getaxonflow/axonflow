// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package activation_test

import (
	"strings"
	"testing"

	"axonflow/platform/decision/legacycompile"
)

// THE CATEGORY-ADMISSION ARM (#3895 PR-A2).
//
// The detector census's `planes` column is the compiler's LOAD/PHASE model: a
// row is listed on every plane whose loader returns it for that phase. It is
// NOT what the plane's call sites EVALUATE, because every shared-engine call
// site narrows the loaded set with a Categories filter before a single pattern
// runs. A row that is loaded and not admitted never runs, so on an enforcing
// plane its detector signal is never produced and the control that reads it is
// UNKNOWN on every request - an anchored engine answering ERROR for everything,
// which is S10's whole-corpus measurement one level down.
//
// MEASURED on the decide plane before this arm existed: the four system
// security-admin controls (seeded category `security-admin`, core/031) were in
// the restriction, and decide's call site filters by mcpInputPolicyCategories
// plus the derived pii-* family, which does not name that category.
//
// So excluding such a control is the restriction telling the truth about what
// the plane can produce, not a narrowing of enforcement: the legacy engine does
// not evaluate it there either.
func TestTheRestrictionDropsWhatThePlanesCategoryFilterNeverEvaluates(t *testing.T) {
	adminControls := []string{
		legacycompile.CorpusPolicyIDFor("static_policies", "sys_admin_audit_log"),
		legacycompile.CorpusPolicyIDFor("static_policies", "sys_admin_config_table"),
		legacycompile.CorpusPolicyIDFor("static_policies", "sys_admin_info_schema"),
		legacycompile.CorpusPolicyIDFor("static_policies", "sys_admin_users_table"),
	}

	t.Run("decide does not bind a control its category filter never admits", func(t *testing.T) {
		doc, reason, err := restrict(string(legacycompile.PlaneDecide))
		if err != nil {
			t.Fatal(err)
		}
		kept := controlsOf(t, doc)
		for _, id := range adminControls {
			if kept[id] {
				t.Errorf("%s binds on decide, but decide's call site never evaluates category security-admin, so its "+
					"detector signal is never produced and the control would be UNKNOWN on every request", id)
			}
		}
		if !strings.Contains(reason, "category admission") {
			t.Errorf("the restriction reason does not name the category-admission arm, so an operator reading which "+
				"controls this plane enforces cannot see why four were left out: %s", reason)
		}
	})

	t.Run("the control: proxy_request, which admits security-admin since #4253, keeps the same four", func(t *testing.T) {
		// /api/request's detector pass admits security-admin since #4253, and
		// its PlaneSpec binds the four rows' stored block there (the refusal
		// its retired second pass gave). If the four vanish here too, the arm
		// is keying on something other than the plane's admission - an id
		// list, or a category refused everywhere.
		doc, _, err := restrict(string(legacycompile.PlaneProxyRequest))
		if err != nil {
			t.Fatal(err)
		}
		kept := controlsOf(t, doc)
		for _, id := range adminControls {
			if !kept[id] {
				t.Errorf("%s does not bind on proxy_request, whose admission names security-admin; the arm is not "+
					"reading the plane's admission", id)
			}
		}
	})
}
