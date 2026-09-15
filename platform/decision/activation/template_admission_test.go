// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package activation_test

import (
	"fmt"
	"sort"
	"strings"
	"testing"

	"axonflow/platform/decision/activation"
	"axonflow/platform/decision/legacycompile"
	"axonflow/platform/decision/pdp"
)

// THE TEMPLATE'S EIGHT v10-CATEGORY ROWS BIND ON THE PROXY AND NOWHERE NEW (#4131).
//
// migrations/core/010 and core/014 seeded eight organization-template rows
// under v10 categories core/127 never canonicalised, and every enforcing
// scope's category admission named canonical categories only, so the eight
// decided nothing on /api/request. The proxy admission now carries the three
// v10 spellings. These tests hold what that changes, per scope, on the shipped
// template.

// legacyCategoryRows are the eight rows, by corpus control, measured at #4131.
var legacyCategoryRows = []string{
	"corpus:static_policies:drop__table__prevention",
	"corpus:static_policies:eu__gdpr__credit__card__detection",
	"corpus:static_policies:eu__gdpr__loyalty__number__detection",
	"corpus:static_policies:eu__gdpr__passport__detection",
	"corpus:static_policies:pii__ssn__detection",
	"corpus:static_policies:sql__injection__or",
	"corpus:static_policies:sql__injection__union",
	"corpus:static_policies:truncate__prevention",
}

// scopesAdmittingLegacyCategories are the scopes whose admission names a v10
// spelling: /api/request's one pass. Its preview shares the call site, and the
// unfiltered tier engine that also admitted them retired with proxy_tier
// (#4253).
var scopesAdmittingLegacyCategories = map[string]bool{"proxy_request": true}

// templateControlsOn is the set of template controls the implicit bundle binds
// on scope, by corpus control (a split control's variants count once).
func templateControlsOn(t *testing.T, scope legacycompile.EnforcementScope) map[string]bool {
	t.Helper()
	doc, err := activation.OrganizationTemplateForScope(scope)
	if err != nil {
		t.Fatalf("restricting the template to %s: %v", scope, err)
	}
	out := map[string]bool{}
	for _, p := range doc.Policies {
		control, _, ok := legacycompile.CorpusControlOf(p.ID)
		if !ok {
			t.Fatalf("%s: template policy %q is not a corpus id", scope, p.ID)
		}
		out[control] = true
	}
	return out
}

// TestEveryTemplateRowBindsOnTheProxyRequestPass is the admission seam, one
// assertion per row: all twenty-two template controls bind on proxy_request,
// the eight v10-category rows among them.
func TestEveryTemplateRowBindsOnTheProxyRequestPass(t *testing.T) {
	template, err := pdp.SystemCorpusOrganizationTemplate()
	if err != nil {
		t.Fatal(err)
	}
	all := map[string]bool{}
	for _, p := range template.Policies {
		control, _, _ := legacycompile.CorpusControlOf(p.ID)
		all[control] = true
	}
	if len(all) != 22 {
		t.Fatalf("PREMISE: the organization template carries %d controls; #4131 was measured against 22", len(all))
	}
	bound := templateControlsOn(t, legacycompile.MustScopeFor(legacycompile.PlaneProxyRequest, ""))
	controls := make([]string, 0, len(all))
	for c := range all {
		controls = append(controls, c)
	}
	sort.Strings(controls)
	for _, c := range controls {
		c := c
		t.Run(c, func(t *testing.T) {
			if !bound[c] {
				t.Errorf("%s does not bind on proxy_request, so it decides nothing on /api/request", c)
			}
		})
	}
	for _, c := range legacyCategoryRows {
		if !all[c] {
			t.Errorf("PREMISE: %s is not an organization-template control", c)
		}
	}
}

// TestTheV10CategoryRowsBindOnlyWhereALegacySpellingIsAdmitted holds the other
// direction: no scope but the three that admit a v10 spelling binds any of the
// eight, so the proxy's admission did not widen decide, the gateway pre-check,
// the OpenAI-compatible route or MCP (#4230 is where that is decided).
func TestTheV10CategoryRowsBindOnlyWhereALegacySpellingIsAdmitted(t *testing.T) {
	var problems []string
	for _, s := range legacycompile.AllScopes() {
		bound := templateControlsOn(t, s)
		for _, c := range legacyCategoryRows {
			want := scopesAdmittingLegacyCategories[s.String()]
			if bound[c] != want {
				problems = append(problems, fmt.Sprintf("%s on %s: bound=%v, want %v", c, s, bound[c], want))
			}
		}
	}
	if len(problems) > 0 {
		t.Fatalf("the eight v10-category template rows bind where the admission does not say they should:\n  %s", strings.Join(problems, "\n  "))
	}
}
