// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

// #3529: every US compliance template seeded by
// migrations/enterprise/139_us_compliance_templates.sql must be APPLICABLE.
//
// WHY THIS EXISTS. A policy template is not a document. It is the input to
// POST /api/v1/templates/{id}/apply, which reads the template's `type`,
// `conditions` and `actions` and builds a policy from them. A template naming
// a condition field, a condition operator, an action type or a policy type the
// validators do not accept is a row that lists perfectly in the portal catalog
// and FAILS the moment a customer clicks Apply. Every other assertion about
// these templates - that the rows exist, that the category is canonical, that
// the descriptions are present - passes just as happily on a template that can
// never be used.
//
// WHY IT LIVES IN THIS PACKAGE. ValidPolicyTypes, ValidPolicyFields,
// ValidPolicyOperators and ValidActionTypes are orchestrator-package values,
// and the agent package (which owns the migration's real-Postgres test) cannot
// import the orchestrator without an import cycle. Restating the four
// vocabularies over there would be a hand-copied duplicate of exactly the kind
// this change is trying to stop producing, so the check is here, where it can
// read the shipped lists.
//
// WHY IT PARSES THE MIGRATION FILE. Reading the SQL is what makes this a test
// of the shipped artifact rather than of a fixture. No database is needed: the
// template JSON is in the file, and the vocabularies are in this package.

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

const usTemplateMigrationPath = "../../migrations/enterprise/139_us_compliance_templates.sql"

type usTemplateBody struct {
	Name       string `json:"name"`
	Type       string `json:"type"`
	Conditions []struct {
		Field    string      `json:"field"`
		Operator string      `json:"operator"`
		Value    interface{} `json:"value"`
	} `json:"conditions"`
	Actions []struct {
		Type   string                 `json:"type"`
		Config map[string]interface{} `json:"config"`
	} `json:"actions"`
	Priority int `json:"priority"`
}

func TestUSComplianceTemplatesAreApplicable(t *testing.T) {
	raw, err := os.ReadFile(usTemplateMigrationPath)
	if err != nil {
		// The migration is enterprise-only and excluded from the community
		// mirror's source tree. Skip where it legitimately is not present
		// rather than failing the community build.
		if os.IsNotExist(err) {
			t.Skipf("%s not present in this edition; skipping", usTemplateMigrationPath)
		}
		t.Fatalf("read %s: %v", usTemplateMigrationPath, err)
	}

	valid := func(list []string, want string) bool {
		for _, v := range list {
			if v == want {
				return true
			}
		}
		return false
	}

	var checked int
	for _, m := range jsonbLiteral.FindAllStringSubmatch(string(raw), -1) {
		body := m[1]
		if !strings.Contains(body, `"conditions"`) {
			continue // a `variables` literal or some other object, not a template
		}

		var tpl usTemplateBody
		if err := json.Unmarshal([]byte(body), &tpl); err != nil {
			t.Errorf("a seeded template body is not valid JSON, so ApplyTemplate cannot parse it: %v\nbody: %s", err, body)
			continue
		}
		checked++

		if tpl.Name == "" {
			t.Error("a seeded template body has no \"name\"")
		}

		// Policy type: extractPolicyFields defaults to "content" when absent,
		// but an explicitly WRONG type is not defaulted and reaches the policy.
		if tpl.Type != "" && !valid(ValidPolicyTypes, tpl.Type) {
			t.Errorf("template %q declares policy type %q, which is not in ValidPolicyTypes - applying it would create a policy with an unrecognised type", tpl.Name, tpl.Type)
		}

		if len(tpl.Conditions) == 0 {
			t.Errorf("template %q has no conditions - it would match everything or nothing depending on the evaluator, neither of which is what a compliance control should do", tpl.Name)
		}
		for i, c := range tpl.Conditions {
			if !valid(ValidPolicyFields, c.Field) {
				t.Errorf("template %q condition %d uses field %q, which is not in ValidPolicyFields - the condition can never match", tpl.Name, i, c.Field)
			}
			if !valid(ValidPolicyOperators, c.Operator) {
				t.Errorf("template %q condition %d uses operator %q, which is not in ValidPolicyOperators - apply would reject or the condition would never fire", tpl.Name, i, c.Operator)
			}
			if c.Value == nil {
				t.Errorf("template %q condition %d has a null value", tpl.Name, i)
			}
		}

		if len(tpl.Actions) == 0 {
			t.Errorf("template %q has no actions - applying it would create a policy that detects and then does nothing, not even log", tpl.Name)
		}
		for i, a := range tpl.Actions {
			if !valid(ValidActionTypes, a.Type) {
				t.Errorf("template %q action %d has type %q, which is not in ValidActionTypes - the policy would be created with an action nothing executes", tpl.Name, i, a.Type)
			}
		}
	}

	// Anti-vacuity. Every assertion above is inside the loop, so a pattern that
	// matched nothing - a reformatted migration, a moved file, a changed cast -
	// would make this test pass while checking zero templates. Nine is the
	// seeded count and it is asserted, not merely required to be non-zero.
	const wantTemplates = 9
	if checked != wantTemplates {
		t.Errorf("parsed %d template bodies from %s, want %d - if the migration genuinely changed its template count, update this number deliberately; if it did not, the parser stopped matching and every check above was skipped", checked, usTemplateMigrationPath, wantTemplates)
	}
}

// TestUSComplianceTemplateVocabulariesAreNonEmpty guards the guard. Every check
// above is "is X in list L"; if any L were empty, every check would fail loudly
// rather than silently, but if a list were replaced by one containing a single
// permissive entry the checks would weaken invisibly. Assert the four lists
// still carry the values the templates actually rely on.
func TestUSComplianceTemplateVocabulariesAreNonEmpty(t *testing.T) {
	for name, pair := range map[string]struct {
		list []string
		want string
	}{
		"ValidPolicyTypes":     {ValidPolicyTypes, "content"},
		"ValidPolicyFields":    {ValidPolicyFields, "query"},
		"ValidPolicyOperators": {ValidPolicyOperators, "contains_any"},
		"ValidActionTypes":     {ValidActionTypes, "require_approval"},
	} {
		if len(pair.list) == 0 {
			t.Errorf("%s is empty - the applicability check would be meaningless", name)
			continue
		}
		var found bool
		for _, v := range pair.list {
			if v == pair.want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("%s no longer contains %q, which the US templates rely on - either the templates or this expectation must change", name, pair.want)
		}
	}
}
