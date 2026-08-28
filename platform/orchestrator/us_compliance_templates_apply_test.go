// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

// #3529 R3 round 1: the test whose absence let a BLOCKER through.
//
// THE DEFECT IT EXISTS FOR. A list-valued template variable written as
//
//	"value": ["{{authorized_roles}}"]
//
// does not substitute to a list. deepSubstitute walks INTO the array and calls
// substituteString on the single element; that element is a whole-string
// variable reference, so substituteString returns the variable's value with its
// TYPE PRESERVED (template_api_service.go:271-279) - an array. The result is an
// array nested inside an array. At evaluation toStringSlice stringifies each
// item with %v, so the one item becomes the single string
// "[query mutation admin]" and matchInList compares the field against that. It
// can never be equal.
//
// So `in` NEVER fires and `not_in` ALWAYS fires. Seven of the nine US templates
// and four pre-existing builtins carried this. Every other test in this change
// passed on all of them: the rows existed, the categories were canonical, the
// descriptions were present, the operators and fields were in the valid lists.
// Vocabulary membership cannot see a shape defect.
//
// WHAT THIS TEST DOES DIFFERENTLY. It runs the REAL substitution
// (TemplateService.substituteVariables, which is what ApplyTemplate calls) with
// each template's OWN declared defaults, then evaluates the substituted
// condition with the REAL shared evaluator, and asserts the condition
// discriminates: it must match a value the author intended to match and NOT
// match one they did not. A template whose condition cannot tell those apart is
// not a control.
//
// No database: the migration file and the two engines are all in-process.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	sharedpolicy "axonflow/platform/shared/policy"
)

// jsonbLiteral matches a single-quoted SQL literal cast to jsonb, which is how
// both the `template` and `variables` columns are written in every seed
// migration. Templates are selected from the matches by the presence of a
// "conditions" key, so `variables` arrays are skipped without a second, more
// fragile pattern. Shared with us_compliance_templates_applicable_test.go.
var jsonbLiteral = regexp.MustCompile(`(?s)'(\{.*?\})'::jsonb`)

// templateSeeds DISCOVERS every migration that seeds builtin policy_templates
// rows, rather than naming them.
//
// All of them, not just the US one: the defect above was in three families
// before this change, and a guard that only looked at the new file would have
// reported the codebase clean while four shipped templates stayed broken.
//
// Discovery rather than a hardcoded list, because a hardcoded list is the same
// drift this whole change is about. Two seed files (core/043 MAS FEAT,
// enterprise/128 OJK) declare no variables today and so cannot carry the
// defect - but a list written today would not have covered them tomorrow, and
// nothing would have said so.
func templateSeeds(t *testing.T) []string {
	t.Helper()
	var out []string
	for _, dir := range []string{"../../migrations/core", "../../migrations/enterprise", "../../migrations/industry"} {
		_ = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			if err != nil || info == nil || info.IsDir() {
				return nil //nolint:nilerr // an absent enterprise/ or industry/ dir is expected in the community tree
			}
			if !strings.HasSuffix(path, ".sql") || strings.HasSuffix(path, "_down.sql") {
				return nil
			}
			b, readErr := os.ReadFile(path)
			if readErr != nil {
				return nil //nolint:nilerr // unreadable file is covered by the count assertion below
			}
			if strings.Contains(string(b), "INSERT INTO policy_templates") {
				out = append(out, path)
			}
			return nil
		})
	}
	// Anti-vacuity: discovery that finds nothing would make every check below
	// pass having read no templates at all. core/024 always ships (it creates
	// the table), so at minimum it must be found.
	var foundCore24 bool
	for _, p := range out {
		if strings.Contains(p, "024_policy_templates.sql") {
			foundCore24 = true
		}
	}
	if !foundCore24 {
		t.Fatalf("template-seed discovery found %v - core/024 seeds templates and must be among them; the walk is broken and every check below would be vacuous", out)
	}
	return out
}

// TestNoBuiltinTemplateWrapsAListVariable is the direct, cheap regression pin.
// It is deliberately a pure text check on the shipped SQL: the shape is wrong
// wherever it appears, in any template, for any variable name.
func TestNoBuiltinTemplateWrapsAListVariable(t *testing.T) {
	var scanned int
	for _, path := range templateSeeds(t) {
		raw, err := os.ReadFile(path)
		if err != nil {
			if os.IsNotExist(err) {
				// enterprise/ seeds are absent from the community source tree.
				t.Logf("%s not present in this edition; skipping", path)
				continue
			}
			t.Fatalf("read %s: %v", path, err)
		}
		scanned++
		for _, line := range strings.Split(string(raw), "\n") {
			// Match the DEFINITION shape only: `"value": ["{{`. A bare `["{{`
			// also occurs legitimately in this file's own prose and in the
			// forward-fix WHERE clauses, which quote the defective shape in
			// order to FIND it - matching those was a false positive that
			// failed this guard on a correct tree. SQL comment lines are
			// skipped for the same reason.
			if strings.HasPrefix(strings.TrimSpace(line), "--") {
				continue
			}
			if strings.Contains(line, `"value": ["{{`) {
				t.Errorf(`%s contains a wrapped list variable: %s

A variable reference inside an array substitutes to a NESTED array, so an "in"
condition can never fire and a "not_in" condition always fires. Write it
unwrapped: "value": "{{var}}".`, path, strings.TrimSpace(line))
			}
		}
	}
	if scanned == 0 {
		t.Fatal("no template seed files were readable - this guard checked nothing")
	}
}

// TestBuiltinTemplateConditionsDiscriminate is the behavioural proof: substitute
// with the template's own defaults, then evaluate.
func TestBuiltinTemplateConditionsDiscriminate(t *testing.T) {
	svc := &TemplateService{}
	var checked int

	for _, path := range templateSeeds(t) {
		raw, err := os.ReadFile(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			t.Fatalf("read %s: %v", path, err)
		}

		for _, tpl := range parseSeededTemplates(t, string(raw)) {
			substituted, err := svc.substituteVariables(tpl.body, tpl.variables, nil)
			if err != nil {
				t.Errorf("%s: substituteVariables failed: %v", tpl.name, err)
				continue
			}

			conds, _ := substituted["conditions"].([]interface{})
			if len(conds) == 0 {
				t.Errorf("%s: no conditions after substitution", tpl.name)
				continue
			}

			for i, c := range conds {
				cm, _ := c.(map[string]interface{})
				op, _ := cm["operator"].(string)
				val := cm["value"]

				// The shape assertion. Only list operators are affected; for
				// them the substituted value must be a FLAT list of scalars.
				if op != "in" && op != "not_in" && op != "contains_any" {
					continue
				}
				checked++
				items, ok := val.([]interface{})
				if !ok {
					t.Errorf("%s condition %d: operator %q needs a list value, got %T", tpl.name, i, op, val)
					continue
				}
				if len(items) == 0 {
					t.Errorf("%s condition %d: operator %q got an empty list, which can never match", tpl.name, i, op)
					continue
				}
				for j, item := range items {
					switch item.(type) {
					case []interface{}, map[string]interface{}:
						t.Errorf(`%s condition %d item %d: substituted to a NESTED %T.

This is the wrapped-variable defect: the evaluator stringifies the nested value
with %%v into a single string, so %q can never match a real field value (and
"not_in" then matches everything). Write the value as "{{var}}", unwrapped.`,
							tpl.name, i, j, item, op)
					}
				}

				// Behavioural check: the condition must DISCRIMINATE. Take the
				// first item as a value the author meant to match, and a string
				// that is certainly not in the list as one they did not.
				first, isStr := items[0].(string)
				if !isStr || strings.Contains(first, "{{") {
					continue // unresolved or non-string; the shape checks above own it
				}
				const absent = "zzz_value_no_template_lists_zzz"
				evalWith := func(fieldValue string) bool {
					return sharedpolicy.ConditionEvaluator{}.Match(
						sharedpolicy.MatchCondition{Field: "f", Operator: op, Value: val},
						func(string) (any, bool) { return fieldValue, true },
						nil,
					)
				}
				hit, miss := evalWith(first), evalWith(absent)
				if hit == miss {
					t.Errorf("%s condition %d (operator %q) does not discriminate: a listed value (%q) and an unlisted one both evaluate to %v, so the condition is equivalent to a constant", tpl.name, i, op, first, hit)
				}
			}
		}
	}

	// Anti-vacuity: every assertion lives inside the loops, so a parser that
	// matched nothing would leave this test green having proven nothing.
	if checked == 0 {
		t.Fatal("no list-operator conditions were evaluated - the parser matched nothing and this test proved nothing")
	}
	t.Logf("evaluated %d list-operator conditions across the builtin template seeds", checked)
}

type seededTemplate struct {
	name      string
	body      map[string]interface{}
	variables []TemplateVariable
}

// parseSeededTemplates pulls (template, variables) pairs out of a seed
// migration. The two jsonb literals are adjacent in every INSERT: the object
// carrying "conditions" is the template, and the array immediately after it is
// that template's variables.
func parseSeededTemplates(t *testing.T, sql string) []seededTemplate {
	t.Helper()
	var out []seededTemplate

	for _, m := range jsonbLiteral.FindAllStringSubmatchIndex(sql, -1) {
		body := sql[m[2]:m[3]]
		if !strings.Contains(body, `"conditions"`) {
			continue
		}
		var tpl map[string]interface{}
		if err := json.Unmarshal([]byte(body), &tpl); err != nil {
			continue
		}
		name, _ := tpl["name"].(string)
		if name == "" {
			name = "(unnamed template)"
		}

		// The variables array is the next '[...]'::jsonb after this literal.
		vars := parseNextVariables(sql[m[1]:])
		out = append(out, seededTemplate{name: name, body: tpl, variables: vars})
	}
	return out
}

func parseNextVariables(rest string) []TemplateVariable {
	idx := strings.Index(rest, "'::jsonb")
	if idx < 0 {
		return nil
	}
	start := strings.Index(rest, "'[")
	if start < 0 || start > idx {
		return nil
	}
	end := strings.Index(rest[start:], "]'::jsonb")
	if end < 0 {
		return nil
	}
	var vars []TemplateVariable
	if err := json.Unmarshal([]byte(rest[start+1:start+end+1]), &vars); err != nil {
		return nil
	}
	return vars
}
