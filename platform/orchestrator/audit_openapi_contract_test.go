// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
//
// Guards the PUBLISHED OpenAPI contract against the Go structs that actually
// serve it.
//
// Why this exists (#3438 R4): #3426 widened the top-policies aggregation and
// added identity_is_name / total_policies / top_policies_unavailable to the
// response structs, and docs/api/orchestrator-api.yaml kept describing the
// pre-#3426 shape at all four of its top_policies sites. That is not a cosmetic
// drift. An integrator reading the spec had no way to learn that policy_name
// may carry a raw IDENTIFIER rather than a display name, so they would style an
// id as a name (the #3347 defect, one hop out), and no way to learn that a
// failed aggregation is signalled at all, so they would render it as "no
// policies fired" (the fail-quiet #3426 removed, one hop out).
//
// Nothing in CI could catch it: validate-openapi.yml runs swagger-cli, spectral
// and redocly SYNTAX lint only, with no binding to these structs, and no schema
// sets additionalProperties: false, so an omission is additive rather than a
// validation break. This test is that binding.
//
// Deliberately NARROW. It pins the PolicyHitSummary property set exactly at
// both documented sites, and the presence of the policy-related container
// fields. It does NOT demand the containers be fully documented: the summary
// schema has a pre-existing, unrelated gap (total_requests and the other
// per-verdict counters are emitted and undocumented) which is outside this PR,
// and a guard that failed on it would be turned off rather than fixed.
package orchestrator

import (
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// specPath is resolved relative to this package, so the test fails loudly if
// the layout moves rather than silently skipping.
const specPath = "../../docs/api/orchestrator-api.yaml"

// jsonFieldNames returns the wire names encoding/json emits for a struct type,
// which is the thing the spec has to match. Embedded/skipped fields are
// ignored the same way the encoder ignores them.
func jsonFieldNames(t *testing.T, typ reflect.Type) []string {
	t.Helper()
	var names []string
	for i := 0; i < typ.NumField(); i++ {
		f := typ.Field(i)
		if f.PkgPath != "" { // unexported
			continue
		}
		tag := f.Tag.Get("json")
		if tag == "-" {
			continue
		}
		name := strings.Split(tag, ",")[0]
		if name == "" {
			name = f.Name
		}
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// walk descends a parsed YAML tree by key, failing with the path it got to
// rather than panicking on a nil map, so a spec restructure names the site.
func walk(t *testing.T, doc interface{}, path ...string) map[string]interface{} {
	t.Helper()
	cur := doc
	for i, key := range path {
		m, ok := cur.(map[string]interface{})
		if !ok {
			t.Fatalf("spec path %v: element %d (%q) is not a mapping (got %T)",
				path, i, key, cur)
		}
		next, ok := m[key]
		if !ok {
			t.Fatalf("spec path %v: key %q missing at element %d. If the spec was "+
				"restructured, update this guard; do not delete it.", path, key, i)
		}
		cur = next
	}
	m, ok := cur.(map[string]interface{})
	if !ok {
		t.Fatalf("spec path %v: leaf is not a mapping (got %T)", path, cur)
	}
	return m
}

func loadSpec(t *testing.T) map[string]interface{} {
	t.Helper()
	abs, err := filepath.Abs(specPath)
	if err != nil {
		t.Fatalf("resolving spec path: %v", err)
	}
	raw, err := os.ReadFile(abs)
	if err != nil {
		// FAIL, never skip: a guard that skips when its input is missing is a
		// guard that fails open exactly when the layout changed under it.
		t.Fatalf("reading published OpenAPI spec at %s: %v", abs, err)
	}
	var doc map[string]interface{}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parsing %s: %v", abs, err)
	}
	if len(doc) == 0 {
		t.Fatalf("%s parsed to an empty document", abs)
	}
	return doc
}

// TestPolicyHitSummaryMatchesOpenAPISpec pins the emitted PolicyHitSummary
// shape against every place the spec documents it.
func TestPolicyHitSummaryMatchesOpenAPISpec(t *testing.T) {
	doc := loadSpec(t)

	want := jsonFieldNames(t, reflect.TypeOf(PolicyHitSummary{}))
	// Anti-vacuity: if reflection returned nothing, every comparison below
	// would pass against an empty spec section and prove nothing.
	if len(want) < 4 {
		t.Fatalf("PolicyHitSummary reflected only %d json fields (%v); the guard "+
			"would be vacuous", len(want), want)
	}

	sites := map[string][]string{
		"compliance summary (inline schema)": {
			"paths", "/api/v1/audit/summary", "post", "responses", "200",
			"content", "application/json", "schema", "properties",
			"top_policies", "items", "properties",
		},
		"AuditActionReport (component schema)": {
			"components", "schemas", "AuditActionReport", "properties",
			"top_policies", "items", "properties",
		},
	}

	for label, path := range sites {
		props := walk(t, doc, path...)
		var got []string
		for k := range props {
			got = append(got, k)
		}
		sort.Strings(got)

		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s: documented top_policies item properties diverge from "+
				"PolicyHitSummary.\n  spec:   %v\n  struct: %v\n"+
				"Every field the API emits must be documented: an integrator who "+
				"cannot see identity_is_name will render a policy IDENTIFIER "+
				"styled as a display name, which is the #3347 defect.", label, got, want)
		}

		// The two fields whose ABSENCE from the spec caused the #3438 R4
		// blocker carry the semantics, not just the name. A bare type with no
		// description would satisfy a set comparison and still leave the
		// integrator unable to act on the value.
		for _, k := range []string{"policy_name", "identity_is_name"} {
			prop, ok := props[k].(map[string]interface{})
			if !ok {
				continue // the set comparison above already reported it
			}
			desc, _ := prop["description"].(string)
			if len(strings.TrimSpace(desc)) < 80 {
				t.Errorf("%s: %q needs a description explaining that the value may "+
					"be an identifier rather than a display name (got %d chars)",
					label, k, len(strings.TrimSpace(desc)))
			}
		}
	}
}

// TestPolicyAggregateContainerFieldsDocumented pins the container-level fields
// #3426 added, including the ASYMMETRY between the two surfaces: the summary
// degrades with a flag, the regulator-facing report 500s instead and therefore
// must NOT advertise a flag it never emits.
func TestPolicyAggregateContainerFieldsDocumented(t *testing.T) {
	doc := loadSpec(t)

	summaryProps := walk(t, doc,
		"paths", "/api/v1/audit/summary", "post", "responses", "200",
		"content", "application/json", "schema", "properties")
	reportProps := walk(t, doc,
		"components", "schemas", "AuditActionReport", "properties")

	summaryFields := jsonFieldNames(t, reflect.TypeOf(ComplianceSummary{}))
	reportFields := jsonFieldNames(t, reflect.TypeOf(ActionReport{}))

	has := func(list []string, name string) bool {
		for _, s := range list {
			if s == name {
				return true
			}
		}
		return false
	}

	// Anti-vacuity: assert the premises this test's expectations rest on, so a
	// rename of the struct field cannot quietly turn the checks below into
	// no-ops.
	if !has(summaryFields, "total_policies") || !has(summaryFields, "top_policies_unavailable") {
		t.Fatalf("ComplianceSummary no longer emits total_policies + "+
			"top_policies_unavailable (%v); update this guard", summaryFields)
	}
	if !has(reportFields, "total_policies") {
		t.Fatalf("ActionReport no longer emits total_policies (%v); update this guard", reportFields)
	}

	for _, f := range []string{"total_policies", "top_policies_unavailable"} {
		if _, ok := summaryProps[f]; !ok {
			t.Errorf("compliance summary schema does not document %q, which the "+
				"handler emits. Without it a client cannot tell a failed "+
				"aggregation from \"no policies fired\".", f)
		}
	}
	if _, ok := reportProps["total_policies"]; !ok {
		t.Errorf("AuditActionReport does not document \"total_policies\", so a " +
			"truncated regulator-facing table reads as the complete set")
	}

	// The report genuinely has no top_policies_unavailable (it hard-fails), so
	// documenting one would be the mirror-image defect: a client branching on a
	// field that never arrives would treat every response as healthy.
	if has(reportFields, "top_policies_unavailable") {
		t.Fatalf("ActionReport gained top_policies_unavailable; the spec and this " +
			"guard both assume it hard-fails instead")
	}
	if _, ok := reportProps["top_policies_unavailable"]; ok {
		t.Errorf("AuditActionReport documents \"top_policies_unavailable\", which " +
			"this endpoint never emits: a failed aggregation fails the whole " +
			"response with a 500")
	}
}
