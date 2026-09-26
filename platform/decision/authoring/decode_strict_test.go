// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package authoring

import (
	"strings"
	"testing"
)

// TestDecodeStrictRefusesWhatWouldDecodeAsSomethingElse (#4371): the transports'
// one parser refuses a null binds_on (which decodes as absent, every plane), an
// unknown member at any depth (a misspelled bind_on would decode as absent
// too), and a second value; a list, an empty list and an absent binds_on pass
// through to the validator.
func TestDecodeStrictRefusesWhatWouldDecodeAsSomethingElse(t *testing.T) {
	type policy struct {
		ID      string    `json:"id"`
		BindsOn *[]string `json:"binds_on,omitempty"`
	}
	type body struct {
		Document struct {
			Policies []policy `json:"policies"`
		} `json:"document"`
	}
	for _, tc := range []struct {
		raw, refused string
	}{
		{`{"document":{"policies":[{"id":"a","binds_on":["wcp"]}]}}`, ""},
		{`{"document":{"policies":[{"id":"a","binds_on":[]}]}}`, ""},
		{`{"document":{"policies":[{"id":"a"}]}}`, ""},
		{`{"document":{"policies":[{"id":"a"},{"id":"b","binds_on":null}]}}`, "$.document.policies[1].binds_on is null"},
		{`{"document":{"policies":[{"id":"a","bind_on":["wcp"]}]}}`, `unknown field "bind_on"`},
		{`{"document":{"policies":[]}} {}`, "more than one JSON value"},
	} {
		var got body
		err := DecodeStrict([]byte(tc.raw), &got)
		switch {
		case tc.refused == "" && err != nil:
			t.Errorf("%s: refused: %v", tc.raw, err)
		case tc.refused != "" && (err == nil || !strings.Contains(err.Error(), tc.refused)):
			t.Errorf("%s: %v, want a refusal naming %q", tc.raw, err, tc.refused)
		}
	}
}

// TestTheSchemaStatesTheBindsOnListRules pins the published contract: the raw
// schema check that authoring.Parse runs refuses an empty binds_on
// (minItems) and a repeated plane (uniqueItems), the rules BINDS_ON_EMPTY and
// BINDS_ON_DUPLICATE_PLANE enforce at publication. A list of distinct planes
// passes it.
func TestTheSchemaStatesTheBindsOnListRules(t *testing.T) {
	raw, err := Render(baseDocument(t))
	if err != nil {
		t.Fatal(err)
	}
	const anchor = `"id":"perm.refund",`
	if !strings.Contains(string(raw), anchor) {
		t.Fatalf("PREMISE: the rendered baseline has no %s", anchor)
	}
	for list, refused := range map[string]string{
		`["wcp","decide"]`: "",
		`[]`:               "minItems",
		`["wcp","wcp"]`:    "items at 0 and 1 are equal",
	} {
		scoped := strings.Replace(string(raw), anchor, anchor+`"binds_on":`+list+`,`, 1)
		err := ValidateRawAgainstSchema([]byte(scoped))
		switch {
		case refused == "" && err != nil:
			t.Errorf("binds_on %s: %v", list, err)
		case refused != "" && (err == nil || !strings.Contains(err.Error(), "/policy/policies/0/binds_on") || !strings.Contains(err.Error(), refused)):
			t.Errorf("binds_on %s: %v, want a schema refusal at /policy/policies/0/binds_on saying %q", list, err, refused)
		}
	}
}
