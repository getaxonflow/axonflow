// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package contenttext

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func decode(t *testing.T, raw string) any {
	t.Helper()
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		t.Fatal(err)
	}
	return v
}

// A newline inside a JSON string is a newline in the projection, never a
// backslash and an n: the pattern the receiver sees is the one the detector
// sees.
func TestAnEscapedNewlineIsPresentedRaw(t *testing.T) {
	got, err := Projection(decode(t, `{"where":"tenant_id\n!= 42"}`))
	if err != nil {
		t.Fatal(err)
	}
	if want := "where\ntenant_id\n!= 42"; got != want {
		t.Fatalf("projection = %q, want %q", got, want)
	}
	if strings.Contains(got, `\n`) {
		t.Fatalf("projection %q carries the JSON escape", got)
	}
}

// Keys and string leaves in sorted-path order, one per line; numbers and
// booleans as their JSON text; null and "" as nothing.
func TestTheProjectionIsKeysAndLeavesInSortedOrder(t *testing.T) {
	got, err := Projection(decode(t, `{"b":[1,true,null,""],"a":{"y":"v","x":2.50}}`))
	if err != nil {
		t.Fatal(err)
	}
	if want := strings.Join([]string{"a", "x", "2.50", "y", "v", "b", "1", "true"}, "\n"); got != want {
		t.Fatalf("projection = %q, want %q", got, want)
	}
}

func TestInvalidUTF8IsRefusedNotReplaced(t *testing.T) {
	if _, err := Projection(map[string]interface{}{"k": "a\xffb"}); !errors.Is(err, ErrNotUTF8) {
		t.Fatalf("invalid UTF-8 answered %v, want ErrNotUTF8", err)
	}
}

// A typed value a caller built in process is read as the JSON value it
// encodes to, and invalid UTF-8 inside one is refused as well.
func TestATypedValueIsProjectedAsTheJSONItEncodesTo(t *testing.T) {
	got, err := Projection(struct {
		B int    `json:"b"`
		A string `json:"a"`
	}{1, "x"})
	if err != nil || got != "a\nx\nb\n1" {
		t.Fatalf("projection = %q, %v; want %q", got, err, "a\nx\nb\n1")
	}
	if _, err := Projection(struct{ A string }{"a\xffb"}); !errors.Is(err, ErrNotUTF8) {
		t.Fatalf("a typed value with invalid UTF-8 answered %v, want ErrNotUTF8", err)
	}
}

// THE STEP PLANES' CORPUS (#4360), run through this package: the orchestrator
// now reads it (step_content_projection.go), so these are the cells that
// proved the step planes' content, held here where the rule lives.
func TestTheStepPlanesCorpus(t *testing.T) {
	for _, tc := range []struct {
		name  string
		parts []any
		want  string
	}{
		{"key order does not move it; every character as sent",
			[]any{map[string]interface{}{"b": 1, "a": "e\u0301\n\t\"q\" C:\\x"}}, "a\ne\u0301\n\t\"q\" C:\\x\nb\n1"},
		{"a tool step's tool input follows its step input",
			[]any{map[string]interface{}{"s": "x"}, map[string]interface{}{"k": []interface{}{"v", true}}}, "s\nx\nk\nv\ntrue"},
		{"a newline inside a value is a newline",
			[]any{map[string]interface{}{"filter": "tenant_id\n!= 42"}}, "filter\ntenant_id\n!= 42"},
		{"a tab inside a value is a tab",
			[]any{map[string]interface{}{"filter": "tenant_id\t!= 42"}}, "filter\ntenant_id\t!= 42"},
		{"a key and its value are adjacent, so a pattern crosses them",
			[]any{map[string]interface{}{"tenant_id": "!= 42"}}, "tenant_id\n!= 42"},
		{"a quote and a backslash as written",
			[]any{map[string]interface{}{"note": `please say "hi" at C:\temp now`}}, "note\n" + `please say "hi" at C:\temp now`},
		{"no input presents nothing", []any{nil, map[string]interface{}{}}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Projection(tc.parts...)
			if err != nil || got != tc.want {
				t.Fatalf("projection = %q, %v; want %q", got, err, tc.want)
			}
		})
	}
	if _, err := Projection(map[string]interface{}{"prompt": "debug \xff"}); !errors.Is(err, ErrNotUTF8) {
		t.Fatalf("step input that is not valid UTF-8 answered %v, want ErrNotUTF8", err)
	}
}
