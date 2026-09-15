// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package policy

import "testing"

// TestParameterScanTextIsWhatTheRequestPassScans pins the text the request
// pass scans for each parameter shape, which the MCP request pass redacts to
// tell whether a composed redaction would mask a parameter (#4264). Both read
// this one function; a shape it changes changes both together.
func TestParameterScanTextIsWhatTheRequestPassScans(t *testing.T) {
	for _, c := range []struct {
		name    string
		in      interface{}
		want    string
		scanned bool
	}{
		{"a string, as it is", "4111 1111 1111 1111", "4111 1111 1111 1111", true},
		{"an empty string is not scanned", "", "", false},
		{"a JSON number, in decimal so a card number's digits survive", float64(4111111111111111), "4111111111111111", true},
		{"an int64", int64(123456789), "123456789", true},
		{"a boolean is not scanned", true, "", false},
		{"an object, JSON-encoded", map[string]interface{}{"to": "a@b.c"}, `{"to":"a@b.c"}`, true},
		{"an array, JSON-encoded", []interface{}{"-s", "x"}, `["-s","x"]`, true},
		{"anything else, formatted", 7, "7", true},
	} {
		t.Run(c.name, func(t *testing.T) {
			got, scanned := ParameterScanText(c.in)
			if got != c.want || scanned != c.scanned {
				t.Fatalf("ParameterScanText(%#v) = %q, %v; want %q, %v", c.in, got, scanned, c.want, c.scanned)
			}
		})
	}
}
