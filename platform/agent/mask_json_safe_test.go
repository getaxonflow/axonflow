package agent

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"
)

// stubMasker masks any 12+ digit run (stands in for the EE NIK/phone detector)
// so maskJSONSafe can be tested without the Enterprise detector wired in.
func stubMasker(s string) (string, bool) {
	re := regexp.MustCompile(`\b\d{12,}\b`)
	if !re.MatchString(s) {
		return s, false
	}
	return re.ReplaceAllStringFunc(s, func(m string) string {
		if len(m) <= 4 {
			return strings.Repeat("*", len(m))
		}
		return m[:1] + strings.Repeat("*", len(m)-2) + m[len(m)-1:]
	}), true
}

// crossLeafMasker matches "NNNNNN,NNNNNN" — only across a JSON array comma — so the
// per-leaf walk never sees it; used to prove the fail-closed fallback.
func crossLeafMasker(s string) (string, bool) {
	re := regexp.MustCompile(`\d{6},\d{6}`)
	if !re.MatchString(s) {
		return s, false
	}
	return re.ReplaceAllString(s, "******,******"), true
}

// Fail-closed invariant (R3): when the per-leaf walk masks nothing but the
// whole-string masker WOULD mask (cross-leaf match), maskJSONSafe must fall back to
// the flat masker — never return the original unmasked (fail-open leak).
func TestMaskJSONSafe_CrossLeafFailsClosed(t *testing.T) {
	in := `{"vals":[123456,789012]}`
	out, changed := maskJSONSafe(in, crossLeafMasker)
	if !changed {
		t.Fatalf("FAIL-OPEN: cross-leaf match not redacted (returned unmasked): %s", out)
	}
	if out == in || strings.Contains(out, "123456,789012") {
		t.Errorf("cross-leaf secret survived: %s", out)
	}
}

// comboMasker masks a 16+ digit run (per-leaf) AND a cross-leaf 6-digit pair.
func comboMasker(s string) (string, bool) {
	long := regexp.MustCompile(`\b\d{16,}\b`)
	pair := regexp.MustCompile(`\d{6},\d{6}`)
	if !long.MatchString(s) && !pair.MatchString(s) {
		return s, false
	}
	o := long.ReplaceAllStringFunc(s, func(m string) string { return m[:1] + strings.Repeat("*", len(m)-2) + m[len(m)-1:] })
	o = pair.ReplaceAllString(o, "******,******")
	return o, true
}

// Symmetric fail-closed (R3 round 2): masking a per-leaf NIK must not let a cross-leaf
// pair leak through the JSON-aware path.
func TestMaskJSONSafe_CrossLeafWithOtherLeafFailsClosed(t *testing.T) {
	in := `{"nik":3174012509900001,"vals":[123456,789012]}`
	out, changed := maskJSONSafe(in, comboMasker)
	if !changed {
		t.Fatalf("expected redaction, got none: %s", out)
	}
	if strings.Contains(out, "123456,789012") {
		t.Errorf("FAIL-OPEN: cross-leaf pair leaked while NIK leaf was masked: %s", out)
	}
}

// HTML chars must not be gratuitously escaped on the repair path (R3 low).
func TestMaskJSONSafe_NoHTMLEscape(t *testing.T) {
	in := `{"nik":3174012509900001,"note":"a<b>&c"}`
	out, _ := maskJSONSafe(in, stubMasker)
	if !json.Valid([]byte(out)) {
		t.Fatalf("not valid JSON: %s", out)
	}
	if strings.Contains(out, "\\u003c") || strings.Contains(out, "\\u0026") {
		t.Errorf("HTML gratuitously \\u-escaped: %s", out)
	}
	if !strings.Contains(out, "a<b>&c") { // literal angle/amp preserved (not escaped)
		t.Errorf("HTML string was altered: %s", out)
	}
}

func TestMaskJSONSafe(t *testing.T) {
	cases := []struct {
		name        string
		in          string
		wantChanged bool
		// validators applied to the output
		mustBeValidJSON bool
		mustNotContain  string
		exact           string // when set, output must equal this (byte-identical paths)
	}{
		{
			name:        "bare number NIK coerces to string, stays valid JSON",
			in:          `{"customer":"Budi","nik":3174012509900001}`,
			wantChanged: true, mustBeValidJSON: true, mustNotContain: "3174012509900001",
		},
		{
			name:        "bare number in array",
			in:          `{"ids":[3174012509900001,12345]}`,
			wantChanged: true, mustBeValidJSON: true, mustNotContain: "3174012509900001",
		},
		{
			name:        "string-position value masked in place",
			in:          `{"note":"id is 3174012509900001 ok"}`,
			wantChanged: true, mustBeValidJSON: true, mustNotContain: "3174012509900001",
		},
		{
			name:        "non-JSON falls back to flat masking (byte-identical)",
			in:          "ticket 3174012509900001 escalated",
			wantChanged: true, exact: "ticket 3**************1 escalated",
		},
		{
			name:        "no match → unchanged",
			in:          `{"a":1,"b":"hello"}`,
			wantChanged: false, exact: `{"a":1,"b":"hello"}`,
		},
		{
			name:        "trailing garbage is treated as non-JSON (flat)",
			in:          `{"a":3174012509900001} extra`,
			wantChanged: true, mustNotContain: "3174012509900001",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out, changed := maskJSONSafe(c.in, stubMasker)
			if changed != c.wantChanged {
				t.Fatalf("changed=%v want %v (out=%q)", changed, c.wantChanged, out)
			}
			if c.exact != "" && out != c.exact {
				t.Errorf("out=%q want exact %q", out, c.exact)
			}
			if c.mustBeValidJSON && !json.Valid([]byte(out)) {
				t.Errorf("output is not valid JSON: %s", out)
			}
			if c.mustNotContain != "" && strings.Contains(out, c.mustNotContain) {
				t.Errorf("output still contains %q: %s", c.mustNotContain, out)
			}
		})
	}
}
