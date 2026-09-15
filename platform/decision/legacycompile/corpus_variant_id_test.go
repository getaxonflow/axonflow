// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package legacycompile

import (
	"strings"
	"testing"
)

// TestACorpusVariantIdentifierReadsBackToItsControl holds CorpusControlOf to
// CorpusVariantIDFor in both shapes a corpus identifier takes - a control the
// corpus did not split, and one per-scope variant of a split control - with and
// without a "#n" multi-policy suffix, and refuses every string that is not one.
func TestACorpusVariantIdentifierReadsBackToItsControl(t *testing.T) {
	control := CorpusPolicyIDFor("static_policies", "sys_pii_email")
	for _, c := range []struct {
		id              string
		control, action string
		ok              bool
	}{
		{control, control, "", true},
		{control + "#2", control, "", true},
		{CorpusVariantIDFor("static_policies", "sys_pii_email", "log"), control, "log", true},
		{CorpusVariantIDFor("static_policies", "sys_pii_email", "redact") + "#3", control, "redact", true},
		{"static_policies:sys__pii__email", "", "", false},
		{"corpus:static_policies", "", "", false},
		{"corpus::sys__pii__email", "", "", false},
		{control + ":", "", "", false},
		{control + ":log:extra", "", "", false},
	} {
		gotControl, gotAction, ok := CorpusControlOf(c.id)
		if ok != c.ok || gotControl != c.control || gotAction != c.action {
			t.Errorf("CorpusControlOf(%q) = (%q, %q, %v); want (%q, %q, %v)", c.id, gotControl, gotAction, ok, c.control, c.action, c.ok)
		}
	}

	// THE SEPARATOR CANNOT OCCUR INSIDE AN ENCODED ROW IDENTIFIER, which is what
	// makes a third segment unambiguously a variant action. A policy_id carrying
	// a colon is encoded, and the encoding reads back to it.
	raw := "vendor:row"
	encoded := SanitizePolicyID(raw)
	if strings.Contains(encoded, ":") {
		t.Fatalf("SanitizePolicyID(%q) = %q still carries the separator, so a variant action could be read out of a row identifier", raw, encoded)
	}
	if back, ok := UnsanitizePolicyID(encoded); !ok || back != raw {
		t.Fatalf("UnsanitizePolicyID(%q) = (%q, %v); want (%q, true)", encoded, back, ok, raw)
	}
	id := CorpusVariantIDFor("static_policies", raw, "warn")
	if gotControl, gotAction, ok := CorpusControlOf(id); !ok || gotControl != CorpusPolicyIDFor("static_policies", raw) || gotAction != "warn" {
		t.Fatalf("a variant of a colon-carrying row read back as (%q, %q, %v)", gotControl, gotAction, ok)
	}
}
