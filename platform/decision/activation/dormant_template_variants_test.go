// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package activation

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

// THE LEDGER OF DORMANT TEMPLATE VARIANTS (#4131).
//
// A template redaction is split by discharge: redact on the scopes that can
// carry a redaction out, warn on the scopes that cannot. The template's four PII
// rows carry a v10 category only the proxy admits
// (sharedpolicy.LegacyTemplateCategories), and the proxy cannot discharge a
// redaction, so their redact halves are kept on no scope: they decide nowhere
// until #4230 decides whether the category is canonicalised. Each is listed in
// dormant_template_variants.tsv BY NAME, with the category no scope admits and
// the condition that revisits it. The binding-arm guard exempts only those ids,
// and the posture table names each one as dormant. A dormant variant the ledger
// does not list fails both, and a listed one that stops being dormant fails as
// stale.
//
// #4253 WIDENED IT TO SYSTEM-DOCUMENT VARIANTS. The four sys_admin_* rows carry
// security-admin, which since #4253 only proxy_request admits, where their
// :block variant binds. Their :log variant binds the planes that resolve log
// for them, none of which admits the category, so it is kept on no scope; the
// agent's policy_test tier pass, which #4253 retires, was the one scope that
// kept it. The same category and admitted-on-no-scope checks apply to them.
//
// Exported from a test file (the export_test idiom) so the external posture
// test reads the same rows through the same parser.

// DormantTemplateVariantsPath is the ledger, relative to this package.
const DormantTemplateVariantsPath = "dormant_template_variants.tsv"

// dormantLedgerHeader is the ledger's exact header row.
const dormantLedgerHeader = "policy_id\tcategory\trevisit"

// DormantTemplateVariant is one ledger row.
type DormantTemplateVariant struct {
	PolicyID, Category, Revisit string
}

// ParseDormantTemplateVariants parses the ledger, keyed by policy id. It
// refuses a missing header, a short or blank row and a duplicate id.
func ParseDormantTemplateVariants(raw []byte) (map[string]DormantTemplateVariant, error) {
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	if lines[0] != dormantLedgerHeader {
		return nil, fmt.Errorf("%s: the header is %q; want %q", DormantTemplateVariantsPath, lines[0], dormantLedgerHeader)
	}
	out := map[string]DormantTemplateVariant{}
	for i, line := range lines[1:] {
		cells := strings.Split(line, "\t")
		if len(cells) != 3 || cells[0] == "" || cells[1] == "" || cells[2] == "" {
			return nil, fmt.Errorf("%s line %d: %q is not three non-empty cells", DormantTemplateVariantsPath, i+2, line)
		}
		if _, twice := out[cells[0]]; twice {
			return nil, fmt.Errorf("%s line %d: %s is listed twice", DormantTemplateVariantsPath, i+2, cells[0])
		}
		out[cells[0]] = DormantTemplateVariant{PolicyID: cells[0], Category: cells[1], Revisit: cells[2]}
	}
	return out, nil
}

// ReadDormantTemplateVariants reads and parses the ledger.
func ReadDormantTemplateVariants(t *testing.T) map[string]DormantTemplateVariant {
	t.Helper()
	raw, err := os.ReadFile(DormantTemplateVariantsPath)
	if err != nil {
		t.Fatalf("reading %s: %v", DormantTemplateVariantsPath, err)
	}
	ledger, err := ParseDormantTemplateVariants(raw)
	if err != nil {
		t.Fatal(err)
	}
	return ledger
}

func TestTheDormantLedgerParserRefusesAMalformedLedger(t *testing.T) {
	for _, tc := range []struct{ name, raw, want string }{
		{"no header", "corpus:x:redact\tpii_detection\t#4230\n", "the header is"},
		{"a short row", dormantLedgerHeader + "\ncorpus:x:redact\tpii_detection\n", "not three non-empty cells"},
		{"a blank cell", dormantLedgerHeader + "\ncorpus:x:redact\t\t#4230\n", "not three non-empty cells"},
		{"a duplicate id", dormantLedgerHeader + "\ncorpus:x:redact\tpii_detection\t#4230\ncorpus:x:redact\tpii_detection\t#4230\n", "listed twice"},
	} {
		if _, err := ParseDormantTemplateVariants([]byte(tc.raw)); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: parsed with %v; want a refusal containing %q", tc.name, err, tc.want)
		}
	}
	// The control: the shipped ledger parses.
	if got := ReadDormantTemplateVariants(t); len(got) == 0 {
		t.Fatal("the shipped ledger lists no variant")
	}
}
