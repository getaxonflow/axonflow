// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package authoring

import (
	"strings"
	"testing"

	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/pdp"
)

// TestALosingObligationSpellingCannotBeAuthored is the structural half of
// "no stored row carries the losing vocabulary" (#3891). The only write path
// into typed_policy_artifacts is NewDocument/Publish, and both run Validate,
// which refuses an obligation whose type the canonical vocabulary does not
// declare. So a document spelling an obligation `field_redaction`,
// `response_filtering` or `schema_constrained_transform` is refused before it
// is signed, and could never have been stored.
//
// The positive control is the same document with the canonical spelling,
// which is accepted - so the refusal is about the spelling and not about the
// document.
func TestALosingObligationSpellingCannotBeAuthored(t *testing.T) {
	for _, losing := range []contract.ObligationType{"field_redaction", "response_filtering", "schema_constrained_transform"} {
		t.Run(string(losing), func(t *testing.T) {
			doc := basePDPDocument(t)
			for i := range doc.Policies {
				if doc.Policies[i].ID == "insp.pii" {
					doc.Policies[i].Obligations = []contract.Obligation{{
						Type: losing, Target: "report.customer.email", Mandatory: false,
						SourcePolicy: "insp.pii", SchemaVersion: 1,
					}}
				}
			}
			_, findings, err := NewDocument(Document{Metadata: baseMetadata(t), Policy: doc}, baseCatalog(t))
			if err == nil {
				t.Fatalf("a document spelling an obligation %q was accepted for signing; findings=%v", losing, findings)
			}
			joined := strings.Join(findingsText(findings), " | ")
			if !strings.Contains(joined, string(losing)) {
				t.Fatalf("the refusal does not name the spelling it refused; findings=%v", findings)
			}
		})
	}

	// Positive control: the canonical spelling of the same instruction is
	// accepted, so the refusals above are about the vocabulary.
	doc := basePDPDocument(t)
	for i := range doc.Policies {
		if doc.Policies[i].ID == "insp.pii" {
			doc.Policies[i].Obligations = []contract.Obligation{{
				Type: contract.ObFieldRedact, Target: "report.customer.email", Mandatory: false,
				SourcePolicy: "insp.pii", SchemaVersion: 1,
			}}
		}
	}
	if _, findings, err := NewDocument(Document{Metadata: baseMetadata(t), Policy: doc}, baseCatalog(t)); err != nil {
		t.Fatalf("the canonical spelling was refused: %v (%v)", err, findings)
	}
	_ = pdp.RootSystem
}

func findingsText(f Findings) []string {
	out := make([]string, 0, len(f))
	for _, x := range f {
		out = append(out, x.Code+": "+x.Detail)
	}
	return out
}
