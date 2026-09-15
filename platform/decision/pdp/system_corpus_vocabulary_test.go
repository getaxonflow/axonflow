// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package pdp

import (
	"sort"
	"strings"
	"testing"

	"axonflow/platform/decision/contract"
)

// TestSystemCorpusObligationsSpeakTheCanonicalVocabulary asserts that every
// obligation the shipped corpus carries - system document and organization
// template - is spelled in the ONE vocabulary and validates under the ONE
// algebra's own validator (#3891). It also pins the PARAMETER KEYS the corpus
// uses to the documented set, so the day a policy is authored with a key the
// algebra neither composes nor documents, the drift is a red test rather than
// a silently carried string.
func TestSystemCorpusObligationsSpeakTheCanonicalVocabulary(t *testing.T) {
	system, err := SystemCorpusDocument()
	if err != nil {
		t.Fatalf("system corpus: %v", err)
	}
	org, err := SystemCorpusOrganizationTemplate()
	if err != nil {
		t.Fatalf("organization template: %v", err)
	}
	// The documented parameter keys, per family, as the API spec lists them
	// under AuthZENObligation.params. A key outside this set is either a new
	// key that needs documenting or a spelling that composes to nothing.
	documented := map[string]bool{
		// audit_notify
		"channel": true, "address": true, "delivery": true, "level": true,
		"category": true, "severity": true, "message": true, "kind": true, "observed": true,
		// approval
		"quorum": true, "eligible": true, "separation_of_duties": true, contract.ParamExpirySeconds: true,
		// routing (route properties are namespaced and handled below)
		contract.ParamAllowedDestinations: true,
		// step_up
		contract.ParamAssurance: true, contract.ParamMethods: true,
		// budget: the quantity is a REFERENCE the reservation service
		// resolves from the request, not a value the policy carries.
		contract.ParamCounter: true, contract.ParamWindow: true,
		contract.ParamUnit: true, contract.ParamLimit: true,
		contract.ParamAmountFrom: true,
	}
	types := map[contract.ObligationType]int{}
	keys := map[string]int{}
	total := 0
	for _, doc := range []*Document{system, org} {
		for _, p := range doc.Policies {
			for _, o := range p.Obligations {
				total++
				if err := o.Validate(); err != nil {
					t.Errorf("policy %s: obligation %s does not validate under the canonical validator: %v", p.ID, o.Type, err)
				}
				types[o.Type]++
				fam, err := contract.FamilyOf(o.Type)
				if err != nil {
					t.Errorf("policy %s: %v", p.ID, err)
					continue
				}
				for k := range o.Params {
					keys[k]++
					if fam == contract.FamilyDisclosure {
						// A disclosure transform's parameters are its own
						// (keep=last4); they are not composed and not enumerated.
						continue
					}
					if strings.HasPrefix(k, contract.RoutePropertyPrefix) {
						continue
					}
					if !documented[k] {
						t.Errorf("policy %s: obligation %s carries parameter %q, which docs/api/agent-api.yaml#AuthZENObligation.params does not document", p.ID, o.Type, k)
					}
				}
			}
		}
	}
	if total == 0 {
		t.Fatal("the shipped corpus carries no obligation at all; this test would compare nothing")
	}
	var typeNames []string
	for typ := range types {
		typeNames = append(typeNames, string(typ))
	}
	sort.Strings(typeNames)
	// The corpus's obligation types are exactly the three the legacy tables
	// produce, spelled canonically. Pinned as a literal so a fourth appearing
	// (or one disappearing) is noticed.
	if got := strings.Join(typeNames, ","); got != "field_redact,immutable_audit,notification" {
		t.Errorf("corpus obligation types = %q, want the three canonical spellings the legacy tables produce", got)
	}
}
