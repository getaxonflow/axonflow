// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package pdp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
)

// retainedPayloadLeaves is the parsed set of payload fields the shipped corpus's
// divergences retain, memoised as shippedCorpus is.
var retainedPayloadLeaves struct {
	once   sync.Once
	leaves []string
	err    error
}

// SystemCorpusRetainedPayloadLeaves returns, sorted and as a copy, every payload
// field a divergence in the shipped corpus records as retained: the fields a
// compiled redaction named before the corpus shipped it as something that masks
// nothing (#4254: a dynamic redaction bound only on scopes that cannot carry one
// out ships as a warn).
//
// THE DEPLOYMENT VOCABULARY KEEPS THEM AS PAYLOAD LEAVES. Its leaves are derived
// from the redaction targets the corpus carries, and an organization's typed
// document is refused a disclosure target that covers no declared leaf
// (authoring's DISCLOSURE_TARGET_NOT_A_LEAF). Shipping a platform control as a
// warn must not also narrow what an organization may redact, so its fields stay
// declared. Deriving the leaves from the payload schema instead of from what the
// shipped policies redact is a v11.1.0 row on #4249.
func SystemCorpusRetainedPayloadLeaves() ([]string, error) {
	retainedPayloadLeaves.once.Do(func() {
		retainedPayloadLeaves.leaves, retainedPayloadLeaves.err = parseRetainedPayloadLeaves(SystemCorpusSource)
	})
	if retainedPayloadLeaves.err != nil {
		return nil, retainedPayloadLeaves.err
	}
	return append([]string(nil), retainedPayloadLeaves.leaves...), nil
}

// parseRetainedPayloadLeaves reads the divergences' fields out of an artifact
// and nothing else: parseShippedCorpus owns the artifact's shape.
func parseRetainedPayloadLeaves(src []byte) ([]string, error) {
	var f struct {
		Divergences []struct {
			PolicyID string   `json:"policy_id"`
			Fields   []string `json:"fields"`
		} `json:"divergences"`
	}
	if err := json.NewDecoder(bytes.NewReader(src)).Decode(&f); err != nil {
		return nil, fmt.Errorf("pdp: the shipped system corpus's divergences could not be parsed: %w", err)
	}
	set := map[string]struct{}{}
	for _, d := range f.Divergences {
		for _, field := range d.Fields {
			if field == "" || strings.TrimSpace(field) != field {
				return nil, fmt.Errorf("pdp: the shipped system corpus's divergence for %q retains a blank or padded field %q", d.PolicyID, field)
			}
			set[field] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for field := range set {
		out = append(out, field)
	}
	sort.Strings(out)
	return out, nil
}
