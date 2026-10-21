// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"axonflow/platform/agent/fincrime"
	sharedpolicy "axonflow/platform/shared/policy"
)

type fincrimeDecisionRecord struct {
	Version        int    `json:"version"`
	RegistryDigest string `json:"registry_digest"`
	Class          string `json:"action_class,omitempty"`
	Reason         string `json:"reason,omitempty"`
}

// applyFincrimeFacts replaces only this pack's detector facts. In particular,
// words in the statement or unrelated parameters cannot turn a false fact
// true. Every other category's observation is retained.
func applyFincrimeFacts(observation *sharedpolicy.Observation, result fincrime.Result) *sharedpolicy.Observation {
	if observation == nil {
		observation = &sharedpolicy.Observation{}
	}
	rows := make([]sharedpolicy.DetectorFact, 0, len(observation.Rows)+len(result.Facts))
	for _, row := range observation.Rows {
		if _, isFincrime := result.Facts[row.PolicyID]; !isFincrime {
			rows = append(rows, row)
		}
	}
	for _, id := range fincrime.DetectorIDs() {
		rows = append(rows, sharedpolicy.DetectorFact{PolicyID: id, Ran: true, Matched: result.Facts[id]})
	}
	return &sharedpolicy.Observation{Rows: rows, CapabilityScoped: observation.CapabilityScoped}
}
