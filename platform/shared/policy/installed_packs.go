// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package policy

import (
	"database/sql"
	"fmt"
	"time"

	"axonflow/platform/decision/policypack"
)

// INSTALLED POLICY PACK DETECTORS (PRD v11 §1.9, #4126)
//
// A policy pack's controls are typed policies that read their detectors'
// verdicts (signal.detector.<id>), and this layer is what produces a
// detector's verdict. A pack's detectors are therefore loaded here - beside the
// static_policies rows, on every load, in the global scope - so each evaluation
// that loads the pack's phase reports whether each detector ran and matched
// (detector_facts.go), and the anchored engine decides the pack's controls from
// that.
//
// THEY ARE NEVER ROWS. They are compiled once, from the pack the deployment
// installed, and appended to what loadFromDatabase returns; nothing writes them
// to static_policies (PRD §1.2: a seeded row authors no verdict, and a row the
// organization could see, edit or disable would be a second, unaudited
// authoring surface for a deployment-authored control).
//
// They do not count toward the system-tier floor (ErrEmptySystemPolicySet): that
// floor proves the migrated rows are reachable, and a pack's detectors are not a
// migrated row.

// InstalledPackTier is the tier an installed pack's detectors carry, so a
// reader of an evaluation can tell them from a migrated row.
const InstalledPackTier = "pack"

// CompileInstalledDetectors compiles the detectors of each installed pack as the
// loader compiles a static_policies row, through the same compilePolicy and the
// same RE2 engine. Its validator is the one its source names (packDetectorValidator). A
// pattern that does not compile is an error here, where the database load logs
// and skips it: a skipped pack detector would ship a control whose signal is
// never produced.
func CompileInstalledDetectors(packs []*policypack.Pack) ([]CompiledPolicy, error) {
	var out []CompiledPolicy
	compiler := &PolicyLoader{}
	for _, p := range packs {
		for _, d := range p.Source.Detectors {
			row := policyRow{
				ID:          policypack.PolicyID(p.Source.ID, d.ID),
				PolicyID:    d.ID,
				Name:        d.Name,
				Category:    d.Category,
				Tier:        InstalledPackTier,
				Pattern:     d.Pattern,
				Severity:    d.Severity,
				Description: sql.NullString{String: d.Description, Valid: d.Description != ""},
				Phase:       sql.NullString{String: d.Phase, Valid: true},
				Enabled:     true,
				Priority:    d.Priority,
				TenantID:    globalTenantSentinel,
				CreatedAt:   time.Time{},
			}
			// The actions are the detector's legacy action on each phase it
			// scans (Detector.ActionFor), a per-phase override included. The
			// anchored engine decides the pack's controls from the document, not
			// from these; they are carried so that a reader still on the legacy
			// path sees the pack's own intent on each phase rather than a default.
			request := sql.NullString{String: d.ActionFor("request"), Valid: true}
			response := sql.NullString{String: d.ActionFor("response"), Valid: true}
			switch Phase(d.Phase) {
			case PhaseRequest:
				row.ActionRequest = request
			case PhaseResponse:
				row.ActionResponse = response
			default:
				row.ActionRequest, row.ActionResponse = request, response
			}
			compiled, err := compiler.compilePolicy(row)
			if err != nil {
				return nil, fmt.Errorf("policy: pack %q detector %q: %w", p.Source.ID, d.ID, err)
			}
			if compiled.Validator, err = packDetectorValidator(d); err != nil {
				return nil, fmt.Errorf("policy: pack %q detector %q: %w", p.Source.ID, d.ID, err)
			}
			out = append(out, *compiled)
		}
	}
	return out, nil
}

// packDetectorValidator is the validator gating a pack detector: the one its
// source names, or none. It is never resolved as a row's is (ValidatorFor). A
// pack detector's category says which call sites admit it and its id is a
// name; neither says what shape its pattern matches. Resolved as a row, every
// pii-india detector was gated by the Aadhaar checksum and one whose id carries
// "bank_account" by a US routing checksum, so a UPI id, a mobile number or an
// Indian account number never matched (#4141).
func packDetectorValidator(d policypack.Detector) (ValidatorFunc, error) {
	if d.Validator == "" {
		return matchesAsWritten, nil
	}
	if v := GetValidatorByType(d.Validator); v != nil {
		return v, nil
	}
	return nil, fmt.Errorf("names the validator %q, which the detector layer does not have", d.Validator)
}

// matchesAsWritten accepts every match at full confidence: what the evaluator
// does when no validator gates a policy. It is set rather than left nil because
// the evaluator resolves a nil validator again, by category (getValidator).
func matchesAsWritten(string, string) (bool, float64) { return true, 1.0 }

// withoutInstalledIDs drops the rows that carry an installed detector's id. A
// detector's facts are keyed by its id, so a row under the same id - the rows
// the pack's retired seed script wrote, still present on a deployment that ran
// it - would report under the pack's id, and a row whose pattern had drifted
// from the pack's would decide the pack's control. The pack is the only author
// of its detectors (PRD v11 §1.2: a row authors no verdict).
func withoutInstalledIDs(rows, installed []CompiledPolicy) []CompiledPolicy {
	ids := make(map[string]bool, len(installed))
	for i := range installed {
		ids[installed[i].PolicyID] = true
	}
	kept := rows[:0]
	for i := range rows {
		if !ids[rows[i].PolicyID] {
			kept = append(kept, rows[i])
		}
	}
	return kept
}
