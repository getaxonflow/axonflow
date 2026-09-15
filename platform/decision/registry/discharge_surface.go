// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package registry

import "axonflow/platform/decision/contract"

// DischargeSurface is everything that can discharge a mandatory obligation on
// one enforcement scope: the plane's registered profile, which is what the
// plane discharges itself, and what the scope's wire hands to an enforcement
// point that declares it, narrowed to what this edition may declare
// (SplitOverAdvertised).
//
// It lives here, beside the profiles and the edition rule it reads, so that
// activation's discharge guard and the corpus build's template split
// (legacycompile, #4131) ask one question of one model. Neither package can
// import the other in the direction a single copy needs.
type DischargeSurface struct {
	// Profile is the plane's registered enforcement profile: what the plane
	// discharges itself. Nil discharges nothing.
	Profile *contract.PEPProfile
	// Delivers is what the scope's wire hands to an enforcement point that
	// declares it, already narrowed to what this edition may declare.
	Delivers []contract.Capability
}

// NewDischargeSurface builds a scope's surface from its registered profile and
// the capabilities its wire delivers, keeping only the delivered capabilities
// an enforcement point of this edition may declare.
func NewDischargeSurface(profile *contract.PEPProfile, delivers []contract.Capability, edition Edition) DischargeSurface {
	kept, _ := SplitOverAdvertised(edition, delivers)
	return DischargeSurface{Profile: profile, Delivers: kept}
}

// Discharges reports whether the plane discharges o itself or its wire hands o
// to a caller that declares it - by exact type and schema version, as
// contract.PEPProfile.Supports compares.
func (s DischargeSurface) Discharges(o contract.Obligation) bool {
	if s.Profile.Supports(o) {
		return true
	}
	for _, c := range s.Delivers {
		if c == o.CapabilityOf() {
			return true
		}
	}
	return false
}
