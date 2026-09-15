// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package activation

import "fmt"

// EffectCounts is how many of an activation's policies are whose on its scope
// (#4152), read from PolicyEffects.
type EffectCounts struct {
	// Shipped, Organization and Pack partition the policies the engine carries.
	Shipped, Organization, Pack int
	// Disabled is the policies of the shipped controls the organization's
	// document disabled on the scope; one control can bind several. The engine
	// does not carry them, so no other count includes them.
	Disabled int
}

// Total is every policy the engine carries on the scope.
func (c EffectCounts) Total() int { return c.Shipped + c.Organization + c.Pack }

// CountEffects counts effects by whose each policy is.
//
// A RECORDED OVERRIDE'S REPLACEMENT COUNTS AS THE ORGANIZATION'S. On the wire it
// is shipped (SourceShipped, identity.go), because it has no published version
// and the bundle digest identifies it. It enforces what the organization
// recorded, though, and a count of the organization's policies that left it out
// would say an organization that re-actioned a category had changed nothing.
//
// Every replacement is counted once, in place of the control it displaces,
// which the engine no longer carries. A source no count names is an error
// rather than a bucket nobody reads.
func CountEffects(effects []PolicyEffect) (EffectCounts, error) {
	var c EffectCounts
	for _, e := range effects {
		switch {
		case e.Disabled:
			c.Disabled++
		case e.Replacement == ReplacementOverride:
			c.Organization++
		case e.Source == SourceShipped:
			c.Shipped++
		case e.Source == SourceOrganization:
			c.Organization++
		case e.Source == SourcePack:
			c.Pack++
		default:
			return EffectCounts{}, fmt.Errorf("activation: policy %s has source %q, which no count names", e.PolicyID, e.Source)
		}
	}
	return c, nil
}
