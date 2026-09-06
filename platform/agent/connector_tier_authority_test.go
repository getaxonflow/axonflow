// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"testing"

	"axonflow/platform/agent/license"
	sharedpolicy "axonflow/platform/shared/policy"
)

// TestConnectorCeilingFollowsTheLicencePackage pins the correspondence between
// the licence package's tier→limits table and the connector ceiling that
// platform/shared/policy applies.
//
// # WHY THIS TEST EXISTS, AND WHY IT LIVES HERE
//
// `classifyConnectorTier` in platform/shared/policy is a HAND-WRITTEN
// correspondence to `license.GetTierLimits`. It cannot import it: the ceiling is
// read at config time and `license.GetCurrentLimits` does signature
// verification, so making the ceiling depend on it would put licence I/O on
// every config read. A hand-written correspondence with no cross-check is the
// duplication this whole change is about, one layer up — R3 round 2 measured
// exactly that, planting `EnterpriseLimits.CustomPolicyConnectors: -1 -> 3` in
// the authority and watching `go test ./shared/policy/` stay green while only
// the licence package's own tables noticed.
//
// So the correspondence is pinned from the side that CAN see both. package
// agent already imports both; platform/shared cannot import package agent's
// licence table without inverting the dependency this test exists to avoid.
//
// A failure here means the two have diverged, and the fix is a decision, not a
// re-run: either the licence package changed what a tier is worth and
// classifyConnectorTier must follow, or someone widened the ceiling for a tier
// the licence does not actually grant it to.
func TestConnectorCeilingFollowsTheLicencePackage(t *testing.T) {
	cfg := sharedpolicy.DefaultDynamicPolicyConfig()

	// Every tier the licence package defines and can issue. Written out rather
	// than ranged over a map because there is no exported enumeration — and a
	// tier added to license.Tier without a row here is the drift the next
	// assertion catches.
	tiers := []license.Tier{
		license.TierCommunity,
		license.TierEvaluation,
		license.TierProfessional,
		license.TierEnterprise,
		license.TierEnterprisePlus,
	}

	for _, tier := range tiers {
		t.Run(string(tier), func(t *testing.T) {
			authority := license.GetTierLimits(tier).CustomPolicyConnectors
			applied := cfg.CustomPolicyConnectorLimitForTier(string(tier))

			if authority != applied {
				t.Errorf("tier %q: license.GetTierLimits says CustomPolicyConnectors=%d, "+
					"but the connector ceiling applies %d.\n"+
					"These are two statements of one entitlement and they have diverged. "+
					"Either the licence package changed what this tier is worth and "+
					"classifyConnectorTier in platform/shared/policy must follow, or the "+
					"ceiling was widened for a tier the licence does not grant it to.",
					tier, authority, applied)
			}
		})
	}

	// Anti-vacuity: the loop above is only evidence if the two sides CAN
	// disagree. If every tier resolved to the same number, this test would pass
	// for any implementation at all.
	distinct := map[int]bool{}
	for _, tier := range tiers {
		distinct[license.GetTierLimits(tier).CustomPolicyConnectors] = true
	}
	if len(distinct) < 2 {
		t.Fatalf("every tier maps to the same connector limit (%v), so this test "+
			"cannot distinguish a correct mapping from a constant one", distinct)
	}
}
