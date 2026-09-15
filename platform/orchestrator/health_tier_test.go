// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"testing"

	"axonflow/platform/agent/license"
)

// fakeTierChecker is the minimum tierReader that lets the two PRODUCTION
// branches of licenseTierFrom be reached at all.
type fakeTierChecker struct{ tier license.Tier }

func (f fakeTierChecker) IsEnterprise() bool  { return f.tier == license.TierEnterprise }
func (f fakeTierChecker) Tier() license.Tier  { return f.tier }
func (f fakeTierChecker) PolicyLimit() int    { return -1 }
func (f fakeTierChecker) OrgPolicyLimit() int { return -1 }

// TestLicenseTierFromCoversEveryBranchIncludingTheOnesProductionTakes.
//
// The /health test above it can only ever observe the nil branch, because
// `tierChecker` is a package global that a unit test never assigns. So the two
// branches that run on a real deployment were unreachable, and mutating both to
// garbage left every test green. This drives all three.
func TestLicenseTierFromCoversEveryBranchIncludingTheOnesProductionTakes(t *testing.T) {
	for _, tc := range []struct {
		name    string
		checker tierReader
		want    string
	}{
		{"before initialization the checker is nil", nil, "starting"},
		{"a checker reporting nothing means community", fakeTierChecker{tier: ""}, string(license.TierCommunity)},
		{"a real tier is reported verbatim", fakeTierChecker{tier: license.TierEnterprise}, string(license.TierEnterprise)},
		{"community is reported verbatim too", fakeTierChecker{tier: license.TierCommunity}, string(license.TierCommunity)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := licenseTierFrom(tc.checker); got != tc.want {
				t.Errorf("licenseTierFrom = %q, want %q", got, tc.want)
			}
		})
	}
}
