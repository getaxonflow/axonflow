// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"errors"
	"testing"
)

// TestThePolicyProbeWithoutAPoolFallsThrough: a policy repository with no pool
// reports an error rather than panicking, so the pre-read guard falls through
// and a handler built without a database behaves as it did before the guard
// (#4237 follow-up, R3 round 1 L1).
func TestThePolicyProbeWithoutAPoolFallsThrough(t *testing.T) {
	var nilRepo *PolicyRepository
	if may, err := nilRepo.MayWriteLegacyPolicies(context.Background()); !errors.Is(err, errNoPolicyPool) || may {
		t.Fatalf("nil repository: %v, %v; want false and errNoPolicyPool", may, err)
	}
	if may, err := (&PolicyRepository{}).MayWriteLegacyPolicies(context.Background()); !errors.Is(err, errNoPolicyPool) || may {
		t.Fatalf("repository without a pool: %v, %v; want false and errNoPolicyPool", may, err)
	}
	// Template apply asks the POLICY repository's probe: the pool its create
	// writes through (ApplyTemplate -> policyRepo.Create). A service built on a
	// policy repository without a pool reports that repository's error.
	if may, err := NewTemplateService(nil, &PolicyRepository{}).MayWriteLegacyPolicies(context.Background()); !errors.Is(err, errNoPolicyPool) || may {
		t.Fatalf("template service over a policy repository without a pool: %v, %v; want false and errNoPolicyPool", may, err)
	}
}
