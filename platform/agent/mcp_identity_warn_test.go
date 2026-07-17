// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"testing"
	"time"

	sharedidentity "axonflow/platform/shared/identity"
)

// resetFleetValidatorWarn restores the rate-limit state and clock so warn tests
// are deterministic and independent.
func resetFleetValidatorWarn(t *testing.T, now func() time.Time) {
	t.Helper()
	fleetValidatorWarnMu.Lock()
	fleetValidatorWarnedAt = time.Time{}
	fleetValidatorWarnMu.Unlock()
	orig := fleetValidatorWarnNow
	fleetValidatorWarnNow = now
	t.Cleanup(func() {
		fleetValidatorWarnNow = orig
		fleetValidatorWarnMu.Lock()
		fleetValidatorWarnedAt = time.Time{}
		fleetValidatorWarnMu.Unlock()
	})
}

func warnedAt() time.Time {
	fleetValidatorWarnMu.Lock()
	defer fleetValidatorWarnMu.Unlock()
	return fleetValidatorWarnedAt
}

// A presented token with no registered validator (#2932 misconfig) warns; and
// the warn is rate-limited so a busy fleet cannot flood the log.
func TestWarnPerUserTokenWithoutValidator_RateLimited(t *testing.T) {
	sharedidentity.ResetRegistryForTest()
	t.Cleanup(sharedidentity.ResetRegistryForTest)

	base := time.Unix(1_700_000_000, 0).UTC()
	var offset time.Duration
	resetFleetValidatorWarn(t, func() time.Time { return base.Add(offset) })

	// Token present, registry empty → warns (records the time).
	warnIfTokenWithoutValidator("some-token")
	first := warnedAt()
	if first.IsZero() {
		t.Fatal("expected a warning to be recorded")
	}

	// Within the interval → suppressed (timestamp unchanged).
	offset = time.Minute
	warnIfTokenWithoutValidator("some-token")
	if !warnedAt().Equal(first) {
		t.Fatal("warning within the rate-limit interval must be suppressed")
	}

	// Past the interval → warns again (timestamp advances).
	offset = fleetValidatorWarnInterval + time.Second
	warnIfTokenWithoutValidator("some-token")
	if warnedAt().Equal(first) || warnedAt().IsZero() {
		t.Fatal("warning must re-fire after the rate-limit interval")
	}
}

// No warning when there is no token, or when a validator IS registered.
func TestWarnIfTokenWithoutValidator_Quiet(t *testing.T) {
	base := time.Unix(1_700_000_000, 0).UTC()
	resetFleetValidatorWarn(t, func() time.Time { return base })

	// No token → never warns, regardless of registry.
	sharedidentity.ResetRegistryForTest()
	t.Cleanup(sharedidentity.ResetRegistryForTest)
	warnIfTokenWithoutValidator("")
	if !warnedAt().IsZero() {
		t.Fatal("no token must not warn")
	}

	// Token present but a validator IS registered → no misconfig, no warn.
	if err := sharedidentity.RegisterValidator(stubFleetValidator{name: "stub"}); err != nil {
		t.Fatalf("RegisterValidator: %v", err)
	}
	warnIfTokenWithoutValidator("some-token")
	if !warnedAt().IsZero() {
		t.Fatal("a registered validator means no misconfig — must not warn")
	}
}

// ensureFleetValidatorsRegistered is idempotent (sync.Once): calling it twice
// does not panic or double-register. In the community test build the
// constructors return ErrEnterpriseOnly, so nothing registers — a harmless
// no-op, exactly as a community deployment behaves.
func TestEnsureFleetValidatorsRegistered_Idempotent(t *testing.T) {
	sharedidentity.ResetRegistryForTest()
	t.Cleanup(sharedidentity.ResetRegistryForTest)
	ensureFleetValidatorsRegistered()
	ensureFleetValidatorsRegistered()
	if isCommunityBuild && sharedidentity.HasRegisteredValidators() {
		t.Fatal("community build must register no fleet validators")
	}
}
