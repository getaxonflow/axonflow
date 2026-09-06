// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package policy

import (
	"context"
	"log"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// This file is the seam through which the connector ceiling learns which tier
// the deployment's licence key VERIFIABLY grants (#3709 row 1).
//
// # WHY A SEAM AND NOT A PARSER
//
// Until this change resolveConnectorLimitTier carried its own reader,
// extractTierFromLicenseKey, which base64-decoded AXONFLOW_LICENSE_KEY and took
// the payload's `tier` on trust: no signature, no expiry. Its comment said the
// signature was "verified elsewhere at startup", and for the community and
// community-saas postures that was false - platform/agent/run.go returns
// before license.ValidateWithRetry under both. Measured: a key signed with the
// literal bytes `NOTASIG!` and a payload naming tier Enterprise resolved to
// "enterprise" here, and nothing on the path read expires_at, so an expired or
// revoked key kept its grant indefinitely.
//
// The verified read exists - license.ReadCurrentTier checks the Ed25519
// signature and compares ExpiresAt - and it lives in platform/agent/license.
// Reaching it from here has two shapes:
//
//   - import platform/agent/license from platform/shared/policy. It compiles
//     (loader.go in this package already imports platform/agent/rls, and the
//     licence package has no in-repo dependencies), but it deepens an
//     inversion this tree treats as debt: platform/shared is the layer the
//     planes are built ON, and every import upward is one more reason the
//     packages cannot be moved apart. REJECTED for that reason, not because
//     it cannot be built.
//   - have the plane that owns the licence hand the verified read DOWN. That
//     is this file. package agent registers license.GetCurrentTier at init
//     (platform/agent/license_tier_source.go); this package never learns what
//     a licence key looks like. CHOSEN.
//
// The third shape - moving platform/agent/license itself under platform/shared,
// where its dependency set says it belongs - is the eventual destination and
// is filed on #3709 rather than done in a pre-cut change: it is a package move
// with an ee/ twin and over a hundred importers.
//
// # THE DEFAULT FAILS CLOSED, AND IT IS NOT SILENT
//
// With no source registered every licence-key entitlement resolves to the
// Community tier. Closed is the only safe answer for an unverified claim, but
// it is also a NEW way for a paying deployment to land on the two-connector
// ceiling - a binary that forgot to register, a wiring regression - and #3749's
// own review history is the warning: its first round silently dropped the
// Professional and Plus tiers to that ceiling through exactly this shape of
// default. So the unregistered case is observable on two surfaces: a log line
// naming it, and axonflow_license_tier_source_unregistered_total, which a fleet
// reader can alert on. A fail-closed default that is also silent is the
// "truncates lists silently" hazard wearing a safer name.

// LicenseTierSource answers "which tier does this deployment's licence key
// verifiably grant?" with the tier's name (the license.Tier string, any case)
// or "" when it grants nothing. It must NOT trust the key's payload: an
// implementation that decodes a tier without checking the signature and the
// expiry re-creates the defect this seam removed.
type LicenseTierSource func(ctx context.Context) string

var (
	licenseTierSourceMu sync.RWMutex
	licenseTierSource   LicenseTierSource

	// unregisteredLogged gates the log line to once per registration state:
	// SetLicenseTierSource resets it, so a process that resolves before its
	// plane registers a source logs once, and a test that clears the source
	// can observe the line again.
	unregisteredLogged atomic.Bool
)

var licenseTierSourceUnregistered = promauto.NewCounter(prometheus.CounterOpts{
	Name: "axonflow_license_tier_source_unregistered_total",
	Help: "Licence-key entitlement resolutions made while NO verified tier source was registered, each answered Community. " +
		"Non-zero means this binary resolves tier-gated limits without ever consulting its licence.",
})

// SetLicenseTierSource registers the verified read. The plane that owns the
// licence calls it at init; passing nil clears it (tests).
func SetLicenseTierSource(src LicenseTierSource) {
	licenseTierSourceMu.Lock()
	defer licenseTierSourceMu.Unlock()
	licenseTierSource = src
	unregisteredLogged.Store(false)
}

// verifiedLicenseTier returns the lower-cased tier the registered source
// grants, or "community" when there is no source or the source grants nothing.
func verifiedLicenseTier(ctx context.Context) string {
	licenseTierSourceMu.RLock()
	src := licenseTierSource
	licenseTierSourceMu.RUnlock()

	if src == nil {
		licenseTierSourceUnregistered.Inc()
		if unregisteredLogged.CompareAndSwap(false, true) {
			log.Printf("[DynamicPolicyEvaluator] no verified licence tier source is registered in this process; " +
				"every licence-key entitlement resolves to the COMMUNITY tier. A plane that holds a licence " +
				"registers license.GetCurrentTier through policy.SetLicenseTierSource at init (#3709 row 1).")
		}
		return "community"
	}
	tier := strings.ToLower(strings.TrimSpace(src(ctx)))
	if tier == "" {
		return "community"
	}
	return tier
}
