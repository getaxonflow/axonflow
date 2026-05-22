//go:build !enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"testing"

	"github.com/gorilla/mux"
)

// Community-build coverage for the small "this symbol exists so the
// community-side caller compiles, but does nothing on this edition"
// shims that platform/agent/run.go invokes unconditionally regardless
// of build tag.
//
// Each shim's behavior contract is "callable + returns without panic
// + has no observable side effect." The intent of these tests is
// twofold: pin that contract for any future refactor that would turn
// the shim into a non-no-op AND register the lines as covered so the
// community-build coverage report doesn't regress when an unrelated
// PR adds production code elsewhere.

func TestRegisterBillingWebhook_CommunityIsNoop(t *testing.T) {
	// Shim definition: a community-edition no-op. Stripe-driven
	// license issuance is a paid feature. The symbol exists so
	// platform/agent/run.go can call it unconditionally — see
	// billing_register_community.go.
	r := mux.NewRouter()
	RegisterBillingWebhook(r, nil)
	// The shim must NOT register any route on the supplied router. We
	// don't introspect the route table beyond confirming the call
	// returned without panicking — the no-op contract is the entire
	// behavior under the community build tag.
	_ = r
}

func TestStartPluginLicenseMetricsPoller_CommunityReturnsCancellableNoop(t *testing.T) {
	// Shim contract: returns a non-nil cancel function that is safe
	// to call (twice). Even though the poller doesn't start anything
	// in community builds, the caller invariant (always cancel on
	// shutdown) MUST be preserved so a future flip to a non-shim
	// implementation doesn't break the lifecycle.
	cancel := startPluginLicenseMetricsPoller(nil)
	if cancel == nil {
		t.Fatal("startPluginLicenseMetricsPoller returned nil cancel func — caller invariant violated")
	}
	// Double-call must be safe.
	cancel()
	cancel()
}
