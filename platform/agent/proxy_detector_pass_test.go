// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

// TestTurningGatewayDetectionOffFailsClosedOnTheOnePass: no deployment reaches
// this state. GATEWAY_STATIC_POLICIES_ENABLED off refuses the boot
// (refuseNarrowedDetection), and a per-organization detection override writes
// an action, never whether a detector runs. The branch is pinned as defence in
// depth: with no detector input, every shipped control that reads a detector
// is UNKNOWN and the anchored engine refuses the request (unknown_constraint),
// so switching detection off can never open /api/request (#4253). The CONTROL
// is the same clean query with detection on: an evaluation, and an allow.
func TestTurningGatewayDetectionOffFailsClosedOnTheOnePass(t *testing.T) {
	enfProxySetup(t)
	enfCommunityOrg(t, enfOrgPublished)
	user := &User{ID: 1, OrgID: enfOrgPublished, TenantID: enfOrgPublished, Role: "admin"}
	const query = "SELECT id FROM products"

	if ev := proxyDetectorPass(context.Background(), query, user); ev == nil {
		t.Fatal("CONTROL: with gateway detection on the pass returned no evaluation, so the refusal below would prove nothing")
	}
	if r := enfProxy(t, enfOrgPublished, "", query); r.code != http.StatusOK || r.blocked(t) {
		t.Fatalf("CONTROL: with gateway detection on the clean query answered HTTP %d blocked=%v, want an allow: %s", r.code, r.blocked(t), r.raw)
	}

	disabled := ModeDetectionConfig{Enabled: false}
	detectionConfigMu.Lock()
	orig := cachedGatewayConfig
	cachedGatewayConfig = &disabled
	detectionConfigMu.Unlock()
	t.Cleanup(func() {
		detectionConfigMu.Lock()
		cachedGatewayConfig = orig
		detectionConfigMu.Unlock()
	})

	if ev := proxyDetectorPass(context.Background(), query, user); ev != nil {
		t.Fatalf("gateway detection is off and the pass still evaluated: %+v", ev)
	}
	r := enfProxy(t, enfOrgPublished, "", query)
	if r.code != http.StatusForbidden || !r.blocked(t) || r.str(t, "engine") != decisionEngineAnchored ||
		!strings.HasPrefix(r.str(t, "block_reason"), "unknown_constraint") {
		t.Fatalf("with gateway detection off the one pass answered HTTP %d blocked=%v engine=%q block_reason=%q; want 403, blocked, engine=anchored and unknown_constraint: it must fail closed. body=%s",
			r.code, r.blocked(t), r.str(t, "engine"), r.str(t, "block_reason"), r.raw)
	}
}
