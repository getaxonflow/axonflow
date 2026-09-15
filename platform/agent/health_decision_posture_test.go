// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"

	"axonflow/platform/decision/legacycompile"
	sharedidentity "axonflow/platform/shared/identity"
)

// /health's `decision` member (#3895 PR-A2, #3564; PRD v11 §5.1), read off the
// ENCODED body of the handler /health is registered to. The member's absence
// and its presence are both contract, so both are asserted, and "absent" means
// the key is not in the object - a jq path returns the empty string for an
// absent member and a null one alike, which is the collapse this test exists to
// rule out.

// wiredSeamScopes are the scopes whose seams this binary holds, stated here as
// the test's own expectation rather than read back from enforcingSeams, so a
// seam dropped from that list reds here naming the plane it dropped.
var wiredSeamScopes = []legacycompile.EnforcementScope{
	decideSeamScope, gatewayRequestSeamScope, mcpRequestSeamScope, mcpResponseSeamScope, proxyRequestSeamScope, openaiCompatibleSeamScope,
}

func healthBody(t *testing.T) map[string]json.RawMessage {
	t.Helper()
	rr := httptest.NewRecorder()
	readinessAwareHealthHandler(rr, httptest.NewRequest("GET", "/health", nil))
	var body map[string]json.RawMessage
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatalf("/health is not a JSON object: %v\n%s", err, rr.Body.String())
	}
	return body
}

// withNoEnforcer clears the process enforcer for the test and restores it.
func withNoEnforcer(t *testing.T) {
	t.Helper()
	prev := anchoredEnforcerInstance.Load()
	anchoredEnforcerInstance.Store(nil)
	t.Cleanup(func() { anchoredEnforcerInstance.Store(prev) })
}

func TestHealthDecisionPostureIsAbsentOnAProcessWithNoEnforcer(t *testing.T) {
	withNoEnforcer(t)
	if v, has := healthBody(t)["decision"]; has {
		t.Fatalf("/health carries a decision member (%s) on a process with no enforcer; it must be OMITTED, not null", v)
	}
}

// TestHealthDecisionPostureReportsEveryEnforcingPlane drives the REAL installer
// the boot path calls and reads what /health reports. There is no mode, so the
// member carries no `mode` and no process-default `engine`: every enforcing
// plane's verdict is the anchored engine's.
func TestHealthDecisionPostureReportsEveryEnforcingPlane(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "enterprise")
	withNoEnforcer(t)
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	boot, err := sharedidentity.BootstrapAdmission(sharedidentity.AdmissionBootstrapConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if err := installAnchoredEnforcer(db, boot); err != nil {
		t.Fatalf("the installer refused with a database and an identity plane present: %v", err)
	}

	raw, has := healthBody(t)["decision"]
	if !has {
		t.Fatal("/health carries no decision member on a process whose enforcer is installed")
	}
	var posture map[string]json.RawMessage
	if err := json.Unmarshal(raw, &posture); err != nil {
		t.Fatalf("the decision member is not an object: %v (%s)", err, raw)
	}
	for _, retired := range []string{"mode", "engine"} {
		if _, present := posture[retired]; present {
			t.Fatalf("the decision member carries %q (%s); v11 has no decision mode and no other engine to name", retired, raw)
		}
	}
	var planes []string
	if err := json.Unmarshal(posture["enforcing_planes"], &planes); err != nil {
		t.Fatalf("enforcing_planes is not a string list: %v (%s)", err, raw)
	}
	want := make(map[string]bool, len(wiredSeamScopes))
	for _, s := range wiredSeamScopes {
		want[s.String()] = true
	}
	for _, p := range planes {
		if !want[p] {
			t.Errorf("/health reports %s as enforcing and this binary holds no seam for it", p)
		}
		delete(want, p)
	}
	for missing := range want {
		t.Errorf("/health does not report %s, whose seam this binary holds", missing)
	}
}
