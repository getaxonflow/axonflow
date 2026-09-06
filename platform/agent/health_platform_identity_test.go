// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"axonflow/platform/shared/edition"
)

// getHealth drives the real handler and returns the decoded body.
func getHealth(t *testing.T) map[string]any {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	readinessAwareHealthHandler(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("/health returned %d, want 200", w.Code)
	}
	var body map[string]any
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("decode /health: %v", err)
	}
	return body
}

// TestHealthCarriesPlatformIdentity asserts the two #3660 members are served
// and carry the right values, and — the half that matters more — that adding
// them did not displace anything a client already reads.
//
// The displacement check is not paranoia. Every one of the five SDKs decodes
// this body, and the reason the Go SDK decodes /health into a map rather than a
// typed struct is a real incident: with a struct, one badly-typed member fails
// the WHOLE decode, so a new dimension silently regressed platform_version.
// Adding members is exactly the moment to prove the old ones survived.
func TestHealthCarriesPlatformIdentity(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "in-vpc-banking")
	appReady.Store(true)
	t.Cleanup(func() { appReady.Store(false) })

	body := getHealth(t)

	if got, _ := body["edition"].(string); got != edition.Current {
		t.Errorf("/health edition = %q, want %q (this build's tag)", got, edition.Current)
	}
	if got, _ := body["deployment_mode"].(string); got != "in-vpc-banking" {
		t.Errorf("/health deployment_mode = %q, want %q", got, "in-vpc-banking")
	}

	// Pre-existing members must all still be present and non-degraded.
	for _, k := range []string{
		"status", "service", "tier", "timestamp", "version",
		"capabilities", "sdk_compatibility", "plugin_compatibility",
	} {
		if _, ok := body[k]; !ok {
			t.Errorf("/health lost the pre-existing member %q after the additive change", k)
		}
	}
	if got, _ := body["service"].(string); got != "axonflow-agent" {
		t.Errorf("/health service = %q, want axonflow-agent", got)
	}
	if got, _ := body["version"].(string); got == "" {
		t.Error("/health version is empty; the SDK relay reads this field")
	}
	if got, _ := body["tier"].(string); got == "" {
		t.Error("/health tier is empty; the SDK licence-tier relay reads this field")
	}
}

// TestHealthOmitsDeploymentModeWhenUnset is the "absent is not empty" pin on
// the disclosure surface.
//
// An UNSET DEPLOYMENT_MODE must make the key MISSING, not present-and-empty and
// not defaulted to `community`. A relaying SDK omits what it did not learn, so
// a present-but-empty member here would put an empty string on the telemetry
// wire, and a `community` default would publish a claim about the customer's
// deployment that the deployment itself disagrees with — the runtime posture
// for an unset value is the enterprise one (#3128), not the community one.
func TestHealthOmitsDeploymentModeWhenUnset(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "")
	os.Unsetenv("DEPLOYMENT_MODE")
	appReady.Store(true)
	t.Cleanup(func() { appReady.Store(false) })

	body := getHealth(t)

	if v, present := body["deployment_mode"]; present {
		t.Errorf("/health carries deployment_mode = %#v with DEPLOYMENT_MODE unset; "+
			"the member must be OMITTED so a client can tell \"not reported\" from a value", v)
	}
	// edition is a compile-time constant, so it is ALWAYS present — the two
	// members have deliberately different presence rules and this asserts it.
	if _, present := body["edition"]; !present {
		t.Error("/health dropped edition; it is a compile-time constant and is always known")
	}
}

// TestHealthFoldsDeploymentModeAliases pins the alias folding. Every
// self-hosted enterprise compose file in this repo defaults DEPLOYMENT_MODE to
// the literal `enterprise`; reporting that spelling verbatim would split one
// population across two rows in every breakdown that reads this dimension.
func TestHealthFoldsDeploymentModeAliases(t *testing.T) {
	appReady.Store(true)
	t.Cleanup(func() { appReady.Store(false) })

	for raw, want := range map[string]string{
		"enterprise": "in-vpc-enterprise",
		"invpc":      "in-vpc-enterprise",
	} {
		t.Run(raw, func(t *testing.T) {
			t.Setenv("DEPLOYMENT_MODE", raw)
			if got, _ := getHealth(t)["deployment_mode"].(string); got != want {
				t.Errorf("DEPLOYMENT_MODE=%q → /health deployment_mode = %q, want %q", raw, got, want)
			}
		})
	}
}

// TestHealthBoundsAnOversizedDeploymentMode covers the hostile-but-valid path
// on the disclosure surface: an operator's oversized DEPLOYMENT_MODE must not
// be echoed to every client that probes /health, because four SDKs relay this
// member straight onto the telemetry wire.
func TestHealthBoundsAnOversizedDeploymentMode(t *testing.T) {
	appReady.Store(true)
	t.Cleanup(func() { appReady.Store(false) })
	t.Setenv("DEPLOYMENT_MODE", strings.Repeat("z", 10_000))

	got, _ := getHealth(t)["deployment_mode"].(string)
	if got != "unknown" {
		t.Errorf("/health deployment_mode = %q (%d bytes), want \"unknown\" — an unrecognised "+
			"mode must never be echoed verbatim to every client that probes /health",
			got, len(got))
	}
}

// TestHealthPlatformIdentityCapabilityIsAdvertised keeps discovery honest: a
// client branches on the capability list, so a member served without an entry
// reads as "not supported" to every consumer that checks first.
func TestHealthPlatformIdentityCapabilityIsAdvertised(t *testing.T) {
	appReady.Store(true)
	t.Cleanup(func() { appReady.Store(false) })

	var found *PlatformCapability
	for i, c := range getCapabilities() {
		if c.Name == "platform_identity_discovery" {
			found = &getCapabilities()[i]
			break
		}
	}
	if found == nil {
		t.Fatal("getCapabilities() has no platform_identity_discovery entry; the /health members " +
			"are served but undiscoverable")
	}
	if found.Since != "10.4.0" {
		t.Errorf("platform_identity_discovery Since = %q, want 10.4.0", found.Since)
	}
	// The description is the contract a PEP author reads. The two traps it must
	// name are the omission semantics and the deployment_mode mapping; a
	// description that loses either is how a relaying client gets it wrong.
	for _, must := range []string{"edition", "deployment_mode", "platform_deployment_mode", "OMITTED"} {
		if !strings.Contains(found.Description, must) {
			t.Errorf("platform_identity_discovery description does not mention %q", must)
		}
	}
}
