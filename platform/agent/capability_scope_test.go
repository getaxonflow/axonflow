// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import "testing"

// Edition-agnostic capability-scope config levers (#2801). The
// AXONFLOW_TEXT_DOCUMENT_TOOLS extension is enterprise-only and covered in
// capability_scope_config_test.go (build-tagged); the kill switch is a
// bug-fix safety valve available in both editions.
func TestCapabilityScopedEngineConfig_KillSwitch(t *testing.T) {
	t.Setenv("AXONFLOW_CAPABILITY_SCOPING_DISABLED", "")
	if capabilityScopedEngineConfig().DisableCapabilityScoping {
		t.Error("capability scoping must default ON (the fix is default behavior)")
	}

	for _, v := range []string{"true", "TRUE", " true "} {
		t.Setenv("AXONFLOW_CAPABILITY_SCOPING_DISABLED", v)
		if !capabilityScopedEngineConfig().DisableCapabilityScoping {
			t.Errorf("AXONFLOW_CAPABILITY_SCOPING_DISABLED=%q must disable scoping", v)
		}
	}

	// Anything but true keeps the fix on (no accidental disablement).
	for _, v := range []string{"false", "1", "yes"} {
		t.Setenv("AXONFLOW_CAPABILITY_SCOPING_DISABLED", v)
		if capabilityScopedEngineConfig().DisableCapabilityScoping {
			t.Errorf("AXONFLOW_CAPABILITY_SCOPING_DISABLED=%q must NOT disable scoping", v)
		}
	}
}
