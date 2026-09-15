// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"testing"

	"axonflow/platform/shared/retiredenv/retiredenvtest"
)

// TestTheAgentBootRefusesARetiredOrNarrowingConfiguration: Run refuses a
// process whose environment still sets a retired decision-mode variable
// (retiredenv.Refuse, PRD v11 §5.1) or narrows what the engine decides
// (refuseNarrowedDetection, §1.7), and the refusal ends the process. What each
// refusal returns is held by its own tests; that boot calls it where nothing can
// skip it, and cannot continue past it, is held here.
func TestTheAgentBootRefusesARetiredOrNarrowingConfiguration(t *testing.T) {
	retiredenvtest.RequireFatalBootRefusal(t, "run.go", "Run", "retiredenv.Refuse", "refuseNarrowedDetection")
}
