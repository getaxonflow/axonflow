// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"testing"

	"axonflow/platform/shared/retiredenv/retiredenvtest"
)

// TestTheOrchestratorBootRefusesARetiredConfiguration: the orchestrator's boot
// refuses a process whose environment still sets a retired decision-mode
// variable (retiredenv.Refuse, PRD v11 §5.1), and the refusal ends the process.
// The refusal sits in initializeComponents, so the link from Run is held too: a
// Run that stopped calling it would skip the refusal with nothing else failing.
func TestTheOrchestratorBootRefusesARetiredConfiguration(t *testing.T) {
	retiredenvtest.RequireTopLevelCall(t, "run.go", "Run", "initializeComponents")
	retiredenvtest.RequireFatalBootRefusal(t, "run.go", "initializeComponents", "retiredenv.Refuse")
}
