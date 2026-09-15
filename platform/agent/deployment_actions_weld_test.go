// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"sort"
	"strings"
	"testing"

	"axonflow/platform/decision/authoringcatalog"
)

// TestTheDeploymentActionsAreTheAdaptersActions holds the deployment authoring
// vocabulary's action set to the AuthZEN adapter's own mapping table (#3895).
//
// # WHY THIS TEST HAS TO EXIST, AND WHY IT LIVES HERE
//
// authoringcatalog declares three governed operations and its comment says they
// are "the exact action names the AuthZEN adapter maps". That sentence was a
// CLAIM with nothing behind it: the decision module cannot import
// platform/agent, so it cannot check the adapter, and nothing else was looking.
// This package can import the decision module, so the check belongs here.
//
// # WHAT BREAKS IF THE TWO DRIFT
//
// The adapter refuses an action name it does not recognise, and the registry
// refuses one it has not registered. If the adapter gains a fourth stage and the
// vocabulary does not, every request naming it is refused at ADMISSION for an
// unregistered action - a deny with an empty determining set, which explains
// nothing to the caller. If the vocabulary gains one and the adapter does not,
// an author can write a policy over an action no request can ever carry: a
// control that looks live and governs nothing.
//
// Both directions are asserted, because each is a different failure.
func TestTheDeploymentActionsAreTheAdaptersActions(t *testing.T) {
	adapter := make([]string, 0, len(authzenActionStage))
	for name := range authzenActionStage {
		adapter = append(adapter, name)
	}
	sort.Strings(adapter)

	vocabulary := authoringcatalog.DeploymentActions()

	if len(adapter) == 0 || len(vocabulary) == 0 {
		t.Fatalf("one side is empty (adapter %d, vocabulary %d); this test would then compare nothing",
			len(adapter), len(vocabulary))
	}
	if strings.Join(adapter, ",") != strings.Join(vocabulary, ",") {
		t.Fatalf("the AuthZEN adapter maps %v and the deployment vocabulary registers %v.\n"+
			"An action the adapter maps and the registry does not is refused at admission for an unregistered "+
			"action - a deny with an empty determining set. An action the registry declares and the adapter does "+
			"not lets an author write a policy over an operation no request can carry.",
			adapter, vocabulary)
	}

	// AND THE STAGE EACH ONE MAPS TO IS THE STAGE ITS TAG NAMES. The vocabulary
	// tags each action `stage:<x>` so a policy can select a whole stage; if that
	// tag disagreed with the adapter's stage, a stage-scoped policy would govern
	// a different stage than its author read.
	for name, stage := range authzenActionStage {
		local, _, found := strings.Cut(name, ".")
		if !found {
			t.Fatalf("adapter action %q has no dotted prefix to compare against a stage", name)
		}
		if local != stage {
			t.Errorf("the adapter maps %q to stage %q; the vocabulary tags it stage:%s, so a stage-scoped policy "+
				"would select a different population than its author read", name, stage, local)
		}
	}
}
