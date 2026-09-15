// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package activation_test

import (
	"context"
	"errors"
	"testing"

	"axonflow/platform/decision/activation"
	"axonflow/platform/decision/authoring"
)

// AN ACTIVATION WHOSE INPUTS CANNOT BE READ IS REFUSED, NOT RUN ON WHAT WAS
// READABLE (PRD v11 §1.5). A transport whose recorded-posture read fails hands
// the error to the activator, which returns it rather than activating under the
// shipped actions: the dry runs fail closed as the enforcing seam does.
func TestAnActivatorWhoseInputsCannotBeReadRefusesTheActivation(t *testing.T) {
	unreadable := errors.New("the recorded detection posture could not be read")
	activate := activation.Activator(func(context.Context) (activation.Inputs, error) {
		return activation.Inputs{}, unreadable
	})
	if err := activate(context.Background(), authoring.ActivationPromote, nil); !errors.Is(err, unreadable) {
		t.Fatalf("the activator returned %v; want the inputs' error, refusing the activation", err)
	}
}
