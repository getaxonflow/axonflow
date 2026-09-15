// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package activationinputs

import (
	"context"

	"axonflow/platform/decision/activation"
)

// SetActivate replaces ActiveSummary's activation until restore is called.
func SetActivate(f func(context.Context, activation.Inputs) (*activation.Activation, error)) (restore func()) {
	prev := activate
	activate = f
	return func() { activate = prev }
}
