//go:build !enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import "axonflow/platform/decision/legacycompile"

// wiredEditionSeamScopes are the community build's own seams, stated as the
// health test's expectation: none.
var wiredEditionSeamScopes []legacycompile.EnforcementScope
