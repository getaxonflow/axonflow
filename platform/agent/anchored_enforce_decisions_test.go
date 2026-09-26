// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import "axonflow/platform/shared/anchoredenforcer"

// anchoredEnforceDecisions is the enforcement counter, for the tests that read
// a series back. Production code counts only through RecordEnforcement, whose
// verdict label the guard in anchoredenforcer checks; it never names the
// CounterVec (verdict_label_guard_test.go), so this handle lives in a test file.
var anchoredEnforceDecisions = anchoredenforcer.Decisions
