// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"os"
	"strings"

	sharedpolicy "axonflow/platform/shared/policy"
)

// capabilityScopedEngineConfig builds the shared policy-engine config with
// the capability-scoping levers applied (#2801):
//
//   - AXONFLOW_CAPABILITY_SCOPING_DISABLED=true restores pre-#2801 behavior
//     (execution-class detectors evaluate every tool, including
//     text-document tools). Available in BOTH editions — it only ever widens
//     evaluation, never relaxes it.
//   - AXONFLOW_TEXT_DOCUMENT_TOOLS extends the built-in text-document
//     registry. Enterprise-only (see capability_scope_config.go); the
//     community stub returns nil.
func capabilityScopedEngineConfig() sharedpolicy.EngineConfig {
	cfg := sharedpolicy.DefaultEngineConfig()
	cfg.DisableCapabilityScoping = strings.EqualFold(
		strings.TrimSpace(os.Getenv("AXONFLOW_CAPABILITY_SCOPING_DISABLED")), "true")
	cfg.ExtraTextDocumentTools = extraTextDocumentToolsFromEnv()
	return cfg
}
