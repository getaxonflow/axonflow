//go:build !enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

// extraTextDocumentToolsFromEnv is the community stub for the Enterprise
// AXONFLOW_TEXT_DOCUMENT_TOOLS registry extension (#2801, HARD RULE 11):
// community deployments use the built-in text-document tool registry
// (platform/shared/policy/capability.go) with no operator override. The
// AXONFLOW_CAPABILITY_SCOPING_DISABLED kill switch (a bug-fix safety valve
// that only ever WIDENS evaluation) is available in both editions.
func extraTextDocumentToolsFromEnv() []string {
	return nil
}
