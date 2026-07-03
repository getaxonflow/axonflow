//go:build enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"os"
	"strings"
)

// extraTextDocumentToolsFromEnv parses AXONFLOW_TEXT_DOCUMENT_TOOLS — a
// comma-separated list of additional tool identities to classify as
// text-document for capability-scoped evaluation (#2801). Enterprise-only
// operator config surface (HARD RULE 11): the community edition ships the
// built-in registry (platform/shared/policy/capability.go) with no override.
//
// Entries are exact names, case-insensitive, matched against both the full
// identity and its terminal segment (so either `editWikiPage` or
// `claude_code.mcp__wiki__editWikiPage` works). Classifying a tool here
// RELAXES execution-class detection for it — list only tools that genuinely
// cannot execute their input (no shell, no SQL/DSL, no file system, no
// arbitrary network fetch).
func extraTextDocumentToolsFromEnv() []string {
	raw := strings.TrimSpace(os.Getenv("AXONFLOW_TEXT_DOCUMENT_TOOLS"))
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	tools := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			tools = append(tools, p)
		}
	}
	return tools
}
