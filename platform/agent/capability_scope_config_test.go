//go:build enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"reflect"
	"testing"
)

func TestExtraTextDocumentToolsFromEnv_Enterprise(t *testing.T) {
	t.Setenv("AXONFLOW_TEXT_DOCUMENT_TOOLS", " editWikiPage, notion__update_page ,, ")
	got := extraTextDocumentToolsFromEnv()
	want := []string{"editWikiPage", "notion__update_page"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v want %v", got, want)
	}

	t.Setenv("AXONFLOW_TEXT_DOCUMENT_TOOLS", "")
	if got := extraTextDocumentToolsFromEnv(); got != nil {
		t.Errorf("empty env must return nil, got %v", got)
	}
}

func TestCapabilityScopedEngineConfig_WiresExtension(t *testing.T) {
	t.Setenv("AXONFLOW_TEXT_DOCUMENT_TOOLS", "editWikiPage")
	t.Setenv("AXONFLOW_CAPABILITY_SCOPING_DISABLED", "")
	cfg := capabilityScopedEngineConfig()
	if !reflect.DeepEqual(cfg.ExtraTextDocumentTools, []string{"editWikiPage"}) {
		t.Errorf("ExtraTextDocumentTools not wired: %v", cfg.ExtraTextDocumentTools)
	}
	if cfg.DisableCapabilityScoping {
		t.Error("scoping must be enabled by default")
	}
}
