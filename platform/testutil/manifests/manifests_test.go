// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package manifests

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// Files returns exactly the files with a requested extension, sorted, and
// nothing under a directory it skips.
func TestFilesReturnsTheRequestedExtensionsOutsideSkippedDirectories(t *testing.T) {
	root := t.TempDir()
	for _, rel := range []string{
		"docker-compose.yml",
		"infra/stack.yaml",
		"infra/notes.md",
		".git/config.yml",
		"ui/node_modules/pkg/compose.yml",
		"vendor/mod/template.yaml",
		"portal/.next/cache.yml",
	} {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	got := Files(t, root, ".yml", ".yaml")
	want := []string{filepath.Join(root, "docker-compose.yml"), filepath.Join(root, "infra/stack.yaml")}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Files = %v, want %v", got, want)
	}
}
