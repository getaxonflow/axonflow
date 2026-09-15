// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

// Package manifests finds the deployment manifests in a checkout - compose
// files, CloudFormation templates, task definitions - so every guard over them
// reads one population instead of each walking the tree its own way.
package manifests

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// Files returns every file under root whose name ends in one of exts, sorted.
// It skips the directories no manifest the platform ships lives in: version
// control, and dependency and build trees.
func Files(t testing.TB, root string, exts ...string) []string {
	t.Helper()
	var out []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", "vendor", ".next":
				return filepath.SkipDir
			}
			return nil
		}
		for _, e := range exts {
			if strings.HasSuffix(path, e) {
				out = append(out, path)
				return nil
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking manifests: %v", err)
	}
	sort.Strings(out)
	return out
}
