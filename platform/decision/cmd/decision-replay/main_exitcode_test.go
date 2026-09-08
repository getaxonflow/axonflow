// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A MISLABELLED BUNDLE IS A PIN PROBLEM, NOT A USAGE ERROR (#3700).
//
// exitPin means "these are not the artifacts your record was taken against";
// exitUsage means "you called me wrong". A bundle whose content does not hash
// to its advertised digest is squarely the first, and R3 round 2 found that
// the refusal this change exists to produce was exiting as the second - which
// is the one code an operator reads as their own mistake.
//
// No test covered the CLI's exit code for this path before, which is why the
// downgrade shipped through a round of review.
func TestAnUnpinnableEnvironmentExitsAsAPinFailure(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "replay", "testdata", "environment.json"))
	if err != nil {
		t.Skipf("no environment fixture to tamper with: %v", err)
	}
	var env map[string]any
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatal(err)
	}
	roots, _ := env["roots"].([]any)
	if len(roots) == 0 {
		t.Skip("the environment fixture holds no roots")
	}
	root, _ := roots[0].(map[string]any)
	bundle, _ := root["bundle"].(map[string]any)
	if bundle == nil {
		t.Skip("the environment fixture's first root carries no bundle")
	}
	// Content and signature untouched; only the advertised label is a lie.
	bundle["digest"] = "sha256:0000000000000000000000000000000000000000000000000000000000000000"

	dir := t.TempDir()
	path := filepath.Join(dir, "environment.json")
	out, err := json.Marshal(env)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, out, 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	code := run([]string{"-environment", path, filepath.Join("..", "..", "replay", "testdata")}, &stdout, &stderr)
	if code == exitUsage {
		t.Fatalf("a mislabelled bundle exited %d (exitUsage); an operator reads that as their own mistake, when the fact is that the artifacts do not match the record.\nstderr: %s", code, stderr.String())
	}
	if code != exitPin {
		t.Fatalf("exit %d, want exitPin (%d).\nstderr: %s", code, exitPin, stderr.String())
	}
	if !strings.Contains(stderr.String(), "does not match content digest") {
		t.Errorf("the refusal does not name the mismatch:\n%s", stderr.String())
	}
}
