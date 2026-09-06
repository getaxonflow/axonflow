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

// The command's own tests.
//
// The library is tested next door; this file exists because the two things a
// CLI adds are the two things a library test cannot see: the EXIT CODE and
// what the operator is told. Both are load-bearing here. A script that runs
// this tool in an incident branches on the code, and a tool that printed
// REFUSED while exiting 0 would be read as a clean reproduction by anything
// automated and by most people.

// fixtureDir is the library's committed fixture, used from here rather than
// copied. A second copy of the artifact would drift, and a command tested
// against its own private artifact proves nothing about the one on disk.
const fixtureDir = "../../replay/testdata"

func envPath() string     { return filepath.Join(fixtureDir, "environment.json") }
func samplesPath() string { return filepath.Join(fixtureDir, "samples") }

func exec(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errBuf bytes.Buffer
	code := run(args, &out, &errBuf)
	return code, out.String(), errBuf.String()
}

// TestReplayingTheCommittedSamplesVerifiesEveryOne is case 1: identical input
// and bundle reproduce the identical decision, offline.
func TestReplayingTheCommittedSamplesVerifiesEveryOne(t *testing.T) {
	code, _, stderr := exec(t, "-environment", envPath(), "-dir", samplesPath(), "-quiet")
	if code != exitOK {
		t.Fatalf("exit %d, want %d\n%s", code, exitOK, stderr)
	}
	verified := strings.Count(stderr, "VERIFIED ")
	if verified < 5 {
		t.Fatalf("only %d record(s) verified; the committed fixture holds more, so this run did not replay them all\n%s", verified, stderr)
	}
	if strings.Contains(stderr, "DIFFERS") || strings.Contains(stderr, "EMITTED") {
		t.Errorf("a sample did not verify:\n%s", stderr)
	}
	// The states the run reported, so a fixture flattened to one outcome
	// cannot make this case pass by reproducing a constant.
	for _, want := range []string{"ALLOW/", "DENY/", "CHALLENGE/", "ERROR/"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("no sample reported a %s decision; the run reproduced a narrower surface than the fixture holds\n%s", want, stderr)
		}
	}
}

// TestAChangedInputProducesADifferentDecision is case 2. The two arms are the
// matched pair, replayed in one invocation against one environment.
func TestAChangedInputProducesADifferentDecision(t *testing.T) {
	code, stdout, stderr := exec(t, "-environment", envPath(),
		filepath.Join(samplesPath(), "spend-below-threshold.json"),
		filepath.Join(samplesPath(), "spend-above-threshold.json"))
	if code != exitOK {
		t.Fatalf("exit %d, want %d\n%s", code, exitOK, stderr)
	}

	// Read the states off the DECISIONS the tool emitted rather than off its
	// summary line, so the assertion is about the artifact a caller consumes.
	dec := json.NewDecoder(strings.NewReader(stdout))
	var states []string
	for {
		var d struct {
			State  string `json:"state"`
			Reason string `json:"reason"`
		}
		if err := dec.Decode(&d); err != nil {
			break
		}
		states = append(states, d.State+"/"+d.Reason)
	}
	if len(states) != 2 {
		t.Fatalf("the tool emitted %d decision(s), want 2: %v\n%s", len(states), states, stdout)
	}
	if states[0] == states[1] {
		t.Fatalf("both arms decided %s; the replay is not a function of the input it was given", states[0])
	}
}

// TestAMismatchedPinRefusesAndExitsTwo is case 3.
//
// Both halves matter and only one is usually written: the tool must refuse,
// AND it must not emit a decision. A decision on stdout beside a refusal on
// stderr is what a script picks up.
func TestAMismatchedPinRefusesAndExitsTwo(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(samplesPath(), "spend-above-threshold.json"))
	if err != nil {
		t.Fatalf("reading the sample: %v", err)
	}
	var rec map[string]any
	if err := json.Unmarshal(raw, &rec); err != nil {
		t.Fatalf("decoding the sample: %v", err)
	}
	pins, ok := rec["bundle_pins"].([]any)
	if !ok || len(pins) == 0 {
		t.Fatalf("the sample carries no bundle pins to break: %v", rec["bundle_pins"])
	}
	pins[0].(map[string]any)["digest"] = "sha256:" + strings.Repeat("0", 64)

	broken := filepath.Join(t.TempDir(), "mispinned.json")
	out, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		t.Fatalf("re-encoding the sample: %v", err)
	}
	if err := os.WriteFile(broken, out, 0o644); err != nil {
		t.Fatalf("writing the broken record: %v", err)
	}

	code, stdout, stderr := exec(t, "-environment", envPath(), broken)
	if code != exitPin {
		t.Fatalf("exit %d, want %d (pin refusal)\n%s", code, exitPin, stderr)
	}
	if strings.TrimSpace(stdout) != "" {
		t.Errorf("a decision was emitted alongside the refusal:\n%s", stdout)
	}
	if !strings.Contains(stderr, "REFUSED") || !strings.Contains(stderr, "the record pins bundle") {
		t.Errorf("the refusal does not say what did not match:\n%s", stderr)
	}

	// The control: the same record, unbroken, replays. Without it a tool that
	// refused everything would pass the case above.
	code, _, stderr = exec(t, "-environment", envPath(), "-quiet",
		filepath.Join(samplesPath(), "spend-above-threshold.json"))
	if code != exitOK {
		t.Fatalf("the unbroken record was also refused (exit %d), so the refusal above is not attributable to the pin\n%s", code, stderr)
	}
}

// TestANonReproducingRecordExitsThree separates "the artifacts do not match"
// from "the artifacts match and the answer moved". The second is the one an
// evaluator regression looks like, and a tool that reported both as the same
// failure would send whoever is on call to the wrong place.
func TestANonReproducingRecordExitsThree(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(samplesPath(), "spend-above-threshold.json"))
	if err != nil {
		t.Fatalf("reading the sample: %v", err)
	}
	var rec map[string]any
	if err := json.Unmarshal(raw, &rec); err != nil {
		t.Fatalf("decoding the sample: %v", err)
	}
	expected, ok := rec["expected"].(map[string]any)
	if !ok {
		t.Fatalf("the sample records no expected decision to contradict")
	}
	expected["state"] = "ALLOW"
	expected["reason"] = "permitted"

	edited := filepath.Join(t.TempDir(), "wrong-expectation.json")
	out, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		t.Fatalf("re-encoding: %v", err)
	}
	if err := os.WriteFile(edited, out, 0o644); err != nil {
		t.Fatalf("writing: %v", err)
	}

	code, _, stderr := exec(t, "-environment", envPath(), "-quiet", edited)
	if code != exitMismatch {
		t.Fatalf("exit %d, want %d (expectation mismatch)\n%s", code, exitMismatch, stderr)
	}
	if !strings.Contains(stderr, "DIFFERS") {
		t.Errorf("the run does not report the difference:\n%s", stderr)
	}
	for _, field := range []string{"state:", "reason:"} {
		if !strings.Contains(stderr, field) {
			t.Errorf("the run does not name the %s field that moved:\n%s", field, stderr)
		}
	}
}

// TestARunOverNoRecordsIsNotASuccess pins the fail-closed argument handling.
//
// A mistyped directory, an empty glob or a forgotten argument all produce "no
// records", and a tool that exited 0 on that would let a CI step assert
// nothing and report a pass. This is the same class as every anti-vacuity
// floor in this repository.
func TestARunOverNoRecordsIsNotASuccess(t *testing.T) {
	code, _, stderr := exec(t, "-environment", envPath())
	if code == exitOK {
		t.Fatal("a run naming no records exited 0; a replay that verified nothing reads as a replay that verified")
	}
	if !strings.Contains(stderr, "verifies nothing") {
		t.Errorf("the refusal does not explain itself:\n%s", stderr)
	}

	empty := t.TempDir()
	code, _, stderr = exec(t, "-environment", envPath(), "-dir", empty)
	if code == exitOK {
		t.Fatal("a run over an empty directory exited 0")
	}
	if !strings.Contains(stderr, "holds no *.json records") {
		t.Errorf("the refusal does not name the empty directory:\n%s", stderr)
	}

	// And a missing environment, which is the other way to reach a vacuous run.
	if code, _, _ := exec(t, "-environment", filepath.Join(t.TempDir(), "absent.json"), "-dir", samplesPath()); code == exitOK {
		t.Error("a run against a nonexistent environment exited 0")
	}
}
