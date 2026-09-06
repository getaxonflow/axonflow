// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

// Command decision-replay reproduces recorded decisions offline, from
// normalized input against pinned bundles, with nothing running.
//
// It is ADR-065 acceptance gate 16's artifact and the incident tool that goes
// with it: given a decision someone disputes, reproduce it on a laptop from
// the record and the environment it was taken against, and see the same
// operational state and the same safe reason code.
//
// Usage:
//
//	decision-replay -environment ENV.json RECORD.json [RECORD.json ...]
//	decision-replay -environment ENV.json -dir samples/
//
// Exit codes are distinct because the three failures need different responses:
//
//	0  every record replayed, and every record carrying an expectation
//	   reproduced it
//	1  the arguments, the files or the artifacts themselves are unusable
//	2  a record does not match the environment it was replayed against; no
//	   decision was produced
//	3  a record replayed and did NOT reproduce its recorded decision
//
// Code 3 is the interesting one. It means the artifacts agree, the input
// agrees, and the answer moved - which is either a real evaluator regression
// or a record from a build this one is not.
//
// EDITION. This tool lives in the decision module, which is community-licensed
// and mirrors to the public repository, and it imports nothing outside that
// module: replay, pdp and contract. Placing it in the platform module instead
// would make an OFFLINE incident tool link the cloud provider SDKs, database
// drivers and connector stack of axonflow/platform, which is the opposite of
// what "reproduce it without the stack" means.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"axonflow/platform/decision/replay"
)

const (
	exitOK       = 0
	exitUsage    = 1
	exitPin      = 2
	exitMismatch = 3
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// say writes a line to a stream and DISCARDS the error, deliberately and in
// one place.
//
// The alternative is fifteen `_, _ =` prefixes, and neither the operator's
// console nor the exit code has anywhere to go if a write to it fails: a tool
// that exited non-zero because stderr was closed would report a replay
// failure for a replay that succeeded. The exit codes this command promises
// are about the replay, and this keeps them that way.
func say(w io.Writer, format string, args ...any) {
	_, _ = fmt.Fprintf(w, format, args...)
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("decision-replay", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		envPath = fs.String("environment", "", "path to the pinned environment artifact (required)")
		dir     = fs.String("dir", "", "replay every *.json record in this directory")
		quiet   = fs.Bool("quiet", false, "print only the verdict line per record, not the decision")
	)
	fs.Usage = func() {
		say(stderr, "usage: decision-replay -environment ENV.json [-dir DIR] [RECORD.json ...]\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return exitUsage
	}
	if *envPath == "" {
		fs.Usage()
		return exitUsage
	}

	paths := append([]string(nil), fs.Args()...)
	if *dir != "" {
		found, err := recordsIn(*dir)
		if err != nil {
			say(stderr, "decision-replay: %v\n", err)
			return exitUsage
		}
		paths = append(paths, found...)
	}
	if len(paths) == 0 {
		// A run over nothing must not report success. "No records" is the
		// shape a mistyped path takes, and a green exit on it is how a replay
		// that verified nothing gets read as a replay that verified.
		say(stderr, "decision-replay: no records named; a run over zero records verifies nothing\n")
		return exitUsage
	}
	sort.Strings(paths)

	env, err := replay.LoadEnvironment(*envPath)
	if err != nil {
		say(stderr, "decision-replay: %v\n", err)
		return exitUsage
	}
	digest, err := env.Digest()
	if err != nil {
		say(stderr, "decision-replay: %v\n", err)
		return exitUsage
	}
	say(stderr, "environment %s\n", digest)
	for _, p := range env.BundleDigests() {
		say(stderr, "  bundle %-14s %s\n", p.Root, p.Digest)
	}

	worst := exitOK
	for _, path := range paths {
		code := replayOne(context.Background(), env, path, stdout, stderr, *quiet)
		if code > worst {
			worst = code
		}
	}
	return worst
}

func replayOne(ctx context.Context, env *replay.Environment, path string, stdout, stderr io.Writer, quiet bool) int {
	rec, err := replay.LoadRecord(path)
	if err != nil {
		say(stderr, "REFUSED  %s\n  %v\n", path, err)
		return exitUsage
	}
	res, err := replay.Replay(ctx, env, rec)
	if err != nil {
		var pinErr *replay.PinError
		if errors.As(err, &pinErr) {
			say(stderr, "REFUSED  %s\n%s\n", rec.CaseID, indent(err.Error()))
			return exitPin
		}
		say(stderr, "ERROR    %s\n%s\n", rec.CaseID, indent(err.Error()))
		return exitUsage
	}

	var verdict string
	code := exitOK
	switch {
	case rec.Expected == nil:
		verdict = "EMITTED "
	case res.Verified:
		verdict = "VERIFIED"
	default:
		verdict = "DIFFERS "
		code = exitMismatch
	}
	say(stderr, "%s %s  %s/%s  %s\n",
		verdict, rec.CaseID, res.Decision.State, res.Decision.Reason, res.Decision.DecisionID)
	for _, d := range res.Differences {
		say(stderr, "  %s\n", d)
	}
	if !quiet {
		raw, err := json.MarshalIndent(res.Decision, "", "  ")
		if err != nil {
			say(stderr, "  the decision could not be encoded: %v\n", err)
			return exitUsage
		}
		say(stdout, "%s\n", raw)
	}
	return code
}

func recordsIn(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", dir, err)
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		out = append(out, filepath.Join(dir, e.Name()))
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%s holds no *.json records", dir)
	}
	return out, nil
}

func indent(s string) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	for i, l := range lines {
		lines[i] = "  " + l
	}
	return strings.Join(lines, "\n")
}
