// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package retiredenvtest

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeRun writes a Go file whose func Run holds body, and returns its path.
func writeRun(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "run.go")
	src := "package main\n\nfunc Run() {\n\t" + body + "\n}\n"
	if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// wantProblem fails t unless problems is empty (want == "") or is exactly one
// problem naming want.
func wantProblem(t *testing.T, problems []string, err error, want string) {
	t.Helper()
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	switch {
	case want == "" && len(problems) != 0:
		t.Fatalf("a boot path that holds was reported: %v", problems)
	case want != "" && (len(problems) != 1 || !strings.Contains(problems[0], want)):
		t.Fatalf("problems = %v; want exactly one naming %q", problems, want)
	}
}

// TestTheBootCheckSeesEachWayARefusalCanBeLost is the refusal check's control:
// each shape that lets a process start past a refusal is reported, and the
// shapes that cannot are not.
func TestTheBootCheckSeesEachWayARefusalCanBeLost(t *testing.T) {
	for _, c := range []struct{ name, body, want string }{
		{"refused, and the error ends the process", `if err := retiredenv.Refuse(); err != nil {
		log.Fatalf("%v", err)
	}`, ""},
		{"refused through os.Exit", `if err := retiredenv.Refuse(); err != nil {
		log.Printf("%v", err)
		os.Exit(1)
	}`, ""},
		{"never called", `start()`, "does not refuse on retiredenv.Refuse()"},
		{"called under a condition", `if strict {
		if err := retiredenv.Refuse(); err != nil {
			log.Fatalf("%v", err)
		}
	}`, "does not refuse on retiredenv.Refuse()"},
		{"logged and ignored", `if err := retiredenv.Refuse(); err != nil {
		log.Printf("%v", err)
	}`, "its error does not end the process"},
	} {
		t.Run(c.name, func(t *testing.T) {
			problems, err := BootRefusalProblems(writeRun(t, c.body), "Run", "retiredenv.Refuse")
			wantProblem(t, problems, err, c.want)
		})
	}
}

// TestTheLinkCheckSeesACallThatCanBeSkipped is the link check's control.
func TestTheLinkCheckSeesACallThatCanBeSkipped(t *testing.T) {
	for _, c := range []struct{ name, body, want string }{
		{"called as a statement of the body", `initializeComponents()`, ""},
		{"called under a condition", `if ready {
		initializeComponents()
	}`, "does not call initializeComponents()"},
		{"never called", `start()`, "does not call initializeComponents()"},
	} {
		t.Run(c.name, func(t *testing.T) {
			problems, err := UncalledAtTopLevel(writeRun(t, c.body), "Run", "initializeComponents")
			wantProblem(t, problems, err, c.want)
		})
	}
}
