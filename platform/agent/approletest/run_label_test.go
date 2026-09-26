// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package approletest

import (
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

// TestRunLabelArgsFollowTheRunID pins what a container is labelled with for
// each state of AXONFLOW_TEST_RUN_ID (#4184): absent and empty add nothing,
// a well-formed id adds exactly the run label, and a malformed one is refused.
func TestRunLabelArgsFollowTheRunID(t *testing.T) {
	for _, c := range []struct {
		name, value string
		set         bool
		want        []string
		wantErr     bool
	}{
		{name: "absent", set: false},
		{name: "empty", value: "", set: true},
		{name: "well formed", value: "run-all-123-1790000000", set: true,
			want: []string{"--label", "axonflow.test.run=run-all-123-1790000000"}},
		{name: "longest accepted", value: strings.Repeat("a", 64), set: true,
			want: []string{"--label", "axonflow.test.run=" + strings.Repeat("a", 64)}},
		{name: "too long", value: strings.Repeat("a", 65), set: true, wantErr: true},
		{name: "a space", value: "run a", set: true, wantErr: true},
		{name: "a label separator", value: "run=a", set: true, wantErr: true},
	} {
		t.Run(c.name, func(t *testing.T) {
			if c.set {
				t.Setenv(TestRunIDEnv, c.value)
			} else {
				t.Setenv(TestRunIDEnv, "")
				if err := os.Unsetenv(TestRunIDEnv); err != nil {
					t.Fatal(err)
				}
			}
			got, err := runLabelArgs()
			if (err != nil) != c.wantErr {
				t.Fatalf("err = %v, want error %v", err, c.wantErr)
			}
			if !reflect.DeepEqual(got, c.want) {
				t.Fatalf("args = %q, want %q", got, c.want)
			}
		})
	}
}

// TestTheReaperNamesTheLabelsThisPackageSets pins the one fact the reaper and
// this package must share: the reaper script (a shell file, so it cannot import
// the constants) spells the run label key and the ephemeral label exactly as
// they are defined here, and run-all.sh exports the variable this package reads.
func TestTheReaperNamesTheLabelsThisPackageSets(t *testing.T) {
	root := filepath.Join("..", "..", "..")
	read := func(rel string) string {
		t.Helper()
		b, err := os.ReadFile(filepath.Join(root, rel)) //nolint:gosec // the repo's own files
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		return string(b)
	}
	// run-all.sh ships on both trees, so this half is asserted everywhere.
	if runAll := read("tests/regression-test-required/run-all.sh"); !strings.Contains(runAll, "\nexport "+TestRunIDEnv+"\n") {
		t.Errorf("tests/regression-test-required/run-all.sh does not export %s", TestRunIDEnv)
	}

	const reaperPath = "scripts/ci/reap-test-run-containers.sh"
	if _, err := os.Stat(filepath.Join(root, reaperPath)); os.IsNotExist(err) {
		if _, eeErr := os.Stat(filepath.Join(root, "ee")); eeErr == nil {
			t.Fatalf("%s is missing on an enterprise tree (ee/ exists); nothing reaps the containers this package labels", reaperPath)
		}
		// A community-mirror checkout: the sync strips the reaper, so there is
		// no script on this tree whose labels could disagree with these
		// constants. The run-all.sh half above IS asserted here, and the reaper
		// half is asserted on the enterprise tree. PASS rather than skip: a
		// skip would read as "the check did not run" on the mirror.
		t.Logf("%s is absent on a mirror checkout; its label spellings are asserted on the enterprise tree", reaperPath)
		return
	}
	reaper := read(reaperPath)
	for _, want := range []string{
		`RUN_LABEL_KEY="` + TestRunLabelKey + `"`,
		`EPHEMERAL_LABEL="` + TestContainerLabel + `"`,
		`OWNER_LABEL_KEY="` + TestOwnerLabelKey + `"`,
	} {
		if !strings.Contains(reaper, "\n"+want+" ") {
			t.Errorf("%s does not assign %s", reaperPath, want)
		}
	}
}

// TestDockerRunArgsLabelEveryContainerWithItsOwner pins what every docker-CLI
// test container is started with (#4184): the ephemeral label, the owner
// "<hostname>:<pid>" of this process, the run label only when a run id is set,
// and then the caller's arguments, in that order.
func TestDockerRunArgsLabelEveryContainerWithItsOwner(t *testing.T) {
	host, err := os.Hostname()
	if err != nil {
		t.Fatal(err)
	}
	owner := TestOwnerLabelKey + "=" + host + ":" + strconv.Itoa(os.Getpid())

	t.Setenv(TestRunIDEnv, "")
	got := DockerRunArgs(t, "--name", "c1", "postgres:15")
	want := []string{"run", "-d", "--label", TestContainerLabel, "--label", owner, "--name", "c1", "postgres:15"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("no run id: args = %q, want %q", got, want)
	}

	t.Setenv(TestRunIDEnv, "run-7")
	got = DockerRunArgs(t, "postgres:15")
	want = []string{"run", "-d", "--label", TestContainerLabel, "--label", owner, "--label", TestRunLabelKey + "=run-7", "postgres:15"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("with a run id: args = %q, want %q", got, want)
	}
}
