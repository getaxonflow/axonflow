// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

// Subprocess integration test for RequirePlatformAdminOrFatal.
//
// The unit tests in require_platform_admin_test.go swap fatalfFn so the
// decision logic + message formatting can be observed without terminating
// the test process. This test exercises the REAL log.Fatalf path: a child
// go-test process re-exec'd with a crasher env var calls the guard, and
// the parent asserts the child exited non-zero with the expected stderr.
//
// Coverage rationale: if a future change swaps the default fatalfFn to
// log.Printf (or any non-Fatal) the override-pattern test still passes
// but the production binary boots silently — the exact silent-fallback
// regression we exist to prevent. This subprocess test catches that.

import (
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// TestRequirePlatformAdminOrFatal_RealFatalExitsProcess is the subprocess
// half of the mutation gate. It re-execs the test binary in "crasher mode"
// with USE_APP_ROLE=true + PLATFORM_ADMIN_URL unset. The crasher calls
// RequirePlatformAdminOrFatal — production behavior is os.Exit(1) via
// log.Fatalf. Parent asserts non-zero exit + recognizable FATAL message.
func TestRequirePlatformAdminOrFatal_RealFatalExitsProcess(t *testing.T) {
	if os.Getenv("AXONFLOW_TEST_REQUIRE_PLATFORM_ADMIN_CRASHER") == "1" {
		// Child-process branch: simulate the boot-time state the guard is
		// designed to catch, then invoke the guard. log.Fatalf inside the
		// guard calls os.Exit(1).
		os.Setenv(EnvUseAppRole, "true")
		os.Unsetenv(EnvPlatformAdminURL)
		RequirePlatformAdminOrFatal("Marketplace")
		// If we reach here the guard is broken — no FATAL fired.
		os.Exit(0)
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestRequirePlatformAdminOrFatal_RealFatalExitsProcess", "-test.v")
	cmd.Env = append(os.Environ(),
		"AXONFLOW_TEST_REQUIRE_PLATFORM_ADMIN_CRASHER=1",
		// Drop USE_APP_ROLE inheritance from the parent's t.Setenv calls.
		// The child sets it explicitly above so its boot state is
		// independent of parent test ordering.
		EnvUseAppRole+"=true",
	)

	output, runErr := cmd.CombinedOutput()
	out := string(output)

	// Production behavior: log.Fatalf → os.Exit(1). exec.Cmd reports
	// non-zero exits as *exec.ExitError.
	var exitErr *exec.ExitError
	if !errors.As(runErr, &exitErr) {
		t.Fatalf("child process did not exit with a non-zero status (refuse-to-boot guard did not fire). err=%v\noutput:\n%s", runErr, out)
	}
	if exitErr.ExitCode() == 0 {
		t.Fatalf("child process exit code was 0 (refuse-to-boot guard did not fire). output:\n%s", out)
	}

	if !strings.Contains(out, "[Marketplace] FATAL:") {
		t.Errorf("child stderr did not contain '[Marketplace] FATAL:' prefix. output:\n%s", out)
	}
	if !strings.Contains(out, EnvPlatformAdminURL) {
		t.Errorf("child stderr did not name the missing env var %s. output:\n%s", EnvPlatformAdminURL, out)
	}
	if !strings.Contains(out, EnvUseAppRole+"=true") {
		t.Errorf("child stderr did not name the gate env var %s=true. output:\n%s", EnvUseAppRole, out)
	}
}
