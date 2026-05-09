// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package envcompat

import (
	"bytes"
	"log"
	"strings"
	"testing"
)

// withCapturedLog redirects the standard logger's output to an in-memory
// buffer for the duration of fn, restoring the original output afterward.
// Returns the captured log bytes.
func withCapturedLog(t *testing.T, fn func()) string {
	t.Helper()
	orig := log.Writer()
	defer log.SetOutput(orig)
	var buf bytes.Buffer
	log.SetOutput(&buf)
	fn()
	return buf.String()
}

func TestLookup_PrimarySet(t *testing.T) {
	resetWarnedPairsForTest()
	t.Setenv("ENVCOMPAT_PRIMARY", "primary-value")
	t.Setenv("ENVCOMPAT_DEPRECATED", "")

	out := withCapturedLog(t, func() {
		value, source, ok := Lookup("ENVCOMPAT_PRIMARY", "ENVCOMPAT_DEPRECATED")
		if !ok {
			t.Fatalf("expected ok=true")
		}
		if value != "primary-value" {
			t.Errorf("expected primary-value, got %q", value)
		}
		if source != "primary" {
			t.Errorf("expected source=primary, got %q", source)
		}
	})

	if strings.Contains(out, "deprecated") {
		t.Errorf("primary path must not log deprecation warning; got: %s", out)
	}
}

func TestLookup_DeprecatedSet_LogsOnce(t *testing.T) {
	resetWarnedPairsForTest()
	t.Setenv("ENVCOMPAT_PRIMARY", "")
	t.Setenv("ENVCOMPAT_DEPRECATED", "deprecated-value")

	out := withCapturedLog(t, func() {
		// Lookup three times — warning should fire exactly once
		for i := 0; i < 3; i++ {
			value, source, ok := Lookup("ENVCOMPAT_PRIMARY", "ENVCOMPAT_DEPRECATED")
			if !ok || value != "deprecated-value" || source != "deprecated" {
				t.Fatalf("call %d: unexpected result value=%q source=%q ok=%v", i, value, source, ok)
			}
		}
	})

	count := strings.Count(out, "ENVCOMPAT_DEPRECATED is deprecated")
	if count != 1 {
		t.Errorf("expected exactly 1 deprecation warning across 3 calls, got %d. Log:\n%s", count, out)
	}
}

func TestLookup_BothSet_PrimaryWins(t *testing.T) {
	resetWarnedPairsForTest()
	t.Setenv("ENVCOMPAT_PRIMARY", "primary-wins")
	t.Setenv("ENVCOMPAT_DEPRECATED", "deprecated-loses")

	out := withCapturedLog(t, func() {
		value, source, ok := Lookup("ENVCOMPAT_PRIMARY", "ENVCOMPAT_DEPRECATED")
		if !ok {
			t.Fatalf("expected ok=true")
		}
		if value != "primary-wins" {
			t.Errorf("expected primary to win, got %q", value)
		}
		if source != "primary" {
			t.Errorf("expected source=primary, got %q", source)
		}
	})

	if strings.Contains(out, "deprecated") {
		t.Errorf("primary-wins path must not log deprecation; got: %s", out)
	}
}

func TestLookup_NeitherSet(t *testing.T) {
	resetWarnedPairsForTest()
	t.Setenv("ENVCOMPAT_PRIMARY", "")
	t.Setenv("ENVCOMPAT_DEPRECATED", "")

	out := withCapturedLog(t, func() {
		value, source, ok := Lookup("ENVCOMPAT_PRIMARY", "ENVCOMPAT_DEPRECATED")
		if ok {
			t.Errorf("expected ok=false, got true")
		}
		if value != "" || source != "" {
			t.Errorf("expected empty value/source, got value=%q source=%q", value, source)
		}
	})

	if out != "" {
		t.Errorf("expected no log output, got: %s", out)
	}
}

func TestGet_Convenience(t *testing.T) {
	resetWarnedPairsForTest()
	t.Setenv("ENVCOMPAT_PRIMARY", "via-get")
	t.Setenv("ENVCOMPAT_DEPRECATED", "")

	if got := Get("ENVCOMPAT_PRIMARY", "ENVCOMPAT_DEPRECATED"); got != "via-get" {
		t.Errorf("Get returned %q, expected via-get", got)
	}

	t.Setenv("ENVCOMPAT_PRIMARY", "")
	t.Setenv("ENVCOMPAT_DEPRECATED", "deprecated-via-get")
	resetWarnedPairsForTest() // allow second pair's warning to fire in this run
	if got := Get("ENVCOMPAT_PRIMARY", "ENVCOMPAT_DEPRECATED"); got != "deprecated-via-get" {
		t.Errorf("Get returned %q, expected deprecated-via-get", got)
	}

	t.Setenv("ENVCOMPAT_PRIMARY", "")
	t.Setenv("ENVCOMPAT_DEPRECATED", "")
	if got := Get("ENVCOMPAT_PRIMARY", "ENVCOMPAT_DEPRECATED"); got != "" {
		t.Errorf("Get returned %q, expected empty string when neither is set", got)
	}
}

func TestLookup_MultiplePairs_IndependentWarnings(t *testing.T) {
	// Verify that the once-per-pair warning is keyed correctly: two
	// different (primary, deprecated) pairs each log their own warning,
	// even though both fire from the same source-position.
	resetWarnedPairsForTest()

	t.Setenv("ENVCOMPAT_PRIMARY_A", "")
	t.Setenv("ENVCOMPAT_DEPRECATED_A", "value-a")
	t.Setenv("ENVCOMPAT_PRIMARY_B", "")
	t.Setenv("ENVCOMPAT_DEPRECATED_B", "value-b")

	out := withCapturedLog(t, func() {
		_, _, _ = Lookup("ENVCOMPAT_PRIMARY_A", "ENVCOMPAT_DEPRECATED_A")
		_, _, _ = Lookup("ENVCOMPAT_PRIMARY_B", "ENVCOMPAT_DEPRECATED_B")
		// Repeat both — should not log again
		_, _, _ = Lookup("ENVCOMPAT_PRIMARY_A", "ENVCOMPAT_DEPRECATED_A")
		_, _, _ = Lookup("ENVCOMPAT_PRIMARY_B", "ENVCOMPAT_DEPRECATED_B")
	})

	if c := strings.Count(out, "ENVCOMPAT_DEPRECATED_A is deprecated"); c != 1 {
		t.Errorf("expected pair-A warning exactly once, got %d", c)
	}
	if c := strings.Count(out, "ENVCOMPAT_DEPRECATED_B is deprecated"); c != 1 {
		t.Errorf("expected pair-B warning exactly once, got %d", c)
	}
}
