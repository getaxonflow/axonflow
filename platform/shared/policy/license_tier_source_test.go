// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package policy

import (
	"bytes"
	"context"
	"log"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

// withTierSource registers src for the test and clears it afterwards. Every
// test that reads the licence axis goes through here so no test depends on
// what the previous one left registered.
func withTierSource(t *testing.T, src LicenseTierSource) {
	t.Helper()
	SetLicenseTierSource(src)
	t.Cleanup(func() { SetLicenseTierSource(nil) })
}

// fixedTier is a source that answers one string, for varying the licence axis
// independently of the mode. It stands in for the VERIFIED read only in the
// sense that this package never sees a key: what the answer means - that a
// signature and an expiry were checked - is pinned where the real source is
// registered, in platform/agent/license_tier_source_test.go.
func fixedTier(tier string) LicenseTierSource {
	return func(context.Context) string { return tier }
}

// TestNoRegisteredSourceFailsClosedAndSaysSo is the default's own assertion,
// beside the forged-key and expired-key ones: unregistered resolver ->
// community AND the line is emitted AND the counter moves. A fail-closed
// default that is silent is the silent-truncation hazard under a safer name.
func TestNoRegisteredSourceFailsClosedAndSaysSo(t *testing.T) {
	withTierSource(t, nil)
	t.Setenv("DEPLOYMENT_MODE", "community")

	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(prev) })

	before := testutil.ToFloat64(licenseTierSourceUnregistered)

	for i := 0; i < 3; i++ {
		if got := resolveConnectorLimitTier(); got != "community" {
			t.Fatalf("call %d: resolveConnectorLimitTier() with no source = %q, want community", i, got)
		}
	}

	if delta := testutil.ToFloat64(licenseTierSourceUnregistered) - before; delta != 3 {
		t.Errorf("axonflow_license_tier_source_unregistered_total moved by %v over 3 resolutions, want 3", delta)
	}
	out := buf.String()
	if n := strings.Count(out, "no verified licence tier source is registered"); n != 1 {
		t.Fatalf("three unregistered resolutions produced %d log lines, want exactly 1 (once per registration state):\n%s", n, out)
	}
	if !strings.Contains(out, "COMMUNITY") || !strings.Contains(out, "SetLicenseTierSource") {
		t.Errorf("the log line does not say what tier applies and how to register a source:\n%s", out)
	}

	// Registering a source re-arms the line, so a later de-registration is
	// reported again rather than swallowed by the first one.
	withTierSource(t, fixedTier("Enterprise"))
	if got := resolveConnectorLimitTier(); got != "enterprise" {
		t.Fatalf("with a source registered: %q, want enterprise", got)
	}
	SetLicenseTierSource(nil)
	buf.Reset()
	resolveConnectorLimitTier()
	if !strings.Contains(buf.String(), "no verified licence tier source is registered") {
		t.Errorf("after re-registration and clearing, the unregistered line was not emitted again")
	}
}

// TestTheSourceDecidesTheLicenceAxis pins what this package does with the
// answer: lower-case it, treat "" as community, and never consult it for an
// Enterprise-entitled mode.
func TestTheSourceDecidesTheLicenceAxis(t *testing.T) {
	cases := []struct {
		name   string
		mode   string
		source string
		want   string
	}{
		{"enterprise licence in community mode", "community", "Enterprise", "enterprise"},
		{"evaluation licence in community mode", "community", "Evaluation", "evaluation"},
		{"tier is lower-cased", "community", "PLUS", "plus"},
		{"tier is trimmed", "community", "  Professional ", "professional"},
		{"a source that grants nothing is community", "community", "", "community"},
		{"a source answering Community is community", "community", "Community", "community"},
		{"community-saas reaches the source", "community-saas", "Evaluation", "evaluation"},
		{"evaluation mode reaches the source", "evaluation", "Evaluation", "evaluation"},
		{"an unrecognised mode reaches the source and gets what it grants", "comunity", "Evaluation", "evaluation"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			withTierSource(t, fixedTier(tc.source))
			t.Setenv("DEPLOYMENT_MODE", tc.mode)
			if got := resolveConnectorLimitTier(); got != tc.want {
				t.Errorf("mode=%q source=%q: resolveConnectorLimitTier() = %q, want %q", tc.mode, tc.source, got, tc.want)
			}
		})
	}

	t.Run("an Enterprise-entitled mode never asks the source", func(t *testing.T) {
		called := false
		withTierSource(t, func(context.Context) string { called = true; return "Evaluation" })
		t.Setenv("DEPLOYMENT_MODE", "saas")
		if got := resolveConnectorLimitTier(); got != "enterprise" {
			t.Fatalf("DEPLOYMENT_MODE=saas resolved to %q, want enterprise", got)
		}
		if called {
			t.Error("the licence source was consulted for a mode that is entitled on its own; a junk key must not be able to demote a paying deployment")
		}
	})
}

// TestThePackageNoLongerParsesALicenceKey: the environment variable is
// irrelevant to this package now. A payload naming Enterprise, unsigned, sits
// in AXONFLOW_LICENSE_KEY and the answer is whatever the SOURCE says - here,
// nothing. This is the row-1 reproduction turned into a guard: if a parser of
// the key ever returns to this package, this test is what reds.
func TestThePackageNoLongerParsesALicenceKey(t *testing.T) {
	withTierSource(t, fixedTier(""))
	forged := "AXON-eyJ0aWVyIjoiRW50ZXJwcmlzZSJ9.Tk9UQVNJRyE" // {"tier":"Enterprise"} . NOTASIG!
	t.Setenv("DEPLOYMENT_MODE", "community")
	t.Setenv("AXONFLOW_LICENSE_KEY", forged)

	if got := resolveConnectorLimitTier(); got != "community" {
		t.Fatalf("an unsigned payload naming Enterprise in AXONFLOW_LICENSE_KEY resolved to %q with a source "+
			"that grants nothing; something in this package is reading the key again", got)
	}

	config := DefaultDynamicPolicyConfig()
	config.EnabledConnectors = []string{"a", "b", "c", "d", "e", "f"}
	if kept := EnforceCustomPolicyConnectorLimit(config); len(kept) != config.MaxCustomPolicyConnectorsCommunity {
		t.Fatalf("the forged key kept %d of %d connectors, want the community ceiling %d",
			len(kept), len(config.EnabledConnectors), config.MaxCustomPolicyConnectorsCommunity)
	}
}
