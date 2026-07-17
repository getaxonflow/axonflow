// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

// Unit tests for the identity-header trust gate (#2896). The per-plane
// attribution / verdict-invariance / forged-header proofs live in
// identity_attribution_planes_test.go; this file pins the helper contract:
// parse semantics, sanitization, fallbacks, and the detection warning.

import (
	"bytes"
	"log"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	sharedidentity "axonflow/platform/shared/identity"
)

// resetIdentityWarnLatches clears the once-per-process warning latches so a
// test can assert emission deterministically regardless of test order, and
// restores them after the test (the latch state is process-global).
func resetIdentityWarnLatches(t *testing.T) {
	t.Helper()
	prevUnrecognized := unrecognizedTrustValueWarned.Load()
	prevUntrusted := untrustedIdentityWarned.Load()
	unrecognizedTrustValueWarned.Store(false)
	untrustedIdentityWarned.Store(false)
	t.Cleanup(func() {
		unrecognizedTrustValueWarned.Store(prevUnrecognized)
		untrustedIdentityWarned.Store(prevUntrusted)
	})
}

// captureLog redirects the standard logger into a buffer for the duration of
// the test so warning emission can be asserted.
func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(prev) })
	return &buf
}

func TestTrustIdentityHeaders_GateSemantics(t *testing.T) {
	tests := []struct {
		value string
		want  bool
	}{
		{"", false},      // unset — the secure default
		{"false", false}, // explicit off
		{"true", true},   // the ONLY opt-in
		{"TRUE", false},  // unrecognized → off
		{"1", false},     // unrecognized → off
		{"yes", false},   // unrecognized → off
	}
	for _, tc := range tests {
		t.Run("value="+tc.value, func(t *testing.T) {
			resetIdentityWarnLatches(t)
			t.Setenv(sharedidentity.EnvVar, tc.value)
			if got := trustIdentityHeaders(); got != tc.want {
				t.Errorf("trustIdentityHeaders() with %s=%q = %v, want %v",
					sharedidentity.EnvVar, tc.value, got, tc.want)
			}
		})
	}
}

// TestTrustIdentityHeaders_UnrecognizedValueWarnsOnce: a "TRUE"/"1" typo must
// not silently downgrade the operator's intent — it logs, exactly once per
// process, and stays untrusted.
func TestTrustIdentityHeaders_UnrecognizedValueWarnsOnce(t *testing.T) {
	resetIdentityWarnLatches(t)
	t.Setenv(sharedidentity.EnvVar, "TRUE")
	buf := captureLog(t)

	if trustIdentityHeaders() {
		t.Fatal("unrecognized value must be untrusted")
	}
	first := buf.String()
	if !strings.Contains(first, sharedidentity.EnvVar) || !strings.Contains(first, "TRUE") {
		t.Errorf("expected a warning naming the env var and the bad value, got: %q", first)
	}

	buf.Reset()
	_ = trustIdentityHeaders()
	if second := buf.String(); strings.Contains(second, sharedidentity.EnvVar) {
		t.Errorf("warning must fire once per process, got a second emission: %q", second)
	}
}

func TestTrustedIdentityHeader_GateOff_DropsValueAndWarns(t *testing.T) {
	resetIdentityWarnLatches(t)
	t.Setenv(sharedidentity.EnvVar, "false")
	buf := captureLog(t)

	r := httptest.NewRequest("POST", "/", nil)
	r.Header.Set(identityHeaderUserEmail, "forged@victim.example")

	if got := trustedIdentityHeader(r, identityHeaderUserEmail, maxAttributedEmailLen); got != "" {
		t.Fatalf("gate off: header value must be dropped, got %q", got)
	}

	// The detection warning (brief §3.3): actionable — names the header, the
	// gate, and the fallback — so an operator never silently loses attribution.
	warning := buf.String()
	for _, want := range []string{identityHeaderUserEmail, sharedidentity.EnvVar, "validated"} {
		if !strings.Contains(warning, want) {
			t.Errorf("detection warning missing %q; got: %q", want, warning)
		}
	}

	// Once per process: a second governed request does not re-log.
	buf.Reset()
	_ = trustedIdentityHeader(r, identityHeaderUserEmail, maxAttributedEmailLen)
	if second := buf.String(); strings.Contains(second, sharedidentity.EnvVar) {
		t.Errorf("detection warning must be once-per-process, got second emission: %q", second)
	}
}

func TestTrustedIdentityHeader_GateOn_ReturnsSanitizedValue(t *testing.T) {
	resetIdentityWarnLatches(t)
	t.Setenv(sharedidentity.EnvVar, "true")

	t.Run("clean value passes", func(t *testing.T) {
		r := httptest.NewRequest("POST", "/", nil)
		r.Header.Set(identityHeaderUserEmail, "leader@corp.example")
		if got := trustedIdentityHeader(r, identityHeaderUserEmail, maxAttributedEmailLen); got != "leader@corp.example" {
			t.Errorf("got %q, want leader@corp.example", got)
		}
	})

	t.Run("control characters stripped", func(t *testing.T) {
		r := httptest.NewRequest("POST", "/", nil)
		r.Header.Set(identityHeaderUserEmail, "evil\x01@corp\x7f.example")
		if got := trustedIdentityHeader(r, identityHeaderUserEmail, maxAttributedEmailLen); got != "evil@corp.example" {
			t.Errorf("got %q, want control chars stripped", got)
		}
	})

	t.Run("oversized value capped", func(t *testing.T) {
		r := httptest.NewRequest("POST", "/", nil)
		r.Header.Set(identityHeaderUserEmail, strings.Repeat("a", 5000)+"@x.example")
		got := trustedIdentityHeader(r, identityHeaderUserEmail, maxAttributedEmailLen)
		if len(got) > maxAttributedEmailLen {
			t.Errorf("value not capped: len=%d > %d", len(got), maxAttributedEmailLen)
		}
	})

	t.Run("absent header → empty, no warning", func(t *testing.T) {
		buf := captureLog(t)
		r := httptest.NewRequest("POST", "/", nil)
		if got := trustedIdentityHeader(r, identityHeaderUserEmail, maxAttributedEmailLen); got != "" {
			t.Errorf("absent header must resolve empty, got %q", got)
		}
		if s := buf.String(); strings.Contains(s, sharedidentity.EnvVar) {
			t.Errorf("absent header must not warn, got: %q", s)
		}
	})
}

// TestAttributedUserEmail_FailSafeFallbacks: absent / untrusted / garbage
// headers all fall back to the VALIDATED identity — never to an empty or
// attacker-controlled value (brief DoD "Fail-safe").
func TestAttributedUserEmail_FailSafeFallbacks(t *testing.T) {
	const validated = "service@axonflow.local"

	t.Run("gate off + forged header → validated", func(t *testing.T) {
		resetIdentityWarnLatches(t)
		t.Setenv(sharedidentity.EnvVar, "false")
		r := httptest.NewRequest("POST", "/", nil)
		r.Header.Set(identityHeaderUserEmail, "forged@victim.example")
		if got := attributedUserEmail(r, validated); got != validated {
			t.Errorf("got %q, want validated fallback %q", got, validated)
		}
	})

	t.Run("gate on + absent header → validated", func(t *testing.T) {
		resetIdentityWarnLatches(t)
		t.Setenv(sharedidentity.EnvVar, "true")
		r := httptest.NewRequest("POST", "/", nil)
		if got := attributedUserEmail(r, validated); got != validated {
			t.Errorf("got %q, want validated fallback %q", got, validated)
		}
	})

	t.Run("gate on + whitespace-only header → validated", func(t *testing.T) {
		resetIdentityWarnLatches(t)
		t.Setenv(sharedidentity.EnvVar, "true")
		r := httptest.NewRequest("POST", "/", nil)
		r.Header.Set(identityHeaderUserEmail, "   ")
		if got := attributedUserEmail(r, validated); got != validated {
			t.Errorf("got %q, want validated fallback %q", got, validated)
		}
	})

	t.Run("gate on + all-control-chars header → validated (sanitizes to empty)", func(t *testing.T) {
		resetIdentityWarnLatches(t)
		t.Setenv(sharedidentity.EnvVar, "true")
		r := httptest.NewRequest("POST", "/", nil)
		r.Header.Set(identityHeaderUserEmail, "\x01\x02\x03")
		if got := attributedUserEmail(r, validated); got != validated {
			t.Errorf("got %q, want validated fallback %q", got, validated)
		}
	})

	t.Run("gate on + header → header wins the attribution slot", func(t *testing.T) {
		resetIdentityWarnLatches(t)
		t.Setenv(sharedidentity.EnvVar, "true")
		r := httptest.NewRequest("POST", "/", nil)
		r.Header.Set(identityHeaderUserEmail, "leader@corp.example")
		if got := attributedUserEmail(r, validated); got != "leader@corp.example" {
			t.Errorf("got %q, want header value", got)
		}
	})
}

func TestAttributedSessionID_GateSemantics(t *testing.T) {
	t.Run("gate off → dropped", func(t *testing.T) {
		resetIdentityWarnLatches(t)
		t.Setenv(sharedidentity.EnvVar, "false")
		r := httptest.NewRequest("POST", "/", nil)
		r.Header.Set(identityHeaderSessionID, "sess-1234")
		if got := attributedSessionID(r); got != "" {
			t.Errorf("gate off: session id must be dropped, got %q", got)
		}
	})
	t.Run("gate on → honored", func(t *testing.T) {
		resetIdentityWarnLatches(t)
		t.Setenv(sharedidentity.EnvVar, "true")
		r := httptest.NewRequest("POST", "/", nil)
		r.Header.Set(identityHeaderSessionID, "sess-1234")
		if got := attributedSessionID(r); got != "sess-1234" {
			t.Errorf("gate on: got %q, want sess-1234", got)
		}
	})
}

// TestIdentityTrustGate_EnvVarNameIsTheSharedContract guards against the gate
// name drifting from the gateway adapters' knob — they are ONE deployment
// contract (set both, same value).
func TestIdentityTrustGate_EnvVarNameIsTheSharedContract(t *testing.T) {
	if sharedidentity.EnvVar != "AXONFLOW_TRUST_IDENTITY_HEADERS" {
		t.Fatalf("trust gate env var renamed to %q — this breaks the documented deployment contract shared with the gateway adapters", sharedidentity.EnvVar)
	}
	// Belt-and-suspenders: the adapters read the same var (compile-time import
	// isn't possible from here; assert the source still references it).
	src, err := os.ReadFile("../../ee/platform/agent/gateway_adapters/config.go")
	if err != nil {
		t.Skipf("ee tree not present in this build context: %v", err)
	}
	if !bytes.Contains(src, []byte("sharedidentity.FromEnv()")) {
		t.Error("gateway_adapters/config.go no longer reads the shared identity trust gate — parse semantics may drift (#2896)")
	}
}

// TestIsClientSharedPseudoIdentity_DelegatesToSharedCensus pins the #2938
// anti-drift property: the agent trust plane keys on the ONE shared census
// (sharedidentity.IsSharedSyntheticIdentity) rather than a local copy. The
// sixth string is a spelling the original five-entry enumeration never
// listed — it is flagged purely by the shared census rules, so its refusal
// here proves a census addition propagates to this plane with no agent-side
// edit. The orchestrator-side twin is
// TestResolveCallerReadScope_SharedSyntheticCensusFailsClosed.
func TestIsClientSharedPseudoIdentity_DelegatesToSharedCensus(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "enterprise")
	shared := []string{
		"mcp-client:acme-org",                   // token-less MCP pseudo
		"acme-org@axonflow.local",               // enterprise no-token fallback
		"unknown@axonflow.local",                // audit-writer fallback
		"orchestrator@axonflow.internal",        // internal-service ResolveUser
		"system@axonflow.internal",              // HITL auto-approve reviewer (#2938 R3)
		"evaluator@try.getaxonflow.com",         // community-saas ResolveUser
		"local-dev@axonflow.local",              // community synthetic outside community = spoof
		"sixth-new-census-entry@axonflow.local", // census rules, not a copied list
		"future-service@axonflow.internal",      // new internal synthetic, covered by suffix
		"MCP-CLIENT:ACME-ORG",                   // case evasion — canonicalized first
	}
	for _, s := range shared {
		if !sharedidentity.IsSharedSyntheticIdentity(s, false) {
			t.Errorf("shared census must flag %q", s)
		}
		if !isClientSharedPseudoIdentity(s) {
			t.Errorf("agent predicate must refuse %q — delegation to the shared census is broken", s)
		}
	}
	// A real person is never census-flagged on this plane either.
	for _, legit := range []string{"dev@acme.com", "ops@corp.local", "x@notaxonflow.local"} {
		if isClientSharedPseudoIdentity(legit) {
			t.Errorf("agent predicate must not flag the legitimate identity %q", legit)
		}
	}
}

// TestIsClientSharedPseudoIdentity_CommunityLocalDevExempt pins the one
// mode-dependent census arm: in community mode local-dev@axonflow.local IS
// the (single) local developer and may hold per-user state; in any other
// mode the same spelling is a spoof of the community synthetic.
func TestIsClientSharedPseudoIdentity_CommunityLocalDevExempt(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "community")
	if isClientSharedPseudoIdentity("local-dev@axonflow.local") {
		t.Error("community mode: local-dev is a real single user, must not be census-flagged")
	}
	t.Setenv("DEPLOYMENT_MODE", "enterprise")
	if !isClientSharedPseudoIdentity("local-dev@axonflow.local") {
		t.Error("enterprise mode: an asserted local-dev is a spoofed community synthetic, must be census-flagged")
	}
}
