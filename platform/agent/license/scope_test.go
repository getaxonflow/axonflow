// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package license

import "testing"

// scope_test.go — ADR-050 §2/§3/§4 helpers. Pinned shape so we can't
// regress agent-side parsing of the X-Axonflow-Client header convention
// or the per-quadrant aud accept lists.

func TestDeriveScopeFromClientHeader(t *testing.T) {
	cases := []struct {
		name   string
		header string
		want   string
	}{
		{"absent → full", "", ScopeFull},
		{"openclaw plugin", "openclaw/2.1.0", ScopePlugin},
		{"claude-code-plugin", "claude-code-plugin/1.1.0", ScopePlugin},
		{"cursor-plugin", "cursor-plugin/1.1.0", ScopePlugin},
		{"codex-plugin", "codex-plugin/1.1.0", ScopePlugin},
		{"sdk-typescript", "sdk-typescript/7.0.0", ScopeSDK},
		{"sdk-python", "sdk-python/7.0.0", ScopeSDK},
		{"sdk-go", "sdk-go/7.0.0", ScopeSDK},
		{"sdk-java", "sdk-java/7.0.0", ScopeSDK},
		{"unknown id → full", "some-future-tool/1.0.0", ScopeFull},
		{"no version separator → still classified by prefix", "openclaw", ScopePlugin},
		{"empty client-id (only slash) → full", "/1.0.0", ScopeFull},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := DeriveScopeFromClientHeader(tc.header); got != tc.want {
				t.Errorf("DeriveScopeFromClientHeader(%q) = %q, want %q", tc.header, got, tc.want)
			}
		})
	}
}

func TestHasScope(t *testing.T) {
	cases := []struct {
		name      string
		aud       string
		queries   map[string]bool // scope -> expected HasScope result
	}{
		{
			name: "axonflow.saas.plugin",
			aud:  AudSaaSPlugin,
			queries: map[string]bool{
				ScopePlugin: true,
				ScopeSDK:    false,
				ScopeFull:   false,
			},
		},
		{
			name: "axonflow.saas.sdk",
			aud:  AudSaaSSDK,
			queries: map[string]bool{
				ScopePlugin: false,
				ScopeSDK:    true,
				ScopeFull:   false,
			},
		},
		{
			name: "axonflow.saas.full grants any scope",
			aud:  AudSaaSFull,
			queries: map[string]bool{
				ScopePlugin: true,
				ScopeSDK:    true,
				ScopeFull:   true,
			},
		},
		{
			name: "axonflow.self_hosted.full grants any scope",
			aud:  AudSelfHostedFull,
			queries: map[string]bool{
				ScopePlugin: true,
				ScopeSDK:    true,
				ScopeFull:   true,
			},
		},
		{
			name: "legacy community_saas_plugin → plugin scope",
			aud:  AudLegacyPluginClaim,
			queries: map[string]bool{
				ScopePlugin: true,
				ScopeSDK:    false,
				ScopeFull:   false,
			},
		},
		{
			name: "missing aud (legacy self-hosted) → full per ADR §8",
			aud:  "",
			queries: map[string]bool{
				ScopePlugin: true,
				ScopeSDK:    true,
				ScopeFull:   true,
			},
		},
		{
			name: "malformed aud fails closed",
			aud:  "garbage-value",
			queries: map[string]bool{
				ScopePlugin: false,
				ScopeSDK:    false,
				ScopeFull:   false,
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			payload := &ServiceLicensePayload{Aud: tc.aud}
			for query, want := range tc.queries {
				got := payload.HasScope(query)
				if got != want {
					t.Errorf("HasScope(%q) on aud=%q: got %t, want %t", query, tc.aud, got, want)
				}
			}
		})
	}
}

func TestHostingMode(t *testing.T) {
	cases := []struct {
		name string
		aud  string
		want string
	}{
		{"axonflow.saas.plugin", AudSaaSPlugin, HostingModeSaaS},
		{"axonflow.saas.full", AudSaaSFull, HostingModeSaaS},
		{"axonflow.self_hosted.full", AudSelfHostedFull, HostingModeSelfHosted},
		{"axonflow.self_hosted.plugin", AudSelfHostedPlugin, HostingModeSelfHosted},
		{"legacy community_saas_plugin → saas", AudLegacyPluginClaim, HostingModeSaaS},
		{"missing aud → self_hosted (ADR §8)", "", HostingModeSelfHosted},
		{"malformed → empty", "garbage", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			payload := &ServiceLicensePayload{Aud: tc.aud}
			if got := payload.HostingMode(); got != tc.want {
				t.Errorf("HostingMode on aud=%q: got %q, want %q", tc.aud, got, tc.want)
			}
		})
	}
}

func TestIsSaaSPluginPathAud(t *testing.T) {
	cases := []struct {
		aud  string
		want bool
	}{
		{AudSaaSPlugin, true},          // canonical
		{AudSaaSFull, true},            // full-scope SaaS
		{AudLegacyPluginClaim, true},   // backward-compat
		{AudSaaSSDK, false},            // wrong scope on this path
		{AudSelfHostedFull, false},     // wrong quadrant — must reject
		{AudSelfHostedPlugin, false},   // wrong quadrant
		{AudSelfHostedSDK, false},      // wrong quadrant
		{"", false},                    // missing aud — reject on this path
		{"garbage", false},             // unknown — reject
		{"axonflow.saas.http", false},  // future quadrant not yet enabled — fail closed
	}
	for _, tc := range cases {
		t.Run(tc.aud+"="+boolStr(tc.want), func(t *testing.T) {
			if got := IsSaaSPluginPathAud(tc.aud); got != tc.want {
				t.Errorf("IsSaaSPluginPathAud(%q) = %t, want %t", tc.aud, got, tc.want)
			}
		})
	}
}

func boolStr(b bool) string {
	if b {
		return "accept"
	}
	return "reject"
}
