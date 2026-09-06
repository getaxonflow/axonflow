// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package llm

import "testing"

// TestCommunitySaasBootstrapsOllamaOnly is the test the community-SaaS guard in
// BootstrapFromEnv never had.
//
// #3713 replaced `os.Getenv("DEPLOYMENT_MODE") == "community-saas"` at
// bootstrap.go with deploymode.CurrentIsCommunitySaasPosture(). The
// substitution is expression-identical, but R3 measured that swapping it for
// the COMMUNITY posture predicate - a one-word mutant, and the exact confusion
// the two predicates exist to keep apart - left `go test ./orchestrator/llm/`
// green. Nothing in the repository exercised the guard, so "the package's tests
// pass" was not evidence about that line, and would not have been evidence
// about the pre-existing line either.
//
// The two subtests below fail in OPPOSITE directions under that mutant, which
// is what makes them a kill rather than a coincidence:
//
//	DEPLOYMENT_MODE=community-saas -> the real guard skips the paid provider;
//	                                  the mutant does not, and anthropic is
//	                                  registered.
//	DEPLOYMENT_MODE=community      -> the real guard does NOT skip; the mutant
//	                                  does, and anthropic is missing.
//
// A single direction would be satisfied by a guard that always skips, or by one
// that never runs at all.
func TestCommunitySaasBootstrapsOllamaOnly(t *testing.T) {
	// bootstrapWithAnthropic configures exactly one paid provider and returns
	// whether it survived the guard.
	bootstrapWithAnthropic := func(t *testing.T, mode string) *BootstrapResult {
		t.Helper()
		env := newTestEnvHelper(t)
		defer env.Restore()
		env.Unset(EnvOpenAIAPIKey)
		env.Unset(EnvOllamaEndpoint)
		env.Unset(EnvBedrockRegion)
		env.Set(EnvAnthropicAPIKey, "test-anthropic-key")
		env.Set(EnvAnthropicModel, "claude-sonnet-4-20250514")
		t.Setenv("DEPLOYMENT_MODE", mode)

		result, err := BootstrapFromEnv(&BootstrapConfig{SkipHealthCheck: true})
		if err != nil {
			t.Fatalf("bootstrap under DEPLOYMENT_MODE=%q: %v", mode, err)
		}
		return result
	}

	t.Run("community-saas skips a configured paid provider", func(t *testing.T) {
		result := bootstrapWithAnthropic(t, "community-saas")
		if contains(result.ProvidersBootstrapped, "anthropic") {
			t.Errorf("anthropic was bootstrapped on a community-SaaS deployment (%v). "+
				"try.getaxonflow.com is Ollama-only: an ANTHROPIC_API_KEY that reached the "+
				"environment by accident would be spent on public traffic.",
				result.ProvidersBootstrapped)
		}
		if result.Registry.Has(GlobalTenant, "anthropic") {
			t.Error("anthropic was registered on a community-SaaS deployment")
		}
	})

	t.Run("community does NOT skip it", func(t *testing.T) {
		result := bootstrapWithAnthropic(t, "community")
		if !contains(result.ProvidersBootstrapped, "anthropic") {
			t.Errorf("anthropic was skipped on a COMMUNITY deployment (%v). The Ollama-only rule "+
				"belongs to community-SaaS alone; applying it to the Community posture would "+
				"silently disable every paid provider a self-hosted operator configured. This is "+
				"the direction that catches a guard keyed on the wrong one of the two predicates.",
				result.ProvidersBootstrapped)
		}
	})

	t.Run("an unset mode does not skip either", func(t *testing.T) {
		result := bootstrapWithAnthropic(t, "")
		if !contains(result.ProvidersBootstrapped, "anthropic") {
			t.Errorf("anthropic was skipped with DEPLOYMENT_MODE unset (%v); the csaas predicate "+
				"matches exactly one token and unset is not it", result.ProvidersBootstrapped)
		}
	})
}
