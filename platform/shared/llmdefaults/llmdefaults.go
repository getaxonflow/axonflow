// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

// Package llmdefaults is the single source of truth for the platform's
// default LLM model ids. Provider fallbacks, compose/CFN defaults, pricing
// tables, and demo routers all drifted independently until the retired
// claude-*-4-20250514 launch ids started 404ing on the Anthropic API and
// killed every failover through anthropic/bedrock (#2871). Go surfaces
// MUST reference these constants; non-Go surfaces (docker-compose, CFN,
// deploy scripts, env configs) are pinned by the drift test in this
// package, which fails the build when a retired id reappears or a config
// surface stops matching these defaults.
package llmdefaults

const (
	// AnthropicModel is the default model for the direct Anthropic API.
	AnthropicModel = "claude-haiku-4-5-20251001"

	// BedrockModel is the default Bedrock model. Region-prefixed inference
	// profile id: non-prefixed Claude 4+ ids fail on-demand invocation.
	BedrockModel = "us.anthropic.claude-haiku-4-5-20251001-v1:0"
)

// RetiredModelIDs must never reappear in live code or config surfaces.
// The Anthropic API 404s them (not_found_error); Bedrock variants also
// predate the inference-profile requirement.
var RetiredModelIDs = []string{
	"claude-sonnet-4-20250514",
	"claude-opus-4-20250514",
	"anthropic.claude-sonnet-4-20250514-v1:0",
	"anthropic.claude-opus-4-20250514-v1:0",
}
