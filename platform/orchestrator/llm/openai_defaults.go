// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package llm

import "time"

// OpenAI provider defaults.
const (
	// OpenAIDefaultModel is the default OpenAI model.
	OpenAIDefaultModel = "gpt-4o"

	// OpenAIDefaultEndpoint is the default OpenAI API endpoint.
	OpenAIDefaultEndpoint = "https://api.openai.com"

	// OpenAIDefaultTimeout is the default timeout for OpenAI requests.
	OpenAIDefaultTimeout = 120 * time.Second
)
