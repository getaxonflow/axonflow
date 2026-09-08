// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package llm

// EstimateTokens provides rough token estimates for a completion request.
// This is a simple approximation; for accurate counts use a proper tokenizer.
func EstimateTokens(req CompletionRequest) (inputTokens, outputTokens int) {
	return estimateTokens(req)
}

// CalculateCost computes the total cost estimate given token counts and pricing.
func CalculateCost(inputTokens, outputTokens int, inputCostPer1K, outputCostPer1K float64) float64 {
	return calculateCost(inputTokens, outputTokens, inputCostPer1K, outputCostPer1K)
}
