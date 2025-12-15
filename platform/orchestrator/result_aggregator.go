// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package orchestrator

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"
)

// ResultAggregator synthesizes outputs from multiple tasks into a coherent final result
type ResultAggregator struct {
	llmRouter *LLMRouter
}

// NewResultAggregator creates a new result aggregator instance
func NewResultAggregator(router *LLMRouter) *ResultAggregator {
	return &ResultAggregator{
		llmRouter: router,
	}
}

// AggregateResults combines outputs from parallel execution into a final result
func (a *ResultAggregator) AggregateResults(ctx context.Context, taskResults []StepExecution, originalQuery string, user UserContext) (string, error) {
	startTime := time.Now()

	log.Printf("[ResultAggregator] Aggregating %d task results", len(taskResults))

	// Filter successful results
	successfulResults := a.filterSuccessfulResults(taskResults)

	if len(successfulResults) == 0 {
		return "", fmt.Errorf("no successful task results to aggregate")
	}

	log.Printf("[ResultAggregator] %d successful results out of %d total", len(successfulResults), len(taskResults))

	// Build synthesis prompt
	prompt := a.buildSynthesisPrompt(originalQuery, successfulResults)

	// Call LLM for synthesis
	req := OrchestratorRequest{
		RequestID:   fmt.Sprintf("aggregate-%d", time.Now().Unix()),
		Query:       prompt,
		RequestType: "result-aggregation",
		User:        user,
	}

	response, _, err := a.llmRouter.RouteRequest(ctx, req)
	if err != nil {
		// Fallback: Simple concatenation
		log.Printf("[ResultAggregator] LLM synthesis failed, using simple concatenation: %v", err)
		return a.simpleConcatenation(successfulResults, originalQuery), nil
	}

	// Extract final result
	finalResult, err := a.extractSynthesizedResult(response)
	if err != nil {
		log.Printf("[ResultAggregator] Failed to extract result, using concatenation: %v", err)
		return a.simpleConcatenation(successfulResults, originalQuery), nil
	}

	elapsed := time.Since(startTime)
	log.Printf("[ResultAggregator] Synthesis completed in %s", elapsed)

	return finalResult, nil
}

// Filter successful results
func (a *ResultAggregator) filterSuccessfulResults(results []StepExecution) []StepExecution {
	successful := make([]StepExecution, 0)

	for _, result := range results {
		if result.Status == "completed" && result.Output != nil {
			successful = append(successful, result)
		}
	}

	return successful
}

// Build synthesis prompt for LLM
func (a *ResultAggregator) buildSynthesisPrompt(originalQuery string, results []StepExecution) string {
	var promptBuilder strings.Builder

	promptBuilder.WriteString("You are a result synthesis AI. Combine the following task results into a coherent, comprehensive answer.\n\n")
	promptBuilder.WriteString(fmt.Sprintf("Original Query: %s\n\n", originalQuery))
	promptBuilder.WriteString("Task Results:\n\n")

	// Add each task result
	for i, result := range results {
		promptBuilder.WriteString(fmt.Sprintf("Task %d: %s\n", i+1, result.Name))
		promptBuilder.WriteString(fmt.Sprintf("Status: %s\n", result.Status))
		promptBuilder.WriteString(fmt.Sprintf("Time: %s\n", result.ProcessTime))

		// Extract meaningful output
		if output, ok := result.Output["response"]; ok {
			if responseData, ok := output.(*LLMResponse); ok {
				promptBuilder.WriteString(fmt.Sprintf("Result: %s\n", responseData.Content))
			} else if str, ok := output.(string); ok {
				promptBuilder.WriteString(fmt.Sprintf("Result: %s\n", str))
			} else {
				promptBuilder.WriteString(fmt.Sprintf("Result: %v\n", output))
			}
		} else {
			// Try to extract any text content
			promptBuilder.WriteString(fmt.Sprintf("Result: %v\n", result.Output))
		}

		promptBuilder.WriteString("\n")
	}

	promptBuilder.WriteString("\nInstructions:\n")
	promptBuilder.WriteString("1. Synthesize all task results into a single, coherent response\n")
	promptBuilder.WriteString("2. Ensure the answer directly addresses the original query\n")
	promptBuilder.WriteString("3. Organize information logically\n")
	promptBuilder.WriteString("4. If tasks provide conflicting information, reconcile or note the conflict\n")
	promptBuilder.WriteString("5. Be concise but comprehensive\n\n")
	promptBuilder.WriteString("Provide your synthesized response:")

	return promptBuilder.String()
}

// Extract synthesized result from LLM response
func (a *ResultAggregator) extractSynthesizedResult(response interface{}) (string, error) {
	// Handle LLMResponse type
	if llmResp, ok := response.(*LLMResponse); ok {
		return llmResp.Content, nil
	}

	// Handle string type
	if str, ok := response.(string); ok {
		return str, nil
	}

	return "", fmt.Errorf("unexpected response type: %T", response)
}

// Simple concatenation fallback (when LLM unavailable)
func (a *ResultAggregator) simpleConcatenation(results []StepExecution, originalQuery string) string {
	var output strings.Builder

	output.WriteString(fmt.Sprintf("Results for: %s\n\n", originalQuery))

	for i, result := range results {
		output.WriteString(fmt.Sprintf("%d. %s (completed in %s)\n", i+1, result.Name, result.ProcessTime))

		// Extract output
		if responseOutput, ok := result.Output["response"]; ok {
			if llmResp, ok := responseOutput.(*LLMResponse); ok {
				output.WriteString(fmt.Sprintf("   %s\n\n", llmResp.Content))
			} else if str, ok := responseOutput.(string); ok {
				output.WriteString(fmt.Sprintf("   %s\n\n", str))
			} else {
				output.WriteString(fmt.Sprintf("   %v\n\n", responseOutput))
			}
		} else {
			// Fallback: stringify entire output
			output.WriteString(fmt.Sprintf("   %v\n\n", result.Output))
		}
	}

	output.WriteString("---\n")
	output.WriteString("Note: Results aggregated without LLM synthesis (simple concatenation)\n")

	return output.String()
}

// AggregateWithCustomPrompt allows custom synthesis prompts (advanced use case)
func (a *ResultAggregator) AggregateWithCustomPrompt(ctx context.Context, taskResults []StepExecution, customPrompt string, user UserContext) (string, error) {
	// Filter successful results
	successfulResults := a.filterSuccessfulResults(taskResults)

	if len(successfulResults) == 0 {
		return "", fmt.Errorf("no successful task results to aggregate")
	}

	// Use custom prompt directly
	req := OrchestratorRequest{
		RequestID:   fmt.Sprintf("aggregate-custom-%d", time.Now().Unix()),
		Query:       customPrompt,
		RequestType: "custom-aggregation",
		User:        user,
	}

	response, _, err := a.llmRouter.RouteRequest(ctx, req)
	if err != nil {
		return a.simpleConcatenation(successfulResults, "Custom aggregation"), nil
	}

	return a.extractSynthesizedResult(response)
}

// IsHealthy checks if aggregator is operational
func (a *ResultAggregator) IsHealthy() bool {
	return a.llmRouter != nil && a.llmRouter.IsHealthy()
}

// GetAggregationStats returns statistics about aggregation operations
func (a *ResultAggregator) GetAggregationStats(results []StepExecution) AggregationStats {
	stats := AggregationStats{
		TotalTasks:      len(results),
		SuccessfulTasks: 0,
		FailedTasks:     0,
		TotalTimeMs:     0,
	}

	for _, result := range results {
		switch result.Status {
		case "completed":
			stats.SuccessfulTasks++
		case "failed":
			stats.FailedTasks++
		}

		// Parse process time (format: "123.45ms")
		if duration, err := time.ParseDuration(result.ProcessTime); err == nil {
			stats.TotalTimeMs += int64(duration.Milliseconds())
		}
	}

	if stats.TotalTasks > 0 {
		stats.SuccessRate = float64(stats.SuccessfulTasks) / float64(stats.TotalTasks) * 100
	}

	return stats
}

// AggregationStats holds statistics about aggregation
type AggregationStats struct {
	TotalTasks      int     `json:"total_tasks"`
	SuccessfulTasks int     `json:"successful_tasks"`
	FailedTasks     int     `json:"failed_tasks"`
	SuccessRate     float64 `json:"success_rate"`
	TotalTimeMs     int64   `json:"total_time_ms"`
}
