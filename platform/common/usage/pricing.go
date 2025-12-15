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

package usage

import "fmt"

// LLM provider pricing as of October 2025
// Prices stored in cents per 1K tokens to avoid floating point issues
// All prices are USD

// ProviderPricing contains pricing for a specific model
type ProviderPricing struct {
	PromptCostPer1K     int // cents per 1K prompt tokens
	CompletionCostPer1K int // cents per 1K completion tokens
}

// providerPricing maps provider-model combinations to pricing
var providerPricing = map[string]ProviderPricing{
	// OpenAI pricing (as of October 2025)
	"openai-gpt-4":          {3000, 6000},   // $0.03/$0.06 per 1K tokens
	"openai-gpt-4-turbo":    {1000, 3000},   // $0.01/$0.03 per 1K tokens
	"openai-gpt-3.5-turbo":  {50, 150},      // $0.0005/$0.0015 per 1K tokens
	"openai-gpt-3.5-turbo-1106": {100, 200}, // $0.001/$0.002 per 1K tokens

	// Anthropic pricing (as of October 2025)
	"anthropic-claude-3-opus":   {1500, 7500}, // $0.015/$0.075 per 1K tokens
	"anthropic-claude-3-sonnet": {300, 1500},  // $0.003/$0.015 per 1K tokens
	"anthropic-claude-3-haiku":  {25, 125},    // $0.00025/$0.00125 per 1K tokens
	"anthropic-claude-3.5-sonnet": {300, 1500}, // $0.003/$0.015 per 1K tokens

	// Default fallback pricing (conservative estimate)
	"default": {1000, 3000}, // $0.01/$0.03 per 1K tokens
}

// CalculateCost calculates the cost in cents for an LLM request
// Returns cost in cents (integer) to avoid floating point precision issues
func CalculateCost(provider, model string, promptTokens, completionTokens int) int {
	// Build lookup key
	key := provider + "-" + model

	// Get pricing, fallback to default if not found
	pricing, ok := providerPricing[key]
	if !ok {
		pricing = providerPricing["default"]
	}

	// Calculate cost in cents
	promptCost := (promptTokens * pricing.PromptCostPer1K) / 1000
	completionCost := (completionTokens * pricing.CompletionCostPer1K) / 1000

	return promptCost + completionCost
}

// GetProviderPricing returns the pricing for a specific provider-model combination
// This is useful for displaying pricing information to users
func GetProviderPricing(provider, model string) (ProviderPricing, bool) {
	key := provider + "-" + model
	pricing, ok := providerPricing[key]
	return pricing, ok
}

// FormatCostToDollars converts cents to dollar string (e.g., 135 cents -> "$1.35")
func FormatCostToDollars(cents int) string {
	dollars := float64(cents) / 100.0
	return fmt.Sprintf("$%.2f", dollars)
}
