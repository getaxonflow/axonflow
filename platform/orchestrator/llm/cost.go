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
