// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package media

// MediaCostEstimate provides estimated costs for media analysis.
type MediaCostEstimate struct {
	// TotalEstimateUSD is the total estimated cost across all analyzers.
	TotalEstimateUSD float64 `json:"total_estimate_usd"`

	// PerAnalyzerBreakdown is the cost per analyzer (Evaluation+ tiers only).
	PerAnalyzerBreakdown []AnalyzerCostBreakdown `json:"per_analyzer_breakdown,omitempty"`

	// Currency is the currency for costs (always "USD").
	Currency string `json:"currency"`
}

// AnalyzerCostBreakdown shows cost for a single analyzer.
type AnalyzerCostBreakdown struct {
	AnalyzerName string  `json:"analyzer_name"`
	AnalyzerType string  `json:"analyzer_type"`
	EstimateUSD  float64 `json:"estimate_usd"`
	Details      string  `json:"details,omitempty"`
}

// Pricing constants per image analysis (approximate, in USD).
// These are configurable via environment variables in production.
var analyzerPricing = map[MediaAnalyzerType]float64{
	AnalyzerTypeLocalOCR:       0.0,    // Free (local processing)
	AnalyzerTypeAWSRekognition: 0.001,  // ~$1 per 1000 images
	AnalyzerTypeGoogleVision:   0.0015, // ~$1.50 per 1000 images
	AnalyzerTypeAzureVision:    0.001,  // ~$1 per 1000 images
}

// EstimateMediaCost estimates the cost for analyzing a set of media items.
func EstimateMediaCost(mediaCount int, analyzerTypes []MediaAnalyzerType) MediaCostEstimate {
	estimate := MediaCostEstimate{
		Currency: "USD",
	}

	for _, at := range analyzerTypes {
		price, ok := analyzerPricing[at]
		if !ok {
			price = 0.001 // Default estimate for unknown analyzers
		}

		cost := price * float64(mediaCount)
		estimate.TotalEstimateUSD += cost

		estimate.PerAnalyzerBreakdown = append(estimate.PerAnalyzerBreakdown, AnalyzerCostBreakdown{
			AnalyzerName: string(at),
			AnalyzerType: string(at),
			EstimateUSD:  cost,
		})
	}

	return estimate
}

// EstimateAnalyzerCost returns the per-image cost for a specific analyzer type.
func EstimateAnalyzerCost(analyzerType MediaAnalyzerType) float64 {
	price, ok := analyzerPricing[analyzerType]
	if !ok {
		return 0.001
	}
	return price
}

// AggregateMediaCostFromResults calculates total cost from analysis results.
func AggregateMediaCostFromResults(results []*AggregatedMediaResult) float64 {
	var total float64
	for _, r := range results {
		if r != nil {
			total += r.EstimatedCostUSD
		}
	}
	return total
}
