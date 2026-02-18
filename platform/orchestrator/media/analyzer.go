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

import (
	"context"
)

// MediaAnalyzer is the unified interface for all media analyzers.
// Implementations must be safe for concurrent use.
//
// Minimal implementation requires: Name(), Type(), Analyze(), HealthCheck(), and Capabilities().
// Optional methods can be implemented via type assertion for advanced features.
type MediaAnalyzer interface {
	// Name returns the unique identifier for this analyzer instance.
	Name() string

	// Type returns the analyzer type (e.g., "local-ocr", "aws-rekognition").
	Type() MediaAnalyzerType

	// Analyze performs media analysis on the given content.
	// The context should be used for cancellation and timeout.
	Analyze(ctx context.Context, media MediaContent) (*MediaAnalysisResult, error)

	// HealthCheck verifies the analyzer is operational.
	HealthCheck(ctx context.Context) error

	// Capabilities returns the list of analysis capabilities this analyzer supports.
	Capabilities() []MediaAnalyzerCapability
}

// BatchMediaAnalyzer extends MediaAnalyzer with batch analysis support.
// Implement this interface to enable efficient batch processing (Enterprise).
type BatchMediaAnalyzer interface {
	MediaAnalyzer

	// AnalyzeBatch analyzes multiple media items in a single call.
	AnalyzeBatch(ctx context.Context, media []MediaContent) ([]*MediaAnalysisResult, error)
}

// ConfigurableMediaAnalyzer extends MediaAnalyzer with runtime configuration.
// Implement this interface to allow analyzers to be reconfigured without restart.
type ConfigurableMediaAnalyzer interface {
	MediaAnalyzer

	// Configure updates the analyzer configuration.
	Configure(config AnalyzerConfig) error

	// GetConfig returns the current analyzer configuration.
	GetConfig() AnalyzerConfig
}

// AnalyzerConfig contains configuration for creating or updating an analyzer.
type AnalyzerConfig struct {
	// Name is the unique identifier for this analyzer instance.
	Name string `json:"name"`

	// Type identifies the analyzer implementation to use.
	Type MediaAnalyzerType `json:"type"`

	// Enabled indicates if this analyzer is active.
	Enabled bool `json:"enabled"`

	// APIKey is the authentication key for cloud analyzers.
	APIKey string `json:"api_key,omitempty"`

	// APIKeySecretARN is the AWS Secrets Manager ARN for the API key.
	APIKeySecretARN string `json:"api_key_secret_arn,omitempty"`

	// Region is the cloud region (for AWS Rekognition).
	Region string `json:"region,omitempty"`

	// Endpoint is the API endpoint URL (for Azure Vision).
	Endpoint string `json:"endpoint,omitempty"`

	// Settings contains analyzer-specific configuration.
	Settings map[string]any `json:"settings,omitempty"`
}

// HasCapability returns true if the analyzer supports the given capability.
func HasCapability(a MediaAnalyzer, cap MediaAnalyzerCapability) bool {
	for _, c := range a.Capabilities() {
		if c == cap {
			return true
		}
	}
	return false
}
