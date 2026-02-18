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

/*
Package media provides image governance and analysis for AxonFlow's multimodal pipeline.

# Overview

This package implements media (image) analysis that runs before LLM routing in the
orchestrator pipeline. It detects PII in images via OCR, classifies content safety,
identifies faces/biometric data, and flags sensitive documents.

# Analyzer Interface

The MediaAnalyzer interface is the core abstraction that all media analyzers must implement:

	type MediaAnalyzer interface {
		Name() string
		Type() MediaAnalyzerType
		Analyze(ctx context.Context, media MediaContent) (*MediaAnalysisResult, error)
		HealthCheck(ctx context.Context) error
		Capabilities() []MediaAnalyzerCapability
	}

# Built-in Analyzers

  - LocalOCRAnalyzer: Tesseract OCR → existing PII detection (Community)
  - AWSRekognitionAnalyzer: AWS Rekognition (Enterprise)
  - GoogleVisionAnalyzer: Google Cloud Vision (Enterprise)
  - AzureVisionAnalyzer: Azure Computer Vision (Enterprise)

# Tier Model

  - Community: Local OCR + PII detection, fail-open enforcement, basic audit
  - Evaluation: Same as Community plus configurable analyzers and classification labels
  - Enterprise: Cloud analyzers, face/biometric detection, content safety, fail-closed enforcement

# Thread Safety

All analyzer implementations must be safe for concurrent use. The registry and
pipeline implementations use sync.RWMutex for thread-safe operations.
*/
package media
