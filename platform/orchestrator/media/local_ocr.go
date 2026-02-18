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
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// LocalOCRAnalyzer uses Tesseract OCR to extract text from images,
// then feeds the extracted text through the existing PII detection pipeline.
// Available in Community tier (no license required).
type LocalOCRAnalyzer struct {
	name           string
	tesseractPath  string
	language       string
	piiDetector    PIIDetectorFunc
}

// PIIDetectorFunc is a function type for PII detection on extracted text.
// This allows injecting the existing EnhancedPIIDetector.DetectAll() via composition.
type PIIDetectorFunc func(text string) []PIIFinding

// NewLocalOCRAnalyzer creates a new local OCR analyzer.
func NewLocalOCRAnalyzer(name string, tesseractPath string, language string, piiDetector PIIDetectorFunc) *LocalOCRAnalyzer {
	if tesseractPath == "" {
		tesseractPath = "tesseract"
	}
	if language == "" {
		language = "eng"
	}

	return &LocalOCRAnalyzer{
		name:          name,
		tesseractPath: tesseractPath,
		language:      language,
		piiDetector:   piiDetector,
	}
}

// Name returns the analyzer name.
func (a *LocalOCRAnalyzer) Name() string {
	return a.name
}

// Type returns the analyzer type.
func (a *LocalOCRAnalyzer) Type() MediaAnalyzerType {
	return AnalyzerTypeLocalOCR
}

// Capabilities returns the capabilities of this analyzer.
func (a *LocalOCRAnalyzer) Capabilities() []MediaAnalyzerCapability {
	caps := []MediaAnalyzerCapability{CapabilityOCR}
	if a.piiDetector != nil {
		caps = append(caps, CapabilityPIIDetection)
	}
	return caps
}

// HealthCheck verifies Tesseract is available.
func (a *LocalOCRAnalyzer) HealthCheck(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, a.tesseractPath, "--version")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("tesseract not available at %q: %w", a.tesseractPath, err)
	}
	return nil
}

// Analyze performs OCR on the image and detects PII in the extracted text.
func (a *LocalOCRAnalyzer) Analyze(ctx context.Context, media MediaContent) (*MediaAnalysisResult, error) {
	start := time.Now()

	result := &MediaAnalysisResult{
		AnalyzerName:     a.name,
		AnalyzerType:     AnalyzerTypeLocalOCR,
		EstimatedCostUSD: EstimateAnalyzerCost(AnalyzerTypeLocalOCR),
	}

	// Get raw image data (handles both base64 and URL sources)
	rawData, err := media.GetRawData()
	if err != nil {
		result.Error = fmt.Sprintf("failed to get raw data: %v", err)
		result.AnalysisTimeMs = time.Since(start).Milliseconds()
		return result, nil // Non-fatal: return partial result with error
	}

	// Run Tesseract OCR
	extractedText, err := a.runTesseract(ctx, rawData)
	if err != nil {
		result.Error = fmt.Sprintf("OCR failed: %v", err)
		result.AnalysisTimeMs = time.Since(start).Milliseconds()
		return result, nil // Non-fatal: return partial result
	}

	result.ExtractedText = strings.TrimSpace(extractedText)

	// Run PII detection on extracted text
	if a.piiDetector != nil && result.ExtractedText != "" {
		result.PIIFindings = a.piiDetector(result.ExtractedText)
	}

	result.AnalysisTimeMs = time.Since(start).Milliseconds()
	return result, nil
}

// runTesseract executes the Tesseract OCR binary on raw image data.
func (a *LocalOCRAnalyzer) runTesseract(ctx context.Context, imageData []byte) (string, error) {
	// Tesseract reads from stdin when given "-" as input
	cmd := exec.CommandContext(ctx, a.tesseractPath, "stdin", "stdout", "-l", a.language)
	cmd.Stdin = bytes.NewReader(imageData)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("tesseract execution failed: %w (stderr: %s)", err, stderr.String())
	}

	return stdout.String(), nil
}

// init registers the LocalOCR factory.
func init() {
	RegisterAnalyzerFactory(AnalyzerTypeLocalOCR, func(config AnalyzerConfig) (MediaAnalyzer, error) {
		tesseractPath := "tesseract"
		language := "eng"

		if config.Settings != nil {
			if tp, ok := config.Settings["tesseract_path"].(string); ok && tp != "" {
				tesseractPath = tp
			}
			if lang, ok := config.Settings["language"].(string); ok && lang != "" {
				language = lang
			}
		}

		return NewLocalOCRAnalyzer(config.Name, tesseractPath, language, nil), nil
	})
}
