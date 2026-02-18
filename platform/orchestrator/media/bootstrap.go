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
	"fmt"
	"log"
	"os"
	"os/exec"
)

// additionalBootstrapAnalyzers allows enterprise builds to add additional analyzers.
// This is populated by init() in bootstrap_enterprise.go for enterprise builds.
var additionalBootstrapAnalyzers []struct {
	name      string
	atype     MediaAnalyzerType
	bootstrap func() (*AnalyzerConfig, error)
}

// Environment variable names for media analyzer configuration.
const (
	// Local OCR configuration
	EnvTesseractPath = "TESSERACT_PATH"
	EnvOCRLanguage   = "OCR_LANGUAGE"

	// AWS Rekognition configuration (Enterprise)
	EnvRekognitionRegion = "REKOGNITION_REGION"

	// Google Vision configuration (Enterprise)
	EnvGoogleVisionAPIKey = "GOOGLE_VISION_API_KEY"

	// Azure Vision configuration (Enterprise)
	EnvAzureVisionEndpoint = "AZURE_VISION_ENDPOINT"
	EnvAzureVisionAPIKey   = "AZURE_VISION_API_KEY"

	// General media configuration
	EnvMediaAnalyzers         = "MEDIA_ANALYZERS"
	EnvMediaEnforcementStrategy = "MEDIA_ENFORCEMENT_STRATEGY"
	EnvMediaMaxImageSizeMB    = "MEDIA_MAX_IMAGE_SIZE_MB"
)

// BootstrapMediaConfig contains configuration for the media bootstrap process.
type BootstrapMediaConfig struct {
	Logger   *log.Logger
	Registry *Registry
}

// BootstrapMediaResult contains the result of the media bootstrap process.
type BootstrapMediaResult struct {
	Registry              *Registry
	AnalyzersBootstrapped []string
	AnalyzersFailed       map[string]error
	Warnings              []string
}

// BootstrapFromEnv bootstraps media analyzers from environment variables.
func BootstrapFromEnv(cfg *BootstrapMediaConfig) (*BootstrapMediaResult, error) {
	if cfg == nil {
		cfg = &BootstrapMediaConfig{}
	}

	logger := cfg.Logger
	if logger == nil {
		logger = log.New(os.Stdout, "[MEDIA_BOOTSTRAP] ", log.LstdFlags)
	}

	registry := cfg.Registry
	if registry == nil {
		maxAnalyzers := DefaultAnalyzerValidator.GetMaxAnalyzers(context.Background())
		registry = NewRegistry(
			WithRegistryLogger(logger),
			WithMaxAnalyzers(maxAnalyzers),
		)
	}

	result := &BootstrapMediaResult{
		Registry:        registry,
		AnalyzersFailed: make(map[string]error),
	}

	// Bootstrap community analyzers
	analyzers := []struct {
		name      string
		atype     MediaAnalyzerType
		bootstrap func() (*AnalyzerConfig, error)
	}{
		{"local-ocr", AnalyzerTypeLocalOCR, bootstrapLocalOCR},
	}

	// Add enterprise analyzers if available
	for _, ea := range additionalBootstrapAnalyzers {
		analyzers = append(analyzers, struct {
			name      string
			atype     MediaAnalyzerType
			bootstrap func() (*AnalyzerConfig, error)
		}{ea.name, ea.atype, ea.bootstrap})
	}

	ctx := context.Background()

	for _, a := range analyzers {
		config, err := a.bootstrap()
		if err != nil {
			logger.Printf("Skipping %s: %v", a.name, err)
			continue
		}

		if config == nil {
			logger.Printf("Skipping %s: not configured", a.name)
			continue
		}

		if err := registry.Register(ctx, config); err != nil {
			result.AnalyzersFailed[a.name] = err
			logger.Printf("Failed to register %s: %v", a.name, err)
			continue
		}

		result.AnalyzersBootstrapped = append(result.AnalyzersBootstrapped, config.Name)
		logger.Printf("Successfully bootstrapped %s", a.name)
	}

	logger.Printf("Media bootstrap complete: %d analyzers registered, %d failed",
		len(result.AnalyzersBootstrapped), len(result.AnalyzersFailed))

	if len(result.AnalyzersBootstrapped) == 0 && len(result.AnalyzersFailed) == 0 {
		logger.Println("INFO: No media analyzers configured. Local OCR is enabled by default when Tesseract is available.")
	}

	return result, nil
}

// bootstrapLocalOCR creates a LocalOCR analyzer config from environment variables.
func bootstrapLocalOCR() (*AnalyzerConfig, error) {
	// Local OCR is always available in Community — check if Tesseract is present
	tesseractPath := os.Getenv(EnvTesseractPath)
	if tesseractPath == "" {
		tesseractPath = "tesseract" // Default: assume it's on PATH
	}

	// Verify Tesseract is actually installed before registering
	if _, err := exec.LookPath(tesseractPath); err != nil {
		return nil, nil // Tesseract not found, skip registration
	}

	config := &AnalyzerConfig{
		Name:    "local-ocr",
		Type:    AnalyzerTypeLocalOCR,
		Enabled: true,
		Settings: map[string]any{
			"tesseract_path": tesseractPath,
			"language":       getOCRLanguage(),
		},
	}

	return config, nil
}

// getOCRLanguage returns the OCR language from environment or default.
func getOCRLanguage() string {
	lang := os.Getenv(EnvOCRLanguage)
	if lang == "" {
		return "eng" // Default: English
	}
	return lang
}

// QuickBootstrap is a convenience function for simple bootstrap scenarios.
func QuickBootstrap() (*Pipeline, error) {
	result, err := BootstrapFromEnv(nil)
	if err != nil {
		return nil, fmt.Errorf("media bootstrap failed: %w", err)
	}

	pipeline := NewPipeline(
		WithPipelineRegistry(result.Registry),
		WithPipelineAuditLogger(NewAuditLogger()),
	)

	return pipeline, nil
}
