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
	"sort"
	"sync"
	"time"
)

// DefaultMaxConcurrentAnalyzers is the maximum number of analyzers that can run in parallel.
const DefaultMaxConcurrentAnalyzers = 10

// Pipeline orchestrates multi-analyzer media analysis.
// It runs all registered analyzers against each media item and aggregates results.
type Pipeline struct {
	registry               *Registry
	validator              AnalyzerLicenseValidator
	auditLogger            *AuditLogger
	logger                 *log.Logger
	maxConcurrentAnalyzers int
}

// PipelineOption configures the pipeline during creation.
type PipelineOption func(*Pipeline)

// WithPipelineRegistry sets the analyzer registry for the pipeline.
func WithPipelineRegistry(r *Registry) PipelineOption {
	return func(p *Pipeline) {
		p.registry = r
	}
}

// WithPipelineValidator sets the license validator for the pipeline.
func WithPipelineValidator(v AnalyzerLicenseValidator) PipelineOption {
	return func(p *Pipeline) {
		p.validator = v
	}
}

// WithPipelineAuditLogger sets the audit logger for the pipeline.
func WithPipelineAuditLogger(a *AuditLogger) PipelineOption {
	return func(p *Pipeline) {
		p.auditLogger = a
	}
}

// WithPipelineLogger sets the logger for the pipeline.
func WithPipelineLogger(l *log.Logger) PipelineOption {
	return func(p *Pipeline) {
		p.logger = l
	}
}

// WithMaxConcurrentAnalyzers sets the maximum number of analyzers that can run in parallel.
func WithMaxConcurrentAnalyzers(n int) PipelineOption {
	return func(p *Pipeline) {
		if n > 0 {
			p.maxConcurrentAnalyzers = n
		}
	}
}

// NewPipeline creates a new media analysis pipeline.
func NewPipeline(opts ...PipelineOption) *Pipeline {
	p := &Pipeline{
		logger:                 log.New(os.Stdout, "[MEDIA_PIPELINE] ", log.LstdFlags),
		maxConcurrentAnalyzers: DefaultMaxConcurrentAnalyzers,
	}

	for _, opt := range opts {
		opt(p)
	}

	if p.validator == nil {
		p.validator = DefaultAnalyzerValidator
	}

	return p
}

// AnalyzeMedia runs all registered analyzers against a list of media items.
// Returns an aggregated result for each media item.
func (p *Pipeline) AnalyzeMedia(ctx context.Context, requestID string, media []MediaContent) ([]*AggregatedMediaResult, error) {
	if len(media) == 0 {
		return nil, nil
	}

	// Validate all media items first
	if err := ValidateMediaList(media); err != nil {
		return nil, err
	}

	// Get all available analyzers
	var analyzers []MediaAnalyzer
	if p.registry != nil {
		var err error
		analyzers, err = p.registry.GetAllAnalyzers(ctx)
		if err != nil {
			p.logger.Printf("Failed to get analyzers: %v", err)
			// Fail-open: continue with empty analyzer list
			if p.validator.GetEnforcementStrategy(ctx) == EnforcementFailOpen {
				return p.buildEmptyResults(media), nil
			}
			return nil, fmt.Errorf("failed to get analyzers: %w", err)
		}
	}

	if len(analyzers) == 0 {
		p.logger.Println("No analyzers registered")
		if p.validator.GetEnforcementStrategy(ctx) == EnforcementFailClosed {
			return nil, &MediaError{Code: ErrMediaAnalysisFailed, Message: "no analyzers available and enforcement is fail-closed"}
		}
		return p.buildEmptyResults(media), nil
	}

	results := make([]*AggregatedMediaResult, len(media))

	for i := range media {
		result, err := p.analyzeOne(ctx, i, &media[i], analyzers)
		if err != nil {
			if p.validator.GetEnforcementStrategy(ctx) == EnforcementFailOpen {
				p.logger.Printf("Analysis failed for media[%d], continuing (fail-open): %v", i, err)
				results[i] = p.buildEmptyResult(i, &media[i])
				results[i].AddWarning(WarnMediaAnalysisFailed, fmt.Sprintf("analysis failed: %v", err))
				continue
			}
			return nil, fmt.Errorf("media[%d]: %w", i, err)
		}
		results[i] = result

		// Log audit record
		if p.auditLogger != nil {
			p.auditLogger.LogMediaAnalysis(requestID, result, &media[i])
		}
	}

	return results, nil
}

// analyzeOne runs all analyzers against a single media item and aggregates results.
func (p *Pipeline) analyzeOne(ctx context.Context, index int, mc *MediaContent, analyzers []MediaAnalyzer) (*AggregatedMediaResult, error) {
	start := time.Now()

	// Compute SHA-256 hash (also pre-fetches and caches URL data for URL sources)
	hash, hashErr := mc.ComputeSHA256()

	// Ensure raw data is cached before goroutines copy the struct.
	// ComputeSHA256 already fetches for URL sources, but if it failed we retry once
	// so goroutines don't each independently fetch.
	var prefetchErr error
	if mc.Source == MediaSourceURL {
		_, prefetchErr = mc.GetRawData()
	}

	// If we cannot obtain the image data at all, handle according to enforcement strategy.
	// In fail-closed mode, refuse to produce a "safe" result for an image we cannot inspect.
	if mc.Source == MediaSourceURL && prefetchErr != nil {
		if p.validator.GetEnforcementStrategy(ctx) == EnforcementFailClosed {
			return nil, fmt.Errorf("cannot fetch URL media for analysis: %w", prefetchErr)
		}
		// Fail-open: warn but continue — analyzers will each fail individually too
	}

	result := &AggregatedMediaResult{
		MediaIndex:  index,
		SHA256Hash:  hash,
		ContentSafe: true, // Assume safe until proven otherwise
	}

	// Record prefetch warnings so callers see what happened
	if hashErr != nil {
		result.AddWarning(WarnMediaAnalysisFailed, fmt.Sprintf("SHA-256 computation failed: %v", hashErr))
	}
	if prefetchErr != nil {
		result.AddWarning(WarnMediaAnalysisFailed, fmt.Sprintf("URL prefetch failed: %v", prefetchErr))
	}

	// Run analyzers in parallel with concurrency cap
	type analyzerResult struct {
		analyzerName string
		result       *MediaAnalysisResult
		err          error
	}

	resultsCh := make(chan analyzerResult, len(analyzers))
	sem := make(chan struct{}, p.maxConcurrentAnalyzers)
	var wg sync.WaitGroup

	for _, a := range analyzers {
		wg.Add(1)
		go func(analyzer MediaAnalyzer) {
			defer wg.Done()
			sem <- struct{}{}        // acquire semaphore
			defer func() { <-sem }() // release semaphore
			r, err := analyzer.Analyze(ctx, *mc)
			resultsCh <- analyzerResult{analyzerName: analyzer.Name(), result: r, err: err}
		}(a)
	}

	// Close channel when all goroutines complete
	go func() {
		wg.Wait()
		close(resultsCh)
	}()

	// Collect results with context cancellation awareness
	for {
		select {
		case <-ctx.Done():
			if p.validator.GetEnforcementStrategy(ctx) == EnforcementFailClosed {
				return nil, fmt.Errorf("media analysis cancelled: %w", ctx.Err())
			}
			// Fail-open: return partial results
			result.AddWarning(WarnMediaPartialResults, fmt.Sprintf("analysis cancelled: %v", ctx.Err()))
			p.aggregateSignals(result)
			result.AnalysisTimeMs = time.Since(start).Milliseconds()
			return result, nil
		case ar, ok := <-resultsCh:
			if !ok {
				// Channel closed — all results collected
				goto done
			}
			if ar.err != nil {
				p.logger.Printf("Analyzer %s error: %v", ar.analyzerName, ar.err)
				result.AddWarning(WarnMediaAnalyzerError, fmt.Sprintf("analyzer %s: %v", ar.analyzerName, ar.err))
				continue
			}
			if ar.result != nil {
				result.AnalyzerResults = append(result.AnalyzerResults, *ar.result)
				result.EstimatedCostUSD += ar.result.EstimatedCostUSD
			}
		}
	}
done:

	// Deterministic ordering of analyzer results
	sort.Slice(result.AnalyzerResults, func(i, j int) bool {
		return result.AnalyzerResults[i].AnalyzerName < result.AnalyzerResults[j].AnalyzerName
	})

	// Aggregate governance signals
	p.aggregateSignals(result)

	result.AnalysisTimeMs = time.Since(start).Milliseconds()
	return result, nil
}

// GetEnforcementStrategy returns the pipeline's enforcement strategy for the given context.
func (p *Pipeline) GetEnforcementStrategy(ctx context.Context) EnforcementStrategy {
	return p.validator.GetEnforcementStrategy(ctx)
}

// aggregateSignals merges individual analyzer results into governance signals.
func (p *Pipeline) aggregateSignals(result *AggregatedMediaResult) {
	piiTypeSet := make(map[string]bool)
	var bestDocConfidence float64

	for _, ar := range result.AnalyzerResults {
		// Faces
		if len(ar.Faces) > 0 {
			result.HasFaces = true
			result.FaceCount += len(ar.Faces)
			for _, f := range ar.Faces {
				if f.IsBiometric {
					result.HasBiometricData = true
				}
			}
		}

		// Content safety
		if ar.ContentSafety != nil {
			if ar.ContentSafety.NSFWScore > result.NSFWScore {
				result.NSFWScore = ar.ContentSafety.NSFWScore
			}
			if ar.ContentSafety.ViolenceScore > result.ViolenceScore {
				result.ViolenceScore = ar.ContentSafety.ViolenceScore
			}
			if !ar.ContentSafety.IsSafe {
				result.ContentSafe = false
			}
		}

		// Document classification (use highest confidence, OR for sensitivity)
		if ar.DocumentClassification != nil {
			if ar.DocumentClassification.Confidence > bestDocConfidence {
				result.DocumentType = ar.DocumentClassification.DocumentType
				bestDocConfidence = ar.DocumentClassification.Confidence
			}
			if ar.DocumentClassification.IsSensitive {
				result.IsSensitiveDocument = true
			}
		}

		// PII from extracted text
		if len(ar.PIIFindings) > 0 {
			result.HasPII = true
			for _, pii := range ar.PIIFindings {
				piiTypeSet[pii.Type] = true
			}
		}

		// Extracted text (concatenate from all OCR analyzers)
		if ar.ExtractedText != "" {
			if result.ExtractedText != "" {
				result.ExtractedText += "\n"
			}
			result.ExtractedText += ar.ExtractedText
		}
	}

	// Flatten PII types
	for t := range piiTypeSet {
		result.PIITypes = append(result.PIITypes, t)
	}
	sort.Strings(result.PIITypes)
}

// buildEmptyResults creates empty results for when no analyzers are available.
func (p *Pipeline) buildEmptyResults(media []MediaContent) []*AggregatedMediaResult {
	results := make([]*AggregatedMediaResult, len(media))
	for i := range media {
		results[i] = p.buildEmptyResult(i, &media[i])
	}
	return results
}

// buildEmptyResult creates an empty result for a single media item.
func (p *Pipeline) buildEmptyResult(index int, mc *MediaContent) *AggregatedMediaResult {
	hash, _ := mc.ComputeSHA256()
	r := &AggregatedMediaResult{
		MediaIndex:  index,
		SHA256Hash:  hash,
		ContentSafe: true,
	}
	r.AddWarning(WarnMediaNoAnalyzers, "no analyzers available")
	return r
}
