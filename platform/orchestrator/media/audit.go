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
	"fmt"
	"log"
	"os"
	"time"
)

// AuditLogger handles media analysis audit logging.
// Community: logs hash + results summary.
// Enterprise: logs full per-analyzer metadata, biometric flags, extended retention.
type AuditLogger struct {
	logger       *log.Logger
	isEnterprise bool
}

// AuditLoggerOption configures the audit logger.
type AuditLoggerOption func(*AuditLogger)

// WithAuditLoggerEnterprise enables enterprise-level audit detail.
func WithAuditLoggerEnterprise(enterprise bool) AuditLoggerOption {
	return func(a *AuditLogger) {
		a.isEnterprise = enterprise
	}
}

// WithAuditLoggerLogger sets a custom logger.
func WithAuditLoggerLogger(l *log.Logger) AuditLoggerOption {
	return func(a *AuditLogger) {
		a.logger = l
	}
}

// NewAuditLogger creates a new media audit logger.
func NewAuditLogger(opts ...AuditLoggerOption) *AuditLogger {
	a := &AuditLogger{
		logger: log.New(os.Stdout, "[MEDIA_AUDIT] ", log.LstdFlags),
	}

	for _, opt := range opts {
		opt(a)
	}

	return a
}

// LogMediaAnalysis logs an audit record for a media analysis.
func (a *AuditLogger) LogMediaAnalysis(requestID string, result *AggregatedMediaResult, mc *MediaContent) {
	if result == nil {
		return
	}

	record := a.buildAuditRecord(requestID, result, mc)

	// Core audit log (all tiers)
	a.logger.Printf("request=%s media_index=%d hash=%s mime=%s size=%d analyzers=%d pii=%t safe=%t time_ms=%d",
		record.RequestID,
		record.MediaIndex,
		record.SHA256Hash,
		record.MIMEType,
		record.FileSizeBytes,
		record.AnalyzerCount,
		record.HasPII,
		record.ContentSafe,
		record.AnalysisTimeMs,
	)

	// Enterprise-level detail
	if a.isEnterprise {
		if record.HasFaces {
			a.logger.Printf("request=%s media_index=%d faces=%d biometric=%t",
				record.RequestID, record.MediaIndex, record.FaceCount, record.HasBiometricData)
		}
		if record.NSFWScore > 0 || record.ViolenceScore > 0 {
			a.logger.Printf("request=%s media_index=%d nsfw=%.2f violence=%.2f",
				record.RequestID, record.MediaIndex, record.NSFWScore, record.ViolenceScore)
		}
		if record.DocumentType != "" {
			a.logger.Printf("request=%s media_index=%d doc_type=%s",
				record.RequestID, record.MediaIndex, record.DocumentType)
		}
	}
}

// buildAuditRecord creates an audit record from analysis results.
func (a *AuditLogger) buildAuditRecord(requestID string, result *AggregatedMediaResult, mc *MediaContent) MediaAuditRecord {
	record := MediaAuditRecord{
		RequestID:      requestID,
		MediaIndex:     result.MediaIndex,
		SHA256Hash:     result.SHA256Hash,
		MIMEType:       mc.MIMEType,
		AnalyzerCount:  len(result.AnalyzerResults),
		HasPII:         result.HasPII,
		PIITypes:       result.PIITypes,
		ContentSafe:    result.ContentSafe,
		Warnings:       result.Warnings,
		AnalysisTimeMs: result.AnalysisTimeMs,
		Timestamp:      time.Now(),
	}

	if mc.Metadata != nil {
		record.FileSizeBytes = mc.Metadata.FileSizeBytes
	}

	// Enterprise-only fields
	if a.isEnterprise {
		record.HasFaces = result.HasFaces
		record.FaceCount = result.FaceCount
		record.HasBiometricData = result.HasBiometricData
		record.NSFWScore = result.NSFWScore
		record.ViolenceScore = result.ViolenceScore
		record.DocumentType = result.DocumentType
		record.AnalyzerDetails = sanitizeAnalyzerDetails(result.AnalyzerResults)
	}

	return record
}

// sanitizeAnalyzerDetails creates a deep copy of analyzer results with sensitive text redacted.
func sanitizeAnalyzerDetails(results []MediaAnalysisResult) []MediaAnalysisResult {
	sanitized := make([]MediaAnalysisResult, len(results))
	for i, r := range results {
		sanitized[i] = r
		if r.ExtractedText != "" {
			sanitized[i].ExtractedText = fmt.Sprintf("[redacted: %d chars]", len(r.ExtractedText))
		}
		if len(r.PIIFindings) > 0 {
			redactedPII := make([]PIIFinding, len(r.PIIFindings))
			for j, pii := range r.PIIFindings {
				redactedPII[j] = pii
				redactedPII[j].Value = "[redacted]"
			}
			sanitized[i].PIIFindings = redactedPII
		}
	}
	return sanitized
}

// GetAuditRecord returns a structured audit record for external storage.
func (a *AuditLogger) GetAuditRecord(requestID string, result *AggregatedMediaResult, mc *MediaContent) MediaAuditRecord {
	return a.buildAuditRecord(requestID, result, mc)
}
