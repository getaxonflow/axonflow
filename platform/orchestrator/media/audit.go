// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package media

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	logutil "axonflow/platform/shared/logger"
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
	// pii and safe print "unknown" when the capability that measures them did
	// not run on the item (result.Scanned), never a zero no detector produced
	// (#4249 row 5705208432); scanned lists what ran.
	a.logger.Printf("request=%s media_index=%d hash=%s mime=%s size=%d analyzers=%d pii=%s safe=%s scanned=%s time_ms=%d",
		logutil.Sanitize(record.RequestID),
		record.MediaIndex,
		record.SHA256Hash,
		logutil.Sanitize(record.MIMEType),
		record.FileSizeBytes,
		record.AnalyzerCount,
		measuredBool(result.Scanned, ScanPII, record.HasPII),
		measuredBool(result.Scanned, ScanContentSafety, record.ContentSafe),
		scannedList(result.Scanned),
		record.AnalysisTimeMs,
	)

	// Enterprise-level detail
	if a.isEnterprise {
		if record.HasFaces {
			a.logger.Printf("request=%s media_index=%d faces=%d biometric=%t",
				logutil.Sanitize(record.RequestID), record.MediaIndex, record.FaceCount, record.HasBiometricData)
		}
		if record.NSFWScore > 0 || record.ViolenceScore > 0 {
			a.logger.Printf("request=%s media_index=%d nsfw=%.2f violence=%.2f",
				logutil.Sanitize(record.RequestID), record.MediaIndex, record.NSFWScore, record.ViolenceScore)
		}
		if record.DocumentType != "" {
			a.logger.Printf("request=%s media_index=%d doc_type=%s",
				logutil.Sanitize(record.RequestID), record.MediaIndex, logutil.Sanitize(record.DocumentType))
		}
	}
}

// measuredBool renders a signal for the audit line: its value when capability
// is in scanned, "unknown" otherwise.
func measuredBool(scanned []string, capability string, value bool) string {
	for _, c := range scanned {
		if c == capability {
			return strconv.FormatBool(value)
		}
	}
	return "unknown"
}

// scannedList renders scanned for the audit line, "-" when nothing ran.
func scannedList(scanned []string) string {
	if len(scanned) == 0 {
		return "-"
	}
	return strings.Join(scanned, ",")
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
