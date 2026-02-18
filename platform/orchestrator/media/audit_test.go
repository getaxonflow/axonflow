// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package media

import (
	"bytes"
	"log"
	"strings"
	"testing"
	"time"
)

func TestNewAuditLogger_Defaults(t *testing.T) {
	al := NewAuditLogger()
	if al == nil {
		t.Fatal("expected non-nil AuditLogger")
	}
	if al.isEnterprise {
		t.Error("expected isEnterprise to be false by default")
	}
	if al.logger == nil {
		t.Error("expected non-nil default logger")
	}
}

func TestNewAuditLogger_WithEnterprise(t *testing.T) {
	al := NewAuditLogger(WithAuditLoggerEnterprise(true))
	if !al.isEnterprise {
		t.Error("expected isEnterprise to be true")
	}
}

func TestNewAuditLogger_WithCustomLogger(t *testing.T) {
	var buf bytes.Buffer
	customLogger := log.New(&buf, "[TEST] ", 0)
	al := NewAuditLogger(WithAuditLoggerLogger(customLogger))
	if al.logger != customLogger {
		t.Error("expected custom logger to be set")
	}
}

func TestNewAuditLogger_WithMultipleOptions(t *testing.T) {
	var buf bytes.Buffer
	customLogger := log.New(&buf, "[TEST] ", 0)
	al := NewAuditLogger(
		WithAuditLoggerEnterprise(true),
		WithAuditLoggerLogger(customLogger),
	)
	if !al.isEnterprise {
		t.Error("expected isEnterprise to be true")
	}
	if al.logger != customLogger {
		t.Error("expected custom logger to be set")
	}
}

func TestLogMediaAnalysis_NilResult_NoPanic(t *testing.T) {
	var buf bytes.Buffer
	al := NewAuditLogger(WithAuditLoggerLogger(log.New(&buf, "", 0)))

	// Should not panic with nil result.
	al.LogMediaAnalysis("req-123", nil, &MediaContent{MIMEType: "image/jpeg"})

	if buf.Len() != 0 {
		t.Errorf("expected no log output for nil result, got %q", buf.String())
	}
}

func TestLogMediaAnalysis_ValidResult(t *testing.T) {
	var buf bytes.Buffer
	al := NewAuditLogger(WithAuditLoggerLogger(log.New(&buf, "", 0)))

	result := &AggregatedMediaResult{
		MediaIndex:     0,
		SHA256Hash:     "abc123def456",
		ContentSafe:    true,
		HasPII:         true,
		PIITypes:       []string{"email"},
		AnalysisTimeMs: 42,
		AnalyzerResults: []MediaAnalysisResult{
			{AnalyzerName: "ocr", AnalyzerType: AnalyzerTypeLocalOCR},
		},
	}
	mc := &MediaContent{
		MIMEType: "image/png",
		Metadata: &MediaMetadata{FileSizeBytes: 1024},
	}

	al.LogMediaAnalysis("req-456", result, mc)

	output := buf.String()
	if output == "" {
		t.Error("expected log output for valid result, got empty string")
	}
}

func TestGetAuditRecord_CommunityMode(t *testing.T) {
	al := NewAuditLogger() // community by default

	result := &AggregatedMediaResult{
		MediaIndex:       1,
		SHA256Hash:       "hash123",
		ContentSafe:      true,
		HasPII:           false,
		HasFaces:         true,
		FaceCount:        2,
		HasBiometricData: true,
		NSFWScore:        0.8,
		ViolenceScore:    0.3,
		DocumentType:     "passport",
		AnalysisTimeMs:   100,
		AnalyzerResults: []MediaAnalysisResult{
			{AnalyzerName: "test-analyzer", AnalyzerType: AnalyzerTypeLocalOCR},
		},
	}
	mc := &MediaContent{
		MIMEType: "image/jpeg",
		Metadata: &MediaMetadata{FileSizeBytes: 2048},
	}

	record := al.GetAuditRecord("req-community", result, mc)

	// Core fields should be populated.
	if record.RequestID != "req-community" {
		t.Errorf("expected RequestID 'req-community', got %q", record.RequestID)
	}
	if record.MediaIndex != 1 {
		t.Errorf("expected MediaIndex 1, got %d", record.MediaIndex)
	}
	if record.SHA256Hash != "hash123" {
		t.Errorf("expected SHA256Hash 'hash123', got %q", record.SHA256Hash)
	}
	if record.MIMEType != "image/jpeg" {
		t.Errorf("expected MIMEType 'image/jpeg', got %q", record.MIMEType)
	}
	if record.FileSizeBytes != 2048 {
		t.Errorf("expected FileSizeBytes 2048, got %d", record.FileSizeBytes)
	}
	if record.AnalyzerCount != 1 {
		t.Errorf("expected AnalyzerCount 1, got %d", record.AnalyzerCount)
	}
	if record.ContentSafe != true {
		t.Error("expected ContentSafe to be true")
	}
	if record.AnalysisTimeMs != 100 {
		t.Errorf("expected AnalysisTimeMs 100, got %d", record.AnalysisTimeMs)
	}
	if record.Timestamp.IsZero() {
		t.Error("expected Timestamp to be set")
	}

	// Enterprise-specific fields should be zero/empty in community mode.
	if record.HasFaces != false {
		t.Error("expected HasFaces to be false in community mode")
	}
	if record.FaceCount != 0 {
		t.Errorf("expected FaceCount 0 in community mode, got %d", record.FaceCount)
	}
	if record.HasBiometricData != false {
		t.Error("expected HasBiometricData to be false in community mode")
	}
	if record.NSFWScore != 0 {
		t.Errorf("expected NSFWScore 0 in community mode, got %f", record.NSFWScore)
	}
	if record.ViolenceScore != 0 {
		t.Errorf("expected ViolenceScore 0 in community mode, got %f", record.ViolenceScore)
	}
	if record.DocumentType != "" {
		t.Errorf("expected empty DocumentType in community mode, got %q", record.DocumentType)
	}
	if record.AnalyzerDetails != nil {
		t.Errorf("expected nil AnalyzerDetails in community mode, got %v", record.AnalyzerDetails)
	}
}

func TestGetAuditRecord_EnterpriseMode(t *testing.T) {
	al := NewAuditLogger(WithAuditLoggerEnterprise(true))

	result := &AggregatedMediaResult{
		MediaIndex:       0,
		SHA256Hash:       "enterprise-hash",
		ContentSafe:      false,
		HasPII:           true,
		PIITypes:         []string{"ssn", "email"},
		HasFaces:         true,
		FaceCount:        3,
		HasBiometricData: true,
		NSFWScore:        0.9,
		ViolenceScore:    0.5,
		DocumentType:     "id_card",
		AnalysisTimeMs:   250,
		Warnings:         []string{"nsfw_detected"},
		AnalyzerResults: []MediaAnalysisResult{
			{AnalyzerName: "rekognition", AnalyzerType: AnalyzerTypeAWSRekognition, AnalysisTimeMs: 200},
			{AnalyzerName: "ocr", AnalyzerType: AnalyzerTypeLocalOCR, AnalysisTimeMs: 50},
		},
	}
	mc := &MediaContent{
		MIMEType: "image/png",
		Metadata: &MediaMetadata{FileSizeBytes: 4096},
	}

	record := al.GetAuditRecord("req-enterprise", result, mc)

	// Core fields.
	if record.RequestID != "req-enterprise" {
		t.Errorf("expected RequestID 'req-enterprise', got %q", record.RequestID)
	}
	if record.HasPII != true {
		t.Error("expected HasPII to be true")
	}
	if len(record.PIITypes) != 2 {
		t.Errorf("expected 2 PII types, got %d", len(record.PIITypes))
	}
	if record.AnalyzerCount != 2 {
		t.Errorf("expected AnalyzerCount 2, got %d", record.AnalyzerCount)
	}

	// Enterprise fields should be populated.
	if record.HasFaces != true {
		t.Error("expected HasFaces to be true in enterprise mode")
	}
	if record.FaceCount != 3 {
		t.Errorf("expected FaceCount 3, got %d", record.FaceCount)
	}
	if record.HasBiometricData != true {
		t.Error("expected HasBiometricData to be true in enterprise mode")
	}
	if record.NSFWScore != 0.9 {
		t.Errorf("expected NSFWScore 0.9, got %f", record.NSFWScore)
	}
	if record.ViolenceScore != 0.5 {
		t.Errorf("expected ViolenceScore 0.5, got %f", record.ViolenceScore)
	}
	if record.DocumentType != "id_card" {
		t.Errorf("expected DocumentType 'id_card', got %q", record.DocumentType)
	}
	if len(record.AnalyzerDetails) != 2 {
		t.Errorf("expected 2 AnalyzerDetails, got %d", len(record.AnalyzerDetails))
	}
	if len(record.Warnings) != 1 {
		t.Errorf("expected 1 warning, got %d", len(record.Warnings))
	}
}

func TestGetAuditRecord_NoMetadata(t *testing.T) {
	al := NewAuditLogger()

	result := &AggregatedMediaResult{
		SHA256Hash:  "nometadata",
		ContentSafe: true,
	}
	mc := &MediaContent{
		MIMEType: "image/gif",
		// Metadata is nil
	}

	record := al.GetAuditRecord("req-nometa", result, mc)

	if record.FileSizeBytes != 0 {
		t.Errorf("expected FileSizeBytes 0 with nil metadata, got %d", record.FileSizeBytes)
	}
	if record.MIMEType != "image/gif" {
		t.Errorf("expected MIMEType 'image/gif', got %q", record.MIMEType)
	}
}

func TestGetAuditRecord_TimestampIsRecent(t *testing.T) {
	al := NewAuditLogger()

	before := time.Now()
	record := al.GetAuditRecord("req-ts", &AggregatedMediaResult{}, &MediaContent{MIMEType: "image/jpeg"})
	after := time.Now()

	if record.Timestamp.Before(before) || record.Timestamp.After(after) {
		t.Errorf("expected Timestamp between %v and %v, got %v", before, after, record.Timestamp)
	}
}

// --- sanitizeAnalyzerDetails ---

func TestSanitizeAnalyzerDetails_RedactsExtractedText(t *testing.T) {
	results := []MediaAnalysisResult{
		{
			AnalyzerName:  "ocr",
			ExtractedText: "John Doe 123-45-6789",
		},
	}

	sanitized := sanitizeAnalyzerDetails(results)
	if len(sanitized) != 1 {
		t.Fatalf("expected 1 result, got %d", len(sanitized))
	}
	if !strings.Contains(sanitized[0].ExtractedText, "[redacted:") {
		t.Errorf("expected redacted text, got %q", sanitized[0].ExtractedText)
	}
	if strings.Contains(sanitized[0].ExtractedText, "John") {
		t.Error("expected extracted text to be fully redacted")
	}
	// Original should be unchanged
	if results[0].ExtractedText != "John Doe 123-45-6789" {
		t.Error("original results should not be modified")
	}
}

func TestSanitizeAnalyzerDetails_RedactsPIIValues(t *testing.T) {
	results := []MediaAnalysisResult{
		{
			AnalyzerName: "pii-scanner",
			PIIFindings: []PIIFinding{
				{Type: "ssn", Value: "123-45-6789", Confidence: 0.99},
				{Type: "email", Value: "john@example.com", Confidence: 0.95},
			},
		},
	}

	sanitized := sanitizeAnalyzerDetails(results)
	for _, pii := range sanitized[0].PIIFindings {
		if pii.Value != "[redacted]" {
			t.Errorf("expected PII value '[redacted]', got %q", pii.Value)
		}
	}
	// Type and confidence should be preserved
	if sanitized[0].PIIFindings[0].Type != "ssn" {
		t.Errorf("expected PII type 'ssn', got %q", sanitized[0].PIIFindings[0].Type)
	}
	if sanitized[0].PIIFindings[0].Confidence != 0.99 {
		t.Errorf("expected confidence 0.99, got %f", sanitized[0].PIIFindings[0].Confidence)
	}
	// Original should be unchanged
	if results[0].PIIFindings[0].Value != "123-45-6789" {
		t.Error("original PII values should not be modified")
	}
}

func TestSanitizeAnalyzerDetails_PreservesOtherFields(t *testing.T) {
	results := []MediaAnalysisResult{
		{
			AnalyzerName:   "safety",
			AnalyzerType:   AnalyzerTypeAWSRekognition,
			AnalysisTimeMs: 200,
			ContentSafety: &ContentSafetyResult{
				NSFWScore: 0.1,
				IsSafe:    true,
			},
		},
	}

	sanitized := sanitizeAnalyzerDetails(results)
	if sanitized[0].AnalyzerName != "safety" {
		t.Errorf("expected AnalyzerName 'safety', got %q", sanitized[0].AnalyzerName)
	}
	if sanitized[0].AnalyzerType != AnalyzerTypeAWSRekognition {
		t.Errorf("expected AnalyzerType %q, got %q", AnalyzerTypeAWSRekognition, sanitized[0].AnalyzerType)
	}
	if sanitized[0].AnalysisTimeMs != 200 {
		t.Errorf("expected AnalysisTimeMs 200, got %d", sanitized[0].AnalysisTimeMs)
	}
	if sanitized[0].ContentSafety == nil || sanitized[0].ContentSafety.NSFWScore != 0.1 {
		t.Error("expected ContentSafety to be preserved")
	}
}

func TestGetAuditRecord_Enterprise_SanitizesAnalyzerDetails(t *testing.T) {
	al := NewAuditLogger(WithAuditLoggerEnterprise(true))

	result := &AggregatedMediaResult{
		SHA256Hash:  "test-hash",
		ContentSafe: true,
		AnalyzerResults: []MediaAnalysisResult{
			{
				AnalyzerName:  "ocr",
				ExtractedText: "sensitive data here",
				PIIFindings: []PIIFinding{
					{Type: "ssn", Value: "123-45-6789"},
				},
			},
		},
	}
	mc := &MediaContent{MIMEType: "image/png"}

	record := al.GetAuditRecord("req-sanitize", result, mc)

	if len(record.AnalyzerDetails) != 1 {
		t.Fatalf("expected 1 analyzer detail, got %d", len(record.AnalyzerDetails))
	}
	if !strings.Contains(record.AnalyzerDetails[0].ExtractedText, "[redacted:") {
		t.Errorf("expected redacted text in audit record, got %q", record.AnalyzerDetails[0].ExtractedText)
	}
	if record.AnalyzerDetails[0].PIIFindings[0].Value != "[redacted]" {
		t.Errorf("expected redacted PII value in audit record, got %q", record.AnalyzerDetails[0].PIIFindings[0].Value)
	}
	// Original result should be unchanged
	if result.AnalyzerResults[0].ExtractedText != "sensitive data here" {
		t.Error("original result should not be modified by audit")
	}
}
