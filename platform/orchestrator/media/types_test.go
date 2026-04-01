// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package media

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// --- MediaContent.Validate() ---

func TestValidate_EmptySource(t *testing.T) {
	m := MediaContent{
		Source:   "",
		MIMEType: "image/png",
	}
	err := m.Validate()
	if err == nil {
		t.Fatal("expected error for empty source")
	}
	var me *MediaError
	if !errors.As(err, &me) {
		t.Fatalf("expected *MediaError, got %T", err)
	}
	if me.Code != ErrMediaInvalidContent {
		t.Errorf("expected code %s, got %s", ErrMediaInvalidContent, me.Code)
	}
}

func TestValidate_UnsupportedMIMEType(t *testing.T) {
	m := MediaContent{
		Source:   MediaSourceBase64,
		MIMEType: "image/bmp",
	}
	err := m.Validate()
	if err == nil {
		t.Fatal("expected error for unsupported MIME type")
	}
	var me *MediaError
	if !errors.As(err, &me) {
		t.Fatalf("expected *MediaError, got %T", err)
	}
	if me.Code != ErrMediaUnsupportedFormat {
		t.Errorf("expected code %s, got %s", ErrMediaUnsupportedFormat, me.Code)
	}
}

func TestValidate_Base64_EmptyData(t *testing.T) {
	m := MediaContent{
		Source:     MediaSourceBase64,
		MIMEType:  "image/png",
		Base64Data: "",
	}
	err := m.Validate()
	if err == nil {
		t.Fatal("expected error for empty base64_data")
	}
	var me *MediaError
	if !errors.As(err, &me) {
		t.Fatalf("expected *MediaError, got %T", err)
	}
	if me.Code != ErrMediaInvalidContent {
		t.Errorf("expected code %s, got %s", ErrMediaInvalidContent, me.Code)
	}
	if !strings.Contains(me.Message, "base64_data is required") {
		t.Errorf("unexpected message: %s", me.Message)
	}
}

func TestValidate_Base64_InvalidEncoding(t *testing.T) {
	m := MediaContent{
		Source:     MediaSourceBase64,
		MIMEType:  "image/jpeg",
		Base64Data: "this-is-not-valid-base64!!!",
	}
	err := m.Validate()
	if err == nil {
		t.Fatal("expected error for invalid base64")
	}
	var me *MediaError
	if !errors.As(err, &me) {
		t.Fatalf("expected *MediaError, got %T", err)
	}
	if me.Code != ErrMediaInvalidContent {
		t.Errorf("expected code %s, got %s", ErrMediaInvalidContent, me.Code)
	}
	if me.Cause == nil {
		t.Error("expected Cause to be set for invalid base64")
	}
}

func TestValidate_Base64_TooLarge(t *testing.T) {
	// Create data that exceeds MaxImageSizeBytes (20 MB).
	oversized := make([]byte, MaxImageSizeBytes+1)
	encoded := base64.StdEncoding.EncodeToString(oversized)

	m := MediaContent{
		Source:     MediaSourceBase64,
		MIMEType:  "image/png",
		Base64Data: encoded,
	}
	err := m.Validate()
	if err == nil {
		t.Fatal("expected error for oversized base64 data")
	}
	var me *MediaError
	if !errors.As(err, &me) {
		t.Fatalf("expected *MediaError, got %T", err)
	}
	if me.Code != ErrMediaTooLarge {
		t.Errorf("expected code %s, got %s", ErrMediaTooLarge, me.Code)
	}
}

func TestValidate_URL_Empty(t *testing.T) {
	m := MediaContent{
		Source:   MediaSourceURL,
		MIMEType: "image/jpeg",
		URL:      "",
	}
	err := m.Validate()
	if err == nil {
		t.Fatal("expected error for empty URL")
	}
	var me *MediaError
	if !errors.As(err, &me) {
		t.Fatalf("expected *MediaError, got %T", err)
	}
	if me.Code != ErrMediaInvalidContent {
		t.Errorf("expected code %s, got %s", ErrMediaInvalidContent, me.Code)
	}
	if !strings.Contains(me.Message, "url is required") {
		t.Errorf("unexpected message: %s", me.Message)
	}
}

func TestValidate_URL_InvalidScheme(t *testing.T) {
	m := MediaContent{
		Source:   MediaSourceURL,
		MIMEType: "image/png",
		URL:      "ftp://example.com/image.png",
	}
	err := m.Validate()
	if err == nil {
		t.Fatal("expected error for non-http(s) scheme")
	}
	var me *MediaError
	if !errors.As(err, &me) {
		t.Fatalf("expected *MediaError, got %T", err)
	}
	if me.Code != ErrMediaInvalidContent {
		t.Errorf("expected code %s, got %s", ErrMediaInvalidContent, me.Code)
	}
	if !strings.Contains(me.Message, "http or https") {
		t.Errorf("unexpected message: %s", me.Message)
	}
}

func TestValidate_InvalidSourceType(t *testing.T) {
	m := MediaContent{
		Source:   "s3",
		MIMEType: "image/png",
	}
	err := m.Validate()
	if err == nil {
		t.Fatal("expected error for invalid source type")
	}
	var me *MediaError
	if !errors.As(err, &me) {
		t.Fatalf("expected *MediaError, got %T", err)
	}
	if me.Code != ErrMediaInvalidContent {
		t.Errorf("expected code %s, got %s", ErrMediaInvalidContent, me.Code)
	}
	if !strings.Contains(me.Message, "invalid source") {
		t.Errorf("unexpected message: %s", me.Message)
	}
}

func TestValidate_ValidBase64(t *testing.T) {
	data := make([]byte, 128)
	encoded := base64.StdEncoding.EncodeToString(data)

	m := MediaContent{
		Source:     MediaSourceBase64,
		MIMEType:  "image/jpeg",
		Base64Data: encoded,
	}
	if err := m.Validate(); err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
}

func TestValidate_ValidURL(t *testing.T) {
	m := MediaContent{
		Source:   MediaSourceURL,
		MIMEType: "image/webp",
		URL:      "https://example.com/photo.webp",
	}
	if err := m.Validate(); err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
}

func TestValidate_ValidURL_HTTP(t *testing.T) {
	m := MediaContent{
		Source:   MediaSourceURL,
		MIMEType: "image/gif",
		URL:      "http://example.com/animation.gif",
	}
	if err := m.Validate(); err != nil {
		t.Fatalf("expected no error for http URL, got: %v", err)
	}
}

func TestValidate_DimensionExceedsMax(t *testing.T) {
	data := make([]byte, 64)
	encoded := base64.StdEncoding.EncodeToString(data)

	m := MediaContent{
		Source:     MediaSourceBase64,
		MIMEType:  "image/png",
		Base64Data: encoded,
		Metadata: &MediaMetadata{
			Width:  MaxImageDimension + 1,
			Height: 100,
		},
	}
	err := m.Validate()
	if err == nil {
		t.Fatal("expected error for oversized dimensions")
	}
	var me *MediaError
	if !errors.As(err, &me) {
		t.Fatalf("expected *MediaError, got %T", err)
	}
	if me.Code != ErrMediaTooLarge {
		t.Errorf("expected code %s, got %s", ErrMediaTooLarge, me.Code)
	}
}

func TestValidate_DimensionExceedsMax_Height(t *testing.T) {
	data := make([]byte, 64)
	encoded := base64.StdEncoding.EncodeToString(data)

	m := MediaContent{
		Source:     MediaSourceBase64,
		MIMEType:  "image/png",
		Base64Data: encoded,
		Metadata: &MediaMetadata{
			Width:  100,
			Height: MaxImageDimension + 1,
		},
	}
	err := m.Validate()
	if err == nil {
		t.Fatal("expected error for oversized height dimension")
	}
	var me *MediaError
	if !errors.As(err, &me) {
		t.Fatalf("expected *MediaError, got %T", err)
	}
	if me.Code != ErrMediaTooLarge {
		t.Errorf("expected code %s, got %s", ErrMediaTooLarge, me.Code)
	}
}

func TestValidate_DimensionWithinMax(t *testing.T) {
	data := make([]byte, 64)
	encoded := base64.StdEncoding.EncodeToString(data)

	m := MediaContent{
		Source:     MediaSourceBase64,
		MIMEType:  "image/png",
		Base64Data: encoded,
		Metadata: &MediaMetadata{
			Width:  MaxImageDimension,
			Height: MaxImageDimension,
		},
	}
	if err := m.Validate(); err != nil {
		t.Fatalf("expected no error for dimensions at max, got: %v", err)
	}
}

// --- MediaContent.ComputeSHA256() ---

func TestComputeSHA256_Base64(t *testing.T) {
	raw := []byte("test image data for hashing")
	encoded := base64.StdEncoding.EncodeToString(raw)

	m := MediaContent{
		Source:     MediaSourceBase64,
		MIMEType:  "image/png",
		Base64Data: encoded,
	}

	hash, err := m.ComputeSHA256()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expected := sha256.Sum256(raw)
	expectedHex := fmt.Sprintf("%x", expected)
	if hash != expectedHex {
		t.Errorf("hash mismatch: got %s, want %s", hash, expectedHex)
	}

	// Verify metadata was populated.
	if m.Metadata == nil {
		t.Fatal("expected metadata to be populated")
	}
	if m.Metadata.SHA256Hash != expectedHex {
		t.Errorf("metadata SHA256Hash mismatch: got %s, want %s", m.Metadata.SHA256Hash, expectedHex)
	}
	if m.Metadata.FileSizeBytes != int64(len(raw)) {
		t.Errorf("metadata FileSizeBytes mismatch: got %d, want %d", m.Metadata.FileSizeBytes, len(raw))
	}
}

func TestComputeSHA256_URL(t *testing.T) {
	// Use standard HTTP client for test server on loopback
	origClient := ssrfSafeClient
	ssrfSafeClient = &http.Client{Timeout: 5 * time.Second}
	defer func() { ssrfSafeClient = origClient }()
	// Skip pre-flight SSRF check for loopback test server
	origValidate := validateURLForSSRF
	validateURLForSSRF = func(string) error { return nil }
	defer func() { validateURLForSSRF = origValidate }()

	imageData := []byte("test image bytes from URL")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/jpeg")
		w.Write(imageData)
	}))
	defer srv.Close()

	m := MediaContent{
		Source:   MediaSourceURL,
		MIMEType: "image/jpeg",
		URL:      srv.URL + "/img.jpg",
	}

	hash, err := m.ComputeSHA256()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expected := sha256.Sum256(imageData)
	expectedHex := fmt.Sprintf("%x", expected)
	if hash != expectedHex {
		t.Errorf("hash mismatch: got %s, want %s", hash, expectedHex)
	}
	if m.Metadata == nil {
		t.Fatal("expected metadata to be populated")
	}
	if m.Metadata.FileSizeBytes != int64(len(imageData)) {
		t.Errorf("metadata FileSizeBytes mismatch: got %d, want %d", m.Metadata.FileSizeBytes, len(imageData))
	}
}

func TestComputeSHA256_URL_DownloadFails(t *testing.T) {
	m := MediaContent{
		Source:   MediaSourceURL,
		MIMEType: "image/jpeg",
		URL:      "http://127.0.0.1:1/nonexistent",
	}

	_, err := m.ComputeSHA256()
	if err == nil {
		t.Fatal("expected error for unreachable URL")
	}
}

// --- MediaContent.GetRawData() ---

func TestGetRawData_Base64(t *testing.T) {
	raw := []byte("raw image bytes here")
	encoded := base64.StdEncoding.EncodeToString(raw)

	m := MediaContent{
		Source:     MediaSourceBase64,
		MIMEType:  "image/png",
		Base64Data: encoded,
	}

	data, err := m.GetRawData()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(data) != string(raw) {
		t.Errorf("data mismatch: got %q, want %q", data, raw)
	}
}

func TestGetRawData_URL(t *testing.T) {
	// Use standard HTTP client for test server on loopback
	origClient := ssrfSafeClient
	ssrfSafeClient = &http.Client{Timeout: 5 * time.Second}
	defer func() { ssrfSafeClient = origClient }()
	// Skip pre-flight SSRF check for loopback test server
	origValidate := validateURLForSSRF
	validateURLForSSRF = func(string) error { return nil }
	defer func() { validateURLForSSRF = origValidate }()

	imageData := []byte("raw URL image content")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		w.Write(imageData)
	}))
	defer srv.Close()

	m := MediaContent{
		Source:   MediaSourceURL,
		MIMEType: "image/png",
		URL:      srv.URL + "/img.png",
	}

	data, err := m.GetRawData()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(data) != string(imageData) {
		t.Errorf("data mismatch: got %q, want %q", data, imageData)
	}

	// Second call should return cached data
	data2, err := m.GetRawData()
	if err != nil {
		t.Fatalf("unexpected error on cached call: %v", err)
	}
	if string(data2) != string(imageData) {
		t.Errorf("cached data mismatch")
	}
}

func TestGetRawData_URL_DownloadFails(t *testing.T) {
	m := MediaContent{
		Source:   MediaSourceURL,
		MIMEType: "image/jpeg",
		URL:      "http://127.0.0.1:1/nonexistent",
	}

	_, err := m.GetRawData()
	if err == nil {
		t.Fatal("expected error for unreachable URL")
	}
	var me *MediaError
	if !errors.As(err, &me) {
		t.Fatalf("expected *MediaError, got %T", err)
	}
	if me.Code != ErrMediaDownloadFailed {
		t.Errorf("expected code %s, got %s", ErrMediaDownloadFailed, me.Code)
	}
}

// --- ValidateMediaList() ---

func TestValidateMediaList_TooManyItems(t *testing.T) {
	items := make([]MediaContent, MaxMediaPerRequest+1)
	err := ValidateMediaList(items)
	if err == nil {
		t.Fatal("expected error for too many media items")
	}
	var me *MediaError
	if !errors.As(err, &me) {
		t.Fatalf("expected *MediaError, got %T", err)
	}
	if me.Code != ErrMediaTooLarge {
		t.Errorf("expected code %s, got %s", ErrMediaTooLarge, me.Code)
	}
}

func TestValidateMediaList_ValidList(t *testing.T) {
	data := make([]byte, 64)
	encoded := base64.StdEncoding.EncodeToString(data)

	items := []MediaContent{
		{
			Source:     MediaSourceBase64,
			MIMEType:  "image/png",
			Base64Data: encoded,
		},
		{
			Source:   MediaSourceURL,
			MIMEType: "image/jpeg",
			URL:      "https://example.com/photo.jpg",
		},
	}
	if err := ValidateMediaList(items); err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
}

func TestValidateMediaList_ItemValidationError(t *testing.T) {
	data := make([]byte, 64)
	encoded := base64.StdEncoding.EncodeToString(data)

	items := []MediaContent{
		{
			Source:     MediaSourceBase64,
			MIMEType:  "image/png",
			Base64Data: encoded,
		},
		{
			// Invalid: missing source
			Source:   "",
			MIMEType: "image/png",
		},
	}
	err := ValidateMediaList(items)
	if err == nil {
		t.Fatal("expected error for invalid item in list")
	}
	if !strings.Contains(err.Error(), "media[1]") {
		t.Errorf("expected error to reference media[1], got: %v", err)
	}
}

// --- IsSensitiveDocType() ---

func TestIsSensitiveDocType_KnownSensitive(t *testing.T) {
	sensitiveTypes := []string{
		"id_card",
		"passport",
		"drivers_license",
		"bank_statement",
		"tax_document",
		"medical_record",
		"insurance_card",
		"credit_card",
		"social_security",
		"birth_certificate",
	}
	for _, dt := range sensitiveTypes {
		if !IsSensitiveDocType(dt) {
			t.Errorf("expected %q to be sensitive", dt)
		}
	}
}

func TestIsSensitiveDocType_CaseInsensitive(t *testing.T) {
	if !IsSensitiveDocType("PASSPORT") {
		t.Error("expected PASSPORT (uppercase) to be sensitive")
	}
	if !IsSensitiveDocType("Id_Card") {
		t.Error("expected Id_Card (mixed case) to be sensitive")
	}
}

func TestIsSensitiveDocType_NonSensitive(t *testing.T) {
	nonSensitive := []string{
		"receipt",
		"invoice",
		"letter",
		"photo",
		"",
	}
	for _, dt := range nonSensitive {
		if IsSensitiveDocType(dt) {
			t.Errorf("expected %q to NOT be sensitive", dt)
		}
	}
}

// --- MediaError ---

func TestMediaError_ErrorWithoutCause(t *testing.T) {
	e := &MediaError{
		Code:    ErrMediaInvalidContent,
		Message: "something went wrong",
	}
	expected := "media error [media_invalid_content]: something went wrong"
	if e.Error() != expected {
		t.Errorf("got %q, want %q", e.Error(), expected)
	}
}

func TestMediaError_ErrorWithCause(t *testing.T) {
	cause := fmt.Errorf("underlying problem")
	e := &MediaError{
		Code:    ErrMediaAnalysisFailed,
		Message: "analysis failed",
		Cause:   cause,
	}
	expected := "media error [media_analysis_failed]: analysis failed: underlying problem"
	if e.Error() != expected {
		t.Errorf("got %q, want %q", e.Error(), expected)
	}
}

func TestMediaError_Unwrap(t *testing.T) {
	cause := fmt.Errorf("root cause")
	e := &MediaError{
		Code:    ErrMediaInvalidContent,
		Message: "wrapped",
		Cause:   cause,
	}
	if e.Unwrap() != cause {
		t.Errorf("Unwrap() returned wrong error: got %v, want %v", e.Unwrap(), cause)
	}
}

func TestMediaError_UnwrapNil(t *testing.T) {
	e := &MediaError{
		Code:    ErrMediaInvalidContent,
		Message: "no cause",
	}
	if e.Unwrap() != nil {
		t.Errorf("expected Unwrap() to return nil, got %v", e.Unwrap())
	}
}

// --- MediaWarning ---

func TestMediaWarning_String(t *testing.T) {
	w := MediaWarning{Code: WarnMediaAnalyzerError, Message: "analyzer timed out"}
	expected := "[media_analyzer_error] analyzer timed out"
	if w.String() != expected {
		t.Errorf("got %q, want %q", w.String(), expected)
	}
}

func TestAggregatedMediaResult_AddWarning(t *testing.T) {
	r := &AggregatedMediaResult{}
	r.AddWarning(WarnMediaNoAnalyzers, "no analyzers available")
	r.AddWarning(WarnMediaOCRFailed, "OCR timed out")

	if len(r.Warnings) != 2 {
		t.Fatalf("expected 2 warnings, got %d", len(r.Warnings))
	}
	if len(r.StructuredWarnings) != 2 {
		t.Fatalf("expected 2 structured warnings, got %d", len(r.StructuredWarnings))
	}
	if r.StructuredWarnings[0].Code != WarnMediaNoAnalyzers {
		t.Errorf("expected code %s, got %s", WarnMediaNoAnalyzers, r.StructuredWarnings[0].Code)
	}
	if r.StructuredWarnings[1].Code != WarnMediaOCRFailed {
		t.Errorf("expected code %s, got %s", WarnMediaOCRFailed, r.StructuredWarnings[1].Code)
	}
	// Verify backward-compatible string warnings contain the structured format
	if !strings.Contains(r.Warnings[0], WarnMediaNoAnalyzers) {
		t.Errorf("expected warning string to contain code, got %q", r.Warnings[0])
	}
}

// --- Pre-decode base64 size check ---

func TestValidate_Base64_PreDecodeRejectsOversized(t *testing.T) {
	// Create a base64 string that is clearly oversized without needing actual decode.
	// MaxImageSizeBytes = 20MB, so base64 encoding of that would be ~28MB of base64 chars.
	// We create a string large enough that estimated size > MaxImageSizeBytes.
	oversizedB64Len := (MaxImageSizeBytes * 4 / 3) + 100
	bigString := strings.Repeat("A", int(oversizedB64Len))

	m := MediaContent{
		Source:     MediaSourceBase64,
		MIMEType:  "image/png",
		Base64Data: bigString,
	}
	err := m.Validate()
	if err == nil {
		t.Fatal("expected error for oversized base64 (pre-decode)")
	}
	var me *MediaError
	if !errors.As(err, &me) {
		t.Fatalf("expected *MediaError, got %T", err)
	}
	if me.Code != ErrMediaTooLarge {
		t.Errorf("expected code %s, got %s", ErrMediaTooLarge, me.Code)
	}
	if !strings.Contains(me.Message, "estimated") {
		t.Errorf("expected pre-decode (estimated) error message, got %q", me.Message)
	}
}

// --- Base64 rawData cache ---

func TestGetRawData_Base64_UsesCachedData(t *testing.T) {
	raw := []byte("cached raw data test")
	encoded := base64.StdEncoding.EncodeToString(raw)

	m := MediaContent{
		Source:     MediaSourceBase64,
		MIMEType:  "image/jpeg",
		Base64Data: encoded,
	}

	// After Validate(), rawData should be cached
	if err := m.Validate(); err != nil {
		t.Fatalf("unexpected validation error: %v", err)
	}

	// GetRawData should return cached data without re-decoding
	data, err := m.GetRawData()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(data) != string(raw) {
		t.Errorf("data mismatch: got %q, want %q", data, raw)
	}
}

func TestComputeSHA256_Base64_UsesCachedData(t *testing.T) {
	raw := []byte("test data for sha256 cache")
	encoded := base64.StdEncoding.EncodeToString(raw)

	m := MediaContent{
		Source:     MediaSourceBase64,
		MIMEType:  "image/png",
		Base64Data: encoded,
	}

	// Validate to populate cache
	if err := m.Validate(); err != nil {
		t.Fatalf("unexpected validation error: %v", err)
	}

	// ComputeSHA256 should use cached rawData
	hash, err := m.ComputeSHA256()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	expected := fmt.Sprintf("%x", sha256.Sum256(raw))
	if hash != expected {
		t.Errorf("hash mismatch: got %s, want %s", hash, expected)
	}
}

// --- Decompression bomb ---

func TestCheckPixelCount_ValidImage(t *testing.T) {
	// Create a minimal valid 1x1 PNG
	img := createTestPNG(1, 1)
	if err := checkPixelCount(img, "image/png"); err != nil {
		t.Fatalf("unexpected error for 1x1 image: %v", err)
	}
}

func TestCheckPixelCount_InvalidImage(t *testing.T) {
	// Non-image data should fail open (no error)
	if err := checkPixelCount([]byte("not an image"), "image/png"); err != nil {
		t.Fatalf("expected fail-open for non-parseable data, got: %v", err)
	}
}

func TestValidate_Base64_DecompressionBomb(t *testing.T) {
	// Create a PNG with headers indicating an absurdly large image.
	// We'll craft a minimal PNG IHDR chunk with huge dimensions.
	bomb := createBombPNG(20000, 20000) // 400M pixels > MaxPixelCount
	encoded := base64.StdEncoding.EncodeToString(bomb)

	m := MediaContent{
		Source:     MediaSourceBase64,
		MIMEType:  "image/png",
		Base64Data: encoded,
	}
	err := m.Validate()
	if err == nil {
		t.Fatal("expected error for decompression bomb")
	}
	var me *MediaError
	if !errors.As(err, &me) {
		t.Fatalf("expected *MediaError, got %T", err)
	}
	if me.Code != ErrMediaDecompressionBomb {
		t.Errorf("expected code %s, got %s", ErrMediaDecompressionBomb, me.Code)
	}

	// Verify rawData was nil'd out
	if m.rawData != nil {
		t.Error("expected rawData to be nil after decompression bomb rejection")
	}
}

// createTestPNG creates a minimal valid PNG with the given dimensions.
func createTestPNG(width, height int) []byte {
	return createBombPNG(width, height)
}

// createBombPNG creates a minimal PNG with specified dimensions in the IHDR chunk.
// The image data is empty/minimal — only headers matter for DecodeConfig.
func createBombPNG(width, height int) []byte {
	var buf bytes.Buffer
	// PNG signature
	buf.Write([]byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A})

	// IHDR chunk (13 bytes data)
	ihdr := []byte{
		byte(width >> 24), byte(width >> 16), byte(width >> 8), byte(width),
		byte(height >> 24), byte(height >> 16), byte(height >> 8), byte(height),
		8,    // bit depth
		2,    // color type (RGB)
		0,    // compression
		0,    // filter
		0,    // interlace
	}
	writeChunk(&buf, "IHDR", ihdr)

	// IEND chunk (empty)
	writeChunk(&buf, "IEND", nil)

	return buf.Bytes()
}

// writeChunk writes a PNG chunk to the buffer.
func writeChunk(buf *bytes.Buffer, chunkType string, data []byte) {
	// Length (4 bytes)
	l := len(data)
	buf.Write([]byte{byte(l >> 24), byte(l >> 16), byte(l >> 8), byte(l)})
	// Type (4 bytes)
	buf.WriteString(chunkType)
	// Data
	buf.Write(data)
	// CRC32 (we compute a simple one — Go's image.DecodeConfig is lenient)
	crc := crc32PNG(append([]byte(chunkType), data...))
	buf.Write([]byte{byte(crc >> 24), byte(crc >> 16), byte(crc >> 8), byte(crc)})
}

// --- SSRF protection ---

func TestIsPrivateIP(t *testing.T) {
	tests := []struct {
		ip      string
		private bool
	}{
		{"127.0.0.1", true},
		{"10.0.0.1", true},
		{"172.16.0.1", true},
		{"192.168.1.1", true},
		{"169.254.169.254", true}, // AWS metadata
		{"0.0.0.0", true},
		{"::1", true},
		{"8.8.8.8", false},
		{"1.2.3.4", false},
	}
	for _, tt := range tests {
		ip := net.ParseIP(tt.ip)
		if ip == nil {
			t.Fatalf("failed to parse IP: %s", tt.ip)
		}
		got := isPrivateIP(ip)
		if got != tt.private {
			t.Errorf("isPrivateIP(%s) = %v, want %v", tt.ip, got, tt.private)
		}
	}
}

func TestFetchURLData_BlocksLoopback(t *testing.T) {
	m := MediaContent{
		Source:   MediaSourceURL,
		MIMEType: "image/jpeg",
		URL:      "http://127.0.0.1:8080/evil.jpg",
	}

	_, err := m.fetchURLData(context.Background())
	if err == nil {
		t.Fatal("expected SSRF protection to block loopback URL")
	}
	if !strings.Contains(err.Error(), "private/internal IP") {
		t.Errorf("expected SSRF error message, got: %v", err)
	}
}

func TestFetchURLData_BlocksPrivateIP(t *testing.T) {
	m := MediaContent{
		Source:   MediaSourceURL,
		MIMEType: "image/jpeg",
		URL:      "http://10.0.0.1:8080/internal.jpg",
	}

	_, err := m.fetchURLData(context.Background())
	if err == nil {
		t.Fatal("expected SSRF protection to block private IP")
	}
	if !strings.Contains(err.Error(), "private/internal IP") {
		t.Errorf("expected SSRF error message, got: %v", err)
	}
}

// crc32PNG computes CRC32 for a PNG chunk (type + data).
func crc32PNG(data []byte) uint32 {
	// Using the standard CRC-32 used by PNG
	var table [256]uint32
	for i := 0; i < 256; i++ {
		c := uint32(i)
		for j := 0; j < 8; j++ {
			if c&1 != 0 {
				c = 0xEDB88320 ^ (c >> 1)
			} else {
				c >>= 1
			}
		}
		table[i] = c
	}
	crc := uint32(0xFFFFFFFF)
	for _, b := range data {
		crc = table[(crc^uint32(b))&0xFF] ^ (crc >> 8)
	}
	return crc ^ 0xFFFFFFFF
}
