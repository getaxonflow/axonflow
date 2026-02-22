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
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"image"
	_ "image/gif"
	_ "image/jpeg"
	_ "image/png"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"syscall"
	"time"

	_ "golang.org/x/image/webp"
)

// Constants for media validation.
const (
	// MaxImageSizeBytes is the maximum allowed image size (20MB).
	MaxImageSizeBytes = 20 * 1024 * 1024

	// MaxImageDimension is the maximum allowed width or height in pixels.
	MaxImageDimension = 8192

	// MaxMediaPerRequest is the maximum number of media items per request.
	MaxMediaPerRequest = 10

	// MaxPixelCount is the maximum total pixel count allowed (width * height).
	// Prevents decompression bombs where small files decompress into huge pixel buffers.
	MaxPixelCount = 100_000_000
)

// Supported MIME types for image content.
var SupportedMIMETypes = map[string]bool{
	"image/jpeg": true,
	"image/png":  true,
	"image/gif":  true,
	"image/webp": true,
}

// MediaSourceType identifies how the media content is provided.
type MediaSourceType string

const (
	// MediaSourceBase64 indicates the content is inline base64-encoded.
	MediaSourceBase64 MediaSourceType = "base64"

	// MediaSourceURL indicates the content is referenced by URL.
	MediaSourceURL MediaSourceType = "url"
)

// MediaContent represents a single media item (image) in a request.
type MediaContent struct {
	// Source indicates how the media is provided: "base64" or "url".
	Source MediaSourceType `json:"source"`

	// Base64Data contains the base64-encoded image data (when Source=base64).
	Base64Data string `json:"base64_data,omitempty"`

	// URL contains the image URL (when Source=url).
	URL string `json:"url,omitempty"`

	// MIMEType is the media content type (e.g., "image/jpeg").
	MIMEType string `json:"mime_type"`

	// Metadata contains optional metadata about the image.
	Metadata *MediaMetadata `json:"metadata,omitempty"`

	// rawData caches downloaded bytes for URL sources (not serialized).
	rawData []byte `json:"-"`
}

// MediaMetadata contains optional metadata about a media item.
type MediaMetadata struct {
	// Width is the image width in pixels.
	Width int `json:"width,omitempty"`

	// Height is the image height in pixels.
	Height int `json:"height,omitempty"`

	// FileSizeBytes is the raw file size.
	FileSizeBytes int64 `json:"file_size_bytes,omitempty"`

	// SHA256Hash is the hex-encoded SHA-256 hash of the raw image data.
	SHA256Hash string `json:"sha256_hash,omitempty"`

	// FileName is the original file name, if known.
	FileName string `json:"file_name,omitempty"`
}

// Validate checks the media content for correctness.
func (m *MediaContent) Validate() error {
	if m.Source == "" {
		return &MediaError{Code: ErrMediaInvalidContent, Message: "source is required"}
	}

	if !SupportedMIMETypes[m.MIMEType] {
		return &MediaError{
			Code:    ErrMediaUnsupportedFormat,
			Message: fmt.Sprintf("unsupported MIME type %q; supported: image/jpeg, image/png, image/gif, image/webp", m.MIMEType),
		}
	}

	switch m.Source {
	case MediaSourceBase64:
		if m.Base64Data == "" {
			return &MediaError{Code: ErrMediaInvalidContent, Message: "base64_data is required when source is base64"}
		}
		// Pre-decode size estimate to reject obviously oversized payloads without decoding
		estimatedSize := int64(len(m.Base64Data)) * 3 / 4
		if estimatedSize > MaxImageSizeBytes {
			return &MediaError{
				Code:    ErrMediaTooLarge,
				Message: fmt.Sprintf("estimated image size %d bytes exceeds maximum %d bytes", estimatedSize, MaxImageSizeBytes),
			}
		}
		// Validate base64 encoding and check exact size
		decoded, err := base64.StdEncoding.DecodeString(m.Base64Data)
		if err != nil {
			return &MediaError{Code: ErrMediaInvalidContent, Message: "invalid base64 encoding", Cause: err}
		}
		if int64(len(decoded)) > MaxImageSizeBytes {
			return &MediaError{
				Code:    ErrMediaTooLarge,
				Message: fmt.Sprintf("image size %d bytes exceeds maximum %d bytes", len(decoded), MaxImageSizeBytes),
			}
		}
		// Cache decoded bytes to avoid redundant base64 decoding
		m.rawData = decoded
		// Check for decompression bomb (pixel buffer overflow)
		if err := checkPixelCount(decoded, m.MIMEType); err != nil {
			m.rawData = nil
			return err
		}

	case MediaSourceURL:
		if m.URL == "" {
			return &MediaError{Code: ErrMediaInvalidContent, Message: "url is required when source is url"}
		}
		parsed, err := url.Parse(m.URL)
		if err != nil {
			return &MediaError{Code: ErrMediaInvalidContent, Message: "invalid URL", Cause: err}
		}
		if parsed.Scheme != "https" && parsed.Scheme != "http" {
			return &MediaError{Code: ErrMediaInvalidContent, Message: "URL must use http or https scheme"}
		}

	default:
		return &MediaError{
			Code:    ErrMediaInvalidContent,
			Message: fmt.Sprintf("invalid source %q; must be \"base64\" or \"url\"", m.Source),
		}
	}

	// Validate dimensions if provided
	if m.Metadata != nil {
		if m.Metadata.Width > MaxImageDimension || m.Metadata.Height > MaxImageDimension {
			return &MediaError{
				Code:    ErrMediaTooLarge,
				Message: fmt.Sprintf("image dimensions %dx%d exceed maximum %d", m.Metadata.Width, m.Metadata.Height, MaxImageDimension),
			}
		}
	}

	return nil
}

// ComputeSHA256 computes and stores the SHA-256 hash of the raw image data.
// For base64 sources, it decodes and hashes the data.
// For URL sources, it downloads the image and hashes the data.
func (m *MediaContent) ComputeSHA256() (string, error) {
	var data []byte
	var err error

	switch m.Source {
	case MediaSourceBase64:
		if m.rawData != nil {
			data = m.rawData
		} else {
			data, err = base64.StdEncoding.DecodeString(m.Base64Data)
			if err != nil {
				return "", fmt.Errorf("failed to decode base64: %w", err)
			}
		}
	case MediaSourceURL:
		data, err = m.fetchURLData(context.Background())
		if err != nil {
			return "", fmt.Errorf("failed to fetch URL: %w", err)
		}
	default:
		return "", nil
	}

	hash := sha256.Sum256(data)
	hexHash := fmt.Sprintf("%x", hash)

	if m.Metadata == nil {
		m.Metadata = &MediaMetadata{}
	}
	m.Metadata.SHA256Hash = hexHash
	m.Metadata.FileSizeBytes = int64(len(data))

	return hexHash, nil
}

// GetRawData returns the decoded raw image bytes.
// For base64 sources, it decodes the base64 data.
// For URL sources, it downloads the image (cached after first fetch).
func (m *MediaContent) GetRawData() ([]byte, error) {
	switch m.Source {
	case MediaSourceBase64:
		if m.rawData != nil {
			return m.rawData, nil
		}
		return base64.StdEncoding.DecodeString(m.Base64Data)
	case MediaSourceURL:
		return m.fetchURLData(context.Background())
	default:
		return nil, &MediaError{Code: ErrMediaInvalidContent, Message: "unsupported media source type"}
	}
}

// isPrivateIP returns true if the IP is loopback, private, link-local, or unspecified.
// Used to block SSRF attacks when fetching user-supplied URLs.
func isPrivateIP(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsUnspecified()
}

// ssrfSafeClient is an HTTP client that blocks connections to private/internal IP ranges.
// The net.Dialer.Control callback inspects the resolved IP at the socket level,
// preventing DNS rebinding and redirect-based SSRF attacks.
var ssrfSafeClient = newSSRFSafeClient()

func newSSRFSafeClient() *http.Client {
	dialer := &net.Dialer{
		Timeout: 10 * time.Second,
		Control: func(network, address string, c syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return err
			}
			// Strip IPv6 zone ID (e.g. "%eth0") before parsing
			if idx := strings.Index(host, "%"); idx != -1 {
				host = host[:idx]
			}
			ip := net.ParseIP(host)
			if ip == nil {
				// If we can't parse the IP at all, block it (fail closed)
				return &MediaError{
					Code:    ErrMediaDownloadFailed,
					Message: fmt.Sprintf("could not parse resolved address %q; request blocked for security", address),
				}
			}
			if isPrivateIP(ip) {
				return &MediaError{
					Code:    ErrMediaDownloadFailed,
					Message: fmt.Sprintf("URL resolves to private/internal IP %s; request blocked for security", ip),
				}
			}
			return nil
		},
	}
	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			DialContext: dialer.DialContext,
		},
	}
}

// fetchURLData downloads URL content with caching. Subsequent calls return cached data.
// The provided context is used for request cancellation and deadline propagation.
func (m *MediaContent) fetchURLData(ctx context.Context) ([]byte, error) {
	if m.rawData != nil {
		return m.rawData, nil
	}

	if m.URL == "" {
		return nil, &MediaError{Code: ErrMediaInvalidContent, Message: "URL is empty"}
	}

	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, m.URL, nil)
	if err != nil {
		return nil, &MediaError{Code: ErrMediaDownloadFailed, Message: fmt.Sprintf("failed to create request: %v", err)}
	}

	resp, err := ssrfSafeClient.Do(req)
	if err != nil {
		return nil, &MediaError{Code: ErrMediaDownloadFailed, Message: fmt.Sprintf("failed to download: %v", err)}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, &MediaError{Code: ErrMediaDownloadFailed, Message: fmt.Sprintf("download returned status %d", resp.StatusCode)}
	}

	// Limit to MaxImageSizeBytes to prevent memory exhaustion
	data, err := io.ReadAll(io.LimitReader(resp.Body, MaxImageSizeBytes+1))
	if err != nil {
		return nil, &MediaError{Code: ErrMediaDownloadFailed, Message: fmt.Sprintf("failed to read response: %v", err)}
	}

	if int64(len(data)) > MaxImageSizeBytes {
		return nil, &MediaError{Code: ErrMediaTooLarge, Message: fmt.Sprintf("downloaded file exceeds %d bytes", MaxImageSizeBytes)}
	}

	// Check for decompression bomb
	if err := checkPixelCount(data, m.MIMEType); err != nil {
		return nil, err
	}

	m.rawData = data
	return data, nil
}

// MediaAnalyzerType identifies the type of media analyzer.
type MediaAnalyzerType string

const (
	AnalyzerTypeLocalOCR       MediaAnalyzerType = "local-ocr"
	AnalyzerTypeAWSRekognition MediaAnalyzerType = "aws-rekognition"
	AnalyzerTypeGoogleVision   MediaAnalyzerType = "google-vision"
	AnalyzerTypeAzureVision    MediaAnalyzerType = "azure-vision"
	AnalyzerTypeCustom         MediaAnalyzerType = "custom"
)

// MediaAnalyzerCapability represents a specific analysis capability.
type MediaAnalyzerCapability string

const (
	CapabilityOCR                    MediaAnalyzerCapability = "ocr"
	CapabilityFaceDetection          MediaAnalyzerCapability = "face_detection"
	CapabilityContentSafety          MediaAnalyzerCapability = "content_safety"
	CapabilityDocumentClassification MediaAnalyzerCapability = "document_classification"
	CapabilityLabelDetection         MediaAnalyzerCapability = "label_detection"
	CapabilityPIIDetection           MediaAnalyzerCapability = "pii_detection"
)

// MediaAnalysisResult contains the result of analyzing a single media item
// with a single analyzer.
type MediaAnalysisResult struct {
	// AnalyzerName is the name of the analyzer that produced this result.
	AnalyzerName string `json:"analyzer_name"`

	// AnalyzerType is the type of analyzer.
	AnalyzerType MediaAnalyzerType `json:"analyzer_type"`

	// ExtractedText is text extracted via OCR.
	ExtractedText string `json:"extracted_text,omitempty"`

	// Faces contains detected face information.
	Faces []FaceDetection `json:"faces,omitempty"`

	// ContentSafety contains content safety scores.
	ContentSafety *ContentSafetyResult `json:"content_safety,omitempty"`

	// DocumentClassification contains document type classification.
	DocumentClassification *DocumentClassification `json:"document_classification,omitempty"`

	// Labels are detected content labels.
	Labels []ContentLabel `json:"labels,omitempty"`

	// PIIFindings contains PII detected in extracted text.
	PIIFindings []PIIFinding `json:"pii_findings,omitempty"`

	// AnalysisTimeMs is how long the analysis took.
	AnalysisTimeMs int64 `json:"analysis_time_ms"`

	// EstimatedCostUSD is the estimated cost of this analysis.
	EstimatedCostUSD float64 `json:"estimated_cost_usd,omitempty"`

	// Error contains any error that occurred during analysis.
	Error string `json:"error,omitempty"`
}

// FaceDetection represents a detected face in an image.
type FaceDetection struct {
	Confidence     float64 `json:"confidence"`
	BoundingBox    *Box    `json:"bounding_box,omitempty"`
	IsBiometric    bool    `json:"is_biometric"`
	AgeRange       string  `json:"age_range,omitempty"`
	HasSunglasses  bool    `json:"has_sunglasses,omitempty"`
	HasEyeglasses  bool    `json:"has_eyeglasses,omitempty"`
}

// Box represents a bounding box.
type Box struct {
	Left   float64 `json:"left"`
	Top    float64 `json:"top"`
	Width  float64 `json:"width"`
	Height float64 `json:"height"`
}

// ContentSafetyResult contains content safety scores.
type ContentSafetyResult struct {
	NSFWScore     float64 `json:"nsfw_score"`
	ViolenceScore float64 `json:"violence_score"`
	HateScore     float64 `json:"hate_score,omitempty"`
	SelfHarmScore float64 `json:"self_harm_score,omitempty"`
	IsSafe        bool    `json:"is_safe"`
}

// DocumentClassification identifies the type of document in an image.
type DocumentClassification struct {
	DocumentType string  `json:"document_type"`
	Confidence   float64 `json:"confidence"`
	IsSensitive  bool    `json:"is_sensitive"`
}

// Sensitive document types.
var SensitiveDocumentTypes = map[string]bool{
	"id_card":            true,
	"passport":           true,
	"drivers_license":    true,
	"bank_statement":     true,
	"tax_document":       true,
	"medical_record":     true,
	"insurance_card":     true,
	"credit_card":        true,
	"social_security":    true,
	"birth_certificate":  true,
}

// ContentLabel is a detected label/tag for the image content.
type ContentLabel struct {
	Name       string  `json:"name"`
	Confidence float64 `json:"confidence"`
}

// PIIFinding represents a PII detection in extracted text.
type PIIFinding struct {
	Type       string  `json:"type"`
	Value      string  `json:"value,omitempty"`
	Redacted   string  `json:"redacted,omitempty"`
	Confidence float64 `json:"confidence"`
	StartIndex int     `json:"start_index"`
	EndIndex   int     `json:"end_index"`
}

// AggregatedMediaResult merges results from all analyzers for a single media item.
type AggregatedMediaResult struct {
	// MediaIndex is the index of the media item in the request.
	MediaIndex int `json:"media_index"`

	// SHA256Hash is the hex-encoded SHA-256 hash of the image data.
	SHA256Hash string `json:"sha256_hash"`

	// AnalyzerResults contains per-analyzer results.
	AnalyzerResults []MediaAnalysisResult `json:"analyzer_results"`

	// Governance signals (aggregated from all analyzers)
	HasFaces            bool     `json:"has_faces"`
	FaceCount           int      `json:"face_count"`
	HasBiometricData    bool     `json:"has_biometric_data"`
	NSFWScore           float64  `json:"nsfw_score"`
	ViolenceScore       float64  `json:"violence_score"`
	ContentSafe         bool     `json:"content_safe"`
	DocumentType        string   `json:"document_type,omitempty"`
	IsSensitiveDocument bool     `json:"is_sensitive_document"`
	HasPII              bool     `json:"has_pii"`
	PIITypes            []string `json:"pii_types,omitempty"`
	ExtractedText       string   `json:"extracted_text,omitempty"`

	// Cost estimation (aggregate at all tiers)
	EstimatedCostUSD float64 `json:"estimated_cost_usd"`

	// Enforcement result
	Warnings           []string       `json:"warnings,omitempty"`
	StructuredWarnings []MediaWarning `json:"structured_warnings,omitempty"`

	// AnalysisTimeMs is the total time for all analyzers.
	AnalysisTimeMs int64 `json:"analysis_time_ms"`
}

// AddWarning appends a structured warning and its string representation for backward compatibility.
func (r *AggregatedMediaResult) AddWarning(code, message string) {
	w := MediaWarning{Code: code, Message: message}
	r.Warnings = append(r.Warnings, w.String())
	r.StructuredWarnings = append(r.StructuredWarnings, w)
}

// MediaAuditRecord captures audit information for a media analysis.
// Community stores hash + results summary.
// Enterprise adds per-analyzer metadata, biometric flags, extended retention.
type MediaAuditRecord struct {
	// Core fields (all tiers)
	RequestID      string    `json:"request_id"`
	MediaIndex     int       `json:"media_index"`
	SHA256Hash     string    `json:"sha256_hash"`
	MIMEType       string    `json:"mime_type"`
	FileSizeBytes  int64     `json:"file_size_bytes"`
	AnalyzerCount  int       `json:"analyzer_count"`
	HasPII         bool      `json:"has_pii"`
	PIITypes       []string  `json:"pii_types,omitempty"`
	ContentSafe    bool      `json:"content_safe"`
	Warnings       []string  `json:"warnings,omitempty"`
	AnalysisTimeMs int64     `json:"analysis_time_ms"`
	Timestamp      time.Time `json:"timestamp"`

	// Enterprise-only fields
	HasFaces         bool                  `json:"has_faces,omitempty"`
	FaceCount        int                   `json:"face_count,omitempty"`
	HasBiometricData bool                  `json:"has_biometric_data,omitempty"`
	NSFWScore        float64               `json:"nsfw_score,omitempty"`
	ViolenceScore    float64               `json:"violence_score,omitempty"`
	DocumentType     string                `json:"document_type,omitempty"`
	AnalyzerDetails  []MediaAnalysisResult `json:"analyzer_details,omitempty"`
}

// EnforcementStrategy controls how media analysis results are enforced.
type EnforcementStrategy string

const (
	// EnforcementFailOpen logs warnings but allows the request to proceed.
	// This is the default for Community tier.
	EnforcementFailOpen EnforcementStrategy = "fail_open"

	// EnforcementFailClosed blocks requests that violate media policies.
	// Available in Enterprise tier only.
	EnforcementFailClosed EnforcementStrategy = "fail_closed"
)

// MediaError represents an error from media operations.
type MediaError struct {
	Code    string
	Message string
	Cause   error
}

// Media error codes.
const (
	ErrMediaInvalidContent    = "media_invalid_content"
	ErrMediaTooLarge          = "media_too_large"
	ErrMediaUnsupportedFormat = "media_unsupported_format"
	ErrMediaAnalysisFailed    = "media_analysis_failed"
	ErrMediaDownloadFailed    = "media_download_failed"
	ErrMediaPolicyViolation   = "media_policy_violation"
	ErrMediaAnalyzerLimit     = "media_analyzer_limit"
	ErrMediaAnalyzerNotFound      = "media_analyzer_not_found"
	ErrMediaDecompressionBomb     = "media_decompression_bomb"
)

// Warning codes for non-fatal media analysis issues.
const (
	WarnMediaAnalysisFailed     = "media_analysis_failed"
	WarnMediaAnalyzerError      = "media_analyzer_error"
	WarnMediaAnalyzerTimeout    = "media_analyzer_timeout"
	WarnMediaNoAnalyzers        = "media_no_analyzers"
	WarnMediaOCRFailed          = "media_ocr_failed"
	WarnMediaPartialResults     = "media_partial_results"
	WarnMediaGetAnalyzersFailed = "media_get_analyzers_failed"
)

// MediaWarning represents a structured warning from media analysis.
type MediaWarning struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// String returns a human-readable representation of the warning.
func (w MediaWarning) String() string {
	return fmt.Sprintf("[%s] %s", w.Code, w.Message)
}

// Error implements the error interface.
func (e *MediaError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("media error [%s]: %s: %v", e.Code, e.Message, e.Cause)
	}
	return fmt.Sprintf("media error [%s]: %s", e.Code, e.Message)
}

// Unwrap returns the underlying error.
func (e *MediaError) Unwrap() error {
	return e.Cause
}

// checkPixelCount decodes image headers to check total pixel count against MaxPixelCount.
// Fails open on decode errors (unknown/corrupt headers are skipped).
func checkPixelCount(data []byte, mimeType string) error {
	cfg, _, err := image.DecodeConfig(bytes.NewReader(data))
	if err != nil {
		// Fail open: if we can't parse the image header, skip the check
		return nil
	}
	pixelCount := int64(cfg.Width) * int64(cfg.Height)
	if pixelCount > MaxPixelCount {
		return &MediaError{
			Code:    ErrMediaDecompressionBomb,
			Message: fmt.Sprintf("image dimensions %dx%d (%d pixels) exceed maximum %d pixels", cfg.Width, cfg.Height, pixelCount, MaxPixelCount),
		}
	}
	return nil
}

// ValidateMediaList validates a list of media items in a request.
func ValidateMediaList(media []MediaContent) error {
	if len(media) > MaxMediaPerRequest {
		return &MediaError{
			Code:    ErrMediaTooLarge,
			Message: fmt.Sprintf("too many media items: %d (max %d)", len(media), MaxMediaPerRequest),
		}
	}

	for i := range media {
		if err := media[i].Validate(); err != nil {
			return fmt.Errorf("media[%d]: %w", i, err)
		}
	}

	return nil
}

// IsSensitiveDocType returns true if the document type is considered sensitive.
func IsSensitiveDocType(docType string) bool {
	return SensitiveDocumentTypes[strings.ToLower(docType)]
}
