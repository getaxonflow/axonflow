package sqli

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"
)

// ScanningMiddleware provides SQL injection scanning for MCP connector responses.
// It integrates with the agent's request/response pipeline to detect and optionally
// block responses containing SQL injection payloads.
type ScanningMiddleware struct {
	config        Config
	scanner       Scanner // Response scanner
	inputScanner  Scanner // Cached input scanner (may differ from response scanner)
	mu            sync.RWMutex

	// Metrics
	scansTotal      int64
	detectionsTotal int64
	blockedTotal    int64
}

// MiddlewareOption configures the ScanningMiddleware.
type MiddlewareOption func(*ScanningMiddleware)

// WithMiddlewareConfig sets the configuration.
func WithMiddlewareConfig(cfg Config) MiddlewareOption {
	return func(m *ScanningMiddleware) {
		m.config = cfg
	}
}

// WithMiddlewareScanner sets a custom scanner (useful for testing).
func WithMiddlewareScanner(s Scanner) MiddlewareOption {
	return func(m *ScanningMiddleware) {
		m.scanner = s
	}
}

// NewScanningMiddleware creates a new scanning middleware.
func NewScanningMiddleware(opts ...MiddlewareOption) (*ScanningMiddleware, error) {
	m := &ScanningMiddleware{
		config: DefaultConfig(),
	}

	for _, opt := range opts {
		opt(m)
	}

	// Validate configuration
	if err := m.config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	// Create response scanner based on response mode
	if m.scanner == nil {
		scanner, err := NewScanner(m.config.ResponseMode)
		if err != nil {
			return nil, fmt.Errorf("failed to create response scanner: %w", err)
		}
		m.scanner = scanner
	}

	// Create input scanner (may differ from response scanner)
	if m.inputScanner == nil {
		inputScanner, err := NewScanner(m.config.InputMode)
		if err != nil {
			return nil, fmt.Errorf("failed to create input scanner: %w", err)
		}
		m.inputScanner = inputScanner
	}

	return m, nil
}

// ScanQueryResponse scans a query response for SQL injection.
// It returns true if the response should be blocked.
func (m *ScanningMiddleware) ScanQueryResponse(ctx context.Context, connectorName string, rows []map[string]interface{}) (*ResponseScanResult, error) {
	start := time.Now()

	m.mu.Lock()
	m.scansTotal++
	m.mu.Unlock()

	// Check if scanning is disabled for this connector
	if !m.config.IsConnectorEnabled(connectorName) {
		return &ResponseScanResult{
			Blocked:  false,
			Duration: time.Since(start),
		}, nil
	}

	// Get the scanning mode for this connector
	mode := m.config.GetResponseModeForConnector(connectorName)
	if mode == ModeOff {
		return &ResponseScanResult{
			Blocked:  false,
			Duration: time.Since(start),
		}, nil
	}

	// Convert rows to scannable content
	content := m.rowsToContent(rows)

	// Scan the content
	result := m.scanner.Scan(ctx, content, ScanTypeResponse)

	scanResult := &ResponseScanResult{
		Detected:      result.Detected,
		Blocked:       result.Detected && m.config.BlockOnDetection,
		Pattern:       result.Pattern,
		Category:      result.Category,
		Confidence:    result.Confidence,
		ConnectorName: connectorName,
		Duration:      time.Since(start),
		ScanResult:    result,
	}

	if result.Detected {
		m.mu.Lock()
		m.detectionsTotal++
		if scanResult.Blocked {
			m.blockedTotal++
		}
		m.mu.Unlock()

		if m.config.LogDetections {
			log.Printf("[SQLi] Detection in connector '%s' response: pattern=%s category=%s blocked=%v",
				connectorName, result.Pattern, result.Category, scanResult.Blocked)
		}

		// Emit audit event for compliance
		if m.config.AuditTrailEnabled {
			auditEvent := NewAuditEvent(result, connectorName)
			EmitAuditEvent(auditEvent)
		}
	}

	return scanResult, nil
}

// ScanCommandResponse scans a command response for SQL injection.
func (m *ScanningMiddleware) ScanCommandResponse(ctx context.Context, connectorName string, message string, metadata map[string]interface{}) (*ResponseScanResult, error) {
	start := time.Now()

	m.mu.Lock()
	m.scansTotal++
	m.mu.Unlock()

	// Check if scanning is disabled for this connector
	if !m.config.IsConnectorEnabled(connectorName) {
		return &ResponseScanResult{
			Blocked:  false,
			Duration: time.Since(start),
		}, nil
	}

	// Get the scanning mode for this connector
	mode := m.config.GetResponseModeForConnector(connectorName)
	if mode == ModeOff {
		return &ResponseScanResult{
			Blocked:  false,
			Duration: time.Since(start),
		}, nil
	}

	// Convert message and metadata to scannable content
	var content string
	if message != "" {
		content = message
	}
	if len(metadata) > 0 {
		metaJSON, _ := json.Marshal(metadata)
		if content != "" {
			content += " "
		}
		content += string(metaJSON)
	}

	// Scan the content
	result := m.scanner.Scan(ctx, content, ScanTypeResponse)

	scanResult := &ResponseScanResult{
		Detected:      result.Detected,
		Blocked:       result.Detected && m.config.BlockOnDetection,
		Pattern:       result.Pattern,
		Category:      result.Category,
		Confidence:    result.Confidence,
		ConnectorName: connectorName,
		Duration:      time.Since(start),
		ScanResult:    result,
	}

	if result.Detected {
		m.mu.Lock()
		m.detectionsTotal++
		if scanResult.Blocked {
			m.blockedTotal++
		}
		m.mu.Unlock()

		if m.config.LogDetections {
			log.Printf("[SQLi] Detection in connector '%s' command response: pattern=%s category=%s blocked=%v",
				connectorName, result.Pattern, result.Category, scanResult.Blocked)
		}

		// Emit audit event for compliance
		if m.config.AuditTrailEnabled {
			auditEvent := NewAuditEvent(result, connectorName)
			EmitAuditEvent(auditEvent)
		}
	}

	return scanResult, nil
}

// ScanInput scans user input for SQL injection.
func (m *ScanningMiddleware) ScanInput(ctx context.Context, input string) (*Result, error) {
	m.mu.Lock()
	m.scansTotal++
	m.mu.Unlock()

	// Check input mode
	if m.config.InputMode == ModeOff {
		return &Result{
			Detected: false,
			ScanType: ScanTypeInput,
			Mode:     ModeOff,
		}, nil
	}

	// Use cached input scanner
	result := m.inputScanner.Scan(ctx, input, ScanTypeInput)

	if result.Detected {
		m.mu.Lock()
		m.detectionsTotal++
		if m.config.BlockOnDetection {
			m.blockedTotal++
		}
		m.mu.Unlock()

		if m.config.LogDetections {
			log.Printf("[SQLi] Detection in user input: pattern=%s category=%s",
				result.Pattern, result.Category)
		}

		// Emit audit event for compliance
		if m.config.AuditTrailEnabled {
			auditEvent := NewAuditEvent(result, "user_input")
			EmitAuditEvent(auditEvent)
		}
	}

	return result, nil
}

// GetMetrics returns current scanning metrics.
func (m *ScanningMiddleware) GetMetrics() MiddlewareMetrics {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return MiddlewareMetrics{
		ScansTotal:      m.scansTotal,
		DetectionsTotal: m.detectionsTotal,
		BlockedTotal:    m.blockedTotal,
	}
}

// ResetMetrics resets the metrics counters.
func (m *ScanningMiddleware) ResetMetrics() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.scansTotal = 0
	m.detectionsTotal = 0
	m.blockedTotal = 0
}

// UpdateConfig updates the middleware configuration.
func (m *ScanningMiddleware) UpdateConfig(cfg Config) error {
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("invalid configuration: %w", err)
	}

	// Create new response scanner if mode changed
	responseScanner, err := NewScanner(cfg.ResponseMode)
	if err != nil {
		return fmt.Errorf("failed to create response scanner: %w", err)
	}

	// Create new input scanner if mode changed
	inputScanner, err := NewScanner(cfg.InputMode)
	if err != nil {
		return fmt.Errorf("failed to create input scanner: %w", err)
	}

	m.mu.Lock()
	m.config = cfg
	m.scanner = responseScanner
	m.inputScanner = inputScanner
	m.mu.Unlock()

	return nil
}

// rowsToContent converts query result rows into a scannable string.
func (m *ScanningMiddleware) rowsToContent(rows []map[string]interface{}) string {
	if len(rows) == 0 {
		return ""
	}

	// For efficiency, limit scanning to first N rows and reasonable content length
	maxRows := 100
	if len(rows) < maxRows {
		maxRows = len(rows)
	}

	// Marshal rows to JSON for scanning
	rowsToScan := rows[:maxRows]
	content, err := json.Marshal(rowsToScan)
	if err != nil {
		// Fall back to basic string conversion
		var sb []byte
		for i, row := range rowsToScan {
			if i > 0 {
				sb = append(sb, ' ')
			}
			rowContent, _ := json.Marshal(row)
			sb = append(sb, rowContent...)
		}
		return string(sb)
	}

	// Truncate if too long
	if len(content) > m.config.MaxContentLength {
		return string(content[:m.config.MaxContentLength])
	}

	return string(content)
}

// ResponseScanResult contains the result of scanning a connector response.
type ResponseScanResult struct {
	// Detected indicates whether SQL injection was detected.
	Detected bool

	// Blocked indicates whether the response should be blocked.
	// This is true only if Detected is true AND BlockOnDetection is enabled.
	Blocked bool

	// Pattern is the name of the pattern that matched (if any).
	Pattern string

	// Category is the category of SQL injection detected.
	Category Category

	// Confidence is the detection confidence score.
	Confidence float64

	// ConnectorName is the name of the connector that produced the response.
	ConnectorName string

	// Duration is the time taken to scan the response.
	Duration time.Duration

	// ScanResult is the underlying scan result (for detailed access).
	ScanResult *Result
}

// MiddlewareMetrics contains scanning metrics.
type MiddlewareMetrics struct {
	// ScansTotal is the total number of scans performed.
	ScansTotal int64

	// DetectionsTotal is the total number of detections.
	DetectionsTotal int64

	// BlockedTotal is the total number of blocked responses.
	BlockedTotal int64
}

// Global middleware instance (lazy initialized)
var (
	globalMiddleware   *ScanningMiddleware
	globalMiddlewareMu sync.RWMutex
)

// GetGlobalMiddleware returns the global scanning middleware instance.
// If not initialized, it creates one with default configuration.
func GetGlobalMiddleware() *ScanningMiddleware {
	globalMiddlewareMu.RLock()
	if globalMiddleware != nil {
		globalMiddlewareMu.RUnlock()
		return globalMiddleware
	}
	globalMiddlewareMu.RUnlock()

	globalMiddlewareMu.Lock()
	defer globalMiddlewareMu.Unlock()

	// Double-check after acquiring write lock
	if globalMiddleware != nil {
		return globalMiddleware
	}

	// Initialize with default configuration
	m, err := NewScanningMiddleware()
	if err != nil {
		log.Printf("[SQLi] Warning: Failed to initialize global middleware: %v", err)
		// Return a no-op middleware
		m = &ScanningMiddleware{
			config:  DefaultConfig().WithResponseMode(ModeOff),
			scanner: &NoOpScanner{},
		}
	}
	globalMiddleware = m

	return globalMiddleware
}

// SetGlobalMiddleware sets the global scanning middleware instance.
// This is useful for initialization with custom configuration.
func SetGlobalMiddleware(m *ScanningMiddleware) {
	globalMiddlewareMu.Lock()
	defer globalMiddlewareMu.Unlock()
	globalMiddleware = m
}

// InitGlobalMiddleware initializes the global middleware with the given configuration.
func InitGlobalMiddleware(cfg Config) error {
	m, err := NewScanningMiddleware(WithMiddlewareConfig(cfg))
	if err != nil {
		return err
	}

	SetGlobalMiddleware(m)
	log.Printf("[SQLi] Global middleware initialized: input_mode=%s response_mode=%s block=%v",
		cfg.InputMode, cfg.ResponseMode, cfg.BlockOnDetection)
	return nil
}
