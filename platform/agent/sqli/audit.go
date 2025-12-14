package sqli

import (
	"sync"
	"time"
)

// AuditEvent represents a SQL injection detection event for audit logging.
// This struct is designed to integrate with the agent's audit queue system
// for compliance with EU AI Act, RBI FREE-AI, and SEBI requirements.
type AuditEvent struct {
	// Type identifies this as a SQL injection event
	Type string `json:"type"`

	// Timestamp when the detection occurred (UTC)
	Timestamp time.Time `json:"timestamp"`

	// Severity of the detection (critical, high, medium, low)
	Severity string `json:"severity"`

	// UserID from the request context (if available)
	UserID string `json:"user_id,omitempty"`

	// ClientID from the request context
	ClientID string `json:"client_id,omitempty"`

	// TenantID for multi-tenant isolation
	TenantID string `json:"tenant_id,omitempty"`

	// ConnectorName that produced the response
	ConnectorName string `json:"connector_name"`

	// ScanType indicates what was scanned (input or response)
	ScanType ScanType `json:"scan_type"`

	// Pattern that matched
	Pattern string `json:"pattern"`

	// Category of SQL injection detected
	Category Category `json:"category"`

	// Confidence score (0.0-1.0)
	Confidence float64 `json:"confidence"`

	// Mode used for scanning
	Mode Mode `json:"mode"`

	// Blocked indicates whether the content was blocked
	Blocked bool `json:"blocked"`

	// ScanDuration in nanoseconds
	ScanDuration time.Duration `json:"scan_duration_ns"`

	// RequestID for tracing (if available)
	RequestID string `json:"request_id,omitempty"`

	// InputSnippet is a sanitized snippet of the input (for forensics)
	InputSnippet string `json:"input_snippet,omitempty"`
}

// AuditEventType is the type string for SQL injection audit events.
const AuditEventType = "sqli_detection"

// Severity levels for SQL injection detections
const (
	SeverityCritical = "critical" // Actively exploited injection
	SeverityHigh     = "high"     // Definite injection attempt
	SeverityMedium   = "medium"   // Suspected injection
	SeverityLow      = "low"      // Minor pattern match
)

// CategorySeverity maps SQL injection categories to severity levels.
func CategorySeverity(category Category) string {
	switch category {
	case CategoryStackedQueries:
		return SeverityCritical // Can modify/delete data
	case CategoryDangerousQuery:
		return SeverityCritical // DDL operations that can destroy data
	case CategoryUnionBased:
		return SeverityHigh // Can extract data
	case CategoryTimeBased:
		return SeverityHigh // Confirms vulnerability
	case CategoryBooleanBlind:
		return SeverityMedium // May be false positive
	case CategoryErrorBased:
		return SeverityMedium
	case CategoryCommentInjection:
		return SeverityMedium
	case CategoryGeneric:
		return SeverityLow
	default:
		return SeverityLow
	}
}

// NewAuditEvent creates an audit event from a scan result.
func NewAuditEvent(result *Result, connectorName string) *AuditEvent {
	if result == nil || !result.Detected {
		return nil
	}

	return &AuditEvent{
		Type:          AuditEventType,
		Timestamp:     time.Now().UTC(),
		Severity:      CategorySeverity(result.Category),
		ConnectorName: connectorName,
		ScanType:      result.ScanType,
		Pattern:       result.Pattern,
		Category:      result.Category,
		Confidence:    result.Confidence,
		Mode:          result.Mode,
		Blocked:       result.Blocked,
		ScanDuration:  result.Duration,
		InputSnippet:  result.Input,
	}
}

// WithUserContext adds user context to the audit event.
func (e *AuditEvent) WithUserContext(userID, clientID, tenantID string) *AuditEvent {
	e.UserID = userID
	e.ClientID = clientID
	e.TenantID = tenantID
	return e
}

// WithRequestID adds a request ID for tracing.
func (e *AuditEvent) WithRequestID(requestID string) *AuditEvent {
	e.RequestID = requestID
	return e
}

// ToAuditDetails converts the event to a map suitable for the audit queue.
func (e *AuditEvent) ToAuditDetails() map[string]interface{} {
	return map[string]interface{}{
		"connector_name": e.ConnectorName,
		"scan_type":      string(e.ScanType),
		"pattern":        e.Pattern,
		"category":       string(e.Category),
		"confidence":     e.Confidence,
		"mode":           string(e.Mode),
		"blocked":        e.Blocked,
		"scan_duration":  e.ScanDuration.String(),
		"request_id":     e.RequestID,
		"input_snippet":  e.InputSnippet,
	}
}

// AuditCallback is a function type for audit event callbacks.
// This allows the middleware to emit audit events to the audit queue
// without creating a circular dependency.
type AuditCallback func(event *AuditEvent)

// DefaultAuditCallback is a no-op callback used when no audit system is configured.
var DefaultAuditCallback AuditCallback = func(event *AuditEvent) {}

// globalAuditCallback holds the configured audit callback.
// Protected by auditCallbackMu for thread safety.
var (
	globalAuditCallback AuditCallback = DefaultAuditCallback
	auditCallbackMu     sync.RWMutex
)

// SetAuditCallback configures the global audit callback.
// This should be called during agent initialization to connect
// the SQL injection detection to the audit queue.
// Thread-safe: can be called from any goroutine.
func SetAuditCallback(callback AuditCallback) {
	auditCallbackMu.Lock()
	defer auditCallbackMu.Unlock()
	if callback == nil {
		globalAuditCallback = DefaultAuditCallback
		return
	}
	globalAuditCallback = callback
}

// EmitAuditEvent sends a detection event to the configured audit system.
// Thread-safe: can be called from any goroutine.
func EmitAuditEvent(event *AuditEvent) {
	if event == nil {
		return
	}
	auditCallbackMu.RLock()
	cb := globalAuditCallback
	auditCallbackMu.RUnlock()
	cb(event)
}
