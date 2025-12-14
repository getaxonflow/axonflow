package sqli

import (
	"context"
	"fmt"
	"time"
)

// Mode represents the SQL injection scanning mode.
type Mode string

const (
	// ModeOff disables SQL injection scanning.
	ModeOff Mode = "off"

	// ModeBasic enables pattern-based SQL injection detection using regex.
	// This mode is fast (<1ms) and available in Community edition.
	ModeBasic Mode = "basic"

	// ModeAdvanced enables ML/heuristic SQL injection detection.
	// This mode provides higher accuracy but is slower (~5-10ms).
	// Available in Enterprise edition only.
	ModeAdvanced Mode = "advanced"
)

// DefaultMode is the default scanning mode (security-first approach).
const DefaultMode = ModeBasic

// ValidModes returns all valid scanning modes.
func ValidModes() []Mode {
	return []Mode{ModeOff, ModeBasic, ModeAdvanced}
}

// IsValid checks if the mode is a valid scanning mode.
func (m Mode) IsValid() bool {
	switch m {
	case ModeOff, ModeBasic, ModeAdvanced:
		return true
	default:
		return false
	}
}

// String returns the string representation of the mode.
func (m Mode) String() string {
	return string(m)
}

// ParseMode parses a string into a Mode, returning an error if invalid.
func ParseMode(s string) (Mode, error) {
	mode := Mode(s)
	if !mode.IsValid() {
		return "", fmt.Errorf("invalid scanning mode: %q, valid modes are: off, basic, advanced", s)
	}
	return mode, nil
}

// ScanType indicates what is being scanned.
type ScanType string

const (
	// ScanTypeInput indicates scanning of user input/prompts.
	ScanTypeInput ScanType = "input"

	// ScanTypeResponse indicates scanning of MCP connector responses.
	ScanTypeResponse ScanType = "response"
)

// Result represents the outcome of a SQL injection scan.
type Result struct {
	// Detected indicates whether SQL injection was detected.
	Detected bool `json:"detected"`

	// Blocked indicates whether the content was blocked (vs just logged).
	Blocked bool `json:"blocked"`

	// Pattern is the pattern that matched (if detected).
	Pattern string `json:"pattern,omitempty"`

	// Category classifies the type of SQL injection detected.
	Category Category `json:"category,omitempty"`

	// Confidence is the confidence level of the detection (0.0-1.0).
	// Basic mode typically returns 1.0 for matches, 0.0 otherwise.
	// Advanced mode returns a probability score.
	Confidence float64 `json:"confidence,omitempty"`

	// Input is a sanitized snippet of the scanned content (for logging).
	Input string `json:"input,omitempty"`

	// ScanType indicates what was scanned (input or response).
	ScanType ScanType `json:"scan_type"`

	// Mode is the scanning mode that was used.
	Mode Mode `json:"mode"`

	// Duration is how long the scan took.
	Duration time.Duration `json:"duration_ns"`

	// Metadata contains additional scanner-specific information.
	Metadata map[string]any `json:"metadata,omitempty"`
}

// Category classifies the type of SQL injection detected.
type Category string

const (
	// CategoryUnionBased represents UNION-based SQL injection.
	CategoryUnionBased Category = "union_based"

	// CategoryBooleanBlind represents boolean-based blind SQL injection.
	CategoryBooleanBlind Category = "boolean_blind"

	// CategoryTimeBased represents time-based blind SQL injection.
	CategoryTimeBased Category = "time_based"

	// CategoryErrorBased represents error-based SQL injection.
	CategoryErrorBased Category = "error_based"

	// CategoryStackedQueries represents stacked queries SQL injection.
	CategoryStackedQueries Category = "stacked_queries"

	// CategoryCommentInjection represents comment-based SQL injection.
	CategoryCommentInjection Category = "comment_injection"

	// CategoryGeneric represents generic SQL injection patterns.
	CategoryGeneric Category = "generic"

	// CategoryDangerousQuery represents dangerous SQL operations that should be blocked.
	// This includes DDL operations (DROP, ALTER, TRUNCATE) and privilege modifications.
	CategoryDangerousQuery Category = "dangerous_query"
)

// Scanner is the interface for SQL injection detection.
type Scanner interface {
	// Scan checks the content for SQL injection patterns.
	// Returns a Result indicating whether injection was detected.
	Scan(ctx context.Context, content string, scanType ScanType) *Result

	// Mode returns the scanning mode of this scanner.
	Mode() Mode

	// IsEnterprise returns true if this scanner requires an enterprise license.
	IsEnterprise() bool
}

// NoOpScanner is a scanner that does nothing (used for ModeOff).
type NoOpScanner struct{}

// Scan always returns a clean result.
func (s *NoOpScanner) Scan(_ context.Context, _ string, scanType ScanType) *Result {
	return &Result{
		Detected: false,
		Blocked:  false,
		ScanType: scanType,
		Mode:     ModeOff,
		Duration: 0,
	}
}

// Mode returns ModeOff.
func (s *NoOpScanner) Mode() Mode {
	return ModeOff
}

// IsEnterprise returns false.
func (s *NoOpScanner) IsEnterprise() bool {
	return false
}

// scannerRegistry holds registered scanner factories.
var scannerRegistry = make(map[Mode]func() Scanner)

// RegisterScanner registers a scanner factory for a given mode.
// This is used by the enterprise package to register the advanced scanner.
func RegisterScanner(mode Mode, factory func() Scanner) {
	scannerRegistry[mode] = factory
}

// NewScanner creates a new scanner for the given mode.
// Returns an error if the mode is not available (e.g., advanced mode without enterprise license).
func NewScanner(mode Mode) (Scanner, error) {
	if !mode.IsValid() {
		return nil, fmt.Errorf("invalid scanning mode: %q", mode)
	}

	if mode == ModeOff {
		return &NoOpScanner{}, nil
	}

	factory, ok := scannerRegistry[mode]
	if !ok {
		if mode == ModeAdvanced {
			return nil, fmt.Errorf("advanced scanning mode requires enterprise license")
		}
		return nil, fmt.Errorf("scanner not registered for mode: %q", mode)
	}

	return factory(), nil
}

// MustNewScanner creates a new scanner, panicking on error.
// Use only in initialization code where errors are programming mistakes.
func MustNewScanner(mode Mode) Scanner {
	scanner, err := NewScanner(mode)
	if err != nil {
		panic(fmt.Sprintf("failed to create scanner: %v", err))
	}
	return scanner
}

func init() {
	// NoOp scanner is always available
	RegisterScanner(ModeOff, func() Scanner { return &NoOpScanner{} })
}
