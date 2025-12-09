// Copyright 2025 AxonFlow
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package agent provides the AxonFlow Agent service for authentication,
// authorization, and static policy enforcement.
package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// EU AI Act Article 13 - Transparency Requirements
// These headers provide transparency information for AI system interactions.
// They enable users and oversight bodies to understand what AI processing occurred.
//
// Header Naming Convention:
// - X-AI-* : Standard AI transparency headers
// - X-AxonFlow-* : AxonFlow-specific implementation details

// TransparencyHeaders defines the headers for EU AI Act Article 13 compliance.
// These headers MUST be set on all AI-processed responses.
const (
	// HeaderAIRequestID uniquely identifies this AI interaction for audit purposes.
	// Format: UUID v4
	// EU AI Act: Article 12 (Record-keeping) - enables linking to full audit trail
	HeaderAIRequestID = "X-AI-Request-ID"

	// HeaderAITimestamp indicates when the AI system processed this request.
	// Format: RFC3339 with nanoseconds (ISO 8601)
	// EU AI Act: Article 12 (Record-keeping) - temporal audit evidence
	HeaderAITimestamp = "X-AI-Timestamp"

	// HeaderAISystemID identifies the AI system that processed the request.
	// Format: "axonflow-agent/{version}" or "axonflow-orchestrator/{version}"
	// EU AI Act: Article 13 (Transparency) - which AI system was involved
	HeaderAISystemID = "X-AI-System-ID"

	// HeaderAIModelProvider indicates the LLM provider used (if any).
	// Values: "openai", "anthropic", "bedrock", "ollama", "none"
	// EU AI Act: Article 13 (Transparency) - what model processed the data
	HeaderAIModelProvider = "X-AI-Model-Provider"

	// HeaderAIModelID identifies the specific model version used.
	// Examples: "gpt-4-turbo", "claude-3-opus", "amazon.titan-text-express-v1"
	// EU AI Act: Article 13 (Transparency) - model version traceability
	HeaderAIModelID = "X-AI-Model-ID"

	// HeaderAIProcessingType indicates the type of AI processing performed.
	// Values: "policy-enforcement", "llm-generation", "data-retrieval", "hybrid"
	// EU AI Act: Article 13 (Transparency) - what kind of AI was applied
	HeaderAIProcessingType = "X-AI-Processing-Type"

	// HeaderAIPoliciesApplied lists the policies that were evaluated.
	// Format: Comma-separated policy IDs
	// EU AI Act: Article 14 (Human Oversight) - what rules governed the output
	HeaderAIPoliciesApplied = "X-AI-Policies-Applied"

	// HeaderAIDecisionBlocked indicates if the request was blocked by policy.
	// Values: "true", "false"
	// EU AI Act: Article 14 (Human Oversight) - intervention indicator
	HeaderAIDecisionBlocked = "X-AI-Decision-Blocked"

	// HeaderAIProcessingTimeMs indicates total AI processing time.
	// Format: Integer milliseconds
	// EU AI Act: Article 12 (Record-keeping) - performance monitoring
	HeaderAIProcessingTimeMs = "X-AI-Processing-Time-Ms"

	// HeaderAIChainID links related AI decisions in a multi-step workflow.
	// Format: UUID v4 (same across all related requests)
	// EU AI Act: Article 12 (Record-keeping) - decision chain traceability
	HeaderAIChainID = "X-AI-Chain-ID"

	// HeaderAIRiskLevel indicates the assessed risk level of the operation.
	// Values: "minimal", "limited", "high", "unacceptable"
	// EU AI Act: Article 6 (Classification) - risk category transparency
	HeaderAIRiskLevel = "X-AI-Risk-Level"

	// HeaderAIHumanOversightRequired indicates if human review is needed.
	// Values: "true", "false"
	// EU AI Act: Article 14 (Human Oversight) - flagged for human review
	HeaderAIHumanOversightRequired = "X-AI-Human-Oversight-Required"

	// HeaderAIDataSources lists the data sources queried for this request.
	// Format: Comma-separated connector names
	// EU AI Act: Article 10 (Data Governance) - data lineage
	HeaderAIDataSources = "X-AI-Data-Sources"

	// HeaderAIContentFiltered indicates if content filtering was applied.
	// Values: "true", "false"
	// EU AI Act: Article 13 (Transparency) - modification indicator
	HeaderAIContentFiltered = "X-AI-Content-Filtered"

	// HeaderAIAuditHash provides a hash of the audit record for verification.
	// Format: SHA-256 hex string (64 characters)
	// EU AI Act: Article 12 (Record-keeping) - tamper-evident audit
	HeaderAIAuditHash = "X-AI-Audit-Hash"
)

// Capacity limits to prevent unbounded memory growth
const (
	maxPolicies    = 100
	maxDataSources = 50
	defaultVersion = "1.0.0"
)

// versionRegex validates version string format (semver)
var versionRegex = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.]+)?$`)

// TransparencyContext holds all transparency-related information for a request.
// This struct is populated throughout request processing and used to set headers.
// All methods are thread-safe and can be called from multiple goroutines.
type TransparencyContext struct {
	mu sync.RWMutex // Protects all fields below

	// Request identification
	RequestID string    // Unique request ID (UUID)
	ChainID   string    // Decision chain ID (UUID)
	Timestamp time.Time // Processing start time

	// System information
	SystemID      string // "axonflow-agent/1.0.0"
	ModelProvider string // LLM provider name
	ModelID       string // Specific model identifier

	// Processing details
	ProcessingType   string   // Type of AI processing
	PoliciesApplied  []string // List of policies evaluated
	DataSources      []string // Data connectors used
	ProcessingTimeMs int64    // Total processing time
	DecisionBlocked  bool     // Was request blocked?
	ContentFiltered  bool     // Was content modified?
	HumanOversight   bool     // Requires human review?
	RiskLevel        string   // Risk classification
	BlockReason      string   // Why blocked (if applicable)

	// Audit
	AuditHash string // SHA-256 of audit record

	// Tenant context
	OrgID    string
	TenantID string
	ClientID string
	UserID   string
}

// NewTransparencyContext creates a new transparency context for a request.
// Call this at the start of request processing. The returned context is
// thread-safe and can be shared across goroutines.
func NewTransparencyContext() *TransparencyContext {
	return &TransparencyContext{
		RequestID:       uuid.New().String(),
		ChainID:         uuid.New().String(),
		Timestamp:       time.Now().UTC(),
		SystemID:        getSystemID(),
		ProcessingType:  "policy-enforcement",
		RiskLevel:       "limited", // Default risk level
		PoliciesApplied: make([]string, 0, 10),
		DataSources:     make([]string, 0, 5),
	}
}

// NewTransparencyContextWithChain creates a context with an existing chain ID.
// Use this for multi-step workflows where requests are related. If chainID is
// empty, a new chain ID will be generated.
func NewTransparencyContextWithChain(chainID string) *TransparencyContext {
	tc := NewTransparencyContext()
	if chainID != "" {
		tc.ChainID = chainID
	}
	return tc
}

// sanitizeHeaderValue removes characters that could cause HTTP header injection.
// This prevents CRLF injection attacks where user input could be used to inject
// additional headers.
func sanitizeHeaderValue(s string) string {
	// Remove carriage return and newline characters
	s = strings.ReplaceAll(s, "\r", "")
	s = strings.ReplaceAll(s, "\n", "")
	// Remove null bytes
	s = strings.ReplaceAll(s, "\x00", "")
	return s
}

// SetHeaders sets all transparency headers on the HTTP response.
// Call this before writing the response body. This method is thread-safe.
func (tc *TransparencyContext) SetHeaders(w http.ResponseWriter) {
	if tc == nil {
		return
	}

	tc.mu.RLock()
	defer tc.mu.RUnlock()

	// Always set these core headers
	w.Header().Set(HeaderAIRequestID, tc.RequestID)
	w.Header().Set(HeaderAITimestamp, tc.Timestamp.Format(time.RFC3339Nano))
	w.Header().Set(HeaderAISystemID, sanitizeHeaderValue(tc.SystemID))
	w.Header().Set(HeaderAIChainID, tc.ChainID)

	// Processing information
	if tc.ProcessingType != "" {
		w.Header().Set(HeaderAIProcessingType, sanitizeHeaderValue(tc.ProcessingType))
	}

	if len(tc.PoliciesApplied) > 0 {
		// Sanitize each policy ID before joining
		sanitized := make([]string, len(tc.PoliciesApplied))
		for i, p := range tc.PoliciesApplied {
			sanitized[i] = sanitizeHeaderValue(p)
		}
		w.Header().Set(HeaderAIPoliciesApplied, strings.Join(sanitized, ","))
	}

	if tc.ProcessingTimeMs > 0 {
		w.Header().Set(HeaderAIProcessingTimeMs, fmt.Sprintf("%d", tc.ProcessingTimeMs))
	}

	// Decision/outcome headers
	w.Header().Set(HeaderAIDecisionBlocked, fmt.Sprintf("%t", tc.DecisionBlocked))
	w.Header().Set(HeaderAIContentFiltered, fmt.Sprintf("%t", tc.ContentFiltered))
	w.Header().Set(HeaderAIHumanOversightRequired, fmt.Sprintf("%t", tc.HumanOversight))

	// Risk level
	if tc.RiskLevel != "" {
		w.Header().Set(HeaderAIRiskLevel, sanitizeHeaderValue(tc.RiskLevel))
	}

	// Model information (only if LLM was used)
	if tc.ModelProvider != "" {
		w.Header().Set(HeaderAIModelProvider, sanitizeHeaderValue(tc.ModelProvider))
	}
	if tc.ModelID != "" {
		w.Header().Set(HeaderAIModelID, sanitizeHeaderValue(tc.ModelID))
	}

	// Data sources
	if len(tc.DataSources) > 0 {
		sanitized := make([]string, len(tc.DataSources))
		for i, s := range tc.DataSources {
			sanitized[i] = sanitizeHeaderValue(s)
		}
		w.Header().Set(HeaderAIDataSources, strings.Join(sanitized, ","))
	}

	// Audit hash (if available)
	if tc.AuditHash != "" {
		w.Header().Set(HeaderAIAuditHash, tc.AuditHash)
	}
}

// ComputeAuditHash computes a SHA-256 hash of the audit record.
// This provides tamper-evident verification of the audit trail.
// The hash is deterministic for the same inputs. This method is thread-safe.
//
// The hash uses length-prefixed encoding to prevent collision attacks where
// different field values could produce the same hash string.
func (tc *TransparencyContext) ComputeAuditHash() string {
	tc.mu.Lock()
	defer tc.mu.Unlock()

	// Use length-prefixed encoding to prevent hash collisions from field concatenation
	// Format: len:value for each string field
	hashInput := fmt.Sprintf(
		"%d:%s|%d:%s|%d:%s|%d:%s|%d:%s|%d:%s|%d:%s|%t|%t|%t|%d",
		len(tc.RequestID), tc.RequestID,
		len(tc.ChainID), tc.ChainID,
		len(tc.Timestamp.Format(time.RFC3339Nano)), tc.Timestamp.Format(time.RFC3339Nano),
		len(tc.OrgID), tc.OrgID,
		len(tc.TenantID), tc.TenantID,
		len(tc.ClientID), tc.ClientID,
		len(tc.UserID), tc.UserID,
		tc.DecisionBlocked,
		tc.ContentFiltered,
		tc.HumanOversight,
		tc.ProcessingTimeMs,
	)

	hash := sha256.Sum256([]byte(hashInput))
	tc.AuditHash = hex.EncodeToString(hash[:])
	return tc.AuditHash
}

// MarkBlocked marks the request as blocked by policy.
// This method is thread-safe.
func (tc *TransparencyContext) MarkBlocked(reason string) {
	if tc == nil {
		return
	}
	tc.mu.Lock()
	defer tc.mu.Unlock()
	tc.DecisionBlocked = true
	tc.BlockReason = reason
}

// MarkFiltered marks that content was filtered/modified.
// This method is thread-safe.
func (tc *TransparencyContext) MarkFiltered() {
	if tc == nil {
		return
	}
	tc.mu.Lock()
	defer tc.mu.Unlock()
	tc.ContentFiltered = true
}

// RequireHumanOversight flags this request for human review.
// This also elevates the risk level to "high" unless it's already "unacceptable".
// This method is thread-safe.
func (tc *TransparencyContext) RequireHumanOversight() {
	if tc == nil {
		return
	}
	tc.mu.Lock()
	defer tc.mu.Unlock()
	tc.HumanOversight = true
	// Only elevate risk level if not already at maximum
	if tc.RiskLevel != "unacceptable" {
		tc.RiskLevel = "high"
	}
}

// SetProcessingTime calculates and sets the processing time from the given start time.
// This method is thread-safe.
func (tc *TransparencyContext) SetProcessingTime(start time.Time) {
	if tc == nil {
		return
	}
	tc.mu.Lock()
	defer tc.mu.Unlock()
	tc.ProcessingTimeMs = time.Since(start).Milliseconds()
}

// SetProcessingDuration directly sets the processing duration.
// This method is thread-safe.
func (tc *TransparencyContext) SetProcessingDuration(d time.Duration) {
	if tc == nil {
		return
	}
	tc.mu.Lock()
	defer tc.mu.Unlock()
	tc.ProcessingTimeMs = d.Milliseconds()
}

// AddPolicy adds a policy ID to the list of applied policies.
// Empty policy IDs are ignored. Duplicate policies are allowed.
// The list is capped at maxPolicies to prevent memory exhaustion.
// This method is thread-safe.
func (tc *TransparencyContext) AddPolicy(policyID string) {
	if tc == nil || policyID == "" {
		return
	}
	tc.mu.Lock()
	defer tc.mu.Unlock()
	if len(tc.PoliciesApplied) >= maxPolicies {
		return // Cap reached, silently ignore
	}
	tc.PoliciesApplied = append(tc.PoliciesApplied, policyID)
}

// AddPolicies adds multiple policy IDs to the list.
// Empty policy IDs are filtered out. The list is capped at maxPolicies.
// This method is thread-safe.
func (tc *TransparencyContext) AddPolicies(policyIDs []string) {
	if tc == nil {
		return
	}
	tc.mu.Lock()
	defer tc.mu.Unlock()
	for _, p := range policyIDs {
		if p == "" {
			continue
		}
		if len(tc.PoliciesApplied) >= maxPolicies {
			break
		}
		tc.PoliciesApplied = append(tc.PoliciesApplied, p)
	}
}

// AddDataSource adds a data source to the list.
// Empty source names are ignored. The list is capped at maxDataSources.
// This method is thread-safe.
func (tc *TransparencyContext) AddDataSource(source string) {
	if tc == nil || source == "" {
		return
	}
	tc.mu.Lock()
	defer tc.mu.Unlock()
	if len(tc.DataSources) >= maxDataSources {
		return // Cap reached, silently ignore
	}
	tc.DataSources = append(tc.DataSources, source)
}

// SetModel sets the LLM model information.
// This also changes ProcessingType to "hybrid" since LLM + policy is hybrid processing.
// This method is thread-safe.
func (tc *TransparencyContext) SetModel(provider, modelID string) {
	if tc == nil {
		return
	}
	tc.mu.Lock()
	defer tc.mu.Unlock()
	tc.ModelProvider = provider
	tc.ModelID = modelID
	tc.ProcessingType = "hybrid" // If model is used, it's hybrid processing
}

// SetTenantContext sets the tenant/org context for audit purposes.
// This method is thread-safe.
func (tc *TransparencyContext) SetTenantContext(orgID, tenantID, clientID, userID string) {
	if tc == nil {
		return
	}
	tc.mu.Lock()
	defer tc.mu.Unlock()
	tc.OrgID = orgID
	tc.TenantID = tenantID
	tc.ClientID = clientID
	tc.UserID = userID
}

// getSystemID returns the system identifier with version.
// The version is read from AXONFLOW_VERSION environment variable.
// Invalid version formats are replaced with the default version.
func getSystemID() string {
	version := os.Getenv("AXONFLOW_VERSION")
	if version == "" || !versionRegex.MatchString(version) {
		version = defaultVersion
	}
	return fmt.Sprintf("axonflow-agent/%s", version)
}

// TransparencyMiddleware creates middleware that adds transparency context to requests.
// The context is stored in the request context and can be retrieved with GetTransparencyContext.
// If an incoming X-AI-Chain-ID header is present, the chain ID is inherited.
func TransparencyMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if there's an incoming chain ID (for multi-step workflows)
		incomingChainID := r.Header.Get(HeaderAIChainID)

		var tc *TransparencyContext
		if incomingChainID != "" {
			tc = NewTransparencyContextWithChain(incomingChainID)
		} else {
			tc = NewTransparencyContext()
		}

		// Store in request context
		ctx := SetTransparencyContext(r.Context(), tc)
		r = r.WithContext(ctx)

		// Call next handler
		next.ServeHTTP(w, r)
	})
}

// TransparencyResponseWriter wraps http.ResponseWriter to automatically set headers.
// This ensures transparency headers are always set, even if the handler forgets.
// The wrapper is thread-safe for concurrent Write/WriteHeader calls.
type TransparencyResponseWriter struct {
	http.ResponseWriter
	tc             *TransparencyContext
	mu             sync.Mutex
	headersWritten bool
}

// NewTransparencyResponseWriter creates a new transparency-aware response writer.
func NewTransparencyResponseWriter(w http.ResponseWriter, tc *TransparencyContext) *TransparencyResponseWriter {
	return &TransparencyResponseWriter{
		ResponseWriter: w,
		tc:             tc,
		headersWritten: false,
	}
}

// WriteHeader sets transparency headers before writing the status code.
// This method is thread-safe.
func (tw *TransparencyResponseWriter) WriteHeader(statusCode int) {
	tw.mu.Lock()
	if !tw.headersWritten && tw.tc != nil {
		tw.tc.SetHeaders(tw.ResponseWriter)
		tw.headersWritten = true
	}
	tw.mu.Unlock()
	tw.ResponseWriter.WriteHeader(statusCode)
}

// Write ensures headers are set before writing the body.
// This method is thread-safe.
func (tw *TransparencyResponseWriter) Write(data []byte) (int, error) {
	tw.mu.Lock()
	if !tw.headersWritten && tw.tc != nil {
		tw.tc.SetHeaders(tw.ResponseWriter)
		tw.headersWritten = true
	}
	tw.mu.Unlock()
	return tw.ResponseWriter.Write(data)
}

// GetWrappedResponseWriter returns the underlying ResponseWriter.
func (tw *TransparencyResponseWriter) GetWrappedResponseWriter() http.ResponseWriter {
	return tw.ResponseWriter
}
