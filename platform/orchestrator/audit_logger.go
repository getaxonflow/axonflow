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

package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	_ "github.com/lib/pq"
)

// AuditLogger handles comprehensive audit logging for all orchestrator activities
type AuditLogger struct {
	db           *sql.DB
	batchWriter  *BatchWriter
	auditQueue   chan *AuditEntry
	wg           sync.WaitGroup
	shutdownChan chan struct{}
}

// AuditEntry represents a single audit log entry
type AuditEntry struct {
	ID               string                 `json:"id"`
	RequestID        string                 `json:"request_id"`
	Timestamp        time.Time              `json:"timestamp"`
	UserID           int                    `json:"user_id"`
	UserEmail        string                 `json:"user_email"`
	UserRole         string                 `json:"user_role"`
	ClientID         string                 `json:"client_id"`
	TenantID         string                 `json:"tenant_id"`
	RequestType      string                 `json:"request_type"`
	Query            string                 `json:"query"`
	QueryHash        string                 `json:"query_hash"`
	PolicyDecision   string                 `json:"policy_decision"` // "allowed", "blocked", "redacted"
	PolicyDetails    map[string]interface{} `json:"policy_details"`
	Provider         string                 `json:"provider"`
	Model            string                 `json:"model"`
	ResponseTime     int64                  `json:"response_time_ms"`
	TokensUsed       int                    `json:"tokens_used"`
	Cost             float64                `json:"cost"`
	RedactedFields   []string               `json:"redacted_fields"`
	ErrorMessage     string                 `json:"error_message,omitempty"`
	ResponseSample   string                 `json:"response_sample"`
	ComplianceFlags  []string               `json:"compliance_flags"`
	SecurityMetrics  map[string]interface{} `json:"security_metrics"`
}

// BatchWriter handles batch writing of audit entries
type BatchWriter struct {
	db          *sql.DB
	batchSize   int
	flushTicker *time.Ticker
	entries     []*AuditEntry
	mu          sync.Mutex
}

// NewAuditLogger creates a new audit logger
func NewAuditLogger(databaseURL string) *AuditLogger {
	db, err := sql.Open("postgres", databaseURL)
	if err != nil {
		log.Printf("Failed to connect to audit database: %v", err)
		// Return a no-op logger if database is unavailable
		return &AuditLogger{
			auditQueue:   make(chan *AuditEntry, 10000),
			shutdownChan: make(chan struct{}),
		}
	}

	// Create tables if they don't exist
	if err := createAuditTables(db); err != nil {
		log.Printf("Failed to create audit tables: %v", err)
	}

	logger := &AuditLogger{
		db:           db,
		batchWriter:  NewBatchWriter(db, 100),
		auditQueue:   make(chan *AuditEntry, 10000),
		shutdownChan: make(chan struct{}),
	}

	// Start background workers
	logger.wg.Add(1)
	go logger.processAuditQueue()

	return logger
}

// LogSuccessfulRequest logs a successful request
func (l *AuditLogger) LogSuccessfulRequest(ctx context.Context, req OrchestratorRequest, 
	response interface{}, policyResult *PolicyEvaluationResult, providerInfo *ProviderInfo) *AuditEntry {
	
	entry := &AuditEntry{
		ID:            generateAuditID(),
		RequestID:     req.RequestID,
		Timestamp:     time.Now().UTC(),
		UserID:        req.User.ID,
		UserEmail:     req.User.Email,
		UserRole:      req.User.Role,
		ClientID:      req.Client.ID,
		TenantID:      req.User.TenantID,
		RequestType:   req.RequestType,
		Query:         req.Query,
		QueryHash:     hashQuery(req.Query),
		PolicyDecision: "allowed",
		PolicyDetails: map[string]interface{}{
			"applied_policies": policyResult.AppliedPolicies,
			"risk_score":       policyResult.RiskScore,
			"processing_time":  policyResult.ProcessingTimeMs,
		},
		Provider:        providerInfo.Provider,
		Model:           providerInfo.Model,
		ResponseTime:    providerInfo.ResponseTimeMs,
		TokensUsed:      providerInfo.TokensUsed,
		Cost:            providerInfo.Cost,
		ResponseSample:  truncateResponse(response),
		ComplianceFlags: l.detectComplianceFlags(req, response),
		SecurityMetrics: l.calculateSecurityMetrics(req, policyResult),
	}

	// Check for redactions
	if redactionInfo, ok := ctx.Value("redaction_info").(*RedactionInfo); ok && redactionInfo != nil {
		entry.RedactedFields = redactionInfo.RedactedFields
		if redactionInfo.HasRedactions {
			entry.PolicyDecision = "redacted"
		}
	}

	l.enqueueEntry(entry)
	return entry
}

// LogBlockedRequest logs a blocked request
func (l *AuditLogger) LogBlockedRequest(ctx context.Context, req OrchestratorRequest, 
	policyResult *PolicyEvaluationResult) {
	
	entry := &AuditEntry{
		ID:            generateAuditID(),
		RequestID:     req.RequestID,
		Timestamp:     time.Now().UTC(),
		UserID:        req.User.ID,
		UserEmail:     req.User.Email,
		UserRole:      req.User.Role,
		ClientID:      req.Client.ID,
		TenantID:      req.User.TenantID,
		RequestType:   req.RequestType,
		Query:         req.Query,
		QueryHash:     hashQuery(req.Query),
		PolicyDecision: "blocked",
		PolicyDetails: map[string]interface{}{
			"applied_policies":  policyResult.AppliedPolicies,
			"risk_score":        policyResult.RiskScore,
			"required_actions":  policyResult.RequiredActions,
			"processing_time":   policyResult.ProcessingTimeMs,
		},
		ComplianceFlags: l.detectComplianceFlags(req, nil),
		SecurityMetrics: l.calculateSecurityMetrics(req, policyResult),
	}

	l.enqueueEntry(entry)
}

// LogFailedRequest logs a failed request
func (l *AuditLogger) LogFailedRequest(ctx context.Context, req OrchestratorRequest, err error) {
	entry := &AuditEntry{
		ID:            generateAuditID(),
		RequestID:     req.RequestID,
		Timestamp:     time.Now().UTC(),
		UserID:        req.User.ID,
		UserEmail:     req.User.Email,
		UserRole:      req.User.Role,
		ClientID:      req.Client.ID,
		TenantID:      req.User.TenantID,
		RequestType:   req.RequestType,
		Query:         req.Query,
		QueryHash:     hashQuery(req.Query),
		PolicyDecision: "error",
		ErrorMessage:   err.Error(),
		ComplianceFlags: l.detectComplianceFlags(req, nil),
	}

	l.enqueueEntry(entry)
}

// SearchAuditLogs searches audit logs based on criteria
func (l *AuditLogger) SearchAuditLogs(criteria interface{}) ([]*AuditEntry, error) {
	if l.db == nil {
		return []*AuditEntry{}, nil
	}

	// Build query based on criteria
	query := `
		SELECT id, request_id, timestamp, user_id, user_email, user_role,
			   client_id, tenant_id, request_type, query, policy_decision,
			   policy_details, provider, model, response_time_ms, tokens_used,
			   cost, redacted_fields, error_message, compliance_flags
		FROM audit_logs
		WHERE 1=1
	`

	args := []interface{}{}
	argIndex := 1

	// Add search conditions based on criteria
	if searchReq, ok := criteria.(struct {
		UserEmail   string
		ClientID    string
		StartTime   time.Time
		EndTime     time.Time
		RequestType string
		Limit       int
	}); ok {
		if searchReq.UserEmail != "" {
			query += fmt.Sprintf(" AND user_email = $%d", argIndex)
			args = append(args, searchReq.UserEmail)
			argIndex++
		}
		if searchReq.ClientID != "" {
			query += fmt.Sprintf(" AND client_id = $%d", argIndex)
			args = append(args, searchReq.ClientID)
			argIndex++
		}
		if !searchReq.StartTime.IsZero() {
			query += fmt.Sprintf(" AND timestamp >= $%d", argIndex)
			args = append(args, searchReq.StartTime)
			argIndex++
		}
		if !searchReq.EndTime.IsZero() {
			query += fmt.Sprintf(" AND timestamp <= $%d", argIndex)
			args = append(args, searchReq.EndTime)
			argIndex++
		}
		if searchReq.RequestType != "" {
			query += fmt.Sprintf(" AND request_type = $%d", argIndex)
			args = append(args, searchReq.RequestType)
		}

		query += " ORDER BY timestamp DESC"

		if searchReq.Limit > 0 {
			query += fmt.Sprintf(" LIMIT %d", searchReq.Limit)
		}
	}

	rows, err := l.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()

	var entries []*AuditEntry
	for rows.Next() {
		entry := &AuditEntry{}
		var policyDetailsJSON, redactedFieldsJSON, complianceFlagsJSON []byte

		err := rows.Scan(
			&entry.ID,
			&entry.RequestID,
			&entry.Timestamp,
			&entry.UserID,
			&entry.UserEmail,
			&entry.UserRole,
			&entry.ClientID,
			&entry.TenantID,
			&entry.RequestType,
			&entry.Query,
			&entry.PolicyDecision,
			&policyDetailsJSON,
			&entry.Provider,
			&entry.Model,
			&entry.ResponseTime,
			&entry.TokensUsed,
			&entry.Cost,
			&redactedFieldsJSON,
			&entry.ErrorMessage,
			&complianceFlagsJSON,
		)
		if err != nil {
			log.Printf("Error scanning audit log: %v", err)
			continue
		}

		// Unmarshal JSON fields
		_ = json.Unmarshal(policyDetailsJSON, &entry.PolicyDetails)
		_ = json.Unmarshal(redactedFieldsJSON, &entry.RedactedFields)
		_ = json.Unmarshal(complianceFlagsJSON, &entry.ComplianceFlags)

		entries = append(entries, entry)
	}

	return entries, nil
}

// IsHealthy checks if the audit logger is healthy
func (l *AuditLogger) IsHealthy() bool {
	if l.db == nil {
		return true // No-op logger is always healthy
	}

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	err := l.db.PingContext(ctx)
	return err == nil
}

// enqueueEntry adds an entry to the processing queue
func (l *AuditLogger) enqueueEntry(entry *AuditEntry) {
	select {
	case l.auditQueue <- entry:
		// Entry queued successfully
	default:
		// Queue is full, log directly (blocking)
		log.Printf("Audit queue full, writing directly")
		if l.batchWriter != nil {
			_ = l.batchWriter.Write([]*AuditEntry{entry})
		}
	}
}

// processAuditQueue processes audit entries from the queue
func (l *AuditLogger) processAuditQueue() {
	defer l.wg.Done()

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case entry := <-l.auditQueue:
			if l.batchWriter != nil {
				l.batchWriter.Add(entry)
			}
		case <-ticker.C:
			if l.batchWriter != nil {
				l.batchWriter.Flush()
			}
		case <-l.shutdownChan:
			// Flush remaining entries
			if l.batchWriter != nil {
				l.batchWriter.Flush()
			}
			return
		}
	}
}

// detectComplianceFlags detects compliance-related flags in the request
func (l *AuditLogger) detectComplianceFlags(req OrchestratorRequest, response interface{}) []string {
	flags := []string{}

	// Check for HIPAA-related queries
	if strings.Contains(strings.ToLower(req.Query), "patient") ||
		strings.Contains(strings.ToLower(req.Query), "medical") {
		flags = append(flags, "hipaa_relevant")
	}

	// Check for GDPR-related queries
	if req.User.TenantID != "" && strings.HasPrefix(req.User.TenantID, "eu_") {
		flags = append(flags, "gdpr_applicable")
	}

	// Check for financial data
	if strings.Contains(strings.ToLower(req.Query), "account") ||
		strings.Contains(strings.ToLower(req.Query), "transaction") {
		flags = append(flags, "sox_relevant")
	}

	// Check for PII access
	piiKeywords := []string{"ssn", "email", "phone", "address", "credit_card"}
	for _, keyword := range piiKeywords {
		if strings.Contains(strings.ToLower(req.Query), keyword) {
			flags = append(flags, "pii_access")
			break
		}
	}

	return flags
}

// calculateSecurityMetrics calculates security metrics for the request
func (l *AuditLogger) calculateSecurityMetrics(req OrchestratorRequest, policyResult *PolicyEvaluationResult) map[string]interface{} {
	metrics := map[string]interface{}{
		"risk_score":        policyResult.RiskScore,
		"policies_applied":  len(policyResult.AppliedPolicies),
		"query_complexity":  calculateQueryComplexity(req.Query),
		"sensitive_access":  containsSensitiveAccess(req.Query),
	}

	return metrics
}

// Utility functions

func generateAuditID() string {
	return fmt.Sprintf("audit_%d_%s", time.Now().Unix(), generateRandomString(8))
}

func hashQuery(query string) string {
	// Simple hash for query deduplication
	// In production, use a proper hash function
	return fmt.Sprintf("%x", len(query))
}

func truncateResponse(response interface{}) string {
	respStr := fmt.Sprint(response)
	if len(respStr) > 200 {
		return respStr[:200] + "..."
	}
	return respStr
}

func calculateQueryComplexity(query string) string {
	// Simple complexity calculation
	if strings.Count(strings.ToLower(query), "join") > 2 {
		return "high"
	}
	if strings.Contains(strings.ToLower(query), "join") {
		return "medium"
	}
	return "low"
}

func containsSensitiveAccess(query string) bool {
	sensitivePatterns := []string{
		"password", "secret", "key", "token",
		"ssn", "social_security", "credit_card",
	}
	
	lowerQuery := strings.ToLower(query)
	for _, pattern := range sensitivePatterns {
		if strings.Contains(lowerQuery, pattern) {
			return true
		}
	}
	return false
}

// BatchWriter implementation

func NewBatchWriter(db *sql.DB, batchSize int) *BatchWriter {
	writer := &BatchWriter{
		db:          db,
		batchSize:   batchSize,
		entries:     make([]*AuditEntry, 0, batchSize),
		flushTicker: time.NewTicker(10 * time.Second),
	}

	go writer.periodicFlush()

	return writer
}

func (b *BatchWriter) Add(entry *AuditEntry) {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.entries = append(b.entries, entry)

	if len(b.entries) >= b.batchSize {
		b.flush()
	}
}

func (b *BatchWriter) Flush() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.flush()
}

func (b *BatchWriter) flush() {
	if len(b.entries) == 0 {
		return
	}

	if err := b.Write(b.entries); err != nil {
		log.Printf("Failed to write audit batch: %v", err)
	}

	b.entries = b.entries[:0]
}

func (b *BatchWriter) Write(entries []*AuditEntry) error {
	if b.db == nil {
		return nil
	}

	tx, err := b.db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	stmt, err := tx.Prepare(`
		INSERT INTO audit_logs (
			id, request_id, timestamp, user_id, user_email, user_role,
			client_id, tenant_id, request_type, query, query_hash,
			policy_decision, policy_details, provider, model,
			response_time_ms, tokens_used, cost, redacted_fields,
			error_message, response_sample, compliance_flags, security_metrics
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23)
	`)
	if err != nil {
		return err
	}
	defer func() { _ = stmt.Close() }()

	for _, entry := range entries {
		policyDetailsJSON, _ := json.Marshal(entry.PolicyDetails)
		redactedFieldsJSON, _ := json.Marshal(entry.RedactedFields)
		complianceFlagsJSON, _ := json.Marshal(entry.ComplianceFlags)
		securityMetricsJSON, _ := json.Marshal(entry.SecurityMetrics)

		_, err = stmt.Exec(
			entry.ID,
			entry.RequestID,
			entry.Timestamp,
			entry.UserID,
			entry.UserEmail,
			entry.UserRole,
			entry.ClientID,
			entry.TenantID,
			entry.RequestType,
			entry.Query,
			entry.QueryHash,
			entry.PolicyDecision,
			policyDetailsJSON,
			entry.Provider,
			entry.Model,
			entry.ResponseTime,
			entry.TokensUsed,
			entry.Cost,
			redactedFieldsJSON,
			entry.ErrorMessage,
			entry.ResponseSample,
			complianceFlagsJSON,
			securityMetricsJSON,
		)
		if err != nil {
			log.Printf("Failed to insert audit entry: %v", err)
		}
	}

	return tx.Commit()
}

func (b *BatchWriter) periodicFlush() {
	for range b.flushTicker.C {
		b.Flush()
	}
}

// createAuditTables creates the audit tables if they don't exist
func createAuditTables(db *sql.DB) error {
	query := `
	CREATE TABLE IF NOT EXISTS audit_logs (
		id VARCHAR(255) PRIMARY KEY,
		request_id VARCHAR(255) NOT NULL,
		timestamp TIMESTAMP NOT NULL,
		user_id INTEGER NOT NULL,
		user_email VARCHAR(255) NOT NULL,
		user_role VARCHAR(50) NOT NULL,
		client_id VARCHAR(255) NOT NULL,
		tenant_id VARCHAR(255) NOT NULL,
		request_type VARCHAR(50) NOT NULL,
		query TEXT NOT NULL,
		query_hash VARCHAR(255) NOT NULL,
		policy_decision VARCHAR(50) NOT NULL,
		policy_details JSONB,
		provider VARCHAR(50),
		model VARCHAR(100),
		response_time_ms BIGINT,
		tokens_used INTEGER,
		cost DECIMAL(10, 6),
		redacted_fields JSONB,
		error_message TEXT,
		response_sample TEXT,
		compliance_flags JSONB,
		security_metrics JSONB,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	);

	CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON audit_logs(timestamp);
	CREATE INDEX IF NOT EXISTS idx_audit_logs_user_email ON audit_logs(user_email);
	CREATE INDEX IF NOT EXISTS idx_audit_logs_tenant_id ON audit_logs(tenant_id);
	CREATE INDEX IF NOT EXISTS idx_audit_logs_request_id ON audit_logs(request_id);
	CREATE INDEX IF NOT EXISTS idx_audit_logs_policy_decision ON audit_logs(policy_decision);
	`

	_, err := db.Exec(query)
	return err
}