// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"bufio"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lib/pq"
)

// execWithRetry executes a database query with exponential backoff retry.
func execWithRetry(db *sql.DB, query string, args ...interface{}) error {
	maxRetries := 3
	baseDelay := 100 * time.Millisecond

	var lastErr error
	for attempt := 0; attempt < maxRetries; attempt++ {
		_, err := db.Exec(query, args...)
		if err == nil {
			return nil
		}

		lastErr = err
		if attempt < maxRetries-1 {
			delay := baseDelay * time.Duration(1<<uint(attempt))
			log.Printf("Database write failed (attempt %d/%d), retrying in %v: %v",
				attempt+1, maxRetries, delay, err)
			time.Sleep(delay)
		}
	}

	log.Printf("Database write failed after %d attempts: %v", maxRetries, lastErr)
	return lastErr
}

// execWithRetryOrgScope is the v9 Phase 8 RLS-aware variant of execWithRetry.
// It wraps the Exec in a WithOrgScope transaction so that app.current_org_id is
// set before the SQL runs — required for tables under FORCE ROW LEVEL SECURITY
// (migration 100 onward: mcp_query_audits, decision_chain, etc.). orgID must
// be non-empty; cross-org writes belong on the platform_admin role, not here.
//
// Retries the full transaction (BEGIN → SET LOCAL → EXEC → COMMIT) on transient
// failures. Each retry opens a fresh txn so any stale txn-local state is
// discarded between attempts.
func execWithRetryOrgScope(db *sql.DB, orgID, query string, args ...interface{}) error {
	if orgID == "" {
		return fmt.Errorf("execWithRetryOrgScope: orgID must be non-empty for RLS-enforced audit tables")
	}
	maxRetries := 3
	baseDelay := 100 * time.Millisecond

	var lastErr error
	for attempt := 0; attempt < maxRetries; attempt++ {
		err := WithOrgScope(context.Background(), db, orgID, func(tx *sql.Tx) error {
			_, exErr := tx.Exec(query, args...)
			return exErr
		})
		if err == nil {
			return nil
		}
		lastErr = err
		if attempt < maxRetries-1 {
			delay := baseDelay * time.Duration(1<<uint(attempt))
			log.Printf("Org-scoped DB write failed (attempt %d/%d), retrying in %v: %v",
				attempt+1, maxRetries, delay, err)
			time.Sleep(delay)
		}
	}
	log.Printf("Org-scoped DB write failed after %d attempts: %v", maxRetries, lastErr)
	return lastErr
}

// AuditMode defines how audit logs are persisted to the database.
// The mode affects whether critical entries (like policy violations)
// are written synchronously or asynchronously.
type AuditMode string

const (
	AuditModeCompliance  AuditMode = "compliance"  // Sync writes for violations
	AuditModePerformance AuditMode = "performance" // Async for everything
)

// AuditEntry represents an audit log entry for policy violations,
// metrics, and Gateway Mode operations. The Type field determines
// which database table the entry is persisted to.
//
// Fields:
//   - Type: Entry type (violation, metric, gateway_context, llm_call_audit)
//   - Timestamp: When the event occurred (UTC)
//   - Severity: For violations: critical, high, medium, low
//   - UserID: User who triggered the event (from JWT)
//   - ClientID: Client application identifier
//   - Details: Additional context (policy name, query, etc.)
type AuditEntry struct {
	Type      string    `json:"type"`
	Timestamp time.Time `json:"timestamp"`
	Severity  string    `json:"severity"`
	UserID    string    `json:"user_id"`
	ClientID  string    `json:"client_id"`
	// OrgID is the tenant scope key (v9 Phase 8 #2384 PR-C1). Required by
	// the RLS-aware audit_queue persistence path for policy_metrics,
	// policy_violations, agent_audit_logs and similar tables — see
	// writeToDBSync's per-type INSERT statements. Empty OrgID causes those
	// INSERTs to be dropped with a loud log (audit is best-effort; the
	// alternative — silent NULL-bucket writes — would mask the upstream
	// OrgID-propagation gap).
	OrgID    string                 `json:"org_id"`
	TenantID string                 `json:"tenant_id"`
	Details  map[string]interface{} `json:"details"`
	Retries  int                    `json:"-"`
	// RecoveryAttempts counts the startups whose RecoverFromFallback failed to
	// write this entry. It is persisted with the entry, so an entry that can
	// never be written (a violation with no organization) is dropped, counted,
	// after maxFallbackRecoveryAttempts instead of being re-pended forever.
	RecoveryAttempts int `json:"recovery_attempts,omitempty"`
}

// maxFallbackRecoveryAttempts bounds how many startups retry one fallback
// entry before it is dropped and counted (#4249 row 5705939628).
const maxFallbackRecoveryAttempts = 5

// Audit entry types
const (
	AuditTypeViolation      = "violation"
	AuditTypeMetric         = "metric"
	AuditTypeAudit          = "audit"
	AuditTypeGatewayContext = "gateway_context"
	AuditTypeLLMCallAudit   = "llm_call_audit"
	AuditTypeMCPQueryAudit  = "mcp_query_audit"
)

// MCPQueryAuditEntry represents an audit entry for MCP connector queries.
// This captures policy evaluation results at all three phases:
// REQUEST (pre-execution), RESPONSE (post-execution), and EXFILTRATION checks.
type MCPQueryAuditEntry struct {
	AuditID        string `json:"audit_id"`
	TenantID       string `json:"tenant_id"`
	OrgID          string `json:"org_id"`
	ClientID       string `json:"client_id"`
	UserID         string `json:"user_id,omitempty"`
	ConnectorName  string `json:"connector_name"`
	Operation      string `json:"operation"` // query, execute, list_resources, etc.
	StatementHash  string `json:"statement_hash,omitempty"`
	ParametersHash string `json:"parameters_hash,omitempty"`
	ParameterCount int    `json:"parameter_count"`

	// Plugin Batch 1 (ADR-043): stable decision identifier attached to
	// every check-input/check-output audit entry so the explain endpoint
	// (GET /api/v1/decisions/:id/explain) can resolve by this id.
	DecisionID string `json:"decision_id,omitempty"`

	// #1983 / α1 — record policy_version at decision time. Map from
	// matched static-policy id → live version at evaluation. Empty when
	// no static-policy match is in scope (dynamic-only blocks, allow
	// paths with no policy match). Carried through to the audit_queue
	// Details map so it survives the fallback-file replay path; explain's
	// α3 amendment will surface it via DecisionExplanation.
	PolicyVersions map[string]int `json:"policy_versions,omitempty"`

	// Request phase (pre-execution policy evaluation)
	RequestBlocked           bool     `json:"request_blocked"`
	RequestBlockReason       string   `json:"request_block_reason,omitempty"`
	RequestPoliciesEvaluated int      `json:"request_policies_evaluated"`
	RequestMatchedPolicies   []string `json:"request_matched_policies,omitempty"`

	// Response phase (post-execution policy evaluation)
	ResponseRedacted        bool     `json:"response_redacted"`
	ResponseRedactionsCount int      `json:"response_redactions_count"`
	ResponseRedactedFields  []string `json:"response_redacted_fields,omitempty"`

	// Exfiltration detection
	ExfilRowsReturned int    `json:"exfil_rows_returned,omitempty"`
	ExfilExceeded     bool   `json:"exfil_exceeded"`
	ExfilLimitType    string `json:"exfil_limit_type,omitempty"` // row_count, data_volume, etc.

	// Result
	RowCount     int    `json:"row_count,omitempty"`
	DurationMs   int64  `json:"duration_ms"`
	Success      bool   `json:"success"`
	ErrorMessage string `json:"error_message,omitempty"`
}

// AuditQueue manages asynchronous audit logging with persistence guarantees.
// It provides reliable logging for policy violations, metrics, and Gateway
// Mode operations with the following guarantees:
//
//   - Violations: Written synchronously in compliance mode, with retry
//   - Metrics: Always batched asynchronously for performance
//   - Gateway operations: Respect audit mode setting
//   - Fallback: JSONL file when database is unavailable
//   - Recovery: Automatic replay from fallback on startup
//
// Thread Safety: AuditQueue is safe for concurrent use. Multiple goroutines
// can call Log* methods simultaneously.
type AuditQueue struct {
	mode         AuditMode
	queue        chan AuditEntry
	metricsBatch chan AuditEntry
	workers      int
	wg           sync.WaitGroup
	db           *sql.DB
	fallbackFile *os.File
	mu           sync.Mutex
	closed       atomic.Bool // Track if channels are closed
	// sendMu guards every send on queue and metricsBatch against Shutdown
	// closing them: a sender holds it for reading across its closed check and
	// its send, and Shutdown takes it for writing to mark the queue closed and
	// close the channels, so no send can land on a closed channel (#4249 row
	// 5705939628). Lock order: sendMu before mu.
	sendMu sync.RWMutex

	// Metrics (use atomic for thread safety)
	processed uint64
	failed    uint64
	queued    uint64
}

// NewAuditQueue creates a new audit queue with the specified configuration.
//
// Parameters:
//   - mode: AuditModeCompliance for sync violation writes, AuditModePerformance for async
//   - queueSize: Buffer size for the async queue (recommended: 10000)
//   - workers: Number of worker goroutines (recommended: 4-8)
//   - db: PostgreSQL database connection for persistence
//   - fallbackPath: Path to JSONL fallback file (e.g., "/var/log/axonflow/audit_fallback.jsonl")
//
// The queue automatically starts worker goroutines and a metrics batcher.
// Call Shutdown() during graceful shutdown to drain the queue.
//
// Example:
//
//	queue, err := NewAuditQueue(AuditModeCompliance, 10000, 4, db, "/var/log/audit.jsonl")
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer queue.Shutdown(context.Background())
func NewAuditQueue(mode AuditMode, queueSize int, workers int, db *sql.DB, fallbackPath string) (*AuditQueue, error) {
	// Open fallback file
	fallbackFile, err := os.OpenFile(
		fallbackPath,
		os.O_CREATE|os.O_APPEND|os.O_WRONLY,
		0600,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to open fallback file: %v", err)
	}

	aq := &AuditQueue{
		mode:         mode,
		queue:        make(chan AuditEntry, queueSize),
		metricsBatch: make(chan AuditEntry, 1000),
		workers:      workers,
		db:           db,
		fallbackFile: fallbackFile,
	}

	// Start workers
	for i := 0; i < workers; i++ {
		aq.wg.Add(1)
		go aq.worker(i)
	}

	// Start metrics batcher
	aq.wg.Add(1)
	go aq.metricsBatcher()

	log.Printf("AuditQueue started in %s mode with %d workers, fallback: %s", mode, workers, fallbackPath)
	return aq, nil
}

// LogViolation logs a policy violation. In compliance mode, violations are
// written synchronously to ensure they are persisted before returning.
// In performance mode, violations are queued for async processing.
//
// The entry.Details should include:
//   - policy_name: Name of the violated policy
//   - description: Human-readable violation description
//   - query: The query that triggered the violation
func (aq *AuditQueue) LogViolation(entry AuditEntry) error {
	entry.Type = AuditTypeViolation
	// UTC pinned (#2876), defense-in-depth: today entry.Timestamp reaches
	// only the JSONL fallback and the (currently producer-less)
	// AuditTypeAudit INSERT — the live DB writes use column DEFAULTs /
	// handler-supplied values — but pinning UTC here means any future
	// persistence of these stamps is correct regardless of host zone or
	// column type. Same on the three Log* methods below.
	entry.Timestamp = time.Now().UTC()

	// In compliance mode, violations are synchronous. A write that fails is
	// kept in the fallback file for RecoverFromFallback, as performance mode's
	// worker keeps it: a transient failure (a lost connection, a failover), and
	// a Postgres-permanent one too (a revoked grant, a missing table, a
	// constraint), because an operator can fix those and recovery's bound
	// moves an entry that never succeeds to the dead-letter file rather than
	// deleting it. Only an entry with no organization is returned, since no
	// fix makes it writable; the adapter counts it (#4249 row 5705939628). The
	// metrics path's no-retry classification (execMetricsWithRetry) is
	// unchanged.
	if aq.mode == AuditModeCompliance {
		err := aq.writeToDBSync(entry)
		if err == nil || errors.Is(err, errAuditEntryMissingOrgID) {
			return err
		}
		aq.mu.Lock()
		defer aq.mu.Unlock()
		if fallbackErr := aq.writeToFallback(entry); fallbackErr != nil {
			return fmt.Errorf("%w (and the fallback write failed: %v)", err, fallbackErr)
		}
		logAuditRateLimited("violation_kept_in_fallback", "violation write failed (%v); kept in the fallback file for recovery", err)
		return nil
	}

	// In performance mode, queue it
	return aq.queueEntry(entry)
}

// LogMetric logs a metric (always async)
func (aq *AuditQueue) LogMetric(entry AuditEntry) error {
	entry.Type = AuditTypeMetric
	entry.Timestamp = time.Now().UTC()

	// After Shutdown the metrics channel is closed, and a send on it panics. A
	// shared-engine evaluation's metrics are recorded on a goroutine
	// (RecordEvaluation), so one can arrive during or after Shutdown; it is
	// dropped, counted. sendMu makes the check and the send one step against
	// Shutdown's close.
	aq.sendMu.RLock()
	defer aq.sendMu.RUnlock()
	if aq.closed.Load() {
		recordAuditDrop(auditDropMetricsAfterShutdown, "policy_metrics entry for policy %v dropped: the audit queue has shut down",
			entry.Details["policy_id"])
		return nil
	}

	// Metrics are always async, even in compliance mode
	select {
	case aq.metricsBatch <- entry:
		atomic.AddUint64(&aq.queued, 1)
		return nil
	default:
		// Queue full: the metric is dropped, counted and logged at a bounded
		// rate (audit_drop.go), never per entry.
		recordAuditDrop(auditDropMetricsQueueFull, "policy_metrics entry for policy %v dropped: the metrics queue is full",
			entry.Details["policy_id"])
		return nil
	}
}

// LogGatewayContext logs a Gateway Mode pre-check context
// This is used when SDK calls the pre-check endpoint
func (aq *AuditQueue) LogGatewayContext(entry AuditEntry) error {
	entry.Type = AuditTypeGatewayContext
	entry.Timestamp = time.Now().UTC()

	// In compliance mode, gateway contexts are synchronous (critical for audit trail)
	if aq.mode == AuditModeCompliance {
		return aq.writeToDBSync(entry)
	}

	// In performance mode, queue it
	return aq.queueEntry(entry)
}

// LogLLMCallAudit logs a Gateway Mode LLM call audit record
// This is used when SDK reports completion of an LLM call
func (aq *AuditQueue) LogLLMCallAudit(entry AuditEntry) error {
	entry.Type = AuditTypeLLMCallAudit
	entry.Timestamp = time.Now().UTC()

	// In compliance mode, LLM audits are synchronous (critical for audit trail)
	if aq.mode == AuditModeCompliance {
		return aq.writeToDBSync(entry)
	}

	// In performance mode, queue it
	return aq.queueEntry(entry)
}

// LogMCPQueryAudit logs an MCP connector query audit record.
// This captures policy evaluation results for MCP connector operations including:
// - REQUEST phase: SQLi detection, PII blocking
// - RESPONSE phase: PII redaction
// - EXFILTRATION checks: Row/volume limits
//
// In compliance mode, blocked requests and exfiltration violations are written
// synchronously to ensure audit durability. Successful queries are queued for
// async processing in performance mode.
func (aq *AuditQueue) LogMCPQueryAudit(mcpEntry MCPQueryAuditEntry) error {
	// Convert MCPQueryAuditEntry to generic AuditEntry for queue processing
	entry := AuditEntry{
		Type:      AuditTypeMCPQueryAudit,
		Timestamp: time.Now(),
		ClientID:  mcpEntry.ClientID,
		UserID:    mcpEntry.UserID,
		Details: map[string]interface{}{
			"audit_id":                   mcpEntry.AuditID,
			"decision_id":                mcpEntry.DecisionID,
			"policy_versions":            mcpEntry.PolicyVersions,
			"tenant_id":                  mcpEntry.TenantID,
			"org_id":                     mcpEntry.OrgID,
			"connector_name":             mcpEntry.ConnectorName,
			"operation":                  mcpEntry.Operation,
			"statement_hash":             mcpEntry.StatementHash,
			"parameters_hash":            mcpEntry.ParametersHash,
			"parameter_count":            mcpEntry.ParameterCount,
			"request_blocked":            mcpEntry.RequestBlocked,
			"request_block_reason":       mcpEntry.RequestBlockReason,
			"request_policies_evaluated": mcpEntry.RequestPoliciesEvaluated,
			"request_matched_policies":   mcpEntry.RequestMatchedPolicies,
			"response_redacted":          mcpEntry.ResponseRedacted,
			"response_redactions_count":  mcpEntry.ResponseRedactionsCount,
			"response_redacted_fields":   mcpEntry.ResponseRedactedFields,
			"exfil_rows_returned":        mcpEntry.ExfilRowsReturned,
			"exfil_exceeded":             mcpEntry.ExfilExceeded,
			"exfil_limit_type":           mcpEntry.ExfilLimitType,
			"row_count":                  mcpEntry.RowCount,
			"duration_ms":                mcpEntry.DurationMs,
			"success":                    mcpEntry.Success,
			"error_message":              mcpEntry.ErrorMessage,
		},
	}

	// Set severity based on what happened
	switch {
	case mcpEntry.RequestBlocked || mcpEntry.ExfilExceeded:
		entry.Severity = "high"
	case mcpEntry.ResponseRedacted:
		entry.Severity = "medium"
	default:
		entry.Severity = "low"
	}

	// In compliance mode, blocked requests and exfiltration violations are synchronous
	if aq.mode == AuditModeCompliance && (mcpEntry.RequestBlocked || mcpEntry.ExfilExceeded) {
		return aq.writeToDBSync(entry)
	}

	// In performance mode, or for successful queries in compliance mode, queue it
	return aq.queueEntry(entry)
}

// queueEntry queues an entry for async processing
func (aq *AuditQueue) queueEntry(entry AuditEntry) error {
	// The closed check and the send are one step against Shutdown's close
	// (sendMu).
	aq.sendMu.RLock()
	defer aq.sendMu.RUnlock()
	if aq.closed.Load() {
		aq.mu.Lock()
		defer aq.mu.Unlock()
		return aq.writeToFallback(entry)
	}

	select {
	case aq.queue <- entry:
		atomic.AddUint64(&aq.queued, 1)
		return nil
	default:
		// Queue full - write to fallback immediately
		aq.mu.Lock()
		defer aq.mu.Unlock()
		return aq.writeToFallback(entry)
	}
}

// worker processes audit entries from the queue
func (aq *AuditQueue) worker(id int) {
	defer aq.wg.Done()

	for entry := range aq.queue {
		// Try to write to DB with retries
		var err error
		for retry := 0; retry < 3; retry++ {
			if err = aq.writeToDBAsync(entry); err == nil {
				atomic.AddUint64(&aq.processed, 1)
				break
			}

			// Exponential backoff
			time.Sleep(time.Millisecond * time.Duration(100*(retry+1)))
			entry.Retries++
		}

		// If all retries failed, write to fallback
		if err != nil {
			atomic.AddUint64(&aq.failed, 1)
			aq.mu.Lock()
			if fallbackErr := aq.writeToFallback(entry); fallbackErr != nil {
				recordAuditDrop(auditDropFallbackWriteFailed, "worker %d: %s entry (org %q) failed its database write (%v) and its fallback write: %v",
					id, entry.Type, entry.OrgID, err, fallbackErr)
			}
			aq.mu.Unlock()
		}
	}
}

// metricsBatcher batches metrics for efficient writes
func (aq *AuditQueue) metricsBatcher() {
	defer aq.wg.Done()

	batch := make([]AuditEntry, 0, 100)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		select {
		case entry, ok := <-aq.metricsBatch:
			if !ok {
				// Channel closed - flush remaining batch and exit
				if len(batch) > 0 {
					aq.flushMetricsBatch(batch)
				}
				return
			}

			batch = append(batch, entry)

			// Flush if batch is full
			if len(batch) >= 100 {
				aq.flushMetricsBatch(batch)
				batch = batch[:0]
			}

		case <-ticker.C:
			// Periodic flush
			if len(batch) > 0 {
				aq.flushMetricsBatch(batch)
				batch = batch[:0]
			}
		}
	}
}

// flushMetricsBatch writes a batch of metrics to the database.
//
// #4249 row 5705939628: the batch is AGGREGATED before it is written, one
// multi-row UPSERT per organization carrying each policy's hit and block counts
// for the batch, so a busy agent spends one transaction per organization per
// flush rather than one per matched policy per evaluation.
//
// v9 Phase 8 #2384 PR-C1: policy_metrics is ENABLE-RLS (mig 018), so each
// organization's statement runs under WithOrgScope with org_id in the column
// list, and an entry with no organization is dropped, counted.
//
// The conflict target is (org_id, policy_id, date) WHERE policy_id IS NOT NULL,
// the partial unique index migrations/core/186 creates. Before it there was no
// unique index at all, so this statement failed with 42P10 on every write. The
// organization is part of the key because policy ids are shared across
// organizations and the row is RLS-scoped: on a global (policy_id, date) key
// the first organization to write a policy's row on a day would own it, and
// every other organization's UPSERT would conflict with a row its UPDATE policy
// cannot see.
//
// A write that fails for a reason a retry can cure is retried; a permanent one
// (isPermanentAuditWriteError: 42P10, 42501, 22xxx, ...) is not. Either way an
// organization's entries that were not written are counted as
// metrics_write_failed, and every log line goes through the rate-limited drop
// logger.
func (aq *AuditQueue) flushMetricsBatch(batch []AuditEntry) {
	if aq.db == nil || len(batch) == 0 {
		return
	}

	type counts struct{ hits, blocks int }
	byOrg := map[string]map[string]*counts{}
	entriesByOrg := map[string]int{}
	for _, entry := range batch {
		policyID, ok := entry.Details["policy_id"].(string)
		if !ok || policyID == "" {
			continue
		}
		if entry.OrgID == "" {
			recordAuditDrop(auditDropMetricsNoOrg, "policy_metrics entry for policy %s dropped: it carries no organization, and RLS would refuse the row under app_role", policyID)
			continue
		}
		policies, ok := byOrg[entry.OrgID]
		if !ok {
			policies = map[string]*counts{}
			byOrg[entry.OrgID] = policies
		}
		c, ok := policies[policyID]
		if !ok {
			c = &counts{}
			policies[policyID] = c
		}
		c.hits++
		if blocked, ok := entry.Details["blocked"].(bool); ok && blocked {
			c.blocks++
		}
		entriesByOrg[entry.OrgID]++
	}

	orgs := make([]string, 0, len(byOrg))
	for org := range byOrg {
		orgs = append(orgs, org)
	}
	sort.Strings(orgs)
	written := 0
	for _, org := range orgs {
		policies := byOrg[org]
		ids := make([]string, 0, len(policies))
		for id := range policies {
			ids = append(ids, id)
		}
		sort.Strings(ids)

		var values []string
		args := []interface{}{org}
		for _, id := range ids {
			c := policies[id]
			n := len(args)
			values = append(values, fmt.Sprintf("($%d, 'static', $%d, $%d, CURRENT_DATE, $1)", n+1, n+2, n+3))
			args = append(args, id, c.hits, c.blocks)
		}
		query := `INSERT INTO policy_metrics (policy_id, policy_type, hit_count, block_count, date, org_id)
			VALUES ` + strings.Join(values, ", ") + `
			ON CONFLICT (org_id, policy_id, date) WHERE policy_id IS NOT NULL DO UPDATE SET
				hit_count = policy_metrics.hit_count + EXCLUDED.hit_count,
				block_count = policy_metrics.block_count + EXCLUDED.block_count`

		if err := aq.execMetricsWithRetry(org, query, args...); err != nil {
			recordAuditDropN(auditDropMetricsWriteFailed, entriesByOrg[org],
				"%d policy_metrics entries for org %q (%d policies) were not written: %v", entriesByOrg[org], org, len(ids), err)
			continue
		}
		written += entriesByOrg[org]
	}

	atomic.AddUint64(&aq.processed, uint64(written))
	if written > 0 {
		log.Printf("Flushed %d metrics to database", written)
	}
}

// execMetricsWithRetry runs one organization's metrics UPSERT in at most three
// attempts when the failure is transient (two retries, with backoff), and in
// one when it is permanent. Each failed attempt is logged through the rate-limited drop logger, not
// per attempt.
func (aq *AuditQueue) execMetricsWithRetry(orgID, query string, args ...interface{}) error {
	const maxAttempts = 3
	var err error
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		err = WithOrgScope(context.Background(), aq.db, orgID, func(tx *sql.Tx) error {
			_, exErr := tx.Exec(query, args...)
			return exErr
		})
		if err == nil || isPermanentAuditWriteError(err) {
			return err
		}
		if attempt < maxAttempts {
			logAuditRateLimited(auditDropMetricsWriteFailed+"_retry", "policy_metrics write for org %q failed (attempt %d/%d), retrying: %v", orgID, attempt, maxAttempts, err)
			time.Sleep(time.Duration(100*(1<<uint(attempt-1))) * time.Millisecond)
		}
	}
	return err
}

// writeToDBSync writes synchronously to database (for compliance mode)
func (aq *AuditQueue) writeToDBSync(entry AuditEntry) error {
	if aq.db == nil {
		return fmt.Errorf("database connection not initialized")
	}

	// Choose appropriate table and query based on entry type
	switch entry.Type {
	case AuditTypeViolation:
		// v9 Phase 8 #2384 PR-C1: policy_violations is ENABLE-RLS (mig 018).
		// Pin app.current_org_id via execWithRetryOrgScope and include
		// org_id in the INSERT column list so the WITH CHECK predicate
		// matches.
		if entry.OrgID == "" {
			return fmt.Errorf("audit_queue: AuditTypeViolation entry %w — would fail policy_violations RLS WITH CHECK under app_role", errAuditEntryMissingOrgID)
		}
		insertQuery := `
			INSERT INTO policy_violations (violation_type, severity, client_id, user_id, description, details, org_id)
			VALUES ($1, $2, $3, $4, $5, $6, $7)
		`
		detailsJSON, _ := json.Marshal(entry.Details)
		return execWithRetryOrgScope(aq.db, entry.OrgID, insertQuery,
			entry.Details["policy_name"],
			entry.Severity,
			entry.ClientID,
			entry.UserID,
			entry.Details["description"],
			detailsJSON,
			entry.OrgID)

	case AuditTypeAudit:
		// v9 Phase 8 #2384 PR-C1: agent_audit_logs is ENABLE-RLS (mig 018).
		// Same wrap shape as AuditTypeViolation above — org_id column +
		// execWithRetryOrgScope so SET LOCAL matches the row's value.
		if entry.OrgID == "" {
			return fmt.Errorf("audit_queue: AuditTypeAudit entry %w — would fail agent_audit_logs RLS WITH CHECK under app_role", errAuditEntryMissingOrgID)
		}
		insertQuery := `
			INSERT INTO agent_audit_logs (client_id, action, resource, timestamp, org_id)
			VALUES ($1, $2, $3, $4, $5)
		`
		return execWithRetryOrgScope(aq.db, entry.OrgID, insertQuery,
			entry.ClientID,
			entry.Details["action"],
			entry.Details["resource"],
			entry.Timestamp,
			entry.OrgID)

	case AuditTypeMetric:
		// Metrics are always batched and handled by metricsBatcher
		return nil

	case AuditTypeGatewayContext:
		// Gateway Mode pre-check context storage
		insertQuery := `
			INSERT INTO gateway_contexts (
				context_id, client_id, user_token_hash, query_hash,
				data_sources, policies_evaluated, approved, block_reason, expires_at
			) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		`
		// Convert slices to pq.Array for PostgreSQL compatibility
		// (Details stores plain slices for JSON fallback serialization)
		dataSources := toStringSlice(entry.Details["data_sources"])
		policiesEvaluated := toStringSlice(entry.Details["policies_evaluated"])
		return execWithRetry(aq.db, insertQuery,
			entry.Details["context_id"],
			entry.ClientID,
			entry.Details["user_token_hash"],
			entry.Details["query_hash"],
			pq.Array(dataSources),
			pq.Array(policiesEvaluated),
			entry.Details["approved"],
			entry.Details["block_reason"],
			entry.Details["expires_at"])

	case AuditTypeLLMCallAudit:
		// Gateway Mode LLM call audit storage.
		//
		// #3435: org_id is stamped from the authenticated identity. Migration
		// 089 added the column and 094 backfilled the rows that existed then,
		// but this writer and gateway_handlers.go's storeLLMCallAudit both kept
		// omitting it, so every Gateway Mode row written since landed with a
		// NULL organisation and an org-scoped regulator export could not reach
		// it. Written as SQL NULL when blank rather than as '': a
		// blank-but-present tenancy value plants a row no predicate can claim.
		//
		// #3435 R5 CORRECTION: llm_call_audits has THREE writers, not the two an
		// earlier version of this comment implied. The third is
		// openai_compat_handler.go's recordOpenAICompatAudit, which already
		// stamped org_id but bound it raw; it now shares nullIfBlankOrg so all
		// three agree on what an absent organisation looks like on disk.
		//
		// No withOrgScope wrap: migration 101 explicitly left llm_call_audits
		// out of the FORCE ROW LEVEL SECURITY set, so there is no WITH CHECK to
		// satisfy and adding the column to the INSERT is purely additive.
		insertQuery := `
			INSERT INTO llm_call_audits (
				audit_id, context_id, client_id, provider, model,
				prompt_tokens, completion_tokens, total_tokens,
				latency_ms, estimated_cost_usd, metadata, org_id
			) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
		`
		metadataJSON, _ := json.Marshal(entry.Details["metadata"])
		llmOrgID := entry.OrgID
		if llmOrgID == "" {
			llmOrgID, _ = entry.Details["org_id"].(string)
		}
		return execWithRetry(aq.db, insertQuery,
			entry.Details["audit_id"],
			entry.Details["context_id"],
			entry.ClientID,
			entry.Details["provider"],
			entry.Details["model"],
			entry.Details["prompt_tokens"],
			entry.Details["completion_tokens"],
			entry.Details["total_tokens"],
			entry.Details["latency_ms"],
			entry.Details["estimated_cost_usd"],
			metadataJSON,
			nullIfBlankOrg(llmOrgID))

	case AuditTypeMCPQueryAudit:
		// MCP connector query audit storage.
		// v9 Phase 8 B2 (migration 100): mcp_query_audits is FORCE ROW LEVEL
		// SECURITY enforced. Wrap INSERT in WithOrgScope so app.current_org_id
		// matches the row's org_id column at INSERT time (WITH CHECK).
		insertQuery := `
			INSERT INTO mcp_query_audits (
				audit_id, tenant_id, org_id, client_id, user_id, connector_name, operation, statement_hash,
				parameters_hash, parameter_count,
				request_blocked, request_block_reason, request_policies_evaluated, request_matched_policies,
				response_redacted, response_redactions_count, response_redacted_fields,
				exfil_rows_returned, exfil_exceeded, exfil_limit_type,
				row_count, duration_ms, success, error_message
			) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24)
		`
		// Convert slices to pq.Array for PostgreSQL compatibility
		requestMatchedPolicies := toStringSlice(entry.Details["request_matched_policies"])
		responseRedactedFields := toStringSlice(entry.Details["response_redacted_fields"])

		orgID, _ := entry.Details["org_id"].(string)
		return execWithRetryOrgScope(aq.db, orgID, insertQuery,
			entry.Details["audit_id"],
			entry.Details["tenant_id"],
			entry.Details["org_id"],
			entry.ClientID,
			entry.UserID,
			entry.Details["connector_name"],
			entry.Details["operation"],
			entry.Details["statement_hash"],
			entry.Details["parameters_hash"],
			entry.Details["parameter_count"],
			entry.Details["request_blocked"],
			entry.Details["request_block_reason"],
			entry.Details["request_policies_evaluated"],
			pq.Array(requestMatchedPolicies),
			entry.Details["response_redacted"],
			entry.Details["response_redactions_count"],
			pq.Array(responseRedactedFields),
			entry.Details["exfil_rows_returned"],
			entry.Details["exfil_exceeded"],
			entry.Details["exfil_limit_type"],
			entry.Details["row_count"],
			entry.Details["duration_ms"],
			entry.Details["success"],
			entry.Details["error_message"])

	default:
		return fmt.Errorf("unknown entry type: %s", entry.Type)
	}
}

// writeToDBAsync writes asynchronously to database (used by worker goroutines)
func (aq *AuditQueue) writeToDBAsync(entry AuditEntry) error {
	// Use the same implementation as sync (execWithRetry handles retries)
	return aq.writeToDBSync(entry)
}

// writeToFallback writes to the fallback file
func (aq *AuditQueue) writeToFallback(entry AuditEntry) error {
	data, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("failed to marshal entry: %v", err)
	}

	_, err = fmt.Fprintf(aq.fallbackFile, "%s\n", data)
	if err != nil {
		return fmt.Errorf("failed to write to fallback: %v", err)
	}

	return aq.fallbackFile.Sync()
}

// Shutdown gracefully shuts down the queue
func (aq *AuditQueue) Shutdown(ctx context.Context) error {
	log.Println("Shutting down audit queue...")

	// Mark as closed and close the channels under sendMu, so no sender is
	// between its closed check and its send when a channel closes.
	aq.sendMu.Lock()
	aq.closed.Store(true)
	close(aq.queue)
	close(aq.metricsBatch)
	aq.sendMu.Unlock()

	// Wait for workers to finish
	done := make(chan struct{})
	go func() {
		aq.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		log.Printf("Audit queue shutdown complete. Processed: %d, Failed: %d",
			atomic.LoadUint64(&aq.processed), atomic.LoadUint64(&aq.failed))
		return nil
	case <-ctx.Done():
		// Timeout - workers are still running, they'll drain via range on closed channel
		// Just report and return
		log.Printf("Timeout waiting for workers. Processed: %d, Failed: %d",
			atomic.LoadUint64(&aq.processed), atomic.LoadUint64(&aq.failed))
		return ctx.Err()
	}
}

// GetStats returns queue statistics
func (aq *AuditQueue) GetStats() map[string]interface{} {
	return map[string]interface{}{
		"mode":      aq.mode,
		"queued":    atomic.LoadUint64(&aq.queued),
		"processed": atomic.LoadUint64(&aq.processed),
		"failed":    atomic.LoadUint64(&aq.failed),
		"pending":   len(aq.queue),
	}
}

// RecoverFromFallback replays entries from the fallback file to the database
// This should be called during startup to recover any audit entries that failed
// to persist during previous runs. Returns the number of recovered entries.
func (aq *AuditQueue) RecoverFromFallback(fallbackPath string) (int, error) {
	// Check if fallback file exists
	if _, err := os.Stat(fallbackPath); os.IsNotExist(err) {
		log.Println("[AuditQueue] No fallback file found, nothing to recover")
		return 0, nil
	}

	// The queue's own fallback writes take aq.mu, and the rewrite below
	// replaces the file they append to, so recovery holds it throughout: an
	// entry appended between the read and the rename would otherwise land in
	// the replaced file and be lost (#4249 row 5705939628).
	aq.mu.Lock()
	defer aq.mu.Unlock()

	// Open fallback file for reading
	file, err := os.Open(fallbackPath)
	if err != nil {
		return 0, fmt.Errorf("failed to open fallback file for recovery: %v", err)
	}
	defer func() { _ = file.Close() }()

	// Read and parse entries line by line
	var entries []AuditEntry
	var rawLines []string
	scanner := bufio.NewScanner(file)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		if line == "" {
			continue
		}

		var entry AuditEntry
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			recordAuditDrop(auditDropFallbackUnparseable, "fallback line %d could not be parsed and is dropped: %v", lineNum, err)
			continue
		}
		entries = append(entries, entry)
		rawLines = append(rawLines, line)
	}

	if err := scanner.Err(); err != nil {
		return 0, fmt.Errorf("error reading fallback file: %v", err)
	}

	if len(entries) == 0 {
		log.Println("[AuditQueue] Fallback file is empty, nothing to recover")
		// Truncate the empty file
		if err := os.Truncate(fallbackPath, 0); err != nil {
			log.Printf("[AuditQueue] Warning: Failed to truncate empty fallback file: %v", err)
		}
		return 0, nil
	}

	log.Printf("[AuditQueue] Found %d entries in fallback file, starting recovery...", len(entries))

	// Replay entries to database
	recovered := 0
	var failedEntries []AuditEntry

	for i, entry := range entries {
		// Try to write to database with retries
		if err := aq.writeToDBSync(entry); err != nil {
			// Only a failure no retry can cure counts toward the bound; a
			// transient one (the database unreachable, a failover) keeps the
			// entry pending without spending an attempt.
			if isPermanentAuditWriteError(err) {
				entry.RecoveryAttempts++
			}
			if entry.RecoveryAttempts >= maxFallbackRecoveryAttempts {
				// EXHAUSTED IS SET ASIDE, NEVER DELETED. The entry's line
				// moves, byte for byte, to the dead-letter file beside the
				// fallback file, where an operator can replay it once the cause
				// (a grant, a schema) is fixed. It is counted and logged with the
				// path. If the dead-letter write fails, it stays pending.
				deadPath := fallbackPath + ".dead.jsonl"
				if dlErr := appendDeadLetter(deadPath, rawLines[i]); dlErr != nil {
					log.Printf("[AuditQueue] fallback entry (type=%s, org %q) exhausted its recovery attempts but could not be moved to %s, so it stays pending: %v",
						entry.Type, entry.OrgID, deadPath, dlErr)
					failedEntries = append(failedEntries, entry)
					continue
				}
				recordAuditDrop(auditDropRecoveryExhausted, "fallback entry (type=%s, org %q) moved to %s after %d recovery attempts: %v",
					entry.Type, entry.OrgID, deadPath, entry.RecoveryAttempts, err)
				continue
			}
			log.Printf("[AuditQueue] Failed to recover entry (type=%s, attempt %d/%d): %v", entry.Type, entry.RecoveryAttempts, maxFallbackRecoveryAttempts, err)
			failedEntries = append(failedEntries, entry)
			continue
		}
		recovered++
	}

	log.Printf("[AuditQueue] Recovery complete: %d/%d entries recovered", recovered, len(entries))

	// Rewrite fallback file with only failed entries
	if len(failedEntries) > 0 {
		// Write failed entries back to fallback
		// The rewrite replaces the file only when every pending entry was
		// written to the temporary file: a partial rewrite would lose the rest.
		// When it cannot, the original file stays, and the entries this run
		// recovered are replayed again next time (a duplicate row, not a
		// lost one).
		if err := aq.rewriteFallback(fallbackPath, failedEntries); err != nil {
			var reopenErr *fallbackReopenError
			if errors.As(err, &reopenErr) {
				recordAuditDrop(auditDropFallbackReopenFailed, "the fallback file was rewritten but could not be reopened, so later fallback writes go to the replaced file and are lost until restart: %v", err)
			} else {
				log.Printf("[AuditQueue] Warning: the fallback file was not rewritten, so recovered entries will be replayed: %v", err)
			}
		}
		log.Printf("[AuditQueue] %d entries still pending in fallback file", len(failedEntries))
	} else {
		// All entries recovered, truncate the fallback file
		if err := os.Truncate(fallbackPath, 0); err != nil {
			log.Printf("[AuditQueue] Warning: Failed to truncate fallback file: %v", err)
		}
	}

	return recovered, nil
}

// rewriteFallback replaces fallbackPath with entries and, when the queue's own
// fallback file is that path, reopens it, so the queue's later fallback writes
// append to the new file rather than to the replaced one. Caller holds aq.mu.
func (aq *AuditQueue) rewriteFallback(fallbackPath string, entries []AuditEntry) error {
	tmpPath := fallbackPath + ".tmp"
	tmpFile, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("create %s: %w", tmpPath, err)
	}
	for _, entry := range entries {
		data, err := json.Marshal(entry)
		if err == nil {
			_, err = fmt.Fprintf(tmpFile, "%s\n", data)
		}
		if err != nil {
			_ = tmpFile.Close()
			_ = os.Remove(tmpPath)
			return fmt.Errorf("write %s: %w", tmpPath, err)
		}
	}
	if err := tmpFile.Sync(); err != nil {
		_ = tmpFile.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("sync %s: %w", tmpPath, err)
	}
	if err := tmpFile.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("close %s: %w", tmpPath, err)
	}
	if err := os.Rename(tmpPath, fallbackPath); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("rename %s: %w", tmpPath, err)
	}
	if aq.fallbackFile != nil && aq.fallbackFile.Name() == fallbackPath {
		reopened, err := auditFallbackOpen(fallbackPath)
		if err != nil {
			return &fallbackReopenError{path: fallbackPath, err: err}
		}
		_ = aq.fallbackFile.Close()
		aq.fallbackFile = reopened
	}
	return nil
}

// fallbackReopenError is rewriteFallback's failure AFTER the rename: the file
// was rewritten, but the queue's descriptor still names the replaced file.
type fallbackReopenError struct {
	path string
	err  error
}

func (e *fallbackReopenError) Error() string {
	return fmt.Sprintf("reopen %s after the rewrite: %v", e.path, e.err)
}

func (e *fallbackReopenError) Unwrap() error { return e.err }

// auditFallbackOpen opens a fallback file for appending, as NewAuditQueue does.
// It is a variable so a test can make the reopen fail.
var auditFallbackOpen = func(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
}

// appendDeadLetter appends one fallback line to the dead-letter file, created
// with the fallback file's mode (0600), and syncs it.
func appendDeadLetter(path, line string) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(f, "%s\n", line); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// isPermanentAuditWriteError reports whether an audit write failed for a reason
// no retry can cure: an entry with no organization, or a Postgres data
// exception (22), integrity violation (23) or syntax/privilege/schema error
// (42). Anything else - a connection, an admin shutdown, a serialization
// failure, insufficient resources - may succeed later.
func isPermanentAuditWriteError(err error) bool {
	if err == nil {
		return false
	}
	var pqErr *pq.Error
	if errors.As(err, &pqErr) {
		switch pqErr.Code.Class() {
		case "22", "23", "42":
			return true
		}
		return false
	}
	return errors.Is(err, errAuditEntryMissingOrgID)
}

// errAuditEntryMissingOrgID is the refusal of an RLS-scoped audit write whose
// entry names no organization: no retry can cure it.
var errAuditEntryMissingOrgID = errors.New("missing OrgID")

// GetFallbackPath returns the path to the fallback file
func (aq *AuditQueue) GetFallbackPath() string {
	if aq.fallbackFile != nil {
		return aq.fallbackFile.Name()
	}
	return ""
}

// toStringSlice safely converts an interface{} to []string
// Handles: []string, []interface{}, nil, and pq.StringArray
func toStringSlice(v interface{}) []string {
	if v == nil {
		return nil
	}

	switch val := v.(type) {
	case []string:
		return val
	case []interface{}:
		result := make([]string, 0, len(val))
		for _, item := range val {
			if s, ok := item.(string); ok {
				result = append(result, s)
			}
		}
		return result
	case pq.StringArray:
		return []string(val)
	default:
		return nil
	}
}
