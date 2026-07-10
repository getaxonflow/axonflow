// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package agent

import (
	"bufio"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"os"
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
	Type      string                 `json:"type"`
	Timestamp time.Time              `json:"timestamp"`
	Severity  string                 `json:"severity"`
	UserID    string                 `json:"user_id"`
	ClientID  string                 `json:"client_id"`
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
}

// Audit entry types
const (
	AuditTypeViolation       = "violation"
	AuditTypeMetric          = "metric"
	AuditTypeAudit           = "audit"
	AuditTypeGatewayContext  = "gateway_context"
	AuditTypeLLMCallAudit    = "llm_call_audit"
	AuditTypeMCPQueryAudit   = "mcp_query_audit"
)

// MCPQueryAuditEntry represents an audit entry for MCP connector queries.
// This captures policy evaluation results at all three phases:
// REQUEST (pre-execution), RESPONSE (post-execution), and EXFILTRATION checks.
type MCPQueryAuditEntry struct {
	AuditID       string   `json:"audit_id"`
	TenantID      string   `json:"tenant_id"`
	OrgID         string   `json:"org_id"`
	ClientID      string   `json:"client_id"`
	UserID        string   `json:"user_id,omitempty"`
	ConnectorName string   `json:"connector_name"`
	Operation     string   `json:"operation"` // query, execute, list_resources, etc.
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
	RequestBlocked          bool     `json:"request_blocked"`
	RequestBlockReason      string   `json:"request_block_reason,omitempty"`
	RequestPoliciesEvaluated int     `json:"request_policies_evaluated"`
	RequestMatchedPolicies  []string `json:"request_matched_policies,omitempty"`

	// Response phase (post-execution policy evaluation)
	ResponseRedacted       bool     `json:"response_redacted"`
	ResponseRedactionsCount int     `json:"response_redactions_count"`
	ResponseRedactedFields []string `json:"response_redacted_fields,omitempty"`

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

	// In compliance mode, violations are synchronous
	if aq.mode == AuditModeCompliance {
		return aq.writeToDBSync(entry)
	}

	// In performance mode, queue it
	return aq.queueEntry(entry)
}

// LogMetric logs a metric (always async)
func (aq *AuditQueue) LogMetric(entry AuditEntry) error {
	entry.Type = AuditTypeMetric
	entry.Timestamp = time.Now().UTC()

	// Metrics are always async, even in compliance mode
	select {
	case aq.metricsBatch <- entry:
		atomic.AddUint64(&aq.queued, 1)
		return nil
	default:
		// Queue full, drop metric (acceptable for metrics)
		log.Printf("Metrics queue full, dropping entry")
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
	// Check if already closed
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
				log.Printf("Worker %d: Failed to write to fallback: %v", id, fallbackErr)
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

// flushMetricsBatch writes a batch of metrics to the database
func (aq *AuditQueue) flushMetricsBatch(batch []AuditEntry) {
	if aq.db == nil || len(batch) == 0 {
		return
	}

	// Batch INSERT for metrics (policy hit counts)
	for _, entry := range batch {
		if policyID, ok := entry.Details["policy_id"].(string); ok {
			blockCount := 0
			if blocked, ok := entry.Details["blocked"].(bool); ok && blocked {
				blockCount = 1
			}

			// v9 Phase 8 #2384 PR-C1: policy_metrics is ENABLE-RLS (mig 018).
			// INSERT/ON CONFLICT UPSERT WITH CHECK fires under app_role —
			// the predicate org_id = current_setting('app.current_org_id')
			// rejects rows without org_id matching SET LOCAL. We include
			// org_id in the INSERT column list and pass entry.OrgID into
			// execWithRetryOrgScope. The ON CONFLICT (policy_id, date)
			// conflict-target stays as-is; the UPDATE arm doesn't need to
			// re-set org_id because the conflict-matched row already has
			// the correct value (any cross-org collision would have been
			// rejected at INSERT time by FORCE-RLS).
			updateQuery := `
				INSERT INTO policy_metrics (policy_id, policy_type, hit_count, block_count, date, org_id)
				VALUES ($1, 'static', 1, $2, CURRENT_DATE, $3)
				ON CONFLICT (policy_id, date) DO UPDATE SET
					hit_count = policy_metrics.hit_count + 1,
					block_count = policy_metrics.block_count + $2
			`

			if entry.OrgID == "" {
				log.Printf("[audit] policy_metrics flush dropped (policy_id=%s): entry.OrgID empty — RLS would deny under app_role", policyID)
				continue
			}
			// Use retry for each metric update (they're independent)
			if err := execWithRetryOrgScope(aq.db, entry.OrgID, updateQuery, policyID, blockCount, entry.OrgID); err != nil {
				log.Printf("Failed to update metric for policy %s: %v", policyID, err)
			}
		}
	}

	atomic.AddUint64(&aq.processed, uint64(len(batch)))
	log.Printf("Flushed %d metrics to database", len(batch))
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
			return fmt.Errorf("audit_queue: AuditTypeViolation entry missing OrgID — would fail policy_violations RLS WITH CHECK under app_role")
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
			return fmt.Errorf("audit_queue: AuditTypeAudit entry missing OrgID — would fail agent_audit_logs RLS WITH CHECK under app_role")
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
		// Gateway Mode LLM call audit storage
		insertQuery := `
			INSERT INTO llm_call_audits (
				audit_id, context_id, client_id, provider, model,
				prompt_tokens, completion_tokens, total_tokens,
				latency_ms, estimated_cost_usd, metadata
			) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		`
		metadataJSON, _ := json.Marshal(entry.Details["metadata"])
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
			metadataJSON)

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

	// Mark as closed first to prevent new entries
	aq.closed.Store(true)

	// Close channels
	close(aq.queue)
	close(aq.metricsBatch)

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

	// Open fallback file for reading
	file, err := os.Open(fallbackPath)
	if err != nil {
		return 0, fmt.Errorf("failed to open fallback file for recovery: %v", err)
	}
	defer func() { _ = file.Close() }()

	// Read and parse entries line by line
	var entries []AuditEntry
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
			log.Printf("[AuditQueue] Failed to parse line %d in fallback: %v", lineNum, err)
			continue
		}
		entries = append(entries, entry)
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

	for _, entry := range entries {
		// Try to write to database with retries
		if err := aq.writeToDBSync(entry); err != nil {
			log.Printf("[AuditQueue] Failed to recover entry (type=%s): %v", entry.Type, err)
			failedEntries = append(failedEntries, entry)
			continue
		}
		recovered++
	}

	log.Printf("[AuditQueue] Recovery complete: %d/%d entries recovered", recovered, len(entries))

	// Rewrite fallback file with only failed entries
	if len(failedEntries) > 0 {
		// Write failed entries back to fallback
		tmpPath := fallbackPath + ".tmp"
		tmpFile, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
		if err != nil {
			log.Printf("[AuditQueue] Warning: Failed to create temp fallback: %v", err)
		} else {
			for _, entry := range failedEntries {
				data, _ := json.Marshal(entry)
				_, _ = fmt.Fprintf(tmpFile, "%s\n", data)
			}
			_ = tmpFile.Sync()
			_ = tmpFile.Close()

			// Atomic rename
			if err := os.Rename(tmpPath, fallbackPath); err != nil {
				log.Printf("[AuditQueue] Warning: Failed to rename temp fallback: %v", err)
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