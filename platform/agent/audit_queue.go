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

package agent

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sync"
	"time"
)

// AuditMode defines how audit logs are persisted
type AuditMode string

const (
	AuditModeCompliance  AuditMode = "compliance"  // Sync writes for violations
	AuditModePerformance AuditMode = "performance" // Async for everything
)

// AuditEntry represents an audit log entry
type AuditEntry struct {
	Type      string                 `json:"type"`
	Timestamp time.Time              `json:"timestamp"`
	Severity  string                 `json:"severity"`
	UserID    string                 `json:"user_id"`
	ClientID  string                 `json:"client_id"`
	Details   map[string]interface{} `json:"details"`
	Retries   int                    `json:"-"`
}

// AuditQueue manages async audit logging with persistence guarantees
type AuditQueue struct {
	mode         AuditMode
	queue        chan AuditEntry
	metricsBatch chan AuditEntry
	workers      int
	wg           sync.WaitGroup
	db           *sql.DB
	fallbackFile *os.File
	mu           sync.Mutex

	// Metrics
	processed    uint64
	failed       uint64
	queued       uint64
}

// NewAuditQueue creates a new audit queue
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

// LogViolation logs a policy violation
func (aq *AuditQueue) LogViolation(entry AuditEntry) error {
	entry.Type = "violation"
	entry.Timestamp = time.Now()

	// In compliance mode, violations are synchronous
	if aq.mode == AuditModeCompliance {
		return aq.writeToDBSync(entry)
	}

	// In performance mode, queue it
	return aq.queueEntry(entry)
}

// LogMetric logs a metric (always async)
func (aq *AuditQueue) LogMetric(entry AuditEntry) error {
	entry.Type = "metric"
	entry.Timestamp = time.Now()

	// Metrics are always async, even in compliance mode
	select {
	case aq.metricsBatch <- entry:
		aq.queued++
		return nil
	default:
		// Queue full, drop metric (acceptable for metrics)
		log.Printf("Metrics queue full, dropping entry")
		return nil
	}
}

// queueEntry queues an entry for async processing
func (aq *AuditQueue) queueEntry(entry AuditEntry) error {
	select {
	case aq.queue <- entry:
		aq.queued++
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
				aq.processed++
				break
			}

			// Exponential backoff
			time.Sleep(time.Millisecond * time.Duration(100*(retry+1)))
			entry.Retries++
		}

		// If all retries failed, write to fallback
		if err != nil {
			aq.failed++
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

			updateQuery := `
				INSERT INTO policy_metrics (policy_id, policy_type, hit_count, block_count, date)
				VALUES ($1, 'static', 1, $2, CURRENT_DATE)
				ON CONFLICT (policy_id, date) DO UPDATE SET
					hit_count = policy_metrics.hit_count + 1,
					block_count = policy_metrics.block_count + $2
			`

			// Use retry for each metric update (they're independent)
			if err := execWithRetry(aq.db, updateQuery, policyID, blockCount); err != nil {
				log.Printf("Failed to update metric for policy %s: %v", policyID, err)
			}
		}
	}

	aq.processed += uint64(len(batch))
	log.Printf("Flushed %d metrics to database", len(batch))
}

// writeToDBSync writes synchronously to database (for compliance mode)
func (aq *AuditQueue) writeToDBSync(entry AuditEntry) error {
	if aq.db == nil {
		return fmt.Errorf("database connection not initialized")
	}

	// Choose appropriate table and query based on entry type
	switch entry.Type {
	case "violation":
		insertQuery := `
			INSERT INTO policy_violations (violation_type, severity, client_id, user_id, description, details)
			VALUES ($1, $2, $3, $4, $5, $6)
		`
		detailsJSON, _ := json.Marshal(entry.Details)
		return execWithRetry(aq.db, insertQuery,
			entry.Details["policy_name"],
			entry.Severity,
			entry.ClientID,
			entry.UserID,
			entry.Details["description"],
			detailsJSON)

	case "audit":
		insertQuery := `
			INSERT INTO agent_audit_logs (client_id, action, resource, timestamp)
			VALUES ($1, $2, $3, $4)
		`
		return execWithRetry(aq.db, insertQuery,
			entry.ClientID,
			entry.Details["action"],
			entry.Details["resource"],
			entry.Timestamp)

	case "metric":
		// Metrics are always batched and handled by metricsBatcher
		return nil

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
			aq.processed, aq.failed)
		return nil
	case <-ctx.Done():
		// Timeout - drain remaining entries to fallback
		remaining := len(aq.queue)
		for entry := range aq.queue {
			if err := aq.writeToFallback(entry); err != nil {
				log.Printf("Failed to write entry to fallback during timeout: %v", err)
			}
		}
		log.Printf("Timeout: Saved %d entries to fallback", remaining)
		return ctx.Err()
	}
}

// GetStats returns queue statistics
func (aq *AuditQueue) GetStats() map[string]interface{} {
	return map[string]interface{}{
		"mode":      aq.mode,
		"queued":    aq.queued,
		"processed": aq.processed,
		"failed":    aq.failed,
		"pending":   len(aq.queue),
	}
}