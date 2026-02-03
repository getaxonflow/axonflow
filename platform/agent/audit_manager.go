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
	"context"
	"database/sql"
	"fmt"
	"log"
)

// AuditManager provides standalone audit queue lifecycle management.
// It decouples the AuditQueue from DatabasePolicyEngine so that all modes
// (proxy, gateway, MCP) can access the audit queue without going through
// the database policy engine.
type AuditManager struct {
	queue *AuditQueue
	db    *sql.DB
}

// NewAuditManager creates a new AuditManager with its own AuditQueue.
// The queue is initialized with the given parameters and starts processing
// immediately. Call Shutdown() during graceful shutdown.
func NewAuditManager(db *sql.DB, mode AuditMode, queueSize, workers int, fallbackPath string) (*AuditManager, error) {
	queue, err := NewAuditQueue(mode, queueSize, workers, db, fallbackPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create audit queue: %w", err)
	}

	return &AuditManager{
		queue: queue,
		db:    db,
	}, nil
}

// GetQueue returns the underlying AuditQueue for use by handlers.
func (am *AuditManager) GetQueue() *AuditQueue {
	if am == nil {
		return nil
	}
	return am.queue
}

// RecoverEntries recovers any failed audit entries from the fallback file.
// Should be called during startup after initialization.
func (am *AuditManager) RecoverEntries() (int, error) {
	if am == nil || am.queue == nil {
		return 0, nil
	}

	fallbackPath := am.queue.GetFallbackPath()
	if fallbackPath == "" {
		return 0, nil
	}

	return am.queue.RecoverFromFallback(fallbackPath)
}

// Shutdown gracefully shuts down the audit queue, draining pending entries.
func (am *AuditManager) Shutdown(ctx context.Context) error {
	if am == nil || am.queue == nil {
		return nil
	}
	return am.queue.Shutdown(ctx)
}

// Global audit manager instance — initialized before any engine.
var auditManager *AuditManager

// initAuditManager creates and initializes the global AuditManager.
// Must be called before DatabasePolicyEngine or shared engine initialization.
func initAuditManager(db *sql.DB) {
	performanceMode := getEnv("AGENT_PERFORMANCE_MODE", "") == "true"

	var mode AuditMode
	if performanceMode {
		mode = AuditModePerformance
		log.Println("Agent running in PERFORMANCE MODE - async audit writes enabled")
	} else {
		mode = AuditModeCompliance
		log.Println("Agent running in COMPLIANCE MODE - sync audit writes for violations")
	}

	fallbackPath := getEnv("AUDIT_FALLBACK_PATH", "/var/lib/axonflow/audit/audit_fallback.jsonl")

	var err error
	auditManager, err = NewAuditManager(db, mode, 10000, 3, fallbackPath)
	if err != nil {
		log.Printf("Warning: Failed to initialize audit manager: %v", err)
		log.Println("Falling back to direct database writes (no queue)")
		return
	}

	log.Println("✅ Audit manager initialized")
}
