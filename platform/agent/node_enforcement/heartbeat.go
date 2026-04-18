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

//go:build enterprise

package node_enforcement

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/google/uuid"
)

// HeartbeatService manages agent/orchestrator heartbeats for node count tracking
type HeartbeatService struct {
	db          *sql.DB
	instanceID  string
	instanceType string
	licenseKey  string
	orgID       string
	interval    time.Duration
	stopCh      chan struct{}
}

// HostInfo contains system information about the instance
type HostInfo struct {
	Hostname   string `json:"hostname"`
	IPAddress  string `json:"ip_address"`
	Port       int    `json:"port"`
	Version    string `json:"version"`
	OS         string `json:"os"`
	CPUCores   int    `json:"cpu_cores"`
	MemoryMB   int    `json:"memory_mb"`
	Region     string `json:"region"`
}

// NewHeartbeatService creates a new heartbeat service
func NewHeartbeatService(db *sql.DB, instanceType, licenseKey, orgID string) *HeartbeatService {
	// Generate unique instance ID (hostname-pid or custom)
	hostname, _ := os.Hostname()
	pid := os.Getpid()
	instanceID := fmt.Sprintf("%s-%d-%s", hostname, pid, uuid.New().String()[:8])

	return &HeartbeatService{
		db:           db,
		instanceID:   instanceID,
		instanceType: instanceType, // "agent" or "orchestrator"
		licenseKey:   licenseKey,
		orgID:        orgID,
		interval:     2 * time.Minute, // Send heartbeat every 2 minutes
		stopCh:       make(chan struct{}),
	}
}

// Start begins sending periodic heartbeats
func (s *HeartbeatService) Start(ctx context.Context) error {
	// Send initial heartbeat
	if err := s.sendHeartbeat(ctx); err != nil {
		return fmt.Errorf("failed to send initial heartbeat: %w", err)
	}

	// Start background goroutine for periodic heartbeats
	go s.heartbeatLoop(ctx)

	return nil
}

// Stop stops the heartbeat service
func (s *HeartbeatService) Stop() {
	close(s.stopCh)
	// Remove this instance from heartbeats table
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.removeHeartbeat(ctx); err != nil {
		log.Printf("Error removing heartbeat on stop: %v", err)
	}
}

// heartbeatLoop sends periodic heartbeats
func (s *HeartbeatService) heartbeatLoop(ctx context.Context) {
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := s.sendHeartbeat(ctx); err != nil {
				fmt.Printf("Heartbeat error: %v\n", err)
			}
		case <-s.stopCh:
			return
		case <-ctx.Done():
			return
		}
	}
}

// sendHeartbeat updates or inserts this instance's heartbeat
func (s *HeartbeatService) sendHeartbeat(ctx context.Context) error {
	// Hash license key for privacy (don't store raw key in DB)
	licenseKeyHash := hashLicenseKey(s.licenseKey)

	// Collect host info
	hostInfo, err := getHostInfo()
	if err != nil {
		return fmt.Errorf("failed to collect host info: %w", err)
	}

	hostInfoJSON, err := json.Marshal(hostInfo)
	if err != nil {
		return fmt.Errorf("failed to marshal host info: %w", err)
	}

	// Upsert heartbeat (insert or update if exists)
	query := `
		INSERT INTO agent_heartbeats (
			instance_id, instance_type, host_name, ip_address, port,
			version, license_key_hash, org_id, region,
			last_heartbeat, heartbeat_count, host_info
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW(), 1, $10)
		ON CONFLICT (instance_id, instance_type)
		DO UPDATE SET
			last_heartbeat = NOW(),
			heartbeat_count = agent_heartbeats.heartbeat_count + 1,
			host_info = $10
	`

	_, err = s.db.ExecContext(ctx, query,
		s.instanceID,
		s.instanceType,
		hostInfo.Hostname,
		hostInfo.IPAddress,
		hostInfo.Port,
		hostInfo.Version,
		licenseKeyHash,
		s.orgID,
		hostInfo.Region,
		hostInfoJSON,
	)

	if err != nil {
		return fmt.Errorf("failed to upsert heartbeat: %w", err)
	}

	return nil
}

// removeHeartbeat removes this instance from the heartbeats table (on shutdown)
func (s *HeartbeatService) removeHeartbeat(ctx context.Context) error {
	query := `DELETE FROM agent_heartbeats WHERE instance_id = $1`
	_, err := s.db.ExecContext(ctx, query, s.instanceID)
	if err != nil {
		return fmt.Errorf("failed to remove heartbeat: %w", err)
	}
	return nil
}

// hashLicenseKey creates a SHA256 hash of the license key
func hashLicenseKey(licenseKey string) string {
	hash := sha256.Sum256([]byte(licenseKey))
	return hex.EncodeToString(hash[:])
}

// getHostInfo collects system information
func getHostInfo() (*HostInfo, error) {
	hostname, _ := os.Hostname()

	// Get version from environment or default
	version := os.Getenv("AXONFLOW_VERSION")
	if version == "" {
		version = "1.0.0"
	}

	// Get region from environment
	region := os.Getenv("AWS_REGION")
	if region == "" {
		region = "unknown"
	}

	// Get port from environment
	port := 8080
	if portStr := os.Getenv("PORT"); portStr != "" {
		if _, err := fmt.Sscanf(portStr, "%d", &port); err != nil {
			log.Printf("Warning: failed to parse PORT '%s', using default 8080: %v", portStr, err)
		}
	}

	// Get IP address from environment or use placeholder
	ipAddress := os.Getenv("INSTANCE_IP")
	if ipAddress == "" {
		ipAddress = "0.0.0.0" // Placeholder for INET type compatibility
	}

	return &HostInfo{
		Hostname:  hostname,
		IPAddress: ipAddress,
		Port:      port,
		Version:   version,
		OS:        fmt.Sprintf("%s/%s", os.Getenv("GOOS"), os.Getenv("GOARCH")),
		Region:    region,
	}, nil
}

// GetActiveNodeCount returns the current active node count for a license
func GetActiveNodeCount(ctx context.Context, db *sql.DB, licenseKeyHash string) (int, error) {
	query := `
		SELECT COUNT(*)
		FROM agent_heartbeats
		WHERE license_key_hash = $1
		  AND last_heartbeat > NOW() - INTERVAL '5 minutes'
	`

	var count int
	err := db.QueryRowContext(ctx, query, licenseKeyHash).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to get active node count: %w", err)
	}

	return count, nil
}

// GetActiveNodesByOrg returns the active node count grouped by organization
func GetActiveNodesByOrg(ctx context.Context, db *sql.DB) (map[string]int, error) {
	query := `
		SELECT org_id, COUNT(*)
		FROM agent_heartbeats
		WHERE last_heartbeat > NOW() - INTERVAL '5 minutes'
		GROUP BY org_id
	`

	rows, err := db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to query active nodes by org: %w", err)
	}
	defer func() {
		if err := rows.Close(); err != nil {
			log.Printf("Error closing rows: %v", err)
		}
	}()

	result := make(map[string]int)
	for rows.Next() {
		var orgID string
		var count int
		if err := rows.Scan(&orgID, &count); err != nil {
			return nil, err
		}
		result[orgID] = count
	}

	return result, nil
}

// CleanupStaleHeartbeats removes heartbeats older than 1 hour
func CleanupStaleHeartbeats(ctx context.Context, db *sql.DB) error {
	query := `
		DELETE FROM agent_heartbeats
		WHERE last_heartbeat < NOW() - INTERVAL '1 hour'
	`

	result, err := db.ExecContext(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to cleanup stale heartbeats: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows > 0 {
		fmt.Printf("Cleaned up %d stale heartbeats\n", rows)
	}

	return nil
}
