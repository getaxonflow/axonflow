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

package marketplace

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/marketplacemetering"
	"github.com/aws/aws-sdk-go-v2/service/marketplacemetering/types"
)

// MeteringService handles AWS Marketplace metering for container products
type MeteringService struct {
	client      MeteringClient
	db          *sql.DB
	productCode string
	dimension   string
	interval    time.Duration
	dryRun      bool
	stopCh      chan struct{}
}

// UsageRecord represents a metering record
type UsageRecord struct {
	Timestamp      time.Time
	Quantity       int
	Dimension      string
	CustomerID     string
	Status         string
	RequestID      string
	ErrorMessage   string
}

// NewMeteringService creates a new AWS Marketplace metering service
func NewMeteringService(db *sql.DB, productCode string) (*MeteringService, error) {
	// Load AWS SDK config with explicit region
	cfg, err := config.LoadDefaultConfig(
		context.Background(),
		config.WithRegion("eu-central-1"), // Default region
	)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	// Create metering client
	client := marketplacemetering.NewFromConfig(cfg)

	// Dry run mode for testing (doesn't send to AWS)
	dryRun := os.Getenv("METERING_DRY_RUN") == "true"

	return &MeteringService{
		client:      client,
		db:          db,
		productCode: productCode,
		dimension:   "Nodes", // AWS Marketplace dimension name
		interval:    1 * time.Hour, // Meter every hour
		dryRun:      dryRun,
		stopCh:      make(chan struct{}),
	}, nil
}

// Start begins hourly metering
func (s *MeteringService) Start(ctx context.Context) error {
	// Start metering in background (don't block startup)
	go func() {
		// Register usage immediately (in background)
		if err := s.registerUsage(ctx); err != nil {
			fmt.Printf("Initial usage registration failed: %v\n", err)
		}

		// Send first metering record (in background)
		if err := s.meterUsage(ctx); err != nil {
			fmt.Printf("Initial metering failed: %v\n", err)
		}

		// Start hourly metering loop
		s.meteringLoop(ctx)
	}()

	fmt.Println("✅ AWS Marketplace metering service started (background)")
	return nil
}

// Stop stops the metering service
func (s *MeteringService) Stop() {
	close(s.stopCh)
}

// meteringLoop sends usage records hourly
func (s *MeteringService) meteringLoop(ctx context.Context) {
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := s.meterUsage(ctx); err != nil {
				fmt.Printf("Metering error: %v\n", err)
			}
		case <-s.stopCh:
			return
		case <-ctx.Done():
			return
		}
	}
}

// registerUsage registers this container with AWS Marketplace (required for entitlement)
func (s *MeteringService) registerUsage(ctx context.Context) error {
	if s.dryRun {
		fmt.Println("[DRY RUN] Would register usage with AWS Marketplace")
		return nil
	}

	input := &marketplacemetering.RegisterUsageInput{
		ProductCode:      aws.String(s.productCode),
		PublicKeyVersion: aws.Int32(1),
	}

	output, err := s.client.RegisterUsage(ctx, input)
	if err != nil {
		return fmt.Errorf("failed to register usage: %w", err)
	}

	fmt.Printf("✅ Registered with AWS Marketplace: Signature=%s\n",
		aws.ToString(output.Signature))

	return nil
}

// meterUsage sends a usage record to AWS Marketplace
func (s *MeteringService) meterUsage(ctx context.Context) error {
	// Get current active node count
	nodeCount, err := s.getActiveNodeCount(ctx)
	if err != nil {
		return fmt.Errorf("failed to get node count: %w", err)
	}

	if nodeCount == 0 {
		fmt.Println("No active nodes, skipping metering")
		return nil
	}

	// Prepare usage record
	now := time.Now().UTC()
	usageAllocations := []types.UsageAllocation{
		{
			AllocatedUsageQuantity: aws.Int32(int32(nodeCount)),
			Tags: []types.Tag{
				{
					Key:   aws.String("NodeType"),
					Value: aws.String("Agent"),
				},
			},
		},
	}

	input := &marketplacemetering.MeterUsageInput{
		ProductCode:      aws.String(s.productCode),
		Timestamp:        aws.Time(now),
		UsageDimension:   aws.String(s.dimension),
		UsageQuantity:    aws.Int32(int32(nodeCount)),
		UsageAllocations: usageAllocations,
		DryRun:           aws.Bool(s.dryRun),
	}

	// Retry logic (5 attempts with exponential backoff)
	var output *marketplacemetering.MeterUsageOutput
	var lastErr error

	for attempt := 1; attempt <= 5; attempt++ {
		output, lastErr = s.client.MeterUsage(ctx, input)
		if lastErr == nil {
			break
		}

		// Exponential backoff
		backoff := time.Duration(attempt*attempt) * time.Second
		fmt.Printf("Metering attempt %d failed: %v. Retrying in %v...\n", attempt, lastErr, backoff)
		time.Sleep(backoff)
	}

	if lastErr != nil {
		// Queue for retry
		if err := s.queueFailedRecord(ctx, nodeCount, lastErr); err != nil {
			fmt.Printf("Failed to queue record: %v\n", err)
		}
		return fmt.Errorf("metering failed after 5 attempts: %w", lastErr)
	}

	// Store successful record
	record := &UsageRecord{
		Timestamp:    now,
		Quantity:     nodeCount,
		Dimension:    s.dimension,
		CustomerID:   "", // Populated by AWS
		Status:       "SUCCESS",
		RequestID:    aws.ToString(output.MeteringRecordId),
		ErrorMessage: "",
	}

	if err := s.storeUsageRecord(ctx, record); err != nil {
		fmt.Printf("Failed to store usage record: %v\n", err)
	}

	fmt.Printf("✅ Metered %d nodes to AWS Marketplace (RecordID: %s)\n",
		nodeCount, aws.ToString(output.MeteringRecordId))

	return nil
}

// getActiveNodeCount queries the database for active node count
func (s *MeteringService) getActiveNodeCount(ctx context.Context) (int, error) {
	query := `
		SELECT COUNT(*)
		FROM agent_heartbeats
		WHERE last_heartbeat > NOW() - INTERVAL '5 minutes'
	`

	var count int
	err := s.db.QueryRowContext(ctx, query).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to query node count: %w", err)
	}

	return count, nil
}

// storeUsageRecord stores a metering record in the database
func (s *MeteringService) storeUsageRecord(ctx context.Context, record *UsageRecord) error {
	query := `
		INSERT INTO marketplace_usage_records (
			timestamp, quantity, dimension, customer_id, status, request_id, error_message
		) VALUES ($1, $2, $3, $4, $5, $6, $7)
	`

	_, err := s.db.ExecContext(ctx, query,
		record.Timestamp,
		record.Quantity,
		record.Dimension,
		record.CustomerID,
		record.Status,
		record.RequestID,
		record.ErrorMessage,
	)

	if err != nil {
		return fmt.Errorf("failed to store usage record: %w", err)
	}

	return nil
}

// queueFailedRecord queues a failed metering record for retry
func (s *MeteringService) queueFailedRecord(ctx context.Context, quantity int, err error) error {
	record := &UsageRecord{
		Timestamp:    time.Now().UTC(),
		Quantity:     quantity,
		Dimension:    s.dimension,
		Status:       "FAILED",
		ErrorMessage: err.Error(),
	}

	query := `
		INSERT INTO marketplace_usage_records (
			timestamp, quantity, dimension, status, error_message
		) VALUES ($1, $2, $3, $4, $5)
	`

	_, dbErr := s.db.ExecContext(ctx, query,
		record.Timestamp,
		record.Quantity,
		record.Dimension,
		record.Status,
		record.ErrorMessage,
	)

	return dbErr
}

// RetryFailedRecords attempts to resend failed metering records
func (s *MeteringService) RetryFailedRecords(ctx context.Context) error {
	query := `
		SELECT id, timestamp, quantity, dimension
		FROM marketplace_usage_records
		WHERE status = 'FAILED'
		  AND timestamp > NOW() - INTERVAL '24 hours'
		ORDER BY timestamp ASC
		LIMIT 100
	`

	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to query failed records: %w", err)
	}
	defer func() {
		if err := rows.Close(); err != nil {
			log.Printf("Error closing rows: %v", err)
		}
	}()

	retryCount := 0
	successCount := 0

	for rows.Next() {
		var id int64
		var timestamp time.Time
		var quantity int
		var dimension string

		if err := rows.Scan(&id, &timestamp, &quantity, &dimension); err != nil {
			continue
		}

		retryCount++

		// Retry metering
		input := &marketplacemetering.MeterUsageInput{
			ProductCode:    aws.String(s.productCode),
			Timestamp:      aws.Time(timestamp),
			UsageDimension: aws.String(dimension),
			UsageQuantity:  aws.Int32(int32(quantity)),
			DryRun:         aws.Bool(s.dryRun),
		}

		output, err := s.client.MeterUsage(ctx, input)
		if err != nil {
			fmt.Printf("Retry failed for record %d: %v\n", id, err)
			continue
		}

		// Mark as successful
		updateQuery := `
			UPDATE marketplace_usage_records
			SET status = 'SUCCESS', request_id = $1, error_message = NULL
			WHERE id = $2
		`
		_, err = s.db.ExecContext(ctx, updateQuery, aws.ToString(output.MeteringRecordId), id)
		if err != nil {
			fmt.Printf("Failed to update record %d: %v\n", id, err)
			continue
		}

		successCount++
	}

	fmt.Printf("Retried %d failed records, %d succeeded\n", retryCount, successCount)
	return nil
}

// GetUsageHistory returns usage history for analytics
func GetUsageHistory(ctx context.Context, db *sql.DB, days int) ([]UsageRecord, error) {
	query := `
		SELECT timestamp, quantity, dimension, customer_id, status, request_id, error_message
		FROM marketplace_usage_records
		WHERE timestamp > NOW() - INTERVAL '$1 days'
		ORDER BY timestamp DESC
	`

	rows, err := db.QueryContext(ctx, query, days)
	if err != nil {
		return nil, fmt.Errorf("failed to query usage history: %w", err)
	}
	defer func() {
		if err := rows.Close(); err != nil {
			log.Printf("Error closing rows: %v", err)
		}
	}()

	var records []UsageRecord
	for rows.Next() {
		var r UsageRecord
		if err := rows.Scan(&r.Timestamp, &r.Quantity, &r.Dimension, &r.CustomerID, &r.Status, &r.RequestID, &r.ErrorMessage); err != nil {
			continue
		}
		records = append(records, r)
	}

	return records, nil
}
