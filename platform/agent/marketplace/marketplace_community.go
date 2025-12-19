//go:build !enterprise

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

// Package marketplace provides AWS Marketplace metering integration.
// This is the Community stub - metering is disabled in Community mode.
package marketplace

import (
	"context"
	"database/sql"
	"time"
)

// MeteringService handles AWS Marketplace metering for container products.
// Community stub: No-op implementation - metering is disabled in Community mode.
type MeteringService struct {
	// No fields needed for Community stub
}

// UsageRecord represents a metering record
type UsageRecord struct {
	Timestamp    time.Time
	Quantity     int
	Dimension    string
	CustomerID   string
	Status       string
	RequestID    string
	ErrorMessage string
}

// NewMeteringService creates a new AWS Marketplace metering service.
// Community stub: Returns a no-op service.
func NewMeteringService(db *sql.DB, productCode string) (*MeteringService, error) {
	return &MeteringService{}, nil
}

// Start begins hourly metering.
// Community stub: No-op - metering is disabled in Community mode.
func (s *MeteringService) Start(ctx context.Context) error {
	// No-op in Community mode - AWS Marketplace metering is an enterprise feature
	return nil
}

// Stop stops the metering service.
// Community stub: No-op.
func (s *MeteringService) Stop() {
	// No-op in Community mode
}

// RetryFailedRecords attempts to resend failed metering records.
// Community stub: No-op - always returns nil.
func (s *MeteringService) RetryFailedRecords(ctx context.Context) error {
	// No-op in Community mode
	return nil
}

// GetUsageHistory returns usage history for analytics.
// Community stub: Returns empty slice.
func GetUsageHistory(ctx context.Context, db *sql.DB, days int) ([]UsageRecord, error) {
	return []UsageRecord{}, nil
}
