//go:build !enterprise

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

// Package node_enforcement provides node count monitoring and enforcement.
// This is the OSS stub - node enforcement is disabled in OSS mode.
package node_enforcement

import (
	"context"
	"database/sql"
	"time"
)

// HeartbeatService manages agent/orchestrator heartbeats for node count tracking.
// OSS stub: No-op implementation - heartbeat tracking is disabled in OSS mode.
type HeartbeatService struct {
	// No fields needed for OSS stub
}

// HostInfo contains system information about the instance
type HostInfo struct {
	Hostname  string `json:"hostname"`
	IPAddress string `json:"ip_address"`
	Port      int    `json:"port"`
	Version   string `json:"version"`
	OS        string `json:"os"`
	CPUCores  int    `json:"cpu_cores"`
	MemoryMB  int    `json:"memory_mb"`
	Region    string `json:"region"`
}

// NewHeartbeatService creates a new heartbeat service.
// OSS stub: Returns a no-op service.
func NewHeartbeatService(db *sql.DB, instanceType, licenseKey, orgID string) *HeartbeatService {
	return &HeartbeatService{}
}

// Start begins sending periodic heartbeats.
// OSS stub: No-op - heartbeat tracking is disabled in OSS mode.
func (s *HeartbeatService) Start(ctx context.Context) error {
	// No-op in OSS mode - node tracking is an enterprise feature
	return nil
}

// Stop stops the heartbeat service.
// OSS stub: No-op.
func (s *HeartbeatService) Stop() {
	// No-op in OSS mode
}

// NodeMonitor monitors node counts against license limits.
// OSS stub: No-op implementation - node monitoring is disabled in OSS mode.
type NodeMonitor struct {
	// No fields needed for OSS stub
}

// ViolationInfo contains details about a node limit violation
type ViolationInfo struct {
	OrgID             string
	LicenseKeyHash    string
	Tier              string
	MaxNodesAllowed   int
	ActualNodeCount   int
	ExcessNodes       int
	ActiveInstances   []string
	ViolationDuration time.Duration
}

// AlertService interface for sending alerts (Slack, email, CloudWatch)
type AlertService interface {
	SendNodeViolationAlert(ctx context.Context, violation *ViolationInfo) error
	SendNodeCountWarning(ctx context.Context, orgID string, usage float64) error
}

// NewNodeMonitor creates a new node monitor.
// OSS stub: Returns a no-op monitor.
func NewNodeMonitor(db *sql.DB, alerter AlertService) *NodeMonitor {
	return &NodeMonitor{}
}

// Start begins monitoring node counts.
// OSS stub: No-op - node monitoring is disabled in OSS mode.
func (m *NodeMonitor) Start(ctx context.Context) {
	// No-op in OSS mode - node monitoring is an enterprise feature
}

// Stop stops the monitor.
// OSS stub: No-op.
func (m *NodeMonitor) Stop() {
	// No-op in OSS mode
}

// MultiChannelAlerter sends alerts to multiple channels (Slack, email, CloudWatch).
// OSS stub: No-op implementation - alerting is disabled in OSS mode.
type MultiChannelAlerter struct {
	// No fields needed for OSS stub
}

// NewMultiChannelAlerter creates a new alerter.
// OSS stub: Returns a no-op alerter.
func NewMultiChannelAlerter() *MultiChannelAlerter {
	return &MultiChannelAlerter{}
}

// SendNodeViolationAlert sends a critical alert for node limit violations.
// OSS stub: No-op - always returns nil.
func (a *MultiChannelAlerter) SendNodeViolationAlert(ctx context.Context, violation *ViolationInfo) error {
	// No-op in OSS mode - alerting is an enterprise feature
	return nil
}

// SendNodeCountWarning sends a warning when node count reaches 80% of limit.
// OSS stub: No-op - always returns nil.
func (a *MultiChannelAlerter) SendNodeCountWarning(ctx context.Context, orgID string, usage float64) error {
	// No-op in OSS mode - alerting is an enterprise feature
	return nil
}

// GetActiveNodeCount returns the current active node count for a license.
// OSS stub: Always returns 0 (no tracking).
func GetActiveNodeCount(ctx context.Context, db *sql.DB, licenseKeyHash string) (int, error) {
	return 0, nil
}

// GetActiveNodesByOrg returns the active node count grouped by organization.
// OSS stub: Always returns empty map (no tracking).
func GetActiveNodesByOrg(ctx context.Context, db *sql.DB) (map[string]int, error) {
	return map[string]int{}, nil
}

// CleanupStaleHeartbeats removes heartbeats older than 1 hour.
// OSS stub: No-op - always returns nil.
func CleanupStaleHeartbeats(ctx context.Context, db *sql.DB) error {
	return nil
}

// GetViolationHistory returns all violations for an organization.
// OSS stub: Always returns empty slice (no violations tracked).
func GetViolationHistory(ctx context.Context, db *sql.DB, orgID string) ([]*ViolationInfo, error) {
	return []*ViolationInfo{}, nil
}
