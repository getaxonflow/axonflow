// Copyright 2026 AxonFlow
// SPDX-License-Identifier: Apache-2.0

//go:build enterprise

package masfeat

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
)

// Integration tests for KillSwitchRepository
// These tests require DATABASE_URL to be set

func TestKillSwitchRepository_Integration_NewPostgresKillSwitchRepository(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	repo := NewPostgresKillSwitchRepository(db)
	if repo == nil {
		t.Fatal("Expected non-nil repository")
	}
	if repo.db != db {
		t.Error("Expected repository to have the provided database connection")
	}
}

func TestKillSwitchRepository_Integration_Create(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	repo := NewPostgresKillSwitchRepository(db)
	orgID := getOrCreateTestOrg(t, db, "test-ks-create-"+time.Now().Format("20060102150405"))
	defer cleanupTestRegistryData(t, db, orgID)

	ctx := context.Background()

	accuracyThreshold := 0.85
	biasThreshold := 0.10
	errorRateThreshold := 0.05

	ks := &KillSwitch{
		OrgID:             orgID,
		SystemID:          "sys-" + uuid.New().String()[:8],
		Status:            KillSwitchEnabled,
		AutoTriggerEnabled: true,
		AccuracyThreshold: &accuracyThreshold,
		BiasThreshold:     &biasThreshold,
		ErrorRateThreshold: &errorRateThreshold,
		TriggerConditions: map[string]interface{}{
			"min_accuracy":    0.85,
			"max_bias_score":  0.10,
			"max_error_rate":  0.05,
		},
	}

	err := repo.Create(ctx, ks)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	if ks.ID == "" {
		t.Error("Expected ID to be generated")
	}

	// Verify by retrieving
	retrieved, err := repo.GetBySystemID(ctx, orgID, ks.SystemID)
	if err != nil {
		t.Fatalf("GetBySystemID() error = %v", err)
	}

	if retrieved == nil {
		t.Fatal("Expected kill switch to be found")
	}
	if retrieved.Status != KillSwitchEnabled {
		t.Errorf("Expected Status 'enabled', got %s", retrieved.Status)
	}
	if !retrieved.AutoTriggerEnabled {
		t.Error("Expected AutoTriggerEnabled to be true")
	}
	if retrieved.AccuracyThreshold == nil || *retrieved.AccuracyThreshold != 0.85 {
		t.Errorf("Expected AccuracyThreshold 0.85, got %v", retrieved.AccuracyThreshold)
	}
	if retrieved.BiasThreshold == nil || *retrieved.BiasThreshold != 0.10 {
		t.Errorf("Expected BiasThreshold 0.10, got %v", retrieved.BiasThreshold)
	}
}

func TestKillSwitchRepository_Integration_Create_Minimal(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	repo := NewPostgresKillSwitchRepository(db)
	orgID := getOrCreateTestOrg(t, db, "test-ks-minimal-"+time.Now().Format("20060102150405"))
	defer cleanupTestRegistryData(t, db, orgID)

	ctx := context.Background()

	ks := &KillSwitch{
		OrgID:    orgID,
		SystemID: "sys-" + uuid.New().String()[:8],
		Status:   KillSwitchEnabled,
	}

	err := repo.Create(ctx, ks)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	retrieved, err := repo.GetBySystemID(ctx, orgID, ks.SystemID)
	if err != nil {
		t.Fatalf("GetBySystemID() error = %v", err)
	}

	if retrieved == nil {
		t.Fatal("Expected kill switch to be found")
	}
	if retrieved.AccuracyThreshold != nil {
		t.Error("Expected AccuracyThreshold to be nil for minimal config")
	}
	if !retrieved.CreatedAt.IsZero() {
		t.Logf("CreatedAt: %v", retrieved.CreatedAt)
	}
}

func TestKillSwitchRepository_Integration_GetBySystemID_NotFound(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	repo := NewPostgresKillSwitchRepository(db)
	orgID := getOrCreateTestOrg(t, db, "test-ks-notfound-"+time.Now().Format("20060102150405"))
	defer cleanupTestRegistryData(t, db, orgID)

	ctx := context.Background()

	retrieved, err := repo.GetBySystemID(ctx, orgID, "non-existent-system")
	if err != nil {
		t.Fatalf("GetBySystemID() error = %v", err)
	}
	if retrieved != nil {
		t.Error("Expected nil for non-existent system")
	}
}

func TestKillSwitchRepository_Integration_Update_Configure(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	repo := NewPostgresKillSwitchRepository(db)
	orgID := getOrCreateTestOrg(t, db, "test-ks-config-"+time.Now().Format("20060102150405"))
	defer cleanupTestRegistryData(t, db, orgID)

	ctx := context.Background()

	// Create a kill switch
	ks := &KillSwitch{
		OrgID:    orgID,
		SystemID: "sys-" + uuid.New().String()[:8],
		Status:   KillSwitchEnabled,
	}
	if err := repo.Create(ctx, ks); err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	// Update configuration
	accuracyThreshold := 0.90
	biasThreshold := 0.08
	ks.AutoTriggerEnabled = true
	ks.AccuracyThreshold = &accuracyThreshold
	ks.BiasThreshold = &biasThreshold
	ks.TriggerConditions = map[string]interface{}{
		"min_accuracy": 0.90,
		"max_bias":     0.08,
	}

	err := repo.Update(ctx, ks)
	if err != nil {
		t.Fatalf("Update() error = %v", err)
	}

	// Verify
	retrieved, err := repo.GetBySystemID(ctx, orgID, ks.SystemID)
	if err != nil {
		t.Fatalf("GetBySystemID() error = %v", err)
	}

	if !retrieved.AutoTriggerEnabled {
		t.Error("Expected AutoTriggerEnabled to be true")
	}
	if retrieved.AccuracyThreshold == nil || *retrieved.AccuracyThreshold != 0.90 {
		t.Errorf("Expected AccuracyThreshold 0.90, got %v", retrieved.AccuracyThreshold)
	}
	if retrieved.TriggerConditions == nil {
		t.Error("Expected TriggerConditions to be set")
	}
}

func TestKillSwitchRepository_Integration_Update_Trigger(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	repo := NewPostgresKillSwitchRepository(db)
	orgID := getOrCreateTestOrg(t, db, "test-ks-trigger-"+time.Now().Format("20060102150405"))
	defer cleanupTestRegistryData(t, db, orgID)

	ctx := context.Background()

	// Create a kill switch
	ks := &KillSwitch{
		OrgID:    orgID,
		SystemID: "sys-" + uuid.New().String()[:8],
		Status:   KillSwitchEnabled,
	}
	if err := repo.Create(ctx, ks); err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	// Trigger the kill switch
	triggeredAt := time.Now().UTC()
	ks.Status = KillSwitchTriggered
	ks.TriggerReason = "Accuracy dropped below 80% threshold"
	ks.TriggeredAt = &triggeredAt
	ks.TriggeredBy = "monitoring-system"

	err := repo.Update(ctx, ks)
	if err != nil {
		t.Fatalf("Update() error = %v", err)
	}

	// Verify
	retrieved, err := repo.GetBySystemID(ctx, orgID, ks.SystemID)
	if err != nil {
		t.Fatalf("GetBySystemID() error = %v", err)
	}

	if retrieved.Status != KillSwitchTriggered {
		t.Errorf("Expected Status 'triggered', got %s", retrieved.Status)
	}
	if retrieved.TriggerReason != "Accuracy dropped below 80% threshold" {
		t.Errorf("Expected TriggerReason, got %s", retrieved.TriggerReason)
	}
	if retrieved.TriggeredAt == nil {
		t.Error("Expected TriggeredAt to be set")
	}
	if retrieved.TriggeredBy != "monitoring-system" {
		t.Errorf("Expected TriggeredBy 'monitoring-system', got %s", retrieved.TriggeredBy)
	}
}

func TestKillSwitchRepository_Integration_Update_Restore(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	repo := NewPostgresKillSwitchRepository(db)
	orgID := getOrCreateTestOrg(t, db, "test-ks-restore-"+time.Now().Format("20060102150405"))
	defer cleanupTestRegistryData(t, db, orgID)

	ctx := context.Background()

	// Create and trigger a kill switch
	triggeredAt := time.Now().UTC().Add(-1 * time.Hour)
	ks := &KillSwitch{
		OrgID:         orgID,
		SystemID:      "sys-" + uuid.New().String()[:8],
		Status:        KillSwitchTriggered,
		TriggerReason: "Auto-triggered due to bias detection",
		TriggeredAt:   &triggeredAt,
		TriggeredBy:   "bias-detector",
	}
	if err := repo.Create(ctx, ks); err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	// Restore the kill switch
	restoredAt := time.Now().UTC()
	ks.Status = KillSwitchEnabled
	ks.RestoredAt = &restoredAt
	ks.RestoredBy = "admin@example.com"
	ks.RestoreReason = "Bias issue resolved, model retrained"

	err := repo.Update(ctx, ks)
	if err != nil {
		t.Fatalf("Update() error = %v", err)
	}

	// Verify
	retrieved, err := repo.GetBySystemID(ctx, orgID, ks.SystemID)
	if err != nil {
		t.Fatalf("GetBySystemID() error = %v", err)
	}

	if retrieved.Status != KillSwitchEnabled {
		t.Errorf("Expected Status 'enabled', got %s", retrieved.Status)
	}
	if retrieved.RestoredAt == nil {
		t.Error("Expected RestoredAt to be set")
	}
	if retrieved.RestoredBy != "admin@example.com" {
		t.Errorf("Expected RestoredBy 'admin@example.com', got %s", retrieved.RestoredBy)
	}
	if retrieved.RestoreReason != "Bias issue resolved, model retrained" {
		t.Errorf("Expected RestoreReason, got %s", retrieved.RestoreReason)
	}
	// Original trigger info should still be preserved
	if retrieved.TriggeredAt == nil {
		t.Error("Expected TriggeredAt to still be set after restore")
	}
}

func TestKillSwitchRepository_Integration_RecordHistory(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	repo := NewPostgresKillSwitchRepository(db)
	orgID := getOrCreateTestOrg(t, db, "test-ks-history-"+time.Now().Format("20060102150405"))
	defer cleanupTestRegistryData(t, db, orgID)

	ctx := context.Background()

	// Create a kill switch
	ks := &KillSwitch{
		OrgID:    orgID,
		SystemID: "sys-" + uuid.New().String()[:8],
		Status:   KillSwitchEnabled,
	}
	if err := repo.Create(ctx, ks); err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	// Record history
	history := &KillSwitchHistory{
		KillSwitchID:   ks.ID,
		Action:         "trigger",
		PreviousStatus: "enabled",
		NewStatus:      "triggered",
		Reason:         "Manual trigger for testing",
		PerformedBy:    "test-user@example.com",
	}

	err := repo.RecordHistory(ctx, orgID, history)
	if err != nil {
		t.Fatalf("RecordHistory() error = %v", err)
	}

	if history.ID == "" {
		t.Error("Expected ID to be generated")
	}
	if history.PerformedAt.IsZero() {
		t.Error("Expected PerformedAt to be set")
	}

	// Verify by retrieving history
	historyList, err := repo.GetHistory(ctx, orgID, ks.SystemID, 10)
	if err != nil {
		t.Fatalf("GetHistory() error = %v", err)
	}

	if len(historyList) != 1 {
		t.Errorf("Expected 1 history entry, got %d", len(historyList))
	}
	if historyList[0].Action != "trigger" {
		t.Errorf("Expected Action 'trigger', got %s", historyList[0].Action)
	}
	if historyList[0].PreviousStatus != "enabled" {
		t.Errorf("Expected PreviousStatus 'enabled', got %s", historyList[0].PreviousStatus)
	}
	if historyList[0].NewStatus != "triggered" {
		t.Errorf("Expected NewStatus 'triggered', got %s", historyList[0].NewStatus)
	}
}

func TestKillSwitchRepository_Integration_RecordHistory_MultipleEntries(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	repo := NewPostgresKillSwitchRepository(db)
	orgID := getOrCreateTestOrg(t, db, "test-ks-hist-multi-"+time.Now().Format("20060102150405"))
	defer cleanupTestRegistryData(t, db, orgID)

	ctx := context.Background()

	// Create a kill switch
	ks := &KillSwitch{
		OrgID:    orgID,
		SystemID: "sys-" + uuid.New().String()[:8],
		Status:   KillSwitchEnabled,
	}
	if err := repo.Create(ctx, ks); err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	// Record multiple history entries
	actions := []struct {
		action     string
		prevStatus string
		newStatus  string
		reason     string
	}{
		{"configure", "enabled", "enabled", "Updated thresholds"},
		{"trigger", "enabled", "triggered", "Accuracy below threshold"},
		{"restore", "triggered", "enabled", "Issue resolved"},
		{"disable", "enabled", "disabled", "Maintenance mode"},
	}

	for _, a := range actions {
		history := &KillSwitchHistory{
			KillSwitchID:   ks.ID,
			Action:         a.action,
			PreviousStatus: a.prevStatus,
			NewStatus:      a.newStatus,
			Reason:         a.reason,
			PerformedBy:    "operator@example.com",
		}
		if err := repo.RecordHistory(ctx, orgID, history); err != nil {
			t.Fatalf("RecordHistory() error = %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Get history
	historyList, err := repo.GetHistory(ctx, orgID, ks.SystemID, 10)
	if err != nil {
		t.Fatalf("GetHistory() error = %v", err)
	}

	if len(historyList) != 4 {
		t.Errorf("Expected 4 history entries, got %d", len(historyList))
	}

	// Verify ordering (most recent first)
	if historyList[0].Action != "disable" {
		t.Errorf("Expected most recent action 'disable', got %s", historyList[0].Action)
	}
}

func TestKillSwitchRepository_Integration_GetHistory_Limit(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	repo := NewPostgresKillSwitchRepository(db)
	orgID := getOrCreateTestOrg(t, db, "test-ks-hist-limit-"+time.Now().Format("20060102150405"))
	defer cleanupTestRegistryData(t, db, orgID)

	ctx := context.Background()

	// Create a kill switch
	ks := &KillSwitch{
		OrgID:    orgID,
		SystemID: "sys-" + uuid.New().String()[:8],
		Status:   KillSwitchEnabled,
	}
	if err := repo.Create(ctx, ks); err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	// Record 10 history entries
	for i := 0; i < 10; i++ {
		history := &KillSwitchHistory{
			KillSwitchID:   ks.ID,
			Action:         "config_update",
			PreviousStatus: "enabled",
			NewStatus:      "enabled",
			Reason:         "Config update " + string(rune('A'+i)),
			PerformedBy:    "operator@example.com",
		}
		if err := repo.RecordHistory(ctx, orgID, history); err != nil {
			t.Fatalf("RecordHistory() error = %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Get limited history
	historyList, err := repo.GetHistory(ctx, orgID, ks.SystemID, 5)
	if err != nil {
		t.Fatalf("GetHistory() error = %v", err)
	}

	if len(historyList) != 5 {
		t.Errorf("Expected 5 history entries with limit, got %d", len(historyList))
	}

	// Should be most recent 5
	if historyList[0].Reason != "Config update J" {
		t.Errorf("Expected most recent reason 'Config update J', got %s", historyList[0].Reason)
	}
}

func TestKillSwitchRepository_Integration_GetHistory_Empty(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	repo := NewPostgresKillSwitchRepository(db)
	orgID := getOrCreateTestOrg(t, db, "test-ks-hist-empty-"+time.Now().Format("20060102150405"))
	defer cleanupTestRegistryData(t, db, orgID)

	ctx := context.Background()

	// Create a kill switch
	ks := &KillSwitch{
		OrgID:    orgID,
		SystemID: "sys-" + uuid.New().String()[:8],
		Status:   KillSwitchEnabled,
	}
	if err := repo.Create(ctx, ks); err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	// Get history (should be empty)
	historyList, err := repo.GetHistory(ctx, orgID, ks.SystemID, 10)
	if err != nil {
		t.Fatalf("GetHistory() error = %v", err)
	}

	if historyList == nil {
		historyList = []*KillSwitchHistory{}
	}
	if len(historyList) != 0 {
		t.Errorf("Expected 0 history entries, got %d", len(historyList))
	}
}

func TestKillSwitchRepository_Integration_AllStatuses(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	repo := NewPostgresKillSwitchRepository(db)
	orgID := getOrCreateTestOrg(t, db, "test-ks-all-status-"+time.Now().Format("20060102150405"))
	defer cleanupTestRegistryData(t, db, orgID)

	ctx := context.Background()

	// Test all kill switch statuses
	statuses := []KillSwitchStatus{
		KillSwitchEnabled,
		KillSwitchDisabled,
		KillSwitchTriggered,
	}

	for _, status := range statuses {
		ks := &KillSwitch{
			OrgID:    orgID,
			SystemID: "sys-status-" + uuid.New().String()[:8],
			Status:   status,
		}
		if err := repo.Create(ctx, ks); err != nil {
			t.Fatalf("Create() error for status %s: %v", status, err)
		}

		retrieved, err := repo.GetBySystemID(ctx, orgID, ks.SystemID)
		if err != nil {
			t.Fatalf("GetBySystemID() error for status %s: %v", status, err)
		}
		if retrieved.Status != status {
			t.Errorf("Expected Status %s, got %s", status, retrieved.Status)
		}
	}
}

func TestKillSwitchRepository_Integration_TriggerConditionsJSON(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	repo := NewPostgresKillSwitchRepository(db)
	orgID := getOrCreateTestOrg(t, db, "test-ks-conditions-"+time.Now().Format("20060102150405"))
	defer cleanupTestRegistryData(t, db, orgID)

	ctx := context.Background()

	conditions := map[string]interface{}{
		"accuracy_threshold":     0.90,
		"bias_threshold":         0.08,
		"error_rate_threshold":   0.02,
		"consecutive_violations": 3,
		"monitoring_window":      "1h",
		"alert_channels":         []string{"slack", "email"},
	}

	ks := &KillSwitch{
		OrgID:             orgID,
		SystemID:          "sys-" + uuid.New().String()[:8],
		Status:            KillSwitchEnabled,
		TriggerConditions: conditions,
	}

	if err := repo.Create(ctx, ks); err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	retrieved, err := repo.GetBySystemID(ctx, orgID, ks.SystemID)
	if err != nil {
		t.Fatalf("GetBySystemID() error = %v", err)
	}

	if retrieved.TriggerConditions == nil {
		t.Fatal("Expected TriggerConditions to be set")
	}
	if retrieved.TriggerConditions["accuracy_threshold"] != 0.90 {
		t.Errorf("Expected accuracy_threshold 0.90, got %v", retrieved.TriggerConditions["accuracy_threshold"])
	}
	if retrieved.TriggerConditions["monitoring_window"] != "1h" {
		t.Errorf("Expected monitoring_window '1h', got %v", retrieved.TriggerConditions["monitoring_window"])
	}
}

func TestKillSwitchRepository_Integration_ThresholdValues(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	repo := NewPostgresKillSwitchRepository(db)
	orgID := getOrCreateTestOrg(t, db, "test-ks-thresholds-"+time.Now().Format("20060102150405"))
	defer cleanupTestRegistryData(t, db, orgID)

	ctx := context.Background()

	// Test various threshold values
	thresholds := []struct {
		accuracy  float64
		bias      float64
		errorRate float64
	}{
		{0.95, 0.05, 0.01},
		{0.80, 0.15, 0.10},
		{0.99, 0.01, 0.001},
	}

	for _, th := range thresholds {
		accuracy := th.accuracy
		bias := th.bias
		errRate := th.errorRate

		ks := &KillSwitch{
			OrgID:             orgID,
			SystemID:          "sys-th-" + uuid.New().String()[:8],
			Status:            KillSwitchEnabled,
			AccuracyThreshold: &accuracy,
			BiasThreshold:     &bias,
			ErrorRateThreshold: &errRate,
		}

		if err := repo.Create(ctx, ks); err != nil {
			t.Fatalf("Create() error = %v", err)
		}

		retrieved, err := repo.GetBySystemID(ctx, orgID, ks.SystemID)
		if err != nil {
			t.Fatalf("GetBySystemID() error = %v", err)
		}

		if *retrieved.AccuracyThreshold != accuracy {
			t.Errorf("Expected AccuracyThreshold %f, got %f", accuracy, *retrieved.AccuracyThreshold)
		}
		if *retrieved.BiasThreshold != bias {
			t.Errorf("Expected BiasThreshold %f, got %f", bias, *retrieved.BiasThreshold)
		}
		if *retrieved.ErrorRateThreshold != errRate {
			t.Errorf("Expected ErrorRateThreshold %f, got %f", errRate, *retrieved.ErrorRateThreshold)
		}
	}
}

func TestKillSwitchRepository_Integration_FullLifecycle(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	repo := NewPostgresKillSwitchRepository(db)
	orgID := getOrCreateTestOrg(t, db, "test-ks-lifecycle-"+time.Now().Format("20060102150405"))
	defer cleanupTestRegistryData(t, db, orgID)

	ctx := context.Background()

	systemID := "sys-lifecycle-" + uuid.New().String()[:8]

	// 1. Create enabled kill switch
	accuracy := 0.85
	ks := &KillSwitch{
		OrgID:             orgID,
		SystemID:          systemID,
		Status:            KillSwitchEnabled,
		AutoTriggerEnabled: true,
		AccuracyThreshold: &accuracy,
	}
	if err := repo.Create(ctx, ks); err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	// Record create history
	if err := repo.RecordHistory(ctx, orgID, &KillSwitchHistory{
		KillSwitchID:   ks.ID,
		Action:         "create",
		PreviousStatus: "",
		NewStatus:      "enabled",
		Reason:         "Initial creation",
		PerformedBy:    "system",
	}); err != nil {
		t.Fatalf("RecordHistory() error = %v", err)
	}

	// 2. Trigger the kill switch
	triggeredAt := time.Now().UTC()
	ks.Status = KillSwitchTriggered
	ks.TriggerReason = "Accuracy dropped to 0.75"
	ks.TriggeredAt = &triggeredAt
	ks.TriggeredBy = "monitoring-system"
	if err := repo.Update(ctx, ks); err != nil {
		t.Fatalf("Update() error = %v", err)
	}

	if err := repo.RecordHistory(ctx, orgID, &KillSwitchHistory{
		KillSwitchID:   ks.ID,
		Action:         "trigger",
		PreviousStatus: "enabled",
		NewStatus:      "triggered",
		Reason:         "Accuracy dropped to 0.75",
		PerformedBy:    "monitoring-system",
	}); err != nil {
		t.Fatalf("RecordHistory() error = %v", err)
	}

	// 3. Restore the kill switch
	restoredAt := time.Now().UTC()
	ks.Status = KillSwitchEnabled
	ks.RestoredAt = &restoredAt
	ks.RestoredBy = "admin@example.com"
	ks.RestoreReason = "Model retrained, accuracy restored"
	if err := repo.Update(ctx, ks); err != nil {
		t.Fatalf("Update() error = %v", err)
	}

	if err := repo.RecordHistory(ctx, orgID, &KillSwitchHistory{
		KillSwitchID:   ks.ID,
		Action:         "restore",
		PreviousStatus: "triggered",
		NewStatus:      "enabled",
		Reason:         "Model retrained, accuracy restored",
		PerformedBy:    "admin@example.com",
	}); err != nil {
		t.Fatalf("RecordHistory() error = %v", err)
	}

	// Verify final state
	final, err := repo.GetBySystemID(ctx, orgID, systemID)
	if err != nil {
		t.Fatalf("GetBySystemID() error = %v", err)
	}

	if final.Status != KillSwitchEnabled {
		t.Errorf("Expected final Status 'enabled', got %s", final.Status)
	}

	// Verify history
	history, err := repo.GetHistory(ctx, orgID, systemID, 10)
	if err != nil {
		t.Fatalf("GetHistory() error = %v", err)
	}

	if len(history) != 3 {
		t.Errorf("Expected 3 history entries, got %d", len(history))
	}

	// Verify history order (most recent first)
	expectedActions := []string{"restore", "trigger", "create"}
	for i, expected := range expectedActions {
		if history[i].Action != expected {
			t.Errorf("Expected history[%d].Action '%s', got '%s'", i, expected, history[i].Action)
		}
	}
}

func TestKillSwitchRepository_Integration_DefaultLimits(t *testing.T) {
	db := getTestDB(t)
	defer db.Close()

	repo := NewPostgresKillSwitchRepository(db)
	orgID := getOrCreateTestOrg(t, db, "test-ks-limits-"+time.Now().Format("20060102150405"))
	defer cleanupTestRegistryData(t, db, orgID)

	ctx := context.Background()

	// Create a kill switch
	ks := &KillSwitch{
		OrgID:    orgID,
		SystemID: "sys-" + uuid.New().String()[:8],
		Status:   KillSwitchEnabled,
	}
	if err := repo.Create(ctx, ks); err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	// Record many history entries
	for i := 0; i < 30; i++ {
		history := &KillSwitchHistory{
			KillSwitchID:   ks.ID,
			Action:         "check",
			PreviousStatus: "enabled",
			NewStatus:      "enabled",
			Reason:         "Periodic health check",
			PerformedBy:    "health-monitor",
		}
		if err := repo.RecordHistory(ctx, orgID, history); err != nil {
			t.Fatalf("RecordHistory() error = %v", err)
		}
	}

	// Get history with invalid limit (0 should use default of 50)
	historyList, err := repo.GetHistory(ctx, orgID, ks.SystemID, 0)
	if err != nil {
		t.Fatalf("GetHistory() error = %v", err)
	}

	// Should use default limit (50), but we only have 30 entries
	if len(historyList) != 30 {
		t.Errorf("Expected 30 history entries (all created, less than default limit 50), got %d", len(historyList))
	}
}
