// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	"axonflow/platform/agent/rls"
)

// MediaGovernanceConfig represents per-tenant media governance configuration.
type MediaGovernanceConfig struct {
	TenantID         string    `json:"tenant_id"`
	Enabled          bool      `json:"enabled"`
	AllowedAnalyzers []string  `json:"allowed_analyzers,omitempty"`
	UpdatedAt        time.Time `json:"updated_at"`
	UpdatedBy        string    `json:"updated_by,omitempty"`
}

// MediaGovernanceStatus represents the media governance feature status for a tier.
type MediaGovernanceStatus struct {
	Available        bool   `json:"available"`
	EnabledByDefault bool   `json:"enabled_by_default"`
	PerTenantControl bool   `json:"per_tenant_control"`
	Tier             string `json:"tier"`
}

// MediaGovernanceConfigStore provides DB-backed storage with in-memory cache
// for per-tenant media governance configuration.
type MediaGovernanceConfigStore struct {
	db    *sql.DB
	cache map[string]*MediaGovernanceConfig
	mu    sync.RWMutex
}

// NewMediaGovernanceConfigStore creates a new config store backed by the given database.
func NewMediaGovernanceConfigStore(db *sql.DB) (*MediaGovernanceConfigStore, error) {
	store := &MediaGovernanceConfigStore{
		db:    db,
		cache: make(map[string]*MediaGovernanceConfig),
	}

	// media_governance_config table created by migration 059_runtime_tables_to_migrations.sql

	return store, nil
}

func (s *MediaGovernanceConfigStore) loadAll() error {
	return fmt.Errorf("cross-tenant media governance preload is disabled; use GetFromDB with a tenant scope")
}

// Get returns the media governance config for a tenant. Returns nil if no override exists.
func (s *MediaGovernanceConfigStore) Get(tenantID string) *MediaGovernanceConfig {
	s.mu.RLock()
	if cfg, ok := s.cache[tenantID]; ok {
		s.mu.RUnlock()
		cfgCopy := *cfg
		if cfg.AllowedAnalyzers != nil {
			cfgCopy.AllowedAnalyzers = make([]string, len(cfg.AllowedAnalyzers))
			copy(cfgCopy.AllowedAnalyzers, cfg.AllowedAnalyzers)
		}
		return &cfgCopy
	}
	s.mu.RUnlock()
	cfg, err := s.GetFromDB(context.Background(), tenantID)
	if err != nil {
		log.Printf("[MediaGovernanceConfig] tenant-scoped lookup failed for %q: %v", tenantID, err)
	}
	return cfg
}

// GetFromDB fetches the config directly from the database (bypasses cache).
func (s *MediaGovernanceConfigStore) GetFromDB(ctx context.Context, tenantID string) (*MediaGovernanceConfig, error) {
	var cfg MediaGovernanceConfig
	var analyzersJSON []byte
	err := rls.WithOrgScope(ctx, s.db, tenantID, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx,
			"SELECT tenant_id, enabled, allowed_analyzers, updated_at, COALESCE(updated_by, '') FROM media_governance_config WHERE tenant_id = $1",
			tenantID,
		).Scan(&cfg.TenantID, &cfg.Enabled, &analyzersJSON, &cfg.UpdatedAt, &cfg.UpdatedBy)
	})

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get media governance config: %w", err)
	}

	if len(analyzersJSON) > 0 {
		if err := json.Unmarshal(analyzersJSON, &cfg.AllowedAnalyzers); err != nil {
			return nil, fmt.Errorf("failed to parse allowed analyzers: %w", err)
		}
	}
	s.mu.Lock()
	cacheCopy := cfg
	s.cache[tenantID] = &cacheCopy
	s.mu.Unlock()

	return &cfg, nil
}

// Upsert creates or updates the media governance config for a tenant.
func (s *MediaGovernanceConfigStore) Upsert(ctx context.Context, cfg *MediaGovernanceConfig) error {
	analyzersJSON, err := json.Marshal(cfg.AllowedAnalyzers)
	if err != nil {
		return fmt.Errorf("failed to marshal allowed analyzers: %w", err)
	}

	now := time.Now()

	err = rls.WithOrgScope(ctx, s.db, cfg.TenantID, func(tx *sql.Tx) error {
		_, execErr := tx.ExecContext(ctx, `
		INSERT INTO media_governance_config (tenant_id, enabled, allowed_analyzers, updated_at, updated_by)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (tenant_id) DO UPDATE SET
			enabled = EXCLUDED.enabled,
			allowed_analyzers = EXCLUDED.allowed_analyzers,
			updated_at = EXCLUDED.updated_at,
			updated_by = EXCLUDED.updated_by
		`, cfg.TenantID, cfg.Enabled, analyzersJSON, now, cfg.UpdatedBy)
		return execErr
	})

	if err != nil {
		return fmt.Errorf("failed to upsert media governance config: %w", err)
	}

	cfg.UpdatedAt = now

	// Update cache with a deep copy
	s.mu.Lock()
	cacheCopy := *cfg
	if cfg.AllowedAnalyzers != nil {
		cacheCopy.AllowedAnalyzers = make([]string, len(cfg.AllowedAnalyzers))
		copy(cacheCopy.AllowedAnalyzers, cfg.AllowedAnalyzers)
	}
	s.cache[cfg.TenantID] = &cacheCopy
	s.mu.Unlock()

	return nil
}

// Delete removes the media governance config for a tenant.
func (s *MediaGovernanceConfigStore) Delete(ctx context.Context, tenantID string) error {
	err := rls.WithOrgScope(ctx, s.db, tenantID, func(tx *sql.Tx) error {
		_, execErr := tx.ExecContext(ctx, "DELETE FROM media_governance_config WHERE tenant_id = $1", tenantID)
		return execErr
	})
	if err != nil {
		return fmt.Errorf("failed to delete media governance config: %w", err)
	}

	s.mu.Lock()
	delete(s.cache, tenantID)
	s.mu.Unlock()

	return nil
}
