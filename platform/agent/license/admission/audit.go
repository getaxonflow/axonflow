// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package admission

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"log"
	"time"

	"github.com/google/uuid"
)

// AuditRequestType is the audit_logs.request_type every refusal row carries.
// Distinct from every authentication marker (user_token_rejected,
// user_token_required, tenant_mismatch) so a reader of the audit table can
// select tier refusals without a substring match on free text.
const AuditRequestType = "tier_limit_refusal"

// DBAuditSink writes one audit_logs row per refusal, to the SAME table every
// plane writes (single audit source), with the refusal's fields under
// policy_details. audit_logs is not FORCE-RLS, so the write needs no scope.
type DBAuditSink struct {
	db *sql.DB
}

// NewDBAuditSink wraps the application pool.
func NewDBAuditSink(db *sql.DB) *DBAuditSink { return &DBAuditSink{db: db} }

// RecordRefusal writes the row. A failure is logged and dropped: the refusal
// has already been decided and counted, and an audit write must never turn a
// refusal into an error or a retry.
func (s *DBAuditSink) RecordRefusal(ctx context.Context, d Decision) {
	if s == nil || s.db == nil {
		log.Printf("[admission] audit row DROPPED (no database): %s principal=%q org=%q reason=%s", d.Dimension, d.PrincipalID, d.OrgID, d.Reason)
		return
	}
	details, err := json.Marshal(map[string]interface{}{
		"code":          d.Code,
		"dimension":     string(d.Dimension),
		"reason":        d.Reason,
		"edition":       d.Edition,
		"licence_state": d.LicenceState,
		"limit":         d.Limit,
		"count":         d.Count,
		"principal_id":  d.PrincipalID,
		"source":        string(d.Source),
	})
	if err != nil {
		log.Printf("[admission] audit row DROPPED (marshal): %v", err)
		return
	}
	id := uuid.NewString()
	query := "tier admission refused: " + string(d.Dimension)
	sum := sha256.Sum256([]byte(query))
	userEmail, clientID := "", d.OrgID
	switch d.Dimension {
	case HumanPrincipal:
		userEmail = d.PrincipalID
	case ServicePrincipal:
		clientID = d.PrincipalID
	}
	if userEmail == "" {
		userEmail = "unknown@axonflow.local"
	}
	// Bounded so a wedged database cannot hold the request that was refused.
	wctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	_, err = s.db.ExecContext(wctx, `
		INSERT INTO audit_logs (
			id, request_id, timestamp, user_id, user_email, user_role,
			client_id, tenant_id, org_id, request_type, query, query_hash,
			policy_decision, policy_details
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)`,
		"audit_tier_"+id, id, time.Now().UTC(), 0, userEmail, "principal",
		clientID, d.OrgID, d.OrgID, AuditRequestType, query, hex.EncodeToString(sum[:]),
		"blocked", details)
	if err != nil {
		log.Printf("[admission] audit row DROPPED (insert): %v", err)
	}
}
