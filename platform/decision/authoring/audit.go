// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package authoring

import (
	"time"

	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/pdp"
)

// AuditAction is what one audit entry records.
type AuditAction string

const (
	// AuditPublish records an artifact admitted to the store: the version
	// exists, signed, and may now be activated.
	AuditPublish AuditAction = "publish"
	// AuditPromote records a promotion.
	AuditPromote AuditAction = "promote"
	// AuditRollback records a rollback.
	AuditRollback AuditAction = "rollback"
	// AuditWithdraw records a withdrawal (PRD v11 §1.15).
	AuditWithdraw AuditAction = "withdraw"
)

// AuditEntry is one row of the typed-policy audit trail (PRD v11 §1.12).
//
// # WHY A BACKEND RECORDS IT, AND NOT A TRANSPORT
//
// Before it existed, neither the portal nor the orchestrator recorded an audit
// row for a publish, a promote or a rollback (W3-I census, 2026-09-12). Asking
// each transport to remember is how that happened. So a Backend records the
// entry in the same atomic step as the write it describes: a publish entry
// when PutArtifact stores a new artifact, an activation entry when
// AppendActivation commits. Every transport reaches storage through those two
// methods, so every transport audits by construction, and a write whose entry
// cannot be recorded does not happen.
//
// # WHERE EACH FIELD COMES FROM
//
// Nothing here is supplied beyond what the write itself carries. A publish
// entry is derived from the artifact's SIGNED provenance, and an activation
// entry from the Activation that Store built after its rules ran.
// PublishAuditEntry and ActivationAuditEntry are the only derivations and every
// Backend uses them, so two backends cannot disagree about what a publish was.
type AuditEntry struct {
	Action AuditAction `json:"action"`
	Root   pdp.Root    `json:"root"`
	// Digest is the artifact published or activated.
	Digest string `json:"digest"`
	// PreviousDigest is what an activation replaced, and empty on a publish.
	PreviousDigest  string `json:"previous_digest,omitempty"`
	DocumentID      string `json:"document_id"`
	DocumentVersion int    `json:"document_version"`
	// Actor is the author of a publish and the activator of an activation.
	Actor contract.ID `json:"actor"`
	// Approvers and SelfApproved describe a publication, and are empty on an
	// activation.
	Approvers    []contract.ID `json:"approvers,omitempty"`
	SelfApproved bool          `json:"self_approved"`
	// Reason is an activation's reason, or the reason a self-approved
	// publication states (PRD v11 §1.12).
	Reason string `json:"reason,omitempty"`
	// At is when the event happened as its own record states it: the signed
	// publication time, or the activation time.
	At time.Time `json:"at"`
}

// PublishAuditEntry is the audit entry for admitting a.
func PublishAuditEntry(a *Artifact) AuditEntry {
	p := a.provenance
	return AuditEntry{
		Action:          AuditPublish,
		Root:            p.Root,
		Digest:          a.digest,
		DocumentID:      p.DocumentID,
		DocumentVersion: p.DocumentVersion,
		Actor:           p.Author,
		Approvers:       append([]contract.ID(nil), p.Approvers...),
		SelfApproved:    everyApproverIsTheAuthor(p.Author, p.Approvers),
		Reason:          p.SelfApprovalReason,
		At:              p.PublishedAt.UTC(),
	}
}

// ActivationAuditEntry is the audit entry for recording act.
//
// The action is the activation's kind carried over as it is, not mapped with a
// default: a kind added later reaches storage under its own name, where
// migrations/core/181's action CHECK refuses it, rather than being filed
// silently as a promotion.
func ActivationAuditEntry(act Activation) AuditEntry {
	return AuditEntry{
		Action:          AuditAction(act.Kind),
		Root:            act.Root,
		Digest:          act.Digest,
		PreviousDigest:  act.PreviousDigest,
		DocumentID:      act.DocumentID,
		DocumentVersion: act.DocumentVersion,
		Actor:           act.Actor,
		Reason:          act.Reason,
		At:              act.At.UTC(),
	}
}
