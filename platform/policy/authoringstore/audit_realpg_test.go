// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package authoringstore

// Real-Postgres proof for the typed-policy audit row (PRD v11 §1.12,
// migrations/core/181): the durable Store records one row per publish, promote
// and rollback IN THE SAME TRANSACTION as the write it records, as the
// application role.
//
// Gated on TEST_PG_INTEGRATION=1 through approletest, like every real-Postgres
// test in this package.

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"axonflow/platform/decision/authoring"
	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/pdp"
)

const (
	auditAuthor   = "User::portal:alice@example.com"
	auditApprover = "User::portal:bob@example.com"
)

func auditActivation(t *testing.T, kind authoring.ActivationKind, art *authoring.Artifact, at time.Time, reason string) authoring.Activation {
	t.Helper()
	return authoring.Activation{
		Kind: kind, Root: pdp.RootOrganization, Digest: art.Digest(),
		DocumentID: art.Provenance().DocumentID, DocumentVersion: art.Provenance().DocumentVersion,
		Actor: contract.MustParseID(contract.KindPrincipal, auditApprover), At: at, Reason: reason,
	}
}

func (h *harness) auditCount(t *testing.T, table, org string) int {
	t.Helper()
	var n int
	// The master connection bypasses row-level security, so this counts what is
	// stored rather than what one organization's scope can see.
	if err := h.masterDB.QueryRow("SELECT COUNT(*) FROM "+table+" WHERE org_id = $1", org).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestTheDurableStoreAuditsPublishPromoteAndRollback_RealPG(t *testing.T) {
	h := setup(t)
	ctx := context.Background()
	s := h.storeFor(t, orgA)
	p1, p2 := time.Unix(1_700_000_100, 0).UTC(), time.Unix(1_700_000_150, 0).UTC()
	t1 := time.Unix(1_700_000_200, 0).UTC()
	t2, t3 := t1.Add(time.Hour), t1.Add(2*time.Hour)

	v1, v2 := h.publish(t, 1, p1), h.publish(t, 2, p2)
	for _, art := range []*authoring.Artifact{v1, v2} {
		if err := s.PutArtifact(ctx, pdp.RootOrganization, art); err != nil {
			t.Fatal(err)
		}
	}
	for _, step := range []struct {
		act  authoring.Activation
		prev string
	}{
		{auditActivation(t, authoring.ActivationPromote, v1, t1, "initial rollout"), ""},
		{auditActivation(t, authoring.ActivationPromote, v2, t2, "second version"), v1.Digest()},
		{auditActivation(t, authoring.ActivationRollback, v1, t3, "the second version misbehaved"), v2.Digest()},
	} {
		step.act.PreviousDigest = step.prev
		if err := s.AppendActivation(ctx, pdp.RootOrganization, step.act, step.prev); err != nil {
			t.Fatal(err)
		}
	}

	trail, err := s.AuditTrail(ctx, pdp.RootOrganization)
	if err != nil {
		t.Fatal(err)
	}
	type want struct {
		action          authoring.AuditAction
		digest, prev    string
		actor, approver string
		reason          string
		at              time.Time
	}
	wants := []want{
		{authoring.AuditPublish, v1.Digest(), "", auditAuthor, auditApprover, "", p1},
		{authoring.AuditPublish, v2.Digest(), "", auditAuthor, auditApprover, "", p2},
		{authoring.AuditPromote, v1.Digest(), "", auditApprover, "", "initial rollout", t1},
		{authoring.AuditPromote, v2.Digest(), v1.Digest(), auditApprover, "", "second version", t2},
		{authoring.AuditRollback, v1.Digest(), v2.Digest(), auditApprover, "", "the second version misbehaved", t3},
	}
	if len(trail) != len(wants) {
		t.Fatalf("the durable trail holds %d rows, want %d: %+v", len(trail), len(wants), trail)
	}
	for i, w := range wants {
		g := trail[i]
		approver := ""
		if len(g.Approvers) == 1 {
			approver = g.Approvers[0].String()
		}
		if g.Action != w.action || g.Digest != w.digest || g.PreviousDigest != w.prev || g.Actor.String() != w.actor ||
			approver != w.approver || len(g.Approvers) > 1 || g.SelfApproved || g.Reason != w.reason || !g.At.Equal(w.at) {
			t.Fatalf("audit row %d is %+v, want %+v", i, g, w)
		}
	}

	// EVERY ACTIVATION ROW IS KEYED TO ITS OWN EVENT: its activation_seq is the
	// sequence number of the activation row for the same digest and kind, and
	// every publish row carries 0.
	var matched, publishes int
	if err := h.masterDB.QueryRow(`
		SELECT
		  (SELECT COUNT(*) FROM typed_policy_audit a JOIN typed_policy_activations v
		     ON v.org_id = a.org_id AND v.root = a.root AND v.seq = a.activation_seq
		    AND v.digest = a.digest AND v.kind = a.action AND v.actor = a.actor
		   WHERE a.org_id = $1),
		  (SELECT COUNT(*) FROM typed_policy_audit WHERE org_id = $1 AND action = 'publish' AND activation_seq = 0)
	`, orgA).Scan(&matched, &publishes); err != nil {
		t.Fatal(err)
	}
	if matched != 3 || publishes != 2 {
		t.Fatalf("%d activation audit rows match their activation row (want 3) and %d publish rows carry sequence 0 (want 2)", matched, publishes)
	}
}

// TestAWriteWhoseAuditRowCannotBeRecordedDoesNotHappen_RealPG is the
// same-transaction property. With only the application role's INSERT on
// typed_policy_audit taken away, a publish and an activation both fail and
// store nothing; with it restored, the same two writes succeed, so the refusal
// was the audit row's.
func TestAWriteWhoseAuditRowCannotBeRecordedDoesNotHappen_RealPG(t *testing.T) {
	h := setup(t)
	ctx := context.Background()
	s := h.storeFor(t, orgA)
	v1 := h.publish(t, 1, time.Unix(1_700_000_100, 0).UTC())
	if err := s.PutArtifact(ctx, pdp.RootOrganization, v1); err != nil {
		t.Fatal(err)
	}
	first := auditActivation(t, authoring.ActivationPromote, v1, time.Unix(1_700_000_200, 0).UTC(), "initial rollout")
	if err := s.AppendActivation(ctx, pdp.RootOrganization, first, ""); err != nil {
		t.Fatal(err)
	}

	if _, err := h.masterDB.Exec(`REVOKE INSERT ON typed_policy_audit FROM axonflow_app_role`); err != nil {
		t.Fatal(err)
	}
	restore := func() {
		if _, err := h.masterDB.Exec(`GRANT INSERT ON typed_policy_audit TO axonflow_app_role`); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { _, _ = h.masterDB.Exec(`GRANT INSERT ON typed_policy_audit TO axonflow_app_role`) })

	v2 := h.publish(t, 2, time.Unix(1_700_000_300, 0).UTC())
	again := auditActivation(t, authoring.ActivationRollback, v1, time.Unix(1_700_000_400, 0).UTC(), "probe")
	again.PreviousDigest = v1.Digest()

	if err := s.PutArtifact(ctx, pdp.RootOrganization, v2); err == nil || !strings.Contains(err.Error(), "typed_policy_audit") {
		t.Fatalf("a publish whose audit row could not be written returned %v, want the audit insert's failure", err)
	}
	if err := s.AppendActivation(ctx, pdp.RootOrganization, again, v1.Digest()); err == nil || !strings.Contains(err.Error(), "typed_policy_audit") {
		t.Fatalf("an activation whose audit row could not be written returned %v, want the audit insert's failure", err)
	}
	if a, v := h.auditCount(t, "typed_policy_artifacts", orgA), h.auditCount(t, "typed_policy_activations", orgA); a != 1 || v != 1 {
		t.Fatalf("with the audit insert refused, %d artifact(s) and %d activation(s) are stored, want 1 and 1: a write outlived its audit row", a, v)
	}

	restore()
	if err := s.PutArtifact(ctx, pdp.RootOrganization, v2); err != nil {
		t.Fatalf("the control publish failed with the grant restored: %v", err)
	}
	if err := s.AppendActivation(ctx, pdp.RootOrganization, again, v1.Digest()); err != nil {
		t.Fatalf("the control activation failed with the grant restored: %v", err)
	}
	if a, v, r := h.auditCount(t, "typed_policy_artifacts", orgA), h.auditCount(t, "typed_policy_activations", orgA), h.auditCount(t, "typed_policy_audit", orgA); a != 2 || v != 2 || r != 4 {
		t.Fatalf("after the control writes: %d artifacts, %d activations, %d audit rows; want 2, 2 and 4", a, v, r)
	}
}

func TestARacedActivationWritesNoAuditRow_RealPG(t *testing.T) {
	h := setup(t)
	ctx := context.Background()
	s := h.storeFor(t, orgA)
	v1 := h.publish(t, 1, time.Unix(1_700_000_100, 0).UTC())
	if err := s.PutArtifact(ctx, pdp.RootOrganization, v1); err != nil {
		t.Fatal(err)
	}
	act := auditActivation(t, authoring.ActivationPromote, v1, time.Unix(1_700_000_200, 0).UTC(), "")
	if err := s.AppendActivation(ctx, pdp.RootOrganization, act, "sha256:not-the-tip"); !errors.Is(err, authoring.ErrActivationRaced) {
		t.Fatalf("an append against the wrong tip returned %v, want ErrActivationRaced", err)
	}
	if n := h.auditCount(t, "typed_policy_audit", orgA); n != 1 {
		t.Fatalf("after a lost race the organization holds %d audit rows, want 1 (the publish)", n)
	}
}

// TestAnActivationWhoseAuditKeyIsTakenIsRefused_RealPG is the other half of
// recordAudit's rule: an ACTIVATION row is not idempotent. A row already
// holding the key the next activation would take - left behind when the
// activation history was lost and the audit table was not - describes a
// different event, so the insert is refused and the activation with it.
func TestAnActivationWhoseAuditKeyIsTakenIsRefused_RealPG(t *testing.T) {
	h := setup(t)
	ctx := context.Background()
	s := h.storeFor(t, orgA)
	v1 := h.publish(t, 1, time.Unix(1_700_000_100, 0).UTC())
	if err := s.PutArtifact(ctx, pdp.RootOrganization, v1); err != nil {
		t.Fatal(err)
	}
	// The key the first promotion of v1 takes: (promote, v1, sequence 1).
	if _, err := h.masterDB.Exec(`
		INSERT INTO typed_policy_audit (org_id, root, action, digest, activation_seq, document_id, document_version, actor, occurred_at)
		VALUES ($1, 'organization', 'promote', $2, 1, 'durable-store-probe', 1, $3, NOW())
	`, orgA, v1.Digest(), auditApprover); err != nil {
		t.Fatal(err)
	}
	act := auditActivation(t, authoring.ActivationPromote, v1, time.Unix(1_700_000_200, 0).UTC(), "")
	if err := s.AppendActivation(ctx, pdp.RootOrganization, act, ""); err == nil || !strings.Contains(err.Error(), "typed_policy_audit") {
		t.Fatalf("an activation whose audit key was already taken returned %v, want the audit insert's refusal", err)
	}
	if n := h.auditCount(t, "typed_policy_activations", orgA); n != 0 {
		t.Fatalf("the refused activation left %d activation row(s); an activation must not outlive its audit row", n)
	}
}

func TestTheAuditTrailIsOrganizationScoped_RealPG(t *testing.T) {
	h := setup(t)
	ctx := context.Background()
	if err := h.storeFor(t, orgA).PutArtifact(ctx, pdp.RootOrganization, h.publish(t, 1, time.Unix(1_700_000_100, 0).UTC())); err != nil {
		t.Fatal(err)
	}
	trail, err := h.storeFor(t, orgB).AuditTrail(ctx, pdp.RootOrganization)
	if err != nil {
		t.Fatal(err)
	}
	if len(trail) != 0 {
		t.Fatalf("organization %s read %d of %s's audit rows", orgB, len(trail), orgA)
	}
	// THE CONTROL: the row is there for its own organization.
	if mine, err := h.storeFor(t, orgA).AuditTrail(ctx, pdp.RootOrganization); err != nil || len(mine) != 1 {
		t.Fatalf("organization %s reads %d of its own audit rows (err %v), want 1", orgA, len(mine), err)
	}
}

// TestACorruptAuditRowIsRefusedOnRead: an actor that does not parse is not
// handed back as nobody.
func TestACorruptAuditRowIsRefusedOnRead_RealPG(t *testing.T) {
	h := setup(t)
	if _, err := h.masterDB.Exec(`
		INSERT INTO typed_policy_audit (org_id, root, action, digest, document_id, document_version, actor, occurred_at)
		VALUES ($1, 'organization', 'publish', 'sha256:corrupt', 'corrupt', 1, 'not a principal', NOW())
	`, orgA); err != nil {
		t.Fatal(err)
	}
	if _, err := h.storeFor(t, orgA).AuditTrail(context.Background(), pdp.RootOrganization); err == nil || !strings.Contains(err.Error(), "does not parse") {
		t.Fatalf("reading a row whose actor does not parse returned %v, want a refusal naming the parse", err)
	}
}
