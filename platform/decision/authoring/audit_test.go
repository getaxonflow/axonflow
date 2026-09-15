// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package authoring

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/pdp"
)

// wantAudit is what one audit entry must say. It is written out rather than
// derived with PublishAuditEntry or ActivationAuditEntry, because an
// expectation computed by the code under test agrees with it by construction.
type wantAudit struct {
	action    AuditAction
	digest    string
	previous  string
	version   int
	actor     string
	approvers []string
	self      bool
	reason    string
	at        time.Time
}

func checkTrail(t *testing.T, got []AuditEntry, want []wantAudit) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("the audit trail holds %d entries, want %d: %+v", len(got), len(want), got)
	}
	for i, w := range want {
		g := got[i]
		approvers := make([]string, 0, len(g.Approvers))
		for _, a := range g.Approvers {
			approvers = append(approvers, a.String())
		}
		if g.Action != w.action || g.Root != pdp.RootOrganization || g.Digest != w.digest ||
			g.PreviousDigest != w.previous || g.DocumentVersion != w.version || g.Actor.String() != w.actor ||
			strings.Join(approvers, ",") != strings.Join(w.approvers, ",") || g.SelfApproved != w.self ||
			g.Reason != w.reason || !g.At.Equal(w.at) {
			t.Fatalf("audit entry %d is %+v, want %+v", i, g, w)
		}
	}
}

// TestEveryPublishPromoteAndRollbackIsOnTheAuditTrail drives the organization
// authority through every audited action and reads the trail back: one entry
// per action, in order, each saying what its write carried (PRD v11 §1.12).
func TestEveryPublishPromoteAndRollbackIsOnTheAuditTrail(t *testing.T) {
	ctx := context.Background()
	cat := baseCatalog(t)
	trust, priv := organizationTrust(t)
	api, err := NewAPI(cat, StaticTrust(trust), mustProfile(t, EditionEnterprise))
	if err != nil {
		t.Fatal(err)
	}
	bob := pid(t, principalBob)
	published := organizationPublishOptions(t, priv).Now
	t1 := time.Unix(1_700_000_200, 0).UTC()
	t2 := t1.Add(time.Hour)
	t3 := t2.Add(time.Hour)

	v1, _, err := api.Publish(ctx, organizationDocument(t), organizationPublishOptions(t, priv))
	if err != nil {
		t.Fatalf("v1 must publish: %v", err)
	}
	if _, err := api.Promote(ctx, pdp.RootOrganization, v1.Digest(), bob, t1, "initial rollout"); err != nil {
		t.Fatalf("an approver must be able to promote v1: %v", err)
	}
	v2doc := organizationDocumentWith(t, cat, func(m *Metadata, d *pdp.Document) {
		d.Version = 2
		m.Supersedes = v1.Digest()
		policyByIDIn(d, "perm.refund").Where = pdp.Compare("args.amount_cents", pdp.OpLe, 250000)
	})
	v2, _, err := api.Publish(ctx, v2doc, organizationPublishOptions(t, priv))
	if err != nil {
		t.Fatalf("v2 must publish: %v", err)
	}
	if _, err := api.Promote(ctx, pdp.RootOrganization, v2.Digest(), bob, t2, "raise the refund ceiling"); err != nil {
		t.Fatalf("an approver must be able to promote v2: %v", err)
	}
	if _, err := api.Rollback(ctx, pdp.RootOrganization, v1.Digest(), bob, t3, "the ceiling was too high"); err != nil {
		t.Fatalf("a non-author must be able to roll back to v1: %v", err)
	}

	trail, err := api.Store().AuditTrail(ctx, pdp.RootOrganization)
	if err != nil {
		t.Fatal(err)
	}
	checkTrail(t, trail, []wantAudit{
		{action: AuditPublish, digest: v1.Digest(), version: 1, actor: principalAlice, approvers: []string{principalBob}, at: published},
		{action: AuditPromote, digest: v1.Digest(), version: 1, actor: principalBob, reason: "initial rollout", at: t1},
		{action: AuditPublish, digest: v2.Digest(), version: 2, actor: principalAlice, approvers: []string{principalBob}, at: published},
		{action: AuditPromote, digest: v2.Digest(), previous: v1.Digest(), version: 2, actor: principalBob, reason: "raise the refund ceiling", at: t2},
		{action: AuditRollback, digest: v1.Digest(), previous: v2.Digest(), version: 1, actor: principalBob, reason: "the ceiling was too high", at: t3},
	})
}

// TestReadmittingAStoredArtifactAddsNoAuditEntry: a publish entry is recorded
// when an artifact is stored, not every time one is offered.
func TestReadmittingAStoredArtifactAddsNoAuditEntry(t *testing.T) {
	ctx := context.Background()
	api, art := publishedAPI(t, false)
	if err := api.Store().Admit(ctx, art); err != nil {
		t.Fatalf("re-admitting a stored artifact must be a no-op: %v", err)
	}
	trail, err := api.Store().AuditTrail(ctx, pdp.RootOrganization)
	if err != nil {
		t.Fatal(err)
	}
	if len(trail) != 1 || trail[0].Action != AuditPublish || trail[0].Digest != art.Digest() {
		t.Fatalf("after one publish and one re-admission the trail is %+v, want the one publish", trail)
	}
}

// TestAnActivationThatDoesNotHappenLeavesNoAuditEntry covers both ways an
// activation fails: refused by a rule before storage is reached, and refused
// by the backend's compare-and-set. The same activation against the right tip
// is the control.
func TestAnActivationThatDoesNotHappenLeavesNoAuditEntry(t *testing.T) {
	ctx := context.Background()
	api, art := publishedAPI(t, false)
	at := time.Unix(1_700_000_200, 0).UTC()

	if _, err := api.Promote(ctx, pdp.RootOrganization, art.Digest(), pid(t, principalAlice), at, "self"); err == nil {
		t.Fatal("the author promoted their own version on Enterprise, so this refusal proves nothing")
	}
	act := Activation{
		Kind: ActivationPromote, Root: pdp.RootOrganization, Digest: art.Digest(),
		DocumentID: art.Provenance().DocumentID, DocumentVersion: art.Provenance().DocumentVersion,
		Actor: pid(t, principalBob), At: at,
	}
	backend := api.Store().backend
	if err := backend.AppendActivation(ctx, pdp.RootOrganization, act, "sha256:not-the-tip"); !errors.Is(err, ErrActivationRaced) {
		t.Fatalf("an append against the wrong tip returned %v, want ErrActivationRaced", err)
	}
	trail, err := api.Store().AuditTrail(ctx, pdp.RootOrganization)
	if err != nil {
		t.Fatal(err)
	}
	if len(trail) != 1 || trail[0].Action != AuditPublish {
		t.Fatalf("after two refused activations the trail is %+v, want only the publish", trail)
	}

	if err := backend.AppendActivation(ctx, pdp.RootOrganization, act, ""); err != nil {
		t.Fatalf("the control append against the real tip failed: %v", err)
	}
	trail, err = api.Store().AuditTrail(ctx, pdp.RootOrganization)
	if err != nil {
		t.Fatal(err)
	}
	if len(trail) != 2 || trail[1].Action != AuditPromote || trail[1].Digest != art.Digest() {
		t.Fatalf("after the control append the trail is %+v, want the publish then the promotion", trail)
	}
}

type selfApprovalCase struct {
	name      string
	approvers []contract.ID
	want      bool
}

// TestSelfApprovedIsTheFactThatEveryApproverIsTheAuthor pins PRD §1.12's
// "the approvers equal the author" as an IDENTITY comparison: the author named
// under any other principal type is still the author (#3878).
func TestSelfApprovedIsTheFactThatEveryApproverIsTheAuthor(t *testing.T) {
	alice, bob := pid(t, principalAlice), pid(t, principalBob)
	cases := []selfApprovalCase{
		{"no approvers", nil, false},
		{"the author alone", []contract.ID{alice}, true},
		{"another person", []contract.ID{bob}, false},
		{"the author and another person", []contract.ID{alice, bob}, false},
	}
	retyped := 0
	for _, typ := range contract.PrincipalTypes() {
		if string(typ) == alice.Type {
			continue
		}
		same := alice
		same.Type = string(typ)
		cases = append(cases, selfApprovalCase{"the author named as a " + string(typ), []contract.ID{same}, true})
		retyped++
	}
	if retyped == 0 {
		t.Fatal("no principal type differs from the author's, so the identity case below cannot fail")
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := everyApproverIsTheAuthor(alice, c.approvers); got != c.want {
				t.Fatalf("everyApproverIsTheAuthor = %v, want %v", got, c.want)
			}
		})
	}
}

// TestACommunityPublishIsMarkedSelfApprovedOnlyWhenItsApproverIsItsAuthor runs
// the two shapes a Community publication takes end to end: the portal names the
// sole administrator as their own approver, which §1.12 records as
// self-approved, and the orchestrator names no approver at all, which it does
// not.
func TestACommunityPublishIsMarkedSelfApprovedOnlyWhenItsApproverIsItsAuthor(t *testing.T) {
	for _, c := range []struct {
		name      string
		approvers []contract.ID
		want      bool
	}{
		{"the author as the sole approver", []contract.ID{pid(t, principalAlice)}, true},
		{"no approver", nil, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			ctx := context.Background()
			cat := baseCatalog(t)
			trust, priv := organizationTrust(t)
			api, err := NewAPI(cat, StaticTrust(trust), mustProfile(t, EditionCommunity))
			if err != nil {
				t.Fatal(err)
			}
			opts := communityPublishOptions(t, priv, EditionCommunity)
			opts.Approvers = c.approvers
			art, findings, err := api.Publish(ctx, communityDocument(t), opts)
			if err != nil {
				t.Fatalf("a Community sole administrator could not publish: %v\n%v", err, findings)
			}
			trail, err := api.Store().AuditTrail(ctx, pdp.RootOrganization)
			if err != nil {
				t.Fatal(err)
			}
			if len(trail) != 1 || trail[0].Digest != art.Digest() || trail[0].SelfApproved != c.want {
				t.Fatalf("the trail is %+v, want one publish with self_approved=%v", trail, c.want)
			}
		})
	}
}
