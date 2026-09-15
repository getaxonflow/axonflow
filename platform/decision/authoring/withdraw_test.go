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

// WITHDRAWAL (PRD v11 §1.15): an organization returns to the implicit bundle -
// the shipped set - without deleting history. The entry names the shipped
// organization template, chains onto the document it withdrew, and leaves
// nothing active; a later promotion starts from nothing active and chains onto
// the withdrawal.

func TestAWithdrawalLeavesNothingActiveAndAPromotionChainsOntoIt(t *testing.T) {
	api, art := publishedAPI(t, false)
	ctx := context.Background()
	org := pdp.RootOrganization
	bob := pid(t, principalBob)
	t1 := timeFixture()
	t2, t3 := t1.Add(time.Hour), t1.Add(2*time.Hour)
	if _, err := api.Promote(ctx, org, art.Digest(), bob, t1, "rollout"); err != nil {
		t.Fatalf("an approver must be able to promote: %v", err)
	}

	got, err := api.Withdraw(ctx, org, bob, t2, "back to the shipped set")
	if err != nil {
		t.Fatalf("withdrawing an active document was refused: %v", err)
	}
	template, err := pdp.SystemCorpusOrganizationTemplateDigest()
	if err != nil {
		t.Fatal(err)
	}
	want := Activation{
		Kind: ActivationWithdraw, Root: org, Digest: template, PreviousDigest: art.Digest(),
		DocumentID: pdp.SystemCorpusOrganizationTemplateID, DocumentVersion: 1,
		Actor: bob, At: t2, Reason: "back to the shipped set",
	}
	if *got != want {
		t.Fatalf("the withdrawal recorded %+v; want %+v", *got, want)
	}
	if _, active, err := api.Store().Active(ctx, org); err != nil || active {
		t.Fatalf("after a withdrawal the store reports a document active (%v, %v); nothing is", active, err)
	}

	// A promotion after it starts from nothing active - the artifact declares no
	// parent, which is admitted only when nothing is active - and its entry's
	// parent is the withdrawal, so the ledger stays one chain.
	again, err := api.Promote(ctx, org, art.Digest(), bob, t3, "reinstated")
	if err != nil {
		t.Fatalf("a promotion after a withdrawal was refused: %v", err)
	}
	if again.PreviousDigest != template {
		t.Fatalf("the promotion after the withdrawal chains onto %q; want the withdrawal's %q", again.PreviousDigest, template)
	}
	if active, ok, err := api.Store().Active(ctx, org); err != nil || !ok || active.Digest() != art.Digest() {
		t.Fatalf("after the promotion the active document is %v (%v, %v); want %s", active, ok, err, art.Digest())
	}
	history, err := api.Store().History(ctx, org)
	if err != nil {
		t.Fatal(err)
	}
	var kinds []string
	for _, h := range history {
		kinds = append(kinds, string(h.Kind))
	}
	if strings.Join(kinds, ",") != "promote,withdraw,promote" {
		t.Fatalf("history %v; want promote, withdraw, promote, nothing deleted", kinds)
	}
}

func TestAWithdrawalIsRefusedByName(t *testing.T) {
	ctx := context.Background()
	org := pdp.RootOrganization
	bob := pid(t, principalBob)
	promoted := func(t *testing.T) *API {
		t.Helper()
		api, art := publishedAPI(t, false)
		if _, err := api.Promote(ctx, org, art.Digest(), bob, timeFixture(), "rollout"); err != nil {
			t.Fatal(err)
		}
		return api
	}
	for _, c := range []struct {
		name   string
		api    func(t *testing.T) *API
		actor  contract.ID
		reason string
		says   string
	}{
		{"nothing was ever activated", func(t *testing.T) *API { api, _ := publishedAPI(t, false); return api }, bob, "why", "nothing is active"},
		{"no reason", promoted, bob, "", "records a reason"},
		{"no actor", promoted, contract.ID{}, "why", "names no actor"},
		{"already withdrawn", func(t *testing.T) *API {
			api := promoted(t)
			if _, err := api.Withdraw(ctx, org, bob, timeFixture(), "first"); err != nil {
				t.Fatal(err)
			}
			return api
		}, bob, "again", "nothing is active"},
	} {
		t.Run(c.name, func(t *testing.T) {
			api := c.api(t)
			before, _ := api.Store().History(ctx, org)
			if _, err := api.Withdraw(ctx, org, c.actor, timeFixture(), c.reason); err == nil || !strings.Contains(err.Error(), c.says) {
				t.Fatalf("withdraw with %s answered %v; want a refusal saying %q", c.name, err, c.says)
			}
			if after, _ := api.Store().History(ctx, org); len(after) != len(before) {
				t.Fatalf("a refused withdrawal appended an entry: %d -> %d", len(before), len(after))
			}
		})
	}

	t.Run("a fixture vocabulary", func(t *testing.T) {
		api, _ := publishedAPI(t, true)
		var fixture *ErrCatalogIsFixture
		if _, err := api.Withdraw(ctx, org, bob, timeFixture(), "why"); !errors.As(err, &fixture) {
			t.Fatalf("a withdrawal under a fixture catalog was not refused as a fixture: %v", err)
		}
	})
}

func TestTheActivatorDryRunsTheImplicitBundleBeforeAWithdrawal(t *testing.T) {
	api, art := publishedAPI(t, false)
	ctx := context.Background()
	org := pdp.RootOrganization
	bob := pid(t, principalBob)
	if _, err := api.Promote(ctx, org, art.Digest(), bob, timeFixture(), "rollout"); err != nil {
		t.Fatal(err)
	}
	var (
		kinds     []ActivationKind
		candidate *Artifact
		refuse    = errors.New("the implicit bundle cannot be enforced here")
		answer    error
	)
	api.WithActivator(func(_ context.Context, kind ActivationKind, c *Artifact) error {
		kinds, candidate = append(kinds, kind), c
		return answer
	})

	answer = refuse
	if _, err := api.Withdraw(ctx, org, bob, timeFixture(), "why"); !errors.Is(err, refuse) {
		t.Fatalf("a withdrawal the activator refused answered %v; want its refusal", err)
	}
	if active, ok, _ := api.Store().Active(ctx, org); !ok || active.Digest() != art.Digest() {
		t.Fatal("a withdrawal the activator refused changed what is active")
	}

	answer = nil
	if _, err := api.Withdraw(ctx, org, bob, timeFixture(), "why"); err != nil {
		t.Fatalf("a withdrawal the activator admitted was refused: %v", err)
	}
	if len(kinds) != 2 || kinds[0] != ActivationWithdraw || kinds[1] != ActivationWithdraw || candidate != nil {
		t.Fatalf("the activator saw kinds %v and candidate %v; want withdraw twice, with no artifact - it dry-runs the implicit bundle", kinds, candidate)
	}
}

func TestAWithdrawalIsOnTheAuditTrail(t *testing.T) {
	api, art := publishedAPI(t, false)
	ctx := context.Background()
	org := pdp.RootOrganization
	bob := pid(t, principalBob)
	t1 := timeFixture()
	t2 := t1.Add(time.Hour)
	if _, err := api.Promote(ctx, org, art.Digest(), bob, t1, "rollout"); err != nil {
		t.Fatal(err)
	}
	if _, err := api.Withdraw(ctx, org, bob, t2, "back to the shipped set"); err != nil {
		t.Fatal(err)
	}
	template, err := pdp.SystemCorpusOrganizationTemplateDigest()
	if err != nil {
		t.Fatal(err)
	}
	trail, err := api.Store().AuditTrail(ctx, org)
	if err != nil {
		t.Fatal(err)
	}
	if len(trail) == 0 {
		t.Fatal("the audit trail is empty")
	}
	last := trail[len(trail)-1]
	if last.Action != AuditWithdraw || last.Digest != template || last.PreviousDigest != art.Digest() ||
		last.Actor != bob || last.Reason != "back to the shipped set" || !last.At.Equal(t2) {
		t.Fatalf("the withdrawal's audit entry is %+v; want withdraw of %s from %s by %s", last, template, art.Digest(), bob)
	}
}

// THE SAME AUTHORITY AS ROLLBACK (PRD v11 §1.15, #4299). A withdrawal removes
// every constraint the organization authored, so the author of the ACTIVE
// document cannot do it alone. The rule is rollback's - "not the author" - and
// not promote's "an approver", so a principal who is neither is admitted: the
// third row holds that the fix did not over-tighten into promote's rule.
func TestTheAuthorCannotWithdrawTheirOwnActiveDocument(t *testing.T) {
	ctx := context.Background()
	org := pdp.RootOrganization
	alice, bob, carol := pid(t, principalAlice), pid(t, principalBob), pid(t, principalCarol)
	for _, c := range []struct {
		name  string
		actor contract.ID
		want  string // "" = admitted
	}{
		{"the author is refused, in the store's own sentence", alice, "separation of author and approver duties"},
		{"an approver is admitted", bob, ""},
		{"a principal who is neither is admitted, as a rollback would be", carol, ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			api, art := publishedAPI(t, false)
			if _, err := api.Promote(ctx, org, art.Digest(), bob, timeFixture(), "rollout"); err != nil {
				t.Fatal(err)
			}
			before, _ := api.Store().History(ctx, org)
			_, err := api.Withdraw(ctx, org, c.actor, timeFixture().Add(time.Hour), "back to the shipped set")
			if c.want == "" {
				if err != nil {
					t.Fatalf("%s's withdrawal was refused: %v", c.actor, err)
				}
				if _, active, err := api.Store().Active(ctx, org); err != nil || active {
					t.Fatalf("after %s's withdrawal the store reports a document active (%v, %v)", c.actor, active, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), c.want) || !strings.Contains(err.Error(), "refusing to withdraw") {
				t.Fatalf("the author's withdrawal answered %v; want a refusal to withdraw saying %q", err, c.want)
			}
			if after, _ := api.Store().History(ctx, org); len(after) != len(before) {
				t.Fatalf("a refused withdrawal appended an entry: %d -> %d", len(before), len(after))
			}
			if active, ok, _ := api.Store().Active(ctx, org); !ok || active.Digest() != art.Digest() {
				t.Fatal("a refused withdrawal changed what is active")
			}
		})
	}
}

// A ONE-PERSON ORGANIZATION (PRD v11 §1.12) that enabled self-approval can
// still return to the shipped set: the author withdraws their own self-approved
// document while the grant holds, and cannot once it is withdrawn. The grant is
// asked at withdrawal, as at activation, and only API.Withdraw asks it.
func TestAOnePersonOrganizationWithdrawsOnlyWhileSelfApprovalIsGranted(t *testing.T) {
	ctx := context.Background()
	org := pdp.RootOrganization
	f := newSelfApprovalFixture(t, mustProfile(t, EditionEnterprise))
	alice := pid(t, principalAlice)
	at := time.Unix(1_700_000_200, 0).UTC()
	v1, findings, err := f.publish(t, organizationDocument(t), []contract.ID{alice}, selfApprovalReason)
	if err != nil {
		t.Fatalf("v1 must publish: %v\n%v", err, findings)
	}
	if _, err := f.api.Promote(ctx, org, v1.Digest(), alice, at, "first rollout"); err != nil {
		t.Fatalf("the author could not promote their self-approved version while self-approval is granted: %v", err)
	}

	f.granted = false
	if _, err := f.api.Withdraw(ctx, org, alice, at.Add(time.Hour), "back to the shipped set"); err == nil || !strings.Contains(err.Error(), "cannot also activate") {
		t.Fatalf("with the grant withdrawn the author withdrew their own document alone: %v", err)
	}

	// The exported store method grants none, even while the API in front of
	// the same store would.
	f.granted = true
	if _, err := f.api.Store().Withdraw(ctx, org, alice, at.Add(2*time.Hour), "back to the shipped set"); err == nil || !strings.Contains(err.Error(), "cannot also activate") {
		t.Fatalf("the exported Store.Withdraw granted self-approval: %v", err)
	}

	if _, err := f.api.Withdraw(ctx, org, alice, at.Add(3*time.Hour), "back to the shipped set"); err != nil {
		t.Fatalf("with the grant held the author could not withdraw their self-approved document: %v", err)
	}
	if _, active, err := f.api.Store().Active(ctx, org); err != nil || active {
		t.Fatalf("after the withdrawal the store reports a document active (%v, %v)", active, err)
	}
}

// The grant covers only a version whose every approver is its author, so it
// never lets the author withdraw a document a second person approved - and the
// deployment is not even asked.
func TestSelfApprovalNeverLetsTheAuthorWithdrawADocumentASecondPersonApproved(t *testing.T) {
	ctx := context.Background()
	org := pdp.RootOrganization
	f := newSelfApprovalFixture(t, mustProfile(t, EditionEnterprise))
	alice, bob := pid(t, principalAlice), pid(t, principalBob)
	v1, findings, err := f.publish(t, organizationDocument(t), []contract.ID{bob}, "")
	if err != nil {
		t.Fatalf("v1 must publish: %v\n%v", err, findings)
	}
	if _, err := f.api.Promote(ctx, org, v1.Digest(), bob, time.Unix(1_700_000_200, 0).UTC(), "rollout"); err != nil {
		t.Fatal(err)
	}
	asked := f.asked
	_, err = f.api.Withdraw(ctx, org, alice, time.Unix(1_700_000_300, 0).UTC(), "back to the shipped set")
	if err == nil || !strings.Contains(err.Error(), "cannot also activate") {
		t.Fatalf("the author withdrew a document a second person approved: %v", err)
	}
	if f.asked != asked {
		t.Fatalf("the deployment was asked %d time(s) about a document a second person approved", f.asked-asked)
	}
}

// withdrawProbeBackend is the in-process backend with GetArtifact switchable to
// fail - as the durable backend's does for a document whose signing key has
// been revoked - and with the publish audit entries optionally hidden, as a
// store admitted before migrations/core/181 would have none.
type withdrawProbeBackend struct {
	Backend
	failGet, hidePublish bool
}

func (b *withdrawProbeBackend) GetArtifact(ctx context.Context, root pdp.Root, digest string) (*Artifact, bool, error) {
	if b.failGet {
		return nil, false, errors.New("the stored artifact did not verify on load (its signing key was revoked)")
	}
	return b.Backend.GetArtifact(ctx, root, digest)
}

func (b *withdrawProbeBackend) AuditTrail(ctx context.Context, root pdp.Root) ([]AuditEntry, error) {
	trail, err := b.Backend.AuditTrail(ctx, root)
	if err != nil || !b.hidePublish {
		return trail, err
	}
	var kept []AuditEntry
	for _, e := range trail {
		if e.Action != AuditPublish {
			kept = append(kept, e)
		}
	}
	return kept, nil
}

// withdrawFixture publishes one document through an API over b and has the
// approver promote it.
func withdrawFixture(t *testing.T, b Backend) (*API, *Artifact) {
	t.Helper()
	cat := baseCatalog(t)
	cat.Provenance = CatalogProvenance{Source: "test", Fixture: false}
	trust, priv := organizationTrust(t)
	api, err := NewAPIWithBackend(cat, StaticTrust(trust), mustProfile(t, EditionEnterprise), b)
	if err != nil {
		t.Fatal(err)
	}
	art, findings, err := api.Publish(context.Background(), organizationDocument(t), organizationPublishOptions(t, priv))
	if err != nil {
		t.Fatalf("publish: %v\n%v", err, findings)
	}
	if _, err := api.Promote(context.Background(), pdp.RootOrganization, art.Digest(), pid(t, principalBob), timeFixture(), "rollout"); err != nil {
		t.Fatal(err)
	}
	return api, art
}

// A WITHDRAWAL NEEDS THE ACTIVE DOCUMENT'S AUTHOR, NOT THE DOCUMENT (#4299).
// With every artifact load failing - as the durable backend's does for a
// revoked signing key - the author is still refused and the approver admitted.
func TestAWithdrawalReadsTheAuthorFromTheAdmissionRecordNotTheArtifact(t *testing.T) {
	ctx := context.Background()
	org := pdp.RootOrganization
	b := &withdrawProbeBackend{Backend: NewMemoryBackend()}
	api, art := withdrawFixture(t, b)
	b.failGet = true
	if _, _, err := b.GetArtifact(ctx, org, art.Digest()); err == nil {
		t.Fatal("premise: the artifact still loads, so this test would prove nothing")
	}
	_, err := api.Withdraw(ctx, org, pid(t, principalAlice), timeFixture().Add(time.Hour), "back to the shipped set")
	if err == nil || !strings.Contains(err.Error(), "separation of author and approver duties") {
		t.Fatalf("the author's withdrawal with the artifact unloadable answered %v; want the actor rule, read from the admission record", err)
	}
	if _, err := api.Withdraw(ctx, org, pid(t, principalBob), timeFixture().Add(2*time.Hour), "back to the shipped set"); err != nil {
		t.Fatalf("the approver's withdrawal of a document that no longer loads was refused: %v", err)
	}
	if _, active, err := api.Store().Active(ctx, org); err != nil || active {
		t.Fatalf("after the withdrawal the store reports a document active (%v, %v)", active, err)
	}
}

// NO ADMISSION RECORD - only a store admitted before migrations/core/181 - and
// the withdrawal falls back to the artifact. It fails CLOSED: the rule applies
// through the artifact while it loads, and when it will not load the
// withdrawal is refused, never admitted without the rule.
func TestAWithdrawalWithNoAdmissionRecordFallsBackToTheArtifactAndFailsClosed(t *testing.T) {
	ctx := context.Background()
	org := pdp.RootOrganization
	b := &withdrawProbeBackend{Backend: NewMemoryBackend()}
	api, _ := withdrawFixture(t, b)
	b.hidePublish = true
	if _, err := api.Withdraw(ctx, org, pid(t, principalAlice), timeFixture().Add(time.Hour), "why"); err == nil || !strings.Contains(err.Error(), "separation of author and approver duties") {
		t.Fatalf("with no admission record the author's withdrawal answered %v; want the actor rule, through the artifact", err)
	}
	b.failGet = true
	before, err := api.Store().History(ctx, org)
	if err != nil {
		t.Fatalf("reading the history before the refused withdrawal: %v", err)
	}
	if _, err := api.Withdraw(ctx, org, pid(t, principalBob), timeFixture().Add(2*time.Hour), "why"); err == nil || !strings.Contains(err.Error(), "did not verify on load") {
		t.Fatalf("with no admission record and no loadable artifact the withdrawal answered %v; want it refused, fail closed", err)
	}
	after, err := api.Store().History(ctx, org)
	if err != nil {
		t.Fatalf("reading the history after the refused withdrawal: %v", err)
	}
	if len(after) != len(before) {
		t.Fatal("a refused withdrawal appended an entry")
	}
}

// TestAWithdrawalWithNoAdmissionRecordAdmitsTheApproverThroughTheArtifact is the
// POSITIVE half of the fallback, and the test the fallback exists for: with no
// publish entry the rule still applies through the artifact, so an actor who is
// not its author is admitted. Removing the fallback - refusing whenever no
// record names the active digest - fails here, and fails the fail-closed half
// on the sentence that half pins.
func TestAWithdrawalWithNoAdmissionRecordAdmitsTheApproverThroughTheArtifact(t *testing.T) {
	ctx := context.Background()
	org := pdp.RootOrganization
	b := &withdrawProbeBackend{Backend: NewMemoryBackend()}
	api, art := withdrawFixture(t, b)
	b.hidePublish = true
	act, err := api.Withdraw(ctx, org, pid(t, principalBob), timeFixture().Add(time.Hour), "why")
	if err != nil {
		t.Fatalf("with no admission record the approver's withdrawal answered %v; want it admitted through the artifact", err)
	}
	if act.Kind != ActivationWithdraw || act.PreviousDigest != art.Digest() {
		t.Fatalf("the withdrawal recorded %s over %q; want %s over %q", act.Kind, act.PreviousDigest, ActivationWithdraw, art.Digest())
	}
	if _, ok, err := api.Store().Active(ctx, org); err != nil || ok {
		t.Fatalf("after the withdrawal Active answered ok=%v err=%v; want nothing active", ok, err)
	}
}
