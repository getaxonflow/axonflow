// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package authoring

import (
	"context"
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"
	"time"

	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/pdp"
)

// Self-approval (PRD v11 §1.12): an organization with fewer than two eligible
// approvers may enable it; every self-approved publish records the reason and
// the fact on the audit row; the author may activate a self-approved version
// only while self-approval is still granted; an unestablished tier gets none.

const selfApprovalReason = "sole administrator while the second approver is onboarded"

// selfApprovalFixture is an organization authority whose SelfApproval answer
// the test controls, and counts.
type selfApprovalFixture struct {
	api     *API
	cat     *Catalog
	priv    ed25519.PrivateKey
	granted bool
	err     error
	asked   int
}

func newSelfApprovalFixture(t *testing.T, profile Profile) *selfApprovalFixture {
	t.Helper()
	f := &selfApprovalFixture{cat: baseCatalog(t), granted: true}
	trust, priv := organizationTrust(t)
	f.priv = priv
	api, err := NewAPI(f.cat, StaticTrust(trust), profile)
	if err != nil {
		t.Fatal(err)
	}
	f.api = api.WithSelfApproval(func(context.Context) (bool, error) {
		f.asked++
		return f.granted, f.err
	})
	return f
}

func (f *selfApprovalFixture) publish(t *testing.T, doc *Document, approvers []contract.ID, reason string) (*Artifact, Findings, error) {
	t.Helper()
	opts := organizationPublishOptions(t, f.priv)
	opts.Approvers = approvers
	opts.SelfApprovalReason = reason
	return f.api.Publish(context.Background(), doc, opts)
}

func findingsCarry(fs Findings, code string) bool {
	for _, f := range fs {
		if f.Code == code {
			return true
		}
	}
	return false
}

func TestAGrantedSelfApprovalPublishesAndRecordsTheReason(t *testing.T) {
	f := newSelfApprovalFixture(t, mustProfile(t, EditionEnterprise))
	art, findings, err := f.publish(t, organizationDocument(t), []contract.ID{pid(t, principalAlice)}, "  "+selfApprovalReason+" ")
	if err != nil {
		t.Fatalf("a granted self-approval with a reason did not publish: %v\n%v", err, findings)
	}
	if got := art.Provenance().SelfApprovalReason; got != selfApprovalReason {
		t.Fatalf("the signed provenance records reason %q, want %q", got, selfApprovalReason)
	}
	trail, err := f.api.Store().AuditTrail(context.Background(), pdp.RootOrganization)
	if err != nil {
		t.Fatal(err)
	}
	if len(trail) != 1 || !trail[0].SelfApproved || trail[0].Reason != selfApprovalReason {
		t.Fatalf("the audit trail is %+v, want one self-approved publish carrying the reason", trail)
	}
	if f.asked != 1 {
		t.Fatalf("the deployment was asked %d time(s), want once", f.asked)
	}
}

func TestAGrantedSelfApprovalStillRequiresAReason(t *testing.T) {
	f := newSelfApprovalFixture(t, mustProfile(t, EditionEnterprise))
	art, findings, err := f.publish(t, organizationDocument(t), []contract.ID{pid(t, principalAlice)}, "   ")
	if err == nil || art != nil || !findingsCarry(findings, CodeSelfApprovalReasonRequired) {
		t.Fatalf("a granted self-approval with no reason returned err=%v findings=%v, want %s", err, findings, CodeSelfApprovalReasonRequired)
	}
}

func TestSelfApprovalWithoutTheDeploymentsGrantIsTheTwoPersonRefusal(t *testing.T) {
	for _, c := range []struct {
		name    string
		install bool
	}{
		{"no answer installed", false},
		{"the deployment does not grant it", true},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newSelfApprovalFixture(t, mustProfile(t, EditionEnterprise))
			f.granted = false
			if !c.install {
				f.api.selfApproval = nil
			}
			_, findings, err := f.publish(t, organizationDocument(t), []contract.ID{pid(t, principalAlice)}, selfApprovalReason)
			if err == nil || !findingsCarry(findings, CodeApproverIsAuthor) {
				t.Fatalf("err=%v findings=%v, want %s", err, findings, CodeApproverIsAuthor)
			}
		})
	}
}

func TestAnUndecidableSelfApprovalRefusesThePublication(t *testing.T) {
	f := newSelfApprovalFixture(t, mustProfile(t, EditionEnterprise))
	f.err = errors.New("the approver directory is unreachable")
	art, _, err := f.publish(t, organizationDocument(t), []contract.ID{pid(t, principalAlice)}, selfApprovalReason)
	if err == nil || art != nil || !strings.Contains(err.Error(), "the approver directory is unreachable") {
		t.Fatalf("an answer that failed returned an artifact=%v, err=%v; an exception that cannot be decided is not granted", art != nil, err)
	}
}

func TestAnUnestablishedTierGetsNoSelfApproval(t *testing.T) {
	f := newSelfApprovalFixture(t, ProfileForUnestablishedTier())
	_, findings, err := f.publish(t, organizationDocument(t), []contract.ID{pid(t, principalAlice)}, selfApprovalReason)
	if err == nil || !findingsCarry(findings, CodeApproverIsAuthor) {
		t.Fatalf("err=%v findings=%v, want %s", err, findings, CodeApproverIsAuthor)
	}
	if f.asked != 0 {
		t.Fatalf("the deployment was asked %d time(s); an unestablished tier must not reach the question", f.asked)
	}
}

func TestTheDeploymentIsNotAskedAboutATwoPersonPublication(t *testing.T) {
	f := newSelfApprovalFixture(t, mustProfile(t, EditionEnterprise))
	if _, findings, err := f.publish(t, organizationDocument(t), []contract.ID{pid(t, principalBob)}, ""); err != nil {
		t.Fatalf("a two-person publication did not publish: %v\n%v", err, findings)
	}
	if f.asked != 0 {
		t.Fatalf("the deployment was asked %d time(s) about a publication a second person approved", f.asked)
	}
}

func TestASelfApprovalReasonOnATwoPersonPublicationIsRefused(t *testing.T) {
	t.Run("Enterprise", func(t *testing.T) {
		f := newSelfApprovalFixture(t, mustProfile(t, EditionEnterprise))
		_, findings, err := f.publish(t, organizationDocument(t), []contract.ID{pid(t, principalBob)}, selfApprovalReason)
		if err == nil || !findingsCarry(findings, CodeSelfApprovalReasonWithoutSelfApproval) {
			t.Fatalf("err=%v findings=%v, want %s", err, findings, CodeSelfApprovalReasonWithoutSelfApproval)
		}
	})
	t.Run("Community", func(t *testing.T) {
		cat := baseCatalog(t)
		trust, priv := organizationTrust(t)
		api, err := NewAPI(cat, StaticTrust(trust), mustProfile(t, EditionCommunity))
		if err != nil {
			t.Fatal(err)
		}
		opts := communityPublishOptions(t, priv, EditionCommunity)
		opts.Approvers = []contract.ID{pid(t, principalBob)}
		opts.SelfApprovalReason = selfApprovalReason
		_, findings, err := api.Publish(context.Background(), communityDocument(t), opts)
		if err == nil || !findingsCarry(findings, CodeSelfApprovalReasonWithoutSelfApproval) {
			t.Fatalf("err=%v findings=%v, want %s", err, findings, CodeSelfApprovalReasonWithoutSelfApproval)
		}
	})
}

// TestTheAuthorActivatesASelfApprovedVersionOnlyWhileSelfApprovalIsGranted
// withdraws and restores the grant between activations: the answer is asked
// at activation, not trusted from publication.
func TestTheAuthorActivatesASelfApprovedVersionOnlyWhileSelfApprovalIsGranted(t *testing.T) {
	ctx := context.Background()
	f := newSelfApprovalFixture(t, mustProfile(t, EditionEnterprise))
	alice := pid(t, principalAlice)
	at := time.Unix(1_700_000_200, 0).UTC()

	v1, findings, err := f.publish(t, organizationDocument(t), []contract.ID{alice}, selfApprovalReason)
	if err != nil {
		t.Fatalf("v1 must publish: %v\n%v", err, findings)
	}
	v2doc := organizationDocumentWith(t, f.cat, func(m *Metadata, d *pdp.Document) {
		d.Version = 2
		m.Supersedes = v1.Digest()
		policyByIDIn(d, "perm.refund").Where = pdp.Compare("args.amount_cents", pdp.OpLe, 250000)
	})
	v2, findings, err := f.publish(t, v2doc, []contract.ID{alice}, selfApprovalReason)
	if err != nil {
		t.Fatalf("v2 must publish: %v\n%v", err, findings)
	}

	if _, err := f.api.Promote(ctx, pdp.RootOrganization, v1.Digest(), alice, at, "first rollout"); err != nil {
		t.Fatalf("the author could not promote their self-approved version while self-approval is granted: %v", err)
	}
	f.granted = false
	if _, err := f.api.Promote(ctx, pdp.RootOrganization, v2.Digest(), alice, at.Add(time.Hour), "second"); err == nil || !strings.Contains(err.Error(), "cannot also activate") {
		t.Fatalf("with the grant withdrawn the author promoted their own version: %v", err)
	}
	f.granted = true
	if _, err := f.api.Promote(ctx, pdp.RootOrganization, v2.Digest(), alice, at.Add(2*time.Hour), "second"); err != nil {
		t.Fatalf("with the grant restored the author could not promote v2: %v", err)
	}
	if _, err := f.api.Rollback(ctx, pdp.RootOrganization, v1.Digest(), alice, at.Add(3*time.Hour), "the second version misbehaved"); err != nil {
		t.Fatalf("the author could not roll back to their self-approved version while self-approval is granted: %v", err)
	}
	f.granted = false
	if _, err := f.api.Rollback(ctx, pdp.RootOrganization, v2.Digest(), alice, at.Add(4*time.Hour), "again"); err == nil || !strings.Contains(err.Error(), "cannot also activate") {
		t.Fatalf("with the grant withdrawn the author rolled back to their own version: %v", err)
	}
}

func TestSelfApprovalNeverRelievesTheAuthorOfAVersionASecondPersonApproved(t *testing.T) {
	f := newSelfApprovalFixture(t, mustProfile(t, EditionEnterprise))
	v1, findings, err := f.publish(t, organizationDocument(t), []contract.ID{pid(t, principalBob)}, "")
	if err != nil {
		t.Fatalf("v1 must publish: %v\n%v", err, findings)
	}
	_, err = f.api.Promote(context.Background(), pdp.RootOrganization, v1.Digest(), pid(t, principalAlice), time.Unix(1_700_000_200, 0).UTC(), "self")
	if err == nil || !strings.Contains(err.Error(), "cannot also activate") {
		t.Fatalf("the author promoted a version a second person approved: %v", err)
	}
	if f.asked != 0 {
		t.Fatalf("the deployment was asked %d time(s) about a version a second person approved", f.asked)
	}
}

func TestAnUndecidableSelfApprovalRefusesTheActivation(t *testing.T) {
	f := newSelfApprovalFixture(t, mustProfile(t, EditionEnterprise))
	alice := pid(t, principalAlice)
	v1, findings, err := f.publish(t, organizationDocument(t), []contract.ID{alice}, selfApprovalReason)
	if err != nil {
		t.Fatalf("v1 must publish: %v\n%v", err, findings)
	}
	f.err = errors.New("the approver directory is unreachable")
	_, err = f.api.Promote(context.Background(), pdp.RootOrganization, v1.Digest(), alice, time.Unix(1_700_000_200, 0).UTC(), "rollout")
	if err == nil || !strings.Contains(err.Error(), "the approver directory is unreachable") {
		t.Fatalf("an answer that failed returned %v; an exception that cannot be decided is not granted", err)
	}
}

// TestTheExportedStorePromoteGrantsNoSelfApproval: the exported Store.Promote
// passes no answer, so a caller holding a *Store cannot activate their own
// self-approved version through it, even while the deployment grants
// self-approval to the API in front of that store.
func TestTheExportedStorePromoteGrantsNoSelfApproval(t *testing.T) {
	f := newSelfApprovalFixture(t, mustProfile(t, EditionEnterprise))
	alice := pid(t, principalAlice)
	v1, findings, err := f.publish(t, organizationDocument(t), []contract.ID{alice}, selfApprovalReason)
	if err != nil {
		t.Fatalf("v1 must publish: %v\n%v", err, findings)
	}
	_, err = f.api.Store().Promote(context.Background(), pdp.RootOrganization, v1.Digest(), alice, time.Unix(1_700_000_200, 0).UTC(), "rollout")
	if err == nil || !strings.Contains(err.Error(), "cannot also activate") {
		t.Fatalf("the exported Store.Promote let the author activate their own self-approved version: %v", err)
	}
}

// TestThePackageLevelPublishCannotGrantItselfSelfApproval: the grant is
// unexported and only API.PublishAdmitting sets it, so the exported Publish,
// which asks nothing, holds the two-person rule even when handed a reason.
func TestThePackageLevelPublishCannotGrantItselfSelfApproval(t *testing.T) {
	_, priv := organizationTrust(t)
	opts := organizationPublishOptions(t, priv)
	opts.Approvers = []contract.ID{pid(t, principalAlice)}
	opts.SelfApprovalReason = selfApprovalReason
	_, findings, err := Publish(context.Background(), organizationDocument(t), baseCatalog(t), opts)
	if err == nil || !findingsCarry(findings, CodeApproverIsAuthor) {
		t.Fatalf("err=%v findings=%v, want %s", err, findings, CodeApproverIsAuthor)
	}
}
