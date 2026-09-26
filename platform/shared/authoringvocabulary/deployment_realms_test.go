// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package authoringvocabulary_test

import (
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"axonflow/platform/decision/authoring"
	"axonflow/platform/decision/authoringcatalog"
	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/pdp"
	"axonflow/platform/shared/authoringvocabulary"
	"axonflow/platform/shared/identity"
)

// THE `oidc` REALM IN THE DEPLOYMENT VOCABULARY (#4249). The anchored engine's
// admission realm set and the authoring catalog's realm registry are both built
// from DeploymentRealms, so one declaration decides both whether an
// OIDC-admitted user reaches policy and whether an author may name the realm.

// communityBaseDigest is the digest of the vocabulary a deployment with NOTHING
// wired resolves to - a community build, and any process with no database -
// COMPUTED ON THE BASE of #4249's change
// (main 76fb9d3768a50465f16e1f1ddf29585bd26beb39), before HasOIDC existed, by
// ResolveCatalogValue(SourceDeployment, CatalogDeployment{}) in this package
// with DEPLOYMENT_MODE unset, community-saas, enterprise and saas: all four gave
// this value.
//
// IT IS NOT RECOMPUTED HERE, and that is the point. The change adds a realm to
// some vocabularies; the claim is that it adds it to no Community or Community
// SaaS DEPLOYMENT. A before and after computed in one tree would compare the
// change with itself.
//
// A DEPLOYMENT IS NOT A BUILD. The Community SaaS fleet runs the
// enterprise-tagged image, where a database builds the directory resolver and
// the OIDC configuration provider; its vocabulary is pinned by the tagged twin
// (deployment_realms_enterprise_test.go) against the base digest of what that
// build derived there. An earlier revision of this comment named "every
// Community and Community-SaaS process" here and tested only community builds,
// which is how R3 round 1 found the OIDC realm declared on Community SaaS.
// IT MOVED WITH #4249 row 5670275054, and that is what the version bump is
// for: this PR declares args.context.step__name and args.context.tool__name on
// every deployment action, so the content of EVERY vocabulary changes, in every
// edition and mode, and DeploymentCatalogVersion goes to 4. The guard itself is
// unchanged: one digest under every mode, no edition in it. The value this pin
// held from v11.0.0 to #4347 was
// sha256:8eec9ebcdaec99a36a7bf904ad7f11df008af2dffa31edd4593e0c8dbb93cfa1.
// IT MOVED AGAIN WITH #4371: every deployment action states the enforcement
// scopes that present it (pdp.ActionEntry.Planes), the same on every edition
// and mode, and DeploymentCatalogVersion goes to 5. The guard is unchanged. The
// value this pin held from #4350 to #4371 was
// sha256:c78e1f7c71d55bde064222a332d1b513a5f62c8a78ed860f2be848aaae3aca04.
// SINCE #4259 THE EDITION ENTERS IT, and only there: the Enterprise plane set
// registers cowork_ingest, so an Enterprise-category mode's actions state one
// more scope. The Community and Community SaaS value above is the base's,
// unmoved; enterprisePlaneBaseDigest is the Enterprise-category value, which
// #4259 moved from this one (the base resolved communityBaseDigest under every
// mode).
//
// AND AGAIN WITH #4249 row 5706695827: the orchestrator's two request routes
// are their own enforcement scope, orchestrator_request, so llm.completion and
// agent.invoke each state one scope more. That is edition-independent, unlike
// #4259's, so BOTH pins below move and DeploymentCatalogVersion goes to 7.
const communityBaseDigest = "sha256:2552e410b695fc2ffdbb5d58b6d3ea5681240852c0a08bb62b968ef4bba892ec"

// enterprisePlaneBaseDigest is the digest of the vocabulary a deployment with
// NOTHING wired resolves to under an Enterprise-category deployment mode
// (enterprise, saas): communityBaseDigest's content plus cowork_ingest on
// llm.completion and tool.call (#4259), computed at #4259's head.
const enterprisePlaneBaseDigest = "sha256:1e1638394c74d8825f534ace35a24b9c048d8f474a05e96d1b3a114941de0bc4"

var builtinQualifiers = []string{"axonflow-api-credential", "axonflow-community", "axonflow-internal-service", "axonflow-minted", "axonflow-trusted-header"}

// withMode runs fn under DEPLOYMENT_MODE=mode, or with it unset when mode is "".
func withMode(t *testing.T, mode string, fn func()) {
	t.Helper()
	prev, had := os.LookupEnv("DEPLOYMENT_MODE")
	if mode == "" {
		_ = os.Unsetenv("DEPLOYMENT_MODE")
	} else {
		_ = os.Setenv("DEPLOYMENT_MODE", mode)
	}
	defer func() {
		if had {
			_ = os.Setenv("DEPLOYMENT_MODE", prev)
		} else {
			_ = os.Unsetenv("DEPLOYMENT_MODE")
		}
	}()
	fn()
}

func resolve(t *testing.T, dep authoringvocabulary.CatalogDeployment) *authoringcatalog.Snapshot {
	t.Helper()
	snap, err := authoringvocabulary.ResolveCatalogValue(authoringcatalog.SourceDeployment, dep)
	if err != nil || snap == nil {
		t.Fatalf("%+v: the deployment vocabulary must resolve: %v", dep, err)
	}
	return snap
}

// TestDeploymentRealmsDeclaresOIDCIffTheDeploymentWiresIt drives the four cells
// of HasOIDC x HasDirectory: `oidc` present iff HasOIDC, interactive, with a
// group graph iff HasDirectory too; the five built-ins unchanged by HasOIDC.
func TestDeploymentRealmsDeclaresOIDCIffTheDeploymentWiresIt(t *testing.T) {
	for _, tc := range []struct {
		dep       authoringvocabulary.CatalogDeployment
		oidc      bool
		groupEdge bool
	}{
		{authoringvocabulary.CatalogDeployment{}, false, false},
		{authoringvocabulary.CatalogDeployment{HasDirectory: true}, false, false},
		{authoringvocabulary.CatalogDeployment{HasOIDC: true}, true, false},
		{authoringvocabulary.CatalogDeployment{HasOIDC: true, HasDirectory: true}, true, true},
	} {
		realms := authoringvocabulary.DeploymentRealms(tc.dep)
		entry, ok := realms[string(identity.BuiltinRealmOIDC)]
		if ok != tc.oidc {
			t.Fatalf("%+v: oidc declared=%v, want %v (realms %v)", tc.dep, ok, tc.oidc, keys(realms))
		}
		if ok && (!entry.Interactive || entry.HasGroupGraph != tc.groupEdge) {
			t.Fatalf("%+v: oidc entry %+v; want interactive, group graph %v", tc.dep, entry, tc.groupEdge)
		}
		want := len(builtinQualifiers)
		if tc.oidc {
			want++
		}
		if len(realms) != want {
			t.Fatalf("%+v: %d realms %v, want %d", tc.dep, len(realms), keys(realms), want)
		}
		without := tc.dep
		without.HasOIDC = false
		base := authoringvocabulary.DeploymentRealms(without)
		for _, q := range builtinQualifiers {
			if realms[q] != base[q] {
				t.Fatalf("%+v: HasOIDC moved built-in realm %q from %+v to %+v", tc.dep, q, base[q], realms[q])
			}
		}
	}
}

// TestAVocabularyWithNothingWiredIsTheBaseDigestUnderEveryMode is half 1 of
// the community guard: a Community or Community SaaS deployment's content is
// the base's, and the edition enters the digest only as the plane set the
// Enterprise category registers (#4259). A realm declared unconditionally reds
// here.
func TestAVocabularyWithNothingWiredIsTheBaseDigestUnderEveryMode(t *testing.T) {
	for mode, want := range map[string]string{
		"": communityBaseDigest, "community": communityBaseDigest, "community-saas": communityBaseDigest,
		"enterprise": enterprisePlaneBaseDigest, "saas": enterprisePlaneBaseDigest,
	} {
		withMode(t, mode, func() {
			if got := resolve(t, authoringvocabulary.CatalogDeployment{}).Digest; got != want {
				t.Fatalf("DEPLOYMENT_MODE=%q: a deployment with nothing wired digests to %s; want %s. "+
					"A Community or Community-SaaS vocabulary changed, or the edition now enters the digest beyond the plane set", mode, got, want)
			}
		})
	}
}

// TestTheDeploymentDerivedFromADatabaseDeclaresOIDCOnlyOnEnterprise drives the
// PREDICATE, not DeploymentRealms (half 2 of the community guard): what the
// portal and the importer derive with no database, and with one on this build.
// HasOIDC forced true on a community build reds here; see the tagged twins.
func TestTheDeploymentDerivedFromADatabaseDeclaresOIDCOnlyOnEnterprise(t *testing.T) {
	dep := authoringvocabulary.DeploymentFromDatabase(nil)
	if dep != (authoringvocabulary.CatalogDeployment{}) {
		t.Fatalf("no database: derived %+v; want nothing wired", dep)
	}
	withMode(t, "", func() {
		if got := resolve(t, dep).Digest; got != communityBaseDigest {
			t.Fatalf("no database: digest %s; want the base %s", got, communityBaseDigest)
		}
	})
	assertDerivedFromADatabase(t)
}

// TestPDPRegistryAdmitsTheOIDCRealmIffDeclared is the engine half: the realm
// set the anchored engine admits against carries `oidc` exactly when the
// deployment wires the source, an OIDC actor is admitted then and refused
// unknown_realm otherwise, and a realm nobody declared is still refused (EX-47).
func TestPDPRegistryAdmitsTheOIDCRealmIffDeclared(t *testing.T) {
	for _, hasOIDC := range []bool{false, true} {
		dep := authoringvocabulary.CatalogDeployment{HasOIDC: hasOIDC, HasDirectory: true}
		snap := resolve(t, dep)
		reg, err := snap.Registry.PDPRegistry()
		if err != nil {
			t.Fatal(err)
		}
		if reg.Realms["oidc"] != hasOIDC {
			t.Fatalf("HasOIDC=%v: the engine's realm set %v", hasOIDC, reg.Realms)
		}
		// Both halves come from one function: the catalog an author validates
		// against declares exactly the realms the engine admits, less the two
		// the registry adds for its own planes.
		for q := range snap.Catalog.Realms {
			if !reg.Realms[q] {
				t.Fatalf("HasOIDC=%v: the authoring catalog declares %q and the engine does not admit it", hasOIDC, q)
			}
		}

		oidc := admit(t, reg, "User::oidc:00u-alice")
		switch {
		case hasOIDC && oidc.Failed:
			t.Fatalf("declared: User::oidc refused %s: %s", oidc.Reason, oidc.Detail)
		case !hasOIDC && (!oidc.Failed || oidc.Reason != contract.ReasonUnknownRealm):
			t.Fatalf("undeclared: User::oidc answered failed=%v reason %q; want unknown_realm", oidc.Failed, oidc.Reason)
		case !hasOIDC && !strings.Contains(oidc.Detail, `realm "oidc"`):
			t.Fatalf("undeclared: the refusal does not name the realm: %q", oidc.Detail)
		}
		for _, fake := range []string{"User::okta-prod:x", "User::oidc2:x", "User::OIDC:x"} {
			if r := admit(t, reg, fake); !r.Failed || r.Reason != contract.ReasonUnknownRealm {
				t.Fatalf("HasOIDC=%v: undeclared %s answered failed=%v reason %q; want unknown_realm", hasOIDC, fake, r.Failed, r.Reason)
			}
		}
		if minted := admit(t, reg, "User::axonflow-minted:alice"); minted.Failed {
			t.Fatalf("HasOIDC=%v: the control, a minted actor, was refused %s: %s", hasOIDC, minted.Reason, minted.Detail)
		}
	}
}

func admit(t *testing.T, reg *pdp.Registry, actor string) pdp.AdmissionResult {
	t.Helper()
	id := contract.MustParseID(contract.KindPrincipal, actor)
	return reg.Admit(&contract.Request{
		Principal: id,
		Action:    contract.MustParseID(contract.KindAction, "Action::"+authoringcatalog.ActionToolCall),
		Context:   contract.Context{ActorChain: []contract.Actor{{ID: id}}},
		// tool.call's one required argument, so an admitted actor passes every
		// check after the realm's and "not refused" means admitted.
		Attributes: contract.AttributeSet{"args.query": contract.Known("select 1", contract.ProvCaller, 1, time.Now())},
	})
}

// TestPublicationAcceptsTheOIDCRealmIffDeclared is the authoring half: a scope
// naming User::oidc or Group::oidc is REALM_NOT_DECLARED exactly when the
// deployment does not wire the source, and a realm nobody declared still is.
func TestPublicationAcceptsTheOIDCRealmIffDeclared(t *testing.T) {
	for _, hasOIDC := range []bool{false, true} {
		snap := resolve(t, authoringvocabulary.CatalogDeployment{HasOIDC: hasOIDC, HasDirectory: true})
		for _, scope := range []pdp.Scope{
			{Principals: []contract.ID{contract.MustParseID(contract.KindPrincipal, "User::oidc:00u-alice")}},
			{Groups: []contract.ID{contract.MustParseID(contract.KindGroup, "Group::oidc:finance")}},
		} {
			got := realmFindings(authoring.Validate(scopedDocument(scope), snap.Catalog))
			if hasOIDC && len(got) != 0 {
				t.Fatalf("declared: scope %+v refused %v", scope, got)
			}
			if !hasOIDC && (len(got) != 1 || !strings.Contains(got[0], `"oidc"`)) {
				t.Fatalf("undeclared: scope %+v answered %v; want one REALM_NOT_DECLARED naming oidc", scope, got)
			}
		}
		fake := pdp.Scope{Principals: []contract.ID{contract.MustParseID(contract.KindPrincipal, "User::okta-prod:x")}}
		if got := realmFindings(authoring.Validate(scopedDocument(fake), snap.Catalog)); len(got) != 1 {
			t.Fatalf("HasOIDC=%v: a realm nobody declared answered %v; want REALM_NOT_DECLARED", hasOIDC, got)
		}
	}
}

func realmFindings(fs authoring.Findings) []string {
	var out []string
	for _, f := range fs {
		if f.Code == authoring.CodeRealmNotDeclared {
			out = append(out, f.Detail)
		}
	}
	return out
}

func scopedDocument(scope pdp.Scope) *authoring.Document {
	action := contract.MustParseID(contract.KindAction, "Action::"+authoringcatalog.ActionToolCall)
	attrs := []pdp.AttributeSchema{
		{Path: pdp.PrincipalIDPath, Type: pdp.TypeString},
		{Path: pdp.ActionIDPath, Type: pdp.TypeString},
		{Path: "args.request_type", Type: pdp.TypeString},
	}
	if len(scope.Groups) > 0 {
		attrs = append(attrs, pdp.AttributeSchema{Path: pdp.PrincipalGroupsPath, Type: pdp.TypeArray})
	}
	return &authoring.Document{
		APIVersion: authoring.APIVersion,
		Metadata: authoring.Metadata{
			DocumentID: "org-baseline",
			Title:      "Organization baseline",
			Author:     contract.MustParseID(contract.KindPrincipal, "User::axonflow-minted:author"),
		},
		Policy: pdp.Document{
			Root: pdp.RootOrganization, Version: 1, Attributes: attrs,
			Policies: []pdp.Policy{{
				ID: "ceiling.refund", Authority: contract.AuthorityConstraint, Root: pdp.RootOrganization,
				Scope: scope, Actions: pdp.ActionSelector{Actions: []contract.ID{action}},
				Where: pdp.Compare("args.request_type", pdp.OpEq, "wire_transfer"),
			}},
		},
	}
}

func keys(m map[string]authoring.RealmEntry) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
