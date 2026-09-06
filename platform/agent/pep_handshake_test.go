package agent

import (
	"bytes"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/registry"
	"axonflow/platform/shared/deploymode"
)

// requestWithHandshake builds a request carrying zero or more handshake header
// lines.
//
// Header.Add, not Set, and a slice rather than a string, so the repeated-header
// case is constructible. A helper that could only build one header line would
// make the case that motivated base64 encoding untestable.
func requestWithHandshake(values ...string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/api/v1/decide", strings.NewReader(`{}`))
	for _, v := range values {
		r.Header.Add(contract.PEPHandshakeHeader, v)
	}
	return r
}

func encodedHandshake(t *testing.T, name string, caps ...contract.Capability) string {
	t.Helper()
	if caps == nil {
		caps = []contract.Capability{}
	}
	out, refusal := contract.PEPHandshake{
		ProfileVersion: contract.PEPHandshakeProfileV1,
		PEPID:          name,
		Audience:       "axonflow-decision-proof",
		Capabilities:   caps,
	}.Encode()
	if refusal != nil {
		t.Fatalf("fixture handshake was refused by its own encoder: %v", refusal)
	}
	return out
}

// TestResolvePEPHandshakeAbsentIsTodaysBehaviour.
//
// The nothing-changes-by-default arm. It is asserted on the RESOLUTION rather
// than on a response body so it holds regardless of what the rest of the
// handler does with it: absent must refuse nothing, admit nothing, and be
// counted as absent.
func TestResolvePEPHandshakeAbsentIsTodaysBehaviour(t *testing.T) {
	res := resolvePEPHandshake(requestWithHandshake(), "acme")
	if res.outcome != pepHandshakeAbsent {
		t.Fatalf("outcome = %q, want %q", res.outcome, pepHandshakeAbsent)
	}
	if res.refused {
		t.Error("an absent handshake must refuse nothing")
	}
	if res.pep.Admitted() {
		t.Error("an absent handshake must admit no enforcement point")
	}
	if res.presented() {
		t.Error("an absent handshake must not report itself as presented")
	}
}

// TestPresentButEmptyHeaderIsNotAbsent.
//
// Header.Get returns "" for a header that is ABSENT and for one that is PRESENT
// AND EMPTY, so a resolver written against it reads the second as today's
// behaviour - a degrade-to-legacy that no counter would show.
//
// MUTANT: replace r.Header.Values(...) with a Get-based length check at
// pep_handshake.go's `values := r.Header.Values(...)` and this dies.
func TestPresentButEmptyHeaderIsNotAbsent(t *testing.T) {
	res := resolvePEPHandshake(requestWithHandshake(""), "acme")
	if res.outcome == pepHandshakeAbsent {
		t.Fatal("a present-but-empty handshake header was read as absent; Header.Get cannot tell the two apart and neither may this resolver")
	}
	if !res.refused {
		t.Error("a present-but-empty header must refuse: it is a declaration that could not be read, not a caller that said nothing")
	}
}

// TestTheThreeHeaderPresenceStatesAreThreeOUTCOMES.
//
// Rows 1, 2 and 3 of the design's wire table - absent, present-and-empty,
// present-more-than-once - must be TELLABLE APART, not merely all handled.
// `Header.Get` collapses the first two into one return value and cannot see the
// third at all, so a resolver written against it would answer row 1 for row 2
// (a degrade to legacy that no counter shows) and would silently act on one of
// two conflicting declarations for row 3.
//
// The distinctness assertion is the point: a build that refused rows 2 and 3
// with the SAME message would satisfy every other test in this file while
// leaving an operator unable to tell "my client sent an empty header" from "an
// intermediary duplicated my header".
func TestTheThreeHeaderPresenceStatesAreThreeOutcomes(t *testing.T) {
	valid := encodedHandshake(t, "sdk-go", contract.Capability{Type: contract.ObFieldRedact, Version: 1})

	absent := resolvePEPHandshake(requestWithHandshake(), "acme")
	empty := resolvePEPHandshake(requestWithHandshake(""), "acme")
	repeated := resolvePEPHandshake(requestWithHandshake(valid, valid), "acme")

	if absent.outcome != pepHandshakeAbsent || absent.refused {
		t.Fatalf("absent: outcome=%q refused=%v", absent.outcome, absent.refused)
	}
	if !empty.refused || !repeated.refused {
		t.Fatalf("present-empty and repeated must both refuse: empty=%v repeated=%v", empty.refused, repeated.refused)
	}
	if empty.outcome == pepHandshakeAbsent || repeated.outcome == pepHandshakeAbsent {
		t.Fatal("a PRESENT header was reported as absent; Header.Get cannot tell the two apart and neither may this resolver")
	}
	if empty.detail == repeated.detail {
		t.Fatalf("an empty header and a repeated header produced the SAME refusal: %q. "+
			"They are different client-side problems - one client sent nothing, an intermediary duplicated the other - "+
			"and an operator reading the message must be able to tell which", empty.detail)
	}
	if !strings.Contains(repeated.detail, "presented 2 times") {
		t.Errorf("the repeated-header refusal must say how many were presented, got %q", repeated.detail)
	}
	// Both name the header, so neither reads as a body defect on the delegated
	// AuthZEN plane.
	for name, res := range map[string]pepHandshakeResolution{"empty": empty, "repeated": repeated} {
		if !strings.Contains(res.detail, contract.PEPHandshakeHeader) {
			t.Errorf("%s: refusal does not name the header: %q", name, res.detail)
		}
	}
}

// TestTheResolverNeverReadsTheHandshakeHeaderWithGet.
//
// A SOURCE check, and it is narrow on purpose: one file, one symbol. It is the
// weaker of the two proofs here - the behavioural one above is what actually
// catches a regression, and an overlay mutant walks straight past a source
// scan - but it names the prohibited call directly, so a reader who reaches for
// `Get` out of habit sees WHY rather than only that a distant test went red.
func TestTheResolverNeverReadsTheHandshakeHeaderWithGet(t *testing.T) {
	src, err := os.ReadFile("pep_handshake.go")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(src, []byte("Header.Get(contract.PEPHandshakeHeader")) {
		t.Error("the handshake header is read with Header.Get, which returns \"\" for a header that is ABSENT and " +
			"for one that is PRESENT AND EMPTY, and returns only the first of a repeated header. Use Header.Values.")
	}
	if !bytes.Contains(src, []byte("Header.Values(contract.PEPHandshakeHeader")) {
		t.Error("control failed: the resolver no longer reads the header with Header.Values, so the check above " +
			"is asserting the absence of a call in a file that may no longer read the header at all")
	}
}

// TestRepeatedHandshakeHeaderIsRefused.
//
// Header.Get returns only the FIRST of a repeated header, so a resolver written
// against it cannot see the repeat at all and would silently act on one of two
// declarations.
func TestRepeatedHandshakeHeaderIsRefused(t *testing.T) {
	a := encodedHandshake(t, "sdk-go", contract.Capability{Type: contract.ObFieldRedact, Version: 1})
	b := encodedHandshake(t, "sdk-go")
	res := resolvePEPHandshake(requestWithHandshake(a, b), "acme")
	if res.outcome != pepHandshakeMalformed || !res.refused {
		t.Fatalf("outcome = %q refused = %v, want a malformed refusal", res.outcome, res.refused)
	}
	if res.status != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", res.status)
	}
}

// TestHandshakeRefusalNamesTheHeader.
//
// Required by the design review (A3). A refusal raised here is delegated from
// /api/v1/access/evaluation, and that surface renders any 4xx from the
// evaluator as ErrIncompleteEvaluation carrying this text - so the prose is the
// ONLY thing distinguishing a malformed HANDSHAKE from a malformed body
// envelope. A message naming only "/capabilities" would send an operator to
// look at an envelope that has no such member.
func TestHandshakeRefusalNamesTheHeader(t *testing.T) {
	for _, tc := range []struct {
		name    string
		values  []string
		client  string
		wantOut string
	}{
		{"malformed document", []string{"!!!"}, "acme", pepHandshakeMalformed},
		{"missing member", []string{base64.RawURLEncoding.EncodeToString(
			[]byte(`{"profile_version":1,"pep_id":"p","audience":"a"}`))}, "acme", pepHandshakeMalformed},
		{"empty channel identity", []string{encodedHandshake(t, "sdk-go")}, "", pepHandshakeUnbindable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := resolvePEPHandshake(requestWithHandshake(tc.values...), tc.client)
			if res.outcome != tc.wantOut {
				t.Fatalf("outcome = %q, want %q", res.outcome, tc.wantOut)
			}
			if !strings.Contains(res.detail, contract.PEPHandshakeHeader) {
				t.Errorf("the refusal detail must name %s so it cannot be read as a body defect; got %q",
					contract.PEPHandshakeHeader, res.detail)
			}
		})
	}
}

// TestEmptyChannelIdentityRefusesRatherThanSharingOneRecord.
//
// The equals-shaped condition satisfied by the empty actor. Building
// "client::name" from an absent identity would give every such caller ONE
// accepted identifier, so two different enforcement points would share one
// record and one's declaration would answer for the other's request.
//
// MUTANT: delete the TrimSpace guard at pep_handshake.go's
// `if strings.TrimSpace(authenticatedClientID) == ""` and this dies.
func TestEmptyChannelIdentityRefusesRatherThanSharingOneRecord(t *testing.T) {
	h := encodedHandshake(t, "sdk-go")
	for _, id := range []string{"", "   "} {
		res := resolvePEPHandshake(requestWithHandshake(h), id)
		if res.outcome != pepHandshakeUnbindable {
			t.Errorf("client id %q: outcome = %q, want %q", id, res.outcome, pepHandshakeUnbindable)
		}
		if !res.refused || res.status != http.StatusForbidden {
			t.Errorf("client id %q: refused = %v status = %d, want a 403 refusal", id, res.refused, res.status)
		}
	}
	// Control: the same handshake on a real channel is admitted.
	if res := resolvePEPHandshake(requestWithHandshake(h), "acme"); res.refused {
		t.Fatalf("control failed: a bindable channel was refused: %s", res.detail)
	}
}

// TestAdmittedEnforcementPointIsNamespacedByTheCredential.
//
// The identity property, observed end to end through the resolver rather than
// through ExternalPEPID alone: the same document on two channels produces two
// enforcement points.
func TestAdmittedEnforcementPointIsNamespacedByTheCredential(t *testing.T) {
	h := encodedHandshake(t, "sdk-go", contract.Capability{Type: contract.ObFieldRedact, Version: 1})

	mine := resolvePEPHandshake(requestWithHandshake(h), "acme")
	theirs := resolvePEPHandshake(requestWithHandshake(h), "other-org")
	if mine.refused || theirs.refused {
		t.Fatalf("a valid handshake was refused: %s / %s", mine.detail, theirs.detail)
	}
	if mine.pep.Record().ID == theirs.pep.Record().ID {
		t.Fatal("one document produced one identifier on two channels; a declaration from one credential would answer for another's request")
	}
	if !strings.HasPrefix(mine.pep.Record().ID, registry.ExternalPEPPrefix+"acme:") {
		t.Errorf("identifier %q is not namespaced by the authenticated credential", mine.pep.Record().ID)
	}
	// Two names behind ONE credential stay distinguishable, which is what the
	// gateway adapters' two call paths need.
	other := resolvePEPHandshake(requestWithHandshake(encodedHandshake(t, "gateway-headers-only")), "acme")
	if other.pep.Record().ID == mine.pep.Record().ID {
		t.Fatal("two enforcement point names behind one credential collapsed to one identifier")
	}
}

// TestExternalPEPEditionIsDerivedFromTheDeploymentMode.
//
// The blocker this test exists for: the first version of this code used
// isCommunityMode(), which is `DEPLOYMENT_MODE == "community"` and nothing else.
// It answers FALSE - Enterprise, the PERMISSIVE direction here - for an UNSET
// variable and for the whole community-saas fleet, whose own helper comment
// says it is intentionally not community mode. Either would silently disable
// the over-advertising rule on a deployment that is genuinely community.
//
// MUTANT: replace the body with `return registry.EditionEnterprise, true` and
// every community row dies; replace it with isCommunityMode()-based logic and
// the community-saas, evaluation and unset rows die.
func TestExternalPEPEditionIsDerivedFromTheDeploymentMode(t *testing.T) {
	// The expected side is written by hand; the MODE side is derived from
	// deploymode.RecognisedModes(). An earlier version listed eight of the ten
	// recognised spellings by hand and every answer it gave was right - which is
	// the problem: a mode added to deploymode would have been silently
	// unexercised here, and this is the function that decides whether the
	// over-advertising rule runs at all.
	want := map[string]registry.Edition{
		"community":         registry.EditionCommunity,
		"evaluation":        registry.EditionCommunity,
		"community-saas":    registry.EditionCommunity,
		"in-vpc-enterprise": registry.EditionEnterprise,
		"in-vpc-healthcare": registry.EditionEnterprise,
		"in-vpc-banking":    registry.EditionEnterprise,
		"in-vpc-travel":     registry.EditionEnterprise,
		"saas":              registry.EditionEnterprise,
		"invpc":             registry.EditionEnterprise, // alias
		"enterprise":        registry.EditionEnterprise, // alias: what the compose files default to
	}

	recognised := deploymode.RecognisedModes()
	if len(recognised) == 0 {
		t.Fatal("deploymode declares no recognised modes, so this table asserts nothing")
	}
	for _, mode := range recognised {
		expected, listed := want[mode]
		if !listed {
			t.Fatalf("deploymode recognises %q and this table does not classify it. Decide whether a deployment in "+
				"that mode issues Enterprise-only obligation families before adding a row - guessing here is how the "+
				"over-advertising rule silently stops running on a whole class of deployment.", mode)
		}
		t.Run("mode="+mode, func(t *testing.T) {
			t.Setenv("DEPLOYMENT_MODE", mode)
			got, ok := externalPEPEdition()
			if !ok {
				t.Fatalf("a recognised mode was not resolvable")
			}
			if got != expected {
				t.Fatalf("edition = %s, want %s", got, expected)
			}
		})
	}
	// Both classes must be represented, or the table could be satisfied by a
	// function that returns one constant.
	var sawCommunity, sawEnterprise bool
	for _, e := range want {
		sawCommunity = sawCommunity || e == registry.EditionCommunity
		sawEnterprise = sawEnterprise || e == registry.EditionEnterprise
	}
	if !sawCommunity || !sawEnterprise {
		t.Fatal("the table classifies every mode the same way, so a constant-returning derivation would satisfy it")
	}

	// UNSET is not a "recognised mode" and is handled separately: deploymode
	// resolves it to `community` for schema selection, and this must agree - the
	// alternative reading (Enterprise) is the permissive one here.
	t.Run("mode=(unset)", func(t *testing.T) {
		t.Setenv("DEPLOYMENT_MODE", "")
		got, ok := externalPEPEdition()
		if !ok || got != registry.EditionCommunity {
			t.Fatalf("unset: edition = %s ok = %v, want community; Enterprise is the arm on which the over-advertising rule never runs", got, ok)
		}
	})

	t.Run("mode=(unrecognised)", func(t *testing.T) {
		t.Setenv("DEPLOYMENT_MODE", "not-a-mode")
		got, ok := externalPEPEdition()
		if ok || got != registry.EditionUnspecified {
			t.Fatalf("unrecognised: edition = %s ok = %v, want a refusal", got, ok)
		}
	})
}

// TestUnrecognisedDeploymentModeRefusesRatherThanGuessing.
//
// deploymode.AppliesCategory answers "yes" for an unrecognised mode, which is
// correct for schema selection - a read that fails is recoverable, a schema
// that is missing is not - and is the WRONG direction here, where "yes" means
// Enterprise and Enterprise is the arm on which the over-advertising rule never
// runs. So this path resolves first and refuses.
func TestUnrecognisedDeploymentModeRefusesRatherThanGuessing(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "not-a-mode")
	res := resolvePEPHandshake(requestWithHandshake(encodedHandshake(t, "sdk-go")), "acme")
	if res.outcome != pepHandshakeUnresolvable || !res.refused {
		t.Fatalf("outcome = %q refused = %v, want an edition_unresolvable refusal", res.outcome, res.refused)
	}
	if res.pep.Admitted() {
		t.Error("an enforcement point was admitted with no established edition")
	}
}

// TestOverAdvertisedCapabilitiesAreDroppedAndTheRequestProceeds.
//
// Dropping rather than refusing, because refusing would 400 every call from a
// correctly-built client whose single compile-time capability set names a
// family this deployment does not issue - and under the derivation rule that
// refusal can only ever fire in Community, i.e. it would land exclusively on
// the edition it disadvantages.
func TestOverAdvertisedCapabilitiesAreDroppedAndTheRequestProceeds(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "community")
	h := encodedHandshake(t, "sdk-go",
		contract.Capability{Type: contract.ObApprovalChallenge, Version: 1},
		contract.Capability{Type: contract.ObFieldRedact, Version: 1})

	res := resolvePEPHandshake(requestWithHandshake(h), "acme")
	if res.refused {
		t.Fatalf("an over-advertising declaration refused the request: %s", res.detail)
	}
	if res.outcome != pepHandshakeOverAdvertised {
		t.Fatalf("outcome = %q, want %q: a silent narrowing is the only thing that would make dropping worse than refusing",
			res.outcome, pepHandshakeOverAdvertised)
	}
	if len(res.dropped) != 1 || res.dropped[0].Type != contract.ObApprovalChallenge {
		t.Fatalf("dropped = %v, want exactly the approval capability", res.dropped)
	}
	// The narrowed set is what the enforcement point is held to.
	if !res.pep.SupportsObligation(contract.Obligation{Type: contract.ObFieldRedact, SchemaVersion: 1, Mandatory: true}).Supported() {
		t.Error("the kept capability must still be honoured")
	}
	if res.pep.SupportsObligation(contract.Obligation{Type: contract.ObApprovalChallenge, SchemaVersion: 1, Mandatory: true}).Supported() {
		t.Error("the dropped capability must not be honoured")
	}

	// The CONTROL that makes this about the EDITION: the same declaration on an
	// Enterprise deployment drops nothing.
	t.Setenv("DEPLOYMENT_MODE", "in-vpc-enterprise")
	ent := resolvePEPHandshake(requestWithHandshake(h), "acme")
	if len(ent.dropped) != 0 || ent.outcome != pepHandshakeAccepted {
		t.Fatalf("enterprise: outcome = %q dropped = %v, want a clean acceptance", ent.outcome, ent.dropped)
	}
}

// TestDroppingAnOverAdvertisedCapabilityCanNeverCauseASilentDeny is the
// INVARIANT the design review requires before dropping is safe.
//
// Dropping is fail-safe only if a dropped capability can never be the one a
// decision actually needed. That holds because of a fact about the decide
// plane, and this test is what pins the fact rather than the intention: the
// obligation types this plane can emit are exactly the values of
// legacyObligationType - a CLOSED table whose absent key is an error rather
// than a default - and none of them belongs to an Enterprise-only family. So no
// obligation the plane composes can name a family the edition rule would have
// dropped, in either edition, and a dropped entry can never become a deny the
// operator cannot explain.
//
// MUTANT: add `ObligationApprovalChallenge: contract.ObApprovalChallenge` to
// legacyObligationType and this dies. That is the exact change that would make
// dropping unsafe, and it is caught here rather than in production.
func TestDroppingAnOverAdvertisedCapabilityCanNeverCauseASilentDeny(t *testing.T) {
	if len(legacyObligationType) == 0 {
		t.Fatal("the legacy obligation table is empty, so this invariant is vacuous")
	}
	enterpriseOnly := map[contract.ObligationFamily]bool{}
	for _, f := range registry.EnterpriseOnlyFamilies() {
		enterpriseOnly[f] = true
	}
	if len(enterpriseOnly) == 0 {
		t.Fatal("no family is Enterprise-only, so this invariant is vacuous and the drop rule has nothing to drop")
	}

	for legacy, typed := range legacyObligationType {
		family, err := contract.FamilyOf(typed)
		if err != nil {
			t.Fatalf("legacy obligation %q maps to %q, which declares no family", legacy, typed)
		}
		if enterpriseOnly[family] {
			t.Errorf("the decide plane can emit %q (from legacy %q), whose family %q is Enterprise-only. "+
				"Dropping an over-advertised capability is fail-safe ONLY while no emittable obligation belongs to a droppable family; "+
				"with this mapping a community enforcement point that advertised %q would have it dropped and then be denied for not "+
				"having it. Either revert the external over-advertising remedy to a refusal, or exclude this family from the drop rule.",
				typed, legacy, family, typed)
		}
	}
}

// TestEveryOutcomeTheResolverProducesIsADeclaredLabel.
//
// THE FIRST VERSION OF THIS TEST WAS A TAUTOLOGY. It built the "declared" set
// from allPEPHandshakeOutcomes() and then compared it against a hand-copied
// literal of the same six constants, so it could only fail if somebody edited
// one of two adjacent lists. A seventh outcome added to the resolver and
// omitted from the declared list would have passed - which is precisely the
// case a label-domain test exists for.
//
// The produced side is now DRIVEN THROUGH THE RESOLVER: every outcome is
// reached by a real input, and each answer must be a declared member. An
// outcome the resolver can produce and the list does not name now fails here.
func TestEveryOutcomeTheResolverProducesIsADeclaredLabel(t *testing.T) {
	declared := map[string]bool{}
	for _, o := range allPEPHandshakeOutcomes() {
		if declared[o] {
			t.Fatalf("outcome %q is declared twice", o)
		}
		declared[o] = true
	}

	valid := encodedHandshake(t, "sdk-go", contract.Capability{Type: contract.ObFieldRedact, Version: 1})
	overAdvertising := encodedHandshake(t, "sdk-go",
		contract.Capability{Type: contract.ObApprovalChallenge, Version: 1})

	produced := map[string]bool{}
	for _, tc := range []struct {
		name     string
		mode     string
		clientID string
		values   []string
		want     string
	}{
		{"absent", "in-vpc-enterprise", "acme", nil, pepHandshakeAbsent},
		{"accepted", "in-vpc-enterprise", "acme", []string{valid}, pepHandshakeAccepted},
		{"malformed", "in-vpc-enterprise", "acme", []string{"!!!"}, pepHandshakeMalformed},
		{"identity unbindable", "in-vpc-enterprise", "", []string{valid}, pepHandshakeUnbindable},
		{"over advertised", "community", "acme", []string{overAdvertising}, pepHandshakeOverAdvertised},
		{"edition unresolvable", "not-a-mode", "acme", []string{valid}, pepHandshakeUnresolvable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("DEPLOYMENT_MODE", tc.mode)
			got := resolvePEPHandshake(requestWithHandshake(tc.values...), tc.clientID).outcome
			if got != tc.want {
				t.Fatalf("outcome = %q, want %q", got, tc.want)
			}
			if !declared[got] {
				t.Fatalf("the resolver produced outcome %q, which allPEPHandshakeOutcomes() does not declare; "+
					"an undeclared label is an unbounded series nobody reviewed", got)
			}
			produced[got] = true
		})
	}

	// EVERY declared outcome must be reachable, or the domain carries a label
	// no input produces - which is the mirror defect and is how a stale member
	// survives a rename.
	for _, o := range allPEPHandshakeOutcomes() {
		if !produced[o] {
			t.Errorf("outcome %q is declared but no input in this table produces it; either it is unreachable "+
				"or this table has stopped covering the resolver", o)
		}
	}

	for _, o := range allPEPHandshakeOutcomes() {
		if strings.ContainsAny(o, "@:/") {
			t.Errorf("outcome label %q looks like an identifier rather than a closed enumeration member", o)
		}
	}
}

// TestTheCapabilityRefusalStatusLabelIsBounded.
//
// THE DEFECT A LIST-VS-LIST TEST COULD NOT SEE. The first version of this
// check compared allCapabilityRefusalStatuses() against
// registry.AllCapabilityStatuses() - two hand-maintained lists, so it could
// only fail if somebody edited one and not the other. Driving the real refusal
// path instead (see the enterprise arm) immediately produced two labels neither
// list declares.
//
// The sharper of the two is unbounded: CapabilityStatus.String() renders an
// unrecognised value as "CapabilityStatus(9999)", a DISTINCT string per value,
// so one such status in a Prometheus label is one new series per value. The
// zero value renders as "unspecified", which as a REFUSAL label means nobody
// ever answered rather than that a check refused. Both collapse onto one
// bounded literal, loudly - the series exists, so an operator sees that
// something wrote a status this build has no name for.
func TestTheCapabilityRefusalStatusLabelIsBounded(t *testing.T) {
	domain := map[string]bool{}
	for _, st := range allCapabilityRefusalStatuses() {
		if domain[st] {
			t.Fatalf("status %q is declared twice", st)
		}
		domain[st] = true
	}
	if domain[registry.CapabilitySupported.String()] {
		t.Error("the ADMITTING status is in a REFUSAL counter's domain; it can never be written there")
	}
	if !domain[capabilityRefusalProjectionFailed] || !domain[capabilityRefusalStatusUndeclared] {
		t.Error("a label the code writes is missing from the declared domain")
	}

	for _, st := range []registry.CapabilityStatus{
		registry.CapabilityStatusUnspecified, registry.CapabilityStatus(9999), registry.CapabilityStatus(-1),
	} {
		got := capabilityRefusalStatusLabel(st)
		if got != capabilityRefusalStatusUndeclared {
			t.Errorf("status %s produced label %q; an undeclared status must collapse to ONE bounded literal, or one bad value is one new series", st, got)
		}
		if !domain[got] {
			t.Errorf("the bounded label %q is not in the declared domain", got)
		}
	}

	// The CONTROL: a declared status keeps its own name, or the bounding helper
	// has erased the very distinction the counter exists for.
	for _, st := range registry.AllCapabilityStatuses() {
		if st == registry.CapabilitySupported {
			continue
		}
		got := capabilityRefusalStatusLabel(st)
		if got != st.String() {
			t.Errorf("declared status %s was collapsed to %q", st, got)
		}
		if !domain[got] {
			t.Errorf("declared status %s produces label %q, absent from the domain", st, got)
		}
	}
}

// TestAnAdmittedDeclarationReachesTheAuditRow.
//
// A COUNTER ANSWERS HOW MANY; AN AUDIT ROW ANSWERS WHICH. A
// `pep_capability_unsupported` deny is the one kind of refusal whose cause
// lives entirely in something the CALLER said, so a compliance reader asking
// "why was this refused, and on whose word" has nowhere else to look. The
// legacy `gateway_id` this handshake supersedes is already on the row;
// recording strictly less about its successor would be a regression nobody
// declared.
func TestAnAdmittedDeclarationReachesTheAuditRow(t *testing.T) {
	t.Setenv("DEPLOYMENT_MODE", "in-vpc-enterprise")

	res := resolvePEPHandshake(requestWithHandshake(encodedHandshake(t, "sdk-go",
		contract.Capability{Type: contract.ObFieldRedact, Version: 1})), "acme")
	if res.refused {
		t.Fatalf("fixture refused: %s", res.detail)
	}

	fields, ok := res.auditFields()
	if !ok {
		t.Fatal("an admitted declaration contributed nothing to the audit row")
	}
	// The RESOLVED identifier, never the caller's raw pep_id: a row recording a
	// name the platform did not compose could not be told from a claim.
	if fields.identity != "client:acme:sdk-go" {
		t.Errorf("identity = %q, want the composed identifier", fields.identity)
	}
	if fields.identity == "sdk-go" {
		t.Error("the row recorded the caller's raw pep_id")
	}
	if fields.audience != "axonflow-decision-proof" {
		t.Errorf("audience = %q", fields.audience)
	}
	if len(fields.capabilities) != 1 || fields.capabilities[0] != "field_redact@1" {
		t.Errorf("capabilities = %v, want [field_redact@1]", fields.capabilities)
	}

	// An admitted point that declared NOTHING records an EMPTY list, not an
	// absent one — the same collapse this lane exists to correct, one storage
	// layer down.
	none := resolvePEPHandshake(requestWithHandshake(encodedHandshake(t, "sdk-none")), "acme")
	noneFields, ok := none.auditFields()
	if !ok {
		t.Fatal("a declared-empty enforcement point contributed nothing")
	}
	if noneFields.capabilities == nil {
		t.Error("a declared-empty set reached the audit row as an ABSENT member; 'declared none' and 'declared nothing at all' must stay distinguishable in the durable record too")
	}
	if len(noneFields.capabilities) != 0 {
		t.Errorf("capabilities = %v, want empty", noneFields.capabilities)
	}

	// The ADMITTED set, not the declared one: an over-advertised entry was
	// dropped, and the row must record what the decision was taken against.
	t.Setenv("DEPLOYMENT_MODE", "community")
	narrowed := resolvePEPHandshake(requestWithHandshake(encodedHandshake(t, "sdk-x",
		contract.Capability{Type: contract.ObApprovalChallenge, Version: 1},
		contract.Capability{Type: contract.ObFieldRedact, Version: 1})), "acme")
	nf, ok := narrowed.auditFields()
	if !ok {
		t.Fatal("an over-advertising point contributed nothing")
	}
	for _, c := range nf.capabilities {
		if strings.HasPrefix(c, string(contract.ObApprovalChallenge)) {
			t.Errorf("the audit row records a capability the platform DROPPED (%q); the row must say what the decision was taken against", c)
		}
	}
	if len(nf.capabilities) != 1 {
		t.Errorf("capabilities = %v, want only the kept one", nf.capabilities)
	}

	// A caller that presented NOTHING contributes nothing, so an empty identity
	// can never make "no handshake" look like "a handshake from nobody".
	if _, ok := resolvePEPHandshake(requestWithHandshake(), "acme").auditFields(); ok {
		t.Error("a caller that presented no handshake contributed audit fields")
	}
}

// TestTheAuditDetailsCarryTheDeclaration drives the real details builder, so
// the fields above are asserted where they actually land rather than only on
// the struct that feeds it.
func TestTheAuditDetailsCarryTheDeclaration(t *testing.T) {
	details := buildDecisionAuditDetails("d-1", "llm", nil, nil, nil, false, decisionAuditInput{
		pepIdentity:     "client:acme:sdk-go",
		pepAudience:     "axonflow-decision-proof",
		pepCapabilities: []string{"field_redact@1"},
	})
	for k, want := range map[string]any{
		"pep_id":       "client:acme:sdk-go",
		"pep_audience": "axonflow-decision-proof",
	} {
		if got, ok := details[k]; !ok || got != want {
			t.Errorf("details[%q] = %v (present=%v), want %v", k, got, ok, want)
		}
	}
	caps, ok := details["pep_capabilities"].([]string)
	if !ok || len(caps) != 1 || caps[0] != "field_redact@1" {
		t.Errorf("details[pep_capabilities] = %v", details["pep_capabilities"])
	}

	// A declared-empty set is an EMPTY member, never an absent one.
	empty := buildDecisionAuditDetails("d-2", "llm", nil, nil, nil, false, decisionAuditInput{
		pepIdentity: "client:acme:sdk-none",
	})
	if _, ok := empty["pep_capabilities"]; !ok {
		t.Error("a declared-empty enforcement point produced NO pep_capabilities member; absent and empty must not collapse in the durable record")
	}

	// A caller with no handshake adds no members at all.
	bare := buildDecisionAuditDetails("d-3", "llm", nil, nil, nil, false, decisionAuditInput{})
	for _, k := range []string{"pep_id", "pep_audience", "pep_capabilities"} {
		if _, ok := bare[k]; ok {
			t.Errorf("a handshake-less decision wrote %q onto its audit row", k)
		}
	}
}

// TestEveryFamilyTheOverAdvertisedCounterWritesIsADeclaredLabel.
//
// THE THIRD COUNTER'S DOMAIN, ASSERTED RATHER THAN MERELY DECLARED — and the
// reason this test exists is that its own fix repeated the defect it fixed.
// Round 2 found `pepCapabilityOverAdvertised` had no declared label domain
// while the other two counters had been given one in the same change; the fix
// added `allOverAdvertisedFamilies()` and then read it from nowhere, which the
// unused-symbol linter caught. A declared domain nothing checks is the same
// shape as a documented field nothing reads.
//
// So this drives the real recording path and asserts the label the counter
// actually receives.
func TestEveryFamilyTheOverAdvertisedCounterWritesIsADeclaredLabel(t *testing.T) {
	domain := map[string]bool{}
	for _, f := range allOverAdvertisedFamilies() {
		if domain[f] {
			t.Fatalf("family %q is declared twice", f)
		}
		domain[f] = true
	}
	if !domain[overAdvertisedFamilyUnresolved] {
		t.Error("the unresolved-family literal is written by recordPEPHandshakeOutcome and is not in the declared domain")
	}
	for _, f := range contract.AllObligationFamilies() {
		if !domain[string(f)] {
			t.Errorf("obligation family %q can be dropped and is not in the declared domain", f)
		}
	}

	// Driven through the real path: a community deployment dropping an
	// Enterprise-only family must produce a label inside the domain.
	t.Setenv("DEPLOYMENT_MODE", "community")
	res := resolvePEPHandshake(requestWithHandshake(encodedHandshake(t, "sdk-x",
		contract.Capability{Type: contract.ObApprovalChallenge, Version: 1},
		contract.Capability{Type: contract.ObFieldRedact, Version: 1})), "acme")
	if len(res.dropped) == 0 {
		t.Fatal("fixture invalid: nothing was dropped, so no family label is written and this asserts nothing")
	}
	for _, c := range res.dropped {
		family, err := contract.FamilyOf(c.Type)
		label := string(family)
		if err != nil {
			label = overAdvertisedFamilyUnresolved
		}
		if !domain[label] {
			t.Errorf("the drop path writes family label %q, which allOverAdvertisedFamilies() does not declare", label)
		}
	}
	// The recording call itself must not panic on the real resolution — a
	// counter that errors on its own input is worse than an undeclared label.
	recordPEPHandshakeOutcome(PlaneDecision, res)
}

// TestEveryReasonTheResolverPutsInFrontOfACallerIsDeclared.
//
// The four reason strings are what a PEP branches on, so an undeclared one is
// an unreviewed branch in somebody else's client — a stronger claim than any of
// the three metric label domains, all of which were given a declared set while
// these were not.
//
// DRIVEN THROUGH THE RESOLVER, not compared against a second list. A
// list-versus-list check is the tautology this lane has already had to remove
// twice, and it cannot see a reason string the code writes and neither list
// names.
func TestEveryReasonTheResolverPutsInFrontOfACallerIsDeclared(t *testing.T) {
	declared := map[string]bool{}
	for _, r := range allPEPHandshakeReasons() {
		if declared[r] {
			t.Fatalf("reason %q is declared twice", r)
		}
		declared[r] = true
	}

	valid := encodedHandshake(t, "sdk-go", contract.Capability{Type: contract.ObFieldRedact, Version: 1})
	produced := map[string]bool{}
	for _, tc := range []struct {
		name, mode, clientID string
		values               []string
	}{
		{"malformed", "in-vpc-enterprise", "acme", []string{"!!!"}},
		{"repeated", "in-vpc-enterprise", "acme", []string{valid, valid}},
		{"unbindable", "in-vpc-enterprise", "", []string{valid}},
		{"edition unresolvable", "not-a-mode", "acme", []string{valid}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("DEPLOYMENT_MODE", tc.mode)
			res := resolvePEPHandshake(requestWithHandshake(tc.values...), tc.clientID)
			if !res.refused {
				t.Fatalf("fixture invalid: %s did not refuse, so no reason is produced", tc.name)
			}
			if res.reason == "" {
				t.Fatal("a refusal reached a caller with no machine reason to branch on")
			}
			if !declared[res.reason] {
				t.Fatalf("the resolver put reason %q in front of a caller, and allPEPHandshakeReasons() does not "+
					"declare it; an undeclared reason string is an unreviewed branch in somebody else's client", res.reason)
			}
			produced[res.reason] = true
		})
	}

	// The capability-deny reason is produced by the enforcement arm rather than
	// the resolver, so it is not reachable here — but it must still be declared,
	// and its absence from `produced` is expected rather than a gap.
	if !declared[pepCapabilityUnsupportedCode] {
		t.Error("the capability-deny reason is written by the enterprise arm and is not declared")
	}
	for r := range produced {
		if r == pepCapabilityUnsupportedCode {
			t.Error("the capability reason is not produced by the resolver; if it now is, this test's accounting is stale")
		}
	}
	if len(produced)+1 != len(allPEPHandshakeReasons()) {
		t.Errorf("the resolver produced %d of the %d declared reasons (plus the enforcement arm's one); "+
			"a declared reason no input produces is either unreachable or this table has stopped covering the resolver",
			len(produced), len(allPEPHandshakeReasons()))
	}
}
