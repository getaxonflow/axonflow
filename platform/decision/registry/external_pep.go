package registry

import (
	"fmt"

	"axonflow/platform/decision/contract"
)

// External enforcement points: how an SDK client, a plugin or a gateway adapter
// enters the ADR-065 PEP catalog.
//
// # WHY ADMITTED AND NOT REGISTERED
//
// Catalog registration is CREATE-ONLY and process-wide, and both properties are
// correct for the in-process planes and wrong for an external enforcement
// point. Create-only exists so that a caller cannot drop a governed tag by
// re-registering; applied to an external PEP it would mean the SECOND request
// from the same enforcement point is refused for existing. Process-wide means
// one instance's declaration would answer for another instance's request, which
// during a rolling upgrade is exactly the wrong instance: the one that has NOT
// caught up would be judged by the one that has.
//
// So an external declaration is ADMITTED - held to every rule a registered
// record is held to, and then used for THIS request and discarded. Nothing is
// stored, so there is nothing to go stale, nothing to invalidate on rotation,
// and no coherence problem between replicas.
//
// # WHAT IS SHARED WITH THE REGISTERED PATH, AND WHY IT MATTERS
//
// The validation is PEPRecord.Validate - the same capability vocabulary check,
// the same positive-version rule, the same edition requirement and the same
// community over-advertising rule. The capability answer is checkCapability -
// the same function, so the CapabilityStatus mapping has one implementation and
// an external PEP and an in-process plane can never disagree about what
// "declared none" means. A second copy of either would be a second thing to
// drift, and the drift would be invisible: both copies would keep passing their
// own tests.

// ExternalPEPRealm is the trust realm an externally authenticated enforcement
// point resolves in.
//
// One realm rather than one per client, for the same reason LegacyPlaneRealm is
// one realm rather than twelve: a realm claims a trust boundary, and the
// deployment does not separate two API credentials into different trust
// domains. A realm per client would let a policy be scoped to a boundary
// nothing enforces.
const ExternalPEPRealm = "axonflow_client"

// ExternalPEPPrefix prefixes an external enforcement point's identifier.
//
// Deliberately distinct from LegacyPlanePEPPrefix ("plane:"), so an external
// enforcement point can never collide with, or be read as, an in-process plane
// in a capability refusal or a log line.
const ExternalPEPPrefix = "client:"

// ExternalPEPID builds the platform's identifier for one external enforcement
// point.
//
// authenticatedClientID is the identity apiAuthMiddleware derived from the
// CREDENTIAL. declaredName is the name the enforcement point chose for itself
// inside that credential, and it is the ONLY half a caller supplies.
//
// This is the identity property, and it holds structurally rather than by a
// comparison that could be deleted: there is no input that reaches the prefix,
// so a caller cannot name an enforcement point belonging to another credential
// at all. The alternative - accepting a full identifier and refusing a mismatch
// - would require every client to predict the server's own derivation of its
// authenticated identity, which differs by auth path, so a correct client could
// not satisfy it without guessing.
//
// declaredName is required by contract.PEPHandshake's validator to contain no
// colon, so the LAST colon separates the credential from the name and the
// identifier parses back unambiguously even when a credential contains one.
func ExternalPEPID(authenticatedClientID, declaredName string) string {
	return ExternalPEPPrefix + authenticatedClientID + ":" + declaredName
}

// RegisterExternalPEPRealm declares the external realm on a catalog.
//
// It is idempotent, unlike RegisterRealm, because the catalog a deployment
// admits external PEPs against is built once per process and a second call is a
// caller asking for a state that already holds rather than a collision worth
// refusing.
func RegisterExternalPEPRealm(c *Catalog) error {
	if c == nil {
		return fmt.Errorf("registry: cannot declare the external enforcement point realm on a nil catalog")
	}
	if c.RealmDeclared(ExternalPEPRealm) {
		return nil
	}
	return c.RegisterRealm(ExternalPEPRealm)
}

// ExternalPEPRecordFrom builds the record an admitted handshake produces.
//
// THE TWO FIELDS A CALLER DOES NOT SUPPLY are the point of this function.
//
// The IDENTITY's namespace comes from authenticatedClientID; the handshake
// supplies only the name inside it. See ExternalPEPID.
//
// The EDITION comes from the enforcement context, not from the handshake, and
// there is deliberately no edition member on the wire at all. A PEP declaring
// its own edition would defeat exactly the over-advertising rule that exists to
// catch it: a community build claiming Enterprise would be believed. The
// residual is real and is named rather than hidden - a community-built PEP
// talking to an Enterprise deployment is admitted as Enterprise and may
// over-advertise. Only that PEP's own build knows its edition, and the platform
// cannot verify a claim about another machine; this is the same trust the
// obligation contract already places in an authenticated PEP to PERFORM the
// redaction it is told to perform. What the rule does close is the case where
// the claim is provably impossible: a deployment that does not issue the family
// at all.
func ExternalPEPRecordFrom(authenticatedClientID string, edition Edition, h contract.PEPHandshake) PEPRecord {
	return PEPRecord{
		ID:           ExternalPEPID(authenticatedClientID, h.PEPID),
		Realm:        ExternalPEPRealm,
		Edition:      edition,
		Capabilities: contract.SortCapabilities(h.Capabilities),
		Description: fmt.Sprintf(
			"external enforcement point, %s build, handshake profile %d, audience %q",
			edition, h.ProfileVersion, h.Audience),
	}
}

// ExternalPEP is one enforcement point admitted for the life of one request.
//
// The unexported `admitted` flag is what makes the ZERO VALUE unusable. Without
// it a zero ExternalPEP would answer every capability question with
// CapabilityDeclaredNone - a plausible, wrong answer that reads as "this PEP
// told us it can do nothing" when the truth is that nobody ever admitted one.
// A construction defect must not be indistinguishable from a declaration.
type ExternalPEP struct {
	rec      PEPRecord
	admitted bool
}

// Admitted reports whether this value came from AdmitExternalPEP.
func (e ExternalPEP) Admitted() bool { return e.admitted }

// Record returns a copy of the admitted record.
func (e ExternalPEP) Record() PEPRecord { return e.rec.clone() }

// Profile projects the admitted record onto the enforcement profile the
// obligation algebra consults.
//
// A nil profile for an unadmitted value, which is the reading ADR-065 invariant
// 12 already defines: an enforcement point that has not advertised a profile
// refuses the request rather than having it interpreted partially.
func (e ExternalPEP) Profile() *contract.PEPProfile {
	if !e.admitted {
		return nil
	}
	return e.rec.Profile()
}

// SupportsObligation answers whether this admitted enforcement point can
// discharge one obligation.
//
// It calls the SAME checkCapability the registered path calls, so the status
// mapping has one implementation. An unadmitted value answers with the
// UNSPECIFIED status, whose Supported() is false and whose IsValid() is false:
// a construction defect must fail closed AND be recognisable as a defect, which
// CapabilityNoRecord would not be - that status means "no enforcement point is
// registered under that identifier", which is a statement about a catalog
// rather than about this value.
func (e ExternalPEP) SupportsObligation(o contract.Obligation) CapabilityCheck {
	if !e.admitted {
		return CapabilityCheck{
			Status:     CapabilityStatusUnspecified,
			PEP:        e.rec.ID,
			Obligation: o.Type,
			Version:    o.SchemaVersion,
			Detail: "this enforcement point value was never admitted, so nothing has been validated about it; " +
				"an unadmitted value is a construction defect rather than a declaration, and it refuses",
		}
	}
	return checkCapability(e.rec.ID, e.rec, true, o)
}

// AdmitExternalPEP validates a handshake-derived record against every catalog
// rule that governs a registered one, and returns it WITHOUT storing it.
//
// The create-only rule is the one rule deliberately NOT applied: storing
// nothing, there is nothing to collide with, and a second request from the same
// enforcement point is a second declaration rather than a re-registration. See
// the file comment for why storing it would be wrong rather than merely
// unnecessary.
//
// The realm rule IS applied, and through the catalog rather than a constant
// comparison, so a deployment that has not declared the external realm cannot
// admit external enforcement points at all. That is the same fence
// RegisterPEP puts in front of the in-process planes.
func (c *Catalog) AdmitExternalPEP(p PEPRecord) (ExternalPEP, Findings) {
	var out Findings
	if c == nil {
		return ExternalPEP{}, out.errorf(CodeUnknownRealm, p.ID,
			"an enforcement point cannot be admitted against a nil catalog")
	}
	out = append(out, p.Validate()...)
	if p.Realm == "" {
		out = out.errorf(CodeUnknownRealm, p.ID,
			"enforcement point %q declares no identity realm; a plane that authenticates as nothing cannot be scoped to by any policy",
			p.ID)
	} else if !c.RealmDeclared(p.Realm) {
		out = out.errorf(CodeUnknownRealm, p.ID,
			"enforcement point %q authenticates as realm %q, which this deployment does not declare",
			p.ID, p.Realm)
	}
	if err := out.Err(); err != nil {
		return ExternalPEP{}, out.Sorted()
	}
	stored := p.clone()
	stored.Capabilities = contract.SortCapabilities(p.Capabilities)
	return ExternalPEP{rec: stored, admitted: true}, nil
}
