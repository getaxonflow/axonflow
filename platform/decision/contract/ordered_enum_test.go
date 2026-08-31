package contract

import "testing"

// orderedEnum is one map from a declared enumeration to a rank, together with
// the way the package is supposed to read it.
//
// Every one of these is a place where an out-of-range key would otherwise
// return the ZERO rank, and in each case the zero rank is a meaningful position
// in the order rather than a sentinel. Reading such a map bare hands an
// undeclared value the rank at one end of the scale, which is the permissive
// end for two of the three, and does it silently.
type orderedEnum struct {
	name string
	// declared is the enumeration in its documented order.
	declared []string
	// rank reports a value's position and whether it is declared at all.
	rank func(string) (int, bool)
	// declaredInRankOrder is true only where the accessor documents its list
	// as running weakest to strongest, so the ranks must follow it.
	//
	// It is false for the other two and that is not an omission: AllAuthorizations
	// returns a DECLARATION order and AllObligationTypes returns an
	// ALPHABETICAL one, so asserting monotonicity over either would be
	// asserting a property the list never claimed. Getting that wrong is the
	// same mistake as the defect this file exists for, made in a test instead
	// of in a comparison.
	declaredInRankOrder bool
}

func orderedEnums() []orderedEnum {
	var deliveries []string
	for _, d := range AllDeliveries() {
		deliveries = append(deliveries, string(d))
	}
	var assurances []string
	for _, a := range AllAssurances() {
		assurances = append(assurances, string(a))
	}
	var authorizations []string
	for _, a := range AllAuthorizations() {
		authorizations = append(authorizations, string(a))
	}
	var disclosures []string
	for _, o := range AllObligationTypes() {
		if _, ranked := disclosureRank[o]; ranked {
			disclosures = append(disclosures, string(o))
		}
	}
	return []orderedEnum{
		{"delivery guarantees", deliveries, func(v string) (int, bool) { return Delivery(v).Strength() }, true},
		{"assurance levels", assurances, func(v string) (int, bool) {
			r, ok := assuranceStrength[Assurance(v)]
			return r, ok
		}, true},
		{"authorization precedence", authorizations, func(v string) (int, bool) {
			r, ok := precedence[Authorization(v)]
			return r, ok
		}, false},
		{"disclosure ranks", disclosures, func(v string) (int, bool) {
			r, ok := disclosureRank[ObligationType(v)]
			return r, ok
		}, false},
	}
}

// TestOrderedEnumsRefuseAnOutOfRangeValue is the class guard.
//
// It exists because a single enum value over the range reinstated a permissive
// default in a comparison whose whole job was to keep the strongest: an
// undeclared delivery guarantee ranked zero, tied with the weakest declared
// one, so whichever obligation arrived first won and an enforcement point was
// handed a guarantee nothing had validated.
//
// The rule this pins is not "validate delivery". It is that a value used for
// ORDERING must have its membership checked before it is ordered, while a value
// used only for EQUALITY need not: an unrecognised value simply matches
// nothing, whereas a comparison is itself what turns an unrecognised value into
// an answer, and the answer it reaches for is at one end of the scale. That is
// why the rank maps below need this and the package's many equality-only
// enumerations genuinely do not.
//
// WHAT THIS GUARD CANNOT SEE, stated so nobody assumes otherwise: it enumerates
// rank MAPS. An ordered enumeration implemented as an integer type with iota
// and compared directly with < has no map to enumerate, and an out-of-range
// value there fails at the OTHER end, outranking every declared value instead
// of sorting below them. The identity-plane workstream hit exactly that in its
// own tree. There is no such type in this package today, which is the only
// reason this guard is sufficient here; adding one means extending this test
// rather than trusting it.
func TestOrderedEnumsRefuseAnOutOfRangeValue(t *testing.T) {
	for _, e := range orderedEnums() {
		if len(e.declared) < 2 {
			t.Errorf("%s: an order over %d values is not an order", e.name, len(e.declared))
			continue
		}
		seen := map[int]string{}
		previous, havePrevious := 0, false
		for _, v := range e.declared {
			r, ok := e.rank(v)
			if !ok {
				t.Errorf("%s: the declared value %q has no rank", e.name, v)
				continue
			}
			if prev, dup := seen[r]; dup {
				t.Errorf("%s: %q and %q share rank %d, so the order cannot distinguish them", e.name, prev, v, r)
			}
			// Where the accessor documents its list as weakest first, the
			// ranks must follow it. Nothing else checks that, so reordering
			// the list without reordering the map would leave every other
			// assertion here passing while the documented order became false.
			if e.declaredInRankOrder && havePrevious && r <= previous {
				t.Errorf("%s: %q ranks %d, not above the %d of the value declared before it; "+
					"the enumeration is documented in order and the ranks no longer follow it", e.name, v, r, previous)
			}
			previous, havePrevious = r, true
			seen[r] = v
		}
		// What makes a bare read unsafe is that the zero a missing key returns
		// sits AT OR BEYOND one end of the order, so an undeclared value is
		// silently sorted to an extreme rather than rejected. It is asserted as
		// "at or below the minimum declared rank" rather than as "rank 0 is
		// occupied", which was the first shape of this check and was wrong:
		// assurance levels start at 1, so nothing holds rank 0 there and the
		// hazard is present anyway.
		//
		// The DIRECTION differs per enumeration and is worth knowing when
		// reading a bare read in review. For delivery, assurance and disclosure
		// the zero end is the permissive one, so a bare read fails open. For
		// the authorization precedence the zero end is Deny, so a bare read
		// fails closed, silently. Neither is acceptable, and only one of them
		// would ever be noticed.
		minRank := 0
		first := true
		for r := range seen {
			if first || r < minRank {
				minRank, first = r, false
			}
		}
		if minRank < 0 {
			t.Errorf("%s: the minimum declared rank is %d, below the zero a missing key returns, so an undeclared value would sort in the MIDDLE of the order", e.name, minRank)
		}
		for _, bad := range []string{"", "invented", e.declared[len(e.declared)-1] + "_v2", "DURABLE"} {
			if _, ok := e.rank(bad); ok {
				t.Errorf("%s: the undeclared value %q was given a rank", e.name, bad)
			}
		}
	}
}

// TestAnUndeclaredDeliveryGuaranteeIsRefused pins the specific defect end to
// end, at both the boundary and the comparison.
func TestAnUndeclaredDeliveryGuaranteeIsRefused(t *testing.T) {
	audit := func(delivery string) Obligation {
		return Obligation{Type: ObImmutableAudit, Mandatory: true, SourcePolicy: "R-" + delivery, SchemaVersion: 1,
			Params: map[string]string{"channel": "audit", "level": "high", "delivery": delivery}}
	}
	pep := &PEPProfile{ID: "p", Capabilities: []Capability{{Type: ObImmutableAudit, Version: 1}}}

	// The control: two declared guarantees compose, and the STRONGEST survives,
	// in either input order.
	for _, order := range [][]Obligation{
		{audit(string(DeliveryBestEffort)), audit(string(DeliveryDurable))},
		{audit(string(DeliveryDurable)), audit(string(DeliveryBestEffort))},
	} {
		got := ComposeObligations(ComposeInput{Obligations: order, PEP: pep})
		if got.Denied {
			t.Fatalf("two declared guarantees did not compose: %s", got.Detail)
		}
		if len(got.Obligations) != 1 {
			t.Fatalf("expected one merged audit obligation, got %+v", got.Obligations)
		}
		if d := got.Obligations[0].Params["delivery"]; d != string(DeliveryDurable) {
			t.Errorf("the merged obligation requires %q, expected the strongest guarantee %q", d, DeliveryDurable)
		}
	}

	// The defect: an undeclared guarantee used to rank zero, tie with the
	// weakest, and win by arriving first.
	for name, order := range map[string][]Obligation{
		"the undeclared guarantee first":  {audit("durabl"), audit(string(DeliveryBestEffort))},
		"the undeclared guarantee second": {audit(string(DeliveryBestEffort)), audit("durabl")},
	} {
		got := ComposeObligations(ComposeInput{Obligations: order, PEP: pep})
		if !got.Denied {
			t.Errorf("%s: composed to a permit carrying %+v; an enforcement point would be handed a guarantee nothing validated",
				name, got.Obligations)
		}
	}

	// And it is refused at the boundary too, so the comparison is not the only
	// thing standing between an undeclared value and an enforcement point.
	if err := audit("durabl").Validate(); err == nil {
		t.Error("an obligation carrying an undeclared delivery guarantee validated")
	}
	// A family that reads no delivery guarantee must not carry the parameter,
	// because a parameter nothing reads is an instruction silently ignored.
	stray := Obligation{Type: ObFieldRedact, Target: "response.ssn", Mandatory: true,
		SourcePolicy: "R", SchemaVersion: 1, Params: map[string]string{"delivery": string(DeliveryDurable)}}
	if err := stray.Validate(); err == nil {
		t.Error("a disclosure transform carrying a delivery guarantee validated")
	}
}
