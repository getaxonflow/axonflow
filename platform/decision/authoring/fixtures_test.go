package authoring

import (
	"crypto/ed25519"
	"testing"
	"time"

	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/pdp"
)

// The fixture world below is small on purpose and complete on purpose. Every
// check in the save-time set has to be reachable from it by ONE targeted edit,
// so that a rejection test says "this document is the good one with this one
// thing wrong" rather than "here is a bespoke document that fails". A rejection
// test built on its own bespoke document proves the checker fires on that
// document and says nothing about whether the rule is the rule.

const (
	actionRefund = "Action::refund.issue"
	actionTicket = "Action::ticket.read"
	actionExport = "Action::report.export"

	groupFinance  = "Group::acme:finance"
	groupIncident = "Group::acme:incident"
	groupBots     = "Group::bots:automation"
	groupFlat     = "Group::flat:reviewers"

	principalAlice = "Principal::acme:alice"
	principalBob   = "Principal::acme:bob"
	principalCarol = "Principal::acme:carol"
)

func gid(t *testing.T, s string) contract.ID {
	t.Helper()
	return contract.MustParseID(contract.KindGroup, s)
}

func pid(t *testing.T, s string) contract.ID {
	t.Helper()
	return contract.MustParseID(contract.KindPrincipal, s)
}

func aid(t *testing.T, s string) contract.ID {
	t.Helper()
	return contract.MustParseID(contract.KindAction, s)
}

// baseCatalog is the registry every test starts from.
func baseCatalog(t *testing.T) *Catalog {
	t.Helper()
	return &Catalog{
		Actions: map[string]pdp.ActionEntry{
			actionRefund: {
				ID:                 aid(t, actionRefund),
				Tags:               []string{"money", "irreversible"},
				MaxDelegationDepth: 3,
				Arguments: map[string]pdp.ValueType{
					"amount_cents": pdp.TypeNumber,
					"note":         pdp.TypeString,
				},
				RequiredArguments: []string{"amount_cents"},
				PayloadLeaves:     []string{"refund.id", "refund.customer.email"},
				Irreversible:      true,
			},
			actionTicket: {
				ID:                 aid(t, actionTicket),
				Tags:               []string{"read"},
				MaxDelegationDepth: 3,
				Arguments: map[string]pdp.ValueType{
					"amount_cents": pdp.TypeNumber,
					"note":         pdp.TypeString,
				},
				PayloadLeaves: []string{"ticket.summary", "ticket.reporter.email"},
			},
			actionExport: {
				ID:                 aid(t, actionExport),
				Tags:               []string{"pii_egress"},
				MaxDelegationDepth: 2,
				Arguments: map[string]pdp.ValueType{
					"amount_cents": pdp.TypeNumber,
					"note":         pdp.TypeString,
				},
				PayloadLeaves: []string{"report.total", "report.customer.email"},
				DataEgress:    true,
			},
		},
		Realms: map[string]RealmEntry{
			"acme": {Interactive: true, HasGroupGraph: true},
			"bots": {Interactive: false, HasGroupGraph: true},
			"flat": {Interactive: true, HasGroupGraph: false},
		},
		ResourceTypes: map[string]ResourceType{
			"Ticket": {
				Type:          "Ticket",
				Ancestors:     []string{"project", "space"},
				Recursive:     true,
				PayloadLeaves: []string{"ticket.summary"},
			},
		},
	}
}

// catalogWithFlatType adds a second resource type whose hierarchy declares
// fewer levels and is not recursive, which is what makes LEVEL_NOT_DECLARED and
// SCOPE_REQUIRES_RECURSION reachable: both rules require the property to hold
// for EVERY reachable type, and a one-type registry can never fail them.
func catalogWithFlatType(t *testing.T) *Catalog {
	c := baseCatalog(t)
	c.ResourceTypes["Ledger"] = ResourceType{
		Type:          "Ledger",
		Ancestors:     []string{"project"},
		Recursive:     false,
		PayloadLeaves: []string{"ledger.total"},
	}
	return c
}

func baseAttributes() []pdp.AttributeSchema {
	return []pdp.AttributeSchema{
		{Path: pdp.PrincipalIDPath, Type: pdp.TypeString},
		{Path: pdp.PrincipalGroupsPath, Type: pdp.TypeArray},
		{Path: pdp.ActionIDPath, Type: pdp.TypeString},
		{Path: pdp.ActionTagsPath, Type: pdp.TypeArray},
		{Path: pdp.ResourceAncestorsPath, Type: pdp.TypeArray},
		{Path: "args.amount_cents", Type: pdp.TypeNumber},
		{Path: "args.note", Type: pdp.TypeString, Optional: true},
		{Path: "resource.project.owner", Type: pdp.TypeString},
		{Path: "signal.pii_score", Type: pdp.TypeNumber},
		{Path: "state.spend_cents", Type: pdp.TypeNumber},
	}
}

func auditObligation(source string) contract.Obligation {
	return contract.Obligation{
		Type:          contract.ObImmutableAudit,
		Params:        map[string]string{"level": "high", "delivery": string(contract.DeliveryDurable)},
		Mandatory:     true,
		SourcePolicy:  source,
		SchemaVersion: 1,
	}
}

func redactObligation(source, target string, params map[string]string) contract.Obligation {
	return contract.Obligation{
		Type:          contract.ObFieldRedact,
		Target:        target,
		Params:        params,
		Mandatory:     true,
		SourcePolicy:  source,
		SchemaVersion: 1,
	}
}

// basePolicy returns the clean policy set. Tests mutate one policy and expect
// exactly one new code.
func basePolicies(t *testing.T) []pdp.Policy {
	t.Helper()
	return []pdp.Policy{
		{
			ID:        "perm.refund",
			Authority: contract.AuthorityPermission,
			Root:      pdp.RootSystem,
			Scope:     pdp.Scope{Groups: []contract.ID{gid(t, groupFinance)}},
			Actions:   pdp.ActionSelector{Actions: []contract.ID{aid(t, actionRefund)}},
			Where:     pdp.Compare("args.amount_cents", pdp.OpLe, 500000),
		},
		{
			ID:           "con.big",
			Authority:    contract.AuthorityConstraint,
			Root:         pdp.RootSystem,
			Scope:        pdp.Scope{Organization: true},
			Actions:      pdp.ActionSelector{Actions: []contract.ID{aid(t, actionRefund)}},
			Where:        pdp.Compare("args.amount_cents", pdp.OpGt, 1000000),
			PierceableBy: []contract.ID{gid(t, groupIncident)},
		},
		{
			ID:          "req.audit",
			Authority:   contract.AuthorityRequirement,
			Root:        pdp.RootSystem,
			Scope:       pdp.Scope{Organization: true},
			Actions:     pdp.ActionSelector{Any: true},
			Where:       pdp.True(),
			Mandatory:   true,
			Obligations: []contract.Obligation{auditObligation("req.audit")},
		},
		{
			ID:        "insp.pii",
			Authority: contract.AuthorityInspection,
			Root:      pdp.RootSystem,
			Scope:     pdp.Scope{Organization: true},
			Actions:   pdp.ActionSelector{Actions: []contract.ID{aid(t, actionExport)}},
			Where:     pdp.Compare("signal.pii_score", pdp.OpGe, 0.8),
			Obligations: []contract.Obligation{
				redactObligation("insp.pii", "report.customer.email", map[string]string{"style": "fixed"}),
			},
		},
		{
			ID:        "con.owner",
			Authority: contract.AuthorityConstraint,
			Root:      pdp.RootSystem,
			Scope:     pdp.Scope{Organization: true},
			Actions:   pdp.ActionSelector{Actions: []contract.ID{aid(t, actionTicket)}},
			Where:     pdp.Not(pdp.AttrCompare("resource.project.owner", pdp.OpEq, pdp.PrincipalIDPath)),
		},
	}
}

func baseMetadata(t *testing.T) Metadata {
	t.Helper()
	return Metadata{
		DocumentID: "system-baseline",
		Title:      "System baseline policy",
		Author:     pid(t, principalAlice),
	}
}

func basePDPDocument(t *testing.T) pdp.Document {
	t.Helper()
	return pdp.Document{
		Root:       pdp.RootSystem,
		Version:    1,
		Attributes: baseAttributes(),
		Policies:   basePolicies(t),
	}
}

// baseDocument builds the clean document. It fails the test if the clean
// document is rejected, because a rejection suite whose baseline is already
// broken reports every rule as firing and proves none of them.
func baseDocument(t *testing.T) *Document {
	t.Helper()
	cat := baseCatalog(t)
	d, findings, err := NewDocument(baseMetadata(t), basePDPDocument(t), cat)
	if err != nil {
		t.Fatalf("the baseline document must be clean, got: %v\nfindings: %v", err, findings)
	}
	if len(findings.Rejections()) != 0 {
		t.Fatalf("the baseline document must have no rejections, got %v", findings.Rejections())
	}
	return d
}

func known(v any, src contract.Provenance) contract.Attribute {
	return contract.Known(v, src, 1, time.Unix(1_700_000_000, 0).UTC())
}

// baseFixtures are the author-declared cases the gauntlet runs. They cover both
// a refund and an export so that every policy in the baseline is observed both
// matching and not matching by at least one case.
func baseFixtures() []Fixture {
	refund := contract.AttributeSet{
		pdp.PrincipalIDPath:      known(principalAlice, contract.ProvAuthentication),
		pdp.PrincipalGroupsPath:  known([]any{groupFinance}, contract.ProvDirectory),
		pdp.ActionIDPath:         known(actionRefund, contract.ProvPlatform),
		pdp.ActionTagsPath:       known([]any{"money", "irreversible"}, contract.ProvPlatform),
		"args.amount_cents":      known(json100k, contract.ProvCaller),
		"resource.project.owner": known("Principal::acme:bob", contract.ProvResource),
		"signal.pii_score":       known(json0, contract.ProvDetector),
	}
	export := contract.AttributeSet{
		pdp.PrincipalIDPath:      known(principalAlice, contract.ProvAuthentication),
		pdp.PrincipalGroupsPath:  known([]any{groupFinance}, contract.ProvDirectory),
		pdp.ActionIDPath:         known(actionExport, contract.ProvPlatform),
		pdp.ActionTagsPath:       known([]any{"pii_egress"}, contract.ProvPlatform),
		"args.amount_cents":      known(json100k, contract.ProvCaller),
		"resource.project.owner": known("Principal::acme:alice", contract.ProvResource),
		"signal.pii_score":       known(json09, contract.ProvDetector),
	}
	return []Fixture{
		{
			Name:       "refund below the cap",
			Attributes: refund,
			Expect: map[string]pdp.Verdict{
				"perm.refund": pdp.VerdictMatch,
				"con.big":     pdp.VerdictNoMatch,
				"req.audit":   pdp.VerdictMatch,
				"insp.pii":    pdp.VerdictNoMatch,
				"con.owner":   pdp.VerdictNoMatch,
			},
		},
		{
			Name:       "export with a high detector score",
			Attributes: export,
			Expect: map[string]pdp.Verdict{
				"perm.refund": pdp.VerdictNoMatch,
				"con.big":     pdp.VerdictNoMatch,
				"req.audit":   pdp.VerdictMatch,
				"insp.pii":    pdp.VerdictMatch,
				"con.owner":   pdp.VerdictNoMatch,
			},
		},
	}
}

// fixturesWithNote adds the optional caller-supplied note to both cases, for
// documents whose condition reads it. Without it the condition is UNKNOWN and
// the fixture would assert something about a policy the case never resolved.
func fixturesWithNote(note string) []Fixture {
	out := baseFixtures()
	for i := range out {
		out[i].Attributes["args.note"] = known(note, contract.ProvCaller)
	}
	return out
}

// Numeric fixture values are declared once so that a change to one is a change
// everywhere it is asserted.
var (
	json100k any = 100000
	json0    any = 0.0
	json09   any = 0.9
)

func testKeys(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	// A fixed seed, so a published artifact has a stable digest and a test can
	// assert on one. Randomness here would make every digest assertion a
	// tautology about whatever the run produced.
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	return priv.Public().(ed25519.PublicKey), priv
}

func otherKeys(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(200 - i)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	return priv.Public().(ed25519.PublicKey), priv
}

func systemTrust(t *testing.T) (*pdp.TrustStore, ed25519.PrivateKey) {
	t.Helper()
	pub, priv := testKeys(t)
	trust := pdp.NewTrustStore()
	trust.Authorize(pdp.RootSystem, "system-key-1", pub)
	return trust, priv
}

func publishOptions(t *testing.T, priv ed25519.PrivateKey) PublishOptions {
	t.Helper()
	return PublishOptions{
		Root:       pdp.RootSystem,
		KeyID:      "system-key-1",
		PrivateKey: priv,
		Approvers:  []contract.ID{pid(t, principalBob)},
		Fixtures:   baseFixtures(),
		Now:        time.Unix(1_700_000_100, 0).UTC(),
	}
}

// timeFixture is the fixed instant activation records are stamped with, so a
// history assertion is about the chain rather than about the clock.
func timeFixture() time.Time { return time.Unix(1_700_000_300, 0).UTC() }
