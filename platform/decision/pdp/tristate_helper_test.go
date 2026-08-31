package pdp

import (
	"context"
	"crypto/ed25519"
	"testing"
	"time"

	"axonflow/platform/decision/contract"
)

// helperProbeDocument builds a document whose every policy is a single leaf
// condition, so that a policy's verdict IS the helper's verdict for that leaf
// with nothing else able to decide it.
func helperProbeDocument(optional bool) *Document {
	handling := AbsenceHandling("")
	if optional {
		handling = AbsentIsNoMatch
	}
	num := Compare("resource.probe_number", OpLe, 100)
	str := Compare("resource.probe_string", OpEq, "match")
	arr := Member("resource.probe_array", "needle")
	if optional {
		num = num.HandlingAbsence(handling)
		str = str.HandlingAbsence(handling)
		arr = arr.HandlingAbsence(handling)
	}
	return &Document{
		Root: RootSystem, Version: 1,
		Attributes: []AttributeSchema{
			{Path: "resource.probe_number", Type: TypeNumber, Optional: optional},
			{Path: "resource.probe_string", Type: TypeString, Optional: optional},
			{Path: "resource.probe_array", Type: TypeArray, Optional: optional},
		},
		Policies: []Policy{
			{ID: "NUM", Authority: contract.AuthorityConstraint, Root: RootSystem,
				Scope: Scope{Organization: true}, Actions: ActionSelector{Any: true}, Where: num},
			{ID: "STR", Authority: contract.AuthorityConstraint, Root: RootSystem,
				Scope: Scope{Organization: true}, Actions: ActionSelector{Any: true}, Where: str},
			{ID: "ARR", Authority: contract.AuthorityConstraint, Root: RootSystem,
				Scope: Scope{Organization: true}, Actions: ActionSelector{Any: true}, Where: arr},
		},
	}
}

func helperProbeRuntime(t *testing.T, optional bool) *Runtime {
	t.Helper()
	d := helperProbeDocument(optional)
	b, err := BuildBundle(d)
	if err != nil {
		t.Fatalf("building the probe bundle: %v", err)
	}
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generating a key: %v", err)
	}
	if err := b.Sign("probe", priv); err != nil {
		t.Fatalf("signing: %v", err)
	}
	ts := NewTrustStore()
	ts.Authorize(RootSystem, "probe", pub)
	if err := ts.Verify(b); err != nil {
		t.Fatalf("verifying: %v", err)
	}
	rt, err := NewRuntime(context.Background(), b, DefaultLimits())
	if err != nil {
		t.Fatalf("preparing: %v", err)
	}
	return rt
}

// TestTriStateHelperTruthTable pins the platform-owned helper's state
// discipline exhaustively.
//
// The conformance corpus proves the discipline holds across a policy set. This
// proves it holds for EVERY combination of attribute state, declared type,
// declared optionality and comparison outcome, one leaf at a time, so that a
// branch added to the helper that resolves an unknown to a determinate verdict
// breaks a named row here rather than being caught only where some policy set
// happens to reach it.
func TestTriStateHelperTruthTable(t *testing.T) {
	now := time.Now()
	num, str, arr := "resource.probe_number", "resource.probe_string", "resource.probe_array"

	type want struct {
		verdict Verdict
		reason  contract.UnknownReason
	}
	cases := []struct {
		name     string
		optional bool
		attrs    contract.AttributeSet
		want     map[string]want
	}{
		{
			name: "resolved values on both sides of every comparison",
			attrs: contract.AttributeSet{
				num: contract.Known(50, contract.ProvResource, 0, now),
				str: contract.Known("match", contract.ProvResource, 0, now),
				arr: contract.Known([]any{"needle", "hay"}, contract.ProvResource, 0, now),
			},
			want: map[string]want{"NUM": {VerdictMatch, ""}, "STR": {VerdictMatch, ""}, "ARR": {VerdictMatch, ""}},
		},
		{
			name: "resolved values that do not satisfy the comparison",
			attrs: contract.AttributeSet{
				num: contract.Known(500, contract.ProvResource, 0, now),
				str: contract.Known("other", contract.ProvResource, 0, now),
				arr: contract.Known([]any{"hay"}, contract.ProvResource, 0, now),
			},
			want: map[string]want{"NUM": {VerdictNoMatch, ""}, "STR": {VerdictNoMatch, ""}, "ARR": {VerdictNoMatch, ""}},
		},
		{
			// The reason the whole model exists. An attribute the Policy
			// Information Point never produced must not read as a condition
			// that did not hold.
			name:  "attributes the Policy Information Point never produced",
			attrs: contract.AttributeSet{},
			want: map[string]want{
				"NUM": {VerdictUnknown, contract.ReasonNotSupplied},
				"STR": {VerdictUnknown, contract.ReasonNotSupplied},
				"ARR": {VerdictUnknown, contract.ReasonNotSupplied},
			},
		},
		{
			name: "a resolver failure",
			attrs: contract.AttributeSet{
				num: contract.Unknown(contract.ReasonResolutionFailed, contract.ProvResource, 0, now),
				str: contract.Unknown(contract.ReasonResolutionFailed, contract.ProvResource, 0, now),
				arr: contract.Unknown(contract.ReasonResolutionFailed, contract.ProvResource, 0, now),
			},
			want: map[string]want{
				"NUM": {VerdictUnknown, contract.ReasonResolutionFailed},
				"STR": {VerdictUnknown, contract.ReasonResolutionFailed},
				"ARR": {VerdictUnknown, contract.ReasonResolutionFailed},
			},
		},
		{
			// A value of the wrong declared type is classified BEFORE it is
			// compared, so it becomes a tagged unknown rather than a built-in
			// error that aborts the whole evaluation.
			name: "values of the wrong declared type",
			attrs: contract.AttributeSet{
				num: contract.Known("fifty", contract.ProvResource, 0, now),
				str: contract.Known(50, contract.ProvResource, 0, now),
				arr: contract.Known("needle", contract.ProvResource, 0, now),
			},
			want: map[string]want{
				"NUM": {VerdictUnknown, contract.ReasonSchemaMismatch},
				"STR": {VerdictUnknown, contract.ReasonSchemaMismatch},
				"ARR": {VerdictUnknown, contract.ReasonSchemaMismatch},
			},
		},
		{
			// Absence of an attribute the schema declares REQUIRED is a data
			// defect, not evidence that the condition does not hold.
			name: "authoritative absence where the schema declares the attribute required",
			attrs: contract.AttributeSet{
				num: contract.Absent(contract.ProvResource, 0, now),
				str: contract.Absent(contract.ProvResource, 0, now),
				arr: contract.Absent(contract.ProvResource, 0, now),
			},
			want: map[string]want{
				"NUM": {VerdictUnknown, contract.ReasonRequiredAbsent},
				"STR": {VerdictUnknown, contract.ReasonRequiredAbsent},
				"ARR": {VerdictUnknown, contract.ReasonRequiredAbsent},
			},
		},
		{
			// And absence where the schema marks it optional AND the policy
			// declared what absence means is an ordinary non-match. Both
			// conjuncts are required, which is what the previous row shows.
			name:     "authoritative absence where the policy declared what absence means",
			optional: true,
			attrs: contract.AttributeSet{
				num: contract.Absent(contract.ProvResource, 0, now),
				str: contract.Absent(contract.ProvResource, 0, now),
				arr: contract.Absent(contract.ProvResource, 0, now),
			},
			want: map[string]want{"NUM": {VerdictNoMatch, ""}, "STR": {VerdictNoMatch, ""}, "ARR": {VerdictNoMatch, ""}},
		},
		{
			// Optionality does not weaken the unknown case: an optional
			// attribute that could not be RESOLVED is still unknown, because
			// the schema said it may be absent, not that it may be unreadable.
			name:     "an optional attribute that could not be resolved",
			optional: true,
			attrs: contract.AttributeSet{
				num: contract.Unknown(contract.ReasonStale, contract.ProvResource, 0, now),
				str: contract.Unknown(contract.ReasonStale, contract.ProvResource, 0, now),
				arr: contract.Unknown(contract.ReasonStale, contract.ProvResource, 0, now),
			},
			want: map[string]want{
				"NUM": {VerdictUnknown, contract.ReasonStale},
				"STR": {VerdictUnknown, contract.ReasonStale},
				"ARR": {VerdictUnknown, contract.ReasonStale},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rt := helperProbeRuntime(t, tc.optional)
			res, err := rt.Eval(context.Background(), tc.attrs)
			if err != nil {
				t.Fatalf("evaluating: %v", err)
			}
			for id, w := range tc.want {
				got := res.Outcomes[id]
				if got.Verdict != w.verdict {
					t.Errorf("policy %s returned %s, expected %s (causes %v)", id, got.Verdict, w.verdict, got.Causes)
					continue
				}
				if w.reason == "" {
					if len(got.Causes) != 0 {
						t.Errorf("policy %s is determinate but reports causes %v", id, got.Causes)
					}
					continue
				}
				if len(got.Causes) == 0 || got.Causes[0].Reason != w.reason {
					t.Errorf("policy %s is unknown with causes %v, expected reason %q", id, got.Causes, w.reason)
				}
			}
		})
	}
}

// TestTriStateHelperKleeneTable pins the connectives.
//
// The load-bearing cell is a known-false conjunct with an unavailable one
// yielding FALSE. Short-circuiting there is sound and removes a great deal of
// spurious indeterminacy during a partial outage; getting it wrong in the other
// direction, an unknown conjunct swallowing a known-false one, would turn every
// dependency blip into an error on requests that were already settled.
func TestTriStateHelperKleeneTable(t *testing.T) {
	now := time.Now()
	num, str := "resource.probe_number", "resource.probe_string"
	d := &Document{
		Root: RootSystem, Version: 1,
		Attributes: []AttributeSchema{
			{Path: num, Type: TypeNumber},
			{Path: str, Type: TypeString},
		},
		Policies: []Policy{
			{ID: "AND", Authority: contract.AuthorityConstraint, Root: RootSystem,
				Scope: Scope{Organization: true}, Actions: ActionSelector{Any: true},
				Where: And(Compare(num, OpLe, 100), Compare(str, OpEq, "match"))},
			{ID: "OR", Authority: contract.AuthorityConstraint, Root: RootSystem,
				Scope: Scope{Organization: true}, Actions: ActionSelector{Any: true},
				Where: Or(Compare(num, OpLe, 100), Compare(str, OpEq, "match"))},
			{ID: "NOT", Authority: contract.AuthorityConstraint, Root: RootSystem,
				Scope: Scope{Organization: true}, Actions: ActionSelector{Any: true},
				Where: Not(Compare(num, OpLe, 100))},
		},
	}
	b, err := BuildBundle(d)
	if err != nil {
		t.Fatalf("building: %v", err)
	}
	pub, priv, _ := ed25519.GenerateKey(nil)
	if err := b.Sign("k", priv); err != nil {
		t.Fatalf("signing: %v", err)
	}
	ts := NewTrustStore()
	ts.Authorize(RootSystem, "k", pub)
	rt, err := NewRuntime(context.Background(), b, DefaultLimits())
	if err != nil {
		t.Fatalf("preparing: %v", err)
	}

	known := func(v any, path string) contract.Attribute { return contract.Known(v, contract.ProvResource, 0, now) }
	unknown := contract.Unknown(contract.ReasonResolutionFailed, contract.ProvResource, 0, now)

	rows := []struct {
		name          string
		numAttr       contract.Attribute
		strAttr       contract.Attribute
		and, or, not_ Verdict
	}{
		{"true and true", known(50, num), known("match", str), VerdictMatch, VerdictMatch, VerdictNoMatch},
		{"true and false", known(50, num), known("other", str), VerdictNoMatch, VerdictMatch, VerdictNoMatch},
		{"false and false", known(500, num), known("other", str), VerdictNoMatch, VerdictNoMatch, VerdictMatch},
		{"true and unknown", known(50, num), unknown, VerdictUnknown, VerdictMatch, VerdictNoMatch},
		// The cell that earns its keep: a determinately false conjunct settles
		// the conjunction even though the other term is unavailable.
		{"false and unknown", known(500, num), unknown, VerdictNoMatch, VerdictUnknown, VerdictMatch},
		{"unknown and unknown", unknown, unknown, VerdictUnknown, VerdictUnknown, VerdictUnknown},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			res, err := rt.Eval(context.Background(), contract.AttributeSet{num: r.numAttr, str: r.strAttr})
			if err != nil {
				t.Fatalf("evaluating: %v", err)
			}
			for id, want := range map[string]Verdict{"AND": r.and, "OR": r.or, "NOT": r.not_} {
				if got := res.Outcomes[id].Verdict; got != want {
					t.Errorf("%s returned %s, expected %s", id, got, want)
				}
			}
		})
	}
}
