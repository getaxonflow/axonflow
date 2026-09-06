// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package replay

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"sort"
	"time"

	"axonflow/platform/decision/contract"
)

// Result is one replayed record.
type Result struct {
	// CaseID is the record's identifier.
	CaseID string
	// Decision is what the pinned artifacts produced for the pinned input.
	Decision *contract.Decision
	// Verified is true when the record carried an expected decision and the
	// replay reproduced it. It is false when the record carried none, so a
	// caller can never read "no expectation" as "verified".
	Verified bool
	// Differences is empty when Verified, and names every field that differs
	// otherwise.
	Differences []string
}

// Replay reproduces one record against one environment.
//
// The order is deliberate: pins first, then activation, then evaluation. A
// mismatched pin must refuse before the engine is built, so that an operator
// holding the wrong artifact gets "these are not the artifacts your decision
// was made against" rather than a decision.
func Replay(ctx context.Context, env *Environment, rec *Record) (*Result, error) {
	if err := rec.Validate(); err != nil {
		return nil, err
	}
	if err := env.Validate(); err != nil {
		return nil, err
	}
	if err := CheckPins(env, rec); err != nil {
		return nil, err
	}
	engine, err := env.Engine(ctx)
	if err != nil {
		return nil, err
	}
	decision, err := engine.Decide(ctx, rec.Request)
	if err != nil {
		return nil, fmt.Errorf("replay: record %q could not be decided: %w", rec.CaseID, err)
	}
	res := &Result{CaseID: rec.CaseID, Decision: decision}
	if rec.Expected == nil {
		return res, nil
	}
	res.Differences = Diff(rec.Expected, decision)
	res.Verified = len(res.Differences) == 0
	return res, nil
}

// Diff names every way two decisions differ, in a fixed order.
//
// Field by field rather than one digest comparison, because "the digests
// differ" is useless in an incident and "the reason code moved from
// explicit_constraint to unknown_constraint" is the whole answer. The digest
// comparison happens anyway, as the last entry, so a field this function does
// not know about cannot make two different decisions compare equal - which is
// the failure a hand-written comparison normally has.
func Diff(want, got *contract.Decision) []string {
	var out []string
	if want == nil || got == nil {
		if want != got {
			return []string{fmt.Sprintf("one decision is nil: want %v, got %v", want != nil, got != nil)}
		}
		return nil
	}
	cmp := func(field string, a, b any) {
		if !reflect.DeepEqual(a, b) {
			out = append(out, fmt.Sprintf("%s: want %v, got %v", field, a, b))
		}
	}
	cmp("decision_id", want.DecisionID, got.DecisionID)
	cmp("request_id", want.RequestID, got.RequestID)
	cmp("authorization", want.Authorization, got.Authorization)
	cmp("state", want.State, got.State)
	cmp("reason", want.Reason, got.Reason)
	cmp("obligations", obligationKeys(want), obligationKeys(got))
	cmp("approval", approvalKeys(want), approvalKeys(got))
	cmp("determining", want.Determining, got.Determining)
	cmp("snapshot", want.Snapshot, got.Snapshot)

	// The catch-all. A field added to contract.Decision that no line above
	// compares would otherwise be invisible here for ever, and this is the
	// place a reviewer cannot be relied on to notice the omission.
	wd, werr := contract.ExactDigest(want)
	gd, gerr := contract.ExactDigest(got)
	switch {
	case werr != nil || gerr != nil:
		out = append(out, fmt.Sprintf("the decisions could not be digested for comparison: %v / %v", werr, gerr))
	case wd != gd && len(out) == 0:
		out = append(out, fmt.Sprintf(
			"the decisions digest differently (%s vs %s) although every named field agrees; "+
				"a decision field exists that Diff does not compare", wd, gd))
	}
	return out
}

func obligationKeys(d *contract.Decision) []string {
	out := make([]string, 0, len(d.Obligations))
	for _, o := range d.Obligations {
		key := string(o.Type)
		if o.Target != "" {
			key += "@" + o.Target
		}
		key += fmt.Sprintf("/v%d", o.SchemaVersion)
		params := make([]string, 0, len(o.Params))
		for k, v := range o.Params {
			params = append(params, k+"="+v)
		}
		sort.Strings(params)
		for _, p := range params {
			key += ";" + p
		}
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}

func approvalKeys(d *contract.Decision) []string {
	if d.Approval == nil {
		return nil
	}
	out := make([]string, 0, len(d.Approval.AllOf))
	for _, c := range d.Approval.AllOf {
		names := make([]string, 0, len(c.Eligible))
		for _, e := range c.Eligible {
			names = append(names, e.String())
		}
		sort.Strings(names)
		key := fmt.Sprintf("%d of", c.Quorum)
		for _, n := range names {
			key += " " + n
		}
		out = append(out, key)
	}
	sort.Strings(out)
	// The challenge lifetime and the separation-of-duties flag are part of the
	// requirement, not decoration around it: an expiry stamped from the wall
	// clock instead of from the evaluation instant makes a decision
	// irreproducible, and it moves NO clause. Without these two the catch-all
	// digest comparison is the only thing that sees it, and "the digests
	// differ" is not an answer anyone can act on.
	out = append(out,
		fmt.Sprintf("expires_at=%s", d.Approval.ExpiresAt.UTC().Format(time.RFC3339Nano)),
		fmt.Sprintf("separation_of_duties=%t", d.Approval.SeparationOfDuties))
	return out
}

// LoadEnvironment reads an environment artifact.
func LoadEnvironment(path string) (*Environment, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("replay: reading the environment: %w", err)
	}
	var env Environment
	dec := json.NewDecoder(bytes.NewReader(raw))
	// An unknown field is a decision input this build does not understand.
	// Ignoring it would mean replaying against an environment that is not the
	// one the file describes.
	dec.DisallowUnknownFields()
	if err := dec.Decode(&env); err != nil {
		return nil, fmt.Errorf("replay: decoding the environment %s: %w", path, err)
	}
	if err := env.Validate(); err != nil {
		return nil, err
	}
	return &env, nil
}

// LoadRecord reads one decision record.
func LoadRecord(path string) (*Record, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("replay: reading the record: %w", err)
	}
	var rec Record
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&rec); err != nil {
		return nil, fmt.Errorf("replay: decoding the record %s: %w", path, err)
	}
	if err := rec.Validate(); err != nil {
		return nil, err
	}
	return &rec, nil
}
