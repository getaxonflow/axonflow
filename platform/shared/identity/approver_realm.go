// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

// ADR-065 realm-side approver-pool checks (EX-46), consumed by the obligation
// and approval plane (#3551).
//
// Whether a subject can answer a question is a property of the REALM, not of
// the subject. Service accounts land in approver groups for automation reasons
// all the time, and a subject-by-subject guess about which principals are
// people is a guess the engine should never make. Declaring it on the realm
// keeps the engine out of that business entirely.
//
// THE SAME FACT IS CHECKED TWICE, AT TWO DIFFERENT TIMES, ON PURPOSE
//
//	ValidateApproverPool   authoring time. A policy naming a pool in a
//	                       non-interactive realm is REFUSED AT SAVE, so it
//	                       never becomes a live escalation.
//	ApproverPoolReachable  runtime. The same fact, re-checked, because a realm
//	                       can be reconfigured from interactive to
//	                       non-interactive AFTER a policy referencing it was
//	                       saved, and because a policy can arrive from an
//	                       import path that did not run the authoring check.
//
// The runtime check is not redundant with the authoring one. Without it, the
// escalation is issued, its eligible count is inflated by members who cannot
// answer, and it parks until on_timeout because nothing there can respond.
// Without the authoring check, that outcome is only discoverable in
// production, on a request that was going to be approved.
package identity

import (
	"fmt"
	"sort"
	"strings"
)

// ApproverPool is a set of realm-qualified principals eligible to answer an
// escalation. Members may be Group or individual subject principals.
type ApproverPool struct {
	// Name is the pool's operator-facing label. Never an identifier.
	Name string
	// Members are the realm-qualified eligible principals.
	Members []PrincipalID
}

// ValidateApproverPool refuses a pool that cannot answer, at authoring time.
//
// It returns an error naming EVERY offending member rather than the first,
// because an author fixing one at a time learns about the next only on the
// next save, and a pool assembled from several directories usually has all of
// its non-interactive members from one of them.
//
// A member whose realm is not declared is refused too, with UNKNOWN_REALM
// semantics: an author cannot name a pool in a directory this organization has
// not declared, and treating the miss as "assume it can answer" would be EX-47
// in the authoring path.
func ValidateApproverPool(reg *RealmRegistry, orgID string, pool ApproverPool) error {
	if reg == nil {
		return fmt.Errorf("identity: approver pool %q cannot be validated without a realm registry", pool.Name)
	}
	if strings.TrimSpace(orgID) == "" {
		return fmt.Errorf("identity: approver pool %q cannot be validated without an authenticated organization", pool.Name)
	}
	if len(pool.Members) == 0 {
		return fmt.Errorf("identity: approver pool %q has no members; an empty pool can never reach quorum", pool.Name)
	}

	var unknown, nonInteractive, disabled, malformed []string
	for _, m := range pool.Members {
		if err := m.Validate(); err != nil {
			malformed = append(malformed, fmt.Sprintf("%v", err))
			continue
		}
		realm, ok := reg.Lookup(orgID, m.Realm)
		if !ok {
			unknown = append(unknown, m.String())
			continue
		}
		if !realm.Enabled {
			disabled = append(disabled, m.String())
			continue
		}
		if !realm.CanAnswerApprovals() {
			nonInteractive = append(nonInteractive, m.String())
		}
	}

	var problems []string
	if len(malformed) > 0 {
		sort.Strings(malformed)
		problems = append(problems, fmt.Sprintf("malformed members: %s", strings.Join(malformed, "; ")))
	}
	if len(unknown) > 0 {
		sort.Strings(unknown)
		problems = append(problems, fmt.Sprintf("%s: members in undeclared realms: %s",
			ReasonUnknownRealm, strings.Join(unknown, ", ")))
	}
	if len(disabled) > 0 {
		sort.Strings(disabled)
		problems = append(problems, fmt.Sprintf("%s: members in disabled realms: %s",
			ReasonRealmDisabled, strings.Join(disabled, ", ")))
	}
	if len(nonInteractive) > 0 {
		sort.Strings(nonInteractive)
		problems = append(problems, fmt.Sprintf(
			"%s: members in realms that cannot be asked a question: %s",
			ReasonPoolNotInteractive, strings.Join(nonInteractive, ", ")))
	}
	if len(problems) == 0 {
		return nil
	}
	return fmt.Errorf("identity: approver pool %q is not answerable: %s", pool.Name, strings.Join(problems, " | "))
}

// InteractiveMembers returns the pool members that can actually answer, and
// the admission covering the pool as a whole.
//
// This is the runtime half of EX-46 and it is what an eligibility count must
// be taken over. Counting raw membership inflates the count with principals
// that cannot respond, and the escalation then parks until timeout.
//
// The admission is Deny(ESCALATION_UNREACHABLE) when no member can answer, and
// Accept otherwise. It is deliberately NOT Indeterminate: whether a realm is
// interactive is configuration this process already holds, so there is nothing
// unresolved about it.
//
// A member whose realm is undeclared or disabled is dropped from the eligible
// set rather than failing the whole pool. That is the conservative direction:
// dropping shrinks the eligible set, which can only make quorum harder to
// reach, never easier. The dropped members are named in the admission detail
// so the shrinkage is visible rather than silent.
func InteractiveMembers(reg *RealmRegistry, orgID string, pool ApproverPool) ([]PrincipalID, Admission) {
	if reg == nil {
		return nil, IndeterminateAdmission(ReasonUnknownRealm, fmt.Sprintf(
			"approver pool %q cannot be resolved without a realm registry", pool.Name))
	}
	if strings.TrimSpace(orgID) == "" {
		return nil, DenyAdmission(ReasonOrgBindingMismatch, fmt.Sprintf(
			"approver pool %q cannot be resolved without an authenticated organization", pool.Name))
	}

	var eligible, dropped []PrincipalID
	for _, m := range pool.Members {
		if err := m.Validate(); err != nil {
			dropped = append(dropped, m)
			continue
		}
		realm, ok := reg.Lookup(orgID, m.Realm)
		if !ok || !realm.Enabled || !realm.CanAnswerApprovals() {
			dropped = append(dropped, m)
			continue
		}
		eligible = append(eligible, m)
	}

	if len(eligible) == 0 {
		return nil, DenyAdmission(ReasonEscalationUnreachable, fmt.Sprintf(
			"approver pool %q has %d member(s) and none is in a declared, enabled, interactive realm",
			pool.Name, len(pool.Members)))
	}

	eligible = sortedPrincipals(eligible)
	if len(dropped) == 0 {
		return eligible, AcceptPoolAdmission(fmt.Sprintf(
			"approver pool %q: all %d member(s) can answer", pool.Name, len(eligible)))
	}
	names := make([]string, len(dropped))
	for i, d := range dropped {
		names[i] = d.String()
	}
	sort.Strings(names)
	return eligible, AcceptPoolAdmission(fmt.Sprintf(
		"approver pool %q: %d of %d members dropped as unable to answer: %s",
		pool.Name, len(dropped), len(pool.Members), strings.Join(names, ", ")))
}

// EligibleApprovers returns the pool members that can answer AND are not
// already in the requesting actor chain.
//
// Self-exclusion covers the WHOLE chain, not just its root. An agent acting
// for alice cannot approve alice's own request, and neither can alice: both
// appear in the chain, and separation of duties is about the request, not
// about which hop happens to be named as the requester.
//
// The interactive filter runs FIRST and the chain exclusion second. Running
// them the other way round gives the same set but a worse diagnostic: a pool
// emptied by self-exclusion and a pool emptied by an unanswerable realm need
// different remedies, and the caller can only tell them apart if the
// unanswerable case is reported before the exclusion happens.
func EligibleApprovers(reg *RealmRegistry, orgID string, pool ApproverPool, chain ActorChain) ([]PrincipalID, Admission) {
	interactive, adm := InteractiveMembers(reg, orgID, pool)
	if !adm.State.IsAdmitted() {
		return nil, adm
	}
	var out, excluded []PrincipalID
	for _, m := range interactive {
		if chain.Contains(m) {
			excluded = append(excluded, m)
			continue
		}
		out = append(out, m)
	}
	if len(out) == 0 {
		return nil, DenyAdmission(ReasonEscalationUnreachable, fmt.Sprintf(
			"approver pool %q has %d answerable member(s) and every one of them is in the requesting actor chain %s",
			pool.Name, len(interactive), chain))
	}
	if len(excluded) > 0 {
		// The admission that arrives here describes the INTERACTIVE set. After
		// self-exclusion it would otherwise still describe a set this function
		// is not returning, so it is rebuilt rather than passed through.
		names := make([]string, len(excluded))
		for i, e := range excluded {
			names[i] = e.String()
		}
		sort.Strings(names)
		adm = AcceptPoolAdmission(fmt.Sprintf(
			"%s; a further %d excluded as members of the requesting actor chain: %s",
			adm.Detail, len(excluded), strings.Join(names, ", ")))
	}
	return out, adm
}
