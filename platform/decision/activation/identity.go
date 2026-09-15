// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package activation

import "axonflow/platform/decision/contract"

// PolicySource says whose an activated policy is, as the wire and the audit
// row name it beside its identifier (PRD v11 §1.14).
type PolicySource string

const (
	// SourceShipped is a control the release ships: the system corpus, the
	// organization template, the deployment's baseline permission pack, or a
	// recorded override's replacement of a shipped control (#4045). Every
	// shipped document is version 1, so a shipped control carries no version of
	// its own: the bundle digest a decision already names identifies it.
	SourceShipped PolicySource = "shipped"
	// SourceOrganization is a policy of the organization's own published
	// document.
	SourceOrganization PolicySource = "organization"
	// SourcePack is a control of an installed policy pack (PRD v11 §1.9).
	SourcePack PolicySource = "pack"
)

// PolicyIdentity is one activated policy as a decision names it: its
// identifier, its operator-facing name, whose it is, and the version it was
// published at.
type PolicyIdentity struct {
	ID string
	// Name is the policy's own display name, empty when it declares none. An
	// identifier is never presented as a name.
	Name   string
	Source PolicySource
	// Version is the organization document's published version for its own
	// policies and the pack's version for a pack's; zero for a shipped control.
	Version int
}

// policyOrigin is where an organization-root policy that is not shipped came
// from, recorded as Activate composes the root, where it is known.
type policyOrigin struct {
	source  PolicySource
	version int
}

// Identity names a policy this engine activated. ok is false for an id it did
// not activate, which is named by its identifier alone.
func (a *Activation) Identity(id string) (PolicyIdentity, bool) {
	p, ok := a.Policy(id)
	if !ok {
		return PolicyIdentity{ID: id}, false
	}
	origin, recorded := a.origins[id]
	if !recorded {
		origin = policyOrigin{source: SourceShipped}
	}
	return PolicyIdentity{ID: id, Name: p.Name, Source: origin.source, Version: origin.version}, true
}

// ActionName is the operator-facing name of the registered action local, as
// the deployment vocabulary this engine admits against labels it (#3789);
// empty when the vocabulary carries no label for it.
func (a *Activation) ActionName(local string) string {
	if a == nil || a.Snapshot == nil || a.Snapshot.Catalog == nil {
		return ""
	}
	action, err := contract.ParseID(contract.KindAction, "Action::"+local)
	if err != nil {
		return ""
	}
	return a.Snapshot.Catalog.ActionLabels[action.String()].DisplayName
}
