// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package authoring

import (
	"encoding/json"
	"fmt"

	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/legacycompile"
	"axonflow/platform/decision/pdp"
)

// THE SHIPPED SYSTEM CORPUS, READ-ONLY (#3884)
//
// The platform's own controls are a system-root document this binary ships
// (pdp.SystemCorpusDocument) and no authoring surface may write (see
// system_authority.go). What an operator needs is to SEE them - which controls
// the platform enforces beneath every organization document, and how each one
// behaves when it cannot be evaluated - on the same typed-policies surface an
// organization authors through, rather than on the legacy page this model
// replaces.
//
// This is the one rendering both transports serve, so the orchestrator route and
// the portal cannot describe the corpus two ways.

// SystemCorpusView is the read-only rendering of the shipped system corpus.
type SystemCorpusView struct {
	Root    pdp.Root `json:"root"`
	Version int      `json:"version"`
	// Digest is the corpus digest this binary shipped - the trust anchor an
	// enforcing engine checks the system bundle against.
	Digest string `json:"digest"`
	// Authority names who may write this document: the release that built the
	// binary, and nobody on the deployment (SYSTEM_ROOT_SIGNING_AUTHORITY.md).
	Authority string `json:"authority"`
	// Controls lists each policy with the fields an operator reads first.
	Controls []SystemControl `json:"controls"`
	// AssuranceCounts is how many controls declare each class.
	AssuranceCounts map[pdp.AssuranceClass]int `json:"assurance_counts"`
	// Document is the system document itself, as the exact canonical bytes the
	// digest is computed over, so a client can render any field this view does
	// not summarize without a second endpoint and without a second encoding.
	Document json.RawMessage `json:"document"`
}

// SystemControl is one shipped control as an operator reads it.
type SystemControl struct {
	ID string `json:"id"`
	// Control is the corpus control this policy belongs to
	// (legacycompile.CorpusControlOf): the identifier an organization
	// document's system_controls names. The variants a control ships as, one
	// per enforcement scope's action, share it.
	Control string `json:"control"`
	// Dynamic reports a shipped dynamic control, which an organization may
	// disable but not re-action (PRD v11 §1.5, #4187).
	Dynamic     bool                  `json:"dynamic,omitempty"`
	Name        string                `json:"name,omitempty"`
	Authority   contract.Authority    `json:"authority"`
	Assurance   pdp.AssuranceClass    `json:"assurance,omitempty"`
	Mandatory   bool                  `json:"mandatory,omitempty"`
	Description string                `json:"description,omitempty"`
	Obligations []contract.Obligation `json:"obligations,omitempty"`
}

// ShippedCorpusAuthority is the Authority a SystemCorpusView names.
const ShippedCorpusAuthority = "shipped_corpus"

// ShippedSystemCorpusView renders the shipped system corpus.
//
// The document is serialized, never handed out: pdp.SystemCorpusDocument returns
// the memoised pointer the anchor's digest is computed from, and a transport
// has no business holding a writable reference to the platform's ceiling.
func ShippedSystemCorpusView() (*SystemCorpusView, error) {
	doc, err := pdp.SystemCorpusDocument()
	if err != nil {
		return nil, err
	}
	digest, err := pdp.SystemCorpusDigest()
	if err != nil {
		return nil, err
	}
	raw, err := contract.ExactJSON(doc)
	if err != nil {
		return nil, fmt.Errorf("authoring: rendering the shipped system corpus: %w", err)
	}
	view := &SystemCorpusView{
		Root: doc.Root, Version: doc.Version, Digest: digest, Authority: ShippedCorpusAuthority,
		Controls:        make([]SystemControl, 0, len(doc.Policies)),
		AssuranceCounts: map[pdp.AssuranceClass]int{},
		Document:        raw,
	}
	for _, p := range doc.Policies {
		control, _, _ := legacycompile.CorpusControlOf(p.ID)
		view.Controls = append(view.Controls, SystemControl{
			ID: p.ID, Control: control, Dynamic: DynamicSystemControl(control),
			Name: p.Name, Authority: p.Authority, Assurance: p.Assurance, Mandatory: p.Mandatory,
			Description: p.Description, Obligations: append([]contract.Obligation(nil), p.Obligations...),
		})
		if p.Assurance != "" {
			view.AssuranceCounts[p.Assurance]++
		}
	}
	return view, nil
}
