// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package authoring

import (
	"encoding/json"
	"fmt"

	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/pdp"
)

// A new organization draft starts from the shipped organization template (PRD
// v11 §1.5): the organization edits the template's rows directly, and a
// published document replaces the template, so a draft that started empty
// would stop every template control deciding. The editor seeds from this view.

// OrganizationTemplateView is the read-only rendering of the shipped
// organization template.
type OrganizationTemplateView struct {
	// ID names the template as a document: what an activation history records
	// once an organization withdraws its own (pdp.SystemCorpusOrganizationTemplateID).
	ID string `json:"id"`
	// Digest is the template digest this binary shipped.
	Digest string `json:"digest"`
	// Document is the template itself, as the exact canonical bytes the digest
	// is computed over: the organization-root policy document a draft copies.
	Document json.RawMessage `json:"document"`
}

// ShippedOrganizationTemplateView renders the shipped organization template.
func ShippedOrganizationTemplateView() (*OrganizationTemplateView, error) {
	doc, err := pdp.SystemCorpusOrganizationTemplate()
	if err != nil {
		return nil, err
	}
	digest, err := pdp.SystemCorpusOrganizationTemplateDigest()
	if err != nil {
		return nil, err
	}
	raw, err := contract.ExactJSON(doc)
	if err != nil {
		return nil, fmt.Errorf("authoring: rendering the shipped organization template: %w", err)
	}
	return &OrganizationTemplateView{ID: pdp.SystemCorpusOrganizationTemplateID, Digest: digest, Document: raw}, nil
}
