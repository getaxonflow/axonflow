//go:build enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package ojk

// Framework-driven report composition (#3242, epic #2892).
//
// # The defect this replaces
//
// OJKComplianceFramework existed only as a validation whitelist: the four
// labels OJK_AI_GOVERNANCE / UU_PDP / BI_PJP / OJK_BI_COMBINED were accepted on
// input, echoed back on the response, and changed NOTHING about the report.
// BI PJP in particular was an enum member and nothing else. A customer could
// request a payment-system pack and a data-protection pack and receive two
// byte-identical documents with different labels on them.
//
// # What a framework label now does
//
//  1. It SELECTS the report sections when the caller names no explicit
//     data_types (the normal path -- the portal sends a framework, not a list).
//  2. It ANNOTATES every section with that framework's relevance, and flags
//     sections the caller explicitly asked for that the framework does not
//     consider in scope. An explicit request always wins; it is never silently
//     dropped, only labelled.
//  3. It emits a framework summary block naming the instrument and mapping each
//     regulatory pillar to the sections that evidence it.
//
// # Section order
//
// Each framework's Sections slice is the REPORT ORDER for that framework, not
// merely a set. OJK_BI_COMBINED leads with governance, BI_PJP leads with
// transaction integrity. Order is stable so two runs of the same export are
// comparable.

// ojkAllDataTypes is the canonical, ordered list of every concrete data type
// the exporter serves. OJKDataTypeAll is NOT a member -- it is the request-time
// alias that expands to this list.
//
// This slice is the SINGLE definition of "every section". The exhaustive-switch
// guarantee in ExportAuditData is derived from it (every entry must resolve to a
// section handler), and TestEveryDeclaredDataTypeHasASectionHandler drives the
// declared OJKAuditDataType constants against it -- so adding a new data type
// constant without a handler fails a test rather than silently falling through
// to an empty section, which is how hitl_oversight and pii_redactions came to
// return silent successful empties for months.
func ojkAllDataTypes() []OJKAuditDataType {
	return []OJKAuditDataType{
		OJKDataTypePolicyViolations,
		OJKDataTypeLLMCalls,
		OJKDataTypeDecisionChain,
		OJKDataTypeHITLOversight,
		OJKDataTypePIIRedactions,
		OJKDataTypeCrossBorder,
		OJKDataTypeBreachNotify,
	}
}

// frameworkProfile is the internal, ordered description of one framework.
type frameworkProfile struct {
	title    string
	citation string
	sections []OJKAuditDataType
	// relevance explains, per in-scope section, WHY this framework includes it.
	// Surfaced on OJKSectionStatus.Note so a regulator reading the pack does not
	// have to guess the mapping.
	relevance map[OJKAuditDataType]string
	pillars   []OJKFrameworkPillar
	notes     string
}

// ojkFrameworkProfiles returns the profile for every framework label.
//
// Regulatory grounding:
//   - OJK_AI_GOVERNANCE: OJK AI governance guidance (April 2025) + POJK 11/2022
//     on IT risk management -- model activity, refusals, decision lineage and
//     human oversight over material decisions.
//   - UU_PDP: Law 27/2022. Pasal 56 (cross-border transfer basis), Art. 46
//     (breach notification within 3x24 hours), and the processing record for
//     personal data (evidenced by the Indonesia PII detection events).
//   - BI_PJP: PBI 23/6/PBI/2021 on payment service providers -- transaction
//     integrity, data protection, and incident handling.
//   - OJK_BI_COMBINED: the union, governance-first.
func ojkFrameworkProfiles() map[OJKComplianceFramework]frameworkProfile {
	return map[OJKComplianceFramework]frameworkProfile{
		OJKFrameworkAIGovernance: {
			title:    "OJK AI Governance",
			citation: "OJK AI governance guidance (April 2025); POJK 11/2022 (IT risk management)",
			sections: []OJKAuditDataType{
				OJKDataTypePolicyViolations,
				OJKDataTypeLLMCalls,
				OJKDataTypeDecisionChain,
				OJKDataTypeHITLOversight,
			},
			relevance: map[OJKAuditDataType]string{
				OJKDataTypePolicyViolations: "Governance control effectiveness: decisions the platform refused or modified.",
				OJKDataTypeLLMCalls:         "Model activity register: which models were invoked, under which verdict (metadata only).",
				OJKDataTypeDecisionChain:    "Decision traceability: the ordered steps behind each governed request.",
				OJKDataTypeHITLOversight:    "Human oversight over material decisions.",
			},
			pillars: []OJKFrameworkPillar{
				{
					Name:        "Accountability and oversight",
					Citation:    "OJK AI governance guidance (April 2025)",
					Description: "Material AI decisions are subject to recorded human review.",
					Sections:    []OJKAuditDataType{OJKDataTypeHITLOversight, OJKDataTypeDecisionChain},
				},
				{
					Name:        "Control effectiveness",
					Citation:    "POJK 11/2022",
					Description: "Policy controls demonstrably act on model traffic.",
					Sections:    []OJKAuditDataType{OJKDataTypePolicyViolations, OJKDataTypeLLMCalls},
				},
			},
			notes: "Personal-data sections (PII redactions, cross-border transfers, breach log) are out of scope for this label; request UU_PDP or OJK_BI_COMBINED for them.",
		},

		OJKFrameworkUUPDP: {
			title:    "UU PDP (Law 27/2022) personal data protection",
			citation: "UU PDP Law 27/2022, Pasal 56 (cross-border transfer) and Art. 46 (3x24h breach notification)",
			sections: []OJKAuditDataType{
				OJKDataTypePIIRedactions,
				OJKDataTypeCrossBorder,
				OJKDataTypeBreachNotify,
				OJKDataTypePolicyViolations,
			},
			relevance: map[OJKAuditDataType]string{
				OJKDataTypePIIRedactions:    "Processing record for Indonesian personal data (NIK, NPWP, contact, bank account) with the action taken.",
				OJKDataTypeCrossBorder:      "Pasal 56 transfer basis recorded at the moment data left the deployment.",
				OJKDataTypeBreachNotify:     "Art. 46 breach log with the 3x24 hour deadline verdict per incident.",
				OJKDataTypePolicyViolations: "Personal-data refusals: requests the platform declined or masked.",
			},
			pillars: []OJKFrameworkPillar{
				{
					Name:        "Lawful processing record",
					Citation:    "UU PDP Pasal 4, Pasal 20",
					Description: "Personal data encountered by the platform is recorded with the action taken (blocked, redacted, or detected and forwarded).",
					Sections:    []OJKAuditDataType{OJKDataTypePIIRedactions, OJKDataTypePolicyViolations},
				},
				{
					Name:        "Cross-border transfer",
					Citation:    "UU PDP Pasal 56",
					Description: "Every declared transfer carries the legal basis recorded at decision time, surfaced verbatim.",
					Sections:    []OJKAuditDataType{OJKDataTypeCrossBorder},
				},
				{
					Name:        "Breach notification",
					Citation:    "UU PDP Art. 46",
					Description: "Breaches are tracked against the 3x24 hour notification window.",
					Sections:    []OJKAuditDataType{OJKDataTypeBreachNotify},
				},
			},
		},

		OJKFrameworkBIPJP: {
			title:    "Bank Indonesia payment service provider (PJP)",
			citation: "PBI 23/6/PBI/2021 (Penyedia Jasa Pembayaran)",
			sections: []OJKAuditDataType{
				OJKDataTypeDecisionChain,
				OJKDataTypeHITLOversight,
				OJKDataTypePIIRedactions,
				OJKDataTypeCrossBorder,
				OJKDataTypeBreachNotify,
			},
			relevance: map[OJKAuditDataType]string{
				OJKDataTypeDecisionChain: "Transaction integrity: the reconstructable decision path behind each payment-relevant request.",
				OJKDataTypeHITLOversight: "Transaction integrity: human authorisation recorded for gated payment operations.",
				OJKDataTypePIIRedactions: "Data protection: customer identifiers and bank-account data handled during payment processing.",
				OJKDataTypeCrossBorder:   "Data protection: payment data leaving Indonesian jurisdiction, with the declared basis.",
				OJKDataTypeBreachNotify:  "Incident handling: recorded incidents and their notification timeliness.",
			},
			pillars: []OJKFrameworkPillar{
				{
					Name:        "Transaction integrity",
					Citation:    "PBI 23/6/PBI/2021",
					Description: "Every governed payment-path request has a reconstructable decision chain, and gated operations carry a recorded human authorisation.",
					Sections:    []OJKAuditDataType{OJKDataTypeDecisionChain, OJKDataTypeHITLOversight},
				},
				{
					Name:        "Data protection",
					Citation:    "PBI 23/6/PBI/2021; UU PDP Pasal 56",
					Description: "Customer and account data encountered on the payment path is recorded, and any transfer out of jurisdiction carries a declared basis.",
					Sections:    []OJKAuditDataType{OJKDataTypePIIRedactions, OJKDataTypeCrossBorder},
				},
				{
					Name:        "Incident handling",
					Citation:    "PBI 23/6/PBI/2021; UU PDP Art. 46",
					Description: "Incidents are recorded and tracked against their notification deadline.",
					Sections:    []OJKAuditDataType{OJKDataTypeBreachNotify},
				},
			},
			notes: "Scoped to payment-system relevance. The model-activity register (llm_calls) is not a PBI 23/6 requirement and is omitted; request OJK_AI_GOVERNANCE or OJK_BI_COMBINED for it.",
		},

		OJKFrameworkCombined: {
			title:    "OJK + Bank Indonesia + UU PDP combined",
			citation: "OJK AI governance (April 2025); PBI 23/6/PBI/2021; UU PDP Law 27/2022",
			sections: ojkAllDataTypes(),
			relevance: map[OJKAuditDataType]string{
				OJKDataTypePolicyViolations: "Governance control effectiveness (OJK).",
				OJKDataTypeLLMCalls:         "Model activity register (OJK).",
				OJKDataTypeDecisionChain:    "Decision traceability (OJK) and transaction integrity (BI PJP).",
				OJKDataTypeHITLOversight:    "Human oversight (OJK) and payment authorisation (BI PJP).",
				OJKDataTypePIIRedactions:    "Personal-data processing record (UU PDP).",
				OJKDataTypeCrossBorder:      "Cross-border transfer basis (UU PDP Pasal 56).",
				OJKDataTypeBreachNotify:     "Breach notification timeliness (UU PDP Art. 46).",
			},
			pillars: []OJKFrameworkPillar{
				{
					Name:        "AI governance",
					Citation:    "OJK AI governance guidance (April 2025)",
					Description: "Control effectiveness, model activity, decision traceability and human oversight.",
					Sections: []OJKAuditDataType{
						OJKDataTypePolicyViolations, OJKDataTypeLLMCalls,
						OJKDataTypeDecisionChain, OJKDataTypeHITLOversight,
					},
				},
				{
					Name:        "Payment system",
					Citation:    "PBI 23/6/PBI/2021",
					Description: "Transaction integrity, data protection and incident handling for payment services.",
					Sections: []OJKAuditDataType{
						OJKDataTypeDecisionChain, OJKDataTypeHITLOversight,
						OJKDataTypePIIRedactions, OJKDataTypeCrossBorder, OJKDataTypeBreachNotify,
					},
				},
				{
					Name:        "Personal data protection",
					Citation:    "UU PDP Law 27/2022",
					Description: "Processing record, cross-border transfer basis and breach notification.",
					Sections: []OJKAuditDataType{
						OJKDataTypePIIRedactions, OJKDataTypeCrossBorder, OJKDataTypeBreachNotify,
					},
				},
			},
		},
	}
}

// resolveFrameworkProfile returns the profile for fw, falling back to the
// combined profile for an unrecognised label. The handler validates the
// framework before the service is reached, so the fallback is defence in depth
// for direct service callers (the exporter is also used as a data provider);
// it is deliberately the WIDEST profile, so a mis-labelled request over-reports
// rather than silently omitting sections.
func resolveFrameworkProfile(fw OJKComplianceFramework) frameworkProfile {
	profiles := ojkFrameworkProfiles()
	if p, ok := profiles[fw]; ok {
		return p
	}
	return profiles[OJKFrameworkCombined]
}

// frameworkSummary projects a profile onto the wire type.
func (p frameworkProfile) frameworkSummary(fw OJKComplianceFramework) *OJKFrameworkSummary {
	sections := make([]OJKAuditDataType, len(p.sections))
	copy(sections, p.sections)
	pillars := make([]OJKFrameworkPillar, len(p.pillars))
	copy(pillars, p.pillars)
	return &OJKFrameworkSummary{
		Framework: fw,
		Title:     p.title,
		Citation:  p.citation,
		Sections:  sections,
		Pillars:   pillars,
		Notes:     p.notes,
	}
}

// inScope reports whether dt is one of the framework's own sections.
func (p frameworkProfile) inScope(dt OJKAuditDataType) bool {
	for _, s := range p.sections {
		if s == dt {
			return true
		}
	}
	return false
}

// resolveRequestedDataTypes turns the caller's data_types into the ORDERED,
// de-duplicated list of concrete sections to produce, plus whether the list came
// from the framework (rather than an explicit request).
//
// Rules, in order:
//   - No data_types, or a list containing only "all": the framework's sections,
//     in framework order. This is the path the portal and the SDKs take, and it
//     is what makes the four framework labels produce four different reports.
//   - An explicit list: honoured verbatim in request order, de-duplicated.
//     "all" appearing alongside explicit types expands to EVERY concrete type
//     (not just the framework's) -- "all" means all.
//   - Unknown values are RETAINED in the returned list. They must reach the
//     dispatcher so it can report an explicit per-section error; filtering them
//     here would restore the silent-drop behaviour this replaces.
func resolveRequestedDataTypes(requested []OJKAuditDataType, p frameworkProfile) (types []OJKAuditDataType, fromFramework bool) {
	// Treat an all-empty/whitespace request as absent.
	cleaned := make([]OJKAuditDataType, 0, len(requested))
	for _, dt := range requested {
		if dt == "" {
			continue
		}
		cleaned = append(cleaned, dt)
	}

	onlyAll := len(cleaned) > 0
	for _, dt := range cleaned {
		if dt != OJKDataTypeAll {
			onlyAll = false
			break
		}
	}

	if len(cleaned) == 0 {
		out := make([]OJKAuditDataType, len(p.sections))
		copy(out, p.sections)
		return out, true
	}
	if onlyAll {
		// "all" on its own means the framework's full scope. A caller who wants
		// literally every section regardless of framework asks for
		// OJK_BI_COMBINED, whose scope IS every section.
		out := make([]OJKAuditDataType, len(p.sections))
		copy(out, p.sections)
		return out, true
	}

	seen := make(map[OJKAuditDataType]bool, len(cleaned))
	out := make([]OJKAuditDataType, 0, len(cleaned))
	for _, dt := range cleaned {
		if dt == OJKDataTypeAll {
			for _, concrete := range ojkAllDataTypes() {
				if !seen[concrete] {
					seen[concrete] = true
					out = append(out, concrete)
				}
			}
			continue
		}
		if seen[dt] {
			continue
		}
		seen[dt] = true
		out = append(out, dt)
	}
	return out, false
}
