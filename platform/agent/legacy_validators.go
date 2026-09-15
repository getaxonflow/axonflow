// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

// LegacyValidatorAction names a checksum validator that acted on a request or a
// response BEFORE the anchored engine decided it (#4122).
//
// On the scopes the anchored engine enforces this is the one legacy author
// left: under an organization's recorded pii detection override, the Indonesia
// and India validators block a request, or mask a response, ahead of the
// decision plane. Naming the validator and its action on the wire and the audit
// row keeps the record honest about who acted - a masked response otherwise
// goes out under the anchored engine's name - until #4122 routes the
// validators through the engine.
type LegacyValidatorAction struct {
	// Validator is legacyValidatorIndonesia or legacyValidatorIndia.
	Validator string `json:"validator"`
	// Action is legacyActionBlocked, legacyActionMasked or
	// legacyActionRedactionRequired.
	Action string `json:"action"`
}

const (
	legacyValidatorIndonesia = "indonesia_pii"
	legacyValidatorIndia     = "india_pii"
	legacyActionBlocked      = "blocked"
	legacyActionMasked       = "masked"
	// legacyActionRedactionRequired: the validator found a critical identifier
	// under a pii=redact override, and the seam carried the redaction onto the
	// anchored verdict as a mandatory obligation (attachValidatorRedactions).
	legacyActionRedactionRequired = "redaction_required"
)

// LegacyValidatorIndonesia and LegacyActionMasked are the names another
// process's response pass records the Indonesia validator's masking under (the
// orchestrator response plane), so both planes name the same act identically.
const (
	LegacyValidatorIndonesia = legacyValidatorIndonesia
	LegacyActionMasked       = legacyActionMasked
)

// legacyValidatorPolicyIDs names each validator the way its block path already
// names it in evaluated_policies, so a validator's block and its redaction read
// as one policy.
var legacyValidatorPolicyIDs = map[string]string{
	legacyValidatorIndonesia: "indonesia_pii_protection",
	legacyValidatorIndia:     "rbi_pii_protection",
}

// requiredValidatorRedactions lists, in a fixed order, the validators whose
// redaction a request requires (requestPassInput.validatorRedactions).
func requiredValidatorRedactions(indonesia, india bool) []string {
	var out []string
	if indonesia {
		out = append(out, legacyValidatorIndonesia)
	}
	if india {
		out = append(out, legacyValidatorIndia)
	}
	return out
}
