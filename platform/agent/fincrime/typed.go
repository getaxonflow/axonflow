// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package fincrime

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"math/big"
	"regexp"
	"strings"
	"time"

	"golang.org/x/text/currency"
)

// Registry is trusted deployment configuration, not a request field. Its
// digest is recorded with decisions so a threshold can be reconstructed.
type Registry struct {
	Version       int                     `json:"version"`
	Organizations map[string]Organization `json:"organizations"`
	Digest        string                  `json:"-"`
}

type Organization struct {
	Actions             []Action                  `json:"actions"`
	Currencies          map[string]CurrencyPolicy `json:"currencies"`
	ProhibitedCountries []string                  `json:"prohibited_countries"`
	HighRiskCountries   []string                  `json:"high_risk_countries"`
	RestrictedMCCs      []string                  `json:"restricted_mccs"`
}

type Action struct {
	ClientID  string `json:"client_id"`
	Plane     string `json:"plane"`
	Server    string `json:"server"`
	Tool      string `json:"tool"`
	Operation string `json:"operation"`
	Class     string `json:"class"`
}

type CurrencyPolicy struct {
	Cap              string `json:"cap"`
	StructuringFloor string `json:"structuring_floor"`
	CNP              string `json:"cnp"`
}

type Target struct {
	OrgID, ClientID, Plane, Server, Tool, Operation string
}

type Result struct {
	Covered bool
	Reason  string
	Facts   map[string]bool
	Class   string
}

var decimal = regexp.MustCompile(`^(0|[1-9][0-9]*)(?:\.([0-9]+))?$`)
var country = regexp.MustCompile(`^[A-Z]{2}(?:-[A-Z0-9]{1,4})?$`)
var mcc = regexp.MustCompile(`^[0-9]{4}$`)

var detectorIDs = []string{
	"fincrime_invalid_context_block",
	"fincrime_prohibited_geography_block",
	"fincrime_high_value_amount_cap",
	"fincrime_payment_tool_authorization_gate",
	"fincrime_payment_execution_stepup",
	"fincrime_restricted_mcc_block",
	"fincrime_velocity_frequency_stepup",
	"fincrime_structuring_pattern_stepup",
	"fincrime_cumulative_exposure_stepup",
	"fincrime_geo_corridor_stepup",
	"fincrime_cnp_high_value_stepup",
}

func DetectorIDs() []string { return append([]string(nil), detectorIDs...) }

func ParseRegistry(raw []byte) (*Registry, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var r Registry
	if err := dec.Decode(&r); err != nil {
		return nil, fmt.Errorf("fincrime registry: %w", err)
	}
	if err := dec.Decode(new(interface{})); err != io.EOF {
		return nil, fmt.Errorf("fincrime registry: trailing JSON: %v", err)
	}
	if r.Version != 3 || len(r.Organizations) == 0 {
		return nil, fmt.Errorf("fincrime registry: version 3 and organizations are required")
	}
	for org, cfg := range r.Organizations {
		if org == "" || len(cfg.Actions) == 0 || len(cfg.Currencies) == 0 {
			return nil, fmt.Errorf("fincrime registry: organization %q needs actions and currencies", org)
		}
		seen := map[string]bool{}
		for _, a := range cfg.Actions {
			if a.ClientID == "" || a.Server == "" || a.Tool == "" || (a.Plane != "decide" && a.Plane != "mcp") {
				return nil, fmt.Errorf("fincrime registry: organization %q has incomplete action declaration", org)
			}
			switch a.Class {
			case "execute", "retry", "beneficiary_change", "investigate":
			default:
				return nil, fmt.Errorf("fincrime registry: unknown action class %q", a.Class)
			}
			if a.Plane == "decide" && a.Operation != "" {
				return nil, fmt.Errorf("fincrime registry: Decision API action %q must have no operation", a.Tool)
			}
			if a.Class == "investigate" && (a.Plane != "mcp" || a.Operation != "query") {
				return nil, fmt.Errorf("fincrime registry: investigation %q must be an MCP query", a.Tool)
			}
			if a.Plane == "mcp" && a.Class != "investigate" && a.Operation != "execute" {
				return nil, fmt.Errorf("fincrime registry: monetary action %q must be an MCP execute", a.Tool)
			}
			key := a.ClientID + "\x00" + a.Plane + "\x00" + a.Server + "\x00" + a.Tool + "\x00" + a.Operation
			if seen[key] {
				return nil, fmt.Errorf("fincrime registry: duplicate action in organization %q", org)
			}
			seen[key] = true
		}
		for code, p := range cfg.Currencies {
			if _, err := exponent(code); err != nil {
				return nil, err
			}
			for _, amount := range []string{p.Cap, p.StructuringFloor, p.CNP} {
				if _, err := minor(amount, code); err != nil {
					return nil, fmt.Errorf("fincrime registry: %s: %w", code, err)
				}
			}
		}
		for _, c := range append(append([]string{}, cfg.ProhibitedCountries...), cfg.HighRiskCountries...) {
			if !country.MatchString(c) {
				return nil, fmt.Errorf("fincrime registry: invalid country %q", c)
			}
		}
		for _, code := range cfg.RestrictedMCCs {
			if !mcc.MatchString(code) {
				return nil, fmt.Errorf("fincrime registry: invalid MCC %q", code)
			}
		}
	}
	h := sha256.Sum256(raw)
	r.Digest = "sha256:" + hex.EncodeToString(h[:])
	return &r, nil
}

func exponent(code string) (int, error) {
	if len(code) != 3 || strings.ToUpper(code) != code {
		return 0, fmt.Errorf("unsupported ISO 4217 currency %q", code)
	}
	u, err := currency.ParseISO(code)
	if err != nil || u == currency.XXX || code == "XXX" {
		return 0, fmt.Errorf("unsupported ISO 4217 currency %q", code)
	}
	scale, increment := currency.Standard.Rounding(u)
	if scale < 0 || scale > 3 || increment != 1 {
		return 0, fmt.Errorf("unsupported currency precision %q", code)
	}
	return scale, nil
}

func minor(s, code string) (*big.Int, error) {
	scale, err := exponent(code)
	if err != nil {
		return nil, err
	}
	m := decimal.FindStringSubmatch(s)
	if m == nil || len(m[2]) > scale || len(s) > 40 {
		return nil, fmt.Errorf("invalid major-unit decimal %q for %s", s, code)
	}
	digits := m[1] + m[2] + strings.Repeat("0", scale-len(m[2]))
	n, ok := new(big.Int).SetString(digits, 10)
	if !ok {
		return nil, fmt.Errorf("invalid amount %q", s)
	}
	return n, nil
}

func field(m map[string]interface{}, key string) (string, bool) {
	v, ok := m[key].(string)
	return v, ok && v != ""
}

func member(s string, list []string) bool {
	for _, v := range list {
		if s == v || strings.HasPrefix(s, v+"-") {
			return true
		}
	}
	return false
}

// Evaluate computes only detector facts. The typed pack document alone turns
// them into blocks and approval requirements.
func (r *Registry) Evaluate(t Target, parameters map[string]interface{}) Result {
	out := Result{Facts: map[string]bool{}}
	for _, id := range detectorIDs {
		out.Facts[id] = false
	}
	if r == nil {
		return out
	}
	cfg, orgKnown := r.Organizations[t.OrgID]
	for _, c := range r.Organizations {
		for _, a := range c.Actions {
			if a.Server == t.Server {
				out.Covered = true
			}
		}
	}
	if !out.Covered {
		return out
	}
	invalid := func(reason string) Result {
		out.Reason = reason
		for id := range out.Facts {
			out.Facts[id] = false
		}
		out.Facts["fincrime_invalid_context_block"] = true
		return out
	}
	if !orgKnown {
		return invalid("unknown_organization")
	}
	var selected *Action
	for i := range cfg.Actions {
		a := &cfg.Actions[i]
		if a.ClientID == t.ClientID && a.Plane == t.Plane && a.Server == t.Server && a.Tool == t.Tool && a.Operation == t.Operation {
			selected = a
			break
		}
	}
	if selected == nil {
		return invalid("undeclared_payment_action")
	}
	out.Class = selected.Class
	if selected.Class == "investigate" {
		return out
	}
	tx, ok := parameters[TransactionContextKey].(map[string]interface{})
	if !ok || len(tx) == 0 || tx["version"] != float64(2) {
		return invalid("missing_or_invalid_transaction_v2")
	}
	amount, aok := field(tx, "amount")
	unit, uok := field(tx, "amount_unit")
	code, cok := field(tx, "currency")
	id, iok := field(tx, "transaction_id")
	beneficiary, bok := field(tx, "beneficiary_id")
	paymentType, pok := field(tx, "payment_type")
	sender, sok := field(tx, "sender_location")
	receiver, rok := field(tx, "receiver_location")
	stamp, tok := field(tx, "timestamp")
	if !aok || !uok || unit != "major" || !cok || !iok || !bok || !pok || !sok || !rok || !tok || !country.MatchString(sender) || !country.MatchString(receiver) {
		return invalid("missing_required_transaction_field")
	}
	if paymentType != "transfer" && paymentType != "wire" && paymentType != "card" {
		return invalid("invalid_payment_type")
	}
	if _, err := time.Parse(time.RFC3339Nano, stamp); err != nil {
		return invalid("invalid_timestamp")
	}
	value, err := minor(amount, code)
	if err != nil {
		return invalid("invalid_amount_or_currency")
	}
	policy, ok := cfg.Currencies[code]
	if !ok {
		return invalid("missing_currency_policy")
	}
	cap, _ := minor(policy.Cap, code)
	floor, _ := minor(policy.StructuringFloor, code)
	cnp, _ := minor(policy.CNP, code)
	if selected.Class == "retry" {
		previous, ok := tx["previous_state"].(string)
		previousID, idOK := field(tx, "retry_of")
		previousAmount, amountOK := field(tx, "previous_amount")
		previousCurrency, currencyOK := field(tx, "previous_currency")
		previousBeneficiary, beneficiaryOK := field(tx, "previous_beneficiary_id")
		if !ok || previous != "failed" || !idOK || previousID != id || !amountOK || previousAmount != amount || !currencyOK || previousCurrency != code || !beneficiaryOK || previousBeneficiary != beneficiary {
			return invalid("invalid_retry_state")
		}
	}
	if selected.Class == "beneficiary_change" {
		before, beforeOK := field(tx, "beneficiary_before")
		after, afterOK := field(tx, "beneficiary_after")
		if !beforeOK || !afterOK || before == after || after != beneficiary {
			return invalid("invalid_beneficiary_change")
		}
		out.Facts["fincrime_payment_tool_authorization_gate"] = true
	}
	if selected.Class == "execute" || selected.Class == "retry" {
		out.Facts["fincrime_payment_execution_stepup"] = true
	}
	if member(sender, cfg.ProhibitedCountries) || member(receiver, cfg.ProhibitedCountries) {
		out.Facts["fincrime_prohibited_geography_block"] = true
	}
	out.Facts["fincrime_high_value_amount_cap"] = value.Cmp(cap) >= 0
	out.Facts["fincrime_structuring_pattern_stepup"] = (paymentType == "transfer" || paymentType == "wire") && value.Cmp(floor) >= 0 && value.Cmp(cap) < 0
	out.Facts["fincrime_geo_corridor_stepup"] = member(receiver, cfg.HighRiskCountries)
	if codeMCC, present := tx["merchant_category_code"]; present {
		s, ok := codeMCC.(string)
		if !ok || !mcc.MatchString(s) {
			return invalid("invalid_merchant_category_code")
		}
		out.Facts["fincrime_restricted_mcc_block"] = member(s, cfg.RestrictedMCCs)
	}
	if paymentType == "card" {
		method, ok := field(tx, "payment_method")
		if !ok || (method != "card_present" && method != "card_not_present") {
			return invalid("missing_or_invalid_payment_method")
		}
		out.Facts["fincrime_cnp_high_value_stepup"] = method == "card_not_present" && value.Cmp(cnp) >= 0
	}
	cohort, ok := parameters[CohortContextKey].(map[string]interface{})
	if !ok {
		return invalid("missing_cohort")
	}
	cohortCurrency, currencyOK := field(cohort, "currency")
	mean, meanOK := field(cohort, "historical_mean_amount")
	freq, freqOK := cohort["txn_frequency_1h"].(float64)
	if !currencyOK || cohortCurrency != code || !meanOK || !freqOK || math.IsNaN(freq) || math.IsInf(freq, 0) || freq < 0 || math.Trunc(freq) != freq || freq > 1e9 {
		return invalid("invalid_cohort")
	}
	if _, err := minor(mean, code); err != nil {
		return invalid("invalid_cohort")
	}
	out.Facts["fincrime_velocity_frequency_stepup"] = freq >= 10
	out.Facts["fincrime_cumulative_exposure_stepup"] = freq >= 20
	return out
}
