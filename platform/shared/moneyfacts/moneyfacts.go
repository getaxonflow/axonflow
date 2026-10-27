// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

// Package moneyfacts validates caller-declared minor-unit amounts for typed policy.
package moneyfacts

import (
	"encoding/json"
	"math"
	"strconv"
)

const maxExactMinorUnits = 9007199254740991

// Minor accepts positive integer minor units that survive JSON float decoding
// exactly. It rejects decimal money, strings, booleans and unsafe magnitudes.
func Minor(value any) (float64, bool) {
	var amount float64
	switch v := value.(type) {
	case int:
		amount = float64(v)
	case int64:
		amount = float64(v)
	case float64:
		amount = v
	case json.Number:
		parsed, err := strconv.ParseInt(v.String(), 10, 64)
		if err != nil {
			return 0, false
		}
		amount = float64(parsed)
	default:
		return 0, false
	}
	return amount, amount > 0 && amount <= maxExactMinorUnits && !math.IsInf(amount, 0) && !math.IsNaN(amount) && math.Trunc(amount) == amount
}

// Currency accepts an uppercase three-letter ISO-style code. Configuration
// still decides which codes and thresholds are valid for an organization.
func Currency(value any) (string, bool) {
	code, ok := value.(string)
	if !ok || len(code) != 3 {
		return "", false
	}
	for _, letter := range code {
		if letter < 'A' || letter > 'Z' {
			return "", false
		}
	}
	return code, true
}
