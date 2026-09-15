// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package policy

import (
	"encoding/json"
	"fmt"
	"strconv"
)

// ParameterScanText is the text the request pass scans for one parameter value
// (EvaluateRequest, #1287): a string as it is, an object or an array as its JSON
// encoding, a JSON number in decimal notation, and anything else as %v. A
// boolean carries nothing a detector reads and is not scanned, and neither is
// an empty text.
//
// It is the ONE definition of that text. The MCP request pass redacts the same
// text to tell whether a redaction the decision composed would mask a parameter
// (#4264), and a second copy of these rules would drift from the scan it has to
// agree with.
func ParameterScanText(val interface{}) (string, bool) {
	text := ""
	switch v := val.(type) {
	case string:
		text = v
	case map[string]interface{}, []interface{}:
		if data, err := json.Marshal(v); err == nil {
			text = string(data)
		}
	case float64:
		// JSON decodes numbers as float64. Use decimal notation to preserve
		// digit sequences for PII pattern matching (credit cards, SSNs, etc).
		// fmt.Sprintf("%v") produces scientific notation for large values.
		text = strconv.FormatFloat(v, 'f', -1, 64)
	case int64:
		text = strconv.FormatInt(v, 10)
	case bool:
		return "", false // booleans have no PII/compliance/injection risk
	default:
		text = fmt.Sprintf("%v", v)
	}
	return text, text != ""
}
