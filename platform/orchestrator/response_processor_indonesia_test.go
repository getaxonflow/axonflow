// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
package orchestrator

import (
	"fmt"
	"strings"
	"testing"
)

const orchValidNIK = "3174042506780001" // checksum-valid (shared with 2478 + agent #2565)

// maskIndonesiaPIIDeep masks string leaves recursively across JSON shapes
// (object + array), not just top-level strings.
func TestMaskIndonesiaPIIDeep_Nested(t *testing.T) {
	d := getOrchestratorIndonesiaDetector()
	if d == nil {
		t.Skip("Indonesia detector disabled")
	}
	in := map[string]interface{}{
		"customer": map[string]interface{}{"nik": "NIK " + orchValidNIK},
		"notes":    []interface{}{"clean note", "another " + orchValidNIK},
		"count":    42, // non-string leaf untouched
	}
	out, types := maskIndonesiaPIIDeep(d, in)
	if len(types) == 0 {
		t.Fatal("expected detected types in nested structure")
	}
	if strings.Contains(fmt.Sprint(out), orchValidNIK) {
		t.Errorf("nested NIK not fully masked: %v", out)
	}
	// Non-string leaf preserved.
	if m, ok := out.(map[string]interface{}); !ok || m["count"] != 42 {
		t.Error("non-string leaf must be preserved")
	}
}
