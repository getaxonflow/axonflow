// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestThePreCheckCensusCatchesEveryBypassShape is the census's own control.
//
// THE LIVE TREE IS NOT A CONTROL. Two rounds of review each defeated this
// census with an ordinary Go idiom, and each time the live tree happened not to
// contain that idiom - so the census looked healthy right up until somebody
// wrote one. The four shapes below are the three R3 round 2 planted plus the
// one round 1 planted, driven against a fixture rather than against luck.
//
// Every one of them emits `context_id` with no `decision_id` and no `verdict`,
// because both are minted only inside writePreCheckResponse.
func TestThePreCheckCensusCatchesEveryBypassShape(t *testing.T) {
	const bypasses = `package agent

import (
	"encoding/json"
	"net/http"
)

// 1. built and encoded in one function - the round-1 shape.
func zzDirect(w http.ResponseWriter) {
	resp := PreCheckResponse{ContextID: "a"}
	_ = json.NewEncoder(w).Encode(resp)
}

// 2. encoded through a POINTER - what defeated the round-1 fix.
func zzPointer(w http.ResponseWriter) {
	resp := PreCheckResponse{ContextID: "b"}
	_ = json.NewEncoder(w).Encode(&resp)
}

// 3. taken as a PARAMETER, so this function never constructs one.
func zzParam(w http.ResponseWriter, resp PreCheckResponse) {
	_ = json.NewEncoder(w).Encode(resp)
}

// 4. json.Marshal + Write, so .Encode never appears.
func zzMarshal(w http.ResponseWriter) {
	resp := PreCheckResponse{ContextID: "c"}
	b, _ := json.Marshal(resp)
	_, _ = w.Write(b)
}

// 5. RETURNED by a constructor and encoded by a caller that never names the
//    type - the one shape that survived the first widening.
func zzBuild() PreCheckResponse { return PreCheckResponse{ContextID: "d"} }

func zzEncodeReturned(w http.ResponseWriter) {
	_ = json.NewEncoder(w).Encode(zzBuild())
}
`
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "bypasses.go"), []byte(bypasses), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}

	found, _, _ := preCheckBypassSites(t, []string{dir})
	wantIn := []string{"zzDirect", "zzPointer", "zzParam", "zzMarshal", "zzEncodeReturned"}
	for _, fn := range wantIn {
		hit := false
		for _, f := range found {
			if strings.Contains(f, fn) {
				hit = true
			}
		}
		if !hit {
			t.Errorf("the census did not flag %s. That shape emits `context_id` with no `decision_id` "+
				"and no `verdict`, and it is one of the shapes a review has already used to defeat "+
				"this census.\n  found: %v", fn, found)
		}
	}

	// THE OTHER HALF: a function that routes through the blessed writer must
	// NOT be flagged, or a census that reported everything would pass above.
	clean := `package agent

import "net/http"

func zzClean(w http.ResponseWriter) {
	writePreCheckResponse(w, http.StatusOK, PreCheckResponse{ContextID: "e"})
}
`
	cleanDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(cleanDir, "clean.go"), []byte(clean), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	if got, _, _ := preCheckBypassSites(t, []string{cleanDir}); len(got) != 0 {
		t.Errorf("a handler that correctly calls writePreCheckResponse was flagged: %v. A census that "+
			"reports correct code cannot be told apart from one that reports everything.", got)
	}
}
