//go:build enterprise

// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package license

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

// V3 license payload tests — covers ADR-052 §3 + ADR-054 deployment-identity
// rename. Pinned behaviors:
//
//  1. V2 license (only `org_id`) validates; resolved DeploymentID == OrgID.
//  2. V3 license (both `deployment_id` + `org_id` with same value) validates;
//     resolved DeploymentID == deployment_id, OrgID == deployment_id.
//  3. V3 license where `deployment_id` != `org_id` (forged or hand-edited):
//     `deployment_id` WINS — the rotation safety property ADR-054
//     §"Operational Rule" depends on.
//  4. Both fields empty after parse → resolver returns empty; the agent's
//     startup mismatch check (run.go:568) catches it.
//  5. LicenseDeploymentID() accessor is the canonical reader; OrgID is the
//     deprecated alias.
//  6. Keygen mints both fields in new signed payloads (V3 + V2 readers OK).

// signV3TestPayload builds an AXON-{base64(json)}.{base64(sig)} string
// signed by the evaluation-tier test seed (see setupTestKeypair).
// Bypasses GenerateServiceLicenseKey* so test cases can stamp arbitrary
// DeploymentID/OrgID combinations the keygen wouldn't normally allow.
func signV3TestPayload(t *testing.T, payload ServiceLicensePayload) string {
	t.Helper()
	seed, err := base64.StdEncoding.DecodeString("b58iLWB8r+Fezjj0cUWFzXi471GlFtKvvYSWi1gbIC4=")
	if err != nil {
		t.Fatalf("decode test seed: %v", err)
	}
	priv := ed25519.NewKeyFromSeed(seed)

	if payload.Tier == "" {
		payload.Tier = string(TierEvaluation)
	}
	if payload.ExpiresAt == "" {
		payload.ExpiresAt = time.Now().AddDate(0, 0, 30).Format("20060102")
	}
	if payload.IssuedAt == "" {
		payload.IssuedAt = time.Now().Format("20060102")
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)
	sig := ed25519.Sign(priv, []byte(payloadB64))
	sigB64 := base64.RawURLEncoding.EncodeToString(sig)
	return fmt.Sprintf("AXON-%s.%s", payloadB64, sigB64)
}

func TestV3_LegacyV2LicenseStillValidates(t *testing.T) {
	setupTestKeypair(t)
	// V2-only payload: just `org_id`, no `deployment_id`. This is the
	// shape of every license minted before today; reader must continue
	// to accept them and resolve DeploymentID from OrgID.
	payload := ServiceLicensePayload{
		OrgID:       "acme-corp",
		ServiceName: "platform",
		ServiceType: "backend-service",
		Permissions: []string{"mcp:*:*"},
		Aud:         AudSelfHostedFull,
	}
	licenseKey := signV3TestPayload(t, payload)

	result, err := ValidateLicense(context.Background(), licenseKey)
	if err != nil {
		t.Fatalf("V2 license validation failed: %v", err)
	}
	if !result.Valid {
		t.Fatalf("V2 license should be Valid=true, got %+v", result)
	}
	if got, want := result.LicenseDeploymentID(), "acme-corp"; got != want {
		t.Errorf("LicenseDeploymentID() = %q, want %q (fallback from OrgID)", got, want)
	}
	if got, want := result.OrgID, "acme-corp"; got != want {
		t.Errorf("OrgID = %q, want %q (back-compat field)", got, want)
	}
	if got, want := result.DeploymentID, "acme-corp"; got != want {
		t.Errorf("DeploymentID = %q, want %q (resolved from OrgID fallback)", got, want)
	}
}

func TestV3_NewV3LicenseValidates_BothFieldsSame(t *testing.T) {
	setupTestKeypair(t)
	// V3 payload as minted by GenerateServiceLicenseKey* post-Phase-5:
	// both fields populated with the same value.
	payload := ServiceLicensePayload{
		DeploymentID: "axonflow-community-saas-staging",
		OrgID:        "axonflow-community-saas-staging",
		ServiceName:  "platform",
		ServiceType:  "backend-service",
		Permissions:  []string{"mcp:*:*"},
		Aud:          AudSelfHostedFull,
	}
	licenseKey := signV3TestPayload(t, payload)

	result, err := ValidateLicense(context.Background(), licenseKey)
	if err != nil {
		t.Fatalf("V3 license validation failed: %v", err)
	}
	if !result.Valid {
		t.Fatalf("V3 license should be Valid=true, got %+v", result)
	}
	if got, want := result.LicenseDeploymentID(), "axonflow-community-saas-staging"; got != want {
		t.Errorf("LicenseDeploymentID() = %q, want %q", got, want)
	}
}

func TestV3_DeploymentIDWinsWhenFieldsDiffer(t *testing.T) {
	setupTestKeypair(t)
	// Build a payload with diverging `deployment_id` and `org_id` values
	// and assert the resolver picks `deployment_id`. This is the rotation
	// invariant — if a stale V2 alias somehow lingers on a re-signed
	// payload, the new V3 field must take precedence.
	payload := ServiceLicensePayload{
		DeploymentID: "axonflow-production-us",
		OrgID:        "production-us", // legacy unprefixed
		ServiceName:  "platform",
		ServiceType:  "backend-service",
		Permissions:  []string{"mcp:*:*"},
		Aud:          AudSelfHostedFull,
	}
	licenseKey := signV3TestPayload(t, payload)

	result, err := ValidateLicense(context.Background(), licenseKey)
	if err != nil {
		t.Fatalf("validation failed: %v", err)
	}
	if got, want := result.LicenseDeploymentID(), "axonflow-production-us"; got != want {
		t.Errorf("LicenseDeploymentID() = %q (legacy OrgID won), want %q (deployment_id wins)", got, want)
	}
	if got, want := result.OrgID, "axonflow-production-us"; got != want {
		// OrgID is populated from the resolved identity, NOT from the raw
		// payload.OrgID — back-compat call sites that read .OrgID
		// transparently get the V3 value.
		t.Errorf("OrgID = %q (raw payload value leaked), want %q (resolved)", got, want)
	}
}

func TestV3_EmptyBothFields_StillValidatesButHasEmptyDeploymentID(t *testing.T) {
	setupTestKeypair(t)
	// Pre-v9 behavior: missing org_id is not a hard validation error
	// here (the agent's startup check in run.go:568 enforces non-empty
	// mismatch instead). Make sure the resolver doesn't blow up.
	payload := ServiceLicensePayload{
		// DeploymentID + OrgID both empty
		ServiceName: "platform",
		ServiceType: "backend-service",
		Permissions: []string{"mcp:*:*"},
		Aud:         AudSelfHostedFull,
	}
	licenseKey := signV3TestPayload(t, payload)

	result, err := ValidateLicense(context.Background(), licenseKey)
	if err != nil {
		t.Fatalf("validation failed: %v", err)
	}
	if got := result.LicenseDeploymentID(); got != "" {
		t.Errorf("LicenseDeploymentID() = %q with both fields empty, want \"\"", got)
	}
}

func TestV3_LicenseDeploymentID_Accessor(t *testing.T) {
	// Unit-test the accessor directly (no signed payload needed).
	tests := []struct {
		name         string
		deploymentID string
		orgID        string
		want         string
	}{
		{
			name:         "v3 only — deployment_id present",
			deploymentID: "axonflow-acme",
			orgID:        "",
			want:         "axonflow-acme",
		},
		{
			name:         "v2 only — org_id present",
			deploymentID: "",
			orgID:        "acme",
			want:         "acme",
		},
		{
			name:         "both present — deployment_id wins",
			deploymentID: "axonflow-acme",
			orgID:        "acme",
			want:         "axonflow-acme",
		},
		{
			name:         "both empty",
			deploymentID: "",
			orgID:        "",
			want:         "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &ValidationResult{
				DeploymentID: tt.deploymentID,
				OrgID:        tt.orgID,
			}
			if got := r.LicenseDeploymentID(); got != tt.want {
				t.Errorf("LicenseDeploymentID() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestV3_LicenseKey_DeploymentIDAccessor(t *testing.T) {
	// Mirror tests for *LicenseKey, which has the same accessor.
	tests := []struct {
		name         string
		deploymentID string
		orgID        string
		want         string
	}{
		{name: "v3 wins", deploymentID: "axonflow-x", orgID: "x", want: "axonflow-x"},
		{name: "v2 fallback", deploymentID: "", orgID: "x", want: "x"},
		{name: "both empty", deploymentID: "", orgID: "", want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			k := &LicenseKey{
				DeploymentID: tt.deploymentID,
				OrgID:        tt.orgID,
			}
			if got := k.LicenseDeploymentID(); got != tt.want {
				t.Errorf("LicenseDeploymentID() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestV3_KeygenMintsBothFields(t *testing.T) {
	setupTestKeypair(t)
	// Verify the keygen produces V3-shaped payloads: when an operator
	// supplies `-org foo`, the signed payload should have both
	// `deployment_id: "foo"` AND `org_id: "foo"`. Inspecting the raw JSON
	// is the only way to confirm wire compatibility — a V2-only reader
	// must still see `org_id`.
	licenseKey, err := GenerateServiceLicenseKey(
		TierEvaluation,
		"axonflow-test-deployment",
		"platform",
		"backend-service",
		[]string{"mcp:*:*"},
		30,
	)
	if err != nil {
		t.Fatalf("keygen failed: %v", err)
	}
	// Decode the signed payload's JSON.
	rest := licenseKey[5:]
	dotIdx := strings.LastIndex(rest, ".")
	payloadB64 := rest[:dotIdx]
	payloadJSON, err := base64.RawURLEncoding.DecodeString(payloadB64)
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}

	// Parse as generic map to assert on BOTH JSON keys' presence.
	var m map[string]any
	if err := json.Unmarshal(payloadJSON, &m); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	if got, want := m["deployment_id"], "axonflow-test-deployment"; got != want {
		t.Errorf("payload deployment_id = %v, want %q (V3 field missing — V2-only readers OK, V3 readers blind)", got, want)
	}
	if got, want := m["org_id"], "axonflow-test-deployment"; got != want {
		t.Errorf("payload org_id = %v, want %q (V2 alias missing — pre-v9 readers will fail)", got, want)
	}
}
