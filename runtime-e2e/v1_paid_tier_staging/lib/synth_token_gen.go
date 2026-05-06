//go:build enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

// synth_token mints synthetic license tokens for the runtime-e2e harness
// covering the issue #1885 sequences that the real Stripe-webhook + DB
// path can't produce on demand:
//
//   §3a  Self-hosted Enterprise token (aud=axonflow.self_hosted.full)
//        sent as X-License-Token against the SaaS path → 401 cross-quadrant.
//   §4   Past-expired Pro token (custom -issued-at + ValidityDays=1) →
//        401 "token expired" without ever hitting the DB.
//
// Why a Go CLI: the SaaS Plugin signing key (Ed25519 seed in
// AXONFLOW_PLUGIN_CLAIMED_SIGNING_KEY) is held by the in-agent issuer.
// Reusing license.GeneratePluginClaimLicense / GenerateServiceLicenseKeyWithAud
// keeps the synthetic tokens byte-identical to what production issues —
// a Python re-implementation would drift away from the canonical shape on
// the next ADR-050 iteration.
//
// Usage examples:
//
//	# §3a — self-hosted Enterprise token, sent against SaaS path
//	AXONFLOW_ENT_SIGNING_KEY=<base64-seed> \
//	  synth_token -kind self_hosted -tier Enterprise -aud axonflow.self_hosted.full \
//	    -org synth-test -service-name synth-svc -permissions 'mcp:test:*'
//
//	# §4 — past-expired Pro token; -jti lets caller correlate with logs
//	AXONFLOW_PLUGIN_CLAIMED_SIGNING_KEY=<base64-seed> \
//	  synth_token -kind saas_plugin -tier Pro -tenant-id cs_<uuid> \
//	    -email dev@x -issued-at 2026-04-01 -validity-days 1 -jti synth-expired-001
//
// Output: JSON to stdout — {token, jti, aud, tier, issued_at, expires_at,
// kind}. Exit code 0 on success, 1 on any error (signing key absent,
// invalid flag values, etc).
package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"axonflow/platform/agent/license"
)

func main() {
	var (
		kind         = flag.String("kind", "", "Token kind: saas_plugin | self_hosted (required)")
		tier         = flag.String("tier", "Pro", "Tier: Pro | Premium (saas_plugin) | Enterprise | Professional | Plus (self_hosted)")
		tenantID     = flag.String("tenant-id", "", "Required for saas_plugin (cs_<uuid>); ignored for self_hosted")
		email        = flag.String("email", "synth@axonflow-test.invalid", "ClaimedByEmail for saas_plugin")
		orgID        = flag.String("org", "synth-test", "OrgID for self_hosted tokens")
		serviceName  = flag.String("service-name", "synth-self-hosted", "ServiceName for self_hosted")
		permsCSV     = flag.String("permissions", "mcp:test:*", "Comma-separated permissions for self_hosted")
		validityDays = flag.Int("validity-days", 90, "Days until expiry; 0 = no expiry (saas_plugin only)")
		issuedAtStr  = flag.String("issued-at", "", "Override IssuedAt as YYYY-MM-DD (default = now); used by §4 to mint past-expired tokens")
		aud          = flag.String("aud", "", "Aud override for self_hosted: axonflow.self_hosted.{plugin,sdk,full}; default=full")
		jti          = flag.String("jti", "", "Override JTI for saas_plugin (else random UUID v4)")
	)
	flag.Parse()

	if *kind == "" {
		die("missing required -kind (saas_plugin | self_hosted)")
	}

	var issuedAt time.Time
	if *issuedAtStr != "" {
		t, err := time.Parse("2006-01-02", *issuedAtStr)
		if err != nil {
			die(fmt.Sprintf("invalid -issued-at %q: %v", *issuedAtStr, err))
		}
		issuedAt = t
	}

	switch *kind {
	case "saas_plugin":
		if *tenantID == "" {
			die("missing -tenant-id for saas_plugin (cs_<uuid>)")
		}
		out, err := mintSaasPlugin(*tenantID, *email, license.Tier(*tier), *validityDays, issuedAt, *jti)
		if err != nil {
			die(err.Error())
		}
		emit(out)

	case "self_hosted":
		if *aud == "" {
			*aud = license.AudSelfHostedFull
		}
		out, err := mintSelfHosted(license.Tier(*tier), *orgID, *serviceName, *permsCSV, *validityDays, *aud)
		if err != nil {
			die(err.Error())
		}
		emit(out)

	default:
		die(fmt.Sprintf("unknown -kind %q (want saas_plugin | self_hosted)", *kind))
	}
}

type tokenOut struct {
	Token     string `json:"token"`
	JTI       string `json:"jti,omitempty"`
	Aud       string `json:"aud"`
	Tier      string `json:"tier"`
	IssuedAt  string `json:"issued_at,omitempty"`
	ExpiresAt string `json:"expires_at,omitempty"`
	Kind      string `json:"kind"`
}

func mintSaasPlugin(tenantID, email string, tier license.Tier, validityDays int, issuedAt time.Time, jti string) (tokenOut, error) {
	in := license.PluginClaimLicenseInput{
		TenantID:       tenantID,
		ClaimedByEmail: email,
		ValidityDays:   validityDays,
		Tier:           tier,
		IssuedAt:       issuedAt,
		JTI:            jti, // empty → GeneratePluginClaimLicense fills with UUID v4
	}
	tok, err := license.GeneratePluginClaimLicense(in)
	if err != nil {
		return tokenOut{}, fmt.Errorf("GeneratePluginClaimLicense: %w", err)
	}

	// Decode the payload to surface the canonical JTI + ExpiresAt the
	// issuer ended up with. Bypass signature/expiry verification here —
	// the §4 case intentionally produces a past-expired token, which the
	// real validator (correctly) rejects. Caller wants the metadata
	// regardless.
	payload, decErr := decodePayload(tok)
	if decErr != nil {
		return tokenOut{}, fmt.Errorf("decode payload: %w", decErr)
	}
	return tokenOut{
		Token: tok, Kind: "saas_plugin", Tier: string(tier), Aud: payload.Aud,
		JTI: payload.JTI, IssuedAt: payload.IssuedAt, ExpiresAt: payload.ExpiresAt,
	}, nil
}

func mintSelfHosted(tier license.Tier, orgID, serviceName, permsCSV string, validityDays int, aud string) (tokenOut, error) {
	perms := splitCSV(permsCSV)
	if len(perms) == 0 {
		return tokenOut{}, fmt.Errorf("self_hosted requires -permissions (comma-separated, e.g. 'mcp:test:*')")
	}
	tok, err := license.GenerateServiceLicenseKeyWithAud(
		tier, orgID, serviceName, "client-application", perms, validityDays, aud,
	)
	if err != nil {
		return tokenOut{}, fmt.Errorf("GenerateServiceLicenseKeyWithAud: %w", err)
	}
	return tokenOut{Token: tok, Kind: "self_hosted", Tier: string(tier), Aud: aud}, nil
}

func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := parts[:0]
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// decodePayload pulls JTI / ExpiresAt / Aud / IssuedAt out of an AXON-prefixed
// token's base64-encoded payload without signature verification. Used to
// surface metadata for tokens the validator will (correctly) reject
// downstream — e.g. the §4 past-expired Pro token.
func decodePayload(token string) (*license.ServiceLicensePayload, error) {
	const prefix = "AXON-"
	if !strings.HasPrefix(token, prefix) {
		return nil, fmt.Errorf("missing AXON- prefix")
	}
	rest := token[len(prefix):]
	dot := strings.LastIndex(rest, ".")
	if dot < 1 {
		return nil, fmt.Errorf("missing signature separator")
	}
	payloadJSON, err := base64.RawURLEncoding.DecodeString(rest[:dot])
	if err != nil {
		return nil, fmt.Errorf("payload decode: %w", err)
	}
	var p license.ServiceLicensePayload
	if err := json.Unmarshal(payloadJSON, &p); err != nil {
		return nil, fmt.Errorf("payload unmarshal: %w", err)
	}
	return &p, nil
}

func emit(out tokenOut) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		die("json encode: " + err.Error())
	}
}

func die(msg string) {
	fmt.Fprintln(os.Stderr, "synth_token: "+msg)
	os.Exit(1)
}
