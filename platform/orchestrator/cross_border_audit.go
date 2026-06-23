//go:build enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

// UU PDP Pasal 56(b) cross-border transfer-basis AUTO-STAMP (#2718, epic #2716).
//
// PROBLEM: the transfer_basis column exists on the canonical decision row
// (audit_logs, via core migration 126) and the OJK cross-border export reads it
// back verbatim, but the platform never WROTE it: a calling integration had to
// supply the basis at decision time. This closes that: when the orchestrator
// FORWARDS a request to an LLM (the moment data leaves the deployment), it
// auto-stamps the operator-declared transfer basis from config, with a per-org
// override and a per-request override on top, so Pasal 56(b) attestation is
// turnkey instead of an integration chore.
//
// BUILD-TAG SEAM: this file is enterprise-only (it validates against the
// enterprise-only ojk package's canonical forms). The non-tagged audit_logger.go
// declares a nil hook `stampCrossBorderTransfer`; this file's init() wires it.
// In a community build the hook stays nil → the columns are written NULL and
// behavior is byte-identical to before migration 126.
//
// PRECEDENCE (highest first): per-request value > per-org override > global
// default. An EXPLICIT per-request value always wins; if it is not a canonical
// UU PDP Pasal 56 form it is REJECTED (the row is left unstamped) rather than
// silently falling back to config. Writing the wrong basis, or substituting a
// default for a caller's typo, is worse for a compliance attribute than writing
// none. Config-sourced values are validated at load time and invalid entries are
// dropped, so they can never shadow a valid lower-precedence source.
//
// SAFE DEFAULT: with no config and no per-request value the resolver returns ""
// → both columns stay NULL → the row is NOT a tracked cross-border transfer and
// the export skips it. The Phase-1 PoC (no declared basis) is therefore safe.

import (
	"log"
	"os"
	"strings"
	"sync"

	"axonflow/platform/orchestrator/ojk"
)

// Environment knobs (config loading, owned by this workstream).
const (
	// EnvDefaultTransferBasis is the deployment-global UU PDP Pasal 56 transfer
	// basis applied to every cross-border LLM forward when no higher-precedence
	// value is present. Empty (the default) means "do not assert a basis".
	EnvDefaultTransferBasis = "AXONFLOW_DEFAULT_TRANSFER_BASIS"
	// EnvOrgTransferBasis is a comma-separated per-org override list of
	// `org_id:basis` pairs, e.g. "org-buku:pasal_56b_dpa,org-acme:adequacy".
	// An org listed here overrides the global default; a per-request value still
	// overrides the org value.
	EnvOrgTransferBasis = "AXONFLOW_ORG_TRANSFER_BASIS"
	// ctxKeyTransferBasis is the request-context key a calling integration may
	// set to override the basis for a single decision.
	ctxKeyTransferBasis = "transfer_basis"
)

// transferBasisConfig holds the validated global default and per-org overrides.
// All stored values are guaranteed canonical (validated at load) or absent.
type transferBasisConfig struct {
	defaultBasis string            // canonical form, or "" when unset/invalid
	orgOverrides map[string]string // org_id -> canonical form
}

// loadTransferBasisConfig reads the env knobs and validates every value against
// ojk.TransferBasisCanonicalForms. Invalid values are dropped with a warning so
// a misconfiguration is visible and can never shadow a valid lower-precedence
// source.
func loadTransferBasisConfig() *transferBasisConfig {
	cfg := &transferBasisConfig{orgOverrides: map[string]string{}}

	if def := strings.TrimSpace(os.Getenv(EnvDefaultTransferBasis)); def != "" {
		if ojk.TransferBasisValid(def) {
			cfg.defaultBasis = def
		} else {
			log.Printf("[CrossBorder] WARNING: %s=%q is not a UU PDP Pasal 56 canonical form %v; ignoring",
				EnvDefaultTransferBasis, def, ojk.TransferBasisCanonicalForms())
		}
	}

	if raw := strings.TrimSpace(os.Getenv(EnvOrgTransferBasis)); raw != "" {
		for _, pair := range strings.Split(raw, ",") {
			pair = strings.TrimSpace(pair)
			if pair == "" {
				continue
			}
			idx := strings.LastIndex(pair, ":")
			if idx <= 0 || idx == len(pair)-1 {
				log.Printf("[CrossBorder] WARNING: %s entry %q is not a valid org_id:basis pair; ignoring",
					EnvOrgTransferBasis, pair)
				continue
			}
			orgID := strings.TrimSpace(pair[:idx])
			basis := strings.TrimSpace(pair[idx+1:])
			if orgID == "" {
				continue
			}
			if !ojk.TransferBasisValid(basis) {
				log.Printf("[CrossBorder] WARNING: %s override for org %q (%q) is not a UU PDP Pasal 56 canonical form; ignoring",
					EnvOrgTransferBasis, orgID, basis)
				continue
			}
			cfg.orgOverrides[orgID] = basis
		}
	}

	return cfg
}

// resolve returns the transfer basis to stamp for a decision, applying the
// precedence per-request > per-org > global default. A non-empty per-request
// value wins outright: if it is invalid it is rejected (returns "") rather than
// falling through. Config sources are pre-validated, so an empty return means
// "no basis declared" and the row is left unstamped.
func (c *transferBasisConfig) resolve(perRequest, orgID string) string {
	if pr := strings.TrimSpace(perRequest); pr != "" {
		if ojk.TransferBasisValid(pr) {
			return pr
		}
		log.Printf("[CrossBorder] WARNING: per-request transfer_basis %q is not a UU PDP Pasal 56 canonical form %v; rejecting (row left unstamped)",
			pr, ojk.TransferBasisCanonicalForms())
		return ""
	}
	if orgID != "" {
		if b := c.orgOverrides[orgID]; b != "" {
			return b
		}
	}
	return c.defaultBasis
}

var (
	transferBasisCfg   *transferBasisConfig
	transferBasisCfgMu sync.Mutex
)

// getTransferBasisConfig lazily loads (once) and returns the process config.
func getTransferBasisConfig() *transferBasisConfig {
	transferBasisCfgMu.Lock()
	defer transferBasisCfgMu.Unlock()
	if transferBasisCfg == nil {
		transferBasisCfg = loadTransferBasisConfig()
	}
	return transferBasisCfg
}

// setTransferBasisConfigForTest installs an explicit config (test-only).
func setTransferBasisConfigForTest(c *transferBasisConfig) {
	transferBasisCfgMu.Lock()
	transferBasisCfg = c
	transferBasisCfgMu.Unlock()
}

// resetTransferBasisConfigForTest forces a reload on next access (test-only).
func resetTransferBasisConfigForTest() { setTransferBasisConfigForTest(nil) }

// perRequestTransferBasis extracts an explicit per-request basis from the
// request context (the channel a calling integration uses to supply the value
// at decision time). Non-string / absent values yield "".
func perRequestTransferBasis(req OrchestratorRequest) string {
	if req.Context == nil {
		return ""
	}
	if v, ok := req.Context[ctxKeyTransferBasis].(string); ok {
		return strings.TrimSpace(v)
	}
	return ""
}

// resolveDataResidency derives the ISO 3166-1 alpha-2 destination country from
// the resolved LLM provider at forward time. The default provider names are
// stable type tokens ("anthropic", "openai", "bedrock", ...) and custom
// instance names embed the type, so substring matching is robust. Only
// providers whose hosting country is known are mapped; anything else (azure
// without a known region, mistral, custom, ollama/self-hosted, mock, unknown)
// returns "" so we never fabricate a residency. Bedrock is region-specific:
// derived from BEDROCK_REGION.
func resolveDataResidency(provider string) string {
	p := strings.ToLower(strings.TrimSpace(provider))
	switch {
	case p == "":
		return ""
	case strings.Contains(p, "bedrock"):
		return awsRegionCountry(os.Getenv("BEDROCK_REGION"))
	case strings.Contains(p, "anthropic"):
		return "US" // Anthropic API is US-hosted
	case strings.Contains(p, "openai") && !strings.Contains(p, "azure"):
		return "US" // OpenAI API is US-hosted
	case strings.Contains(p, "gemini"), strings.Contains(p, "google"):
		return "US" // Google Generative AI API is US-hosted
	default:
		// azure-openai (region embedded in the endpoint, not reliably known at
		// audit time), mistral, ollama (self-hosted), mock, custom, unknown:
		// do not fabricate a destination country.
		return ""
	}
}

// awsRegionCountry maps an AWS region code to its ISO 3166-1 alpha-2 country.
// Unknown / empty regions return "". ap-southeast-3 (Jakarta) → ID is included
// for the Indonesia residency case. Region→country is by the region's physical
// location.
func awsRegionCountry(region string) string {
	switch strings.ToLower(strings.TrimSpace(region)) {
	case "us-east-1", "us-east-2", "us-west-1", "us-west-2", "us-gov-east-1", "us-gov-west-1":
		return "US"
	case "ca-central-1", "ca-west-1":
		return "CA"
	case "sa-east-1":
		return "BR"
	case "eu-west-1":
		return "IE"
	case "eu-west-2":
		return "GB"
	case "eu-west-3":
		return "FR"
	case "eu-central-1", "eu-central-2":
		return "DE"
	case "eu-north-1":
		return "SE"
	case "eu-south-1", "eu-south-2":
		return "IT"
	case "ap-south-1", "ap-south-2":
		return "IN"
	case "ap-southeast-1":
		return "SG"
	case "ap-southeast-2":
		return "AU"
	case "ap-southeast-3":
		return "ID" // Jakarta
	case "ap-northeast-1", "ap-northeast-3":
		return "JP"
	case "ap-northeast-2":
		return "KR"
	case "ap-east-1":
		return "HK"
	case "me-south-1":
		return "BH"
	case "me-central-1":
		return "AE"
	case "af-south-1":
		return "ZA"
	default:
		return ""
	}
}

// stampCrossBorderTransferImpl is the enterprise implementation wired into the
// non-tagged audit_logger.go hook. It resolves the transfer basis and, when one
// is declared, stamps it together with the derived data residency onto the audit
// row. No declared basis → both columns are left empty (NULL) and the row is not
// a tracked cross-border transfer.
func stampCrossBorderTransferImpl(entry *AuditEntry, req OrchestratorRequest, providerInfo *ProviderInfo) {
	if entry == nil {
		return
	}
	// SkipLLM is the synthetic hourly-validation path (mock provider, no real
	// forward), so no data crossed any border: never stamp it as a transfer.
	if req.SkipLLM {
		return
	}
	basis := getTransferBasisConfig().resolve(perRequestTransferBasis(req), req.Client.OrgID)
	if basis == "" {
		return
	}
	entry.TransferBasis = basis
	if providerInfo != nil {
		entry.DataResidency = resolveDataResidency(providerInfo.Provider)
	}
}

func init() {
	stampCrossBorderTransfer = stampCrossBorderTransferImpl
}
