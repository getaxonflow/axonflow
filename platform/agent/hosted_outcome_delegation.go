// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"unicode/utf8"

	"axonflow/platform/shared/serviceauth"
)

const hostedOutcomeDelegationPrefix = "axonflow.tenant-delegation.v1."

type hostedOutcomeDelegation struct {
	OrganizationID string `json:"organization_id"`
	Service        string `json:"service"`
	TenantID       string `json:"tenant_id"`
}

func validHostedOutcomeDelegationIdentity(value string) bool {
	if value == "" || len(value) > 128 || strings.TrimSpace(value) != value || !utf8.ValidString(value) {
		return false
	}
	for _, char := range value {
		allowed := (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') || strings.ContainsRune("._:@/-", char)
		if !allowed {
			return false
		}
	}
	return true
}

// parseHostedOutcomeDelegation accepts only the canonical subject minted by
// the Hosted outcome sidecar. The HMAC covers this entire value through
// serviceauth.ValidateTokenForSubject; headers and request bodies cannot
// substitute another tenant after authentication.
func parseHostedOutcomeDelegation(subject string) (hostedOutcomeDelegation, error) {
	if !strings.HasPrefix(subject, hostedOutcomeDelegationPrefix) {
		return hostedOutcomeDelegation{}, fmt.Errorf("not a Hosted outcome delegation")
	}
	encoded := strings.TrimPrefix(subject, hostedOutcomeDelegationPrefix)
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(raw) == 0 || len(raw) > 512 {
		return hostedOutcomeDelegation{}, fmt.Errorf("invalid Hosted outcome delegation encoding")
	}
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	var delegation hostedOutcomeDelegation
	if err := decoder.Decode(&delegation); err != nil {
		return hostedOutcomeDelegation{}, fmt.Errorf("invalid Hosted outcome delegation: %w", err)
	}
	var trailing any
	if decoder.Decode(&trailing) == nil || delegation.Service != "hosted-outcome-service" ||
		!validHostedOutcomeDelegationIdentity(delegation.OrganizationID) ||
		!validHostedOutcomeDelegationIdentity(delegation.TenantID) {
		return hostedOutcomeDelegation{}, fmt.Errorf("invalid Hosted outcome delegation identity")
	}
	canonical, err := json.Marshal(delegation)
	if err != nil || base64.RawURLEncoding.EncodeToString(canonical) != encoded {
		return hostedOutcomeDelegation{}, fmt.Errorf("non-canonical Hosted outcome delegation")
	}
	return delegation, nil
}

// authenticateHostedOutcomeDelegation returns attempted=true whenever the
// request declared a subject. Callers must not retry such a request against
// the weaker unbound internal-service credential path.
func authenticateHostedOutcomeDelegation(request *http.Request, hints *AuthHints) (*AuthResult, bool) {
	subject := request.Header.Get(serviceauth.SubjectHeader)
	if subject == "" {
		return nil, false
	}
	if hints.ClientID != serviceauth.ClientID || internalTokenValidator == nil {
		return nil, true
	}
	delegation, parseErr := parseHostedOutcomeDelegation(subject)
	valid, validationErr := internalTokenValidator.ValidateTokenForSubject(hints.UserToken, subject)
	if parseErr != nil || validationErr != nil || !valid {
		return nil, true
	}
	return &AuthResult{
		Kind: AuthKindInternalService,
		Client: &Client{
			// The transport credential ID selects the verifier; the canonical
			// subject names the authenticated tenant service. Policy, audit,
			// admission and usage identity must use the latter rather than
			// collapsing every delegated caller into "orchestrator-internal".
			ID: delegation.Service, ClientID: delegation.Service,
			Name: "Hosted Outcome Service", OrgID: delegation.OrganizationID,
			TenantID:    delegation.TenantID,
			Permissions: []string{"query", "execute", "mcp"}, Enabled: true,
		},
		TenantID: delegation.TenantID, OrgID: delegation.OrganizationID,
		ClientID: delegation.Service,
	}, true
}
