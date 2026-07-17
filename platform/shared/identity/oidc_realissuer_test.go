//go:build enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

// Real-issuer proof for Path B (#2924 DoD): the OIDC verifier is driven with
// tokens minted by a REAL standards-compliant OIDC issuer (Keycloak) — a
// real password grant, real RS256 signatures, and the issuer's real JWKS
// endpoint fetched over HTTP — not a hand-signed synthetic token. JumpCloud
// itself requires a live tenant; Keycloak is the standards-equivalent issuer
// (same OIDC/JWKS contract) and the docs map the config fields to JumpCloud.
package identity

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"axonflow/platform/testutil"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

// keycloakRealm imports a realm with password-grant clients (public,
// direct-access grants), an audience mapper stamping the AxonFlow audience,
// and one fleet developer with a verified email. The second client overrides
// the access-token lifespan to 1 second so the expiry negative test runs in
// seconds, against a REAL issuer-stamped exp.
const keycloakRealm = `{
  "realm": "axonflow",
  "enabled": true,
  "users": [
    {
      "username": "fleet-dev",
      "email": "Fleet-Dev@Example.com",
      "emailVerified": true,
      "enabled": true,
      "firstName": "Fleet",
      "lastName": "Dev",
      "credentials": [{"type": "password", "value": "fleet-dev-password", "temporary": false}]
    }
  ],
  "clients": [
    {
      "clientId": "axonflow-fleet",
      "enabled": true,
      "publicClient": true,
      "directAccessGrantsEnabled": true,
      "standardFlowEnabled": false,
      "protocolMappers": [
        {
          "name": "axonflow-audience",
          "protocol": "openid-connect",
          "protocolMapper": "oidc-audience-mapper",
          "config": {
            "included.custom.audience": "axonflow-platform",
            "access.token.claim": "true"
          }
        }
      ]
    },
    {
      "clientId": "axonflow-fleet-short",
      "enabled": true,
      "publicClient": true,
      "directAccessGrantsEnabled": true,
      "standardFlowEnabled": false,
      "attributes": {"access.token.lifespan": "1"},
      "protocolMappers": [
        {
          "name": "axonflow-audience",
          "protocol": "openid-connect",
          "protocolMapper": "oidc-audience-mapper",
          "config": {
            "included.custom.audience": "axonflow-platform",
            "access.token.claim": "true"
          }
        }
      ]
    }
  ]
}`

// startKeycloak launches a real Keycloak and returns its base URL.
func startKeycloak(t *testing.T) string {
	t.Helper()
	ctx := context.Background()
	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        "quay.io/keycloak/keycloak:26.0",
			ExposedPorts: []string{"8080/tcp"},
			Env: map[string]string{
				"KC_BOOTSTRAP_ADMIN_USERNAME": "admin",
				"KC_BOOTSTRAP_ADMIN_PASSWORD": "admin",
			},
			Cmd: []string{"start-dev", "--import-realm"},
			Files: []testcontainers.ContainerFile{{
				Reader:            strings.NewReader(keycloakRealm),
				ContainerFilePath: "/opt/keycloak/data/import/axonflow-realm.json",
				FileMode:          0o644,
			}},
			WaitingFor: wait.ForHTTP("/realms/axonflow").WithPort("8080/tcp").WithStartupTimeout(3 * time.Minute),
		},
		Started: true,
	})
	if err != nil {
		t.Fatalf("start keycloak: %v", err)
	}
	t.Cleanup(func() { _ = container.Terminate(context.Background()) })

	host, err := container.Host(ctx)
	if err != nil {
		t.Fatalf("keycloak host: %v", err)
	}
	port, err := container.MappedPort(ctx, "8080/tcp")
	if err != nil {
		t.Fatalf("keycloak port: %v", err)
	}
	return fmt.Sprintf("http://%s:%s", host, port.Port())
}

// passwordGrant obtains a REAL access token from Keycloak.
func passwordGrant(t *testing.T, base, clientID, username, password string) string {
	t.Helper()
	form := url.Values{
		"grant_type": {"password"},
		"client_id":  {clientID},
		"username":   {username},
		"password":   {password},
		"scope":      {"openid email"},
	}
	resp, err := http.PostForm(base+"/realms/axonflow/protocol/openid-connect/token", form)
	if err != nil {
		t.Fatalf("token request: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("token request returned %d: %s", resp.StatusCode, body)
	}
	var out struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &out); err != nil || out.AccessToken == "" {
		t.Fatalf("token response unparseable: %v %s", err, body)
	}
	return out.AccessToken
}

func TestOIDCVerifier_RealKeycloakIssuer(t *testing.T) {
	testutil.SkipIfNoDocker(t)
	if testing.Short() {
		t.Skip("keycloak container is heavy; skipped in -short")
	}

	base := startKeycloak(t)
	issuer := base + "/realms/axonflow"
	jwksURI := issuer + "/protocol/openid-connect/certs"
	ctx := context.Background()

	cfg := &OIDCConfig{
		OrgID:      "org-fleet",
		Issuer:     issuer,
		Audience:   "axonflow-platform",
		JWKSURI:    jwksURI,
		EmailClaim: "email",
	}
	roles := &stubRoles{role: "developer"}
	verifier := newVerifier(t, cfg, roles)

	token := passwordGrant(t, base, "axonflow-fleet", "fleet-dev", "fleet-dev-password")

	t.Run("real IdP token validates with identity from token, role from directory", func(t *testing.T) {
		id, err := verifier.Validate(ctx, "org-fleet", token)
		if err != nil {
			t.Fatalf("Validate: %v", err)
		}
		if id.Email != "fleet-dev@example.com" {
			t.Fatalf("email = %q, want canonicalized fleet-dev@example.com", id.Email)
		}
		if id.Role != "developer" {
			t.Fatalf("role must come from the directory resolver, got %q", id.Role)
		}
		if !id.Validated || id.Source != ValidatorNameOIDC {
			t.Fatalf("unexpected identity: %+v", id)
		}
		if roles.email != "fleet-dev@example.com" || roles.orgID != "org-fleet" {
			t.Fatalf("role resolver keyed on %q/%q", roles.orgID, roles.email)
		}
	})

	t.Run("tampered payload rejected", func(t *testing.T) {
		parts := strings.Split(token, ".")
		if len(parts) != 3 {
			t.Fatalf("unexpected JWT shape")
		}
		// Flip a byte in the payload; the real signature no longer matches.
		payload := []rune(parts[1])
		if payload[10] == 'A' {
			payload[10] = 'B'
		} else {
			payload[10] = 'A'
		}
		tampered := parts[0] + "." + string(payload) + "." + parts[2]
		if _, err := verifier.Validate(ctx, "org-fleet", tampered); err == nil {
			t.Fatal("tampered token must be rejected")
		}
	})

	t.Run("wrong audience rejected", func(t *testing.T) {
		wrongAud := &OIDCConfig{OrgID: "org-fleet", Issuer: issuer, Audience: "some-other-api", JWKSURI: jwksURI, EmailClaim: "email"}
		v := newVerifier(t, wrongAud, roles)
		if _, err := v.Validate(ctx, "org-fleet", token); err == nil {
			t.Fatal("a token for another audience must be rejected")
		}
	})

	t.Run("wrong issuer rejected", func(t *testing.T) {
		wrongIss := &OIDCConfig{OrgID: "org-fleet", Issuer: issuer + "-evil", Audience: "axonflow-platform", JWKSURI: jwksURI, EmailClaim: "email"}
		v := newVerifier(t, wrongIss, roles)
		if _, err := v.Validate(ctx, "org-fleet", token); err == nil {
			t.Fatal("a token from another issuer must be rejected")
		}
	})

	t.Run("expired real token rejected", func(t *testing.T) {
		// The -short client's access.token.lifespan is 1s: Keycloak stamps a
		// REAL exp one second out. Validate with a tight-leeway verifier
		// (production option) after the second passes.
		expToken := passwordGrant(t, base, "axonflow-fleet-short", "fleet-dev", "fleet-dev-password")
		tight, err := NewOIDCVerifier(&stubConfigs{cfg: cfg}, roles, WithOIDCLeeway(0))
		if err != nil {
			t.Fatalf("NewOIDCVerifier: %v", err)
		}
		time.Sleep(3 * time.Second)
		if _, err := tight.Validate(ctx, "org-fleet", expToken); err == nil {
			t.Fatal("an expired real-issuer token must be rejected")
		}
	})

	t.Run("wrong password yields no token (issuer-side auth works)", func(t *testing.T) {
		form := url.Values{
			"grant_type": {"password"}, "client_id": {"axonflow-fleet"},
			"username": {"fleet-dev"}, "password": {"wrong"},
		}
		resp, err := http.PostForm(base+"/realms/axonflow/protocol/openid-connect/token", form)
		if err != nil {
			t.Fatalf("token request: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode == http.StatusOK {
			t.Fatal("keycloak must reject a wrong password")
		}
	})
}
