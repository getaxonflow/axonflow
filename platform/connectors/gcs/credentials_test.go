// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package gcs

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"axonflow/platform/connectors/base"
)

// #3645: the connector loads credentials by TYPE through cloud.google.com/go/auth.
// These tests exercise clientOptions without a network: a service-account
// credential builds a token provider lazily, so construction never calls
// Google, and every refusal here is a parse- or type-time refusal. The private
// key itself is parsed at the first token request, as it was under the
// deprecated helpers, so a malformed PEM is NOT a construction-time refusal and
// is deliberately not asserted as one.

// serviceAccountJSON is a syntactically complete service-account key with a
// freshly generated RSA private key. The key is never used to sign anything
// in these tests; it exists because the loader parses the PEM at construction
// and a placeholder string is refused as malformed, which would make the
// positive cases below fail for the wrong reason.
func serviceAccountJSON(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}
	pemKey := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	doc := map[string]string{
		"type":                        "service_account",
		"project_id":                  "axonflow-test",
		"private_key_id":              "k1",
		"private_key":                 string(pemKey),
		"client_email":                "connector@axonflow-test.iam.gserviceaccount.com",
		"client_id":                   "1",
		"auth_uri":                    "https://accounts.google.com/o/oauth2/auth",
		"token_uri":                   "https://oauth2.googleapis.com/token",
		"auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
		"client_x509_cert_url":        "https://www.googleapis.com/robot/v1/metadata/x509/connector%40axonflow-test.iam.gserviceaccount.com",
	}
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	return string(b)
}

func writeTemp(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "creds.json")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("writing %s: %v", path, err)
	}
	return path
}

// configuredConnector runs the BaseConnector's Connect so GetCredential and
// GetStringOption read the configuration, without opening a storage client.
func configuredConnector(t *testing.T, creds map[string]string, options map[string]interface{}) *GCSConnector {
	t.Helper()
	conn := NewGCSConnector()
	cfg := &base.ConnectorConfig{Name: "gcs-under-test", Type: "gcs", Credentials: creds, Options: options}
	if err := conn.BaseConnector.Connect(t.Context(), cfg); err != nil {
		t.Fatalf("BaseConnector.Connect: %v", err)
	}
	return conn
}

func TestClientOptionsLoadsServiceAccountCredentials(t *testing.T) {
	sa := serviceAccountJSON(t)

	t.Run("credentials_json service account", func(t *testing.T) {
		conn := configuredConnector(t, map[string]string{"credentials_json": sa}, nil)
		opts, err := conn.clientOptions()
		if err != nil {
			t.Fatalf("a valid service-account key was refused: %v", err)
		}
		if len(opts) != 1 {
			t.Fatalf("got %d option(s), want exactly the credentials option", len(opts))
		}
	})

	t.Run("credentials_file service account", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "sa.json")
		if err := os.WriteFile(path, []byte(sa), 0o600); err != nil {
			t.Fatalf("writing the key file: %v", err)
		}
		conn := configuredConnector(t, map[string]string{"credentials_file": path}, nil)
		opts, err := conn.clientOptions()
		if err != nil {
			t.Fatalf("a valid service-account key file was refused: %v", err)
		}
		if len(opts) != 1 {
			t.Fatalf("got %d option(s), want exactly the credentials option", len(opts))
		}
	})

	t.Run("no credentials means Application Default Credentials: no auth option", func(t *testing.T) {
		conn := configuredConnector(t, nil, nil)
		opts, err := conn.clientOptions()
		if err != nil {
			t.Fatalf("no credentials must not be an error (ADC is the documented default): %v", err)
		}
		if len(opts) != 0 {
			t.Fatalf("got %d option(s), want none", len(opts))
		}
	})

	t.Run("endpoint adds the emulator option beside the credentials", func(t *testing.T) {
		conn := configuredConnector(t, map[string]string{"credentials_json": sa}, map[string]interface{}{"endpoint": "http://localhost:4443/storage/v1/"})
		opts, err := conn.clientOptions()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(opts) != 2 {
			t.Fatalf("got %d option(s), want credentials + endpoint", len(opts))
		}
	})

	t.Run("both set: the file wins, as before, and nothing is refused", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "sa.json")
		if err := os.WriteFile(path, []byte(sa), 0o600); err != nil {
			t.Fatalf("writing the key file: %v", err)
		}
		// The JSON is deliberately NOT a service account: if the file did not
		// win, this would be refused, which is how the precedence is observable.
		conn := configuredConnector(t, map[string]string{"credentials_file": path, "credentials_json": `{"type":"authorized_user"}`}, nil)
		if _, err := conn.clientOptions(); err != nil {
			t.Fatalf("credentials_file must take precedence over credentials_json: %v", err)
		}
	})
}

func TestClientOptionsRefusesWhatItCannotVouchFor(t *testing.T) {
	cases := []struct {
		name  string
		creds map[string]string
		want  string
	}{
		{
			name:  "credentials_json of another type",
			creds: map[string]string{"credentials_json": `{"type":"authorized_user","client_id":"x","client_secret":"y","refresh_token":"z"}`},
			want:  "credentials_json:",
		},
		{
			name:  "credentials_json that is not JSON",
			creds: map[string]string{"credentials_json": `{not json`},
			want:  "credentials_json:",
		},
		{
			name:  "credentials_file that does not exist is refused at Connect, not on the first request",
			creds: map[string]string{"credentials_file": filepath.Join(os.TempDir(), "axonflow-gcs-missing", "sa.json")},
			want:  "credentials_file:",
		},
		{
			name:  "credentials_file of another type",
			creds: map[string]string{"credentials_file": writeTemp(t, `{"type":"authorized_user"}`)},
			want:  "credentials_file:",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			conn := configuredConnector(t, tc.creds, nil)
			opts, err := conn.clientOptions()
			if err == nil {
				t.Fatalf("accepted (%d option(s)); the loader must refuse a credential it cannot vouch for", len(opts))
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not name the input %q", err, tc.want)
			}
			if strings.Contains(err.Error(), "expected type") && !strings.Contains(err.Error(), "service-account keys only") {
				t.Errorf("a type refusal %q does not tell the operator what the connector accepts and how to use another credential type", err)
			}
		})
	}

	t.Run("a type refusal names the type it found", func(t *testing.T) {
		conn := configuredConnector(t, map[string]string{"credentials_json": `{"type":"external_account"}`}, nil)
		_, err := conn.clientOptions()
		if err == nil {
			t.Fatal("an external_account configuration was accepted as a service account")
		}
		if !strings.Contains(err.Error(), "external_account") && !strings.Contains(err.Error(), "service_account") {
			t.Errorf("error %q says neither what it found nor what it wanted", err)
		}
	})
}

// TestConnectReportsACredentialRefusalAsAConfigurationError pins the wiring:
// Connect turns a clientOptions refusal into a connector error before any
// client is built, so an operator sees "invalid GCS credentials configuration"
// rather than a failure on the first request.
func TestConnectReportsACredentialRefusalAsAConfigurationError(t *testing.T) {
	conn := NewGCSConnector()
	cfg := &base.ConnectorConfig{
		Name: "gcs-bad-creds", Type: "gcs",
		Credentials: map[string]string{"credentials_json": `{"type":"authorized_user"}`},
	}
	err := conn.Connect(t.Context(), cfg)
	if err == nil {
		t.Fatal("Connect accepted a credential the loader refuses")
	}
	if !strings.Contains(err.Error(), "invalid GCS credentials configuration") {
		t.Errorf("error %q does not name the configuration as the cause", err)
	}
	if conn.client != nil {
		t.Error("a client was built despite the refusal")
	}
}
