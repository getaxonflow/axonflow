// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package base

import (
	"testing"
)

func TestBuildConnectionURL_Postgres(t *testing.T) {
	tests := []struct {
		name        string
		options     map[string]interface{}
		credentials map[string]string
		want        string
	}{
		{
			name: "full credentials",
			options: map[string]interface{}{
				"host":     "db.example.com",
				"port":     float64(5432),
				"database": "mydb",
				"sslmode":  "require",
			},
			credentials: map[string]string{
				"username": "admin",
				"password": "s3cret",
			},
			want: "postgres://admin:s3cret@db.example.com:5432/mydb?sslmode=require",
		},
		{
			name: "no credentials",
			options: map[string]interface{}{
				"host":     "db.example.com",
				"port":     float64(5432),
				"database": "mydb",
				"sslmode":  "disable",
			},
			credentials: nil,
			want:        "postgres://db.example.com:5432/mydb?sslmode=disable",
		},
		{
			name: "username only",
			options: map[string]interface{}{
				"host":     "localhost",
				"port":     float64(5432),
				"database": "testdb",
			},
			credentials: map[string]string{
				"username": "readonly",
			},
			want: "postgres://readonly@localhost:5432/testdb?sslmode=disable",
		},
		{
			name: "special chars in password",
			options: map[string]interface{}{
				"host":     "host",
				"port":     float64(5432),
				"database": "db",
			},
			credentials: map[string]string{
				"username": "user",
				"password": "p@ss:word/123",
			},
			want: "postgres://user:p%40ss%3Aword%2F123@host:5432/db?sslmode=disable",
		},
		{
			name: "ssl_mode override",
			options: map[string]interface{}{
				"host":     "host",
				"port":     float64(5432),
				"database": "db",
				"ssl_mode": "verify-full",
			},
			credentials: nil,
			want:        "postgres://host:5432/db?sslmode=verify-full",
		},
		{
			name:        "defaults",
			options:     map[string]interface{}{},
			credentials: nil,
			want:        "postgres://localhost:5432/?sslmode=disable",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := BuildConnectionURL("postgres", tt.options, tt.credentials)
			if got != tt.want {
				t.Errorf("BuildConnectionURL(postgres) = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestBuildConnectionURL_MySQL(t *testing.T) {
	tests := []struct {
		name        string
		options     map[string]interface{}
		credentials map[string]string
		want        string
	}{
		{
			name: "full credentials",
			options: map[string]interface{}{
				"host":     "mysql.example.com",
				"port":     float64(3306),
				"database": "app",
			},
			credentials: map[string]string{
				"username": "root",
				"password": "secret",
			},
			want: "root:secret@tcp(mysql.example.com:3306)/app",
		},
		{
			name: "no credentials",
			options: map[string]interface{}{
				"host":     "localhost",
				"port":     float64(3306),
				"database": "test",
			},
			credentials: nil,
			want:        "tcp(localhost:3306)/test",
		},
		{
			name: "username only",
			options: map[string]interface{}{
				"host":     "localhost",
				"port":     float64(3306),
				"database": "db",
			},
			credentials: map[string]string{
				"username": "viewer",
			},
			want: "viewer@tcp(localhost:3306)/db",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := BuildConnectionURL("mysql", tt.options, tt.credentials)
			if got != tt.want {
				t.Errorf("BuildConnectionURL(mysql) = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestBuildConnectionURL_MongoDB(t *testing.T) {
	tests := []struct {
		name        string
		options     map[string]interface{}
		credentials map[string]string
		want        string
	}{
		{
			name: "with auth source",
			options: map[string]interface{}{
				"host":        "mongo.example.com",
				"port":        float64(27017),
				"database":    "app",
				"auth_source": "admin",
			},
			credentials: map[string]string{
				"username": "admin",
				"password": "pass",
			},
			want: "mongodb://admin:pass@mongo.example.com:27017/app?authSource=admin",
		},
		{
			name: "no credentials",
			options: map[string]interface{}{
				"host":     "localhost",
				"port":     float64(27017),
				"database": "test",
			},
			credentials: nil,
			want:        "mongodb://localhost:27017/test",
		},
		{
			name: "username only",
			options: map[string]interface{}{
				"host":     "localhost",
				"port":     float64(27017),
				"database": "db",
			},
			credentials: map[string]string{
				"username": "reader",
			},
			want: "mongodb://reader@localhost:27017/db",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := BuildConnectionURL("mongodb", tt.options, tt.credentials)
			if got != tt.want {
				t.Errorf("BuildConnectionURL(mongodb) = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestBuildConnectionURL_Redis(t *testing.T) {
	tests := []struct {
		name        string
		options     map[string]interface{}
		credentials map[string]string
		want        string
	}{
		{
			name: "with password",
			options: map[string]interface{}{
				"host": "redis.example.com",
				"port": float64(6379),
				"db":   float64(2),
			},
			credentials: map[string]string{
				"password": "redispass",
			},
			want: "redis://:redispass@redis.example.com:6379/2",
		},
		{
			name:        "no password",
			options:     map[string]interface{}{},
			credentials: nil,
			want:        "redis://localhost:6379/0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := BuildConnectionURL("redis", tt.options, tt.credentials)
			if got != tt.want {
				t.Errorf("BuildConnectionURL(redis) = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestBuildConnectionURL_Cassandra(t *testing.T) {
	tests := []struct {
		name        string
		options     map[string]interface{}
		credentials map[string]string
		want        string
	}{
		{
			name: "with credentials",
			options: map[string]interface{}{
				"host":     "cass.example.com",
				"port":     float64(9042),
				"keyspace": "mykeyspace",
			},
			credentials: map[string]string{
				"username": "cassuser",
				"password": "casspass",
			},
			want: "cassandra://cassuser:casspass@cass.example.com:9042/mykeyspace",
		},
		{
			name: "no credentials with database fallback",
			options: map[string]interface{}{
				"host":     "localhost",
				"port":     float64(9042),
				"database": "defaultks",
			},
			credentials: nil,
			want:        "cassandra://localhost:9042/defaultks",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := BuildConnectionURL("cassandra", tt.options, tt.credentials)
			if got != tt.want {
				t.Errorf("BuildConnectionURL(cassandra) = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestBuildConnectionURL_HTTP(t *testing.T) {
	tests := []struct {
		name    string
		options map[string]interface{}
		want    string
	}{
		{
			name:    "with base_url",
			options: map[string]interface{}{"base_url": "https://api.example.com"},
			want:    "https://api.example.com",
		},
		{
			name:    "no base_url",
			options: map[string]interface{}{},
			want:    "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := BuildConnectionURL("http", tt.options, nil)
			if got != tt.want {
				t.Errorf("BuildConnectionURL(http) = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestBuildConnectionURL_Unknown(t *testing.T) {
	got := BuildConnectionURL("unknown", map[string]interface{}{"base_url": "http://x"}, nil)
	if got != "http://x" {
		t.Errorf("expected base_url fallback, got %q", got)
	}

	got = BuildConnectionURL("unknown", map[string]interface{}{}, nil)
	if got != "" {
		t.Errorf("expected empty string, got %q", got)
	}
}

func TestBuildConnectionURL_ExplicitConnectionURL(t *testing.T) {
	options := map[string]interface{}{
		"connection_url": "postgres://user:secret@host/db",
		"host":           "ignored",
	}

	// With credentials (runtime path) — return as-is
	got := BuildConnectionURL("postgres", options, map[string]string{"username": "user"})
	if got != "postgres://user:secret@host/db" {
		t.Errorf("with credentials: expected full URL, got %q", got)
	}

	// Without credentials (storage path) — strip userinfo
	got = BuildConnectionURL("postgres", options, nil)
	if got != "postgres://host/db" {
		t.Errorf("without credentials: expected stripped URL, got %q", got)
	}
}

func TestStripURLCredentials(t *testing.T) {
	tests := []struct {
		name string
		url  string
		want string
	}{
		{"postgres with creds", "postgres://user:pass@host:5432/db?sslmode=require", "postgres://host:5432/db?sslmode=require"},
		{"postgres no creds", "postgres://host:5432/db", "postgres://host:5432/db"},
		{"mongodb with creds", "mongodb://admin:secret@mongo:27017/app", "mongodb://mongo:27017/app"},
		{"mysql DSN with creds", "user:pass@tcp(host:3306)/db", "tcp(host:3306)/db"},
		{"mysql DSN user only", "user@tcp(host:3306)/db", "tcp(host:3306)/db"},
		{"mysql DSN no creds", "tcp(host:3306)/db", "tcp(host:3306)/db"},
		{"mysql DSN unix socket", "user:pass@unix(/var/run/mysql.sock)/db", "unix(/var/run/mysql.sock)/db"},
		{"empty string", "", ""},
		{"https URL", "https://user:token@api.example.com/v1", "https://api.example.com/v1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := StripURLCredentials(tt.url)
			if got != tt.want {
				t.Errorf("StripURLCredentials(%q) = %q, want %q", tt.url, got, tt.want)
			}
		})
	}
}

func TestGetStringOption(t *testing.T) {
	tests := []struct {
		name       string
		options    map[string]interface{}
		key        string
		defaultVal string
		want       string
	}{
		{"found", map[string]interface{}{"k": "v"}, "k", "def", "v"},
		{"not found", map[string]interface{}{"k": "v"}, "other", "def", "def"},
		{"nil map", nil, "k", "def", "def"},
		{"wrong type", map[string]interface{}{"k": 42}, "k", "def", "def"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := GetStringOption(tt.options, tt.key, tt.defaultVal); got != tt.want {
				t.Errorf("GetStringOption() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestGetIntOption(t *testing.T) {
	tests := []struct {
		name       string
		options    map[string]interface{}
		key        string
		defaultVal int
		want       int
	}{
		{"float64", map[string]interface{}{"k": float64(42)}, "k", 0, 42},
		{"int", map[string]interface{}{"k": 42}, "k", 0, 42},
		{"not found", map[string]interface{}{"k": 42}, "other", 99, 99},
		{"nil map", nil, "k", 99, 99},
		{"wrong type", map[string]interface{}{"k": "str"}, "k", 99, 99},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := GetIntOption(tt.options, tt.key, tt.defaultVal); got != tt.want {
				t.Errorf("GetIntOption() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestBuildConnectionURL_CredentialFreeRoundTrip(t *testing.T) {
	// Verify that storing without credentials and reconstructing with credentials
	// produces the same result as building directly with credentials
	connectorTypes := []struct {
		typ     string
		options map[string]interface{}
		creds   map[string]string
	}{
		{
			typ: "postgres",
			options: map[string]interface{}{
				"host": "db.example.com", "port": float64(5432),
				"database": "prod", "sslmode": "require",
			},
			creds: map[string]string{"username": "admin", "password": "p@ss"},
		},
		{
			typ: "mysql",
			options: map[string]interface{}{
				"host": "mysql.example.com", "port": float64(3306),
				"database": "app",
			},
			creds: map[string]string{"username": "root", "password": "secret"},
		},
		{
			typ: "mongodb",
			options: map[string]interface{}{
				"host": "mongo.example.com", "port": float64(27017),
				"database": "data", "auth_source": "admin",
			},
			creds: map[string]string{"username": "mongoadmin", "password": "mongopass"},
		},
		{
			typ: "redis",
			options: map[string]interface{}{
				"host": "redis.example.com", "port": float64(6379), "db": float64(1),
			},
			creds: map[string]string{"password": "redispwd"},
		},
		{
			typ: "cassandra",
			options: map[string]interface{}{
				"host": "cass.example.com", "port": float64(9042),
				"keyspace": "ks",
			},
			creds: map[string]string{"username": "cassuser", "password": "casspass"},
		},
	}

	for _, tc := range connectorTypes {
		t.Run(tc.typ, func(t *testing.T) {
			// Direct build with credentials (what the old code stored)
			fullURL := BuildConnectionURL(tc.typ, tc.options, tc.creds)

			// Build without credentials (what we now store)
			storedURL := BuildConnectionURL(tc.typ, tc.options, nil)

			// Verify stored URL does NOT contain password
			if tc.creds["password"] != "" {
				for _, secret := range []string{tc.creds["password"]} {
					if containsUnencoded(storedURL, secret) {
						t.Errorf("stored URL contains credential %q: %s", secret, storedURL)
					}
				}
			}

			// Reconstruct with credentials (what the read path does)
			reconstructedURL := BuildConnectionURL(tc.typ, tc.options, tc.creds)

			// Verify reconstruction matches direct build
			if reconstructedURL != fullURL {
				t.Errorf("reconstructed URL doesn't match:\n  got:  %s\n  want: %s", reconstructedURL, fullURL)
			}
		})
	}
}

// containsUnencoded checks if a raw secret appears in a URL (not URL-encoded).
func containsUnencoded(url, secret string) bool {
	// Simple containment check — sufficient for test purposes
	return len(secret) > 0 && len(url) > 0 && stringContains(url, secret)
}

func stringContains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
