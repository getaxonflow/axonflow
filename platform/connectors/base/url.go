// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package base

import (
	"fmt"
	"net/url"
	"strings"
)

// BuildConnectionURL constructs a connection URL from connector type, options, and credentials.
// Credentials are properly URL-encoded to handle special characters.
// Pass nil credentials to build a credential-free URL suitable for storage.
func BuildConnectionURL(connectorType string, options map[string]interface{}, credentials map[string]string) string {
	// If connection_url is explicitly provided, use it.
	// When credentials is nil (storage path), strip userinfo to avoid persisting secrets.
	if connURL, ok := options["connection_url"].(string); ok && connURL != "" {
		if credentials == nil {
			return StripURLCredentials(connURL)
		}
		return connURL
	}

	host := GetStringOption(options, "host", "localhost")
	database := GetStringOption(options, "database", "")

	var username, password string
	if credentials != nil {
		username = credentials["username"]
		password = credentials["password"]
	}

	switch connectorType {
	case "postgres":
		port := GetIntOption(options, "port", 5432)
		sslMode := GetStringOption(options, "ssl_mode", "")
		if sslMode == "" {
			sslMode = GetStringOption(options, "sslmode", "disable")
		}
		return BuildPostgresURL(host, port, database, username, password, sslMode)

	case "mysql":
		port := GetIntOption(options, "port", 3306)
		return BuildMySQLURL(host, port, database, username, password)

	case "mongodb":
		port := GetIntOption(options, "port", 27017)
		authSource := GetStringOption(options, "auth_source", "")
		return BuildMongoDBURL(host, port, database, username, password, authSource)

	case "redis":
		port := GetIntOption(options, "port", 6379)
		db := GetIntOption(options, "db", 0)
		return BuildRedisURL(host, port, db, password)

	case "cassandra":
		port := GetIntOption(options, "port", 9042)
		keyspace := GetStringOption(options, "keyspace", database)
		return BuildCassandraURL(host, port, keyspace, username, password)

	default:
		if baseURL, ok := options["base_url"].(string); ok {
			return baseURL
		}
		return ""
	}
}

// BuildPostgresURL constructs a PostgreSQL connection URL with proper encoding.
func BuildPostgresURL(host string, port int, database, username, password, sslMode string) string {
	u := &url.URL{
		Scheme: "postgres",
		Host:   fmt.Sprintf("%s:%d", host, port),
		Path:   "/" + database,
	}
	if username != "" && password != "" {
		u.User = url.UserPassword(username, password)
	} else if username != "" {
		u.User = url.User(username)
	}
	q := u.Query()
	q.Set("sslmode", sslMode)
	u.RawQuery = q.Encode()
	return u.String()
}

// BuildMySQLURL constructs a MySQL DSN with proper encoding.
// MySQL DSN format: [username[:password]@][protocol[(address)]]/dbname
func BuildMySQLURL(host string, port int, database, username, password string) string {
	if username != "" && password != "" {
		return fmt.Sprintf("%s:%s@tcp(%s:%d)/%s",
			url.QueryEscape(username),
			url.QueryEscape(password),
			host, port, database)
	}
	if username != "" {
		return fmt.Sprintf("%s@tcp(%s:%d)/%s", url.QueryEscape(username), host, port, database)
	}
	return fmt.Sprintf("tcp(%s:%d)/%s", host, port, database)
}

// BuildMongoDBURL constructs a MongoDB connection URL with proper encoding.
func BuildMongoDBURL(host string, port int, database, username, password, authSource string) string {
	u := &url.URL{
		Scheme: "mongodb",
		Host:   fmt.Sprintf("%s:%d", host, port),
		Path:   "/" + database,
	}
	if username != "" && password != "" {
		u.User = url.UserPassword(username, password)
	} else if username != "" {
		u.User = url.User(username)
	}
	if authSource != "" {
		q := u.Query()
		q.Set("authSource", authSource)
		u.RawQuery = q.Encode()
	}
	return u.String()
}

// BuildRedisURL constructs a Redis connection URL with proper encoding.
func BuildRedisURL(host string, port, db int, password string) string {
	u := &url.URL{
		Scheme: "redis",
		Host:   fmt.Sprintf("%s:%d", host, port),
		Path:   fmt.Sprintf("/%d", db),
	}
	if password != "" {
		u.User = url.UserPassword("", password)
	}
	return u.String()
}

// BuildCassandraURL constructs a Cassandra connection URL.
func BuildCassandraURL(host string, port int, keyspace, username, password string) string {
	u := &url.URL{
		Scheme: "cassandra",
		Host:   fmt.Sprintf("%s:%d", host, port),
		Path:   "/" + keyspace,
	}
	if username != "" && password != "" {
		u.User = url.UserPassword(username, password)
	} else if username != "" {
		u.User = url.User(username)
	}
	return u.String()
}

// GetStringOption safely extracts a string from options map (nil-safe).
func GetStringOption(options map[string]interface{}, key, defaultVal string) string {
	if options == nil {
		return defaultVal
	}
	if val, ok := options[key].(string); ok {
		return val
	}
	return defaultVal
}

// GetIntOption safely extracts an int from options map (handles float64 from JSON, nil-safe).
func GetIntOption(options map[string]interface{}, key string, defaultVal int) int {
	if options == nil {
		return defaultVal
	}
	if val, ok := options[key].(float64); ok {
		return int(val)
	}
	if val, ok := options[key].(int); ok {
		return val
	}
	return defaultVal
}

// StripURLCredentials removes userinfo (username:password) from a URL.
// Handles both standard URLs (postgres://, mongodb://) and MySQL DSN format
// (user:pass@tcp(host:port)/db).
func StripURLCredentials(rawURL string) string {
	if rawURL == "" {
		return rawURL
	}

	// MySQL DSN format: user:pass@tcp(host:port)/db or user@tcp(host:port)/db
	// Must check before url.Parse, which misparses DSNs as opaque URIs.
	if idx := strings.Index(rawURL, "@tcp("); idx >= 0 {
		return rawURL[idx+1:] // Strip everything before and including @
	}
	if idx := strings.Index(rawURL, "@unix("); idx >= 0 {
		return rawURL[idx+1:]
	}

	// Standard URL with scheme (postgres://, mongodb://, https://)
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme == "" {
		return rawURL
	}
	u.User = nil
	return u.String()
}
