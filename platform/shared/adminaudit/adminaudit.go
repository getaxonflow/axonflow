// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

// Package adminaudit is the one writer of admin_audit_log. Every row the
// customer portal records for a privileged mutation goes through Insert, and
// so does the row the Community SaaS registration records for the detection
// posture it gives a new organization (#4017). There is no second INSERT:
// TestInsertIsTheOnlyWriterOfTheTable holds that.
//
// WHERE THE TABLE EXISTS. migrations/enterprise/113 creates it, and
// migrations/community-saas/088 creates it with the same DDL. The
// community-saas fleet runs the enterprise-tagged binary against the
// community-saas schema, which applies core + community-saas and NOT the
// enterprise chain, so nothing here may assume the enterprise chain ran. A
// Community deployment (core only) has no such table, and no Community code
// path reaches Insert.
//
// NO ORG SCOPE. The table is not row-level secured, so Insert writes on
// whatever connection or transaction it is given. A caller whose row must
// commit with the change it records passes that change's transaction.
package adminaudit

import (
	"context"
	"database/sql"
	"encoding/json"
	"net"
	"net/netip"
	"strings"
)

// Execer is what Insert writes through: a *sql.DB, *sql.Conn or *sql.Tx.
type Execer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

// UnknownActor is the admin_identifier recorded for an Entry that names no
// actor.
const UnknownActor = "unknown"

// Entry is one admin_audit_log row. Every field is non-secret control data:
// no licence key, password, token or credential is ever carried here.
type Entry struct {
	// Action is the queryable action label. The column is an open
	// VARCHAR(50) with no CHECK, so the vocabulary lives with each writer.
	Action string
	// OrgID is the target organization. Empty records a system-wide action
	// as NULL.
	OrgID string
	// Identifier names the actor: an operator, an API-key prefix, or a
	// "system:" identity for an automated action. Empty is UnknownActor.
	Identifier string
	// IPAddress is the source address, in any form CanonicalIP accepts. One
	// that holds no address is stored as NULL rather than losing the row.
	IPAddress string
	// UserAgent is the HTTP User-Agent. Empty is NULL.
	UserAgent string
	// Details is action-specific data. Nil, or a value that does not
	// marshal, is NULL.
	Details map[string]any
	// Success records whether the action succeeded.
	Success bool
	// ErrorMessage is a fixed label for a failed action. Empty is NULL.
	ErrorMessage string
}

const insertSQL = `INSERT INTO admin_audit_log (
		action, org_id, admin_identifier, details,
		ip_address, user_agent, success, error_message
	) VALUES ($1, $2, $3, $4::jsonb, $5::inet, $6, $7, $8)`

// Insert writes e as one admin_audit_log row through db and returns the
// database's error. Whether a lost row fails the caller's action is the
// caller's decision: the portal's best-effort writer reports the loss and
// carries on, and a posture change writes its row in its own transaction, so
// the change does not commit without it.
func Insert(ctx context.Context, db Execer, e Entry) error {
	identifier := e.Identifier
	if identifier == "" {
		identifier = UnknownActor
	}
	var details sql.NullString
	if e.Details != nil {
		if b, err := json.Marshal(e.Details); err == nil && string(b) != "null" {
			details = sql.NullString{String: string(b), Valid: true}
		}
	}
	_, err := db.ExecContext(ctx, insertSQL,
		e.Action,
		nullString(e.OrgID),
		identifier,
		details,
		NullIP(e.IPAddress),
		nullString(e.UserAgent),
		e.Success,
		nullString(e.ErrorMessage),
	)
	return err
}

// NullIP is the parameter an ip_address column is written with: the canonical
// form of ip, or NULL when ip holds no address. PostgreSQL's inet refuses both
// "" and a malformed value, and a writer that passes either loses its row.
func NullIP(ip string) sql.NullString {
	canonical := CanonicalIP(ip)
	return sql.NullString{String: canonical, Valid: canonical != ""}
}

// CanonicalIP returns the canonical text of the address in s, or "" when s
// holds none. s may carry surrounding whitespace, a port ("192.0.2.1:8080",
// "[2001:db8::1]:8080"), an IPv6 zone, which is dropped because inet has none,
// or an IPv4-mapped IPv6 form, which is returned as IPv4. Anything else is "".
// So a non-empty result always casts to inet, and it fits the portal's
// sso_login_attempts.ip_address VARCHAR(50).
func CanonicalIP(s string) string {
	s = strings.TrimSpace(s)
	if host, _, err := net.SplitHostPort(s); err == nil {
		s = host
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return ""
	}
	return addr.WithZone("").Unmap().String()
}

func nullString(s string) sql.NullString {
	return sql.NullString{String: s, Valid: s != ""}
}
