//go:build enterprise

// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package ojk

// Derived retention posture (#3242, epic #2892).
//
// # What this replaces
//
// GetRetentionStatus returned `DataTypes: []OJKDataTypeRetentionStatus{}` -- an
// unconditional empty slice. The published API reference had to say of it: "the
// shape reserves one entry per audit data type ... but the current
// implementation always returns it empty". That is the same silent-empty class
// as the export sections this workstream fixes, in the same file: a compliance
// team asking "is this audit window fully defensible?" got a successful,
// structurally-correct, contentless answer.
//
// Each entry is now derived: the oldest and newest record the organization
// actually holds for that data type, the row count, and a status computed
// against the Indonesian 5-year floor. A data type whose backing store cannot be
// read reports status "unknown" and is NOT presented as an empty holding.

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"
)

// Retention statuses per data type. `compliant` means the organization's oldest
// record for that type is still inside the configured retention window, so
// nothing has aged out of the required period.
const (
	OJKRetentionCompliant    = "compliant"
	OJKRetentionNoData       = "no_data"
	OJKRetentionShortHistory = "short_history"
	OJKRetentionUnknown      = "unknown"
)

// retentionSource describes where one data type's records live and which column
// carries their timestamp. Keeping it as data means the retention view and the
// export sections cannot drift about what "a policy violation" is.
type retentionSource struct {
	table string
	// tsColumn is the timestamp the retention window is measured on.
	tsColumn string
	// filter is an optional extra predicate (the audit_logs-backed types share
	// one table and are distinguished by a predicate).
	filter string
	// rlsWrapped is true when the table is RLS-gated and the read must run
	// inside withOrgScope. An unwrapped read of one of these returns silent zero
	// rows under axonflow_app_role -- which would report a real holding as
	// "no_data".
	rlsWrapped bool
}

// ojkRetentionSources maps each data type to its backing store. Its key set is
// ojkAllDataTypes(); TestEveryDataTypeHasARetentionSource enforces that, so a
// new data type cannot appear in exports while silently missing from the
// retention view.
func ojkRetentionSources() map[OJKAuditDataType]retentionSource {
	return map[OJKAuditDataType]retentionSource{
		OJKDataTypePolicyViolations: {
			table: "audit_logs", tsColumn: "timestamp",
			filter: "policy_decision IN ('blocked', 'redacted', 'needs_approval')",
		},
		OJKDataTypeLLMCalls: {
			table: "audit_logs", tsColumn: "timestamp",
			filter: "COALESCE(plane, policy_details->>'plane') = 'llm'",
		},
		OJKDataTypeDecisionChain: {
			table: "audit_logs", tsColumn: "timestamp",
			filter: "COALESCE(decision_id, policy_details->>'decision_id') IS NOT NULL",
		},
		OJKDataTypeHITLOversight: {
			table: "hitl_approval_queue", tsColumn: "created_at",
			filter: "reviewed_at IS NOT NULL", rlsWrapped: true,
		},
		OJKDataTypePIIRedactions: {
			table: "indonesia_pii_detection_events", tsColumn: "detected_at",
			rlsWrapped: true,
		},
		OJKDataTypeCrossBorder: {
			table: "audit_logs", tsColumn: "timestamp",
			filter: "transfer_basis IS NOT NULL AND transfer_basis <> ''",
		},
		OJKDataTypeBreachNotify: {
			table: "ojk_breach_notifications", tsColumn: "discovery_time",
			rlsWrapped: true,
		},
	}
}

// GetRetentionStatus returns the organization's retention posture, per data
// type. orgID is the resolved organization (resolveOrgID).
//
// req.DataTypes narrows the report; an empty list means every data type. An
// unknown data type is reported explicitly with status "unknown" and a
// self-describing entry, never dropped.
func (s *ojkAuditExportServiceImpl) GetRetentionStatus(ctx context.Context, orgID string, req *OJKRetentionStatusRequest) (*OJKRetentionStatusResponse, error) {
	if strings.TrimSpace(orgID) == "" {
		return nil, errOrgScopeRequired
	}
	if s.db == nil {
		return nil, fmt.Errorf("database connection not available")
	}

	retentionDays := s.getEffectiveRetentionDays()
	sources := ojkRetentionSources()

	requested := req.DataTypes
	if len(requested) == 0 {
		requested = ojkAllDataTypes()
	} else if len(requested) == 1 && requested[0] == OJKDataTypeAll {
		requested = ojkAllDataTypes()
	}

	cutoff := time.Now().UTC().AddDate(0, 0, -retentionDays)
	entries := make([]OJKDataTypeRetentionStatus, 0, len(requested))
	seen := make(map[OJKAuditDataType]bool, len(requested))

	for _, dt := range requested {
		if dt == OJKDataTypeAll || seen[dt] {
			continue
		}
		seen[dt] = true

		entry := OJKDataTypeRetentionStatus{DataType: dt}
		src, known := sources[dt]
		if !known {
			// EXPLICIT, mirroring the export dispatcher: an unrecognised data
			// type names itself rather than vanishing from the report.
			entry.Status = OJKRetentionUnknown
			entries = append(entries, entry)
			continue
		}

		count, oldest, newest, err := s.retentionWindowFor(ctx, orgID, src)
		if err != nil {
			// Missing table or unreadable store: "unknown", never "no_data".
			// Reporting an unreadable holding as empty is how a compliance team
			// concludes an audit window is defensible when nothing was checked.
			entry.Status = OJKRetentionUnknown
			entries = append(entries, entry)
			continue
		}

		entry.TotalRecords = count
		if oldest.Valid {
			o := oldest.Time.UTC()
			entry.OldestRecord = &o
		}
		if newest.Valid {
			n := newest.Time.UTC()
			entry.NewestRecord = &n
		}

		switch {
		case count == 0:
			entry.Status = OJKRetentionNoData
		case oldest.Valid && oldest.Time.UTC().After(cutoff):
			// The organization's whole history is newer than the retention
			// floor. That is NOT non-compliance -- a young deployment cannot
			// have five years of records -- but it is not proof of a five-year
			// window either, so it gets its own honest label.
			entry.Status = OJKRetentionShortHistory
		default:
			entry.Status = OJKRetentionCompliant
		}
		entries = append(entries, entry)
	}

	status := OJKRetentionCompliant
	if retentionDays < IndonesiaRetentionDays {
		status = "non_compliant"
	}

	return &OJKRetentionStatusResponse{
		ComplianceStatus: status,
		Framework:        OJKFrameworkCombined,
		RetentionDays:    retentionDays,
		MinRetentionDays: IndonesiaRetentionDays,
		DataTypes:        entries,
	}, nil
}

// retentionWindowFor returns (count, oldest, newest) for one data type, scoped
// to the organization.
//
// The SQL is assembled from the retentionSource TABLE and COLUMN NAMES, which
// are compile-time constants in this file -- never from request input. The
// organization is always a bound parameter.
func (s *ojkAuditExportServiceImpl) retentionWindowFor(ctx context.Context, orgID string, src retentionSource) (int64, sql.NullTime, sql.NullTime, error) {
	var (
		count  int64
		oldest sql.NullTime
		newest sql.NullTime
	)

	// The audit_logs-backed sources use the SAME shared predicate as the export
	// queries, so the retention view and the report can never disagree about
	// which rows belong to the caller. The RLS-gated tables are org_id-keyed
	// with a NOT NULL column, so they take the simple predicate.
	where := "org_id = $1"
	if src.table == "audit_logs" {
		where = ojkOrgPredicate
	}
	if src.filter != "" {
		where += " AND " + src.filter
	}
	query := fmt.Sprintf(
		"SELECT COUNT(*), MIN(%s), MAX(%s) FROM %s WHERE %s",
		src.tsColumn, src.tsColumn, src.table, where,
	)

	scan := func(row *sql.Row) error { return row.Scan(&count, &oldest, &newest) }

	var err error
	if src.rlsWrapped {
		err = withOrgScope(ctx, s.db, orgID, func(tx *sql.Tx) error {
			return scan(tx.QueryRowContext(ctx, query, orgID))
		})
	} else {
		err = scan(s.db.QueryRowContext(ctx, query, orgID))
	}
	if err != nil {
		return 0, oldest, newest, err
	}
	return count, oldest, newest, nil
}
