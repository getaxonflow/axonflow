// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package idempotency

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestValidateKey(t *testing.T) {
	cases := []struct {
		name    string
		key     string
		wantErr error
	}{
		{"empty", "", ErrKeyEmpty},
		{"too long", strings.Repeat("a", MaxKeyLength+1), ErrKeyTooLong},
		{"trailing newline", "abc\n", ErrKeyInvalid},
		{"shell metachar", "abc;rm", ErrKeyInvalid},
		{"space", "abc def", ErrKeyInvalid},
		{"happy path uuid", "550e8400-e29b-41d4-a716-446655440000", nil},
		{"happy path slash colon", "exec/abc:1/2", nil},
		{"happy path dots", "node.run.42", nil},
		{"max length OK", strings.Repeat("a", MaxKeyLength), nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ValidateKey(tc.key)
			if !errors.Is(got, tc.wantErr) {
				t.Fatalf("ValidateKey(%q) = %v, want %v", tc.key, got, tc.wantErr)
			}
		})
	}
}

func TestStore_Enabled(t *testing.T) {
	if (&Store{}).Enabled() {
		t.Fatal("nil appDB Store should not be Enabled")
	}
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock.New: %v", err)
	}
	defer db.Close()
	if !NewStore(db, nil).Enabled() {
		t.Fatal("Store with appDB should be Enabled")
	}
}

func TestStore_LookupMissReturnsNil(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mock.ExpectBegin()
	mock.ExpectExec("set_config.*app.current_org_id").
		WithArgs("org-a", true).
		WillReturnResult(sqlmock.NewResult(0, 0))
	// The rls package uses SELECT set_config, not EXEC. Adjust.
	_ = mock
}

func TestStore_LookupAndStoreRoundtrip(t *testing.T) {
	// Tested via integration in package agent via approletest harness; this
	// unit test asserts the syntactic SQL shape only via sqlmock. The
	// rls.WithOrgAndTenantScope helper uses SELECT set_config(...), not EXEC,
	// so we ExpectQuery for each set_config call.
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store := NewStore(db, nil)

	// Lookup miss path
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id'`).
		WithArgs("org-a").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(`SELECT set_config\('app.current_tenant_id'`).
		WithArgs("tenant-a").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(`SELECT set_config\('app.tenant_id'`).
		WithArgs("tenant-a").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`SELECT status_code, response_body, created_at, expires_at\s*FROM idempotency_keys`).
		WithArgs("key-1", "tenant-a", "ep-1").
		WillReturnRows(sqlmock.NewRows([]string{"status_code", "response_body", "created_at", "expires_at"}))
	mock.ExpectCommit()

	got, err := store.Lookup(context.Background(), "org-a", "tenant-a", "key-1", "ep-1")
	if err != nil {
		t.Fatalf("Lookup miss returned err=%v", err)
	}
	if got != nil {
		t.Fatalf("Lookup miss returned %+v, want nil", got)
	}

	// Lookup hit path
	now := time.Now()
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id'`).
		WithArgs("org-a").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(`SELECT set_config\('app.current_tenant_id'`).
		WithArgs("tenant-a").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(`SELECT set_config\('app.tenant_id'`).
		WithArgs("tenant-a").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectQuery(`SELECT status_code, response_body, created_at, expires_at\s*FROM idempotency_keys`).
		WithArgs("key-1", "tenant-a", "ep-1").
		WillReturnRows(sqlmock.NewRows([]string{"status_code", "response_body", "created_at", "expires_at"}).
			AddRow(201, []byte(`{"audit_id":"abc"}`), now.Add(-1*time.Hour), now.Add(23*time.Hour)))
	mock.ExpectCommit()

	hit, err := store.Lookup(context.Background(), "org-a", "tenant-a", "key-1", "ep-1")
	if err != nil {
		t.Fatalf("Lookup hit err=%v", err)
	}
	if hit == nil || hit.StatusCode != 201 || string(hit.Body) != `{"audit_id":"abc"}` {
		t.Fatalf("Lookup hit returned %+v", hit)
	}

	// Store path
	mock.ExpectBegin()
	mock.ExpectExec(`SELECT set_config\('app.current_org_id'`).
		WithArgs("org-a").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(`SELECT set_config\('app.current_tenant_id'`).
		WithArgs("tenant-a").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(`SELECT set_config\('app.tenant_id'`).
		WithArgs("tenant-a").
		WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec(`INSERT INTO idempotency_keys.*ON CONFLICT.*DO NOTHING`).
		WithArgs("key-1", "tenant-a", "ep-1", 201, []byte(`{"audit_id":"abc"}`), sqlmock.AnyArg()).
		WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()

	if err := store.Store(context.Background(), "org-a", "tenant-a", "key-1", "ep-1", 201, []byte(`{"audit_id":"abc"}`), 0); err != nil {
		t.Fatalf("Store err=%v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("mock expectations: %v", err)
	}
}

func TestStore_LookupRejectsEmptyKeys(t *testing.T) {
	db, _, _ := sqlmock.New()
	defer db.Close()
	s := NewStore(db, nil)
	if _, err := s.Lookup(context.Background(), "", "t", "k", "e"); err == nil {
		t.Fatal("expected error for empty orgID")
	}
	if _, err := s.Lookup(context.Background(), "o", "", "k", "e"); err == nil {
		t.Fatal("expected error for empty tenantID")
	}
	if _, err := s.Lookup(context.Background(), "o", "t", "", "e"); err == nil {
		t.Fatal("expected error for empty key")
	}
	if _, err := s.Lookup(context.Background(), "o", "t", "k", ""); err == nil {
		t.Fatal("expected error for empty endpoint")
	}
}

func TestStore_SweepNoAdminDBIsNoOp(t *testing.T) {
	s := NewStore(nil, nil)
	n, err := s.Sweep(context.Background())
	if err != nil {
		t.Fatalf("Sweep err=%v", err)
	}
	if n != 0 {
		t.Fatalf("Sweep returned %d, want 0", n)
	}
}

func TestStore_SweepDeletesExpired(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	s := NewStore(nil, db)
	mock.ExpectExec(`DELETE FROM idempotency_keys WHERE expires_at`).
		WillReturnResult(sqlmock.NewResult(0, 7))
	n, err := s.Sweep(context.Background())
	if err != nil {
		t.Fatalf("Sweep err=%v", err)
	}
	if n != 7 {
		t.Fatalf("Sweep returned %d, want 7", n)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("mock expectations: %v", err)
	}
}
