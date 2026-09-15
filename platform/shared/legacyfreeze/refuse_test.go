// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package legacyfreeze

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
)

// captureLog points the standard logger at a buffer for one test.
func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prevOut, prevFlags := log.Writer(), log.Flags()
	log.SetOutput(&buf)
	log.SetFlags(0)
	t.Cleanup(func() {
		log.SetOutput(prevOut)
		log.SetFlags(prevFlags)
	})
	return &buf
}

// TestRefuseAnswersTheTableFreezeAndLogsTheOrganization is #4237's shared
// half: the pre-read refusal answers exactly what Answer answers for the
// database's refusal - one status, one code, one message - and logs one
// countable line per refused request naming the organization, the tenant and
// the route.
func TestRefuseAnswersTheTableFreezeAndLogsTheOrganization(t *testing.T) {
	buf := captureLog(t)
	var calls, status int
	var code, message string
	write := func(w http.ResponseWriter, s int, c, m string) {
		calls++
		status, code, message = s, c, m
		w.WriteHeader(s)
	}
	r := httptest.NewRequest(http.MethodPost, "/api/v1/example-writes/import", nil)
	rr := httptest.NewRecorder()
	Refuse(rr, r, "DynamicPolicyAPI", "ImportPolicies", "org-a", "tenant-a", write)

	if calls != 1 || status != http.StatusConflict || rr.Code != http.StatusConflict {
		t.Fatalf("writer called %d time(s) with status %d (recorder %d), want once with 409", calls, status, rr.Code)
	}
	if code != ErrCode {
		t.Fatalf("code = %q, want %q", code, ErrCode)
	}
	// ONE MESSAGE. The pre-read refusal and the classified refusal of the
	// write are the same fact to a caller, so they are the same sentence.
	if message != Message {
		t.Fatalf("message = %q, want Message (the sentence Answer sends)", message)
	}
	if !strings.Contains(message, TypedAuthoringRoute) {
		t.Fatalf("the refusal does not name the typed authoring route: %q", message)
	}
	line := buf.String()
	if n := strings.Count(line, RefusedPrefix); n != 1 {
		t.Fatalf("logged %d refusal line(s), want exactly one: %q", n, line)
	}
	for _, want := range []string{"org=org-a", "tenant=tenant-a",
		"route=POST /api/v1/example-writes/import", "op=ImportPolicies", "surface=DynamicPolicyAPI"} {
		if !strings.Contains(line, want) {
			t.Errorf("the refusal line lacks %q, so it cannot be counted per organization and route: %q", want, line)
		}
	}
}

// TestRefuseLogsCallerSuppliedFieldsOnOneLine: the organization, the tenant
// and the path arrive from the caller, and a newline in any of them would
// forge a second log line, which a per-organization counter would count.
func TestRefuseLogsCallerSuppliedFieldsOnOneLine(t *testing.T) {
	buf := captureLog(t)
	r := httptest.NewRequest(http.MethodPost, "/api/v1/example-writes/import", nil)
	r.URL.Path = "/api/v1/example-writes/import\n" + RefusedPrefix + " org=forged-by-path"
	Refuse(httptest.NewRecorder(), r, "PolicyAPI", "ImportPolicies",
		"org-a\n"+RefusedPrefix+" org=forged-by-org", "tenant-a\r\n",
		func(w http.ResponseWriter, s int, _, _ string) { w.WriteHeader(s) })
	out := strings.TrimSuffix(buf.String(), "\n")
	if strings.ContainsAny(out, "\r\n") {
		t.Fatalf("one refusal wrote more than one log line: %q", out)
	}
}

// TestMayWriteAsksTheDatabaseAboutAFrozenTableOnly pins what MayWrite sends
// and how it reads the answer. Whether Postgres resolves the query the way its
// comment says is a property of Postgres, not of this mock: the orchestrator's
// TestLegacyImportAgainstTheRealRevoke_RealPG asks it on a real application
// role connection and a real owner connection.
func TestMayWriteAsksTheDatabaseAboutAFrozenTableOnly(t *testing.T) {
	const query = "SELECT has_table_privilege($1::text, 'INSERT')"
	newMock := func(t *testing.T) (*sql.DB, sqlmock.Sqlmock) {
		t.Helper()
		db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherEqual))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = db.Close() })
		return db, mock
	}

	for _, table := range frozenTables {
		for _, held := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s held=%v", table, held), func(t *testing.T) {
				db, mock := newMock(t)
				mock.ExpectQuery(query).WithArgs(table).
					WillReturnRows(sqlmock.NewRows([]string{"has_table_privilege"}).AddRow(held))
				got, err := MayWrite(context.Background(), db, table)
				if err != nil || got != held {
					t.Fatalf("MayWrite = %v, %v; want %v, nil", got, err, held)
				}
				if err := mock.ExpectationsWereMet(); err != nil {
					t.Fatal(err)
				}
			})
		}
	}

	// THE FAIL DIRECTION. A probe that cannot be answered must be an ERROR,
	// never a false: a false would read as "revoked" and turn a database blip
	// into a retirement notice on a deployment that may write.
	t.Run("an unanswered probe is an error, not a false", func(t *testing.T) {
		db, mock := newMock(t)
		reset := errors.New("connection reset by peer")
		mock.ExpectQuery(query).WithArgs("dynamic_policies").WillReturnError(reset)
		got, err := MayWrite(context.Background(), db, "dynamic_policies")
		if !errors.Is(err, reset) || got {
			t.Fatalf("MayWrite = %v, %v; want false and an error wrapping %v", got, err, reset)
		}
		if !strings.Contains(err.Error(), "dynamic_policies") {
			t.Fatalf("the error does not name the table it asked about: %v", err)
		}
	})

	// A table this freeze does not cover is refused BY NAME before any query:
	// answering the freeze's message for policy_versions is the mistake
	// IsFrozen's subject anchor exists to prevent. The reason is asserted,
	// because a mock with nothing queued errors every query too.
	t.Run("a table the freeze does not cover is refused by name", func(t *testing.T) {
		db, _ := newMock(t)
		_, err := MayWrite(context.Background(), db, "policy_versions")
		if err == nil || !strings.Contains(err.Error(), "not a table the core/172 freeze covers") {
			t.Fatalf("MayWrite(policy_versions) err = %v, want the not-covered refusal", err)
		}
	})
}

// TestRefuseWhenRevokedAnswersOnlyARevokedConnection pins the one pre-read
// guard's three outcomes directly: a connection that may write proceeds, an
// unanswered probe proceeds (the write's own refusal is still classified), and
// only a revoked connection is answered, with exactly Refuse's answer.
func TestRefuseWhenRevokedAnswersOnlyARevokedConnection(t *testing.T) {
	captureLog(t)
	for _, c := range []struct {
		name    string
		may     func(context.Context) (bool, error)
		refused bool
	}{
		{"a connection that may write", func(context.Context) (bool, error) { return true, nil }, false},
		{"an unanswered probe", func(context.Context) (bool, error) { return false, errors.New("connection reset by peer") }, false},
		{"a revoked connection", func(context.Context) (bool, error) { return false, nil }, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			var calls, status int
			var code, message string
			write := func(w http.ResponseWriter, s int, cd, m string) {
				calls++
				status, code, message = s, cd, m
				w.WriteHeader(s)
			}
			r := httptest.NewRequest(http.MethodPost, "/api/v1/example-writes", nil)
			got := RefuseWhenRevoked(httptest.NewRecorder(), r, c.may, "ExampleAPI", "ExampleWrite", "org-a", "tenant-a", write)
			if got != c.refused {
				t.Fatalf("refused = %v, want %v", got, c.refused)
			}
			if !c.refused {
				if calls != 0 {
					t.Fatalf("the writer was called %d time(s) for a request that proceeds", calls)
				}
				return
			}
			if calls != 1 || status != http.StatusConflict || code != ErrCode || message != Message {
				t.Fatalf("writer called %d time(s) with %d %q %q; want once with 409, ErrCode and Message", calls, status, code, message)
			}
		})
	}
}
