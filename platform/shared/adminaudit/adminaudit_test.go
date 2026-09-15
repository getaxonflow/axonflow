// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package adminaudit

import (
	"context"
	"database/sql"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
)

// repoRoot is the repository checkout this package sits in.
const repoRoot = "../../.."

// TestInsertBindsEveryColumn pins the row Insert writes: each field to its
// column, the address canonicalised, the details marshalled, and every empty
// optional field NULL rather than "".
func TestInsertBindsEveryColumn(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("sqlmock: %v", err)
	}
	defer func() { _ = db.Close() }()

	mock.ExpectExec(`INSERT INTO admin_audit_log`).
		WithArgs(
			"DETECTION_POSTURE_SET",
			sql.NullString{String: "cs_org", Valid: true},
			"system:community-saas-registration",
			sql.NullString{String: `{"action":"block","category":"sqli"}`, Valid: true},
			sql.NullString{String: "192.0.2.1", Valid: true},
			sql.NullString{String: "curl/8", Valid: true},
			true,
			sql.NullString{},
		).
		WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectExec(`INSERT INTO admin_audit_log`).
		WithArgs(
			"AUTH_FAILURE",
			sql.NullString{},
			UnknownActor,
			sql.NullString{},
			sql.NullString{},
			sql.NullString{},
			false,
			sql.NullString{String: "no api key provided", Valid: true},
		).
		WillReturnResult(sqlmock.NewResult(2, 1))

	ctx := context.Background()
	if err := Insert(ctx, db, Entry{
		Action:     "DETECTION_POSTURE_SET",
		OrgID:      "cs_org",
		Identifier: "system:community-saas-registration",
		IPAddress:  "192.0.2.1:4711",
		UserAgent:  "curl/8",
		Details:    map[string]any{"category": "sqli", "action": "block"},
		Success:    true,
	}); err != nil {
		t.Fatalf("Insert: %v", err)
	}
	// A system-wide failure with no actor and an address that is not one: the
	// row is still written, with NULLs where there is nothing to record.
	if err := Insert(ctx, db, Entry{Action: "AUTH_FAILURE", IPAddress: "unknown", ErrorMessage: "no api key provided"}); err != nil {
		t.Fatalf("Insert: %v", err)
	}
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestCanonicalIPReturnsAnAddressOrNothing(t *testing.T) {
	cases := []struct{ in, want string }{
		{"192.0.2.1", "192.0.2.1"},
		// #3289: the port on a direct connection 500'd the SSO session INSERT.
		{"192.168.65.1:57318", "192.168.65.1"},
		// #4075: the IPv6 RemoteAddr the LastIndex strip turned into "[::1]".
		{"[::1]:54321", "::1"},
		{"::1", "::1"},
		{"[2001:db8::1]:8080", "2001:db8::1"},
		{"2001:DB8:0:0:0:0:0:1", "2001:db8::1"},
		{"  203.0.113.9  ", "203.0.113.9"},
		{"[fe80::1%en0]:80", "fe80::1"},
		{"::ffff:192.0.2.1", "192.0.2.1"},
		{"", ""},
		{"[::1]", ""},
		{"not-an-ip", ""},
		{"unknown", ""},
		{"192.0.2.1, 10.0.0.1", ""},
		{"/var/run/app.sock", ""},
		{"999.1.1.1", ""},
		{"' OR 1=1 --", ""},
	}
	for _, tc := range cases {
		got := CanonicalIP(tc.in)
		if got != tc.want {
			t.Errorf("CanonicalIP(%q) = %q, want %q", tc.in, got, tc.want)
		}
		if len(got) > 50 {
			t.Errorf("CanonicalIP(%q) = %q is longer than sso_login_attempts.ip_address VARCHAR(50)", tc.in, got)
		}
	}
}

func TestNullIPIsNullForEverythingThatIsNotAnAddress(t *testing.T) {
	for in, want := range map[string]string{"[::1]:54321": "::1", "192.0.2.1": "192.0.2.1"} {
		if got := NullIP(in); !got.Valid || got.String != want {
			t.Errorf("NullIP(%q) = %+v, want the valid %q", in, got, want)
		}
	}
	for _, in := range []string{"", "   ", "[::1]", "not-an-ip"} {
		if got := NullIP(in); got.Valid {
			t.Errorf("NullIP(%q) = %+v, want NULL: inet refuses it", in, got)
		}
	}
}

// writesTable matches SQL that inserts an admin_audit_log row.
var writesTable = regexp.MustCompile(`(?is)\bINSERT\s+INTO\s+admin_audit_log\b`)

// tableWriters returns every non-test Go file under root, relative to root,
// whose string literals insert an admin_audit_log row. It reads literals, not
// text, so a comment describing the INSERT is not a writer. Bound: SQL built
// by concatenating literals that each hold half the statement is not seen.
func tableWriters(t *testing.T, root string) []string {
	t.Helper()
	var writers []string
	fset := token.NewFileSet()
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", "vendor", "testdata":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, perr := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if perr != nil {
			return perr
		}
		found := false
		ast.Inspect(f, func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING || found {
				return !found
			}
			if s, uerr := strconv.Unquote(lit.Value); uerr == nil && writesTable.MatchString(s) {
				found = true
			}
			return !found
		})
		if found {
			rel, _ := filepath.Rel(root, path)
			writers = append(writers, filepath.ToSlash(rel))
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	sort.Strings(writers)
	return writers
}

// TestInsertIsTheOnlyWriterOfTheTable: admin_audit_log has one writer, so the
// row the portal records and the row the registration records cannot drift
// apart in shape or in how they treat an address. A second INSERT anywhere in
// the tree reds here; it belongs in Insert's callers, not beside it.
func TestInsertIsTheOnlyWriterOfTheTable(t *testing.T) {
	got := tableWriters(t, repoRoot)
	want := []string{"platform/shared/adminaudit/adminaudit.go"}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("admin_audit_log writers = %v, want only %v: write the row through adminaudit.Insert", got, want)
	}
}

// TestTheWriterCensusFindsAPlantedWriter proves the census sees what it
// claims to: an INSERT in a literal, raw or quoted, and not a comment, a
// read, or a test file.
func TestTheWriterCensusFindsAPlantedWriter(t *testing.T) {
	dir := t.TempDir()
	files := map[string]string{
		"raw.go":       "package p\n\nconst q = `insert into ADMIN_AUDIT_LOG (action) values ($1)`\n",
		"quoted.go":    "package p\n\nfunc f() string { return \"INSERT INTO admin_audit_log (action) VALUES ($1)\" }\n",
		"comment.go":   "package p\n\n// INSERT INTO admin_audit_log is described here, not executed.\nconst c = 1\n",
		"read.go":      "package p\n\nconst r = `SELECT action FROM admin_audit_log`\n",
		"raw_test.go":  "package p\n\nconst tq = `INSERT INTO admin_audit_log (action) VALUES ($1)`\n",
		"otherdb.go":   "package p\n\nconst o = `INSERT INTO admin_audit_log_archive (action) VALUES ($1)`\n",
		"multiline.go": "package p\n\nconst m = `INSERT\n\tINTO admin_audit_log (action) VALUES ($1)`\n",
	}
	for name, src := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(src), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	got := strings.Join(tableWriters(t, dir), ",")
	if want := "multiline.go,quoted.go,raw.go"; got != want {
		t.Fatalf("census found %s, want %s", got, want)
	}
}

// adminAuditDDL returns the CREATE TABLE and CREATE INDEX statements for
// admin_audit_log in a migration, each from its CREATE to its semicolon.
func adminAuditDDL(t *testing.T, path string) []string {
	t.Helper()
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var out []string
	for _, chunk := range strings.Split(string(src), ";") {
		i := strings.Index(chunk, "CREATE ")
		if i < 0 {
			continue
		}
		stmt := chunk[i:]
		if strings.HasPrefix(stmt, "CREATE TABLE IF NOT EXISTS admin_audit_log ") ||
			(strings.HasPrefix(stmt, "CREATE INDEX IF NOT EXISTS idx_admin_audit_") && strings.Contains(stmt, " ON admin_audit_log(")) {
			out = append(out, stmt+";")
		}
	}
	return out
}

// TestTheCommunitySaasTableIsTheEnterpriseTable: community-saas/088 creates
// admin_audit_log for the Community SaaS schema with enterprise/113's DDL, byte
// for byte, so adminaudit.Insert writes one table on either schema. An edit to
// either file that the other does not repeat reds here.
func TestTheCommunitySaasTableIsTheEnterpriseTable(t *testing.T) {
	if communityMirrorTree(repoRoot) {
		t.Skip("no ee/ - community mirror tree, where migrations/enterprise/ and migrations/community-saas/ are not synced; the identity is held in the enterprise repository")
	}
	enterprise := adminAuditDDL(t, filepath.Join(repoRoot, "migrations/enterprise/113_admin_audit_log.sql"))
	saas := adminAuditDDL(t, filepath.Join(repoRoot, "migrations/community-saas/088_admin_audit_log.sql"))
	if len(enterprise) < 2 || !strings.HasPrefix(enterprise[0], "CREATE TABLE") {
		t.Fatalf("enterprise/113 yielded %d statement(s), want the table and its indexes: the extraction is reading the wrong file", len(enterprise))
	}
	if len(saas) != len(enterprise) {
		t.Fatalf("community-saas/088 has %d admin_audit_log statement(s), enterprise/113 has %d", len(saas), len(enterprise))
	}
	for i := range enterprise {
		if saas[i] != enterprise[i] {
			t.Errorf("statement %d differs between the chains:\nenterprise/113:\n%s\ncommunity-saas/088:\n%s", i+1, enterprise[i], saas[i])
		}
	}
}

// communityMirrorTree reports whether root is the community mirror's tree,
// which carries no ee/. The sync excludes migrations/enterprise/ and
// migrations/community-saas/ with it (sync-community-repo.yml), so a check that
// reads those chains can run only in the enterprise repository, and there a
// missing file is a failure, not a skip.
func communityMirrorTree(root string) bool {
	_, err := os.Stat(filepath.Join(root, "ee"))
	return errors.Is(err, fs.ErrNotExist)
}

// TestCommunityMirrorTreeIsTheTreeWithoutEE pins the skip above on planted
// trees, so it is known to skip only where ee/ is absent.
func TestCommunityMirrorTreeIsTheTreeWithoutEE(t *testing.T) {
	mirror, enterprise := t.TempDir(), t.TempDir()
	if err := os.Mkdir(filepath.Join(enterprise, "ee"), 0o700); err != nil {
		t.Fatal(err)
	}
	if !communityMirrorTree(mirror) {
		t.Error("a tree without ee/ is not read as the community mirror")
	}
	if communityMirrorTree(enterprise) {
		t.Error("a tree with ee/ is read as the community mirror, so the DDL identity would be skipped where it must run")
	}
}
