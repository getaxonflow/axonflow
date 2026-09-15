// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package legacycompile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeSeedSQL(t *testing.T, sql string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "seed.sql")
	if err := os.WriteFile(path, []byte(sql), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// #4254: the reader returns every dynamic_policies row's policy_id and stored
// conditions, reading columns by name, and skips the parenthesised groups a
// statement carries after its last row (an ON CONFLICT column list) rather
// than reading one as a row.
func TestSeedDynamicConditionsReadsEveryRowAndSkipsTrailingGroups(t *testing.T) {
	path := writeSeedSQL(t, `
INSERT INTO static_policies (policy_id, pattern) VALUES ('sys_static', 'x;y');
INSERT INTO dynamic_policies (name, policy_id, conditions, actions) VALUES
('A (first)', 'sys_dyn_a', '[{"field": "query", "operator": "contains", "value": "it''s"}]', '[]'),
('B', 'sys_dyn_b', '[{"field": "query", "operator": "regex", "value": "tenant_id\\s*[!=<>]+"}]', '[]')
ON CONFLICT (policy_id) DO UPDATE SET conditions = EXCLUDED.conditions, updated_at = NOW();
INSERT INTO dynamic_policies (policy_id, conditions) VALUES
    ('sys_media_c', '[{"field":"media.nsfw_score","operator":"greater_than","value":0.8}]'::jsonb);
`)
	got, err := SeedDynamicConditions(path)
	if err != nil {
		t.Fatalf("a well-formed seed with an ON CONFLICT clause and a cast literal was refused: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("read %d dynamic rows (%v); want exactly the three the statements insert", len(got), got)
	}
	if want := `[{"field":"media.nsfw_score","operator":"greater_than","value":0.8}]`; got["sys_media_c"] != want {
		t.Errorf("sys_media_c's conditions read as %q; want %q, the literal without its ::jsonb cast", got["sys_media_c"], want)
	}
	if want := `[{"field": "query", "operator": "contains", "value": "it's"}]`; got["sys_dyn_a"] != want {
		t.Errorf("sys_dyn_a's conditions read as %q; want %q, with the doubled quote undoubled", got["sys_dyn_a"], want)
	}
	if !strings.Contains(got["sys_dyn_b"], `tenant_id\\s*`) {
		t.Errorf("sys_dyn_b's conditions read as %q; want the stored text, backslashes as written", got["sys_dyn_b"])
	}
	if _, isStatic := got["sys_static"]; isStatic {
		t.Error("a static_policies row was read as a dynamic row")
	}
}

// A row whose policy_id or conditions is not a quoted string is refused, and so
// is a seed that inserts no dynamic row, and a path that cannot be read: a
// reader that quietly dropped any of them would report that row's facts as
// never needed.
func TestSeedDynamicConditionsRefusesWhatItCannotRead(t *testing.T) {
	unquoted := writeSeedSQL(t, `INSERT INTO dynamic_policies (policy_id, conditions) VALUES (sys_dyn_a, '[]');`)
	if _, err := SeedDynamicConditions(unquoted); err == nil || !strings.Contains(err.Error(), "does not quote") {
		t.Errorf("an unquoted policy_id was answered %v; want the refusal naming it", err)
	}
	noDynamic := writeSeedSQL(t, `INSERT INTO static_policies (policy_id, pattern) VALUES ('sys_static', 'x');`)
	if _, err := SeedDynamicConditions(noDynamic); err == nil || !strings.Contains(err.Error(), "no dynamic_policies row") {
		t.Errorf("a seed with no dynamic row was answered %v; want the refusal", err)
	}
	noColumn := writeSeedSQL(t, `INSERT INTO dynamic_policies (name, actions) VALUES ('x', '[]');`)
	if _, err := SeedDynamicConditions(noColumn); err == nil || !strings.Contains(err.Error(), "names no policy_id or conditions column") {
		t.Errorf("a dynamic INSERT with no policy_id column was answered %v; want the refusal", err)
	}
	if _, err := SeedDynamicConditions(filepath.Join(t.TempDir(), "missing.sql")); err == nil {
		t.Error("a path that does not exist was read without an error")
	}
}
