// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package upgradepin

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func sum(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func plant(t *testing.T, root, rel, body string) {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

const corePins = "platform/agent/testdata/v10_2_0"

// synthetic builds a repository with two core migrations v10.2.0 shipped: one
// unchanged since, one edited since and pinned. It also carries a migration
// added after the release, and a down-migration.
func synthetic(t *testing.T) string {
	root := t.TempDir()
	plant(t, root, "migrations/core/001_a.sql", "A\n")
	plant(t, root, "migrations/core/002_b.sql", "B edited after the release\n")
	plant(t, root, "migrations/core/002_b_down.sql", "B down\n")
	plant(t, root, "migrations/core/003_new.sql", "added after the release\n")
	plant(t, root, corePins+"/core.sha256", "# a comment\n\n"+
		sum("A\n")+"  migrations/core/001_a.sql\n"+
		sum("B as released\n")+"  migrations/core/002_b.sql\n")
	plant(t, root, corePins+"/migrations/core/002_b.sql", "B as released\n")
	return root
}

func TestMaterializeTakesTheLiveFileOrItsPinByDigest(t *testing.T) {
	root := synthetic(t)
	dst := t.TempDir()
	res, err := Materialize(root, "community", dst)
	if err != nil {
		t.Fatal(err)
	}
	if res.Files != 2 || res.Pinned != 1 || len(res.Absent) != 0 {
		t.Fatalf("got %+v, want 2 files, 1 of them pinned, nothing absent", res)
	}
	for name, want := range map[string]string{"001_a.sql": "A\n", "002_b.sql": "B as released\n"} {
		got, err := os.ReadFile(filepath.Join(dst, "core", name))
		if err != nil || string(got) != want {
			t.Errorf("%s = %q (%v), want %q", name, got, err, want)
		}
	}
	for _, name := range []string{"003_new.sql", "002_b_down.sql"} {
		if _, err := os.Stat(filepath.Join(dst, "core", name)); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("%s was written; v10.2.0's set is the manifest's and nothing else (err %v)", name, err)
		}
	}
}

func TestMaterializeRefuses(t *testing.T) {
	for _, c := range []struct {
		name  string
		setup func(t *testing.T, root string)
		want  string
	}{
		{"one byte of an unpinned live file changed", func(t *testing.T, root string) {
			plant(t, root, "migrations/core/001_a.sql", "a\n")
		}, "refused migrations/core/001_a.sql"},
		{"one byte of a pin changed", func(t *testing.T, root string) {
			plant(t, root, corePins+"/migrations/core/002_b.sql", "b as released\n")
		}, "refused migrations/core/002_b.sql"},
		{"a live file the manifest lists is gone", func(t *testing.T, root string) {
			if err := os.Remove(filepath.Join(root, "migrations", "core", "001_a.sql")); err != nil {
				t.Fatal(err)
			}
		}, "the live file's is (none)"},
		{"a pin no manifest line lists", func(t *testing.T, root string) {
			plant(t, root, corePins+"/migrations/core/003_new.sql", "added after the release\n")
		}, "is a pin no line of"},
		{"a pin whose live file matches again", func(t *testing.T, root string) {
			plant(t, root, "migrations/core/002_b.sql", "B as released\n")
		}, "is stale; delete the pin"},
		{"a malformed manifest line", func(t *testing.T, root string) {
			plant(t, root, corePins+"/core.sha256", sum("A\n")+" migrations/core/001_a.sql\n")
		}, "is not `<sha256>  migrations/core/<up-migration>.sql`"},
		{"a down-migration in the manifest", func(t *testing.T, root string) {
			plant(t, root, corePins+"/core.sha256", sum("B down\n")+"  migrations/core/002_b_down.sql\n")
		}, "is not `<sha256>  migrations/core/<up-migration>.sql`"},
		{"a pin under a root that does not hold its category's manifest", func(t *testing.T, root string) {
			plant(t, root, corePins+"/migrations/industry/banking/300_x.sql", "X\n")
		}, "is a pin for industry/banking, whose manifest industry-banking.sha256 is not in platform/agent/testdata/v10_2_0"},
		{"a manifest other than core's under the synced root", func(t *testing.T, root string) {
			plant(t, root, corePins+"/enterprise.sha256", "")
		}, "but the synced root holds only core.sha256"},
		{"a pin outside migrations/ under the synced root", func(t *testing.T, root string) {
			plant(t, root, corePins+"/industry/banking/300_x.sql", "X\n")
		}, "a pin root holds its manifests and a migrations/ tree, nothing else"},
		{"a stray file under the ee root", func(t *testing.T, root string) {
			plant(t, root, "ee/platform/agent/testdata/v10_2_0/README.md", "x\n")
		}, "a pin root holds its manifests and a migrations/ tree, nothing else"},
		{"a manifest held under both roots", func(t *testing.T, root string) {
			plant(t, root, "ee/platform/agent/testdata/v10_2_0/core.sha256", sum("A\n")+"  migrations/core/001_a.sql\n")
		}, "is held twice"},
	} {
		t.Run(c.name, func(t *testing.T) {
			root := synthetic(t)
			c.setup(t, root)
			_, err := Materialize(root, "community", t.TempDir())
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want one containing %q", err, c.want)
			}
		})
	}
}

func TestMaterializeRefusesALiveCategoryWithNoManifest(t *testing.T) {
	root := synthetic(t)
	plant(t, root, "migrations/community-saas/085_x.sql", "X\n")
	_, err := Materialize(root, "community-saas", t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "migrations/community-saas exists but no community-saas.sha256 manifest") {
		t.Fatalf("err = %v, want the missing-manifest refusal", err)
	}
}

func TestMaterializeReportsACategoryTheCheckoutDoesNotCarry(t *testing.T) {
	root := synthetic(t)
	res, err := Materialize(root, "community-saas", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if res.Files != 2 || len(res.Absent) != 1 || res.Absent[0] != "community-saas" {
		t.Fatalf("got %+v, want core's 2 files and community-saas absent", res)
	}
}

func TestMaterializeRefusesAnUnknownMode(t *testing.T) {
	if _, err := Materialize(synthetic(t), "enterprise", t.TempDir()); err == nil {
		t.Fatal("an alias was accepted; the manifests are keyed by canonical mode")
	}
}

func repoRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "migrations", "core")); err != nil {
		t.Fatalf("%s is not the repository root: %v", root, err)
	}
	return root
}

// mirrorShape reports whether the checkout is the community mirror, which
// strips ee/ and every Enterprise-only migration category with it.
func mirrorShape(root string) bool {
	_, err := os.Stat(filepath.Join(root, "ee"))
	return errors.Is(err, fs.ErrNotExist)
}

// The real subset, per mode. The counts are facts about v10.2.0 and never
// move: 153 core, 3 community-saas, 39 enterprise, 7 banking and 2 travel
// up-migrations, 8 core and 4 industry files edited since.
func TestTheRealV1020SubsetMaterializes(t *testing.T) {
	root := repoRoot(t)
	for _, c := range []struct {
		mode          string
		files, pinned int
	}{
		{"community", 153, 8},
		{"community-saas", 156, 8},
		{"saas", 201, 12},
	} {
		t.Run(c.mode, func(t *testing.T) {
			res, err := Materialize(root, c.mode, t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			if len(res.Absent) > 0 {
				if !mirrorShape(root) {
					t.Fatalf("categories %v are absent, and this checkout has ee/: the enterprise tree carries every category", res.Absent)
				}
				t.Skipf("community mirror: %v not carried", res.Absent)
			}
			if res.Files != c.files || res.Pinned != c.pinned {
				t.Fatalf("got %d files, %d pinned; v10.2.0's %s set is %d, %d pinned", res.Files, res.Pinned, c.mode, c.files, c.pinned)
			}
		})
	}
}

// The positive control on the real subset: a copy of the real core tree, its
// manifest and its pins materializes, and one byte changed in a live file, or
// in a pin, is refused.
func TestOneByteInTheRealCoreSubsetIsRefused(t *testing.T) {
	src := repoRoot(t)
	copyTree := func(t *testing.T) string {
		dst := t.TempDir()
		for _, dir := range []string{"migrations/core", corePins} {
			err := filepath.WalkDir(filepath.Join(src, filepath.FromSlash(dir)), func(p string, d fs.DirEntry, err error) error {
				if err != nil || d.IsDir() {
					return err
				}
				rel, err := filepath.Rel(src, p)
				if err != nil {
					return err
				}
				b, err := os.ReadFile(p)
				if err != nil {
					return err
				}
				plant(t, dst, filepath.ToSlash(rel), string(b))
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
		}
		return dst
	}
	flip := func(t *testing.T, root, rel string) {
		p := filepath.Join(root, filepath.FromSlash(rel))
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		b[len(b)/2] ^= 0x01
		if err := os.WriteFile(p, b, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	root := copyTree(t)
	if res, err := Materialize(root, "community", t.TempDir()); err != nil || res.Files != 153 || res.Pinned != 8 {
		t.Fatalf("the unaltered copy: %+v, %v; want 153 files, 8 pinned", res, err)
	}
	for _, rel := range []string{"migrations/core/001_schema_migrations.sql", corePins + "/migrations/core/031_seed_system_policies.sql"} {
		t.Run(rel, func(t *testing.T) {
			root := copyTree(t)
			flip(t, root, rel)
			_, err := Materialize(root, "community", t.TempDir())
			if err == nil || !strings.Contains(err.Error(), "refused migrations/core/"+filepath.Base(rel)) {
				t.Fatalf("one byte changed in %s: err = %v, want the refusal naming it", rel, err)
			}
		})
	}
}
