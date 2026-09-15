// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

// Package upgradepin materializes the migration tree a v10.2.0 deployment
// applied, for the database upgrade tests of #3894 clause (a).
//
// A v10.2.0 database is not "today's migrations minus the ones added since":
// twelve up-migrations v10.2.0 shipped were edited after the tag (#3841
// repointed an ADR citation in each). So the set is pinned by digest. Each
// migration category has a manifest, the sha256 of every up-migration the
// category held at v10.2.0, and beside it a copy of v10.2.0's bytes for exactly
// the files whose bytes have changed since. Materialize takes a file from the
// live tree when its digest matches the manifest, from its pin when the pin's
// does, and refuses anything else: a mismatch, a pin no manifest lists, and a
// pin whose live file matches again.
//
// The manifests follow the community mirror. Core's is under
// platform/agent/testdata/v10_2_0, which syncs; the categories the mirror
// strips (community-saas, enterprise, industry) keep theirs under
// ee/platform/agent/testdata/v10_2_0, which it strips too.
//
// It imports nothing from package agent, so the agent's in-package tests and
// the orchestrator's tests can both use it.
package upgradepin

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"axonflow/platform/shared/deploymode"
)

const (
	// Version is the release the pinned set is from.
	Version = "v10.2.0"
	// Commit is the commit the v10.2.0 tag peels to. Every digest in the
	// manifests is of a blob at this commit.
	Commit = "2b8eba3207113179958a61ab591eabfb01f93a58"
)

// ManifestRoots are the directories, relative to the repository root, that
// hold the manifests and the pinned copies beside them.
var ManifestRoots = []string{
	"platform/agent/testdata/v10_2_0",
	"ee/platform/agent/testdata/v10_2_0",
}

// Result is what Materialize wrote.
type Result struct {
	// Files is how many up-migrations were written.
	Files int
	// Pinned is how many of them came from a pinned copy.
	Pinned int
	// Absent names the categories this checkout carries neither a live
	// directory nor a manifest for: on the community mirror, every category
	// but core.
	Absent []string
}

var manifestLine = regexp.MustCompile(`^([0-9a-f]{64})  (migrations/[a-z0-9/-]+/[^/]+\.sql)$`)

type entry struct {
	digest string
	path   string // slash-separated, relative to the repository root
}

// Materialize writes the up-migrations a v10.2.0 deployment of mode applied into
// dst/<category>/, the layout collectMigrations reads with DEPLOYMENT_MODE set
// to mode. repoRoot is the repository root.
func Materialize(repoRoot, mode, dst string) (Result, error) {
	if err := checkPinRoots(repoRoot); err != nil {
		return Result{}, err
	}
	cats, ok := deploymode.CanonicalModes()[mode]
	if !ok {
		return Result{}, fmt.Errorf("upgradepin: %q is not a canonical deployment mode", mode)
	}
	var res Result
	for _, cat := range cats {
		files, pinned, err := materializeCategory(repoRoot, cat, dst)
		if errors.Is(err, errCategoryAbsent) {
			res.Absent = append(res.Absent, cat)
			continue
		}
		if err != nil {
			return res, err
		}
		res.Files += files
		res.Pinned += pinned
	}
	return res, nil
}

var errCategoryAbsent = errors.New("category absent from this checkout")

func materializeCategory(repoRoot, cat, dst string) (files, pinned int, err error) {
	manifest, pinRoot, err := findManifest(repoRoot, cat)
	if err != nil {
		return 0, 0, err
	}
	live := filepath.Join(repoRoot, "migrations", filepath.FromSlash(cat))
	if manifest == "" {
		if _, statErr := os.Stat(live); errors.Is(statErr, fs.ErrNotExist) {
			return 0, 0, errCategoryAbsent
		}
		return 0, 0, fmt.Errorf("upgradepin: migrations/%s exists but no %s manifest names what it held at %s", cat, manifestName(cat), Version)
	}
	entries, err := readManifest(manifest, cat)
	if err != nil {
		return 0, 0, err
	}

	outDir := filepath.Join(dst, filepath.FromSlash(cat))
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return 0, 0, err
	}
	listed := map[string]bool{}
	for _, e := range entries {
		listed[e.path] = true
		liveBytes, liveSum, err := digestOf(filepath.Join(repoRoot, filepath.FromSlash(e.path)))
		if err != nil {
			return 0, 0, err
		}
		pinPath := filepath.Join(pinRoot, filepath.FromSlash(e.path))
		pinBytes, pinSum, err := digestOf(pinPath)
		if err != nil {
			return 0, 0, err
		}
		var b []byte
		switch {
		case liveSum == e.digest && pinSum != "":
			return 0, 0, fmt.Errorf("upgradepin: %s matches %s again, so its pin %s is stale; delete the pin", e.path, Version, pinPath)
		case liveSum == e.digest:
			b = liveBytes
		case pinSum == e.digest:
			b = pinBytes
			pinned++
		default:
			return 0, 0, fmt.Errorf("upgradepin: refused %s: its %s sha256 is %s, the live file's is %s and the pin's is %s",
				e.path, Version, e.digest, orNone(liveSum), orNone(pinSum))
		}
		if err := os.WriteFile(filepath.Join(outDir, filepath.Base(e.path)), b, 0o644); err != nil {
			return 0, 0, err
		}
		files++
	}

	// Every pin is one a manifest line needs.
	pinDir := filepath.Join(pinRoot, "migrations", filepath.FromSlash(cat))
	pins, err := os.ReadDir(pinDir)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return 0, 0, err
	}
	for _, p := range pins {
		rel := "migrations/" + cat + "/" + p.Name()
		if p.IsDir() || !listed[rel] {
			return 0, 0, fmt.Errorf("upgradepin: %s is a pin no line of %s lists", filepath.Join(pinDir, p.Name()), manifest)
		}
	}
	return files, pinned, nil
}

// checkPinRoots refuses a file placed where Materialize would never read it: a
// pin under a root that does not hold its category's manifest, or a manifest
// other than core's under the root the community mirror carries. Such a file
// is exempt from the two guards that exempt the pin roots, and under the
// synced root an Enterprise pin would reach the public mirror (#3894 R3).
func checkPinRoots(repoRoot string) error {
	// A pin root holds its manifests and a migrations/ tree, nothing else; the
	// synced root holds core's manifest only.
	for i, r := range ManifestRoots {
		entries, err := os.ReadDir(filepath.Join(repoRoot, filepath.FromSlash(r)))
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		for _, e := range entries {
			manifest := !e.IsDir() && strings.HasSuffix(e.Name(), ".sha256")
			switch {
			case e.IsDir() && e.Name() == "migrations":
			case manifest && (i > 0 || e.Name() == manifestName("core")):
			case manifest:
				return fmt.Errorf("upgradepin: %s holds %s, but the synced root holds only %s; the others belong under %s",
					r, e.Name(), manifestName("core"), ManifestRoots[1])
			default:
				return fmt.Errorf("upgradepin: %s holds %s; a pin root holds its manifests and a migrations/ tree, nothing else", r, e.Name())
			}
		}
	}
	for _, r := range ManifestRoots {
		root := filepath.Join(repoRoot, filepath.FromSlash(r))
		base := filepath.Join(root, "migrations")
		if _, statErr := os.Stat(base); errors.Is(statErr, fs.ErrNotExist) {
			continue
		}
		walkErr := filepath.WalkDir(base, func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}
			rel, err := filepath.Rel(base, p)
			if err != nil {
				return err
			}
			cat := filepath.ToSlash(filepath.Dir(rel))
			if _, statErr := os.Stat(filepath.Join(root, manifestName(cat))); statErr != nil {
				return fmt.Errorf("upgradepin: %s is a pin for %s, whose manifest %s is not in %s", p, cat, manifestName(cat), r)
			}
			return nil
		})
		if walkErr != nil {
			return walkErr
		}
	}
	return nil
}

func manifestName(cat string) string { return strings.ReplaceAll(cat, "/", "-") + ".sha256" }

// findManifest returns the category's manifest and the root that holds it, or
// "" when no root does. A manifest held under two roots is refused.
func findManifest(repoRoot, cat string) (manifest, root string, err error) {
	for _, r := range ManifestRoots {
		p := filepath.Join(repoRoot, filepath.FromSlash(r), manifestName(cat))
		if _, statErr := os.Stat(p); statErr == nil {
			if manifest != "" {
				return "", "", fmt.Errorf("upgradepin: %s is held twice, at %s and %s", manifestName(cat), manifest, p)
			}
			manifest, root = p, filepath.Join(repoRoot, filepath.FromSlash(r))
		} else if !errors.Is(statErr, fs.ErrNotExist) {
			return "", "", statErr
		}
	}
	return manifest, root, nil
}

func readManifest(path, cat string) ([]entry, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []entry
	seen := map[string]bool{}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for n := 1; sc.Scan(); n++ {
		line := sc.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		m := manifestLine.FindStringSubmatch(line)
		if m == nil || filepath.ToSlash(filepath.Dir(m[2])) != "migrations/"+cat || strings.HasSuffix(m[2], "_down.sql") {
			return nil, fmt.Errorf("upgradepin: %s:%d is not `<sha256>  migrations/%s/<up-migration>.sql`: %q", path, n, cat, line)
		}
		if seen[m[2]] {
			return nil, fmt.Errorf("upgradepin: %s:%d lists %s twice", path, n, m[2])
		}
		seen[m[2]] = true
		out = append(out, entry{digest: m[1], path: m[2]})
	}
	return out, sc.Err()
}

// digestOf returns a file's bytes and sha256, or empty values when it does
// not exist.
func digestOf(path string) ([]byte, string, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, "", nil
	}
	if err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256(b)
	return b, hex.EncodeToString(sum[:]), nil
}

func orNone(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}
