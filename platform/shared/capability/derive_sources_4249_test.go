// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package capability

import (
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// TestDeriveSourcesIsDeriveOverTheSameFiles is a FILTER-PARITY cell (#4249 row
// 5782954005): the no-reference census reads its trees through DeriveSources,
// the registration census through Derive, and a file one of them reads and the
// other skips would be a census gap that reads as agreement. Over the real tree,
// DeriveSources given every .go file - read by a separate walk that applies none
// of Derive's filters, so DeriveSources' own filters are exercised - must produce
// the same routes, enterprise directories and file count.
//
// WHAT IT CANNOT SEE: Derive delegates to DeriveSources, so a defect in the
// shared derivation is on both sides and agrees with itself here. The content
// control is TestTheTreeDerivationIsNotVacuous, which holds the derivation to
// what the tree actually registers.
func TestDeriveSourcesIsDeriveOverTheSameFiles(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	roots := []string{"platform", "ee"}
	want, err := Derive(root, roots)
	if err != nil {
		t.Fatal(err)
	}
	if want.FilesParsed < 100 || len(want.Routes) < 100 {
		t.Fatalf("Derive parsed %d files and found %d routes; this comparison would be over nothing", want.FilesParsed, len(want.Routes))
	}

	var srcs []Source
	for _, r := range roots {
		abs := filepath.Join(root, r)
		if _, err := os.Stat(abs); err != nil {
			continue
		}
		err := filepath.WalkDir(abs, func(path string, e fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if e.IsDir() && (e.Name() == ".git" || e.Name() == "node_modules") {
				return filepath.SkipDir // size only; the filters under test are applied below
			}
			if e.IsDir() || filepath.Ext(path) != ".go" {
				return nil
			}
			b, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			rel, _ := filepath.Rel(root, path)
			srcs = append(srcs, Source{Rel: filepath.ToSlash(rel), Content: b})
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	got, err := DeriveSources(srcs)
	if err != nil {
		t.Fatal(err)
	}
	if got.FilesParsed != want.FilesParsed {
		t.Errorf("DeriveSources parsed %d files, Derive %d: the two apply different filters", got.FilesParsed, want.FilesParsed)
	}
	if !reflect.DeepEqual(got.EnterpriseDirs, want.EnterpriseDirs) {
		t.Errorf("enterprise directories differ: DeriveSources %d, Derive %d", len(got.EnterpriseDirs), len(want.EnterpriseDirs))
	}
	if len(got.Routes) != len(want.Routes) {
		t.Fatalf("DeriveSources found %d routes, Derive %d", len(got.Routes), len(want.Routes))
	}
	for i := range want.Routes {
		if !reflect.DeepEqual(got.Routes[i], want.Routes[i]) {
			t.Fatalf("route %d differs:\n  Derive        %+v\n  DeriveSources %+v", i, want.Routes[i], got.Routes[i])
		}
	}
}
