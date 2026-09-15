// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package legacycompile

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"axonflow/platform/decision/registry"
)

// THE CORPUS AGAINST A REAL DATABASE (#3884)
//
// Everything here needs a capture of a migrated database, because the corpus
// is a migration of rows that exist rather than of rows somebody wrote down. A
// fixture would prove the builder handles the shapes its author thought of.
//
// The skip is LOUD about what was not verified, for the reason
// TestCapturedCorpusReconciles' is: a green run with no capture must not read
// as this having passed.

// corpusContentTarget is the redaction target the corpus build uses.
//
// It is the plane-independent content root, and it is a constant here rather
// than an option a caller picks, because the corpus has one answer: legacy
// static_policies stores no field path for a redaction - the target was the
// span the detector matched at runtime - so every migrated redaction targets
// the request content and that fact is stated once.
const corpusContentTarget = "request.content"

func captureDirOrSkip(t *testing.T) string {
	t.Helper()
	dir := os.Getenv("AXONFLOW_LEGACY_CAPTURE_DIR")
	if dir == "" {
		t.Skip("no AXONFLOW_LEGACY_CAPTURE_DIR: the corpus was NOT built against a real database and no row-by-row " +
			"before/after was produced. Produce a capture with scripts/legacy-policy-capture.sh and set the variable.")
	}
	return dir
}

func buildCorpusFromCapture(t *testing.T) (*Corpus, *Report, []registry.CensusRow) {
	t.Helper()
	dir := captureDirOrSkip(t)
	owner := loadCapture(t, filepath.Join(dir, "capture-owner.json"))
	// THE CAPTURE IS THE WHOLE SUBSTRATE AGAIN, AND THAT CHANGED WITH #3962.
	//
	// This used to append five `sys_media_*` rows from a checked-in inventory,
	// because they were written by the orchestrator's boot-path seeder and by
	// no migration - so a migrated capture held ten enabled system-tier
	// dynamic rows where a booted deployment held fifteen. `migrations/core/173`
	// now seeds them, so a migrated capture carries them and appending the
	// inventory would hand the compiler five rows it already has. The
	// inventory is deleted; that was the REVISIT WHEN written into it.
	rep, err := Compile(owner, Options{})
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	census, err := registry.ShippedCensus()
	if err != nil {
		t.Fatalf("ShippedCensus: %v", err)
	}
	ledger, err := registry.ShippedSupersessionLedger()
	if err != nil {
		t.Fatalf("ShippedSupersessionLedger: %v", err)
	}
	corpus, err := BuildCorpus(*rep, CorpusOptions{ContentTarget: corpusContentTarget, Rows: owner, Census: census, Ledger: ledger})
	if err != nil {
		t.Fatalf("BuildCorpus: %v", err)
	}
	if err := corpus.Validate(); err != nil {
		t.Fatalf("the built corpus does not validate: %v", err)
	}
	return corpus, rep, census
}

// TestCorpusRowByRowBeforeAndAfter is the migration's row-by-row account.
//
// For every legacy row in a real capture it states what the legacy engines
// decide - per plane, as a set - and what the corpus decides, and it requires
// that every row where the two differ carries a DECLARED divergence naming it.
// A difference the builder did not declare fails the test, which is the
// mechanical form of "any divergence discovered by a reader rather than
// declared by the author".
func TestCorpusRowByRowBeforeAndAfter(t *testing.T) {
	corpus, rep, _ := buildCorpusFromCapture(t)

	declared := map[string][]Divergence{}
	for _, d := range corpus.Divergences {
		declared[d.PolicyID] = append(declared[d.PolicyID], d)
	}
	inCorpus := map[string]bool{}
	inSystem := map[string]bool{}
	for _, p := range corpus.System.Policies {
		inCorpus[p.ID] = true
		control, _, _ := CorpusControlOf(p.ID)
		inSystem[control] = true
	}
	for _, p := range corpus.OrganizationTemplate.Policies {
		inCorpus[p.ID] = true
	}

	var undeclared []string
	rows := 0
	for _, rec := range rep.Records {
		rows++
		id := rec.Source.PolicyID
		before := map[string]bool{}
		// enforced is what each plane's COMPILATION carries, which a plane
		// coercion can make differ from the resolved action; a system row is
		// split by it (#4046).
		enforced := map[string]bool{}
		// PER (PLANE, PHASE), as well as the set: a collapse is a reversal only on
		// the planes and phases whose own action is weaker than the one chosen,
		// and the set alone cannot say which those are (#3564, #4016).
		var perPhase []string
		for _, p := range rec.Planes {
			if len(p.Policies) > 0 && enforcedActionOf(&p) != "" {
				enforced[enforcedActionOf(&p)] = true
			}
			if p.ResolvedAction != "" {
				before[p.ResolvedAction] = true
				label := string(p.Plane)
				if p.Phase != "" {
					label += ":" + string(p.Phase)
				}
				perPhase = append(perPhase, label+"="+p.ResolvedAction)
			}
		}
		sort.Strings(perPhase)
		beforeList := sortedSet(before)
		after := ""
		for _, d := range declared[id] {
			if d.Chosen != "" {
				after = d.Chosen
			}
		}
		// A record that compiled to more than one policy carries a "#n" suffix
		// on each, so presence is a PREFIX question. Asking for the bare
		// identifier reported two multi-obligation dynamic rows as absent while
		// they were in the document under suffixed identifiers - a false
		// negative that would have read as five media controls being four.
		// Presence is a CONTROL question: a multi-policy row carries "#n" siblings
		// and a split row carries one variant per action (#4046), and neither is
		// the bare identifier.
		present := false
		for got := range inCorpus {
			if control, _, ok := CorpusControlOf(got); ok && control == CorpusPolicyIDFor(rec.Source.Table, id) {
				present = true
				break
			}
		}
		// A SPLIT ROW IS ACCOUNTED FOR POSITIVELY, not excused: every scope that
		// compiled a policy for it must be bound to the variant carrying that
		// scope's own resolved action. A split that bound one scope to another
		// scope's action would pass a presence check and decide the wrong thing.
		split := false
		for bound := range corpus.ScopeBindings {
			if control, _, ok := CorpusControlOf(bound); ok && control == CorpusPolicyIDFor(rec.Source.Table, id) {
				split = true
				break
			}
		}
		// The legacy-resolution check is #4046's, for a SYSTEM row split by what
		// its planes enforce. An organization-template row is bound by discharge
		// instead (#4131), which the divergence check below requires it to say.
		if split && inSystem[CorpusPolicyIDFor(rec.Source.Table, id)] {
			for _, pr := range rec.Planes {
				if len(pr.Policies) == 0 || enforcedActionOf(&pr) == "" {
					continue
				}
				scope, err := ScopeFor(pr.Plane, pr.Phase)
				if err != nil {
					t.Errorf("%s/%s: plane %s phase %q is not a declared scope: %v", rec.Source.Table, id, pr.Plane, pr.Phase, err)
					continue
				}
				boundHere := false
				for bound, scopes := range corpus.ScopeBindings {
					control, action, ok := CorpusControlOf(bound)
					if !ok || control != CorpusPolicyIDFor(rec.Source.Table, id) || action != enforcedActionOf(&pr) {
						continue
					}
					for _, s := range scopes {
						if s == scope.String() {
							boundHere = true
						}
					}
				}
				if !boundHere {
					t.Errorf("%s/%s enforces %q on %s and no variant carrying that action is bound to %s", rec.Source.Table, id, enforcedActionOf(&pr), scope, scope)
				}
			}
		}

		// THE KIND IS ASSERTED, NOT ONLY THE PRESENCE OF A DIVERGENCE.
		//
		// The earlier version asked `len(declared[id]) == 0` and nothing more.
		// R3 relabelled every `plane_action_collapsed` as
		// `action_unrankable` in the builder - mutation present and compiling
		// - and this test passed with all forty mislabelled, while its own
		// doc comment claimed it "requires that every row where the two differ
		// carries a DECLARED divergence NAMING it". A divergence set with the
		// right cardinality and the wrong names is a report that describes a
		// different migration.
		kinds := map[DivergenceKind]bool{}
		for _, d := range declared[id] {
			kinds[d.Kind] = true
		}
		if split && !inSystem[CorpusPolicyIDFor(rec.Source.Table, id)] && !kinds[DivergenceRedactionBoundByDischarge] {
			t.Errorf("%s/%s: an organization-template row is bound per scope and declares no %s", rec.Source.Table, id, DivergenceRedactionBoundByDischarge)
		}
		// #4254: a dynamic row that compiles a mandatory field_redact ships it as a
		// warn on scopes that cannot carry it out, and must say so.
		if rec.Source.Table == "dynamic_policies" && !kinds[DivergenceDynamicRedactionShipsAsWarn] {
			redacts := false
			for _, pr := range rec.Planes {
				for _, pol := range pr.Policies {
					if carriesMandatoryFieldRedact(pol) {
						redacts = true
					}
				}
			}
			if redacts {
				t.Errorf("%s/%s: the row compiles a mandatory field_redact and declares no %s", rec.Source.Table, id, DivergenceDynamicRedactionShipsAsWarn)
			}
		}
		switch {
		case len(beforeList) == 0 && present:
			t.Errorf("%s/%s: the legacy engines resolve no action anywhere and the corpus emitted a policy anyway", rec.Source.Table, id)
		case inSystem[CorpusPolicyIDFor(rec.Source.Table, id)] && len(enforced) > 1 && !split:
			undeclared = append(undeclared, fmt.Sprintf("%s (a system row whose planes enforce %v and is not split by scope)",
				id, sortedSet(enforced)))
		case !inSystem[CorpusPolicyIDFor(rec.Source.Table, id)] && len(beforeList) > 1 && !kinds[DivergencePlaneActionCollapsed]:
			undeclared = append(undeclared, fmt.Sprintf("%s (resolves %v across planes and declares no %s)",
				id, beforeList, DivergencePlaneActionCollapsed))
		}
		if !present && !kinds[DivergenceRowNotRepresented] && !kinds[DivergenceActionUnrankable] {
			undeclared = append(undeclared, fmt.Sprintf("%s (no corpus policy and declares neither %s nor %s)",
				id, DivergenceRowNotRepresented, DivergenceActionUnrankable))
		}
		if present && kinds[DivergenceRowNotRepresented] {
			t.Errorf("%s/%s: declares %s and IS in the corpus", rec.Source.Table, id, DivergenceRowNotRepresented)
		}
		t.Logf("%-22s %-34s before=%v after=%q in_corpus=%v per_phase=%v", rec.Source.Table, id, beforeList, after, present, perPhase)
	}

	if len(undeclared) > 0 {
		sort.Strings(undeclared)
		t.Errorf("%d row(s) either resolve more than one legacy action or produce no corpus policy, and the build declared no divergence for them: %v\n"+
			"A migration that decides differently without saying so is the failure this whole enumeration exists to prevent.",
			len(undeclared), undeclared)
	}
	if rows == 0 {
		t.Fatal("the capture contains no rows; a before/after over nothing is not evidence")
	}
	counts := corpus.DivergenceCounts()
	t.Logf("rows=%d system_policies=%d org_template_policies=%d divergences=%v",
		rows, len(corpus.System.Policies), len(corpus.OrganizationTemplate.Policies), counts)
}

// TestCorpusCoversEveryCensusedSystemRow holds the built corpus to the census
// in BOTH directions over the system-tier population.
//
// One direction alone is half a check: a corpus missing a row is a shipped
// control that stopped existing, and a corpus carrying a row the census does
// not know about is a control nobody classified.
func TestCorpusCoversEveryCensusedSystemRow(t *testing.T) {
	corpus, _, census := buildCorpusFromCapture(t)

	wantSystem := map[string]bool{}
	for _, r := range census {
		if r.SystemTier() {
			wantSystem[CorpusPolicyIDFor("static_policies", r.PolicyID)] = true
		}
	}
	// Keyed on the CONTROL, so a split row's per-scope variants (#4046) and a
	// multi-policy row's "#n" siblings count once, for the row they came from.
	gotSystem := map[string]bool{}
	for _, p := range corpus.System.Policies {
		control, _, ok := CorpusControlOf(p.ID)
		if !ok {
			control = p.ID
		}
		gotSystem[control] = true
	}

	var missing, extra []string
	for id := range wantSystem {
		if !gotSystem[id] {
			missing = append(missing, id)
		}
	}
	for id := range gotSystem {
		if !wantSystem[id] && strings.HasPrefix(id, "corpus:static_policies:") {
			extra = append(extra, id)
		}
	}
	sort.Strings(missing)
	sort.Strings(extra)
	if len(missing) > 0 {
		t.Errorf("%d censused system-tier row(s) produced no system-root corpus policy: %v", len(missing), missing)
	}
	if len(extra) > 0 {
		t.Errorf("%d system-root corpus policy(ies) come from a static row the census does not class as system tier: %v", len(extra), extra)
	}
	if len(wantSystem) == 0 {
		t.Fatal("the census names no system-tier row; this comparison would be vacuous")
	}
	fromStatic := 0
	for id := range gotSystem {
		if strings.HasPrefix(id, "corpus:static_policies:") {
			fromStatic++
		}
	}
	t.Logf("system-tier census rows: %d; system-root corpus policies from static_policies: %d; system-root policies in total: %d",
		len(wantSystem), fromStatic, len(gotSystem))
}

// TestRegenerateTheShippedCorpusArtifact holds the checked-in artifact to a
// fresh build, byte for byte.
//
// Set AXONFLOW_WRITE_SYSTEM_CORPUS=1 to regenerate. The pair is the pattern
// every pinned fixture in this tree uses, and the reason is the same: an
// artifact nobody can regenerate is an artifact nobody can change, and one
// that regenerates without being compared is not pinned at all.
func TestRegenerateTheShippedCorpusArtifact(t *testing.T) {
	corpus, _, _ := buildCorpusFromCapture(t)

	rendered, err := RenderCorpus(corpus)
	if err != nil {
		t.Fatalf("RenderCorpus: %v", err)
	}
	path := filepath.Join("..", "pdp", ShippedCorpusFileName)
	if os.Getenv("AXONFLOW_WRITE_SYSTEM_CORPUS") == "1" {
		if err := os.WriteFile(path, rendered, 0o644); err != nil {
			t.Fatalf("writing %s: %v", path, err)
		}
		t.Logf("regenerated %s (%d bytes)", path, len(rendered))
		return
	}
	onDisk, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v (regenerate with AXONFLOW_WRITE_SYSTEM_CORPUS=1)", path, err)
	}
	if string(onDisk) != string(rendered) {
		t.Errorf("the checked-in system corpus artifact is not what a fresh build against this database produces.\n"+
			"on disk: %d bytes, rebuilt: %d bytes.\n"+
			"Regenerate with AXONFLOW_WRITE_SYSTEM_CORPUS=1 and read the diff before committing it: this file is the "+
			"platform's own controls, and a change to it changes what every deployment ships.",
			len(onDisk), len(rendered))
	}
}

func sortedSet(in map[string]bool) []string {
	out := make([]string, 0, len(in))
	for k := range in {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
