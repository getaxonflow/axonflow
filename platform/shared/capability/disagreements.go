// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package capability

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// DisagreementNarrativesPath is where the prose behind each classified
// disagreement lives, relative to the repository root.
//
// It is NOT in this package, and that is the point. registry.json reaches the
// community mirror because the community build projects its own /health from
// it; technical-docs/ is excluded from the sync. So the CLASS of a
// disagreement — structural, and already implied by the row beside it — ships,
// and the sentence spelling out which Enterprise-marked feature a Community
// build can in fact serve does not. Whether that sentence publishes is an
// operator decision, not a side effect of which directory a file happens to
// live in. Conservative default; reversible in either direction.
const DisagreementNarrativesPath = "technical-docs/capability-census-disagreements.tsv"

// Narrative is the prose behind one classified disagreement.
type Narrative struct {
	ID     string
	Class  Disagreement
	Detail string
}

// Narratives is the whole file, keyed by capability id.
type Narratives map[string]Narrative

// LoadNarratives reads the disagreement narratives.
//
// A missing file is reported as (nil, nil) rather than an error: the community
// mirror does not carry technical-docs/ at all, and a caller there has nothing
// to load and nothing to check. A caller that NEEDS the file — the census
// generator — checks for the directory itself and fails when it exists without
// the file, which is a deleted narrative rather than a stripped one.
func LoadNarratives(root string) (Narratives, error) {
	f, err := os.Open(filepath.Clean(filepath.Join(root, DisagreementNarrativesPath)))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer func() { _ = f.Close() }()

	out := Narratives{}
	sc := bufio.NewScanner(f)
	// A narrative is a paragraph on one line; the default 64KiB token limit is
	// comfortably enough, but a silently truncated line would become a
	// silently truncated finding, so the limit is stated rather than assumed.
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	line := 0
	for sc.Scan() {
		line++
		text := sc.Text()
		if strings.TrimSpace(text) == "" || strings.HasPrefix(text, "#") {
			continue
		}
		parts := strings.Split(text, "\t")
		if len(parts) != 3 {
			return nil, fmt.Errorf("%s:%d: want 3 tab-separated fields (id, class, detail), got %d",
				DisagreementNarrativesPath, line, len(parts))
		}
		id, class, detail := parts[0], Disagreement(parts[1]), strings.TrimSpace(parts[2])
		if _, dup := out[id]; dup {
			return nil, fmt.Errorf("%s:%d: duplicate row for %q", DisagreementNarrativesPath, line, id)
		}
		if !ValidDisagreement(class) {
			return nil, fmt.Errorf("%s:%d: unknown class %q for %q", DisagreementNarrativesPath, line, class, id)
		}
		if detail == "" {
			return nil, fmt.Errorf("%s:%d: %q has an empty detail; a classified disagreement "+
				"with no narrative is a class nobody can act on", DisagreementNarrativesPath, line, id)
		}
		out[id] = Narrative{ID: id, Class: class, Detail: detail}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// Reconcile compares the narratives against the registry in BOTH directions
// and returns the problems.
//
// One direction alone is not a check: only-forward accepts a registry row
// classified with nothing explaining it, and only-backward accepts a narrative
// for a row that no longer disagrees — which is the shape a stale finding
// takes, and the one a reader trusts because it is written down.
func (r *Registry) Reconcile(n Narratives) []string {
	var problems []string
	classified := map[string]Disagreement{}
	for _, e := range r.Entries {
		if e.MatrixDisagreement != "" {
			classified[e.ID] = e.MatrixDisagreement
		}
	}
	for id, class := range classified {
		narrative, ok := n[id]
		if !ok {
			problems = append(problems, fmt.Sprintf(
				"%s is classified %q in the registry and has no narrative in %s",
				id, class, DisagreementNarrativesPath))
			continue
		}
		if narrative.Class != class {
			problems = append(problems, fmt.Sprintf(
				"%s is classified %q in the registry and %q in %s",
				id, class, narrative.Class, DisagreementNarrativesPath))
		}
	}
	for id := range n {
		if _, ok := classified[id]; !ok {
			problems = append(problems, fmt.Sprintf(
				"%s has a narrative in %s but the registry records no disagreement for it; "+
					"the finding is stale", id, DisagreementNarrativesPath))
		}
	}
	sort.Strings(problems)
	return problems
}
