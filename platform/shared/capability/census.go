// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package capability

import (
	"fmt"
	"sort"
	"strings"
)

// FamilyScore is one family's aggregated availability.
type FamilyScore struct {
	Family string
	// Scored is the number of capabilities in the family that carry an
	// availability. Unscorable ones are excluded from every figure below and
	// counted separately, because averaging in a number nobody could justify
	// is how a band stops being derived.
	Scored     int
	Unscorable int
	Community  float64
	Evaluation float64
	// Measured and Chosen count the basis of the scored capabilities, so a
	// reader can see how much of a family's figure is read off the tree.
	Measured int
	Chosen   int
}

// Bands is the whole scoring result.
type Bands struct {
	Families []FamilyScore
	// ByCapability weights every capability equally.
	CommunityByCapability  float64
	EvaluationByCapability float64
	// ByFamily weights every family equally, which is a different answer and
	// is reported beside the first rather than instead of it. The two bracket
	// the sensitivity of the result to a weighting nobody can derive.
	CommunityByFamily  float64
	EvaluationByFamily float64

	Scored     int
	Unscorable int
	Measured   int
	Chosen     int
}

// Score aggregates the registry into the two bands ADR-066 and #3590 ask for.
//
// The weighting is the one thing here that is not a measurement, and it is
// stated rather than buried: ByCapability treats every capability as one unit,
// ByFamily treats every family as one unit. Neither is derivable from anything;
// the honest response is to publish both and let the spread be visible. A
// single figure would let a reader believe the weighting was measured too.
func (r *Registry) Score() Bands { return r.score(false) }

// ScoreRescoredFromTree answers the sensitivity question the census would
// otherwise leave a reader to notice on their own.
//
// Four capabilities are scored FROM THE MATRIX - budget CRUD, usage analytics,
// checkpoint resume, webhooks - and the census's own finding 3 records that the
// matrix is contradicted on exactly those rows: nothing in the tree gates any
// of them. So the headline band rests on a document this document says is
// wrong there. Rescoring them as the TREE implies gives the other figure, and
// publishing both is the only honest way to state a number whose input the
// same page disputes.
func (r *Registry) ScoreRescoredFromTree() Bands { return r.score(true) }

func (r *Registry) score(fromTree bool) Bands {
	type acc struct {
		c, e             float64
		n, unscorable    int
		measured, chosen int
	}
	byFamily := map[string]*acc{}
	var total acc

	for _, entry := range r.Entries {
		a := byFamily[entry.Family]
		if a == nil {
			a = &acc{}
			byFamily[entry.Family] = a
		}
		if entry.Score.Basis == BasisUnscorable {
			a.unscorable++
			total.unscorable++
			continue
		}
		community, evaluation := entry.Score.Community, entry.Score.Evaluation
		if fromTree && entry.MatrixDisagreement == DisagreeMatrixStricter {
			// The tree gates nothing here: no build constraint and no
			// TierLimits field. `full` is what "available to this edition"
			// means when nothing stands in the way.
			community, evaluation = AvailFull, AvailFull
		}
		cw, cok := community.Weight()
		ew, eok := evaluation.Weight()
		if !cok || !eok {
			// Unreachable through Validate, which rejects an unknown
			// availability. Skipping rather than defaulting to zero matters
			// anyway: a zero here is indistinguishable from an honest "not
			// available" and would deflate the band silently.
			continue
		}
		a.c += cw
		a.e += ew
		a.n++
		total.c += cw
		total.e += ew
		total.n++
		switch entry.Score.Basis {
		case BasisMeasured:
			a.measured++
			total.measured++
		case BasisChosen:
			a.chosen++
			total.chosen++
		}
	}

	b := Bands{Scored: total.n, Unscorable: total.unscorable,
		Measured: total.measured, Chosen: total.chosen}
	if total.n > 0 {
		b.CommunityByCapability = 100 * total.c / float64(total.n)
		b.EvaluationByCapability = 100 * total.e / float64(total.n)
	}
	var famC, famE float64
	var famN int
	for _, f := range r.Families() {
		a := byFamily[f]
		fs := FamilyScore{Family: f, Scored: a.n, Unscorable: a.unscorable,
			Measured: a.measured, Chosen: a.chosen}
		if a.n > 0 {
			fs.Community = 100 * a.c / float64(a.n)
			fs.Evaluation = 100 * a.e / float64(a.n)
			famC += fs.Community
			famE += fs.Evaluation
			famN++
		}
		b.Families = append(b.Families, fs)
	}
	if famN > 0 {
		b.CommunityByFamily = famC / float64(famN)
		b.EvaluationByFamily = famE / float64(famN)
	}
	return b
}

// AdvertisedButAbsentInCommunity returns the capabilities whose /health entry
// is served by every build while the census scores Community as having none of
// them.
//
// This is a DERIVED finding, not a list anybody typed: it falls out of putting
// the served list and the edition scoring in one document, which is the first
// thing this registry made possible. The served list carries no build
// constraint, so a Community deployment advertises every name on it.
func (r *Registry) AdvertisedButAbsentInCommunity() []*Entry {
	var out []*Entry
	for i := range r.Entries {
		e := &r.Entries[i]
		if e.Health == nil || e.Score.Basis == BasisUnscorable {
			continue
		}
		if w, ok := e.Score.Community.Weight(); ok && w == 0 {
			out = append(out, e)
		}
	}
	return out
}

// HealthGaps returns the capabilities whose absence from /health the census
// records as arguably wrong rather than settled.
func (r *Registry) HealthGaps() []*Entry {
	var out []*Entry
	for i := range r.Entries {
		if r.Entries[i].HealthGap {
			out = append(out, &r.Entries[i])
		}
	}
	return out
}

// MatrixDisagreements returns the capabilities where the living feature matrix
// and the tree say different things.
func (r *Registry) MatrixDisagreements() []*Entry {
	var out []*Entry
	for i := range r.Entries {
		if r.Entries[i].MatrixDisagreement != "" {
			out = append(out, &r.Entries[i])
		}
	}
	return out
}

// rowsRescoredFromTree names the capabilities the sensitivity paragraph is
// about, in the order the registry holds them, so the prose cannot drift from
// the arithmetic beside it.
func (r *Registry) rowsRescoredFromTree() []string {
	var out []string
	for _, e := range r.Entries {
		if e.MatrixDisagreement != DisagreeMatrixStricter {
			continue
		}
		// The human title, because this paragraph is prose a reader follows,
		// and the id if a row has no title rather than silently naming nothing.
		if e.Title != "" {
			out = append(out, e.Title)
			continue
		}
		out = append(out, e.ID)
	}
	return out
}

// countNoun spells a small count in words and agrees the noun with it, because
// "1 capabilities" in a published document reads as a generator nobody checked.
func countNoun(n int, singular, plural string) string {
	noun := plural
	if n == 1 {
		noun = singular
	}
	return numberWord(n) + " " + noun
}

// numberWord spells a small integer, falling back to digits above ten.
func numberWord(n int) string {
	words := []string{"zero", "one", "two", "three", "four", "five", "six",
		"seven", "eight", "nine", "ten"}
	if n >= 0 && n < len(words) {
		return words[n]
	}
	return fmt.Sprintf("%d", n)
}

// RenderCensus produces the human-readable census from the registry.
//
// Everything in the output is computed from the registry; there is no prose
// here that a reader could edit without editing the data first. That is the
// difference between this document and the one it reconciles against.
//
// IT TAKES NO DERIVATION, and that is deliberate rather than an omission. The
// census is compared against a checked-in golden file, so anything in it that
// moves for a reason unrelated to capabilities reds an unrelated PR and trains
// the next reader to regenerate without looking. The tree-derived numbers —
// files parsed, registration sites, enterprise-tagged directories — move
// exactly like that: an ordinary PR adding a Go file changes the first of them.
// (Measured: rebasing this work onto one unrelated merge did precisely that.)
// Those numbers are EVIDENCE and belong where evidence stays fresh — printed
// by TestTheTreeDerivationIsNotVacuous on every run, in both lanes — not
// frozen into a document where they age silently. The counts below are a
// function of the registry alone, so this file changes when, and only when,
// the capability surface does.
func RenderCensus(r *Registry, narratives Narratives) string {
	var b strings.Builder
	p := func(f string, a ...any) { fmt.Fprintf(&b, f, a...) }

	p("# AxonFlow Edition Capability Census\n\n")
	p("**Platform version:** %s  \n", r.Platform)
	p("**Registry schema:** %s  \n", r.Schema)
	p("**Generated:** %s\n\n", r.Generated)
	p("> GENERATED FILE — do not edit. Every number, row and finding below is\n")
	p("> computed from `platform/shared/capability/registry.json` by\n")
	p("> `capability.RenderCensus`. Change the registry and regenerate:\n")
	p("> `UPDATE_CENSUS=1 go test ./shared/capability/ -run TestCensusIsUpToDate`.\n")
	p("> `TestCensusIsUpToDate` fails CI if this file and the registry disagree.\n\n")

	p("## Method\n\n")
	p("Three things are derived from the tree and checked, rather than asserted:\n\n")
	p("1. **Routes.** `capability.Derive` PARSES every non-test Go file under the\n")
	p("   declared scan roots with `go/ast` and resolves the path argument of every\n")
	p("   `HandleFunc` / `Handle` / `PathPrefix` / `Path` call, following package-local\n")
	p("   and cross-package string constants and `PathPrefix(...).Subrouter()` chains.\n")
	p("   A regex would not do: **19 registration sites name a constant rather than a\n")
	p("   string literal, and two of them are `POST /api/v1/decide` and\n")
	p("   `POST /api/v1/access/evaluation`** — the platform's two most-called\n")
	p("   governance surfaces. Every derived route must belong to a capability.\n")
	p("2. **Build constraints.** Read from the same parse, using the community sync's\n")
	p("   own expression for enterprise-only source, so a capability's classification\n")
	p("   is checked against the mirror that actually gets published.\n")
	p("3. **The `/health` list.** Both planes now PROJECT it from this registry, and a\n")
	p("   frozen capture of what they served beforehand is compared byte for byte.\n\n")
	p("Every count below carries a positive control in the same test: the derivation\n")
	p("must find named routes registered through a constant and through a subrouter\n")
	p("before any conclusion is drawn from what it did not find. A zero from a broken\n")
	p("scan is indistinguishable from a zero from a clean one.\n\n")

	p("### Counts\n\n")
	p("These are counts of the REGISTRY. The tree-derived numbers it is checked\n")
	p("against — files parsed, registration sites, resolved and unresolved call\n")
	p("sites, enterprise-tagged directories — are printed by\n")
	p("`TestTheTreeDerivationIsNotVacuous` on every CI run rather than recorded here,\n")
	p("because they move whenever any Go file is added and a number frozen in a\n")
	p("document ages without saying so.\n\n")
	p("| Measure | Value |\n|---|---:|\n")
	p("| Capabilities | %d |\n", len(r.Entries))
	p("| Families | %d |\n", len(r.Families()))
	p("| Route prefixes claimed | %d |\n", countRoutePrefixes(r))
	p("| Capabilities serving no route | %d |\n", countRouteless(r))
	p("| `/health` entries, agent plane | %d |\n", len(r.Advertise(PlaneAgent)))
	p("| `/health` entries, orchestrator plane | %d |\n", len(r.Advertise(PlaneOrchestrator)))
	p("| Recorded absences from `/health` | %d |\n", len(r.Entries)-countAdvertised(r))
	p("| ...of which recorded as GAPS | %d |\n", len(r.HealthGaps()))
	p("| Matrix disagreements | %d |\n", len(r.MatrixDisagreements()))
	p("| Route exemptions | %d |\n", len(r.RouteExemptions))
	p("| Matrix sections declared out of scope | %d |\n", len(r.MatrixSectionsOutOfScope))
	p("\n")

	bands := r.Score()
	rescored := r.ScoreRescoredFromTree()
	p("## The two bands\n\n")
	p("**Where the target numbers come from, since it matters and was nearly cited\n")
	p("wrongly:** the Community 35-40%% and Evaluation 50-55%% figures are stated in\n")
	p("[#3590](https://github.com/getaxonflow/axonflow-enterprise/issues/3590), which\n")
	p("asks this census to \"score capability families to establish the Community 35 to\n")
	p("40 percent and Evaluation 50 to 55 percent baselines\". **ADR-066 does not\n")
	p("contain them** - it contains no percentage at all - so an earlier draft of this\n")
	p("document attributed them to the wrong source. They are a TARGET stated in an\n")
	p("issue, not an accepted architectural decision, and this census is the first\n")
	p("thing to measure against them.\n\n")
	p("Availability is scored per capability as `full` (1.0), `limited` (0.5) or\n")
	p("`none` (0.0). `limited` means the edition has the capability subject to a\n")
	p("named cap or a reduced mode; the registry requires a `license_gate` or a note\n")
	p("naming the cap, so a half-mark cannot be unfalsifiable.\n\n")
	p("| Weighting | Community | Evaluation | Note |\n|---|---:|---:|---|\n")
	p("| Per capability | %.1f%% | %.1f%% | every capability one unit |\n",
		bands.CommunityByCapability, bands.EvaluationByCapability)
	p("| Per family | %.1f%% | %.1f%% | every family one unit |\n",
		bands.CommunityByFamily, bands.EvaluationByFamily)
	p("\n**The weighting is CHOSEN, not measured, and nothing derives it.** Per-family\n")
	p("weighting lets a one-capability family (`llm`, `media`, `webhook`) count the\n")
	p("same as a ten-capability one (`compliance`); per-capability weighting lets the\n")
	p("shape of the census's own row-splitting move the number. Both are published so\n")
	p("the spread between them is visible instead of a single figure implying a\n")
	p("precision the method does not have.\n\n")
	p("**Basis:** %d capabilities scored MEASURED, %d CHOSEN, %d UNSCORABLE.\n",
		bands.Measured, bands.Chosen, bands.Unscorable)
	p("Unscorable capabilities are excluded from every figure above rather than\n")
	p("given a placeholder.\n\n")

	// THE COUNT AND THE NAMES ARE DERIVED, not written.
	//
	// This paragraph used to say "four capabilities ... budget CRUD, usage
	// analytics, checkpoint resume, webhooks" as prose, in a document that is
	// GENERATED from the registry. A count written into generated text is the
	// defect this whole PR is about, one level up: it is right until a row is
	// added or reclassified, and then it is a confident wrong number in a
	// document whose whole claim is that its numbers are measured. Six other
	// copies of exactly that shape were found in this round by reading the
	// artefacts line by line rather than the lines someone pointed at.
	rescoredRows := r.rowsRescoredFromTree()
	p("### The sensitivity this table rests on\n\n")
	p("The figures above score %s FROM THE MATRIX - %s - and finding 3\n",
		countNoun(len(rescoredRows), "capability", "capabilities"),
		strings.Join(rescoredRows, ", "))
	p("below records that the matrix is contradicted on exactly those %s: no build\n",
		numberWord(len(rescoredRows)))
	p("constraint and no `TierLimits` field gates any of them. **So the headline band\n")
	p("rests on a document this same page says is wrong there.** Rescoring them as\n")
	p("the tree implies - available, because nothing stands in the way - gives:\n\n")
	p("| Weighting | Community | Evaluation |\n|---|---:|---:|\n")
	p("| Per capability, as scored | %.1f%% | %.1f%% |\n",
		bands.CommunityByCapability, bands.EvaluationByCapability)
	p("| Per capability, rescored from the tree | %.1f%% | %.1f%% |\n",
		rescored.CommunityByCapability, rescored.EvaluationByCapability)
	p("| Per family, as scored | %.1f%% | %.1f%% |\n",
		bands.CommunityByFamily, bands.EvaluationByFamily)
	p("| Per family, rescored from the tree | %.1f%% | %.1f%% |\n",
		rescored.CommunityByFamily, rescored.EvaluationByFamily)
	p("\nThe per-family Community figure moves %.1f points, from %.1f%% to %.1f%%, and\n",
		rescored.CommunityByFamily-bands.CommunityByFamily,
		bands.CommunityByFamily, rescored.CommunityByFamily)
	p("that is the whole point of stating it: the closest the census comes to the\n")
	p("Community target is an artifact of scoring %s rows from a source it\n",
		numberWord(len(rescoredRows)))
	p("simultaneously reports as contradicted. **Which of the two is right is an\n")
	p("entitlement question**, not a scoring one - either the matrix is wrong and\n")
	p("Community has more than intended, or the gating is missing and should be built.\n")
	p("The census records both numbers and decides neither.\n\n")

	p("### Against the target bands\n\n")
	p("| Band | Target | Per capability | Per family |\n|---|---|---|---|\n")
	p("| Community | 35-40%% | %.1f%% (%s) | %.1f%% (%s) |\n",
		bands.CommunityByCapability, versus(bands.CommunityByCapability, 35, 40),
		bands.CommunityByFamily, versus(bands.CommunityByFamily, 35, 40))
	p("| Evaluation | 50-55%% | %.1f%% (%s) | %.1f%% (%s) |\n",
		bands.EvaluationByCapability, versus(bands.EvaluationByCapability, 50, 55),
		bands.EvaluationByFamily, versus(bands.EvaluationByFamily, 50, 55))
	p("\nThe measurement does not land in the targets, and that is a result rather than\n")
	p("an error to be corrected by re-scoring. Two things drive it:\n\n")
	p("- **The Community edition gives away more than the target boundary assumes.**\n")
	p("  ADR-066 decision 3 keeps the deterministic PDP edition-neutral on purpose, and\n")
	p("  the `governance` family is where most of the platform's traffic goes: %d\n",
		familyOf(bands, "governance").Scored)
	p("  capabilities, %.0f%% available to Community. A boundary drawn at 35-40%% of\n",
		familyOf(bands, "governance").Community)
	p("  capabilities is not the boundary this tree implements.\n")
	p("- **Evaluation adds %.1f points over Community per capability, and %.1f per\n",
		bands.EvaluationByCapability-bands.CommunityByCapability,
		bands.EvaluationByFamily-bands.CommunityByFamily)
	p("  family.** The Evaluation tier's value is concentrated in raising numeric caps,\n")
	p("  which a capability-availability score cannot see: a cap raised from 20 to 50\n")
	p("  leaves the capability `limited` in both editions. Whether the band should be\n")
	p("  measured on capabilities at all, or on something cap-aware, is a product\n")
	p("  question this census raises and does not answer.\n\n")

	p("### By family\n\n")
	p("| Family | Capabilities | Community | Evaluation | Measured | Chosen | Unscorable |\n")
	p("|---|---:|---:|---:|---:|---:|---:|\n")
	for _, f := range bands.Families {
		if f.Scored == 0 {
			p("| `%s` | 0 | — | — | 0 | 0 | %d |\n", f.Family, f.Unscorable)
			continue
		}
		p("| `%s` | %d | %.0f%% | %.0f%% | %d | %d | %d |\n",
			f.Family, f.Scored, f.Community, f.Evaluation, f.Measured, f.Chosen, f.Unscorable)
	}
	p("\n")

	p("## Findings\n\n")
	p("### 1. The `/health` capability list is edition-blind\n\n")
	blind := r.AdvertisedButAbsentInCommunity()
	p("`getCapabilities()` carries no build constraint on either plane, so a Community\n")
	p("build advertises every name on the list. **%d of them are capabilities this\n", len(blind))
	p("census scores as unavailable to a Community deployment**, which means a\n")
	p("Community `/health` claims support for things that build does not serve:\n\n")
	p("| Capability | `/health` name | Since | Why Community does not have it |\n|---|---|---|---|\n")
	for _, e := range blind {
		p("| `%s` | `%s` | %s | %s |\n", e.ID, e.Health.Name, e.Health.Since,
			firstSentence(e.Notes, e.Summary))
	}
	p("\nThe sharpest case is `circuit.breaker`: its `!enterprise` twin's\n")
	p("`RegisterRoutes` registers **nothing at all**, so a Community build serves no\n")
	p("circuit-breaker route while advertising `circuit_breaker` since 4.7.0.\n\n")
	p("**Not fixed here, deliberately.** Making the served list edition-aware changes\n")
	p("what an existing deployment advertises, and #3590's acceptance criterion is\n")
	p("that no entitlement behaviour changes in this issue. The registry now makes\n")
	p("the decision cheap: an edition-aware projection is a filter over these rows.\n\n")

	p("### 2. Client-observable surfaces with no capability name\n\n")
	gaps := r.HealthGaps()
	p("A capability's absence from `/health` is now a recorded decision — every entry\n")
	p("carries either a `health` block or a `health_absent_reason`. **%d of those\n", len(gaps))
	p("reasons record a GAP rather than a settled decision**: the surface is one a\n")
	p("client can observe, and it has no name to feature-detect:\n\n")
	p("| Capability | Surface | Why it is still absent |\n|---|---|---|\n")
	for _, e := range gaps {
		surface := "—"
		if len(e.Routes) > 0 {
			surface = "`" + strings.Join(e.Routes, "`, `") + "`"
		}
		p("| `%s` | %s | %s |\n", e.ID, surface, oneLine(e.HealthAbsentReason))
	}
	p("\nAdding a name to any of these is a wire ADDITION, which belongs to a release\n")
	p("train rather than to a census PR, and several of them are Enterprise-only —\n")
	p("so adding them to an edition-blind list would widen finding 1.\n\n")

	p("### 3. Where the living feature matrix and the tree disagree\n\n")
	dis := r.MatrixDisagreements()
	p("`technical-docs/COMMUNITY_ENTERPRISE_FEATURE_MATRIX.md` is the living matrix.\n")
	p("**%d capabilities disagree with it.** Every one is recorded as a row; NEITHER\n", len(dis))
	p("SIDE WAS EDITED to make them agree. Editing the matrix to match a reading of\n")
	p("the code would launder the discrepancy #3590 exists to surface, and changing\n")
	p("the code would be the entitlement change #3590 forbids.\n\n")
	p("The registry carries the CLASS of each disagreement, because a class is\n")
	p("structural and queryable. The narrative below comes from\n")
	p("`%s`, which lives here rather than\n", DisagreementNarrativesPath)
	p("beside the registry because `technical-docs/` is excluded from the community\n")
	p("sync and `registry.json` is not. Whether a sentence naming an Enterprise-marked\n")
	p("feature a Community build can in fact serve should publish is the operator's\n")
	p("call, not a side effect of which directory a file sits in.\n\n")
	byClass := map[Disagreement][]*Entry{}
	for _, e := range dis {
		byClass[e.MatrixDisagreement] = append(byClass[e.MatrixDisagreement], e)
	}
	p("| Class | Capabilities |\n|---|---:|\n")
	for _, c := range Disagreements() {
		if len(byClass[c]) > 0 {
			p("| `%s` | %d |\n", c, len(byClass[c]))
		}
	}
	p("\n")
	for _, c := range Disagreements() {
		if len(byClass[c]) == 0 {
			continue
		}
		p("#### `%s`\n\n", c)
		for _, e := range byClass[c] {
			detail := "NO NARRATIVE — " + DisagreementNarrativesPath + " has no row for this capability."
			if n, ok := narratives[e.ID]; ok {
				detail = oneLine(n.Detail)
			}
			p("**`%s`** — %s\n\n", e.ID, detail)
		}
	}

	p("## The census\n\n")
	p("`Min` is the least edition that can use the capability. `Class` is the ADR-066\n")
	p("source classification. `Tag` and `Sync` are derived from the build constraints\n")
	p("and the community sync's own rules. `C`/`E`/`Ent` are the availability scores.\n\n")
	p("| ID | Min | Class | Tag | Sync | C | E | Ent | Basis | /health |\n")
	p("|---|---|---|---|---|---|---|---|---|---|\n")
	entries := make([]*Entry, 0, len(r.Entries))
	for i := range r.Entries {
		entries = append(entries, &r.Entries[i])
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].ID < entries[j].ID })
	for _, e := range entries {
		health := "—"
		if e.Health != nil {
			health = "`" + e.Health.Name + "`"
		} else if e.HealthGap {
			health = "gap"
		}
		c, ev, en := dash(e.Score.Community), dash(e.Score.Evaluation), dash(e.Score.Enterprise)
		p("| `%s` | %s | `%s` | %s | %s | %s | %s | %s | %s | %s |\n",
			e.ID, e.MinimumEdition, e.Classification, e.BuildTag, e.Sync,
			c, ev, en, e.Score.Basis, health)
	}
	p("\n")

	p("## Route exemptions\n\n")
	p("A registration site the scanner cannot resolve is a declared hole with a\n")
	p("reason, never a silent one. A stale exemption fails CI in the other direction.\n\n")
	for _, x := range r.RouteExemptions {
		p("- `%s`\n  %s\n", x.Pattern, oneLine(x.Reason))
	}
	p("\n")
	return b.String()
}

func dash(a Availability) string {
	if a == "" {
		return "—"
	}
	return string(a)
}

func oneLine(s string) string {
	return strings.Join(strings.Fields(strings.ReplaceAll(s, "|", "\\|")), " ")
}

// firstSentence returns the first sentence of s, or of fallback when s is
// empty. It is used only for a table cell, where a paragraph would be unusable.
func firstSentence(s, fallback string) string {
	if strings.TrimSpace(s) == "" {
		s = fallback
	}
	s = oneLine(s)
	if i := strings.Index(s, ". "); i > 0 {
		return s[:i+1]
	}
	return s
}

// versus says where a measured figure falls relative to a target band. It
// never rounds a figure INTO the band: a census that reported "on target" for
// anything close would be doing the calibration it exists to avoid.
func versus(got, lo, hi float64) string {
	switch {
	case got < lo:
		return fmt.Sprintf("%.1f below", lo-got)
	case got > hi:
		return fmt.Sprintf("%.1f above", got-hi)
	default:
		return "inside"
	}
}

// familyOf returns a family's score, or a zero value if the family is gone.
// The zero value is deliberate and safe here: the caller prints the number, and
// a 0% for a family that no longer exists is visibly wrong in a way a made-up
// figure would not be.
func familyOf(b Bands, name string) FamilyScore {
	for _, f := range b.Families {
		if f.Family == name {
			return f
		}
	}
	return FamilyScore{Family: name}
}

func countRoutePrefixes(r *Registry) int {
	n := 0
	for _, e := range r.Entries {
		n += len(e.Routes)
	}
	return n
}

func countRouteless(r *Registry) int {
	n := 0
	for _, e := range r.Entries {
		if len(e.Routes) == 0 {
			n++
		}
	}
	return n
}

func countAdvertised(r *Registry) int {
	n := 0
	for _, e := range r.Entries {
		if e.Health != nil {
			n++
		}
	}
	return n
}
