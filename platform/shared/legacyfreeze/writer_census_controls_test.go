// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package legacyfreeze

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"axonflow/platform/testutil/gocensus"
)

// plantedWriters is a source file planted into THIS package, from memory.
//
// Each declaration is one shape the census must classify correctly:
//   - sinks whose statement is a named constant built by concatenation, a
//     package-level string VARIABLE, and a MAP VALUE in a package-level
//     variable spelled as a schema-qualified TRUNCATE - found at the function
//     that executes each, never at the declaration;
//   - further writes spelled MERGE INTO (held in a STRUCT FIELD of a
//     package-level variable), DELETE FROM ONLY and COPY ... FROM;
//   - three things that name a frozen table and are NOT writes: a log line in
//     prose, a privilege string (REVOKE ..., TRUNCATE ON), and COPY ... TO,
//     which is an export;
//   - a handler that reaches a sink and does not answer, one that answers
//     directly, and one that answers through a bound method the way every
//     real surface does;
//   - a handler LITERAL returned by a setup function that reaches the sink
//     only through an interface;
//   - functions nothing calls.
const plantedWriters = `package legacyfreeze

import (
	"database/sql"
	"net/http"
)

const plantedTable = "dynamic_policies"

const plantedInsert = "INSERT INTO " + plantedTable + " (policy_id) VALUES ($1)"

var plantedDelete = "DELETE FROM static_policies WHERE policy_id = $1"

var plantedStatements = map[string]string{"reset": "TRUNCATE TABLE public.dynamic_policies"}

type plantedRepo struct{ db *sql.DB }

func (r *plantedRepo) plantedCreate() error {
	_, err := r.db.Exec(plantedInsert, "x")
	return err
}

func (r *plantedRepo) plantedRemove() error {
	_, err := r.db.Exec(plantedDelete, "x")
	return err
}

func (r *plantedRepo) plantedReset() error {
	_, err := r.db.Exec(plantedStatements["reset"])
	return err
}

type plantedCreator interface{ plantedCreate() error }

type plantedEnvelope struct{}

func (plantedEnvelope) write(w http.ResponseWriter, status int, code, message string) {
	http.Error(w, message, status)
}

func (e plantedEnvelope) writeFreeze(w http.ResponseWriter, err error) bool {
	return Answer(w, err, "Planted", "create", "t", e.write)
}

func plantedUnclassified(w http.ResponseWriter, r *http.Request) {
	if err := (&plantedRepo{}).plantedCreate(); err != nil {
		http.Error(w, "x", http.StatusInternalServerError)
	}
}

func plantedAnswersDirectly(w http.ResponseWriter, r *http.Request) {
	if err := (&plantedRepo{}).plantedCreate(); err != nil {
		if Answer(w, err, "Planted", "create", "t", plantedEnvelope{}.write) {
			return
		}
	}
}

func plantedAnswersThroughABoundMethod(w http.ResponseWriter, r *http.Request) {
	if err := (&plantedRepo{}).plantedCreate(); err != nil {
		if (plantedEnvelope{}).writeFreeze(w, err) {
			return
		}
	}
}

func plantedThroughAnInterface(c plantedCreator) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := c.plantedCreate(); err != nil {
			http.Error(w, "x", http.StatusInternalServerError)
		}
	}
}

func PlantedNothingCallsThis() error { return (&plantedRepo{}).plantedCreate() }

func PlantedNothingCallsThisEither() error { return (&plantedRepo{}).plantedRemove() }

func PlantedNorThis() error { return (&plantedRepo{}).plantedReset() }

func PlantedLogsOnly() string { return "seeding skipped: this connection may not INSERT into dynamic_policies" }

var plantedMore = struct{ merge string }{merge: "MERGE INTO dynamic_policies AS d USING staged AS s ON d.policy_id = s.policy_id WHEN MATCHED THEN DELETE"}

func (r *plantedRepo) plantedMerge() error {
	_, err := r.db.Exec(plantedMore.merge)
	return err
}

func (r *plantedRepo) plantedDeleteOnly() error {
	_, err := r.db.Exec("DELETE FROM ONLY static_policies WHERE policy_id = $1", "x")
	return err
}

func (r *plantedRepo) plantedCopyIn() error {
	_, err := r.db.Exec("COPY static_policies (policy_id) FROM STDIN")
	return err
}

func (r *plantedRepo) plantedRevokeOnly() error {
	_, err := r.db.Exec("REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON static_policies FROM axonflow_app_role")
	return err
}

func (r *plantedRepo) plantedCopyOut() error {
	_, err := r.db.Exec("COPY static_policies TO STDOUT")
	return err
}

func PlantedWritesMore() error {
	r := &plantedRepo{}
	_ = r.plantedMerge()
	_ = r.plantedDeleteOnly()
	_ = r.plantedRevokeOnly()
	_ = r.plantedCopyOut()
	return r.plantedCopyIn()
}
`

// plantedTwinBase, with one of the two handler bodies below, is a function
// with BUILD-TAG TWINS: the same handler in two builds, answering in one and
// not the other. Its write is spelled UPDATE ONLY with a quoted name.
const plantedTwinBase = `package legacyfreeze

import (
	"database/sql"
	"net/http"
)

type plantedTwinRepo struct{ db *sql.DB }

func (r *plantedTwinRepo) write() error {
	_, err := r.db.Exec("UPDATE ONLY \"static_policies\" SET enabled = false")
	return err
}

func plantedTwinWriter(w http.ResponseWriter, status int, code, message string) {}
`

const plantedTwinAnswers = `
func plantedTwin(w http.ResponseWriter, r *http.Request) {
	if err := (&plantedTwinRepo{}).write(); err != nil {
		if Answer(w, err, "Planted", "twin", "t", plantedTwinWriter) {
			return
		}
	}
}
`

const plantedTwinSilent = `
func plantedTwin(w http.ResponseWriter, r *http.Request) {
	if err := (&plantedTwinRepo{}).write(); err != nil {
		http.Error(w, "x", http.StatusInternalServerError)
	}
}
`

// loadThisPackage resolves the platform module once for the controls and
// returns a builder that type-checks this package with a planted file.
func loadThisPackage(t *testing.T) func(plant string) *callGraph {
	t.Helper()
	root := gocensus.RepoRoot(t)
	m, err := gocensus.Load(filepath.Join(root, "platform"), "")
	if err != nil {
		t.Fatalf("loading %s: %v", platformModule, err)
	}
	const plantName = "zz_planted_writers.go"
	if _, err := os.Stat(filepath.Join(m.Dir(thisPackage), plantName)); err == nil {
		t.Fatalf("a real file named %s exists in %s; the plant would shadow it", plantName, thisPackage)
	}
	return func(plant string) *callGraph {
		t.Helper()
		var extra map[string]string
		if plant != "" {
			extra = map[string]string{plantName: plant}
		}
		files, _, err := m.Parse(thisPackage, extra)
		if err != nil {
			t.Fatalf("parsing %s: %v", thisPackage, err)
		}
		g := newCallGraph()
		if err := g.addPackage(m.Fset, m.Importer, thisPackage, files); err != nil {
			t.Fatalf("type-checking %s with the plant: %v", thisPackage, err)
		}
		g.resolve()
		return g
	}
}

// TestTheWriterCensusFindsWhatItIsPlantedWith proves the census can report
// each outcome it claims to, on inputs whose right answer is known.
//
// NOTHING IS WRITTEN TO THE TREE. The source is parsed from memory; a harness
// that plants by editing a file in a shared clone can be killed between the
// plant and the restore, and the next run then treats the plant as the
// baseline.
func TestTheWriterCensusFindsWhatItIsPlantedWith(t *testing.T) {
	build := loadThisPackage(t)

	// THE BASELINE IS EMPTY, so everything below is attributable to the plant:
	// this package writes no frozen table of its own.
	if rep := build("").reach(); len(rep.sinks) != 0 || len(rep.handlers) != 0 {
		t.Fatalf("the unplanted package already reports %d sink(s) and %d handler(s); the controls below would not be attributable to the plant",
			len(rep.sinks), len(rep.handlers))
	}

	g := build(plantedWriters)
	rep := g.reach()

	// Exactly the methods that EXECUTE a write. The constant, the variable,
	// the map and the struct that hold the statements are declarations and
	// must not be reported, or every package that names a query would be a
	// sink; and the REVOKE string and COPY ... TO name a frozen table without
	// writing it.
	wantSinks := []string{
		"(*" + thisPackage + ".plantedRepo).plantedCopyIn",
		"(*" + thisPackage + ".plantedRepo).plantedCreate",
		"(*" + thisPackage + ".plantedRepo).plantedDeleteOnly",
		"(*" + thisPackage + ".plantedRepo).plantedMerge",
		"(*" + thisPackage + ".plantedRepo).plantedRemove",
		"(*" + thisPackage + ".plantedRepo).plantedReset",
	}
	sort.Strings(wantSinks)
	if strings.Join(rep.sinks, "\n") != strings.Join(wantSinks, "\n") {
		t.Fatalf("sinks = %v, want exactly %v: a write held in a constant CONCATENATION, a package-level "+
			"VARIABLE, a MAP VALUE or a STRUCT FIELD, and spelled MERGE, DELETE FROM ONLY or COPY ... FROM, must be "+
			"found at the function that executes it and nowhere else; a REVOKE string and COPY ... TO are not writes",
			rep.sinks, wantSinks)
	}

	for _, tc := range []struct {
		handler    string
		classified bool
	}{
		{thisPackage + ".plantedUnclassified", false},
		{thisPackage + ".plantedAnswersDirectly", true},
		{thisPackage + ".plantedAnswersThroughABoundMethod", true},
	} {
		if _, reached := rep.handlers[tc.handler]; !reached {
			t.Errorf("the walk did not reach the planted handler %s", tc.handler)
			continue
		}
		if got := g.classified(tc.handler); got != tc.classified {
			t.Errorf("%s classified = %t, want %t", tc.handler, got, tc.classified)
		}
	}

	// A HANDLER LITERAL reached only through an INTERFACE call. Two properties
	// at once: the literal is an entry in its own right, and the interface
	// resolves to the one type that implements it.
	var literal []string
	for h := range rep.handlers {
		if strings.HasPrefix(h, thisPackage+".plantedThroughAnInterface$handler@") {
			literal = append(literal, h)
		}
	}
	if len(literal) != 1 {
		t.Errorf("handler literals reached through the interface = %v, want exactly one", literal)
	} else if g.classified(literal[0]) {
		t.Errorf("%s does not answer the freeze and must be reported unclassified", literal[0])
	}

	// FUNCTIONS NOTHING CALLS are entries the census must report, and only
	// those four are.
	var entries []string
	for e := range rep.entries {
		entries = append(entries, e)
	}
	sort.Strings(entries)
	wantEntries := []string{
		thisPackage + ".PlantedNorThis",
		thisPackage + ".PlantedNothingCallsThis",
		thisPackage + ".PlantedNothingCallsThisEither",
		thisPackage + ".PlantedWritesMore",
	}
	if strings.Join(entries, "\n") != strings.Join(wantEntries, "\n") {
		t.Errorf("entries = %v, want exactly %v", entries, wantEntries)
	}
}

// TestLocalReplacementsAreReadFromGoMod pins how the census domain finds the
// modules the platform module compiles in from this checkout (R3 round two):
// every `replace X => ./dir` or ../dir, single-line or in a block, and never
// a module-version replacement. It runs against a go.mod written to a temporary
// directory - nothing in the tree - and then against the real platform/go.mod,
// which must yield at least one module, or the derivation has gone blind and
// the census domain has quietly shrunk to "requires platform".
func TestLocalReplacementsAreReadFromGoMod(t *testing.T) {
	dir := t.TempDir()
	write := func(rel, body string) {
		t.Helper()
		p := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("root/go.mod", `module example.com/root

replace example.com/single => ./single // a trailing comment

replace (
	example.com/inblock => ../sibling
	example.com/versioned => example.com/fork v1.2.3
)
`)
	write("root/single/go.mod", "module example.com/single\n")
	write("sibling/go.mod", "module example.com/inblock\n")

	got := localReplacements(t, filepath.Join(dir, "root", "go.mod"))
	if want := []string{"example.com/inblock", "example.com/single"}; strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("localReplacements = %v, want %v: both local forms read, the version replacement ignored", got, want)
	}

	real := localReplacements(t, filepath.Join(gocensus.RepoRoot(t), "platform", "go.mod"))
	if len(real) == 0 {
		t.Fatal("platform/go.mod yields no local replacement; it replaces axonflow/platform/decision with ./decision, " +
			"so the derivation is blind and the census domain has lost the code the platform binaries compile in")
	}
}

// TestTheCensusJudgesEachBuildOnItsOwn is R3 round one's F3: a handler whose
// build-tag twins disagree must be reported for the build that does not
// answer. The two builds are two graphs; nothing either holds can vouch for the
// other.
func TestTheCensusJudgesEachBuildOnItsOwn(t *testing.T) {
	build := loadThisPackage(t)
	res := evaluate(map[string]*callGraph{
		"":           build(plantedTwinBase + plantedTwinAnswers),
		"enterprise": build(plantedTwinBase + plantedTwinSilent),
	})

	// The UPDATE ONLY "static_policies" write is found in both builds.
	for _, tags := range gocensus.TagSets {
		if got := res.reports[tags].sinks; len(got) != 1 || got[0] != "(*"+thisPackage+".plantedTwinRepo).write" {
			t.Fatalf("%s: sinks = %v, want the one UPDATE ONLY write", buildLabel(tags), got)
		}
	}
	if len(res.unclassified) != 1 ||
		!strings.HasPrefix(res.unclassified[0], thisPackage+".plantedTwin (") ||
		!strings.Contains(res.unclassified[0], buildLabel("enterprise")) {
		t.Fatalf("unclassified = %v, want exactly the enterprise twin of plantedTwin: the community twin's answer "+
			"must not vouch for it", res.unclassified)
	}
}
