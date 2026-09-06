// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package identity

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// The two censuses below READ SOURCE FROM DISK, and that is why each one is
// split into a scan half and a DECISION half.
//
// A `go test -overlay` mutant - the mechanism the compatmutation harness uses
// for every other guard in this package - is a compiler input, not a
// filesystem: a census that opens the file itself sees the ORIGINAL bytes and
// passes, which reads exactly like a guard that caught nothing. So neither
// census can be killed by a mutant, and an exemption alone would leave them
// unproven.
//
// Instead the decision each census makes is a pure function over material the
// test supplies, and two planted-input tests below feed each one the shape it
// exists to catch and require it to report. That is a failing input, produced
// here rather than promised.
// ---------------------------------------------------------------------------

// missingEnvReads is the DECISION half of the EnvCompatConfig census: given the
// package's env-name constants, the text of the single reader, and the
// exemptions, it reports what is wrong. Pure, so it can be fed a planted input.
//
// # checkStale IS A BUILD-TAG QUESTION, NOT A STRICTNESS DIAL
//
// "This exemption names a constant that does not exist" is only answerable in a
// build that can SEE every constant, and this package's constant set differs by
// build tag: EnvOrgSettingsTTLSeconds and EnvSegmentCacheTTLSeconds are
// declared in enterprise-tagged files, and the community mirror STRIPS those
// files, so under the community build the names genuinely do not resolve.
//
// The first version asked the question unconditionally and reported both as
// stale on the mirror - a true statement about that tree and a false one about
// the exemption, which is a considered decision about an enterprise-only
// variable. So the staleness half runs only under the enterprise tag (see
// compat_env_reader_enterprise_test.go), where a constant absent from the
// parse is absent from EVERY build and the exemption really is dead.
//
// The half that matters in BOTH builds is the other one, and it is unchanged:
// every constant this build can see is read by EnvCompatConfig or exempted.
func missingEnvReads(envConsts map[string]string, readerBody string, notBootstrap map[string]string, checkStale bool) []string {
	var problems []string
	if checkStale {
		for id, why := range notBootstrap {
			if _, exists := envConsts[id]; !exists {
				problems = append(problems, "stale exemption: "+id+" ("+why+") names a constant that no longer exists")
			}
		}
	}
	for id, envName := range envConsts {
		if why, excluded := notBootstrap[id]; excluded {
			if strings.Contains(readerBody, id) {
				problems = append(problems, "exempt but read: "+id+" ("+why+")")
			}
			continue
		}
		if !strings.Contains(readerBody, id) {
			problems = append(problems, "not read: "+id+" ("+envName+")")
		}
	}
	sort.Strings(problems)
	return problems
}

// parseEnvConstantsAndReader is the SCAN half: the constants this package
// declares and the source text of EnvCompatConfig, both read from dir.
func parseEnvConstantsAndReader(t *testing.T, dir string) (map[string]string, string) {
	t.Helper()
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, dir, func(fi os.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", dir, err)
	}
	envConsts := map[string]string{}
	readerBody := ""
	for _, p := range pkgs {
		for _, f := range p.Files {
			for _, decl := range f.Decls {
				if gd, ok := decl.(*ast.GenDecl); ok && gd.Tok == token.CONST {
					for _, spec := range gd.Specs {
						vs, ok := spec.(*ast.ValueSpec)
						if !ok || len(vs.Names) == 0 || len(vs.Values) == 0 {
							continue
						}
						id := vs.Names[0].Name
						lit, ok := vs.Values[0].(*ast.BasicLit)
						if !ok || !strings.HasPrefix(id, "Env") {
							continue
						}
						if val := strings.Trim(lit.Value, `"`); strings.HasPrefix(val, "AXONFLOW_") {
							envConsts[id] = val
						}
					}
				}
				if fd, ok := decl.(*ast.FuncDecl); ok && fd.Name.Name == "EnvCompatConfig" {
					src, rerr := os.ReadFile(filepath.Clean(fset.Position(fd.Pos()).Filename))
					if rerr != nil {
						t.Fatalf("read the file declaring EnvCompatConfig: %v", rerr)
					}
					readerBody = string(src)[fset.Position(fd.Pos()).Offset:fset.Position(fd.End()).Offset]
				}
			}
		}
	}
	return envConsts, readerBody
}

// TestEnvCompatConfigReadsEveryCompatEnvVar is the guard for the defect that
// produced this helper, and it is DERIVED rather than a list.
//
// The agent and the orchestrator each built a bootstrap config, each reading
// the same environment variables by hand. When AXONFLOW_IDENTITY_COMPAT_PATHS
// was added (#3634) only one copy grew, so the orchestrator kept evaluating
// every path while its compose line and the documentation said otherwise -
// dead configuration that changed nothing observable, which is the worst shape
// a config bug can take because nothing fails.
//
// A test that listed the three variables would have to be remembered when a
// fourth arrives - the same remembering that failed. So the expected set is
// read from the PACKAGE's own env-name constants, and the assertion is that
// EnvCompatConfig mentions each one. A new Env* constant fails this test until
// it is either read here or explicitly excluded below with a reason.
// compatEnvExemptions are the constants that name an environment variable but
// are NOT part of the bootstrap config, each with the reason it is not.
//
// ONE list, read by the census here and by the staleness check in the
// enterprise-tagged file. Two lists would be two things to keep in step, and
// the one that drifted would be the one that runs in fewer builds.
func compatEnvExemptions() map[string]string {
	return map[string]string{
		// Read by the settings store, which has its own lifetime and is
		// constructed separately from the adapter.
		"EnvOrgSettingsTTLSeconds": "read by the org settings store, not the adapter bootstrap",
		// Read inside BootstrapCompat itself when building the recorder, not
		// carried on the config.
		"EnvAgreementLogEvery": "consumed directly when the log recorder is built",
		// The trust gate for upstream identity headers. It decides whether a
		// header is honoured at all, upstream of the adapter, and is read by
		// the binaries' own auth paths rather than by the compat bootstrap.
		"EnvVar": "the X-User-Email trust gate, read on the authentication path, not by the adapter",
		// The segment cache's lifetime, owned by the segment resolver.
		"EnvSegmentCacheTTLSeconds": "the fleet segment cache's TTL, owned by the resolver",
		// The DECISION axis's own process mode. It is parsed by
		// ParseDecisionShadowMode and consumed by planeshadow, which imports
		// this package; the identity adapter never reads it.
		"EnvDecisionShadowMode": "the decision axis's process mode, consumed by planeshadow",
	}
}

func TestEnvCompatConfigReadsEveryCompatEnvVar(t *testing.T) {
	notBootstrap := compatEnvExemptions()

	envConsts, readerBody := parseEnvConstantsAndReader(t, ".")

	// ANTI-VACUITY, both directions: a census that found no constants, or no
	// reader, passes trivially and would keep passing after the helper was
	// deleted.
	if len(envConsts) == 0 {
		t.Fatal("the census found no AXONFLOW_* env constants in this package; the extraction, not the code, is broken")
	}
	if readerBody == "" {
		t.Fatal("EnvCompatConfig was not found. It is the single reader of the compat environment; without it each " +
			"binary reads the variables itself, which is exactly how the per-path lever reached only the agent.")
	}

	// THE EXEMPTION LIST IS A CLOSED SET, AND A STALE ENTRY IS THE SECOND WAY
	// THIS GOES BLIND. Every exemption names a constant that must still exist:
	// if the constant is renamed or deleted, the exemption covers nothing while
	// staying in the list looking like a considered decision, so the next
	// reader trusts it. missingEnvReads reports both directions.
	// checkStale=false: see missingEnvReads. Under the community build two of
	// the exemptions name constants declared in enterprise-tagged files the
	// mirror strips, and calling those stale would be a false statement about a
	// considered decision. The enterprise-tagged sibling asks that half.
	for _, problem := range missingEnvReads(envConsts, readerBody, notBootstrap, false) {
		t.Errorf("%s\n\n"+
			"Every binary bootstraps the compat adapter from ONE function, EnvCompatConfig. A variable it does not "+
			"read is one that reaches no binary while still being declared in compose and documented - dead "+
			"configuration that changes nothing observable, which is how #3634's per-path lever reached the agent "+
			"and not the orchestrator. Read it there, or add it to notBootstrap with the reason.", problem)
	}
}

// TestEnvCompatConfigCensusReportsAPlantedOmission is that census's failing
// input, and it exists because no mutant can produce one.
//
// The census reads this package's source FROM DISK, so a `go test -overlay`
// mutant - the only mutation mechanism this repo has - is invisible to it: the
// overlay changes what the compiler sees, never what os.ReadFile returns. A
// census with no demonstrated failing input is indistinguishable from one whose
// extraction silently returns nothing, which is the exact failure its
// anti-vacuity checks exist for. So the DECISION half is fed the three shapes
// it must report, plus the clean case it must not.
func TestEnvCompatConfigCensusReportsAPlantedOmission(t *testing.T) {
	envConsts := map[string]string{
		"EnvCompatMode":  "AXONFLOW_IDENTITY_COMPAT_MODE",
		"EnvCompatPaths": "AXONFLOW_IDENTITY_COMPAT_PATHS",
		"EnvSomeoneElse": "AXONFLOW_SOMETHING_ELSE",
	}
	exempt := map[string]string{"EnvSomeoneElse": "owned by another component"}

	// 1. THE DEFECT THIS WHOLE FILE EXISTS FOR: a variable declared, documented
	//    and never read by the single reader.
	got := missingEnvReads(envConsts, "func EnvCompatConfig() { os.Getenv(EnvCompatMode) }", exempt, true)
	if len(got) != 1 || !strings.Contains(got[0], "EnvCompatPaths") {
		t.Errorf("a reader that omits EnvCompatPaths was reported as %v; the census cannot see the omission it "+
			"was written for, and would pass on the very defect that produced it", got)
	}

	// 2. A STALE EXEMPTION - a constant that no longer exists, still listed.
	got = missingEnvReads(envConsts, "func EnvCompatConfig() { os.Getenv(EnvCompatMode); os.Getenv(EnvCompatPaths) }",
		map[string]string{"EnvSomeoneElse": "owned elsewhere", "EnvLongDeleted": "renamed two releases ago"}, true)
	if len(got) != 1 || !strings.Contains(got[0], "EnvLongDeleted") {
		t.Errorf("a stale exemption was reported as %v; an exemption naming a constant that is gone covers nothing "+
			"while reading as a decision somebody made", got)
	}

	// 3. EXEMPT AND READ AT ONCE - the exemption is a lie in the other
	//    direction, and the next author reads it as one.
	got = missingEnvReads(envConsts,
		"func EnvCompatConfig() { os.Getenv(EnvCompatMode); os.Getenv(EnvCompatPaths); os.Getenv(EnvSomeoneElse) }", exempt, true)
	if len(got) != 1 || !strings.Contains(got[0], "EnvSomeoneElse") {
		t.Errorf("a constant that is both exempt and read was reported as %v", got)
	}

	// 4. THE CLEAN CASE. Without it, a decision function that reported
	//    everything unconditionally would satisfy all three checks above.
	got = missingEnvReads(envConsts,
		"func EnvCompatConfig() { os.Getenv(EnvCompatMode); os.Getenv(EnvCompatPaths) }", exempt, true)
	if len(got) != 0 {
		t.Errorf("a correct reader was reported as defective (%v); the three positives above would then be "+
			"evidence about a function that always complains", got)
	}

	// 5. THE BUILD-TAG CASE, IN BOTH DIRECTIONS, and it is the one this
	//    function was wrong about on the community mirror.
	//
	//    An exemption naming a constant this BUILD cannot see - an
	//    enterprise-tagged declaration the mirror strips - must NOT be reported
	//    when the staleness half is off, and MUST be reported when it is on.
	//    Same input, opposite answers, which is the whole content of the
	//    checkStale parameter.
	tagged := map[string]string{
		"EnvCompatMode":     "AXONFLOW_IDENTITY_COMPAT_MODE",
		"EnvSomeoneElse":    "AXONFLOW_SOMETHING_ELSE",
		"EnvEnterpriseOnly": "AXONFLOW_ENTERPRISE_ONLY",
	}
	strippedExempt := map[string]string{
		"EnvSomeoneElse":    "owned by another component",
		"EnvEnterpriseOnly": "declared in an enterprise-tagged file the community mirror strips",
	}
	// The community shape: the enterprise constant is NOT in the parse.
	community := map[string]string{"EnvCompatMode": tagged["EnvCompatMode"], "EnvSomeoneElse": tagged["EnvSomeoneElse"]}
	reader := "func EnvCompatConfig() { os.Getenv(EnvCompatMode) }"
	if got := missingEnvReads(community, reader, strippedExempt, false); len(got) != 0 {
		t.Errorf("with the staleness half OFF, an exemption for a constant this build cannot see was reported "+
			"as a problem (%v). That is the community mirror, and calling a considered decision about an "+
			"enterprise-only variable 'stale' is a false statement about the exemption.", got)
	}
	if got := missingEnvReads(community, reader, strippedExempt, true); len(got) != 1 || !strings.Contains(got[0], "EnvEnterpriseOnly") {
		t.Errorf("with the staleness half ON, an exemption naming a constant absent from the parse was not "+
			"reported (%v). Under the enterprise tag every constant is visible, so absent means absent from "+
			"EVERY build and the exemption really is dead.", got)
	}
}

// compatEnvReaderForms are the spellings a direct read of a compat variable can
// take. THE QUALIFIED FORM IS THE CASE THAT MATTERS.
//
// A first version matched only `os.Getenv(EnvCompatPaths` - the UNQUALIFIED
// form, which only code inside this package can write. Every other package must
// qualify it (`os.Getenv(sharedidentity.EnvCompatPaths)`), so the census could
// not see a second reader in the orchestrator or the agent: precisely the files
// it exists to guard. Caught by planting the mutant, not by reading the code -
// which is why TestCompatEnvReaderCensusCatchesAPlantedSecondReader now plants
// one on every run.
func compatEnvReaderForms(constName, value string) []*regexp.Regexp {
	return []*regexp.Regexp{
		regexp.MustCompile(`os\.Getenv\(\s*(?:[A-Za-z_][A-Za-z0-9_]*\.)?` + regexp.QuoteMeta(constName) + `\s*\)`),
		regexp.MustCompile(`os\.Getenv\(\s*"` + regexp.QuoteMeta(value) + `"\s*\)`),
	}
}

// scanCompatEnvReaders walks root and reports every non-test Go file that reads
// a guarded compat variable directly, excluding the one legitimate reader.
// Returns the files scanned, the reads found, and the offending paths.
func scanCompatEnvReaders(root string, guarded map[string]string, reader string) (scanned, found int, offenders []string) {
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, werr error) error {
		if werr != nil {
			return nil // an unreadable subtree is not this census's business
		}
		if d.IsDir() {
			if d.Name() == "vendor" || d.Name() == "node_modules" || d.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		name := d.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			return nil
		}
		body, rerr := os.ReadFile(filepath.Clean(path))
		if rerr != nil {
			return nil
		}
		scanned++
		text := string(body)
		for value, constName := range guarded {
			for _, re := range compatEnvReaderForms(constName, value) {
				if !re.MatchString(text) {
					continue
				}
				found++
				if name != reader {
					rel, _ := filepath.Rel(root, path)
					offenders = append(offenders, rel+" reads "+value)
				}
			}
		}
		return nil
	})
	sort.Strings(offenders)
	return scanned, found, offenders
}

// guardedCompatEnv is the set that must have exactly ONE reader, keyed by
// VALUE so a hard-coded string is caught as well as a use of the constant.
func guardedCompatEnv() map[string]string {
	return map[string]string{
		EnvCompatMode:     "EnvCompatMode",
		EnvEnforceReasons: "EnvEnforceReasons",
		EnvCompatPaths:    "EnvCompatPaths",
	}
}

// compatEnvReaderFile is the one legitimate reader.
const compatEnvReaderFile = "compat_bootstrap.go"

// TestOnlyOneReaderOfTheCompatEnvironmentExistsUnderPlatform is the fence
// around the fix, and it scans the WHOLE tree rather than the two binaries
// that happened to be wrong.
//
// The hole was not that the orchestrator forgot a line. It was that TWO call
// sites each maintained their own copy of the variable list, so adding a
// variable required remembering both - and the remembering failed silently:
// the lever was declared in compose for both services and documented as
// applying to both, while reaching one. Nothing failed; the orchestrator
// simply kept evaluating every path.
//
// Adding the missing line to the second site would have fixed this instance
// and left the mechanism. One reader removes the mechanism, and this test is
// what keeps it at one: a second `os.Getenv` of any compat variable anywhere
// under platform/ fails here, wherever a future author puts it.
func TestOnlyOneReaderOfTheCompatEnvironmentExistsUnderPlatform(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatalf("resolve platform root: %v", err)
	}
	scanned, found, offenders := scanCompatEnvReaders(root, guardedCompatEnv(), compatEnvReaderFile)
	for _, o := range offenders {
		t.Errorf("%s directly.\n\n"+
			"There must be exactly ONE reader of the compat environment, in %s, because two hand-maintained copies "+
			"of the variable list is what let AXONFLOW_IDENTITY_COMPAT_PATHS reach the agent and not the "+
			"orchestrator - declared in compose for both, documented for both, read by one, and nothing failed. "+
			"Bootstrap through identity.EnvCompatConfig.", o, compatEnvReaderFile)
	}

	// ANTI-VACUITY, both directions. A walk that read nothing passes, and so
	// does one that found no reader at all - which would mean the helper had
	// been deleted and every binary was reading the environment itself again.
	if scanned == 0 {
		t.Fatal("the census scanned zero Go files under platform/; the walk, not the code, is broken")
	}
	if found == 0 {
		t.Fatalf("no reader of the compat environment was found in %d files. EnvCompatConfig is the single "+
			"reader; if it is gone, every binary is reading the variables itself and this census is guarding "+
			"nothing.", scanned)
	}
}

// TestCompatEnvReaderCensusCatchesAPlantedSecondReader is that census's failing
// input, planted into a temporary tree on every run.
//
// It exists for the same reason as the omission test above - a disk-reading
// census cannot be reached by an overlay mutant - and for one more: this census
// has ALREADY been blind once, in exactly the way a reviewer cannot see by
// reading it. The first version's regex matched only the unqualified
// `os.Getenv(EnvCompatPaths)`, which no package outside this one can write, so
// a second reader in the agent or the orchestrator - the two files the fence
// exists for - matched nothing and the census passed. The planted second reader
// below is written the way another package must write it, QUALIFIED, so that
// blindness cannot return silently.
func TestCompatEnvReaderCensusCatchesAPlantedSecondReader(t *testing.T) {
	root := t.TempDir()
	mkdir := func(p string) string {
		full := filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatalf("plant %s: %v", p, err)
		}
		return full
	}
	write := func(p, body string) {
		if err := os.WriteFile(mkdir(p), []byte(body), 0o600); err != nil {
			t.Fatalf("plant %s: %v", p, err)
		}
	}

	// The legitimate reader, which must NOT be reported.
	write("shared/identity/"+compatEnvReaderFile,
		"package identity\nfunc EnvCompatConfig() { os.Getenv(EnvCompatMode); os.Getenv(EnvCompatPaths); os.Getenv(EnvEnforceReasons) }\n")
	// A second reader in another package, written the ONLY way another package
	// can write it: qualified.
	write("orchestrator/identity_compat.go",
		"package orchestrator\nfunc boot() { _ = os.Getenv(sharedidentity.EnvCompatPaths) }\n")
	// A hard-coded string, the other spelling a future author reaches for.
	write("agent/identity_boot.go",
		"package agent\nfunc boot() { _ = os.Getenv(\"AXONFLOW_IDENTITY_COMPAT_MODE\") }\n")
	// A TEST file with the same read, which must be IGNORED - test files
	// legitimately set and read these, and reporting them would make the fence
	// unusable and get it deleted.
	write("orchestrator/identity_compat_test.go",
		"package orchestrator\nfunc TestX() { _ = os.Getenv(sharedidentity.EnvCompatMode) }\n")

	scanned, found, offenders := scanCompatEnvReaders(root, guardedCompatEnv(), compatEnvReaderFile)
	if scanned != 3 {
		t.Fatalf("the walk scanned %d non-test files, want 3; the plant, not the census, is what this measured", scanned)
	}
	// FIVE READS, NOT THREE FILES. `found` counts READS: the legitimate reader
	// holds three (mode, paths, reasons) and each offender one. Getting this
	// wrong in the first draft is the reason it is pinned - the number is the
	// only thing standing between this control and a census that silently
	// stopped matching one of the two spellings.
	if found != 5 {
		t.Errorf("the census found %d reads across the planted tree, want 5: three in the legitimate reader and "+
			"one in each of the two offenders", found)
	}
	joined := strings.Join(offenders, " | ")
	if !strings.Contains(joined, filepath.Join("orchestrator", "identity_compat.go")) {
		t.Errorf("the QUALIFIED second reader was not reported (offenders: %v). This is the exact blindness the "+
			"first version of this census had: every package but identity must qualify the constant, so an "+
			"unqualified-only pattern cannot see the files the fence exists to guard.", offenders)
	}
	if !strings.Contains(joined, filepath.Join("agent", "identity_boot.go")) {
		t.Errorf("the HARD-CODED second reader was not reported (offenders: %v); a future author who types the "+
			"variable name rather than the constant would slip past the fence", offenders)
	}
	if strings.Contains(joined, compatEnvReaderFile) {
		t.Errorf("the legitimate reader was reported as an offender (%v); a census that flags the one permitted "+
			"site fails on a correct tree and gets deleted", offenders)
	}
	if strings.Contains(joined, "_test.go") {
		t.Errorf("a _test.go file was reported (%v); tests set and read these variables legitimately", offenders)
	}
}
