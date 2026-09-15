// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package authoringedition

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"axonflow/platform/testutil/manifests"
)

// The deployment guard for #3956: a process that resolves an authoring edition
// must actually be GIVEN the input it resolves it from.
//
// # WHY A GUARD AND NOT A COMMENT
//
// The runtime half of this fix - Resolve failing closed on the duty rule when
// it cannot establish a tier - is correct and is not sufficient. It makes the
// consequence SAFE; it does not make it right. A portal that never receives
// AXONFLOW_LICENSE_KEY still loses the Enterprise construct set on a
// deployment that paid for it, and nothing at runtime can give that back.
// Only the deployment manifest can, so only a check over the manifests can say
// it is there.
//
// # THE POPULATION IS DERIVED, NOT LISTED
//
// #3877 shipped a guard whose "a new template cannot ship without them" was
// asserted against a hardcoded triple of paths, and the sentence was in three
// places including the issue's acceptance box. So neither half of this file
// hardcodes what it checks:
//
//   - the SURFACES come from the source tree - every Go file that imports this
//     package - folded onto the binary that contains them;
//   - the MANIFESTS come from a walk of the repository, not from a list.
//
// Both halves assert their own population is non-empty and contains what this
// tree is known to contain, so an extraction that silently stops matching
// fails here rather than reporting a clean sweep over nothing.
//
// # WHAT THIS GUARD IS DELIBERATELY NOT ABOUT
//
// AXONFLOW_TYPED_AUTHORING_CATALOG is plumbed by the same change and is NOT
// guarded here. A process missing it answers 503 naming the variable, on every
// endpoint, immediately: the failure announces itself and cannot be mistaken
// for correct operation. A process missing the LICENCE key answered every
// request successfully under the wrong boundary, which is the property that
// makes it a thing a guard has to see for us.

// envLicenseKeyInManifest is the variable as a manifest writes it. It is
// derived from the constant this package's own resolution depends on, so the
// guard cannot come to check a different spelling from the one that is read.
var envLicenseKeyInManifest = EnvLicenseKey

// repoRoot walks up from this package to the directory holding the repository
// marker, so the guard does not encode its own depth.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := filepath.Abs(".")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 12; i++ {
		if _, err := os.Stat(filepath.Join(dir, "docker-compose.yml")); err == nil {
			if _, err := os.Stat(filepath.Join(dir, "CHANGELOG.md")); err == nil {
				return dir
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatal("the repository root was not found above this package; the guard cannot walk a tree it cannot locate")
	return ""
}

// authoringSurfaceRoots returns the binary directories whose source resolves an
// authoring edition: for every Go file importing this package, the nearest
// ancestor directory that holds a Dockerfile.
//
// THE FILE-TO-BINARY FOLD IS "NEAREST DOCKERFILE" and it is a real claim about
// this tree rather than a convention: a deployment manifest names a Dockerfile,
// so the directory that holds one is exactly the unit a manifest can talk
// about. A resolver call placed somewhere with no ancestor Dockerfile is
// reported as UNCLASSIFIED and fails the guard - it is not silently dropped,
// and the failure does not prescribe a remedy, because the right one depends
// on what that new caller turns out to be.
func authoringSurfaceRoots(t *testing.T, root string) []string {
	t.Helper()
	const selfImport = "axonflow/platform/shared/authoringedition"
	fset := token.NewFileSet()
	seen := map[string]bool{}
	var unclassified []string
	parsed := 0

	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", "vendor", ".next", "testdata":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		f, perr := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if perr != nil {
			return nil
		}
		parsed++
		for _, imp := range f.Imports {
			p, uerr := strconv.Unquote(imp.Path.Value)
			if uerr != nil || p != selfImport {
				continue
			}
			// This package's own files are the resolver, not a surface.
			if filepath.Dir(path) == filepath.Join(root, "platform", "shared", "authoringedition") {
				return nil
			}
			if rel, _ := filepath.Rel(root, path); declaredNonDeployedAuthoringUsers[filepath.ToSlash(rel)] != "" {
				// CLASSIFIED, and not as a surface. See the map.
				return nil
			}
			if bin := nearestDockerfileDir(root, filepath.Dir(path)); bin != "" {
				seen[bin] = true
			} else {
				rel, _ := filepath.Rel(root, path)
				unclassified = append(unclassified, rel)
			}
			return nil
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking the tree: %v", err)
	}

	// NON-VACUITY ON THE WALK ITSELF. A parser that matched nothing and a tree
	// with nothing to match are the same empty answer, and the empty answer
	// would let every manifest assertion below pass over an empty population.
	if parsed < 500 {
		t.Fatalf("the walk parsed only %d Go files; the extraction is broken, not the tree", parsed)
	}
	if len(unclassified) > 0 {
		sort.Strings(unclassified)
		t.Fatalf("these files resolve an authoring edition and sit under no Dockerfile, so this guard cannot say "+
			"which deployed process they run in: %v\nClassify them: either they belong to a binary whose "+
			"Dockerfile directory contains them, or this guard's file-to-binary fold no longer describes the tree "+
			"and needs the decision recorded here.", unclassified)
	}

	out := make([]string, 0, len(seen))
	for b := range seen {
		out = append(out, b)
	}
	sort.Strings(out)
	return out
}

func nearestDockerfileDir(root, dir string) string {
	for {
		if _, err := os.Stat(filepath.Join(dir, "Dockerfile")); err == nil {
			rel, err := filepath.Rel(root, dir)
			if err != nil {
				return ""
			}
			return filepath.ToSlash(rel)
		}
		parent := filepath.Dir(dir)
		if parent == dir || len(parent) < len(root) {
			return ""
		}
		dir = parent
	}
}

// declaredAuthoringSurfaces is the roster of binaries entitled to resolve an
// authoring edition, and it is the ONE hand-written list in this file.
//
// It is a roster and not an expectation, because THIS FILE RUNS ON TWO TREES.
// It reaches the community mirror, where `ee/` does not exist at all - no
// customer-portal source, no Dockerfile, and no CloudFormation template of any
// kind. An expectation naming both surfaces would be true here and red there,
// on a public repository, for a guard that is working correctly.
//
// So the expectation is DERIVED from the roster by asking the tree which of
// them it actually contains, and the roster is what makes a NEW surface fail:
// a binary that resolves an edition and is not named here has not been checked
// against its deployment manifests by anybody.
var declaredAuthoringSurfaces = []string{
	// The agent joined this roster with #3592's activation chokepoint. Its
	// enforcing seam resolves the deployment's edition to decide whether an
	// ALREADY ACTIVE document may be refused for spending a construct outside
	// it, which is a different use from the two surfaces below - they resolve
	// the boundary an author WRITES within - but it is the same read, and the
	// same consequence follows from an empty key: a process that cannot
	// establish its tier answers "unestablished", and the seam then declines to
	// enforce the boundary at all. That direction is deliberately fail-soft
	// (#4094), so the cost of a missing key here is a boundary that silently
	// stops being enforced rather than an author silently narrowed - which is
	// exactly why it belongs under this guard rather than beside it.
	"ee/platform/customer-portal",
	"platform/agent",
	"platform/orchestrator",
}

// declaredNonDeployedAuthoringUsers are files that import this package and are
// NOT a deployed process, with the reason each one is not.
//
// # WHY AN EXEMPTION EXISTS AT ALL, AND WHY IT IS A MAP RATHER THAN A COUNT
//
// The guard keys on the IMPORT, deliberately: it is the one signal that cannot
// be evaded by spelling a call differently.
//
// IT IS EMPTY, AND THAT IS THE POINT OF THE #3895 MOVE. Its one entry was the
// operator-run legacy importer, which imported this package only for the
// deployment's authoring VOCABULARY and never for a licence read. The
// vocabulary now lives in platform/shared/authoringvocabulary - moved when the
// agent's decide-plane enforcing seam needed it and would otherwise have been
// counted here as a binary owing AXONFLOW_LICENSE_KEY - so the importer no
// longer imports this package at all and an entry naming it would be a claim
// about the tree that is false.
//
// The mechanism stays because the case it covers stays possible: a program that
// is not a deployed process and genuinely needs the licence read. It is a map
// from path to REASON, so an entry cannot be added without saying why, and it
// pins the SET: a CLI that starts importing this package is unclassified and
// fails, exactly as a new server would. What it must never hold is a file that
// DOES run as a deployed process, because that is the #3956 defect this whole
// guard exists to prevent - so each reason has to say what supplies that file's
// edition instead of a licence read in a container.
var declaredNonDeployedAuthoringUsers = map[string]string{}

// presentAuthoringSurfaces is the roster narrowed to what this tree holds.
func presentAuthoringSurfaces(root string) []string {
	var out []string
	for _, r := range declaredAuthoringSurfaces {
		if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(r), "Dockerfile")); err == nil {
			out = append(out, r)
		}
	}
	sort.Strings(out)
	return out
}

// TestTheAuthoringSurfacesAreTheOnesThisTreeDeclares is the anti-vacuity
// control for every assertion below.
//
// A derived population that quietly became empty - an import path renamed, the
// walk skipping a directory - would otherwise make the manifest guards sweep
// nothing and report success, which is the exact shape this whole issue is
// about. So the extracted set is compared with the roster narrowed to this
// tree, in BOTH directions, and the floor below refuses an empty answer on any
// tree: platform/orchestrator survives the mirror strip, so there is never a
// legitimate reason for this to find none.
func TestTheAuthoringSurfacesAreTheOnesThisTreeDeclares(t *testing.T) {
	root := repoRoot(t)
	got := authoringSurfaceRoots(t, root)
	want := presentAuthoringSurfaces(root)
	if len(want) == 0 {
		t.Fatal("no declared authoring surface has a Dockerfile in this tree; the roster no longer describes it")
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("the set of binaries that resolve an authoring edition changed.\n got: %v\nwant: %v (the roster, "+
			"narrowed to the surfaces whose Dockerfile is present in this tree)\n"+
			"A NEW one is not a problem to suppress here: give its deployment manifests %s, then add it to "+
			"declaredAuthoringSurfaces. A MISSING one means either a surface stopped resolving its edition through "+
			"this package - which is the thing the census below forbids - or this extraction stopped working.",
			got, want, envLicenseKeyInManifest)
	}
}

// TestEveryComposeServiceRunningAnAuthoringSurfaceReceivesTheLicenceKey is the
// half that would have caught #3956 before it merged.
//
// # THE MERGE RULE IS MODELLED, NOT ASSUMED AWAY
//
// Compose overlays merge, so "this file does not name the variable" is not a
// defect on its own: docker-compose.enterprise.yml re-declares the agent and
// the orchestrator and lets docker-compose.yml supply their environment. The
// rule applied here is the one that is actually true of every stack this
// repository documents - a service is satisfied when its OWN block names the
// variable, or when the base docker-compose.yml declares a service of the same
// name that does.
//
// That is exactly the distinction the defect turned on. The portal is declared
// in docker-compose.enterprise.yml and in NO base file, so nothing could have
// supplied it and the overlay was the only place it could come from.
func TestEveryComposeServiceRunningAnAuthoringSurfaceReceivesTheLicenceKey(t *testing.T) {
	root := repoRoot(t)
	roots := authoringSurfaceRoots(t, root)
	base := composeServicesDeclaring(t, filepath.Join(root, "docker-compose.yml"), envLicenseKeyInManifest)

	checked := 0
	var missing []string
	for _, path := range manifests.Files(t, root, ".yml", ".yaml") {
		for _, svc := range composeServicesBuiltFrom(t, path, roots) {
			checked++
			if svc.namesVariable || base[svc.name] {
				continue
			}
			rel, _ := filepath.Rel(root, path)
			missing = append(missing, fmt.Sprintf("%s: service %q (built from %s/Dockerfile)", rel, svc.name, svc.root))
		}
	}
	if checked == 0 {
		t.Fatal("no compose service was found building an authoring surface; the extraction matched nothing, " +
			"so a pass here would mean nothing")
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		t.Fatalf("these compose services run a process that resolves an authoring edition and are never given %s:\n  %s\n"+
			"Compose passes NO host environment to a service that does not name it, so such a process reads an empty "+
			"key. It then runs on the Community CONSTRUCT set on a deployment that may have paid for more - which no "+
			"runtime fallback can give back - and reports its licensed tier as unestablished.",
			envLicenseKeyInManifest, strings.Join(missing, "\n  "))
	}
	t.Logf("checked %d compose service declarations across the tree", checked)
}

// TestEveryTaskDefinitionRunningAnAuthoringSurfaceReceivesTheLicenceKey is the
// same rule for CloudFormation, where there is no overlay merge to model: a
// container definition carries its whole environment or it does not have one.
//
// The container NAME is matched against the last path element of the binary
// root - `customer-portal` against ee/platform/customer-portal - and that fold
// is asserted to hit something rather than assumed, so a template that renames
// its containers fails here instead of sweeping zero rows.
func TestEveryTaskDefinitionRunningAnAuthoringSurfaceReceivesTheLicenceKey(t *testing.T) {
	root := repoRoot(t)
	names := map[string]string{}
	for _, r := range authoringSurfaceRoots(t, root) {
		names[path4Base(r)] = r
	}

	// TWO MEASUREMENTS, NOT ONE, because "this tree has no ECS template" and
	// "the matcher found no container definition" are different facts that
	// produce the same zero. The first is true of the community mirror, which
	// carries no CloudFormation at all; the second is a broken extraction, and
	// treating it as the first is how a guard reports a clean sweep over
	// nothing. So templates are counted before containers are.
	templates := 0
	checked := 0
	var missing []string
	for _, path := range manifests.Files(t, root, ".yaml", ".yml") {
		body, err := os.ReadFile(path)
		if err != nil || !strings.Contains(string(body), "AWS::ECS::TaskDefinition") {
			continue
		}
		templates++
		for _, c := range containerDefinitions(string(body)) {
			bin, ok := names[c.name]
			if !ok {
				continue
			}
			checked++
			if strings.Contains(c.body, "Name: "+envLicenseKeyInManifest) {
				continue
			}
			rel, _ := filepath.Rel(root, path)
			missing = append(missing, fmt.Sprintf("%s: container %q (%s)", rel, c.name, bin))
		}
	}
	if templates == 0 {
		// The stripped tree. It is ASSERTED to be that tree rather than
		// assumed: a full checkout that had lost its templates would reach
		// here too, and would be a broken repository rather than a mirror.
		if len(presentAuthoringSurfaces(root)) == len(declaredAuthoringSurfaces) {
			t.Fatal("this tree declares every authoring surface and yet holds no CloudFormation template with an " +
				"ECS task definition; the templates have gone missing, which is not something to pass over")
		}
		t.Log("no CloudFormation template in this tree declares an ECS task definition, and this tree is missing " +
			"authoring surfaces too, so it is the stripped community copy. There is nothing here for this half " +
			"to check; the compose half above still ran.")
		return
	}
	if checked == 0 {
		t.Fatalf("%d CloudFormation templates declare ECS task definitions and none of their container definitions "+
			"matched an authoring surface (%v); either the templates renamed their containers or this extraction "+
			"is broken, and in both cases a pass here would mean nothing", templates, names)
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		t.Fatalf("these container definitions run a process that resolves an authoring edition and are never given %s:\n  %s\n"+
			"The same LicenseKeySecret and the same TaskExecutionRole already serve the agent and the orchestrator, "+
			"so this is a missing entry rather than a missing grant.",
			envLicenseKeyInManifest, strings.Join(missing, "\n  "))
	}
	t.Logf("checked %d CloudFormation container definitions", checked)
}

func path4Base(p string) string {
	i := strings.LastIndex(p, "/")
	if i < 0 {
		return p
	}
	return p[i+1:]
}

type composeService struct {
	name          string
	root          string
	namesVariable bool
}

var (
	composeFileHeader  = regexp.MustCompile(`(?m)^services:\s*$`)
	composeServiceLine = regexp.MustCompile(`^  ([A-Za-z0-9][A-Za-z0-9._-]*):\s*$`)
	// (?m) is load bearing: this pattern is applied to a joined service BLOCK,
	// not to a line, and without it `^` anchors to the start of that whole
	// block and the extraction matches nothing at all - which reads as "no
	// service builds an authoring surface", i.e. as a clean sweep. The
	// non-vacuity assertion in the caller is what caught it.
	composeDockerfile = regexp.MustCompile(`(?m)^\s*dockerfile:\s*(\S+)\s*$`)
)

// composeServicesBuiltFrom returns the services in one compose file that BUILD
// one of the given binary roots, and whether each names the licence key in its
// own block.
//
// Only services with a `build:` stanza are in the population. An overlay that
// merely renames a container or remaps a port declares no build and supplies no
// image, so it is not a place the environment can be said to be missing from -
// and treating it as one would put every runtime-e2e harness in the population
// for a variable its base file already provides.
func composeServicesBuiltFrom(t *testing.T, path string, roots []string) []composeService {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	// A COMPOSE FILE IS IDENTIFIED BY ITS SHAPE, NOT BY ITS NAME. Any YAML in
	// the tree can carry a `dockerfile:` line - .goreleaser.yml does, under
	// `dockers.extra_files`, and the first version of this guard reported it
	// as a service missing the licence key. A top-level `services:` mapping is
	// what makes a file a compose file, and it is the file's own declaration
	// rather than a name this guard would have to keep a list of.
	if !composeFileHeader.Match(body) {
		return nil
	}
	inRoot := map[string]bool{}
	for _, r := range roots {
		inRoot[r+"/Dockerfile"] = true
	}
	var out []composeService
	cur := ""
	block := []string{}
	flush := func() {
		if cur == "" {
			return
		}
		text := strings.Join(block, "\n")
		for _, m := range composeDockerfile.FindAllStringSubmatch(text, -1) {
			if inRoot[filepath.ToSlash(m[1])] {
				out = append(out, composeService{
					name:          cur,
					root:          strings.TrimSuffix(filepath.ToSlash(m[1]), "/Dockerfile"),
					namesVariable: strings.Contains(text, envLicenseKeyInManifest+":"),
				})
				break
			}
		}
	}
	for _, ln := range strings.Split(string(body), "\n") {
		if m := composeServiceLine.FindStringSubmatch(ln); m != nil {
			flush()
			cur, block = m[1], nil
			continue
		}
		if cur != "" {
			block = append(block, ln)
		}
	}
	flush()
	return out
}

// composeServicesDeclaring returns the services in one compose file whose block
// names the given variable. It is how the base file's contribution to an
// overlay is read.
func composeServicesDeclaring(t *testing.T, path, variable string) map[string]bool {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("the base compose file must be readable: %v", err)
	}
	out := map[string]bool{}
	cur := ""
	for _, ln := range strings.Split(string(body), "\n") {
		if m := composeServiceLine.FindStringSubmatch(ln); m != nil {
			cur = m[1]
			continue
		}
		if cur != "" && strings.Contains(ln, variable+":") && !strings.HasPrefix(strings.TrimSpace(ln), "#") {
			out[cur] = true
		}
	}
	return out
}

type containerDef struct {
	name string
	body string
}

var cfnContainerName = regexp.MustCompile(`(?m)^(\s*)- Name: ([a-z0-9][a-z0-9-]*)\s*$`)

// containerDefinitions splits a CloudFormation template into container
// definitions by their `- Name:` entries at the ContainerDefinitions
// indentation, taking each one's body up to the next entry at the same indent.
func containerDefinitions(body string) []containerDef {
	locs := cfnContainerName.FindAllStringSubmatchIndex(body, -1)
	var out []containerDef
	for i, loc := range locs {
		indent := body[loc[2]:loc[3]]
		// ContainerDefinitions entries sit at eight spaces in both templates;
		// anything deeper is an Environment or Secrets entry, which is what
		// the guard reads INSIDE a definition rather than as one.
		if len(indent) != 8 {
			continue
		}
		end := len(body)
		for _, next := range locs[i+1:] {
			if len(body[next[2]:next[3]]) == 8 {
				end = next[0]
				break
			}
		}
		out = append(out, containerDef{name: body[loc[4]:loc[5]], body: body[loc[0]:end]})
	}
	return out
}

// TestNoSurfaceResolvesItsEditionOutsideThisPackage is the structural half.
//
// The manifest guard above can only check the surfaces it can SEE, and it sees
// them by their import of this package. A future surface that folded a licence
// read onto an edition itself - which is what both surfaces did until #3956,
// in two byte-identical copies - would be invisible to it, and would carry the
// defect this whole change is about.
//
// So authoring.EditionFor, the fold itself, must be called only from this
// package and from the authoring package's own tests. It is a syntactic census
// over the parsed tree rather than a grep: an aliased or dot import spells the
// call differently and a grep for one spelling is blind to every other.
func TestNoSurfaceResolvesItsEditionOutsideThisPackage(t *testing.T) {
	root := repoRoot(t)
	const authoringImport = "axonflow/platform/decision/authoring"
	fset := token.NewFileSet()
	var offenders []string
	found := 0

	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", "vendor", ".next", "testdata":
				return filepath.SkipDir
			}
			// The authoring package declares EditionFor and is entitled to use
			// it; every other directory is a caller.
			if filepath.ToSlash(path) == filepath.ToSlash(filepath.Join(root, "platform/decision/authoring")) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		// TEST FILES ARE OUT OF THE CENSUS'S SUBJECT, and the exclusion is
		// narrow rather than convenient: this census is about which DEPLOYED
		// PROCESS resolves an edition, and a _test.go file is in no shipped
		// binary, so a call there cannot be a surface carrying the defect.
		// Production code cannot reach one either, so the exclusion opens no
		// path back in. It is stated here rather than left implicit because an
		// exclusion nobody wrote down reads as coverage.
		if strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			return nil
		}
		// Resolve the local name of the authoring import in THIS file, so an
		// alias is followed rather than missed.
		local := ""
		for _, imp := range f.Imports {
			p, uerr := strconv.Unquote(imp.Path.Value)
			if uerr != nil || p != authoringImport {
				continue
			}
			if imp.Name != nil {
				local = imp.Name.Name
			} else {
				local = "authoring"
			}
		}
		if local == "" {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		ast.Inspect(f, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "EditionFor" {
				return true
			}
			// A dot import makes the package name absent; that spelling would
			// be an *ast.Ident rather than a selector and is refused by the
			// import check below instead.
			id, ok := sel.X.(*ast.Ident)
			if !ok || id.Name != local {
				return true
			}
			found++
			if strings.HasPrefix(rel, "platform/shared/authoringedition/") {
				return true
			}
			offenders = append(offenders, fmt.Sprintf("%s:%d", rel, fset.Position(sel.Pos()).Line))
			return true
		})
		for _, imp := range f.Imports {
			p, _ := strconv.Unquote(imp.Path.Value)
			if p == authoringImport && imp.Name != nil && imp.Name.Name == "." {
				offenders = append(offenders, rel+": dot-imports the authoring package, which makes every call to it "+
					"unqualified and invisible to this census")
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking the tree: %v", err)
	}

	// POSITIVE CONTROL. This package calls EditionFor exactly once, in
	// non-test code, so a census that found nothing has stopped matching
	// rather than found a clean tree - the failure mode that made three of
	// this tree's other censuses report a confident wrong answer.
	if found == 0 {
		t.Fatal("the census found no call to authoring.EditionFor anywhere, including this package's own; " +
			"the matcher is broken, so its silence is not evidence")
	}
	if len(offenders) > 0 {
		sort.Strings(offenders)
		t.Fatalf("authoring.EditionFor is called outside %s:\n  %s\n"+
			"That fold turns an absent, forged or expired licence key into the Community edition, and it cannot "+
			"tell an absent key apart from a Community deployment. A surface that performs it itself carries #3956 "+
			"by construction. Call authoringedition.Resolve instead; it separates the two and returns the profile.",
			"platform/shared/authoringedition", strings.Join(offenders, "\n  "))
	}
}
