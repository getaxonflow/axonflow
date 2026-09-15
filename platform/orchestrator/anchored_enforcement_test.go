// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"os"
	"os/exec"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"

	"axonflow/platform/agent"
	"axonflow/platform/decision/authoringcatalog"
	"axonflow/platform/decision/legacycompile"
	"axonflow/platform/shared/anchoredenforcer"
	sharedidentity "axonflow/platform/shared/identity"
)

// overrideReaderFunc is a detectionOverrideReader from a function.
type overrideReaderFunc func(ctx context.Context, orgID string) (map[string]agent.DetectionAction, error)

func (f overrideReaderFunc) ReadOrgOverrides(ctx context.Context, orgID string) (map[string]agent.DetectionAction, error) {
	return f(ctx, orgID)
}

// isolateOrchestratorEnforcer restores the process enforcer, the override cache
// and the install's constructors after a test.
func isolateOrchestratorEnforcer(t *testing.T) {
	t.Helper()
	prevInstance := orchestratorEnforcerInstance.Load()
	prevCache := getDetectionOverrideCache()
	prevBootstrap, prevNew := bootstrapOrchestratorAdmission, newOrchestratorEnforcer
	prevScopes := append([]legacycompile.EnforcementScope(nil), orchestratorEnforcingScopes...)
	t.Cleanup(func() {
		orchestratorEnforcerInstance.Store(prevInstance)
		setDetectionOverrideCacheForTest(prevCache)
		bootstrapOrchestratorAdmission, newOrchestratorEnforcer = prevBootstrap, prevNew
		orchestratorEnforcingScopes = prevScopes
	})
}

func testOverrideCache(read func(ctx context.Context, orgID string) (map[string]agent.DetectionAction, error)) *detectionOverrideCache {
	return newDetectionOverrideCache(overrideReaderFunc(read), minDetectionOverrideTTL, minDetectionOverrideMaxEntries)
}

func noOverrides(context.Context, string) (map[string]agent.DetectionAction, error) {
	return map[string]agent.DetectionAction{}, nil
}

// TestTheOrchestratorEnforcerIsNotInstalledWithoutItsDependencies: each missing
// dependency is refused by name, because wireOrchestratorEnforcer turns the
// refusal into a refusal to boot and the operator reads the message. Nothing
// is installed on any refusal, and the control proves the refusals are about
// the missing piece rather than the call.
func TestTheOrchestratorEnforcerIsNotInstalledWithoutItsDependencies(t *testing.T) {
	isolateOrchestratorEnforcer(t)
	db, _, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	for _, c := range []struct {
		name  string
		db    *sql.DB
		setup func()
		want  string
	}{
		{"no database", nil, func() { setDetectionOverrideCacheForTest(testOverrideCache(noOverrides)) }, "this orchestrator has no database (PRD v11 §1.1)"},
		{"no override store", db, func() { setDetectionOverrideCacheForTest(nil) }, "override store is not wired"},
		{"an identity plane that cannot be assembled", db, func() {
			setDetectionOverrideCacheForTest(testOverrideCache(noOverrides))
			bootstrapOrchestratorAdmission = func(sharedidentity.AdmissionBootstrapConfig) (*sharedidentity.AdmissionBootstrap, error) {
				return nil, errors.New("realm registry refused")
			}
		}, "identity plane could not be assembled: realm registry refused"},
		{"an identity plane with no admitter", db, func() {
			setDetectionOverrideCacheForTest(testOverrideCache(noOverrides))
			bootstrapOrchestratorAdmission = func(sharedidentity.AdmissionBootstrapConfig) (*sharedidentity.AdmissionBootstrap, error) {
				return &sharedidentity.AdmissionBootstrap{}, nil
			}
		}, "identity plane is not bootstrapped"},
		{"an enforcer that cannot be built", db, func() {
			setDetectionOverrideCacheForTest(testOverrideCache(noOverrides))
			newOrchestratorEnforcer = failingEnforcerBuild
		}, "anchored enforcer could not be built: planted build failure"},
	} {
		t.Run(c.name, func(t *testing.T) {
			orchestratorEnforcerInstance.Store(nil)
			bootstrapOrchestratorAdmission, newOrchestratorEnforcer = sharedidentity.BootstrapAdmission, anchoredenforcer.New
			c.setup()
			err := installOrchestratorEnforcer(c.db)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("got %v; want a refusal saying %q", err, c.want)
			}
			if orchestratorEnforcer() != nil {
				t.Fatalf("an enforcer was installed although the install refused: %v", err)
			}
		})
	}

	// CONTROL: with a database, an override store and the real constructors the
	// install succeeds and installs the shared enforcer.
	orchestratorEnforcerInstance.Store(nil)
	bootstrapOrchestratorAdmission, newOrchestratorEnforcer = sharedidentity.BootstrapAdmission, anchoredenforcer.New
	setDetectionOverrideCacheForTest(testOverrideCache(noOverrides))
	if err := installOrchestratorEnforcer(db); err != nil {
		t.Fatalf("CONTROL: with every dependency present the install returned %v, so the refusals above prove nothing", err)
	}
	if _, ok := orchestratorEnforcer().(*anchoredenforcer.Enforcer); !ok {
		t.Fatalf("CONTROL: the installed enforcement is %T, want the shared *anchoredenforcer.Enforcer", orchestratorEnforcer())
	}
}

func failingEnforcerBuild(anchoredenforcer.ActiveDocumentSource, func() (*authoringcatalog.Snapshot, error),
	*sharedidentity.SubjectAdmitter, func() int64, anchoredenforcer.Options) (*anchoredenforcer.Enforcer, error) {
	return nil, errors.New("planted build failure")
}

// The boot refusal runs in a child process, because log.Fatalf exits: the
// child is this test binary, re-run on this test alone with the case named in
// its environment.
const orchestratorBootRefusalCaseEnv = "AXONFLOW_TEST_ORCHESTRATOR_BOOT_REFUSAL_CASE"

// TestTheOrchestratorRefusesToBootWithoutADatabaseOrABuildableEnforcer: a
// nil usageDB and a failing build each end the process with a non-zero exit
// and the refusal on its log, and neither prints the wired line.
func TestTheOrchestratorRefusesToBootWithoutADatabaseOrABuildableEnforcer(t *testing.T) {
	switch os.Getenv(orchestratorBootRefusalCaseEnv) {
	case "nil-database":
		setDetectionOverrideCacheForTest(testOverrideCache(noOverrides))
		wireOrchestratorEnforcer(nil)
		return
	case "failing-build":
		db, _, err := sqlmock.New()
		if err != nil {
			fmt.Println(err)
			os.Exit(3)
		}
		setDetectionOverrideCacheForTest(testOverrideCache(noOverrides))
		newOrchestratorEnforcer = failingEnforcerBuild
		wireOrchestratorEnforcer(db)
		return
	}

	for _, c := range []struct{ name, want string }{
		{"nil-database", "this orchestrator has no database (PRD v11 §1.1)"},
		{"failing-build", "anchored enforcer could not be built: planted build failure"},
	} {
		t.Run(c.name, func(t *testing.T) {
			cmd := exec.Command(os.Args[0], "-test.run=^TestTheOrchestratorRefusesToBootWithoutADatabaseOrABuildableEnforcer$", "-test.count=1")
			cmd.Env = append(os.Environ(), orchestratorBootRefusalCaseEnv+"="+c.name)
			out, err := cmd.CombinedOutput()
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() == 0 {
				t.Fatalf("the process did not exit non-zero (err %v); output:\n%s", err, out)
			}
			if !strings.Contains(string(out), "[ANCHORED-ENFORCE]") || !strings.Contains(string(out), c.want) {
				t.Fatalf("the exit did not name the refusal %q; output:\n%s", c.want, out)
			}
			if strings.Contains(string(out), "anchored enforcer is wired") || strings.Contains(string(out), "authors every verdict on") {
				t.Fatalf("the refused process also printed the wired line; output:\n%s", out)
			}
		})
	}
}

// TestTheAnchoredOverrideReadFailsClosed: a store error reaches the enforcer
// as an error, never as "no override", while the legacy read beside it keeps
// its documented fail-safe. The control reads a recorded override through.
func TestTheAnchoredOverrideReadFailsClosed(t *testing.T) {
	isolateOrchestratorEnforcer(t)
	ctx := context.Background()
	storeDown := errors.New("detection_action_overrides could not be read")
	reads := 0
	cache := testOverrideCache(func(context.Context, string) (map[string]agent.DetectionAction, error) {
		reads++
		return nil, storeDown
	})
	setDetectionOverrideCacheForTest(cache)

	if got, err := cache.read(ctx, "org-a"); !errors.Is(err, storeDown) || got != nil {
		t.Fatalf("read with the store down = (%v, %v), want (nil, the store's error)", got, err)
	}
	// The failure is cached for the error window, as get caches one, and is
	// still an error on the second read.
	if _, err := cache.read(ctx, "org-a"); !errors.Is(err, storeDown) || reads != 1 {
		t.Fatalf("the second read inside the error window = %v after %d store reads, want the cached error after 1", err, reads)
	}
	if got, err := orchestratorRecordedOverrides(ctx, "org-a"); !errors.Is(err, storeDown) || got != nil {
		t.Fatalf("the enforcer's read with the store down = (%v, %v), want (nil, the store's error)", got, err)
	}
	// The legacy read is unchanged: fail-safe to no override (detection_override.go).
	if got := cache.get(ctx, "org-a"); len(got) != 0 {
		t.Fatalf("the legacy get with the store down = %v, want its documented empty set", got)
	}

	setDetectionOverrideCacheForTest(nil)
	if _, err := orchestratorRecordedOverrides(ctx, "org-a"); err == nil {
		t.Fatal("the enforcer's read with no override store wired returned no error")
	}

	// CONTROL: a recorded override is read through, folded into the anchored key.
	setDetectionOverrideCacheForTest(testOverrideCache(func(context.Context, string) (map[string]agent.DetectionAction, error) {
		return map[string]agent.DetectionAction{agent.DetectionCategoryPII: agent.DetectionAction("block")}, nil
	}))
	got, err := orchestratorRecordedOverrides(ctx, "org-a")
	if err != nil || len(got) == 0 {
		t.Fatalf("CONTROL: a recorded pii=block override read as (%v, %v), want a non-empty set and no error", got, err)
	}
}

type evaluatesNothing struct{}

func (evaluatesNothing) Evaluate(context.Context, anchoredenforcer.Call) anchoredenforcer.Verdict {
	return anchoredenforcer.Verdict{Unavailable: anchoredenforcer.CauseNotWired}
}

// TestTheOrchestratorHealthReportsItsEnforcingScopes: the member is omitted
// with no enforcer, is exactly the registration list with one, and a scope's
// delivery is read from legacycompile.ScopeDeliveries only once it is
// registered.
func TestTheOrchestratorHealthReportsItsEnforcingScopes(t *testing.T) {
	isolateOrchestratorEnforcer(t)
	orchestratorEnforcerInstance.Store(nil)
	if got := orchestratorDecisionPosture(); got != nil {
		t.Fatalf("with no enforcer the decision member is %v, want it omitted", got)
	}

	orchestratorEnforcerInstance.Store(&orchestratorEnforcerSlot{enforcement: evaluatesNothing{}})
	orchestratorEnforcingScopes = nil
	body, err := json.Marshal(orchestratorDecisionPosture())
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != `{"enforcing_planes":[]}` {
		t.Fatalf("with an enforcer and nothing registered the member encodes %s, want an empty list, never null", body)
	}

	decide := legacycompile.MustScopeFor(legacycompile.PlaneDecide, "")
	if orchestratorSeamDelivers(decide) != nil {
		t.Fatal("an unregistered scope delivers something; a scope with no seam in this binary delivers nothing")
	}
	orchestratorEnforcingScopes = []legacycompile.EnforcementScope{decide}
	if got := orchestratorDecisionPosture()["enforcing_planes"]; !reflect.DeepEqual(got, []string{decide.String()}) {
		t.Fatalf("the member lists %v, want exactly the registration list %v", got, []string{decide.String()})
	}
	if got, want := orchestratorSeamDelivers(decide), legacycompile.ScopeDeliveries(decide); len(want) == 0 || !reflect.DeepEqual(got, want) {
		t.Fatalf("a registered scope delivers %v, want legacycompile.ScopeDeliveries' %v (non-empty for decide)", got, want)
	}
}

// TestTheOrchestratorEnforcerGatesTheConstructCheck reads this process's edition
// boundary from source: it must resolve the edition from the licence and return
// the RESOLVED gate, never a literal, and the enforcer must be built with it.
// A literal true turns a lapsed licence into refused requests; a literal false
// makes the chokepoint decorative. The shared enforcer's own arm is
// anchoredenforcer's TestTheActivationTakesTheEditionBoundaryFromTheProcess.
func TestTheOrchestratorEnforcerGatesTheConstructCheck(t *testing.T) {
	const file = "anchored_enforcement.go"
	src, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if err := orchestratorEditionBoundaryWiring(src); err != nil {
		t.Fatalf("%s: %v", file, err)
	}
	for name, mutate := range map[string]func(string) string{
		"a literal true refusal": func(s string) string {
			return regexp.MustCompile(`return edition\.Profile, edition\.EnforcesConstructBoundary\(\)`).ReplaceAllString(s, "return edition.Profile, true")
		},
		"a literal false refusal": func(s string) string {
			return regexp.MustCompile(`return edition\.Profile, edition\.EnforcesConstructBoundary\(\)`).ReplaceAllString(s, "return edition.Profile, false")
		},
		"a profile that is not the resolved one": func(s string) string {
			return regexp.MustCompile(`return edition\.Profile, `).ReplaceAllString(s, "return authoring.Profile{}, ")
		},
		"an enforcer built with another boundary": func(s string) string {
			return regexp.MustCompile(`EditionBoundary:\s*orchestratorEditionBoundary,`).ReplaceAllString(s, "EditionBoundary: func(context.Context) (authoring.Profile, bool) { return authoring.Profile{}, true },")
		},
	} {
		t.Run("planted "+name, func(t *testing.T) {
			mutant := mutate(string(src))
			if mutant == string(src) {
				t.Fatal("the mutation did not apply, so this positive control proves nothing")
			}
			if err := orchestratorEditionBoundaryWiring([]byte(mutant)); err == nil {
				t.Fatalf("the census accepted %s", name)
			}
		})
	}
}

func orchestratorEditionBoundaryWiring(src []byte) error {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "anchored_enforcement.go", src, 0)
	if err != nil {
		return err
	}
	render := func(n ast.Node) string {
		var b bytes.Buffer
		if printer.Fprint(&b, fset, n) != nil {
			return ""
		}
		return b.String()
	}
	var (
		resolved  bool
		results   []string
		builtWith []string
	)
	ast.Inspect(f, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.FuncDecl:
			if x.Name.Name != "orchestratorEditionBoundary" || x.Recv != nil {
				return true
			}
			ast.Inspect(x.Body, func(m ast.Node) bool {
				switch y := m.(type) {
				case *ast.AssignStmt:
					if len(y.Lhs) == 1 && len(y.Rhs) == 1 && render(y.Lhs[0]) == "edition" && render(y.Rhs[0]) == "authoringedition.Resolve(ctx)" {
						resolved = true
					}
				case *ast.ReturnStmt:
					results = results[:0]
					for _, r := range y.Results {
						results = append(results, render(r))
					}
				}
				return true
			})
			return false
		case *ast.CompositeLit:
			sel, ok := x.Type.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "Options" {
				return true
			}
			if pkg, ok := sel.X.(*ast.Ident); !ok || pkg.Name != "anchoredenforcer" {
				return true
			}
			for _, elt := range x.Elts {
				if kv, ok := elt.(*ast.KeyValueExpr); ok && render(kv.Key) == "EditionBoundary" {
					builtWith = append(builtWith, render(kv.Value))
				}
			}
		}
		return true
	})
	switch {
	case !resolved:
		return errors.New("orchestratorEditionBoundary does not resolve `edition := authoringedition.Resolve(ctx)`")
	case len(results) != 2 || results[1] != "edition.EnforcesConstructBoundary()":
		return fmt.Errorf("orchestratorEditionBoundary returns %v, want (edition.Profile, edition.EnforcesConstructBoundary())", results)
	case results[0] != "edition.Profile":
		return fmt.Errorf("orchestratorEditionBoundary returns the profile %s, want edition.Profile", results[0])
	case len(builtWith) != 1 || builtWith[0] != "orchestratorEditionBoundary":
		return fmt.Errorf("the enforcer is built with EditionBoundary %v, want exactly orchestratorEditionBoundary", builtWith)
	}
	return nil
}
