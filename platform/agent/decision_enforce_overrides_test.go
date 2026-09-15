// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"axonflow/platform/decision/activation"
	"axonflow/platform/decision/authoringcatalog"
	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/legacycompile"
	"axonflow/platform/shared/detectionposture"
	sharedidentity "axonflow/platform/shared/identity"
	sharedpolicy "axonflow/platform/shared/policy"
)

// An organization's recorded detection overrides on the enforcing seams
// (#4045): what the table admits, how the enforcer reads it, and the verdicts it
// moves.

// overrideVocabularyFromMigrations reads the categories and actions
// detection_action_overrides admits, from the CHECK constraints the migrations
// leave in force: for each, the last migration that declares it, core before
// enterprise and each by number. A CHECK on the table in a form this reader does
// not parse reds the guard instead of being skipped.
func overrideVocabularyFromMigrations(t *testing.T) (categories, actions []string) {
	t.Helper()
	type migration struct {
		number int
		path   string
	}
	var ordered []migration
	for _, dir := range []string{"core", "enterprise"} {
		files, err := filepath.Glob(filepath.Join("../../migrations", dir, "*.sql"))
		if err != nil {
			t.Fatal(err)
		}
		var up []migration
		for _, f := range files {
			base := filepath.Base(f)
			if strings.HasSuffix(base, "_down.sql") {
				continue
			}
			n, err := strconv.Atoi(strings.SplitN(base, "_", 2)[0])
			if err != nil {
				continue
			}
			up = append(up, migration{n, f})
		}
		sort.Slice(up, func(i, j int) bool { return up[i].number < up[j].number })
		ordered = append(ordered, up...)
	}
	declaration := func(constraint, column string) string {
		return constraint + `\s+CHECK\s*\(\s*` + column + `\s+IN\s*\(`
	}
	declarations := []struct {
		shape *regexp.Regexp
		value *regexp.Regexp
		into  *[]string
	}{
		{
			regexp.MustCompile(declaration("detection_action_overrides_category_chk", "category")),
			regexp.MustCompile(declaration("detection_action_overrides_category_chk", "category") + `([^)]*)\)`),
			&categories,
		},
		{
			regexp.MustCompile(declaration("detection_action_overrides_action_chk", "action")),
			regexp.MustCompile(declaration("detection_action_overrides_action_chk", "action") + `([^)]*)\)`),
			&actions,
		},
	}
	quoted := regexp.MustCompile(`'([a-z_]+)'`)
	// A row-level-security policy's WITH CHECK is a predicate, not a constraint.
	check := regexp.MustCompile(`(?i)\bCHECK\b`)
	policyCheck := regexp.MustCompile(`(?i)\bWITH\s+CHECK\b`)
	for _, m := range ordered {
		body, err := os.ReadFile(m.path)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(body), "detection_action_overrides") {
			continue
		}
		for _, statement := range strings.Split(sqlCode(string(body)), ";") {
			if !strings.Contains(statement, "detection_action_overrides") {
				continue
			}
			parsed := 0
			for _, d := range declarations {
				parsed += len(d.shape.FindAllStringIndex(statement, -1))
			}
			if checks := len(check.FindAllStringIndex(statement, -1)) - len(policyCheck.FindAllStringIndex(statement, -1)); checks > parsed {
				t.Fatalf("%s constrains detection_action_overrides with %d CHECK clause(s) and this guard parses %d; extend overrideVocabularyFromMigrations so the vocabulary it reads is the one in force", m.path, checks, parsed)
			}
		}
		for _, d := range declarations {
			found := d.value.FindAllSubmatch(body, -1)
			if len(found) == 0 {
				continue
			}
			*d.into = nil
			for _, q := range quoted.FindAllSubmatch(found[len(found)-1][1], -1) {
				*d.into = append(*d.into, string(q[1]))
			}
		}
	}
	if len(categories) == 0 || len(actions) == 0 {
		t.Fatalf("no migration declares the detection_action_overrides category and action CHECK constraints (categories %v, actions %v), so the vocabulary this guard reads has moved", categories, actions)
	}
	return categories, actions
}

// sqlCode returns SQL with its comments removed and its string literals
// emptied, so a word inside either is not read as code.
func sqlCode(sql string) string {
	var b strings.Builder
	for i := 0; i < len(sql); i++ {
		switch {
		case strings.HasPrefix(sql[i:], "--"):
			for i < len(sql) && sql[i] != '\n' {
				i++
			}
			b.WriteByte('\n')
		case sql[i] == '\'':
			for i++; i < len(sql); i++ {
				if sql[i] != '\'' {
					continue
				}
				if i+1 < len(sql) && sql[i+1] == '\'' {
					i++
					continue
				}
				break
			}
			b.WriteString("''")
		default:
			b.WriteByte(sql[i])
		}
	}
	return b.String()
}

// TestEveryRecordedOverrideIsFoldedIntoTheAnchoredEngineOrDeclaredInert is
// #4045's guard: every (category, action) the table admits either assigns an
// action the anchored engine folds, on a policy category OrgOverrideCategoryFor
// reads back to the recorded category, or names a category declared inert with
// its reason. A category a migration adds reds here instead of being ignored.
func TestEveryRecordedOverrideIsFoldedIntoTheAnchoredEngineOrDeclaredInert(t *testing.T) {
	categories, actions := overrideVocabularyFromMigrations(t)
	for _, want := range []string{DetectionCategoryPII, DetectionCategorySQLI, DetectionCategoryDangerousQuery, DetectionCategoryDangerousCommand, DetectionCategoryObligationFallback} {
		if !slices.Contains(categories, want) {
			t.Fatalf("PREMISE: the migrations' category CHECK %v does not admit %q", categories, want)
		}
	}
	inertCategories := detectionposture.InertCategories()
	for _, category := range categories {
		_, inert := inertCategories[category]
		for _, action := range actions {
			assigned, err := anchoredCategoryActions(map[string]DetectionAction{category: DetectionAction(action)})
			if err != nil {
				t.Fatalf("%s=%s: %v", category, action, err)
			}
			switch {
			case len(assigned) == 0 && !inert:
				t.Fatalf("%s=%s assigns nothing on the anchored engine and is not declared inert", category, action)
			case len(assigned) > 0 && inert:
				t.Fatalf("%s is declared inert, yet %s=%s assigns %v", category, category, action, assigned)
			}
			for policyCategory, got := range assigned {
				if got != legacycompile.LegacyAction(action) || sharedpolicy.OrgOverrideCategoryFor(sharedpolicy.PolicyCategory(policyCategory)) != category {
					t.Fatalf("%s=%s assigns %s to %s; want %s on a category OrgOverrideCategoryFor reads back to %s", category, action, got, policyCategory, action, category)
				}
			}
		}
	}
	for category, reason := range inertCategories {
		if !slices.Contains(categories, category) || reason == "" {
			t.Fatalf("the inert declaration %q names a category the table does not admit, or gives no reason", category)
		}
	}
	if _, err := anchoredCategoryActions(map[string]DetectionAction{"exfiltration": DetectionActionBlock}); err == nil {
		t.Fatal("PLANTED: a recorded category nothing folds or declares inert was ignored")
	}
}

func TestTheAnchoredReadOfOverridesReturnsTheErrorTheLegacyReadFailsSafeOn(t *testing.T) {
	ctx := context.Background()
	reader := &fakeOverrideReader{err: errors.New("the override table is unreadable")}
	c := newDetectionOverrideCache(reader, time.Minute)
	if got := c.get(ctx, "org-a"); len(got) != 0 {
		t.Fatalf("CONTROL: the legacy read failed safe to %v, want no override", got)
	}
	calls := reader.callCount()
	if _, err := c.read(ctx, "org-a"); err == nil {
		t.Fatal("the anchored read served the empty set the legacy read cached for a failed lookup")
	}
	if reader.callCount() != calls {
		t.Fatalf("the anchored read re-read a failing store inside the error window (reads %d -> %d)", calls, reader.callCount())
	}

	fresh := newDetectionOverrideCache(reader, time.Minute)
	if _, err := fresh.read(ctx, "org-b"); err == nil {
		t.Fatal("the anchored read returned no error for a failed lookup")
	}
	calls = reader.callCount()
	if _, err := fresh.read(ctx, "org-b"); err == nil || reader.callCount() != calls {
		t.Fatalf("the anchored read's own failure was not cached for the error window (err=%v, reads %d -> %d)", err, calls, reader.callCount())
	}
	if got := fresh.get(ctx, "org-b"); len(got) != 0 {
		t.Fatalf("beside the anchored read's cached failure the legacy read served %v, want no override", got)
	}

	reader.mu.Lock()
	reader.err = nil
	reader.data = map[string]map[string]DetectionAction{"org-a": {DetectionCategorySQLI: DetectionActionBlock}}
	reader.mu.Unlock()
	c.invalidate("org-a")
	got, err := c.read(ctx, "org-a")
	if err != nil || got[DetectionCategorySQLI] != DetectionActionBlock {
		t.Fatalf("once the store reads, the anchored read returned %v (err=%v); want the recorded sqli=block", got, err)
	}
	calls = reader.callCount()
	if _, err := c.read(ctx, "org-a"); err != nil || reader.callCount() != calls {
		t.Fatalf("a successful read was not served from the cache within its TTL (err=%v, reads %d -> %d)", err, calls, reader.callCount())
	}
}

func TestTheEnforcerRebuildsAnOrganizationsEngineWhenItsRecordedOverridesChange(t *testing.T) {
	enfSetup(t)
	ctx := context.Background()
	snap := enfSnapshot(t)
	docs := enfPublishDocument(t, snap)
	boot, err := sharedidentity.BootstrapAdmission(sharedidentity.AdmissionBootstrapConfig{})
	if err != nil {
		t.Fatal(err)
	}
	e, err := newAnchoredEnforcer(docs, func() (*authoringcatalog.Snapshot, error) { return snap, nil }, boot.Admitter, boot.Registry.Epoch)
	if err != nil {
		t.Fatal(err)
	}
	digest, _, err := docs.ActiveTip(ctx, enfOrgPublished)
	if err != nil {
		t.Fatal(err)
	}
	activate := func(assigned legacycompile.CategoryActions) *activation.Activation {
		t.Helper()
		act, err := e.activationFor(ctx, decideSeamScope, enfOrgPublished, digest, assigned)
		if err != nil {
			t.Fatal(err)
		}
		return act
	}

	shipped := activate(nil)
	if activate(nil) != shipped {
		t.Fatal("CONTROL: an unchanged engine was rebuilt rather than served from the cache")
	}
	overridden := activate(legacycompile.CategoryActions{"security-sqli": legacycompile.ActionBlock})
	if overridden == shipped || len(overridden.Overrides) != 1 || overridden.PolicyBundle == shipped.PolicyBundle {
		t.Fatalf("a recorded override did not rebuild the engine: %+v", overridden.Overrides)
	}
	if activate(legacycompile.CategoryActions{"security-sqli": legacycompile.ActionBlock}) != overridden {
		t.Fatal("an unchanged override set rebuilt the engine")
	}
	if back := activate(nil); back == overridden || back.Overrides != nil || back.PolicyBundle != shipped.PolicyBundle {
		t.Fatalf("deleting the override did not return the shipped engine: overrides %+v, bundle %s want %s", back.Overrides, back.PolicyBundle, shipped.PolicyBundle)
	}
}

// enfOverrideReachedControl derives a decide-bound control of an enabled system
// row that a recorded override of category reaches, with a probe that fires it:
// a token for a row carrying no validator, a value its validator accepts
// otherwise.
func enfOverrideReachedControl(t *testing.T, category string) (rowID, policyID, probe string) {
	t.Helper()
	for _, c := range enfScopeControls(t, decideSeamScope) {
		if c.row.Tier != "system" || !c.row.Enabled || sharedpolicy.OrgOverrideCategoryFor(sharedpolicy.PolicyCategory(c.row.Category)) != category {
			continue
		}
		validator := sharedpolicy.ValidatorFor(c.row.PolicyID, sharedpolicy.PolicyCategory(c.row.Category))
		if validator == nil {
			return c.row.PolicyID, c.policy.ID, "ZZOVERRIDEPROBE4045"
		}
		for _, candidate := range mrsRedactCandidates {
			if ok, _ := validator(candidate, mrsRedactContent(candidate)); ok {
				return c.row.PolicyID, c.policy.ID, candidate
			}
		}
	}
	t.Fatalf("decide binds no enabled system control a recorded %s override reaches with a probe that fires it", category)
	return "", "", ""
}

// enfRecordOverride records one category's action for org and drops the cached
// read, so the next request sees it.
func enfRecordOverride(reader *fakeOverrideReader, org, category string, action DetectionAction) {
	reader.mu.Lock()
	reader.data[org] = map[string]DetectionAction{category: action}
	reader.mu.Unlock()
	InvalidateOrgDetectionOverrides(org)
}

// TestARecordedSQLiBlockDeniesOnDecide is #4017's case on the decide seam:
// every shipped sys_sqli_* row stores warn, and an organization that recorded
// sqli=block is denied by the organization root's replacement of the control.
func TestARecordedSQLiBlockDeniesOnDecide(t *testing.T) {
	enfSetup(t)
	row, policy, probe := enfOverrideReachedControl(t, DetectionCategorySQLI)
	enfInstallDetectors(t, map[string]string{row: regexp.QuoteMeta(probe)}, nil)
	reader := &fakeOverrideReader{data: map[string]map[string]DetectionAction{}}
	installTestOverrideCache(t, reader, time.Minute)
	query := mrsRedactContent(probe)

	if r := enfDecide(t, enfOrgPublished, true, DecisionStageLLM, query); r.code != http.StatusOK || r.str(t, "verdict") != VerdictAllow {
		t.Fatalf("CONTROL: with no override recorded got HTTP %d verdict %q for the stored warn; want allow. body=%s", r.code, r.str(t, "verdict"), r.raw)
	}

	enfRecordOverride(reader, enfOrgPublished, DetectionCategorySQLI, DetectionActionBlock)
	anchored := enfDecide(t, enfOrgPublished, true, DecisionStageLLM, query)
	if anchored.code != http.StatusOK || anchored.str(t, "verdict") != VerdictDeny || anchored.str(t, "engine") != decisionEngineAnchored {
		t.Fatalf("the recorded sqli=block got HTTP %d verdict %q engine %q; want the anchored deny. body=%s",
			anchored.code, anchored.str(t, "verdict"), anchored.str(t, "engine"), anchored.raw)
	}
	if reasons := anchored.strings(t, "reasons"); len(reasons) != 1 || reasons[0] != string(contract.ReasonExplicitConstraint) {
		t.Fatalf("reasons %v; want exactly [%s]", reasons, contract.ReasonExplicitConstraint)
	}
	if policies := anchored.strings(t, "evaluated_policies"); len(policies) == 0 || policies[0] != activation.OverridePolicyIDPrefix+policy {
		t.Fatalf("evaluated_policies %v; the organization root's replacement of %s must decide", policies, policy)
	}
}

// TestAnOverrideDrivenBlockOnDecideIsNamedByTheControlItReplaces is #4211: the
// organization root's replacement under a recorded detection override is the
// shipped control enforced with the recorded action, so the wire and the audit
// row name it by that control (PRD v11 §1.14). An empty policy_names left the
// audit view (#3347) showing no name for any override-driven block.
func TestAnOverrideDrivenBlockOnDecideIsNamedByTheControlItReplaces(t *testing.T) {
	enfSetup(t)
	rowID, policy, probe := enfOverrideReachedControl(t, DetectionCategorySQLI)
	var name string
	for _, c := range enfScopeControls(t, decideSeamScope) {
		if c.policy.ID == policy {
			name = c.policy.Name
		}
	}
	if name == "" {
		t.Fatalf("the decide restriction names no %s, so the assertions below would be vacuous", policy)
	}
	enfInstallDetectors(t, map[string]string{rowID: regexp.QuoteMeta(probe)}, nil)
	reader := &fakeOverrideReader{data: map[string]map[string]DetectionAction{}}
	installTestOverrideCache(t, reader, time.Minute)
	enfRecordOverride(reader, enfOrgPublished, DetectionCategorySQLI, DetectionActionBlock)

	read := expectIdentityRow(t, PlaneDecision, decideAuditColumns)
	r := enfDecide(t, enfOrgPublished, true, DecisionStageLLM, mrsRedactContent(probe))
	if r.code != http.StatusOK || r.str(t, "verdict") != VerdictDeny {
		t.Fatalf("the recorded sqli=block got HTTP %d verdict %q; want 200 deny. body=%s", r.code, r.str(t, "verdict"), r.raw)
	}
	replacement := activation.OverridePolicyIDPrefix + policy
	if identities, want := r.wireIdentities(t), (PolicyIdentity{ID: replacement, Name: name, Source: "shipped"}); len(identities) == 0 || identities[0] != want {
		t.Fatalf("policy_identities %+v; want the first %+v. body=%s", identities, want, r.raw)
	}
	row := read(t)
	if !slices.Contains(row.PolicyIDs, replacement) || !slices.Contains(row.PolicyNames, name) || slices.Contains(row.PolicyNames, replacement) {
		t.Errorf("row policy_ids %v policy_names %v; want %s named %q, and never by its id", row.PolicyIDs, row.PolicyNames, replacement, name)
	}
}

// TestARecordedRedactOnDecideIsMandatoryForACallerThatDeclaresNoRedaction is
// the stated #4045 divergence. The obligation model is unchanged by an
// override: a pii=redact override makes field_redact a mandatory requirement,
// which decide hands only to a caller whose handshake declares it, so a caller
// that declares none is refused where the retired legacy engine answered allow
// with a redact_pii obligation it trusted the caller to carry out.
func TestARecordedRedactOnDecideIsMandatoryForACallerThatDeclaresNoRedaction(t *testing.T) {
	enfSetup(t)
	row, _, probe := enfOverrideReachedControl(t, DetectionCategoryPII)
	enfInstallDetectors(t, map[string]string{row: regexp.QuoteMeta(probe)}, nil)
	reader := &fakeOverrideReader{data: map[string]map[string]DetectionAction{}}
	installTestOverrideCache(t, reader, time.Minute)
	query := mrsRedactContent(probe)

	if r := enfDecide(t, enfOrgPublished, true, DecisionStageLLM, query); r.code != http.StatusOK || r.str(t, "verdict") != VerdictAllow {
		t.Fatalf("CONTROL: with no override recorded got HTTP %d verdict %q; want allow, so the refusal below is the override's. body=%s", r.code, r.str(t, "verdict"), r.raw)
	}
	enfRecordOverride(reader, enfOrgPublished, DetectionCategoryPII, DetectionActionRedact)
	anchored := enfDecide(t, enfOrgPublished, true, DecisionStageLLM, query)
	reasons := anchored.strings(t, "reasons")
	if anchored.code != http.StatusOK || anchored.str(t, "verdict") != VerdictDeny || anchored.str(t, "engine") != decisionEngineAnchored ||
		len(reasons) != 1 || !strings.HasPrefix(reasons[0], string(contract.ReasonUnsupportedObligation)) {
		t.Fatalf("the recorded pii=redact got HTTP %d verdict %q engine %q reasons %v; want the anchored deny unsupported_obligation. body=%s",
			anchored.code, anchored.str(t, "verdict"), anchored.str(t, "engine"), reasons, anchored.raw)
	}
}
