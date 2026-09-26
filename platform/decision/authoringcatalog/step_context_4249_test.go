// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package authoringcatalog_test

import (
	"context"
	"crypto/ed25519"
	"strings"
	"testing"
	"time"

	"axonflow/platform/decision/authoring"
	"axonflow/platform/decision/authoringcatalog"
	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/pdp"
	"axonflow/platform/decision/registry"
)

// #4249 row 5670275054: an organization's own document constrains a workflow or
// multi-agent step by the step's name or its tool. These are the PUBLISH half,
// through the real deployment vocabulary and the real authoring.API.Publish, on
// both editions.

const (
	stepNamePath = "args.context.step__name"
	toolNamePath = "args.context.tool__name"
	stepTypePath = "args.context.step__type"
)

var stepAt = time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)

func toolCallID() contract.ID {
	return contract.MustParseID(contract.KindAction, "Action::"+authoringcatalog.ActionToolCall)
}

// stepDocument is an organization document with one policy of authority over
// path, reading it with where, and declaring it at declType. declare=false omits
// the document's own declaration, which the ruling says the document must carry.
func stepDocument(authority contract.Authority, path string, declType pdp.ValueType, declare bool, where pdp.Condition) pdp.Document {
	attrs := []pdp.AttributeSchema{
		{Path: pdp.ActionIDPath, Type: pdp.TypeString},
		{Path: pdp.ActionTagsPath, Type: pdp.TypeArray},
	}
	if declare {
		// A caller-typed label is declared optional (pdp checkCallerTypedLabels).
		label := path == stepNamePath || path == toolNamePath
		attrs = append(attrs, pdp.AttributeSchema{Path: path, Type: declType, Optional: label})
	}
	return pdp.Document{
		Root: pdp.RootOrganization, Version: 1, Attributes: attrs,
		Policies: []pdp.Policy{{
			ID: "step.export_ledger", Authority: authority, Root: pdp.RootOrganization,
			Scope: pdp.Scope{Organization: true}, Actions: pdp.ActionSelector{Actions: []contract.ID{toolCallID()}},
			Where: where,
		}},
	}
}

func stepFixture(path string, value any, expect pdp.Verdict) []authoring.Fixture {
	return []authoring.Fixture{{
		Name: "a tool step named export_ledger",
		Attributes: contract.AttributeSet{
			pdp.ActionIDPath:   contract.Known(toolCallID().String(), contract.ProvPlatform, 1, stepAt),
			pdp.ActionTagsPath: contract.Known([]any{"stage:tool"}, contract.ProvPlatform, 1, stepAt),
			path:               contract.Known(value, contract.ProvCaller, 1, stepAt),
		},
		Expect: map[string]pdp.Verdict{"step.export_ledger": expect},
	}}
}

// publishStepDocument runs NewDocument and API.Publish under edition, returning
// every finding either raised and the first error.
func publishStepDocument(t *testing.T, edition authoring.Edition, doc pdp.Document, fixtures []authoring.Fixture) (authoring.Findings, error) {
	t.Helper()
	dep := testDeployment()
	if edition == authoring.EditionEnterprise {
		dep.Edition = registry.EditionEnterprise
	}
	snap, err := authoringcatalog.Resolve(authoringcatalog.SourceDeployment, dep)
	if err != nil {
		t.Fatal(err)
	}
	pub, priv, _ := ed25519.GenerateKey(nil)
	trust := pdp.NewTrustStore()
	trust.Authorize(pdp.RootOrganization, "org-key", pub)
	profile, err := authoring.ProfileFor(edition)
	if err != nil {
		t.Fatal(err)
	}
	api, err := authoring.NewAPI(snap.Catalog, authoring.StaticTrust(trust), profile)
	if err != nil {
		t.Fatal(err)
	}
	meta := authoring.Metadata{
		DocumentID: "step-context-4249", Title: "a named step",
		Author: contract.MustParseID(contract.KindPrincipal, "User::axonflow-minted:installer"),
	}
	d, findings, err := authoring.NewDocument(authoring.Document{Metadata: meta, Policy: doc}, snap.Catalog)
	if err != nil {
		return findings, err
	}
	opts := authoring.PublishOptions{Root: pdp.RootOrganization, KeyID: "org-key", PrivateKey: priv, Fixtures: fixtures, Now: stepAt}
	if edition == authoring.EditionEnterprise {
		opts.Approvers = []contract.ID{contract.MustParseID(contract.KindPrincipal, "User::axonflow-minted:reviewer")}
	}
	_, pubFindings, err := api.Publish(context.Background(), d, opts)
	return append(findings, pubFindings...), err
}

func findingNaming(f authoring.Findings, code, fragment string) bool {
	for _, x := range f {
		if x.Code == code && strings.Contains(x.Detail, fragment) {
			return true
		}
	}
	return false
}

// TestTheDeploymentVocabularyDeclaresTheStepLabelsOnEveryAction: corpusArguments
// makes every corpus args.* declaration an argument of every deployment action,
// which is what publish's argument check and pdp admission both read. The step
// TYPE is not one: it is the action.
func TestTheDeploymentVocabularyDeclaresTheStepLabelsOnEveryAction(t *testing.T) {
	snap, err := authoringcatalog.Resolve(authoringcatalog.SourceDeployment, testDeployment())
	if err != nil {
		t.Fatal(err)
	}
	for _, local := range authoringcatalog.DeploymentActions() {
		entry, ok := snap.Catalog.Actions["Action::"+local]
		if !ok {
			t.Fatalf("PREMISE: the deployment vocabulary has no Action::%s", local)
		}
		for _, name := range []string{"context.step__name", "context.tool__name"} {
			if got := entry.Arguments[name]; got != pdp.TypeString {
				t.Errorf("Action::%s declares argument %s as %q; want string", local, name, got)
			}
		}
		if _, ok := entry.Arguments["context.step__type"]; ok {
			t.Errorf("Action::%s declares context.step__type; a step's type is the action", local)
		}
	}
}

func TestADocumentConstrainingAStepByItsNamePublishesOnBothEditions(t *testing.T) {
	for _, ed := range []authoring.Edition{authoring.EditionCommunity, authoring.EditionEnterprise} {
		for _, path := range []string{stepNamePath, toolNamePath} {
			t.Run(string(ed)+"/"+path, func(t *testing.T) {
				doc := stepDocument(contract.AuthorityConstraint, path, pdp.TypeString, true, pdp.Compare(path, pdp.OpEq, "export_ledger").HandlingAbsence(pdp.AbsentIsNoMatch))
				if f, err := publishStepDocument(t, ed, doc, stepFixture(path, "export_ledger", pdp.VerdictMatch)); err != nil {
					t.Fatalf("a %s constraint over %s was refused at publish: %v\n%v", ed, path, err, f)
				}
			})
			t.Run(string(ed)+"/requirement/"+path, func(t *testing.T) {
				doc := stepDocument(contract.AuthorityRequirement, path, pdp.TypeString, true, pdp.Compare(path, pdp.OpEq, "export_ledger").HandlingAbsence(pdp.AbsentIsNoMatch))
				doc.Policies[0].Mandatory = true
				doc.Policies[0].Obligations = []contract.Obligation{{Type: contract.ObImmutableAudit, Mandatory: true, SourcePolicy: "step.export_ledger", SchemaVersion: 1}}
				if f, err := publishStepDocument(t, ed, doc, stepFixture(path, "export_ledger", pdp.VerdictMatch)); err != nil {
					t.Fatalf("a %s requirement over %s was refused at publish: %v\n%v", ed, path, err, f)
				}
			})
		}
	}
}

// TestTheDocumentMustDeclareTheStepLabelItself answers the brief's item 6: the
// system corpus's declaration does not reach an organization document's own
// schema, so a document that reads the path without declaring it is refused
// FIELD_NOT_IN_SCHEMA.
func TestTheDocumentMustDeclareTheStepLabelItself(t *testing.T) {
	doc := stepDocument(contract.AuthorityConstraint, stepNamePath, pdp.TypeString, false, pdp.Compare(stepNamePath, pdp.OpEq, "export_ledger").HandlingAbsence(pdp.AbsentIsNoMatch))
	f, err := publishStepDocument(t, authoring.EditionCommunity, doc, stepFixture(stepNamePath, "export_ledger", pdp.VerdictMatch))
	if err == nil || !findingNaming(f, pdp.RuleFieldNotInSchema, stepNamePath) {
		t.Fatalf("an undeclared read of %s published (err %v); want FIELD_NOT_IN_SCHEMA naming it: %v", stepNamePath, err, f)
	}
}

// TestADocumentDeclaringTheStepLabelAtAnotherTypeIsRefused: nothing else in a
// composition declares the path (no template or pack reads it), so no
// composed-attribute conflict fires; the refusal that bites is publish's
// argument check against the action's declared type.
func TestADocumentDeclaringTheStepLabelAtAnotherTypeIsRefused(t *testing.T) {
	doc := stepDocument(contract.AuthorityConstraint, stepNamePath, pdp.TypeNumber, true, pdp.Compare(stepNamePath, pdp.OpEq, 7).HandlingAbsence(pdp.AbsentIsNoMatch))
	f, err := publishStepDocument(t, authoring.EditionCommunity, doc, stepFixture(stepNamePath, 7, pdp.VerdictMatch))
	if err == nil || !findingNaming(f, authoring.CodeArgumentNotInActionSchema, `declares as "number"`) {
		t.Fatalf("a number declaration of %s published (err %v); want ARGUMENT_NOT_IN_ACTION_SCHEMA naming the type disagreement: %v", stepNamePath, err, f)
	}
}

// TestADocumentReadingTheStepTypeIsRefusedAndPointedAtTheAction: the step type is
// not declared, so an organization selects it with the action selector.
func TestADocumentReadingTheStepTypeIsRefusedAndPointedAtTheAction(t *testing.T) {
	doc := stepDocument(contract.AuthorityConstraint, stepTypePath, pdp.TypeString, true, pdp.Compare(stepTypePath, pdp.OpEq, "tool_call"))
	f, err := publishStepDocument(t, authoring.EditionCommunity, doc, stepFixture(stepTypePath, "tool_call", pdp.VerdictMatch))
	if err == nil || !findingNaming(f, authoring.CodeArgumentNotInActionSchema, stepTypePath) {
		t.Fatalf("a read of %s published (err %v); want ARGUMENT_NOT_IN_ACTION_SCHEMA naming it: %v", stepTypePath, err, f)
	}
}

// TestAPermissionKeyedOnAStepLabelIsRefusedAtPublish is the (B') refusal through
// the real publish path, on both editions.
func TestAPermissionKeyedOnAStepLabelIsRefusedAtPublish(t *testing.T) {
	for _, ed := range []authoring.Edition{authoring.EditionCommunity, authoring.EditionEnterprise} {
		for _, path := range []string{stepNamePath, toolNamePath} {
			t.Run(string(ed)+"/"+path, func(t *testing.T) {
				doc := stepDocument(contract.AuthorityPermission, path, pdp.TypeString, true, pdp.Compare(path, pdp.OpEq, "read_only_lookup"))
				f, err := publishStepDocument(t, ed, doc, stepFixture(path, "read_only_lookup", pdp.VerdictMatch))
				if err == nil || !findingNaming(f, pdp.RuleAuthorityFromUntrusted, "caller-typed label") {
					t.Fatalf("a %s permission over %s published (err %v); want AUTHORITY_FROM_UNTRUSTED naming the label: %v", ed, path, err, f)
				}
			})
		}
	}
}

// TestALabelConstraintThatAnswersUnknownOnAbsenceIsRefusedAtPublish is master's
// ruling (A) through the real publish path on both editions: a constraint over a
// label that says unknown (or nothing) about its absence would withhold every
// request on every plane that carries no such label, so publish refuses it.
func TestALabelConstraintThatAnswersUnknownOnAbsenceIsRefusedAtPublish(t *testing.T) {
	for _, ed := range []authoring.Edition{authoring.EditionCommunity, authoring.EditionEnterprise} {
		for _, path := range []string{stepNamePath, toolNamePath} {
			for name, cond := range map[string]pdp.Condition{
				"unknown":     pdp.Compare(path, pdp.OpEq, "export_ledger").HandlingAbsence(pdp.AbsentIsUnknown),
				"unspecified": pdp.Compare(path, pdp.OpEq, "export_ledger"),
			} {
				t.Run(string(ed)+"/"+path+"/"+name, func(t *testing.T) {
					doc := stepDocument(contract.AuthorityConstraint, path, pdp.TypeString, true, cond)
					f, err := publishStepDocument(t, ed, doc, stepFixture(path, "export_ledger", pdp.VerdictMatch))
					if err == nil || !findingNaming(f, pdp.RuleAbsenceNotHandled, "same dodge as a renamed one") {
						t.Fatalf("a %s label constraint with absence %s published (err %v); want ABSENCE_NOT_HANDLED requiring no_match: %v", ed, name, err, f)
					}
				})
			}
		}
	}
}
