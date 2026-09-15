// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package authoring_test

import (
	"crypto/ed25519"
	"errors"
	"reflect"
	"strings"
	"testing"

	"axonflow/platform/decision/authoring"
	"axonflow/platform/decision/contract"
	"axonflow/platform/decision/pdp"
)

// The composition authority (#4045) signs an organization root that is the
// organization's authored document, verified and unchanged, followed by the
// controls its recorded detection overrides re-action.

const (
	composedProbe  = "signal.detector.composition__probe"
	composedSecond = "signal.detector.composition__second"
)

func notifyOn(id, path string) pdp.Policy {
	return pdp.Policy{
		ID: id, Authority: contract.AuthorityRequirement, Root: pdp.RootOrganization,
		Scope: pdp.Scope{Organization: true}, Actions: pdp.ActionSelector{Any: true},
		Where: pdp.Compare(path, pdp.OpEq, true),
		Obligations: []contract.Obligation{{
			Type: contract.ObNotification, Params: map[string]string{"severity": "high", "category": "security-sqli"},
			SourcePolicy: id, SchemaVersion: 1,
		}},
	}
}

func boolSchema(path string) pdp.AttributeSchema {
	return pdp.AttributeSchema{Path: path, Type: pdp.TypeBoolean}
}

func newCompositionAuthority(t *testing.T) *authoring.CompositionAuthority {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	c, err := authoring.NewCompositionAuthority(priv)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func authoredDocument(root pdp.Root) *pdp.Document {
	p := notifyOn("authored.notify", composedProbe)
	p.Root = root
	return &pdp.Document{
		Root: root, Version: 7, Attributes: []pdp.AttributeSchema{boolSchema(composedProbe)},
		Policies: []pdp.Policy{p}, InteractiveRealms: map[string]bool{"axonflow-trusted-header": true},
	}
}

// authoredSource signs doc as a publication attests an organization document.
func authoredSource(t *testing.T, doc *pdp.Document) *authoring.AuthoredSource {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := pdp.BuildBundle(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := bundle.Sign("org-key", priv); err != nil {
		t.Fatal(err)
	}
	return &authoring.AuthoredSource{Document: doc, Bundle: bundle, Key: pub}
}

func TestACompositionIsTheAuthoredDocumentUnchangedFollowedByItsAdditions(t *testing.T) {
	comp := newCompositionAuthority(t)
	authored := authoredSource(t, authoredDocument(pdp.RootOrganization))
	additions := []pdp.Policy{notifyOn("organization_override:first", composedProbe), notifyOn("organization_override:second", composedSecond)}
	schemas := []pdp.AttributeSchema{boolSchema(composedProbe), boolSchema(composedSecond)}

	got, err := comp.Compose(authored, nil, additions, schemas)
	if err != nil {
		t.Fatal(err)
	}
	if want := append(append([]pdp.Policy(nil), authored.Document.Policies...), additions...); !reflect.DeepEqual(got.Document.Policies, want) {
		t.Fatalf("the composition carries %+v; want the authored policies unchanged and in order, then the additions", got.Document.Policies)
	}
	if want := schemas; !reflect.DeepEqual(got.Document.Attributes, want) {
		t.Fatalf("the composition declares %+v; want each attribute once, the authored declaration first", got.Document.Attributes)
	}
	if got.Document.Root != pdp.RootOrganization || got.Document.Version != 7 ||
		!reflect.DeepEqual(got.Document.InteractiveRealms, authored.Document.InteractiveRealms) {
		t.Fatalf("the composition is root %q version %d realms %v; want the authored document's", got.Document.Root, got.Document.Version, got.Document.InteractiveRealms)
	}
	if len(authored.Document.Policies) != 1 || len(authored.Document.Attributes) != 1 {
		t.Fatalf("composing edited the authored document: %d policies, %d attributes", len(authored.Document.Policies), len(authored.Document.Attributes))
	}

	if got.Bundle.KeyID != authoring.CompositionKeyID {
		t.Fatalf("the composition is signed under key %q, want %q", got.Bundle.KeyID, authoring.CompositionKeyID)
	}
	trust := pdp.NewTrustStore()
	trust.Authorize(pdp.RootOrganization, authoring.CompositionKeyID, comp.PublicKey())
	if err := trust.Verify(got.Bundle); err != nil {
		t.Fatalf("the composition does not verify under the composition key: %v", err)
	}
	if err := pdp.BindSourceDocument(got.Document, got.Bundle); err != nil {
		t.Fatalf("the composed document is not the one its bundle was built from: %v", err)
	}
	orgTrust := pdp.NewTrustStore()
	orgTrust.Authorize(pdp.RootOrganization, authoring.CompositionKeyID, authored.Key)
	if orgTrust.Verify(got.Bundle) == nil {
		t.Fatal("the composition verifies under the organization's key, so the organization could have signed it")
	}

	t.Run("an organization with no active document composes its additions alone", func(t *testing.T) {
		alone, err := comp.Compose(nil, nil, additions, schemas)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(alone.Document.Policies, additions) || !reflect.DeepEqual(alone.Document.Attributes, schemas) || alone.Document.Version != 0 {
			t.Fatalf("the composition of no authored document is %+v", alone.Document)
		}
	})

	t.Run("an omission leaves out the policy it names and nothing else, with or without additions", func(t *testing.T) {
		doc := authoredDocument(pdp.RootOrganization)
		kept := notifyOn("authored.kept", composedSecond)
		kept.Root = pdp.RootOrganization
		doc.Policies = append(doc.Policies, kept)
		doc.Attributes = append(doc.Attributes, boolSchema(composedSecond))
		two := authoredSource(t, doc)
		for _, adds := range [][]pdp.Policy{nil, additions[:1]} {
			got, err := comp.Compose(two, []string{"authored.notify"}, adds, nil)
			if err != nil {
				t.Fatal(err)
			}
			if want := append([]pdp.Policy{kept}, adds...); !reflect.DeepEqual(got.Document.Policies, want) {
				t.Fatalf("omitting authored.notify with %d additions composed %+v; want the other authored policy, then the additions", len(adds), got.Document.Policies)
			}
			if !reflect.DeepEqual(got.Document.Attributes, doc.Attributes) {
				t.Fatalf("the composition declares %+v; an omission leaves the authored declarations as published", got.Document.Attributes)
			}
		}
		if len(doc.Policies) != 2 {
			t.Fatalf("omitting edited the authored document: %d policies", len(doc.Policies))
		}
	})
}

func TestTheCompositionAuthorityRefusesByName(t *testing.T) {
	comp := newCompositionAuthority(t)
	additions := []pdp.Policy{notifyOn("organization_override:first", composedProbe)}
	schemas := []pdp.AttributeSchema{boolSchema(composedProbe)}
	if _, err := comp.Compose(authoredSource(t, authoredDocument(pdp.RootOrganization)), nil, additions, schemas); err != nil {
		t.Fatalf("CONTROL: the unmutated composition was refused, so the refusals below prove nothing: %v", err)
	}

	for _, c := range []struct {
		name    string
		code    string
		compose func(t *testing.T) error
	}{
		{"a bundle the supplied key did not sign", authoring.CodeComposedContentUnverified, func(t *testing.T) error {
			a := authoredSource(t, authoredDocument(pdp.RootOrganization))
			other, _, err := ed25519.GenerateKey(nil)
			if err != nil {
				t.Fatal(err)
			}
			a.Key = other
			_, err = comp.Compose(a, nil, additions, schemas)
			return err
		}},
		{"a document edited after its bundle was signed", authoring.CodeComposedContentUnverified, func(t *testing.T) error {
			a := authoredSource(t, authoredDocument(pdp.RootOrganization))
			edited := *a.Document
			edited.Policies = append([]pdp.Policy(nil), a.Document.Policies...)
			edited.Policies[0].Description = "edited after signing"
			a.Document = &edited
			_, err := comp.Compose(a, nil, additions, schemas)
			return err
		}},
		{"a document and bundle on the system root", authoring.CodeComposedContentUnverified, func(t *testing.T) error {
			_, err := comp.Compose(authoredSource(t, authoredDocument(pdp.RootSystem)), nil, additions, schemas)
			return err
		}},
		{"an addition that takes an authored policy's id", authoring.CodeComposedPolicyIDTaken, func(t *testing.T) error {
			_, err := comp.Compose(authoredSource(t, authoredDocument(pdp.RootOrganization)), nil, []pdp.Policy{notifyOn("authored.notify", composedProbe)}, schemas)
			return err
		}},
		{"an addition that takes an omitted policy's id", authoring.CodeComposedPolicyIDTaken, func(t *testing.T) error {
			_, err := comp.Compose(authoredSource(t, authoredDocument(pdp.RootOrganization)), []string{"authored.notify"},
				[]pdp.Policy{notifyOn("authored.notify", composedProbe)}, schemas)
			return err
		}},
		{"an omission the authored document does not carry", authoring.CodeComposedOmissionNotCarried, func(t *testing.T) error {
			_, err := comp.Compose(authoredSource(t, authoredDocument(pdp.RootOrganization)), []string{"not.carried"}, additions, schemas)
			return err
		}},
		{"an omission with no authored document", authoring.CodeComposedOmissionNotCarried, func(t *testing.T) error {
			_, err := comp.Compose(nil, []string{"authored.notify"}, additions, schemas)
			return err
		}},
		{"two additions with one id", authoring.CodeComposedPolicyIDTaken, func(t *testing.T) error {
			_, err := comp.Compose(nil, nil, append(additions, additions...), schemas)
			return err
		}},
		{"a schema that redescribes an authored attribute", authoring.CodeComposedAttributeConflict, func(t *testing.T) error {
			_, err := comp.Compose(authoredSource(t, authoredDocument(pdp.RootOrganization)), nil, additions,
				[]pdp.AttributeSchema{{Path: composedProbe, Type: pdp.TypeString}})
			return err
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			err := c.compose(t)
			var refused *authoring.ErrCompositionRefused
			if !errors.As(err, &refused) || refused.Code() != c.code {
				t.Fatalf("got %v; want a composition refused %s", err, c.code)
			}
		})
	}

	t.Run("no additions and no omissions", func(t *testing.T) {
		if _, err := comp.Compose(authoredSource(t, authoredDocument(pdp.RootOrganization)), nil, nil, nil); err == nil || !strings.Contains(err.Error(), "no additions and no omissions") {
			t.Fatalf("a composition with nothing to add or leave out was signed (err=%v)", err)
		}
	})
	t.Run("a key that is not an ed25519 private key", func(t *testing.T) {
		if _, err := authoring.NewCompositionAuthority(make(ed25519.PrivateKey, 10)); err == nil {
			t.Fatal("a 10-byte key became a composition authority")
		}
	})
}
