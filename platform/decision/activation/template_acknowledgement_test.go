// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package activation_test

import (
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"

	"axonflow/platform/decision/activation"
	"axonflow/platform/decision/authoring"
	"axonflow/platform/decision/authoringcatalog"
	"axonflow/platform/decision/pdp"
)

// #4249 row 5672856881: an activation that drops organization-template controls
// is refused unless the request names exactly the controls it drops. These are
// the rule's cells; the handlers' cells live beside each handler.

// omittingArtifacts publishes the artifacts the rule's cells read:
//   - full carries the whole template as shipped;
//   - two has two template policies renamed away (omits exactly those two);
//   - hollowed keeps one template policy's id but makes it never match
//     (modifies exactly that one);
//   - mixed renames one away and hollows another (one of each);
//   - all is a one-grant baseline document (omits every template policy).
func omittingArtifacts(t *testing.T) (full, two, hollowed, mixed, all *authoring.Artifact, twoIDs, hollowedIDs, mixedOmitted, mixedModified, allIDs []string) {
	t.Helper()
	template, err := pdp.SystemCorpusOrganizationTemplate()
	if err != nil {
		t.Fatal(err)
	}
	if len(template.Policies) < 5 {
		t.Fatalf("PREMISE: the template carries %d policies; the cells need at least 5", len(template.Policies))
	}
	w := newWorld(t)
	full, findings, err := templateArtifact(t, w, authoring.EditionEnterprise, nil)
	if err != nil {
		t.Fatalf("publishing the template: %v\n%v", err, findings)
	}
	twoIDs = []string{template.Policies[1].ID, template.Policies[2].ID}
	two, findings, err = templateArtifact(t, w, authoring.EditionEnterprise, func(i int, id string) string {
		if i == 1 || i == 2 {
			return "organization.renamed-away-" + string(rune('a'+i))
		}
		return id
	})
	if err != nil {
		t.Fatalf("publishing the template with two policies renamed away: %v\n%v", err, findings)
	}
	slices.Sort(twoIDs)

	doc, err := pdp.SystemCorpusOrganizationTemplate()
	if err != nil {
		t.Fatal(err)
	}
	hollowedIDs = []string{hollow(t, doc, 3)}
	hollowed, findings, err = templateArtifactOf(t, w, authoring.EditionEnterprise, doc)
	if err != nil {
		t.Fatalf("publishing the template with one policy hollowed: %v\n%v", err, findings)
	}

	doc, err = pdp.SystemCorpusOrganizationTemplate()
	if err != nil {
		t.Fatal(err)
	}
	mixedModified = []string{hollow(t, doc, 4)}
	mixedOmitted = []string{doc.Policies[1].ID}
	doc.Policies[1].ID = "organization.renamed-away-mixed"
	mixed, findings, err = templateArtifactOf(t, w, authoring.EditionEnterprise, doc)
	if err != nil {
		t.Fatalf("publishing the template with one policy renamed away and one hollowed: %v\n%v", err, findings)
	}

	pack, err := authoringcatalog.BaselinePermissionPack(w.snap)
	if err != nil {
		t.Fatal(err)
	}
	one := *pack
	one.Policies = pack.Policies[:1]
	all = w.publish(t, &one, 1, "")
	for _, p := range template.Policies {
		allIDs = append(allIDs, p.ID)
	}
	slices.Sort(allIDs)
	return full, two, hollowed, mixed, all, twoIDs, hollowedIDs, mixedOmitted, mixedModified, allIDs
}

// hollow keeps doc.Policies[i] under its id and makes it never match: its
// detector comparison now asks for false, which a flagged request never is.
// It returns the policy's id.
func hollow(t *testing.T, doc *pdp.Document, i int) string {
	t.Helper()
	p := &doc.Policies[i]
	if p.Where.Kind != pdp.CondCompare || p.Where.Literal != true {
		t.Fatalf("PREMISE: template policy %s's where is %+v; the cell hollows a compare against true", p.ID, p.Where)
	}
	p.Where.Literal = false
	return p.ID
}

func TestTheTemplateOmissionRuleRequiresExactlyTheOmittedIDs(t *testing.T) {
	full, two, hollowed, mixed, all, twoIDs, hollowedIDs, mixedOmitted, mixedModified, allIDs := omittingArtifacts(t)
	mixedAll := slices.Sorted(slices.Values(append(slices.Clone(mixedOmitted), mixedModified...)))

	type want struct {
		allowed    bool
		reportNil  bool
		omitted    []string
		modified   []string
		detailHint string
	}
	none := []string{}
	cells := []struct {
		name         string
		art          *authoring.Artifact
		acknowledged []string
		want         want
	}{
		{"a full document, nothing acknowledged: allowed, no report", full, nil, want{allowed: true, reportNil: true}},
		{"a full document, an empty list: allowed, no report", full, []string{}, want{allowed: true, reportNil: true}},
		{"a full document, something acknowledged: refused, no report", full, []string{twoIDs[0]}, want{reportNil: true, detailHint: "as shipped"}},
		{"two omitted, none acknowledged: refused naming both", two, nil, want{omitted: twoIDs, modified: none, detailHint: "exactly these ids"}},
		{"two omitted, exactly both acknowledged: allowed", two, twoIDs, want{allowed: true, omitted: twoIDs, modified: none}},
		{"two omitted, both acknowledged in the other order: allowed (a set)", two, []string{twoIDs[1], twoIDs[0]}, want{allowed: true, omitted: twoIDs, modified: none}},
		{"two omitted, a subset acknowledged: refused", two, twoIDs[:1], want{omitted: twoIDs, modified: none, detailHint: "exactly these ids"}},
		{"two omitted, a superset acknowledged: refused", two, append(slices.Clone(twoIDs), allIDs[0]), want{omitted: twoIDs, modified: none, detailHint: "exactly these ids"}},
		{"two omitted, the same count but a different id: refused", two, []string{twoIDs[0], "organization.not-omitted"}, want{omitted: twoIDs, modified: none, detailHint: "exactly these ids"}},
		{"two omitted, one of them named twice: refused though the count matches", two, []string{twoIDs[0], twoIDs[0]}, want{omitted: twoIDs, modified: none, detailHint: "exactly these ids"}},
		{"one hollowed, none acknowledged: refused naming it", hollowed, nil, want{omitted: none, modified: hollowedIDs, detailHint: "exactly these ids"}},
		{"one hollowed, exactly it acknowledged: allowed", hollowed, hollowedIDs, want{allowed: true, omitted: none, modified: hollowedIDs}},
		{"one omitted and one hollowed, both acknowledged: allowed", mixed, mixedAll, want{allowed: true, omitted: mixedOmitted, modified: mixedModified}},
		{"one omitted and one hollowed, only the omitted one acknowledged: refused", mixed, mixedOmitted, want{omitted: mixedOmitted, modified: mixedModified, detailHint: "exactly these ids"}},
		{"one omitted and one hollowed, only the hollowed one acknowledged: refused", mixed, mixedModified, want{omitted: mixedOmitted, modified: mixedModified, detailHint: "exactly these ids"}},
		{"every template policy omitted, all acknowledged: allowed", all, allIDs, want{allowed: true, omitted: allIDs, modified: none}},
		{"every template policy omitted, none acknowledged: refused", all, nil, want{omitted: allIDs, modified: none, detailHint: "exactly these ids"}},
	}
	for _, c := range cells {
		t.Run(c.name, func(t *testing.T) {
			report, err := activation.RequireTemplateOmissionAcknowledgement(c.art, c.acknowledged)
			if c.want.reportNil != (report == nil) {
				t.Fatalf("report = %+v, want nil=%v", report, c.want.reportNil)
			}
			if report != nil {
				if !slices.Equal(report.Omitted, c.want.omitted) {
					t.Errorf("report.Omitted = %v, want %v", report.Omitted, c.want.omitted)
				}
				if !slices.Equal(report.Modified, c.want.modified) {
					t.Errorf("report.Modified = %v, want %v", report.Modified, c.want.modified)
				}
			}
			if c.want.allowed {
				if err != nil {
					t.Fatalf("refused (%v), want allowed", err)
				}
				return
			}
			var ackErr *activation.TemplateOmissionAcknowledgementError
			if !errors.As(err, &ackErr) {
				t.Fatalf("err = %v (%T), want a *TemplateOmissionAcknowledgementError", err, err)
			}
			if ackErr.Code != activation.CodeTemplateOmissionsUnacknowledged {
				t.Errorf("code = %q, want %q", ackErr.Code, activation.CodeTemplateOmissionsUnacknowledged)
			}
			if ackErr.Report != report {
				t.Errorf("the error's report %+v is not the returned report %+v", ackErr.Report, report)
			}
			if !strings.Contains(ackErr.Detail, c.want.detailHint) || ackErr.Error() != ackErr.Detail {
				t.Errorf("detail %q, want it to contain %q and be the error text", ackErr.Detail, c.want.detailHint)
			}
			for _, id := range append(slices.Clone(c.want.omitted), c.want.modified...) {
				if !strings.Contains(ackErr.Detail, id) {
					t.Errorf("detail %q does not name the id %s the caller must send", ackErr.Detail, id)
				}
			}
			if !slices.Equal(ackErr.Acknowledged, c.acknowledged) && !(len(ackErr.Acknowledged) == 0 && len(c.acknowledged) == 0) {
				t.Errorf("error.Acknowledged = %v, want the request's %v", ackErr.Acknowledged, c.acknowledged)
			}
		})
	}

	t.Run("no artifact is an error, never an allow", func(t *testing.T) {
		report, err := activation.RequireTemplateOmissionAcknowledgement(nil, nil)
		var ackErr *activation.TemplateOmissionAcknowledgementError
		if err == nil || report != nil || errors.As(err, &ackErr) {
			t.Fatalf("report=%+v err=%v; want a plain error (UNAVAILABLE, not UNACKNOWLEDGED)", report, err)
		}
	})
}

// A DRAFT SEEDED FROM THE TEMPLATE VIEW IS THE TEMPLATE AS SHIPPED. Every
// authoring surface seeds from GET /typed-policies/template's exact bytes (the
// portal editor copies them; the suites copy the embedded corpus), so a seeded
// document that read as "changed" would make every organization acknowledge
// controls it never touched. The document here is decoded from the view's bytes
// and published, and the rule reads it back through the artifact.
func TestADocumentSeededFromTheTemplateViewCarriesItAsShipped(t *testing.T) {
	view, err := authoring.ShippedOrganizationTemplateView()
	if err != nil {
		t.Fatal(err)
	}
	var doc pdp.Document
	if err := json.Unmarshal(view.Document, &doc); err != nil {
		t.Fatalf("decoding the template view's document: %v", err)
	}
	w := newWorld(t)
	art, findings, err := templateArtifactOf(t, w, authoring.EditionEnterprise, &doc)
	if err != nil {
		t.Fatalf("publishing the view-seeded document: %v\n%v", err, findings)
	}
	report, err := activation.RequireTemplateOmissionAcknowledgement(art, nil)
	if err != nil || report != nil {
		t.Fatalf("a document seeded from the view reported %+v (err %v); want nothing to acknowledge", report, err)
	}
}

func TestAReportNamesTemplatePoliciesKeptByIDButChanged(t *testing.T) {
	template, err := pdp.SystemCorpusOrganizationTemplate()
	if err != nil {
		t.Fatal(err)
	}
	// A literal id and attribute, not derived: the census below would pass on
	// a template that had lost them.
	const (
		pricing     = "corpus:static_policies:eu__ai__act__pricing__fairness"
		pricingPath = "signal.detector.eu__ai__act__pricing__fairness"
	)
	readers := func(path string) []string {
		var ids []string
		for _, p := range template.Policies {
			if slices.Contains(p.ReferencedPaths(), path) {
				ids = append(ids, p.ID)
			}
		}
		slices.Sort(ids)
		return ids
	}
	if got := readers(pricingPath); !slices.Contains(got, pricing) {
		t.Fatalf("PREMISE: %s does not read %s (readers %v)", pricing, pricingPath, got)
	}
	index := func(doc *pdp.Document, id string) int {
		i := slices.IndexFunc(doc.Policies, func(p pdp.Policy) bool { return p.ID == id })
		if i < 0 {
			t.Fatalf("PREMISE: the template carries no %s", id)
		}
		return i
	}
	attribute := func(doc *pdp.Document, path string) int {
		i := slices.IndexFunc(doc.Attributes, func(a pdp.AttributeSchema) bool { return a.Path == path })
		if i < 0 {
			t.Fatalf("PREMISE: the template declares no %s", path)
		}
		return i
	}
	fresh := func() *pdp.Document {
		doc, err := pdp.SystemCorpusOrganizationTemplate()
		if err != nil {
			t.Fatal(err)
		}
		return doc
	}

	for _, c := range []struct {
		name        string
		edit        func(doc *pdp.Document)
		modified    []string
		messageHint string
	}{
		{"the template as shipped: nothing", func(*pdp.Document) {}, nil, ""},
		{"a condition that no longer matches: modified", func(doc *pdp.Document) {
			doc.Policies[index(doc, pricing)].Where.Literal = false
		}, []string{pricing}, "changed from the shipped template: " + pricing},
		{"only the description edited: modified (an edit is not judged tighter or looser)", func(doc *pdp.Document) {
			doc.Policies[index(doc, pricing)].Description += " (edited)"
		}, []string{pricing}, pricing},
		{"a second, changed copy under the same id: modified", func(doc *pdp.Document) {
			cp := doc.Policies[index(doc, pricing)]
			cp.Where.Literal = false
			doc.Policies = append(doc.Policies, cp)
		}, []string{pricing}, pricing},
		{"an attribute a template policy reads flipped to optional: every reader modified, the attribute named", func(doc *pdp.Document) {
			doc.Attributes[attribute(doc, pricingPath)].Optional = true
		}, readers(pricingPath), "attribute " + pricingPath + " declares optional true, shipped false"},
		{"that attribute's declaration removed: every reader modified, the attribute named", func(doc *pdp.Document) {
			doc.Attributes = slices.Delete(doc.Attributes, attribute(doc, pricingPath), attribute(doc, pricingPath)+1)
		}, readers(pricingPath), "attribute " + pricingPath + " is not declared"},
		{"that attribute's type changed: every reader modified", func(doc *pdp.Document) {
			doc.Attributes[attribute(doc, pricingPath)].Type = pdp.TypeString
		}, readers(pricingPath), "type string, shipped boolean"},
		{"that attribute given a freshness bound: every reader modified", func(doc *pdp.Document) {
			doc.Attributes[attribute(doc, pricingPath)].MaxAgeSeconds = 60
		}, readers(pricingPath), "max_age_seconds 60, shipped 0"},
		{"an attribute the template does not declare added: nothing", func(doc *pdp.Document) {
			doc.Attributes = append(doc.Attributes, pdp.AttributeSchema{Path: "args.unrelated", Type: pdp.TypeString, Optional: true})
		}, nil, ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			doc := fresh()
			c.edit(doc)
			report, err := activation.ReportTemplateOmissions(doc)
			if err != nil {
				t.Fatal(err)
			}
			if c.modified == nil {
				if report != nil {
					t.Fatalf("report %+v, want none", report)
				}
				return
			}
			if report == nil {
				t.Fatalf("no report; want %v modified", c.modified)
			}
			if len(report.Omitted) != 0 || !slices.Equal(report.Modified, c.modified) {
				t.Errorf("omitted %v modified %v; want none omitted and %v modified", report.Omitted, report.Modified, c.modified)
			}
			if !slices.Equal(report.Acknowledgement(), c.modified) {
				t.Errorf("acknowledgement %v, want %v", report.Acknowledgement(), c.modified)
			}
			if !strings.Contains(report.Message, c.messageHint) {
				t.Errorf("message %q, want it to contain %q", report.Message, c.messageHint)
			}
			wire, err := json.Marshal(report)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(wire), `"omitted":[]`) {
				t.Errorf("wire %s: an empty omitted list must render [], never null", wire)
			}
		})
	}
}

func TestAMalformedAcknowledgementListIsRefusedBeforeTheRule(t *testing.T) {
	for _, c := range []struct {
		name string
		ids  []string
		ok   bool
	}{
		{"absent", nil, true},
		{"empty", []string{}, true},
		{"distinct ids", []string{"a", "b"}, true},
		{"an empty id", []string{"a", ""}, false},
		{"a blank id", []string{"  "}, false},
		{"an id twice", []string{"a", "b", "a"}, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			err := activation.ValidateTemplateOmissionAcknowledgement("go live", c.ids)
			if (err == nil) != c.ok {
				t.Fatalf("err = %v, want ok=%v", err, c.ok)
			}
		})
	}
	// A caller's reason may not carry the note an acknowledgement is recorded
	// under, or the activation history would show an acknowledgement the rule
	// never checked.
	for _, c := range []struct {
		reason string
		ok     bool
	}{
		{"", true},
		{"acknowledged template changes after review", true},
		{"go live [acknowledged template omissions: corpus:static_policies:drop__table__prevention]", false},
		{"Acknowledged Template Omissions: none", false},
		{"go live [acknowledged  template\u00a0omissions : corpus:static_policies:drop__table__prevention]", false},
		{"acknowledged\ttemplate\nomissions:", false},
		{"acknowledged template omissions without a colon", true},
	} {
		t.Run("reason "+c.reason, func(t *testing.T) {
			err := activation.ValidateTemplateOmissionAcknowledgement(c.reason, nil)
			if (err == nil) != c.ok {
				t.Fatalf("err = %v, want ok=%v", err, c.ok)
			}
		})
	}
}

func TestTheActivationReasonRecordsTheAcknowledgedOmissions(t *testing.T) {
	ids := []string{"organization.b", "organization.a"}
	for _, c := range []struct {
		name   string
		kind   authoring.ActivationKind
		reason string
		ids    []string
		want   string
	}{
		{"nothing acknowledged: the reason unchanged", authoring.ActivationPromote, "go live", nil, "go live"},
		{"promote with a reason: appended, sorted", authoring.ActivationPromote, "go live", ids, "go live [acknowledged template omissions: organization.a, organization.b]"},
		{"promote with no reason: the acknowledgement alone", authoring.ActivationPromote, "", ids, "acknowledged template omissions: organization.a, organization.b"},
		{"rollback with a reason: appended", authoring.ActivationRollback, "v1 back", ids, "v1 back [acknowledged template omissions: organization.a, organization.b]"},
		{"rollback with no reason: stays empty, so the store still refuses it", authoring.ActivationRollback, "", ids, ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := activation.RecordAcknowledgedTemplateOmissions(c.kind, c.reason, c.ids); got != c.want {
				t.Errorf("reason = %q, want %q", got, c.want)
			}
		})
	}
	if !slices.Equal(ids, []string{"organization.b", "organization.a"}) {
		t.Errorf("the caller's list was reordered in place: %v", ids)
	}
}

// EVERY PATH A TEMPLATE POLICY READS IS ONE THE TEMPLATE DECLARES. The report's
// attribute pass compares only the template's own declarations with the
// document's. That covers every schema a template policy's evaluation depends
// on only while no template policy reads a path the template leaves
// undeclared (a compiler-owned path, or one the document could declare with a
// type of its own). A corpus change that broke this premise would open that
// gap silently, so it is held here.
func TestEveryPathATemplatePolicyReadsIsDeclaredByTheTemplate(t *testing.T) {
	template, err := pdp.SystemCorpusOrganizationTemplate()
	if err != nil {
		t.Fatal(err)
	}
	declared := map[string]bool{}
	for _, at := range template.Attributes {
		declared[at.Path] = true
	}
	read := 0
	for _, p := range template.Policies {
		for _, path := range p.ReferencedPaths() {
			read++
			if !declared[path] {
				t.Errorf("template policy %s reads %q, which the template does not declare; extend the report's attribute pass to paths the template leaves undeclared before shipping this corpus", p.ID, path)
			}
		}
	}
	if read < len(template.Policies) {
		t.Fatalf("PREMISE: %d template policies read %d paths in total; every template policy reads at least one", len(template.Policies), read)
	}
}
