// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package activation

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"axonflow/platform/decision/authoring"
)

// AN ACTIVATION THAT DROPS TEMPLATE CONTROLS NAMES THEM FIRST (#4249 row
// 5672856881).
//
// A published organization document REPLACES the shipped organization template
// (PRD v11 §1.5; the template's policies enter an activation only when the
// organization has authored nothing), so activating a document that omits
// template policies stops those controls deciding for the organization. The
// report of what it omits used to travel only as a field of a 200, and a caller
// reading the status code alone weakened its own posture without knowing. A
// template policy kept under its id but changed - its body, or an attribute
// schema it reads - stops deciding as shipped just as surely, so the report
// names those too (TemplateOmissionReport.Modified) and the acknowledgement
// covers both.
//
// Publish is not the moment of effect, activation is, so the rule runs on every
// path that makes a document active - the orchestrator's activate, the portal's
// promote and the portal's rollback - and never at publish. Withdraw restores
// the template and is exempt.
//
// ONE RULE, EVERY PATH. Each handler authorizes, validates its body and the
// digest (ValidateTemplateOmissionAcknowledgement is part of that), reads the
// artifact, and calls RequireTemplateOmissionAcknowledgement BEFORE
// Promote/Rollback. No handler compares the lists itself. The rule cannot live
// inside authoring.API.Promote: this package imports authoring.

// CodeTemplateOmissionsUnacknowledged refuses an activation whose document
// omits or changes organization-template policies the request did not name
// exactly.
const CodeTemplateOmissionsUnacknowledged = "TEMPLATE_OMISSIONS_UNACKNOWLEDGED"

// CodeTemplateOmissionsUnavailable refuses an activation whose omissions could
// not be computed from an artifact the store returned (its document did not
// decode, or the template did not load); a store that could not be read is
// refused by the handlers' store refusal instead. It is distinct
// from CodeTemplateOmissionsUnacknowledged so a client can tell "retry" from
// "send this list": an activation is never allowed through on an unknown report.
const CodeTemplateOmissionsUnavailable = "TEMPLATE_OMISSIONS_UNAVAILABLE"

// TemplateOmissionAcknowledgementError is the rule's refusal. Report is the
// document's omissions and changes (nil when the document carries the template as
// shipped and the request named something anyway); Code is
// CodeTemplateOmissionsUnacknowledged.
type TemplateOmissionAcknowledgementError struct {
	Code         string
	Report       *TemplateOmissionReport
	Acknowledged []string
	Detail       string
}

func (e *TemplateOmissionAcknowledgementError) Error() string { return e.Detail }

// acknowledgementNote is the text RecordAcknowledgedTemplateOmissions writes
// into an activation's reason. A caller's own reason may not carry it: the
// recorded reason is what audit reads, and a reason that already said
// "acknowledged template omissions: ..." would read as an acknowledgement the
// rule never checked.
const acknowledgementNote = "acknowledged template omissions:"

// ValidateTemplateOmissionAcknowledgement refuses a malformed activation
// request: an acknowledgement list with an empty id or an id named twice, or a
// reason that already carries the note an acknowledgement is recorded under.
// Both handlers call it while they validate the request body, so the rule's
// equality is over a SET of non-empty ids and a malformed request is a 400,
// never a 409.
func ValidateTemplateOmissionAcknowledgement(reason string, acknowledged []string) error {
	if strings.Contains(normalizedNoteText(reason), acknowledgementNote) {
		return fmt.Errorf("reason may not contain %q: the platform records an acknowledgement of template omissions under that text, "+
			"so send the ids in acknowledge_template_omissions instead", acknowledgementNote)
	}
	seen := make(map[string]bool, len(acknowledged))
	for i, id := range acknowledged {
		if strings.TrimSpace(id) == "" {
			return fmt.Errorf("acknowledge_template_omissions[%d] is empty; name each template policy id the activation drops or changes", i)
		}
		if seen[id] {
			return fmt.Errorf("acknowledge_template_omissions names %q twice; name each template policy id once", id)
		}
		seen[id] = true
	}
	return nil
}

// normalizedNoteText is reason as the note check reads it: lower case, every
// run of Unicode white space one ASCII space, and no space before a colon, so
// "Acknowledged  Template\u00a0Omissions :" reads as the note it imitates.
func normalizedNoteText(reason string) string {
	collapsed := strings.Join(strings.Fields(strings.ToLower(reason)), " ")
	return strings.ReplaceAll(collapsed, " :", ":")
}

// RequireTemplateOmissionAcknowledgement is the rule. It returns art's report
// (nil when the document carries every template policy as shipped) and a
// *TemplateOmissionAcknowledgementError unless acknowledged EQUALS the report's
// Acknowledgement - the omitted and the modified template policies - as a set:
//
//   - the document carries the template as shipped and nothing is
//     acknowledged: allowed;
//   - the document omits or changes template policies and the acknowledgement
//     names exactly those: allowed;
//   - fewer ids (a subset, or none): refused, an unacknowledged drop or change;
//   - more ids (a superset): refused. The template is a build constant, so a
//     superset arises when the binary changed between publish and activation
//     and the caller acknowledged another build's template; the refusal says
//     exactly which list to send;
//   - a list naming an id twice: refused, whatever its length, so the equality
//     holds for a caller that skipped ValidateTemplateOmissionAcknowledgement;
//   - a non-empty acknowledgement for a document that carries the template as
//     shipped: refused, as a self-approval reason without self-approval is.
//
// The artifact is immutable by digest, so the report computed here on the
// loaded artifact is the report of exactly what Promote/Rollback activates.
// A report that cannot be computed is returned as an error that is NOT a
// *TemplateOmissionAcknowledgementError; callers refuse it with
// CodeTemplateOmissionsUnavailable.
func RequireTemplateOmissionAcknowledgement(art *authoring.Artifact, acknowledged []string) (*TemplateOmissionReport, error) {
	if art == nil {
		return nil, errors.New("activation: no artifact to compute template omissions for")
	}
	report, err := ReportArtifactTemplateOmissions(art)
	if err != nil {
		return nil, err
	}
	if report == nil {
		if len(acknowledged) == 0 {
			return nil, nil
		}
		return nil, &TemplateOmissionAcknowledgementError{
			Code: CodeTemplateOmissionsUnacknowledged, Acknowledged: slices.Clone(acknowledged),
			Detail: "this document carries every organization-template policy as shipped, so acknowledge_template_omissions must be absent or empty",
		}
	}
	want := report.Acknowledgement()
	if equalIDSets(want, acknowledged) {
		return report, nil
	}
	return report, &TemplateOmissionAcknowledgementError{
		Code: CodeTemplateOmissionsUnacknowledged, Report: report, Acknowledged: slices.Clone(acknowledged),
		Detail: fmt.Sprintf("activating this document stops %d of the %d organization-template policies deciding as shipped for the organization "+
			"(%d omitted, %d changed); send acknowledge_template_omissions with exactly these ids to accept that: %s",
			len(want), report.Of, len(report.Omitted), len(report.Modified), strings.Join(want, ", ")),
	}
}

// equalIDSets reports whether two id lists name the same set with no id named
// twice in either.
func equalIDSets(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	in := make(map[string]bool, len(a))
	for _, id := range a {
		if in[id] {
			return false
		}
		in[id] = true
	}
	matched := make(map[string]bool, len(b))
	for _, id := range b {
		if !in[id] || matched[id] {
			return false
		}
		matched[id] = true
	}
	return true
}

// RecordAcknowledgedTemplateOmissions is the reason an activation records when
// its request acknowledged template omissions, so the activation history
// answers "who accepted dropping which controls, and when" with no schema
// change (Activation.Reason). The acknowledged ids are appended, sorted, to the
// caller's reason.
//
// An EMPTY reason on a rollback stays empty: the store refuses a rollback
// without a reason, and a reason this function wrote must not satisfy that
// rule on the caller's behalf. A promotion needs no reason, so there the
// acknowledgement alone is recorded.
func RecordAcknowledgedTemplateOmissions(kind authoring.ActivationKind, reason string, acknowledged []string) string {
	if len(acknowledged) == 0 {
		return reason
	}
	if strings.TrimSpace(reason) == "" && kind != authoring.ActivationPromote {
		return reason
	}
	ids := slices.Clone(acknowledged)
	slices.Sort(ids)
	note := acknowledgementNote + " " + strings.Join(ids, ", ")
	if strings.TrimSpace(reason) == "" {
		return note
	}
	return reason + " [" + note + "]"
}
