package contract

import (
	"strings"
	"testing"
	"time"
)

// TestMergedAuditKeepsEverySource pins source attribution across the THIRD of
// the three obligation merge points.
//
// dedupeObligations and chooseLeastDisclosing both join the sources of a
// merged instruction; composeAuditNotify used to keep a single source, chosen
// by delivery strength and otherwise by input order - so which policy a merged
// audit was attributed to was arbitrary, and a consumer comparing obligations
// per source policy (the ADR-065 shadow harness does exactly that) read every
// other demanding policy's control as missing.
func TestMergedAuditKeepsEverySource(t *testing.T) {
	obl := func(src string) Obligation {
		return Obligation{
			Type:          ObImmutableAudit,
			Params:        map[string]string{"category": "admin-access", "severity": "high"},
			SourcePolicy:  src,
			SchemaVersion: 1,
		}
	}
	out := ComposeObligations(ComposeInput{
		Obligations:    []Obligation{obl("policy:a"), obl("policy:b")},
		Leaves:         []string{"response.content"},
		ApprovalExpiry: time.Now().Add(time.Hour),
	})
	if out.Denied {
		t.Fatalf("two identical audits denied: %s", out.Detail)
	}
	if len(out.Obligations) != 1 {
		t.Fatalf("two identical audit instructions composed to %d obligation(s), want 1 merged", len(out.Obligations))
	}
	src := out.Obligations[0].SourcePolicy
	if !strings.Contains(src, "policy:a") || !strings.Contains(src, "policy:b") {
		t.Fatalf("the merged audit names sources %q; a demanding policy fell off the attribution", src)
	}

	// The delivery-strength winner keeps its OWN parameters and still carries
	// both sources - merging must never let attribution decide which
	// instruction wins.
	strong := obl("policy:strong")
	strong.Params = map[string]string{"category": "admin-access", "severity": "high", "delivery": string(DeliveryDurable)}
	weak := obl("policy:weak")
	weak.Params = map[string]string{"category": "admin-access", "severity": "high", "delivery": string(DeliveryBestEffort)}
	out2 := ComposeObligations(ComposeInput{
		Obligations:    []Obligation{weak, strong},
		Leaves:         []string{"response.content"},
		ApprovalExpiry: time.Now().Add(time.Hour),
	})
	if out2.Denied || len(out2.Obligations) != 1 {
		t.Fatalf("delivery merge produced denied=%t n=%d", out2.Denied, len(out2.Obligations))
	}
	got := out2.Obligations[0]
	if got.Params["delivery"] != string(DeliveryDurable) {
		t.Fatalf("the merged audit carries delivery %q, want durable; the stronger guarantee must win", got.Params["delivery"])
	}
	if !strings.Contains(got.SourcePolicy, "policy:strong") || !strings.Contains(got.SourcePolicy, "policy:weak") {
		t.Fatalf("the delivery-merged audit names sources %q, want both", got.SourcePolicy)
	}

	// ABSENT is not UNDECLARED. An audit that carries no delivery parameter
	// at all is a state Validate admits - it demands no guarantee, which is
	// the weakest declared rank - and it must merge with a declared one
	// rather than deny or be dropped. Conflating the two states made two
	// identical no-delivery audits (the most common shape the legacy
	// compiler emits) undroppable-by-merge: mandatory pairs denied the
	// request, advisory pairs vanished as non-composing.
	absent := obl("policy:absent")
	out3 := ComposeObligations(ComposeInput{
		Obligations:    []Obligation{absent, strong},
		Leaves:         []string{"response.content"},
		ApprovalExpiry: time.Now().Add(time.Hour),
	})
	if out3.Denied || len(out3.Obligations) != 1 {
		t.Fatalf("an absent-delivery audit merging with a durable one produced denied=%t n=%d; absence is a legitimate authored state, not an undeclared enum value",
			out3.Denied, len(out3.Obligations))
	}
	if out3.Obligations[0].Params["delivery"] != string(DeliveryDurable) {
		t.Fatalf("the merge kept delivery %q, want durable to outrank the absent guarantee", out3.Obligations[0].Params["delivery"])
	}
}
