package pep

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// frozenWireFile is the pre-#3704 capture. See testdata/README.md for why the
// commit is in the name and why it is never regenerated to make a test pass.
const frozenWireFile = "testdata/frozen_wire_origin_main_0a4b97119.json"

type frozenCase struct {
	Name string `json:"name"`
	Body string `json:"body"`
}

// TestFrozenWireBytesAreUnchangedForEveryCallerThatExistedBefore.
//
// THE COMPATIBILITY CLAIM OF THIS WHOLE CHANGE, and the reason the fixture was
// captured from a worktree at origin/main rather than regenerated here.
//
// A regeneration gate proves CONSISTENCY, not FIDELITY: a fixture written by
// the new code would agree with the new code whatever the new code did, so it
// could not answer the only question that matters - do the bytes a shipped SDK,
// plugin or adapter puts on the wire today still produce the same request?
// These bytes were produced by the code that shipped.
//
// Four of the five captured shapes must be byte-identical. The fifth is the
// state that was unsendable FROM THE GO ENCODER before this change -
// `FulfillmentCapabilities` as an explicitly empty list - and it must be the
// ONLY one whose BYTES moved.
//
// Its MEANING did not move, and the distinction is the whole of a correction
// this change had to make: the server's decoder has always accepted those bytes
// from a non-Go caller, and they still read as a legacy caller. This fixture
// speaks for the encoder and cannot speak for the decoder;
// TestExplicitEmptyOnTheWireStillReadsAsALegacyCaller in platform/agent is what
// speaks for that, and it starts from literal bytes for exactly that reason.
func TestFrozenWireBytesAreUnchangedForEveryCallerThatExistedBefore(t *testing.T) {
	raw, err := os.ReadFile(frozenWireFile)
	if err != nil {
		t.Fatalf("reading the frozen capture: %v", err)
	}
	var frozen []frozenCase
	if err := json.Unmarshal(raw, &frozen); err != nil {
		t.Fatalf("parsing the frozen capture: %v", err)
	}
	if len(frozen) != 5 {
		t.Fatalf("the capture holds %d cases, expected 5; a shrunk fixture asserts less while still passing", len(frozen))
	}

	base := DecideRequest{
		Stage:          "llm",
		CallerIdentity: CallerIdentity{GatewayID: "gw-1", OrgID: "acme", TenantID: "acme"},
		Target:         Target{Type: "llm", Model: "gpt-4", Provider: "openai"},
		Query:          "hello",
	}
	withCaps := func(v *[]string) DecideRequest {
		out := base
		out.FulfillmentCapabilities = v
		return out
	}

	// The five shapes, in the capture's order, expressed in the NEW types.
	now := []DecideRequest{
		base,
		withCaps(AdvertiseCapabilities([]string{CapabilityRequestHeaderMutation})),
		withCaps(AdvertiseCapabilities([]string{CapabilityRequestBodyRedaction})),
		withCaps(nil),
		withCaps(AdvertiseCapabilities(nil)), // empty list: newly sendable FROM GO, same meaning
	}

	var moved []string
	for i, want := range frozen {
		got, err := json.Marshal(now[i])
		if err != nil {
			t.Fatalf("%s: %v", want.Name, err)
		}
		if string(got) != want.Body {
			moved = append(moved, want.Name)
			if i < 4 {
				t.Errorf("THE WIRE MOVED for a caller that existed before #3704.\n case: %s\n  was: %s\n  now: %s",
					want.Name, want.Body, got)
			}
		}
	}

	// The empty-list row MUST have moved. Without this assertion the test would
	// also pass against a build that changed nothing at all, which is the
	// vacuous reading of "the wire is unchanged".
	if len(moved) != 1 || moved[0] != frozen[4].Name {
		t.Fatalf("exactly one shape must have moved, and it must be the previously unsendable empty list; moved = %v", moved)
	}
}

// TestTheCaptureRecordsTheEncoderCollapseItself.
//
// On origin/main the empty list and the absent member encoded to the SAME
// bytes FROM THIS ENCODER. That is in the fixture as a measurement rather than
// as a sentence in a comment, so a reader can check it instead of trusting it.
//
// It is the ENCODER's collapse, not the wire's: a non-Go caller could always
// put `[]` on the wire, and the server has always read it as a legacy caller
// and still does. An earlier version of this comment called it "the #2958
// defect" without that qualifier, which is the claim-about-a-type-mistaken-for-
// a-claim-about-the-wire this change had to correct elsewhere.
func TestTheCaptureRecordsTheCollapseItself(t *testing.T) {
	raw, err := os.ReadFile(frozenWireFile)
	if err != nil {
		t.Fatal(err)
	}
	var frozen []frozenCase
	if err := json.Unmarshal(raw, &frozen); err != nil {
		t.Fatal(err)
	}
	if frozen[0].Body != frozen[4].Body {
		t.Fatalf("the capture no longer shows the collapse it was taken to record: the pre-change encoder produced\n  absent: %s\n   empty: %s\nIf the fixture was re-captured from a tree that already carries the fix, it proves nothing.",
			frozen[0].Body, frozen[4].Body)
	}

	// And the ENCODER's collapse is gone: three states, three encodings. Two of
	// them still MEAN the same thing to the server, deliberately.
	base := DecideRequest{Stage: "llm", Query: "hello"}
	absent := base
	empty := base
	empty.FulfillmentCapabilities = AdvertiseCapabilities(nil)
	one := base
	one.FulfillmentCapabilities = AdvertiseCapabilities([]string{CapabilityRequestBodyRedaction})

	seen := map[string]string{}
	for name, req := range map[string]DecideRequest{"absent": absent, "empty": empty, "one": one} {
		out, err := json.Marshal(req)
		if err != nil {
			t.Fatal(err)
		}
		if prev, dup := seen[string(out)]; dup {
			t.Errorf("%q and %q still encode identically: %s", name, prev, out)
		}
		seen[string(out)] = name
	}
	if len(seen) != 3 {
		t.Errorf("three wire states must produce three ENCODINGS, got %d (their READINGS are a separate question, and two of them are deliberately the same)", len(seen))
	}
}

// TestAdvertiseCapabilitiesCopiesAndIsNeverNil.
//
// It copies so a caller passing a package-level constant slice cannot have it
// mutated through the request, and it is non-nil for an empty input because an
// empty advertisement must be SENDABLE - which is the whole point.
func TestAdvertiseCapabilitiesCopiesAndIsNeverNil(t *testing.T) {
	src := []string{CapabilityRequestBodyRedaction}
	got := AdvertiseCapabilities(src)
	if got == nil || *got == nil {
		t.Fatal("AdvertiseCapabilities returned nil")
	}
	(*got)[0] = "mutated"
	if src[0] != CapabilityRequestBodyRedaction {
		t.Error("the caller's slice was mutated through the returned pointer")
	}
	empty := AdvertiseCapabilities(nil)
	if empty == nil || *empty == nil || len(*empty) != 0 {
		t.Fatalf("an empty advertisement must be a non-nil pointer to a non-nil empty slice, got %v", empty)
	}
	raw, err := json.Marshal(DecideRequest{FulfillmentCapabilities: empty})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"fulfillment_capabilities":[]`) {
		t.Errorf("an empty advertisement must reach the wire as [], got %s", raw)
	}
}
