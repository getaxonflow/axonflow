package legacycompile

import (
	"os"
	"strings"
	"testing"
)

// TestCaptureDocDoesNotRestateTheLimitations pins a documentation invariant
// that has already failed once.
//
// CAPTURE.md used to enumerate shadow.ModelLimitations() and say "today it
// names three". The function grew to twelve in a single commit and the
// document was left describing three - so the shipped, community-syncing
// design note gave a materially more reassuring picture than the code, on the
// one list that is the reader's only protection against over-trusting this
// harness.
//
// A prose copy of a list in another package cannot be kept correct by
// intention, so the document is required not to carry one. This test is the
// mechanism that makes "read the function" stick.
func TestCaptureDocDoesNotRestateTheLimitations(t *testing.T) {
	b, err := os.ReadFile("CAPTURE.md")
	if err != nil {
		t.Fatalf("reading CAPTURE.md: %v", err)
	}
	doc := string(b)

	// A count claim about the list is the specific shape that rotted.
	for _, phrase := range []string{
		"it names three", "names three items", "Today it names",
		"it names four", "it names five", "it names twelve",
	} {
		if strings.Contains(doc, phrase) {
			t.Fatalf("CAPTURE.md contains %q. It must not state how many model limitations there are: "+
				"the count lives in shadow.ModelLimitations() and a prose copy of it goes stale silently, "+
				"which is exactly how the document came to understate the list by nine items.", phrase)
		}
	}
	// And it must still POINT at the function, or a reader has nowhere to go.
	if !strings.Contains(doc, "ModelLimitations") {
		t.Fatal("CAPTURE.md no longer mentions shadow.ModelLimitations(); a reader has no way to find what the harness does not reproduce")
	}
	// The one item quoted verbatim is quoted because a reader deciding whether
	// to trust a green gate needs it before they reach the code. Losing it
	// would be a real loss, so it is pinned too.
	if !strings.Contains(doc, "DEPLOYMENT_MODE=community") {
		t.Fatal("CAPTURE.md no longer names the community-mode require_approval limitation, which is the one that is " +
			"wrong in the fail-open direction for an entire deployment mode")
	}
}
