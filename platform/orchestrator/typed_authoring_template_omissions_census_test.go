// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// NO SET COMPARISON OUTSIDE THE RULE (#4249 row 5672856881). The acknowledged
// ids are compared to the omitted ids in exactly one place,
// activation.RequireTemplateOmissionAcknowledgement. The three activation paths
// (this route's activate, the portal's promote and rollback) may only VALIDATE
// the list, hand it to the rule, and RECORD it. A handler that read the list for
// anything else - a length check, a loop, a membership test against the report -
// would be a second comparison that the rule's cells do not cover, so every line
// of the two handler files that touches the request's list must be one of those
// three calls, the struct field that decodes it, or a comment.
func TestNoHandlerComparesTheAcknowledgementOutsideTheRule(t *testing.T) {
	allowed := regexp.MustCompile(`activation\.(ValidateTemplateOmissionAcknowledgement|RequireTemplateOmissionAcknowledgement|RecordAcknowledgedTemplateOmissions)\(|refuseUnacknowledgedTemplateOmissions\(|AcknowledgeTemplateOmissions \[\]string ` + "`json:\"acknowledge_template_omissions,omitempty\"`")
	// A second comparison has to read the request's list, so the census follows
	// the list; the publish handler's own count of report.Omitted is not an
	// activation path and reads no list.
	touches := regexp.MustCompile(`AcknowledgeTemplateOmissions|acknowledged\b`)
	files := []string{"typed_authoring_route.go"}
	// The portal's handler is Enterprise code, which the community mirror does
	// not carry (sync-community-repo.yml excludes ee/). There this census reads
	// the orchestrator's handler alone.
	portal := filepath.Join("..", "..", "ee", "platform", "customer-portal", "api", "typed_authoring.go")
	if _, err := os.Stat(filepath.Join("..", "..", "ee")); err == nil {
		files = append(files, portal)
	} else if !os.IsNotExist(err) {
		t.Fatalf("stat ee/: %v", err)
	} else {
		t.Logf("ee/ is absent (a community tree): reading %s only", files[0])
	}
	seen := 0
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		for i, line := range strings.Split(string(raw), "\n") {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "//") || !touches.MatchString(line) {
				continue
			}
			seen++
			if allowed.MatchString(line) {
				continue
			}
			t.Errorf("%s:%d reads the acknowledgement or the omitted ids outside the rule: %s", f, i+1, trimmed)
		}
	}
	// ANTI-VACUITY: each handler validates, runs the rule and records, so the
	// walk must have seen those lines in every file it read.
	// Six per file: the struct field, the validation, the refusal call, the
	// recording, the refusal helper's signature and its call to the rule.
	if floor := 6 * len(files); seen < floor {
		t.Fatalf("the census saw %d lines touching the acknowledgement across %v, want at least %d; it is reading the wrong files", seen, files, floor)
	}
}
