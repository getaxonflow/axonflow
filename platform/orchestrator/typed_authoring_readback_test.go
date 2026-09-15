// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package orchestrator

import (
	"bytes"
	"context"
	"errors"
	"log"
	"strings"
	"testing"

	"axonflow/platform/decision/authoring"
	"axonflow/platform/decision/pdp"
)

// readBackFailingBackend is the in-process backend whose artifact read fails,
// as the durable store's does when postgres cannot be reached after a promote.
type readBackFailingBackend struct {
	authoring.Backend
	err error
}

func (b readBackFailingBackend) GetArtifact(context.Context, pdp.Root, string) (*authoring.Artifact, bool, error) {
	return nil, false, b.err
}

// A READ-BACK THAT FAILS KEEPS THE ACTIVATION, NOT THE STORE'S ERROR (#4271).
// /activate answered 200 with the store's raw error in
// template_omissions_unavailable. The activation has happened, so the answer
// stays 200; the reason is a fixed sentence and the store's error goes to the
// log.
func TestAnActivationReadBackThatFailsKeepsTheActivationNotTheStoreError(t *testing.T) {
	profile, err := authoring.ProfileFor(authoring.EditionCommunity)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name string
		b    authoring.Backend
		want string
	}{
		{"a store read that fails", readBackFailingBackend{Backend: authoring.NewMemoryBackend(), err: errors.New(plantedStoreError)}, "planted-4255-store-error"},
		{"an artifact the store does not hold", authoring.NewMemoryBackend(), "found=false"},
	} {
		t.Run(c.name, func(t *testing.T) {
			store, err := authoring.NewStoreWithBackend(authoring.StaticTrust(pdp.NewTrustStore()), profile, c.b)
			if err != nil {
				t.Fatal(err)
			}
			var logs bytes.Buffer
			prev := log.Writer()
			log.SetOutput(&logs)
			t.Cleanup(func() { log.SetOutput(prev) })
			body := map[string]any{"success": true}
			addActivatedTemplateOmissions(context.Background(), store, testOrg, "sha256:planted-4271-digest", body)
			msg, _ := body["template_omissions_unavailable"].(string)
			if !strings.Contains(msg, "the activation stands") {
				t.Fatalf("template_omissions_unavailable = %q; want the fixed sentence", msg)
			}
			for _, fragment := range []string{"pq:", "10.42.255.7", "5432", "connection to", "planted-4255-store-error"} {
				if strings.Contains(msg, fragment) {
					t.Fatalf("the success body carries %q from the store's own error: %q", fragment, msg)
				}
			}
			if body["success"] != true {
				t.Fatalf("the read-back changed the activation's success: %v", body)
			}
			if !strings.Contains(logs.String(), c.want) {
				t.Fatalf("the read-back's cause was not logged (want %q): %q", c.want, logs.String())
			}
		})
	}
}
