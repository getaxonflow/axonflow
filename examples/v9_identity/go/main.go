// AxonFlow v9 Identity Forwarding Example - Go
//
// This example demonstrates the v9 identity model end-to-end (ADR-052 §5,
// ADR-053 §Step 2) by booting a self-contained pair of mock servers that
// implement the same auth-header-overwrite rule shipped in the real
// agent + orchestrator pair. Run it with:
//
//	go run ./examples/v9_identity/go
//
// The example exits with code 1 if any assertion fails.
package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
)

// authDerive simulates platform/agent/auth.go::Authenticate by mapping a
// Basic Auth client ID to a (orgID, clientID) tuple. In a real
// deployment this would come from a license validation + DB lookup.
func authDerive(clientID string) (orgID, derivedClientID string, ok bool) {
	known := map[string]struct{ org, client string }{
		"acme-prod-api": {"acme-corp", "acme-prod-api"},
		"cs_demo":       {"cs_demo", "cs_demo"},
	}
	if v, exists := known[clientID]; exists {
		return v.org, v.client, true
	}
	return "", "", false
}

// extractBasicAuthClientID parses Basic Auth and returns the username.
func extractBasicAuthClientID(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if !strings.HasPrefix(h, "Basic ") {
		return ""
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(h, "Basic "))
	if err != nil {
		return ""
	}
	parts := strings.SplitN(string(raw), ":", 2)
	if len(parts) >= 1 {
		return parts[0]
	}
	return ""
}

// mockOrchestrator echoes the three identity headers it received so we
// can prove what crossed the agent→orchestrator boundary.
func mockOrchestrator(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"x_org_id":    r.Header.Get("X-Org-ID"),
		"x_client_id": r.Header.Get("X-Client-ID"),
		"x_tenant_id": r.Header.Get("X-Tenant-ID"),
	})
}

// mockAgent implements the v9 overwrite rule. ANY caller-supplied
// X-Org-ID / X-Client-ID / X-Tenant-ID is replaced with the values
// derived from Basic Auth before the request is forwarded.
func mockAgent(orchestratorURL string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		clientID := extractBasicAuthClientID(r)
		orgID, derivedClientID, ok := authDerive(clientID)
		if !ok {
			http.Error(w, "auth failed", http.StatusUnauthorized)
			return
		}

		// The v9 invariant: Set (not Add) so any caller value is
		// overwritten. The values stamped here are the canonical ones
		// the orchestrator must trust.
		out, err := http.NewRequestWithContext(r.Context(), "GET", orchestratorURL+r.URL.Path, nil)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		out.Header.Set("X-Org-ID", orgID)
		out.Header.Set("X-Client-ID", derivedClientID)
		out.Header.Set("X-Tenant-ID", derivedClientID) // v9 compat alias

		resp, err := http.DefaultClient.Do(out)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(resp.StatusCode)
		_, _ = w.Write(body)
	}
}

func mustGet(t *http.Client, agentURL, clientID, password string, spoof map[string]string) map[string]string {
	req, err := http.NewRequest("GET", agentURL+"/api/v1/echo-identity", nil)
	if err != nil {
		log.Fatalf("build req: %v", err)
	}
	req.SetBasicAuth(clientID, password)
	for k, v := range spoof {
		req.Header.Set(k, v)
	}
	resp, err := t.Do(req)
	if err != nil {
		log.Fatalf("do req: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		log.Fatalf("unexpected status %d: %s", resp.StatusCode, string(body))
	}
	var got map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		log.Fatalf("decode response: %v", err)
	}
	return got
}

var failures int

func assertEqual(label, want, got string) {
	if want == got {
		fmt.Printf("   PASS: %s = %q\n", label, got)
		return
	}
	fmt.Printf("   FAIL: %s — got %q, want %q\n", label, got, want)
	failures++
}

func assertNotEqual(label, banned, got string) {
	if got != banned {
		fmt.Printf("   PASS: %s overwritten (got %q, not %q)\n", label, got, banned)
		return
	}
	fmt.Printf("   FAIL: %s NOT overwritten — spoof succeeded (got %q)\n", label, got)
	failures++
}

func main() {
	orchSrv := httptest.NewServer(http.HandlerFunc(mockOrchestrator))
	defer orchSrv.Close()
	fmt.Printf("[v9-identity] Mock orchestrator listening on %s\n", orchSrv.URL)

	agentSrv := httptest.NewServer(mockAgent(orchSrv.URL))
	defer agentSrv.Close()
	fmt.Printf("[v9-identity] Mock agent listening    on %s\n", agentSrv.URL)

	cli := http.DefaultClient

	fmt.Println()
	fmt.Println("--- Round 1: clean request, no spoofed headers ---")
	got := mustGet(cli, agentSrv.URL, "acme-prod-api", "secret", nil)
	assertEqual("orchestrator received X-Org-ID   ", "acme-corp", got["x_org_id"])
	assertEqual("orchestrator received X-Client-ID", "acme-prod-api", got["x_client_id"])
	assertEqual("orchestrator received X-Tenant-ID", "acme-prod-api", got["x_tenant_id"])

	fmt.Println()
	fmt.Println("--- Round 2: caller attempts to spoof identity ---")
	got = mustGet(cli, agentSrv.URL, "acme-prod-api", "secret", map[string]string{
		"X-Org-ID":    "victim-org",
		"X-Client-ID": "victim-client",
		"X-Tenant-ID": "victim-tenant",
	})
	assertNotEqual("X-Org-ID   ", "victim-org", got["x_org_id"])
	assertNotEqual("X-Client-ID", "victim-client", got["x_client_id"])
	assertNotEqual("X-Tenant-ID", "victim-tenant", got["x_tenant_id"])
	assertEqual("after overwrite, X-Org-ID   ", "acme-corp", got["x_org_id"])
	assertEqual("after overwrite, X-Client-ID", "acme-prod-api", got["x_client_id"])

	fmt.Println()
	if failures > 0 {
		fmt.Printf("v9 identity forwarding example: %d FAILURE(S)\n", failures)
		os.Exit(1)
	}
	fmt.Println("v9 identity forwarding example: OK")
}
