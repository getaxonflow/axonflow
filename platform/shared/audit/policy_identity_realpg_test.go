// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package audit

import (
	"database/sql"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	_ "github.com/lib/pq"
)

// Real-Postgres SQL/Go parity for the policy-identity extraction chain
// (#3243 v9.16.1, second R3 round).
//
// WHY A REAL DATABASE: the Go mirror (ExtractPolicyIdentity) is what the
// cross-plane contract tests execute, but the exporters execute the SQL - and
// Postgres jsonb operators have semantics no mock reproduces (`->>0` treats a
// jsonb scalar as a one-element array; `->>` renders raw JSON text for
// object-valued keys). Both R3-confirmed divergences of this PR were exactly
// that class: the SQL resolved something the mirror did not, on a
// regulator-facing field, and every non-DB test stayed green. This test runs
// EVERY vector in policyIdentityParityVectors through the REAL expressions on
// a throwaway postgres:16 (the version the R3 confirmation used) and asserts
// the SQL agrees with the Go mirror AND with the vector's declared expectation.
//
// Hermetic, same pattern as platform/agent/approletest: spins its own
// container, no DATABASE_URL, gated on TEST_PG_INTEGRATION=1 (the
// "Unit Tests: Enterprise-Tagged + Real-PG" CI job sets it).
func TestPolicyIdentitySQL_ParityWithGoExtractor_RealPG(t *testing.T) {
	if os.Getenv("TEST_PG_INTEGRATION") != "1" {
		t.Skip("TEST_PG_INTEGRATION=1 not set - skipping real-Postgres parity test")
	}

	db := startParityPG(t)

	// One SELECT evaluating both expressions over a bound jsonb parameter -
	// the exact strings the exporters embed, no rewriting.
	query := "SELECT " + PolicyIdentitySQLExpr("$1::jsonb") + ", " + PolicyVersionSQLExpr("$1::jsonb")

	ran := 0
	for _, tc := range policyIdentityParityVectors {
		t.Run(tc.name, func(t *testing.T) {
			// A malformed-JSON vector cannot exist in a jsonb COLUMN (Postgres
			// rejects it at write time); it exists to prove the GO side never
			// panics. The cast erroring here is the correct SQL behavior.
			var sqlID, sqlVer string
			if err := db.QueryRow(query, tc.details).Scan(&sqlID, &sqlVer); err != nil {
				if tc.name == "malformed json resolves empty, never panics" {
					return
				}
				t.Fatalf("query: %v", err)
			}
			ran++

			goID, goVer := ExtractPolicyIdentity([]byte(tc.details))
			if sqlID != goID || sqlVer != goVer {
				t.Errorf("SQL/Go DIVERGE on %s:\n  SQL (id=%q, ver=%q)\n  Go  (id=%q, ver=%q)\n  details: %s",
					tc.name, sqlID, sqlVer, goID, goVer, tc.details)
			}
			if sqlID != tc.wantIdentity || sqlVer != tc.wantVersion {
				t.Errorf("SQL resolved (id=%q, ver=%q), vector wants (id=%q, ver=%q) for %s",
					sqlID, sqlVer, tc.wantIdentity, tc.wantVersion, tc.details)
			}
		})
	}
	if ran == 0 {
		t.Fatal("no parity vectors executed against Postgres; the parity gate asserted nothing")
	}
}

// startParityPG starts a throwaway postgres:16 container and returns an open,
// pinged connection. Mirrors approletest's container bring-up (including the
// docker-port polling race note there) without importing an agent package
// from a shared-package test.
func startParityPG(t *testing.T) *sql.DB {
	t.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		t.Fatal("TEST_PG_INTEGRATION=1 is set but docker is not available; refusing to skip a requested integration test")
	}

	name := fmt.Sprintf("axonflow-test-policyid-pg-%d", time.Now().UnixNano())
	out, err := exec.Command("docker", "run", "-d",
		"--name", name,
		"-e", "POSTGRES_PASSWORD=testpass",
		"-e", "POSTGRES_DB=axonflow_test",
		"-p", "0:5432",
		"postgres:16",
	).CombinedOutput()
	if err != nil {
		t.Fatalf("docker run: %v\n%s", err, string(out))
	}
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", name).Run() })

	var hostPort string
	deadline := time.Now().Add(30 * time.Second)
	for hostPort == "" {
		if time.Now().After(deadline) {
			t.Fatal("docker port mapping did not resolve within 30s")
		}
		if portBytes, portErr := exec.Command("docker", "port", name, "5432/tcp").CombinedOutput(); portErr == nil {
			line := strings.TrimSpace(strings.Split(string(portBytes), "\n")[0])
			if parts := strings.Split(line, ":"); len(parts) >= 2 && parts[len(parts)-1] != "" {
				hostPort = parts[len(parts)-1]
			}
		}
		if hostPort == "" {
			time.Sleep(500 * time.Millisecond)
		}
	}

	dsn := fmt.Sprintf("postgres://postgres:testpass@127.0.0.1:%s/axonflow_test?sslmode=disable", hostPort)
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	deadline = time.Now().Add(60 * time.Second)
	for {
		if err := db.Ping(); err == nil {
			return db
		}
		if time.Now().After(deadline) {
			t.Fatal("postgres did not become ready within 60s")
		}
		time.Sleep(500 * time.Millisecond)
	}
}
