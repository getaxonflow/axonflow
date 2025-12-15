// Copyright 2025 AxonFlow
// SPDX-License-Identifier: BUSL-1.1
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

/*
Command agent runs the AxonFlow Agent service.

The Agent is the first line of defense in the AxonFlow architecture,
handling client authentication, static policy enforcement, and request
routing to the Orchestrator.

# Usage

	agent [flags]

# Environment Variables

Required:
  - DATABASE_URL: PostgreSQL connection string
  - ORCHESTRATOR_URL: URL to the Orchestrator service

Optional:
  - PORT: HTTP server port (default: 8080)
  - REDIS_URL: Redis URL for distributed rate limiting
  - JWT_SECRET: Secret for JWT token validation
  - AUDIT_MODE: "compliance" or "performance" (default: compliance)

# Example

	export DATABASE_URL="postgres://user:pass@localhost:5432/axonflow"
	export ORCHESTRATOR_URL="http://localhost:8081"
	./agent
*/
package main
