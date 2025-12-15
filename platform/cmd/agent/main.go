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

// Package main is the entry point for the AxonFlow Agent service.
//
// The Agent is a sub-10ms policy enforcement gateway that:
// - Evaluates governance policies for AI requests
// - Routes approved requests to the Orchestrator
// - Provides comprehensive audit logging
// - Handles authentication and rate limiting
//
// Usage:
//
//	./agent
//
// Environment Variables:
//
//	PORT - HTTP server port (default: 8080)
//	ORCHESTRATOR_URL - URL of the Orchestrator service
//	DATABASE_URL - PostgreSQL connection string
//	JWT_SECRET - Secret for JWT token validation
//
// For more information, see https://docs.getaxonflow.com
package main

import (
	"axonflow/platform/agent"
)

func main() {
	agent.Run()
}
