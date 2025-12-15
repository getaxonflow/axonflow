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
Command orchestrator runs the AxonFlow Orchestrator service.

The Orchestrator is the brain of the AxonFlow system, providing intelligent
LLM routing, dynamic policy evaluation, and Multi-Agent Planning (MAP).

# Usage

	orchestrator [flags]

# Environment Variables

Required:
  - DATABASE_URL: PostgreSQL connection string

Optional:
  - PORT: HTTP server port (default: 8081)
  - OPENAI_API_KEY: OpenAI API key
  - ANTHROPIC_API_KEY: Anthropic API key
  - BEDROCK_REGION: AWS Bedrock region
  - OLLAMA_ENDPOINT: Ollama endpoint URL

# LLM Provider Configuration

Configure providers via environment variables. The Orchestrator auto-detects
available providers based on which API keys are set:

	# OpenAI
	export OPENAI_API_KEY="sk-..."

	# Anthropic
	export ANTHROPIC_API_KEY="sk-ant-..."

	# AWS Bedrock
	export BEDROCK_REGION="us-east-1"
	export BEDROCK_MODEL="anthropic.claude-3-sonnet-20240229-v1:0"

	# Ollama (self-hosted)
	export OLLAMA_ENDPOINT="http://localhost:11434"
	export OLLAMA_MODEL="llama2"

# Example

	export DATABASE_URL="postgres://user:pass@localhost:5432/axonflow"
	export OPENAI_API_KEY="sk-..."
	./orchestrator
*/
package main
