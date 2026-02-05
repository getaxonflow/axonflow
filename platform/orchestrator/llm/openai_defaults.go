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

package llm

import "time"

// OpenAI provider defaults.
const (
	// OpenAIDefaultModel is the default OpenAI model.
	OpenAIDefaultModel = "gpt-4o"

	// OpenAIDefaultEndpoint is the default OpenAI API endpoint.
	OpenAIDefaultEndpoint = "https://api.openai.com"

	// OpenAIDefaultTimeout is the default timeout for OpenAI requests.
	OpenAIDefaultTimeout = 120 * time.Second
)
