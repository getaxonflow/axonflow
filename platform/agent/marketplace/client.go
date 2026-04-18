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

//go:build enterprise

package marketplace

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/marketplacemetering"
)

// MeteringClient is an interface for AWS Marketplace Metering operations
// This allows for easy mocking in tests
type MeteringClient interface {
	RegisterUsage(ctx context.Context, input *marketplacemetering.RegisterUsageInput, opts ...func(*marketplacemetering.Options)) (*marketplacemetering.RegisterUsageOutput, error)
	MeterUsage(ctx context.Context, input *marketplacemetering.MeterUsageInput, opts ...func(*marketplacemetering.Options)) (*marketplacemetering.MeterUsageOutput, error)
}

// Ensure *marketplacemetering.Client implements MeteringClient
var _ MeteringClient = (*marketplacemetering.Client)(nil)
