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

package agent

import (
	"context"
)

// contextKey is a private type for context keys to avoid collisions
// with other packages that might use string keys.
type contextKey string

// transparencyContextKey is the key for storing TransparencyContext in context.Context.
const transparencyContextKey contextKey = "transparency"

// SetTransparencyContext stores a TransparencyContext in the context.Context.
// This enables transparency tracking across function boundaries and goroutines.
// The context should be propagated through the request lifecycle.
//
// Example:
//
//	tc := NewTransparencyContext()
//	ctx = SetTransparencyContext(ctx, tc)
//	// Pass ctx to downstream functions
func SetTransparencyContext(ctx context.Context, tc *TransparencyContext) context.Context {
	return context.WithValue(ctx, transparencyContextKey, tc)
}

// GetTransparencyContext retrieves the TransparencyContext from the context.
// Returns nil if no transparency context is set. The returned context is
// thread-safe and can be modified concurrently.
//
// Example:
//
//	tc := GetTransparencyContext(ctx)
//	if tc != nil {
//	    tc.AddPolicy("my-policy")
//	}
func GetTransparencyContext(ctx context.Context) *TransparencyContext {
	if tc, ok := ctx.Value(transparencyContextKey).(*TransparencyContext); ok {
		return tc
	}
	return nil
}

// GetOrCreateTransparencyContext retrieves an existing TransparencyContext
// from the context, or creates a new one if none exists. This is useful when
// you want to ensure a context always exists without checking for nil.
//
// Returns both the TransparencyContext and a potentially updated context.Context.
// If a new context was created, it will be stored in the returned context.
//
// Example:
//
//	tc, ctx := GetOrCreateTransparencyContext(ctx)
//	tc.AddPolicy("my-policy")
//	// Use ctx for further operations
func GetOrCreateTransparencyContext(ctx context.Context) (*TransparencyContext, context.Context) {
	tc := GetTransparencyContext(ctx)
	if tc == nil {
		tc = NewTransparencyContext()
		ctx = SetTransparencyContext(ctx, tc)
	}
	return tc, ctx
}
