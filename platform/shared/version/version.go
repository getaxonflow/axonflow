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

// Package version exposes the platform version baked into the binary at build
// time. It is the single trustworthy source for what /health reports (#2662).
package version

import "os"

// Version is the platform version baked into the binary at build time via:
//
//	-ldflags "-X axonflow/platform/shared/version.Version=$AXONFLOW_VERSION"
//
// (see platform/agent/Dockerfile + platform/orchestrator/Dockerfile, fed by the
// AXONFLOW_VERSION build-arg in .github/workflows/build.yml, which reads the repo
// VERSION file). That build-arg is the SAME source that sets the image
// io.opencontainer.image.version label, so the baked binary version and the
// image label never drift.
//
// It is empty in unbaked builds (go run / go test / a `go build` without the
// ldflag). Resolve() then falls back to the AXONFLOW_VERSION env var for local
// dev. A baked value ALWAYS wins over the env, so /health reports the true
// shipped binary version and cannot be spoofed by a runtime env override.
var Version string

// Resolve returns the effective platform version, preferring the build-baked
// Version. Order:
//
//	baked Version (trustworthy) -> AXONFLOW_VERSION env (dev/local) -> ""
//
// Callers apply their own default + format validation to the returned string.
func Resolve() string {
	if Version != "" {
		return Version
	}
	return os.Getenv("AXONFLOW_VERSION")
}

// Baked reports whether a version was baked into the binary at build time.
// When false, Resolve() is using the env fallback (a dev/unbaked build).
func Baked() bool {
	return Version != ""
}
