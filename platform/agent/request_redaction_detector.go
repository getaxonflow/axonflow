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

package agent

// Request-phase redaction detector seam (ADR-056 / #2563 addendum).
//
// The request-redaction endpoint (check-input) and the redact_pii obligation
// contract are content-type-agnostic on purpose. A redaction request carries a
// `content_type` (mime); the endpoint dispatches to the RequestRedactionDetector
// registered for that mime. TEXT is the only detector wired today.
//
// IMPORTANT — there is no single PII engine (#2563 "three diverged detectors").
// Detection is fragmented across at least four detectors wired inconsistently
// over request/response × agent/orchestrator:
//   1. static category engine (platform/shared/policy, text regex) — what the
//      text detector below wraps via redactInputStatement;
//   2. EE Indonesia checksum detector (ee/platform/agent/indonesia,
//      CheckRequestForPII) — checksum NIK/NPWP, REQUEST-PHASE ONLY;
//   3. orchestrator EnhancedPIIDetector (response_processor.go) — response-side;
//   4. orchestrator media subsystem (/api/v1/media-governance/*).
// This seam is the dispatch point that lets an obligation reach whichever
// detector is authoritative for the content + phase, rather than assuming (1).
// The text detector below now wires BOTH (1) the static category engine and
// (2) the EE Indonesia checksum detector: redactInputStatement applies the
// static redactor and then redactIndonesiaPIIInString (#2571), so this path
// masks static-engine PII (e.g. Singapore NRIC) AND checksum-validated
// NIK/NPWP. That closes the request-path NIK leak — previously a /decide
// redact_pii obligation naming check-input went unfulfilled because the static
// engine alone does not carry the checksum NIK validator. Converging the
// orchestrator-side detectors (3)/(4) behind one shared response-side detector
// (with media as a plug-in) remains the W2 re-baseline tracked on #2563; the
// request path here no longer depends on it. See ADR-056 "Detector topology".
//
// Media is NOT a hypothetical future build — it already exists. The orchestrator
// ships a media-governance subsystem (v4.5.0): real detection via AWS Rekognition
// + Azure Vision, four categories (media-safety, media-biometric, media-document,
// media-pii), the `sys_media_pii_block` system policy, and the
// `/api/v1/media-governance/*` API (platform/orchestrator/media/,
// platform/orchestrator/media_governance_handlers.go). It is currently
// DISCONNECTED from the agent Decision-Mode / check-input / check-output / PEP
// path — there are no media references in decision_handler.go or mcp_handler.go.
//
// So the seam to close (a tracked #2563 follow-up, NOT this PR) is: register a
// media RequestRedactionDetector here whose Redact() routes image/* and
// application/pdf content to that EXISTING orchestrator subsystem — we wire to
// it, we do not rebuild media detection. The contract already carries everything
// that wiring needs (content_type + a binary Content carrier on RedactionInput),
// so closing the seam is a detector registration, never an endpoint or
// wire-contract redesign. This is the connector-assumption trap (#2563) avoided
// one layer up, in the content modality: the shape never assumed text.

import (
	"context"
	"sort"
)

// RedactionInput carries the content a detector must mask. Text carries the
// text/plain modality; Content carries binary modalities (images, PDFs) for a
// media detector that routes to the orchestrator media-governance subsystem.
// The dispatch model is fixed; new modalities ride existing fields (or add a
// field additively) — never a reshape.
type RedactionInput struct {
	TenantID      string
	UserID        string
	ConnectorName string
	ContentType   string
	Text          string
	Content       []byte // binary carrier for media modalities (image/*, application/pdf)
}

// RedactionOutput is the masked result. Redacted reports whether anything was
// masked; Text is the masked text for text content types. Evaluated reports
// whether the detector actually RAN (vs short-circuited because detection is
// disabled) — the request-redaction endpoint surfaces it so a PEP can fail
// closed instead of forwarding when the redactor did not run (#2563 B1).
type RedactionOutput struct {
	Redacted  bool
	Text      string
	Evaluated bool
}

// RequestRedactionDetector masks PII in content of a single mime-type.
type RequestRedactionDetector interface {
	// ContentType is the mime-type this detector handles, e.g. "text/plain".
	ContentType() string
	// Redact masks PII in the input and reports whether anything changed.
	Redact(ctx context.Context, in RedactionInput) RedactionOutput
}

// requestRedactionDetectors is the mime-type -> detector registry.
var requestRedactionDetectors = map[string]RequestRedactionDetector{}

// RegisterRequestRedactionDetector registers a detector for its content-type.
// Call from init(); later calls override an earlier registration for the same
// mime so a deployment can swap the text detector for a richer one.
func RegisterRequestRedactionDetector(d RequestRedactionDetector) {
	requestRedactionDetectors[d.ContentType()] = d
}

// requestRedactionDetectorFor returns the detector for a content-type. An empty
// content-type defaults to text/plain (backward compatibility for callers that
// don't set the field). Returns (nil, false) for an unregistered mime so the
// endpoint can fail closed rather than forward unredacted content.
func requestRedactionDetectorFor(contentType string) (RequestRedactionDetector, bool) {
	if contentType == "" {
		contentType = contentTypeText
	}
	d, ok := requestRedactionDetectors[contentType]
	return d, ok
}

// MediaContentTypes lists the modalities the orchestrator media-governance
// subsystem can analyze. They are NOT yet registered as request-redaction
// detectors (the agent->orchestrator wiring is the tracked seam to close), so a
// PEP submitting them fails closed today. Named here so the wiring change is a
// one-line registration against a documented set, not a rediscovery exercise.
var MediaContentTypes = []string{"image/png", "image/jpeg", "application/pdf"}

// requestRedactionContentTypes returns the registered mime-types, sorted. Used
// to populate the obligation's content_types so PEPs know which modalities the
// endpoint can redact and fail closed on the rest.
func requestRedactionContentTypes() []string {
	out := make([]string, 0, len(requestRedactionDetectors))
	for ct := range requestRedactionDetectors {
		out = append(out, ct)
	}
	sort.Strings(out)
	return out
}

// textPIIDetector is the built-in text/plain detector. It delegates to the
// policy engine's redactor (redactInputStatement) — engine-backed, never a
// local regex. This is the only modality shipped today.
type textPIIDetector struct{}

func (textPIIDetector) ContentType() string { return contentTypeText }

func (textPIIDetector) Redact(ctx context.Context, in RedactionInput) RedactionOutput {
	masked, did, evaluated := redactInputStatement(ctx, in.TenantID, in.UserID, in.ConnectorName, in.Text)
	if !did {
		return RedactionOutput{Redacted: false, Text: in.Text, Evaluated: evaluated}
	}
	return RedactionOutput{Redacted: true, Text: masked, Evaluated: evaluated}
}

func init() {
	RegisterRequestRedactionDetector(textPIIDetector{})
}
