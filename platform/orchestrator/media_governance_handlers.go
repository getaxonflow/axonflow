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

package orchestrator

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"time"

	"axonflow/platform/agent/license"

	"github.com/gorilla/mux"
)

// MediaGovernanceHandler handles media governance config API endpoints.
type MediaGovernanceHandler struct {
	configStore    *MediaGovernanceConfigStore
	licenseChecker LicenseChecker
}

// NewMediaGovernanceHandler creates a new handler with the given store and license checker.
func NewMediaGovernanceHandler(store *MediaGovernanceConfigStore, lc LicenseChecker) *MediaGovernanceHandler {
	return &MediaGovernanceHandler{
		configStore:    store,
		licenseChecker: lc,
	}
}

// RegisterRoutes registers the media governance API routes on the given router.
func (h *MediaGovernanceHandler) RegisterRoutes(r *mux.Router) {
	r.HandleFunc("/api/v1/media-governance/config", h.handleGetConfig).Methods("GET", "OPTIONS")
	r.HandleFunc("/api/v1/media-governance/config", h.handleUpdateConfig).Methods("PUT", "OPTIONS")
	r.HandleFunc("/api/v1/media-governance/status", h.handleGetStatus).Methods("GET", "OPTIONS")
}

// handleGetConfig returns the current tenant's media governance configuration.
func (h *MediaGovernanceHandler) handleGetConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method == "OPTIONS" {
		h.handleCORS(w, r)
		return
	}

	tenantID := h.getTenantID(r)
	if tenantID == "" {
		h.writeError(w, http.StatusBadRequest, "MISSING_TENANT_ID", "X-Tenant-ID header is required")
		return
	}

	cfg, err := h.configStore.GetFromDB(r.Context(), tenantID)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to get config")
		return
	}

	if cfg == nil {
		// Return default config (enabled follows tier default)
		cfg = &MediaGovernanceConfig{
			TenantID:  tenantID,
			Enabled:   h.isMediaGovernanceAvailable(),
			UpdatedAt: time.Now().UTC(),
		}
	}

	h.writeJSON(w, http.StatusOK, cfg)
}

// UpdateMediaGovernanceConfigRequest is the request body for PUT /api/v1/media-governance/config.
type UpdateMediaGovernanceConfigRequest struct {
	Enabled          *bool    `json:"enabled,omitempty"`
	AllowedAnalyzers []string `json:"allowed_analyzers,omitempty"`
}

// handleUpdateConfig updates the media governance configuration for the current tenant.
func (h *MediaGovernanceHandler) handleUpdateConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method == "OPTIONS" {
		h.handleCORS(w, r)
		return
	}

	tenantID := h.getTenantID(r)
	if tenantID == "" {
		h.writeError(w, http.StatusBadRequest, "MISSING_TENANT_ID", "X-Tenant-ID header is required")
		return
	}

	// Only Enterprise tier can modify per-tenant configuration
	tier := h.licenseChecker.Tier()
	if !license.IsPaidTier(tier) {
		h.writeError(w, http.StatusForbidden, "TIER_RESTRICTED",
			"Per-tenant media governance configuration requires an Enterprise license. "+
				"Use the MEDIA_GOVERNANCE_ENABLED environment variable for platform-wide control.")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1 MB limit
	var req UpdateMediaGovernanceConfigRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, "INVALID_REQUEST", "Invalid request body")
		return
	}

	// Get existing config or create default
	cfg, err := h.configStore.GetFromDB(r.Context(), tenantID)
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to get config")
		return
	}
	if cfg == nil {
		cfg = &MediaGovernanceConfig{
			TenantID: tenantID,
			Enabled:  h.isMediaGovernanceAvailable(),
		}
	}

	// Apply updates
	if req.Enabled != nil {
		cfg.Enabled = *req.Enabled
	}
	if req.AllowedAnalyzers != nil {
		cfg.AllowedAnalyzers = req.AllowedAnalyzers
	}
	cfg.UpdatedBy = h.getUserID(r)

	if err := h.configStore.Upsert(r.Context(), cfg); err != nil {
		h.writeError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to save config")
		return
	}

	h.writeJSON(w, http.StatusOK, cfg)
}

// handleGetStatus returns the media governance feature availability for the current tier.
func (h *MediaGovernanceHandler) handleGetStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method == "OPTIONS" {
		h.handleCORS(w, r)
		return
	}

	tier := h.licenseChecker.Tier()

	// Available reflects whether media governance is actually active,
	// considering tier defaults AND the MEDIA_GOVERNANCE_ENABLED env var override.
	tierEnabled := h.licenseChecker.MediaGovernanceEnabled()
	envVal := os.Getenv("MEDIA_GOVERNANCE_ENABLED")
	envOverride := envVal == "true" || envVal == "1"

	status := MediaGovernanceStatus{
		Available:        tierEnabled || envOverride,
		EnabledByDefault: tierEnabled,
		PerTenantControl: license.IsPaidTier(tier),
		Tier:             string(tier),
	}

	h.writeJSON(w, http.StatusOK, status)
}

// isMediaGovernanceAvailable returns true if media governance is enabled by tier default
// or by the MEDIA_GOVERNANCE_ENABLED env var (community opt-in).
func (h *MediaGovernanceHandler) isMediaGovernanceAvailable() bool {
	if h.licenseChecker.MediaGovernanceEnabled() {
		return true
	}
	envVal := os.Getenv("MEDIA_GOVERNANCE_ENABLED")
	return envVal == "true" || envVal == "1"
}

func (h *MediaGovernanceHandler) getTenantID(r *http.Request) string {
	if tenantID := r.Header.Get("X-Tenant-ID"); tenantID != "" {
		return tenantID
	}
	// Fallback to X-Org-ID for backward compatibility
	if tenantID := r.Header.Get("X-Org-ID"); tenantID != "" {
		return tenantID
	}
	if tenantID, ok := r.Context().Value("tenant_id").(string); ok {
		return tenantID
	}
	return ""
}

func (h *MediaGovernanceHandler) getUserID(r *http.Request) string {
	if userID := r.Header.Get("X-User-ID"); userID != "" {
		return userID
	}
	if userID, ok := r.Context().Value("user_id").(string); ok {
		return userID
	}
	return "system"
}

func (h *MediaGovernanceHandler) handleCORS(w http.ResponseWriter, r *http.Request) {
	origin := r.Header.Get("Origin")
	if origin != "" && allowedOrigins[origin] {
		w.Header().Set("Access-Control-Allow-Origin", origin)
	}
	w.Header().Set("Access-Control-Allow-Methods", "GET, PUT, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Tenant-ID, X-Org-ID, X-User-ID")
	w.Header().Set("Access-Control-Max-Age", "86400")
	w.WriteHeader(http.StatusOK)
}

func (h *MediaGovernanceHandler) writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		log.Printf("[MediaGovernance] Error encoding JSON response: %v", err)
	}
}

func (h *MediaGovernanceHandler) writeError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(map[string]interface{}{
		"error": map[string]string{
			"code":    code,
			"message": message,
		},
	}); err != nil {
		log.Printf("[MediaGovernance] Error encoding error response: %v", err)
	}
}
