// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

// Test helpers moved unchanged from run_segment_policy_test.go when #4253
// deleted the /api/request segment gate that file tested. The gateway
// pre-check and MCP-server segment suites still use them.

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"time"

	sharedidentity "axonflow/platform/shared/identity"
)

var errAssertSegmentResolutionFailed = errors.New("segment query failed (test)")

// generateTestJWTWithOrgEmail mirrors generateTestJWT (same signing
// approach, same testJWTSecret) but additionally sets the "org_id" and
// "email" claims validateUserToken reads (run.go) — generateTestJWT itself
// carries neither, so resolveUserSegments would otherwise be called
// with an empty email/an org_id that merely falls back to tenantID.
func generateTestJWTWithOrgEmail(userID interface{}, tenantID, orgID, email string, permissions []string, role string) string {
	jwtSecret = []byte(testJWTSecret)

	header := map[string]string{"alg": "HS256", "typ": "JWT"}
	now := time.Now().Unix()
	claims := map[string]interface{}{
		"iss":         sharedidentity.UserTokenIssuer,
		"sub":         email,
		"user_id":     userID,
		"tenant_id":   tenantID,
		"org_id":      orgID,
		"email":       email,
		"jti":         "test-jti-" + orgID + "-" + email,
		"permissions": permissions,
		"role":        role,
		"iat":         now,
		"exp":         now + 86400,
	}

	headerJSON, _ := json.Marshal(header)
	claimsJSON, _ := json.Marshal(claims)
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	claimsB64 := base64.RawURLEncoding.EncodeToString(claimsJSON)

	signingInput := headerB64 + "." + claimsB64
	h := hmac.New(sha256.New, []byte(testJWTSecret))
	h.Write([]byte(signingInput))
	signature := base64.RawURLEncoding.EncodeToString(h.Sum(nil))

	return signingInput + "." + signature
}
