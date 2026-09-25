// Copyright 2026 AxonFlow
// SPDX-License-Identifier: BUSL-1.1

package agent

import (
	"bytes"
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
)

// THE CONTRACT OF POST /api/v1/register (#4249 row 5764325123).
//
// Every request field is optional: `{}` and an empty body register an
// unlabelled tenant with no email. That is the shipped contract, not a gap -
// the released Go SDK's RegisterTry("") and Java SDK's register("") send
// exactly `{}` - and a field the route does not know (the row's "organization
// name", "consent") is ignored, not refused. What the route DOES refuse, it
// refuses before any database call: the cells below give the handler a
// database that counts every connection it is asked for and fails it, and
// require zero.

// countingConnector is a driver.Connector that counts connection attempts and
// fails every one, so any database use by the handler is visible and writes
// nothing.
type countingConnector struct{ n atomic.Int32 }

func (c *countingConnector) Connect(context.Context) (driver.Conn, error) {
	c.n.Add(1)
	return nil, errors.New("this cell expects no database call")
}
func (c *countingConnector) Driver() driver.Driver { return countingDriver{c} }

type countingDriver struct{ c *countingConnector }

func (d countingDriver) Open(string) (driver.Conn, error) { return d.c.Connect(context.Background()) }

func postRegister(t *testing.T, db *sql.DB, contentType string, body []byte, remote string) *httptest.ResponseRecorder {
	t.Helper()
	router := setupCSAASTestRouter(t)
	resetRegIPTracker()
	RegisterCommunityRegistrationHandler(router, db)
	var rdr *bytes.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	var req *http.Request
	if rdr != nil {
		req = httptest.NewRequest(http.MethodPost, "/api/v1/register", rdr)
	} else {
		req = httptest.NewRequest(http.MethodPost, "/api/v1/register", nil)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	req.RemoteAddr = remote
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)
	return rr
}

func TestRegister_RefusalsNameTheFieldAndWriteNothing(t *testing.T) {
	cases := []struct {
		name        string
		contentType string
		body        []byte
		wantStatus  int
		wantMessage string
	}{
		{"malformed JSON", "application/json", []byte(`not json`), http.StatusBadRequest, "Invalid JSON in request body"},
		{"a truncated object", "application/json", []byte(`{"label":`), http.StatusBadRequest, "Invalid JSON in request body"},
		{"label of the wrong type", "application/json", []byte(`{"label":5}`), http.StatusBadRequest, "Invalid JSON in request body"},
		{"a non-JSON content type", "text/plain", []byte(`{}`), http.StatusUnsupportedMediaType, "Content-Type must be application/json"},
		{"a body over 1 KiB", "application/json", []byte(`{"label":"` + strings.Repeat("a", maxRequestBodySize) + `"}`), http.StatusRequestEntityTooLarge,
			fmt.Sprintf("Request body too large (max %d bytes)", maxRequestBodySize)},
		{"a label over 255 characters", "application/json", []byte(`{"label":"` + strings.Repeat("a", maxLabelLength+1) + `"}`), http.StatusBadRequest,
			fmt.Sprintf("Label too long (max %d characters)", maxLabelLength)},
		{"an email that is not one", "application/json", []byte(`{"email":"not-an-email"}`), http.StatusBadRequest, "Invalid email format"},
		{"a prefix outside the allowlist", "application/json", []byte(`{"internal_tenant_id_prefix":"evil-"}`), http.StatusBadRequest, "Unsupported internal_tenant_id_prefix value"},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cc := &countingConnector{}
			db := sql.OpenDB(cc)
			t.Cleanup(func() { _ = db.Close() })

			rr := postRegister(t, db, tc.contentType, tc.body, fmt.Sprintf("10.42.0.%d:1234", i+1))
			if rr.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d; body %s", rr.Code, tc.wantStatus, rr.Body.String())
			}
			var got struct {
				Error struct {
					Code    int    `json:"code"`
					Message string `json:"message"`
				} `json:"error"`
			}
			if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
				t.Fatalf("the refusal is not the JSON error body: %v: %s", err, rr.Body.String())
			}
			if got.Error.Code != tc.wantStatus || got.Error.Message != tc.wantMessage {
				t.Errorf("refusal = %d %q, want %d %q", got.Error.Code, got.Error.Message, tc.wantStatus, tc.wantMessage)
			}
			if n := cc.n.Load(); n != 0 {
				t.Errorf("the refusal asked for %d database connection(s); a refused registration touches nothing", n)
			}
			if strings.Contains(rr.Body.String(), `"secret"`) {
				t.Error("a refused registration disclosed a secret")
			}
		})
	}
}

// `{}`, an empty body and an object of fields the route does not know each
// register an unlabelled tenant with no email: 201, the credentials, and the
// tenant helper called with a NULL label and a NULL email.
func TestRegister_EveryFieldIsOptional(t *testing.T) {
	cases := []struct {
		name        string
		contentType string
		body        []byte
	}{
		{"{} (the Go and Java SDKs' RegisterTry with no label)", "application/json", []byte(`{}`)},
		{"an empty body", "application/json", nil},
		{"no Content-Type and no body", "", nil},
		{"only fields the route does not know", "application/json", []byte(`{"organization_name":"acme","consent":true}`)},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db, mock, err := sqlmock.New(sqlmock.QueryMatcherOption(sqlmock.QueryMatcherRegexp))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = db.Close() })
			// $4 is the label, $6 the email: both NULL.
			mock.ExpectExec(`SELECT csaas_register_tenant\(\$1, \$2, \$3, \$4, \$5, \$6\)`).
				WithArgs(sqlmock.AnyArg(), sqlmock.AnyArg(), sqlmock.AnyArg(), nil, sqlmock.AnyArg(), nil).
				WillReturnResult(sqlmock.NewResult(1, 1))
			mock.ExpectExec(`SELECT register_org`).WillReturnResult(sqlmock.NewResult(0, 0))
			mock.ExpectExec(`SELECT register_tenant`).WillReturnResult(sqlmock.NewResult(0, 0))
			expectRegistrationPosture(mock, sqlmock.AnyArg())

			rr := postRegister(t, db, tc.contentType, tc.body, fmt.Sprintf("10.43.0.%d:1234", i+1))
			if rr.Code != http.StatusCreated {
				t.Fatalf("status = %d, want 201; body %s", rr.Code, rr.Body.String())
			}
			var resp registrationResponse
			if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
				t.Fatalf("the 201 body is not a registration: %v", err)
			}
			if !strings.HasPrefix(resp.TenantID, communitySaasTenantPrefix) || len(resp.Secret) != 2*secretBytes {
				t.Errorf("registration = tenant %q secret length %d", resp.TenantID, len(resp.Secret))
			}
			if err := mock.ExpectationsWereMet(); err != nil {
				t.Errorf("the registration did not write as expected (label and email NULL): %v", err)
			}
		})
	}
}
