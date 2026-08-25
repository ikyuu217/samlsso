package app

import (
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// stubAuthenticator is a hand-written Authenticator for handler tests,
// possible because the handlers depend only on the port.
type stubAuthenticator struct {
	redirect LoginRedirect
	result   AuthResult
	err      error
}

func (s *stubAuthenticator) BuildLoginRedirect(relayState string) (LoginRedirect, error) {
	return s.redirect, s.err
}

func (s *stubAuthenticator) ValidateResponse(encodedResponse string) (AuthResult, error) {
	return s.result, s.err
}

func postACS(h *Handlers, form url.Values) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/saml/acs", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.ACS(rec, req)
	return rec
}

func TestLoginRedirectsToIdP(t *testing.T) {
	h := NewHandlers(&stubAuthenticator{redirect: LoginRedirect{
		URL:        "https://idp.example.test/sso?SAMLRequest=x",
		RequestXML: "<AuthnRequest/>",
	}})

	rec := httptest.NewRecorder()
	h.Login(rec, httptest.NewRequest(http.MethodGet, "/saml/login", nil))

	if rec.Code != http.StatusFound {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusFound)
	}
	if got, want := rec.Header().Get("Location"), "https://idp.example.test/sso?SAMLRequest=x"; got != want {
		t.Errorf("Location = %q, want %q", got, want)
	}
}

func TestACSShowsAuthResult(t *testing.T) {
	h := NewHandlers(&stubAuthenticator{result: AuthResult{
		NameID:       "user@example.test",
		NameIDFormat: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
		Attributes: []Attribute{
			{Name: "displayname", Values: []string{"Test User"}},
		},
	}})

	encoded := base64.StdEncoding.EncodeToString([]byte("<Response/>"))
	rec := postACS(h, url.Values{"SAMLResponse": {encoded}})

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	body := rec.Body.String()
	for _, want := range []string{"user@example.test", "displayname", "Test User"} {
		if !strings.Contains(body, want) {
			t.Errorf("body does not contain %q", want)
		}
	}
}

func TestACSRejectsInvalidResponse(t *testing.T) {
	h := NewHandlers(&stubAuthenticator{err: errors.New("validate SAMLResponse: bad signature")})

	encoded := base64.StdEncoding.EncodeToString([]byte("<Response/>"))
	rec := postACS(h, url.Values{"SAMLResponse": {encoded}})

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
	if !strings.Contains(rec.Body.String(), "bad signature") {
		t.Error("body does not contain the validation error")
	}
}

func TestACSRequiresSAMLResponse(t *testing.T) {
	h := NewHandlers(&stubAuthenticator{})

	rec := postACS(h, url.Values{})

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
}
