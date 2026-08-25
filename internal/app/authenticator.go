// Package app is the application layer of the SAML SP: the HTTP handlers
// and the port (contract) through which authentication is performed.
//
// The application side owns the Authenticator contract and the
// infrastructure layer implements it, so the source-level dependency points
// from infrastructure to application (dependency inversion).
package app

// Authenticator is the port through which the application starts a SAML
// login and validates the IdP's response. Implementations live in the
// infrastructure layer (e.g. internal/infra/entraid).
type Authenticator interface {
	// BuildLoginRedirect builds an authentication request and returns the
	// IdP redirect URL together with the request XML before encoding.
	BuildLoginRedirect(relayState string) (LoginRedirect, error)
	// ValidateResponse validates an encoded SAMLResponse (signature, issuer,
	// validity period, audience) and returns the authenticated identity.
	// Any validation failure is reported as a non-nil error.
	ValidateResponse(encodedResponse string) (AuthResult, error)
}

// LoginRedirect is the outcome of starting a login.
type LoginRedirect struct {
	// URL is the IdP SSO URL with the encoded SAMLRequest attached.
	URL string
	// RequestXML is the AuthnRequest XML before encoding, kept for the
	// learning-oriented log.
	RequestXML string
}

// AuthResult is the identity extracted from a validated SAMLResponse.
type AuthResult struct {
	NameID       string
	NameIDFormat string
	Attributes   []Attribute
}

// Attribute is one assertion attribute.
type Attribute struct {
	Name   string
	Values []string
}
