// Package entraid is the infrastructure layer that talks to Microsoft Entra
// ID as the SAML IdP. It implements the app.Authenticator port with gosaml2:
// it fetches and parses the federation metadata, assembles the gosaml2
// service provider, and hides gosaml2's validation quirks behind the port.
//
// The logic itself is standard SAML 2.0 handling, but its assumptions are
// tuned to Entra ID: the metadata may contain WS-Fed RoleDescriptor elements
// (ignored), the entityID has the form https://sts.windows.net/{tenant-id}/,
// and the assertion Audience is the "Identifier (Entity ID)" registered in
// the portal.
package entraid

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	saml2 "github.com/russellhaering/gosaml2"
	"github.com/russellhaering/gosaml2/types"
	dsig "github.com/russellhaering/goxmldsig"

	"github.com/ikyuu217/samlsso/internal/app"
)

// SPParams carries the SP-side values needed to assemble the service
// provider. They must match what is registered on the Entra ID side.
type SPParams struct {
	// EntityID is the value registered as "Identifier (Entity ID)".
	EntityID string
	// ACSURL is the value registered as "Reply URL".
	ACSURL string
}

// ServiceProvider implements the application-side app.Authenticator port
// for Entra ID using gosaml2 (dependency inversion).
type ServiceProvider struct {
	sp *saml2.SAMLServiceProvider
}

var _ app.Authenticator = (*ServiceProvider)(nil)

// New downloads the IdP federation metadata and assembles the service provider.
func New(metadataURL string, params SPParams) (*ServiceProvider, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(metadataURL)
	if err != nil {
		return nil, fmt.Errorf("fetch IdP metadata: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch IdP metadata: unexpected status %s", resp.Status)
	}
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read IdP metadata: %w", err)
	}
	return NewFromMetadata(raw, params)
}

// NewFromMetadata assembles the service provider from already-retrieved
// federation metadata XML. Entra ID metadata also contains WS-Fed
// RoleDescriptor elements, but they are ignored because only the SAML
// IDPSSODescriptor is used here.
func NewFromMetadata(rawMetadata []byte, params SPParams) (*ServiceProvider, error) {
	metadata := &types.EntityDescriptor{}
	if err := xml.Unmarshal(rawMetadata, metadata); err != nil {
		return nil, fmt.Errorf("parse IdP metadata: %w", err)
	}
	sp, err := buildSAMLServiceProvider(metadata, params)
	if err != nil {
		return nil, err
	}
	return &ServiceProvider{sp: sp}, nil
}

// IdPIssuer reports the IdP entityID resolved from the metadata, for
// startup diagnostics.
func (s *ServiceProvider) IdPIssuer() string { return s.sp.IdentityProviderIssuer }

// IdPSSOURL reports the SSO URL resolved from the metadata, for startup
// diagnostics.
func (s *ServiceProvider) IdPSSOURL() string { return s.sp.IdentityProviderSSOURL }

// BuildLoginRedirect implements app.Authenticator. It builds an unsigned
// AuthnRequest and encodes it for the HTTP-Redirect binding.
func (s *ServiceProvider) BuildLoginRedirect(relayState string) (app.LoginRedirect, error) {
	doc, err := s.sp.BuildAuthRequestDocument()
	if err != nil {
		return app.LoginRedirect{}, fmt.Errorf("build AuthnRequest: %w", err)
	}
	xmlStr, err := doc.WriteToString()
	if err != nil {
		return app.LoginRedirect{}, fmt.Errorf("serialize AuthnRequest: %w", err)
	}
	redirectURL, err := s.sp.BuildAuthURLRedirect(relayState, doc)
	if err != nil {
		return app.LoginRedirect{}, fmt.Errorf("build redirect URL: %w", err)
	}
	return app.LoginRedirect{URL: redirectURL, RequestXML: xmlStr}, nil
}

// ValidateResponse implements app.Authenticator.
func (s *ServiceProvider) ValidateResponse(encodedResponse string) (app.AuthResult, error) {
	info, err := s.sp.RetrieveAssertionInfo(encodedResponse)
	if err != nil {
		return app.AuthResult{}, fmt.Errorf("validate SAMLResponse: %w", err)
	}
	// gosaml2 reports validity-period and audience violations via WarningInfo
	// rather than an error, so turn them into errors here to honor the port
	// contract ("any validation failure is a non-nil error").
	if info.WarningInfo.InvalidTime {
		return app.AuthResult{}, errors.New("assertion is outside its validity period (Conditions NotBefore/NotOnOrAfter)")
	}
	if info.WarningInfo.NotInAudience {
		return app.AuthResult{}, errors.New("assertion audience does not include our entity ID")
	}

	attrs := make([]app.Attribute, 0, len(info.Values))
	for _, attr := range info.Values {
		values := make([]string, 0, len(attr.Values))
		for _, v := range attr.Values {
			values = append(values, v.Value)
		}
		attrs = append(attrs, app.Attribute{Name: attr.Name, Values: values})
	}
	return app.AuthResult{
		NameID:       info.NameID,
		NameIDFormat: info.NameIDFormat,
		Attributes:   attrs,
	}, nil
}

// buildSAMLServiceProvider extracts the SSO URL and signing certificates
// from the metadata and configures gosaml2.
func buildSAMLServiceProvider(metadata *types.EntityDescriptor, params SPParams) (*saml2.SAMLServiceProvider, error) {
	idp := metadata.IDPSSODescriptor
	if idp == nil {
		return nil, fmt.Errorf("IdP metadata has no IDPSSODescriptor")
	}

	// Find the HTTP-Redirect binding SSO URL, the redirect target when starting a login.
	var ssoURL string
	for _, svc := range idp.SingleSignOnServices {
		if svc.Binding == saml2.BindingHttpRedirect {
			ssoURL = svc.Location
			break
		}
	}
	if ssoURL == "" {
		return nil, fmt.Errorf("IdP metadata has no SingleSignOnService with HTTP-Redirect binding")
	}

	// Collect the IdP certificates used to verify SAMLResponse signatures.
	certStore := &dsig.MemoryX509CertificateStore{}
	for _, kd := range idp.KeyDescriptors {
		// A KeyDescriptor with an empty use attribute serves both signing and encryption.
		if kd.Use != "" && kd.Use != "signing" {
			continue
		}
		for i, xcert := range kd.KeyInfo.X509Data.X509Certificates {
			// Certificate base64 in metadata may contain newlines and indentation.
			data := strings.Join(strings.Fields(xcert.Data), "")
			if data == "" {
				return nil, fmt.Errorf("IdP metadata certificate %d is empty", i)
			}
			der, err := base64.StdEncoding.DecodeString(data)
			if err != nil {
				return nil, fmt.Errorf("decode IdP metadata certificate %d: %w", i, err)
			}
			cert, err := x509.ParseCertificate(der)
			if err != nil {
				return nil, fmt.Errorf("parse IdP metadata certificate %d: %w", i, err)
			}
			certStore.Roots = append(certStore.Roots, cert)
		}
	}
	if len(certStore.Roots) == 0 {
		return nil, fmt.Errorf("IdP metadata has no signing certificate")
	}

	return &saml2.SAMLServiceProvider{
		IdentityProviderSSOURL:     ssoURL,
		IdentityProviderSSOBinding: saml2.BindingHttpRedirect,
		// The Response/Assertion Issuer must match the metadata entityID.
		// For Entra ID it has the form https://sts.windows.net/{tenant-id}/.
		IdentityProviderIssuer:      metadata.EntityID,
		ServiceProviderIssuer:       params.EntityID,
		AssertionConsumerServiceURL: params.ACSURL,
		// Entra ID sets the assertion Audience to the "Identifier (Entity ID)".
		AudienceURI:         params.EntityID,
		IDPCertificateStore: certStore,
		// No SP certificate; signing AuthnRequests is out of scope.
		SignAuthnRequests: false,
	}, nil
}
