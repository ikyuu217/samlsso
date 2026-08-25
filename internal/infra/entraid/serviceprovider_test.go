package entraid

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"fmt"
	"math/big"
	"testing"
	"time"
)

// entraMetadataFormat mimics Entra ID federation metadata. Like the real
// thing it contains a WS-Fed RoleDescriptor, and the signing certificate
// base64 is embedded with newlines and indentation. The two %s verbs take
// the signing and encryption certificates, in that order.
const entraMetadataFormat = `<?xml version="1.0" encoding="utf-8"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" ID="_00000000-0000-0000-0000-000000000000" entityID="https://sts.windows.net/11111111-2222-3333-4444-555555555555/">
  <RoleDescriptor xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:fed="http://docs.oasis-open.org/wsfed/federation/200706" xsi:type="fed:SecurityTokenServiceType" protocolSupportEnumeration="http://docs.oasis-open.org/wsfed/federation/200706">
    <fed:TokenTypesOffered>
      <fed:TokenType Uri="urn:oasis:names:tc:SAML:1.0:assertion"/>
    </fed:TokenTypesOffered>
  </RoleDescriptor>
  <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <KeyDescriptor use="signing">
      <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
        <X509Data>
          <X509Certificate>
            %s
          </X509Certificate>
        </X509Data>
      </KeyInfo>
    </KeyDescriptor>
    <KeyDescriptor use="encryption">
      <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
        <X509Data>
          <X509Certificate>%s</X509Certificate>
        </X509Data>
      </KeyInfo>
    </KeyDescriptor>
    <SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://login.microsoftonline.com/11111111-2222-3333-4444-555555555555/saml2"/>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://login.microsoftonline.com/11111111-2222-3333-4444-555555555555/saml2"/>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://login.microsoftonline.com/11111111-2222-3333-4444-555555555555/saml2"/>
  </IDPSSODescriptor>
</EntityDescriptor>`

// newTestCertBase64 generates a self-signed certificate and returns its DER
// encoding as base64.
func newTestCertBase64(t *testing.T, commonName string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(2040, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(der)
}

var testSPParams = SPParams{
	EntityID: "urn:samlsso:verification",
	ACSURL:   "http://localhost:8080/saml/acs",
}

func TestNewFromMetadataWithEntraMetadata(t *testing.T) {
	signingCert := newTestCertBase64(t, "signing")
	encryptionCert := newTestCertBase64(t, "encryption")
	raw := fmt.Sprintf(entraMetadataFormat, signingCert, encryptionCert)

	s, err := NewFromMetadata([]byte(raw), testSPParams)
	if err != nil {
		t.Fatalf("NewFromMetadata: %v", err)
	}

	if got, want := s.IdPIssuer(), "https://sts.windows.net/11111111-2222-3333-4444-555555555555/"; got != want {
		t.Errorf("IdPIssuer = %q, want %q", got, want)
	}
	if got, want := s.IdPSSOURL(), "https://login.microsoftonline.com/11111111-2222-3333-4444-555555555555/saml2"; got != want {
		t.Errorf("IdPSSOURL = %q, want %q", got, want)
	}
	if got, want := s.sp.AssertionConsumerServiceURL, "http://localhost:8080/saml/acs"; got != want {
		t.Errorf("AssertionConsumerServiceURL = %q, want %q", got, want)
	}
	if got, want := s.sp.AudienceURI, "urn:samlsso:verification"; got != want {
		t.Errorf("AudienceURI = %q, want %q", got, want)
	}
	if s.sp.SignAuthnRequests {
		t.Error("SignAuthnRequests = true, want false")
	}

	// Only the signing certificate must be loaded: use="encryption" is
	// excluded, and base64 containing newlines must be accepted.
	certs, err := s.sp.IDPCertificateStore.Certificates()
	if err != nil {
		t.Fatalf("Certificates: %v", err)
	}
	if len(certs) != 1 {
		t.Fatalf("len(certs) = %d, want 1", len(certs))
	}
	if got, want := certs[0].Subject.CommonName, "signing"; got != want {
		t.Errorf("cert CommonName = %q, want %q", got, want)
	}
}

func TestNewFromMetadataErrors(t *testing.T) {
	signingCert := newTestCertBase64(t, "signing")

	tests := []struct {
		name string
		raw  string
	}{
		{
			name: "not XML",
			raw:  "this is not metadata",
		},
		{
			name: "no IDPSSODescriptor",
			raw: `<?xml version="1.0" encoding="utf-8"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://sts.windows.net/tenant/"/>`,
		},
		{
			name: "no HTTP-Redirect SSO URL",
			raw: fmt.Sprintf(`<?xml version="1.0" encoding="utf-8"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://sts.windows.net/tenant/">
  <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <KeyDescriptor use="signing">
      <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><X509Data><X509Certificate>%s</X509Certificate></X509Data></KeyInfo>
    </KeyDescriptor>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://example.test/saml2"/>
  </IDPSSODescriptor>
</EntityDescriptor>`, signingCert),
		},
		{
			name: "no signing certificate",
			raw: fmt.Sprintf(`<?xml version="1.0" encoding="utf-8"?>
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://sts.windows.net/tenant/">
  <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <KeyDescriptor use="encryption">
      <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#"><X509Data><X509Certificate>%s</X509Certificate></X509Data></KeyInfo>
    </KeyDescriptor>
    <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://example.test/saml2"/>
  </IDPSSODescriptor>
</EntityDescriptor>`, signingCert),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := NewFromMetadata([]byte(tt.raw), testSPParams); err == nil {
				t.Error("NewFromMetadata succeeded, want error")
			}
		})
	}
}
