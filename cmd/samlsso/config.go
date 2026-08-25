package main

import (
	"fmt"
	"net/url"
	"os"
	"strings"
)

// defaultSPBaseURL is used when SAML_SP_BASE_URL is not set.
// To run on a different port, override SAML_SP_BASE_URL itself.
const defaultSPBaseURL = "http://localhost:8080"

// config holds the SP settings given via environment variables.
type config struct {
	// idpMetadataURL is the "App Federation Metadata URL" of the Entra ID application.
	idpMetadataURL string
	// spEntityID is the value registered as "Identifier (Entity ID)" on the Entra ID side.
	spEntityID string
	// spBaseURL is the public URL of this app; the ACS URL and listen port are derived from it.
	spBaseURL *url.URL
}

// loadConfig builds the configuration from environment variables.
func loadConfig() (*config, error) {
	idpMetadataURL := os.Getenv("SAML_IDP_METADATA_URL")
	if idpMetadataURL == "" {
		return nil, fmt.Errorf("environment variable SAML_IDP_METADATA_URL is required")
	}

	spEntityID := os.Getenv("SAML_SP_ENTITY_ID")
	if spEntityID == "" {
		return nil, fmt.Errorf("environment variable SAML_SP_ENTITY_ID is required")
	}

	rawBaseURL := os.Getenv("SAML_SP_BASE_URL")
	if rawBaseURL == "" {
		rawBaseURL = defaultSPBaseURL
	}
	spBaseURL, err := url.Parse(rawBaseURL)
	if err != nil {
		return nil, fmt.Errorf("parse SAML_SP_BASE_URL: %w", err)
	}
	if (spBaseURL.Scheme != "http" && spBaseURL.Scheme != "https") || spBaseURL.Host == "" {
		return nil, fmt.Errorf("SAML_SP_BASE_URL must be an absolute http(s) URL, got %q", rawBaseURL)
	}

	return &config{
		idpMetadataURL: idpMetadataURL,
		spEntityID:     spEntityID,
		spBaseURL:      spBaseURL,
	}, nil
}

// acsURL is the full ACS URL to register as the "Reply URL" on the Entra ID side.
func (c *config) acsURL() string {
	return strings.TrimSuffix(c.spBaseURL.String(), "/") + "/saml/acs"
}

// listenAddr derives the listen address from the spBaseURL port.
// When the URL has no explicit port, the scheme's default port is used.
func (c *config) listenAddr() string {
	if port := c.spBaseURL.Port(); port != "" {
		return ":" + port
	}
	if c.spBaseURL.Scheme == "https" {
		return ":443"
	}
	return ":80"
}
