// samlsso is a minimal SAML SP for verification purposes, built with gosaml2.
// It completes one round of the SP-initiated login flow against Microsoft
// Entra ID as the IdP.
//
// Endpoints:
//
//	GET  /           shows the login link
//	GET  /saml/login builds an AuthnRequest and redirects to the IdP (HTTP-Redirect binding)
//	POST /saml/acs   validates the SAMLResponse from the IdP and shows the result (HTTP-POST binding)
//
// This package is the composition root: it reads the configuration and wires
// the application layer (internal/app) to the Entra ID infrastructure layer
// (internal/infra/entraid).
package main

import (
	"log"
	"net/http"
	"os"

	"github.com/ikyuu217/samlsso/internal/app"
	"github.com/ikyuu217/samlsso/internal/infra/entraid"
)

func main() {
	// Send the learning-oriented logs, including AuthnRequest/SAMLResponse XML, to stdout.
	log.SetOutput(os.Stdout)

	cfg, err := loadConfig()
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("fetching IdP metadata from %s", cfg.idpMetadataURL)
	sp, err := entraid.New(cfg.idpMetadataURL, entraid.SPParams{
		EntityID: cfg.spEntityID,
		ACSURL:   cfg.acsURL(),
	})
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("IdP issuer:   %s", sp.IdPIssuer())
	log.Printf("IdP SSO URL:  %s", sp.IdPSSOURL())
	log.Printf("SP entity ID: %s", cfg.spEntityID)
	log.Printf("ACS URL:      %s", cfg.acsURL())

	h := app.NewHandlers(sp)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", h.Index)
	mux.HandleFunc("GET /saml/login", h.Login)
	mux.HandleFunc("POST /saml/acs", h.ACS)

	log.Printf("listening on %s (base URL %s)", cfg.listenAddr(), cfg.spBaseURL)
	if err := http.ListenAndServe(cfg.listenAddr(), mux); err != nil {
		log.Fatal(err)
	}
}
