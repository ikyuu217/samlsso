# samlsso

A verification-purpose SAML SP built with [gosaml2](https://github.com/russellhaering/gosaml2) that completes one round of the SP-initiated login flow against Microsoft Entra ID.

For learning purposes it logs the outgoing AuthnRequest XML (before encoding) and the received SAMLResponse XML (after base64 decoding) to stdout. It has no session management, SLO, HTTPS, or IdP-initiated flow — verification use only.

## Endpoints

| Method / path | Role |
|---|---|
| `GET /` | Shows the login link |
| `GET /saml/login` | Builds an AuthnRequest and redirects to the Entra ID SSO URL (HTTP-Redirect binding) |
| `POST /saml/acs` | Validates the SAMLResponse from Entra ID (signature, audience, validity period) and shows the NameID and all assertion attributes (HTTP-POST binding) |

## Package layout

- `cmd/samlsso` — composition root: configuration from environment variables and wiring
- `internal/app` — application layer: HTTP handlers and the `Authenticator` port (contract) they depend on
- `internal/infra/entraid` — infrastructure layer: implements the port with gosaml2 against Entra ID (metadata fetch/parse, AuthnRequest building, response validation)

The application side owns the contract and the infrastructure side implements it (dependency inversion), so gosaml2 stays inside `internal/infra/entraid`.

## Prerequisites

- Go 1.27 (managed with mise; installed via `mise install`)
- A verification Enterprise Application registered in Entra ID (see [docs/entraid-setup.md](docs/entraid-setup.md))

## Environment variables

| Variable | Required | Description |
|---|---|---|
| `SAML_IDP_METADATA_URL` | ✅ | The "App Federation Metadata URL" of the Entra ID application. Fetched and parsed at startup to configure the SSO URL and signing certificates |
| `SAML_SP_ENTITY_ID` | ✅ | The same value registered as "Identifier (Entity ID)" in Entra ID |
| `SAML_SP_BASE_URL` | | The public URL of this app. Defaults to `http://localhost:8080`. The listen port is derived from this URL, and `{SAML_SP_BASE_URL}/saml/acs` must match the "Reply URL" registered in Entra ID |

## Running

```sh
export SAML_IDP_METADATA_URL='https://login.microsoftonline.com/<tenant-id>/federationmetadata/2007-06/federationmetadata.xml?appid=<application-id>'
export SAML_SP_ENTITY_ID='<the identifier registered in Entra ID>'
go run ./cmd/samlsso
```

On successful startup the IdP issuer, IdP SSO URL, SP entity ID, and ACS URL are logged. The app fetches `SAML_IDP_METADATA_URL` at startup, so network reachability to it is required.

## Verifying the login flow

1. Register an Enterprise Application and assign your own account to it, following [docs/entraid-setup.md](docs/entraid-setup.md).
2. Set the environment variables above and start the app.
3. Open <http://localhost:8080> in a browser and click the login link.
4. Sign in on the Entra ID page; the browser is sent back to `/saml/acs`. The round trip is complete when the success page shows the NameID and the assertion attributes (displayname, emailaddress, etc.).
5. The AuthnRequest and SAMLResponse XML are logged to stdout — read through them to inspect the protocol internals (Issuer, Audience, Conditions, Signature, AttributeStatement, and so on).

## Tests

```sh
go test ./...
```

IdP metadata parsing and SP construction (`internal/infra/entraid`) are covered with an Entra ID-shaped fixture, and the HTTP handlers (`internal/app`) are covered through a stub `Authenticator`.
