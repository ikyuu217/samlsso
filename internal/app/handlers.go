package app

import (
	"encoding/base64"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"sort"
)

// Handlers is the set of HTTP handlers of the SP. It depends only on the
// Authenticator port, not on any concrete SAML implementation.
type Handlers struct {
	auth Authenticator
}

// NewHandlers wires the handlers to an Authenticator implementation.
func NewHandlers(auth Authenticator) *Handlers {
	return &Handlers{auth: auth}
}

var indexTmpl = template.Must(template.New("index").Parse(`<!DOCTYPE html>
<html lang="ja">
<head><meta charset="utf-8"><title>samlsso</title></head>
<body>
<h1>samlsso: SAML SP 検証アプリ</h1>
<p><a href="/saml/login">Microsoft Entra ID でログイン</a></p>
</body>
</html>
`))

var resultTmpl = template.Must(template.New("result").Parse(`<!DOCTYPE html>
<html lang="ja">
<head><meta charset="utf-8"><title>ログイン成功 - samlsso</title></head>
<body>
<h1>ログイン成功</h1>
<dl>
  <dt>NameID</dt><dd>{{.NameID}}</dd>
  <dt>NameID Format</dt><dd>{{.NameIDFormat}}</dd>
</dl>
<h2>アサーション属性</h2>
<table border="1" cellpadding="4">
  <tr><th>Name</th><th>値</th></tr>
  {{range .Attributes}}
  <tr><td>{{.Name}}</td><td>{{range .Values}}{{.}}<br>{{end}}</td></tr>
  {{end}}
</table>
<p><a href="/">トップへ戻る</a></p>
</body>
</html>
`))

var errorTmpl = template.Must(template.New("error").Parse(`<!DOCTYPE html>
<html lang="ja">
<head><meta charset="utf-8"><title>ログイン失敗 - samlsso</title></head>
<body>
<h1>ログイン失敗</h1>
<p>{{.}}</p>
<p><a href="/">トップへ戻る</a></p>
</body>
</html>
`))

// Index serves the top page, which only has the login link.
func (h *Handlers) Index(w http.ResponseWriter, r *http.Request) {
	if err := indexTmpl.Execute(w, nil); err != nil {
		log.Printf("render index: %v", err)
	}
}

// Login starts a SAML login: it obtains the redirect from the Authenticator
// and sends the browser to the IdP.
func (h *Handlers) Login(w http.ResponseWriter, r *http.Request) {
	redirect, err := h.auth.BuildLoginRedirect("")
	if err != nil {
		h.renderError(w, http.StatusInternalServerError, err)
		return
	}

	// For learning: log the AuthnRequest XML before it is deflate+base64 encoded.
	log.Printf("sending AuthnRequest:\n%s", redirect.RequestXML)

	http.Redirect(w, r, redirect.URL, http.StatusFound)
}

// ACS receives the SAMLResponse posted by the IdP (HTTP-POST binding),
// validates it through the Authenticator, and shows the NameID and all
// received assertion attributes.
func (h *Handlers) ACS(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		h.renderError(w, http.StatusBadRequest, fmt.Errorf("parse form: %w", err))
		return
	}
	encoded := r.PostFormValue("SAMLResponse")
	if encoded == "" {
		h.renderError(w, http.StatusBadRequest, errors.New("SAMLResponse form value is missing"))
		return
	}

	// For learning: log the base64-decoded SAMLResponse XML. Done here rather
	// than in the Authenticator so the XML is logged even when validation fails.
	if raw, err := base64.StdEncoding.DecodeString(encoded); err == nil {
		log.Printf("received SAMLResponse:\n%s", raw)
	} else {
		log.Printf("received SAMLResponse that is not valid base64: %v", err)
	}

	result, err := h.auth.ValidateResponse(encoded)
	if err != nil {
		h.renderError(w, http.StatusUnauthorized, err)
		return
	}

	// Sort by attribute name for stable display.
	sort.Slice(result.Attributes, func(i, j int) bool {
		return result.Attributes[i].Name < result.Attributes[j].Name
	})

	if err := resultTmpl.Execute(w, result); err != nil {
		log.Printf("render result: %v", err)
	}
}

// renderError writes the error to both the log and an HTML page.
func (h *Handlers) renderError(w http.ResponseWriter, status int, err error) {
	log.Printf("error: %v", err)
	w.WriteHeader(status)
	if terr := errorTmpl.Execute(w, err.Error()); terr != nil {
		log.Printf("render error page: %v", terr)
	}
}
