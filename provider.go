package oauth2

import (
	"encoding/json"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Provider represents a entire instance of a provider, connected to a specific backend.
//
//  // oauthBackend implements the provider.Backend interface
// 	p := provider.New(oauthBackend)
//  http.Handle("/oauth", p.HTTPHandler())
type Provider struct {
	persistence PersistenceBackend
	http        HTTPBackend
}

// Creates a new Provider instance for the given backend
func NewProvider(p PersistenceBackend, h HTTPBackend) *Provider {
	prv := Provider{p, h}
	return &prv
}

// HTTPHandler builds and return an http.Handler that can be mounted into any net/http
// based application.
//
// For example, this will define all oauth routes on the /oauth namespace (i.e. /oauth/token):
//  http.Handler("/oauth", p.HTTPHandler())
func (p Provider) HTTPHandler() *http.ServeMux {
	routes := map[string]http.Handler{
		"/authorize": AuthorizeHTTPHandler{p.persistence, p.http},
		"/token":     TokenHTTPHandler{p.persistence, p.http},
	}

	mux := http.NewServeMux()
	for r, h := range routes {
		mux.Handle(r, h)
	}

	return mux
}

// Encoder is a default interface for encoders
type Encoder interface {
	Encode(v interface{}) error
}

// EncoderResponseWriter that extends http.ResponseWriter to allow easy object serialization
type EncoderResponseWriter struct {
	http.ResponseWriter
	contentType string
	enc         Encoder
}

// NewEncoderResponseWriter creates a new EncoderResponseWriter with the proper encoder for
// the current request.
func NewEncoderResponseWriter(w http.ResponseWriter, req *http.Request) *EncoderResponseWriter {
	return &EncoderResponseWriter{w, "application/json", json.NewEncoder(w)}
}

// Encode takes an object, encoding it and calling the Write method appropriately.
func (w EncoderResponseWriter) Encode(v interface{}) {
	w.Header().Set("Content-Type", w.contentType)

	switch err := v.(type) {
	case Error:
		w.WriteHeader(err.Code)
	case error:
		w.WriteHeader(http.StatusInternalServerError)
	}

	if err := w.enc.Encode(v); err != nil {
		panic(err)
	}
}

func redirectTo(w http.ResponseWriter, req *http.Request, baseURL *url.URL, newValues url.Values) {
	values := baseURL.Query()
	for k, v := range newValues {
		values[k] = v
	}

	// Clone it
	u, err := url.ParseRequestURI(baseURL.String())
	if err != nil {
		panic(err)
	}

	u.RawQuery = values.Encode()
	http.Redirect(w, req, u.String(), http.StatusFound)
}

// AuthorizeHTTPHandler
type AuthorizeHTTPHandler struct {
	persistence PersistenceBackend
	http        HTTPBackend
}

// ServeHTTP implements the http.Handler interface for this struct.
func (h AuthorizeHTTPHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	redirectURI, err := url.ParseRequestURI(req.URL.Query().Get("redirect_uri"))
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("redirect_uri is missing"))
		return
	}

	id := req.URL.Query().Get("client_id")
	if id == "" {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("client_id is missing"))
		return
	}

	// Get the client asnd authenticate it
	c, err := h.persistence.GetClientByID(id)
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Invalid client_id"))
		return
	}

	// If provided redirectURI does not match the stored RedirectURI
	if redirectURI.String() != c.RedirectURI {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("Invalid redirect_uri"))
		return
	}

	u, err := h.http.AuthenticateRequest(w, req)
	if err != nil {
		log.Println(err)
		redirectTo(w, req, redirectURI, url.Values{"error": []string{"server_error"}})
		return
	}

	if u == nil {
		return
	}

	scope := req.URL.Query().Get("scope")
	scopes, err := h.persistence.GetScopesByID(strings.Split(scope, " ")...)
	if err != nil {
		redirectTo(w, req, redirectURI, url.Values{"error": []string{"invalid_scope"}})
		return
	}

	switch req.URL.Query().Get("response_type") {
	case "code":
		switch req.Method {
		case "GET":
			h.http.RenderAuthorizationPage(w, &AuthorizationPageData{
				Client: c,
				User:   u,
				Scopes: scopes,
			})

		case "POST":
			if req.PostFormValue("action") == "authorize" {
				auth, err := NewAuthorization(c, u, scope, true)
				if err != nil {
					log.Println(err)
					redirectTo(w, req, redirectURI, url.Values{"error": []string{"server_error"}})
					return
				}

				if err := h.persistence.SaveAuthorization(auth); err != nil {
					log.Println(err)
					redirectTo(w, req, redirectURI, url.Values{"error": []string{"server_error"}})
					return
				}

				redirectTo(w, req, redirectURI, url.Values{"code": []string{auth.Code}, "state": []string{req.URL.Query().Get("state")}})
			}
		}

	default:
		redirectURI.Query().Set("error", "unsupported_response_type")
		http.Redirect(w, req, redirectURI.String(), http.StatusFound)
	}
}

// TokenHTTPHandler handles the requests to the /token endpoint.
type TokenHTTPHandler struct {
	persistence PersistenceBackend
	http        HTTPBackend
}

// ServeHTTP implements the http.Handler interface for this struct.
func (h TokenHTTPHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	ew := NewEncoderResponseWriter(w, req)

	var id, secret string

	if req.Header.Get("Authorization") != "" {
		var ok bool
		// Read the Authorization header for client credentials
		id, secret, ok = req.BasicAuth()
		if !ok {
			log.Println("Invalid Authorization header")
			ew.Encode(ErrInvalidRequest)
			return
		}
	} else {
		id = req.PostFormValue("client_id")
		secret = req.PostFormValue("client_secret")

		if id == "" || secret == "" {
			log.Println("Client credentials missing")
			ew.Encode(ErrInvalidRequest)
			return
		}
	}

	// Get the client asnd authenticate it
	c, err := h.persistence.GetClientByID(id)
	if err != nil {
		log.Println("Can't find client")
		ew.Encode(ErrServerError)
		return
	} else if c.Secret != secret {
		log.Println("Invalid client password")
		ew.Encode(ErrInvalidClient)
		return
	}

	// Read the grant_type from the body parameters
	gt := req.PostFormValue("grant_type")
	if gt == "" {
		log.Println("Grant type is missing")
		ew.Encode(ErrInvalidRequest)
		return
	}

	switch gt {
	case "authorization_code":
		h.authorizationCode(c, ew, req)
	case "password":
		h.resourceOwnerCredentials(c, ew, req)
	default:
		log.Println("Unsupported grant type")
		ew.Encode(ErrUnsupportedGrantType)
	}
}

// authorizationCode implements that Authorization Code grant type.
func (h TokenHTTPHandler) authorizationCode(c *Client, ew *EncoderResponseWriter, req *http.Request) {
	if !c.Confidential {
		ew.Encode(ErrUnauthorizedClient)
		return
	}

	var (
		code        = req.PostFormValue("code")
		redirectURI = req.PostFormValue("redirect_uri")
	)

	if code == "" || redirectURI == "" {
		log.Println("missing required parameters")
		ew.Encode(ErrInvalidRequest)
		return
	}

	if redirectURI != c.RedirectURI {
		log.Println("redirect_uri does not match authorization")
		ew.Encode(ErrInvalidGrant)
		return
	}

	auth, err := h.persistence.GetAuthorizationByCode(code)
	if err != nil {
		log.Println("couldn't find authorization for code:", err)
		ew.Encode(ErrInvalidGrant)
		return
	}

	if time.Now().Unix() > auth.CreatedAt.Add(5*time.Minute).Unix() {
		log.Println("code has expired")
		ew.Encode(ErrInvalidGrant)
		return
	}

	auth.Code = ""
	if err := h.persistence.SaveAuthorization(auth); err != nil {
		log.Println("could not save authorization:", err)
		ew.Encode(ErrServerError)
		return
	}

	ew.Encode(auth)
}

// resourceOwnerCredentials implements that Resource Owner Credentials grant type.
func (h TokenHTTPHandler) resourceOwnerCredentials(c *Client, ew *EncoderResponseWriter, req *http.Request) {
	if !c.Internal {
		ew.Encode(ErrUnauthorizedClient)
	}

	var (
		username = req.PostFormValue("username")
		password = req.PostFormValue("password")
		scope    = req.PostFormValue("scope")
	)

	if username == "" || password == "" {
		ew.Encode(ErrInvalidRequest)
		return
	}

	u, err := h.persistence.GetUserByCredentials(username, password)
	if err != nil {
		ew.Encode(ErrAccessDenied)
		return
	}

	auth, err := NewAuthorization(c, u, scope, false)
	if err != nil {
		ew.Encode(ErrServerError)
		return
	}

	if err := h.persistence.SaveAuthorization(auth); err != nil {
		ew.Encode(ErrServerError)
		return
	}

	ew.Encode(auth)
}
