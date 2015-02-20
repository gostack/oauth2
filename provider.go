package oauth2

import (
	"encoding/json"
	"net/http"
	"net/url"
)

// Provider represents a entire instance of a provider, connected to a specific backend.
//
//  // oauthBackend implements the provider.Backend interface
// 	p := provider.New(oauthBackend)
//  http.Handle("/oauth", p.HTTPHandler())
type Provider struct {
	backend Backend
}

// Creates a new Provider instance for the given backend
func NewProvider(b Backend) *Provider {
	p := Provider{backend: b}
	return &p
}

// HTTPHandler builds and return an http.Handler that can be mounted into any net/http
// based application.
//
// For example, this will define all oauth routes on the /oauth namespace (i.e. /oauth/token):
//  http.Handler("/oauth", p.HTTPHandler())
func (p Provider) HTTPHandler() *http.ServeMux {
	routes := map[string]http.Handler{
		"/token": TokenHTTPHandler{p.backend},
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
	enc Encoder
}

// NewEncoderResponseWriter creates a new EncoderResponseWriter with the proper encoder for
// the current request.
func NewEncoderResponseWriter(w http.ResponseWriter, req *http.Request) *EncoderResponseWriter {
	return &EncoderResponseWriter{w, json.NewEncoder(w)}
}

// Encode takes an object, encoding it and calling the Write method appropriately.
func (w EncoderResponseWriter) Encode(v interface{}) {
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

// AuthorizeHTTPHandler
type AuthorizeHTTPHandler struct {
	backend Backend
}

// ServeHTTP implements the http.Handler interface for this struct.
func (h AuthorizeHTTPHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	redirectURI, err := url.ParseRequestURI(req.URL.Query().Get("redirect_uri"))
	if err != nil {
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
	c, err := h.backend.ClientLookup(id)
	if err != nil {
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

}

// TokenHTTPHandler handles the requests to the /token endpoint.
type TokenHTTPHandler struct {
	backend Backend
}

// ServeHTTP implements the http.Handler interface for this struct.
func (h TokenHTTPHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	ew := NewEncoderResponseWriter(w, req)

	// Read the Authorization header for client credentials
	id, secret, ok := req.BasicAuth()
	if !ok {
		ew.Encode(ErrInvalidRequest)
		return
	}

	// Get the client asnd authenticate it
	c, err := h.backend.ClientLookup(id)
	if err != nil {
		ew.Encode(ErrServerError)
		return
	} else if c.Secret != secret {
		ew.Encode(ErrInvalidClient)
		return
	}

	// Read the grant_type from the body parameters
	gt := req.PostFormValue("grant_type")
	if gt == "" {
		ew.Encode(ErrInvalidRequest)
		return
	}

	switch gt {
	case "password":
		h.resourceOwnerCredentials(c, ew, req)
	default:
		ew.Encode(ErrUnsupportedGrantType)
	}
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

	u, err := h.backend.UserAuthenticate(username, password)
	if err != nil {
		ew.Encode(ErrAccessDenied)
		return
	}

	auth, err := NewAuthorization(c, u, scope)
	if err != nil {
		ew.Encode(ErrServerError)
		return
	}

	if err := h.backend.AuthorizationPersist(auth); err != nil {
		ew.Encode(ErrServerError)
		return
	}

	ew.Encode(auth)
}
