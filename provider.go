package oauth2

import (
	"encoding/json"
	"net/http"
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

	auth := &Authorization{
		Client:       c,
		User:         u,
		AccessToken:  "fe23f7f48d1856785f4eeda57e52fffada592df7dc24e580401e2d6007cf23d557b5fb36588539a2f477f657e127c94644796e1ad9afb785fa69df0a1b6e473d",
		RefreshToken: "0ca5e99b50b8cd9393265a3ce64338635cf1182984236d9832e77a1431efb814b7c79d93710ce1f95992f608ecbd2ba20104644664ef41ab6293ed0a5417666c",
		TokenType:    "bearer",
		ExpiresIn:    3600,
		Scope:        scope,
	}
	if err := h.backend.AuthorizationPersist(auth); err != nil {
		ew.Encode(ErrServerError)
		return
	}

	ew.Encode(auth)
}
