/*
Copyright 2015 Rodrigo Rafael Monti Kochenburger

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

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
func (p Provider) HTTPHandler() http.Handler {
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
		log.Println("redirect_uri is missing or is an invalid URL")
		w.WriteHeader(ErrInvalidRequest.Code)
		h.http.RenderErrorPage(w, req, &ErrorPageData{ErrInvalidRequest})
		return
	}

	id := req.URL.Query().Get("client_id")
	if id == "" {
		log.Println("client_id is missing")
		w.WriteHeader(ErrInvalidRequest.Code)
		h.http.RenderErrorPage(w, req, &ErrorPageData{ErrInvalidRequest})
		return
	}

	// Get the client asnd authenticate it
	c, err := h.persistence.GetClientByID(id)
	if err != nil {
		log.Println("couldn't find client with id", id)
		w.WriteHeader(ErrInvalidClient.Code)
		h.http.RenderErrorPage(w, req, &ErrorPageData{ErrInvalidClient})
		return
	}

	// If provided redirectURI does not match the stored RedirectURI
	if redirectURI.String() != c.RedirectURI {
		log.Println("redirect_uri does not match the client's registered")
		w.WriteHeader(ErrInvalidRequest.Code)
		h.http.RenderErrorPage(w, req, &ErrorPageData{ErrInvalidRequest})
		return
	}

	state := req.URL.Query().Get("state")

	u, err := h.http.AuthenticateRequest(c, w, req)
	if err != nil {
		log.Println(err)
		redirectTo(w, req, redirectURI, url.Values{"error": []string{"server_error"}, "state": []string{state}})
		return
	}

	if u == nil {
		return
	}

	scope := req.URL.Query().Get("scope")
	scopes, err := h.persistence.GetScopesByID(strings.Split(scope, " ")...)
	if err != nil {
		redirectTo(w, req, redirectURI, url.Values{"error": []string{"invalid_scope"}, "state": []string{state}})
		return
	}

	switch req.URL.Query().Get("response_type") {
	case "code":
		switch req.Method {
		case "GET":
			h.http.RenderAuthorizationPage(w, req, &AuthorizationPageData{
				Client: c,
				User:   u,
				Scopes: scopes,
			})

		case "POST":
			if req.PostFormValue("action") == "authorize" {
				auth, err := NewAuthorization(c, u, scope, c.Confidential, true)
				if err != nil {
					log.Println(err)
					redirectTo(w, req, redirectURI, url.Values{"error": []string{"server_error"}, "state": []string{state}})
					return
				}

				if err := h.persistence.SaveAuthorization(auth); err != nil {
					log.Println(err)
					redirectTo(w, req, redirectURI, url.Values{"error": []string{"server_error"}, "state": []string{state}})
					return
				}

				redirectTo(w, req, redirectURI, url.Values{"code": []string{auth.Code}, "state": []string{state}})
				return
			}

			redirectTo(w, req, redirectURI, url.Values{"error": []string{"access_denied"}, "state": []string{state}})
		}

	default:
		redirectTo(w, req, redirectURI, url.Values{"error": []string{"unsupported_response_type"}, "state": []string{state}})
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
	case "client_credentials":
		h.clientCredentials(c, ew, req)
	case "refresh_token":
		h.refreshToken(c, ew, req)
	default:
		log.Println("Unsupported grant type")
		ew.Encode(ErrUnsupportedGrantType)
	}
}

// authorizationCode implements that Authorization Code grant type.
func (h TokenHTTPHandler) authorizationCode(c *Client, ew *EncoderResponseWriter, req *http.Request) {
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
		log.Println("client not internal")
		ew.Encode(ErrUnauthorizedClient)
		return
	}

	var (
		username = req.PostFormValue("username")
		password = req.PostFormValue("password")
		scope    = req.PostFormValue("scope")
	)

	if username == "" || password == "" {
		log.Println("username or password is empty")
		ew.Encode(ErrInvalidRequest)
		return
	}

	u, err := h.persistence.GetUserByCredentials(username, password)
	if err != nil {
		log.Println("invalid credentials")
		ew.Encode(ErrAccessDenied)
		return
	}

	auth, err := NewAuthorization(c, u, scope, c.Confidential, false)
	if err != nil {
		log.Println(err)
		ew.Encode(ErrServerError)
		return
	}

	if err := h.persistence.SaveAuthorization(auth); err != nil {
		log.Println(err)
		ew.Encode(ErrServerError)
		return
	}

	ew.Encode(auth)
}

// clientCredentials implements the Client Credentials grant type.
func (h TokenHTTPHandler) clientCredentials(c *Client, ew *EncoderResponseWriter, req *http.Request) {
	if !(c.Confidential && c.Internal) {
		log.Println("client is not confidential and internal")
		ew.Encode(ErrUnauthorizedClient)
		return
	}

	var (
		scope = req.PostFormValue("scope")
	)

	if scope != "" {
		scopesSl, err := h.persistence.GetScopesByID(strings.Split(scope, " ")...)
		if err != nil {
			log.Println("couldn't fetch scopes by id:", err)
			ew.Encode(ErrServerError)
			return
		}

		for _, s := range scopesSl {
			if s.UserOnly == true {
				log.Println("attempt to request user only scope on client credentials grant type")
				ew.Encode(ErrInvalidScope)
				return
			}
		}
	}

	auth, err := NewAuthorization(c, nil, scope, false, false)
	if err != nil {
		log.Println(err)
		ew.Encode(ErrServerError)
		return
	}

	if err := h.persistence.SaveAuthorization(auth); err != nil {
		log.Println(err)
		ew.Encode(ErrServerError)
		return
	}

	ew.Encode(auth)
}

// refreshToken implements the token refresh flow
func (h TokenHTTPHandler) refreshToken(c *Client, ew *EncoderResponseWriter, req *http.Request) {
	if !c.Confidential {
		log.Println("client not confidential")
		ew.Encode(ErrUnauthorizedClient)
		return
	}

	var (
		refreshToken = req.PostFormValue("refresh_token")
		scope        = req.PostFormValue("scope")
	)

	if refreshToken == "" || scope == "" {
		log.Println("missing required parameters")
		ew.Encode(ErrInvalidRequest)
		return
	}

	auth, err := h.persistence.GetAuthorizationByRefreshToken(refreshToken)
	if err != nil {
		log.Println("invalida refresh token:", refreshToken)
		ew.Encode(ErrInvalidGrant)
		return
	}

	if err := auth.Refresh(scope); err != nil {
		log.Println("failed to refresh token")
		ew.Encode(ErrServerError)
		return
	}

	if err := h.persistence.SaveAuthorization(auth); err != nil {
		log.Println("failed to persist authorization")
		ew.Encode(ErrServerError)
		return
	}

	ew.Encode(auth)
}
