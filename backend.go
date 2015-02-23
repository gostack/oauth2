package oauth2

import (
	"io"
	"net/http"
)

type AuthorizationPageData struct {
	Client *Client
	User   *User
	Scopes []*Scope
}

type Backend interface {
	// AuthorizationPersist persists the provided Authorization in the backend
	AuthorizationPersist(a *Authorization) error

	// AuthorizationAuthenticate takes an access token and returns the authorization
	// it represents, if exists.
	AuthorizationAuthenticate(accessToken string) (*Authorization, error)

	// ClientLookup returns the Client that is identified by the provided id.
	ClientLookup(clientID string) (*Client, error)

	// ClientPerist persists the provided client in the backend
	ClientPersist(c *Client) error

	// RenderAuthorizationPage should write to the io.Writer the HTML for the
	// authorization page.
	RenderAuthorizationPage(w io.Writer, data *AuthorizationPageData) error

	// ScopesLookup takes scope IDs and fetches the Scope from backend
	ScopesLookup(scopeIDs ...string) ([]*Scope, error)

	// UserAuthenticate should authenticate a user using the provided username
	// and password and return a User object or an error.
	UserAuthenticate(username, password string) (*User, error)

	// UserAuthenticateRequest should take an http.Request and either return
	// the current logged in user or generate a response that will allow the
	// user to login, such as a redirect. If the later happens, both User and
	// error should be nil.
	UserAuthenticateRequest(w http.ResponseWriter, req *http.Request) (*User, error)
}
